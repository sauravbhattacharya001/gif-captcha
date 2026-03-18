/**
 * ChallengeRotationScheduler — rotates active challenge types on a
 * configurable schedule to prevent bots from adapting to a single format.
 *
 * Bots trained on one challenge type (e.g. color-shape recognition) become
 * ineffective when the system switches to sequence or counting challenges.
 * This module automates that rotation with configurable strategies.
 *
 * Features:
 *   - Multiple rotation strategies (round-robin, weighted-random, performance-based)
 *   - Configurable rotation intervals (time-based or solve-count-based)
 *   - Challenge type enable/disable with activation windows
 *   - Performance tracking per challenge type (solve rates, avg times)
 *   - Emergency rotation on anomaly detection (sudden bot solve spike)
 *   - Transition cooldown to prevent flip-flopping
 *   - Event hooks for rotation events
 *   - State export/import for persistence
 *
 * Usage:
 *   var scheduler = createChallengeRotationScheduler();
 *   scheduler.addChallengeType({ id: 'color_shape', weight: 3 });
 *   scheduler.addChallengeType({ id: 'sequence', weight: 2 });
 *   scheduler.start();
 *   var current = scheduler.getCurrentType();
 *   scheduler.recordSolve('color_shape', true, 4500);
 *
 * @module gif-captcha/challenge-rotation-scheduler
 */

"use strict";

var DEFAULT_OPTIONS = {
  // Rotation strategy: 'round-robin' | 'weighted-random' | 'performance-based'
  strategy: "round-robin",

  // How often to rotate (ms). 0 = manual only.
  rotationIntervalMs: 600000, // 10 minutes

  // Or rotate after N total solves (0 = disabled)
  rotationAfterSolves: 0,

  // Minimum time between rotations (ms) — prevents flip-flopping
  cooldownMs: 30000,

  // For performance-based strategy: prefer types with solve rates in this band
  targetSolveRateMin: 0.50,
  targetSolveRateMax: 0.80,

  // Emergency rotation: if solve rate exceeds this, rotate immediately
  emergencySolveRateThreshold: 0.95,
  emergencyMinSamples: 15,

  // Sliding window for per-type stats (ms)
  statsWindowMs: 300000, // 5 minutes

  // Maximum types active simultaneously (0 = single active type)
  maxActiveTypes: 1,

  // PRNG seed for reproducibility (null = use crypto-secure random)
  seed: null,
};


// ── Cryptographic randomness (CWE-330 mitigation) ──────────────────
// Challenge rotation must be unpredictable — if an attacker can predict
// when/what type rotates to, they can pre-load the right solver.
var _secureRandom = require("./crypto-utils").secureRandom;

// ── Lightweight PRNG ────────────────────────────────────────────────

function _xorshift32(seed) {
  var state = seed | 0 || 1;
  return function () {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return (state >>> 0) / 4294967296;
  };
}


// ── Main factory ────────────────────────────────────────────────────

function createChallengeRotationScheduler(options) {
  var opts = Object.create(null);
  var key;
  for (key in DEFAULT_OPTIONS) {
    if (DEFAULT_OPTIONS.hasOwnProperty(key)) {
      opts[key] = (options && options[key] !== undefined) ? options[key] : DEFAULT_OPTIONS[key];
    }
  }

  // Validate strategy
  var VALID_STRATEGIES = ["round-robin", "weighted-random", "performance-based"];
  if (VALID_STRATEGIES.indexOf(opts.strategy) === -1) {
    throw new Error("Invalid strategy: " + opts.strategy + ". Must be one of: " + VALID_STRATEGIES.join(", "));
  }

  var _rng = opts.seed != null ? _xorshift32(opts.seed) : _secureRandom;

  // ── Internal state ──────────────────────────────────────────────

  /** @type {Array<{id:string, weight:number, enabled:boolean, meta:Object}>} */
  var _types = [];

  /** @type {string|null} */
  var _currentTypeId = null;

  /** @type {number} */
  var _currentIndex = 0;

  /** @type {number} */
  var _lastRotationTime = 0;

  /** @type {number} */
  var _solvesSinceRotation = 0;

  /** @type {number} */
  var _totalRotations = 0;

  /** @type {Object<string, Array<{solved:boolean, timeMs:number, ts:number}>>} */
  var _solveHistory = Object.create(null);

  /** @type {Array<{from:string|null, to:string, ts:number, reason:string}>} */
  var _rotationLog = [];

  /** @type {boolean} */
  var _running = false;

  /** @type {number|null} */
  var _timerHandle = null;

  /** @type {Object<string, Array<function>>} */
  var _listeners = Object.create(null);


  // ── Challenge type management ───────────────────────────────────

  /**
   * Register a challenge type for rotation.
   * @param {Object} typeConfig
   * @param {string} typeConfig.id — unique identifier
   * @param {number} [typeConfig.weight=1] — weight for weighted-random strategy
   * @param {boolean} [typeConfig.enabled=true] — whether type is available
   * @param {Object} [typeConfig.meta] — arbitrary metadata
   * @returns {Object} the registered type
   */
  function addChallengeType(typeConfig) {
    if (!typeConfig || typeof typeConfig.id !== "string" || !typeConfig.id.trim()) {
      throw new Error("Challenge type must have a non-empty string id");
    }
    var existing = _findType(typeConfig.id);
    if (existing) {
      throw new Error("Challenge type already registered: " + typeConfig.id);
    }
    var entry = {
      id: typeConfig.id.trim(),
      weight: typeof typeConfig.weight === "number" && typeConfig.weight > 0 ? typeConfig.weight : 1,
      enabled: typeConfig.enabled !== false,
      meta: typeConfig.meta || {},
    };
    _types.push(entry);
    _solveHistory[entry.id] = [];
    return { id: entry.id, weight: entry.weight, enabled: entry.enabled };
  }

  /**
   * Remove a challenge type.
   * @param {string} id
   * @returns {boolean}
   */
  function removeChallengeType(id) {
    var idx = _typeIndex(id);
    if (idx === -1) return false;
    _types.splice(idx, 1);
    delete _solveHistory[id];
    if (_currentTypeId === id) {
      _currentTypeId = null;
      if (_types.length > 0) _rotate("type_removed");
    }
    return true;
  }

  /**
   * Enable or disable a challenge type.
   * @param {string} id
   * @param {boolean} enabled
   * @returns {boolean}
   */
  function setTypeEnabled(id, enabled) {
    var t = _findType(id);
    if (!t) return false;
    t.enabled = !!enabled;
    if (!t.enabled && _currentTypeId === id) {
      _rotate("type_disabled");
    }
    return true;
  }

  /**
   * Update weight for a challenge type.
   * @param {string} id
   * @param {number} weight
   * @returns {boolean}
   */
  function setTypeWeight(id, weight) {
    var t = _findType(id);
    if (!t) return false;
    if (typeof weight !== "number" || weight <= 0) {
      throw new Error("Weight must be a positive number");
    }
    t.weight = weight;
    return true;
  }

  /**
   * Get all registered types with their current status.
   * @returns {Array<Object>}
   */
  function getTypes() {
    return _types.map(function (t) {
      var stats = _getTypeStats(t.id);
      return {
        id: t.id,
        weight: t.weight,
        enabled: t.enabled,
        active: t.id === _currentTypeId,
        stats: stats,
        meta: t.meta,
      };
    });
  }


  // ── Rotation logic ──────────────────────────────────────────────

  /**
   * Get the currently active challenge type ID.
   * @returns {string|null}
   */
  function getCurrentType() {
    return _currentTypeId;
  }

  /**
   * Force an immediate rotation (respects cooldown unless force=true).
   * @param {boolean} [force=false] — skip cooldown check
   * @returns {Object} { from, to, reason }
   */
  function rotate(force) {
    if (!force && !_cooldownElapsed()) {
      return { from: _currentTypeId, to: _currentTypeId, reason: "cooldown_active" };
    }
    return _rotate("manual");
  }

  /**
   * Change strategy at runtime.
   * @param {string} strategy
   */
  function setStrategy(strategy) {
    if (VALID_STRATEGIES.indexOf(strategy) === -1) {
      throw new Error("Invalid strategy: " + strategy);
    }
    opts.strategy = strategy;
  }

  /**
   * Get the current strategy.
   * @returns {string}
   */
  function getStrategy() {
    return opts.strategy;
  }

  /** Internal: perform rotation */
  function _rotate(reason) {
    var enabledTypes = _types.filter(function (t) { return t.enabled; });
    if (enabledTypes.length === 0) {
      _currentTypeId = null;
      return { from: null, to: null, reason: "no_enabled_types" };
    }
    if (enabledTypes.length === 1) {
      var only = enabledTypes[0].id;
      var prev = _currentTypeId;
      _currentTypeId = only;
      _recordRotation(prev, only, reason);
      return { from: prev, to: only, reason: reason };
    }

    var prev = _currentTypeId;
    var next;

    if (opts.strategy === "round-robin") {
      next = _roundRobin(enabledTypes);
    } else if (opts.strategy === "weighted-random") {
      next = _weightedRandom(enabledTypes);
    } else if (opts.strategy === "performance-based") {
      next = _performanceBased(enabledTypes);
    } else {
      next = enabledTypes[0].id;
    }

    _currentTypeId = next;
    _lastRotationTime = Date.now();
    _solvesSinceRotation = 0;
    _currentIndex = _typeIndex(next);
    _recordRotation(prev, next, reason);
    _emit("rotation", { from: prev, to: next, reason: reason, totalRotations: _totalRotations });

    return { from: prev, to: next, reason: reason };
  }

  function _roundRobin(enabledTypes) {
    // Find current in enabled list, advance to next
    var ids = enabledTypes.map(function (t) { return t.id; });
    var curIdx = ids.indexOf(_currentTypeId);
    var nextIdx = (curIdx + 1) % ids.length;
    return ids[nextIdx];
  }

  function _weightedRandom(enabledTypes) {
    // Weighted random, but avoid picking same type twice in a row
    var candidates = enabledTypes;
    if (enabledTypes.length > 1) {
      candidates = enabledTypes.filter(function (t) { return t.id !== _currentTypeId; });
    }
    var totalWeight = 0;
    for (var i = 0; i < candidates.length; i++) {
      totalWeight += candidates[i].weight;
    }
    var r = _rng() * totalWeight;
    var cumulative = 0;
    for (var j = 0; j < candidates.length; j++) {
      cumulative += candidates[j].weight;
      if (r <= cumulative) return candidates[j].id;
    }
    return candidates[candidates.length - 1].id;
  }

  function _performanceBased(enabledTypes) {
    // Pick the type whose solve rate is closest to the target band midpoint
    // but different from the current type
    var targetMid = (opts.targetSolveRateMin + opts.targetSolveRateMax) / 2;
    var bestId = null;
    var bestScore = Infinity;

    for (var i = 0; i < enabledTypes.length; i++) {
      var t = enabledTypes[i];
      if (t.id === _currentTypeId && enabledTypes.length > 1) continue;
      var stats = _getTypeStats(t.id);
      var rate = stats.solveRate != null ? stats.solveRate : targetMid;
      var distance = Math.abs(rate - targetMid);
      if (distance < bestScore) {
        bestScore = distance;
        bestId = t.id;
      }
    }
    return bestId || enabledTypes[0].id;
  }

  function _recordRotation(from, to, reason) {
    _totalRotations++;
    _rotationLog.push({ from: from, to: to, ts: Date.now(), reason: reason });
    // Trim log to last 200 entries
    if (_rotationLog.length > 200) {
      _rotationLog = _rotationLog.slice(-200);
    }
  }


  // ── Solve tracking ──────────────────────────────────────────────

  /**
   * Record a solve attempt for a challenge type.
   * @param {string} typeId — which challenge type
   * @param {boolean} solved — was the challenge solved correctly?
   * @param {number} [timeMs] — time taken in milliseconds
   */
  function recordSolve(typeId, solved, timeMs) {
    if (typeof typeId !== "string" || !typeId) {
      throw new Error("typeId must be a non-empty string");
    }
    if (typeof solved !== "boolean") {
      throw new Error("solved must be a boolean");
    }
    if (!_solveHistory[typeId]) {
      _solveHistory[typeId] = [];
    }
    _solveHistory[typeId].push({
      solved: solved,
      timeMs: typeof timeMs === "number" && timeMs >= 0 ? timeMs : null,
      ts: Date.now(),
    });
    _solvesSinceRotation++;

    // Prune old entries outside stats window
    _pruneHistory(typeId);

    // Check solve-count-based rotation
    if (opts.rotationAfterSolves > 0 && _solvesSinceRotation >= opts.rotationAfterSolves) {
      if (_cooldownElapsed()) {
        _rotate("solve_count");
      }
    }

    // Check emergency rotation
    if (opts.emergencySolveRateThreshold > 0 && _currentTypeId === typeId) {
      var stats = _getTypeStats(typeId);
      if (stats.total >= opts.emergencyMinSamples && stats.solveRate > opts.emergencySolveRateThreshold) {
        if (_cooldownElapsed()) {
          _rotate("emergency_high_solve_rate");
        }
      }
    }
  }

  /**
   * Get performance stats for a challenge type.
   * @param {string} typeId
   * @returns {Object} { total, solved, failed, solveRate, avgTimeMs }
   */
  function getTypeStats(typeId) {
    return _getTypeStats(typeId);
  }

  /** Internal stats calculation within the sliding window */
  function _getTypeStats(typeId) {
    var history = _solveHistory[typeId] || [];
    var cutoff = Date.now() - opts.statsWindowMs;
    var recent = history.filter(function (e) { return e.ts >= cutoff; });

    var solved = 0;
    var totalTime = 0;
    var timeCount = 0;
    for (var i = 0; i < recent.length; i++) {
      if (recent[i].solved) solved++;
      if (recent[i].timeMs != null) {
        totalTime += recent[i].timeMs;
        timeCount++;
      }
    }

    return {
      total: recent.length,
      solved: solved,
      failed: recent.length - solved,
      solveRate: recent.length > 0 ? Math.round((solved / recent.length) * 1000) / 1000 : null,
      avgTimeMs: timeCount > 0 ? Math.round(totalTime / timeCount) : null,
    };
  }

  function _pruneHistory(typeId) {
    var history = _solveHistory[typeId];
    if (!history) return;
    var cutoff = Date.now() - opts.statsWindowMs * 2; // keep 2x window
    if (history.length > 0 && history[0].ts < cutoff) {
      var start = 0;
      while (start < history.length && history[start].ts < cutoff) start++;
      _solveHistory[typeId] = history.slice(start);
    }
  }


  // ── Timer-based scheduling ──────────────────────────────────────

  /**
   * Start automatic rotation on the configured interval.
   * If no current type is set, picks the first enabled type.
   */
  function start() {
    if (_running) return;
    _running = true;

    if (!_currentTypeId) {
      var enabled = _types.filter(function (t) { return t.enabled; });
      if (enabled.length > 0) {
        _currentTypeId = enabled[0].id;
        _lastRotationTime = Date.now();
        _emit("start", { type: _currentTypeId });
      }
    }

    if (opts.rotationIntervalMs > 0) {
      _timerHandle = setInterval(function () {
        if (_cooldownElapsed()) {
          _rotate("scheduled");
        }
      }, opts.rotationIntervalMs);
    }
  }

  /**
   * Stop automatic rotation.
   */
  function stop() {
    _running = false;
    if (_timerHandle != null) {
      clearInterval(_timerHandle);
      _timerHandle = null;
    }
    _emit("stop", { type: _currentTypeId });
  }

  /**
   * Whether the scheduler is currently running.
   * @returns {boolean}
   */
  function isRunning() {
    return _running;
  }


  // ── Event system ────────────────────────────────────────────────

  /**
   * Subscribe to an event.
   * Events: 'rotation', 'start', 'stop', 'emergency'
   * @param {string} event
   * @param {function} handler
   */
  function on(event, handler) {
    if (typeof handler !== "function") throw new Error("Handler must be a function");
    if (!_listeners[event]) _listeners[event] = [];
    _listeners[event].push(handler);
  }

  /**
   * Unsubscribe from an event.
   * @param {string} event
   * @param {function} handler
   */
  function off(event, handler) {
    if (!_listeners[event]) return;
    _listeners[event] = _listeners[event].filter(function (h) { return h !== handler; });
  }

  function _emit(event, data) {
    var handlers = _listeners[event] || [];
    for (var i = 0; i < handlers.length; i++) {
      try { handlers[i](data); } catch (e) { /* swallow listener errors */ }
    }
  }


  // ── State persistence ───────────────────────────────────────────

  /**
   * Export scheduler state for persistence.
   * @returns {Object}
   */
  function exportState() {
    return {
      types: _types.map(function (t) {
        return { id: t.id, weight: t.weight, enabled: t.enabled, meta: t.meta };
      }),
      currentTypeId: _currentTypeId,
      currentIndex: _currentIndex,
      totalRotations: _totalRotations,
      lastRotationTime: _lastRotationTime,
      solvesSinceRotation: _solvesSinceRotation,
      rotationLog: _rotationLog.slice(-50),
      strategy: opts.strategy,
    };
  }

  /**
   * Import previously exported state.
   * @param {Object} state
   */
  function importState(state) {
    if (!state || typeof state !== "object") {
      throw new Error("State must be a non-null object");
    }
    if (Array.isArray(state.types)) {
      _types.length = 0;
      for (var i = 0; i < state.types.length; i++) {
        var t = state.types[i];
        _types.push({
          id: t.id,
          weight: t.weight || 1,
          enabled: t.enabled !== false,
          meta: t.meta || {},
        });
        if (!_solveHistory[t.id]) _solveHistory[t.id] = [];
      }
    }
    if (state.currentTypeId !== undefined) _currentTypeId = state.currentTypeId;
    if (typeof state.currentIndex === "number") _currentIndex = state.currentIndex;
    if (typeof state.totalRotations === "number") _totalRotations = state.totalRotations;
    if (typeof state.lastRotationTime === "number") _lastRotationTime = state.lastRotationTime;
    if (typeof state.solvesSinceRotation === "number") _solvesSinceRotation = state.solvesSinceRotation;
    if (Array.isArray(state.rotationLog)) _rotationLog = state.rotationLog.slice();
    if (state.strategy && VALID_STRATEGIES.indexOf(state.strategy) !== -1) {
      opts.strategy = state.strategy;
    }
  }

  /**
   * Reset all state.
   */
  function reset() {
    stop();
    _types.length = 0;
    _currentTypeId = null;
    _currentIndex = 0;
    _lastRotationTime = 0;
    _solvesSinceRotation = 0;
    _totalRotations = 0;
    _rotationLog.length = 0;
    for (var k in _solveHistory) {
      if (_solveHistory.hasOwnProperty(k)) delete _solveHistory[k];
    }
    _listeners = Object.create(null);
  }

  /**
   * Get summary of rotation activity.
   * @returns {Object}
   */
  function getSummary() {
    return {
      strategy: opts.strategy,
      running: _running,
      currentType: _currentTypeId,
      totalTypes: _types.length,
      enabledTypes: _types.filter(function (t) { return t.enabled; }).length,
      totalRotations: _totalRotations,
      solvesSinceRotation: _solvesSinceRotation,
      lastRotationTime: _lastRotationTime,
      recentRotations: _rotationLog.slice(-10),
    };
  }


  // ── Helpers ─────────────────────────────────────────────────────

  function _findType(id) {
    for (var i = 0; i < _types.length; i++) {
      if (_types[i].id === id) return _types[i];
    }
    return null;
  }

  function _typeIndex(id) {
    for (var i = 0; i < _types.length; i++) {
      if (_types[i].id === id) return i;
    }
    return -1;
  }

  function _cooldownElapsed() {
    return (Date.now() - _lastRotationTime) >= opts.cooldownMs;
  }


  // ── Public API ──────────────────────────────────────────────────

  return Object.freeze({
    addChallengeType: addChallengeType,
    removeChallengeType: removeChallengeType,
    setTypeEnabled: setTypeEnabled,
    setTypeWeight: setTypeWeight,
    getTypes: getTypes,
    getCurrentType: getCurrentType,
    rotate: rotate,
    setStrategy: setStrategy,
    getStrategy: getStrategy,
    recordSolve: recordSolve,
    getTypeStats: getTypeStats,
    start: start,
    stop: stop,
    isRunning: isRunning,
    on: on,
    off: off,
    exportState: exportState,
    importState: importState,
    reset: reset,
    getSummary: getSummary,
  });
}

// ── Export ───────────────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createChallengeRotationScheduler: createChallengeRotationScheduler };
}
