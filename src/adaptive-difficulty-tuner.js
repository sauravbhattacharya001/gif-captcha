/**
 * AdaptiveDifficultyTuner — automatically adjusts CAPTCHA difficulty
 * based on real-time solve rates to maintain optimal security/usability balance.
 *
 * Monitors solve/fail events in sliding time windows, computes solve rates,
 * and recommends difficulty adjustments to keep the solve rate within a
 * configurable target band. Supports multiple difficulty dimensions
 * (speed, complexity, distortion, frame count) and provides hooks for
 * automatic or manual application of recommendations.
 *
 * @module gif-captcha/adaptive-difficulty-tuner
 */

"use strict";

// ── Defaults ────────────────────────────────────────────────────────

var DEFAULT_OPTIONS = {
  // Target solve rate band (fraction 0-1)
  targetSolveRateMin: 0.55,
  targetSolveRateMax: 0.75,

  // Sliding window for rate calculation
  windowMs: 300000, // 5 minutes
  minSamplesForAdjustment: 20,

  // How often to evaluate (ms)
  evaluationIntervalMs: 30000, // 30 seconds

  // Difficulty range (1 = easiest, 10 = hardest)
  minDifficulty: 1,
  maxDifficulty: 10,
  initialDifficulty: 5,

  // Step sizes
  stepUp: 1,   // increase difficulty when too easy
  stepDown: 1, // decrease difficulty when too hard

  // Cooldown: minimum ms between adjustments
  cooldownMs: 60000,

  // Difficulty dimensions and their weight in the composite score
  dimensions: {
    speed: { weight: 0.3, min: 1, max: 10, value: 5 },
    complexity: { weight: 0.3, min: 1, max: 10, value: 5 },
    distortion: { weight: 0.2, min: 1, max: 10, value: 5 },
    frameCount: { weight: 0.2, min: 1, max: 10, value: 5 }
  },

  // Auto-apply recommendations
  autoApply: false,

  // Max history entries to retain
  maxHistory: 500
};

// ── Helpers ─────────────────────────────────────────────────────────

function clamp(val, min, max) {
  return val < min ? min : val > max ? max : val;
}

function now() {
  return Date.now();
}

function shallowMerge(defaults, overrides) {
  var result = Object.create(null);
  var key;
  for (key in defaults) {
    if (defaults.hasOwnProperty(key)) {
      result[key] = overrides && overrides.hasOwnProperty(key) ? overrides[key] : defaults[key];
    }
  }
  return result;
}

function deepCopyDimensions(dims) {
  var result = Object.create(null);
  var key;
  for (key in dims) {
    if (dims.hasOwnProperty(key)) {
      result[key] = {
        weight: dims[key].weight,
        min: dims[key].min,
        max: dims[key].max,
        value: dims[key].value
      };
    }
  }
  return result;
}

// ── Event Ring Buffer ───────────────────────────────────────────────

/**
 * Time-windowed event buffer for tracking solve/fail events.
 * @constructor
 * @param {number} windowMs - sliding window duration
 */
function EventWindow(windowMs) {
  this.windowMs = windowMs;
  this._events = []; // [{ts, solved}]
}

EventWindow.prototype.record = function (solved) {
  this._events.push({ ts: now(), solved: !!solved });
  this._prune();
};

EventWindow.prototype._prune = function () {
  var cutoff = now() - this.windowMs;
  while (this._events.length > 0 && this._events[0].ts < cutoff) {
    this._events.shift();
  }
};

EventWindow.prototype.getStats = function () {
  this._prune();
  var total = this._events.length;
  var solved = 0;
  for (var i = 0; i < total; i++) {
    if (this._events[i].solved) solved++;
  }
  return {
    total: total,
    solved: solved,
    failed: total - solved,
    solveRate: total > 0 ? solved / total : null,
    windowMs: this.windowMs,
    oldestTs: total > 0 ? this._events[0].ts : null,
    newestTs: total > 0 ? this._events[total - 1].ts : null
  };
};

EventWindow.prototype.clear = function () {
  this._events = [];
};

EventWindow.prototype.count = function () {
  this._prune();
  return this._events.length;
};

// ── Adjustment History ──────────────────────────────────────────────

function AdjustmentHistory(maxEntries) {
  this._entries = [];
  this._maxEntries = maxEntries || 500;
}

AdjustmentHistory.prototype.record = function (entry) {
  this._entries.push(entry);
  while (this._entries.length > this._maxEntries) {
    this._entries.shift();
  }
};

AdjustmentHistory.prototype.getAll = function () {
  return this._entries.slice();
};

AdjustmentHistory.prototype.getLast = function (n) {
  return this._entries.slice(-n);
};

AdjustmentHistory.prototype.count = function () {
  return this._entries.length;
};

AdjustmentHistory.prototype.clear = function () {
  this._entries = [];
};

// ── AdaptiveDifficultyTuner ─────────────────────────────────────────

/**
 * Create an adaptive difficulty tuner.
 *
 * @param {Object} [options] - Configuration options
 * @param {number} [options.targetSolveRateMin=0.55] - Lower bound of target solve rate
 * @param {number} [options.targetSolveRateMax=0.75] - Upper bound of target solve rate
 * @param {number} [options.windowMs=300000] - Sliding window duration (ms)
 * @param {number} [options.minSamplesForAdjustment=20] - Minimum samples before adjusting
 * @param {number} [options.evaluationIntervalMs=30000] - Evaluation interval (ms)
 * @param {number} [options.minDifficulty=1] - Minimum composite difficulty
 * @param {number} [options.maxDifficulty=10] - Maximum composite difficulty
 * @param {number} [options.initialDifficulty=5] - Starting difficulty
 * @param {number} [options.stepUp=1] - Step size for increasing difficulty
 * @param {number} [options.stepDown=1] - Step size for decreasing difficulty
 * @param {number} [options.cooldownMs=60000] - Cooldown between adjustments
 * @param {Object} [options.dimensions] - Difficulty dimensions config
 * @param {boolean} [options.autoApply=false] - Auto-apply recommendations
 * @param {number} [options.maxHistory=500] - Max adjustment history entries
 * @returns {Object} Tuner instance
 */
function createAdaptiveDifficultyTuner(options) {
  var opts = shallowMerge(DEFAULT_OPTIONS, options);

  // Deep copy dimensions
  var dimensions = options && options.dimensions
    ? deepCopyDimensions(options.dimensions)
    : deepCopyDimensions(DEFAULT_OPTIONS.dimensions);

  var currentDifficulty = clamp(opts.initialDifficulty, opts.minDifficulty, opts.maxDifficulty);
  var eventWindow = new EventWindow(opts.windowMs);
  var history = new AdjustmentHistory(opts.maxHistory);
  var lastAdjustmentTs = 0;
  var evaluationTimer = null;
  var listeners = Object.create(null);
  var totalSolves = 0;
  var totalFails = 0;
  var paused = false;

  // ── Event emitter (minimal) ─────────────────────────────────────

  function on(event, fn) {
    if (!listeners[event]) listeners[event] = [];
    listeners[event].push(fn);
  }

  function off(event, fn) {
    if (!listeners[event]) return;
    listeners[event] = listeners[event].filter(function (f) { return f !== fn; });
  }

  function emit(event, data) {
    var fns = listeners[event];
    if (!fns) return;
    for (var i = 0; i < fns.length; i++) {
      try { fns[i](data); } catch (e) { /* swallow listener errors */ }
    }
  }

  // ── Core logic ──────────────────────────────────────────────────

  function recordSolve() {
    eventWindow.record(true);
    totalSolves++;
    emit("solve", { difficulty: currentDifficulty, timestamp: now() });
  }

  function recordFail() {
    eventWindow.record(false);
    totalFails++;
    emit("fail", { difficulty: currentDifficulty, timestamp: now() });
  }

  function getCompositeDifficulty() {
    var totalWeight = 0;
    var weightedSum = 0;
    for (var key in dimensions) {
      if (dimensions.hasOwnProperty(key)) {
        var dim = dimensions[key];
        // Normalize to 0-1 range, then scale to minDifficulty-maxDifficulty
        var normalized = (dim.value - dim.min) / (dim.max - dim.min || 1);
        weightedSum += normalized * dim.weight;
        totalWeight += dim.weight;
      }
    }
    if (totalWeight === 0) return currentDifficulty;
    var composite = opts.minDifficulty + (weightedSum / totalWeight) * (opts.maxDifficulty - opts.minDifficulty);
    return Math.round(composite * 100) / 100;
  }

  function setCompositeDifficulty(target) {
    target = clamp(target, opts.minDifficulty, opts.maxDifficulty);
    currentDifficulty = target;

    // Scale all dimensions proportionally
    var fraction = (target - opts.minDifficulty) / (opts.maxDifficulty - opts.minDifficulty || 1);
    for (var key in dimensions) {
      if (dimensions.hasOwnProperty(key)) {
        var dim = dimensions[key];
        dim.value = Math.round((dim.min + fraction * (dim.max - dim.min)) * 100) / 100;
      }
    }
  }

  function evaluate() {
    if (paused) return null;

    var stats = eventWindow.getStats();

    if (stats.total < opts.minSamplesForAdjustment) {
      return {
        action: "hold",
        reason: "insufficient_samples",
        samplesNeeded: opts.minSamplesForAdjustment - stats.total,
        currentDifficulty: currentDifficulty,
        stats: stats
      };
    }

    var solveRate = stats.solveRate;
    var timeSinceLastAdj = now() - lastAdjustmentTs;

    if (timeSinceLastAdj < opts.cooldownMs) {
      return {
        action: "hold",
        reason: "cooldown",
        cooldownRemainingMs: opts.cooldownMs - timeSinceLastAdj,
        currentDifficulty: currentDifficulty,
        solveRate: solveRate,
        stats: stats
      };
    }

    var recommendation;

    if (solveRate > opts.targetSolveRateMax) {
      // Too easy — increase difficulty
      var newDiff = clamp(currentDifficulty + opts.stepUp, opts.minDifficulty, opts.maxDifficulty);
      recommendation = {
        action: "increase",
        reason: "solve_rate_above_target",
        from: currentDifficulty,
        to: newDiff,
        solveRate: solveRate,
        targetRange: [opts.targetSolveRateMin, opts.targetSolveRateMax],
        stats: stats
      };
    } else if (solveRate < opts.targetSolveRateMin) {
      // Too hard — decrease difficulty
      var newDiff2 = clamp(currentDifficulty - opts.stepDown, opts.minDifficulty, opts.maxDifficulty);
      recommendation = {
        action: "decrease",
        reason: "solve_rate_below_target",
        from: currentDifficulty,
        to: newDiff2,
        solveRate: solveRate,
        targetRange: [opts.targetSolveRateMin, opts.targetSolveRateMax],
        stats: stats
      };
    } else {
      // In the sweet spot
      recommendation = {
        action: "hold",
        reason: "within_target",
        currentDifficulty: currentDifficulty,
        solveRate: solveRate,
        targetRange: [opts.targetSolveRateMin, opts.targetSolveRateMax],
        stats: stats
      };
    }

    if (opts.autoApply && recommendation.action !== "hold") {
      applyRecommendation(recommendation);
    }

    emit("evaluation", recommendation);
    return recommendation;
  }

  function applyRecommendation(rec) {
    if (!rec || rec.action === "hold") return false;

    var oldDifficulty = currentDifficulty;
    setCompositeDifficulty(rec.to);
    lastAdjustmentTs = now();

    var entry = {
      timestamp: now(),
      action: rec.action,
      from: oldDifficulty,
      to: currentDifficulty,
      solveRate: rec.solveRate,
      sampleSize: rec.stats.total,
      dimensions: deepCopyDimensions(dimensions)
    };
    history.record(entry);

    emit("adjustment", entry);
    return true;
  }

  function setDimension(name, value) {
    if (!dimensions[name]) {
      throw new Error("Unknown dimension: " + name);
    }
    dimensions[name].value = clamp(value, dimensions[name].min, dimensions[name].max);
    currentDifficulty = getCompositeDifficulty();
  }

  function getDimension(name) {
    if (!dimensions[name]) {
      throw new Error("Unknown dimension: " + name);
    }
    return {
      name: name,
      value: dimensions[name].value,
      min: dimensions[name].min,
      max: dimensions[name].max,
      weight: dimensions[name].weight
    };
  }

  function getAllDimensions() {
    var result = Object.create(null);
    for (var key in dimensions) {
      if (dimensions.hasOwnProperty(key)) {
        result[key] = getDimension(key);
      }
    }
    return result;
  }

  function addDimension(name, config) {
    if (dimensions[name]) {
      throw new Error("Dimension already exists: " + name);
    }
    dimensions[name] = {
      weight: config.weight || 0.1,
      min: config.min != null ? config.min : 1,
      max: config.max != null ? config.max : 10,
      value: config.value != null ? config.value : 5
    };
  }

  function removeDimension(name) {
    if (!dimensions[name]) {
      throw new Error("Unknown dimension: " + name);
    }
    delete dimensions[name];
    currentDifficulty = getCompositeDifficulty();
  }

  // ── Auto-evaluation timer ──────────────────────────────────────

  function startAutoEval() {
    if (evaluationTimer) return;
    evaluationTimer = setInterval(function () {
      evaluate();
    }, opts.evaluationIntervalMs);
  }

  function stopAutoEval() {
    if (evaluationTimer) {
      clearInterval(evaluationTimer);
      evaluationTimer = null;
    }
  }

  // ── Status & reporting ─────────────────────────────────────────

  function getStatus() {
    var stats = eventWindow.getStats();
    return {
      currentDifficulty: currentDifficulty,
      compositeDifficulty: getCompositeDifficulty(),
      dimensions: getAllDimensions(),
      solveRate: stats.solveRate,
      windowStats: stats,
      totalSolves: totalSolves,
      totalFails: totalFails,
      totalAttempts: totalSolves + totalFails,
      overallSolveRate: (totalSolves + totalFails) > 0
        ? totalSolves / (totalSolves + totalFails)
        : null,
      targetRange: [opts.targetSolveRateMin, opts.targetSolveRateMax],
      lastAdjustmentTs: lastAdjustmentTs || null,
      adjustmentCount: history.count(),
      paused: paused,
      autoApply: opts.autoApply,
      autoEvalRunning: evaluationTimer !== null
    };
  }

  function getReport() {
    var status = getStatus();
    var recentAdj = history.getLast(10);
    var healthScore = _calculateHealthScore(status);

    return {
      status: status,
      healthScore: healthScore,
      healthLabel: healthScore >= 80 ? "excellent"
        : healthScore >= 60 ? "good"
        : healthScore >= 40 ? "fair"
        : "poor",
      recentAdjustments: recentAdj,
      recommendation: _generateRecommendation(status),
      stabilityIndex: _calculateStability(recentAdj)
    };
  }

  function _calculateHealthScore(status) {
    var score = 100;

    // Penalize if solve rate is outside target
    if (status.solveRate !== null) {
      if (status.solveRate < opts.targetSolveRateMin) {
        var deficit = opts.targetSolveRateMin - status.solveRate;
        score -= Math.min(40, deficit * 200);
      } else if (status.solveRate > opts.targetSolveRateMax) {
        var excess = status.solveRate - opts.targetSolveRateMax;
        score -= Math.min(30, excess * 150);
      }
    } else {
      score -= 20; // No data penalty
    }

    // Penalize extremes of difficulty
    var diffRange = opts.maxDifficulty - opts.minDifficulty;
    if (diffRange > 0) {
      var diffPosition = (status.currentDifficulty - opts.minDifficulty) / diffRange;
      if (diffPosition > 0.9 || diffPosition < 0.1) {
        score -= 15; // Near limits
      }
    }

    // Penalize low sample size
    if (status.windowStats.total < opts.minSamplesForAdjustment) {
      score -= 10;
    }

    return Math.max(0, Math.round(score));
  }

  function _calculateStability(recentAdj) {
    if (recentAdj.length < 2) return 1.0;

    // Check for oscillation (alternating increase/decrease)
    var oscillations = 0;
    for (var i = 1; i < recentAdj.length; i++) {
      if (recentAdj[i].action !== recentAdj[i - 1].action &&
          recentAdj[i].action !== "hold" &&
          recentAdj[i - 1].action !== "hold") {
        oscillations++;
      }
    }

    var maxOscillations = recentAdj.length - 1;
    return Math.round((1 - oscillations / maxOscillations) * 100) / 100;
  }

  function _generateRecommendation(status) {
    if (status.solveRate === null) {
      return "Collecting data — need " + opts.minSamplesForAdjustment + " samples for first evaluation.";
    }
    if (status.solveRate >= opts.targetSolveRateMin && status.solveRate <= opts.targetSolveRateMax) {
      return "Solve rate is within target range. No action needed.";
    }
    if (status.solveRate > opts.targetSolveRateMax) {
      if (status.currentDifficulty >= opts.maxDifficulty) {
        return "Solve rate too high but difficulty is at maximum. Consider adding new challenge types.";
      }
      return "Solve rate above target (" + (status.solveRate * 100).toFixed(1) + "%). Recommend increasing difficulty.";
    }
    if (status.currentDifficulty <= opts.minDifficulty) {
      return "Solve rate too low but difficulty is at minimum. Consider reviewing challenge design.";
    }
    return "Solve rate below target (" + (status.solveRate * 100).toFixed(1) + "%). Recommend decreasing difficulty.";
  }

  // ── Pause / Resume ────────────────────────────────────────────

  function pause() {
    paused = true;
    emit("paused", { timestamp: now() });
  }

  function resume() {
    paused = false;
    emit("resumed", { timestamp: now() });
  }

  // ── Reset ─────────────────────────────────────────────────────

  function reset() {
    currentDifficulty = clamp(opts.initialDifficulty, opts.minDifficulty, opts.maxDifficulty);
    setCompositeDifficulty(currentDifficulty);
    eventWindow.clear();
    history.clear();
    totalSolves = 0;
    totalFails = 0;
    lastAdjustmentTs = 0;
    paused = false;
    emit("reset", { timestamp: now() });
  }

  // ── Export / Import state ─────────────────────────────────────

  function exportState() {
    return {
      currentDifficulty: currentDifficulty,
      dimensions: deepCopyDimensions(dimensions),
      totalSolves: totalSolves,
      totalFails: totalFails,
      lastAdjustmentTs: lastAdjustmentTs,
      history: history.getAll(),
      paused: paused
    };
  }

  function importState(state) {
    if (!state) throw new Error("State is required");

    if (state.currentDifficulty != null) {
      currentDifficulty = clamp(state.currentDifficulty, opts.minDifficulty, opts.maxDifficulty);
    }
    if (state.dimensions) {
      for (var key in state.dimensions) {
        if (state.dimensions.hasOwnProperty(key) && dimensions[key]) {
          dimensions[key].value = state.dimensions[key].value;
        }
      }
    }
    if (state.totalSolves != null) totalSolves = state.totalSolves;
    if (state.totalFails != null) totalFails = state.totalFails;
    if (state.lastAdjustmentTs != null) lastAdjustmentTs = state.lastAdjustmentTs;
    if (state.paused != null) paused = state.paused;
    if (state.history && Array.isArray(state.history)) {
      history.clear();
      for (var i = 0; i < state.history.length; i++) {
        history.record(state.history[i]);
      }
    }

    emit("imported", { timestamp: now() });
  }

  // ── Destroy ───────────────────────────────────────────────────

  function destroy() {
    stopAutoEval();
    listeners = Object.create(null);
    eventWindow.clear();
  }

  // ── Public API ────────────────────────────────────────────────

  return {
    // Event recording
    recordSolve: recordSolve,
    recordFail: recordFail,

    // Evaluation
    evaluate: evaluate,
    applyRecommendation: applyRecommendation,

    // Difficulty management
    getDifficulty: function () { return currentDifficulty; },
    setDifficulty: function (val) { setCompositeDifficulty(val); },
    getCompositeDifficulty: getCompositeDifficulty,

    // Dimension management
    setDimension: setDimension,
    getDimension: getDimension,
    getAllDimensions: getAllDimensions,
    addDimension: addDimension,
    removeDimension: removeDimension,

    // Auto-evaluation
    startAutoEval: startAutoEval,
    stopAutoEval: stopAutoEval,

    // Status & reporting
    getStatus: getStatus,
    getReport: getReport,

    // Lifecycle
    pause: pause,
    resume: resume,
    reset: reset,
    destroy: destroy,

    // State management
    exportState: exportState,
    importState: importState,

    // Events
    on: on,
    off: off
  };
}

// ── Exports ─────────────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createAdaptiveDifficultyTuner: createAdaptiveDifficultyTuner };
}
