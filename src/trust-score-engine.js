"use strict";

// Shared helpers (inlined from index.js for module independence)
function LruTracker() {
  this._map = Object.create(null); // key → {key, prev, next}
  this._head = null; // oldest
  this._tail = null; // newest
  this.length = 0;
}

LruTracker.prototype.push = function (key) {
  if (this._map[key]) {
    this.touch(key);
    return;
  }
  var node = { key: key, prev: this._tail, next: null };
  if (this._tail) {
    this._tail.next = node;
  } else {
    this._head = node;
  }
  this._tail = node;
  this._map[key] = node;
  this.length++;
};

LruTracker.prototype.touch = function (key) {
  var node = this._map[key];
  if (!node || node === this._tail) return;
  // Unlink
  if (node.prev) node.prev.next = node.next;
  else this._head = node.next;
  if (node.next) node.next.prev = node.prev;
  // Append to tail
  node.prev = this._tail;
  node.next = null;
  this._tail.next = node;
  this._tail = node;
};

LruTracker.prototype.evictOldest = function () {
  if (!this._head) return undefined;
  var node = this._head;
  this._head = node.next;
  if (this._head) this._head.prev = null;
  else this._tail = null;
  delete this._map[node.key];
  this.length--;
  return node.key;
};

LruTracker.prototype.remove = function (key) {
  var node = this._map[key];
  if (!node) return false;
  if (node.prev) node.prev.next = node.next;
  else this._head = node.next;
  if (node.next) node.next.prev = node.prev;
  else this._tail = node.prev;
  delete this._map[node.key];
  this.length--;
  return true;
};

LruTracker.prototype.has = function (key) {
  return !!this._map[key];
};

LruTracker.prototype.toArray = function () {
  var result = [];
  var node = this._head;
  while (node) {
    result.push(node.key);
    node = node.next;
  }
  return result;
};

LruTracker.prototype.clear = function () {
  this._map = Object.create(null);
  this._head = null;
  this._tail = null;
  this.length = 0;
};

/**
 * Re-populate from a serialized array (for state restore).
 * @param {string[]} arr - keys in oldest-to-newest order
 */
LruTracker.prototype.fromArray = function (arr) {
  this.clear();
  for (var i = 0; i < arr.length; i++) {
    this.push(arr[i]);
  }
};

// ── Crypto-secure Randomness ────────────────────────────────────────

var _crypto = null;
try {
  if (typeof require !== 'undefined') _crypto = require('crypto');
} catch (e) { /* not available */ }

/**
 * Generate a cryptographically secure random integer in [0, max).
 * Throws if no cryptographic RNG is available — a CAPTCHA library
 * must never fall back to Math.random() as it is predictable and
 * would allow attackers to forecast challenges.
 *
 * @param {number} max - Exclusive upper bound (must be > 0)
 * @returns {number} Random integer in [0, max)
 * @throws {Error} If no cryptographic random source is available
 */

function _now() { return Date.now(); }

/**
 * Constant-time string comparison to prevent timing side-channel attacks.
 * Uses crypto.timingSafeEqual when available (Node.js), otherwise
 * performs a bitwise XOR comparison over all characters regardless of
 * where the first mismatch occurs.
 *
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} True if strings are identical
 */

function _clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }



/**
 * createTrustScoreEngine — Unified trust scoring that aggregates signals from
 * multiple modules (reputation, fingerprinting, bot detection, rate limiting,
 * response analysis, etc.) into a single 0.0–1.0 trust score per client.
 *
 * Analogous to reCAPTCHA v3's invisible score but transparent and configurable.
 *
 * @param {Object} [options]
 * @param {Object} [options.weights] - Signal name → weight (default: equal)
 * @param {Object} [options.thresholds] - Action thresholds
 * @param {number} [options.thresholds.block=0.2] - Below this → block
 * @param {number} [options.thresholds.challenge=0.5] - Below this → challenge
 * @param {number} [options.thresholds.pass=0.7] - Above this → pass (between challenge and pass → soft challenge)
 * @param {number} [options.cacheTtlMs=30000] - Cache TTL per client
 * @param {number} [options.maxClients=5000] - Max cached client entries
 * @param {number} [options.maxHistory=100] - Max score history per client
 * @param {number} [options.decayFactor=0.95] - Weight of historical average in blended score
 * @returns {Object} Trust score engine instance
 */
function createTrustScoreEngine(options) {
  options = options || {};

  var defaultWeights = {
    reputation: 1.0,
    fingerprint: 1.0,
    botDetection: 1.0,
    rateLimit: 1.0,
    responseQuality: 1.0,
    behaviorEntropy: 1.0
  };

  var weights = Object.create(null);
  var userWeights = options.weights || {};
  var wKeys = Object.keys(defaultWeights);
  for (var wi = 0; wi < wKeys.length; wi++) {
    var wk = wKeys[wi];
    weights[wk] = typeof userWeights[wk] === "number" ? userWeights[wk] : defaultWeights[wk];
  }
  // Allow custom signal names not in defaults
  var uKeys = Object.keys(userWeights);
  for (var ui = 0; ui < uKeys.length; ui++) {
    if (typeof weights[uKeys[ui]] === "undefined") {
      weights[uKeys[ui]] = userWeights[uKeys[ui]];
    }
  }

  var thresholds = options.thresholds || {};
  var blockThreshold = typeof thresholds.block === "number" ? thresholds.block : 0.2;
  var challengeThreshold = typeof thresholds.challenge === "number" ? thresholds.challenge : 0.5;
  var passThreshold = typeof thresholds.pass === "number" ? thresholds.pass : 0.7;

  var cacheTtlMs = typeof options.cacheTtlMs === "number" && options.cacheTtlMs >= 0 ? options.cacheTtlMs : 30000;
  var maxClients = typeof options.maxClients === "number" && options.maxClients > 0 ? options.maxClients : 5000;
  var maxHistory = typeof options.maxHistory === "number" && options.maxHistory > 0 ? options.maxHistory : 100;
  var decayFactor = typeof options.decayFactor === "number" ? options.decayFactor : 0.7;
  var anomalyDropThreshold = typeof options.anomalyDropThreshold === "number" ? options.anomalyDropThreshold : 0.3;

  // clientId → { score, signals, action, timestamp, history: [{ score, timestamp }] }
  var clients = Object.create(null);
  var clientOrder = new LruTracker(); // O(1) LRU order
  var totalEvaluations = 0;
  var actionCounts = { block: 0, challenge: 0, softChallenge: 0, pass: 0 };

  // Registered signal providers: name → function(clientId) → { score: 0-1, confidence: 0-1, detail: string }
  var providers = Object.create(null);

  function _evictIfNeeded() {
    while (clientOrder.length > maxClients) {
      var oldest = clientOrder.evictOldest();
      if (oldest !== undefined) delete clients[oldest];
    }
  }

  function _touchClient(clientId) {
    clientOrder.push(clientId);
  }

  function _determineAction(score) {
    if (score <= blockThreshold) return "block";
    if (score <= challengeThreshold) return "challenge";
    if (score <= passThreshold) return "softChallenge";
    return "pass";
  }

  /**
   * Register a signal provider function.
   * @param {string} name - Signal name (must match a weight key to contribute)
   * @param {Function} fn - function(clientId) → { score: 0-1, confidence?: 0-1, detail?: string }
   */
  function registerProvider(name, fn) {
    if (typeof name !== "string" || !name) return;
    if (typeof fn !== "function") return;
    providers[name] = fn;
  }

  /**
   * Remove a signal provider.
   * @param {string} name
   */
  function unregisterProvider(name) {
    delete providers[name];
  }

  /**
   * Evaluate trust score for a client using all registered providers.
   * @param {string} clientId
   * @param {Object} [manualSignals] - Optional manual signal overrides: { signalName: 0-1 score }
   * @returns {Object} { clientId, score, action, signals, breakdown, cached }
   */
  function evaluate(clientId, manualSignals) {
    if (typeof clientId !== "string" || !clientId) {
      return { clientId: "", score: 0, action: "block", signals: {}, breakdown: [], cached: false, error: "invalid clientId" };
    }

    // Check cache
    var cached = clients[clientId];
    if (cached && (_now() - cached.timestamp) < cacheTtlMs) {
      _touchClient(clientId);
      return {
        clientId: clientId,
        score: cached.score,
        action: cached.action,
        signals: cached.signals,
        breakdown: cached.breakdown,
        cached: true
      };
    }

    manualSignals = manualSignals || {};
    var signals = {};
    var breakdown = [];

    // Collect signals from providers
    var pNames = Object.keys(providers);
    for (var pi = 0; pi < pNames.length; pi++) {
      var pName = pNames[pi];
      try {
        var result = providers[pName](clientId);
        if (result && typeof result.score === "number") {
          signals[pName] = {
            score: _clamp(result.score, 0, 1),
            confidence: typeof result.confidence === "number" ? _clamp(result.confidence, 0, 1) : 1,
            detail: result.detail || null
          };
        }
      } catch (e) {
        // Provider error — skip this signal
        signals[pName] = { score: 0.5, confidence: 0, detail: "provider error: " + (e.message || e), error: true };
      }
    }

    // Apply manual signal overrides
    var mKeys = Object.keys(manualSignals);
    for (var mi = 0; mi < mKeys.length; mi++) {
      var mName = mKeys[mi];
      var mVal = manualSignals[mName];
      if (typeof mVal === "number") {
        signals[mName] = { score: _clamp(mVal, 0, 1), confidence: 1, detail: "manual override" };
      } else if (mVal && typeof mVal.score === "number") {
        signals[mName] = {
          score: _clamp(mVal.score, 0, 1),
          confidence: typeof mVal.confidence === "number" ? _clamp(mVal.confidence, 0, 1) : 1,
          detail: mVal.detail || "manual override"
        };
      }
    }

    // Compute weighted score
    var weightedSum = 0;
    var totalWeight = 0;
    var sigNames = Object.keys(signals);
    for (var si = 0; si < sigNames.length; si++) {
      var sName = sigNames[si];
      var sig = signals[sName];
      var w = typeof weights[sName] === "number" ? weights[sName] : 0;
      if (w <= 0) continue;

      // Scale weight by confidence
      var effectiveWeight = w * sig.confidence;
      weightedSum += sig.score * effectiveWeight;
      totalWeight += effectiveWeight;

      breakdown.push({
        signal: sName,
        score: sig.score,
        weight: w,
        confidence: sig.confidence,
        effectiveWeight: effectiveWeight,
        contribution: sig.score * effectiveWeight,
        detail: sig.detail
      });
    }

    var rawScore = totalWeight > 0 ? weightedSum / totalWeight : 0.5;

    // Blend with historical average (recency-weighted)
    var blendedScore = rawScore;
    if (cached && cached.history && cached.history.length > 0) {
      // Recency-weighted average: more recent scores count more.
      // Weight_i = (i+1) / sum(1..n), so last entry gets highest weight.
      var histLen = cached.history.length;
      var weightDenom = (histLen * (histLen + 1)) / 2; // sum of 1..n
      var histWeightedSum = 0;
      for (var hi = 0; hi < histLen; hi++) {
        histWeightedSum += cached.history[hi].score * (hi + 1);
      }
      var histAvg = histWeightedSum / weightDenom;

      // Anomaly detection: if rawScore drops sharply from historical
      // average, use a more aggressive weight for the current evaluation
      // to react faster to behavioral changes (e.g., trust-washing attacks).
      var effectiveDecay = decayFactor;
      var drop = histAvg - rawScore;
      if (drop > anomalyDropThreshold) {
        // Scale decay down proportionally — bigger drop = less history weight
        // At drop=0.3 with threshold=0.3: effectiveDecay = decayFactor * 0.5
        // At drop=0.6: effectiveDecay = decayFactor * 0.25 (floor)
        var dropRatio = Math.min(drop / anomalyDropThreshold, 2);
        effectiveDecay = decayFactor * Math.max(0.25, 1 - dropRatio * 0.5);
      }

      blendedScore = rawScore * (1 - effectiveDecay) + histAvg * effectiveDecay;
    }

    var finalScore = _clamp(Math.round(blendedScore * 1000) / 1000, 0, 1);
    var action = _determineAction(finalScore);

    // Sort breakdown by contribution descending
    breakdown.sort(function (a, b) { return b.contribution - a.contribution; });

    // Update cache — store RAW scores in history (not blended) to prevent
    // compounding feedback loop where blended-of-blended scores create
    // exponential dampening of behavioral changes.
    var history = (cached && cached.history) ? cached.history.slice() : [];
    history.push({ score: rawScore, timestamp: _now() });
    if (history.length > maxHistory) {
      history = history.slice(history.length - maxHistory);
    }

    clients[clientId] = {
      score: finalScore,
      action: action,
      signals: signals,
      breakdown: breakdown,
      timestamp: _now(),
      history: history,
      rawScore: rawScore
    };
    _touchClient(clientId);
    _evictIfNeeded();

    totalEvaluations++;
    actionCounts[action] = (actionCounts[action] || 0) + 1;

    return {
      clientId: clientId,
      score: finalScore,
      rawScore: rawScore,
      action: action,
      signals: signals,
      breakdown: breakdown,
      cached: false
    };
  }

  /**
   * Evaluate multiple clients in batch.
   * @param {string[]} clientIds
   * @param {Object} [manualSignals] - Shared manual signals for all
   * @returns {Object[]} Array of evaluation results
   */
  function batchEvaluate(clientIds, manualSignals) {
    if (!Array.isArray(clientIds)) return [];
    var results = [];
    for (var i = 0; i < clientIds.length; i++) {
      results.push(evaluate(clientIds[i], manualSignals));
    }
    return results;
  }

  /**
   * Get the cached score for a client without re-evaluating.
   * @param {string} clientId
   * @returns {Object|null}
   */
  function getScore(clientId) {
    var c = clients[clientId];
    if (!c) return null;
    return {
      clientId: clientId,
      score: c.score,
      action: c.action,
      age: _now() - c.timestamp,
      stale: (_now() - c.timestamp) >= cacheTtlMs,
      historyLength: c.history ? c.history.length : 0
    };
  }

  /**
   * Get score trend for a client.
   * @param {string} clientId
   * @param {number} [lastN] - Last N scores to analyze
   * @returns {Object|null} { trend, slope, min, max, avg, scores }
   */
  function getScoreTrend(clientId, lastN) {
    var c = clients[clientId];
    if (!c || !c.history || c.history.length < 2) return null;

    var hist = c.history;
    if (typeof lastN === "number" && lastN > 0 && lastN < hist.length) {
      hist = hist.slice(hist.length - lastN);
    }

    var scores = [];
    var sum = 0;
    var min = 1;
    var max = 0;
    for (var i = 0; i < hist.length; i++) {
      var s = hist[i].score;
      scores.push(s);
      sum += s;
      if (s < min) min = s;
      if (s > max) max = s;
    }
    var avg = sum / scores.length;

    // Simple linear regression for slope
    var n = scores.length;
    var sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
    for (var j = 0; j < n; j++) {
      sumX += j;
      sumY += scores[j];
      sumXY += j * scores[j];
      sumXX += j * j;
    }
    var slope = n > 1 ? (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX) : 0;

    var trend = "stable";
    if (slope > 0.01) trend = "improving";
    else if (slope < -0.01) trend = "declining";

    return {
      trend: trend,
      slope: Math.round(slope * 10000) / 10000,
      min: min,
      max: max,
      avg: Math.round(avg * 1000) / 1000,
      count: scores.length,
      scores: scores
    };
  }

  /**
   * Invalidate cache for a client (force re-evaluation next time).
   * @param {string} clientId
   */
  function invalidate(clientId) {
    if (clients[clientId]) {
      clients[clientId].timestamp = 0; // Mark stale
    }
  }

  /**
   * Clear all cached data for a client.
   * @param {string} clientId
   */
  function clearClient(clientId) {
    delete clients[clientId];
    clientOrder.remove(clientId);
  }

  /**
   * Update action thresholds dynamically.
   * @param {Object} newThresholds - { block?, challenge?, pass? }
   */
  function setThresholds(newThresholds) {
    if (!newThresholds) return;
    if (typeof newThresholds.block === "number") blockThreshold = newThresholds.block;
    if (typeof newThresholds.challenge === "number") challengeThreshold = newThresholds.challenge;
    if (typeof newThresholds.pass === "number") passThreshold = newThresholds.pass;
  }

  /**
   * Get current threshold configuration.
   * @returns {Object}
   */
  function getThresholds() {
    return { block: blockThreshold, challenge: challengeThreshold, pass: passThreshold };
  }

  /**
   * Update signal weights dynamically.
   * @param {Object} newWeights - { signalName: weight }
   */
  function setWeights(newWeights) {
    if (!newWeights) return;
    var k = Object.keys(newWeights);
    for (var i = 0; i < k.length; i++) {
      if (typeof newWeights[k[i]] === "number") {
        weights[k[i]] = newWeights[k[i]];
      }
    }
  }

  /**
   * Get current weight configuration.
   * @returns {Object}
   */
  function getWeights() {
    var copy = Object.create(null);
    var k = Object.keys(weights);
    for (var i = 0; i < k.length; i++) copy[k[i]] = weights[k[i]];
    return copy;
  }

  /**
   * Get aggregate statistics.
   * @returns {Object}
   */
  function getStats() {
    var clientCount = clientOrder.length;
    var scoreSum = 0;
    var scoreCounts = { high: 0, medium: 0, low: 0, veryLow: 0 };
    var order = clientOrder.toArray();

    for (var i = 0; i < order.length; i++) {
      var c = clients[order[i]];
      if (c) {
        scoreSum += c.score;
        if (c.score > passThreshold) scoreCounts.high++;
        else if (c.score > challengeThreshold) scoreCounts.medium++;
        else if (c.score > blockThreshold) scoreCounts.low++;
        else scoreCounts.veryLow++;
      }
    }

    return {
      totalEvaluations: totalEvaluations,
      activeClients: clientCount,
      averageScore: clientCount > 0 ? Math.round((scoreSum / clientCount) * 1000) / 1000 : 0,
      actionCounts: {
        block: actionCounts.block || 0,
        challenge: actionCounts.challenge || 0,
        softChallenge: actionCounts.softChallenge || 0,
        pass: actionCounts.pass || 0
      },
      scoreBuckets: scoreCounts,
      providerCount: Object.keys(providers).length,
      weights: getWeights(),
      thresholds: getThresholds()
    };
  }

  /**
   * Get clients below a score threshold (for monitoring).
   * @param {number} [threshold=0.5]
   * @returns {Object[]} Array of { clientId, score, action, age }
   */
  function getLowScoreClients(threshold) {
    if (typeof threshold !== "number") threshold = 0.5;
    var results = [];
    var now = _now();
    var order2 = clientOrder.toArray();
    for (var i = 0; i < order2.length; i++) {
      var id = order2[i];
      var c = clients[id];
      if (c && c.score < threshold) {
        results.push({
          clientId: id,
          score: c.score,
          action: c.action,
          age: now - c.timestamp
        });
      }
    }
    results.sort(function (a, b) { return a.score - b.score; });
    return results;
  }

  /**
   * Compare two clients' trust profiles.
   * @param {string} clientA
   * @param {string} clientB
   * @returns {Object|null}
   */
  function compareClients(clientA, clientB) {
    var a = clients[clientA];
    var b = clients[clientB];
    if (!a || !b) return null;

    var signalDiffs = [];
    var allSignals = Object.create(null);
    var sk;
    for (sk in a.signals) allSignals[sk] = true;
    for (sk in b.signals) allSignals[sk] = true;
    var sNames = Object.keys(allSignals);

    for (var i = 0; i < sNames.length; i++) {
      var sn = sNames[i];
      var sa = a.signals[sn] ? a.signals[sn].score : null;
      var sb = b.signals[sn] ? b.signals[sn].score : null;
      signalDiffs.push({
        signal: sn,
        scoreA: sa,
        scoreB: sb,
        diff: sa !== null && sb !== null ? Math.round((sa - sb) * 1000) / 1000 : null
      });
    }

    return {
      clientA: { clientId: clientA, score: a.score, action: a.action },
      clientB: { clientId: clientB, score: b.score, action: b.action },
      scoreDiff: Math.round((a.score - b.score) * 1000) / 1000,
      signalComparison: signalDiffs
    };
  }

  /**
   * Export engine state for persistence.
   * @returns {Object}
   */
  function exportState() {
    var state = Object.create(null);
    var order3 = clientOrder.toArray();
    for (var i = 0; i < order3.length; i++) {
      var id = order3[i];
      var c = clients[id];
      if (c) {
        state[id] = {
          score: c.score,
          action: c.action,
          history: c.history,
          timestamp: c.timestamp
        };
      }
    }
    return {
      clients: state,
      stats: {
        totalEvaluations: totalEvaluations,
        actionCounts: actionCounts
      }
    };
  }

  /**
   * Import engine state from persistence.
   * @param {Object} state
   */
  function importState(state) {
    if (!state || !state.clients) return;
    var ids = Object.keys(state.clients);
    for (var i = 0; i < ids.length; i++) {
      var id = ids[i];
      var s = state.clients[id];
      clients[id] = {
        score: s.score || 0,
        action: s.action || "block",
        signals: {},
        breakdown: [],
        timestamp: s.timestamp || 0,
        history: s.history || [],
        rawScore: s.score || 0
      };
      clientOrder.push(id);
    }
    _evictIfNeeded();
    if (state.stats) {
      totalEvaluations = state.stats.totalEvaluations || 0;
      if (state.stats.actionCounts) {
        var ac = state.stats.actionCounts;
        actionCounts.block = ac.block || 0;
        actionCounts.challenge = ac.challenge || 0;
        actionCounts.softChallenge = ac.softChallenge || 0;
        actionCounts.pass = ac.pass || 0;
      }
    }
  }

  /**
   * Reset all state.
   */
  function reset() {
    clients = Object.create(null);
    clientOrder.clear();
    totalEvaluations = 0;
    actionCounts = { block: 0, challenge: 0, softChallenge: 0, pass: 0 };
  }

  return {
    registerProvider: registerProvider,
    unregisterProvider: unregisterProvider,
    evaluate: evaluate,
    batchEvaluate: batchEvaluate,
    getScore: getScore,
    getScoreTrend: getScoreTrend,
    invalidate: invalidate,
    clearClient: clearClient,
    setThresholds: setThresholds,
    getThresholds: getThresholds,
    setWeights: setWeights,
    getWeights: getWeights,
    getStats: getStats,
    getLowScoreClients: getLowScoreClients,
    compareClients: compareClients,
    exportState: exportState,
    importState: importState,
    reset: reset
  };
}


module.exports = { createTrustScoreEngine: createTrustScoreEngine };
