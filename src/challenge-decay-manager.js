'use strict';

/**
 * createChallengeDecayManager — tracks challenge freshness and auto-retires
 * stale challenges to prevent CAPTCHA-solving services from memorising the pool.
 *
 * Problem: static challenge pools become predictable.  Bots and human-solver
 * farms cache answers after repeated exposure.  This module assigns each
 * challenge a "freshness" score that decays with age, solve count, and
 * exposure frequency, then auto-retires challenges below a threshold.
 *
 * @param {object} [options]
 * @param {number} [options.maxAge=86400000]          Max challenge age (ms) before forced retirement (default 24h)
 * @param {number} [options.maxSolves=500]            Max total solves before retirement
 * @param {number} [options.maxExposures=1000]        Max times a challenge was shown
 * @param {number} [options.freshnessThreshold=0.2]   Freshness below this triggers retirement (0–1)
 * @param {number} [options.halfLifeMs=43200000]      Half-life for time-based decay (default 12h)
 * @param {number} [options.solveHalfLife=250]        Half-life for solve-count decay
 * @param {number} [options.maxChallenges=5000]       Max tracked challenges
 * @param {function} [options.onRetire]               Callback(challengeId, stats) when a challenge is retired
 * @param {function} [options.now]                    Time source (default Date.now)
 * @returns {object}
 */
function createChallengeDecayManager(options) {
  options = options || {};

  var maxAge = options.maxAge != null && options.maxAge > 0 ? options.maxAge : 86400000;
  var maxSolves = options.maxSolves != null && options.maxSolves > 0 ? options.maxSolves : 500;
  var maxExposures = options.maxExposures != null && options.maxExposures > 0 ? options.maxExposures : 1000;
  var freshnessThreshold = options.freshnessThreshold != null && options.freshnessThreshold >= 0
    ? options.freshnessThreshold : 0.2;
  var halfLifeMs = options.halfLifeMs != null && options.halfLifeMs > 0 ? options.halfLifeMs : 43200000;
  var solveHalfLife = options.solveHalfLife != null && options.solveHalfLife > 0 ? options.solveHalfLife : 250;
  var maxChallenges = options.maxChallenges != null && options.maxChallenges > 0 ? options.maxChallenges : 5000;
  var onRetire = typeof options.onRetire === "function" ? options.onRetire : null;
  var _now = typeof options.now === "function" ? options.now : function() { return Date.now(); };

  // challengeId -> { addedAt, solves, exposures, correctSolves, lastSolvedAt, lastExposedAt, retired }
  var challenges = Object.create(null);
  var challengeCount = 0;
  var retiredCount = 0;

  // ── Freshness Calculation ────────────────────────────────────────

  /**
   * Exponential decay: returns value between 0 and 1.
   * f(t) = 2^(-t / halfLife)
   */
  function _decay(value, halfLife) {
    if (halfLife <= 0) return 0;
    return Math.pow(2, -(value / halfLife));
  }

  /**
   * Calculate the freshness score (0–1) for a challenge.
   *
   * Combines three decay dimensions:
   *   - Time decay (40%): based on age since creation
   *   - Solve decay (35%): based on total solve count
   *   - Exposure decay (25%): based on total exposure count
   *
   * A challenge that exceeds maxAge, maxSolves, or maxExposures
   * immediately gets 0 freshness in that dimension.
   */
  function _computeFreshness(entry) {
    var age = _now() - entry.addedAt;

    // Time dimension (40% weight)
    var timeFreshness = age >= maxAge ? 0 : _decay(age, halfLifeMs);

    // Solve dimension (35% weight)
    var solveFreshness = entry.solves >= maxSolves ? 0 : _decay(entry.solves, solveHalfLife);

    // Exposure dimension (25% weight)
    var exposureFreshness = entry.exposures >= maxExposures ? 0 : _decay(entry.exposures, solveHalfLife * 2);

    return timeFreshness * 0.40 + solveFreshness * 0.35 + exposureFreshness * 0.25;
  }

  // ── Challenge Management ─────────────────────────────────────────

  /**
   * Register a new challenge in the pool.
   * @param {string} challengeId - Unique challenge identifier.
   * @param {object} [meta] - Optional metadata to attach.
   * @returns {{ challengeId: string, freshness: number }}
   */
  function addChallenge(challengeId, meta) {
    if (!challengeId || typeof challengeId !== "string") {
      throw new Error("challengeId must be a non-empty string");
    }
    if (challenges[challengeId]) {
      throw new Error("Challenge '" + challengeId + "' already exists");
    }
    if (challengeCount >= maxChallenges) {
      throw new Error("Maximum challenges (" + maxChallenges + ") reached");
    }

    challenges[challengeId] = {
      addedAt: _now(),
      solves: 0,
      correctSolves: 0,
      exposures: 0,
      lastSolvedAt: null,
      lastExposedAt: null,
      retired: false,
      meta: meta || null
    };
    challengeCount++;

    return { challengeId: challengeId, freshness: 1 };
  }

  /**
   * Record that a challenge was shown to a user.
   * @param {string} challengeId
   * @returns {{ freshness: number, retired: boolean }}
   */
  function recordExposure(challengeId) {
    var entry = challenges[challengeId];
    if (!entry) throw new Error("Unknown challenge: " + challengeId);
    if (entry.retired) return { freshness: 0, retired: true };

    entry.exposures++;
    entry.lastExposedAt = _now();

    var freshness = _computeFreshness(entry);
    if (freshness < freshnessThreshold) {
      _retire(challengeId, entry);
      return { freshness: freshness, retired: true };
    }

    return { freshness: Math.round(freshness * 10000) / 10000, retired: false };
  }

  /**
   * Record a solve attempt for a challenge.
   * @param {string} challengeId
   * @param {boolean} correct - Whether the solve was correct.
   * @returns {{ freshness: number, retired: boolean }}
   */
  function recordSolve(challengeId, correct) {
    var entry = challenges[challengeId];
    if (!entry) throw new Error("Unknown challenge: " + challengeId);
    if (entry.retired) return { freshness: 0, retired: true };

    entry.solves++;
    if (correct) entry.correctSolves++;
    entry.lastSolvedAt = _now();

    var freshness = _computeFreshness(entry);
    if (freshness < freshnessThreshold) {
      _retire(challengeId, entry);
      return { freshness: freshness, retired: true };
    }

    return { freshness: Math.round(freshness * 10000) / 10000, retired: false };
  }

  /**
   * Retire a challenge — mark as inactive, fire callback.
   */
  function _retire(challengeId, entry) {
    if (entry.retired) return;
    entry.retired = true;
    retiredCount++;
    if (onRetire) {
      onRetire(challengeId, _buildStats(challengeId, entry));
    }
  }

  /**
   * Manually retire a challenge.
   * @param {string} challengeId
   * @returns {boolean} True if retired (false if already retired or unknown).
   */
  function retire(challengeId) {
    var entry = challenges[challengeId];
    if (!entry || entry.retired) return false;
    _retire(challengeId, entry);
    return true;
  }

  /**
   * Build stats object for a challenge entry.
   */
  function _buildStats(challengeId, entry) {
    var freshness = entry.retired ? 0 : _computeFreshness(entry);
    return {
      challengeId: challengeId,
      addedAt: entry.addedAt,
      ageMs: _now() - entry.addedAt,
      solves: entry.solves,
      correctSolves: entry.correctSolves,
      solveRate: entry.solves > 0 ? Math.round((entry.correctSolves / entry.solves) * 10000) / 10000 : null,
      exposures: entry.exposures,
      lastSolvedAt: entry.lastSolvedAt,
      lastExposedAt: entry.lastExposedAt,
      freshness: Math.round(freshness * 10000) / 10000,
      retired: entry.retired,
      meta: entry.meta
    };
  }

  /**
   * Get stats for a specific challenge.
   * @param {string} challengeId
   * @returns {object|null}
   */
  function getStats(challengeId) {
    var entry = challenges[challengeId];
    return entry ? _buildStats(challengeId, entry) : null;
  }

  /**
   * Get freshness score for a challenge.
   * @param {string} challengeId
   * @returns {number} Freshness 0–1, or -1 if unknown.
   */
  function getFreshness(challengeId) {
    var entry = challenges[challengeId];
    if (!entry) return -1;
    if (entry.retired) return 0;
    return Math.round(_computeFreshness(entry) * 10000) / 10000;
  }

  /**
   * Run a sweep: check all active challenges and retire any below threshold.
   * Returns a list of newly retired challenge IDs.
   * @returns {{ retired: string[], poolHealth: object }}
   */
  function sweep() {
    var newlyRetired = [];
    var keys = Object.keys(challenges);
    for (var i = 0; i < keys.length; i++) {
      var entry = challenges[keys[i]];
      if (entry.retired) continue;
      var freshness = _computeFreshness(entry);
      if (freshness < freshnessThreshold) {
        _retire(keys[i], entry);
        newlyRetired.push(keys[i]);
      }
    }
    return { retired: newlyRetired, poolHealth: getPoolHealth() };
  }

  /**
   * Get overall pool health metrics.
   * @returns {object}
   */
  function getPoolHealth() {
    var keys = Object.keys(challenges);
    var active = 0;
    var totalFreshness = 0;
    var fresh = 0;     // freshness >= 0.7
    var stale = 0;     // freshness 0.2–0.7
    var critical = 0;  // freshness < 0.2 (but not yet retired)
    var oldest = null;
    var mostSolved = null;

    for (var i = 0; i < keys.length; i++) {
      var entry = challenges[keys[i]];
      if (entry.retired) continue;
      active++;
      var f = _computeFreshness(entry);
      totalFreshness += f;

      if (f >= 0.7) fresh++;
      else if (f >= freshnessThreshold) stale++;
      else critical++;

      if (!oldest || entry.addedAt < challenges[oldest].addedAt) oldest = keys[i];
      if (!mostSolved || entry.solves > challenges[mostSolved].solves) mostSolved = keys[i];
    }

    return {
      totalChallenges: challengeCount,
      activeChallenges: active,
      retiredChallenges: retiredCount,
      averageFreshness: active > 0 ? Math.round((totalFreshness / active) * 10000) / 10000 : 0,
      freshCount: fresh,
      staleCount: stale,
      criticalCount: critical,
      needsRefresh: fresh === 0 && active > 0,
      oldestActive: oldest,
      mostSolvedActive: mostSolved
    };
  }

  /**
   * Get the N freshest active challenges (for preferential selection).
   * @param {number} [n=10] - Number to return.
   * @returns {object[]} Array of stats objects, sorted by freshness desc.
   */
  function getFreshest(n) {
    n = n != null && n > 0 ? n : 10;
    var scored = [];
    var keys = Object.keys(challenges);
    for (var i = 0; i < keys.length; i++) {
      var entry = challenges[keys[i]];
      if (entry.retired) continue;
      scored.push({ id: keys[i], freshness: _computeFreshness(entry) });
    }
    scored.sort(function(a, b) { return b.freshness - a.freshness; });
    var result = [];
    for (var j = 0; j < Math.min(n, scored.length); j++) {
      result.push(_buildStats(scored[j].id, challenges[scored[j].id]));
    }
    return result;
  }

  /**
   * Get the N stalest active challenges (candidates for retirement).
   * @param {number} [n=10]
   * @returns {object[]}
   */
  function getStalest(n) {
    n = n != null && n > 0 ? n : 10;
    var scored = [];
    var keys = Object.keys(challenges);
    for (var i = 0; i < keys.length; i++) {
      var entry = challenges[keys[i]];
      if (entry.retired) continue;
      scored.push({ id: keys[i], freshness: _computeFreshness(entry) });
    }
    scored.sort(function(a, b) { return a.freshness - b.freshness; });
    var result = [];
    for (var j = 0; j < Math.min(n, scored.length); j++) {
      result.push(_buildStats(scored[j].id, challenges[scored[j].id]));
    }
    return result;
  }

  /**
   * Remove a challenge entirely (active or retired).
   * @param {string} challengeId
   * @returns {boolean}
   */
  function remove(challengeId) {
    var entry = challenges[challengeId];
    if (!entry) return false;
    if (entry.retired) retiredCount--;
    delete challenges[challengeId];
    challengeCount--;
    return true;
  }

  /**
   * Reset all data.
   */
  function reset() {
    challenges = Object.create(null);
    challengeCount = 0;
    retiredCount = 0;
  }

  return {
    addChallenge: addChallenge,
    recordExposure: recordExposure,
    recordSolve: recordSolve,
    retire: retire,
    getStats: getStats,
    getFreshness: getFreshness,
    sweep: sweep,
    getPoolHealth: getPoolHealth,
    getFreshest: getFreshest,
    getStalest: getStalest,
    remove: remove,
    reset: reset
  };
}

module.exports = { createChallengeDecayManager: createChallengeDecayManager };
