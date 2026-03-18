/**
 * ChallengePoolManager — Pre-generated challenge pool for instant CAPTCHA serving.
 *
 * Maintains a ready pool of CAPTCHA challenges so they can be served instantly
 * instead of generating on-demand. Supports auto-replenishment, priority lanes,
 * difficulty tiers, pool health monitoring, and warm-up strategies.
 *
 * No external dependencies — pure JavaScript, no timers, no I/O.
 * Generation is pluggable via a factory callback.
 *
 * @example
 *   var pool = createChallengePoolManager({
 *     factory: function(tier) {
 *       return { id: Math.random().toString(36).slice(2), tier: tier, frames: 8 };
 *     },
 *     tiers: ['easy', 'medium', 'hard'],
 *     targetSize: 50,
 *     minSize: 10,
 *     maxAge: 300000  // 5 minutes
 *   });
 *
 *   pool.warmUp();  // pre-fill the pool
 *   var challenge = pool.take('medium');
 *   // challenge => { id: 'abc123', tier: 'medium', frames: 8 }
 *
 *   var health = pool.health();
 *   // health => { total: 147, tiers: { easy: 49, medium: 48, hard: 50 }, ... }
 *
 * @module challenge-pool-manager
 */

"use strict";

// -- Cryptographic randomness (CWE-330 mitigation) --
var _cryptoUtils = require("./crypto-utils");
var _secureRandom = _cryptoUtils.secureRandom;
var _secureRandomHex = _cryptoUtils.secureRandomHex;

// ── Defaults ────────────────────────────────────────────────────────

var DEFAULT_TARGET_SIZE = 50;       // per tier
var DEFAULT_MIN_SIZE = 10;          // trigger replenish below this
var DEFAULT_MAX_AGE = 300000;       // 5 min TTL
var DEFAULT_MAX_POOL_SIZE = 500;    // absolute cap per tier
var DEFAULT_TIERS = ["easy", "medium", "hard"];
var DEFAULT_REPLENISH_BATCH = 10;   // generate this many per replenish call
var DEFAULT_PRIORITY_RESERVE = 5;   // reserved slots for priority takes

// ── Validation ──────────────────────────────────────────────────────

function _validateOptions(opts) {
  if (typeof opts.factory !== "function") {
    throw new Error("ChallengePoolManager: factory must be a function");
  }
  if (opts.targetSize != null && (typeof opts.targetSize !== "number" || opts.targetSize < 1)) {
    throw new Error("ChallengePoolManager: targetSize must be a positive number");
  }
  if (opts.minSize != null && (typeof opts.minSize !== "number" || opts.minSize < 0)) {
    throw new Error("ChallengePoolManager: minSize must be a non-negative number");
  }
  if (opts.maxAge != null && (typeof opts.maxAge !== "number" || opts.maxAge < 0)) {
    throw new Error("ChallengePoolManager: maxAge must be a non-negative number");
  }
  if (opts.tiers != null) {
    if (!Array.isArray(opts.tiers) || opts.tiers.length === 0) {
      throw new Error("ChallengePoolManager: tiers must be a non-empty array");
    }
    for (var i = 0; i < opts.tiers.length; i++) {
      if (typeof opts.tiers[i] !== "string" || opts.tiers[i].length === 0) {
        throw new Error("ChallengePoolManager: each tier must be a non-empty string");
      }
    }
  }
  if (opts.maxPoolSize != null && (typeof opts.maxPoolSize !== "number" || opts.maxPoolSize < 1)) {
    throw new Error("ChallengePoolManager: maxPoolSize must be a positive number");
  }
}

function _posOpt(val, fallback) {
  return val != null && val > 0 ? val : fallback;
}

function _nnOpt(val, fallback) {
  return val != null && val >= 0 ? val : fallback;
}

// ── Pool Entry ──────────────────────────────────────────────────────

function _createEntry(challenge, tier, now) {
  return {
    challenge: challenge,
    tier: tier,
    createdAt: now,
    id: challenge.id || _secureRandomHex(16)
  };
}

// ── Core ────────────────────────────────────────────────────────────

/**
 * Create a ChallengePoolManager instance.
 *
 * @param {Object}   options
 * @param {Function} options.factory         - Called as factory(tier) to generate a challenge
 * @param {string[]} [options.tiers]         - Difficulty tiers (default: easy/medium/hard)
 * @param {number}   [options.targetSize]    - Target pool size per tier (default: 50)
 * @param {number}   [options.minSize]       - Replenish trigger threshold per tier (default: 10)
 * @param {number}   [options.maxAge]        - Max age in ms before challenge expires (default: 300000)
 * @param {number}   [options.maxPoolSize]   - Absolute max per tier (default: 500)
 * @param {number}   [options.replenishBatch]- Challenges to generate per replenish call (default: 10)
 * @param {number}   [options.priorityReserve]- Reserved slots for priority takes (default: 5)
 * @param {Function} [options.nowFn]         - Custom time function for testing (default: Date.now)
 * @returns {Object} ChallengePoolManager instance
 */
function createChallengePoolManager(options) {
  var opts = options || {};
  _validateOptions(opts);

  var factory = opts.factory;
  var tiers = opts.tiers || DEFAULT_TIERS.slice();
  var targetSize = _posOpt(opts.targetSize, DEFAULT_TARGET_SIZE);
  var minSize = _nnOpt(opts.minSize, DEFAULT_MIN_SIZE);
  var maxAge = _nnOpt(opts.maxAge, DEFAULT_MAX_AGE);
  var maxPoolSize = _posOpt(opts.maxPoolSize, DEFAULT_MAX_POOL_SIZE);
  var replenishBatch = _posOpt(opts.replenishBatch, DEFAULT_REPLENISH_BATCH);
  var priorityReserve = _nnOpt(opts.priorityReserve, DEFAULT_PRIORITY_RESERVE);
  var nowFn = typeof opts.nowFn === "function" ? opts.nowFn : Date.now;

  // tier name → boolean lookup
  var tierSet = Object.create(null);
  for (var i = 0; i < tiers.length; i++) {
    tierSet[tiers[i]] = true;
  }

  // Storage: tier → array of entries (FIFO)
  var pools = Object.create(null);
  for (var t = 0; t < tiers.length; t++) {
    pools[tiers[t]] = [];
  }

  // Stats
  var stats = {
    totalGenerated: 0,
    totalServed: 0,
    totalExpired: 0,
    totalReplenishments: 0,
    servedByTier: Object.create(null),
    generatedByTier: Object.create(null),
    missCount: 0       // times pool was empty on take
  };
  for (var s = 0; s < tiers.length; s++) {
    stats.servedByTier[tiers[s]] = 0;
    stats.generatedByTier[tiers[s]] = 0;
  }

  // ── Internal helpers ────────────────────────────────────────────

  function _purgeExpired(tier) {
    if (maxAge === 0) return 0; // 0 means no expiry
    var now = nowFn();
    var pool = pools[tier];
    var cutoff = now - maxAge;
    // Binary search for first non-expired entry — O(log n)
    // then splice once — O(n) total, instead of repeated
    // shift() which is O(n) per call = O(n²) overall
    var lo = 0, hi = pool.length;
    while (lo < hi) {
      var mid = (lo + hi) >>> 1;
      if (pool[mid].createdAt < cutoff) lo = mid + 1;
      else hi = mid;
    }
    if (lo === 0) return 0;
    pool.splice(0, lo);
    stats.totalExpired += lo;
    return lo;
  }

  function _generate(tier, count) {
    var pool = pools[tier];
    var now = nowFn();
    var generated = 0;
    for (var i = 0; i < count; i++) {
      if (pool.length >= maxPoolSize) break;
      var challenge = factory(tier);
      if (challenge == null) continue;
      pool.push(_createEntry(challenge, tier, now));
      generated++;
    }
    stats.totalGenerated += generated;
    stats.generatedByTier[tier] += generated;
    return generated;
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Take a challenge from the pool.
   *
   * @param {string} [tier]      - Difficulty tier (default: random tier)
   * @param {Object} [options]
   * @param {boolean} [options.priority] - Use priority lane (bypasses low-pool guard)
   * @returns {Object|null} The challenge object, or null if pool empty
   */
  function take(tier, takeOpts) {
    var t = tier || tiers[Math.floor(_secureRandom() * tiers.length)];
    if (!tierSet[t]) return null;

    _purgeExpired(t);

    var pool = pools[t];
    var isPriority = takeOpts && takeOpts.priority === true;

    // Guard non-priority takes when pool is critically low
    if (!isPriority && pool.length <= priorityReserve && pool.length > 0) {
      stats.missCount++;
      return null;
    }

    if (pool.length === 0) {
      stats.missCount++;
      // Emergency generate one
      var challenge = factory(t);
      if (challenge == null) return null;
      stats.totalGenerated++;
      stats.generatedByTier[t]++;
      stats.totalServed++;
      stats.servedByTier[t]++;
      return challenge;
    }

    var entry = pool.shift();
    stats.totalServed++;
    stats.servedByTier[t]++;
    return entry.challenge;
  }

  /**
   * Warm up the pool by pre-filling all tiers to target size.
   *
   * @returns {Object} Map of tier → number generated
   */
  function warmUp() {
    var result = Object.create(null);
    for (var i = 0; i < tiers.length; i++) {
      var t = tiers[i];
      _purgeExpired(t);
      var deficit = targetSize - pools[t].length;
      if (deficit > 0) {
        result[t] = _generate(t, deficit);
      } else {
        result[t] = 0;
      }
    }
    return result;
  }

  /**
   * Replenish tiers that have fallen below minSize.
   * Called periodically or after heavy usage.
   *
   * @returns {Object} { replenished: string[], counts: { tier: n } }
   */
  function replenish() {
    var replenished = [];
    var counts = Object.create(null);
    for (var i = 0; i < tiers.length; i++) {
      var t = tiers[i];
      _purgeExpired(t);
      if (pools[t].length < minSize) {
        var needed = Math.min(replenishBatch, targetSize - pools[t].length);
        if (needed > 0) {
          counts[t] = _generate(t, needed);
          replenished.push(t);
        }
      }
    }
    if (replenished.length > 0) {
      stats.totalReplenishments++;
    }
    return { replenished: replenished, counts: counts };
  }

  /**
   * Get pool health status.
   *
   * @returns {Object} Health report
   */
  function health() {
    var total = 0;
    var tierCounts = Object.create(null);
    var tierHealth = Object.create(null);
    var warnings = [];
    var now = nowFn();

    for (var i = 0; i < tiers.length; i++) {
      var t = tiers[i];
      _purgeExpired(t);
      var pool = pools[t];
      var count = pool.length;
      total += count;
      tierCounts[t] = count;

      var pct = targetSize > 0 ? Math.round((count / targetSize) * 100) : 0;
      tierHealth[t] = pct >= 80 ? "healthy" : pct >= 40 ? "degraded" : "critical";

      if (count < minSize) {
        warnings.push(t + " pool below minimum (" + count + "/" + minSize + ")");
      }
      if (count === 0) {
        warnings.push(t + " pool EMPTY");
      }

      // Check age of oldest entry
      if (pool.length > 0 && maxAge > 0) {
        var oldest = pool[0];
        var age = now - oldest.createdAt;
        if (age > maxAge * 0.8) {
          warnings.push(t + " has entries near expiry (" + Math.round(age / 1000) + "s old)");
        }
      }
    }

    return {
      total: total,
      tiers: tierCounts,
      tierHealth: tierHealth,
      warnings: warnings,
      status: warnings.length === 0 ? "healthy" : warnings.some(function(w) { return w.indexOf("EMPTY") >= 0; }) ? "critical" : "degraded",
      stats: {
        totalGenerated: stats.totalGenerated,
        totalServed: stats.totalServed,
        totalExpired: stats.totalExpired,
        totalReplenishments: stats.totalReplenishments,
        missCount: stats.missCount,
        hitRate: stats.totalServed > 0 ? Math.round(((stats.totalServed - stats.missCount) / stats.totalServed) * 10000) / 100 : 100
      }
    };
  }

  /**
   * Get the current size of a specific tier's pool.
   *
   * @param {string} tier
   * @returns {number}
   */
  function size(tier) {
    if (!tierSet[tier]) return 0;
    _purgeExpired(tier);
    return pools[tier].length;
  }

  /**
   * Drain (empty) a tier or all tiers.
   *
   * @param {string} [tier] - Specific tier to drain, or omit for all
   * @returns {number} Number of challenges discarded
   */
  function drain(tier) {
    var count = 0;
    if (tier) {
      if (!tierSet[tier]) return 0;
      count = pools[tier].length;
      pools[tier] = [];
    } else {
      for (var i = 0; i < tiers.length; i++) {
        count += pools[tiers[i]].length;
        pools[tiers[i]] = [];
      }
    }
    return count;
  }

  /**
   * Reset all stats counters.
   */
  function resetStats() {
    stats.totalGenerated = 0;
    stats.totalServed = 0;
    stats.totalExpired = 0;
    stats.totalReplenishments = 0;
    stats.missCount = 0;
    for (var i = 0; i < tiers.length; i++) {
      stats.servedByTier[tiers[i]] = 0;
      stats.generatedByTier[tiers[i]] = 0;
    }
  }

  /**
   * Get detailed stats.
   *
   * @returns {Object} Statistics snapshot
   */
  function getStats() {
    return {
      totalGenerated: stats.totalGenerated,
      totalServed: stats.totalServed,
      totalExpired: stats.totalExpired,
      totalReplenishments: stats.totalReplenishments,
      missCount: stats.missCount,
      servedByTier: _copyObj(stats.servedByTier),
      generatedByTier: _copyObj(stats.generatedByTier)
    };
  }

  /**
   * Peek at the next challenge without removing it.
   *
   * @param {string} [tier]
   * @returns {Object|null}
   */
  function peek(tier) {
    var t = tier || tiers[0];
    if (!tierSet[t]) return null;
    _purgeExpired(t);
    var pool = pools[t];
    return pool.length > 0 ? pool[0].challenge : null;
  }

  /**
   * Get the list of configured tiers.
   *
   * @returns {string[]}
   */
  function getTiers() {
    return tiers.slice();
  }

  /**
   * Export pool contents for persistence/debugging.
   *
   * @returns {Object} Serializable pool snapshot
   */
  function exportPool() {
    var result = Object.create(null);
    for (var i = 0; i < tiers.length; i++) {
      var t = tiers[i];
      _purgeExpired(t);
      result[t] = pools[t].map(function(e) {
        return { challenge: e.challenge, tier: e.tier, createdAt: e.createdAt, id: e.id };
      });
    }
    return result;
  }

  /**
   * Import challenges into the pool (e.g., from persistence).
   *
   * @param {Object} data - Map of tier → array of { challenge, createdAt }
   * @returns {number} Number of entries imported
   */
  function importPool(data) {
    if (data == null || typeof data !== "object") return 0;
    var count = 0;
    var now = nowFn();
    for (var i = 0; i < tiers.length; i++) {
      var t = tiers[i];
      var entries = data[t];
      if (!Array.isArray(entries)) continue;
      for (var j = 0; j < entries.length; j++) {
        if (pools[t].length >= maxPoolSize) break;
        var e = entries[j];
        if (e == null || e.challenge == null) continue;
        var createdAt = e.createdAt || now;
        // Skip expired
        if (maxAge > 0 && now - createdAt >= maxAge) continue;
        pools[t].push(_createEntry(e.challenge, t, createdAt));
        count++;
      }
    }
    return count;
  }

  function _copyObj(obj) {
    var copy = Object.create(null);
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      copy[keys[i]] = obj[keys[i]];
    }
    return copy;
  }

  return {
    take: take,
    warmUp: warmUp,
    replenish: replenish,
    health: health,
    size: size,
    drain: drain,
    resetStats: resetStats,
    getStats: getStats,
    peek: peek,
    getTiers: getTiers,
    exportPool: exportPool,
    importPool: importPool
  };
}

// ── Exports ─────────────────────────────────────────────────────────

module.exports = { createChallengePoolManager: createChallengePoolManager };
