/**
 * CaptchaRateLimiter — Multi-algorithm rate limiting for CAPTCHA requests.
 *
 * Provides per-key rate limiting with three algorithms:
 *   - **Sliding window**: Counts requests in a rolling time window
 *   - **Token bucket**: Allows bursts up to a capacity, refills at a steady rate
 *   - **Leaky bucket**: Smooths request flow, rejects when queue is full
 *
 * Keys are typically IP addresses, session IDs, or user fingerprints.
 * No external dependencies — pure JavaScript, no timers, no I/O.
 *
 * @example
 *   var limiter = createCaptchaRateLimiter({
 *     algorithm: 'sliding-window',
 *     windowMs: 60000,
 *     maxRequests: 10
 *   });
 *   var result = limiter.check('192.168.1.1');
 *   // result => { allowed: true, remaining: 9, retryAfterMs: 0, ... }
 *
 *   // Token bucket for burst-tolerant limiting
 *   var burst = createCaptchaRateLimiter({
 *     algorithm: 'token-bucket',
 *     capacity: 20,
 *     refillRate: 2   // tokens per second
 *   });
 *
 * @module captcha-rate-limiter
 */

"use strict";

// ── Defaults ────────────────────────────────────────────────────────

var DEFAULT_WINDOW_MS = 60000;       // 1 minute
var DEFAULT_MAX_REQUESTS = 10;
var DEFAULT_CAPACITY = 20;
var DEFAULT_REFILL_RATE = 2;         // tokens/sec
var DEFAULT_LEAK_RATE = 1;           // requests/sec
var DEFAULT_QUEUE_SIZE = 30;
var DEFAULT_CLEANUP_INTERVAL = 300;  // every 300 checks
var DEFAULT_MAX_KEYS = 50000;
var DEFAULT_BAN_DURATION_MS = 300000; // 5 min ban
var DEFAULT_BAN_THRESHOLD = 3;       // strikes before ban

var ALGORITHMS = Object.create(null);
ALGORITHMS["sliding-window"] = true;
ALGORITHMS["token-bucket"] = true;
ALGORITHMS["leaky-bucket"] = true;

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Binary search for the first index >= target in a sorted array.
 * Used for efficiently trimming expired timestamps in sliding window.
 */
function _lowerBound(arr, target) {
  var lo = 0;
  var hi = arr.length;
  while (lo < hi) {
    var mid = (lo + hi) >>> 1;
    if (arr[mid] < target) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return lo;
}

/**
 * Evict oldest entries when key count exceeds maxKeys.
 * Uses LRU-style eviction based on lastSeen timestamp.
 */
function _evictOldest(store, maxKeys) {
  var keys = Object.keys(store);
  if (keys.length <= maxKeys) return 0;

  // Sort by lastSeen ascending — evict oldest first
  var entries = [];
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    entries.push({ key: k, lastSeen: store[k].lastSeen || 0 });
  }
  entries.sort(function (a, b) { return a.lastSeen - b.lastSeen; });

  var toRemove = keys.length - maxKeys;
  var removed = 0;
  for (var j = 0; j < toRemove; j++) {
    delete store[entries[j].key];
    removed++;
  }
  return removed;
}

// ── Factory ─────────────────────────────────────────────────────────

/**
 * Create a rate limiter instance.
 *
 * @param {Object} [options]
 * @param {string} [options.algorithm='sliding-window'] - Algorithm: 'sliding-window' | 'token-bucket' | 'leaky-bucket'
 * @param {number} [options.windowMs=60000] - Window size in ms (sliding-window)
 * @param {number} [options.maxRequests=10] - Max requests per window (sliding-window)
 * @param {number} [options.capacity=20] - Token bucket capacity
 * @param {number} [options.refillRate=2] - Token refill rate (tokens/sec)
 * @param {number} [options.leakRate=1] - Leak rate (requests/sec, leaky-bucket)
 * @param {number} [options.queueSize=30] - Max queue size (leaky-bucket)
 * @param {number} [options.maxKeys=50000] - Max tracked keys before eviction
 * @param {number} [options.cleanupInterval=300] - Checks between cleanup sweeps
 * @param {boolean} [options.enableBans=false] - Auto-ban after repeated violations
 * @param {number} [options.banThreshold=3] - Consecutive rejections before ban
 * @param {number} [options.banDurationMs=300000] - Ban duration in ms
 * @returns {Object} Rate limiter instance
 */
function createCaptchaRateLimiter(options) {
  options = options || {};

  var algorithm = options.algorithm || "sliding-window";
  if (!ALGORITHMS[algorithm]) {
    throw new Error("Unknown algorithm: " + algorithm +
      ". Use: sliding-window, token-bucket, or leaky-bucket");
  }

  // Sliding window config
  var windowMs = options.windowMs || DEFAULT_WINDOW_MS;
  var maxRequests = options.maxRequests || DEFAULT_MAX_REQUESTS;

  // Token bucket config
  var capacity = options.capacity || DEFAULT_CAPACITY;
  var refillRate = options.refillRate || DEFAULT_REFILL_RATE;

  // Leaky bucket config
  var leakRate = options.leakRate || DEFAULT_LEAK_RATE;
  var queueSize = options.queueSize || DEFAULT_QUEUE_SIZE;

  // Shared config
  var maxKeys = options.maxKeys || DEFAULT_MAX_KEYS;
  var cleanupInterval = options.cleanupInterval || DEFAULT_CLEANUP_INTERVAL;
  var enableBans = !!options.enableBans;
  var banThreshold = options.banThreshold || DEFAULT_BAN_THRESHOLD;
  var banDurationMs = options.banDurationMs || DEFAULT_BAN_DURATION_MS;

  // State
  var store = Object.create(null);       // per-key rate state
  var bans = Object.create(null);        // per-key ban state
  var strikes = Object.create(null);     // per-key consecutive rejection count
  var checkCount = 0;
  var totalAllowed = 0;
  var totalRejected = 0;
  var totalBanned = 0;
  var evictions = 0;

  // ── Sliding Window ──────────────────────────────────────────────

  function _checkSlidingWindow(key, now) {
    var entry = store[key];
    if (!entry) {
      entry = { timestamps: [], lastSeen: now };
      store[key] = entry;
    }

    // Trim expired timestamps using binary search
    var cutoff = now - windowMs;
    var idx = _lowerBound(entry.timestamps, cutoff);
    if (idx > 0) {
      entry.timestamps = entry.timestamps.slice(idx);
    }

    entry.lastSeen = now;
    var count = entry.timestamps.length;

    if (count >= maxRequests) {
      // Rejected — compute retry-after from oldest timestamp in window
      var oldestInWindow = entry.timestamps[0];
      var retryAfterMs = oldestInWindow + windowMs - now;
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: Math.max(0, retryAfterMs),
        current: count,
        limit: maxRequests,
        windowMs: windowMs
      };
    }

    // Allowed — record timestamp
    entry.timestamps.push(now);
    return {
      allowed: true,
      remaining: maxRequests - count - 1,
      retryAfterMs: 0,
      current: count + 1,
      limit: maxRequests,
      windowMs: windowMs
    };
  }

  // ── Token Bucket ────────────────────────────────────────────────

  function _checkTokenBucket(key, now) {
    var entry = store[key];
    if (!entry) {
      entry = { tokens: capacity, lastRefill: now, lastSeen: now };
      store[key] = entry;
    }

    // Refill tokens based on elapsed time
    var elapsed = (now - entry.lastRefill) / 1000;
    var newTokens = elapsed * refillRate;
    entry.tokens = Math.min(capacity, entry.tokens + newTokens);
    entry.lastRefill = now;
    entry.lastSeen = now;

    if (entry.tokens < 1) {
      // Rejected — compute wait until 1 token available
      var deficit = 1 - entry.tokens;
      var retryAfterMs = Math.ceil((deficit / refillRate) * 1000);
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: retryAfterMs,
        tokens: Math.floor(entry.tokens),
        capacity: capacity,
        refillRate: refillRate
      };
    }

    // Consume one token
    entry.tokens -= 1;
    return {
      allowed: true,
      remaining: Math.floor(entry.tokens),
      retryAfterMs: 0,
      tokens: Math.floor(entry.tokens),
      capacity: capacity,
      refillRate: refillRate
    };
  }

  // ── Leaky Bucket ────────────────────────────────────────────────

  function _checkLeakyBucket(key, now) {
    var entry = store[key];
    if (!entry) {
      entry = { water: 0, lastLeak: now, lastSeen: now };
      store[key] = entry;
    }

    // Leak water based on elapsed time
    var elapsed = (now - entry.lastLeak) / 1000;
    var leaked = elapsed * leakRate;
    entry.water = Math.max(0, entry.water - leaked);
    entry.lastLeak = now;
    entry.lastSeen = now;

    if (entry.water >= queueSize) {
      // Queue full — reject
      var excess = entry.water - queueSize + 1;
      var retryAfterMs = Math.ceil((excess / leakRate) * 1000);
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: retryAfterMs,
        queueLevel: Math.floor(entry.water),
        queueSize: queueSize,
        leakRate: leakRate
      };
    }

    // Add to queue
    entry.water += 1;
    return {
      allowed: true,
      remaining: Math.floor(queueSize - entry.water),
      retryAfterMs: 0,
      queueLevel: Math.floor(entry.water),
      queueSize: queueSize,
      leakRate: leakRate
    };
  }

  // ── Dispatch ────────────────────────────────────────────────────

  var checkers = Object.create(null);
  checkers["sliding-window"] = _checkSlidingWindow;
  checkers["token-bucket"] = _checkTokenBucket;
  checkers["leaky-bucket"] = _checkLeakyBucket;

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Check if a request from the given key is allowed.
   *
   * @param {string} key - Identifier (IP, session ID, fingerprint)
   * @param {number} [now] - Current timestamp (default: Date.now())
   * @returns {Object} Result with allowed, remaining, retryAfterMs, etc.
   */
  function check(key, now) {
    if (!key || typeof key !== "string") {
      throw new Error("Key must be a non-empty string");
    }
    now = now || Date.now();
    checkCount++;

    // Periodic cleanup
    if (checkCount % cleanupInterval === 0) {
      _cleanup(now);
    }

    // Check ban status
    if (enableBans && bans[key]) {
      var ban = bans[key];
      if (now < ban.expiresAt) {
        totalRejected++;
        return {
          allowed: false,
          remaining: 0,
          retryAfterMs: ban.expiresAt - now,
          banned: true,
          banExpiresAt: ban.expiresAt,
          reason: "Temporarily banned after " + banThreshold + " consecutive rejections"
        };
      }
      // Ban expired — clear it
      delete bans[key];
      delete strikes[key];
    }

    // Run algorithm check
    var result = checkers[algorithm](key, now);

    // Track bans
    if (enableBans) {
      if (!result.allowed) {
        strikes[key] = (strikes[key] || 0) + 1;
        if (strikes[key] >= banThreshold) {
          bans[key] = { expiresAt: now + banDurationMs, bannedAt: now };
          totalBanned++;
          result.banned = true;
          result.banExpiresAt = now + banDurationMs;
          result.reason = "Banned after " + banThreshold + " consecutive rejections";
        }
      } else {
        // Reset strikes on successful request
        delete strikes[key];
      }
    }

    // Stats
    if (result.allowed) {
      totalAllowed++;
    } else {
      totalRejected++;
    }

    result.algorithm = algorithm;
    result.key = key;
    return result;
  }

  /**
   * Consume multiple tokens/requests at once (batch check).
   *
   * @param {string} key - Identifier
   * @param {number} count - Number of requests to consume
   * @param {number} [now] - Current timestamp
   * @returns {Object} Result for the batch
   */
  function consume(key, count, now) {
    if (count < 1 || !Number.isFinite(count)) {
      throw new Error("Count must be a positive finite number");
    }
    now = now || Date.now();

    // For simplicity, check one-by-one internally, but atomically
    var lastResult;
    for (var i = 0; i < count; i++) {
      lastResult = check(key, now);
      if (!lastResult.allowed) {
        lastResult.consumed = i;
        lastResult.requested = count;
        return lastResult;
      }
    }
    lastResult.consumed = count;
    lastResult.requested = count;
    return lastResult;
  }

  /**
   * Peek at rate limit status for a key without consuming a request.
   *
   * @param {string} key - Identifier
   * @param {number} [now] - Current timestamp
   * @returns {Object} Current status
   */
  function peek(key, now) {
    if (!key || typeof key !== "string") {
      throw new Error("Key must be a non-empty string");
    }
    now = now || Date.now();

    // Check ban
    if (enableBans && bans[key]) {
      if (now < bans[key].expiresAt) {
        return { allowed: false, banned: true, retryAfterMs: bans[key].expiresAt - now };
      }
    }

    var entry = store[key];
    if (!entry) {
      // No history — would be allowed
      if (algorithm === "sliding-window") {
        return { allowed: true, remaining: maxRequests, current: 0 };
      } else if (algorithm === "token-bucket") {
        return { allowed: true, remaining: capacity, tokens: capacity };
      } else {
        return { allowed: true, remaining: queueSize, queueLevel: 0 };
      }
    }

    // Simulate without mutating state
    if (algorithm === "sliding-window") {
      var cutoff = now - windowMs;
      var idx = _lowerBound(entry.timestamps, cutoff);
      var count = entry.timestamps.length - idx;
      return {
        allowed: count < maxRequests,
        remaining: Math.max(0, maxRequests - count),
        current: count,
        limit: maxRequests
      };
    } else if (algorithm === "token-bucket") {
      var elapsed = (now - entry.lastRefill) / 1000;
      var tokens = Math.min(capacity, entry.tokens + elapsed * refillRate);
      return {
        allowed: tokens >= 1,
        remaining: Math.floor(tokens),
        tokens: Math.floor(tokens),
        capacity: capacity
      };
    } else {
      var elapsedL = (now - entry.lastLeak) / 1000;
      var water = Math.max(0, entry.water - elapsedL * leakRate);
      return {
        allowed: water < queueSize,
        remaining: Math.floor(queueSize - water),
        queueLevel: Math.floor(water),
        queueSize: queueSize
      };
    }
  }

  /**
   * Manually ban a key.
   *
   * @param {string} key - Identifier
   * @param {number} [durationMs] - Ban duration (default: banDurationMs)
   * @param {number} [now] - Current timestamp
   */
  function ban(key, durationMs, now) {
    if (!key || typeof key !== "string") {
      throw new Error("Key must be a non-empty string");
    }
    now = now || Date.now();
    durationMs = durationMs || banDurationMs;
    bans[key] = { expiresAt: now + durationMs, bannedAt: now };
    totalBanned++;
  }

  /**
   * Manually unban a key.
   *
   * @param {string} key - Identifier
   * @returns {boolean} Whether the key was banned
   */
  function unban(key) {
    if (bans[key]) {
      delete bans[key];
      delete strikes[key];
      return true;
    }
    return false;
  }

  /**
   * Check if a key is currently banned.
   *
   * @param {string} key - Identifier
   * @param {number} [now] - Current timestamp
   * @returns {boolean}
   */
  function isBanned(key, now) {
    if (!bans[key]) return false;
    now = now || Date.now();
    if (now >= bans[key].expiresAt) {
      delete bans[key];
      return false;
    }
    return true;
  }

  /**
   * Reset rate limit state for a specific key.
   *
   * @param {string} key - Identifier
   * @returns {boolean} Whether the key existed
   */
  function reset(key) {
    var existed = !!store[key] || !!bans[key];
    delete store[key];
    delete bans[key];
    delete strikes[key];
    return existed;
  }

  /**
   * Reset all state for all keys.
   */
  function resetAll() {
    var keys = Object.keys(store);
    for (var i = 0; i < keys.length; i++) {
      delete store[keys[i]];
    }
    var banKeys = Object.keys(bans);
    for (var j = 0; j < banKeys.length; j++) {
      delete bans[banKeys[j]];
    }
    var strikeKeys = Object.keys(strikes);
    for (var k = 0; k < strikeKeys.length; k++) {
      delete strikes[strikeKeys[k]];
    }
    totalAllowed = 0;
    totalRejected = 0;
    totalBanned = 0;
    checkCount = 0;
    evictions = 0;
  }

  /**
   * Get aggregate statistics.
   *
   * @returns {Object} Stats: tracked keys, bans, requests, rejection rate
   */
  function getStats() {
    var keyCount = Object.keys(store).length;
    var banCount = Object.keys(bans).length;
    var total = totalAllowed + totalRejected;
    return {
      algorithm: algorithm,
      trackedKeys: keyCount,
      activeBans: banCount,
      totalChecks: total,
      totalAllowed: totalAllowed,
      totalRejected: totalRejected,
      totalBanned: totalBanned,
      rejectionRate: total > 0 ? totalRejected / total : 0,
      evictions: evictions,
      config: algorithm === "sliding-window"
        ? { windowMs: windowMs, maxRequests: maxRequests }
        : algorithm === "token-bucket"
          ? { capacity: capacity, refillRate: refillRate }
          : { queueSize: queueSize, leakRate: leakRate }
    };
  }

  /**
   * Get per-key status for monitoring / debug.
   *
   * @param {number} [limit=20] - Max keys to return
   * @param {string} [sortBy='recent'] - Sort: 'recent' | 'active' | 'strikes'
   * @returns {Array} Top keys with their current state
   */
  function getTopKeys(limit, sortBy) {
    limit = limit || 20;
    sortBy = sortBy || "recent";

    var keys = Object.keys(store);
    var entries = [];
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var e = store[k];
      var info = { key: k, lastSeen: e.lastSeen || 0 };
      if (algorithm === "sliding-window") {
        info.requestCount = e.timestamps ? e.timestamps.length : 0;
      } else if (algorithm === "token-bucket") {
        info.tokens = Math.floor(e.tokens || 0);
      } else {
        info.queueLevel = Math.floor(e.water || 0);
      }
      info.strikes = strikes[k] || 0;
      info.banned = !!bans[k];
      entries.push(info);
    }

    if (sortBy === "active") {
      entries.sort(function (a, b) {
        var aVal = a.requestCount || a.queueLevel || (capacity - (a.tokens || 0));
        var bVal = b.requestCount || b.queueLevel || (capacity - (b.tokens || 0));
        return bVal - aVal;
      });
    } else if (sortBy === "strikes") {
      entries.sort(function (a, b) { return b.strikes - a.strikes; });
    } else {
      entries.sort(function (a, b) { return b.lastSeen - a.lastSeen; });
    }

    return entries.slice(0, limit);
  }

  /**
   * Add a key to a whitelist — whitelisted keys are always allowed.
   * Returns a function to manage the whitelist.
   */
  var whitelist = Object.create(null);

  /**
   * Add key to whitelist.
   * @param {string} key
   */
  function whitelistAdd(key) {
    if (!key || typeof key !== "string") {
      throw new Error("Key must be a non-empty string");
    }
    whitelist[key] = true;
  }

  /**
   * Remove key from whitelist.
   * @param {string} key
   * @returns {boolean}
   */
  function whitelistRemove(key) {
    if (whitelist[key]) {
      delete whitelist[key];
      return true;
    }
    return false;
  }

  /**
   * Check if key is whitelisted.
   * @param {string} key
   * @returns {boolean}
   */
  function isWhitelisted(key) {
    return !!whitelist[key];
  }

  // Override check to respect whitelist
  var _originalCheck = check;
  check = function (key, now) {
    if (whitelist[key]) {
      return {
        allowed: true,
        remaining: Infinity,
        retryAfterMs: 0,
        whitelisted: true,
        algorithm: algorithm,
        key: key
      };
    }
    return _originalCheck(key, now);
  };

  // ── Cleanup ───────────────────────────────────────────────────

  function _cleanup(now) {
    now = now || Date.now();

    // Evict expired bans
    var banKeys = Object.keys(bans);
    for (var i = 0; i < banKeys.length; i++) {
      if (now >= bans[banKeys[i]].expiresAt) {
        delete bans[banKeys[i]];
        delete strikes[banKeys[i]];
      }
    }

    // Evict stale entries (sliding window: no timestamps in window)
    if (algorithm === "sliding-window") {
      var cutoff = now - windowMs * 2; // 2x window for grace
      var storeKeys = Object.keys(store);
      for (var j = 0; j < storeKeys.length; j++) {
        var entry = store[storeKeys[j]];
        if (entry.lastSeen < cutoff) {
          delete store[storeKeys[j]];
        }
      }
    }

    // LRU eviction if over maxKeys
    var removed = _evictOldest(store, maxKeys);
    evictions += removed;
  }

  // ── Serialization ─────────────────────────────────────────────

  /**
   * Export current state for persistence.
   * @returns {Object} Serializable state
   */
  function exportState() {
    return {
      algorithm: algorithm,
      store: JSON.parse(JSON.stringify(store)),
      bans: JSON.parse(JSON.stringify(bans)),
      strikes: JSON.parse(JSON.stringify(strikes)),
      stats: { totalAllowed: totalAllowed, totalRejected: totalRejected, totalBanned: totalBanned },
      exportedAt: Date.now()
    };
  }

  /**
   * Import previously exported state.
   * @param {Object} state - State from exportState()
   * @returns {number} Number of keys restored
   */
  function importState(state) {
    if (!state || typeof state !== "object") {
      throw new Error("Invalid state object");
    }
    if (state.algorithm && state.algorithm !== algorithm) {
      throw new Error("Algorithm mismatch: expected " + algorithm + ", got " + state.algorithm);
    }

    var count = 0;
    if (state.store) {
      var sKeys = Object.keys(state.store);
      for (var i = 0; i < sKeys.length; i++) {
        store[sKeys[i]] = state.store[sKeys[i]];
        count++;
      }
    }
    if (state.bans) {
      var bKeys = Object.keys(state.bans);
      for (var j = 0; j < bKeys.length; j++) {
        bans[bKeys[j]] = state.bans[bKeys[j]];
      }
    }
    if (state.strikes) {
      var kKeys = Object.keys(state.strikes);
      for (var k = 0; k < kKeys.length; k++) {
        strikes[kKeys[k]] = state.strikes[kKeys[k]];
      }
    }
    if (state.stats) {
      totalAllowed += state.stats.totalAllowed || 0;
      totalRejected += state.stats.totalRejected || 0;
      totalBanned += state.stats.totalBanned || 0;
    }
    return count;
  }

  // ── Return public API ─────────────────────────────────────────

  return {
    check: check,
    consume: consume,
    peek: peek,
    ban: ban,
    unban: unban,
    isBanned: isBanned,
    reset: reset,
    resetAll: resetAll,
    getStats: getStats,
    getTopKeys: getTopKeys,
    whitelistAdd: whitelistAdd,
    whitelistRemove: whitelistRemove,
    isWhitelisted: isWhitelisted,
    exportState: exportState,
    importState: importState
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createCaptchaRateLimiter: createCaptchaRateLimiter };
}
