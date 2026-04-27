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
 *
 * Uses a partial-selection approach (O(n)) instead of sorting all keys
 * (O(n log n)).  When only a handful of entries need evicting — the
 * common case — we maintain a small max-heap of the `toRemove` oldest
 * entries and scan once through the store.  For 50k keys this avoids
 * an expensive full sort on every cleanup sweep.
 */
function _evictOldest(store, maxKeys) {
  var keys = Object.keys(store);
  var total = keys.length;
  if (total <= maxKeys) return 0;

  var toRemove = total - maxKeys;

  // For very large evictions (>25% of keys) fall back to full sort —
  // partial selection isn't advantageous when k is close to n.
  if (toRemove > (total >>> 2)) {
    var entries = [];
    for (var s = 0; s < total; s++) {
      entries.push({ key: keys[s], lastSeen: store[keys[s]].lastSeen || 0 });
    }
    entries.sort(function (a, b) { return a.lastSeen - b.lastSeen; });
    for (var r = 0; r < toRemove; r++) {
      delete store[entries[r].key];
    }
    return toRemove;
  }

  // Partial selection: maintain a small array of the `toRemove` oldest
  // entries (by lastSeen), with the maximum tracked so we can skip
  // entries that are newer than everything in our eviction set.
  var evictSet = []; // {key, lastSeen}[]  length <= toRemove
  var maxInSet = -Infinity;

  for (var i = 0; i < total; i++) {
    var k = keys[i];
    var ls = store[k].lastSeen || 0;

    if (evictSet.length < toRemove) {
      evictSet.push({ key: k, lastSeen: ls });
      if (ls > maxInSet) maxInSet = ls;
    } else if (ls < maxInSet) {
      // Replace the newest entry in evictSet with this older one
      var maxIdx = 0;
      for (var m = 1; m < evictSet.length; m++) {
        if (evictSet[m].lastSeen > evictSet[maxIdx].lastSeen) maxIdx = m;
      }
      evictSet[maxIdx] = { key: k, lastSeen: ls };
      // Recompute max
      maxInSet = evictSet[0].lastSeen;
      for (var n = 1; n < evictSet.length; n++) {
        if (evictSet[n].lastSeen > maxInSet) maxInSet = evictSet[n].lastSeen;
      }
    }
  }

  for (var j = 0; j < evictSet.length; j++) {
    delete store[evictSet[j].key];
  }
  return evictSet.length;
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

  // ── Shared Helpers ──────────────────────────────────────────────

  /**
   * Validate that key is a non-empty string.
   * @param {string} key
   * @throws {Error} If key is falsy or not a string
   */
  function _validateKey(key) {
    if (!key || typeof key !== "string") {
      throw new Error("Key must be a non-empty string");
    }
  }

  /**
   * Check if a key is currently banned.
   * @param {string} key
   * @param {number} now - Current timestamp
   * @returns {Object|null} Ban result object if banned, null otherwise
   */
  function _checkBanStatus(key, now) {
    if (!enableBans || !bans[key]) return null;
    var ban = bans[key];
    if (now < ban.expiresAt) {
      return { banned: true, expiresAt: ban.expiresAt, retryAfterMs: ban.expiresAt - now };
    }
    // Ban expired — clean up
    delete bans[key];
    delete strikes[key];
    return null;
  }

  /**
   * Check if a key is whitelisted (fast-path bypass).
   * @param {string} key
   * @returns {boolean}
   */
  function _isWhitelisted(key) {
    return !!whitelist[key];
  }

  /**
   * Build an "allowed" result for whitelisted keys.
   * Centralises the whitelist fast-path return shape that was previously
   * duplicated in check() and consume().
   * @param {string} key
   * @param {number} [consumed] - For batch consume; omit for single check
   * @returns {Object}
   */
  function _whitelistResult(key, consumed) {
    var r = {
      allowed: true, remaining: Infinity, retryAfterMs: 0,
      whitelisted: true, algorithm: algorithm, key: key
    };
    if (consumed !== undefined) {
      r.consumed = consumed;
      r.requested = consumed;
    }
    return r;
  }

  /**
   * Build a ban-rejection result.  Centralises the ban response shape
   * that was previously duplicated in check() and consume().
   * @param {Object} banResult - From _checkBanStatus
   * @param {string} key
   * @param {number} [requested] - For batch consume
   * @returns {Object}
   */
  function _banRejectionResult(banResult, key, requested) {
    var r = {
      allowed: false, remaining: 0,
      retryAfterMs: banResult.retryAfterMs,
      banned: true, banExpiresAt: banResult.expiresAt,
      reason: "Temporarily banned after " + banThreshold + " consecutive rejections",
      algorithm: algorithm, key: key
    };
    if (requested !== undefined) {
      r.consumed = 0;
      r.requested = requested;
    }
    return r;
  }

  /**
   * Handle strike tracking after a rejection.  If the strike count
   * reaches banThreshold, bans the key and decorates the result.
   * Previously this 6-line block was copy-pasted in check(), consume()
   * token-bucket, and consume() leaky-bucket paths.
   * @param {string} key
   * @param {number} now
   * @param {Object} result - Mutated in-place if ban is triggered
   */
  function _trackRejection(key, now, result) {
    if (!enableBans) return;
    strikes[key] = (strikes[key] || 0) + 1;
    if (strikes[key] >= banThreshold) {
      bans[key] = { expiresAt: now + banDurationMs, bannedAt: now };
      totalBanned++;
      result.banned = true;
      result.banExpiresAt = now + banDurationMs;
      result.reason = "Banned after " + banThreshold + " consecutive rejections";
    }
  }

  /**
   * Clear strikes for a key after a successful request.
   * @param {string} key
   */
  function _clearStrikes(key) {
    if (enableBans) delete strikes[key];
  }

  // ── Sliding Window ──────────────────────────────────────────────
  // Uses a startIdx pointer to avoid allocating a new array on every
  // check().  The timestamps array is only compacted when the dead
  // prefix exceeds half the array length, amortising GC pressure to
  // O(1) per check on average while keeping memory bounded.

  var SW_COMPACT_RATIO = 0.5; // compact when startIdx > length * ratio

  function _checkSlidingWindow(key, now) {
    var entry = store[key];
    if (!entry) {
      entry = { timestamps: [], startIdx: 0, lastSeen: now };
      store[key] = entry;
    }

    // Trim expired timestamps using binary search on the live portion
    var cutoff = now - windowMs;
    var ts = entry.timestamps;
    var base = entry.startIdx;
    // Binary search within [base, ts.length)
    var lo = base;
    var hi = ts.length;
    while (lo < hi) {
      var mid = (lo + hi) >>> 1;
      if (ts[mid] < cutoff) lo = mid + 1;
      else hi = mid;
    }
    entry.startIdx = lo;

    // Compact only when the dead prefix is large relative to the array
    if (lo > 0 && lo > ts.length * SW_COMPACT_RATIO) {
      entry.timestamps = ts.slice(lo);
      entry.startIdx = 0;
    }

    entry.lastSeen = now;
    var count = entry.timestamps.length - entry.startIdx;

    if (count >= maxRequests) {
      // Rejected — compute retry-after from oldest timestamp in window
      var oldestInWindow = entry.timestamps[entry.startIdx];
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

  /**
   * Initialise (if absent) and refill a token-bucket entry.
   * Extracted so both check() and consume() share the same init + refill
   * logic instead of duplicating it.
   * @param {string} key
   * @param {number} now
   * @returns {Object} The entry (store[key])
   */
  function _refreshTokenBucket(key, now) {
    var entry = store[key];
    if (!entry) {
      entry = { tokens: capacity, lastRefill: now, lastSeen: now };
      store[key] = entry;
    }
    var elapsed = (now - entry.lastRefill) / 1000;
    entry.tokens = Math.min(capacity, entry.tokens + elapsed * refillRate);
    entry.lastRefill = now;
    entry.lastSeen = now;
    return entry;
  }

  function _checkTokenBucket(key, now) {
    var entry = _refreshTokenBucket(key, now);

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

  /**
   * Initialise (if absent) and drain a leaky-bucket entry.
   * Extracted so both check() and consume() share the same init + leak
   * logic instead of duplicating it.
   * @param {string} key
   * @param {number} now
   * @returns {Object} The entry (store[key])
   */
  function _refreshLeakyBucket(key, now) {
    var entry = store[key];
    if (!entry) {
      entry = { water: 0, lastLeak: now, lastSeen: now };
      store[key] = entry;
    }
    var elapsed = (now - entry.lastLeak) / 1000;
    entry.water = Math.max(0, entry.water - elapsed * leakRate);
    entry.lastLeak = now;
    entry.lastSeen = now;
    return entry;
  }

  function _checkLeakyBucket(key, now) {
    var entry = _refreshLeakyBucket(key, now);

    if (entry.water + 1 > queueSize) {
      // Queue full — reject (use +1 to prevent fractional water overflow,
      // consistent with consume()'s batch check: water + count > queueSize)
      var excess = entry.water + 1 - queueSize;
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
    _validateKey(key);
    if (_isWhitelisted(key)) return _whitelistResult(key);
    now = now || Date.now();
    checkCount++;

    // Periodic cleanup
    if (checkCount % cleanupInterval === 0) {
      _cleanup(now);
    }

    // Check ban status
    var banResult = _checkBanStatus(key, now);
    if (banResult) {
      totalRejected++;
      return _banRejectionResult(banResult, key);
    }

    // Run algorithm check
    var result = checkers[algorithm](key, now);

    // Track bans / stats
    if (!result.allowed) {
      totalRejected++;
      _trackRejection(key, now, result);
    } else {
      totalAllowed++;
      _clearStrikes(key);
    }

    result.algorithm = algorithm;
    result.key = key;
    return result;
  }

  /**
   * Consume multiple tokens/requests at once (batch check).
   *
   * For token-bucket and leaky-bucket algorithms this runs in O(1) by
   * doing the arithmetic directly instead of looping N times through
   * check().  Sliding-window still loops because each request needs its
   * own timestamp recorded, but the per-iteration cost is lower thanks
   * to the startIdx optimisation above.
   *
   * Uses the shared _refreshTokenBucket / _refreshLeakyBucket helpers
   * to avoid duplicating init + refill/leak logic from check().
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
    if (_isWhitelisted(key)) return _whitelistResult(key, count);
    _validateKey(key);
    now = now || Date.now();
    checkCount++;
    if (checkCount % cleanupInterval === 0) _cleanup(now);

    var banResult = _checkBanStatus(key, now);
    if (banResult) {
      totalRejected++;
      return _banRejectionResult(banResult, key, count);
    }

    // ── O(1) path for token-bucket ──
    if (algorithm === "token-bucket") {
      var entry = _refreshTokenBucket(key, now);

      if (Math.floor(entry.tokens) < count) {
        var retryMs = Math.ceil(((count - entry.tokens) / refillRate) * 1000);
        totalRejected++;
        var tbReject = {
          allowed: false, remaining: Math.floor(entry.tokens), retryAfterMs: Math.max(0, retryMs),
          tokens: Math.floor(entry.tokens), capacity: capacity, refillRate: refillRate,
          consumed: 0, requested: count, algorithm: algorithm, key: key
        };
        _trackRejection(key, now, tbReject);
        return tbReject;
      }
      entry.tokens -= count;
      totalAllowed++;
      _clearStrikes(key);
      return {
        allowed: true, remaining: Math.floor(entry.tokens), retryAfterMs: 0,
        tokens: Math.floor(entry.tokens), capacity: capacity, refillRate: refillRate,
        consumed: count, requested: count, algorithm: algorithm, key: key
      };
    }

    // ── O(1) path for leaky-bucket ──
    if (algorithm === "leaky-bucket") {
      var entryL = _refreshLeakyBucket(key, now);

      if (entryL.water + count > queueSize) {
        var excess = entryL.water + count - queueSize;
        totalRejected++;
        var lbReject = {
          allowed: false, remaining: 0,
          retryAfterMs: Math.ceil((excess / leakRate) * 1000),
          queueLevel: Math.floor(entryL.water), queueSize: queueSize, leakRate: leakRate,
          consumed: 0, requested: count, algorithm: algorithm, key: key
        };
        _trackRejection(key, now, lbReject);
        return lbReject;
      }
      entryL.water += count;
      totalAllowed++;
      _clearStrikes(key);
      return {
        allowed: true, remaining: Math.floor(queueSize - entryL.water), retryAfterMs: 0,
        queueLevel: Math.floor(entryL.water), queueSize: queueSize, leakRate: leakRate,
        consumed: count, requested: count, algorithm: algorithm, key: key
      };
    }

    // ── Sliding window: loop (each request needs its own timestamp) ──
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
    _validateKey(key);
    now = now || Date.now();

    // Check ban
    var banResult = _checkBanStatus(key, now);
    if (banResult) {
      return { allowed: false, banned: true, retryAfterMs: banResult.retryAfterMs };
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
      var base = entry.startIdx || 0;
      var lo = base;
      var hi = entry.timestamps.length;
      while (lo < hi) {
        var mid = (lo + hi) >>> 1;
        if (entry.timestamps[mid] < cutoff) lo = mid + 1;
        else hi = mid;
      }
      var count = entry.timestamps.length - lo;
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
        allowed: water + 1 <= queueSize,
        remaining: Math.max(0, Math.floor(queueSize - water)),
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
    _validateKey(key);
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
    store = Object.create(null);
    bans = Object.create(null);
    strikes = Object.create(null);
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
   * Uses partial selection (O(n)) instead of sorting all entries
   * (O(n log n)) when limit < total keys — maintains a small
   * sorted result set and only inserts when an entry qualifies.
   *
   * @param {number} [limit=20] - Max keys to return
   * @param {string} [sortBy='recent'] - Sort: 'recent' | 'active' | 'strikes'
   * @returns {Array} Top keys with their current state
   */
  function getTopKeys(limit, sortBy) {
    limit = limit || 20;
    sortBy = sortBy || "recent";

    var keys = Object.keys(store);

    function _buildInfo(k) {
      var e = store[k];
      var info = { key: k, lastSeen: e.lastSeen || 0 };
      if (algorithm === "sliding-window") {
        info.requestCount = e.timestamps ? e.timestamps.length - (e.startIdx || 0) : 0;
      } else if (algorithm === "token-bucket") {
        info.tokens = Math.floor(e.tokens || 0);
      } else {
        info.queueLevel = Math.floor(e.water || 0);
      }
      info.strikes = strikes[k] || 0;
      info.banned = !!bans[k];
      return info;
    }

    function _sortValue(info) {
      if (sortBy === "active") {
        return info.requestCount || info.queueLevel || (capacity - (info.tokens || 0));
      } else if (sortBy === "strikes") {
        return info.strikes;
      }
      return info.lastSeen;
    }

    // When limit >= total keys, just build, sort, return (no benefit
    // from partial selection when we need everything).
    if (keys.length <= limit) {
      var all = [];
      for (var a = 0; a < keys.length; a++) {
        all.push(_buildInfo(keys[a]));
      }
      all.sort(function (x, y) { return _sortValue(y) - _sortValue(x); });
      return all;
    }

    // Partial selection: maintain a result array of `limit` entries,
    // tracking the minimum sort value so we can skip entries that
    // can't possibly make the top-N.
    var result = [];
    var minVal = -Infinity;

    for (var i = 0; i < keys.length; i++) {
      var info = _buildInfo(keys[i]);
      var val = _sortValue(info);

      if (result.length < limit) {
        result.push({ info: info, val: val });
        if (result.length === limit) {
          // Sort and set minVal
          result.sort(function (x, y) { return y.val - x.val; });
          minVal = result[result.length - 1].val;
        }
      } else if (val > minVal) {
        // Replace the last (smallest) entry
        result[result.length - 1] = { info: info, val: val };
        // Re-sort to maintain order (small array, fast)
        result.sort(function (x, y) { return y.val - x.val; });
        minVal = result[result.length - 1].val;
      }
    }

    // If we didn't fill up to limit, sort what we have
    if (result.length < limit) {
      result.sort(function (x, y) { return y.val - x.val; });
    }

    var out = [];
    for (var j = 0; j < result.length; j++) {
      out.push(result[j].info);
    }
    return out;
  }

  /**
   * Per-key whitelist — whitelisted keys bypass all rate limiting.
   */
  var whitelist = Object.create(null);

  /**
   * Add key to whitelist.
   * @param {string} key
   */
  function whitelistAdd(key) {
    _validateKey(key);
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
   * Reject keys that could cause prototype pollution.
   * @param {string} key
   * @returns {boolean} true if the key is safe
   */
  function _isSafeKey(key) {
    return key !== "__proto__" && key !== "constructor" && key !== "prototype";
  }

  /**
   * Import previously exported state.
   *
   * Validates imported data to prevent prototype pollution and
   * rejects entries with unsafe keys or malformed payloads.
   *
   * @param {Object} state - State from exportState()
   * @returns {number} Number of keys restored
   */
  function importState(state) {
    if (!state || typeof state !== "object" || Array.isArray(state)) {
      throw new Error("Invalid state object");
    }
    if (state.algorithm && state.algorithm !== algorithm) {
      throw new Error("Algorithm mismatch: expected " + algorithm + ", got " + state.algorithm);
    }

    var count = 0;
    if (state.store && typeof state.store === "object" && !Array.isArray(state.store)) {
      var sKeys = Object.keys(state.store);
      for (var i = 0; i < sKeys.length; i++) {
        if (!_isSafeKey(sKeys[i])) continue;
        var entry = state.store[sKeys[i]];
        if (!entry || typeof entry !== "object") continue;
        store[sKeys[i]] = entry;
        count++;
      }
    }
    if (state.bans && typeof state.bans === "object" && !Array.isArray(state.bans)) {
      var bKeys = Object.keys(state.bans);
      for (var j = 0; j < bKeys.length; j++) {
        if (!_isSafeKey(bKeys[j])) continue;
        var banEntry = state.bans[bKeys[j]];
        if (!banEntry || typeof banEntry !== "object" ||
            typeof banEntry.expiresAt !== "number") continue;
        bans[bKeys[j]] = banEntry;
      }
    }
    if (state.strikes && typeof state.strikes === "object" && !Array.isArray(state.strikes)) {
      var kKeys = Object.keys(state.strikes);
      for (var k = 0; k < kKeys.length; k++) {
        if (!_isSafeKey(kKeys[k])) continue;
        var strikeVal = state.strikes[kKeys[k]];
        if (typeof strikeVal !== "number" || strikeVal < 0) continue;
        strikes[kKeys[k]] = strikeVal;
      }
    }
    if (state.stats && typeof state.stats === "object") {
      totalAllowed += Number(state.stats.totalAllowed) || 0;
      totalRejected += Number(state.stats.totalRejected) || 0;
      totalBanned += Number(state.stats.totalBanned) || 0;
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
