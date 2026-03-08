/**
 * gif-captcha — Core library for GIF-based CAPTCHA challenges.
 *
 * Provides utilities for creating, presenting, and validating GIF CAPTCHAs
 * that leverage human visual comprehension to distinguish humans from bots.
 *
 * @module gif-captcha
 */

"use strict";

// ── Shared Option Helpers ───────────────────────────────────────────

/**
 * Extract a positive-number option, falling back to a default.
 *
 * Replaces the verbose pattern:
 *   options.x != null && options.x > 0 ? options.x : fallback
 *
 * @param {*}      val      The option value to check
 * @param {number} fallback Default when val is null/undefined/non-positive
 * @returns {number}
 */
function _posOpt(val, fallback) {
  return val != null && val > 0 ? val : fallback;
}

/**
 * Extract a non-negative-number option, falling back to a default.
 *
 * Like _posOpt but allows 0.
 *
 * @param {*}      val      The option value to check
 * @param {number} fallback Default when val is null/undefined/negative
 * @returns {number}
 */
function _nnOpt(val, fallback) {
  return val != null && val >= 0 ? val : fallback;
}

// ── LRU Order Tracker (O(1) touch/evict) ────────────────────────────

/**
 * A doubly-linked-list backed LRU order tracker.
 *
 * Replaces the array + indexOf + splice pattern used across multiple
 * subsystems for O(n) LRU tracking with an O(1) implementation.
 *
 * API:
 *   push(key)        — add key to the end (most recent)
 *   touch(key)       — move key to end (most recent), no-op if absent
 *   evictOldest()    — remove & return the oldest key (or undefined)
 *   remove(key)      — remove a specific key, returns true if existed
 *   has(key)         — check membership
 *   length           — number of tracked keys (property)
 *   toArray()        — return keys in insertion order (for serialization)
 *   clear()          — remove all keys
 *
 * ES5-compatible. Uses an object-based doubly-linked list internally.
 *
 * @constructor
 */
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
function secureRandomInt(max) {
  if (_crypto && typeof _crypto.randomInt === 'function') {
    return _crypto.randomInt(max);
  }
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    // Rejection sampling to eliminate modulo bias
    var arr = new Uint32Array(1);
    var limit = Math.floor(0x100000000 / max) * max; // largest multiple of max that fits in uint32
    do {
      crypto.getRandomValues(arr);
    } while (arr[0] >= limit);
    return arr[0] % max;
  }
  throw new Error(
    'gif-captcha: no cryptographic random source available. ' +
    'CAPTCHA security requires crypto.randomInt (Node.js) or ' +
    'crypto.getRandomValues (browser). Math.random() is predictable ' +
    'and must not be used for challenge generation.'
  );
}

// ── Shared Helpers ──────────────────────────────────────────────────

/** @returns {number} Current time in milliseconds (Date.now()). */
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
function _constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;

  // Prefer crypto.timingSafeEqual for strongest guarantee
  if (_crypto && typeof _crypto.timingSafeEqual === 'function') {
    var bufA = Buffer.from(a, 'utf8');
    var bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) return false;
    return _crypto.timingSafeEqual(bufA, bufB);
  }

  // Fallback: bitwise XOR over all chars (constant-time in character count)
  var mismatch = 0;
  for (var i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * Clamp a numeric value to [lo, hi].
 * @param {number} v
 * @param {number} lo - Lower bound
 * @param {number} hi - Upper bound
 * @returns {number}
 */
function _clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }

/** Numeric ascending comparator for Array.sort(). */
function _numAsc(a, b) { return a - b; }

/**
 * Compute the arithmetic mean of a numeric array.
 * @param {number[]} arr
 * @returns {number} Mean, or 0 for empty arrays
 */
function _mean(arr) {
  if (arr.length === 0) return 0;
  var sum = 0;
  for (var i = 0; i < arr.length; i++) sum += arr[i];
  return sum / arr.length;
}

/**
 * Compute the median of a numeric array (does NOT mutate the input).
 * @param {number[]} arr
 * @returns {number} Median, or 0 for empty arrays
 */
function _median(arr) {
  if (arr.length === 0) return 0;
  var sorted = arr.slice().sort(_numAsc);
  var mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

/**
 * Compute the sample standard deviation of a numeric array.
 * Uses Bessel's correction (n-1 denominator).
 * @param {number[]} arr
 * @param {number} [avg] - Pre-computed mean (avoids recomputation)
 * @returns {number} Standard deviation, or 0 for arrays with fewer than 2 elements
 */
function _stddev(arr, avg) {
  if (arr.length < 2) return 0;
  var m = avg !== undefined ? avg : _mean(arr);
  var sumSq = 0;
  for (var i = 0; i < arr.length; i++) {
    var d = arr[i] - m;
    sumSq += d * d;
  }
  return Math.sqrt(sumSq / (arr.length - 1));
}

// ── Text Sanitizer ──────────────────────────────────────────────────

/**
 * Create a text sanitizer for HTML-escaping untrusted strings.
 * Works in browser (DOM-based) and Node.js (regex-based) environments.
 *
 * @returns {{ sanitize: (str: string) => string }}
 */
function createSanitizer() {
  if (typeof document !== "undefined") {
    var el = document.createElement("div");
    return {
      sanitize: function (str) {
        el.textContent = str;
        return el.innerHTML;
      },
    };
  }
  // Node.js fallback — regex-based HTML entity escaping
  var ENTITIES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return {
    sanitize: function (str) {
      return String(str).replace(/[&<>"']/g, function (ch) {
        return ENTITIES[ch];
      });
    },
  };
}

/**
 * Escape a string for safe insertion into innerHTML.
 *
 * @param {string} str - Untrusted input
 * @returns {string} HTML-safe string
 */
var _defaultSanitizer = createSanitizer();
function sanitize(str) {
  return _defaultSanitizer.sanitize(str);
}

// ── URL Validation ──────────────────────────────────────────────────

/**
 * Validate that a URL is safe for use as an image source.
 * Rejects javascript:, data:, vbscript:, and other dangerous schemes.
 * Only allows http: and https: protocols.
 *
 * @param {string} url - URL to validate
 * @returns {boolean} True if the URL is safe for img.src
 */
function isSafeUrl(url) {
  if (!url || typeof url !== "string") return false;
  var trimmed = url.trim();
  if (trimmed.length === 0) return false;
  // Strip leading control characters and whitespace (bypass prevention)
  var cleaned = trimmed.replace(/^[\x00-\x1f\s]+/, "");
  // Reject known dangerous schemes (case-insensitive)
  var lower = cleaned.toLowerCase();
  if (/^(javascript|data|vbscript|blob|file|ftp):/.test(lower)) return false;
  // Must start with http: or https: or be a relative/protocol-relative URL
  if (/^https?:\/\//i.test(cleaned)) return true;
  // Allow protocol-relative URLs (//example.com/image.gif)
  if (/^\/\//.test(cleaned)) return true;
  // Allow relative paths (/images/foo.gif, images/foo.gif)
  if (/^[a-zA-Z0-9\/._-]/.test(cleaned)) return true;
  return false;
}

// ── GIF Loading ─────────────────────────────────────────────────────

/** Maximum number of retries for GIF loading. */
var GIF_MAX_RETRIES = 2;

/** Delay in milliseconds between retries. */
var GIF_RETRY_DELAY_MS = 1500;

/**
 * Load a GIF image into a DOM container with automatic retry on failure.
 * On final failure, shows a fallback with a link to the source or a hint.
 *
 * @param {HTMLElement} container - DOM element to render into
 * @param {Object} challenge - Challenge object
 * @param {string} challenge.title - Human-readable challenge title
 * @param {string} challenge.gifUrl - URL of the GIF image
 * @param {string} [challenge.sourceUrl] - Original source URL for fallback link
 * @param {number} [attempt=0] - Current attempt (0-indexed)
 */
function loadGifWithRetry(container, challenge, attempt) {
  attempt = attempt || 0;

  // Validate URL before setting img.src (prevent javascript: / data: XSS)
  if (!isSafeUrl(challenge.gifUrl)) {
    container.innerHTML =
      '<div class="gif-error"><p>\u26a0\ufe0f Invalid GIF URL.</p></div>';
    return;
  }

  var img = document.createElement("img");
  img.alt = (challenge.title || "CAPTCHA") + " GIF";

  img.onload = function () {
    container.innerHTML = "";
    container.appendChild(img);
  };

  img.onerror = function () {
    if (attempt < GIF_MAX_RETRIES) {
      container.innerHTML =
        '<span class="gif-loading">Retrying... (' +
        (attempt + 1) + "/" + GIF_MAX_RETRIES + ")</span>";
      setTimeout(function () {
        loadGifWithRetry(container, challenge, attempt + 1);
      }, GIF_RETRY_DELAY_MS);
      return;
    }

    var hasSource = challenge.sourceUrl && challenge.sourceUrl !== "#" && isSafeUrl(challenge.sourceUrl);
    var errorHtml =
      '<div class="gif-error">' +
      "<p>\u26a0\ufe0f GIF couldn't load (CDN may be blocking direct access).</p>";

    if (hasSource) {
      errorHtml +=
        '<p><a href="' + sanitize(challenge.sourceUrl) +
        '" target="_blank" rel="noopener noreferrer">Open GIF in new tab \u2192</a></p>' +
        '<p style="margin-top:0.5rem;font-size:0.8rem;">Watch it there, then come back and describe what happened.</p>';
    } else {
      errorHtml +=
        '<p style="margin-top:0.5rem;font-size:0.85rem;">\ud83d\udca1 Hint: This GIF is titled "' +
        sanitize(challenge.title) + '".</p>' +
        '<p style="margin-top:0.3rem;font-size:0.8rem;">Try searching for it online, or skip this challenge.</p>';
    }

    errorHtml += "</div>";
    container.innerHTML = errorHtml;
  };

  img.src = attempt > 0
    ? challenge.gifUrl + "?retry=" + attempt
    : challenge.gifUrl;
}

// ── Challenge Validation ────────────────────────────────────────────

/**
 * Score how similar two text strings are using word overlap (Jaccard index).
 * Useful for fuzzy matching user answers against expected CAPTCHA answers.
 *
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {number} Similarity score between 0 and 1
 */
function textSimilarity(a, b) {
  if (!a || !b) return 0;
  var wordsA = String(a).toLowerCase().split(/\s+/).filter(Boolean);
  var wordsB = String(b).toLowerCase().split(/\s+/).filter(Boolean);
  if (wordsA.length === 0 || wordsB.length === 0) return 0;

  var setA = {};
  var uniqueA = 0;
  wordsA.forEach(function (w) { if (!setA[w]) { setA[w] = true; uniqueA++; } });

  var intersection = 0;
  var uniqueB = 0;
  var setB = {};
  wordsB.forEach(function (w) {
    if (!setB[w]) {
      setB[w] = true;
      uniqueB++;
      if (setA[w]) intersection++;
    }
  });

  // |A ∪ B| = |A| + |B| − |A ∩ B|  (avoids allocating a union object)
  return intersection / (uniqueA + uniqueB - intersection);
}

/**
 * Validate a user's CAPTCHA answer against the expected answer.
 *
 * @param {string} userAnswer - The user's response
 * @param {string} expectedAnswer - The correct/expected answer
 * @param {Object} [options] - Validation options
 * @param {number} [options.threshold=0.3] - Minimum similarity score to pass
 * @param {string[]} [options.requiredKeywords] - Words that must appear in the answer
 * @returns {{ passed: boolean, score: number, hasKeywords: boolean }}
 */
function validateAnswer(userAnswer, expectedAnswer, options) {
  options = options || {};
  var threshold = options.threshold != null ? options.threshold : 0.3;
  var requiredKeywords = options.requiredKeywords || [];

  var score = textSimilarity(userAnswer, expectedAnswer);
  var lowerAnswer = String(userAnswer || "").toLowerCase();
  var hasKeywords = requiredKeywords.length === 0 ||
    requiredKeywords.some(function (kw) {
      return lowerAnswer.indexOf(kw.toLowerCase()) !== -1;
    });

  return {
    passed: score >= threshold && hasKeywords,
    score: score,
    hasKeywords: hasKeywords,
  };
}

// ── Challenge Builder ───────────────────────────────────────────────

/**
 * Create a CAPTCHA challenge object.
 *
 * @param {Object} opts - Challenge options
 * @param {number|string} opts.id - Unique challenge identifier
 * @param {string} opts.title - Human-readable title
 * @param {string} opts.gifUrl - URL of the GIF image
 * @param {string} [opts.sourceUrl] - Original source URL
 * @param {string} opts.humanAnswer - Expected human description
 * @param {string} [opts.aiAnswer] - Typical AI response (for comparison/scoring)
 * @param {string[]} [opts.keywords] - Keywords for fuzzy validation
 * @returns {Object} A structured challenge object
 */
function createChallenge(opts) {
  if (!opts || !opts.id || !opts.gifUrl || !opts.humanAnswer) {
    throw new Error("Challenge requires id, gifUrl, and humanAnswer");
  }
  if (!isSafeUrl(opts.gifUrl)) {
    throw new Error("Challenge gifUrl must be a safe HTTP(S) or relative URL");
  }
  if (opts.sourceUrl && opts.sourceUrl !== "#" && !isSafeUrl(opts.sourceUrl)) {
    throw new Error("Challenge sourceUrl must be a safe HTTP(S) or relative URL");
  }
  return Object.freeze({
    id: opts.id,
    title: opts.title || "Challenge " + opts.id,
    gifUrl: opts.gifUrl,
    sourceUrl: opts.sourceUrl || "#",
    humanAnswer: opts.humanAnswer,
    aiAnswer: opts.aiAnswer || "",
    keywords: opts.keywords || [],
  });
}

/**
 * Pick N random challenges from a pool without replacement.
 *
 * @param {Object[]} pool - Array of challenge objects
 * @param {number} count - Number of challenges to pick
 * @returns {Object[]} Selected challenges (shuffled)
 */
function pickChallenges(pool, count) {
  if (!Array.isArray(pool) || pool.length === 0) return [];
  count = Math.min(count || 5, pool.length);
  var shuffled = pool.slice();
  // Fisher-Yates shuffle
  for (var i = shuffled.length - 1; i > 0; i--) {
    var j = secureRandomInt(i + 1);
    var temp = shuffled[i];
    shuffled[i] = shuffled[j];
    shuffled[j] = temp;
  }
  return shuffled.slice(0, count);
}

// ── Attempt Tracking / Rate Limiting ────────────────────────────────

/**
 * Create an attempt tracker for rate-limiting CAPTCHA validation.
 * Tracks attempts per challenge ID with configurable limits and lockout.
 *
 * @param {Object} [options] - Tracker configuration
 * @param {number} [options.maxAttempts=5] - Maximum attempts before lockout
 * @param {number} [options.lockoutMs=30000] - Base lockout duration in ms
 * @param {boolean} [options.exponentialBackoff=true] - Double lockout on each subsequent violation
 * @param {number} [options.maxLockoutMs=300000] - Maximum lockout duration (5 minutes)
 * @returns {Object} AttemptTracker instance
 */
function createAttemptTracker(options) {
  options = options || {};
  var maxAttempts = Math.floor(_posOpt(options.maxAttempts, 5));
  var baseLockoutMs = _posOpt(options.lockoutMs, 30000);
  var exponentialBackoff = options.exponentialBackoff !== false;
  var maxLockoutMs = _posOpt(options.maxLockoutMs, 300000);

  // Internal state: Map<challengeId, { attempts: number, timestamps: number[], lockoutUntil: number, lockoutCount: number }>
  // Use null-prototype object to prevent prototype pollution when
  // user-supplied challengeIds collide with Object.prototype keys
  // (e.g. "__proto__", "constructor", "toString").
  var challenges = Object.create(null);

  function _getEntry(challengeId) {
    var id = String(challengeId);
    if (!challenges[id]) {
      challenges[id] = { attempts: 0, timestamps: [], lockoutUntil: 0, lockoutCount: 0 };
    }
    return challenges[id];
  }

  function _computeLockoutMs(lockoutCount) {
    if (!exponentialBackoff) return baseLockoutMs;
    // 2^(lockoutCount-1) * baseLockoutMs, capped at maxLockoutMs
    var multiplier = Math.pow(2, Math.max(0, lockoutCount - 1));
    return Math.min(baseLockoutMs * multiplier, maxLockoutMs);
  }

  /**
   * Check if a challenge is currently locked out.
   *
   * @param {string|number} challengeId - Challenge identifier
   * @returns {{ locked: boolean, lockoutRemainingMs: number }}
   */
  function isLocked(challengeId) {
    var entry = _getEntry(challengeId);
    var now = _now();
    if (entry.lockoutUntil > now) {
      return { locked: true, lockoutRemainingMs: entry.lockoutUntil - now };
    }
    // Lockout expired — reset attempts for this lockout period
    if (entry.lockoutUntil > 0 && entry.lockoutUntil <= now) {
      entry.attempts = 0;
      entry.timestamps = [];
      entry.lockoutUntil = 0;
    }
    return { locked: false, lockoutRemainingMs: 0 };
  }

  /**
   * Record an attempt and check for lockout.
   *
   * @param {string|number} challengeId - Challenge identifier
   * @returns {{ allowed: boolean, attemptsRemaining: number, lockoutRemainingMs: number, attemptNumber: number }}
   */
  function recordAttempt(challengeId) {
    var lockStatus = isLocked(challengeId);
    if (lockStatus.locked) {
      var entry = _getEntry(challengeId);
      return {
        allowed: false,
        attemptsRemaining: 0,
        lockoutRemainingMs: lockStatus.lockoutRemainingMs,
        attemptNumber: entry.attempts,
      };
    }

    var entry = _getEntry(challengeId);
    entry.attempts++;
    entry.timestamps.push(_now());

    if (entry.attempts >= maxAttempts) {
      // Trigger lockout
      entry.lockoutCount++;
      var lockMs = _computeLockoutMs(entry.lockoutCount);
      entry.lockoutUntil = _now() + lockMs;
      return {
        allowed: false,
        attemptsRemaining: 0,
        lockoutRemainingMs: lockMs,
        attemptNumber: entry.attempts,
      };
    }

    return {
      allowed: true,
      attemptsRemaining: maxAttempts - entry.attempts,
      lockoutRemainingMs: 0,
      attemptNumber: entry.attempts,
    };
  }

  /**
   * Validate a CAPTCHA answer with attempt tracking.
   * Wraps the core validateAnswer() with rate limiting.
   *
   * @param {string} userAnswer - User's response
   * @param {string} expectedAnswer - Expected answer
   * @param {string|number} challengeId - Challenge identifier for tracking
   * @param {Object} [validationOptions] - Options passed to validateAnswer()
   * @returns {{ passed: boolean, score: number, hasKeywords: boolean, locked: boolean, attemptsRemaining: number, lockoutRemainingMs: number }}
   */
  function trackedValidate(userAnswer, expectedAnswer, challengeId, validationOptions) {
    if (challengeId == null) {
      throw new Error("challengeId is required for tracked validation");
    }

    var attempt = recordAttempt(challengeId);
    if (!attempt.allowed) {
      return {
        passed: false,
        score: 0,
        hasKeywords: false,
        locked: true,
        attemptsRemaining: attempt.attemptsRemaining,
        lockoutRemainingMs: attempt.lockoutRemainingMs,
      };
    }

    var result = validateAnswer(userAnswer, expectedAnswer, validationOptions);
    return {
      passed: result.passed,
      score: result.score,
      hasKeywords: result.hasKeywords,
      locked: false,
      attemptsRemaining: attempt.attemptsRemaining,
      lockoutRemainingMs: 0,
    };
  }

  /**
   * Reset tracking for a specific challenge.
   *
   * @param {string|number} challengeId - Challenge to reset
   */
  function resetChallenge(challengeId) {
    delete challenges[String(challengeId)];
  }

  /**
   * Reset all tracking state.
   */
  function resetAll() {
    challenges = Object.create(null);
  }

  /**
   * Get tracking stats for a challenge.
   *
   * @param {string|number} challengeId - Challenge identifier
   * @returns {{ attempts: number, lockoutCount: number, isLocked: boolean, lockoutRemainingMs: number }}
   */
  function getStats(challengeId) {
    var entry = _getEntry(challengeId);
    var lockStatus = isLocked(challengeId);
    return {
      attempts: entry.attempts,
      lockoutCount: entry.lockoutCount,
      isLocked: lockStatus.locked,
      lockoutRemainingMs: lockStatus.lockoutRemainingMs,
    };
  }

  /**
   * Get the tracker configuration.
   *
   * @returns {{ maxAttempts: number, lockoutMs: number, exponentialBackoff: boolean, maxLockoutMs: number }}
   */
  function getConfig() {
    return {
      maxAttempts: maxAttempts,
      lockoutMs: baseLockoutMs,
      exponentialBackoff: exponentialBackoff,
      maxLockoutMs: maxLockoutMs,
    };
  }

  return {
    isLocked: isLocked,
    recordAttempt: recordAttempt,
    validateAnswer: trackedValidate,
    resetChallenge: resetChallenge,
    resetAll: resetAll,
    getStats: getStats,
    getConfig: getConfig,
  };
}

// ── Canvas Polyfill ─────────────────────────────────────────────────

/**
 * Install the roundRect polyfill for CanvasRenderingContext2D.
 * No-op if already available or not in a browser environment.
 */
function installRoundRectPolyfill() {
  if (
    typeof CanvasRenderingContext2D !== "undefined" &&
    !CanvasRenderingContext2D.prototype.roundRect
  ) {
    CanvasRenderingContext2D.prototype.roundRect = function (x, y, w, h, radii) {
      var r = Array.isArray(radii) ? radii[0] : (radii || 0);
      this.moveTo(x + r, y);
      this.lineTo(x + w - r, y);
      this.quadraticCurveTo(x + w, y, x + w, y + r);
      this.lineTo(x + w, y + h - r);
      this.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
      this.lineTo(x + r, y + h);
      this.quadraticCurveTo(x, y + h, x, y + h - r);
      this.lineTo(x, y + r);
      this.quadraticCurveTo(x, y, x + r, y);
      this.closePath();
    };
  }
}

// ── Challenge Set Analyzer ──────────────────────────────────────────

/**
 * Create an analyzer for a set of CAPTCHA challenges.
 * Computes aggregate statistics about challenge quality, diversity,
 * and potential issues.
 *
 * @param {Object[]} challenges - Array of challenge objects (from createChallenge)
 * @returns {Object} SetAnalyzer instance
 */
function createSetAnalyzer(challenges) {
  if (!Array.isArray(challenges) || challenges.length === 0) {
    throw new Error("challenges must be a non-empty array");
  }

  // Validate all are proper challenge objects
  challenges.forEach(function (c, i) {
    if (!c || !c.id || !c.humanAnswer) {
      throw new Error("Invalid challenge at index " + i + ": requires id and humanAnswer");
    }
  });

  var _challenges = challenges.slice(); // defensive copy

  // Precompute word-sets for pairwise similarity (avoids recomputing in O(n²) loops)
  var _wordSets = null;
  function _getWordSets() {
    if (_wordSets) return _wordSets;
    _wordSets = _challenges.map(function (c) {
      var words = String(c.humanAnswer || "").toLowerCase().split(/\s+/).filter(Boolean);
      var set = {};
      words.forEach(function (w) { set[w] = true; });
      return set;
    });
    return _wordSets;
  }

  // Cache for pairwise similarity matrix — avoids redundant O(n²) recomputation
  // in findSimilarPairs(), detectDuplicates(), and diversityScore().
  var _pairwiseSim = null;
  function _getPairwiseSim() {
    if (_pairwiseSim) return _pairwiseSim;
    var sets = _getWordSets();
    var n = _challenges.length;
    _pairwiseSim = [];
    for (var i = 0; i < n; i++) {
      _pairwiseSim[i] = new Array(n);
      _pairwiseSim[i][i] = 1; // self-similarity
      for (var j = 0; j < i; j++) {
        var sim = _jaccardSets(sets[i], sets[j]);
        _pairwiseSim[i][j] = sim;
        _pairwiseSim[j][i] = sim;
      }
    }
    return _pairwiseSim;
  }

  /**
   * Compute Jaccard similarity between two precomputed word sets.
   * @param {Object} setA - Word set (keys = words)
   * @param {Object} setB - Word set
   * @returns {number} Similarity 0-1
   */
  function _jaccardSets(setA, setB) {
    var keysA = Object.keys(setA);
    var keysB = Object.keys(setB);
    if (keysA.length === 0 || keysB.length === 0) return 0;
    var intersection = 0;
    var union = {};
    keysA.forEach(function (w) { union[w] = true; });
    keysB.forEach(function (w) {
      if (setA[w]) intersection++;
      union[w] = true;
    });
    return intersection / Object.keys(union).length;
  }

  /**
   * Compute answer length statistics.
   * @returns {{ min: number, max: number, mean: number, median: number, stdDev: number }}
   */
  function answerLengthStats() {
    var lengths = _challenges.map(function (c) { return c.humanAnswer.length; });
    lengths.sort(_numAsc);
    var n = lengths.length;
    var min = lengths[0];
    var max = lengths[n - 1];
    var mean = _mean(lengths);
    var median = _median(lengths);
    var stdDev = _stddev(lengths, mean);
    return { min: min, max: max, mean: mean, median: median, stdDev: stdDev };
  }

  /**
   * Compute keyword coverage — which keywords appear across challenges
   * and how frequently.
   * @returns {{ totalKeywords: number, uniqueKeywords: number,
   *             keywordFrequency: Object<string, number>,
   *             challengesWithKeywords: number,
   *             challengesWithoutKeywords: number,
   *             coverageRatio: number }}
   */
  function keywordCoverage() {
    var totalKeywords = 0;
    var keywordFrequency = {};
    var challengesWithKeywords = 0;
    var challengesWithoutKeywords = 0;

    _challenges.forEach(function (c) {
      var kws = c.keywords || [];
      if (kws.length > 0) {
        challengesWithKeywords++;
      } else {
        challengesWithoutKeywords++;
      }
      kws.forEach(function (kw) {
        totalKeywords++;
        var lower = kw.toLowerCase();
        keywordFrequency[lower] = (keywordFrequency[lower] || 0) + 1;
      });
    });

    var uniqueKeywords = Object.keys(keywordFrequency).length;
    var coverageRatio = _challenges.length > 0
      ? challengesWithKeywords / _challenges.length : 0;

    return {
      totalKeywords: totalKeywords,
      uniqueKeywords: uniqueKeywords,
      keywordFrequency: keywordFrequency,
      challengesWithKeywords: challengesWithKeywords,
      challengesWithoutKeywords: challengesWithoutKeywords,
      coverageRatio: coverageRatio,
    };
  }

  /**
   * Find pairs of challenges with similar human answers.
   * Uses textSimilarity() from the library.
   * @param {number} [threshold=0.6] - Similarity threshold (0-1)
   * @returns {Array<{ idA: string|number, idB: string|number, similarity: number }>}
   */
  function findSimilarPairs(threshold) {
    if (threshold === undefined || threshold === null) threshold = 0.6;
    var simMatrix = _getPairwiseSim();
    var pairs = [];
    for (var i = 0; i < _challenges.length; i++) {
      for (var j = i + 1; j < _challenges.length; j++) {
        var sim = simMatrix[i][j];
        if (sim >= threshold) {
          pairs.push({ idA: _challenges[i].id, idB: _challenges[j].id, similarity: sim });
        }
      }
    }
    pairs.sort(function (a, b) { return b.similarity - a.similarity; });
    return pairs;
  }

  /**
   * Detect potential duplicates (very high similarity > 0.85).
   * @returns {Array<{ idA: string|number, idB: string|number, similarity: number }>}
   */
  function detectDuplicates() {
    return findSimilarPairs(0.85);
  }

  /**
   * Compute diversity score (0-100) based on:
   * - Answer variety (low similarity between answers)
   * - Keyword spread (different keywords across challenges)
   * - Title uniqueness
   * @returns {{ score: number, breakdown: { answerDiversity: number, keywordSpread: number, titleUniqueness: number }}}
   */
  function diversityScore() {
    // answerDiversity: mean pairwise dissimilarity × 100
    var simMatrix = _getPairwiseSim();
    var totalDissimilarity = 0;
    var pairCount = 0;
    for (var i = 0; i < _challenges.length; i++) {
      for (var j = i + 1; j < _challenges.length; j++) {
        totalDissimilarity += (1 - simMatrix[i][j]);
        pairCount++;
      }
    }
    var answerDiversity = pairCount > 0 ? (totalDissimilarity / pairCount) * 100 : 100;

    // keywordSpread: uniqueKeywords / (challengeCount × 2) × 100, capped at 100
    var kc = keywordCoverage();
    var keywordSpread = _challenges.length > 0
      ? Math.min(100, (kc.uniqueKeywords / (_challenges.length * 2)) * 100) : 0;

    // titleUniqueness: uniqueTitles / totalChallenges × 100
    var titleSet = {};
    _challenges.forEach(function (c) {
      var t = (c.title || "").toLowerCase();
      titleSet[t] = true;
    });
    var uniqueTitles = Object.keys(titleSet).length;
    var titleUniqueness = _challenges.length > 0
      ? (uniqueTitles / _challenges.length) * 100 : 0;

    // Overall: weighted average
    var score = answerDiversity * 0.5 + keywordSpread * 0.3 + titleUniqueness * 0.2;

    return {
      score: score,
      breakdown: {
        answerDiversity: answerDiversity,
        keywordSpread: keywordSpread,
        titleUniqueness: titleUniqueness,
      },
    };
  }

  /**
   * Analyze answer complexity for each challenge.
   * @returns {Array<{ id: string|number, wordCount: number,
   *                    uniqueWords: number, avgWordLength: number,
   *                    complexity: string }>}
   * complexity is "simple" (<5 words), "moderate" (5-15), "complex" (>15)
   */
  function answerComplexity() {
    return _challenges.map(function (c) {
      var words = c.humanAnswer.split(/\s+/).filter(Boolean);
      var wordCount = words.length;
      var lowerWords = {};
      words.forEach(function (w) { lowerWords[w.toLowerCase()] = true; });
      var uniqueWords = Object.keys(lowerWords).length;
      var totalWordLen = words.reduce(function (s, w) { return s + w.length; }, 0);
      var avgWordLength = wordCount > 0 ? totalWordLen / wordCount : 0;
      var complexity;
      if (wordCount < 5) {
        complexity = "simple";
      } else if (wordCount <= 15) {
        complexity = "moderate";
      } else {
        complexity = "complex";
      }
      return {
        id: c.id,
        wordCount: wordCount,
        uniqueWords: uniqueWords,
        avgWordLength: avgWordLength,
        complexity: complexity,
      };
    });
  }

  /**
   * Check for common quality issues in the challenge set.
   * @returns {Array<{ type: string, severity: string, message: string, challengeIds: Array }>}
   */
  function qualityIssues() {
    var issues = [];

    // duplicate_answers
    var dups = detectDuplicates();
    if (dups.length > 0) {
      var dupIds = [];
      dups.forEach(function (d) {
        if (dupIds.indexOf(d.idA) === -1) dupIds.push(d.idA);
        if (dupIds.indexOf(d.idB) === -1) dupIds.push(d.idB);
      });
      issues.push({
        type: "duplicate_answers",
        severity: "error",
        message: "Found " + dups.length + " pair(s) with very similar answers",
        challengeIds: dupIds,
      });
    }

    // missing_keywords
    var missingKw = _challenges.filter(function (c) {
      return !c.keywords || c.keywords.length === 0;
    });
    if (missingKw.length > 0) {
      issues.push({
        type: "missing_keywords",
        severity: "warning",
        message: missingKw.length + " challenge(s) have no keywords",
        challengeIds: missingKw.map(function (c) { return c.id; }),
      });
    }

    // short_answers
    var shortAns = _challenges.filter(function (c) {
      return c.humanAnswer.length < 10;
    });
    if (shortAns.length > 0) {
      issues.push({
        type: "short_answers",
        severity: "warning",
        message: shortAns.length + " challenge(s) have answers under 10 characters",
        challengeIds: shortAns.map(function (c) { return c.id; }),
      });
    }

    // identical_titles — group by title in single pass
    var titleGroups = {};
    _challenges.forEach(function (c) {
      var t = (c.title || "").toLowerCase();
      if (!titleGroups[t]) titleGroups[t] = [];
      titleGroups[t].push(c.id);
    });
    var dupTitleIds = [];
    Object.keys(titleGroups).forEach(function (t) {
      if (titleGroups[t].length > 1) {
        dupTitleIds = dupTitleIds.concat(titleGroups[t]);
      }
    });
    if (dupTitleIds.length > 0) {
      issues.push({
        type: "identical_titles",
        severity: "warning",
        message: "Some challenges share identical titles",
        challengeIds: dupTitleIds,
      });
    }

    // small_set
    if (_challenges.length < 5) {
      issues.push({
        type: "small_set",
        severity: "info",
        message: "Challenge set has fewer than 5 challenges",
        challengeIds: _challenges.map(function (c) { return c.id; }),
      });
    }

    // no_ai_answers
    var noAi = _challenges.filter(function (c) {
      return !c.aiAnswer || c.aiAnswer === "";
    });
    if (noAi.length > 0) {
      issues.push({
        type: "no_ai_answers",
        severity: "info",
        message: noAi.length + " challenge(s) have no AI answer",
        challengeIds: noAi.map(function (c) { return c.id; }),
      });
    }

    // unbalanced_complexity
    var comp = answerComplexity();
    var counts = { simple: 0, moderate: 0, complex: 0 };
    comp.forEach(function (c) { counts[c.complexity]++; });
    var total = _challenges.length;
    var dominant = null;
    Object.keys(counts).forEach(function (k) {
      if (counts[k] / total > 0.7) dominant = k;
    });
    if (dominant) {
      issues.push({
        type: "unbalanced_complexity",
        severity: "info",
        message: "Over 70% of challenges are " + dominant + " complexity",
        challengeIds: comp.filter(function (c) { return c.complexity === dominant; }).map(function (c) { return c.id; }),
      });
    }

    return issues;
  }

  /**
   * Generate a comprehensive quality report.
   * @returns {{ challengeCount: number, answerStats: Object, keywords: Object,
   *   similarPairs: Array, duplicates: Array, diversity: Object,
   *   complexity: Array, issues: Array,
   *   overallQuality: { score: number, grade: string } }}
   */
  function generateReport() {
    var issuesList = qualityIssues();

    var score = 100;
    issuesList.forEach(function (issue) {
      if (issue.severity === "error") score -= 20;
      else if (issue.severity === "warning") score -= 10;
      else if (issue.severity === "info") score -= 5;
    });
    if (score < 0) score = 0;

    var grade;
    if (score >= 90) grade = "A";
    else if (score >= 75) grade = "B";
    else if (score >= 60) grade = "C";
    else if (score >= 40) grade = "D";
    else grade = "F";

    // Compute similar pairs once; duplicates are a subset (threshold 0.85)
    var allSimilarPairs = findSimilarPairs();
    var duplicatePairs = allSimilarPairs.filter(function (p) { return p.similarity >= 0.85; });

    return {
      challengeCount: _challenges.length,
      answerStats: answerLengthStats(),
      keywords: keywordCoverage(),
      similarPairs: allSimilarPairs,
      duplicates: duplicatePairs,
      diversity: diversityScore(),
      complexity: answerComplexity(),
      issues: issuesList,
      overallQuality: { score: score, grade: grade },
    };
  }

  /**
   * Get the challenge count.
   * @returns {number}
   */
  function size() {
    return _challenges.length;
  }

  return {
    answerLengthStats: answerLengthStats,
    keywordCoverage: keywordCoverage,
    findSimilarPairs: findSimilarPairs,
    detectDuplicates: detectDuplicates,
    diversityScore: diversityScore,
    answerComplexity: answerComplexity,
    qualityIssues: qualityIssues,
    generateReport: generateReport,
    size: size,
  };
}

// ── Difficulty Calibrator ────────────────────────────────────────────

/**
 * Create a difficulty calibrator for CAPTCHA challenges.
 * Ingests real human response data and recalibrates challenge difficulty
 * ratings based on statistical performance analysis.
 *
 * @param {Object[]} challenges - Array of challenge objects
 * @param {Object} [opts] - Options
 * @param {number} [opts.maxResponsesPerChallenge=1000] - Maximum stored responses per challenge (FIFO eviction)
 * @param {number} [opts.maxTotalResponses=50000] - Maximum total responses across all challenges
 * @returns {Object} DifficultyCalibrator instance
 */
function createDifficultyCalibrator(challenges, opts) {
  if (!Array.isArray(challenges) || challenges.length === 0) {
    throw new Error("challenges must be a non-empty array");
  }

  opts = opts || {};
  var _maxPerChallenge = typeof opts.maxResponsesPerChallenge === 'number' && opts.maxResponsesPerChallenge > 0
    ? Math.floor(opts.maxResponsesPerChallenge) : 1000;
  var _maxTotal = typeof opts.maxTotalResponses === 'number' && opts.maxTotalResponses > 0
    ? Math.floor(opts.maxTotalResponses) : 50000;

  var _challenges = challenges.slice();
  var _responses = Object.create(null);
  var _totalCount = 0;

  /**
   * Record a response for a challenge.
   * @param {string} challengeId
   * @param {{ timeMs: number, correct: boolean, skipped?: boolean }} response
   */
  function recordResponse(challengeId, response) {
    if (!challengeId || typeof challengeId !== "string") {
      throw new Error("challengeId must be a non-empty string");
    }
    if (!response || typeof response !== "object") {
      throw new Error("response must be an object");
    }
    if (typeof response.timeMs !== "number" || response.timeMs < 0) {
      throw new Error("response.timeMs must be a non-negative number");
    }
    if (typeof response.correct !== "boolean") {
      throw new Error("response.correct must be a boolean");
    }
    if (!_responses[challengeId]) _responses[challengeId] = [];
    var bucket = _responses[challengeId];

    // Enforce per-challenge cap (FIFO eviction)
    if (bucket.length >= _maxPerChallenge) {
      bucket.shift();
      _totalCount--;
    }

    // Enforce total cap — evict oldest from the largest bucket
    if (_totalCount >= _maxTotal) {
      var largestId = null;
      var largestLen = 0;
      var ids = Object.keys(_responses);
      for (var ri = 0; ri < ids.length; ri++) {
        if (_responses[ids[ri]].length > largestLen) {
          largestLen = _responses[ids[ri]].length;
          largestId = ids[ri];
        }
      }
      if (largestId && _responses[largestId].length > 0) {
        _responses[largestId].shift();
        _totalCount--;
      }
    }

    bucket.push({
      timeMs: response.timeMs,
      correct: response.correct,
      skipped: Boolean(response.skipped),
    });
    _totalCount++;
  }

  /**
   * Record multiple responses at once.
   * @param {Array<{ challengeId: string, timeMs: number, correct: boolean, skipped?: boolean }>} responses
   */
  function recordBatch(responses) {
    if (!Array.isArray(responses)) {
      throw new Error("responses must be an array");
    }
    responses.forEach(function (r) {
      recordResponse(r.challengeId, r);
    });
  }

  /**
   * Get response statistics for a challenge.
   * @param {string} challengeId
   * @returns {{ totalResponses: number, correctCount: number, skipCount: number,
   *             accuracy: number, skipRate: number, avgTimeMs: number,
   *             medianTimeMs: number, minTimeMs: number, maxTimeMs: number,
   *             stdDevTimeMs: number }|null}
   */
  function getStats(challengeId) {
    var data = _responses[challengeId];
    if (!data || data.length === 0) {
      return null;
    }

    var correctCount = 0;
    var skipCount = 0;
    var times = [];

    data.forEach(function (r) {
      if (r.correct) correctCount++;
      if (r.skipped) skipCount++;
      if (!r.skipped) times.push(r.timeMs);
    });

    times.sort(_numAsc);

    var avgTime = 0;
    var medianTime = 0;
    var minTime = 0;
    var maxTime = 0;
    var stdDev = 0;

    if (times.length > 0) {
      avgTime = _mean(times);
      medianTime = _median(times);

      times.sort(_numAsc);
      minTime = times[0];
      maxTime = times[times.length - 1];

      // Population stddev (n denominator) — preserved for API compatibility
      var sqDiffSum = 0;
      times.forEach(function (t) {
        var diff = t - avgTime;
        sqDiffSum += diff * diff;
      });
      stdDev = Math.sqrt(sqDiffSum / times.length);
    }

    return {
      totalResponses: data.length,
      correctCount: correctCount,
      skipCount: skipCount,
      accuracy: data.length > 0 ? correctCount / data.length : 0,
      skipRate: data.length > 0 ? skipCount / data.length : 0,
      avgTimeMs: Math.round(avgTime),
      medianTimeMs: Math.round(medianTime),
      minTimeMs: minTime,
      maxTimeMs: maxTime,
      stdDevTimeMs: Math.round(stdDev),
    };
  }

  /**
   * Calculate calibrated difficulty score (0-100) for a challenge.
   * Factors: accuracy (40%), skip rate (20%), response time percentile (40%).
   * Lower accuracy = higher difficulty, higher skip rate = higher difficulty,
   * longer response time = higher difficulty.
   * @param {string} challengeId
   * @returns {number|null} Calibrated difficulty 0-100, null if no data
   */
  function calibrateDifficulty(challengeId, precomputedMedians) {
    var stats = getStats(challengeId);
    if (!stats) return null;

    // Accuracy factor: 0% accuracy = 100 difficulty, 100% accuracy = 0
    var accuracyScore = (1 - stats.accuracy) * 100;

    // Skip factor: 100% skip rate = 100 difficulty
    var skipScore = stats.skipRate * 100;

    // Time factor: normalize against all challenges
    // Use precomputed medians if available, otherwise compute
    var allMedians = precomputedMedians;
    if (!allMedians) {
      allMedians = [];
      Object.keys(_responses).forEach(function (id) {
        var s = getStats(id);
        if (s && s.medianTimeMs > 0) allMedians.push(s.medianTimeMs);
      });
    }

    var timeScore = 50; // default
    if (allMedians.length > 1 && stats.medianTimeMs > 0) {
      allMedians.sort(_numAsc);
      // Percentile rank
      var rank = 0;
      allMedians.forEach(function (m) {
        if (m <= stats.medianTimeMs) rank++;
      });
      timeScore = (rank / allMedians.length) * 100;
    } else if (allMedians.length === 1 && stats.medianTimeMs > 0) {
      timeScore = 50;
    }

    // Weighted combination
    var difficulty = (accuracyScore * 0.4) + (skipScore * 0.2) + (timeScore * 0.4);
    return Math.round(_clamp(difficulty, 0, 100));
  }

  /**
   * Get calibration results for all challenges with data.
   * @returns {Array<{ challengeId: string, originalDifficulty: number,
   *                    calibratedDifficulty: number, stats: Object, delta: number }>}
   */
  function calibrateAll() {
    // Precompute median times once for all challenges
    var allMedians = [];
    Object.keys(_responses).forEach(function (id) {
      var s = getStats(id);
      if (s && s.medianTimeMs > 0) allMedians.push(s.medianTimeMs);
    });

    var results = [];
    _challenges.forEach(function (ch) {
      var id = ch.id || ch.title;
      var calibrated = calibrateDifficulty(id, allMedians);
      if (calibrated !== null) {
        var original = typeof ch.difficulty === "number" ? ch.difficulty : 50;
        results.push({
          challengeId: id,
          originalDifficulty: original,
          calibratedDifficulty: calibrated,
          stats: getStats(id),
          delta: calibrated - original,
        });
      }
    });
    // Sort by largest delta (biggest calibration adjustment first)
    results.sort(function (a, b) {
      return Math.abs(b.delta) - Math.abs(a.delta);
    });
    return results;
  }

  /**
   * Identify outlier challenges — ones where original difficulty
   * differs significantly from calibrated difficulty.
   * @param {number} [threshold=20] - Delta threshold to flag as outlier
   * @param {Array} [precomputedCalibration] - Pre-computed calibrateAll() results to reuse
   * @returns {Array<{ challengeId: string, originalDifficulty: number,
   *                    calibratedDifficulty: number, delta: number, direction: string }>}
   */
  function findOutliers(threshold, precomputedCalibration) {
    if (threshold === undefined) threshold = 20;
    if (typeof threshold !== "number" || threshold < 0) {
      throw new Error("threshold must be a non-negative number");
    }
    var all = precomputedCalibration || calibrateAll();
    return all
      .filter(function (r) { return Math.abs(r.delta) >= threshold; })
      .map(function (r) {
        return {
          challengeId: r.challengeId,
          originalDifficulty: r.originalDifficulty,
          calibratedDifficulty: r.calibratedDifficulty,
          delta: r.delta,
          direction: r.delta > 0 ? "harder_than_rated" : "easier_than_rated",
        };
      });
  }

  /**
   * Get difficulty distribution buckets.
   * @returns {{ easy: number, medium: number, hard: number }}
   */
  function getDifficultyDistribution(precomputedCalibration) {
    var dist = { easy: 0, medium: 0, hard: 0 };
    if (precomputedCalibration) {
      // Use pre-computed calibration results directly
      precomputedCalibration.forEach(function (r) {
        var d = r.calibratedDifficulty;
        if (d < 33) dist.easy++;
        else if (d < 67) dist.medium++;
        else dist.hard++;
      });
    } else {
      _challenges.forEach(function (ch) {
        var id = ch.id || ch.title;
        var d = calibrateDifficulty(id);
        if (d === null) return;
        if (d < 33) dist.easy++;
        else if (d < 67) dist.medium++;
        else dist.hard++;
      });
    }
    return dist;
  }

  /**
   * Generate a calibration summary report.
   * @returns {{ challengeCount: number, responsesRecorded: number,
   *             calibratedCount: number, avgDifficulty: number,
   *             distribution: Object, outlierCount: number,
   *             recommendations: string[] }}
   */
  function generateReport() {
    var calibrated = calibrateAll();
    var totalResp = 0;
    Object.keys(_responses).forEach(function (id) {
      totalResp += _responses[id].length;
    });

    var avgDiff = 0;
    if (calibrated.length > 0) {
      var sum = 0;
      calibrated.forEach(function (c) { sum += c.calibratedDifficulty; });
      avgDiff = Math.round(sum / calibrated.length);
    }

    // Reuse calibrateAll() results for outliers and distribution
    // instead of recomputing from scratch
    var outliers = findOutliers(20, calibrated);
    var dist = getDifficultyDistribution(calibrated);

    var recommendations = [];
    if (dist.easy === 0 && calibrated.length > 0) {
      recommendations.push("No easy challenges detected — consider adding simpler CAPTCHAs for better UX.");
    }
    if (dist.hard === 0 && calibrated.length > 0) {
      recommendations.push("No hard challenges — security may be weak against advanced bots.");
    }
    if (outliers.length > 0) {
      var harderCount = outliers.filter(function (o) { return o.direction === "harder_than_rated"; }).length;
      var easierCount = outliers.length - harderCount;
      if (harderCount > 0) {
        recommendations.push(harderCount + " challenge(s) are harder than their rated difficulty — consider adjusting.");
      }
      if (easierCount > 0) {
        recommendations.push(easierCount + " challenge(s) are easier than their rated difficulty — consider adjusting.");
      }
    }
    var totalCh = _challenges.length;
    if (totalResp < totalCh * 5) {
      recommendations.push("Insufficient data — collect at least 5 responses per challenge for reliable calibration.");
    }

    return {
      challengeCount: totalCh,
      responsesRecorded: totalResp,
      calibratedCount: calibrated.length,
      avgDifficulty: avgDiff,
      distribution: dist,
      outlierCount: outliers.length,
      recommendations: recommendations,
    };
  }

  /**
   * Clear all recorded responses.
   */
  function reset() {
    Object.keys(_responses).forEach(function (k) {
      delete _responses[k];
    });
    _totalCount = 0;
  }

  /**
   * Get the number of responses recorded for a challenge.
   * @param {string} challengeId
   * @returns {number}
   */
  function responseCount(challengeId) {
    return (_responses[challengeId] || []).length;
  }

  /**
   * Get total responses across all challenges.
   * @returns {number}
   */
  function totalResponses() {
    return _totalCount;
  }

  return {
    recordResponse: recordResponse,
    recordBatch: recordBatch,
    getStats: getStats,
    calibrateDifficulty: calibrateDifficulty,
    calibrateAll: calibrateAll,
    findOutliers: findOutliers,
    getDifficultyDistribution: getDifficultyDistribution,
    generateReport: generateReport,
    reset: reset,
    responseCount: responseCount,
    totalResponses: totalResponses,
  };
}

// ── Security Scorer ─────────────────────────────────────────────────

/**
 * createSecurityScorer(challenges) — evaluates a CAPTCHA challenge set's
 * resistance to automated solving across 6 security dimensions.
 */
function createSecurityScorer(challenges) {
  // ── input validation ──
  function validateChallenges(ch) {
    if (!Array.isArray(ch) || ch.length === 0) {
      throw new Error("challenges must be a non-empty array");
    }
    for (var i = 0; i < ch.length; i++) {
      if (ch[i] == null || typeof ch[i] !== "object") {
        throw new Error("each challenge must be an object");
      }
      if (ch[i].id == null || ch[i].id === "") {
        throw new Error("each challenge must have an id");
      }
      if (ch[i].humanAnswer == null || ch[i].humanAnswer === "") {
        throw new Error("each challenge must have a humanAnswer");
      }
    }
  }

  validateChallenges(challenges);

  // defensive copy
  var _challenges = challenges.map(function (c) {
    return Object.assign({}, c, {
      keywords: Array.isArray(c.keywords) ? c.keywords.slice() : [],
    });
  });

  var _dimensions = null;

  // ── helpers ──
  function clamp(v) {
    return _clamp(v, 0, 100);
  }

  function getWords(text) {
    return text.toLowerCase().split(/\s+/).filter(function (w) { return w.length > 0; });
  }

  // ── dimension scorers ──

  function scoreAnswerDiversity() {
    var answers = _challenges.map(function (c) { return c.humanAnswer; });
    var allWords = [];
    var lengths = [];
    for (var i = 0; i < answers.length; i++) {
      var words = getWords(answers[i]);
      lengths.push(words.length);
      for (var j = 0; j < words.length; j++) {
        allWords.push(words[j]);
      }
    }

    var totalWords = allWords.length;
    var uniqueSet = {};
    for (var i = 0; i < allWords.length; i++) {
      uniqueSet[allWords[i]] = true;
    }
    var uniqueCount = Object.keys(uniqueSet).length;
    var uniqueWordRatio = totalWords > 0 ? uniqueCount / totalWords : 0;

    // coefficient of variation for answer lengths
    var mean = _mean(lengths);

    var variance = 0;
    for (var i = 0; i < lengths.length; i++) {
      variance += (lengths[i] - mean) * (lengths[i] - mean);
    }
    variance = lengths.length > 1 ? variance / lengths.length : 0;
    var stddev = Math.sqrt(variance);
    var coefficientOfVariation = mean > 0 ? stddev / mean : 0;

    var avgAnswerLength = mean;

    // score: blend unique ratio and CV
    // uniqueWordRatio close to 1 = very diverse, close to 0 = repetitive
    // CV > 0.5 = good variance in length
    var ratioScore = uniqueWordRatio * 100;
    var cvScore = Math.min(coefficientOfVariation / 0.5, 1) * 100;
    var lengthScore = Math.min(avgAnswerLength / 10, 1) * 100;

    var score = clamp(ratioScore * 0.5 + cvScore * 0.25 + lengthScore * 0.25);

    return {
      name: "Answer Diversity",
      score: Math.round(score),
      weight: 0.20,
      details: {
        uniqueWordRatio: uniqueWordRatio,
        coefficientOfVariation: coefficientOfVariation,
        avgAnswerLength: avgAnswerLength,
        totalWords: totalWords,
        uniqueWords: uniqueCount,
      },
    };
  }

  function scoreAIResistance() {
    var withAI = [];
    for (var i = 0; i < _challenges.length; i++) {
      if (_challenges[i].aiAnswer != null && _challenges[i].aiAnswer !== "") {
        withAI.push(_challenges[i]);
      }
    }

    if (withAI.length === 0) {
      return {
        name: "AI Resistance",
        score: 50,
        weight: 0.25,
        details: {
          avgSimilarity: 0,
          challengesWithAI: 0,
          totalChallenges: _challenges.length,
          perChallenge: [],
        },
      };
    }

    var totalDissimilarity = 0;
    var perChallenge = [];
    for (var i = 0; i < withAI.length; i++) {
      var sim = textSimilarity(withAI[i].humanAnswer, withAI[i].aiAnswer);
      perChallenge.push({ id: withAI[i].id, similarity: sim });
      totalDissimilarity += (1 - sim);
    }
    var avgDissimilarity = totalDissimilarity / withAI.length;
    var avgSimilarity = 1 - avgDissimilarity;

    return {
      name: "AI Resistance",
      score: clamp(Math.round(avgDissimilarity * 100)),
      weight: 0.25,
      details: {
        avgSimilarity: avgSimilarity,
        challengesWithAI: withAI.length,
        totalChallenges: _challenges.length,
        perChallenge: perChallenge,
      },
    };
  }

  function scoreKeywordSpecificity() {
    var WEAK = { video: 1, gif: 1, image: 1, picture: 1, animation: 1, clip: 1, funny: 1, cool: 1, thing: 1, stuff: 1 };

    var allKeywords = [];
    for (var i = 0; i < _challenges.length; i++) {
      var kw = _challenges[i].keywords;
      if (Array.isArray(kw)) {
        for (var j = 0; j < kw.length; j++) {
          allKeywords.push(kw[j].toLowerCase());
        }
      }
    }

    if (allKeywords.length === 0) {
      return {
        name: "Keyword Specificity",
        score: 50,
        weight: 0.15,
        details: {
          uniqueKeywordRatio: 0,
          avgKeywordLength: 0,
          weakKeywordRatio: 0,
          totalKeywords: 0,
          uniqueKeywords: 0,
        },
      };
    }

    var uniqueSet = {};
    var weakCount = 0;
    var totalLen = 0;
    for (var i = 0; i < allKeywords.length; i++) {
      uniqueSet[allKeywords[i]] = true;
      if (WEAK[allKeywords[i]]) weakCount++;
      totalLen += allKeywords[i].length;
    }
    var uniqueCount = Object.keys(uniqueSet).length;
    var uniqueRatio = uniqueCount / allKeywords.length;
    var avgLen = totalLen / allKeywords.length;
    var weakRatio = weakCount / allKeywords.length;

    // avg keyword length score: 6+ chars is good
    var lengthScore = Math.min(avgLen / 6, 1) * 100;
    var uScore = uniqueRatio * 100;
    var weakScore = (1 - weakRatio) * 100;

    var score = clamp(Math.round(uScore * 0.35 + lengthScore * 0.30 + weakScore * 0.35));

    return {
      name: "Keyword Specificity",
      score: score,
      weight: 0.15,
      details: {
        uniqueKeywordRatio: uniqueRatio,
        avgKeywordLength: avgLen,
        weakKeywordRatio: weakRatio,
        totalKeywords: allKeywords.length,
        uniqueKeywords: uniqueCount,
      },
    };
  }

  function scoreDifficultyCoverage() {
    var withDiff = [];
    for (var i = 0; i < _challenges.length; i++) {
      if (_challenges[i].difficulty != null && typeof _challenges[i].difficulty === "number") {
        withDiff.push(_challenges[i].difficulty);
      }
    }

    if (withDiff.length === 0) {
      return {
        name: "Difficulty Coverage",
        score: 50,
        weight: 0.15,
        details: {
          easy: 0,
          medium: 0,
          hard: 0,
          challengesWithDifficulty: 0,
          totalChallenges: _challenges.length,
        },
      };
    }

    var easy = 0, medium = 0, hard = 0;
    for (var i = 0; i < withDiff.length; i++) {
      var d = withDiff[i];
      if (d <= 33) easy++;
      else if (d <= 66) medium++;
      else hard++;
    }

    var bucketsFilled = (easy > 0 ? 1 : 0) + (medium > 0 ? 1 : 0) + (hard > 0 ? 1 : 0);
    var coverageScore = (bucketsFilled / 3) * 100;

    // evenness: ideal is 1/3 each
    var total = withDiff.length;
    var easyP = total > 0 ? easy / total : 0;
    var medP = total > 0 ? medium / total : 0;
    var hardP = total > 0 ? hard / total : 0;
    var ideal = 1 / 3;
    var deviation = Math.abs(easyP - ideal) + Math.abs(medP - ideal) + Math.abs(hardP - ideal);
    // max deviation is ~1.33 (all in one bucket)
    var evennessScore = (1 - deviation / 1.334) * 100;

    var score = clamp(Math.round(coverageScore * 0.5 + evennessScore * 0.5));

    return {
      name: "Difficulty Coverage",
      score: score,
      weight: 0.15,
      details: {
        easy: easy,
        medium: medium,
        hard: hard,
        challengesWithDifficulty: withDiff.length,
        totalChallenges: _challenges.length,
      },
    };
  }

  function scoreCognitiveComplexity() {
    var TEMPORAL = ["then", "after", "before", "while", "suddenly", "until", "finally", "next"];
    var CAUSAL = ["because", "so", "causes", "makes"];
    var CAUSAL_PHRASES = ["leads to", "results in"];

    var totalWordCount = 0;
    var temporalCount = 0;
    var causalCount = 0;

    for (var i = 0; i < _challenges.length; i++) {
      var answer = _challenges[i].humanAnswer.toLowerCase();
      var words = getWords(answer);
      totalWordCount += words.length;

      for (var j = 0; j < words.length; j++) {
        if (TEMPORAL.indexOf(words[j]) !== -1) temporalCount++;
        if (CAUSAL.indexOf(words[j]) !== -1) causalCount++;
      }
      for (var k = 0; k < CAUSAL_PHRASES.length; k++) {
        if (answer.indexOf(CAUSAL_PHRASES[k]) !== -1) causalCount++;
      }
    }

    var avgWordCount = _challenges.length > 0 ? totalWordCount / _challenges.length : 0;
    var totalAnswerWords = totalWordCount;
    var temporalDensity = totalAnswerWords > 0 ? temporalCount / totalAnswerWords : 0;
    var causalDensity = totalAnswerWords > 0 ? causalCount / totalAnswerWords : 0;

    // wordCountScore: 15+ words is good
    var wordCountScore = Math.min(avgWordCount / 15, 1) * 100;
    // temporal density: 0.05+ is good
    var temporalScore = Math.min(temporalDensity / 0.05, 1) * 100;
    // causal density: 0.03+ is good
    var causalScore = Math.min(causalDensity / 0.03, 1) * 100;

    var score = clamp(Math.round(wordCountScore * 0.50 + temporalScore * 0.25 + causalScore * 0.25));

    return {
      name: "Cognitive Complexity",
      score: score,
      weight: 0.15,
      details: {
        avgWordCount: avgWordCount,
        temporalWords: temporalCount,
        causalWords: causalCount,
        temporalDensity: temporalDensity,
        causalDensity: causalDensity,
      },
    };
  }

  function scorePatternPredictability() {
    var answers = _challenges.map(function (c) { return c.humanAnswer; });

    if (answers.length <= 1) {
      return {
        name: "Pattern Predictability",
        score: 50,
        weight: 0.10,
        details: {
          firstWordDiversity: 1,
          avgBigramUniqueness: 1,
          mostCommonFirstWordRatio: answers.length === 1 ? 1 : 0,
        },
      };
    }

    // first-word diversity — single object tracks both counts and diversity
    var firstWordCounts = {};
    for (var i = 0; i < answers.length; i++) {
      var w = getWords(answers[i]);
      if (w.length > 0) {
        var fw = w[0];
        firstWordCounts[fw] = (firstWordCounts[fw] || 0) + 1;
      }
    }
    var fwKeys = Object.keys(firstWordCounts);
    var firstWordDiversity = fwKeys.length / answers.length;

    // most common first word ratio (structural similarity)
    var maxFirstWordCount = 0;
    for (var i = 0; i < fwKeys.length; i++) {
      if (firstWordCounts[fwKeys[i]] > maxFirstWordCount) {
        maxFirstWordCount = firstWordCounts[fwKeys[i]];
      }
    }
    var mostCommonFirstWordRatio = maxFirstWordCount / answers.length;

    // bigram uniqueness
    var totalBigrams = 0;
    var uniqueBigrams = {};
    for (var i = 0; i < answers.length; i++) {
      var words = getWords(answers[i]);
      for (var j = 0; j < words.length - 1; j++) {
        var bigram = words[j] + " " + words[j + 1];
        uniqueBigrams[bigram] = true;
        totalBigrams++;
      }
    }
    var bigramUniqueness = totalBigrams > 0 ? Object.keys(uniqueBigrams).length / totalBigrams : 1;

    // score: high diversity + high bigram uniqueness + low structural similarity = good
    var diversityScore = firstWordDiversity * 100;
    var bigramScore = bigramUniqueness * 100;
    var structureScore = (1 - mostCommonFirstWordRatio) * 100;

    var score = clamp(Math.round(diversityScore * 0.40 + bigramScore * 0.30 + structureScore * 0.30));

    return {
      name: "Pattern Predictability",
      score: score,
      weight: 0.10,
      details: {
        firstWordDiversity: firstWordDiversity,
        avgBigramUniqueness: bigramUniqueness,
        mostCommonFirstWordRatio: mostCommonFirstWordRatio,
      },
    };
  }

  // ── compute all dimensions ──

  function computeDimensions() {
    _dimensions = [
      scoreAnswerDiversity(),
      scoreAIResistance(),
      scoreKeywordSpecificity(),
      scoreDifficultyCoverage(),
      scoreCognitiveComplexity(),
      scorePatternPredictability(),
    ];
  }

  function ensureComputed() {
    if (!_dimensions) computeDimensions();
  }

  // ── grade ──
  function computeGrade(score) {
    if (score >= 80) return "A";
    if (score >= 65) return "B";
    if (score >= 50) return "C";
    if (score >= 35) return "D";
    return "F";
  }

  // ── public API ──

  function getDimensions() {
    ensureComputed();
    return _dimensions.slice();
  }

  function getDimension(name) {
    ensureComputed();
    var nameMap = {
      answerDiversity: "Answer Diversity",
      aiResistance: "AI Resistance",
      keywordSpecificity: "Keyword Specificity",
      difficultyCoverage: "Difficulty Coverage",
      cognitiveComplexity: "Cognitive Complexity",
      patternPredictability: "Pattern Predictability",
    };
    var fullName = nameMap[name] || name;
    for (var i = 0; i < _dimensions.length; i++) {
      if (_dimensions[i].name === fullName) return _dimensions[i];
    }
    return null;
  }

  function getVulnerabilities() {
    ensureComputed();
    var vulns = [];
    for (var i = 0; i < _dimensions.length; i++) {
      var d = _dimensions[i];
      if (d.score < 60) {
        var severity = d.score < 20 ? "critical" : d.score < 40 ? "high" : "medium";
        var descriptions = {
          "Answer Diversity": "Human answers lack diversity — bots can pattern-match common phrasing",
          "AI Resistance": "AI-generated answers closely match human answers — weak bot discrimination",
          "Keyword Specificity": "Keywords are too generic — bots can guess challenge content",
          "Difficulty Coverage": "Challenge difficulty is not well-distributed across easy, medium, and hard",
          "Cognitive Complexity": "Answers lack cognitive complexity — simple patterns are easy for bots",
          "Pattern Predictability": "Answers follow predictable structural patterns — bots can exploit this",
        };
        vulns.push({
          dimension: d.name,
          score: d.score,
          severity: severity,
          description: descriptions[d.name] || "This dimension scores below secure threshold",
        });
      }
    }
    return vulns;
  }

  function getRecommendations() {
    ensureComputed();
    var vulns = getVulnerabilities();
    var recs = [];

    var recTexts = {
      "Answer Diversity": "Add challenges with longer, more varied descriptions to increase answer diversity",
      "AI Resistance": "Replace challenges where AI answers closely match human answers — these provide weak bot discrimination",
      "Keyword Specificity": "Replace generic keywords (video, gif, funny) with specific, descriptive terms",
      "Difficulty Coverage": "Include challenges across easy, medium, and hard difficulty levels",
      "Cognitive Complexity": "Add challenges requiring temporal or causal reasoning (sequences, cause-effect)",
      "Pattern Predictability": "Vary answer structure — avoid starting all answers with the same phrase",
    };

    for (var i = 0; i < vulns.length; i++) {
      recs.push({
        priority: vulns[i].severity,
        dimension: vulns[i].dimension,
        text: recTexts[vulns[i].dimension] || "Improve this dimension to strengthen security",
      });
    }

    // general recommendation based on overall score
    var overall = computeOverallScore();
    var generalPriority = overall >= 80 ? "low" : overall >= 65 ? "medium" : overall >= 50 ? "high" : "critical";
    var generalText = overall >= 80
      ? "Challenge set has strong security — maintain current diversity and complexity levels"
      : overall >= 65
        ? "Challenge set is reasonably secure — address flagged vulnerabilities for improvement"
        : overall >= 50
          ? "Challenge set has moderate security gaps — prioritize fixing high-severity vulnerabilities"
          : "Challenge set has significant security weaknesses — comprehensive improvements needed";
    recs.push({
      priority: generalPriority,
      dimension: "overall",
      text: generalText,
    });

    return recs;
  }

  function computeOverallScore() {
    ensureComputed();
    var score = 0;
    for (var i = 0; i < _dimensions.length; i++) {
      score += _dimensions[i].score * _dimensions[i].weight;
    }
    return clamp(Math.round(score));
  }

  function getReport() {
    ensureComputed();
    var score = computeOverallScore();
    var grade = computeGrade(score);
    var dims = getDimensions();
    var vulns = getVulnerabilities();
    var recs = getRecommendations();

    var summary = "Security score: " + score + "/100 (Grade " + grade + "). ";
    if (vulns.length === 0) {
      summary += "No vulnerabilities detected across " + dims.length + " dimensions.";
    } else {
      summary += vulns.length + " vulnerability" + (vulns.length > 1 ? "ies" : "") + " detected: " +
        vulns.map(function (v) { return v.dimension + " (" + v.severity + ")"; }).join(", ") + ".";
    }

    return {
      score: score,
      grade: grade,
      dimensions: dims,
      vulnerabilities: vulns,
      recommendations: recs,
      summary: summary,
    };
  }

  function isSecure(threshold) {
    if (threshold == null) threshold = 60;
    return computeOverallScore() >= threshold;
  }

  function reset(newChallenges) {
    validateChallenges(newChallenges);
    _challenges = newChallenges.map(function (c) {
      return Object.assign({}, c, {
        keywords: Array.isArray(c.keywords) ? c.keywords.slice() : [],
      });
    });
    _dimensions = null;
  }

  return {
    getReport: getReport,
    getDimensions: getDimensions,
    getDimension: getDimension,
    getVulnerabilities: getVulnerabilities,
    getRecommendations: getRecommendations,
    isSecure: isSecure,
    reset: reset,
  };
}

// ── Session Manager ─────────────────────────────────────────────────

/**
 * Creates a CAPTCHA session manager for multi-step verification flows.
 * Manages sessions where users must pass multiple challenges with
 * configurable difficulty escalation, timeouts, and pass thresholds.
 *
 * @param {Object} [options]
 * @param {number} [options.challengesPerSession=3] - Challenges required per session
 * @param {number} [options.passThreshold=0.67] - Fraction of correct answers to pass (0-1)
 * @param {number} [options.sessionTimeoutMs=300000] - Session expiry in ms (default 5 min)
 * @param {boolean} [options.escalateDifficulty=true] - Increase difficulty after each correct answer
 * @param {number} [options.difficultyStep=15] - Difficulty increase per correct answer (0-100)
 * @param {number} [options.baseDifficulty=30] - Starting difficulty (0-100)
 * @param {number} [options.maxDifficulty=95] - Maximum difficulty cap (0-100)
 * @param {number} [options.maxSessions=1000] - Maximum concurrent sessions before cleanup
 * @returns {Object} Session manager instance
 */
function createSessionManager(options) {
  options = options || {};

  var challengesPerSession = Math.floor(_posOpt(options.challengesPerSession, 3));
  var passThreshold = (typeof options.passThreshold === "number" && options.passThreshold >= 0 && options.passThreshold <= 1)
    ? options.passThreshold : 0.67;
  var sessionTimeoutMs = _posOpt(options.sessionTimeoutMs, 300000);
  var escalateDifficulty = options.escalateDifficulty !== false;
  var difficultyStep = (typeof options.difficultyStep === "number" && options.difficultyStep >= 0)
    ? options.difficultyStep : 15;
  var baseDifficulty = (typeof options.baseDifficulty === "number" && options.baseDifficulty >= 0 && options.baseDifficulty <= 100)
    ? options.baseDifficulty : 30;
  var maxDifficulty = (typeof options.maxDifficulty === "number" && options.maxDifficulty >= 0 && options.maxDifficulty <= 100)
    ? options.maxDifficulty : 95;
  var maxSessions = Math.floor(_posOpt(options.maxSessions, 1000));

  // Internal state: Map<sessionId, SessionState>
  // Use null-prototype object to prevent prototype pollution via
  // crafted session IDs targeting Object.prototype properties.
  var sessions = Object.create(null);
  var sessionCount = 0;

  function _generateId() {
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    var id = "";
    for (var i = 0; i < 16; i++) {
      id += chars.charAt(secureRandomInt(chars.length));
    }
    return "sess_" + id + "_" + _now().toString(36);
  }

  /**
   * Remove expired sessions to bound memory usage.
   */
  function _cleanup() {
    var now = _now();
    var keys = Object.keys(sessions);
    for (var i = 0; i < keys.length; i++) {
      var s = sessions[keys[i]];
      if (s.status !== "active" || now - s.createdAt > sessionTimeoutMs) {
        if (s.status === "active") {
          s.status = "expired";
          s.completedAt = now;
        }
        // Only delete completed/expired sessions older than 2x timeout
        if (now - s.createdAt > sessionTimeoutMs * 2) {
          delete sessions[keys[i]];
          sessionCount--;
        }
      }
    }
  }

  /**
   * Start a new CAPTCHA verification session.
   *
   * @param {Object} [metadata] - Optional metadata to attach (userId, ip, etc.)
   * @returns {{ sessionId: string, difficulty: number, challengeIndex: number, totalChallenges: number }}
   */
  function startSession(metadata) {
    // Cleanup if we're at capacity
    if (sessionCount >= maxSessions) {
      _cleanup();
    }

    var id = _generateId();
    var now = _now();

    sessions[id] = {
      status: "active",
      createdAt: now,
      completedAt: null,
      currentIndex: 0,
      results: [],
      currentDifficulty: baseDifficulty,
      metadata: metadata || {},
    };
    sessionCount++;

    return {
      sessionId: id,
      difficulty: baseDifficulty,
      challengeIndex: 0,
      totalChallenges: challengesPerSession,
    };
  }

  /**
   * Submit a challenge response for a session.
   *
   * @param {string} sessionId - Session identifier
   * @param {boolean} correct - Whether the user answered correctly
   * @param {number} [responseTimeMs] - Optional response time in ms
   * @returns {{ done: boolean, passed: boolean|null, nextDifficulty: number|null, challengeIndex: number, correctCount: number, totalAnswered: number }}
   */
  function submitResponse(sessionId, correct, responseTimeMs) {
    var session = sessions[sessionId];
    if (!session) {
      return { error: "session_not_found" };
    }
    if (session.status !== "active") {
      return { error: "session_" + session.status };
    }

    // Check timeout
    var now = _now();
    if (now - session.createdAt > sessionTimeoutMs) {
      session.status = "expired";
      session.completedAt = now;
      return { error: "session_expired" };
    }

    // Record result
    session.results.push({
      index: session.currentIndex,
      correct: !!correct,
      difficulty: session.currentDifficulty,
      responseTimeMs: (typeof responseTimeMs === "number" && responseTimeMs >= 0) ? responseTimeMs : null,
      timestamp: now,
    });
    session.currentIndex++;

    // Escalate or reset difficulty
    if (escalateDifficulty) {
      if (correct) {
        session.currentDifficulty = Math.min(session.currentDifficulty + difficultyStep, maxDifficulty);
      } else {
        // On wrong answer, reduce difficulty slightly (half step)
        session.currentDifficulty = Math.max(session.currentDifficulty - Math.floor(difficultyStep / 2), baseDifficulty);
      }
    }

    var correctCount = 0;
    for (var i = 0; i < session.results.length; i++) {
      if (session.results[i].correct) correctCount++;
    }

    // Check if session is complete
    if (session.currentIndex >= challengesPerSession) {
      var passRate = correctCount / challengesPerSession;
      var passed = passRate >= passThreshold;
      session.status = passed ? "passed" : "failed";
      session.completedAt = now;

      return {
        done: true,
        passed: passed,
        nextDifficulty: null,
        challengeIndex: session.currentIndex,
        correctCount: correctCount,
        totalAnswered: session.results.length,
        passRate: Math.round(passRate * 1000) / 1000,
      };
    }

    return {
      done: false,
      passed: null,
      nextDifficulty: session.currentDifficulty,
      challengeIndex: session.currentIndex,
      correctCount: correctCount,
      totalAnswered: session.results.length,
    };
  }

  /**
   * Get the current state of a session.
   *
   * @param {string} sessionId
   * @returns {Object|null} Session state or null if not found
   */
  function getSession(sessionId) {
    var session = sessions[sessionId];
    if (!session) return null;

    // Check timeout for active sessions
    if (session.status === "active" && _now() - session.createdAt > sessionTimeoutMs) {
      session.status = "expired";
      session.completedAt = _now();
    }

    var correctCount = 0;
    var totalResponseMs = 0;
    var responseCount = 0;
    for (var i = 0; i < session.results.length; i++) {
      if (session.results[i].correct) correctCount++;
      if (session.results[i].responseTimeMs !== null) {
        totalResponseMs += session.results[i].responseTimeMs;
        responseCount++;
      }
    }

    return {
      sessionId: sessionId,
      status: session.status,
      challengeIndex: session.currentIndex,
      totalChallenges: challengesPerSession,
      correctCount: correctCount,
      currentDifficulty: session.currentDifficulty,
      avgResponseTimeMs: responseCount > 0 ? Math.round(totalResponseMs / responseCount) : null,
      results: session.results.slice(),
      metadata: session.metadata,
      createdAt: session.createdAt,
      completedAt: session.completedAt,
      remainingMs: session.status === "active"
        ? Math.max(0, sessionTimeoutMs - (_now() - session.createdAt))
        : 0,
    };
  }

  /**
   * Invalidate / cancel a session early.
   *
   * @param {string} sessionId
   * @returns {boolean} True if invalidated, false if not found
   */
  function invalidateSession(sessionId) {
    var session = sessions[sessionId];
    if (!session) return false;
    if (session.status === "active") {
      session.status = "cancelled";
      session.completedAt = _now();
    }
    return true;
  }

  /**
   * Get aggregate statistics across all sessions.
   *
   * @returns {Object} Stats summary
   */
  function getStats() {
    var keys = Object.keys(sessions);
    var total = keys.length;
    var active = 0, passed = 0, failed = 0, expired = 0, cancelled = 0;
    var totalResponseMs = 0;
    var responseCount = 0;
    var difficultySum = 0;
    var completedSessions = 0;

    for (var i = 0; i < keys.length; i++) {
      var s = sessions[keys[i]];
      switch (s.status) {
        case "active": active++; break;
        case "passed": passed++; completedSessions++; break;
        case "failed": failed++; completedSessions++; break;
        case "expired": expired++; break;
        case "cancelled": cancelled++; break;
      }
      for (var j = 0; j < s.results.length; j++) {
        difficultySum += s.results[j].difficulty;
        if (s.results[j].responseTimeMs !== null) {
          totalResponseMs += s.results[j].responseTimeMs;
          responseCount++;
        }
      }
    }

    return {
      totalSessions: total,
      active: active,
      passed: passed,
      failed: failed,
      expired: expired,
      cancelled: cancelled,
      passRate: completedSessions > 0 ? Math.round((passed / completedSessions) * 1000) / 1000 : 0,
      avgResponseTimeMs: responseCount > 0 ? Math.round(totalResponseMs / responseCount) : null,
      avgDifficulty: responseCount > 0 ? Math.round((difficultySum / responseCount) * 10) / 10 : null,
    };
  }

  /**
   * Get current configuration.
   *
   * @returns {Object} Configuration values
   */
  function getConfig() {
    return {
      challengesPerSession: challengesPerSession,
      passThreshold: passThreshold,
      sessionTimeoutMs: sessionTimeoutMs,
      escalateDifficulty: escalateDifficulty,
      difficultyStep: difficultyStep,
      baseDifficulty: baseDifficulty,
      maxDifficulty: maxDifficulty,
      maxSessions: maxSessions,
    };
  }

  return {
    startSession: startSession,
    submitResponse: submitResponse,
    getSession: getSession,
    invalidateSession: invalidateSession,
    getStats: getStats,
    getConfig: getConfig,
  };
}

// ── Challenge Pool Manager ───────────────────────────────────────────

/**
 * Create a pool manager for rotating and tracking CAPTCHA challenges.
 * Tracks usage statistics per challenge, supports weighted selection
 * (least-used challenges are preferred), and auto-retires overused or
 * too-easy challenges.
 *
 * @param {Object} [options] - Pool configuration
 * @param {number} [options.maxServes=100] - Retire a challenge after this many serves
 * @param {number} [options.minPassRate=0.3] - Retire if pass rate drops below this (too hard)
 * @param {number} [options.maxPassRate=0.95] - Retire if pass rate exceeds this (too easy / leaked)
 * @param {number} [options.minPoolSize=3] - Never retire below this many active challenges
 * @returns {Object} PoolManager instance
 */
function createPoolManager(options) {
  options = options || {};
  var maxServes = Math.floor(_posOpt(options.maxServes, 100));
  var minPassRate = (typeof options.minPassRate === "number") ? options.minPassRate : 0.3;
  var maxPassRate = (typeof options.maxPassRate === "number") ? options.maxPassRate : 0.95;
  var minPoolSize = Math.floor(_posOpt(options.minPoolSize, 3));

  // challenge id → { challenge, serves, passes, fails, retired, addedAt, retiredAt, retireReason }
  // Use null-prototype object to prevent prototype pollution via crafted challenge IDs.
  var registry = Object.create(null);
  var activeIds = [];

  function _rebuildActive() {
    activeIds = [];
    for (var id in registry) {
      if (!registry[id].retired) {
        activeIds.push(id);
      }
    }
  }

  /**
   * Add one or more challenges to the pool.
   *
   * @param {Object|Object[]} challenges - Challenge object(s) with at least an `id` property
   * @returns {number} Number of challenges added (duplicates are skipped)
   */
  function add(challenges) {
    if (!Array.isArray(challenges)) challenges = [challenges];
    var added = 0;
    for (var i = 0; i < challenges.length; i++) {
      var c = challenges[i];
      if (!c || !c.id) continue;
      var id = String(c.id);
      if (registry[id]) continue; // skip duplicates
      registry[id] = {
        challenge: c,
        serves: 0,
        passes: 0,
        fails: 0,
        retired: false,
        addedAt: _now(),
        retiredAt: null,
        retireReason: null,
      };
      activeIds.push(id);
      added++;
    }
    return added;
  }

  /**
   * Check if a challenge should be retired based on its stats.
   * @private
   */
  function _shouldRetire(entry) {
    if (entry.serves >= maxServes) return "max_serves";
    if (entry.serves >= 10) { // need at least 10 serves for meaningful rate
      var rate = entry.passes / entry.serves;
      if (rate < minPassRate) return "too_hard";
      if (rate > maxPassRate) return "too_easy";
    }
    return null;
  }

  /**
   * Run retirement checks on all active challenges.
   * Won't retire below minPoolSize.
   *
   * @returns {string[]} IDs of newly retired challenges
   */
  function enforceRetirement() {
    var retired = [];
    // Sort by severity: highest-serve challenges first
    var candidates = activeIds.slice().sort(function (a, b) {
      return registry[b].serves - registry[a].serves;
    });
    for (var i = 0; i < candidates.length; i++) {
      if (activeIds.length - retired.length <= minPoolSize) break;
      var id = candidates[i];
      var reason = _shouldRetire(registry[id]);
      if (reason) {
        registry[id].retired = true;
        registry[id].retiredAt = _now();
        registry[id].retireReason = reason;
        retired.push(id);
      }
    }
    if (retired.length > 0) _rebuildActive();
    return retired;
  }

  /**
   * Pick N challenges using weighted random selection.
   * Less-served challenges are more likely to be picked.
   *
   * @param {number} [count=1] - Number of challenges to pick
   * @returns {Object[]} Selected challenge objects
   */
  function pick(count) {
    count = Math.min(Math.max(1, count || 1), activeIds.length);
    if (activeIds.length === 0) return [];

    // Build weights: inverse of (serves + 1)
    var weights = [];
    var totalWeight = 0;
    for (var i = 0; i < activeIds.length; i++) {
      var w = 1 / (registry[activeIds[i]].serves + 1);
      weights.push(w);
      totalWeight += w;
    }

    var picked = [];
    var usedIndices = {};
    for (var n = 0; n < count; n++) {
      var rand = (secureRandomInt(1000000) / 1000000) * totalWeight;
      var cumulative = 0;
      for (var j = 0; j < weights.length; j++) {
        if (usedIndices[j]) continue;
        cumulative += weights[j];
        if (rand <= cumulative) {
          var id = activeIds[j];
          registry[id].serves++;
          picked.push(registry[id].challenge);
          totalWeight -= weights[j];
          usedIndices[j] = true;
          break;
        }
      }
    }

    return picked;
  }

  /**
   * Record a pass or fail result for a challenge.
   *
   * @param {string|number} challengeId - Challenge identifier
   * @param {boolean} passed - Whether the user passed
   */
  function recordResult(challengeId, passed) {
    var id = String(challengeId);
    if (!registry[id]) return;
    if (passed) {
      registry[id].passes++;
    } else {
      registry[id].fails++;
    }
  }

  /**
   * Get stats for all challenges or a specific one.
   *
   * @param {string|number} [challengeId] - Optional specific challenge ID
   * @returns {Object|Object[]} Stats object(s)
   */
  function getStats(challengeId) {
    if (challengeId !== undefined) {
      var id = String(challengeId);
      var e = registry[id];
      if (!e) return null;
      return {
        id: id,
        serves: e.serves,
        passes: e.passes,
        fails: e.fails,
        passRate: e.serves > 0 ? e.passes / e.serves : null,
        retired: e.retired,
        retireReason: e.retireReason,
      };
    }
    var all = [];
    for (var rid in registry) {
      var entry = registry[rid];
      all.push({
        id: rid,
        serves: entry.serves,
        passes: entry.passes,
        fails: entry.fails,
        passRate: entry.serves > 0 ? entry.passes / entry.serves : null,
        retired: entry.retired,
        retireReason: entry.retireReason,
      });
    }
    return all;
  }

  /**
   * Get pool summary: active count, retired count, total serves.
   *
   * @returns {{ activeCount: number, retiredCount: number, totalServes: number, totalPasses: number, totalFails: number }}
   */
  function getSummary() {
    var totalServes = 0, totalPasses = 0, totalFails = 0, retiredCount = 0;
    for (var id in registry) {
      var e = registry[id];
      totalServes += e.serves;
      totalPasses += e.passes;
      totalFails += e.fails;
      if (e.retired) retiredCount++;
    }
    return {
      activeCount: activeIds.length,
      retiredCount: retiredCount,
      totalServes: totalServes,
      totalPasses: totalPasses,
      totalFails: totalFails,
      overallPassRate: totalServes > 0 ? totalPasses / totalServes : null,
    };
  }

  /**
   * Reinstate a previously retired challenge (e.g., after updating it).
   *
   * @param {string|number} challengeId - Challenge to reinstate
   * @returns {boolean} True if reinstated
   */
  function reinstate(challengeId) {
    var id = String(challengeId);
    var e = registry[id];
    if (!e || !e.retired) return false;
    e.retired = false;
    e.retiredAt = null;
    e.retireReason = null;
    e.serves = 0;
    e.passes = 0;
    e.fails = 0;
    _rebuildActive();
    return true;
  }

  /**
   * Export the pool state as a serializable object (for persistence).
   *
   * @returns {Object} Serializable pool state
   */
  function exportState() {
    var entries = [];
    for (var id in registry) {
      var e = registry[id];
      entries.push({
        id: id,
        serves: e.serves,
        passes: e.passes,
        fails: e.fails,
        retired: e.retired,
        addedAt: e.addedAt,
        retiredAt: e.retiredAt,
        retireReason: e.retireReason,
      });
    }
    return { entries: entries, exportedAt: _now() };
  }

  /**
   * Import previously exported stats (challenges must already be added).
   *
   * @param {Object} state - State object from exportState()
   * @returns {number} Number of entries restored
   */
  function importState(state) {
    if (!state || !Array.isArray(state.entries)) return 0;
    var restored = 0;
    for (var i = 0; i < state.entries.length; i++) {
      var s = state.entries[i];
      var e = registry[s.id];
      if (!e) continue;
      e.serves = s.serves || 0;
      e.passes = s.passes || 0;
      e.fails = s.fails || 0;
      e.retired = !!s.retired;
      e.addedAt = s.addedAt || e.addedAt;
      e.retiredAt = s.retiredAt || null;
      e.retireReason = s.retireReason || null;
      restored++;
    }
    _rebuildActive();
    return restored;
  }

  return {
    add: add,
    pick: pick,
    recordResult: recordResult,
    enforceRetirement: enforceRetirement,
    reinstate: reinstate,
    getStats: getStats,
    getSummary: getSummary,
    exportState: exportState,
    importState: importState,
  };
}

// ── Response Analyzer ───────────────────────────────────────────────

/**
 * Create a response analyzer that evaluates CAPTCHA responses for
 * bot-like patterns and generates a humanity confidence score.
 *
 * Analyzes timing, linguistic diversity, response specificity, and
 * cross-response consistency to distinguish human from automated submissions.
 *
 * @param {Object} [opts] - Configuration options
 * @param {number} [opts.minResponseTimeMs=800] - Responses faster than this are suspicious
 * @param {number} [opts.maxTimingCvThreshold=0.15] - Coefficient of variation below this flags uniform timing
 * @param {number} [opts.duplicateThreshold=0.85] - Jaccard similarity above this counts as duplicate
 * @param {number} [opts.minWordDiversity=0.4] - Type-token ratio below this is suspicious
 * @returns {Object} Analyzer instance
 */
function createResponseAnalyzer(opts) {
  opts = opts || {};
  var minResponseTimeMs = opts.minResponseTimeMs != null ? opts.minResponseTimeMs : 800;
  var maxTimingCvThreshold = opts.maxTimingCvThreshold != null ? opts.maxTimingCvThreshold : 0.15;
  var duplicateThreshold = opts.duplicateThreshold != null ? opts.duplicateThreshold : 0.85;
  var minWordDiversity = opts.minWordDiversity != null ? opts.minWordDiversity : 0.4;

  function tokenize(text) {
    if (!text || typeof text !== 'string') return [];
    return text.toLowerCase().replace(/[^a-z0-9\s'-]/g, '').split(/\s+/).filter(function (w) { return w.length > 0; });
  }

  /**
   * Analyze timing patterns in responses.
   * @param {number[]} responseTimes - Array of response times in ms
   * @returns {Object} Timing analysis with suspicion flags
   */
  function analyzeTiming(responseTimes) {
    var flags = [];
    if (!responseTimes || responseTimes.length === 0) {
      return { avgMs: 0, medianMs: 0, stdDevMs: 0, cv: 0,
               tooFastCount: 0, isUniform: false, suspicionFlags: ['no_timing_data'] };
    }

    var sorted = responseTimes.slice().sort(_numAsc);
    var avg = _mean(sorted);
    var median = _median(sorted);
    var stdDev = _stddev(sorted, avg);
    var cv = avg > 0 ? stdDev / avg : 0;

    var tooFastCount = sorted.filter(function (t) { return t < minResponseTimeMs; }).length;
    var isUniform = sorted.length >= 3 && cv < maxTimingCvThreshold;

    if (tooFastCount > 0) flags.push('fast_responses:' + tooFastCount);
    if (tooFastCount === sorted.length) flags.push('all_responses_suspiciously_fast');
    if (isUniform) flags.push('uniform_timing');
    if (avg < minResponseTimeMs) flags.push('avg_below_threshold');

    return {
      avgMs: Math.round(avg), medianMs: Math.round(median),
      stdDevMs: Math.round(stdDev), cv: Math.round(cv * 1000) / 1000,
      tooFastCount: tooFastCount, isUniform: isUniform, suspicionFlags: flags
    };
  }

  /**
   * Analyze linguistic properties of a single response.
   * @param {string} response - User response text
   * @returns {Object} Linguistic analysis
   */
  function analyzeResponse(response) {
    var words = tokenize(response);
    var n = words.length;
    if (n === 0) {
      return { wordCount: 0, uniqueWords: 0, typeTokenRatio: 0,
        avgWordLength: 0, hasDescriptiveWords: false, specificity: 'empty' };
    }

    var uniqueSet = {};
    words.forEach(function (w) { uniqueSet[w] = true; });
    var unique = Object.keys(uniqueSet).length;
    var ttr = unique / n;

    var totalLen = words.reduce(function (s, w) { return s + w.length; }, 0);
    var avgWordLen = totalLen / n;

    var descriptivePatterns = [
      'suddenly', 'unexpectedly', 'surprisingly', 'then', 'but',
      'while', 'instead', 'actually', 'realizes', 'noticed',
      'turns', 'falls', 'jumps', 'appears', 'disappears',
      'funny', 'hilarious', 'weird', 'strange', 'shocking'
    ];
    var lowerResp = (response || '').toLowerCase();
    var hasDescriptive = descriptivePatterns.some(function (p) {
      return lowerResp.indexOf(p) !== -1;
    });

    var specificity;
    if (n <= 2) specificity = 'vague';
    else if (n <= 5 && !hasDescriptive) specificity = 'low';
    else if (n <= 10) specificity = 'moderate';
    else specificity = 'detailed';

    return {
      wordCount: n, uniqueWords: unique,
      typeTokenRatio: Math.round(ttr * 1000) / 1000,
      avgWordLength: Math.round(avgWordLen * 100) / 100,
      hasDescriptiveWords: hasDescriptive, specificity: specificity
    };
  }

  /**
   * Detect duplicate/near-duplicate responses in a batch.
   * @param {string[]} responses - Array of response texts
   * @returns {Object} Duplicate analysis
   */
  function detectDuplicateResponses(responses) {
    if (!responses || responses.length < 2) {
      return { duplicateCount: 0, duplicatePairs: [], uniqueRatio: 1 };
    }

    var pairs = [];
    var duplicatedIndices = {};
    for (var i = 0; i < responses.length; i++) {
      for (var j = i + 1; j < responses.length; j++) {
        var sim = textSimilarity(responses[i], responses[j]);
        if (sim >= duplicateThreshold) {
          pairs.push({ i: i, j: j, similarity: Math.round(sim * 1000) / 1000 });
          duplicatedIndices[i] = true;
          duplicatedIndices[j] = true;
        }
      }
    }

    var duplicateCount = Object.keys(duplicatedIndices).length;
    var uniqueRatio = 1 - (duplicateCount / responses.length);

    return {
      duplicateCount: duplicateCount, duplicatePairs: pairs,
      uniqueRatio: Math.round(uniqueRatio * 1000) / 1000
    };
  }

  /**
   * Generate a comprehensive humanity confidence score.
   * @param {Array<{response: string, timeMs: number}>} submissions
   * @returns {Object} Scoring result with verdict and flags
   */
  function scoreSubmissions(submissions) {
    if (!submissions || submissions.length === 0) {
      return {
        humanityScore: 0, verdict: 'insufficient_data',
        timing: { suspicionFlags: ['no_data'] }, linguistic: {},
        duplicates: { duplicateCount: 0, duplicatePairs: [], uniqueRatio: 1 },
        flags: ['no_submissions']
      };
    }

    var times = submissions.map(function (s) { return s.timeMs; }).filter(function (t) { return t > 0; });
    var responses = submissions.map(function (s) { return s.response || ''; });

    var timing = analyzeTiming(times);
    var duplicates = detectDuplicateResponses(responses);

    var analyses = responses.map(analyzeResponse);
    var totalWords = 0, descriptiveCount = 0, emptyCount = 0;
    var specificities = {};
    analyses.forEach(function (a) {
      totalWords += a.wordCount;
      if (a.hasDescriptiveWords) descriptiveCount++;
      if (a.wordCount === 0) emptyCount++;
      specificities[a.specificity] = (specificities[a.specificity] || 0) + 1;
    });

    var avgWords = totalWords / submissions.length;
    var avgTTR = analyses.reduce(function (s, a) { return s + a.typeTokenRatio; }, 0) / submissions.length;

    var linguistic = {
      avgWordCount: Math.round(avgWords * 10) / 10,
      avgTypeTokenRatio: Math.round(avgTTR * 1000) / 1000,
      descriptiveResponseCount: descriptiveCount,
      emptyResponseCount: emptyCount,
      specificityBreakdown: specificities
    };

    var score = 100;
    var flags = [];

    if (timing.tooFastCount > 0) {
      score -= Math.min(30, timing.tooFastCount * 10);
      flags.push('fast_responses');
    }
    if (timing.isUniform) { score -= 20; flags.push('uniform_timing'); }
    if (duplicates.duplicateCount > 0) {
      score -= Math.min(30, duplicates.duplicatePairs.length * 15);
      flags.push('duplicate_responses');
    }
    if (emptyCount > 0) { score -= emptyCount * 10; flags.push('empty_responses'); }
    if (avgTTR < minWordDiversity && avgWords > 3) { score -= 15; flags.push('low_word_diversity'); }
    if (descriptiveCount === 0 && submissions.length >= 3) { score -= 10; flags.push('no_descriptive_language'); }
    if (avgWords < 3 && emptyCount === 0) { score -= 10; flags.push('very_short_responses'); }

    if (descriptiveCount >= Math.ceil(submissions.length / 2)) score = Math.min(100, score + 5);
    if (duplicates.uniqueRatio >= 0.95 && submissions.length >= 3) score = Math.min(100, score + 5);

    score = _clamp(score, 0, 100);

    var verdict;
    if (score >= 80) verdict = 'likely_human';
    else if (score >= 50) verdict = 'uncertain';
    else verdict = 'likely_bot';

    return {
      humanityScore: score, verdict: verdict,
      timing: timing, linguistic: linguistic,
      duplicates: duplicates, flags: flags
    };
  }

  function getConfig() {
    return {
      minResponseTimeMs: minResponseTimeMs,
      maxTimingCvThreshold: maxTimingCvThreshold,
      duplicateThreshold: duplicateThreshold,
      minWordDiversity: minWordDiversity
    };
  }

  return {
    analyzeTiming: analyzeTiming,
    analyzeResponse: analyzeResponse,
    detectDuplicateResponses: detectDuplicateResponses,
    scoreSubmissions: scoreSubmissions,
    getConfig: getConfig
  };
}

// ── Honeypot & Bot Behavior Detector ────────────────────────────────

/**
 * Creates a honeypot and behavioral analysis system for detecting bots.
 *
 * Analyzes multiple behavioral signals that distinguish humans from
 * automated solvers:
 *
 * - **Hidden field honeypots**: Invisible form fields that bots fill but
 *   humans leave empty. Configurable field names and trap types.
 * - **Interaction fingerprinting**: Mouse movement entropy, click patterns,
 *   and scroll behavior that bots typically lack or fake poorly.
 * - **Keystroke dynamics**: Typing speed, rhythm variance, and key-hold
 *   patterns that are difficult to simulate realistically.
 * - **Timing analysis**: Time-to-first-interaction, total solve time, and
 *   pacing consistency across challenge steps.
 * - **JavaScript verification**: Checks that JS executed (bots sometimes
 *   submit forms without running page scripts).
 * - **Behavior scoring**: Weighted composite score (0–100) from all signals
 *   with configurable thresholds for flag/block decisions.
 *
 * Usage:
 * ```js
 * var detector = gifCaptcha.createBotDetector({ honeypotFields: ['email2', 'website'] });
 *
 * // On form submission, collect signals:
 * var result = detector.analyze({
 *   honeypotValues: { email2: '', website: '' },
 *   mouseMovements: [{ x: 10, y: 20, t: 100 }, { x: 50, y: 80, t: 200 }],
 *   keystrokes: [{ key: 'a', downAt: 100, upAt: 150 }, { key: 'b', downAt: 200, upAt: 260 }],
 *   timeOnPageMs: 15000,
 *   firstInteractionMs: 2000,
 *   jsToken: detector.getJsToken(),
 *   scrollEvents: [{ y: 0, t: 0 }, { y: 100, t: 500 }],
 * });
 *
 * if (result.isBot) {
 *   // Block or serve harder CAPTCHA
 * }
 * ```
 *
 * @param {Object} [options]
 * @param {string[]} [options.honeypotFields=['hp_email','hp_url','hp_phone']]
 *   Names of hidden form fields used as traps.
 * @param {number} [options.minTimeOnPageMs=3000]
 *   Minimum plausible time a human spends on the page.
 * @param {number} [options.maxTimeOnPageMs=600000]
 *   Maximum plausible time (10 minutes) — bots may have stale sessions.
 * @param {number} [options.minMouseMovements=3]
 *   Minimum number of mouse movements expected from a human.
 * @param {number} [options.minKeystrokeVariance=10]
 *   Minimum variance (ms²) in inter-key intervals for human-like typing.
 * @param {number} [options.botThreshold=60]
 *   Composite score at or above which the submission is flagged as bot.
 * @param {number} [options.suspiciousThreshold=40]
 *   Score at or above which the submission is flagged as suspicious.
 * @returns {Object} Bot detector instance
 */
function createBotDetector(options) {
  options = options || {};

  var honeypotFields = Array.isArray(options.honeypotFields)
    ? options.honeypotFields
    : ['hp_email', 'hp_url', 'hp_phone'];
  var minTimeOnPageMs = typeof options.minTimeOnPageMs === 'number'
    ? options.minTimeOnPageMs : 3000;
  var maxTimeOnPageMs = typeof options.maxTimeOnPageMs === 'number'
    ? options.maxTimeOnPageMs : 600000;
  var minMouseMovements = typeof options.minMouseMovements === 'number'
    ? options.minMouseMovements : 3;
  var minKeystrokeVariance = typeof options.minKeystrokeVariance === 'number'
    ? options.minKeystrokeVariance : 10;
  var botThreshold = typeof options.botThreshold === 'number'
    ? options.botThreshold : 60;
  var suspiciousThreshold = typeof options.suspiciousThreshold === 'number'
    ? options.suspiciousThreshold : 40;

  // JS verification token — must be retrieved by client-side JS
  var _jsTokens = Object.create(null);
  var _jsTokenCount = 0;

  /** Maximum number of unverified JS tokens before oldest are evicted. */
  var JS_TOKEN_MAX = 10000;
  /** JS tokens expire after 5 minutes (300 000 ms). */
  var JS_TOKEN_TTL_MS = 300000;

  /**
   * Purge expired JS tokens and enforce capacity limit.
   * Called on every getJsToken() to prevent unbounded memory growth.
   * @private
   */
  function _purgeExpiredJsTokens() {
    var now = Date.now();
    var ids = Object.keys(_jsTokens);
    for (var i = 0; i < ids.length; i++) {
      if (now - _jsTokens[ids[i]].createdAt > JS_TOKEN_TTL_MS) {
        delete _jsTokens[ids[i]];
        _jsTokenCount--;
      }
    }
    // If still over capacity after TTL purge, evict oldest entries
    if (_jsTokenCount > JS_TOKEN_MAX) {
      var remaining = Object.keys(_jsTokens);
      remaining.sort(function (a, b) {
        return _jsTokens[a].createdAt - _jsTokens[b].createdAt;
      });
      var toRemove = _jsTokenCount - JS_TOKEN_MAX;
      for (var j = 0; j < toRemove && j < remaining.length; j++) {
        delete _jsTokens[remaining[j]];
        _jsTokenCount--;
      }
    }
  }

  /**
   * Generate a one-time JS verification token.
   * The client must call this (proving JS execution) and submit it.
   *
   * Tokens expire after 5 minutes. A maximum of 10 000 tokens are held
   * in memory; oldest are evicted when the limit is reached.
   *
   * @param {string} [sessionId] - Optional session identifier for binding
   * @returns {string} Token string to include in form submission
   */
  function getJsToken(sessionId) {
    _purgeExpiredJsTokens();
    var id = sessionId || '_default';
    if (!_jsTokens[id]) _jsTokenCount++;
    var token = '';
    for (var i = 0; i < 32; i++) {
      token += secureRandomInt(36).toString(36);
    }
    _jsTokens[id] = { token: token, createdAt: Date.now() };
    return token;
  }

  /**
   * Verify a submitted JS token.
   *
   * Uses constant-time comparison to prevent timing side-channel attacks
   * that could allow an attacker to brute-force token values one character
   * at a time (CWE-208).
   *
   * @private
   */
  function _verifyJsToken(submittedToken, sessionId) {
    var id = sessionId || '_default';
    var entry = _jsTokens[id];
    if (!entry) return false;
    // Reject expired tokens
    if (Date.now() - entry.createdAt > JS_TOKEN_TTL_MS) {
      delete _jsTokens[id];
      _jsTokenCount--;
      return false;
    }
    var valid = _constantTimeEqual(entry.token, submittedToken);
    // One-time use: delete after verification
    delete _jsTokens[id];
    _jsTokenCount--;
    return valid;
  }

  /**
   * Analyze honeypot field values.
   * Any filled honeypot field = instant bot detection.
   *
   * @param {Object} honeypotValues - Map of field name → submitted value
   * @returns {{ score: number, filled: string[], clean: boolean }}
   */
  function analyzeHoneypots(honeypotValues) {
    if (!honeypotValues || typeof honeypotValues !== 'object') {
      return { score: 0, filled: [], clean: true };
    }

    var filled = [];
    for (var i = 0; i < honeypotFields.length; i++) {
      var field = honeypotFields[i];
      var val = honeypotValues[field];
      if (val !== undefined && val !== null && String(val).trim().length > 0) {
        filled.push(field);
      }
    }

    // Any filled honeypot is a very strong bot signal
    var score = filled.length > 0 ? 100 : 0;
    return { score: score, filled: filled, clean: filled.length === 0 };
  }

  /**
   * Analyze mouse movement patterns.
   * Humans produce curved, variable paths; bots produce straight lines
   * or no movement at all.
   *
   * @param {Array<{x: number, y: number, t: number}>} movements
   *   Mouse movement events with coordinates and timestamps.
   * @returns {{ score: number, count: number, entropy: number, isLinear: boolean, flags: string[] }}
   */
  function analyzeMouseMovements(movements) {
    var flags = [];

    if (!Array.isArray(movements) || movements.length === 0) {
      return { score: 80, count: 0, entropy: 0, isLinear: false, flags: ['no_mouse_data'] };
    }

    if (movements.length < minMouseMovements) {
      flags.push('too_few_movements');
    }

    // Calculate directional entropy — humans change direction frequently
    var angles = [];
    for (var i = 1; i < movements.length; i++) {
      var dx = movements[i].x - movements[i - 1].x;
      var dy = movements[i].y - movements[i - 1].y;
      if (dx !== 0 || dy !== 0) {
        angles.push(Math.atan2(dy, dx));
      }
    }

    var entropy = 0;
    if (angles.length > 1) {
      // Discretize angles into 8 bins (N, NE, E, SE, S, SW, W, NW)
      var bins = [0, 0, 0, 0, 0, 0, 0, 0];
      for (var j = 0; j < angles.length; j++) {
        var binIdx = Math.floor(((angles[j] + Math.PI) / (2 * Math.PI)) * 8) % 8;
        bins[binIdx]++;
      }
      // Shannon entropy over direction bins
      var total = angles.length;
      for (var k = 0; k < bins.length; k++) {
        if (bins[k] > 0) {
          var p = bins[k] / total;
          entropy -= p * Math.log2(p);
        }
      }
    }

    // Check for linear movement (all same direction)
    var isLinear = angles.length > 2 && entropy < 0.5;
    if (isLinear) flags.push('linear_movement');

    // Check for identical timestamps (scripted events)
    var sameTimestampCount = 0;
    for (var m = 1; m < movements.length; m++) {
      if (movements[m].t === movements[m - 1].t) sameTimestampCount++;
    }
    if (sameTimestampCount > movements.length * 0.5) {
      flags.push('identical_timestamps');
    }

    // Score: 0 (human-like) to 100 (bot-like)
    var score = 0;
    if (movements.length < minMouseMovements) score += 30;
    if (isLinear) score += 25;
    if (entropy < 1.0 && angles.length > 2) score += 20;
    if (sameTimestampCount > movements.length * 0.5) score += 25;

    // Low entropy with sufficient data is suspicious
    var maxEntropy = Math.log2(8); // 3.0 for 8 bins
    if (angles.length > 5 && entropy > maxEntropy * 0.6) {
      score = Math.max(0, score - 20); // reward high entropy
    }

    return {
      score: Math.min(100, score),
      count: movements.length,
      entropy: Math.round(entropy * 1000) / 1000,
      isLinear: isLinear,
      flags: flags,
    };
  }

  /**
   * Analyze keystroke dynamics.
   * Humans have variable inter-key intervals and key-hold durations;
   * bots tend to be perfectly uniform or impossibly fast.
   *
   * @param {Array<{key: string, downAt: number, upAt: number}>} keystrokes
   *   Keystroke events with key-down and key-up timestamps.
   * @returns {{ score: number, count: number, avgHoldMs: number, intervalVariance: number, flags: string[] }}
   */
  function analyzeKeystrokes(keystrokes) {
    var flags = [];

    if (!Array.isArray(keystrokes) || keystrokes.length === 0) {
      return { score: 50, count: 0, avgHoldMs: 0, intervalVariance: 0, flags: ['no_keystroke_data'] };
    }

    // Key-hold durations (how long each key is pressed)
    var holdTimes = [];
    for (var i = 0; i < keystrokes.length; i++) {
      var hold = keystrokes[i].upAt - keystrokes[i].downAt;
      if (hold >= 0) holdTimes.push(hold);
    }

    var avgHold = 0;
    if (holdTimes.length > 0) {
      var sum = 0;
      for (var h = 0; h < holdTimes.length; h++) sum += holdTimes[h];
      avgHold = sum / holdTimes.length;
    }

    // Inter-key intervals (time between consecutive key presses)
    var intervals = [];
    for (var j = 1; j < keystrokes.length; j++) {
      intervals.push(keystrokes[j].downAt - keystrokes[j - 1].downAt);
    }

    // Variance of inter-key intervals
    var intervalVariance = 0;
    if (intervals.length > 1) {
      var mean = 0;
      for (var k = 0; k < intervals.length; k++) mean += intervals[k];
      mean /= intervals.length;
      var sumSq = 0;
      for (var l = 0; l < intervals.length; l++) {
        sumSq += (intervals[l] - mean) * (intervals[l] - mean);
      }
      intervalVariance = sumSq / (intervals.length - 1);
    }

    var score = 0;

    // Super-fast typing (< 20ms per key) is suspicious
    if (avgHold < 20 && holdTimes.length > 0) {
      score += 30;
      flags.push('impossibly_fast_typing');
    }

    // Zero-hold keys (all exactly 0ms) — scripted input
    var zeroHoldCount = holdTimes.filter(function (t) { return t === 0; }).length;
    if (zeroHoldCount === holdTimes.length && holdTimes.length > 2) {
      score += 35;
      flags.push('zero_hold_times');
    }

    // Low variance = robotic typing
    if (intervalVariance < minKeystrokeVariance && intervals.length > 2) {
      score += 25;
      flags.push('uniform_typing_rhythm');
    }

    // Very high variance with very fast keys = simulated randomness
    if (intervalVariance > 100000 && avgHold < 30) {
      score += 15;
      flags.push('simulated_variance');
    }

    return {
      score: Math.min(100, score),
      count: keystrokes.length,
      avgHoldMs: Math.round(avgHold),
      intervalVariance: Math.round(intervalVariance),
      flags: flags,
    };
  }

  /**
   * Analyze page timing signals.
   *
   * @param {number} timeOnPageMs - Total time spent on page
   * @param {number} [firstInteractionMs] - Time until first interaction
   * @returns {{ score: number, timeOnPageMs: number, flags: string[] }}
   */
  function analyzeTiming(timeOnPageMs, firstInteractionMs) {
    var flags = [];
    var score = 0;

    if (typeof timeOnPageMs !== 'number' || timeOnPageMs <= 0) {
      return { score: 50, timeOnPageMs: 0, flags: ['no_timing_data'] };
    }

    // Too fast = bot
    if (timeOnPageMs < minTimeOnPageMs) {
      score += 40;
      flags.push('too_fast');
    }

    // Too slow = stale session or very slow bot
    if (timeOnPageMs > maxTimeOnPageMs) {
      score += 15;
      flags.push('stale_session');
    }

    // First interaction timing
    if (typeof firstInteractionMs === 'number') {
      if (firstInteractionMs < 200) {
        score += 25;
        flags.push('instant_interaction');
      } else if (firstInteractionMs < 500) {
        score += 10;
        flags.push('very_fast_first_interaction');
      }
    }

    return {
      score: Math.min(100, score),
      timeOnPageMs: timeOnPageMs,
      flags: flags,
    };
  }

  /**
   * Analyze scroll behavior.
   *
   * @param {Array<{y: number, t: number}>} scrollEvents
   * @returns {{ score: number, count: number, flags: string[] }}
   */
  function analyzeScroll(scrollEvents) {
    var flags = [];

    if (!Array.isArray(scrollEvents) || scrollEvents.length === 0) {
      return { score: 20, count: 0, flags: ['no_scroll_data'] };
    }

    var score = 0;

    // Check for all-identical scroll positions
    var allSame = scrollEvents.every(function (e) { return e.y === scrollEvents[0].y; });
    if (allSame && scrollEvents.length > 2) {
      score += 20;
      flags.push('no_actual_scrolling');
    }

    // Check for perfectly uniform scroll intervals
    if (scrollEvents.length > 3) {
      var diffs = [];
      for (var i = 1; i < scrollEvents.length; i++) {
        diffs.push(scrollEvents[i].t - scrollEvents[i - 1].t);
      }
      var mean = 0;
      for (var j = 0; j < diffs.length; j++) mean += diffs[j];
      mean /= diffs.length;
      var variance = 0;
      for (var k = 0; k < diffs.length; k++) {
        variance += (diffs[k] - mean) * (diffs[k] - mean);
      }
      variance = diffs.length > 1 ? variance / (diffs.length - 1) : 0;
      if (variance < 5 && diffs.length > 2) {
        score += 20;
        flags.push('uniform_scroll_timing');
      }
    }

    return {
      score: Math.min(100, score),
      count: scrollEvents.length,
      flags: flags,
    };
  }

  /**
   * Run full behavioral analysis and produce a composite bot score.
   *
   * @param {Object} signals - All collected behavioral signals
   * @param {Object} [signals.honeypotValues] - Honeypot field values
   * @param {Array} [signals.mouseMovements] - Mouse movement events
   * @param {Array} [signals.keystrokes] - Keystroke events
   * @param {number} [signals.timeOnPageMs] - Time spent on page
   * @param {number} [signals.firstInteractionMs] - Time to first interaction
   * @param {string} [signals.jsToken] - JS verification token
   * @param {string} [signals.sessionId] - Session ID for token binding
   * @param {Array} [signals.scrollEvents] - Scroll events
   * @returns {{
   *   score: number,
   *   isBot: boolean,
   *   isSuspicious: boolean,
   *   verdict: string,
   *   signals: Object,
   *   flags: string[],
   *   breakdown: Object
   * }}
   */
  function analyze(signals) {
    signals = signals || {};
    var allFlags = [];

    // Analyze each signal type
    var honeypot = analyzeHoneypots(signals.honeypotValues);
    var mouse = analyzeMouseMovements(signals.mouseMovements);
    var keys = analyzeKeystrokes(signals.keystrokes);
    var timing = analyzeTiming(signals.timeOnPageMs, signals.firstInteractionMs);
    var scroll = analyzeScroll(signals.scrollEvents);

    // JS token verification
    var jsValid = false;
    var jsScore = 50; // neutral if no token submitted
    if (signals.jsToken) {
      jsValid = _verifyJsToken(signals.jsToken, signals.sessionId);
      jsScore = jsValid ? 0 : 80;
      if (!jsValid) allFlags.push('invalid_js_token');
    } else {
      allFlags.push('no_js_token');
    }

    // Collect all flags
    allFlags = allFlags.concat(honeypot.filled.map(function (f) { return 'honeypot_filled:' + f; }));
    allFlags = allFlags.concat(mouse.flags);
    allFlags = allFlags.concat(keys.flags);
    allFlags = allFlags.concat(timing.flags);
    allFlags = allFlags.concat(scroll.flags);

    // Honeypot is decisive — any filled field = instant bot
    if (!honeypot.clean) {
      return {
        score: 100,
        isBot: true,
        isSuspicious: true,
        verdict: 'bot',
        signals: signals,
        flags: allFlags,
        breakdown: {
          honeypot: honeypot.score,
          mouse: mouse.score,
          keystrokes: keys.score,
          timing: timing.score,
          scroll: scroll.score,
          jsVerification: jsScore,
        },
      };
    }

    // Weighted composite score
    // Weights reflect how reliable each signal is
    var weights = {
      mouse: 0.25,
      keystrokes: 0.25,
      timing: 0.20,
      jsVerification: 0.15,
      scroll: 0.15,
    };

    var composite =
      mouse.score * weights.mouse +
      keys.score * weights.keystrokes +
      timing.score * weights.timing +
      jsScore * weights.jsVerification +
      scroll.score * weights.scroll;

    composite = Math.round(composite * 10) / 10;

    var isBot = composite >= botThreshold;
    var isSuspicious = composite >= suspiciousThreshold;
    var verdict = isBot ? 'bot' : (isSuspicious ? 'suspicious' : 'human');

    return {
      score: composite,
      isBot: isBot,
      isSuspicious: isSuspicious,
      verdict: verdict,
      signals: signals,
      flags: allFlags,
      breakdown: {
        honeypot: honeypot.score,
        mouse: mouse.score,
        keystrokes: keys.score,
        timing: timing.score,
        scroll: scroll.score,
        jsVerification: jsScore,
      },
    };
  }

  /**
   * Get the honeypot field names for embedding in the form.
   * @returns {string[]} Field names that should be hidden in the form
   */
  function getHoneypotFields() {
    return honeypotFields.slice();
  }

  /**
   * Get configuration summary.
   * @returns {Object} Current detector configuration
   */
  function getConfig() {
    return {
      honeypotFields: honeypotFields.slice(),
      minTimeOnPageMs: minTimeOnPageMs,
      maxTimeOnPageMs: maxTimeOnPageMs,
      minMouseMovements: minMouseMovements,
      minKeystrokeVariance: minKeystrokeVariance,
      botThreshold: botThreshold,
      suspiciousThreshold: suspiciousThreshold,
    };
  }

  return {
    analyze: analyze,
    analyzeHoneypots: analyzeHoneypots,
    analyzeMouseMovements: analyzeMouseMovements,
    analyzeKeystrokes: analyzeKeystrokes,
    analyzeTiming: analyzeTiming,
    analyzeScroll: analyzeScroll,
    getJsToken: getJsToken,
    getHoneypotFields: getHoneypotFields,
    getConfig: getConfig,
  };
}


// ~~ Token Verifier ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/**
 * Create a stateless token verifier for CAPTCHA completion tokens.
 *
 * Issues HMAC-signed tokens when a session passes, which can be
 * verified server-side without shared session state. Similar to
 * how reCAPTCHA / hCaptcha issue signed verification tokens.
 *
 * Tokens encode: sessionId, timestamp, difficulty, score, IP hash.
 * They are signed with HMAC-SHA256 and expire after a configurable TTL.
 *
 * Requires Node.js crypto module.
 *
 * @param {Object} options
 * @param {string} options.secret - HMAC signing secret (min 16 chars)
 * @param {number} [options.tokenTtlMs=300000] - Token validity window (default 5 min)
 * @param {number} [options.maxTokenUses=1] - Max times a token can be verified (0 = unlimited)
 * @param {boolean} [options.bindIp=true] - Bind token to originating IP
 * @param {number} [options.maxUsedTokens=10000] - Max used-token nonces to track
 * @returns {Object} Token verifier instance
 */
function createTokenVerifier(options) {
  options = options || {};

  if (!options.secret || typeof options.secret !== 'string') {
    throw new Error('Token verifier requires a secret string');
  }
  if (options.secret.length < 16) {
    throw new Error('Secret must be at least 16 characters');
  }
  if (!_crypto || typeof _crypto.createHmac !== 'function') {
    throw new Error('Token verifier requires Node.js crypto module');
  }

  var secret = options.secret;
  var tokenTtlMs = _posOpt(options.tokenTtlMs, 300000);
  var maxTokenUses = _nnOpt(options.maxTokenUses, 1);
  var bindIp = options.bindIp !== false;
  var maxUsedTokens = _posOpt(options.maxUsedTokens, 10000);

  var usedNonces = Object.create(null);
  var usedNonceCount = 0;
  var usedNonceList = [];

  function _hmac(data) {
    return _crypto.createHmac('sha256', secret).update(data).digest('hex');
  }

  function _hashIp(ip) {
    if (!ip || typeof ip !== 'string') return 'none';
    return _crypto.createHash('sha256').update(ip + ':' + secret).digest('hex').substring(0, 16);
  }

  function _generateNonce() {
    return _crypto.randomBytes(12).toString('hex');
  }

  function _recordNonce(nonce) {
    if (usedNonces[nonce]) {
      usedNonces[nonce].uses++;
      return usedNonces[nonce].uses;
    }
    if (usedNonceCount >= maxUsedTokens) {
      var evict = usedNonceList.shift();
      if (evict && usedNonces[evict]) {
        delete usedNonces[evict];
        usedNonceCount--;
      }
    }
    usedNonces[nonce] = { uses: 1, ts: Date.now() };
    usedNonceList.push(nonce);
    usedNonceCount++;
    return 1;
  }

  /**
   * Issue a signed verification token for a passed CAPTCHA session.
   *
   * @param {Object} params
   * @param {string} params.sessionId - Session that passed
   * @param {number} params.score - Pass score (0-1)
   * @param {number} params.difficulty - Difficulty level used
   * @param {string} [params.ip] - Client IP (hashed into token if bindIp)
   * @param {Object} [params.metadata] - Extra claims to embed (max 10 keys, primitives only)
   * @returns {{ token: string, expiresAt: number }}
   */
  function issueToken(params) {
    params = params || {};
    if (!params.sessionId || typeof params.sessionId !== 'string') {
      throw new Error('sessionId is required');
    }
    if (typeof params.score !== 'number' || params.score < 0 || params.score > 1) {
      throw new Error('score must be a number between 0 and 1');
    }
    if (typeof params.difficulty !== 'number' || params.difficulty < 0) {
      throw new Error('difficulty must be a non-negative number');
    }

    var now = Date.now();
    var nonce = _generateNonce();
    var ipHash = bindIp ? _hashIp(params.ip) : 'unbound';

    var payload = {
      sid: params.sessionId,
      scr: Math.round(params.score * 1000) / 1000,
      dif: params.difficulty,
      iph: ipHash,
      iat: now,
      exp: now + tokenTtlMs,
      non: nonce,
    };

    if (params.metadata && typeof params.metadata === 'object') {
      var metaKeys = Object.keys(params.metadata);
      if (metaKeys.length > 10) {
        throw new Error('metadata cannot have more than 10 keys');
      }
      payload.meta = {};
      for (var i = 0; i < metaKeys.length; i++) {
        var k = metaKeys[i];
        var v = params.metadata[k];
        if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
          payload.meta[k] = v;
        }
      }
    }

    var payloadStr = JSON.stringify(payload);
    var payloadB64 = Buffer.from(payloadStr).toString('base64url');
    var signature = _hmac(payloadB64);

    return {
      token: payloadB64 + '.' + signature,
      expiresAt: payload.exp,
    };
  }

  /**
   * Verify a previously issued token.
   *
   * Checks signature, expiry, IP binding, and replay protection.
   *
   * @param {string} token - The token string to verify
   * @param {Object} [context]
   * @param {string} [context.ip] - Client IP to check against binding
   * @returns {{ valid: boolean, reason?: string, payload?: Object }}
   */
  function verifyToken(token, context) {
    context = context || {};

    if (!token || typeof token !== 'string') {
      return { valid: false, reason: 'missing_token' };
    }

    var parts = token.split('.');
    if (parts.length !== 2) {
      return { valid: false, reason: 'malformed_token' };
    }

    var payloadB64 = parts[0];
    var signature = parts[1];

    var expectedSig = _hmac(payloadB64);

    // Constant-time comparison using crypto.timingSafeEqual.
    // Both length mismatch and content mismatch must take the same
    // time to prevent timing side-channels that leak signature bytes.
    var sigValid = false;
    try {
      var sigBuf = Buffer.from(signature, 'utf-8');
      var expBuf = Buffer.from(expectedSig, 'utf-8');
      // timingSafeEqual requires equal-length buffers; if lengths
      // differ, compare expectedSig against itself (constant time)
      // then reject — this prevents length-oracle attacks.
      if (sigBuf.length === expBuf.length) {
        sigValid = _crypto.timingSafeEqual(sigBuf, expBuf);
      } else {
        _crypto.timingSafeEqual(expBuf, expBuf);
        sigValid = false;
      }
    } catch (e) {
      sigValid = false;
    }
    if (!sigValid) {
      return { valid: false, reason: 'invalid_signature' };
    }

    var payload;
    try {
      var payloadStr = Buffer.from(payloadB64, 'base64url').toString('utf-8');
      payload = JSON.parse(payloadStr);
    } catch (e) {
      return { valid: false, reason: 'corrupt_payload' };
    }

    if (!payload.sid || typeof payload.iat !== 'number' || typeof payload.exp !== 'number' || !payload.non) {
      return { valid: false, reason: 'incomplete_payload' };
    }

    var now = Date.now();
    if (now > payload.exp) {
      return { valid: false, reason: 'token_expired' };
    }

    if (payload.iat > now + 30000) {
      return { valid: false, reason: 'token_from_future' };
    }

    if (bindIp && payload.iph !== 'unbound' && payload.iph !== 'none') {
      var contextIpHash = _hashIp(context.ip);
      if (payload.iph !== contextIpHash) {
        return { valid: false, reason: 'ip_mismatch' };
      }
    }

    if (maxTokenUses > 0) {
      var uses = _recordNonce(payload.non);
      if (uses > maxTokenUses) {
        return { valid: false, reason: 'token_already_used' };
      }
    }

    return {
      valid: true,
      payload: {
        sessionId: payload.sid,
        score: payload.scr,
        difficulty: payload.dif,
        issuedAt: payload.iat,
        expiresAt: payload.exp,
        metadata: payload.meta || {},
      },
    };
  }

  /**
   * Convenience: issue token from a session manager result.
   *
   * @param {Object} sessionResult - Result from submitResponse
   * @param {string} sessionId - The session ID
   * @param {Object} [opts]
   * @param {string} [opts.ip] - Client IP
   * @param {Object} [opts.metadata] - Extra metadata
   * @returns {{ token: string, expiresAt: number }|null} Token or null if not passed
   */
  function issueFromSession(sessionResult, sessionId, opts) {
    opts = opts || {};
    if (!sessionResult || !sessionResult.done || !sessionResult.passed) {
      return null;
    }
    var score = sessionResult.passRate != null
      ? sessionResult.passRate
      : (sessionResult.correctCount / sessionResult.totalAnswered);
    return issueToken({
      sessionId: sessionId,
      score: score,
      difficulty: sessionResult.nextDifficulty || 0,
      ip: opts.ip,
      metadata: opts.metadata,
    });
  }

  /**
   * Get current verifier stats.
   * @returns {{ trackedNonces: number, maxCapacity: number, tokenTtlMs: number, maxUses: number, ipBound: boolean }}
   */
  function getStats() {
    return {
      trackedNonces: usedNonceCount,
      maxCapacity: maxUsedTokens,
      tokenTtlMs: tokenTtlMs,
      maxUses: maxTokenUses,
      ipBound: bindIp,
    };
  }

  /**
   * Clear all tracked nonces. Useful for testing or periodic maintenance.
   */
  function clearUsedTokens() {
    usedNonces = Object.create(null);
    usedNonceCount = 0;
    usedNonceList = [];
  }

  return {
    issueToken: issueToken,
    verifyToken: verifyToken,
    issueFromSession: issueFromSession,
    getStats: getStats,
    clearUsedTokens: clearUsedTokens,
  };
}

// ── Exports ─────────────────────────────────────────────────────────

/**
 * createReputationTracker -- Cross-session IP/device reputation tracking
 * for CAPTCHA challenge systems.
 *
 * Tracks solve/fail history per identifier (IP, device fingerprint, etc.),
 * computes trust scores, supports allowlists/blocklists, and decays
 * reputation over time to prevent stale entries.
 */
function createReputationTracker(options) {
  options = options || {};
  var decayHalfLifeMs = _posOpt(options.decayHalfLifeMs, 86400000); // 24 hours default
  var maxEntries = Math.floor(_posOpt(options.maxEntries, 10000));
  var suspiciousThreshold = _nnOpt(options.suspiciousThreshold, 0.3);
  var trustedThreshold = _nnOpt(options.trustedThreshold, 0.8);
  var blockThreshold = _nnOpt(options.blockThreshold, 0.1);
  var initialScore = (typeof options.initialScore === "number")
    ? _clamp(options.initialScore, 0, 1) : 0.5;
  var solveWeight = _posOpt(options.solveWeight, 0.1);
  var failWeight = _posOpt(options.failWeight, 0.15);
  var timeoutWeight = _posOpt(options.timeoutWeight, 0.05);
  var burstPenalty = (typeof options.burstPenalty === "number" && options.burstPenalty >= 0)
    ? options.burstPenalty : 0.2;
  var burstWindowMs = _posOpt(options.burstWindowMs, 10000); // 10 seconds

  // Use null-prototype objects to prevent prototype pollution
  var entries = Object.create(null);
  var allowlist = Object.create(null);
  var blocklist = Object.create(null);
  var entryCount = 0;

  // O(1) LRU eviction tracker (replaces array + indexOf + splice)
  var evictionOrder = new LruTracker();


  /**
   * Apply exponential decay to a score based on time elapsed.
   * Score decays toward initialScore (regression to mean).
   */
  function _applyDecay(entry) {
    var elapsed = _now() - entry.lastActivity;
    if (elapsed <= 0) return entry.score;
    // Exponential decay toward initialScore
    var lambda = Math.LN2 / decayHalfLifeMs;
    var decayFactor = Math.exp(-lambda * elapsed);
    return initialScore + (entry.score - initialScore) * decayFactor;
  }

  function _ensureEntry(identifier) {
    var id = String(identifier);
    if (!entries[id]) {
      // Evict oldest if at capacity
      if (entryCount >= maxEntries) {
        _evictOldest();
      }
      entries[id] = {
        score: initialScore,
        solves: 0,
        fails: 0,
        timeouts: 0,
        totalAttempts: 0,
        lastActivity: _now(),
        firstSeen: _now(),
        recentTimestamps: [],
        tags: Object.create(null),
      };
      entryCount++;
      evictionOrder.push(id);
    }
    return entries[id];
  }

  function _evictOldest() {
    var oldestId = evictionOrder.evictOldest();
    if (oldestId !== undefined && entries[oldestId]) {
      delete entries[oldestId];
      entryCount--;
    }
  }

  /**
   * Move an identifier to the end of the eviction order (most recent).
   */
  function _touchEviction(id) {
    evictionOrder.touch(id);
  }

  /**
   * Detect burst activity (many attempts in short window).
   */
  function _checkBurst(entry) {
    var now = _now();
    var cutoff = now - burstWindowMs;
    // Prune old timestamps
    var recent = [];
    for (var i = 0; i < entry.recentTimestamps.length; i++) {
      if (entry.recentTimestamps[i] >= cutoff) {
        recent.push(entry.recentTimestamps[i]);
      }
    }
    entry.recentTimestamps = recent;
    entry.recentTimestamps.push(now);
    // More than 5 attempts in burst window triggers penalty
    return entry.recentTimestamps.length > 5;
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Record a successful CAPTCHA solve.
   *
   * @param {string} identifier - IP address or device fingerprint
   * @returns {{ score: number, classification: string }}
   */
  function recordSolve(identifier) {
    var id = String(identifier);
    if (blocklist[id]) {
      return { score: 0, classification: "blocked" };
    }
    if (allowlist[id]) {
      return { score: 1, classification: "trusted" };
    }
    var entry = _ensureEntry(id);
    entry.score = _applyDecay(entry);
    entry.solves++;
    entry.totalAttempts++;
    entry.score = _clamp(entry.score + solveWeight, 0, 1);
    var isBurst = _checkBurst(entry);
    if (isBurst) {
      entry.score = _clamp(entry.score - burstPenalty, 0, 1);
    }
    entry.lastActivity = _now();
    _touchEviction(id);
    return { score: entry.score, classification: _classify(entry.score) };
  }

  /**
   * Record a failed CAPTCHA attempt.
   *
   * @param {string} identifier - IP address or device fingerprint
   * @returns {{ score: number, classification: string }}
   */
  function recordFail(identifier) {
    var id = String(identifier);
    if (blocklist[id]) {
      return { score: 0, classification: "blocked" };
    }
    if (allowlist[id]) {
      return { score: 1, classification: "trusted" };
    }
    var entry = _ensureEntry(id);
    entry.score = _applyDecay(entry);
    entry.fails++;
    entry.totalAttempts++;
    entry.score = _clamp(entry.score - failWeight, 0, 1);
    var isBurst = _checkBurst(entry);
    if (isBurst) {
      entry.score = _clamp(entry.score - burstPenalty, 0, 1);
    }
    entry.lastActivity = _now();
    _touchEviction(id);
    return { score: entry.score, classification: _classify(entry.score) };
  }

  /**
   * Record a CAPTCHA timeout (user abandoned).
   *
   * @param {string} identifier - IP address or device fingerprint
   * @returns {{ score: number, classification: string }}
   */
  function recordTimeout(identifier) {
    var id = String(identifier);
    if (blocklist[id]) {
      return { score: 0, classification: "blocked" };
    }
    if (allowlist[id]) {
      return { score: 1, classification: "trusted" };
    }
    var entry = _ensureEntry(id);
    entry.score = _applyDecay(entry);
    entry.timeouts++;
    entry.totalAttempts++;
    entry.score = _clamp(entry.score - timeoutWeight, 0, 1);
    entry.lastActivity = _now();
    _touchEviction(id);
    return { score: entry.score, classification: _classify(entry.score) };
  }

  /**
   * Get the current reputation for an identifier.
   *
   * @param {string} identifier
   * @returns {{ score: number, classification: string, solves: number, fails: number, timeouts: number, totalAttempts: number, firstSeen: number, lastActivity: number } | null}
   */
  function getReputation(identifier) {
    var id = String(identifier);
    if (blocklist[id]) {
      return { score: 0, classification: "blocked", solves: 0, fails: 0, timeouts: 0, totalAttempts: 0, firstSeen: 0, lastActivity: 0 };
    }
    if (allowlist[id]) {
      return { score: 1, classification: "trusted", solves: 0, fails: 0, timeouts: 0, totalAttempts: 0, firstSeen: 0, lastActivity: 0 };
    }
    if (!entries[id]) return null;
    var entry = entries[id];
    var decayed = _applyDecay(entry);
    return {
      score: decayed,
      classification: _classify(decayed),
      solves: entry.solves,
      fails: entry.fails,
      timeouts: entry.timeouts,
      totalAttempts: entry.totalAttempts,
      firstSeen: entry.firstSeen,
      lastActivity: entry.lastActivity,
    };
  }

  /**
   * Check if an identifier should be challenged, trusted, or blocked.
   *
   * @param {string} identifier
   * @returns {{ action: string, score: number, reason: string }}
   */
  function getAction(identifier) {
    var id = String(identifier);
    if (blocklist[id]) {
      return { action: "block", score: 0, reason: "blocklisted" };
    }
    if (allowlist[id]) {
      return { action: "allow", score: 1, reason: "allowlisted" };
    }
    if (!entries[id]) {
      return { action: "challenge", score: initialScore, reason: "unknown_identifier" };
    }
    var entry = entries[id];
    var score = _applyDecay(entry);
    if (score <= blockThreshold) {
      return { action: "block", score: score, reason: "reputation_too_low" };
    }
    if (score >= trustedThreshold) {
      return { action: "allow", score: score, reason: "trusted_reputation" };
    }
    if (score <= suspiciousThreshold) {
      return { action: "challenge_hard", score: score, reason: "suspicious_reputation" };
    }
    return { action: "challenge", score: score, reason: "normal_reputation" };
  }

  /**
   * Classify a score into a human-readable category.
   */
  function _classify(score) {
    if (score >= trustedThreshold) return "trusted";
    if (score >= suspiciousThreshold) return "neutral";
    if (score >= blockThreshold) return "suspicious";
    return "dangerous";
  }

  /**
   * Add an identifier to the allowlist (always trusted).
   *
   * @param {string} identifier
   */
  function addToAllowlist(identifier) {
    var id = String(identifier);
    allowlist[id] = true;
    // Remove from blocklist if present
    delete blocklist[id];
  }

  /**
   * Add an identifier to the blocklist (always blocked).
   *
   * @param {string} identifier
   */
  function addToBlocklist(identifier) {
    var id = String(identifier);
    blocklist[id] = true;
    // Remove from allowlist if present
    delete allowlist[id];
  }

  /**
   * Remove an identifier from the allowlist.
   *
   * @param {string} identifier
   */
  function removeFromAllowlist(identifier) {
    delete allowlist[String(identifier)];
  }

  /**
   * Remove an identifier from the blocklist.
   *
   * @param {string} identifier
   */
  function removeFromBlocklist(identifier) {
    delete blocklist[String(identifier)];
  }

  /**
   * Check if an identifier is on the allowlist.
   *
   * @param {string} identifier
   * @returns {boolean}
   */
  function isAllowlisted(identifier) {
    return allowlist[String(identifier)] === true;
  }

  /**
   * Check if an identifier is on the blocklist.
   *
   * @param {string} identifier
   * @returns {boolean}
   */
  function isBlocklisted(identifier) {
    return blocklist[String(identifier)] === true;
  }

  /**
   * Tag an identifier with metadata (e.g., country, user-agent class).
   *
   * @param {string} identifier
   * @param {string} tag
   * @param {*} value
   */
  function setTag(identifier, tag, value) {
    var entry = _ensureEntry(identifier);
    entry.tags[String(tag)] = value;
  }

  /**
   * Get a tag value for an identifier.
   *
   * @param {string} identifier
   * @param {string} tag
   * @returns {*}
   */
  function getTag(identifier, tag) {
    var id = String(identifier);
    if (!entries[id]) return undefined;
    return entries[id].tags[String(tag)];
  }

  /**
   * Get aggregate statistics about tracked reputations.
   *
   * @returns {{ trackedCount: number, allowlistCount: number, blocklistCount: number, classifications: { trusted: number, neutral: number, suspicious: number, dangerous: number }, averageScore: number }}
   */
  function getStats() {
    var classifications = { trusted: 0, neutral: 0, suspicious: 0, dangerous: 0 };
    var totalScore = 0;
    var count = 0;
    for (var id in entries) {
      var score = _applyDecay(entries[id]);
      var cls = _classify(score);
      classifications[cls]++;
      totalScore += score;
      count++;
    }
    var allowlistCount = 0;
    for (var a in allowlist) { allowlistCount++; }
    var blocklistCount = 0;
    for (var b in blocklist) { blocklistCount++; }
    return {
      trackedCount: count,
      allowlistCount: allowlistCount,
      blocklistCount: blocklistCount,
      classifications: classifications,
      averageScore: count > 0 ? totalScore / count : 0,
    };
  }

  /**
   * Remove an identifier's reputation data entirely.
   *
   * @param {string} identifier
   * @returns {boolean} true if the identifier was tracked
   */
  function forget(identifier) {
    var id = String(identifier);
    if (!entries[id]) return false;
    delete entries[id];
    entryCount--;
    evictionOrder.remove(id);
    return true;
  }

  /**
   * Clear all reputation data, allowlists, and blocklists.
   */
  function reset() {
    entries = Object.create(null);
    allowlist = Object.create(null);
    blocklist = Object.create(null);
    entryCount = 0;
    evictionOrder.clear();
  }

  /**
   * Export all reputation data for persistence.
   *
   * @returns {{ entries: Object, allowlist: string[], blocklist: string[] }}
   */
  function exportData() {
    var exportedEntries = Object.create(null);
    for (var id in entries) {
      var e = entries[id];
      exportedEntries[id] = {
        score: e.score,
        solves: e.solves,
        fails: e.fails,
        timeouts: e.timeouts,
        totalAttempts: e.totalAttempts,
        lastActivity: e.lastActivity,
        firstSeen: e.firstSeen,
        tags: JSON.parse(JSON.stringify(e.tags)),
      };
    }
    var allowArr = [];
    for (var a in allowlist) { allowArr.push(a); }
    var blockArr = [];
    for (var b in blocklist) { blockArr.push(b); }
    return {
      entries: exportedEntries,
      allowlist: allowArr,
      blocklist: blockArr,
    };
  }

  /**
   * Import previously exported reputation data.
   *
   * @param {{ entries?: Object, allowlist?: string[], blocklist?: string[] }} data
   */
  function importData(data) {
    if (!data || typeof data !== "object") return;
    // Import entries
    if (data.entries && typeof data.entries === "object") {
      for (var id in data.entries) {
        if (typeof id !== "string") continue;
        var src = data.entries[id];
        if (!src || typeof src !== "object") continue;
        var entry = _ensureEntry(id);
        if (typeof src.score === "number") entry.score = _clamp(src.score, 0, 1);
        if (typeof src.solves === "number") entry.solves = Math.max(0, Math.floor(src.solves));
        if (typeof src.fails === "number") entry.fails = Math.max(0, Math.floor(src.fails));
        if (typeof src.timeouts === "number") entry.timeouts = Math.max(0, Math.floor(src.timeouts));
        if (typeof src.totalAttempts === "number") entry.totalAttempts = Math.max(0, Math.floor(src.totalAttempts));
        if (typeof src.lastActivity === "number") entry.lastActivity = src.lastActivity;
        if (typeof src.firstSeen === "number") entry.firstSeen = src.firstSeen;
        if (src.tags && typeof src.tags === "object") {
          for (var tag in src.tags) {
            entry.tags[String(tag)] = src.tags[tag];
          }
        }
      }
    }
    // Import allowlist
    if (Array.isArray(data.allowlist)) {
      for (var i = 0; i < data.allowlist.length; i++) {
        if (typeof data.allowlist[i] === "string") {
          allowlist[data.allowlist[i]] = true;
        }
      }
    }
    // Import blocklist
    if (Array.isArray(data.blocklist)) {
      for (var i = 0; i < data.blocklist.length; i++) {
        if (typeof data.blocklist[i] === "string") {
          blocklist[data.blocklist[i]] = true;
        }
      }
    }
  }

  return {
    recordSolve: recordSolve,
    recordFail: recordFail,
    recordTimeout: recordTimeout,
    getReputation: getReputation,
    getAction: getAction,
    addToAllowlist: addToAllowlist,
    addToBlocklist: addToBlocklist,
    removeFromAllowlist: removeFromAllowlist,
    removeFromBlocklist: removeFromBlocklist,
    isAllowlisted: isAllowlisted,
    isBlocklisted: isBlocklisted,
    setTag: setTag,
    getTag: getTag,
    getStats: getStats,
    forget: forget,
    reset: reset,
    exportData: exportData,
    importData: importData,
  };
}


/**
 * createChallengeRouter - intelligent CAPTCHA routing orchestrator.
 *
 * Combines reputation, attempt history, and client context to select
 * the optimal challenge difficulty and type for each request.
 * Routes suspicious clients to harder CAPTCHAs, trusted clients to
 * easier ones, and blocks known bad actors outright.
 *
 * @param {Object} options
 * @param {Object} [options.difficulties]     - Difficulty name -> numeric level mapping
 * @param {number} [options.defaultDifficulty] - Level for unknown clients (default: 2)
 * @param {number} [options.maxEscalation]    - Max difficulty level (default: 5)
 * @param {number} [options.escalateAfterFails] - Consecutive fails before escalation (default: 2)
 * @param {number} [options.deescalateAfterPasses] - Consecutive passes before de-escalation (default: 3)
 * @param {number} [options.reputationWeight]   - Weight for reputation signal 0-1 (default: 0.6)
 * @param {number} [options.historyWeight]      - Weight for attempt history signal 0-1 (default: 0.4)
 * @param {number} [options.blockThreshold]     - Reputation score below which to block (default: 0.15)
 * @param {number} [options.trustThreshold]     - Reputation score above which to use easy (default: 0.85)
 * @param {number} [options.hardThreshold]      - Reputation score below which to use hard (default: 0.4)
 * @param {number} [options.maxDecisionLog]     - Max routing decisions to retain (default: 1000)
 * @param {Array}  [options.rules]              - Custom routing rules [{name, test, difficulty, priority}]
 * @returns {Object} Router instance
 */
function createChallengeRouter(options) {
  options = options || {};

  var difficulties = options.difficulties || {
    trivial: 1,
    easy: 2,
    medium: 3,
    hard: 4,
    extreme: 5,
  };
  var defaultDifficulty = _clampInt(options.defaultDifficulty, 1, 10, 2);
  var maxEscalation = _clampInt(options.maxEscalation, 1, 10, 5);
  var escalateAfterFails = _clampInt(options.escalateAfterFails, 1, 20, 2);
  var deescalateAfterPasses = _clampInt(options.deescalateAfterPasses, 1, 20, 3);
  var reputationWeight = _clampFloat(options.reputationWeight, 0, 1, 0.6);
  var historyWeight = _clampFloat(options.historyWeight, 0, 1, 0.4);
  var blockThreshold = _clampFloat(options.blockThreshold, 0, 1, 0.15);
  var trustThreshold = _clampFloat(options.trustThreshold, 0, 1, 0.85);
  var hardThreshold = _clampFloat(options.hardThreshold, 0, 1, 0.4);
  var maxDecisionLog = _clampInt(options.maxDecisionLog, 10, 100000, 1000);
  var customRules = _validateRules(options.rules || []);

  // Client state: identifier -> { level, consecutiveFails, consecutivePasses, totalRouted, lastRoutedAt }
  var clients = Object.create(null);
  // Routing decision log (circular buffer)
  var decisionLog = [];
  var decisionCount = 0;
  // Aggregate stats
  var stats = {
    totalRouted: 0,
    totalBlocked: 0,
    totalAllowed: 0,
    totalEscalated: 0,
    totalDeescalated: 0,
    byDifficulty: Object.create(null),
    byReason: Object.create(null),
  };

  // --- Helpers ---

  function _clampInt(val, min, max, fallback) {
    if (typeof val !== "number" || isNaN(val)) return fallback;
    return _clamp(Math.floor(val), min, max);
  }

  function _clampFloat(val, min, max, fallback) {
    if (typeof val !== "number" || isNaN(val)) return fallback;
    return _clamp(val, min, max);
  }

  function _validateRules(rules) {
    if (!Array.isArray(rules)) return [];
    var valid = [];
    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      if (r && typeof r === "object" && typeof r.name === "string" &&
          typeof r.test === "function" && typeof r.difficulty === "number") {
        valid.push({
          name: r.name,
          test: r.test,
          difficulty: _clamp(Math.floor(r.difficulty), 1, maxEscalation),
          priority: typeof r.priority === "number" ? r.priority : 0,
        });
      }
    }
    valid.sort(function (a, b) { return b.priority - a.priority; });
    return valid;
  }

  function _difficultyName(level) {
    for (var name in difficulties) {
      if (difficulties[name] === level) return name;
    }
    return "level_" + level;
  }

  function _getClient(identifier) {
    var id = String(identifier);
    if (!clients[id]) {
      clients[id] = {
        level: defaultDifficulty,
        consecutiveFails: 0,
        consecutivePasses: 0,
        totalRouted: 0,
        totalFails: 0,
        totalPasses: 0,
        lastRoutedAt: 0,
      };
    }
    return clients[id];
  }

  function _logDecision(decision) {
    if (decisionLog.length >= maxDecisionLog) {
      decisionLog[decisionCount % maxDecisionLog] = decision;
    } else {
      decisionLog.push(decision);
    }
    decisionCount++;
  }

  function _incStat(key, subkey) {
    var obj = stats[key];
    obj[subkey] = (obj[subkey] || 0) + 1;
  }

  // --- Core Routing ---

  /**
   * Route a client to the appropriate challenge difficulty.
   *
   * @param {string} identifier - Client identifier (IP, fingerprint, session ID)
   * @param {Object} [context]  - Optional context for custom rules
   * @param {number} [context.reputationScore] - Reputation score 0-1 (from reputation tracker)
   * @param {string} [context.reputationAction] - Action from reputation tracker
   * @param {string} [context.userAgent]        - User-Agent string
   * @param {string} [context.country]          - Country code
   * @param {boolean} [context.isProxy]         - Whether the client is behind a proxy
   * @param {Object} [context.custom]           - Custom data for custom rules
   * @returns {{ action: string, difficulty: number, difficultyName: string,
   *             reason: string, identifier: string, timestamp: number }}
   */
  function route(identifier, context) {
    if (!identifier || typeof identifier !== "string") {
      throw new Error("identifier must be a non-empty string");
    }
    context = context || {};
    var client = _getClient(identifier);
    var now = _now();

    // 1. Check custom rules first (highest priority)
    for (var ri = 0; ri < customRules.length; ri++) {
      var rule = customRules[ri];
      try {
        if (rule.test(identifier, context, client)) {
          var ruleLevel = rule.difficulty;
          var ruleDecision = _makeDecision(
            identifier, "challenge", ruleLevel, "custom_rule:" + rule.name, now
          );
          _applyDecision(client, ruleDecision, now);
          return ruleDecision;
        }
      } catch (e) {
        // Skip broken rules silently
      }
    }

    // 2. Check for block via reputation
    var repScore = typeof context.reputationScore === "number" ? context.reputationScore : null;
    var repAction = typeof context.reputationAction === "string" ? context.reputationAction : null;

    if (repAction === "block" || (repScore !== null && repScore < blockThreshold)) {
      var blockDecision = _makeDecision(identifier, "block", 0, "blocked_by_reputation", now);
      stats.totalBlocked++;
      _logDecision(blockDecision);
      return blockDecision;
    }

    // 3. Check for auto-allow via reputation
    if (repAction === "allow" || (repScore !== null && repScore > trustThreshold)) {
      var allowLevel = Math.max(1, defaultDifficulty - 1);
      var allowDecision = _makeDecision(identifier, "challenge", allowLevel, "trusted_reputation", now);
      _applyDecision(client, allowDecision, now);
      stats.totalAllowed++;
      return allowDecision;
    }

    // 4. Compute difficulty from signals
    var baseLevel = client.level;

    // Reputation signal: maps score to difficulty adjustment
    var repAdjustment = 0;
    if (repScore !== null) {
      if (repScore < hardThreshold) {
        repAdjustment = 2; // push harder
      } else if (repAction === "challenge_hard") {
        repAdjustment = 1;
      } else if (repScore > 0.7) {
        repAdjustment = -1; // easier
      }
    }

    // History signal: consecutive fails/passes adjust difficulty
    var histAdjustment = 0;
    if (client.consecutiveFails >= escalateAfterFails) {
      histAdjustment = Math.min(
        Math.floor(client.consecutiveFails / escalateAfterFails),
        maxEscalation - baseLevel
      );
    } else if (client.consecutivePasses >= deescalateAfterPasses) {
      histAdjustment = -Math.min(
        Math.floor(client.consecutivePasses / deescalateAfterPasses),
        baseLevel - 1
      );
    }

    // Weighted combination
    var combinedAdjustment = Math.round(
      reputationWeight * repAdjustment + historyWeight * histAdjustment
    );
    var finalLevel = _clamp(baseLevel + combinedAdjustment, 1, maxEscalation);

    var reason = "computed";
    if (combinedAdjustment > 0) {
      reason = "escalated";
      stats.totalEscalated++;
    } else if (combinedAdjustment < 0) {
      reason = "deescalated";
      stats.totalDeescalated++;
    }

    var decision = _makeDecision(identifier, "challenge", finalLevel, reason, now);
    _applyDecision(client, decision, now);
    return decision;
  }

  function _makeDecision(identifier, action, difficulty, reason, timestamp) {
    var diffName = difficulty > 0 ? _difficultyName(difficulty) : "none";
    return {
      action: action,
      difficulty: difficulty,
      difficultyName: diffName,
      reason: reason,
      identifier: identifier,
      timestamp: timestamp,
    };
  }

  function _applyDecision(client, decision, now) {
    client.level = decision.difficulty || client.level;
    client.totalRouted++;
    client.lastRoutedAt = now;
    stats.totalRouted++;
    _incStat("byDifficulty", decision.difficultyName);
    _incStat("byReason", decision.reason);
    _logDecision(decision);
  }

  // --- Feedback ---

  /**
   * Record a solve result to update client routing state.
   *
   * @param {string} identifier - Client identifier
   * @param {boolean} passed    - Whether the client solved the challenge
   */
  function recordResult(identifier, passed) {
    if (!identifier || typeof identifier !== "string") {
      throw new Error("identifier must be a non-empty string");
    }
    var client = _getClient(identifier);
    if (passed) {
      client.consecutivePasses++;
      client.consecutiveFails = 0;
      client.totalPasses++;
      // De-escalate if enough consecutive passes
      if (client.consecutivePasses >= deescalateAfterPasses && client.level > 1) {
        client.level = Math.max(1, client.level - 1);
      }
    } else {
      client.consecutiveFails++;
      client.consecutivePasses = 0;
      client.totalFails++;
      // Escalate if enough consecutive fails
      if (client.consecutiveFails >= escalateAfterFails && client.level < maxEscalation) {
        client.level = Math.min(maxEscalation, client.level + 1);
      }
    }
  }

  // --- Client Info ---

  /**
   * Get routing info for a specific client.
   */
  function getClientInfo(identifier) {
    if (!identifier || typeof identifier !== "string") return null;
    var id = String(identifier);
    var c = clients[id];
    if (!c) return null;
    var total = c.totalPasses + c.totalFails;
    return {
      level: c.level,
      levelName: _difficultyName(c.level),
      consecutiveFails: c.consecutiveFails,
      consecutivePasses: c.consecutivePasses,
      totalRouted: c.totalRouted,
      totalFails: c.totalFails,
      totalPasses: c.totalPasses,
      passRate: total > 0 ? c.totalPasses / total : 0,
      lastRoutedAt: c.lastRoutedAt,
    };
  }

  /**
   * Get list of all known client identifiers.
   */
  function getKnownClients() {
    return Object.keys(clients);
  }

  /**
   * Remove a client's routing state.
   */
  function forgetClient(identifier) {
    if (!identifier || typeof identifier !== "string") return false;
    var id = String(identifier);
    if (clients[id]) {
      delete clients[id];
      return true;
    }
    return false;
  }

  /**
   * Reset a client's difficulty to default without clearing stats.
   */
  function resetClientLevel(identifier) {
    if (!identifier || typeof identifier !== "string") return false;
    var id = String(identifier);
    var c = clients[id];
    if (!c) return false;
    c.level = defaultDifficulty;
    c.consecutiveFails = 0;
    c.consecutivePasses = 0;
    return true;
  }

  // --- Decision Log ---

  /**
   * Get recent routing decisions.
   */
  function getRecentDecisions(count) {
    count = _clampInt(count, 1, decisionLog.length || 1, 10);
    var result = [];
    var total = Math.min(count, decisionLog.length);
    for (var i = 0; i < total; i++) {
      var idx = (decisionCount - 1 - i) % maxDecisionLog;
      if (idx < 0) idx += maxDecisionLog;
      if (idx < decisionLog.length) {
        result.push(decisionLog[idx]);
      }
    }
    return result;
  }

  /**
   * Get decisions for a specific client.
   */
  function getClientDecisions(identifier, count) {
    if (!identifier || typeof identifier !== "string") return [];
    count = _clampInt(count, 1, 1000, 10);
    var result = [];
    for (var i = decisionLog.length - 1; i >= 0 && result.length < count; i--) {
      if (decisionLog[i] && decisionLog[i].identifier === identifier) {
        result.push(decisionLog[i]);
      }
    }
    return result;
  }

  // --- Stats ---

  /**
   * Get aggregate routing statistics.
   */
  function getStats() {
    var clientCount = Object.keys(clients).length;
    var escalatedClients = 0;
    var maxLevel = 0;
    for (var id in clients) {
      if (clients[id].level > defaultDifficulty) escalatedClients++;
      if (clients[id].level > maxLevel) maxLevel = clients[id].level;
    }
    return {
      totalRouted: stats.totalRouted,
      totalBlocked: stats.totalBlocked,
      totalAllowed: stats.totalAllowed,
      totalEscalated: stats.totalEscalated,
      totalDeescalated: stats.totalDeescalated,
      activeClients: clientCount,
      escalatedClients: escalatedClients,
      maxActiveLevel: maxLevel,
      decisionsLogged: Math.min(decisionCount, maxDecisionLog),
      byDifficulty: _copyObj(stats.byDifficulty),
      byReason: _copyObj(stats.byReason),
    };
  }

  function _copyObj(obj) {
    var copy = Object.create(null);
    for (var k in obj) {
      copy[k] = obj[k];
    }
    return copy;
  }

  // --- Bulk Operations ---

  /**
   * Route multiple clients at once.
   */
  function routeBatch(requests) {
    if (!Array.isArray(requests)) {
      throw new Error("requests must be an array");
    }
    var results = [];
    for (var i = 0; i < requests.length; i++) {
      var req = requests[i];
      if (!req || typeof req.identifier !== "string") {
        results.push({ action: "error", reason: "invalid_request", index: i });
        continue;
      }
      results.push(route(req.identifier, req.context));
    }
    return results;
  }

  // --- Config ---

  /**
   * Get current router configuration.
   */
  function getConfig() {
    return {
      difficulties: _copyObj(difficulties),
      defaultDifficulty: defaultDifficulty,
      maxEscalation: maxEscalation,
      escalateAfterFails: escalateAfterFails,
      deescalateAfterPasses: deescalateAfterPasses,
      reputationWeight: reputationWeight,
      historyWeight: historyWeight,
      blockThreshold: blockThreshold,
      trustThreshold: trustThreshold,
      hardThreshold: hardThreshold,
      maxDecisionLog: maxDecisionLog,
      customRuleCount: customRules.length,
    };
  }

  // --- Persistence ---

  /**
   * Export router state for persistence.
   */
  function exportState() {
    var clientsCopy = Object.create(null);
    for (var id in clients) {
      var c = clients[id];
      clientsCopy[id] = {
        level: c.level,
        consecutiveFails: c.consecutiveFails,
        consecutivePasses: c.consecutivePasses,
        totalRouted: c.totalRouted,
        totalFails: c.totalFails,
        totalPasses: c.totalPasses,
        lastRoutedAt: c.lastRoutedAt,
      };
    }
    return {
      clients: clientsCopy,
      stats: {
        totalRouted: stats.totalRouted,
        totalBlocked: stats.totalBlocked,
        totalAllowed: stats.totalAllowed,
        totalEscalated: stats.totalEscalated,
        totalDeescalated: stats.totalDeescalated,
        byDifficulty: _copyObj(stats.byDifficulty),
        byReason: _copyObj(stats.byReason),
      },
      decisionCount: decisionCount,
    };
  }

  /**
   * Import previously exported state.
   */
  function importState(state) {
    if (!state || typeof state !== "object") {
      throw new Error("state must be an object");
    }
    if (state.clients && typeof state.clients === "object") {
      for (var id in state.clients) {
        var sc = state.clients[id];
        if (sc && typeof sc === "object") {
          clients[id] = {
            level: _clampInt(sc.level, 1, maxEscalation, defaultDifficulty),
            consecutiveFails: Math.max(0, sc.consecutiveFails || 0),
            consecutivePasses: Math.max(0, sc.consecutivePasses || 0),
            totalRouted: Math.max(0, sc.totalRouted || 0),
            totalFails: Math.max(0, sc.totalFails || 0),
            totalPasses: Math.max(0, sc.totalPasses || 0),
            lastRoutedAt: sc.lastRoutedAt || 0,
          };
        }
      }
    }
    if (state.stats && typeof state.stats === "object") {
      var s = state.stats;
      stats.totalRouted = Math.max(0, s.totalRouted || 0);
      stats.totalBlocked = Math.max(0, s.totalBlocked || 0);
      stats.totalAllowed = Math.max(0, s.totalAllowed || 0);
      stats.totalEscalated = Math.max(0, s.totalEscalated || 0);
      stats.totalDeescalated = Math.max(0, s.totalDeescalated || 0);
      if (s.byDifficulty) {
        for (var dk in s.byDifficulty) stats.byDifficulty[dk] = s.byDifficulty[dk];
      }
      if (s.byReason) {
        for (var rk in s.byReason) stats.byReason[rk] = s.byReason[rk];
      }
    }
    decisionCount = Math.max(0, state.decisionCount || 0);
  }

  /**
   * Reset all state (clients, stats, decisions).
   */
  function reset() {
    for (var id in clients) delete clients[id];
    decisionLog.length = 0;
    decisionCount = 0;
    stats.totalRouted = 0;
    stats.totalBlocked = 0;
    stats.totalAllowed = 0;
    stats.totalEscalated = 0;
    stats.totalDeescalated = 0;
    for (var dk in stats.byDifficulty) delete stats.byDifficulty[dk];
    for (var rk in stats.byReason) delete stats.byReason[rk];
  }

  return {
    route: route,
    recordResult: recordResult,
    getClientInfo: getClientInfo,
    getKnownClients: getKnownClients,
    forgetClient: forgetClient,
    resetClientLevel: resetClientLevel,
    getRecentDecisions: getRecentDecisions,
    getClientDecisions: getClientDecisions,
    getStats: getStats,
    getConfig: getConfig,
    routeBatch: routeBatch,
    exportState: exportState,
    importState: importState,
    reset: reset,
  };
}

// ── Sliding Window Rate Limiter ────────────────────────────────────

/**
 * createRateLimiter -- Sliding window rate limiter for CAPTCHA request throttling.
 *
 * Tracks per-client request counts in configurable time windows with:
 * - Sliding window counters (not fixed buckets) for smooth limiting
 * - Progressive delay calculation based on request pressure
 * - Burst detection with configurable thresholds
 * - Client allowlist/blocklist
 * - Automatic cleanup of expired entries (LRU eviction)
 * - State export/import for persistence
 * - Batch check for multiple clients
 *
 * @param {Object} [options]
 * @param {number} [options.windowMs=60000]         - Window size in milliseconds (default: 60s)
 * @param {number} [options.maxRequests=10]          - Max requests per window
 * @param {number} [options.burstThreshold=5]        - Requests in burstWindowMs to trigger burst
 * @param {number} [options.burstWindowMs=5000]      - Burst detection window (default: 5s)
 * @param {number} [options.maxDelay=30000]          - Maximum progressive delay in ms
 * @param {number} [options.baseDelay=1000]          - Base delay for progressive calculation
 * @param {number} [options.maxClients=10000]        - Max tracked clients (LRU eviction)
 * @param {string[]} [options.allowlist=[]]          - Client IDs that bypass limiting
 * @param {string[]} [options.blocklist=[]]          - Client IDs always blocked
 * @returns {Object} Rate limiter instance
 */
function createRateLimiter(options) {
  options = options || {};

  var windowMs = _posOpt(options.windowMs, 60000);
  var maxRequests = _posOpt(options.maxRequests, 10);
  var burstThreshold = _posOpt(options.burstThreshold, 5);
  var burstWindowMs = _posOpt(options.burstWindowMs, 5000);
  var maxDelay = _nnOpt(options.maxDelay, 30000);
  var baseDelay = _nnOpt(options.baseDelay, 1000);
  var maxClients = _posOpt(options.maxClients, 10000);

  // Sets for O(1) lookup
  var allowSet = {};
  var blockSet = {};
  (options.allowlist || []).forEach(function (id) { allowSet[id] = true; });
  (options.blocklist || []).forEach(function (id) { blockSet[id] = true; });

  // clientId -> { timestamps: number[], lastAccess: number }
  var clients = {};
  var clientCount = 0;

  // Stats
  var totalChecks = 0;
  var totalAllowed = 0;
  var totalLimited = 0;
  var totalBlocked = 0;
  var totalBursts = 0;

  /**
   * Remove expired timestamps from a client's record.
   */
  /**
   * Remove expired timestamps from a client's record.
   * Uses in-place splice instead of slice to avoid allocating a new array
   * on every prune call — reduces GC pressure on the hot path.
   */
  function pruneTimestamps(record, now) {
    var cutoff = now - windowMs;
    var ts = record.timestamps;
    // Binary search for the first non-expired timestamp
    var lo = 0, hi = ts.length;
    while (lo < hi) {
      var mid = (lo + hi) >>> 1;
      if (ts[mid] <= cutoff) lo = mid + 1;
      else hi = mid;
    }
    if (lo > 0) {
      ts.splice(0, lo);
    }
  }

  /**
   * Evict oldest clients when over maxClients.
   * Uses partial selection (quickselect-style partition) to find the K oldest
   * clients in O(n) average time instead of O(n log n) full sort.
   * This matters at scale — with 10K clients, evicting 1 shouldn't sort all 10K.
   */
  function evictIfNeeded() {
    if (clientCount <= maxClients) return;

    var toEvict = clientCount - maxClients;

    // Collect all client entries
    var entries = [];
    for (var id in clients) {
      entries.push({ id: id, lastAccess: clients[id].lastAccess });
    }

    // For small eviction counts, use simple linear scan to find K oldest
    // (O(n*k) but k is typically 1, so this is O(n) — much faster than sorting)
    if (toEvict <= 10) {
      for (var e = 0; e < toEvict; e++) {
        var minIdx = 0;
        for (var i = 1; i < entries.length; i++) {
          if (entries[i].lastAccess < entries[minIdx].lastAccess) {
            minIdx = i;
          }
        }
        delete clients[entries[minIdx].id];
        clientCount--;
        // Remove from entries array to avoid re-selecting
        entries[minIdx] = entries[entries.length - 1];
        entries.pop();
      }
    } else {
      // For large eviction counts, fall back to sort
      entries.sort(function (a, b) { return a.lastAccess - b.lastAccess; });
      for (var j = 0; j < toEvict && j < entries.length; j++) {
        delete clients[entries[j].id];
        clientCount--;
      }
    }
  }

  /**
   * Get or create client record.
   */
  function getRecord(clientId, now) {
    if (!clients[clientId]) {
      clients[clientId] = { timestamps: [], lastAccess: now };
      clientCount++;
      evictIfNeeded();
    }
    clients[clientId].lastAccess = now;
    return clients[clientId];
  }

  /**
   * Count timestamps in last N ms.
   * Uses binary search on the sorted timestamp array for O(log n) instead
   * of O(n) linear backward scan.
   */
  function countInWindow(timestamps, now, windowSize) {
    var cutoff = now - windowSize;
    if (timestamps.length === 0) return 0;
    // Binary search for first timestamp > cutoff
    var lo = 0, hi = timestamps.length;
    while (lo < hi) {
      var mid = (lo + hi) >>> 1;
      if (timestamps[mid] <= cutoff) lo = mid + 1;
      else hi = mid;
    }
    return timestamps.length - lo;
  }

  /**
   * Calculate progressive delay based on how far over the limit.
   * Uses exponential curve: baseDelay * 2^(overage-1), capped at maxDelay.
   */
  function calculateDelay(requestCount) {
    if (requestCount <= maxRequests) return 0;
    var overage = requestCount - maxRequests;
    var delay = baseDelay * Math.pow(2, overage - 1);
    return Math.min(delay, maxDelay);
  }

  /**
   * Check if a client is rate-limited. Records the attempt.
   *
   * @param {string} clientId - Unique client identifier (IP, session, etc.)
   * @param {Object} [opts]
   * @param {number} [opts.now]      - Current timestamp (for testing)
   * @param {boolean} [opts.dryRun]  - If true, don't record the attempt
   * @returns {{ allowed: boolean, remaining: number, resetMs: number,
   *             delay: number, burst: boolean, reason: string, retryAfter: number }}
   */
  function check(clientId, opts) {
    opts = opts || {};
    var now = opts.now != null ? opts.now : Date.now();

    totalChecks++;

    // Allowlist bypass
    if (allowSet[clientId]) {
      totalAllowed++;
      return {
        allowed: true,
        remaining: maxRequests,
        resetMs: 0,
        delay: 0,
        burst: false,
        reason: "allowlisted",
        retryAfter: 0,
      };
    }

    // Blocklist reject
    if (blockSet[clientId]) {
      totalBlocked++;
      return {
        allowed: false,
        remaining: 0,
        resetMs: windowMs,
        delay: maxDelay,
        burst: false,
        reason: "blocklisted",
        retryAfter: windowMs,
      };
    }

    var record = getRecord(clientId, now);
    pruneTimestamps(record, now);

    var currentCount = record.timestamps.length;

    // Check burst
    var burstCount = countInWindow(record.timestamps, now, burstWindowMs);
    var isBurst = burstCount >= burstThreshold;
    if (isBurst) totalBursts++;

    // Record attempt (unless dry run)
    if (!opts.dryRun) {
      record.timestamps.push(now);
      currentCount++;
    }

    var isLimited = currentCount > maxRequests || isBurst;

    // Calculate reset time
    var resetMs = 0;
    if (record.timestamps.length > 0) {
      resetMs = Math.max(0, record.timestamps[0] + windowMs - now);
    }

    var delay = calculateDelay(currentCount);
    if (isBurst && delay < baseDelay) {
      delay = baseDelay; // minimum delay on burst
    }

    var retryAfter = isLimited ? Math.max(delay, resetMs > 0 ? Math.min(resetMs, windowMs) : windowMs) : 0;

    if (isLimited) {
      totalLimited++;
      return {
        allowed: false,
        remaining: 0,
        resetMs: resetMs,
        delay: delay,
        burst: isBurst,
        reason: isBurst ? "burst_detected" : "rate_limited",
        retryAfter: retryAfter,
      };
    }

    totalAllowed++;
    return {
      allowed: true,
      remaining: Math.max(0, maxRequests - currentCount),
      resetMs: resetMs,
      delay: 0,
      burst: false,
      reason: "ok",
      retryAfter: 0,
    };
  }

  /**
   * Check multiple clients at once.
   * @param {string[]} clientIds
   * @param {Object} [opts]
   * @returns {Object} Map of clientId -> check result
   */
  function checkBatch(clientIds, opts) {
    var results = {};
    for (var i = 0; i < clientIds.length; i++) {
      results[clientIds[i]] = check(clientIds[i], opts);
    }
    return results;
  }

  /**
   * Get current status for a client without recording an attempt.
   * @param {string} clientId
   * @param {Object} [opts]
   * @returns {{ count: number, remaining: number, burst: boolean, limited: boolean }}
   */
  function peek(clientId, opts) {
    opts = opts || {};
    var now = (opts.now != null ? opts.now : Date.now());

    if (allowSet[clientId]) {
      return { count: 0, remaining: maxRequests, burst: false, limited: false };
    }
    if (blockSet[clientId]) {
      return { count: 0, remaining: 0, burst: false, limited: true };
    }

    var record = clients[clientId];
    if (!record) {
      return { count: 0, remaining: maxRequests, burst: false, limited: false };
    }

    pruneTimestamps(record, now);
    var count = record.timestamps.length;
    var burstCount = countInWindow(record.timestamps, now, burstWindowMs);

    return {
      count: count,
      remaining: Math.max(0, maxRequests - count),
      burst: burstCount >= burstThreshold,
      limited: count >= maxRequests || burstCount >= burstThreshold,
    };
  }

  /**
   * Reset a specific client's rate limit state.
   * @param {string} clientId
   */
  function resetClient(clientId) {
    if (clients[clientId]) {
      delete clients[clientId];
      clientCount--;
    }
  }

  /**
   * Add client(s) to allowlist.
   * @param {string|string[]} ids
   */
  function allow(ids) {
    var arr = Array.isArray(ids) ? ids : [ids];
    arr.forEach(function (id) {
      allowSet[id] = true;
      delete blockSet[id];
    });
  }

  /**
   * Add client(s) to blocklist.
   * @param {string|string[]} ids
   */
  function block(ids) {
    var arr = Array.isArray(ids) ? ids : [ids];
    arr.forEach(function (id) {
      blockSet[id] = true;
      delete allowSet[id];
    });
  }

  /**
   * Remove client from both allowlist and blocklist.
   * @param {string} clientId
   */
  function unlist(clientId) {
    delete allowSet[clientId];
    delete blockSet[clientId];
  }

  /**
   * Get aggregate stats.
   * @returns {Object}
   */
  function getStats() {
    return {
      totalChecks: totalChecks,
      totalAllowed: totalAllowed,
      totalLimited: totalLimited,
      totalBlocked: totalBlocked,
      totalBursts: totalBursts,
      activeClients: clientCount,
      allowlistSize: Object.keys(allowSet).length,
      blocklistSize: Object.keys(blockSet).length,
      limitRate: totalChecks > 0 ? totalLimited / totalChecks : 0,
    };
  }

  /**
   * Export state for persistence.
   * @returns {Object}
   */
  function exportState() {
    var clientData = {};
    Object.keys(clients).forEach(function (id) {
      clientData[id] = {
        timestamps: clients[id].timestamps.slice(),
        lastAccess: clients[id].lastAccess,
      };
    });
    return {
      clients: clientData,
      allowlist: Object.keys(allowSet),
      blocklist: Object.keys(blockSet),
      stats: getStats(),
    };
  }

  /**
   * Import previously exported state.
   * @param {Object} state
   */
  function importState(state) {
    if (!state || typeof state !== "object") return;

    if (state.clients) {
      clients = {};
      clientCount = 0;
      Object.keys(state.clients).forEach(function (id) {
        clients[id] = {
          timestamps: (state.clients[id].timestamps || []).slice(),
          lastAccess: state.clients[id].lastAccess || 0,
        };
        clientCount++;
      });
    }

    if (state.allowlist) {
      allowSet = {};
      state.allowlist.forEach(function (id) { allowSet[id] = true; });
    }
    if (state.blocklist) {
      blockSet = {};
      state.blocklist.forEach(function (id) { blockSet[id] = true; });
    }
  }

  /**
   * Get the most active clients by request count.
   * @param {number} [n=10]
   * @param {Object} [opts]
   * @returns {Array<{clientId: string, count: number, lastAccess: number}>}
   */
  function topClients(n, opts) {
    opts = opts || {};
    var now = (opts.now != null ? opts.now : Date.now());
    n = n || 10;

    var entries = [];
    Object.keys(clients).forEach(function (id) {
      pruneTimestamps(clients[id], now);
      if (clients[id].timestamps.length > 0) {
        entries.push({
          clientId: id,
          count: clients[id].timestamps.length,
          lastAccess: clients[id].lastAccess,
        });
      }
    });

    entries.sort(function (a, b) { return b.count - a.count; });
    return entries.slice(0, n);
  }

  /**
   * Reset all state.
   */
  function reset() {
    clients = {};
    clientCount = 0;
    totalChecks = 0;
    totalAllowed = 0;
    totalLimited = 0;
    totalBlocked = 0;
    totalBursts = 0;
  }

  /**
   * Get configuration.
   * @returns {Object}
   */
  function getConfig() {
    return {
      windowMs: windowMs,
      maxRequests: maxRequests,
      burstThreshold: burstThreshold,
      burstWindowMs: burstWindowMs,
      maxDelay: maxDelay,
      baseDelay: baseDelay,
      maxClients: maxClients,
    };
  }

  return {
    check: check,
    checkBatch: checkBatch,
    peek: peek,
    resetClient: resetClient,
    allow: allow,
    block: block,
    unlist: unlist,
    getStats: getStats,
    topClients: topClients,
    exportState: exportState,
    importState: importState,
    reset: reset,
    getConfig: getConfig,
  };
}

// ── Client Fingerprinter ────────────────────────────────────────────

/**
 * Create a client fingerprinter for identifying repeat CAPTCHA visitors
 * without cookies. Collects multiple browser/device signals, hashes them
 * into a composite fingerprint, tracks fingerprint history, and detects
 * suspicious patterns (rapid identity changes, known bot fingerprints).
 *
 * Works server-side: the caller collects signals from the client and
 * passes them in. The fingerprinter handles hashing, storage, and analysis.
 *
 * @param {Object} [options]
 * @param {number} [options.maxFingerprints=10000] - Max stored fingerprints (LRU)
 * @param {number} [options.ttlMs=86400000] - Fingerprint TTL (default 24h)
 * @param {number} [options.suspiciousChangeThreshold=5] - Identity changes in window to flag
 * @param {number} [options.changeWindowMs=3600000] - Window for change detection (1h)
 * @param {string[]} [options.signalWeights] - Custom signal weight overrides
 * @returns {Object} Fingerprinter instance
 */
function createClientFingerprinter(options) {
  var opts = options || {};
  var maxFingerprints = opts.maxFingerprints || 10000;
  var ttlMs = opts.ttlMs || 86400000;
  var suspiciousChangeThreshold = opts.suspiciousChangeThreshold || 5;
  var changeWindowMs = opts.changeWindowMs || 3600000;

  // Signal weights for similarity scoring (sum to 1.0)
  var defaultWeights = {
    userAgent: 0.15,
    screen: 0.10,
    timezone: 0.10,
    language: 0.10,
    platform: 0.10,
    colorDepth: 0.05,
    touchSupport: 0.05,
    canvasHash: 0.15,
    webglVendor: 0.10,
    fonts: 0.10,
  };
  var signalWeights = {};
  var k;
  for (k in defaultWeights) {
    if (defaultWeights.hasOwnProperty(k)) {
      signalWeights[k] = (opts.signalWeights && opts.signalWeights[k] !== undefined)
        ? opts.signalWeights[k]
        : defaultWeights[k];
    }
  }

  // Storage: fingerprint hash -> { signals, firstSeen, lastSeen, visits, ipSet, meta }
  var store = {};
  var storeOrder = new LruTracker(); // O(1) LRU tracking

  // IP -> [{ fingerprintHash, timestamp }] for change tracking
  var ipHistory = {};

  // Known bot fingerprint patterns
  var botPatterns = [
    { field: "userAgent", pattern: /headless/i, label: "headless-browser" },
    { field: "userAgent", pattern: /phantom/i, label: "phantomjs" },
    { field: "userAgent", pattern: /selenium/i, label: "selenium" },
    { field: "userAgent", pattern: /puppeteer/i, label: "puppeteer" },
    { field: "webglVendor", pattern: /swiftshader/i, label: "swiftshader-gpu" },
    { field: "webglVendor", pattern: /llvmpipe/i, label: "software-renderer" },
    { field: "screen", pattern: /^0x0$/, label: "zero-screen" },
    { field: "colorDepth", pattern: /^0$/, label: "zero-color-depth" },
  ];

  /**
   * Simple string hash (djb2) for generating fingerprint IDs.
   * @param {string} str
   * @returns {string} Hex hash
   */
  function djb2Hash(str) {
    var hash = 5381;
    for (var i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0xffffffff;
    }
    // Convert to unsigned hex
    return (hash >>> 0).toString(16).padStart(8, "0");
  }

  /**
   * Normalize signals into a canonical object.
   * @param {Object} raw - Raw signals from client
   * @returns {Object} Normalized signals
   */
  function normalizeSignals(raw) {
    if (!raw || typeof raw !== "object") {
      return {};
    }
    return {
      userAgent: String(raw.userAgent || ""),
      screen: String(raw.screenWidth || 0) + "x" + String(raw.screenHeight || 0),
      timezone: String(raw.timezone || raw.timezoneOffset || ""),
      language: String(raw.language || "").toLowerCase(),
      platform: String(raw.platform || "").toLowerCase(),
      colorDepth: String(raw.colorDepth || 0),
      touchSupport: raw.touchSupport ? "true" : "false",
      canvasHash: String(raw.canvasHash || ""),
      webglVendor: String(raw.webglVendor || ""),
      fonts: Array.isArray(raw.fonts) ? raw.fonts.slice().sort().join(",") : String(raw.fonts || ""),
    };
  }

  /**
   * Generate a fingerprint hash from normalized signals.
   * @param {Object} signals - Normalized signals
   * @returns {string} Fingerprint hash
   */
  function generateHash(signals) {
    var parts = [];
    var keys = Object.keys(signals).sort();
    for (var i = 0; i < keys.length; i++) {
      parts.push(keys[i] + "=" + signals[keys[i]]);
    }
    return djb2Hash(parts.join("|"));
  }

  /**
   * Compute similarity between two normalized signal sets (0-1).
   * @param {Object} a
   * @param {Object} b
   * @returns {number} Similarity score
   */
  function computeSimilarity(a, b) {
    var score = 0;
    var totalWeight = 0;
    for (var key in signalWeights) {
      if (!signalWeights.hasOwnProperty(key)) continue;
      var w = signalWeights[key];
      totalWeight += w;
      if (a[key] === b[key] && a[key] !== "" && a[key] !== "0" && a[key] !== "0x0") {
        score += w;
      }
    }
    return totalWeight > 0 ? score / totalWeight : 0;
  }

  /**
   * Evict expired and over-limit entries.
   */
  function evict() {
    var now = Date.now();
    // Remove expired — iterate from oldest (head) since expired entries tend to be oldest
    var keys = storeOrder.toArray();
    for (var i = 0; i < keys.length; i++) {
      var hash = keys[i];
      if (store[hash] && (now - store[hash].lastSeen) > ttlMs) {
        delete store[hash];
        storeOrder.remove(hash);
      }
    }
    // LRU eviction if over limit — evict oldest first
    while (storeOrder.length > maxFingerprints) {
      var oldest = storeOrder.evictOldest();
      if (oldest !== undefined) delete store[oldest];
    }
  }

  /**
   * Record IP history for change detection.
   * @param {string} ip
   * @param {string} fpHash
   * @param {number} now
   */
  function recordIpChange(ip, fpHash, now) {
    if (!ip) return;
    if (!ipHistory[ip]) {
      ipHistory[ip] = [];
    }
    var hist = ipHistory[ip];
    // Only record if different from last
    if (hist.length === 0 || hist[hist.length - 1].fingerprintHash !== fpHash) {
      hist.push({ fingerprintHash: fpHash, timestamp: now });
    }
    // Trim old entries
    var cutoff = now - changeWindowMs;
    while (hist.length > 0 && hist[0].timestamp < cutoff) {
      hist.shift();
    }
    if (hist.length === 0) {
      delete ipHistory[ip];
    }
  }

  /**
   * Check if an IP has suspicious identity changes.
   * @param {string} ip
   * @returns {{ suspicious: boolean, changes: number, threshold: number }}
   */
  function checkIdentityChanges(ip) {
    if (!ip || !ipHistory[ip]) {
      return { suspicious: false, changes: 0, threshold: suspiciousChangeThreshold };
    }
    var now = Date.now();
    var cutoff = now - changeWindowMs;
    var recent = ipHistory[ip].filter(function (e) { return e.timestamp >= cutoff; });
    var uniqueHashes = {};
    for (var i = 0; i < recent.length; i++) {
      uniqueHashes[recent[i].fingerprintHash] = true;
    }
    var changes = Object.keys(uniqueHashes).length;
    return {
      suspicious: changes >= suspiciousChangeThreshold,
      changes: changes,
      threshold: suspiciousChangeThreshold,
    };
  }

  /**
   * Check signals against known bot patterns.
   * @param {Object} signals - Normalized signals
   * @returns {string[]} Matched bot pattern labels
   */
  function detectBotSignals(signals) {
    var matches = [];
    for (var i = 0; i < botPatterns.length; i++) {
      var bp = botPatterns[i];
      var val = signals[bp.field] || "";
      if (bp.pattern.test(val)) {
        matches.push(bp.label);
      }
    }
    return matches;
  }

  /**
   * Process a fingerprint: normalize, hash, store, detect.
   * @param {Object} rawSignals - Raw signals from client
   * @param {Object} [meta] - Optional metadata (ip, sessionId, etc.)
   * @returns {Object} Fingerprint result
   */
  function identify(rawSignals, meta) {
    var m = meta || {};
    var now = Date.now();
    var signals = normalizeSignals(rawSignals);
    var hash = generateHash(signals);

    evict();

    var isNew = !store[hash];
    if (isNew) {
      store[hash] = {
        signals: signals,
        firstSeen: now,
        lastSeen: now,
        visits: 0,
        ips: {},
      };
      storeOrder.push(hash);
    }

    var entry = store[hash];
    entry.lastSeen = now;
    entry.visits++;
    if (m.ip) {
      entry.ips[m.ip] = (entry.ips[m.ip] || 0) + 1;
    }

    // Move to end of LRU (O(1) via LruTracker)
    storeOrder.touch(hash);

    recordIpChange(m.ip, hash, now);
    var botSignals = detectBotSignals(signals);
    var identityCheck = checkIdentityChanges(m.ip);

    var riskScore = 0;
    if (botSignals.length > 0) riskScore += Math.min(botSignals.length * 20, 60);
    if (identityCheck.suspicious) riskScore += 30;
    if (isNew && m.ip && ipHistory[m.ip] && ipHistory[m.ip].length > 2) riskScore += 10;
    riskScore = Math.min(riskScore, 100);

    return {
      fingerprintHash: hash,
      isNew: isNew,
      visits: entry.visits,
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
      signals: signals,
      botSignals: botSignals,
      identityChanges: identityCheck,
      riskScore: riskScore,
      riskLevel: riskScore >= 60 ? "high" : riskScore >= 30 ? "medium" : "low",
    };
  }

  /**
   * Find stored fingerprints similar to given signals.
   * @param {Object} rawSignals
   * @param {number} [minSimilarity=0.7] - Minimum similarity threshold
   * @returns {Array<{ fingerprintHash: string, similarity: number, visits: number }>}
   */
  function findSimilar(rawSignals, minSimilarity) {
    var threshold = minSimilarity !== undefined ? minSimilarity : 0.7;
    var signals = normalizeSignals(rawSignals);
    var results = [];
    for (var hash in store) {
      if (!store.hasOwnProperty(hash)) continue;
      var sim = computeSimilarity(signals, store[hash].signals);
      if (sim >= threshold) {
        results.push({
          fingerprintHash: hash,
          similarity: Math.round(sim * 1000) / 1000,
          visits: store[hash].visits,
          firstSeen: store[hash].firstSeen,
          lastSeen: store[hash].lastSeen,
        });
      }
    }
    results.sort(function (a, b) { return b.similarity - a.similarity; });
    return results;
  }

  /**
   * Get fingerprint details by hash.
   * @param {string} hash
   * @returns {Object|null}
   */
  function getFingerprint(hash) {
    if (!store[hash]) return null;
    var e = store[hash];
    return {
      fingerprintHash: hash,
      signals: e.signals,
      firstSeen: e.firstSeen,
      lastSeen: e.lastSeen,
      visits: e.visits,
      uniqueIps: Object.keys(e.ips).length,
    };
  }

  /**
   * Get aggregate statistics.
   * @returns {Object}
   */
  function getStats() {
    var totalVisits = 0;
    var totalIps = {};
    for (var hash in store) {
      if (!store.hasOwnProperty(hash)) continue;
      totalVisits += store[hash].visits;
      for (var ip in store[hash].ips) {
        if (store[hash].ips.hasOwnProperty(ip)) {
          totalIps[ip] = true;
        }
      }
    }
    return {
      totalFingerprints: storeOrder.length,
      totalVisits: totalVisits,
      uniqueIps: Object.keys(totalIps).length,
      maxCapacity: maxFingerprints,
      trackedIps: Object.keys(ipHistory).length,
    };
  }

  /**
   * Export state for persistence.
   * @returns {Object}
   */
  function exportState() {
    return {
      store: JSON.parse(JSON.stringify(store)),
      storeOrder: storeOrder.toArray(),
      ipHistory: JSON.parse(JSON.stringify(ipHistory)),
    };
  }

  /**
   * Import previously exported state.
   * @param {Object} state
   */
  function importState(state) {
    if (!state || typeof state !== "object") return;
    if (state.store) {
      store = {};
      for (var h in state.store) {
        if (state.store.hasOwnProperty(h)) {
          store[h] = state.store[h];
        }
      }
    }
    if (Array.isArray(state.storeOrder)) {
      storeOrder.fromArray(state.storeOrder);
    }
    if (state.ipHistory) {
      ipHistory = {};
      for (var ip in state.ipHistory) {
        if (state.ipHistory.hasOwnProperty(ip)) {
          ipHistory[ip] = state.ipHistory[ip];
        }
      }
    }
  }

  /**
   * Reset all state.
   */
  function reset() {
    store = {};
    storeOrder.clear();
    ipHistory = {};
  }

  /**
   * Get configuration.
   * @returns {Object}
   */
  function getConfig() {
    return {
      maxFingerprints: maxFingerprints,
      ttlMs: ttlMs,
      suspiciousChangeThreshold: suspiciousChangeThreshold,
      changeWindowMs: changeWindowMs,
      signalWeights: JSON.parse(JSON.stringify(signalWeights)),
    };
  }

  return {
    identify: identify,
    findSimilar: findSimilar,
    getFingerprint: getFingerprint,
    getStats: getStats,
    exportState: exportState,
    importState: importState,
    reset: reset,
    getConfig: getConfig,
  };
}

// ── Incident Correlator ─────────────────────────────────────────────

/**
 * Create a security incident correlator that aggregates signals from
 * multiple detection systems (bot detector, rate limiter, reputation
 * tracker, response analyzer) into unified security incidents with
 * severity classification and alert generation.
 *
 * In production CAPTCHA deployments, individual signals (a failed
 * challenge, a rate limit trip, a low reputation score) may each be
 * benign. The correlator identifies *patterns* across signals that
 * indicate coordinated attacks: credential stuffing, CAPTCHA farming,
 * distributed bot networks, or targeted abuse.
 *
 * @param {object} [options]
 * @param {number} [options.correlationWindowMs=60000] - Time window for
 *   grouping related signals into a single incident (default: 60s)
 * @param {number} [options.maxIncidents=1000] - Max stored incidents
 *   before oldest are evicted (LRU)
 * @param {number} [options.maxSignalsPerIncident=50] - Max signals per
 *   incident before auto-escalation
 * @param {object} [options.thresholds] - Signal count thresholds for
 *   severity escalation
 * @param {number} [options.thresholds.warning=3] - Signals to trigger
 *   WARNING severity
 * @param {number} [options.thresholds.high=6] - Signals to trigger HIGH
 * @param {number} [options.thresholds.critical=10] - Signals to trigger
 *   CRITICAL
 * @param {function} [options.onAlert] - Callback fired when an incident
 *   reaches WARNING or above: onAlert(incident)
 * @param {function} [options.onEscalation] - Callback fired when an
 *   incident's severity increases: onEscalation(incident, oldSeverity)
 * @returns {object} Correlator instance
 */
function createIncidentCorrelator(options) {
  options = options || {};

  var correlationWindowMs = _posOpt(options.correlationWindowMs, 60000);
  var maxIncidents = _posOpt(options.maxIncidents, 1000);
  var maxSignalsPerIncident = _posOpt(options.maxSignalsPerIncident, 50);

  var thresholds = options.thresholds || {};
  var warningThreshold = _posOpt(thresholds.warning, 3);
  var highThreshold = _posOpt(thresholds.high, 6);
  var criticalThreshold = thresholds.critical != null && thresholds.critical > 0 ? thresholds.critical : 10;

  var onAlert = typeof options.onAlert === "function" ? options.onAlert : null;
  var onEscalation = typeof options.onEscalation === "function" ? options.onEscalation : null;

  // Severity levels (ordered)
  var SEVERITY = { INFO: "info", WARNING: "warning", HIGH: "high", CRITICAL: "critical" };
  var SEVERITY_ORDER = { info: 0, warning: 1, high: 2, critical: 3 };

  // Signal types recognized by the correlator
  var SIGNAL_TYPES = {
    CHALLENGE_FAILED: "challenge_failed",
    CHALLENGE_TIMEOUT: "challenge_timeout",
    RATE_LIMITED: "rate_limited",
    BOT_DETECTED: "bot_detected",
    REPUTATION_DROP: "reputation_drop",
    SUSPICIOUS_FINGERPRINT: "suspicious_fingerprint",
    TOKEN_INVALID: "token_invalid",
    TOKEN_REPLAY: "token_replay",
    BURST_DETECTED: "burst_detected",
    RAPID_ATTEMPTS: "rapid_attempts",
    CUSTOM: "custom",
  };

  // clientId -> incidentId mapping for correlation
  var clientIncidents = {};
  // incidentId -> incident object
  var incidents = {};
  var incidentOrder = []; // oldest first for LRU eviction
  var incidentOrderStart = 0; // pointer to first live entry (avoids O(n) shift)
  var nextIncidentId = 1;

  // Global stats
  var stats = {
    totalSignals: 0,
    totalIncidents: 0,
    totalAlerts: 0,
    totalEscalations: 0,
    signalsByType: {},
    incidentsBySeverity: { info: 0, warning: 0, high: 0, critical: 0 },
  };

  /**
   * Compute severity from signal count.
   */
  function computeSeverity(signalCount) {
    if (signalCount >= criticalThreshold) return SEVERITY.CRITICAL;
    if (signalCount >= highThreshold) return SEVERITY.HIGH;
    if (signalCount >= warningThreshold) return SEVERITY.WARNING;
    return SEVERITY.INFO;
  }

  /**
   * Evict oldest incidents when over maxIncidents.
   * Uses an index pointer instead of Array.shift() to avoid O(n)
   * element shifting on every eviction.
   */
  function evictIfNeeded() {
    var liveCount = incidentOrder.length - incidentOrderStart;
    while (liveCount > maxIncidents) {
      var oldId = incidentOrder[incidentOrderStart];
      incidentOrderStart++;
      liveCount--;
      var old = incidents[oldId];
      if (old) {
        if (old.clientId && clientIncidents[old.clientId] === oldId) {
          delete clientIncidents[old.clientId];
        }
        if (stats.incidentsBySeverity[old.severity] > 0) {
          stats.incidentsBySeverity[old.severity]--;
        }
        delete incidents[oldId];
      }
    }
    // Compact the array when the dead prefix grows too large
    // (> 2x live entries) to prevent unbounded memory growth
    if (incidentOrderStart > liveCount * 2 && incidentOrderStart > 100) {
      incidentOrder = incidentOrder.slice(incidentOrderStart);
      incidentOrderStart = 0;
    }
  }

  /**
   * Get a read-only summary of an incident.
   * Uses manual shallow copy for signalTypes instead of
   * JSON.parse(JSON.stringify(...)) — ~10x faster for flat objects.
   */
  function getIncidentSummary(incident) {
    // Shallow-copy the flat { type: count } map
    var typesCopy = {};
    for (var t in incident.signalTypes) {
      if (incident.signalTypes.hasOwnProperty(t)) {
        typesCopy[t] = incident.signalTypes[t];
      }
    }
    return {
      id: incident.id,
      clientId: incident.clientId,
      severity: incident.severity,
      status: incident.status,
      signalCount: incident.signalCount,
      weightedCount: incident.weightedCount,
      signalTypes: typesCopy,
      firstSignalAt: incident.firstSignalAt,
      lastSignalAt: incident.lastSignalAt,
      durationMs: incident.lastSignalAt - incident.firstSignalAt,
      signals: incident.signals.map(function (s) {
        return {
          type: s.type,
          description: s.description,
          timestamp: s.timestamp,
          weight: s.weight,
        };
      }),
    };
  }

  /**
   * Ingest a security signal. The correlator groups signals from the
   * same client within the correlation window into a single incident.
   *
   * @param {object} signal
   * @param {string} signal.type - One of SIGNAL_TYPES
   * @param {string} signal.clientId - Client/session identifier
   * @param {string} [signal.description] - Human-readable description
   * @param {object} [signal.metadata] - Additional context
   * @param {number} [signal.timestamp] - Signal time (default: Date.now())
   * @param {number} [signal.weight] - Signal importance multiplier (default: 1)
   * @returns {object} { incidentId, severity, isNew, escalated }
   */
  function ingest(signal) {
    if (!signal || !signal.type || !signal.clientId) {
      return { error: "Signal must have type and clientId" };
    }

    var now = signal.timestamp || Date.now();
    var weight = signal.weight != null && signal.weight > 0 ? signal.weight : 1;

    stats.totalSignals++;
    stats.signalsByType[signal.type] = (stats.signalsByType[signal.type] || 0) + 1;

    var existingId = clientIncidents[signal.clientId];
    var incident = existingId != null ? incidents[existingId] : null;

    // Close incident if outside correlation window
    if (incident && (now - incident.lastSignalAt) > correlationWindowMs) {
      incident.status = "closed";
      incident = null;
      existingId = null;
    }

    var isNew = false;
    var escalated = false;
    var oldSeverity = null;

    if (!incident) {
      isNew = true;
      var id = nextIncidentId++;
      incident = {
        id: id,
        clientId: signal.clientId,
        severity: SEVERITY.INFO,
        status: "open",
        signals: [],
        signalCount: 0,
        weightedCount: 0,
        signalTypes: {},
        firstSignalAt: now,
        lastSignalAt: now,
        createdAt: now,
      };
      incidents[id] = incident;
      incidentOrder.push(id);
      clientIncidents[signal.clientId] = id;
      stats.totalIncidents++;
      stats.incidentsBySeverity.info++;
      evictIfNeeded();
    }

    oldSeverity = incident.severity;
    incident.lastSignalAt = now;
    incident.signalCount++;
    incident.weightedCount += weight;
    incident.signalTypes[signal.type] = (incident.signalTypes[signal.type] || 0) + 1;

    if (incident.signals.length < maxSignalsPerIncident) {
      incident.signals.push({
        type: signal.type,
        description: signal.description || null,
        metadata: signal.metadata || null,
        timestamp: now,
        weight: weight,
      });
    }

    var newSeverity = computeSeverity(incident.weightedCount);
    if (SEVERITY_ORDER[newSeverity] > SEVERITY_ORDER[incident.severity]) {
      if (stats.incidentsBySeverity[incident.severity] > 0) {
        stats.incidentsBySeverity[incident.severity]--;
      }
      incident.severity = newSeverity;
      stats.incidentsBySeverity[newSeverity]++;
      escalated = true;
      stats.totalEscalations++;

      if (onEscalation) {
        try { onEscalation(getIncidentSummary(incident), oldSeverity); } catch (e) { /* swallow */ }
      }
    }

    if (escalated && SEVERITY_ORDER[newSeverity] >= SEVERITY_ORDER[SEVERITY.WARNING]) {
      stats.totalAlerts++;
      if (onAlert) {
        try { onAlert(getIncidentSummary(incident)); } catch (e) { /* swallow */ }
      }
    }

    return {
      incidentId: incident.id,
      severity: incident.severity,
      isNew: isNew,
      escalated: escalated,
    };
  }

  /**
   * Get an incident by ID.
   * @param {number} incidentId
   * @returns {object|null} Incident summary or null
   */
  function getIncident(incidentId) {
    var incident = incidents[incidentId];
    return incident ? getIncidentSummary(incident) : null;
  }

  /**
   * Get the active incident for a client.
   * @param {string} clientId
   * @returns {object|null} Incident summary or null
   */
  function getClientIncident(clientId) {
    var id = clientIncidents[clientId];
    if (id == null) return null;
    var incident = incidents[id];
    if (!incident || incident.status === "closed") return null;
    return getIncidentSummary(incident);
  }

  /**
   * Manually close an incident.
   * @param {number} incidentId
   * @returns {boolean} True if closed
   */
  function closeIncident(incidentId) {
    var incident = incidents[incidentId];
    if (!incident) return false;
    incident.status = "closed";
    if (clientIncidents[incident.clientId] === incidentId) {
      delete clientIncidents[incident.clientId];
    }
    return true;
  }

  /**
   * Query incidents by severity, status, and/or time range.
   * @param {object} [query]
   * @param {string} [query.severity] - Filter by exact severity
   * @param {string} [query.minSeverity] - Filter by minimum severity
   * @param {string} [query.status] - Filter by status
   * @param {number} [query.since] - Only incidents after this timestamp
   * @param {number} [query.limit] - Max results (default: 100)
   * @returns {Array} Matching incident summaries (newest first)
   */
  function queryIncidents(query) {
    query = query || {};
    var limit = query.limit != null && query.limit > 0 ? query.limit : 100;
    var minSev = query.minSeverity ? SEVERITY_ORDER[query.minSeverity] || 0 : 0;

    var results = [];
    for (var i = incidentOrder.length - 1; i >= 0 && results.length < limit; i--) {
      var inc = incidents[incidentOrder[i]];
      if (!inc) continue;
      if (query.severity && inc.severity !== query.severity) continue;
      if (SEVERITY_ORDER[inc.severity] < minSev) continue;
      if (query.status && inc.status !== query.status) continue;
      if (query.since && inc.lastSignalAt < query.since) continue;
      results.push(getIncidentSummary(inc));
    }
    return results;
  }

  /**
   * Get correlator statistics.
   * Uses manual shallow copy instead of JSON round-trip for flat maps.
   * Counts active incidents from the live portion of incidentOrder only.
   * @returns {object} Current stats snapshot
   */
  function getStats() {
    var activeCount = 0;
    for (var i = incidentOrderStart; i < incidentOrder.length; i++) {
      var inc = incidents[incidentOrder[i]];
      if (inc && inc.status === "open") activeCount++;
    }
    var byTypeCopy = {};
    for (var st in stats.signalsByType) {
      if (stats.signalsByType.hasOwnProperty(st)) {
        byTypeCopy[st] = stats.signalsByType[st];
      }
    }
    var bySevCopy = {};
    for (var sv in stats.incidentsBySeverity) {
      if (stats.incidentsBySeverity.hasOwnProperty(sv)) {
        bySevCopy[sv] = stats.incidentsBySeverity[sv];
      }
    }
    return {
      totalSignals: stats.totalSignals,
      totalIncidents: stats.totalIncidents,
      activeIncidents: activeCount,
      totalAlerts: stats.totalAlerts,
      totalEscalations: stats.totalEscalations,
      signalsByType: byTypeCopy,
      incidentsBySeverity: bySevCopy,
    };
  }

  /**
   * Reset all state.
   */
  function reset() {
    clientIncidents = {};
    incidents = {};
    incidentOrder = [];
    incidentOrderStart = 0;
    nextIncidentId = 1;
    stats.totalSignals = 0;
    stats.totalIncidents = 0;
    stats.totalAlerts = 0;
    stats.totalEscalations = 0;
    stats.signalsByType = {};
    stats.incidentsBySeverity = { info: 0, warning: 0, high: 0, critical: 0 };
  }

  /**
   * Export full correlator state for persistence/debugging.
   * @returns {object} Serializable state
   */
  function exportState() {
    var liveIncidents = [];
    for (var i = incidentOrderStart; i < incidentOrder.length; i++) {
      var inc = incidents[incidentOrder[i]];
      if (inc) liveIncidents.push(getIncidentSummary(inc));
    }
    return {
      incidents: liveIncidents,
      stats: getStats(),
      config: {
        correlationWindowMs: correlationWindowMs,
        maxIncidents: maxIncidents,
        maxSignalsPerIncident: maxSignalsPerIncident,
        thresholds: {
          warning: warningThreshold,
          high: highThreshold,
          critical: criticalThreshold,
        },
      },
    };
  }

  return {
    ingest: ingest,
    getIncident: getIncident,
    getClientIncident: getClientIncident,
    closeIncident: closeIncident,
    queryIncidents: queryIncidents,
    getStats: getStats,
    reset: reset,
    exportState: exportState,
    SIGNAL_TYPES: SIGNAL_TYPES,
    SEVERITY: SEVERITY,
  };
}

// ── Adaptive Timeout Manager ──────────────────────────────────────
//
// Calculates optimal response timeouts for CAPTCHA challenges based on
// difficulty, client reputation, historical response times, and network
// conditions. Harder challenges get more time; suspicious clients get
// less. Uses percentile-based baselines from actual response data.

/**
 * @param {Object} [options]
 * @param {number} [options.baseTimeoutMs=30000]       - Default timeout when no data available
 * @param {number} [options.minTimeoutMs=5000]          - Absolute minimum timeout
 * @param {number} [options.maxTimeoutMs=120000]        - Absolute maximum timeout
 * @param {number} [options.difficultyMultiplierLow=0.7]  - Timeout multiplier for easy challenges
 * @param {number} [options.difficultyMultiplierHigh=1.8] - Timeout multiplier for hard challenges
 * @param {number} [options.suspiciousReduction=0.5]    - Multiply timeout by this for suspicious clients
 * @param {number} [options.trustedBonus=1.3]           - Multiply timeout by this for trusted clients
 * @param {number} [options.targetPercentile=0.90]      - Response time percentile to use as baseline
 * @param {number} [options.baselineMargin=1.5]         - Multiplier on top of percentile baseline
 * @param {number} [options.maxHistoryPerDifficulty=500] - Max stored response times per difficulty bucket
 * @param {number} [options.latencyBufferMs=2000]       - Extra buffer added for estimated network latency
 * @returns {Object} Adaptive timeout manager instance
 */
function createAdaptiveTimeout(options) {
  options = options || {};

  var baseTimeoutMs = _posOpt(options.baseTimeoutMs, 30000);
  var minTimeoutMs = _posOpt(options.minTimeoutMs, 5000);
  var maxTimeoutMs = _posOpt(options.maxTimeoutMs, 120000);
  var difficultyMultiplierLow = options.difficultyMultiplierLow != null
    ? options.difficultyMultiplierLow : 0.7;
  var difficultyMultiplierHigh = options.difficultyMultiplierHigh != null
    ? options.difficultyMultiplierHigh : 1.8;
  var suspiciousReduction = options.suspiciousReduction != null
    ? options.suspiciousReduction : 0.5;
  var trustedBonus = options.trustedBonus != null
    ? options.trustedBonus : 1.3;
  var targetPercentile = options.targetPercentile != null
    ? options.targetPercentile : 0.90;
  var baselineMargin = options.baselineMargin != null
    ? options.baselineMargin : 1.5;
  var maxHistoryPerDifficulty = Math.floor(_posOpt(options.maxHistoryPerDifficulty, 500));
  var latencyBufferMs = _nnOpt(options.latencyBufferMs, 2000);

  // Difficulty buckets: "easy", "medium", "hard", or numeric 0-100
  // Normalized to 3 buckets for history tracking
  // Each bucket stores sorted response times for percentile calculation.
  var history = Object.create(null);
  history.easy = [];
  history.medium = [];
  history.hard = [];

  // Per-client latency estimates: clientId → { samples: number[], avg: number }
  var clientLatency = Object.create(null);
  var clientLatencyCount = 0;
  var maxClientLatencyEntries = 5000;

  // Stats
  var totalCalculations = 0;
  var totalRecorded = 0;

  /**
   * Normalize a difficulty value to a bucket name.
   * Accepts "easy"/"medium"/"hard" strings or numeric 0-100.
   * @param {string|number} difficulty
   * @returns {string} "easy", "medium", or "hard"
   */
  function normalizeDifficulty(difficulty) {
    if (typeof difficulty === "string") {
      var lower = difficulty.toLowerCase();
      if (lower === "easy" || lower === "low") return "easy";
      if (lower === "hard" || lower === "high") return "hard";
      return "medium";
    }
    if (typeof difficulty === "number") {
      if (difficulty <= 33) return "easy";
      if (difficulty >= 67) return "hard";
      return "medium";
    }
    return "medium";
  }

  /**
   * Get the difficulty multiplier for a bucket.
   * @param {string} bucket
   * @returns {number}
   */
  function getDifficultyMultiplier(bucket) {
    if (bucket === "easy") return difficultyMultiplierLow;
    if (bucket === "hard") return difficultyMultiplierHigh;
    return 1.0;
  }

  /**
   * Calculate the Nth percentile from a sorted array.
   * @param {number[]} sorted - Sorted array of values
   * @param {number} p - Percentile (0-1)
   * @returns {number}
   */
  function percentile(sorted, p) {
    if (sorted.length === 0) return 0;
    if (sorted.length === 1) return sorted[0];
    var idx = p * (sorted.length - 1);
    var lower = Math.floor(idx);
    var upper = Math.ceil(idx);
    if (lower === upper) return sorted[lower];
    var frac = idx - lower;
    return sorted[lower] * (1 - frac) + sorted[upper] * frac;
  }

  /**
   * Insert a value into a sorted array, maintaining sort order.
   * If the array exceeds maxHistoryPerDifficulty, remove the oldest
   * (first) entry.
   * @param {number[]} arr
   * @param {number} value
   */
  function insertSorted(arr, value) {
    // Binary search for insertion point
    var lo = 0;
    var hi = arr.length;
    while (lo < hi) {
      var mid = (lo + hi) >>> 1;
      if (arr[mid] < value) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    arr.splice(lo, 0, value);
    // Evict when over capacity.  The original arr.shift() systematically
    // removed the *smallest* value, biasing percentile calculations upward.
    // The subsequent fix evicted from the middle (arr.length >>> 1), which
    // systematically removed median values and created a bimodal
    // distribution — overrepresenting both tails and inflating higher
    // percentiles used for timeout calibration.
    //
    // Correct approach: evict at a random index so no part of the
    // distribution is systematically thinned.
    if (arr.length > maxHistoryPerDifficulty) {
      var evictIdx = secureRandomInt(arr.length);
      arr.splice(evictIdx, 1);
    }
  }

  /**
   * Record a response time for a given difficulty level.
   * Builds up the baseline data used for percentile calculations.
   *
   * @param {string|number} difficulty - Challenge difficulty
   * @param {number} responseTimeMs - Actual response time in ms
   */
  function recordResponse(difficulty, responseTimeMs) {
    if (typeof responseTimeMs !== "number" || responseTimeMs < 0) return;
    var bucket = normalizeDifficulty(difficulty);
    insertSorted(history[bucket], responseTimeMs);
    totalRecorded++;
  }

  /**
   * Record a network latency sample for a client.
   * Used to add per-client latency compensation.
   *
   * @param {string} clientId - Client identifier
   * @param {number} latencyMs - Measured round-trip latency in ms
   */
  function recordLatency(clientId, latencyMs) {
    if (typeof latencyMs !== "number" || latencyMs < 0) return;
    if (!clientId) return;

    if (!clientLatency[clientId]) {
      // Evict oldest if at capacity
      if (clientLatencyCount >= maxClientLatencyEntries) {
        var keys = Object.keys(clientLatency);
        if (keys.length > 0) {
          delete clientLatency[keys[0]];
          clientLatencyCount--;
        }
      }
      clientLatency[clientId] = { samples: [], avg: 0 };
      clientLatencyCount++;
    }

    var entry = clientLatency[clientId];
    entry.samples.push(latencyMs);
    // Keep last 10 samples
    if (entry.samples.length > 10) {
      entry.samples.shift();
    }
    // Recalculate average
    var sum = 0;
    for (var i = 0; i < entry.samples.length; i++) {
      sum += entry.samples[i];
    }
    entry.avg = sum / entry.samples.length;
  }

  /**
   * Get the estimated latency for a client.
   * @param {string} [clientId]
   * @returns {number} Latency in ms (0 if unknown)
   */
  function getClientLatency(clientId) {
    if (!clientId || !clientLatency[clientId]) return 0;
    return clientLatency[clientId].avg;
  }

  /**
   * Calculate the adaptive timeout for a challenge.
   *
   * The calculation layers multiple factors:
   * 1. Baseline: percentile-based response time from history (or baseTimeoutMs)
   * 2. Difficulty: multiplier based on challenge difficulty
   * 3. Reputation: reduction for suspicious clients, bonus for trusted
   * 4. Latency: per-client network latency compensation
   * 5. Clamped to [minTimeoutMs, maxTimeoutMs]
   *
   * @param {Object} params
   * @param {string|number} [params.difficulty="medium"] - Challenge difficulty
   * @param {string} [params.reputation="neutral"]       - "trusted", "neutral", or "suspicious"
   * @param {string} [params.clientId]                    - Client ID for latency lookup
   * @returns {{ timeoutMs: number, factors: Object }}
   */
  function calculate(params) {
    params = params || {};
    totalCalculations++;

    var bucket = normalizeDifficulty(params.difficulty != null ? params.difficulty : "medium");
    var reputation = params.reputation || "neutral";
    var clientId = params.clientId || null;

    // Step 1: Baseline from history or default
    var baseline;
    var historyData = history[bucket];
    if (historyData.length >= 10) {
      var p = percentile(historyData, targetPercentile);
      baseline = p * baselineMargin;
    } else {
      baseline = baseTimeoutMs;
    }

    // Step 2: Difficulty multiplier
    var diffMult = getDifficultyMultiplier(bucket);
    var afterDifficulty = baseline * diffMult;

    // Step 3: Reputation adjustment
    var repMult = 1.0;
    if (reputation === "suspicious") {
      repMult = suspiciousReduction;
    } else if (reputation === "trusted") {
      repMult = trustedBonus;
    }
    var afterReputation = afterDifficulty * repMult;

    // Step 4: Latency compensation
    var clientLat = getClientLatency(clientId);
    var latencyCompensation = clientLat > 0 ? clientLat : latencyBufferMs;
    var afterLatency = afterReputation + latencyCompensation;

    // Step 5: Clamp
    var finalTimeout = Math.round(
      _clamp(afterLatency, minTimeoutMs, maxTimeoutMs)
    );

    return {
      timeoutMs: finalTimeout,
      factors: {
        baseline: Math.round(baseline),
        difficulty: bucket,
        difficultyMultiplier: diffMult,
        reputation: reputation,
        reputationMultiplier: repMult,
        latencyMs: Math.round(latencyCompensation),
        unclamped: Math.round(afterLatency),
      },
    };
  }

  /**
   * Get the baseline response time for a difficulty bucket.
   *
   * @param {string|number} [difficulty="medium"]
   * @returns {{ percentile: number, sampleCount: number, bucketMs: number|null }}
   */
  function getBaseline(difficulty) {
    var bucket = normalizeDifficulty(difficulty != null ? difficulty : "medium");
    var data = history[bucket];
    if (data.length === 0) {
      return { percentile: targetPercentile, sampleCount: 0, baselineMs: null };
    }
    return {
      percentile: targetPercentile,
      sampleCount: data.length,
      baselineMs: Math.round(percentile(data, targetPercentile)),
    };
  }

  /**
   * Get overall statistics.
   * @returns {Object}
   */
  function getStats() {
    return {
      totalCalculations: totalCalculations,
      totalRecorded: totalRecorded,
      historySizes: {
        easy: history.easy.length,
        medium: history.medium.length,
        hard: history.hard.length,
      },
      clientLatencyEntries: clientLatencyCount,
    };
  }

  /**
   * Export full state for persistence.
   * @returns {Object}
   */
  function exportState() {
    var latencyExport = Object.create(null);
    for (var id in clientLatency) {
      latencyExport[id] = {
        samples: clientLatency[id].samples.slice(),
        avg: clientLatency[id].avg,
      };
    }
    return {
      history: {
        easy: history.easy.slice(),
        medium: history.medium.slice(),
        hard: history.hard.slice(),
      },
      clientLatency: latencyExport,
      totalCalculations: totalCalculations,
      totalRecorded: totalRecorded,
    };
  }

  /**
   * Import previously exported state.
   * @param {Object} state
   */
  function importState(state) {
    if (!state || typeof state !== "object") return;
    if (state.history) {
      history.easy = Array.isArray(state.history.easy) ? state.history.easy.slice() : [];
      history.medium = Array.isArray(state.history.medium) ? state.history.medium.slice() : [];
      history.hard = Array.isArray(state.history.hard) ? state.history.hard.slice() : [];
    }
    if (state.clientLatency) {
      clientLatency = Object.create(null);
      clientLatencyCount = 0;
      var keys = Object.keys(state.clientLatency);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        var entry = state.clientLatency[k];
        clientLatency[k] = {
          samples: Array.isArray(entry.samples) ? entry.samples.slice() : [],
          avg: entry.avg || 0,
        };
        clientLatencyCount++;
      }
    }
    if (typeof state.totalCalculations === "number") {
      totalCalculations = state.totalCalculations;
    }
    if (typeof state.totalRecorded === "number") {
      totalRecorded = state.totalRecorded;
    }
  }

  /**
   * Reset all state.
   */
  function reset() {
    history.easy = [];
    history.medium = [];
    history.hard = [];
    clientLatency = Object.create(null);
    clientLatencyCount = 0;
    totalCalculations = 0;
    totalRecorded = 0;
  }

  /**
   * Get configuration.
   * @returns {Object}
   */
  function getConfig() {
    return {
      baseTimeoutMs: baseTimeoutMs,
      minTimeoutMs: minTimeoutMs,
      maxTimeoutMs: maxTimeoutMs,
      difficultyMultiplierLow: difficultyMultiplierLow,
      difficultyMultiplierHigh: difficultyMultiplierHigh,
      suspiciousReduction: suspiciousReduction,
      trustedBonus: trustedBonus,
      targetPercentile: targetPercentile,
      baselineMargin: baselineMargin,
      maxHistoryPerDifficulty: maxHistoryPerDifficulty,
      latencyBufferMs: latencyBufferMs,
    };
  }

  return {
    calculate: calculate,
    recordResponse: recordResponse,
    recordLatency: recordLatency,
    getClientLatency: getClientLatency,
    getBaseline: getBaseline,
    getStats: getStats,
    exportState: exportState,
    importState: importState,
    reset: reset,
    getConfig: getConfig,
  };
}

// ── Audit Trail ──────────────────────────────────────────────────
//
// Structured, queryable log of all CAPTCHA lifecycle events for
// compliance auditing, forensic analysis, and debugging.
// Events are stored in a bounded ring buffer with automatic eviction.

/**
 * @param {Object} [options]
 * @param {number} [options.maxEntries=10000]   - Maximum stored events (ring buffer)
 * @param {boolean} [options.includeMetadata=true] - Attach extra metadata to events
 * @param {Function} [options.onEvent]          - Optional callback for each event
 * @param {string[]} [options.enabledTypes]     - If set, only record these event types
 * @returns {Object} Audit trail instance
 */
function createAuditTrail(options) {
  options = options || {};

  var maxEntries = Math.floor(_posOpt(options.maxEntries, 10000));
  var includeMetadata = options.includeMetadata !== false;
  var onEvent = typeof options.onEvent === "function" ? options.onEvent : null;
  var enabledTypes = null;
  if (Array.isArray(options.enabledTypes) && options.enabledTypes.length > 0) {
    enabledTypes = Object.create(null);
    for (var i = 0; i < options.enabledTypes.length; i++) {
      enabledTypes[options.enabledTypes[i]] = true;
    }
  }

  var EVENT_TYPES = [
    "challenge.created",
    "challenge.served",
    "challenge.solved",
    "challenge.failed",
    "challenge.expired",
    "challenge.refreshed",
    "session.started",
    "session.ended",
    "rate.limited",
    "rate.blocked",
    "bot.detected",
    "bot.suspected",
    "reputation.updated",
    "reputation.blocked",
    "incident.created",
    "incident.escalated",
    "incident.closed",
    "timeout.calculated",
    "fingerprint.generated",
    "config.changed",
  ];

  var entries = [];
  var _head = 0;   // Ring buffer: index of oldest entry in entries[]
  var _size = 0;    // Ring buffer: number of live entries
  var nextId = 1;
  var totalLogged = 0;
  var evictedCount = 0;
  var typeCounts = Object.create(null);

  /**
   * Ring buffer helper: get the logical-index-th entry (0 = oldest).
   * O(1) access without needing Array.shift().
   */
  function _rbGet(logicalIndex) {
    return entries[(_head + logicalIndex) % maxEntries];
  }

  function record(type, data, meta) {
    if (typeof type !== "string" || type.length === 0) return null;
    if (enabledTypes && !enabledTypes[type]) return null;

    var entry = {
      id: nextId++,
      type: type,
      timestamp: Date.now(),
      data: data || null,
    };

    if (includeMetadata && meta) {
      entry.meta = {
        clientId: meta.clientId || null,
        sessionId: meta.sessionId || null,
        ip: meta.ip || null,
        userAgent: meta.userAgent || null,
      };
      var metaKeys = Object.keys(meta);
      for (var i = 0; i < metaKeys.length; i++) {
        var k = metaKeys[i];
        if (!(k in entry.meta)) {
          entry.meta[k] = meta[k];
        }
      }
    }

    if (_size >= maxEntries) {
      // O(1) eviction: overwrite the oldest slot and advance _head,
      // instead of O(n) Array.shift() that copies every element.
      entries[(_head + _size) % maxEntries] = entry;
      _head = (_head + 1) % maxEntries;
      evictedCount++;
    } else {
      entries.push(entry);
      _size++;
    }
    totalLogged++;

    typeCounts[type] = (typeCounts[type] || 0) + 1;

    if (onEvent) {
      try { onEvent(entry); } catch (e) { /* swallow callback errors */ }
    }

    return entry;
  }

  function query(q) {
    q = q || {};
    var limit = q.limit != null && q.limit > 0 ? q.limit : 100;
    var results = [];

    for (var i = _size - 1; i >= 0 && results.length < limit; i--) {
      var e = _rbGet(i);
      if (q.type && e.type !== q.type) continue;
      if (q.typePrefix && e.type.indexOf(q.typePrefix) !== 0) continue;
      if (q.since && e.timestamp < q.since) continue;
      if (q.until && e.timestamp > q.until) continue;
      if (q.clientId && (!e.meta || e.meta.clientId !== q.clientId)) continue;
      if (q.sessionId && (!e.meta || e.meta.sessionId !== q.sessionId)) continue;
      results.push(e);
    }

    return results;
  }

  function recent(n) {
    n = n != null && n > 0 ? n : 10;
    var start = Math.max(0, _size - n);
    var result = [];
    for (var i = _size - 1; i >= start; i--) {
      result.push(_rbGet(i));
    }
    return result;
  }

  function getById(id) {
    if (_size === 0) return null;
    var firstId = _rbGet(0).id;
    var idx = id - firstId;
    if (idx < 0 || idx >= _size) return null;
    var entry = _rbGet(idx);
    return entry && entry.id === id ? entry : null;
  }

  function getStats() {
    var typeCountsCopy = Object.create(null);
    var keys = Object.keys(typeCounts);
    for (var i = 0; i < keys.length; i++) {
      typeCountsCopy[keys[i]] = typeCounts[keys[i]];
    }
    return {
      totalLogged: totalLogged,
      currentSize: _size,
      maxEntries: maxEntries,
      evictedCount: evictedCount,
      typeCounts: typeCountsCopy,
      oldestTimestamp: _size > 0 ? _rbGet(0).timestamp : null,
      newestTimestamp: _size > 0 ? _rbGet(_size - 1).timestamp : null,
    };
  }

  function countByType(opts) {
    opts = opts || {};
    var counts = Object.create(null);

    if (!opts.since && !opts.until) {
      var keys = Object.keys(typeCounts);
      for (var i = 0; i < keys.length; i++) {
        counts[keys[i]] = typeCounts[keys[i]];
      }
      return counts;
    }

    for (var j = 0; j < _size; j++) {
      var e = _rbGet(j);
      if (opts.since && e.timestamp < opts.since) continue;
      if (opts.until && e.timestamp > opts.until) continue;
      counts[e.type] = (counts[e.type] || 0) + 1;
    }
    return counts;
  }

  function timeline(opts) {
    if (!opts || !opts.bucketMs || opts.bucketMs <= 0) {
      return { buckets: [], total: 0 };
    }

    var since = opts.since || (_size > 0 ? _rbGet(0).timestamp : 0);
    var until = opts.until || (_size > 0 ? _rbGet(_size - 1).timestamp : 0);
    if (since > until) return { buckets: [], total: 0 };

    var buckets = [];
    var numBuckets = Math.ceil((until - since + 1) / opts.bucketMs);
    if (numBuckets > 1000) numBuckets = 1000;

    for (var b = 0; b < numBuckets; b++) {
      buckets.push({
        start: since + b * opts.bucketMs,
        end: since + (b + 1) * opts.bucketMs - 1,
        count: 0,
      });
    }

    var total = 0;
    for (var i = 0; i < _size; i++) {
      var e = _rbGet(i);
      if (e.timestamp < since || e.timestamp > until) continue;
      if (opts.type && e.type !== opts.type) continue;
      var bucketIdx = Math.floor((e.timestamp - since) / opts.bucketMs);
      if (bucketIdx >= 0 && bucketIdx < buckets.length) {
        buckets[bucketIdx].count++;
        total++;
      }
    }

    return { buckets: buckets, total: total };
  }

  function exportState() {
    // Linearise ring buffer to a plain array for serialisation
    var arr = new Array(_size);
    for (var i = 0; i < _size; i++) {
      arr[i] = _rbGet(i);
    }
    return {
      entries: arr,
      nextId: nextId,
      totalLogged: totalLogged,
      evictedCount: evictedCount,
      typeCounts: countByType(),
    };
  }

  function importState(state) {
    if (!state || typeof state !== "object") return;
    if (Array.isArray(state.entries)) {
      var imported = state.entries.slice();
      if (imported.length > maxEntries) {
        var excess = imported.length - maxEntries;
        imported = imported.slice(excess);
        evictedCount += excess;
      }
      // Reset ring buffer and load imported entries linearly
      entries = imported;
      _head = 0;
      _size = imported.length;
    }
    if (typeof state.nextId === "number") nextId = state.nextId;
    if (typeof state.totalLogged === "number") totalLogged = state.totalLogged;
    if (typeof state.evictedCount === "number") evictedCount = state.evictedCount;
    typeCounts = Object.create(null);
    for (var i = 0; i < _size; i++) {
      var t = _rbGet(i).type;
      typeCounts[t] = (typeCounts[t] || 0) + 1;
    }
  }

  function reset() {
    entries = [];
    _head = 0;
    _size = 0;
    nextId = 1;
    totalLogged = 0;
    evictedCount = 0;
    typeCounts = Object.create(null);
  }

  return {
    record: record,
    query: query,
    recent: recent,
    getById: getById,
    getStats: getStats,
    countByType: countByType,
    timeline: timeline,
    exportState: exportState,
    importState: importState,
    reset: reset,
    EVENT_TYPES: EVENT_TYPES,
  };
}

// ── Session Recorder ────────────────────────────────────────────────

/**
 * Create a CAPTCHA session recorder for capturing, replaying, and analyzing
 * complete user interaction sessions. Useful for debugging, QA testing,
 * identifying UX issues, and generating test fixtures from real traffic.
 *
 * Each session captures a sequence of events (challenge served, user input,
 * answer submitted, result) with precise timing. Sessions can be exported,
 * imported, replayed step-by-step, compared, and queried.
 *
 * @param {Object} [options]
 * @param {number} [options.maxSessions=1000] - Maximum stored sessions (LRU eviction)
 * @param {number} [options.sessionTimeoutMs=300000] - Auto-close inactive sessions (5 min default)
 * @param {boolean} [options.captureInputs=true] - Record intermediate user inputs
 * @param {function} [options.onSessionEnd] - Callback when a session ends
 * @param {string[]} [options.tags] - Default tags for all sessions
 * @returns {Object} Session recorder API
 */
function createSessionRecorder(options) {
  options = options || {};

  var maxSessions = Math.floor(_posOpt(options.maxSessions, 1000));
  var sessionTimeoutMs = _posOpt(options.sessionTimeoutMs, 300000);
  var captureInputs = options.captureInputs !== false;
  var onSessionEnd = typeof options.onSessionEnd === "function" ? options.onSessionEnd : null;
  var defaultTags = Array.isArray(options.tags) ? options.tags.slice() : [];

  var sessions = Object.create(null);
  var sessionOrder = new LruTracker(); // O(1) LRU tracking
  var sessionCount = 0;
  var nextId = 1;
  var totalRecorded = 0;
  var totalEvicted = 0;

  var EVENT_TYPES = [
    "session.start",
    "challenge.served",
    "input.keystroke",
    "input.click",
    "input.focus",
    "input.blur",
    "input.paste",
    "answer.submitted",
    "answer.correct",
    "answer.incorrect",
    "challenge.timeout",
    "challenge.skipped",
    "challenge.refreshed",
    "session.end",
    "error",
    "custom"
  ];

  var eventTypeSet = Object.create(null);
  for (var i = 0; i < EVENT_TYPES.length; i++) {
    eventTypeSet[EVENT_TYPES[i]] = true;
  }

  function _evictOldest() {
    var oldest = sessionOrder.evictOldest();
    if (oldest === undefined) return;
    delete sessions[oldest];
    sessionCount--;
    totalEvicted++;
  }

  /**
   * Start a new recording session.
   * @param {Object} [meta] - Session metadata (clientId, difficulty, etc.)
   * @returns {string} Session ID
   */
  function startSession(meta) {
    var id = "rec_" + nextId++;
    var now = _now();

    if (sessionCount >= maxSessions) {
      _evictOldest();
    }

    var session = {
      id: id,
      startedAt: now,
      endedAt: null,
      status: "active",  // active | completed | timeout | error
      events: [],
      metadata: meta || {},
      tags: defaultTags.slice(),
      outcome: null,  // correct | incorrect | timeout | skipped | null
      challengeCount: 0,
      inputCount: 0,
      duration: null
    };

    sessions[id] = session;
    sessionOrder.push(id);
    sessionCount++;
    totalRecorded++;

    _addEvent(id, "session.start", { metadata: session.metadata });

    return id;
  }

  function _addEvent(sessionId, type, data) {
    var session = sessions[sessionId];
    if (!session) return null;
    if (session.status !== "active") return null;

    var event = {
      seq: session.events.length,
      type: type,
      timestamp: _now(),
      elapsed: _now() - session.startedAt,
      data: data || null
    };

    session.events.push(event);

    // Auto-timeout check
    if (event.elapsed > sessionTimeoutMs && type !== "session.end") {
      endSession(sessionId, "timeout");
    }

    return event;
  }

  /**
   * Record a challenge being served in a session.
   * @param {string} sessionId
   * @param {Object} challengeInfo - Challenge details (type, difficulty, id)
   */
  function recordChallenge(sessionId, challengeInfo) {
    var session = sessions[sessionId];
    if (!session) return;
    session.challengeCount++;
    _addEvent(sessionId, "challenge.served", challengeInfo || {});
  }

  /**
   * Record user input (keystroke, click, etc.).
   * @param {string} sessionId
   * @param {string} inputType - "keystroke" | "click" | "focus" | "blur" | "paste"
   * @param {Object} [data] - Input details
   */
  function recordInput(sessionId, inputType, data) {
    if (!captureInputs) return;
    var session = sessions[sessionId];
    if (!session) return;
    session.inputCount++;
    var type = "input." + (inputType || "keystroke");
    if (!eventTypeSet[type]) type = "custom";
    _addEvent(sessionId, type, data || {});
  }

  /**
   * Record an answer submission.
   * @param {string} sessionId
   * @param {Object} submission - { answer, challengeId, ... }
   */
  function recordSubmission(sessionId, submission) {
    _addEvent(sessionId, "answer.submitted", submission || {});
  }

  /**
   * Record the answer result.
   * @param {string} sessionId
   * @param {boolean} correct
   * @param {Object} [details]
   */
  function recordResult(sessionId, correct, details) {
    var session = sessions[sessionId];
    if (!session) return;
    var type = correct ? "answer.correct" : "answer.incorrect";
    session.outcome = correct ? "correct" : "incorrect";
    _addEvent(sessionId, type, details || {});
  }

  /**
   * Record a challenge skip.
   * @param {string} sessionId
   * @param {Object} [data]
   */
  function recordSkip(sessionId, data) {
    var session = sessions[sessionId];
    if (!session) return;
    session.outcome = "skipped";
    _addEvent(sessionId, "challenge.skipped", data || {});
  }

  /**
   * Record a challenge refresh (user requested new challenge).
   * @param {string} sessionId
   * @param {Object} [data]
   */
  function recordRefresh(sessionId, data) {
    _addEvent(sessionId, "challenge.refreshed", data || {});
  }

  /**
   * Record an error event.
   * @param {string} sessionId
   * @param {string} message
   * @param {Object} [data]
   */
  function recordError(sessionId, message, data) {
    var d = data || {};
    d.message = message;
    _addEvent(sessionId, "error", d);
  }

  /**
   * Record a custom event.
   * @param {string} sessionId
   * @param {Object} [data]
   */
  function recordCustom(sessionId, data) {
    _addEvent(sessionId, "custom", data || {});
  }

  /**
   * End a session.
   * @param {string} sessionId
   * @param {string} [reason] - "completed" | "timeout" | "error"
   */
  function endSession(sessionId, reason) {
    var session = sessions[sessionId];
    if (!session || session.status !== "active") return;

    session.status = reason || "completed";
    session.endedAt = _now();
    session.duration = session.endedAt - session.startedAt;

    if (reason === "timeout" && !session.outcome) {
      session.outcome = "timeout";
    }

    // Add end event directly to avoid recursion
    session.events.push({
      seq: session.events.length,
      type: "session.end",
      timestamp: session.endedAt,
      elapsed: session.duration,
      data: { reason: session.status, outcome: session.outcome }
    });

    if (onSessionEnd) {
      try { onSessionEnd(session); } catch (e) { /* ignore */ }
    }
  }

  /**
   * Get a session by ID.
   * @param {string} sessionId
   * @returns {Object|null}
   */
  function getSession(sessionId) {
    return sessions[sessionId] || null;
  }

  /**
   * Add tags to a session.
   * @param {string} sessionId
   * @param {string[]} tags
   */
  function addTags(sessionId, tags) {
    var session = sessions[sessionId];
    if (!session || !Array.isArray(tags)) return;
    for (var i = 0; i < tags.length; i++) {
      if (session.tags.indexOf(tags[i]) === -1) {
        session.tags.push(tags[i]);
      }
    }
  }

  /**
   * Query sessions with filters.
   * @param {Object} [filters]
   * @param {string} [filters.status] - Filter by status
   * @param {string} [filters.outcome] - Filter by outcome
   * @param {string} [filters.tag] - Filter by tag
   * @param {number} [filters.since] - Filter sessions started after timestamp
   * @param {number} [filters.until] - Filter sessions started before timestamp
   * @param {string} [filters.clientId] - Filter by metadata.clientId
   * @param {number} [filters.minEvents] - Minimum event count
   * @param {number} [filters.limit] - Max results
   * @returns {Object[]}
   */
  function querySessions(filters) {
    filters = filters || {};
    var results = [];
    var limit = filters.limit > 0 ? filters.limit : Infinity;

    var order = sessionOrder.toArray();
    for (var i = order.length - 1; i >= 0 && results.length < limit; i--) {
      var s = sessions[order[i]];
      if (!s) continue;

      if (filters.status && s.status !== filters.status) continue;
      if (filters.outcome && s.outcome !== filters.outcome) continue;
      if (filters.tag && s.tags.indexOf(filters.tag) === -1) continue;
      if (filters.since && s.startedAt < filters.since) continue;
      if (filters.until && s.startedAt > filters.until) continue;
      if (filters.clientId && (!s.metadata || s.metadata.clientId !== filters.clientId)) continue;
      if (filters.minEvents && s.events.length < filters.minEvents) continue;

      results.push(s);
    }

    return results;
  }

  /**
   * Create a step-by-step replay iterator for a session.
   * @param {string} sessionId
   * @returns {Object} Replay controller with next(), peek(), reset(), progress()
   */
  function createReplay(sessionId) {
    var session = sessions[sessionId];
    if (!session) return null;

    var events = session.events;
    var cursor = 0;

    return {
      /** Get next event or null if done */
      next: function () {
        if (cursor >= events.length) return null;
        return events[cursor++];
      },
      /** Peek at next event without advancing */
      peek: function () {
        if (cursor >= events.length) return null;
        return events[cursor];
      },
      /** Reset replay to beginning */
      reset: function () {
        cursor = 0;
      },
      /** Jump to a specific step */
      jumpTo: function (step) {
        if (step >= 0 && step <= events.length) cursor = step;
      },
      /** Get progress info */
      progress: function () {
        return {
          current: cursor,
          total: events.length,
          percent: events.length > 0 ? Math.round((cursor / events.length) * 100) : 0,
          done: cursor >= events.length
        };
      },
      /** Get all remaining events */
      remaining: function () {
        return events.slice(cursor);
      }
    };
  }

  /**
   * Compare two sessions side-by-side.
   * @param {string} sessionIdA
   * @param {string} sessionIdB
   * @returns {Object|null} Comparison result
   */
  function compareSessions(sessionIdA, sessionIdB) {
    var a = sessions[sessionIdA];
    var b = sessions[sessionIdB];
    if (!a || !b) return null;

    function eventTypeCounts(session) {
      var counts = Object.create(null);
      for (var i = 0; i < session.events.length; i++) {
        var t = session.events[i].type;
        counts[t] = (counts[t] || 0) + 1;
      }
      return counts;
    }

    var aCounts = eventTypeCounts(a);
    var bCounts = eventTypeCounts(b);

    // Collect all event types
    var allTypes = Object.create(null);
    var k;
    for (k in aCounts) allTypes[k] = true;
    for (k in bCounts) allTypes[k] = true;

    var eventDiffs = [];
    for (k in allTypes) {
      var ca = aCounts[k] || 0;
      var cb = bCounts[k] || 0;
      if (ca !== cb) {
        eventDiffs.push({ type: k, countA: ca, countB: cb, delta: cb - ca });
      }
    }

    return {
      sessionA: { id: a.id, status: a.status, outcome: a.outcome, duration: a.duration, eventCount: a.events.length, challengeCount: a.challengeCount, inputCount: a.inputCount },
      sessionB: { id: b.id, status: b.status, outcome: b.outcome, duration: b.duration, eventCount: b.events.length, challengeCount: b.challengeCount, inputCount: b.inputCount },
      durationDelta: (b.duration || 0) - (a.duration || 0),
      eventCountDelta: b.events.length - a.events.length,
      sameOutcome: a.outcome === b.outcome,
      eventDiffs: eventDiffs
    };
  }

  /**
   * Get aggregate analytics across all (or filtered) sessions.
   * @param {Object} [filters] - Same as querySessions filters
   * @returns {Object} Analytics summary
   */
  function getAnalytics(filters) {
    var target = filters ? querySessions(filters) : querySessions();
    var total = target.length;
    if (total === 0) {
      return {
        totalSessions: 0, outcomes: {}, avgDuration: 0, avgEvents: 0,
        avgInputs: 0, avgChallenges: 0, statusBreakdown: {}, tags: {}
      };
    }

    var outcomes = Object.create(null);
    var statuses = Object.create(null);
    var tagCounts = Object.create(null);
    var totalDuration = 0;
    var totalEvents = 0;
    var totalInputs = 0;
    var totalChallenges = 0;
    var completedCount = 0;

    for (var i = 0; i < target.length; i++) {
      var s = target[i];
      if (s.outcome) outcomes[s.outcome] = (outcomes[s.outcome] || 0) + 1;
      statuses[s.status] = (statuses[s.status] || 0) + 1;
      if (s.duration != null) { totalDuration += s.duration; completedCount++; }
      totalEvents += s.events.length;
      totalInputs += s.inputCount;
      totalChallenges += s.challengeCount;
      for (var j = 0; j < s.tags.length; j++) {
        tagCounts[s.tags[j]] = (tagCounts[s.tags[j]] || 0) + 1;
      }
    }

    return {
      totalSessions: total,
      outcomes: outcomes,
      avgDuration: completedCount > 0 ? Math.round(totalDuration / completedCount) : 0,
      avgEvents: Math.round(totalEvents / total),
      avgInputs: Math.round(totalInputs / total),
      avgChallenges: total > 0 ? +(totalChallenges / total).toFixed(1) : 0,
      statusBreakdown: statuses,
      successRate: outcomes.correct ? +(outcomes.correct / total * 100).toFixed(1) : 0,
      tags: tagCounts
    };
  }

  /**
   * Get a timeline of events across multiple sessions (interleaved by timestamp).
   * @param {string[]} sessionIds
   * @param {number} [limit]
   * @returns {Object[]}
   */
  function mergedTimeline(sessionIds, limit) {
    var allEvents = [];
    for (var i = 0; i < sessionIds.length; i++) {
      var s = sessions[sessionIds[i]];
      if (!s) continue;
      for (var j = 0; j < s.events.length; j++) {
        allEvents.push({
          sessionId: s.id,
          event: s.events[j]
        });
      }
    }
    allEvents.sort(function (a, b) { return a.event.timestamp - b.event.timestamp; });
    if (limit && limit > 0) allEvents = allEvents.slice(0, limit);
    return allEvents;
  }

  /**
   * Export all sessions as serializable state.
   * @returns {Object}
   */
  function exportState() {
    var sessionsArr = [];
    var order = sessionOrder.toArray();
    for (var i = 0; i < order.length; i++) {
      var s = sessions[order[i]];
      if (s) sessionsArr.push(s);
    }
    return {
      sessions: sessionsArr,
      nextId: nextId,
      totalRecorded: totalRecorded,
      totalEvicted: totalEvicted
    };
  }

  /**
   * Import previously exported state.
   * @param {Object} state
   */
  function importState(state) {
    if (!state || !Array.isArray(state.sessions)) return;

    sessions = Object.create(null);
    sessionOrder.clear();
    sessionCount = 0;

    var imported = state.sessions;
    // Respect maxSessions
    var start = imported.length > maxSessions ? imported.length - maxSessions : 0;
    for (var i = start; i < imported.length; i++) {
      var s = imported[i];
      if (s && s.id) {
        sessions[s.id] = s;
        sessionOrder.push(s.id);
        sessionCount++;
      }
    }

    if (typeof state.nextId === "number") nextId = state.nextId;
    if (typeof state.totalRecorded === "number") totalRecorded = state.totalRecorded;
    if (typeof state.totalEvicted === "number") totalEvicted = state.totalEvicted;
  }

  /**
   * Get overall stats.
   * @returns {Object}
   */
  function getStats() {
    return {
      activeSessions: sessionCount,
      totalRecorded: totalRecorded,
      totalEvicted: totalEvicted,
      maxSessions: maxSessions,
      sessionTimeoutMs: sessionTimeoutMs,
      captureInputs: captureInputs
    };
  }

  /**
   * Delete a session.
   * @param {string} sessionId
   * @returns {boolean}
   */
  function deleteSession(sessionId) {
    if (!sessions[sessionId]) return false;
    delete sessions[sessionId];
    sessionOrder.remove(sessionId);
    sessionCount--;
    return true;
  }

  /**
   * Reset all sessions.
   */
  function reset() {
    sessions = Object.create(null);
    sessionOrder.clear();
    sessionCount = 0;
    nextId = 1;
    totalRecorded = 0;
    totalEvicted = 0;
  }

  return {
    startSession: startSession,
    endSession: endSession,
    recordChallenge: recordChallenge,
    recordInput: recordInput,
    recordSubmission: recordSubmission,
    recordResult: recordResult,
    recordSkip: recordSkip,
    recordRefresh: recordRefresh,
    recordError: recordError,
    recordCustom: recordCustom,
    getSession: getSession,
    addTags: addTags,
    querySessions: querySessions,
    createReplay: createReplay,
    compareSessions: compareSessions,
    getAnalytics: getAnalytics,
    mergedTimeline: mergedTimeline,
    exportState: exportState,
    importState: importState,
    getStats: getStats,
    deleteSession: deleteSession,
    reset: reset,
    EVENT_TYPES: EVENT_TYPES
  };
}

// ── Load Tester ─────────────────────────────────────────────────────

/**
 * Create a load tester that stress-tests the CAPTCHA system by simulating
 * concurrent virtual users exercising the full challenge lifecycle.
 *
 * Integrates with:
 * - PoolManager (challenge selection under load)
 * - RateLimiter (per-client throttling under concurrent access)
 * - SessionManager (session creation/cleanup at scale)
 * - BotDetector (behavior analysis with varied profiles)
 * - TokenVerifier (token generation/validation throughput)
 * - ResponseAnalyzer (answer quality metrics under stress)
 *
 * @param {Object} [options]
 * @param {number} [options.concurrency=10] - Number of simulated concurrent users
 * @param {number} [options.requestsPerUser=50] - Requests each user makes
 * @param {number} [options.rampUpMs=1000] - Time to ramp up to full concurrency
 * @param {number} [options.thinkTimeMs=100] - Simulated user think time between actions
 * @param {number} [options.humanRatio=0.8] - Fraction of users simulating human behavior
 * @param {number} [options.timeoutMs=30000] - Max test duration before forced stop
 * @param {Object} [options.challenges] - Custom challenge pool (array)
 * @param {string} [options.tokenSecret] - Secret for token verifier
 * @returns {Object} Load tester instance
 */
function createLoadTester(options) {
  options = options || {};

  var concurrency = Math.floor(_posOpt(options.concurrency, 10));
  var requestsPerUser = Math.floor(_posOpt(options.requestsPerUser, 50));
  var rampUpMs = (typeof options.rampUpMs === "number" && options.rampUpMs >= 0)
    ? options.rampUpMs : 1000;
  var thinkTimeMs = (typeof options.thinkTimeMs === "number" && options.thinkTimeMs >= 0)
    ? options.thinkTimeMs : 100;
  var humanRatio = (typeof options.humanRatio === "number" && options.humanRatio >= 0 && options.humanRatio <= 1)
    ? options.humanRatio : 0.8;
  var timeoutMs = _posOpt(options.timeoutMs, 30000);
  var tokenSecret = options.tokenSecret || "load-test-secret-key-minimum-length";

  // Default challenge pool
  var challengePool = Array.isArray(options.challenges) && options.challenges.length > 0
    ? options.challenges
    : [
        { id: "lt-1", title: "Cat jumping", gifUrl: "https://example.com/cat.gif", humanAnswer: "A cat jumps off a table and lands on the floor" },
        { id: "lt-2", title: "Ball bouncing", gifUrl: "https://example.com/ball.gif", humanAnswer: "A red ball bounces three times on concrete" },
        { id: "lt-3", title: "Dog running", gifUrl: "https://example.com/dog.gif", humanAnswer: "A golden retriever runs across a grassy field" },
        { id: "lt-4", title: "Bird flying", gifUrl: "https://example.com/bird.gif", humanAnswer: "A small bird takes off from a branch and flies away" },
        { id: "lt-5", title: "Water pouring", gifUrl: "https://example.com/water.gif", humanAnswer: "Water is poured from a pitcher into a clear glass" },
      ];

  // Phase tracking
  var PHASE = { IDLE: "idle", RAMPING: "ramping", RUNNING: "running", STOPPING: "stopping", DONE: "done" };
  var phase = PHASE.IDLE;
  var startTime = 0;
  var endTime = 0;
  var stopped = false;

  // Per-user results
  var userResults = [];

  // Aggregate metrics
  var metrics = {
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    rateLimited: 0,
    botDetected: 0,
    tokenVerified: 0,
    tokenRejected: 0,
    responseTimes: [],
    errors: [],
    challengesServed: {},
  };

  // Internal subsystem instances (created fresh per run)
  var pool = null;
  var rateLimiter = null;
  var tokenVerifier = null;
  var botDetector = null;
  var responseAnalyzer = null;
  var submissions = [];  // Collected submissions for response analysis

  /**
   * Initialize subsystems for a fresh test run.
   */
  function _initSubsystems() {
    pool = createPoolManager({ maxServes: requestsPerUser * concurrency, minPoolSize: 2 });
    pool.add(challengePool);

    rateLimiter = createRateLimiter({
      windowMs: 60000,
      maxRequests: Math.max(requestsPerUser, 20),
      burstThreshold: Math.max(Math.floor(requestsPerUser / 5), 5),
      maxClients: concurrency * 2,
    });

    tokenVerifier = createTokenVerifier({ secret: tokenSecret, tokenTtlMs: timeoutMs * 2 });
    botDetector = createBotDetector({ botThreshold: 60 });
    responseAnalyzer = createResponseAnalyzer({ similarityThreshold: 0.3 });
  }

  /**
   * Generate simulated mouse movements for bot detection.
   * Human profiles produce varied, curved movements.
   * Bot profiles produce linear or no movements.
   */
  function _generateMouseMovements(isHuman) {
    if (!isHuman) {
      // Bot: no mouse data or perfectly linear
      return secureRandomInt(2) === 0 ? [] : [
        { x: 0, y: 0, t: 0 },
        { x: 100, y: 100, t: 50 },
        { x: 200, y: 200, t: 100 },
      ];
    }
    // Human: varied movements with direction changes
    var moves = [];
    var count = 5 + secureRandomInt(20);
    var x = secureRandomInt(500);
    var y = secureRandomInt(400);
    var t = 0;
    for (var i = 0; i < count; i++) {
      x += secureRandomInt(100) - 50;
      y += secureRandomInt(80) - 40;
      t += 20 + secureRandomInt(200);
      moves.push({ x: Math.max(0, x), y: Math.max(0, y), t: t });
    }
    return moves;
  }

  /**
   * Generate simulated keystroke timing data.
   */
  function _generateKeystrokeTiming(isHuman, answerLength) {
    var intervals = [];
    for (var i = 0; i < answerLength; i++) {
      if (isHuman) {
        // Human: 50-300ms between keystrokes, with variance
        intervals.push(50 + secureRandomInt(250));
      } else {
        // Bot: very consistent, fast timing
        intervals.push(5 + secureRandomInt(10));
      }
    }
    return intervals;
  }

  /**
   * Simulate a single user's complete CAPTCHA lifecycle.
   * Returns per-user metrics.
   */
  function _simulateUser(userId, isHuman) {
    var userMetrics = {
      userId: userId,
      isHuman: isHuman,
      requests: 0,
      passed: 0,
      failed: 0,
      rateLimited: 0,
      responseTimes: [],
      errors: [],
    };

    var clientId = "load-test-user-" + userId;
    var startTs = Date.now();

    for (var i = 0; i < requestsPerUser; i++) {
      if (stopped) break;

      var reqStart = Date.now();
      metrics.totalRequests++;
      userMetrics.requests++;

      try {
        // Step 1: Rate limit check
        var rateCheck = rateLimiter.check(clientId, { now: reqStart });
        if (!rateCheck.allowed) {
          metrics.rateLimited++;
          userMetrics.rateLimited++;
          var reqEnd = Date.now();
          var elapsed = reqEnd - reqStart;
          metrics.responseTimes.push(elapsed);
          userMetrics.responseTimes.push(elapsed);
          continue;
        }

        // Step 2: Pick a challenge
        var picked = pool.pick(1);
        if (picked.length === 0) {
          metrics.failedRequests++;
          userMetrics.failed++;
          metrics.errors.push({ userId: userId, error: "no_challenges_available", request: i });
          continue;
        }
        var challenge = picked[0];
        metrics.challengesServed[challenge.id] = (metrics.challengesServed[challenge.id] || 0) + 1;

        // Step 3: Issue and verify token
        var issued = tokenVerifier.issueToken({
          sessionId: "lt-session-" + userId + "-" + i,
          score: 0.5,
          difficulty: 1,
          ip: "127.0.0." + userId,
        });
        var tokenResult = tokenVerifier.verifyToken(issued.token, { ip: "127.0.0." + userId });
        if (tokenResult.valid) {
          metrics.tokenVerified++;
        } else {
          metrics.tokenRejected++;
        }

        // Step 4: Bot detection
        var movements = _generateMouseMovements(isHuman);
        var timeOnPage = isHuman ? (3000 + secureRandomInt(10000)) : (500 + secureRandomInt(1000));
        var keystrokes = _generateKeystrokeTiming(isHuman, 30);

        var botResult = botDetector.analyze({
          mouseMovements: movements,
          timeOnPageMs: timeOnPage,
          keystrokeTimings: keystrokes,
        });

        if (botResult.verdict === "bot") {
          metrics.botDetected++;
        }

        // Step 5: Simulate answer
        var answer;
        if (isHuman) {
          // Human: give a somewhat relevant answer (50-90% similarity)
          var words = challenge.humanAnswer.split(/\s+/);
          var useWords = Math.max(2, Math.floor(words.length * (0.5 + Math.random() * 0.4)));
          answer = words.slice(0, useWords).join(" ");
        } else {
          // Bot: random gibberish or exact copy
          if (secureRandomInt(3) === 0) {
            answer = challenge.humanAnswer; // exact copy (suspicious)
          } else {
            answer = "random answer " + secureRandomInt(10000);
          }
        }

        // Step 6: Validate answer
        var validation = validateAnswer(answer, challenge.humanAnswer, { threshold: 0.3 });
        if (validation.passed) {
          metrics.successfulRequests++;
          userMetrics.passed++;
          pool.recordResult(challenge.id, true);
        } else {
          metrics.failedRequests++;
          userMetrics.failed++;
          pool.recordResult(challenge.id, false);
        }

        // Step 7: Collect submission for analysis
        submissions.push({
          timeMs: timeOnPage,
          response: answer,
        });

        var reqEnd2 = Date.now();
        var elapsed2 = reqEnd2 - reqStart;
        metrics.responseTimes.push(elapsed2);
        userMetrics.responseTimes.push(elapsed2);

      } catch (err) {
        metrics.failedRequests++;
        userMetrics.failed++;
        userMetrics.errors.push({ request: i, error: String(err.message || err) });
        metrics.errors.push({ userId: userId, request: i, error: String(err.message || err) });
      }
    }

    userMetrics.totalTimeMs = Date.now() - startTs;
    return userMetrics;
  }

  /**
   * Calculate percentile from a sorted array of numbers.
   */
  function _percentile(sorted, p) {
    if (sorted.length === 0) return 0;
    var idx = Math.ceil(p / 100 * sorted.length) - 1;
    return sorted[_clamp(idx, 0, sorted.length - 1)];
  }

  /**
   * Run the load test synchronously.
   * Simulates concurrent users sequentially (no true parallelism in
   * single-threaded JS, but exercises all subsystems at scale).
   *
   * @returns {Object} Complete test results with per-user and aggregate metrics
   */
  function run() {
    if (phase !== PHASE.IDLE && phase !== PHASE.DONE) {
      return { error: "Test already running", phase: phase };
    }

    // Reset state
    phase = PHASE.RAMPING;
    stopped = false;
    startTime = Date.now();
    userResults = [];
    metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      rateLimited: 0,
      botDetected: 0,
      tokenVerified: 0,
      tokenRejected: 0,
      responseTimes: [],
      errors: [],
      challengesServed: {},
    };

    _initSubsystems();

    // Determine user profiles
    var humanCount = Math.round(concurrency * humanRatio);
    var botCount = concurrency - humanCount;

    phase = PHASE.RUNNING;

    // Simulate each user
    for (var i = 0; i < concurrency; i++) {
      if (stopped) break;
      var isHuman = i < humanCount;
      var result = _simulateUser(i + 1, isHuman);
      userResults.push(result);
    }

    endTime = Date.now();
    phase = PHASE.DONE;

    return _buildReport();
  }

  /**
   * Stop a running test early.
   */
  function stop() {
    stopped = true;
    phase = PHASE.STOPPING;
  }

  /**
   * Build the final test report with aggregate statistics.
   */
  function _buildReport() {
    var duration = endTime - startTime;
    var sortedTimes = metrics.responseTimes.slice().sort(_numAsc);

    var avgTime = sortedTimes.length > 0
      ? sortedTimes.reduce(function (s, v) { return s + v; }, 0) / sortedTimes.length
      : 0;

    // Calculate throughput
    var throughput = duration > 0 ? (metrics.totalRequests / (duration / 1000)) : 0;

    // Challenge distribution analysis
    var challengeIds = Object.keys(metrics.challengesServed);
    var serveValues = challengeIds.map(function (id) { return metrics.challengesServed[id]; });
    var minServes = serveValues.length > 0 ? Math.min.apply(null, serveValues) : 0;
    var maxServes = serveValues.length > 0 ? Math.max.apply(null, serveValues) : 0;
    var avgServes = serveValues.length > 0
      ? serveValues.reduce(function (s, v) { return s + v; }, 0) / serveValues.length : 0;

    // Pool stats
    var poolStats = pool ? pool.getSummary() : null;

    // Response analyzer report
    var analyzerReport = null;
    try {
      analyzerReport = responseAnalyzer ? responseAnalyzer.scoreSubmissions(submissions) : null;
    } catch (e) {
      analyzerReport = { error: String(e.message || e) };
    }

    // Per-user summaries
    var userSummaries = userResults.map(function (u) {
      var uSorted = u.responseTimes.slice().sort(_numAsc);
      return {
        userId: u.userId,
        isHuman: u.isHuman,
        requests: u.requests,
        passed: u.passed,
        failed: u.failed,
        rateLimited: u.rateLimited,
        passRate: u.requests > 0 ? u.passed / u.requests : 0,
        avgResponseMs: uSorted.length > 0
          ? uSorted.reduce(function (s, v) { return s + v; }, 0) / uSorted.length : 0,
        p50ResponseMs: _percentile(uSorted, 50),
        p95ResponseMs: _percentile(uSorted, 95),
        p99ResponseMs: _percentile(uSorted, 99),
        totalTimeMs: u.totalTimeMs,
        errorCount: u.errors.length,
      };
    });

    // Separate human vs bot stats
    var humanUsers = userSummaries.filter(function (u) { return u.isHuman; });
    var botUsers = userSummaries.filter(function (u) { return !u.isHuman; });

    var humanPassRate = humanUsers.length > 0
      ? humanUsers.reduce(function (s, u) { return s + u.passRate; }, 0) / humanUsers.length : 0;
    var botPassRate = botUsers.length > 0
      ? botUsers.reduce(function (s, u) { return s + u.passRate; }, 0) / botUsers.length : 0;

    return {
      summary: {
        phase: phase,
        concurrency: concurrency,
        requestsPerUser: requestsPerUser,
        totalRequests: metrics.totalRequests,
        successfulRequests: metrics.successfulRequests,
        failedRequests: metrics.failedRequests,
        rateLimited: metrics.rateLimited,
        botDetected: metrics.botDetected,
        tokenVerified: metrics.tokenVerified,
        tokenRejected: metrics.tokenRejected,
        durationMs: duration,
        throughputRps: Math.round(throughput * 100) / 100,
        errorCount: metrics.errors.length,
      },
      latency: {
        avgMs: Math.round(avgTime * 100) / 100,
        p50Ms: _percentile(sortedTimes, 50),
        p95Ms: _percentile(sortedTimes, 95),
        p99Ms: _percentile(sortedTimes, 99),
        minMs: sortedTimes.length > 0 ? sortedTimes[0] : 0,
        maxMs: sortedTimes.length > 0 ? sortedTimes[sortedTimes.length - 1] : 0,
      },
      challengeDistribution: {
        totalChallenges: challengeIds.length,
        minServes: minServes,
        maxServes: maxServes,
        avgServes: Math.round(avgServes * 100) / 100,
        distribution: metrics.challengesServed,
      },
      userBreakdown: {
        humanCount: humanUsers.length,
        botCount: botUsers.length,
        humanPassRate: Math.round(humanPassRate * 10000) / 10000,
        botPassRate: Math.round(botPassRate * 10000) / 10000,
      },
      poolStats: poolStats,
      analyzerReport: analyzerReport,
      users: userSummaries,
      errors: metrics.errors.slice(0, 100), // cap at 100 for readability
    };
  }

  /**
   * Get current test configuration.
   */
  function getConfig() {
    return {
      concurrency: concurrency,
      requestsPerUser: requestsPerUser,
      rampUpMs: rampUpMs,
      thinkTimeMs: thinkTimeMs,
      humanRatio: humanRatio,
      timeoutMs: timeoutMs,
      challengeCount: challengePool.length,
      phase: phase,
    };
  }

  /**
   * Get current phase.
   */
  function getPhase() {
    return phase;
  }

  /**
   * Reset for another run.
   */
  function reset() {
    phase = PHASE.IDLE;
    stopped = false;
    startTime = 0;
    endTime = 0;
    userResults = [];
    metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      rateLimited: 0,
      botDetected: 0,
      tokenVerified: 0,
      tokenRejected: 0,
      responseTimes: [],
      errors: [],
      challengesServed: {},
    };
    pool = null;
    rateLimiter = null;
    tokenVerifier = null;
    botDetector = null;
    responseAnalyzer = null;
    submissions = [];
  }

  return {
    run: run,
    stop: stop,
    reset: reset,
    getConfig: getConfig,
    getPhase: getPhase,
    PHASE: PHASE,
  };
}

// ── A/B Experiment Runner ────────────────────────────────────────────

/**
 * Factory: create an A/B experiment runner for CAPTCHA configurations.
 *
 * Supports full experiment lifecycle: create experiments with named variants,
 * deterministically assign users via hashing, track solve/fail/abandon events,
 * compute statistical significance (chi-squared + z-test for proportions),
 * detect winners, and support early stopping.
 *
 * @param {Object} [options]
 * @param {number} [options.maxExperiments=50] - Maximum concurrent experiments
 * @param {number} [options.significanceLevel=0.05] - P-value threshold for significance
 * @param {number} [options.minSampleSize=30] - Minimum observations per variant before analysis
 * @param {boolean} [options.earlyStoppingEnabled=true] - Allow early stopping when significance reached
 * @param {number} [options.earlyStoppingConfidence=0.01] - Stricter p-value for early stop
 * @returns {Object} A/B experiment runner API
 *
 * @example
 *   var runner = gifCaptcha.createABExperimentRunner();
 *   runner.createExperiment('diff-test', {
 *     control: { difficulty: 'easy', theme: 'default' },
 *     variants: [
 *       { name: 'hard-dark', config: { difficulty: 'hard', theme: 'dark' } },
 *     ],
 *     targetSampleSize: 200,
 *   });
 *   var variant = runner.assignUser('diff-test', 'user-123');
 *   runner.recordEvent('diff-test', 'user-123', 'solve', { timeMs: 3200 });
 *   var results = runner.analyzeExperiment('diff-test');
 */
function createABExperimentRunner(options) {
  options = options || {};
  var maxExperiments = options.maxExperiments > 0 ? options.maxExperiments : 50;
  var defaultSignificance = typeof options.significanceLevel === 'number' ? options.significanceLevel : 0.05;
  var defaultMinSample = options.minSampleSize > 0 ? options.minSampleSize : 30;
  var earlyStoppingEnabled = options.earlyStoppingEnabled !== false;
  var earlyStoppingConfidence = typeof options.earlyStoppingConfidence === 'number' ? options.earlyStoppingConfidence : 0.01;

  var experiments = {};
  var experimentOrder = new LruTracker();
  var onResultCallbacks = [];

  // ── Helpers ──

  /** djb2 hash for deterministic variant assignment */
  function djb2(str) {
    var hash = 5381;
    for (var i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0x7FFFFFFF;
    }
    return hash;
  }

  /** Approximation of standard normal CDF (Abramowitz & Stegun 26.2.17) */
  function normalCdf(x) {
    if (x < -8) return 0;
    if (x > 8) return 1;
    var sign = x < 0 ? -1 : 1;
    x = Math.abs(x);
    var t = 1 / (1 + 0.2316419 * x);
    var d = 0.3989422804014327; // 1/sqrt(2*pi)
    var prob = d * Math.exp(-0.5 * x * x) *
      (t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429)))));
    return sign < 0 ? prob : 1 - prob;
  }

  /** Two-tailed z-test p-value for difference in proportions */
  function proportionZTest(n1, s1, n2, s2) {
    if (n1 === 0 || n2 === 0) return { z: 0, pValue: 1 };
    var p1 = s1 / n1;
    var p2 = s2 / n2;
    var pPool = (s1 + s2) / (n1 + n2);
    if (pPool === 0 || pPool === 1) return { z: 0, pValue: 1 };
    var se = Math.sqrt(pPool * (1 - pPool) * (1 / n1 + 1 / n2));
    if (se === 0) return { z: 0, pValue: 1 };
    var z = (p1 - p2) / se;
    var pValue = 2 * (1 - normalCdf(Math.abs(z)));
    return { z: z, pValue: pValue };
  }

  /** Chi-squared test for k variants (Pearson's goodness-of-fit) */
  function chiSquaredTest(variants) {
    var totalSolves = 0;
    var totalAttempts = 0;
    for (var i = 0; i < variants.length; i++) {
      totalSolves += variants[i].solves;
      totalAttempts += variants[i].attempts;
    }
    if (totalAttempts === 0) return { chiSq: 0, df: 0, pValue: 1 };
    var expectedRate = totalSolves / totalAttempts;
    var chiSq = 0;
    for (var j = 0; j < variants.length; j++) {
      var n = variants[j].attempts;
      if (n === 0) continue;
      var expectedSolves = n * expectedRate;
      var expectedFails = n * (1 - expectedRate);
      if (expectedSolves > 0) {
        var dS = variants[j].solves - expectedSolves;
        chiSq += (dS * dS) / expectedSolves;
      }
      var fails = n - variants[j].solves;
      if (expectedFails > 0) {
        var dF = fails - expectedFails;
        chiSq += (dF * dF) / expectedFails;
      }
    }
    var df = variants.length - 1;
    // Approximate chi-squared p-value using Wilson-Hilferty
    var pValue = 1;
    if (df > 0 && chiSq > 0) {
      var k = df;
      var z2 = Math.pow(chiSq / k, 1 / 3) - (1 - 2 / (9 * k));
      z2 = z2 / Math.sqrt(2 / (9 * k));
      pValue = 1 - normalCdf(z2);
    }
    return { chiSq: chiSq, df: df, pValue: pValue };
  }

  /** Compute per-variant stats */
  function computeVariantStats(variantData) {
    var completedAttempts = variantData.solves + variantData.fails;
    var totalAttempts = completedAttempts + variantData.abandons;
    var solveRate = completedAttempts > 0 ? variantData.solves / completedAttempts : 0;
    var times = variantData.solveTimes;
    var avgTime = _mean(times);
    var medianTime = _median(times);
    var p95Time = 0;
    if (times.length > 0) {
      var sorted = times.slice().sort(_numAsc);
      p95Time = sorted[Math.floor(sorted.length * 0.95)];
    }
    return {
      name: variantData.name,
      config: variantData.config,
      attempts: completedAttempts,
      totalAttempts: totalAttempts,
      solves: variantData.solves,
      fails: variantData.fails,
      abandons: variantData.abandons,
      solveRate: solveRate,
      avgSolveTimeMs: Math.round(avgTime),
      medianSolveTimeMs: Math.round(medianTime),
      p95SolveTimeMs: Math.round(p95Time),
      abandonRate: totalAttempts > 0 ? variantData.abandons / totalAttempts : 0,
    };
  }

  // ── Core API ──

  /**
   * Create a new experiment.
   * @param {string} experimentId - Unique experiment identifier
   * @param {Object} spec
   * @param {Object} spec.control - Control config
   * @param {Object[]} spec.variants - Array of { name: string, config: Object }
   * @param {number} [spec.targetSampleSize=100] - Target observations per variant
   * @param {string} [spec.description] - Human-readable description
   * @returns {Object} Created experiment summary
   */
  function createExperiment(experimentId, spec) {
    if (!experimentId || typeof experimentId !== 'string') {
      throw new Error('experimentId must be a non-empty string');
    }
    if (experiments[experimentId]) {
      throw new Error('Experiment already exists: ' + experimentId);
    }
    if (experimentOrder.length >= maxExperiments) {
      throw new Error('Maximum experiments reached (' + maxExperiments + ')');
    }
    if (!spec || !spec.control) {
      throw new Error('spec.control is required');
    }
    if (!spec.variants || !Array.isArray(spec.variants) || spec.variants.length === 0) {
      throw new Error('spec.variants must be a non-empty array');
    }
    // Validate variant names are unique
    var names = { control: true };
    for (var i = 0; i < spec.variants.length; i++) {
      var v = spec.variants[i];
      if (!v.name || typeof v.name !== 'string') {
        throw new Error('Each variant must have a name string');
      }
      if (names[v.name]) {
        throw new Error('Duplicate variant name: ' + v.name);
      }
      names[v.name] = true;
    }

    var allVariants = [{ name: 'control', config: spec.control }];
    for (var j = 0; j < spec.variants.length; j++) {
      allVariants.push({ name: spec.variants[j].name, config: spec.variants[j].config || {} });
    }

    var variantData = {};
    for (var k = 0; k < allVariants.length; k++) {
      variantData[allVariants[k].name] = {
        name: allVariants[k].name,
        config: allVariants[k].config,
        solves: 0,
        fails: 0,
        abandons: 0,
        solveTimes: [],
        users: {},
      };
    }

    experiments[experimentId] = {
      id: experimentId,
      description: spec.description || '',
      status: 'running',
      createdAt: Date.now(),
      endedAt: null,
      targetSampleSize: spec.targetSampleSize > 0 ? spec.targetSampleSize : 100,
      variantNames: allVariants.map(function (v) { return v.name; }),
      variants: variantData,
      winner: null,
      userAssignments: {},
    };
    experimentOrder.push(experimentId);

    return { id: experimentId, variants: allVariants.length, status: 'running' };
  }

  /**
   * Deterministically assign a user to a variant.
   * Subsequent calls with the same experimentId + userId return the same variant.
   * @param {string} experimentId
   * @param {string} userId
   * @returns {{ variant: string, config: Object }}
   */
  function assignUser(experimentId, userId) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    if (!userId || typeof userId !== 'string') throw new Error('userId must be a non-empty string');

    // Check existing assignment
    if (exp.userAssignments[userId]) {
      var assignedName = exp.userAssignments[userId];
      return { variant: assignedName, config: exp.variants[assignedName].config };
    }

    // Deterministic hash-based assignment
    var hash = djb2(experimentId + ':' + userId);
    var idx = hash % exp.variantNames.length;
    var variantName = exp.variantNames[idx];
    exp.userAssignments[userId] = variantName;

    return { variant: variantName, config: exp.variants[variantName].config };
  }

  /**
   * Record an event (solve, fail, abandon) for a user in an experiment.
   * @param {string} experimentId
   * @param {string} userId
   * @param {string} eventType - 'solve' | 'fail' | 'abandon'
   * @param {Object} [data]
   * @param {number} [data.timeMs] - Solve time in milliseconds (for 'solve' events)
   */
  function recordEvent(experimentId, userId, eventType, data) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    if (exp.status !== 'running') return; // Silently ignore if stopped

    // Auto-assign if not already
    var assignment = assignUser(experimentId, userId);
    var variant = exp.variants[assignment.variant];
    data = data || {};

    switch (eventType) {
      case 'solve':
        variant.solves++;
        if (typeof data.timeMs === 'number' && data.timeMs > 0) {
          variant.solveTimes.push(data.timeMs);
        }
        break;
      case 'fail':
        variant.fails++;
        break;
      case 'abandon':
        variant.abandons++;
        break;
      default:
        throw new Error('Unknown event type: ' + eventType + '. Expected solve/fail/abandon');
    }

    // Track per-user events
    if (!variant.users[userId]) variant.users[userId] = [];
    variant.users[userId].push({ type: eventType, time: Date.now(), data: data });

    // Check early stopping
    if (earlyStoppingEnabled && exp.status === 'running') {
      var ready = true;
      for (var i = 0; i < exp.variantNames.length; i++) {
        var vd = exp.variants[exp.variantNames[i]];
        if (vd.solves + vd.fails + vd.abandons < defaultMinSample) {
          ready = false;
          break;
        }
      }
      if (ready) {
        var analysis = _analyzeInternal(exp);
        if (analysis.significant && analysis.pValue <= earlyStoppingConfidence) {
          exp.status = 'completed';
          exp.endedAt = Date.now();
          exp.winner = analysis.winner;
          _fireCallbacks(experimentId, analysis);
        }
      }
    }
  }

  /**
   * Analyze an experiment's results.
   * @param {string} experimentId
   * @returns {Object} Analysis results with statistics
   */
  function analyzeExperiment(experimentId) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    return _analyzeInternal(exp);
  }

  function _analyzeInternal(exp) {
    var variantStats = [];
    var chiVariants = [];
    for (var i = 0; i < exp.variantNames.length; i++) {
      var name = exp.variantNames[i];
      var vd = exp.variants[name];
      var stats = computeVariantStats(vd);
      variantStats.push(stats);
      chiVariants.push({ solves: vd.solves, attempts: stats.attempts });
    }

    // Chi-squared across all variants
    var chiResult = chiSquaredTest(chiVariants);

    // Pairwise z-tests: each variant vs control
    var controlData = exp.variants['control'];
    var controlAttempts = controlData.solves + controlData.fails;
    var pairwise = [];
    for (var j = 1; j < exp.variantNames.length; j++) {
      var vName = exp.variantNames[j];
      var vData = exp.variants[vName];
      var vAttempts = vData.solves + vData.fails;
      var zResult = proportionZTest(controlAttempts, controlData.solves, vAttempts, vData.solves);
      var controlRate = controlAttempts > 0 ? controlData.solves / controlAttempts : 0;
      var variantRate = vAttempts > 0 ? vData.solves / vAttempts : 0;
      var lift = controlRate > 0 ? ((variantRate - controlRate) / controlRate) * 100 : 0;
      pairwise.push({
        variant: vName,
        vsControl: {
          z: Math.round(zResult.z * 1000) / 1000,
          pValue: zResult.pValue,
          significant: zResult.pValue < defaultSignificance,
          lift: Math.round(lift * 100) / 100,
        },
      });
    }

    // Determine winner
    var winner = null;
    var bestRate = -1;
    var significant = chiResult.pValue < defaultSignificance;

    var sufficientData = true;
    for (var m = 0; m < variantStats.length; m++) {
      if (variantStats[m].attempts < defaultMinSample) {
        sufficientData = false;
        break;
      }
    }

    if (sufficientData && significant) {
      for (var k = 0; k < variantStats.length; k++) {
        if (variantStats[k].solveRate > bestRate) {
          bestRate = variantStats[k].solveRate;
          winner = variantStats[k].name;
        }
      }
    }

    return {
      experimentId: exp.id,
      status: exp.status,
      variants: variantStats,
      chiSquared: {
        value: Math.round(chiResult.chiSq * 1000) / 1000,
        df: chiResult.df,
        pValue: chiResult.pValue,
      },
      pairwiseTests: pairwise,
      significant: significant,
      pValue: chiResult.pValue,
      sufficientData: sufficientData,
      winner: winner,
      recommendation: _getRecommendation(winner, significant, sufficientData, variantStats),
    };
  }

  function _getRecommendation(winner, significant, sufficientData, variantStats) {
    if (!sufficientData) {
      var current = Infinity;
      for (var i = 0; i < variantStats.length; i++) {
        if (variantStats[i].attempts < current) current = variantStats[i].attempts;
      }
      return 'Insufficient data. Minimum ' + defaultMinSample + ' attempts per variant needed (lowest: ' + current + ').';
    }
    if (!significant) {
      return 'No statistically significant difference detected. Continue collecting data or accept null hypothesis.';
    }
    if (winner === 'control') {
      return 'Control performs best. No change recommended.';
    }
    return 'Variant "' + winner + '" is the winner. Consider adopting its configuration.';
  }

  /**
   * Stop an experiment manually.
   * @param {string} experimentId
   * @returns {Object} Final analysis
   */
  function stopExperiment(experimentId) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    exp.status = 'stopped';
    exp.endedAt = Date.now();
    var analysis = _analyzeInternal(exp);
    exp.winner = analysis.winner;
    return analysis;
  }

  /**
   * Get experiment info.
   * @param {string} experimentId
   * @returns {Object|null}
   */
  function getExperiment(experimentId) {
    var exp = experiments[experimentId];
    if (!exp) return null;
    return {
      id: exp.id,
      description: exp.description,
      status: exp.status,
      createdAt: exp.createdAt,
      endedAt: exp.endedAt,
      variantNames: exp.variantNames.slice(),
      targetSampleSize: exp.targetSampleSize,
      winner: exp.winner,
      totalUsers: Object.keys(exp.userAssignments).length,
    };
  }

  /**
   * List all experiments.
   * @param {Object} [filters]
   * @param {string} [filters.status] - Filter by status (running/stopped/completed)
   * @returns {Object[]}
   */
  function listExperiments(filters) {
    filters = filters || {};
    var results = [];
    var order = experimentOrder.toArray();
    for (var i = 0; i < order.length; i++) {
      var exp = experiments[order[i]];
      if (!exp) continue;
      if (filters.status && exp.status !== filters.status) continue;
      results.push(getExperiment(exp.id));
    }
    return results;
  }

  /**
   * Delete an experiment.
   * @param {string} experimentId
   * @returns {boolean} True if deleted
   */
  function deleteExperiment(experimentId) {
    if (!experiments[experimentId]) return false;
    delete experiments[experimentId];
    experimentOrder.remove(experimentId);
    return true;
  }

  /**
   * Get variant assignment counts for an experiment.
   * @param {string} experimentId
   * @returns {Object} Map of variant name to user count
   */
  function getAssignmentCounts(experimentId) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    var counts = {};
    for (var i = 0; i < exp.variantNames.length; i++) {
      counts[exp.variantNames[i]] = 0;
    }
    var keys = Object.keys(exp.userAssignments);
    for (var j = 0; j < keys.length; j++) {
      var v2 = exp.userAssignments[keys[j]];
      counts[v2] = (counts[v2] || 0) + 1;
    }
    return counts;
  }

  /**
   * Register a callback for experiment completion (via early stopping).
   * @param {Function} fn - Called with (experimentId, analysis)
   */
  function onResult(fn) {
    if (typeof fn === 'function') onResultCallbacks.push(fn);
  }

  function _fireCallbacks(experimentId, analysis) {
    for (var i = 0; i < onResultCallbacks.length; i++) {
      try { onResultCallbacks[i](experimentId, analysis); } catch (e) { /* ignore */ }
    }
  }

  /**
   * Export all experiment data as JSON-serializable object.
   * @returns {Object}
   */
  function exportState() {
    var data = [];
    var order = experimentOrder.toArray();
    for (var i = 0; i < order.length; i++) {
      var exp = experiments[order[i]];
      if (!exp) continue;
      var variantExport = {};
      for (var j = 0; j < exp.variantNames.length; j++) {
        var name = exp.variantNames[j];
        var vd = exp.variants[name];
        variantExport[name] = {
          name: vd.name,
          config: vd.config,
          solves: vd.solves,
          fails: vd.fails,
          abandons: vd.abandons,
          solveTimes: vd.solveTimes.slice(),
        };
      }
      data.push({
        id: exp.id,
        description: exp.description,
        status: exp.status,
        createdAt: exp.createdAt,
        endedAt: exp.endedAt,
        targetSampleSize: exp.targetSampleSize,
        variantNames: exp.variantNames.slice(),
        variants: variantExport,
        winner: exp.winner,
      });
    }
    return { experiments: data, exportedAt: Date.now() };
  }

  /**
   * Import experiment data from a previous export.
   * @param {Object} state - Data from exportState()
   * @returns {number} Number of experiments imported
   */
  function importState(state) {
    if (!state || !Array.isArray(state.experiments)) return 0;
    var imported = 0;
    for (var i = 0; i < state.experiments.length; i++) {
      var e = state.experiments[i];
      if (!e.id || experiments[e.id]) continue;
      if (experimentOrder.length >= maxExperiments) break;

      var variantData = {};
      for (var j = 0; j < e.variantNames.length; j++) {
        var name = e.variantNames[j];
        var src = (e.variants && e.variants[name]) || {};
        variantData[name] = {
          name: name,
          config: src.config || {},
          solves: src.solves || 0,
          fails: src.fails || 0,
          abandons: src.abandons || 0,
          solveTimes: Array.isArray(src.solveTimes) ? src.solveTimes.slice() : [],
          users: {},
        };
      }

      experiments[e.id] = {
        id: e.id,
        description: e.description || '',
        status: e.status || 'stopped',
        createdAt: e.createdAt || Date.now(),
        endedAt: e.endedAt || null,
        targetSampleSize: e.targetSampleSize || 100,
        variantNames: e.variantNames.slice(),
        variants: variantData,
        winner: e.winner || null,
        userAssignments: {},
      };
      experimentOrder.push(e.id);
      imported++;
    }
    return imported;
  }

  /**
   * Generate a text summary of an experiment's results.
   * @param {string} experimentId
   * @returns {string}
   */
  function textReport(experimentId) {
    var analysis = analyzeExperiment(experimentId);
    var exp = experiments[experimentId];
    var lines = [];
    lines.push('A/B Experiment: ' + analysis.experimentId);
    if (exp.description) lines.push('Description: ' + exp.description);
    lines.push('Status: ' + analysis.status);
    lines.push('');
    lines.push('Variants:');
    for (var i = 0; i < analysis.variants.length; i++) {
      var v = analysis.variants[i];
      lines.push('  ' + v.name + ':');
      lines.push('    Attempts: ' + v.attempts);
      lines.push('    Solve rate: ' + (v.solveRate * 100).toFixed(1) + '%');
      lines.push('    Abandon rate: ' + (v.abandonRate * 100).toFixed(1) + '%');
      if (v.avgSolveTimeMs > 0) {
        lines.push('    Avg solve time: ' + v.avgSolveTimeMs + 'ms');
        lines.push('    Median solve time: ' + v.medianSolveTimeMs + 'ms');
        lines.push('    P95 solve time: ' + v.p95SolveTimeMs + 'ms');
      }
    }
    lines.push('');
    lines.push('Chi-squared: ' + analysis.chiSquared.value + ' (df=' + analysis.chiSquared.df + ', p=' + analysis.pValue.toFixed(4) + ')');
    lines.push('Significant: ' + (analysis.significant ? 'Yes' : 'No'));
    if (analysis.pairwiseTests.length > 0) {
      lines.push('');
      lines.push('Pairwise vs Control:');
      for (var j = 0; j < analysis.pairwiseTests.length; j++) {
        var pw = analysis.pairwiseTests[j];
        lines.push('  ' + pw.variant + ': z=' + pw.vsControl.z + ', p=' + pw.vsControl.pValue.toFixed(4) +
          ', lift=' + pw.vsControl.lift + '%' +
          (pw.vsControl.significant ? ' *' : ''));
      }
    }
    lines.push('');
    lines.push('Winner: ' + (analysis.winner || 'None'));
    lines.push('Recommendation: ' + analysis.recommendation);
    return lines.join('\n');
  }

  return {
    createExperiment: createExperiment,
    assignUser: assignUser,
    recordEvent: recordEvent,
    analyzeExperiment: analyzeExperiment,
    stopExperiment: stopExperiment,
    getExperiment: getExperiment,
    listExperiments: listExperiments,
    deleteExperiment: deleteExperiment,
    getAssignmentCounts: getAssignmentCounts,
    onResult: onResult,
    exportState: exportState,
    importState: importState,
    textReport: textReport,
  };
}

// ─── Fraud Ring Detector ──────────────────────────────────────────────────────

/**
 * createFraudRingDetector — identifies coordinated CAPTCHA-solving operations
 * by analyzing cross-client behavioral patterns.
 *
 * Detects fraud rings through:
 * - Timing cluster analysis (clients solving within narrow windows)
 * - Shared fingerprint/signal detection
 * - IP proximity clustering
 * - Sequential solve pattern matching
 * - Graph-based ring detection (union-find)
 *
 * @param {Object} [options]
 * @param {number} [options.maxClients=5000] - Max tracked clients (LRU eviction)
 * @param {number} [options.timingWindowMs=5000] - Window for timing cluster detection
 * @param {number} [options.minRingSize=3] - Minimum clients to form a ring
 * @param {number} [options.suspicionThreshold=60] - Score threshold (0-100) for ring flagging
 * @param {number} [options.signalDecayMs=3600000] - Signal decay time (1 hour default)
 * @param {number} [options.maxRings=200] - Maximum tracked rings
 * @returns {Object} fraud ring detector instance
 */
function createFraudRingDetector(options) {
  options = options || {};
  var maxClients = options.maxClients > 0 ? options.maxClients : 5000;
  var timingWindowMs = options.timingWindowMs > 0 ? options.timingWindowMs : 5000;
  var minRingSize = options.minRingSize > 0 ? options.minRingSize : 3;
  var suspicionThreshold = typeof options.suspicionThreshold === 'number' ? options.suspicionThreshold : 60;
  var signalDecayMs = options.signalDecayMs > 0 ? options.signalDecayMs : 3600000;
  var maxRings = options.maxRings > 0 ? options.maxRings : 200;

  var clients = {};
  var clientOrder = new LruTracker();
  var rings = {};
  var ringCounter = 0;
  var onRingCallbacks = [];
  var parent = {};
  var rank = {};

  function ufFind(x) {
    if (parent[x] === undefined) { parent[x] = x; rank[x] = 0; }
    if (parent[x] !== x) parent[x] = ufFind(parent[x]);
    return parent[x];
  }

  function ufUnion(a, b) {
    var ra = ufFind(a), rb = ufFind(b);
    if (ra === rb) return;
    if (rank[ra] < rank[rb]) { parent[ra] = rb; }
    else if (rank[ra] > rank[rb]) { parent[rb] = ra; }
    else { parent[rb] = ra; rank[ra]++; }
  }

  function getClient(clientId) {
    if (!clients[clientId]) {
      if (clientOrder.length >= maxClients) {
        var evicted = clientOrder.evictOldest();
        if (evicted !== undefined) {
          delete clients[evicted];
          delete parent[evicted];
          delete rank[evicted];
        }
      }
      clients[clientId] = {
        id: clientId, events: [], fingerprints: [], ips: [], userAgents: [],
        _ipSet: {}, _fpSet: {}, _uaSet: {},
        solveCount: 0, failCount: 0, firstSeen: Date.now(), lastSeen: Date.now(), ringId: null
      };
      clientOrder.push(clientId);
    } else {
      clientOrder.touch(clientId);
    }
    return clients[clientId];
  }

  function recordEvent(event) {
    if (!event || !event.clientId || !event.type) return null;
    var client = getClient(event.clientId);
    var ts = event.timestamp || Date.now();
    var record = {
      clientId: event.clientId, type: event.type, timestamp: ts,
      ip: event.ip || null, fingerprint: event.fingerprint || null,
      userAgent: event.userAgent || null, responseTimeMs: event.responseTimeMs || null,
      challengeId: event.challengeId || null
    };
    client.events.push(record);
    client.lastSeen = ts;
    if (event.type === 'solve') client.solveCount++;
    if (event.type === 'fail') client.failCount++;
    if (event.ip && !client._ipSet[event.ip]) { client._ipSet[event.ip] = true; client.ips.push(event.ip); }
    if (event.fingerprint && !client._fpSet[event.fingerprint]) { client._fpSet[event.fingerprint] = true; client.fingerprints.push(event.fingerprint); }
    if (event.userAgent && !client._uaSet[event.userAgent]) { client._uaSet[event.userAgent] = true; client.userAgents.push(event.userAgent); }
    if (client.events.length > 200) client.events = client.events.slice(-200);
    return record;
  }

  function findTimingClusters() {
    var solves = [];
    var ids = Object.keys(clients);
    for (var i = 0; i < ids.length; i++) {
      var c = clients[ids[i]];
      for (var j = 0; j < c.events.length; j++) {
        if (c.events[j].type === 'solve') solves.push({ clientId: ids[i], timestamp: c.events[j].timestamp });
      }
    }
    solves.sort(function(a, b) { return a.timestamp - b.timestamp; });
    var clusters = [], current = [], currentSet = Object.create(null);
    for (var k = 0; k < solves.length; k++) {
      if (current.length === 0) { current.push(solves[k]); currentSet[solves[k].clientId] = true; continue; }
      if (solves[k].timestamp - current[0].timestamp <= timingWindowMs) {
        if (!currentSet[solves[k].clientId]) { current.push(solves[k]); currentSet[solves[k].clientId] = true; }
      } else {
        if (current.length >= minRingSize) clusters.push(current.slice());
        current = [solves[k]];
        currentSet = Object.create(null);
        currentSet[solves[k].clientId] = true;
      }
    }
    if (current.length >= minRingSize) clusters.push(current);
    return clusters;
  }

  /**
   * Build a map of key → list of distinct client IDs that share that key.
   * Reused by findSharedFingerprints and findIPClusters to avoid code duplication.
   * Uses a parallel set-of-sets for O(1) deduplication instead of O(n) indexOf
   * per client — reduces from O(n*m) to O(n+m) for n clients with m keys each.
   * @param {string} prop – client property to group by ('fingerprints' | 'ips')
   * @returns {Object.<string, string[]>}
   */
  function _buildGroupMap(prop) {
    var map = {};
    var seen = {};
    var ids = Object.keys(clients);
    for (var i = 0; i < ids.length; i++) {
      var cid = ids[i];
      var arr = clients[cid][prop];
      for (var j = 0; j < arr.length; j++) {
        var key = arr[j];
        if (!map[key]) { map[key] = []; seen[key] = {}; }
        if (!seen[key][cid]) {
          seen[key][cid] = true;
          map[key].push(cid);
        }
      }
    }
    return map;
  }

  function findSharedFingerprints() {
    var fpMap = _buildGroupMap('fingerprints');
    var groups = [];
    var fps = Object.keys(fpMap);
    for (var k = 0; k < fps.length; k++) {
      if (fpMap[fps[k]].length >= 2) groups.push({ fingerprint: fps[k], clients: fpMap[fps[k]] });
    }
    return groups;
  }

  function findIPClusters() {
    var ipMap = _buildGroupMap('ips');
    var clusters = [];
    var ips = Object.keys(ipMap);
    for (var k = 0; k < ips.length; k++) {
      if (ipMap[ips[k]].length >= 2) clusters.push({ ip: ips[k], clients: ipMap[ips[k]] });
    }
    var subnetMap = {};
    for (var s = 0; s < ips.length; s++) {
      var parts = ips[s].split('.');
      if (parts.length === 4) {
        var subnet = parts[0] + '.' + parts[1] + '.' + parts[2];
        if (!subnetMap[subnet]) subnetMap[subnet] = [];
        for (var t = 0; t < ipMap[ips[s]].length; t++) {
          if (subnetMap[subnet].indexOf(ipMap[ips[s]][t]) === -1) subnetMap[subnet].push(ipMap[ips[s]][t]);
        }
      }
    }
    var subnets = Object.keys(subnetMap);
    for (var u = 0; u < subnets.length; u++) {
      if (subnetMap[subnets[u]].length >= minRingSize) clusters.push({ subnet: subnets[u], clients: subnetMap[subnets[u]] });
    }
    return clusters;
  }

  function findSequentialPatterns() {
    var solves = [];
    var ids = Object.keys(clients);
    for (var i = 0; i < ids.length; i++) {
      var c = clients[ids[i]];
      for (var j = 0; j < c.events.length; j++) {
        if (c.events[j].type === 'solve') solves.push({ clientId: ids[i], timestamp: c.events[j].timestamp, challengeId: c.events[j].challengeId });
      }
    }
    solves.sort(function(a, b) { return a.timestamp - b.timestamp; });
    var patterns = [];
    for (var k = 0; k < solves.length - 1; k++) {
      var seq = [solves[k]];
      for (var m = k + 1; m < solves.length; m++) {
        var gap = solves[m].timestamp - solves[m - 1].timestamp;
        if (gap > 0 && gap < 2000 && solves[m].clientId !== solves[m - 1].clientId) seq.push(solves[m]);
        else break;
      }
      if (seq.length >= minRingSize) {
        var seqSet = Object.create(null);
        var seqClients = [];
        for (var n = 0; n < seq.length; n++) {
          if (!seqSet[seq[n].clientId]) { seqSet[seq[n].clientId] = true; seqClients.push(seq[n].clientId); }
        }
        if (seqClients.length >= minRingSize) patterns.push({ clients: seqClients, events: seq });
      }
    }
    return patterns;
  }

  function computeRingScore(clientIds) {
    if (!clientIds || clientIds.length < 2) return { score: 0, factors: [] };
    var score = 0, factors = [];

    // Size (up to 20)
    var sizeScore = Math.min(20, (clientIds.length - 1) * 4);
    score += sizeScore;
    factors.push({ name: 'ringSize', score: sizeScore, detail: clientIds.length + ' clients' });

    // Shared fingerprints (up to 25)
    var fpSets = {};
    for (var i = 0; i < clientIds.length; i++) {
      var c = clients[clientIds[i]];
      if (c) for (var j = 0; j < c.fingerprints.length; j++) {
        var fp = c.fingerprints[j];
        fpSets[fp] = (fpSets[fp] || 0) + 1;
      }
    }
    var maxShared = 0;
    var fps = Object.keys(fpSets);
    for (var k = 0; k < fps.length; k++) { if (fpSets[fps[k]] > maxShared) maxShared = fpSets[fps[k]]; }
    var fpScore = Math.min(25, Math.floor(maxShared / clientIds.length * 25));
    score += fpScore;
    factors.push({ name: 'sharedFingerprint', score: fpScore, detail: maxShared + '/' + clientIds.length + ' share fingerprint' });

    // IP proximity (up to 20)
    var allIps = {};
    for (var m = 0; m < clientIds.length; m++) {
      var cl = clients[clientIds[m]];
      if (cl) for (var n = 0; n < cl.ips.length; n++) { allIps[cl.ips[n]] = (allIps[cl.ips[n]] || 0) + 1; }
    }
    var sharedIps = 0;
    var ipKeys = Object.keys(allIps);
    for (var p = 0; p < ipKeys.length; p++) { if (allIps[ipKeys[p]] >= 2) sharedIps++; }
    var ipScore = Math.min(20, sharedIps * 10);
    score += ipScore;
    factors.push({ name: 'ipProximity', score: ipScore, detail: sharedIps + ' shared IPs' });

    // Timing (up to 20)
    var solveTimes = [];
    for (var q = 0; q < clientIds.length; q++) {
      var client = clients[clientIds[q]];
      if (client) for (var r = 0; r < client.events.length; r++) {
        if (client.events[r].type === 'solve') solveTimes.push(client.events[r].timestamp);
      }
    }
    solveTimes.sort(_numAsc);
    var closeCount = 0;
    for (var s = 1; s < solveTimes.length; s++) { if (solveTimes[s] - solveTimes[s - 1] < timingWindowMs) closeCount++; }
    var timingScore = solveTimes.length > 1 ? Math.min(20, Math.floor(closeCount / (solveTimes.length - 1) * 20)) : 0;
    score += timingScore;
    factors.push({ name: 'timingCorrelation', score: timingScore, detail: closeCount + ' close-timed solves' });

    // Response uniformity (up to 15)
    var responseTimes = [];
    for (var t = 0; t < clientIds.length; t++) {
      var ct = clients[clientIds[t]];
      if (ct) for (var u = 0; u < ct.events.length; u++) {
        if (ct.events[u].responseTimeMs != null) responseTimes.push(ct.events[u].responseTimeMs);
      }
    }
    var uniformScore = 0;
    if (responseTimes.length >= 3) {
      var mean = _mean(responseTimes);
      var variance = 0;
      for (var w = 0; w < responseTimes.length; w++) variance += (responseTimes[w] - mean) * (responseTimes[w] - mean);
      variance /= responseTimes.length;
      var cv = mean > 0 ? Math.sqrt(variance) / mean : 1;
      uniformScore = cv < 0.1 ? 15 : cv < 0.2 ? 10 : cv < 0.3 ? 5 : 0;
    }
    score += uniformScore;
    factors.push({ name: 'responseUniformity', score: uniformScore });

    return { score: Math.min(100, score), factors: factors };
  }

  function detectRings() {
    parent = {}; rank = {};

    var fpGroups = findSharedFingerprints();
    for (var i = 0; i < fpGroups.length; i++) {
      var group = fpGroups[i].clients;
      for (var j = 1; j < group.length; j++) ufUnion(group[0], group[j]);
    }

    var ipGroups = findIPClusters();
    for (var k = 0; k < ipGroups.length; k++) {
      var ipGroup = ipGroups[k].clients;
      for (var m = 1; m < ipGroup.length; m++) ufUnion(ipGroup[0], ipGroup[m]);
    }

    var timingClusters = findTimingClusters();
    for (var n = 0; n < timingClusters.length; n++) {
      var cluster = timingClusters[n];
      for (var p = 1; p < cluster.length; p++) ufUnion(cluster[0].clientId, cluster[p].clientId);
    }

    var seqPatterns = findSequentialPatterns();
    for (var q = 0; q < seqPatterns.length; q++) {
      var pat = seqPatterns[q].clients;
      for (var r = 1; r < pat.length; r++) ufUnion(pat[0], pat[r]);
    }

    var components = {};
    var ids = Object.keys(clients);
    for (var s = 0; s < ids.length; s++) {
      var root = ufFind(ids[s]);
      if (!components[root]) components[root] = [];
      components[root].push(ids[s]);
    }

    var detected = [];
    var roots = Object.keys(components);
    for (var t = 0; t < roots.length; t++) {
      var members = components[roots[t]];
      if (members.length < minRingSize) continue;
      var result = computeRingScore(members);
      if (result.score >= suspicionThreshold) {
        var ringId = 'ring-' + (++ringCounter);
        var ring = { id: ringId, members: members, size: members.length, score: result.score, factors: result.factors, detectedAt: Date.now(), status: 'active' };
        if (Object.keys(rings).length >= maxRings) {
          var oldest = null, oldestTime = Infinity;
          var rids = Object.keys(rings);
          for (var u = 0; u < rids.length; u++) { if (rings[rids[u]].detectedAt < oldestTime) { oldest = rids[u]; oldestTime = rings[rids[u]].detectedAt; } }
          if (oldest) delete rings[oldest];
        }
        rings[ringId] = ring;
        for (var v = 0; v < members.length; v++) { if (clients[members[v]]) clients[members[v]].ringId = ringId; }
        detected.push(ring);
        for (var w = 0; w < onRingCallbacks.length; w++) { try { onRingCallbacks[w](ring); } catch (e) { /* ignore */ } }
      }
    }
    detected.sort(function(a, b) { return b.score - a.score; });
    return detected;
  }

  function checkClient(clientId) {
    var client = clients[clientId];
    if (!client) return null;
    if (client.ringId && rings[client.ringId]) return { isFlagged: true, ringId: client.ringId, ring: rings[client.ringId] };
    return { isFlagged: false, ringId: null, ring: null };
  }

  function getRing(ringId) { return rings[ringId] || null; }

  function listRings(filter) {
    filter = filter || {};
    var result = [];
    var rids = Object.keys(rings);
    for (var i = 0; i < rids.length; i++) {
      var ring = rings[rids[i]];
      if (filter.status && ring.status !== filter.status) continue;
      if (filter.minScore && ring.score < filter.minScore) continue;
      result.push(ring);
    }
    result.sort(function(a, b) { return b.score - a.score; });
    return result;
  }

  function dismissRing(ringId) {
    if (!rings[ringId]) return false;
    rings[ringId].status = 'dismissed';
    return true;
  }

  function onRingDetected(cb) { if (typeof cb === 'function') onRingCallbacks.push(cb); }

  function getStats() {
    var totalClients = Object.keys(clients).length;
    var flaggedCount = 0;
    var ids = Object.keys(clients);
    for (var i = 0; i < ids.length; i++) { if (clients[ids[i]].ringId) flaggedCount++; }
    var activeRings = 0, dismissedRings = 0, highestScore = 0;
    var rids = Object.keys(rings);
    for (var j = 0; j < rids.length; j++) {
      if (rings[rids[j]].status === 'active') activeRings++; else dismissedRings++;
      if (rings[rids[j]].score > highestScore) highestScore = rings[rids[j]].score;
    }
    return { totalClients: totalClients, flaggedClients: flaggedCount, flaggedPercent: totalClients > 0 ? Math.round(flaggedCount / totalClients * 100 * 10) / 10 : 0, totalRings: rids.length, activeRings: activeRings, dismissedRings: dismissedRings, highestScore: highestScore, minRingSize: minRingSize, suspicionThreshold: suspicionThreshold };
  }

  function exportState() {
    return { clients: JSON.parse(JSON.stringify(clients)), clientOrder: clientOrder.toArray(), rings: JSON.parse(JSON.stringify(rings)), ringCounter: ringCounter };
  }

  function importState(state) {
    if (!state || typeof state !== 'object') return false;
    if (state.clients) clients = JSON.parse(JSON.stringify(state.clients));
    if (Array.isArray(state.clientOrder)) clientOrder.fromArray(state.clientOrder);
    if (state.rings) rings = JSON.parse(JSON.stringify(state.rings));
    if (typeof state.ringCounter === 'number') ringCounter = state.ringCounter;
    return true;
  }

  function generateReport() {
    var stats = getStats();
    var lines = ['=== Fraud Ring Detection Report ===', 'Tracked Clients: ' + stats.totalClients, 'Flagged Clients: ' + stats.flaggedClients + ' (' + stats.flaggedPercent + '%)', 'Active Rings: ' + stats.activeRings, 'Dismissed Rings: ' + stats.dismissedRings, 'Highest Score: ' + stats.highestScore + '/100', ''];
    var activeList = listRings({ status: 'active' });
    if (activeList.length > 0) {
      lines.push('--- Active Rings ---');
      for (var i = 0; i < activeList.length; i++) {
        var r = activeList[i];
        lines.push('  ' + r.id + ': ' + r.size + ' members, score=' + r.score);
        for (var j = 0; j < r.factors.length; j++) lines.push('    ' + r.factors[j].name + ': +' + r.factors[j].score);
      }
    } else { lines.push('No active fraud rings detected.'); }
    return lines.join('\n');
  }

  function reset() { clients = {}; clientOrder.clear(); rings = {}; parent = {}; rank = {}; ringCounter = 0; }

  return {
    recordEvent: recordEvent, detectRings: detectRings, checkClient: checkClient,
    getRing: getRing, listRings: listRings, dismissRing: dismissRing, onRingDetected: onRingDetected,
    getStats: getStats, findTimingClusters: findTimingClusters, findSharedFingerprints: findSharedFingerprints,
    findIPClusters: findIPClusters, findSequentialPatterns: findSequentialPatterns, computeRingScore: computeRingScore,
    exportState: exportState, importState: importState, generateReport: generateReport, reset: reset
  };
}

// ── Compliance Report Generator ───────────────────────────────────────

/**
 * Creates a compliance report generator that evaluates CAPTCHA system
 * configuration and runtime metrics against accessibility, security,
 * privacy, and operational standards.
 *
 * Checks against:
 * - WCAG 2.1 AA accessibility guidelines
 * - GDPR / privacy data-retention requirements
 * - OWASP bot-mitigation best practices
 * - Operational health thresholds
 *
 * @param {Object} [options] - Generator configuration
 * @param {string} [options.systemName="gif-captcha"] - System identifier for reports
 * @param {number} [options.maxDataRetentionDays=30] - GDPR data retention limit in days
 * @param {number} [options.minSolveRatePercent=70] - Minimum acceptable human solve rate
 * @param {number} [options.maxSolveTimeMs=60000] - Maximum acceptable solve time
 * @param {number} [options.maxFailRatePercent=50] - Maximum acceptable failure rate
 * @param {number} [options.minBotBlockRatePercent=90] - Minimum bot detection rate
 * @returns {Object} Compliance report generator instance
 */
/**
 * Count severity occurrences across an array of findings.
 * @param {Object[]} findings - Array of finding objects with .severity
 * @param {Object} SEV - Severity constants (PASS, CRITICAL, WARNING, INFO)
 * @returns {{ passed: number, criticals: number, warnings: number, infos: number }}
 */
function _countSeverities(findings, SEV) {
  var passed = 0, criticals = 0, warnings = 0, infos = 0;
  for (var i = 0; i < findings.length; i++) {
    var s = findings[i].severity;
    if (s === SEV.PASS) passed++;
    else if (s === SEV.CRITICAL) criticals++;
    else if (s === SEV.WARNING) warnings++;
    else if (s === SEV.INFO) infos++;
  }
  return { passed: passed, criticals: criticals, warnings: warnings, infos: infos };
}

/**
 * Compute per-category compliance scores from findings.
 * @param {Object[]} findings - Array of finding objects with .category and .severity
 * @param {Object} SEV - Severity constants
 * @returns {Object} Map of category -> { score, total, passed, criticals, warnings }
 */
function _computeAllCategoryScores(findings, SEV) {
  var buckets = {};
  for (var i = 0; i < findings.length; i++) {
    var cat = findings[i].category;
    if (!buckets[cat]) buckets[cat] = [];
    buckets[cat].push(findings[i]);
  }
  var scores = {};
  var cats = Object.keys(buckets);
  for (var c = 0; c < cats.length; c++) {
    var catName = cats[c];
    var items = buckets[catName];
    var counts = _countSeverities(items, SEV);
    var scorable = items.length - counts.infos;
    var score = scorable > 0 ? Math.round((counts.passed / scorable) * 100) : 100;
    scores[catName] = {
      score: score,
      total: items.length,
      passed: counts.passed,
      criticals: counts.criticals,
      warnings: counts.warnings
    };
  }
  return scores;
}

/**
 * Compute a weighted average score from category scores and weight map.
 * @param {Object} categoryScores - Map of category -> { score }
 * @param {Object} weights - Map of category -> weight (number)
 * @returns {number} Weighted average (0-100), rounded
 */
function _weightedAverage(categoryScores, weights) {
  var total = 0, weightSum = 0;
  var cats = Object.keys(weights);
  for (var i = 0; i < cats.length; i++) {
    var cat = cats[i];
    if (categoryScores[cat]) {
      total += categoryScores[cat].score * weights[cat];
      weightSum += weights[cat];
    }
  }
  return weightSum > 0 ? Math.round(total / weightSum) : 0;
}

function createComplianceReporter(options) {
  options = options || {};
  var systemName = options.systemName || "gif-captcha";
  var maxRetentionDays = options.maxDataRetentionDays > 0 ? options.maxDataRetentionDays : 30;
  var minSolveRate = typeof options.minSolveRatePercent === "number" ? options.minSolveRatePercent : 70;
  var maxSolveTimeMs = options.maxSolveTimeMs > 0 ? options.maxSolveTimeMs : 60000;
  var maxFailRate = typeof options.maxFailRatePercent === "number" ? options.maxFailRatePercent : 50;
  var minBotBlockRate = typeof options.minBotBlockRatePercent === "number" ? options.minBotBlockRatePercent : 90;

  var SEVERITY = { CRITICAL: "critical", WARNING: "warning", INFO: "info", PASS: "pass" };
  var CATEGORY = {
    ACCESSIBILITY: "accessibility",
    PRIVACY: "privacy",
    SECURITY: "security",
    OPERATIONAL: "operational"
  };

  /**
   * Run all compliance checks against provided configuration and metrics.
   *
   * @param {Object} config - CAPTCHA system configuration
   * @param {boolean} [config.audioAlternative] - Whether audio CAPTCHA is available
   * @param {boolean} [config.keyboardNavigable] - Whether CAPTCHA is keyboard-navigable
   * @param {string} [config.ariaLabel] - ARIA label for the CAPTCHA element
   * @param {number} [config.colorContrast] - Color contrast ratio (e.g. 4.5)
   * @param {number} [config.timeLimitMs] - Time limit given to solve
   * @param {boolean} [config.canExtendTime] - Whether user can extend time
   * @param {string[]} [config.supportedLanguages] - List of supported locale codes
   * @param {number} [config.dataRetentionDays] - How long data is retained
   * @param {boolean} [config.consentRequired] - Whether consent is collected
   * @param {boolean} [config.anonymization] - Whether data is anonymised
   * @param {boolean} [config.deletionSupported] - Whether right-to-delete is supported
   * @param {boolean} [config.rateLimitEnabled] - Whether rate limiting is active
   * @param {boolean} [config.tokenSigned] - Whether tokens use HMAC signing
   * @param {boolean} [config.httpsOnly] - Whether HTTPS is enforced
   * @param {boolean} [config.inputSanitized] - Whether input is sanitised
   * @param {number} [config.maxAttempts] - Max attempts before lockout
   * @param {boolean} [config.replayProtection] - Whether replay attacks are prevented
   * @param {Object} [metrics] - Runtime metrics snapshot
   * @param {number} [metrics.totalChallenges] - Total challenges served
   * @param {number} [metrics.totalSolves] - Successful solves
   * @param {number} [metrics.totalFailures] - Failed attempts
   * @param {number} [metrics.avgSolveTimeMs] - Average solve time in ms
   * @param {number} [metrics.p95SolveTimeMs] - P95 solve time in ms
   * @param {number} [metrics.botAttempts] - Detected bot attempts
   * @param {number} [metrics.botBlocked] - Blocked bot attempts
   * @param {number} [metrics.uptimePercent] - System uptime percentage
   * @param {number} [metrics.avgResponseTimeMs] - Average server response time
   * @param {number} [metrics.errorCount] - Server error count
   * @returns {Object} Compliance report
   */
  function generateReport(config, metrics) {
    config = config || {};
    metrics = metrics || {};
    var findings = [];
    var now = new Date();

    // ── Accessibility Checks (WCAG 2.1 AA) ─────────────────────────

    findings.push({
      id: "ACC-001",
      category: CATEGORY.ACCESSIBILITY,
      title: "Audio alternative available",
      description: "WCAG 1.1.1: Non-text content must have a text or audio alternative",
      severity: config.audioAlternative ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.audioAlternative ? null : "Enable audio CAPTCHA alternative for visually impaired users"
    });

    findings.push({
      id: "ACC-002",
      category: CATEGORY.ACCESSIBILITY,
      title: "Keyboard navigation support",
      description: "WCAG 2.1.1: All functionality must be operable through a keyboard",
      severity: config.keyboardNavigable ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.keyboardNavigable ? null : "Ensure CAPTCHA can be completed using keyboard only"
    });

    findings.push({
      id: "ACC-003",
      category: CATEGORY.ACCESSIBILITY,
      title: "ARIA labelling",
      description: "WCAG 4.1.2: UI components must have accessible names and roles",
      severity: config.ariaLabel ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.ariaLabel ? null : "Add aria-label or aria-labelledby to the CAPTCHA container"
    });

    var contrast = typeof config.colorContrast === "number" ? config.colorContrast : 0;
    findings.push({
      id: "ACC-004",
      category: CATEGORY.ACCESSIBILITY,
      title: "Color contrast ratio",
      description: "WCAG 1.4.3: Text must have a contrast ratio of at least 4.5:1",
      severity: contrast >= 4.5 ? SEVERITY.PASS : contrast >= 3 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: contrast >= 4.5 ? null : "Increase color contrast to at least 4.5:1 (current: " + contrast.toFixed(1) + ":1)"
    });

    var hasTimeLimit = typeof config.timeLimitMs === "number" && config.timeLimitMs > 0;
    findings.push({
      id: "ACC-005",
      category: CATEGORY.ACCESSIBILITY,
      title: "Time limit accommodation",
      description: "WCAG 2.2.1: Users must be able to turn off, adjust, or extend time limits",
      severity: !hasTimeLimit || config.canExtendTime ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: hasTimeLimit && !config.canExtendTime ? "Allow users to request additional time to complete the CAPTCHA" : null
    });

    var langCount = Array.isArray(config.supportedLanguages) ? config.supportedLanguages.length : 0;
    findings.push({
      id: "ACC-006",
      category: CATEGORY.ACCESSIBILITY,
      title: "Multilingual support",
      description: "WCAG 3.1.1: Default language must be programmatically determinable",
      severity: langCount >= 3 ? SEVERITY.PASS : langCount >= 1 ? SEVERITY.INFO : SEVERITY.WARNING,
      recommendation: langCount < 3 ? "Support at least 3 languages for broader accessibility (" + langCount + " currently configured)" : null
    });

    // ── Privacy Checks (GDPR) ───────────────────────────────────────

    var retDays = typeof config.dataRetentionDays === "number" ? config.dataRetentionDays : -1;
    findings.push({
      id: "PRV-001",
      category: CATEGORY.PRIVACY,
      title: "Data retention policy",
      description: "GDPR Art. 5(1)(e): Data must not be kept longer than necessary",
      severity: retDays >= 0 && retDays <= maxRetentionDays ? SEVERITY.PASS : retDays < 0 ? SEVERITY.CRITICAL : SEVERITY.WARNING,
      recommendation: retDays < 0 ? "Define a data retention period (max " + maxRetentionDays + " days recommended)"
        : retDays > maxRetentionDays ? "Reduce retention from " + retDays + " to " + maxRetentionDays + " days or less" : null
    });

    findings.push({
      id: "PRV-002",
      category: CATEGORY.PRIVACY,
      title: "User consent collection",
      description: "GDPR Art. 6: Processing requires a lawful basis (consent for CAPTCHAs)",
      severity: config.consentRequired ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.consentRequired ? null : "Collect explicit consent before processing CAPTCHA interaction data"
    });

    findings.push({
      id: "PRV-003",
      category: CATEGORY.PRIVACY,
      title: "Data anonymisation",
      description: "GDPR Art. 25: Data protection by design and default",
      severity: config.anonymization ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.anonymization ? null : "Anonymise or pseudonymise stored CAPTCHA interaction data"
    });

    findings.push({
      id: "PRV-004",
      category: CATEGORY.PRIVACY,
      title: "Right to deletion",
      description: "GDPR Art. 17: Users have the right to erasure of personal data",
      severity: config.deletionSupported ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.deletionSupported ? null : "Implement data deletion endpoint for GDPR Art. 17 compliance"
    });

    // ── Security Checks (OWASP) ─────────────────────────────────────

    findings.push({
      id: "SEC-001",
      category: CATEGORY.SECURITY,
      title: "Rate limiting enabled",
      description: "OWASP: Implement rate limiting to prevent automated attacks",
      severity: config.rateLimitEnabled ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.rateLimitEnabled ? null : "Enable request rate limiting to prevent brute-force attacks"
    });

    findings.push({
      id: "SEC-002",
      category: CATEGORY.SECURITY,
      title: "Token signing (HMAC)",
      description: "OWASP: Validate CAPTCHA tokens server-side with cryptographic signatures",
      severity: config.tokenSigned ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.tokenSigned ? null : "Use HMAC-signed tokens for stateless CAPTCHA validation"
    });

    findings.push({
      id: "SEC-003",
      category: CATEGORY.SECURITY,
      title: "HTTPS enforcement",
      description: "OWASP: Encrypt all CAPTCHA traffic to prevent interception",
      severity: config.httpsOnly ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.httpsOnly ? null : "Enforce HTTPS for all CAPTCHA endpoints"
    });

    findings.push({
      id: "SEC-004",
      category: CATEGORY.SECURITY,
      title: "Input sanitisation",
      description: "OWASP: Sanitise all user input to prevent injection attacks",
      severity: config.inputSanitized ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.inputSanitized ? null : "Sanitise CAPTCHA answer input before processing"
    });

    var maxAttempts = typeof config.maxAttempts === "number" ? config.maxAttempts : 0;
    findings.push({
      id: "SEC-005",
      category: CATEGORY.SECURITY,
      title: "Attempt limiting / lockout",
      description: "OWASP: Lock out after repeated failures to prevent brute force",
      severity: maxAttempts > 0 && maxAttempts <= 10 ? SEVERITY.PASS : maxAttempts > 10 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: maxAttempts <= 0 ? "Configure a maximum attempt limit (recommended: 3-5)"
        : maxAttempts > 10 ? "Reduce max attempts from " + maxAttempts + " to 5 or fewer" : null
    });

    findings.push({
      id: "SEC-006",
      category: CATEGORY.SECURITY,
      title: "Replay protection",
      description: "Prevent reuse of solved CAPTCHA tokens",
      severity: config.replayProtection ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.replayProtection ? null : "Implement one-time-use tokens to prevent replay attacks"
    });

    var botBlockRate = 0;
    if (metrics.botAttempts > 0) {
      botBlockRate = (metrics.botBlocked / metrics.botAttempts) * 100;
    }
    findings.push({
      id: "SEC-007",
      category: CATEGORY.SECURITY,
      title: "Bot detection effectiveness",
      description: "Bot block rate should be at least " + minBotBlockRate + "%",
      severity: metrics.botAttempts === 0 ? SEVERITY.INFO
        : botBlockRate >= minBotBlockRate ? SEVERITY.PASS
        : botBlockRate >= minBotBlockRate * 0.8 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: metrics.botAttempts > 0 && botBlockRate < minBotBlockRate
        ? "Bot block rate is " + botBlockRate.toFixed(1) + "% (target: " + minBotBlockRate + "%)" : null
    });

    // ── Operational Checks ──────────────────────────────────────────

    var solveRate = 0;
    if (metrics.totalChallenges > 0) {
      solveRate = (metrics.totalSolves / metrics.totalChallenges) * 100;
    }
    findings.push({
      id: "OPS-001",
      category: CATEGORY.OPERATIONAL,
      title: "Human solve rate",
      description: "Solve rate should be at least " + minSolveRate + "% to avoid user frustration",
      severity: metrics.totalChallenges === 0 ? SEVERITY.INFO
        : solveRate >= minSolveRate ? SEVERITY.PASS
        : solveRate >= minSolveRate * 0.8 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: metrics.totalChallenges > 0 && solveRate < minSolveRate
        ? "Solve rate is " + solveRate.toFixed(1) + "% (target: " + minSolveRate + "%). Consider reducing difficulty." : null
    });

    var failRate = 0;
    if (metrics.totalChallenges > 0) {
      failRate = (metrics.totalFailures / metrics.totalChallenges) * 100;
    }
    findings.push({
      id: "OPS-002",
      category: CATEGORY.OPERATIONAL,
      title: "Failure rate within threshold",
      description: "Failure rate should be below " + maxFailRate + "%",
      severity: metrics.totalChallenges === 0 ? SEVERITY.INFO
        : failRate <= maxFailRate ? SEVERITY.PASS
        : failRate <= maxFailRate * 1.2 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: metrics.totalChallenges > 0 && failRate > maxFailRate
        ? "Failure rate is " + failRate.toFixed(1) + "% (threshold: " + maxFailRate + "%)" : null
    });

    var avgTime = typeof metrics.avgSolveTimeMs === "number" ? metrics.avgSolveTimeMs : 0;
    findings.push({
      id: "OPS-003",
      category: CATEGORY.OPERATIONAL,
      title: "Average solve time acceptable",
      description: "Solve time should be under " + (maxSolveTimeMs / 1000) + "s",
      severity: avgTime <= 0 ? SEVERITY.INFO
        : avgTime <= maxSolveTimeMs ? SEVERITY.PASS
        : avgTime <= maxSolveTimeMs * 1.5 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: avgTime > maxSolveTimeMs
        ? "Average solve time is " + (avgTime / 1000).toFixed(1) + "s (target: " + (maxSolveTimeMs / 1000) + "s)" : null
    });

    var p95Time = typeof metrics.p95SolveTimeMs === "number" ? metrics.p95SolveTimeMs : 0;
    findings.push({
      id: "OPS-004",
      category: CATEGORY.OPERATIONAL,
      title: "P95 solve time acceptable",
      description: "95th percentile solve time should be under " + (maxSolveTimeMs * 2 / 1000) + "s",
      severity: p95Time <= 0 ? SEVERITY.INFO
        : p95Time <= maxSolveTimeMs * 2 ? SEVERITY.PASS
        : p95Time <= maxSolveTimeMs * 3 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: p95Time > maxSolveTimeMs * 2
        ? "P95 solve time is " + (p95Time / 1000).toFixed(1) + "s — consider simplifying hard challenges" : null
    });

    var uptime = typeof metrics.uptimePercent === "number" ? metrics.uptimePercent : 100;
    findings.push({
      id: "OPS-005",
      category: CATEGORY.OPERATIONAL,
      title: "System availability",
      description: "Uptime should be at least 99.5%",
      severity: uptime >= 99.5 ? SEVERITY.PASS : uptime >= 99 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: uptime < 99.5 ? "Uptime is " + uptime.toFixed(2) + "% (target: 99.5%)" : null
    });

    var responseTime = typeof metrics.avgResponseTimeMs === "number" ? metrics.avgResponseTimeMs : 0;
    findings.push({
      id: "OPS-006",
      category: CATEGORY.OPERATIONAL,
      title: "Server response time",
      description: "Average response time should be under 500ms",
      severity: responseTime <= 0 ? SEVERITY.INFO
        : responseTime <= 500 ? SEVERITY.PASS
        : responseTime <= 1000 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: responseTime > 500 ? "Average response time is " + responseTime + "ms (target: <500ms)" : null
    });

    var errCount = typeof metrics.errorCount === "number" ? metrics.errorCount : 0;
    var errRate = metrics.totalChallenges > 0 ? (errCount / metrics.totalChallenges) * 100 : 0;
    findings.push({
      id: "OPS-007",
      category: CATEGORY.OPERATIONAL,
      title: "Error rate",
      description: "Server error rate should be below 1%",
      severity: metrics.totalChallenges === 0 ? SEVERITY.INFO
        : errRate <= 1 ? SEVERITY.PASS
        : errRate <= 5 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: errRate > 1 ? "Error rate is " + errRate.toFixed(2) + "% (" + errCount + " errors)" : null
    });

    // ── Compute Scores ──────────────────────────────────────────────

    var categoryScores = _computeAllCategoryScores(findings, SEVERITY);

    // Overall score: weighted average (security 35%, privacy 25%, accessibility 25%, operational 15%)
    var weights = { security: 35, privacy: 25, accessibility: 25, operational: 15 };
    var overallScore = _weightedAverage(categoryScores, weights);
    var grade = overallScore >= 90 ? "A" : overallScore >= 80 ? "B" : overallScore >= 70 ? "C" : overallScore >= 60 ? "D" : "F";

    var counts = _countSeverities(findings, SEVERITY);
    var totalCriticals = counts.criticals;
    var totalWarnings = counts.warnings;
    var totalPassed = counts.passed;

    return {
      system: systemName,
      generatedAt: now.toISOString(),
      overallScore: overallScore,
      grade: grade,
      totalFindings: findings.length,
      passed: totalPassed,
      criticals: totalCriticals,
      warnings: totalWarnings,
      categoryScores: categoryScores,
      findings: findings
    };
  }

  /**
   * Generate a minimal configuration template that would achieve a passing score.
   * Useful for bootstrapping new CAPTCHA deployments.
   *
   * @returns {Object} Recommended configuration object
   */
  function getRecommendedConfig() {
    return {
      audioAlternative: true,
      keyboardNavigable: true,
      ariaLabel: "Security verification",
      colorContrast: 4.5,
      timeLimitMs: 120000,
      canExtendTime: true,
      supportedLanguages: ["en", "es", "fr"],
      dataRetentionDays: maxRetentionDays,
      consentRequired: true,
      anonymization: true,
      deletionSupported: true,
      rateLimitEnabled: true,
      tokenSigned: true,
      httpsOnly: true,
      inputSanitized: true,
      maxAttempts: 5,
      replayProtection: true
    };
  }

  /**
   * Compare two reports and return a diff summary showing improvements
   * and regressions between audits.
   *
   * @param {Object} oldReport - Previous compliance report
   * @param {Object} newReport - Current compliance report
   * @returns {Object} Diff summary with improved, regressed, and unchanged counts
   */
  function compareReports(oldReport, newReport) {
    if (!oldReport || !newReport || !oldReport.findings || !newReport.findings) {
      return { error: "invalid_reports", improved: 0, regressed: 0, unchanged: 0, details: [] };
    }
    var oldMap = {};
    for (var oi = 0; oi < oldReport.findings.length; oi++) {
      oldMap[oldReport.findings[oi].id] = oldReport.findings[oi].severity;
    }

    var severityRank = {};
    severityRank[SEVERITY.PASS] = 0;
    severityRank[SEVERITY.INFO] = 1;
    severityRank[SEVERITY.WARNING] = 2;
    severityRank[SEVERITY.CRITICAL] = 3;

    var improved = 0, regressed = 0, unchanged = 0;
    var details = [];
    for (var ni = 0; ni < newReport.findings.length; ni++) {
      var finding = newReport.findings[ni];
      var oldSev = oldMap[finding.id];
      if (oldSev === undefined) {
        details.push({ id: finding.id, change: "new", severity: finding.severity });
        continue;
      }
      var oldRank = severityRank[oldSev] !== undefined ? severityRank[oldSev] : 1;
      var newRank = severityRank[finding.severity] !== undefined ? severityRank[finding.severity] : 1;
      if (newRank < oldRank) {
        improved++;
        details.push({ id: finding.id, change: "improved", from: oldSev, to: finding.severity });
      } else if (newRank > oldRank) {
        regressed++;
        details.push({ id: finding.id, change: "regressed", from: oldSev, to: finding.severity });
      } else {
        unchanged++;
      }
    }

    return {
      oldScore: oldReport.overallScore,
      newScore: newReport.overallScore,
      scoreDelta: newReport.overallScore - oldReport.overallScore,
      improved: improved,
      regressed: regressed,
      unchanged: unchanged,
      details: details
    };
  }

  /**
   * Format a report as a plain-text summary suitable for terminal output or logging.
   *
   * @param {Object} report - Compliance report from generateReport()
   * @returns {string} Formatted text report
   */
  function formatReportText(report) {
    if (!report) return "";
    var lines = [];
    lines.push("=== CAPTCHA Compliance Report ===");
    lines.push("System: " + report.system);
    lines.push("Generated: " + report.generatedAt);
    lines.push("Overall Score: " + report.overallScore + "/100 (Grade: " + report.grade + ")");
    lines.push("");

    var cats = ["accessibility", "privacy", "security", "operational"];
    for (var ci = 0; ci < cats.length; ci++) {
      var cat = cats[ci];
      var cs = report.categoryScores[cat];
      if (!cs) continue;
      lines.push("  " + cat.charAt(0).toUpperCase() + cat.slice(1) + ": " + cs.score + "/100 (" + cs.passed + "/" + cs.total + " passed)");
    }
    lines.push("");

    var actionItems = [];
    for (var fi = 0; fi < report.findings.length; fi++) {
      var f = report.findings[fi];
      if (f.severity === SEVERITY.CRITICAL || f.severity === SEVERITY.WARNING) {
        actionItems.push(f);
      }
    }

    if (actionItems.length > 0) {
      lines.push("Action Items:");
      for (var ai = 0; ai < actionItems.length; ai++) {
        var item = actionItems[ai];
        var icon = item.severity === SEVERITY.CRITICAL ? "[CRITICAL]" : "[WARNING]";
        lines.push("  " + icon + " " + item.id + " " + item.title);
        if (item.recommendation) {
          lines.push("    -> " + item.recommendation);
        }
      }
    } else {
      lines.push("No action items - all checks passed!");
    }

    return lines.join("\n");
  }

  /**
   * Render a compliance report as a self-contained HTML page with inline
   * CSS styling, color-coded severity badges, category score bars, and
   * a summary dashboard. The output is a complete HTML document that can
   * be saved to a file and opened in any browser.
   *
   * @param {Object} report - Compliance report from generateReport()
   * @param {Object} [htmlOptions] - Rendering options
   * @param {string} [htmlOptions.title] - Custom page title
   * @param {boolean} [htmlOptions.darkMode=false] - Use dark colour scheme
   * @param {boolean} [htmlOptions.includeTimestamp=true] - Show generation timestamp
   * @returns {string} Complete HTML document string
   */
  function formatReportHtml(report, htmlOptions) {
    if (!report) return "";
    htmlOptions = htmlOptions || {};
    var title = htmlOptions.title || "CAPTCHA Compliance Report — " + (report.system || "System");
    var dark = !!htmlOptions.darkMode;
    var showTime = htmlOptions.includeTimestamp !== false;

    // Colour palette
    var bg = dark ? "#1a1a2e" : "#f8f9fa";
    var cardBg = dark ? "#16213e" : "#ffffff";
    var textColor = dark ? "#e0e0e0" : "#333333";
    var mutedText = dark ? "#a0a0a0" : "#6c757d";
    var borderColor = dark ? "#2a2a4a" : "#dee2e6";

    var severityColors = {
      critical: { bg: "#dc3545", text: "#fff" },
      warning:  { bg: "#ffc107", text: "#333" },
      info:     { bg: "#17a2b8", text: "#fff" },
      pass:     { bg: "#28a745", text: "#fff" }
    };

    var gradeColors = {
      A: "#28a745", B: "#5cb85c", C: "#ffc107", D: "#fd7e14", F: "#dc3545"
    };

    var gradeColor = gradeColors[report.grade] || "#6c757d";

    // Build category score bars
    var cats = ["accessibility", "privacy", "security", "operational"];
    var catLabels = { accessibility: "Accessibility", privacy: "Privacy", security: "Security", operational: "Operational" };
    var catIcons = { accessibility: "♿", privacy: "🔒", security: "🛡️", operational: "⚙️" };

    var scoreBarsHtml = "";
    for (var ci = 0; ci < cats.length; ci++) {
      var cat = cats[ci];
      var cs = report.categoryScores[cat];
      if (!cs) continue;
      var barColor = cs.score >= 80 ? "#28a745" : cs.score >= 60 ? "#ffc107" : "#dc3545";
      scoreBarsHtml += '<div style="margin-bottom:12px">'
        + '<div style="display:flex;justify-content:space-between;margin-bottom:4px">'
        + '<span>' + catIcons[cat] + ' ' + catLabels[cat] + '</span>'
        + '<span style="font-weight:600">' + cs.score + '/100</span>'
        + '</div>'
        + '<div style="background:' + borderColor + ';border-radius:8px;height:10px;overflow:hidden">'
        + '<div style="width:' + cs.score + '%;height:100%;background:' + barColor + ';border-radius:8px;transition:width 0.5s"></div>'
        + '</div>'
        + '<div style="font-size:12px;color:' + mutedText + ';margin-top:2px">'
        + cs.passed + '/' + cs.total + ' passed'
        + (cs.criticals > 0 ? ' · ' + cs.criticals + ' critical' : '')
        + (cs.warnings > 0 ? ' · ' + cs.warnings + ' warning' : '')
        + '</div></div>';
    }

    // Build findings table
    var findingsHtml = "";
    // Sort: critical first, then warning, info, pass
    var sortedFindings = report.findings.slice().sort(function (a, b) {
      var order = { critical: 0, warning: 1, info: 2, pass: 3 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    });

    for (var fi = 0; fi < sortedFindings.length; fi++) {
      var f = sortedFindings[fi];
      var sc = severityColors[f.severity] || severityColors.info;
      var recHtml = f.recommendation
        ? '<div style="margin-top:6px;padding:8px 12px;background:' + (dark ? "#1a1a2e" : "#f1f3f5")
          + ';border-left:3px solid ' + sc.bg + ';border-radius:4px;font-size:13px">💡 ' + escapeHtml(f.recommendation) + '</div>'
        : '';

      findingsHtml += '<div style="padding:14px 16px;border-bottom:1px solid ' + borderColor + '">'
        + '<div style="display:flex;align-items:center;gap:10px">'
        + '<span style="display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;text-transform:uppercase;background:'
        + sc.bg + ';color:' + sc.text + '">' + f.severity + '</span>'
        + '<span style="font-size:12px;color:' + mutedText + '">' + escapeHtml(f.id) + '</span>'
        + '<span style="font-weight:600">' + escapeHtml(f.title) + '</span>'
        + '</div>'
        + '<div style="margin-top:4px;font-size:13px;color:' + mutedText + '">' + escapeHtml(f.description) + '</div>'
        + recHtml
        + '</div>';
    }

    // Summary counters
    var summaryItems = [
      { label: "Passed", value: report.passed, color: "#28a745" },
      { label: "Critical", value: report.criticals, color: "#dc3545" },
      { label: "Warnings", value: report.warnings, color: "#ffc107" },
      { label: "Total Checks", value: report.totalFindings, color: mutedText }
    ];
    var summaryHtml = "";
    for (var si = 0; si < summaryItems.length; si++) {
      var s = summaryItems[si];
      summaryHtml += '<div style="text-align:center;flex:1;min-width:100px">'
        + '<div style="font-size:28px;font-weight:700;color:' + s.color + '">' + s.value + '</div>'
        + '<div style="font-size:12px;color:' + mutedText + '">' + s.label + '</div></div>';
    }

    var html = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
      + '<meta name="viewport" content="width=device-width,initial-scale=1">'
      + '<title>' + escapeHtml(title) + '</title>'
      + '<style>'
      + 'body{margin:0;padding:20px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;'
      + 'background:' + bg + ';color:' + textColor + '}'
      + '.card{background:' + cardBg + ';border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,' + (dark ? '0.3' : '0.08') + ');margin-bottom:20px;overflow:hidden}'
      + '.card-header{padding:16px 20px;font-weight:600;font-size:16px;border-bottom:1px solid ' + borderColor + '}'
      + '.card-body{padding:20px}'
      + '@media print{body{background:#fff;color:#333}.card{box-shadow:none;border:1px solid #ddd}}'
      + '</style></head><body>'
      + '<div style="max-width:900px;margin:0 auto">'
      // Header
      + '<div style="text-align:center;margin-bottom:24px">'
      + '<h1 style="margin:0 0 4px 0;font-size:24px">' + escapeHtml(report.system) + ' Compliance Report</h1>'
      + (showTime ? '<div style="color:' + mutedText + ';font-size:13px">Generated ' + escapeHtml(report.generatedAt) + '</div>' : '')
      + '</div>'
      // Grade circle + summary
      + '<div class="card"><div class="card-body" style="display:flex;align-items:center;gap:24px;flex-wrap:wrap">'
      + '<div style="flex-shrink:0;text-align:center">'
      + '<div style="width:90px;height:90px;border-radius:50%;border:4px solid ' + gradeColor
      + ';display:flex;flex-direction:column;align-items:center;justify-content:center">'
      + '<div style="font-size:32px;font-weight:800;color:' + gradeColor + '">' + report.grade + '</div>'
      + '<div style="font-size:12px;color:' + mutedText + '">' + report.overallScore + '/100</div>'
      + '</div></div>'
      + '<div style="display:flex;flex-wrap:wrap;flex:1;gap:8px">' + summaryHtml + '</div>'
      + '</div></div>'
      // Category scores
      + '<div class="card"><div class="card-header">Category Scores</div><div class="card-body">'
      + scoreBarsHtml
      + '</div></div>'
      // Findings
      + '<div class="card"><div class="card-header">Findings (' + report.totalFindings + ')</div>'
      + findingsHtml
      + '</div>'
      // Footer
      + '<div style="text-align:center;padding:16px;font-size:12px;color:' + mutedText + '">'
      + 'Generated by gif-captcha compliance reporter'
      + '</div></div></body></html>';

    return html;
  }

  /**
   * Escape HTML special characters to prevent XSS in generated reports.
   * @param {string} str - Raw string
   * @returns {string} HTML-safe string
   */
  function escapeHtml(str) {
    if (typeof str !== "string") return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  return {
    generateReport: generateReport,
    getRecommendedConfig: getRecommendedConfig,
    compareReports: compareReports,
    formatReportText: formatReportText,
    formatReportHtml: formatReportHtml,
    SEVERITY: SEVERITY,
    CATEGORY: CATEGORY
  };
}

// ═══════════════════════════════════════════════════════════════════
// Metrics Aggregator — unified metrics collection from all subsystems
// ═══════════════════════════════════════════════════════════════════

/**
 * Creates a metrics aggregator that collects and unifies stats from all
 * registered CAPTCHA subsystems into a single dashboard-ready snapshot.
 *
 * Accepts instances of any subsystem (bot detector, rate limiter,
 * reputation tracker, etc.) and calls their getStats/getReport methods
 * to produce a unified view.
 *
 * Usage:
 * ```js
 * var agg = createMetricsAggregator({ historySize: 100 });
 * agg.register('sessions', sessionManager);
 * agg.register('reputation', reputationTracker);
 * agg.register('rateLimiter', rateLimiter);
 *
 * var snapshot = agg.snapshot();
 * // { timestamp, subsystems: {...}, health: {...}, alerts: [...] }
 *
 * var trends = agg.getTrends();
 * // { snapshots: [...], uptimeMs, snapshotCount }
 * ```
 *
 * @param {Object} [options]
 * @param {number} [options.historySize=60]  Max snapshots to retain
 * @param {Object} [options.thresholds]      Alert thresholds
 * @param {number} [options.thresholds.passRate]      Min acceptable pass rate (0-1)
 * @param {number} [options.thresholds.avgResponseMs] Max acceptable avg response time ms
 * @param {number} [options.thresholds.dangerousRate] Max acceptable dangerous-classified rate (0-1)
 * @param {number} [options.thresholds.botDetectionRate] Max acceptable bot rate (0-1)
 * @returns {Object} Metrics aggregator instance
 */
function createMetricsAggregator(options) {
  var opts = options || {};
  var historySize = Math.max(1, opts.historySize || 60);
  var thresholds = Object.assign({
    passRate: 0.3,
    avgResponseMs: 30000,
    dangerousRate: 0.25,
    botDetectionRate: 0.4,
  }, opts.thresholds || {});

  var subsystems = Object.create(null);
  var history = [];
  var startTime = Date.now();
  var autoCaptureTimer = null;
  var alertListeners = [];

  // ── Registration ──

  /**
   * Register a subsystem instance for metrics collection.
   * The instance must have at least one of: getStats, getReport, getSummary.
   *
   * @param {string} name   Unique subsystem identifier
   * @param {Object} instance  Subsystem instance
   * @returns {boolean} true if registered successfully
   */
  function register(name, instance) {
    if (!name || typeof name !== 'string') return false;
    if (!instance || typeof instance !== 'object') return false;
    if (typeof instance.getStats !== 'function' &&
        typeof instance.getReport !== 'function' &&
        typeof instance.getSummary !== 'function') {
      return false;
    }
    subsystems[name] = instance;
    return true;
  }

  /**
   * Unregister a subsystem.
   * @param {string} name
   * @returns {boolean} true if was registered
   */
  function unregister(name) {
    if (!(name in subsystems)) return false;
    delete subsystems[name];
    return true;
  }

  /**
   * Get list of registered subsystem names.
   * @returns {string[]}
   */
  function listSubsystems() {
    return Object.keys(subsystems);
  }

  // ── Stats Collection ──

  /**
   * Safely collect stats from a single subsystem.
   * Tries getStats, then getReport, then getSummary.
   * @param {Object} instance
   * @returns {Object|null}
   */
  function _collectStats(instance) {
    try {
      if (typeof instance.getStats === 'function') return instance.getStats();
      if (typeof instance.getReport === 'function') return instance.getReport();
      if (typeof instance.getSummary === 'function') return instance.getSummary();
    } catch (_) {
      return null;
    }
    return null;
  }

  /**
   * Compute overall health score (0-100) from subsystem stats.
   * Checks known patterns: passRate, avgResponseTimeMs,
   * classifications.dangerous, botRate.
   *
   * @param {Object} stats  Map of subsystem name → stats object
   * @returns {{ score: number, status: string, factors: Object[] }}
   */
  function _computeHealth(stats) {
    var factors = [];
    var penalties = 0;

    // Check session pass rate
    if (stats.sessions && typeof stats.sessions.passRate === 'number') {
      var pr = stats.sessions.passRate;
      if (pr < thresholds.passRate) {
        var impact = Math.round((thresholds.passRate - pr) * 100);
        factors.push({ subsystem: 'sessions', metric: 'passRate', value: pr, threshold: thresholds.passRate, impact: impact });
        penalties += impact;
      }
    }

    // Check response time
    if (stats.sessions && typeof stats.sessions.avgResponseTimeMs === 'number' && stats.sessions.avgResponseTimeMs !== null) {
      var rt = stats.sessions.avgResponseTimeMs;
      if (rt > thresholds.avgResponseMs) {
        var rtImpact = Math.min(30, Math.round((rt - thresholds.avgResponseMs) / thresholds.avgResponseMs * 30));
        factors.push({ subsystem: 'sessions', metric: 'avgResponseTimeMs', value: rt, threshold: thresholds.avgResponseMs, impact: rtImpact });
        penalties += rtImpact;
      }
    }

    // Check reputation dangerous rate
    if (stats.reputation && stats.reputation.classifications) {
      var cls = stats.reputation.classifications;
      var total = (cls.trusted || 0) + (cls.neutral || 0) + (cls.suspicious || 0) + (cls.dangerous || 0);
      if (total > 0) {
        var dangRate = (cls.dangerous || 0) / total;
        if (dangRate > thresholds.dangerousRate) {
          var dImpact = Math.round((dangRate - thresholds.dangerousRate) * 80);
          factors.push({ subsystem: 'reputation', metric: 'dangerousRate', value: dangRate, threshold: thresholds.dangerousRate, impact: dImpact });
          penalties += dImpact;
        }
      }
    }

    // Check bot detection rate from botDetector
    if (stats.botDetector && typeof stats.botDetector.totalChecks === 'number' && stats.botDetector.totalChecks > 0) {
      var botRate = (stats.botDetector.botsDetected || 0) / stats.botDetector.totalChecks;
      if (botRate > thresholds.botDetectionRate) {
        var bImpact = Math.round((botRate - thresholds.botDetectionRate) * 60);
        factors.push({ subsystem: 'botDetector', metric: 'botRate', value: botRate, threshold: thresholds.botDetectionRate, impact: bImpact });
        penalties += bImpact;
      }
    }

    // Check rate limiter rejections
    if (stats.rateLimiter && typeof stats.rateLimiter.totalRequests === 'number' && stats.rateLimiter.totalRequests > 0) {
      var rejectRate = (stats.rateLimiter.rejected || 0) / stats.rateLimiter.totalRequests;
      if (rejectRate > 0.5) {
        var rlImpact = Math.round(rejectRate * 20);
        factors.push({ subsystem: 'rateLimiter', metric: 'rejectRate', value: rejectRate, threshold: 0.5, impact: rlImpact });
        penalties += rlImpact;
      }
    }

    var score = Math.max(0, 100 - penalties);
    var status = score >= 80 ? 'healthy' : score >= 50 ? 'degraded' : 'critical';

    return { score: score, status: status, factors: factors };
  }

  /**
   * Generate alerts from current stats.
   * @param {Object} stats
   * @param {{ score: number, status: string }} health
   * @returns {Object[]}
   */
  function _generateAlerts(stats, health) {
    var alerts = [];
    var now = Date.now();

    if (health.status === 'critical') {
      alerts.push({ level: 'critical', message: 'System health is critical (score: ' + health.score + ')', timestamp: now });
    } else if (health.status === 'degraded') {
      alerts.push({ level: 'warning', message: 'System health is degraded (score: ' + health.score + ')', timestamp: now });
    }

    for (var i = 0; i < health.factors.length; i++) {
      var f = health.factors[i];
      alerts.push({
        level: f.impact >= 20 ? 'critical' : 'warning',
        message: f.subsystem + '.' + f.metric + ' = ' + (typeof f.value === 'number' ? Math.round(f.value * 1000) / 1000 : f.value) + ' (threshold: ' + f.threshold + ')',
        timestamp: now,
        subsystem: f.subsystem,
        metric: f.metric,
      });
    }

    return alerts;
  }

  // ── Snapshot ──

  /**
   * Take a point-in-time snapshot of all subsystem metrics.
   * @returns {{ timestamp: number, subsystems: Object, health: Object, alerts: Object[], registeredCount: number }}
   */
  function snapshot() {
    var now = Date.now();
    var stats = Object.create(null);
    var names = Object.keys(subsystems);

    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var collected = _collectStats(subsystems[name]);
      if (collected !== null) {
        stats[name] = collected;
      }
    }

    var health = _computeHealth(stats);
    var alerts = _generateAlerts(stats, health);

    var snap = {
      timestamp: now,
      subsystems: stats,
      health: health,
      alerts: alerts,
      registeredCount: names.length,
    };

    history.push(snap);
    if (history.length > historySize) {
      history = history.slice(history.length - historySize);
    }

    // Notify alert listeners if there are new alerts
    if (alerts.length > 0) {
      for (var li = 0; li < alertListeners.length; li++) {
        try { alertListeners[li](alerts, snap); } catch (_ignored) {}
      }
    }

    return snap;
  }

  /**
   * Get the most recent snapshot without taking a new one.
   * @returns {Object|null}
   */
  function lastSnapshot() {
    return history.length > 0 ? history[history.length - 1] : null;
  }

  // ── Trends ──

  /**
   * Get historical trend data from stored snapshots.
   * @returns {{ snapshots: Object[], uptimeMs: number, snapshotCount: number, healthTrend: string|null }}
   */
  function getTrends() {
    var uptimeMs = Date.now() - startTime;
    var healthTrend = null;

    if (history.length >= 3) {
      var recentScores = [];
      var startIdx = Math.max(0, history.length - 5);
      for (var i = startIdx; i < history.length; i++) {
        recentScores.push(history[i].health.score);
      }
      var firstHalf = 0, secondHalf = 0;
      var mid = Math.floor(recentScores.length / 2);
      for (var j = 0; j < mid; j++) firstHalf += recentScores[j];
      for (var k = mid; k < recentScores.length; k++) secondHalf += recentScores[k];
      firstHalf /= mid;
      secondHalf /= (recentScores.length - mid);

      if (secondHalf > firstHalf + 5) healthTrend = 'improving';
      else if (secondHalf < firstHalf - 5) healthTrend = 'declining';
      else healthTrend = 'stable';
    }

    return {
      snapshots: history.slice(),
      uptimeMs: uptimeMs,
      snapshotCount: history.length,
      healthTrend: healthTrend,
    };
  }

  /**
   * Get a compact summary suitable for logging or external reporting.
   * @returns {Object}
   */
  function getSummary() {
    var snap = history.length > 0 ? history[history.length - 1] : snapshot();
    return {
      timestamp: snap.timestamp,
      healthScore: snap.health.score,
      healthStatus: snap.health.status,
      registeredCount: snap.registeredCount,
      alertCount: snap.alerts.length,
      criticalAlerts: snap.alerts.filter(function(a) { return a.level === 'critical'; }).length,
      uptimeMs: Date.now() - startTime,
      snapshotCount: history.length,
    };
  }

  /**
   * Clear all historical snapshots.
   */
  function clearHistory() {
    history = [];
  }

  /**
   * Reset everything — unregister all subsystems and clear history.
   */
  function reset() {
    stopAutoCapture();
    subsystems = Object.create(null);
    history = [];
    alertListeners = [];
  }

  // ── Auto-Capture ──

  /**
   * Start periodic auto-snapshots at the given interval.
   * Only one auto-capture timer can be active at a time; calling again
   * replaces the previous interval.
   *
   * @param {number} intervalMs  Capture interval in milliseconds (min 1000)
   * @returns {{ intervalMs: number, active: boolean }}
   */
  function startAutoCapture(intervalMs) {
    if (typeof intervalMs !== 'number' || intervalMs < 1000) {
      intervalMs = 60000; // default 60s
    }
    stopAutoCapture();
    autoCaptureTimer = setInterval(function () {
      snapshot();
    }, intervalMs);
    // Prevent timer from keeping Node.js process alive
    if (autoCaptureTimer && typeof autoCaptureTimer.unref === 'function') {
      autoCaptureTimer.unref();
    }
    return { intervalMs: intervalMs, active: true };
  }

  /**
   * Stop periodic auto-snapshots.
   * @returns {{ active: boolean }}
   */
  function stopAutoCapture() {
    if (autoCaptureTimer !== null) {
      clearInterval(autoCaptureTimer);
      autoCaptureTimer = null;
    }
    return { active: false };
  }

  /**
   * Check whether auto-capture is currently running.
   * @returns {boolean}
   */
  function isAutoCapturing() {
    return autoCaptureTimer !== null;
  }

  // ── Alert Listeners ──

  /**
   * Register a callback invoked whenever a snapshot produces alerts.
   * The callback receives (alerts, snapshot).
   *
   * @param {Function} callback
   * @returns {Function} Unsubscribe function
   */
  function onAlert(callback) {
    if (typeof callback !== 'function') {
      throw new Error('onAlert requires a function callback');
    }
    alertListeners.push(callback);
    return function unsubscribe() {
      var idx = alertListeners.indexOf(callback);
      if (idx !== -1) alertListeners.splice(idx, 1);
    };
  }

  // ── Export ──

  /**
   * Export snapshot history in the requested format.
   * Supported formats: 'json' (default) and 'csv'.
   *
   * CSV columns: timestamp, healthScore, healthStatus, registeredCount,
   *              alertCount, criticalAlerts
   *
   * @param {string} [format='json']  'json' or 'csv'
   * @returns {string}
   */
  function exportHistory(format) {
    var fmt = (format || 'json').toLowerCase();
    if (fmt === 'csv') {
      var header = 'timestamp,healthScore,healthStatus,registeredCount,alertCount,criticalAlerts';
      var rows = [header];
      for (var i = 0; i < history.length; i++) {
        var s = history[i];
        var critCount = 0;
        for (var a = 0; a < s.alerts.length; a++) {
          if (s.alerts[a].level === 'critical') critCount++;
        }
        rows.push([
          s.timestamp,
          s.health.score,
          s.health.status,
          s.registeredCount,
          s.alerts.length,
          critCount
        ].join(','));
      }
      return rows.join('\n');
    }
    // Default: JSON
    return JSON.stringify(history, null, 2);
  }

  return {
    register: register,
    unregister: unregister,
    listSubsystems: listSubsystems,
    snapshot: snapshot,
    lastSnapshot: lastSnapshot,
    getTrends: getTrends,
    getSummary: getSummary,
    clearHistory: clearHistory,
    reset: reset,
    startAutoCapture: startAutoCapture,
    stopAutoCapture: stopAutoCapture,
    isAutoCapturing: isAutoCapturing,
    onAlert: onAlert,
    exportHistory: exportHistory,
  };
}


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

  var weights = {};
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
    var copy = {};
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
    var allSignals = {};
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
    var state = {};
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


// ── Event Emitter ───────────────────────────────────────────────────
//
// Lightweight pub/sub for CAPTCHA lifecycle events.
//
// Usage:
//   var emitter = gifCaptcha.createEventEmitter();
//   emitter.on('challenge.created', function(data) { console.log(data); });
//   emitter.on('challenge.passed', function(data) { sendToAnalytics(data); });
//   emitter.emit('challenge.created', { id: 'abc', difficulty: 3 });
//
// Supported event conventions (users can use any string):
//   challenge.created   — a new challenge was generated
//   challenge.presented — challenge shown to user
//   challenge.answered  — user submitted an answer
//   challenge.passed    — answer accepted
//   challenge.failed    — answer rejected
//   challenge.expired   — challenge timed out
//   challenge.suspicious — bot-like behavior detected
//   session.started     — new verification session
//   session.completed   — session finished (pass or fail)
//
// Features:
//   .on(event, fn)       — subscribe (returns unsubscribe function)
//   .once(event, fn)     — subscribe for one firing only
//   .off(event, fn)      — unsubscribe specific handler
//   .emit(event, data)   — fire event, returns count of handlers called
//   .listeners(event)    — list handlers for an event
//   .removeAll([event])  — clear handlers (optionally for one event)
//   .pipe(otherEmitter)  — forward all events to another emitter

/**
 * Create an event emitter for CAPTCHA lifecycle hooks.
 *
 * @param {Object} [options]
 * @param {number} [options.maxListeners=50] Max listeners per event (0 = unlimited)
 * @param {function} [options.onError] Error handler for listener exceptions
 * @returns {Object} emitter instance
 */
function createEventEmitter(options) {
  var opts = options || {};
  var maxListeners = _nnOpt(opts.maxListeners, 50);
  var onError = typeof opts.onError === "function" ? opts.onError : null;
  var handlers = Object.create(null); // event → [{fn, once}]
  var pipes = [];

  function _ensure(event) {
    if (!handlers[event]) handlers[event] = [];
    return handlers[event];
  }

  /**
   * Subscribe to an event. Returns an unsubscribe function.
   * @param {string} event
   * @param {function} fn
   * @returns {function} unsubscribe
   */
  function on(event, fn) {
    if (typeof event !== "string" || typeof fn !== "function") return function () {};
    var list = _ensure(event);
    if (maxListeners > 0 && list.length >= maxListeners) {
      if (onError) onError(new Error("Max listeners (" + maxListeners + ") reached for event: " + event));
      return function () {};
    }
    var entry = { fn: fn, once: false };
    list.push(entry);
    return function () {
      var idx = list.indexOf(entry);
      if (idx !== -1) list.splice(idx, 1);
    };
  }

  /**
   * Subscribe to an event for a single firing.
   * @param {string} event
   * @param {function} fn
   * @returns {function} unsubscribe
   */
  function once(event, fn) {
    if (typeof event !== "string" || typeof fn !== "function") return function () {};
    var list = _ensure(event);
    if (maxListeners > 0 && list.length >= maxListeners) {
      if (onError) onError(new Error("Max listeners (" + maxListeners + ") reached for event: " + event));
      return function () {};
    }
    var entry = { fn: fn, once: true };
    list.push(entry);
    return function () {
      var idx = list.indexOf(entry);
      if (idx !== -1) list.splice(idx, 1);
    };
  }

  /**
   * Unsubscribe a specific handler from an event.
   * @param {string} event
   * @param {function} fn
   */
  function off(event, fn) {
    var list = handlers[event];
    if (!list) return;
    for (var i = list.length - 1; i >= 0; i--) {
      if (list[i].fn === fn) { list.splice(i, 1); break; }
    }
  }

  /**
   * Emit an event with optional data. Returns count of handlers invoked.
   * @param {string} event
   * @param {*} [data]
   * @returns {number}
   */
  function emit(event, data) {
    var count = 0;
    var list = handlers[event];
    if (list) {
      // Snapshot to allow modifications during iteration
      var snapshot = list.slice();
      for (var i = 0; i < snapshot.length; i++) {
        var entry = snapshot[i];
        if (entry.once) {
          var idx = list.indexOf(entry);
          if (idx !== -1) list.splice(idx, 1);
        }
        try {
          entry.fn(data);
        } catch (err) {
          if (onError) onError(err);
        }
        count++;
      }
    }
    // Wildcard listeners
    var wild = handlers["*"];
    if (wild) {
      var ws = wild.slice();
      for (var j = 0; j < ws.length; j++) {
        var we = ws[j];
        if (we.once) {
          var wi = wild.indexOf(we);
          if (wi !== -1) wild.splice(wi, 1);
        }
        try {
          we.fn({ event: event, data: data });
        } catch (err2) {
          if (onError) onError(err2);
        }
        count++;
      }
    }
    // Forward to piped emitters
    for (var p = 0; p < pipes.length; p++) {
      try { pipes[p].emit(event, data); } catch (_) {}
    }
    return count;
  }

  /**
   * List handler functions for an event.
   * @param {string} event
   * @returns {function[]}
   */
  function listeners(event) {
    var list = handlers[event];
    if (!list) return [];
    var result = [];
    for (var i = 0; i < list.length; i++) result.push(list[i].fn);
    return result;
  }

  /**
   * Remove all listeners, optionally for a specific event only.
   * @param {string} [event]
   */
  function removeAll(event) {
    if (event) {
      delete handlers[event];
    } else {
      handlers = Object.create(null);
    }
  }

  /**
   * Forward all events to another emitter.
   * @param {Object} otherEmitter Must have an emit(event, data) method
   * @returns {function} unpipe function
   */
  function pipe(otherEmitter) {
    if (!otherEmitter || typeof otherEmitter.emit !== "function") return function () {};
    pipes.push(otherEmitter);
    return function () {
      var idx = pipes.indexOf(otherEmitter);
      if (idx !== -1) pipes.splice(idx, 1);
    };
  }

  return {
    on: on,
    once: once,
    off: off,
    emit: emit,
    listeners: listeners,
    removeAll: removeAll,
    pipe: pipe
  };
}


// ── Internationalization ────────────────────────────────────────────

/**
 * createI18n — Localization support for CAPTCHA UI strings.
 *
 * Ships with built-in translations for common CAPTCHA labels, instructions,
 * error messages, and accessibility text.  Custom locales can be registered
 * at runtime.
 *
 * Supported built-in locales: en, es, fr, de, pt, ja, zh, ko, ar, hi, ru, it
 *
 * Usage:
 *   var i18n = gifCaptcha.createI18n({ locale: "es" });
 *   i18n.t("instructions");   // "Selecciona la imagen correcta..."
 *   i18n.t("error.timeout");  // "Tiempo agotado. Inténtalo de nuevo."
 *   i18n.t("greeting", { name: "Ana" }); // interpolation
 *   i18n.setLocale("fr");
 *   i18n.addLocale("th", { instructions: "เลือกภาพ..." });
 *
 * @param {Object} [options]
 * @param {string} [options.locale="en"]         Active locale
 * @param {string} [options.fallbackLocale="en"] Fallback when key missing
 * @param {Object} [options.locales]             Extra locale maps to merge
 * @returns {Object} i18n instance
 */
function createI18n(options) {
  options = options || {};
  var fallbackLocale = (typeof options.fallbackLocale === "string") ? options.fallbackLocale : "en";
  var currentLocale = (typeof options.locale === "string") ? options.locale : "en";

  var catalogs = {
    en: {
      "instructions":        "Select the correct image to prove you are human.",
      "instructions.audio":  "Listen to the audio and type what you hear.",
      "submit":              "Submit",
      "retry":               "Try Again",
      "loading":             "Loading challenge…",
      "success":             "Verification successful!",
      "error.generic":       "Something went wrong. Please try again.",
      "error.timeout":       "Time expired. Please try again.",
      "error.wrong":         "Incorrect answer. Please try again.",
      "error.tooMany":       "Too many attempts. Please wait before trying again.",
      "error.blocked":       "Access denied.",
      "accessibility.label": "CAPTCHA verification challenge",
      "accessibility.help":  "Complete this challenge to continue.",
      "timer.remaining":     "Time remaining: {seconds} seconds",
      "attempts.remaining":  "Attempts remaining: {count}",
      "difficulty.easy":     "Easy",
      "difficulty.medium":   "Medium",
      "difficulty.hard":     "Hard"
    },
    es: {
      "instructions":        "Selecciona la imagen correcta para demostrar que eres humano.",
      "instructions.audio":  "Escucha el audio y escribe lo que oyes.",
      "submit":              "Enviar",
      "retry":               "Intentar de nuevo",
      "loading":             "Cargando desafío…",
      "success":             "¡Verificación exitosa!",
      "error.generic":       "Algo salió mal. Inténtalo de nuevo.",
      "error.timeout":       "Tiempo agotado. Inténtalo de nuevo.",
      "error.wrong":         "Respuesta incorrecta. Inténtalo de nuevo.",
      "error.tooMany":       "Demasiados intentos. Espera antes de intentarlo de nuevo.",
      "error.blocked":       "Acceso denegado.",
      "accessibility.label": "Desafío de verificación CAPTCHA",
      "accessibility.help":  "Completa este desafío para continuar.",
      "timer.remaining":     "Tiempo restante: {seconds} segundos",
      "attempts.remaining":  "Intentos restantes: {count}",
      "difficulty.easy":     "Fácil",
      "difficulty.medium":   "Medio",
      "difficulty.hard":     "Difícil"
    },
    fr: {
      "instructions":        "Sélectionnez la bonne image pour prouver que vous êtes humain.",
      "instructions.audio":  "Écoutez l'audio et tapez ce que vous entendez.",
      "submit":              "Soumettre",
      "retry":               "Réessayer",
      "loading":             "Chargement du défi…",
      "success":             "Vérification réussie !",
      "error.generic":       "Une erreur est survenue. Veuillez réessayer.",
      "error.timeout":       "Temps écoulé. Veuillez réessayer.",
      "error.wrong":         "Réponse incorrecte. Veuillez réessayer.",
      "error.tooMany":       "Trop de tentatives. Veuillez patienter.",
      "error.blocked":       "Accès refusé.",
      "accessibility.label": "Défi de vérification CAPTCHA",
      "accessibility.help":  "Complétez ce défi pour continuer.",
      "timer.remaining":     "Temps restant : {seconds} secondes",
      "attempts.remaining":  "Tentatives restantes : {count}",
      "difficulty.easy":     "Facile",
      "difficulty.medium":   "Moyen",
      "difficulty.hard":     "Difficile"
    },
    de: {
      "instructions":        "Wählen Sie das richtige Bild, um zu beweisen, dass Sie ein Mensch sind.",
      "instructions.audio":  "Hören Sie sich das Audio an und geben Sie ein, was Sie hören.",
      "submit":              "Absenden",
      "retry":               "Erneut versuchen",
      "loading":             "Herausforderung wird geladen…",
      "success":             "Verifizierung erfolgreich!",
      "error.generic":       "Etwas ist schiefgelaufen. Bitte versuchen Sie es erneut.",
      "error.timeout":       "Zeit abgelaufen. Bitte versuchen Sie es erneut.",
      "error.wrong":         "Falsche Antwort. Bitte versuchen Sie es erneut.",
      "error.tooMany":       "Zu viele Versuche. Bitte warten Sie.",
      "error.blocked":       "Zugang verweigert.",
      "accessibility.label": "CAPTCHA-Verifizierungsaufgabe",
      "accessibility.help":  "Schließen Sie diese Aufgabe ab, um fortzufahren.",
      "timer.remaining":     "Verbleibende Zeit: {seconds} Sekunden",
      "attempts.remaining":  "Verbleibende Versuche: {count}",
      "difficulty.easy":     "Leicht",
      "difficulty.medium":   "Mittel",
      "difficulty.hard":     "Schwer"
    },
    pt: {
      "instructions":        "Selecione a imagem correta para provar que você é humano.",
      "submit":              "Enviar",
      "retry":               "Tentar novamente",
      "loading":             "Carregando desafio…",
      "success":             "Verificação bem-sucedida!",
      "error.generic":       "Algo deu errado. Tente novamente.",
      "error.timeout":       "Tempo esgotado. Tente novamente.",
      "error.wrong":         "Resposta incorreta. Tente novamente.",
      "error.tooMany":       "Muitas tentativas. Aguarde antes de tentar novamente.",
      "error.blocked":       "Acesso negado.",
      "accessibility.label": "Desafio de verificação CAPTCHA",
      "timer.remaining":     "Tempo restante: {seconds} segundos",
      "attempts.remaining":  "Tentativas restantes: {count}",
      "difficulty.easy":     "Fácil",
      "difficulty.medium":   "Médio",
      "difficulty.hard":     "Difícil"
    },
    ja: {
      "instructions":        "正しい画像を選択して、あなたが人間であることを証明してください。",
      "submit":              "送信",
      "retry":               "もう一度試す",
      "loading":             "チャレンジを読み込み中…",
      "success":             "認証成功！",
      "error.generic":       "エラーが発生しました。もう一度お試しください。",
      "error.timeout":       "時間切れです。もう一度お試しください。",
      "error.wrong":         "不正解です。もう一度お試しください。",
      "error.tooMany":       "試行回数が多すぎます。しばらくお待ちください。",
      "error.blocked":       "アクセスが拒否されました。",
      "accessibility.label": "CAPTCHA認証チャレンジ",
      "timer.remaining":     "残り時間: {seconds}秒",
      "attempts.remaining":  "残り試行回数: {count}",
      "difficulty.easy":     "簡単",
      "difficulty.medium":   "普通",
      "difficulty.hard":     "難しい"
    },
    zh: {
      "instructions":        "请选择正确的图片以证明您是人类。",
      "submit":              "提交",
      "retry":               "重试",
      "loading":             "正在加载验证…",
      "success":             "验证成功！",
      "error.generic":       "出现错误，请重试。",
      "error.timeout":       "已超时，请重试。",
      "error.wrong":         "回答不正确，请重试。",
      "error.tooMany":       "尝试次数过多，请稍后再试。",
      "error.blocked":       "访问被拒绝。",
      "accessibility.label": "CAPTCHA验证挑战",
      "timer.remaining":     "剩余时间：{seconds}秒",
      "attempts.remaining":  "剩余尝试次数：{count}",
      "difficulty.easy":     "简单",
      "difficulty.medium":   "中等",
      "difficulty.hard":     "困难"
    },
    ko: {
      "instructions":        "올바른 이미지를 선택하여 사람임을 증명하세요.",
      "submit":              "제출",
      "retry":               "다시 시도",
      "loading":             "챌린지 로딩 중…",
      "success":             "인증 성공!",
      "error.generic":       "오류가 발생했습니다. 다시 시도해 주세요.",
      "error.timeout":       "시간이 초과되었습니다. 다시 시도해 주세요.",
      "error.wrong":         "오답입니다. 다시 시도해 주세요.",
      "error.tooMany":       "시도 횟수를 초과했습니다. 잠시 후 다시 시도해 주세요.",
      "error.blocked":       "접근이 거부되었습니다.",
      "accessibility.label": "CAPTCHA 인증 챌린지",
      "timer.remaining":     "남은 시간: {seconds}초",
      "attempts.remaining":  "남은 시도 횟수: {count}",
      "difficulty.easy":     "쉬움",
      "difficulty.medium":   "보통",
      "difficulty.hard":     "어려움"
    },
    ar: {
      "instructions":        "اختر الصورة الصحيحة لإثبات أنك إنسان.",
      "submit":              "إرسال",
      "retry":               "حاول مرة أخرى",
      "loading":             "جارٍ تحميل التحدي…",
      "success":             "تم التحقق بنجاح!",
      "error.generic":       "حدث خطأ. يرجى المحاولة مرة أخرى.",
      "error.timeout":       "انتهى الوقت. يرجى المحاولة مرة أخرى.",
      "error.wrong":         "إجابة خاطئة. يرجى المحاولة مرة أخرى.",
      "error.tooMany":       "محاولات كثيرة جداً. يرجى الانتظار.",
      "error.blocked":       "تم رفض الوصول.",
      "accessibility.label": "تحدي التحقق CAPTCHA",
      "timer.remaining":     "الوقت المتبقي: {seconds} ثانية",
      "attempts.remaining":  "المحاولات المتبقية: {count}",
      "difficulty.easy":     "سهل",
      "difficulty.medium":   "متوسط",
      "difficulty.hard":     "صعب"
    },
    hi: {
      "instructions":        "यह साबित करने के लिए कि आप इंसान हैं, सही छवि चुनें।",
      "submit":              "जमा करें",
      "retry":               "पुनः प्रयास करें",
      "loading":             "चुनौती लोड हो रही है…",
      "success":             "सत्यापन सफल!",
      "error.generic":       "कुछ गलत हो गया। कृपया पुनः प्रयास करें।",
      "error.timeout":       "समय समाप्त। कृपया पुनः प्रयास करें।",
      "error.wrong":         "गलत उत्तर। कृपया पुनः प्रयास करें।",
      "error.tooMany":       "बहुत अधिक प्रयास। कृपया प्रतीक्षा करें।",
      "error.blocked":       "पहुँच अस्वीकृत।",
      "accessibility.label": "CAPTCHA सत्यापन चुनौती",
      "timer.remaining":     "शेष समय: {seconds} सेकंड",
      "attempts.remaining":  "शेष प्रयास: {count}",
      "difficulty.easy":     "आसान",
      "difficulty.medium":   "मध्यम",
      "difficulty.hard":     "कठिन"
    },
    ru: {
      "instructions":        "Выберите правильное изображение, чтобы подтвердить, что вы человек.",
      "submit":              "Отправить",
      "retry":               "Попробовать снова",
      "loading":             "Загрузка задания…",
      "success":             "Проверка пройдена!",
      "error.generic":       "Что-то пошло не так. Попробуйте ещё раз.",
      "error.timeout":       "Время истекло. Попробуйте ещё раз.",
      "error.wrong":         "Неправильный ответ. Попробуйте ещё раз.",
      "error.tooMany":       "Слишком много попыток. Подождите немного.",
      "error.blocked":       "Доступ запрещён.",
      "accessibility.label": "Задание проверки CAPTCHA",
      "timer.remaining":     "Осталось времени: {seconds} секунд",
      "attempts.remaining":  "Осталось попыток: {count}",
      "difficulty.easy":     "Легко",
      "difficulty.medium":   "Средне",
      "difficulty.hard":     "Сложно"
    },
    it: {
      "instructions":        "Seleziona l'immagine corretta per dimostrare che sei umano.",
      "submit":              "Invia",
      "retry":               "Riprova",
      "loading":             "Caricamento sfida…",
      "success":             "Verifica riuscita!",
      "error.generic":       "Qualcosa è andato storto. Riprova.",
      "error.timeout":       "Tempo scaduto. Riprova.",
      "error.wrong":         "Risposta errata. Riprova.",
      "error.tooMany":       "Troppi tentativi. Attendi prima di riprovare.",
      "error.blocked":       "Accesso negato.",
      "accessibility.label": "Sfida di verifica CAPTCHA",
      "timer.remaining":     "Tempo rimanente: {seconds} secondi",
      "attempts.remaining":  "Tentativi rimanenti: {count}",
      "difficulty.easy":     "Facile",
      "difficulty.medium":   "Medio",
      "difficulty.hard":     "Difficile"
    }
  };

  if (options.locales && typeof options.locales === "object") {
    var keys = Object.keys(options.locales);
    for (var i = 0; i < keys.length; i++) {
      addLocale(keys[i], options.locales[keys[i]]);
    }
  }

  function t(key, vars) {
    var catalog = catalogs[currentLocale];
    var str = (catalog && catalog[key]) || null;
    if (str === null) {
      var fb = catalogs[fallbackLocale];
      str = (fb && fb[key]) || key;
    }
    if (vars && typeof vars === "object") {
      var vkeys = Object.keys(vars);
      for (var i = 0; i < vkeys.length; i++) {
        str = str.split("{" + vkeys[i] + "}").join(String(vars[vkeys[i]]));
      }
    }
    return str;
  }

  function addLocale(locale, strings) {
    if (typeof locale !== "string" || !strings || typeof strings !== "object") return;
    if (!catalogs[locale]) catalogs[locale] = {};
    var keys = Object.keys(strings);
    for (var i = 0; i < keys.length; i++) {
      catalogs[locale][keys[i]] = String(strings[keys[i]]);
    }
  }

  function setLocale(locale) {
    if (typeof locale === "string") currentLocale = locale;
  }

  function getLocale() { return currentLocale; }

  function getAvailableLocales() { return Object.keys(catalogs); }

  function hasKey(key) {
    var catalog = catalogs[currentLocale];
    if (catalog && catalog[key] != null) return true;
    var fb = catalogs[fallbackLocale];
    return !!(fb && fb[key] != null);
  }

  function exportCatalog() {
    var result = {};
    var locales = Object.keys(catalogs);
    for (var i = 0; i < locales.length; i++) {
      result[locales[i]] = {};
      var keys = Object.keys(catalogs[locales[i]]);
      for (var j = 0; j < keys.length; j++) {
        result[locales[i]][keys[j]] = catalogs[locales[i]][keys[j]];
      }
    }
    return result;
  }

  return {
    t: t,
    addLocale: addLocale,
    setLocale: setLocale,
    getLocale: getLocale,
    getAvailableLocales: getAvailableLocales,
    hasKey: hasKey,
    exportCatalog: exportCatalog
  };
}


// ── Accessibility Auditor ───────────────────────────────────────────

/**
 * Create an accessibility auditor that checks CAPTCHA configurations
 * against WCAG 2.1 guidelines and produces actionable recommendations.
 *
 * The auditor evaluates:
 *   - Keyboard navigability (2.1.1)
 *   - Sufficient time (2.2.1)
 *   - Seizure safety / animation (2.3.1)
 *   - Text alternatives (1.1.1)
 *   - Color contrast & non-color cues (1.4.1, 1.4.3)
 *   - Error identification & suggestion (3.3.1, 3.3.3)
 *   - Focus visibility (2.4.7)
 *   - Touch target size (2.5.5 / 2.5.8)
 *   - Alternative access methods (non-visual)
 *
 * @param {Object} [options] - Auditor configuration
 * @param {string} [options.level="AA"] - Target conformance level: "A", "AA", or "AAA"
 * @param {boolean} [options.strict=false] - Treat warnings as failures
 * @returns {Object} Auditor instance
 *
 * @example
 *   var auditor = gifCaptcha.createAccessibilityAuditor({ level: "AA" });
 *   var report = auditor.audit({
 *     timeoutMs: 15000,
 *     hasAltText: true,
 *     hasKeyboardNav: true,
 *     hasAudioFallback: false,
 *     touchTargetPx: 40,
 *     animationDurationMs: 3000,
 *     flashesPerSecond: 2,
 *     hasErrorMessages: true,
 *     hasFocusIndicator: true,
 *     contrastRatio: 4.5,
 *     hasNonColorCues: true,
 *     maxAttempts: 5,
 *     hasSkipOption: false,
 *   });
 *   // report.score  → 0.78 (0–1)
 *   // report.grade  → "B"
 *   // report.issues → [{rule, severity, wcag, message, recommendation}]
 *   // report.passed → [{rule, wcag, message}]
 */
function createAccessibilityAuditor(options) {
  options = options || {};
  var level = (options.level || "AA").toUpperCase();
  if (level !== "A" && level !== "AA" && level !== "AAA") {
    throw new Error("Conformance level must be A, AA, or AAA");
  }
  var strict = !!options.strict;

  // Each rule: { id, wcag, level, check(config) → {pass, severity, message, recommendation} }
  var rules = [
    {
      id: "text-alternatives",
      wcag: "1.1.1",
      level: "A",
      check: function (c) {
        if (c.hasAltText) return { pass: true, message: "Images have text alternatives." };
        return {
          pass: false,
          severity: "error",
          message: "CAPTCHA images lack text alternatives.",
          recommendation: "Add descriptive alt text to all CAPTCHA images, or provide an audio/text fallback challenge."
        };
      }
    },
    {
      id: "non-color-cues",
      wcag: "1.4.1",
      level: "A",
      check: function (c) {
        if (c.hasNonColorCues !== false) return { pass: true, message: "Information is not conveyed by color alone." };
        return {
          pass: false,
          severity: "error",
          message: "Color is the sole indicator for some UI elements.",
          recommendation: "Add icons, patterns, or text labels alongside color cues (e.g. ✓/✗ icons for pass/fail)."
        };
      }
    },
    {
      id: "contrast-ratio",
      wcag: "1.4.3",
      level: "AA",
      check: function (c) {
        var ratio = c.contrastRatio != null ? c.contrastRatio : 4.5;
        var threshold = level === "AAA" ? 7.0 : 4.5;
        if (ratio >= threshold) return { pass: true, message: "Contrast ratio (" + ratio + ":1) meets " + level + " threshold (" + threshold + ":1)." };
        return {
          pass: false,
          severity: "warning",
          message: "Contrast ratio (" + ratio + ":1) is below " + level + " threshold (" + threshold + ":1).",
          recommendation: "Increase text/background contrast to at least " + threshold + ":1. Use darker text or lighter backgrounds."
        };
      }
    },
    {
      id: "keyboard-nav",
      wcag: "2.1.1",
      level: "A",
      check: function (c) {
        if (c.hasKeyboardNav) return { pass: true, message: "CAPTCHA is keyboard navigable." };
        return {
          pass: false,
          severity: "error",
          message: "CAPTCHA cannot be operated via keyboard alone.",
          recommendation: "Ensure all interactive elements are focusable (tabindex) and operable with Enter/Space. Add arrow-key navigation between options."
        };
      }
    },
    {
      id: "sufficient-time",
      wcag: "2.2.1",
      level: "A",
      check: function (c) {
        var timeout = c.timeoutMs != null ? c.timeoutMs : 30000;
        if (timeout === 0 || timeout === null) return { pass: true, message: "No time limit applied." };
        if (timeout >= 20000) return { pass: true, message: "Timeout (" + (timeout / 1000) + "s) provides sufficient time." };
        return {
          pass: false,
          severity: "warning",
          message: "Timeout (" + (timeout / 1000) + "s) may not provide sufficient time for users with disabilities.",
          recommendation: "Increase timeout to at least 20 seconds, or allow users to extend the time limit. Consider offering an 'extend time' button."
        };
      }
    },
    {
      id: "seizure-safety",
      wcag: "2.3.1",
      level: "A",
      check: function (c) {
        var fps = c.flashesPerSecond != null ? c.flashesPerSecond : 0;
        if (fps < 3) return { pass: true, message: "Animation is below the 3-flash-per-second threshold." };
        return {
          pass: false,
          severity: "error",
          message: "Animation flashes " + fps + " times per second, exceeding the safe threshold of 3.",
          recommendation: "Reduce animation speed below 3 flashes per second, or add a reduced-motion option (prefers-reduced-motion media query)."
        };
      }
    },
    {
      id: "animation-duration",
      wcag: "2.3.1",
      level: "A",
      check: function (c) {
        var dur = c.animationDurationMs != null ? c.animationDurationMs : 0;
        if (dur === 0) return { pass: true, message: "No auto-playing animation." };
        if (dur <= 5000) return { pass: true, message: "Animation duration (" + (dur / 1000) + "s) is within acceptable range." };
        return {
          pass: false,
          severity: "warning",
          message: "Animation plays for " + (dur / 1000) + "s which may be distracting.",
          recommendation: "Limit auto-play to 5 seconds or provide a pause/stop control. Respect prefers-reduced-motion."
        };
      }
    },
    {
      id: "focus-indicator",
      wcag: "2.4.7",
      level: "AA",
      check: function (c) {
        if (c.hasFocusIndicator !== false) return { pass: true, message: "Focus indicators are visible." };
        return {
          pass: false,
          severity: "error",
          message: "No visible focus indicator for keyboard users.",
          recommendation: "Add a visible focus ring (outline: 2px solid) to all interactive CAPTCHA elements. Never use outline:none without a replacement."
        };
      }
    },
    {
      id: "error-messages",
      wcag: "3.3.1",
      level: "A",
      check: function (c) {
        if (c.hasErrorMessages) return { pass: true, message: "Error messages are provided for failed attempts." };
        return {
          pass: false,
          severity: "warning",
          message: "No descriptive error messages on failed CAPTCHA attempts.",
          recommendation: "Provide clear error messages explaining what went wrong and how to retry. Use aria-live regions for screen reader announcements."
        };
      }
    },
    {
      id: "touch-target",
      wcag: "2.5.8",
      level: "AA",
      check: function (c) {
        var size = c.touchTargetPx != null ? c.touchTargetPx : 44;
        var threshold = level === "AAA" ? 44 : 24;
        if (size >= threshold) return { pass: true, message: "Touch targets (" + size + "px) meet minimum size (" + threshold + "px)." };
        return {
          pass: false,
          severity: "warning",
          message: "Touch targets (" + size + "px) are smaller than recommended minimum (" + threshold + "px).",
          recommendation: "Increase interactive element size to at least " + threshold + "px. Consider 44px for optimal mobile accessibility."
        };
      }
    },
    {
      id: "audio-fallback",
      wcag: "1.1.1",
      level: "A",
      check: function (c) {
        if (c.hasAudioFallback) return { pass: true, message: "Audio fallback challenge is available." };
        return {
          pass: false,
          severity: level === "AAA" ? "error" : "warning",
          message: "No audio fallback for visually impaired users.",
          recommendation: "Provide an audio-based CAPTCHA alternative so blind and low-vision users can complete verification."
        };
      }
    },
    {
      id: "skip-option",
      wcag: "3.3.3",
      level: "AAA",
      check: function (c) {
        if (c.hasSkipOption) return { pass: true, message: "Alternative verification method is available." };
        return {
          pass: false,
          severity: "info",
          message: "No alternative verification method if CAPTCHA is unsolvable.",
          recommendation: "Offer an email verification or support contact link as a fallback for users who cannot complete the CAPTCHA."
        };
      }
    },
    {
      id: "retry-limit",
      wcag: "3.3.3",
      level: "AA",
      check: function (c) {
        var max = c.maxAttempts != null ? c.maxAttempts : 5;
        if (max >= 3) return { pass: true, message: "Users get " + max + " attempts before lockout." };
        return {
          pass: false,
          severity: "warning",
          message: "Only " + max + " attempt(s) allowed, which may frustrate users with motor/cognitive disabilities.",
          recommendation: "Allow at least 3 attempts before lockout. Consider progressive delays instead of hard lockouts."
        };
      }
    }
  ];

  /**
   * Audit a CAPTCHA configuration.
   * @param {Object} config - Configuration properties to audit
   * @returns {Object} Audit report
   */
  function audit(config) {
    config = config || {};
    var issues = [];
    var passed = [];
    var levelWeight = { "A": 1, "AA": 2, "AAA": 3 };
    var targetWeight = levelWeight[level] || 2;

    for (var i = 0; i < rules.length; i++) {
      var rule = rules[i];
      var ruleWeight = levelWeight[rule.level] || 1;
      if (ruleWeight > targetWeight) continue; // skip rules above target level

      var result = rule.check(config);
      if (result.pass) {
        passed.push({ rule: rule.id, wcag: rule.wcag, message: result.message });
      } else {
        var severity = result.severity || "warning";
        if (strict && severity === "warning") severity = "error";
        issues.push({
          rule: rule.id,
          severity: severity,
          wcag: rule.wcag,
          level: rule.level,
          message: result.message,
          recommendation: result.recommendation || ""
        });
      }
    }

    var total = passed.length + issues.length;
    var score = total > 0 ? passed.length / total : 1;
    var errorCount = 0;
    var warningCount = 0;
    var infoCount = 0;
    for (var j = 0; j < issues.length; j++) {
      if (issues[j].severity === "error") errorCount++;
      else if (issues[j].severity === "warning") warningCount++;
      else infoCount++;
    }

    var grade;
    if (score >= 0.95 && errorCount === 0) grade = "A+";
    else if (score >= 0.9 && errorCount === 0) grade = "A";
    else if (score >= 0.8 && errorCount <= 1) grade = "B";
    else if (score >= 0.65) grade = "C";
    else if (score >= 0.5) grade = "D";
    else grade = "F";

    return {
      score: Math.round(score * 100) / 100,
      grade: grade,
      level: level,
      total: total,
      passedCount: passed.length,
      issueCount: issues.length,
      errorCount: errorCount,
      warningCount: warningCount,
      infoCount: infoCount,
      issues: issues,
      passed: passed,
      conformant: errorCount === 0
    };
  }

  /**
   * Get a plain-text summary of an audit report.
   * @param {Object} report - Report from audit()
   * @returns {string} Human-readable summary
   */
  function summarize(report) {
    var lines = [];
    lines.push("WCAG " + report.level + " Accessibility Audit — Grade: " + report.grade + " (" + (report.score * 100).toFixed(0) + "%)");
    lines.push("Passed: " + report.passedCount + " / " + report.total + " checks");
    if (report.conformant) {
      lines.push("✓ No critical accessibility errors found.");
    } else {
      lines.push("✗ " + report.errorCount + " critical error(s) must be fixed for " + report.level + " conformance.");
    }
    if (report.warningCount > 0) {
      lines.push("⚠ " + report.warningCount + " warning(s) should be addressed.");
    }
    lines.push("");
    if (report.issues.length > 0) {
      lines.push("Issues:");
      for (var i = 0; i < report.issues.length; i++) {
        var issue = report.issues[i];
        var icon = issue.severity === "error" ? "✗" : issue.severity === "warning" ? "⚠" : "ℹ";
        lines.push("  " + icon + " [WCAG " + issue.wcag + "] " + issue.message);
        if (issue.recommendation) {
          lines.push("    → " + issue.recommendation);
        }
      }
    }
    return lines.join("\n");
  }

  /**
   * List all rules the auditor checks.
   * @returns {Object[]} Array of {id, wcag, level} for each rule
   */
  function listRules() {
    var result = [];
    for (var i = 0; i < rules.length; i++) {
      result.push({ id: rules[i].id, wcag: rules[i].wcag, level: rules[i].level });
    }
    return result;
  }

  return {
    audit: audit,
    summarize: summarize,
    listRules: listRules
  };
}


// ── Configuration Validator ─────────────────────────────────────────
/**
 * createConfigValidator -- Validates CAPTCHA deployment configuration
 * objects against known constraints. Catches misconfigurations that
 * silently degrade security, performance, or usability before they
 * reach production.
 *
 * Checks:
 *  - Type correctness and range validation for all known options
 *  - Security warnings (weak secrets, disabled features)
 *  - Performance warnings (extreme timeouts, oversized pools)
 *  - Usability warnings (impossible difficulty, overly aggressive rate limiting)
 *  - Cross-field consistency (e.g. minPassRate >= maxPassRate)
 *
 * @param {Object} [options]
 * @param {boolean} [options.strict=false] - Treat warnings as errors
 * @param {string[]} [options.ignore] - Rule IDs to skip
 * @returns {{ validate: Function, rules: Function }}
 */
function createConfigValidator(options) {
  options = options || {};
  var strict = options.strict === true;
  var ignoreSet = Object.create(null);
  var ignoreList = options.ignore || [];
  for (var ig = 0; ig < ignoreList.length; ig++) {
    ignoreSet[ignoreList[ig]] = true;
  }

  // Severity levels
  var ERROR = "error";
  var WARNING = "warning";
  var INFO = "info";

  // ── Rule definitions ──────────────────────────────────────────

  var RULES = [
    // ── AttemptTracker ──
    {
      id: "attempt.maxAttempts.type",
      module: "attemptTracker",
      field: "maxAttempts",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.maxAttempts != null && (typeof cfg.maxAttempts !== "number" || cfg.maxAttempts < 1)) {
          return "maxAttempts must be a positive integer, got " + cfg.maxAttempts;
        }
      }
    },
    {
      id: "attempt.maxAttempts.low",
      module: "attemptTracker",
      field: "maxAttempts",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.maxAttempts === "number" && cfg.maxAttempts < 2) {
          return "maxAttempts=1 gives users no chance to retry — consider at least 3";
        }
      }
    },
    {
      id: "attempt.lockoutMs.type",
      module: "attemptTracker",
      field: "lockoutMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.lockoutMs != null && (typeof cfg.lockoutMs !== "number" || cfg.lockoutMs < 0)) {
          return "lockoutMs must be a non-negative number";
        }
      }
    },
    {
      id: "attempt.lockoutMs.short",
      module: "attemptTracker",
      field: "lockoutMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.lockoutMs === "number" && cfg.lockoutMs > 0 && cfg.lockoutMs < 1000) {
          return "lockoutMs under 1 second provides negligible brute-force protection";
        }
      }
    },
    {
      id: "attempt.lockoutMs.long",
      module: "attemptTracker",
      field: "lockoutMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.lockoutMs === "number" && cfg.lockoutMs > 3600000) {
          return "lockoutMs over 1 hour may frustrate legitimate users (" + Math.round(cfg.lockoutMs / 60000) + " min)";
        }
      }
    },
    // ── TokenVerifier ──
    {
      id: "token.secret.missing",
      module: "tokenVerifier",
      field: "secret",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.secret != null && typeof cfg.secret !== "string") {
          return "secret must be a string";
        }
      }
    },
    {
      id: "token.secret.weak",
      module: "tokenVerifier",
      field: "secret",
      severity: ERROR,
      check: function (cfg) {
        if (typeof cfg.secret === "string" && cfg.secret.length < 16) {
          return "secret must be at least 16 characters for HMAC security (got " + cfg.secret.length + ")";
        }
      }
    },
    {
      id: "token.secret.entropy",
      module: "tokenVerifier",
      field: "secret",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.secret === "string" && cfg.secret.length >= 16) {
          // Check for low-entropy patterns
          var unique = Object.create(null);
          for (var i = 0; i < cfg.secret.length; i++) { unique[cfg.secret[i]] = true; }
          var count = 0;
          for (var k in unique) { count++; }
          if (count < 6) {
            return "secret has very low character diversity (" + count + " unique chars) — use a random generator";
          }
        }
      }
    },
    {
      id: "token.ttlMs.type",
      module: "tokenVerifier",
      field: "ttlMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.ttlMs != null && (typeof cfg.ttlMs !== "number" || cfg.ttlMs < 1)) {
          return "ttlMs must be a positive number";
        }
      }
    },
    {
      id: "token.ttlMs.short",
      module: "tokenVerifier",
      field: "ttlMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.ttlMs === "number" && cfg.ttlMs < 10000) {
          return "ttlMs under 10 seconds may expire before users complete the CAPTCHA";
        }
      }
    },
    // ── BotDetector ──
    {
      id: "bot.threshold.range",
      module: "botDetector",
      field: "botThreshold",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.botThreshold != null && (typeof cfg.botThreshold !== "number" || cfg.botThreshold < 0 || cfg.botThreshold > 100)) {
          return "botThreshold must be 0-100, got " + cfg.botThreshold;
        }
      }
    },
    {
      id: "bot.threshold.inverted",
      module: "botDetector",
      field: "botThreshold",
      severity: ERROR,
      check: function (cfg) {
        if (typeof cfg.botThreshold === "number" && typeof cfg.suspiciousThreshold === "number") {
          if (cfg.suspiciousThreshold >= cfg.botThreshold) {
            return "suspiciousThreshold (" + cfg.suspiciousThreshold + ") should be less than botThreshold (" + cfg.botThreshold + ")";
          }
        }
      }
    },
    {
      id: "bot.minMouseMovements.type",
      module: "botDetector",
      field: "minMouseMovements",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.minMouseMovements != null && (typeof cfg.minMouseMovements !== "number" || cfg.minMouseMovements < 0)) {
          return "minMouseMovements must be a non-negative number";
        }
      }
    },
    {
      id: "bot.minTimeOnPage.type",
      module: "botDetector",
      field: "minTimeOnPageMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.minTimeOnPageMs != null && (typeof cfg.minTimeOnPageMs !== "number" || cfg.minTimeOnPageMs < 0)) {
          return "minTimeOnPageMs must be a non-negative number";
        }
      }
    },
    // ── DifficultyCalibrator ──
    {
      id: "difficulty.passRate.range",
      module: "difficultyCalibrator",
      field: "minPassRate",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.minPassRate != null && (typeof cfg.minPassRate !== "number" || cfg.minPassRate < 0 || cfg.minPassRate > 1)) {
          return "minPassRate must be 0-1, got " + cfg.minPassRate;
        }
      }
    },
    {
      id: "difficulty.passRate.inverted",
      module: "difficultyCalibrator",
      field: "minPassRate",
      severity: ERROR,
      check: function (cfg) {
        if (typeof cfg.minPassRate === "number" && typeof cfg.maxPassRate === "number") {
          if (cfg.minPassRate >= cfg.maxPassRate) {
            return "minPassRate (" + cfg.minPassRate + ") must be less than maxPassRate (" + cfg.maxPassRate + ") — no valid calibration range";
          }
        }
      }
    },
    {
      id: "difficulty.base.range",
      module: "difficultyCalibrator",
      field: "baseDifficulty",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.baseDifficulty != null && (typeof cfg.baseDifficulty !== "number" || cfg.baseDifficulty < 0 || cfg.baseDifficulty > 100)) {
          return "baseDifficulty must be 0-100";
        }
      }
    },
    {
      id: "difficulty.base.exceeds.max",
      module: "difficultyCalibrator",
      field: "baseDifficulty",
      severity: ERROR,
      check: function (cfg) {
        if (typeof cfg.baseDifficulty === "number" && typeof cfg.maxDifficulty === "number") {
          if (cfg.baseDifficulty > cfg.maxDifficulty) {
            return "baseDifficulty (" + cfg.baseDifficulty + ") exceeds maxDifficulty (" + cfg.maxDifficulty + ")";
          }
        }
      }
    },
    // ── RateLimiter ──
    {
      id: "rate.windowMs.type",
      module: "rateLimiter",
      field: "windowMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.windowMs != null && (typeof cfg.windowMs !== "number" || cfg.windowMs < 1)) {
          return "windowMs must be a positive number";
        }
      }
    },
    {
      id: "rate.maxRequests.type",
      module: "rateLimiter",
      field: "maxRequests",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.maxRequests != null && (typeof cfg.maxRequests !== "number" || cfg.maxRequests < 1)) {
          return "maxRequests must be a positive integer";
        }
      }
    },
    {
      id: "rate.maxRequests.aggressive",
      module: "rateLimiter",
      field: "maxRequests",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.maxRequests === "number" && typeof cfg.windowMs === "number") {
          var perMinute = (cfg.maxRequests / cfg.windowMs) * 60000;
          if (perMinute < 2) {
            return "Rate limit allows fewer than 2 requests/minute — legitimate users may be blocked";
          }
        }
      }
    },
    // ── ReputationTracker ──
    {
      id: "reputation.threshold.inverted",
      module: "reputationTracker",
      field: "trustedThreshold",
      severity: ERROR,
      check: function (cfg) {
        var trusted = typeof cfg.trustedThreshold === "number" ? cfg.trustedThreshold : 0.8;
        var suspicious = typeof cfg.suspiciousThreshold === "number" ? cfg.suspiciousThreshold : 0.3;
        var block = typeof cfg.blockThreshold === "number" ? cfg.blockThreshold : 0.1;
        if (cfg.trustedThreshold != null || cfg.suspiciousThreshold != null || cfg.blockThreshold != null) {
          if (!(block < suspicious && suspicious < trusted)) {
            return "Reputation thresholds must be: blockThreshold < suspiciousThreshold < trustedThreshold (got " + block + " / " + suspicious + " / " + trusted + ")";
          }
        }
      }
    },
    {
      id: "reputation.initialScore.range",
      module: "reputationTracker",
      field: "initialScore",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.initialScore != null && (typeof cfg.initialScore !== "number" || cfg.initialScore < 0 || cfg.initialScore > 1)) {
          return "initialScore must be 0-1, got " + cfg.initialScore;
        }
      }
    },
    {
      id: "reputation.maxEntries.low",
      module: "reputationTracker",
      field: "maxEntries",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.maxEntries === "number" && cfg.maxEntries < 100) {
          return "maxEntries under 100 causes frequent evictions — reputation data won't accumulate";
        }
      }
    },
    // ── PoolManager ──
    {
      id: "pool.rotationInterval.type",
      module: "poolManager",
      field: "rotationIntervalMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.rotationIntervalMs != null && (typeof cfg.rotationIntervalMs !== "number" || cfg.rotationIntervalMs < 1)) {
          return "rotationIntervalMs must be a positive number";
        }
      }
    },
    {
      id: "pool.rotation.fast",
      module: "poolManager",
      field: "rotationIntervalMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.rotationIntervalMs === "number" && cfg.rotationIntervalMs < 30000) {
          return "Rotation interval under 30 seconds may cause cache misses and increased load";
        }
      }
    },
    // ── AdaptiveTimeout ──
    {
      id: "timeout.base.type",
      module: "adaptiveTimeout",
      field: "baseTimeoutMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.baseTimeoutMs != null && (typeof cfg.baseTimeoutMs !== "number" || cfg.baseTimeoutMs < 1)) {
          return "baseTimeoutMs must be a positive number";
        }
      }
    },
    {
      id: "timeout.base.short",
      module: "adaptiveTimeout",
      field: "baseTimeoutMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.baseTimeoutMs === "number" && cfg.baseTimeoutMs < 5000) {
          return "baseTimeoutMs under 5 seconds may not give users enough time to solve CAPTCHAs";
        }
      }
    },
    // ── General ──
    {
      id: "general.passThreshold.range",
      module: "general",
      field: "passThreshold",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.passThreshold != null && (typeof cfg.passThreshold !== "number" || cfg.passThreshold < 0 || cfg.passThreshold > 1)) {
          return "passThreshold must be 0-1, got " + cfg.passThreshold;
        }
      }
    },
    {
      id: "general.passThreshold.extreme",
      module: "general",
      field: "passThreshold",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.passThreshold === "number") {
          if (cfg.passThreshold > 0.95) {
            return "passThreshold above 0.95 means users must answer nearly every challenge correctly";
          }
          if (cfg.passThreshold < 0.3) {
            return "passThreshold below 0.3 means bots can pass by guessing — security is degraded";
          }
        }
      }
    },
    {
      id: "general.challenges.count",
      module: "general",
      field: "challengeCount",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.challengeCount === "number" && cfg.challengeCount > 10) {
          return "More than 10 challenges per session creates user fatigue — completion rates will drop";
        }
      }
    }
  ];

  // ── Validation engine ─────────────────────────────────────────

  /**
   * Validate a configuration object.
   *
   * @param {Object} config - The config to validate
   * @param {Object} [opts]
   * @param {string} [opts.module] - Only check rules for a specific module
   * @returns {{ valid: boolean, errors: Array, warnings: Array, info: Array, summary: string }}
   */
  function validate(config) {
    var opts = arguments.length > 1 ? arguments[1] : {};
    config = config || {};
    var moduleFilter = opts.module || null;
    var errors = [];
    var warnings = [];
    var infos = [];

    for (var i = 0; i < RULES.length; i++) {
      var rule = RULES[i];

      // Skip ignored rules
      if (ignoreSet[rule.id]) { continue; }

      // Module filter
      if (moduleFilter && rule.module !== moduleFilter) { continue; }

      var message = rule.check(config);
      if (message) {
        var finding = {
          id: rule.id,
          module: rule.module,
          field: rule.field,
          severity: rule.severity,
          message: message
        };

        if (rule.severity === ERROR) {
          errors.push(finding);
        } else if (rule.severity === WARNING) {
          if (strict) {
            errors.push(finding);
          } else {
            warnings.push(finding);
          }
        } else {
          infos.push(finding);
        }
      }
    }

    var valid = errors.length === 0;

    var parts = [];
    if (errors.length > 0) { parts.push(errors.length + " error(s)"); }
    if (warnings.length > 0) { parts.push(warnings.length + " warning(s)"); }
    if (infos.length > 0) { parts.push(infos.length + " info"); }
    var summary = valid
      ? (warnings.length > 0 ? "Valid with " + warnings.length + " warning(s)" : "Valid — no issues found")
      : "Invalid — " + parts.join(", ");

    return {
      valid: valid,
      errors: errors,
      warnings: warnings,
      info: infos,
      summary: summary
    };
  }

  /**
   * Get the list of all validation rules.
   *
   * @returns {Array<{ id: string, module: string, field: string, severity: string }>}
   */
  function rules() {
    var result = [];
    for (var i = 0; i < RULES.length; i++) {
      var r = RULES[i];
      result.push({
        id: r.id,
        module: r.module,
        field: r.field,
        severity: r.severity
      });
    }
    return result;
  }

  return {
    validate: validate,
    rules: rules
  };
}



// -- Challenge Analytics ---------------------------------------------------

/**
 * Create a challenge analytics engine that tracks per-challenge performance
 * metrics: solve rates, timing distributions, abandonment, difficulty
 * effectiveness, and pool diversity scoring.
 *
 * @param {Object} [options]
 * @param {number} [options.maxChallenges=500]  Max tracked challenge IDs
 * @param {number} [options.maxEventsPerChallenge=200]  Events kept per ID
 * @returns {Object} Challenge analytics instance
 */
function createChallengeAnalytics(options) {
  var opts = options || {};
  var maxChallenges = Math.max(1, opts.maxChallenges || 500);
  var maxEventsPerChallenge = Math.max(1, opts.maxEventsPerChallenge || 200);

  // challengeId -> { events: [], stats cache }
  var store = Object.create(null);
  var challengeCount = 0;
  var evictionOrder = new LruTracker();  // true LRU via doubly-linked list

  function _ensureEntry(challengeId) {
    if (store[challengeId]) {
      evictionOrder.push(challengeId);  // promote to most-recently-used
      return store[challengeId];
    }
    if (challengeCount >= maxChallenges) {
      // Evict least-recently-used
      var oldest = evictionOrder.evictOldest();
      if (oldest !== undefined && store[oldest]) {
        delete store[oldest];
        challengeCount--;
      }
    }
    store[challengeId] = { events: [], dirty: true };
    challengeCount++;
    evictionOrder.push(challengeId);
    return store[challengeId];
  }

  /**
   * Record a challenge attempt event.
   * @param {Object} event
   * @param {string} event.challengeId
   * @param {boolean} event.correct - Whether the answer was correct
   * @param {number} event.timeMs - Time taken in milliseconds
   * @param {boolean} [event.abandoned] - Whether the user abandoned
   * @param {number} [event.difficulty] - Difficulty level (1-10)
   * @param {string} [event.clientId] - Optional client identifier
   */
  function record(event) {
    if (!event || typeof event.challengeId !== 'string') {
      throw new Error('event.challengeId is required');
    }
    if (typeof event.correct !== 'boolean' && !event.abandoned) {
      throw new Error('event.correct (boolean) is required unless abandoned');
    }
    var entry = _ensureEntry(event.challengeId);
    var ev = {
      correct: !!event.correct,
      timeMs: typeof event.timeMs === 'number' ? event.timeMs : 0,
      abandoned: !!event.abandoned,
      difficulty: typeof event.difficulty === 'number' ? event.difficulty : null,
      clientId: event.clientId || null,
      ts: _now(),
    };
    entry.events.push(ev);
    if (entry.events.length > maxEventsPerChallenge) {
      entry.events.shift();
    }
    entry.dirty = true;
  }

  /**
   * Get detailed stats for a single challenge.
   * @param {string} challengeId
   * @returns {Object|null} Stats object or null if not found
   */
  function getChallengeStats(challengeId) {
    var entry = store[challengeId];
    if (!entry || entry.events.length === 0) return null;

    var events = entry.events;
    var total = events.length;
    var correct = 0;
    var abandoned = 0;
    var times = [];
    var correctTimes = [];
    var incorrectTimes = [];
    var difficulties = [];

    for (var i = 0; i < total; i++) {
      var ev = events[i];
      if (ev.abandoned) {
        abandoned++;
        continue;
      }
      if (ev.correct) {
        correct++;
        if (ev.timeMs > 0) correctTimes.push(ev.timeMs);
      } else {
        if (ev.timeMs > 0) incorrectTimes.push(ev.timeMs);
      }
      if (ev.timeMs > 0) times.push(ev.timeMs);
      if (ev.difficulty !== null) difficulties.push(ev.difficulty);
    }

    var attempted = total - abandoned;
    var solveRate = attempted > 0 ? correct / attempted : 0;
    var abandonRate = total > 0 ? abandoned / total : 0;

    return {
      challengeId: challengeId,
      totalEvents: total,
      attempted: attempted,
      correct: correct,
      incorrect: attempted - correct,
      abandoned: abandoned,
      solveRate: Math.round(solveRate * 10000) / 10000,
      abandonRate: Math.round(abandonRate * 10000) / 10000,
      timing: _computeTimingStats(times),
      correctTiming: _computeTimingStats(correctTimes),
      incorrectTiming: _computeTimingStats(incorrectTimes),
      avgDifficulty: difficulties.length > 0
        ? Math.round(_mean(difficulties) * 100) / 100
        : null,
    };
  }

  /**
   * Get a ranked leaderboard of challenges by a metric.
   * @param {Object} [opts]
   * @param {string} [opts.sortBy='solveRate'] - Metric to sort by
   * @param {string} [opts.order='asc'] - 'asc' or 'desc'
   * @param {number} [opts.minEvents=5] - Minimum events to include
   * @param {number} [opts.limit=20] - Max results
   * @returns {Object[]} Ranked challenge stats
   */
  function ranking(opts) {
    opts = opts || {};
    var sortBy = opts.sortBy || 'solveRate';
    var order = opts.order || 'asc';
    var minEvents = typeof opts.minEvents === 'number' ? opts.minEvents : 5;
    var limit = typeof opts.limit === 'number' ? opts.limit : 20;

    var results = [];
    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      var stats = getChallengeStats(ids[i]);
      if (!stats || stats.totalEvents < minEvents) continue;
      results.push(stats);
    }

    results.sort(function (a, b) {
      var va = _extractMetric(a, sortBy);
      var vb = _extractMetric(b, sortBy);
      return order === 'desc' ? vb - va : va - vb;
    });

    if (limit > 0 && results.length > limit) {
      results = results.slice(0, limit);
    }
    return results;
  }

  function _extractMetric(stats, metric) {
    if (metric === 'solveRate') return stats.solveRate;
    if (metric === 'abandonRate') return stats.abandonRate;
    if (metric === 'avgTime') return stats.timing.mean || 0;
    if (metric === 'totalEvents') return stats.totalEvents;
    if (metric === 'medianTime') return stats.timing.median || 0;
    return 0;
  }

  /**
   * Compute aggregate pool-level statistics across all tracked challenges.
   * @returns {Object} Pool-level metrics
   */
  function poolStats() {
    var ids = Object.keys(store);
    var totalChallenges = ids.length;
    var totalEvents = 0;
    var totalCorrect = 0;
    var totalAttempted = 0;
    var totalAbandoned = 0;
    var solveRates = [];
    var abandonRates = [];

    for (var i = 0; i < ids.length; i++) {
      var stats = getChallengeStats(ids[i]);
      if (!stats) continue;
      totalEvents += stats.totalEvents;
      totalCorrect += stats.correct;
      totalAttempted += stats.attempted;
      totalAbandoned += stats.abandoned;
      if (stats.attempted >= 3) {
        solveRates.push(stats.solveRate);
        abandonRates.push(stats.abandonRate);
      }
    }

    var overallSolveRate = totalAttempted > 0 ? totalCorrect / totalAttempted : 0;

    return {
      totalChallenges: totalChallenges,
      totalEvents: totalEvents,
      totalAttempted: totalAttempted,
      totalCorrect: totalCorrect,
      totalAbandoned: totalAbandoned,
      overallSolveRate: Math.round(overallSolveRate * 10000) / 10000,
      solveRateDistribution: solveRates.length > 0 ? _computeTimingStats(solveRates) : null,
      abandonRateDistribution: abandonRates.length > 0 ? _computeTimingStats(abandonRates) : null,
      diversity: _computeDiversity(solveRates),
    };
  }

  /**
   * Identify challenges that may need attention.
   * @param {Object} [thresholds]
   * @param {number} [thresholds.tooEasy=0.95] - Solve rate above this = too easy
   * @param {number} [thresholds.tooHard=0.15] - Solve rate below this = too hard
   * @param {number} [thresholds.highAbandon=0.4] - Abandon rate above this = problematic
   * @param {number} [thresholds.minEvents=10] - Min events to flag
   * @returns {{ tooEasy: Object[], tooHard: Object[], highAbandon: Object[] }}
   */
  function flagged(thresholds) {
    thresholds = thresholds || {};
    var tooEasyThreshold = typeof thresholds.tooEasy === 'number' ? thresholds.tooEasy : 0.95;
    var tooHardThreshold = typeof thresholds.tooHard === 'number' ? thresholds.tooHard : 0.15;
    var highAbandonThreshold = typeof thresholds.highAbandon === 'number' ? thresholds.highAbandon : 0.4;
    var minEvents = typeof thresholds.minEvents === 'number' ? thresholds.minEvents : 10;

    var tooEasy = [];
    var tooHard = [];
    var highAbandon = [];

    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      var stats = getChallengeStats(ids[i]);
      if (!stats || stats.totalEvents < minEvents) continue;
      if (stats.solveRate >= tooEasyThreshold) tooEasy.push(stats);
      if (stats.solveRate <= tooHardThreshold && stats.attempted > 0) tooHard.push(stats);
      if (stats.abandonRate >= highAbandonThreshold) highAbandon.push(stats);
    }

    tooEasy.sort(function (a, b) { return b.solveRate - a.solveRate; });
    tooHard.sort(function (a, b) { return a.solveRate - b.solveRate; });
    highAbandon.sort(function (a, b) { return b.abandonRate - a.abandonRate; });

    return { tooEasy: tooEasy, tooHard: tooHard, highAbandon: highAbandon };
  }

  /**
   * Compute difficulty effectiveness — how well different difficulty
   * levels discriminate between humans and bots.
   * @returns {Object[]} Array of { difficulty, solveRate, avgTime, count }
   */
  function difficultyEffectiveness() {
    var buckets = Object.create(null);  // difficulty -> { correct, total, times }

    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      var events = store[ids[i]].events;
      for (var j = 0; j < events.length; j++) {
        var ev = events[j];
        if (ev.difficulty === null || ev.abandoned) continue;
        var d = Math.round(ev.difficulty);
        if (!buckets[d]) buckets[d] = { correct: 0, total: 0, times: [] };
        buckets[d].total++;
        if (ev.correct) buckets[d].correct++;
        if (ev.timeMs > 0) buckets[d].times.push(ev.timeMs);
      }
    }

    var result = [];
    var diffs = Object.keys(buckets).sort(function (a, b) { return +a - +b; });
    for (var k = 0; k < diffs.length; k++) {
      var d = +diffs[k];
      var b = buckets[d];
      result.push({
        difficulty: d,
        solveRate: b.total > 0 ? Math.round(b.correct / b.total * 10000) / 10000 : 0,
        avgTimeMs: b.times.length > 0 ? Math.round(_mean(b.times)) : 0,
        count: b.total,
      });
    }
    return result;
  }

  /**
   * Compute time-of-day patterns across all challenges.
   * Returns solve rates bucketed by hour (0-23).
   * @returns {Object[]} Array of { hour, solveRate, count }
   */
  function hourlyPatterns() {
    var buckets = [];
    for (var h = 0; h < 24; h++) {
      buckets.push({ correct: 0, total: 0 });
    }

    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      var events = store[ids[i]].events;
      for (var j = 0; j < events.length; j++) {
        var ev = events[j];
        if (ev.abandoned) continue;
        var hour = new Date(ev.ts).getHours();
        buckets[hour].total++;
        if (ev.correct) buckets[hour].correct++;
      }
    }

    var result = [];
    for (var k = 0; k < 24; k++) {
      result.push({
        hour: k,
        solveRate: buckets[k].total > 0
          ? Math.round(buckets[k].correct / buckets[k].total * 10000) / 10000
          : 0,
        count: buckets[k].total,
      });
    }
    return result;
  }

  /**
   * Export/import state for persistence.
   */
  function exportState() {
    var data = Object.create(null);
    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      data[ids[i]] = store[ids[i]].events.slice();
    }
    return { version: 1, challenges: data, exportedAt: new Date().toISOString() };
  }

  function importState(state) {
    if (!state || typeof state !== 'object' || !state.challenges) {
      throw new Error('Invalid state: must have challenges object');
    }
    reset();
    var ids = Object.keys(state.challenges);
    for (var i = 0; i < ids.length; i++) {
      var entry = _ensureEntry(ids[i]);
      var events = state.challenges[ids[i]];
      if (Array.isArray(events)) {
        entry.events = events.slice(0, maxEventsPerChallenge);
      }
    }
  }

  /**
   * Get summary with stats for getStats() compatibility.
   */
  function getStats() {
    return poolStats();
  }

  function reset() {
    store = Object.create(null);
    challengeCount = 0;
    evictionOrder.clear();
  }

  // -- Internal helpers --
  // _mean, _median, _stddev are provided by shared top-level helpers

  function _percentile(arr, p) {
    if (arr.length === 0) return 0;
    var sorted = arr.slice().sort(_numAsc);
    var idx = (p / 100) * (sorted.length - 1);
    var lo = Math.floor(idx);
    var hi = Math.ceil(idx);
    if (lo === hi) return sorted[lo];
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
  }

  function _computeTimingStats(arr) {
    if (arr.length === 0) return { count: 0, mean: 0, median: 0, stddev: 0, p5: 0, p95: 0, min: 0, max: 0 };
    var m = _mean(arr);
    var sorted = arr.slice().sort(_numAsc);
    return {
      count: arr.length,
      mean: Math.round(m * 100) / 100,
      median: Math.round(_median(arr) * 100) / 100,
      stddev: Math.round(_stddev(arr, m) * 100) / 100,
      p5: Math.round(_percentile(arr, 5) * 100) / 100,
      p95: Math.round(_percentile(arr, 95) * 100) / 100,
      min: sorted[0],
      max: sorted[sorted.length - 1],
    };
  }

  function _computeDiversity(solveRates) {
    if (solveRates.length < 2) return { score: 0, label: 'insufficient data' };
    var m = _mean(solveRates);
    var sd = _stddev(solveRates, m);
    // Coefficient of variation (higher = more diverse solve rates)
    var cv = m > 0 ? sd / m : 0;
    var score = _clamp(Math.round(cv * 100), 0, 100);
    var label = score < 15 ? 'low' : score < 40 ? 'moderate' : 'high';
    return { score: score, label: label, cv: Math.round(cv * 1000) / 1000 };
  }

  return {
    record: record,
    getChallengeStats: getChallengeStats,
    ranking: ranking,
    poolStats: poolStats,
    flagged: flagged,
    difficultyEffectiveness: difficultyEffectiveness,
    hourlyPatterns: hourlyPatterns,
    exportState: exportState,
    importState: importState,
    getStats: getStats,
    reset: reset,
  };
}

// ── Haversine distance (km) ─────────────────────────────────────────
function _haversineKm(lat1, lon1, lat2, lon2) {
  var R = 6371;
  var dLat = (lat2 - lat1) * Math.PI / 180;
  var dLon = (lon2 - lon1) * Math.PI / 180;
  var a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// ── Default risk tiers ──────────────────────────────────────────────
var DEFAULT_HIGH_RISK = ["CN", "RU", "KP", "IR", "NG", "VN", "PK", "BD"];
var DEFAULT_MEDIUM_RISK = ["BR", "IN", "ID", "PH", "UA", "RO", "TH", "EG"];

// ── Thresholds ──────────────────────────────────────────────────────
var IMPOSSIBLE_TRAVEL_SPEED_KMH = 900; // faster than commercial flight
var SUSPICIOUS_TRAVEL_SPEED_KMH = 300;
var VELOCITY_WINDOW_MS = 3600000; // 1 hour

function createGeoRiskScorer(options) {
  options = options || {};

  var highRisk = options.highRiskCountries || DEFAULT_HIGH_RISK;
  var mediumRisk = options.mediumRiskCountries || DEFAULT_MEDIUM_RISK;
  var impossibleSpeedKmh = options.impossibleTravelSpeedKmh || IMPOSSIBLE_TRAVEL_SPEED_KMH;
  var suspiciousSpeedKmh = options.suspiciousTravelSpeedKmh || SUSPICIOUS_TRAVEL_SPEED_KMH;
  var velocityWindowMs = options.velocityWindowMs || VELOCITY_WINDOW_MS;
  var maxHistory = options.maxHistory || 500;

  // Thresholds for action mapping
  var thresholds = options.thresholds || {};
  var blockThreshold = thresholds.block || 0.8;
  var challengeThreshold = thresholds.challenge || 0.5;
  var warnThreshold = thresholds.warn || 0.3;

  // IP history for velocity checks: { ip: [{ lat, lon, ts, country }] }
  var _ipHistory = Object.create(null);
  // Session history for geo-hopping: { sessionId: [{ country, ts }] }
  var _sessionGeo = Object.create(null);
  // Regional stats: { country: { attempts, solves } }
  var _regionStats = Object.create(null);
  // Custom blocklist/allowlist
  var _blockedIPs = Object.create(null);
  var _allowedIPs = Object.create(null);

  var _totalScored = 0;
  var _totalBlocked = 0;
  var _totalChallenged = 0;

  // ── Helpers ──────────────────────────────────────────────────────

  function _clamp01(v) { return Math.max(0, Math.min(1, v)); }

  function _pushCapped(arr, item, cap) {
    arr.push(item);
    while (arr.length > cap) { arr.shift(); }
  }

  function _toAction(score) {
    if (score >= blockThreshold) return "block";
    if (score >= challengeThreshold) return "challenge";
    if (score >= warnThreshold) return "warn";
    return "allow";
  }

  function _toLevel(score) {
    if (score >= blockThreshold) return "critical";
    if (score >= challengeThreshold) return "high";
    if (score >= warnThreshold) return "medium";
    return "low";
  }

  // ── Factor Evaluators ────────────────────────────────────────────

  function _countryRiskFactor(country) {
    if (!country) return { name: "country_unknown", score: 0.3, detail: "No country data" };
    var cc = country.toUpperCase();
    if (highRisk.indexOf(cc) !== -1) return { name: "country_high_risk", score: 0.4, detail: cc + " is high-risk" };
    if (mediumRisk.indexOf(cc) !== -1) return { name: "country_medium_risk", score: 0.2, detail: cc + " is medium-risk" };
    return { name: "country_ok", score: 0, detail: cc + " is low-risk" };
  }

  function _proxyFactor(meta) {
    var s = 0;
    var parts = [];
    if (meta.isProxy) { s += 0.35; parts.push("proxy"); }
    if (meta.isDatacenter) { s += 0.3; parts.push("datacenter"); }
    if (meta.isTor) { s += 0.4; parts.push("Tor"); }
    if (meta.isVpn) { s += 0.25; parts.push("VPN"); }
    if (s === 0) return { name: "proxy_none", score: 0, detail: "No proxy signals" };
    return { name: "proxy_detected", score: _clamp01(s), detail: parts.join(", ") + " detected" };
  }

  function _velocityFactor(ip, lat, lon, ts) {
    if (lat == null || lon == null || !ip) return null;
    var history = _ipHistory[ip];
    if (!history || history.length === 0) return null;
    var dominated = false;
    var worst = { name: "velocity_ok", score: 0, detail: "Normal travel speed" };
    for (var i = history.length - 1; i >= 0; i--) {
      var prev = history[i];
      if (ts - prev.ts > velocityWindowMs) break;
      var dt = (ts - prev.ts) / 3600000; // hours
      if (dt <= 0) continue;
      var dist = _haversineKm(prev.lat, prev.lon, lat, lon);
      var speed = dist / dt;
      if (speed > impossibleSpeedKmh) {
        return { name: "impossible_travel", score: 0.9, detail: Math.round(speed) + " km/h (" + Math.round(dist) + " km in " + Math.round(dt * 60) + " min)" };
      }
      if (speed > suspiciousSpeedKmh && !dominated) {
        worst = { name: "suspicious_travel", score: 0.4, detail: Math.round(speed) + " km/h" };
        dominated = true;
      }
    }
    return worst;
  }

  function _geoHoppingFactor(sessionId, country, ts) {
    if (!sessionId || !country) return null;
    var hist = _sessionGeo[sessionId];
    if (!hist || hist.length === 0) return null;
    var countries = Object.create(null);
    countries[country.toUpperCase()] = true;
    var recent = 0;
    for (var i = hist.length - 1; i >= 0; i--) {
      if (ts - hist[i].ts > velocityWindowMs) break;
      countries[hist[i].country] = true;
      recent++;
    }
    var uniqueCount = Object.keys(countries).length;
    if (uniqueCount >= 4) return { name: "geo_hopping_extreme", score: 0.8, detail: uniqueCount + " countries in window" };
    if (uniqueCount >= 3) return { name: "geo_hopping_high", score: 0.5, detail: uniqueCount + " countries in window" };
    if (uniqueCount >= 2) return { name: "geo_hopping_mild", score: 0.15, detail: uniqueCount + " countries in window" };
    return null;
  }

  function _regionalAnomalyFactor(country) {
    if (!country) return null;
    var cc = country.toUpperCase();
    var stats = _regionStats[cc];
    if (!stats || stats.attempts < 20) return null; // not enough data
    var solveRate = stats.solves / stats.attempts;
    if (solveRate < 0.1) return { name: "region_low_solve_rate", score: 0.35, detail: cc + " solve rate " + (solveRate * 100).toFixed(1) + "%" };
    if (solveRate < 0.3) return { name: "region_below_avg_solve", score: 0.15, detail: cc + " solve rate " + (solveRate * 100).toFixed(1) + "%" };
    return null;
  }

  // ── Main Scoring ─────────────────────────────────────────────────

  function score(meta) {
    if (!meta) throw new Error("GeoRiskScorer: meta object required");
    var ts = meta.timestamp || Date.now();
    var factors = [];

    // Allowlist/blocklist short-circuits
    if (meta.ip && _allowedIPs[meta.ip]) {
      return { score: 0, level: "low", factors: [{ name: "ip_allowlisted", score: 0, detail: meta.ip }], action: "allow" };
    }
    if (meta.ip && _blockedIPs[meta.ip]) {
      return { score: 1, level: "critical", factors: [{ name: "ip_blocklisted", score: 1, detail: meta.ip }], action: "block" };
    }

    // Evaluate all factors
    factors.push(_countryRiskFactor(meta.country));
    factors.push(_proxyFactor(meta));

    var vf = _velocityFactor(meta.ip, meta.lat, meta.lon, ts);
    if (vf) factors.push(vf);

    var ghf = _geoHoppingFactor(meta.sessionId, meta.country, ts);
    if (ghf) factors.push(ghf);

    var raf = _regionalAnomalyFactor(meta.country);
    if (raf) factors.push(raf);

    // Composite score: weighted max + average blend
    var maxScore = 0;
    var sum = 0;
    var count = 0;
    for (var i = 0; i < factors.length; i++) {
      if (factors[i].score > maxScore) maxScore = factors[i].score;
      sum += factors[i].score;
      count++;
    }
    var avg = count > 0 ? sum / count : 0;
    var composite = _clamp01(maxScore * 0.7 + avg * 0.3);

    var action = _toAction(composite);
    var level = _toLevel(composite);

    // Update history
    if (meta.ip && meta.lat != null && meta.lon != null) {
      if (!_ipHistory[meta.ip]) _ipHistory[meta.ip] = [];
      _pushCapped(_ipHistory[meta.ip], { lat: meta.lat, lon: meta.lon, ts: ts, country: (meta.country || "").toUpperCase() }, maxHistory);
    }
    if (meta.sessionId && meta.country) {
      if (!_sessionGeo[meta.sessionId]) _sessionGeo[meta.sessionId] = [];
      _pushCapped(_sessionGeo[meta.sessionId], { country: meta.country.toUpperCase(), ts: ts }, maxHistory);
    }

    _totalScored++;
    if (action === "block") _totalBlocked++;
    if (action === "challenge") _totalChallenged++;

    return { score: Math.round(composite * 1000) / 1000, level: level, factors: factors, action: action };
  }

  // ── Region Stats ─────────────────────────────────────────────────

  function recordAttempt(country, solved) {
    if (!country) return;
    var cc = country.toUpperCase();
    if (!_regionStats[cc]) _regionStats[cc] = { attempts: 0, solves: 0 };
    _regionStats[cc].attempts++;
    if (solved) _regionStats[cc].solves++;
  }

  function getRegionStats(country) {
    if (country) {
      var cc = country.toUpperCase();
      var s = _regionStats[cc];
      return s ? { country: cc, attempts: s.attempts, solves: s.solves, solveRate: s.attempts > 0 ? Math.round((s.solves / s.attempts) * 1000) / 1000 : 0 } : null;
    }
    var result = [];
    var keys = Object.keys(_regionStats);
    for (var i = 0; i < keys.length; i++) {
      var st = _regionStats[keys[i]];
      result.push({ country: keys[i], attempts: st.attempts, solves: st.solves, solveRate: st.attempts > 0 ? Math.round((st.solves / st.attempts) * 1000) / 1000 : 0 });
    }
    result.sort(function (a, b) { return b.attempts - a.attempts; });
    return result;
  }

  // ── IP Management ────────────────────────────────────────────────

  function blockIP(ip) { _blockedIPs[ip] = true; }
  function allowIP(ip) { _allowedIPs[ip] = true; }
  function unblockIP(ip) { delete _blockedIPs[ip]; }
  function unallowIP(ip) { delete _allowedIPs[ip]; }
  function isBlocked(ip) { return !!_blockedIPs[ip]; }
  function isAllowed(ip) { return !!_allowedIPs[ip]; }

  // ── Batch Scoring ────────────────────────────────────────────────

  function scoreBatch(metas) {
    var results = [];
    for (var i = 0; i < metas.length; i++) {
      results.push(score(metas[i]));
    }
    return results;
  }

  // ── Risk Summary ─────────────────────────────────────────────────

  function summary() {
    return {
      totalScored: _totalScored,
      totalBlocked: _totalBlocked,
      totalChallenged: _totalChallenged,
      blockRate: _totalScored > 0 ? Math.round((_totalBlocked / _totalScored) * 1000) / 1000 : 0,
      challengeRate: _totalScored > 0 ? Math.round((_totalChallenged / _totalScored) * 1000) / 1000 : 0,
      trackedIPs: Object.keys(_ipHistory).length,
      trackedSessions: Object.keys(_sessionGeo).length,
      regionCount: Object.keys(_regionStats).length,
      blockedIPs: Object.keys(_blockedIPs).length,
      allowedIPs: Object.keys(_allowedIPs).length
    };
  }

  // ── Reset ────────────────────────────────────────────────────────

  function reset() {
    _ipHistory = Object.create(null);
    _sessionGeo = Object.create(null);
    _regionStats = Object.create(null);
    _blockedIPs = Object.create(null);
    _allowedIPs = Object.create(null);
    _totalScored = 0;
    _totalBlocked = 0;
    _totalChallenged = 0;
  }

  return {
    score: score,
    scoreBatch: scoreBatch,
    recordAttempt: recordAttempt,
    getRegionStats: getRegionStats,
    blockIP: blockIP,
    allowIP: allowIP,
    unblockIP: unblockIP,
    unallowIP: unallowIP,
    isBlocked: isBlocked,
    isAllowed: isAllowed,
    summary: summary,
    reset: reset
  };
}

// ── Proof of Work ───────────────────────────────────────────────────

/**
 * Create a Hashcash-style proof-of-work challenge gate.
 *
 * Requires clients to find a nonce such that
 *   SHA-256(prefix + ":" + nonce)
 * has at least `difficulty` leading zero bits.  Server issues challenges
 * in O(1), client solves in O(2^difficulty), server verifies in O(1).
 *
 * This adds an economic cost to every CAPTCHA attempt, deterring large-
 * scale bot farms and automated solvers.  Typical difficulty of 16–20
 * takes 50–500 ms on a modern browser, negligible for humans but
 * expensive at scale for attackers.
 *
 * Options:
 *   difficulty          {number}  Leading zero bits required (default 16)
 *   challengeTtlMs      {number}  Challenge expiry (default 60 000 ms)
 *   maxPendingPerIp     {number}  Max concurrent challenges per IP (default 10)
 *   maxPending          {number}  Global pending-challenge cap (default 50 000)
 *   adaptiveDifficulty  {boolean} Auto-scale difficulty based on solve rate (default false)
 *   targetSolveMs       {number}  Adaptive: target solve time (default 200 ms)
 *   minDifficulty       {number}  Adaptive: floor (default 8)
 *   maxDifficulty       {number}  Adaptive: ceiling (default 28)
 *   adjustWindowSize    {number}  Adaptive: rolling window size (default 50)
 *
 * @param {Object} [options]
 * @returns {Object} Proof-of-work challenge manager
 */
function createProofOfWork(options) {
  var opts = options || {};

  if (!_crypto || typeof _crypto.createHash !== 'function') {
    throw new Error('Proof-of-work requires Node.js crypto module');
  }

  var difficulty = _posOpt(opts.difficulty, 16);
  var challengeTtlMs = _posOpt(opts.challengeTtlMs, 60000);
  var maxPendingPerIp = _posOpt(opts.maxPendingPerIp, 10);
  var maxPending = _posOpt(opts.maxPending, 50000);
  var adaptiveDifficulty = !!opts.adaptiveDifficulty;
  var targetSolveMs = _posOpt(opts.targetSolveMs, 200);
  var minDifficulty = _posOpt(opts.minDifficulty, 8);
  var maxDifficulty = _posOpt(opts.maxDifficulty, 28);
  var adjustWindowSize = _posOpt(opts.adjustWindowSize, 50);

  // Current effective difficulty (may change if adaptive)
  var effectiveDifficulty = difficulty;

  // Pending challenges: prefixHex → { ip, difficulty, issuedAt }
  var _pending = Object.create(null);
  var _pendingCount = 0;
  var _pendingByIp = Object.create(null); // ip → count

  // Stats
  var _issued = 0;
  var _verified = 0;
  var _rejected = 0;
  var _expired = 0;
  var _replayBlocked = 0;

  // Used prefixes (replay prevention): prefixHex → true
  var _used = Object.create(null);
  var _usedList = []; // for bounded eviction
  var MAX_USED = 100000;

  // Adaptive difficulty tracking
  var _solveTimes = []; // rolling window of solve durations (ms)

  // ── Internal helpers ───────────────────────────────────────────

  function _sha256hex(data) {
    return _crypto.createHash('sha256').update(data).digest('hex');
  }

  function _randomPrefix() {
    return _crypto.randomBytes(16).toString('hex');
  }

  /**
   * Count leading zero bits in a hex hash string.
   * Each hex digit represents 4 bits: '0' = 4 zeros, '1' = 3, etc.
   */
  function _countLeadingZeroBits(hexStr) {
    var bits = 0;
    for (var i = 0; i < hexStr.length; i++) {
      var nibble = parseInt(hexStr[i], 16);
      if (nibble === 0) {
        bits += 4;
      } else {
        // Count leading zeros in this 4-bit nibble
        if (nibble < 2) bits += 3;
        else if (nibble < 4) bits += 2;
        else if (nibble < 8) bits += 1;
        break;
      }
    }
    return bits;
  }

  function _cleanExpired() {
    var now = Date.now();
    var keys = Object.keys(_pending);
    for (var i = 0; i < keys.length; i++) {
      var entry = _pending[keys[i]];
      if (now - entry.issuedAt > challengeTtlMs) {
        _removePending(keys[i]);
        _expired++;
      }
    }
  }

  function _removePending(prefix) {
    var entry = _pending[prefix];
    if (!entry) return;
    var ip = entry.ip;
    delete _pending[prefix];
    _pendingCount--;
    if (ip && _pendingByIp[ip]) {
      _pendingByIp[ip]--;
      if (_pendingByIp[ip] <= 0) delete _pendingByIp[ip];
    }
  }

  function _recordUsed(prefix) {
    if (_usedList.length >= MAX_USED) {
      var evict = _usedList.shift();
      delete _used[evict];
    }
    _used[prefix] = true;
    _usedList.push(prefix);
  }

  function _updateAdaptiveDifficulty(solveMs) {
    _solveTimes.push(solveMs);
    while (_solveTimes.length > adjustWindowSize) {
      _solveTimes.shift();
    }
    if (_solveTimes.length < 5) return; // need enough samples

    var avg = 0;
    for (var i = 0; i < _solveTimes.length; i++) avg += _solveTimes[i];
    avg /= _solveTimes.length;

    // If solving too fast, increase difficulty; too slow, decrease
    if (avg < targetSolveMs * 0.5 && effectiveDifficulty < maxDifficulty) {
      effectiveDifficulty++;
    } else if (avg > targetSolveMs * 2 && effectiveDifficulty > minDifficulty) {
      effectiveDifficulty--;
    }
  }

  // ── Public API ─────────────────────────────────────────────────

  /**
   * Issue a new proof-of-work challenge.
   *
   * @param {Object} [params]
   * @param {string} [params.ip]        Client IP for per-IP limiting
   * @param {number} [params.difficulty] Override difficulty for this challenge
   * @returns {{ prefix: string, difficulty: number, algorithm: string, expiresAt: number }}
   * @throws {Error} If IP has too many pending challenges or global cap exceeded
   */
  function issue(params) {
    params = params || {};
    var ip = params.ip || null;

    _cleanExpired();

    // Per-IP throttle
    if (ip) {
      var ipCount = _pendingByIp[ip] || 0;
      if (ipCount >= maxPendingPerIp) {
        throw new Error(
          'Too many pending challenges for this IP (max ' + maxPendingPerIp + ')'
        );
      }
    }

    // Global cap
    if (_pendingCount >= maxPending) {
      throw new Error(
        'Global pending-challenge limit reached (' + maxPending + ')'
      );
    }

    var prefix = _randomPrefix();
    var diff = params.difficulty || effectiveDifficulty;
    var now = Date.now();

    _pending[prefix] = {
      ip: ip,
      difficulty: diff,
      issuedAt: now
    };
    _pendingCount++;
    if (ip) {
      _pendingByIp[ip] = (_pendingByIp[ip] || 0) + 1;
    }
    _issued++;

    return {
      prefix: prefix,
      difficulty: diff,
      algorithm: 'sha256',
      expiresAt: now + challengeTtlMs
    };
  }

  /**
   * Verify a client's proof-of-work solution.
   *
   * @param {Object} params
   * @param {string} params.prefix  The challenge prefix from issue()
   * @param {string} params.nonce   The nonce found by the client
   * @param {string} [params.ip]    Client IP for binding verification
   * @returns {{ valid: boolean, reason: string, hash: string|null, leadingZeros: number, solveMs: number|null }}
   */
  function verify(params) {
    if (!params || typeof params.prefix !== 'string' || typeof params.nonce !== 'string') {
      _rejected++;
      return { valid: false, reason: 'missing_params', hash: null, leadingZeros: 0, solveMs: null };
    }

    var prefix = params.prefix;
    var nonce = params.nonce;
    var ip = params.ip || null;

    // Replay detection: already used?
    if (_used[prefix]) {
      _replayBlocked++;
      _rejected++;
      return { valid: false, reason: 'replay', hash: null, leadingZeros: 0, solveMs: null };
    }

    // Is it pending?
    var entry = _pending[prefix];
    if (!entry) {
      // Could be expired or never issued
      _rejected++;
      return { valid: false, reason: 'unknown_challenge', hash: null, leadingZeros: 0, solveMs: null };
    }

    // TTL check
    var now = Date.now();
    if (now - entry.issuedAt > challengeTtlMs) {
      _removePending(prefix);
      _expired++;
      _rejected++;
      return { valid: false, reason: 'expired', hash: null, leadingZeros: 0, solveMs: null };
    }

    // IP binding: if challenge was issued with IP, verify same IP submits
    if (entry.ip && ip && entry.ip !== ip) {
      _rejected++;
      return { valid: false, reason: 'ip_mismatch', hash: null, leadingZeros: 0, solveMs: null };
    }

    // Compute and check hash
    var data = prefix + ':' + nonce;
    var hash = _sha256hex(data);
    var zeros = _countLeadingZeroBits(hash);
    var requiredDiff = entry.difficulty;
    var solveMs = now - entry.issuedAt;

    // Remove from pending regardless of outcome
    _removePending(prefix);

    if (zeros < requiredDiff) {
      _rejected++;
      return {
        valid: false,
        reason: 'insufficient_work',
        hash: hash,
        leadingZeros: zeros,
        solveMs: solveMs
      };
    }

    // Success — record prefix to prevent replay
    _recordUsed(prefix);
    _verified++;

    if (adaptiveDifficulty) {
      _updateAdaptiveDifficulty(solveMs);
    }

    return {
      valid: true,
      reason: 'ok',
      hash: hash,
      leadingZeros: zeros,
      solveMs: solveMs
    };
  }

  /**
   * Solve a challenge (utility for testing and client-side use).
   * Iterates nonces until SHA-256(prefix:nonce) has enough leading zeros.
   *
   * @param {string} prefix     The challenge prefix
   * @param {number} diff       Required leading zero bits
   * @returns {{ nonce: string, hash: string, iterations: number }}
   */
  function solve(prefix, diff) {
    for (var i = 0; i < 100000000; i++) {
      var nonce = i.toString(36);
      var data = prefix + ':' + nonce;
      var hash = _sha256hex(data);
      if (_countLeadingZeroBits(hash) >= diff) {
        return { nonce: nonce, hash: hash, iterations: i + 1 };
      }
    }
    throw new Error('Could not solve challenge within 100M iterations');
  }

  /**
   * Estimate average iterations required for a given difficulty.
   *
   * @param {number} [diff] Difficulty (defaults to current effective)
   * @returns {{ difficulty: number, expectedIterations: number, estimatedMs: string }}
   */
  function estimateCost(diff) {
    var d = diff || effectiveDifficulty;
    var expected = Math.pow(2, d);
    var ms;
    if (expected < 1000) ms = '< 1ms';
    else if (expected < 100000) ms = '~' + Math.round(expected / 1000) + 'ms';
    else if (expected < 10000000) ms = '~' + Math.round(expected / 100000) / 10 + 's';
    else ms = '~' + Math.round(expected / 1000000) + 's';
    return {
      difficulty: d,
      expectedIterations: expected,
      estimatedMs: ms
    };
  }

  /**
   * Get the current effective difficulty.
   *
   * @returns {number}
   */
  function getDifficulty() {
    return effectiveDifficulty;
  }

  /**
   * Get pending-challenge count for an IP (or global).
   *
   * @param {string} [ip] Specific IP to query
   * @returns {number}
   */
  function pendingCount(ip) {
    if (ip) return _pendingByIp[ip] || 0;
    return _pendingCount;
  }

  /**
   * Get summary statistics.
   *
   * @returns {{ issued: number, verified: number, rejected: number, expired: number, replayBlocked: number, pending: number, difficulty: number, adaptiveEnabled: boolean }}
   */
  function summary() {
    return {
      issued: _issued,
      verified: _verified,
      rejected: _rejected,
      expired: _expired,
      replayBlocked: _replayBlocked,
      pending: _pendingCount,
      difficulty: effectiveDifficulty,
      adaptiveEnabled: adaptiveDifficulty
    };
  }

  /**
   * Reset all state (for testing).
   */
  function reset() {
    _pending = Object.create(null);
    _pendingCount = 0;
    _pendingByIp = Object.create(null);
    _issued = 0;
    _verified = 0;
    _rejected = 0;
    _expired = 0;
    _replayBlocked = 0;
    _used = Object.create(null);
    _usedList = [];
    _solveTimes = [];
    effectiveDifficulty = difficulty;
  }

  return {
    issue: issue,
    verify: verify,
    solve: solve,
    estimateCost: estimateCost,
    getDifficulty: getDifficulty,
    pendingCount: pendingCount,
    summary: summary,
    reset: reset
  };
}

// ── Device Cohort Analyzer ──────────────────────────────────────────

var DCA_DEVICE_CATEGORIES = {
  mobile: { label: "Mobile", patterns: ["iphone", "ipad", "android", "mobile", "phone", "tablet"] },
  desktop: { label: "Desktop", patterns: ["windows", "macintosh", "mac os", "linux", "x11", "cros"] },
  bot: { label: "Bot/Crawler", patterns: ["bot", "crawler", "spider", "headless", "phantom", "puppeteer", "selenium"] },
  unknown: { label: "Unknown", patterns: [] }
};

var DCA_CAPABILITY_TIERS = {
  high: { minScreenWidth: 1440, minMemory: 8 },
  mid: { minScreenWidth: 768, minMemory: 4 },
  low: { minScreenWidth: 0, minMemory: 0 }
};

/**
 * Create a DeviceCohortAnalyzer — groups CAPTCHA sessions by device type/capability,
 * detects statistical anomalies within cohorts, and produces per-cohort risk profiles.
 *
 * @param {Object} [options]
 * @param {number} [options.anomalyThreshold=2.0] Z-score threshold for anomaly detection
 * @param {number} [options.minCohortSize=5] Minimum sessions before cohort analysis triggers
 * @param {number} [options.maxCohorts=200] Maximum tracked cohorts
 * @param {number} [options.maxSessionsPerCohort=1000] Max sessions stored per cohort
 * @param {number} [options.suspiciousSolveMs=500] Solve time below this is suspicious
 * @param {number} [options.botSolveMs=200] Solve time below this is bot-like
 * @returns {Object} DeviceCohortAnalyzer instance
 */
function createDeviceCohortAnalyzer(options) {
  options = options || {};
  var anomalyThreshold = options.anomalyThreshold > 0 ? options.anomalyThreshold : 2.0;
  var minCohortSize = options.minCohortSize > 0 ? options.minCohortSize : 5;
  var maxCohorts = options.maxCohorts > 0 ? options.maxCohorts : 200;
  var maxSessionsPerCohort = options.maxSessionsPerCohort > 0 ? options.maxSessionsPerCohort : 1000;
  var suspiciousSolveMs = options.suspiciousSolveMs > 0 ? options.suspiciousSolveMs : 500;
  var botSolveMs = options.botSolveMs > 0 ? options.botSolveMs : 200;

  var _cohorts = Object.create(null);
  var _cohortKeys = [];
  var _totalRecorded = 0;
  var _totalAnomalies = 0;

  function _classifyDevice(ua) {
    if (!ua) return "unknown";
    var lower = ua.toLowerCase();
    var cats = Object.keys(DCA_DEVICE_CATEGORIES);
    for (var i = 0; i < cats.length; i++) {
      var pats = DCA_DEVICE_CATEGORIES[cats[i]].patterns;
      for (var j = 0; j < pats.length; j++) {
        if (lower.indexOf(pats[j]) !== -1) return cats[i];
      }
    }
    return "unknown";
  }

  function _classifyCap(info) {
    if (!info) return "low";
    var sw = info.screenWidth || 0, mem = info.memory || 0;
    if (sw >= DCA_CAPABILITY_TIERS.high.minScreenWidth && mem >= DCA_CAPABILITY_TIERS.high.minMemory) return "high";
    if (sw >= DCA_CAPABILITY_TIERS.mid.minScreenWidth && mem >= DCA_CAPABILITY_TIERS.mid.minMemory) return "mid";
    return "low";
  }

  function _cKey(cat, cap) { return cat + ":" + cap; }

  function _ensure(key, cat, cap) {
    if (!_cohorts[key]) {
      if (_cohortKeys.length >= maxCohorts) { delete _cohorts[_cohortKeys.shift()]; }
      _cohorts[key] = { category: cat, capability: cap, sessions: [], stats: { count: 0, totalSolveMs: 0, totalAttempts: 0, solves: 0, failures: 0 } };
      _cohortKeys.push(key);
    } else {
      var idx = _cohortKeys.indexOf(key);
      if (idx !== -1 && idx !== _cohortKeys.length - 1) { _cohortKeys.splice(idx, 1); _cohortKeys.push(key); }
    }
    return _cohorts[key];
  }

  function _dcaMean(a) { if (!a.length) return 0; var s = 0; for (var i = 0; i < a.length; i++) s += a[i]; return s / a.length; }
  function _dcaStddev(a, m) { if (a.length < 2) return 0; var s = 0; for (var i = 0; i < a.length; i++) { var d = a[i] - m; s += d * d; } return Math.sqrt(s / a.length); }
  function _dcaMedian(a) { if (!a.length) return 0; var s = a.slice().sort(function(x,y){return x-y;}); var m = Math.floor(s.length/2); return s.length%2 ? s[m] : (s[m-1]+s[m])/2; }
  function _dcaPct(a, p) { if (!a.length) return 0; var s = a.slice().sort(function(x,y){return x-y;}); var i = (p/100)*(s.length-1); var lo = Math.floor(i), hi = Math.ceil(i); return lo===hi ? s[lo] : s[lo]+(s[hi]-s[lo])*(i-lo); }

  function _detectAnomalies(key, entry) {
    var c = _cohorts[key];
    if (!c || c.sessions.length < minCohortSize) return [];
    var anomalies = [], times = [];
    for (var i = 0; i < c.sessions.length; i++) times.push(c.sessions[i].solveTimeMs);
    var avg = _dcaMean(times), sd = _dcaStddev(times, avg);
    if (sd > 0) {
      var z = (entry.solveTimeMs - avg) / sd;
      if (Math.abs(z) > anomalyThreshold) {
        anomalies.push({ type: "zscore_outlier", severity: Math.abs(z) > anomalyThreshold * 2 ? "critical" : "high", detail: "Solve time z-score: " + z.toFixed(2), zScore: Math.round(z * 100) / 100 });
      }
    }
    if (entry.solveTimeMs < botSolveMs) {
      anomalies.push({ type: "bot_speed", severity: "critical", detail: "Solve time " + entry.solveTimeMs + "ms below bot threshold (" + botSolveMs + "ms)" });
    } else if (entry.solveTimeMs < suspiciousSolveMs) {
      anomalies.push({ type: "suspicious_speed", severity: "high", detail: "Solve time " + entry.solveTimeMs + "ms below suspicious threshold (" + suspiciousSolveMs + "ms)" });
    }
    var fast = 0;
    for (var j = 0; j < c.sessions.length; j++) { if (c.sessions[j].solveTimeMs < suspiciousSolveMs) fast++; }
    var fr = fast / c.sessions.length;
    if (fr > 0.5 && c.sessions.length >= minCohortSize) {
      anomalies.push({ type: "cohort_suspicious", severity: "critical", detail: Math.round(fr * 100) + "% of cohort solves below " + suspiciousSolveMs + "ms", fastRatio: Math.round(fr * 100) / 100 });
    }
    return anomalies;
  }

  function record(session) {
    if (!session) throw new Error("session is required");
    if (typeof session.solveTimeMs !== "number" || session.solveTimeMs < 0) throw new Error("solveTimeMs must be a non-negative number");
    var cat = _classifyDevice(session.userAgent);
    var cap = _classifyCap(session.deviceInfo);
    var key = _cKey(cat, cap);
    var cohort = _ensure(key, cat, cap);
    var entry = { solveTimeMs: session.solveTimeMs, solved: !!session.solved, attempts: session.attempts > 0 ? session.attempts : 1, ip: session.ip || null, timestamp: session.timestamp || Date.now() };
    cohort.sessions.push(entry);
    if (cohort.sessions.length > maxSessionsPerCohort) cohort.sessions.shift();
    cohort.stats.count++; cohort.stats.totalSolveMs += entry.solveTimeMs; cohort.stats.totalAttempts += entry.attempts;
    if (entry.solved) cohort.stats.solves++; else cohort.stats.failures++;
    _totalRecorded++;
    var anomalies = _detectAnomalies(key, entry);
    if (anomalies.length > 0) _totalAnomalies++;
    return { cohortKey: key, category: cat, capability: cap, anomalies: anomalies };
  }

  function getCohortProfile(cohortKey) {
    var c = _cohorts[cohortKey];
    if (!c) return null;
    var times = [], ips = Object.create(null), ipCount = 0;
    for (var i = 0; i < c.sessions.length; i++) {
      times.push(c.sessions[i].solveTimeMs);
      if (c.sessions[i].ip && !ips[c.sessions[i].ip]) { ips[c.sessions[i].ip] = true; ipCount++; }
    }
    var avg = _dcaMean(times), sd = _dcaStddev(times, avg);
    var solveRate = c.stats.count > 0 ? c.stats.solves / c.stats.count : 0;
    var cv = avg > 0 ? sd / avg : 0;
    var riskScore = 0, factors = [];
    if (avg < botSolveMs) { riskScore += 0.4; factors.push("Average solve time (" + Math.round(avg) + "ms) below bot threshold"); }
    else if (avg < suspiciousSolveMs) { riskScore += 0.2; factors.push("Average solve time (" + Math.round(avg) + "ms) suspiciously fast"); }
    if (cv < 0.05 && c.sessions.length >= minCohortSize) { riskScore += 0.3; factors.push("Extremely low variance (CV: " + (cv*100).toFixed(1) + "%)"); }
    else if (cv < 0.15 && c.sessions.length >= minCohortSize) { riskScore += 0.15; factors.push("Low variance (CV: " + (cv*100).toFixed(1) + "%)"); }
    if (solveRate > 0.99 && c.stats.count >= minCohortSize) { riskScore += 0.2; factors.push("Near-perfect solve rate (" + (solveRate*100).toFixed(1) + "%)"); }
    if (c.stats.count >= minCohortSize * 2 && ipCount > 0) {
      var spi = c.stats.count / ipCount;
      if (spi > 20) { riskScore += 0.2; factors.push("High sessions-per-IP (" + spi.toFixed(1) + ")"); }
    }
    if (c.category === "bot") { riskScore += 0.3; factors.push("User-agent classified as bot/crawler"); }
    riskScore = Math.min(1, riskScore);
    var level = riskScore >= 0.7 ? "critical" : riskScore >= 0.5 ? "high" : riskScore >= 0.3 ? "medium" : "low";
    return {
      cohortKey: cohortKey, category: c.category, capability: c.capability,
      sessionCount: c.stats.count, uniqueIPs: ipCount,
      solveRate: Math.round(solveRate * 1000) / 1000,
      timing: { mean: Math.round(avg*100)/100, median: Math.round(_dcaMedian(times)*100)/100, stddev: Math.round(sd*100)/100, p5: Math.round(_dcaPct(times,5)*100)/100, p95: Math.round(_dcaPct(times,95)*100)/100, cv: Math.round(cv*1000)/1000 },
      risk: { score: Math.round(riskScore*100)/100, level: level, factors: factors }
    };
  }

  function getAllProfiles(opts) {
    opts = opts || {};
    var sortBy = opts.sortBy || "risk", minRisk = opts.minRisk || null;
    var ro = { low: 0, medium: 1, high: 2, critical: 3 };
    var out = [];
    for (var i = 0; i < _cohortKeys.length; i++) {
      var p = getCohortProfile(_cohortKeys[i]);
      if (p && (!minRisk || ro[p.risk.level] >= ro[minRisk])) out.push(p);
    }
    if (sortBy === "risk") out.sort(function(a,b){ return (ro[b.risk.level]-ro[a.risk.level]) || (b.risk.score-a.risk.score); });
    else if (sortBy === "count") out.sort(function(a,b){ return b.sessionCount - a.sessionCount; });
    else out.sort(function(a,b){ return a.cohortKey < b.cohortKey ? -1 : 1; });
    return out;
  }

  function compareCohorts(keyA, keyB) {
    var a = getCohortProfile(keyA), b = getCohortProfile(keyB);
    if (!a || !b) return null;
    var td = Math.abs(a.timing.mean - b.timing.mean), srd = Math.abs(a.solveRate - b.solveRate), cvd = Math.abs(a.timing.cv - b.timing.cv);
    var sim = 1 - Math.min(1, (td / Math.max(a.timing.mean, b.timing.mean, 1)) * 0.4 + srd * 0.3 + cvd * 0.3);
    var spoofs = [];
    if (sim > 0.9 && a.category !== b.category) spoofs.push("Different device categories with very similar behavior");
    if (a.risk.level === "critical" && b.risk.level === "low" && sim > 0.7) spoofs.push("High-risk cohort mimicking low-risk patterns");
    return { cohortA: keyA, cohortB: keyB, similarity: Math.round(sim*1000)/1000, timingDiff: Math.round(td*100)/100, solveRateDiff: Math.round(srd*1000)/1000, spoofingIndicators: spoofs, verdict: spoofs.length > 0 ? "suspicious" : "normal" };
  }

  function dcaSummary() {
    var profiles = getAllProfiles();
    var byCat = Object.create(null), byCap = Object.create(null), byRisk = { low: 0, medium: 0, high: 0, critical: 0 };
    for (var i = 0; i < profiles.length; i++) {
      byCat[profiles[i].category] = (byCat[profiles[i].category] || 0) + profiles[i].sessionCount;
      byCap[profiles[i].capability] = (byCap[profiles[i].capability] || 0) + profiles[i].sessionCount;
      byRisk[profiles[i].risk.level]++;
    }
    return { totalSessions: _totalRecorded, totalCohorts: _cohortKeys.length, totalAnomalies: _totalAnomalies, sessionsByCategory: byCat, sessionsByCapability: byCap, cohortsByRisk: byRisk, profiles: profiles };
  }

  function reset() { _cohorts = Object.create(null); _cohortKeys = []; _totalRecorded = 0; _totalAnomalies = 0; }

  function exportState() { return { cohorts: JSON.parse(JSON.stringify(_cohorts)), cohortKeys: _cohortKeys.slice(), totalRecorded: _totalRecorded, totalAnomalies: _totalAnomalies }; }

  function importState(state) {
    if (!state || !state.cohorts) throw new Error("Invalid state");
    _cohorts = Object.create(null);
    var keys = Object.keys(state.cohorts);
    for (var i = 0; i < keys.length; i++) _cohorts[keys[i]] = state.cohorts[keys[i]];
    _cohortKeys = state.cohortKeys ? state.cohortKeys.slice() : keys;
    _totalRecorded = state.totalRecorded || 0;
    _totalAnomalies = state.totalAnomalies || 0;
  }

  return { record: record, getCohortProfile: getCohortProfile, getAllProfiles: getAllProfiles, compareCohorts: compareCohorts, summary: dcaSummary, reset: reset, exportState: exportState, importState: importState };
}

var gifCaptcha = {
  sanitize: sanitize,
  createSanitizer: createSanitizer,
  isSafeUrl: isSafeUrl,
  loadGifWithRetry: loadGifWithRetry,
  textSimilarity: textSimilarity,
  validateAnswer: validateAnswer,
  createChallenge: createChallenge,
  pickChallenges: pickChallenges,
  createAttemptTracker: createAttemptTracker,
  installRoundRectPolyfill: installRoundRectPolyfill,
  secureRandomInt: secureRandomInt,
  createSetAnalyzer: createSetAnalyzer,
  createDifficultyCalibrator: createDifficultyCalibrator,
  createSecurityScorer: createSecurityScorer,
  createSessionManager: createSessionManager,
  createPoolManager: createPoolManager,
  createResponseAnalyzer: createResponseAnalyzer,
  createBotDetector: createBotDetector,
  createTokenVerifier: createTokenVerifier,
  createReputationTracker: createReputationTracker,
  createChallengeRouter: createChallengeRouter,
  createRateLimiter: createRateLimiter,
  createClientFingerprinter: createClientFingerprinter,
  createIncidentCorrelator: createIncidentCorrelator,
  createAdaptiveTimeout: createAdaptiveTimeout,
  createAuditTrail: createAuditTrail,
  createSessionRecorder: createSessionRecorder,
  createLoadTester: createLoadTester,
  createABExperimentRunner: createABExperimentRunner,
  createFraudRingDetector: createFraudRingDetector,
  createComplianceReporter: createComplianceReporter,
  createMetricsAggregator: createMetricsAggregator,
  createTrustScoreEngine: createTrustScoreEngine,
  GIF_MAX_RETRIES: GIF_MAX_RETRIES,
  GIF_RETRY_DELAY_MS: GIF_RETRY_DELAY_MS,
  createEventEmitter: createEventEmitter,
  createI18n: createI18n,
  createAccessibilityAuditor: createAccessibilityAuditor,
  createConfigValidator: createConfigValidator,
  createChallengeAnalytics: createChallengeAnalytics,
  createGeoRiskScorer: createGeoRiskScorer,
  createProofOfWork: createProofOfWork,
  createDeviceCohortAnalyzer: createDeviceCohortAnalyzer,
};

// UMD export — works in Node.js, AMD, and browser globals
if (typeof module !== "undefined" && module.exports) {
  module.exports = gifCaptcha;
} else if (typeof define === "function" && define.amd) {
  define(function () { return gifCaptcha; });
} else if (typeof window !== "undefined") {
  window.gifCaptcha = gifCaptcha;
}
