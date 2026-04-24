"use strict";

// ── Shared Utilities ────────────────────────────────────────────
// Extracted from index.js for modular restructuring (issue #91)


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
// Delegates to crypto-utils.js which has the most robust implementation
// (including crypto.randomBytes fallback and RangeError on invalid input).
// This eliminates the duplicated secureRandomInt that previously lived here
// and in crypto-utils.js — see issue #91.

var _cryptoUtils = require('./crypto-utils');
var secureRandomInt = _cryptoUtils.secureRandomInt;

// Keep _crypto reference for other shared-utils consumers (_constantTimeEqual)
var _crypto = null;
try {
  if (typeof require !== 'undefined') _crypto = require('crypto');
} catch (e) { /* not available */ }

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

  // Prefer crypto.timingSafeEqual for strongest guarantee.
  // timingSafeEqual requires equal-length buffers, so when lengths
  // differ we still perform a full comparison (against b itself) to
  // avoid leaking length information via early-return timing (CWE-208).
  if (_crypto && typeof _crypto.timingSafeEqual === 'function') {
    var bufA = Buffer.from(a, 'utf8');
    var bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) {
      // Compare bufB to itself so the timing is indistinguishable
      // from a same-length comparison, then return false.
      _crypto.timingSafeEqual(bufB, bufB);
      return false;
    }
    return _crypto.timingSafeEqual(bufA, bufB);
  }

  // Fallback: bitwise XOR over all chars (constant-time in character count).
  // Always iterate over the longer string to prevent length-oracle attacks.
  var maxLen = Math.max(a.length, b.length);
  var mismatch = a.length ^ b.length; // non-zero if lengths differ
  for (var i = 0; i < maxLen; i++) {
    mismatch |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
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

/**
 * Compute an exponential decay factor based on age and half-life.
 * Returns 1.0 for age <= 0, 0.5 at age === halfLifeMs, approaching 0 as age grows.
 * Used for time-weighted signal scoring (session-risk-aggregator, fraud-ring-detector).
 *
 * @param {number} ageMs      - Age of the signal in milliseconds
 * @param {number} halfLifeMs - Half-life in milliseconds
 * @returns {number} Decay multiplier in (0, 1]
 */
function _decayFactor(ageMs, halfLifeMs) {
  if (ageMs <= 0) return 1;
  return Math.pow(0.5, ageMs / halfLifeMs);
}

/**
 * Compute cosine similarity between two equal-length numeric arrays.
 * Returns 0 for empty, mismatched-length, or zero-magnitude arrays.
 *
 * @param {number[]} a
 * @param {number[]} b
 * @returns {number} Similarity in [0, 1] (or negative for opposing vectors)
 */
function _cosineSimilarity(a, b) {
  if (!a || !b || a.length !== b.length || a.length === 0) return 0;
  var dot = 0, magA = 0, magB = 0;
  for (var i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }
  if (magA === 0 || magB === 0) return 0;
  return dot / (Math.sqrt(magA) * Math.sqrt(magB));
}

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

/**
 * Compute the population standard deviation (n denominator, no Bessel's correction).
 * Useful for cohort analysis where the data IS the entire population, not a sample.
 * @param {number[]} arr
 * @param {number} [avg] - Pre-computed mean
 * @returns {number} Population standard deviation, or 0 for arrays with fewer than 2 elements
 */
function _populationStddev(arr, avg) {
  if (arr.length < 2) return 0;
  var m = avg !== undefined ? avg : _mean(arr);
  var sumSq = 0;
  for (var i = 0; i < arr.length; i++) {
    var d = arr[i] - m;
    sumSq += d * d;
  }
  return Math.sqrt(sumSq / arr.length);
}

/**
 * Compute the p-th percentile of a numeric array using linear interpolation.
 * @param {number[]} arr - Input array (not mutated)
 * @param {number} p - Percentile (0-100)
 * @returns {number} Percentile value, or 0 for empty arrays
 */
function _percentile(arr, p) {
  if (!arr.length) return 0;
  var sorted = arr.slice().sort(_numAsc);
  var i = (p / 100) * (sorted.length - 1);
  var lo = Math.floor(i);
  var hi = Math.ceil(i);
  return lo === hi ? sorted[lo] : sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
}

/**
 * Compute the median of a pre-sorted numeric array (avoids redundant sorting).
 * Callers must ensure the input is sorted in ascending order.
 * @param {number[]} sorted - Pre-sorted numeric array
 * @returns {number} Median, or 0 for empty arrays
 */
function _medianSorted(sorted) {
  if (sorted.length === 0) return 0;
  var mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

/**
 * Compute the p-th percentile of a pre-sorted numeric array (avoids redundant sorting).
 * Callers must ensure the input is sorted in ascending order.
 * @param {number[]} sorted - Pre-sorted numeric array
 * @param {number} p - Percentile (0-100)
 * @returns {number} Percentile value, or 0 for empty arrays
 */
function _percentileSorted(sorted, p) {
  if (sorted.length === 0) return 0;
  var i = (p / 100) * (sorted.length - 1);
  var lo = Math.floor(i);
  var hi = Math.ceil(i);
  return lo === hi ? sorted[lo] : sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
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
        // textContent→innerHTML escapes <, >, & but NOT quotes.
        // Unescaped quotes allow attribute injection (XSS) when the
        // result is used inside HTML attributes (e.g. href="...").
        return el.innerHTML
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
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

  // Cache-buster on retry to bypass cached failures.
  // Use & if URL already has query parameters, ? otherwise.
  if (attempt > 0) {
    var separator = challenge.gifUrl.indexOf("?") !== -1 ? "&" : "?";
    img.src = challenge.gifUrl + separator + "retry=" + attempt;
  } else {
    img.src = challenge.gifUrl;
  }
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

  var setA = Object.create(null);
  var uniqueA = 0;
  wordsA.forEach(function (w) { if (!setA[w]) { setA[w] = true; uniqueA++; } });

  var intersection = 0;
  var uniqueB = 0;
  var setB = Object.create(null);
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

// ── Exports ─────────────────────────────────────────────────────
module.exports = {
  _posOpt: _posOpt,
  _nnOpt: _nnOpt,
  LruTracker: LruTracker,
  secureRandomInt: secureRandomInt,
  _now: _now,
  _constantTimeEqual: _constantTimeEqual,
  _clamp: _clamp,
  _decayFactor: _decayFactor,
  _cosineSimilarity: _cosineSimilarity,
  _numAsc: _numAsc,
  _mean: _mean,
  _median: _median,
  _stddev: _stddev,
  _populationStddev: _populationStddev,
  _percentile: _percentile,
  _medianSorted: _medianSorted,
  _percentileSorted: _percentileSorted,
  createSanitizer: createSanitizer,
  sanitize: sanitize,
  isSafeUrl: isSafeUrl,
  GIF_MAX_RETRIES: GIF_MAX_RETRIES,
  GIF_RETRY_DELAY_MS: GIF_RETRY_DELAY_MS,
  loadGifWithRetry: loadGifWithRetry,
  textSimilarity: textSimilarity,
  validateAnswer: validateAnswer,
  createChallenge: createChallenge,
  pickChallenges: pickChallenges,
  createAttemptTracker: createAttemptTracker,
  installRoundRectPolyfill: installRoundRectPolyfill,
};
