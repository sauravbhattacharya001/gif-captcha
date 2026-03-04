/**
 * gif-captcha — Core library for GIF-based CAPTCHA challenges.
 *
 * Provides utilities for creating, presenting, and validating GIF CAPTCHAs
 * that leverage human visual comprehension to distinguish humans from bots.
 *
 * @module gif-captcha
 */

"use strict";

// ── Crypto-secure Randomness ────────────────────────────────────────

var _crypto = null;
try {
  if (typeof require !== 'undefined') _crypto = require('crypto');
} catch (e) { /* not available */ }

/**
 * Generate a cryptographically secure random integer in [0, max).
 * Falls back to Math.random() if no crypto API is available.
 *
 * @param {number} max - Exclusive upper bound (must be > 0)
 * @returns {number} Random integer in [0, max)
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
  return Math.floor(Math.random() * max);
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
  var setB = {};
  wordsA.forEach(function (w) { setA[w] = true; });
  wordsB.forEach(function (w) { setB[w] = true; });

  var intersection = 0;
  var union = Object.assign({}, setA);
  Object.keys(setB).forEach(function (w) {
    if (setA[w]) intersection++;
    union[w] = true;
  });

  return intersection / Object.keys(union).length;
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
  var maxAttempts = (typeof options.maxAttempts === "number" && options.maxAttempts > 0)
    ? Math.floor(options.maxAttempts) : 5;
  var baseLockoutMs = (typeof options.lockoutMs === "number" && options.lockoutMs > 0)
    ? options.lockoutMs : 30000;
  var exponentialBackoff = options.exponentialBackoff !== false;
  var maxLockoutMs = (typeof options.maxLockoutMs === "number" && options.maxLockoutMs > 0)
    ? options.maxLockoutMs : 300000;

  // Internal state: Map<challengeId, { attempts: number, timestamps: number[], lockoutUntil: number, lockoutCount: number }>
  // Use null-prototype object to prevent prototype pollution when
  // user-supplied challengeIds collide with Object.prototype keys
  // (e.g. "__proto__", "constructor", "toString").
  var challenges = Object.create(null);

  function _now() {
    return Date.now();
  }

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
    lengths.sort(function (a, b) { return a - b; });
    var n = lengths.length;
    var min = lengths[0];
    var max = lengths[n - 1];
    var sum = lengths.reduce(function (s, v) { return s + v; }, 0);
    var mean = sum / n;
    var median;
    if (n % 2 === 1) {
      median = lengths[Math.floor(n / 2)];
    } else {
      median = (lengths[n / 2 - 1] + lengths[n / 2]) / 2;
    }
    var variance = lengths.reduce(function (s, v) {
      return s + (v - mean) * (v - mean);
    }, 0);
    var stdDev = n > 1 ? Math.sqrt(variance / (n - 1)) : 0;
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
    var coverageRatio = challengesWithKeywords / _challenges.length;

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
    var keywordSpread = Math.min(100, (kc.uniqueKeywords / (_challenges.length * 2)) * 100);

    // titleUniqueness: uniqueTitles / totalChallenges × 100
    var titleSet = {};
    _challenges.forEach(function (c) {
      var t = (c.title || "").toLowerCase();
      titleSet[t] = true;
    });
    var uniqueTitles = Object.keys(titleSet).length;
    var titleUniqueness = (uniqueTitles / _challenges.length) * 100;

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
 * @returns {Object} DifficultyCalibrator instance
 */
function createDifficultyCalibrator(challenges) {
  if (!Array.isArray(challenges) || challenges.length === 0) {
    throw new Error("challenges must be a non-empty array");
  }

  var _challenges = challenges.slice();
  var _responses = Object.create(null);

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
    _responses[challengeId].push({
      timeMs: response.timeMs,
      correct: response.correct,
      skipped: Boolean(response.skipped),
    });
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

    times.sort(function (a, b) { return a - b; });

    var avgTime = 0;
    var medianTime = 0;
    var minTime = 0;
    var maxTime = 0;
    var stdDev = 0;

    if (times.length > 0) {
      var sum = 0;
      times.forEach(function (t) { sum += t; });
      avgTime = sum / times.length;

      var mid = Math.floor(times.length / 2);
      medianTime = times.length % 2 === 0
        ? (times[mid - 1] + times[mid]) / 2
        : times[mid];

      minTime = times[0];
      maxTime = times[times.length - 1];

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
      allMedians.sort(function (a, b) { return a - b; });
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
    return Math.round(Math.min(100, Math.max(0, difficulty)));
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
    var count = 0;
    Object.keys(_responses).forEach(function (id) {
      count += _responses[id].length;
    });
    return count;
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
    return Math.max(0, Math.min(100, v));
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
    var mean = 0;
    for (var i = 0; i < lengths.length; i++) mean += lengths[i];
    mean = lengths.length > 0 ? mean / lengths.length : 0;

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
    var easyP = easy / total, medP = medium / total, hardP = hard / total;
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

  var challengesPerSession = (typeof options.challengesPerSession === "number" && options.challengesPerSession > 0)
    ? Math.floor(options.challengesPerSession) : 3;
  var passThreshold = (typeof options.passThreshold === "number" && options.passThreshold >= 0 && options.passThreshold <= 1)
    ? options.passThreshold : 0.67;
  var sessionTimeoutMs = (typeof options.sessionTimeoutMs === "number" && options.sessionTimeoutMs > 0)
    ? options.sessionTimeoutMs : 300000;
  var escalateDifficulty = options.escalateDifficulty !== false;
  var difficultyStep = (typeof options.difficultyStep === "number" && options.difficultyStep >= 0)
    ? options.difficultyStep : 15;
  var baseDifficulty = (typeof options.baseDifficulty === "number" && options.baseDifficulty >= 0 && options.baseDifficulty <= 100)
    ? options.baseDifficulty : 30;
  var maxDifficulty = (typeof options.maxDifficulty === "number" && options.maxDifficulty >= 0 && options.maxDifficulty <= 100)
    ? options.maxDifficulty : 95;
  var maxSessions = (typeof options.maxSessions === "number" && options.maxSessions > 0)
    ? Math.floor(options.maxSessions) : 1000;

  // Internal state: Map<sessionId, SessionState>
  // Use null-prototype object to prevent prototype pollution via
  // crafted session IDs targeting Object.prototype properties.
  var sessions = Object.create(null);
  var sessionCount = 0;

  function _now() {
    return Date.now();
  }

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
  var maxServes = (typeof options.maxServes === "number" && options.maxServes > 0)
    ? Math.floor(options.maxServes) : 100;
  var minPassRate = (typeof options.minPassRate === "number") ? options.minPassRate : 0.3;
  var maxPassRate = (typeof options.maxPassRate === "number") ? options.maxPassRate : 0.95;
  var minPoolSize = (typeof options.minPoolSize === "number" && options.minPoolSize > 0)
    ? Math.floor(options.minPoolSize) : 3;

  // challenge id → { challenge, serves, passes, fails, retired, addedAt, retiredAt, retireReason }
  // Use null-prototype object to prevent prototype pollution via crafted challenge IDs.
  var registry = Object.create(null);
  var activeIds = [];

  function _now() { return Date.now(); }

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

    var sorted = responseTimes.slice().sort(function (a, b) { return a - b; });
    var n = sorted.length;
    var sum = sorted.reduce(function (s, v) { return s + v; }, 0);
    var avg = sum / n;

    var median;
    if (n % 2 === 1) {
      median = sorted[Math.floor(n / 2)];
    } else {
      median = (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
    }

    var variance = sorted.reduce(function (s, v) { return s + (v - avg) * (v - avg); }, 0);
    var stdDev = n > 1 ? Math.sqrt(variance / (n - 1)) : 0;
    var cv = avg > 0 ? stdDev / avg : 0;

    var tooFastCount = sorted.filter(function (t) { return t < minResponseTimeMs; }).length;
    var isUniform = n >= 3 && cv < maxTimingCvThreshold;

    if (tooFastCount > 0) flags.push('fast_responses:' + tooFastCount);
    if (tooFastCount === n) flags.push('all_responses_suspiciously_fast');
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

    score = Math.max(0, Math.min(100, score));

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

  /**
   * Generate a one-time JS verification token.
   * The client must call this (proving JS execution) and submit it.
   *
   * @param {string} [sessionId] - Optional session identifier for binding
   * @returns {string} Token string to include in form submission
   */
  function getJsToken(sessionId) {
    var id = sessionId || '_default';
    var token = '';
    for (var i = 0; i < 32; i++) {
      token += secureRandomInt(36).toString(36);
    }
    _jsTokens[id] = { token: token, createdAt: Date.now() };
    return token;
  }

  /**
   * Verify a submitted JS token.
   * @private
   */
  function _verifyJsToken(submittedToken, sessionId) {
    var id = sessionId || '_default';
    var entry = _jsTokens[id];
    if (!entry) return false;
    var valid = entry.token === submittedToken;
    // One-time use: delete after verification
    delete _jsTokens[id];
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
  var tokenTtlMs = (typeof options.tokenTtlMs === 'number' && options.tokenTtlMs > 0)
    ? options.tokenTtlMs : 300000;
  var maxTokenUses = (typeof options.maxTokenUses === 'number' && options.maxTokenUses >= 0)
    ? options.maxTokenUses : 1;
  var bindIp = options.bindIp !== false;
  var maxUsedTokens = (typeof options.maxUsedTokens === 'number' && options.maxUsedTokens > 0)
    ? options.maxUsedTokens : 10000;

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
    if (signature.length !== expectedSig.length) {
      return { valid: false, reason: 'invalid_signature' };
    }
    var sigValid = true;
    for (var i = 0; i < signature.length; i++) {
      if (signature.charCodeAt(i) !== expectedSig.charCodeAt(i)) {
        sigValid = false;
      }
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
  var decayHalfLifeMs = (typeof options.decayHalfLifeMs === "number" && options.decayHalfLifeMs > 0)
    ? options.decayHalfLifeMs : 86400000; // 24 hours default
  var maxEntries = (typeof options.maxEntries === "number" && options.maxEntries > 0)
    ? Math.floor(options.maxEntries) : 10000;
  var suspiciousThreshold = (typeof options.suspiciousThreshold === "number")
    ? options.suspiciousThreshold : 0.3;
  var trustedThreshold = (typeof options.trustedThreshold === "number")
    ? options.trustedThreshold : 0.8;
  var blockThreshold = (typeof options.blockThreshold === "number")
    ? options.blockThreshold : 0.1;
  var initialScore = (typeof options.initialScore === "number")
    ? Math.max(0, Math.min(1, options.initialScore)) : 0.5;
  var solveWeight = (typeof options.solveWeight === "number" && options.solveWeight > 0)
    ? options.solveWeight : 0.1;
  var failWeight = (typeof options.failWeight === "number" && options.failWeight > 0)
    ? options.failWeight : 0.15;
  var timeoutWeight = (typeof options.timeoutWeight === "number" && options.timeoutWeight > 0)
    ? options.timeoutWeight : 0.05;
  var burstPenalty = (typeof options.burstPenalty === "number" && options.burstPenalty >= 0)
    ? options.burstPenalty : 0.2;
  var burstWindowMs = (typeof options.burstWindowMs === "number" && options.burstWindowMs > 0)
    ? options.burstWindowMs : 10000; // 10 seconds

  // Use null-prototype objects to prevent prototype pollution
  var entries = Object.create(null);
  var allowlist = Object.create(null);
  var blocklist = Object.create(null);
  var entryCount = 0;

  // Ordered list for LRU eviction
  var evictionOrder = [];

  function _now() {
    return Date.now();
  }

  function _clampScore(score) {
    return Math.max(0, Math.min(1, score));
  }

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
    if (evictionOrder.length === 0) return;
    var oldestId = evictionOrder.shift();
    if (entries[oldestId]) {
      delete entries[oldestId];
      entryCount--;
    }
  }

  /**
   * Move an identifier to the end of the eviction order (most recent).
   */
  function _touchEviction(id) {
    var idx = evictionOrder.indexOf(id);
    if (idx !== -1) {
      evictionOrder.splice(idx, 1);
    }
    evictionOrder.push(id);
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
    entry.score = _clampScore(entry.score + solveWeight);
    var isBurst = _checkBurst(entry);
    if (isBurst) {
      entry.score = _clampScore(entry.score - burstPenalty);
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
    entry.score = _clampScore(entry.score - failWeight);
    var isBurst = _checkBurst(entry);
    if (isBurst) {
      entry.score = _clampScore(entry.score - burstPenalty);
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
    entry.score = _clampScore(entry.score - timeoutWeight);
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
    var idx = evictionOrder.indexOf(id);
    if (idx !== -1) evictionOrder.splice(idx, 1);
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
    evictionOrder = [];
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
        if (typeof src.score === "number") entry.score = _clampScore(src.score);
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
    return Math.max(min, Math.min(max, Math.floor(val)));
  }

  function _clampFloat(val, min, max, fallback) {
    if (typeof val !== "number" || isNaN(val)) return fallback;
    return Math.max(min, Math.min(max, val));
  }

  function _now() { return Date.now(); }

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
          difficulty: Math.max(1, Math.min(maxEscalation, Math.floor(r.difficulty))),
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
    var finalLevel = Math.max(1, Math.min(maxEscalation, baseLevel + combinedAdjustment));

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

  var windowMs = options.windowMs != null && options.windowMs > 0 ? options.windowMs : 60000;
  var maxRequests = options.maxRequests != null && options.maxRequests > 0 ? options.maxRequests : 10;
  var burstThreshold = options.burstThreshold != null && options.burstThreshold > 0 ? options.burstThreshold : 5;
  var burstWindowMs = options.burstWindowMs != null && options.burstWindowMs > 0 ? options.burstWindowMs : 5000;
  var maxDelay = options.maxDelay != null && options.maxDelay >= 0 ? options.maxDelay : 30000;
  var baseDelay = options.baseDelay != null && options.baseDelay >= 0 ? options.baseDelay : 1000;
  var maxClients = options.maxClients != null && options.maxClients > 0 ? options.maxClients : 10000;

  // Sets for O(1) lookup
  var allowSet = {};
  var blockSet = {};
  (options.allowlist || []).forEach(function (id) { allowSet[id] = true; });
  (options.blocklist || []).forEach(function (id) { blockSet[id] = true; });

  // clientId -> { timestamps: number[], lastAccess: number }
  var clients = {};
  var clientCount = 0;
  var clientOrder = []; // LRU order (oldest first)

  // Stats
  var totalChecks = 0;
  var totalAllowed = 0;
  var totalLimited = 0;
  var totalBlocked = 0;
  var totalBursts = 0;

  /**
   * Remove expired timestamps from a client's record.
   */
  function pruneTimestamps(record, now) {
    var cutoff = now - windowMs;
    var i = 0;
    while (i < record.timestamps.length && record.timestamps[i] <= cutoff) {
      i++;
    }
    if (i > 0) {
      record.timestamps = record.timestamps.slice(i);
    }
  }

  /**
   * Evict oldest clients when over maxClients.
   */
  function evictIfNeeded() {
    while (clientCount > maxClients && clientOrder.length > 0) {
      var oldest = clientOrder.shift();
      if (clients[oldest]) {
        delete clients[oldest];
        clientCount--;
      }
    }
  }

  /**
   * Move client to end of LRU order.
   */
  function touchClient(clientId) {
    var idx = clientOrder.indexOf(clientId);
    if (idx !== -1) {
      clientOrder.splice(idx, 1);
    }
    clientOrder.push(clientId);
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
    touchClient(clientId);
    return clients[clientId];
  }

  /**
   * Count timestamps in last N ms.
   */
  function countInWindow(timestamps, now, windowSize) {
    var cutoff = now - windowSize;
    var count = 0;
    for (var i = timestamps.length - 1; i >= 0; i--) {
      if (timestamps[i] > cutoff) count++;
      else break;
    }
    return count;
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
      var idx = clientOrder.indexOf(clientId);
      if (idx !== -1) clientOrder.splice(idx, 1);
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
      clientOrder = [];
      clientCount = 0;
      Object.keys(state.clients).forEach(function (id) {
        clients[id] = {
          timestamps: (state.clients[id].timestamps || []).slice(),
          lastAccess: state.clients[id].lastAccess || 0,
        };
        clientOrder.push(id);
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
    clientOrder = [];
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
  var storeOrder = []; // LRU tracking: oldest first

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
    // Remove expired
    var i = 0;
    while (i < storeOrder.length) {
      var hash = storeOrder[i];
      if (store[hash] && (now - store[hash].lastSeen) > ttlMs) {
        delete store[hash];
        storeOrder.splice(i, 1);
      } else {
        i++;
      }
    }
    // LRU eviction if over limit
    while (storeOrder.length > maxFingerprints) {
      var oldest = storeOrder.shift();
      delete store[oldest];
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

    // Move to end of LRU
    var idx = storeOrder.indexOf(hash);
    if (idx !== -1 && idx !== storeOrder.length - 1) {
      storeOrder.splice(idx, 1);
      storeOrder.push(hash);
    }

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
      storeOrder: storeOrder.slice(),
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
      storeOrder = state.storeOrder.slice();
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
    storeOrder = [];
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

  var correlationWindowMs = options.correlationWindowMs != null && options.correlationWindowMs > 0
    ? options.correlationWindowMs : 60000;
  var maxIncidents = options.maxIncidents != null && options.maxIncidents > 0
    ? options.maxIncidents : 1000;
  var maxSignalsPerIncident = options.maxSignalsPerIncident != null && options.maxSignalsPerIncident > 0
    ? options.maxSignalsPerIncident : 50;

  var thresholds = options.thresholds || {};
  var warningThreshold = thresholds.warning != null && thresholds.warning > 0 ? thresholds.warning : 3;
  var highThreshold = thresholds.high != null && thresholds.high > 0 ? thresholds.high : 6;
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
   */
  function evictIfNeeded() {
    while (incidentOrder.length > maxIncidents) {
      var oldId = incidentOrder.shift();
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
  }

  /**
   * Get a read-only summary of an incident.
   */
  function getIncidentSummary(incident) {
    return {
      id: incident.id,
      clientId: incident.clientId,
      severity: incident.severity,
      status: incident.status,
      signalCount: incident.signalCount,
      weightedCount: incident.weightedCount,
      signalTypes: JSON.parse(JSON.stringify(incident.signalTypes)),
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
   * @returns {object} Current stats snapshot
   */
  function getStats() {
    return {
      totalSignals: stats.totalSignals,
      totalIncidents: stats.totalIncidents,
      activeIncidents: incidentOrder.reduce(function (n, id) {
        return n + (incidents[id] && incidents[id].status === "open" ? 1 : 0);
      }, 0),
      totalAlerts: stats.totalAlerts,
      totalEscalations: stats.totalEscalations,
      signalsByType: JSON.parse(JSON.stringify(stats.signalsByType)),
      incidentsBySeverity: JSON.parse(JSON.stringify(stats.incidentsBySeverity)),
    };
  }

  /**
   * Reset all state.
   */
  function reset() {
    clientIncidents = {};
    incidents = {};
    incidentOrder = [];
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
    return {
      incidents: incidentOrder.map(function (id) {
        return incidents[id] ? getIncidentSummary(incidents[id]) : null;
      }).filter(Boolean),
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
  GIF_MAX_RETRIES: GIF_MAX_RETRIES,
  GIF_RETRY_DELAY_MS: GIF_RETRY_DELAY_MS,
};

// UMD export — works in Node.js, AMD, and browser globals
if (typeof module !== "undefined" && module.exports) {
  module.exports = gifCaptcha;
} else if (typeof define === "function" && define.amd) {
  define(function () { return gifCaptcha; });
} else if (typeof window !== "undefined") {
  window.gifCaptcha = gifCaptcha;
}
