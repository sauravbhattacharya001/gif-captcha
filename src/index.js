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
    var arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
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
  var challenges = {};

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
    challenges = {};
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
    var sets = _getWordSets();
    var pairs = [];
    for (var i = 0; i < _challenges.length; i++) {
      for (var j = i + 1; j < _challenges.length; j++) {
        var sim = _jaccardSets(sets[i], sets[j]);
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
    var sets = _getWordSets();
    var totalDissimilarity = 0;
    var pairCount = 0;
    for (var i = 0; i < _challenges.length; i++) {
      for (var j = i + 1; j < _challenges.length; j++) {
        var sim = _jaccardSets(sets[i], sets[j]);
        totalDissimilarity += (1 - sim);
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
  var _responses = {};

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
   * @returns {Array<{ challengeId: string, originalDifficulty: number,
   *                    calibratedDifficulty: number, delta: number, direction: string }>}
   */
  function findOutliers(threshold) {
    if (threshold === undefined) threshold = 20;
    if (typeof threshold !== "number" || threshold < 0) {
      throw new Error("threshold must be a non-negative number");
    }
    var all = calibrateAll();
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
  function getDifficultyDistribution() {
    var dist = { easy: 0, medium: 0, hard: 0 };
    _challenges.forEach(function (ch) {
      var id = ch.id || ch.title;
      var d = calibrateDifficulty(id);
      if (d === null) return;
      if (d < 33) dist.easy++;
      else if (d < 67) dist.medium++;
      else dist.hard++;
    });
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

    var outliers = findOutliers(20);
    var dist = getDifficultyDistribution();

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
  var sessions = {};
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
  var registry = {};
  var activeIds = [];

  function _now() { return Date.now(); }

  function _rebuildActive() {
    activeIds = [];
    for (var id in registry) {
      if (registry.hasOwnProperty(id) && !registry[id].retired) {
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
      var rand = Math.random() * totalWeight;
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
      if (registry.hasOwnProperty(rid)) {
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
      if (!registry.hasOwnProperty(id)) continue;
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
      if (!registry.hasOwnProperty(id)) continue;
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

// ── Exports ─────────────────────────────────────────────────────────

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
