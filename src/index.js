/**
 * gif-captcha — Core library for GIF-based CAPTCHA challenges.
 *
 * Provides utilities for creating, presenting, and validating GIF CAPTCHAs
 * that leverage human visual comprehension to distinguish humans from bots.
 *
 * @module gif-captcha
 */

"use strict";

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
  return {
    id: opts.id,
    title: opts.title || "Challenge " + opts.id,
    gifUrl: opts.gifUrl,
    sourceUrl: opts.sourceUrl || "#",
    humanAnswer: opts.humanAnswer,
    aiAnswer: opts.aiAnswer || "",
    keywords: opts.keywords || [],
  };
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
    var j = Math.floor(Math.random() * (i + 1));
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
