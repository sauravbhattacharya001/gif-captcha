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

    var hasSource = challenge.sourceUrl && challenge.sourceUrl !== "#";
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
  loadGifWithRetry: loadGifWithRetry,
  textSimilarity: textSimilarity,
  validateAnswer: validateAnswer,
  createChallenge: createChallenge,
  pickChallenges: pickChallenges,
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
