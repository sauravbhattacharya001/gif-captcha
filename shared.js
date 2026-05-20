/**
 * shared.js — Common JavaScript utilities for gif-captcha.
 *
 * Extracted from duplicate inline <script> blocks across HTML pages.
 * Previously each page created its own sanitizer element and GIF retry
 * logic. This module provides them once.
 */

// ===== Text Sanitizer =====
// Reusable DOM element for HTML-escaping untrusted strings.
// Shared across demo.html, analysis.html, generator.html, temporal.html.
var _sanitizeEl = document.createElement("div");

/**
 * Escape a string for safe insertion into innerHTML.
 * Uses the browser's built-in text → HTML encoding.
 * @param {string} str - Untrusted input
 * @returns {string} HTML-safe string
 */
function sanitize(str) {
    _sanitizeEl.textContent = str;
    // textContent→innerHTML escapes <, >, & but NOT quotes.
    // When the result is used inside HTML attributes (e.g. href="..."),
    // unescaped quotes allow attribute injection (XSS).
    // Escape both quote styles for safe use in any HTML context.
    return _sanitizeEl.innerHTML
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// ===== URL Sanitizer =====

/**
 * Sanitize a URL for safe use in href attributes.
 * Rejects dangerous schemes (javascript:, data:, vbscript:, blob:, file:)
 * to prevent XSS via URL injection.
 *
 * @param {string} url - Untrusted URL
 * @returns {string} Safe URL, or empty string if dangerous
 */
function sanitizeUrl(url) {
    if (!url || typeof url !== "string") return "";
    var trimmed = url.replace(/^[\x00-\x1f\s]+/, "").trim();
    if (trimmed.length === 0) return "";
    var lower = trimmed.toLowerCase();
    if (/^(javascript|data|vbscript|blob|file|ftp):/.test(lower)) return "";
    return trimmed;
}

// ===== GIF Loading with Retry =====
var GIF_MAX_RETRIES = 2;
var GIF_RETRY_DELAY_MS = 1500;

/**
 * Load a GIF image into a container with automatic retry on failure.
 * On final failure, shows a fallback with a link to the source or a hint.
 *
 * @param {HTMLElement} container - DOM element to render into
 * @param {Object} challenge - Object with { title, gifUrl, sourceUrl }
 * @param {number} attempt - Current attempt (0-indexed)
 */
function loadGifWithRetry(container, challenge, attempt) {
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
                (attempt + 1) + '/' + GIF_MAX_RETRIES + ')</span>';
            setTimeout(function () {
                loadGifWithRetry(container, challenge, attempt + 1);
            }, GIF_RETRY_DELAY_MS);
            return;
        }

        var safeSource = sanitizeUrl(challenge.sourceUrl);
        var hasSource = safeSource && safeSource !== "#";
        var errorHtml = '<div class="gif-error">' +
            "<p>⚠️ GIF couldn't load (CDN may be blocking direct access).</p>";

        if (hasSource) {
            errorHtml +=
                '<p><a href="' + sanitize(safeSource) +
                '" target="_blank" rel="noopener noreferrer">Open GIF in new tab →</a></p>' +
                '<p style="margin-top:0.5rem;font-size:0.8rem;">Watch it there, then come back and describe what happened.</p>';
        } else {
            errorHtml +=
                '<p style="margin-top:0.5rem;font-size:0.85rem;color:var(--yellow);">💡 Hint: This GIF is titled "' +
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

// ===== Browser-side gifCaptcha shim =====
// Some pages (e.g. batch.html) need a small subset of the library that is
// genuinely browser-safe (no Node `require`). The full src/index.js is a
// CommonJS module that throws "require is not defined" when loaded into a
// plain <script> tag, so we expose just the pure-string helpers here.
//
// This intentionally mirrors the names/signatures of the equivalents in
// src/shared-utils.js so behaviour stays in sync.

/**
 * Word-set Jaccard similarity between two strings (case-insensitive).
 * Matches src/shared-utils.js `textSimilarity` so server-side and
 * browser-side validation produce identical scores.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} similarity in [0, 1]
 */
function _gcTextSimilarity(a, b) {
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

    // |A ∪ B| = |A| + |B| - |A ∩ B|
    return intersection / (uniqueA + uniqueB - intersection);
}

// Expose as `window.gifCaptcha.textSimilarity` so pages can use the same
// surface they use in Node tests via `require('gif-captcha').textSimilarity`.
if (typeof window !== "undefined") {
    window.gifCaptcha = window.gifCaptcha || {};
    if (typeof window.gifCaptcha.textSimilarity !== "function") {
        window.gifCaptcha.textSimilarity = _gcTextSimilarity;
    }
    if (typeof window.gifCaptcha.sanitize !== "function") {
        // `sanitize` is declared at file scope above and is HTML-escape only;
        // exposing it on the namespace lets pages use a single import surface.
        window.gifCaptcha.sanitize = sanitize;
    }
}

// ===== Canvas roundRect Polyfill =====
// Used by analysis.html and simulator.html for chart rendering.
if (typeof CanvasRenderingContext2D !== "undefined" &&
    !CanvasRenderingContext2D.prototype.roundRect) {
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
