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
    return _sanitizeEl.innerHTML;
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

        var hasSource = challenge.sourceUrl && challenge.sourceUrl !== "#";
        var errorHtml = '<div class="gif-error">' +
            "<p>⚠️ GIF couldn't load (CDN may be blocking direct access).</p>";

        if (hasSource) {
            errorHtml +=
                '<p><a href="' + sanitize(challenge.sourceUrl) +
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

    // Cache-buster on retry to bypass cached failures
    img.src = attempt > 0
        ? challenge.gifUrl + "?retry=" + attempt
        : challenge.gifUrl;
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
