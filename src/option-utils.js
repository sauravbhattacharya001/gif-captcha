/**
 * option-utils.js — Shared option-parsing helpers for gif-captcha.
 *
 * Consolidates _posOpt and _nnOpt which were previously duplicated in
 * index.js, challenge-pool-manager.js, and webhook-dispatcher.js.
 *
 * @module gif-captcha/option-utils
 */

"use strict";

/**
 * Extract a positive-number option, falling back to a default.
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
 * @param {*}      val      The option value to check
 * @param {number} fallback Default when val is null/undefined/negative
 * @returns {number}
 */
function _nnOpt(val, fallback) {
  return val != null && val >= 0 ? val : fallback;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    _posOpt: _posOpt,
    _nnOpt: _nnOpt,
  };
}
