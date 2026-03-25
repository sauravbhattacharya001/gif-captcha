/**
 * crypto-utils.js — Shared cryptographic random utilities for gif-captcha.
 *
 * Consolidates the _crypto require + random helpers that were previously
 * copy-pasted across 6+ modules (bot-signature-database, challenge-pool-manager,
 * challenge-rotation-scheduler, challenge-template-engine, honeypot-injector,
 * ab-experiment-runner, trust-score-engine).
 *
 * All CAPTCHA-security-critical modules should import from here to ensure
 * consistent CWE-330 mitigation and avoid duplicated fallback logic.
 *
 * @module gif-captcha/crypto-utils
 */

"use strict";

var _crypto;
try { _crypto = require("crypto"); } catch (e) { _crypto = null; }

var _warnedNoCrypto = false;

function _warnOnce() {
  if (!_warnedNoCrypto) {
    _warnedNoCrypto = true;
    if (typeof console !== "undefined" && console.warn) {
      console.warn(
        "gif-captcha/crypto-utils: no crypto source available, falling back to " +
        "Math.random(). Random values will be predictable (CWE-330)."
      );
    }
  }
}

/**
 * Return a cryptographically secure random float in [0, 1).
 *
 * Uses Node.js crypto.randomBytes or Web Crypto API when available.
 * Falls back to Math.random() with a console warning.
 *
 * @returns {number} Random float in [0, 1)
 */
function secureRandom() {
  if (_crypto && typeof _crypto.randomBytes === "function") {
    return _crypto.randomBytes(4).readUInt32BE(0) / 4294967296;
  }
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    var arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return arr[0] / 4294967296;
  }
  _warnOnce();
  return Math.random();
}

/**
 * Generate a cryptographically secure hex string of the given length.
 *
 * @param {number} len - Desired hex character count
 * @returns {string} Hex string of exactly `len` characters
 */
function secureRandomHex(len) {
  if (_crypto && typeof _crypto.randomBytes === "function") {
    return _crypto.randomBytes(Math.ceil(len / 2)).toString("hex").slice(0, len);
  }
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    var bytes = new Uint8Array(Math.ceil(len / 2));
    crypto.getRandomValues(bytes);
    var s = "";
    for (var i = 0; i < bytes.length; i++) {
      s += bytes[i].toString(16).padStart(2, "0");
    }
    return s.slice(0, len);
  }
  _warnOnce();
  var s = "";
  for (var j = 0; j < len; j++) {
    s += Math.floor(Math.random() * 16).toString(16);
  }
  return s;
}

/**
 * Generate a cryptographically secure random integer in [0, exclusiveMax).
 *
 * Uses rejection sampling to eliminate modulo bias: raw 32-bit random
 * values that fall in the biased remainder zone (above the largest
 * multiple of exclusiveMax that fits in 2^32) are discarded and
 * re-sampled.  This guarantees a perfectly uniform distribution for
 * any exclusiveMax up to 2^32.
 *
 * @param {number} exclusiveMax - Exclusive upper bound (must be > 0 and <= 2^32)
 * @returns {number} Random integer in [0, exclusiveMax)
 */
function secureRandomInt(exclusiveMax) {
  if (exclusiveMax <= 0 || exclusiveMax > 4294967296) {
    throw new Error("exclusiveMax must be in (0, 2^32]");
  }
  if (exclusiveMax === 1) return 0;

  // Rejection sampling: discard values in the biased tail.
  // limit is the largest multiple of exclusiveMax that fits in 2^32.
  var limit = 4294967296 - (4294967296 % exclusiveMax);

  if (_crypto && typeof _crypto.randomBytes === "function") {
    for (;;) {
      var val = _crypto.randomBytes(4).readUInt32BE(0);
      if (val < limit) return val % exclusiveMax;
    }
  }
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    var arr = new Uint32Array(1);
    for (;;) {
      crypto.getRandomValues(arr);
      if (arr[0] < limit) return arr[0] % exclusiveMax;
    }
  }
  _warnOnce();
  return Math.floor(Math.random() * exclusiveMax);
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    secureRandom: secureRandom,
    secureRandomHex: secureRandomHex,
    secureRandomInt: secureRandomInt
  };
}
