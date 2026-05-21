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

// Resolved Web Crypto reference (or null). Looked up once at module load to
// avoid repeating `typeof crypto !== "undefined"` dances on every call and to
// keep the hot paths branch-light.
var _webCrypto = (typeof crypto !== "undefined" && crypto && typeof crypto.getRandomValues === "function")
  ? crypto
  : null;

// Single source of truth for the CWE-330 hard-fail message. Previously each
// function carried its own near-identical copy, which drifted on edits and
// made it harder for security reviewers to grep for a canonical string.
var NO_CRYPTO_MESSAGE =
  "gif-captcha/crypto-utils: no cryptographic random source available. " +
  "CAPTCHA security requires crypto.randomBytes/randomInt (Node.js) or " +
  "crypto.getRandomValues (browser). Math.random() is predictable " +
  "and must not be used for challenge generation (CWE-330).";

function noCryptoError() {
  return new Error(NO_CRYPTO_MESSAGE);
}

/**
 * Return a cryptographically secure random float in [0, 1).
 *
 * Uses Node.js crypto.randomBytes or Web Crypto API when available.
 * Throws if no cryptographic source is available — a CAPTCHA library
 * must never fall back to Math.random() as it is predictable (CWE-330)
 * and would allow attackers to forecast challenges.
 *
 * @returns {number} Random float in [0, 1)
 * @throws {Error} If no cryptographic random source is available
 */
function secureRandom() {
  if (_crypto && typeof _crypto.randomBytes === "function") {
    return _crypto.randomBytes(4).readUInt32BE(0) / 4294967296;
  }
  if (_webCrypto) {
    var arr = new Uint32Array(1);
    _webCrypto.getRandomValues(arr);
    return arr[0] / 4294967296;
  }
  throw noCryptoError();
}

/**
 * Generate a cryptographically secure hex string of the given length.
 *
 * @param {number} len - Desired hex character count
 * @returns {string} Hex string of exactly `len` characters
 * @throws {Error} If no cryptographic random source is available
 */
function secureRandomHex(len) {
  var byteLen = Math.ceil(len / 2);
  if (_crypto && typeof _crypto.randomBytes === "function") {
    return _crypto.randomBytes(byteLen).toString("hex").slice(0, len);
  }
  if (_webCrypto) {
    var bytes = new Uint8Array(byteLen);
    _webCrypto.getRandomValues(bytes);
    var s = "";
    for (var i = 0; i < bytes.length; i++) {
      s += bytes[i].toString(16).padStart(2, "0");
    }
    return s.slice(0, len);
  }
  throw noCryptoError();
}

/**
 * Generate a cryptographically secure random integer in [0, exclusiveMax).
 *
 * Uses Node.js crypto.randomInt when available for bias-free generation.
 * Falls back to rejection sampling with crypto.randomBytes or Web Crypto
 * to eliminate modulo bias (which could let attackers predict challenges
 * with slightly skewed probability distributions).
 *
 * @param {number} exclusiveMax - Exclusive upper bound (must be > 0)
 * @returns {number} Random integer in [0, exclusiveMax)
 * @throws {RangeError} If exclusiveMax <= 0
 * @throws {Error} If no cryptographic random source is available
 */
function secureRandomInt(exclusiveMax) {
  if (exclusiveMax <= 0) {
    throw new RangeError("exclusiveMax must be > 0, got " + exclusiveMax);
  }
  if (exclusiveMax === 1) return 0;

  // Prefer crypto.randomInt — no bias, no rejection loop.
  if (_crypto && typeof _crypto.randomInt === "function") {
    return _crypto.randomInt(exclusiveMax);
  }

  // Rejection sampling to eliminate modulo bias. Both fallback paths share
  // the same `limit` computation, so we hoist it out of the source-specific
  // branches.
  var limit = Math.floor(0x100000000 / exclusiveMax) * exclusiveMax;

  if (_crypto && typeof _crypto.randomBytes === "function") {
    var val;
    do {
      val = _crypto.randomBytes(4).readUInt32BE(0);
    } while (val >= limit);
    return val % exclusiveMax;
  }

  if (_webCrypto) {
    var arr = new Uint32Array(1);
    do {
      _webCrypto.getRandomValues(arr);
    } while (arr[0] >= limit);
    return arr[0] % exclusiveMax;
  }

  throw noCryptoError();
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    secureRandom: secureRandom,
    secureRandomHex: secureRandomHex,
    secureRandomInt: secureRandomInt
  };
}
