/**
 * crypto-utils-fallback.test.js — Covers the non-Node fallback and error
 * branches in src/crypto-utils.js.
 *
 * The primary crypto-utils.test.js exercises the happy path on Node, where
 * `require('crypto')` succeeds and `_crypto.randomInt` / `_crypto.randomBytes`
 * are used. That leaves three branches uncovered:
 *
 *   1. Web Crypto fallback: `_crypto` is null but a global `crypto` with
 *      `getRandomValues` is available (browser environment).
 *   2. Hard-error path: no Node crypto AND no global `crypto.getRandomValues`,
 *      so all three exported functions must throw a CWE-330 error rather
 *      than silently fall back to Math.random().
 *   3. secureRandomInt input validation: exclusiveMax <= 0 must throw
 *      RangeError.
 *
 * Stubbing `require('crypto')` from outside doesn't work cleanly because
 * Node builtins bypass `Module._load`. Instead we load the source of
 * crypto-utils.js into a `vm` context where `require` and `crypto` are
 * exactly what we want them to be. The functions we get back are then
 * indistinguishable from the production module — they were compiled from
 * the same source bytes.
 *
 * This is important coverage: the whole point of crypto-utils.js is the
 * CWE-330 guarantee that a CAPTCHA build will _refuse_ to start rather
 * than silently use Math.random(). If that error branch regresses we
 * have to know.
 */

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const SRC = fs.readFileSync(path.resolve(__dirname, "../src/crypto-utils.js"), "utf8");

/**
 * Compile crypto-utils.js inside a fresh vm context with a controlled
 * `require` and optional global `crypto`. Returns the module's exports.
 *
 * @param {object} opts
 * @param {boolean} [opts.blockNodeCrypto=false] - if true, require('crypto') throws.
 * @param {object|null} [opts.fakeWebCrypto=null] - value for global `crypto`.
 */
function loadCryptoUtils({ blockNodeCrypto = false, fakeWebCrypto = null } = {}) {
  const moduleObj = { exports: {} };
  const requireStub = function (name) {
    if (name === "crypto") {
      if (blockNodeCrypto) {
        throw new Error("synthetic: crypto module unavailable");
      }
      return require("crypto");
    }
    return require(name);
  };

  const sandbox = {
    module: moduleObj,
    exports: moduleObj.exports,
    require: requireStub,
    console,
    Uint32Array,
    Uint8Array,
    Math,
    RangeError,
    Error,
  };
  if (fakeWebCrypto !== null) {
    sandbox.crypto = fakeWebCrypto;
  }

  const context = vm.createContext(sandbox);
  vm.runInContext(SRC, context, { filename: "crypto-utils.js" });
  return moduleObj.exports;
}

describe("crypto-utils fallback: Web Crypto path", function () {
  it("secureRandom uses global crypto.getRandomValues when Node crypto is unavailable", function () {
    let callCount = 0;
    const fakeWebCrypto = {
      getRandomValues(arr) {
        callCount++;
        for (let i = 0; i < arr.length; i++) arr[i] = (i + 1) * 1234567;
        return arr;
      },
    };

    const mod = loadCryptoUtils({ blockNodeCrypto: true, fakeWebCrypto });

    const v = mod.secureRandom();
    assert.equal(typeof v, "number");
    assert.ok(v >= 0 && v < 1, "secureRandom result must be in [0,1), got " + v);
    assert.ok(callCount >= 1, "expected Web Crypto getRandomValues to be called");
  });

  it("secureRandomHex uses global crypto.getRandomValues when Node crypto is unavailable", function () {
    let callCount = 0;
    const fakeWebCrypto = {
      getRandomValues(arr) {
        callCount++;
        for (let i = 0; i < arr.length; i++) arr[i] = (i * 17 + 3) & 0xff;
        return arr;
      },
    };

    const mod = loadCryptoUtils({ blockNodeCrypto: true, fakeWebCrypto });

    // Even-length result.
    const a = mod.secureRandomHex(16);
    assert.equal(a.length, 16);
    assert.match(a, /^[0-9a-f]+$/);

    // Odd-length result (covers the .slice(0, len) tail-trim branch).
    const b = mod.secureRandomHex(7);
    assert.equal(b.length, 7);
    assert.match(b, /^[0-9a-f]+$/);

    assert.ok(callCount >= 2, "expected getRandomValues to be called at least twice");
  });

  it("secureRandomInt uses global crypto.getRandomValues with rejection sampling", function () {
    // Drive a deterministic stream: first sample is above the rejection
    // threshold so the loop must reject and pull again.
    // exclusiveMax = 10 → limit = floor(2^32 / 10) * 10 = 4294967290.
    const stream = [4294967291, 42];
    let i = 0;
    const fakeWebCrypto = {
      getRandomValues(arr) {
        arr[0] = stream[Math.min(i, stream.length - 1)];
        i++;
        return arr;
      },
    };

    const mod = loadCryptoUtils({ blockNodeCrypto: true, fakeWebCrypto });

    const v = mod.secureRandomInt(10);
    assert.equal(v, 42 % 10);
    assert.ok(i >= 2, "expected at least one rejection-and-retry, got i=" + i);
  });

  it("secureRandomInt special-cases exclusiveMax === 1 without consuming entropy", function () {
    let called = 0;
    const fakeWebCrypto = {
      getRandomValues(arr) { called++; arr[0] = 0; return arr; },
    };

    const mod = loadCryptoUtils({ blockNodeCrypto: true, fakeWebCrypto });

    assert.equal(mod.secureRandomInt(1), 0);
    assert.equal(called, 0, "exclusiveMax=1 must not consume entropy");
  });
});

describe("crypto-utils fallback: hard-error path (CWE-330 guarantee)", function () {
  it("secureRandom throws when no Node crypto and no Web Crypto are available", function () {
    const mod = loadCryptoUtils({ blockNodeCrypto: true, fakeWebCrypto: null });

    assert.throws(() => mod.secureRandom(), /no cryptographic random source available/i);
  });

  it("secureRandomHex throws when no Node crypto and no Web Crypto are available", function () {
    const mod = loadCryptoUtils({ blockNodeCrypto: true, fakeWebCrypto: null });

    assert.throws(() => mod.secureRandomHex(16), /no cryptographic random source available/i);
  });

  it("secureRandomInt throws when no Node crypto and no Web Crypto are available", function () {
    const mod = loadCryptoUtils({ blockNodeCrypto: true, fakeWebCrypto: null });

    // exclusiveMax > 1 so we go past the trivial short-circuit and actually
    // hit the no-source branch.
    assert.throws(() => mod.secureRandomInt(10), /no cryptographic random source available/i);
  });

  it("error message mentions CWE-330 so security reviewers can grep for it", function () {
    const mod = loadCryptoUtils({ blockNodeCrypto: true, fakeWebCrypto: null });

    try {
      mod.secureRandom();
      assert.fail("expected secureRandom to throw");
    } catch (e) {
      assert.match(e.message, /CWE-330/);
    }
  });
});

describe("crypto-utils input validation", function () {
  // Real (non-stubbed) module — input validation runs before any RNG.
  const { secureRandomInt } = require("../src/crypto-utils");

  it("secureRandomInt(0) throws RangeError", function () {
    assert.throws(() => secureRandomInt(0), RangeError);
  });

  it("secureRandomInt(-1) throws RangeError", function () {
    assert.throws(() => secureRandomInt(-1), RangeError);
  });

  it("RangeError message mentions exclusiveMax for debuggability", function () {
    try {
      secureRandomInt(-5);
      assert.fail("expected throw");
    } catch (e) {
      assert.ok(e instanceof RangeError);
      assert.match(e.message, /exclusiveMax/);
    }
  });
});
