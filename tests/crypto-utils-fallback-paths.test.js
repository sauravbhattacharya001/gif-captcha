/**
 * crypto-utils-fallback-paths.test.js — Cover the non-default crypto branches.
 *
 * The default `crypto-utils.test.js` exercises the happy path on Node, which
 * means coverage only ever hits the `_crypto.randomBytes` / `_crypto.randomInt`
 * branches. The three fallback paths (Web Crypto for `secureRandom`,
 * `secureRandomHex`, and `secureRandomInt`'s rejection-sampling loop) plus
 * the "no crypto at all" hard-fail branch never run.
 *
 * Those branches are the security-critical edges: they're what actually
 * executes in a browser bundle and what hard-fails (CWE-330) if neither
 * source is available. They MUST be tested.
 *
 * Strategy: reload `crypto-utils.js` with the `require("crypto")` resolution
 * and the global `crypto` swapped so each module-load-time capture picks the
 * variant we want. We never touch the real `require("crypto")` outside this
 * file.
 */

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const Module = require("node:module");

const cryptoUtilsPath = require.resolve("../src/crypto-utils");

function loadCryptoUtilsWith({ nodeCrypto, webCrypto }) {
  // Drop any cached copy so the module's top-level captures re-execute.
  delete require.cache[cryptoUtilsPath];

  const origLoad = Module._load;
  Module._load = function (request, parent, ...rest) {
    if (request === "crypto" && parent && parent.filename === cryptoUtilsPath) {
      if (nodeCrypto === "throw") {
        throw new Error("simulated: crypto module unavailable");
      }
      return nodeCrypto;
    }
    return origLoad.call(this, request, parent, ...rest);
  };

  const hadGlobal = "crypto" in globalThis;
  const prevGlobal = globalThis.crypto;
  if (webCrypto === undefined) {
    try { delete globalThis.crypto; } catch (_) { /* non-configurable */ }
  } else {
    Object.defineProperty(globalThis, "crypto", {
      value: webCrypto, configurable: true, writable: true,
    });
  }

  let mod;
  try {
    mod = require("../src/crypto-utils");
  } finally {
    Module._load = origLoad;
    if (hadGlobal) {
      Object.defineProperty(globalThis, "crypto", {
        value: prevGlobal, configurable: true, writable: true,
      });
    } else {
      try { delete globalThis.crypto; } catch (_) { /* non-configurable */ }
    }
    // Always evict our temporarily-loaded copy so other test files get the
    // real one back.
    delete require.cache[cryptoUtilsPath];
  }
  return mod;
}

// Build a Web Crypto stub that yields the given byte sequence, looping.
// Honors view type: Uint32Array consumes 4 bytes per slot (big-endian-ish,
// matching how `getRandomValues` would just fill the underlying buffer).
function makeWebCryptoStub(bytes) {
  let i = 0;
  const next = () => bytes[(i++) % bytes.length] & 0xFF;
  return {
    getRandomValues(view) {
      if (view instanceof Uint8Array) {
        for (let k = 0; k < view.length; k++) view[k] = next();
      } else if (view instanceof Uint32Array) {
        for (let k = 0; k < view.length; k++) {
          // Order doesn't matter for the consuming code's correctness; it just
          // divides by 2^32 or compares against a limit. Pack four bytes
          // unsigned.
          const b0 = next(), b1 = next(), b2 = next(), b3 = next();
          view[k] = ((b0 << 24) >>> 0) | (b1 << 16) | (b2 << 8) | b3;
        }
      } else {
        for (let k = 0; k < view.length; k++) view[k] = next();
      }
      return view;
    },
  };
}

// ---------------------------------------------------------------------------
// Path 1: Web Crypto present, Node crypto absent. Exercises the browser-bundle
// branches in secureRandom and secureRandomHex.
// ---------------------------------------------------------------------------

describe("crypto-utils: Web Crypto fallback — secureRandom / secureRandomHex", function () {
  it("secureRandom() uses getRandomValues and stays in [0,1)", function () {
    const mod = loadCryptoUtilsWith({
      nodeCrypto: null,
      webCrypto: makeWebCryptoStub([0x12, 0x34, 0x56, 0x78]),
    });
    const v = mod.secureRandom();
    assert.equal(typeof v, "number");
    assert.ok(v >= 0 && v < 1, "out of range: " + v);
  });

  it("secureRandomHex(n) returns exactly n lowercase hex chars (even n)", function () {
    const mod = loadCryptoUtilsWith({
      nodeCrypto: null,
      webCrypto: makeWebCryptoStub([0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45]),
    });
    const h = mod.secureRandomHex(12);
    assert.equal(h.length, 12);
    assert.match(h, /^[0-9a-f]{12}$/);
  });

  it("secureRandomHex handles odd lengths via the slice() tail", function () {
    const mod = loadCryptoUtilsWith({
      nodeCrypto: null,
      webCrypto: makeWebCryptoStub([0x0A, 0xBC, 0xDE]),
    });
    const h = mod.secureRandomHex(5);
    assert.equal(h.length, 5);
    assert.match(h, /^[0-9a-f]{5}$/);
  });

  it("secureRandomHex single-byte padStart path (leading-zero byte)", function () {
    // 0x00 byte must be encoded as "00", not "0" — covers padStart branch.
    const mod = loadCryptoUtilsWith({
      nodeCrypto: null,
      webCrypto: makeWebCryptoStub([0x00, 0x00, 0x00, 0x00]),
    });
    assert.equal(mod.secureRandomHex(8), "00000000");
  });
});

// ---------------------------------------------------------------------------
// Path 2: Web Crypto-only secureRandomInt rejection-sampling loop. exclusiveMax
// = 10 → limit = floor(2^32 / 10) * 10 = 4294967290. We feed 0xFFFFFFFF (>=
// limit, rejected) then a small value that maps to a deterministic result.
// ---------------------------------------------------------------------------

describe("crypto-utils: Web Crypto fallback — secureRandomInt rejection sampling", function () {
  it("loops on out-of-range draws and returns a valid int", function () {
    const mod = loadCryptoUtilsWith({
      nodeCrypto: null,
      webCrypto: makeWebCryptoStub([
        0xFF, 0xFF, 0xFF, 0xFF,   // first draw = 4294967295 → >= limit, retry
        0x00, 0x00, 0x00, 0x07,   // second draw = 7 → accepted, 7 % 10 = 7
      ]),
    });
    assert.equal(mod.secureRandomInt(10), 7);
  });

  it("short-circuits exclusiveMax=1 without consuming entropy", function () {
    let calls = 0;
    const mod = loadCryptoUtilsWith({
      nodeCrypto: null,
      webCrypto: {
        getRandomValues(v) { calls++; return v; },
      },
    });
    assert.equal(mod.secureRandomInt(1), 0);
    assert.equal(calls, 0, "no Web Crypto call should have happened");
  });

  it("rejects exclusiveMax <= 0 with RangeError before touching crypto", function () {
    let calls = 0;
    const mod = loadCryptoUtilsWith({
      nodeCrypto: null,
      webCrypto: {
        getRandomValues(v) { calls++; return v; },
      },
    });
    assert.throws(() => mod.secureRandomInt(0), RangeError);
    assert.throws(() => mod.secureRandomInt(-5), RangeError);
    assert.equal(calls, 0);
  });
});

// ---------------------------------------------------------------------------
// Path 3: Node crypto present but only with `randomBytes` (no `randomInt`).
// Some bundler shims expose this shape. Exercises the rejection-sampling
// branch with crypto.randomBytes.
// ---------------------------------------------------------------------------

describe("crypto-utils: Node crypto without randomInt (randomBytes fallback)", function () {
  it("loops on rejection and returns a valid int", function () {
    let drawCount = 0;
    const fakeNodeCrypto = {
      randomBytes(n) {
        drawCount++;
        const buf = Buffer.alloc(n);
        if (drawCount === 1 && n === 4) {
          // exclusiveMax=10 → limit = 4294967290. 0xFFFFFFFF is rejected.
          buf.writeUInt32BE(0xFFFFFFFF, 0);
        } else if (n === 4) {
          buf.writeUInt32BE(0x00000004, 0); // 4 % 10 = 4
        }
        return buf;
      },
      // Intentionally no randomInt.
    };
    const mod = loadCryptoUtilsWith({
      nodeCrypto: fakeNodeCrypto, webCrypto: undefined,
    });
    const v = mod.secureRandomInt(10);
    assert.equal(v, 4);
    assert.ok(drawCount >= 2, "expected the rejection branch to retry, got drawCount=" + drawCount);
  });

  it("secureRandom() goes through randomBytes when randomInt is missing", function () {
    let n4Calls = 0;
    const fakeNodeCrypto = {
      randomBytes(n) {
        if (n === 4) n4Calls++;
        const buf = Buffer.alloc(n);
        for (let i = 0; i < n; i++) buf[i] = (i * 31 + 7) & 0xFF;
        return buf;
      },
    };
    const mod = loadCryptoUtilsWith({
      nodeCrypto: fakeNodeCrypto, webCrypto: undefined,
    });
    const v = mod.secureRandom();
    assert.ok(v >= 0 && v < 1);
    assert.equal(n4Calls, 1);
  });

  it("secureRandomHex() goes through randomBytes when randomInt is missing", function () {
    const fakeNodeCrypto = {
      randomBytes(n) { return Buffer.alloc(n, 0xAB); },
    };
    const mod = loadCryptoUtilsWith({
      nodeCrypto: fakeNodeCrypto, webCrypto: undefined,
    });
    const h = mod.secureRandomHex(6);
    assert.equal(h, "ababab");
  });
});

// ---------------------------------------------------------------------------
// Path 4: No crypto source at all. All three helpers must hard-fail with the
// CWE-330 message — never silently fall back to Math.random.
// ---------------------------------------------------------------------------

describe("crypto-utils: no crypto source (CWE-330 hard-fail)", function () {
  function assertCweError(fn) {
    assert.throws(fn, (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /CWE-330/);
      assert.match(err.message, /no cryptographic random source/i);
      return true;
    });
  }

  it("secureRandom() throws the canonical CWE-330 error", function () {
    const mod = loadCryptoUtilsWith({ nodeCrypto: null, webCrypto: undefined });
    assertCweError(() => mod.secureRandom());
  });

  it("secureRandomHex() throws the canonical CWE-330 error", function () {
    const mod = loadCryptoUtilsWith({ nodeCrypto: null, webCrypto: undefined });
    assertCweError(() => mod.secureRandomHex(8));
  });

  it("secureRandomInt() throws the canonical CWE-330 error", function () {
    // exclusiveMax > 1 so we get past the early-return short-circuit.
    const mod = loadCryptoUtilsWith({ nodeCrypto: null, webCrypto: undefined });
    assertCweError(() => mod.secureRandomInt(5));
  });
});

// ---------------------------------------------------------------------------
// Path 5: require('crypto') itself throws at module load (sandboxed runtimes).
// Should be indistinguishable from "Node crypto absent".
// ---------------------------------------------------------------------------

describe("crypto-utils: require('crypto') throws at module load", function () {
  it("loads cleanly and hard-fails on use (no silent Math.random)", function () {
    const mod = loadCryptoUtilsWith({ nodeCrypto: "throw", webCrypto: undefined });
    assert.throws(() => mod.secureRandom(), /CWE-330/);
    assert.throws(() => mod.secureRandomHex(4), /CWE-330/);
    assert.throws(() => mod.secureRandomInt(7), /CWE-330/);
  });
});
