/**
 * Tests for captcha-rate-limiter.js
 *
 * Covers all three algorithms (sliding-window, token-bucket, leaky-bucket),
 * banning, whitelist, consume(), peek(), serialization, eviction, and edge cases.
 */

"use strict";

var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var { createCaptchaRateLimiter } = require("../src/captcha-rate-limiter.js");

// ── Factory / validation ────────────────────────────────────────

describe("createCaptchaRateLimiter", function () {
  it("creates a limiter with default sliding-window algorithm", function () {
    var limiter = createCaptchaRateLimiter();
    var stats = limiter.getStats();
    assert.equal(stats.algorithm, "sliding-window");
  });

  it("throws on unknown algorithm", function () {
    assert.throws(function () {
      createCaptchaRateLimiter({ algorithm: "bogus" });
    }, /Unknown algorithm/);
  });

  it("throws on empty key", function () {
    var limiter = createCaptchaRateLimiter();
    assert.throws(function () { limiter.check(""); }, /non-empty string/);
    assert.throws(function () { limiter.check(null); }, /non-empty string/);
  });
});

// ── Sliding window ──────────────────────────────────────────────

describe("sliding-window", function () {
  it("allows requests up to maxRequests then rejects", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 3,
      windowMs: 10000,
    });
    var t = 1000000;
    assert.equal(limiter.check("ip1", t).allowed, true);
    assert.equal(limiter.check("ip1", t + 1).allowed, true);
    assert.equal(limiter.check("ip1", t + 2).allowed, true);
    var r = limiter.check("ip1", t + 3);
    assert.equal(r.allowed, false);
    assert.equal(r.remaining, 0);
    assert.ok(r.retryAfterMs > 0);
  });

  it("allows again after window expires", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 2,
      windowMs: 1000,
    });
    var t = 1000000;
    limiter.check("k", t);
    limiter.check("k", t + 1);
    assert.equal(limiter.check("k", t + 2).allowed, false);
    // After window passes
    assert.equal(limiter.check("k", t + 1500).allowed, true);
  });

  it("tracks independent keys separately", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 1,
      windowMs: 10000,
    });
    var t = 1000000;
    assert.equal(limiter.check("a", t).allowed, true);
    assert.equal(limiter.check("a", t + 1).allowed, false);
    assert.equal(limiter.check("b", t + 2).allowed, true);
  });

  it("reports correct remaining count", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 5,
      windowMs: 10000,
    });
    var t = 1000000;
    var r1 = limiter.check("x", t);
    assert.equal(r1.remaining, 4);
    limiter.check("x", t + 1);
    limiter.check("x", t + 2);
    var r4 = limiter.check("x", t + 3);
    assert.equal(r4.remaining, 1);
  });
});

// ── Token bucket ────────────────────────────────────────────────

describe("token-bucket", function () {
  it("allows burst up to capacity then rejects", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 3,
      refillRate: 1,
    });
    var t = 1000000;
    assert.equal(limiter.check("k", t).allowed, true);
    assert.equal(limiter.check("k", t).allowed, true);
    assert.equal(limiter.check("k", t).allowed, true);
    var r = limiter.check("k", t);
    assert.equal(r.allowed, false);
    assert.ok(r.retryAfterMs > 0);
  });

  it("refills tokens over time", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 2,
      refillRate: 2, // 2 tokens/sec
    });
    var t = 1000000;
    limiter.check("k", t);
    limiter.check("k", t);
    assert.equal(limiter.check("k", t).allowed, false);
    // 1 second later: 2 tokens refilled
    assert.equal(limiter.check("k", t + 1000).allowed, true);
  });

  it("caps tokens at capacity", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 5,
      refillRate: 100, // very fast refill
    });
    var t = 1000000;
    limiter.check("k", t);
    // After long wait, tokens should cap at capacity (5)
    var r = limiter.peek("k", t + 100000);
    assert.equal(r.tokens, 5);
  });
});

// ── Leaky bucket ────────────────────────────────────────────────

describe("leaky-bucket", function () {
  it("allows requests until queue is full", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "leaky-bucket",
      queueSize: 3,
      leakRate: 1,
    });
    var t = 1000000;
    assert.equal(limiter.check("k", t).allowed, true);
    assert.equal(limiter.check("k", t).allowed, true);
    assert.equal(limiter.check("k", t).allowed, true);
    assert.equal(limiter.check("k", t).allowed, false);
  });

  it("leaks water over time to allow more requests", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "leaky-bucket",
      queueSize: 2,
      leakRate: 2, // 2/sec
    });
    var t = 1000000;
    limiter.check("k", t);
    limiter.check("k", t);
    assert.equal(limiter.check("k", t).allowed, false);
    // 1 second later: leaked 2 units
    assert.equal(limiter.check("k", t + 1000).allowed, true);
  });

  it("reports queue level in result", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "leaky-bucket",
      queueSize: 10,
      leakRate: 1,
    });
    var t = 1000000;
    var r = limiter.check("k", t);
    assert.equal(r.queueLevel, 1);
    assert.equal(r.queueSize, 10);
  });
});

// ── Banning ─────────────────────────────────────────────────────

describe("banning", function () {
  it("auto-bans after consecutive rejections with enableBans", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 1,
      windowMs: 60000,
      enableBans: true,
      banThreshold: 2,
      banDurationMs: 5000,
    });
    var t = 1000000;
    limiter.check("k", t); // allowed
    limiter.check("k", t + 1); // rejected (strike 1)
    var r = limiter.check("k", t + 2); // rejected (strike 2 -> ban)
    assert.equal(r.banned, true);
    assert.ok(r.banExpiresAt);
  });

  it("manual ban and unban work", function () {
    var limiter = createCaptchaRateLimiter({ enableBans: true });
    limiter.ban("bad-ip", 10000, 1000000);
    assert.equal(limiter.isBanned("bad-ip", 1000000), true);
    assert.equal(limiter.isBanned("bad-ip", 1020000), false); // expired

    limiter.ban("bad-ip2", 100000, 1000000);
    assert.equal(limiter.unban("bad-ip2"), true);
    assert.equal(limiter.isBanned("bad-ip2", 1000000), false);
  });

  it("ban expires after duration", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 1,
      windowMs: 60000,
      enableBans: true,
      banThreshold: 1,
      banDurationMs: 5000,
    });
    var t = 1000000;
    limiter.check("k", t); // allowed
    limiter.check("k", t + 1); // rejected + banned
    var r1 = limiter.check("k", t + 2);
    assert.equal(r1.allowed, false);
    assert.equal(r1.banned, true);
    // After ban expires (and window expires)
    var r2 = limiter.check("k", t + 70000);
    assert.equal(r2.allowed, true);
  });
});

// ── Whitelist ───────────────────────────────────────────────────

describe("whitelist", function () {
  it("whitelisted keys are always allowed", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 1,
      windowMs: 60000,
    });
    limiter.whitelistAdd("vip");
    var t = 1000000;
    // Should always be allowed regardless of limit
    for (var i = 0; i < 20; i++) {
      var r = limiter.check("vip", t + i);
      assert.equal(r.allowed, true);
      assert.equal(r.whitelisted, true);
    }
  });

  it("isWhitelisted and whitelistRemove work", function () {
    var limiter = createCaptchaRateLimiter();
    assert.equal(limiter.isWhitelisted("a"), false);
    limiter.whitelistAdd("a");
    assert.equal(limiter.isWhitelisted("a"), true);
    assert.equal(limiter.whitelistRemove("a"), true);
    assert.equal(limiter.isWhitelisted("a"), false);
    assert.equal(limiter.whitelistRemove("a"), false);
  });
});

// ── consume() ───────────────────────────────────────────────────

describe("consume", function () {
  it("consumes multiple tokens at once (token-bucket)", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 10,
      refillRate: 1,
    });
    var t = 1000000;
    var r = limiter.consume("k", 5, t);
    assert.equal(r.allowed, true);
    assert.equal(r.consumed, 5);
    assert.equal(r.tokens, 5);
    // Consume remaining 5
    var r2 = limiter.consume("k", 5, t);
    assert.equal(r2.allowed, true);
    assert.equal(r2.consumed, 5);
    // Should reject now
    var r3 = limiter.consume("k", 1, t);
    assert.equal(r3.allowed, false);
  });

  it("consumes batch in leaky-bucket", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "leaky-bucket",
      queueSize: 10,
      leakRate: 1,
    });
    var t = 1000000;
    var r = limiter.consume("k", 8, t);
    assert.equal(r.allowed, true);
    assert.equal(r.consumed, 8);
    // Can't fit 5 more (8+5 > 10)
    var r2 = limiter.consume("k", 5, t);
    assert.equal(r2.allowed, false);
  });

  it("consumes batch in sliding-window", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 5,
      windowMs: 10000,
    });
    var t = 1000000;
    var r = limiter.consume("k", 3, t);
    assert.equal(r.allowed, true);
    assert.equal(r.consumed, 3);
  });

  it("throws on invalid count", function () {
    var limiter = createCaptchaRateLimiter();
    assert.throws(function () { limiter.consume("k", 0); }, /positive finite/);
    assert.throws(function () { limiter.consume("k", -1); }, /positive finite/);
    assert.throws(function () { limiter.consume("k", Infinity); }, /positive finite/);
  });

  it("respects whitelist in consume", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 1,
      refillRate: 1,
    });
    limiter.whitelistAdd("vip");
    var r = limiter.consume("vip", 100, 1000000);
    assert.equal(r.allowed, true);
    assert.equal(r.whitelisted, true);
  });
});

// ── peek() ──────────────────────────────────────────────────────

describe("peek", function () {
  it("does not consume a request (sliding-window)", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 2,
      windowMs: 10000,
    });
    var t = 1000000;
    limiter.check("k", t);
    var p = limiter.peek("k", t + 1);
    assert.equal(p.remaining, 1);
    // Still 1 remaining because peek didn't consume
    var p2 = limiter.peek("k", t + 2);
    assert.equal(p2.remaining, 1);
  });

  it("works for token-bucket", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 10,
      refillRate: 1,
    });
    var t = 1000000;
    limiter.check("k", t); // consume 1
    var p = limiter.peek("k", t);
    assert.equal(p.tokens, 9);
    assert.equal(p.allowed, true);
  });

  it("works for leaky-bucket", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "leaky-bucket",
      queueSize: 5,
      leakRate: 1,
    });
    var t = 1000000;
    limiter.check("k", t);
    var p = limiter.peek("k", t);
    assert.equal(p.queueLevel, 1);
    assert.equal(p.allowed, true);
  });

  it("returns full capacity for unknown key", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 20,
    });
    var p = limiter.peek("unknown", 1000000);
    assert.equal(p.allowed, true);
    assert.equal(p.tokens, 20);
  });
});

// ── reset / resetAll ────────────────────────────────────────────

describe("reset", function () {
  it("resets a specific key", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 1,
      windowMs: 60000,
    });
    var t = 1000000;
    limiter.check("k", t);
    assert.equal(limiter.check("k", t + 1).allowed, false);
    assert.equal(limiter.reset("k"), true);
    assert.equal(limiter.check("k", t + 2).allowed, true);
  });

  it("reset returns false for non-existent key", function () {
    var limiter = createCaptchaRateLimiter();
    assert.equal(limiter.reset("nope"), false);
  });

  it("resetAll clears everything", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 1,
      windowMs: 60000,
    });
    var t = 1000000;
    limiter.check("a", t);
    limiter.check("b", t);
    limiter.resetAll();
    var stats = limiter.getStats();
    assert.equal(stats.trackedKeys, 0);
    assert.equal(stats.totalChecks, 0);
    assert.equal(limiter.check("a", t + 1).allowed, true);
  });
});

// ── getStats / getTopKeys ───────────────────────────────────────

describe("getStats", function () {
  it("tracks allowed and rejected counts", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 2,
      windowMs: 60000,
    });
    var t = 1000000;
    limiter.check("k", t);
    limiter.check("k", t + 1);
    limiter.check("k", t + 2); // rejected
    var stats = limiter.getStats();
    assert.equal(stats.totalAllowed, 2);
    assert.equal(stats.totalRejected, 1);
    assert.ok(stats.rejectionRate > 0.3);
  });
});

describe("getTopKeys", function () {
  it("returns tracked keys sorted by recency", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "sliding-window",
      maxRequests: 100,
      windowMs: 60000,
    });
    limiter.check("old", 1000);
    limiter.check("new", 2000);
    var top = limiter.getTopKeys(10, "recent");
    assert.equal(top[0].key, "new");
    assert.equal(top[1].key, "old");
  });
});

// ── Serialization ───────────────────────────────────────────────

describe("exportState / importState", function () {
  it("round-trips state correctly", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 10,
      refillRate: 1,
    });
    var t = 1000000;
    limiter.check("k1", t);
    limiter.check("k2", t);
    var exported = limiter.exportState();

    var limiter2 = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 10,
      refillRate: 1,
    });
    var restored = limiter2.importState(exported);
    assert.equal(restored, 2);
    var p = limiter2.peek("k1", t);
    assert.equal(p.tokens, 9);
  });

  it("rejects algorithm mismatch on import", function () {
    var limiter = createCaptchaRateLimiter({ algorithm: "token-bucket" });
    assert.throws(function () {
      limiter.importState({ algorithm: "leaky-bucket", store: {} });
    }, /Algorithm mismatch/);
  });

  it("rejects invalid state input", function () {
    var limiter = createCaptchaRateLimiter();
    assert.throws(function () { limiter.importState(null); }, /Invalid state/);
    assert.throws(function () { limiter.importState([1, 2]); }, /Invalid state/);
  });

  it("rejects prototype pollution keys", function () {
    var limiter = createCaptchaRateLimiter({
      algorithm: "token-bucket",
      capacity: 10,
    });
    var count = limiter.importState({
      algorithm: "token-bucket",
      store: {
        "__proto__": { tokens: 10, lastRefill: 0, lastSeen: 0 },
        "safe-key": { tokens: 5, lastRefill: 0, lastSeen: 0 },
      },
    });
    assert.equal(count, 1); // only safe-key imported
  });
});
