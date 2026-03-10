/**
 * @jest-environment jsdom
 */

"use strict";

var { createCaptchaRateLimiter } = require("../src/captcha-rate-limiter");

describe("CaptchaRateLimiter", function () {

  // ── Construction ──────────────────────────────────────────────

  describe("construction", function () {
    test("creates with default options (sliding-window)", function () {
      var limiter = createCaptchaRateLimiter();
      var stats = limiter.getStats();
      expect(stats.algorithm).toBe("sliding-window");
      expect(stats.trackedKeys).toBe(0);
    });

    test("creates with token-bucket algorithm", function () {
      var limiter = createCaptchaRateLimiter({ algorithm: "token-bucket" });
      expect(limiter.getStats().algorithm).toBe("token-bucket");
    });

    test("creates with leaky-bucket algorithm", function () {
      var limiter = createCaptchaRateLimiter({ algorithm: "leaky-bucket" });
      expect(limiter.getStats().algorithm).toBe("leaky-bucket");
    });

    test("throws on unknown algorithm", function () {
      expect(function () {
        createCaptchaRateLimiter({ algorithm: "invalid" });
      }).toThrow("Unknown algorithm");
    });
  });

  // ── Sliding Window ────────────────────────────────────────────

  describe("sliding-window", function () {
    var limiter;

    beforeEach(function () {
      limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 3
      });
    });

    test("allows requests under limit", function () {
      var result = limiter.check("ip1", 1000);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2);
      expect(result.current).toBe(1);
    });

    test("rejects when limit reached", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1001);
      limiter.check("ip1", 1002);
      var result = limiter.check("ip1", 1003);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    test("allows again after window expires", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1001);
      limiter.check("ip1", 1002);

      // After window expires
      var result = limiter.check("ip1", 2001);
      expect(result.allowed).toBe(true);
    });

    test("returns retryAfterMs when rejected", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1001);
      limiter.check("ip1", 1002);
      var result = limiter.check("ip1", 1003);
      expect(result.retryAfterMs).toBeGreaterThan(0);
      expect(result.retryAfterMs).toBeLessThanOrEqual(1000);
    });

    test("tracks keys independently", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1001);
      limiter.check("ip1", 1002);

      var result = limiter.check("ip2", 1003);
      expect(result.allowed).toBe(true);
    });

    test("sliding window correctly trims old entries", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1500);
      limiter.check("ip1", 1800);

      // At 2100, the first request (1000) has expired
      var result = limiter.check("ip1", 2100);
      expect(result.allowed).toBe(true);
      expect(result.current).toBe(3); // 1500, 1800, 2100
    });
  });

  // ── Token Bucket ──────────────────────────────────────────────

  describe("token-bucket", function () {
    var limiter;

    beforeEach(function () {
      limiter = createCaptchaRateLimiter({
        algorithm: "token-bucket",
        capacity: 5,
        refillRate: 2 // 2 tokens/sec
      });
    });

    test("allows initial burst up to capacity", function () {
      for (var i = 0; i < 5; i++) {
        var result = limiter.check("ip1", 1000);
        expect(result.allowed).toBe(true);
      }
    });

    test("rejects when bucket empty", function () {
      for (var i = 0; i < 5; i++) {
        limiter.check("ip1", 1000);
      }
      var result = limiter.check("ip1", 1000);
      expect(result.allowed).toBe(false);
    });

    test("refills over time", function () {
      // Drain bucket
      for (var i = 0; i < 5; i++) {
        limiter.check("ip1", 1000);
      }
      // Wait 1 second = 2 tokens
      var result = limiter.check("ip1", 2000);
      expect(result.allowed).toBe(true);
    });

    test("does not exceed capacity after long wait", function () {
      limiter.check("ip1", 1000);
      // Wait a long time
      var result = limiter.check("ip1", 100000);
      expect(result.tokens).toBeLessThanOrEqual(5);
    });

    test("returns retryAfterMs when empty", function () {
      for (var i = 0; i < 5; i++) {
        limiter.check("ip1", 1000);
      }
      var result = limiter.check("ip1", 1000);
      expect(result.retryAfterMs).toBeGreaterThan(0);
    });
  });

  // ── Leaky Bucket ──────────────────────────────────────────────

  describe("leaky-bucket", function () {
    var limiter;

    beforeEach(function () {
      limiter = createCaptchaRateLimiter({
        algorithm: "leaky-bucket",
        queueSize: 3,
        leakRate: 1 // 1 per sec
      });
    });

    test("allows when queue not full", function () {
      var result = limiter.check("ip1", 1000);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2);
    });

    test("rejects when queue full", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1000);
      var result = limiter.check("ip1", 1000);
      expect(result.allowed).toBe(false);
    });

    test("leaks over time allowing more requests", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1000);

      // After 2 seconds, 2 requests leak out
      var result = limiter.check("ip1", 3000);
      expect(result.allowed).toBe(true);
    });

    test("returns retryAfterMs when full", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1000);
      var result = limiter.check("ip1", 1000);
      expect(result.retryAfterMs).toBeGreaterThan(0);
    });
  });

  // ── Banning ───────────────────────────────────────────────────

  describe("banning", function () {
    var limiter;

    beforeEach(function () {
      limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 2,
        enableBans: true,
        banThreshold: 2,
        banDurationMs: 5000
      });
    });

    test("auto-bans after banThreshold consecutive rejections", function () {
      // Use up limit
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1001);
      // Two rejections
      limiter.check("ip1", 1002); // rejection 1
      var result = limiter.check("ip1", 1003); // rejection 2 → ban
      expect(result.allowed).toBe(false);
      expect(result.banned).toBe(true);
    });

    test("banned key stays rejected until ban expires", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1001);
      limiter.check("ip1", 1002);
      limiter.check("ip1", 1003); // triggers ban

      // Still banned at 5000
      var result = limiter.check("ip1", 5000);
      expect(result.allowed).toBe(false);
      expect(result.banned).toBe(true);

      // Allowed after ban expires (>= 1003 + 5000)
      result = limiter.check("ip1", 7000);
      expect(result.allowed).toBe(true);
    });

    test("manual ban works", function () {
      limiter.ban("ip1", 10000, 1000);
      expect(limiter.isBanned("ip1", 1000)).toBe(true);

      var result = limiter.check("ip1", 5000);
      expect(result.allowed).toBe(false);
      expect(result.banned).toBe(true);
    });

    test("manual unban works", function () {
      limiter.ban("ip1", 10000, 1000);
      expect(limiter.unban("ip1")).toBe(true);
      expect(limiter.isBanned("ip1")).toBe(false);
    });

    test("unban returns false for non-banned key", function () {
      expect(limiter.unban("ip1")).toBe(false);
    });

    test("successful request resets strikes", function () {
      limiter.check("ip1", 1000);
      limiter.check("ip1", 1001);
      limiter.check("ip1", 1002); // rejection 1

      // Window expires — allowed again
      limiter.check("ip1", 2500); // allowed → strikes reset

      // Need another round of rejections
      limiter.check("ip1", 2501);
      var result = limiter.check("ip1", 2502); // rejection 1 again
      expect(result.banned).toBeUndefined();
    });
  });

  // ── Peek ──────────────────────────────────────────────────────

  describe("peek", function () {
    test("peek without any requests shows full capacity (sliding)", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        maxRequests: 5
      });
      var result = limiter.peek("ip1");
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(5);
    });

    test("peek does not consume requests", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 2
      });
      limiter.check("ip1", 1000);
      limiter.peek("ip1", 1001);
      var result = limiter.check("ip1", 1002);
      expect(result.allowed).toBe(true); // still have 1 left
    });

    test("peek token-bucket shows available tokens", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "token-bucket",
        capacity: 10
      });
      var result = limiter.peek("ip1");
      expect(result.tokens).toBe(10);
    });

    test("peek leaky-bucket shows queue level", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "leaky-bucket",
        queueSize: 5
      });
      var result = limiter.peek("ip1");
      expect(result.queueLevel).toBe(0);
    });

    test("peek throws on invalid key", function () {
      var limiter = createCaptchaRateLimiter();
      expect(function () { limiter.peek(""); }).toThrow();
      expect(function () { limiter.peek(null); }).toThrow();
    });
  });

  // ── Consume ───────────────────────────────────────────────────

  describe("consume", function () {
    test("consumes multiple requests atomically", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 5
      });
      var result = limiter.consume("ip1", 3, 1000);
      expect(result.allowed).toBe(true);
      expect(result.consumed).toBe(3);
      expect(result.remaining).toBe(2);
    });

    test("partial consume when not enough capacity", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 3
      });
      limiter.check("ip1", 1000);
      var result = limiter.consume("ip1", 5, 1001);
      expect(result.allowed).toBe(false);
      expect(result.consumed).toBe(2);
      expect(result.requested).toBe(5);
    });

    test("throws on invalid count", function () {
      var limiter = createCaptchaRateLimiter();
      expect(function () { limiter.consume("ip1", 0); }).toThrow();
      expect(function () { limiter.consume("ip1", -1); }).toThrow();
      expect(function () { limiter.consume("ip1", Infinity); }).toThrow();
    });
  });

  // ── Whitelist ─────────────────────────────────────────────────

  describe("whitelist", function () {
    var limiter;

    beforeEach(function () {
      limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 1
      });
    });

    test("whitelisted key is always allowed", function () {
      limiter.whitelistAdd("trusted");
      // Even past limit
      for (var i = 0; i < 100; i++) {
        var result = limiter.check("trusted", 1000);
        expect(result.allowed).toBe(true);
        expect(result.whitelisted).toBe(true);
      }
    });

    test("isWhitelisted returns correct status", function () {
      expect(limiter.isWhitelisted("ip1")).toBe(false);
      limiter.whitelistAdd("ip1");
      expect(limiter.isWhitelisted("ip1")).toBe(true);
    });

    test("whitelistRemove removes key", function () {
      limiter.whitelistAdd("ip1");
      expect(limiter.whitelistRemove("ip1")).toBe(true);
      expect(limiter.isWhitelisted("ip1")).toBe(false);
    });

    test("whitelistRemove returns false for non-whitelisted", function () {
      expect(limiter.whitelistRemove("ip1")).toBe(false);
    });

    test("throws on invalid key", function () {
      expect(function () { limiter.whitelistAdd(""); }).toThrow();
      expect(function () { limiter.whitelistAdd(null); }).toThrow();
    });
  });

  // ── Reset ─────────────────────────────────────────────────────

  describe("reset", function () {
    test("reset clears state for key", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 1
      });
      limiter.check("ip1", 1000);
      limiter.reset("ip1");

      var result = limiter.check("ip1", 1001);
      expect(result.allowed).toBe(true);
    });

    test("reset returns false for unknown key", function () {
      var limiter = createCaptchaRateLimiter();
      expect(limiter.reset("nope")).toBe(false);
    });

    test("resetAll clears everything", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 1
      });
      limiter.check("ip1", 1000);
      limiter.check("ip2", 1000);
      limiter.resetAll();

      var stats = limiter.getStats();
      expect(stats.trackedKeys).toBe(0);
      expect(stats.totalChecks).toBe(0);
    });
  });

  // ── Stats ─────────────────────────────────────────────────────

  describe("getStats", function () {
    test("tracks allowed and rejected counts", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 2
      });
      limiter.check("ip1", 1000); // allowed
      limiter.check("ip1", 1001); // allowed
      limiter.check("ip1", 1002); // rejected

      var stats = limiter.getStats();
      expect(stats.totalAllowed).toBe(2);
      expect(stats.totalRejected).toBe(1);
      expect(stats.totalChecks).toBe(3);
      expect(stats.rejectionRate).toBeCloseTo(0.333, 2);
    });

    test("returns config info", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "token-bucket",
        capacity: 42,
        refillRate: 7
      });
      var stats = limiter.getStats();
      expect(stats.config.capacity).toBe(42);
      expect(stats.config.refillRate).toBe(7);
    });
  });

  // ── getTopKeys ────────────────────────────────────────────────

  describe("getTopKeys", function () {
    test("returns tracked keys sorted by recency", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 10000,
        maxRequests: 100
      });
      limiter.check("old", 1000);
      limiter.check("new", 2000);

      var top = limiter.getTopKeys(10, "recent");
      expect(top.length).toBe(2);
      expect(top[0].key).toBe("new");
    });

    test("limits output count", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 10000,
        maxRequests: 100
      });
      for (var i = 0; i < 10; i++) {
        limiter.check("ip" + i, 1000 + i);
      }
      var top = limiter.getTopKeys(3);
      expect(top.length).toBe(3);
    });
  });

  // ── Serialization ─────────────────────────────────────────────

  describe("export/import", function () {
    test("roundtrip preserves state", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 10000,
        maxRequests: 5
      });
      limiter.check("ip1", 1000);
      limiter.check("ip1", 2000);

      var exported = limiter.exportState();
      expect(exported.algorithm).toBe("sliding-window");

      var limiter2 = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 10000,
        maxRequests: 5
      });
      var count = limiter2.importState(exported);
      expect(count).toBe(1); // 1 key

      // Should have 2 requests already counted
      var peek = limiter2.peek("ip1", 3000);
      expect(peek.current).toBe(2);
    });

    test("import rejects mismatched algorithm", function () {
      var limiter = createCaptchaRateLimiter({ algorithm: "token-bucket" });
      expect(function () {
        limiter.importState({ algorithm: "sliding-window", store: {} });
      }).toThrow("Algorithm mismatch");
    });

    test("import throws on invalid state", function () {
      var limiter = createCaptchaRateLimiter();
      expect(function () { limiter.importState(null); }).toThrow();
    });
  });

  // ── Input Validation ──────────────────────────────────────────

  describe("input validation", function () {
    test("check throws on empty key", function () {
      var limiter = createCaptchaRateLimiter();
      expect(function () { limiter.check(""); }).toThrow();
    });

    test("check throws on null key", function () {
      var limiter = createCaptchaRateLimiter();
      expect(function () { limiter.check(null); }).toThrow();
    });

    test("ban throws on invalid key", function () {
      var limiter = createCaptchaRateLimiter();
      expect(function () { limiter.ban(""); }).toThrow();
    });
  });

  // ── Edge Cases ────────────────────────────────────────────────

  describe("edge cases", function () {
    test("result includes algorithm and key", function () {
      var limiter = createCaptchaRateLimiter({ algorithm: "token-bucket" });
      var result = limiter.check("mykey", 1000);
      expect(result.algorithm).toBe("token-bucket");
      expect(result.key).toBe("mykey");
    });

    test("handles high concurrency (many keys)", function () {
      var limiter = createCaptchaRateLimiter({
        algorithm: "sliding-window",
        windowMs: 1000,
        maxRequests: 5,
        maxKeys: 100,
        cleanupInterval: 50
      });
      for (var i = 0; i < 200; i++) {
        limiter.check("key" + i, 1000 + i);
      }
      var stats = limiter.getStats();
      // Should have evicted down to maxKeys
      expect(stats.trackedKeys).toBeLessThanOrEqual(101); // +1 for the last check before cleanup
      expect(stats.evictions).toBeGreaterThan(0);
    });

    test("isBanned returns false for expired ban", function () {
      var limiter = createCaptchaRateLimiter({ enableBans: true });
      limiter.ban("ip1", 1000, 1000);
      expect(limiter.isBanned("ip1", 3000)).toBe(false);
    });

    test("isBanned returns false for unknown key", function () {
      var limiter = createCaptchaRateLimiter();
      expect(limiter.isBanned("nope")).toBe(false);
    });
  });
});
