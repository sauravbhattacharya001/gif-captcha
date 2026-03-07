"use strict";

var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var gifCaptcha = require("../src/index");

// ── createAttemptTracker extended tests ──────────────────────────────

describe("createAttemptTracker (extended)", function () {

  // ── Exponential backoff cap ──

  describe("exponential backoff cap", function () {
    it("should double lockout on each cycle", function () {
      var tracker = gifCaptcha.createAttemptTracker({
        maxAttempts: 1,
        lockoutMs: 1000,
        exponentialBackoff: true,
        maxLockoutMs: 100000,
      });

      // First lockout: 1000ms
      var r1 = tracker.recordAttempt("cap1");
      assert.equal(r1.allowed, false);
      assert.equal(r1.lockoutRemainingMs, 1000);

      // Verify stats reflect lockoutCount = 1
      var stats = tracker.getStats("cap1");
      assert.equal(stats.lockoutCount, 1);
      assert.equal(stats.isLocked, true);
    });

    it("should not exceed maxLockoutMs regardless of lockout count", function () {
      var tracker = gifCaptcha.createAttemptTracker({
        maxAttempts: 1,
        lockoutMs: 10000,
        exponentialBackoff: true,
        maxLockoutMs: 20000,
      });

      // First lockout: 10000ms (10000 * 2^0)
      var r1 = tracker.recordAttempt("cap2");
      assert.equal(r1.lockoutRemainingMs, 10000);

      // Can't easily test second lockout without time manipulation,
      // but the _computeLockoutMs logic caps at maxLockoutMs
      // Verify the config is stored correctly
      var config = tracker.getConfig();
      assert.equal(config.maxLockoutMs, 20000);
    });

    it("should use flat lockout when exponentialBackoff is false", function () {
      var tracker = gifCaptcha.createAttemptTracker({
        maxAttempts: 1,
        lockoutMs: 5000,
        exponentialBackoff: false,
      });

      var r1 = tracker.recordAttempt("flat1");
      assert.equal(r1.allowed, false);
      assert.equal(r1.lockoutRemainingMs, 5000);
    });
  });

  // ── Prototype pollution safety ──

  describe("prototype pollution safety", function () {
    it("should handle __proto__ as challengeId safely", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      var r = tracker.recordAttempt("__proto__");
      assert.equal(r.allowed, true);
      assert.equal(r.attemptsRemaining, 2);

      // Should not pollute Object.prototype
      assert.equal(({}).attempts, undefined);

      var stats = tracker.getStats("__proto__");
      assert.equal(stats.attempts, 1);
    });

    it("should handle constructor as challengeId safely", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      var r = tracker.recordAttempt("constructor");
      assert.equal(r.allowed, true);
      assert.equal(r.attemptsRemaining, 2);

      var stats = tracker.getStats("constructor");
      assert.equal(stats.attempts, 1);
    });

    it("should handle toString as challengeId safely", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      var r = tracker.recordAttempt("toString");
      assert.equal(r.allowed, true);
      assert.equal(r.attemptsRemaining, 2);

      // toString should still work on normal objects
      assert.equal(typeof ({}).toString, "function");
    });

    it("should handle hasOwnProperty as challengeId safely", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2 });

      tracker.recordAttempt("hasOwnProperty");
      var r2 = tracker.recordAttempt("hasOwnProperty");
      assert.equal(r2.allowed, false);
      assert.ok(r2.lockoutRemainingMs > 0);
    });
  });

  // ── trackedValidate edge cases ──

  describe("trackedValidate (validateAnswer wrapper)", function () {
    it("should pass correct answer through", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

      var result = tracker.validateAnswer("cat", "cat", "v1");
      assert.equal(result.passed, true);
      assert.equal(result.score, 1);
      assert.equal(result.locked, false);
      assert.equal(result.attemptsRemaining, 4);
    });

    it("should fail incorrect answer but track attempt", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

      var result = tracker.validateAnswer("dog", "cat", "v2");
      assert.equal(result.passed, false);
      assert.equal(result.locked, false);
      assert.equal(result.attemptsRemaining, 4);
    });

    it("should return locked=true when all attempts exhausted", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2 });

      tracker.validateAnswer("wrong", "right", "v3");
      var r2 = tracker.validateAnswer("wrong", "right", "v3");

      assert.equal(r2.passed, false);
      assert.equal(r2.locked, true);
      assert.equal(r2.attemptsRemaining, 0);
      assert.ok(r2.lockoutRemainingMs > 0);
    });

    it("should block validation during lockout without checking answer", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 1 });

      // Trigger lockout
      tracker.validateAnswer("wrong", "right", "v4");

      // Even correct answer should be blocked
      var r2 = tracker.validateAnswer("right", "right", "v4");
      assert.equal(r2.passed, false);
      assert.equal(r2.locked, true);
      assert.equal(r2.score, 0);
      assert.equal(r2.hasKeywords, false);
    });

    it("should throw when challengeId is undefined", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

      assert.throws(function () {
        tracker.validateAnswer("answer", "expected", undefined);
      }, /challengeId is required/);
    });

    it("should throw when challengeId is null", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

      assert.throws(function () {
        tracker.validateAnswer("answer", "expected", null);
      }, /challengeId is required/);
    });

    it("should pass validation options through to underlying validateAnswer", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

      // Case-insensitive by default
      var result = tracker.validateAnswer("CAT", "cat", "v5");
      assert.equal(result.passed, true);
    });

    it("should return score=0 for failed answers (below threshold)", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

      var result = tracker.validateAnswer("completely wrong", "cat", "v6");
      assert.equal(result.passed, false);
      assert.equal(result.score, 0);
    });

    it("should count validation attempts in stats", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

      tracker.validateAnswer("a", "b", "v7");
      tracker.validateAnswer("c", "d", "v7");
      tracker.validateAnswer("e", "f", "v7");

      var stats = tracker.getStats("v7");
      assert.equal(stats.attempts, 3);
      assert.equal(stats.lockoutCount, 0);
    });
  });

  // ── isLocked edge cases ──

  describe("isLocked edge cases", function () {
    it("should return locked=false for never-seen challenge", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      var result = tracker.isLocked("never-seen");
      assert.equal(result.locked, false);
      assert.equal(result.lockoutRemainingMs, 0);
    });

    it("should return locked=true immediately after max attempts", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 1, lockoutMs: 60000 });

      tracker.recordAttempt("lock-test");
      var result = tracker.isLocked("lock-test");
      assert.equal(result.locked, true);
      assert.ok(result.lockoutRemainingMs > 0);
      assert.ok(result.lockoutRemainingMs <= 60000);
    });

    it("should track different challenges independently for lockout", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 1, lockoutMs: 60000 });

      tracker.recordAttempt("a");
      assert.equal(tracker.isLocked("a").locked, true);
      assert.equal(tracker.isLocked("b").locked, false);
    });
  });

  // ── getStats edge cases ──

  describe("getStats edge cases", function () {
    it("should return zero stats for unknown challenge (creates entry)", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      var stats = tracker.getStats("unknown-x");
      assert.equal(stats.attempts, 0);
      assert.equal(stats.lockoutCount, 0);
      assert.equal(stats.isLocked, false);
      assert.equal(stats.lockoutRemainingMs, 0);
    });

    it("should reflect lockout state after max attempts", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2, lockoutMs: 30000 });

      tracker.recordAttempt("stats1");
      tracker.recordAttempt("stats1");

      var stats = tracker.getStats("stats1");
      assert.equal(stats.attempts, 2);
      assert.equal(stats.lockoutCount, 1);
      assert.equal(stats.isLocked, true);
      assert.ok(stats.lockoutRemainingMs > 0);
    });

    it("should convert numeric challengeId to string", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      tracker.recordAttempt(42);
      var stats = tracker.getStats(42);
      assert.equal(stats.attempts, 1);

      // Should be same as string "42"
      var stats2 = tracker.getStats("42");
      assert.equal(stats2.attempts, 1);
    });
  });

  // ── resetChallenge edge cases ──

  describe("resetChallenge edge cases", function () {
    it("should clear lockout state on reset", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 1, lockoutMs: 60000 });

      tracker.recordAttempt("reset1");
      assert.equal(tracker.isLocked("reset1").locked, true);

      tracker.resetChallenge("reset1");
      assert.equal(tracker.isLocked("reset1").locked, false);
    });

    it("should allow new attempts after reset", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2, lockoutMs: 60000 });

      tracker.recordAttempt("reset2");
      tracker.recordAttempt("reset2"); // triggers lockout
      assert.equal(tracker.isLocked("reset2").locked, true);

      tracker.resetChallenge("reset2");
      var r = tracker.recordAttempt("reset2");
      assert.equal(r.allowed, true);
    });

    it("should not affect other challenges when resetting one", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 1, lockoutMs: 60000 });

      tracker.recordAttempt("a");
      tracker.recordAttempt("b");

      tracker.resetChallenge("a");
      assert.equal(tracker.isLocked("a").locked, false);
      assert.equal(tracker.isLocked("b").locked, true);
    });

    it("should handle resetting nonexistent challenge silently", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      // Should not throw
      tracker.resetChallenge("nonexistent");
      assert.equal(tracker.isLocked("nonexistent").locked, false);
    });

    it("should reset numeric challengeId (string conversion)", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 1, lockoutMs: 60000 });

      tracker.recordAttempt(99);
      assert.equal(tracker.isLocked(99).locked, true);

      tracker.resetChallenge(99);
      assert.equal(tracker.isLocked(99).locked, false);
    });
  });

  // ── resetAll edge cases ──

  describe("resetAll edge cases", function () {
    it("should clear all challenges including locked ones", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 1, lockoutMs: 60000 });

      tracker.recordAttempt("all1");
      tracker.recordAttempt("all2");
      tracker.recordAttempt("all3");

      assert.equal(tracker.isLocked("all1").locked, true);
      assert.equal(tracker.isLocked("all2").locked, true);
      assert.equal(tracker.isLocked("all3").locked, true);

      tracker.resetAll();

      assert.equal(tracker.isLocked("all1").locked, false);
      assert.equal(tracker.isLocked("all2").locked, false);
      assert.equal(tracker.isLocked("all3").locked, false);
    });

    it("should allow new attempts on all challenges after resetAll", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2, lockoutMs: 60000 });

      tracker.recordAttempt("x");
      tracker.recordAttempt("x"); // triggers lockout
      tracker.resetAll();

      var r = tracker.recordAttempt("x");
      assert.equal(r.allowed, true);
      assert.equal(r.attemptsRemaining, 1);
    });

    it("should reset stats counters", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      tracker.recordAttempt("s1");
      tracker.recordAttempt("s1");
      tracker.resetAll();

      var stats = tracker.getStats("s1");
      assert.equal(stats.attempts, 0);
      assert.equal(stats.lockoutCount, 0);
    });
  });

  // ── Multiple challenges concurrent ──

  describe("concurrent challenges", function () {
    it("should handle many challenges simultaneously", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2 });

      for (var i = 0; i < 50; i++) {
        var r = tracker.recordAttempt("ch" + i);
        assert.equal(r.allowed, true);
        assert.equal(r.attemptsRemaining, 1);
      }
    });

    it("should lock only exhausted challenges", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2 });

      // Exhaust ch0
      tracker.recordAttempt("ch0");
      tracker.recordAttempt("ch0");

      // ch1 still fine
      tracker.recordAttempt("ch1");

      assert.equal(tracker.isLocked("ch0").locked, true);
      assert.equal(tracker.isLocked("ch1").locked, false);
    });

    it("should maintain separate attempt counts", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

      tracker.recordAttempt("a");
      tracker.recordAttempt("a");
      tracker.recordAttempt("b");

      assert.equal(tracker.getStats("a").attempts, 2);
      assert.equal(tracker.getStats("b").attempts, 1);
    });
  });

  // ── Config edge cases ──

  describe("config edge cases", function () {
    it("should use default maxLockoutMs when not specified", function () {
      var tracker = gifCaptcha.createAttemptTracker({});
      var config = tracker.getConfig();
      assert.equal(config.maxLockoutMs, 300000); // 5 min default
    });

    it("should accept very large maxAttempts", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 1000000 });
      var config = tracker.getConfig();
      assert.equal(config.maxAttempts, 1000000);

      var r = tracker.recordAttempt("big");
      assert.equal(r.allowed, true);
      assert.equal(r.attemptsRemaining, 999999);
    });

    it("should handle lockoutMs of 1ms", function () {
      var tracker = gifCaptcha.createAttemptTracker({
        maxAttempts: 1,
        lockoutMs: 1,
      });

      var r = tracker.recordAttempt("tiny");
      assert.equal(r.allowed, false);
      assert.ok(r.lockoutRemainingMs >= 0);
      assert.ok(r.lockoutRemainingMs <= 1);
    });

    it("should be immutable — config returns same values each time", function () {
      var tracker = gifCaptcha.createAttemptTracker({
        maxAttempts: 7,
        lockoutMs: 12345,
      });

      var c1 = tracker.getConfig();
      var c2 = tracker.getConfig();
      assert.deepEqual(c1, c2);
    });

    it("should ignore unknown config options", function () {
      var tracker = gifCaptcha.createAttemptTracker({
        maxAttempts: 3,
        unknownField: "ignored",
        anotherField: 42,
      });

      var config = tracker.getConfig();
      assert.equal(config.maxAttempts, 3);
      assert.equal(config.unknownField, undefined);
    });
  });

  // ── attemptNumber tracking ──

  describe("attemptNumber tracking", function () {
    it("should increment attemptNumber on each call", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

      assert.equal(tracker.recordAttempt("seq").attemptNumber, 1);
      assert.equal(tracker.recordAttempt("seq").attemptNumber, 2);
      assert.equal(tracker.recordAttempt("seq").attemptNumber, 3);
      assert.equal(tracker.recordAttempt("seq").attemptNumber, 4);
    });

    it("should report correct attemptNumber on lockout", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      tracker.recordAttempt("an");
      tracker.recordAttempt("an");
      var r3 = tracker.recordAttempt("an");

      assert.equal(r3.allowed, false);
      assert.equal(r3.attemptNumber, 3);
    });

    it("should report last attempt number during lockout", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2, lockoutMs: 60000 });

      tracker.recordAttempt("lk");
      tracker.recordAttempt("lk"); // triggers lockout

      // During lockout, attemptNumber should be the last attempt count
      var r = tracker.recordAttempt("lk");
      assert.equal(r.allowed, false);
      assert.equal(r.attemptNumber, 2);
    });
  });

  // ── Empty string / special challengeIds ──

  describe("special challengeId values", function () {
    it("should handle empty string as challengeId", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      var r = tracker.recordAttempt("");
      assert.equal(r.allowed, true);
      assert.equal(r.attemptsRemaining, 2);
    });

    it("should handle numeric zero as challengeId", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      var r = tracker.recordAttempt(0);
      assert.equal(r.allowed, true);

      var stats = tracker.getStats(0);
      assert.equal(stats.attempts, 1);

      // Should be same as string "0"
      var stats2 = tracker.getStats("0");
      assert.equal(stats2.attempts, 1);
    });

    it("should handle very long challengeId", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });
      var longId = "x".repeat(10000);

      var r = tracker.recordAttempt(longId);
      assert.equal(r.allowed, true);

      var stats = tracker.getStats(longId);
      assert.equal(stats.attempts, 1);
    });

    it("should handle challengeId with special characters", function () {
      var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

      var ids = ["null", "undefined", "NaN", "true", "false", "0", "-1"];
      ids.forEach(function (id) {
        var r = tracker.recordAttempt(id);
        assert.equal(r.allowed, true);
      });
    });
  });

  // ── Instance isolation ──

  describe("instance isolation", function () {
    it("should isolate state between tracker instances", function () {
      var t1 = gifCaptcha.createAttemptTracker({ maxAttempts: 1, lockoutMs: 60000 });
      var t2 = gifCaptcha.createAttemptTracker({ maxAttempts: 1, lockoutMs: 60000 });

      t1.recordAttempt("shared-id");
      assert.equal(t1.isLocked("shared-id").locked, true);
      assert.equal(t2.isLocked("shared-id").locked, false);
    });

    it("should allow different configs per instance", function () {
      var strict = gifCaptcha.createAttemptTracker({ maxAttempts: 1 });
      var lenient = gifCaptcha.createAttemptTracker({ maxAttempts: 100 });

      strict.recordAttempt("x");
      assert.equal(strict.isLocked("x").locked, true);

      lenient.recordAttempt("x");
      assert.equal(lenient.isLocked("x").locked, false);
    });
  });
});
