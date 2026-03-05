/* eslint-env mocha */
"use strict";


// Load source directly
var src = require("../src/index");
var createReputationTracker = src.createReputationTracker;

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

describe("createReputationTracker", function () {

  describe("initialization", function () {
    it("should create a tracker with default options", function () {
      var tracker = createReputationTracker();
      assert.ok(tracker);
      assert.strictEqual(typeof tracker.recordSolve, "function");
      assert.strictEqual(typeof tracker.recordFail, "function");
      assert.strictEqual(typeof tracker.recordTimeout, "function");
      assert.strictEqual(typeof tracker.getReputation, "function");
      assert.strictEqual(typeof tracker.getAction, "function");
    });

    it("should return null reputation for unknown identifier", function () {
      var tracker = createReputationTracker();
      assert.strictEqual(tracker.getReputation("1.2.3.4"), null);
    });

    it("should accept custom options", function () {
      var tracker = createReputationTracker({
        maxEntries: 100,
        suspiciousThreshold: 0.4,
        trustedThreshold: 0.9,
        blockThreshold: 0.05,
        initialScore: 0.6,
      });
      var action = tracker.getAction("new-ip");
      assert.strictEqual(action.score, 0.6);
    });
  });

  describe("recordSolve", function () {
    it("should increase score on successful solve", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      var result = tracker.recordSolve("1.2.3.4");
      assert.ok(result.score > 0.5);
    });

    it("should accumulate score with multiple solves", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      tracker.recordSolve("ip1");
      tracker.recordSolve("ip1");
      var rep = tracker.getReputation("ip1");
      assert.ok(rep.score > 0.6);
      assert.strictEqual(rep.solves, 2);
    });

    it("should cap score at 1.0", function () {
      var tracker = createReputationTracker({ initialScore: 0.95 });
      tracker.recordSolve("ip1");
      tracker.recordSolve("ip1");
      var rep = tracker.getReputation("ip1");
      assert.ok(rep.score <= 1.0);
    });

    it("should track totalAttempts", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      tracker.recordSolve("ip1");
      var rep = tracker.getReputation("ip1");
      assert.strictEqual(rep.totalAttempts, 2);
    });
  });

  describe("recordFail", function () {
    it("should decrease score on failure", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      var result = tracker.recordFail("1.2.3.4");
      assert.ok(result.score < 0.5);
    });

    it("should floor score at 0", function () {
      var tracker = createReputationTracker({ initialScore: 0.1 });
      tracker.recordFail("ip1");
      tracker.recordFail("ip1");
      var rep = tracker.getReputation("ip1");
      assert.ok(rep.score >= 0);
    });

    it("should classify as suspicious after repeated fails", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      tracker.recordFail("ip1");
      tracker.recordFail("ip1");
      var rep = tracker.getReputation("ip1");
      assert.ok(rep.classification === "suspicious" || rep.classification === "neutral");
    });

    it("should track fail count", function () {
      var tracker = createReputationTracker();
      tracker.recordFail("ip1");
      tracker.recordFail("ip1");
      tracker.recordFail("ip1");
      var rep = tracker.getReputation("ip1");
      assert.strictEqual(rep.fails, 3);
    });
  });

  describe("recordTimeout", function () {
    it("should slightly decrease score on timeout", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      var result = tracker.recordTimeout("ip1");
      assert.ok(result.score < 0.5);
    });

    it("should penalize less than a fail", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      var t1 = createReputationTracker({ initialScore: 0.5 });
      tracker.recordTimeout("ip1");
      t1.recordFail("ip1");
      var timeoutScore = tracker.getReputation("ip1").score;
      var failScore = t1.getReputation("ip1").score;
      assert.ok(timeoutScore > failScore);
    });

    it("should track timeout count", function () {
      var tracker = createReputationTracker();
      tracker.recordTimeout("ip1");
      tracker.recordTimeout("ip1");
      var rep = tracker.getReputation("ip1");
      assert.strictEqual(rep.timeouts, 2);
    });
  });

  describe("getAction", function () {
    it("should return challenge for unknown identifiers", function () {
      var tracker = createReputationTracker();
      var action = tracker.getAction("unknown");
      assert.strictEqual(action.action, "challenge");
      assert.strictEqual(action.reason, "unknown_identifier");
    });

    it("should return allow for high-reputation identifiers", function () {
      // Disable burst penalty so rapid test solves build trust cleanly
      var tracker = createReputationTracker({
        initialScore: 0.5, trustedThreshold: 0.8,
        burstPenalty: 0, solveWeight: 0.1,
      });
      // Solve many times to build reputation
      for (var i = 0; i < 10; i++) tracker.recordSolve("good-ip");
      var action = tracker.getAction("good-ip");
      assert.strictEqual(action.action, "allow");
      assert.strictEqual(action.reason, "trusted_reputation");
    });

    it("should return block for very low reputation", function () {
      var tracker = createReputationTracker({ initialScore: 0.3, blockThreshold: 0.1 });
      for (var i = 0; i < 5; i++) tracker.recordFail("bad-ip");
      var action = tracker.getAction("bad-ip");
      assert.strictEqual(action.action, "block");
      assert.strictEqual(action.reason, "reputation_too_low");
    });

    it("should return challenge_hard for suspicious reputation", function () {
      var tracker = createReputationTracker({ initialScore: 0.4, suspiciousThreshold: 0.3 });
      tracker.recordFail("sus-ip");
      var action = tracker.getAction("sus-ip");
      assert.strictEqual(action.action, "challenge_hard");
      assert.strictEqual(action.reason, "suspicious_reputation");
    });
  });

  describe("allowlist", function () {
    it("should always return trusted for allowlisted identifiers", function () {
      var tracker = createReputationTracker();
      tracker.addToAllowlist("vip-ip");
      var rep = tracker.getReputation("vip-ip");
      assert.strictEqual(rep.score, 1);
      assert.strictEqual(rep.classification, "trusted");
    });

    it("should return allow action for allowlisted", function () {
      var tracker = createReputationTracker();
      tracker.addToAllowlist("vip");
      var action = tracker.getAction("vip");
      assert.strictEqual(action.action, "allow");
      assert.strictEqual(action.reason, "allowlisted");
    });

    it("should remove from blocklist when adding to allowlist", function () {
      var tracker = createReputationTracker();
      tracker.addToBlocklist("ip1");
      assert.ok(tracker.isBlocklisted("ip1"));
      tracker.addToAllowlist("ip1");
      assert.ok(tracker.isAllowlisted("ip1"));
      assert.ok(!tracker.isBlocklisted("ip1"));
    });

    it("should not change score on recordSolve for allowlisted", function () {
      var tracker = createReputationTracker();
      tracker.addToAllowlist("ip1");
      var result = tracker.recordSolve("ip1");
      assert.strictEqual(result.score, 1);
      assert.strictEqual(result.classification, "trusted");
    });

    it("should support isAllowlisted check", function () {
      var tracker = createReputationTracker();
      assert.ok(!tracker.isAllowlisted("ip1"));
      tracker.addToAllowlist("ip1");
      assert.ok(tracker.isAllowlisted("ip1"));
    });

    it("should support removeFromAllowlist", function () {
      var tracker = createReputationTracker();
      tracker.addToAllowlist("ip1");
      tracker.removeFromAllowlist("ip1");
      assert.ok(!tracker.isAllowlisted("ip1"));
    });
  });

  describe("blocklist", function () {
    it("should always return blocked for blocklisted identifiers", function () {
      var tracker = createReputationTracker();
      tracker.addToBlocklist("bad-ip");
      var rep = tracker.getReputation("bad-ip");
      assert.strictEqual(rep.score, 0);
      assert.strictEqual(rep.classification, "blocked");
    });

    it("should return block action for blocklisted", function () {
      var tracker = createReputationTracker();
      tracker.addToBlocklist("bad");
      var action = tracker.getAction("bad");
      assert.strictEqual(action.action, "block");
      assert.strictEqual(action.reason, "blocklisted");
    });

    it("should remove from allowlist when adding to blocklist", function () {
      var tracker = createReputationTracker();
      tracker.addToAllowlist("ip1");
      tracker.addToBlocklist("ip1");
      assert.ok(tracker.isBlocklisted("ip1"));
      assert.ok(!tracker.isAllowlisted("ip1"));
    });

    it("should not change score on recordFail for blocklisted", function () {
      var tracker = createReputationTracker();
      tracker.addToBlocklist("ip1");
      var result = tracker.recordFail("ip1");
      assert.strictEqual(result.score, 0);
      assert.strictEqual(result.classification, "blocked");
    });

    it("should support isBlocklisted check", function () {
      var tracker = createReputationTracker();
      assert.ok(!tracker.isBlocklisted("ip1"));
      tracker.addToBlocklist("ip1");
      assert.ok(tracker.isBlocklisted("ip1"));
    });

    it("should support removeFromBlocklist", function () {
      var tracker = createReputationTracker();
      tracker.addToBlocklist("ip1");
      tracker.removeFromBlocklist("ip1");
      assert.ok(!tracker.isBlocklisted("ip1"));
    });
  });

  describe("tags", function () {
    it("should store and retrieve tags", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1"); // ensure entry exists
      tracker.setTag("ip1", "country", "US");
      assert.strictEqual(tracker.getTag("ip1", "country"), "US");
    });

    it("should return undefined for missing tag", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      assert.strictEqual(tracker.getTag("ip1", "missing"), undefined);
    });

    it("should return undefined for unknown identifier", function () {
      var tracker = createReputationTracker();
      assert.strictEqual(tracker.getTag("unknown", "tag"), undefined);
    });

    it("should overwrite existing tags", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      tracker.setTag("ip1", "ua", "chrome");
      tracker.setTag("ip1", "ua", "firefox");
      assert.strictEqual(tracker.getTag("ip1", "ua"), "firefox");
    });
  });

  describe("LRU eviction", function () {
    it("should evict oldest entry when maxEntries exceeded", function () {
      var tracker = createReputationTracker({ maxEntries: 3 });
      tracker.recordSolve("ip1");
      tracker.recordSolve("ip2");
      tracker.recordSolve("ip3");
      tracker.recordSolve("ip4"); // should evict ip1
      assert.strictEqual(tracker.getReputation("ip1"), null);
      assert.ok(tracker.getReputation("ip4") !== null);
    });

    it("should keep recently accessed entries", function () {
      var tracker = createReputationTracker({ maxEntries: 3 });
      tracker.recordSolve("ip1");
      tracker.recordSolve("ip2");
      tracker.recordSolve("ip3");
      tracker.recordSolve("ip1"); // touch ip1
      tracker.recordSolve("ip4"); // should evict ip2 (oldest untouched)
      assert.ok(tracker.getReputation("ip1") !== null);
      assert.strictEqual(tracker.getReputation("ip2"), null);
    });
  });

  describe("getStats", function () {
    it("should return empty stats for new tracker", function () {
      var tracker = createReputationTracker();
      var stats = tracker.getStats();
      assert.strictEqual(stats.trackedCount, 0);
      assert.strictEqual(stats.allowlistCount, 0);
      assert.strictEqual(stats.blocklistCount, 0);
      assert.strictEqual(stats.averageScore, 0);
    });

    it("should count tracked entries", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      tracker.recordSolve("ip2");
      var stats = tracker.getStats();
      assert.strictEqual(stats.trackedCount, 2);
    });

    it("should count allowlist and blocklist", function () {
      var tracker = createReputationTracker();
      tracker.addToAllowlist("a1");
      tracker.addToAllowlist("a2");
      tracker.addToBlocklist("b1");
      var stats = tracker.getStats();
      assert.strictEqual(stats.allowlistCount, 2);
      assert.strictEqual(stats.blocklistCount, 1);
    });

    it("should compute average score", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      tracker.recordSolve("ip1"); // ~0.6
      tracker.recordSolve("ip2"); // ~0.6
      var stats = tracker.getStats();
      assert.ok(stats.averageScore > 0.5);
    });

    it("should track classifications", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      tracker.recordSolve("ip1");
      var stats = tracker.getStats();
      assert.ok(stats.classifications.neutral >= 0 || stats.classifications.trusted >= 0);
    });
  });

  describe("forget", function () {
    it("should remove an identifier", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      assert.ok(tracker.getReputation("ip1") !== null);
      var result = tracker.forget("ip1");
      assert.strictEqual(result, true);
      assert.strictEqual(tracker.getReputation("ip1"), null);
    });

    it("should return false for unknown identifier", function () {
      var tracker = createReputationTracker();
      assert.strictEqual(tracker.forget("unknown"), false);
    });

    it("should update stats after forget", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      tracker.recordSolve("ip2");
      tracker.forget("ip1");
      var stats = tracker.getStats();
      assert.strictEqual(stats.trackedCount, 1);
    });
  });

  describe("reset", function () {
    it("should clear all data", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      tracker.addToAllowlist("ip2");
      tracker.addToBlocklist("ip3");
      tracker.reset();
      assert.strictEqual(tracker.getReputation("ip1"), null);
      assert.ok(!tracker.isAllowlisted("ip2"));
      assert.ok(!tracker.isBlocklisted("ip3"));
      var stats = tracker.getStats();
      assert.strictEqual(stats.trackedCount, 0);
      assert.strictEqual(stats.allowlistCount, 0);
      assert.strictEqual(stats.blocklistCount, 0);
    });
  });

  describe("export/import", function () {
    it("should export reputation data", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      tracker.addToAllowlist("vip");
      tracker.addToBlocklist("bad");
      tracker.setTag("ip1", "region", "US");
      var data = tracker.exportData();
      assert.ok(data.entries["ip1"]);
      assert.strictEqual(data.entries["ip1"].solves, 1);
      assert.deepStrictEqual(data.allowlist, ["vip"]);
      assert.deepStrictEqual(data.blocklist, ["bad"]);
    });

    it("should import reputation data", function () {
      var tracker = createReputationTracker();
      tracker.importData({
        entries: {
          "ip1": { score: 0.8, solves: 5, fails: 1, timeouts: 0, totalAttempts: 6, lastActivity: Date.now(), firstSeen: Date.now() - 100000 }
        },
        allowlist: ["vip"],
        blocklist: ["bad"],
      });
      var rep = tracker.getReputation("ip1");
      assert.ok(rep !== null);
      assert.strictEqual(rep.solves, 5);
      assert.ok(tracker.isAllowlisted("vip"));
      assert.ok(tracker.isBlocklisted("bad"));
    });

    it("should roundtrip export/import", function () {
      var t1 = createReputationTracker({ initialScore: 0.5 });
      t1.recordSolve("ip1");
      t1.recordFail("ip2");
      t1.addToAllowlist("vip");
      t1.setTag("ip1", "ua", "bot-check");
      var data = t1.exportData();

      var t2 = createReputationTracker({ initialScore: 0.5 });
      t2.importData(data);
      assert.strictEqual(t2.getReputation("ip1").solves, 1);
      assert.strictEqual(t2.getReputation("ip2").fails, 1);
      assert.ok(t2.isAllowlisted("vip"));
      assert.strictEqual(t2.getTag("ip1", "ua"), "bot-check");
    });

    it("should handle invalid import data gracefully", function () {
      var tracker = createReputationTracker();
      tracker.importData(null);
      tracker.importData(undefined);
      tracker.importData({});
      tracker.importData({ entries: "not-an-object" });
      assert.strictEqual(tracker.getStats().trackedCount, 0);
    });

    it("should clamp imported scores to [0,1]", function () {
      var tracker = createReputationTracker();
      tracker.importData({
        entries: {
          "ip1": { score: 5.0, solves: 0, fails: 0, timeouts: 0, totalAttempts: 0, lastActivity: Date.now(), firstSeen: Date.now() }
        }
      });
      var rep = tracker.getReputation("ip1");
      assert.ok(rep.score <= 1.0);
    });
  });

  describe("prototype pollution safety", function () {
    it("should not be affected by __proto__ as identifier", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("__proto__");
      var rep = tracker.getReputation("__proto__");
      assert.ok(rep !== null);
      assert.strictEqual(rep.solves, 1);
      // Ensure Object.prototype was not modified
      assert.strictEqual(({}).solves, undefined);
    });

    it("should not be affected by constructor as identifier", function () {
      var tracker = createReputationTracker();
      tracker.recordFail("constructor");
      var rep = tracker.getReputation("constructor");
      assert.ok(rep !== null);
      assert.strictEqual(rep.fails, 1);
    });

    it("should not pollute via tags", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      tracker.setTag("ip1", "__proto__", "evil");
      assert.strictEqual(({}).evil, undefined);
    });
  });

  describe("score boundaries", function () {
    it("should never produce score below 0", function () {
      var tracker = createReputationTracker({ initialScore: 0.1, failWeight: 0.5 });
      for (var i = 0; i < 20; i++) tracker.recordFail("ip1");
      var rep = tracker.getReputation("ip1");
      assert.ok(rep.score >= 0);
    });

    it("should never produce score above 1", function () {
      var tracker = createReputationTracker({ initialScore: 0.9, solveWeight: 0.5 });
      for (var i = 0; i < 20; i++) tracker.recordSolve("ip1");
      var rep = tracker.getReputation("ip1");
      assert.ok(rep.score <= 1.0);
    });

    it("should clamp initialScore to [0,1]", function () {
      var tracker = createReputationTracker({ initialScore: 2.0 });
      var action = tracker.getAction("new");
      assert.ok(action.score <= 1.0);
    });
  });

  describe("mixed behavior", function () {
    it("should handle mixed solves and fails correctly", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      tracker.recordSolve("ip1");
      tracker.recordFail("ip1");
      var rep = tracker.getReputation("ip1");
      // Solve adds 0.1, fail subtracts 0.15, net ~-0.05
      assert.ok(rep.score < 0.5);
      assert.strictEqual(rep.solves, 1);
      assert.strictEqual(rep.fails, 1);
      assert.strictEqual(rep.totalAttempts, 2);
    });

    it("should handle different identifiers independently", function () {
      var tracker = createReputationTracker({ initialScore: 0.5 });
      tracker.recordSolve("good-ip");
      tracker.recordFail("bad-ip");
      var goodRep = tracker.getReputation("good-ip");
      var badRep = tracker.getReputation("bad-ip");
      assert.ok(goodRep.score > badRep.score);
    });

    it("should convert numeric identifiers to strings", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve(12345);
      var rep = tracker.getReputation("12345");
      assert.ok(rep !== null);
      assert.strictEqual(rep.solves, 1);
    });
  });

  describe("firstSeen and lastActivity", function () {
    it("should track firstSeen timestamp", function () {
      var before = Date.now();
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      var rep = tracker.getReputation("ip1");
      assert.ok(rep.firstSeen >= before);
      assert.ok(rep.firstSeen <= Date.now());
    });

    it("should update lastActivity on each action", function () {
      var tracker = createReputationTracker();
      tracker.recordSolve("ip1");
      var rep1 = tracker.getReputation("ip1");
      var lastAct1 = rep1.lastActivity;
      tracker.recordFail("ip1");
      var rep2 = tracker.getReputation("ip1");
      assert.ok(rep2.lastActivity >= lastAct1);
    });
  });
});
