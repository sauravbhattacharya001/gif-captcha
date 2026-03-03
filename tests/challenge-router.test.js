"use strict";
var assert = require("assert");
var gifCaptcha = require("../src/index");
var createChallengeRouter = gifCaptcha.createChallengeRouter;

describe("createChallengeRouter", function () {
  describe("construction", function () {
    it("creates router with default options", function () {
      var router = createChallengeRouter();
      var config = router.getConfig();
      assert.strictEqual(config.defaultDifficulty, 2);
      assert.strictEqual(config.maxEscalation, 5);
      assert.strictEqual(config.escalateAfterFails, 2);
      assert.strictEqual(config.deescalateAfterPasses, 3);
      assert.strictEqual(config.reputationWeight, 0.6);
      assert.strictEqual(config.historyWeight, 0.4);
      assert.strictEqual(config.blockThreshold, 0.15);
      assert.strictEqual(config.trustThreshold, 0.85);
    });

    it("accepts custom difficulty levels", function () {
      var router = createChallengeRouter({
        difficulties: { low: 1, mid: 2, high: 3 },
        maxEscalation: 3,
      });
      var d = router.route("c1");
      assert.ok(d.difficultyName);
    });

    it("clamps invalid options to safe ranges", function () {
      var router = createChallengeRouter({
        defaultDifficulty: -5,
        maxEscalation: 999,
        blockThreshold: 2.5,
      });
      var config = router.getConfig();
      assert.strictEqual(config.defaultDifficulty, 1);
      assert.strictEqual(config.maxEscalation, 10);
      assert.strictEqual(config.blockThreshold, 1);
    });

    it("ignores non-numeric options", function () {
      var router = createChallengeRouter({
        defaultDifficulty: "abc",
        reputationWeight: null,
      });
      var config = router.getConfig();
      assert.strictEqual(config.defaultDifficulty, 2);
      assert.strictEqual(config.reputationWeight, 0.6);
    });
  });

  describe("route()", function () {
    it("throws on empty identifier", function () {
      var router = createChallengeRouter();
      assert.throws(function () { router.route(""); });
      assert.throws(function () { router.route(null); });
      assert.throws(function () { router.route(123); });
    });

    it("routes unknown client with default difficulty", function () {
      var router = createChallengeRouter();
      var d = router.route("client1");
      assert.strictEqual(d.action, "challenge");
      assert.strictEqual(d.difficulty, 2);
      assert.strictEqual(d.difficultyName, "easy");
      assert.strictEqual(d.reason, "computed");
      assert.strictEqual(d.identifier, "client1");
      assert.ok(d.timestamp > 0);
    });

    it("blocks clients with low reputation score", function () {
      var router = createChallengeRouter();
      var d = router.route("badguy", { reputationScore: 0.05 });
      assert.strictEqual(d.action, "block");
      assert.strictEqual(d.difficulty, 0);
      assert.strictEqual(d.reason, "blocked_by_reputation");
    });

    it("blocks clients with block action from reputation tracker", function () {
      var router = createChallengeRouter();
      var d = router.route("blocked", { reputationAction: "block" });
      assert.strictEqual(d.action, "block");
    });

    it("allows trusted clients with easy difficulty", function () {
      var router = createChallengeRouter();
      var d = router.route("trusted", { reputationScore: 0.95 });
      assert.strictEqual(d.action, "challenge");
      assert.strictEqual(d.difficulty, 1);
      assert.strictEqual(d.reason, "trusted_reputation");
    });

    it("allows clients with allow action from reputation tracker", function () {
      var router = createChallengeRouter();
      var d = router.route("good", { reputationAction: "allow" });
      assert.strictEqual(d.action, "challenge");
      assert.strictEqual(d.reason, "trusted_reputation");
    });

    it("escalates for suspicious reputation", function () {
      var router = createChallengeRouter();
      var d = router.route("sus", { reputationScore: 0.3 });
      assert.strictEqual(d.action, "challenge");
      assert.ok(d.difficulty > 2, "should be harder than default");
      assert.strictEqual(d.reason, "escalated");
    });

    it("escalates for challenge_hard action", function () {
      var router = createChallengeRouter();
      var d = router.route("sus2", { reputationAction: "challenge_hard", reputationScore: 0.5 });
      assert.ok(d.difficulty >= 2);
    });

    it("de-escalates for good reputation", function () {
      var router = createChallengeRouter();
      var d = router.route("nice", { reputationScore: 0.75 });
      assert.strictEqual(d.reason, "deescalated");
      assert.ok(d.difficulty <= 2);
    });

    it("routes same client consistently", function () {
      var router = createChallengeRouter();
      var d1 = router.route("c1");
      var d2 = router.route("c1");
      assert.strictEqual(d1.difficulty, d2.difficulty);
    });
  });

  describe("recordResult()", function () {
    it("throws on invalid identifier", function () {
      var router = createChallengeRouter();
      assert.throws(function () { router.recordResult("", true); });
      assert.throws(function () { router.recordResult(null, true); });
    });

    it("escalates after consecutive fails", function () {
      var router = createChallengeRouter({ escalateAfterFails: 2 });
      router.route("c1"); // initialize at default=2
      router.recordResult("c1", false);
      router.recordResult("c1", false);
      var info = router.getClientInfo("c1");
      assert.ok(info.level > 2, "should have escalated");
    });

    it("de-escalates after consecutive passes", function () {
      var router = createChallengeRouter({
        deescalateAfterPasses: 2,
        defaultDifficulty: 3,
      });
      router.route("c1");
      router.recordResult("c1", true);
      router.recordResult("c1", true);
      var info = router.getClientInfo("c1");
      assert.ok(info.level < 3, "should have de-escalated");
    });

    it("resets consecutive counter on opposite result", function () {
      var router = createChallengeRouter();
      router.route("c1");
      router.recordResult("c1", false);
      router.recordResult("c1", false); // 2 fails
      router.recordResult("c1", true);  // resets fails
      var info = router.getClientInfo("c1");
      assert.strictEqual(info.consecutiveFails, 0);
      assert.strictEqual(info.consecutivePasses, 1);
    });

    it("does not escalate beyond maxEscalation", function () {
      var router = createChallengeRouter({ maxEscalation: 3, defaultDifficulty: 2 });
      router.route("c1");
      for (var i = 0; i < 20; i++) router.recordResult("c1", false);
      var info = router.getClientInfo("c1");
      assert.ok(info.level <= 3);
    });

    it("does not de-escalate below 1", function () {
      var router = createChallengeRouter({ defaultDifficulty: 1 });
      router.route("c1");
      for (var i = 0; i < 20; i++) router.recordResult("c1", true);
      var info = router.getClientInfo("c1");
      assert.strictEqual(info.level, 1);
    });

    it("tracks totalPasses and totalFails", function () {
      var router = createChallengeRouter();
      router.route("c1");
      router.recordResult("c1", true);
      router.recordResult("c1", true);
      router.recordResult("c1", false);
      var info = router.getClientInfo("c1");
      assert.strictEqual(info.totalPasses, 2);
      assert.strictEqual(info.totalFails, 1);
      assert.ok(Math.abs(info.passRate - 2/3) < 0.01);
    });
  });

  describe("custom rules", function () {
    it("applies matching custom rule", function () {
      var router = createChallengeRouter({
        rules: [{
          name: "proxy_block",
          test: function (id, ctx) { return ctx.isProxy === true; },
          difficulty: 5,
          priority: 10,
        }],
      });
      var d = router.route("c1", { isProxy: true });
      assert.strictEqual(d.difficulty, 5);
      assert.strictEqual(d.reason, "custom_rule:proxy_block");
    });

    it("skips non-matching rules", function () {
      var router = createChallengeRouter({
        rules: [{
          name: "proxy_block",
          test: function (id, ctx) { return ctx.isProxy === true; },
          difficulty: 5,
        }],
      });
      var d = router.route("c1", { isProxy: false });
      assert.strictEqual(d.reason, "computed");
    });

    it("uses highest priority rule", function () {
      var router = createChallengeRouter({
        rules: [
          { name: "low", test: function () { return true; }, difficulty: 1, priority: 1 },
          { name: "high", test: function () { return true; }, difficulty: 5, priority: 10 },
        ],
      });
      var d = router.route("c1");
      assert.strictEqual(d.difficulty, 5);
      assert.strictEqual(d.reason, "custom_rule:high");
    });

    it("ignores rules that throw", function () {
      var router = createChallengeRouter({
        rules: [{
          name: "broken",
          test: function () { throw new Error("oops"); },
          difficulty: 5,
        }],
      });
      var d = router.route("c1");
      assert.strictEqual(d.reason, "computed"); // fell through
    });

    it("ignores invalid rule definitions", function () {
      var router = createChallengeRouter({
        rules: [
          null,
          { name: 123 },
          { name: "no_test", difficulty: 3 },
          { name: "no_diff", test: function () { return true; } },
        ],
      });
      var config = router.getConfig();
      assert.strictEqual(config.customRuleCount, 0);
    });
  });

  describe("getClientInfo()", function () {
    it("returns null for unknown client", function () {
      var router = createChallengeRouter();
      assert.strictEqual(router.getClientInfo("unknown"), null);
    });

    it("returns null for invalid identifier", function () {
      var router = createChallengeRouter();
      assert.strictEqual(router.getClientInfo(""), null);
      assert.strictEqual(router.getClientInfo(null), null);
    });

    it("returns correct info after routing and results", function () {
      var router = createChallengeRouter();
      router.route("c1");
      router.recordResult("c1", true);
      var info = router.getClientInfo("c1");
      assert.strictEqual(info.totalRouted, 1);
      assert.strictEqual(info.totalPasses, 1);
      assert.strictEqual(info.consecutivePasses, 1);
      assert.ok(info.lastRoutedAt > 0);
    });
  });

  describe("forgetClient()", function () {
    it("removes known client", function () {
      var router = createChallengeRouter();
      router.route("c1");
      assert.ok(router.forgetClient("c1"));
      assert.strictEqual(router.getClientInfo("c1"), null);
    });

    it("returns false for unknown client", function () {
      var router = createChallengeRouter();
      assert.strictEqual(router.forgetClient("nope"), false);
    });

    it("returns false for invalid input", function () {
      var router = createChallengeRouter();
      assert.strictEqual(router.forgetClient(""), false);
    });
  });

  describe("resetClientLevel()", function () {
    it("resets level to default", function () {
      var router = createChallengeRouter({ defaultDifficulty: 2 });
      router.route("c1");
      router.recordResult("c1", false);
      router.recordResult("c1", false);
      router.recordResult("c1", false);
      router.resetClientLevel("c1");
      var info = router.getClientInfo("c1");
      assert.strictEqual(info.level, 2);
      assert.strictEqual(info.consecutiveFails, 0);
      assert.strictEqual(info.consecutivePasses, 0);
      // Stats should be preserved
      assert.strictEqual(info.totalFails, 3);
    });

    it("returns false for unknown client", function () {
      var router = createChallengeRouter();
      assert.strictEqual(router.resetClientLevel("nope"), false);
    });
  });

  describe("getKnownClients()", function () {
    it("returns empty list initially", function () {
      var router = createChallengeRouter();
      assert.deepStrictEqual(router.getKnownClients(), []);
    });

    it("lists all routed clients", function () {
      var router = createChallengeRouter();
      router.route("a");
      router.route("b");
      router.route("c");
      var clients = router.getKnownClients();
      assert.strictEqual(clients.length, 3);
      assert.ok(clients.indexOf("a") >= 0);
      assert.ok(clients.indexOf("b") >= 0);
      assert.ok(clients.indexOf("c") >= 0);
    });
  });

  describe("decision log", function () {
    it("records decisions", function () {
      var router = createChallengeRouter();
      router.route("c1");
      router.route("c2");
      var recent = router.getRecentDecisions(5);
      assert.strictEqual(recent.length, 2);
      assert.strictEqual(recent[0].identifier, "c2"); // most recent first
      assert.strictEqual(recent[1].identifier, "c1");
    });

    it("respects count limit", function () {
      var router = createChallengeRouter();
      for (var i = 0; i < 10; i++) router.route("c" + i);
      var recent = router.getRecentDecisions(3);
      assert.strictEqual(recent.length, 3);
    });

    it("uses circular buffer", function () {
      var router = createChallengeRouter({ maxDecisionLog: 5 });
      for (var i = 0; i < 10; i++) router.route("c" + i);
      var recent = router.getRecentDecisions(5);
      assert.strictEqual(recent.length, 5);
      assert.strictEqual(recent[0].identifier, "c9");
    });

    it("filters decisions by client", function () {
      var router = createChallengeRouter();
      router.route("a");
      router.route("b");
      router.route("a");
      var aDecisions = router.getClientDecisions("a", 10);
      assert.strictEqual(aDecisions.length, 2);
      aDecisions.forEach(function (d) {
        assert.strictEqual(d.identifier, "a");
      });
    });

    it("returns empty for invalid client decisions", function () {
      var router = createChallengeRouter();
      assert.deepStrictEqual(router.getClientDecisions("", 10), []);
    });
  });

  describe("getStats()", function () {
    it("returns zeroed stats initially", function () {
      var router = createChallengeRouter();
      var s = router.getStats();
      assert.strictEqual(s.totalRouted, 0);
      assert.strictEqual(s.totalBlocked, 0);
      assert.strictEqual(s.activeClients, 0);
    });

    it("tracks routing counts", function () {
      var router = createChallengeRouter();
      router.route("c1");
      router.route("c2");
      router.route("c1");
      var s = router.getStats();
      assert.strictEqual(s.totalRouted, 3);
      assert.strictEqual(s.activeClients, 2);
    });

    it("tracks blocks and allows", function () {
      var router = createChallengeRouter();
      router.route("bad", { reputationScore: 0.01 });
      router.route("good", { reputationScore: 0.99 });
      var s = router.getStats();
      assert.strictEqual(s.totalBlocked, 1);
      assert.strictEqual(s.totalAllowed, 1);
    });

    it("tracks difficulty distribution", function () {
      var router = createChallengeRouter();
      router.route("c1"); // default = easy
      var s = router.getStats();
      assert.ok(s.byDifficulty.easy >= 1);
    });

    it("tracks escalated clients count", function () {
      var router = createChallengeRouter({ defaultDifficulty: 2, escalateAfterFails: 1 });
      router.route("c1");
      router.recordResult("c1", false);
      var s = router.getStats();
      assert.strictEqual(s.escalatedClients, 1);
    });
  });

  describe("routeBatch()", function () {
    it("routes multiple clients", function () {
      var router = createChallengeRouter();
      var results = router.routeBatch([
        { identifier: "a" },
        { identifier: "b" },
        { identifier: "c" },
      ]);
      assert.strictEqual(results.length, 3);
      results.forEach(function (r) {
        assert.strictEqual(r.action, "challenge");
      });
    });

    it("handles invalid entries gracefully", function () {
      var router = createChallengeRouter();
      var results = router.routeBatch([
        { identifier: "a" },
        null,
        { identifier: "c" },
      ]);
      assert.strictEqual(results.length, 3);
      assert.strictEqual(results[1].action, "error");
    });

    it("throws on non-array input", function () {
      var router = createChallengeRouter();
      assert.throws(function () { router.routeBatch("not array"); });
    });
  });

  describe("persistence", function () {
    it("exports and imports state", function () {
      var router = createChallengeRouter();
      router.route("c1");
      router.route("c2");
      router.recordResult("c1", false);
      router.recordResult("c1", false);
      var state = router.exportState();

      var router2 = createChallengeRouter();
      router2.importState(state);
      var info = router2.getClientInfo("c1");
      assert.strictEqual(info.totalFails, 2);
      assert.strictEqual(info.consecutiveFails, 2);
      var s2 = router2.getStats();
      assert.strictEqual(s2.totalRouted, 2);
    });

    it("throws on invalid import", function () {
      var router = createChallengeRouter();
      assert.throws(function () { router.importState(null); });
      assert.throws(function () { router.importState("string"); });
    });

    it("handles empty state import", function () {
      var router = createChallengeRouter();
      router.importState({});
      assert.strictEqual(router.getKnownClients().length, 0);
    });

    it("clamps imported values to safe ranges", function () {
      var router = createChallengeRouter({ maxEscalation: 5 });
      router.importState({
        clients: {
          "c1": { level: 99, consecutiveFails: -3, totalRouted: -1 },
        },
      });
      var info = router.getClientInfo("c1");
      assert.strictEqual(info.level, 5);
      assert.strictEqual(info.consecutiveFails, 0);
      assert.strictEqual(info.totalRouted, 0);
    });
  });

  describe("reset()", function () {
    it("clears all state", function () {
      var router = createChallengeRouter();
      router.route("c1");
      router.route("c2");
      router.recordResult("c1", false);
      router.reset();
      assert.deepStrictEqual(router.getKnownClients(), []);
      var s = router.getStats();
      assert.strictEqual(s.totalRouted, 0);
      assert.strictEqual(s.totalBlocked, 0);
      assert.strictEqual(s.decisionsLogged, 0);
    });
  });

  describe("end-to-end scenarios", function () {
    it("progressive escalation for repeated failures", function () {
      var router = createChallengeRouter({
        defaultDifficulty: 1,
        maxEscalation: 5,
        escalateAfterFails: 2,
      });
      router.route("attacker");
      var levels = [1]; // start
      for (var i = 0; i < 10; i++) {
        router.recordResult("attacker", false);
        levels.push(router.getClientInfo("attacker").level);
      }
      // Should monotonically increase (or plateau at max)
      for (var j = 1; j < levels.length; j++) {
        assert.ok(levels[j] >= levels[j-1], "level should not decrease: " + levels);
      }
      assert.ok(levels[levels.length - 1] >= 3, "should have escalated significantly");
    });

    it("rehabilitation for improved behavior", function () {
      var router = createChallengeRouter({
        defaultDifficulty: 3,
        maxEscalation: 5,
        escalateAfterFails: 2,
        deescalateAfterPasses: 2,
      });
      router.route("c1");
      // Escalate
      router.recordResult("c1", false);
      router.recordResult("c1", false);
      router.recordResult("c1", false);
      router.recordResult("c1", false);
      var escalated = router.getClientInfo("c1").level;
      // Then rehabilitate
      router.recordResult("c1", true);
      router.recordResult("c1", true);
      router.recordResult("c1", true);
      router.recordResult("c1", true);
      var rehabbed = router.getClientInfo("c1").level;
      assert.ok(rehabbed < escalated, "should have de-escalated after passes");
    });

    it("reputation overrides history for blocked clients", function () {
      var router = createChallengeRouter();
      router.route("c1");
      // Build up good history
      for (var i = 0; i < 10; i++) router.recordResult("c1", true);
      // But reputation says block
      var d = router.route("c1", { reputationScore: 0.01 });
      assert.strictEqual(d.action, "block");
    });

    it("multi-client isolation", function () {
      var router = createChallengeRouter();
      router.route("good_client");
      router.route("bad_client");
      // bad client fails
      for (var i = 0; i < 5; i++) router.recordResult("bad_client", false);
      // good client passes
      for (var j = 0; j < 5; j++) router.recordResult("good_client", true);
      var good = router.getClientInfo("good_client");
      var bad = router.getClientInfo("bad_client");
      assert.ok(good.level <= bad.level, "good client should not be penalized");
    });

    it("batch routing with mixed contexts", function () {
      var router = createChallengeRouter();
      var results = router.routeBatch([
        { identifier: "trusted", context: { reputationScore: 0.95 } },
        { identifier: "normal", context: {} },
        { identifier: "blocked", context: { reputationScore: 0.01 } },
      ]);
      assert.strictEqual(results[0].reason, "trusted_reputation");
      assert.strictEqual(results[1].action, "challenge");
      assert.strictEqual(results[2].action, "block");
    });
  });
});
