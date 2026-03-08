"use strict";

var assert = require("assert");
var gifCaptcha = require("../src/index");
var createHoneypotInjector = gifCaptcha.createHoneypotInjector;

describe("createHoneypotInjector", function () {

  it("should export createHoneypotInjector", function () {
    assert.strictEqual(typeof createHoneypotInjector, "function");
  });

  it("should create an instance with all methods", function () {
    var hi = createHoneypotInjector();
    ["createTrap","createTrapSet","check","checkBatch","getSessionScore",
     "getStrategyStats","getTrap","getTrippedHistory","summary",
     "generateReport","exportState","importState","reset"].forEach(function(m) {
      assert.strictEqual(typeof hi[m], "function", "missing method: " + m);
    });
  });

  describe("createTrap", function () {
    it("should throw on missing sessionId", function () {
      var hi = createHoneypotInjector();
      assert.throws(function () { hi.createTrap(); }, /sessionId is required/);
      assert.throws(function () { hi.createTrap({}); }, /sessionId is required/);
      assert.throws(function () { hi.createTrap({ sessionId: "" }); }, /sessionId is required/);
    });

    it("should create a trap with expected fields", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      assert.ok(trap.id);
      assert.ok(trap.fieldName);
      assert.ok(trap.strategy);
      assert.ok(trap.html);
      assert.strictEqual(typeof trap.createdAt, "number");
    });

    it("should use specified strategy", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1", strategy: "aria-hidden" });
      assert.strictEqual(trap.strategy, "aria-hidden");
      assert.ok(trap.html.indexOf("aria-hidden") !== -1);
    });

    it("should use specified fieldName", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1", fieldName: "my_custom_field" });
      assert.strictEqual(trap.fieldName, "my_custom_field");
      assert.ok(trap.html.indexOf("my_custom_field") !== -1);
    });

    it("should generate css-hidden HTML", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1", strategy: "css-hidden" });
      assert.ok(trap.html.indexOf("position:absolute") !== -1);
      assert.ok(trap.html.indexOf("opacity:0") !== -1);
    });

    it("should generate tab-excluded HTML", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1", strategy: "tab-excluded" });
      assert.ok(trap.html.indexOf('tabindex="-1"') !== -1);
      assert.ok(trap.html.indexOf("width:0") !== -1);
    });

    it("should generate decoy-label HTML", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1", strategy: "decoy-label" });
      assert.ok(trap.html.indexOf("<label") !== -1);
    });

    it("should generate temporal HTML with script", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1", strategy: "temporal" });
      assert.ok(trap.html.indexOf("<script>") !== -1);
      assert.ok(trap.html.indexOf("setTimeout") !== -1);
    });

    it("should evict oldest when maxTraps reached", function () {
      var hi = createHoneypotInjector({ maxTraps: 3 });
      var t1 = hi.createTrap({ sessionId: "s1" });
      hi.createTrap({ sessionId: "s1" });
      hi.createTrap({ sessionId: "s1" });
      hi.createTrap({ sessionId: "s1" });
      assert.strictEqual(hi.getTrap(t1.id), null);
    });

    it("should respect custom fieldNames", function () {
      var hi = createHoneypotInjector({ fieldNames: ["trap_field"] });
      var trap = hi.createTrap({ sessionId: "s1" });
      assert.strictEqual(trap.fieldName, "trap_field");
    });
  });

  describe("createTrapSet", function () {
    it("should throw on missing sessionId", function () {
      var hi = createHoneypotInjector();
      assert.throws(function () { hi.createTrapSet(); }, /sessionId is required/);
    });

    it("should create multiple traps with different strategies", function () {
      var hi = createHoneypotInjector();
      var set = hi.createTrapSet({ sessionId: "s1", count: 3 });
      assert.strictEqual(set.length, 3);
      var strats = set.map(function (t) { return t.strategy; });
      var unique = strats.filter(function (v, i, a) { return a.indexOf(v) === i; });
      assert.strictEqual(unique.length, 3);
    });

    it("should cap count to available strategies", function () {
      var hi = createHoneypotInjector({ strategies: ["css-hidden", "aria-hidden"] });
      var set = hi.createTrapSet({ sessionId: "s1", count: 10 });
      assert.strictEqual(set.length, 2);
    });
  });

  describe("check", function () {
    it("should throw on missing trapId", function () {
      var hi = createHoneypotInjector();
      assert.throws(function () { hi.check(); }, /trapId is required/);
      assert.throws(function () { hi.check({}); }, /trapId is required/);
    });

    it("should return clean for empty value", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      var result = hi.check({ trapId: trap.id, value: "" });
      assert.strictEqual(result.tripped, false);
      assert.strictEqual(result.detail, "clean");
    });

    it("should return clean for undefined value", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      var result = hi.check({ trapId: trap.id });
      assert.strictEqual(result.tripped, false);
    });

    it("should return clean for null value", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      var result = hi.check({ trapId: trap.id, value: null });
      assert.strictEqual(result.tripped, false);
    });

    it("should trip on non-empty value", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      var result = hi.check({ trapId: trap.id, value: "spam" });
      assert.strictEqual(result.tripped, true);
      assert.ok(result.confidence >= 0.95);
      assert.strictEqual(result.detail, "honeypot_triggered");
    });

    it("should have higher confidence for URL values", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      var result = hi.check({ trapId: trap.id, value: "https://spam.example.com" });
      assert.strictEqual(result.confidence, 0.99);
    });

    it("should have higher confidence for HTML values", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      var result = hi.check({ trapId: trap.id, value: "<a href='x'>click</a>" });
      assert.strictEqual(result.confidence, 0.99);
    });

    it("should have higher confidence for very long values", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      var result = hi.check({ trapId: trap.id, value: new Array(102).join("x") });
      assert.strictEqual(result.confidence, 0.99);
    });

    it("should return unknown_trap for missing trap", function () {
      var hi = createHoneypotInjector();
      var result = hi.check({ trapId: "nonexistent" });
      assert.strictEqual(result.tripped, false);
      assert.strictEqual(result.detail, "unknown_trap");
    });

    it("should record tripped in history", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      hi.check({ trapId: trap.id, value: "bot" });
      var history = hi.getTrippedHistory();
      assert.strictEqual(history.length, 1);
      assert.strictEqual(history[0].trapId, trap.id);
      assert.strictEqual(history[0].sessionId, "s1");
    });
  });

  describe("checkBatch", function () {
    it("should throw on non-array", function () {
      var hi = createHoneypotInjector();
      assert.throws(function () { hi.checkBatch("not array"); }, /must be an array/);
    });

    it("should return human verdict for all clean", function () {
      var hi = createHoneypotInjector();
      var t1 = hi.createTrap({ sessionId: "s1" });
      var t2 = hi.createTrap({ sessionId: "s1" });
      var result = hi.checkBatch([{ trapId: t1.id, value: "" }, { trapId: t2.id, value: "" }]);
      assert.strictEqual(result.anyTripped, false);
      assert.strictEqual(result.verdict, "human");
    });

    it("should return likely_bot for one tripped", function () {
      var hi = createHoneypotInjector();
      var t1 = hi.createTrap({ sessionId: "s1" });
      var t2 = hi.createTrap({ sessionId: "s1" });
      var result = hi.checkBatch([{ trapId: t1.id, value: "spam" }, { trapId: t2.id, value: "" }]);
      assert.strictEqual(result.trippedCount, 1);
      assert.strictEqual(result.verdict, "likely_bot");
    });

    it("should return definite_bot for multiple tripped", function () {
      var hi = createHoneypotInjector();
      var t1 = hi.createTrap({ sessionId: "s1" });
      var t2 = hi.createTrap({ sessionId: "s1" });
      var result = hi.checkBatch([{ trapId: t1.id, value: "spam1" }, { trapId: t2.id, value: "spam2" }]);
      assert.strictEqual(result.trippedCount, 2);
      assert.strictEqual(result.verdict, "definite_bot");
      assert.ok(result.confidence > 0.95);
    });
  });

  describe("getSessionScore", function () {
    it("should throw on missing sessionId", function () {
      var hi = createHoneypotInjector();
      assert.throws(function () { hi.getSessionScore(); }, /sessionId is required/);
    });

    it("should return unknown for unseen session", function () {
      var hi = createHoneypotInjector();
      assert.strictEqual(hi.getSessionScore("unknown").verdict, "unknown");
    });

    it("should return human for clean session", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      hi.check({ trapId: trap.id, value: "" });
      assert.strictEqual(hi.getSessionScore("s1").verdict, "human");
    });

    it("should return bot for tripped session", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      hi.check({ trapId: trap.id, value: "bot_input" });
      var score = hi.getSessionScore("s1");
      assert.strictEqual(score.verdict, "bot");
      assert.ok(score.botProbability >= 0.9);
    });
  });

  describe("getStrategyStats", function () {
    it("should return stats for all strategies", function () {
      var hi = createHoneypotInjector();
      assert.strictEqual(hi.getStrategyStats().length, 5);
    });

    it("should track per-strategy trips", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1", strategy: "css-hidden" });
      hi.check({ trapId: trap.id, value: "spam" });
      var css = hi.getStrategyStats().find(function (s) { return s.strategy === "css-hidden"; });
      assert.strictEqual(css.tripped, 1);
      assert.strictEqual(css.tripRate, 1);
    });
  });

  describe("getTrap", function () {
    it("should return null for unknown trap", function () {
      assert.strictEqual(createHoneypotInjector().getTrap("x"), null);
    });

    it("should return trap info", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      var info = hi.getTrap(trap.id);
      assert.strictEqual(info.id, trap.id);
      assert.strictEqual(info.checked, false);
    });
  });

  describe("getTrippedHistory", function () {
    it("should return empty initially", function () {
      assert.deepStrictEqual(createHoneypotInjector().getTrippedHistory(), []);
    });

    it("should respect limit", function () {
      var hi = createHoneypotInjector();
      for (var i = 0; i < 5; i++) { var t = hi.createTrap({ sessionId: "s" + i }); hi.check({ trapId: t.id, value: "b" }); }
      assert.strictEqual(hi.getTrippedHistory(3).length, 3);
    });

    it("should cap at maxTrippedHistory", function () {
      var hi = createHoneypotInjector({ maxTrippedHistory: 3, maxTraps: 100 });
      for (var i = 0; i < 5; i++) { var t = hi.createTrap({ sessionId: "s" + i }); hi.check({ trapId: t.id, value: "b" }); }
      assert.strictEqual(hi.getTrippedHistory(100).length, 3);
    });
  });

  describe("summary", function () {
    it("should return initial summary", function () {
      var s = createHoneypotInjector().summary();
      assert.strictEqual(s.activeTraps, 0);
      assert.strictEqual(s.totalCreated, 0);
    });

    it("should reflect activity", function () {
      var hi = createHoneypotInjector();
      var t1 = hi.createTrap({ sessionId: "s1" });
      var t2 = hi.createTrap({ sessionId: "s2" });
      hi.check({ trapId: t1.id, value: "" });
      hi.check({ trapId: t2.id, value: "bot" });
      var s = hi.summary();
      assert.strictEqual(s.totalTripped, 1);
      assert.strictEqual(s.totalClean, 1);
      assert.strictEqual(s.botSessions, 1);
    });
  });

  describe("generateReport", function () {
    it("should return a string report", function () {
      var hi = createHoneypotInjector();
      hi.createTrap({ sessionId: "s1" });
      assert.ok(hi.generateReport().indexOf("Honeypot Injector Report") !== -1);
    });
  });

  describe("exportState / importState", function () {
    it("should roundtrip state", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1" });
      hi.check({ trapId: trap.id, value: "bot" });
      var hi2 = createHoneypotInjector();
      hi2.importState(hi.exportState());
      assert.strictEqual(hi2.summary().totalTripped, 1);
    });

    it("should throw on invalid state", function () {
      assert.throws(function () { createHoneypotInjector().importState(null); }, /state must be an object/);
    });
  });

  describe("reset", function () {
    it("should clear all state", function () {
      var hi = createHoneypotInjector();
      hi.createTrap({ sessionId: "s1" });
      hi.reset();
      assert.strictEqual(hi.summary().totalCreated, 0);
    });
  });

  describe("options", function () {
    it("should fallback on invalid strategies", function () {
      var hi = createHoneypotInjector({ strategies: ["invalid"] });
      assert.ok(hi.createTrap({ sessionId: "s1" }).strategy);
    });

    it("should accept valid strategy subset", function () {
      var hi = createHoneypotInjector({ strategies: ["css-hidden"] });
      assert.strictEqual(hi.createTrap({ sessionId: "s1" }).strategy, "css-hidden");
    });

    it("should respect custom temporalDelayMs", function () {
      var hi = createHoneypotInjector({ temporalDelayMs: 5000 });
      assert.ok(hi.createTrap({ sessionId: "s1", strategy: "temporal" }).html.indexOf("5000") !== -1);
    });
  });

  describe("HTML escaping", function () {
    it("should escape special characters", function () {
      var hi = createHoneypotInjector();
      var trap = hi.createTrap({ sessionId: "s1", fieldName: 'test"<script>' });
      assert.ok(trap.html.indexOf('&quot;') !== -1);
      assert.ok(trap.html.indexOf('&lt;script&gt;') !== -1);
    });
  });

  describe("trap expiry", function () {
    it("should evict expired traps", function () {
      var hi = createHoneypotInjector({ trapTTLMs: 1 });
      var trap = hi.createTrap({ sessionId: "s1" });
      var start = Date.now();
      while (Date.now() - start < 5) {}
      hi.createTrap({ sessionId: "s2" });
      assert.strictEqual(hi.getTrap(trap.id), null);
    });
  });
});
