"use strict";

var test = require("node:test");
var assert = require("node:assert/strict");

var mod = require("../src/challenge-autopilot");
var createChallengeAutopilot = mod.createChallengeAutopilot;

test("ChallengeAutopilot", async function (t) {

  // ── Creation ──────────────────────────────────────────────────

  await t.test("creates with default options", function () {
    var ap = createChallengeAutopilot();
    assert.ok(ap);
    assert.equal(typeof ap.recordOutcome, "function");
    assert.equal(typeof ap.evaluate, "function");
    assert.equal(typeof ap.selectChallenge, "function");
    assert.equal(typeof ap.selfReport, "function");
    assert.equal(typeof ap.situationReport, "function");
  });

  await t.test("creates with custom options", function () {
    var ap = createChallengeAutopilot({
      targetSolveRate: { min: 0.4, max: 0.8 },
      botSolveRateThreshold: 0.3,
      minObservations: 10,
      cooldownMs: 0,
      autoAct: true
    });
    var cfg = ap.getConfig();
    assert.equal(cfg.targetSolveRateMin, 0.4);
    assert.equal(cfg.targetSolveRateMax, 0.8);
    assert.equal(cfg.botSolveRateThreshold, 0.3);
    assert.equal(cfg.minObservations, 10);
    assert.equal(cfg.autoAct, true);
  });

  // ── Outcome Recording ─────────────────────────────────────────

  await t.test("records outcomes and tracks stats", function () {
    var ap = createChallengeAutopilot();
    ap.recordOutcome("c1", { solved: true, isBot: false, timeMs: 3000, trustScore: 0.8 });
    ap.recordOutcome("c1", { solved: false, isBot: false, timeMs: 5000, trustScore: 0.7 });
    ap.recordOutcome("c1", { solved: true, isBot: true, timeMs: 1000 });

    var stats = ap.getChallengeStats("c1");
    assert.equal(stats.totalHuman, 2);
    assert.equal(stats.totalBot, 1);
    assert.equal(stats.humanSolves, 1);
    assert.equal(stats.botSolves, 1);
    assert.equal(stats.humanSolveRate, 0.5);
    assert.equal(stats.botSolveRate, 1.0);
    assert.ok(stats.avgSolveTimeMs > 0);
    assert.ok(stats.avgTrustScore > 0);
  });

  await t.test("throws on invalid challengeId", function () {
    var ap = createChallengeAutopilot();
    assert.throws(function () { ap.recordOutcome("", { solved: true }); });
    assert.throws(function () { ap.recordOutcome(null, { solved: true }); });
    assert.throws(function () { ap.recordOutcome(42, { solved: true }); });
  });

  await t.test("throws on invalid outcome", function () {
    var ap = createChallengeAutopilot();
    assert.throws(function () { ap.recordOutcome("c1", null); });
    assert.throws(function () { ap.recordOutcome("c1", "bad"); });
  });

  // ── Register Challenge ────────────────────────────────────────

  await t.test("registerChallenge creates entry", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    var stats = ap.getChallengeStats("c1");
    assert.equal(stats.id, "c1");
    assert.equal(stats.status, "active");
    assert.equal(stats.totalHuman, 0);
  });

  await t.test("registerChallenge throws on empty id", function () {
    var ap = createChallengeAutopilot();
    assert.throws(function () { ap.registerChallenge(""); });
  });

  // ── Evaluate: Quarantine Compromised ──────────────────────────

  await t.test("quarantines challenge with high bot solve rate", function () {
    var ap = createChallengeAutopilot({
      minObservations: 5,
      cooldownMs: 0,
      botSolveRateThreshold: 0.4
    });
    // 15 human attempts, 10 bot attempts with 5 solves (50% bot rate)
    for (var i = 0; i < 15; i++) {
      ap.recordOutcome("c1", { solved: true, isBot: false });
    }
    for (var j = 0; j < 10; j++) {
      ap.recordOutcome("c1", { solved: j < 5, isBot: true });
    }

    var decisions = ap.evaluate();
    assert.ok(decisions.length >= 1);
    var d = decisions.find(function (x) { return x.challengeId === "c1"; });
    assert.ok(d);
    assert.equal(d.action, "quarantine");
    assert.ok(d.confidence > 0);
    assert.ok(d.reason.indexOf("Bot solve rate") >= 0);
  });

  // ── Evaluate: Retire from Quarantine ──────────────────────────

  await t.test("retires quarantined challenge still compromised", function () {
    var ap = createChallengeAutopilot({
      minObservations: 5,
      cooldownMs: 0,
      botSolveRateThreshold: 0.4,
      autoAct: true
    });
    // First quarantine it
    for (var i = 0; i < 10; i++) {
      ap.recordOutcome("c1", { solved: true, isBot: false });
    }
    for (var j = 0; j < 8; j++) {
      ap.recordOutcome("c1", { solved: j < 5, isBot: true });
    }
    ap.evaluate(); // should quarantine
    assert.equal(ap.getChallengeStats("c1").status, "quarantined");

    // Add more bad bot data
    for (var k = 0; k < 5; k++) {
      ap.recordOutcome("c1", { solved: true, isBot: true });
    }
    var decisions = ap.evaluate();
    var d = decisions.find(function (x) { return x.challengeId === "c1"; });
    assert.ok(d);
    assert.equal(d.action, "retire");
  });

  // ── Evaluate: Promote Recovered ───────────────────────────────

  await t.test("promotes quarantined challenge that recovered", function () {
    var ap = createChallengeAutopilot({
      minObservations: 5,
      cooldownMs: 0,
      botSolveRateThreshold: 0.4,
      autoAct: true
    });
    ap.registerChallenge("c1");
    ap.setStatus("c1", "quarantined");

    // Add data showing recovery (low bot rate)
    for (var i = 0; i < 15; i++) {
      ap.recordOutcome("c1", { solved: true, isBot: false });
    }
    for (var j = 0; j < 10; j++) {
      ap.recordOutcome("c1", { solved: j < 1, isBot: true }); // 10% bot rate
    }

    var decisions = ap.evaluate();
    var d = decisions.find(function (x) { return x.challengeId === "c1"; });
    assert.ok(d);
    assert.equal(d.action, "promote");
  });

  // ── Evaluate: Boost Effective ─────────────────────────────────

  await t.test("boosts effective challenge with high human rate and low bot rate", function () {
    var ap = createChallengeAutopilot({
      minObservations: 5,
      cooldownMs: 0,
      targetSolveRate: { min: 0.55, max: 0.75 }
    });
    // High human solve rate (90%), very low bot rate
    for (var i = 0; i < 20; i++) {
      ap.recordOutcome("c1", { solved: i < 18, isBot: false });
    }
    for (var j = 0; j < 10; j++) {
      ap.recordOutcome("c1", { solved: false, isBot: true });
    }

    var decisions = ap.evaluate();
    var d = decisions.find(function (x) { return x.challengeId === "c1"; });
    assert.ok(d);
    assert.equal(d.action, "boost");
  });

  // ── Evaluate: Demote Too Hard ─────────────────────────────────

  await t.test("demotes challenge with low human solve rate", function () {
    var ap = createChallengeAutopilot({
      minObservations: 5,
      cooldownMs: 0,
      targetSolveRate: { min: 0.55, max: 0.75 }
    });
    // Low human solve rate (20%)
    for (var i = 0; i < 20; i++) {
      ap.recordOutcome("c1", { solved: i < 4, isBot: false });
    }

    var decisions = ap.evaluate();
    var d = decisions.find(function (x) { return x.challengeId === "c1"; });
    assert.ok(d);
    assert.equal(d.action, "demote");
  });

  // ── Evaluate: No Decisions on Insufficient Data ───────────────

  await t.test("no decisions with insufficient observations", function () {
    var ap = createChallengeAutopilot({ minObservations: 50, cooldownMs: 0 });
    for (var i = 0; i < 10; i++) {
      ap.recordOutcome("c1", { solved: true, isBot: true });
    }
    var decisions = ap.evaluate();
    assert.equal(decisions.length, 0);
  });

  // ── Evaluate: Skips Retired Challenges ────────────────────────

  await t.test("skips retired challenges in evaluate", function () {
    var ap = createChallengeAutopilot({ minObservations: 2, cooldownMs: 0 });
    ap.registerChallenge("c1");
    ap.setStatus("c1", "retired");
    for (var i = 0; i < 20; i++) {
      ap.recordOutcome("c1", { solved: true, isBot: true });
    }
    var decisions = ap.evaluate();
    var d = decisions.find(function (x) { return x.challengeId === "c1"; });
    assert.equal(d, undefined);
  });

  // ── applyDecision ─────────────────────────────────────────────

  await t.test("applyDecision manually changes status", function () {
    var ap = createChallengeAutopilot({ autoAct: false });
    ap.registerChallenge("c1");
    ap.applyDecision({ challengeId: "c1", action: "quarantine" });
    assert.equal(ap.getChallengeStats("c1").status, "quarantined");
    ap.applyDecision({ challengeId: "c1", action: "promote" });
    assert.equal(ap.getChallengeStats("c1").status, "active");
    ap.applyDecision({ challengeId: "c1", action: "retire" });
    assert.equal(ap.getChallengeStats("c1").status, "retired");
  });

  await t.test("applyDecision throws on invalid input", function () {
    var ap = createChallengeAutopilot();
    assert.throws(function () { ap.applyDecision(null); });
    assert.throws(function () { ap.applyDecision({}); });
  });

  await t.test("applyDecision boost increases weight", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    var before = ap.getChallengeStats("c1").weight;
    ap.applyDecision({ challengeId: "c1", action: "boost" });
    assert.ok(ap.getChallengeStats("c1").weight > before);
  });

  await t.test("applyDecision demote decreases weight", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    var before = ap.getChallengeStats("c1").weight;
    ap.applyDecision({ challengeId: "c1", action: "demote" });
    assert.ok(ap.getChallengeStats("c1").weight < before);
  });

  // ── selectChallenge ───────────────────────────────────────────

  await t.test("selectChallenge returns null when no challenges", function () {
    var ap = createChallengeAutopilot();
    assert.equal(ap.selectChallenge({}), null);
  });

  await t.test("selectChallenge returns an active challenge", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    ap.registerChallenge("c2");
    ap.registerChallenge("c3");
    var selected = ap.selectChallenge({});
    assert.ok(["c1", "c2", "c3"].indexOf(selected) >= 0);
  });

  await t.test("selectChallenge skips retired challenges", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    ap.registerChallenge("c2");
    ap.setStatus("c1", "retired");
    // Run many times to ensure retired never selected
    for (var i = 0; i < 50; i++) {
      assert.equal(ap.selectChallenge({}), "c2");
    }
  });

  await t.test("selectChallenge respects previousChallenges", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    ap.registerChallenge("c2");
    var selected = ap.selectChallenge({ previousChallenges: ["c1"] });
    assert.equal(selected, "c2");
  });

  await t.test("selectChallenge returns null when all excluded", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    assert.equal(ap.selectChallenge({ previousChallenges: ["c1"] }), null);
  });

  await t.test("selectChallenge with low trust prefers bot-resistant challenges", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("easy");
    ap.registerChallenge("hard");
    // "easy" has high bot solve rate
    for (var i = 0; i < 20; i++) {
      ap.recordOutcome("easy", { solved: true, isBot: true });
      ap.recordOutcome("hard", { solved: false, isBot: true });
    }
    // Low-trust selection should prefer "hard"
    var hardCount = 0;
    for (var j = 0; j < 100; j++) {
      if (ap.selectChallenge({ trustScore: 0.1 }) === "hard") hardCount++;
    }
    // "hard" should be selected much more often
    assert.ok(hardCount > 60, "hard selected " + hardCount + " times, expected >60");
  });

  // ── selfReport ────────────────────────────────────────────────

  await t.test("selfReport returns structure with no decisions", function () {
    var ap = createChallengeAutopilot();
    var report = ap.selfReport();
    assert.equal(report.totalDecisions, 0);
    assert.equal(report.recentDecisions, 0);
    assert.equal(report.accuracy, null);
    assert.ok(Array.isArray(report.recommendations));
  });

  await t.test("selfReport tracks decisions after evaluate", function () {
    var ap = createChallengeAutopilot({
      minObservations: 5,
      cooldownMs: 0,
      botSolveRateThreshold: 0.4
    });
    for (var i = 0; i < 20; i++) {
      ap.recordOutcome("c1", { solved: true, isBot: false });
    }
    for (var j = 0; j < 10; j++) {
      ap.recordOutcome("c1", { solved: j < 5, isBot: true });
    }
    ap.evaluate();
    var report = ap.selfReport();
    assert.ok(report.totalDecisions >= 1);
    assert.ok(report.recentDecisions >= 1);
  });

  // ── situationReport ───────────────────────────────────────────

  await t.test("situationReport returns fleet overview", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    ap.registerChallenge("c2");
    ap.registerChallenge("c3");
    ap.setStatus("c2", "quarantined");
    ap.setStatus("c3", "retired");

    var report = ap.situationReport();
    assert.equal(report.fleet.total, 3);
    assert.equal(report.fleet.active, 1);
    assert.equal(report.fleet.quarantined, 1);
    assert.equal(report.fleet.retired, 1);
    assert.ok(Array.isArray(report.topThreats));
    assert.ok(Array.isArray(report.recommendedActions));
    assert.ok(report.selfMonitoring);
  });

  await t.test("situationReport identifies top threats", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    for (var i = 0; i < 10; i++) {
      ap.recordOutcome("c1", { solved: true, isBot: true });
    }
    var report = ap.situationReport();
    assert.ok(report.topThreats.length >= 1);
    assert.equal(report.topThreats[0].challengeId, "c1");
  });

  // ── setStatus ─────────────────────────────────────────────────

  await t.test("setStatus validates status values", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    assert.throws(function () { ap.setStatus("c1", "invalid"); });
    assert.throws(function () { ap.setStatus("c1", ""); });
  });

  await t.test("setStatus transitions correctly", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    ap.setStatus("c1", "quarantined");
    assert.equal(ap.getChallengeStats("c1").status, "quarantined");
    ap.setStatus("c1", "active");
    assert.equal(ap.getChallengeStats("c1").status, "active");
  });

  // ── listChallenges ────────────────────────────────────────────

  await t.test("listChallenges returns all or filtered", function () {
    var ap = createChallengeAutopilot();
    ap.registerChallenge("c1");
    ap.registerChallenge("c2");
    ap.registerChallenge("c3");
    ap.setStatus("c2", "quarantined");

    assert.equal(ap.listChallenges().length, 3);
    assert.equal(ap.listChallenges("active").length, 2);
    assert.equal(ap.listChallenges("quarantined").length, 1);
    assert.equal(ap.listChallenges("retired").length, 0);
  });

  // ── getChallengeStats ─────────────────────────────────────────

  await t.test("getChallengeStats returns null for unknown", function () {
    var ap = createChallengeAutopilot();
    assert.equal(ap.getChallengeStats("unknown"), null);
  });

  // ── Quarantine Overflow ───────────────────────────────────────

  await t.test("quarantine overflow retires oldest", function () {
    var ap = createChallengeAutopilot({
      maxQuarantineSize: 3,
      minObservations: 2,
      cooldownMs: 0,
      autoAct: true
    });
    // Create 5 quarantined challenges
    for (var i = 0; i < 5; i++) {
      var id = "q" + i;
      ap.registerChallenge(id);
      ap.setStatus(id, "quarantined");
      // Add enough data for evaluation
      for (var j = 0; j < 5; j++) {
        ap.recordOutcome(id, { solved: false, isBot: false });
      }
    }

    var decisions = ap.evaluate();
    var retires = decisions.filter(function (d) { return d.action === "retire" && d.evidence && d.evidence.quarantineOverflow; });
    assert.ok(retires.length >= 2, "Expected at least 2 overflow retires, got " + retires.length);
  });

  // ── Edge: Single Challenge ────────────────────────────────────

  await t.test("works with single challenge", function () {
    var ap = createChallengeAutopilot({ minObservations: 3, cooldownMs: 0 });
    for (var i = 0; i < 10; i++) {
      ap.recordOutcome("only", { solved: true, isBot: false });
    }
    var selected = ap.selectChallenge({});
    assert.equal(selected, "only");
    var decisions = ap.evaluate();
    assert.ok(Array.isArray(decisions));
  });

});
