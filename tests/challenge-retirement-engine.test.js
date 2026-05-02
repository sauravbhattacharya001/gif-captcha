"use strict";

var assert = require("assert");
var ChallengeRetirementEngine = require("../src/challenge-retirement-engine");
var TIERS = ChallengeRetirementEngine.TIERS;

var passed = 0;
var failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log("  \u2713 " + name);
  } catch (e) {
    failed++;
    console.log("  \u2717 " + name);
    console.log("    " + e.message);
  }
}

console.log("\nChallengeRetirementEngine Tests\n");

// ── Basic Construction ──────────────────────────────────────────────

test("creates engine with default options", function () {
  var engine = new ChallengeRetirementEngine();
  var result = engine.analyze();
  assert.strictEqual(result.totalTracked, 0);
  assert.strictEqual(result.fleetHealth, 0);
});

test("creates engine with custom options", function () {
  var engine = new ChallengeRetirementEngine({ solveRateThreshold: 0.5, minAttempts: 5 });
  assert.ok(engine);
});

// ── Recording Attempts ──────────────────────────────────────────────

test("records a single attempt", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true, timeMs: 1000, isBot: false });
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.id, "ch1");
  assert.strictEqual(status.totalAttempts, 1);
});

test("ignores invalid challengeId", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("", { solved: true });
  engine.recordAttempt(null, { solved: true });
  assert.strictEqual(engine.analyze().totalTracked, 0);
});

test("ignores invalid attempt object", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", null);
  engine.recordAttempt("ch1", "bad");
  assert.strictEqual(engine.getStatus("ch1"), null);
});

test("tracks bot vs human attempts separately", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true, isBot: true });
  engine.recordAttempt("ch1", { solved: false, isBot: false });
  engine.recordAttempt("ch1", { solved: true, isBot: false });
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.totalAttempts, 3);
  assert.strictEqual(status.botSolveRate, 1.0);
  assert.strictEqual(status.humanSolveRate, 0.5);
});

test("tracks solve times", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true, timeMs: 500 });
  engine.recordAttempt("ch1", { solved: true, timeMs: 1500 });
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.avgSolveTimeMs, 1000);
});

test("uses custom timestamp when provided", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true, timestamp: 1000000 });
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.lastAttemptAt, 1000000);
});

// ── Solve Rate Monitoring ───────────────────────────────────────────

test("high bot solve rate triggers warning tier", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 5, solveRateThreshold: 0.5 });
  var now = Date.now();
  for (var i = 0; i < 10; i++) {
    engine.recordAttempt("ch1", { solved: true, isBot: true, timestamp: now + i * 1000 });
  }
  var status = engine.getStatus("ch1");
  assert.ok(status.effectivenessScore < 70, "Score should be below 70, got " + status.effectivenessScore);
  assert.ok(status.tier === TIERS.WARNING || status.tier === TIERS.PROBATION || status.tier === TIERS.RETIRED);
});

test("low bot solve rate keeps challenge active", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 5 });
  var now = Date.now();
  for (var i = 0; i < 10; i++) {
    engine.recordAttempt("ch1", { solved: false, isBot: true, timestamp: now + i * 1000 });
  }
  for (var j = 0; j < 10; j++) {
    engine.recordAttempt("ch1", { solved: true, isBot: false, timestamp: now + 10000 + j * 1000 });
  }
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.tier, TIERS.ACTIVE);
});

// ── Time-to-Solve Anomaly Detection ────────────────────────────────

test("detects solve time speedup", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 5 });
  var now = Date.now();
  // Early: slow solves
  for (var i = 0; i < 15; i++) {
    engine.recordAttempt("ch1", { solved: true, timeMs: 5000, isBot: true, timestamp: now + i * 1000 });
  }
  // Later: much faster solves (bot learned)
  for (var j = 0; j < 15; j++) {
    engine.recordAttempt("ch1", { solved: true, timeMs: 500, isBot: true, timestamp: now + 20000 + j * 1000 });
  }
  var status = engine.getStatus("ch1");
  assert.ok(status.warnings.length > 0 || status.effectivenessScore < 70);
});

// ── Burst Detection ─────────────────────────────────────────────────

test("detects burst attacks", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 5, burstThreshold: 5, burstWindowMs: 10000 });
  var now = Date.now();
  // Enough to pass minAttempts first
  for (var i = 0; i < 5; i++) {
    engine.recordAttempt("ch1", { solved: true, isBot: true, timestamp: now - 100000 + i * 1000 });
  }
  // Now a burst
  for (var j = 0; j < 15; j++) {
    engine.recordAttempt("ch1", { solved: true, isBot: true, timestamp: now + j * 100 });
  }
  var status = engine.getStatus("ch1");
  var hasBurstWarning = false;
  for (var k = 0; k < status.warnings.length; k++) {
    if (status.warnings[k].indexOf("Burst") >= 0 || status.warnings[k].indexOf("burst") >= 0) {
      hasBurstWarning = true;
      break;
    }
  }
  assert.ok(hasBurstWarning || status.effectivenessScore < 80, "Should detect burst");
});

test("no burst below threshold", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 3, burstThreshold: 10, burstWindowMs: 60000 });
  var now = Date.now();
  for (var i = 0; i < 5; i++) {
    engine.recordAttempt("ch1", { solved: false, isBot: true, timestamp: now + i * 15000 });
  }
  var status = engine.getStatus("ch1");
  var hasBurstWarning = false;
  for (var k = 0; k < (status.warnings || []).length; k++) {
    if (status.warnings[k].indexOf("Burst") >= 0 || status.warnings[k].indexOf("burst") >= 0) {
      hasBurstWarning = true;
    }
  }
  assert.ok(!hasBurstWarning);
});

// ── Effectiveness Decay ─────────────────────────────────────────────

test("effectiveness decays over time", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 5, timeDecayHalfLifeMs: 1000 });
  var now = Date.now();
  // Challenge created long ago
  for (var i = 0; i < 10; i++) {
    engine.recordAttempt("ch1", { solved: false, isBot: true, timestamp: now - 5000 + i });
  }
  var status = engine.getStatus("ch1");
  // Decay should reduce score
  assert.ok(status.effectivenessScore < 100, "Score should decay, got " + status.effectivenessScore);
});

// ── Tier Transitions ────────────────────────────────────────────────

test("challenge transitions through tiers", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 3, solveRateThreshold: 0.5 });
  var now = Date.now();
  // Start active
  for (var i = 0; i < 5; i++) {
    engine.recordAttempt("ch1", { solved: false, isBot: true, timestamp: now + i });
  }
  var s1 = engine.getStatus("ch1");
  assert.strictEqual(s1.tier, TIERS.ACTIVE);

  // Degrade with high bot solve rate
  for (var j = 0; j < 30; j++) {
    engine.recordAttempt("ch1", { solved: true, isBot: true, timestamp: now + 5000 + j });
  }
  var s2 = engine.getStatus("ch1");
  assert.ok(s2.tier !== TIERS.ACTIVE, "Should degrade from ACTIVE, got " + s2.tier);
});

test("below minAttempts stays at initial tier", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 20 });
  for (var i = 0; i < 5; i++) {
    engine.recordAttempt("ch1", { solved: true, isBot: true });
  }
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.tier, TIERS.ACTIVE);
});

// ── Manual Retirement ───────────────────────────────────────────────

test("manually retires a challenge", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true });
  assert.strictEqual(engine.retire("ch1", "compromised"), true);
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.tier, TIERS.RETIRED);
  assert.strictEqual(status.retiredReason, "compromised");
});

test("retire returns false for unknown challenge", function () {
  var engine = new ChallengeRetirementEngine();
  assert.strictEqual(engine.retire("unknown"), false);
});

test("retirement log tracks retirements", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true });
  engine.retire("ch1", "test");
  var log = engine.getRetirementLog();
  assert.strictEqual(log.length, 1);
  assert.strictEqual(log[0].id, "ch1");
  assert.strictEqual(log[0].reason, "test");
});

// ── Reinstatement ───────────────────────────────────────────────────

test("reinstates a retired challenge", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true });
  engine.retire("ch1");
  assert.strictEqual(engine.reinstate("ch1"), true);
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.tier, TIERS.PROBATION);
  assert.strictEqual(status.retiredAt, null);
});

test("reinstate returns false for non-retired challenge", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true });
  assert.strictEqual(engine.reinstate("ch1"), false);
});

test("reinstate returns false for unknown challenge", function () {
  var engine = new ChallengeRetirementEngine();
  assert.strictEqual(engine.reinstate("nope"), false);
});

// ── Fleet Health ────────────────────────────────────────────────────

test("fleet health is average of non-retired challenges", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 2 });
  var now = Date.now();
  // Two challenges, both good
  for (var i = 0; i < 5; i++) {
    engine.recordAttempt("ch1", { solved: false, isBot: true, timestamp: now + i });
    engine.recordAttempt("ch2", { solved: false, isBot: true, timestamp: now + i });
  }
  var result = engine.analyze();
  assert.ok(result.fleetHealth > 50);
});

test("fleet health excludes retired challenges", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true });
  engine.recordAttempt("ch2", { solved: true });
  engine.retire("ch1");
  var result = engine.analyze();
  // Only ch2 counted
  assert.strictEqual(result.tierCounts.RETIRED, 1);
});

// ── Insights Generation ─────────────────────────────────────────────

test("generates fleet health warning insight", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 3, solveRateThreshold: 0.3 });
  var now = Date.now();
  // Create degraded challenges
  for (var c = 0; c < 5; c++) {
    for (var i = 0; i < 10; i++) {
      engine.recordAttempt("ch" + c, { solved: true, isBot: true, timestamp: now + i });
    }
  }
  var result = engine.analyze();
  assert.ok(result.insights.length > 0, "Should have insights");
});

test("generates category correlation insight", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 3, solveRateThreshold: 0.5 });
  var now = Date.now();
  for (var c = 0; c < 4; c++) {
    for (var i = 0; i < 10; i++) {
      engine.recordAttempt("ch" + c, { solved: true, isBot: true, timestamp: now + i, category: "math" });
    }
  }
  var result = engine.analyze();
  var hasCategoryInsight = false;
  for (var k = 0; k < result.insights.length; k++) {
    if (result.insights[k].message.indexOf("category") >= 0 || result.insights[k].message.indexOf("math") >= 0) {
      hasCategoryInsight = true;
      break;
    }
  }
  assert.ok(hasCategoryInsight, "Should have category correlation insight, insights: " + JSON.stringify(result.insights) + ", tiers: " + JSON.stringify(result.tierCounts));
});

test("generates recommendation when few active challenges", function () {
  var engine = new ChallengeRetirementEngine();
  // Create 6 challenges and retire 4
  for (var c = 0; c < 6; c++) {
    engine.recordAttempt("ch" + c, { solved: true });
  }
  for (var r = 0; r < 4; r++) {
    engine.retire("ch" + r);
  }
  var result = engine.analyze();
  var hasRec = false;
  for (var k = 0; k < result.insights.length; k++) {
    if (result.insights[k].type === "RECOMMENDATION") {
      hasRec = true;
      break;
    }
  }
  assert.ok(hasRec, "Should recommend adding new challenges");
});

// ── Cross-Challenge Correlation ─────────────────────────────────────

test("detects correlated challenges in same category", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 3, solveRateThreshold: 0.3 });
  var now = Date.now();
  for (var c = 0; c < 3; c++) {
    for (var i = 0; i < 10; i++) {
      engine.recordAttempt("ch" + c, { solved: true, isBot: true, timestamp: now + i * 100, category: "visual" });
    }
  }
  engine.analyze(); // trigger recalculation
  var correlations = engine.detectCorrelations();
  assert.ok(correlations.length > 0, "Should detect correlations");
  assert.strictEqual(correlations[0].category, "visual");
});

// ── State Export/Import ─────────────────────────────────────────────

test("exports and imports state", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true, timeMs: 500, isBot: true });
  engine.recordAttempt("ch2", { solved: false, isBot: false });
  engine.retire("ch1", "test");

  var state = engine.exportState();
  var engine2 = new ChallengeRetirementEngine();
  assert.strictEqual(engine2.importState(state), true);

  var s1 = engine2.getStatus("ch1");
  assert.strictEqual(s1.tier, TIERS.RETIRED);
  assert.strictEqual(s1.retiredReason, "test");

  var s2 = engine2.getStatus("ch2");
  assert.strictEqual(s2.totalAttempts, 1);
});

test("importState rejects invalid state", function () {
  var engine = new ChallengeRetirementEngine();
  assert.strictEqual(engine.importState(null), false);
  assert.strictEqual(engine.importState({ version: 99 }), false);
});

test("export preserves retirement log", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true });
  engine.retire("ch1", "reason1");
  var state = engine.exportState();
  assert.strictEqual(state.retirementLog.length, 1);
});

// ── LRU Eviction ────────────────────────────────────────────────────

test("evicts oldest challenge when maxChallenges exceeded", function () {
  var engine = new ChallengeRetirementEngine({ maxChallenges: 3 });
  engine.recordAttempt("ch1", { solved: true, timestamp: 1000 });
  engine.recordAttempt("ch2", { solved: true, timestamp: 2000 });
  engine.recordAttempt("ch3", { solved: true, timestamp: 3000 });
  engine.recordAttempt("ch4", { solved: true, timestamp: 4000 });
  // ch1 should be evicted
  assert.strictEqual(engine.getStatus("ch1"), null);
  assert.ok(engine.getStatus("ch4") !== null);
});

test("touching an existing challenge prevents eviction", function () {
  var engine = new ChallengeRetirementEngine({ maxChallenges: 3 });
  engine.recordAttempt("ch1", { solved: true, timestamp: 1000 });
  engine.recordAttempt("ch2", { solved: true, timestamp: 2000 });
  engine.recordAttempt("ch3", { solved: true, timestamp: 3000 });
  // Touch ch1 to make it recent
  engine.recordAttempt("ch1", { solved: true, timestamp: 4000 });
  // Now add ch4 - ch2 should be evicted (oldest untouched)
  engine.recordAttempt("ch4", { solved: true, timestamp: 5000 });
  assert.ok(engine.getStatus("ch1") !== null);
  assert.strictEqual(engine.getStatus("ch2"), null);
});

// ── Edge Cases ──────────────────────────────────────────────────────

test("getStatus returns null for unknown challenge", function () {
  var engine = new ChallengeRetirementEngine();
  assert.strictEqual(engine.getStatus("nonexistent"), null);
});

test("analyze on empty engine returns valid structure", function () {
  var engine = new ChallengeRetirementEngine();
  var result = engine.analyze();
  assert.strictEqual(result.totalTracked, 0);
  assert.strictEqual(result.fleetHealth, 0);
  assert.deepStrictEqual(result.challenges, []);
  assert.deepStrictEqual(result.retirementQueue, []);
});

test("single attempt does not trigger evaluation", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 20 });
  engine.recordAttempt("ch1", { solved: true, isBot: true });
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.tier, TIERS.ACTIVE);
  assert.strictEqual(status.effectivenessScore, 100);
});

test("category is tracked", function () {
  var engine = new ChallengeRetirementEngine();
  engine.recordAttempt("ch1", { solved: true, category: "math" });
  var status = engine.getStatus("ch1");
  assert.strictEqual(status.category, "math");
});

test("many attempts on same challenge works", function () {
  var engine = new ChallengeRetirementEngine({ minAttempts: 5 });
  var now = Date.now();
  for (var i = 0; i < 200; i++) {
    engine.recordAttempt("ch1", { solved: i % 3 === 0, isBot: true, timeMs: 1000 + i, timestamp: now + i * 100 });
  }
  var status = engine.getStatus("ch1");
  assert.ok(status.totalAttempts === 200);
  assert.ok(status.effectivenessScore >= 0 && status.effectivenessScore <= 100);
});

// ── Summary ─────────────────────────────────────────────────────────

console.log("\n" + passed + " passed, " + failed + " failed\n");
if (failed > 0) process.exit(1);
