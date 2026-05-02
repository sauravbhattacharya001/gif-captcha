"use strict";

var assert = require("assert");
var ChallengeEcosystemHealthEngine = require("../src/challenge-ecosystem-health");
var HEALTH_TIERS = ChallengeEcosystemHealthEngine.HEALTH_TIERS;
var EXTINCTION_RISK = ChallengeEcosystemHealthEngine.EXTINCTION_RISK;
var NICHE_STATUS = ChallengeEcosystemHealthEngine.NICHE_STATUS;

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

console.log("\nChallengeEcosystemHealthEngine Tests\n");

// ── Construction ────────────────────────────────────────────────────

test("creates engine with default options", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  var result = engine.analyze();
  assert.strictEqual(result.totalActive, 0);
  assert.strictEqual(result.totalRetired, 0);
  assert.strictEqual(result.healthScore, 0);
});

test("creates engine with custom options", function () {
  var engine = new ChallengeEcosystemHealthEngine({ maxChallenges: 50, difficultyBands: 3 });
  assert.ok(engine);
});

// ── Registration ────────────────────────────────────────────────────

test("registers a challenge", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  var r = engine.analyze();
  assert.strictEqual(r.totalActive, 1);
  assert.strictEqual(r.totalRegistered, 1);
});

test("throws on invalid registration", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  assert.throws(function () { engine.register("c1", {}); }, /requires/);
  assert.throws(function () { engine.register(null, { category: "x", difficulty: 0.5 }); }, /requires/);
});

test("updates metadata on re-register", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.register("c1", { category: "temporal", difficulty: 0.8 });
  var r = engine.analyze();
  assert.strictEqual(r.totalActive, 1);
  assert.strictEqual(r.biodiversity.categoryDistribution.temporal.count, 1);
});

test("enforces max challenge limit via LRU eviction", function () {
  var engine = new ChallengeEcosystemHealthEngine({ maxChallenges: 3 });
  engine.register("c1", { category: "a", difficulty: 0.1 });
  engine.register("c2", { category: "b", difficulty: 0.3 });
  engine.register("c3", { category: "c", difficulty: 0.5 });
  engine.register("c4", { category: "d", difficulty: 0.7 });
  var r = engine.analyze();
  assert.strictEqual(r.totalActive, 3);
});

test("clamps difficulty to [0,1]", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "x", difficulty: -0.5 });
  engine.register("c2", { category: "x", difficulty: 1.5 });
  var r = engine.analyze();
  assert.strictEqual(r.totalActive, 2);
});

// ── Event Recording ─────────────────────────────────────────────────

test("records human solve event", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.recordEvent("c1", { isBot: false, solved: true, solveTimeMs: 5000 });
  var r = engine.analyze();
  assert.strictEqual(r.totalEvents, 1);
  assert.ok(r.predatorPrey.humanEngagement > 0);
});

test("records bot solve event", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.recordEvent("c1", { isBot: true, solved: true, solveTimeMs: 100 });
  var r = engine.analyze();
  assert.ok(r.predatorPrey.botPressure > 0);
});

test("ignores events for unregistered challenges", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.recordEvent("nonexistent", { isBot: false, solved: true });
  var r = engine.analyze();
  assert.strictEqual(r.totalEvents, 0);
});

test("tracks solve times", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.recordEvent("c1", { isBot: false, solved: true, solveTimeMs: 3000 });
  engine.recordEvent("c1", { isBot: false, solved: true, solveTimeMs: 4000 });
  engine.recordEvent("c1", { isBot: false, solved: true, solveTimeMs: 2000 });
  assert.strictEqual(engine.analyze().totalEvents, 3);
});

// ── Retirement ──────────────────────────────────────────────────────

test("retires a challenge", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.register("c2", { category: "visual", difficulty: 0.7 });
  engine.retire("c1");
  var r = engine.analyze();
  assert.strictEqual(r.totalActive, 1);
  assert.strictEqual(r.totalRetired, 1);
});

// ── Biodiversity ────────────────────────────────────────────────────

test("computes Shannon diversity for multiple categories", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.3 });
  engine.register("c2", { category: "temporal", difficulty: 0.5 });
  engine.register("c3", { category: "spatial", difficulty: 0.7 });
  engine.register("c4", { category: "logic", difficulty: 0.9 });
  var r = engine.analyze();
  assert.ok(r.biodiversity.shannonIndex > 0);
  assert.strictEqual(r.biodiversity.richness, 4);
  assert.ok(r.biodiversity.evenness > 0.9); // perfectly even distribution
});

test("detects category dominance", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  for (var i = 0; i < 10; i++) engine.register("v" + i, { category: "visual", difficulty: 0.5 });
  engine.register("t1", { category: "temporal", difficulty: 0.5 });
  var r = engine.analyze();
  assert.strictEqual(r.biodiversity.dominantCategory, "visual");
  assert.ok(r.biodiversity.evenness < 0.7);
});

test("single category has evenness 1", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.register("c2", { category: "visual", difficulty: 0.7 });
  var r = engine.analyze();
  assert.strictEqual(r.biodiversity.evenness, 1);
  assert.strictEqual(r.biodiversity.richness, 1);
});

// ── Predator-Prey ───────────────────────────────────────────────────

test("classifies peaceful phase with no bots", function () {
  var engine = new ChallengeEcosystemHealthEngine({ minSamplesForAnalysis: 2 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  for (var i = 0; i < 10; i++) {
    engine.recordEvent("c1", { isBot: false, solved: true, solveTimeMs: 3000 });
  }
  var r = engine.analyze();
  assert.strictEqual(r.predatorPrey.phase, "peaceful");
  assert.strictEqual(r.predatorPrey.botPressure, 0);
});

test("classifies predator-dominance when bots win", function () {
  var engine = new ChallengeEcosystemHealthEngine({ minSamplesForAnalysis: 2 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  for (var i = 0; i < 20; i++) {
    engine.recordEvent("c1", { isBot: true, solved: true, solveTimeMs: 50 });
  }
  for (var j = 0; j < 5; j++) {
    engine.recordEvent("c1", { isBot: false, solved: true, solveTimeMs: 3000 });
  }
  var r = engine.analyze();
  assert.strictEqual(r.predatorPrey.phase, "predator-dominance");
});

test("computes defense effectiveness", function () {
  var engine = new ChallengeEcosystemHealthEngine({ minSamplesForAnalysis: 1 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  // Bots fail most attempts
  for (var i = 0; i < 10; i++) engine.recordEvent("c1", { isBot: true, solved: false });
  for (var j = 0; j < 2; j++) engine.recordEvent("c1", { isBot: true, solved: true });
  engine.recordEvent("c1", { isBot: false, solved: true });
  var r = engine.analyze();
  assert.ok(r.predatorPrey.defenseEffectiveness > 0.7);
});

test("dormant phase with insufficient data", function () {
  var engine = new ChallengeEcosystemHealthEngine({ minSamplesForAnalysis: 100 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.recordEvent("c1", { isBot: false, solved: true });
  var r = engine.analyze();
  assert.strictEqual(r.predatorPrey.phase, "dormant");
});

// ── Carrying Capacity ───────────────────────────────────────────────

test("reports underpopulated when few challenges", function () {
  var engine = new ChallengeEcosystemHealthEngine({ carryingCapacityBase: 100 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  var r = engine.analyze();
  assert.strictEqual(r.carryingCapacity.status, "underpopulated");
  assert.ok(r.carryingCapacity.utilizationRatio < 0.3);
});

test("reports empty ecosystem has 0 utilization", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  var r = engine.analyze();
  assert.strictEqual(r.carryingCapacity.utilizationRatio, 0);
  assert.strictEqual(r.carryingCapacity.status, "empty");
});

// ── Extinction Risk ─────────────────────────────────────────────────

test("classifies safe categories", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  for (var i = 0; i < 10; i++) {
    engine.register("c" + i, { category: "visual", difficulty: i / 10 });
  }
  var r = engine.analyze();
  assert.strictEqual(r.extinctionRisk.categories[0].risk, EXTINCTION_RISK.SAFE);
});

test("detects critically endangered category", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "temporal", difficulty: 0.5 });
  // Heavy bot solving
  for (var i = 0; i < 10; i++) engine.recordEvent("c1", { isBot: true, solved: true });
  var r = engine.analyze();
  var temporal = r.extinctionRisk.categories.filter(function (c) { return c.category === "temporal"; })[0];
  assert.ok(temporal.risk === EXTINCTION_RISK.CRITICAL || temporal.risk === EXTINCTION_RISK.ENDANGERED);
});

test("detects extinct category (all retired)", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "legacy", difficulty: 0.5 });
  engine.retire("c1");
  var r = engine.analyze();
  var legacy = r.extinctionRisk.categories.filter(function (c) { return c.category === "legacy"; })[0];
  assert.strictEqual(legacy.risk, EXTINCTION_RISK.EXTINCT);
});

// ── Evolution Pressure ──────────────────────────────────────────────

test("no pressure with no bots", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  for (var i = 0; i < 5; i++) engine.recordEvent("c1", { isBot: false, solved: true, solveTimeMs: 3000 });
  var r = engine.analyze();
  assert.strictEqual(r.evolutionPressure.adaptationSpeed, "none");
});

test("high pressure with successful bots", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  for (var i = 0; i < 20; i++) engine.recordEvent("c1", { isBot: true, solved: true, solveTimeMs: 100 - i });
  var r = engine.analyze();
  assert.ok(r.evolutionPressure.pressure > 0);
  assert.ok(r.evolutionPressure.botLearningRate > 0);
});

test("empty ecosystem has no evolution pressure", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  var r = engine.analyze();
  assert.strictEqual(r.evolutionPressure.pressure, 0);
  assert.strictEqual(r.evolutionPressure.adaptationSpeed, "none");
});

// ── Niche Analysis ──────────────────────────────────────────────────

test("identifies barren niches", function () {
  var engine = new ChallengeEcosystemHealthEngine({ difficultyBands: 5 });
  // Only easy challenges
  engine.register("c1", { category: "visual", difficulty: 0.1 });
  engine.register("c2", { category: "visual", difficulty: 0.15 });
  var r = engine.analyze();
  var barren = r.niches.bands.filter(function (b) { return b.status === NICHE_STATUS.BARREN; });
  assert.ok(barren.length >= 3); // Most bands should be empty
});

test("balanced niches with even distribution", function () {
  var engine = new ChallengeEcosystemHealthEngine({ difficultyBands: 5 });
  for (var i = 0; i < 25; i++) {
    engine.register("c" + i, { category: "visual", difficulty: (i % 5) * 0.2 + 0.1 });
  }
  var r = engine.analyze();
  assert.ok(r.niches.balance > 0.8);
  assert.strictEqual(r.niches.gapCount, 0);
});

test("reports correct band labels", function () {
  var engine = new ChallengeEcosystemHealthEngine({ difficultyBands: 5 });
  engine.register("c1", { category: "visual", difficulty: 0.1 });
  var r = engine.analyze();
  assert.strictEqual(r.niches.bands[0].label, "Trivial");
  assert.strictEqual(r.niches.bands[4].label, "Expert");
});

test("empty ecosystem all bands barren", function () {
  var engine = new ChallengeEcosystemHealthEngine({ difficultyBands: 3 });
  var r = engine.analyze();
  assert.strictEqual(r.niches.gapCount, 3);
});

// ── Keystone Identification ─────────────────────────────────────────

test("identifies keystone challenge", function () {
  var engine = new ChallengeEcosystemHealthEngine({ keystoneThreshold: 0.2 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.register("c2", { category: "temporal", difficulty: 0.7 });
  // c1 gets most traffic
  for (var i = 0; i < 50; i++) engine.recordEvent("c1", { isBot: false, solved: true });
  for (var j = 0; j < 5; j++) engine.recordEvent("c2", { isBot: false, solved: true });
  var r = engine.analyze();
  assert.ok(r.keystones.count > 0);
  assert.strictEqual(r.keystones.keystones[0].id, "c1");
});

test("no keystones when traffic is even", function () {
  var engine = new ChallengeEcosystemHealthEngine({ keystoneThreshold: 0.25 });
  for (var i = 0; i < 10; i++) {
    engine.register("c" + i, { category: "visual", difficulty: 0.5 });
    for (var j = 0; j < 10; j++) engine.recordEvent("c" + i, { isBot: false, solved: true });
  }
  var r = engine.analyze();
  assert.strictEqual(r.keystones.count, 0);
});

// ── Health Score ─────────────────────────────────────────────────────

test("healthy ecosystem gets high score", function () {
  var engine = new ChallengeEcosystemHealthEngine({ difficultyBands: 5, minSamplesForAnalysis: 1, carryingCapacityBase: 20 });
  var cats = ["visual", "temporal", "spatial", "logic"];
  for (var i = 0; i < 20; i++) {
    engine.register("c" + i, { category: cats[i % 4], difficulty: (i % 5) * 0.2 + 0.1 });
    for (var j = 0; j < 5; j++) {
      engine.recordEvent("c" + i, { isBot: false, solved: true, solveTimeMs: 3000 });
    }
    // Some bot failures
    engine.recordEvent("c" + i, { isBot: true, solved: false });
  }
  var r = engine.analyze();
  assert.ok(r.healthScore >= 60, "Expected healthy score >= 60, got " + r.healthScore);
  assert.ok(r.tier === HEALTH_TIERS.THRIVING || r.tier === HEALTH_TIERS.HEALTHY);
});

test("unhealthy ecosystem gets low score", function () {
  var engine = new ChallengeEcosystemHealthEngine({ difficultyBands: 5, minSamplesForAnalysis: 1, carryingCapacityBase: 100 });
  // Only 1 category, bots cracking everything
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  for (var i = 0; i < 20; i++) engine.recordEvent("c1", { isBot: true, solved: true });
  var r = engine.analyze();
  assert.ok(r.healthScore < 50);
});

test("tier classification boundaries", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  assert.strictEqual(engine._classifyTier(85), HEALTH_TIERS.THRIVING);
  assert.strictEqual(engine._classifyTier(65), HEALTH_TIERS.HEALTHY);
  assert.strictEqual(engine._classifyTier(45), HEALTH_TIERS.STRESSED);
  assert.strictEqual(engine._classifyTier(25), HEALTH_TIERS.ENDANGERED);
  assert.strictEqual(engine._classifyTier(10), HEALTH_TIERS.CRITICAL);
});

// ── Insights ────────────────────────────────────────────────────────

test("generates biodiversity warning for imbalanced pool", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  for (var i = 0; i < 20; i++) engine.register("v" + i, { category: "visual", difficulty: 0.5 });
  engine.register("t1", { category: "temporal", difficulty: 0.5 });
  var r = engine.analyze();
  var bioInsights = r.insights.filter(function (ins) { return ins.category === "biodiversity"; });
  assert.ok(bioInsights.length > 0);
});

test("generates predator-dominance critical insight", function () {
  var engine = new ChallengeEcosystemHealthEngine({ minSamplesForAnalysis: 1 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  for (var i = 0; i < 30; i++) engine.recordEvent("c1", { isBot: true, solved: true });
  for (var j = 0; j < 5; j++) engine.recordEvent("c1", { isBot: false, solved: true });
  var r = engine.analyze();
  var ppInsights = r.insights.filter(function (ins) { return ins.category === "predator-prey"; });
  assert.ok(ppInsights.length > 0);
  assert.strictEqual(ppInsights[0].type, "critical");
});

test("generates extinction critical insight", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "rare", difficulty: 0.5 });
  for (var i = 0; i < 10; i++) engine.recordEvent("c1", { isBot: true, solved: true });
  var r = engine.analyze();
  var extInsights = r.insights.filter(function (ins) { return ins.category === "extinction"; });
  assert.ok(extInsights.length > 0);
});

test("insights sorted by priority", function () {
  var engine = new ChallengeEcosystemHealthEngine({ minSamplesForAnalysis: 1 });
  for (var i = 0; i < 20; i++) engine.register("v" + i, { category: "visual", difficulty: 0.5 });
  engine.register("t1", { category: "temporal", difficulty: 0.5 });
  // Bots cracking temporal
  for (var j = 0; j < 20; j++) engine.recordEvent("t1", { isBot: true, solved: true });
  var r = engine.analyze();
  if (r.insights.length >= 2) {
    var priorities = { critical: 0, high: 1, medium: 2, low: 3 };
    assert.ok(priorities[r.insights[0].priority] <= priorities[r.insights[1].priority]);
  }
});

// ── State Export/Import ─────────────────────────────────────────────

test("exports and imports state correctly", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5, tags: ["gif"] });
  engine.recordEvent("c1", { isBot: false, solved: true, solveTimeMs: 3000 });
  engine.retire("c1");

  var state = engine.exportState();
  assert.strictEqual(state.version, 1);
  assert.ok(state.challenges.c1);

  var engine2 = new ChallengeEcosystemHealthEngine();
  engine2.importState(state);
  var r = engine2.analyze();
  assert.strictEqual(r.totalRetired, 1);
  assert.strictEqual(r.totalEvents, 1);
});

test("rejects invalid state version", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  assert.throws(function () { engine.importState({ version: 99 }); }, /Invalid/);
  assert.throws(function () { engine.importState(null); }, /Invalid/);
});

test("round-trips state preserving data", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  for (var i = 0; i < 10; i++) engine.recordEvent("c1", { isBot: false, solved: true, solveTimeMs: 2000 + i * 100 });

  var original = engine.analyze();
  var state = engine.exportState();
  var engine2 = new ChallengeEcosystemHealthEngine();
  engine2.importState(state);
  var restored = engine2.analyze();

  assert.strictEqual(original.totalActive, restored.totalActive);
  assert.strictEqual(original.totalEvents, restored.totalEvents);
});

// ── Snapshots / History ─────────────────────────────────────────────

test("takes snapshots based on interval", function () {
  var engine = new ChallengeEcosystemHealthEngine({ snapshotIntervalMs: 100 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.recordEvent("c1", { isBot: false, solved: true, timestamp: 1000 });
  engine.recordEvent("c1", { isBot: false, solved: true, timestamp: 1200 });
  var history = engine.getHistory();
  assert.ok(history.length > 0);
});

test("limits snapshot count", function () {
  var engine = new ChallengeEcosystemHealthEngine({ snapshotIntervalMs: 1, maxSnapshots: 3 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  for (var i = 0; i < 10; i++) {
    engine.recordEvent("c1", { isBot: false, solved: true, timestamp: i * 10 });
  }
  assert.ok(engine.getHistory().length <= 3);
});

test("history returns a copy", function () {
  var engine = new ChallengeEcosystemHealthEngine({ snapshotIntervalMs: 1 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.recordEvent("c1", { isBot: false, solved: true, timestamp: 100 });
  engine.recordEvent("c1", { isBot: false, solved: true, timestamp: 200 });
  var h1 = engine.getHistory();
  var h2 = engine.getHistory();
  assert.notStrictEqual(h1, h2);
});

// ── HTML Dashboard ──────────────────────────────────────────────────

test("renders HTML dashboard with data", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  engine.register("c2", { category: "temporal", difficulty: 0.7 });
  engine.recordEvent("c1", { isBot: false, solved: true });
  var html = engine.renderDashboard();
  assert.ok(html.indexOf("<!DOCTYPE html>") === 0);
  assert.ok(html.indexOf("Ecosystem Health") > -1);
  assert.ok(html.indexOf("Biodiversity") > -1);
  assert.ok(html.indexOf("Predator-Prey") > -1);
});

test("renders HTML dashboard for empty ecosystem", function () {
  var engine = new ChallengeEcosystemHealthEngine();
  var html = engine.renderDashboard();
  assert.ok(html.indexOf("<!DOCTYPE html>") === 0);
});

// ── Constants ───────────────────────────────────────────────────────

test("exports HEALTH_TIERS", function () {
  assert.strictEqual(HEALTH_TIERS.THRIVING, "THRIVING");
  assert.strictEqual(HEALTH_TIERS.CRITICAL, "CRITICAL");
});

test("exports EXTINCTION_RISK", function () {
  assert.strictEqual(EXTINCTION_RISK.SAFE, "SAFE");
  assert.strictEqual(EXTINCTION_RISK.EXTINCT, "EXTINCT");
});

test("exports NICHE_STATUS", function () {
  assert.strictEqual(NICHE_STATUS.BARREN, "BARREN");
  assert.strictEqual(NICHE_STATUS.BALANCED, "BALANCED");
});

// ── Edge Cases ──────────────────────────────────────────────────────

test("handles large number of challenges", function () {
  var engine = new ChallengeEcosystemHealthEngine({ maxChallenges: 200 });
  var cats = ["visual", "temporal", "spatial", "logic", "pattern"];
  for (var i = 0; i < 100; i++) {
    engine.register("c" + i, { category: cats[i % 5], difficulty: Math.random() });
  }
  var r = engine.analyze();
  assert.strictEqual(r.totalActive, 100);
  assert.ok(r.healthScore >= 0 && r.healthScore <= 100);
});

test("predator-prey with mixed bot success/failure", function () {
  var engine = new ChallengeEcosystemHealthEngine({ minSamplesForAnalysis: 1 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  for (var i = 0; i < 10; i++) {
    engine.recordEvent("c1", { isBot: true, solved: i < 3 }); // 30% success
    engine.recordEvent("c1", { isBot: false, solved: true });
  }
  var r = engine.analyze();
  assert.ok(r.predatorPrey.botPressure > 0.3);
  assert.ok(r.predatorPrey.defenseEffectiveness > 0.5);
});

test("niche analysis with 3 custom bands", function () {
  var engine = new ChallengeEcosystemHealthEngine({ difficultyBands: 3 });
  engine.register("c1", { category: "visual", difficulty: 0.1 });
  engine.register("c2", { category: "visual", difficulty: 0.5 });
  engine.register("c3", { category: "visual", difficulty: 0.9 });
  var r = engine.analyze();
  assert.strictEqual(r.niches.bands.length, 3);
  assert.strictEqual(r.niches.gapCount, 0);
});

test("equilibrium detection", function () {
  var engine = new ChallengeEcosystemHealthEngine({ minSamplesForAnalysis: 1 });
  engine.register("c1", { category: "visual", difficulty: 0.5 });
  // Balanced bot/human mix with moderate defense
  for (var i = 0; i < 30; i++) engine.recordEvent("c1", { isBot: false, solved: true });
  for (var j = 0; j < 10; j++) engine.recordEvent("c1", { isBot: true, solved: j < 4 });
  var r = engine.analyze();
  assert.strictEqual(typeof r.predatorPrey.equilibrium, "boolean");
});

// ── Summary ─────────────────────────────────────────────────────────

console.log("\n" + passed + " passed, " + failed + " failed\n");
if (failed > 0) process.exit(1);
