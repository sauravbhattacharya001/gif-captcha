/**
 * Tests for DefensePostureOptimizer
 */

"use strict";

var assert = require("assert");
var mod = require("../src/defense-posture-optimizer");
var DefensePostureOptimizer = mod.DefensePostureOptimizer;
var DIMENSIONS = mod.DIMENSIONS;
var KNOB_TYPES = mod.KNOB_TYPES;
var DRIFT_STATES = mod.DRIFT_STATES;

// ── Helpers ─────────────────────────────────────────────────────────

function makeMetrics(overrides) {
  var defaults = {
    catchRate: 0.8,
    humanFriction: 0.3,
    latencyCost: 500,
    challengeDiversity: 0.7,
    attackSurface: 0.75,
    fatigueRisk: 0.2
  };
  var m = {};
  for (var k in defaults) m[k] = defaults[k];
  if (overrides) for (var o in overrides) m[o] = overrides[o];
  return m;
}

function makeConfig(overrides) {
  var defaults = {
    DIFFICULTY: 0.5,
    RATE_LIMIT: 100,
    HONEYPOT_DENSITY: 0.3,
    RETRY_LIMIT: 3,
    PROOF_OF_WORK: 1.0,
    BEHAVIORAL_DEPTH: 0.5,
    DELAY_INJECTION: 300,
    MULTI_FACTOR: 0
  };
  var c = {};
  for (var k in defaults) c[k] = defaults[k];
  if (overrides) for (var o in overrides) c[o] = overrides[o];
  return c;
}

function seedOptimizer(opt, count, metricsFn) {
  opt.setConfig(makeConfig());
  for (var i = 0; i < count; i++) {
    var m = metricsFn ? metricsFn(i, count) : makeMetrics();
    opt.recordSnapshot(m);
  }
}

// ── Tests ───────────────────────────────────────────────────────────

var passed = 0;
var failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failed++;
    console.error("FAIL: " + name + " — " + e.message);
  }
}

// Constants
test("DIMENSIONS has 6 entries", function () {
  assert.strictEqual(DIMENSIONS.length, 6);
});

test("KNOB_TYPES has 8 entries", function () {
  assert.strictEqual(KNOB_TYPES.length, 8);
});

test("DRIFT_STATES has 4 entries", function () {
  assert.strictEqual(DRIFT_STATES.length, 4);
});

// Construction
test("constructor with defaults", function () {
  var opt = new DefensePostureOptimizer();
  assert.ok(opt);
});

test("constructor with options", function () {
  var opt = new DefensePostureOptimizer({ maxSnapshots: 100, driftThreshold: 0.1 });
  assert.ok(opt);
});

// setConfig
test("setConfig stores config", function () {
  var opt = new DefensePostureOptimizer();
  var cfg = opt.setConfig({ DIFFICULTY: 0.7, RATE_LIMIT: 50 });
  assert.strictEqual(cfg.DIFFICULTY, 0.7);
  assert.strictEqual(cfg.RATE_LIMIT, 50);
});

test("setConfig rejects non-object", function () {
  var opt = new DefensePostureOptimizer();
  assert.throws(function () { opt.setConfig(null); });
});

test("getConfig returns null initially", function () {
  var opt = new DefensePostureOptimizer();
  assert.strictEqual(opt.getConfig(), null);
});

test("getConfig returns copy", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig({ DIFFICULTY: 0.5 });
  var cfg = opt.getConfig();
  cfg.DIFFICULTY = 999;
  assert.strictEqual(opt.getConfig().DIFFICULTY, 0.5);
});

// recordSnapshot
test("recordSnapshot stores metrics", function () {
  var opt = new DefensePostureOptimizer();
  var snap = opt.recordSnapshot(makeMetrics());
  assert.ok(snap.id);
  assert.ok(snap.timestamp);
  assert.strictEqual(snap.metrics.catchRate, 0.8);
});

test("recordSnapshot clamps values", function () {
  var opt = new DefensePostureOptimizer();
  var snap = opt.recordSnapshot({ catchRate: 1.5, humanFriction: -0.2 });
  assert.strictEqual(snap.metrics.catchRate, 1);
  assert.strictEqual(snap.metrics.humanFriction, 0);
});

test("recordSnapshot rejects non-object", function () {
  var opt = new DefensePostureOptimizer();
  assert.throws(function () { opt.recordSnapshot(null); });
});

test("recordSnapshot respects maxSnapshots", function () {
  var opt = new DefensePostureOptimizer({ maxSnapshots: 5 });
  for (var i = 0; i < 10; i++) opt.recordSnapshot(makeMetrics());
  assert.strictEqual(opt._snapshots.length, 5);
});

// Drift detection
test("drift is STABLE with few snapshots", function () {
  var opt = new DefensePostureOptimizer({ driftWindow: 3 });
  opt.recordSnapshot(makeMetrics());
  assert.strictEqual(opt._driftState, "STABLE");
});

test("drift detects degradation", function () {
  var opt = new DefensePostureOptimizer({ driftWindow: 3, driftThreshold: 0.1, criticalThreshold: 0.3 });
  // Good baseline
  for (var i = 0; i < 3; i++) opt.recordSnapshot(makeMetrics({ catchRate: 0.9 }));
  // Degraded recent
  for (var j = 0; j < 3; j++) opt.recordSnapshot(makeMetrics({ catchRate: 0.4, attackSurface: 0.3 }));
  assert.ok(opt._driftState === "DEGRADED" || opt._driftState === "CRITICAL");
});

test("drift detects critical degradation", function () {
  var opt = new DefensePostureOptimizer({ driftWindow: 3, criticalThreshold: 0.2 });
  for (var i = 0; i < 3; i++) opt.recordSnapshot(makeMetrics({ catchRate: 0.95, attackSurface: 0.9 }));
  for (var j = 0; j < 3; j++) opt.recordSnapshot(makeMetrics({ catchRate: 0.2, attackSurface: 0.1, humanFriction: 0.9 }));
  assert.strictEqual(opt._driftState, "CRITICAL");
});

// getDriftStatus
test("getDriftStatus returns structure", function () {
  var opt = new DefensePostureOptimizer();
  seedOptimizer(opt, 10);
  var status = opt.getDriftStatus();
  assert.strictEqual(status.state, "STABLE");
  assert.ok(status.currentScore != null);
  assert.ok(status.averageScore != null);
});

test("getDriftStatus includes trend", function () {
  var opt = new DefensePostureOptimizer();
  seedOptimizer(opt, 10);
  var status = opt.getDriftStatus();
  assert.ok(status.trend);
  assert.ok(status.trend.direction);
});

// Pareto
test("computePareto returns empty for no snapshots", function () {
  var opt = new DefensePostureOptimizer();
  var result = opt.computePareto();
  assert.strictEqual(result.frontier.length, 0);
});

test("computePareto finds frontier", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  // Add diverse configs
  opt.recordSnapshot(makeMetrics({ catchRate: 0.9, humanFriction: 0.6 }));
  opt.recordSnapshot(makeMetrics({ catchRate: 0.6, humanFriction: 0.1 }));
  opt.recordSnapshot(makeMetrics({ catchRate: 0.5, humanFriction: 0.5 })); // dominated
  var result = opt.computePareto();
  assert.ok(result.frontier.length >= 2);
  assert.ok(result.dominated >= 0);
});

test("computePareto respects frictionBudget", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  opt.recordSnapshot(makeMetrics({ humanFriction: 0.8 }));
  opt.recordSnapshot(makeMetrics({ humanFriction: 0.2 }));
  var result = opt.computePareto({ frictionBudget: 0.3 });
  assert.strictEqual(result.budgetFiltered, 1);
});

test("computePareto ranks by priorities", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  opt.recordSnapshot(makeMetrics({ catchRate: 0.95, humanFriction: 0.8 }));
  opt.recordSnapshot(makeMetrics({ catchRate: 0.6, humanFriction: 0.1 }));
  var secResult = opt.computePareto({ priorities: { catchRate: 5, humanFriction: 1 } });
  var uxResult = opt.computePareto({ priorities: { catchRate: 1, humanFriction: 5 } });
  // First result in security-priority should be the high-catch-rate one
  assert.ok(secResult.frontier.length > 0);
  assert.ok(uxResult.frontier.length > 0);
});

// Simulate
test("simulate returns error with insufficient data", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  opt.recordSnapshot(makeMetrics());
  var result = opt.simulate({ DIFFICULTY: 0.8 });
  assert.strictEqual(result.error, "INSUFFICIENT_DATA");
});

test("simulate works with sufficient data", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  for (var i = 0; i < 10; i++) {
    opt.setConfig(makeConfig({ DIFFICULTY: 0.3 + i * 0.05 }));
    opt.recordSnapshot(makeMetrics({ catchRate: 0.5 + i * 0.04 }));
  }
  var result = opt.simulate({ DIFFICULTY: 0.9 });
  assert.ok(!result.error);
  assert.ok(result.predictions);
  assert.ok(result.comparison);
  assert.ok(result.verdict);
});

test("simulate rejects non-object", function () {
  var opt = new DefensePostureOptimizer();
  assert.throws(function () { opt.simulate(null); });
});

test("simulate stores simulation history", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  for (var i = 0; i < 10; i++) {
    opt.setConfig(makeConfig({ DIFFICULTY: 0.2 + i * 0.06 }));
    opt.recordSnapshot(makeMetrics({ catchRate: 0.4 + i * 0.05 }));
  }
  opt.simulate({ DIFFICULTY: 0.9 });
  assert.strictEqual(opt._simulations.length, 1);
});

// Recommend
test("recommend returns empty with few snapshots", function () {
  var opt = new DefensePostureOptimizer();
  opt.recordSnapshot(makeMetrics());
  var result = opt.recommend();
  assert.strictEqual(result.recommendations.length, 0);
});

test("recommend detects low catch rate", function () {
  var opt = new DefensePostureOptimizer();
  for (var i = 0; i < 5; i++) opt.recordSnapshot(makeMetrics({ catchRate: 0.3 }));
  var result = opt.recommend({ priority: "SECURITY" });
  var found = result.recommendations.some(function (r) { return r.dimension === "CATCH_RATE"; });
  assert.ok(found);
});

test("recommend detects high friction", function () {
  var opt = new DefensePostureOptimizer();
  for (var i = 0; i < 5; i++) opt.recordSnapshot(makeMetrics({ humanFriction: 0.8 }));
  var result = opt.recommend({ priority: "USABILITY" });
  var found = result.recommendations.some(function (r) { return r.dimension === "HUMAN_FRICTION"; });
  assert.ok(found);
});

test("recommend detects high fatigue", function () {
  var opt = new DefensePostureOptimizer();
  for (var i = 0; i < 5; i++) opt.recordSnapshot(makeMetrics({ fatigueRisk: 0.8 }));
  var result = opt.recommend({ priority: "USABILITY" });
  var found = result.recommendations.some(function (r) { return r.dimension === "FATIGUE_RISK"; });
  assert.ok(found);
});

test("recommend detects low diversity", function () {
  var opt = new DefensePostureOptimizer();
  for (var i = 0; i < 5; i++) opt.recordSnapshot(makeMetrics({ challengeDiversity: 0.2 }));
  var result = opt.recommend();
  var found = result.recommendations.some(function (r) { return r.dimension === "CHALLENGE_DIVERSITY"; });
  assert.ok(found);
});

test("recommend detects high latency", function () {
  var opt = new DefensePostureOptimizer();
  for (var i = 0; i < 5; i++) opt.recordSnapshot(makeMetrics({ latencyCost: 6000 }));
  var result = opt.recommend();
  var found = result.recommendations.some(function (r) { return r.dimension === "LATENCY_COST"; });
  assert.ok(found);
});

test("recommend includes drift warning when degraded", function () {
  var opt = new DefensePostureOptimizer({ driftWindow: 3, criticalThreshold: 0.2 });
  for (var i = 0; i < 3; i++) opt.recordSnapshot(makeMetrics({ catchRate: 0.95 }));
  for (var j = 0; j < 3; j++) opt.recordSnapshot(makeMetrics({ catchRate: 0.2, attackSurface: 0.1 }));
  var result = opt.recommend();
  var found = result.recommendations.some(function (r) { return r.dimension === "DRIFT"; });
  assert.ok(found);
});

// Budget optimization
test("optimizeWithinBudget requires maxFriction", function () {
  var opt = new DefensePostureOptimizer();
  assert.throws(function () { opt.optimizeWithinBudget({}); });
});

test("optimizeWithinBudget returns not-found when empty", function () {
  var opt = new DefensePostureOptimizer();
  var result = opt.optimizeWithinBudget({ maxFriction: 0.5 });
  assert.strictEqual(result.found, false);
});

test("optimizeWithinBudget finds feasible config", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  opt.recordSnapshot(makeMetrics({ humanFriction: 0.2, catchRate: 0.9 }));
  opt.recordSnapshot(makeMetrics({ humanFriction: 0.8, catchRate: 0.95 }));
  var result = opt.optimizeWithinBudget({ maxFriction: 0.5 });
  assert.strictEqual(result.found, true);
  assert.ok(result.optimal.metrics.humanFriction <= 0.5);
});

test("optimizeWithinBudget respects latency budget", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  opt.recordSnapshot(makeMetrics({ latencyCost: 100, catchRate: 0.7 }));
  opt.recordSnapshot(makeMetrics({ latencyCost: 5000, catchRate: 0.95 }));
  var result = opt.optimizeWithinBudget({ maxFriction: 1, maxLatency: 200 });
  assert.strictEqual(result.found, true);
  assert.ok(result.optimal.metrics.latencyCost <= 200);
});

// Timeline
test("getTimeline returns entries", function () {
  var opt = new DefensePostureOptimizer();
  seedOptimizer(opt, 10);
  var timeline = opt.getTimeline();
  assert.strictEqual(timeline.entries.length, 10);
  assert.ok(timeline.trend);
});

test("getTimeline respects limit", function () {
  var opt = new DefensePostureOptimizer();
  seedOptimizer(opt, 20);
  var timeline = opt.getTimeline({ limit: 5 });
  assert.strictEqual(timeline.entries.length, 5);
});

test("getTimeline entries have compositeScore", function () {
  var opt = new DefensePostureOptimizer();
  seedOptimizer(opt, 5);
  var timeline = opt.getTimeline();
  assert.ok(timeline.entries[0].compositeScore >= 0);
  assert.ok(timeline.entries[0].compositeScore <= 1);
});

// Dimension breakdown
test("getDimensionBreakdown returns empty for no data", function () {
  var opt = new DefensePostureOptimizer();
  var result = opt.getDimensionBreakdown();
  assert.strictEqual(result.snapshotCount, 0);
});

test("getDimensionBreakdown returns all dimensions", function () {
  var opt = new DefensePostureOptimizer();
  seedOptimizer(opt, 10);
  var result = opt.getDimensionBreakdown();
  assert.ok(result.dimensions.catchRate);
  assert.ok(result.dimensions.humanFriction);
  assert.ok(result.dimensions.latencyCost);
  assert.ok(result.dimensions.challengeDiversity);
  assert.ok(result.dimensions.attackSurface);
  assert.ok(result.dimensions.fatigueRisk);
});

test("getDimensionBreakdown includes trend", function () {
  var opt = new DefensePostureOptimizer();
  seedOptimizer(opt, 10);
  var result = opt.getDimensionBreakdown();
  assert.ok(result.dimensions.catchRate.trend);
  assert.ok(result.dimensions.catchRate.trend.direction);
});

// Export/Import
test("exportState returns versioned state", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  opt.recordSnapshot(makeMetrics());
  var state = opt.exportState();
  assert.strictEqual(state.version, 1);
  assert.ok(state.exportedAt);
  assert.strictEqual(state.snapshots.length, 1);
});

test("importState restores state", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  opt.recordSnapshot(makeMetrics({ catchRate: 0.99 }));
  var state = opt.exportState();

  var opt2 = new DefensePostureOptimizer();
  opt2.importState(state);
  assert.strictEqual(opt2._snapshots.length, 1);
  assert.strictEqual(opt2._snapshots[0].metrics.catchRate, 0.99);
});

test("importState rejects invalid version", function () {
  var opt = new DefensePostureOptimizer();
  assert.throws(function () { opt.importState({ version: 99 }); });
});

test("importState enforces limits", function () {
  var opt = new DefensePostureOptimizer({ maxSnapshots: 3 });
  var bigState = { version: 1, snapshots: [], simulations: [], config: null, driftState: "STABLE", recommendations: [] };
  for (var i = 0; i < 10; i++) bigState.snapshots.push({ id: "s" + i, timestamp: i, metrics: makeMetrics(), config: null, driftState: "STABLE" });
  opt.importState(bigState);
  assert.strictEqual(opt._snapshots.length, 3);
});

// Summary
test("getSummary returns NO_DATA when empty", function () {
  var opt = new DefensePostureOptimizer();
  var summary = opt.getSummary();
  assert.strictEqual(summary.status, "NO_DATA");
});

test("getSummary returns grade and score", function () {
  var opt = new DefensePostureOptimizer();
  opt.setConfig(makeConfig());
  opt.recordSnapshot(makeMetrics());
  var summary = opt.getSummary();
  assert.strictEqual(summary.status, "ACTIVE");
  assert.ok(summary.grade);
  assert.ok(summary.compositeScore >= 0);
});

test("getSummary grade A for excellent posture", function () {
  var opt = new DefensePostureOptimizer();
  opt.recordSnapshot(makeMetrics({ catchRate: 0.95, humanFriction: 0.1, attackSurface: 0.9, challengeDiversity: 0.9, fatigueRisk: 0.05, latencyCost: 100 }));
  var summary = opt.getSummary();
  assert.strictEqual(summary.grade, "A");
});

test("getSummary grade F for poor posture", function () {
  var opt = new DefensePostureOptimizer();
  opt.recordSnapshot(makeMetrics({ catchRate: 0.1, humanFriction: 0.9, attackSurface: 0.1, challengeDiversity: 0.1, fatigueRisk: 0.9, latencyCost: 8000 }));
  var summary = opt.getSummary();
  assert.strictEqual(summary.grade, "F");
});

// ── Report ──────────────────────────────────────────────────────────

console.log("\n" + (passed + failed) + " tests: " + passed + " passed, " + failed + " failed\n");
if (failed > 0) process.exit(1);
