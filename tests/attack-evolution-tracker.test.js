/**
 * Tests for AttackEvolutionTracker.
 */

"use strict";

var test = require("node:test");
var assert = require("node:assert/strict");
var mod = require("../src/attack-evolution-tracker");
var createAttackEvolutionTracker = mod.createAttackEvolutionTracker;

// ── Helpers ─────────────────────────────────────────────────────────

function makeAttempt(overrides) {
  var base = {
    challengeId: "ch-1",
    tool: "selenium",
    technique: "pixel-scan",
    timingProfile: "fast",
    success: false,
    timestamp: Date.now()
  };
  if (overrides) {
    var keys = Object.keys(overrides);
    for (var i = 0; i < keys.length; i++) base[keys[i]] = overrides[keys[i]];
  }
  return base;
}

// ── Basic Tests ─────────────────────────────────────────────────────

test("creates tracker with default options", function () {
  var tracker = createAttackEvolutionTracker();
  assert.ok(tracker);
  assert.equal(typeof tracker.recordAttempt, "function");
  assert.equal(typeof tracker.analyze, "function");
  assert.equal(typeof tracker.forecast, "function");
});

test("recordAttempt returns strategyId and epoch", function () {
  var tracker = createAttackEvolutionTracker();
  var result = tracker.recordAttempt(makeAttempt());
  assert.ok(result);
  assert.equal(result.strategyId, "selenium::pixel-scan::fast");
  assert.equal(typeof result.epoch, "number");
});

test("recordAttempt rejects invalid input", function () {
  var tracker = createAttackEvolutionTracker();
  assert.equal(tracker.recordAttempt(null), null);
  assert.equal(tracker.recordAttempt(42), null);
  assert.equal(tracker.recordAttempt("string"), null);
});

test("strategy fingerprint combines tool, technique, timingProfile", function () {
  var tracker = createAttackEvolutionTracker();
  tracker.recordAttempt(makeAttempt({ tool: "puppeteer", technique: "ocr", timingProfile: "slow" }));
  var strats = tracker._strategies();
  assert.ok(strats["puppeteer::ocr::slow"]);
});

test("missing fields use 'unknown' in fingerprint", function () {
  var tracker = createAttackEvolutionTracker();
  tracker.recordAttempt({ challengeId: "ch-1", success: false });
  var strats = tracker._strategies();
  assert.ok(strats["unknown::unknown::unknown"]);
});

test("explicit strategyId overrides fingerprinting", function () {
  var tracker = createAttackEvolutionTracker();
  tracker.recordAttempt(makeAttempt({ strategyId: "custom-id" }));
  var strats = tracker._strategies();
  assert.ok(strats["custom-id"]);
});

// ── Analysis Tests ──────────────────────────────────────────────────

test("analyze returns proper structure with no data", function () {
  var tracker = createAttackEvolutionTracker();
  var report = tracker.analyze();
  assert.ok(report);
  assert.ok(report.summary);
  assert.equal(report.summary.totalStrategies, 0);
  assert.equal(report.summary.totalChallenges, 0);
  assert.deepEqual(report.strategies, []);
  assert.deepEqual(report.adaptingStrategies, []);
  assert.deepEqual(report.challengeRisks, []);
  assert.deepEqual(report.rotationRecommendations, []);
});

test("analyze counts strategies correctly", function () {
  var tracker = createAttackEvolutionTracker();
  for (var i = 0; i < 5; i++) {
    tracker.recordAttempt(makeAttempt({ tool: "tool-" + i }));
  }
  var report = tracker.analyze();
  assert.equal(report.summary.totalStrategies, 5);
});

test("strategy with high success rate is classified as evolved", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 5, compromiseThreshold: 0.7 });
  var ts = Date.now();
  for (var i = 0; i < 10; i++) {
    tracker.recordAttempt(makeAttempt({
      success: true,
      timestamp: ts + i * 1000
    }));
  }
  var report = tracker.analyze();
  assert.equal(report.strategies[0].status, "evolved");
});

test("challenge gets compromised status when bot success rate is high", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 5, compromiseThreshold: 0.7 });
  var ts = Date.now();
  // 8 out of 10 succeed = 80% > 70% threshold
  for (var i = 0; i < 10; i++) {
    tracker.recordAttempt(makeAttempt({
      success: i < 8,
      timestamp: ts + i * 1000
    }));
  }
  var report = tracker.analyze();
  var atRisk = report.challengeRisks.filter(function (r) { return r.id === "ch-1"; });
  assert.ok(atRisk.length > 0);
  assert.equal(atRisk[0].status, "compromised");
});

test("secure challenge does not appear in challengeRisks", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 5 });
  var ts = Date.now();
  // All fail = 0% success rate
  for (var i = 0; i < 10; i++) {
    tracker.recordAttempt(makeAttempt({
      success: false,
      timestamp: ts + i * 1000
    }));
  }
  var report = tracker.analyze();
  assert.equal(report.challengeRisks.length, 0);
});

// ── Learning Rate Detection ─────────────────────────────────────────

test("detects adapting strategy with rising success over epochs", function () {
  var tracker = createAttackEvolutionTracker({
    minObservations: 3,
    epochMs: 1000,
    learningRateThreshold: 0.01,
    compromiseThreshold: 0.95
  });

  var ts = Date.now();
  // Epoch 0: 0/5 success (0%)
  for (var i = 0; i < 5; i++) {
    tracker.recordAttempt(makeAttempt({ success: false, timestamp: ts + i * 100 }));
  }
  // Epoch 1: 2/5 success (40%)
  for (var j = 0; j < 5; j++) {
    tracker.recordAttempt(makeAttempt({ success: j < 2, timestamp: ts + 1000 + j * 100 }));
  }
  // Epoch 2: 4/5 success (80%)
  for (var k = 0; k < 5; k++) {
    tracker.recordAttempt(makeAttempt({ success: k < 4, timestamp: ts + 2000 + k * 100 }));
  }

  var report = tracker.analyze();
  var strat = report.strategies[0];
  assert.ok(strat.learningRate > 0, "learning rate should be positive");
  assert.equal(strat.status, "adapting");
  assert.ok(report.adaptingStrategies.length > 0);
});

// ── Mutation / Lineage Detection ────────────────────────────────────

test("detects strategy mutation from same tool family", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 3 });
  var ts = Date.now();

  // Parent strategy
  for (var i = 0; i < 5; i++) {
    tracker.recordAttempt(makeAttempt({
      tool: "selenium",
      technique: "v1",
      timingProfile: "fast",
      timestamp: ts + i * 100
    }));
  }

  // Child strategy (same tool, different technique)
  tracker.recordAttempt(makeAttempt({
    tool: "selenium",
    technique: "v2",
    timingProfile: "fast",
    timestamp: ts + 10000
  }));

  var strats = tracker._strategies();
  var child = strats["selenium::v2::fast"];
  assert.ok(child);
  assert.equal(child.parentId, "selenium::v1::fast");
  assert.equal(child.generation, 1);
});

test("getLineage returns ancestor chain", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 2 });
  var ts = Date.now();

  // Gen 0
  for (var i = 0; i < 3; i++) {
    tracker.recordAttempt(makeAttempt({
      tool: "bot",
      technique: "gen0",
      timingProfile: "x",
      timestamp: ts + i * 100
    }));
  }
  // Gen 1
  for (var j = 0; j < 3; j++) {
    tracker.recordAttempt(makeAttempt({
      tool: "bot",
      technique: "gen1",
      timingProfile: "x",
      timestamp: ts + 5000 + j * 100
    }));
  }

  var lineage = tracker.getLineage("bot::gen1::x");
  assert.ok(lineage.length >= 2);
  assert.equal(lineage[0].id, "bot::gen1::x");
  assert.equal(lineage[1].id, "bot::gen0::x");
});

// ── Rotation Recommendations ────────────────────────────────────────

test("generates rotation recommendation for compromised challenge", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 5, compromiseThreshold: 0.6 });
  var ts = Date.now();

  for (var i = 0; i < 10; i++) {
    tracker.recordAttempt(makeAttempt({
      success: i < 8,
      timestamp: ts + i * 1000
    }));
  }

  var report = tracker.analyze();
  assert.ok(report.rotationRecommendations.length > 0);
  var rec = report.rotationRecommendations[0];
  assert.equal(rec.challengeId, "ch-1");
  assert.equal(rec.urgency, "critical");
  assert.ok(rec.recommendation.length > 0);
  assert.ok(Array.isArray(rec.topThreats));
});

test("rotation cooldown prevents duplicate recommendations", function () {
  var tracker = createAttackEvolutionTracker({
    minObservations: 5,
    compromiseThreshold: 0.6,
    rotationCooldownMs: 999999999
  });
  var ts = Date.now();

  for (var i = 0; i < 10; i++) {
    tracker.recordAttempt(makeAttempt({ success: true, timestamp: ts + i * 100 }));
  }

  var r1 = tracker.analyze();
  assert.equal(r1.rotationRecommendations.length, 1);

  var r2 = tracker.analyze();
  assert.equal(r2.rotationRecommendations.length, 0, "should be suppressed by cooldown");
});

// ── Forecast ────────────────────────────────────────────────────────

test("forecast returns predictions for challenges with history", function () {
  var tracker = createAttackEvolutionTracker({
    minObservations: 3,
    epochMs: 1000,
    predictionHorizonEpochs: 12
  });
  var ts = Date.now();

  // Build 4 epochs with rising success
  for (var epoch = 0; epoch < 4; epoch++) {
    for (var i = 0; i < 5; i++) {
      tracker.recordAttempt(makeAttempt({
        success: i < epoch + 1,
        timestamp: ts + epoch * 1000 + i * 100
      }));
    }
  }

  var predictions = tracker.forecast();
  assert.ok(predictions.length > 0);
  var pred = predictions[0];
  assert.equal(pred.challengeId, "ch-1");
  assert.equal(pred.trend, "rising");
  assert.ok(pred.trendSlope > 0);
  assert.ok(pred.forecast.length > 0);
  assert.ok(pred.forecast.length <= 12);
});

test("forecast shows stable trend for constant success rate", function () {
  var tracker = createAttackEvolutionTracker({
    minObservations: 3,
    epochMs: 1000
  });
  // Align ts to an epoch boundary so every 5-attempt batch (spanning
  // 0..400ms) lands fully inside one epoch. Without this, when
  // Date.now() % 1000 >= 600 the final attempts in each batch spill into
  // the next epoch, producing per-epoch rates that are not constant
  // (e.g. 1/2, 2/3, ...) and a non-zero slope. Locally we usually get a
  // lucky offset; CI hosts trip the spillover and the test flakes.
  var ts = Math.floor(Date.now() / 1000) * 1000;

  // 4 epochs with consistent 40% success
  for (var epoch = 0; epoch < 4; epoch++) {
    for (var i = 0; i < 5; i++) {
      tracker.recordAttempt(makeAttempt({
        success: i < 2,
        timestamp: ts + epoch * 1000 + i * 100
      }));
    }
  }

  var predictions = tracker.forecast();
  assert.ok(predictions.length > 0);
  assert.equal(predictions[0].trend, "stable");
});

// ── Timeline ────────────────────────────────────────────────────────

test("getTimeline returns mutation events", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 2 });
  var ts = Date.now();

  for (var i = 0; i < 3; i++) {
    tracker.recordAttempt(makeAttempt({ tool: "t", technique: "a", timestamp: ts + i * 100 }));
  }
  tracker.recordAttempt(makeAttempt({ tool: "t", technique: "b", timestamp: ts + 5000 }));

  var timeline = tracker.getTimeline({ type: "mutation" });
  assert.ok(timeline.length > 0);
  assert.equal(timeline[0].type, "mutation");
  assert.equal(timeline[0].details.childId, "t::b::fast");
});

test("getTimeline respects limit", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 1 });
  var ts = Date.now();

  for (var i = 0; i < 5; i++) {
    for (var j = 0; j < 2; j++) {
      tracker.recordAttempt(makeAttempt({ tool: "t", technique: "v" + i, timestamp: ts + i * 5000 + j * 100 }));
    }
  }

  var timeline = tracker.getTimeline({ limit: 2 });
  assert.ok(timeline.length <= 2);
});

// ── Export / Import ─────────────────────────────────────────────────

test("export and import state round-trips", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 3 });
  var ts = Date.now();
  for (var i = 0; i < 5; i++) {
    tracker.recordAttempt(makeAttempt({ timestamp: ts + i * 100 }));
  }

  var state = tracker.exportState();
  var tracker2 = createAttackEvolutionTracker({ minObservations: 3 });
  assert.equal(tracker2.importState(state), true);

  var r1 = tracker.analyze();
  var r2 = tracker2.analyze();
  assert.equal(r1.summary.totalStrategies, r2.summary.totalStrategies);
  assert.equal(r1.summary.totalChallenges, r2.summary.totalChallenges);
});

test("importState rejects invalid input", function () {
  var tracker = createAttackEvolutionTracker();
  assert.equal(tracker.importState(null), false);
  assert.equal(tracker.importState("string"), false);
});

// ── Reset ───────────────────────────────────────────────────────────

test("reset clears all state", function () {
  var tracker = createAttackEvolutionTracker();
  for (var i = 0; i < 10; i++) {
    tracker.recordAttempt(makeAttempt());
  }
  tracker.reset();
  var report = tracker.analyze();
  assert.equal(report.summary.totalStrategies, 0);
  assert.equal(report.summary.totalChallenges, 0);
  assert.equal(tracker._events().length, 0);
});

// ── Eviction ────────────────────────────────────────────────────────

test("evicts oldest strategy when maxStrategies reached", function () {
  var tracker = createAttackEvolutionTracker({ maxStrategies: 3 });

  tracker.recordAttempt(makeAttempt({ tool: "a" }));
  tracker.recordAttempt(makeAttempt({ tool: "b" }));
  tracker.recordAttempt(makeAttempt({ tool: "c" }));
  tracker.recordAttempt(makeAttempt({ tool: "d" }));

  var strats = tracker._strategies();
  assert.ok(!strats["a::pixel-scan::fast"], "oldest should be evicted");
  assert.ok(strats["d::pixel-scan::fast"], "newest should exist");
  assert.equal(Object.keys(strats).length, 3);
});

// ── Multiple Challenges ─────────────────────────────────────────────

test("tracks multiple challenges independently", function () {
  var tracker = createAttackEvolutionTracker({ minObservations: 3 });
  var ts = Date.now();

  for (var i = 0; i < 5; i++) {
    tracker.recordAttempt(makeAttempt({ challengeId: "ch-A", success: true, timestamp: ts + i * 100 }));
    tracker.recordAttempt(makeAttempt({ challengeId: "ch-B", success: false, timestamp: ts + i * 100 }));
  }

  var chs = tracker._challenges();
  assert.equal(chs["ch-A"].currentBotSuccessRate, 1.0);
  assert.equal(chs["ch-B"].currentBotSuccessRate, 0.0);
});

// ── Dormant Strategy ────────────────────────────────────────────────

test("strategy goes dormant when not seen for 2x window", function () {
  var tracker = createAttackEvolutionTracker({
    minObservations: 3,
    windowMs: 1000
  });

  // Record old attempts
  var oldTs = Date.now() - 5000;
  for (var i = 0; i < 5; i++) {
    tracker.recordAttempt(makeAttempt({ timestamp: oldTs + i * 100 }));
  }

  var report = tracker.analyze();
  assert.equal(report.strategies[0].status, "dormant");
  assert.equal(report.summary.dormant, 1);
});
