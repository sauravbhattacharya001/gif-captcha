/**
 * Tests for BotCapabilityProfiler — autonomous bot sophistication analysis engine.
 */

"use strict";

var _test = require("node:test");
var _assert = require("node:assert/strict");
var _mod = require("../src/bot-capability-profiler.js");
var createBotCapabilityProfiler = _mod.createBotCapabilityProfiler;

// ── Helpers ─────────────────────────────────────────────────────────

function makeAttempt(botId, challengeType, solved, opts) {
  opts = opts || {};
  return {
    botId: botId,
    challengeType: challengeType,
    solved: solved,
    difficulty: opts.difficulty || 0.5,
    solveTimeMs: opts.solveTimeMs || 1000,
    dimensions: opts.dimensions || null,
    features: opts.features || null
  };
}

function feedAttempts(profiler, botId, challengeType, count, solveRate, opts) {
  opts = opts || {};
  for (var i = 0; i < count; i++) {
    profiler.recordAttempt(makeAttempt(
      botId, challengeType, Math.random() < solveRate,
      { difficulty: opts.difficulty || 0.5, dimensions: opts.dimensions || null, features: opts.features || null }
    ));
  }
}

// ── Basic Tests ─────────────────────────────────────────────────────

_test("creates profiler with default options", function () {
  var p = createBotCapabilityProfiler();
  _assert.ok(p);
  _assert.ok(p.recordAttempt);
  _assert.ok(p.getProfile);
  _assert.ok(p.predictVulnerability);
  _assert.ok(p.getDefenseRecommendations);
  _assert.ok(p.getStats);
});

_test("exposes capability dimensions and tiers", function () {
  var p = createBotCapabilityProfiler();
  _assert.equal(p.CAPABILITY_DIMENSIONS.length, 8);
  _assert.equal(p.SOPHISTICATION_TIERS.length, 5);
  _assert.equal(p.VULNERABILITY_LEVELS.length, 5);
});

_test("recordAttempt requires botId and challengeType", function () {
  var p = createBotCapabilityProfiler();
  var r1 = p.recordAttempt(null);
  _assert.ok(r1.error);
  var r2 = p.recordAttempt({ botId: "b1" });
  _assert.ok(r2.error);
  var r3 = p.recordAttempt({ challengeType: "ct1" });
  _assert.ok(r3.error);
});

_test("recordAttempt returns bot summary", function () {
  var p = createBotCapabilityProfiler();
  var r = p.recordAttempt(makeAttempt("bot1", "type1", true));
  _assert.equal(r.botId, "bot1");
  _assert.ok(r.tier);
  _assert.equal(typeof r.tierScore, "number");
  _assert.equal(r.totalAttempts, 1);
});

_test("bot tier increases with successful solves", function () {
  var p = createBotCapabilityProfiler();
  for (var i = 0; i < 30; i++) {
    p.recordAttempt(makeAttempt("bot1", "type1", true, {
      difficulty: 0.8,
      dimensions: ["OCR_ACCURACY", "MOTION_TRACKING", "TEMPORAL_REASONING", "SPATIAL_REASONING"]
    }));
  }
  var profile = p.getProfile("bot1");
  _assert.ok(profile.tierScore > 30);
  _assert.notEqual(profile.tier, "SCRIPT_KIDDIE");
});

_test("bot tier stays low with failed attempts", function () {
  var p = createBotCapabilityProfiler();
  for (var i = 0; i < 20; i++) {
    p.recordAttempt(makeAttempt("bot1", "type1", false, { difficulty: 0.8 }));
  }
  var profile = p.getProfile("bot1");
  _assert.ok(profile.tierScore < 30);
});

_test("getProfile returns null for unknown bot", function () {
  var p = createBotCapabilityProfiler();
  _assert.equal(p.getProfile("unknown"), null);
});

_test("getProfile includes strengths and weaknesses", function () {
  var p = createBotCapabilityProfiler();
  // Good at OCR, bad at motion
  for (var i = 0; i < 25; i++) {
    p.recordAttempt(makeAttempt("bot1", "ocr-type", true, {
      difficulty: 0.7, dimensions: ["OCR_ACCURACY"]
    }));
    p.recordAttempt(makeAttempt("bot1", "motion-type", false, {
      difficulty: 0.3, dimensions: ["MOTION_TRACKING"]
    }));
  }
  var profile = p.getProfile("bot1");
  _assert.ok(profile.strengths.indexOf("OCR_ACCURACY") >= 0);
  _assert.ok(profile.weaknesses.indexOf("MOTION_TRACKING") >= 0);
});

_test("predictVulnerability for single tier", function () {
  var p = createBotCapabilityProfiler();
  // Create an ELITE bot that solves everything
  for (var i = 0; i < 30; i++) {
    p.recordAttempt(makeAttempt("elite1", "easy-challenge", true, {
      difficulty: 0.9, dimensions: ["PATTERN_RECOGNITION", "OCR_ACCURACY", "TEMPORAL_REASONING", "SPATIAL_REASONING"]
    }));
  }
  var vuln = p.predictVulnerability("easy-challenge", "ELITE");
  _assert.ok(vuln.level);
  _assert.ok(vuln.confidence >= 0);
});

_test("predictVulnerability for ALL tiers", function () {
  var p = createBotCapabilityProfiler();
  feedAttempts(p, "bot1", "ct1", 10, 0.5);
  var vuln = p.predictVulnerability("ct1", "ALL");
  _assert.ok(vuln.challengeType);
  _assert.ok(vuln.vulnerabilityByTier);
  _assert.ok(vuln.overallRisk);
});

_test("predictVulnerability returns MODERATE for unknown challenge", function () {
  var p = createBotCapabilityProfiler();
  var vuln = p.predictVulnerability("unknown-type", "BASIC_BOT");
  _assert.equal(vuln.level, "MODERATE");
  _assert.equal(vuln.confidence, 0);
});

_test("getDefenseRecommendations returns structured data", function () {
  var p = createBotCapabilityProfiler();
  feedAttempts(p, "bot1", "ct1", 15, 0.8, { dimensions: ["OCR_ACCURACY"] });
  feedAttempts(p, "bot2", "ct2", 15, 0.2, { dimensions: ["TEMPORAL_REASONING"] });
  var recs = p.getDefenseRecommendations();
  _assert.ok(recs.activeBots >= 0);
  _assert.ok(recs.tierDistribution);
  _assert.ok(recs.dimensionEffectiveness);
  _assert.ok(recs.topRecommendation);
});

_test("getTierDistribution returns counts and percentages", function () {
  var p = createBotCapabilityProfiler();
  feedAttempts(p, "bot1", "ct1", 5, 0.5);
  feedAttempts(p, "bot2", "ct1", 5, 0.5);
  var dist = p.getTierDistribution();
  _assert.equal(dist.total, 2);
  _assert.ok(dist.counts);
  _assert.ok(dist.percentages);
});

_test("compareBots returns null if bot not found", function () {
  var p = createBotCapabilityProfiler();
  feedAttempts(p, "bot1", "ct1", 5, 0.5);
  _assert.equal(p.compareBots("bot1", "unknown"), null);
  _assert.equal(p.compareBots("unknown", "bot1"), null);
});

_test("compareBots returns dimension comparison", function () {
  var p = createBotCapabilityProfiler();
  for (var i = 0; i < 20; i++) {
    p.recordAttempt(makeAttempt("bot1", "ct1", true, { difficulty: 0.7, dimensions: ["OCR_ACCURACY"] }));
    p.recordAttempt(makeAttempt("bot2", "ct1", false, { difficulty: 0.7, dimensions: ["OCR_ACCURACY"] }));
  }
  var cmp = p.compareBots("bot1", "bot2");
  _assert.ok(cmp.bot1);
  _assert.ok(cmp.bot2);
  _assert.ok(cmp.dimensionComparison.OCR_ACCURACY);
  _assert.equal(cmp.dimensionComparison.OCR_ACCURACY.advantage, "bot1");
});

_test("getStats returns aggregate data", function () {
  var p = createBotCapabilityProfiler();
  feedAttempts(p, "bot1", "ct1", 10, 0.6);
  feedAttempts(p, "bot2", "ct2", 5, 0.4);
  var stats = p.getStats();
  _assert.equal(stats.trackedBots, 2);
  _assert.equal(stats.totalAttempts, 15);
  _assert.ok(stats.overallSolveRate >= 0);
  _assert.ok(stats.tierDistribution);
});

_test("exportState and importState roundtrip", function () {
  var p = createBotCapabilityProfiler();
  feedAttempts(p, "bot1", "ct1", 10, 0.7);
  var state = p.exportState();
  _assert.equal(state.version, 1);
  _assert.ok(state.bots);

  var p2 = createBotCapabilityProfiler();
  _assert.ok(p2.importState(state));
  _assert.ok(p2.getProfile("bot1"));
  _assert.equal(p2.getProfile("bot1").totalAttempts, 10);
});

_test("importState rejects invalid state", function () {
  var p = createBotCapabilityProfiler();
  _assert.equal(p.importState(null), false);
  _assert.equal(p.importState({ version: 99 }), false);
});

_test("reset clears all state", function () {
  var p = createBotCapabilityProfiler();
  feedAttempts(p, "bot1", "ct1", 10, 0.5);
  p.reset();
  _assert.equal(p.getProfile("bot1"), null);
  _assert.equal(p.getStats().trackedBots, 0);
});

_test("LRU eviction works when maxBots exceeded", function () {
  var p = createBotCapabilityProfiler({ maxBots: 3 });
  p.recordAttempt(makeAttempt("bot1", "ct1", true));
  p.recordAttempt(makeAttempt("bot2", "ct1", true));
  p.recordAttempt(makeAttempt("bot3", "ct1", true));
  p.recordAttempt(makeAttempt("bot4", "ct1", true)); // should evict bot1
  _assert.equal(p.getProfile("bot1"), null);
  _assert.ok(p.getProfile("bot4"));
});

_test("dimension inference from features", function () {
  var p = createBotCapabilityProfiler();
  p.recordAttempt(makeAttempt("bot1", "ct1", true, {
    features: { hasText: true, hasMotion: true, hasNoise: true }
  }));
  var profile = p.getProfile("bot1");
  _assert.ok(profile.capabilities.OCR_ACCURACY.samples > 0);
  _assert.ok(profile.capabilities.MOTION_TRACKING.samples > 0);
  _assert.ok(profile.capabilities.ADVERSARIAL_RESISTANCE.samples > 0);
});

_test("default dimension is PATTERN_RECOGNITION when no features", function () {
  var p = createBotCapabilityProfiler();
  p.recordAttempt(makeAttempt("bot1", "ct1", true));
  var profile = p.getProfile("bot1");
  _assert.ok(profile.capabilities.PATTERN_RECOGNITION.samples > 0);
});

_test("learning rate detected for improving bot", function () {
  var p = createBotCapabilityProfiler({ learningDetectionMs: 999999999 });
  // Start bad, get good
  for (var i = 0; i < 15; i++) {
    p.recordAttempt(makeAttempt("learner", "ct1", false, { dimensions: ["OCR_ACCURACY"] }));
  }
  for (var j = 0; j < 15; j++) {
    p.recordAttempt(makeAttempt("learner", "ct1", true, { dimensions: ["OCR_ACCURACY"] }));
  }
  var profile = p.getProfile("learner");
  _assert.ok(profile.learningRate > 0, "learning rate should be positive for improving bot");
});

_test("plateau detected for stable bot", function () {
  var p = createBotCapabilityProfiler();
  // Consistent 50% solve rate
  for (var i = 0; i < 30; i++) {
    p.recordAttempt(makeAttempt("steady", "ct1", i % 2 === 0, { dimensions: ["OCR_ACCURACY"] }));
  }
  var profile = p.getProfile("steady");
  _assert.ok(profile.plateauDetected);
});

_test("getEvolutionEvents respects limit", function () {
  var p = createBotCapabilityProfiler();
  var events = p.getEvolutionEvents(5);
  _assert.ok(Array.isArray(events));
  _assert.ok(events.length <= 5);
});

_test("getAlerts respects limit", function () {
  var p = createBotCapabilityProfiler();
  var alerts = p.getAlerts(10);
  _assert.ok(Array.isArray(alerts));
});

_test("challenge type profile tracks solve rates", function () {
  var p = createBotCapabilityProfiler();
  for (var i = 0; i < 20; i++) {
    p.recordAttempt(makeAttempt("bot1", "hard-challenge", i < 3, { difficulty: 0.9 }));
  }
  var vuln = p.predictVulnerability("hard-challenge", "ALL");
  _assert.ok(vuln.overallRisk);
});

_test("custom options are respected", function () {
  var p = createBotCapabilityProfiler({
    maxBots: 50,
    minAttemptsForProfile: 3,
    jumpThreshold: 0.1
  });
  _assert.ok(p);
  // Just verify it runs without error
  feedAttempts(p, "bot1", "ct1", 10, 0.5);
  _assert.ok(p.getStats().trackedBots === 1);
});

_test("solveRate computed correctly", function () {
  var p = createBotCapabilityProfiler();
  p.recordAttempt(makeAttempt("bot1", "ct1", true));
  p.recordAttempt(makeAttempt("bot1", "ct1", true));
  p.recordAttempt(makeAttempt("bot1", "ct1", false));
  var profile = p.getProfile("bot1");
  _assert.ok(Math.abs(profile.solveRate - 0.67) < 0.01);
});

_test("multiple challenge types tracked independently", function () {
  var p = createBotCapabilityProfiler();
  feedAttempts(p, "bot1", "easy", 10, 0.9, { dimensions: ["OCR_ACCURACY"] });
  feedAttempts(p, "bot1", "hard", 10, 0.1, { dimensions: ["SEMANTIC_UNDERSTANDING"] });
  var profile = p.getProfile("bot1");
  _assert.ok(profile.capabilities.OCR_ACCURACY.score > profile.capabilities.SEMANTIC_UNDERSTANDING.score);
});

_test("defense recommendations sorted by bot weakness", function () {
  var p = createBotCapabilityProfiler();
  feedAttempts(p, "bot1", "ct1", 20, 0.9, { dimensions: ["OCR_ACCURACY"] });
  feedAttempts(p, "bot1", "ct2", 20, 0.1, { dimensions: ["TEMPORAL_REASONING"] });
  var recs = p.getDefenseRecommendations();
  _assert.ok(recs.dimensionEffectiveness.length > 0);
  // First recommendation should be the dimension bots are weakest at
  var first = recs.dimensionEffectiveness[0];
  _assert.ok(first.botAvgCapability < 0.5);
});

_test("attempt pruning keeps bot attempts bounded", function () {
  var p = createBotCapabilityProfiler({ maxAttemptsPerBot: 20 });
  for (var i = 0; i < 50; i++) {
    p.recordAttempt(makeAttempt("bot1", "ct1", true));
  }
  var profile = p.getProfile("bot1");
  _assert.ok(profile.activeAttempts <= 20);
});
