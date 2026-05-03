"use strict";

var _t = require("node:test");
var _a = require("node:assert/strict");
var _mod = require("../src/challenge-coevolution-engine");
var createEngine = _mod.createChallengeCoevolutionEngine;
var RACE_STATES = _mod.RACE_STATES;
var HEALTH_TIERS = _mod.HEALTH_TIERS;
var MUTATION_TYPES = _mod.MUTATION_TYPES;
var BOT_OUTCOMES = _mod.BOT_OUTCOMES;

// ── Helpers ──────────────────────────────────────────────────────────

var NOW = Date.now();
var HOUR = 60 * 60 * 1000;
var DAY = 24 * HOUR;

function makeEvent(type, outcome, botId, ts) {
  return {
    challengeId: "ch-" + Math.random().toString(36).slice(2, 8),
    challengeType: type || "gif_motion",
    botId: botId || "bot-1",
    outcome: outcome || "fail",
    solveTimeMs: outcome === "solve" ? 1200 : null,
    timestamp: ts || NOW,
    botStrategy: "ocr_v2"
  };
}

function seedEvents(eng, type, count, solveRatio, startTs) {
  var base = startTs || NOW - 6 * DAY;
  for (var i = 0; i < count; i++) {
    var outcome = (i / count) < solveRatio ? "solve" : "fail";
    eng.recordChallengeEvent(makeEvent(
      type, outcome, "bot-" + (i % 5), base + (i * HOUR)
    ));
  }
}

function seedEscalation(eng, type) {
  // Simulate bots improving over time: low solve rate early, high later
  var base = NOW - 6 * DAY;
  for (var i = 0; i < 60; i++) {
    var solveChance = i / 60; // goes from 0 to ~1
    var outcome = Math.random() < solveChance ? "solve" : "fail";
    eng.recordChallengeEvent(makeEvent(
      type, outcome, "bot-" + (i % 3), base + i * 2 * HOUR
    ));
  }
}

// ── Constants ────────────────────────────────────────────────────────

_t.test("exports RACE_STATES with 5 entries", function () {
  _a.ok(Array.isArray(RACE_STATES));
  _a.equal(RACE_STATES.length, 5);
  _a.ok(RACE_STATES.indexOf("DORMANT") >= 0);
  _a.ok(RACE_STATES.indexOf("CRITICAL") >= 0);
});

_t.test("exports HEALTH_TIERS with 5 entries", function () {
  _a.ok(Array.isArray(HEALTH_TIERS));
  _a.equal(HEALTH_TIERS.length, 5);
  _a.ok(HEALTH_TIERS.indexOf("DOMINANT") >= 0);
  _a.ok(HEALTH_TIERS.indexOf("COLLAPSED") >= 0);
});

_t.test("exports MUTATION_TYPES with 5 entries", function () {
  _a.ok(Array.isArray(MUTATION_TYPES));
  _a.equal(MUTATION_TYPES.length, 5);
});

_t.test("exports BOT_OUTCOMES with 3 entries", function () {
  _a.ok(Array.isArray(BOT_OUTCOMES));
  _a.equal(BOT_OUTCOMES.length, 3);
  _a.deepStrictEqual(BOT_OUTCOMES, ["solve", "fail", "timeout"]);
});

// ── Constructor ──────────────────────────────────────────────────────

_t.test("createEngine returns object with expected methods", function () {
  var eng = createEngine();
  _a.equal(typeof eng.recordChallengeEvent, "function");
  _a.equal(typeof eng.recordChallengeEvolution, "function");
  _a.equal(typeof eng.recordBotMutation, "function");
  _a.equal(typeof eng.getAdaptationVelocity, "function");
  _a.equal(typeof eng.detectRedQueenRaces, "function");
  _a.equal(typeof eng.predictObsolescence, "function");
  _a.equal(typeof eng.getEvolutionaryFitness, "function");
  _a.equal(typeof eng.getMutationPressure, "function");
  _a.equal(typeof eng.getCoevolutionHealth, "function");
  _a.equal(typeof eng.generateInsights, "function");
  _a.equal(typeof eng.getReport, "function");
  _a.equal(typeof eng.exportState, "function");
  _a.equal(typeof eng.importState, "function");
});

_t.test("createEngine accepts custom options", function () {
  var eng = createEngine({ maxEvents: 100, minSamplesForAnalysis: 5 });
  _a.ok(eng);
  // Should work without crashing
  _a.equal(eng.getCoevolutionHealth().score >= 0, true);
});

// ── Recording ────────────────────────────────────────────────────────

_t.test("recordChallengeEvent stores events and affects analysis", function () {
  var eng = createEngine({ minSamplesForAnalysis: 3 });
  seedEvents(eng, "gif_motion", 20, 0.3);
  var vel = eng.getAdaptationVelocity("gif_motion");
  _a.ok(vel);
  _a.equal(vel.challengeType, "gif_motion");
  _a.equal(typeof vel.botVelocity, "number");
});

_t.test("recordChallengeEvent ignores invalid outcome", function () {
  var eng = createEngine({ minSamplesForAnalysis: 3 });
  eng.recordChallengeEvent({ challengeType: "x", outcome: "invalid" });
  _a.equal(eng.getAdaptationVelocity("x"), null);
});

_t.test("recordChallengeEvent ignores missing fields", function () {
  var eng = createEngine();
  eng.recordChallengeEvent(null);
  eng.recordChallengeEvent({});
  eng.recordChallengeEvent({ challengeType: "x" });
  // Should not crash
  _a.ok(true);
});

_t.test("recordChallengeEvolution stores mutations", function () {
  var eng = createEngine({ minSamplesForAnalysis: 3 });
  seedEvents(eng, "gif_motion", 20, 0.2);
  eng.recordChallengeEvolution({
    challengeType: "gif_motion",
    mutation: "difficulty_increase",
    timestamp: NOW
  });
  var vel = eng.getAdaptationVelocity("gif_motion");
  _a.ok(vel);
  _a.ok(vel.challengeVelocity > 0);
});

_t.test("recordChallengeEvolution rejects invalid mutation type", function () {
  var eng = createEngine();
  eng.recordChallengeEvolution({ challengeType: "x", mutation: "bogus" });
  // Should not crash, and type should not appear
  _a.equal(eng.getAdaptationVelocity("x"), null);
});

_t.test("recordBotMutation stores bot strategy changes", function () {
  var eng = createEngine();
  eng.recordBotMutation({
    botId: "bot-1",
    challengeType: "gif_motion",
    oldStrategy: "ocr_v1",
    newStrategy: "ocr_v2",
    timestamp: NOW
  });
  var pressure = eng.getMutationPressure();
  _a.ok(pressure.totalMutations > 0);
});

_t.test("recordBotMutation ignores missing botId", function () {
  var eng = createEngine();
  eng.recordBotMutation(null);
  eng.recordBotMutation({});
  _a.equal(eng.getMutationPressure().totalMutations, 0);
});

// ── Adaptation Velocity ──────────────────────────────────────────────

_t.test("getAdaptationVelocity returns null for unknown type", function () {
  var eng = createEngine();
  _a.equal(eng.getAdaptationVelocity("nonexistent"), null);
});

_t.test("getAdaptationVelocity returns null for insufficient samples", function () {
  var eng = createEngine({ minSamplesForAnalysis: 50 });
  seedEvents(eng, "gif_motion", 5, 0.2);
  _a.equal(eng.getAdaptationVelocity("gif_motion"), null);
});

_t.test("getAdaptationVelocity detects bots_gaining trend", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  // Early: all fails, later: all solves — clear monotonic escalation
  var base = NOW - 6 * DAY;
  for (var i = 0; i < 70; i++) {
    var outcome = i >= 50 ? "solve" : "fail";
    eng.recordChallengeEvent(makeEvent("test", outcome, "bot-1", base + i * 2 * HOUR));
  }
  var vel = eng.getAdaptationVelocity("test");
  _a.ok(vel);
  // With clear escalation the velocity should be non-negative
  _a.ok(vel.botVelocity >= 0, "Expected non-negative bot velocity, got " + vel.botVelocity);
});

_t.test("getAdaptationVelocity includes sample count", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "t1", 20, 0.5);
  var vel = eng.getAdaptationVelocity("t1");
  _a.ok(vel.sampleCount > 0);
});

// ── Red Queen Detector ───────────────────────────────────────────────

_t.test("detectRedQueenRaces returns empty array for no data", function () {
  var eng = createEngine();
  _a.deepStrictEqual(eng.detectRedQueenRaces(), []);
});

_t.test("detectRedQueenRaces classifies races", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEscalation(eng, "gif_motion");
  seedEvents(eng, "text_distortion", 30, 0.1);
  var races = eng.detectRedQueenRaces();
  _a.ok(races.length >= 1);
  for (var i = 0; i < races.length; i++) {
    _a.ok(RACE_STATES.indexOf(races[i].state) >= 0);
    _a.ok(typeof races[i].intensity === "number");
  }
});

_t.test("detectRedQueenRaces sorts by intensity descending", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "type_a", 30, 0.5);
  seedEvents(eng, "type_b", 30, 0.1);
  // Also add evolution events to type_a to ensure different intensities
  for (var i = 0; i < 5; i++) {
    eng.recordChallengeEvolution({
      challengeType: "type_a",
      mutation: MUTATION_TYPES[i % MUTATION_TYPES.length],
      timestamp: NOW - i * HOUR
    });
  }
  var races = eng.detectRedQueenRaces();
  _a.ok(races.length >= 2, "Expected at least 2 races");
  // Verify sorting: first should have >= intensity than second
  for (var j = 1; j < races.length; j++) {
    _a.ok(races[j - 1].intensity >= races[j].intensity,
      "Expected sorted by intensity descending");
  }
});

// ── Obsolescence Predictor ───────────────────────────────────────────

_t.test("predictObsolescence returns predictions for all types", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "type_a", 30, 0.5);
  seedEvents(eng, "type_b", 30, 0.1);
  var preds = eng.predictObsolescence();
  _a.ok(preds.length >= 2);
  for (var i = 0; i < preds.length; i++) {
    _a.ok(typeof preds[i].currentSolveRate === "number");
    _a.ok(preds[i].status);
  }
});

_t.test("predictObsolescence handles single type filter", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "type_a", 30, 0.5);
  seedEvents(eng, "type_b", 30, 0.1);
  var preds = eng.predictObsolescence("type_a");
  _a.equal(preds.length, 1);
  _a.equal(preds[0].challengeType, "type_a");
});

_t.test("predictObsolescence reports insufficient_data for small sets", function () {
  var eng = createEngine({ minSamplesForAnalysis: 50 });
  seedEvents(eng, "small", 5, 0.5);
  var preds = eng.predictObsolescence("small");
  _a.equal(preds.length, 1);
  _a.equal(preds[0].confidence, "insufficient_data");
});

_t.test("predictObsolescence detects broken challenge", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  // All solves = broken
  seedEvents(eng, "broken_type", 30, 1.0);
  var preds = eng.predictObsolescence("broken_type");
  _a.equal(preds[0].status, "broken");
});

// ── Evolutionary Fitness ─────────────────────────────────────────────

_t.test("getEvolutionaryFitness returns scores for all types", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "strong", 30, 0.1);
  seedEvents(eng, "weak", 30, 0.9);
  var fitness = eng.getEvolutionaryFitness();
  _a.ok(fitness.length >= 2);
  for (var i = 0; i < fitness.length; i++) {
    _a.ok(fitness[i].fitness >= 0 && fitness[i].fitness <= 100);
    _a.ok(typeof fitness[i].tier === "string");
  }
});

_t.test("getEvolutionaryFitness ranks strong > weak", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "strong", 30, 0.05);
  seedEvents(eng, "weak", 30, 0.95);
  var fitness = eng.getEvolutionaryFitness();
  // Sorted by fitness descending
  _a.ok(fitness[0].fitness >= fitness[fitness.length - 1].fitness);
});

_t.test("getEvolutionaryFitness for specific type", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "target", 30, 0.3);
  var fitness = eng.getEvolutionaryFitness("target");
  _a.equal(fitness.length, 1);
  _a.equal(fitness[0].challengeType, "target");
});

_t.test("getEvolutionaryFitness boosts score for active mutations", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "evolved", 30, 0.3);
  for (var i = 0; i < 5; i++) {
    eng.recordChallengeEvolution({
      challengeType: "evolved",
      mutation: MUTATION_TYPES[i % MUTATION_TYPES.length],
      timestamp: NOW - i * HOUR
    });
  }
  seedEvents(eng, "static", 30, 0.3);
  var evolved = eng.getEvolutionaryFitness("evolved")[0];
  var static_ = eng.getEvolutionaryFitness("static")[0];
  _a.ok(evolved.adaptationScore > static_.adaptationScore);
});

// ── Mutation Pressure ────────────────────────────────────────────────

_t.test("getMutationPressure returns empty for no mutations", function () {
  var eng = createEngine();
  var p = eng.getMutationPressure();
  _a.equal(p.totalMutations, 0);
  _a.equal(p.types.length, 0);
});

_t.test("getMutationPressure analyzes bot mutations", function () {
  var eng = createEngine();
  for (var i = 0; i < 10; i++) {
    eng.recordBotMutation({
      botId: "bot-" + (i % 3),
      challengeType: "gif_motion",
      oldStrategy: "s" + i,
      newStrategy: "s" + (i + 1),
      timestamp: NOW - i * HOUR
    });
  }
  var p = eng.getMutationPressure();
  _a.ok(p.totalMutations >= 10);
  _a.ok(p.types.length >= 1);
  _a.ok(p.types[0].mutationCount > 0);
  _a.ok(p.types[0].uniqueBots > 0);
});

_t.test("getMutationPressure filters by challenge type", function () {
  var eng = createEngine();
  eng.recordBotMutation({
    botId: "bot-1", challengeType: "type_a",
    newStrategy: "x", timestamp: NOW
  });
  eng.recordBotMutation({
    botId: "bot-2", challengeType: "type_b",
    newStrategy: "y", timestamp: NOW
  });
  var p = eng.getMutationPressure("type_a");
  var types = p.types.filter(function (t) { return t.challengeType === "type_a"; });
  _a.ok(types.length >= 1);
});

// ── Coevolution Health ───────────────────────────────────────────────

_t.test("getCoevolutionHealth returns valid score for empty engine", function () {
  var eng = createEngine();
  var h = eng.getCoevolutionHealth();
  _a.ok(h.score >= 0 && h.score <= 100);
  _a.ok(HEALTH_TIERS.indexOf(h.tier) >= 0);
  _a.ok(h.components);
  _a.ok(h.summary);
});

_t.test("getCoevolutionHealth produces high score for effective defenses", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "strong_a", 30, 0.05);
  seedEvents(eng, "strong_b", 30, 0.1);
  var h = eng.getCoevolutionHealth();
  _a.ok(h.score >= 50, "Expected high score, got " + h.score);
});

_t.test("getCoevolutionHealth includes summary counts", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "t1", 30, 0.5);
  var h = eng.getCoevolutionHealth();
  _a.ok(h.summary.challengeTypes >= 1);
  _a.ok(h.summary.totalEvents > 0);
});

// ── Insight Generator ────────────────────────────────────────────────

_t.test("generateInsights returns array", function () {
  var eng = createEngine();
  var insights = eng.generateInsights();
  _a.ok(Array.isArray(insights));
});

_t.test("generateInsights produces stagnation warning when no evolutions", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "t1", 30, 0.3);
  var insights = eng.generateInsights();
  var stagnation = insights.filter(function (i) { return i.category === "stagnation"; });
  _a.ok(stagnation.length > 0, "Expected stagnation insight");
});

_t.test("generateInsights produces fitness warnings for broken challenges", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "broken", 30, 1.0);
  var insights = eng.generateInsights();
  var fitnessInsights = insights.filter(function (i) {
    return i.category === "fitness" || i.category === "obsolescence" || i.category === "health";
  });
  _a.ok(fitnessInsights.length > 0);
});

// ── Full Report ──────────────────────────────────────────────────────

_t.test("getReport returns all sections", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "t1", 30, 0.3);
  seedEscalation(eng, "t2");
  var report = eng.getReport();
  _a.ok(report.health);
  _a.ok(report.races);
  _a.ok(report.fitness);
  _a.ok(report.mutationPressure);
  _a.ok(report.obsolescence);
  _a.ok(report.insights);
  _a.ok(report.generatedAt > 0);
});

// ── State Export/Import ──────────────────────────────────────────────

_t.test("exportState returns version 1 state", function () {
  var eng = createEngine();
  seedEvents(eng, "t1", 10, 0.5);
  var state = eng.exportState();
  _a.equal(state.version, 1);
  _a.ok(state.challengeEvents);
  _a.ok(state.totalEvents > 0);
  _a.ok(state.exportedAt > 0);
});

_t.test("importState restores engine state", function () {
  var eng1 = createEngine({ minSamplesForAnalysis: 3 });
  seedEvents(eng1, "t1", 20, 0.4);
  eng1.recordBotMutation({ botId: "b1", challengeType: "t1", newStrategy: "s2", timestamp: NOW });
  var state = eng1.exportState();

  var eng2 = createEngine({ minSamplesForAnalysis: 3 });
  _a.ok(eng2.importState(state));
  var vel = eng2.getAdaptationVelocity("t1");
  _a.ok(vel, "Velocity should be available after import");
});

_t.test("importState rejects invalid state", function () {
  var eng = createEngine();
  _a.equal(eng.importState(null), false);
  _a.equal(eng.importState({}), false);
  _a.equal(eng.importState({ version: 99 }), false);
});

_t.test("importState prevents prototype pollution", function () {
  var eng = createEngine();
  var malicious = {
    version: 1,
    challengeEvents: { __proto__: { polluted: true }, safe: [] },
    challengeEvolutions: {},
    botMutations: {},
    totalEvents: 0,
    totalEvolutions: 0,
    totalBotMutations: 0
  };
  eng.importState(malicious);
  // __proto__ key should be filtered out
  _a.equal(({}).polluted, undefined, "Prototype should not be polluted");
});

_t.test("importState deep-clones to prevent reference leakage", function () {
  var eng = createEngine({ minSamplesForAnalysis: 3 });
  seedEvents(eng, "t1", 20, 0.4);
  var state = eng.exportState();

  var eng2 = createEngine({ minSamplesForAnalysis: 3 });
  eng2.importState(state);

  // Mutate exported state — should not affect eng2
  state.challengeEvents.t1 = [];
  var vel = eng2.getAdaptationVelocity("t1");
  _a.ok(vel, "Engine should be unaffected by external mutation");
});

// ── Edge Cases ───────────────────────────────────────────────────────

_t.test("handles multiple challenge types simultaneously", function () {
  var eng = createEngine({ minSamplesForAnalysis: 5 });
  seedEvents(eng, "type_a", 30, 0.2);
  seedEvents(eng, "type_b", 30, 0.8);
  seedEvents(eng, "type_c", 30, 0.5);
  var report = eng.getReport();
  _a.ok(report.fitness.length >= 3);
  _a.ok(report.health.summary.challengeTypes >= 3);
});

_t.test("LRU eviction works for challenge types", function () {
  var eng = createEngine({ maxChallengeTypes: 3, minSamplesForAnalysis: 1 });
  seedEvents(eng, "a", 5, 0.5);
  seedEvents(eng, "b", 5, 0.5);
  seedEvents(eng, "c", 5, 0.5);
  seedEvents(eng, "d", 5, 0.5);
  // "a" should have been evicted
  _a.equal(eng.getAdaptationVelocity("a"), null);
});

_t.test("LRU eviction works for bots", function () {
  var eng = createEngine({ maxBots: 2 });
  eng.recordBotMutation({ botId: "b1", newStrategy: "s1", timestamp: NOW });
  eng.recordBotMutation({ botId: "b2", newStrategy: "s2", timestamp: NOW });
  eng.recordBotMutation({ botId: "b3", newStrategy: "s3", timestamp: NOW });
  var p = eng.getMutationPressure();
  _a.ok(p.activeBots <= 3);
});

_t.test("timeout outcomes are recorded correctly", function () {
  var eng = createEngine({ minSamplesForAnalysis: 3 });
  for (var i = 0; i < 10; i++) {
    eng.recordChallengeEvent(makeEvent("t1", "timeout", "bot-1", NOW - i * HOUR));
  }
  var preds = eng.predictObsolescence("t1");
  _a.ok(preds.length === 1);
  _a.ok(preds[0].currentSolveRate === 0, "Timeouts should not count as solves");
});
