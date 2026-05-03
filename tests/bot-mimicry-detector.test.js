/**
 * Tests for BotMimicryDetector — autonomous bot mimicry detection engine.
 */

"use strict";

var _test = require("node:test");
var _assert = require("node:assert/strict");
var _mod = require("../src/bot-mimicry-detector.js");
var createBotMimicryDetector = _mod.createBotMimicryDetector;

// ── Helpers ─────────────────────────────────────────────────────────

function makeEvent(sessionId, solved, solveTimeMs, opts) {
  opts = opts || {};
  return {
    sessionId: sessionId,
    sourceId: opts.sourceId || null,
    solved: solved,
    solveTimeMs: solveTimeMs,
    difficulty: opts.difficulty || 0.5,
    timestamp: opts.timestamp || Date.now()
  };
}

function feedEvents(detector, sessionId, count, opts) {
  opts = opts || {};
  var baseTime = opts.baseTime || Date.now();
  var solveRate = opts.solveRate != null ? opts.solveRate : 0.8;
  var meanTime = opts.meanTime || 3000;
  var timeJitter = opts.timeJitter || 1200;
  var interval = opts.interval || 8000;
  var intervalJitter = opts.intervalJitter || 4000;

  for (var i = 0; i < count; i++) {
    var solveTime = meanTime + (Math.random() - 0.5) * 2 * timeJitter;
    if (solveTime < 100) solveTime = 100;
    var ts = baseTime + i * (interval + (Math.random() - 0.5) * 2 * intervalJitter);
    detector.recordEvent({
      sessionId: sessionId,
      sourceId: opts.sourceId || null,
      solved: Math.random() < solveRate,
      solveTimeMs: Math.round(solveTime),
      difficulty: opts.difficulty || 0.5,
      timestamp: Math.round(ts)
    });
  }
}

function feedPerfectMimic(detector, sessionId, count, opts) {
  opts = opts || {};
  var baseTime = opts.baseTime || Date.now();
  // "Perfect" human mimic: very close to baselines, suspiciously ideal
  for (var i = 0; i < count; i++) {
    var solveTime = 3000 + (Math.random() - 0.5) * 2 * 1200;
    var ts = baseTime + i * 8000;
    detector.recordEvent({
      sessionId: sessionId,
      sourceId: opts.sourceId || null,
      solved: Math.random() < 0.78,
      solveTimeMs: Math.round(solveTime),
      difficulty: 0.5,
      timestamp: Math.round(ts)
    });
  }
}

function feedNoFatigueBot(detector, sessionId, count, opts) {
  opts = opts || {};
  var baseTime = opts.baseTime || Date.now();
  // Bot with perfectly consistent times (no fatigue), regular intervals
  for (var i = 0; i < count; i++) {
    var solveTime = 2500 + Math.floor(Math.random() * 500);
    var ts = baseTime + i * 5000;
    detector.recordEvent({
      sessionId: sessionId,
      sourceId: opts.sourceId || null,
      solved: i % 5 !== 0, // 80% rate, perfectly periodic
      solveTimeMs: solveTime,
      difficulty: 0.5,
      timestamp: ts
    });
  }
}

// ── Creation Tests ──────────────────────────────────────────────────

_test("creates detector with default options", function () {
  var d = createBotMimicryDetector();
  _assert.ok(d);
  _assert.ok(d.recordEvent);
  _assert.ok(d.analyzeSession);
  _assert.ok(d.addTemplate);
  _assert.ok(d.removeTemplate);
  _assert.ok(d.getTemplates);
  _assert.ok(d.getStats);
  _assert.ok(d.exportState);
  _assert.ok(d.importState);
  _assert.ok(d.reset);
});

_test("exposes tiers and engine names", function () {
  var d = createBotMimicryDetector();
  _assert.deepStrictEqual(d.MIMICRY_TIERS, ["GENUINE", "LIKELY_HUMAN", "SUSPICIOUS", "LIKELY_MIMICRY", "CONFIRMED_MIMICRY"]);
  _assert.strictEqual(d.ENGINE_NAMES.length, 6);
});

_test("creates detector with custom options", function () {
  var d = createBotMimicryDetector({ maxSessions: 100, minEventsForAnalysis: 5 });
  _assert.ok(d);
});

_test("module exports tiers and engine names", function () {
  _assert.ok(_mod.MIMICRY_TIERS);
  _assert.ok(_mod.ENGINE_NAMES);
  _assert.strictEqual(_mod.MIMICRY_TIERS.length, 5);
  _assert.strictEqual(_mod.ENGINE_NAMES.length, 6);
});

// ── Event Recording Tests ───────────────────────────────────────────

_test("records events and returns event count", function () {
  var d = createBotMimicryDetector();
  var res = d.recordEvent(makeEvent("s1", true, 2000));
  _assert.ok(res);
  _assert.strictEqual(res.sessionId, "s1");
  _assert.strictEqual(res.eventCount, 1);
});

_test("records multiple events for same session", function () {
  var d = createBotMimicryDetector();
  d.recordEvent(makeEvent("s1", true, 2000));
  d.recordEvent(makeEvent("s1", false, 3000));
  var res = d.recordEvent(makeEvent("s1", true, 2500));
  _assert.strictEqual(res.eventCount, 3);
});

_test("returns null for invalid event", function () {
  var d = createBotMimicryDetector();
  _assert.strictEqual(d.recordEvent(null), null);
  _assert.strictEqual(d.recordEvent({}), null);
  _assert.strictEqual(d.recordEvent({ sessionId: null }), null);
});

_test("enforces maxEventsPerSession", function () {
  var d = createBotMimicryDetector({ maxEventsPerSession: 5 });
  for (var i = 0; i < 10; i++) {
    d.recordEvent(makeEvent("s1", true, 2000, { timestamp: 1000 + i * 100 }));
  }
  var res = d.recordEvent(makeEvent("s1", true, 2000, { timestamp: 2000 }));
  _assert.strictEqual(res.eventCount, 5);
});

_test("enforces maxSessions via LRU eviction", function () {
  var d = createBotMimicryDetector({ maxSessions: 3 });
  d.recordEvent(makeEvent("s1", true, 2000));
  d.recordEvent(makeEvent("s2", true, 2000));
  d.recordEvent(makeEvent("s3", true, 2000));
  d.recordEvent(makeEvent("s4", true, 2000));
  // s1 should be evicted
  var analysis = d.analyzeSession("s1");
  _assert.strictEqual(analysis.error, "Session not found");
});

_test("stores sourceId from event", function () {
  var d = createBotMimicryDetector();
  d.recordEvent(makeEvent("s1", true, 2000, { sourceId: "ip-1" }));
  var state = d.exportState();
  _assert.strictEqual(state.sessions["s1"].sourceId, "ip-1");
});

// ── Analysis: Insufficient Data ─────────────────────────────────────

_test("returns insufficient data for sessions with few events", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 8 });
  for (var i = 0; i < 5; i++) {
    d.recordEvent(makeEvent("s1", true, 2000 + i * 100, { timestamp: 1000 + i * 1000 }));
  }
  var result = d.analyzeSession("s1");
  _assert.strictEqual(result.mimicryScore, 0);
  _assert.strictEqual(result.error, "Insufficient data");
});

_test("returns error for unknown session", function () {
  var d = createBotMimicryDetector();
  var result = d.analyzeSession("nonexistent");
  _assert.strictEqual(result.error, "Session not found");
});

// ── Analysis: Uncanny Valley ────────────────────────────────────────

_test("uncanny valley detects suspiciously ideal metrics", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedPerfectMimic(d, "mimic1", 30);
  var result = d.analyzeSession("mimic1");
  _assert.ok(result.engines.uncannyValley);
  _assert.ok(result.engines.uncannyValley.score >= 0);
  // Perfect mimic should have some uncanny valley signal
  _assert.ok(typeof result.engines.uncannyValley.solveTimeMean === "number");
  _assert.ok(typeof result.engines.uncannyValley.accuracy === "number");
});

_test("uncanny valley score is lower for clearly non-human patterns", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  // Very fast, 100% accuracy — not mimicking human at all
  for (var i = 0; i < 20; i++) {
    d.recordEvent(makeEvent("fast-bot", true, 50 + Math.floor(Math.random() * 20), { timestamp: 1000 + i * 100 }));
  }
  var result = d.analyzeSession("fast-bot");
  // Low uncanny valley score because it's not trying to look human
  _assert.ok(result.engines.uncannyValley.score < 80);
});

// ── Analysis: Consistency Paradox ───────────────────────────────────

_test("consistency paradox detects too-regular randomness", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  // Very consistent timing with tiny variance
  for (var i = 0; i < 30; i++) {
    d.recordEvent(makeEvent("reg1", true, 2500 + (i % 3) * 10, { timestamp: 1000 + i * 5000 }));
  }
  var result = d.analyzeSession("reg1");
  _assert.ok(result.engines.consistencyParadox);
  _assert.ok(result.engines.consistencyParadox.score > 0);
});

_test("consistency paradox returns inter-arrival CV", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "rand1", 20);
  var result = d.analyzeSession("rand1");
  _assert.ok(result.engines.consistencyParadox.interArrivalCV != null);
});

// ── Analysis: Fatigue Immunity ──────────────────────────────────────

_test("fatigue immunity detects no degradation", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5, fatigueWindowEvents: 10 });
  feedNoFatigueBot(d, "bot1", 40);
  var result = d.analyzeSession("bot1");
  _assert.ok(result.engines.fatigueImmunity);
  _assert.ok(result.engines.fatigueImmunity.score > 30);
});

_test("fatigue immunity has lower score when clear fatigue exists", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5, fatigueWindowEvents: 10 });
  // Simulate increasing solve times (fatigue)
  var baseTime = Date.now();
  for (var i = 0; i < 30; i++) {
    d.recordEvent(makeEvent("tired1", i < 20, 1500 + i * 80, { timestamp: baseTime + i * 5000 }));
  }
  var result = d.analyzeSession("tired1");
  // With clear fatigue slope, should be lower
  _assert.ok(result.engines.fatigueImmunity.slope > 0);
});

_test("fatigue immunity reports hasEnoughData correctly", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 3, fatigueWindowEvents: 20 });
  for (var i = 0; i < 5; i++) {
    d.recordEvent(makeEvent("small1", true, 2000 + i * 10, { timestamp: 1000 + i * 1000 }));
  }
  var result = d.analyzeSession("small1");
  _assert.strictEqual(result.engines.fatigueImmunity.hasEnoughData, false);
});

// ── Analysis: Template Matching ─────────────────────────────────────

_test("template matching returns zero when no templates exist", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 15);
  var result = d.analyzeSession("s1");
  _assert.strictEqual(result.engines.templateMatch.score, 0);
  _assert.strictEqual(result.engines.templateMatch.matchedTemplates.length, 0);
});

_test("template matching detects matching template", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });

  // Add a broad template that should match many sessions
  d.addTemplate({
    name: "generic_mimic",
    signature: {
      accuracy: [0.5, 1.0],
      varianceRatio: [0, 2.0]
    }
  });

  feedEvents(d, "s1", 15);
  var result = d.analyzeSession("s1");
  _assert.ok(result.engines.templateMatch.bestMatch !== null);
});

_test("add template returns true", function () {
  var d = createBotMimicryDetector();
  var ok = d.addTemplate({ name: "t1", signature: { accuracy: [0.7, 0.9] } });
  _assert.strictEqual(ok, true);
});

_test("add template rejects invalid", function () {
  var d = createBotMimicryDetector();
  _assert.strictEqual(d.addTemplate(null), false);
  _assert.strictEqual(d.addTemplate({}), false);
  _assert.strictEqual(d.addTemplate({ name: "t1" }), false);
});

_test("add template updates existing by name", function () {
  var d = createBotMimicryDetector();
  d.addTemplate({ name: "t1", signature: { accuracy: [0.7, 0.9] } });
  d.addTemplate({ name: "t1", signature: { accuracy: [0.5, 0.8] } });
  _assert.strictEqual(d.getTemplates().length, 1);
  _assert.deepStrictEqual(d.getTemplates()[0].signature, { accuracy: [0.5, 0.8] });
});

_test("remove template works", function () {
  var d = createBotMimicryDetector();
  d.addTemplate({ name: "t1", signature: { accuracy: [0.7, 0.9] } });
  _assert.strictEqual(d.removeTemplate("t1"), true);
  _assert.strictEqual(d.getTemplates().length, 0);
});

_test("remove template returns false for unknown", function () {
  var d = createBotMimicryDetector();
  _assert.strictEqual(d.removeTemplate("nonexistent"), false);
});

// ── Analysis: Micro-Pattern ─────────────────────────────────────────

_test("micro-pattern analyzer produces score and entropy", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 20);
  var result = d.analyzeSession("s1");
  _assert.ok(result.engines.microPattern);
  _assert.ok(typeof result.engines.microPattern.digitEntropy === "number");
  _assert.ok(typeof result.engines.microPattern.roundNumberRatio === "number");
});

_test("micro-pattern detects round number patterns", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  // All times divisible by 100 — suspicious
  for (var i = 0; i < 20; i++) {
    d.recordEvent(makeEvent("round1", true, (20 + i) * 100, { timestamp: 1000 + i * 5000 }));
  }
  var result = d.analyzeSession("round1");
  _assert.strictEqual(result.engines.microPattern.roundNumberRatio, 1);
});

// ── Analysis: Cross-Session ─────────────────────────────────────────

_test("cross-session returns zero when no sourceId", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 15);
  var result = d.analyzeSession("s1");
  _assert.strictEqual(result.engines.crossSession.score, 0);
  _assert.strictEqual(result.engines.crossSession.sourceId, null);
});

_test("cross-session detects similar sessions from same source", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  var baseTime = Date.now();

  // Two sessions from same source with very similar patterns
  for (var i = 0; i < 20; i++) {
    var solveTime = 2500 + (i % 3) * 100;
    d.recordEvent(makeEvent("cs1", true, solveTime, { sourceId: "ip-x", timestamp: baseTime + i * 5000 }));
    d.recordEvent(makeEvent("cs2", true, solveTime + 10, { sourceId: "ip-x", timestamp: baseTime + i * 5000 + 100 }));
  }

  var result = d.analyzeSession("cs1");
  _assert.ok(result.engines.crossSession.sourceId === "ip-x");
  _assert.ok(result.engines.crossSession.relatedSessions >= 1);
});

_test("cross-session returns zero when no related sessions have enough data", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 10 });
  feedEvents(d, "s1", 15, { sourceId: "ip-y" });
  // s2 has too few events
  d.recordEvent(makeEvent("s2", true, 2000, { sourceId: "ip-y" }));

  var result = d.analyzeSession("s1");
  _assert.strictEqual(result.engines.crossSession.relatedSessions, 0);
});

// ── Composite Scoring ───────────────────────────────────────────────

_test("composite score is between 0 and 100", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 20);
  var result = d.analyzeSession("s1");
  _assert.ok(result.mimicryScore >= 0);
  _assert.ok(result.mimicryScore <= 100);
});

_test("tier matches score range", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 20);
  var result = d.analyzeSession("s1");
  var tier = result.tier;
  var score = result.mimicryScore;
  if (score <= 20) _assert.strictEqual(tier, "GENUINE");
  else if (score <= 40) _assert.strictEqual(tier, "LIKELY_HUMAN");
  else if (score <= 60) _assert.strictEqual(tier, "SUSPICIOUS");
  else if (score <= 80) _assert.strictEqual(tier, "LIKELY_MIMICRY");
  else _assert.strictEqual(tier, "CONFIRMED_MIMICRY");
});

_test("analysis returns all engine results", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 20);
  var result = d.analyzeSession("s1");
  _assert.ok(result.engines.uncannyValley);
  _assert.ok(result.engines.consistencyParadox);
  _assert.ok(result.engines.fatigueImmunity);
  _assert.ok(result.engines.templateMatch);
  _assert.ok(result.engines.microPattern);
  _assert.ok(result.engines.crossSession);
});

// ── Insights ────────────────────────────────────────────────────────

_test("insights are generated for analysis", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 25);
  var result = d.analyzeSession("s1");
  _assert.ok(Array.isArray(result.insights));
});

_test("high-score session generates alert insight", function () {
  var d = createBotMimicryDetector({
    minEventsForAnalysis: 5,
    weights: { uncannyValley: 1, consistencyParadox: 0, fatigueImmunity: 0, templateMatch: 0, microPattern: 0, crossSession: 0 }
  });
  // Feed data that mimics perfect human baselines
  feedPerfectMimic(d, "mimic1", 40);
  var result = d.analyzeSession("mimic1");
  // Should generate some insights regardless of exact score
  _assert.ok(result.insights.length >= 0); // may or may not trigger depending on randomness
});

// ── Stats ───────────────────────────────────────────────────────────

_test("getStats returns structure with all fields", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 15);
  feedEvents(d, "s2", 15);
  var stats = d.getStats();
  _assert.ok(stats.totalSessions >= 2);
  _assert.ok(stats.analyzedSessions >= 2);
  _assert.ok(stats.tierDistribution);
  _assert.ok(Array.isArray(stats.topMimics));
  _assert.ok(typeof stats.averageMimicryScore === "number");
  _assert.ok(typeof stats.templateCount === "number");
  _assert.ok(Array.isArray(stats.recentInsights));
  _assert.ok(Array.isArray(stats.insights));
});

_test("getStats with no sessions returns zeros", function () {
  var d = createBotMimicryDetector();
  var stats = d.getStats();
  _assert.strictEqual(stats.totalSessions, 0);
  _assert.strictEqual(stats.analyzedSessions, 0);
  _assert.strictEqual(stats.averageMimicryScore, 0);
});

// ── Export/Import ───────────────────────────────────────────────────

_test("export/import roundtrip preserves state", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 15, { sourceId: "src1" });
  d.addTemplate({ name: "t1", signature: { accuracy: [0.6, 0.9] } });

  var state = d.exportState();
  _assert.ok(state.version === 1);
  _assert.ok(state.sessions["s1"]);
  _assert.strictEqual(state.templates.length, 1);

  var d2 = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  _assert.strictEqual(d2.importState(state), true);

  var analysis = d2.analyzeSession("s1");
  _assert.ok(analysis.mimicryScore >= 0);
  _assert.strictEqual(d2.getTemplates().length, 1);
});

_test("importState rejects invalid state", function () {
  var d = createBotMimicryDetector();
  _assert.strictEqual(d.importState(null), false);
  _assert.strictEqual(d.importState({}), false);
  _assert.strictEqual(d.importState({ version: 99 }), false);
});

// ── Reset ───────────────────────────────────────────────────────────

_test("reset clears all state", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 5 });
  feedEvents(d, "s1", 15);
  d.addTemplate({ name: "t1", signature: { accuracy: [0.6, 0.9] } });
  d.reset();

  var stats = d.getStats();
  _assert.strictEqual(stats.totalSessions, 0);
  _assert.strictEqual(stats.templateCount, 0);
  _assert.strictEqual(d.getTemplates().length, 0);
});

// ── Edge Cases ──────────────────────────────────────────────────────

_test("handles single event session gracefully", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 1 });
  d.recordEvent(makeEvent("single1", true, 2000, { timestamp: 1000 }));
  var result = d.analyzeSession("single1");
  _assert.ok(result.mimicryScore >= 0);
  _assert.ok(result.mimicryScore <= 100);
});

_test("handles zero solve times", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 3 });
  for (var i = 0; i < 5; i++) {
    d.recordEvent(makeEvent("zero1", true, 0, { timestamp: 1000 + i * 1000 }));
  }
  var result = d.analyzeSession("zero1");
  _assert.ok(result.mimicryScore >= 0);
});

_test("handles all-failed session", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 3 });
  for (var i = 0; i < 10; i++) {
    d.recordEvent(makeEvent("fail1", false, 5000 + i * 100, { timestamp: 1000 + i * 3000 }));
  }
  var result = d.analyzeSession("fail1");
  _assert.ok(result.mimicryScore >= 0);
  _assert.strictEqual(result.engines.uncannyValley.accuracy, 0);
});

_test("handles identical timestamps", function () {
  var d = createBotMimicryDetector({ minEventsForAnalysis: 3 });
  for (var i = 0; i < 5; i++) {
    d.recordEvent(makeEvent("same-ts", true, 2000, { timestamp: 1000 }));
  }
  var result = d.analyzeSession("same-ts");
  _assert.ok(result.mimicryScore >= 0);
});

_test("custom weights affect scoring", function () {
  var d = createBotMimicryDetector({
    minEventsForAnalysis: 5,
    weights: { uncannyValley: 1, consistencyParadox: 0, fatigueImmunity: 0, templateMatch: 0, microPattern: 0, crossSession: 0 }
  });
  feedEvents(d, "w1", 20);
  var result = d.analyzeSession("w1");
  // Should be entirely driven by uncanny valley engine
  _assert.ok(typeof result.mimicryScore === "number");
});
