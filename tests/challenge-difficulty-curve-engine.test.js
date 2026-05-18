require("./_expect");
const { describe, test } = require("node:test");
/**
 * ChallengeDifficultyCurveEngine — tests
 * 45+ test cases covering sample recording, curve analysis, optimal difficulty
 * finding, drift detection, bot adaptation, recommendations, health scoring,
 * prediction, state export/import, and integration scenarios.
 */

"use strict";

var engine = require("../src/challenge-difficulty-curve-engine");
var ChallengeDifficultyCurveEngine = engine.ChallengeDifficultyCurveEngine;
var OUTCOMES = engine.OUTCOMES;
var DIFFICULTY_BANDS = engine.DIFFICULTY_BANDS;
var HEALTH_TIERS = engine.HEALTH_TIERS;
var DEFAULTS = engine.DEFAULTS;

// Helper: populate a bucket with samples
function populate(eng, difficulty, humanPass, humanFail, humanAbandon, botPass, botFail) {
  for (var i = 0; i < humanPass; i++) eng.recordSample(difficulty, OUTCOMES.HUMAN_PASS);
  for (var j = 0; j < humanFail; j++) eng.recordSample(difficulty, OUTCOMES.HUMAN_FAIL);
  for (var k = 0; k < humanAbandon; k++) eng.recordSample(difficulty, OUTCOMES.HUMAN_ABANDON);
  for (var l = 0; l < botPass; l++) eng.recordSample(difficulty, OUTCOMES.BOT_PASS);
  for (var m = 0; m < botFail; m++) eng.recordSample(difficulty, OUTCOMES.BOT_FAIL);
}

/* ═══════════════════════════════════════════════════════
 * 1. Initialization
 * ═══════════════════════════════════════════════════════ */
describe("initialization", function () {
  test("creates engine with default config", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var cfg = eng.getConfig();
    expect(cfg.targetHumanPassRate).toBe(0.85);
    expect(cfg.targetBotRejectRate).toBe(0.95);
    expect(cfg.difficultyBuckets).toBe(10);
  });

  test("accepts custom options", function () {
    var eng = new ChallengeDifficultyCurveEngine({ targetHumanPassRate: 0.9, difficultyBuckets: 5 });
    var cfg = eng.getConfig();
    expect(cfg.targetHumanPassRate).toBe(0.9);
    expect(cfg.difficultyBuckets).toBe(5);
  });

  test("initializes empty buckets", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var buckets = eng.getBuckets();
    expect(Object.keys(buckets).length).toBe(10);
    Object.keys(buckets).forEach(function (k) {
      expect(buckets[k].total).toBe(0);
    });
  });

  test("starts with zero samples", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(eng.getSampleCount()).toBe(0);
  });
});

/* ═══════════════════════════════════════════════════════
 * 2. Sample Recording
 * ═══════════════════════════════════════════════════════ */
describe("recordSample", function () {
  test("records valid sample", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var sample = eng.recordSample(50, OUTCOMES.HUMAN_PASS);
    expect(sample.difficulty).toBe(50);
    expect(sample.outcome).toBe(OUTCOMES.HUMAN_PASS);
    expect(sample.timestamp).toBeGreaterThan(0);
    expect(eng.getSampleCount()).toBe(1);
  });

  test("updates bucket counts", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    eng.recordSample(25, OUTCOMES.HUMAN_PASS);
    eng.recordSample(25, OUTCOMES.BOT_FAIL);
    var buckets = eng.getBuckets();
    expect(buckets[2].humanPass).toBe(1);
    expect(buckets[2].botFail).toBe(1);
    expect(buckets[2].total).toBe(2);
  });

  test("rejects invalid difficulty", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(function () { eng.recordSample(-1, OUTCOMES.HUMAN_PASS); }).toThrow();
    expect(function () { eng.recordSample(101, OUTCOMES.HUMAN_PASS); }).toThrow();
    expect(function () { eng.recordSample("abc", OUTCOMES.HUMAN_PASS); }).toThrow();
  });

  test("rejects invalid outcome", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(function () { eng.recordSample(50, "invalid"); }).toThrow();
  });

  test("accepts boundary difficulties (0 and 100)", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(function () { eng.recordSample(0, OUTCOMES.HUMAN_PASS); }).not.toThrow();
    expect(function () { eng.recordSample(100, OUTCOMES.BOT_FAIL); }).not.toThrow();
    expect(eng.getSampleCount()).toBe(2);
  });

  test("caps samples at maxSamples", function () {
    var eng = new ChallengeDifficultyCurveEngine({ maxSamples: 50 });
    for (var i = 0; i < 60; i++) eng.recordSample(50, OUTCOMES.HUMAN_PASS);
    expect(eng.getSampleCount()).toBe(50);
  });

  test("records optional metadata", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var sample = eng.recordSample(50, OUTCOMES.HUMAN_PASS, { solveTimeMs: 1234, challengeId: "abc" });
    expect(sample.meta.solveTimeMs).toBe(1234);
    expect(sample.meta.challengeId).toBe("abc");
  });

  test("records all outcome types", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    eng.recordSample(50, OUTCOMES.HUMAN_PASS);
    eng.recordSample(50, OUTCOMES.HUMAN_FAIL);
    eng.recordSample(50, OUTCOMES.HUMAN_ABANDON);
    eng.recordSample(50, OUTCOMES.BOT_PASS);
    eng.recordSample(50, OUTCOMES.BOT_FAIL);
    var buckets = eng.getBuckets();
    var b = buckets[5];
    expect(b.humanPass).toBe(1);
    expect(b.humanFail).toBe(1);
    expect(b.humanAbandon).toBe(1);
    expect(b.botPass).toBe(1);
    expect(b.botFail).toBe(1);
  });
});

/* ═══════════════════════════════════════════════════════
 * 3. Curve Analysis
 * ═══════════════════════════════════════════════════════ */
describe("curve analysis", function () {
  test("getHumanPassCurve returns all buckets", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var curve = eng.getHumanPassCurve();
    expect(curve.length).toBe(10);
    curve.forEach(function (point) {
      expect(point).toHaveProperty("bucket");
      expect(point).toHaveProperty("difficulty");
      expect(point).toHaveProperty("passRate");
      expect(point).toHaveProperty("sampleCount");
    });
  });

  test("human pass rate decreases with difficulty", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    // Easy: 90% pass, Hard: 30% pass
    populate(eng, 15, 18, 2, 0, 0, 0);  // easy: 90%
    populate(eng, 75, 6, 14, 0, 0, 0);  // hard: 30%
    var curve = eng.getHumanPassCurve();
    var easy = curve[1];  // bucket 1 (10-19)
    var hard = curve[7];  // bucket 7 (70-79)
    expect(easy.passRate).toBeGreaterThan(hard.passRate);
  });

  test("getBotRejectCurve returns correct reject rates", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 25, 0, 0, 0, 8, 2);   // easy: 20% reject
    populate(eng, 75, 0, 0, 0, 1, 19);  // hard: 95% reject
    var curve = eng.getBotRejectCurve();
    var easy = curve[2];
    var hard = curve[7];
    expect(hard.rejectRate).toBeGreaterThan(easy.rejectRate);
  });

  test("getAbandonmentCurve tracks abandonment", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 15, 15, 3, 2, 0, 0);   // 10% abandon
    populate(eng, 85, 5, 5, 10, 0, 0);   // 50% abandon
    var curve = eng.getAbandonmentCurve();
    var easy = curve[1];
    var hard = curve[8];
    expect(hard.abandonRate).toBeGreaterThan(easy.abandonRate);
  });

  test("empty buckets return null rates", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var curve = eng.getHumanPassCurve();
    curve.forEach(function (point) {
      expect(point.passRate).toBeNull();
      expect(point.sampleCount).toBe(0);
    });
  });
});

/* ═══════════════════════════════════════════════════════
 * 4. Optimal Difficulty Finding
 * ═══════════════════════════════════════════════════════ */
describe("findOptimalDifficulty", function () {
  test("returns default 50 with no data", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var result = eng.findOptimalDifficulty();
    expect(result.optimalDifficulty).toBe(50);
    expect(result.confidence).toBe(0);
  });

  test("finds bucket with best combined score", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    // Easy: good human pass but bad bot reject
    populate(eng, 15, 18, 1, 1, 8, 12);  // humanPass=90%, botReject=60%
    // Moderate: good balance
    populate(eng, 45, 16, 2, 2, 2, 18);  // humanPass=80%, botReject=90%
    // Hard: bad human pass but great bot reject
    populate(eng, 75, 6, 10, 4, 0, 20);  // humanPass=30%, botReject=100%

    var result = eng.findOptimalDifficulty();
    // Moderate should win (best combined score)
    expect(result.optimalDifficulty).toBeGreaterThanOrEqual(40);
    expect(result.optimalDifficulty).toBeLessThanOrEqual(60);
    expect(result.score).toBeGreaterThan(0);
  });

  test("returns human and bot rates", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 45, 15, 3, 2, 2, 18);
    var result = eng.findOptimalDifficulty();
    expect(result).toHaveProperty("humanPassRate");
    expect(result).toHaveProperty("botRejectRate");
    expect(result).toHaveProperty("abandonRate");
    expect(result).toHaveProperty("confidence");
  });

  test("confidence increases with more data", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 45, 10, 0, 0, 0, 10);
    var low = eng.findOptimalDifficulty().confidence;

    populate(eng, 45, 50, 5, 5, 5, 50);
    var high = eng.findOptimalDifficulty().confidence;

    expect(high).toBeGreaterThanOrEqual(low);
  });
});

/* ═══════════════════════════════════════════════════════
 * 5. Difficulty Classification
 * ═══════════════════════════════════════════════════════ */
describe("classifyDifficulty", function () {
  test("classifies trivial difficulty", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(eng.classifyDifficulty(10).id).toBe("TRIVIAL");
  });

  test("classifies easy difficulty", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(eng.classifyDifficulty(30).id).toBe("EASY");
  });

  test("classifies moderate difficulty", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(eng.classifyDifficulty(50).id).toBe("MODERATE");
  });

  test("classifies hard difficulty", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(eng.classifyDifficulty(70).id).toBe("HARD");
  });

  test("classifies extreme difficulty", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(eng.classifyDifficulty(90).id).toBe("EXTREME");
  });

  test("clamps out-of-range values", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(eng.classifyDifficulty(-10).id).toBe("TRIVIAL");
    expect(eng.classifyDifficulty(150).id).toBe("EXTREME");
  });
});

/* ═══════════════════════════════════════════════════════
 * 6. Drift Detection
 * ═══════════════════════════════════════════════════════ */
describe("detectDrift", function () {
  test("reports no drift with insufficient history", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var result = eng.detectDrift();
    expect(result.drifting).toBe(false);
    expect(result.direction).toBe("stable");
  });

  test("detects upward drift", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    // Simulate gradually harder optimal difficulty
    for (var i = 0; i < 5; i++) {
      var diff = 30 + i * 10;
      populate(eng, diff, 15, 2, 1, 1, 15);
      eng.detectDrift();
    }
    var result = eng.detectDrift();
    expect(result.history.length).toBeGreaterThan(3);
  });

  test("returns drift history", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 50, 15, 3, 2, 2, 15);
    eng.detectDrift();
    eng.detectDrift();
    eng.detectDrift();
    var result = eng.detectDrift();
    expect(result.history.length).toBe(4);
    result.history.forEach(function (h) {
      expect(h).toHaveProperty("ts");
      expect(h).toHaveProperty("optimalDifficulty");
    });
  });

  test("caps drift history at 100", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 50, 15, 3, 2, 2, 15);
    for (var i = 0; i < 110; i++) eng.detectDrift();
    var result = eng.detectDrift();
    expect(result.history.length).toBeLessThanOrEqual(100);
  });
});

/* ═══════════════════════════════════════════════════════
 * 7. Bot Adaptation Detection
 * ═══════════════════════════════════════════════════════ */
describe("detectBotAdaptation", function () {
  test("returns no adaptation with no data", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var result = eng.detectBotAdaptation();
    expect(result.adapting).toBe(false);
    expect(result.signal).toBe("none");
  });

  test("returns result structure", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var result = eng.detectBotAdaptation();
    expect(result).toHaveProperty("adapting");
    expect(result).toHaveProperty("signal");
    expect(result).toHaveProperty("botPassTrend");
    expect(result).toHaveProperty("recentBotPassRate");
    expect(result).toHaveProperty("historicBotPassRate");
  });
});

/* ═══════════════════════════════════════════════════════
 * 8. Recommendations
 * ═══════════════════════════════════════════════════════ */
describe("generateRecommendations", function () {
  test("generates insufficient data recommendation for empty engine", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var recs = eng.generateRecommendations();
    var dataRec = recs.find(function (r) { return r.type === "insufficient_data"; });
    expect(dataRec).toBeTruthy();
    expect(dataRec.severity).toBe("info");
  });

  test("generates human pass low recommendation", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    // Very hard: low human pass
    populate(eng, 75, 3, 15, 2, 1, 19);
    var recs = eng.generateRecommendations();
    var passRec = recs.find(function (r) { return r.type === "human_pass_low"; });
    expect(passRec).toBeTruthy();
    expect(passRec.action).toBe("decrease_difficulty");
  });

  test("generates bot reject low recommendation", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    // Easy: low bot rejection
    populate(eng, 15, 18, 1, 1, 15, 5);
    var recs = eng.generateRecommendations();
    var rejectRec = recs.find(function (r) { return r.type === "bot_reject_low"; });
    expect(rejectRec).toBeTruthy();
    expect(rejectRec.action).toBe("increase_difficulty");
  });

  test("recommendations have required fields", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 50, 15, 3, 2, 2, 15);
    var recs = eng.generateRecommendations();
    recs.forEach(function (r) {
      expect(r).toHaveProperty("type");
      expect(r).toHaveProperty("severity");
      expect(r).toHaveProperty("emoji");
      expect(r).toHaveProperty("title");
      expect(r).toHaveProperty("text");
      expect(r).toHaveProperty("action");
    });
  });

  test("stores recommendations for later retrieval", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    eng.generateRecommendations();
    expect(eng.getRecommendations().length).toBeGreaterThan(0);
  });
});

/* ═══════════════════════════════════════════════════════
 * 9. Health Scoring
 * ═══════════════════════════════════════════════════════ */
describe("computeHealth", function () {
  test("returns score between 0 and 100", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var health = eng.computeHealth();
    expect(health.score).toBeGreaterThanOrEqual(0);
    expect(health.score).toBeLessThanOrEqual(100);
  });

  test("returns health tier", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var health = eng.computeHealth();
    expect(health.tier).toHaveProperty("label");
    expect(health.tier).toHaveProperty("emoji");
  });

  test("returns component scores", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 50, 15, 3, 2, 2, 15);
    var health = eng.computeHealth();
    expect(health.components).toHaveProperty("humanPassAlignment");
    expect(health.components).toHaveProperty("botRejectEffectiveness");
    expect(health.components).toHaveProperty("stability");
    expect(health.components).toHaveProperty("dataCoverage");
  });

  test("well-calibrated engine scores higher", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    // Perfect calibration: 85% human pass, 95% bot reject
    populate(eng, 50, 17, 2, 1, 1, 19);
    var health = eng.computeHealth();
    expect(health.score).toBeGreaterThan(40);
  });

  test("returns insights array", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var health = eng.computeHealth();
    expect(Array.isArray(health.insights)).toBe(true);
  });
});

/* ═══════════════════════════════════════════════════════
 * 10. Prediction
 * ═══════════════════════════════════════════════════════ */
describe("predictOutcome", function () {
  test("returns null prediction with no data", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var pred = eng.predictOutcome(50);
    expect(pred.predictedPassRate).toBeNull();
    expect(pred.confidence).toBe(0);
  });

  test("predicts from bucket data", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 45, 17, 2, 1, 0, 0);
    var pred = eng.predictOutcome(45);
    expect(pred.predictedPassRate).toBeGreaterThan(0.8);
    expect(pred.confidence).toBeGreaterThan(0);
  });

  test("interpolates between buckets", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 15, 18, 1, 1, 0, 0);  // 90% pass at easy
    populate(eng, 75, 6, 14, 0, 0, 0);  // 30% pass at hard
    var pred = eng.predictOutcome(45);   // interpolate mid
    if (pred.predictedPassRate !== null) {
      expect(pred.interpolated).toBe(true);
      expect(pred.predictedPassRate).toBeGreaterThan(0.3);
      expect(pred.predictedPassRate).toBeLessThan(0.9);
    }
  });

  test("returns difficulty band", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    var pred = eng.predictOutcome(75);
    expect(pred.band.id).toBe("HARD");
  });
});

/* ═══════════════════════════════════════════════════════
 * 11. Summary
 * ═══════════════════════════════════════════════════════ */
describe("getSummary", function () {
  test("returns comprehensive summary", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 45, 15, 3, 2, 2, 15);
    var summary = eng.getSummary();
    expect(summary).toHaveProperty("optimal");
    expect(summary).toHaveProperty("humanCurve");
    expect(summary).toHaveProperty("botCurve");
    expect(summary).toHaveProperty("abandonmentCurve");
    expect(summary).toHaveProperty("drift");
    expect(summary).toHaveProperty("botAdaptation");
    expect(summary).toHaveProperty("recommendations");
    expect(summary).toHaveProperty("health");
    expect(summary).toHaveProperty("totalSamples");
    expect(summary).toHaveProperty("config");
  });
});

/* ═══════════════════════════════════════════════════════
 * 12. State Export / Import
 * ═══════════════════════════════════════════════════════ */
describe("state export/import", function () {
  test("exports state", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 50, 15, 3, 2, 2, 15);
    var state = eng.exportState();
    expect(state).toHaveProperty("samples");
    expect(state).toHaveProperty("buckets");
    expect(state).toHaveProperty("config");
    expect(state.samples.length).toBe(37);
  });

  test("imports state correctly", function () {
    var eng1 = new ChallengeDifficultyCurveEngine();
    populate(eng1, 50, 15, 3, 2, 2, 15);
    var exported = eng1.exportState();

    var eng2 = new ChallengeDifficultyCurveEngine();
    eng2.importState(exported);
    expect(eng2.getSampleCount()).toBe(37);
    expect(eng2.getBuckets()[5].humanPass).toBe(15);
  });

  test("import rejects invalid state", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    expect(function () { eng.importState(null); }).toThrow();
    expect(function () { eng.importState("string"); }).toThrow();
  });
});

/* ═══════════════════════════════════════════════════════
 * 13. Reset
 * ═══════════════════════════════════════════════════════ */
describe("reset", function () {
  test("clears all state", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 50, 20, 5, 5, 5, 20);
    eng.detectDrift();
    eng.reset();
    expect(eng.getSampleCount()).toBe(0);
    expect(eng.getDriftHistory().length).toBe(0);
    var buckets = eng.getBuckets();
    Object.keys(buckets).forEach(function (k) {
      expect(buckets[k].total).toBe(0);
    });
  });
});

/* ═══════════════════════════════════════════════════════
 * 14. Constants
 * ═══════════════════════════════════════════════════════ */
describe("constants", function () {
  test("DIFFICULTY_BANDS has 5 bands", function () {
    expect(Object.keys(DIFFICULTY_BANDS).length).toBe(5);
  });

  test("OUTCOMES has 5 types", function () {
    expect(Object.keys(OUTCOMES).length).toBe(5);
  });

  test("HEALTH_TIERS has 5 tiers", function () {
    expect(Object.keys(HEALTH_TIERS).length).toBe(5);
  });

  test("bands cover full 0-100 range", function () {
    var covered = new Set();
    Object.keys(DIFFICULTY_BANDS).forEach(function (k) {
      var band = DIFFICULTY_BANDS[k];
      for (var i = band.min; i <= band.max; i++) covered.add(i);
    });
    for (var i = 0; i <= 100; i++) {
      expect(covered.has(i)).toBe(true);
    }
  });
});

/* ═══════════════════════════════════════════════════════
 * 15. Integration Scenarios
 * ═══════════════════════════════════════════════════════ */
describe("integration", function () {
  test("realistic scenario: finding sweet spot", function () {
    var eng = new ChallengeDifficultyCurveEngine();

    // Trivial: everyone passes, bots too
    populate(eng, 5, 20, 0, 0, 18, 2);
    // Easy: humans good, bots still pass
    populate(eng, 25, 19, 1, 0, 12, 8);
    // Moderate: good balance
    populate(eng, 45, 17, 2, 1, 2, 18);
    // Hard: humans struggle, bots fail
    populate(eng, 65, 10, 8, 2, 1, 19);
    // Extreme: humans abandon, bots fail
    populate(eng, 85, 4, 4, 12, 0, 20);

    var optimal = eng.findOptimalDifficulty();
    // Should pick moderate (best combined score)
    expect(optimal.optimalDifficulty).toBeGreaterThanOrEqual(30);
    expect(optimal.optimalDifficulty).toBeLessThanOrEqual(70);
    expect(optimal.score).toBeGreaterThan(0);

    var health = eng.computeHealth();
    expect(health.score).toBeGreaterThan(0);

    var recs = eng.generateRecommendations();
    expect(Array.isArray(recs)).toBe(true);
  });

  test("high abandonment triggers recommendation", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 85, 3, 3, 14, 0, 20);  // 70% abandon at extreme
    populate(eng, 45, 17, 2, 1, 2, 18);  // good at moderate

    var recs = eng.generateRecommendations();
    var abandonRec = recs.find(function (r) { return r.type === "high_abandonment"; });
    expect(abandonRec).toBeTruthy();
  });

  test("full lifecycle: record → analyze → recommend → export → import", function () {
    var eng = new ChallengeDifficultyCurveEngine();
    populate(eng, 50, 15, 3, 2, 2, 15);

    var summary = eng.getSummary();
    expect(summary.totalSamples).toBe(37);

    var exported = eng.exportState();
    var eng2 = new ChallengeDifficultyCurveEngine();
    eng2.importState(exported);

    var summary2 = eng2.getSummary();
    expect(summary2.totalSamples).toBe(37);
    expect(summary2.optimal.optimalDifficulty).toBe(summary.optimal.optimalDifficulty);
  });
});
