/**
 * Tests for AdaptiveDifficultyTuner
 */

"use strict";

var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var { createAdaptiveDifficultyTuner } = require("../src/adaptive-difficulty-tuner");

describe("createAdaptiveDifficultyTuner", function () {
  it("creates a tuner with default options", function () {
    var t = createAdaptiveDifficultyTuner();
    assert.equal(t.getDifficulty(), 5);
    var s = t.getStatus();
    assert.equal(s.currentDifficulty, 5);
    assert.equal(s.totalSolves, 0);
    assert.equal(s.totalFails, 0);
    assert.equal(s.paused, false);
  });

  it("respects initialDifficulty option", function () {
    var t = createAdaptiveDifficultyTuner({ initialDifficulty: 3 });
    assert.equal(t.getDifficulty(), 3);
  });

  it("clamps initialDifficulty to range", function () {
    var t = createAdaptiveDifficultyTuner({ initialDifficulty: 99, maxDifficulty: 10 });
    assert.equal(t.getDifficulty(), 10);
  });
});

describe("recordSolve / recordFail", function () {
  it("increments counters", function () {
    var t = createAdaptiveDifficultyTuner();
    t.recordSolve();
    t.recordSolve();
    t.recordFail();
    var s = t.getStatus();
    assert.equal(s.totalSolves, 2);
    assert.equal(s.totalFails, 1);
    assert.equal(s.totalAttempts, 3);
  });

  it("emits solve event", function () {
    var t = createAdaptiveDifficultyTuner();
    var events = [];
    t.on("solve", function (e) { events.push(e); });
    t.recordSolve();
    assert.equal(events.length, 1);
    assert.equal(events[0].difficulty, 5);
  });

  it("emits fail event", function () {
    var t = createAdaptiveDifficultyTuner();
    var events = [];
    t.on("fail", function (e) { events.push(e); });
    t.recordFail();
    assert.equal(events.length, 1);
  });
});

describe("evaluate", function () {
  it("returns hold with insufficient samples", function () {
    var t = createAdaptiveDifficultyTuner({ minSamplesForAdjustment: 10 });
    for (var i = 0; i < 5; i++) t.recordSolve();
    var rec = t.evaluate();
    assert.equal(rec.action, "hold");
    assert.equal(rec.reason, "insufficient_samples");
    assert.equal(rec.samplesNeeded, 5);
  });

  it("recommends increase when solve rate too high", function () {
    var t = createAdaptiveDifficultyTuner({
      minSamplesForAdjustment: 5,
      targetSolveRateMax: 0.75,
      cooldownMs: 0
    });
    // 90% solve rate
    for (var i = 0; i < 9; i++) t.recordSolve();
    t.recordFail();
    var rec = t.evaluate();
    assert.equal(rec.action, "increase");
    assert.equal(rec.from, 5);
    assert.equal(rec.to, 6);
  });

  it("recommends decrease when solve rate too low", function () {
    var t = createAdaptiveDifficultyTuner({
      minSamplesForAdjustment: 5,
      targetSolveRateMin: 0.55,
      cooldownMs: 0
    });
    // 20% solve rate
    for (var i = 0; i < 8; i++) t.recordFail();
    for (var j = 0; j < 2; j++) t.recordSolve();
    var rec = t.evaluate();
    assert.equal(rec.action, "decrease");
    assert.equal(rec.from, 5);
    assert.equal(rec.to, 4);
  });

  it("returns hold when within target", function () {
    var t = createAdaptiveDifficultyTuner({
      minSamplesForAdjustment: 5,
      targetSolveRateMin: 0.5,
      targetSolveRateMax: 0.8,
      cooldownMs: 0
    });
    // 60% solve rate
    for (var i = 0; i < 6; i++) t.recordSolve();
    for (var j = 0; j < 4; j++) t.recordFail();
    var rec = t.evaluate();
    assert.equal(rec.action, "hold");
    assert.equal(rec.reason, "within_target");
  });

  it("returns null when paused", function () {
    var t = createAdaptiveDifficultyTuner({ minSamplesForAdjustment: 1, cooldownMs: 0 });
    t.recordSolve();
    t.pause();
    assert.equal(t.evaluate(), null);
  });

  it("auto-applies when autoApply is true", function () {
    var t = createAdaptiveDifficultyTuner({
      minSamplesForAdjustment: 5,
      cooldownMs: 0,
      autoApply: true,
      targetSolveRateMax: 0.75
    });
    for (var i = 0; i < 10; i++) t.recordSolve();
    t.evaluate();
    assert.equal(t.getDifficulty(), 6);
  });

  it("respects cooldown", function () {
    var t = createAdaptiveDifficultyTuner({
      minSamplesForAdjustment: 5,
      cooldownMs: 999999999,
      targetSolveRateMax: 0.75
    });
    for (var i = 0; i < 10; i++) t.recordSolve();
    // Apply an adjustment to set lastAdjustmentTs
    var rec = t.evaluate();
    t.applyRecommendation(rec);
    // Next eval should be in cooldown
    for (var j = 0; j < 10; j++) t.recordSolve();
    var rec2 = t.evaluate();
    assert.equal(rec2.action, "hold");
    assert.equal(rec2.reason, "cooldown");
  });
});

describe("applyRecommendation", function () {
  it("applies increase", function () {
    var t = createAdaptiveDifficultyTuner();
    t.applyRecommendation({ action: "increase", to: 7, solveRate: 0.9, stats: { total: 20 } });
    assert.equal(t.getDifficulty(), 7);
  });

  it("ignores hold action", function () {
    var t = createAdaptiveDifficultyTuner();
    var result = t.applyRecommendation({ action: "hold" });
    assert.equal(result, false);
    assert.equal(t.getDifficulty(), 5);
  });

  it("records in history", function () {
    var t = createAdaptiveDifficultyTuner();
    t.applyRecommendation({ action: "decrease", to: 3, solveRate: 0.3, stats: { total: 25 } });
    var report = t.getReport();
    assert.equal(report.recentAdjustments.length, 1);
    assert.equal(report.recentAdjustments[0].from, 5);
    assert.equal(report.recentAdjustments[0].to, 3);
  });

  it("emits adjustment event", function () {
    var t = createAdaptiveDifficultyTuner();
    var events = [];
    t.on("adjustment", function (e) { events.push(e); });
    t.applyRecommendation({ action: "increase", to: 8, solveRate: 0.9, stats: { total: 30 } });
    assert.equal(events.length, 1);
    assert.equal(events[0].to, 8);
  });
});

describe("dimensions", function () {
  it("gets default dimensions", function () {
    var t = createAdaptiveDifficultyTuner();
    var dims = t.getAllDimensions();
    assert.ok(dims.speed);
    assert.ok(dims.complexity);
    assert.ok(dims.distortion);
    assert.ok(dims.frameCount);
  });

  it("sets a dimension value", function () {
    var t = createAdaptiveDifficultyTuner();
    t.setDimension("speed", 8);
    assert.equal(t.getDimension("speed").value, 8);
  });

  it("clamps dimension value", function () {
    var t = createAdaptiveDifficultyTuner();
    t.setDimension("speed", 99);
    assert.equal(t.getDimension("speed").value, 10);
  });

  it("throws on unknown dimension", function () {
    var t = createAdaptiveDifficultyTuner();
    assert.throws(function () { t.setDimension("bogus", 5); }, /Unknown dimension/);
    assert.throws(function () { t.getDimension("bogus"); }, /Unknown dimension/);
  });

  it("adds a new dimension", function () {
    var t = createAdaptiveDifficultyTuner();
    t.addDimension("noise", { weight: 0.15, min: 0, max: 5, value: 2 });
    assert.equal(t.getDimension("noise").value, 2);
  });

  it("throws on duplicate dimension add", function () {
    var t = createAdaptiveDifficultyTuner();
    assert.throws(function () { t.addDimension("speed", {}); }, /already exists/);
  });

  it("removes a dimension", function () {
    var t = createAdaptiveDifficultyTuner();
    t.removeDimension("distortion");
    var dims = t.getAllDimensions();
    assert.equal(dims.distortion, undefined);
  });

  it("throws on removing unknown dimension", function () {
    var t = createAdaptiveDifficultyTuner();
    assert.throws(function () { t.removeDimension("bogus"); }, /Unknown dimension/);
  });
});

describe("setDifficulty", function () {
  it("sets composite difficulty and scales dimensions", function () {
    var t = createAdaptiveDifficultyTuner();
    t.setDifficulty(8);
    assert.equal(t.getDifficulty(), 8);
    // All dimensions should be scaled proportionally
    var dims = t.getAllDimensions();
    // 8/10 = 0.7778 fraction, each dim should be min + 0.7778 * range
    assert.ok(dims.speed.value > 5);
  });

  it("clamps to range", function () {
    var t = createAdaptiveDifficultyTuner();
    t.setDifficulty(0);
    assert.equal(t.getDifficulty(), 1);
    t.setDifficulty(100);
    assert.equal(t.getDifficulty(), 10);
  });
});

describe("pause / resume", function () {
  it("pauses and resumes", function () {
    var t = createAdaptiveDifficultyTuner();
    t.pause();
    assert.equal(t.getStatus().paused, true);
    t.resume();
    assert.equal(t.getStatus().paused, false);
  });

  it("emits events", function () {
    var t = createAdaptiveDifficultyTuner();
    var events = [];
    t.on("paused", function () { events.push("paused"); });
    t.on("resumed", function () { events.push("resumed"); });
    t.pause();
    t.resume();
    assert.deepEqual(events, ["paused", "resumed"]);
  });
});

describe("reset", function () {
  it("resets all state", function () {
    var t = createAdaptiveDifficultyTuner({ initialDifficulty: 5 });
    t.recordSolve();
    t.recordFail();
    t.setDifficulty(8);
    t.reset();
    var s = t.getStatus();
    assert.equal(s.currentDifficulty, 5);
    assert.equal(s.totalSolves, 0);
    assert.equal(s.totalFails, 0);
    assert.equal(s.adjustmentCount, 0);
  });
});

describe("exportState / importState", function () {
  it("round-trips state", function () {
    var t = createAdaptiveDifficultyTuner();
    t.recordSolve();
    t.recordSolve();
    t.recordFail();
    t.setDifficulty(7);
    var state = t.exportState();

    var t2 = createAdaptiveDifficultyTuner();
    t2.importState(state);
    assert.equal(t2.getDifficulty(), 7);
    assert.equal(t2.getStatus().totalSolves, 2);
    assert.equal(t2.getStatus().totalFails, 1);
  });

  it("throws on null state", function () {
    var t = createAdaptiveDifficultyTuner();
    assert.throws(function () { t.importState(null); }, /State is required/);
  });
});

describe("getReport", function () {
  it("returns health score and label", function () {
    var t = createAdaptiveDifficultyTuner({ minSamplesForAdjustment: 5 });
    // In-range solve rate
    for (var i = 0; i < 7; i++) t.recordSolve();
    for (var j = 0; j < 3; j++) t.recordFail();
    var report = t.getReport();
    assert.ok(report.healthScore >= 0 && report.healthScore <= 100);
    assert.ok(["excellent", "good", "fair", "poor"].indexOf(report.healthLabel) >= 0);
    assert.ok(typeof report.recommendation === "string");
    assert.ok(report.stabilityIndex >= 0 && report.stabilityIndex <= 1);
  });

  it("penalizes no data", function () {
    var t = createAdaptiveDifficultyTuner();
    var report = t.getReport();
    assert.ok(report.healthScore < 100);
  });

  it("stability index is 1.0 with no adjustments", function () {
    var t = createAdaptiveDifficultyTuner();
    assert.equal(t.getReport().stabilityIndex, 1.0);
  });
});

describe("event emitter", function () {
  it("on/off works", function () {
    var t = createAdaptiveDifficultyTuner();
    var count = 0;
    var fn = function () { count++; };
    t.on("solve", fn);
    t.recordSolve();
    assert.equal(count, 1);
    t.off("solve", fn);
    t.recordSolve();
    assert.equal(count, 1);
  });

  it("off on non-existent event is no-op", function () {
    var t = createAdaptiveDifficultyTuner();
    t.off("nope", function () {});
    // no throw
  });

  it("listener errors are swallowed", function () {
    var t = createAdaptiveDifficultyTuner();
    t.on("solve", function () { throw new Error("boom"); });
    t.recordSolve(); // should not throw
  });
});

describe("getStatus", function () {
  it("includes all expected fields", function () {
    var t = createAdaptiveDifficultyTuner();
    var s = t.getStatus();
    assert.ok("currentDifficulty" in s);
    assert.ok("compositeDifficulty" in s);
    assert.ok("dimensions" in s);
    assert.ok("solveRate" in s);
    assert.ok("windowStats" in s);
    assert.ok("totalSolves" in s);
    assert.ok("totalFails" in s);
    assert.ok("targetRange" in s);
    assert.ok("paused" in s);
    assert.ok("autoApply" in s);
    assert.ok("autoEvalRunning" in s);
  });

  it("overallSolveRate is null with no attempts", function () {
    var t = createAdaptiveDifficultyTuner();
    assert.equal(t.getStatus().overallSolveRate, null);
  });

  it("calculates overallSolveRate correctly", function () {
    var t = createAdaptiveDifficultyTuner();
    t.recordSolve();
    t.recordSolve();
    t.recordFail();
    var rate = t.getStatus().overallSolveRate;
    assert.ok(Math.abs(rate - 2/3) < 0.001);
  });
});

describe("destroy", function () {
  it("cleans up timer and listeners", function () {
    var t = createAdaptiveDifficultyTuner();
    var called = false;
    t.on("solve", function () { called = true; });
    t.destroy();
    t.recordSolve(); // listeners cleared, should not fire
    // Can't easily test timer cleanup, but at least no throw
  });
});

describe("custom dimensions", function () {
  it("works with custom dimension config", function () {
    var t = createAdaptiveDifficultyTuner({
      dimensions: {
        color: { weight: 0.5, min: 1, max: 5, value: 3 },
        motion: { weight: 0.5, min: 1, max: 5, value: 3 }
      }
    });
    var dims = t.getAllDimensions();
    assert.ok(dims.color);
    assert.ok(dims.motion);
    assert.equal(dims.speed, undefined); // default replaced
  });
});

describe("edge cases", function () {
  it("handles max difficulty boundary on increase", function () {
    var t = createAdaptiveDifficultyTuner({
      initialDifficulty: 10,
      maxDifficulty: 10,
      minSamplesForAdjustment: 3,
      cooldownMs: 0,
      targetSolveRateMax: 0.75
    });
    for (var i = 0; i < 5; i++) t.recordSolve();
    var rec = t.evaluate();
    assert.equal(rec.action, "increase");
    assert.equal(rec.to, 10); // clamped at max
  });

  it("handles min difficulty boundary on decrease", function () {
    var t = createAdaptiveDifficultyTuner({
      initialDifficulty: 1,
      minDifficulty: 1,
      minSamplesForAdjustment: 3,
      cooldownMs: 0,
      targetSolveRateMin: 0.55
    });
    for (var i = 0; i < 5; i++) t.recordFail();
    var rec = t.evaluate();
    assert.equal(rec.action, "decrease");
    assert.equal(rec.to, 1); // clamped at min
  });

  it("getReport recommendation for max difficulty", function () {
    var t = createAdaptiveDifficultyTuner({
      initialDifficulty: 10,
      maxDifficulty: 10,
      minSamplesForAdjustment: 3,
      targetSolveRateMax: 0.5
    });
    for (var i = 0; i < 5; i++) t.recordSolve();
    var report = t.getReport();
    assert.ok(report.recommendation.indexOf("adding new challenge types") >= 0);
  });

  it("getReport recommendation for min difficulty", function () {
    var t = createAdaptiveDifficultyTuner({
      initialDifficulty: 1,
      minDifficulty: 1,
      minSamplesForAdjustment: 3,
      targetSolveRateMin: 0.5
    });
    for (var i = 0; i < 5; i++) t.recordFail();
    var report = t.getReport();
    assert.ok(report.recommendation.indexOf("challenge design") >= 0);
  });
});
