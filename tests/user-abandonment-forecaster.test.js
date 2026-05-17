"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/user-abandonment-forecaster");

function mk(opts) { return mod.createUserAbandonmentForecaster(opts || {}); }

function calmInput() {
  return {
    funnelStages: [
      { stage: "presented", count: 1000 },
      { stage: "started", count: 980 },
      { stage: "first_interaction", count: 970 },
      { stage: "submitted", count: 960 },
      { stage: "verified", count: 955 },
    ],
    cohorts: [
      { id: "c1", label: "Returning", sampleSize: 500, completionRate: 0.96, avgTimeToCompleteMs: 4000, retryRate: 0.05 },
      { id: "c2", label: "New", sampleSize: 200, completionRate: 0.92, avgTimeToCompleteMs: 5500, retryRate: 0.10 },
    ],
    currentDifficulty: 4,
    accessibilityFlags: { hasAudioAlt: true, hasTextAlt: true, supportsScreenReader: true, lowMotion: true },
    recentLatencyP95Ms: 800,
    recentTimeoutRate: 0.01,
    deviceMixSample: [
      { id: "m", device: "mobile", completionRate: 0.94 },
      { id: "d", device: "desktop", completionRate: 0.97 },
    ],
  };
}

function criticalInput() {
  return {
    funnelStages: [
      { stage: "presented", count: 1000 },
      { stage: "started", count: 600 },
      { stage: "first_interaction", count: 400 },
      { stage: "submitted", count: 250 },
      { stage: "verified", count: 150 },
    ],
    cohorts: [
      { id: "lc", label: "Mobile-LowEnd", sampleSize: 400, completionRate: 0.35, avgTimeToCompleteMs: 18000, retryRate: 0.45 },
      { id: "wc", label: "Webview", sampleSize: 150, completionRate: 0.42, avgTimeToCompleteMs: 16000, retryRate: 0.38 },
      { id: "rc", label: "Regular", sampleSize: 300, completionRate: 0.78, avgTimeToCompleteMs: 9000, retryRate: 0.18 },
    ],
    currentDifficulty: 9,
    accessibilityFlags: { hasAudioAlt: false, hasTextAlt: false, supportsScreenReader: false, lowMotion: false },
    recentLatencyP95Ms: 6200,
    recentTimeoutRate: 0.18,
    deviceMixSample: [
      { id: "m", device: "mobile", completionRate: 0.45 },
      { id: "d", device: "desktop", completionRate: 0.85 },
    ],
  };
}

test("factory exposes expected API", function () {
  var f = mk();
  ["analyze", "simulate", "formatText", "formatMarkdown", "formatJson"]
    .forEach(function (k) { assert.strictEqual(typeof f[k], "function", k); });
});

test("rejects bad riskAppetite", function () {
  assert.throws(function () { mk({ riskAppetite: "yolo" }); }, /riskAppetite/);
});

test("analyze() throws on bad input", function () {
  var f = mk();
  assert.throws(function () { f.analyze(null); }, TypeError);
  assert.throws(function () { f.analyze({}); }, TypeError);
  assert.throws(function () { f.analyze({ funnelStages: [] }); }, TypeError);
});

test("calm portfolio -> grade A and no P0 actions", function () {
  var r = mk().analyze(calmInput());
  assert.strictEqual(r.grade, "A");
  assert.strictEqual(r.band, "CALM");
  var p0 = r.playbook.filter(function (a) { return a.priority === "P0"; });
  assert.strictEqual(p0.length, 0, "no P0 expected, got " + JSON.stringify(p0));
});

test("critical portfolio -> grade F and multiple P0 actions", function () {
  var r = mk().analyze(criticalInput());
  assert.strictEqual(r.grade, "F");
  assert.strictEqual(r.band, "CRITICAL");
  var p0 = r.playbook.filter(function (a) { return a.priority === "P0"; });
  assert.ok(p0.length >= 3, "expected >=3 P0 actions, got " + p0.length);
  // Mobile + difficulty + accessibility + losing cohorts all firing
  var ids = r.playbook.map(function (a) { return a.id; });
  assert.ok(ids.indexOf("MOBILE_OPTIMIZED_CHALLENGE_SET") >= 0);
  assert.ok(ids.indexOf("LOWER_DIFFICULTY_ONE_NOTCH") >= 0);
});

test("INSUFFICIENT_DATA verdict when sampleSize < 30", function () {
  var inp = calmInput();
  inp.cohorts.push({ id: "x", label: "Tiny", sampleSize: 5, completionRate: 0.50 });
  var r = mk().analyze(inp);
  var tiny = r.cohortVerdicts.filter(function (c) { return c.id === "x"; })[0];
  assert.ok(tiny);
  assert.strictEqual(tiny.verdict, "INSUFFICIENT_DATA");
  assert.deepStrictEqual(tiny.reasons, ["SMALL_SAMPLE"]);
});

test("LOSING cohort triggers INVESTIGATE_COHORT with cohort id in meta", function () {
  var r = mk().analyze(criticalInput());
  var invest = r.playbook.filter(function (a) { return a.id === "INVESTIGATE_COHORT"; });
  assert.ok(invest.length >= 2, "expected >=2 INVESTIGATE_COHORT entries");
  invest.forEach(function (a) {
    assert.strictEqual(a.priority, "P0");
    assert.ok(a.meta && typeof a.meta.cohortId === "string");
  });
});

test("mobile penalty triggers MOBILE_OPTIMIZED_CHALLENGE_SET as P0", function () {
  var inp = calmInput();
  inp.deviceMixSample = [
    { id: "m", device: "mobile", completionRate: 0.50 },
    { id: "d", device: "desktop", completionRate: 0.90 },
  ];
  var r = mk().analyze(inp);
  var act = r.playbook.filter(function (a) { return a.id === "MOBILE_OPTIMIZED_CHALLENGE_SET"; })[0];
  assert.ok(act, "expected MOBILE_OPTIMIZED_CHALLENGE_SET");
  assert.strictEqual(act.priority, "P0");
});

test("missing accessibility flags trigger accessibility actions", function () {
  var inp = calmInput();
  inp.accessibilityFlags = { hasAudioAlt: false, hasTextAlt: false, supportsScreenReader: false, lowMotion: false };
  inp.currentDifficulty = 7;
  // Force one cohort LOSING for ADD_AUDIO_ALT trigger
  inp.cohorts.push({ id: "loser", label: "Loser", sampleSize: 100, completionRate: 0.40, avgTimeToCompleteMs: 8000, retryRate: 0.20 });
  var r = mk().analyze(inp);
  var ids = r.playbook.map(function (a) { return a.id; });
  assert.ok(ids.indexOf("ADD_AUDIO_ALT") >= 0);
  assert.ok(ids.indexOf("ENABLE_SCREEN_READER_SUPPORT") >= 0 || ids.indexOf("HONOR_PREFERS_REDUCED_MOTION") >= 0);
});

test("simulate(applyTop:3) reduces risk and uses diminishing returns", function () {
  var f = mk();
  var r = f.analyze(criticalInput());
  var sim = f.simulate(r, { applyTop: 3 });
  assert.ok(sim.abandonmentRisk < r.abandonmentRisk, "expected reduced risk");
  assert.strictEqual(sim.appliedActions.length, 3);
  // diminishing: |delta[0]| >= |delta[1]| >= |delta[2]|
  var deltas = sim.appliedActions.map(function (a) { return Math.abs(a.projectedDelta); });
  assert.ok(deltas[0] >= deltas[1], "delta0 >= delta1");
  assert.ok(deltas[1] >= deltas[2], "delta1 >= delta2");
});

test("simulate never mutates original report", function () {
  var f = mk();
  var r = f.analyze(criticalInput());
  var snapshot = JSON.stringify(r);
  f.simulate(r, { applyTop: 5 });
  assert.strictEqual(JSON.stringify(r), snapshot);
});

test("risk appetite shifts band on a borderline case", function () {
  // Borderline ~ELEVATED/HIGH
  function borderline() {
    return {
      funnelStages: [
        { stage: "presented", count: 1000 },
        { stage: "started", count: 820 },
        { stage: "first_interaction", count: 760 },
        { stage: "submitted", count: 700 },
        { stage: "verified", count: 650 },
      ],
      cohorts: [
        { id: "a", label: "A", sampleSize: 200, completionRate: 0.78, avgTimeToCompleteMs: 9000, retryRate: 0.22 },
      ],
      currentDifficulty: 6,
      accessibilityFlags: { hasAudioAlt: true, hasTextAlt: true, supportsScreenReader: true, lowMotion: true },
      recentLatencyP95Ms: 2800,
      recentTimeoutRate: 0.04,
      deviceMixSample: [],
    };
  }
  var rB = mk({ riskAppetite: "balanced" }).analyze(borderline());
  var rC = mk({ riskAppetite: "cautious" }).analyze(borderline());
  var rA = mk({ riskAppetite: "aggressive" }).analyze(borderline());
  // Same risk, different band thresholds: cautious band index >= balanced >= aggressive
  var rank = { CALM: 0, WATCH: 1, ELEVATED: 2, HIGH: 3, CRITICAL: 4 };
  assert.ok(rank[rC.band] >= rank[rB.band], "cautious band >= balanced");
  assert.ok(rank[rB.band] >= rank[rA.band], "balanced band >= aggressive");
});

test("formatJson is byte-stable across calls", function () {
  var f = mk();
  var r = f.analyze(criticalInput());
  var a = f.formatJson(r);
  var b = f.formatJson(r);
  assert.strictEqual(a, b);
  // sorted keys: ensure 'abandonmentRisk' appears before 'band' textually
  assert.ok(a.indexOf("\"abandonmentRisk\"") < a.indexOf("\"band\""));
});

test("formatMarkdown contains required section headers", function () {
  var f = mk();
  var r = f.analyze(criticalInput());
  var md = f.formatMarkdown(r);
  ["# User Abandonment Forecast", "## Summary", "## Risk Breakdown", "## Cohort Verdicts", "## Playbook"]
    .forEach(function (h) { assert.ok(md.indexOf(h) >= 0, "missing: " + h); });
});

test("playbook is P0-first ordered and deduped", function () {
  var r = mk().analyze(criticalInput());
  var rank = { P0: 0, P1: 1, P2: 2 };
  for (var i = 1; i < r.playbook.length; i++) {
    assert.ok(rank[r.playbook[i].priority] >= rank[r.playbook[i - 1].priority],
      "out of order at " + i + ": " + r.playbook[i - 1].priority + " -> " + r.playbook[i].priority);
  }
  // Dedup of catalog actions (INVESTIGATE_COHORT is allowed to repeat)
  var nonInvest = r.playbook.filter(function (a) { return a.id !== "INVESTIGATE_COHORT"; });
  var seen = {};
  nonInvest.forEach(function (a) {
    assert.ok(!seen[a.id], "dup action " + a.id);
    seen[a.id] = true;
  });
});

test("empty / edge inputs do not throw", function () {
  var f = mk();
  var r = f.analyze({
    funnelStages: [{ stage: "presented", count: 100 }, { stage: "verified", count: 100 }],
    cohorts: [],
  });
  assert.strictEqual(typeof r.abandonmentRisk, "number");
  assert.ok(Array.isArray(r.playbook));
  assert.ok(Array.isArray(r.cohortVerdicts));
});

test("linear funnel with no drop-off -> CALM", function () {
  var f = mk();
  var r = f.analyze({
    funnelStages: STAGES_FLAT(),
    cohorts: [{ id: "a", label: "A", sampleSize: 100, completionRate: 0.95, avgTimeToCompleteMs: 4000, retryRate: 0.05 }],
    currentDifficulty: 3,
    accessibilityFlags: { hasAudioAlt: true, hasTextAlt: true, supportsScreenReader: true, lowMotion: true },
    recentLatencyP95Ms: 500,
    recentTimeoutRate: 0,
    deviceMixSample: [],
  });
  assert.strictEqual(r.band, "CALM");
  assert.strictEqual(r.grade, "A");
});

function STAGES_FLAT() {
  return [
    { stage: "presented", count: 1000 },
    { stage: "started", count: 1000 },
    { stage: "first_interaction", count: 1000 },
    { stage: "submitted", count: 1000 },
    { stage: "verified", count: 1000 },
  ];
}
