/**
 * Tests for AttackForecaster (src/attack-forecaster.js)
 *
 * Style mirrors tests/attack-response-playbook.test.js — node:test + assert,
 * no jest, no external deps.
 */

"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/attack-forecaster");

function _make(opts) {
  return mod.createAttackForecaster(opts || {});
}

// Build a synthetic snapshot stream where chosen metrics drift toward
// breach over N minutes ending "now". Times are in milliseconds.
function _buildStream(opts) {
  opts = opts || {};
  var nowFn = opts.now || function () { return 1_700_000_000_000; };
  var now = nowFn();
  var count = opts.count || 8;
  var intervalMs = opts.intervalMs || 60_000;
  var rampMetrics = opts.rampMetrics || {};
  var baseMetrics = opts.baseMetrics || {
    trafficRpm: 800, solveRate: 0.82, p95Duration: 1800, errorRate: 0.02, geoEntropy: 2.4,
  };
  var anomaliesPerStep = opts.anomaliesPerStep || function () { return []; };

  var snaps = [];
  for (var i = 0; i < count; i++) {
    var t = now - (count - 1 - i) * intervalMs;
    var metrics = Object.assign({}, baseMetrics);
    var step = i; // 0..count-1
    Object.keys(rampMetrics).forEach(function (k) {
      metrics[k] = baseMetrics[k] + rampMetrics[k] * step;
    });
    snaps.push({ timestamp: t, anomalies: anomaliesPerStep(i, count), metrics: metrics });
  }
  return { snaps: snaps, now: now };
}

test("factory returns expected API surface", function () {
  var fc = _make();
  ["recordSnapshot", "forecast", "simulate", "formatAs", "formatText", "formatMarkdown", "reset"]
    .forEach(function (k) { assert.strictEqual(typeof fc[k], "function", k); });
});

test("forecast() returns sufficient=false when too few snapshots", function () {
  var fc = _make({ minSnapshots: 4 });
  fc.recordSnapshot({ timestamp: 1, anomalies: [], metrics: { trafficRpm: 100 } });
  var r = fc.forecast();
  assert.strictEqual(r.sufficient, false);
  assert.ok(/Insufficient/.test(r.reason));
  assert.strictEqual(r.preemptiveActions.length, 0);
});

test("calm stream → low probability, calm/watch band, no severe reasons", function () {
  var built = _buildStream({ count: 8 });
  var fc = _make({ horizonMinutes: 15 });
  built.snaps.forEach(function (s) { fc.recordSnapshot(s); });
  var r = fc.forecast();
  assert.strictEqual(r.sufficient, true);
  assert.ok(r.escalationProbability < 0.5,
    "expected calm probability, got " + r.escalationProbability);
  assert.ok(["calm", "watch"].indexOf(r.band.id) !== -1, "band=" + r.band.id);
});

test("traffic ramping toward breach → elevated+ probability with lead time", function () {
  // 8 snapshots, traffic climbing 600/min toward breach of 5000.
  var built = _buildStream({
    count: 8,
    rampMetrics: { trafficRpm: 600 },
    anomaliesPerStep: function (i) {
      return i >= 4 ? [{ type: "traffic_spike", severity: "medium" }] : [];
    },
  });
  var fc = _make({ horizonMinutes: 10 });
  built.snaps.forEach(function (s) { fc.recordSnapshot(s); });
  var r = fc.forecast();
  assert.strictEqual(r.sufficient, true);
  assert.ok(r.escalationProbability > 0.5,
    "expected elevated probability, got " + r.escalationProbability);
  assert.ok(r.metricProjections.trafficRpm.slopePerMin > 0, "traffic slope should be positive");
  assert.ok(r.leadTimeMinutes !== null && r.leadTimeMinutes >= 0, "should have a lead time");
  assert.ok(r.reasons.length > 0, "should produce at least one reason");
});

test("predicted profile reflects anomaly indicators in stream", function () {
  var built = _buildStream({
    count: 6,
    rampMetrics: { solveRate: -0.04 },
    anomaliesPerStep: function () {
      return [
        { type: "solve_rate_drop", severity: "high" },
        { type: "failure_burst", severity: "high" },
        { type: "ip_concentration", severity: "medium" },
      ];
    },
  });
  var fc = _make({ horizonMinutes: 10 });
  built.snaps.forEach(function (s) { fc.recordSnapshot(s); });
  var r = fc.forecast();
  assert.strictEqual(r.predictedProfile, "credential_stuffing",
    "expected credential_stuffing, got " + r.predictedProfile);
});

test("pre-emptive actions ranked, capped, and P0/P1 prioritised", function () {
  var built = _buildStream({
    count: 8,
    rampMetrics: { trafficRpm: 700 },
    anomaliesPerStep: function (i) {
      return i >= 4
        ? [{ type: "traffic_spike", severity: "high" }, { type: "fingerprint_collision", severity: "medium" }]
        : [];
    },
  });
  var fc = _make({ riskAppetite: "balanced" });
  built.snaps.forEach(function (s) { fc.recordSnapshot(s); });
  var r = fc.forecast();
  assert.ok(r.preemptiveActions.length > 0, "expected at least one pre-emptive action");
  assert.ok(r.preemptiveActions.length <= mod.RISK_PRESETS.balanced.maxActions);
  assert.strictEqual(r.preemptiveActions[0].priority, "P0");
  // No duplicates by id
  var ids = r.preemptiveActions.map(function (a) { return a.id; });
  assert.strictEqual(new Set(ids).size, ids.length, "actions should be unique");
});

test("risk appetite shifts band boundaries", function () {
  var build = function () {
    return _buildStream({
      count: 8,
      rampMetrics: { trafficRpm: 400 },
      anomaliesPerStep: function (i) {
        return i >= 5 ? [{ type: "traffic_spike", severity: "medium" }] : [];
      },
    });
  };
  var cautious = _make({ riskAppetite: "cautious" });
  var aggressive = _make({ riskAppetite: "aggressive" });
  build().snaps.forEach(function (s) { cautious.recordSnapshot(s); });
  build().snaps.forEach(function (s) { aggressive.recordSnapshot(s); });
  var rc = cautious.forecast();
  var ra = aggressive.forecast();
  // Same probability magnitude but different shifts; cautious band ordinal
  // should be >= aggressive band ordinal.
  var ordinal = function (b) {
    return mod.BANDS.findIndex(function (x) { return x.id === b.id; });
  };
  assert.ok(ordinal(rc.band) >= ordinal(ra.band),
    "cautious band (" + rc.band.id + ") should be >= aggressive band (" + ra.band.id + ")");
});

test("simulate() applying top actions reduces probability for trajectory-driven forecast", function () {
  var built = _buildStream({
    count: 8,
    rampMetrics: { trafficRpm: 700, errorRate: 0.012 },
    anomaliesPerStep: function (i) {
      return i >= 3 ? [{ type: "traffic_spike", severity: "high" }] : [];
    },
  });
  var fc = _make({ horizonMinutes: 10 });
  built.snaps.forEach(function (s) { fc.recordSnapshot(s); });
  var r = fc.forecast();
  var sim = fc.simulate(r, { applyTop: 3 });
  assert.ok(sim.simulated.escalationProbability <= r.escalationProbability,
    "simulated prob (" + sim.simulated.escalationProbability +
    ") should be <= baseline (" + r.escalationProbability + ")");
  assert.ok(sim.deltaProbability <= 0);
  assert.ok(Array.isArray(sim.applied));
});

test("simulate() with insufficient baseline returns informational note", function () {
  var fc = _make({ minSnapshots: 5 });
  fc.recordSnapshot({ timestamp: 1, anomalies: [], metrics: { trafficRpm: 100 } });
  var r = fc.forecast();
  var sim = fc.simulate(r, { applyTop: 2 });
  assert.strictEqual(sim.simulated.sufficient, false);
  assert.ok(/Baseline insufficient/.test(sim.note));
});

test("formatAs renders text, md, and json without throwing", function () {
  var built = _buildStream({
    count: 6,
    rampMetrics: { trafficRpm: 500 },
    anomaliesPerStep: function (i) { return i >= 3 ? [{ type: "traffic_spike", severity: "medium" }] : []; },
  });
  var fc = _make();
  built.snaps.forEach(function (s) { fc.recordSnapshot(s); });
  var r = fc.forecast();
  var text = fc.formatAs(r, "text");
  var md = fc.formatAs(r, "md");
  var json = fc.formatAs(r, "json");
  assert.ok(text.indexOf("AttackForecaster") !== -1);
  assert.ok(md.indexOf("# Attack Forecast") !== -1);
  var parsed = JSON.parse(json);
  assert.strictEqual(typeof parsed.escalationProbability, "number");
});

test("maxSnapshots caps internal buffer", function () {
  var fc = _make({ maxSnapshots: 3 });
  for (var i = 0; i < 10; i++) {
    fc.recordSnapshot({ timestamp: 1000 * i, anomalies: [], metrics: { trafficRpm: i } });
  }
  assert.strictEqual(fc._snapshots().length, 3);
  // Oldest of the kept window should be the (10-3)=7th = trafficRpm=7
  assert.strictEqual(fc._snapshots()[0].metrics.trafficRpm, 7);
});

test("reset() clears state", function () {
  var fc = _make();
  fc.recordSnapshot({ timestamp: 1, anomalies: [], metrics: { trafficRpm: 1 } });
  fc.recordSnapshot({ timestamp: 2, anomalies: [], metrics: { trafficRpm: 2 } });
  assert.ok(fc._snapshots().length === 2);
  fc.reset();
  assert.strictEqual(fc._snapshots().length, 0);
});

test("public API exposes createAttackForecaster from src/index.js", function () {
  var idx = require("../src/index");
  assert.strictEqual(typeof idx.createAttackForecaster, "function");
  var fc = idx.createAttackForecaster();
  assert.strictEqual(typeof fc.forecast, "function");
});

test("snapshots inserted out-of-order are sorted by timestamp", function () {
  var fc = _make();
  fc.recordSnapshot({ timestamp: 3000, anomalies: [], metrics: { trafficRpm: 3 } });
  fc.recordSnapshot({ timestamp: 1000, anomalies: [], metrics: { trafficRpm: 1 } });
  fc.recordSnapshot({ timestamp: 2000, anomalies: [], metrics: { trafficRpm: 2 } });
  var snaps = fc._snapshots();
  assert.deepStrictEqual(snaps.map(function (s) { return s.timestamp; }), [1000, 2000, 3000]);
});

test("intel-only actions (no dampening) still score with forecast probability", function () {
  // Build a moderate-probability forecast then ensure 'snapshot_baseline'
  // or similar intel-only actions can appear with non-zero score.
  var built = _buildStream({
    count: 6,
    rampMetrics: { solveRate: -0.03 },
    anomaliesPerStep: function (i) {
      return i >= 2 ? [{ type: "geo_shift", severity: "medium" }] : [];
    },
  });
  var fc = _make({ riskAppetite: "cautious" });
  built.snaps.forEach(function (s) { fc.recordSnapshot(s); });
  var r = fc.forecast();
  var ids = r.preemptiveActions.map(function (a) { return a.id; });
  // At least one of the always-applicable intel/notify actions should appear
  // in cautious mode given non-trivial probability.
  var anyIntel = ["snapshot_baseline", "notify_oncall_pre_alert", "increase_sampling"]
    .some(function (id) { return ids.indexOf(id) !== -1; });
  assert.ok(anyIntel, "expected at least one intel/notify action in cautious mode; got " + ids.join(","));
});
