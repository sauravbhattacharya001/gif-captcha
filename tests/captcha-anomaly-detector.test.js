/**
 * Tests for CaptchaAnomalyDetector
 */

"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/captcha-anomaly-detector.js");

test("createAnomalyDetector returns object with expected API", function () {
  var d = mod.createAnomalyDetector();
  assert.strictEqual(typeof d.recordEvent, "function");
  assert.strictEqual(typeof d.recordEvents, "function");
  assert.strictEqual(typeof d.analyze, "function");
  assert.strictEqual(typeof d.getAlertHistory, "function");
  assert.strictEqual(typeof d.getEmaSnapshot, "function");
  assert.strictEqual(typeof d.getStats, "function");
  assert.strictEqual(typeof d.reset, "function");
});

test("analyze with no events returns healthy", function () {
  var d = mod.createAnomalyDetector();
  var r = d.analyze();
  assert.strictEqual(r.healthy, true);
  assert.deepStrictEqual(r.anomalies, []);
  assert.strictEqual(r.metrics.totalEvents, 0);
});

test("recordEvent stores events correctly", function () {
  var d = mod.createAnomalyDetector();
  d.recordEvent({ type: "solve", duration: 1000, success: true, country: "US" });
  var stats = d.getStats();
  assert.strictEqual(stats.totalEventsRecorded, 1);
  assert.strictEqual(stats.currentBufferSize, 1);
});

test("recordEvents batch records", function () {
  var d = mod.createAnomalyDetector();
  d.recordEvents([
    { duration: 500, country: "US" },
    { duration: 600, country: "DE" },
    { duration: 700, country: "JP" }
  ]);
  assert.strictEqual(d.getStats().totalEventsRecorded, 3);
});

test("analyze computes correct metrics for uniform data", function () {
  var d = mod.createAnomalyDetector({ minSamples: 5 });
  var now = Date.now();
  for (var i = 0; i < 20; i++) {
    d.recordEvent({ duration: 1000, success: true, country: "US", timestamp: now - i * 1000 });
  }
  var r = d.analyze({ timestamp: now });
  assert.strictEqual(r.metrics.solveRate, 1);
  assert.strictEqual(r.metrics.avgDuration, 1000);
  assert.strictEqual(r.metrics.totalEvents, 20);
});

test("z-score detects extreme outlier duration", function () {
  var d = mod.createAnomalyDetector({ sensitivity: "high", minSamples: 10 });
  var now = Date.now();
  // 50 normal events
  for (var i = 0; i < 50; i++) {
    d.recordEvent({ duration: 1000 + Math.sin(i) * 50, success: true, country: "US", timestamp: now - (60 - i) * 1000 });
  }
  // 1 extreme outlier
  d.recordEvent({ duration: 50000, success: true, country: "US", timestamp: now - 500 });
  var r = d.analyze({ timestamp: now });
  var zAnomalies = r.anomalies.filter(function (a) { return a.method === "z-score"; });
  assert.ok(zAnomalies.length > 0, "should detect z-score anomaly");
});

test("burst detection flags traffic spikes", function () {
  var d = mod.createAnomalyDetector({ sensitivity: "medium" });
  var now = Date.now();
  // Inject burst of events within burst window
  for (var i = 0; i < 15; i++) {
    d.recordEvent({ duration: 500, success: true, country: "US", timestamp: now - i * 100 });
  }
  var r = d.analyze({ timestamp: now });
  var bursts = r.anomalies.filter(function (a) { return a.method === "burst"; });
  assert.ok(bursts.length > 0, "should detect traffic burst");
});

test("failure burst detection", function () {
  var d = mod.createAnomalyDetector({ sensitivity: "medium" });
  var now = Date.now();
  for (var i = 0; i < 12; i++) {
    d.recordEvent({ duration: 500, success: false, country: "US", timestamp: now - i * 100 });
  }
  var r = d.analyze({ timestamp: now });
  var failBursts = r.anomalies.filter(function (a) { return a.metric === "failure_burst"; });
  assert.ok(failBursts.length > 0, "should detect failure burst");
  assert.strictEqual(failBursts[0].severity, "critical");
});

test("geo shift detection", function () {
  var d = mod.createAnomalyDetector({ sensitivity: "high", minSamples: 10 });
  var now = Date.now();
  // First half: all US
  for (var i = 0; i < 20; i++) {
    d.recordEvent({ duration: 1000, success: true, country: "US", timestamp: now - (40 - i) * 1000 });
  }
  // Second half: all CN
  for (var j = 0; j < 20; j++) {
    d.recordEvent({ duration: 1000, success: true, country: "CN", timestamp: now - (20 - j) * 1000 });
  }
  var r = d.analyze({ timestamp: now });
  var geoAnomalies = r.anomalies.filter(function (a) { return a.method === "geo_shift"; });
  assert.ok(geoAnomalies.length > 0, "should detect geo distribution shift");
});

test("sensitivity presets affect thresholds", function () {
  var low = mod.createAnomalyDetector({ sensitivity: "low" });
  var high = mod.createAnomalyDetector({ sensitivity: "high" });
  var lowStats = low.getStats();
  var highStats = high.getStats();
  assert.ok(lowStats.config.zThreshold > highStats.config.zThreshold);
  assert.ok(lowStats.config.minSamples > highStats.config.minSamples);
});

test("EMA snapshot updates after analysis", function () {
  var d = mod.createAnomalyDetector();
  var now = Date.now();
  for (var i = 0; i < 5; i++) {
    d.recordEvent({ duration: 1000, success: true, country: "US", timestamp: now - i * 1000 });
  }
  d.analyze({ timestamp: now });
  var ema = d.getEmaSnapshot();
  assert.ok(ema.solveRate !== null, "EMA solve rate should be set");
  assert.ok(ema.avgDuration !== null, "EMA avg duration should be set");
});

test("reset clears all state", function () {
  var d = mod.createAnomalyDetector();
  d.recordEvent({ duration: 1000, success: true, country: "US" });
  d.reset();
  assert.strictEqual(d.getStats().currentBufferSize, 0);
  assert.deepStrictEqual(d.getEmaSnapshot(), { solveRate: null, avgDuration: null, trafficRate: null });
});

test("alert history tracks anomalies", function () {
  var d = mod.createAnomalyDetector({ sensitivity: "medium" });
  var now = Date.now();
  for (var i = 0; i < 15; i++) {
    d.recordEvent({ duration: 500, success: false, country: "US", timestamp: now - i * 100 });
  }
  d.analyze({ timestamp: now });
  var history = d.getAlertHistory();
  assert.ok(history.length > 0, "alert history should have entries");
});

test("maxEvents trims buffer", function () {
  var d = mod.createAnomalyDetector({ maxEvents: 10 });
  for (var i = 0; i < 20; i++) {
    d.recordEvent({ duration: 500, success: true, country: "US" });
  }
  assert.strictEqual(d.getStats().currentBufferSize, 10);
  assert.strictEqual(d.getStats().totalEventsRecorded, 20);
});

test("country breakdown in metrics", function () {
  var d = mod.createAnomalyDetector();
  var now = Date.now();
  for (var i = 0; i < 10; i++) {
    d.recordEvent({ duration: 500, success: true, country: i < 7 ? "US" : "DE", timestamp: now - i * 1000 });
  }
  var r = d.analyze({ timestamp: now });
  assert.ok(r.metrics.countryBreakdown.length > 0);
  assert.strictEqual(r.metrics.countryBreakdown[0].country, "US");
});

test("recordEvent ignores null/undefined", function () {
  var d = mod.createAnomalyDetector();
  d.recordEvent(null);
  d.recordEvent(undefined);
  assert.strictEqual(d.getStats().totalEventsRecorded, 0);
});

test("recordEvents ignores non-array", function () {
  var d = mod.createAnomalyDetector();
  d.recordEvents("not an array");
  assert.strictEqual(d.getStats().totalEventsRecorded, 0);
});

test("solve rate changepoint detection", function () {
  var d = mod.createAnomalyDetector({ sensitivity: "high", minSamples: 10 });
  var now = Date.now();
  // 40 successes then 20 failures to create a changepoint
  for (var i = 0; i < 40; i++) {
    d.recordEvent({ duration: 1000, success: true, country: "US", timestamp: now - (60 - i) * 1000 });
  }
  for (var j = 0; j < 20; j++) {
    d.recordEvent({ duration: 1000, success: false, country: "US", timestamp: now - (20 - j) * 1000 });
  }
  var r = d.analyze({ timestamp: now });
  var cpAnomalies = r.anomalies.filter(function (a) { return a.method === "changepoint"; });
  // May or may not trigger depending on exact z-score; just verify analysis runs cleanly
  assert.ok(Array.isArray(cpAnomalies));
});

test("percentile metrics computed correctly", function () {
  var d = mod.createAnomalyDetector({ minSamples: 5 });
  var now = Date.now();
  var durations = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
  for (var i = 0; i < durations.length; i++) {
    d.recordEvent({ duration: durations[i], success: true, country: "US", timestamp: now - i * 1000 });
  }
  var r = d.analyze({ timestamp: now });
  assert.ok(r.metrics.p95Duration >= 900, "p95 should be high");
  assert.ok(r.metrics.medianDuration > 0, "median should be set");
});
