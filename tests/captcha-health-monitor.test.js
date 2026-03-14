"use strict";

var test = require("node:test");
var assert = require("node:assert/strict");
var { createCaptchaHealthMonitor } = require("../src/captcha-health-monitor");

// ── Helper: controllable clock ──────────────────────────────────────

function makeClock(start) {
  var t = start || 1000000;
  return {
    now: function () { return t; },
    advance: function (ms) { t += ms; }
  };
}

// ── Factory ─────────────────────────────────────────────────────────

test("createCaptchaHealthMonitor returns an object with expected API", function () {
  var m = createCaptchaHealthMonitor();
  assert.equal(typeof m.recordSolve, "function");
  assert.equal(typeof m.recordBotDetection, "function");
  assert.equal(typeof m.recordPoolLevel, "function");
  assert.equal(typeof m.recordRateLimitHit, "function");
  assert.equal(typeof m.recordError, "function");
  assert.equal(typeof m.recordOperation, "function");
  assert.equal(typeof m.check, "function");
  assert.equal(typeof m.summary, "function");
  assert.equal(typeof m.trend, "function");
  assert.equal(typeof m.getAlerts, "function");
  assert.equal(typeof m.getCheckHistory, "function");
  assert.equal(typeof m.stats, "function");
  assert.equal(typeof m.reset, "function");
  assert.equal(typeof m.exportJSON, "function");
  assert.equal(typeof m.importJSON, "function");
});

test("fresh monitor check returns healthy", function () {
  var m = createCaptchaHealthMonitor();
  var h = m.check();
  assert.equal(h.status, "healthy");
  assert.equal(h.score, 100);
  assert.equal(h.alerts.length, 0);
  assert.equal(h.recommendations.length, 0);
  assert.equal(h.checksPerformed, 1);
});

// ── Solve Rate ──────────────────────────────────────────────────────

test("high solve rate → healthy", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) {
    m.recordSolve({ solved: true, timeMs: 2000 });
  }
  var h = m.check();
  assert.equal(h.signals.solveRate.status, "healthy");
  assert.equal(h.signals.solveRate.value, 1);
  assert.equal(h.signals.solveRate.solved, 10);
  assert.equal(h.signals.solveRate.total, 10);
});

test("low solve rate → degraded", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 4; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  for (var j = 0; j < 6; j++) m.recordSolve({ solved: false, timeMs: 5000 });
  var h = m.check();
  assert.equal(h.signals.solveRate.status, "degraded");
  assert.ok(h.signals.solveRate.value < 0.60);
});

test("very low solve rate → critical", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 2; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  for (var j = 0; j < 8; j++) m.recordSolve({ solved: false, timeMs: 5000 });
  var h = m.check();
  assert.equal(h.signals.solveRate.status, "critical");
});

test("solve rate with fewer than 3 samples stays healthy", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.recordSolve({ solved: false, timeMs: 5000 });
  m.recordSolve({ solved: false, timeMs: 6000 });
  var h = m.check();
  assert.equal(h.signals.solveRate.status, "healthy");
});

// ── Response Time ───────────────────────────────────────────────────

test("fast response times → healthy", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  var h = m.check();
  assert.equal(h.signals.responseTime.status, "healthy");
  assert.equal(h.signals.responseTime.value, 2000);
});

test("slow response times → degraded", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m.recordSolve({ solved: true, timeMs: 9000 });
  var h = m.check();
  assert.equal(h.signals.responseTime.status, "degraded");
});

test("very slow response times → critical", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m.recordSolve({ solved: true, timeMs: 16000 });
  var h = m.check();
  assert.equal(h.signals.responseTime.status, "critical");
});

test("response time percentiles computed correctly", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 1; i <= 100; i++) m.recordSolve({ solved: true, timeMs: i * 100 });
  var h = m.check();
  assert.ok(h.signals.responseTime.p50 > 4000 && h.signals.responseTime.p50 < 6000);
  assert.ok(h.signals.responseTime.p95 > 9000);
  assert.ok(h.signals.responseTime.p99 > 9500);
});

// ── Pool Level ──────────────────────────────────────────────────────

test("full pool → healthy", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.recordPoolLevel({ available: 80, total: 100 });
  var h = m.check();
  assert.equal(h.signals.poolLevel.status, "healthy");
  assert.equal(h.signals.poolLevel.value, 0.8);
});

test("low pool → degraded", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.recordPoolLevel({ available: 15, total: 100 });
  var h = m.check();
  assert.equal(h.signals.poolLevel.status, "degraded");
});

test("empty pool → critical", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.recordPoolLevel({ available: 3, total: 100 });
  var h = m.check();
  assert.equal(h.signals.poolLevel.status, "critical");
});

test("pool level uses most recent snapshot", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.recordPoolLevel({ available: 5, total: 100 });
  m.recordPoolLevel({ available: 90, total: 100 });
  var h = m.check();
  assert.equal(h.signals.poolLevel.status, "healthy");
});

// ── Bot Rate ────────────────────────────────────────────────────────

test("low bot rate → healthy", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 8; i++) m.recordBotDetection({ blocked: false });
  for (var j = 0; j < 2; j++) m.recordBotDetection({ blocked: true });
  var h = m.check();
  assert.equal(h.signals.botRate.status, "healthy");
});

test("high bot rate → degraded", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 4; i++) m.recordBotDetection({ blocked: false });
  for (var j = 0; j < 6; j++) m.recordBotDetection({ blocked: true });
  var h = m.check();
  assert.equal(h.signals.botRate.status, "degraded");
});

test("extreme bot rate → critical", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 2; i++) m.recordBotDetection({ blocked: false });
  for (var j = 0; j < 8; j++) m.recordBotDetection({ blocked: true });
  var h = m.check();
  assert.equal(h.signals.botRate.status, "critical");
});

// ── Rate Limit Pressure ─────────────────────────────────────────────

test("no rate limit hits → healthy", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordOperation();
  var h = m.check();
  assert.equal(h.signals.rateLimitPressure.status, "healthy");
  assert.equal(h.signals.rateLimitPressure.value, 0);
});

test("moderate rate limit hits → degraded", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordOperation();
  for (var j = 0; j < 3; j++) m.recordRateLimitHit({ key: "10.0.0." + j });
  var h = m.check();
  assert.equal(h.signals.rateLimitPressure.status, "degraded");
});

test("heavy rate limit hits → critical", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordOperation();
  for (var j = 0; j < 5; j++) m.recordRateLimitHit({ key: "10.0.0." + j });
  var h = m.check();
  assert.equal(h.signals.rateLimitPressure.status, "critical");
});

// ── Error Rate ──────────────────────────────────────────────────────

test("no errors → healthy", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordOperation();
  var h = m.check();
  assert.equal(h.signals.errorRate.status, "healthy");
  assert.equal(h.signals.errorRate.errors, 0);
});

test("some errors → degraded", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  // Need error rate > 5% (degraded) but < 15% (critical)
  // recordError also adds to totalOps, so 2 errors + 18 ops = 2/20 = 10%
  for (var i = 0; i < 18; i++) m.recordOperation();
  for (var j = 0; j < 2; j++) m.recordError({ code: "TIMEOUT" });
  var h = m.check();
  assert.equal(h.signals.errorRate.status, "degraded");
});

test("many errors → critical", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m.recordOperation();
  for (var j = 0; j < 5; j++) m.recordError({ code: "GEN_FAIL" });
  var h = m.check();
  assert.equal(h.signals.errorRate.status, "critical");
});

test("error rate tracks top error codes", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m.recordError({ code: "TIMEOUT" });
  for (var j = 0; j < 3; j++) m.recordError({ code: "GEN_FAIL" });
  m.recordError({ code: "DB_ERROR" });
  var h = m.check();
  assert.equal(h.signals.errorRate.topCodes[0].code, "TIMEOUT");
  assert.equal(h.signals.errorRate.topCodes[0].count, 5);
  assert.equal(h.signals.errorRate.topCodes[1].code, "GEN_FAIL");
});

// ── Overall Health Score ────────────────────────────────────────────

test("all healthy signals → score 100", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) {
    m.recordSolve({ solved: true, timeMs: 2000 });
  }
  m.recordPoolLevel({ available: 80, total: 100 });
  var h = m.check();
  assert.equal(h.score, 100);
});

test("mixed signal statuses → intermediate score", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 4; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  for (var j = 0; j < 6; j++) m.recordSolve({ solved: false, timeMs: 5000 });
  m.recordPoolLevel({ available: 80, total: 100 });
  var h = m.check();
  assert.ok(h.score > 30 && h.score < 100);
});

test("worst signal determines overall status", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  m.recordPoolLevel({ available: 2, total: 100 });
  var h = m.check();
  assert.equal(h.status, "critical");
});

// ── Alerts ──────────────────────────────────────────────────────────

test("critical signal emits critical alert", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordSolve({ solved: false, timeMs: 5000 });
  var h = m.check();
  var critAlerts = h.alerts.filter(function (a) { return a.level === "critical"; });
  assert.ok(critAlerts.length > 0);
  assert.equal(critAlerts[0].signal, "solveRate");
});

test("degraded signal emits warning alert", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 4; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  for (var j = 0; j < 6; j++) m.recordSolve({ solved: false, timeMs: 5000 });
  var h = m.check();
  var warnings = h.alerts.filter(function (a) { return a.level === "warning"; });
  assert.ok(warnings.length > 0);
});

test("getAlerts filters by level", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordSolve({ solved: false, timeMs: 5000 });
  m.recordPoolLevel({ available: 10, total: 100 });
  m.check();

  var crits = m.getAlerts({ level: "critical" });
  for (var j = 0; j < crits.length; j++) {
    assert.equal(crits[j].level, "critical");
  }
});

test("getAlerts filters by signal", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordSolve({ solved: false, timeMs: 5000 });
  m.check();

  var solveAlerts = m.getAlerts({ signal: "solveRate" });
  for (var j = 0; j < solveAlerts.length; j++) {
    assert.equal(solveAlerts[j].signal, "solveRate");
  }
});

test("getAlerts respects limit", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordSolve({ solved: false, timeMs: 5000 });
  m.check();
  m.check();
  m.check();

  var limited = m.getAlerts({ limit: 2 });
  assert.ok(limited.length <= 2);
});

// ── Recommendations ─────────────────────────────────────────────────

test("low solve rate generates recommendation", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 4; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  for (var j = 0; j < 6; j++) m.recordSolve({ solved: false, timeMs: 5000 });
  var h = m.check();
  assert.ok(h.recommendations.some(function (r) { return r.indexOf("Solve rate") >= 0; }));
});

test("slow response generates recommendation", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m.recordSolve({ solved: true, timeMs: 10000 });
  var h = m.check();
  assert.ok(h.recommendations.some(function (r) { return r.indexOf("response time") >= 0; }));
});

test("low pool generates recommendation", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.recordPoolLevel({ available: 10, total: 100 });
  var h = m.check();
  assert.ok(h.recommendations.some(function (r) { return r.indexOf("Pool level") >= 0; }));
});

test("high bot rate generates recommendation", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 3; i++) m.recordBotDetection({ blocked: false });
  for (var j = 0; j < 7; j++) m.recordBotDetection({ blocked: true });
  var h = m.check();
  assert.ok(h.recommendations.some(function (r) { return r.indexOf("Bot rate") >= 0; }));
});

test("high error rate generates recommendation with top code", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m.recordOperation();
  for (var j = 0; j < 5; j++) m.recordError({ code: "TIMEOUT" });
  var h = m.check();
  assert.ok(h.recommendations.some(function (r) {
    return r.indexOf("Error rate") >= 0 && r.indexOf("TIMEOUT") >= 0;
  }));
});

// ── Window Eviction ─────────────────────────────────────────────────

test("old events outside window are evicted", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now, windowMs: 5000 });
  for (var i = 0; i < 5; i++) m.recordSolve({ solved: false, timeMs: 5000 });
  clock.advance(6000);
  for (var j = 0; j < 5; j++) m.recordSolve({ solved: true, timeMs: 2000 });
  var h = m.check();
  assert.equal(h.signals.solveRate.value, 1);
  assert.equal(h.signals.solveRate.solved, 5);
});

// ── Check History ───────────────────────────────────────────────────

test("check history tracks previous results", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.check();
  clock.advance(1000);
  m.check();
  clock.advance(1000);
  m.check();

  var history = m.getCheckHistory();
  assert.equal(history.length, 3);
  assert.ok(history[0].ts < history[1].ts);
  assert.ok(history[1].ts < history[2].ts);
});

test("check history respects limit", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) {
    m.check();
    clock.advance(1000);
  }
  var history = m.getCheckHistory(3);
  assert.equal(history.length, 3);
});

// ── Trend Analysis ──────────────────────────────────────────────────

test("stable scores → stable trend", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) {
    m.check();
    clock.advance(1000);
  }
  var t = m.trend();
  assert.equal(t.direction, "stable");
});

test("improving scores → improving trend", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now, windowMs: 100000 });
  for (var i = 0; i < 10; i++) m.recordSolve({ solved: false, timeMs: 5000 });
  m.check();
  clock.advance(1000);
  m.check();
  clock.advance(1000);

  for (var j = 0; j < 30; j++) m.recordSolve({ solved: true, timeMs: 2000 });
  m.check();
  clock.advance(1000);

  var t = m.trend();
  assert.equal(t.direction, "improving");
  assert.ok(t.delta > 0);
});

test("declining scores → declining trend", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now, windowMs: 100000 });
  for (var i = 0; i < 10; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  m.check();
  clock.advance(1000);
  m.check();
  clock.advance(1000);

  for (var j = 0; j < 30; j++) m.recordSolve({ solved: false, timeMs: 5000 });
  m.check();
  clock.advance(1000);

  var t = m.trend();
  assert.equal(t.direction, "declining");
  assert.ok(t.delta < 0);
});

test("trend with no history returns stable", function () {
  var m = createCaptchaHealthMonitor();
  var t = m.trend();
  assert.equal(t.direction, "stable");
  assert.equal(t.current, null);
});

// ── Summary ─────────────────────────────────────────────────────────

test("summary returns a string with status info", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  var s = m.summary();
  assert.equal(typeof s, "string");
  assert.ok(s.indexOf("HEALTHY") >= 0);
  assert.ok(s.indexOf("solveRate") >= 0);
});

test("summary includes recommendations when unhealthy", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordSolve({ solved: false, timeMs: 5000 });
  var s = m.summary();
  assert.ok(s.indexOf("Recommendations") >= 0);
  assert.ok(s.indexOf("Solve rate") >= 0);
});

// ── Reset ───────────────────────────────────────────────────────────

test("reset clears all data", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 10; i++) m.recordSolve({ solved: false, timeMs: 5000 });
  m.recordPoolLevel({ available: 2, total: 100 });
  m.recordError({ code: "FAIL" });
  m.check();

  m.reset();
  var s = m.stats();
  assert.equal(s.solves, 0);
  assert.equal(s.errors, 0);
  assert.equal(s.checksPerformed, 0);

  var h = m.check();
  assert.equal(h.status, "healthy");
  assert.equal(h.score, 100);
});

// ── Export/Import ───────────────────────────────────────────────────

test("exportJSON returns valid JSON string", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  m.check();

  var json = m.exportJSON();
  assert.equal(typeof json, "string");
  var parsed = JSON.parse(json);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.solves.length, 5);
  assert.equal(parsed.checksPerformed, 1);
});

test("importJSON restores state", function () {
  var clock = makeClock(1000000);
  var m1 = createCaptchaHealthMonitor({ nowFn: clock.now });
  for (var i = 0; i < 5; i++) m1.recordSolve({ solved: false, timeMs: 5000 });
  m1.recordError({ code: "TIMEOUT" });
  m1.check();
  var json = m1.exportJSON();

  var m2 = createCaptchaHealthMonitor({ nowFn: clock.now });
  m2.importJSON(json);
  var s = m2.stats();
  assert.equal(s.solves, 5);
  assert.equal(s.errors, 1);
  assert.equal(s.checksPerformed, 1);
});

test("importJSON with invalid data is no-op", function () {
  var m = createCaptchaHealthMonitor();
  m.importJSON("not-json");
  assert.equal(m.stats().solves, 0);

  m.importJSON(JSON.stringify({ version: 99 }));
  assert.equal(m.stats().solves, 0);
});

// ── Stats ───────────────────────────────────────────────────────────

test("stats returns event counts and config", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now, windowMs: 10000 });
  m.recordSolve({ solved: true, timeMs: 2000 });
  m.recordBotDetection({ blocked: true });
  m.recordPoolLevel({ available: 50, total: 100 });
  m.recordRateLimitHit({ key: "1.2.3.4" });
  m.recordError({ code: "E1" });
  m.recordOperation();

  var s = m.stats();
  assert.equal(s.solves, 1);
  assert.equal(s.botChecks, 1);
  assert.equal(s.poolSnapshots, 1);
  assert.equal(s.rateLimitHits, 1);
  assert.equal(s.errors, 1);
  assert.equal(s.windowMs, 10000);
  assert.ok(s.thresholds.minSolveRate > 0);
});

// ── Custom Thresholds ───────────────────────────────────────────────

test("custom thresholds override defaults", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({
    nowFn: clock.now,
    thresholds: { minSolveRate: 0.90 }
  });
  for (var i = 0; i < 7; i++) m.recordSolve({ solved: true, timeMs: 2000 });
  for (var j = 0; j < 3; j++) m.recordSolve({ solved: false, timeMs: 5000 });
  var h = m.check();
  assert.equal(h.signals.solveRate.status, "degraded");
});

// ── Edge Cases ──────────────────────────────────────────────────────

test("recordSolve ignores null/undefined input", function () {
  var m = createCaptchaHealthMonitor();
  m.recordSolve(null);
  m.recordSolve(undefined);
  m.recordSolve("string");
  assert.equal(m.stats().solves, 0);
});

test("recordBotDetection ignores invalid input", function () {
  var m = createCaptchaHealthMonitor();
  m.recordBotDetection(null);
  m.recordBotDetection(42);
  assert.equal(m.stats().botChecks, 0);
});

test("recordPoolLevel handles zero total gracefully", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.recordPoolLevel({ available: 0, total: 0 });
  var h = m.check();
  assert.equal(h.signals.poolLevel.status, "healthy");
});

test("recordError without code defaults to UNKNOWN", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.recordError({});
  for (var i = 0; i < 5; i++) m.recordOperation();
  var h = m.check();
  if (h.signals.errorRate.topCodes.length > 0) {
    assert.equal(h.signals.errorRate.topCodes[0].code, "UNKNOWN");
  }
});

test("multiple checks increment checksPerformed", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  m.check();
  m.check();
  m.check();
  assert.equal(m.check().checksPerformed, 4);
});

test("constants are exposed on the monitor instance", function () {
  var m = createCaptchaHealthMonitor();
  assert.equal(m.STATUS.HEALTHY, "healthy");
  assert.equal(m.STATUS.CRITICAL, "critical");
  assert.equal(m.SIGNALS.SOLVE_RATE, "solveRate");
  assert.equal(m.ALERT_LEVEL.WARNING, "warning");
});

test("uptime increases with clock", function () {
  var clock = makeClock(1000000);
  var m = createCaptchaHealthMonitor({ nowFn: clock.now });
  var h1 = m.check();
  clock.advance(5000);
  var h2 = m.check();
  assert.ok(h2.uptimeMs > h1.uptimeMs);
  assert.equal(h2.uptimeMs - h1.uptimeMs, 5000);
});
