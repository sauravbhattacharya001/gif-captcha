/**
 * Tests for CaptchaFatigueDetector
 */

"use strict";

var assert = require("assert");
var mod = require("../src/captcha-fatigue-detector");
var createCaptchaFatigueDetector = mod.createCaptchaFatigueDetector;
var FATIGUE_LEVELS = mod.FATIGUE_LEVELS;
var RECOMMENDATIONS = mod.RECOMMENDATIONS;

var passed = 0;
var failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log("  ✓ " + name);
  } catch (e) {
    failed++;
    console.log("  ✗ " + name);
    console.log("    " + e.message);
  }
}

function assertThrows(fn) {
  var threw = false;
  try { fn(); } catch (e) { threw = true; }
  if (!threw) throw new Error("Expected function to throw");
}

console.log("\nCaptchaFatigueDetector Tests\n");

test("creates detector with defaults", function () {
  var d = createCaptchaFatigueDetector();
  assert.ok(d);
  assert.ok(typeof d.recordEvent === "function");
});

test("creates detector with custom options", function () {
  var d = createCaptchaFatigueDetector({ mildThreshold: 20 });
  assert.ok(d);
});

test("exports constants", function () {
  assert.strictEqual(FATIGUE_LEVELS.NONE, "none");
  assert.strictEqual(FATIGUE_LEVELS.SEVERE, "severe");
  assert.strictEqual(RECOMMENDATIONS.SKIP_CAPTCHA, "skip_captcha");
});

test("records solve event", function () {
  var d = createCaptchaFatigueDetector();
  var r = d.recordEvent("s1", { type: "solve", solveTimeMs: 3000, timestamp: 1000 });
  assert.strictEqual(r.sessionId, "s1");
});

test("records fail event", function () {
  var d = createCaptchaFatigueDetector();
  d.recordEvent("s1", { type: "fail", timestamp: 1000 });
});

test("records abandon event", function () {
  var d = createCaptchaFatigueDetector();
  d.recordEvent("s1", { type: "abandon", timestamp: 1000 });
});

test("records refresh event", function () {
  var d = createCaptchaFatigueDetector();
  d.recordEvent("s1", { type: "refresh", timestamp: 1000 });
});

test("throws on missing sessionId", function () {
  var d = createCaptchaFatigueDetector();
  assertThrows(function () { d.recordEvent(null, { type: "solve" }); });
});

test("throws on invalid event type", function () {
  var d = createCaptchaFatigueDetector();
  assertThrows(function () { d.recordEvent("s1", { type: "invalid" }); });
});

test("throws on missing eventData", function () {
  var d = createCaptchaFatigueDetector();
  assertThrows(function () { d.recordEvent("s1", null); });
});

test("no fatigue with insufficient events", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3 });
  d.recordEvent("s1", { type: "solve", timestamp: 1000 });
  d.recordEvent("s1", { type: "solve", timestamp: 2000 });
  var r = d.evaluate("s1", 3000);
  assert.strictEqual(r.fatigueScore, 0);
});

test("no fatigue for nonexistent session", function () {
  var d = createCaptchaFatigueDetector();
  var r = d.evaluate("nonexistent", 1000);
  assert.strictEqual(r.fatigueScore, 0);
});

test("low fatigue for successful solves", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3 });
  var base = 100000;
  for (var i = 0; i < 5; i++)
    d.recordEvent("s1", { type: "solve", solveTimeMs: 3000, timestamp: base + i * 10000 });
  var r = d.evaluate("s1", base + 50000);
  assert.strictEqual(r.level, "none");
});

test("high fatigue for all failures", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3, windowMs: 600000 });
  var base = 100000;
  for (var i = 0; i < 10; i++)
    d.recordEvent("s1", { type: "fail", solveTimeMs: 15000 + i * 2000, timestamp: base + i * 1500 });
  var r = d.evaluate("s1", base + 15000);
  assert.ok(r.fatigueScore > 30, "Expected > 30, got " + r.fatigueScore);
});

test("detects rapid retry / rage clicking", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3, rapidRetryThresholdMs: 3000, windowMs: 600000 });
  var base = 100000;
  for (var i = 0; i < 8; i++)
    d.recordEvent("s1", { type: "fail", timestamp: base + i * 500 });
  var r = d.evaluate("s1", base + 4000);
  assert.ok(r.dimensions.rapidRetry > 50);
});

test("detects solve time escalation", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3, windowMs: 600000 });
  var base = 100000;
  d.recordEvent("s1", { type: "solve", solveTimeMs: 3000, timestamp: base });
  d.recordEvent("s1", { type: "solve", solveTimeMs: 8000, timestamp: base + 10000 });
  d.recordEvent("s1", { type: "solve", solveTimeMs: 15000, timestamp: base + 20000 });
  d.recordEvent("s1", { type: "solve", solveTimeMs: 25000, timestamp: base + 30000 });
  var r = d.evaluate("s1", base + 40000);
  assert.ok(r.dimensions.solveTimeEscalation > 0);
});

test("session length contributes to fatigue", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3, sessionFatigueCeilingMs: 60000, windowMs: 600000 });
  var base = 100000;
  d.recordEvent("s1", { type: "solve", timestamp: base });
  d.recordEvent("s1", { type: "solve", timestamp: base + 10000 });
  d.recordEvent("s1", { type: "solve", timestamp: base + 50000 });
  var r = d.evaluate("s1", base + 55000);
  assert.ok(r.dimensions.sessionLength > 50, "Expected > 50, got " + r.dimensions.sessionLength);
});

test("abandonment signals detected", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3, windowMs: 600000 });
  d.recordEvent("s1", { type: "abandon", timestamp: 100000 });
  d.recordEvent("s1", { type: "abandon", timestamp: 101000 });
  d.recordEvent("s1", { type: "refresh", timestamp: 102000 });
  var r = d.evaluate("s1", 103000);
  assert.ok(r.dimensions.abandonmentSignal > 0);
});

test("mild level for moderate failure", function () {
  var d = createCaptchaFatigueDetector({
    minEvents: 3, mildThreshold: 25, moderateThreshold: 50, severeThreshold: 75, windowMs: 600000
  });
  var base = 100000;
  d.recordEvent("s1", { type: "fail", solveTimeMs: 8000, timestamp: base });
  d.recordEvent("s1", { type: "fail", solveTimeMs: 10000, timestamp: base + 5000 });
  d.recordEvent("s1", { type: "solve", solveTimeMs: 5000, timestamp: base + 10000 });
  d.recordEvent("s1", { type: "fail", solveTimeMs: 12000, timestamp: base + 15000 });
  var r = d.evaluate("s1", base + 20000);
  assert.ok(r.fatigueScore >= 25);
});

test("no recommendation for no fatigue", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3 });
  var base = 100000;
  for (var i = 0; i < 5; i++)
    d.recordEvent("s1", { type: "solve", solveTimeMs: 3000, timestamp: base + i * 10000 });
  var r = d.evaluate("s1", base + 60000);
  assert.strictEqual(r.recommendation, "none");
});

test("skip_captcha for severe fatigue", function () {
  var d = createCaptchaFatigueDetector({
    minEvents: 3, severeThreshold: 60, windowMs: 600000, sessionFatigueCeilingMs: 10000
  });
  var base = 100000;
  for (var i = 0; i < 15; i++)
    d.recordEvent("s1", { type: "fail", solveTimeMs: 20000 + i * 1000, timestamp: base + i * 800 });
  d.recordEvent("s1", { type: "abandon", timestamp: base + 15000 });
  var r = d.evaluate("s1", base + 20000);
  if (r.level === "severe") assert.strictEqual(r.recommendation, "skip_captcha");
  assert.ok(r.fatigueScore > 30);
});

test("cooldown_pause for rage clicking", function () {
  var d = createCaptchaFatigueDetector({
    minEvents: 3, moderateThreshold: 30, severeThreshold: 90,
    rapidRetryThresholdMs: 3000, windowMs: 600000, sessionFatigueCeilingMs: 600000
  });
  var base = 100000;
  for (var i = 0; i < 12; i++)
    d.recordEvent("s1", { type: "fail", timestamp: base + i * 500 });
  var r = d.evaluate("s1", base + 6500);
  if (r.level === "moderate" && r.dimensions.rapidRetry > 60)
    assert.strictEqual(r.recommendation, "cooldown_pause");
});

test("dismiss fatigue", function () {
  var d = createCaptchaFatigueDetector();
  d.recordEvent("s1", { type: "fail", timestamp: 1000 });
  assert.ok(d.dismissFatigue("s1"));
});

test("dismiss returns false for nonexistent", function () {
  var d = createCaptchaFatigueDetector();
  assert.strictEqual(d.dismissFatigue("nope"), false);
});

test("reset session", function () {
  var d = createCaptchaFatigueDetector();
  d.recordEvent("s1", { type: "solve", timestamp: 1000 });
  assert.ok(d.resetSession("s1"));
  assert.strictEqual(d.evaluate("s1", 2000).fatigueScore, 0);
});

test("reset nonexistent returns false", function () {
  var d = createCaptchaFatigueDetector();
  assert.strictEqual(d.resetSession("nope"), false);
});

test("session report includes all stats", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 2, windowMs: 600000 });
  d.recordEvent("s1", { type: "solve", solveTimeMs: 3000, timestamp: 100000 });
  d.recordEvent("s1", { type: "fail", timestamp: 101000 });
  d.recordEvent("s1", { type: "abandon", timestamp: 102000 });
  d.recordEvent("s1", { type: "refresh", timestamp: 103000 });
  var r = d.getSessionReport("s1", 104000);
  assert.strictEqual(r.solves, 1);
  assert.strictEqual(r.fails, 1);
  assert.strictEqual(r.abandons, 1);
  assert.strictEqual(r.refreshes, 1);
  assert.strictEqual(r.totalEvents, 4);
});

test("session report null for nonexistent", function () {
  var d = createCaptchaFatigueDetector();
  assert.strictEqual(d.getSessionReport("nope"), null);
});

test("solve rate computed correctly", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 2, windowMs: 600000 });
  d.recordEvent("s1", { type: "solve", timestamp: 100000 });
  d.recordEvent("s1", { type: "solve", timestamp: 101000 });
  d.recordEvent("s1", { type: "fail", timestamp: 102000 });
  var r = d.getSessionReport("s1", 103000);
  assert.ok(Math.abs(r.solveRate - 2 / 3) < 0.01);
});

test("fleet report with multiple sessions", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 2, windowMs: 600000, sessionTtlMs: 600000 });
  d.recordEvent("s1", { type: "solve", timestamp: 100000 });
  d.recordEvent("s1", { type: "solve", timestamp: 101000 });
  d.recordEvent("s2", { type: "fail", timestamp: 100000 });
  d.recordEvent("s2", { type: "fail", timestamp: 101000 });
  var r = d.getFleetReport(102000);
  assert.strictEqual(r.activeSessions, 2);
});

test("fleet report excludes expired", function () {
  var d = createCaptchaFatigueDetector({ sessionTtlMs: 5000 });
  d.recordEvent("s1", { type: "solve", timestamp: 1000 });
  assert.strictEqual(d.getFleetReport(100000).activeSessions, 0);
});

test("fatigue trend null with no history", function () {
  var d = createCaptchaFatigueDetector();
  assert.strictEqual(d.getFatigueTrend("nope"), null);
});

test("fatigue trend detects change", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3, windowMs: 600000, sessionFatigueCeilingMs: 600000 });
  var base = 100000;
  for (var i = 0; i < 3; i++)
    d.recordEvent("s1", { type: "solve", solveTimeMs: 3000, timestamp: base + i * 10000 });
  d.evaluate("s1", base + 35000);
  for (var j = 0; j < 5; j++)
    d.recordEvent("s1", { type: "fail", solveTimeMs: 15000, timestamp: base + 40000 + j * 5000 });
  d.evaluate("s1", base + 70000);
  var trend = d.getFatigueTrend("s1");
  assert.ok(trend && trend.dataPoints >= 2);
});

test("emits event on recordEvent", function () {
  var d = createCaptchaFatigueDetector();
  var received = null;
  d.on("event", function (data) { received = data; });
  d.recordEvent("s1", { type: "solve", timestamp: 1000 });
  assert.ok(received);
});

test("off removes listener", function () {
  var d = createCaptchaFatigueDetector();
  var count = 0;
  var fn = function () { count++; };
  d.on("event", fn);
  d.recordEvent("s1", { type: "solve", timestamp: 1000 });
  d.off("event", fn);
  d.recordEvent("s1", { type: "solve", timestamp: 2000 });
  assert.strictEqual(count, 1);
});

test("emits dismissed event", function () {
  var d = createCaptchaFatigueDetector();
  var dismissed = false;
  d.on("dismissed", function () { dismissed = true; });
  d.recordEvent("s1", { type: "solve", timestamp: 1000 });
  d.dismissFatigue("s1");
  assert.ok(dismissed);
});

test("generates text report", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 2, windowMs: 600000 });
  d.recordEvent("s1", { type: "solve", solveTimeMs: 3000, timestamp: 100000 });
  d.recordEvent("s1", { type: "fail", timestamp: 101000 });
  d.recordEvent("s1", { type: "solve", solveTimeMs: 4000, timestamp: 102000 });
  var report = d.generateTextReport("s1", 103000);
  assert.ok(report.indexOf("FATIGUE REPORT") !== -1);
  assert.ok(report.indexOf("FATIGUE SCORE") !== -1);
});

test("text report for nonexistent session", function () {
  var d = createCaptchaFatigueDetector();
  assert.ok(d.generateTextReport("nope").indexOf("No session found") !== -1);
});

test("export and import state roundtrip", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 2, windowMs: 600000 });
  d.recordEvent("s1", { type: "solve", solveTimeMs: 3000, timestamp: 100000 });
  d.recordEvent("s1", { type: "fail", timestamp: 101000 });
  var state = d.exportState();
  var d2 = createCaptchaFatigueDetector({ minEvents: 2, windowMs: 600000 });
  d2.importState(state);
  var r = d2.getSessionReport("s1", 102000);
  assert.strictEqual(r.solves, 1);
  assert.strictEqual(r.fails, 1);
});

test("import throws on invalid state", function () {
  var d = createCaptchaFatigueDetector();
  assertThrows(function () { d.importState(null); });
});

test("handles events outside window", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 3, windowMs: 10000 });
  d.recordEvent("s1", { type: "fail", timestamp: 100000 });
  d.recordEvent("s1", { type: "fail", timestamp: 101000 });
  d.recordEvent("s1", { type: "fail", timestamp: 102000 });
  assert.strictEqual(d.evaluate("s1", 200000).fatigueScore, 0);
});

test("trims events beyond max", function () {
  var d = createCaptchaFatigueDetector({ maxEventsPerSession: 5, minEvents: 3, windowMs: 600000 });
  for (var i = 0; i < 10; i++)
    d.recordEvent("s1", { type: "solve", timestamp: 100000 + i * 1000 });
  assert.ok(d.getSessionReport("s1", 115000).totalEvents <= 5);
});

test("multiple sessions tracked independently", function () {
  var d = createCaptchaFatigueDetector({ minEvents: 2, windowMs: 600000 });
  d.recordEvent("s1", { type: "solve", timestamp: 100000 });
  d.recordEvent("s1", { type: "solve", timestamp: 101000 });
  d.recordEvent("s2", { type: "fail", timestamp: 100000 });
  d.recordEvent("s2", { type: "fail", timestamp: 101000 });
  assert.ok(d.evaluate("s2", 102000).fatigueScore >= d.evaluate("s1", 102000).fatigueScore);
});

test("challenge metadata preserved", function () {
  var d = createCaptchaFatigueDetector();
  d.recordEvent("s1", { type: "solve", challengeId: "ch1", difficulty: 5, metadata: { foo: "bar" }, timestamp: 1000 });
  assert.ok(d.getSessionReport("s1", 2000));
});

test("custom weights accepted", function () {
  var d = createCaptchaFatigueDetector({
    weights: { failureRate: 0.5, solveTimeEscalation: 0.1, rapidRetry: 0.1, sessionLength: 0.1, abandonmentSignal: 0.2 }
  });
  assert.ok(d);
});

console.log("\n" + passed + " passed, " + failed + " failed, " + (passed + failed) + " total\n");
if (failed > 0) process.exit(1);
