/**
 * captcha-replay-detector.test.js — Tests for the Replay Attack Detector.
 */

"use strict";

var _require = require("node:test");
var describe = _require.describe;
var it = _require.it;
var assert = require("node:assert/strict");
var _det = require("../src/captcha-replay-detector");
var CaptchaReplayDetector = _det.CaptchaReplayDetector;

describe("CaptchaReplayDetector", function () {

  it("allows normal solves", function () {
    var d = new CaptchaReplayDetector();
    var r = d.recordSolve("s1", "token-abc", 2500, "1.2.3.4");
    assert.equal(r.allowed, true);
    assert.equal(r.flags.length, 0);
    assert.equal(r.threatScore, 0);
  });

  it("detects token replay", function () {
    var d = new CaptchaReplayDetector();
    d.recordSolve("s1", "tok1", 2000, "1.1.1.1");
    var r = d.recordSolve("s2", "tok1", 2100, "2.2.2.2");
    assert.ok(r.flags.indexOf("token-replay") !== -1);
    assert.ok(r.threatScore >= 30);
  });

  it("detects timing anomaly for fast solves", function () {
    var d = new CaptchaReplayDetector({ minSolveMs: 800 });
    var r = d.recordSolve("s1", "tok-fast", 200, "1.1.1.1");
    assert.ok(r.flags.indexOf("timing-anomaly") !== -1);
    assert.ok(r.threatScore > 0);
  });

  it("detects identical timing patterns", function () {
    var d = new CaptchaReplayDetector();
    d.recordSolve("s1", "a", 1500, "1.1.1.1");
    d.recordSolve("s1", "b", 1501, "1.1.1.1");
    d.recordSolve("s1", "c", 1500, "1.1.1.1");
    d.recordSolve("s1", "d", 1501, "1.1.1.1");
    var r = d.recordSolve("s1", "e", 1500, "1.1.1.1");
    assert.ok(r.flags.indexOf("timing-anomaly") !== -1);
  });

  it("detects pattern match across IPs", function () {
    var d = new CaptchaReplayDetector();
    d.recordSolve("s1", "shared-tok", 2000, "1.1.1.1");
    var r = d.recordSolve("s2", "shared-tok", 2000, "2.2.2.2");
    // same token+time from different IPs → both token-replay and pattern-match
    assert.ok(r.flags.indexOf("pattern-match") !== -1);
  });

  it("detects fingerprint clustering", function () {
    var d = new CaptchaReplayDetector();
    var fp = "mouse:fast;scroll:none;keys:robotic";
    d.recordSolve("s1", "t1", 2000, "1.1.1.1", fp);
    d.recordSolve("s2", "t2", 2100, "2.2.2.2", fp);
    d.recordSolve("s3", "t3", 2200, "3.3.3.3", fp);
    var r = d.recordSolve("s4", "t4", 2300, "4.4.4.4", fp);
    assert.ok(r.flags.indexOf("fingerprint-cluster") !== -1);
  });

  it("auto-blocks when enabled and threshold exceeded", function () {
    var d = new CaptchaReplayDetector({ autoBlock: true, threatThreshold: 30 });
    d.recordSolve("s1", "tok-x", 2000, "1.1.1.1");
    // Replay same token → should trigger block
    var r = d.recordSolve("s1", "tok-x", 2000, "1.1.1.1");
    assert.ok(r.threatScore >= 30);
    assert.equal(r.allowed, false);
    // Subsequent calls also blocked
    var r2 = d.recordSolve("s1", "tok-new", 3000, "1.1.1.1");
    assert.equal(r2.allowed, false);
  });

  it("emits replay-detected event", function (_, done) {
    var d = new CaptchaReplayDetector();
    d.on("replay-detected", function (e) {
      assert.equal(e.sessionId, "s2");
      done();
    });
    d.recordSolve("s1", "tok-evt", 2000, "1.1.1.1");
    d.recordSolve("s2", "tok-evt", 2100, "2.2.2.2");
  });

  it("getSessionProfile returns correct data", function () {
    var d = new CaptchaReplayDetector();
    d.recordSolve("s1", "t1", 2000, "1.1.1.1");
    d.recordSolve("s1", "t2", 2100, "1.1.1.1");
    var p = d.getSessionProfile("s1");
    assert.equal(p.sessionId, "s1");
    assert.equal(p.solveCount, 2);
    assert.equal(p.blocked, false);
    assert.equal(typeof p.avgThreatScore, "number");
  });

  it("getSessionProfile returns null for unknown session", function () {
    var d = new CaptchaReplayDetector();
    assert.equal(d.getSessionProfile("nope"), null);
  });

  it("getStats tracks correctly", function () {
    var d = new CaptchaReplayDetector();
    d.recordSolve("s1", "t1", 2000, "1.1.1.1");
    d.recordSolve("s2", "t1", 2100, "2.2.2.2");
    var s = d.getStats();
    assert.equal(s.totalSolves, 2);
    assert.equal(s.replaysDetected, 1);
    assert.ok(s.replayRate > 0);
  });

  it("reset clears all state", function () {
    var d = new CaptchaReplayDetector();
    d.recordSolve("s1", "t1", 2000, "1.1.1.1");
    d.reset();
    var s = d.getStats();
    assert.equal(s.totalSolves, 0);
    assert.equal(s.activeSessions, 0);
    assert.equal(d.getSessionProfile("s1"), null);
  });

});
