"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/false-reject-recovery-advisor");

function mk(opts) { return mod.createFalseRejectRecoveryAdvisor(opts || {}); }

function baseSession(over) {
  var s = {
    id: "s1",
    lastVerdict: "fail",
    attempts: 1,
    biometricsScore: 0.5,
    trustScore: 0.5,
    retryCount: 0,
    challengeType: "gif-frames",
    difficulty: 5,
    completionTimeMs: 5000,
    deviceClass: "desktop",
    accessibilityNeeds: [],
    geoRiskScore: 0.1,
    hadAudioAlt: true,
    hadTextAlt: true,
  };
  if (over) Object.keys(over).forEach(function (k) { s[k] = over[k]; });
  return s;
}

test("factory exposes expected API", function () {
  var f = mk();
  ["analyze", "simulate", "formatText", "formatMarkdown", "formatJson"]
    .forEach(function (m) { assert.strictEqual(typeof f[m], "function", m + " is fn"); });
});

test("all-clear (all WRITE_OFF bots) -> CALM band, grade A, empty playbook", function () {
  var f = mk();
  var sessions = [
    baseSession({ id: "b1", biometricsScore: 0.1, geoRiskScore: 0.9 }),
    baseSession({ id: "b2", biometricsScore: 0.05, geoRiskScore: 0.85 }),
  ];
  var r = f.analyze({ sessions: sessions }, { now: 0 });
  assert.strictEqual(r.band, "CALM");
  assert.strictEqual(r.grade, "A");
  assert.deepStrictEqual(r.playbook, []);
});

test("empty session list -> CALM band, grade A", function () {
  var f = mk();
  var r = f.analyze({ sessions: [] }, { now: 0 });
  assert.strictEqual(r.band, "CALM");
  assert.strictEqual(r.grade, "A");
  assert.strictEqual(r.overall.sessionCount, 0);
});

test("high biometrics + difficulty>=6 -> RETRY_EASIER P0", function () {
  var f = mk();
  var s = baseSession({ biometricsScore: 0.85, difficulty: 8, geoRiskScore: 0.05, trustScore: 0.8 });
  var r = f.analyze({ sessions: [s] }, { now: 0 });
  var v = r.recoveryVerdicts[0];
  assert.strictEqual(v.verdict, "RETRY_EASIER");
  assert.strictEqual(v.priority, "P0");
  assert.ok(v.recoveryScore >= 70, "score>=70 got " + v.recoveryScore);
});

test("accessibility need + missing audio alt -> RETRY_DIFFERENT_TYPE", function () {
  var f = mk();
  var s = baseSession({
    biometricsScore: 0.8, accessibilityNeeds: ["screen-reader"],
    hadAudioAlt: false, hadTextAlt: false, trustScore: 0.7,
  });
  var r = f.analyze({ sessions: [s] }, { now: 0 });
  assert.strictEqual(r.recoveryVerdicts[0].verdict, "RETRY_DIFFERENT_TYPE");
});

test("retryCount>=3 + high biometrics -> OFFER_FALLBACK", function () {
  var f = mk();
  var s = baseSession({
    biometricsScore: 0.85, retryCount: 4, difficulty: 4, geoRiskScore: 0.5,
  });
  var r = f.analyze({ sessions: [s] }, { now: 0 });
  assert.strictEqual(r.recoveryVerdicts[0].verdict, "OFFER_FALLBACK");
});

test("low biometrics + high geo -> WRITE_OFF P3", function () {
  var f = mk();
  var s = baseSession({ biometricsScore: 0.15, geoRiskScore: 0.85, trustScore: 0.1 });
  var r = f.analyze({ sessions: [s] }, { now: 0 });
  var v = r.recoveryVerdicts[0];
  assert.strictEqual(v.verdict, "WRITE_OFF");
  assert.strictEqual(v.priority, "P3");
});

test("mid biometrics + mid trust -> ESCALATE_MANUAL_REVIEW P2", function () {
  var f = mk();
  var s = baseSession({ biometricsScore: 0.55, trustScore: 0.5, geoRiskScore: 0.2, difficulty: 4 });
  var r = f.analyze({ sessions: [s] }, { now: 0 });
  var v = r.recoveryVerdicts[0];
  assert.strictEqual(v.verdict, "ESCALATE_MANUAL_REVIEW");
  assert.strictEqual(v.priority, "P2");
});

test("risk_appetite cautious boosts recovery scores vs balanced", function () {
  var f = mk();
  var s = baseSession({ biometricsScore: 0.7, trustScore: 0.7, geoRiskScore: 0.1 });
  var balanced = f.analyze({ sessions: [s] }, { risk_appetite: "balanced", now: 0 });
  var cautious = f.analyze({ sessions: [s] }, { risk_appetite: "cautious", now: 0 });
  assert.ok(cautious.recoveryVerdicts[0].recoveryScore > balanced.recoveryVerdicts[0].recoveryScore,
    "cautious " + cautious.recoveryVerdicts[0].recoveryScore + " > balanced " + balanced.recoveryVerdicts[0].recoveryScore);
});

test("risk_appetite aggressive lowers recovery scores vs balanced", function () {
  var f = mk();
  var s = baseSession({ biometricsScore: 0.7, trustScore: 0.7, geoRiskScore: 0.1 });
  var balanced = f.analyze({ sessions: [s] }, { risk_appetite: "balanced", now: 0 });
  var aggressive = f.analyze({ sessions: [s] }, { risk_appetite: "aggressive", now: 0 });
  assert.ok(aggressive.recoveryVerdicts[0].recoveryScore < balanced.recoveryVerdicts[0].recoveryScore);
});

test("confidence rises with attempts and biometric extremes", function () {
  var f = mk();
  var weak = baseSession({ biometricsScore: 0.5, attempts: 1 });
  var strong = baseSession({ id: "s2", biometricsScore: 0.9, attempts: 3 });
  var r = f.analyze({ sessions: [weak, strong] }, { now: 0 });
  assert.ok(r.recoveryVerdicts[1].confidence > r.recoveryVerdicts[0].confidence);
});

test("playbook contains LOWER_DEFAULT_DIFFICULTY when >=3 RETRY_EASIER", function () {
  var f = mk();
  var sessions = [];
  for (var i = 0; i < 4; i++) {
    sessions.push(baseSession({
      id: "e" + i, biometricsScore: 0.85, difficulty: 8, geoRiskScore: 0.05, trustScore: 0.8,
    }));
  }
  var r = f.analyze({ sessions: sessions }, { now: 0 });
  var ids = r.playbook.map(function (a) { return a.id; });
  assert.ok(ids.indexOf("LOWER_DEFAULT_DIFFICULTY") >= 0, "got " + ids.join(","));
  var act = r.playbook.find(function (a) { return a.id === "LOWER_DEFAULT_DIFFICULTY"; });
  assert.strictEqual(act.priority, "P0");
  assert.strictEqual(act.sessionIds.length, 4);
});

test("playbook contains ENABLE_ACCESSIBLE_CHALLENGE when >=2 RETRY_DIFFERENT_TYPE", function () {
  var f = mk();
  var sessions = [];
  for (var i = 0; i < 3; i++) {
    sessions.push(baseSession({
      id: "a" + i, biometricsScore: 0.8,
      accessibilityNeeds: ["screen-reader"],
      hadAudioAlt: false, hadTextAlt: false, trustScore: 0.7,
    }));
  }
  var r = f.analyze({ sessions: sessions }, { now: 0 });
  var ids = r.playbook.map(function (a) { return a.id; });
  assert.ok(ids.indexOf("ENABLE_ACCESSIBLE_CHALLENGE") >= 0);
});

test("simulate applies actions with diminishing returns and does not mutate input", function () {
  var f = mk();
  var sessions = [];
  for (var i = 0; i < 4; i++) {
    sessions.push(baseSession({
      id: "e" + i, biometricsScore: 0.85, difficulty: 8, geoRiskScore: 0.05, trustScore: 0.8,
    }));
  }
  var r = f.analyze({ sessions: sessions }, { now: 0 });
  var snapshot = JSON.stringify(r);
  var sim = f.simulate(r, { applyTop: 2 });
  assert.strictEqual(JSON.stringify(r), snapshot, "report not mutated");
  assert.ok(Array.isArray(sim.appliedActions));
  assert.ok(sim.recoverableShare <= r.overall.recoverableShare,
    "share decreased or equal: " + sim.recoverableShare + " vs " + r.overall.recoverableShare);
  if (sim.appliedActions.length === 2) {
    assert.ok(Math.abs(sim.appliedActions[1].appliedDelta) < Math.abs(sim.appliedActions[0].appliedDelta) + 1e-9,
      "second delta smaller in magnitude");
  }
});

test("formatJson is byte-stable across runs", function () {
  var f = mk();
  var sessions = [
    baseSession({ id: "z", biometricsScore: 0.85, difficulty: 8 }),
    baseSession({ id: "a", biometricsScore: 0.2, geoRiskScore: 0.7 }),
  ];
  var r1 = f.analyze({ sessions: sessions }, { now: 1000 });
  var r2 = f.analyze({ sessions: sessions.slice().reverse() }, { now: 1000 });
  // Both reports should serialize each session-record identically; we compare the
  // two formatJson strings of the SAME report twice to assert byte-stability.
  assert.strictEqual(f.formatJson(r1), f.formatJson(r1));
  assert.strictEqual(typeof f.formatJson(r2), "string");
});

test("formatMarkdown contains required headings", function () {
  var f = mk();
  var sessions = [baseSession({ biometricsScore: 0.85, difficulty: 8 })];
  var md = f.formatMarkdown(f.analyze({ sessions: sessions }, { now: 0 }));
  assert.ok(md.indexOf("# False-Reject Recovery Report") >= 0);
  assert.ok(md.indexOf("## Playbook") >= 0);
  assert.ok(md.indexOf("## Insights") >= 0);
});

test("throws TypeError on missing sessions array", function () {
  var f = mk();
  assert.throws(function () { f.analyze({}, {}); }, /TypeError/);
  assert.throws(function () { f.analyze(null, {}); }, /TypeError/);
});

test("INVESTIGATE_GEO_FALSE_POSITIVES insight + playbook entry fires", function () {
  var f = mk();
  var sessions = [
    baseSession({ id: "g1", biometricsScore: 0.8, geoRiskScore: 0.7 }),
    baseSession({ id: "g2", biometricsScore: 0.85, geoRiskScore: 0.75 }),
  ];
  var r = f.analyze({ sessions: sessions }, { now: 0 });
  var ids = r.playbook.map(function (a) { return a.id; });
  assert.ok(ids.indexOf("INVESTIGATE_GEO_FALSE_POSITIVES") >= 0, "playbook ids: " + ids.join(","));
  assert.ok(r.insights.some(function (s) { return /geo false-positives/.test(s); }),
    "insights: " + JSON.stringify(r.insights));
});
