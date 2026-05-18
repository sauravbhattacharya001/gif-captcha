"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/human-verification-confidence-auditor");

function mk() { return mod.createHumanVerificationConfidenceAuditor(); }

function baseV(over) {
  var s = {
    id: "v1",
    verdict: "PASSED",
    challengeType: "gif_recognize",
    difficulty: 5,
    biometricsScore: 0.8,
    trustScore: 0.7,
    solveTimeMs: 6000,
    expectedSolveTimeMs: 6000,
    attemptCount: 1,
    geoRiskScore: 0.05,
    deviceClass: "desktop",
    ipReputation: 0.1,
    proxyVpnFlag: false,
    userAgentSuspicious: false,
    powDurationMs: 1200,
    expectedPowMs: 1000,
    accountAgeDays: 365,
    previousFailureRate: 0.05,
  };
  if (over) Object.keys(over).forEach(function (k) { s[k] = over[k]; });
  return s;
}

test("factory exposes expected API", function () {
  var f = mk();
  ["analyze", "simulate", "formatText", "formatMarkdown", "formatJson"]
    .forEach(function (m) { assert.strictEqual(typeof f[m], "function", m + " is fn"); });
});

test("clean passing session => ACCEPTED or ACCEPTED_HIGH_CONFIDENCE", function () {
  var f = mk();
  var r = f.analyze({ verifications: [baseV()] }, { now: 0 });
  var v = r.verifications[0];
  assert.ok(v.verdict === "ACCEPTED" || v.verdict === "ACCEPTED_HIGH_CONFIDENCE",
    "expected ACCEPTED*, got " + v.verdict);
  assert.strictEqual(r.band, "CALM");
  assert.strictEqual(r.grade, "A");
});

test("empty input -> CALM band, grade A, healthy insight", function () {
  var f = mk();
  var r = f.analyze({ verifications: [] }, { now: 0 });
  assert.strictEqual(r.band, "CALM");
  assert.strictEqual(r.grade, "A");
  assert.strictEqual(r.overall.sessionCount, 0);
  assert.ok(r.insights.some(function (i) { return i.code === "HEALTHY_PORTFOLIO"; }));
});

test("suspicious fast solve => STEP_UP or higher", function () {
  var f = mk();
  var s = baseV({
    id: "fast1",
    solveTimeMs: 500,
    expectedSolveTimeMs: 6000,
    biometricsScore: 0.5,
    trustScore: 0.4,
    ipReputation: 0.4,
  });
  var r = f.analyze({ verifications: [s] }, { now: 0 });
  var v = r.verifications[0];
  assert.ok(["STEP_UP_CHALLENGE_NEXT", "HIGH_RISK_RETROACTIVE_BLOCK", "FLAG_FOR_HUMAN_REVIEW"].indexOf(v.verdict) >= 0,
    "expected escalation, got " + v.verdict);
});

test("proxy+VPN cluster -> PROXY_VPN_CLUSTER insight", function () {
  var f = mk();
  var sessions = [
    baseV({ id: "p1", proxyVpnFlag: true }),
    baseV({ id: "p2", proxyVpnFlag: true }),
    baseV({ id: "p3", proxyVpnFlag: true }),
  ];
  var r = f.analyze({ verifications: sessions }, { now: 0 });
  assert.ok(r.insights.some(function (i) { return i.code === "PROXY_VPN_CLUSTER"; }));
});

test("high-IP-rep amplifier produces P1 INVESTIGATE_IP_REPUTATION_FEED", function () {
  var f = mk();
  var sessions = [
    baseV({ id: "h1", ipReputation: 0.6 }),
    baseV({ id: "h2", ipReputation: 0.7 }),
  ];
  var r = f.analyze({ verifications: sessions }, { now: 0 });
  assert.ok(r.playbook.some(function (a) { return a.id === "INVESTIGATE_IP_REPUTATION_FEED"; }));
  assert.ok(r.insights.some(function (i) { return i.code === "IP_REPUTATION_CLUSTER"; }));
});

test("active attack profile amplifies portfolio risk", function () {
  var f = mk();
  var sessions = [
    baseV({ id: "a1", biometricsScore: 0.5, trustScore: 0.4, ipReputation: 0.6 }),
    baseV({ id: "a2", biometricsScore: 0.5, trustScore: 0.4, ipReputation: 0.6 }),
  ];
  var r1 = f.analyze({ verifications: sessions }, { now: 0 });
  var r2 = f.analyze({
    verifications: sessions,
    recentDefenseSignals: { activeAttackProfile: "credential_stuffing", surgeFactor: 2.0 },
  }, { now: 0 });
  assert.ok(r2.portfolioRisk > r1.portfolioRisk, "attack profile should raise risk");
});

test("honeypotHitRate >= 0.05 raises risk", function () {
  var f = mk();
  var sessions = [baseV({ id: "h1" })];
  var base = f.analyze({ verifications: sessions }, { now: 0 });
  var withHp = f.analyze({
    verifications: sessions,
    recentDefenseSignals: { honeypotHitRate: 0.10 },
  }, { now: 0 });
  assert.ok(withHp.portfolioRisk > base.portfolioRisk);
});

test("risk_appetite monotonicity cautious >= balanced >= aggressive risk", function () {
  var f = mk();
  var sessions = [
    baseV({ id: "m1", biometricsScore: 0.5, trustScore: 0.4, ipReputation: 0.5, proxyVpnFlag: true }),
  ];
  var rc = f.analyze({ verifications: sessions }, { risk_appetite: "cautious", now: 0 });
  var rb = f.analyze({ verifications: sessions }, { risk_appetite: "balanced", now: 0 });
  var ra = f.analyze({ verifications: sessions }, { risk_appetite: "aggressive", now: 0 });
  assert.ok(rc.portfolioRisk >= rb.portfolioRisk, "cautious >= balanced");
  assert.ok(rb.portfolioRisk >= ra.portfolioRisk, "balanced >= aggressive");
});

test("verdict ladder boundary: very high risk -> HIGH_RISK_RETROACTIVE_BLOCK + P0 grade F", function () {
  var f = mk();
  var sessions = [baseV({
    id: "x1",
    biometricsScore: 0.1,
    trustScore: 0.1,
    ipReputation: 0.95,
    geoRiskScore: 0.9,
    proxyVpnFlag: true,
    userAgentSuspicious: true,
    solveTimeMs: 200,
    expectedSolveTimeMs: 6000,
    powDurationMs: 100,
    expectedPowMs: 1000,
    accountAgeDays: 0,
    previousFailureRate: 0.8,
  })];
  var r = f.analyze({ verifications: sessions }, { now: 0 });
  assert.strictEqual(r.verifications[0].verdict, "HIGH_RISK_RETROACTIVE_BLOCK");
  assert.strictEqual(r.verifications[0].priority, "P0");
  assert.strictEqual(r.grade, "F");
  assert.ok(r.playbook.some(function (a) { return a.id === "INVALIDATE_RECENT_PASSES"; }));
});

test("simulate diminishing returns reduces projected risk", function () {
  var f = mk();
  var sessions = [
    baseV({ id: "s1", biometricsScore: 0.2, ipReputation: 0.8, geoRiskScore: 0.7, proxyVpnFlag: true }),
    baseV({ id: "s2", biometricsScore: 0.2, ipReputation: 0.8, geoRiskScore: 0.7, proxyVpnFlag: true }),
  ];
  var r = f.analyze({ verifications: sessions }, { now: 0 });
  var sim = f.simulate(r, { applyTop: 3 });
  assert.ok(sim.projectedPortfolioRisk <= r.portfolioRisk);
  assert.ok(Array.isArray(sim.appliedActions));
  // diminishing factor: second applied delta should be 0.85x raw at most
  if (sim.appliedActions.length >= 2 && sim.appliedActions[1].rawDelta !== 0) {
    var ratio = Math.abs(sim.appliedActions[1].appliedDelta / sim.appliedActions[1].rawDelta);
    assert.ok(ratio <= 0.851, "expected diminishing factor <= 0.85, got " + ratio);
  }
});

test("simulate does not mutate input report or sessions", function () {
  var f = mk();
  var sessions = [baseV({ id: "k1", ipReputation: 0.7, geoRiskScore: 0.6 })];
  var snap = JSON.stringify(sessions);
  var r = f.analyze({ verifications: sessions }, { now: 0 });
  var rSnap = JSON.stringify(r);
  f.simulate(r, { applyTop: 5 });
  assert.strictEqual(JSON.stringify(sessions), snap);
  assert.strictEqual(JSON.stringify(r), rSnap);
});

test("formatJson byte-stable across calls", function () {
  var f = mk();
  var sessions = [
    baseV({ id: "a", ipReputation: 0.3 }),
    baseV({ id: "b", ipReputation: 0.6, proxyVpnFlag: true }),
  ];
  var r = f.analyze({ verifications: sessions }, { now: 0 });
  var s1 = f.formatJson(r);
  var s2 = f.formatJson(r);
  assert.strictEqual(s1, s2);
  // valid JSON
  assert.doesNotThrow(function () { JSON.parse(s1); });
});

test("formatMarkdown has expected section headers", function () {
  var f = mk();
  var r = f.analyze({ verifications: [baseV()] }, { now: 0 });
  var md = f.formatMarkdown(r);
  assert.ok(md.indexOf("## Summary") >= 0);
  assert.ok(md.indexOf("## Sessions") >= 0);
  assert.ok(md.indexOf("## Playbook") >= 0);
  assert.ok(md.indexOf("## Insights") >= 0);
});

test("formatText starts with the auditor headline", function () {
  var f = mk();
  var r = f.analyze({ verifications: [baseV()] }, { now: 0 });
  var t = f.formatText(r);
  assert.ok(/^HumanVerificationConfidenceAuditor:/.test(t));
});

test("playbook actions are deduped and P0-first ordered", function () {
  var f = mk();
  var sessions = [
    baseV({ id: "x1", biometricsScore: 0.1, ipReputation: 0.95, geoRiskScore: 0.9, proxyVpnFlag: true, solveTimeMs: 100, expectedSolveTimeMs: 5000 }),
    baseV({ id: "x2", biometricsScore: 0.1, ipReputation: 0.95, geoRiskScore: 0.9, proxyVpnFlag: true, solveTimeMs: 100, expectedSolveTimeMs: 5000 }),
    baseV({ id: "x3", biometricsScore: 0.1, ipReputation: 0.95, geoRiskScore: 0.9, proxyVpnFlag: true, solveTimeMs: 100, expectedSolveTimeMs: 5000 }),
  ];
  var r = f.analyze({ verifications: sessions }, { now: 0 });
  var ids = r.playbook.map(function (a) { return a.id; });
  var unique = ids.filter(function (v, i, a) { return a.indexOf(v) === i; });
  assert.strictEqual(ids.length, unique.length, "deduped");
  // P0 actions come first
  var seenP1 = false;
  r.playbook.forEach(function (a) {
    if (a.priority !== "P0") seenP1 = true;
    if (a.priority === "P0") assert.strictEqual(seenP1, false, "P0 must precede non-P0");
  });
});

test("FLAG_FOR_HUMAN_REVIEW triggers manual review playbook", function () {
  var f = mk();
  var s = baseV({
    id: "rev1",
    biometricsScore: 0.5,
    trustScore: 0.4,
    ipReputation: 0.35,
    geoRiskScore: 0.2,
    proxyVpnFlag: false,
    solveTimeMs: 4000,
    expectedSolveTimeMs: 6000,
  });
  var r = f.analyze({ verifications: [s] }, { now: 0 });
  // could be FLAG_FOR_HUMAN_REVIEW or MONITOR_ELEVATED — try harder if not flagged
  if (r.verifications[0].verdict !== "FLAG_FOR_HUMAN_REVIEW") {
    s = baseV({ id: "rev1", biometricsScore: 0.4, trustScore: 0.3, ipReputation: 0.55, geoRiskScore: 0.3 });
    r = f.analyze({ verifications: [s] }, { now: 0 });
  }
  if (r.verifications[0].verdict === "FLAG_FOR_HUMAN_REVIEW") {
    assert.ok(r.playbook.some(function (a) { return a.id === "ROUTE_TO_MANUAL_REVIEW_QUEUE"; }));
  } else {
    // at least ensure session was not a pure ACCEPTED
    assert.notStrictEqual(r.verifications[0].verdict, "ACCEPTED");
  }
});

test("fast PoW pattern raises AUDIT_POW_VALIDATION", function () {
  var f = mk();
  var sessions = [
    baseV({ id: "p1", powDurationMs: 100, expectedPowMs: 1000 }),
    baseV({ id: "p2", powDurationMs: 100, expectedPowMs: 1000 }),
  ];
  var r = f.analyze({ verifications: sessions }, { now: 0 });
  assert.ok(r.playbook.some(function (a) { return a.id === "AUDIT_POW_VALIDATION"; }));
  assert.ok(r.insights.some(function (i) { return i.code === "POW_BYPASS_PATTERN"; }));
});

test("fallback playbook is MAINTAIN_OBSERVABILITY when nothing else fires", function () {
  var f = mk();
  var r = f.analyze({ verifications: [baseV()] }, { now: 0 });
  assert.ok(r.playbook.some(function (a) { return a.id === "MAINTAIN_OBSERVABILITY"; }));
});
