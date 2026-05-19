"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/captcha-type-mix-optimizer");

function mk() { return mod.createCaptchaTypeMixOptimizer(); }

var NOW = Date.parse("2026-05-19T00:00:00Z");

function strongType(over) {
  var t = {
    id: "img1", kind: "image", currentSharePct: 50,
    impressions: 10000, solves: 9000, failures: 800, abandonments: 200,
    avgSolveSeconds: 6, botPassRate: 0.02, accessibilityScore: 0.85,
    costUsdPer1k: 0.5, a11yIncidents: 0, userComplaintRate: 0.01,
    recentTrend: 0, isFallbackOnly: false,
  };
  if (over) Object.keys(over).forEach(function (k) { t[k] = over[k]; });
  return t;
}

function leakyText(over) {
  var t = {
    id: "txt1", kind: "text", currentSharePct: 50,
    impressions: 10000, solves: 5000, failures: 2000, abandonments: 3000,
    avgSolveSeconds: 25, botPassRate: 0.40, accessibilityScore: 0.30,
    costUsdPer1k: 0.4, a11yIncidents: 12, userComplaintRate: 0.10,
    recentTrend: 0.4, isFallbackOnly: false,
  };
  if (over) Object.keys(over).forEach(function (k) { t[k] = over[k]; });
  return t;
}

test("factory exposes expected API", function () {
  var f = mk();
  ["analyze", "recommendMix", "formatText", "formatMarkdown", "formatJson"]
    .forEach(function (m) { assert.strictEqual(typeof f[m], "function", m + " is fn"); });
});

test("empty input -> CALM band, grade A, HEALTHY/SOLID insights", function () {
  var f = mk();
  var r = f.analyze({ types: [] }, { now: NOW });
  assert.strictEqual(r.band, "CALM");
  assert.strictEqual(r.grade, "A");
  assert.strictEqual(r.summary.totalTypes, 0);
  var codes = r.insights.map(function (i) { return i.code; });
  assert.ok(codes.indexOf("HEALTHY_PORTFOLIO") >= 0);
  assert.ok(codes.indexOf("SOLID_PORTFOLIO") >= 0);
  assert.ok(Array.isArray(r.playbook) && r.playbook.length >= 1);
});

test("null/undefined input safe", function () {
  var f = mk();
  var r1 = f.analyze(null, { now: NOW });
  var r2 = f.analyze(undefined, {});
  assert.strictEqual(r1.band, "CALM");
  assert.strictEqual(r2.band, "CALM");
});

test("share-sum mismatch triggers INSUFFICIENT_DATA_OR_BAD_INPUT", function () {
  var f = mk();
  var r = f.analyze({ types: [strongType({ currentSharePct: 30 }), leakyText({ currentSharePct: 30 })] }, { now: NOW });
  var codes = r.insights.map(function (i) { return i.code; });
  assert.ok(codes.indexOf("INSUFFICIENT_DATA_OR_BAD_INPUT") >= 0);
});

test("high botPassRate triggers RETIRE + P0 + LEAKY_TYPE_DOMINANT", function () {
  var f = mk();
  // Two types so share totals 100.
  var leaky = leakyText({ currentSharePct: 60, botPassRate: 0.6, a11yIncidents: 12 });
  var ok = strongType({ currentSharePct: 40 });
  var r = f.analyze({ types: [leaky, ok] }, { now: NOW });
  var leakyAssessment = r.perType.filter(function (p) { return p.id === "txt1"; })[0];
  assert.ok(leakyAssessment, "leaky present");
  assert.strictEqual(leakyAssessment.verdict, "RETIRE");
  assert.strictEqual(leakyAssessment.priority, "P0");
  var codes = r.insights.map(function (i) { return i.code; });
  assert.ok(codes.indexOf("LEAKY_TYPE_DOMINANT") >= 0);
  var pcodes = r.playbook.map(function (p) { return p.code; });
  assert.ok(pcodes.indexOf("RETIRE_FAILED_TYPE") >= 0);
});

test("a11y_incidents>=10 forces RETIRE", function () {
  var f = mk();
  var bad = strongType({ id: "img_a11y", a11yIncidents: 15, currentSharePct: 50 });
  var ok = strongType({ id: "img_ok", currentSharePct: 50 });
  var r = f.analyze({ types: [bad, ok] }, { now: NOW });
  var v = r.perType.filter(function (p) { return p.id === "img_a11y"; })[0];
  assert.strictEqual(v.verdict, "RETIRE");
});

test("SCALE_UP verdict on strong performer", function () {
  var f = mk();
  var beh = strongType({ id: "beh1", kind: "behavioral", currentSharePct: 10 });
  var img = strongType({ id: "img1", currentSharePct: 90 });
  var r = f.analyze({ types: [beh, img] }, { now: NOW });
  var v = r.perType.filter(function (p) { return p.id === "img1"; })[0];
  assert.strictEqual(v.verdict, "SCALE_UP");
  var pcodes = r.playbook.map(function (p) { return p.code; });
  assert.ok(pcodes.indexOf("SCALE_PROVEN_PERFORMER") >= 0);
});

test("risk_appetite monotonicity: cautious >= balanced >= aggressive portfolio risk", function () {
  var f = mk();
  var types = [leakyText({ currentSharePct: 40 }), strongType({ currentSharePct: 60 })];
  var rC = f.analyze({ types: types }, { now: NOW, risk_appetite: "cautious" });
  var rB = f.analyze({ types: types }, { now: NOW, risk_appetite: "balanced" });
  var rA = f.analyze({ types: types }, { now: NOW, risk_appetite: "aggressive" });
  assert.ok(rC.summary.portfolioRisk >= rB.summary.portfolioRisk - 1e-6);
  assert.ok(rB.summary.portfolioRisk >= rA.summary.portfolioRisk - 1e-6);
});

test("formatJson is deterministic (byte-equal)", function () {
  var f = mk();
  var types = [strongType({ currentSharePct: 50 }), leakyText({ currentSharePct: 50 })];
  var r1 = f.analyze({ types: types }, { now: NOW });
  var r2 = f.analyze({ types: types }, { now: NOW });
  assert.strictEqual(f.formatJson(r1), f.formatJson(r2));
});

test("recommendMix allocations sum to ~totalBudgetPct", function () {
  var f = mk();
  var types = [
    strongType({ id: "a", currentSharePct: 40 }),
    strongType({ id: "b", currentSharePct: 30 }),
    strongType({ id: "c", kind: "behavioral", currentSharePct: 30 }),
  ];
  var r = f.analyze({ types: types }, { now: NOW });
  var mix = f.recommendMix(r);
  var sum = 0;
  mix.allocations.forEach(function (al) { sum += al.recommendedPct; });
  assert.ok(Math.abs(sum - 100) <= 0.5, "sum=" + sum);
});

test("recommendMix sets RETIRE entry to 0 and labels REPLACE", function () {
  var f = mk();
  var types = [
    leakyText({ id: "bad", currentSharePct: 40, botPassRate: 0.7, a11yIncidents: 12 }),
    strongType({ id: "good", currentSharePct: 30 }),
    strongType({ id: "beh", kind: "behavioral", currentSharePct: 30 }),
  ];
  var r = f.analyze({ types: types }, { now: NOW });
  var mix = f.recommendMix(r);
  var bad = mix.allocations.filter(function (a) { return a.typeId === "bad"; })[0];
  assert.strictEqual(bad.recommendedPct, 0);
  assert.strictEqual(bad.action, "REPLACE");
});

test("OVER_CONCENTRATED insight when single kind has >=70 share", function () {
  var f = mk();
  var types = [
    strongType({ id: "big", currentSharePct: 80 }),
    strongType({ id: "small", kind: "behavioral", currentSharePct: 20 }),
  ];
  var r = f.analyze({ types: types }, { now: NOW });
  var codes = r.insights.map(function (i) { return i.code; });
  assert.ok(codes.indexOf("OVER_CONCENTRATED") >= 0);
});

test("BEHAVIORAL_LAYER_MISSING when no behavioral/honeypot kind has share>=5", function () {
  var f = mk();
  var types = [
    strongType({ id: "i1", currentSharePct: 60 }),
    strongType({ id: "i2", kind: "puzzle", currentSharePct: 40 }),
  ];
  var r = f.analyze({ types: types }, { now: NOW });
  var codes = r.insights.map(function (i) { return i.code; });
  assert.ok(codes.indexOf("BEHAVIORAL_LAYER_MISSING") >= 0);
  var pcodes = r.playbook.map(function (p) { return p.code; });
  assert.ok(pcodes.indexOf("ADD_BEHAVIORAL_OR_HONEYPOT_LAYER") >= 0);
});

test("markdown renderer contains expected section headers", function () {
  var f = mk();
  var types = [strongType({ currentSharePct: 50 }), leakyText({ currentSharePct: 50 })];
  var r = f.analyze({ types: types }, { now: NOW });
  var md = f.formatMarkdown(r);
  assert.ok(md.indexOf("## Headline") >= 0);
  assert.ok(md.indexOf("## Per-type") >= 0);
  assert.ok(md.indexOf("## Playbook") >= 0);
  assert.ok(md.indexOf("## Insights") >= 0);
});

test("aggressive risk trims P3 playbook entries", function () {
  var f = mk();
  // Use low-impression types -> MONITOR verdict -> MONITOR_BORDERLINE P3.
  var types = [
    strongType({ id: "a", currentSharePct: 50, impressions: 20, solves: 10, failures: 5, abandonments: 5 }),
    strongType({ id: "b", kind: "behavioral", currentSharePct: 50, impressions: 20, solves: 10, failures: 5, abandonments: 5 }),
  ];
  var rBalanced = f.analyze({ types: types }, { now: NOW, risk_appetite: "balanced" });
  var rAggressive = f.analyze({ types: types }, { now: NOW, risk_appetite: "aggressive" });
  var p3Balanced = rBalanced.playbook.filter(function (p) { return p.priority === "P3"; });
  var p3Aggressive = rAggressive.playbook.filter(function (p) { return p.priority === "P3"; });
  assert.ok(p3Balanced.length >= 1);
  assert.strictEqual(p3Aggressive.length, 0);
});

test("cautious + P0 appends SOLICIT_SECURITY_REVIEW", function () {
  var f = mk();
  var types = [
    leakyText({ currentSharePct: 60, botPassRate: 0.6, a11yIncidents: 12 }),
    strongType({ currentSharePct: 40 }),
  ];
  var r = f.analyze({ types: types }, { now: NOW, risk_appetite: "cautious" });
  var codes = r.playbook.map(function (p) { return p.code; });
  assert.ok(codes.indexOf("SOLICIT_SECURITY_REVIEW") >= 0);
});

test("never mutates input", function () {
  var f = mk();
  var orig = [strongType({ currentSharePct: 50 }), leakyText({ currentSharePct: 50 })];
  var snapshot = JSON.stringify(orig);
  f.analyze({ types: orig }, { now: NOW });
  assert.strictEqual(JSON.stringify(orig), snapshot);
});

test("text renderer is non-empty and includes type ids", function () {
  var f = mk();
  var types = [strongType({ id: "alpha", currentSharePct: 60 }), strongType({ id: "beta", kind: "behavioral", currentSharePct: 40 })];
  var r = f.analyze({ types: types }, { now: NOW });
  var txt = f.formatText(r);
  assert.ok(txt.indexOf("alpha") >= 0);
  assert.ok(txt.indexOf("beta") >= 0);
});
