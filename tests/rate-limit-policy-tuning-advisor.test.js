"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/rate-limit-policy-tuning-advisor");

function mk() { return mod.createRateLimitPolicyTuningAdvisor(); }

var NOW = Date.parse("2026-05-23T15:00:00Z");

function basePolicy(over) {
  var p = {
    id: "p1",
    scope: "ip",
    algorithm: "sliding-window",
    windowMs: 60000,
    maxRequests: 10,
    capacity: 100,
    refillRate: 2,
    banThreshold: 3,
    banDurationMs: 300000,
    criticality: 3,
  };
  if (over) Object.keys(over).forEach(function (k) { p[k] = over[k]; });
  return p;
}

function decisions(n, opts) {
  opts = opts || {};
  var arr = [];
  for (var i = 0; i < n; i++) {
    arr.push({
      ts: NOW - (n - i) * 1000,
      policyId: opts.policyId || "p1",
      key: opts.key || ("k" + (i % (opts.distinctKeys || 1))),
      outcome: opts.outcome || "allowed",
      isBot: !!opts.isBot,
      isHuman: !!opts.isHuman,
    });
  }
  return arr;
}

test("factory exposes expected API", function () {
  var f = mk();
  ["analyze", "simulate", "formatText", "formatMarkdown", "formatJson"]
    .forEach(function (m) { assert.strictEqual(typeof f[m], "function", m + " is fn"); });
});

test("empty input -> grade A, EMPTY_INPUT insight", function () {
  var f = mk();
  var r = f.analyze({ policies: [], decisions: [], events: [] }, { now: NOW });
  assert.strictEqual(r.grade, "A");
  assert.strictEqual(r.summary.totalPolicies, 0);
  assert.ok(r.insights.some(function (i) { return i.code === "EMPTY_INPUT"; }));
  assert.ok(Array.isArray(r.playbook) && r.playbook.length >= 1);
});

test("null input never throws", function () {
  var f = mk();
  var r = f.analyze(null, { now: NOW });
  assert.strictEqual(r.summary.totalPolicies, 0);
});

test("POLICY_TOO_LAX detection (bot allow >= 25%)", function () {
  var f = mk();
  var decs = [];
  // 20 bot hits, 8 allowed (40%)
  for (var i = 0; i < 20; i++) {
    decs.push({ ts: NOW - i * 1000, policyId: "p1", key: "k" + i, outcome: i < 8 ? "allowed" : "rate_limited", isBot: true });
  }
  var r = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW });
  var pol = r.policies[0];
  assert.strictEqual(pol.verdict, "POLICY_TOO_LAX");
  assert.strictEqual(pol.priority, "P0");
  assert.ok(pol.suggestedChanges.some(function (c) { return c.field === "maxRequests" && c.suggested < c.current; }));
  assert.ok(r.playbook.some(function (a) { return a.id === "TIGHTEN_LAX_POLICIES"; }));
});

test("POLICY_TOO_STRICT detection (human throttle >= 15%)", function () {
  var f = mk();
  var decs = [];
  for (var i = 0; i < 30; i++) {
    decs.push({ ts: NOW - i * 1000, policyId: "p1", key: "k" + i, outcome: i < 8 ? "rate_limited" : "allowed", isHuman: true });
  }
  var r = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW });
  var pol = r.policies[0];
  assert.strictEqual(pol.verdict, "POLICY_TOO_STRICT");
  assert.ok(pol.suggestedChanges.some(function (c) { return c.field === "maxRequests" && c.suggested > c.current; }));
});

test("BAN_THRESHOLD_TOO_LOW (banned humans)", function () {
  var f = mk();
  var decs = [];
  // 10 banned events, 4 humans
  for (var i = 0; i < 10; i++) {
    decs.push({ ts: NOW - i * 1000, policyId: "p1", key: "k" + i, outcome: "banned", isHuman: i < 4 });
  }
  // pad with allowed to clear too-lax/strict guards
  for (var j = 0; j < 5; j++) decs.push({ ts: NOW - j * 100, policyId: "p1", key: "ok" + j, outcome: "allowed" });
  var r = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW });
  var pol = r.policies[0];
  assert.strictEqual(pol.verdict, "BAN_THRESHOLD_TOO_LOW");
  assert.strictEqual(pol.priority, "P1");
});

test("BAN_THRESHOLD_TOO_HIGH (repeat offenders)", function () {
  var f = mk();
  var decs = [];
  // 6 distinct keys, each rate_limited 3x then allowed
  for (var k = 0; k < 6; k++) {
    for (var j = 0; j < 3; j++) decs.push({ ts: NOW - (k * 10 + j) * 1000, policyId: "p1", key: "off" + k, outcome: "rate_limited" });
    decs.push({ ts: NOW - (k * 10 + 3) * 1000, policyId: "p1", key: "off" + k, outcome: "allowed" });
  }
  var r = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW });
  var pol = r.policies[0];
  assert.strictEqual(pol.verdict, "BAN_THRESHOLD_TOO_HIGH");
  assert.ok(pol.suggestedChanges.some(function (c) { return c.field === "banDurationMs"; }));
});

test("WINDOW_TOO_SHORT bursty pattern", function () {
  var f = mk();
  // 6 rate_limited events 100ms apart, windowMs=60000 so gap is way below window*0.2 (12000)
  var decs = [];
  for (var i = 0; i < 6; i++) {
    decs.push({ ts: NOW - (6 - i) * 100, policyId: "p1", key: "k" + i, outcome: "rate_limited" });
  }
  for (var j = 0; j < 5; j++) decs.push({ ts: NOW - j * 100, policyId: "p1", key: "h" + j, outcome: "allowed" });
  var r = f.analyze({ policies: [basePolicy({ maxRequests: 10 })], decisions: decs }, { now: NOW });
  var pol = r.policies[0];
  assert.strictEqual(pol.verdict, "WINDOW_TOO_SHORT");
  assert.strictEqual(pol.priority, "P2");
  assert.ok(pol.suggestedChanges.some(function (c) { return c.field === "windowMs" && c.suggested > c.current; }));
});

test("EVICTION_PRESSURE from events", function () {
  var f = mk();
  var decs = decisions(10, {});
  var events = [
    { ts: NOW, policyId: "p1", type: "eviction" },
    { ts: NOW, policyId: "p1", type: "eviction" },
    { ts: NOW, policyId: "p1", type: "memory_pressure" },
  ];
  var r = f.analyze({ policies: [basePolicy()], decisions: decs, events: events }, { now: NOW });
  var pol = r.policies[0];
  assert.strictEqual(pol.verdict, "EVICTION_PRESSURE");
  assert.ok(r.insights.some(function (i) { return i.code === "KEY_STORE_OVERFLOW"; }));
});

test("UNUSED_POLICY when no decisions", function () {
  var f = mk();
  var r = f.analyze({ policies: [basePolicy(), basePolicy({ id: "p2" })], decisions: [] }, { now: NOW });
  assert.strictEqual(r.policies[0].verdict, "UNUSED_POLICY");
  assert.strictEqual(r.policies[1].verdict, "UNUSED_POLICY");
  assert.ok(r.playbook.some(function (a) { return a.id === "RETIRE_UNUSED_POLICIES"; }));
  assert.ok(r.insights.some(function (i) { return i.code === "DEAD_POLICY_PORTFOLIO"; }));
});

test("INSUFFICIENT_DATA when <5 decisions", function () {
  var f = mk();
  var decs = decisions(3, {});
  var r = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW });
  assert.strictEqual(r.policies[0].verdict, "INSUFFICIENT_DATA");
  assert.ok(r.playbook.some(function (a) { return a.id === "COLLECT_MORE_DECISION_TELEMETRY"; }));
});

test("critical-asset P0 forces grade F", function () {
  var f = mk();
  var decs = [];
  for (var i = 0; i < 20; i++) {
    decs.push({ ts: NOW - i * 1000, policyId: "p1", key: "k" + i, outcome: i < 10 ? "allowed" : "rate_limited", isBot: true });
  }
  var r = f.analyze({ policies: [basePolicy({ criticality: 5 })], decisions: decs }, { now: NOW });
  assert.strictEqual(r.grade, "F");
});

test("cautious vs aggressive scaling differs", function () {
  var f = mk();
  var decs = [];
  for (var i = 0; i < 20; i++) {
    decs.push({ ts: NOW - i * 1000, policyId: "p1", key: "k" + i, outcome: i < 8 ? "allowed" : "rate_limited", isBot: true });
  }
  var cautious = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW, risk_appetite: "cautious" });
  var aggressive = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW, risk_appetite: "aggressive" });
  assert.ok(cautious.policies[0].risk_score >= aggressive.policies[0].risk_score);
});

test("aggressive trims P3 when P0/P1 present", function () {
  var f = mk();
  var decs = [];
  for (var i = 0; i < 20; i++) {
    decs.push({ ts: NOW - i * 1000, policyId: "p1", key: "k" + i, outcome: i < 8 ? "allowed" : "rate_limited", isBot: true });
  }
  var r = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW, risk_appetite: "aggressive" });
  assert.ok(!r.playbook.some(function (a) { return a.priority === "P3"; }));
});

test("playbook is P0-first ordered", function () {
  var f = mk();
  var decs = [];
  for (var i = 0; i < 20; i++) {
    decs.push({ ts: NOW - i * 1000, policyId: "p1", key: "k" + i, outcome: i < 8 ? "allowed" : "rate_limited", isBot: true });
  }
  // Add second policy with eviction pressure (P2)
  var r = f.analyze({
    policies: [basePolicy(), basePolicy({ id: "p2" })],
    decisions: decs.concat(decisions(10, { policyId: "p2" })),
    events: [{ ts: NOW, policyId: "p2", type: "eviction" }, { ts: NOW, policyId: "p2", type: "eviction" }],
  }, { now: NOW });
  var order = { P0: 0, P1: 1, P2: 2, P3: 3 };
  for (var k = 1; k < r.playbook.length; k++) {
    assert.ok(order[r.playbook[k - 1].priority] <= order[r.playbook[k].priority]);
  }
});

test("simulate reduces portfolio_risk_score", function () {
  var f = mk();
  var decs = [];
  for (var i = 0; i < 20; i++) {
    decs.push({ ts: NOW - i * 1000, policyId: "p1", key: "k" + i, outcome: i < 8 ? "allowed" : "rate_limited", isBot: true });
  }
  var r = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW });
  var sim = f.simulate(r, { applyTopN: 3 });
  assert.ok(sim.projectedPortfolioRisk < r.portfolio_risk_score);
  assert.ok(sim.appliedActions.length > 0);
});

test("simulate never mutates report", function () {
  var f = mk();
  var decs = decisions(10, {});
  var r = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW });
  var snap = JSON.stringify(r);
  f.simulate(r, { applyTopN: 5 });
  assert.strictEqual(JSON.stringify(r), snap);
});

test("formatJson is byte-stable across two calls", function () {
  var f = mk();
  var decs = decisions(20, {});
  var r = f.analyze({ policies: [basePolicy(), basePolicy({ id: "p2" })], decisions: decs }, { now: NOW });
  var a = f.formatJson(r);
  var b = f.formatJson(r);
  assert.strictEqual(a, b);
});

test("formatMarkdown contains all four sections", function () {
  var f = mk();
  var r = f.analyze({ policies: [basePolicy()], decisions: decisions(10, {}) }, { now: NOW });
  var md = f.formatMarkdown(r);
  assert.ok(md.indexOf("## Summary") !== -1);
  assert.ok(md.indexOf("## Policies") !== -1);
  assert.ok(md.indexOf("## Playbook") !== -1);
  assert.ok(md.indexOf("## Insights") !== -1);
});

test("input immutability snapshot", function () {
  var f = mk();
  var input = {
    policies: [basePolicy()],
    decisions: decisions(20, {}),
    events: [{ ts: NOW, policyId: "p1", type: "eviction" }],
  };
  var before = JSON.stringify(input);
  f.analyze(input, { now: NOW });
  assert.strictEqual(JSON.stringify(input), before);
});

test("suggested values present on findings with current+suggested+field", function () {
  var f = mk();
  var decs = [];
  for (var i = 0; i < 20; i++) {
    decs.push({ ts: NOW - i * 1000, policyId: "p1", key: "k" + i, outcome: i < 8 ? "allowed" : "rate_limited", isBot: true });
  }
  var r = f.analyze({ policies: [basePolicy()], decisions: decs }, { now: NOW });
  var changes = r.policies[0].suggestedChanges;
  assert.ok(changes.length > 0);
  changes.forEach(function (c) {
    assert.ok(c.field && typeof c.current !== "undefined" && typeof c.suggested !== "undefined");
  });
});

test("headline format includes grade and portfolio_risk", function () {
  var f = mk();
  var r = f.analyze({ policies: [basePolicy()], decisions: decisions(10, {}) }, { now: NOW });
  assert.ok(/VERDICT: grade=. policies=\d+ P0=\d+ P1=\d+ portfolio_risk=/.test(r.summary.headline));
});
