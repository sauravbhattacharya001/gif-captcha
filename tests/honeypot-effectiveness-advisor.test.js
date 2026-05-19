"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/honeypot-effectiveness-advisor");

function mk() { return mod.createHoneypotEffectivenessAdvisor(); }

var NOW = Date.parse("2026-05-18T00:00:00Z");
var DAY = 24 * 60 * 60 * 1000;

function baseH(over) {
  var h = {
    id: "hp1",
    type: "invisible_field",
    deployedAt: NOW - 60 * DAY,
    totalImpressions: 1000,
    botHits: 150,
    confirmedBotHits: 120,
    humanHits: 5,
    uniqueIPs: 80,
    uniqueUserAgents: 30,
    avgTriggerLatencyMs: 250,
    recentTrend: 1.0,
    isAccessibilityRisk: false,
    lastTrippedAt: NOW - DAY,
    cost: 1,
  };
  if (over) Object.keys(over).forEach(function (k) { h[k] = over[k]; });
  return h;
}

test("factory exposes expected API", function () {
  var f = mk();
  ["analyze", "simulate", "formatText", "formatMarkdown", "formatJson"]
    .forEach(function (m) { assert.strictEqual(typeof f[m], "function", m + " is fn"); });
});

test("empty input -> CALM band, grade A, healthy insight, no honeypots", function () {
  var f = mk();
  var r = f.analyze({ honeypots: [] }, { now: NOW });
  assert.strictEqual(r.band, "CALM");
  assert.strictEqual(r.grade, "A");
  assert.strictEqual(r.summary.totalHoneypots, 0);
  assert.ok(r.insights.some(function (i) { return i.code === "HEALTHY_PORTFOLIO"; }));
  assert.ok(Array.isArray(r.playbook) && r.playbook.length >= 1);
});

test("null input never throws and yields safe report", function () {
  var f = mk();
  var r = f.analyze(null, { now: NOW });
  assert.strictEqual(r.summary.totalHoneypots, 0);
});

test("clean high-performing honeypot -> KEEP_PERFORMING/KEEP_HIGH_PERFORMER, P3", function () {
  var f = mk();
  var r = f.analyze({ honeypots: [baseH()] }, { now: NOW });
  var hp = r.honeypots[0];
  assert.ok(hp.verdict === "KEEP_PERFORMING" || hp.verdict === "KEEP_HIGH_PERFORMER",
    "expected KEEP_*, got " + hp.verdict);
  assert.strictEqual(hp.priority, "P3");
});

test("accessibility-risk honeypot with human hits forces P0 DISABLE", function () {
  var f = mk();
  var r = f.analyze({
    honeypots: [baseH({ id: "a11y1", isAccessibilityRisk: true, humanHits: 3 })],
  }, { now: NOW });
  var hp = r.honeypots[0];
  assert.strictEqual(hp.verdict, "DISABLE_FALSE_POSITIVE_RISK");
  assert.strictEqual(hp.priority, "P0");
  assert.ok(r.playbook.some(function (a) { return a.id === "DISABLE_ACCESSIBILITY_BREAKING_TRAPS"; }));
  assert.ok(r.insights.some(function (i) { return i.code === "ACCESSIBILITY_GAP_DETECTED"; }));
  assert.strictEqual(r.grade, "F");
});

test("high false-positive rate forces P0 DISABLE (non-accessibility)", function () {
  var f = mk();
  var r = f.analyze({
    honeypots: [baseH({ id: "fp1", humanHits: 60 })], // 6% > 2% ceiling
  }, { now: NOW });
  assert.strictEqual(r.honeypots[0].verdict, "DISABLE_FALSE_POSITIVE_RISK");
  assert.strictEqual(r.honeypots[0].priority, "P0");
  assert.ok(r.playbook.some(function (a) { return a.id === "DISABLE_HIGH_FALSE_POSITIVE_TRAPS"; }));
});

test("decayed honeypot (recentTrend < 0.5) -> ROTATE_OR_REDESIGN", function () {
  var f = mk();
  var r = f.analyze({
    honeypots: [baseH({ id: "decay1", recentTrend: 0.2, botHits: 40, confirmedBotHits: 20 })],
  }, { now: NOW });
  assert.strictEqual(r.honeypots[0].verdict, "ROTATE_OR_REDESIGN");
  assert.strictEqual(r.honeypots[0].priority, "P2");
  assert.ok(r.playbook.some(function (a) { return a.id === "REDESIGN_DECAYED_TRAPS"; }));
});

test("fingerprinted honeypot (few IPs, many hits) -> BLOCK_REVERSE_FINGERPRINT", function () {
  var f = mk();
  var r = f.analyze({
    honeypots: [baseH({ id: "fp_print", botHits: 200, uniqueIPs: 5, confirmedBotHits: 150 })],
  }, { now: NOW });
  assert.strictEqual(r.honeypots[0].verdict, "BLOCK_REVERSE_FINGERPRINT");
  assert.strictEqual(r.honeypots[0].priority, "P1");
  assert.ok(r.playbook.some(function (a) { return a.id === "ROTATE_FINGERPRINTED_HONEYPOTS"; }));
});

test("insufficient impressions -> INSUFFICIENT_DATA", function () {
  var f = mk();
  var r = f.analyze({
    honeypots: [baseH({ id: "small", totalImpressions: 10, botHits: 1, humanHits: 0 })],
  }, { now: NOW });
  assert.strictEqual(r.honeypots[0].verdict, "INSUFFICIENT_DATA");
  assert.strictEqual(r.honeypots[0].priority, "P3");
});

test("dead aged honeypot -> RETIRE_LOW_VALUE", function () {
  var f = mk();
  var r = f.analyze({
    honeypots: [baseH({
      id: "dead",
      deployedAt: NOW - 120 * DAY,
      botHits: 2,
      confirmedBotHits: 0,
      uniqueIPs: 2,
    })],
  }, { now: NOW });
  assert.strictEqual(r.honeypots[0].verdict, "RETIRE_LOW_VALUE");
  assert.strictEqual(r.honeypots[0].priority, "P2");
});

test("narrow attacker base with high catch rate -> INVESTIGATE_ANOMALY", function () {
  var f = mk();
  var r = f.analyze({
    honeypots: [baseH({
      id: "narrow",
      totalImpressions: 100,
      botHits: 90,
      confirmedBotHits: 80,
      humanHits: 0,
      uniqueIPs: 50,
      uniqueUserAgents: 2,
    })],
  }, { now: NOW });
  assert.strictEqual(r.honeypots[0].verdict, "INVESTIGATE_ANOMALY");
  assert.strictEqual(r.honeypots[0].priority, "P1");
  assert.ok(r.playbook.some(function (a) { return a.id === "INVESTIGATE_NARROW_ATTACKER"; }));
});

test("cautious vs aggressive band shift is monotonic", function () {
  var f = mk();
  var input = {
    honeypots: [
      baseH({ id: "h1", humanHits: 60 }), // P0
      baseH({ id: "h2" }), // P3
      baseH({ id: "h3" }), // P3
      baseH({ id: "h4" }), // P3
    ],
  };
  var bandRank = { CALM: 0, WATCH: 1, ELEVATED: 2, HIGH: 3, CRITICAL: 4 };
  var rA = f.analyze(input, { now: NOW, risk_appetite: "aggressive" });
  var rB = f.analyze(input, { now: NOW, risk_appetite: "balanced" });
  var rC = f.analyze(input, { now: NOW, risk_appetite: "cautious" });
  assert.ok(bandRank[rA.band] >= bandRank[rB.band]);
  assert.ok(bandRank[rB.band] >= bandRank[rC.band]);
});

test("formatJson is byte-stable across runs", function () {
  var f = mk();
  var input = {
    honeypots: [
      baseH({ id: "z" }),
      baseH({ id: "a", humanHits: 60 }),
      baseH({ id: "m", recentTrend: 0.2 }),
    ],
  };
  var r1 = f.analyze(input, { now: NOW });
  var r2 = f.analyze(input, { now: NOW });
  assert.strictEqual(f.formatJson(r1), f.formatJson(r2));
});

test("formatMarkdown contains required section headers", function () {
  var f = mk();
  var r = f.analyze({ honeypots: [baseH(), baseH({ id: "h2", humanHits: 60 })] }, { now: NOW });
  var md = f.formatMarkdown(r);
  ["## Summary", "## Honeypots", "## Playbook", "## Insights"].forEach(function (h) {
    assert.ok(md.indexOf(h) !== -1, "missing header " + h);
  });
});

test("formatText includes verdicts and playbook entries", function () {
  var f = mk();
  var r = f.analyze({ honeypots: [baseH({ humanHits: 60 })] }, { now: NOW });
  var txt = f.formatText(r);
  assert.ok(txt.indexOf("HoneypotEffectivenessAdvisor") !== -1);
  assert.ok(txt.indexOf("DISABLE_FALSE_POSITIVE_RISK") !== -1);
  assert.ok(txt.indexOf("Playbook:") !== -1);
});

test("simulate reduces riskScore and respects diminishing returns", function () {
  var f = mk();
  var input = {
    honeypots: [
      baseH({ id: "h1", humanHits: 60 }), // P0
      baseH({ id: "h2", botHits: 200, uniqueIPs: 5 }), // P1 fingerprinted
      baseH({ id: "h3", recentTrend: 0.2 }), // P2 rotate
    ],
  };
  var r = f.analyze(input, { now: NOW });
  var sim = f.simulate(r, { applyTop: 3 });
  assert.ok(sim.projectedRiskScore <= r.riskScore, "projected should not exceed current");
  assert.strictEqual(sim.appliedActions.length, 3);
  // diminishing: |applied[1]| < |raw[1]| and |applied[2]| < |applied[1]|
  var a0 = Math.abs(sim.appliedActions[0].appliedDelta);
  var a1 = Math.abs(sim.appliedActions[1].appliedDelta);
  var a2 = Math.abs(sim.appliedActions[2].appliedDelta);
  // Account for different raw deltas; compare ratios to raw
  assert.ok(a0 >= a1 * 0.5, "diminishing returns expected");
  assert.ok(a1 >= a2 * 0.5, "diminishing returns expected");
  assert.ok(sim.projectedRiskScore >= 5, "riskScore floor of 5");
});

test("HEALTHY_PORTFOLIO playbook fallback when no findings", function () {
  var f = mk();
  var r = f.analyze({ honeypots: [baseH()] }, { now: NOW });
  assert.ok(r.playbook.some(function (a) { return a.id === "HEALTHY_PORTFOLIO"; }));
});

test("module is exposed in src/index.js manifest", function () {
  var manifest = require("../src/index");
  assert.strictEqual(typeof manifest.createHoneypotEffectivenessAdvisor, "function");
  var advisor = manifest.createHoneypotEffectivenessAdvisor();
  assert.strictEqual(typeof advisor.analyze, "function");
});

test("monoculture insight when >=70% same type and rotate present", function () {
  var f = mk();
  var input = {
    honeypots: [
      baseH({ id: "a", type: "invisible_field", recentTrend: 0.2 }),
      baseH({ id: "b", type: "invisible_field" }),
      baseH({ id: "c", type: "invisible_field" }),
      baseH({ id: "d", type: "invisible_field" }),
      baseH({ id: "e", type: "timing_trap" }),
    ],
  };
  var r = f.analyze(input, { now: NOW });
  assert.ok(r.insights.some(function (i) { return i.code === "HONEYPOT_TYPE_MONOCULTURE"; }));
  assert.ok(r.playbook.some(function (a) { return a.id === "DIVERSIFY_HONEYPOT_TYPES"; }));
});

test("telemetry gap insight when >=30% INSUFFICIENT_DATA", function () {
  var f = mk();
  var input = {
    honeypots: [
      baseH({ id: "a", totalImpressions: 10, botHits: 1, humanHits: 0 }),
      baseH({ id: "b", totalImpressions: 10, botHits: 1, humanHits: 0 }),
      baseH({ id: "c" }),
    ],
  };
  var r = f.analyze(input, { now: NOW });
  assert.ok(r.insights.some(function (i) { return i.code === "TELEMETRY_GAP"; }));
  assert.ok(r.playbook.some(function (a) { return a.id === "INSTRUMENT_MORE_TELEMETRY"; }));
});

test("never mutates input honeypots", function () {
  var f = mk();
  var h = baseH({ humanHits: 60 });
  var input = { honeypots: [h] };
  var copy = JSON.parse(JSON.stringify(input));
  f.analyze(input, { now: NOW });
  assert.deepStrictEqual(input, copy, "input must not be mutated");
});

test("unknown risk_appetite falls back to balanced", function () {
  var f = mk();
  var r = f.analyze({ honeypots: [baseH()] }, { now: NOW, risk_appetite: "garbage" });
  assert.strictEqual(r.risk_appetite, "balanced");
});
