"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/captcha-roi-advisor.js");

function mk() { return mod.createCaptchaROIAdvisor(); }

test("returns factory with expected API", function () {
  var advisor = mk();
  assert.strictEqual(typeof advisor.analyze, "function");
  assert.strictEqual(typeof advisor.simulate, "function");
  assert.strictEqual(typeof advisor.formatText, "function");
  assert.strictEqual(typeof advisor.formatMarkdown, "function");
  assert.strictEqual(typeof advisor.formatJson, "function");
});

test("handles empty input gracefully", function () {
  var r = mk().analyze({ challengeTypes: [] });
  assert.strictEqual(r.grade, "A");
  assert.strictEqual(r.findings.length, 0);
  assert.ok(r.insights.indexOf("NO_DATA_PROVIDED") >= 0);
});

test("classifies high-ROI challenge correctly", function () {
  var r = mk().analyze({ challengeTypes: [{
    id: "animated-gif", botBlockRate: 0.95, falsePositiveRate: 0.01,
    avgComputeMs: 50, avgBandwidthKb: 50, userDropoffRate: 0.01,
    supportTicketsPerK: 0.1, servedCount: 5000
  }]});
  assert.strictEqual(r.findings[0].verdict, "HIGH_ROI");
  assert.strictEqual(r.findings[0].priority, 3);
});

test("classifies cost-sink challenge correctly", function () {
  var r = mk().analyze({ challengeTypes: [{
    id: "heavy-3d", botBlockRate: 0.15, falsePositiveRate: 0.25,
    avgComputeMs: 2000, avgBandwidthKb: 3000, userDropoffRate: 0.40,
    supportTicketsPerK: 8, servedCount: 1000
  }]});
  assert.strictEqual(r.findings[0].verdict, "COST_SINK");
  assert.strictEqual(r.findings[0].priority, 0);
});

test("flags insufficient data for low-volume challenges", function () {
  var r = mk().analyze({ challengeTypes: [{
    id: "new-type", botBlockRate: 0.80, servedCount: 20
  }]});
  assert.strictEqual(r.findings[0].verdict, "INSUFFICIENT_DATA");
  assert.ok(r.findings[0].reasons.indexOf("MISSING_METRICS") >= 0);
});

test("generates P0 playbook for cost-sink cluster", function () {
  var r = mk().analyze({ challengeTypes: [
    { id: "a", botBlockRate: 0.10, falsePositiveRate: 0.30, avgComputeMs: 2000, avgBandwidthKb: 2000, userDropoffRate: 0.5, supportTicketsPerK: 10, servedCount: 500 },
    { id: "b", botBlockRate: 0.12, falsePositiveRate: 0.28, avgComputeMs: 1800, avgBandwidthKb: 2500, userDropoffRate: 0.45, supportTicketsPerK: 9, servedCount: 500 }
  ]});
  assert.ok(r.playbook.some(function (a) { return a.id === "RETIRE_COST_SINK_CHALLENGES" && a.priority === 0; }));
});

test("risk_appetite aggressive trims P3 when P0/P1 present", function () {
  var r = mk().analyze({ challengeTypes: [
    { id: "sink", botBlockRate: 0.10, falsePositiveRate: 0.30, avgComputeMs: 2000, avgBandwidthKb: 2000, userDropoffRate: 0.5, supportTicketsPerK: 10, servedCount: 500 },
    { id: "good", botBlockRate: 0.90, falsePositiveRate: 0.01, avgComputeMs: 100, avgBandwidthKb: 100, userDropoffRate: 0.02, supportTicketsPerK: 0.1, servedCount: 5000 }
  ]}, { risk_appetite: "aggressive" });
  assert.ok(!r.playbook.some(function (a) { return a.priority === 3; }));
});

test("simulate projects score lift", function () {
  var r = mk().analyze({ challengeTypes: [
    { id: "a", botBlockRate: 0.10, falsePositiveRate: 0.30, avgComputeMs: 2000, avgBandwidthKb: 2000, userDropoffRate: 0.5, supportTicketsPerK: 10, servedCount: 500 }
  ]});
  var sim = mk().simulate(r, { applyTop: 2 });
  assert.ok(sim.projectedScore >= sim.currentScore);
  assert.strictEqual(sim.actionsApplied, Math.min(2, r.playbook.length));
});

test("formatMarkdown contains all sections", function () {
  var r = mk().analyze({ challengeTypes: [
    { id: "x", botBlockRate: 0.70, falsePositiveRate: 0.05, avgComputeMs: 300, avgBandwidthKb: 400, userDropoffRate: 0.10, supportTicketsPerK: 1, servedCount: 2000 }
  ]});
  var md = mk().formatMarkdown(r);
  assert.ok(md.indexOf("## Summary") >= 0);
  assert.ok(md.indexOf("## Challenge Types") >= 0);
  assert.ok(md.indexOf("## Playbook") >= 0);
  assert.ok(md.indexOf("## Insights") >= 0);
});

test("formatJson is byte-stable across calls", function () {
  var ct = [{ id: "z", botBlockRate: 0.60, falsePositiveRate: 0.03, avgComputeMs: 200, avgBandwidthKb: 300, userDropoffRate: 0.08, supportTicketsPerK: 1, servedCount: 3000 }];
  var a = mk();
  var r1 = a.analyze({ challengeTypes: ct }, { now: function () { return 1000; } });
  var r2 = a.analyze({ challengeTypes: ct }, { now: function () { return 1000; } });
  assert.strictEqual(a.formatJson(r1), a.formatJson(r2));
});

test("never mutates input", function () {
  var input = { challengeTypes: [{ id: "orig", botBlockRate: 0.80, falsePositiveRate: 0.02, avgComputeMs: 100, avgBandwidthKb: 100, userDropoffRate: 0.03, supportTicketsPerK: 0.5, servedCount: 2000 }] };
  var snapshot = JSON.stringify(input);
  mk().analyze(input);
  assert.strictEqual(JSON.stringify(input), snapshot);
});

test("throws on invalid risk_appetite", function () {
  assert.throws(function () {
    mk().analyze({ challengeTypes: [] }, { risk_appetite: "yolo" });
  });
});

test("grade F on multiple cost sinks", function () {
  var r = mk().analyze({ challengeTypes: [
    { id: "a", botBlockRate: 0.05, falsePositiveRate: 0.40, avgComputeMs: 3000, avgBandwidthKb: 4000, userDropoffRate: 0.6, supportTicketsPerK: 12, servedCount: 500 },
    { id: "b", botBlockRate: 0.08, falsePositiveRate: 0.35, avgComputeMs: 2500, avgBandwidthKb: 3500, userDropoffRate: 0.55, supportTicketsPerK: 11, servedCount: 500 }
  ]});
  assert.strictEqual(r.grade, "F");
});

test("grade A on all high-ROI challenges", function () {
  var r = mk().analyze({ challengeTypes: [
    { id: "a", botBlockRate: 0.95, falsePositiveRate: 0.01, avgComputeMs: 80, avgBandwidthKb: 50, userDropoffRate: 0.02, supportTicketsPerK: 0.1, servedCount: 10000 },
    { id: "b", botBlockRate: 0.90, falsePositiveRate: 0.02, avgComputeMs: 120, avgBandwidthKb: 80, userDropoffRate: 0.03, supportTicketsPerK: 0.2, servedCount: 8000 }
  ]});
  assert.strictEqual(r.grade, "A");
});

test("formatText includes headline", function () {
  var r = mk().analyze({ challengeTypes: [
    { id: "x", botBlockRate: 0.70, falsePositiveRate: 0.05, avgComputeMs: 300, avgBandwidthKb: 400, userDropoffRate: 0.10, supportTicketsPerK: 1, servedCount: 2000 }
  ]});
  var txt = mk().formatText(r);
  assert.ok(txt.indexOf("CAPTCHA ROI ADVISOR") >= 0);
  assert.ok(txt.indexOf("grade=") >= 0);
});
