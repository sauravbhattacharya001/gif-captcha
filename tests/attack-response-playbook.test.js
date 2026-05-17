/**
 * Tests for AttackResponsePlaybookGenerator
 */

"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/attack-response-playbook");

function _make(opts) {
  return mod.createAttackResponsePlaybook(opts || {});
}

test("factory returns expected API surface", function () {
  var p = _make();
  ["generate", "simulate", "explain", "formatAs", "listProfiles", "listActions"]
    .forEach(function (k) { assert.strictEqual(typeof p[k], "function", k); });
});

test("factory rejects unknown riskAppetite", function () {
  assert.throws(function () { _make({ riskAppetite: "yolo" }); }, /riskAppetite/);
});

test("generate() throws on bad input", function () {
  var p = _make();
  assert.throws(function () { p.generate(null); }, TypeError);
  assert.throws(function () { p.generate({}); }, TypeError);
  assert.throws(function () { p.generate({ anomalies: [{ severity: "high" }] }); }, TypeError);
});

test("empty anomalies → generic profile with low severity", function () {
  var p = _make();
  var pb = p.generate({ anomalies: [] });
  assert.strictEqual(pb.profile.id, "generic_degradation");
  assert.strictEqual(pb.severity, 0);
  // generic profile + zero severity → no action should score > 0
  assert.strictEqual(pb.actions.length, 0);
});

test("credential-stuffing signals classify correctly", function () {
  var p = _make();
  var pb = p.generate({
    anomalies: [
      { type: "solve_rate_drop", severity: "high" },
      { type: "failure_burst", severity: "high" },
      { type: "ip_concentration", severity: "medium" },
    ],
  });
  assert.strictEqual(pb.profile.id, "credential_stuffing");
  assert.ok(pb.profile.confidence > 0.5);
  assert.ok(pb.actions.length > 0);
  // top action should be relevant to throttling/rotation
  var topIds = pb.actions.slice(0, 3).map(function (a) { return a.id; });
  assert.ok(
    topIds.some(function (id) {
      return ["enable_pow", "tighten_rate_limits", "rotate_challenge_pool"].indexOf(id) !== -1;
    }),
    "expected throttle/rotate action in top 3, got " + topIds.join(",")
  );
});

test("slow_burn_probe requires absence of traffic_spike", function () {
  var p = _make();
  var withSpike = p.generate({
    anomalies: [
      { type: "response_time_drift", severity: "medium" },
      { type: "solve_rate_drop", severity: "low" },
      { type: "traffic_spike", severity: "high" },
    ],
  });
  // traffic_spike present → should NOT classify as slow_burn_probe
  assert.notStrictEqual(withSpike.profile.id, "slow_burn_probe");

  var withoutSpike = p.generate({
    anomalies: [
      { type: "response_time_drift", severity: "medium" },
      { type: "solve_rate_drop", severity: "low" },
    ],
  });
  assert.strictEqual(withoutSpike.profile.id, "slow_burn_probe");
});

test("volumetric_ddos surfaces shed_load action", function () {
  var p = _make({ riskAppetite: "aggressive" });
  var pb = p.generate({
    anomalies: [
      { type: "traffic_spike", severity: "critical" },
      { type: "response_time_drift", severity: "high" },
    ],
  });
  assert.strictEqual(pb.profile.id, "volumetric_ddos");
  var ids = pb.actions.map(function (a) { return a.id; });
  assert.ok(ids.indexOf("shed_load") !== -1, "shed_load expected for volumetric_ddos");
});

test("aggressive risk appetite recommends more actions than cautious", function () {
  var input = {
    anomalies: [
      { type: "solve_rate_drop", severity: "high" },
      { type: "failure_burst", severity: "high" },
    ],
  };
  var cautious = _make({ riskAppetite: "cautious" }).generate(input);
  var aggressive = _make({ riskAppetite: "aggressive" }).generate(input);
  assert.ok(
    aggressive.actions.length >= cautious.actions.length,
    "aggressive (" + aggressive.actions.length +
      ") should be >= cautious (" + cautious.actions.length + ")"
  );
});

test("context.recentlyRotated demotes rotate_challenge_pool", function () {
  var input = {
    anomalies: [
      { type: "solve_rate_drop", severity: "high" },
      { type: "failure_burst", severity: "high" },
    ],
  };
  var p = _make();
  var fresh = p.generate(input);
  var stale = p.generate(Object.assign({}, input, { context: { recentlyRotated: true } }));
  var freshRotate = fresh.actions.find(function (a) { return a.id === "rotate_challenge_pool"; });
  var staleRotate = stale.actions.find(function (a) { return a.id === "rotate_challenge_pool"; });
  // Either stale should be lower-impact, or it should be dropped entirely.
  if (freshRotate && staleRotate) {
    assert.ok(staleRotate.predictedImpact < freshRotate.predictedImpact);
  } else {
    assert.ok(freshRotate, "rotate should appear when not recently rotated");
  }
});

test("actions are sorted by score desc, ETA asc tiebreak", function () {
  var p = _make();
  var pb = p.generate({
    anomalies: [
      { type: "traffic_spike", severity: "high" },
      { type: "fingerprint_collision", severity: "medium" },
      { type: "geo_shift", severity: "medium" },
    ],
  });
  for (var i = 1; i < pb.actions.length; i++) {
    var prev = pb.actions[i - 1];
    var curr = pb.actions[i];
    assert.ok(
      prev.score > curr.score ||
        (prev.score === curr.score && prev.etaMinutes <= curr.etaMinutes),
      "ordering broken at index " + i
    );
  }
});

test("priority buckets are valid", function () {
  var p = _make();
  var pb = p.generate({
    anomalies: [
      { type: "solve_rate_drop", severity: "critical" },
      { type: "failure_burst", severity: "critical" },
    ],
  });
  pb.actions.forEach(function (a) {
    assert.ok(["P0", "P1", "P2", "P3"].indexOf(a.priority) !== -1);
  });
});

test("simulate() applies diminishing returns", function () {
  var p = _make({ riskAppetite: "aggressive" });
  var pb = p.generate({
    anomalies: [
      { type: "traffic_spike", severity: "critical" },
      { type: "response_time_drift", severity: "high" },
    ],
  });
  var sim1 = p.simulate(pb, { applyTop: 1 });
  var sim3 = p.simulate(pb, { applyTop: 3 });
  assert.ok(sim3.projectedReduction >= sim1.projectedReduction);
  assert.ok(sim3.projectedReduction <= 1);
  assert.ok(sim3.totalEtaMinutes >= sim1.totalEtaMinutes);
});

test("simulate() handles empty action set safely", function () {
  var p = _make();
  var pb = p.generate({ anomalies: [] });
  var sim = p.simulate(pb);
  assert.strictEqual(sim.appliedActions, 0);
  assert.strictEqual(sim.projectedReduction, 0);
  assert.strictEqual(sim.projectedResidualRisk, 1);
});

test("simulate() rejects bad input", function () {
  var p = _make();
  assert.throws(function () { p.simulate(null); }, TypeError);
  assert.throws(function () { p.simulate({}); }, TypeError);
});

test("formatAs(md) includes profile + action table", function () {
  var p = _make();
  var pb = p.generate({
    anomalies: [
      { type: "solve_rate_drop", severity: "high" },
      { type: "failure_burst", severity: "high" },
    ],
  });
  var md = p.formatAs(pb, "md");
  assert.match(md, /# Attack Response Playbook/);
  assert.match(md, /Profile:/);
  assert.match(md, /## Recommended Actions/);
  assert.match(md, /\| Priority \|/);
});

test("formatAs(json) round-trips", function () {
  var p = _make();
  var pb = p.generate({ anomalies: [{ type: "traffic_spike", severity: "high" }] });
  var json = p.formatAs(pb, "json");
  var parsed = JSON.parse(json);
  assert.strictEqual(parsed.profile.id, pb.profile.id);
  assert.strictEqual(parsed.actions.length, pb.actions.length);
});

test("formatAs(csv) has header + one row per action", function () {
  var p = _make();
  var pb = p.generate({ anomalies: [{ type: "traffic_spike", severity: "high" }] });
  var csv = p.formatAs(pb, "csv");
  var lines = csv.split("\n");
  assert.strictEqual(lines.length, pb.actions.length + 1);
  assert.match(lines[0], /^rank,priority,id,label/);
});

test("formatAs(text) is plain", function () {
  var p = _make();
  var pb = p.generate({ anomalies: [{ type: "traffic_spike", severity: "high" }] });
  var txt = p.formatAs(pb, "text");
  assert.match(txt, /Attack Response Playbook/);
  assert.doesNotMatch(txt, /\|/);
});

test("formatAs rejects unknown format", function () {
  var p = _make();
  var pb = p.generate({ anomalies: [] });
  assert.throws(function () { p.formatAs(pb, "xml"); }, /Unknown format/);
});

test("explain() returns human-readable summary", function () {
  var p = _make();
  var pb = p.generate({
    anomalies: [
      { type: "traffic_spike", severity: "critical" },
      { type: "response_time_drift", severity: "high" },
    ],
  });
  var msg = p.explain(pb);
  assert.match(msg, /Profile:/);
  assert.match(msg, /Severity/);
  assert.match(msg, /confidence/);
});

test("listProfiles / listActions expose catalogue", function () {
  var p = _make();
  assert.ok(p.listProfiles().indexOf("credential_stuffing") !== -1);
  assert.ok(p.listActions().indexOf("enable_pow") !== -1);
});
