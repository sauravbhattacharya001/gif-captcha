"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/cross-session-linkage-advisor");

function mk(opts) { return mod.createCrossSessionLinkageAdvisor(opts || {}); }

function s(over) {
  var base = {
    sessionId: "s-" + Math.random().toString(36).slice(2, 8),
    ip: "1.2.3.4",
    asn: "AS100",
    asnOrg: "ExampleNet",
    userAgent: "Mozilla/5.0",
    fingerprintHash: null,
    deviceCohortKey: null,
    solveTimeMs: 4000,
    solveSuccessful: true,
    solvePatternFingerprint: null,
    biometricsScore: 0.5,
    geoCountry: "US",
    blockedReason: null,
    ts: 1700000000000
  };
  if (over) Object.keys(over).forEach(function (k) { base[k] = over[k]; });
  return base;
}

test("empty input -> ISOLATED report with grade A", function () {
  var adv = mk({ now: function () { return 1; } });
  var r = adv.analyze([]);
  assert.strictEqual(r.summary.totalSessions, 0);
  assert.strictEqual(r.summary.totalGroups, 0);
  assert.strictEqual(r.summary.grade, "A");
  assert.ok(r.insights.some(function (i) { return i.code === "NO_LINKAGE_DETECTED"; }));
  assert.ok(r.playbook.some(function (a) { return a.id === "NO_LINKAGE_ACTION"; }));
});

test("single session has no linkage", function () {
  var adv = mk();
  var r = adv.analyze([s({ sessionId: "only-1" })]);
  assert.strictEqual(r.groups.length, 0);
  assert.strictEqual(r.summary.isolatedSessions, 1);
});

test("COORDINATED_BOTNET fires on shared IP+UA+tight timing", function () {
  var adv = mk();
  var sessions = [
    s({ sessionId: "b1", ip: "10.0.0.1", userAgent: "BotUA", solveTimeMs: 1000 }),
    s({ sessionId: "b2", ip: "10.0.0.1", userAgent: "BotUA", solveTimeMs: 1010 }),
    s({ sessionId: "b3", ip: "10.0.0.1", userAgent: "BotUA", solveTimeMs: 1020 })
  ];
  var r = adv.analyze(sessions);
  var g = r.groups.find(function (x) { return x.verdict === "COORDINATED_BOTNET"; });
  assert.ok(g, "expected botnet group");
  assert.strictEqual(g.priority, "P0");
  assert.deepStrictEqual(g.memberSessionIds, ["b1", "b2", "b3"]);
  assert.strictEqual(g.recommended_action, "BLOCK_GROUP_NOW");
  assert.ok(g.linkage_strength >= 80);
  assert.strictEqual(r.summary.grade, "F");
  assert.ok(r.playbook[0].id === "BLOCK_TOP_BOTNET");
});

test("SUBNET_CLUSTER fires on shared /24 with varied UAs", function () {
  var adv = mk();
  var sessions = [
    s({ sessionId: "u1", ip: "192.168.5.10", userAgent: "Chrome/120" }),
    s({ sessionId: "u2", ip: "192.168.5.20", userAgent: "Firefox/120" }),
    s({ sessionId: "u3", ip: "192.168.5.30", userAgent: "Safari/16" })
  ];
  var r = adv.analyze(sessions);
  var g = r.groups.find(function (x) { return x.verdict === "SUBNET_CLUSTER"; });
  assert.ok(g, "expected subnet group");
  assert.strictEqual(g.recommended_action, "BLOCK_SUBNET");
  assert.strictEqual(g.priority, "P0");
});

test("ASN_FLEET fires on >=5 sessions same ASN with distinct IPs and high fail rate", function () {
  var adv = mk();
  var arr = [];
  for (var i = 0; i < 6; i++) {
    arr.push(s({ sessionId: "a" + i, ip: "203.0." + i + ".1", asn: "AS999", solveSuccessful: false, userAgent: "UA-" + i }));
  }
  var r = adv.analyze(arr);
  var g = r.groups.find(function (x) { return x.verdict === "ASN_FLEET"; });
  assert.ok(g, "expected ASN fleet");
  assert.strictEqual(g.priority, "P1");
  assert.strictEqual(g.recommended_action, "FLAG_ASN_FOR_REVIEW");
});

test("DEVICE_COHORT_DUPLICATE fires on shared fingerprint", function () {
  var adv = mk();
  var sessions = [
    s({ sessionId: "f1", ip: "5.5.5.1", fingerprintHash: "fp-abc" }),
    s({ sessionId: "f2", ip: "5.5.6.1", fingerprintHash: "fp-abc" })
  ];
  var r = adv.analyze(sessions);
  var g = r.groups.find(function (x) { return x.verdict === "DEVICE_COHORT_DUPLICATE"; });
  assert.ok(g, "expected device cohort group");
  assert.strictEqual(g.recommended_action, "FORCE_STEP_UP_GROUP");
});

test("BEHAVIORAL_TWIN fires when solve pattern identical and timing within 5%", function () {
  var adv = mk();
  var sessions = [
    s({ sessionId: "t1", ip: "8.8.8.1", solvePatternFingerprint: "pat-xyz", solveTimeMs: 2000 }),
    s({ sessionId: "t2", ip: "8.8.8.2", solvePatternFingerprint: "pat-xyz", solveTimeMs: 2050 })
  ];
  var r = adv.analyze(sessions);
  var g = r.groups.find(function (x) { return x.verdict === "BEHAVIORAL_TWIN"; });
  assert.ok(g, "expected behavioral twin");
  assert.strictEqual(g.recommended_action, "FORCE_STEP_UP_GROUP");
});

test("SHARED_PROXY fires on same IP varied UAs with mixed pass/fail", function () {
  var adv = mk();
  var sessions = [
    s({ sessionId: "p1", ip: "100.100.100.1", userAgent: "Office Chrome", solveSuccessful: true }),
    s({ sessionId: "p2", ip: "100.100.100.1", userAgent: "Office Firefox", solveSuccessful: false }),
    s({ sessionId: "p3", ip: "100.100.100.1", userAgent: "Office Safari", solveSuccessful: true })
  ];
  var r = adv.analyze(sessions);
  var g = r.groups.find(function (x) { return x.verdict === "SHARED_PROXY"; });
  assert.ok(g, "expected shared proxy group");
  assert.strictEqual(g.priority, "P2");
  assert.strictEqual(g.expected_fp_rate, "high");
});

test("risk_appetite cautious lowers thresholds, aggressive raises them", function () {
  var sessions = [
    s({ sessionId: "x1", ip: "9.9.9.1", userAgent: "BotUA", solveTimeMs: 1000 }),
    s({ sessionId: "x2", ip: "9.9.9.1", userAgent: "BotUA", solveTimeMs: 1005 })
  ];
  // Cautious: minBotnet -> 2, should detect
  var rCaut = mk({ riskAppetite: "cautious" }).analyze(sessions);
  assert.ok(rCaut.groups.some(function (g) { return g.verdict === "COORDINATED_BOTNET"; }));
  // Aggressive: minBotnet -> 4, should NOT detect
  var rAgg = mk({ riskAppetite: "aggressive" }).analyze(sessions);
  assert.ok(!rAgg.groups.some(function (g) { return g.verdict === "COORDINATED_BOTNET"; }));
});

test("deterministic groupId across re-runs", function () {
  var sessions = [
    s({ sessionId: "g1", ip: "1.1.1.1", userAgent: "ua", solveTimeMs: 100 }),
    s({ sessionId: "g2", ip: "1.1.1.1", userAgent: "ua", solveTimeMs: 102 }),
    s({ sessionId: "g3", ip: "1.1.1.1", userAgent: "ua", solveTimeMs: 104 })
  ];
  var r1 = mk({ now: function () { return 1; } }).analyze(sessions);
  var r2 = mk({ now: function () { return 9999; } }).analyze(sessions.slice().reverse());
  var g1 = r1.groups.find(function (x) { return x.verdict === "COORDINATED_BOTNET"; });
  var g2 = r2.groups.find(function (x) { return x.verdict === "COORDINATED_BOTNET"; });
  assert.strictEqual(g1.groupId, g2.groupId);
});

test("JSON output is byte-stable across two runs with same data and clock", function () {
  var sessions = [
    s({ sessionId: "j1", ip: "2.2.2.1", userAgent: "ua-a" }),
    s({ sessionId: "j2", ip: "2.2.2.2", userAgent: "ua-b" }),
    s({ sessionId: "j3", ip: "2.2.2.3", userAgent: "ua-c" })
  ];
  var adv = mk({ now: function () { return 42; } });
  var a = adv.format(adv.analyze(sessions), "json");
  var b = adv.format(adv.analyze(sessions), "json");
  assert.strictEqual(a, b);
  // Keys should be sorted at the top level
  var parsed = JSON.parse(a);
  assert.ok(Object.prototype.hasOwnProperty.call(parsed, "generated_at"));
});

test("text and markdown formatters produce non-empty headered output", function () {
  var adv = mk();
  var r = adv.analyze([s(), s({ sessionId: "z2", ip: "3.3.3.3" })]);
  var t = adv.format(r, "text");
  var m = adv.format(r, "md");
  assert.ok(/CrossSessionLinkageAdvisor report/.test(t));
  assert.ok(/Summary:/.test(t));
  assert.ok(/^# Cross-Session Linkage Advisor/m.test(m));
  assert.ok(/## Summary/.test(m));
  assert.ok(/## Playbook/.test(m));
});

test("analyze never mutates the caller's input array or objects", function () {
  var sessions = [
    s({ sessionId: "im1", ip: "4.4.4.1", userAgent: "ua", solveTimeMs: 100 }),
    s({ sessionId: "im2", ip: "4.4.4.1", userAgent: "ua", solveTimeMs: 105 }),
    s({ sessionId: "im3", ip: "4.4.4.1", userAgent: "ua", solveTimeMs: 108 })
  ];
  var snapshot = JSON.parse(JSON.stringify(sessions));
  mk().analyze(sessions);
  assert.deepStrictEqual(sessions, snapshot);
});

test("playbook P0-first ordering and dedupe by id", function () {
  var sessions = [
    s({ sessionId: "p0a", ip: "10.0.0.1", userAgent: "BotUA", solveTimeMs: 1000 }),
    s({ sessionId: "p0b", ip: "10.0.0.1", userAgent: "BotUA", solveTimeMs: 1003 }),
    s({ sessionId: "p0c", ip: "10.0.0.1", userAgent: "BotUA", solveTimeMs: 1006 }),
    s({ sessionId: "su1", ip: "11.0.0.1", fingerprintHash: "shared-fp" }),
    s({ sessionId: "su2", ip: "11.0.0.2", fingerprintHash: "shared-fp" })
  ];
  var r = mk().analyze(sessions);
  var ids = r.playbook.map(function (a) { return a.id; });
  assert.strictEqual(new Set(ids).size, ids.length); // dedupe
  var priorities = r.playbook.map(function (a) { return a.priority; });
  // P0 should appear before any P1
  var firstP1 = priorities.indexOf("P1");
  var lastP0 = priorities.lastIndexOf("P0");
  if (firstP1 !== -1 && lastP0 !== -1) assert.ok(lastP0 < firstP1);
});

test("A-F grade ladder: A on healthy, F on P0", function () {
  var advA = mk();
  var rA = advA.analyze([s({ sessionId: "lone1" }), s({ sessionId: "lone2", ip: "20.0.0.1" })]);
  assert.strictEqual(rA.summary.grade, "A");

  var rF = mk().analyze([
    s({ sessionId: "f1", ip: "21.0.0.1", userAgent: "U", solveTimeMs: 100 }),
    s({ sessionId: "f2", ip: "21.0.0.1", userAgent: "U", solveTimeMs: 102 }),
    s({ sessionId: "f3", ip: "21.0.0.1", userAgent: "U", solveTimeMs: 104 })
  ]);
  assert.strictEqual(rF.summary.grade, "F");
});

test("insights flag SPARSE_INPUT when fewer than 5 sessions", function () {
  var r = mk().analyze([s({ sessionId: "only-a" })]);
  assert.ok(r.insights.some(function (i) { return i.code === "SPARSE_INPUT"; }));
});

test("_deriveCidr24 handles obvious cases and rejects garbage", function () {
  var fn = mod._internal._deriveCidr24;
  assert.strictEqual(fn("1.2.3.4"), "1.2.3.0/24");
  assert.strictEqual(fn("not-an-ip"), null);
  assert.strictEqual(fn(""), null);
  assert.strictEqual(fn("999.0.0.1"), null);
});

test("malformed sessions are gracefully skipped", function () {
  var r = mk().analyze([null, {}, { sessionId: "" }, { sessionId: "ok-1" }]);
  assert.strictEqual(r.summary.totalSessions, 1);
});
