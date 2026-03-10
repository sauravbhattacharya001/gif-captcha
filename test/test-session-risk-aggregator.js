/**
 * Tests for SessionRiskAggregator
 */

"use strict";

var assert = require("assert");
var createSessionRiskAggregator =
  require("../src/session-risk-aggregator").createSessionRiskAggregator;

var passed = 0;
var failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failed++;
    console.error("FAIL: " + name);
    console.error("  " + e.message);
  }
}

var NOW = 1700000000000;

// ── Construction ────────────────────────────────────────────────────

test("creates with defaults", function () {
  var agg = createSessionRiskAggregator();
  assert.ok(agg);
  assert.deepStrictEqual(agg.getStats().totalSignals, 0);
});

test("creates with custom weights", function () {
  var agg = createSessionRiskAggregator({ weights: { geo: 0.5 } });
  assert.strictEqual(agg.getWeights().geo, 0.5);
  assert.strictEqual(agg.getWeights().biometrics, 0.20);
});

// ── addSignal ───────────────────────────────────────────────────────

test("addSignal requires sessionId and module", function () {
  var agg = createSessionRiskAggregator();
  assert.strictEqual(agg.addSignal(null, { module: "geo" }).ok, false);
  assert.strictEqual(agg.addSignal("s1", {}).ok, false);
  assert.strictEqual(agg.addSignal("s1", null).ok, false);
});

test("addSignal accepts valid signal", function () {
  var agg = createSessionRiskAggregator();
  var r = agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.module, "geo");
  assert.strictEqual(r.signalCount, 1);
});

test("addSignal normalizes module aliases", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "behavioral-biometrics", score: 0.3, timestamp: NOW });
  agg.addSignal("s1", { module: "geo-risk", score: 0.4, timestamp: NOW });
  agg.addSignal("s1", { module: "solve-pattern", score: 0.2, timestamp: NOW });
  agg.addSignal("s1", { module: "device-cohort", score: 0.1, timestamp: NOW });
  var sess = agg.getSession("s1");
  assert.ok(sess.modules.biometrics);
  assert.ok(sess.modules.geo);
  assert.ok(sess.modules.fingerprint);
  assert.ok(sess.modules.cohort);
});

test("addSignal clamps score to 0-1", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 2.5, timestamp: NOW });
  agg.addSignal("s1", { module: "geo", score: -1, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.ok(v.moduleScores.geo >= 0 && v.moduleScores.geo <= 1);
});

test("addSignal trims old signals beyond max", function () {
  var agg = createSessionRiskAggregator({ maxSignalsPerModule: 3 });
  for (var i = 0; i < 5; i++) {
    agg.addSignal("s1", { module: "geo", score: 0.1 * i, timestamp: NOW + i * 1000 });
  }
  var sess = agg.getSession("s1");
  assert.strictEqual(sess.modules.geo.signalCount, 3);
});

test("addSignal rejects on locked session", function () {
  var agg = createSessionRiskAggregator({ thresholds: { critical: 0.3, high: 0.2, medium: 0.1, low: 0 } });
  agg.addSignal("s1", { module: "honeypot", score: 0.95, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.strictEqual(v.action, "block");
  var r = agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
  assert.strictEqual(r.ok, false);
  assert.ok(r.error.indexOf("locked") >= 0);
});

// ── evaluate ────────────────────────────────────────────────────────

test("evaluate returns low for empty session", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0 });
  // unknown session
  var v = agg.evaluate("unknown");
  assert.strictEqual(v.level, "low");
  assert.strictEqual(v.score, 0);
});

test("evaluate computes weighted average", function () {
  var agg = createSessionRiskAggregator({
    weights: { geo: 1.0, biometrics: 1.0 }
  });
  agg.addSignal("s1", { module: "geo", score: 0.8, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.2, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  // Should be close to 0.5 (average of 0.8 and 0.2)
  assert.ok(Math.abs(v.score - 0.5) < 0.15);
});

test("evaluate single module", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.6, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.ok(v.score > 0);
  assert.strictEqual(v.modulesReporting, 1);
});

test("evaluate applies decay to older signals", function () {
  var agg = createSessionRiskAggregator({ decayHalfLifeMs: 60000 }); // 1 min half-life
  agg.addSignal("s1", { module: "geo", score: 1.0, timestamp: NOW - 120000 }); // 2 min old
  agg.addSignal("s1", { module: "geo", score: 0.0, timestamp: NOW }); // current
  var v = agg.evaluate("s1", { now: NOW });
  // Old signal should be heavily decayed, score should be close to 0
  assert.ok(v.score < 0.3);
});

test("evaluate classifies levels correctly", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
  assert.strictEqual(agg.evaluate("s1", { now: NOW }).level, "low");

  var agg2 = createSessionRiskAggregator();
  agg2.addSignal("s2", { module: "geo", score: 0.95, timestamp: NOW });
  // With only geo (weight 0.2), score ~0.19 → low
  // Use higher weight
  var agg3 = createSessionRiskAggregator({ weights: { geo: 10 } });
  agg3.addSignal("s3", { module: "geo", score: 0.95, timestamp: NOW });
  var v3 = agg3.evaluate("s3", { now: NOW });
  assert.strictEqual(v3.level, "critical");
});

test("evaluate maps actions to levels", function () {
  var agg = createSessionRiskAggregator({
    weights: { geo: 10 },
    actions: { low: "pass", medium: "warn", high: "flag", critical: "deny" }
  });
  agg.addSignal("s1", { module: "geo", score: 0.95, timestamp: NOW });
  assert.strictEqual(agg.evaluate("s1", { now: NOW }).action, "deny");
});

test("evaluate includes timeline when requested", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.5, timestamp: NOW + 1000 });
  var v = agg.evaluate("s1", { now: NOW + 2000, includeTimeline: true });
  assert.ok(v.timeline);
  assert.strictEqual(v.timeline.length, 2);
  assert.ok(v.timeline[0].timestamp <= v.timeline[1].timestamp);
});

test("evaluate collects unique factors", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.5, factors: ["vpn", "high_risk_country"], timestamp: NOW });
  agg.addSignal("s1", { module: "geo", score: 0.6, factors: ["vpn", "impossible_travel"], timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.ok(v.factors.indexOf("vpn") >= 0);
  assert.ok(v.factors.indexOf("impossible_travel") >= 0);
  assert.ok(v.factors.indexOf("high_risk_country") >= 0);
  // vpn should appear only once
  var vpnCount = v.factors.filter(function (f) { return f === "vpn"; }).length;
  assert.strictEqual(vpnCount, 1);
});

// ── Correlation rules ───────────────────────────────────────────────

test("correlation: geo + biometrics bot boost", function () {
  var agg = createSessionRiskAggregator({ weights: { geo: 1, biometrics: 1 } });
  agg.addSignal("s1", { module: "geo", score: 0.7, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.7, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.ok(v.correlations.some(function (c) { return c.rule === "geo_plus_biometrics_bot"; }));
  assert.ok(v.score > 0.7); // boosted
});

test("correlation: honeypot triggered boost", function () {
  var agg = createSessionRiskAggregator({ weights: { honeypot: 1 } });
  agg.addSignal("s1", { module: "honeypot", score: 0.9, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.ok(v.correlations.some(function (c) { return c.rule === "honeypot_triggered"; }));
});

test("correlation: clean session reduces score", function () {
  var agg = createSessionRiskAggregator({ weights: { geo: 1, biometrics: 1, fingerprint: 1 } });
  agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.1, timestamp: NOW });
  agg.addSignal("s1", { module: "fingerprint", score: 0.1, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.ok(v.correlations.some(function (c) { return c.rule === "clean_session"; }));
  assert.ok(v.score < 0.1);
});

test("correlation: multi-module consensus", function () {
  var agg = createSessionRiskAggregator({
    weights: { geo: 1, biometrics: 1, fingerprint: 1, cohort: 1, difficulty: 1 }
  });
  agg.addSignal("s1", { module: "geo", score: 0.6, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.6, timestamp: NOW });
  agg.addSignal("s1", { module: "fingerprint", score: 0.6, timestamp: NOW });
  agg.addSignal("s1", { module: "cohort", score: 0.6, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.ok(v.correlations.some(function (c) { return c.rule === "multi_module_consensus"; }));
});

test("custom correlation rules", function () {
  var agg = createSessionRiskAggregator({
    weights: { geo: 1 },
    correlationRules: [{
      name: "custom_test",
      description: "test rule",
      modules: ["geo"],
      condition: function (s) { return s.geo >= 0.5; },
      boost: 0.05
    }]
  });
  agg.addSignal("s1", { module: "geo", score: 0.6, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.ok(v.correlations.some(function (c) { return c.rule === "custom_test"; }));
});

// ── evaluateAll ─────────────────────────────────────────────────────

test("evaluateAll returns all sessions sorted by score", function () {
  var agg = createSessionRiskAggregator({ weights: { geo: 1 } });
  agg.addSignal("low", { module: "geo", score: 0.1, timestamp: NOW });
  agg.addSignal("high", { module: "geo", score: 0.9, timestamp: NOW });
  agg.addSignal("mid", { module: "geo", score: 0.5, timestamp: NOW });
  var r = agg.evaluateAll({ now: NOW });
  assert.strictEqual(r.sessions.length, 3);
  assert.strictEqual(r.sessions[0].sessionId, "high");
  assert.strictEqual(r.summary.total, 3);
});

test("evaluateAll prunes expired sessions", function () {
  var agg = createSessionRiskAggregator({ sessionTTLMs: 1000 });
  agg.addSignal("old", { module: "geo", score: 0.5, timestamp: NOW });
  agg.addSignal("new", { module: "geo", score: 0.3, timestamp: NOW + 2000 });
  var r = agg.evaluateAll({ now: NOW + 2000 });
  assert.strictEqual(r.sessions.length, 1);
  assert.strictEqual(r.sessions[0].sessionId, "new");
});

// ── getSession ──────────────────────────────────────────────────────

test("getSession returns null for unknown", function () {
  var agg = createSessionRiskAggregator();
  assert.strictEqual(agg.getSession("nope"), null);
});

test("getSession returns module summary", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.4, timestamp: NOW });
  agg.addSignal("s1", { module: "geo", score: 0.6, timestamp: NOW + 1000 });
  var s = agg.getSession("s1");
  assert.strictEqual(s.modules.geo.signalCount, 2);
  assert.strictEqual(s.modules.geo.latestScore, 0.6);
  assert.strictEqual(s.locked, false);
});

// ── setMetadata ─────────────────────────────────────────────────────

test("setMetadata attaches data to session", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
  agg.setMetadata("s1", { ip: "1.2.3.4", ua: "test" });
  var s = agg.getSession("s1");
  assert.strictEqual(s.metadata.ip, "1.2.3.4");
});

// ── unlock ──────────────────────────────────────────────────────────

test("unlock re-enables signal ingestion", function () {
  var agg = createSessionRiskAggregator({
    weights: { honeypot: 10 },
    thresholds: { critical: 0.5, high: 0.4, medium: 0.2, low: 0 }
  });
  agg.addSignal("s1", { module: "honeypot", score: 0.9, timestamp: NOW });
  agg.evaluate("s1", { now: NOW }); // triggers block
  assert.strictEqual(agg.addSignal("s1", { module: "geo", score: 0.1 }).ok, false);
  agg.unlock("s1");
  assert.strictEqual(agg.addSignal("s1", { module: "geo", score: 0.1 }).ok, true);
});

test("unlock returns error for unknown session", function () {
  var agg = createSessionRiskAggregator();
  assert.strictEqual(agg.unlock("nope").ok, false);
});

// ── removeSession ───────────────────────────────────────────────────

test("removeSession deletes session", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
  assert.strictEqual(agg.removeSession("s1").ok, true);
  assert.strictEqual(agg.getSession("s1"), null);
});

test("removeSession returns error for unknown", function () {
  var agg = createSessionRiskAggregator();
  assert.strictEqual(agg.removeSession("nope").ok, false);
});

// ── getTrend ────────────────────────────────────────────────────────

test("getTrend returns stable for single evaluation", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  var t = agg.getTrend("s1");
  assert.strictEqual(t.direction, "stable");
  assert.strictEqual(t.trend.length, 1);
});

test("getTrend detects rising risk", function () {
  var agg = createSessionRiskAggregator({ weights: { geo: 1 } });
  agg.addSignal("s1", { module: "geo", score: 0.2, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  agg.addSignal("s1", { module: "geo", score: 0.8, timestamp: NOW + 1000 });
  agg.evaluate("s1", { now: NOW + 1000 });
  var t = agg.getTrend("s1");
  assert.strictEqual(t.direction, "rising");
});

test("getTrend detects falling risk", function () {
  var agg = createSessionRiskAggregator({ weights: { geo: 1 } });
  agg.addSignal("s1", { module: "geo", score: 0.8, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW + 1000 });
  agg.evaluate("s1", { now: NOW + 1000 });
  var t = agg.getTrend("s1");
  assert.strictEqual(t.direction, "falling");
});

test("getTrend returns empty for unknown session", function () {
  var agg = createSessionRiskAggregator();
  var t = agg.getTrend("nope");
  assert.strictEqual(t.trend.length, 0);
  assert.strictEqual(t.direction, "stable");
});

// ── getStats ────────────────────────────────────────────────────────

test("getStats tracks signal and evaluation counts", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.5, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  var st = agg.getStats();
  assert.strictEqual(st.totalSignals, 2);
  assert.strictEqual(st.totalEvaluations, 1);
  assert.strictEqual(st.totalSessions, 1);
  assert.strictEqual(st.moduleSignalCounts.geo, 1);
  assert.strictEqual(st.moduleSignalCounts.biometrics, 1);
});

// ── setWeights ──────────────────────────────────────────────────────

test("setWeights updates weights at runtime", function () {
  var agg = createSessionRiskAggregator();
  var r = agg.setWeights({ geo: 0.99 });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.weights.geo, 0.99);
  assert.strictEqual(agg.getWeights().geo, 0.99);
});

// ── prune ───────────────────────────────────────────────────────────

test("prune removes expired sessions", function () {
  var agg = createSessionRiskAggregator({ sessionTTLMs: 5000 });
  agg.addSignal("old", { module: "geo", score: 0.5, timestamp: NOW });
  agg.addSignal("new", { module: "geo", score: 0.3, timestamp: NOW + 10000 });
  var r = agg.prune(NOW + 10000);
  assert.strictEqual(r.pruned, 1);
  assert.strictEqual(agg.getSession("old"), null);
  assert.ok(agg.getSession("new"));
});

// ── report ──────────────────────────────────────────────────────────

test("report generates readable output", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.6, factors: ["vpn"], timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.3, factors: ["natural_mouse"], timestamp: NOW });
  var rpt = agg.report("s1");
  assert.ok(rpt.indexOf("Session Risk Report") >= 0);
  assert.ok(rpt.indexOf("geo") >= 0);
  assert.ok(rpt.indexOf("biometrics") >= 0);
  assert.ok(rpt.indexOf("vpn") >= 0);
});

test("report handles unknown session", function () {
  var agg = createSessionRiskAggregator();
  var rpt = agg.report("nope");
  assert.ok(rpt.indexOf("not found") >= 0);
});

// ── export/import ───────────────────────────────────────────────────

test("exportData and importData roundtrip", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.3, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  var data = agg.exportData();

  var agg2 = createSessionRiskAggregator();
  var r = agg2.importData(data);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.sessionsLoaded, 1);
  var s = agg2.getSession("s1");
  assert.ok(s);
  assert.strictEqual(s.modules.geo.signalCount, 1);
});

test("importData rejects invalid data", function () {
  var agg = createSessionRiskAggregator();
  assert.strictEqual(agg.importData(null).ok, false);
  assert.strictEqual(agg.importData({}).ok, false);
});

// ── reset ───────────────────────────────────────────────────────────

test("reset clears all state", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  agg.reset();
  assert.strictEqual(agg.getSession("s1"), null);
  assert.strictEqual(agg.getStats().totalSignals, 0);
});

// ── Edge cases ──────────────────────────────────────────────────────

test("multiple modules with varying weights", function () {
  var agg = createSessionRiskAggregator({
    weights: { geo: 0.5, biometrics: 0.5, honeypot: 5.0 }
  });
  agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.1, timestamp: NOW });
  agg.addSignal("s1", { module: "honeypot", score: 0.9, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  // honeypot dominates due to weight
  assert.ok(v.score > 0.5);
});

test("session age is tracked", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW + 5000 });
  assert.strictEqual(v.sessionAge, 5000);
});

test("no timeline by default", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.strictEqual(v.timeline, undefined);
});

test("unknown module gets default weight", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "custom_module", score: 0.5, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  assert.ok(v.score > 0);
  assert.ok(v.moduleScores.custom_module !== undefined);
});

// ── Regression: stats drift fixes ───────────────────────────────────

test("blockedSessions does not double-count on re-evaluation", function () {
  var agg = createSessionRiskAggregator({
    thresholds: { low: 0.3, medium: 0.5, high: 0.7, critical: 0.9 },
    actions: { low: "allow", medium: "challenge", high: "block", critical: "block" }
  });
  agg.addSignal("s1", { module: "geo", score: 0.95, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.95, timestamp: NOW });
  agg.addSignal("s1", { module: "fingerprint", score: 0.95, timestamp: NOW });

  var v1 = agg.evaluate("s1", { now: NOW });
  assert.strictEqual(v1.action, "block");
  assert.strictEqual(agg.getStats().blockedSessions, 1);

  // Re-evaluate same blocked session — should NOT increment again
  var v2 = agg.evaluate("s1", { now: NOW + 1000 });
  assert.strictEqual(v2.action, "block");
  assert.strictEqual(agg.getStats().blockedSessions, 1);
});

test("removeSession decrements totalSessions", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  agg.addSignal("s2", { module: "geo", score: 0.3, timestamp: NOW });
  assert.strictEqual(agg.getStats().totalSessions, 2);

  agg.removeSession("s1");
  assert.strictEqual(agg.getStats().totalSessions, 1);
});

test("removeSession decrements blockedSessions for locked session", function () {
  var agg = createSessionRiskAggregator({
    actions: { low: "allow", medium: "challenge", high: "block", critical: "block" }
  });
  agg.addSignal("s1", { module: "geo", score: 0.99, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.99, timestamp: NOW });
  agg.addSignal("s1", { module: "fingerprint", score: 0.99, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  assert.strictEqual(agg.getStats().blockedSessions, 1);

  agg.removeSession("s1");
  assert.strictEqual(agg.getStats().blockedSessions, 0);
});

test("prune decrements totalSessions for expired sessions", function () {
  var agg = createSessionRiskAggregator({ sessionTTLMs: 5000 });
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  agg.addSignal("s2", { module: "geo", score: 0.3, timestamp: NOW + 4000 });
  assert.strictEqual(agg.getStats().totalSessions, 2);

  // At NOW + 6000, s1 has been idle >5000ms, should be pruned
  agg.prune(NOW + 6000);
  assert.strictEqual(agg.getStats().totalSessions, 1);
});

test("prune decrements blockedSessions for expired blocked sessions", function () {
  var agg = createSessionRiskAggregator({
    sessionTTLMs: 5000,
    actions: { low: "allow", medium: "challenge", high: "block", critical: "block" }
  });
  agg.addSignal("s1", { module: "geo", score: 0.99, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.99, timestamp: NOW });
  agg.addSignal("s1", { module: "fingerprint", score: 0.99, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  assert.strictEqual(agg.getStats().blockedSessions, 1);

  agg.prune(NOW + 6000);
  assert.strictEqual(agg.getStats().blockedSessions, 0);
  assert.strictEqual(agg.getStats().totalSessions, 0);
});

// ── Edge cases ──────────────────────────────────────────────────────

test("evaluate with includeTimeline sorts by timestamp", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW + 200 });
  agg.addSignal("s1", { module: "biometrics", score: 0.5, timestamp: NOW + 100 });
  agg.addSignal("s1", { module: "fingerprint", score: 0.2, timestamp: NOW + 300 });

  var v = agg.evaluate("s1", { now: NOW + 500, includeTimeline: true });
  assert.ok(v.timeline);
  assert.strictEqual(v.timeline.length, 3);
  // Should be in ascending timestamp order
  for (var i = 0; i < v.timeline.length - 1; i++) {
    assert.ok(v.timeline[i].timestamp <= v.timeline[i + 1].timestamp,
      "timeline should be sorted by timestamp");
  }
});

test("evaluate with all modules reporting", function () {
  var agg = createSessionRiskAggregator();
  var modules = ["geo", "biometrics", "fingerprint", "cohort", "difficulty", "honeypot", "template"];
  for (var i = 0; i < modules.length; i++) {
    agg.addSignal("s1", { module: modules[i], score: 0.4, timestamp: NOW });
  }
  var v = agg.evaluate("s1", { now: NOW });
  assert.strictEqual(v.modulesReporting, 7);
  assert.ok(v.score > 0);
});

test("addSignal with module alias georisk normalizes to geo", function () {
  var agg = createSessionRiskAggregator();
  var r = agg.addSignal("s1", { module: "georisk", score: 0.5, timestamp: NOW });
  assert.strictEqual(r.module, "geo");
});

test("addSignal with module alias behavioral normalizes to biometrics", function () {
  var agg = createSessionRiskAggregator();
  var r = agg.addSignal("s1", { module: "behavioral", score: 0.5, timestamp: NOW });
  assert.strictEqual(r.module, "biometrics");
});

test("addSignal with module alias solve-pattern normalizes to fingerprint", function () {
  var agg = createSessionRiskAggregator();
  var r = agg.addSignal("s1", { module: "solve-pattern", score: 0.5, timestamp: NOW });
  assert.strictEqual(r.module, "fingerprint");
});

test("setMetadata merges with existing metadata", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  agg.setMetadata("s1", { ip: "1.2.3.4" });
  agg.setMetadata("s1", { userAgent: "test" });

  var s = agg.getSession("s1");
  assert.strictEqual(s.metadata.ip, "1.2.3.4");
  assert.strictEqual(s.metadata.userAgent, "test");
});

test("evaluateAll summary includes correct p50 and p90", function () {
  var agg = createSessionRiskAggregator();
  for (var i = 1; i <= 10; i++) {
    agg.addSignal("s" + i, { module: "geo", score: i * 0.1, timestamp: NOW });
  }
  var result = agg.evaluateAll({ now: NOW });
  assert.strictEqual(result.sessions.length, 10);
  assert.ok(result.summary.p50Score >= 0);
  assert.ok(result.summary.p90Score >= result.summary.p50Score);
});

test("correlation fingerprint_replay fires with fingerprint+geo", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "fingerprint", score: 0.8, timestamp: NOW });
  agg.addSignal("s1", { module: "geo", score: 0.6, timestamp: NOW });
  var v = agg.evaluate("s1", { now: NOW });
  var rules = v.correlations.map(function(c) { return c.rule; });
  assert.ok(rules.indexOf("fingerprint_replay") !== -1);
});

test("getTrend returns stable for small score changes", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  agg.addSignal("s1", { module: "geo", score: 0.52, timestamp: NOW + 1000 });
  agg.evaluate("s1", { now: NOW + 1000 });
  var trend = agg.getTrend("s1");
  assert.strictEqual(trend.direction, "stable");
});

test("report contains module score bars", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.7, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.3, timestamp: NOW });
  var r = agg.report("s1");
  assert.ok(r.indexOf("Module Scores") !== -1);
  assert.ok(r.indexOf("geo") !== -1);
  assert.ok(r.indexOf("biometrics") !== -1);
});

test("exportData and importData preserve locked state", function () {
  var agg = createSessionRiskAggregator({
    actions: { low: "allow", medium: "challenge", high: "block", critical: "block" }
  });
  agg.addSignal("s1", { module: "geo", score: 0.99, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.99, timestamp: NOW });
  agg.addSignal("s1", { module: "fingerprint", score: 0.99, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  var exported = agg.exportData();

  var agg2 = createSessionRiskAggregator({
    actions: { low: "allow", medium: "challenge", high: "block", critical: "block" }
  });
  agg2.importData(exported);

  // Session should still be locked
  var r = agg2.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW + 1000 });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.error, "session is locked (blocked)");
});

test("stats totalSignals increments with each signal", function () {
  var agg = createSessionRiskAggregator();
  assert.strictEqual(agg.getStats().totalSignals, 0);
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  assert.strictEqual(agg.getStats().totalSignals, 1);
  agg.addSignal("s1", { module: "biometrics", score: 0.5, timestamp: NOW });
  assert.strictEqual(agg.getStats().totalSignals, 2);
  agg.addSignal("s2", { module: "geo", score: 0.1, timestamp: NOW });
  assert.strictEqual(agg.getStats().totalSignals, 3);
});

test("stats moduleSignalCounts tracks per-module", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
  agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
  agg.addSignal("s1", { module: "biometrics", score: 0.2, timestamp: NOW });
  var counts = agg.getStats().moduleSignalCounts;
  assert.strictEqual(counts.geo, 2);
  assert.strictEqual(counts.biometrics, 1);
});

test("evaluate increments verdictCounts", function () {
  var agg = createSessionRiskAggregator();
  agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
  agg.evaluate("s1", { now: NOW });
  assert.strictEqual(agg.getStats().verdictCounts.low, 1);
  assert.strictEqual(agg.getStats().totalEvaluations, 1);
});

// ── Summary ─────────────────────────────────────────────────────────

console.log("\n" + passed + " passed, " + failed + " failed, " + (passed + failed) + " total");
if (failed > 0) process.exit(1);
