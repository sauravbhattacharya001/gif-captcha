"use strict";

var { describe, it, beforeEach } = require("node:test");
var assert = require("node:assert/strict");
var { createSessionRiskAggregator } = require("../src/session-risk-aggregator");

var NOW = 1700000000000;

describe("SessionRiskAggregator", function () {
  var agg;

  beforeEach(function () {
    agg = createSessionRiskAggregator();
  });

  // ── Construction ──────────────────────────────────────────────

  describe("construction", function () {
    it("creates with defaults and returns zero-score for unknown session", function () {
      var v = agg.evaluate("nonexistent");
      assert.equal(v.score, 0);
      assert.equal(v.level, "low");
      assert.equal(v.action, "allow");
    });

    it("accepts custom weights", function () {
      var custom = createSessionRiskAggregator({ weights: { geo: 0.9, biometrics: 0.1 } });
      var w = custom.getWeights();
      assert.equal(w.geo, 0.9);
      assert.equal(w.biometrics, 0.1);
      // other defaults preserved
      assert.equal(w.fingerprint, 0.15);
    });

    it("accepts custom thresholds and actions", function () {
      var custom = createSessionRiskAggregator({
        thresholds: { low: 0.1, medium: 0.4, high: 0.6, critical: 0.8 },
        actions: { low: "pass", critical: "deny" }
      });
      custom.addSignal("s1", { module: "geo", score: 0.05, timestamp: NOW });
      var v = custom.evaluate("s1", { now: NOW });
      assert.equal(v.level, "low");
      assert.equal(v.action, "pass");
    });
  });

  // ── addSignal ─────────────────────────────────────────────────

  describe("addSignal", function () {
    it("adds a signal and returns ok", function () {
      var r = agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      assert.equal(r.ok, true);
      assert.equal(r.module, "geo");
      assert.equal(r.signalCount, 1);
    });

    it("rejects missing sessionId", function () {
      var r = agg.addSignal(null, { module: "geo", score: 0.5 });
      assert.equal(r.ok, false);
    });

    it("rejects missing module", function () {
      var r = agg.addSignal("s1", { score: 0.5 });
      assert.equal(r.ok, false);
    });

    it("normalizes module aliases", function () {
      agg.addSignal("s1", { module: "geo-risk", score: 0.5, timestamp: NOW });
      agg.addSignal("s1", { module: "georisk", score: 0.6, timestamp: NOW });
      agg.addSignal("s1", { module: "geo_risk", score: 0.7, timestamp: NOW });
      var sess = agg.getSession("s1");
      // All three should map to 'geo'
      assert.equal(sess.modules.geo.signalCount, 3);
    });

    it("normalizes biometrics aliases", function () {
      agg.addSignal("s1", { module: "behavioral-biometrics", score: 0.3, timestamp: NOW });
      agg.addSignal("s1", { module: "behavioral", score: 0.4, timestamp: NOW });
      var sess = agg.getSession("s1");
      assert.equal(sess.modules.biometrics.signalCount, 2);
    });

    it("normalizes fingerprint aliases", function () {
      agg.addSignal("s1", { module: "solve-pattern", score: 0.3, timestamp: NOW });
      agg.addSignal("s1", { module: "solve_pattern", score: 0.4, timestamp: NOW });
      agg.addSignal("s1", { module: "solvepattern", score: 0.5, timestamp: NOW });
      var sess = agg.getSession("s1");
      assert.equal(sess.modules.fingerprint.signalCount, 3);
    });

    it("clamps scores to [0, 1]", function () {
      agg.addSignal("s1", { module: "geo", score: 5.0, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      assert.ok(v.moduleScores.geo <= 1);
    });

    it("clamps negative scores to 0", function () {
      agg.addSignal("s1", { module: "geo", score: -2.0, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      assert.equal(v.moduleScores.geo, 0);
    });

    it("trims signals beyond maxSignalsPerModule", function () {
      var small = createSessionRiskAggregator({ maxSignalsPerModule: 3 });
      for (var i = 0; i < 10; i++) {
        small.addSignal("s1", { module: "geo", score: 0.1 * i, timestamp: NOW + i });
      }
      var sess = small.getSession("s1");
      assert.equal(sess.modules.geo.signalCount, 3);
    });

    it("rejects signals on locked (blocked) sessions", function () {
      var strict = createSessionRiskAggregator({ thresholds: { critical: 0.0 } });
      strict.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
      strict.evaluate("s1", { now: NOW }); // triggers block
      var r = strict.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      assert.equal(r.ok, false);
      assert.ok(r.error.includes("locked"));
    });

    it("tracks firstSeen and lastSeen correctly", function () {
      agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW + 100 });
      agg.addSignal("s1", { module: "geo", score: 0.4, timestamp: NOW });
      var sess = agg.getSession("s1");
      assert.equal(sess.firstSeen, NOW);
      assert.equal(sess.lastSeen, NOW + 100);
    });
  });

  // ── evaluate ──────────────────────────────────────────────────

  describe("evaluate", function () {
    it("returns error for null sessionId", function () {
      var v = agg.evaluate(null);
      assert.ok(v.error);
    });

    it("returns weighted average across modules", function () {
      agg.addSignal("s1", { module: "geo", score: 1.0, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.0, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      // geo weight 0.20, biometrics 0.20 → average should be 0.5
      assert.equal(v.score, 0.5);
    });

    it("classifies risk levels correctly", function () {
      // Low
      agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
      var v1 = agg.evaluate("s1", { now: NOW });
      assert.equal(v1.level, "low");
      assert.equal(v1.action, "allow");

      // Medium
      agg.reset();
      agg.addSignal("s2", { module: "geo", score: 0.6, timestamp: NOW });
      var v2 = agg.evaluate("s2", { now: NOW });
      assert.equal(v2.level, "medium");
      assert.equal(v2.action, "challenge");

      // High
      agg.reset();
      agg.addSignal("s3", { module: "geo", score: 0.8, timestamp: NOW });
      var v3 = agg.evaluate("s3", { now: NOW });
      assert.equal(v3.level, "high");
      assert.equal(v3.action, "escalate");
    });

    it("applies decay — older signals have less impact", function () {
      var halfLife = 300000; // 5 min default
      agg.addSignal("s1", { module: "geo", score: 1.0, timestamp: NOW - halfLife * 3 });
      agg.addSignal("s1", { module: "geo", score: 0.0, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      // Old high signal decayed significantly, recent 0.0 dominates
      assert.ok(v.moduleScores.geo < 0.2, "decayed score should be low: " + v.moduleScores.geo);
    });

    it("collects unique factors from all signals", function () {
      agg.addSignal("s1", { module: "geo", score: 0.5, factors: ["vpn", "tor"], timestamp: NOW });
      agg.addSignal("s1", { module: "geo", score: 0.6, factors: ["vpn", "impossible_travel"], timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      assert.ok(v.factors.includes("vpn"));
      assert.ok(v.factors.includes("tor"));
      assert.ok(v.factors.includes("impossible_travel"));
      // vpn should appear only once (deduped)
      assert.equal(v.factors.filter(function (f) { return f === "vpn"; }).length, 1);
    });

    it("includes signal count and module count", function () {
      agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
      agg.addSignal("s1", { module: "geo", score: 0.4, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.2, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      assert.equal(v.signalCount, 3);
      assert.equal(v.modulesReporting, 2);
    });

    it("handles unknown module with default weight", function () {
      agg.addSignal("s1", { module: "custom_scanner", score: 0.8, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      assert.ok(v.score > 0);
      assert.ok(v.moduleScores.custom_scanner > 0);
    });

    it("includes timeline when requested", function () {
      agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.3, timestamp: NOW + 100 });
      var v = agg.evaluate("s1", { now: NOW + 200, includeTimeline: true });
      assert.ok(v.timeline);
      assert.equal(v.timeline.length, 2);
      // Timeline should be sorted by timestamp
      assert.ok(v.timeline[0].timestamp <= v.timeline[1].timestamp);
    });

    it("does not include timeline by default", function () {
      agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      assert.equal(v.timeline, undefined);
    });

    it("includes sessionAge in verdict", function () {
      agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW + 5000 });
      assert.equal(v.sessionAge, 5000);
    });
  });

  // ── Correlation rules ─────────────────────────────────────────

  describe("correlation rules", function () {
    it("boosts score for geo + biometrics bot pattern", function () {
      agg.addSignal("s1", { module: "geo", score: 0.7, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.7, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      // geo_plus_biometrics_bot boost = 0.15
      var corr = v.correlations.find(function (c) { return c.rule === "geo_plus_biometrics_bot"; });
      assert.ok(corr, "geo_plus_biometrics_bot correlation should fire");
      assert.equal(corr.boost, 0.15);
    });

    it("boosts score for honeypot triggered", function () {
      agg.addSignal("s1", { module: "honeypot", score: 0.9, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      var corr = v.correlations.find(function (c) { return c.rule === "honeypot_triggered"; });
      assert.ok(corr);
      assert.equal(corr.boost, 0.20);
    });

    it("boosts score for fingerprint + geo replay pattern", function () {
      agg.addSignal("s1", { module: "fingerprint", score: 0.8, timestamp: NOW });
      agg.addSignal("s1", { module: "geo", score: 0.6, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      var corr = v.correlations.find(function (c) { return c.rule === "fingerprint_replay"; });
      assert.ok(corr);
      assert.equal(corr.boost, 0.10);
    });

    it("applies multi-module consensus boost", function () {
      agg.addSignal("s1", { module: "geo", score: 0.6, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.6, timestamp: NOW });
      agg.addSignal("s1", { module: "fingerprint", score: 0.6, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      var corr = v.correlations.find(function (c) { return c.rule === "multi_module_consensus"; });
      assert.ok(corr, "multi_module_consensus should fire with 3 elevated modules");
    });

    it("reduces score for clean session", function () {
      agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.1, timestamp: NOW });
      agg.addSignal("s1", { module: "fingerprint", score: 0.1, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      var corr = v.correlations.find(function (c) { return c.rule === "clean_session"; });
      assert.ok(corr, "clean_session should fire");
      assert.equal(corr.boost, -0.10);
    });

    it("supports custom correlation rules", function () {
      var custom = createSessionRiskAggregator({
        correlationRules: [{
          name: "custom_rule",
          description: "always fires",
          modules: [],
          condition: function () { return true; },
          boost: 0.05
        }]
      });
      custom.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
      var v = custom.evaluate("s1", { now: NOW });
      var corr = v.correlations.find(function (c) { return c.rule === "custom_rule"; });
      assert.ok(corr);
    });

    it("clamps final score to [0, 1] even with heavy boosts", function () {
      agg.addSignal("s1", { module: "geo", score: 1.0, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 1.0, timestamp: NOW });
      agg.addSignal("s1", { module: "fingerprint", score: 1.0, timestamp: NOW });
      agg.addSignal("s1", { module: "honeypot", score: 1.0, timestamp: NOW });
      var v = agg.evaluate("s1", { now: NOW });
      assert.ok(v.score <= 1, "score should be clamped to 1, got " + v.score);
    });
  });

  // ── evaluateAll ───────────────────────────────────────────────

  describe("evaluateAll", function () {
    it("evaluates all active sessions", function () {
      agg.addSignal("s1", { module: "geo", score: 0.2, timestamp: NOW });
      agg.addSignal("s2", { module: "geo", score: 0.8, timestamp: NOW });
      agg.addSignal("s3", { module: "geo", score: 0.5, timestamp: NOW });
      var result = agg.evaluateAll({ now: NOW });
      assert.equal(result.sessions.length, 3);
      assert.equal(result.summary.total, 3);
      // Sessions sorted by score descending
      assert.ok(result.sessions[0].score >= result.sessions[1].score);
      assert.ok(result.sessions[1].score >= result.sessions[2].score);
    });

    it("computes summary statistics", function () {
      agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
      agg.addSignal("s2", { module: "geo", score: 0.5, timestamp: NOW });
      agg.addSignal("s3", { module: "geo", score: 0.9, timestamp: NOW });
      var result = agg.evaluateAll({ now: NOW });
      assert.ok(result.summary.avgScore > 0);
      assert.ok(result.summary.p50Score !== undefined);
      assert.ok(result.summary.p90Score !== undefined);
      assert.ok(result.summary.p99Score !== undefined);
    });

    it("prunes expired sessions before evaluating", function () {
      var ttl = 60000;
      var shortLived = createSessionRiskAggregator({ sessionTTLMs: ttl });
      shortLived.addSignal("old", { module: "geo", score: 0.5, timestamp: NOW - ttl - 1000 });
      shortLived.addSignal("fresh", { module: "geo", score: 0.3, timestamp: NOW });
      var result = shortLived.evaluateAll({ now: NOW });
      assert.equal(result.summary.total, 1);
      assert.equal(result.sessions[0].sessionId, "fresh");
    });

    it("returns empty results when no sessions exist", function () {
      var result = agg.evaluateAll({ now: NOW });
      assert.equal(result.summary.total, 0);
      assert.equal(result.summary.avgScore, 0);
    });
  });

  // ── Session management ────────────────────────────────────────

  describe("session management", function () {
    it("getSession returns null for nonexistent", function () {
      assert.equal(agg.getSession("nope"), null);
    });

    it("getSession returns module summary", function () {
      agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.3, timestamp: NOW });
      var sess = agg.getSession("s1");
      assert.equal(sess.sessionId, "s1");
      assert.equal(sess.modules.geo.signalCount, 1);
      assert.equal(sess.modules.biometrics.signalCount, 1);
      assert.equal(sess.locked, false);
    });

    it("setMetadata attaches metadata to session", function () {
      agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
      agg.setMetadata("s1", { ip: "1.2.3.4", ua: "Chrome" });
      var sess = agg.getSession("s1");
      assert.equal(sess.metadata.ip, "1.2.3.4");
      assert.equal(sess.metadata.ua, "Chrome");
    });

    it("setMetadata merges with existing metadata", function () {
      agg.setMetadata("s1", { ip: "1.2.3.4" });
      agg.setMetadata("s1", { ua: "Firefox" });
      var sess = agg.getSession("s1");
      assert.equal(sess.metadata.ip, "1.2.3.4");
      assert.equal(sess.metadata.ua, "Firefox");
    });

    it("removeSession deletes a session", function () {
      agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
      var r = agg.removeSession("s1");
      assert.equal(r.ok, true);
      assert.equal(agg.getSession("s1"), null);
    });

    it("removeSession returns error for nonexistent", function () {
      var r = agg.removeSession("nope");
      assert.equal(r.ok, false);
    });

    it("unlock re-enables signal ingestion on blocked session", function () {
      var strict = createSessionRiskAggregator({
        thresholds: { low: 0.3, medium: 0.5, high: 0.7, critical: 0.0 }
      });
      strict.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      strict.evaluate("s1", { now: NOW }); // triggers block

      var locked = strict.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
      assert.equal(locked.ok, false);

      strict.unlock("s1");
      var unlocked = strict.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
      assert.equal(unlocked.ok, true);
    });

    it("unlock returns error for nonexistent session", function () {
      var r = agg.unlock("nope");
      assert.equal(r.ok, false);
    });
  });

  // ── getTrend ──────────────────────────────────────────────────

  describe("getTrend", function () {
    it("returns empty trend for unknown session", function () {
      var t = agg.getTrend("nope");
      assert.deepEqual(t.trend, []);
      assert.equal(t.direction, "stable");
    });

    it("returns stable when only one evaluation", function () {
      agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      agg.evaluate("s1", { now: NOW });
      var t = agg.getTrend("s1");
      assert.equal(t.trend.length, 1);
      assert.equal(t.direction, "stable");
    });

    it("detects rising trend", function () {
      agg.addSignal("s1", { module: "geo", score: 0.2, timestamp: NOW });
      agg.evaluate("s1", { now: NOW });
      agg.addSignal("s1", { module: "geo", score: 0.8, timestamp: NOW + 1000 });
      agg.evaluate("s1", { now: NOW + 1000 });
      var t = agg.getTrend("s1");
      assert.equal(t.direction, "rising");
    });

    it("detects falling trend", function () {
      agg.addSignal("s1", { module: "geo", score: 0.8, timestamp: NOW });
      agg.evaluate("s1", { now: NOW });
      agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW + 1000 });
      agg.evaluate("s1", { now: NOW + 1000 });
      var t = agg.getTrend("s1");
      assert.equal(t.direction, "falling");
    });
  });

  // ── Stats ─────────────────────────────────────────────────────

  describe("getStats", function () {
    it("tracks signal counts", function () {
      agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.5, timestamp: NOW });
      var st = agg.getStats();
      assert.equal(st.totalSignals, 2);
      assert.equal(st.moduleSignalCounts.geo, 1);
      assert.equal(st.moduleSignalCounts.biometrics, 1);
    });

    it("tracks evaluations and verdict counts", function () {
      agg.addSignal("s1", { module: "geo", score: 0.1, timestamp: NOW });
      agg.evaluate("s1", { now: NOW });
      agg.addSignal("s2", { module: "geo", score: 0.8, timestamp: NOW });
      agg.evaluate("s2", { now: NOW });
      var st = agg.getStats();
      assert.equal(st.totalEvaluations, 2);
      assert.ok(st.verdictCounts.low >= 1);
    });

    it("tracks session count", function () {
      agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
      agg.addSignal("s2", { module: "geo", score: 0.5, timestamp: NOW });
      var st = agg.getStats();
      assert.equal(st.totalSessions, 2);
    });

    it("returns a copy (not a reference)", function () {
      agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
      var st1 = agg.getStats();
      st1.totalSignals = 9999;
      var st2 = agg.getStats();
      assert.equal(st2.totalSignals, 1);
    });
  });

  // ── Weights ───────────────────────────────────────────────────

  describe("weights", function () {
    it("getWeights returns current config", function () {
      var w = agg.getWeights();
      assert.equal(w.geo, 0.20);
      assert.equal(w.honeypot, 0.15);
    });

    it("setWeights updates weights at runtime", function () {
      agg.setWeights({ geo: 0.5, biometrics: 0.5 });
      var w = agg.getWeights();
      assert.equal(w.geo, 0.5);
      assert.equal(w.biometrics, 0.5);
      // Others preserved
      assert.equal(w.fingerprint, 0.15);
    });

    it("weight changes affect subsequent evaluations", function () {
      agg.addSignal("s1", { module: "geo", score: 1.0, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.0, timestamp: NOW });

      var v1 = agg.evaluate("s1", { now: NOW });

      // Heavily weight geo
      agg.setWeights({ geo: 0.99, biometrics: 0.01 });
      var v2 = agg.evaluate("s1", { now: NOW });
      assert.ok(v2.score > v1.score, "heavier geo weight should raise score");
    });
  });

  // ── Prune ─────────────────────────────────────────────────────

  describe("prune", function () {
    it("removes expired sessions", function () {
      var ttl = 60000;
      var prunable = createSessionRiskAggregator({ sessionTTLMs: ttl });
      prunable.addSignal("old", { module: "geo", score: 0.5, timestamp: NOW - ttl - 1000 });
      prunable.addSignal("fresh", { module: "geo", score: 0.3, timestamp: NOW });
      var r = prunable.prune(NOW);
      assert.equal(r.pruned, 1);
      assert.equal(prunable.getSession("old"), null);
      assert.ok(prunable.getSession("fresh") !== null);
    });

    it("returns zero when nothing to prune", function () {
      agg.addSignal("s1", { module: "geo", score: 0.3, timestamp: NOW });
      var r = agg.prune(NOW);
      assert.equal(r.pruned, 0);
    });
  });

  // ── Report ────────────────────────────────────────────────────

  describe("report", function () {
    it("generates a human-readable report", function () {
      agg.addSignal("s1", { module: "geo", score: 0.7, factors: ["vpn"], timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.3, factors: ["natural_mouse"], timestamp: NOW });
      var r = agg.report("s1");
      assert.ok(r.includes("Session Risk Report"));
      assert.ok(r.includes("s1"));
      assert.ok(r.includes("geo"));
      assert.ok(r.includes("biometrics"));
      assert.ok(r.includes("vpn"));
    });

    it("handles nonexistent session gracefully", function () {
      var r = agg.report("nope");
      assert.ok(r.includes("not found"));
    });
  });

  // ── Export / Import ───────────────────────────────────────────

  describe("export and import", function () {
    it("exports all session data", function () {
      agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      agg.addSignal("s2", { module: "biometrics", score: 0.3, timestamp: NOW });
      var data = agg.exportData();
      assert.ok(data.sessions.s1);
      assert.ok(data.sessions.s2);
      assert.ok(data.config.weights);
      assert.ok(data.stats);
    });

    it("imports session data into a fresh aggregator", function () {
      agg.addSignal("s1", { module: "geo", score: 0.6, timestamp: NOW });
      agg.addSignal("s1", { module: "biometrics", score: 0.4, timestamp: NOW });
      var data = agg.exportData();

      var fresh = createSessionRiskAggregator();
      var r = fresh.importData(data);
      assert.equal(r.ok, true);
      assert.equal(r.sessionsLoaded, 1);

      // Imported session should be evaluable
      var v = fresh.evaluate("s1", { now: NOW });
      assert.ok(v.score > 0);
    });

    it("rejects invalid import data", function () {
      var r = agg.importData(null);
      assert.equal(r.ok, false);
    });

    it("export returns copies (not references)", function () {
      agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      var data = agg.exportData();
      data.sessions.s1.signals.geo[0].score = 999;
      var v = agg.evaluate("s1", { now: NOW });
      assert.ok(v.moduleScores.geo <= 1, "export mutation should not affect original");
    });
  });

  // ── Reset ─────────────────────────────────────────────────────

  describe("reset", function () {
    it("clears all sessions and stats", function () {
      agg.addSignal("s1", { module: "geo", score: 0.5, timestamp: NOW });
      agg.addSignal("s2", { module: "biometrics", score: 0.3, timestamp: NOW });
      agg.evaluate("s1", { now: NOW });
      agg.reset();

      assert.equal(agg.getSession("s1"), null);
      assert.equal(agg.getSession("s2"), null);
      var st = agg.getStats();
      assert.equal(st.totalSignals, 0);
      assert.equal(st.totalEvaluations, 0);
      assert.equal(st.totalSessions, 0);
    });
  });

  // ── Multi-session isolation ───────────────────────────────────

  describe("session isolation", function () {
    it("signals on one session do not affect another", function () {
      agg.addSignal("s1", { module: "geo", score: 0.9, timestamp: NOW });
      agg.addSignal("s2", { module: "geo", score: 0.1, timestamp: NOW });
      var v1 = agg.evaluate("s1", { now: NOW });
      var v2 = agg.evaluate("s2", { now: NOW });
      assert.ok(v1.score > v2.score);
      assert.equal(v1.signalCount, 1);
      assert.equal(v2.signalCount, 1);
    });

    it("blocking one session does not block others", function () {
      var strict = createSessionRiskAggregator({
        thresholds: { low: 0.3, medium: 0.5, high: 0.7, critical: 0.0 }
      });
      strict.addSignal("s1", { module: "geo", score: 0.9, timestamp: NOW });
      strict.evaluate("s1", { now: NOW }); // blocks s1

      var r = strict.addSignal("s2", { module: "geo", score: 0.1, timestamp: NOW });
      assert.equal(r.ok, true); // s2 is not blocked
    });
  });
});
