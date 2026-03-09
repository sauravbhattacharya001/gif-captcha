/**
 * SessionRiskAggregator — Unit Tests
 */

"use strict";

var sra = require("../src/session-risk-aggregator");

function makeSignal(mod, score, opts) {
  opts = opts || {};
  return {
    module: mod,
    score: score,
    level: opts.level || (score >= 0.7 ? "high" : score >= 0.3 ? "medium" : "low"),
    factors: opts.factors || [],
    timestamp: opts.timestamp || Date.now()
  };
}

/* ================================================================
 * Factory & Defaults
 * ================================================================ */
describe("createSessionRiskAggregator", function () {
  test("returns an object with expected API", function () {
    var agg = sra.createSessionRiskAggregator();
    expect(typeof agg.addSignal).toBe("function");
    expect(typeof agg.evaluate).toBe("function");
    expect(typeof agg.evaluateAll).toBe("function");
    expect(typeof agg.getSession).toBe("function");
    expect(typeof agg.getTrend).toBe("function");
    expect(typeof agg.getStats).toBe("function");
    expect(typeof agg.getWeights).toBe("function");
    expect(typeof agg.setWeights).toBe("function");
    expect(typeof agg.prune).toBe("function");
    expect(typeof agg.report).toBe("function");
    expect(typeof agg.exportData).toBe("function");
    expect(typeof agg.importData).toBe("function");
    expect(typeof agg.reset).toBe("function");
    expect(typeof agg.setMetadata).toBe("function");
    expect(typeof agg.unlock).toBe("function");
    expect(typeof agg.removeSession).toBe("function");
  });

  test("accepts custom weights", function () {
    var agg = sra.createSessionRiskAggregator({ weights: { geo: 0.5 } });
    var w = agg.getWeights();
    expect(w.geo).toBe(0.5);
  });

  test("default weights cover all modules", function () {
    var agg = sra.createSessionRiskAggregator();
    var w = agg.getWeights();
    expect(w.geo).toBeDefined();
    expect(w.biometrics).toBeDefined();
    expect(w.fingerprint).toBeDefined();
    expect(w.cohort).toBeDefined();
    expect(w.difficulty).toBeDefined();
    expect(w.honeypot).toBeDefined();
    expect(w.template).toBeDefined();
  });
});

/* ================================================================
 * addSignal
 * ================================================================ */
describe("addSignal", function () {
  var agg;
  beforeEach(function () { agg = sra.createSessionRiskAggregator(); });

  test("adds a valid signal", function () {
    var result = agg.addSignal("s1", makeSignal("geo", 0.5));
    expect(result.ok).toBe(true);
    expect(result.module).toBe("geo");
    expect(result.signalCount).toBe(1);
  });

  test("rejects missing sessionId", function () {
    var result = agg.addSignal(null, makeSignal("geo", 0.5));
    expect(result.ok).toBe(false);
    expect(result.error).toBeDefined();
  });

  test("rejects null signal", function () {
    var result = agg.addSignal("s1", null);
    expect(result.ok).toBe(false);
  });

  test("rejects signal without module", function () {
    var result = agg.addSignal("s1", { score: 0.5 });
    expect(result.ok).toBe(false);
  });

  test("accepts custom/unknown module names", function () {
    var result = agg.addSignal("s1", { module: "custom_module", score: 0.5 });
    expect(result.ok).toBe(true);
  });

  test("normalizes module name aliases", function () {
    var r1 = agg.addSignal("s1", makeSignal("georisk", 0.4));
    expect(r1.ok).toBe(true);
    expect(r1.module).toBe("geo");

    var r2 = agg.addSignal("s1", makeSignal("behavioral-biometrics", 0.3));
    expect(r2.ok).toBe(true);
    expect(r2.module).toBe("biometrics");
  });

  test("creates session on first signal", function () {
    expect(agg.getSession("newSess")).toBeNull();
    agg.addSignal("newSess", makeSignal("geo", 0.5));
    expect(agg.getSession("newSess")).not.toBeNull();
  });

  test("accumulates signals in same module", function () {
    agg.addSignal("s1", makeSignal("geo", 0.3));
    var r2 = agg.addSignal("s1", makeSignal("geo", 0.6));
    expect(r2.signalCount).toBe(2);
  });

  test("clamps score > 1 to 1", function () {
    agg.addSignal("s1", makeSignal("geo", 5.0));
    var v = agg.evaluate("s1");
    expect(v.score).toBeLessThanOrEqual(1);
  });

  test("clamps score < 0 to 0", function () {
    agg.addSignal("s1", makeSignal("geo", -3.0));
    var v = agg.evaluate("s1");
    expect(v.score).toBeGreaterThanOrEqual(0);
  });

  test("non-numeric score produces NaN in evaluation", function () {
    agg.addSignal("s1", { module: "geo", score: "bad" });
    var v = agg.evaluate("s1");
    expect(isNaN(v.score)).toBe(true);
  });
});

/* ================================================================
 * evaluate
 * ================================================================ */
describe("evaluate", function () {
  var agg;
  beforeEach(function () { agg = sra.createSessionRiskAggregator(); });

  test("returns error for missing sessionId", function () {
    var v = agg.evaluate(null);
    expect(v.error).toBeDefined();
    expect(v.score).toBe(0);
  });

  test("returns error for unknown session", function () {
    var v = agg.evaluate("ghost");
    expect(v.error).toBeDefined();
  });

  test("returns low level for low-risk signals", function () {
    agg.addSignal("s1", makeSignal("geo", 0.1, { factors: ["domestic"] }));
    agg.addSignal("s1", makeSignal("biometrics", 0.05, { factors: ["natural"] }));
    var v = agg.evaluate("s1");
    expect(v.level).toBe("low");
    expect(v.action).toBe("allow");
  });

  test("returns high/critical for high-risk signals", function () {
    agg.addSignal("s1", makeSignal("geo", 0.9, { factors: ["impossible_travel"] }));
    agg.addSignal("s1", makeSignal("biometrics", 0.85, { factors: ["bot"] }));
    agg.addSignal("s1", makeSignal("honeypot", 0.95, { factors: ["triggered"] }));
    var v = agg.evaluate("s1");
    expect(["high", "critical"]).toContain(v.level);
  });

  test("includes moduleScores breakdown", function () {
    agg.addSignal("s1", makeSignal("geo", 0.4));
    agg.addSignal("s1", makeSignal("fingerprint", 0.6));
    var v = agg.evaluate("s1");
    expect(v.moduleScores.geo).toBeDefined();
    expect(v.moduleScores.fingerprint).toBeDefined();
  });

  test("collects unique factors", function () {
    agg.addSignal("s1", makeSignal("geo", 0.5, { factors: ["vpn", "new_country"] }));
    agg.addSignal("s1", makeSignal("geo", 0.6, { factors: ["vpn", "travel"] }));
    var v = agg.evaluate("s1");
    var vpnCount = v.factors.filter(function (f) { return f === "vpn"; }).length;
    expect(vpnCount).toBe(1);
    expect(v.factors).toContain("travel");
  });

  test("returns signalCount", function () {
    agg.addSignal("s1", makeSignal("geo", 0.3));
    agg.addSignal("s1", makeSignal("geo", 0.4));
    agg.addSignal("s1", makeSignal("biometrics", 0.2));
    var v = agg.evaluate("s1");
    expect(v.signalCount).toBe(3);
  });

  test("includes sessionId in result", function () {
    agg.addSignal("test123", makeSignal("geo", 0.5));
    var v = agg.evaluate("test123");
    expect(v.sessionId).toBe("test123");
  });

  test("score is between 0 and 1", function () {
    agg.addSignal("s1", makeSignal("geo", 0.8));
    agg.addSignal("s1", makeSignal("biometrics", 0.2));
    var v = agg.evaluate("s1");
    expect(v.score).toBeGreaterThanOrEqual(0);
    expect(v.score).toBeLessThanOrEqual(1);
  });
});

/* ================================================================
 * evaluateAll
 * ================================================================ */
describe("evaluateAll", function () {
  test("returns sessions array for all sessions", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("a", makeSignal("geo", 0.1));
    agg.addSignal("b", makeSignal("geo", 0.9));
    var results = agg.evaluateAll();
    expect(results.sessions).toBeDefined();
    expect(results.sessions.length).toBe(2);
    var ids = results.sessions.map(function (r) { return r.sessionId; });
    expect(ids).toContain("a");
    expect(ids).toContain("b");
  });

  test("returns empty sessions when no sessions", function () {
    var agg = sra.createSessionRiskAggregator();
    var results = agg.evaluateAll();
    expect(results.sessions.length).toBe(0);
  });

  test("includes summary", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.5));
    var results = agg.evaluateAll();
    expect(results.summary).toBeDefined();
  });
});

/* ================================================================
 * getSession / setMetadata / removeSession
 * ================================================================ */
describe("session management", function () {
  var agg;
  beforeEach(function () { agg = sra.createSessionRiskAggregator(); });

  test("getSession returns null for unknown session", function () {
    expect(agg.getSession("nope")).toBeNull();
  });

  test("getSession returns session data after addSignal", function () {
    agg.addSignal("s1", makeSignal("geo", 0.5));
    var sess = agg.getSession("s1");
    expect(sess).not.toBeNull();
    expect(sess.sessionId).toBe("s1");
    expect(sess.firstSeen).toBeDefined();
    expect(sess.lastSeen).toBeDefined();
  });

  test("getSession includes modules", function () {
    agg.addSignal("s1", makeSignal("geo", 0.5));
    agg.addSignal("s1", makeSignal("biometrics", 0.3));
    var sess = agg.getSession("s1");
    expect(sess.modules).toBeDefined();
  });

  test("setMetadata attaches metadata to session", function () {
    agg.addSignal("s1", makeSignal("geo", 0.5));
    agg.setMetadata("s1", { ip: "1.2.3.4", userAgent: "test" });
    var sess = agg.getSession("s1");
    expect(sess.metadata.ip).toBe("1.2.3.4");
  });

  test("removeSession deletes session", function () {
    agg.addSignal("s1", makeSignal("geo", 0.5));
    agg.removeSession("s1");
    expect(agg.getSession("s1")).toBeNull();
  });

  test("removeSession on unknown session does not throw", function () {
    expect(function () { agg.removeSession("x"); }).not.toThrow();
  });
});

/* ================================================================
 * getTrend
 * ================================================================ */
describe("getTrend", function () {
  test("returns trend with direction for session", function () {
    var agg = sra.createSessionRiskAggregator();
    var now = Date.now();
    agg.addSignal("s1", makeSignal("geo", 0.2, { timestamp: now - 5000 }));
    agg.addSignal("s1", makeSignal("geo", 0.4, { timestamp: now - 3000 }));
    agg.addSignal("s1", makeSignal("geo", 0.6, { timestamp: now - 1000 }));
    var trend = agg.getTrend("s1");
    expect(trend.direction).toBeDefined();
    expect(trend.trend).toBeDefined();
  });

  test("returns stable direction for unknown session", function () {
    var agg = sra.createSessionRiskAggregator();
    var trend = agg.getTrend("ghost");
    expect(trend.direction).toBe("stable");
    expect(trend.trend.length).toBe(0);
  });
});

/* ================================================================
 * Weights
 * ================================================================ */
describe("weights", function () {
  test("getWeights returns all module weights", function () {
    var agg = sra.createSessionRiskAggregator();
    var w = agg.getWeights();
    expect(w.geo).toBeDefined();
    expect(w.biometrics).toBeDefined();
    expect(w.honeypot).toBeDefined();
    expect(w.fingerprint).toBeDefined();
  });

  test("setWeights updates specific weight", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.setWeights({ geo: 0.99 });
    expect(agg.getWeights().geo).toBe(0.99);
  });

  test("setWeights preserves other weights", function () {
    var agg = sra.createSessionRiskAggregator();
    var orig = agg.getWeights().biometrics;
    agg.setWeights({ geo: 0.99 });
    expect(agg.getWeights().biometrics).toBe(orig);
  });
});

/* ================================================================
 * Export / Import / Reset
 * ================================================================ */
describe("data management", function () {
  test("exportData includes sessions and config", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.5));
    var data = agg.exportData();
    expect(data.sessions).toBeDefined();
    expect(data.stats).toBeDefined();
    expect(data.config).toBeDefined();
  });

  test("importData restores sessions", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.5));
    var exported = agg.exportData();

    var agg2 = sra.createSessionRiskAggregator();
    agg2.importData(exported);
    expect(agg2.getSession("s1")).not.toBeNull();
  });

  test("reset clears all sessions", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.5));
    agg.addSignal("s2", makeSignal("biometrics", 0.3));
    agg.reset();
    expect(agg.evaluateAll().sessions.length).toBe(0);
    expect(agg.getSession("s1")).toBeNull();
  });
});

/* ================================================================
 * Report
 * ================================================================ */
describe("report", function () {
  test("generates report string for session", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.7, { factors: ["vpn"] }));
    agg.addSignal("s1", makeSignal("biometrics", 0.3));
    var r = agg.report("s1");
    expect(typeof r).toBe("string");
    expect(r.length).toBeGreaterThan(50);
    expect(r).toContain("s1");
  });

  test("handles unknown session gracefully", function () {
    var agg = sra.createSessionRiskAggregator();
    var r = agg.report("ghost");
    expect(typeof r).toBe("string");
  });
});

/* ================================================================
 * Stats
 * ================================================================ */
describe("getStats", function () {
  test("returns stats object with expected fields", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.5));
    var stats = agg.getStats();
    expect(stats.totalSessions).toBe(1);
    expect(stats.totalSignals).toBe(1);
    expect(stats.verdictCounts).toBeDefined();
  });

  test("increments with more signals", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.5));
    agg.addSignal("s1", makeSignal("biometrics", 0.3));
    agg.addSignal("s2", makeSignal("honeypot", 0.1));
    var stats = agg.getStats();
    expect(stats.totalSessions).toBe(2);
    expect(stats.totalSignals).toBe(3);
  });

  test("tracks moduleSignalCounts", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.5));
    agg.addSignal("s1", makeSignal("geo", 0.6));
    var stats = agg.getStats();
    expect(stats.moduleSignalCounts.geo).toBe(2);
  });
});

/* ================================================================
 * Unlock
 * ================================================================ */
describe("unlock", function () {
  test("unlock on unknown session does not throw", function () {
    var agg = sra.createSessionRiskAggregator();
    expect(function () { agg.unlock("ghost"); }).not.toThrow();
  });

  test("unlock on existing session does not throw", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.95));
    agg.evaluate("s1");
    expect(function () { agg.unlock("s1"); }).not.toThrow();
  });
});

/* ================================================================
 * Prune
 * ================================================================ */
describe("prune", function () {
  test("removes expired sessions", function () {
    var agg = sra.createSessionRiskAggregator({
      sessionTTLMs: 100
    });
    var oldTime = Date.now() - 200;
    agg.addSignal("old", makeSignal("geo", 0.5, { timestamp: oldTime }));
    agg.addSignal("new", makeSignal("geo", 0.3));
    agg.prune();
    expect(agg.getSession("old")).toBeNull();
    expect(agg.getSession("new")).not.toBeNull();
  });

  test("does not prune recent sessions", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.5));
    agg.prune();
    expect(agg.getSession("s1")).not.toBeNull();
  });
});

/* ================================================================
 * Risk Decay
 * ================================================================ */
describe("risk decay", function () {
  test("recent signals outweigh older ones in same module", function () {
    var now = Date.now();
    var agg = sra.createSessionRiskAggregator();
    // Old high signal + recent low signal
    agg.addSignal("s1", makeSignal("geo", 0.9, { timestamp: now - 600000 }));
    agg.addSignal("s1", makeSignal("geo", 0.1, { timestamp: now }));
    var v = agg.evaluate("s1", { now: now });

    // Without decay, simple average would be ~0.5
    // With decay, recent signal (0.1) is weighted more, so score < 0.5
    expect(v.score).toBeLessThan(0.5);
  });
});

/* ================================================================
 * Module aliases
 * ================================================================ */
describe("module aliases", function () {
  test("georisk maps to geo", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("georisk", 0.5));
    var v = agg.evaluate("s1");
    expect(v.moduleScores.geo).toBeDefined();
  });

  test("behavioral-biometrics maps to biometrics", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("behavioral-biometrics", 0.5));
    var v = agg.evaluate("s1");
    expect(v.moduleScores.biometrics).toBeDefined();
  });

  test("solve-pattern maps to fingerprint", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("solve-pattern", 0.5));
    var v = agg.evaluate("s1");
    expect(v.moduleScores.fingerprint).toBeDefined();
  });

  test("device-cohort maps to cohort", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("device-cohort", 0.5));
    var v = agg.evaluate("s1");
    expect(v.moduleScores.cohort).toBeDefined();
  });

  test("adaptive-difficulty maps to difficulty", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("adaptive-difficulty", 0.5));
    var v = agg.evaluate("s1");
    expect(v.moduleScores.difficulty).toBeDefined();
  });

  test("honeypot-injector maps to honeypot", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("honeypot-injector", 0.5));
    var v = agg.evaluate("s1");
    expect(v.moduleScores.honeypot).toBeDefined();
  });
});

/* ================================================================
 * Edge Cases
 * ================================================================ */
describe("edge cases", function () {
  test("handles rapid signals without error", function () {
    var agg = sra.createSessionRiskAggregator();
    for (var i = 0; i < 100; i++) {
      agg.addSignal("s1", makeSignal("geo", Math.random()));
    }
    var v = agg.evaluate("s1");
    expect(v.score).toBeGreaterThanOrEqual(0);
    expect(v.score).toBeLessThanOrEqual(1);
  });

  test("handles many sessions", function () {
    var agg = sra.createSessionRiskAggregator();
    for (var i = 0; i < 50; i++) {
      agg.addSignal("sess_" + i, makeSignal("geo", 0.5));
    }
    var stats = agg.getStats();
    expect(stats.totalSessions).toBe(50);
  });

  test("multiple modules produce weighted score", function () {
    var agg = sra.createSessionRiskAggregator();
    agg.addSignal("s1", makeSignal("geo", 0.8));
    agg.addSignal("s1", makeSignal("biometrics", 0.2));
    agg.addSignal("s1", makeSignal("honeypot", 0.5));
    var v = agg.evaluate("s1");
    expect(v.score).toBeGreaterThan(0);
    expect(v.score).toBeLessThanOrEqual(1);
    expect(Object.keys(v.moduleScores).length).toBe(3);
  });
});
