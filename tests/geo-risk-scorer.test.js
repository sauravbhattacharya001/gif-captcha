"use strict";

var assert = require("assert");
var mod = require("../src/geo-risk-scorer");
var createGeoRiskScorer = mod.createGeoRiskScorer;

describe("createGeoRiskScorer", function () {
  it("should return a scorer with expected API", function () {
    var s = createGeoRiskScorer();
    assert.strictEqual(typeof s.score, "function");
    assert.strictEqual(typeof s.scoreBatch, "function");
    assert.strictEqual(typeof s.recordAttempt, "function");
    assert.strictEqual(typeof s.getRegionStats, "function");
    assert.strictEqual(typeof s.blockIP, "function");
    assert.strictEqual(typeof s.allowIP, "function");
    assert.strictEqual(typeof s.summary, "function");
    assert.strictEqual(typeof s.reset, "function");
  });

  it("should score a clean request as low risk", function () {
    var s = createGeoRiskScorer();
    var r = s.score({ ip: "1.2.3.4", country: "US", lat: 37.77, lon: -122.42 });
    assert.strictEqual(r.level, "low");
    assert.strictEqual(r.action, "allow");
    assert(r.score < 0.3);
  });

  it("should score high-risk country higher", function () {
    var s = createGeoRiskScorer();
    var r = s.score({ ip: "1.2.3.4", country: "RU" });
    assert(r.score > 0);
    var clean = s.score({ ip: "1.2.3.5", country: "US" });
    assert(r.score > clean.score);
  });

  it("should detect proxy/datacenter signals", function () {
    var s = createGeoRiskScorer();
    var r = s.score({ ip: "1.2.3.4", country: "US", isProxy: true, isDatacenter: true });
    assert(r.score > 0.3);
    assert(r.factors.some(function (f) { return f.name === "proxy_detected"; }));
  });

  it("should detect Tor exit nodes", function () {
    var s = createGeoRiskScorer();
    var r = s.score({ ip: "1.2.3.4", country: "DE", isTor: true });
    assert(r.factors.some(function (f) { return f.name === "proxy_detected" && f.detail.indexOf("Tor") !== -1; }));
  });

  it("should detect impossible travel", function () {
    var s = createGeoRiskScorer();
    var now = Date.now();
    // First request from San Francisco
    s.score({ ip: "1.2.3.4", country: "US", lat: 37.77, lon: -122.42, timestamp: now - 60000 });
    // Second request from Tokyo, 1 minute later (impossible)
    var r = s.score({ ip: "1.2.3.4", country: "JP", lat: 35.68, lon: 139.69, timestamp: now });
    assert(r.factors.some(function (f) { return f.name === "impossible_travel"; }));
    assert(r.score >= 0.5);
  });

  it("should not flag normal travel speed", function () {
    var s = createGeoRiskScorer();
    var now = Date.now();
    s.score({ ip: "1.2.3.4", country: "US", lat: 37.77, lon: -122.42, timestamp: now - 7200000 }); // 2h ago
    var r = s.score({ ip: "1.2.3.4", country: "US", lat: 34.05, lon: -118.24, timestamp: now }); // LA
    var hasImpossible = r.factors.some(function (f) { return f.name === "impossible_travel"; });
    assert(!hasImpossible);
  });

  it("should detect geo-hopping across sessions", function () {
    var s = createGeoRiskScorer();
    var now = Date.now();
    s.score({ ip: "1.1.1.1", country: "US", sessionId: "s1", timestamp: now - 30000 });
    s.score({ ip: "1.1.1.2", country: "DE", sessionId: "s1", timestamp: now - 20000 });
    s.score({ ip: "1.1.1.3", country: "JP", sessionId: "s1", timestamp: now - 10000 });
    var r = s.score({ ip: "1.1.1.4", country: "BR", sessionId: "s1", timestamp: now });
    assert(r.factors.some(function (f) { return f.name.indexOf("geo_hopping") !== -1; }));
  });

  it("should short-circuit on blocklisted IP", function () {
    var s = createGeoRiskScorer();
    s.blockIP("6.6.6.6");
    var r = s.score({ ip: "6.6.6.6", country: "US" });
    assert.strictEqual(r.score, 1);
    assert.strictEqual(r.action, "block");
  });

  it("should short-circuit on allowlisted IP", function () {
    var s = createGeoRiskScorer();
    s.allowIP("8.8.8.8");
    var r = s.score({ ip: "8.8.8.8", country: "RU", isProxy: true });
    assert.strictEqual(r.score, 0);
    assert.strictEqual(r.action, "allow");
  });

  it("should unblock/unallow IPs", function () {
    var s = createGeoRiskScorer();
    s.blockIP("1.1.1.1");
    assert(s.isBlocked("1.1.1.1"));
    s.unblockIP("1.1.1.1");
    assert(!s.isBlocked("1.1.1.1"));
  });

  it("should track region stats", function () {
    var s = createGeoRiskScorer();
    s.recordAttempt("US", true);
    s.recordAttempt("US", true);
    s.recordAttempt("US", false);
    var stats = s.getRegionStats("US");
    assert.strictEqual(stats.attempts, 3);
    assert.strictEqual(stats.solves, 2);
    assert(stats.solveRate > 0.6);
  });

  it("should return all region stats sorted by attempts", function () {
    var s = createGeoRiskScorer();
    for (var i = 0; i < 10; i++) s.recordAttempt("US", true);
    for (var j = 0; j < 5; j++) s.recordAttempt("DE", true);
    var all = s.getRegionStats();
    assert(Array.isArray(all));
    assert.strictEqual(all[0].country, "US");
  });

  it("should factor in low regional solve rate", function () {
    var s = createGeoRiskScorer();
    for (var i = 0; i < 25; i++) s.recordAttempt("XX", false); // 0% solve rate
    s.recordAttempt("XX", true); // 1/26 ≈ 3.8%
    var r = s.score({ ip: "2.2.2.2", country: "XX" });
    assert(r.factors.some(function (f) { return f.name === "region_low_solve_rate"; }));
  });

  it("should score batches", function () {
    var s = createGeoRiskScorer();
    var results = s.scoreBatch([
      { ip: "1.1.1.1", country: "US" },
      { ip: "2.2.2.2", country: "RU" },
    ]);
    assert.strictEqual(results.length, 2);
    assert(results[1].score > results[0].score);
  });

  it("should provide a summary", function () {
    var s = createGeoRiskScorer();
    s.score({ ip: "1.1.1.1", country: "US" });
    s.score({ ip: "2.2.2.2", country: "US" });
    var sum = s.summary();
    assert.strictEqual(sum.totalScored, 2);
    assert.strictEqual(sum.trackedIPs, 0); // no lat/lon
  });

  it("should reset all state", function () {
    var s = createGeoRiskScorer();
    s.score({ ip: "1.1.1.1", country: "US", lat: 0, lon: 0 });
    s.blockIP("9.9.9.9");
    s.recordAttempt("US", true);
    s.reset();
    var sum = s.summary();
    assert.strictEqual(sum.totalScored, 0);
    assert.strictEqual(sum.blockedIPs, 0);
    assert.strictEqual(sum.regionCount, 0);
  });

  it("should use custom thresholds", function () {
    var s = createGeoRiskScorer({ thresholds: { block: 0.9, challenge: 0.6, warn: 0.2 } });
    var r = s.score({ ip: "1.1.1.1", country: "RU" });
    // With only country risk factor at 0.4, composite should be moderate
    assert(r.action !== "block");
  });

  it("should throw on null meta", function () {
    var s = createGeoRiskScorer();
    assert.throws(function () { s.score(null); });
  });

  it("should handle custom high-risk countries", function () {
    var s = createGeoRiskScorer({ highRiskCountries: ["ZZ"] });
    var r = s.score({ ip: "1.1.1.1", country: "ZZ" });
    assert(r.factors.some(function (f) { return f.name === "country_high_risk"; }));
    // RU is NOT high risk with custom list
    var r2 = s.score({ ip: "1.1.1.2", country: "RU" });
    assert(!r2.factors.some(function (f) { return f.name === "country_high_risk"; }));
  });

  it("should handle missing country gracefully", function () {
    var s = createGeoRiskScorer();
    var r = s.score({ ip: "1.1.1.1" });
    assert(r.factors.some(function (f) { return f.name === "country_unknown"; }));
  });

  it("should handle VPN detection", function () {
    var s = createGeoRiskScorer();
    var r = s.score({ ip: "1.1.1.1", country: "US", isVpn: true });
    assert(r.factors.some(function (f) { return f.name === "proxy_detected" && f.detail.indexOf("VPN") !== -1; }));
  });

  it("should return null for unknown region stats", function () {
    var s = createGeoRiskScorer();
    assert.strictEqual(s.getRegionStats("ZZ"), null);
  });

  it("should track IPs with lat/lon in summary", function () {
    var s = createGeoRiskScorer();
    s.score({ ip: "1.1.1.1", country: "US", lat: 37, lon: -122 });
    s.score({ ip: "2.2.2.2", country: "US", lat: 40, lon: -74 });
    assert.strictEqual(s.summary().trackedIPs, 2);
  });
});
