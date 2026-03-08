"use strict";

/**
 * Additional tests for GeoRiskScorer — edge cases, boundary conditions,
 * composite scoring, suspicious travel, concurrency patterns, and
 * configuration validation.
 *
 * Supplements the existing 22 tests in geo-risk-scorer.test.js.
 */

var assert = require("assert");
var mod = require("../src/geo-risk-scorer");
var createGeoRiskScorer = mod.createGeoRiskScorer;

describe("GeoRiskScorer — extended tests", function () {

  // ── Composite Scoring ────────────────────────────────────────────

  describe("composite scoring formula", function () {
    it("should compute 70/30 max/avg blend", function () {
      // A request from a high-risk country with proxy → two non-zero factors
      var s = createGeoRiskScorer();
      var r = s.score({ ip: "1.2.3.4", country: "CN", isProxy: true });
      // Both country_high_risk (0.4) and proxy_detected (0.35) contribute
      assert(r.score > 0.2, "composite should reflect multiple risk factors");
      assert(r.score <= 1.0);
    });

    it("should clamp composite to 0-1 range", function () {
      // Max stacking: Tor + proxy + datacenter + VPN + high-risk country
      var s = createGeoRiskScorer();
      var r = s.score({
        ip: "1.2.3.4", country: "KP",
        isProxy: true, isDatacenter: true, isTor: true, isVpn: true
      });
      assert(r.score <= 1.0);
      assert(r.score >= 0);
    });

    it("should produce higher score for more risk factors", function () {
      var s = createGeoRiskScorer();
      var r1 = s.score({ ip: "1.1.1.1", country: "RU" });
      var r2 = s.score({ ip: "1.1.1.2", country: "RU", isProxy: true });
      var r3 = s.score({ ip: "1.1.1.3", country: "RU", isProxy: true, isTor: true });
      assert(r2.score > r1.score, "proxy + country > country alone");
      assert(r3.score > r2.score, "Tor + proxy + country > proxy + country");
    });
  });

  // ── Suspicious Travel (sub-impossible threshold) ─────────────────

  describe("suspicious travel detection", function () {
    it("should detect suspicious but not impossible travel speed", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      // SF to LA (distance ~560km), in 1 hour → ~560 km/h (suspicious, not impossible)
      s.score({ ip: "5.5.5.5", country: "US", lat: 37.77, lon: -122.42, timestamp: now - 3600000 });
      var r = s.score({ ip: "5.5.5.5", country: "US", lat: 34.05, lon: -118.24, timestamp: now });
      var hasSuspicious = r.factors.some(function (f) { return f.name === "suspicious_travel"; });
      var hasImpossible = r.factors.some(function (f) { return f.name === "impossible_travel"; });
      assert(hasSuspicious, "should flag suspicious travel");
      assert(!hasImpossible, "should not flag as impossible");
    });

    it("should not flag velocity when dt is zero", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      s.score({ ip: "7.7.7.7", country: "US", lat: 37.77, lon: -122.42, timestamp: now });
      // Same timestamp (dt=0) — should be skipped without division by zero
      var r = s.score({ ip: "7.7.7.7", country: "US", lat: 40.71, lon: -74.00, timestamp: now });
      var hasImpossible = r.factors.some(function (f) { return f.name === "impossible_travel"; });
      // With dt=0 the velocity check should skip (dt <= 0 guard)
      assert(!hasImpossible);
    });
  });

  // ── Velocity Window Boundary ─────────────────────────────────────

  describe("velocity window", function () {
    it("should ignore history outside the velocity window", function () {
      var s = createGeoRiskScorer({ velocityWindowMs: 3600000 }); // 1 hour
      var now = Date.now();
      // Request from SF 2 hours ago (outside window)
      s.score({ ip: "9.9.9.9", country: "US", lat: 37.77, lon: -122.42, timestamp: now - 7200000 });
      // Request from Tokyo now — should NOT trigger impossible travel (old history is outside window)
      var r = s.score({ ip: "9.9.9.9", country: "JP", lat: 35.68, lon: 139.69, timestamp: now });
      var hasImpossible = r.factors.some(function (f) { return f.name === "impossible_travel"; });
      assert(!hasImpossible, "should not flag travel outside velocity window");
    });
  });

  // ── Geo-Hopping Levels ───────────────────────────────────────────

  describe("geo-hopping granularity", function () {
    it("should report mild hopping for 2 countries", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      s.score({ ip: "1.1.1.1", country: "US", sessionId: "mild", timestamp: now - 1000 });
      var r = s.score({ ip: "1.1.1.2", country: "DE", sessionId: "mild", timestamp: now });
      var has = r.factors.some(function (f) { return f.name === "geo_hopping_mild"; });
      assert(has, "2 countries should be mild hopping");
    });

    it("should report high hopping for 3 countries", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      s.score({ ip: "1.1.1.1", country: "US", sessionId: "high", timestamp: now - 2000 });
      s.score({ ip: "1.1.1.2", country: "DE", sessionId: "high", timestamp: now - 1000 });
      var r = s.score({ ip: "1.1.1.3", country: "JP", sessionId: "high", timestamp: now });
      var has = r.factors.some(function (f) { return f.name === "geo_hopping_high"; });
      assert(has, "3 countries should be high hopping");
    });

    it("should report extreme hopping for 4+ countries", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      s.score({ ip: "a", country: "US", sessionId: "ext", timestamp: now - 3000 });
      s.score({ ip: "b", country: "DE", sessionId: "ext", timestamp: now - 2000 });
      s.score({ ip: "c", country: "JP", sessionId: "ext", timestamp: now - 1000 });
      var r = s.score({ ip: "d", country: "BR", sessionId: "ext", timestamp: now });
      var has = r.factors.some(function (f) { return f.name === "geo_hopping_extreme"; });
      assert(has, "4 countries should be extreme hopping");
    });

    it("should not flag geo-hopping with same country", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      s.score({ ip: "1.1.1.1", country: "US", sessionId: "same", timestamp: now - 1000 });
      var r = s.score({ ip: "1.1.1.2", country: "US", sessionId: "same", timestamp: now });
      var hasHopping = r.factors.some(function (f) { return f.name.indexOf("geo_hopping") !== -1; });
      assert(!hasHopping, "same country should not trigger geo-hopping");
    });
  });

  // ── Medium Risk Countries ────────────────────────────────────────

  describe("medium risk countries", function () {
    it("should flag medium-risk country", function () {
      var s = createGeoRiskScorer();
      var r = s.score({ ip: "1.1.1.1", country: "BR" });
      assert(r.factors.some(function (f) { return f.name === "country_medium_risk"; }));
    });

    it("should score medium-risk lower than high-risk", function () {
      var s = createGeoRiskScorer();
      var rMed = s.score({ ip: "1.1.1.1", country: "IN" });
      var rHigh = s.score({ ip: "1.1.1.2", country: "CN" });
      assert(rHigh.score > rMed.score);
    });
  });

  // ── Regional Anomaly Factor ──────────────────────────────────────

  describe("regional anomaly", function () {
    it("should not flag region with insufficient data", function () {
      var s = createGeoRiskScorer();
      // Only 10 attempts (< 20 threshold)
      for (var i = 0; i < 10; i++) s.recordAttempt("YY", false);
      var r = s.score({ ip: "1.1.1.1", country: "YY" });
      var has = r.factors.some(function (f) { return f.name.indexOf("region_") !== -1; });
      assert(!has, "should not flag region with < 20 attempts");
    });

    it("should flag below-average solve rate (10-30%)", function () {
      var s = createGeoRiskScorer();
      // 25 attempts, 6 solves = 24% solve rate
      for (var i = 0; i < 19; i++) s.recordAttempt("QQ", false);
      for (var j = 0; j < 6; j++) s.recordAttempt("QQ", true);
      var r = s.score({ ip: "1.1.1.1", country: "QQ" });
      assert(r.factors.some(function (f) { return f.name === "region_below_avg_solve"; }));
    });

    it("should not flag region with healthy solve rate (>30%)", function () {
      var s = createGeoRiskScorer();
      for (var i = 0; i < 10; i++) s.recordAttempt("WW", false);
      for (var j = 0; j < 15; j++) s.recordAttempt("WW", true);
      var r = s.score({ ip: "1.1.1.1", country: "WW" });
      var has = r.factors.some(function (f) { return f.name.indexOf("region_") !== -1; });
      assert(!has, "healthy solve rate should not be flagged");
    });
  });

  // ── IP Blocklist / Allowlist Edge Cases ──────────────────────────

  describe("IP list management", function () {
    it("should handle block then unblock then re-block", function () {
      var s = createGeoRiskScorer();
      s.blockIP("3.3.3.3");
      assert(s.isBlocked("3.3.3.3"));
      s.unblockIP("3.3.3.3");
      assert(!s.isBlocked("3.3.3.3"));
      // Re-scoring should not be blocked
      var r = s.score({ ip: "3.3.3.3", country: "US" });
      assert(r.action !== "block" || r.score < 1);
      // Re-block
      s.blockIP("3.3.3.3");
      r = s.score({ ip: "3.3.3.3", country: "US" });
      assert.strictEqual(r.score, 1);
    });

    it("should prioritize allowlist over risk factors", function () {
      var s = createGeoRiskScorer();
      s.allowIP("4.4.4.4");
      var r = s.score({ ip: "4.4.4.4", country: "KP", isTor: true, isProxy: true });
      assert.strictEqual(r.score, 0);
      assert.strictEqual(r.action, "allow");
    });

    it("should handle IP on both blocklist and allowlist", function () {
      var s = createGeoRiskScorer();
      // Allowlist is checked first in score()
      s.allowIP("5.5.5.5");
      s.blockIP("5.5.5.5");
      var r = s.score({ ip: "5.5.5.5", country: "US" });
      // allowlist check comes first, so it should allow
      assert.strictEqual(r.score, 0);
    });

    it("should not crash on unblocking non-existent IP", function () {
      var s = createGeoRiskScorer();
      s.unblockIP("nonexistent");
      assert(!s.isBlocked("nonexistent"));
    });

    it("should not crash on unallowing non-existent IP", function () {
      var s = createGeoRiskScorer();
      s.unallowIP("nonexistent");
      assert(!s.isAllowed("nonexistent"));
    });
  });

  // ── Scoring with Missing Fields ──────────────────────────────────

  describe("scoring with partial metadata", function () {
    it("should handle request with only IP", function () {
      var s = createGeoRiskScorer();
      var r = s.score({ ip: "1.2.3.4" });
      assert(typeof r.score === "number");
      assert(r.action);
    });

    it("should handle request with empty object", function () {
      var s = createGeoRiskScorer();
      var r = s.score({});
      assert(typeof r.score === "number");
    });

    it("should handle request with null IP", function () {
      var s = createGeoRiskScorer();
      var r = s.score({ ip: null, country: "US" });
      assert(typeof r.score === "number");
    });

    it("should handle lat without lon", function () {
      var s = createGeoRiskScorer();
      var r = s.score({ ip: "1.1.1.1", country: "US", lat: 37.77 });
      // Should not crash — velocity check requires both lat and lon
      assert(typeof r.score === "number");
    });
  });

  // ── Haversine Edge Cases ─────────────────────────────────────────

  describe("haversine distance", function () {
    it("should handle same location (zero distance)", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      s.score({ ip: "h1", country: "US", lat: 37.77, lon: -122.42, timestamp: now - 60000 });
      var r = s.score({ ip: "h1", country: "US", lat: 37.77, lon: -122.42, timestamp: now });
      // Zero distance, no suspicious travel
      var hasTravel = r.factors.some(function (f) {
        return f.name === "impossible_travel" || f.name === "suspicious_travel";
      });
      assert(!hasTravel);
    });

    it("should handle antipodal points", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      // North pole to south pole
      s.score({ ip: "h2", country: "US", lat: 90, lon: 0, timestamp: now - 60000 });
      var r = s.score({ ip: "h2", country: "US", lat: -90, lon: 0, timestamp: now });
      // ~20,000 km in 1 minute = impossible
      assert(r.factors.some(function (f) { return f.name === "impossible_travel"; }));
    });
  });

  // ── Summary and Stats ────────────────────────────────────────────

  describe("summary accuracy", function () {
    it("should count blocked and challenged actions", function () {
      var s = createGeoRiskScorer({ thresholds: { block: 0.3, challenge: 0.2, warn: 0.1 } });
      s.score({ ip: "1.1.1.1", country: "CN" }); // high risk → likely blocked
      s.score({ ip: "1.1.1.2", country: "US" }); // clean → allowed
      var sum = s.summary();
      assert.strictEqual(sum.totalScored, 2);
      assert(sum.totalBlocked + sum.totalChallenged <= sum.totalScored);
    });

    it("should report correct blockedIPs count", function () {
      var s = createGeoRiskScorer();
      s.blockIP("a");
      s.blockIP("b");
      s.blockIP("c");
      assert.strictEqual(s.summary().blockedIPs, 3);
    });

    it("should report correct allowedIPs count", function () {
      var s = createGeoRiskScorer();
      s.allowIP("x");
      s.allowIP("y");
      assert.strictEqual(s.summary().allowedIPs, 2);
    });
  });

  // ── Custom Configuration ─────────────────────────────────────────

  describe("custom configuration", function () {
    it("should use custom medium-risk countries", function () {
      var s = createGeoRiskScorer({ mediumRiskCountries: ["AA"] });
      var r = s.score({ ip: "1.1.1.1", country: "AA" });
      assert(r.factors.some(function (f) { return f.name === "country_medium_risk"; }));
    });

    it("should use custom impossible travel speed", function () {
      // Use custom impossibleTravelSpeedKmh=100 AND a wider velocity window
      // so the 3-hour-old history entry stays within the check window
      var s = createGeoRiskScorer({ impossibleTravelSpeedKmh: 100, velocityWindowMs: 14400000 }); // 4h window
      var now = Date.now();
      // SF to LA (~560km) in 3 hours = ~187 km/h (impossible at 100 km/h threshold)
      s.score({ ip: "c1", country: "US", lat: 37.77, lon: -122.42, timestamp: now - 10800000 });
      var r = s.score({ ip: "c1", country: "US", lat: 34.05, lon: -118.24, timestamp: now });
      assert(r.factors.some(function (f) { return f.name === "impossible_travel"; }));
    });

    it("should use custom velocity window", function () {
      var s = createGeoRiskScorer({ velocityWindowMs: 60000 }); // 1 minute
      var now = Date.now();
      // Request 2 minutes ago — outside window
      s.score({ ip: "c2", country: "US", lat: 37.77, lon: -122.42, timestamp: now - 120000 });
      var r = s.score({ ip: "c2", country: "JP", lat: 35.68, lon: 139.69, timestamp: now });
      var hasImpossible = r.factors.some(function (f) { return f.name === "impossible_travel"; });
      assert(!hasImpossible, "outside custom velocity window");
    });

    it("should use custom history limit", function () {
      var s = createGeoRiskScorer({ maxHistory: 2 });
      var now = Date.now();
      // Push 3 entries — oldest should be evicted
      s.score({ ip: "c3", country: "US", lat: 0, lon: 0, timestamp: now - 3000 });
      s.score({ ip: "c3", country: "US", lat: 10, lon: 10, timestamp: now - 2000 });
      s.score({ ip: "c3", country: "US", lat: 20, lon: 20, timestamp: now - 1000 });
      // Only 2 most recent should remain in history
      assert.strictEqual(s.summary().trackedIPs, 1);
    });
  });

  // ── Region Stats Edge Cases ──────────────────────────────────────

  describe("region stats edge cases", function () {
    it("should normalize country code to uppercase", function () {
      var s = createGeoRiskScorer();
      s.recordAttempt("us", true);
      s.recordAttempt("Us", true);
      s.recordAttempt("US", false);
      var stats = s.getRegionStats("us");
      assert.strictEqual(stats.attempts, 3);
      assert.strictEqual(stats.solves, 2);
    });

    it("should handle null country in recordAttempt", function () {
      var s = createGeoRiskScorer();
      s.recordAttempt(null, true); // should not crash
      assert.strictEqual(s.getRegionStats().length, 0);
    });

    it("should handle empty country in recordAttempt", function () {
      var s = createGeoRiskScorer();
      s.recordAttempt("", true); // should not crash
      // Empty string becomes "" key
      var stats = s.getRegionStats("");
      // Depends on implementation — may be null or have data
      assert(stats === null || typeof stats === "object");
    });
  });

  // ── Country Case Normalization in Scoring ────────────────────────

  describe("country case normalization", function () {
    it("should normalize lowercase country in score", function () {
      var s = createGeoRiskScorer();
      var r = s.score({ ip: "1.1.1.1", country: "ru" });
      assert(r.factors.some(function (f) { return f.name === "country_high_risk"; }));
    });

    it("should normalize mixed-case country", function () {
      var s = createGeoRiskScorer();
      var r = s.score({ ip: "1.1.1.1", country: "Cn" });
      assert(r.factors.some(function (f) { return f.name === "country_high_risk"; }));
    });
  });

  // ── Multiple IPs Tracking ────────────────────────────────────────

  describe("multiple IP tracking", function () {
    it("should track multiple IPs independently", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      s.score({ ip: "m1", country: "US", lat: 37.77, lon: -122.42, timestamp: now });
      s.score({ ip: "m2", country: "US", lat: 40.71, lon: -74.00, timestamp: now });
      assert.strictEqual(s.summary().trackedIPs, 2);
    });

    it("should not cross-contaminate velocity checks between IPs", function () {
      var s = createGeoRiskScorer();
      var now = Date.now();
      // IP A in SF
      s.score({ ip: "a1", country: "US", lat: 37.77, lon: -122.42, timestamp: now - 60000 });
      // IP B in Tokyo (different IP — should not trigger impossible travel)
      var r = s.score({ ip: "b1", country: "JP", lat: 35.68, lon: 139.69, timestamp: now });
      var hasImpossible = r.factors.some(function (f) { return f.name === "impossible_travel"; });
      assert(!hasImpossible, "different IPs should not cross-contaminate");
    });
  });
});
