"use strict";

var assert = require("assert");
var mod = require("../src/geo-risk-scorer");
var createGeoRiskScorer = mod.createGeoRiskScorer;

describe("GeoRiskScorer — bounded memory (issue #25)", function () {
  it("should evict oldest IPs when maxTrackedIPs is exceeded", function () {
    var s = createGeoRiskScorer({ maxTrackedIPs: 5 });
    for (var i = 1; i <= 10; i++) {
      s.score({ ip: "10.0.0." + i, country: "US", lat: 37 + i * 0.01, lon: -122 });
    }
    var sum = s.summary();
    assert(sum.trackedIPs <= 5, "trackedIPs should be capped at 5, got " + sum.trackedIPs);
  });

  it("should evict oldest sessions when maxTrackedSessions is exceeded", function () {
    var s = createGeoRiskScorer({ maxTrackedSessions: 3 });
    for (var i = 1; i <= 8; i++) {
      s.score({ ip: "1.1.1.1", country: "US", sessionId: "sess-" + i });
    }
    var sum = s.summary();
    assert(sum.trackedSessions <= 3, "trackedSessions should be capped at 3, got " + sum.trackedSessions);
  });

  it("should expire blocked IPs after TTL", function () {
    var s = createGeoRiskScorer({ blocklistTTLMs: 1 }); // 1ms TTL
    s.blockIP("9.9.9.9");
    // Wait a tiny bit for expiry
    var start = Date.now();
    while (Date.now() - start < 5) { /* spin */ }
    assert(!s.isBlocked("9.9.9.9"), "blocked IP should have expired");
  });

  it("should expire allowed IPs after TTL", function () {
    var s = createGeoRiskScorer({ blocklistTTLMs: 1 });
    s.allowIP("8.8.8.8");
    var start = Date.now();
    while (Date.now() - start < 5) { /* spin */ }
    assert(!s.isAllowed("8.8.8.8"), "allowed IP should have expired");
  });

  it("should not short-circuit on expired blocklist entry", function () {
    var s = createGeoRiskScorer({ blocklistTTLMs: 1 });
    s.blockIP("6.6.6.6");
    var start = Date.now();
    while (Date.now() - start < 5) { /* spin */ }
    var r = s.score({ ip: "6.6.6.6", country: "US" });
    assert(r.score < 1, "expired blocklist should not trigger block");
    assert.strictEqual(r.action, "allow");
  });

  it("should cap blocked IPs at maxBlockedIPs", function () {
    var s = createGeoRiskScorer({ maxBlockedIPs: 5, blocklistTTLMs: 60000 });
    for (var i = 0; i < 10; i++) {
      s.blockIP("10.10.10." + i);
    }
    var sum = s.summary();
    assert(sum.blockedIPs <= 5, "blockedIPs should be capped at 5, got " + sum.blockedIPs);
  });

  it("should expose cleanup() method", function () {
    var s = createGeoRiskScorer({ maxTrackedIPs: 2 });
    for (var i = 1; i <= 5; i++) {
      s.score({ ip: "10.0.0." + i, country: "US", lat: 37, lon: -122 });
    }
    s.cleanup();
    assert(s.summary().trackedIPs <= 2);
  });

  it("should accept custom TTL per blockIP/allowIP call", function () {
    var s = createGeoRiskScorer({ blocklistTTLMs: 60000 });
    s.blockIP("5.5.5.5", 1); // 1ms override
    var start = Date.now();
    while (Date.now() - start < 5) { /* spin */ }
    assert(!s.isBlocked("5.5.5.5"), "per-call TTL should override default");
  });

  it("should keep most recent IPs during eviction", function () {
    var s = createGeoRiskScorer({ maxTrackedIPs: 3 });
    var now = Date.now();
    // Score 5 IPs in order
    for (var i = 1; i <= 5; i++) {
      s.score({ ip: "10.0.0." + i, country: "US", lat: 37, lon: -122, timestamp: now + i * 1000 });
    }
    // IP .5 should still be tracked (most recent)
    // Score from .5 again - it should have history
    var r = s.score({ ip: "10.0.0.5", country: "US", lat: 37.01, lon: -122, timestamp: now + 6000 });
    // If properly tracked, velocity check should work (no impossible travel for small move)
    assert(r.score < 1, "should not be fully blocked for small movement");
  });
});
