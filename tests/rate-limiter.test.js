var { describe, it, beforeEach } = require("node:test");
var assert = require("node:assert/strict");
var { createRateLimiter } = require("../src/index");

describe("createRateLimiter", function () {
  var limiter;

  beforeEach(function () {
    limiter = createRateLimiter({
      windowMs: 10000,
      maxRequests: 5,
      burstThreshold: 3,
      burstWindowMs: 1000,
      baseDelay: 500,
      maxDelay: 10000,
      maxClients: 100,
    });
  });

  describe("basic rate limiting", function () {
    it("should allow requests under the limit", function () {
      var result = limiter.check("client1", { now: 1000 });
      assert.equal(result.allowed, true);
      assert.equal(result.reason, "ok");
      assert.equal(result.remaining, 4);
    });

    it("should allow exactly maxRequests when spread out", function () {
      for (var i = 0; i < 5; i++) {
        var result = limiter.check("client1", { now: 1000 + i * 2000 });
        assert.equal(result.allowed, true);
      }
    });

    it("should block after maxRequests exceeded", function () {
      for (var i = 0; i < 5; i++) {
        limiter.check("client1", { now: 1000 + i * 2000 });
      }
      var result = limiter.check("client1", { now: 10000 });
      assert.equal(result.allowed, false);
      assert.equal(result.remaining, 0);
    });

    it("should allow again after window expires", function () {
      for (var i = 0; i < 5; i++) {
        limiter.check("client1", { now: 1000 });
      }
      // After window
      var result = limiter.check("client1", { now: 12000 });
      assert.equal(result.allowed, true);
    });

    it("should track clients independently", function () {
      for (var i = 0; i < 5; i++) {
        limiter.check("client1", { now: 1000 });
      }
      var r1 = limiter.check("client1", { now: 1100 });
      var r2 = limiter.check("client2", { now: 1100 });
      assert.equal(r1.allowed, false);
      assert.equal(r2.allowed, true);
    });

    it("remaining should decrease with each request", function () {
      // Spread out to avoid burst
      assert.equal(limiter.check("c1", { now: 1000 }).remaining, 4);
      assert.equal(limiter.check("c1", { now: 3000 }).remaining, 3);
      assert.equal(limiter.check("c1", { now: 5000 }).remaining, 2);
      assert.equal(limiter.check("c1", { now: 7000 }).remaining, 1);
      assert.equal(limiter.check("c1", { now: 9000 }).remaining, 0);
    });
  });

  describe("sliding window behavior", function () {
    it("should allow after oldest timestamps expire", function () {
      // 5 requests spread out to avoid burst
      for (var i = 0; i < 5; i++) {
        limiter.check("c1", { now: i * 2000 });
      }
      // At t=10001, first request (t=0) should have expired (0 <= 10001-10000=10001? 0 <= 1 yes)
      var r = limiter.check("c1", { now: 10001 });
      assert.equal(r.allowed, true);
    });

    it("should expire old timestamps as window slides", function () {
      limiter.check("c1", { now: 0 });
      limiter.check("c1", { now: 5000 });
      limiter.check("c1", { now: 9000 });
      // At t=10001, first (t=0) pruned (0 <= 10001-10000=1, yes). t=5000 and t=9000 remain
      var p = limiter.peek("c1", { now: 10001 });
      assert.equal(p.count, 2);
    });
  });

  describe("burst detection", function () {
    it("should detect burst within burst window", function () {
      // 3 requests in 1s = burst
      limiter.check("c1", { now: 1000 });
      limiter.check("c1", { now: 1100 });
      var result = limiter.check("c1", { now: 1200 });
      // 3rd request: before check, 2 timestamps exist. burstCount of those 2 in last 1000ms = 2.
      // Then we add 3rd. But burst is checked before adding.
      // Actually burstCount checks existing timestamps before adding the new one.
      // So at 3rd check: existing = [1000, 1100], burstCount in last 1000ms from now=1200 = 2
      // 2 < 3 (burstThreshold), not burst yet
      // Need 4th to trigger? No - let me re-read the code
      // burstCount checks BEFORE adding. So we need burstThreshold existing timestamps in burst window
      // to trigger. So need 3 existing = 4th call triggers it.
      assert.equal(result.allowed, true); // not burst yet
      var result2 = limiter.check("c1", { now: 1300 });
      // existing = [1000, 1100, 1200], all in last 1000ms, burstCount=3 >= 3
      assert.equal(result2.burst, true);
    });

    it("should not detect burst if spread out", function () {
      limiter.check("c1", { now: 0 });
      limiter.check("c1", { now: 2000 });
      limiter.check("c1", { now: 4000 });
      var result = limiter.check("c1", { now: 6000 });
      assert.equal(result.burst, false);
    });
  });

  describe("progressive delay", function () {
    it("should return 0 delay when under limit", function () {
      var result = limiter.check("c1", { now: 1000 });
      assert.equal(result.delay, 0);
    });

    it("should return increasing delay as overage grows", function () {
      for (var i = 0; i < 5; i++) {
        limiter.check("c1", { now: 1000 + i });
      }
      // 6th request: overage=1, delay = 500 * 2^0 = 500
      var r1 = limiter.check("c1", { now: 1010 });
      assert.equal(r1.delay, 500);

      // 7th: overage=2, delay = 500 * 2^1 = 1000
      var r2 = limiter.check("c1", { now: 1020 });
      assert.equal(r2.delay, 1000);

      // 8th: overage=3, delay = 500 * 2^2 = 2000
      var r3 = limiter.check("c1", { now: 1030 });
      assert.equal(r3.delay, 2000);
    });

    it("should cap delay at maxDelay", function () {
      for (var i = 0; i < 20; i++) {
        limiter.check("c1", { now: 1000 + i });
      }
      var result = limiter.check("c1", { now: 1100 });
      assert.ok(result.delay <= 10000);
    });
  });

  describe("allowlist", function () {
    it("should always allow allowlisted clients", function () {
      limiter.allow("vip");
      for (var i = 0; i < 20; i++) {
        var result = limiter.check("vip", { now: 1000 + i });
        assert.equal(result.allowed, true);
        assert.equal(result.reason, "allowlisted");
      }
    });

    it("should allow adding multiple via array", function () {
      limiter.allow(["vip1", "vip2"]);
      assert.equal(limiter.check("vip1", { now: 1000 }).allowed, true);
      assert.equal(limiter.check("vip2", { now: 1000 }).allowed, true);
    });
  });

  describe("blocklist", function () {
    it("should always block blocklisted clients", function () {
      limiter.block("bad");
      var result = limiter.check("bad", { now: 1000 });
      assert.equal(result.allowed, false);
      assert.equal(result.reason, "blocklisted");
    });

    it("should remove from allowlist when blocklisted", function () {
      limiter.allow("c1");
      limiter.block("c1");
      assert.equal(limiter.check("c1", { now: 1000 }).allowed, false);
    });

    it("should remove from blocklist when allowlisted", function () {
      limiter.block("c1");
      limiter.allow("c1");
      assert.equal(limiter.check("c1", { now: 1000 }).allowed, true);
    });
  });

  describe("unlist", function () {
    it("should remove from both lists", function () {
      limiter.allow("c1");
      limiter.unlist("c1");
      // Now subject to normal limiting
      for (var i = 0; i < 6; i++) {
        limiter.check("c1", { now: 1000 + i });
      }
      var result = limiter.check("c1", { now: 1100, dryRun: true });
      assert.equal(result.allowed, false);
    });
  });

  describe("peek", function () {
    it("should return status without recording", function () {
      limiter.check("c1", { now: 1000 });
      limiter.check("c1", { now: 1001 });
      var p = limiter.peek("c1", { now: 1002 });
      assert.equal(p.count, 2);
      assert.equal(p.remaining, 3);
      assert.equal(p.limited, false);
      // Peek again - count should still be 2
      var p2 = limiter.peek("c1", { now: 1003 });
      assert.equal(p2.count, 2);
    });

    it("should return empty for unknown client", function () {
      var p = limiter.peek("unknown");
      assert.equal(p.count, 0);
      assert.equal(p.remaining, 5);
    });

    it("should handle allowlisted client", function () {
      limiter.allow("vip");
      var p = limiter.peek("vip");
      assert.equal(p.limited, false);
    });

    it("should handle blocklisted client", function () {
      limiter.block("bad");
      var p = limiter.peek("bad");
      assert.equal(p.limited, true);
    });
  });

  describe("dryRun", function () {
    it("should not record attempt in dry run", function () {
      limiter.check("c1", { now: 1000, dryRun: true });
      var p = limiter.peek("c1", { now: 1001 });
      assert.equal(p.count, 0);
    });
  });

  describe("resetClient", function () {
    it("should clear client state", function () {
      for (var i = 0; i < 5; i++) {
        limiter.check("c1", { now: 1000 + i });
      }
      limiter.resetClient("c1");
      var p = limiter.peek("c1");
      assert.equal(p.count, 0);
      var r = limiter.check("c1", { now: 2000 });
      assert.equal(r.allowed, true);
    });

    it("should handle resetting unknown client", function () {
      limiter.resetClient("nonexistent"); // should not throw
    });
  });

  describe("checkBatch", function () {
    it("should check multiple clients at once", function () {
      for (var i = 0; i < 6; i++) {
        limiter.check("c1", { now: 1000 + i });
      }
      var results = limiter.checkBatch(["c1", "c2"], { now: 2000 });
      assert.equal(results.c1.allowed, false);
      assert.equal(results.c2.allowed, true);
    });
  });

  describe("LRU eviction", function () {
    it("should evict oldest clients when over maxClients", function () {
      var small = createRateLimiter({ maxClients: 3, windowMs: 10000, maxRequests: 5 });
      small.check("a", { now: 1000 });
      small.check("b", { now: 2000 });
      small.check("c", { now: 3000 });
      small.check("d", { now: 4000 }); // should evict 'a'
      assert.equal(small.peek("a").count, 0); // evicted
      assert.equal(small.peek("b", { now: 4000 }).count, 1);
    });

    it("should update LRU order on access", function () {
      var small = createRateLimiter({ maxClients: 3, windowMs: 10000, maxRequests: 5 });
      small.check("a", { now: 1000 });
      small.check("b", { now: 2000 });
      small.check("c", { now: 3000 });
      small.check("a", { now: 3500 }); // touch 'a', now 'b' is oldest
      small.check("d", { now: 4000 }); // should evict 'b'
      assert.ok(small.peek("a", { now: 4000 }).count > 0);
      assert.equal(small.peek("b").count, 0); // evicted
    });
  });

  describe("stats", function () {
    it("should track stats correctly", function () {
      limiter.allow("vip");
      limiter.block("bad");

      limiter.check("c1", { now: 1000 }); // allowed
      limiter.check("vip", { now: 1000 }); // allowed (allowlist)
      limiter.check("bad", { now: 1000 }); // blocked

      var stats = limiter.getStats();
      assert.equal(stats.totalChecks, 3);
      assert.equal(stats.totalAllowed, 2);
      assert.equal(stats.totalBlocked, 1);
      assert.equal(stats.allowlistSize, 1);
      assert.equal(stats.blocklistSize, 1);
    });

    it("should track limit rate", function () {
      for (var i = 0; i < 5; i++) {
        limiter.check("c1", { now: 1000 + i });
      }
      limiter.check("c1", { now: 1100 }); // limited
      var stats = limiter.getStats();
      assert.ok(stats.limitRate > 0);
    });

    it("should track burst count", function () {
      // Trigger burst: need 3 existing timestamps in burstWindow
      limiter.check("c1", { now: 1000 });
      limiter.check("c1", { now: 1100 });
      limiter.check("c1", { now: 1200 });
      limiter.check("c1", { now: 1300 }); // burst detected
      var stats = limiter.getStats();
      assert.ok(stats.totalBursts >= 1);
    });
  });

  describe("topClients", function () {
    it("should return most active clients", function () {
      for (var i = 0; i < 4; i++) limiter.check("heavy", { now: 1000 + i });
      limiter.check("light", { now: 1000 });

      var top = limiter.topClients(2, { now: 2000 });
      assert.equal(top.length, 2);
      assert.equal(top[0].clientId, "heavy");
      assert.equal(top[0].count, 4);
    });

    it("should default to 10", function () {
      limiter.check("c1", { now: 1000 });
      var top = limiter.topClients(undefined, { now: 2000 });
      assert.ok(Array.isArray(top));
    });
  });

  describe("export/import", function () {
    it("should round-trip state", function () {
      limiter.allow("vip");
      limiter.block("bad");
      limiter.check("c1", { now: 1000 });
      limiter.check("c1", { now: 1001 });

      var state = limiter.exportState();
      assert.ok(state.clients.c1);
      assert.deepEqual(state.allowlist, ["vip"]);
      assert.deepEqual(state.blocklist, ["bad"]);

      var limiter2 = createRateLimiter({ windowMs: 10000, maxRequests: 5 });
      limiter2.importState(state);

      assert.equal(limiter2.check("vip", { now: 2000 }).reason, "allowlisted");
      assert.equal(limiter2.check("bad", { now: 2000 }).reason, "blocklisted");
      var p = limiter2.peek("c1", { now: 2000 });
      assert.equal(p.count, 2);
    });

    it("should handle null/invalid import gracefully", function () {
      limiter.importState(null);
      limiter.importState("invalid");
      limiter.importState({});
    });
  });

  describe("reset", function () {
    it("should clear all state", function () {
      limiter.check("c1", { now: 1000 });
      limiter.allow("vip");
      limiter.reset();
      var stats = limiter.getStats();
      assert.equal(stats.totalChecks, 0);
      assert.equal(stats.activeClients, 0);
    });
  });

  describe("getConfig", function () {
    it("should return configuration", function () {
      var config = limiter.getConfig();
      assert.equal(config.windowMs, 10000);
      assert.equal(config.maxRequests, 5);
      assert.equal(config.burstThreshold, 3);
    });
  });

  describe("default options", function () {
    it("should work with no options", function () {
      var def = createRateLimiter();
      var config = def.getConfig();
      assert.equal(config.windowMs, 60000);
      assert.equal(config.maxRequests, 10);
      assert.equal(config.burstThreshold, 5);
      assert.equal(config.burstWindowMs, 5000);
      assert.equal(config.maxDelay, 30000);
      assert.equal(config.baseDelay, 1000);
      assert.equal(config.maxClients, 10000);
    });
  });

  describe("retryAfter", function () {
    it("should be 0 when allowed", function () {
      var result = limiter.check("c1", { now: 1000 });
      assert.equal(result.retryAfter, 0);
    });

    it("should be positive when limited", function () {
      for (var i = 0; i < 6; i++) {
        limiter.check("c1", { now: 1000 + i });
      }
      var result = limiter.check("c1", { now: 1100, dryRun: true });
      assert.ok(result.retryAfter > 0);
    });
  });

  describe("resetMs", function () {
    it("should indicate when window resets", function () {
      limiter.check("c1", { now: 5000 });
      var result = limiter.check("c1", { now: 8000 });
      // Oldest timestamp at 5000, window=10000, reset at 15000, from now=8000 => 7000ms
      assert.ok(result.resetMs > 0);
    });
  });

  describe("edge cases", function () {
    it("should handle empty clientId", function () {
      var result = limiter.check("", { now: 1000 });
      assert.equal(result.allowed, true);
    });

    it("should handle concurrent timestamps", function () {
      for (var i = 0; i < 5; i++) {
        limiter.check("c1", { now: 1000 }); // all same time
      }
      var result = limiter.check("c1", { now: 1000 });
      assert.equal(result.allowed, false);
    });
  });
});
