var { describe, it, beforeEach } = require("node:test");
var assert = require("node:assert/strict");
var { createAuditTrail } = require("../src/index");

describe("createAuditTrail", function () {
  var trail;

  beforeEach(function () {
    trail = createAuditTrail();
  });

  // ── Initialization ─────────────────────────────────────

  describe("initialization", function () {
    it("should start with empty stats", function () {
      var stats = trail.getStats();
      assert.equal(stats.totalLogged, 0);
      assert.equal(stats.currentSize, 0);
      assert.equal(stats.maxEntries, 10000);
      assert.equal(stats.evictedCount, 0);
      assert.equal(stats.oldestTimestamp, null);
      assert.equal(stats.newestTimestamp, null);
    });

    it("should have EVENT_TYPES array", function () {
      assert.ok(Array.isArray(trail.EVENT_TYPES));
      assert.ok(trail.EVENT_TYPES.length >= 15);
      assert.ok(trail.EVENT_TYPES.indexOf("challenge.solved") >= 0);
      assert.ok(trail.EVENT_TYPES.indexOf("bot.detected") >= 0);
    });
  });

  // ── Recording Events ───────────────────────────────────

  describe("record()", function () {
    it("should record a basic event", function () {
      var entry = trail.record("challenge.created", { challengeId: "abc" });
      assert.equal(entry.type, "challenge.created");
      assert.equal(entry.id, 1);
      assert.equal(entry.data.challengeId, "abc");
      assert.equal(typeof entry.timestamp, "number");
    });

    it("should auto-increment IDs", function () {
      var e1 = trail.record("challenge.created");
      var e2 = trail.record("challenge.served");
      assert.equal(e1.id, 1);
      assert.equal(e2.id, 2);
    });

    it("should attach metadata when provided", function () {
      var entry = trail.record("challenge.solved", { score: 100 }, {
        clientId: "client1",
        sessionId: "sess1",
        ip: "1.2.3.4",
        userAgent: "Mozilla/5.0",
      });
      assert.equal(entry.meta.clientId, "client1");
      assert.equal(entry.meta.sessionId, "sess1");
      assert.equal(entry.meta.ip, "1.2.3.4");
      assert.equal(entry.meta.userAgent, "Mozilla/5.0");
    });

    it("should include extra meta fields", function () {
      var entry = trail.record("bot.detected", null, {
        clientId: "c1",
        customField: "custom-value",
      });
      assert.equal(entry.meta.clientId, "c1");
      assert.equal(entry.meta.customField, "custom-value");
    });

    it("should reject empty type", function () {
      assert.equal(trail.record(""), null);
    });

    it("should reject null type", function () {
      assert.equal(trail.record(null), null);
    });

    it("should reject numeric type", function () {
      assert.equal(trail.record(42), null);
    });

    it("should work without data or meta", function () {
      var entry = trail.record("config.changed");
      assert.equal(entry.type, "config.changed");
      assert.equal(entry.data, null);
    });

    it("should update type counts", function () {
      trail.record("challenge.created");
      trail.record("challenge.created");
      trail.record("challenge.solved");
      var stats = trail.getStats();
      assert.equal(stats.typeCounts["challenge.created"], 2);
      assert.equal(stats.typeCounts["challenge.solved"], 1);
    });

    it("should fire onEvent callback", function () {
      var events = [];
      var trail2 = createAuditTrail({
        onEvent: function (e) { events.push(e); },
      });
      trail2.record("challenge.created");
      trail2.record("bot.detected");
      assert.equal(events.length, 2);
      assert.equal(events[0].type, "challenge.created");
    });

    it("should swallow callback errors", function () {
      var trail2 = createAuditTrail({
        onEvent: function () { throw new Error("boom"); },
      });
      var entry = trail2.record("challenge.created");
      assert.ok(entry);
    });

    it("should not include metadata when includeMetadata=false", function () {
      var trail2 = createAuditTrail({ includeMetadata: false });
      var entry = trail2.record("challenge.created", null, { clientId: "c1" });
      assert.equal(entry.meta, undefined);
    });
  });

  // ── Enabled Types Filter ───────────────────────────────

  describe("enabledTypes filter", function () {
    it("should only record enabled types", function () {
      var trail2 = createAuditTrail({
        enabledTypes: ["challenge.solved", "bot.detected"],
      });
      var e1 = trail2.record("challenge.created");
      var e2 = trail2.record("challenge.solved");
      var e3 = trail2.record("bot.detected");
      assert.equal(e1, null);
      assert.equal(e2.type, "challenge.solved");
      assert.equal(e3.type, "bot.detected");
      assert.equal(trail2.getStats().currentSize, 2);
    });
  });

  // ── Ring Buffer Eviction ───────────────────────────────

  describe("ring buffer", function () {
    it("should evict oldest when exceeding maxEntries", function () {
      var trail2 = createAuditTrail({ maxEntries: 5 });
      for (var i = 0; i < 8; i++) {
        trail2.record("challenge.created", { idx: i });
      }
      var stats = trail2.getStats();
      assert.equal(stats.currentSize, 5);
      assert.equal(stats.evictedCount, 3);
      assert.equal(stats.totalLogged, 8);

      var entries = trail2.recent(5);
      assert.equal(entries[4].data.idx, 3);
      assert.equal(entries[0].data.idx, 7);
    });
  });

  // ── Query ──────────────────────────────────────────────

  describe("query()", function () {
    beforeEach(function () {
      trail.record("challenge.created", { id: 1 }, { clientId: "c1" });
      trail.record("challenge.served", { id: 1 }, { clientId: "c1" });
      trail.record("challenge.solved", { id: 1 }, { clientId: "c1", sessionId: "s1" });
      trail.record("bot.detected", { score: 0.9 }, { clientId: "c2" });
      trail.record("challenge.failed", { id: 2 }, { clientId: "c2" });
    });

    it("should return all when no filters", function () {
      var results = trail.query();
      assert.equal(results.length, 5);
    });

    it("should filter by exact type", function () {
      var results = trail.query({ type: "bot.detected" });
      assert.equal(results.length, 1);
      assert.equal(results[0].data.score, 0.9);
    });

    it("should filter by type prefix", function () {
      var results = trail.query({ typePrefix: "challenge." });
      assert.equal(results.length, 4);
    });

    it("should filter by clientId", function () {
      var results = trail.query({ clientId: "c2" });
      assert.equal(results.length, 2);
    });

    it("should filter by sessionId", function () {
      var results = trail.query({ sessionId: "s1" });
      assert.equal(results.length, 1);
      assert.equal(results[0].type, "challenge.solved");
    });

    it("should respect limit", function () {
      var results = trail.query({ limit: 2 });
      assert.equal(results.length, 2);
      assert.equal(results[0].type, "challenge.failed");
    });

    it("should return newest first", function () {
      var results = trail.query();
      assert.ok(results[0].id > results[1].id);
    });

    it("should combine filters", function () {
      var results = trail.query({ typePrefix: "challenge.", clientId: "c1" });
      assert.equal(results.length, 3);
    });
  });

  // ── Time-Based Queries ─────────────────────────────────

  describe("time-based queries", function () {
    it("should filter by since timestamp", function () {
      trail.record("challenge.created");
      // All entries so far have a timestamp <= Date.now()
      // Create a cutoff in the far future so only entries
      // after that time would match — there should be none.
      var results = trail.query({ since: Date.now() + 100000 });
      assert.equal(results.length, 0);
    });

    it("should filter by until timestamp", function () {
      trail.record("challenge.created");
      trail.record("challenge.solved");
      // Both were recorded at roughly the same time;
      // until=now+1 should include both
      var results = trail.query({ until: Date.now() + 1 });
      assert.equal(results.length, 2);

      // until=1 (epoch + 1ms) should include none since all entries are recent
      var none = trail.query({ until: 1 });
      assert.equal(none.length, 0);
    });
  });

  // ── Recent ─────────────────────────────────────────────

  describe("recent()", function () {
    it("should return last N entries newest first", function () {
      trail.record("challenge.created");
      trail.record("challenge.served");
      trail.record("challenge.solved");

      var r = trail.recent(2);
      assert.equal(r.length, 2);
      assert.equal(r[0].type, "challenge.solved");
      assert.equal(r[1].type, "challenge.served");
    });

    it("should default to 10", function () {
      for (var i = 0; i < 15; i++) {
        trail.record("challenge.created", { i: i });
      }
      var r = trail.recent();
      assert.equal(r.length, 10);
    });
  });

  // ── getById ────────────────────────────────────────────

  describe("getById()", function () {
    it("should find entry by ID", function () {
      trail.record("challenge.created");
      var e2 = trail.record("bot.detected", { score: 0.8 });
      trail.record("challenge.solved");

      var found = trail.getById(e2.id);
      assert.equal(found.type, "bot.detected");
      assert.equal(found.data.score, 0.8);
    });

    it("should return null for non-existent ID", function () {
      trail.record("challenge.created");
      assert.equal(trail.getById(999), null);
    });

    it("should return null for empty trail", function () {
      assert.equal(trail.getById(1), null);
    });
  });

  // ── countByType ────────────────────────────────────────

  describe("countByType()", function () {
    it("should return counts by event type", function () {
      trail.record("challenge.created");
      trail.record("challenge.created");
      trail.record("challenge.solved");
      trail.record("bot.detected");

      var counts = trail.countByType();
      assert.equal(counts["challenge.created"], 2);
      assert.equal(counts["challenge.solved"], 1);
      assert.equal(counts["bot.detected"], 1);
    });
  });

  // ── Timeline ───────────────────────────────────────────

  describe("timeline()", function () {
    it("should return empty for invalid params", function () {
      var t = trail.timeline({});
      assert.equal(t.buckets.length, 0);
    });

    it("should bucket events by time", function () {
      trail.record("challenge.created");
      trail.record("challenge.solved");
      trail.record("bot.detected");

      var t = trail.timeline({ bucketMs: 60000 });
      assert.ok(t.total > 0);
      assert.ok(t.buckets.length >= 1);
    });

    it("should filter by type", function () {
      trail.record("challenge.created");
      trail.record("challenge.solved");
      trail.record("bot.detected");

      var t = trail.timeline({ bucketMs: 60000, type: "bot.detected" });
      assert.equal(t.total, 1);
    });
  });

  // ── State Export/Import ────────────────────────────────

  describe("state persistence", function () {
    it("should export and import state", function () {
      trail.record("challenge.created", { id: 1 });
      trail.record("bot.detected", { score: 0.9 }, { clientId: "c1" });

      var exported = trail.exportState();
      var trail2 = createAuditTrail();
      trail2.importState(exported);

      var stats = trail2.getStats();
      assert.equal(stats.totalLogged, 2);
      assert.equal(stats.currentSize, 2);
      assert.equal(stats.typeCounts["challenge.created"], 1);
      assert.equal(stats.typeCounts["bot.detected"], 1);

      var found = trail2.getById(2);
      assert.equal(found.type, "bot.detected");
    });

    it("should handle null/invalid import", function () {
      trail.importState(null);
      trail.importState("invalid");
      trail.importState({});
      assert.equal(trail.getStats().totalLogged, 0);
    });

    it("should trim to maxEntries on import", function () {
      var big = createAuditTrail({ maxEntries: 100 });
      for (var i = 0; i < 50; i++) {
        big.record("challenge.created", { i: i });
      }
      var exported = big.exportState();

      var small = createAuditTrail({ maxEntries: 10 });
      small.importState(exported);
      assert.equal(small.getStats().currentSize, 10);
    });
  });

  // ── Reset ──────────────────────────────────────────────

  describe("reset()", function () {
    it("should clear all state", function () {
      trail.record("challenge.created");
      trail.record("bot.detected");
      trail.reset();

      var stats = trail.getStats();
      assert.equal(stats.totalLogged, 0);
      assert.equal(stats.currentSize, 0);
      assert.equal(stats.evictedCount, 0);
    });
  });

  // ── Edge Cases ─────────────────────────────────────────

  describe("edge cases", function () {
    it("should handle custom event types", function () {
      var entry = trail.record("custom.event", { foo: "bar" });
      assert.equal(entry.type, "custom.event");
    });

    it("should handle very large data objects", function () {
      var bigData = {};
      for (var i = 0; i < 100; i++) {
        bigData["key" + i] = "value" + i;
      }
      var entry = trail.record("challenge.created", bigData);
      assert.equal(Object.keys(entry.data).length, 100);
    });

    it("should track stats across evictions", function () {
      var small = createAuditTrail({ maxEntries: 3 });
      for (var i = 0; i < 10; i++) {
        small.record("challenge.created");
      }
      var stats = small.getStats();
      assert.equal(stats.totalLogged, 10);
      assert.equal(stats.currentSize, 3);
      assert.equal(stats.evictedCount, 7);
    });
  });
});
