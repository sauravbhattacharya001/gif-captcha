/**
 * Tests for captcha-stats-collector.js
 */

"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { createStatsCollector, percentile } = require("../src/captcha-stats-collector");

describe("percentile()", () => {
  it("returns null for empty array", () => {
    assert.equal(percentile([], 50), null);
  });

  it("returns the single element for length-1 array", () => {
    assert.equal(percentile([42], 50), 42);
    assert.equal(percentile([42], 99), 42);
  });

  it("computes p50 (median) correctly", () => {
    assert.equal(percentile([1, 2, 3, 4, 5], 50), 3);
  });

  it("interpolates between values", () => {
    const result = percentile([10, 20, 30, 40], 25);
    assert.equal(result, 17.5);
  });

  it("returns min at p0 and max at p100", () => {
    assert.equal(percentile([5, 10, 15], 0), 5);
    assert.equal(percentile([5, 10, 15], 100), 15);
  });
});

describe("createStatsCollector()", () => {
  let stats;

  beforeEach(() => {
    stats = createStatsCollector({ windowMs: 1000, maxWindows: 5 });
  });

  describe("record()", () => {
    it("throws on missing object", () => {
      assert.throws(() => stats.record(null), /requires an object/);
      assert.throws(() => stats.record("bad"), /requires an object/);
    });

    it("throws on missing solved boolean", () => {
      assert.throws(() => stats.record({ solved: 1, timeMs: 100 }), /solved to be a boolean/);
    });

    it("throws on missing or negative timeMs", () => {
      assert.throws(() => stats.record({ solved: true, timeMs: -1 }), /timeMs/);
      assert.throws(() => stats.record({ solved: true, timeMs: "fast" }), /timeMs/);
    });

    it("records a valid entry", () => {
      stats.record({ solved: true, timeMs: 500 });
      const s = stats.summary();
      assert.equal(s.total, 1);
      assert.equal(s.solved, 1);
    });
  });

  describe("summary()", () => {
    it("returns null when no records exist", () => {
      assert.equal(stats.summary(), null);
    });

    it("returns current window stats", () => {
      const now = Date.now();
      stats.record({ solved: true, timeMs: 200, timestamp: now });
      stats.record({ solved: true, timeMs: 400, timestamp: now + 1 });
      stats.record({ solved: false, timeMs: 5000, timestamp: now + 2 });

      const s = stats.summary();
      assert.equal(s.total, 3);
      assert.equal(s.solved, 2);
      assert.equal(s.failed, 1);
      assert.equal(s.solveRate, 66.67);
      assert.equal(s.timing.count, 2);
      assert.equal(s.timing.min, 200);
      assert.equal(s.timing.max, 400);
    });

    it("includes per-type breakdown", () => {
      const now = Date.now();
      stats.record({ solved: true, timeMs: 100, challengeType: "sequence", timestamp: now });
      stats.record({ solved: false, timeMs: 300, challengeType: "pattern", timestamp: now + 1 });

      const s = stats.summary();
      assert.ok(s.byType.sequence);
      assert.equal(s.byType.sequence.solved, 1);
      assert.ok(s.byType.pattern);
      assert.equal(s.byType.pattern.failed, 1);
    });
  });

  describe("report()", () => {
    it("aggregates across windows", () => {
      const base = 1000000;
      // Window 1
      stats.record({ solved: true, timeMs: 100, timestamp: base });
      stats.record({ solved: true, timeMs: 200, timestamp: base + 100 });
      // Window 2 (1 second later)
      stats.record({ solved: false, timeMs: 800, timestamp: base + 1500 });

      const r = stats.report();
      assert.equal(r.windowCount, 2);
      assert.equal(r.aggregate.total, 3);
      assert.equal(r.aggregate.solved, 2);
      assert.equal(r.aggregate.failed, 1);
      assert.equal(r.windows.length, 2);
    });

    it("tracks lifetime across resets of windows", () => {
      // Fill more than maxWindows (5)
      for (let i = 0; i < 7; i++) {
        stats.record({ solved: true, timeMs: 50, timestamp: i * 1000 });
      }
      const r = stats.report();
      assert.equal(r.lifetime.total, 7);
      assert.equal(r.lifetime.solved, 7);
      assert.ok(r.windowCount <= 5);
    });
  });

  describe("exportCSV()", () => {
    it("produces valid CSV header and rows", () => {
      const now = Date.now();
      stats.record({ solved: true, timeMs: 150, timestamp: now });
      const csv = stats.exportCSV();
      const lines = csv.split("\n");
      assert.equal(lines.length, 2); // header + 1 row
      assert.ok(lines[0].startsWith("window_start"));
      assert.ok(lines[1].includes("150")); // mean/p50 should be 150
    });

    it("returns header only when empty", () => {
      const csv = stats.exportCSV();
      assert.equal(csv.split("\n").length, 1);
    });
  });

  describe("exportJSON()", () => {
    it("produces valid JSON", () => {
      stats.record({ solved: true, timeMs: 300 });
      const json = stats.exportJSON();
      const parsed = JSON.parse(json);
      assert.equal(parsed.aggregate.total, 1);
    });
  });

  describe("reset()", () => {
    it("clears all data", () => {
      stats.record({ solved: true, timeMs: 100 });
      stats.reset();
      assert.equal(stats.summary(), null);
      assert.equal(stats.windowCount(), 0);
      const r = stats.report();
      assert.equal(r.lifetime.total, 0);
    });
  });

  describe("windowCount()", () => {
    it("returns 0 initially", () => {
      assert.equal(stats.windowCount(), 0);
    });

    it("increases with records in different windows", () => {
      stats.record({ solved: true, timeMs: 100, timestamp: 1000 });
      stats.record({ solved: true, timeMs: 100, timestamp: 2500 });
      assert.equal(stats.windowCount(), 2);
    });
  });

  describe("window eviction", () => {
    it("respects maxWindows limit", () => {
      for (let i = 0; i < 10; i++) {
        stats.record({ solved: true, timeMs: 50, timestamp: i * 1000 });
      }
      assert.ok(stats.windowCount() <= 5);
    });
  });

  describe("default challengeType", () => {
    it("uses _default when no challengeType given", () => {
      stats.record({ solved: true, timeMs: 200 });
      const s = stats.summary();
      assert.ok(s.byType._default);
      assert.equal(s.byType._default.total, 1);
    });
  });

  describe("custom percentiles", () => {
    it("uses configured percentiles", () => {
      const custom = createStatsCollector({ percentiles: [25, 75] });
      custom.record({ solved: true, timeMs: 100 });
      custom.record({ solved: true, timeMs: 200 });
      custom.record({ solved: true, timeMs: 300 });
      const s = custom.summary();
      assert.ok("p25" in s.timing.percentiles);
      assert.ok("p75" in s.timing.percentiles);
      assert.ok(!("p50" in s.timing.percentiles));
    });
  });
});
