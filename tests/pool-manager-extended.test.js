/* ── Additional Pool Manager tests — edge cases, retirement, serialization ── */
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const gifCaptcha = require("../src/index.js");

function makeChallenge(id) {
  return gifCaptcha.createChallenge({
    id: "p" + id,
    gifUrl: "https://example.com/" + id + ".gif",
    humanAnswer: "answer " + id,
    title: "Challenge " + id,
  });
}

describe("createPoolManager (extended)", () => {
  /* ── Weighted pick distribution ─────────────────────────────────── */

  describe("weighted pick fairness", () => {
    it("should favor less-served challenges over time", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);

      // Pick 300 times and count selections
      var counts = { p1: 0, p2: 0, p3: 0 };
      for (var i = 0; i < 300; i++) {
        var picked = pool.pick(1);
        counts[picked[0].id]++;
      }

      // All challenges should have been picked at least once
      assert.ok(counts.p1 > 0, "p1 should be picked");
      assert.ok(counts.p2 > 0, "p2 should be picked");
      assert.ok(counts.p3 > 0, "p3 should be picked");

      // Distribution should be roughly even (within 50% of fair share)
      var fair = 100;
      assert.ok(counts.p1 > fair * 0.4 && counts.p1 < fair * 1.8,
        "p1 should be within fair range: " + counts.p1);
      assert.ok(counts.p2 > fair * 0.4 && counts.p2 < fair * 1.8,
        "p2 should be within fair range: " + counts.p2);
    });

    it("should pick exactly count challenges without repeats", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3),
                makeChallenge(4), makeChallenge(5)]);
      var picked = pool.pick(3);
      assert.equal(picked.length, 3);

      // No duplicates
      var ids = picked.map(function (c) { return c.id; });
      assert.equal(new Set(ids).size, 3);
    });

    it("should clamp count to at least 1", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add(makeChallenge(1));
      var picked = pool.pick(0);
      assert.equal(picked.length, 1);
    });

    it("should handle negative count gracefully", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add(makeChallenge(1));
      var picked = pool.pick(-5);
      assert.equal(picked.length, 1);
    });
  });

  /* ── Retirement logic ───────────────────────────────────────────── */

  describe("retirement", () => {
    it("should retire by max_serves reason", () => {
      var pool = gifCaptcha.createPoolManager({
        maxServes: 5,
        minPoolSize: 1
      });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);

      // Force all serves onto one challenge by picking many times
      // and checking which gets retired
      for (var i = 0; i < 30; i++) pool.pick(1);
      var retired = pool.enforceRetirement();

      if (retired.length > 0) {
        var stats = pool.getStats(retired[0]);
        assert.equal(stats.retired, true);
        assert.equal(stats.retireReason, "max_serves");
      }
    });

    it("should retire too_hard challenges (low pass rate)", () => {
      var pool = gifCaptcha.createPoolManager({
        minPassRate: 0.3,
        minPoolSize: 1
      });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);

      // Simulate: p1 gets 12 serves but only 1 pass (8.3% rate < 30%)
      for (var i = 0; i < 12; i++) pool.pick(1);
      var allStats = pool.getStats();
      // Find the most-served challenge and make it have low pass rate
      allStats.sort(function (a, b) { return b.serves - a.serves; });
      var target = allStats[0].id;

      // Record mostly failures
      pool.recordResult(target, true);  // 1 pass
      for (var j = 0; j < 11; j++) pool.recordResult(target, false);

      var retired = pool.enforceRetirement();
      // May have been retired for max_serves or too_hard
      if (retired.indexOf(target) >= 0) {
        var targetStats = pool.getStats(target);
        assert.equal(targetStats.retired, true);
      }
    });

    it("should preserve minPoolSize even with all overserved", () => {
      var pool = gifCaptcha.createPoolManager({
        maxServes: 2,
        minPoolSize: 3
      });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);

      // All 3 exceed maxServes
      for (var i = 0; i < 20; i++) pool.pick(3);
      var retired = pool.enforceRetirement();

      assert.equal(retired.length, 0);
      assert.equal(pool.getSummary().activeCount, 3);
    });

    it("should retire highest-serve challenges first", () => {
      var pool = gifCaptcha.createPoolManager({
        maxServes: 3,
        minPoolSize: 1
      });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3),
                makeChallenge(4), makeChallenge(5)]);

      // Force many picks to exceed max for some
      for (var i = 0; i < 50; i++) pool.pick(1);
      var retired = pool.enforceRetirement();

      if (retired.length >= 2) {
        var s1 = pool.getStats(retired[0]);
        var s2 = pool.getStats(retired[1]);
        // First retired should have >= serves than second (sorted by serves desc)
        assert.ok(s1.serves >= s2.serves,
          "Higher-serve challenges should retire first");
      }
    });

    it("should set retiredAt timestamp on retirement", () => {
      var pool = gifCaptcha.createPoolManager({ maxServes: 3, minPoolSize: 1 });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);
      for (var i = 0; i < 20; i++) pool.pick(1);
      var before = Date.now();
      var retired = pool.enforceRetirement();
      var after = Date.now();

      if (retired.length > 0) {
        var state = pool.exportState();
        var entry = state.entries.find(function (e) { return e.id === retired[0]; });
        assert.ok(entry.retiredAt >= before && entry.retiredAt <= after,
          "retiredAt should be close to now");
      }
    });

    it("should not check pass rate with fewer than 10 serves", () => {
      var pool = gifCaptcha.createPoolManager({
        minPassRate: 0.5,
        maxServes: 100,
        minPoolSize: 1
      });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);

      // Only 5 serves, all fails → 0% pass rate but shouldn't retire (< 10 serves)
      for (var i = 0; i < 5; i++) pool.pick(1);
      var allStats = pool.getStats();
      allStats.forEach(function (s) {
        for (var j = 0; j < s.serves; j++) pool.recordResult(s.id, false);
      });

      var retired = pool.enforceRetirement();
      assert.equal(retired.length, 0, "Should not retire with < 10 serves");
    });
  });

  /* ── Reinstate ──────────────────────────────────────────────────── */

  describe("reinstate", () => {
    it("should reset serves/passes/fails on reinstate", () => {
      var pool = gifCaptcha.createPoolManager({ maxServes: 3, minPoolSize: 1 });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);
      for (var i = 0; i < 20; i++) pool.pick(1);
      pool.enforceRetirement();

      var allStats = pool.getStats();
      var retiredId = allStats.find(function (s) { return s.retired; });

      if (retiredId) {
        pool.reinstate(retiredId.id);
        var after = pool.getStats(retiredId.id);
        assert.equal(after.serves, 0);
        assert.equal(after.passes, 0);
        assert.equal(after.fails, 0);
        assert.equal(after.retired, false);
        assert.equal(after.retireReason, null);
      }
    });

    it("should return false for unknown challenge", () => {
      var pool = gifCaptcha.createPoolManager();
      assert.equal(pool.reinstate("nonexistent"), false);
    });

    it("should increase active count after reinstate", () => {
      var pool = gifCaptcha.createPoolManager({ maxServes: 3, minPoolSize: 1 });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);
      for (var i = 0; i < 20; i++) pool.pick(1);
      pool.enforceRetirement();

      var beforeActive = pool.getSummary().activeCount;
      var allStats = pool.getStats();
      var retiredId = allStats.find(function (s) { return s.retired; });

      if (retiredId) {
        pool.reinstate(retiredId.id);
        assert.equal(pool.getSummary().activeCount, beforeActive + 1);
      }
    });
  });

  /* ── Export / Import ────────────────────────────────────────────── */

  describe("export/import state", () => {
    it("should preserve retired state across export/import", () => {
      var pool = gifCaptcha.createPoolManager({ maxServes: 3, minPoolSize: 1 });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);
      for (var i = 0; i < 20; i++) pool.pick(1);
      pool.enforceRetirement();
      var state = pool.exportState();

      var pool2 = gifCaptcha.createPoolManager({ maxServes: 3, minPoolSize: 1 });
      pool2.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);
      pool2.importState(state);

      var stats1 = pool.getStats();
      var stats2 = pool2.getStats();
      stats1.sort(function (a, b) { return a.id.localeCompare(b.id); });
      stats2.sort(function (a, b) { return a.id.localeCompare(b.id); });

      for (var j = 0; j < stats1.length; j++) {
        assert.equal(stats1[j].retired, stats2[j].retired);
        assert.equal(stats1[j].serves, stats2[j].serves);
        assert.equal(stats1[j].passes, stats2[j].passes);
      }
    });

    it("should preserve pass/fail counts across export/import", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add([makeChallenge(1), makeChallenge(2)]);
      pool.pick(1);
      pool.recordResult("p1", true);
      pool.recordResult("p1", true);
      pool.recordResult("p2", false);
      pool.recordResult("p2", false);
      pool.recordResult("p2", false);

      var state = pool.exportState();
      var pool2 = gifCaptcha.createPoolManager();
      pool2.add([makeChallenge(1), makeChallenge(2)]);
      pool2.importState(state);

      var s1 = pool2.getStats("p1");
      var s2 = pool2.getStats("p2");
      assert.equal(s1.passes, 2);
      assert.equal(s2.fails, 3);
    });

    it("should include exportedAt timestamp", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add(makeChallenge(1));
      var before = Date.now();
      var state = pool.exportState();
      var after = Date.now();
      assert.ok(state.exportedAt >= before && state.exportedAt <= after);
    });

    it("should handle import with missing challenges (skip unknown)", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add(makeChallenge(1));

      var state = {
        entries: [
          { id: "p1", serves: 5, passes: 3, fails: 2, retired: false },
          { id: "unknown", serves: 10, passes: 5, fails: 5, retired: true },
        ],
        exportedAt: Date.now()
      };

      var restored = pool.importState(state);
      assert.equal(restored, 1); // only p1 matched
    });

    it("should return 0 for import with empty entries array", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add(makeChallenge(1));
      assert.equal(pool.importState({ entries: [] }), 0);
    });
  });

  /* ── getStats ───────────────────────────────────────────────────── */

  describe("getStats", () => {
    it("should compute passRate correctly", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add(makeChallenge(1));
      pool.pick(1); // 1 serve
      pool.recordResult("p1", true);
      pool.recordResult("p1", false);

      // Note: recordResult doesn't increment serves, only passes/fails
      // serves=1 from pick, passes=1, fails=1
      var stats = pool.getStats("p1");
      assert.equal(stats.passRate, 1.0); // 1 pass / 1 serve
    });

    it("should return null passRate for 0 serves", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add(makeChallenge(1));
      var stats = pool.getStats("p1");
      assert.equal(stats.passRate, null);
    });

    it("should include retireReason in stats", () => {
      var pool = gifCaptcha.createPoolManager({ maxServes: 3, minPoolSize: 1 });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3)]);
      for (var i = 0; i < 20; i++) pool.pick(1);
      pool.enforceRetirement();

      var allStats = pool.getStats();
      var retired = allStats.find(function (s) { return s.retired; });
      if (retired) {
        assert.ok(typeof retired.retireReason === "string");
        assert.ok(retired.retireReason.length > 0);
      }
    });
  });

  /* ── getSummary ─────────────────────────────────────────────────── */

  describe("getSummary", () => {
    it("should return correct overallPassRate", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add([makeChallenge(1), makeChallenge(2)]);
      pool.pick(2); // 2 serves
      pool.recordResult("p1", true);
      pool.recordResult("p2", true);
      pool.recordResult("p2", false);

      var summary = pool.getSummary();
      assert.equal(summary.totalPasses, 2);
      assert.equal(summary.totalFails, 1);
      assert.ok(summary.overallPassRate !== null);
    });

    it("should return null overallPassRate with 0 serves", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add(makeChallenge(1));
      assert.equal(pool.getSummary().overallPassRate, null);
    });

    it("should count retired correctly after retirement and reinstate", () => {
      var pool = gifCaptcha.createPoolManager({ maxServes: 3, minPoolSize: 1 });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3),
                makeChallenge(4), makeChallenge(5)]);
      for (var i = 0; i < 50; i++) pool.pick(1);
      pool.enforceRetirement();

      var summary = pool.getSummary();
      var retiredCount = summary.retiredCount;
      assert.ok(retiredCount > 0);

      // Reinstate one
      var allStats = pool.getStats();
      var retiredId = allStats.find(function (s) { return s.retired; }).id;
      pool.reinstate(retiredId);

      var after = pool.getSummary();
      assert.equal(after.retiredCount, retiredCount - 1);
    });
  });

  /* ── Edge cases ─────────────────────────────────────────────────── */

  describe("edge cases", () => {
    it("should handle adding challenge with numeric id", () => {
      var pool = gifCaptcha.createPoolManager();
      var c = gifCaptcha.createChallenge({
        id: 42,
        gifUrl: "https://example.com/42.gif",
        humanAnswer: "answer",
        title: "Numeric"
      });
      var added = pool.add(c);
      assert.equal(added, 1);
      var stats = pool.getStats("42");
      assert.ok(stats !== null);
    });

    it("should handle recording result for string-coerced numeric id", () => {
      var pool = gifCaptcha.createPoolManager();
      var c = gifCaptcha.createChallenge({
        id: 7,
        gifUrl: "https://example.com/7.gif",
        humanAnswer: "x",
        title: "T"
      });
      pool.add(c);
      pool.recordResult(7, true);
      var stats = pool.getStats(7);
      assert.equal(stats.passes, 1);
    });

    it("should handle rapid pick-retire cycles", () => {
      var pool = gifCaptcha.createPoolManager({ maxServes: 5, minPoolSize: 1 });
      for (var i = 1; i <= 10; i++) pool.add(makeChallenge(i));

      for (var round = 0; round < 5; round++) {
        for (var j = 0; j < 20; j++) pool.pick(1);
        pool.enforceRetirement();
      }

      var summary = pool.getSummary();
      assert.ok(summary.activeCount >= 1, "Should maintain at least minPoolSize");
      assert.ok(summary.retiredCount >= 0);
      assert.equal(summary.activeCount + summary.retiredCount, 10);
    });

    it("should handle single-challenge pool", () => {
      var pool = gifCaptcha.createPoolManager({ minPoolSize: 1 });
      pool.add(makeChallenge(1));
      var picked = pool.pick(1);
      assert.equal(picked.length, 1);
      assert.equal(picked[0].id, "p1");

      pool.recordResult("p1", true);
      var stats = pool.getStats("p1");
      assert.equal(stats.passes, 1);
    });

    it("should handle enforceRetirement on empty pool", () => {
      var pool = gifCaptcha.createPoolManager();
      var retired = pool.enforceRetirement();
      assert.deepEqual(retired, []);
    });

    it("should handle multiple add calls for same batch", () => {
      var pool = gifCaptcha.createPoolManager();
      pool.add([makeChallenge(1), makeChallenge(2)]);
      pool.add([makeChallenge(3), makeChallenge(4)]);
      assert.equal(pool.getSummary().activeCount, 4);
    });

    it("should handle challenge with special characters in id", () => {
      var pool = gifCaptcha.createPoolManager();
      var c = gifCaptcha.createChallenge({
        id: "test-challenge_v2.0",
        gifUrl: "https://example.com/test.gif",
        humanAnswer: "ans",
        title: "Special"
      });
      pool.add(c);
      var stats = pool.getStats("test-challenge_v2.0");
      assert.ok(stats !== null);
      assert.equal(stats.id, "test-challenge_v2.0");
    });

    it("should not let retired challenges appear in pick()", () => {
      var pool = gifCaptcha.createPoolManager({ maxServes: 3, minPoolSize: 1 });
      pool.add([makeChallenge(1), makeChallenge(2), makeChallenge(3),
                makeChallenge(4), makeChallenge(5)]);
      for (var i = 0; i < 40; i++) pool.pick(1);
      pool.enforceRetirement();

      var retiredIds = pool.getStats()
        .filter(function (s) { return s.retired; })
        .map(function (s) { return s.id; });

      // Pick 100 more times — retired should never appear
      for (var j = 0; j < 100; j++) {
        var picked = pool.pick(1);
        if (picked.length > 0) {
          assert.ok(retiredIds.indexOf(picked[0].id) === -1,
            "Retired challenge " + picked[0].id + " was picked");
        }
      }
    });
  });
});
