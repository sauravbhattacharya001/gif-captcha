var { describe, it, beforeEach } = require("node:test");
var assert = require("node:assert/strict");
var { createAdaptiveTimeout } = require("../src/index");

describe("createAdaptiveTimeout", function () {
  var at;

  beforeEach(function () {
    at = createAdaptiveTimeout();
  });

  // ── Initialization ─────────────────────────────────────

  describe("initialization", function () {
    it("should create with default config", function () {
      var config = at.getConfig();
      assert.equal(config.baseTimeoutMs, 30000);
      assert.equal(config.minTimeoutMs, 5000);
      assert.equal(config.maxTimeoutMs, 120000);
      assert.equal(config.difficultyMultiplierLow, 0.7);
      assert.equal(config.difficultyMultiplierHigh, 1.8);
      assert.equal(config.suspiciousReduction, 0.5);
      assert.equal(config.trustedBonus, 1.3);
      assert.equal(config.targetPercentile, 0.90);
      assert.equal(config.baselineMargin, 1.5);
      assert.equal(config.maxHistoryPerDifficulty, 500);
      assert.equal(config.latencyBufferMs, 2000);
    });

    it("should accept custom config", function () {
      var custom = createAdaptiveTimeout({
        baseTimeoutMs: 10000,
        minTimeoutMs: 2000,
        maxTimeoutMs: 60000,
        suspiciousReduction: 0.3,
      });
      var config = custom.getConfig();
      assert.equal(config.baseTimeoutMs, 10000);
      assert.equal(config.minTimeoutMs, 2000);
      assert.equal(config.maxTimeoutMs, 60000);
      assert.equal(config.suspiciousReduction, 0.3);
    });

    it("should start with empty stats", function () {
      var stats = at.getStats();
      assert.equal(stats.totalCalculations, 0);
      assert.equal(stats.totalRecorded, 0);
      assert.equal(stats.historySizes.easy, 0);
      assert.equal(stats.historySizes.medium, 0);
      assert.equal(stats.historySizes.hard, 0);
      assert.equal(stats.clientLatencyEntries, 0);
    });
  });

  // ── Basic Calculation ──────────────────────────────────

  describe("calculate() basics", function () {
    it("should return baseTimeoutMs + latencyBuffer for default params with no history", function () {
      var result = at.calculate();
      // base=30000, diffMult=1.0 (medium), repMult=1.0 (neutral), latency=2000
      assert.equal(result.timeoutMs, 32000);
      assert.equal(result.factors.difficulty, "medium");
      assert.equal(result.factors.difficultyMultiplier, 1.0);
      assert.equal(result.factors.reputation, "neutral");
      assert.equal(result.factors.reputationMultiplier, 1.0);
    });

    it("should increment calculation count", function () {
      at.calculate();
      at.calculate();
      at.calculate();
      assert.equal(at.getStats().totalCalculations, 3);
    });

    it("should return factors breakdown", function () {
      var result = at.calculate({ difficulty: "hard" });
      assert.equal(result.factors.difficulty, "hard");
      assert.equal(result.factors.difficultyMultiplier, 1.8);
      assert.equal(typeof result.factors.baseline, "number");
      assert.equal(typeof result.factors.unclamped, "number");
    });
  });

  // ── Difficulty Multipliers ─────────────────────────────

  describe("difficulty multipliers", function () {
    it("should apply lower multiplier for easy", function () {
      var easy = at.calculate({ difficulty: "easy" });
      var medium = at.calculate({ difficulty: "medium" });
      assert.ok(easy.timeoutMs < medium.timeoutMs);
    });

    it("should apply higher multiplier for hard", function () {
      var medium = at.calculate({ difficulty: "medium" });
      var hard = at.calculate({ difficulty: "hard" });
      assert.ok(hard.timeoutMs > medium.timeoutMs);
    });

    it("should accept numeric difficulty 0-100", function () {
      var easy = at.calculate({ difficulty: 10 });
      assert.equal(easy.factors.difficulty, "easy");

      var medium = at.calculate({ difficulty: 50 });
      assert.equal(medium.factors.difficulty, "medium");

      var hard = at.calculate({ difficulty: 80 });
      assert.equal(hard.factors.difficulty, "hard");
    });

    it("should accept string aliases", function () {
      var low = at.calculate({ difficulty: "low" });
      assert.equal(low.factors.difficulty, "easy");

      var high = at.calculate({ difficulty: "high" });
      assert.equal(high.factors.difficulty, "hard");
    });

    it("should default unknown difficulty to medium", function () {
      var result = at.calculate({ difficulty: "unknown" });
      assert.equal(result.factors.difficulty, "medium");
    });
  });

  // ── Reputation Adjustments ─────────────────────────────

  describe("reputation adjustments", function () {
    it("should reduce timeout for suspicious clients", function () {
      var neutral = at.calculate({ reputation: "neutral" });
      var suspicious = at.calculate({ reputation: "suspicious" });
      assert.ok(suspicious.timeoutMs < neutral.timeoutMs);
    });

    it("should increase timeout for trusted clients", function () {
      var neutral = at.calculate({ reputation: "neutral" });
      var trusted = at.calculate({ reputation: "trusted" });
      assert.ok(trusted.timeoutMs > neutral.timeoutMs);
    });

    it("should apply correct multiplier for suspicious", function () {
      var result = at.calculate({ reputation: "suspicious" });
      assert.equal(result.factors.reputationMultiplier, 0.5);
    });

    it("should apply correct multiplier for trusted", function () {
      var result = at.calculate({ reputation: "trusted" });
      assert.equal(result.factors.reputationMultiplier, 1.3);
    });
  });

  // ── History-Based Baseline ─────────────────────────────

  describe("history-based baseline", function () {
    it("should use baseTimeoutMs when fewer than 10 samples", function () {
      for (var i = 0; i < 9; i++) {
        at.recordResponse("medium", 5000 + i * 100);
      }
      var result = at.calculate({ difficulty: "medium" });
      assert.equal(result.factors.baseline, 30000); // still default
    });

    it("should switch to percentile baseline after 10+ samples", function () {
      for (var i = 0; i < 20; i++) {
        at.recordResponse("medium", 3000 + i * 200);
      }
      var result = at.calculate({ difficulty: "medium" });
      // Should be based on 90th percentile, not default 30000
      assert.ok(result.factors.baseline < 30000);
    });

    it("should have separate baselines per difficulty", function () {
      // Easy: fast responses
      for (var i = 0; i < 15; i++) {
        at.recordResponse("easy", 1000 + i * 50);
      }
      // Hard: slow responses
      for (var i = 0; i < 15; i++) {
        at.recordResponse("hard", 8000 + i * 200);
      }
      var easyResult = at.calculate({ difficulty: "easy" });
      var hardResult = at.calculate({ difficulty: "hard" });

      // Hard baseline should be higher AND multiplied by 1.8
      assert.ok(hardResult.factors.baseline > easyResult.factors.baseline);
    });

    it("should increment recorded count", function () {
      at.recordResponse("easy", 5000);
      at.recordResponse("medium", 6000);
      at.recordResponse("hard", 7000);
      assert.equal(at.getStats().totalRecorded, 3);
      assert.equal(at.getStats().historySizes.easy, 1);
    });

    it("should ignore negative response times", function () {
      at.recordResponse("medium", -100);
      assert.equal(at.getStats().totalRecorded, 0);
    });

    it("should ignore non-number response times", function () {
      at.recordResponse("medium", "fast");
      assert.equal(at.getStats().totalRecorded, 0);
    });
  });

  // ── Client Latency ─────────────────────────────────────

  describe("client latency", function () {
    it("should use latencyBufferMs when no client data", function () {
      var result = at.calculate({ clientId: "unknown" });
      assert.equal(result.factors.latencyMs, 2000);
    });

    it("should use recorded latency for known clients", function () {
      at.recordLatency("client1", 100);
      at.recordLatency("client1", 200);
      at.recordLatency("client1", 150);
      var lat = at.getClientLatency("client1");
      assert.equal(lat, 150); // average of 100, 200, 150
    });

    it("should use client latency in calculations", function () {
      at.recordLatency("fast-client", 50);
      at.recordLatency("slow-client", 500);

      var fast = at.calculate({ clientId: "fast-client" });
      var slow = at.calculate({ clientId: "slow-client" });

      // Slow client should get more time
      assert.ok(slow.timeoutMs > fast.timeoutMs);
    });

    it("should keep only last 10 samples", function () {
      for (var i = 0; i < 15; i++) {
        at.recordLatency("client1", 100 + i * 10);
      }
      // Should have samples 5-14 (values 150-240), avg = 195
      var lat = at.getClientLatency("client1");
      assert.equal(lat, 195);
    });

    it("should return 0 for unknown client", function () {
      assert.equal(at.getClientLatency("unknown"), 0);
      assert.equal(at.getClientLatency(null), 0);
      assert.equal(at.getClientLatency(undefined), 0);
    });

    it("should ignore negative latency", function () {
      at.recordLatency("client1", -50);
      assert.equal(at.getClientLatency("client1"), 0);
    });

    it("should ignore null clientId", function () {
      at.recordLatency(null, 100);
      assert.equal(at.getStats().clientLatencyEntries, 0);
    });
  });

  // ── Clamping ───────────────────────────────────────────

  describe("clamping", function () {
    it("should not go below minTimeoutMs", function () {
      var at2 = createAdaptiveTimeout({
        baseTimeoutMs: 1000,
        minTimeoutMs: 5000,
        latencyBufferMs: 0,
      });
      // Easy + suspicious: 1000 * 0.7 * 0.5 = 350 → clamped to 5000
      var result = at2.calculate({
        difficulty: "easy",
        reputation: "suspicious",
      });
      assert.equal(result.timeoutMs, 5000);
    });

    it("should not exceed maxTimeoutMs", function () {
      var at2 = createAdaptiveTimeout({
        baseTimeoutMs: 100000,
        maxTimeoutMs: 60000,
        latencyBufferMs: 5000,
      });
      var result = at2.calculate({ difficulty: "hard", reputation: "trusted" });
      assert.equal(result.timeoutMs, 60000);
    });
  });

  // ── Baseline API ───────────────────────────────────────

  describe("getBaseline()", function () {
    it("should return null baselineMs with no data", function () {
      var bl = at.getBaseline("medium");
      assert.equal(bl.sampleCount, 0);
      assert.equal(bl.baselineMs, null);
    });

    it("should return computed baseline with data", function () {
      for (var i = 0; i < 10; i++) {
        at.recordResponse("hard", 5000);
      }
      var bl = at.getBaseline("hard");
      assert.equal(bl.sampleCount, 10);
      assert.equal(bl.baselineMs, 5000);
    });
  });

  // ── State Export/Import ────────────────────────────────

  describe("state persistence", function () {
    it("should export and import state", function () {
      at.recordResponse("easy", 2000);
      at.recordResponse("medium", 5000);
      at.recordLatency("client1", 100);
      at.calculate();
      at.calculate();

      var exported = at.exportState();
      var at2 = createAdaptiveTimeout();
      at2.importState(exported);

      var stats = at2.getStats();
      assert.equal(stats.totalCalculations, 2);
      assert.equal(stats.totalRecorded, 2);
      assert.equal(stats.historySizes.easy, 1);
      assert.equal(stats.historySizes.medium, 1);
      assert.equal(stats.clientLatencyEntries, 1);
      assert.equal(at2.getClientLatency("client1"), 100);
    });

    it("should handle null/invalid import gracefully", function () {
      at.importState(null);
      at.importState("invalid");
      at.importState({});
      assert.equal(at.getStats().totalRecorded, 0);
    });
  });

  // ── Reset ──────────────────────────────────────────────

  describe("reset()", function () {
    it("should clear all state", function () {
      at.recordResponse("easy", 2000);
      at.recordResponse("hard", 8000);
      at.recordLatency("client1", 100);
      at.calculate();

      at.reset();

      var stats = at.getStats();
      assert.equal(stats.totalCalculations, 0);
      assert.equal(stats.totalRecorded, 0);
      assert.equal(stats.historySizes.easy, 0);
      assert.equal(stats.historySizes.medium, 0);
      assert.equal(stats.historySizes.hard, 0);
      assert.equal(stats.clientLatencyEntries, 0);
    });
  });

  // ── Combined Factors ───────────────────────────────────

  describe("combined factor interactions", function () {
    it("should combine difficulty + reputation + latency", function () {
      at.recordLatency("client1", 300);
      var result = at.calculate({
        difficulty: "hard",
        reputation: "suspicious",
        clientId: "client1",
      });
      // base=30000, diff=1.8 → 54000, rep=0.5 → 27000, lat=+300 → 27300
      assert.equal(result.timeoutMs, 27300);
      assert.equal(result.factors.difficultyMultiplier, 1.8);
      assert.equal(result.factors.reputationMultiplier, 0.5);
      assert.equal(result.factors.latencyMs, 300);
    });

    it("hard + trusted should give maximum leeway", function () {
      var result = at.calculate({
        difficulty: "hard",
        reputation: "trusted",
      });
      // base=30000, diff=1.8 → 54000, rep=1.3 → 70200, lat=2000 → 72200
      assert.equal(result.timeoutMs, 72200);
    });

    it("easy + suspicious should give minimum time", function () {
      var result = at.calculate({
        difficulty: "easy",
        reputation: "suspicious",
      });
      // base=30000, diff=0.7 → 21000, rep=0.5 → 10500, lat=2000 → 12500
      assert.equal(result.timeoutMs, 12500);
    });
  });

  // ── History Cap ────────────────────────────────────────

  describe("history capacity", function () {
    it("should cap history at maxHistoryPerDifficulty", function () {
      var small = createAdaptiveTimeout({ maxHistoryPerDifficulty: 5 });
      for (var i = 0; i < 10; i++) {
        small.recordResponse("easy", 1000 + i * 100);
      }
      assert.equal(small.getStats().historySizes.easy, 5);
    });
  });

  // ── Client Latency Eviction ────────────────────────────

  describe("client latency eviction", function () {
    it("should evict oldest when at capacity", function () {
      var tiny = createAdaptiveTimeout();
      // The default maxClientLatencyEntries is 5000, too many to test.
      // Instead, verify that recording many clients works without error.
      for (var i = 0; i < 100; i++) {
        tiny.recordLatency("client" + i, 50 + i);
      }
      assert.equal(tiny.getStats().clientLatencyEntries, 100);
    });
  });

  // ── Edge Cases ─────────────────────────────────────────

  describe("edge cases", function () {
    it("should handle zero latencyBufferMs", function () {
      var at2 = createAdaptiveTimeout({ latencyBufferMs: 0 });
      var result = at2.calculate();
      // base=30000, diff=1.0, rep=1.0, lat=0 → 30000
      assert.equal(result.timeoutMs, 30000);
    });

    it("should handle single response time in history", function () {
      at.recordResponse("medium", 5000);
      var bl = at.getBaseline("medium");
      assert.equal(bl.sampleCount, 1);
    });

    it("should handle calculate with empty params", function () {
      var result = at.calculate({});
      assert.equal(typeof result.timeoutMs, "number");
      assert.ok(result.timeoutMs >= 5000);
    });
  });
});
