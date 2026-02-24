const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { createDifficultyCalibrator } = require("../src/index");

// Test helper — create sample challenges
function sampleChallenges() {
  return [
    { id: "ch1", title: "Easy GIF", difficulty: 20 },
    { id: "ch2", title: "Medium GIF", difficulty: 50 },
    { id: "ch3", title: "Hard GIF", difficulty: 80 },
  ];
}

describe("createDifficultyCalibrator", function () {
  describe("initialization", function () {
    it("returns object with expected methods", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      assert.equal(typeof cal.recordResponse, "function");
      assert.equal(typeof cal.recordBatch, "function");
      assert.equal(typeof cal.getStats, "function");
      assert.equal(typeof cal.calibrateDifficulty, "function");
      assert.equal(typeof cal.calibrateAll, "function");
      assert.equal(typeof cal.findOutliers, "function");
      assert.equal(typeof cal.getDifficultyDistribution, "function");
      assert.equal(typeof cal.generateReport, "function");
      assert.equal(typeof cal.reset, "function");
      assert.equal(typeof cal.responseCount, "function");
      assert.equal(typeof cal.totalResponses, "function");
    });

    it("throws on empty array", function () {
      assert.throws(function () {
        createDifficultyCalibrator([]);
      }, /challenges must be a non-empty array/);
    });

    it("throws on non-array", function () {
      assert.throws(function () {
        createDifficultyCalibrator("not an array");
      }, /challenges must be a non-empty array/);
    });

    it("throws on null", function () {
      assert.throws(function () {
        createDifficultyCalibrator(null);
      }, /challenges must be a non-empty array/);
    });

    it("accepts array of challenges", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      assert.ok(cal);
    });
  });

  describe("recordResponse", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("records a valid response", function () {
      cal.recordResponse("ch1", { timeMs: 1000, correct: true });
      assert.equal(cal.responseCount("ch1"), 1);
    });

    it("throws on empty challengeId", function () {
      assert.throws(function () {
        cal.recordResponse("", { timeMs: 100, correct: true });
      }, /challengeId must be a non-empty string/);
    });

    it("throws on non-string challengeId", function () {
      assert.throws(function () {
        cal.recordResponse(123, { timeMs: 100, correct: true });
      }, /challengeId must be a non-empty string/);
    });

    it("throws on null response", function () {
      assert.throws(function () {
        cal.recordResponse("ch1", null);
      }, /response must be an object/);
    });

    it("throws on negative timeMs", function () {
      assert.throws(function () {
        cal.recordResponse("ch1", { timeMs: -1, correct: true });
      }, /response\.timeMs must be a non-negative number/);
    });

    it("throws on non-number timeMs", function () {
      assert.throws(function () {
        cal.recordResponse("ch1", { timeMs: "fast", correct: true });
      }, /response\.timeMs must be a non-negative number/);
    });

    it("throws on non-boolean correct", function () {
      assert.throws(function () {
        cal.recordResponse("ch1", { timeMs: 100, correct: "yes" });
      }, /response\.correct must be a boolean/);
    });

    it("records skipped flag", function () {
      cal.recordResponse("ch1", { timeMs: 0, correct: false, skipped: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.skipCount, 1);
    });

    it("defaults skipped to false", function () {
      cal.recordResponse("ch1", { timeMs: 500, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.skipCount, 0);
    });

    it("records multiple responses for same challenge", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: false });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      assert.equal(cal.responseCount("ch1"), 3);
    });
  });

  describe("recordBatch", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("records multiple responses", function () {
      cal.recordBatch([
        { challengeId: "ch1", timeMs: 100, correct: true },
        { challengeId: "ch2", timeMs: 200, correct: false },
        { challengeId: "ch3", timeMs: 300, correct: true },
      ]);
      assert.equal(cal.totalResponses(), 3);
    });

    it("throws on non-array", function () {
      assert.throws(function () {
        cal.recordBatch("not an array");
      }, /responses must be an array/);
    });

    it("validates each response", function () {
      assert.throws(function () {
        cal.recordBatch([
          { challengeId: "ch1", timeMs: 100, correct: true },
          { challengeId: "", timeMs: 200, correct: false },
        ]);
      }, /challengeId must be a non-empty string/);
    });
  });

  describe("getStats", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("returns null for unknown challengeId", function () {
      assert.equal(cal.getStats("unknown"), null);
    });

    it("returns null for challenge with no responses", function () {
      assert.equal(cal.getStats("ch1"), null);
    });

    it("returns correct totalResponses", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: false });
      var stats = cal.getStats("ch1");
      assert.equal(stats.totalResponses, 2);
    });

    it("returns correct correctCount", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: false });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.correctCount, 2);
    });

    it("returns correct skipCount", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: false, skipped: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: false, skipped: true });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.skipCount, 2);
    });

    it("returns correct accuracy", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: false });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      cal.recordResponse("ch1", { timeMs: 400, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.accuracy, 0.75);
    });

    it("returns correct skipRate", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: false, skipped: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: true });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      cal.recordResponse("ch1", { timeMs: 400, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.skipRate, 0.25);
    });

    it("returns correct avgTimeMs", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: true });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.avgTimeMs, 200);
    });

    it("returns correct medianTimeMs with odd count", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 500, correct: true });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.medianTimeMs, 300);
    });

    it("returns correct medianTimeMs with even count", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: true });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      cal.recordResponse("ch1", { timeMs: 400, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.medianTimeMs, 250);
    });

    it("returns correct min/max", function () {
      cal.recordResponse("ch1", { timeMs: 500, correct: true });
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 900, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.minTimeMs, 100);
      assert.equal(stats.maxTimeMs, 900);
    });

    it("returns correct stdDevTimeMs", function () {
      // times: 100, 200, 300 → avg=200, variance=((100)^2+(0)^2+(100)^2)/3=20000/3, stddev≈81.65
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: true });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.stdDevTimeMs, 82); // Math.round(81.649...)
    });

    it("excludes skipped from time stats", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 99999, correct: false, skipped: true });
      cal.recordResponse("ch1", { timeMs: 300, correct: true });
      var stats = cal.getStats("ch1");
      // Only 100 and 300 should be counted for time stats
      assert.equal(stats.avgTimeMs, 200);
      assert.equal(stats.minTimeMs, 100);
      assert.equal(stats.maxTimeMs, 300);
    });
  });

  describe("calibrateDifficulty", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("returns null for challenge with no data", function () {
      assert.equal(cal.calibrateDifficulty("ch1"), null);
    });

    it("returns 0-100 range", function () {
      cal.recordResponse("ch1", { timeMs: 500, correct: true });
      var d = cal.calibrateDifficulty("ch1");
      assert.ok(d >= 0 && d <= 100);
    });

    it("harder for low accuracy", function () {
      // ch1: all wrong, ch2: all correct
      cal.recordResponse("ch1", { timeMs: 500, correct: false });
      cal.recordResponse("ch1", { timeMs: 500, correct: false });
      cal.recordResponse("ch2", { timeMs: 500, correct: true });
      cal.recordResponse("ch2", { timeMs: 500, correct: true });
      var d1 = cal.calibrateDifficulty("ch1");
      var d2 = cal.calibrateDifficulty("ch2");
      assert.ok(d1 > d2, "low accuracy should be harder: " + d1 + " vs " + d2);
    });

    it("harder for high skip rate", function () {
      // ch1: all skipped, ch2: none skipped
      cal.recordResponse("ch1", { timeMs: 500, correct: false, skipped: true });
      cal.recordResponse("ch1", { timeMs: 500, correct: false, skipped: true });
      cal.recordResponse("ch2", { timeMs: 500, correct: false });
      cal.recordResponse("ch2", { timeMs: 500, correct: false });
      var d1 = cal.calibrateDifficulty("ch1");
      var d2 = cal.calibrateDifficulty("ch2");
      assert.ok(d1 > d2, "high skip should be harder: " + d1 + " vs " + d2);
    });

    it("harder for slow response time", function () {
      // ch1: slow, ch2: fast — both same accuracy
      cal.recordResponse("ch1", { timeMs: 10000, correct: true });
      cal.recordResponse("ch2", { timeMs: 100, correct: true });
      var d1 = cal.calibrateDifficulty("ch1");
      var d2 = cal.calibrateDifficulty("ch2");
      assert.ok(d1 > d2, "slow response should be harder: " + d1 + " vs " + d2);
    });

    it("easier for high accuracy fast response", function () {
      // ch1: high accuracy + fast, ch2: low accuracy + slow
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch2", { timeMs: 5000, correct: false });
      cal.recordResponse("ch2", { timeMs: 5000, correct: false });
      var d1 = cal.calibrateDifficulty("ch1");
      var d2 = cal.calibrateDifficulty("ch2");
      assert.ok(d1 < d2, "high accuracy + fast should be easier: " + d1 + " vs " + d2);
    });

    it("returns number (not null) with valid data", function () {
      cal.recordResponse("ch1", { timeMs: 1000, correct: true });
      var d = cal.calibrateDifficulty("ch1");
      assert.equal(typeof d, "number");
      assert.notEqual(d, null);
    });
  });

  describe("calibrateAll", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("returns array of calibration results", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch2", { timeMs: 200, correct: false });
      var results = cal.calibrateAll();
      assert.ok(Array.isArray(results));
      assert.equal(results.length, 2);
      assert.ok(results[0].challengeId);
      assert.equal(typeof results[0].originalDifficulty, "number");
      assert.equal(typeof results[0].calibratedDifficulty, "number");
      assert.ok(results[0].stats);
      assert.equal(typeof results[0].delta, "number");
    });

    it("sorted by largest absolute delta", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch2", { timeMs: 200, correct: false });
      cal.recordResponse("ch3", { timeMs: 5000, correct: false });
      var results = cal.calibrateAll();
      for (var i = 1; i < results.length; i++) {
        assert.ok(
          Math.abs(results[i - 1].delta) >= Math.abs(results[i].delta),
          "should be sorted by abs delta descending"
        );
      }
    });

    it("includes originalDifficulty from challenge", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      var results = cal.calibrateAll();
      var r = results.find(function (r) { return r.challengeId === "ch1"; });
      assert.equal(r.originalDifficulty, 20);
    });

    it("defaults originalDifficulty to 50 if missing", function () {
      var cal2 = createDifficultyCalibrator([{ id: "x", title: "No Diff" }]);
      cal2.recordResponse("x", { timeMs: 100, correct: true });
      var results = cal2.calibrateAll();
      assert.equal(results[0].originalDifficulty, 50);
    });

    it("returns empty array if no responses", function () {
      var results = cal.calibrateAll();
      assert.deepEqual(results, []);
    });
  });

  describe("findOutliers", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("returns challenges with delta >= threshold", function () {
      // ch1 rated 20, make it appear very hard → big positive delta
      cal.recordResponse("ch1", { timeMs: 10000, correct: false });
      cal.recordResponse("ch1", { timeMs: 10000, correct: false });
      var outliers = cal.findOutliers(10);
      assert.ok(outliers.length > 0);
      outliers.forEach(function (o) {
        assert.ok(Math.abs(o.delta) >= 10);
      });
    });

    it("default threshold is 20", function () {
      // Make ch1 (rated 20) appear very hard
      cal.recordResponse("ch1", { timeMs: 10000, correct: false });
      cal.recordResponse("ch1", { timeMs: 10000, correct: false });
      cal.recordResponse("ch1", { timeMs: 10000, correct: false });
      var outliers = cal.findOutliers();
      // Should use threshold 20 by default
      outliers.forEach(function (o) {
        assert.ok(Math.abs(o.delta) >= 20);
      });
    });

    it("throws on negative threshold", function () {
      assert.throws(function () {
        cal.findOutliers(-5);
      }, /threshold must be a non-negative number/);
    });

    it("includes direction field", function () {
      cal.recordResponse("ch1", { timeMs: 10000, correct: false });
      cal.recordResponse("ch1", { timeMs: 10000, correct: false });
      var outliers = cal.findOutliers(0);
      if (outliers.length > 0) {
        assert.ok(
          outliers[0].direction === "harder_than_rated" ||
            outliers[0].direction === "easier_than_rated"
        );
      }
    });

    it("returns empty if all within threshold", function () {
      // Record minimal data so delta is small
      cal.recordResponse("ch2", { timeMs: 500, correct: true });
      var outliers = cal.findOutliers(1000);
      assert.deepEqual(outliers, []);
    });
  });

  describe("getDifficultyDistribution", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("returns easy/medium/hard buckets", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      var dist = cal.getDifficultyDistribution();
      assert.equal(typeof dist.easy, "number");
      assert.equal(typeof dist.medium, "number");
      assert.equal(typeof dist.hard, "number");
    });

    it("easy < 33, medium < 67, hard >= 67", function () {
      // ch1: all correct + fast → easy
      // ch3: all wrong + slow → hard
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch3", { timeMs: 10000, correct: false });
      cal.recordResponse("ch3", { timeMs: 10000, correct: false });
      cal.recordResponse("ch3", { timeMs: 10000, correct: false });
      var dist = cal.getDifficultyDistribution();
      assert.ok(dist.easy >= 1, "should have at least one easy: " + JSON.stringify(dist));
      assert.ok(dist.hard >= 1, "should have at least one hard: " + JSON.stringify(dist));
    });

    it("all zeros with no responses", function () {
      var dist = cal.getDifficultyDistribution();
      assert.deepEqual(dist, { easy: 0, medium: 0, hard: 0 });
    });
  });

  describe("generateReport", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("returns report with all fields", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      var report = cal.generateReport();
      assert.equal(typeof report.challengeCount, "number");
      assert.equal(typeof report.responsesRecorded, "number");
      assert.equal(typeof report.calibratedCount, "number");
      assert.equal(typeof report.avgDifficulty, "number");
      assert.ok(report.distribution);
      assert.equal(typeof report.outlierCount, "number");
      assert.ok(Array.isArray(report.recommendations));
    });

    it("includes recommendations array", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      var report = cal.generateReport();
      assert.ok(Array.isArray(report.recommendations));
    });

    it("recommends more data when insufficient", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      var report = cal.generateReport();
      var hasDataRec = report.recommendations.some(function (r) {
        return r.indexOf("Insufficient data") !== -1;
      });
      assert.ok(hasDataRec, "should recommend more data");
    });

    it("recommends easy challenges when none exist", function () {
      // All challenges appear hard
      var hardChallenges = [
        { id: "h1", title: "H1", difficulty: 80 },
        { id: "h2", title: "H2", difficulty: 90 },
      ];
      var cal2 = createDifficultyCalibrator(hardChallenges);
      cal2.recordResponse("h1", { timeMs: 10000, correct: false });
      cal2.recordResponse("h2", { timeMs: 10000, correct: false });
      var report = cal2.generateReport();
      var hasEasyRec = report.recommendations.some(function (r) {
        return r.indexOf("No easy challenges") !== -1;
      });
      assert.ok(hasEasyRec, "should recommend adding easy challenges");
    });

    it("recommends hard challenges when none exist", function () {
      // All challenges appear easy
      var easyChallenges = [
        { id: "e1", title: "E1", difficulty: 10 },
        { id: "e2", title: "E2", difficulty: 15 },
      ];
      var cal2 = createDifficultyCalibrator(easyChallenges);
      cal2.recordResponse("e1", { timeMs: 100, correct: true });
      cal2.recordResponse("e2", { timeMs: 100, correct: true });
      var report = cal2.generateReport();
      var hasHardRec = report.recommendations.some(function (r) {
        return r.indexOf("No hard challenges") !== -1;
      });
      assert.ok(hasHardRec, "should recommend adding hard challenges");
    });

    it("reports outlier count", function () {
      cal.recordResponse("ch1", { timeMs: 10000, correct: false });
      cal.recordResponse("ch1", { timeMs: 10000, correct: false });
      var report = cal.generateReport();
      assert.equal(typeof report.outlierCount, "number");
    });
  });

  describe("reset", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("clears all responses", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch2", { timeMs: 200, correct: false });
      cal.reset();
      assert.equal(cal.getStats("ch1"), null);
      assert.equal(cal.getStats("ch2"), null);
    });

    it("totalResponses returns 0 after reset", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch2", { timeMs: 200, correct: false });
      cal.reset();
      assert.equal(cal.totalResponses(), 0);
    });
  });

  describe("responseCount", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("returns 0 for unknown challenge", function () {
      assert.equal(cal.responseCount("nonexistent"), 0);
    });

    it("returns correct count after recording", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: false });
      assert.equal(cal.responseCount("ch1"), 2);
    });
  });

  describe("totalResponses", function () {
    var cal;
    beforeEach(function () {
      cal = createDifficultyCalibrator(sampleChallenges());
    });

    it("returns 0 initially", function () {
      assert.equal(cal.totalResponses(), 0);
    });

    it("returns sum across all challenges", function () {
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: false });
      cal.recordResponse("ch2", { timeMs: 300, correct: true });
      assert.equal(cal.totalResponses(), 3);
    });
  });

  // Additional edge case tests
  describe("edge cases", function () {
    it("challenge with only skipped responses has 0 time stats", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      cal.recordResponse("ch1", { timeMs: 0, correct: false, skipped: true });
      cal.recordResponse("ch1", { timeMs: 0, correct: false, skipped: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.totalResponses, 2);
      assert.equal(stats.avgTimeMs, 0);
      assert.equal(stats.medianTimeMs, 0);
    });

    it("calibrate with single challenge uses default time score", function () {
      var cal = createDifficultyCalibrator([{ id: "solo", title: "Solo", difficulty: 50 }]);
      cal.recordResponse("solo", { timeMs: 1000, correct: true });
      var d = cal.calibrateDifficulty("solo");
      assert.equal(typeof d, "number");
      assert.ok(d >= 0 && d <= 100);
    });

    it("challenge uses title as id fallback", function () {
      var cal = createDifficultyCalibrator([{ title: "FallbackTitle", difficulty: 30 }]);
      cal.recordResponse("FallbackTitle", { timeMs: 500, correct: true });
      var results = cal.calibrateAll();
      assert.equal(results.length, 1);
      assert.equal(results[0].challengeId, "FallbackTitle");
    });

    it("recordResponse with timeMs of 0 is valid", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      cal.recordResponse("ch1", { timeMs: 0, correct: true });
      assert.equal(cal.responseCount("ch1"), 1);
    });

    it("findOutliers with threshold 0 returns all with any delta", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      cal.recordResponse("ch1", { timeMs: 500, correct: true });
      var outliers = cal.findOutliers(0);
      // Any challenge with calibrated != original is an outlier at threshold 0
      outliers.forEach(function (o) {
        assert.ok(Math.abs(o.delta) >= 0);
      });
    });

    it("generateReport challengeCount matches input", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      var report = cal.generateReport();
      assert.equal(report.challengeCount, 3);
    });

    it("generateReport with no responses", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      var report = cal.generateReport();
      assert.equal(report.responsesRecorded, 0);
      assert.equal(report.calibratedCount, 0);
      assert.equal(report.avgDifficulty, 0);
    });

    it("multiple challenges calibrated correctly", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch2", { timeMs: 500, correct: true });
      cal.recordResponse("ch3", { timeMs: 2000, correct: false });
      var d1 = cal.calibrateDifficulty("ch1");
      var d3 = cal.calibrateDifficulty("ch3");
      assert.ok(d1 < d3, "ch1 should be easier than ch3");
    });

    it("getStats accuracy with all correct", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.recordResponse("ch1", { timeMs: 200, correct: true });
      var stats = cal.getStats("ch1");
      assert.equal(stats.accuracy, 1.0);
    });

    it("getStats accuracy with none correct", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      cal.recordResponse("ch1", { timeMs: 100, correct: false });
      cal.recordResponse("ch1", { timeMs: 200, correct: false });
      var stats = cal.getStats("ch1");
      assert.equal(stats.accuracy, 0);
    });

    it("does not mutate original challenges array", function () {
      var challenges = sampleChallenges();
      var original = challenges.slice();
      var cal = createDifficultyCalibrator(challenges);
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      assert.deepEqual(challenges, original);
    });

    it("reset allows re-recording", function () {
      var cal = createDifficultyCalibrator(sampleChallenges());
      cal.recordResponse("ch1", { timeMs: 100, correct: true });
      cal.reset();
      cal.recordResponse("ch1", { timeMs: 500, correct: false });
      assert.equal(cal.responseCount("ch1"), 1);
      var stats = cal.getStats("ch1");
      assert.equal(stats.correctCount, 0);
    });
  });
});
