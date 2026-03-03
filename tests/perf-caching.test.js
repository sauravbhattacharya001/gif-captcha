var assert = require("assert");
var { describe, it } = require("node:test");
var gifCaptcha = require("../src/index");

// Helper: make N challenges with unique answers
function makeChallenges(n) {
  var challenges = [];
  for (var i = 0; i < n; i++) {
    challenges.push(
      gifCaptcha.createChallenge({
        id: "perf-" + i,
        title: "Challenge " + i,
        gifUrl: "https://example.com/" + i + ".gif",
        humanAnswer: "answer number " + i + " with unique words like " +
          String.fromCharCode(97 + (i % 26)) + " special",
        keywords: ["word" + i],
      })
    );
  }
  return challenges;
}

describe("SetAnalyzer pairwise similarity caching", function () {
  it("findSimilarPairs returns consistent results across calls", function () {
    var analyzer = gifCaptcha.createSetAnalyzer(makeChallenges(10));
    var pairs1 = analyzer.findSimilarPairs(0);
    var pairs2 = analyzer.findSimilarPairs(0);
    assert.deepStrictEqual(pairs1, pairs2);
  });

  it("findSimilarPairs with different thresholds uses same cache", function () {
    var analyzer = gifCaptcha.createSetAnalyzer(makeChallenges(10));
    var all = analyzer.findSimilarPairs(0);
    var high = analyzer.findSimilarPairs(0.5);
    // All high-threshold pairs must be a subset of zero-threshold pairs
    high.forEach(function (p) {
      var found = all.some(function (a) {
        return a.idA === p.idA && a.idB === p.idB &&
          Math.abs(a.similarity - p.similarity) < 0.001;
      });
      assert.ok(found, "Pair " + p.idA + "-" + p.idB + " should exist in full set");
    });
  });

  it("diversityScore and findSimilarPairs produce consistent similarities", function () {
    var challenges = makeChallenges(5);
    var analyzer = gifCaptcha.createSetAnalyzer(challenges);
    var pairs = analyzer.findSimilarPairs(0);
    var diversity = analyzer.diversityScore();
    // Both should reflect the same underlying pairwise data
    assert.ok(typeof diversity.score === "number");
    assert.ok(diversity.score >= 0 && diversity.score <= 100);
    // If all pairs have low similarity, diversity should be high
    var maxSim = pairs.reduce(function (m, p) {
      return Math.max(m, p.similarity);
    }, 0);
    if (maxSim < 0.3) {
      assert.ok(diversity.breakdown.answerDiversity > 70,
        "High dissimilarity should yield high diversity score");
    }
  });

  it("generateReport calls do not change results", function () {
    var analyzer = gifCaptcha.createSetAnalyzer(makeChallenges(8));
    var report1 = analyzer.generateReport();
    var report2 = analyzer.generateReport();
    assert.deepStrictEqual(report1.similarPairs, report2.similarPairs);
    assert.deepStrictEqual(report1.duplicates, report2.duplicates);
    assert.deepStrictEqual(report1.diversity, report2.diversity);
    assert.deepStrictEqual(report1.overallQuality, report2.overallQuality);
  });

  it("generateReport duplicates are subset of similarPairs", function () {
    var analyzer = gifCaptcha.createSetAnalyzer(makeChallenges(6));
    var report = analyzer.generateReport();
    report.duplicates.forEach(function (d) {
      var found = report.similarPairs.some(function (p) {
        return p.idA === d.idA && p.idB === d.idB;
      });
      assert.ok(found, "Duplicate should appear in similarPairs");
    });
    // All duplicates have similarity >= 0.85
    report.duplicates.forEach(function (d) {
      assert.ok(d.similarity >= 0.85);
    });
  });
});

describe("DifficultyCalibrator findOutliers reuse", function () {
  function makeCalibrator() {
    var challenges = makeChallenges(5);
    var cal = gifCaptcha.createDifficultyCalibrator(challenges);
    for (var i = 0; i < 5; i++) {
      for (var j = 0; j < 10; j++) {
        cal.recordResponse("perf-" + i, {
          timeMs: 1000 + i * 500 + j * 100,
          correct: j < (8 - i), // harder challenges have lower accuracy
          skipped: false,
        });
      }
    }
    return cal;
  }

  it("findOutliers with precomputed calibration matches standalone", function () {
    var cal = makeCalibrator();
    var calibrated = cal.calibrateAll();
    var outliersStandalone = cal.findOutliers(20);
    var outliersPrecomp = cal.findOutliers(20, calibrated);
    assert.deepStrictEqual(outliersStandalone, outliersPrecomp);
  });

  it("generateReport produces consistent results across calls", function () {
    var cal = makeCalibrator();
    var report1 = cal.generateReport();
    var report2 = cal.generateReport();
    assert.strictEqual(report1.avgDifficulty, report2.avgDifficulty);
    assert.deepStrictEqual(report1.distribution, report2.distribution);
    assert.strictEqual(report1.outlierCount, report2.outlierCount);
    assert.strictEqual(report1.calibratedCount, report2.calibratedCount);
  });

  it("getDifficultyDistribution with precomputed matches standalone", function () {
    var cal = makeCalibrator();
    var calibrated = cal.calibrateAll();
    var distStandalone = cal.getDifficultyDistribution();
    var distPrecomp = cal.getDifficultyDistribution(calibrated);
    assert.deepStrictEqual(distStandalone, distPrecomp);
  });

  it("findOutliers threshold still works with precomputed data", function () {
    var cal = makeCalibrator();
    var calibrated = cal.calibrateAll();
    var outliers0 = cal.findOutliers(0, calibrated);
    var outliers100 = cal.findOutliers(100, calibrated);
    assert.ok(outliers0.length >= outliers100.length);
    outliers100.forEach(function (o) {
      assert.ok(Math.abs(o.delta) >= 100);
    });
  });

  it("findOutliers still validates threshold", function () {
    var cal = makeCalibrator();
    assert.throws(function () {
      cal.findOutliers(-5);
    }, /threshold must be a non-negative number/);
  });
});
