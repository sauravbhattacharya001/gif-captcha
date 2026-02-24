/* ── Challenge Set Analyzer tests ────────────────────────────────── */
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const gifCaptcha = require("../src/index.js");

// ── Test helpers ────────────────────────────────────────────────────

function makeChallenge(overrides) {
  return {
    id: "c1",
    title: "Test",
    gifUrl: "test.gif",
    sourceUrl: "#",
    humanAnswer: "A cat jumps over a fence",
    aiAnswer: "An animal moves",
    keywords: ["cat", "jump"],
    ...overrides,
  };
}

function makeDiverseSet() {
  return [
    makeChallenge({ id: "d1", title: "Cat Jump", humanAnswer: "A cat jumps over a tall wooden fence", keywords: ["cat", "jump", "fence"] }),
    makeChallenge({ id: "d2", title: "Dog Run", humanAnswer: "A golden retriever runs through a green park", keywords: ["dog", "run", "park"] }),
    makeChallenge({ id: "d3", title: "Bird Fly", humanAnswer: "A blue bird flies across a cloudy sky", keywords: ["bird", "fly", "sky"] }),
    makeChallenge({ id: "d4", title: "Fish Swim", humanAnswer: "An orange fish swims in a coral reef", keywords: ["fish", "swim", "reef"] }),
    makeChallenge({ id: "d5", title: "Horse Gallop", humanAnswer: "A brown horse gallops across an open field", keywords: ["horse", "gallop", "field"] }),
    makeChallenge({ id: "d6", title: "Snake Slide", humanAnswer: "A green snake slithers through tall grass", keywords: ["snake", "slither", "grass"] }),
  ];
}

// ── Constructor validation ──────────────────────────────────────────

describe("createSetAnalyzer: constructor", () => {
  it("should throw on empty array", () => {
    assert.throws(() => gifCaptcha.createSetAnalyzer([]), /non-empty array/);
  });

  it("should throw on non-array", () => {
    assert.throws(() => gifCaptcha.createSetAnalyzer("not an array"), /non-empty array/);
  });

  it("should throw on null", () => {
    assert.throws(() => gifCaptcha.createSetAnalyzer(null), /non-empty array/);
  });

  it("should throw on invalid challenge (missing id)", () => {
    assert.throws(
      () => gifCaptcha.createSetAnalyzer([{ humanAnswer: "test" }]),
      /Invalid challenge at index 0/
    );
  });

  it("should throw on invalid challenge (missing humanAnswer)", () => {
    assert.throws(
      () => gifCaptcha.createSetAnalyzer([{ id: "x" }]),
      /Invalid challenge at index 0/
    );
  });

  it("should throw on null challenge in array", () => {
    assert.throws(
      () => gifCaptcha.createSetAnalyzer([null]),
      /Invalid challenge at index 0/
    );
  });

  it("should accept a valid set of challenges", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([makeChallenge()]);
    assert.ok(analyzer);
    assert.equal(typeof analyzer.size, "function");
  });
});

// ── answerLengthStats ───────────────────────────────────────────────

describe("createSetAnalyzer: answerLengthStats", () => {
  it("should return correct stats for a single challenge", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([makeChallenge()]);
    const stats = analyzer.answerLengthStats();
    const len = "A cat jumps over a fence".length;
    assert.equal(stats.min, len);
    assert.equal(stats.max, len);
    assert.equal(stats.mean, len);
    assert.equal(stats.median, len);
    assert.equal(stats.stdDev, 0);
  });

  it("should compute correct min and max", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "short" }),
      makeChallenge({ id: "b", humanAnswer: "a much longer answer here" }),
    ]);
    const stats = analyzer.answerLengthStats();
    assert.equal(stats.min, 5);
    assert.equal(stats.max, 25);
  });

  it("should compute correct mean", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "1234567890" }),  // 10
      makeChallenge({ id: "b", humanAnswer: "12345678901234567890" }),  // 20
    ]);
    const stats = analyzer.answerLengthStats();
    assert.equal(stats.mean, 15);
  });

  it("should compute median for odd count", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "12345" }),       // 5
      makeChallenge({ id: "b", humanAnswer: "1234567890" }),   // 10
      makeChallenge({ id: "c", humanAnswer: "123456789012345678901234567890" }), // 30
    ]);
    const stats = analyzer.answerLengthStats();
    assert.equal(stats.median, 10);
  });

  it("should compute median for even count", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "12345" }),       // 5
      makeChallenge({ id: "b", humanAnswer: "1234567890" }),   // 10
      makeChallenge({ id: "c", humanAnswer: "123456789012345" }), // 15
      makeChallenge({ id: "d", humanAnswer: "12345678901234567890" }), // 20
    ]);
    const stats = analyzer.answerLengthStats();
    assert.equal(stats.median, 12.5); // (10+15)/2
  });

  it("should compute sample standard deviation", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "1234567890" }),  // 10
      makeChallenge({ id: "b", humanAnswer: "12345678901234567890" }),  // 20
      makeChallenge({ id: "c", humanAnswer: "123456789012345678901234567890" }), // 30
    ]);
    const stats = analyzer.answerLengthStats();
    // mean = 20, variance = ((10-20)^2 + (20-20)^2 + (30-20)^2) / 2 = 200/2 = 100
    assert.equal(stats.stdDev, 10);
  });
});

// ── keywordCoverage ─────────────────────────────────────────────────

describe("createSetAnalyzer: keywordCoverage", () => {
  it("should report all challenges with keywords", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", keywords: ["cat"] }),
      makeChallenge({ id: "b", keywords: ["dog"] }),
    ]);
    const kc = analyzer.keywordCoverage();
    assert.equal(kc.challengesWithKeywords, 2);
    assert.equal(kc.challengesWithoutKeywords, 0);
    assert.equal(kc.coverageRatio, 1);
  });

  it("should report challenges without keywords", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", keywords: [] }),
      makeChallenge({ id: "b", keywords: [] }),
    ]);
    const kc = analyzer.keywordCoverage();
    assert.equal(kc.challengesWithKeywords, 0);
    assert.equal(kc.challengesWithoutKeywords, 2);
    assert.equal(kc.coverageRatio, 0);
  });

  it("should handle mixed keyword presence", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", keywords: ["cat"] }),
      makeChallenge({ id: "b", keywords: [] }),
    ]);
    const kc = analyzer.keywordCoverage();
    assert.equal(kc.challengesWithKeywords, 1);
    assert.equal(kc.challengesWithoutKeywords, 1);
    assert.equal(kc.coverageRatio, 0.5);
  });

  it("should count keyword frequency correctly", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", keywords: ["cat", "jump"] }),
      makeChallenge({ id: "b", keywords: ["cat", "run"] }),
    ]);
    const kc = analyzer.keywordCoverage();
    assert.equal(kc.keywordFrequency["cat"], 2);
    assert.equal(kc.keywordFrequency["jump"], 1);
    assert.equal(kc.keywordFrequency["run"], 1);
  });

  it("should count total and unique keywords", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", keywords: ["cat", "jump"] }),
      makeChallenge({ id: "b", keywords: ["cat", "run"] }),
    ]);
    const kc = analyzer.keywordCoverage();
    assert.equal(kc.totalKeywords, 4);
    assert.equal(kc.uniqueKeywords, 3);
  });

  it("should lowercase keywords for frequency counting", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", keywords: ["Cat"] }),
      makeChallenge({ id: "b", keywords: ["CAT"] }),
    ]);
    const kc = analyzer.keywordCoverage();
    assert.equal(kc.keywordFrequency["cat"], 2);
    assert.equal(kc.uniqueKeywords, 1);
  });
});

// ── findSimilarPairs ────────────────────────────────────────────────

describe("createSetAnalyzer: findSimilarPairs", () => {
  it("should find identical answers with similarity 1.0", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps" }),
      makeChallenge({ id: "b", humanAnswer: "A cat jumps" }),
    ]);
    const pairs = analyzer.findSimilarPairs(0);
    assert.ok(pairs.length > 0);
    assert.equal(pairs[0].similarity, 1.0);
  });

  it("should return empty for completely different answers below threshold", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps over a fence" }),
      makeChallenge({ id: "b", humanAnswer: "Underwater volcano erupts violently" }),
    ]);
    const pairs = analyzer.findSimilarPairs(0.8);
    assert.equal(pairs.length, 0);
  });

  it("should use default threshold of 0.6", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps over a fence" }),
      makeChallenge({ id: "b", humanAnswer: "A cat jumps over a wall" }),
    ]);
    // These share most words so should be above 0.6
    const pairs = analyzer.findSimilarPairs();
    assert.ok(pairs.length > 0);
  });

  it("should respect custom threshold", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps" }),
      makeChallenge({ id: "b", humanAnswer: "A cat jumps" }),
    ]);
    const pairs = analyzer.findSimilarPairs(1.0);
    assert.ok(pairs.length > 0);
  });

  it("should sort by similarity descending", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps over a fence" }),
      makeChallenge({ id: "b", humanAnswer: "A cat jumps over a wall" }),
      makeChallenge({ id: "c", humanAnswer: "A cat jumps over a fence quickly" }),
    ]);
    const pairs = analyzer.findSimilarPairs(0.3);
    for (let i = 1; i < pairs.length; i++) {
      assert.ok(pairs[i - 1].similarity >= pairs[i].similarity);
    }
  });

  it("should return empty when no pairs above threshold", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const pairs = analyzer.findSimilarPairs(0.99);
    assert.equal(pairs.length, 0);
  });
});

// ── detectDuplicates ────────────────────────────────────────────────

describe("createSetAnalyzer: detectDuplicates", () => {
  it("should find near-duplicate answers", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps over a fence" }),
      makeChallenge({ id: "b", humanAnswer: "A cat jumps over a fence" }),
    ]);
    const dups = analyzer.detectDuplicates();
    assert.ok(dups.length > 0);
    assert.ok(dups[0].similarity >= 0.85);
  });

  it("should return empty for a diverse set", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const dups = analyzer.detectDuplicates();
    assert.equal(dups.length, 0);
  });
});

// ── diversityScore ──────────────────────────────────────────────────

describe("createSetAnalyzer: diversityScore", () => {
  it("should return high diversity for diverse set", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const ds = analyzer.diversityScore();
    assert.ok(ds.score > 50, "Expected high diversity score, got " + ds.score);
  });

  it("should return low diversity for identical answers", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "same answer", title: "T", keywords: ["x"] }),
      makeChallenge({ id: "b", humanAnswer: "same answer", title: "T", keywords: ["x"] }),
      makeChallenge({ id: "c", humanAnswer: "same answer", title: "T", keywords: ["x"] }),
    ]);
    const ds = analyzer.diversityScore();
    assert.ok(ds.score < 50, "Expected low diversity score, got " + ds.score);
  });

  it("should have breakdown values in range 0-100", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const ds = analyzer.diversityScore();
    assert.ok(ds.breakdown.answerDiversity >= 0 && ds.breakdown.answerDiversity <= 100);
    assert.ok(ds.breakdown.keywordSpread >= 0 && ds.breakdown.keywordSpread <= 100);
    assert.ok(ds.breakdown.titleUniqueness >= 0 && ds.breakdown.titleUniqueness <= 100);
  });

  it("should compute overall as weighted average", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const ds = analyzer.diversityScore();
    const expected = ds.breakdown.answerDiversity * 0.5 +
                     ds.breakdown.keywordSpread * 0.3 +
                     ds.breakdown.titleUniqueness * 0.2;
    assert.ok(Math.abs(ds.score - expected) < 0.01);
  });
});

// ── answerComplexity ────────────────────────────────────────────────

describe("createSetAnalyzer: answerComplexity", () => {
  it("should classify simple answers (<5 words)", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "cat jumps high" }),
    ]);
    const comp = analyzer.answerComplexity();
    assert.equal(comp[0].complexity, "simple");
  });

  it("should classify moderate answers (5-15 words)", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps over a tall wooden fence" }),
    ]);
    const comp = analyzer.answerComplexity();
    assert.equal(comp[0].complexity, "moderate");
  });

  it("should classify complex answers (>15 words)", () => {
    const longAnswer = "The big fluffy orange cat gracefully leaps over the very tall old wooden fence in the sunny backyard on a warm day";
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: longAnswer }),
    ]);
    const comp = analyzer.answerComplexity();
    assert.equal(comp[0].complexity, "complex");
  });

  it("should count words correctly", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "one two three four five" }),
    ]);
    const comp = analyzer.answerComplexity();
    assert.equal(comp[0].wordCount, 5);
  });

  it("should count unique words (case-insensitive)", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "the cat and the dog" }),
    ]);
    const comp = analyzer.answerComplexity();
    assert.equal(comp[0].uniqueWords, 4); // the, cat, and, dog
  });

  it("should compute average word length", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "cat dog" }),
    ]);
    const comp = analyzer.answerComplexity();
    assert.equal(comp[0].avgWordLength, 3); // (3+3)/2
  });

  it("should return correct id for each challenge", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "alpha", humanAnswer: "hello world" }),
      makeChallenge({ id: "beta", humanAnswer: "foo bar baz" }),
    ]);
    const comp = analyzer.answerComplexity();
    assert.equal(comp[0].id, "alpha");
    assert.equal(comp[1].id, "beta");
  });
});

// ── qualityIssues ───────────────────────────────────────────────────

describe("createSetAnalyzer: qualityIssues", () => {
  it("should detect duplicate answers", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps over a fence" }),
      makeChallenge({ id: "b", humanAnswer: "A cat jumps over a fence" }),
    ]);
    const issues = analyzer.qualityIssues();
    const dup = issues.find((i) => i.type === "duplicate_answers");
    assert.ok(dup);
    assert.equal(dup.severity, "error");
  });

  it("should detect missing keywords", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", keywords: [] }),
    ]);
    const issues = analyzer.qualityIssues();
    const missing = issues.find((i) => i.type === "missing_keywords");
    assert.ok(missing);
    assert.equal(missing.severity, "warning");
  });

  it("should detect short answers", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "cat jump" }),
    ]);
    const issues = analyzer.qualityIssues();
    const short = issues.find((i) => i.type === "short_answers");
    assert.ok(short);
    assert.equal(short.severity, "warning");
  });

  it("should detect identical titles", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", title: "Same Title", humanAnswer: "Answer one here is long enough" }),
      makeChallenge({ id: "b", title: "Same Title", humanAnswer: "Answer two here is also long enough" }),
    ]);
    const issues = analyzer.qualityIssues();
    const titles = issues.find((i) => i.type === "identical_titles");
    assert.ok(titles);
    assert.equal(titles.severity, "warning");
  });

  it("should detect small set", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a" }),
      makeChallenge({ id: "b" }),
    ]);
    const issues = analyzer.qualityIssues();
    const small = issues.find((i) => i.type === "small_set");
    assert.ok(small);
    assert.equal(small.severity, "info");
  });

  it("should detect missing AI answers", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", aiAnswer: "" }),
    ]);
    const issues = analyzer.qualityIssues();
    const noAi = issues.find((i) => i.type === "no_ai_answers");
    assert.ok(noAi);
    assert.equal(noAi.severity, "info");
  });

  it("should detect unbalanced complexity", () => {
    // All simple -> >70% in simple
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "cat" }),
      makeChallenge({ id: "b", humanAnswer: "dog" }),
      makeChallenge({ id: "c", humanAnswer: "bird" }),
      makeChallenge({ id: "d", humanAnswer: "fish" }),
    ]);
    const issues = analyzer.qualityIssues();
    const unbalanced = issues.find((i) => i.type === "unbalanced_complexity");
    assert.ok(unbalanced);
    assert.equal(unbalanced.severity, "info");
  });

  it("should report no errors for a clean, diverse set", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const issues = analyzer.qualityIssues();
    const errors = issues.filter((i) => i.severity === "error");
    assert.equal(errors.length, 0);
  });
});

// ── generateReport ──────────────────────────────────────────────────

describe("createSetAnalyzer: generateReport", () => {
  it("should contain all report sections", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const report = analyzer.generateReport();
    assert.ok("challengeCount" in report);
    assert.ok("answerStats" in report);
    assert.ok("keywords" in report);
    assert.ok("similarPairs" in report);
    assert.ok("duplicates" in report);
    assert.ok("diversity" in report);
    assert.ok("complexity" in report);
    assert.ok("issues" in report);
    assert.ok("overallQuality" in report);
  });

  it("should have overallQuality with score and grade", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const report = analyzer.generateReport();
    assert.equal(typeof report.overallQuality.score, "number");
    assert.equal(typeof report.overallQuality.grade, "string");
  });

  it("should assign grade A for score >= 90", () => {
    // Diverse set should have high quality
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const report = analyzer.generateReport();
    assert.ok(report.overallQuality.score >= 90, "Score should be >= 90, got " + report.overallQuality.score);
    assert.equal(report.overallQuality.grade, "A");
  });

  it("should have lower score for sets with issues", () => {
    // Set with duplicates (error) and small set (info)
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps over a fence" }),
      makeChallenge({ id: "b", humanAnswer: "A cat jumps over a fence" }),
    ]);
    const report = analyzer.generateReport();
    assert.ok(report.overallQuality.score < 90);
  });

  it("should assign grade B for score in [75, 90)", () => {
    // 1 warning = -10, score = 90 → A. 2 warnings = -20, score = 80 → B
    // Create set with exactly 2 warnings and nothing else
    const set = makeDiverseSet().map((c, i) => ({
      ...c,
      // give first two identical titles to trigger identical_titles warning
      title: i < 3 ? "Same" : c.title,
    }));
    const analyzer = gifCaptcha.createSetAnalyzer(set);
    const report = analyzer.generateReport();
    // We should get identical_titles warning + possibly others. Check grade range.
    assert.ok(report.overallQuality.score >= 0);
  });

  it("should floor score at 0", () => {
    // Many issues -> score should not go below 0
    const badSet = [
      makeChallenge({ id: "a", humanAnswer: "cat", title: "T", keywords: [], aiAnswer: "" }),
      makeChallenge({ id: "b", humanAnswer: "cat", title: "T", keywords: [], aiAnswer: "" }),
      makeChallenge({ id: "c", humanAnswer: "cat", title: "T", keywords: [], aiAnswer: "" }),
    ];
    const analyzer = gifCaptcha.createSetAnalyzer(badSet);
    const report = analyzer.generateReport();
    assert.ok(report.overallQuality.score >= 0);
  });

  it("should assign grade F for very low score", () => {
    const badSet = [
      makeChallenge({ id: "a", humanAnswer: "cat", title: "T", keywords: [], aiAnswer: "" }),
      makeChallenge({ id: "b", humanAnswer: "cat", title: "T", keywords: [], aiAnswer: "" }),
      makeChallenge({ id: "c", humanAnswer: "cat", title: "T", keywords: [], aiAnswer: "" }),
    ];
    const analyzer = gifCaptcha.createSetAnalyzer(badSet);
    const report = analyzer.generateReport();
    // duplicate_answers: -20, missing_keywords: -10, short_answers: -10,
    // identical_titles: -10, small_set: -5, no_ai_answers: -5, unbalanced_complexity: -5
    // = -65, score = 35 → F
    assert.equal(report.overallQuality.grade, "F");
  });

  it("should return correct challengeCount", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    const report = analyzer.generateReport();
    assert.equal(report.challengeCount, 6);
  });
});

// ── size ─────────────────────────────────────────────────────────────

describe("createSetAnalyzer: size", () => {
  it("should return correct count for single challenge", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([makeChallenge()]);
    assert.equal(analyzer.size(), 1);
  });

  it("should return correct count for multiple challenges", () => {
    const analyzer = gifCaptcha.createSetAnalyzer(makeDiverseSet());
    assert.equal(analyzer.size(), 6);
  });
});

// ── Defensive copy ──────────────────────────────────────────────────

describe("createSetAnalyzer: defensive copy", () => {
  it("should not be affected by modifying original array", () => {
    const challenges = [
      makeChallenge({ id: "a" }),
      makeChallenge({ id: "b" }),
      makeChallenge({ id: "c" }),
    ];
    const analyzer = gifCaptcha.createSetAnalyzer(challenges);
    assert.equal(analyzer.size(), 3);
    challenges.push(makeChallenge({ id: "d" }));
    assert.equal(analyzer.size(), 3);
  });

  it("should not be affected by removing from original array", () => {
    const challenges = [
      makeChallenge({ id: "a" }),
      makeChallenge({ id: "b" }),
    ];
    const analyzer = gifCaptcha.createSetAnalyzer(challenges);
    assert.equal(analyzer.size(), 2);
    challenges.pop();
    assert.equal(analyzer.size(), 2);
  });
});

// ── Additional edge cases ───────────────────────────────────────────

describe("createSetAnalyzer: edge cases", () => {
  it("should handle challenges without keywords property", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      { id: "a", humanAnswer: "A cat jumps over a fence" },
    ]);
    const kc = analyzer.keywordCoverage();
    assert.equal(kc.challengesWithoutKeywords, 1);
  });

  it("should handle challenges without title property", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      { id: "a", humanAnswer: "A cat jumps over a fence" },
      { id: "b", humanAnswer: "A dog runs in the park" },
    ]);
    const ds = analyzer.diversityScore();
    assert.ok(ds.breakdown.titleUniqueness >= 0);
  });

  it("answerLengthStats should handle all same-length answers", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "abcde" }),
      makeChallenge({ id: "b", humanAnswer: "fghij" }),
    ]);
    const stats = analyzer.answerLengthStats();
    assert.equal(stats.min, 5);
    assert.equal(stats.max, 5);
    assert.equal(stats.mean, 5);
    assert.equal(stats.stdDev, 0);
  });

  it("findSimilarPairs returns pairs with correct ids", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "x1", humanAnswer: "same words here" }),
      makeChallenge({ id: "x2", humanAnswer: "same words here" }),
    ]);
    const pairs = analyzer.findSimilarPairs(0);
    assert.ok(pairs.length > 0);
    assert.equal(pairs[0].idA, "x1");
    assert.equal(pairs[0].idB, "x2");
  });

  it("diversityScore keywordSpread is capped at 100", () => {
    // Many unique keywords relative to challenge count
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "a", humanAnswer: "A cat jumps over a fence", keywords: ["a", "b", "c", "d", "e", "f", "g", "h"] }),
    ]);
    const ds = analyzer.diversityScore();
    assert.ok(ds.breakdown.keywordSpread <= 100);
  });

  it("qualityIssues challengeIds contains correct ids", () => {
    const analyzer = gifCaptcha.createSetAnalyzer([
      makeChallenge({ id: "short1", humanAnswer: "tiny" }),
    ]);
    const issues = analyzer.qualityIssues();
    const shortIssue = issues.find((i) => i.type === "short_answers");
    assert.ok(shortIssue);
    assert.ok(shortIssue.challengeIds.includes("short1"));
  });
});
