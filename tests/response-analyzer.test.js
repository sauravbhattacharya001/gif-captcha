const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { createResponseAnalyzer, textSimilarity } = require("../src/index");

// ── createResponseAnalyzer ──────────────────────────────────────────

describe("createResponseAnalyzer", function () {

  describe("initialization", function () {
    it("creates analyzer with default config", function () {
      var a = createResponseAnalyzer();
      var c = a.getConfig();
      assert.equal(c.minResponseTimeMs, 800);
      assert.equal(c.maxTimingCvThreshold, 0.15);
      assert.equal(c.duplicateThreshold, 0.85);
      assert.equal(c.minWordDiversity, 0.4);
    });

    it("accepts custom config", function () {
      var a = createResponseAnalyzer({
        minResponseTimeMs: 500,
        maxTimingCvThreshold: 0.1,
        duplicateThreshold: 0.9,
        minWordDiversity: 0.3
      });
      var c = a.getConfig();
      assert.equal(c.minResponseTimeMs, 500);
      assert.equal(c.maxTimingCvThreshold, 0.1);
      assert.equal(c.duplicateThreshold, 0.9);
      assert.equal(c.minWordDiversity, 0.3);
    });

    it("returns all expected methods", function () {
      var a = createResponseAnalyzer();
      assert.equal(typeof a.analyzeTiming, "function");
      assert.equal(typeof a.analyzeResponse, "function");
      assert.equal(typeof a.detectDuplicateResponses, "function");
      assert.equal(typeof a.scoreSubmissions, "function");
      assert.equal(typeof a.getConfig, "function");
    });
  });

  // ── analyzeTiming ─────────────────────────────────────────────────

  describe("analyzeTiming", function () {
    var analyzer;
    beforeEach(function () { analyzer = createResponseAnalyzer(); });

    it("handles empty array", function () {
      var r = analyzer.analyzeTiming([]);
      assert.equal(r.avgMs, 0);
      assert.ok(r.suspicionFlags.includes("no_timing_data"));
    });

    it("handles null input", function () {
      var r = analyzer.analyzeTiming(null);
      assert.ok(r.suspicionFlags.includes("no_timing_data"));
    });

    it("calculates average correctly", function () {
      var r = analyzer.analyzeTiming([1000, 2000, 3000]);
      assert.equal(r.avgMs, 2000);
    });

    it("calculates median for odd count", function () {
      var r = analyzer.analyzeTiming([1000, 3000, 5000]);
      assert.equal(r.medianMs, 3000);
    });

    it("calculates median for even count", function () {
      var r = analyzer.analyzeTiming([1000, 2000, 3000, 4000]);
      assert.equal(r.medianMs, 2500);
    });

    it("detects too-fast responses", function () {
      var r = analyzer.analyzeTiming([100, 200, 5000]);
      assert.equal(r.tooFastCount, 2);
      assert.ok(r.suspicionFlags.includes("fast_responses:2"));
    });

    it("flags all-fast submissions", function () {
      var r = analyzer.analyzeTiming([100, 200, 300]);
      assert.equal(r.tooFastCount, 3);
      assert.ok(r.suspicionFlags.includes("all_responses_suspiciously_fast"));
    });

    it("detects uniform timing (bot-like)", function () {
      var r = analyzer.analyzeTiming([5000, 5010, 5020, 5005]);
      assert.equal(r.isUniform, true);
      assert.ok(r.suspicionFlags.includes("uniform_timing"));
    });

    it("human-like timing is not uniform", function () {
      var r = analyzer.analyzeTiming([2000, 5000, 1500, 8000, 3000]);
      assert.equal(r.isUniform, false);
    });

    it("single response has no uniform flag", function () {
      var r = analyzer.analyzeTiming([3000]);
      assert.equal(r.isUniform, false);
      assert.equal(r.avgMs, 3000);
    });

    it("stdDev is zero for single value", function () {
      var r = analyzer.analyzeTiming([5000]);
      assert.equal(r.stdDevMs, 0);
    });

    it("cv is positive for varied times", function () {
      var r = analyzer.analyzeTiming([2000, 4000, 6000, 8000]);
      assert.ok(r.cv > 0);
      assert.ok(r.cv < 1);
    });

    it("flags avg below threshold", function () {
      var r = analyzer.analyzeTiming([100, 200, 300, 400]);
      assert.ok(r.suspicionFlags.includes("avg_below_threshold"));
    });

    it("no flags for normal timing", function () {
      var r = analyzer.analyzeTiming([3000, 5000, 7000, 4000, 6000]);
      assert.equal(r.tooFastCount, 0);
      assert.equal(r.isUniform, false);
      assert.equal(r.suspicionFlags.length, 0);
    });
  });

  // ── analyzeResponse ───────────────────────────────────────────────

  describe("analyzeResponse", function () {
    var analyzer;
    beforeEach(function () { analyzer = createResponseAnalyzer(); });

    it("handles empty string", function () {
      var r = analyzer.analyzeResponse("");
      assert.equal(r.wordCount, 0);
      assert.equal(r.specificity, "empty");
    });

    it("handles null input", function () {
      var r = analyzer.analyzeResponse(null);
      assert.equal(r.wordCount, 0);
      assert.equal(r.specificity, "empty");
    });

    it("counts words correctly", function () {
      var r = analyzer.analyzeResponse("The cat jumped off the table");
      assert.equal(r.wordCount, 6);
    });

    it("calculates unique words", function () {
      var r = analyzer.analyzeResponse("the cat and the dog");
      assert.equal(r.wordCount, 5);
      assert.equal(r.uniqueWords, 4);
    });

    it("type-token ratio 1.0 for all unique", function () {
      var r = analyzer.analyzeResponse("cat dog bird fish");
      assert.equal(r.typeTokenRatio, 1.0);
    });

    it("type-token ratio reflects repetition", function () {
      var r = analyzer.analyzeResponse("yes yes yes yes");
      assert.equal(r.typeTokenRatio, 0.25);
    });

    it("detects descriptive words", function () {
      var r = analyzer.analyzeResponse("The cat suddenly jumped off the table");
      assert.equal(r.hasDescriptiveWords, true);
    });

    it("no descriptive words in plain text", function () {
      var r = analyzer.analyzeResponse("cat table");
      assert.equal(r.hasDescriptiveWords, false);
    });

    it("specificity: vague for 1-2 words", function () {
      var r = analyzer.analyzeResponse("yes");
      assert.equal(r.specificity, "vague");
    });

    it("specificity: low for 3-5 words without descriptive", function () {
      var r = analyzer.analyzeResponse("a cat fell down");
      assert.equal(r.specificity, "low");
    });

    it("specificity: moderate for 6-10 words", function () {
      var r = analyzer.analyzeResponse("The person tripped over the rope and fell");
      assert.equal(r.specificity, "moderate");
    });

    it("specificity: detailed for 11+ words", function () {
      var r = analyzer.analyzeResponse("The person was walking down the street when a car appeared from behind the corner");
      assert.equal(r.specificity, "detailed");
    });

    it("calculates average word length", function () {
      var r = analyzer.analyzeResponse("cat dog");
      assert.equal(r.avgWordLength, 3);
    });

    it("strips punctuation for tokenization", function () {
      var r = analyzer.analyzeResponse("Hello, world! How are you?");
      assert.equal(r.wordCount, 5);
    });
  });

  // ── detectDuplicateResponses ──────────────────────────────────────

  describe("detectDuplicateResponses", function () {
    var analyzer;
    beforeEach(function () { analyzer = createResponseAnalyzer(); });

    it("no duplicates in unique responses", function () {
      var r = analyzer.detectDuplicateResponses([
        "The cat jumped off the table",
        "A car drove through the wall",
        "The bird flew into the window"
      ]);
      assert.equal(r.duplicateCount, 0);
      assert.equal(r.duplicatePairs.length, 0);
      assert.equal(r.uniqueRatio, 1);
    });

    it("detects exact duplicates", function () {
      var r = analyzer.detectDuplicateResponses([
        "The cat jumped off the table",
        "The cat jumped off the table",
        "A completely different response"
      ]);
      assert.equal(r.duplicateCount, 2);
      assert.equal(r.duplicatePairs.length, 1);
      assert.ok(r.duplicatePairs[0].similarity >= 0.85);
    });

    it("handles single response", function () {
      var r = analyzer.detectDuplicateResponses(["single response"]);
      assert.equal(r.duplicateCount, 0);
      assert.equal(r.uniqueRatio, 1);
    });

    it("handles empty array", function () {
      var r = analyzer.detectDuplicateResponses([]);
      assert.equal(r.duplicateCount, 0);
      assert.equal(r.uniqueRatio, 1);
    });

    it("handles null input", function () {
      var r = analyzer.detectDuplicateResponses(null);
      assert.equal(r.duplicateCount, 0);
    });

    it("uniqueRatio decreases with duplicates", function () {
      var r = analyzer.detectDuplicateResponses([
        "same response here",
        "same response here",
        "same response here",
        "completely different thing"
      ]);
      assert.ok(r.uniqueRatio < 1);
    });

    it("all identical responses give zero uniqueRatio", function () {
      var r = analyzer.detectDuplicateResponses([
        "I dont know",
        "I dont know",
        "I dont know"
      ]);
      assert.equal(r.duplicateCount, 3);
      assert.equal(r.uniqueRatio, 0);
    });
  });

  // ── scoreSubmissions ──────────────────────────────────────────────

  describe("scoreSubmissions", function () {
    var analyzer;
    beforeEach(function () { analyzer = createResponseAnalyzer(); });

    it("handles empty submissions", function () {
      var r = analyzer.scoreSubmissions([]);
      assert.equal(r.humanityScore, 0);
      assert.equal(r.verdict, "insufficient_data");
      assert.ok(r.flags.includes("no_submissions"));
    });

    it("handles null submissions", function () {
      var r = analyzer.scoreSubmissions(null);
      assert.equal(r.humanityScore, 0);
      assert.equal(r.verdict, "insufficient_data");
    });

    it("human-like submissions score high", function () {
      var r = analyzer.scoreSubmissions([
        { response: "The cat suddenly jumped off the table and ran away", timeMs: 5000 },
        { response: "A skateboarder unexpectedly flew over the ramp", timeMs: 4200 },
        { response: "The dog surprisingly started dancing with the owner", timeMs: 6100 },
        { response: "Two people then hugged each other instead of fighting", timeMs: 3800 },
      ]);
      assert.ok(r.humanityScore >= 80, "Score should be >= 80, got " + r.humanityScore);
      assert.equal(r.verdict, "likely_human");
    });

    it("bot-like submissions score low", function () {
      var r = analyzer.scoreSubmissions([
        { response: "I cannot view animations", timeMs: 100 },
        { response: "I cannot view animations", timeMs: 105 },
        { response: "I cannot view animations", timeMs: 98 },
        { response: "I cannot view animations", timeMs: 102 },
      ]);
      assert.ok(r.humanityScore < 50, "Score should be < 50, got " + r.humanityScore);
      assert.equal(r.verdict, "likely_bot");
    });

    it("mixed signals are not insufficient_data", function () {
      var r = analyzer.scoreSubmissions([
        { response: "The cat fell unexpectedly from the shelf", timeMs: 300 },
        { response: "Something happened with the dog", timeMs: 2000 },
        { response: "A person appeared out of nowhere suddenly", timeMs: 4000 },
      ]);
      assert.notEqual(r.verdict, "insufficient_data");
    });

    it("empty responses get penalized", function () {
      var r = analyzer.scoreSubmissions([
        { response: "", timeMs: 5000 },
        { response: "A real response here", timeMs: 4000 },
        { response: "", timeMs: 3000 },
      ]);
      assert.ok(r.flags.includes("empty_responses"));
      assert.ok(r.humanityScore < 100);
    });

    it("returns timing analysis", function () {
      var r = analyzer.scoreSubmissions([
        { response: "test", timeMs: 2000 },
        { response: "test two", timeMs: 3000 },
      ]);
      assert.ok(r.timing !== undefined);
      assert.ok(typeof r.timing.avgMs === "number");
    });

    it("returns linguistic analysis", function () {
      var r = analyzer.scoreSubmissions([
        { response: "The cat jumped", timeMs: 3000 },
        { response: "A dog ran away", timeMs: 4000 },
      ]);
      assert.ok(r.linguistic !== undefined);
      assert.ok(typeof r.linguistic.avgWordCount === "number");
      assert.ok(typeof r.linguistic.avgTypeTokenRatio === "number");
      assert.ok(typeof r.linguistic.descriptiveResponseCount === "number");
    });

    it("returns duplicate analysis", function () {
      var r = analyzer.scoreSubmissions([
        { response: "hello world", timeMs: 3000 },
        { response: "different response", timeMs: 4000 },
      ]);
      assert.ok(r.duplicates !== undefined);
      assert.ok(typeof r.duplicates.uniqueRatio === "number");
    });

    it("accumulates flags for suspicious submissions", function () {
      var r = analyzer.scoreSubmissions([
        { response: "", timeMs: 100 },
        { response: "", timeMs: 100 },
        { response: "", timeMs: 100 },
      ]);
      assert.ok(r.flags.length > 0);
    });

    it("score is clamped to 0-100", function () {
      var r = analyzer.scoreSubmissions([
        { response: "", timeMs: 50 },
        { response: "", timeMs: 50 },
        { response: "", timeMs: 50 },
        { response: "", timeMs: 50 },
        { response: "", timeMs: 50 },
      ]);
      assert.ok(r.humanityScore >= 0);
      assert.ok(r.humanityScore <= 100);
    });

    it("single submission works", function () {
      var r = analyzer.scoreSubmissions([
        { response: "The person suddenly tripped over the wire", timeMs: 3000 }
      ]);
      assert.ok(r.humanityScore > 0);
      assert.notEqual(r.verdict, "insufficient_data");
    });

    it("descriptive responses get bonus", function () {
      var r = analyzer.scoreSubmissions([
        { response: "The cat suddenly jumped off the table", timeMs: 5000 },
        { response: "Then the dog unexpectedly ran into the room", timeMs: 4000 },
        { response: "Surprisingly a bird appeared from behind", timeMs: 6000 },
      ]);
      assert.ok(r.humanityScore >= 90, "Score should be >= 90, got " + r.humanityScore);
    });

    it("unique responses have ratio 1", function () {
      var r = analyzer.scoreSubmissions([
        { response: "The cat jumped off the table", timeMs: 3000 },
        { response: "A car crashed through the wall", timeMs: 4000 },
        { response: "Birds flew in a funny pattern", timeMs: 5000 },
      ]);
      assert.equal(r.duplicates.uniqueRatio, 1);
    });

    it("very short responses penalized", function () {
      var r = analyzer.scoreSubmissions([
        { response: "ok", timeMs: 3000 },
        { response: "no", timeMs: 4000 },
        { response: "yes", timeMs: 5000 },
      ]);
      assert.ok(r.flags.includes("very_short_responses"));
    });

    it("specificity breakdown included", function () {
      var r = analyzer.scoreSubmissions([
        { response: "yes", timeMs: 3000 },
        { response: "The cat jumped off the table and ran away quickly", timeMs: 4000 },
      ]);
      assert.ok(r.linguistic.specificityBreakdown !== undefined);
    });
  });

  // ── Custom thresholds integration ─────────────────────────────────

  describe("custom thresholds", function () {
    it("stricter timing catches more bots", function () {
      var strict = createResponseAnalyzer({ minResponseTimeMs: 2000 });
      var r = strict.analyzeTiming([1000, 1500, 1800]);
      assert.equal(r.tooFastCount, 3);
    });

    it("looser duplicate threshold allows variation", function () {
      var loose = createResponseAnalyzer({ duplicateThreshold: 0.99 });
      var r = loose.detectDuplicateResponses([
        "The cat jumped off the table",
        "The cat jumped off the table suddenly"
      ]);
      assert.equal(r.duplicateCount, 0);
    });
  });
});
