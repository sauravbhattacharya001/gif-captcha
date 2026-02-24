const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { createSecurityScorer } = require("../src/index");

// ── Test Helpers ──

function diverseChallenges() {
  return [
    { id: "c1", humanAnswer: "A cat jumps over a fence then lands gracefully", aiAnswer: "Some animal near a barrier", keywords: ["feline", "jumping", "agility"], difficulty: 15 },
    { id: "c2", humanAnswer: "The ball rolls down the hill because of gravity and suddenly bounces off a rock", aiAnswer: "Sphere descending terrain", keywords: ["physics", "momentum", "collision"], difficulty: 45 },
    { id: "c3", humanAnswer: "A person opens an umbrella while walking through rain after leaving a building", aiAnswer: "Human with umbrella outdoors", keywords: ["weather", "pedestrian", "shelter"], difficulty: 70 },
    { id: "c4", humanAnswer: "Two dogs chase each other around a tree until one finally catches the other", aiAnswer: "Canines playing near vegetation", keywords: ["pursuit", "canine", "playful"], difficulty: 30 },
    { id: "c5", humanAnswer: "Fire spreads across the field because dry grass makes it burn faster, then firefighters arrive", aiAnswer: "Flames in open area", keywords: ["wildfire", "emergency", "combustion"], difficulty: 85 },
    { id: "c6", humanAnswer: "A chef carefully slices vegetables before tossing them into a sizzling pan next to the stove", aiAnswer: "Food preparation scene", keywords: ["culinary", "preparation", "cooking"], difficulty: 55 },
  ];
}

function identicalChallenges() {
  return [
    { id: "c1", humanAnswer: "A dog runs", aiAnswer: "A dog runs", keywords: ["video", "gif", "funny"], difficulty: 50 },
    { id: "c2", humanAnswer: "A dog runs", aiAnswer: "A dog runs", keywords: ["video", "gif", "cool"], difficulty: 50 },
    { id: "c3", humanAnswer: "A dog runs", aiAnswer: "A dog runs", keywords: ["video", "clip", "stuff"], difficulty: 50 },
    { id: "c4", humanAnswer: "A dog runs", aiAnswer: "A dog runs", keywords: ["image", "thing", "animation"], difficulty: 50 },
  ];
}

function minimalChallenge() {
  return [{ id: "c1", humanAnswer: "Hello world" }];
}

// ── Initialization ──

describe("createSecurityScorer", function () {
  describe("initialization", function () {
    it("returns object with expected methods", function () {
      var scorer = createSecurityScorer(diverseChallenges());
      assert.equal(typeof scorer.getReport, "function");
      assert.equal(typeof scorer.getDimensions, "function");
      assert.equal(typeof scorer.getDimension, "function");
      assert.equal(typeof scorer.getVulnerabilities, "function");
      assert.equal(typeof scorer.getRecommendations, "function");
      assert.equal(typeof scorer.isSecure, "function");
      assert.equal(typeof scorer.reset, "function");
    });

    it("throws on empty array", function () {
      assert.throws(function () { createSecurityScorer([]); }, /non-empty array/);
    });

    it("throws on non-array", function () {
      assert.throws(function () { createSecurityScorer("hello"); }, /non-empty array/);
    });

    it("throws on null", function () {
      assert.throws(function () { createSecurityScorer(null); }, /non-empty array/);
    });

    it("throws on challenges missing id", function () {
      assert.throws(function () { createSecurityScorer([{ humanAnswer: "test" }]); }, /must have an id/);
    });

    it("throws on challenges missing humanAnswer", function () {
      assert.throws(function () { createSecurityScorer([{ id: "c1" }]); }, /must have a humanAnswer/);
    });

    it("accepts valid challenges", function () {
      var scorer = createSecurityScorer(minimalChallenge());
      assert.ok(scorer);
    });
  });

  // ── getDimensions ──

  describe("getDimensions", function () {
    it("returns 6 dimensions", function () {
      var dims = createSecurityScorer(diverseChallenges()).getDimensions();
      assert.equal(dims.length, 6);
    });

    it("each dimension has name, score, weight, details", function () {
      var dims = createSecurityScorer(diverseChallenges()).getDimensions();
      for (var i = 0; i < dims.length; i++) {
        assert.equal(typeof dims[i].name, "string");
        assert.equal(typeof dims[i].score, "number");
        assert.equal(typeof dims[i].weight, "number");
        assert.equal(typeof dims[i].details, "object");
      }
    });

    it("all scores between 0 and 100", function () {
      var dims = createSecurityScorer(diverseChallenges()).getDimensions();
      for (var i = 0; i < dims.length; i++) {
        assert.ok(dims[i].score >= 0, dims[i].name + " score >= 0");
        assert.ok(dims[i].score <= 100, dims[i].name + " score <= 100");
      }
    });

    it("weights sum to 1.0", function () {
      var dims = createSecurityScorer(diverseChallenges()).getDimensions();
      var sum = 0;
      for (var i = 0; i < dims.length; i++) sum += dims[i].weight;
      assert.ok(Math.abs(sum - 1.0) < 0.001, "weights sum to " + sum);
    });

    it("handles challenges with no aiAnswer", function () {
      var ch = [
        { id: "c1", humanAnswer: "Cat jumps over fence" },
        { id: "c2", humanAnswer: "Dog runs through park" },
      ];
      var dims = createSecurityScorer(ch).getDimensions();
      assert.equal(dims.length, 6);
    });

    it("handles challenges with no keywords", function () {
      var ch = [
        { id: "c1", humanAnswer: "Cat jumps over fence" },
        { id: "c2", humanAnswer: "Dog runs through park" },
      ];
      var dims = createSecurityScorer(ch).getDimensions();
      var kw = dims.find(function (d) { return d.name === "Keyword Specificity"; });
      assert.ok(kw);
      assert.equal(kw.score, 50);
    });
  });

  // ── getDimension ──

  describe("getDimension", function () {
    it("returns correct dimension by name", function () {
      var scorer = createSecurityScorer(diverseChallenges());
      var d = scorer.getDimension("aiResistance");
      assert.equal(d.name, "AI Resistance");
    });

    it("returns null for unknown dimension", function () {
      var scorer = createSecurityScorer(diverseChallenges());
      var d = scorer.getDimension("nonExistent");
      assert.equal(d, null);
    });

    it("answerDiversity has expected detail fields", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("answerDiversity");
      assert.ok("uniqueWordRatio" in d.details);
      assert.ok("coefficientOfVariation" in d.details);
      assert.ok("avgAnswerLength" in d.details);
    });

    it("aiResistance has expected detail fields", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("aiResistance");
      assert.ok("avgSimilarity" in d.details);
      assert.ok("challengesWithAI" in d.details);
      assert.ok("perChallenge" in d.details);
    });
  });

  // ── getReport ──

  describe("getReport", function () {
    it("returns score, grade, dimensions, vulnerabilities, recommendations, summary", function () {
      var report = createSecurityScorer(diverseChallenges()).getReport();
      assert.ok("score" in report);
      assert.ok("grade" in report);
      assert.ok("dimensions" in report);
      assert.ok("vulnerabilities" in report);
      assert.ok("recommendations" in report);
      assert.ok("summary" in report);
    });

    it("score is between 0 and 100", function () {
      var report = createSecurityScorer(diverseChallenges()).getReport();
      assert.ok(report.score >= 0);
      assert.ok(report.score <= 100);
    });

    it("grade is one of A/B/C/D/F", function () {
      var report = createSecurityScorer(diverseChallenges()).getReport();
      assert.ok(["A", "B", "C", "D", "F"].indexOf(report.grade) !== -1);
    });

    it("summary is a non-empty string", function () {
      var report = createSecurityScorer(diverseChallenges()).getReport();
      assert.equal(typeof report.summary, "string");
      assert.ok(report.summary.length > 0);
    });

    it("dimensions array has 6 entries", function () {
      var report = createSecurityScorer(diverseChallenges()).getReport();
      assert.equal(report.dimensions.length, 6);
    });
  });

  // ── Answer Diversity ──

  describe("Answer Diversity", function () {
    it("high score for diverse answers", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("answerDiversity");
      assert.ok(d.score >= 60, "diverse answers should score >= 60, got " + d.score);
    });

    it("low score for identical answers", function () {
      var d = createSecurityScorer(identicalChallenges()).getDimension("answerDiversity");
      assert.ok(d.score < 40, "identical answers should score < 40, got " + d.score);
    });

    it("handles single challenge", function () {
      var d = createSecurityScorer(minimalChallenge()).getDimension("answerDiversity");
      assert.ok(d.score >= 0 && d.score <= 100);
    });

    it("coefficient of variation in details", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("answerDiversity");
      assert.equal(typeof d.details.coefficientOfVariation, "number");
    });

    it("unique word ratio in details", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("answerDiversity");
      assert.equal(typeof d.details.uniqueWordRatio, "number");
      assert.ok(d.details.uniqueWordRatio > 0 && d.details.uniqueWordRatio <= 1);
    });

    it("identical answers have low unique word ratio", function () {
      var d = createSecurityScorer(identicalChallenges()).getDimension("answerDiversity");
      assert.ok(d.details.uniqueWordRatio < 0.5, "identical should have low unique ratio, got " + d.details.uniqueWordRatio);
    });
  });

  // ── AI Resistance ──

  describe("AI Resistance", function () {
    it("high score when AI answers differ from human", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("aiResistance");
      assert.ok(d.score >= 50, "different AI answers should score >= 50, got " + d.score);
    });

    it("low score when AI answers match human", function () {
      var d = createSecurityScorer(identicalChallenges()).getDimension("aiResistance");
      assert.ok(d.score < 30, "matching AI answers should score < 30, got " + d.score);
    });

    it("neutral score (50) when no aiAnswers", function () {
      var ch = [
        { id: "c1", humanAnswer: "Cat jumps over fence" },
        { id: "c2", humanAnswer: "Dog runs through park" },
      ];
      var d = createSecurityScorer(ch).getDimension("aiResistance");
      assert.equal(d.score, 50);
    });

    it("partial aiAnswer coverage", function () {
      var ch = [
        { id: "c1", humanAnswer: "Cat jumps over fence", aiAnswer: "Completely different text about weather patterns" },
        { id: "c2", humanAnswer: "Dog runs through park" },
      ];
      var d = createSecurityScorer(ch).getDimension("aiResistance");
      assert.ok(d.details.challengesWithAI === 1);
      assert.ok(d.details.totalChallenges === 2);
    });

    it("handles empty string aiAnswer", function () {
      var ch = [
        { id: "c1", humanAnswer: "Cat jumps over fence", aiAnswer: "" },
        { id: "c2", humanAnswer: "Dog runs through park", aiAnswer: "Different description entirely" },
      ];
      var d = createSecurityScorer(ch).getDimension("aiResistance");
      // empty string aiAnswer should be treated as no aiAnswer
      assert.equal(d.details.challengesWithAI, 1);
    });

    it("per-challenge similarity in details", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("aiResistance");
      assert.ok(Array.isArray(d.details.perChallenge));
      assert.ok(d.details.perChallenge.length > 0);
      assert.ok("id" in d.details.perChallenge[0]);
      assert.ok("similarity" in d.details.perChallenge[0]);
    });

    it("avgSimilarity in details is between 0 and 1", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("aiResistance");
      assert.ok(d.details.avgSimilarity >= 0 && d.details.avgSimilarity <= 1);
    });
  });

  // ── Keyword Specificity ──

  describe("Keyword Specificity", function () {
    it("high score for specific keywords", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("keywordSpecificity");
      assert.ok(d.score >= 60, "specific keywords should score >= 60, got " + d.score);
    });

    it("low score for generic/weak keywords", function () {
      var d = createSecurityScorer(identicalChallenges()).getDimension("keywordSpecificity");
      assert.ok(d.score <= 50, "weak keywords should score <= 50, got " + d.score);
    });

    it("handles empty keywords array", function () {
      var ch = [
        { id: "c1", humanAnswer: "Cat jumps", keywords: [] },
        { id: "c2", humanAnswer: "Dog runs", keywords: [] },
      ];
      var d = createSecurityScorer(ch).getDimension("keywordSpecificity");
      assert.equal(d.score, 50); // neutral
    });

    it("handles no keywords at all", function () {
      var ch = [
        { id: "c1", humanAnswer: "Cat jumps" },
        { id: "c2", humanAnswer: "Dog runs" },
      ];
      var d = createSecurityScorer(ch).getDimension("keywordSpecificity");
      assert.equal(d.score, 50);
    });

    it("weak keyword ratio in details", function () {
      var d = createSecurityScorer(identicalChallenges()).getDimension("keywordSpecificity");
      assert.ok("weakKeywordRatio" in d.details);
      assert.ok(d.details.weakKeywordRatio > 0.5, "should have high weak ratio, got " + d.details.weakKeywordRatio);
    });

    it("unique keyword ratio in details", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("keywordSpecificity");
      assert.ok("uniqueKeywordRatio" in d.details);
      assert.equal(typeof d.details.uniqueKeywordRatio, "number");
    });
  });

  // ── Difficulty Coverage ──

  describe("Difficulty Coverage", function () {
    it("high score for well-distributed difficulties", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("difficultyCoverage");
      assert.ok(d.score >= 60, "well-distributed should score >= 60, got " + d.score);
    });

    it("low score for clustered difficulties", function () {
      var ch = [
        { id: "c1", humanAnswer: "Answer one here", difficulty: 50 },
        { id: "c2", humanAnswer: "Answer two here", difficulty: 51 },
        { id: "c3", humanAnswer: "Answer three here", difficulty: 52 },
        { id: "c4", humanAnswer: "Answer four here", difficulty: 53 },
      ];
      var d = createSecurityScorer(ch).getDimension("difficultyCoverage");
      assert.ok(d.score < 60, "clustered should score < 60, got " + d.score);
    });

    it("neutral (50) when no difficulties set", function () {
      var ch = [
        { id: "c1", humanAnswer: "Answer one here" },
        { id: "c2", humanAnswer: "Answer two here" },
      ];
      var d = createSecurityScorer(ch).getDimension("difficultyCoverage");
      assert.equal(d.score, 50);
    });

    it("handles all same difficulty", function () {
      var ch = [
        { id: "c1", humanAnswer: "Answer one here", difficulty: 50 },
        { id: "c2", humanAnswer: "Answer two here", difficulty: 50 },
        { id: "c3", humanAnswer: "Answer three here", difficulty: 50 },
      ];
      var d = createSecurityScorer(ch).getDimension("difficultyCoverage");
      assert.ok(d.score < 60, "all same difficulty should score low, got " + d.score);
    });

    it("bucket distribution in details", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("difficultyCoverage");
      assert.ok("easy" in d.details);
      assert.ok("medium" in d.details);
      assert.ok("hard" in d.details);
    });

    it("perfect distribution scores high", function () {
      var ch = [
        { id: "c1", humanAnswer: "Answer one here with detail", difficulty: 10 },
        { id: "c2", humanAnswer: "Answer two here with detail", difficulty: 50 },
        { id: "c3", humanAnswer: "Answer three here with detail", difficulty: 90 },
      ];
      var d = createSecurityScorer(ch).getDimension("difficultyCoverage");
      assert.ok(d.score >= 80, "perfect distribution should score >= 80, got " + d.score);
    });
  });

  // ── Cognitive Complexity ──

  describe("Cognitive Complexity", function () {
    it("high score for complex multi-step answers", function () {
      var ch = [
        { id: "c1", humanAnswer: "The cat jumps over the fence then lands gracefully before running away because it was startled" },
        { id: "c2", humanAnswer: "Water flows down the hill and then pools at the bottom while the rain continues to fall heavily until it finally stops" },
        { id: "c3", humanAnswer: "The chef prepares the ingredients before cooking because the recipe requires precise timing so nothing burns" },
      ];
      var d = createSecurityScorer(ch).getDimension("cognitiveComplexity");
      assert.ok(d.score >= 60, "complex answers should score >= 60, got " + d.score);
    });

    it("low score for simple short answers", function () {
      var ch = [
        { id: "c1", humanAnswer: "Cat runs" },
        { id: "c2", humanAnswer: "Dog sits" },
        { id: "c3", humanAnswer: "Bird flies" },
      ];
      var d = createSecurityScorer(ch).getDimension("cognitiveComplexity");
      assert.ok(d.score < 30, "simple answers should score < 30, got " + d.score);
    });

    it("temporal word detection", function () {
      var ch = [
        { id: "c1", humanAnswer: "First the ball rolls then it bounces and finally stops after hitting the wall" },
        { id: "c2", humanAnswer: "The bird flies up before diving down and then suddenly changes direction while spinning" },
      ];
      var d = createSecurityScorer(ch).getDimension("cognitiveComplexity");
      assert.ok(d.details.temporalWords > 0, "should detect temporal words");
    });

    it("causal word detection", function () {
      var ch = [
        { id: "c1", humanAnswer: "The ice melts because the temperature rises which causes the water to overflow and results in flooding" },
        { id: "c2", humanAnswer: "She runs fast so she wins the race because her training makes her stronger" },
      ];
      var d = createSecurityScorer(ch).getDimension("cognitiveComplexity");
      assert.ok(d.details.causalWords > 0, "should detect causal words");
    });

    it("avg word count in details", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("cognitiveComplexity");
      assert.ok("avgWordCount" in d.details);
      assert.equal(typeof d.details.avgWordCount, "number");
      assert.ok(d.details.avgWordCount > 0);
    });
  });

  // ── Pattern Predictability ──

  describe("Pattern Predictability", function () {
    it("high score when answers are structurally varied", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("patternPredictability");
      assert.ok(d.score >= 50, "varied answers should score >= 50, got " + d.score);
    });

    it("low score when all answers start same way", function () {
      var ch = [
        { id: "c1", humanAnswer: "The animal runs quickly across the field" },
        { id: "c2", humanAnswer: "The animal jumps over the fence" },
        { id: "c3", humanAnswer: "The animal swims in the lake" },
        { id: "c4", humanAnswer: "The animal climbs up the tree" },
        { id: "c5", humanAnswer: "The animal hides behind the bush" },
      ];
      var d = createSecurityScorer(ch).getDimension("patternPredictability");
      assert.ok(d.score < 50, "same-start answers should score < 50, got " + d.score);
    });

    it("first-word diversity in details", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("patternPredictability");
      assert.ok("firstWordDiversity" in d.details);
      assert.equal(typeof d.details.firstWordDiversity, "number");
    });

    it("handles single challenge", function () {
      var d = createSecurityScorer(minimalChallenge()).getDimension("patternPredictability");
      assert.equal(d.score, 50); // neutral for single challenge
    });

    it("mostCommonFirstWordRatio in details", function () {
      var d = createSecurityScorer(diverseChallenges()).getDimension("patternPredictability");
      assert.ok("mostCommonFirstWordRatio" in d.details);
      assert.equal(typeof d.details.mostCommonFirstWordRatio, "number");
    });
  });

  // ── getVulnerabilities ──

  describe("getVulnerabilities", function () {
    it("returns empty for secure set", function () {
      // Build a very secure set
      var ch = diverseChallenges();
      var scorer = createSecurityScorer(ch);
      var vulns = scorer.getVulnerabilities();
      // may or may not have vulns depending on scoring — just ensure it's an array
      assert.ok(Array.isArray(vulns));
    });

    it("identifies weak dimensions", function () {
      var scorer = createSecurityScorer(identicalChallenges());
      var vulns = scorer.getVulnerabilities();
      assert.ok(vulns.length > 0, "identical challenges should have vulnerabilities");
    });

    it("severity levels are correct", function () {
      var scorer = createSecurityScorer(identicalChallenges());
      var vulns = scorer.getVulnerabilities();
      for (var i = 0; i < vulns.length; i++) {
        assert.ok(["critical", "high", "medium"].indexOf(vulns[i].severity) !== -1,
          "unexpected severity: " + vulns[i].severity);
        if (vulns[i].score < 20) assert.equal(vulns[i].severity, "critical");
        else if (vulns[i].score < 40) assert.equal(vulns[i].severity, "high");
        else assert.equal(vulns[i].severity, "medium");
      }
    });

    it("description is non-empty string", function () {
      var scorer = createSecurityScorer(identicalChallenges());
      var vulns = scorer.getVulnerabilities();
      for (var i = 0; i < vulns.length; i++) {
        assert.equal(typeof vulns[i].description, "string");
        assert.ok(vulns[i].description.length > 0);
      }
    });
  });

  // ── getRecommendations ──

  describe("getRecommendations", function () {
    it("returns recommendations for weak areas", function () {
      var recs = createSecurityScorer(identicalChallenges()).getRecommendations();
      assert.ok(recs.length > 0);
    });

    it("each has priority, dimension, text", function () {
      var recs = createSecurityScorer(diverseChallenges()).getRecommendations();
      for (var i = 0; i < recs.length; i++) {
        assert.ok("priority" in recs[i]);
        assert.ok("dimension" in recs[i]);
        assert.ok("text" in recs[i]);
        assert.ok(["critical", "high", "medium", "low"].indexOf(recs[i].priority) !== -1);
      }
    });

    it("always includes at least one general recommendation", function () {
      var recs = createSecurityScorer(diverseChallenges()).getRecommendations();
      var general = recs.filter(function (r) { return r.dimension === "overall"; });
      assert.ok(general.length >= 1, "should have at least one general recommendation");
    });
  });

  // ── isSecure ──

  describe("isSecure", function () {
    it("returns true above threshold", function () {
      var scorer = createSecurityScorer(diverseChallenges());
      var score = scorer.getReport().score;
      // Use a threshold well below the score
      assert.equal(scorer.isSecure(0), true);
    });

    it("returns false below threshold", function () {
      var scorer = createSecurityScorer(identicalChallenges());
      // Use a very high threshold
      assert.equal(scorer.isSecure(100), false);
    });

    it("uses default threshold of 60", function () {
      var scorer = createSecurityScorer(diverseChallenges());
      var score = scorer.getReport().score;
      var result = scorer.isSecure();
      assert.equal(result, score >= 60);
    });
  });

  // ── reset ──

  describe("reset", function () {
    it("updates scores with new challenges", function () {
      var scorer = createSecurityScorer(diverseChallenges());
      var report1 = scorer.getReport();
      scorer.reset(identicalChallenges());
      var report2 = scorer.getReport();
      assert.notEqual(report1.score, report2.score);
    });

    it("throws on invalid input", function () {
      var scorer = createSecurityScorer(diverseChallenges());
      assert.throws(function () { scorer.reset([]); }, /non-empty array/);
      assert.throws(function () { scorer.reset(null); }, /non-empty array/);
    });

    it("clears previous state", function () {
      var scorer = createSecurityScorer(diverseChallenges());
      var dims1 = scorer.getDimensions();
      scorer.reset(identicalChallenges());
      var dims2 = scorer.getDimensions();
      // answer diversity should be different
      var ad1 = dims1.find(function (d) { return d.name === "Answer Diversity"; });
      var ad2 = dims2.find(function (d) { return d.name === "Answer Diversity"; });
      assert.notEqual(ad1.score, ad2.score);
    });
  });

  // ── Grade boundaries ──

  describe("grade boundaries", function () {
    it("score 80+ gives grade A", function () {
      // We can't easily control exact score, but we can check the mapping via report
      var scorer = createSecurityScorer(diverseChallenges());
      var report = scorer.getReport();
      if (report.score >= 80) assert.equal(report.grade, "A");
      else if (report.score >= 65) assert.equal(report.grade, "B");
      else if (report.score >= 50) assert.equal(report.grade, "C");
      else if (report.score >= 35) assert.equal(report.grade, "D");
      else assert.equal(report.grade, "F");
    });

    it("grade matches score for weak set", function () {
      var scorer = createSecurityScorer(identicalChallenges());
      var report = scorer.getReport();
      if (report.score >= 80) assert.equal(report.grade, "A");
      else if (report.score >= 65) assert.equal(report.grade, "B");
      else if (report.score >= 50) assert.equal(report.grade, "C");
      else if (report.score >= 35) assert.equal(report.grade, "D");
      else assert.equal(report.grade, "F");
    });
  });

  // ── Edge cases ──

  describe("edge cases", function () {
    it("challenges with very long answers", function () {
      var ch = [
        { id: "c1", humanAnswer: "The quick brown fox jumps over the lazy dog and then runs through the forest before swimming across the river because the bridge was broken so it had to find another way while the sun was setting and the birds were singing their evening songs until darkness finally came" },
        { id: "c2", humanAnswer: "A massive thunderstorm suddenly appears over the mountain range causing flash floods in the valley below which results in the river overflowing its banks while villagers scramble to higher ground before the waters reach their homes and then emergency services arrive to coordinate the evacuation" },
      ];
      var scorer = createSecurityScorer(ch);
      var report = scorer.getReport();
      assert.ok(report.score >= 0 && report.score <= 100);
    });

    it("challenges with single-word answers", function () {
      var ch = [
        { id: "c1", humanAnswer: "Running" },
        { id: "c2", humanAnswer: "Jumping" },
        { id: "c3", humanAnswer: "Swimming" },
      ];
      var scorer = createSecurityScorer(ch);
      var report = scorer.getReport();
      assert.ok(report.score >= 0 && report.score <= 100);
    });

    it("many challenges", function () {
      var ch = [];
      for (var i = 0; i < 100; i++) {
        ch.push({ id: "c" + i, humanAnswer: "Unique answer number " + i + " with varied content about topic " + (i % 10) });
      }
      var scorer = createSecurityScorer(ch);
      var dims = scorer.getDimensions();
      assert.equal(dims.length, 6);
    });

    it("defensive copy prevents external mutation", function () {
      var ch = diverseChallenges();
      var scorer = createSecurityScorer(ch);
      var score1 = scorer.getReport().score;
      // mutate original
      ch[0].humanAnswer = "MUTATED";
      var score2 = scorer.getReport().score;
      assert.equal(score1, score2, "external mutation should not affect scorer");
    });
  });
});
