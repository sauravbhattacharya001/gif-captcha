"use strict";

var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var { createCaptchaStrengthScorer } = require("../src/captcha-strength-scorer");

describe("CaptchaStrengthScorer", function () {
  it("scores a basic configuration", function () {
    var scorer = createCaptchaStrengthScorer();
    var result = scorer.score({
      frameCount: 12,
      animationSpeedMs: 80,
      distortionLevel: 7,
      noiseLevel: 5,
      colorCount: 6,
      choiceCount: 4,
      questionType: "sequence",
      poolSize: 500,
      answerDistribution: [0.25, 0.25, 0.25, 0.25]
    });

    assert.ok(result.composite >= 0 && result.composite <= 100);
    assert.ok(typeof result.grade === "string");
    assert.ok(result.dimensions.visual >= 0);
    assert.ok(result.dimensions.temporal >= 0);
    assert.ok(result.dimensions.cognitive >= 0);
    assert.ok(result.dimensions.entropy >= 0);
    assert.ok(result.dimensions.resilience >= 0);
    assert.ok(Array.isArray(result.suggestions));
  });

  it("gives weak config a low score", function () {
    var scorer = createCaptchaStrengthScorer();
    var result = scorer.score({
      frameCount: 1,
      animationSpeedMs: 500,
      distortionLevel: 0,
      noiseLevel: 0,
      colorCount: 1,
      choiceCount: 2,
      questionType: "click",
      poolSize: 10
    });

    assert.ok(result.composite < 40, "Weak config should score below 40, got " + result.composite);
    assert.equal(result.grade.charAt(0), "F", "Should get F grade but got " + result.grade);
  });

  it("gives strong config a high score", function () {
    var scorer = createCaptchaStrengthScorer();
    var result = scorer.score({
      frameCount: 25,
      animationSpeedMs: 40,
      distortionLevel: 9,
      noiseLevel: 8,
      colorCount: 12,
      choiceCount: 6,
      questionType: "reasoning",
      poolSize: 800,
      answerDistribution: [0.17, 0.17, 0.17, 0.17, 0.16, 0.16]
    });

    assert.ok(result.composite >= 75, "Strong config should score 75+, got " + result.composite);
  });

  it("compares two configurations", function () {
    var scorer = createCaptchaStrengthScorer();
    var cmp = scorer.compare(
      { distortionLevel: 8, noiseLevel: 7, frameCount: 20, questionType: "temporal", poolSize: 400 },
      { distortionLevel: 1, noiseLevel: 1, frameCount: 2, questionType: "click", poolSize: 10 }
    );

    assert.equal(cmp.winner, "A");
    assert.ok(cmp.compositeDelta > 0);
    assert.ok(cmp.deltas.visual > 0);
  });

  it("ranks multiple configurations", function () {
    var scorer = createCaptchaStrengthScorer();
    var ranked = scorer.rank([
      { distortionLevel: 1, questionType: "click", poolSize: 10 },
      { distortionLevel: 9, questionType: "reasoning", poolSize: 800, frameCount: 20 },
      { distortionLevel: 5, questionType: "sequence", poolSize: 200, frameCount: 10 }
    ]);

    assert.equal(ranked.length, 3);
    assert.equal(ranked[0].rank, 1);
    assert.ok(ranked[0].composite >= ranked[1].composite);
    assert.ok(ranked[1].composite >= ranked[2].composite);
  });

  it("supports custom weights", function () {
    var scorer = createCaptchaStrengthScorer({ weights: { visual: 1, temporal: 0, cognitive: 0, entropy: 0, resilience: 0 } });
    var result = scorer.score({ distortionLevel: 10, noiseLevel: 10, colorCount: 16 });
    // With only visual weight, composite should equal visual score
    assert.equal(result.composite, result.dimensions.visual);
  });

  it("handles empty config gracefully", function () {
    var scorer = createCaptchaStrengthScorer();
    var result = scorer.score({});
    assert.ok(result.composite >= 0);
    assert.ok(typeof result.grade === "string");
  });

  it("exposes question types", function () {
    var scorer = createCaptchaStrengthScorer();
    assert.ok(scorer.QUESTION_TYPES.length > 0);
    assert.ok(scorer.QUESTION_TYPES.indexOf("sequence") >= 0);
  });
});
