"use strict";

/**
 * Extended test suite for captcha-strength-scorer.
 *
 * The original test file covers happy-path behavior. These tests target
 * edge cases, internal scoring behavior, grade boundary classification,
 * suggestion engine logic, weight normalization invariants, entropy
 * sensitivity to answer distributions, and comparison/ranking semantics.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var { createCaptchaStrengthScorer } = require("../src/captcha-strength-scorer");

// ── Helpers ─────────────────────────────────────────────────────────

function weakConfig() {
  return {
    frameCount: 1,
    animationSpeedMs: 500,
    distortionLevel: 0,
    noiseLevel: 0,
    colorCount: 1,
    choiceCount: 2,
    questionType: "click",
    poolSize: 10
  };
}

function strongConfig() {
  return {
    frameCount: 25,
    animationSpeedMs: 40,
    distortionLevel: 9,
    noiseLevel: 8,
    colorCount: 12,
    choiceCount: 6,
    questionType: "reasoning",
    poolSize: 800,
    answerDistribution: [0.17, 0.17, 0.17, 0.17, 0.16, 0.16]
  };
}

describe("CaptchaStrengthScorer — score() output shape", function () {
  it("returns dimensions clamped to 0..100", function () {
    var scorer = createCaptchaStrengthScorer();
    var configs = [weakConfig(), strongConfig(), {}, { distortionLevel: 100, noiseLevel: 100, colorCount: 100 }];
    for (var i = 0; i < configs.length; i++) {
      var r = scorer.score(configs[i]);
      var dims = ["visual", "temporal", "cognitive", "entropy", "resilience"];
      for (var j = 0; j < dims.length; j++) {
        var v = r.dimensions[dims[j]];
        assert.ok(Number.isFinite(v), dims[j] + " should be finite, got " + v);
        assert.ok(v >= 0 && v <= 100, dims[j] + " should be in [0,100], got " + v);
      }
      assert.ok(r.composite >= 0 && r.composite <= 100, "composite out of range: " + r.composite);
    }
  });

  it("echoes back the supplied config object", function () {
    var scorer = createCaptchaStrengthScorer();
    var cfg = { distortionLevel: 3 };
    var r = scorer.score(cfg);
    assert.equal(r.config, cfg);
  });

  it("treats null config the same as empty object", function () {
    var scorer = createCaptchaStrengthScorer();
    var rNull = scorer.score(null);
    var rEmpty = scorer.score({});
    assert.equal(rNull.composite, rEmpty.composite);
    assert.deepEqual(rNull.dimensions, rEmpty.dimensions);
  });

  it("does not mutate the input config", function () {
    var scorer = createCaptchaStrengthScorer();
    var cfg = { distortionLevel: 5, noiseLevel: 4, frameCount: 8 };
    var snapshot = JSON.stringify(cfg);
    scorer.score(cfg);
    assert.equal(JSON.stringify(cfg), snapshot);
  });
});

describe("CaptchaStrengthScorer — grade classification", function () {
  it("maps composite scores to grades monotonically", function () {
    var scorer = createCaptchaStrengthScorer();
    // Build a sequence of configs with increasing strength; grades should
    // never go DOWN as composite goes UP.
    var distortions = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    var lastComposite = -1;
    var lastGrade = null;
    var gradeRank = scorer.GRADE_THRESHOLDS.map(function (g) { return g.grade; });
    function rankOf(g) { return gradeRank.indexOf(g); }
    for (var i = 0; i < distortions.length; i++) {
      var r = scorer.score({
        distortionLevel: distortions[i],
        noiseLevel: distortions[i],
        colorCount: 1 + distortions[i],
        frameCount: 1 + distortions[i] * 2,
        animationSpeedMs: Math.max(20, 500 - distortions[i] * 40),
        poolSize: 10 + distortions[i] * 80,
        choiceCount: 2 + distortions[i] >> 1,
        questionType: distortions[i] > 5 ? "sequence" : "click"
      });
      assert.ok(r.composite >= lastComposite,
        "composite must be non-decreasing: prev=" + lastComposite + " now=" + r.composite);
      if (lastGrade !== null) {
        // Higher rank-index = weaker grade; ensure we never get weaker
        assert.ok(rankOf(r.grade) <= rankOf(lastGrade),
          "grade got weaker as score increased: " + lastGrade + " -> " + r.grade);
      }
      lastComposite = r.composite;
      lastGrade = r.grade;
    }
  });

  it("returns 'F' for the minimum visual score and 'A+' near the visual cap", function () {
    // We can't directly set composite, but we can use crafted weights so
    // composite mirrors a single dimension we control.
    var onlyVisual = createCaptchaStrengthScorer({
      weights: { visual: 1, temporal: 0, cognitive: 0, entropy: 0, resilience: 0 }
    });
    var weak = onlyVisual.score({ distortionLevel: 0, noiseLevel: 0, colorCount: 1 });
    assert.equal(weak.grade, "F");
    // Max visual is bounded by the weighted dimension caps (≈95), so the
    // top-end check is against the highest reachable grade tier.
    var strong = onlyVisual.score({ distortionLevel: 10, noiseLevel: 10, colorCount: 16 });
    assert.ok(strong.composite >= 90, "expected composite >= 90, got " + strong.composite);
    assert.ok(["A+", "A"].indexOf(strong.grade) >= 0,
      "expected A/A+, got " + strong.grade);
  });
});

describe("CaptchaStrengthScorer — weight normalization", function () {
  it("normalizes non-unit weights so composite stays in [0,100]", function () {
    var scorer = createCaptchaStrengthScorer({
      weights: { visual: 10, temporal: 10, cognitive: 10, entropy: 10, resilience: 10 }
    });
    var r = scorer.score(strongConfig());
    assert.ok(r.composite >= 0 && r.composite <= 100, "composite out of range: " + r.composite);
    var weights = scorer.getWeights();
    var sum = 0;
    Object.keys(weights).forEach(function (k) { sum += weights[k]; });
    assert.ok(Math.abs(sum - 1) < 1e-6, "weights should sum to ~1, got " + sum);
  });

  it("fills missing weights from defaults", function () {
    var scorer = createCaptchaStrengthScorer({ weights: { visual: 0.5 } });
    var w = scorer.getWeights();
    assert.ok(w.visual > 0);
    assert.ok(w.temporal > 0);
    assert.ok(w.cognitive > 0);
    assert.ok(w.entropy > 0);
    assert.ok(w.resilience > 0);
  });

  it("getWeights returns a defensive copy", function () {
    var scorer = createCaptchaStrengthScorer();
    var w1 = scorer.getWeights();
    w1.visual = 999;
    var w2 = scorer.getWeights();
    assert.notEqual(w2.visual, 999);
  });

  it("supports a single-dimension weight (others 0)", function () {
    var scorer = createCaptchaStrengthScorer({
      weights: { visual: 0, temporal: 1, cognitive: 0, entropy: 0, resilience: 0 }
    });
    var r = scorer.score({ frameCount: 15, animationSpeedMs: 60, frameVariance: 2 });
    assert.equal(r.composite, r.dimensions.temporal);
  });
});

describe("CaptchaStrengthScorer — entropy dimension", function () {
  it("uniform distribution scores higher than skewed", function () {
    var scorer = createCaptchaStrengthScorer();
    var uniform = scorer.score({ poolSize: 500, answerDistribution: [0.25, 0.25, 0.25, 0.25] });
    var skewed = scorer.score({ poolSize: 500, answerDistribution: [0.97, 0.01, 0.01, 0.01] });
    assert.ok(uniform.dimensions.entropy > skewed.dimensions.entropy,
      "uniform " + uniform.dimensions.entropy + " should beat skewed " + skewed.dimensions.entropy);
  });

  it("missing distribution falls back to moderate (50)", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score({ poolSize: 500 });
    // pool=500 → ~67 from pool half, dist=50 → entropy ≈ round(67*.5 + 50*.5) ~58
    assert.ok(r.dimensions.entropy > 40 && r.dimensions.entropy < 80,
      "entropy fallback unexpected: " + r.dimensions.entropy);
  });

  it("zero-sum distribution does not throw or produce NaN", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score({ poolSize: 100, answerDistribution: [0, 0, 0] });
    assert.ok(Number.isFinite(r.dimensions.entropy));
  });

  it("empty distribution does not throw", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score({ poolSize: 100, answerDistribution: [] });
    assert.ok(Number.isFinite(r.dimensions.entropy));
  });

  it("single-element distribution gives zero distribution entropy", function () {
    // log2(1) = 0; component contributes 0, leaving only pool component
    var scorer = createCaptchaStrengthScorer({
      weights: { visual: 0, temporal: 0, cognitive: 0, entropy: 1, resilience: 0 }
    });
    var r1 = scorer.score({ poolSize: 100, answerDistribution: [1] });
    var r2 = scorer.score({ poolSize: 100, answerDistribution: [0.5, 0.5] });
    assert.ok(r2.dimensions.entropy > r1.dimensions.entropy);
  });
});

describe("CaptchaStrengthScorer — cognitive dimension", function () {
  it("more complex question types score higher", function () {
    var scorer = createCaptchaStrengthScorer();
    var click = scorer.score({ questionType: "click", choiceCount: 4 });
    var reasoning = scorer.score({ questionType: "reasoning", choiceCount: 4 });
    assert.ok(reasoning.dimensions.cognitive > click.dimensions.cognitive,
      "reasoning should beat click cognitively");
  });

  it("unknown question types use a moderate default (≈40)", function () {
    var scorer = createCaptchaStrengthScorer();
    var unknown = scorer.score({ questionType: "totally-made-up", choiceCount: 4 });
    var click = scorer.score({ questionType: "click", choiceCount: 4 });
    // 40 default > 10 for "click"
    assert.ok(unknown.dimensions.cognitive > click.dimensions.cognitive);
  });

  it("more choices increase cognitive score", function () {
    var scorer = createCaptchaStrengthScorer();
    var few = scorer.score({ questionType: "click_shape", choiceCount: 2 });
    var many = scorer.score({ questionType: "click_shape", choiceCount: 8 });
    assert.ok(many.dimensions.cognitive > few.dimensions.cognitive);
  });

  it("ambiguity factor pushes cognitive score up", function () {
    var scorer = createCaptchaStrengthScorer();
    var clear = scorer.score({ questionType: "click_shape", choiceCount: 4, ambiguityFactor: 0 });
    var fuzzy = scorer.score({ questionType: "click_shape", choiceCount: 4, ambiguityFactor: 1 });
    assert.ok(fuzzy.dimensions.cognitive >= clear.dimensions.cognitive);
  });
});

describe("CaptchaStrengthScorer — temporal/visual dimensions", function () {
  it("faster animation scores higher than slower", function () {
    var scorer = createCaptchaStrengthScorer();
    var slow = scorer.score({ frameCount: 10, animationSpeedMs: 500 });
    var fast = scorer.score({ frameCount: 10, animationSpeedMs: 30 });
    assert.ok(fast.dimensions.temporal > slow.dimensions.temporal);
  });

  it("more frames score higher than fewer", function () {
    var scorer = createCaptchaStrengthScorer();
    var few = scorer.score({ frameCount: 2, animationSpeedMs: 100 });
    var many = scorer.score({ frameCount: 25, animationSpeedMs: 100 });
    assert.ok(many.dimensions.temporal > few.dimensions.temporal);
  });

  it("higher distortion increases visual score", function () {
    var scorer = createCaptchaStrengthScorer();
    var low = scorer.score({ distortionLevel: 1, noiseLevel: 1, colorCount: 2 });
    var high = scorer.score({ distortionLevel: 10, noiseLevel: 1, colorCount: 2 });
    assert.ok(high.dimensions.visual > low.dimensions.visual);
  });
});

describe("CaptchaStrengthScorer — resilience dimension", function () {
  it("strong combined config crosses resilience bonuses", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score(strongConfig());
    assert.ok(r.dimensions.resilience >= 80,
      "expected resilience >= 80 for strong config, got " + r.dimensions.resilience);
  });

  it("weak config bottoms out near base resilience", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score(weakConfig());
    assert.ok(r.dimensions.resilience <= 40,
      "expected resilience <= 40 for weak config, got " + r.dimensions.resilience);
  });

  it("never exceeds 100 even when every bonus triggers", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score({
      frameCount: 100,
      animationSpeedMs: 10,
      distortionLevel: 10,
      noiseLevel: 10,
      questionType: "reasoning",
      poolSize: 10000
    });
    assert.ok(r.dimensions.resilience <= 100);
  });
});

describe("CaptchaStrengthScorer — suggestion engine", function () {
  it("emits at least one suggestion for any config", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score(weakConfig());
    assert.ok(r.suggestions.length >= 1);
  });

  it("strong config yields the positive 'looks strong' suggestion", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score(strongConfig());
    var joined = r.suggestions.join(" | ");
    assert.ok(/looks strong/i.test(joined), "expected positive suggestion, got: " + joined);
  });

  it("low distortion triggers a distortion-related suggestion", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score({ distortionLevel: 0, noiseLevel: 0, colorCount: 1, frameCount: 1 });
    var hit = r.suggestions.some(function (s) { return /distortion/i.test(s); });
    assert.ok(hit, "expected a distortion suggestion, got: " + r.suggestions.join(" | "));
  });

  it("low pool size triggers a pool expansion suggestion", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score({ poolSize: 5 });
    var hit = r.suggestions.some(function (s) { return /pool/i.test(s); });
    assert.ok(hit);
  });

  it("simple question type triggers a question-type suggestion", function () {
    var scorer = createCaptchaStrengthScorer();
    var r = scorer.score({ questionType: "click", choiceCount: 2 });
    var hit = r.suggestions.some(function (s) { return /question type/i.test(s); });
    assert.ok(hit);
  });
});

describe("CaptchaStrengthScorer — compare()", function () {
  it("declares 'tie' for two identical configs", function () {
    var scorer = createCaptchaStrengthScorer();
    var cfg = { distortionLevel: 5, frameCount: 10, questionType: "sequence", poolSize: 200 };
    var cmp = scorer.compare(cfg, Object.assign({}, cfg));
    assert.equal(cmp.winner, "tie");
    assert.equal(cmp.compositeDelta, 0);
    var dims = Object.keys(cmp.deltas);
    for (var i = 0; i < dims.length; i++) {
      assert.equal(cmp.deltas[dims[i]], 0);
    }
  });

  it("declares 'B' when B is stronger", function () {
    var scorer = createCaptchaStrengthScorer();
    var cmp = scorer.compare(weakConfig(), strongConfig());
    assert.equal(cmp.winner, "B");
    assert.ok(cmp.compositeDelta < 0);
  });

  it("deltas == a.dimensions - b.dimensions", function () {
    var scorer = createCaptchaStrengthScorer();
    var a = { distortionLevel: 8, frameCount: 20, questionType: "temporal", poolSize: 400 };
    var b = { distortionLevel: 1, frameCount: 2, questionType: "click", poolSize: 10 };
    var cmp = scorer.compare(a, b);
    Object.keys(cmp.deltas).forEach(function (d) {
      assert.equal(cmp.deltas[d], cmp.a.dimensions[d] - cmp.b.dimensions[d]);
    });
  });
});

describe("CaptchaStrengthScorer — rank()", function () {
  it("returns empty array for non-array inputs", function () {
    var scorer = createCaptchaStrengthScorer();
    assert.deepEqual(scorer.rank(null), []);
    assert.deepEqual(scorer.rank(undefined), []);
    assert.deepEqual(scorer.rank("oops"), []);
    assert.deepEqual(scorer.rank({}), []);
  });

  it("returns empty array for empty input", function () {
    var scorer = createCaptchaStrengthScorer();
    assert.deepEqual(scorer.rank([]), []);
  });

  it("assigns ranks 1..N in descending composite order", function () {
    var scorer = createCaptchaStrengthScorer();
    var ranked = scorer.rank([weakConfig(), strongConfig(), {}]);
    assert.equal(ranked.length, 3);
    for (var i = 0; i < ranked.length; i++) {
      assert.equal(ranked[i].rank, i + 1);
      if (i > 0) {
        assert.ok(ranked[i - 1].composite >= ranked[i].composite,
          "rank order violated at position " + i);
      }
    }
  });

  it("preserves the original input index on each result", function () {
    var scorer = createCaptchaStrengthScorer();
    var inputs = [weakConfig(), strongConfig(), {}];
    var ranked = scorer.rank(inputs);
    var seen = ranked.map(function (r) { return r.index; }).sort();
    assert.deepEqual(seen, [0, 1, 2]);
  });
});

describe("CaptchaStrengthScorer — exposed metadata", function () {
  it("QUESTION_TYPES includes all known types", function () {
    var scorer = createCaptchaStrengthScorer();
    ["click", "click_shape", "count_objects", "odd_one_out", "spatial",
      "sequence", "temporal", "multi_step", "reasoning"].forEach(function (t) {
      assert.ok(scorer.QUESTION_TYPES.indexOf(t) >= 0, "missing question type: " + t);
    });
  });

  it("GRADE_THRESHOLDS is sorted high-to-low", function () {
    var scorer = createCaptchaStrengthScorer();
    var t = scorer.GRADE_THRESHOLDS;
    for (var i = 1; i < t.length; i++) {
      assert.ok(t[i - 1].min >= t[i].min, "thresholds not monotonic at " + i);
    }
    assert.equal(t[t.length - 1].grade, "F");
  });
});
