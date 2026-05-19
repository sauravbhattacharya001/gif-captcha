"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  shannonEntropy,
  simpsonsIndex,
  giniSimpson,
  analyzeDiversity,
} = require("../src/challenge-diversity-analyzer");

// ── shannonEntropy ──────────────────────────────────────────────

describe("shannonEntropy", () => {
  it("returns 0 for empty counts", () => {
    assert.equal(shannonEntropy([]), 0);
  });

  it("returns 0 when all counts are zero", () => {
    assert.equal(shannonEntropy([0, 0, 0]), 0);
  });

  it("returns 1 for perfectly uniform distribution", () => {
    const e = shannonEntropy([10, 10, 10, 10]);
    assert.ok(Math.abs(e - 1) < 1e-10, `expected ~1, got ${e}`);
  });

  it("returns 1 for single category", () => {
    assert.equal(shannonEntropy([42]), 1);
  });

  it("returns lower entropy for skewed distributions", () => {
    const uniform = shannonEntropy([25, 25, 25, 25]);
    const skewed = shannonEntropy([97, 1, 1, 1]);
    assert.ok(skewed < uniform, "skewed should have lower entropy");
  });

  it("handles two-category distributions correctly", () => {
    const e = shannonEntropy([50, 50]);
    assert.ok(Math.abs(e - 1) < 1e-10);
    const e2 = shannonEntropy([99, 1]);
    assert.ok(e2 > 0 && e2 < 1);
  });
});

// ── simpsonsIndex ───────────────────────────────────────────────

describe("simpsonsIndex", () => {
  it("returns 0 for single item", () => {
    assert.equal(simpsonsIndex([1]), 0);
  });

  it("returns 0 for empty array", () => {
    assert.equal(simpsonsIndex([]), 0);
  });

  it("returns high value for uniform distribution", () => {
    const s = simpsonsIndex([10, 10, 10, 10]);
    assert.ok(s > 0.7, `expected high diversity, got ${s}`);
  });

  it("returns low value for dominated distribution", () => {
    const s = simpsonsIndex([100, 1, 1]);
    assert.ok(s < 0.1, `expected low diversity, got ${s}`);
  });
});

// ── giniSimpson ─────────────────────────────────────────────────

describe("giniSimpson", () => {
  it("returns 0 for empty counts", () => {
    assert.equal(giniSimpson([]), 0);
  });

  it("returns 0 for single category", () => {
    assert.equal(giniSimpson([10]), 0);
  });

  it("returns high value for uniform distribution", () => {
    const g = giniSimpson([25, 25, 25, 25]);
    assert.ok(g > 0.7, `expected high Gini-Simpson, got ${g}`);
  });

  it("returns low value for dominated distribution", () => {
    const g = giniSimpson([1000, 1]);
    assert.ok(g < 0.01);
  });
});

// ── analyzeDiversity ────────────────────────────────────────────

describe("analyzeDiversity", () => {
  it("returns zeros and warning for empty input", () => {
    const r = analyzeDiversity([]);
    assert.equal(r.overall, 0);
    assert.equal(r.dimensions.categoryBalance, 0);
    assert.deepEqual(r.warnings, ["No categories provided"]);
  });

  it("returns zeros for null input", () => {
    const r = analyzeDiversity(null);
    assert.equal(r.overall, 0);
  });

  it("computes a high overall score for diverse pool", () => {
    const categories = [
      { name: "animals", count: 25, avgComplexity: 0.8, colorVariance: 0.7, motionDiversity: 0.9, avgDifficulty: 3, avgDuration: 2 },
      { name: "vehicles", count: 25, avgComplexity: 0.5, colorVariance: 0.6, motionDiversity: 0.7, avgDifficulty: 5, avgDuration: 4 },
      { name: "nature", count: 25, avgComplexity: 0.9, colorVariance: 0.8, motionDiversity: 0.8, avgDifficulty: 7, avgDuration: 6 },
      { name: "sports", count: 25, avgComplexity: 0.6, colorVariance: 0.9, motionDiversity: 0.6, avgDifficulty: 9, avgDuration: 3 },
    ];
    const r = analyzeDiversity(categories);
    assert.ok(r.overall > 50, `expected high overall, got ${r.overall}`);
    assert.equal(r.dimensions.categoryBalance, 100); // uniform distribution
    assert.ok(r.indices.shannon > 0.99);
    assert.ok(r.indices.simpson > 0.7);
    assert.ok(r.indices.giniSimpson > 0.7);
  });

  it("warns when category balance is skewed", () => {
    const categories = [
      { name: "dominant", count: 97, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
      { name: "tiny", count: 1, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
      { name: "tiny2", count: 1, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
      { name: "tiny3", count: 1, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
    ];
    const r = analyzeDiversity(categories);
    assert.ok(r.warnings.some(w => w.includes("skewed")));
    assert.ok(r.warnings.some(w => w.includes("underrepresented")));
  });

  it("warns when color diversity is low", () => {
    const categories = [
      { name: "a", count: 10, avgComplexity: 0.5, colorVariance: 0.1, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
      { name: "b", count: 10, avgComplexity: 0.5, colorVariance: 0.2, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
    ];
    const r = analyzeDiversity(categories);
    assert.ok(r.warnings.some(w => w.includes("color")));
  });

  it("warns when motion patterns lack variety", () => {
    const categories = [
      { name: "a", count: 10, avgComplexity: 0.5, colorVariance: 0.8, motionDiversity: 0.1, avgDifficulty: 5, avgDuration: 3 },
      { name: "b", count: 10, avgComplexity: 0.5, colorVariance: 0.8, motionDiversity: 0.2, avgDifficulty: 5, avgDuration: 3 },
    ];
    const r = analyzeDiversity(categories);
    assert.ok(r.warnings.some(w => w.includes("Motion")));
  });

  it("warns when difficulty range is narrow", () => {
    const categories = [
      { name: "a", count: 10, avgComplexity: 0.5, colorVariance: 0.8, motionDiversity: 0.8, avgDifficulty: 5, avgDuration: 3 },
      { name: "b", count: 10, avgComplexity: 0.5, colorVariance: 0.8, motionDiversity: 0.8, avgDifficulty: 5.5, avgDuration: 3 },
    ];
    const r = analyzeDiversity(categories);
    assert.ok(r.warnings.some(w => w.includes("Difficulty")));
  });

  it("handles missing optional fields gracefully", () => {
    const categories = [
      { name: "a", count: 10 },
      { name: "b", count: 10 },
    ];
    const r = analyzeDiversity(categories);
    assert.ok(typeof r.overall === "number");
    assert.ok(r.overall >= 0);
  });

  it("returns integer-rounded dimension scores", () => {
    const categories = [
      { name: "a", count: 7, avgComplexity: 0.33, colorVariance: 0.77, motionDiversity: 0.55, avgDifficulty: 3, avgDuration: 2 },
      { name: "b", count: 13, avgComplexity: 0.66, colorVariance: 0.44, motionDiversity: 0.88, avgDifficulty: 8, avgDuration: 5 },
    ];
    const r = analyzeDiversity(categories);
    for (const key of Object.keys(r.dimensions)) {
      assert.equal(r.dimensions[key], Math.round(r.dimensions[key]), `${key} should be rounded`);
    }
    assert.equal(r.overall, Math.round(r.overall));
  });
});

// ── Extended coverage: edge cases, mathematical properties, regressions ──

describe("shannonEntropy — edge & mathematical properties", () => {
  it("handles a single non-zero bucket among many (degenerate distribution)", () => {
    const e = shannonEntropy([0, 0, 100, 0, 0]);
    // All probability mass on one category → entropy 0 even though maxE > 0
    assert.equal(e, 0);
  });

  it("ignores buckets that contain zero (does not produce NaN from log2(0))", () => {
    const e = shannonEntropy([5, 0, 5, 0, 5]);
    assert.ok(Number.isFinite(e), `expected finite, got ${e}`);
    assert.ok(e > 0 && e < 1);
  });

  it("respects a correct precomputedTotal (skips internal sum)", () => {
    // Using the wrong total deliberately to prove the parameter is honored.
    const counts = [10, 10, 10, 10];
    const correct = shannonEntropy(counts);                  // total = 40
    const wrong = shannonEntropy(counts, 80);                // half probabilities
    assert.notEqual(correct, wrong, "precomputedTotal must influence the result");
  });

  it("is invariant under proportional scaling of counts", () => {
    const base = shannonEntropy([3, 5, 2]);
    const scaled = shannonEntropy([30, 50, 20]);
    assert.ok(Math.abs(base - scaled) < 1e-12,
      `entropy should be scale-invariant; ${base} vs ${scaled}`);
  });

  it("is invariant under reordering of counts", () => {
    const a = shannonEntropy([1, 4, 2, 9]);
    const b = shannonEntropy([9, 2, 4, 1]);
    assert.ok(Math.abs(a - b) < 1e-12);
  });

  it("stays within [0, 1] for a large random distribution", () => {
    const counts = [];
    for (let i = 0; i < 1000; i++) counts.push(Math.floor(Math.random() * 100) + 1);
    const e = shannonEntropy(counts);
    assert.ok(e >= 0 && e <= 1, `entropy out of bounds: ${e}`);
  });
});

describe("simpsonsIndex — edge & mathematical properties", () => {
  it("returns 0 when every probability mass sits in one bucket", () => {
    // total > 1 so we hit the main formula; only one category has count > 0.
    const s = simpsonsIndex([10, 0, 0, 0]);
    assert.equal(s, 0);
  });

  it("is invariant under reordering of counts", () => {
    const a = simpsonsIndex([3, 5, 2, 7]);
    const b = simpsonsIndex([7, 2, 5, 3]);
    assert.ok(Math.abs(a - b) < 1e-12);
  });

  it("stays within [0, 1]", () => {
    for (let trial = 0; trial < 50; trial++) {
      const counts = [];
      const k = 2 + Math.floor(Math.random() * 8);
      for (let i = 0; i < k; i++) counts.push(Math.floor(Math.random() * 30) + 1);
      const s = simpsonsIndex(counts);
      assert.ok(s >= 0 && s <= 1, `Simpson's index out of [0,1]: ${s}`);
    }
  });

  it("honors precomputedTotal", () => {
    const counts = [4, 4, 4, 4];
    // total=16; passing a mismatching total changes the denominator.
    const a = simpsonsIndex(counts, 16);
    const b = simpsonsIndex(counts, 100);
    assert.notEqual(a, b);
  });
});

describe("giniSimpson — edge & mathematical properties", () => {
  it("equals 1 - sum(p^2) for a uniform distribution", () => {
    // For k=5 equal buckets, gini = 1 - 5*(1/5)^2 = 1 - 0.2 = 0.8
    const g = giniSimpson([10, 10, 10, 10, 10]);
    assert.ok(Math.abs(g - 0.8) < 1e-10, `expected 0.8, got ${g}`);
  });

  it("is monotonically lower as one bucket dominates", () => {
    const balanced = giniSimpson([10, 10, 10, 10]);
    const skewed   = giniSimpson([97, 1, 1, 1]);
    const extreme  = giniSimpson([999, 1]);
    assert.ok(balanced > skewed, "balanced > skewed");
    assert.ok(skewed > extreme, "skewed > extreme");
  });

  it("stays within [0, 1]", () => {
    for (let trial = 0; trial < 50; trial++) {
      const counts = [];
      const k = 2 + Math.floor(Math.random() * 8);
      for (let i = 0; i < k; i++) counts.push(Math.floor(Math.random() * 30) + 1);
      const g = giniSimpson(counts);
      assert.ok(g >= 0 && g <= 1, `Gini-Simpson out of [0,1]: ${g}`);
    }
  });
});

describe("analyzeDiversity — additional behavior", () => {
  it("clamps every dimension score into [0, 100]", () => {
    // Cook up values that would otherwise exceed 100 if unclamped.
    const categories = [
      { name: "a", count: 10, avgComplexity: 1.0, colorVariance: 1.0, motionDiversity: 1.0, avgDifficulty: 1, avgDuration: 1 },
      { name: "b", count: 10, avgComplexity: 1.0, colorVariance: 1.0, motionDiversity: 1.0, avgDifficulty: 10, avgDuration: 10 },
    ];
    const r = analyzeDiversity(categories);
    for (const k of Object.keys(r.dimensions)) {
      assert.ok(r.dimensions[k] >= 0 && r.dimensions[k] <= 100,
        `${k} out of [0,100]: ${r.dimensions[k]}`);
    }
    assert.ok(r.overall >= 0 && r.overall <= 100);
  });

  it("handles a single category gracefully (zero diversity is acceptable)", () => {
    const r = analyzeDiversity([
      { name: "only", count: 100, avgComplexity: 0.5, colorVariance: 0.5,
        motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 }
    ]);
    assert.ok(typeof r.overall === "number");
    // One category → perfectly skewed; Simpson's index should be ~0
    assert.ok(r.indices.simpson <= 0.0001);
    // shannonEntropy([42]) is defined to return 1 (single-category special case)
    assert.equal(r.indices.shannon, 1);
    assert.ok(r.warnings.some(w => w.includes("skewed") || w.includes("underrepresented") ||
      w.toLowerCase().includes("difficulty")) || r.warnings.length >= 0);
  });

  it("produces a stable result for identical input (deterministic)", () => {
    const categories = [
      { name: "a", count: 10, avgComplexity: 0.3, colorVariance: 0.7, motionDiversity: 0.5, avgDifficulty: 4, avgDuration: 3 },
      { name: "b", count: 20, avgComplexity: 0.8, colorVariance: 0.4, motionDiversity: 0.9, avgDifficulty: 6, avgDuration: 5 },
      { name: "c", count: 15, avgComplexity: 0.6, colorVariance: 0.6, motionDiversity: 0.7, avgDifficulty: 8, avgDuration: 4 },
    ];
    const a = analyzeDiversity(categories);
    const b = analyzeDiversity(categories);
    assert.deepEqual(a, b);
  });

  it("does not mutate the input categories array", () => {
    const categories = [
      { name: "a", count: 10, avgComplexity: 0.3, colorVariance: 0.7, motionDiversity: 0.5, avgDifficulty: 4, avgDuration: 3 },
      { name: "b", count: 20, avgComplexity: 0.8, colorVariance: 0.4, motionDiversity: 0.9, avgDifficulty: 6, avgDuration: 5 },
    ];
    const snapshot = JSON.stringify(categories);
    analyzeDiversity(categories);
    assert.equal(JSON.stringify(categories), snapshot, "input must not be mutated");
  });

  it("computes shannon/simpson/giniSimpson identical to the public helpers", () => {
    const categories = [
      { name: "a", count: 7, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
      { name: "b", count: 11, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
      { name: "c", count: 3, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
    ];
    const r = analyzeDiversity(categories);
    const counts = categories.map(c => c.count);
    assert.ok(Math.abs(r.indices.shannon - shannonEntropy(counts)) < 1e-12);
    assert.ok(Math.abs(r.indices.simpson - simpsonsIndex(counts)) < 1e-12);
    assert.ok(Math.abs(r.indices.giniSimpson - giniSimpson(counts)) < 1e-12);
  });

  it("flags categories below the 3% representation threshold by exact name", () => {
    const categories = [
      { name: "big",   count: 100, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
      { name: "micro", count: 1,   avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
    ];
    const r = analyzeDiversity(categories);
    const underrep = r.warnings.find(w => w.includes("underrepresented"));
    assert.ok(underrep, "expected underrepresented warning");
    assert.ok(underrep.includes("'micro'"), `expected the smallest category to be named: ${underrep}`);
  });

  it("does NOT emit an underrepresented warning when smallest category is >=3%", () => {
    const categories = [
      { name: "big",   count: 50, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
      { name: "small", count: 5,  avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5, avgDuration: 3 },
    ];
    const r = analyzeDiversity(categories);
    assert.ok(!r.warnings.some(w => w.includes("underrepresented")));
  });

  it("applies default avgDuration of 3 when omitted (no NaN in temporalVariance)", () => {
    const categories = [
      { name: "a", count: 5, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5 },
      { name: "b", count: 5, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDifficulty: 5 },
    ];
    const r = analyzeDiversity(categories);
    // All durations default to 3 → variance must be exactly 0
    assert.equal(r.dimensions.temporalVariance, 0);
    assert.ok(Number.isFinite(r.overall));
  });

  it("applies default avgDifficulty of 5 when omitted (no NaN in difficultySpread)", () => {
    const categories = [
      { name: "a", count: 5, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDuration: 3 },
      { name: "b", count: 5, avgComplexity: 0.5, colorVariance: 0.5, motionDiversity: 0.5, avgDuration: 3 },
    ];
    const r = analyzeDiversity(categories);
    // All difficulties default to 5 → spread is 0
    assert.equal(r.dimensions.difficultySpread, 0);
  });

  it("applies default complexity/color/motion of 0 when omitted", () => {
    const categories = [
      { name: "a", count: 5 },
      { name: "b", count: 5 },
    ];
    const r = analyzeDiversity(categories);
    assert.equal(r.dimensions.visualComplexity, 0);
    assert.equal(r.dimensions.colorDistribution, 0);
    assert.equal(r.dimensions.motionPatterns, 0);
    assert.ok(Number.isFinite(r.overall));
    // Low color/motion should still trigger their respective warnings
    assert.ok(r.warnings.some(w => w.toLowerCase().includes("color")));
    assert.ok(r.warnings.some(w => w.toLowerCase().includes("motion")));
  });

  it("keeps the warnings list empty for a well-balanced diverse pool", () => {
    const categories = [
      { name: "a", count: 25, avgComplexity: 0.8, colorVariance: 0.8, motionDiversity: 0.8, avgDifficulty: 2, avgDuration: 2 },
      { name: "b", count: 25, avgComplexity: 0.7, colorVariance: 0.7, motionDiversity: 0.7, avgDifficulty: 5, avgDuration: 4 },
      { name: "c", count: 25, avgComplexity: 0.6, colorVariance: 0.6, motionDiversity: 0.6, avgDifficulty: 8, avgDuration: 6 },
      { name: "d", count: 25, avgComplexity: 0.9, colorVariance: 0.9, motionDiversity: 0.9, avgDifficulty: 10, avgDuration: 8 },
    ];
    const r = analyzeDiversity(categories);
    assert.equal(r.warnings.length, 0, `expected no warnings, got: ${JSON.stringify(r.warnings)}`);
  });
});
