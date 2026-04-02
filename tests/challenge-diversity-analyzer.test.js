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
