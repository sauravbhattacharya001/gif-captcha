/**
 * challenge-diversity-analyzer.js — Measures diversity metrics for CAPTCHA challenge pools.
 *
 * Provides Shannon entropy, Simpson's index, Gini-Simpson index, and composite
 * diversity scoring across multiple dimensions (category balance, visual complexity,
 * color distribution, motion patterns, difficulty spread, temporal variance).
 *
 * Helps researchers ensure their challenge pools are diverse enough to resist
 * bot pattern exploitation.
 *
 * @module challenge-diversity-analyzer
 */

"use strict";

// ── Diversity Indices ────────────────────────────────────────────

/**
 * Compute normalized Shannon entropy (0–1) for a set of category counts.
 *
 * @param {number[]} counts - Array of counts per category
 * @param {number} [precomputedTotal] - Optional pre-summed total to avoid redundant O(n) pass
 * @returns {number} Normalized entropy (1 = perfectly uniform)
 */
function shannonEntropy(counts, precomputedTotal) {
    var total = precomputedTotal != null ? precomputedTotal : _sumArray(counts);
    if (total === 0) return 0;
    var maxE = Math.log2(counts.length);
    if (maxE === 0) return 1;
    var e = 0;
    for (var i = 0; i < counts.length; i++) {
        if (counts[i] > 0) {
            var p = counts[i] / total;
            e -= p * Math.log2(p);
        }
    }
    return e / maxE;
}

/**
 * Compute Simpson's Diversity Index (1 - D).
 * Probability that two randomly chosen challenges are different types.
 *
 * @param {number[]} counts - Array of counts per category
 * @param {number} [precomputedTotal] - Optional pre-summed total to avoid redundant O(n) pass
 * @returns {number} Simpson's index (0–1, higher = more diverse)
 */
function simpsonsIndex(counts, precomputedTotal) {
    var total = precomputedTotal != null ? precomputedTotal : _sumArray(counts);
    if (total <= 1) return 0;
    var d = 0;
    for (var i = 0; i < counts.length; i++) {
        d += counts[i] * (counts[i] - 1);
    }
    return 1 - d / (total * (total - 1));
}

/**
 * Compute Gini-Simpson index.
 *
 * @param {number[]} counts - Array of counts per category
 * @param {number} [precomputedTotal] - Optional pre-summed total to avoid redundant O(n) pass
 * @returns {number} Gini-Simpson index (0–1)
 */
function giniSimpson(counts, precomputedTotal) {
    var total = precomputedTotal != null ? precomputedTotal : _sumArray(counts);
    if (total === 0) return 0;
    var sum = 0;
    for (var i = 0; i < counts.length; i++) {
        var p = counts[i] / total;
        sum += p * p;
    }
    return 1 - sum;
}

/**
 * Sum an array of numbers.  Extracted so that callers (index functions)
 * can share a precomputed total instead of each computing their own O(n) sum.
 *
 * @param {number[]} arr
 * @returns {number}
 */
function _sumArray(arr) {
    var s = 0;
    for (var i = 0; i < arr.length; i++) s += arr[i];
    return s;
}

// ── Dimension Analyzers ──────────────────────────────────────────

/**
 * @typedef {Object} CategoryProfile
 * @property {string} name - Category name
 * @property {number} count - Number of challenges
 * @property {number} avgComplexity - Average visual complexity (0–1)
 * @property {number} colorVariance - Color distribution variance (0–1)
 * @property {number} motionDiversity - Motion pattern diversity (0–1)
 * @property {number} avgDifficulty - Average difficulty level (1–10)
 * @property {number} avgDuration - Average GIF duration in seconds
 */

/**
 * @typedef {Object} DiversityReport
 * @property {number} overall - Overall diversity score (0–100)
 * @property {Object} dimensions - Per-dimension scores (0–100)
 * @property {number} dimensions.categoryBalance - Shannon entropy of category distribution
 * @property {number} dimensions.visualComplexity - Spread of visual complexity
 * @property {number} dimensions.colorDistribution - Average color variance
 * @property {number} dimensions.motionPatterns - Average motion diversity
 * @property {number} dimensions.difficultySpread - Range coverage of difficulty levels
 * @property {number} dimensions.temporalVariance - Standard deviation of durations
 * @property {Object} indices - Raw statistical indices
 * @property {number} indices.shannon - Normalized Shannon entropy
 * @property {number} indices.simpson - Simpson's diversity index
 * @property {number} indices.giniSimpson - Gini-Simpson index
 * @property {string[]} warnings - List of detected diversity issues
 */

/**
 * Analyze the diversity of a challenge pool.
 *
 * @param {CategoryProfile[]} categories - Array of category profiles
 * @returns {DiversityReport} Computed diversity report
 */
function analyzeDiversity(categories) {
    if (!categories || categories.length === 0) {
        return {
            overall: 0,
            dimensions: {
                categoryBalance: 0, visualComplexity: 0, colorDistribution: 0,
                motionPatterns: 0, difficultySpread: 0, temporalVariance: 0
            },
            indices: { shannon: 0, simpson: 0, giniSimpson: 0 },
            warnings: ["No categories provided"]
        };
    }

    // Single-pass extraction of all per-category metrics — replaces
    // 5 separate .map() allocations + 5 .reduce() iterations (10×N)
    // with one O(N) loop that collects counts, running min/max/sum for
    // complexity, color variance, motion diversity, difficulty, and
    // duration.  The counts array is still needed for the index functions.
    var n = categories.length;
    var counts = new Array(n);
    var total = 0;
    var cSum = 0, cMin = Infinity, cMax = -Infinity;
    var colorSum = 0;
    var motionSum = 0;
    var dMin = Infinity, dMax = -Infinity;
    var durSum = 0;

    for (var ci = 0; ci < n; ci++) {
        var cat = categories[ci];
        counts[ci] = cat.count;
        total += cat.count;

        var complexity = cat.avgComplexity || 0;
        cSum += complexity;
        if (complexity < cMin) cMin = complexity;
        if (complexity > cMax) cMax = complexity;

        colorSum += (cat.colorVariance || 0);
        motionSum += (cat.motionDiversity || 0);

        var diff = cat.avgDifficulty || 5;
        if (diff < dMin) dMin = diff;
        if (diff > dMax) dMax = diff;

        durSum += (cat.avgDuration || 3);
    }

    // Dimension 1: Category Balance
    var catBalance = shannonEntropy(counts, total) * 100;

    // Dimension 2: Visual Complexity spread
    var cMean = cSum / n;
    var visualComplexity = Math.min(100, ((cMax - cMin) * 0.5 + cMean * 0.5) * 100);

    // Dimension 3: Color Distribution
    var colorDist = (colorSum / n) * 100;

    // Dimension 4: Motion Patterns
    var motionScore = (motionSum / n) * 100;

    // Dimension 5: Difficulty Spread
    var diffSpread = Math.min(100, (dMax - dMin) / 9 * 100);

    // Dimension 6: Temporal Variance — second pass for variance
    // (needs the mean first, so two passes is mathematically necessary,
    //  but the first pass is merged into the main loop above).
    var dMean = durSum / n;
    var dVar = 0;
    for (var dvi = 0; dvi < n; dvi++) {
        var dur = categories[dvi].avgDuration || 3;
        dVar += (dur - dMean) * (dur - dMean);
    }
    dVar /= n;
    var temporalVariance = Math.min(100, Math.sqrt(dVar) / 3 * 100);

    // Weighted overall
    var dims = [catBalance, visualComplexity, colorDist, motionScore, diffSpread, temporalVariance];
    var weights = [0.25, 0.15, 0.15, 0.15, 0.15, 0.15];
    var overall = 0;
    for (var i = 0; i < dims.length; i++) overall += dims[i] * weights[i];

    // Warnings
    var warnings = [];
    if (catBalance < 50) warnings.push("Category distribution is highly skewed — bots can exploit dominant types");
    if (colorDist < 40) warnings.push("Low color diversity — automated pixel analysis may succeed");
    if (motionScore < 40) warnings.push("Motion patterns lack variety — add different animation styles");
    if (diffSpread < 30) warnings.push("Difficulty range too narrow — broaden for better adaptive calibration");

    var minCat = categories.reduce(function(a, c) { return c.count < a.count ? c : a; });
    if (minCat.count < total * 0.03) {
        warnings.push("Category '" + minCat.name + "' severely underrepresented (" +
                       (minCat.count / total * 100).toFixed(1) + "%)");
    }

    return {
        overall: Math.round(overall),
        dimensions: {
            categoryBalance: Math.round(catBalance),
            visualComplexity: Math.round(visualComplexity),
            colorDistribution: Math.round(colorDist),
            motionPatterns: Math.round(motionScore),
            difficultySpread: Math.round(diffSpread),
            temporalVariance: Math.round(temporalVariance)
        },
        indices: {
            shannon: shannonEntropy(counts, total),
            simpson: simpsonsIndex(counts, total),
            giniSimpson: giniSimpson(counts, total)
        },
        warnings: warnings
    };
}

// ── Exports ──────────────────────────────────────────────────────

module.exports = {
    shannonEntropy: shannonEntropy,
    simpsonsIndex: simpsonsIndex,
    giniSimpson: giniSimpson,
    analyzeDiversity: analyzeDiversity
};
