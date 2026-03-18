"use strict";

/**
 * CaptchaStrengthScorer — evaluates CAPTCHA challenge configurations and
 * returns a composite strength score with a per-dimension breakdown.
 *
 * Helps operators understand how hard their CAPTCHA is for both humans and
 * bots, tune parameters, and compare configurations side-by-side.
 *
 * Dimensions scored (each 0-100):
 *   - visual:     distortion, noise, color complexity
 *   - temporal:   frame count, animation speed, frame variance
 *   - cognitive:  question complexity, number of choices, ambiguity
 *   - entropy:    randomness of challenge pool / answer distribution
 *   - resilience: estimated resistance to common automated solvers
 *
 * Composite score is a weighted average (weights are configurable).
 *
 * Usage:
 *   var scorer = createCaptchaStrengthScorer();
 *   var result = scorer.score({
 *     frameCount: 12,
 *     animationSpeedMs: 80,
 *     distortionLevel: 7,
 *     noiseLevel: 5,
 *     colorCount: 6,
 *     choiceCount: 4,
 *     questionType: 'sequence',
 *     poolSize: 500,
 *     answerDistribution: [0.25, 0.25, 0.25, 0.25]
 *   });
 *   // result.composite   → 72
 *   // result.grade        → 'B+'
 *   // result.dimensions   → { visual: 68, temporal: 80, ... }
 *   // result.suggestions  → ['Increase distortion for stronger bot resistance']
 *
 *   var cmp = scorer.compare(configA, configB);
 *   // cmp.winner → 'A'  cmp.deltas → { visual: +12, ... }
 *
 * @module gif-captcha/captcha-strength-scorer
 */

// ── Defaults ────────────────────────────────────────────────────────

var DEFAULT_WEIGHTS = {
  visual: 0.25,
  temporal: 0.15,
  cognitive: 0.20,
  entropy: 0.15,
  resilience: 0.25
};

var QUESTION_COMPLEXITY = {
  "click": 10,
  "click_shape": 20,
  "count_objects": 35,
  "odd_one_out": 45,
  "spatial": 50,
  "sequence": 65,
  "temporal": 70,
  "multi_step": 85,
  "reasoning": 95
};

var GRADE_THRESHOLDS = [
  { min: 95, grade: "A+" },
  { min: 90, grade: "A"  },
  { min: 85, grade: "A-" },
  { min: 80, grade: "B+" },
  { min: 75, grade: "B"  },
  { min: 70, grade: "B-" },
  { min: 65, grade: "C+" },
  { min: 60, grade: "C"  },
  { min: 55, grade: "C-" },
  { min: 50, grade: "D+" },
  { min: 45, grade: "D"  },
  { min: 40, grade: "D-" },
  { min: 0,  grade: "F"  }
];

// ── Helpers ─────────────────────────────────────────────────────────

function clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }

function lerp(value, inMin, inMax, outMin, outMax) {
  if (inMax === inMin) return outMax;
  var t = (value - inMin) / (inMax - inMin);
  t = clamp(t, 0, 1);
  return outMin + t * (outMax - outMin);
}

function shannonEntropy(distribution) {
  if (!distribution || distribution.length === 0) return 0;
  var sum = 0;
  var i;
  for (i = 0; i < distribution.length; i++) sum += distribution[i];
  if (sum === 0) return 0;
  var entropy = 0;
  for (i = 0; i < distribution.length; i++) {
    var p = distribution[i] / sum;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  // Normalize to 0-1 relative to maximum possible entropy
  var maxEntropy = Math.log2(distribution.length);
  return maxEntropy > 0 ? entropy / maxEntropy : 0;
}

function toGrade(score) {
  for (var i = 0; i < GRADE_THRESHOLDS.length; i++) {
    if (score >= GRADE_THRESHOLDS[i].min) return GRADE_THRESHOLDS[i].grade;
  }
  return "F";
}

// ── Dimension Scorers ───────────────────────────────────────────────

function scoreVisual(cfg) {
  // distortionLevel: 0-10, noiseLevel: 0-10, colorCount: 1-16+
  var distortion = lerp(cfg.distortionLevel || 0, 0, 10, 0, 100);
  var noise = lerp(cfg.noiseLevel || 0, 0, 10, 0, 100);
  var color = lerp(cfg.colorCount || 1, 1, 16, 10, 80);
  return Math.round(distortion * 0.45 + noise * 0.30 + color * 0.25);
}

function scoreTemporal(cfg) {
  // frameCount: 1-30+, animationSpeedMs: 20-500 (lower = faster = harder)
  var frames = lerp(cfg.frameCount || 1, 1, 30, 5, 100);
  // Faster animation → harder for bots
  var speed = lerp(cfg.animationSpeedMs || 200, 500, 20, 10, 100);
  // Frame variance bonus
  var variance = cfg.frameVariance ? clamp(cfg.frameVariance * 10, 0, 30) : 0;
  return Math.round(frames * 0.40 + speed * 0.40 + variance * 0.20 + (variance > 0 ? variance : 0));
}

function scoreCognitive(cfg) {
  var qType = cfg.questionType || "click";
  var baseComplexity = QUESTION_COMPLEXITY[qType] != null ? QUESTION_COMPLEXITY[qType] : 40;
  // More choices = harder
  var choices = lerp(cfg.choiceCount || 2, 2, 8, 20, 80);
  // Ambiguity factor (0-1)
  var ambiguity = lerp(cfg.ambiguityFactor || 0, 0, 1, 0, 30);
  return Math.round(baseComplexity * 0.50 + choices * 0.30 + ambiguity * 0.20);
}

function scoreEntropy(cfg) {
  // Pool size — more challenges = less predictable
  var pool = lerp(cfg.poolSize || 10, 10, 1000, 10, 80);
  // Answer distribution uniformity
  var dist = cfg.answerDistribution
    ? shannonEntropy(cfg.answerDistribution) * 100
    : 50; // assume moderate if not provided
  return Math.round(pool * 0.50 + dist * 0.50);
}

function scoreResilience(cfg) {
  // Composite heuristic: temporal + visual tricks that defeat ML scrapers
  var base = 30;
  // High frame count with fast speed = hard to scrape individual frames
  if ((cfg.frameCount || 1) > 10 && (cfg.animationSpeedMs || 200) < 100) base += 20;
  // High distortion
  if ((cfg.distortionLevel || 0) >= 6) base += 15;
  // Non-trivial question type
  var qType = cfg.questionType || "click";
  if (QUESTION_COMPLEXITY[qType] != null && QUESTION_COMPLEXITY[qType] >= 50) base += 15;
  // Large pool
  if ((cfg.poolSize || 10) >= 200) base += 10;
  // Noise
  if ((cfg.noiseLevel || 0) >= 5) base += 10;
  return clamp(base, 0, 100);
}

// ── Suggestion Engine ───────────────────────────────────────────────

function generateSuggestions(cfg, dimensions) {
  var suggestions = [];
  if (dimensions.visual < 40) {
    if ((cfg.distortionLevel || 0) < 4) suggestions.push("Increase distortionLevel (currently " + (cfg.distortionLevel || 0) + ") to at least 4 for stronger bot resistance.");
    if ((cfg.noiseLevel || 0) < 3) suggestions.push("Add more noise (noiseLevel " + (cfg.noiseLevel || 0) + " → 3+) to hinder OCR/ML extraction.");
  }
  if (dimensions.temporal < 40) {
    if ((cfg.frameCount || 1) < 8) suggestions.push("Use more animation frames (" + (cfg.frameCount || 1) + " → 8+) to increase temporal complexity.");
    if ((cfg.animationSpeedMs || 200) > 200) suggestions.push("Decrease animation speed (" + (cfg.animationSpeedMs || 200) + "ms → <200ms) — slower GIFs are easier to scrape.");
  }
  if (dimensions.cognitive < 40) {
    suggestions.push("Consider a more complex question type (current: " + (cfg.questionType || "click") + "). Try 'sequence', 'temporal', or 'reasoning'.");
  }
  if (dimensions.entropy < 40) {
    if ((cfg.poolSize || 10) < 100) suggestions.push("Expand the challenge pool (currently ~" + (cfg.poolSize || 10) + "). 200+ recommended to prevent memorization attacks.");
  }
  if (dimensions.resilience < 50) {
    suggestions.push("Overall resilience is low. Combine higher distortion, faster animation, and complex question types for better security.");
  }
  if (suggestions.length === 0) {
    suggestions.push("Configuration looks strong across all dimensions. No critical improvements needed.");
  }
  return suggestions;
}

// ── Factory ─────────────────────────────────────────────────────────

/**
 * Create a CaptchaStrengthScorer instance.
 *
 * @param {Object} [options]
 * @param {Object} [options.weights] Custom dimension weights (should sum to ~1.0)
 * @returns {Object} scorer API
 */
function createCaptchaStrengthScorer(options) {
  options = options || {};
  var weights = {};
  var k;
  for (k in DEFAULT_WEIGHTS) {
    if (DEFAULT_WEIGHTS.hasOwnProperty(k)) {
      weights[k] = (options.weights && options.weights[k] != null) ? options.weights[k] : DEFAULT_WEIGHTS[k];
    }
  }

  // Normalize weights
  var wSum = 0;
  for (k in weights) {
    if (weights.hasOwnProperty(k)) wSum += weights[k];
  }
  if (wSum > 0 && Math.abs(wSum - 1) > 0.001) {
    for (k in weights) {
      if (weights.hasOwnProperty(k)) weights[k] = weights[k] / wSum;
    }
  }

  /**
   * Score a single challenge configuration.
   * @param {Object} cfg Challenge configuration parameters
   * @returns {Object} { composite, grade, dimensions, suggestions, config }
   */
  function score(cfg) {
    cfg = cfg || {};
    var dimensions = {
      visual: scoreVisual(cfg),
      temporal: scoreTemporal(cfg),
      cognitive: scoreCognitive(cfg),
      entropy: scoreEntropy(cfg),
      resilience: scoreResilience(cfg)
    };

    var composite = 0;
    for (var d in dimensions) {
      if (dimensions.hasOwnProperty(d) && weights[d] != null) {
        composite += dimensions[d] * weights[d];
      }
    }
    composite = Math.round(composite);

    return {
      composite: composite,
      grade: toGrade(composite),
      dimensions: dimensions,
      suggestions: generateSuggestions(cfg, dimensions),
      config: cfg
    };
  }

  /**
   * Compare two configurations side-by-side.
   * @param {Object} cfgA First configuration
   * @param {Object} cfgB Second configuration
   * @returns {Object} { a, b, winner, deltas }
   */
  function compare(cfgA, cfgB) {
    var a = score(cfgA);
    var b = score(cfgB);
    var deltas = {};
    for (var d in a.dimensions) {
      if (a.dimensions.hasOwnProperty(d)) {
        deltas[d] = a.dimensions[d] - b.dimensions[d];
      }
    }
    return {
      a: a,
      b: b,
      winner: a.composite > b.composite ? "A" : (b.composite > a.composite ? "B" : "tie"),
      compositeDelta: a.composite - b.composite,
      deltas: deltas
    };
  }

  /**
   * Batch-score an array of configurations and rank them.
   * @param {Array<Object>} configs Array of challenge configs
   * @returns {Array<Object>} Scored results sorted best-to-worst
   */
  function rank(configs) {
    if (!Array.isArray(configs)) return [];
    var results = [];
    for (var i = 0; i < configs.length; i++) {
      var r = score(configs[i]);
      r.index = i;
      results.push(r);
    }
    results.sort(function (a, b) { return b.composite - a.composite; });
    for (var j = 0; j < results.length; j++) {
      results[j].rank = j + 1;
    }
    return results;
  }

  /**
   * Get the current scoring weights.
   * @returns {Object}
   */
  function getWeights() {
    var copy = {};
    for (var k in weights) {
      if (weights.hasOwnProperty(k)) copy[k] = weights[k];
    }
    return copy;
  }

  return {
    score: score,
    compare: compare,
    rank: rank,
    getWeights: getWeights,
    QUESTION_TYPES: Object.keys(QUESTION_COMPLEXITY),
    GRADE_THRESHOLDS: GRADE_THRESHOLDS
  };
}

// ── Exports ─────────────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createCaptchaStrengthScorer: createCaptchaStrengthScorer };
}
