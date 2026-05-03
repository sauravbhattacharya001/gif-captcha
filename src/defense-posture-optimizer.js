/**
 * DefensePostureOptimizer — Autonomous multi-objective defense configuration
 * optimization for GIF-CAPTCHA deployments.
 *
 * Analyzes defense metrics across multiple dimensions and computes Pareto-optimal
 * configurations that balance bot catch rate, human friction, latency, and
 * challenge diversity. Tracks posture drift over time and recommends re-tuning
 * when the current configuration degrades.
 *
 * Key capabilities:
 *   - 6 defense dimensions: catch rate, human friction, latency cost,
 *     challenge diversity, attack surface coverage, fatigue risk
 *   - Multi-objective Pareto frontier computation (no single "best" — presents trade-offs)
 *   - Autonomous drift detection with configurable sensitivity
 *   - Configuration recommendation engine with priority weighting
 *   - Historical posture timeline with trend analysis
 *   - What-if simulation for proposed config changes
 *   - Budget-constrained optimization (maximize protection within friction budget)
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/defense-posture-optimizer
 */

"use strict";

var _shared = require("./shared-utils");
var _cryptoUtils = require("./crypto-utils");
var _now = _shared._now;
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _clamp = _shared._clamp;
var _posOpt = _shared._posOpt;
var _nnOpt = _shared._nnOpt;
var _linearRegression = _shared._linearRegression;

// ── Constants ───────────────────────────────────────────────────────

var DIMENSIONS = [
  "CATCH_RATE",          // % of bots detected and blocked
  "HUMAN_FRICTION",      // friction imposed on legitimate users (lower = better)
  "LATENCY_COST",        // additional latency introduced by defense layers (ms)
  "CHALLENGE_DIVERSITY", // variety in challenge types (higher = harder to script)
  "ATTACK_SURFACE",      // coverage of known attack vectors (higher = better)
  "FATIGUE_RISK"         // risk of user abandonment from excessive challenges
];

var KNOB_TYPES = [
  "DIFFICULTY",          // challenge difficulty level (0-1)
  "RATE_LIMIT",          // requests per window
  "HONEYPOT_DENSITY",    // fraction of pages with honeypots
  "RETRY_LIMIT",         // max retries before lockout
  "PROOF_OF_WORK",       // PoW difficulty multiplier
  "BEHAVIORAL_DEPTH",    // depth of behavioral analysis (0-1)
  "DELAY_INJECTION",     // artificial delay range (ms)
  "MULTI_FACTOR"         // whether multi-challenge is enabled (0 or 1)
];

var DRIFT_STATES = ["STABLE", "DRIFTING", "DEGRADED", "CRITICAL"];

var MAX_SNAPSHOTS = 500;
var MAX_SIMULATIONS = 200;
var MAX_PARETO_CONFIGS = 100;
var DRIFT_WINDOW = 10;       // snapshots to compare for drift
var DRIFT_THRESHOLD = 0.15;  // 15% change triggers drift warning
var CRITICAL_THRESHOLD = 0.30; // 30% change is critical

// ── Helpers ─────────────────────────────────────────────────────────

function _uid() {
  return _cryptoUtils.secureRandomHex(12);
}

function _deepCopy(obj) {
  return JSON.parse(JSON.stringify(obj));
}


/**
 * Check if point A dominates point B in multi-objective sense.
 * A dominates B if A is >= B on ALL objectives and > on at least one.
 * (Assumes higher = better for all normalized objectives.)
 */
function _dominates(a, b) {
  var dominated = false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return false;
    if (a[i] > b[i]) dominated = true;
  }
  return dominated;
}


// ── DefensePostureOptimizer ──────────────────────────────────────────

/**
 * @constructor
 * @param {Object} [options]
 * @param {number} [options.maxSnapshots=500]
 * @param {number} [options.maxSimulations=200]
 * @param {number} [options.driftWindow=10]
 * @param {number} [options.driftThreshold=0.15]
 * @param {number} [options.criticalThreshold=0.30]
 */
function DefensePostureOptimizer(options) {
  var opts = options || {};
  this._maxSnapshots = _posOpt(opts.maxSnapshots, MAX_SNAPSHOTS);
  this._maxSimulations = _posOpt(opts.maxSimulations, MAX_SIMULATIONS);
  this._driftWindow = _posOpt(opts.driftWindow, DRIFT_WINDOW);
  this._driftThreshold = opts.driftThreshold != null ? opts.driftThreshold : DRIFT_THRESHOLD;
  this._criticalThreshold = opts.criticalThreshold != null ? opts.criticalThreshold : CRITICAL_THRESHOLD;

  // State
  this._snapshots = [];       // historical posture snapshots
  this._currentConfig = null; // current knob configuration
  this._simulations = [];     // what-if simulation results
  this._paretoFrontier = [];  // current Pareto-optimal configs
  this._driftState = "STABLE";
  this._recommendations = []; // pending recommendations
}

// ── Configuration Management ────────────────────────────────────────

/**
 * Set the current defense configuration (knob values).
 * @param {Object} config - key-value pairs from KNOB_TYPES
 * @returns {Object} validated config
 */
DefensePostureOptimizer.prototype.setConfig = function (config) {
  if (!config || typeof config !== "object") {
    throw new Error("config must be an object");
  }
  var validated = {};
  for (var i = 0; i < KNOB_TYPES.length; i++) {
    var knob = KNOB_TYPES[i];
    if (config[knob] != null) {
      validated[knob] = typeof config[knob] === "number" ? config[knob] : 0;
    }
  }
  this._currentConfig = validated;
  return _deepCopy(validated);
};

/**
 * Get the current configuration.
 * @returns {Object|null}
 */
DefensePostureOptimizer.prototype.getConfig = function () {
  return this._currentConfig ? _deepCopy(this._currentConfig) : null;
};

// ── Metric Recording ────────────────────────────────────────────────

/**
 * Record a posture snapshot — a point-in-time measurement of all defense dimensions.
 * @param {Object} metrics
 * @param {number} metrics.catchRate        - 0-1, fraction of bots caught
 * @param {number} metrics.humanFriction    - 0-1, friction level (0=none, 1=max)
 * @param {number} metrics.latencyCost      - milliseconds of added latency
 * @param {number} metrics.challengeDiversity - 0-1, variety score
 * @param {number} metrics.attackSurface    - 0-1, coverage of attack vectors
 * @param {number} metrics.fatigueRisk      - 0-1, user fatigue probability
 * @returns {Object} the recorded snapshot
 */
DefensePostureOptimizer.prototype.recordSnapshot = function (metrics) {
  if (!metrics || typeof metrics !== "object") {
    throw new Error("metrics must be an object");
  }

  var snapshot = {
    id: _uid(),
    timestamp: _now(),
    config: this._currentConfig ? _deepCopy(this._currentConfig) : null,
    metrics: {
      catchRate: _clamp(_nnOpt(metrics.catchRate, 0), 0, 1),
      humanFriction: _clamp(_nnOpt(metrics.humanFriction, 0), 0, 1),
      latencyCost: _nnOpt(metrics.latencyCost, 0),
      challengeDiversity: _clamp(_nnOpt(metrics.challengeDiversity, 0), 0, 1),
      attackSurface: _clamp(_nnOpt(metrics.attackSurface, 0), 0, 1),
      fatigueRisk: _clamp(_nnOpt(metrics.fatigueRisk, 0), 0, 1)
    },
    driftState: this._driftState
  };

  this._snapshots.push(snapshot);
  if (this._snapshots.length > this._maxSnapshots) {
    this._snapshots.splice(0, this._snapshots.length - this._maxSnapshots);
  }

  // Detect drift
  this._detectDrift();

  return _deepCopy(snapshot);
};

// ── Drift Detection ─────────────────────────────────────────────────

/**
 * Internal drift detection — compares recent snapshots against baseline.
 */
DefensePostureOptimizer.prototype._detectDrift = function () {
  var snaps = this._snapshots;
  if (snaps.length < this._driftWindow * 2) {
    this._driftState = "STABLE";
    return;
  }

  var recentStart = snaps.length - this._driftWindow;
  var baselineStart = recentStart - this._driftWindow;

  // Compute average composite score for baseline and recent windows
  var baselineScores = [];
  var recentScores = [];

  for (var i = baselineStart; i < recentStart; i++) {
    baselineScores.push(this._compositeScore(snaps[i].metrics));
  }
  for (var j = recentStart; j < snaps.length; j++) {
    recentScores.push(this._compositeScore(snaps[j].metrics));
  }

  var baselineMean = _mean(baselineScores);
  var recentMean = _mean(recentScores);

  if (baselineMean === 0) {
    this._driftState = "STABLE";
    return;
  }

  var drift = Math.abs(recentMean - baselineMean) / baselineMean;

  if (drift >= this._criticalThreshold) {
    this._driftState = "CRITICAL";
  } else if (drift >= this._driftThreshold) {
    this._driftState = recentMean < baselineMean ? "DEGRADED" : "DRIFTING";
  } else {
    this._driftState = "STABLE";
  }
};

/**
 * Composite posture score (0-1, higher = better defense posture).
 * Weights: catch rate & attack surface high, friction & fatigue inverted.
 */
DefensePostureOptimizer.prototype._compositeScore = function (m) {
  // Higher is better: catchRate, challengeDiversity, attackSurface
  // Lower is better: humanFriction, fatigueRisk
  // latencyCost normalized against a 5000ms max
  var latencyNorm = 1 - _clamp(m.latencyCost / 5000, 0, 1);

  var weights = {
    catchRate: 0.30,
    humanFriction: 0.20,
    latencyCost: 0.10,
    challengeDiversity: 0.15,
    attackSurface: 0.15,
    fatigueRisk: 0.10
  };

  return (
    weights.catchRate * m.catchRate +
    weights.humanFriction * (1 - m.humanFriction) +
    weights.latencyCost * latencyNorm +
    weights.challengeDiversity * m.challengeDiversity +
    weights.attackSurface * m.attackSurface +
    weights.fatigueRisk * (1 - m.fatigueRisk)
  );
};

/**
 * Get current drift state and details.
 * @returns {Object}
 */
DefensePostureOptimizer.prototype.getDriftStatus = function () {
  var snaps = this._snapshots;
  var recent = snaps.length >= this._driftWindow
    ? snaps.slice(snaps.length - this._driftWindow)
    : snaps.slice();

  var scores = [];
  for (var i = 0; i < recent.length; i++) {
    scores.push(this._compositeScore(recent[i].metrics));
  }

  var trend = scores.length >= 3 ? _linearRegression(scores) : null;

  return {
    state: this._driftState,
    currentScore: scores.length > 0 ? scores[scores.length - 1] : null,
    averageScore: scores.length > 0 ? _mean(scores) : null,
    trend: trend ? { slope: trend.slope, direction: trend.slope > 0.01 ? "IMPROVING" : trend.slope < -0.01 ? "DECLINING" : "FLAT" } : null,
    snapshotCount: snaps.length,
    windowSize: this._driftWindow
  };
};

// ── Pareto Optimization ─────────────────────────────────────────────

/**
 * Compute Pareto frontier from recorded snapshots.
 * Returns the set of non-dominated configurations (no other config is
 * strictly better on ALL objectives simultaneously).
 *
 * @param {Object} [options]
 * @param {Object} [options.priorities] - weight overrides per dimension
 * @param {number} [options.frictionBudget] - max acceptable friction (0-1)
 * @param {number} [options.latencyBudget]  - max acceptable latency (ms)
 * @returns {Object} frontier analysis
 */
DefensePostureOptimizer.prototype.computePareto = function (options) {
  var opts = options || {};
  var snaps = this._snapshots;
  if (snaps.length === 0) {
    return { frontier: [], dominated: [], totalEvaluated: 0 };
  }

  // Filter by budget constraints
  var candidates = [];
  for (var i = 0; i < snaps.length; i++) {
    var m = snaps[i].metrics;
    if (opts.frictionBudget != null && m.humanFriction > opts.frictionBudget) continue;
    if (opts.latencyBudget != null && m.latencyCost > opts.latencyBudget) continue;
    candidates.push(snaps[i]);
  }

  // Convert to objective vectors (all higher = better)
  var vectors = [];
  for (var j = 0; j < candidates.length; j++) {
    var met = candidates[j].metrics;
    vectors.push({
      snapshot: candidates[j],
      objectives: [
        met.catchRate,
        1 - met.humanFriction,
        1 - _clamp(met.latencyCost / 5000, 0, 1),
        met.challengeDiversity,
        met.attackSurface,
        1 - met.fatigueRisk
      ]
    });
  }

  // Find non-dominated set using incremental frontier approach — O(n*k)
  // where k is the frontier size, instead of O(n²) all-pairs comparison.
  var frontier = [];
  var dominated = [];

  for (var a = 0; a < vectors.length; a++) {
    var isDominated = false;
    var newFrontier = [];
    var aObj = vectors[a].objectives;
    for (var f = 0; f < frontier.length; f++) {
      var fObj = frontier[f].objectives;
      if (!isDominated && _dominates(fObj, aObj)) {
        isDominated = true;
        // Keep remaining frontier members as-is
        for (var r = f; r < frontier.length; r++) newFrontier.push(frontier[r]);
        break;
      }
      if (!_dominates(aObj, fObj)) {
        newFrontier.push(frontier[f]);
      } else {
        dominated.push(frontier[f]);
      }
    }
    if (!isDominated) {
      newFrontier.push(vectors[a]);
      frontier = newFrontier;
    } else {
      dominated.push(vectors[a]);
      frontier = newFrontier;
    }
  }

  // Limit frontier size
  if (frontier.length > MAX_PARETO_CONFIGS) {
    frontier = frontier.slice(0, MAX_PARETO_CONFIGS);
  }

  // Rank frontier by weighted preference if priorities given
  var priorities = opts.priorities || {};
  var dimWeights = [
    priorities.catchRate || 1,
    priorities.humanFriction || 1,
    priorities.latencyCost || 1,
    priorities.challengeDiversity || 1,
    priorities.attackSurface || 1,
    priorities.fatigueRisk || 1
  ];

  var totalWeight = 0;
  for (var w = 0; w < dimWeights.length; w++) totalWeight += dimWeights[w];
  for (var ww = 0; ww < dimWeights.length; ww++) dimWeights[ww] /= totalWeight;

  // Score each frontier point by weighted sum
  var ranked = [];
  for (var f = 0; f < frontier.length; f++) {
    var score = 0;
    for (var d = 0; d < frontier[f].objectives.length; d++) {
      score += frontier[f].objectives[d] * dimWeights[d];
    }
    ranked.push({
      snapshot: frontier[f].snapshot,
      objectives: frontier[f].objectives,
      weightedScore: Math.round(score * 1000) / 1000
    });
  }

  ranked.sort(function (x, y) { return y.weightedScore - x.weightedScore; });

  this._paretoFrontier = ranked;

  return {
    frontier: ranked.map(function (r) {
      return {
        id: r.snapshot.id,
        config: r.snapshot.config,
        metrics: r.snapshot.metrics,
        weightedScore: r.weightedScore,
        objectives: r.objectives
      };
    }),
    dominated: dominated.length,
    totalEvaluated: candidates.length,
    budgetFiltered: snaps.length - candidates.length
  };
};

// ── What-If Simulation ──────────────────────────────────────────────

/**
 * Simulate the effect of a config change based on historical correlations.
 * Uses regression from past snapshots to predict how changing knobs
 * would affect each metric dimension.
 *
 * @param {Object} proposedConfig - knob values to simulate
 * @returns {Object} predicted metrics and comparison to current
 */
DefensePostureOptimizer.prototype.simulate = function (proposedConfig) {
  if (!proposedConfig || typeof proposedConfig !== "object") {
    throw new Error("proposedConfig must be an object");
  }

  var snaps = this._snapshots;
  if (snaps.length < 5) {
    return {
      error: "INSUFFICIENT_DATA",
      message: "Need at least 5 snapshots for simulation",
      snapshotsAvailable: snaps.length
    };
  }

  // Filter snapshots that have configs
  var withConfig = [];
  for (var i = 0; i < snaps.length; i++) {
    if (snaps[i].config) withConfig.push(snaps[i]);
  }

  if (withConfig.length < 5) {
    return {
      error: "INSUFFICIENT_CONFIG_DATA",
      message: "Need at least 5 snapshots with configs for simulation",
      available: withConfig.length
    };
  }

  // For each metric, compute correlation with each knob
  var metricKeys = ["catchRate", "humanFriction", "latencyCost", "challengeDiversity", "attackSurface", "fatigueRisk"];
  var predictions = {};

  for (var mi = 0; mi < metricKeys.length; mi++) {
    var metricKey = metricKeys[mi];
    var metricValues = [];
    for (var s = 0; s < withConfig.length; s++) {
      metricValues.push(withConfig[s].metrics[metricKey]);
    }

    // Simple weighted average of existing data as baseline prediction
    var totalContrib = 0;
    var totalKnobWeight = 0;

    for (var ki = 0; ki < KNOB_TYPES.length; ki++) {
      var knob = KNOB_TYPES[ki];
      if (proposedConfig[knob] == null) continue;

      var knobValues = [];
      for (var sv = 0; sv < withConfig.length; sv++) {
        knobValues.push(withConfig[sv].config[knob] || 0);
      }

      var reg = _linearRegression(knobValues, metricValues);
      if (reg.r2 > 0.1) { // only use if correlation is meaningful
        var predicted = reg.slope * proposedConfig[knob] + reg.intercept;
        totalContrib += predicted * reg.r2;
        totalKnobWeight += reg.r2;
      }
    }

    if (totalKnobWeight > 0) {
      predictions[metricKey] = _clamp(totalContrib / totalKnobWeight, 0, metricKey === "latencyCost" ? 10000 : 1);
    } else {
      predictions[metricKey] = _mean(metricValues);
    }
  }

  // Compare to current
  var current = snaps[snaps.length - 1].metrics;
  var comparison = {};
  for (var ck = 0; ck < metricKeys.length; ck++) {
    var key = metricKeys[ck];
    var diff = predictions[key] - current[key];
    comparison[key] = {
      current: Math.round(current[key] * 1000) / 1000,
      predicted: Math.round(predictions[key] * 1000) / 1000,
      delta: Math.round(diff * 1000) / 1000,
      direction: diff > 0.01 ? "INCREASE" : diff < -0.01 ? "DECREASE" : "STABLE"
    };
  }

  var currentScore = this._compositeScore(current);
  var predictedScore = this._compositeScore(predictions);

  var sim = {
    id: _uid(),
    timestamp: _now(),
    proposedConfig: _deepCopy(proposedConfig),
    predictions: predictions,
    comparison: comparison,
    currentComposite: Math.round(currentScore * 1000) / 1000,
    predictedComposite: Math.round(predictedScore * 1000) / 1000,
    improvement: Math.round((predictedScore - currentScore) * 1000) / 1000,
    verdict: predictedScore > currentScore + 0.02 ? "BENEFICIAL" :
             predictedScore < currentScore - 0.02 ? "HARMFUL" : "NEUTRAL"
  };

  this._simulations.push(sim);
  if (this._simulations.length > this._maxSimulations) {
    this._simulations.splice(0, this._simulations.length - this._maxSimulations);
  }

  return sim;
};

// ── Recommendation Engine ───────────────────────────────────────────

/**
 * Generate autonomous recommendations based on current posture and drift.
 * Analyzes weaknesses and suggests specific knob adjustments.
 *
 * @param {Object} [options]
 * @param {string} [options.priority] - "SECURITY" | "USABILITY" | "BALANCED"
 * @returns {Object} recommendations
 */
DefensePostureOptimizer.prototype.recommend = function (options) {
  var opts = options || {};
  var priority = opts.priority || "BALANCED";
  var snaps = this._snapshots;

  if (snaps.length < 3) {
    return {
      priority: priority,
      recommendations: [],
      message: "Need at least 3 snapshots for recommendations"
    };
  }

  var recent = snaps.slice(Math.max(0, snaps.length - this._driftWindow));
  var recommendations = [];

  // Compute average recent metrics
  var avgMetrics = {
    catchRate: 0, humanFriction: 0, latencyCost: 0,
    challengeDiversity: 0, attackSurface: 0, fatigueRisk: 0
  };
  for (var i = 0; i < recent.length; i++) {
    var m = recent[i].metrics;
    avgMetrics.catchRate += m.catchRate;
    avgMetrics.humanFriction += m.humanFriction;
    avgMetrics.latencyCost += m.latencyCost;
    avgMetrics.challengeDiversity += m.challengeDiversity;
    avgMetrics.attackSurface += m.attackSurface;
    avgMetrics.fatigueRisk += m.fatigueRisk;
  }
  var n = recent.length;
  avgMetrics.catchRate /= n;
  avgMetrics.humanFriction /= n;
  avgMetrics.latencyCost /= n;
  avgMetrics.challengeDiversity /= n;
  avgMetrics.attackSurface /= n;
  avgMetrics.fatigueRisk /= n;

  // Security-focused recommendations
  if (priority === "SECURITY" || priority === "BALANCED") {
    if (avgMetrics.catchRate < 0.7) {
      recommendations.push({
        dimension: "CATCH_RATE",
        severity: avgMetrics.catchRate < 0.5 ? "HIGH" : "MEDIUM",
        message: "Bot catch rate is below target (" + Math.round(avgMetrics.catchRate * 100) + "%)",
        suggestedKnobs: { DIFFICULTY: 0.8, BEHAVIORAL_DEPTH: 0.9, HONEYPOT_DENSITY: 0.6 },
        expectedImpact: "Increase catch rate by 10-25%"
      });
    }
    if (avgMetrics.attackSurface < 0.6) {
      recommendations.push({
        dimension: "ATTACK_SURFACE",
        severity: "MEDIUM",
        message: "Attack surface coverage is insufficient (" + Math.round(avgMetrics.attackSurface * 100) + "%)",
        suggestedKnobs: { MULTI_FACTOR: 1, PROOF_OF_WORK: 1.5 },
        expectedImpact: "Improve coverage by enabling multi-factor challenges"
      });
    }
  }

  // Usability-focused recommendations
  if (priority === "USABILITY" || priority === "BALANCED") {
    if (avgMetrics.humanFriction > 0.5) {
      recommendations.push({
        dimension: "HUMAN_FRICTION",
        severity: avgMetrics.humanFriction > 0.7 ? "HIGH" : "MEDIUM",
        message: "Human friction is too high (" + Math.round(avgMetrics.humanFriction * 100) + "%)",
        suggestedKnobs: { DIFFICULTY: 0.4, RETRY_LIMIT: 5, DELAY_INJECTION: 200 },
        expectedImpact: "Reduce friction by 15-30% with minimal security loss"
      });
    }
    if (avgMetrics.fatigueRisk > 0.6) {
      recommendations.push({
        dimension: "FATIGUE_RISK",
        severity: "HIGH",
        message: "User fatigue risk is elevated (" + Math.round(avgMetrics.fatigueRisk * 100) + "%)",
        suggestedKnobs: { RETRY_LIMIT: 3, DIFFICULTY: 0.3 },
        expectedImpact: "Reduce abandonment rate by lowering challenge intensity"
      });
    }
  }

  // Diversity recommendation
  if (avgMetrics.challengeDiversity < 0.5) {
    recommendations.push({
      dimension: "CHALLENGE_DIVERSITY",
      severity: "LOW",
      message: "Challenge variety is low — bots can pattern-match",
      suggestedKnobs: { HONEYPOT_DENSITY: 0.5, MULTI_FACTOR: 1 },
      expectedImpact: "Increase unpredictability for automated solvers"
    });
  }

  // Latency recommendation
  if (avgMetrics.latencyCost > 3000) {
    recommendations.push({
      dimension: "LATENCY_COST",
      severity: avgMetrics.latencyCost > 5000 ? "HIGH" : "MEDIUM",
      message: "Defense latency is excessive (" + Math.round(avgMetrics.latencyCost) + "ms)",
      suggestedKnobs: { PROOF_OF_WORK: 0.5, DELAY_INJECTION: 100 },
      expectedImpact: "Reduce latency by 40-60% with lighter PoW"
    });
  }

  // Drift-based recommendations
  if (this._driftState === "CRITICAL") {
    recommendations.unshift({
      dimension: "DRIFT",
      severity: "CRITICAL",
      message: "Defense posture has critically degraded — immediate re-tuning required",
      suggestedKnobs: null,
      expectedImpact: "Run computePareto() and adopt the top-ranked frontier config"
    });
  } else if (this._driftState === "DEGRADED") {
    recommendations.unshift({
      dimension: "DRIFT",
      severity: "HIGH",
      message: "Defense posture is degrading — scheduled re-tuning recommended",
      suggestedKnobs: null,
      expectedImpact: "Prevent further decline by reviewing current configuration"
    });
  }

  this._recommendations = recommendations;

  return {
    priority: priority,
    driftState: this._driftState,
    compositeScore: Math.round(this._compositeScore(avgMetrics) * 1000) / 1000,
    recommendations: recommendations,
    generatedAt: _now()
  };
};

// ── Budget-Constrained Optimization ─────────────────────────────────

/**
 * Find the best configuration within a friction and latency budget.
 * Maximizes catch rate + attack surface while staying within constraints.
 *
 * @param {Object} budget
 * @param {number} budget.maxFriction    - max acceptable friction (0-1)
 * @param {number} [budget.maxLatency]   - max acceptable latency (ms)
 * @param {number} [budget.maxFatigue]   - max acceptable fatigue risk (0-1)
 * @returns {Object} optimal config from history
 */
DefensePostureOptimizer.prototype.optimizeWithinBudget = function (budget) {
  if (!budget || budget.maxFriction == null) {
    throw new Error("budget.maxFriction is required");
  }

  var maxFriction = budget.maxFriction;
  var maxLatency = budget.maxLatency != null ? budget.maxLatency : Infinity;
  var maxFatigue = budget.maxFatigue != null ? budget.maxFatigue : 1;

  var feasible = [];
  for (var i = 0; i < this._snapshots.length; i++) {
    var m = this._snapshots[i].metrics;
    if (m.humanFriction <= maxFriction &&
        m.latencyCost <= maxLatency &&
        m.fatigueRisk <= maxFatigue) {
      feasible.push(this._snapshots[i]);
    }
  }

  if (feasible.length === 0) {
    return {
      found: false,
      message: "No historical configuration meets the budget constraints",
      suggestion: "Relax constraints or record more diverse configurations"
    };
  }

  // Score by security value (catch rate + attack surface + diversity)
  var best = null;
  var bestScore = -1;
  for (var j = 0; j < feasible.length; j++) {
    var met = feasible[j].metrics;
    var secScore = met.catchRate * 0.5 + met.attackSurface * 0.3 + met.challengeDiversity * 0.2;
    if (secScore > bestScore) {
      bestScore = secScore;
      best = feasible[j];
    }
  }

  return {
    found: true,
    optimal: {
      id: best.id,
      config: best.config,
      metrics: best.metrics,
      securityScore: Math.round(bestScore * 1000) / 1000,
      compositeScore: Math.round(this._compositeScore(best.metrics) * 1000) / 1000
    },
    feasibleCount: feasible.length,
    totalEvaluated: this._snapshots.length
  };
};

// ── Posture Timeline ────────────────────────────────────────────────

/**
 * Get the posture timeline — composite score history with trend analysis.
 * @param {Object} [options]
 * @param {number} [options.limit] - max entries to return
 * @returns {Object} timeline with trend
 */
DefensePostureOptimizer.prototype.getTimeline = function (options) {
  var opts = options || {};
  var limit = _posOpt(opts.limit, 50);
  var snaps = this._snapshots.slice(-limit);

  var entries = [];
  var scores = [];
  for (var i = 0; i < snaps.length; i++) {
    var score = this._compositeScore(snaps[i].metrics);
    scores.push(score);
    entries.push({
      id: snaps[i].id,
      timestamp: snaps[i].timestamp,
      compositeScore: Math.round(score * 1000) / 1000,
      driftState: snaps[i].driftState,
      metrics: snaps[i].metrics
    });
  }

  var trend = scores.length >= 3 ? _linearRegression(scores) : null;

  return {
    entries: entries,
    trend: trend ? {
      slope: Math.round(trend.slope * 10000) / 10000,
      direction: trend.slope > 0.005 ? "IMPROVING" : trend.slope < -0.005 ? "DECLINING" : "FLAT",
      r2: Math.round(trend.r2 * 1000) / 1000
    } : null,
    currentDrift: this._driftState,
    totalSnapshots: this._snapshots.length
  };
};

// ── Dimension Breakdown ─────────────────────────────────────────────

/**
 * Get per-dimension analysis: trend, average, min, max, variability.
 * @returns {Object} breakdown per dimension
 */
DefensePostureOptimizer.prototype.getDimensionBreakdown = function () {
  var snaps = this._snapshots;
  var n = snaps.length;
  if (n === 0) return { dimensions: {}, snapshotCount: 0 };

  var metricKeys = ["catchRate", "humanFriction", "latencyCost", "challengeDiversity", "attackSurface", "fatigueRisk"];
  var result = {};

  for (var ki = 0; ki < metricKeys.length; ki++) {
    var key = metricKeys[ki];
    // Single-pass extraction with min/max/sum tracking
    var values = new Array(n);
    var vMin = Infinity;
    var vMax = -Infinity;
    var vSum = 0;
    for (var i = 0; i < n; i++) {
      var v = snaps[i].metrics[key];
      values[i] = v;
      vSum += v;
      if (v < vMin) vMin = v;
      if (v > vMax) vMax = v;
    }

    var avg = vSum / n;
    // Single-pass stddev using pre-computed mean (avoids redundant mean call)
    var sqSum = 0;
    for (var si = 0; si < n; si++) {
      var diff = values[si] - avg;
      sqSum += diff * diff;
    }
    var sd = Math.sqrt(sqSum / n);

    var trend = n >= 3 ? _linearRegression(values) : null;

    result[key] = {
      average: Math.round(avg * 1000) / 1000,
      min: vMin,
      max: vMax,
      stddev: Math.round(sd * 1000) / 1000,
      variability: avg > 0 ? Math.round((sd / avg) * 100) / 100 : 0,
      trend: trend ? {
        slope: Math.round(trend.slope * 10000) / 10000,
        direction: trend.slope > 0.002 ? "INCREASING" : trend.slope < -0.002 ? "DECREASING" : "STABLE"
      } : null,
      samples: n
    };
  }

  return { dimensions: result, snapshotCount: n };
};

// ── State Export/Import ─────────────────────────────────────────────

/**
 * Export full state for persistence.
 * @returns {Object}
 */
DefensePostureOptimizer.prototype.exportState = function () {
  return {
    version: 1,
    exportedAt: _now(),
    config: this._currentConfig ? _deepCopy(this._currentConfig) : null,
    snapshots: _deepCopy(this._snapshots),
    simulations: _deepCopy(this._simulations),
    driftState: this._driftState,
    recommendations: _deepCopy(this._recommendations)
  };
};

/**
 * Import previously exported state.
 * @param {Object} state
 */
DefensePostureOptimizer.prototype.importState = function (state) {
  if (!state || state.version !== 1) {
    throw new Error("Invalid state format (expected version 1)");
  }
  this._currentConfig = state.config ? _deepCopy(state.config) : null;
  this._snapshots = Array.isArray(state.snapshots) ? _deepCopy(state.snapshots) : [];
  this._simulations = Array.isArray(state.simulations) ? _deepCopy(state.simulations) : [];
  this._driftState = state.driftState || "STABLE";
  this._recommendations = Array.isArray(state.recommendations) ? _deepCopy(state.recommendations) : [];

  // Enforce limits
  if (this._snapshots.length > this._maxSnapshots) {
    this._snapshots = this._snapshots.slice(-this._maxSnapshots);
  }
  if (this._simulations.length > this._maxSimulations) {
    this._simulations = this._simulations.slice(-this._maxSimulations);
  }
};

/**
 * Get a summary report of the current defense posture.
 * @returns {Object}
 */
DefensePostureOptimizer.prototype.getSummary = function () {
  var snaps = this._snapshots;
  if (snaps.length === 0) {
    return { status: "NO_DATA", message: "No snapshots recorded yet" };
  }

  var latest = snaps[snaps.length - 1];
  var score = this._compositeScore(latest.metrics);

  var grade;
  if (score >= 0.85) grade = "A";
  else if (score >= 0.7) grade = "B";
  else if (score >= 0.55) grade = "C";
  else if (score >= 0.4) grade = "D";
  else grade = "F";

  return {
    status: "ACTIVE",
    grade: grade,
    compositeScore: Math.round(score * 1000) / 1000,
    driftState: this._driftState,
    latestMetrics: latest.metrics,
    currentConfig: this._currentConfig,
    snapshotCount: snaps.length,
    simulationCount: this._simulations.length,
    recommendationCount: this._recommendations.length,
    timestamp: latest.timestamp
  };
};

// ── Exports ─────────────────────────────────────────────────────────

module.exports = {
  DefensePostureOptimizer: DefensePostureOptimizer,
  DIMENSIONS: DIMENSIONS,
  KNOB_TYPES: KNOB_TYPES,
  DRIFT_STATES: DRIFT_STATES
};
