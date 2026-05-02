/**
 * ChallengeDifficultyCurveEngine — Autonomous difficulty curve optimization.
 *
 * Models the relationship between challenge difficulty and solve outcomes
 * (human pass rate vs bot rejection rate) to find and maintain the optimal
 * difficulty sweet spot. Autonomously adjusts difficulty parameters to
 * maximize security while minimizing human frustration.
 *
 * Key capabilities:
 *   - Model difficulty-vs-outcome curves for humans and bots separately
 *   - Identify the optimal difficulty zone (max bot rejection, min human frustration)
 *   - Track difficulty drift over time as bot capabilities evolve
 *   - Detect when bots adapt to current difficulty levels
 *   - Generate autonomous difficulty adjustment recommendations
 *   - Predict human abandonment rates at different difficulty levels
 *   - Score overall difficulty calibration health (0-100)
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/challenge-difficulty-curve-engine
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _clamp = _shared._clamp;
var _posOpt = _shared._posOpt;
var _nnOpt = _shared._nnOpt;
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _linearRegression = _shared._linearRegression;

// ── Constants ───────────────────────────────────────────────────────

/** Difficulty levels (0-100 scale) */
var DIFFICULTY_BANDS = {
  TRIVIAL:    { id: "TRIVIAL",    min: 0,  max: 19, label: "Trivial",    emoji: "🟢" },
  EASY:       { id: "EASY",       min: 20, max: 39, label: "Easy",       emoji: "🟡" },
  MODERATE:   { id: "MODERATE",   min: 40, max: 59, label: "Moderate",   emoji: "🟠" },
  HARD:       { id: "HARD",       min: 60, max: 79, label: "Hard",       emoji: "🔴" },
  EXTREME:    { id: "EXTREME",    min: 80, max: 100, label: "Extreme",   emoji: "⛔" }
};

/** Outcome types */
var OUTCOMES = {
  HUMAN_PASS:    "human_pass",
  HUMAN_FAIL:    "human_fail",
  HUMAN_ABANDON: "human_abandon",
  BOT_PASS:      "bot_pass",
  BOT_FAIL:      "bot_fail"
};

/** Health tiers */
var HEALTH_TIERS = {
  EXCELLENT:  { min: 80, max: 100, label: "Excellent",  emoji: "🟢", desc: "Difficulty perfectly calibrated" },
  GOOD:       { min: 60, max: 79,  label: "Good",       emoji: "🟡", desc: "Minor calibration adjustments possible" },
  FAIR:       { min: 40, max: 59,  label: "Fair",       emoji: "🟠", desc: "Difficulty needs attention" },
  POOR:       { min: 20, max: 39,  label: "Poor",       emoji: "🔴", desc: "Significant calibration issues" },
  CRITICAL:   { min: 0,  max: 19,  label: "Critical",   emoji: "⛔", desc: "Difficulty severely miscalibrated" }
};

/** Default configuration */
var DEFAULTS = {
  targetHumanPassRate: 0.85,
  targetBotRejectRate: 0.95,
  abandonmentThreshold: 0.15,
  minSamples: 10,
  maxSamples: 5000,
  difficultyBuckets: 10,
  adaptationWindowMs: 7 * 24 * 60 * 60 * 1000,  // 7 days
  driftCheckIntervalMs: 24 * 60 * 60 * 1000,     // 1 day
  maxDifficultyShift: 10,
  smoothingFactor: 0.3
};

// ── Engine ──────────────────────────────────────────────────────────

/**
 * Create a new ChallengeDifficultyCurveEngine instance.
 * @param {Object} [options] Configuration overrides
 */
function ChallengeDifficultyCurveEngine(options) {
  var opts = options || {};
  this._config = {
    targetHumanPassRate:  _posOpt(opts.targetHumanPassRate, DEFAULTS.targetHumanPassRate),
    targetBotRejectRate:  _posOpt(opts.targetBotRejectRate, DEFAULTS.targetBotRejectRate),
    abandonmentThreshold: _posOpt(opts.abandonmentThreshold, DEFAULTS.abandonmentThreshold),
    minSamples:           _posOpt(opts.minSamples, DEFAULTS.minSamples),
    maxSamples:           _posOpt(opts.maxSamples, DEFAULTS.maxSamples),
    difficultyBuckets:    _posOpt(opts.difficultyBuckets, DEFAULTS.difficultyBuckets),
    adaptationWindowMs:   _posOpt(opts.adaptationWindowMs, DEFAULTS.adaptationWindowMs),
    driftCheckIntervalMs: _posOpt(opts.driftCheckIntervalMs, DEFAULTS.driftCheckIntervalMs),
    maxDifficultyShift:   _posOpt(opts.maxDifficultyShift, DEFAULTS.maxDifficultyShift),
    smoothingFactor:      _posOpt(opts.smoothingFactor, DEFAULTS.smoothingFactor)
  };

  // Sample storage: per-bucket arrays
  this._samples = [];          // all raw samples
  this._buckets = {};          // bucketIndex → { humanPass, humanFail, humanAbandon, botPass, botFail }
  this._driftHistory = [];     // { ts, optimalDifficulty, humanPassRate, botRejectRate }
  this._recommendations = [];  // most recent recommendations
  this._lastDriftCheck = 0;

  // Initialize empty buckets
  for (var i = 0; i < this._config.difficultyBuckets; i++) {
    this._buckets[i] = { humanPass: 0, humanFail: 0, humanAbandon: 0, botPass: 0, botFail: 0, total: 0 };
  }
}

// ── Sample Recording ────────────────────────────────────────────────

/**
 * Record a solve attempt outcome at a given difficulty level.
 * @param {number} difficulty - Difficulty level (0-100)
 * @param {string} outcome - One of OUTCOMES values
 * @param {Object} [meta] - Optional metadata (solveTimeMs, challengeId, etc.)
 * @returns {Object} The recorded sample
 */
ChallengeDifficultyCurveEngine.prototype.recordSample = function (difficulty, outcome, meta) {
  if (typeof difficulty !== "number" || difficulty < 0 || difficulty > 100) {
    throw new Error("difficulty must be a number between 0 and 100");
  }
  var validOutcomes = {};
  Object.keys(OUTCOMES).forEach(function (k) { validOutcomes[OUTCOMES[k]] = true; });
  if (!validOutcomes[outcome]) {
    throw new Error("outcome must be one of: " + Object.keys(OUTCOMES).map(function (k) { return OUTCOMES[k]; }).join(", "));
  }

  var sample = {
    difficulty: difficulty,
    outcome: outcome,
    timestamp: _now(),
    meta: meta || {}
  };

  this._samples.push(sample);

  // Cap samples
  if (this._samples.length > this._config.maxSamples) {
    this._samples = this._samples.slice(-this._config.maxSamples);
  }

  // Update bucket
  var bucketIdx = this._getBucketIndex(difficulty);
  var bucket = this._buckets[bucketIdx];
  if (outcome === OUTCOMES.HUMAN_PASS) bucket.humanPass++;
  else if (outcome === OUTCOMES.HUMAN_FAIL) bucket.humanFail++;
  else if (outcome === OUTCOMES.HUMAN_ABANDON) bucket.humanAbandon++;
  else if (outcome === OUTCOMES.BOT_PASS) bucket.botPass++;
  else if (outcome === OUTCOMES.BOT_FAIL) bucket.botFail++;
  bucket.total++;

  return sample;
};

/**
 * Get the bucket index for a difficulty level.
 * @private
 */
ChallengeDifficultyCurveEngine.prototype._getBucketIndex = function (difficulty) {
  var idx = Math.floor(difficulty / (100 / this._config.difficultyBuckets));
  return _clamp(idx, 0, this._config.difficultyBuckets - 1);
};

/**
 * Get the difficulty range for a bucket index.
 * @private
 */
ChallengeDifficultyCurveEngine.prototype._getBucketRange = function (idx) {
  var size = 100 / this._config.difficultyBuckets;
  return { min: Math.round(idx * size), max: Math.round((idx + 1) * size - 1) };
};

// ── Curve Analysis ──────────────────────────────────────────────────

/**
 * Compute the human pass rate curve across difficulty buckets.
 * @returns {Array} Array of { bucket, difficulty, passRate, sampleCount }
 */
ChallengeDifficultyCurveEngine.prototype.getHumanPassCurve = function () {
  var curve = [];
  for (var i = 0; i < this._config.difficultyBuckets; i++) {
    var b = this._buckets[i];
    var humanTotal = b.humanPass + b.humanFail + b.humanAbandon;
    var range = this._getBucketRange(i);
    curve.push({
      bucket: i,
      difficulty: Math.round((range.min + range.max) / 2),
      passRate: humanTotal > 0 ? b.humanPass / humanTotal : null,
      sampleCount: humanTotal
    });
  }
  return curve;
};

/**
 * Compute the bot rejection rate curve across difficulty buckets.
 * @returns {Array} Array of { bucket, difficulty, rejectRate, sampleCount }
 */
ChallengeDifficultyCurveEngine.prototype.getBotRejectCurve = function () {
  var curve = [];
  for (var i = 0; i < this._config.difficultyBuckets; i++) {
    var b = this._buckets[i];
    var botTotal = b.botPass + b.botFail;
    var range = this._getBucketRange(i);
    curve.push({
      bucket: i,
      difficulty: Math.round((range.min + range.max) / 2),
      rejectRate: botTotal > 0 ? b.botFail / botTotal : null,
      sampleCount: botTotal
    });
  }
  return curve;
};

/**
 * Compute the human abandonment rate curve across difficulty buckets.
 * @returns {Array} Array of { bucket, difficulty, abandonRate, sampleCount }
 */
ChallengeDifficultyCurveEngine.prototype.getAbandonmentCurve = function () {
  var curve = [];
  for (var i = 0; i < this._config.difficultyBuckets; i++) {
    var b = this._buckets[i];
    var humanTotal = b.humanPass + b.humanFail + b.humanAbandon;
    var range = this._getBucketRange(i);
    curve.push({
      bucket: i,
      difficulty: Math.round((range.min + range.max) / 2),
      abandonRate: humanTotal > 0 ? b.humanAbandon / humanTotal : null,
      sampleCount: humanTotal
    });
  }
  return curve;
};

// ── Optimal Difficulty Finding ──────────────────────────────────────

/**
 * Find the optimal difficulty level that maximizes the combined objective:
 * high bot rejection + high human pass rate + low abandonment.
 *
 * Uses a scoring function: score = botRejectRate * humanPassRate * (1 - abandonRate)
 *
 * @returns {Object} { optimalDifficulty, optimalBucket, score, humanPassRate, botRejectRate, abandonRate, confidence }
 */
ChallengeDifficultyCurveEngine.prototype.findOptimalDifficulty = function () {
  var bestScore = -1;
  var bestBucket = -1;
  var bestData = null;
  var totalSamples = 0;

  for (var i = 0; i < this._config.difficultyBuckets; i++) {
    var b = this._buckets[i];
    var humanTotal = b.humanPass + b.humanFail + b.humanAbandon;
    var botTotal = b.botPass + b.botFail;

    if (humanTotal < this._config.minSamples || botTotal < this._config.minSamples) continue;

    var humanPassRate = b.humanPass / humanTotal;
    var botRejectRate = b.botFail / botTotal;
    var abandonRate = b.humanAbandon / humanTotal;
    var score = botRejectRate * humanPassRate * (1 - abandonRate);
    totalSamples += humanTotal + botTotal;

    if (score > bestScore) {
      bestScore = score;
      bestBucket = i;
      bestData = {
        humanPassRate: humanPassRate,
        botRejectRate: botRejectRate,
        abandonRate: abandonRate
      };
    }
  }

  if (bestBucket === -1) {
    return {
      optimalDifficulty: 50,
      optimalBucket: -1,
      score: 0,
      humanPassRate: 0,
      botRejectRate: 0,
      abandonRate: 0,
      confidence: 0
    };
  }

  var range = this._getBucketRange(bestBucket);
  var confidence = Math.min(1, totalSamples / (this._config.minSamples * this._config.difficultyBuckets * 2));

  return {
    optimalDifficulty: Math.round((range.min + range.max) / 2),
    optimalBucket: bestBucket,
    score: Math.round(bestScore * 1000) / 1000,
    humanPassRate: Math.round(bestData.humanPassRate * 1000) / 1000,
    botRejectRate: Math.round(bestData.botRejectRate * 1000) / 1000,
    abandonRate: Math.round(bestData.abandonRate * 1000) / 1000,
    confidence: Math.round(confidence * 100) / 100
  };
};

/**
 * Classify a difficulty value into a band.
 * @param {number} difficulty - Difficulty level (0-100)
 * @returns {Object} The matching DIFFICULTY_BANDS entry
 */
ChallengeDifficultyCurveEngine.prototype.classifyDifficulty = function (difficulty) {
  var d = _clamp(difficulty, 0, 100);
  var bands = Object.keys(DIFFICULTY_BANDS);
  for (var i = 0; i < bands.length; i++) {
    var band = DIFFICULTY_BANDS[bands[i]];
    if (d >= band.min && d <= band.max) return band;
  }
  return DIFFICULTY_BANDS.MODERATE;
};

// ── Drift Detection ─────────────────────────────────────────────────

/**
 * Check for difficulty drift — whether the optimal difficulty is shifting
 * over time (e.g., bots getting smarter → need harder challenges).
 *
 * @returns {Object} { drifting, direction, magnitude, velocity, history }
 */
ChallengeDifficultyCurveEngine.prototype.detectDrift = function () {
  var optimal = this.findOptimalDifficulty();
  var now = _now();

  this._driftHistory.push({
    ts: now,
    optimalDifficulty: optimal.optimalDifficulty,
    humanPassRate: optimal.humanPassRate,
    botRejectRate: optimal.botRejectRate,
    score: optimal.score
  });

  // Cap drift history
  if (this._driftHistory.length > 100) {
    this._driftHistory = this._driftHistory.slice(-100);
  }

  if (this._driftHistory.length < 3) {
    return { drifting: false, direction: "stable", magnitude: 0, velocity: 0, history: this._driftHistory.slice() };
  }

  // Use linear regression on recent drift points
  var xs = [];
  var ys = [];
  for (var i = 0; i < this._driftHistory.length; i++) {
    xs.push(i);
    ys.push(this._driftHistory[i].optimalDifficulty);
  }

  var reg = _linearRegression(xs, ys);
  var slope = reg.slope;
  var magnitude = Math.abs(slope * this._driftHistory.length);
  var velocity = slope;

  var direction = "stable";
  if (slope > 0.5) direction = "harder";
  else if (slope < -0.5) direction = "easier";

  return {
    drifting: Math.abs(slope) > 0.5,
    direction: direction,
    magnitude: Math.round(magnitude * 10) / 10,
    velocity: Math.round(velocity * 100) / 100,
    history: this._driftHistory.slice()
  };
};

// ── Bot Adaptation Detection ────────────────────────────────────────

/**
 * Detect whether bots are adapting to the current difficulty level.
 * Looks for rising bot pass rates in recent samples at the current optimal difficulty.
 *
 * @returns {Object} { adapting, signal, botPassTrend, recentBotPassRate, historicBotPassRate }
 */
ChallengeDifficultyCurveEngine.prototype.detectBotAdaptation = function () {
  var now = _now();
  var windowMs = this._config.adaptationWindowMs;
  var recentCutoff = now - windowMs;
  var historicCutoff = now - (windowMs * 2);

  var recentBotPass = 0, recentBotTotal = 0;
  var historicBotPass = 0, historicBotTotal = 0;

  for (var i = 0; i < this._samples.length; i++) {
    var s = this._samples[i];
    if (s.outcome === OUTCOMES.BOT_PASS || s.outcome === OUTCOMES.BOT_FAIL) {
      if (s.timestamp >= recentCutoff) {
        recentBotTotal++;
        if (s.outcome === OUTCOMES.BOT_PASS) recentBotPass++;
      } else if (s.timestamp >= historicCutoff) {
        historicBotTotal++;
        if (s.outcome === OUTCOMES.BOT_PASS) historicBotPass++;
      }
    }
  }

  var recentRate = recentBotTotal > 0 ? recentBotPass / recentBotTotal : 0;
  var historicRate = historicBotTotal > 0 ? historicBotPass / historicBotTotal : 0;
  var trend = recentRate - historicRate;
  var adapting = trend > 0.1 && recentBotTotal >= this._config.minSamples;

  var signal = "none";
  if (trend > 0.3) signal = "critical";
  else if (trend > 0.2) signal = "strong";
  else if (trend > 0.1) signal = "moderate";
  else if (trend > 0.05) signal = "weak";

  return {
    adapting: adapting,
    signal: signal,
    botPassTrend: Math.round(trend * 1000) / 1000,
    recentBotPassRate: Math.round(recentRate * 1000) / 1000,
    historicBotPassRate: Math.round(historicRate * 1000) / 1000
  };
};

// ── Recommendations ─────────────────────────────────────────────────

/**
 * Generate autonomous difficulty adjustment recommendations.
 * @returns {Array} Array of recommendation objects
 */
ChallengeDifficultyCurveEngine.prototype.generateRecommendations = function () {
  var recs = [];
  var optimal = this.findOptimalDifficulty();
  var drift = this.detectDrift();
  var adaptation = this.detectBotAdaptation();
  var humanCurve = this.getHumanPassCurve();
  var abandonCurve = this.getAbandonmentCurve();

  // 1. Bot adaptation alert
  if (adaptation.adapting) {
    recs.push({
      type: "bot_adaptation",
      severity: adaptation.signal === "critical" ? "critical" : adaptation.signal === "strong" ? "high" : "medium",
      emoji: "🤖",
      title: "Bot Adaptation Detected",
      text: "Bots are increasingly solving challenges (pass rate +" + Math.round(adaptation.botPassTrend * 100) + "%). Consider increasing difficulty or rotating challenge types.",
      action: "increase_difficulty",
      suggestedShift: Math.min(this._config.maxDifficultyShift, Math.round(adaptation.botPassTrend * 50))
    });
  }

  // 2. Difficulty drift alert
  if (drift.drifting) {
    recs.push({
      type: "difficulty_drift",
      severity: drift.magnitude > 15 ? "high" : "medium",
      emoji: "📈",
      title: "Difficulty Drift: " + drift.direction,
      text: "Optimal difficulty is shifting " + drift.direction + " (velocity: " + drift.velocity + "/check). The challenge landscape is evolving.",
      action: "monitor"
    });
  }

  // 3. Human pass rate too low
  if (optimal.confidence > 0 && optimal.humanPassRate < this._config.targetHumanPassRate) {
    var gap = this._config.targetHumanPassRate - optimal.humanPassRate;
    recs.push({
      type: "human_pass_low",
      severity: gap > 0.2 ? "high" : "medium",
      emoji: "😓",
      title: "Human Pass Rate Below Target",
      text: "Human pass rate (" + Math.round(optimal.humanPassRate * 100) + "%) is below target (" + Math.round(this._config.targetHumanPassRate * 100) + "%). Consider easing difficulty.",
      action: "decrease_difficulty",
      suggestedShift: -Math.min(this._config.maxDifficultyShift, Math.round(gap * 30))
    });
  }

  // 4. Bot reject rate too low
  if (optimal.confidence > 0 && optimal.botRejectRate < this._config.targetBotRejectRate) {
    var botGap = this._config.targetBotRejectRate - optimal.botRejectRate;
    recs.push({
      type: "bot_reject_low",
      severity: botGap > 0.2 ? "critical" : "high",
      emoji: "⚠️",
      title: "Bot Rejection Rate Below Target",
      text: "Bot rejection rate (" + Math.round(optimal.botRejectRate * 100) + "%) is below target (" + Math.round(this._config.targetBotRejectRate * 100) + "%). Increase difficulty urgently.",
      action: "increase_difficulty",
      suggestedShift: Math.min(this._config.maxDifficultyShift, Math.round(botGap * 40))
    });
  }

  // 5. High abandonment
  var highAbandon = abandonCurve.filter(function (p) {
    return p.abandonRate !== null && p.abandonRate > 0.15 && p.sampleCount >= 5;
  });
  if (highAbandon.length > 0) {
    var worstBucket = highAbandon.sort(function (a, b) { return b.abandonRate - a.abandonRate; })[0];
    recs.push({
      type: "high_abandonment",
      severity: worstBucket.abandonRate > 0.3 ? "high" : "medium",
      emoji: "🚪",
      title: "High Abandonment at Difficulty " + worstBucket.difficulty,
      text: Math.round(worstBucket.abandonRate * 100) + "% of humans abandon at difficulty " + worstBucket.difficulty + ". Consider easing or adding hints.",
      action: "ease_or_hint"
    });
  }

  // 6. Insufficient data
  var totalSamples = this._samples.length;
  if (totalSamples < this._config.minSamples * this._config.difficultyBuckets) {
    recs.push({
      type: "insufficient_data",
      severity: "info",
      emoji: "📊",
      title: "More Data Needed",
      text: "Only " + totalSamples + " samples collected. Need " + (this._config.minSamples * this._config.difficultyBuckets) + " for reliable curve analysis.",
      action: "collect_more"
    });
  }

  this._recommendations = recs;
  return recs;
};

// ── Health Scoring ──────────────────────────────────────────────────

/**
 * Compute overall difficulty calibration health score (0-100).
 * @returns {Object} { score, tier, components, insights }
 */
ChallengeDifficultyCurveEngine.prototype.computeHealth = function () {
  var optimal = this.findOptimalDifficulty();
  var adaptation = this.detectBotAdaptation();
  var drift = this.detectDrift();
  var components = {};
  var insights = [];

  // Component 1: Human pass rate alignment (0-25)
  if (optimal.confidence > 0) {
    var passGap = Math.abs(optimal.humanPassRate - this._config.targetHumanPassRate);
    components.humanPassAlignment = Math.round(Math.max(0, 25 - passGap * 100));
    if (passGap > 0.1) insights.push({ emoji: "😓", text: "Human pass rate " + Math.round(passGap * 100) + "% off target" });
  } else {
    components.humanPassAlignment = 12; // neutral when no data
  }

  // Component 2: Bot rejection effectiveness (0-25)
  if (optimal.confidence > 0) {
    var rejectGap = Math.abs(optimal.botRejectRate - this._config.targetBotRejectRate);
    components.botRejectEffectiveness = Math.round(Math.max(0, 25 - rejectGap * 100));
    if (rejectGap > 0.1) insights.push({ emoji: "🤖", text: "Bot reject rate " + Math.round(rejectGap * 100) + "% off target" });
  } else {
    components.botRejectEffectiveness = 12;
  }

  // Component 3: Stability (no drift, no adaptation) (0-25)
  var stabilityScore = 25;
  if (drift.drifting) {
    stabilityScore -= Math.min(15, Math.round(drift.magnitude));
    insights.push({ emoji: "📈", text: "Difficulty drifting " + drift.direction });
  }
  if (adaptation.adapting) {
    stabilityScore -= 10;
    insights.push({ emoji: "🤖", text: "Bot adaptation detected (" + adaptation.signal + ")" });
  }
  components.stability = Math.max(0, stabilityScore);

  // Component 4: Data coverage (0-25)
  var totalSamples = this._samples.length;
  var neededSamples = this._config.minSamples * this._config.difficultyBuckets * 2;
  components.dataCoverage = Math.round(Math.min(25, (totalSamples / neededSamples) * 25));
  if (totalSamples < this._config.minSamples * 3) {
    insights.push({ emoji: "📊", text: "Limited data — collect more samples for reliable analysis" });
  }

  var score = _clamp(
    components.humanPassAlignment + components.botRejectEffectiveness + components.stability + components.dataCoverage,
    0, 100
  );

  // Classify tier
  var tier = HEALTH_TIERS.CRITICAL;
  var tiers = Object.keys(HEALTH_TIERS);
  for (var i = 0; i < tiers.length; i++) {
    var t = HEALTH_TIERS[tiers[i]];
    if (score >= t.min && score <= t.max) { tier = t; break; }
  }

  return {
    score: score,
    tier: tier,
    components: components,
    insights: insights
  };
};

// ── Prediction ──────────────────────────────────────────────────────

/**
 * Predict human outcomes at a specific difficulty level.
 * @param {number} difficulty - Difficulty level (0-100)
 * @returns {Object} { predictedPassRate, predictedAbandonRate, confidence, band }
 */
ChallengeDifficultyCurveEngine.prototype.predictOutcome = function (difficulty) {
  var bucketIdx = this._getBucketIndex(difficulty);
  var bucket = this._buckets[bucketIdx];
  var humanTotal = bucket.humanPass + bucket.humanFail + bucket.humanAbandon;

  if (humanTotal < this._config.minSamples) {
    // Interpolate from neighbors
    var below = null, above = null;
    for (var j = bucketIdx - 1; j >= 0; j--) {
      var bj = this._buckets[j];
      var htj = bj.humanPass + bj.humanFail + bj.humanAbandon;
      if (htj >= this._config.minSamples) {
        below = { idx: j, passRate: bj.humanPass / htj, abandonRate: bj.humanAbandon / htj };
        break;
      }
    }
    for (var k = bucketIdx + 1; k < this._config.difficultyBuckets; k++) {
      var bk = this._buckets[k];
      var htk = bk.humanPass + bk.humanFail + bk.humanAbandon;
      if (htk >= this._config.minSamples) {
        above = { idx: k, passRate: bk.humanPass / htk, abandonRate: bk.humanAbandon / htk };
        break;
      }
    }

    if (below && above) {
      var t = (bucketIdx - below.idx) / (above.idx - below.idx);
      return {
        predictedPassRate: Math.round((below.passRate + t * (above.passRate - below.passRate)) * 1000) / 1000,
        predictedAbandonRate: Math.round((below.abandonRate + t * (above.abandonRate - below.abandonRate)) * 1000) / 1000,
        confidence: 0.5,
        band: this.classifyDifficulty(difficulty),
        interpolated: true
      };
    }

    return {
      predictedPassRate: null,
      predictedAbandonRate: null,
      confidence: 0,
      band: this.classifyDifficulty(difficulty),
      interpolated: false
    };
  }

  return {
    predictedPassRate: Math.round((bucket.humanPass / humanTotal) * 1000) / 1000,
    predictedAbandonRate: Math.round((bucket.humanAbandon / humanTotal) * 1000) / 1000,
    confidence: Math.min(1, humanTotal / (this._config.minSamples * 5)),
    band: this.classifyDifficulty(difficulty),
    interpolated: false
  };
};

// ── Summary / Dashboard ─────────────────────────────────────────────

/**
 * Generate a comprehensive difficulty curve summary.
 * @returns {Object} Full analysis dashboard data
 */
ChallengeDifficultyCurveEngine.prototype.getSummary = function () {
  return {
    optimal: this.findOptimalDifficulty(),
    humanCurve: this.getHumanPassCurve(),
    botCurve: this.getBotRejectCurve(),
    abandonmentCurve: this.getAbandonmentCurve(),
    drift: this.detectDrift(),
    botAdaptation: this.detectBotAdaptation(),
    recommendations: this.generateRecommendations(),
    health: this.computeHealth(),
    totalSamples: this._samples.length,
    config: Object.assign({}, this._config)
  };
};

// ── State Export / Import ───────────────────────────────────────────

/**
 * Export full engine state for persistence.
 * @returns {Object} Serializable state
 */
ChallengeDifficultyCurveEngine.prototype.exportState = function () {
  return {
    samples: this._samples.slice(),
    buckets: JSON.parse(JSON.stringify(this._buckets)),
    driftHistory: this._driftHistory.slice(),
    recommendations: this._recommendations.slice(),
    config: Object.assign({}, this._config)
  };
};

/**
 * Import previously exported state.
 * @param {Object} state - State from exportState()
 */
ChallengeDifficultyCurveEngine.prototype.importState = function (state) {
  if (!state || typeof state !== "object") throw new Error("Invalid state object");
  if (state.samples) this._samples = state.samples.slice();
  if (state.buckets) this._buckets = JSON.parse(JSON.stringify(state.buckets));
  if (state.driftHistory) this._driftHistory = state.driftHistory.slice();
  if (state.recommendations) this._recommendations = state.recommendations.slice();
};

/**
 * Reset all state.
 */
ChallengeDifficultyCurveEngine.prototype.reset = function () {
  this._samples = [];
  this._driftHistory = [];
  this._recommendations = [];
  this._lastDriftCheck = 0;
  for (var i = 0; i < this._config.difficultyBuckets; i++) {
    this._buckets[i] = { humanPass: 0, humanFail: 0, humanAbandon: 0, botPass: 0, botFail: 0, total: 0 };
  }
};

// ── Getters ─────────────────────────────────────────────────────────

ChallengeDifficultyCurveEngine.prototype.getSampleCount = function () { return this._samples.length; };
ChallengeDifficultyCurveEngine.prototype.getConfig = function () { return Object.assign({}, this._config); };
ChallengeDifficultyCurveEngine.prototype.getBuckets = function () { return JSON.parse(JSON.stringify(this._buckets)); };
ChallengeDifficultyCurveEngine.prototype.getDriftHistory = function () { return this._driftHistory.slice(); };
ChallengeDifficultyCurveEngine.prototype.getRecommendations = function () { return this._recommendations.slice(); };

// ── Exports ─────────────────────────────────────────────────────────

module.exports = {
  ChallengeDifficultyCurveEngine: ChallengeDifficultyCurveEngine,
  DIFFICULTY_BANDS: DIFFICULTY_BANDS,
  OUTCOMES: OUTCOMES,
  HEALTH_TIERS: HEALTH_TIERS,
  DEFAULTS: DEFAULTS
};
