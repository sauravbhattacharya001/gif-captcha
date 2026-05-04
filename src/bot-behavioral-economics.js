/**
 * BotBehavioralEconomicsEngine — Autonomous cost-benefit analysis of bot attacks.
 *
 * Models bot operators as rational economic agents and analyzes the
 * cost-benefit dynamics of their attacks against CAPTCHA challenges.
 *
 * Key capabilities:
 *   - Attack cost modeling with marginal cost curves
 *   - Exploit arbitrage detection (disproportionate ROI windows)
 *   - Economic deterrence analysis with price elasticity
 *   - Resource allocation tracking (bot operator budget patterns)
 *   - Nash equilibrium finder (defender vs attacker optimal strategies)
 *   - Economic health scoring 0-100 with 5 tiers
 *   - Autonomous insight generation with actionable recommendations
 *   - Full state export/import with prototype-pollution protection
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/bot-behavioral-economics
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _clamp = _shared._clamp;
var _posOpt = _shared._posOpt;
var _nnOpt = _shared._nnOpt;
var _linearRegression = _shared._linearRegression;
var LruTracker = _shared.LruTracker;

// ── Constants ───────────────────────────────────────────────────────

/** Economic health tiers (best to worst for defender) */
var HEALTH_TIERS = ["PROHIBITIVE", "DETERRENT", "CONTESTED", "EXPLOITABLE", "BANKRUPT"];

/** Default configuration */
var DEFAULTS = {
  maxAttempts: 10000,
  maxBots: 500,
  maxChallengeTypes: 200,
  analysisWindowMs: 7 * 24 * 60 * 60 * 1000,
  arbitrageThreshold: 0.7,
  deterrenceMinSamples: 5,
  costPerAttempt: 1.0,
  valuePerSolve: 10.0,
  minSamplesForAnalysis: 3
};

// ── Helpers ─────────────────────────────────────────────────────────

function _isSafeKey(key) {
  return key !== "__proto__" && key !== "constructor" && key !== "prototype";
}

function _safeClone(src) {
  if (src === null || typeof src !== "object") return src;
  if (Array.isArray(src)) {
    var arr = [];
    for (var i = 0; i < src.length; i++) arr.push(_safeClone(src[i]));
    return arr;
  }
  var out = Object.create(null);
  var keys = Object.keys(src);
  for (var j = 0; j < keys.length; j++) {
    if (_isSafeKey(keys[j])) {
      out[keys[j]] = _safeClone(src[keys[j]]);
    }
  }
  return out;
}

function _objKeys(obj) {
  return obj ? Object.keys(obj) : [];
}

function _sum(arr) {
  var s = 0;
  for (var i = 0; i < arr.length; i++) s += arr[i];
  return s;
}

// ── Constructor ─────────────────────────────────────────────────────

/**
 * Create a new BotBehavioralEconomicsEngine.
 *
 * @constructor
 * @param {Object} [options] - Configuration
 * @param {number} [options.maxAttempts=10000] - Maximum stored attempts
 * @param {number} [options.maxBots=500] - Maximum tracked bots
 * @param {number} [options.maxChallengeTypes=200] - Maximum challenge types
 * @param {number} [options.analysisWindowMs=604800000] - Analysis window (7 days)
 * @param {number} [options.arbitrageThreshold=0.7] - ROI threshold for arbitrage
 * @param {number} [options.costPerAttempt=1.0] - Base cost per attempt
 * @param {number} [options.valuePerSolve=10.0] - Value of a successful solve
 */
function BotBehavioralEconomicsEngine(options) {
  var opts = options || {};
  this._maxAttempts = _posOpt(opts.maxAttempts, DEFAULTS.maxAttempts);
  this._maxBots = _posOpt(opts.maxBots, DEFAULTS.maxBots);
  this._maxChallengeTypes = _posOpt(opts.maxChallengeTypes, DEFAULTS.maxChallengeTypes);
  this._analysisWindowMs = _posOpt(opts.analysisWindowMs, DEFAULTS.analysisWindowMs);
  this._arbitrageThreshold = _nnOpt(opts.arbitrageThreshold, DEFAULTS.arbitrageThreshold);
  this._costPerAttempt = _posOpt(opts.costPerAttempt, DEFAULTS.costPerAttempt);
  this._valuePerSolve = _posOpt(opts.valuePerSolve, DEFAULTS.valuePerSolve);
  this._deterrenceMinSamples = _posOpt(opts.deterrenceMinSamples, DEFAULTS.deterrenceMinSamples);
  this._minSamples = _posOpt(opts.minSamplesForAnalysis, DEFAULTS.minSamplesForAnalysis);

  /** @type {Array} All recorded attempts */
  this._attempts = [];
  /** @type {Object} Per-bot attempt tracker */
  this._botAttempts = Object.create(null);
  /** @type {Object} Per-challenge-type stats */
  this._challengeStats = Object.create(null);
  /** @type {Array} Defense actions history */
  this._defenseActions = [];
  /** @type {LruTracker} Bot LRU for eviction */
  this._botLru = new LruTracker();
  /** @type {LruTracker} Challenge type LRU for eviction */
  this._challengeLru = new LruTracker();
}

// ── Recording ───────────────────────────────────────────────────────

/**
 * Record a bot attempt against a challenge.
 *
 * @param {Object} attempt
 * @param {string} attempt.botId - Bot identifier
 * @param {string} attempt.challengeType - Challenge type identifier
 * @param {number} attempt.difficulty - Difficulty level 0-1
 * @param {boolean} attempt.solved - Whether bot solved it
 * @param {number} [attempt.solveTimeMs] - Time to solve in ms
 * @param {number} [attempt.timestamp] - Event timestamp (defaults to now)
 * @param {Object} [attempt.metadata] - Optional metadata
 */
BotBehavioralEconomicsEngine.prototype.recordAttempt = function (attempt) {
  if (!attempt || typeof attempt !== "object") {
    throw new Error("attempt must be an object");
  }
  if (!attempt.botId || typeof attempt.botId !== "string") {
    throw new Error("attempt.botId must be a non-empty string");
  }
  if (!attempt.challengeType || typeof attempt.challengeType !== "string") {
    throw new Error("attempt.challengeType must be a non-empty string");
  }
  if (attempt.difficulty == null || typeof attempt.difficulty !== "number") {
    throw new Error("attempt.difficulty must be a number");
  }
  if (!_isSafeKey(attempt.botId) || !_isSafeKey(attempt.challengeType)) {
    throw new Error("Dangerous key detected");
  }

  var ts = attempt.timestamp || _now();
  var rec = {
    botId: attempt.botId,
    challengeType: attempt.challengeType,
    difficulty: _clamp(attempt.difficulty, 0, 1),
    solved: !!attempt.solved,
    solveTimeMs: _nnOpt(attempt.solveTimeMs, 0),
    timestamp: ts
  };

  // Store attempt
  this._attempts.push(rec);
  while (this._attempts.length > this._maxAttempts) {
    this._attempts.shift();
  }

  // Per-bot tracking
  if (!this._botAttempts[rec.botId]) {
    this._botAttempts[rec.botId] = [];
    // Evict oldest bot if over limit
    while (this._botLru.length >= this._maxBots) {
      var evicted = this._botLru.evictOldest();
      if (evicted) delete this._botAttempts[evicted];
    }
  }
  this._botLru.push(rec.botId);
  this._botAttempts[rec.botId].push(rec);

  // Per-challenge-type tracking
  if (!this._challengeStats[rec.challengeType]) {
    while (this._challengeLru.length >= this._maxChallengeTypes) {
      var evictedCt = this._challengeLru.evictOldest();
      if (evictedCt) delete this._challengeStats[evictedCt];
    }
    this._challengeStats[rec.challengeType] = {
      attempts: 0,
      solves: 0,
      totalCost: 0,
      totalValue: 0,
      difficulties: [],
      solveTimes: []
    };
  }
  this._challengeLru.push(rec.challengeType);
  var cs = this._challengeStats[rec.challengeType];
  cs.attempts++;
  cs.difficulties.push(rec.difficulty);
  if (rec.solved) {
    cs.solves++;
    cs.totalValue += this._valuePerSolve;
    if (rec.solveTimeMs > 0) cs.solveTimes.push(rec.solveTimeMs);
  }
  // Cost scales with difficulty (harder = more expensive to attack)
  cs.totalCost += this._costPerAttempt * (1 + rec.difficulty);
};

/**
 * Record a defense action (difficulty adjustment).
 *
 * @param {Object} action
 * @param {string} action.challengeType - Challenge type adjusted
 * @param {number} action.difficultyBefore - Previous difficulty
 * @param {number} action.difficultyAfter - New difficulty
 * @param {number} [action.timestamp] - When the change happened
 */
BotBehavioralEconomicsEngine.prototype.recordDefenseAction = function (action) {
  if (!action || typeof action !== "object") {
    throw new Error("action must be an object");
  }
  if (!action.challengeType || typeof action.challengeType !== "string") {
    throw new Error("action.challengeType required");
  }
  this._defenseActions.push({
    challengeType: action.challengeType,
    difficultyBefore: _nnOpt(action.difficultyBefore, 0),
    difficultyAfter: _nnOpt(action.difficultyAfter, 0),
    timestamp: action.timestamp || _now()
  });
};

// ── Engine 1: Attack Cost Modeler ───────────────────────────────────

/**
 * Analyze attack costs per challenge type.
 *
 * @returns {Object} Cost analysis per challenge type
 */
BotBehavioralEconomicsEngine.prototype.analyzeAttackCosts = function () {
  var types = _objKeys(this._challengeStats);
  var results = Object.create(null);

  for (var i = 0; i < types.length; i++) {
    var ct = types[i];
    var cs = this._challengeStats[ct];
    if (cs.attempts < this._minSamples) continue;

    var solveRate = cs.solves / cs.attempts;
    var costPerSolve = cs.solves > 0 ? cs.totalCost / cs.solves : Infinity;
    var avgDifficulty = _mean(cs.difficulties);
    var roi = cs.solves > 0 ? (cs.totalValue - cs.totalCost) / cs.totalCost : -1;

    // Marginal cost: use linear regression on difficulty vs cost-per-attempt
    var marginalSlope = 0;
    if (cs.difficulties.length >= 3) {
      var costs = [];
      for (var j = 0; j < cs.difficulties.length; j++) {
        costs.push(this._costPerAttempt * (1 + cs.difficulties[j]));
      }
      var reg = _linearRegression(cs.difficulties, costs);
      marginalSlope = reg.slope;
    }

    results[ct] = {
      attempts: cs.attempts,
      solves: cs.solves,
      solveRate: Math.round(solveRate * 1000) / 1000,
      totalCost: Math.round(cs.totalCost * 100) / 100,
      totalValue: Math.round(cs.totalValue * 100) / 100,
      costPerSolve: costPerSolve === Infinity ? null : Math.round(costPerSolve * 100) / 100,
      roi: Math.round(roi * 1000) / 1000,
      avgDifficulty: Math.round(avgDifficulty * 1000) / 1000,
      marginalCostSlope: Math.round(marginalSlope * 1000) / 1000,
      profitable: roi > 0
    };
  }

  return {
    challengeTypes: results,
    totalAttempts: this._attempts.length,
    analyzedTypes: _objKeys(results).length
  };
};

// ── Engine 2: Exploit Arbitrage Detector ────────────────────────────

/**
 * Detect arbitrage opportunities — challenge types where bot ROI is disproportionately high.
 *
 * @returns {Object} Arbitrage analysis
 */
BotBehavioralEconomicsEngine.prototype.detectArbitrage = function () {
  var costs = this.analyzeAttackCosts();
  var types = _objKeys(costs.challengeTypes);
  var opportunities = [];
  var rois = [];

  for (var i = 0; i < types.length; i++) {
    var ct = costs.challengeTypes[types[i]];
    if (ct.roi !== null && ct.roi !== undefined) {
      rois.push(ct.roi);
    }
  }

  var avgRoi = rois.length > 0 ? _mean(rois) : 0;
  var roiStd = rois.length > 1 ? _stddev(rois) : 0;

  for (var j = 0; j < types.length; j++) {
    var ctName = types[j];
    var ctData = costs.challengeTypes[ctName];
    if (ctData.roi === null || ctData.roi === undefined) continue;

    // Arbitrage: ROI significantly above average AND above threshold
    var roiZScore = roiStd > 0 ? (ctData.roi - avgRoi) / roiStd : 0;
    var isArbitrage = ctData.roi > this._arbitrageThreshold && roiZScore > 0.5;

    if (isArbitrage) {
      opportunities.push({
        challengeType: ctName,
        roi: ctData.roi,
        roiZScore: Math.round(roiZScore * 100) / 100,
        solveRate: ctData.solveRate,
        avgDifficulty: ctData.avgDifficulty,
        severity: roiZScore > 2 ? "CRITICAL" : roiZScore > 1 ? "HIGH" : "MODERATE"
      });
    }
  }

  // Sort by ROI descending
  opportunities.sort(function (a, b) { return b.roi - a.roi; });

  // Temporal windows: check if arbitrage correlates with defense changes
  var windows = [];
  for (var k = 0; k < this._defenseActions.length; k++) {
    var da = this._defenseActions[k];
    if (da.difficultyAfter < da.difficultyBefore) {
      windows.push({
        challengeType: da.challengeType,
        difficultyDrop: Math.round((da.difficultyBefore - da.difficultyAfter) * 1000) / 1000,
        timestamp: da.timestamp,
        type: "DIFFICULTY_REDUCTION"
      });
    }
  }

  return {
    opportunities: opportunities,
    arbitrageCount: opportunities.length,
    averageRoi: Math.round(avgRoi * 1000) / 1000,
    temporalWindows: windows,
    hasArbitrage: opportunities.length > 0
  };
};

// ── Engine 3: Economic Deterrence Analyzer ──────────────────────────

/**
 * Analyze deterrence effectiveness — what difficulty makes attacks unprofitable.
 *
 * @returns {Object} Deterrence analysis
 */
BotBehavioralEconomicsEngine.prototype.analyzeDeterrence = function () {
  var types = _objKeys(this._challengeStats);
  var deterrenceMap = Object.create(null);
  var covered = 0;
  var total = 0;

  for (var i = 0; i < types.length; i++) {
    var ct = types[i];
    var cs = this._challengeStats[ct];
    if (cs.attempts < this._deterrenceMinSamples) continue;
    total++;

    // Group attempts by difficulty buckets (0.0-0.2, 0.2-0.4, etc.)
    var buckets = [{}, {}, {}, {}, {}]; // 5 buckets
    for (var j = 0; j < this._attempts.length; j++) {
      var a = this._attempts[j];
      if (a.challengeType !== ct) continue;
      var bucketIdx = Math.min(Math.floor(a.difficulty * 5), 4);
      if (!buckets[bucketIdx].attempts) {
        buckets[bucketIdx] = { attempts: 0, solves: 0 };
      }
      buckets[bucketIdx].attempts++;
      if (a.solved) buckets[bucketIdx].solves++;
    }

    // Find deterrence price: difficulty at which solve rate drops below profitability
    var breakEvenRate = this._costPerAttempt / this._valuePerSolve;
    var deterrencePrice = null;
    for (var b = 0; b < buckets.length; b++) {
      if (buckets[b].attempts && buckets[b].attempts >= 2) {
        var rate = buckets[b].solves / buckets[b].attempts;
        if (rate <= breakEvenRate) {
          deterrencePrice = (b * 0.2) + 0.1; // midpoint of bucket
          break;
        }
      }
    }

    // Price elasticity: how much does solve volume drop per unit difficulty increase
    var diffs = [];
    var rates = [];
    for (var c = 0; c < buckets.length; c++) {
      if (buckets[c].attempts && buckets[c].attempts >= 2) {
        diffs.push(c * 0.2 + 0.1);
        rates.push(buckets[c].solves / buckets[c].attempts);
      }
    }

    var elasticity = 0;
    if (diffs.length >= 2) {
      var reg = _linearRegression(diffs, rates);
      elasticity = reg.slope; // negative means higher difficulty reduces solve rate
    }

    var currentDifficulty = _mean(cs.difficulties);
    var isDeterred = deterrencePrice !== null && currentDifficulty >= deterrencePrice;
    if (isDeterred) covered++;

    deterrenceMap[ct] = {
      currentDifficulty: Math.round(currentDifficulty * 1000) / 1000,
      deterrencePrice: deterrencePrice,
      priceElasticity: Math.round(elasticity * 1000) / 1000,
      breakEvenSolveRate: Math.round(breakEvenRate * 1000) / 1000,
      isDeterred: isDeterred,
      recommendation: isDeterred
        ? "MAINTAIN"
        : deterrencePrice !== null
          ? "INCREASE_TO_" + deterrencePrice.toFixed(1)
          : "INSUFFICIENT_DATA"
    };
  }

  return {
    challengeTypes: deterrenceMap,
    coverage: total > 0 ? Math.round((covered / total) * 1000) / 1000 : 0,
    coveredCount: covered,
    totalAnalyzed: total
  };
};

// ── Engine 4: Resource Allocation Tracker ───────────────────────────

/**
 * Track bot operator resource allocation patterns.
 *
 * @returns {Object} Resource allocation analysis
 */
BotBehavioralEconomicsEngine.prototype.analyzeResourceAllocation = function () {
  var botIds = _objKeys(this._botAttempts);
  var botAllocations = Object.create(null);
  var globalAllocation = Object.create(null);
  var totalAttempts = 0;

  for (var i = 0; i < botIds.length; i++) {
    var botId = botIds[i];
    var attempts = this._botAttempts[botId];
    if (!attempts || attempts.length < this._minSamples) continue;

    var allocation = Object.create(null);
    for (var j = 0; j < attempts.length; j++) {
      var ct = attempts[j].challengeType;
      if (!allocation[ct]) allocation[ct] = 0;
      allocation[ct]++;
      if (!globalAllocation[ct]) globalAllocation[ct] = 0;
      globalAllocation[ct]++;
      totalAttempts++;
    }

    // Detect concentration: what fraction goes to top challenge type
    var ctKeys = _objKeys(allocation);
    var counts = [];
    for (var k = 0; k < ctKeys.length; k++) counts.push(allocation[ctKeys[k]]);
    counts.sort(function (a, b) { return b - a; });

    var totalBot = attempts.length;
    var concentration = counts.length > 0 ? counts[0] / totalBot : 0;

    // Detect reallocation events: shifts in target over time
    var reallocations = 0;
    if (attempts.length >= 4) {
      var mid = Math.floor(attempts.length / 2);
      var firstHalf = Object.create(null);
      var secondHalf = Object.create(null);
      for (var m = 0; m < attempts.length; m++) {
        var target = m < mid ? firstHalf : secondHalf;
        if (!target[attempts[m].challengeType]) target[attempts[m].challengeType] = 0;
        target[attempts[m].challengeType]++;
      }
      // Count types that appear in one half but not the other
      var allTypes = Object.create(null);
      var fhKeys = _objKeys(firstHalf);
      var shKeys = _objKeys(secondHalf);
      for (var n = 0; n < fhKeys.length; n++) allTypes[fhKeys[n]] = true;
      for (var o = 0; o < shKeys.length; o++) allTypes[shKeys[o]] = true;
      var allTypeKeys = _objKeys(allTypes);
      for (var p = 0; p < allTypeKeys.length; p++) {
        var f = firstHalf[allTypeKeys[p]] || 0;
        var s = secondHalf[allTypeKeys[p]] || 0;
        var totalFS = f + s;
        if (totalFS > 0 && Math.abs(f - s) / totalFS > 0.5) reallocations++;
      }
    }

    botAllocations[botId] = {
      totalAttempts: totalBot,
      challengeTypes: _objKeys(allocation).length,
      concentration: Math.round(concentration * 1000) / 1000,
      reallocations: reallocations,
      budgetCeiling: totalBot // proxy for budget
    };
  }

  // Global allocation distribution
  var globalKeys = _objKeys(globalAllocation);
  var globalDist = Object.create(null);
  for (var q = 0; q < globalKeys.length; q++) {
    globalDist[globalKeys[q]] = {
      attempts: globalAllocation[globalKeys[q]],
      share: totalAttempts > 0
        ? Math.round((globalAllocation[globalKeys[q]] / totalAttempts) * 1000) / 1000
        : 0
    };
  }

  // Gini coefficient of global allocation
  var shares = [];
  for (var r = 0; r < globalKeys.length; r++) {
    shares.push(globalAllocation[globalKeys[r]]);
  }
  shares.sort(function (a, b) { return a - b; });
  var gini = 0;
  if (shares.length > 1) {
    var sumShares = _sum(shares);
    var giniNum = 0;
    for (var gi = 0; gi < shares.length; gi++) {
      giniNum += (2 * (gi + 1) - shares.length - 1) * shares[gi];
    }
    gini = sumShares > 0 ? giniNum / (shares.length * sumShares) : 0;
  }

  return {
    bots: botAllocations,
    globalDistribution: globalDist,
    giniConcentration: Math.round(Math.abs(gini) * 1000) / 1000,
    totalBots: _objKeys(botAllocations).length,
    totalAttempts: totalAttempts
  };
};

// ── Engine 5: Market Equilibrium Finder ─────────────────────────────

/**
 * Find Nash equilibrium between defender and attacker strategies.
 *
 * @returns {Object} Equilibrium analysis
 */
BotBehavioralEconomicsEngine.prototype.findEquilibrium = function () {
  var types = _objKeys(this._challengeStats);
  var equilibria = Object.create(null);

  for (var i = 0; i < types.length; i++) {
    var ct = types[i];
    var cs = this._challengeStats[ct];
    if (cs.attempts < this._minSamples) continue;

    var solveRate = cs.solves / cs.attempts;
    var avgDiff = _mean(cs.difficulties);

    // Defender utility: higher difficulty reduces solves but costs more to maintain
    // U_d = (1 - solveRate) * avgDiff - maintenanceCost(avgDiff)
    var defenderUtility = (1 - solveRate) * avgDiff - avgDiff * 0.1;

    // Attacker utility: solves generate value but cost increases with difficulty
    // U_a = solveRate * valuePerSolve - costPerAttempt * (1 + difficulty)
    var attackerUtility = solveRate * this._valuePerSolve - this._costPerAttempt * (1 + avgDiff);

    // Equilibrium: both sides have no incentive to deviate
    // Approximate equilibrium difficulty: where attacker ROI ≈ 0
    var eqDifficulty = this._valuePerSolve * solveRate / this._costPerAttempt - 1;
    eqDifficulty = _clamp(eqDifficulty, 0, 1);

    var deviation = Math.abs(avgDiff - eqDifficulty);
    var isConverged = deviation < 0.15;

    var advantage = "NEUTRAL";
    if (attackerUtility > defenderUtility * 2) advantage = "ATTACKER";
    else if (defenderUtility > attackerUtility * 2) advantage = "DEFENDER";

    equilibria[ct] = {
      currentDifficulty: Math.round(avgDiff * 1000) / 1000,
      equilibriumDifficulty: Math.round(eqDifficulty * 1000) / 1000,
      deviation: Math.round(deviation * 1000) / 1000,
      isConverged: isConverged,
      defenderUtility: Math.round(defenderUtility * 100) / 100,
      attackerUtility: Math.round(attackerUtility * 100) / 100,
      advantage: advantage
    };
  }

  // Overall market state
  var eqKeys = _objKeys(equilibria);
  var convergedCount = 0;
  var attackerAdv = 0;
  for (var j = 0; j < eqKeys.length; j++) {
    if (equilibria[eqKeys[j]].isConverged) convergedCount++;
    if (equilibria[eqKeys[j]].advantage === "ATTACKER") attackerAdv++;
  }

  var marketState = "STABLE";
  if (eqKeys.length > 0) {
    if (attackerAdv / eqKeys.length > 0.5) marketState = "ATTACKER_DOMINANT";
    else if (convergedCount / eqKeys.length < 0.3) marketState = "VOLATILE";
  }

  return {
    challengeTypes: equilibria,
    marketState: marketState,
    convergedFraction: eqKeys.length > 0
      ? Math.round((convergedCount / eqKeys.length) * 1000) / 1000
      : 0,
    analyzedTypes: eqKeys.length
  };
};

// ── Engine 6: Economic Health Scorer ────────────────────────────────

/**
 * Compute composite economic health score 0-100.
 *
 * @returns {Object} Health score and tier
 */
BotBehavioralEconomicsEngine.prototype.score = function () {
  if (this._attempts.length < this._minSamples) {
    return {
      score: 50,
      tier: "CONTESTED",
      confidence: 0,
      components: {},
      description: "Insufficient data for scoring"
    };
  }

  var costs = this.analyzeAttackCosts();
  var arb = this.detectArbitrage();
  var det = this.analyzeDeterrence();
  var eq = this.findEquilibrium();

  // Component 1: Average attack ROI (lower = better for defender, 0-25 pts)
  var rois = [];
  var ctKeys = _objKeys(costs.challengeTypes);
  for (var i = 0; i < ctKeys.length; i++) {
    var r = costs.challengeTypes[ctKeys[i]].roi;
    if (r !== null && r !== undefined) rois.push(r);
  }
  var avgRoi = rois.length > 0 ? _mean(rois) : 0;
  // Negative ROI = great for defender (25pts), high positive ROI = bad (0pts)
  var roiScore = _clamp(25 - avgRoi * 25, 0, 25);

  // Component 2: Arbitrage prevalence (fewer = better, 0-25 pts)
  var arbFraction = ctKeys.length > 0 ? arb.arbitrageCount / ctKeys.length : 0;
  var arbScore = _clamp(25 * (1 - arbFraction * 2), 0, 25);

  // Component 3: Deterrence coverage (0-25 pts)
  var detScore = det.coverage * 25;

  // Component 4: Market equilibrium favorability (0-25 pts)
  var eqScore = 12.5; // neutral default
  if (eq.marketState === "ATTACKER_DOMINANT") eqScore = 5;
  else if (eq.marketState === "STABLE") eqScore = 20;
  if (eq.convergedFraction > 0.5) eqScore += 5;

  var total = Math.round(_clamp(roiScore + arbScore + detScore + eqScore, 0, 100));

  var tier;
  if (total >= 80) tier = "PROHIBITIVE";
  else if (total >= 60) tier = "DETERRENT";
  else if (total >= 40) tier = "CONTESTED";
  else if (total >= 20) tier = "EXPLOITABLE";
  else tier = "BANKRUPT";

  return {
    score: total,
    tier: tier,
    confidence: Math.min(this._attempts.length / 100, 1),
    components: {
      attackRoi: Math.round(roiScore * 10) / 10,
      arbitrage: Math.round(arbScore * 10) / 10,
      deterrence: Math.round(detScore * 10) / 10,
      equilibrium: Math.round(eqScore * 10) / 10
    },
    description: "Economic health: " + tier + " (score: " + total + "/100)"
  };
};

// ── Engine 7: Insight Generator ─────────────────────────────────────

/**
 * Generate autonomous insights and recommendations.
 *
 * @returns {Array} Array of insight objects
 */
BotBehavioralEconomicsEngine.prototype.generateInsights = function () {
  var insights = [];

  if (this._attempts.length < this._minSamples) {
    insights.push({
      type: "INFO",
      category: "data",
      message: "Need at least " + this._minSamples + " attempts for meaningful analysis",
      priority: "LOW"
    });
    return insights;
  }

  var costs = this.analyzeAttackCosts();
  var arb = this.detectArbitrage();
  var det = this.analyzeDeterrence();
  var alloc = this.analyzeResourceAllocation();
  var eq = this.findEquilibrium();
  var health = this.score();

  // Arbitrage insights
  if (arb.hasArbitrage) {
    for (var i = 0; i < arb.opportunities.length && i < 3; i++) {
      var opp = arb.opportunities[i];
      insights.push({
        type: "WARNING",
        category: "arbitrage",
        message: "Challenge type '" + opp.challengeType + "' has arbitrage ROI of " +
          opp.roi.toFixed(2) + " (severity: " + opp.severity + ")",
        priority: opp.severity === "CRITICAL" ? "CRITICAL" : "HIGH",
        recommendation: "Increase difficulty for '" + opp.challengeType + "' to eliminate profit margin"
      });
    }
  }

  // Deterrence insights
  var detKeys = _objKeys(det.challengeTypes);
  for (var j = 0; j < detKeys.length; j++) {
    var d = det.challengeTypes[detKeys[j]];
    if (!d.isDeterred && d.deterrencePrice !== null) {
      insights.push({
        type: "RECOMMENDATION",
        category: "deterrence",
        message: "Challenge '" + detKeys[j] + "' needs difficulty increase from " +
          d.currentDifficulty.toFixed(2) + " to " + d.deterrencePrice.toFixed(2) + " for deterrence",
        priority: "HIGH",
        recommendation: d.recommendation
      });
    }
  }

  // Resource concentration insight
  if (alloc.giniConcentration > 0.6) {
    insights.push({
      type: "INFO",
      category: "allocation",
      message: "Bot resources highly concentrated (Gini: " +
        alloc.giniConcentration.toFixed(2) + ") — attackers targeting specific challenge types",
      priority: "MEDIUM",
      recommendation: "Rotate challenge types to disrupt concentrated attacks"
    });
  }

  // Market state insight
  if (eq.marketState === "ATTACKER_DOMINANT") {
    insights.push({
      type: "ALERT",
      category: "equilibrium",
      message: "Attackers have dominant market position — defenses are not economically effective",
      priority: "CRITICAL",
      recommendation: "Urgently increase difficulty across all challenge types"
    });
  } else if (eq.marketState === "VOLATILE") {
    insights.push({
      type: "WARNING",
      category: "equilibrium",
      message: "Market equilibrium is volatile — both sides actively adjusting strategies",
      priority: "MEDIUM",
      recommendation: "Monitor closely and avoid rapid difficulty changes"
    });
  }

  // Overall health insight
  if (health.tier === "BANKRUPT" || health.tier === "EXPLOITABLE") {
    insights.push({
      type: "ALERT",
      category: "health",
      message: "Economic health is " + health.tier + " (score: " + health.score + "/100) — attacks are profitable",
      priority: "CRITICAL",
      recommendation: "Comprehensive difficulty overhaul needed"
    });
  } else if (health.tier === "PROHIBITIVE") {
    insights.push({
      type: "SUCCESS",
      category: "health",
      message: "Economic health is PROHIBITIVE (score: " + health.score + "/100) — attacks are unprofitable",
      priority: "LOW"
    });
  }

  // Cost trend insight
  var ctKeys = _objKeys(costs.challengeTypes);
  var profitableCount = 0;
  for (var k = 0; k < ctKeys.length; k++) {
    if (costs.challengeTypes[ctKeys[k]].profitable) profitableCount++;
  }
  if (ctKeys.length > 0 && profitableCount / ctKeys.length > 0.5) {
    insights.push({
      type: "WARNING",
      category: "cost",
      message: profitableCount + " of " + ctKeys.length + " challenge types are profitable for attackers",
      priority: "HIGH",
      recommendation: "Review pricing model — too many attack vectors remain profitable"
    });
  }

  // Sort by priority
  var priorityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  insights.sort(function (a, b) {
    return (priorityOrder[a.priority] || 3) - (priorityOrder[b.priority] || 3);
  });

  return insights;
};

// ── Full Report ─────────────────────────────────────────────────────

/**
 * Generate a full economic analysis report.
 *
 * @returns {Object} Combined report from all engines
 */
BotBehavioralEconomicsEngine.prototype.analyze = function () {
  return {
    attackCosts: this.analyzeAttackCosts(),
    arbitrage: this.detectArbitrage(),
    deterrence: this.analyzeDeterrence(),
    resourceAllocation: this.analyzeResourceAllocation(),
    equilibrium: this.findEquilibrium(),
    health: this.score(),
    insights: this.generateInsights(),
    meta: {
      totalAttempts: this._attempts.length,
      totalBots: this._botLru.length,
      totalChallengeTypes: this._challengeLru.length,
      generatedAt: _now()
    }
  };
};

// ── State Management ────────────────────────────────────────────────

/**
 * Export engine state for persistence.
 *
 * @returns {Object} Serializable state
 */
BotBehavioralEconomicsEngine.prototype.exportState = function () {
  return {
    version: 1,
    attempts: this._attempts.slice(),
    botAttempts: _safeClone(this._botAttempts),
    challengeStats: _safeClone(this._challengeStats),
    defenseActions: this._defenseActions.slice(),
    botLru: this._botLru.toArray(),
    challengeLru: this._challengeLru.toArray()
  };
};

/**
 * Import engine state from a previously exported snapshot.
 * Rejects prototype-pollution keys.
 *
 * @param {Object} state - Previously exported state
 */
BotBehavioralEconomicsEngine.prototype.importState = function (state) {
  if (!state || typeof state !== "object") {
    throw new Error("state must be an object");
  }
  if (state.__proto__ !== undefined || state.constructor !== undefined) {
    // Check for explicit dangerous keys in top-level
  }

  this._attempts = Array.isArray(state.attempts) ? _safeClone(state.attempts) : [];
  this._botAttempts = state.botAttempts ? _safeClone(state.botAttempts) : Object.create(null);
  this._challengeStats = state.challengeStats ? _safeClone(state.challengeStats) : Object.create(null);
  this._defenseActions = Array.isArray(state.defenseActions) ? _safeClone(state.defenseActions) : [];

  this._botLru = new LruTracker();
  if (Array.isArray(state.botLru)) {
    for (var i = 0; i < state.botLru.length; i++) {
      if (_isSafeKey(state.botLru[i])) this._botLru.push(state.botLru[i]);
    }
  }

  this._challengeLru = new LruTracker();
  if (Array.isArray(state.challengeLru)) {
    for (var j = 0; j < state.challengeLru.length; j++) {
      if (_isSafeKey(state.challengeLru[j])) this._challengeLru.push(state.challengeLru[j]);
    }
  }
};

// ── Exports ─────────────────────────────────────────────────────────

module.exports = {
  BotBehavioralEconomicsEngine: BotBehavioralEconomicsEngine,
  HEALTH_TIERS: HEALTH_TIERS
};
