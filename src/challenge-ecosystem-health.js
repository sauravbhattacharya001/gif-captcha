/**
 * ChallengeEcosystemHealthEngine — Autonomous CAPTCHA challenge pool ecosystem analysis.
 *
 * Models the entire challenge pool as a biological ecosystem where challenges are
 * "species," bots are "predators," and human solvers are "pollinators." Provides
 * holistic health metrics that go beyond individual challenge monitoring.
 *
 * Key capabilities:
 *   - Shannon biodiversity index across challenge categories and difficulty levels
 *   - Predator-prey dynamics (Lotka-Volterra bot-vs-challenge modeling)
 *   - Carrying capacity estimation based on traffic and solve patterns
 *   - Extinction risk detection for endangered challenge types
 *   - Evolution pressure measurement (bot adaptation speed)
 *   - Niche analysis (over/under-served difficulty bands)
 *   - Keystone challenge identification (critical linchpins in the pool)
 *   - Composite ecosystem health score 0-100
 *   - Autonomous insight generation with actionable recommendations
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/challenge-ecosystem-health
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _clamp = _shared._clamp;
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _linearRegression = _shared._linearRegression;
var _posOpt = _shared._posOpt;
var _nnOpt = _shared._nnOpt;
var LruTracker = _shared.LruTracker;

// ── Constants ───────────────────────────────────────────────────────

/** Ecosystem health tiers */
var HEALTH_TIERS = {
  THRIVING: "THRIVING",
  HEALTHY: "HEALTHY",
  STRESSED: "STRESSED",
  ENDANGERED: "ENDANGERED",
  CRITICAL: "CRITICAL"
};

/** Extinction risk levels */
var EXTINCTION_RISK = {
  SAFE: "SAFE",
  VULNERABLE: "VULNERABLE",
  ENDANGERED: "ENDANGERED",
  CRITICAL: "CRITICAL",
  EXTINCT: "EXTINCT"
};

/** Niche saturation levels */
var NICHE_STATUS = {
  BARREN: "BARREN",
  SPARSE: "SPARSE",
  BALANCED: "BALANCED",
  CROWDED: "CROWDED",
  OVERSATURATED: "OVERSATURATED"
};

/** Default configuration */
var DEFAULTS = {
  maxChallenges: 1000,
  difficultyBands: 5,
  minSamplesForAnalysis: 5,
  predatorGrowthRate: 0.1,
  preyGrowthRate: 0.3,
  carryingCapacityBase: 200,
  extinctionThreshold: 0.15,
  keystoneThreshold: 0.25,
  evolutionWindowMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  snapshotIntervalMs: 24 * 60 * 60 * 1000, // 24h
  maxSnapshots: 90,
  maxEventsPerChallenge: 500
};

// ── Constructor ─────────────────────────────────────────────────────

/**
 * @constructor
 * @param {Object} [options]
 * @param {number} [options.maxChallenges=1000]
 * @param {number} [options.difficultyBands=5]
 * @param {number} [options.minSamplesForAnalysis=5]
 * @param {number} [options.predatorGrowthRate=0.1]
 * @param {number} [options.preyGrowthRate=0.3]
 * @param {number} [options.carryingCapacityBase=200]
 * @param {number} [options.extinctionThreshold=0.15]
 * @param {number} [options.keystoneThreshold=0.25]
 * @param {number} [options.evolutionWindowMs]
 * @param {number} [options.snapshotIntervalMs]
 * @param {number} [options.maxSnapshots=90]
 */
function ChallengeEcosystemHealthEngine(options) {
  var o = options || {};
  this._cfg = {
    maxChallenges: _posOpt(o.maxChallenges, DEFAULTS.maxChallenges),
    difficultyBands: _posOpt(o.difficultyBands, DEFAULTS.difficultyBands),
    minSamples: _posOpt(o.minSamplesForAnalysis, DEFAULTS.minSamplesForAnalysis),
    predatorGrowth: _posOpt(o.predatorGrowthRate, DEFAULTS.predatorGrowthRate),
    preyGrowth: _posOpt(o.preyGrowthRate, DEFAULTS.preyGrowthRate),
    carryingCapBase: _posOpt(o.carryingCapacityBase, DEFAULTS.carryingCapacityBase),
    extinctionThresh: _posOpt(o.extinctionThreshold, DEFAULTS.extinctionThreshold),
    keystoneThresh: _posOpt(o.keystoneThreshold, DEFAULTS.keystoneThreshold),
    evolutionWindowMs: _posOpt(o.evolutionWindowMs, DEFAULTS.evolutionWindowMs),
    snapshotIntervalMs: _posOpt(o.snapshotIntervalMs, DEFAULTS.snapshotIntervalMs),
    maxSnapshots: _posOpt(o.maxSnapshots, DEFAULTS.maxSnapshots),
    maxEvents: _posOpt(o.maxEventsPerChallenge, DEFAULTS.maxEventsPerChallenge)
  };

  /** @type {Object.<string, ChallengeRecord>} */
  this._challenges = Object.create(null);
  /** @type {string[]} ordering for LRU eviction */
  this._lru = new LruTracker();
  /** @type {Array} historical ecosystem snapshots */
  this._snapshots = [];
  this._lastSnapshotTs = 0;
  this._totalEvents = 0;
}

// ── Registration ────────────────────────────────────────────────────

/**
 * Register a challenge in the ecosystem.
 *
 * @param {string} id - Unique challenge identifier
 * @param {Object} meta - Challenge metadata
 * @param {string} meta.category - Challenge category (e.g. "visual", "temporal", "spatial")
 * @param {number} meta.difficulty - Difficulty level 0-1
 * @param {string[]} [meta.tags] - Additional classification tags
 * @param {number} [meta.createdAt] - Creation timestamp (ms)
 */
ChallengeEcosystemHealthEngine.prototype.register = function (id, meta) {
  if (!id || !meta || meta.category == null || meta.difficulty == null) {
    throw new Error("register requires id, meta.category, meta.difficulty");
  }
  var cid = String(id);
  if (!this._challenges[cid]) {
    // Evict oldest if at capacity
    if (this._lru.length >= this._cfg.maxChallenges) {
      var evicted = this._lru.evictOldest();
      if (evicted) delete this._challenges[evicted];
    }
    this._challenges[cid] = {
      id: cid,
      category: String(meta.category),
      difficulty: _clamp(Number(meta.difficulty) || 0, 0, 1),
      tags: Array.isArray(meta.tags) ? meta.tags.slice() : [],
      createdAt: _nnOpt(meta.createdAt, _now()),
      humanSolves: 0,
      botSolves: 0,
      humanAttempts: 0,
      botAttempts: 0,
      solveTimes: [],
      lastActivityTs: _now(),
      retired: false
    };
    this._lru.push(cid);
  } else {
    // Update metadata on re-register
    this._challenges[cid].category = String(meta.category);
    this._challenges[cid].difficulty = _clamp(Number(meta.difficulty) || 0, 0, 1);
    if (Array.isArray(meta.tags)) this._challenges[cid].tags = meta.tags.slice();
    this._lru.touch(cid);
  }
};

/**
 * Record a solve event for a challenge.
 *
 * @param {string} id - Challenge identifier
 * @param {Object} event
 * @param {boolean} event.isBot - Whether the solver was identified as a bot
 * @param {boolean} event.solved - Whether the challenge was solved
 * @param {number} [event.solveTimeMs] - Time taken to solve in ms
 * @param {number} [event.timestamp] - Event timestamp
 */
ChallengeEcosystemHealthEngine.prototype.recordEvent = function (id, event) {
  var cid = String(id);
  var ch = this._challenges[cid];
  if (!ch) return; // Silently ignore unregistered challenges

  var e = event || {};
  var ts = _nnOpt(e.timestamp, _now());

  if (e.isBot) {
    ch.botAttempts++;
    if (e.solved) ch.botSolves++;
  } else {
    ch.humanAttempts++;
    if (e.solved) ch.humanSolves++;
  }

  if (e.solveTimeMs != null && e.solveTimeMs > 0 && e.solved) {
    ch.solveTimes.push(e.solveTimeMs);
    if (ch.solveTimes.length > this._cfg.maxEvents) {
      ch.solveTimes = ch.solveTimes.slice(-this._cfg.maxEvents);
    }
  }

  ch.lastActivityTs = ts;
  this._lru.touch(cid);
  this._totalEvents++;

  // Auto-snapshot
  if (ts - this._lastSnapshotTs >= this._cfg.snapshotIntervalMs) {
    this._takeSnapshot(ts);
  }
};

/**
 * Mark a challenge as retired/extinct.
 *
 * @param {string} id - Challenge identifier
 */
ChallengeEcosystemHealthEngine.prototype.retire = function (id) {
  var ch = this._challenges[String(id)];
  if (ch) ch.retired = true;
};

// ── Core Analysis Engines ───────────────────────────────────────────

/**
 * Run full ecosystem analysis.
 *
 * @returns {Object} Complete ecosystem health report
 */
ChallengeEcosystemHealthEngine.prototype.analyze = function () {
  var challenges = this._activeChallenges();
  var allChallenges = this._allChallengeList();

  var biodiversity = this._computeBiodiversity(challenges);
  var predatorPrey = this._computePredatorPrey(challenges);
  var carrying = this._computeCarryingCapacity(challenges);
  var extinction = this._computeExtinctionRisk(challenges);
  var evolution = this._computeEvolutionPressure(challenges);
  var niches = this._computeNicheAnalysis(challenges);
  var keystones = this._computeKeystones(challenges);

  var healthScore = this._computeHealthScore(
    biodiversity, predatorPrey, carrying, extinction, evolution, niches
  );
  var tier = this._classifyTier(healthScore);
  var insights = this._generateInsights(
    biodiversity, predatorPrey, carrying, extinction, evolution, niches, keystones, healthScore
  );

  return {
    timestamp: _now(),
    totalRegistered: allChallenges.length,
    totalActive: challenges.length,
    totalRetired: allChallenges.length - challenges.length,
    totalEvents: this._totalEvents,
    healthScore: Math.round(healthScore * 100) / 100,
    tier: tier,
    biodiversity: biodiversity,
    predatorPrey: predatorPrey,
    carryingCapacity: carrying,
    extinctionRisk: extinction,
    evolutionPressure: evolution,
    niches: niches,
    keystones: keystones,
    insights: insights,
    snapshotCount: this._snapshots.length
  };
};

// ── Engine 1: Biodiversity ──────────────────────────────────────────

/**
 * Compute Shannon diversity index and evenness across categories and difficulty.
 */
ChallengeEcosystemHealthEngine.prototype._computeBiodiversity = function (challenges) {
  if (challenges.length === 0) {
    return { shannonIndex: 0, evenness: 0, richness: 0, categoryDistribution: {}, dominantCategory: null };
  }

  // Category frequency
  var catCounts = Object.create(null);
  var totalCat = 0;
  for (var i = 0; i < challenges.length; i++) {
    var cat = challenges[i].category;
    catCounts[cat] = (catCounts[cat] || 0) + 1;
    totalCat++;
  }

  // Shannon index: H = -Σ(pi * ln(pi))
  var H = 0;
  var cats = Object.keys(catCounts);
  for (var j = 0; j < cats.length; j++) {
    var p = catCounts[cats[j]] / totalCat;
    if (p > 0) H -= p * Math.log(p);
  }

  var richness = cats.length;
  // Evenness: H / Hmax where Hmax = ln(S)
  var evenness = richness > 1 ? H / Math.log(richness) : (richness === 1 ? 1 : 0);

  // Build distribution
  var dist = {};
  for (var k = 0; k < cats.length; k++) {
    dist[cats[k]] = {
      count: catCounts[cats[k]],
      proportion: Math.round((catCounts[cats[k]] / totalCat) * 1000) / 1000
    };
  }

  // Find dominant
  var dominant = null;
  var maxCount = 0;
  for (var m = 0; m < cats.length; m++) {
    if (catCounts[cats[m]] > maxCount) {
      maxCount = catCounts[cats[m]];
      dominant = cats[m];
    }
  }

  return {
    shannonIndex: Math.round(H * 1000) / 1000,
    evenness: Math.round(evenness * 1000) / 1000,
    richness: richness,
    categoryDistribution: dist,
    dominantCategory: dominant
  };
};

// ── Engine 2: Predator-Prey Dynamics ────────────────────────────────

/**
 * Model bot-challenge interaction as predator-prey dynamics.
 */
ChallengeEcosystemHealthEngine.prototype._computePredatorPrey = function (challenges) {
  if (challenges.length === 0) {
    return { botPressure: 0, humanEngagement: 0, predationRate: 0, defenseEffectiveness: 1, phase: "dormant", equilibrium: true };
  }

  var totalBotAttempts = 0, totalBotSolves = 0;
  var totalHumanAttempts = 0, totalHumanSolves = 0;

  for (var i = 0; i < challenges.length; i++) {
    var ch = challenges[i];
    totalBotAttempts += ch.botAttempts;
    totalBotSolves += ch.botSolves;
    totalHumanAttempts += ch.humanAttempts;
    totalHumanSolves += ch.humanSolves;
  }

  var totalAttempts = totalBotAttempts + totalHumanAttempts;
  var botPressure = totalAttempts > 0 ? totalBotAttempts / totalAttempts : 0;
  var humanEngagement = totalAttempts > 0 ? totalHumanAttempts / totalAttempts : 0;

  // Predation rate: how effectively bots crack challenges
  var predationRate = totalBotAttempts > 0 ? totalBotSolves / totalBotAttempts : 0;

  // Defense effectiveness: how well challenges resist bots
  var defenseEffectiveness = 1 - predationRate;

  // Phase classification based on Lotka-Volterra dynamics
  var phase;
  if (totalAttempts < this._cfg.minSamples) {
    phase = "dormant";
  } else if (botPressure < 0.1) {
    phase = "peaceful";
  } else if (botPressure < 0.3 && defenseEffectiveness > 0.7) {
    phase = "balanced";
  } else if (botPressure >= 0.3 && defenseEffectiveness > 0.5) {
    phase = "arms-race";
  } else if (predationRate > 0.6) {
    phase = "predator-dominance";
  } else {
    phase = "siege";
  }

  // Equilibrium: system is in equilibrium when neither side is rapidly gaining
  var equilibrium = botPressure > 0.15 && botPressure < 0.5 && defenseEffectiveness > 0.4;

  return {
    botPressure: Math.round(botPressure * 1000) / 1000,
    humanEngagement: Math.round(humanEngagement * 1000) / 1000,
    predationRate: Math.round(predationRate * 1000) / 1000,
    defenseEffectiveness: Math.round(defenseEffectiveness * 1000) / 1000,
    phase: phase,
    equilibrium: equilibrium,
    totalBotAttempts: totalBotAttempts,
    totalHumanAttempts: totalHumanAttempts
  };
};

// ── Engine 3: Carrying Capacity ─────────────────────────────────────

/**
 * Estimate the ecosystem's carrying capacity — optimal pool size.
 */
ChallengeEcosystemHealthEngine.prototype._computeCarryingCapacity = function (challenges) {
  if (challenges.length === 0) {
    return { currentPopulation: 0, estimatedCapacity: this._cfg.carryingCapBase, utilizationRatio: 0, status: "empty" };
  }

  var currentPop = challenges.length;

  // Estimate capacity from activity distribution
  var activeCounts = [];
  var now = _now();
  var windowMs = this._cfg.evolutionWindowMs;

  for (var i = 0; i < challenges.length; i++) {
    var ch = challenges[i];
    var totalAttempts = ch.humanAttempts + ch.botAttempts;
    if (totalAttempts > 0) activeCounts.push(totalAttempts);
  }

  // Capacity scales with demand — more traffic can sustain more challenges
  var avgActivity = _mean(activeCounts);
  var estimatedCap;
  if (avgActivity > 0) {
    // More active challenges → higher capacity, but with diminishing returns
    estimatedCap = Math.max(
      this._cfg.carryingCapBase,
      Math.round(currentPop * Math.sqrt(avgActivity / Math.max(1, _mean(activeCounts))))
    );
  } else {
    estimatedCap = this._cfg.carryingCapBase;
  }

  var utilization = estimatedCap > 0 ? currentPop / estimatedCap : 0;

  var status;
  if (utilization < 0.3) status = "underpopulated";
  else if (utilization < 0.7) status = "growing";
  else if (utilization < 0.9) status = "optimal";
  else if (utilization < 1.1) status = "near-capacity";
  else status = "overpopulated";

  return {
    currentPopulation: currentPop,
    estimatedCapacity: estimatedCap,
    utilizationRatio: Math.round(utilization * 1000) / 1000,
    status: status
  };
};

// ── Engine 4: Extinction Risk ───────────────────────────────────────

/**
 * Assess extinction risk for each challenge category.
 */
ChallengeEcosystemHealthEngine.prototype._computeExtinctionRisk = function (challenges) {
  var allList = this._allChallengeList();

  // Group by category
  var catActive = Object.create(null);
  var catRetired = Object.create(null);
  var catBotSolveRates = Object.create(null);

  for (var i = 0; i < allList.length; i++) {
    var ch = allList[i];
    var cat = ch.category;
    if (!catActive[cat]) { catActive[cat] = 0; catRetired[cat] = 0; catBotSolveRates[cat] = []; }
    if (ch.retired) {
      catRetired[cat]++;
    } else {
      catActive[cat]++;
      if (ch.botAttempts > 0) {
        catBotSolveRates[cat].push(ch.botSolves / ch.botAttempts);
      }
    }
  }

  var categories = Object.keys(catActive);
  var atRisk = [];
  var endangered = 0;
  var critical = 0;

  for (var j = 0; j < categories.length; j++) {
    var c = categories[j];
    var total = catActive[c] + catRetired[c];
    var retiredRatio = total > 0 ? catRetired[c] / total : 0;
    var avgBotRate = catBotSolveRates[c].length > 0 ? _mean(catBotSolveRates[c]) : 0;

    var risk;
    if (catActive[c] === 0) {
      risk = EXTINCTION_RISK.EXTINCT;
    } else if (catActive[c] <= 2 && avgBotRate > 0.5) {
      risk = EXTINCTION_RISK.CRITICAL;
      critical++;
    } else if (retiredRatio > 0.6 || (catActive[c] <= 3 && avgBotRate > 0.3)) {
      risk = EXTINCTION_RISK.ENDANGERED;
      endangered++;
    } else if (retiredRatio > 0.3 || avgBotRate > 0.4) {
      risk = EXTINCTION_RISK.VULNERABLE;
    } else {
      risk = EXTINCTION_RISK.SAFE;
    }

    atRisk.push({
      category: c,
      risk: risk,
      activeCount: catActive[c],
      retiredCount: catRetired[c],
      avgBotSolveRate: Math.round(avgBotRate * 1000) / 1000
    });
  }

  // Sort by risk severity
  var riskOrder = { CRITICAL: 0, ENDANGERED: 1, EXTINCT: 2, VULNERABLE: 3, SAFE: 4 };
  atRisk.sort(function (a, b) { return (riskOrder[a.risk] || 9) - (riskOrder[b.risk] || 9); });

  return {
    categories: atRisk,
    endangeredCount: endangered,
    criticalCount: critical,
    totalCategories: categories.length
  };
};

// ── Engine 5: Evolution Pressure ────────────────────────────────────

/**
 * Measure how quickly bots are adapting to challenges.
 */
ChallengeEcosystemHealthEngine.prototype._computeEvolutionPressure = function (challenges) {
  if (challenges.length === 0) {
    return { pressure: 0, adaptationSpeed: "none", solvingTimesTrend: 0, botLearningRate: 0 };
  }

  // Compute solve time trends — decreasing bot solve times = high evolution pressure
  var allSolveTimes = [];
  var botSolveRates = [];

  for (var i = 0; i < challenges.length; i++) {
    var ch = challenges[i];
    if (ch.solveTimes.length >= 3) {
      allSolveTimes.push(ch.solveTimes);
    }
    if (ch.botAttempts > 0) {
      botSolveRates.push(ch.botSolves / ch.botAttempts);
    }
  }

  // Trend: negative slope = bots getting faster
  var avgSlope = 0;
  var trendCount = 0;
  for (var j = 0; j < allSolveTimes.length; j++) {
    var reg = _linearRegression(allSolveTimes[j]);
    if (reg.r2 > 0.1) { // Only count meaningful trends
      avgSlope += reg.slope;
      trendCount++;
    }
  }
  avgSlope = trendCount > 0 ? avgSlope / trendCount : 0;

  // Bot learning rate: how quickly bot solve rate increases
  var avgBotRate = botSolveRates.length > 0 ? _mean(botSolveRates) : 0;

  // Composite pressure score
  var timePressure = avgSlope < 0 ? Math.min(1, Math.abs(avgSlope) / 100) : 0;
  var ratePressure = avgBotRate;
  var pressure = _clamp((timePressure * 0.4 + ratePressure * 0.6) * 100, 0, 100);

  var adaptationSpeed;
  if (pressure < 10) adaptationSpeed = "none";
  else if (pressure < 30) adaptationSpeed = "slow";
  else if (pressure < 60) adaptationSpeed = "moderate";
  else if (pressure < 80) adaptationSpeed = "fast";
  else adaptationSpeed = "rapid";

  return {
    pressure: Math.round(pressure * 100) / 100,
    adaptationSpeed: adaptationSpeed,
    solvingTimesTrend: Math.round(avgSlope * 100) / 100,
    botLearningRate: Math.round(avgBotRate * 1000) / 1000
  };
};

// ── Engine 6: Niche Analysis ────────────────────────────────────────

/**
 * Analyze difficulty distribution to find over/under-served niches.
 */
ChallengeEcosystemHealthEngine.prototype._computeNicheAnalysis = function (challenges) {
  var bands = this._cfg.difficultyBands;
  var bandWidth = 1 / bands;

  // Initialize bands
  var niches = [];
  for (var b = 0; b < bands; b++) {
    niches.push({
      band: b,
      rangeMin: Math.round(b * bandWidth * 100) / 100,
      rangeMax: Math.round((b + 1) * bandWidth * 100) / 100,
      label: _bandLabel(b, bands),
      count: 0,
      status: NICHE_STATUS.BARREN,
      avgBotResistance: 0,
      avgHumanSolveRate: 0
    });
  }

  if (challenges.length === 0) return { bands: niches, gapCount: bands, balance: 0 };

  // Classify challenges into bands
  var bandBotRes = [];
  var bandHumanRate = [];
  for (var i = 0; i < bands; i++) { bandBotRes.push([]); bandHumanRate.push([]); }

  for (var j = 0; j < challenges.length; j++) {
    var ch = challenges[j];
    var idx = Math.min(Math.floor(ch.difficulty / bandWidth), bands - 1);
    niches[idx].count++;

    if (ch.botAttempts > 0) {
      bandBotRes[idx].push(1 - ch.botSolves / ch.botAttempts);
    }
    if (ch.humanAttempts > 0) {
      bandHumanRate[idx].push(ch.humanSolves / ch.humanAttempts);
    }
  }

  // Classify niche saturation and compute averages
  var idealPerBand = challenges.length / bands;
  var gapCount = 0;

  for (var k = 0; k < bands; k++) {
    var ratio = idealPerBand > 0 ? niches[k].count / idealPerBand : 0;
    if (niches[k].count === 0) { niches[k].status = NICHE_STATUS.BARREN; gapCount++; }
    else if (ratio < 0.4) { niches[k].status = NICHE_STATUS.SPARSE; gapCount++; }
    else if (ratio < 1.5) niches[k].status = NICHE_STATUS.BALANCED;
    else if (ratio < 2.5) niches[k].status = NICHE_STATUS.CROWDED;
    else niches[k].status = NICHE_STATUS.OVERSATURATED;

    niches[k].avgBotResistance = bandBotRes[k].length > 0
      ? Math.round(_mean(bandBotRes[k]) * 1000) / 1000 : 0;
    niches[k].avgHumanSolveRate = bandHumanRate[k].length > 0
      ? Math.round(_mean(bandHumanRate[k]) * 1000) / 1000 : 0;
  }

  // Balance score: Shannon evenness across bands
  var counts = [];
  for (var m = 0; m < bands; m++) counts.push(niches[m].count);
  var total = challenges.length;
  var H = 0;
  for (var n = 0; n < counts.length; n++) {
    var p = counts[n] / total;
    if (p > 0) H -= p * Math.log(p);
  }
  var balance = bands > 1 ? H / Math.log(bands) : 1;

  return {
    bands: niches,
    gapCount: gapCount,
    balance: Math.round(balance * 1000) / 1000
  };
};

// ── Engine 7: Keystone Identification ───────────────────────────────

/**
 * Identify keystone challenges — critical linchpins whose removal would
 * disproportionately affect the ecosystem.
 */
ChallengeEcosystemHealthEngine.prototype._computeKeystones = function (challenges) {
  if (challenges.length === 0) return { keystones: [], count: 0 };

  var totalHumanSolves = 0;
  for (var i = 0; i < challenges.length; i++) {
    totalHumanSolves += challenges[i].humanSolves;
  }

  var keystones = [];
  for (var j = 0; j < challenges.length; j++) {
    var ch = challenges[j];
    // A keystone handles disproportionate share of traffic and has good bot resistance
    var humanShare = totalHumanSolves > 0 ? ch.humanSolves / totalHumanSolves : 0;
    var botResistance = ch.botAttempts > 0 ? 1 - ch.botSolves / ch.botAttempts : 1;
    var isKeystone = humanShare > this._cfg.keystoneThresh && botResistance > 0.5;

    if (isKeystone) {
      keystones.push({
        id: ch.id,
        category: ch.category,
        difficulty: ch.difficulty,
        humanShare: Math.round(humanShare * 1000) / 1000,
        botResistance: Math.round(botResistance * 1000) / 1000,
        impact: "high"
      });
    }
  }

  // Sort by human share descending
  keystones.sort(function (a, b) { return b.humanShare - a.humanShare; });

  return { keystones: keystones, count: keystones.length };
};

// ── Health Score ─────────────────────────────────────────────────────

/**
 * Compute composite ecosystem health score 0-100.
 */
ChallengeEcosystemHealthEngine.prototype._computeHealthScore = function (
  bio, predPrey, carrying, extinction, evolution, niches
) {
  // Empty ecosystem = no health
  if (carrying.currentPopulation === 0) return 0;

  // Weights for each dimension
  var w = { bio: 0.20, defense: 0.20, capacity: 0.15, extinction: 0.20, evolution: 0.10, niche: 0.15 };

  // Biodiversity: higher evenness = healthier
  var bioScore = bio.evenness * 100;

  // Defense: higher effectiveness = healthier
  var defenseScore = predPrey.defenseEffectiveness * 100;

  // Capacity: closer to optimal = healthier
  var capScore;
  var util = carrying.utilizationRatio;
  if (util >= 0.4 && util <= 1.0) capScore = 100;
  else if (util < 0.4) capScore = (util / 0.4) * 100;
  else capScore = Math.max(0, 100 - (util - 1) * 200);

  // Extinction: fewer endangered = healthier
  var extScore = extinction.totalCategories > 0
    ? (1 - (extinction.endangeredCount + extinction.criticalCount * 2) / Math.max(1, extinction.totalCategories)) * 100
    : 100;

  // Evolution pressure: lower = healthier
  var evoScore = 100 - evolution.pressure;

  // Niche balance
  var nicheScore = niches.balance * 100;

  var score = w.bio * bioScore
    + w.defense * defenseScore
    + w.capacity * capScore
    + w.extinction * _clamp(extScore, 0, 100)
    + w.evolution * _clamp(evoScore, 0, 100)
    + w.niche * nicheScore;

  return _clamp(score, 0, 100);
};

/**
 * Classify health score into tier.
 */
ChallengeEcosystemHealthEngine.prototype._classifyTier = function (score) {
  if (score >= 80) return HEALTH_TIERS.THRIVING;
  if (score >= 60) return HEALTH_TIERS.HEALTHY;
  if (score >= 40) return HEALTH_TIERS.STRESSED;
  if (score >= 20) return HEALTH_TIERS.ENDANGERED;
  return HEALTH_TIERS.CRITICAL;
};

// ── Insight Generation ──────────────────────────────────────────────

/**
 * Generate autonomous insights and recommendations.
 */
ChallengeEcosystemHealthEngine.prototype._generateInsights = function (
  bio, predPrey, carrying, extinction, evolution, niches, keystones, score
) {
  var insights = [];

  // Biodiversity insights
  if (bio.evenness < 0.5 && bio.richness > 1) {
    insights.push({
      type: "warning",
      category: "biodiversity",
      message: "Category imbalance detected — \"" + bio.dominantCategory + "\" dominates at " +
        (bio.categoryDistribution[bio.dominantCategory] ? (bio.categoryDistribution[bio.dominantCategory].proportion * 100).toFixed(0) : "?") +
        "%. Diversify challenge types to improve resilience.",
      priority: "high"
    });
  }
  if (bio.richness <= 2) {
    insights.push({
      type: "critical",
      category: "biodiversity",
      message: "Dangerously low category diversity (" + bio.richness + " types). Add new challenge categories to prevent monoculture vulnerability.",
      priority: "critical"
    });
  }

  // Predator-prey insights
  if (predPrey.phase === "predator-dominance") {
    insights.push({
      type: "critical",
      category: "predator-prey",
      message: "Bots are winning — predation rate " + (predPrey.predationRate * 100).toFixed(0) + "%. Urgent: deploy harder challenges or new challenge types.",
      priority: "critical"
    });
  } else if (predPrey.phase === "arms-race") {
    insights.push({
      type: "warning",
      category: "predator-prey",
      message: "Active arms race detected (bot pressure " + (predPrey.botPressure * 100).toFixed(0) + "%). Defense holding at " +
        (predPrey.defenseEffectiveness * 100).toFixed(0) + "% but monitor closely.",
      priority: "high"
    });
  } else if (predPrey.phase === "peaceful") {
    insights.push({
      type: "info",
      category: "predator-prey",
      message: "Low bot activity — ecosystem is peaceful. Good time to add experimental challenge types.",
      priority: "low"
    });
  }

  // Carrying capacity insights
  if (carrying.status === "underpopulated") {
    insights.push({
      type: "info",
      category: "capacity",
      message: "Challenge pool is underpopulated (" + carrying.currentPopulation + "/" + carrying.estimatedCapacity +
        "). Room for " + (carrying.estimatedCapacity - carrying.currentPopulation) + " more challenges.",
      priority: "medium"
    });
  } else if (carrying.status === "overpopulated") {
    insights.push({
      type: "warning",
      category: "capacity",
      message: "Challenge pool exceeds estimated carrying capacity. Consider retiring low-performing challenges.",
      priority: "medium"
    });
  }

  // Extinction insights
  for (var i = 0; i < extinction.categories.length; i++) {
    var er = extinction.categories[i];
    if (er.risk === EXTINCTION_RISK.CRITICAL) {
      insights.push({
        type: "critical",
        category: "extinction",
        message: "Category \"" + er.category + "\" is critically endangered (" + er.activeCount + " active, " +
          (er.avgBotSolveRate * 100).toFixed(0) + "% bot solve rate). Create new challenges immediately.",
        priority: "critical"
      });
    } else if (er.risk === EXTINCTION_RISK.ENDANGERED) {
      insights.push({
        type: "warning",
        category: "extinction",
        message: "Category \"" + er.category + "\" is endangered. Consider adding variants before bots crack remaining " + er.activeCount + " challenges.",
        priority: "high"
      });
    }
  }

  // Evolution pressure insights
  if (evolution.adaptationSpeed === "rapid") {
    insights.push({
      type: "critical",
      category: "evolution",
      message: "Rapid bot evolution detected (pressure " + evolution.pressure.toFixed(0) + "/100). Challenge types are being cracked faster than replaced.",
      priority: "critical"
    });
  } else if (evolution.adaptationSpeed === "fast") {
    insights.push({
      type: "warning",
      category: "evolution",
      message: "Fast bot adaptation detected. Consider rotating challenge strategies proactively.",
      priority: "high"
    });
  }

  // Niche insights
  for (var n = 0; n < niches.bands.length; n++) {
    var band = niches.bands[n];
    if (band.status === NICHE_STATUS.BARREN) {
      insights.push({
        type: "info",
        category: "niche",
        message: "Difficulty niche \"" + band.label + "\" (" + band.rangeMin + "-" + band.rangeMax + ") is empty. Fill this gap to improve coverage.",
        priority: "medium"
      });
    }
  }

  // Keystone insights
  if (keystones.count > 0) {
    var topKs = keystones.keystones[0];
    insights.push({
      type: "warning",
      category: "keystone",
      message: "Challenge \"" + topKs.id + "\" is a keystone — handles " + (topKs.humanShare * 100).toFixed(0) +
        "% of human traffic. Its loss would significantly impact the ecosystem.",
      priority: "high"
    });
  }

  // Sort by priority
  var priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  insights.sort(function (a, b) { return (priorityOrder[a.priority] || 9) - (priorityOrder[b.priority] || 9); });

  return insights;
};

// ── Snapshots ───────────────────────────────────────────────────────

/**
 * Take a point-in-time snapshot of ecosystem state.
 */
ChallengeEcosystemHealthEngine.prototype._takeSnapshot = function (ts) {
  var challenges = this._activeChallenges();
  var bio = this._computeBiodiversity(challenges);
  var pp = this._computePredatorPrey(challenges);

  this._snapshots.push({
    timestamp: ts || _now(),
    activeCount: challenges.length,
    shannonIndex: bio.shannonIndex,
    botPressure: pp.botPressure,
    defenseEffectiveness: pp.defenseEffectiveness,
    totalEvents: this._totalEvents
  });

  if (this._snapshots.length > this._cfg.maxSnapshots) {
    this._snapshots = this._snapshots.slice(-this._cfg.maxSnapshots);
  }

  this._lastSnapshotTs = ts || _now();
};

/**
 * Get historical trend data.
 *
 * @returns {Array} Snapshots array
 */
ChallengeEcosystemHealthEngine.prototype.getHistory = function () {
  return this._snapshots.slice();
};

// ── State Export/Import ─────────────────────────────────────────────

/**
 * Export full state for persistence.
 *
 * @returns {Object} Serializable state
 */
ChallengeEcosystemHealthEngine.prototype.exportState = function () {
  var challenges = {};
  var keys = Object.keys(this._challenges);
  for (var i = 0; i < keys.length; i++) {
    var ch = this._challenges[keys[i]];
    challenges[keys[i]] = {
      id: ch.id,
      category: ch.category,
      difficulty: ch.difficulty,
      tags: ch.tags,
      createdAt: ch.createdAt,
      humanSolves: ch.humanSolves,
      botSolves: ch.botSolves,
      humanAttempts: ch.humanAttempts,
      botAttempts: ch.botAttempts,
      solveTimes: ch.solveTimes,
      lastActivityTs: ch.lastActivityTs,
      retired: ch.retired
    };
  }
  return {
    version: 1,
    challenges: challenges,
    lruOrder: this._lru.toArray(),
    snapshots: this._snapshots,
    lastSnapshotTs: this._lastSnapshotTs,
    totalEvents: this._totalEvents,
    config: this._cfg
  };
};

/**
 * Import state from a previous export.
 *
 * @param {Object} state - Previously exported state
 */
ChallengeEcosystemHealthEngine.prototype.importState = function (state) {
  if (!state || state.version !== 1) throw new Error("Invalid state version");

  this._challenges = Object.create(null);
  this._lru = new LruTracker();

  var keys = Object.keys(state.challenges || {});
  for (var i = 0; i < keys.length; i++) {
    var ch = state.challenges[keys[i]];
    this._challenges[keys[i]] = {
      id: ch.id,
      category: ch.category,
      difficulty: ch.difficulty,
      tags: ch.tags || [],
      createdAt: ch.createdAt || 0,
      humanSolves: ch.humanSolves || 0,
      botSolves: ch.botSolves || 0,
      humanAttempts: ch.humanAttempts || 0,
      botAttempts: ch.botAttempts || 0,
      solveTimes: ch.solveTimes || [],
      lastActivityTs: ch.lastActivityTs || 0,
      retired: !!ch.retired
    };
  }

  if (Array.isArray(state.lruOrder)) {
    this._lru.fromArray(state.lruOrder);
  } else {
    for (var j = 0; j < keys.length; j++) this._lru.push(keys[j]);
  }

  this._snapshots = Array.isArray(state.snapshots) ? state.snapshots : [];
  this._lastSnapshotTs = state.lastSnapshotTs || 0;
  this._totalEvents = state.totalEvents || 0;
};

// ── HTML Dashboard ──────────────────────────────────────────────────

/**
 * Generate an interactive HTML dashboard.
 *
 * @returns {string} Self-contained HTML page
 */
ChallengeEcosystemHealthEngine.prototype.renderDashboard = function () {
  var report = this.analyze();
  var san = _shared.sanitize;

  var html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">';
  html += '<meta name="viewport" content="width=device-width,initial-scale=1">';
  html += '<title>Challenge Ecosystem Health Dashboard</title>';
  html += '<style>';
  html += 'body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:0;padding:20px;background:#0d1117;color:#c9d1d9}';
  html += '.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}';
  html += '.score{font-size:48px;font-weight:700;text-align:center}';
  html += '.tier{font-size:18px;text-align:center;margin-top:4px;text-transform:uppercase;letter-spacing:2px}';
  html += '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}';
  html += 'h1{color:#58a6ff;margin:0 0 20px}h2{color:#58a6ff;margin:0 0 12px;font-size:16px}';
  html += '.bar{height:8px;border-radius:4px;background:#21262d;margin:4px 0}';
  html += '.bar-fill{height:100%;border-radius:4px;transition:width .3s}';
  html += '.tag{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;margin:2px}';
  html += '.critical{color:#f85149;border-color:#f85149}.warning{color:#d29922;border-color:#d29922}';
  html += '.info{color:#58a6ff}.safe{color:#3fb950}';
  html += 'table{width:100%;border-collapse:collapse}th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #21262d}';
  html += 'th{color:#8b949e;font-weight:500;font-size:13px}';
  html += '.insight{padding:8px 12px;margin:6px 0;border-left:3px solid;border-radius:0 4px 4px 0;background:#21262d;font-size:14px}';
  html += '</style></head><body>';

  // Header
  html += '<h1>\uD83C\uDF3F Challenge Ecosystem Health</h1>';

  // Score card
  var scoreColor = report.healthScore >= 80 ? '#3fb950' : report.healthScore >= 60 ? '#58a6ff' : report.healthScore >= 40 ? '#d29922' : '#f85149';
  html += '<div class="card"><div class="score" style="color:' + scoreColor + '">' + report.healthScore.toFixed(1) + '</div>';
  html += '<div class="tier" style="color:' + scoreColor + '">' + san(report.tier) + '</div>';
  html += '<div style="text-align:center;margin-top:8px;color:#8b949e">' + report.totalActive + ' active / ' + report.totalRetired + ' retired / ' + report.totalEvents + ' events</div></div>';

  // Grid
  html += '<div class="grid">';

  // Biodiversity
  html += '<div class="card"><h2>\uD83E\uDDEC Biodiversity</h2>';
  html += '<p>Shannon Index: <strong>' + report.biodiversity.shannonIndex + '</strong></p>';
  html += '<p>Evenness: <strong>' + report.biodiversity.evenness + '</strong></p>';
  html += '<p>Categories: <strong>' + report.biodiversity.richness + '</strong></p>';
  if (report.biodiversity.dominantCategory) {
    html += '<p>Dominant: <strong>' + san(report.biodiversity.dominantCategory) + '</strong></p>';
  }
  html += '</div>';

  // Predator-Prey
  html += '<div class="card"><h2>\uD83D\uDC3A Predator-Prey</h2>';
  html += '<p>Phase: <strong>' + san(report.predatorPrey.phase) + '</strong></p>';
  html += '<p>Bot Pressure: <strong>' + (report.predatorPrey.botPressure * 100).toFixed(1) + '%</strong></p>';
  html += '<p>Defense: <strong>' + (report.predatorPrey.defenseEffectiveness * 100).toFixed(1) + '%</strong></p>';
  html += '<p>Equilibrium: <strong>' + (report.predatorPrey.equilibrium ? 'Yes' : 'No') + '</strong></p>';
  html += '</div>';

  // Carrying Capacity
  html += '<div class="card"><h2>\uD83C\uDFD7\uFE0F Carrying Capacity</h2>';
  html += '<p>Population: <strong>' + report.carryingCapacity.currentPopulation + '/' + report.carryingCapacity.estimatedCapacity + '</strong></p>';
  html += '<p>Utilization: <strong>' + (report.carryingCapacity.utilizationRatio * 100).toFixed(1) + '%</strong></p>';
  html += '<p>Status: <strong>' + san(report.carryingCapacity.status) + '</strong></p>';
  var utilPct = Math.min(100, report.carryingCapacity.utilizationRatio * 100);
  html += '<div class="bar"><div class="bar-fill" style="width:' + utilPct + '%;background:' + (utilPct > 90 ? '#f85149' : utilPct > 70 ? '#d29922' : '#3fb950') + '"></div></div>';
  html += '</div>';

  // Evolution Pressure
  html += '<div class="card"><h2>\u26A1 Evolution Pressure</h2>';
  html += '<p>Pressure: <strong>' + report.evolutionPressure.pressure.toFixed(1) + '/100</strong></p>';
  html += '<p>Adaptation: <strong>' + san(report.evolutionPressure.adaptationSpeed) + '</strong></p>';
  html += '<p>Bot Learning Rate: <strong>' + (report.evolutionPressure.botLearningRate * 100).toFixed(1) + '%</strong></p>';
  html += '</div>';

  html += '</div>'; // end grid

  // Niche Analysis
  html += '<div class="card"><h2>\uD83C\uDF0D Niche Analysis (Balance: ' + report.niches.balance + ')</h2>';
  html += '<table><tr><th>Band</th><th>Range</th><th>Count</th><th>Status</th><th>Bot Resist.</th><th>Human Solve</th></tr>';
  for (var i = 0; i < report.niches.bands.length; i++) {
    var band = report.niches.bands[i];
    var statusColor = band.status === 'BALANCED' ? '#3fb950' : band.status === 'BARREN' ? '#f85149' : '#d29922';
    html += '<tr><td>' + san(band.label) + '</td><td>' + band.rangeMin + '-' + band.rangeMax + '</td>';
    html += '<td>' + band.count + '</td><td style="color:' + statusColor + '">' + san(band.status) + '</td>';
    html += '<td>' + (band.avgBotResistance * 100).toFixed(0) + '%</td>';
    html += '<td>' + (band.avgHumanSolveRate * 100).toFixed(0) + '%</td></tr>';
  }
  html += '</table></div>';

  // Extinction Risk
  html += '<div class="card"><h2>\u2620\uFE0F Extinction Risk</h2>';
  html += '<table><tr><th>Category</th><th>Risk</th><th>Active</th><th>Retired</th><th>Bot Solve Rate</th></tr>';
  for (var j = 0; j < report.extinctionRisk.categories.length; j++) {
    var er = report.extinctionRisk.categories[j];
    var riskColor = er.risk === 'SAFE' ? '#3fb950' : er.risk === 'CRITICAL' ? '#f85149' : er.risk === 'ENDANGERED' ? '#d29922' : '#8b949e';
    html += '<tr><td>' + san(er.category) + '</td><td style="color:' + riskColor + '">' + san(er.risk) + '</td>';
    html += '<td>' + er.activeCount + '</td><td>' + er.retiredCount + '</td>';
    html += '<td>' + (er.avgBotSolveRate * 100).toFixed(0) + '%</td></tr>';
  }
  html += '</table></div>';

  // Insights
  if (report.insights.length > 0) {
    html += '<div class="card"><h2>\uD83D\uDCA1 Autonomous Insights</h2>';
    for (var k = 0; k < report.insights.length; k++) {
      var ins = report.insights[k];
      var insColor = ins.type === 'critical' ? '#f85149' : ins.type === 'warning' ? '#d29922' : '#58a6ff';
      html += '<div class="insight" style="border-color:' + insColor + '">';
      html += '<span class="tag" style="border:1px solid ' + insColor + ';color:' + insColor + '">' + san(ins.priority) + '</span> ';
      html += san(ins.message) + '</div>';
    }
    html += '</div>';
  }

  html += '<div style="text-align:center;color:#484f58;margin-top:20px;font-size:12px">Generated ' + new Date().toISOString() + '</div>';
  html += '</body></html>';
  return html;
};

// ── Helpers ─────────────────────────────────────────────────────────

ChallengeEcosystemHealthEngine.prototype._activeChallenges = function () {
  var result = [];
  var keys = Object.keys(this._challenges);
  for (var i = 0; i < keys.length; i++) {
    if (!this._challenges[keys[i]].retired) result.push(this._challenges[keys[i]]);
  }
  return result;
};

ChallengeEcosystemHealthEngine.prototype._allChallengeList = function () {
  var result = [];
  var keys = Object.keys(this._challenges);
  for (var i = 0; i < keys.length; i++) result.push(this._challenges[keys[i]]);
  return result;
};

function _bandLabel(index, total) {
  var labels = ["Trivial", "Easy", "Medium", "Hard", "Expert"];
  if (total <= labels.length) return labels[index] || "Band " + index;
  return "Band " + (index + 1);
}

// ── Exports ─────────────────────────────────────────────────────────

ChallengeEcosystemHealthEngine.HEALTH_TIERS = HEALTH_TIERS;
ChallengeEcosystemHealthEngine.EXTINCTION_RISK = EXTINCTION_RISK;
ChallengeEcosystemHealthEngine.NICHE_STATUS = NICHE_STATUS;

module.exports = ChallengeEcosystemHealthEngine;
