/**
 * ChallengeGeneticsLab — Autonomous challenge evolution via genetic algorithms.
 *
 * Breeds more effective CAPTCHA challenges by crossing over traits of
 * successful ones, mutating parameters, and selecting for fitness
 * (high human-pass rate + low bot-pass rate).  Challenges evolve over
 * generations, converging toward the sweet spot that blocks bots while
 * remaining solvable by humans.
 *
 * Key capabilities:
 *   - Genome-based challenge representation (8 numeric traits)
 *   - Tournament selection with configurable pool size
 *   - Uniform crossover + Gaussian mutation, clamped to [0,1]
 *   - Elitism — top K survive unchanged each generation
 *   - Fitness scoring: bot-fail rate, human-pass rate, solve-time proximity, diversity
 *   - Lineage tracking — trace ancestry across generations
 *   - Diversity monitoring with extinction-risk alerts
 *   - Full state export / import for persistence
 *   - Auto-evolve mode when enough outcome data accumulates
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/challenge-genetics-lab
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _clamp = _shared._clamp;
var _mean = _shared._mean;
var _stddev = _shared._stddev;

var _crypto = require("./crypto-utils");
var secureRandom = _crypto.secureRandom;
var secureRandomInt = _crypto.secureRandomInt;

// ── Trait Names ─────────────────────────────────────────────────────

var TRAIT_NAMES = [
  "complexity",
  "distraction",
  "timeWindow",
  "ambiguity",
  "frameCount",
  "colorEntropy",
  "motionIntensity",
  "textObfuscation"
];

// ── Defaults ────────────────────────────────────────────────────────

var DEFAULTS = {
  populationSize: 50,
  eliteCount: 5,
  tournamentSize: 3,
  mutationRate: 0.15,
  mutationStrength: 0.1,
  crossoverRate: 0.7,
  minTrials: 10,
  targetHumanPassRate: 0.82,
  targetSolveTimeMs: 8000,
  botFailWeight: 0.4,
  humanPassWeight: 0.3,
  solveTimeWeight: 0.2,
  diversityWeight: 0.1,
  maxGenerations: 1000,
  maxLineage: 50,
  autoEvolve: false,
  autoEvolveThreshold: 0.8,
  maxOutcomesPerChallenge: 5000
};

// ── Helpers ─────────────────────────────────────────────────────────

var _optNum = _shared._optNum;
var _optBool = _shared._optBool;

/** Generate a short hex id. */
function _genId() {
  var chars = "0123456789abcdef";
  var id = "";
  for (var i = 0; i < 12; i++) {
    id += chars[secureRandomInt(16)];
  }
  return id;
}

/** Box-Muller transform for gaussian random (mean=0, std=1). */
function _gaussianRandom() {
  var u1 = secureRandom();
  var u2 = secureRandom();
  // Avoid log(0)
  if (u1 < 1e-10) u1 = 1e-10;
  return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
}

/** Euclidean distance between two genomes. */
function _genomeDistance(a, b) {
  var sum = 0;
  for (var i = 0; i < TRAIT_NAMES.length; i++) {
    var d = (a[TRAIT_NAMES[i]] || 0) - (b[TRAIT_NAMES[i]] || 0);
    sum += d * d;
  }
  return Math.sqrt(sum);
}

/** Create a random genome with all traits in [0,1]. */
function _randomGenome() {
  var g = {};
  for (var i = 0; i < TRAIT_NAMES.length; i++) {
    g[TRAIT_NAMES[i]] = secureRandom();
  }
  return g;
}

/** Clone a genome. */
function _cloneGenome(g) {
  var c = {};
  for (var i = 0; i < TRAIT_NAMES.length; i++) {
    c[TRAIT_NAMES[i]] = g[TRAIT_NAMES[i]];
  }
  return c;
}

// ── Constructor ─────────────────────────────────────────────────────

/**
 * Create a ChallengeGeneticsLab instance.
 *
 * @constructor
 * @param {Object} [options] Configuration overrides
 */
function ChallengeGeneticsLab(options) {
  var o = options || {};

  this.populationSize = _optNum(o.populationSize, DEFAULTS.populationSize);
  this.eliteCount = _optNum(o.eliteCount, DEFAULTS.eliteCount);
  this.tournamentSize = _optNum(o.tournamentSize, DEFAULTS.tournamentSize);
  this.mutationRate = _optNum(o.mutationRate, DEFAULTS.mutationRate);
  this.mutationStrength = _optNum(o.mutationStrength, DEFAULTS.mutationStrength);
  this.crossoverRate = _optNum(o.crossoverRate, DEFAULTS.crossoverRate);
  this.minTrials = _optNum(o.minTrials, DEFAULTS.minTrials);
  this.targetHumanPassRate = _optNum(o.targetHumanPassRate, DEFAULTS.targetHumanPassRate);
  this.targetSolveTimeMs = _optNum(o.targetSolveTimeMs, DEFAULTS.targetSolveTimeMs);
  this.botFailWeight = _optNum(o.botFailWeight, DEFAULTS.botFailWeight);
  this.humanPassWeight = _optNum(o.humanPassWeight, DEFAULTS.humanPassWeight);
  this.solveTimeWeight = _optNum(o.solveTimeWeight, DEFAULTS.solveTimeWeight);
  this.diversityWeight = _optNum(o.diversityWeight, DEFAULTS.diversityWeight);
  this.maxGenerations = _optNum(o.maxGenerations, DEFAULTS.maxGenerations);
  this.maxLineage = _optNum(o.maxLineage, DEFAULTS.maxLineage);
  this.autoEvolve = _optBool(o.autoEvolve, DEFAULTS.autoEvolve);
  this.autoEvolveThreshold = _optNum(o.autoEvolveThreshold, DEFAULTS.autoEvolveThreshold);
  this.maxOutcomesPerChallenge = _optNum(o.maxOutcomesPerChallenge, DEFAULTS.maxOutcomesPerChallenge);

  // Ensure eliteCount doesn't exceed population
  if (this.eliteCount >= this.populationSize) {
    this.eliteCount = Math.max(1, Math.floor(this.populationSize * 0.1));
  }

  /** @type {Object.<string, Object>} challengeId → challenge record */
  this._challenges = {};

  /** @type {Object.<string, Object>} challengeId → outcome accumulator */
  this._outcomes = {};

  /** @type {string[]} current living population ids */
  this._population = [];

  /** @type {number} current generation counter */
  this._generation = 0;

  /** @type {Array.<Object>} per-generation summary stats */
  this._generationHistory = [];
}

// ── Population Seeding ──────────────────────────────────────────────

/**
 * Initialize the population with random genomes.
 *
 * @param {number} [count] Number of challenges to create (defaults to populationSize)
 * @returns {Array.<Object>} Created challenge records
 */
ChallengeGeneticsLab.prototype.seedPopulation = function seedPopulation(count) {
  var n = _optNum(count, this.populationSize);
  var created = [];
  for (var i = 0; i < n; i++) {
    var id = _genId();
    var challenge = {
      id: id,
      genome: _randomGenome(),
      generation: 0,
      parentIds: [],
      createdAt: _now()
    };
    this._challenges[id] = challenge;
    this._outcomes[id] = { human: [], bot: [] };
    this._population.push(id);
    created.push(challenge);
  }
  return created;
};

// ── Outcome Recording ───────────────────────────────────────────────

/**
 * Record a trial outcome for a challenge.
 *
 * @param {string} challengeId
 * @param {Object} outcome
 * @param {boolean} outcome.isHuman Whether the solver is human
 * @param {boolean} outcome.passed Whether the solver passed
 * @param {number}  outcome.solveTimeMs Time to solve in ms
 * @param {string}  [outcome.botSignature] Bot fingerprint if detected
 * @returns {boolean} True if recorded successfully
 */
ChallengeGeneticsLab.prototype.recordOutcome = function recordOutcome(challengeId, outcome) {
  if (!this._challenges[challengeId]) return false;
  if (!outcome || typeof outcome.isHuman !== "boolean" || typeof outcome.passed !== "boolean") {
    return false;
  }

  var bucket = outcome.isHuman ? "human" : "bot";
  var store = this._outcomes[challengeId];
  if (!store) {
    store = { human: [], bot: [] };
    this._outcomes[challengeId] = store;
  }

  var entry = {
    passed: outcome.passed,
    solveTimeMs: _optNum(outcome.solveTimeMs, 0),
    ts: _now()
  };
  if (outcome.botSignature) {
    entry.botSignature = String(outcome.botSignature);
  }

  store[bucket].push(entry);

  // Cap stored outcomes
  if (store[bucket].length > this.maxOutcomesPerChallenge) {
    store[bucket] = store[bucket].slice(-this.maxOutcomesPerChallenge);
  }

  // Auto-evolve check
  if (this.autoEvolve) {
    this._checkAutoEvolve();
  }

  return true;
};

// ── Fitness Computation ─────────────────────────────────────────────

/**
 * Compute fitness score for a single challenge.
 *
 * @param {string} challengeId
 * @returns {Object|null} Fitness report or null if insufficient data
 */
ChallengeGeneticsLab.prototype.computeFitness = function computeFitness(challengeId) {
  var challenge = this._challenges[challengeId];
  if (!challenge) return null;

  var store = this._outcomes[challengeId];
  if (!store) return null;

  var totalTrials = store.human.length + store.bot.length;
  if (totalTrials < this.minTrials) return null;

  // Human pass rate
  var humanTotal = store.human.length;
  var humanPassed = 0;
  var humanTimes = [];
  for (var i = 0; i < store.human.length; i++) {
    if (store.human[i].passed) humanPassed++;
    if (store.human[i].solveTimeMs > 0) humanTimes.push(store.human[i].solveTimeMs);
  }
  var humanPassRate = humanTotal > 0 ? humanPassed / humanTotal : 0;

  // Bot fail rate
  var botTotal = store.bot.length;
  var botFailed = 0;
  for (var j = 0; j < store.bot.length; j++) {
    if (!store.bot[j].passed) botFailed++;
  }
  var botFailRate = botTotal > 0 ? botFailed / botTotal : 1; // No bot data = assume effective

  // Average solve time
  var avgSolveTimeMs = humanTimes.length > 0 ? _mean(humanTimes) : this.targetSolveTimeMs;

  // Component scores (each 0-1)
  // Bot fail: linear, higher is better
  var botFailScore = _clamp(botFailRate, 0, 1);

  // Human pass: gaussian around target, penalize too low or too high
  var humanDelta = Math.abs(humanPassRate - this.targetHumanPassRate);
  var humanPassScore = Math.exp(-humanDelta * humanDelta / 0.08);

  // Solve time: gaussian around target
  var timeDelta = (avgSolveTimeMs - this.targetSolveTimeMs) / this.targetSolveTimeMs;
  var solveTimeScore = Math.exp(-timeDelta * timeDelta / 0.5);

  // Diversity: distance from population centroid
  var diversityScore = this._diversityContribution(challengeId);

  // Weighted sum
  var fitness = (
    this.botFailWeight * botFailScore +
    this.humanPassWeight * humanPassScore +
    this.solveTimeWeight * solveTimeScore +
    this.diversityWeight * diversityScore
  );
  fitness = _clamp(fitness, 0, 1);

  return {
    fitness: fitness,
    humanPassRate: humanPassRate,
    botFailRate: botFailRate,
    avgSolveTimeMs: avgSolveTimeMs,
    trialCount: totalTrials,
    components: {
      botFail: botFailScore,
      humanPass: humanPassScore,
      solveTime: solveTimeScore,
      diversity: diversityScore
    }
  };
};

/**
 * Diversity contribution: how far this challenge's genome is from the centroid.
 * @private
 */
ChallengeGeneticsLab.prototype._diversityContribution = function (challengeId) {
  if (this._population.length < 2) return 0.5;

  // Compute centroid
  var centroid = {};
  for (var t = 0; t < TRAIT_NAMES.length; t++) {
    centroid[TRAIT_NAMES[t]] = 0;
  }
  var count = 0;
  for (var i = 0; i < this._population.length; i++) {
    var ch = this._challenges[this._population[i]];
    if (ch) {
      for (var t2 = 0; t2 < TRAIT_NAMES.length; t2++) {
        centroid[TRAIT_NAMES[t2]] += ch.genome[TRAIT_NAMES[t2]] || 0;
      }
      count++;
    }
  }
  if (count > 0) {
    for (var t3 = 0; t3 < TRAIT_NAMES.length; t3++) {
      centroid[TRAIT_NAMES[t3]] /= count;
    }
  }

  var challenge = this._challenges[challengeId];
  if (!challenge) return 0;

  // Max possible distance = sqrt(8) ≈ 2.83 (all traits at opposite corners)
  var dist = _genomeDistance(challenge.genome, centroid);
  return _clamp(dist / 2.83, 0, 1);
};

// ── Evolution ───────────────────────────────────────────────────────

/**
 * Run one generation of evolution.
 *
 * @returns {Object} Generation report
 */
ChallengeGeneticsLab.prototype.evolve = function evolve() {
  if (this._generation >= this.maxGenerations) {
    return { error: "max_generations_reached", generation: this._generation };
  }

  this._generation++;

  // Compute fitness for all with enough trials
  var scored = [];
  var unscored = [];
  for (var i = 0; i < this._population.length; i++) {
    var id = this._population[i];
    var fit = this.computeFitness(id);
    if (fit) {
      scored.push({ id: id, fitness: fit.fitness, report: fit });
    } else {
      unscored.push(id);
    }
  }

  // Sort by fitness descending
  scored.sort(function (a, b) { return b.fitness - a.fitness; });

  // If not enough scored challenges, just keep population and add random ones
  if (scored.length < 3) {
    // Only add new challenges if population is below target size
    var deficit = this.populationSize - this._population.length;
    var newOnes = deficit > 0 ? this.seedPopulation(deficit) : [];
    var stats = {
      generation: this._generation,
      populationSize: this._population.length,
      avgFitness: 0,
      bestFitness: 0,
      worstFitness: 0,
      eliteIds: [],
      newbornCount: newOnes.length,
      extinctCount: 0,
      note: "insufficient_data"
    };
    this._generationHistory.push({
      generation: this._generation,
      avgFitness: 0,
      bestFitness: 0,
      diversity: this.getDiversityScore(),
      populationSize: this._population.length,
      timestamp: _now()
    });
    return stats;
  }

  // Select elites
  var eliteCount = Math.min(this.eliteCount, scored.length);
  var eliteIds = [];
  for (var e = 0; e < eliteCount; e++) {
    eliteIds.push(scored[e].id);
  }

  // Build new population
  var newPopulation = [];
  var newChallenges = [];

  // Preserve elites
  for (var ei = 0; ei < eliteIds.length; ei++) {
    newPopulation.push(eliteIds[ei]);
  }

  // Fill remaining slots with offspring
  var targetSize = this.populationSize;
  var extinctCount = 0;

  while (newPopulation.length < targetSize) {
    // Tournament selection for two parents
    var parentA = this._tournamentSelect(scored);
    var parentB = this._tournamentSelect(scored);

    // Avoid self-crossover when possible
    var attempts = 0;
    while (parentB.id === parentA.id && attempts < 5) {
      parentB = this._tournamentSelect(scored);
      attempts++;
    }

    var childGenome;
    var parentIds;

    // Crossover or clone
    if (secureRandom() < this.crossoverRate && parentA.id !== parentB.id) {
      childGenome = this._crossover(
        this._challenges[parentA.id].genome,
        this._challenges[parentB.id].genome
      );
      parentIds = [parentA.id, parentB.id];
    } else {
      childGenome = _cloneGenome(this._challenges[parentA.id].genome);
      parentIds = [parentA.id];
    }

    // Mutation
    childGenome = this._mutate(childGenome);

    var childId = _genId();
    var child = {
      id: childId,
      genome: childGenome,
      generation: this._generation,
      parentIds: parentIds,
      createdAt: _now()
    };

    this._challenges[childId] = child;
    this._outcomes[childId] = { human: [], bot: [] };
    newPopulation.push(childId);
    newChallenges.push(child);
  }

  // Count extinct (those in old population but not new) and clean up
  var newSet = {};
  for (var ns = 0; ns < newPopulation.length; ns++) {
    newSet[newPopulation[ns]] = true;
  }
  for (var oi = 0; oi < this._population.length; oi++) {
    var oldId = this._population[oi];
    if (!newSet[oldId]) {
      extinctCount++;
      // Free memory from extinct challenges no longer in the population
      // or referenced by any surviving challenge's lineage (parentIds).
      // Keep outcomes/challenges only if they appear in a living lineage.
      delete this._challenges[oldId];
      delete this._outcomes[oldId];
    }
  }

  this._population = newPopulation;

  // Compute stats
  var fitnessVals = [];
  for (var si = 0; si < scored.length; si++) {
    fitnessVals.push(scored[si].fitness);
  }
  var avgFit = fitnessVals.length > 0 ? _mean(fitnessVals) : 0;
  var bestFit = fitnessVals.length > 0 ? fitnessVals[0] : 0;
  var worstFit = fitnessVals.length > 0 ? fitnessVals[fitnessVals.length - 1] : 0;

  var genStats = {
    generation: this._generation,
    avgFitness: avgFit,
    bestFitness: bestFit,
    diversity: this.getDiversityScore(),
    populationSize: this._population.length,
    timestamp: _now()
  };
  this._generationHistory.push(genStats);

  return {
    generation: this._generation,
    populationSize: this._population.length,
    avgFitness: avgFit,
    bestFitness: bestFit,
    worstFitness: worstFit,
    eliteIds: eliteIds,
    newbornCount: newChallenges.length,
    extinctCount: extinctCount
  };
};

/**
 * Tournament selection: pick tournamentSize random scored entries, return the fittest.
 * @private
 */
ChallengeGeneticsLab.prototype._tournamentSelect = function (scored) {
  var best = scored[secureRandomInt(scored.length)];
  for (var i = 1; i < this.tournamentSize; i++) {
    var candidate = scored[secureRandomInt(scored.length)];
    if (candidate.fitness > best.fitness) {
      best = candidate;
    }
  }
  return best;
};

/**
 * Uniform crossover: each trait randomly from parent A or B.
 * @private
 */
ChallengeGeneticsLab.prototype._crossover = function (genomeA, genomeB) {
  var child = {};
  for (var i = 0; i < TRAIT_NAMES.length; i++) {
    var trait = TRAIT_NAMES[i];
    child[trait] = secureRandom() < 0.5 ? genomeA[trait] : genomeB[trait];
  }
  return child;
};

/**
 * Gaussian mutation: perturb random traits, clamped to [0,1].
 * @private
 */
ChallengeGeneticsLab.prototype._mutate = function (genome) {
  var mutated = _cloneGenome(genome);
  for (var i = 0; i < TRAIT_NAMES.length; i++) {
    if (secureRandom() < this.mutationRate) {
      var noise = _gaussianRandom() * this.mutationStrength;
      mutated[TRAIT_NAMES[i]] = _clamp(mutated[TRAIT_NAMES[i]] + noise, 0, 1);
    }
  }
  return mutated;
};

/**
 * Check if auto-evolve conditions are met and trigger evolution.
 * @private
 */
ChallengeGeneticsLab.prototype._checkAutoEvolve = function () {
  if (this._population.length === 0) return;
  var ready = 0;
  for (var i = 0; i < this._population.length; i++) {
    var store = this._outcomes[this._population[i]];
    if (store && (store.human.length + store.bot.length) >= this.minTrials) {
      ready++;
    }
  }
  var fraction = ready / this._population.length;
  if (fraction >= this.autoEvolveThreshold) {
    this.evolve();
  }
};

// ── Query Methods ───────────────────────────────────────────────────

/**
 * Get a single challenge with its genome, stats, and fitness.
 *
 * @param {string} challengeId
 * @returns {Object|null}
 */
ChallengeGeneticsLab.prototype.getChallenge = function getChallenge(challengeId) {
  var ch = this._challenges[challengeId];
  if (!ch) return null;

  var store = this._outcomes[challengeId] || { human: [], bot: [] };
  var fit = this.computeFitness(challengeId);

  return {
    id: ch.id,
    genome: _cloneGenome(ch.genome),
    generation: ch.generation,
    parentIds: ch.parentIds.slice(),
    createdAt: ch.createdAt,
    trialCount: store.human.length + store.bot.length,
    fitness: fit
  };
};

/**
 * Get all current population sorted by fitness (desc).
 *
 * @returns {Array.<Object>}
 */
ChallengeGeneticsLab.prototype.getPopulation = function getPopulation() {
  var results = [];
  for (var i = 0; i < this._population.length; i++) {
    var ch = this.getChallenge(this._population[i]);
    if (ch) results.push(ch);
  }

  results.sort(function (a, b) {
    var fa = a.fitness ? a.fitness.fitness : -1;
    var fb = b.fitness ? b.fitness.fitness : -1;
    return fb - fa;
  });

  return results;
};

/**
 * Trace lineage (ancestry) of a challenge back through generations.
 *
 * @param {string} challengeId
 * @returns {Array.<Object>} Ancestor chain, newest first
 */
ChallengeGeneticsLab.prototype.getLineage = function getLineage(challengeId) {
  var chain = [];
  var visited = {};
  var queue = [challengeId];
  var depth = 0;

  while (queue.length > 0 && depth < this.maxLineage) {
    var nextQueue = [];
    for (var i = 0; i < queue.length; i++) {
      var id = queue[i];
      if (visited[id]) continue;
      visited[id] = true;

      var ch = this._challenges[id];
      if (!ch) continue;

      chain.push({
        id: ch.id,
        generation: ch.generation,
        genome: _cloneGenome(ch.genome),
        parentIds: ch.parentIds.slice(),
        depth: depth
      });

      for (var p = 0; p < ch.parentIds.length; p++) {
        if (!visited[ch.parentIds[p]]) {
          nextQueue.push(ch.parentIds[p]);
        }
      }
    }
    queue = nextQueue;
    depth++;
  }

  return chain;
};

/**
 * Get per-generation summary statistics.
 *
 * @returns {Array.<Object>}
 */
ChallengeGeneticsLab.prototype.getGenerationStats = function getGenerationStats() {
  return this._generationHistory.slice();
};

/**
 * Get distribution statistics for a specific trait across the current population.
 *
 * @param {string} traitName
 * @returns {Object|null}
 */
ChallengeGeneticsLab.prototype.getTraitDistribution = function getTraitDistribution(traitName) {
  if (TRAIT_NAMES.indexOf(traitName) === -1) return null;

  var vals = [];
  for (var i = 0; i < this._population.length; i++) {
    var ch = this._challenges[this._population[i]];
    if (ch && ch.genome[traitName] != null) {
      vals.push(ch.genome[traitName]);
    }
  }

  if (vals.length === 0) return null;

  vals.sort(function (a, b) { return a - b; });

  var q1Idx = Math.floor(vals.length * 0.25);
  var q2Idx = Math.floor(vals.length * 0.5);
  var q3Idx = Math.floor(vals.length * 0.75);

  return {
    trait: traitName,
    count: vals.length,
    min: vals[0],
    max: vals[vals.length - 1],
    mean: _mean(vals),
    stddev: vals.length > 1 ? _stddev(vals) : 0,
    quartiles: {
      q1: vals[q1Idx],
      q2: vals[q2Idx],
      q3: vals[q3Idx]
    }
  };
};

// ── Diversity & Extinction ──────────────────────────────────────────

/**
 * Measure genetic diversity as average pairwise Euclidean distance, normalized to [0,1].
 *
 * @returns {number}
 */
ChallengeGeneticsLab.prototype.getDiversityScore = function getDiversityScore() {
  if (this._population.length < 2) return 0;

  // Sample-based for large populations (avoid O(n²) for huge pops)
  var maxPairs = 500;
  var totalDist = 0;
  var pairCount = 0;
  var n = this._population.length;

  if (n * (n - 1) / 2 <= maxPairs) {
    // Exhaustive for small populations
    for (var i = 0; i < n; i++) {
      var gi = this._challenges[this._population[i]];
      if (!gi) continue;
      for (var j = i + 1; j < n; j++) {
        var gj = this._challenges[this._population[j]];
        if (!gj) continue;
        totalDist += _genomeDistance(gi.genome, gj.genome);
        pairCount++;
      }
    }
  } else {
    // Sampling
    for (var s = 0; s < maxPairs; s++) {
      var ai = secureRandomInt(n);
      var bi = secureRandomInt(n);
      if (ai === bi) continue;
      var ga = this._challenges[this._population[ai]];
      var gb = this._challenges[this._population[bi]];
      if (!ga || !gb) continue;
      totalDist += _genomeDistance(ga.genome, gb.genome);
      pairCount++;
    }
  }

  if (pairCount === 0) return 0;

  var avgDist = totalDist / pairCount;
  // Max possible distance = sqrt(8) ≈ 2.83
  return _clamp(avgDist / 2.83, 0, 1);
};

/**
 * Detect extinction risk (dangerously low diversity / convergence).
 *
 * @returns {Object} { risk, diversity, recommendation }
 */
ChallengeGeneticsLab.prototype.getExtinctionRisk = function getExtinctionRisk() {
  var diversity = this.getDiversityScore();
  var risk;
  var recommendation;

  if (diversity < 0.05) {
    risk = "critical";
    recommendation = "Population has converged almost completely. Inject diverse mutants immediately via injectMutant() or re-seed a portion of the population.";
  } else if (diversity < 0.15) {
    risk = "high";
    recommendation = "Genetic diversity is dangerously low. Consider increasing mutationRate or mutationStrength, or injecting fresh genomes.";
  } else if (diversity < 0.30) {
    risk = "medium";
    recommendation = "Diversity is declining. Monitor closely; consider occasional mutant injection to maintain exploration.";
  } else {
    risk = "low";
    recommendation = "Healthy genetic diversity. Population is exploring the solution space well.";
  }

  return {
    risk: risk,
    diversity: diversity,
    populationSize: this._population.length,
    generation: this._generation,
    recommendation: recommendation
  };
};

/**
 * Manually inject a challenge with a specific genome (for diversity rescue).
 *
 * @param {Object} [genome] Genome to inject (random if omitted)
 * @returns {Object} The created challenge
 */
ChallengeGeneticsLab.prototype.injectMutant = function injectMutant(genome) {
  var g = genome ? _cloneGenome(genome) : _randomGenome();

  // Ensure all traits present and clamped
  for (var i = 0; i < TRAIT_NAMES.length; i++) {
    if (typeof g[TRAIT_NAMES[i]] !== "number") {
      g[TRAIT_NAMES[i]] = secureRandom();
    }
    g[TRAIT_NAMES[i]] = _clamp(g[TRAIT_NAMES[i]], 0, 1);
  }

  var id = _genId();
  var challenge = {
    id: id,
    genome: g,
    generation: this._generation,
    parentIds: [],
    createdAt: _now()
  };

  this._challenges[id] = challenge;
  this._outcomes[id] = { human: [], bot: [] };
  this._population.push(id);

  return challenge;
};

// ── Serialization ───────────────────────────────────────────────────

/**
 * Export full state for persistence.
 *
 * @returns {Object}
 */
ChallengeGeneticsLab.prototype.exportState = function exportState() {
  return {
    version: 1,
    generation: this._generation,
    population: this._population.slice(),
    challenges: JSON.parse(JSON.stringify(this._challenges)),
    outcomes: JSON.parse(JSON.stringify(this._outcomes)),
    generationHistory: JSON.parse(JSON.stringify(this._generationHistory)),
    config: {
      populationSize: this.populationSize,
      eliteCount: this.eliteCount,
      tournamentSize: this.tournamentSize,
      mutationRate: this.mutationRate,
      mutationStrength: this.mutationStrength,
      crossoverRate: this.crossoverRate,
      minTrials: this.minTrials,
      targetHumanPassRate: this.targetHumanPassRate,
      targetSolveTimeMs: this.targetSolveTimeMs,
      botFailWeight: this.botFailWeight,
      humanPassWeight: this.humanPassWeight,
      solveTimeWeight: this.solveTimeWeight,
      diversityWeight: this.diversityWeight,
      maxGenerations: this.maxGenerations,
      maxLineage: this.maxLineage,
      autoEvolve: this.autoEvolve,
      autoEvolveThreshold: this.autoEvolveThreshold
    }
  };
};

/**
 * Import previously exported state.
 *
 * @param {Object} state
 * @returns {boolean} True if import succeeded
 */
ChallengeGeneticsLab.prototype.importState = function importState(state) {
  if (!state || state.version !== 1) return false;

  this._generation = typeof state.generation === "number" ? state.generation : 0;
  this._population = Array.isArray(state.population) ? state.population.slice() : [];
  this._challenges = state.challenges ? JSON.parse(JSON.stringify(state.challenges)) : {};
  this._outcomes = state.outcomes ? JSON.parse(JSON.stringify(state.outcomes)) : {};
  this._generationHistory = Array.isArray(state.generationHistory)
    ? JSON.parse(JSON.stringify(state.generationHistory))
    : [];

  return true;
};

// ── TRAIT_NAMES export ──────────────────────────────────────────────

/** Expose trait names for external consumers. */
ChallengeGeneticsLab.TRAIT_NAMES = TRAIT_NAMES;

// ── Module Export ───────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    ChallengeGeneticsLab: ChallengeGeneticsLab
  };
}
