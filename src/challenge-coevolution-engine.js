/**
 * ChallengeCoevolutionEngine — Autonomous Red Queen arms race tracker.
 *
 * Models the evolutionary arms race between CAPTCHA challenges and bot
 * attackers.  Based on the Red Queen hypothesis — both sides must
 * continuously adapt just to maintain their current position.
 *
 * Key capabilities:
 *   - Adaptation velocity tracking (bot vs challenge evolution speed)
 *   - Red Queen race detection & classification (5 states)
 *   - Defense obsolescence prediction via linear regression
 *   - Evolutionary fitness scoring per challenge type
 *   - Mutation pressure analysis (bot strategy diversity & rate)
 *   - Composite coevolution health scoring 0-100 (5 tiers)
 *   - Autonomous insight generation with actionable recommendations
 *   - Full state export/import with prototype-pollution protection
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/challenge-coevolution-engine
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

/** Arms race states (escalation order) */
var RACE_STATES = ["DORMANT", "WARMING", "ACTIVE", "ESCALATING", "CRITICAL"];

/** Coevolution health tiers */
var HEALTH_TIERS = ["DOMINANT", "COMPETITIVE", "CONTESTED", "LOSING", "COLLAPSED"];

/** Allowed challenge mutation types */
var MUTATION_TYPES = [
  "difficulty_increase",
  "visual_change",
  "timing_change",
  "format_change",
  "new_variant"
];

/** Allowed bot outcomes */
var BOT_OUTCOMES = ["solve", "fail", "timeout"];

/** Default configuration */
var DEFAULTS = {
  maxEvents: 5000,
  maxChallengeTypes: 200,
  maxBots: 500,
  adaptationWindowMs: 7 * 24 * 60 * 60 * 1000,
  obsolescenceForecastMs: 30 * 24 * 60 * 60 * 1000,
  minSamplesForAnalysis: 10,
  fitnessDecayRate: 0.05,
  redQueenThreshold: 0.6
};

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Detect dangerous keys that could cause prototype pollution (CWE-1321).
 * @param {string} key
 * @returns {boolean}
 */
function _isSafeKey(key) {
  return key !== "__proto__" && key !== "constructor" && key !== "prototype";
}

/**
 * Deep-clone a dict into a null-prototype object, skipping dangerous keys.
 * @param {Object} src
 * @returns {Object}
 */
function _safeCloneDict(src) {
  var out = Object.create(null);
  if (!src || typeof src !== "object" || Array.isArray(src)) return out;
  var keys = Object.keys(src);
  for (var i = 0; i < keys.length; i++) {
    if (!_isSafeKey(keys[i])) continue;
    out[keys[i]] = JSON.parse(JSON.stringify(src[keys[i]]));
  }
  return out;
}

/**
/**
 * Compute solve rate from events array.
 * @param {Array} events
 * @returns {number} 0-1
 */
function _solveRate(events) {
  if (!events || events.length === 0) return 0;
  var solves = 0;
  for (var i = 0; i < events.length; i++) {
    if (events[i].outcome === "solve") solves++;
  }
  return solves / events.length;
}

/**
 * Get events within a time window.
 * @param {Array} events
 * @param {number} windowMs
 * @param {number} now
 * @returns {Array}
 */
function _recentEvents(events, windowMs, now) {
  var cutoff = now - windowMs;
  var result = [];
  for (var i = 0; i < events.length; i++) {
    if (events[i].timestamp >= cutoff) result.push(events[i]);
  }
  return result;
}

/**
 * Divide time window into N buckets and compute solve rate per bucket.
 * @param {Array} events
 * @param {number} buckets
 * @param {number} windowMs
 * @param {number} now
 * @returns {Array<{x: number, y: number}>}
 */
/**
 * Divide time window into N buckets and compute solve rate per bucket.
 * Returns {xs: number[], ys: number[]} for _linearRegression.
 * @param {Array} events
 * @param {number} buckets
 * @param {number} windowMs
 * @param {number} now
 * @returns {{xs: number[], ys: number[]}}
 */
function _bucketSolveRates(events, buckets, windowMs, now) {
  var cutoff = now - windowMs;
  var bucketSize = windowMs / buckets;
  var counts = [];
  var solves = [];
  var i;
  for (i = 0; i < buckets; i++) {
    counts.push(0);
    solves.push(0);
  }
  for (i = 0; i < events.length; i++) {
    var ev = events[i];
    if (ev.timestamp < cutoff) continue;
    var idx = Math.floor((ev.timestamp - cutoff) / bucketSize);
    if (idx >= buckets) idx = buckets - 1;
    counts[idx]++;
    if (ev.outcome === "solve") solves[idx]++;
  }
  var xs = [];
  var ys = [];
  for (i = 0; i < buckets; i++) {
    if (counts[i] > 0) {
      xs.push(i);
      ys.push(solves[i] / counts[i]);
    }
  }
  return { xs: xs, ys: ys };
}

// ── Engine ──────────────────────────────────────────────────────────

/**
 * Create a ChallengeCoevolutionEngine instance.
 *
 * @param {Object} [options]
 * @param {number} [options.maxEvents=5000]
 * @param {number} [options.maxChallengeTypes=200]
 * @param {number} [options.maxBots=500]
 * @param {number} [options.adaptationWindowMs=604800000]
 * @param {number} [options.obsolescenceForecastMs=2592000000]
 * @param {number} [options.minSamplesForAnalysis=10]
 * @param {number} [options.fitnessDecayRate=0.05]
 * @param {number} [options.redQueenThreshold=0.6]
 * @returns {Object}
 */
function createChallengeCoevolutionEngine(options) {
  var opts = options || {};
  var maxEvents = _posOpt(opts.maxEvents, DEFAULTS.maxEvents);
  var maxChallengeTypes = _posOpt(opts.maxChallengeTypes, DEFAULTS.maxChallengeTypes);
  var maxBots = _posOpt(opts.maxBots, DEFAULTS.maxBots);
  var adaptationWindowMs = _posOpt(opts.adaptationWindowMs, DEFAULTS.adaptationWindowMs);
  var obsolescenceForecastMs = _posOpt(opts.obsolescenceForecastMs, DEFAULTS.obsolescenceForecastMs);
  var minSamples = _posOpt(opts.minSamplesForAnalysis, DEFAULTS.minSamplesForAnalysis);
  var fitnessDecayRate = opts.fitnessDecayRate != null && opts.fitnessDecayRate > 0
    ? opts.fitnessDecayRate : DEFAULTS.fitnessDecayRate;
  var redQueenThreshold = opts.redQueenThreshold != null && opts.redQueenThreshold > 0
    ? opts.redQueenThreshold : DEFAULTS.redQueenThreshold;

  // ── Internal state ──────────────────────────────────────────────

  /** Per-challenge-type event arrays: { [type]: [{...event}] } */
  var challengeEvents = Object.create(null);
  /** Per-challenge-type evolution events: { [type]: [{...mutation}] } */
  var challengeEvolutions = Object.create(null);
  /** Per-bot mutation events: { [botId]: [{...mutation}] } */
  var botMutations = Object.create(null);
  /** LRU trackers for capacity management */
  var typeLru = new LruTracker();
  var botLru = new LruTracker();
  /** Total event counters */
  var totalEvents = 0;
  var totalEvolutions = 0;
  var totalBotMutations = 0;

  // ── Capacity management ─────────────────────────────────────────

  function _evictOldestType() {
    var key = typeLru.evictOldest();
    if (key) {
      delete challengeEvents[key];
      delete challengeEvolutions[key];
    }
  }

  function _evictOldestBot() {
    var key = botLru.evictOldest();
    if (key) {
      delete botMutations[key];
    }
  }

  function _trimEvents(arr) {
    var limit = Math.floor(maxEvents / Math.max(typeLru.length, 1));
    if (limit < 50) limit = 50;
    while (arr.length > limit) {
      arr.shift();
    }
  }

  // ── Recording ───────────────────────────────────────────────────

  /**
   * Record a challenge solve/fail/timeout event.
   * @param {Object} event
   * @param {string} event.challengeId
   * @param {string} event.challengeType
   * @param {string} [event.botId]
   * @param {string} event.outcome - "solve"|"fail"|"timeout"
   * @param {number} [event.solveTimeMs]
   * @param {number} [event.timestamp]
   * @param {string} [event.botStrategy]
   */
  function recordChallengeEvent(event) {
    if (!event || !event.challengeType || !event.outcome) return;
    if (BOT_OUTCOMES.indexOf(event.outcome) === -1) return;
    var type = String(event.challengeType);
    var ts = event.timestamp || _now();
    var record = {
      challengeId: event.challengeId || "unknown",
      challengeType: type,
      botId: event.botId || null,
      outcome: event.outcome,
      solveTimeMs: event.solveTimeMs || null,
      timestamp: ts,
      botStrategy: event.botStrategy || null
    };
    if (!challengeEvents[type]) {
      if (typeLru.length >= maxChallengeTypes) _evictOldestType();
      challengeEvents[type] = [];
      if (!challengeEvolutions[type]) challengeEvolutions[type] = [];
      typeLru.push(type);
    } else {
      typeLru.touch(type);
    }
    challengeEvents[type].push(record);
    _trimEvents(challengeEvents[type]);
    totalEvents++;
  }

  /**
   * Record a challenge evolution/mutation event.
   * @param {Object} event
   * @param {string} event.challengeType
   * @param {string} event.mutation
   * @param {number} [event.timestamp]
   */
  function recordChallengeEvolution(event) {
    if (!event || !event.challengeType || !event.mutation) return;
    if (MUTATION_TYPES.indexOf(event.mutation) === -1) return;
    var type = String(event.challengeType);
    var ts = event.timestamp || _now();
    if (!challengeEvolutions[type]) {
      challengeEvolutions[type] = [];
    }
    if (!challengeEvents[type]) {
      if (typeLru.length >= maxChallengeTypes) _evictOldestType();
      challengeEvents[type] = [];
      typeLru.push(type);
    } else {
      typeLru.touch(type);
    }
    challengeEvolutions[type].push({
      challengeType: type,
      mutation: event.mutation,
      timestamp: ts
    });
    totalEvolutions++;
  }

  /**
   * Record a bot strategy mutation.
   * @param {Object} event
   * @param {string} event.botId
   * @param {string} [event.challengeType]
   * @param {string} [event.oldStrategy]
   * @param {string} [event.newStrategy]
   * @param {number} [event.timestamp]
   */
  function recordBotMutation(event) {
    if (!event || !event.botId) return;
    var botId = String(event.botId);
    var ts = event.timestamp || _now();
    if (!botMutations[botId]) {
      if (botLru.length >= maxBots) _evictOldestBot();
      botMutations[botId] = [];
      botLru.push(botId);
    } else {
      botLru.touch(botId);
    }
    botMutations[botId].push({
      botId: botId,
      challengeType: event.challengeType || null,
      oldStrategy: event.oldStrategy || null,
      newStrategy: event.newStrategy || null,
      timestamp: ts
    });
    totalBotMutations++;
  }

  // ── Engine 1: Adaptation Velocity Tracker ───────────────────────

  /**
   * Measure adaptation velocity for a challenge type.
   * Bot velocity = rate of change in solve rate over time (positive = bots improving).
   * Challenge velocity = rate of challenge mutations over time.
   *
   * @param {string} challengeType
   * @returns {Object|null} { botVelocity, challengeVelocity, ratio, trend }
   */
  function getAdaptationVelocity(challengeType) {
    if (!challengeType || !challengeEvents[challengeType]) return null;
    var now = _now();
    var events = _recentEvents(challengeEvents[challengeType], adaptationWindowMs, now);
    if (events.length < minSamples) return null;

    // Bot velocity: slope of solve rate over time buckets
    var bk = _bucketSolveRates(events, 7, adaptationWindowMs, now);
    var botVelocity = 0;
    if (bk.xs.length >= 2) {
      var reg = _linearRegression(bk.xs, bk.ys);
      botVelocity = reg.slope;
    }

    // Challenge velocity: mutations per day in the window
    var evolutions = challengeEvolutions[challengeType] || [];
    var recentEvolutions = _recentEvents(evolutions, adaptationWindowMs, now);
    var challengeVelocity = recentEvolutions.length / (adaptationWindowMs / (24 * 60 * 60 * 1000));

    // Ratio: bot speed / (challenge speed + epsilon)
    var ratio = botVelocity / (challengeVelocity + 0.001);

    // Trend classification
    var trend = "stable";
    if (botVelocity > 0.05) trend = "bots_gaining";
    else if (botVelocity < -0.05) trend = "defense_winning";
    else if (challengeVelocity > 0.5 && botVelocity > 0) trend = "arms_race";

    return {
      challengeType: challengeType,
      botVelocity: Math.round(botVelocity * 10000) / 10000,
      challengeVelocity: Math.round(challengeVelocity * 10000) / 10000,
      ratio: Math.round(ratio * 1000) / 1000,
      trend: trend,
      sampleCount: events.length,
      windowMs: adaptationWindowMs
    };
  }

  // ── Engine 2: Red Queen Detector ────────────────────────────────

  /**
   * Detect Red Queen arms races across all challenge types.
   * @returns {Array<Object>} Active races with classification
   */
  function detectRedQueenRaces() {
    var types = Object.keys(challengeEvents);
    var races = [];
    for (var i = 0; i < types.length; i++) {
      var vel = getAdaptationVelocity(types[i]);
      if (!vel) continue;

      var intensity = Math.abs(vel.botVelocity) + vel.challengeVelocity;
      var state;
      if (intensity < 0.01) {
        state = RACE_STATES[0]; // DORMANT
      } else if (intensity < 0.05) {
        state = RACE_STATES[1]; // WARMING
      } else if (intensity < 0.15) {
        state = RACE_STATES[2]; // ACTIVE
      } else if (intensity < 0.3 || vel.ratio > redQueenThreshold) {
        state = RACE_STATES[3]; // ESCALATING
      } else {
        state = RACE_STATES[4]; // CRITICAL
      }

      races.push({
        challengeType: types[i],
        state: state,
        intensity: Math.round(intensity * 10000) / 10000,
        botVelocity: vel.botVelocity,
        challengeVelocity: vel.challengeVelocity,
        ratio: vel.ratio,
        trend: vel.trend
      });
    }

    // Sort by intensity descending
    races.sort(function (a, b) { return b.intensity - a.intensity; });
    return races;
  }

  // ── Engine 3: Defense Obsolescence Predictor ────────────────────

  /**
   * Predict when challenge defenses will become obsolete.
   * Uses linear regression on solve rate trends to estimate
   * when bots will reach critical solve rate thresholds.
   *
   * @param {string} [challengeType] - Specific type or all
   * @returns {Array<Object>} Predictions with breakthrough time estimates
   */
  function predictObsolescence(challengeType) {
    var types = challengeType ? [challengeType] : Object.keys(challengeEvents);
    var predictions = [];
    var now = _now();
    var criticalSolveRate = 0.8; // 80% = effectively broken

    for (var i = 0; i < types.length; i++) {
      var type = types[i];
      if (!challengeEvents[type]) continue;
      var events = _recentEvents(challengeEvents[type], adaptationWindowMs, now);
      if (events.length < minSamples) {
        predictions.push({
          challengeType: type,
          currentSolveRate: _solveRate(events),
          predictedBreakthroughMs: null,
          confidence: "insufficient_data",
          status: "unknown"
        });
        continue;
      }

      var bk = _bucketSolveRates(events, 7, adaptationWindowMs, now);
      var currentRate = _solveRate(events);
      var breakthroughMs = null;
      var status = "safe";

      if (bk.xs.length >= 2) {
        var reg = _linearRegression(bk.xs, bk.ys);
        // If slope is positive, estimate when solve rate reaches critical threshold
        if (reg.slope > 0 && currentRate < criticalSolveRate) {
          var bucketsToBreakthrough = (criticalSolveRate - reg.intercept) / reg.slope;
          var msPerBucket = adaptationWindowMs / 7;
          breakthroughMs = Math.round(bucketsToBreakthrough * msPerBucket);
          if (breakthroughMs > obsolescenceForecastMs) {
            status = "safe";
          } else if (breakthroughMs > obsolescenceForecastMs / 2) {
            status = "watch";
          } else {
            status = "urgent";
          }
        } else if (currentRate >= criticalSolveRate) {
          status = "broken";
          breakthroughMs = 0;
        }
      }

      predictions.push({
        challengeType: type,
        currentSolveRate: Math.round(currentRate * 10000) / 10000,
        predictedBreakthroughMs: breakthroughMs,
        confidence: bk.xs.length >= 5 ? "high" : "moderate",
        status: status
      });
    }

    predictions.sort(function (a, b) {
      if (a.predictedBreakthroughMs === null) return 1;
      if (b.predictedBreakthroughMs === null) return -1;
      return a.predictedBreakthroughMs - b.predictedBreakthroughMs;
    });
    return predictions;
  }

  // ── Engine 4: Evolutionary Fitness Scorer ───────────────────────

  /**
   * Score evolutionary fitness of challenge types.
   * Fitness = f(current effectiveness, adaptation rate, predicted longevity).
   *
   * Pre-computes obsolescence predictions for ALL types in one pass
   * and indexes by type, replacing the previous per-type
   * predictObsolescence() call inside the loop — eliminates O(types)
   * redundant _recentEvents + _linearRegression invocations.
   *
   * @param {string} [challengeType] - Specific type or all
   * @returns {Array<Object>} Fitness scores per challenge type
   */
  function getEvolutionaryFitness(challengeType) {
    var types = challengeType ? [challengeType] : Object.keys(challengeEvents);
    var results = [];
    var now = _now();

    // Pre-compute all obsolescence predictions in one call, then index
    // by challenge type for O(1) lookup inside the per-type loop.
    // Previously predictObsolescence(type) was called per type, re-running
    // _recentEvents + _bucketSolveRates + _linearRegression each time.
    var allPreds = predictObsolescence(challengeType);
    var predIndex = Object.create(null);
    for (var p = 0; p < allPreds.length; p++) {
      predIndex[allPreds[p].challengeType] = allPreds[p];
    }

    for (var i = 0; i < types.length; i++) {
      var type = types[i];
      if (!challengeEvents[type]) continue;
      var events = _recentEvents(challengeEvents[type], adaptationWindowMs, now);
      var solveRate = _solveRate(events);
      var effectiveness = 1 - solveRate; // Lower solve rate = more effective

      // Adaptation component: how actively defended
      var evolutions = challengeEvolutions[type] || [];
      var recentEvolutions = _recentEvents(evolutions, adaptationWindowMs, now);
      var adaptationScore = Math.min(recentEvolutions.length / 5, 1); // Up to 5 mutations = max

      // Longevity component from pre-computed obsolescence predictions
      var pred = predIndex[type];
      var longevityScore = 1;
      if (pred && pred.predictedBreakthroughMs !== null) {
        longevityScore = _clamp(pred.predictedBreakthroughMs / obsolescenceForecastMs, 0, 1);
      } else if (pred && pred.status === "broken") {
        longevityScore = 0;
      }

      // Composite fitness: weighted combination
      var fitness = (effectiveness * 0.4) + (adaptationScore * 0.25) + (longevityScore * 0.35);
      fitness = Math.round(_clamp(fitness, 0, 1) * 100);

      // Decay penalty for stale challenge types (no recent events)
      if (events.length < minSamples) {
        fitness = Math.max(fitness - 20, 0);
      }

      var tier;
      if (fitness >= 80) tier = "dominant";
      else if (fitness >= 60) tier = "competitive";
      else if (fitness >= 40) tier = "contested";
      else if (fitness >= 20) tier = "struggling";
      else tier = "obsolete";

      results.push({
        challengeType: type,
        fitness: fitness,
        tier: tier,
        effectiveness: Math.round(effectiveness * 10000) / 10000,
        adaptationScore: Math.round(adaptationScore * 10000) / 10000,
        longevityScore: Math.round(longevityScore * 10000) / 10000,
        sampleCount: events.length,
        recentMutations: recentEvolutions.length
      });
    }

    results.sort(function (a, b) { return b.fitness - a.fitness; });
    return results;
  }

  // ── Engine 5: Mutation Pressure Analyzer ────────────────────────

  /**
   * Analyze mutation pressure — how aggressively bots are adapting.
   *
   * @param {string} [challengeType] - Specific type or all
   * @returns {Object} Mutation pressure analysis
   */
  function getMutationPressure(challengeType) {
    var now = _now();
    var botIds = Object.keys(botMutations);
    var pressureByType = Object.create(null);
    var overallMutations = 0;

    for (var i = 0; i < botIds.length; i++) {
      var mutations = _recentEvents(botMutations[botIds[i]], adaptationWindowMs, now);
      for (var j = 0; j < mutations.length; j++) {
        var mut = mutations[j];
        var targetType = mut.challengeType || "_global";
        if (challengeType && targetType !== challengeType && targetType !== "_global") continue;
        if (!pressureByType[targetType]) {
          pressureByType[targetType] = {
            mutationCount: 0,
            uniqueBots: Object.create(null),
            strategies: Object.create(null)
          };
        }
        pressureByType[targetType].mutationCount++;
        pressureByType[targetType].uniqueBots[botIds[i]] = true;
        if (mut.newStrategy) {
          pressureByType[targetType].strategies[mut.newStrategy] = true;
        }
        overallMutations++;
      }
    }

    var typeKeys = Object.keys(pressureByType);
    var analysis = [];
    for (var k = 0; k < typeKeys.length; k++) {
      var p = pressureByType[typeKeys[k]];
      var uniqueBotCount = Object.keys(p.uniqueBots).length;
      var strategyDiversity = Object.keys(p.strategies).length;
      // Pressure score: combination of mutation rate and diversity
      var pressure = _clamp(
        (p.mutationCount / 10) * 0.5 + (strategyDiversity / 5) * 0.3 + (uniqueBotCount / 5) * 0.2,
        0, 1
      );
      var severity;
      if (pressure >= 0.8) severity = "critical";
      else if (pressure >= 0.6) severity = "high";
      else if (pressure >= 0.3) severity = "moderate";
      else severity = "low";

      analysis.push({
        challengeType: typeKeys[k],
        mutationCount: p.mutationCount,
        uniqueBots: uniqueBotCount,
        strategyDiversity: strategyDiversity,
        pressure: Math.round(pressure * 10000) / 10000,
        severity: severity
      });
    }

    analysis.sort(function (a, b) { return b.pressure - a.pressure; });

    return {
      totalMutations: overallMutations,
      activeBots: botIds.length,
      types: analysis,
      windowMs: adaptationWindowMs
    };
  }

  // ── Engine 6: Coevolution Health Scorer ─────────────────────────

  /**
   * Compute composite coevolution health score 0-100.
   *
   * Accepts optional pre-computed sub-results to avoid redundant work
   * when called from getReport() (which also needs the same data for
   * generateInsights).  Without caching, getReport() recomputed
   * fitness/races/pressure/obsolescence 3-4× each — O(types²) total
   * because getEvolutionaryFitness itself calls predictObsolescence
   * per type.
   *
   * @param {Object} [_cache] Pre-computed sub-results (internal use)
   * @returns {Object} Health report
   */
  function getCoevolutionHealth(_cache) {
    _cache = _cache || {};
    var fitness = _cache.fitness || getEvolutionaryFitness();
    var races = _cache.races || detectRedQueenRaces();
    var pressure = _cache.pressure || getMutationPressure();
    var obsolescence = _cache.obsolescence || predictObsolescence();

    // Component 1: Average fitness (0-100)
    var fitnessScores = [];
    for (var i = 0; i < fitness.length; i++) {
      fitnessScores.push(fitness[i].fitness);
    }
    var avgFitness = fitnessScores.length > 0 ? _mean(fitnessScores) : 50;

    // Component 2: Race stability (fewer critical races = better)
    var criticalRaces = 0;
    var escalatingRaces = 0;
    for (var j = 0; j < races.length; j++) {
      if (races[j].state === "CRITICAL") criticalRaces++;
      if (races[j].state === "ESCALATING") escalatingRaces++;
    }
    var raceStability = 100 - (criticalRaces * 25 + escalatingRaces * 10);
    raceStability = _clamp(raceStability, 0, 100);

    // Component 3: Mutation pressure resistance
    var avgPressure = 0;
    if (pressure.types.length > 0) {
      var pressureSum = 0;
      for (var k = 0; k < pressure.types.length; k++) {
        pressureSum += pressure.types[k].pressure;
      }
      avgPressure = pressureSum / pressure.types.length;
    }
    var pressureResistance = (1 - avgPressure) * 100;

    // Component 4: Obsolescence safety
    var urgentCount = 0;
    var brokenCount = 0;
    for (var m = 0; m < obsolescence.length; m++) {
      if (obsolescence[m].status === "urgent") urgentCount++;
      if (obsolescence[m].status === "broken") brokenCount++;
    }
    var obsolescenceSafety = 100 - (brokenCount * 30 + urgentCount * 15);
    obsolescenceSafety = _clamp(obsolescenceSafety, 0, 100);

    // Composite score: weighted combination
    var score = Math.round(
      avgFitness * 0.3 +
      raceStability * 0.25 +
      pressureResistance * 0.25 +
      obsolescenceSafety * 0.2
    );
    score = _clamp(score, 0, 100);

    // Tier classification
    var tier;
    if (score >= 80) tier = HEALTH_TIERS[0]; // DOMINANT
    else if (score >= 60) tier = HEALTH_TIERS[1]; // COMPETITIVE
    else if (score >= 40) tier = HEALTH_TIERS[2]; // CONTESTED
    else if (score >= 20) tier = HEALTH_TIERS[3]; // LOSING
    else tier = HEALTH_TIERS[4]; // COLLAPSED

    return {
      score: score,
      tier: tier,
      components: {
        avgFitness: Math.round(avgFitness * 100) / 100,
        raceStability: Math.round(raceStability * 100) / 100,
        pressureResistance: Math.round(pressureResistance * 100) / 100,
        obsolescenceSafety: Math.round(obsolescenceSafety * 100) / 100
      },
      summary: {
        challengeTypes: Object.keys(challengeEvents).length,
        totalEvents: totalEvents,
        activeRaces: races.length,
        criticalRaces: criticalRaces,
        escalatingRaces: escalatingRaces,
        brokenDefenses: brokenCount,
        urgentDefenses: urgentCount
      }
    };
  }

  // ── Engine 7: Insight Generator ─────────────────────────────────

  /**
   * Generate autonomous insights about coevolution dynamics.
   *
   * Accepts optional pre-computed sub-results (internal cache) so
   * getReport() can share a single computation pass across health,
   * insights, and top-level report fields.
   *
   * @param {Object} [_cache] Pre-computed sub-results (internal use)
   * @returns {Array<Object>} Insights with recommendations
   */
  function generateInsights(_cache) {
    _cache = _cache || {};
    var insights = [];
    var races = _cache.races || detectRedQueenRaces();
    var fitness = _cache.fitness || getEvolutionaryFitness();
    var pressure = _cache.pressure || getMutationPressure();
    var obsolescence = _cache.obsolescence || predictObsolescence();
    var health = _cache.health || getCoevolutionHealth({ fitness: fitness, races: races, pressure: pressure, obsolescence: obsolescence });

    // Insight: Overall health
    if (health.tier === "COLLAPSED" || health.tier === "LOSING") {
      insights.push({
        type: "critical",
        category: "health",
        message: "Coevolution health is " + health.tier + " (score: " + health.score +
          "/100). Bots are winning the arms race.",
        recommendation: "Urgently introduce new challenge types or significantly increase difficulty."
      });
    } else if (health.tier === "DOMINANT") {
      insights.push({
        type: "positive",
        category: "health",
        message: "Defense ecosystem is DOMINANT (score: " + health.score +
          "/100). Challenges are outpacing bot adaptation.",
        recommendation: "Maintain current evolution pace; monitor for complacency."
      });
    }

    // Insight: Critical races
    for (var i = 0; i < races.length; i++) {
      if (races[i].state === "CRITICAL" || races[i].state === "ESCALATING") {
        insights.push({
          type: "warning",
          category: "arms_race",
          message: races[i].challengeType + " is in " + races[i].state +
            " arms race (intensity: " + races[i].intensity + ").",
          recommendation: "Accelerate challenge mutations for " + races[i].challengeType +
            " or introduce a replacement type."
        });
      }
    }

    // Insight: Low fitness challenges
    for (var j = 0; j < fitness.length; j++) {
      if (fitness[j].tier === "obsolete") {
        insights.push({
          type: "critical",
          category: "fitness",
          message: fitness[j].challengeType + " is OBSOLETE (fitness: " +
            fitness[j].fitness + "/100).",
          recommendation: "Consider retiring " + fitness[j].challengeType +
            " and replacing with evolved variant."
        });
      }
    }

    // Insight: High mutation pressure
    for (var k = 0; k < pressure.types.length; k++) {
      if (pressure.types[k].severity === "critical") {
        insights.push({
          type: "warning",
          category: "mutation_pressure",
          message: "Critical mutation pressure on " + pressure.types[k].challengeType +
            " (" + pressure.types[k].mutationCount + " bot mutations, " +
            pressure.types[k].strategyDiversity + " unique strategies).",
          recommendation: "Deploy diverse defensive mutations to increase bot adaptation cost."
        });
      }
    }

    // Insight: Imminent obsolescence
    for (var m = 0; m < obsolescence.length; m++) {
      if (obsolescence[m].status === "urgent") {
        var daysLeft = obsolescence[m].predictedBreakthroughMs
          ? Math.round(obsolescence[m].predictedBreakthroughMs / (24 * 60 * 60 * 1000))
          : "?";
        insights.push({
          type: "critical",
          category: "obsolescence",
          message: obsolescence[m].challengeType + " predicted to become obsolete in ~" +
            daysLeft + " days.",
          recommendation: "Begin phasing out " + obsolescence[m].challengeType +
            " and prepare replacement."
        });
      }
    }

    // Insight: No evolution activity
    if (totalEvolutions === 0 && totalEvents > 0) {
      insights.push({
        type: "warning",
        category: "stagnation",
        message: "No challenge evolution events recorded. Defenses may be stagnating.",
        recommendation: "Introduce regular challenge mutations to maintain defensive advantage."
      });
    }

    // Insight: Low bot mutation diversity
    if (pressure.totalMutations > 0 && pressure.types.length > 0) {
      var lowDiversity = true;
      for (var n = 0; n < pressure.types.length; n++) {
        if (pressure.types[n].strategyDiversity > 2) {
          lowDiversity = false;
          break;
        }
      }
      if (lowDiversity) {
        insights.push({
          type: "info",
          category: "bot_strategy",
          message: "Bots showing low strategy diversity — may be using a single effective approach.",
          recommendation: "Identify and neutralize the dominant bot strategy to force re-adaptation."
        });
      }
    }

    return insights;
  }

  // ── Report ──────────────────────────────────────────────────────

  /**
   * Generate a full coevolution report.
   *
   * Computes each expensive sub-analysis exactly once and threads
   * the results through getCoevolutionHealth and generateInsights
   * via an internal cache object.  Previously each engine was
   * called independently, causing 3-4× redundant computation of
   * fitness, races, pressure, and obsolescence (and fitness itself
   * calls predictObsolescence per type, compounding the cost).
   *
   * @returns {Object}
   */
  function getReport() {
    var cache = {
      races: detectRedQueenRaces(),
      fitness: getEvolutionaryFitness(),
      pressure: getMutationPressure(),
      obsolescence: predictObsolescence()
    };
    cache.health = getCoevolutionHealth(cache);
    cache.insights = generateInsights(cache);
    return {
      health: cache.health,
      races: cache.races,
      fitness: cache.fitness,
      mutationPressure: cache.pressure,
      obsolescence: cache.obsolescence,
      insights: cache.insights,
      generatedAt: _now()
    };
  }

  // ── State persistence ───────────────────────────────────────────

  /**
   * Export engine state for persistence.
   * @returns {Object}
   */
  function exportState() {
    return {
      version: 1,
      challengeEvents: JSON.parse(JSON.stringify(challengeEvents)),
      challengeEvolutions: JSON.parse(JSON.stringify(challengeEvolutions)),
      botMutations: JSON.parse(JSON.stringify(botMutations)),
      typeLruOrder: typeLru.toArray(),
      botLruOrder: botLru.toArray(),
      totalEvents: totalEvents,
      totalEvolutions: totalEvolutions,
      totalBotMutations: totalBotMutations,
      exportedAt: _now()
    };
  }

  /**
   * Import engine state from a previous export.
   * Uses safe deep-cloning to prevent prototype pollution (CWE-1321)
   * and reference leakage (CWE-915).
   *
   * @param {Object} state
   * @returns {boolean} true if imported successfully
   */
  function importState(state) {
    if (!state || state.version !== 1) return false;

    challengeEvents = _safeCloneDict(state.challengeEvents);
    challengeEvolutions = _safeCloneDict(state.challengeEvolutions);
    botMutations = _safeCloneDict(state.botMutations);

    // Rebuild LRU trackers
    typeLru = new LruTracker();
    var typeOrder = Array.isArray(state.typeLruOrder)
      ? state.typeLruOrder : Object.keys(challengeEvents);
    for (var i = 0; i < typeOrder.length; i++) {
      if (_isSafeKey(typeOrder[i])) typeLru.push(typeOrder[i]);
    }

    botLru = new LruTracker();
    var botOrder = Array.isArray(state.botLruOrder)
      ? state.botLruOrder : Object.keys(botMutations);
    for (var j = 0; j < botOrder.length; j++) {
      if (_isSafeKey(botOrder[j])) botLru.push(botOrder[j]);
    }

    totalEvents = typeof state.totalEvents === "number" ? state.totalEvents : 0;
    totalEvolutions = typeof state.totalEvolutions === "number" ? state.totalEvolutions : 0;
    totalBotMutations = typeof state.totalBotMutations === "number" ? state.totalBotMutations : 0;

    return true;
  }

  // ── Public API ──────────────────────────────────────────────────

  return {
    recordChallengeEvent: recordChallengeEvent,
    recordChallengeEvolution: recordChallengeEvolution,
    recordBotMutation: recordBotMutation,
    getAdaptationVelocity: getAdaptationVelocity,
    detectRedQueenRaces: detectRedQueenRaces,
    predictObsolescence: predictObsolescence,
    getEvolutionaryFitness: getEvolutionaryFitness,
    getMutationPressure: getMutationPressure,
    getCoevolutionHealth: getCoevolutionHealth,
    generateInsights: generateInsights,
    getReport: getReport,
    exportState: exportState,
    importState: importState
  };
}

// ── Exports ─────────────────────────────────────────────────────────

exports.createChallengeCoevolutionEngine = createChallengeCoevolutionEngine;
exports.RACE_STATES = RACE_STATES;
exports.HEALTH_TIERS = HEALTH_TIERS;
exports.MUTATION_TYPES = MUTATION_TYPES;
exports.BOT_OUTCOMES = BOT_OUTCOMES;
