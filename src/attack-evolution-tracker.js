/**
 * AttackEvolutionTracker — Autonomous bot attack pattern evolution tracker.
 *
 * Monitors how bot attack strategies evolve over time by tracking challenge
 * outcomes per attack vector, detecting adaptation patterns (e.g. bots learning
 * to bypass specific challenge types), predicting which challenges are at risk
 * of being compromised next, and recommending preemptive defense rotations.
 *
 * Key capabilities:
 *   - Record attack attempts with strategy fingerprints (timing, tool, technique)
 *   - Track per-challenge success/failure curves over sliding windows
 *   - Detect "learning curves" — strategies whose success rate is rising
 *   - Predict time-to-compromise for challenged defenses via linear extrapolation
 *   - Generate preemptive rotation recommendations before compromise happens
 *   - Maintain an evolving threat model with strategy lineage tracking
 *   - Export evolution timeline for forensic review
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/attack-evolution-tracker
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _clamp = _shared._clamp;
var _sharedLinearRegression = _shared._linearRegression;

var _crypto = require("./crypto-utils");
var secureRandom = _crypto.secureRandom;

// ── Defaults ────────────────────────────────────────────────────────

var DEFAULTS = {
  windowMs: 3600000,               // 1 hour analysis window
  epochMs: 300000,                  // 5-minute epochs for trend tracking
  minObservations: 10,              // min attempts to analyze a strategy
  learningRateThreshold: 0.02,     // rise in success rate per epoch to flag as "learning"
  compromiseThreshold: 0.70,       // success rate above which a challenge is "compromised"
  warningThreshold: 0.50,          // success rate above which we issue a warning
  predictionHorizonEpochs: 12,     // how far ahead to predict (1 hour at 5min epochs)
  maxStrategies: 500,              // cap on tracked strategies
  maxEvents: 50000,                // cap on stored events
  maxEpochHistory: 288,            // 24 hours of 5-min epochs
  rotationCooldownMs: 1800000,     // 30 min before re-recommending rotation for same challenge
  lineageDepth: 10                 // max mutation chain length to track
};

// ── Helpers ─────────────────────────────────────────────────────────

function _optNum(val, def) {
  return typeof val === "number" && val >= 0 ? val : def;
}


function _epochKey(ts, epochMs) {
  return Math.floor(ts / epochMs);
}

/**
 * Linear regression adapter for [[x, y], ...] point arrays.
 * Delegates to shared-utils._linearRegression (which accepts parallel xs, ys)
 * to eliminate the duplicated regression implementation (issue #91 cleanup).
 */
function _linearRegression(points) {
  var n = points.length;
  if (n < 2) return { slope: 0, intercept: 0, r2: 0 };
  var xs = new Array(n);
  var ys = new Array(n);
  for (var i = 0; i < n; i++) {
    xs[i] = points[i][0];
    ys[i] = points[i][1];
  }
  var reg = _sharedLinearRegression(xs, ys);
  return { slope: reg.slope, intercept: reg.intercept, r2: Math.max(0, reg.r2) };
}

/**
 * Fingerprint an attack attempt into a strategy key.
 */
function _fingerprint(attempt) {
  var parts = [];
  parts.push(attempt.tool || "unknown");
  parts.push(attempt.technique || "unknown");
  parts.push(attempt.timingProfile || "unknown");
  return parts.join("::");
}

// ── Strategy Record ─────────────────────────────────────────────────

function _createStrategy(id, firstSeen) {
  return {
    id: id,
    firstSeen: firstSeen,
    lastSeen: firstSeen,
    totalAttempts: 0,
    totalSuccesses: 0,
    epochHistory: [],         // [{epoch, attempts, successes, rate}]
    parentId: null,           // lineage: which strategy this mutated from
    generation: 0,
    status: "active",         // active | adapting | evolved | dormant
    learningRate: 0,          // success rate change per epoch
    r2: 0,                    // regression fit quality
    peakRate: 0,
    peakEpoch: 0
  };
}

// ── Challenge Record ────────────────────────────────────────────────

function _createChallengeRecord(id) {
  return {
    id: id,
    totalAttempts: 0,
    totalBotSuccesses: 0,
    currentBotSuccessRate: 0,
    epochHistory: [],           // [{epoch, attempts, botSuccesses, rate}]
    status: "secure",           // secure | warning | at-risk | compromised
    predictedCompromiseEpoch: null,
    lastRotationRecommendedAt: null,
    strategiesTargeting: {}     // strategyId → count
  };
}

// ── Core Factory ────────────────────────────────────────────────────

function createAttackEvolutionTracker(options) {
  options = options || {};

  var windowMs = _optNum(options.windowMs, DEFAULTS.windowMs);
  var epochMs = _optNum(options.epochMs, DEFAULTS.epochMs);
  var minObservations = _optNum(options.minObservations, DEFAULTS.minObservations);
  var learningRateThreshold = _optNum(options.learningRateThreshold, DEFAULTS.learningRateThreshold);
  var compromiseThreshold = _optNum(options.compromiseThreshold, DEFAULTS.compromiseThreshold);
  var warningThreshold = _optNum(options.warningThreshold, DEFAULTS.warningThreshold);
  var predictionHorizonEpochs = _optNum(options.predictionHorizonEpochs, DEFAULTS.predictionHorizonEpochs);
  var maxStrategies = _optNum(options.maxStrategies, DEFAULTS.maxStrategies);
  var maxEvents = _optNum(options.maxEvents, DEFAULTS.maxEvents);
  var maxEpochHistory = _optNum(options.maxEpochHistory, DEFAULTS.maxEpochHistory);
  var rotationCooldownMs = _optNum(options.rotationCooldownMs, DEFAULTS.rotationCooldownMs);
  var lineageDepth = _optNum(options.lineageDepth, DEFAULTS.lineageDepth);

  // ── Internal State ──────────────────────────────────────────────
  var strategies = {};          // strategyId → strategy record
  var challenges = {};          // challengeId → challenge record
  var events = [];              // raw event log
  var strategyOrder = [];       // for LRU eviction
  var currentEpoch = 0;
  var rotationLog = [];         // [{ts, challengeId, reason, recommendation}]
  var evolutionTimeline = [];   // [{ts, type, details}]

  // ── Record an Attack Attempt ────────────────────────────────────
  function recordAttempt(attempt) {
    if (!attempt || typeof attempt !== "object") return null;

    var ts = attempt.timestamp || _now();
    var epoch = _epochKey(ts, epochMs);
    var challengeId = attempt.challengeId || "unknown";
    var success = attempt.success === true;
    var strategyId = attempt.strategyId || _fingerprint(attempt);

    // Store event
    var evt = {
      ts: ts,
      epoch: epoch,
      strategyId: strategyId,
      challengeId: challengeId,
      success: success
    };
    events.push(evt);
    if (events.length > maxEvents) {
      events = events.slice(events.length - Math.floor(maxEvents * 0.8));
    }

    // Update or create strategy
    var strat = strategies[strategyId];
    if (!strat) {
      // Evict oldest if at capacity
      if (strategyOrder.length >= maxStrategies) {
        var evictId = strategyOrder.shift();
        delete strategies[evictId];
      }
      strat = _createStrategy(strategyId, ts);
      strategies[strategyId] = strat;
      strategyOrder.push(strategyId);

      // Detect mutation: if another strategy has similar fingerprint prefix
      _detectMutation(strat);
    }

    strat.lastSeen = ts;
    strat.totalAttempts++;
    if (success) strat.totalSuccesses++;

    // Update strategy epoch history
    _updateEpochHistory(strat.epochHistory, epoch, success, maxEpochHistory);

    // Update challenge record
    var ch = challenges[challengeId];
    if (!ch) {
      ch = _createChallengeRecord(challengeId);
      challenges[challengeId] = ch;
    }
    ch.totalAttempts++;
    if (success) ch.totalBotSuccesses++;
    ch.currentBotSuccessRate = ch.totalBotSuccesses / ch.totalAttempts;
    ch.strategiesTargeting[strategyId] = (ch.strategiesTargeting[strategyId] || 0) + 1;

    // Update challenge epoch history
    _updateEpochHistory(ch.epochHistory, epoch, success, maxEpochHistory);

    currentEpoch = epoch;

    return { strategyId: strategyId, epoch: epoch };
  }

  function _updateEpochHistory(history, epoch, success, maxLen) {
    var last = history.length > 0 ? history[history.length - 1] : null;
    if (last && last.epoch === epoch) {
      last.attempts++;
      if (success) last.successes++;
      last.rate = last.successes / last.attempts;
    } else {
      history.push({
        epoch: epoch,
        attempts: 1,
        successes: success ? 1 : 0,
        rate: success ? 1 : 0
      });
      if (history.length > maxLen) {
        history.splice(0, history.length - maxLen);
      }
    }
  }

  function _detectMutation(newStrat) {
    var parts = newStrat.id.split("::");
    if (parts.length < 2) return;

    var toolMatch = parts[0];
    var bestParent = null;
    var bestScore = 0;

    var ids = Object.keys(strategies);
    for (var i = 0; i < ids.length; i++) {
      var candidate = strategies[ids[i]];
      if (candidate.id === newStrat.id) continue;
      var cParts = candidate.id.split("::");
      // Same tool, different technique = likely mutation
      if (cParts[0] === toolMatch && candidate.totalAttempts >= minObservations) {
        var score = candidate.totalAttempts;
        if (score > bestScore) {
          bestScore = score;
          bestParent = candidate;
        }
      }
    }

    if (bestParent) {
      newStrat.parentId = bestParent.id;
      newStrat.generation = Math.min(bestParent.generation + 1, lineageDepth);

      evolutionTimeline.push({
        ts: _now(),
        type: "mutation",
        details: {
          parentId: bestParent.id,
          childId: newStrat.id,
          generation: newStrat.generation,
          parentSuccessRate: bestParent.totalSuccesses / bestParent.totalAttempts
        }
      });
    }
  }

  // ── Analyze All Strategies ──────────────────────────────────────
  function analyze() {
    var now = _now();
    var results = {
      timestamp: now,
      strategies: [],
      adaptingStrategies: [],
      challengeRisks: [],
      rotationRecommendations: [],
      summary: {}
    };

    var totalActive = 0;
    var totalAdapting = 0;
    var totalEvolved = 0;
    var totalDormant = 0;

    var ids = Object.keys(strategies);
    for (var i = 0; i < ids.length; i++) {
      var strat = strategies[ids[i]];
      _analyzeStrategy(strat, now);

      var info = {
        id: strat.id,
        status: strat.status,
        totalAttempts: strat.totalAttempts,
        successRate: strat.totalAttempts > 0
          ? Math.round((strat.totalSuccesses / strat.totalAttempts) * 1000) / 1000
          : 0,
        learningRate: Math.round(strat.learningRate * 10000) / 10000,
        r2: Math.round(strat.r2 * 1000) / 1000,
        peakRate: Math.round(strat.peakRate * 1000) / 1000,
        generation: strat.generation,
        parentId: strat.parentId,
        lastSeen: strat.lastSeen
      };

      results.strategies.push(info);

      if (strat.status === "adapting" || strat.status === "evolved") {
        results.adaptingStrategies.push(info);
      }

      if (strat.status === "active") totalActive++;
      else if (strat.status === "adapting") totalAdapting++;
      else if (strat.status === "evolved") totalEvolved++;
      else totalDormant++;
    }

    // Analyze challenges
    var chIds = Object.keys(challenges);
    for (var j = 0; j < chIds.length; j++) {
      var ch = challenges[chIds[j]];
      _analyzeChallenge(ch, now);

      if (ch.status !== "secure") {
        results.challengeRisks.push({
          id: ch.id,
          status: ch.status,
          botSuccessRate: Math.round(ch.currentBotSuccessRate * 1000) / 1000,
          totalAttempts: ch.totalAttempts,
          predictedCompromiseEpoch: ch.predictedCompromiseEpoch,
          strategiesTargeting: Object.keys(ch.strategiesTargeting).length
        });
      }

      // Generate rotation recommendation if needed
      var rec = _rotationRecommendation(ch, now);
      if (rec) {
        results.rotationRecommendations.push(rec);
      }
    }

    results.summary = {
      totalStrategies: ids.length,
      active: totalActive,
      adapting: totalAdapting,
      evolved: totalEvolved,
      dormant: totalDormant,
      totalChallenges: chIds.length,
      challengesAtRisk: results.challengeRisks.length,
      pendingRotations: results.rotationRecommendations.length,
      totalEvents: events.length,
      evolutionEvents: evolutionTimeline.length
    };

    return results;
  }

  function _analyzeStrategy(strat, now) {
    // Dormancy check
    if (now - strat.lastSeen > windowMs * 2) {
      strat.status = "dormant";
      return;
    }

    if (strat.totalAttempts < minObservations) {
      strat.status = "active";
      return;
    }

    // Compute learning rate from epoch history using linear regression
    var history = strat.epochHistory;
    if (history.length >= 3) {
      var points = [];
      for (var i = 0; i < history.length; i++) {
        if (history[i].attempts >= 2) {
          points.push([history[i].epoch, history[i].rate]);
        }
      }

      if (points.length >= 3) {
        // Normalize x values to start from 0
        var x0 = points[0][0];
        var normPoints = [];
        for (var k = 0; k < points.length; k++) {
          normPoints.push([points[k][0] - x0, points[k][1]]);
        }
        var reg = _linearRegression(normPoints);
        strat.learningRate = reg.slope;
        strat.r2 = reg.r2;
      }
    }

    // Track peak
    var overallRate = strat.totalSuccesses / strat.totalAttempts;
    if (overallRate > strat.peakRate) {
      strat.peakRate = overallRate;
      strat.peakEpoch = currentEpoch;
    }

    // Classify
    if (overallRate >= compromiseThreshold) {
      strat.status = "evolved";
    } else if (strat.learningRate >= learningRateThreshold && strat.r2 >= 0.3) {
      strat.status = "adapting";
    } else {
      strat.status = "active";
    }
  }

  function _analyzeChallenge(ch, now) {
    if (ch.totalAttempts < minObservations) {
      ch.status = "secure";
      return;
    }

    var rate = ch.currentBotSuccessRate;

    if (rate >= compromiseThreshold) {
      ch.status = "compromised";
    } else if (rate >= warningThreshold) {
      ch.status = "at-risk";
    } else if (rate >= warningThreshold * 0.6) {
      ch.status = "warning";
    } else {
      ch.status = "secure";
    }

    // Predict time-to-compromise using epoch history regression
    ch.predictedCompromiseEpoch = null;
    var history = ch.epochHistory;
    if (history.length >= 3) {
      var points = [];
      for (var i = 0; i < history.length; i++) {
        if (history[i].attempts >= 2) {
          points.push([history[i].epoch, history[i].rate]);
        }
      }

      if (points.length >= 3) {
        var x0 = points[0][0];
        var normPoints = [];
        for (var k = 0; k < points.length; k++) {
          normPoints.push([points[k][0] - x0, points[k][1]]);
        }
        var reg = _linearRegression(normPoints);

        // If slope is positive and fit is decent, predict when rate hits threshold
        if (reg.slope > 0 && reg.r2 >= 0.25) {
          var currentX = points[points.length - 1][0] - x0;
          var currentY = reg.slope * currentX + reg.intercept;
          var epochsToCompromise = (compromiseThreshold - currentY) / reg.slope;
          if (epochsToCompromise > 0 && epochsToCompromise <= predictionHorizonEpochs) {
            ch.predictedCompromiseEpoch = Math.ceil(currentX + epochsToCompromise + x0);
          }
        }
      }
    }
  }

  function _rotationRecommendation(ch, now) {
    if (ch.status === "secure") return null;
    if (ch.lastRotationRecommendedAt &&
        now - ch.lastRotationRecommendedAt < rotationCooldownMs) {
      return null;
    }

    var urgency = "low";
    var reason = "";

    if (ch.status === "compromised") {
      urgency = "critical";
      reason = "Challenge bot success rate (" +
        Math.round(ch.currentBotSuccessRate * 100) + "%) exceeds compromise threshold";
    } else if (ch.predictedCompromiseEpoch !== null) {
      urgency = "high";
      var epochsLeft = ch.predictedCompromiseEpoch - currentEpoch;
      reason = "Predicted compromise in ~" + epochsLeft + " epochs (" +
        Math.round(epochsLeft * epochMs / 60000) + " min) based on trend analysis";
    } else if (ch.status === "at-risk") {
      urgency = "medium";
      reason = "Bot success rate rising (" +
        Math.round(ch.currentBotSuccessRate * 100) + "%), approaching compromise threshold";
    } else {
      urgency = "low";
      reason = "Early warning: bot success rate above baseline (" +
        Math.round(ch.currentBotSuccessRate * 100) + "%)";
    }

    // Identify which strategies are most dangerous to this challenge
    var topStrategies = [];
    var stratIds = Object.keys(ch.strategiesTargeting);
    stratIds.sort(function (a, b) {
      return ch.strategiesTargeting[b] - ch.strategiesTargeting[a];
    });
    for (var i = 0; i < Math.min(3, stratIds.length); i++) {
      var s = strategies[stratIds[i]];
      topStrategies.push({
        id: stratIds[i],
        attempts: ch.strategiesTargeting[stratIds[i]],
        status: s ? s.status : "unknown",
        learningRate: s ? Math.round(s.learningRate * 10000) / 10000 : 0
      });
    }

    ch.lastRotationRecommendedAt = now;

    var rec = {
      challengeId: ch.id,
      urgency: urgency,
      reason: reason,
      topThreats: topStrategies,
      recommendation: _generateRecommendation(ch, urgency),
      timestamp: now
    };

    rotationLog.push(rec);

    evolutionTimeline.push({
      ts: now,
      type: "rotation_recommended",
      details: { challengeId: ch.id, urgency: urgency }
    });

    return rec;
  }

  function _generateRecommendation(ch, urgency) {
    if (urgency === "critical") {
      return "Immediately retire this challenge and deploy replacement. " +
        "Bots have achieved consistent bypass capability.";
    }
    if (urgency === "high") {
      return "Schedule rotation within next maintenance window. " +
        "Increase challenge difficulty or switch to a different challenge type. " +
        "Consider deploying a honeypot variant to study attacker techniques.";
    }
    if (urgency === "medium") {
      return "Monitor closely and prepare a replacement challenge. " +
        "Consider adding additional verification layers (proof-of-work, behavioral checks).";
    }
    return "No immediate action needed but track the trend. " +
      "Review if new bot strategies are targeting this challenge type.";
  }

  // ── Get Strategy Lineage (ancestry chain) ───────────────────────
  function getLineage(strategyId) {
    var chain = [];
    var visited = {};
    var current = strategyId;

    while (current && !visited[current] && chain.length < lineageDepth) {
      visited[current] = true;
      var strat = strategies[current];
      if (!strat) break;

      chain.push({
        id: strat.id,
        generation: strat.generation,
        successRate: strat.totalAttempts > 0
          ? Math.round((strat.totalSuccesses / strat.totalAttempts) * 1000) / 1000
          : 0,
        status: strat.status,
        firstSeen: strat.firstSeen,
        lastSeen: strat.lastSeen
      });

      current = strat.parentId;
    }

    return chain;
  }

  // ── Get Evolution Timeline ──────────────────────────────────────
  function getTimeline(opts) {
    opts = opts || {};
    var limit = _optNum(opts.limit, 50);
    var typeFilter = opts.type || null;

    var result = evolutionTimeline;
    if (typeFilter) {
      result = [];
      for (var i = 0; i < evolutionTimeline.length; i++) {
        if (evolutionTimeline[i].type === typeFilter) {
          result.push(evolutionTimeline[i]);
        }
      }
    }

    if (result.length > limit) {
      result = result.slice(result.length - limit);
    }

    return result;
  }

  // ── Threat Forecast ─────────────────────────────────────────────
  function forecast() {
    var predictions = [];
    var chIds = Object.keys(challenges);

    for (var i = 0; i < chIds.length; i++) {
      var ch = challenges[chIds[i]];
      if (ch.totalAttempts < minObservations) continue;

      var history = ch.epochHistory;
      if (history.length < 3) continue;

      var points = [];
      for (var j = 0; j < history.length; j++) {
        if (history[j].attempts >= 2) {
          points.push([history[j].epoch, history[j].rate]);
        }
      }
      if (points.length < 3) continue;

      var x0 = points[0][0];
      var normPoints = [];
      for (var k = 0; k < points.length; k++) {
        normPoints.push([points[k][0] - x0, points[k][1]]);
      }
      var reg = _linearRegression(normPoints);

      var lastEpoch = points[points.length - 1][0];
      var forecastPoints = [];
      for (var e = 1; e <= predictionHorizonEpochs; e++) {
        var futureX = lastEpoch - x0 + e;
        var predicted = _clamp(reg.slope * futureX + reg.intercept, 0, 1);
        forecastPoints.push({
          epoch: lastEpoch + e,
          predictedRate: Math.round(predicted * 1000) / 1000
        });
      }

      predictions.push({
        challengeId: ch.id,
        currentRate: Math.round(ch.currentBotSuccessRate * 1000) / 1000,
        trend: reg.slope > 0.001 ? "rising" : (reg.slope < -0.001 ? "falling" : "stable"),
        trendSlope: Math.round(reg.slope * 10000) / 10000,
        r2: Math.round(reg.r2 * 1000) / 1000,
        forecast: forecastPoints,
        willReachCompromise: forecastPoints.some(function (p) {
          return p.predictedRate >= compromiseThreshold;
        })
      });
    }

    // Sort by risk: rising trends first, then by current rate
    predictions.sort(function (a, b) {
      if (a.willReachCompromise !== b.willReachCompromise) {
        return a.willReachCompromise ? -1 : 1;
      }
      return b.trendSlope - a.trendSlope;
    });

    return predictions;
  }

  // ── Export / Import State ───────────────────────────────────────
  function exportState() {
    return {
      strategies: strategies,
      challenges: challenges,
      events: events.slice(-1000),  // keep last 1000 for export
      evolutionTimeline: evolutionTimeline,
      rotationLog: rotationLog,
      currentEpoch: currentEpoch
    };
  }

  /**
   * Reject prototype-pollution keys (CWE-1321).
   * @param {string} key
   * @returns {boolean}
   */
  function _isSafeKey(key) {
    return key !== "__proto__" && key !== "constructor" && key !== "prototype";
  }

  /**
   * Copy own, safe keys from *src* into a null-prototype container.
   * Skips __proto__ / constructor / prototype to prevent CWE-1321
   * prototype pollution via crafted import payloads.
   * @param {Object} src
   * @returns {Object}
   */
  function _sanitizeMap(src) {
    var out = Object.create(null);
    if (!src || typeof src !== "object" || Array.isArray(src)) return out;
    var keys = Object.keys(src);
    for (var i = 0; i < keys.length; i++) {
      if (_isSafeKey(keys[i]) && src[keys[i]] && typeof src[keys[i]] === "object") {
        out[keys[i]] = src[keys[i]];
      }
    }
    return out;
  }

  function importState(state) {
    if (!state || typeof state !== "object") return false;
    if (state.strategies) strategies = _sanitizeMap(state.strategies);
    if (state.challenges) challenges = _sanitizeMap(state.challenges);
    if (Array.isArray(state.events)) events = state.events;
    if (Array.isArray(state.evolutionTimeline)) evolutionTimeline = state.evolutionTimeline;
    if (Array.isArray(state.rotationLog)) rotationLog = state.rotationLog;
    if (typeof state.currentEpoch === "number") currentEpoch = state.currentEpoch;
    // Rebuild strategyOrder
    strategyOrder = Object.keys(strategies);
    return true;
  }

  // ── Reset ───────────────────────────────────────────────────────
  function reset() {
    strategies = {};
    challenges = {};
    events = [];
    strategyOrder = [];
    currentEpoch = 0;
    rotationLog = [];
    evolutionTimeline = [];
  }

  // ── Public API ──────────────────────────────────────────────────
  return {
    recordAttempt: recordAttempt,
    analyze: analyze,
    forecast: forecast,
    getLineage: getLineage,
    getTimeline: getTimeline,
    exportState: exportState,
    importState: importState,
    reset: reset,
    _strategies: function () { return strategies; },
    _challenges: function () { return challenges; },
    _events: function () { return events; }
  };
}

// ── Exports ─────────────────────────────────────────────────────────

module.exports = { createAttackEvolutionTracker: createAttackEvolutionTracker };
