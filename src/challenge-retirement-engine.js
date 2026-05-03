/**
 * ChallengeRetirementEngine — Autonomous challenge lifecycle management.
 *
 * Detects when CAPTCHA challenges have been cracked/compromised by bots and
 * proactively retires them before they become security liabilities. Tracks
 * effectiveness decay, detects burst attacks, correlates cross-challenge
 * compromises, and schedules graceful retirements.
 *
 * Key capabilities:
 *   - Track solve rate per challenge with bot/human distinction
 *   - Detect time-to-solve anomalies (bots getting faster)
 *   - Identify burst attacks (sudden automated solve spikes)
 *   - Model effectiveness decay with configurable half-life
 *   - Correlate simultaneous compromises across related challenges
 *   - Grade challenges into tiers (ACTIVE/WARNING/PROBATION/RETIRED)
 *   - Generate autonomous fleet health insights and recommendations
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/challenge-retirement-engine
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _clamp = _shared._clamp;
var _posOpt = _shared._posOpt;
var _nnOpt = _shared._nnOpt;
var _mean = _shared._mean;
var LruTracker = _shared.LruTracker;

// ── Constants ───────────────────────────────────────────────────────

/** Challenge lifecycle tiers */
var TIERS = {
  ACTIVE: "ACTIVE",
  WARNING: "WARNING",
  PROBATION: "PROBATION",
  RETIRED: "RETIRED"
};

/** Tier thresholds (effectiveness score) */
var TIER_THRESHOLDS = {
  ACTIVE: 70,
  WARNING: 50,
  PROBATION: 30
};

/** Default configuration */
var DEFAULTS = {
  solveRateThreshold: 0.7,
  minAttempts: 20,
  timeDecayHalfLifeMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  burstWindowMs: 60000,
  burstThreshold: 10,
  maxChallenges: 500,
  gracePeriodMs: 24 * 60 * 60 * 1000, // 24 hours
  correlationThreshold: 0.6,
  maxAttemptsPerChallenge: 1000
};

// ── Helper Functions ────────────────────────────────────────────────


function _decayFactor(ageMs, halfLifeMs) {
  if (ageMs <= 0) return 1;
  return Math.pow(0.5, ageMs / halfLifeMs);
}

function _tierFromScore(score) {
  if (score >= TIER_THRESHOLDS.ACTIVE) return TIERS.ACTIVE;
  if (score >= TIER_THRESHOLDS.WARNING) return TIERS.WARNING;
  if (score >= TIER_THRESHOLDS.PROBATION) return TIERS.PROBATION;
  return TIERS.RETIRED;
}

// ── Challenge Record ────────────────────────────────────────────────

function ChallengeRecord(id, nowMs) {
  this.id = id;
  this.createdAt = nowMs;
  this.totalAttempts = 0;
  this.botAttempts = 0;
  this.botSolves = 0;
  this.humanAttempts = 0;
  this.humanSolves = 0;
  this.solveTimes = [];       // recent solve times (ms)
  this.recentTimestamps = []; // recent attempt timestamps for burst detection
  this.tier = TIERS.ACTIVE;
  this.effectivenessScore = 100;
  this.lastAttemptAt = nowMs;
  this.retiredAt = null;
  this.retiredReason = null;
  this.probationStartedAt = null;
  this.warnings = [];
  this.category = null;
}

// ── Main Engine ─────────────────────────────────────────────────────

/**
 * @constructor
 * @param {Object} [options] Configuration options
 */
function ChallengeRetirementEngine(options) {
  var opts = options || {};
  this._solveRateThreshold = _posOpt(opts.solveRateThreshold, DEFAULTS.solveRateThreshold);
  this._minAttempts = _posOpt(opts.minAttempts, DEFAULTS.minAttempts);
  this._timeDecayHalfLifeMs = _posOpt(opts.timeDecayHalfLifeMs, DEFAULTS.timeDecayHalfLifeMs);
  this._burstWindowMs = _posOpt(opts.burstWindowMs, DEFAULTS.burstWindowMs);
  this._burstThreshold = _posOpt(opts.burstThreshold, DEFAULTS.burstThreshold);
  this._maxChallenges = _posOpt(opts.maxChallenges, DEFAULTS.maxChallenges);
  this._gracePeriodMs = _posOpt(opts.gracePeriodMs, DEFAULTS.gracePeriodMs);
  this._correlationThreshold = _posOpt(opts.correlationThreshold, DEFAULTS.correlationThreshold);
  this._maxAttemptsPerChallenge = _posOpt(opts.maxAttemptsPerChallenge, DEFAULTS.maxAttemptsPerChallenge);

  this._challenges = Object.create(null); // id → ChallengeRecord
  this._lru = new LruTracker();
  this._retirementLog = []; // { id, retiredAt, reason }
  this._insights = [];
}

/**
 * Record a solve attempt for a challenge.
 *
 * @param {string} challengeId - Unique challenge identifier
 * @param {Object} attempt - Attempt details
 * @param {boolean} attempt.solved - Whether the attempt was successful
 * @param {number} [attempt.timeMs] - Time to solve in milliseconds
 * @param {boolean} [attempt.isBot] - Whether the solver is classified as a bot
 * @param {number} [attempt.timestamp] - Attempt timestamp (defaults to now)
 * @param {string} [attempt.category] - Challenge category for correlation
 */
ChallengeRetirementEngine.prototype.recordAttempt = function (challengeId, attempt) {
  if (!challengeId || typeof challengeId !== "string") return;
  if (!attempt || typeof attempt !== "object") return;

  var nowMs = (attempt.timestamp != null && attempt.timestamp > 0) ? attempt.timestamp : _now();
  var rec = this._challenges[challengeId];

  if (!rec) {
    // Evict if at capacity
    if (this._lru.length >= this._maxChallenges) {
      var evicted = this._lru.evictOldest();
      if (evicted) delete this._challenges[evicted];
    }
    rec = new ChallengeRecord(challengeId, nowMs);
    this._challenges[challengeId] = rec;
    this._lru.push(challengeId);
  } else {
    this._lru.touch(challengeId);
  }

  if (attempt.category) rec.category = attempt.category;
  rec.totalAttempts++;
  rec.lastAttemptAt = nowMs;

  // Track bot vs human
  if (attempt.isBot) {
    rec.botAttempts++;
    if (attempt.solved) rec.botSolves++;
  } else {
    rec.humanAttempts++;
    if (attempt.solved) rec.humanSolves++;
  }

  // Track solve times (keep last N)
  if (attempt.solved && attempt.timeMs != null && attempt.timeMs > 0) {
    rec.solveTimes.push(attempt.timeMs);
    if (rec.solveTimes.length > 100) rec.solveTimes.shift();
  }

  // Track timestamps for burst detection (keep within window)
  rec.recentTimestamps.push(nowMs);
  while (rec.recentTimestamps.length > 0 && (nowMs - rec.recentTimestamps[0]) > this._burstWindowMs * 2) {
    rec.recentTimestamps.shift();
  }

  // Trim to max attempts
  if (rec.totalAttempts > this._maxAttemptsPerChallenge) {
    // We only track aggregate stats, so no data loss
  }

  // Recalculate effectiveness
  this._recalculate(rec, nowMs);
};

/**
 * Get the current status of a challenge.
 *
 * @param {string} challengeId
 * @returns {Object|null} Status object or null if not found
 */
ChallengeRetirementEngine.prototype.getStatus = function (challengeId) {
  var rec = this._challenges[challengeId];
  if (!rec) return null;
  return {
    id: rec.id,
    tier: rec.tier,
    effectivenessScore: rec.effectivenessScore,
    totalAttempts: rec.totalAttempts,
    botSolveRate: rec.botAttempts > 0 ? rec.botSolves / rec.botAttempts : 0,
    humanSolveRate: rec.humanAttempts > 0 ? rec.humanSolves / rec.humanAttempts : 0,
    avgSolveTimeMs: _mean(rec.solveTimes),
    createdAt: rec.createdAt,
    lastAttemptAt: rec.lastAttemptAt,
    retiredAt: rec.retiredAt,
    retiredReason: rec.retiredReason,
    category: rec.category,
    warnings: rec.warnings.slice()
  };
};

/**
 * Run full fleet analysis across all tracked challenges.
 *
 * @returns {Object} Analysis results with fleet health, retirement queue, and insights
 */
ChallengeRetirementEngine.prototype.analyze = function () {
  var nowMs = _now();
  var challenges = [];
  var retirementQueue = [];
  var tierCounts = { ACTIVE: 0, WARNING: 0, PROBATION: 0, RETIRED: 0 };
  var totalScore = 0;
  var activeCount = 0;

  var ids = Object.keys(this._challenges);
  for (var i = 0; i < ids.length; i++) {
    var rec = this._challenges[ids[i]];
    this._recalculate(rec, nowMs);
    var status = this.getStatus(ids[i]);
    challenges.push(status);
    tierCounts[rec.tier]++;

    if (rec.tier !== TIERS.RETIRED) {
      totalScore += rec.effectivenessScore;
      activeCount++;
    }

    if (rec.tier === TIERS.PROBATION || rec.tier === TIERS.RETIRED) {
      retirementQueue.push(status);
    }
  }

  var fleetHealth = activeCount > 0 ? Math.round(totalScore / activeCount) : 0;
  var insights = this._generateInsights(challenges, tierCounts, fleetHealth, nowMs);
  this._insights = insights;

  return {
    challenges: challenges,
    fleetHealth: fleetHealth,
    tierCounts: tierCounts,
    retirementQueue: retirementQueue,
    insights: insights,
    totalTracked: ids.length
  };
};

/**
 * Manually retire a challenge.
 *
 * @param {string} challengeId
 * @param {string} [reason] - Retirement reason
 * @returns {boolean} True if retired, false if not found
 */
ChallengeRetirementEngine.prototype.retire = function (challengeId, reason) {
  var rec = this._challenges[challengeId];
  if (!rec) return false;
  rec.tier = TIERS.RETIRED;
  rec.retiredAt = _now();
  rec.retiredReason = reason || "manual";
  rec.effectivenessScore = 0;
  this._retirementLog.push({ id: challengeId, retiredAt: rec.retiredAt, reason: rec.retiredReason });
  return true;
};

/**
 * Reinstate a retired challenge.
 *
 * @param {string} challengeId
 * @returns {boolean} True if reinstated, false if not found or not retired
 */
ChallengeRetirementEngine.prototype.reinstate = function (challengeId) {
  var rec = this._challenges[challengeId];
  if (!rec || rec.tier !== TIERS.RETIRED) return false;
  rec.tier = TIERS.PROBATION;
  rec.effectivenessScore = 40;
  rec.retiredAt = null;
  rec.retiredReason = null;
  rec.probationStartedAt = _now();
  rec.warnings = [];
  return true;
};

/**
 * Get the retirement log (history of all retirements).
 *
 * @returns {Array} Retirement log entries
 */
ChallengeRetirementEngine.prototype.getRetirementLog = function () {
  return this._retirementLog.slice();
};

/**
 * Export full engine state for persistence.
 *
 * @returns {Object} Serializable state
 */
ChallengeRetirementEngine.prototype.exportState = function () {
  var challengeData = {};
  var ids = Object.keys(this._challenges);
  for (var i = 0; i < ids.length; i++) {
    var rec = this._challenges[ids[i]];
    challengeData[ids[i]] = {
      id: rec.id,
      createdAt: rec.createdAt,
      totalAttempts: rec.totalAttempts,
      botAttempts: rec.botAttempts,
      botSolves: rec.botSolves,
      humanAttempts: rec.humanAttempts,
      humanSolves: rec.humanSolves,
      solveTimes: rec.solveTimes.slice(),
      recentTimestamps: rec.recentTimestamps.slice(),
      tier: rec.tier,
      effectivenessScore: rec.effectivenessScore,
      lastAttemptAt: rec.lastAttemptAt,
      retiredAt: rec.retiredAt,
      retiredReason: rec.retiredReason,
      probationStartedAt: rec.probationStartedAt,
      warnings: rec.warnings.slice(),
      category: rec.category
    };
  }
  return {
    version: 1,
    challenges: challengeData,
    lruOrder: this._lru.toArray(),
    retirementLog: this._retirementLog.slice(),
    config: {
      solveRateThreshold: this._solveRateThreshold,
      minAttempts: this._minAttempts,
      timeDecayHalfLifeMs: this._timeDecayHalfLifeMs,
      burstWindowMs: this._burstWindowMs,
      burstThreshold: this._burstThreshold,
      maxChallenges: this._maxChallenges,
      gracePeriodMs: this._gracePeriodMs,
      correlationThreshold: this._correlationThreshold
    }
  };
};

/**
 * Import previously exported state.
 *
 * @param {Object} state - State object from exportState()
 * @returns {boolean} True if imported successfully
 */
ChallengeRetirementEngine.prototype.importState = function (state) {
  if (!state || state.version !== 1) return false;
  this._challenges = Object.create(null);
  this._lru = new LruTracker();
  this._retirementLog = state.retirementLog ? state.retirementLog.slice() : [];

  var ids = Object.keys(state.challenges || {});
  for (var i = 0; i < ids.length; i++) {
    var data = state.challenges[ids[i]];
    var rec = new ChallengeRecord(data.id, data.createdAt);
    rec.totalAttempts = data.totalAttempts || 0;
    rec.botAttempts = data.botAttempts || 0;
    rec.botSolves = data.botSolves || 0;
    rec.humanAttempts = data.humanAttempts || 0;
    rec.humanSolves = data.humanSolves || 0;
    rec.solveTimes = (data.solveTimes || []).slice();
    rec.recentTimestamps = (data.recentTimestamps || []).slice();
    rec.tier = data.tier || TIERS.ACTIVE;
    rec.effectivenessScore = data.effectivenessScore != null ? data.effectivenessScore : 100;
    rec.lastAttemptAt = data.lastAttemptAt || data.createdAt;
    rec.retiredAt = data.retiredAt || null;
    rec.retiredReason = data.retiredReason || null;
    rec.probationStartedAt = data.probationStartedAt || null;
    rec.warnings = (data.warnings || []).slice();
    rec.category = data.category || null;
    this._challenges[ids[i]] = rec;
  }

  // Restore LRU order
  if (state.lruOrder && state.lruOrder.length > 0) {
    this._lru.fromArray(state.lruOrder);
  } else {
    for (var j = 0; j < ids.length; j++) {
      this._lru.push(ids[j]);
    }
  }

  return true;
};

// ── Internal Methods ────────────────────────────────────────────────

/**
 * Recalculate effectiveness score and tier for a challenge.
 * @private
 */
ChallengeRetirementEngine.prototype._recalculate = function (rec, nowMs) {
  if (rec.tier === TIERS.RETIRED) return;
  if (rec.totalAttempts < this._minAttempts) return;
  // Always use real current time for decay calculation
  var currentTime = _now();
  if (nowMs > currentTime) currentTime = nowMs;

  var scores = [];

  // 1. Solve Rate Score (lower bot solve rate = better)
  var botSolveRate = rec.botAttempts > 0 ? rec.botSolves / rec.botAttempts : 0;
  var solveRateScore = 100 * (1 - botSolveRate / this._solveRateThreshold);
  solveRateScore = _clamp(solveRateScore, 0, 100);
  scores.push(solveRateScore);

  // 2. Time Decay Score (older challenges lose effectiveness)
  var ageMs = currentTime - rec.createdAt;
  var decayScore = 100 * _decayFactor(ageMs, this._timeDecayHalfLifeMs);
  scores.push(decayScore);

  // 3. Time-to-Solve Score (faster bot solves = worse)
  var timeScore = 100;
  if (rec.solveTimes.length >= 5) {
    var recentTimes = rec.solveTimes.slice(-10);
    var olderTimes = rec.solveTimes.slice(0, Math.max(1, rec.solveTimes.length - 10));
    var recentMean = _mean(recentTimes);
    var olderMean = _mean(olderTimes);
    if (olderMean > 0) {
      var speedup = (olderMean - recentMean) / olderMean;
      // Significant speedup (>30%) indicates bots learning
      if (speedup > 0.3) {
        timeScore = 100 * (1 - speedup);
        timeScore = _clamp(timeScore, 0, 100);
      }
    }
  }
  scores.push(timeScore);

  // 4. Burst Score (recent bursts reduce effectiveness)
  var burstScore = 100;
  var recentInWindow = 0;
  for (var i = 0; i < rec.recentTimestamps.length; i++) {
    if ((currentTime - rec.recentTimestamps[i]) <= this._burstWindowMs) {
      recentInWindow++;
    }
  }
  if (recentInWindow >= this._burstThreshold) {
    burstScore = 100 * (1 - (recentInWindow - this._burstThreshold) / (this._burstThreshold * 3));
    burstScore = _clamp(burstScore, 0, 100);
  }
  scores.push(burstScore);

  // Composite score (weighted average)
  var weights = [0.4, 0.2, 0.2, 0.2]; // solve rate most important
  var weighted = 0;
  for (var w = 0; w < scores.length; w++) {
    weighted += scores[w] * weights[w];
  }
  rec.effectivenessScore = Math.round(_clamp(weighted, 0, 100));

  // Update warnings
  rec.warnings = [];
  if (botSolveRate > this._solveRateThreshold) {
    rec.warnings.push("Bot solve rate " + Math.round(botSolveRate * 100) + "% exceeds threshold");
  }
  if (timeScore < 70) {
    rec.warnings.push("Solve times dropping — possible bot learning");
  }
  if (burstScore < 70) {
    rec.warnings.push("Burst attack detected — " + recentInWindow + " attempts in window");
  }

  // Tier assignment
  var newTier = _tierFromScore(rec.effectivenessScore);

  // Grace period for probation → retired
  if (newTier === TIERS.RETIRED && rec.tier === TIERS.PROBATION) {
    if (rec.probationStartedAt && (nowMs - rec.probationStartedAt) < this._gracePeriodMs) {
      newTier = TIERS.PROBATION; // keep in probation during grace
    } else {
      // Grace period expired, retire
      rec.retiredAt = nowMs;
      rec.retiredReason = "auto-retired: effectiveness score " + rec.effectivenessScore;
      this._retirementLog.push({ id: rec.id, retiredAt: nowMs, reason: rec.retiredReason });
    }
  }

  // Track probation start
  if (newTier === TIERS.PROBATION && rec.tier !== TIERS.PROBATION) {
    rec.probationStartedAt = nowMs;
  }

  rec.tier = newTier;
};

/**
 * Generate fleet-level insights.
 * @private
 */
ChallengeRetirementEngine.prototype._generateInsights = function (challenges, tierCounts, fleetHealth, nowMs) {
  var insights = [];
  var total = challenges.length;
  if (total === 0) return insights;

  // Fleet health insight
  if (fleetHealth < 50) {
    insights.push({
      type: "CRITICAL",
      message: "Fleet health critically low at " + fleetHealth + "% — immediate attention needed"
    });
  } else if (fleetHealth < 70) {
    insights.push({
      type: "WARNING",
      message: "Fleet health declining — " + fleetHealth + "% effectiveness average"
    });
  }

  // Tier distribution insight
  var degraded = tierCounts.WARNING + tierCounts.PROBATION + tierCounts.RETIRED;
  var degradedPct = Math.round((degraded / total) * 100);
  if (degradedPct > 40) {
    insights.push({
      type: "WARNING",
      message: degradedPct + "% of challenges in WARNING or worse — consider rotating challenge pool"
    });
  }

  // Category correlation insight
  var categoryRetirements = Object.create(null);
  for (var i = 0; i < challenges.length; i++) {
    var ch = challenges[i];
    if (ch.category && (ch.tier === TIERS.RETIRED || ch.tier === TIERS.PROBATION || ch.tier === TIERS.WARNING)) {
      if (!categoryRetirements[ch.category]) categoryRetirements[ch.category] = 0;
      categoryRetirements[ch.category]++;
    }
  }
  var cats = Object.keys(categoryRetirements);
  for (var c = 0; c < cats.length; c++) {
    if (categoryRetirements[cats[c]] >= 3) {
      insights.push({
        type: "CRITICAL",
        message: categoryRetirements[cats[c]] + " challenges in category '" + cats[c] + "' compromised — category may be cracked"
      });
    }
  }

  // Recent rapid degradation
  for (var j = 0; j < challenges.length; j++) {
    var ch2 = challenges[j];
    if (ch2.tier === TIERS.WARNING && ch2.warnings && ch2.warnings.length > 0) {
      insights.push({
        type: "INFO",
        message: "Challenge " + ch2.id + " showing signs of compromise: " + ch2.warnings[0]
      });
    }
  }

  // Recommendations
  if (tierCounts.ACTIVE < 5 && total > 5) {
    insights.push({
      type: "RECOMMENDATION",
      message: "Only " + tierCounts.ACTIVE + " active challenges remaining — add new challenges urgently"
    });
  }

  return insights;
};

/**
 * Detect cross-challenge correlation (challenges cracked simultaneously).
 *
 * @returns {Array} Groups of correlated challenges
 */
ChallengeRetirementEngine.prototype.detectCorrelations = function () {
  var groups = [];
  var ids = Object.keys(this._challenges);
  var checked = Object.create(null);

  for (var i = 0; i < ids.length; i++) {
    if (checked[ids[i]]) continue;
    var rec1 = this._challenges[ids[i]];
    if (rec1.tier === TIERS.ACTIVE) continue;
    if (!rec1.category) continue;

    var group = [ids[i]];
    checked[ids[i]] = true;

    for (var j = i + 1; j < ids.length; j++) {
      if (checked[ids[j]]) continue;
      var rec2 = this._challenges[ids[j]];
      if (rec2.tier === TIERS.ACTIVE) continue;

      // Correlation: same category + similar degradation timing
      if (rec1.category === rec2.category) {
        var timeDiff = Math.abs(rec1.lastAttemptAt - rec2.lastAttemptAt);
        if (timeDiff < this._burstWindowMs * 5) {
          group.push(ids[j]);
          checked[ids[j]] = true;
        }
      }
    }

    if (group.length >= 2) {
      groups.push({ category: rec1.category, challenges: group, size: group.length });
    }
  }

  return groups;
};

// ── Exports ─────────────────────────────────────────────────────────

module.exports = ChallengeRetirementEngine;
module.exports.TIERS = TIERS;
module.exports.TIER_THRESHOLDS = TIER_THRESHOLDS;
module.exports.DEFAULTS = DEFAULTS;
