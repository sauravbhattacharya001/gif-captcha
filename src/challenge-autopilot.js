/**
 * ChallengeAutopilot — Autonomous challenge lifecycle controller.
 *
 * Monitors challenge effectiveness in real time and makes autonomous decisions:
 * retiring compromised challenges, quarantining suspicious ones, promoting
 * recovered challenges, selecting optimal challenges per-session based on
 * threat signals, and self-monitoring its own decision quality.
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/challenge-autopilot
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _clamp = _shared._clamp;
var _mean = _shared._mean;
var _median = _shared._median;
var _stddev = _shared._stddev;

var _crypto = require("./crypto-utils");
var secureRandom = _crypto.secureRandom;

// ── Defaults ────────────────────────────────────────────────────────

var DEFAULTS = {
  targetSolveRateMin: 0.55,
  targetSolveRateMax: 0.75,
  botSolveRateThreshold: 0.4,
  minObservations: 20,
  cooldownMs: 60000,
  maxQuarantineSize: 50,
  selfMonitorWindow: 100,
  autoAct: false,
  maxChallenges: 10000,
  windowMs: 600000,         // 10 min sliding window
  quarantineTrafficFraction: 0.1,
  retireAfterQuarantineMs: 1800000  // 30 min in quarantine without recovery → retire
};

// ── Helpers ─────────────────────────────────────────────────────────

function _optNum(val, def) {
  return typeof val === "number" && val >= 0 ? val : def;
}

function _optBool(val, def) {
  return typeof val === "boolean" ? val : def;
}

function _makeSlidingWindow(windowMs) {
  return { entries: [], windowMs: windowMs };
}

function _pushWindow(win, entry) {
  win.entries.push(entry);
  _pruneWindow(win);
}

function _pruneWindow(win) {
  var cutoff = _now() - win.windowMs;
  while (win.entries.length > 0 && win.entries[0].ts < cutoff) {
    win.entries.shift();
  }
}

function _windowEntries(win) {
  _pruneWindow(win);
  return win.entries;
}

// ── Challenge Record ────────────────────────────────────────────────

function _createChallengeRecord(id) {
  return {
    id: id,
    status: "active",          // active | quarantined | retired
    createdAt: _now(),
    quarantinedAt: null,
    retiredAt: null,
    totalHuman: 0,
    totalBot: 0,
    humanSolves: 0,
    botSolves: 0,
    solveTimes: [],
    trustScores: [],
    weight: 1.0,               // selection weight
    lastDecisionAt: 0
  };
}

// ── Factory ─────────────────────────────────────────────────────────

/**
 * Create a ChallengeAutopilot instance.
 *
 * @param {Object} [options]
 * @param {Object} [options.targetSolveRate] - {min, max} target band
 * @param {number} [options.botSolveRateThreshold=0.4] - Above this, challenge is compromised
 * @param {number} [options.minObservations=20] - Min data points before deciding
 * @param {number} [options.cooldownMs=60000] - Min ms between decisions per challenge
 * @param {number} [options.maxQuarantineSize=50] - Max quarantined challenges
 * @param {number} [options.selfMonitorWindow=100] - Decision history for self-monitoring
 * @param {boolean} [options.autoAct=false] - Auto-execute decisions
 * @returns {Object} ChallengeAutopilot instance
 */
function createChallengeAutopilot(options) {
  options = options || {};
  var targetSolveRate = options.targetSolveRate || {};
  var cfg = {
    targetSolveRateMin: _optNum(targetSolveRate.min, DEFAULTS.targetSolveRateMin),
    targetSolveRateMax: _optNum(targetSolveRate.max, DEFAULTS.targetSolveRateMax),
    botSolveRateThreshold: _optNum(options.botSolveRateThreshold, DEFAULTS.botSolveRateThreshold),
    minObservations: _optNum(options.minObservations, DEFAULTS.minObservations),
    cooldownMs: _optNum(options.cooldownMs, DEFAULTS.cooldownMs),
    maxQuarantineSize: _optNum(options.maxQuarantineSize, DEFAULTS.maxQuarantineSize),
    selfMonitorWindow: _optNum(options.selfMonitorWindow, DEFAULTS.selfMonitorWindow),
    autoAct: _optBool(options.autoAct, DEFAULTS.autoAct),
    windowMs: _optNum(options.windowMs, DEFAULTS.windowMs),
    retireAfterQuarantineMs: _optNum(options.retireAfterQuarantineMs, DEFAULTS.retireAfterQuarantineMs)
  };

  // Challenge store: id → record
  var challenges = Object.create(null);
  // Sliding window of all outcomes for trend analysis
  var globalWindow = _makeSlidingWindow(cfg.windowMs);
  // Decision history for self-monitoring
  var decisionHistory = [];

  // ── Internal Helpers ────────────────────────────────────────────

  function _getOrCreate(challengeId) {
    if (!challenges[challengeId]) {
      challenges[challengeId] = _createChallengeRecord(challengeId);
    }
    return challenges[challengeId];
  }

  function _humanSolveRate(rec) {
    return rec.totalHuman > 0 ? rec.humanSolves / rec.totalHuman : null;
  }

  function _botSolveRate(rec) {
    return rec.totalBot > 0 ? rec.botSolves / rec.totalBot : null;
  }

  function _totalObservations(rec) {
    return rec.totalHuman + rec.totalBot;
  }

  function _canDecide(rec) {
    return _totalObservations(rec) >= cfg.minObservations &&
           (_now() - rec.lastDecisionAt) >= cfg.cooldownMs;
  }

  function _countByStatus(status) {
    var count = 0;
    var ids = Object.keys(challenges);
    for (var i = 0; i < ids.length; i++) {
      if (challenges[ids[i]].status === status) count++;
    }
    return count;
  }

  function _recordDecision(decision) {
    decisionHistory.push({
      ts: _now(),
      challengeId: decision.challengeId,
      action: decision.action,
      confidence: decision.confidence,
      evidence: decision.evidence
    });
    if (decisionHistory.length > cfg.selfMonitorWindow * 2) {
      decisionHistory = decisionHistory.slice(-cfg.selfMonitorWindow);
    }
  }

  function _applyDecision(decision) {
    var rec = challenges[decision.challengeId];
    if (!rec) return;
    rec.lastDecisionAt = _now();
    switch (decision.action) {
      case "retire":
        rec.status = "retired";
        rec.retiredAt = _now();
        break;
      case "quarantine":
        if (rec.status !== "quarantined") {
          rec.status = "quarantined";
          rec.quarantinedAt = _now();
        }
        break;
      case "promote":
        rec.status = "active";
        rec.quarantinedAt = null;
        rec.weight = Math.min(rec.weight + 0.2, 2.0);
        break;
      case "boost":
        rec.weight = Math.min(rec.weight + 0.3, 3.0);
        break;
      case "demote":
        rec.weight = Math.max(rec.weight - 0.2, 0.1);
        break;
    }
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Record an outcome for a challenge.
   *
   * @param {string} challengeId
   * @param {Object} outcome
   * @param {boolean} outcome.solved
   * @param {boolean} outcome.isBot
   * @param {number} [outcome.timeMs]
   * @param {number} [outcome.trustScore]
   */
  function recordOutcome(challengeId, outcome) {
    if (!challengeId || typeof challengeId !== "string") {
      throw new Error("challengeId must be a non-empty string");
    }
    if (!outcome || typeof outcome !== "object") {
      throw new Error("outcome must be an object");
    }
    var rec = _getOrCreate(challengeId);
    var isBot = !!outcome.isBot;
    var solved = !!outcome.solved;

    if (isBot) {
      rec.totalBot++;
      if (solved) rec.botSolves++;
    } else {
      rec.totalHuman++;
      if (solved) rec.humanSolves++;
    }

    if (typeof outcome.timeMs === "number" && outcome.timeMs > 0) {
      rec.solveTimes.push(outcome.timeMs);
      if (rec.solveTimes.length > 200) {
        rec.solveTimes = rec.solveTimes.slice(-100);
      }
    }

    if (typeof outcome.trustScore === "number") {
      rec.trustScores.push(outcome.trustScore);
      if (rec.trustScores.length > 200) {
        rec.trustScores = rec.trustScores.slice(-100);
      }
    }

    _pushWindow(globalWindow, {
      ts: _now(),
      challengeId: challengeId,
      isBot: isBot,
      solved: solved
    });
  }

  /**
   * Register a challenge (without waiting for outcomes).
   *
   * @param {string} challengeId
   * @returns {Object} challenge record
   */
  function registerChallenge(challengeId) {
    if (!challengeId || typeof challengeId !== "string") {
      throw new Error("challengeId must be a non-empty string");
    }
    return _getOrCreate(challengeId);
  }

  /**
   * Evaluate all challenges and return autonomous decisions.
   *
   * @returns {Object[]} Array of decision objects
   */
  function evaluate() {
    var decisions = [];
    var ids = Object.keys(challenges);
    var now = _now();

    for (var i = 0; i < ids.length; i++) {
      var rec = challenges[ids[i]];

      // Skip retired challenges
      if (rec.status === "retired") continue;
      // Need enough data and cooldown
      if (!_canDecide(rec)) continue;

      var humanRate = _humanSolveRate(rec);
      var botRate = _botSolveRate(rec);
      var decision = null;

      // ── Compromised check: bots solving too often ──
      if (botRate !== null && botRate >= cfg.botSolveRateThreshold && rec.totalBot >= 5) {
        if (rec.status === "quarantined") {
          // Already quarantined and still compromised → retire
          decision = {
            challengeId: ids[i],
            action: "retire",
            reason: "Bot solve rate (" + (botRate * 100).toFixed(1) + "%) exceeds threshold while quarantined",
            confidence: Math.min(0.6 + (rec.totalBot / 100), 0.95),
            evidence: { botSolveRate: botRate, totalBot: rec.totalBot, status: "quarantined" }
          };
        } else {
          // Active → quarantine first
          decision = {
            challengeId: ids[i],
            action: "quarantine",
            reason: "Bot solve rate (" + (botRate * 100).toFixed(1) + "%) exceeds threshold (" + (cfg.botSolveRateThreshold * 100) + "%)",
            confidence: Math.min(0.5 + (rec.totalBot / 50), 0.9),
            evidence: { botSolveRate: botRate, totalBot: rec.totalBot }
          };
        }
      }
      // ── Quarantine timeout ──
      else if (rec.status === "quarantined" && rec.quarantinedAt) {
        var quarantineDuration = now - rec.quarantinedAt;
        if (quarantineDuration > cfg.retireAfterQuarantineMs) {
          // Too long in quarantine without recovery
          decision = {
            challengeId: ids[i],
            action: "retire",
            reason: "Quarantined for " + Math.round(quarantineDuration / 60000) + " min without recovery",
            confidence: 0.7,
            evidence: { quarantineDurationMs: quarantineDuration }
          };
        } else if (botRate !== null && botRate < cfg.botSolveRateThreshold * 0.5) {
          // Recovered! Bot rate dropped well below threshold
          decision = {
            challengeId: ids[i],
            action: "promote",
            reason: "Bot solve rate recovered to " + (botRate * 100).toFixed(1) + "%, below recovery threshold",
            confidence: Math.min(0.5 + (rec.totalBot / 30), 0.85),
            evidence: { botSolveRate: botRate, recoveryThreshold: cfg.botSolveRateThreshold * 0.5 }
          };
        }
      }
      // ── Human solve rate checks ──
      else if (humanRate !== null && rec.totalHuman >= cfg.minObservations) {
        if (humanRate < cfg.targetSolveRateMin) {
          // Too hard for humans → demote (reduce selection weight)
          decision = {
            challengeId: ids[i],
            action: "demote",
            reason: "Human solve rate (" + (humanRate * 100).toFixed(1) + "%) below target min (" + (cfg.targetSolveRateMin * 100) + "%)",
            confidence: Math.min(0.4 + (rec.totalHuman / 80), 0.8),
            evidence: { humanSolveRate: humanRate, targetMin: cfg.targetSolveRateMin }
          };
        } else if (humanRate > cfg.targetSolveRateMax && (botRate === null || botRate < cfg.botSolveRateThreshold * 0.3)) {
          // Too easy for humans but bots aren't solving it → boost
          decision = {
            challengeId: ids[i],
            action: "boost",
            reason: "Human solve rate (" + (humanRate * 100).toFixed(1) + "%) above target max with low bot rate — challenge is effective",
            confidence: Math.min(0.5 + (rec.totalHuman / 60), 0.85),
            evidence: { humanSolveRate: humanRate, botSolveRate: botRate }
          };
        }
      }

      if (decision) {
        decisions.push(decision);
        _recordDecision(decision);
        if (cfg.autoAct) {
          _applyDecision(decision);
        }
      }
    }

    // ── Quarantine overflow cleanup ──
    var quarantinedCount = _countByStatus("quarantined");
    if (quarantinedCount > cfg.maxQuarantineSize) {
      var quarantined = [];
      var qids = Object.keys(challenges);
      for (var qi = 0; qi < qids.length; qi++) {
        if (challenges[qids[qi]].status === "quarantined") {
          quarantined.push(challenges[qids[qi]]);
        }
      }
      // Sort by quarantine time, oldest first
      quarantined.sort(function(a, b) { return (a.quarantinedAt || 0) - (b.quarantinedAt || 0); });
      var toRetire = quarantinedCount - cfg.maxQuarantineSize;
      for (var ri = 0; ri < toRetire; ri++) {
        var overflowDecision = {
          challengeId: quarantined[ri].id,
          action: "retire",
          reason: "Quarantine overflow — oldest quarantined challenge retired to make room",
          confidence: 0.6,
          evidence: { quarantineOverflow: true, quarantinedCount: quarantinedCount }
        };
        decisions.push(overflowDecision);
        _recordDecision(overflowDecision);
        if (cfg.autoAct) {
          _applyDecision(overflowDecision);
        }
      }
    }

    return decisions;
  }

  /**
   * Manually apply a decision (for when autoAct is false).
   *
   * @param {Object} decision - A decision from evaluate()
   */
  function applyDecision(decision) {
    if (!decision || !decision.challengeId || !decision.action) {
      throw new Error("Invalid decision object");
    }
    _applyDecision(decision);
  }

  /**
   * Select the optimal challenge for a session context.
   *
   * @param {Object} sessionContext
   * @param {number} [sessionContext.trustScore] - 0-1 trust score
   * @param {boolean} [sessionContext.isNewUser]
   * @param {string[]} [sessionContext.previousChallenges] - IDs to avoid
   * @returns {string|null} Selected challenge ID, or null if none available
   */
  function selectChallenge(sessionContext) {
    sessionContext = sessionContext || {};
    var trustScore = typeof sessionContext.trustScore === "number" ? sessionContext.trustScore : 0.5;
    var isNewUser = !!sessionContext.isNewUser;
    var previous = sessionContext.previousChallenges || [];
    var previousSet = Object.create(null);
    for (var pi = 0; pi < previous.length; pi++) {
      previousSet[previous[pi]] = true;
    }

    // Collect active challenges (include quarantined at reduced rate)
    var candidates = [];
    var ids = Object.keys(challenges);
    for (var i = 0; i < ids.length; i++) {
      var rec = challenges[ids[i]];
      if (rec.status === "retired") continue;
      if (previousSet[ids[i]]) continue; // diversity: no repeats

      var effectiveWeight = rec.weight;

      // Quarantined challenges get reduced traffic
      if (rec.status === "quarantined") {
        effectiveWeight *= 0.1;
      }

      // Trust-based weighting
      if (trustScore < 0.3) {
        // Low trust → prefer harder/less-compromised challenges
        var botRate = _botSolveRate(rec);
        if (botRate !== null && botRate < 0.1) {
          effectiveWeight *= 2.0; // Bots can't solve this → good for suspicious sessions
        }
      } else if (isNewUser) {
        // New users → prefer easier challenges
        var humanRate = _humanSolveRate(rec);
        if (humanRate !== null && humanRate > cfg.targetSolveRateMax) {
          effectiveWeight *= 1.5;
        }
      }

      if (effectiveWeight > 0) {
        candidates.push({ id: ids[i], weight: effectiveWeight });
      }
    }

    if (candidates.length === 0) return null;

    // Weighted random selection
    var totalWeight = 0;
    for (var wi = 0; wi < candidates.length; wi++) {
      totalWeight += candidates[wi].weight;
    }

    var roll = secureRandom() * totalWeight;
    var cumulative = 0;
    for (var ci = 0; ci < candidates.length; ci++) {
      cumulative += candidates[ci].weight;
      if (roll <= cumulative) {
        return candidates[ci].id;
      }
    }

    return candidates[candidates.length - 1].id;
  }

  /**
   * Self-monitoring report on decision quality.
   *
   * @returns {Object} Self-monitoring metrics
   */
  function selfReport() {
    var total = decisionHistory.length;
    var recent = decisionHistory.slice(-cfg.selfMonitorWindow);
    var recentCount = recent.length;

    // Analyze decision outcomes
    var correctCount = 0;
    var falsePositives = 0;
    var falseNegatives = 0;
    var actionCounts = Object.create(null);

    for (var i = 0; i < recent.length; i++) {
      var d = recent[i];
      actionCounts[d.action] = (actionCounts[d.action] || 0) + 1;

      var rec = challenges[d.challengeId];
      if (!rec) continue;

      var botRate = _botSolveRate(rec);
      var humanRate = _humanSolveRate(rec);

      if (d.action === "retire" || d.action === "quarantine") {
        // Was it correct? Check if bot rate is actually high
        if (botRate !== null && botRate >= cfg.botSolveRateThreshold * 0.8) {
          correctCount++;
        } else if (botRate !== null) {
          falsePositives++;
        }
      } else if (d.action === "promote" || d.action === "boost") {
        if (botRate === null || botRate < cfg.botSolveRateThreshold) {
          correctCount++;
        } else {
          falseNegatives++;
        }
      } else if (d.action === "demote") {
        if (humanRate !== null && humanRate < cfg.targetSolveRateMin) {
          correctCount++;
        }
      }
    }

    var evaluated = correctCount + falsePositives + falseNegatives;
    var accuracy = evaluated > 0 ? correctCount / evaluated : null;
    var fpRate = evaluated > 0 ? falsePositives / evaluated : 0;
    var fnRate = evaluated > 0 ? falseNegatives / evaluated : 0;

    var recommendations = [];
    if (fpRate > 0.2) {
      recommendations.push("High false positive rate (" + (fpRate * 100).toFixed(1) + "%) — consider raising botSolveRateThreshold");
    }
    if (fnRate > 0.15) {
      recommendations.push("Notable false negative rate (" + (fnRate * 100).toFixed(1) + "%) — consider lowering botSolveRateThreshold");
    }
    if (total === 0) {
      recommendations.push("No decisions made yet — collect more outcome data");
    }

    return {
      accuracy: accuracy,
      falsePositiveRate: fpRate,
      falseNegativeRate: fnRate,
      totalDecisions: total,
      recentDecisions: recentCount,
      actionBreakdown: actionCounts,
      recommendations: recommendations
    };
  }

  /**
   * Generate a comprehensive situation report.
   *
   * @returns {Object} Situation report
   */
  function situationReport() {
    var ids = Object.keys(challenges);
    var active = 0;
    var quarantined = 0;
    var retired = 0;
    var topThreats = [];
    var healthyCount = 0;

    for (var i = 0; i < ids.length; i++) {
      var rec = challenges[ids[i]];
      if (rec.status === "active") active++;
      else if (rec.status === "quarantined") quarantined++;
      else if (rec.status === "retired") retired++;

      var botRate = _botSolveRate(rec);
      if (botRate !== null && botRate > 0.1 && rec.totalBot >= 3) {
        topThreats.push({
          challengeId: ids[i],
          botSolveRate: botRate,
          totalBotAttempts: rec.totalBot,
          status: rec.status
        });
      }

      var humanRate = _humanSolveRate(rec);
      if (rec.status === "active" && humanRate !== null &&
          humanRate >= cfg.targetSolveRateMin && humanRate <= cfg.targetSolveRateMax &&
          (botRate === null || botRate < cfg.botSolveRateThreshold)) {
        healthyCount++;
      }
    }

    // Sort threats by bot solve rate descending
    topThreats.sort(function(a, b) { return b.botSolveRate - a.botSolveRate; });
    topThreats = topThreats.slice(0, 10);

    // Trend analysis from global window
    var windowEntries = _windowEntries(globalWindow);
    var windowBotSolves = 0;
    var windowBotTotal = 0;
    for (var wi = 0; wi < windowEntries.length; wi++) {
      if (windowEntries[wi].isBot) {
        windowBotTotal++;
        if (windowEntries[wi].solved) windowBotSolves++;
      }
    }
    var windowBotRate = windowBotTotal > 0 ? windowBotSolves / windowBotTotal : null;

    // Recommended immediate actions
    var actions = [];
    if (quarantined > cfg.maxQuarantineSize * 0.8) {
      actions.push("Quarantine nearing capacity (" + quarantined + "/" + cfg.maxQuarantineSize + ") — review and retire stale entries");
    }
    if (active < 5) {
      actions.push("Low active challenge count (" + active + ") — add new challenges to maintain diversity");
    }
    if (windowBotRate !== null && windowBotRate > 0.5) {
      actions.push("High recent bot solve rate (" + (windowBotRate * 100).toFixed(1) + "%) — active attack in progress");
    }

    return {
      fleet: {
        total: ids.length,
        active: active,
        quarantined: quarantined,
        retired: retired,
        healthy: healthyCount
      },
      topThreats: topThreats,
      recentBotSolveRate: windowBotRate,
      recentWindowSize: windowEntries.length,
      recommendedActions: actions,
      selfMonitoring: selfReport()
    };
  }

  /**
   * Get the status and stats for a specific challenge.
   *
   * @param {string} challengeId
   * @returns {Object|null}
   */
  function getChallengeStats(challengeId) {
    var rec = challenges[challengeId];
    if (!rec) return null;
    return {
      id: rec.id,
      status: rec.status,
      weight: rec.weight,
      humanSolveRate: _humanSolveRate(rec),
      botSolveRate: _botSolveRate(rec),
      totalHuman: rec.totalHuman,
      totalBot: rec.totalBot,
      humanSolves: rec.humanSolves,
      botSolves: rec.botSolves,
      avgSolveTimeMs: rec.solveTimes.length > 0 ? _mean(rec.solveTimes) : null,
      medianSolveTimeMs: rec.solveTimes.length > 0 ? _median(rec.solveTimes) : null,
      avgTrustScore: rec.trustScores.length > 0 ? _mean(rec.trustScores) : null
    };
  }

  /**
   * Manually set a challenge's status.
   *
   * @param {string} challengeId
   * @param {string} status - "active" | "quarantined" | "retired"
   */
  function setStatus(challengeId, status) {
    if (status !== "active" && status !== "quarantined" && status !== "retired") {
      throw new Error("Invalid status: " + status);
    }
    var rec = _getOrCreate(challengeId);
    rec.status = status;
    if (status === "quarantined") rec.quarantinedAt = _now();
    if (status === "retired") rec.retiredAt = _now();
    if (status === "active") { rec.quarantinedAt = null; rec.retiredAt = null; }
  }

  /**
   * Get current configuration.
   * @returns {Object}
   */
  function getConfig() {
    return {
      targetSolveRateMin: cfg.targetSolveRateMin,
      targetSolveRateMax: cfg.targetSolveRateMax,
      botSolveRateThreshold: cfg.botSolveRateThreshold,
      minObservations: cfg.minObservations,
      cooldownMs: cfg.cooldownMs,
      maxQuarantineSize: cfg.maxQuarantineSize,
      selfMonitorWindow: cfg.selfMonitorWindow,
      autoAct: cfg.autoAct
    };
  }

  /**
   * List all challenge IDs by status.
   * @param {string} [status] - Filter by status. If omitted, returns all.
   * @returns {string[]}
   */
  function listChallenges(status) {
    var ids = Object.keys(challenges);
    if (!status) return ids;
    var filtered = [];
    for (var i = 0; i < ids.length; i++) {
      if (challenges[ids[i]].status === status) {
        filtered.push(ids[i]);
      }
    }
    return filtered;
  }

  return {
    recordOutcome: recordOutcome,
    registerChallenge: registerChallenge,
    evaluate: evaluate,
    applyDecision: applyDecision,
    selectChallenge: selectChallenge,
    selfReport: selfReport,
    situationReport: situationReport,
    getChallengeStats: getChallengeStats,
    setStatus: setStatus,
    getConfig: getConfig,
    listChallenges: listChallenges
  };
}

module.exports = { createChallengeAutopilot: createChallengeAutopilot };
