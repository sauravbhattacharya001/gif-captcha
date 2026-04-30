/**
 * ThreatIntelFusion — Autonomous threat intelligence fusion engine.
 *
 * Correlates signals from multiple detection subsystems (anomaly detector,
 * bot signatures, fraud rings, attack evolution, behavioral biometrics) into
 * a unified threat assessment with autonomous defense posture management.
 *
 * Key capabilities:
 *   - Ingest signals from 6 source types with automatic timestamping
 *   - Produce unified threat assessments with composite scoring (0-100)
 *   - Cross-source correlation detection (5 pattern types)
 *   - Autonomous defense posture management (NORMAL → CRITICAL)
 *   - Signal decay with configurable half-life
 *   - Trend detection (rising/falling, time-of-day, severity velocity)
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/threat-intel-fusion
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _clamp = _shared._clamp;
var _decayFactor = _shared._decayFactor;
var _linearRegression = _shared._linearRegression;
var _posOpt = _shared._posOpt;
var _nnOpt = _shared._nnOpt;

var _crypto = require("./crypto-utils");
var secureRandomHex = _crypto.secureRandomHex;

// ── Defaults ────────────────────────────────────────────────────────

var SOURCE_TYPES = ["anomaly", "botMatch", "fraudRing", "attackEvolution", "biometric", "generic"];

var THREAT_LEVELS = ["GREEN", "YELLOW", "ORANGE", "RED"];

var POSTURE_LEVELS = ["NORMAL", "ELEVATED", "HIGH", "CRITICAL"];

var CORRELATION_PATTERNS = [
  "COORDINATED_ATTACK",
  "ADAPTIVE_THREAT",
  "EVASION_ATTEMPT",
  "EMERGING_THREAT",
  "SUSTAINED_PRESSURE"
];

var DEFAULT_WEIGHTS = {
  anomaly: 0.20,
  botMatch: 0.25,
  fraudRing: 0.20,
  attackEvolution: 0.15,
  biometric: 0.10,
  generic: 0.10
};

var DEFAULT_POSTURE = {
  greenMax: 25,
  yellowMax: 50,
  orangeMax: 75,
  escalationDelayMs: 30000,
  deescalationDelayMs: 300000
};

// ── Helpers ─────────────────────────────────────────────────────────

function _assignDefaults(target, defaults) {
  var result = {};
  var key;
  for (key in defaults) {
    if (defaults.hasOwnProperty(key)) {
      result[key] = (target && target.hasOwnProperty(key)) ? target[key] : defaults[key];
    }
  }
  return result;
}

function _makeSignalId() {
  return "sig_" + secureRandomHex(8);
}

function _severityToScore(severity) {
  return _clamp(typeof severity === "number" ? severity : 0, 0, 1) * 100;
}

/** Group signals by source type. */
function _groupBySource(signals) {
  var groups = {};
  var i;
  for (i = 0; i < SOURCE_TYPES.length; i++) {
    groups[SOURCE_TYPES[i]] = [];
  }
  for (i = 0; i < signals.length; i++) {
    var s = signals[i];
    if (groups[s.source]) {
      groups[s.source].push(s);
    }
  }
  return groups;
}

/** Compute per-source severity score (max of decayed severities). */
function _sourceScore(signals, nowMs, decayHalfLifeMs) {
  if (!signals.length) return 0;
  var maxScore = 0;
  for (var i = 0; i < signals.length; i++) {
    var s = signals[i];
    var age = nowMs - s.timestamp;
    var decay = _decayFactor(age, decayHalfLifeMs);
    var score = _severityToScore(s.severity) * decay;
    if (score > maxScore) maxScore = score;
  }
  return maxScore;
}

/** Find signals within a time window of a reference timestamp. */
function _signalsInWindow(signals, refTime, windowMs) {
  var result = [];
  for (var i = 0; i < signals.length; i++) {
    if (Math.abs(signals[i].timestamp - refTime) <= windowMs) {
      result.push(signals[i]);
    }
  }
  return result;
}

// ── Correlation Detectors ───────────────────────────────────────────

function _detectCoordinatedAttack(groups, correlationWindowMs) {
  // anomaly spike + bot matches + fraud ring activity within window
  if (!groups.anomaly.length || !groups.botMatch.length) return null;
  for (var i = 0; i < groups.anomaly.length; i++) {
    var anom = groups.anomaly[i];
    var nearBots = _signalsInWindow(groups.botMatch, anom.timestamp, correlationWindowMs);
    var nearFraud = _signalsInWindow(groups.fraudRing, anom.timestamp, correlationWindowMs);
    if (nearBots.length > 0 && nearFraud.length > 0) {
      var evidence = [anom].concat(nearBots.slice(0, 3)).concat(nearFraud.slice(0, 3));
      var maxSev = 0;
      for (var j = 0; j < evidence.length; j++) {
        if (evidence[j].severity > maxSev) maxSev = evidence[j].severity;
      }
      return {
        pattern: "COORDINATED_ATTACK",
        confidence: _clamp(0.5 + maxSev * 0.5, 0, 1),
        evidenceCount: evidence.length,
        evidence: evidence.map(function (e) { return e.id; }),
        description: "Anomaly spike correlates with bot matches and fraud ring activity"
      };
    }
  }
  // Also trigger with just anomaly + bots (no fraud ring required)
  for (var k = 0; k < groups.anomaly.length; k++) {
    var a2 = groups.anomaly[k];
    var bots2 = _signalsInWindow(groups.botMatch, a2.timestamp, correlationWindowMs);
    if (bots2.length >= 2) {
      return {
        pattern: "COORDINATED_ATTACK",
        confidence: _clamp(0.3 + a2.severity * 0.4, 0, 1),
        evidenceCount: 1 + bots2.length,
        evidence: [a2.id].concat(bots2.slice(0, 3).map(function (e) { return e.id; })),
        description: "Anomaly spike correlates with multiple bot matches"
      };
    }
  }
  return null;
}

function _detectAdaptiveThreat(groups, correlationWindowMs) {
  // attack evolution learning curve + new bot signatures
  if (!groups.attackEvolution.length) return null;
  for (var i = 0; i < groups.attackEvolution.length; i++) {
    var evo = groups.attackEvolution[i];
    if (evo.details && evo.details.learningRate > 0) {
      var nearBots = _signalsInWindow(groups.botMatch, evo.timestamp, correlationWindowMs);
      if (nearBots.length > 0) {
        return {
          pattern: "ADAPTIVE_THREAT",
          confidence: _clamp(0.4 + (evo.details.learningRate || 0) * 5 + evo.severity * 0.3, 0, 1),
          evidenceCount: 1 + nearBots.length,
          evidence: [evo.id].concat(nearBots.slice(0, 3).map(function (e) { return e.id; })),
          description: "Attack strategies evolving alongside new bot signatures"
        };
      }
      // Even without bot matches, high learning rate is adaptive
      if (evo.details.learningRate >= 0.05) {
        return {
          pattern: "ADAPTIVE_THREAT",
          confidence: _clamp(0.3 + evo.severity * 0.4, 0, 1),
          evidenceCount: 1,
          evidence: [evo.id],
          description: "Rapid attack strategy evolution detected"
        };
      }
    }
  }
  return null;
}

function _detectEvasionAttempt(groups, correlationWindowMs) {
  // biometric anomalies + low bot match confidence
  if (!groups.biometric.length) return null;
  for (var i = 0; i < groups.biometric.length; i++) {
    var bio = groups.biometric[i];
    if (bio.details && bio.details.humanLikelihood > 0.4 && bio.details.humanLikelihood < 0.8) {
      // Ambiguous biometrics — possible evasion
      var nearBots = _signalsInWindow(groups.botMatch, bio.timestamp, correlationWindowMs);
      var lowConfBots = nearBots.filter(function (b) { return b.severity < 0.5; });
      if (lowConfBots.length > 0) {
        return {
          pattern: "EVASION_ATTEMPT",
          confidence: _clamp(0.4 + (1 - bio.details.humanLikelihood) * 0.6, 0, 1),
          evidenceCount: 1 + lowConfBots.length,
          evidence: [bio.id].concat(lowConfBots.slice(0, 3).map(function (e) { return e.id; })),
          description: "Biometric ambiguity with low-confidence bot detections suggests evasion"
        };
      }
    }
    // Flags-based detection
    if (bio.details && bio.details.flags && bio.details.flags.length > 0) {
      return {
        pattern: "EVASION_ATTEMPT",
        confidence: _clamp(0.3 + bio.severity * 0.5, 0, 1),
        evidenceCount: 1,
        evidence: [bio.id],
        description: "Biometric flags indicate possible human mimicry: " + bio.details.flags.join(", ")
      };
    }
  }
  return null;
}

function _detectEmergingThreat(groups, correlationWindowMs) {
  // New signal sources appearing + rising severity
  var activeSources = [];
  var totalSignals = 0;
  var maxSev = 0;
  for (var i = 0; i < SOURCE_TYPES.length; i++) {
    var src = SOURCE_TYPES[i];
    if (groups[src] && groups[src].length > 0) {
      activeSources.push(src);
      totalSignals += groups[src].length;
      for (var j = 0; j < groups[src].length; j++) {
        if (groups[src][j].severity > maxSev) maxSev = groups[src][j].severity;
      }
    }
  }
  if (activeSources.length >= 3 && totalSignals >= 5) {
    return {
      pattern: "EMERGING_THREAT",
      confidence: _clamp(0.3 + activeSources.length * 0.1 + maxSev * 0.2, 0, 1),
      evidenceCount: totalSignals,
      evidence: [],
      description: "Signals from " + activeSources.length + " sources with " + totalSignals + " signals indicate emerging threat"
    };
  }
  return null;
}

/**
 * Detect sustained elevated pressure. Signals are already in chronological
 * order (each receives _now() at ingestion), so skip the O(n log n) sort.
 * Also computes mean severity in a single pass without allocating an
 * intermediate array.
 */
function _detectSustainedPressure(signals, windowMs) {
  // Persistent elevated signals over the full window
  if (signals.length < 5) return null;
  // Signals are chronologically ordered — first/last give the span directly
  var span = signals[signals.length - 1].timestamp - signals[0].timestamp;
  if (span < windowMs * 0.5) return null; // not sustained enough
  // Single-pass mean severity (avoids allocating a mapped array)
  var sevSum = 0;
  for (var i = 0; i < signals.length; i++) sevSum += signals[i].severity;
  var avg = sevSum / signals.length;
  if (avg < 0.3) return null;
  return {
    pattern: "SUSTAINED_PRESSURE",
    confidence: _clamp(avg, 0, 1),
    evidenceCount: signals.length,
    evidence: [],
    description: "Sustained elevated threat signals (avg severity " + (avg * 100).toFixed(0) + "%) over " + Math.round(span / 60000) + " minutes"
  };
}

// ── Posture Recommendations ─────────────────────────────────────────

var POSTURE_RECOMMENDATIONS = {
  NORMAL: [
    "Standard CAPTCHA difficulty",
    "Routine monitoring active"
  ],
  ELEVATED: [
    "Increase CAPTCHA difficulty by one tier",
    "Enable enhanced logging for suspicious sessions",
    "Reduce rate limits by 20%"
  ],
  HIGH: [
    "Maximum CAPTCHA difficulty",
    "Activate honeypot challenges",
    "Enable aggressive rate limiting",
    "Alert security team"
  ],
  CRITICAL: [
    "Emergency CAPTCHA lockdown — proof-of-work required",
    "Block known bot signature IPs",
    "Activate all honeypots",
    "Immediate incident response required",
    "Consider temporary service restriction"
  ]
};

// ── Factory ─────────────────────────────────────────────────────────

/**
 * Create a threat intelligence fusion engine.
 *
 * @param {object} [options]
 * @param {number} [options.windowMs=1800000]           Signal retention window (30 min)
 * @param {number} [options.correlationWindowMs=60000]   Cross-signal correlation window (60s)
 * @param {number} [options.decayHalfLifeMs=1800000]    Signal decay half-life (30 min)
 * @param {number} [options.maxSignals=10000]           Max stored signals
 * @param {number} [options.assessmentCooldownMs=5000]  Min time between assessments
 * @param {object} [options.weights]                    Source weights for composite score
 * @param {object} [options.posture]                    Posture thresholds
 * @returns {object}
 */
function createThreatIntelFusion(options) {
  options = options || {};

  var windowMs = _posOpt(options.windowMs, 1800000);
  var correlationWindowMs = _posOpt(options.correlationWindowMs, 60000);
  var decayHalfLifeMs = _posOpt(options.decayHalfLifeMs, 1800000);
  var maxSignals = _posOpt(options.maxSignals, 10000);
  var assessmentCooldownMs = _nnOpt(options.assessmentCooldownMs, 5000);
  var weights = _assignDefaults(options.weights, DEFAULT_WEIGHTS);
  var postureCfg = _assignDefaults(options.posture, DEFAULT_POSTURE);

  // ── State ───────────────────────────────────────────────────────
  var signals = [];             // all active signals in window
  var postureHistory = [];      // {posture, score, timestamp, reason}
  var currentPosture = "NORMAL";
  var lastPostureChangeMs = 0;
  var lastAssessmentMs = 0;
  var lastAssessment = null;
  var stats = {
    totalIngested: 0,
    totalPruned: 0,
    totalAssessments: 0,
    bySource: {}
  };
  for (var si = 0; si < SOURCE_TYPES.length; si++) {
    stats.bySource[SOURCE_TYPES[si]] = 0;
  }

  // ── Internal ────────────────────────────────────────────────────

  /**
   * Remove expired signals. Uses binary search to find the cutoff index
   * because signals are chronologically ordered (each receives _now() at
   * ingestion time). Previously iterated every signal with a conditional
   * push into a new array — O(n) allocations each time. Binary search +
   * splice is O(log n) to locate + O(k) for the removal of k expired
   * entries, and avoids allocating a fresh array when nothing expired.
   */
  function _prune() {
    if (signals.length === 0) return;
    var cutoff = _now() - windowMs;
    // Fast exit: if the oldest signal is still valid, nothing to prune
    if (signals[0].timestamp >= cutoff) return;
    // Binary search for the first signal at or after cutoff
    var lo = 0, hi = signals.length;
    while (lo < hi) {
      var mid = (lo + hi) >>> 1;
      if (signals[mid].timestamp < cutoff) lo = mid + 1;
      else hi = mid;
    }
    // lo = index of first valid signal
    if (lo > 0) {
      stats.totalPruned += lo;
      signals = signals.slice(lo);
    }
  }

  function _enforceCap() {
    while (signals.length > maxSignals) {
      signals.shift();
      stats.totalPruned++;
    }
  }

  function _ingest(source, severity, details) {
    // Lazy pruning: only prune when signal count exceeds 110% of max or
    // when the oldest signal is clearly expired. Avoids O(log n) binary
    // search overhead on every single ingestion call.
    if (signals.length > maxSignals * 1.1 ||
        (signals.length > 0 && signals[0].timestamp < _now() - windowMs)) {
      _prune();
    }
    var signal = {
      id: _makeSignalId(),
      source: source,
      severity: _clamp(typeof severity === "number" ? severity : 0, 0, 1),
      details: details || {},
      timestamp: _now()
    };
    signals.push(signal);
    _enforceCap();
    stats.totalIngested++;
    stats.bySource[source] = (stats.bySource[source] || 0) + 1;
    return signal;
  }

  function _computeComposite(groups, nowMs) {
    var total = 0;
    for (var i = 0; i < SOURCE_TYPES.length; i++) {
      var src = SOURCE_TYPES[i];
      var score = _sourceScore(groups[src] || [], nowMs, decayHalfLifeMs);
      total += score * (weights[src] || 0);
    }
    return _clamp(total, 0, 100);
  }

  function _scoreThreatLevel(score) {
    if (score <= postureCfg.greenMax) return "GREEN";
    if (score <= postureCfg.yellowMax) return "YELLOW";
    if (score <= postureCfg.orangeMax) return "ORANGE";
    return "RED";
  }

  function _scorePosture(score) {
    if (score <= postureCfg.greenMax) return "NORMAL";
    if (score <= postureCfg.yellowMax) return "ELEVATED";
    if (score <= postureCfg.orangeMax) return "HIGH";
    return "CRITICAL";
  }

  function _updatePosture(newPosture, score, reason) {
    var nowMs = _now();
    var postureIdx = POSTURE_LEVELS.indexOf(newPosture);
    var currentIdx = POSTURE_LEVELS.indexOf(currentPosture);

    if (postureIdx > currentIdx) {
      // Escalation
      if (nowMs - lastPostureChangeMs >= postureCfg.escalationDelayMs || currentPosture === "NORMAL") {
        currentPosture = newPosture;
        lastPostureChangeMs = nowMs;
        postureHistory.push({
          posture: newPosture,
          score: score,
          timestamp: nowMs,
          reason: reason || "Escalation: composite score " + score.toFixed(1),
          direction: "escalation"
        });
      }
    } else if (postureIdx < currentIdx) {
      // De-escalation — requires longer cooldown
      if (nowMs - lastPostureChangeMs >= postureCfg.deescalationDelayMs) {
        currentPosture = newPosture;
        lastPostureChangeMs = nowMs;
        postureHistory.push({
          posture: newPosture,
          score: score,
          timestamp: nowMs,
          reason: reason || "De-escalation: composite score " + score.toFixed(1),
          direction: "de-escalation"
        });
      }
    }
  }

  function _detectCorrelations(groups) {
    var results = [];
    var c;

    c = _detectCoordinatedAttack(groups, correlationWindowMs);
    if (c) results.push(c);

    c = _detectAdaptiveThreat(groups, correlationWindowMs);
    if (c) results.push(c);

    c = _detectEvasionAttempt(groups, correlationWindowMs);
    if (c) results.push(c);

    c = _detectEmergingThreat(groups, correlationWindowMs);
    if (c) results.push(c);

    c = _detectSustainedPressure(signals, windowMs);
    if (c) results.push(c);

    return results;
  }

  function _buildTopThreats(groups, correlations, nowMs) {
    var threats = [];

    // Add high-severity individual signals as threats
    for (var i = 0; i < signals.length; i++) {
      var s = signals[i];
      if (s.severity >= 0.6) {
        var decay = _decayFactor(nowMs - s.timestamp, decayHalfLifeMs);
        threats.push({
          source: s.source,
          severity: s.severity * decay,
          signalId: s.id,
          description: s.source + " signal (severity " + (s.severity * 100).toFixed(0) + "%)",
          timestamp: s.timestamp
        });
      }
    }

    // Add correlations as high-priority threats
    for (var j = 0; j < correlations.length; j++) {
      var cor = correlations[j];
      threats.push({
        source: "correlation",
        severity: cor.confidence,
        pattern: cor.pattern,
        description: cor.description,
        evidenceCount: cor.evidenceCount,
        timestamp: nowMs
      });
    }

    // Sort by severity descending
    threats.sort(function (a, b) { return b.severity - a.severity; });
    return threats.slice(0, 10);
  }

  // ── Public API ──────────────────────────────────────────────────

  function ingestAnomaly(signal) {
    signal = signal || {};
    return _ingest("anomaly", signal.severity, {
      type: signal.type,
      metric: signal.metric,
      value: signal.value,
      threshold: signal.threshold
    });
  }

  function ingestBotMatch(signal) {
    signal = signal || {};
    return _ingest("botMatch", signal.confidence, {
      signatureId: signal.signatureId,
      category: signal.category,
      sessionId: signal.sessionId
    });
  }

  function ingestFraudRing(signal) {
    signal = signal || {};
    return _ingest("fraudRing", signal.confidence || signal.ringSeverity, {
      ringId: signal.ringId,
      memberCount: signal.memberCount,
      ringSeverity: signal.ringSeverity
    });
  }

  function ingestAttackEvolution(signal) {
    signal = signal || {};
    return _ingest("attackEvolution", signal.successRate || signal.severity, {
      strategyId: signal.strategyId,
      successRate: signal.successRate,
      learningRate: signal.learningRate,
      compromisedChallenges: signal.compromisedChallenges || []
    });
  }

  function ingestBiometric(signal) {
    signal = signal || {};
    var severity = 1 - (typeof signal.humanLikelihood === "number" ? signal.humanLikelihood : 0.5);
    return _ingest("biometric", severity, {
      sessionId: signal.sessionId,
      humanLikelihood: signal.humanLikelihood,
      flags: signal.flags || []
    });
  }

  function ingestGeneric(signal) {
    signal = signal || {};
    return _ingest("generic", signal.severity, {
      source: signal.source,
      type: signal.type,
      details: signal.details
    });
  }

  function assess() {
    _prune();
    var nowMs = _now();

    var groups = _groupBySource(signals);

    var activeSources = [];
    for (var i = 0; i < SOURCE_TYPES.length; i++) {
      if (groups[SOURCE_TYPES[i]].length > 0) {
        activeSources.push(SOURCE_TYPES[i]);
      }
    }

    var compositeScore = _computeComposite(groups, nowMs);
    var threatLevel = _scoreThreatLevel(compositeScore);
    var correlations = _detectCorrelations(groups);

    // Boost score for correlations
    var correlationBoost = 0;
    for (var j = 0; j < correlations.length; j++) {
      correlationBoost += correlations[j].confidence * 10;
    }
    compositeScore = _clamp(compositeScore + correlationBoost, 0, 100);
    threatLevel = _scoreThreatLevel(compositeScore);

    var topThreats = _buildTopThreats(groups, correlations, nowMs);
    var recommendedPosture = _scorePosture(compositeScore);
    _updatePosture(recommendedPosture, compositeScore);

    var assessment = {
      threatLevel: threatLevel,
      compositeScore: Math.round(compositeScore * 10) / 10,
      activeSources: activeSources,
      topThreats: topThreats,
      correlations: correlations,
      defensePosture: currentPosture,
      recommendations: POSTURE_RECOMMENDATIONS[currentPosture] || [],
      signalCount: signals.length,
      timestamp: nowMs
    };

    lastAssessment = assessment;
    lastAssessmentMs = nowMs;
    stats.totalAssessments++;
    return assessment;
  }

  function getPosture() {
    return {
      posture: currentPosture,
      recommendations: POSTURE_RECOMMENDATIONS[currentPosture] || [],
      lastChange: lastPostureChangeMs,
      historyLength: postureHistory.length
    };
  }

  function getPostureHistory() {
    return postureHistory.slice();
  }

  function getTrends() {
    if (signals.length < 3) {
      return {
        direction: "insufficient_data",
        signalRate: 0,
        averageSeverity: 0,
        sourceDistribution: {},
        timeOfDayPattern: null,
        severityVelocity: 0
      };
    }

    var sevs = [];
    var times = [];
    var sourceDistribution = {};
    var hourBuckets = {};

    for (var i = 0; i < signals.length; i++) {
      var s = signals[i];
      sevs.push(s.severity);
      times.push(s.timestamp);
      sourceDistribution[s.source] = (sourceDistribution[s.source] || 0) + 1;

      var hour = new Date(s.timestamp).getUTCHours();
      hourBuckets[hour] = (hourBuckets[hour] || 0) + 1;
    }

    var avgSeverity = _mean(sevs);

    // Compute trend via linear regression on severity over time
    var minTime = times[0];
    for (var t = 1; t < times.length; t++) {
      if (times[t] < minTime) minTime = times[t];
    }
    var normalizedTimes = times.map(function (t) { return (t - minTime) / 60000; }); // minutes
    var regression = _linearRegression(normalizedTimes, sevs);
    var slope = regression ? regression.slope : 0;

    var direction = "stable";
    if (slope > 0.001) direction = "rising";
    else if (slope < -0.001) direction = "falling";

    // Signal rate (signals per minute)
    var timeSpan = Math.max(times[times.length - 1] - minTime, 60000);
    var signalRate = signals.length / (timeSpan / 60000);

    // Find peak hour
    var peakHour = null;
    var peakCount = 0;
    for (var h in hourBuckets) {
      if (hourBuckets.hasOwnProperty(h) && hourBuckets[h] > peakCount) {
        peakCount = hourBuckets[h];
        peakHour = parseInt(h, 10);
      }
    }

    return {
      direction: direction,
      signalRate: Math.round(signalRate * 100) / 100,
      averageSeverity: Math.round(avgSeverity * 1000) / 1000,
      sourceDistribution: sourceDistribution,
      timeOfDayPattern: peakHour !== null ? { peakHourUTC: peakHour, count: peakCount } : null,
      severityVelocity: Math.round(slope * 10000) / 10000
    };
  }

  function getStats() {
    return {
      totalIngested: stats.totalIngested,
      totalPruned: stats.totalPruned,
      totalAssessments: stats.totalAssessments,
      activeSignals: signals.length,
      bySource: JSON.parse(JSON.stringify(stats.bySource)),
      currentPosture: currentPosture,
      postureChanges: postureHistory.length
    };
  }

  function exportState() {
    return {
      version: 1,
      signals: signals.slice(),
      postureHistory: postureHistory.slice(),
      currentPosture: currentPosture,
      lastPostureChangeMs: lastPostureChangeMs,
      stats: JSON.parse(JSON.stringify(stats)),
      config: {
        windowMs: windowMs,
        correlationWindowMs: correlationWindowMs,
        decayHalfLifeMs: decayHalfLifeMs,
        maxSignals: maxSignals,
        weights: JSON.parse(JSON.stringify(weights)),
        posture: JSON.parse(JSON.stringify(postureCfg))
      }
    };
  }

  function importState(data) {
    if (!data || data.version !== 1) return false;
    if (Array.isArray(data.signals)) signals = data.signals.slice();
    if (Array.isArray(data.postureHistory)) postureHistory = data.postureHistory.slice();
    if (typeof data.currentPosture === "string") currentPosture = data.currentPosture;
    if (typeof data.lastPostureChangeMs === "number") lastPostureChangeMs = data.lastPostureChangeMs;
    if (data.stats) stats = JSON.parse(JSON.stringify(data.stats));
    return true;
  }

  function reset() {
    signals = [];
    postureHistory = [];
    currentPosture = "NORMAL";
    lastPostureChangeMs = 0;
    lastAssessmentMs = 0;
    lastAssessment = null;
    stats = {
      totalIngested: 0,
      totalPruned: 0,
      totalAssessments: 0,
      bySource: {}
    };
    for (var i = 0; i < SOURCE_TYPES.length; i++) {
      stats.bySource[SOURCE_TYPES[i]] = 0;
    }
  }

  return {
    ingestAnomaly: ingestAnomaly,
    ingestBotMatch: ingestBotMatch,
    ingestFraudRing: ingestFraudRing,
    ingestAttackEvolution: ingestAttackEvolution,
    ingestBiometric: ingestBiometric,
    ingestGeneric: ingestGeneric,
    assess: assess,
    getPosture: getPosture,
    getPostureHistory: getPostureHistory,
    getTrends: getTrends,
    getStats: getStats,
    exportState: exportState,
    importState: importState,
    reset: reset,
    SOURCE_TYPES: SOURCE_TYPES,
    THREAT_LEVELS: THREAT_LEVELS,
    POSTURE_LEVELS: POSTURE_LEVELS,
    CORRELATION_PATTERNS: CORRELATION_PATTERNS
  };
}

module.exports = {
  createThreatIntelFusion: createThreatIntelFusion
};
