/**
 * SessionRiskAggregator — Unified per-session risk scoring for gif-captcha.
 *
 * Combines signals from multiple security modules (GeoRiskScorer,
 * BehavioralBiometrics, SolvePatternFingerprinter, DeviceCohortAnalyzer,
 * AdaptiveDifficultyTuner, HoneypotInjector, ChallengeTemplateEngine)
 * into a single risk verdict with explainable factor breakdown.
 *
 * Supports configurable module weights, custom thresholds, risk decay
 * over time, session timeline reconstruction, and policy-based actions.
 *
 * No external dependencies.
 *
 * @example
 *   var agg = createSessionRiskAggregator({ weights: { geo: 0.25 } });
 *   agg.addSignal('sess1', { module: 'geo', score: 0.8, level: 'high',
 *     factors: ['impossible_travel'], timestamp: Date.now() });
 *   agg.addSignal('sess1', { module: 'biometrics', score: 0.3, level: 'low',
 *     factors: ['natural_mouse'], timestamp: Date.now() });
 *   var verdict = agg.evaluate('sess1');
 *   // => { sessionId:'sess1', score:0.52, level:'medium', action:'challenge',
 *   //      factors:[...], timeline:[...], moduleScores:{...} }
 *
 * @module gif-captcha/session-risk-aggregator
 */

"use strict";

// ── Defaults ────────────────────────────────────────────────────────

var DEFAULT_WEIGHTS = {
  geo: 0.20,
  biometrics: 0.20,
  fingerprint: 0.15,
  cohort: 0.10,
  difficulty: 0.10,
  honeypot: 0.15,
  template: 0.10
};

var DEFAULT_THRESHOLDS = {
  low: 0.3,
  medium: 0.5,
  high: 0.7,
  critical: 0.9
};

var DEFAULT_ACTIONS = {
  low: "allow",
  medium: "challenge",
  high: "escalate",
  critical: "block"
};

var DEFAULT_DECAY_HALF_LIFE_MS = 300000; // 5 minutes — older signals matter less
var DEFAULT_MAX_SIGNALS_PER_MODULE = 50;
var DEFAULT_SESSION_TTL_MS = 1800000; // 30 minutes

// ── Helpers ─────────────────────────────────────────────────────────

function _clamp(v, lo, hi) {
  return v < lo ? lo : v > hi ? hi : v;
}

function _now() {
  return Date.now();
}

function _deepCopy(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function _merge(base, override) {
  var result = Object.create(null);
  var k;
  for (k in base) {
    if (Object.prototype.hasOwnProperty.call(base, k)) result[k] = base[k];
  }
  for (k in override) {
    if (Object.prototype.hasOwnProperty.call(override, k)) result[k] = override[k];
  }
  return result;
}

function _weightedAverage(values, weights) {
  var totalWeight = 0;
  var sum = 0;
  for (var i = 0; i < values.length; i++) {
    sum += values[i] * weights[i];
    totalWeight += weights[i];
  }
  return totalWeight > 0 ? sum / totalWeight : 0;
}

function _decayFactor(ageMs, halfLifeMs) {
  if (ageMs <= 0) return 1;
  return Math.pow(0.5, ageMs / halfLifeMs);
}

function _percentile(arr, p) {
  if (!arr || arr.length === 0) return 0;
  var sorted = arr.slice().sort(function (a, b) { return a - b; });
  var idx = (p / 100) * (sorted.length - 1);
  var lo = Math.floor(idx);
  var hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

// ── Module name normalization ───────────────────────────────────────

var MODULE_ALIASES = {
  geo: "geo",
  georisk: "geo",
  "geo-risk": "geo",
  "geo_risk": "geo",
  biometrics: "biometrics",
  behavioral: "biometrics",
  "behavioral-biometrics": "biometrics",
  "behavioral_biometrics": "biometrics",
  fingerprint: "fingerprint",
  "solve-pattern": "fingerprint",
  "solve_pattern": "fingerprint",
  solvepattern: "fingerprint",
  cohort: "cohort",
  device: "cohort",
  "device-cohort": "cohort",
  "device_cohort": "cohort",
  difficulty: "difficulty",
  adaptive: "difficulty",
  "adaptive-difficulty": "difficulty",
  honeypot: "honeypot",
  "honeypot-injector": "honeypot",
  template: "template",
  "challenge-template": "template"
};

function _normalizeModule(name) {
  if (!name || typeof name !== "string") return null;
  var lower = name.toLowerCase().trim();
  return MODULE_ALIASES[lower] || lower;
}

// ── Correlation rules ───────────────────────────────────────────────

var CORRELATION_RULES = [
  {
    name: "geo_plus_biometrics_bot",
    description: "High geo risk combined with bot-like biometrics",
    modules: ["geo", "biometrics"],
    condition: function (scores) {
      return scores.geo >= 0.6 && scores.biometrics >= 0.6;
    },
    boost: 0.15
  },
  {
    name: "honeypot_triggered",
    description: "Honeypot interaction confirms suspicion",
    modules: ["honeypot"],
    condition: function (scores) {
      return scores.honeypot >= 0.8;
    },
    boost: 0.20
  },
  {
    name: "fingerprint_replay",
    description: "Known solve pattern with geo anomaly suggests replay attack",
    modules: ["fingerprint", "geo"],
    condition: function (scores) {
      return scores.fingerprint >= 0.7 && scores.geo >= 0.5;
    },
    boost: 0.10
  },
  {
    name: "multi_module_consensus",
    description: "3+ modules agree on elevated risk",
    modules: [],
    condition: function (scores) {
      var elevated = 0;
      var modules = ["geo", "biometrics", "fingerprint", "cohort", "difficulty", "honeypot"];
      for (var i = 0; i < modules.length; i++) {
        if (scores[modules[i]] !== undefined && scores[modules[i]] >= 0.5) elevated++;
      }
      return elevated >= 3;
    },
    boost: 0.10
  },
  {
    name: "clean_session",
    description: "Multiple modules show low risk — reduce overall score",
    modules: [],
    condition: function (scores) {
      var clean = 0;
      var modules = ["geo", "biometrics", "fingerprint"];
      for (var i = 0; i < modules.length; i++) {
        if (scores[modules[i]] !== undefined && scores[modules[i]] <= 0.2) clean++;
      }
      return clean >= 3;
    },
    boost: -0.10
  }
];

// ── Factory ─────────────────────────────────────────────────────────

function createSessionRiskAggregator(options) {
  options = options || {};

  var weights = _merge(DEFAULT_WEIGHTS, options.weights || {});
  var thresholds = _merge(DEFAULT_THRESHOLDS, options.thresholds || {});
  var actions = _merge(DEFAULT_ACTIONS, options.actions || {});
  var decayHalfLife = options.decayHalfLifeMs || DEFAULT_DECAY_HALF_LIFE_MS;
  var maxSignals = options.maxSignalsPerModule || DEFAULT_MAX_SIGNALS_PER_MODULE;
  var sessionTTL = options.sessionTTLMs || DEFAULT_SESSION_TTL_MS;
  var customRules = options.correlationRules || [];
  var allRules = CORRELATION_RULES.concat(customRules);

  // sessionId -> { signals: { module: [...] }, firstSeen, lastSeen, metadata }
  var sessions = Object.create(null);

  // Global stats
  var stats = {
    totalSignals: 0,
    totalEvaluations: 0,
    totalSessions: 0,
    verdictCounts: { low: 0, medium: 0, high: 0, critical: 0 },
    moduleSignalCounts: {},
    blockedSessions: 0
  };

  // ── Internal helpers ────────────────────────────────────────────

  function _getSession(sessionId) {
    if (!sessions[sessionId]) {
      sessions[sessionId] = {
        signals: {},
        firstSeen: null,
        lastSeen: null,
        metadata: {},
        evaluations: [],
        locked: false
      };
      stats.totalSessions++;
    }
    return sessions[sessionId];
  }

  function _scoreForModule(session, mod, now) {
    var sigs = session.signals[mod];
    if (!sigs || sigs.length === 0) return undefined;

    var values = [];
    var decayWeights = [];
    for (var i = 0; i < sigs.length; i++) {
      var age = now - (sigs[i].timestamp || now);
      var decay = _decayFactor(age, decayHalfLife);
      values.push(_clamp(sigs[i].score || 0, 0, 1));
      decayWeights.push(decay);
    }

    // Use decay-weighted average for the module score
    return _clamp(_weightedAverage(values, decayWeights), 0, 1);
  }

  function _classifyLevel(score) {
    if (score >= thresholds.critical) return "critical";
    if (score >= thresholds.high) return "high";
    if (score >= thresholds.medium) return "medium";
    return "low";
  }

  function _pruneOld(now) {
    var ids = Object.keys(sessions);
    for (var i = 0; i < ids.length; i++) {
      if (now - sessions[ids[i]].lastSeen > sessionTTL) {
        if (sessions[ids[i]].locked) {
          stats.blockedSessions = Math.max(0, stats.blockedSessions - 1);
        }
        delete sessions[ids[i]];
        stats.totalSessions = Math.max(0, stats.totalSessions - 1);
      }
    }
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Add a risk signal from any security module.
   * @param {string} sessionId
   * @param {Object} signal - { module, score (0-1), level?, factors?, timestamp?, meta? }
   * @returns {{ ok: boolean, module: string, signalCount: number }}
   */
  function addSignal(sessionId, signal) {
    if (!sessionId || !signal || !signal.module) {
      return { ok: false, error: "sessionId and signal.module required" };
    }

    var mod = _normalizeModule(signal.module);
    if (!mod) return { ok: false, error: "unknown module" };

    var session = _getSession(sessionId);
    if (session.locked) {
      return { ok: false, error: "session is locked (blocked)" };
    }

    if (!session.signals[mod]) session.signals[mod] = [];

    var entry = {
      score: _clamp(signal.score || 0, 0, 1),
      level: signal.level || _classifyLevel(signal.score || 0),
      factors: signal.factors || [],
      timestamp: signal.timestamp || _now(),
      meta: signal.meta || {}
    };

    session.signals[mod].push(entry);
    if (session.firstSeen === null || entry.timestamp < session.firstSeen) {
      session.firstSeen = entry.timestamp;
    }
    session.lastSeen = entry.timestamp > (session.lastSeen || 0) ? entry.timestamp : session.lastSeen;

    // Trim old signals
    if (session.signals[mod].length > maxSignals) {
      session.signals[mod] = session.signals[mod].slice(-maxSignals);
    }

    stats.totalSignals++;
    stats.moduleSignalCounts[mod] = (stats.moduleSignalCounts[mod] || 0) + 1;

    return { ok: true, module: mod, signalCount: session.signals[mod].length };
  }

  /**
   * Evaluate the aggregate risk for a session.
   * @param {string} sessionId
   * @param {Object} [evalOptions] - { includeTimeline, now }
   * @returns {Object} verdict
   */
  function evaluate(sessionId, evalOptions) {
    evalOptions = evalOptions || {};
    var now = evalOptions.now || _now();

    if (!sessionId || !sessions[sessionId]) {
      return {
        sessionId: sessionId,
        score: 0,
        level: "low",
        action: actions.low,
        factors: [],
        moduleScores: {},
        correlations: [],
        signalCount: 0,
        error: !sessionId ? "sessionId required" : "session not found"
      };
    }

    var session = sessions[sessionId];
    var moduleScores = Object.create(null);
    var activeModules = [];
    var activeWeights = [];
    var activeValues = [];
    var allFactors = [];

    // Score each module
    var mods = Object.keys(session.signals);
    for (var i = 0; i < mods.length; i++) {
      var mod = mods[i];
      var ms = _scoreForModule(session, mod, now);
      if (ms !== undefined) {
        moduleScores[mod] = Math.round(ms * 1000) / 1000;
        activeModules.push(mod);
        activeValues.push(ms);
        activeWeights.push(weights[mod] || 0.1); // default weight for unknown modules

        // Collect unique factors
        var sigs = session.signals[mod];
        for (var j = 0; j < sigs.length; j++) {
          var factors = sigs[j].factors || [];
          for (var f = 0; f < factors.length; f++) {
            if (allFactors.indexOf(factors[f]) === -1) {
              allFactors.push(factors[f]);
            }
          }
        }
      }
    }

    // Weighted average
    var baseScore = activeValues.length > 0
      ? _weightedAverage(activeValues, activeWeights)
      : 0;

    // Apply correlation rules
    var correlations = [];
    var boostTotal = 0;
    for (var r = 0; r < allRules.length; r++) {
      var rule = allRules[r];
      // Check if we have data for at least the required modules
      var hasModules = true;
      for (var m = 0; m < rule.modules.length; m++) {
        if (moduleScores[rule.modules[m]] === undefined) {
          hasModules = false;
          break;
        }
      }
      if (hasModules && rule.condition(moduleScores)) {
        correlations.push({
          rule: rule.name,
          description: rule.description,
          boost: rule.boost
        });
        boostTotal += rule.boost;
      }
    }

    var finalScore = _clamp(baseScore + boostTotal, 0, 1);
    finalScore = Math.round(finalScore * 1000) / 1000;
    var level = _classifyLevel(finalScore);
    var action = actions[level] || "allow";

    // Count total signals
    var signalCount = 0;
    for (var sc = 0; sc < mods.length; sc++) {
      signalCount += session.signals[mods[sc]].length;
    }

    // Build timeline if requested
    var timeline = [];
    if (evalOptions.includeTimeline) {
      for (var tm = 0; tm < mods.length; tm++) {
        var tsigs = session.signals[mods[tm]];
        for (var ts = 0; ts < tsigs.length; ts++) {
          timeline.push({
            module: mods[tm],
            score: tsigs[ts].score,
            level: tsigs[ts].level,
            factors: tsigs[ts].factors,
            timestamp: tsigs[ts].timestamp
          });
        }
      }
      timeline.sort(function (a, b) { return a.timestamp - b.timestamp; });
    }

    var verdict = {
      sessionId: sessionId,
      score: finalScore,
      level: level,
      action: action,
      factors: allFactors,
      moduleScores: moduleScores,
      modulesReporting: activeModules.length,
      correlations: correlations,
      signalCount: signalCount,
      sessionAge: now - session.firstSeen,
      evaluatedAt: now
    };

    if (timeline.length > 0) verdict.timeline = timeline;

    // Lock session if blocked (avoid double-counting)
    if (action === "block" && !session.locked) {
      session.locked = true;
      stats.blockedSessions++;
    }

    // Track evaluation
    session.evaluations.push({
      score: finalScore,
      level: level,
      action: action,
      timestamp: now
    });
    stats.totalEvaluations++;
    stats.verdictCounts[level] = (stats.verdictCounts[level] || 0) + 1;

    return verdict;
  }

  /**
   * Batch-evaluate all active sessions.
   * @param {Object} [evalOptions]
   * @returns {{ sessions: Object[], summary: Object }}
   */
  function evaluateAll(evalOptions) {
    evalOptions = evalOptions || {};
    var now = evalOptions.now || _now();
    _pruneOld(now);

    var ids = Object.keys(sessions);
    var results = [];
    var levels = { low: 0, medium: 0, high: 0, critical: 0 };

    for (var i = 0; i < ids.length; i++) {
      var v = evaluate(ids[i], { now: now, includeTimeline: evalOptions.includeTimeline });
      results.push(v);
      levels[v.level]++;
    }

    // Sort by score descending
    results.sort(function (a, b) { return b.score - a.score; });

    var scores = results.map(function (r) { return r.score; });

    return {
      sessions: results,
      summary: {
        total: results.length,
        levels: levels,
        avgScore: scores.length > 0 ? Math.round(_weightedAverage(scores, scores.map(function () { return 1; })) * 1000) / 1000 : 0,
        p50Score: _percentile(scores, 50),
        p90Score: _percentile(scores, 90),
        p99Score: _percentile(scores, 99)
      }
    };
  }

  /**
   * Get session details without evaluating.
   * @param {string} sessionId
   * @returns {Object|null}
   */
  function getSession(sessionId) {
    var session = sessions[sessionId];
    if (!session) return null;

    var moduleSummary = Object.create(null);
    var mods = Object.keys(session.signals);
    for (var i = 0; i < mods.length; i++) {
      moduleSummary[mods[i]] = {
        signalCount: session.signals[mods[i]].length,
        latestScore: session.signals[mods[i]][session.signals[mods[i]].length - 1].score,
        latestLevel: session.signals[mods[i]][session.signals[mods[i]].length - 1].level
      };
    }

    return {
      sessionId: sessionId,
      firstSeen: session.firstSeen,
      lastSeen: session.lastSeen,
      locked: session.locked,
      modules: moduleSummary,
      evaluationCount: session.evaluations.length,
      metadata: _deepCopy(session.metadata)
    };
  }

  /**
   * Attach metadata to a session.
   * @param {string} sessionId
   * @param {Object} meta
   */
  function setMetadata(sessionId, meta) {
    var session = _getSession(sessionId);
    session.metadata = _merge(session.metadata, meta || {});
    return { ok: true };
  }

  /**
   * Unlock a blocked session (admin override).
   * @param {string} sessionId
   * @returns {{ ok: boolean }}
   */
  function unlock(sessionId) {
    var session = sessions[sessionId];
    if (!session) return { ok: false, error: "session not found" };
    session.locked = false;
    return { ok: true };
  }

  /**
   * Remove a session.
   * @param {string} sessionId
   * @returns {{ ok: boolean }}
   */
  function removeSession(sessionId) {
    if (!sessions[sessionId]) return { ok: false, error: "session not found" };
    if (sessions[sessionId].locked) {
      stats.blockedSessions = Math.max(0, stats.blockedSessions - 1);
    }
    delete sessions[sessionId];
    stats.totalSessions = Math.max(0, stats.totalSessions - 1);
    return { ok: true };
  }

  /**
   * Get risk trend for a session (evaluation history).
   * @param {string} sessionId
   * @returns {{ trend: Array, direction: string }}
   */
  function getTrend(sessionId) {
    var session = sessions[sessionId];
    if (!session || session.evaluations.length === 0) {
      return { trend: [], direction: "stable" };
    }

    var evals = session.evaluations;
    var trend = evals.map(function (e) {
      return { score: e.score, level: e.level, timestamp: e.timestamp };
    });

    var direction = "stable";
    if (evals.length >= 2) {
      var recent = evals[evals.length - 1].score;
      var prev = evals[evals.length - 2].score;
      if (recent - prev > 0.05) direction = "rising";
      else if (prev - recent > 0.05) direction = "falling";
    }

    return { trend: trend, direction: direction };
  }

  /**
   * Get global aggregator stats.
   * @returns {Object}
   */
  function getStats() {
    return _deepCopy(stats);
  }

  /**
   * Get the current module weight configuration.
   * @returns {Object}
   */
  function getWeights() {
    return _deepCopy(weights);
  }

  /**
   * Update module weights at runtime.
   * @param {Object} newWeights
   * @returns {{ ok: boolean, weights: Object }}
   */
  function setWeights(newWeights) {
    weights = _merge(weights, newWeights || {});
    return { ok: true, weights: _deepCopy(weights) };
  }

  /**
   * Prune expired sessions.
   * @param {number} [now]
   * @returns {{ pruned: number }}
   */
  function prune(now) {
    now = now || _now();
    var before = Object.keys(sessions).length;
    _pruneOld(now);
    var after = Object.keys(sessions).length;
    return { pruned: before - after };
  }

  /**
   * Generate a human-readable risk report for a session.
   * @param {string} sessionId
   * @returns {string}
   */
  function report(sessionId) {
    var v = evaluate(sessionId, { includeTimeline: true });
    if (v.error) return "Session Risk Report: " + v.error;

    var lines = [];
    lines.push("═══ Session Risk Report ═══");
    lines.push("Session:    " + v.sessionId);
    lines.push("Score:      " + v.score + " / 1.00  [" + v.level.toUpperCase() + "]");
    lines.push("Action:     " + v.action);
    lines.push("Signals:    " + v.signalCount + " from " + v.modulesReporting + " module(s)");
    lines.push("Age:        " + Math.round(v.sessionAge / 1000) + "s");
    lines.push("");
    lines.push("── Module Scores ──");
    var mods = Object.keys(v.moduleScores);
    for (var i = 0; i < mods.length; i++) {
      var bar = "";
      var filled = Math.round(v.moduleScores[mods[i]] * 20);
      for (var b = 0; b < 20; b++) bar += b < filled ? "█" : "░";
      lines.push("  " + _padRight(mods[i], 12) + " " + bar + " " + v.moduleScores[mods[i]]);
    }

    if (v.correlations.length > 0) {
      lines.push("");
      lines.push("── Correlations ──");
      for (var c = 0; c < v.correlations.length; c++) {
        var cr = v.correlations[c];
        var sign = cr.boost >= 0 ? "+" : "";
        lines.push("  " + cr.rule + ": " + cr.description + " (" + sign + cr.boost + ")");
      }
    }

    if (v.factors.length > 0) {
      lines.push("");
      lines.push("── Risk Factors ──");
      for (var f = 0; f < v.factors.length; f++) {
        lines.push("  • " + v.factors[f]);
      }
    }

    if (v.timeline && v.timeline.length > 0) {
      lines.push("");
      lines.push("── Timeline ──");
      for (var t = 0; t < Math.min(v.timeline.length, 20); t++) {
        var te = v.timeline[t];
        lines.push("  " + new Date(te.timestamp).toISOString() + "  " +
          _padRight(te.module, 12) + " " + te.score + " [" + te.level + "]");
      }
      if (v.timeline.length > 20) {
        lines.push("  ... +" + (v.timeline.length - 20) + " more");
      }
    }

    lines.push("");
    lines.push("═══════════════════════════");
    return lines.join("\n");
  }

  /**
   * Export all session data (for persistence/debugging).
   * @returns {Object}
   */
  function exportData() {
    return {
      sessions: _deepCopy(sessions),
      stats: _deepCopy(stats),
      config: {
        weights: _deepCopy(weights),
        thresholds: _deepCopy(thresholds),
        actions: _deepCopy(actions),
        decayHalfLifeMs: decayHalfLife,
        maxSignalsPerModule: maxSignals,
        sessionTTLMs: sessionTTL
      }
    };
  }

  /**
   * Import session data (restore from export).
   * @param {Object} data
   * @returns {{ ok: boolean, sessionsLoaded: number }}
   */
  function importData(data) {
    if (!data || !data.sessions) return { ok: false, error: "invalid data" };
    var ids = Object.keys(data.sessions);
    for (var i = 0; i < ids.length; i++) {
      sessions[ids[i]] = _deepCopy(data.sessions[ids[i]]);
    }
    if (data.stats) stats = _merge(stats, data.stats);
    return { ok: true, sessionsLoaded: ids.length };
  }

  /**
   * Reset all state.
   */
  function reset() {
    sessions = Object.create(null);
    stats = {
      totalSignals: 0,
      totalEvaluations: 0,
      totalSessions: 0,
      verdictCounts: { low: 0, medium: 0, high: 0, critical: 0 },
      moduleSignalCounts: {},
      blockedSessions: 0
    };
    return { ok: true };
  }

  function _padRight(str, len) {
    while (str.length < len) str += " ";
    return str;
  }

  return {
    addSignal: addSignal,
    evaluate: evaluate,
    evaluateAll: evaluateAll,
    getSession: getSession,
    setMetadata: setMetadata,
    unlock: unlock,
    removeSession: removeSession,
    getTrend: getTrend,
    getStats: getStats,
    getWeights: getWeights,
    setWeights: setWeights,
    prune: prune,
    report: report,
    exportData: exportData,
    importData: importData,
    reset: reset
  };
}

// ── Exports ─────────────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createSessionRiskAggregator: createSessionRiskAggregator };
}