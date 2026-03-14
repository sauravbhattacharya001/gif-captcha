/**
 * CaptchaFatigueDetector — detects user frustration and fatigue patterns
 * during CAPTCHA solving sessions.
 *
 * Tracks behavioral signals (repeated failures, increasing solve times,
 * rapid retries / rage-clicking, session duration) and computes a composite
 * fatigue score. When fatigue exceeds configurable thresholds the module
 * emits recommendations (reduce difficulty, offer alternative challenge,
 * or cool-down pause).
 *
 * @module gif-captcha/captcha-fatigue-detector
 */

"use strict";

// ── Defaults ────────────────────────────────────────────────────────

var DEFAULT_OPTIONS = {
  mildThreshold: 30,
  moderateThreshold: 55,
  severeThreshold: 80,
  windowMs: 300000,
  minEvents: 3,
  weights: {
    failureRate: 0.30,
    solveTimeEscalation: 0.25,
    rapidRetry: 0.20,
    sessionLength: 0.15,
    abandonmentSignal: 0.10
  },
  rapidRetryThresholdMs: 2000,
  sessionFatigueCeilingMs: 600000,
  baselineSolveTimeMs: 5000,
  maxExpectedSolveTimeMs: 30000,
  abandonmentGapMs: 60000,
  cooldownDurationMs: 30000,
  maxEventsPerSession: 200,
  maxSessions: 5000,
  sessionTtlMs: 3600000
};

var FATIGUE_LEVELS = {
  NONE: "none",
  MILD: "mild",
  MODERATE: "moderate",
  SEVERE: "severe"
};

var RECOMMENDATIONS = {
  NONE: "none",
  REDUCE_DIFFICULTY: "reduce_difficulty",
  OFFER_ALTERNATIVE: "offer_alternative",
  COOLDOWN_PAUSE: "cooldown_pause",
  SKIP_CAPTCHA: "skip_captcha"
};

function clamp(val, min, max) {
  return val < min ? min : val > max ? max : val;
}

function tsNow() { return Date.now(); }

function deepCopy(obj) { return JSON.parse(JSON.stringify(obj)); }

function mean(arr) {
  if (!arr.length) return 0;
  var s = 0;
  for (var i = 0; i < arr.length; i++) s += arr[i];
  return s / arr.length;
}

function linearRegSlope(vals) {
  if (vals.length < 2) return 0;
  var n = vals.length, sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
  for (var i = 0; i < n; i++) {
    sumX += i; sumY += vals[i]; sumXY += i * vals[i]; sumX2 += i * i;
  }
  var denom = n * sumX2 - sumX * sumX;
  return denom === 0 ? 0 : (n * sumXY - sumX * sumY) / denom;
}

function createSession(sessionId, timestamp) {
  return {
    id: sessionId, createdAt: timestamp, lastActivity: timestamp,
    events: [], fatigueHistory: [], recommendationHistory: [], dismissed: false
  };
}

function createCaptchaFatigueDetector(options) {
  var opts = Object.create(null);
  var key;
  for (key in DEFAULT_OPTIONS) {
    if (DEFAULT_OPTIONS.hasOwnProperty(key)) opts[key] = DEFAULT_OPTIONS[key];
  }
  if (options) {
    for (key in options) {
      if (options.hasOwnProperty(key)) {
        if (key === "weights" && typeof options[key] === "object") {
          opts.weights = Object.create(null);
          for (var w in DEFAULT_OPTIONS.weights) {
            if (DEFAULT_OPTIONS.weights.hasOwnProperty(w)) {
              opts.weights[w] = (options.weights && options.weights.hasOwnProperty(w))
                ? options.weights[w] : DEFAULT_OPTIONS.weights[w];
            }
          }
        } else {
          opts[key] = options[key];
        }
      }
    }
  }

  var sessions = Object.create(null);
  var sessionCount = 0;
  var listeners = Object.create(null);
  var globalStats = {
    totalEvents: 0, totalSessions: 0,
    fatigueDetections: { none: 0, mild: 0, moderate: 0, severe: 0 },
    recommendationsIssued: 0
  };

  function on(event, fn) {
    if (!listeners[event]) listeners[event] = [];
    listeners[event].push(fn);
  }

  function off(event, fn) {
    if (!listeners[event]) return;
    listeners[event] = listeners[event].filter(function (f) { return f !== fn; });
  }

  function emit(event, data) {
    if (!listeners[event]) return;
    for (var i = 0; i < listeners[event].length; i++) {
      try { listeners[event][i](data); } catch (e) { /* swallow */ }
    }
  }

  function getOrCreateSession(sessionId, timestamp) {
    var ts = timestamp != null ? timestamp : tsNow();
    if (!sessions[sessionId]) {
      if (sessionCount >= opts.maxSessions) purgeOldSessions(ts);
      sessions[sessionId] = createSession(sessionId, ts);
      sessionCount++;
      globalStats.totalSessions++;
    }
    return sessions[sessionId];
  }

  function purgeOldSessions(currentTime) {
    var cutoff = currentTime - opts.sessionTtlMs;
    var ids = Object.keys(sessions);
    for (var i = 0; i < ids.length; i++) {
      if (sessions[ids[i]].lastActivity < cutoff) {
        delete sessions[ids[i]]; sessionCount--;
      }
    }
  }

  function recordEvent(sessionId, eventData) {
    if (!sessionId || typeof sessionId !== "string")
      throw new Error("sessionId is required and must be a string");
    if (!eventData || typeof eventData !== "object")
      throw new Error("eventData is required and must be an object");
    var type = eventData.type;
    if (type !== "solve" && type !== "fail" && type !== "abandon" && type !== "refresh")
      throw new Error("eventData.type must be 'solve', 'fail', 'abandon', or 'refresh'");

    var ts = eventData.timestamp != null ? eventData.timestamp : tsNow();
    var session = getOrCreateSession(sessionId, ts);
    var evt = {
      type: type, timestamp: ts, solveTimeMs: eventData.solveTimeMs || null,
      challengeId: eventData.challengeId || null, difficulty: eventData.difficulty || null,
      metadata: eventData.metadata || null
    };

    session.events.push(evt);
    session.lastActivity = ts;
    globalStats.totalEvents++;

    if (session.events.length > opts.maxEventsPerSession)
      session.events = session.events.slice(session.events.length - opts.maxEventsPerSession);

    var assessment = evaluate(sessionId, ts);
    emit("event", { sessionId: sessionId, event: evt, assessment: assessment });
    return assessment;
  }

  function computeFailureRate(events) {
    if (!events.length) return 0;
    var fails = 0;
    for (var i = 0; i < events.length; i++) { if (events[i].type === "fail") fails++; }
    return clamp(fails / events.length * 100, 0, 100);
  }

  function computeSolveTimeEscalation(events) {
    var solveTimes = [];
    for (var i = 0; i < events.length; i++) {
      if (events[i].solveTimeMs != null && events[i].solveTimeMs > 0)
        solveTimes.push(events[i].solveTimeMs);
    }
    if (solveTimes.length < 2) return 0;
    var slope = linearRegSlope(solveTimes);
    var slopeScore = clamp(slope / 500 * 50, 0, 50);
    var avg = mean(solveTimes);
    var levelScore = clamp(
      (avg - opts.baselineSolveTimeMs) / (opts.maxExpectedSolveTimeMs - opts.baselineSolveTimeMs) * 50, 0, 50
    );
    return clamp(slopeScore + levelScore, 0, 100);
  }

  function computeRapidRetry(events) {
    if (events.length < 2) return 0;
    var rapidCount = 0;
    for (var i = 1; i < events.length; i++) {
      var gap = events[i].timestamp - events[i - 1].timestamp;
      if (gap < opts.rapidRetryThresholdMs && gap >= 0) rapidCount++;
    }
    return clamp(rapidCount / (events.length - 1) * 100, 0, 100);
  }

  function computeSessionLength(session, currentTime) {
    var duration = currentTime - session.createdAt;
    return clamp(duration / opts.sessionFatigueCeilingMs * 100, 0, 100);
  }

  function computeAbandonmentSignal(events, currentTime) {
    if (events.length === 0) return 0;
    var lastEvent = events[events.length - 1];
    var gap = currentTime - lastEvent.timestamp;
    var abandonCount = 0;
    for (var i = 0; i < events.length; i++) {
      if (events[i].type === "abandon" || events[i].type === "refresh") abandonCount++;
    }
    var eventScore = clamp(abandonCount / Math.max(events.length, 1) * 60, 0, 60);
    var gapScore = gap >= opts.abandonmentGapMs ? 40 : (gap / opts.abandonmentGapMs * 40);
    return clamp(eventScore + gapScore, 0, 100);
  }

  function evaluate(sessionId, currentTime) {
    var ts = currentTime != null ? currentTime : tsNow();
    var session = sessions[sessionId];
    if (!session) {
      return { sessionId: sessionId, fatigueScore: 0, level: FATIGUE_LEVELS.NONE,
        recommendation: RECOMMENDATIONS.NONE, dimensions: null, eventCount: 0, sessionDurationMs: 0 };
    }

    var cutoff = ts - opts.windowMs;
    var windowEvents = [];
    for (var i = 0; i < session.events.length; i++) {
      if (session.events[i].timestamp >= cutoff) windowEvents.push(session.events[i]);
    }

    if (windowEvents.length < opts.minEvents) {
      return { sessionId: sessionId, fatigueScore: 0, level: FATIGUE_LEVELS.NONE,
        recommendation: RECOMMENDATIONS.NONE,
        dimensions: { failureRate: 0, solveTimeEscalation: 0, rapidRetry: 0, sessionLength: 0, abandonmentSignal: 0 },
        eventCount: windowEvents.length, sessionDurationMs: ts - session.createdAt };
    }

    var dims = {
      failureRate: computeFailureRate(windowEvents),
      solveTimeEscalation: computeSolveTimeEscalation(windowEvents),
      rapidRetry: computeRapidRetry(windowEvents),
      sessionLength: computeSessionLength(session, ts),
      abandonmentSignal: computeAbandonmentSignal(windowEvents, ts)
    };

    var score = 0;
    for (var d in dims) {
      if (dims.hasOwnProperty(d) && opts.weights.hasOwnProperty(d))
        score += dims[d] * opts.weights[d];
    }
    score = clamp(Math.round(score * 100) / 100, 0, 100);

    var level;
    if (score >= opts.severeThreshold) level = FATIGUE_LEVELS.SEVERE;
    else if (score >= opts.moderateThreshold) level = FATIGUE_LEVELS.MODERATE;
    else if (score >= opts.mildThreshold) level = FATIGUE_LEVELS.MILD;
    else level = FATIGUE_LEVELS.NONE;

    var recommendation;
    if (level === FATIGUE_LEVELS.SEVERE) recommendation = RECOMMENDATIONS.SKIP_CAPTCHA;
    else if (level === FATIGUE_LEVELS.MODERATE) {
      if (dims.rapidRetry > 60) recommendation = RECOMMENDATIONS.COOLDOWN_PAUSE;
      else if (dims.failureRate > 60) recommendation = RECOMMENDATIONS.REDUCE_DIFFICULTY;
      else recommendation = RECOMMENDATIONS.OFFER_ALTERNATIVE;
    } else if (level === FATIGUE_LEVELS.MILD) recommendation = RECOMMENDATIONS.REDUCE_DIFFICULTY;
    else recommendation = RECOMMENDATIONS.NONE;

    var assessment = {
      sessionId: sessionId, fatigueScore: score, level: level,
      recommendation: recommendation, dimensions: dims,
      eventCount: windowEvents.length, sessionDurationMs: ts - session.createdAt, timestamp: ts
    };

    session.fatigueHistory.push({ score: score, level: level, timestamp: ts });
    if (session.fatigueHistory.length > 50) session.fatigueHistory = session.fatigueHistory.slice(-50);

    globalStats.fatigueDetections[level]++;
    if (recommendation !== RECOMMENDATIONS.NONE) {
      globalStats.recommendationsIssued++;
      session.recommendationHistory.push({ recommendation: recommendation, score: score, timestamp: ts });
      emit("recommendation", { sessionId: sessionId, assessment: assessment });
    }
    if (level === FATIGUE_LEVELS.SEVERE)
      emit("severe_fatigue", { sessionId: sessionId, assessment: assessment });

    return assessment;
  }

  function dismissFatigue(sessionId) {
    var session = sessions[sessionId];
    if (!session) return false;
    session.dismissed = true;
    emit("dismissed", { sessionId: sessionId });
    return true;
  }

  function resetSession(sessionId) {
    if (sessions[sessionId]) { delete sessions[sessionId]; sessionCount--; return true; }
    return false;
  }

  function getSessionReport(sessionId, currentTime) {
    var ts = currentTime != null ? currentTime : tsNow();
    var session = sessions[sessionId];
    if (!session) return null;
    var assessment = evaluate(sessionId, ts);
    var totalSolves = 0, totalFails = 0, totalAbandons = 0, totalRefreshes = 0, solveTimes = [];
    for (var i = 0; i < session.events.length; i++) {
      var e = session.events[i];
      if (e.type === "solve") { totalSolves++; if (e.solveTimeMs) solveTimes.push(e.solveTimeMs); }
      else if (e.type === "fail") totalFails++;
      else if (e.type === "abandon") totalAbandons++;
      else if (e.type === "refresh") totalRefreshes++;
    }
    return {
      sessionId: sessionId, createdAt: session.createdAt, lastActivity: session.lastActivity,
      durationMs: ts - session.createdAt, totalEvents: session.events.length,
      solves: totalSolves, fails: totalFails, abandons: totalAbandons, refreshes: totalRefreshes,
      solveRate: (totalSolves + totalFails) > 0 ? totalSolves / (totalSolves + totalFails) : null,
      avgSolveTimeMs: solveTimes.length > 0 ? Math.round(mean(solveTimes)) : null,
      assessment: assessment, fatigueHistory: deepCopy(session.fatigueHistory), dismissed: session.dismissed
    };
  }

  function getFleetReport(currentTime) {
    var ts = currentTime != null ? currentTime : tsNow();
    var ids = Object.keys(sessions);
    var activeSessions = 0, fatiguedSessions = { mild: 0, moderate: 0, severe: 0 };
    var scores = [], topFatigued = [];
    for (var i = 0; i < ids.length; i++) {
      var session = sessions[ids[i]];
      if (ts - session.lastActivity > opts.sessionTtlMs) continue;
      activeSessions++;
      var assessment = evaluate(ids[i], ts);
      scores.push(assessment.fatigueScore);
      if (assessment.level !== FATIGUE_LEVELS.NONE) {
        fatiguedSessions[assessment.level]++;
        topFatigued.push({ sessionId: ids[i], score: assessment.fatigueScore,
          level: assessment.level, recommendation: assessment.recommendation });
      }
    }
    topFatigued.sort(function (a, b) { return b.score - a.score; });
    if (topFatigued.length > 10) topFatigued = topFatigued.slice(0, 10);
    return {
      activeSessions: activeSessions,
      averageFatigueScore: scores.length > 0 ? Math.round(mean(scores) * 100) / 100 : 0,
      fatiguedSessions: fatiguedSessions, topFatigued: topFatigued,
      globalStats: deepCopy(globalStats), timestamp: ts
    };
  }

  function getFatigueTrend(sessionId) {
    var session = sessions[sessionId];
    if (!session || session.fatigueHistory.length < 2) return null;
    var scores = [];
    for (var i = 0; i < session.fatigueHistory.length; i++) scores.push(session.fatigueHistory[i].score);
    var slope = linearRegSlope(scores);
    var direction = slope > 1 ? "increasing" : slope < -1 ? "decreasing" : "stable";
    return {
      sessionId: sessionId, dataPoints: scores.length,
      currentScore: scores[scores.length - 1],
      previousScore: scores.length >= 2 ? scores[scores.length - 2] : null,
      slope: Math.round(slope * 1000) / 1000, direction: direction,
      peakScore: Math.max.apply(null, scores), minScore: Math.min.apply(null, scores)
    };
  }

  function exportState() {
    return { sessions: deepCopy(sessions), globalStats: deepCopy(globalStats), options: deepCopy(opts) };
  }

  function importState(state) {
    if (!state || typeof state !== "object") throw new Error("Invalid state object");
    if (state.sessions) { sessions = deepCopy(state.sessions); sessionCount = Object.keys(sessions).length; }
    if (state.globalStats) globalStats = deepCopy(state.globalStats);
  }

  function pad(val) { var s = val.toFixed(1); while (s.length < 6) s = " " + s; return s; }

  function generateTextReport(sessionId, currentTime) {
    var report = getSessionReport(sessionId, currentTime);
    if (!report) return "No session found: " + sessionId;
    var lines = [];
    lines.push("╔══════════════════════════════════════════════════════════╗");
    lines.push("║           CAPTCHA FATIGUE REPORT                       ║");
    lines.push("╠══════════════════════════════════════════════════════════╣");
    lines.push("  Session: " + report.sessionId);
    lines.push("  Duration: " + Math.round(report.durationMs / 1000) + "s");
    lines.push("  Events: " + report.totalEvents +
      " (✓" + report.solves + " ✗" + report.fails +
      " ⊘" + report.abandons + " ↻" + report.refreshes + ")");
    if (report.solveRate !== null) lines.push("  Solve Rate: " + (report.solveRate * 100).toFixed(1) + "%");
    if (report.avgSolveTimeMs !== null) lines.push("  Avg Solve Time: " + report.avgSolveTimeMs + "ms");
    lines.push("╠══════════════════════════════════════════════════════════╣");
    lines.push("  FATIGUE SCORE: " + report.assessment.fatigueScore + " / 100");
    lines.push("  Level: " + report.assessment.level.toUpperCase());
    lines.push("  Recommendation: " + report.assessment.recommendation);
    lines.push("╠══════════════════════════════════════════════════════════╣");
    var dims = report.assessment.dimensions;
    if (dims) {
      lines.push("  Dimensions:");
      lines.push("    Failure Rate:         " + pad(dims.failureRate) + " /100");
      lines.push("    Solve Time Escalation:" + pad(dims.solveTimeEscalation) + " /100");
      lines.push("    Rapid Retry:          " + pad(dims.rapidRetry) + " /100");
      lines.push("    Session Length:        " + pad(dims.sessionLength) + " /100");
      lines.push("    Abandonment Signal:   " + pad(dims.abandonmentSignal) + " /100");
    }
    lines.push("╚══════════════════════════════════════════════════════════╝");
    return lines.join("\n");
  }

  return {
    recordEvent: recordEvent, evaluate: evaluate, dismissFatigue: dismissFatigue,
    resetSession: resetSession, getSessionReport: getSessionReport,
    getFleetReport: getFleetReport, getFatigueTrend: getFatigueTrend,
    generateTextReport: generateTextReport, exportState: exportState,
    importState: importState, on: on, off: off,
    FATIGUE_LEVELS: FATIGUE_LEVELS, RECOMMENDATIONS: RECOMMENDATIONS
  };
}

module.exports = {
  createCaptchaFatigueDetector: createCaptchaFatigueDetector,
  FATIGUE_LEVELS: FATIGUE_LEVELS,
  RECOMMENDATIONS: RECOMMENDATIONS,
  DEFAULT_OPTIONS: DEFAULT_OPTIONS
};
