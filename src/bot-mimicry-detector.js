/**
 * BotMimicryDetector — Autonomous bot mimicry detection engine.
 *
 * Detects sophisticated bots that deliberately imitate human behavioral
 * patterns by finding "uncanny valley" signals — behaviors that are TOO
 * human, TOO consistent, or TOO perfect. While basic bot detectors look
 * for inhuman speed or mechanical precision, mimicry detection catches
 * bots that have learned to appear human.
 *
 * Key capabilities:
 *   - Uncanny valley detection (suspiciously ideal human metrics)
 *   - Consistency paradox analysis (too-regular "randomness")
 *   - Fatigue immunity detection (no degradation over long sessions)
 *   - Behavioral template matching against known mimicry signatures
 *   - Micro-pattern analysis (sub-second timing distribution entropy)
 *   - Cross-session coherence checking (same source, same profile)
 *   - Composite mimicry scoring 0-100 with 5-tier classification
 *   - Autonomous insight generation
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/bot-mimicry-detector
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
var _cosineSimilarity = _shared._cosineSimilarity;
var LruTracker = _shared.LruTracker;

// ── Constants ───────────────────────────────────────────────────────

/** Mimicry tiers from least to most suspicious */
var MIMICRY_TIERS = ["GENUINE", "LIKELY_HUMAN", "SUSPICIOUS", "LIKELY_MIMICRY", "CONFIRMED_MIMICRY"];

/** Engine names */
var ENGINE_NAMES = [
  "uncannyValley",
  "consistencyParadox",
  "fatigueImmunity",
  "templateMatch",
  "microPattern",
  "crossSession"
];

/** Default human baselines for uncanny valley detection */
var HUMAN_BASELINES = {
  solveTimeMeanMs: 3000,
  solveTimeStddevMs: 1200,
  accuracyRate: 0.78,
  accuracyStddev: 0.15,
  interArrivalMeanMs: 8000,
  interArrivalStddevMs: 4000
};

var DEFAULT_OPTIONS = {
  maxSessions: 5000,
  maxEventsPerSession: 500,
  minEventsForAnalysis: 8,
  analysisWindowMs: 3600000,
  fatigueWindowEvents: 20,
  microPatternBuckets: 50,
  maxTemplates: 100,
  maxInsights: 200,
  weights: {
    uncannyValley: 0.20,
    consistencyParadox: 0.20,
    fatigueImmunity: 0.15,
    templateMatch: 0.15,
    microPattern: 0.15,
    crossSession: 0.15
  }
};

// ── Helpers ─────────────────────────────────────────────────────────

function _entropy(arr) {
  if (!arr || arr.length < 2) return 0;
  var min = arr[0], max = arr[0];
  for (var i = 1; i < arr.length; i++) {
    if (arr[i] < min) min = arr[i];
    if (arr[i] > max) max = arr[i];
  }
  if (max === min) return 0;
  var buckets = Math.min(10, arr.length);
  var width = (max - min) / buckets;
  var counts = [];
  for (var j = 0; j < buckets; j++) counts[j] = 0;
  for (var k = 0; k < arr.length; k++) {
    var idx = Math.min(Math.floor((arr[k] - min) / width), buckets - 1);
    counts[idx]++;
  }
  var h = 0;
  for (var b = 0; b < buckets; b++) {
    if (counts[b] > 0) {
      var p = counts[b] / arr.length;
      h -= p * (Math.log(p) / Math.LN2);
    }
  }
  return h;
}

function _autocorrelation(values, lag) {
  if (!values || values.length <= lag) return 0;
  var m = _mean(values);
  var n = values.length;
  var num = 0, denom = 0;
  for (var i = 0; i < n; i++) {
    denom += (values[i] - m) * (values[i] - m);
  }
  if (denom === 0) return 1;
  for (var j = 0; j < n - lag; j++) {
    num += (values[j] - m) * (values[j + lag] - m);
  }
  return num / denom;
}

function _varianceOfWindows(values, windowSize) {
  if (!values || values.length < windowSize * 2) return 0;
  var variances = [];
  for (var i = 0; i <= values.length - windowSize; i += windowSize) {
    var win = values.slice(i, i + windowSize);
    var sd = _stddev(win);
    variances.push(sd * sd);
  }
  if (variances.length < 2) return 0;
  return _stddev(variances);
}

function _tierFromScore(score) {
  if (score <= 20) return MIMICRY_TIERS[0];
  if (score <= 40) return MIMICRY_TIERS[1];
  if (score <= 60) return MIMICRY_TIERS[2];
  if (score <= 80) return MIMICRY_TIERS[3];
  return MIMICRY_TIERS[4];
}

// ── Factory ─────────────────────────────────────────────────────────

/**
 * Create a Bot Mimicry Detector instance.
 *
 * @param {object} [options]
 * @param {number} [options.maxSessions=5000]
 * @param {number} [options.maxEventsPerSession=500]
 * @param {number} [options.minEventsForAnalysis=8]
 * @param {number} [options.analysisWindowMs=3600000]
 * @param {number} [options.fatigueWindowEvents=20]
 * @param {number} [options.microPatternBuckets=50]
 * @param {number} [options.maxTemplates=100]
 * @param {number} [options.maxInsights=200]
 * @param {object} [options.weights]
 * @returns {object} BotMimicryDetector instance
 */
function createBotMimicryDetector(options) {
  options = options || {};

  var maxSessions = _posOpt(options.maxSessions, DEFAULT_OPTIONS.maxSessions);
  var maxEventsPerSession = _posOpt(options.maxEventsPerSession, DEFAULT_OPTIONS.maxEventsPerSession);
  var minEventsForAnalysis = _posOpt(options.minEventsForAnalysis, DEFAULT_OPTIONS.minEventsForAnalysis);
  var analysisWindowMs = _posOpt(options.analysisWindowMs, DEFAULT_OPTIONS.analysisWindowMs);
  var fatigueWindowEvents = _posOpt(options.fatigueWindowEvents, DEFAULT_OPTIONS.fatigueWindowEvents);
  var microPatternBuckets = _posOpt(options.microPatternBuckets, DEFAULT_OPTIONS.microPatternBuckets);
  var maxTemplates = _posOpt(options.maxTemplates, DEFAULT_OPTIONS.maxTemplates);
  var maxInsights = _posOpt(options.maxInsights, DEFAULT_OPTIONS.maxInsights);

  var weights = {};
  var uw = options.weights || {};
  for (var wi = 0; wi < ENGINE_NAMES.length; wi++) {
    var en = ENGINE_NAMES[wi];
    weights[en] = uw[en] != null && uw[en] >= 0 ? uw[en] : DEFAULT_OPTIONS.weights[en];
  }

  // ── State ───────────────────────────────────────────────────────

  var _sessions = Object.create(null);
  var _sessionLru = new LruTracker();
  var _templates = [];
  var _insights = [];

  // ── Session Management ──────────────────────────────────────────

  function _getSession(sessionId) {
    if (!_sessions[sessionId]) {
      if (_sessionLru.length >= maxSessions) {
        var evicted = _sessionLru.evictOldest();
        if (evicted) delete _sessions[evicted];
      }
      _sessions[sessionId] = {
        id: sessionId,
        sourceId: null,
        events: [],
        firstSeen: _now(),
        lastSeen: _now(),
        totalEvents: 0
      };
      _sessionLru.push(sessionId);
    } else {
      _sessionLru.touch(sessionId);
    }
    return _sessions[sessionId];
  }

  // ── Record Event ────────────────────────────────────────────────

  function recordEvent(event) {
    if (!event || !event.sessionId) return null;

    var sess = _getSession(event.sessionId);
    var ts = event.timestamp || _now();

    if (event.sourceId && !sess.sourceId) {
      sess.sourceId = event.sourceId;
    }

    var entry = {
      solved: !!event.solved,
      solveTimeMs: _nnOpt(event.solveTimeMs, 0),
      difficulty: event.difficulty != null ? event.difficulty : 0.5,
      timestamp: ts
    };

    sess.events.push(entry);
    sess.lastSeen = ts;
    sess.totalEvents++;

    if (sess.events.length > maxEventsPerSession) {
      sess.events.shift();
    }

    return { sessionId: event.sessionId, eventCount: sess.events.length };
  }

  // ── Engine 1: Uncanny Valley Detector ───────────────────────────

  function _runUncannyValley(events) {
    var solveTimes = [];
    var solves = 0;
    for (var i = 0; i < events.length; i++) {
      solveTimes.push(events[i].solveTimeMs);
      if (events[i].solved) solves++;
    }

    var stMean = _mean(solveTimes);
    var stStddev = _stddev(solveTimes);
    var accuracy = solves / events.length;

    // How close to "ideal human" is each metric?
    var meanDist = Math.abs(stMean - HUMAN_BASELINES.solveTimeMeanMs) / HUMAN_BASELINES.solveTimeMeanMs;
    var stddevDist = stStddev > 0
      ? Math.abs(stStddev - HUMAN_BASELINES.solveTimeStddevMs) / HUMAN_BASELINES.solveTimeStddevMs
      : 1;
    var accDist = Math.abs(accuracy - HUMAN_BASELINES.accuracyRate);

    // Suspiciously close = high uncanny score
    var meanScore = Math.max(0, 1 - meanDist * 3);
    var stddevScore = Math.max(0, 1 - stddevDist * 3);
    var accScore = Math.max(0, 1 - accDist * 5);

    // But also check if stddev is TOO close to expected (real humans vary more between sessions)
    var perfectVarianceBonus = stddevDist < 0.1 ? 0.3 : 0;

    var score = _clamp((meanScore * 0.3 + stddevScore * 0.3 + accScore * 0.2 + perfectVarianceBonus) * 100, 0, 100);

    return {
      score: score,
      solveTimeMean: stMean,
      solveTimeStddev: stStddev,
      accuracy: accuracy,
      meanDeviation: meanDist,
      stddevDeviation: stddevDist,
      accuracyDeviation: accDist
    };
  }

  // ── Engine 2: Consistency Paradox Analyzer ──────────────────────

  function _runConsistencyParadox(events) {
    var solveTimes = [];
    var interArrivals = [];
    for (var i = 0; i < events.length; i++) {
      solveTimes.push(events[i].solveTimeMs);
      if (i > 0) {
        interArrivals.push(events[i].timestamp - events[i - 1].timestamp);
      }
    }

    // Variance of variance (windowed)
    var windowSize = Math.max(3, Math.floor(events.length / 4));
    var vov = _varianceOfWindows(solveTimes, windowSize);

    // Low variance-of-variance is suspicious (randomness is too regular)
    var stMean = _mean(solveTimes);
    var normalizedVov = stMean > 0 ? vov / (stMean * stMean) : 0;
    var vovScore = normalizedVov < 0.01 ? 80 : normalizedVov < 0.05 ? 50 : normalizedVov < 0.1 ? 25 : 5;

    // Autocorrelation at lag 1 — bots often have low autocorrelation (truly independent)
    // Humans show slight positive autocorrelation (momentum, fatigue)
    var ac1 = _autocorrelation(solveTimes, 1);
    var acScore = Math.abs(ac1) < 0.05 ? 60 : Math.abs(ac1) < 0.15 ? 30 : 10;

    // Inter-arrival regularity
    var iaStddev = interArrivals.length > 1 ? _stddev(interArrivals) : 0;
    var iaMean = interArrivals.length > 0 ? _mean(interArrivals) : 0;
    var iaCv = iaMean > 0 ? iaStddev / iaMean : 0;
    var iaScore = iaCv < 0.15 ? 70 : iaCv < 0.3 ? 40 : 10;

    var score = _clamp(vovScore * 0.4 + acScore * 0.3 + iaScore * 0.3, 0, 100);

    return {
      score: score,
      varianceOfVariance: normalizedVov,
      autocorrelationLag1: ac1,
      interArrivalCV: iaCv,
      vovScore: vovScore,
      acScore: acScore,
      iaScore: iaScore
    };
  }

  // ── Engine 3: Fatigue Immunity Detector ─────────────────────────

  function _runFatigueImmunity(events) {
    if (events.length < fatigueWindowEvents) {
      // Use whatever we have
      var times = [];
      for (var j = 0; j < events.length; j++) times.push(events[j].solveTimeMs);
      var reg = _linearRegression(times);
      var flatScore = Math.abs(reg.slope) < 5 ? 50 : 10;
      return { score: flatScore, slope: reg.slope, r2: reg.r2, sampleCount: events.length, hasEnoughData: false };
    }

    var solveTimes = [];
    for (var i = 0; i < events.length; i++) {
      solveTimes.push(events[i].solveTimeMs);
    }

    var regression = _linearRegression(solveTimes);

    // Humans show positive slope (getting slower = fatigue)
    // Flat or negative slope over many events is suspicious
    var slope = regression.slope;
    var fatigueScore;

    if (slope <= 0) {
      // Getting faster or perfectly flat = very suspicious
      fatigueScore = 85;
    } else if (slope < 2) {
      // Barely any slowdown
      fatigueScore = 65;
    } else if (slope < 10) {
      // Mild slowdown — could go either way
      fatigueScore = 35;
    } else {
      // Clear fatigue — likely human
      fatigueScore = 10;
    }

    // Also check accuracy trend
    var accuracyWindows = [];
    var winSize = Math.max(3, Math.floor(events.length / 4));
    for (var w = 0; w <= events.length - winSize; w += winSize) {
      var wins = 0;
      for (var ww = w; ww < w + winSize; ww++) {
        if (events[ww].solved) wins++;
      }
      accuracyWindows.push(wins / winSize);
    }

    var accTrend = accuracyWindows.length >= 2 ? _linearRegression(accuracyWindows) : { slope: 0, r2: 0 };
    // No accuracy drop is slightly suspicious
    if (accTrend.slope >= 0 && events.length > 30) {
      fatigueScore = Math.min(100, fatigueScore + 15);
    }

    return {
      score: _clamp(fatigueScore, 0, 100),
      slope: slope,
      r2: regression.r2,
      accuracyTrend: accTrend.slope,
      sampleCount: events.length,
      hasEnoughData: true
    };
  }

  // ── Engine 4: Behavioral Template Matcher ───────────────────────

  function _extractSessionSignature(events) {
    var solveTimes = [];
    var interArrivals = [];
    for (var i = 0; i < events.length; i++) {
      solveTimes.push(events[i].solveTimeMs);
      if (i > 0) interArrivals.push(events[i].timestamp - events[i - 1].timestamp);
    }

    var solves = 0;
    for (var j = 0; j < events.length; j++) {
      if (events[j].solved) solves++;
    }

    return {
      timingEntropy: _entropy(solveTimes),
      varianceRatio: _mean(solveTimes) > 0 ? _stddev(solveTimes) / _mean(solveTimes) : 0,
      accuracy: solves / events.length,
      interArrivalEntropy: _entropy(interArrivals),
      autocorrelation: _autocorrelation(solveTimes, 1),
      meanSolveTime: _mean(solveTimes),
      stddevSolveTime: _stddev(solveTimes)
    };
  }

  function _matchTemplate(sig, template) {
    if (!template || !template.signature) return 0;
    var tsig = template.signature;
    var matches = 0;
    var checks = 0;

    var fields = ["timingEntropy", "varianceRatio", "accuracy", "interArrivalEntropy",
                  "autocorrelation", "meanSolveTime", "stddevSolveTime"];
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i];
      if (tsig[f]) {
        checks++;
        var range = tsig[f];
        if (Array.isArray(range) && range.length === 2) {
          if (sig[f] >= range[0] && sig[f] <= range[1]) matches++;
        }
      }
    }

    return checks > 0 ? matches / checks : 0;
  }

  function _runTemplateMatch(events) {
    if (_templates.length === 0) {
      return { score: 0, matchedTemplates: [], bestMatch: null };
    }

    var sig = _extractSessionSignature(events);
    var matched = [];
    var bestScore = 0;
    var bestTemplate = null;

    for (var i = 0; i < _templates.length; i++) {
      var tmpl = _templates[i];
      var matchScore = _matchTemplate(sig, tmpl);
      if (matchScore > 0.5) {
        matched.push({ name: tmpl.name, score: matchScore });
      }
      if (matchScore > bestScore) {
        bestScore = matchScore;
        bestTemplate = tmpl.name;
      }
    }

    return {
      score: _clamp(bestScore * 100, 0, 100),
      matchedTemplates: matched,
      bestMatch: bestTemplate,
      bestMatchScore: bestScore
    };
  }

  // ── Engine 5: Micro-Pattern Analyzer ────────────────────────────

  function _runMicroPattern(events) {
    // Analyze sub-second timing digits
    var lastDigits = [];
    var moduloValues = [];
    for (var i = 0; i < events.length; i++) {
      var ms = events[i].solveTimeMs;
      lastDigits.push(ms % 10);
      moduloValues.push(ms % 100);
    }

    // Real humans have non-uniform last-digit distributions
    // Math.random() bots tend to have near-uniform distributions
    var digitEntropy = _entropy(lastDigits);
    var moduloEntropy = _entropy(moduloValues);

    // Maximum entropy for 10 digits = log2(10) ≈ 3.32
    // Too-high entropy (near-uniform) is suspicious for last digits
    var maxDigitEntropy = Math.log(Math.min(10, lastDigits.length)) / Math.LN2;
    var digitUniformity = maxDigitEntropy > 0 ? digitEntropy / maxDigitEntropy : 0;

    // Humans tend to have certain digit biases (round numbers, etc.)
    // Near-perfect uniformity suggests random generation
    var digitScore = digitUniformity > 0.95 ? 70 : digitUniformity > 0.85 ? 45 : digitUniformity > 0.7 ? 25 : 10;

    // Check for suspicious modulo patterns (e.g., all times divisible by 50ms)
    var divisibleBy50 = 0;
    var divisibleBy100 = 0;
    for (var j = 0; j < events.length; j++) {
      if (events[j].solveTimeMs % 50 === 0) divisibleBy50++;
      if (events[j].solveTimeMs % 100 === 0) divisibleBy100++;
    }

    var roundNumberRatio = divisibleBy50 / events.length;
    var roundScore = roundNumberRatio > 0.5 ? 60 : roundNumberRatio > 0.3 ? 35 : 10;

    // Inter-event timing micro-patterns
    var gaps = [];
    for (var k = 1; k < events.length; k++) {
      gaps.push(events[k].timestamp - events[k - 1].timestamp);
    }
    var gapDigits = [];
    for (var g = 0; g < gaps.length; g++) gapDigits.push(gaps[g] % 100);
    var gapEntropy = _entropy(gapDigits);

    var score = _clamp(digitScore * 0.4 + roundScore * 0.3 + (gapEntropy > 0 ? 30 : 15) * 0.3, 0, 100);

    return {
      score: score,
      digitEntropy: digitEntropy,
      moduloEntropy: moduloEntropy,
      digitUniformity: digitUniformity,
      roundNumberRatio: roundNumberRatio,
      gapEntropy: gapEntropy
    };
  }

  // ── Engine 6: Cross-Session Coherence ───────────────────────────

  function _runCrossSession(sessionId) {
    var sess = _sessions[sessionId];
    if (!sess || !sess.sourceId) {
      return { score: 0, relatedSessions: 0, maxSimilarity: 0, sourceId: null };
    }

    var sourceId = sess.sourceId;
    var thisSig = _extractSessionSignature(sess.events);
    var similarities = [];
    var related = 0;

    var keys = Object.keys(_sessions);
    for (var i = 0; i < keys.length; i++) {
      var other = _sessions[keys[i]];
      if (other.id === sessionId) continue;
      if (other.sourceId !== sourceId) continue;
      if (other.events.length < minEventsForAnalysis) continue;

      related++;
      var otherSig = _extractSessionSignature(other.events);

      // Build vectors for cosine similarity
      var vecA = [thisSig.timingEntropy, thisSig.varianceRatio, thisSig.accuracy,
                  thisSig.interArrivalEntropy, thisSig.autocorrelation];
      var vecB = [otherSig.timingEntropy, otherSig.varianceRatio, otherSig.accuracy,
                  otherSig.interArrivalEntropy, otherSig.autocorrelation];

      var sim = _cosineSimilarity(vecA, vecB);
      similarities.push(sim);
    }

    if (similarities.length === 0) {
      return { score: 0, relatedSessions: related, maxSimilarity: 0, sourceId: sourceId };
    }

    var maxSim = 0;
    var avgSim = _mean(similarities);
    for (var j = 0; j < similarities.length; j++) {
      if (similarities[j] > maxSim) maxSim = similarities[j];
    }

    // Very high similarity across sessions from same source = suspicious
    var score = maxSim > 0.98 ? 85 : maxSim > 0.95 ? 65 : maxSim > 0.9 ? 45 : maxSim > 0.8 ? 25 : 10;

    return {
      score: _clamp(score, 0, 100),
      relatedSessions: related,
      maxSimilarity: maxSim,
      averageSimilarity: avgSim,
      sourceId: sourceId
    };
  }

  // ── Composite Analysis ──────────────────────────────────────────

  function analyzeSession(sessionId) {
    var sess = _sessions[sessionId];
    if (!sess) {
      return { sessionId: sessionId, mimicryScore: 0, tier: MIMICRY_TIERS[0], engines: {}, insights: [], error: "Session not found" };
    }

    if (sess.events.length < minEventsForAnalysis) {
      return {
        sessionId: sessionId,
        mimicryScore: 0,
        tier: MIMICRY_TIERS[0],
        engines: {},
        insights: ["Insufficient data: " + sess.events.length + "/" + minEventsForAnalysis + " events"],
        error: "Insufficient data"
      };
    }

    var results = {};
    results.uncannyValley = _runUncannyValley(sess.events);
    results.consistencyParadox = _runConsistencyParadox(sess.events);
    results.fatigueImmunity = _runFatigueImmunity(sess.events);
    results.templateMatch = _runTemplateMatch(sess.events);
    results.microPattern = _runMicroPattern(sess.events);
    results.crossSession = _runCrossSession(sessionId);

    // Weighted composite
    var totalWeight = 0;
    var weightedSum = 0;
    for (var i = 0; i < ENGINE_NAMES.length; i++) {
      var name = ENGINE_NAMES[i];
      var w = weights[name] || 0;
      var s = results[name] ? results[name].score : 0;
      weightedSum += w * s;
      totalWeight += w;
    }

    var mimicryScore = totalWeight > 0 ? _clamp(Math.round(weightedSum / totalWeight), 0, 100) : 0;
    var tier = _tierFromScore(mimicryScore);

    // Generate insights
    var insights = _generateInsights(sessionId, mimicryScore, tier, results);

    return {
      sessionId: sessionId,
      mimicryScore: mimicryScore,
      tier: tier,
      engines: results,
      insights: insights
    };
  }

  // ── Insight Generation ──────────────────────────────────────────

  function _generateInsights(sessionId, score, tier, engines) {
    var out = [];

    if (engines.uncannyValley && engines.uncannyValley.score > 60) {
      out.push("Session " + sessionId + " has suspiciously ideal human metrics (uncanny valley score: " + Math.round(engines.uncannyValley.score) + ")");
    }

    if (engines.consistencyParadox && engines.consistencyParadox.score > 60) {
      out.push("Behavioral variance is too regular — consistency paradox detected (score: " + Math.round(engines.consistencyParadox.score) + ")");
    }

    if (engines.fatigueImmunity && engines.fatigueImmunity.score > 60) {
      out.push("No fatigue degradation detected over " + engines.fatigueImmunity.sampleCount + " events — possible bot endurance");
    }

    if (engines.templateMatch && engines.templateMatch.score > 50) {
      out.push("Behavioral pattern matches known mimicry template: " + (engines.templateMatch.bestMatch || "unknown"));
    }

    if (engines.microPattern && engines.microPattern.score > 50) {
      out.push("Sub-second timing patterns show synthetic characteristics (digit uniformity: " +
        (engines.microPattern.digitUniformity ? engines.microPattern.digitUniformity.toFixed(2) : "N/A") + ")");
    }

    if (engines.crossSession && engines.crossSession.score > 50) {
      out.push("Cross-session profile similarity is suspiciously high (max: " +
        (engines.crossSession.maxSimilarity ? engines.crossSession.maxSimilarity.toFixed(3) : "N/A") + ")");
    }

    if (score > 80) {
      out.push("ALERT: High-confidence mimicry detected — recommend escalation to manual review");
    } else if (score > 60) {
      out.push("WARNING: Likely mimicry — consider increasing challenge difficulty for this session");
    }

    // Store insights
    for (var i = 0; i < out.length; i++) {
      _insights.push({ timestamp: _now(), sessionId: sessionId, message: out[i] });
      if (_insights.length > maxInsights) _insights.shift();
    }

    return out;
  }

  // ── Template Management ─────────────────────────────────────────

  function addTemplate(template) {
    if (!template || !template.name || !template.signature) return false;

    // Check for duplicate
    for (var i = 0; i < _templates.length; i++) {
      if (_templates[i].name === template.name) {
        _templates[i] = { name: template.name, signature: template.signature, addedAt: _now() };
        return true;
      }
    }

    if (_templates.length >= maxTemplates) {
      _templates.shift();
    }

    _templates.push({ name: template.name, signature: template.signature, addedAt: _now() });
    return true;
  }

  function removeTemplate(name) {
    for (var i = 0; i < _templates.length; i++) {
      if (_templates[i].name === name) {
        _templates.splice(i, 1);
        return true;
      }
    }
    return false;
  }

  function getTemplates() {
    var out = [];
    for (var i = 0; i < _templates.length; i++) {
      out.push({ name: _templates[i].name, signature: _templates[i].signature, addedAt: _templates[i].addedAt });
    }
    return out;
  }

  // ── Stats ───────────────────────────────────────────────────────

  function getStats() {
    var sessionIds = Object.keys(_sessions);
    var totalSessions = sessionIds.length;
    var analyzedSessions = 0;
    var tierDist = {};
    for (var t = 0; t < MIMICRY_TIERS.length; t++) tierDist[MIMICRY_TIERS[t]] = 0;

    var scores = [];
    var topMimics = [];

    for (var i = 0; i < sessionIds.length; i++) {
      var sess = _sessions[sessionIds[i]];
      if (sess.events.length < minEventsForAnalysis) continue;

      analyzedSessions++;
      var analysis = analyzeSession(sessionIds[i]);
      scores.push(analysis.mimicryScore);
      tierDist[analysis.tier]++;

      if (analysis.mimicryScore > 50) {
        topMimics.push({ sessionId: sessionIds[i], score: analysis.mimicryScore, tier: analysis.tier });
      }
    }

    // Sort top mimics descending
    topMimics.sort(function (a, b) { return b.score - a.score; });
    if (topMimics.length > 10) topMimics = topMimics.slice(0, 10);

    var statsInsights = [];
    if (analyzedSessions > 0) {
      var avgScore = _mean(scores);
      var suspiciousCount = tierDist.SUSPICIOUS + tierDist.LIKELY_MIMICRY + tierDist.CONFIRMED_MIMICRY;
      var suspiciousRate = suspiciousCount / analyzedSessions;

      if (suspiciousRate > 0.3) {
        statsInsights.push("High mimicry rate: " + Math.round(suspiciousRate * 100) + "% of sessions are suspicious or worse");
      }
      if (avgScore > 50) {
        statsInsights.push("Average mimicry score is elevated (" + Math.round(avgScore) + ") — possible coordinated mimicry campaign");
      }
    }

    return {
      totalSessions: totalSessions,
      analyzedSessions: analyzedSessions,
      tierDistribution: tierDist,
      topMimics: topMimics,
      averageMimicryScore: scores.length > 0 ? Math.round(_mean(scores)) : 0,
      templateCount: _templates.length,
      recentInsights: _insights.slice(-10),
      insights: statsInsights
    };
  }

  // ── Export/Import ───────────────────────────────────────────────

  function exportState() {
    var sessData = {};
    var keys = Object.keys(_sessions);
    for (var i = 0; i < keys.length; i++) {
      var s = _sessions[keys[i]];
      sessData[keys[i]] = {
        id: s.id,
        sourceId: s.sourceId,
        events: s.events.slice(),
        firstSeen: s.firstSeen,
        lastSeen: s.lastSeen,
        totalEvents: s.totalEvents
      };
    }

    return {
      version: 1,
      sessions: sessData,
      sessionOrder: _sessionLru.toArray(),
      templates: _templates.slice(),
      insights: _insights.slice()
    };
  }

  function importState(state) {
    if (!state || state.version !== 1) return false;

    _sessions = Object.create(null);
    _sessionLru = new LruTracker();
    _templates = [];
    _insights = [];

    if (state.sessions) {
      var keys = Object.keys(state.sessions);
      for (var i = 0; i < keys.length; i++) {
        var sd = state.sessions[keys[i]];
        _sessions[keys[i]] = {
          id: sd.id,
          sourceId: sd.sourceId || null,
          events: sd.events || [],
          firstSeen: sd.firstSeen || 0,
          lastSeen: sd.lastSeen || 0,
          totalEvents: sd.totalEvents || 0
        };
      }
    }

    if (state.sessionOrder) {
      _sessionLru.fromArray(state.sessionOrder);
    }

    if (state.templates) {
      _templates = state.templates.slice();
    }

    if (state.insights) {
      _insights = state.insights.slice();
    }

    return true;
  }

  // ── Reset ───────────────────────────────────────────────────────

  function reset() {
    _sessions = Object.create(null);
    _sessionLru = new LruTracker();
    _templates = [];
    _insights = [];
  }

  // ── Public API ──────────────────────────────────────────────────

  return {
    recordEvent: recordEvent,
    analyzeSession: analyzeSession,
    addTemplate: addTemplate,
    removeTemplate: removeTemplate,
    getTemplates: getTemplates,
    getStats: getStats,
    exportState: exportState,
    importState: importState,
    reset: reset,
    MIMICRY_TIERS: MIMICRY_TIERS,
    ENGINE_NAMES: ENGINE_NAMES
  };
}

// ── Exports ─────────────────────────────────────────────────────────

module.exports = {
  createBotMimicryDetector: createBotMimicryDetector,
  MIMICRY_TIERS: MIMICRY_TIERS,
  ENGINE_NAMES: ENGINE_NAMES
};
