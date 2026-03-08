'use strict';

/**
 * createSolvePatternFingerprinter — builds behavioral fingerprints from CAPTCHA
 * solve patterns to identify solver profiles across sessions.
 *
 * Unlike client fingerprinting (browser/device) or biometrics (mouse/keyboard),
 * this fingerprints the *pattern* of how CAPTCHAs are solved: timing distribution,
 * success streaks, retry cadence, time-of-day skew, hesitation signatures.
 *
 * Use case: detect CAPTCHA-solving services that reuse the same human solvers
 * across different IPs/sessions. Also useful for distinguishing genuine variance
 * in human solving vs. mechanical consistency of bots.
 *
 * @param {object} [options]
 * @param {number} [options.minSamples=5]        Minimum solves before generating fingerprint
 * @param {number} [options.maxSamples=200]       Max solves to retain per session
 * @param {number} [options.similarityThreshold=0.75] Match threshold (0–1)
 * @param {number} [options.timeBuckets=24]       Hour buckets for time-of-day distribution
 * @param {number} [options.maxProfiles=500]      Maximum stored profiles
 * @returns {object}
 */
function createSolvePatternFingerprinter(options) {
  options = options || {};

  var minSamples = options.minSamples != null && options.minSamples > 0 ? options.minSamples : 5;
  var maxSamples = options.maxSamples != null && options.maxSamples > 0 ? options.maxSamples : 200;
  var similarityThreshold = options.similarityThreshold != null && options.similarityThreshold >= 0
    ? options.similarityThreshold : 0.75;
  var timeBuckets = options.timeBuckets != null && options.timeBuckets > 0 ? options.timeBuckets : 24;
  var maxProfiles = options.maxProfiles != null && options.maxProfiles > 0 ? options.maxProfiles : 500;

  // sessionId -> { solves: [...], fingerprint: null }
  var sessions = Object.create(null);
  // profileId -> { fingerprint, sessionIds, createdAt, lastSeen }
  var profiles = Object.create(null);
  var profileCount = 0;

  // ── Helpers ──────────────────────────────────────────────────────

  function _mean(arr) {
    if (arr.length === 0) return 0;
    var s = 0;
    for (var i = 0; i < arr.length; i++) s += arr[i];
    return s / arr.length;
  }

  function _stddev(arr, avg) {
    if (arr.length < 2) return 0;
    var s = 0;
    for (var i = 0; i < arr.length; i++) {
      var d = arr[i] - avg;
      s += d * d;
    }
    return Math.sqrt(s / (arr.length - 1));
  }

  function _median(arr) {
    if (arr.length === 0) return 0;
    var sorted = arr.slice().sort(function(a, b) { return a - b; });
    var mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  }

  function _percentile(arr, p) {
    if (arr.length === 0) return 0;
    var sorted = arr.slice().sort(function(a, b) { return a - b; });
    var idx = (p / 100) * (sorted.length - 1);
    var lo = Math.floor(idx);
    var hi = Math.ceil(idx);
    if (lo === hi) return sorted[lo];
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
  }

  /**
   * Cosine similarity between two equal-length arrays.
   */
  function _cosineSimilarity(a, b) {
    if (a.length !== b.length || a.length === 0) return 0;
    var dot = 0, magA = 0, magB = 0;
    for (var i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      magA += a[i] * a[i];
      magB += b[i] * b[i];
    }
    var denom = Math.sqrt(magA) * Math.sqrt(magB);
    return denom > 0 ? dot / denom : 0;
  }

  /**
   * Normalized difference: 1 - |a-b| / max(|a|,|b|,1)
   */
  function _valueSimilarity(a, b) {
    var maxAbs = Math.max(Math.abs(a), Math.abs(b), 1);
    return 1 - Math.abs(a - b) / maxAbs;
  }

  // ── Fingerprint Generation ──────────────────────────────────────

  /**
   * Build a fingerprint from an array of solve records.
   * @param {{ timeMs: number, correct: boolean, timestamp?: number }[]} solves
   * @returns {object|null} Fingerprint object or null if insufficient data.
   */
  function _buildFingerprint(solves) {
    if (solves.length < minSamples) return null;

    var times = [];
    var correctTimes = [];
    var incorrectTimes = [];
    var successes = 0;
    var streaks = [];
    var currentStreak = 0;
    var hourDist = [];
    var gaps = [];
    var i;

    for (i = 0; i < timeBuckets; i++) hourDist.push(0);

    for (i = 0; i < solves.length; i++) {
      var s = solves[i];
      times.push(s.timeMs);

      if (s.correct) {
        correctTimes.push(s.timeMs);
        successes++;
        currentStreak++;
      } else {
        incorrectTimes.push(s.timeMs);
        if (currentStreak > 0) {
          streaks.push(currentStreak);
          currentStreak = 0;
        }
      }

      if (s.timestamp != null) {
        var hour = new Date(s.timestamp).getUTCHours();
        var bucket = Math.floor(hour / (24 / timeBuckets));
        if (bucket >= 0 && bucket < timeBuckets) hourDist[bucket]++;
      }

      if (i > 0 && solves[i].timestamp != null && solves[i - 1].timestamp != null) {
        gaps.push(solves[i].timestamp - solves[i - 1].timestamp);
      }
    }
    if (currentStreak > 0) streaks.push(currentStreak);

    var avgTime = _mean(times);
    var stdTime = _stddev(times, avgTime);

    // Normalize hour distribution to proportions
    var total = solves.length;
    var hourProp = [];
    for (i = 0; i < hourDist.length; i++) {
      hourProp.push(total > 0 ? hourDist[i] / total : 0);
    }

    return {
      sampleCount: solves.length,
      successRate: total > 0 ? successes / total : 0,
      avgSolveTimeMs: Math.round(avgTime * 100) / 100,
      medianSolveTimeMs: _median(times),
      stdSolveTimeMs: Math.round(stdTime * 100) / 100,
      p10SolveTimeMs: _percentile(times, 10),
      p90SolveTimeMs: _percentile(times, 90),
      avgCorrectTimeMs: correctTimes.length > 0 ? Math.round(_mean(correctTimes) * 100) / 100 : null,
      avgIncorrectTimeMs: incorrectTimes.length > 0 ? Math.round(_mean(incorrectTimes) * 100) / 100 : null,
      avgStreakLength: streaks.length > 0 ? Math.round(_mean(streaks) * 100) / 100 : 0,
      maxStreakLength: streaks.length > 0 ? Math.max.apply(null, streaks) : 0,
      avgGapMs: gaps.length > 0 ? Math.round(_mean(gaps)) : null,
      stdGapMs: gaps.length > 0 ? Math.round(_stddev(gaps, _mean(gaps))) : null,
      timeOfDayDistribution: hourProp,
      coefficientOfVariation: avgTime > 0 ? Math.round((stdTime / avgTime) * 10000) / 10000 : 0
    };
  }

  // ── Fingerprint Comparison ──────────────────────────────────────

  /**
   * Compare two fingerprints, returning a similarity score 0–1 and
   * per-dimension breakdown.
   */
  function compareFingerprints(fpA, fpB) {
    if (!fpA || !fpB) return { similarity: 0, dimensions: {}, match: false };

    var dims = {};

    // Timing profile (40% weight)
    dims.avgTime = _valueSimilarity(fpA.avgSolveTimeMs, fpB.avgSolveTimeMs);
    dims.medianTime = _valueSimilarity(fpA.medianSolveTimeMs, fpB.medianSolveTimeMs);
    dims.stdTime = _valueSimilarity(fpA.stdSolveTimeMs, fpB.stdSolveTimeMs);
    dims.p10Time = _valueSimilarity(fpA.p10SolveTimeMs, fpB.p10SolveTimeMs);
    dims.p90Time = _valueSimilarity(fpA.p90SolveTimeMs, fpB.p90SolveTimeMs);
    var timingScore = (dims.avgTime + dims.medianTime + dims.stdTime + dims.p10Time + dims.p90Time) / 5;

    // Success behavior (20% weight)
    dims.successRate = _valueSimilarity(fpA.successRate, fpB.successRate);
    dims.avgStreak = _valueSimilarity(fpA.avgStreakLength, fpB.avgStreakLength);
    dims.cv = _valueSimilarity(fpA.coefficientOfVariation, fpB.coefficientOfVariation);
    var behaviorScore = (dims.successRate + dims.avgStreak + dims.cv) / 3;

    // Time-of-day distribution (25% weight)
    dims.timeOfDay = _cosineSimilarity(fpA.timeOfDayDistribution, fpB.timeOfDayDistribution);
    var todScore = dims.timeOfDay;

    // Correct vs incorrect timing split (15% weight)
    var splitScore = 1;
    if (fpA.avgCorrectTimeMs != null && fpB.avgCorrectTimeMs != null) {
      dims.correctTime = _valueSimilarity(fpA.avgCorrectTimeMs, fpB.avgCorrectTimeMs);
      splitScore = dims.correctTime;
    }
    if (fpA.avgIncorrectTimeMs != null && fpB.avgIncorrectTimeMs != null) {
      dims.incorrectTime = _valueSimilarity(fpA.avgIncorrectTimeMs, fpB.avgIncorrectTimeMs);
      splitScore = (splitScore + dims.incorrectTime) / 2;
    }

    var similarity = timingScore * 0.40 + behaviorScore * 0.20 + todScore * 0.25 + splitScore * 0.15;
    similarity = Math.round(similarity * 10000) / 10000;

    return {
      similarity: similarity,
      dimensions: dims,
      match: similarity >= similarityThreshold
    };
  }

  // ── Session Management ──────────────────────────────────────────

  /**
   * Record a solve event for a session.
   * @param {string} sessionId
   * @param {{ timeMs: number, correct: boolean, timestamp?: number }} solve
   */
  function recordSolve(sessionId, solve) {
    if (!sessionId || typeof sessionId !== "string") {
      throw new Error("sessionId must be a non-empty string");
    }
    if (!solve || typeof solve.timeMs !== "number" || typeof solve.correct !== "boolean") {
      throw new Error("solve must have numeric timeMs and boolean correct");
    }

    if (!sessions[sessionId]) {
      sessions[sessionId] = { solves: [], fingerprint: null };
    }

    var sess = sessions[sessionId];
    var record = {
      timeMs: solve.timeMs,
      correct: solve.correct,
      timestamp: solve.timestamp != null ? solve.timestamp : Date.now()
    };

    sess.solves.push(record);
    if (sess.solves.length > maxSamples) {
      sess.solves.shift();
    }

    // Regenerate fingerprint if we have enough samples
    sess.fingerprint = _buildFingerprint(sess.solves);

    return {
      sessionId: sessionId,
      solveCount: sess.solves.length,
      hasFingerprint: sess.fingerprint !== null
    };
  }

  /**
   * Get the current fingerprint for a session.
   */
  function getFingerprint(sessionId) {
    var sess = sessions[sessionId];
    return sess ? sess.fingerprint : null;
  }

  /**
   * Store a session's fingerprint as a named profile for future matching.
   * @param {string} profileId
   * @param {string} sessionId
   */
  function saveProfile(profileId, sessionId) {
    if (!profileId || typeof profileId !== "string") {
      throw new Error("profileId must be a non-empty string");
    }
    var sess = sessions[sessionId];
    if (!sess || !sess.fingerprint) {
      throw new Error("Session has no fingerprint (need at least " + minSamples + " solves)");
    }

    if (!profiles[profileId]) {
      if (profileCount >= maxProfiles) {
        throw new Error("Maximum profiles (" + maxProfiles + ") reached");
      }
      profileCount++;
    }

    profiles[profileId] = {
      fingerprint: JSON.parse(JSON.stringify(sess.fingerprint)),
      sessionIds: [sessionId],
      createdAt: Date.now(),
      lastSeen: Date.now()
    };

    return { profileId: profileId, fingerprint: profiles[profileId].fingerprint };
  }

  /**
   * Match a session's fingerprint against all stored profiles.
   * Returns sorted matches above the similarity threshold.
   * @param {string} sessionId
   * @returns {{ matches: Array, totalProfiles: number, checked: number }}
   */
  function matchAgainstProfiles(sessionId) {
    var sess = sessions[sessionId];
    if (!sess || !sess.fingerprint) {
      return { matches: [], totalProfiles: profileCount, checked: 0 };
    }

    var fp = sess.fingerprint;
    var matches = [];
    var checked = 0;

    var keys = Object.keys(profiles);
    for (var i = 0; i < keys.length; i++) {
      var pid = keys[i];
      checked++;
      var comparison = compareFingerprints(fp, profiles[pid].fingerprint);
      if (comparison.match) {
        matches.push({
          profileId: pid,
          similarity: comparison.similarity,
          dimensions: comparison.dimensions,
          lastSeen: profiles[pid].lastSeen
        });
      }
    }

    matches.sort(function(a, b) { return b.similarity - a.similarity; });

    return { matches: matches, totalProfiles: profileCount, checked: checked };
  }

  /**
   * Find sessions with similar solve patterns (pairwise comparison).
   * @returns {{ pairs: Array }}
   */
  function findSimilarSessions() {
    var sessionIds = Object.keys(sessions);
    var pairs = [];

    for (var i = 0; i < sessionIds.length; i++) {
      var fpA = sessions[sessionIds[i]].fingerprint;
      if (!fpA) continue;
      for (var j = i + 1; j < sessionIds.length; j++) {
        var fpB = sessions[sessionIds[j]].fingerprint;
        if (!fpB) continue;
        var result = compareFingerprints(fpA, fpB);
        if (result.match) {
          pairs.push({
            sessionA: sessionIds[i],
            sessionB: sessionIds[j],
            similarity: result.similarity,
            dimensions: result.dimensions
          });
        }
      }
    }

    pairs.sort(function(a, b) { return b.similarity - a.similarity; });
    return { pairs: pairs };
  }

  /**
   * Remove a session and its data.
   */
  function removeSession(sessionId) {
    if (sessions[sessionId]) {
      delete sessions[sessionId];
      return true;
    }
    return false;
  }

  /**
   * Remove a profile.
   */
  function removeProfile(profileId) {
    if (profiles[profileId]) {
      delete profiles[profileId];
      profileCount--;
      return true;
    }
    return false;
  }

  /**
   * Get summary statistics.
   */
  function getStats() {
    var sessionIds = Object.keys(sessions);
    var withFingerprint = 0;
    var totalSolves = 0;
    for (var i = 0; i < sessionIds.length; i++) {
      var sess = sessions[sessionIds[i]];
      totalSolves += sess.solves.length;
      if (sess.fingerprint) withFingerprint++;
    }
    return {
      totalSessions: sessionIds.length,
      sessionsWithFingerprint: withFingerprint,
      totalSolves: totalSolves,
      totalProfiles: profileCount,
      config: {
        minSamples: minSamples,
        maxSamples: maxSamples,
        similarityThreshold: similarityThreshold,
        timeBuckets: timeBuckets,
        maxProfiles: maxProfiles
      }
    };
  }

  /**
   * Reset all data.
   */
  function reset() {
    sessions = Object.create(null);
    profiles = Object.create(null);
    profileCount = 0;
  }

  return {
    recordSolve: recordSolve,
    getFingerprint: getFingerprint,
    compareFingerprints: compareFingerprints,
    saveProfile: saveProfile,
    matchAgainstProfiles: matchAgainstProfiles,
    findSimilarSessions: findSimilarSessions,
    removeSession: removeSession,
    removeProfile: removeProfile,
    getStats: getStats,
    reset: reset
  };
}

module.exports = { createSolvePatternFingerprinter: createSolvePatternFingerprinter };
