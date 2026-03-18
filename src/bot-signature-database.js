'use strict';

// -- Cryptographic randomness (CWE-330) --
var _secureRandomHex = require("./crypto-utils").secureRandomHex;

/**
 * createBotSignatureDatabase — manages a database of known bot behavioral
 * signatures and matches incoming CAPTCHA solve sessions against them.
 *
 * Complements the solve-pattern-fingerprinter by providing a curated library
 * of known bot signatures (CAPTCHA farms, automated solvers, replay bots)
 * that can be matched against live sessions for quick classification.
 *
 * Features:
 * - Add/remove/update bot signatures with behavioral profiles
 * - Match sessions against the database with configurable threshold
 * - Categorize bots by type (farm, automated, replay, hybrid)
 * - Track match history and detection rates
 * - Import/export signature database as JSON
 * - Built-in starter signatures for common bot patterns
 *
 * @param {object} [options]
 * @param {number} [options.matchThreshold=0.70]  Minimum similarity to flag as match (0–1)
 * @param {number} [options.maxSignatures=500]     Maximum stored signatures
 * @param {number} [options.maxHistory=1000]       Maximum match history entries
 * @param {boolean} [options.loadDefaults=true]    Pre-load common bot signatures
 * @returns {object}
 */
function createBotSignatureDatabase(options) {
  options = options || {};

  var matchThreshold = options.matchThreshold != null && options.matchThreshold >= 0
    ? options.matchThreshold : 0.70;
  var maxSignatures = options.maxSignatures != null && options.maxSignatures > 0
    ? options.maxSignatures : 500;
  var maxHistory = options.maxHistory != null && options.maxHistory > 0
    ? options.maxHistory : 1000;
  var loadDefaults = options.loadDefaults !== false;

  // ── Storage ─────────────────────────────────────────────────────
  var signatures = Object.create(null);   // id → signature
  var signatureCount = 0;
  var history = [];                        // match results
  var stats = { totalMatches: 0, totalChecks: 0, byCategory: Object.create(null) };

  // ── Bot Categories ──────────────────────────────────────────────
  var CATEGORIES = ['farm', 'automated', 'replay', 'hybrid', 'unknown'];

  // ── Signature Structure ─────────────────────────────────────────
  // {
  //   id: string,
  //   name: string,
  //   category: string,
  //   description: string,
  //   profile: {
  //     avgSolveTimeMs: number,          // typical solve time
  //     solveTimeStdDev: number,         // variance in solve time
  //     successRate: number,             // 0–1
  //     burstRate: number,               // solves per minute when active
  //     retryPattern: string,            // 'none'|'immediate'|'delayed'|'exponential'
  //     timeOfDaySkew: number[],         // 24-bucket distribution (normalized)
  //     consistencyScore: number,        // 0–1 how consistent timing is
  //     hesitationRatio: number,         // ratio of solves with long initial delay
  //   },
  //   severity: string,                  // 'low'|'medium'|'high'|'critical'
  //   tags: string[],
  //   addedAt: number,
  //   matchCount: number,
  //   lastMatchedAt: number|null
  // }

  // ── Default Signatures ──────────────────────────────────────────
  var defaults = [
    {
      id: 'captcha-farm-basic',
      name: 'Basic CAPTCHA Farm',
      category: 'farm',
      description: 'Human solvers in a CAPTCHA farm with moderate speed and high success rate',
      profile: {
        avgSolveTimeMs: 8000,
        solveTimeStdDev: 2000,
        successRate: 0.92,
        burstRate: 6,
        retryPattern: 'immediate',
        timeOfDaySkew: normalizedFlat(24),
        consistencyScore: 0.65,
        hesitationRatio: 0.1
      },
      severity: 'high',
      tags: ['human-solver', 'commercial']
    },
    {
      id: 'captcha-farm-fast',
      name: 'Fast CAPTCHA Farm',
      category: 'farm',
      description: 'Experienced CAPTCHA farm workers with very fast solve times',
      profile: {
        avgSolveTimeMs: 3500,
        solveTimeStdDev: 800,
        successRate: 0.95,
        burstRate: 12,
        retryPattern: 'immediate',
        timeOfDaySkew: normalizedFlat(24),
        consistencyScore: 0.80,
        hesitationRatio: 0.05
      },
      severity: 'critical',
      tags: ['human-solver', 'commercial', 'high-volume']
    },
    {
      id: 'ocr-bot-basic',
      name: 'Basic OCR Bot',
      category: 'automated',
      description: 'Simple OCR-based automated solver with low success on GIF CAPTCHAs',
      profile: {
        avgSolveTimeMs: 1200,
        solveTimeStdDev: 300,
        successRate: 0.35,
        burstRate: 30,
        retryPattern: 'immediate',
        timeOfDaySkew: normalizedFlat(24),
        consistencyScore: 0.95,
        hesitationRatio: 0.0
      },
      severity: 'medium',
      tags: ['ocr', 'low-accuracy']
    },
    {
      id: 'ml-solver',
      name: 'ML-Based Solver',
      category: 'automated',
      description: 'Machine learning model trained on CAPTCHA images',
      profile: {
        avgSolveTimeMs: 800,
        solveTimeStdDev: 200,
        successRate: 0.60,
        burstRate: 45,
        retryPattern: 'immediate',
        timeOfDaySkew: normalizedFlat(24),
        consistencyScore: 0.92,
        hesitationRatio: 0.0
      },
      severity: 'high',
      tags: ['ml', 'neural-net']
    },
    {
      id: 'replay-bot',
      name: 'Replay Attack Bot',
      category: 'replay',
      description: 'Replays previously solved challenges using cached answers',
      profile: {
        avgSolveTimeMs: 200,
        solveTimeStdDev: 50,
        successRate: 0.40,
        burstRate: 60,
        retryPattern: 'none',
        timeOfDaySkew: normalizedFlat(24),
        consistencyScore: 0.98,
        hesitationRatio: 0.0
      },
      severity: 'high',
      tags: ['replay', 'cache-based']
    },
    {
      id: 'hybrid-solver',
      name: 'Hybrid Solver',
      category: 'hybrid',
      description: 'Combines automated pre-screening with human fallback',
      profile: {
        avgSolveTimeMs: 4000,
        solveTimeStdDev: 3000,
        successRate: 0.85,
        burstRate: 15,
        retryPattern: 'delayed',
        timeOfDaySkew: normalizedFlat(24),
        consistencyScore: 0.45,
        hesitationRatio: 0.25
      },
      severity: 'critical',
      tags: ['hybrid', 'adaptive']
    }
  ];

  // ── Helpers ─────────────────────────────────────────────────────

  function normalizedFlat(n) {
    var arr = [];
    var v = 1 / n;
    for (var i = 0; i < n; i++) arr.push(v);
    return arr;
  }

  function generateId() {
    return 'sig-' + Date.now().toString(36) + '-' + _secureRandomHex(8);
  }

  function clamp01(v) { return v < 0 ? 0 : v > 1 ? 1 : v; }

  function cosineSimilarity(a, b) {
    if (!a || !b || a.length !== b.length || a.length === 0) return 0;
    var dot = 0, magA = 0, magB = 0;
    for (var i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      magA += a[i] * a[i];
      magB += b[i] * b[i];
    }
    magA = Math.sqrt(magA);
    magB = Math.sqrt(magB);
    if (magA === 0 || magB === 0) return 0;
    return dot / (magA * magB);
  }

  function gaussianSimilarity(a, b, sigma) {
    var diff = a - b;
    return Math.exp(-(diff * diff) / (2 * sigma * sigma));
  }

  // Compare a session profile against a signature profile
  function profileSimilarity(session, sig) {
    var weights = {
      avgSolveTimeMs: 0.20,
      solveTimeStdDev: 0.10,
      successRate: 0.20,
      burstRate: 0.10,
      retryPattern: 0.10,
      timeOfDaySkew: 0.10,
      consistencyScore: 0.10,
      hesitationRatio: 0.10
    };

    var score = 0;

    // Timing similarity (gaussian, sigma relative to expected)
    if (sig.avgSolveTimeMs != null && session.avgSolveTimeMs != null) {
      score += weights.avgSolveTimeMs * gaussianSimilarity(
        session.avgSolveTimeMs, sig.avgSolveTimeMs, sig.avgSolveTimeMs * 0.5
      );
    }

    if (sig.solveTimeStdDev != null && session.solveTimeStdDev != null) {
      score += weights.solveTimeStdDev * gaussianSimilarity(
        session.solveTimeStdDev, sig.solveTimeStdDev, sig.solveTimeStdDev * 0.5
      );
    }

    // Success rate (direct distance)
    if (sig.successRate != null && session.successRate != null) {
      score += weights.successRate * (1 - Math.abs(session.successRate - sig.successRate));
    }

    // Burst rate
    if (sig.burstRate != null && session.burstRate != null) {
      score += weights.burstRate * gaussianSimilarity(
        session.burstRate, sig.burstRate, sig.burstRate * 0.5
      );
    }

    // Retry pattern (exact match or partial)
    if (sig.retryPattern != null && session.retryPattern != null) {
      score += weights.retryPattern * (session.retryPattern === sig.retryPattern ? 1 : 0.2);
    }

    // Time-of-day distribution (cosine similarity)
    if (sig.timeOfDaySkew && session.timeOfDaySkew) {
      score += weights.timeOfDaySkew * clamp01(cosineSimilarity(
        session.timeOfDaySkew, sig.timeOfDaySkew
      ));
    }

    // Consistency score
    if (sig.consistencyScore != null && session.consistencyScore != null) {
      score += weights.consistencyScore * (1 - Math.abs(session.consistencyScore - sig.consistencyScore));
    }

    // Hesitation ratio
    if (sig.hesitationRatio != null && session.hesitationRatio != null) {
      score += weights.hesitationRatio * (1 - Math.abs(session.hesitationRatio - sig.hesitationRatio));
    }

    return clamp01(score);
  }

  // ── Init ────────────────────────────────────────────────────────

  function addSignature(sig) {
    if (!sig || typeof sig !== 'object') throw new Error('Signature must be an object');
    if (!sig.profile || typeof sig.profile !== 'object') throw new Error('Signature must have a profile');

    var id = sig.id || generateId();
    if (signatures[id] && signatureCount >= maxSignatures) {
      // updating existing is fine
    } else if (signatureCount >= maxSignatures && !signatures[id]) {
      throw new Error('Maximum signatures reached (' + maxSignatures + ')');
    }

    var category = sig.category || 'unknown';
    if (CATEGORIES.indexOf(category) === -1) category = 'unknown';

    var entry = {
      id: id,
      name: sig.name || id,
      category: category,
      description: sig.description || '',
      profile: Object.assign({}, sig.profile),
      severity: sig.severity || 'medium',
      tags: Array.isArray(sig.tags) ? sig.tags.slice() : [],
      addedAt: sig.addedAt || Date.now(),
      matchCount: 0,
      lastMatchedAt: null
    };

    if (!signatures[id]) signatureCount++;
    signatures[id] = entry;
    return entry;
  }

  if (loadDefaults) {
    for (var i = 0; i < defaults.length; i++) {
      addSignature(defaults[i]);
    }
  }

  // ── Core API ────────────────────────────────────────────────────

  function removeSignature(id) {
    if (!signatures[id]) return false;
    delete signatures[id];
    signatureCount--;
    return true;
  }

  function getSignature(id) {
    return signatures[id] || null;
  }

  function listSignatures(filter) {
    var result = [];
    var ids = Object.keys(signatures);
    for (var i = 0; i < ids.length; i++) {
      var sig = signatures[ids[i]];
      if (filter) {
        if (filter.category && sig.category !== filter.category) continue;
        if (filter.severity && sig.severity !== filter.severity) continue;
        if (filter.tag && sig.tags.indexOf(filter.tag) === -1) continue;
      }
      result.push(sig);
    }
    return result;
  }

  function matchSession(sessionProfile, opts) {
    opts = opts || {};
    var threshold = opts.threshold != null ? opts.threshold : matchThreshold;
    var topN = opts.topN != null && opts.topN > 0 ? opts.topN : 5;
    var categoryFilter = opts.category || null;

    var matches = [];
    var ids = Object.keys(signatures);

    for (var i = 0; i < ids.length; i++) {
      var sig = signatures[ids[i]];
      if (categoryFilter && sig.category !== categoryFilter) continue;

      var similarity = profileSimilarity(sessionProfile, sig.profile);
      if (similarity >= threshold) {
        matches.push({
          signatureId: sig.id,
          signatureName: sig.name,
          category: sig.category,
          severity: sig.severity,
          similarity: Math.round(similarity * 1000) / 1000,
          description: sig.description
        });
        sig.matchCount++;
        sig.lastMatchedAt = Date.now();
        stats.totalMatches++;
        stats.byCategory[sig.category] = (stats.byCategory[sig.category] || 0) + 1;
      }
    }

    stats.totalChecks++;

    // Sort by similarity descending
    matches.sort(function (a, b) { return b.similarity - a.similarity; });
    if (matches.length > topN) matches = matches.slice(0, topN);

    var result = {
      matched: matches.length > 0,
      matchCount: matches.length,
      topMatch: matches.length > 0 ? matches[0] : null,
      matches: matches,
      checkedAt: Date.now()
    };

    // Record history
    history.push({
      sessionProfile: Object.assign({}, sessionProfile),
      result: result,
      timestamp: Date.now()
    });
    if (history.length > maxHistory) history.shift();

    return result;
  }

  function batchMatch(sessionProfiles, opts) {
    if (!Array.isArray(sessionProfiles)) throw new Error('Expected array of session profiles');
    var results = [];
    for (var i = 0; i < sessionProfiles.length; i++) {
      results.push({
        index: i,
        result: matchSession(sessionProfiles[i], opts)
      });
    }
    var matched = results.filter(function (r) { return r.result.matched; });
    return {
      total: results.length,
      matchedCount: matched.length,
      matchRate: results.length > 0 ? Math.round((matched.length / results.length) * 1000) / 1000 : 0,
      results: results
    };
  }

  function getStats() {
    var categoryCounts = Object.create(null);
    var severityCounts = Object.create(null);
    var ids = Object.keys(signatures);
    for (var i = 0; i < ids.length; i++) {
      var sig = signatures[ids[i]];
      categoryCounts[sig.category] = (categoryCounts[sig.category] || 0) + 1;
      severityCounts[sig.severity] = (severityCounts[sig.severity] || 0) + 1;
    }
    return {
      signatureCount: signatureCount,
      totalChecks: stats.totalChecks,
      totalMatches: stats.totalMatches,
      detectionRate: stats.totalChecks > 0
        ? Math.round((stats.totalMatches / stats.totalChecks) * 1000) / 1000 : 0,
      matchesByCategory: Object.assign({}, stats.byCategory),
      signaturesByCategory: categoryCounts,
      signaturesBySeverity: severityCounts,
      historySize: history.length
    };
  }

  function getHistory(opts) {
    opts = opts || {};
    var limit = opts.limit != null && opts.limit > 0 ? opts.limit : history.length;
    var onlyMatched = opts.onlyMatched === true;
    var result = history;
    if (onlyMatched) {
      result = result.filter(function (h) { return h.result.matched; });
    }
    if (limit < result.length) {
      result = result.slice(result.length - limit);
    }
    return result;
  }

  function exportDatabase() {
    var sigs = [];
    var ids = Object.keys(signatures);
    for (var i = 0; i < ids.length; i++) {
      sigs.push(Object.assign({}, signatures[ids[i]]));
    }
    return {
      version: 1,
      exportedAt: Date.now(),
      signatures: sigs,
      stats: getStats()
    };
  }

  function importDatabase(data, opts) {
    if (!data || !Array.isArray(data.signatures)) {
      throw new Error('Invalid database format: expected { signatures: [...] }');
    }
    opts = opts || {};
    var merge = opts.merge !== false; // default merge
    var imported = 0;
    var skipped = 0;

    if (!merge) {
      // Clear existing
      signatures = Object.create(null);
      signatureCount = 0;
    }

    for (var i = 0; i < data.signatures.length; i++) {
      var sig = data.signatures[i];
      if (merge && signatures[sig.id]) {
        skipped++;
        continue;
      }
      try {
        addSignature(sig);
        imported++;
      } catch (e) {
        skipped++;
      }
    }

    return { imported: imported, skipped: skipped, total: signatureCount };
  }

  function reset() {
    signatures = Object.create(null);
    signatureCount = 0;
    history = [];
    stats = { totalMatches: 0, totalChecks: 0, byCategory: Object.create(null) };
    if (loadDefaults) {
      for (var i = 0; i < defaults.length; i++) {
        addSignature(defaults[i]);
      }
    }
  }

  function textReport() {
    var s = getStats();
    var lines = [];
    lines.push('=== Bot Signature Database Report ===');
    lines.push('Signatures: ' + s.signatureCount);
    lines.push('Total Checks: ' + s.totalChecks);
    lines.push('Total Matches: ' + s.totalMatches);
    lines.push('Detection Rate: ' + (s.detectionRate * 100).toFixed(1) + '%');
    lines.push('');
    lines.push('--- By Category ---');
    var cats = Object.keys(s.signaturesByCategory);
    for (var i = 0; i < cats.length; i++) {
      lines.push('  ' + cats[i] + ': ' + s.signaturesByCategory[cats[i]] + ' signatures, ' +
        (s.matchesByCategory[cats[i]] || 0) + ' matches');
    }
    lines.push('');
    lines.push('--- By Severity ---');
    var sevs = Object.keys(s.signaturesBySeverity);
    for (var j = 0; j < sevs.length; j++) {
      lines.push('  ' + sevs[j] + ': ' + s.signaturesBySeverity[sevs[j]]);
    }
    lines.push('');
    lines.push('--- Top Matched Signatures ---');
    var all = listSignatures();
    all.sort(function (a, b) { return b.matchCount - a.matchCount; });
    var top = all.slice(0, 10);
    for (var k = 0; k < top.length; k++) {
      lines.push('  ' + top[k].name + ' [' + top[k].category + ']: ' +
        top[k].matchCount + ' matches');
    }
    return lines.join('\n');
  }

  return {
    addSignature: addSignature,
    removeSignature: removeSignature,
    getSignature: getSignature,
    listSignatures: listSignatures,
    matchSession: matchSession,
    batchMatch: batchMatch,
    getStats: getStats,
    getHistory: getHistory,
    exportDatabase: exportDatabase,
    importDatabase: importDatabase,
    reset: reset,
    textReport: textReport,
    CATEGORIES: CATEGORIES.slice()
  };
}

module.exports = { createBotSignatureDatabase: createBotSignatureDatabase };
