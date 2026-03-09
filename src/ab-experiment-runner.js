"use strict";

// Shared helpers (inlined from index.js for module independence)
function LruTracker() {
  this._map = Object.create(null); // key → {key, prev, next}
  this._head = null; // oldest
  this._tail = null; // newest
  this.length = 0;
}

LruTracker.prototype.push = function (key) {
  if (this._map[key]) {
    this.touch(key);
    return;
  }
  var node = { key: key, prev: this._tail, next: null };
  if (this._tail) {
    this._tail.next = node;
  } else {
    this._head = node;
  }
  this._tail = node;
  this._map[key] = node;
  this.length++;
};

LruTracker.prototype.touch = function (key) {
  var node = this._map[key];
  if (!node || node === this._tail) return;
  // Unlink
  if (node.prev) node.prev.next = node.next;
  else this._head = node.next;
  if (node.next) node.next.prev = node.prev;
  // Append to tail
  node.prev = this._tail;
  node.next = null;
  this._tail.next = node;
  this._tail = node;
};

LruTracker.prototype.evictOldest = function () {
  if (!this._head) return undefined;
  var node = this._head;
  this._head = node.next;
  if (this._head) this._head.prev = null;
  else this._tail = null;
  delete this._map[node.key];
  this.length--;
  return node.key;
};

LruTracker.prototype.remove = function (key) {
  var node = this._map[key];
  if (!node) return false;
  if (node.prev) node.prev.next = node.next;
  else this._head = node.next;
  if (node.next) node.next.prev = node.prev;
  else this._tail = node.prev;
  delete this._map[node.key];
  this.length--;
  return true;
};

LruTracker.prototype.has = function (key) {
  return !!this._map[key];
};

LruTracker.prototype.toArray = function () {
  var result = [];
  var node = this._head;
  while (node) {
    result.push(node.key);
    node = node.next;
  }
  return result;
};

LruTracker.prototype.clear = function () {
  this._map = Object.create(null);
  this._head = null;
  this._tail = null;
  this.length = 0;
};

/**
 * Re-populate from a serialized array (for state restore).
 * @param {string[]} arr - keys in oldest-to-newest order
 */
LruTracker.prototype.fromArray = function (arr) {
  this.clear();
  for (var i = 0; i < arr.length; i++) {
    this.push(arr[i]);
  }
};

// ── Crypto-secure Randomness ────────────────────────────────────────

var _crypto = null;
try {
  if (typeof require !== 'undefined') _crypto = require('crypto');
} catch (e) { /* not available */ }

/**
 * Generate a cryptographically secure random integer in [0, max).
 * Throws if no cryptographic RNG is available — a CAPTCHA library
 * must never fall back to Math.random() as it is predictable and
 * would allow attackers to forecast challenges.
 *
 * @param {number} max - Exclusive upper bound (must be > 0)
 * @returns {number} Random integer in [0, max)
 * @throws {Error} If no cryptographic random source is available
 */

function _numAsc(a, b) { return a - b; }

function _mean(arr) {
  if (arr.length === 0) return 0;
  var sum = 0;
  for (var i = 0; i < arr.length; i++) sum += arr[i];
  return sum / arr.length;
}

/**
 * Compute the median of a numeric array (does NOT mutate the input).
 * @param {number[]} arr
 * @returns {number} Median, or 0 for empty arrays
 */

function _median(arr) {
  if (arr.length === 0) return 0;
  var sorted = arr.slice().sort(_numAsc);
  var mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

/**
 * Compute the sample standard deviation of a numeric array.
 * Uses Bessel's correction (n-1 denominator).
 * @param {number[]} arr
 * @param {number} [avg] - Pre-computed mean (avoids recomputation)
 * @returns {number} Standard deviation, or 0 for arrays with fewer than 2 elements
 */


/**
 * Factory: create an A/B experiment runner for CAPTCHA configurations.
 *
 * Supports full experiment lifecycle: create experiments with named variants,
 * deterministically assign users via hashing, track solve/fail/abandon events,
 * compute statistical significance (chi-squared + z-test for proportions),
 * detect winners, and support early stopping.
 *
 * @param {Object} [options]
 * @param {number} [options.maxExperiments=50] - Maximum concurrent experiments
 * @param {number} [options.significanceLevel=0.05] - P-value threshold for significance
 * @param {number} [options.minSampleSize=30] - Minimum observations per variant before analysis
 * @param {boolean} [options.earlyStoppingEnabled=true] - Allow early stopping when significance reached
 * @param {number} [options.earlyStoppingConfidence=0.01] - Stricter p-value for early stop
 * @returns {Object} A/B experiment runner API
 *
 * @example
 *   var runner = gifCaptcha.createABExperimentRunner();
 *   runner.createExperiment('diff-test', {
 *     control: { difficulty: 'easy', theme: 'default' },
 *     variants: [
 *       { name: 'hard-dark', config: { difficulty: 'hard', theme: 'dark' } },
 *     ],
 *     targetSampleSize: 200,
 *   });
 *   var variant = runner.assignUser('diff-test', 'user-123');
 *   runner.recordEvent('diff-test', 'user-123', 'solve', { timeMs: 3200 });
 *   var results = runner.analyzeExperiment('diff-test');
 */
function createABExperimentRunner(options) {
  options = options || {};
  var maxExperiments = options.maxExperiments > 0 ? options.maxExperiments : 50;
  var defaultSignificance = typeof options.significanceLevel === 'number' ? options.significanceLevel : 0.05;
  var defaultMinSample = options.minSampleSize > 0 ? options.minSampleSize : 30;
  var earlyStoppingEnabled = options.earlyStoppingEnabled !== false;
  var earlyStoppingConfidence = typeof options.earlyStoppingConfidence === 'number' ? options.earlyStoppingConfidence : 0.01;

  var experiments = {};
  var experimentOrder = new LruTracker();
  var onResultCallbacks = [];

  // ── Helpers ──

  /** djb2 hash for deterministic variant assignment */
  function djb2(str) {
    var hash = 5381;
    for (var i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0x7FFFFFFF;
    }
    return hash;
  }

  /** Approximation of standard normal CDF (Abramowitz & Stegun 26.2.17) */
  function normalCdf(x) {
    if (x < -8) return 0;
    if (x > 8) return 1;
    var sign = x < 0 ? -1 : 1;
    x = Math.abs(x);
    var t = 1 / (1 + 0.2316419 * x);
    var d = 0.3989422804014327; // 1/sqrt(2*pi)
    var prob = d * Math.exp(-0.5 * x * x) *
      (t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429)))));
    return sign < 0 ? prob : 1 - prob;
  }

  /** Two-tailed z-test p-value for difference in proportions */
  function proportionZTest(n1, s1, n2, s2) {
    if (n1 === 0 || n2 === 0) return { z: 0, pValue: 1 };
    var p1 = s1 / n1;
    var p2 = s2 / n2;
    var pPool = (s1 + s2) / (n1 + n2);
    if (pPool === 0 || pPool === 1) return { z: 0, pValue: 1 };
    var se = Math.sqrt(pPool * (1 - pPool) * (1 / n1 + 1 / n2));
    if (se === 0) return { z: 0, pValue: 1 };
    var z = (p1 - p2) / se;
    var pValue = 2 * (1 - normalCdf(Math.abs(z)));
    return { z: z, pValue: pValue };
  }

  /** Chi-squared test for k variants (Pearson's goodness-of-fit) */
  function chiSquaredTest(variants) {
    var totalSolves = 0;
    var totalAttempts = 0;
    for (var i = 0; i < variants.length; i++) {
      totalSolves += variants[i].solves;
      totalAttempts += variants[i].attempts;
    }
    if (totalAttempts === 0) return { chiSq: 0, df: 0, pValue: 1 };
    var expectedRate = totalSolves / totalAttempts;
    var chiSq = 0;
    for (var j = 0; j < variants.length; j++) {
      var n = variants[j].attempts;
      if (n === 0) continue;
      var expectedSolves = n * expectedRate;
      var expectedFails = n * (1 - expectedRate);
      if (expectedSolves > 0) {
        var dS = variants[j].solves - expectedSolves;
        chiSq += (dS * dS) / expectedSolves;
      }
      var fails = n - variants[j].solves;
      if (expectedFails > 0) {
        var dF = fails - expectedFails;
        chiSq += (dF * dF) / expectedFails;
      }
    }
    var df = variants.length - 1;
    // Approximate chi-squared p-value using Wilson-Hilferty
    var pValue = 1;
    if (df > 0 && chiSq > 0) {
      var k = df;
      var z2 = Math.pow(chiSq / k, 1 / 3) - (1 - 2 / (9 * k));
      z2 = z2 / Math.sqrt(2 / (9 * k));
      pValue = 1 - normalCdf(z2);
    }
    return { chiSq: chiSq, df: df, pValue: pValue };
  }

  /** Compute per-variant stats */
  function computeVariantStats(variantData) {
    var completedAttempts = variantData.solves + variantData.fails;
    var totalAttempts = completedAttempts + variantData.abandons;
    var solveRate = completedAttempts > 0 ? variantData.solves / completedAttempts : 0;
    var times = variantData.solveTimes;
    var avgTime = _mean(times);
    var medianTime = _median(times);
    var p95Time = 0;
    if (times.length > 0) {
      var sorted = times.slice().sort(_numAsc);
      p95Time = sorted[Math.floor(sorted.length * 0.95)];
    }
    return {
      name: variantData.name,
      config: variantData.config,
      attempts: completedAttempts,
      totalAttempts: totalAttempts,
      solves: variantData.solves,
      fails: variantData.fails,
      abandons: variantData.abandons,
      solveRate: solveRate,
      avgSolveTimeMs: Math.round(avgTime),
      medianSolveTimeMs: Math.round(medianTime),
      p95SolveTimeMs: Math.round(p95Time),
      abandonRate: totalAttempts > 0 ? variantData.abandons / totalAttempts : 0,
    };
  }

  // ── Core API ──

  /**
   * Create a new experiment.
   * @param {string} experimentId - Unique experiment identifier
   * @param {Object} spec
   * @param {Object} spec.control - Control config
   * @param {Object[]} spec.variants - Array of { name: string, config: Object }
   * @param {number} [spec.targetSampleSize=100] - Target observations per variant
   * @param {string} [spec.description] - Human-readable description
   * @returns {Object} Created experiment summary
   */
  function createExperiment(experimentId, spec) {
    if (!experimentId || typeof experimentId !== 'string') {
      throw new Error('experimentId must be a non-empty string');
    }
    if (experiments[experimentId]) {
      throw new Error('Experiment already exists: ' + experimentId);
    }
    if (experimentOrder.length >= maxExperiments) {
      throw new Error('Maximum experiments reached (' + maxExperiments + ')');
    }
    if (!spec || !spec.control) {
      throw new Error('spec.control is required');
    }
    if (!spec.variants || !Array.isArray(spec.variants) || spec.variants.length === 0) {
      throw new Error('spec.variants must be a non-empty array');
    }
    // Validate variant names are unique
    var names = { control: true };
    for (var i = 0; i < spec.variants.length; i++) {
      var v = spec.variants[i];
      if (!v.name || typeof v.name !== 'string') {
        throw new Error('Each variant must have a name string');
      }
      if (names[v.name]) {
        throw new Error('Duplicate variant name: ' + v.name);
      }
      names[v.name] = true;
    }

    var allVariants = [{ name: 'control', config: spec.control }];
    for (var j = 0; j < spec.variants.length; j++) {
      allVariants.push({ name: spec.variants[j].name, config: spec.variants[j].config || {} });
    }

    var variantData = {};
    for (var k = 0; k < allVariants.length; k++) {
      variantData[allVariants[k].name] = {
        name: allVariants[k].name,
        config: allVariants[k].config,
        solves: 0,
        fails: 0,
        abandons: 0,
        solveTimes: [],
        users: {},
      };
    }

    experiments[experimentId] = {
      id: experimentId,
      description: spec.description || '',
      status: 'running',
      createdAt: Date.now(),
      endedAt: null,
      targetSampleSize: spec.targetSampleSize > 0 ? spec.targetSampleSize : 100,
      variantNames: allVariants.map(function (v) { return v.name; }),
      variants: variantData,
      winner: null,
      userAssignments: {},
    };
    experimentOrder.push(experimentId);

    return { id: experimentId, variants: allVariants.length, status: 'running' };
  }

  /**
   * Deterministically assign a user to a variant.
   * Subsequent calls with the same experimentId + userId return the same variant.
   * @param {string} experimentId
   * @param {string} userId
   * @returns {{ variant: string, config: Object }}
   */
  function assignUser(experimentId, userId) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    if (!userId || typeof userId !== 'string') throw new Error('userId must be a non-empty string');

    // Check existing assignment
    if (exp.userAssignments[userId]) {
      var assignedName = exp.userAssignments[userId];
      return { variant: assignedName, config: exp.variants[assignedName].config };
    }

    // Deterministic hash-based assignment
    var hash = djb2(experimentId + ':' + userId);
    var idx = hash % exp.variantNames.length;
    var variantName = exp.variantNames[idx];
    exp.userAssignments[userId] = variantName;

    return { variant: variantName, config: exp.variants[variantName].config };
  }

  /**
   * Record an event (solve, fail, abandon) for a user in an experiment.
   * @param {string} experimentId
   * @param {string} userId
   * @param {string} eventType - 'solve' | 'fail' | 'abandon'
   * @param {Object} [data]
   * @param {number} [data.timeMs] - Solve time in milliseconds (for 'solve' events)
   */
  function recordEvent(experimentId, userId, eventType, data) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    if (exp.status !== 'running') return; // Silently ignore if stopped

    // Auto-assign if not already
    var assignment = assignUser(experimentId, userId);
    var variant = exp.variants[assignment.variant];
    data = data || {};

    switch (eventType) {
      case 'solve':
        variant.solves++;
        if (typeof data.timeMs === 'number' && data.timeMs > 0) {
          variant.solveTimes.push(data.timeMs);
        }
        break;
      case 'fail':
        variant.fails++;
        break;
      case 'abandon':
        variant.abandons++;
        break;
      default:
        throw new Error('Unknown event type: ' + eventType + '. Expected solve/fail/abandon');
    }

    // Track per-user events
    if (!variant.users[userId]) variant.users[userId] = [];
    variant.users[userId].push({ type: eventType, time: Date.now(), data: data });

    // Check early stopping
    if (earlyStoppingEnabled && exp.status === 'running') {
      var ready = true;
      for (var i = 0; i < exp.variantNames.length; i++) {
        var vd = exp.variants[exp.variantNames[i]];
        if (vd.solves + vd.fails + vd.abandons < defaultMinSample) {
          ready = false;
          break;
        }
      }
      if (ready) {
        var analysis = _analyzeInternal(exp);
        if (analysis.significant && analysis.pValue <= earlyStoppingConfidence) {
          exp.status = 'completed';
          exp.endedAt = Date.now();
          exp.winner = analysis.winner;
          _fireCallbacks(experimentId, analysis);
        }
      }
    }
  }

  /**
   * Analyze an experiment's results.
   * @param {string} experimentId
   * @returns {Object} Analysis results with statistics
   */
  function analyzeExperiment(experimentId) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    return _analyzeInternal(exp);
  }

  function _analyzeInternal(exp) {
    var variantStats = [];
    var chiVariants = [];
    for (var i = 0; i < exp.variantNames.length; i++) {
      var name = exp.variantNames[i];
      var vd = exp.variants[name];
      var stats = computeVariantStats(vd);
      variantStats.push(stats);
      chiVariants.push({ solves: vd.solves, attempts: stats.attempts });
    }

    // Chi-squared across all variants
    var chiResult = chiSquaredTest(chiVariants);

    // Pairwise z-tests: each variant vs control
    var controlData = exp.variants['control'];
    var controlAttempts = controlData.solves + controlData.fails;
    var pairwise = [];
    for (var j = 1; j < exp.variantNames.length; j++) {
      var vName = exp.variantNames[j];
      var vData = exp.variants[vName];
      var vAttempts = vData.solves + vData.fails;
      var zResult = proportionZTest(controlAttempts, controlData.solves, vAttempts, vData.solves);
      var controlRate = controlAttempts > 0 ? controlData.solves / controlAttempts : 0;
      var variantRate = vAttempts > 0 ? vData.solves / vAttempts : 0;
      var lift = controlRate > 0 ? ((variantRate - controlRate) / controlRate) * 100 : 0;
      pairwise.push({
        variant: vName,
        vsControl: {
          z: Math.round(zResult.z * 1000) / 1000,
          pValue: zResult.pValue,
          significant: zResult.pValue < defaultSignificance,
          lift: Math.round(lift * 100) / 100,
        },
      });
    }

    // Determine winner
    var winner = null;
    var bestRate = -1;
    var significant = chiResult.pValue < defaultSignificance;

    var sufficientData = true;
    for (var m = 0; m < variantStats.length; m++) {
      if (variantStats[m].attempts < defaultMinSample) {
        sufficientData = false;
        break;
      }
    }

    if (sufficientData && significant) {
      for (var k = 0; k < variantStats.length; k++) {
        if (variantStats[k].solveRate > bestRate) {
          bestRate = variantStats[k].solveRate;
          winner = variantStats[k].name;
        }
      }
    }

    return {
      experimentId: exp.id,
      status: exp.status,
      variants: variantStats,
      chiSquared: {
        value: Math.round(chiResult.chiSq * 1000) / 1000,
        df: chiResult.df,
        pValue: chiResult.pValue,
      },
      pairwiseTests: pairwise,
      significant: significant,
      pValue: chiResult.pValue,
      sufficientData: sufficientData,
      winner: winner,
      recommendation: _getRecommendation(winner, significant, sufficientData, variantStats),
    };
  }

  function _getRecommendation(winner, significant, sufficientData, variantStats) {
    if (!sufficientData) {
      var current = Infinity;
      for (var i = 0; i < variantStats.length; i++) {
        if (variantStats[i].attempts < current) current = variantStats[i].attempts;
      }
      return 'Insufficient data. Minimum ' + defaultMinSample + ' attempts per variant needed (lowest: ' + current + ').';
    }
    if (!significant) {
      return 'No statistically significant difference detected. Continue collecting data or accept null hypothesis.';
    }
    if (winner === 'control') {
      return 'Control performs best. No change recommended.';
    }
    return 'Variant "' + winner + '" is the winner. Consider adopting its configuration.';
  }

  /**
   * Stop an experiment manually.
   * @param {string} experimentId
   * @returns {Object} Final analysis
   */
  function stopExperiment(experimentId) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    exp.status = 'stopped';
    exp.endedAt = Date.now();
    var analysis = _analyzeInternal(exp);
    exp.winner = analysis.winner;
    return analysis;
  }

  /**
   * Get experiment info.
   * @param {string} experimentId
   * @returns {Object|null}
   */
  function getExperiment(experimentId) {
    var exp = experiments[experimentId];
    if (!exp) return null;
    return {
      id: exp.id,
      description: exp.description,
      status: exp.status,
      createdAt: exp.createdAt,
      endedAt: exp.endedAt,
      variantNames: exp.variantNames.slice(),
      targetSampleSize: exp.targetSampleSize,
      winner: exp.winner,
      totalUsers: Object.keys(exp.userAssignments).length,
    };
  }

  /**
   * List all experiments.
   * @param {Object} [filters]
   * @param {string} [filters.status] - Filter by status (running/stopped/completed)
   * @returns {Object[]}
   */
  function listExperiments(filters) {
    filters = filters || {};
    var results = [];
    var order = experimentOrder.toArray();
    for (var i = 0; i < order.length; i++) {
      var exp = experiments[order[i]];
      if (!exp) continue;
      if (filters.status && exp.status !== filters.status) continue;
      results.push(getExperiment(exp.id));
    }
    return results;
  }

  /**
   * Delete an experiment.
   * @param {string} experimentId
   * @returns {boolean} True if deleted
   */
  function deleteExperiment(experimentId) {
    if (!experiments[experimentId]) return false;
    delete experiments[experimentId];
    experimentOrder.remove(experimentId);
    return true;
  }

  /**
   * Get variant assignment counts for an experiment.
   * @param {string} experimentId
   * @returns {Object} Map of variant name to user count
   */
  function getAssignmentCounts(experimentId) {
    var exp = experiments[experimentId];
    if (!exp) throw new Error('Unknown experiment: ' + experimentId);
    var counts = {};
    for (var i = 0; i < exp.variantNames.length; i++) {
      counts[exp.variantNames[i]] = 0;
    }
    var keys = Object.keys(exp.userAssignments);
    for (var j = 0; j < keys.length; j++) {
      var v2 = exp.userAssignments[keys[j]];
      counts[v2] = (counts[v2] || 0) + 1;
    }
    return counts;
  }

  /**
   * Register a callback for experiment completion (via early stopping).
   * @param {Function} fn - Called with (experimentId, analysis)
   */
  function onResult(fn) {
    if (typeof fn === 'function') onResultCallbacks.push(fn);
  }

  function _fireCallbacks(experimentId, analysis) {
    for (var i = 0; i < onResultCallbacks.length; i++) {
      try { onResultCallbacks[i](experimentId, analysis); } catch (e) { /* ignore */ }
    }
  }

  /**
   * Export all experiment data as JSON-serializable object.
   * @returns {Object}
   */
  function exportState() {
    var data = [];
    var order = experimentOrder.toArray();
    for (var i = 0; i < order.length; i++) {
      var exp = experiments[order[i]];
      if (!exp) continue;
      var variantExport = {};
      for (var j = 0; j < exp.variantNames.length; j++) {
        var name = exp.variantNames[j];
        var vd = exp.variants[name];
        variantExport[name] = {
          name: vd.name,
          config: vd.config,
          solves: vd.solves,
          fails: vd.fails,
          abandons: vd.abandons,
          solveTimes: vd.solveTimes.slice(),
        };
      }
      data.push({
        id: exp.id,
        description: exp.description,
        status: exp.status,
        createdAt: exp.createdAt,
        endedAt: exp.endedAt,
        targetSampleSize: exp.targetSampleSize,
        variantNames: exp.variantNames.slice(),
        variants: variantExport,
        winner: exp.winner,
      });
    }
    return { experiments: data, exportedAt: Date.now() };
  }

  /**
   * Import experiment data from a previous export.
   * @param {Object} state - Data from exportState()
   * @returns {number} Number of experiments imported
   */
  function importState(state) {
    if (!state || !Array.isArray(state.experiments)) return 0;
    var imported = 0;
    for (var i = 0; i < state.experiments.length; i++) {
      var e = state.experiments[i];
      if (!e.id || experiments[e.id]) continue;
      if (experimentOrder.length >= maxExperiments) break;

      var variantData = {};
      for (var j = 0; j < e.variantNames.length; j++) {
        var name = e.variantNames[j];
        var src = (e.variants && e.variants[name]) || {};
        variantData[name] = {
          name: name,
          config: src.config || {},
          solves: src.solves || 0,
          fails: src.fails || 0,
          abandons: src.abandons || 0,
          solveTimes: Array.isArray(src.solveTimes) ? src.solveTimes.slice() : [],
          users: {},
        };
      }

      experiments[e.id] = {
        id: e.id,
        description: e.description || '',
        status: e.status || 'stopped',
        createdAt: e.createdAt || Date.now(),
        endedAt: e.endedAt || null,
        targetSampleSize: e.targetSampleSize || 100,
        variantNames: e.variantNames.slice(),
        variants: variantData,
        winner: e.winner || null,
        userAssignments: {},
      };
      experimentOrder.push(e.id);
      imported++;
    }
    return imported;
  }

  /**
   * Generate a text summary of an experiment's results.
   * @param {string} experimentId
   * @returns {string}
   */
  function textReport(experimentId) {
    var analysis = analyzeExperiment(experimentId);
    var exp = experiments[experimentId];
    var lines = [];
    lines.push('A/B Experiment: ' + analysis.experimentId);
    if (exp.description) lines.push('Description: ' + exp.description);
    lines.push('Status: ' + analysis.status);
    lines.push('');
    lines.push('Variants:');
    for (var i = 0; i < analysis.variants.length; i++) {
      var v = analysis.variants[i];
      lines.push('  ' + v.name + ':');
      lines.push('    Attempts: ' + v.attempts);
      lines.push('    Solve rate: ' + (v.solveRate * 100).toFixed(1) + '%');
      lines.push('    Abandon rate: ' + (v.abandonRate * 100).toFixed(1) + '%');
      if (v.avgSolveTimeMs > 0) {
        lines.push('    Avg solve time: ' + v.avgSolveTimeMs + 'ms');
        lines.push('    Median solve time: ' + v.medianSolveTimeMs + 'ms');
        lines.push('    P95 solve time: ' + v.p95SolveTimeMs + 'ms');
      }
    }
    lines.push('');
    lines.push('Chi-squared: ' + analysis.chiSquared.value + ' (df=' + analysis.chiSquared.df + ', p=' + analysis.pValue.toFixed(4) + ')');
    lines.push('Significant: ' + (analysis.significant ? 'Yes' : 'No'));
    if (analysis.pairwiseTests.length > 0) {
      lines.push('');
      lines.push('Pairwise vs Control:');
      for (var j = 0; j < analysis.pairwiseTests.length; j++) {
        var pw = analysis.pairwiseTests[j];
        lines.push('  ' + pw.variant + ': z=' + pw.vsControl.z + ', p=' + pw.vsControl.pValue.toFixed(4) +
          ', lift=' + pw.vsControl.lift + '%' +
          (pw.vsControl.significant ? ' *' : ''));
      }
    }
    lines.push('');
    lines.push('Winner: ' + (analysis.winner || 'None'));
    lines.push('Recommendation: ' + analysis.recommendation);
    return lines.join('\n');
  }

  return {
    createExperiment: createExperiment,
    assignUser: assignUser,
    recordEvent: recordEvent,
    analyzeExperiment: analyzeExperiment,
    stopExperiment: stopExperiment,
    getExperiment: getExperiment,
    listExperiments: listExperiments,
    deleteExperiment: deleteExperiment,
    getAssignmentCounts: getAssignmentCounts,
    onResult: onResult,
    exportState: exportState,
    importState: importState,
    textReport: textReport,
  };
}


module.exports = { createABExperimentRunner: createABExperimentRunner };
