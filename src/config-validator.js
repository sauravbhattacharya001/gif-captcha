"use strict";

// ── Shared utilities (deduplicated — issue #91) ─────────────────────
var _shared = require("./shared-utils");
var _now = _shared._now;
var _clamp = _shared._clamp;
var _numAsc = _shared._numAsc;
var _mean = _shared._mean;
var _median = _shared._median;
var _stddev = _shared._stddev;
var LruTracker = _shared.LruTracker;
var _percentile = _shared._percentile;


// ── Configuration Validator ─────────────────────────────────────────
/**
 * createConfigValidator -- Validates CAPTCHA deployment configuration
 * objects against known constraints. Catches misconfigurations that
 * silently degrade security, performance, or usability before they
 * reach production.
 *
 * Checks:
 *  - Type correctness and range validation for all known options
 *  - Security warnings (weak secrets, disabled features)
 *  - Performance warnings (extreme timeouts, oversized pools)
 *  - Usability warnings (impossible difficulty, overly aggressive rate limiting)
 *  - Cross-field consistency (e.g. minPassRate >= maxPassRate)
 *
 * @param {Object} [options]
 * @param {boolean} [options.strict=false] - Treat warnings as errors
 * @param {string[]} [options.ignore] - Rule IDs to skip
 * @returns {{ validate: Function, rules: Function }}
 */
function createConfigValidator(options) {
  options = options || {};
  var strict = options.strict === true;
  var ignoreSet = Object.create(null);
  var ignoreList = options.ignore || [];
  for (var ig = 0; ig < ignoreList.length; ig++) {
    ignoreSet[ignoreList[ig]] = true;
  }

  // Severity levels
  var ERROR = "error";
  var WARNING = "warning";

  // ── Rule definitions ──────────────────────────────────────────

  var RULES = [
    // ── AttemptTracker ──
    {
      id: "attempt.maxAttempts.type",
      module: "attemptTracker",
      field: "maxAttempts",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.maxAttempts != null && (typeof cfg.maxAttempts !== "number" || cfg.maxAttempts < 1)) {
          return "maxAttempts must be a positive integer, got " + cfg.maxAttempts;
        }
      }
    },
    {
      id: "attempt.maxAttempts.low",
      module: "attemptTracker",
      field: "maxAttempts",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.maxAttempts === "number" && cfg.maxAttempts < 2) {
          return "maxAttempts=1 gives users no chance to retry — consider at least 3";
        }
      }
    },
    {
      id: "attempt.lockoutMs.type",
      module: "attemptTracker",
      field: "lockoutMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.lockoutMs != null && (typeof cfg.lockoutMs !== "number" || cfg.lockoutMs < 0)) {
          return "lockoutMs must be a non-negative number";
        }
      }
    },
    {
      id: "attempt.lockoutMs.short",
      module: "attemptTracker",
      field: "lockoutMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.lockoutMs === "number" && cfg.lockoutMs > 0 && cfg.lockoutMs < 1000) {
          return "lockoutMs under 1 second provides negligible brute-force protection";
        }
      }
    },
    {
      id: "attempt.lockoutMs.long",
      module: "attemptTracker",
      field: "lockoutMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.lockoutMs === "number" && cfg.lockoutMs > 3600000) {
          return "lockoutMs over 1 hour may frustrate legitimate users (" + Math.round(cfg.lockoutMs / 60000) + " min)";
        }
      }
    },
    // ── TokenVerifier ──
    {
      id: "token.secret.missing",
      module: "tokenVerifier",
      field: "secret",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.secret != null && typeof cfg.secret !== "string") {
          return "secret must be a string";
        }
      }
    },
    {
      id: "token.secret.weak",
      module: "tokenVerifier",
      field: "secret",
      severity: ERROR,
      check: function (cfg) {
        if (typeof cfg.secret === "string" && cfg.secret.length < 16) {
          return "secret must be at least 16 characters for HMAC security (got " + cfg.secret.length + ")";
        }
      }
    },
    {
      id: "token.secret.entropy",
      module: "tokenVerifier",
      field: "secret",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.secret === "string" && cfg.secret.length >= 16) {
          // Check for low-entropy patterns
          var unique = Object.create(null);
          for (var i = 0; i < cfg.secret.length; i++) { unique[cfg.secret[i]] = true; }
          var count = 0;
          for (var k in unique) { count++; }
          if (count < 6) {
            return "secret has very low character diversity (" + count + " unique chars) — use a random generator";
          }
        }
      }
    },
    {
      id: "token.ttlMs.type",
      module: "tokenVerifier",
      field: "ttlMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.ttlMs != null && (typeof cfg.ttlMs !== "number" || cfg.ttlMs < 1)) {
          return "ttlMs must be a positive number";
        }
      }
    },
    {
      id: "token.ttlMs.short",
      module: "tokenVerifier",
      field: "ttlMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.ttlMs === "number" && cfg.ttlMs < 10000) {
          return "ttlMs under 10 seconds may expire before users complete the CAPTCHA";
        }
      }
    },
    // ── BotDetector ──
    {
      id: "bot.threshold.range",
      module: "botDetector",
      field: "botThreshold",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.botThreshold != null && (typeof cfg.botThreshold !== "number" || cfg.botThreshold < 0 || cfg.botThreshold > 100)) {
          return "botThreshold must be 0-100, got " + cfg.botThreshold;
        }
      }
    },
    {
      id: "bot.threshold.inverted",
      module: "botDetector",
      field: "botThreshold",
      severity: ERROR,
      check: function (cfg) {
        if (typeof cfg.botThreshold === "number" && typeof cfg.suspiciousThreshold === "number") {
          if (cfg.suspiciousThreshold >= cfg.botThreshold) {
            return "suspiciousThreshold (" + cfg.suspiciousThreshold + ") should be less than botThreshold (" + cfg.botThreshold + ")";
          }
        }
      }
    },
    {
      id: "bot.minMouseMovements.type",
      module: "botDetector",
      field: "minMouseMovements",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.minMouseMovements != null && (typeof cfg.minMouseMovements !== "number" || cfg.minMouseMovements < 0)) {
          return "minMouseMovements must be a non-negative number";
        }
      }
    },
    {
      id: "bot.minTimeOnPage.type",
      module: "botDetector",
      field: "minTimeOnPageMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.minTimeOnPageMs != null && (typeof cfg.minTimeOnPageMs !== "number" || cfg.minTimeOnPageMs < 0)) {
          return "minTimeOnPageMs must be a non-negative number";
        }
      }
    },
    // ── DifficultyCalibrator ──
    {
      id: "difficulty.passRate.range",
      module: "difficultyCalibrator",
      field: "minPassRate",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.minPassRate != null && (typeof cfg.minPassRate !== "number" || cfg.minPassRate < 0 || cfg.minPassRate > 1)) {
          return "minPassRate must be 0-1, got " + cfg.minPassRate;
        }
      }
    },
    {
      id: "difficulty.passRate.inverted",
      module: "difficultyCalibrator",
      field: "minPassRate",
      severity: ERROR,
      check: function (cfg) {
        if (typeof cfg.minPassRate === "number" && typeof cfg.maxPassRate === "number") {
          if (cfg.minPassRate >= cfg.maxPassRate) {
            return "minPassRate (" + cfg.minPassRate + ") must be less than maxPassRate (" + cfg.maxPassRate + ") — no valid calibration range";
          }
        }
      }
    },
    {
      id: "difficulty.base.range",
      module: "difficultyCalibrator",
      field: "baseDifficulty",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.baseDifficulty != null && (typeof cfg.baseDifficulty !== "number" || cfg.baseDifficulty < 0 || cfg.baseDifficulty > 100)) {
          return "baseDifficulty must be 0-100";
        }
      }
    },
    {
      id: "difficulty.base.exceeds.max",
      module: "difficultyCalibrator",
      field: "baseDifficulty",
      severity: ERROR,
      check: function (cfg) {
        if (typeof cfg.baseDifficulty === "number" && typeof cfg.maxDifficulty === "number") {
          if (cfg.baseDifficulty > cfg.maxDifficulty) {
            return "baseDifficulty (" + cfg.baseDifficulty + ") exceeds maxDifficulty (" + cfg.maxDifficulty + ")";
          }
        }
      }
    },
    // ── RateLimiter ──
    {
      id: "rate.windowMs.type",
      module: "rateLimiter",
      field: "windowMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.windowMs != null && (typeof cfg.windowMs !== "number" || cfg.windowMs < 1)) {
          return "windowMs must be a positive number";
        }
      }
    },
    {
      id: "rate.maxRequests.type",
      module: "rateLimiter",
      field: "maxRequests",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.maxRequests != null && (typeof cfg.maxRequests !== "number" || cfg.maxRequests < 1)) {
          return "maxRequests must be a positive integer";
        }
      }
    },
    {
      id: "rate.maxRequests.aggressive",
      module: "rateLimiter",
      field: "maxRequests",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.maxRequests === "number" && typeof cfg.windowMs === "number") {
          var perMinute = (cfg.maxRequests / cfg.windowMs) * 60000;
          if (perMinute < 2) {
            return "Rate limit allows fewer than 2 requests/minute — legitimate users may be blocked";
          }
        }
      }
    },
    // ── ReputationTracker ──
    {
      id: "reputation.threshold.inverted",
      module: "reputationTracker",
      field: "trustedThreshold",
      severity: ERROR,
      check: function (cfg) {
        var trusted = typeof cfg.trustedThreshold === "number" ? cfg.trustedThreshold : 0.8;
        var suspicious = typeof cfg.suspiciousThreshold === "number" ? cfg.suspiciousThreshold : 0.3;
        var block = typeof cfg.blockThreshold === "number" ? cfg.blockThreshold : 0.1;
        if (cfg.trustedThreshold != null || cfg.suspiciousThreshold != null || cfg.blockThreshold != null) {
          if (!(block < suspicious && suspicious < trusted)) {
            return "Reputation thresholds must be: blockThreshold < suspiciousThreshold < trustedThreshold (got " + block + " / " + suspicious + " / " + trusted + ")";
          }
        }
      }
    },
    {
      id: "reputation.initialScore.range",
      module: "reputationTracker",
      field: "initialScore",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.initialScore != null && (typeof cfg.initialScore !== "number" || cfg.initialScore < 0 || cfg.initialScore > 1)) {
          return "initialScore must be 0-1, got " + cfg.initialScore;
        }
      }
    },
    {
      id: "reputation.maxEntries.low",
      module: "reputationTracker",
      field: "maxEntries",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.maxEntries === "number" && cfg.maxEntries < 100) {
          return "maxEntries under 100 causes frequent evictions — reputation data won't accumulate";
        }
      }
    },
    // ── PoolManager ──
    {
      id: "pool.rotationInterval.type",
      module: "poolManager",
      field: "rotationIntervalMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.rotationIntervalMs != null && (typeof cfg.rotationIntervalMs !== "number" || cfg.rotationIntervalMs < 1)) {
          return "rotationIntervalMs must be a positive number";
        }
      }
    },
    {
      id: "pool.rotation.fast",
      module: "poolManager",
      field: "rotationIntervalMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.rotationIntervalMs === "number" && cfg.rotationIntervalMs < 30000) {
          return "Rotation interval under 30 seconds may cause cache misses and increased load";
        }
      }
    },
    // ── AdaptiveTimeout ──
    {
      id: "timeout.base.type",
      module: "adaptiveTimeout",
      field: "baseTimeoutMs",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.baseTimeoutMs != null && (typeof cfg.baseTimeoutMs !== "number" || cfg.baseTimeoutMs < 1)) {
          return "baseTimeoutMs must be a positive number";
        }
      }
    },
    {
      id: "timeout.base.short",
      module: "adaptiveTimeout",
      field: "baseTimeoutMs",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.baseTimeoutMs === "number" && cfg.baseTimeoutMs < 5000) {
          return "baseTimeoutMs under 5 seconds may not give users enough time to solve CAPTCHAs";
        }
      }
    },
    // ── General ──
    {
      id: "general.passThreshold.range",
      module: "general",
      field: "passThreshold",
      severity: ERROR,
      check: function (cfg) {
        if (cfg.passThreshold != null && (typeof cfg.passThreshold !== "number" || cfg.passThreshold < 0 || cfg.passThreshold > 1)) {
          return "passThreshold must be 0-1, got " + cfg.passThreshold;
        }
      }
    },
    {
      id: "general.passThreshold.extreme",
      module: "general",
      field: "passThreshold",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.passThreshold === "number") {
          if (cfg.passThreshold > 0.95) {
            return "passThreshold above 0.95 means users must answer nearly every challenge correctly";
          }
          if (cfg.passThreshold < 0.3) {
            return "passThreshold below 0.3 means bots can pass by guessing — security is degraded";
          }
        }
      }
    },
    {
      id: "general.challenges.count",
      module: "general",
      field: "challengeCount",
      severity: WARNING,
      check: function (cfg) {
        if (typeof cfg.challengeCount === "number" && cfg.challengeCount > 10) {
          return "More than 10 challenges per session creates user fatigue — completion rates will drop";
        }
      }
    }
  ];

  // ── Validation engine ─────────────────────────────────────────

  /**
   * Validate a configuration object.
   *
   * @param {Object} config - The config to validate
   * @param {Object} [opts]
   * @param {string} [opts.module] - Only check rules for a specific module
   * @returns {{ valid: boolean, errors: Array, warnings: Array, info: Array, summary: string }}
   */
  function validate(config) {
    var opts = arguments.length > 1 ? arguments[1] : {};
    config = config || {};
    var moduleFilter = opts.module || null;
    var errors = [];
    var warnings = [];
    var infos = [];

    for (var i = 0; i < RULES.length; i++) {
      var rule = RULES[i];

      // Skip ignored rules
      if (ignoreSet[rule.id]) { continue; }

      // Module filter
      if (moduleFilter && rule.module !== moduleFilter) { continue; }

      var message = rule.check(config);
      if (message) {
        var finding = {
          id: rule.id,
          module: rule.module,
          field: rule.field,
          severity: rule.severity,
          message: message
        };

        if (rule.severity === ERROR) {
          errors.push(finding);
        } else if (rule.severity === WARNING) {
          if (strict) {
            errors.push(finding);
          } else {
            warnings.push(finding);
          }
        } else {
          infos.push(finding);
        }
      }
    }

    var valid = errors.length === 0;

    var parts = [];
    if (errors.length > 0) { parts.push(errors.length + " error(s)"); }
    if (warnings.length > 0) { parts.push(warnings.length + " warning(s)"); }
    if (infos.length > 0) { parts.push(infos.length + " info"); }
    var summary = valid
      ? (warnings.length > 0 ? "Valid with " + warnings.length + " warning(s)" : "Valid — no issues found")
      : "Invalid — " + parts.join(", ");

    return {
      valid: valid,
      errors: errors,
      warnings: warnings,
      info: infos,
      summary: summary
    };
  }

  /**
   * Get the list of all validation rules.
   *
   * @returns {Array<{ id: string, module: string, field: string, severity: string }>}
   */
  function rules() {
    var result = [];
    for (var i = 0; i < RULES.length; i++) {
      var r = RULES[i];
      result.push({
        id: r.id,
        module: r.module,
        field: r.field,
        severity: r.severity
      });
    }
    return result;
  }

  return {
    validate: validate,
    rules: rules
  };
}



// -- Challenge Analytics ---------------------------------------------------

/**
 * Create a challenge analytics engine that tracks per-challenge performance
 * metrics: solve rates, timing distributions, abandonment, difficulty
 * effectiveness, and pool diversity scoring.
 *
 * @param {Object} [options]
 * @param {number} [options.maxChallenges=500]  Max tracked challenge IDs
 * @param {number} [options.maxEventsPerChallenge=200]  Events kept per ID
 * @returns {Object} Challenge analytics instance
 */
function createChallengeAnalytics(options) {
  var opts = options || {};
  var maxChallenges = Math.max(1, opts.maxChallenges || 500);
  var maxEventsPerChallenge = Math.max(1, opts.maxEventsPerChallenge || 200);

  // challengeId -> { events: [], stats cache }
  var store = Object.create(null);
  var challengeCount = 0;
  var evictionOrder = new LruTracker();  // true LRU via doubly-linked list

  function _ensureEntry(challengeId) {
    if (store[challengeId]) {
      evictionOrder.push(challengeId);  // promote to most-recently-used
      return store[challengeId];
    }
    if (challengeCount >= maxChallenges) {
      // Evict least-recently-used
      var oldest = evictionOrder.evictOldest();
      if (oldest !== undefined && store[oldest]) {
        delete store[oldest];
        challengeCount--;
      }
    }
    store[challengeId] = { events: [], dirty: true };
    challengeCount++;
    evictionOrder.push(challengeId);
    return store[challengeId];
  }

  /**
   * Record a challenge attempt event.
   * @param {Object} event
   * @param {string} event.challengeId
   * @param {boolean} event.correct - Whether the answer was correct
   * @param {number} event.timeMs - Time taken in milliseconds
   * @param {boolean} [event.abandoned] - Whether the user abandoned
   * @param {number} [event.difficulty] - Difficulty level (1-10)
   * @param {string} [event.clientId] - Optional client identifier
   */
  function record(event) {
    if (!event || typeof event.challengeId !== 'string') {
      throw new Error('event.challengeId is required');
    }
    if (typeof event.correct !== 'boolean' && !event.abandoned) {
      throw new Error('event.correct (boolean) is required unless abandoned');
    }
    var entry = _ensureEntry(event.challengeId);
    var ev = {
      correct: !!event.correct,
      timeMs: typeof event.timeMs === 'number' ? event.timeMs : 0,
      abandoned: !!event.abandoned,
      difficulty: typeof event.difficulty === 'number' ? event.difficulty : null,
      clientId: event.clientId || null,
      ts: _now(),
    };
    entry.events.push(ev);
    if (entry.events.length > maxEventsPerChallenge) {
      entry.events.shift();
    }
    entry.dirty = true;
  }

  /**
   * Get detailed stats for a single challenge.
   * @param {string} challengeId
   * @returns {Object|null} Stats object or null if not found
   */
  function getChallengeStats(challengeId) {
    var entry = store[challengeId];
    if (!entry || entry.events.length === 0) return null;

    var events = entry.events;
    var total = events.length;
    var correct = 0;
    var abandoned = 0;
    var times = [];
    var correctTimes = [];
    var incorrectTimes = [];
    var difficulties = [];

    for (var i = 0; i < total; i++) {
      var ev = events[i];
      if (ev.abandoned) {
        abandoned++;
        continue;
      }
      if (ev.correct) {
        correct++;
        if (ev.timeMs > 0) correctTimes.push(ev.timeMs);
      } else {
        if (ev.timeMs > 0) incorrectTimes.push(ev.timeMs);
      }
      if (ev.timeMs > 0) times.push(ev.timeMs);
      if (ev.difficulty !== null) difficulties.push(ev.difficulty);
    }

    var attempted = total - abandoned;
    var solveRate = attempted > 0 ? correct / attempted : 0;
    var abandonRate = total > 0 ? abandoned / total : 0;

    return {
      challengeId: challengeId,
      totalEvents: total,
      attempted: attempted,
      correct: correct,
      incorrect: attempted - correct,
      abandoned: abandoned,
      solveRate: Math.round(solveRate * 10000) / 10000,
      abandonRate: Math.round(abandonRate * 10000) / 10000,
      timing: _computeTimingStats(times),
      correctTiming: _computeTimingStats(correctTimes),
      incorrectTiming: _computeTimingStats(incorrectTimes),
      avgDifficulty: difficulties.length > 0
        ? Math.round(_mean(difficulties) * 100) / 100
        : null,
    };
  }

  /**
   * Get a ranked leaderboard of challenges by a metric.
   * @param {Object} [opts]
   * @param {string} [opts.sortBy='solveRate'] - Metric to sort by
   * @param {string} [opts.order='asc'] - 'asc' or 'desc'
   * @param {number} [opts.minEvents=5] - Minimum events to include
   * @param {number} [opts.limit=20] - Max results
   * @returns {Object[]} Ranked challenge stats
   */
  function ranking(opts) {
    opts = opts || {};
    var sortBy = opts.sortBy || 'solveRate';
    var order = opts.order || 'asc';
    var minEvents = typeof opts.minEvents === 'number' ? opts.minEvents : 5;
    var limit = typeof opts.limit === 'number' ? opts.limit : 20;

    var results = [];
    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      var stats = getChallengeStats(ids[i]);
      if (!stats || stats.totalEvents < minEvents) continue;
      results.push(stats);
    }

    results.sort(function (a, b) {
      var va = _extractMetric(a, sortBy);
      var vb = _extractMetric(b, sortBy);
      return order === 'desc' ? vb - va : va - vb;
    });

    if (limit > 0 && results.length > limit) {
      results = results.slice(0, limit);
    }
    return results;
  }

  function _extractMetric(stats, metric) {
    if (metric === 'solveRate') return stats.solveRate;
    if (metric === 'abandonRate') return stats.abandonRate;
    if (metric === 'avgTime') return stats.timing.mean || 0;
    if (metric === 'totalEvents') return stats.totalEvents;
    if (metric === 'medianTime') return stats.timing.median || 0;
    return 0;
  }

  /**
   * Compute aggregate pool-level statistics across all tracked challenges.
   * @returns {Object} Pool-level metrics
   */
  function poolStats() {
    var ids = Object.keys(store);
    var totalChallenges = ids.length;
    var totalEvents = 0;
    var totalCorrect = 0;
    var totalAttempted = 0;
    var totalAbandoned = 0;
    var solveRates = [];
    var abandonRates = [];

    for (var i = 0; i < ids.length; i++) {
      var stats = getChallengeStats(ids[i]);
      if (!stats) continue;
      totalEvents += stats.totalEvents;
      totalCorrect += stats.correct;
      totalAttempted += stats.attempted;
      totalAbandoned += stats.abandoned;
      if (stats.attempted >= 3) {
        solveRates.push(stats.solveRate);
        abandonRates.push(stats.abandonRate);
      }
    }

    var overallSolveRate = totalAttempted > 0 ? totalCorrect / totalAttempted : 0;

    return {
      totalChallenges: totalChallenges,
      totalEvents: totalEvents,
      totalAttempted: totalAttempted,
      totalCorrect: totalCorrect,
      totalAbandoned: totalAbandoned,
      overallSolveRate: Math.round(overallSolveRate * 10000) / 10000,
      solveRateDistribution: solveRates.length > 0 ? _computeTimingStats(solveRates) : null,
      abandonRateDistribution: abandonRates.length > 0 ? _computeTimingStats(abandonRates) : null,
      diversity: _computeDiversity(solveRates),
    };
  }

  /**
   * Identify challenges that may need attention.
   * @param {Object} [thresholds]
   * @param {number} [thresholds.tooEasy=0.95] - Solve rate above this = too easy
   * @param {number} [thresholds.tooHard=0.15] - Solve rate below this = too hard
   * @param {number} [thresholds.highAbandon=0.4] - Abandon rate above this = problematic
   * @param {number} [thresholds.minEvents=10] - Min events to flag
   * @returns {{ tooEasy: Object[], tooHard: Object[], highAbandon: Object[] }}
   */
  function flagged(thresholds) {
    thresholds = thresholds || {};
    var tooEasyThreshold = typeof thresholds.tooEasy === 'number' ? thresholds.tooEasy : 0.95;
    var tooHardThreshold = typeof thresholds.tooHard === 'number' ? thresholds.tooHard : 0.15;
    var highAbandonThreshold = typeof thresholds.highAbandon === 'number' ? thresholds.highAbandon : 0.4;
    var minEvents = typeof thresholds.minEvents === 'number' ? thresholds.minEvents : 10;

    var tooEasy = [];
    var tooHard = [];
    var highAbandon = [];

    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      var stats = getChallengeStats(ids[i]);
      if (!stats || stats.totalEvents < minEvents) continue;
      if (stats.solveRate >= tooEasyThreshold) tooEasy.push(stats);
      if (stats.solveRate <= tooHardThreshold && stats.attempted > 0) tooHard.push(stats);
      if (stats.abandonRate >= highAbandonThreshold) highAbandon.push(stats);
    }

    tooEasy.sort(function (a, b) { return b.solveRate - a.solveRate; });
    tooHard.sort(function (a, b) { return a.solveRate - b.solveRate; });
    highAbandon.sort(function (a, b) { return b.abandonRate - a.abandonRate; });

    return { tooEasy: tooEasy, tooHard: tooHard, highAbandon: highAbandon };
  }

  /**
   * Compute difficulty effectiveness — how well different difficulty
   * levels discriminate between humans and bots.
   * @returns {Object[]} Array of { difficulty, solveRate, avgTime, count }
   */
  function difficultyEffectiveness() {
    var buckets = Object.create(null);  // difficulty -> { correct, total, times }

    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      var events = store[ids[i]].events;
      for (var j = 0; j < events.length; j++) {
        var ev = events[j];
        if (ev.difficulty === null || ev.abandoned) continue;
        var d = Math.round(ev.difficulty);
        if (!buckets[d]) buckets[d] = { correct: 0, total: 0, times: [] };
        buckets[d].total++;
        if (ev.correct) buckets[d].correct++;
        if (ev.timeMs > 0) buckets[d].times.push(ev.timeMs);
      }
    }

    var result = [];
    var diffs = Object.keys(buckets).sort(function (a, b) { return +a - +b; });
    for (var k = 0; k < diffs.length; k++) {
      var d = +diffs[k];
      var b = buckets[d];
      result.push({
        difficulty: d,
        solveRate: b.total > 0 ? Math.round(b.correct / b.total * 10000) / 10000 : 0,
        avgTimeMs: b.times.length > 0 ? Math.round(_mean(b.times)) : 0,
        count: b.total,
      });
    }
    return result;
  }

  /**
   * Compute time-of-day patterns across all challenges.
   * Returns solve rates bucketed by hour (0-23).
   * @returns {Object[]} Array of { hour, solveRate, count }
   */
  function hourlyPatterns() {
    var buckets = [];
    for (var h = 0; h < 24; h++) {
      buckets.push({ correct: 0, total: 0 });
    }

    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      var events = store[ids[i]].events;
      for (var j = 0; j < events.length; j++) {
        var ev = events[j];
        if (ev.abandoned) continue;
        var hour = new Date(ev.ts).getHours();
        buckets[hour].total++;
        if (ev.correct) buckets[hour].correct++;
      }
    }

    var result = [];
    for (var k = 0; k < 24; k++) {
      result.push({
        hour: k,
        solveRate: buckets[k].total > 0
          ? Math.round(buckets[k].correct / buckets[k].total * 10000) / 10000
          : 0,
        count: buckets[k].total,
      });
    }
    return result;
  }

  /**
   * Export/import state for persistence.
   */
  function exportState() {
    var data = Object.create(null);
    var ids = Object.keys(store);
    for (var i = 0; i < ids.length; i++) {
      data[ids[i]] = store[ids[i]].events.slice();
    }
    return { version: 1, challenges: data, exportedAt: new Date().toISOString() };
  }

  function importState(state) {
    if (!state || typeof state !== 'object' || !state.challenges) {
      throw new Error('Invalid state: must have challenges object');
    }
    reset();
    var ids = Object.keys(state.challenges);
    for (var i = 0; i < ids.length; i++) {
      var entry = _ensureEntry(ids[i]);
      var events = state.challenges[ids[i]];
      if (Array.isArray(events)) {
        entry.events = events.slice(0, maxEventsPerChallenge);
      }
    }
  }

  /**
   * Get summary with stats for getStats() compatibility.
   */
  function getStats() {
    return poolStats();
  }

  function reset() {
    store = Object.create(null);
    challengeCount = 0;
    evictionOrder.clear();
  }

  // -- Internal helpers --
  // _mean, _median, _stddev, _percentile are provided by shared-utils

  function _computeTimingStats(arr) {
    if (arr.length === 0) return { count: 0, mean: 0, median: 0, stddev: 0, p5: 0, p95: 0, min: 0, max: 0 };
    var m = _mean(arr);
    var sorted = arr.slice().sort(_numAsc);
    return {
      count: arr.length,
      mean: Math.round(m * 100) / 100,
      median: Math.round(_median(arr) * 100) / 100,
      stddev: Math.round(_stddev(arr, m) * 100) / 100,
      p5: Math.round(_percentile(arr, 5) * 100) / 100,
      p95: Math.round(_percentile(arr, 95) * 100) / 100,
      min: sorted[0],
      max: sorted[sorted.length - 1],
    };
  }

  function _computeDiversity(solveRates) {
    if (solveRates.length < 2) return { score: 0, label: 'insufficient data' };
    var m = _mean(solveRates);
    var sd = _stddev(solveRates, m);
    // Coefficient of variation (higher = more diverse solve rates)
    var cv = m > 0 ? sd / m : 0;
    var score = _clamp(Math.round(cv * 100), 0, 100);
    var label = score < 15 ? 'low' : score < 40 ? 'moderate' : 'high';
    return { score: score, label: label, cv: Math.round(cv * 1000) / 1000 };
  }

  return {
    record: record,
    getChallengeStats: getChallengeStats,
    ranking: ranking,
    poolStats: poolStats,
    flagged: flagged,
    difficultyEffectiveness: difficultyEffectiveness,
    hourlyPatterns: hourlyPatterns,
    exportState: exportState,
    importState: importState,
    getStats: getStats,
    reset: reset,
  };
}


module.exports = { createConfigValidator: createConfigValidator, createChallengeAnalytics: createChallengeAnalytics };

