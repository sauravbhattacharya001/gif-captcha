/**
 * BotCapabilityProfiler — Autonomous bot sophistication analysis engine.
 *
 * Builds detailed capability profiles for detected bots by analyzing their
 * solve patterns across challenge types, then predicts which challenges
 * each bot class can/cannot defeat. Enables proactive defense by matching
 * challenge difficulty to bot capability.
 *
 * Key capabilities:
 *   - Ingest solve attempts with challenge metadata (type, difficulty, features)
 *   - Build per-bot capability vectors across 8 skill dimensions
 *   - Classify bots into sophistication tiers (5 levels)
 *   - Predict challenge vulnerability against specific bot profiles
 *   - Track capability evolution over time (learning rate, plateau detection)
 *   - Generate defense recommendations (optimal challenge mix)
 *   - Autonomous threat escalation when capability jumps are detected
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/bot-capability-profiler
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
var LruTracker = _shared.LruTracker;

// ── Constants ───────────────────────────────────────────────────────

/** 8 capability dimensions measured for each bot */
var CAPABILITY_DIMENSIONS = [
  "OCR_ACCURACY",          // Optical character recognition in animated frames
  "MOTION_TRACKING",       // Ability to follow moving objects
  "TEMPORAL_REASONING",    // Understanding frame sequences and timing
  "SPATIAL_REASONING",     // Puzzle-like spatial arrangement challenges
  "COLOR_DISCRIMINATION",  // Subtle color/gradient-based challenges
  "PATTERN_RECOGNITION",   // Identifying visual patterns across frames
  "SEMANTIC_UNDERSTANDING",// Comprehending scene meaning
  "ADVERSARIAL_RESISTANCE" // Handling intentional noise/distortion
];

/** Sophistication tiers (lowest to highest) */
var SOPHISTICATION_TIERS = ["SCRIPT_KIDDIE", "BASIC_BOT", "INTERMEDIATE", "ADVANCED", "ELITE"];

/** Challenge vulnerability levels */
var VULNERABILITY_LEVELS = ["IMMUNE", "RESISTANT", "MODERATE", "VULNERABLE", "DEFEATED"];

var DEFAULT_OPTIONS = {
  maxBots: 2000,
  maxChallengeTypes: 200,
  profileWindowMs: 604800000,     // 7 days
  learningDetectionMs: 86400000,  // 24 hours
  minAttemptsForProfile: 5,
  capabilityDecayMs: 259200000,   // 3 days half-life
  evolutionCheckMs: 3600000,      // 1 hour
  jumpThreshold: 0.25,            // 25% capability jump triggers alert
  maxAttemptsPerBot: 1000
};

// ── Factory ─────────────────────────────────────────────────────────

/**
 * Create a Bot Capability Profiler instance.
 *
 * @param {object} [options]
 * @param {number} [options.maxBots=2000]              Max tracked bot profiles
 * @param {number} [options.maxChallengeTypes=200]     Max challenge type profiles
 * @param {number} [options.profileWindowMs=604800000] Window for profile data (7d)
 * @param {number} [options.learningDetectionMs=86400000] Window for learning rate (24h)
 * @param {number} [options.minAttemptsForProfile=5]   Min attempts before profiling
 * @param {number} [options.capabilityDecayMs=259200000] Capability half-life (3d)
 * @param {number} [options.evolutionCheckMs=3600000]  Min interval between evolution checks
 * @param {number} [options.jumpThreshold=0.25]        Capability jump alert threshold
 * @param {number} [options.maxAttemptsPerBot=1000]    Max stored attempts per bot
 * @returns {object} BotCapabilityProfiler instance
 */
function createBotCapabilityProfiler(options) {
  options = options || {};

  var maxBots = _posOpt(options.maxBots, DEFAULT_OPTIONS.maxBots);
  var maxChallengeTypes = _posOpt(options.maxChallengeTypes, DEFAULT_OPTIONS.maxChallengeTypes);
  var profileWindowMs = _posOpt(options.profileWindowMs, DEFAULT_OPTIONS.profileWindowMs);
  var learningDetectionMs = _posOpt(options.learningDetectionMs, DEFAULT_OPTIONS.learningDetectionMs);
  var minAttemptsForProfile = _posOpt(options.minAttemptsForProfile, DEFAULT_OPTIONS.minAttemptsForProfile);
  var capabilityDecayMs = _posOpt(options.capabilityDecayMs, DEFAULT_OPTIONS.capabilityDecayMs);
  var evolutionCheckMs = _posOpt(options.evolutionCheckMs, DEFAULT_OPTIONS.evolutionCheckMs);
  var jumpThreshold = options.jumpThreshold != null && options.jumpThreshold > 0
    ? options.jumpThreshold : DEFAULT_OPTIONS.jumpThreshold;
  var maxAttemptsPerBot = _posOpt(options.maxAttemptsPerBot, DEFAULT_OPTIONS.maxAttemptsPerBot);

  // ── State ───────────────────────────────────────────────────────

  /** @type {Object<string, BotProfile>} */
  var _bots = Object.create(null);
  var _botLru = new LruTracker();

  /** @type {Object<string, ChallengeTypeProfile>} */
  var _challengeTypes = Object.create(null);
  var _challengeLru = new LruTracker();

  /** @type {Array<EvolutionEvent>} */
  var _evolutionEvents = [];

  /** @type {Array<ThreatAlert>} */
  var _alerts = [];

  var _lastEvolutionCheck = 0;

  // ── Internal Structures ─────────────────────────────────────────

  function _createBotProfile(botId) {
    var caps = {};
    for (var i = 0; i < CAPABILITY_DIMENSIONS.length; i++) {
      caps[CAPABILITY_DIMENSIONS[i]] = { score: 0, samples: 0, trend: 0 };
    }
    return {
      id: botId,
      capabilities: caps,
      tier: SOPHISTICATION_TIERS[0],
      tierScore: 0,
      attempts: [],
      firstSeen: _now(),
      lastSeen: _now(),
      learningRate: 0,
      plateauDetected: false,
      totalAttempts: 0,
      totalSolves: 0
    };
  }

  function _createChallengeTypeProfile(typeId) {
    return {
      id: typeId,
      dimensions: [],       // which CAPABILITY_DIMENSIONS this challenge tests
      difficulty: 0.5,
      totalAttempts: 0,
      botSolveRate: 0,
      humanSolveRate: 0,
      vulnerabilityByTier: {}
    };
  }

  // ── Bot Profile Management ──────────────────────────────────────

  function _getBot(botId) {
    if (!_bots[botId]) {
      if (_botLru.length >= maxBots) {
        var evicted = _botLru.evictOldest();
        if (evicted) delete _bots[evicted];
      }
      _bots[botId] = _createBotProfile(botId);
      _botLru.push(botId);
    } else {
      _botLru.touch(botId);
    }
    return _bots[botId];
  }

  function _getChallengeType(typeId) {
    if (!_challengeTypes[typeId]) {
      if (_challengeLru.length >= maxChallengeTypes) {
        var evicted = _challengeLru.evictOldest();
        if (evicted) delete _challengeTypes[evicted];
      }
      _challengeTypes[typeId] = _createChallengeTypeProfile(typeId);
      _challengeLru.push(typeId);
    } else {
      _challengeLru.touch(typeId);
    }
    return _challengeTypes[typeId];
  }

  // ── Capability Computation ──────────────────────────────────────

  /**
   * Map a challenge attempt to capability dimension scores.
   * Each challenge type tests certain dimensions; success/failure updates those.
   */
  function _mapAttemptToDimensions(attempt) {
    var dims = attempt.dimensions || [];
    if (dims.length === 0) {
      // Infer dimensions from challenge features if not explicit
      dims = _inferDimensions(attempt);
    }
    return dims;
  }

  function _inferDimensions(attempt) {
    var dims = [];
    var features = attempt.features || {};
    if (features.hasText) dims.push("OCR_ACCURACY");
    if (features.hasMotion) dims.push("MOTION_TRACKING");
    if (features.isSequential) dims.push("TEMPORAL_REASONING");
    if (features.isSpatial) dims.push("SPATIAL_REASONING");
    if (features.hasColorTest) dims.push("COLOR_DISCRIMINATION");
    if (features.hasPattern) dims.push("PATTERN_RECOGNITION");
    if (features.requiresMeaning) dims.push("SEMANTIC_UNDERSTANDING");
    if (features.hasNoise) dims.push("ADVERSARIAL_RESISTANCE");
    // Default: at least pattern recognition
    if (dims.length === 0) dims.push("PATTERN_RECOGNITION");
    return dims;
  }

  /**
   * Update capability scores for a bot based on an attempt result.
   * Uses exponential moving average weighted by recency.
   */
  function _updateCapabilities(bot, attempt) {
    var dims = _mapAttemptToDimensions(attempt);
    var solved = attempt.solved ? 1 : 0;
    var difficulty = _clamp(attempt.difficulty || 0.5, 0, 1);
    // Weighted score: solving harder challenges = higher capability evidence
    var evidence = solved ? (0.5 + 0.5 * difficulty) : (0.3 * (1 - difficulty));

    for (var i = 0; i < dims.length; i++) {
      var dim = dims[i];
      var cap = bot.capabilities[dim];
      if (!cap) continue;
      cap.samples++;
      var alpha = Math.min(0.3, 2.0 / (cap.samples + 1));
      cap.score = cap.score * (1 - alpha) + evidence * alpha;
      cap.score = _clamp(cap.score, 0, 1);
    }
  }

  /**
   * Compute the composite tier score (0-100) from capability dimensions.
   */
  function _computeTierScore(bot) {
    var total = 0;
    var count = 0;
    for (var i = 0; i < CAPABILITY_DIMENSIONS.length; i++) {
      var cap = bot.capabilities[CAPABILITY_DIMENSIONS[i]];
      if (cap.samples > 0) {
        total += cap.score;
        count++;
      }
    }
    if (count === 0) return 0;
    return Math.round((total / count) * 100);
  }

  /**
   * Assign sophistication tier based on tier score.
   */
  function _assignTier(score) {
    if (score >= 80) return SOPHISTICATION_TIERS[4]; // ELITE
    if (score >= 60) return SOPHISTICATION_TIERS[3]; // ADVANCED
    if (score >= 40) return SOPHISTICATION_TIERS[2]; // INTERMEDIATE
    if (score >= 20) return SOPHISTICATION_TIERS[1]; // BASIC_BOT
    return SOPHISTICATION_TIERS[0]; // SCRIPT_KIDDIE
  }

  // ── Learning Rate Detection ─────────────────────────────────────

  /**
   * Detect if a bot is getting better over time (learning).
   * Uses linear regression on solve rate within a sliding window.
   */
  function _computeLearningRate(bot) {
    var now = _now();
    var windowStart = now - learningDetectionMs;
    var windowAttempts = [];
    for (var i = 0; i < bot.attempts.length; i++) {
      if (bot.attempts[i].ts >= windowStart) {
        windowAttempts.push(bot.attempts[i]);
      }
    }
    if (windowAttempts.length < 6) return 0;

    // Compute rolling solve rate in buckets of ~10 attempts
    var bucketSize = Math.max(3, Math.floor(windowAttempts.length / 5));
    var xs = [];
    var ys = [];
    for (var b = 0; b + bucketSize <= windowAttempts.length; b += Math.max(1, Math.floor(bucketSize / 2))) {
      var solves = 0;
      for (var j = b; j < b + bucketSize; j++) {
        if (windowAttempts[j].solved) solves++;
      }
      xs.push(b);
      ys.push(solves / bucketSize);
    }
    if (xs.length < 3) return 0;
    var reg = _linearRegression(xs, ys);
    return reg.slope;
  }

  /**
   * Detect if bot has plateaued (stable solve rate, no improvement).
   */
  function _detectPlateau(bot) {
    if (bot.attempts.length < 20) return false;
    var recent = bot.attempts.slice(-20);
    var firstHalf = recent.slice(0, 10);
    var secondHalf = recent.slice(10);
    var rate1 = 0, rate2 = 0;
    for (var i = 0; i < 10; i++) {
      if (firstHalf[i].solved) rate1++;
      if (secondHalf[i].solved) rate2++;
    }
    rate1 /= 10;
    rate2 /= 10;
    return Math.abs(rate2 - rate1) < 0.05;
  }

  // ── Evolution Tracking ──────────────────────────────────────────

  function _checkEvolution() {
    var now = _now();
    if (now - _lastEvolutionCheck < evolutionCheckMs) return;
    _lastEvolutionCheck = now;

    var botIds = Object.keys(_bots);
    for (var i = 0; i < botIds.length; i++) {
      var bot = _bots[botIds[i]];
      if (!bot || bot.attempts.length < minAttemptsForProfile) continue;

      var oldTierScore = bot.tierScore;
      var newTierScore = _computeTierScore(bot);
      var jump = (newTierScore - oldTierScore) / 100;

      if (jump >= jumpThreshold) {
        var evt = {
          botId: bot.id,
          ts: now,
          oldTier: bot.tier,
          oldScore: oldTierScore,
          newScore: newTierScore,
          newTier: _assignTier(newTierScore),
          jump: jump
        };
        _evolutionEvents.push(evt);
        if (_evolutionEvents.length > 500) _evolutionEvents.shift();

        _alerts.push({
          type: "CAPABILITY_JUMP",
          botId: bot.id,
          ts: now,
          message: "Bot " + bot.id + " capability jumped from " + oldTierScore + " to " + newTierScore,
          severity: jump >= 0.5 ? "CRITICAL" : "HIGH"
        });
        if (_alerts.length > 200) _alerts.shift();
      }

      bot.tierScore = newTierScore;
      bot.tier = _assignTier(newTierScore);
    }
  }

  // ── Vulnerability Prediction ────────────────────────────────────

  /**
   * Predict how vulnerable a challenge type is to a specific bot tier.
   * Returns vulnerability level and confidence.
   */
  function _predictVulnerability(challengeType, tier) {
    var tierIndex = SOPHISTICATION_TIERS.indexOf(tier);
    if (tierIndex < 0) return { level: "MODERATE", confidence: 0 };

    var ct = _challengeTypes[challengeType];
    if (!ct) return { level: "MODERATE", confidence: 0 };

    // Look at historical solve rates for this tier against this challenge type
    var tierData = ct.vulnerabilityByTier[tier];
    if (!tierData || tierData.attempts < 3) {
      // Estimate from difficulty and tier capabilities
      var estimated = _estimateVulnerabilityFromDifficulty(ct.difficulty, tierIndex);
      return { level: estimated, confidence: 0.3 };
    }

    var solveRate = tierData.solves / tierData.attempts;
    var level;
    if (solveRate >= 0.8) level = "DEFEATED";
    else if (solveRate >= 0.6) level = "VULNERABLE";
    else if (solveRate >= 0.35) level = "MODERATE";
    else if (solveRate >= 0.15) level = "RESISTANT";
    else level = "IMMUNE";

    var confidence = Math.min(1, tierData.attempts / 20);
    return { level: level, confidence: confidence };
  }

  function _estimateVulnerabilityFromDifficulty(difficulty, tierIndex) {
    var effectiveStrength = (tierIndex + 1) / SOPHISTICATION_TIERS.length;
    var gap = effectiveStrength - difficulty;
    if (gap > 0.3) return "DEFEATED";
    if (gap > 0.1) return "VULNERABLE";
    if (gap > -0.1) return "MODERATE";
    if (gap > -0.3) return "RESISTANT";
    return "IMMUNE";
  }

  // ── Defense Recommendations ─────────────────────────────────────

  /**
   * Generate defense recommendations: which challenge types to prioritize
   * given the current bot population and their capabilities.
   */
  function _generateDefenseRecommendations() {
    var botIds = Object.keys(_bots);
    var tierDistribution = {};
    for (var t = 0; t < SOPHISTICATION_TIERS.length; t++) {
      tierDistribution[SOPHISTICATION_TIERS[t]] = 0;
    }

    var activeBots = 0;
    var now = _now();
    for (var i = 0; i < botIds.length; i++) {
      var bot = _bots[botIds[i]];
      if (now - bot.lastSeen < profileWindowMs) {
        tierDistribution[bot.tier]++;
        activeBots++;
      }
    }

    // Find weakest capability dimensions across the bot population
    var dimWeakness = {};
    for (var d = 0; d < CAPABILITY_DIMENSIONS.length; d++) {
      dimWeakness[CAPABILITY_DIMENSIONS[d]] = { totalScore: 0, count: 0 };
    }
    for (var j = 0; j < botIds.length; j++) {
      var b = _bots[botIds[j]];
      if (now - b.lastSeen >= profileWindowMs) continue;
      for (var k = 0; k < CAPABILITY_DIMENSIONS.length; k++) {
        var dim = CAPABILITY_DIMENSIONS[k];
        if (b.capabilities[dim].samples > 0) {
          dimWeakness[dim].totalScore += b.capabilities[dim].score;
          dimWeakness[dim].count++;
        }
      }
    }

    var recommendations = [];
    for (var dd = 0; dd < CAPABILITY_DIMENSIONS.length; dd++) {
      var dName = CAPABILITY_DIMENSIONS[dd];
      var info = dimWeakness[dName];
      if (info.count === 0) continue;
      var avgScore = info.totalScore / info.count;
      recommendations.push({
        dimension: dName,
        botAvgCapability: Math.round(avgScore * 100) / 100,
        effectiveness: Math.round((1 - avgScore) * 100),
        recommendation: avgScore < 0.3
          ? "HIGHLY_EFFECTIVE — prioritize challenges testing " + dName
          : avgScore < 0.6
            ? "MODERATELY_EFFECTIVE — useful in challenge mix"
            : "LOW_EFFECTIVENESS — bots handle this well, diversify"
      });
    }
    recommendations.sort(function (a, b) { return a.botAvgCapability - b.botAvgCapability; });

    return {
      activeBots: activeBots,
      tierDistribution: tierDistribution,
      dimensionEffectiveness: recommendations,
      topRecommendation: recommendations.length > 0
        ? "Focus on " + recommendations[0].dimension + " challenges (bots weakest here at " + recommendations[0].botAvgCapability + ")"
        : "Insufficient data for recommendations"
    };
  }

  // ── Attempt Pruning ─────────────────────────────────────────────

  function _pruneAttempts(bot) {
    var now = _now();
    if (bot.attempts.length > maxAttemptsPerBot) {
      bot.attempts = bot.attempts.slice(-Math.floor(maxAttemptsPerBot * 0.8));
    }
    // Remove old attempts outside profile window
    var cutoff = now - profileWindowMs;
    while (bot.attempts.length > 0 && bot.attempts[0].ts < cutoff) {
      bot.attempts.shift();
    }
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Record a solve attempt for a bot.
   *
   * @param {object} attempt
   * @param {string} attempt.botId         - Unique bot identifier
   * @param {string} attempt.challengeType - Challenge type identifier
   * @param {boolean} attempt.solved       - Whether the bot solved it
   * @param {number} [attempt.difficulty]   - Challenge difficulty 0-1
   * @param {number} [attempt.solveTimeMs]  - Time taken to solve
   * @param {string[]} [attempt.dimensions] - Which capability dimensions tested
   * @param {object} [attempt.features]     - Challenge features for dimension inference
   * @returns {object} Updated bot profile summary
   */
  function recordAttempt(attempt) {
    if (!attempt || !attempt.botId || !attempt.challengeType) {
      return { error: "botId and challengeType required" };
    }

    var bot = _getBot(attempt.botId);
    var now = _now();
    bot.lastSeen = now;
    bot.totalAttempts++;
    if (attempt.solved) bot.totalSolves++;

    var record = {
      ts: now,
      type: attempt.challengeType,
      solved: !!attempt.solved,
      difficulty: _clamp(attempt.difficulty || 0.5, 0, 1),
      solveTimeMs: _nnOpt(attempt.solveTimeMs, 0),
      dimensions: attempt.dimensions || null,
      features: attempt.features || null
    };
    bot.attempts.push(record);
    _pruneAttempts(bot);

    // Update capability scores
    _updateCapabilities(bot, record);

    // Update challenge type profile
    var ct = _getChallengeType(attempt.challengeType);
    ct.totalAttempts++;
    if (record.dimensions || record.features) {
      ct.dimensions = _mapAttemptToDimensions(record);
    }
    ct.difficulty = _clamp(attempt.difficulty || ct.difficulty, 0, 1);
    ct.botSolveRate = ct.botSolveRate * 0.95 + (attempt.solved ? 0.05 : 0);

    // Update vulnerability by tier
    if (!ct.vulnerabilityByTier[bot.tier]) {
      ct.vulnerabilityByTier[bot.tier] = { attempts: 0, solves: 0 };
    }
    ct.vulnerabilityByTier[bot.tier].attempts++;
    if (attempt.solved) ct.vulnerabilityByTier[bot.tier].solves++;

    // Recompute bot tier
    bot.tierScore = _computeTierScore(bot);
    bot.tier = _assignTier(bot.tierScore);
    bot.learningRate = _computeLearningRate(bot);
    bot.plateauDetected = _detectPlateau(bot);

    // Check for evolution events
    _checkEvolution();

    return {
      botId: bot.id,
      tier: bot.tier,
      tierScore: bot.tierScore,
      learningRate: Math.round(bot.learningRate * 1000) / 1000,
      plateauDetected: bot.plateauDetected,
      totalAttempts: bot.totalAttempts,
      solveRate: bot.totalAttempts > 0
        ? Math.round((bot.totalSolves / bot.totalAttempts) * 100) / 100 : 0
    };
  }

  /**
   * Get the full capability profile for a bot.
   *
   * @param {string} botId
   * @returns {object|null} Full profile or null if not found
   */
  function getProfile(botId) {
    var bot = _bots[botId];
    if (!bot) return null;

    var capabilities = {};
    for (var i = 0; i < CAPABILITY_DIMENSIONS.length; i++) {
      var dim = CAPABILITY_DIMENSIONS[i];
      var cap = bot.capabilities[dim];
      capabilities[dim] = {
        score: Math.round(cap.score * 100) / 100,
        samples: cap.samples,
        rating: cap.score >= 0.8 ? "EXPERT" :
                cap.score >= 0.6 ? "PROFICIENT" :
                cap.score >= 0.4 ? "INTERMEDIATE" :
                cap.score >= 0.2 ? "NOVICE" : "MINIMAL"
      };
    }

    var strengths = [];
    var weaknesses = [];
    for (var j = 0; j < CAPABILITY_DIMENSIONS.length; j++) {
      var d = CAPABILITY_DIMENSIONS[j];
      var c = bot.capabilities[d];
      if (c.samples >= 3) {
        if (c.score >= 0.7) strengths.push(d);
        if (c.score <= 0.3) weaknesses.push(d);
      }
    }

    return {
      id: bot.id,
      tier: bot.tier,
      tierScore: bot.tierScore,
      capabilities: capabilities,
      strengths: strengths,
      weaknesses: weaknesses,
      learningRate: Math.round(bot.learningRate * 1000) / 1000,
      plateauDetected: bot.plateauDetected,
      totalAttempts: bot.totalAttempts,
      totalSolves: bot.totalSolves,
      solveRate: bot.totalAttempts > 0
        ? Math.round((bot.totalSolves / bot.totalAttempts) * 100) / 100 : 0,
      firstSeen: bot.firstSeen,
      lastSeen: bot.lastSeen,
      activeAttempts: bot.attempts.length
    };
  }

  /**
   * Predict vulnerability of a challenge type against a bot tier.
   *
   * @param {string} challengeType
   * @param {string} [tier] - Specific tier or "ALL" for all tiers
   * @returns {object} Vulnerability assessment
   */
  function predictVulnerability(challengeType, tier) {
    if (tier && tier !== "ALL") {
      return _predictVulnerability(challengeType, tier);
    }

    var results = {};
    for (var i = 0; i < SOPHISTICATION_TIERS.length; i++) {
      results[SOPHISTICATION_TIERS[i]] = _predictVulnerability(challengeType, SOPHISTICATION_TIERS[i]);
    }
    return {
      challengeType: challengeType,
      vulnerabilityByTier: results,
      overallRisk: _computeOverallRisk(results)
    };
  }

  function _computeOverallRisk(tierResults) {
    var maxRisk = 0;
    var levels = { "IMMUNE": 0, "RESISTANT": 0.25, "MODERATE": 0.5, "VULNERABLE": 0.75, "DEFEATED": 1 };
    var tiers = Object.keys(tierResults);
    for (var i = 0; i < tiers.length; i++) {
      var riskVal = levels[tierResults[tiers[i]].level] || 0;
      if (riskVal > maxRisk) maxRisk = riskVal;
    }
    if (maxRisk >= 0.9) return "CRITICAL";
    if (maxRisk >= 0.7) return "HIGH";
    if (maxRisk >= 0.4) return "MODERATE";
    if (maxRisk >= 0.2) return "LOW";
    return "MINIMAL";
  }

  /**
   * Get defense recommendations based on current bot population analysis.
   *
   * @returns {object} Recommendations object
   */
  function getDefenseRecommendations() {
    return _generateDefenseRecommendations();
  }

  /**
   * Get the tier distribution of tracked bots.
   *
   * @returns {object} Distribution counts and percentages
   */
  function getTierDistribution() {
    var dist = {};
    var total = 0;
    for (var t = 0; t < SOPHISTICATION_TIERS.length; t++) {
      dist[SOPHISTICATION_TIERS[t]] = 0;
    }
    var botIds = Object.keys(_bots);
    for (var i = 0; i < botIds.length; i++) {
      dist[_bots[botIds[i]].tier]++;
      total++;
    }
    var pct = {};
    for (var p = 0; p < SOPHISTICATION_TIERS.length; p++) {
      var tier = SOPHISTICATION_TIERS[p];
      pct[tier] = total > 0 ? Math.round((dist[tier] / total) * 100) : 0;
    }
    return { counts: dist, percentages: pct, total: total };
  }

  /**
   * Get recent evolution events (capability jumps).
   *
   * @param {number} [limit=20]
   * @returns {Array} Recent evolution events
   */
  function getEvolutionEvents(limit) {
    var n = _posOpt(limit, 20);
    return _evolutionEvents.slice(-n);
  }

  /**
   * Get active threat alerts.
   *
   * @param {number} [limit=20]
   * @returns {Array} Recent alerts
   */
  function getAlerts(limit) {
    var n = _posOpt(limit, 20);
    return _alerts.slice(-n);
  }

  /**
   * Compare two bots' capability profiles.
   *
   * @param {string} botId1
   * @param {string} botId2
   * @returns {object|null} Comparison or null if either bot not found
   */
  function compareBots(botId1, botId2) {
    var b1 = _bots[botId1];
    var b2 = _bots[botId2];
    if (!b1 || !b2) return null;

    var comparison = {};
    for (var i = 0; i < CAPABILITY_DIMENSIONS.length; i++) {
      var dim = CAPABILITY_DIMENSIONS[i];
      comparison[dim] = {
        bot1: Math.round(b1.capabilities[dim].score * 100) / 100,
        bot2: Math.round(b2.capabilities[dim].score * 100) / 100,
        advantage: b1.capabilities[dim].score > b2.capabilities[dim].score ? botId1 :
                   b2.capabilities[dim].score > b1.capabilities[dim].score ? botId2 : "TIED"
      };
    }

    return {
      bot1: { id: botId1, tier: b1.tier, tierScore: b1.tierScore },
      bot2: { id: botId2, tier: b2.tier, tierScore: b2.tierScore },
      dimensionComparison: comparison,
      overallAdvantage: b1.tierScore > b2.tierScore ? botId1 :
                        b2.tierScore > b1.tierScore ? botId2 : "TIED"
    };
  }

  /**
   * Get aggregate statistics across all tracked bots.
   *
   * @returns {object} Aggregate stats
   */
  function getStats() {
    var botIds = Object.keys(_bots);
    var totalAttempts = 0;
    var totalSolves = 0;
    var learningBots = 0;
    var plateauedBots = 0;

    for (var i = 0; i < botIds.length; i++) {
      var bot = _bots[botIds[i]];
      totalAttempts += bot.totalAttempts;
      totalSolves += bot.totalSolves;
      if (bot.learningRate > 0.01) learningBots++;
      if (bot.plateauDetected) plateauedBots++;
    }

    return {
      trackedBots: botIds.length,
      trackedChallengeTypes: Object.keys(_challengeTypes).length,
      totalAttempts: totalAttempts,
      totalSolves: totalSolves,
      overallSolveRate: totalAttempts > 0
        ? Math.round((totalSolves / totalAttempts) * 100) / 100 : 0,
      learningBots: learningBots,
      plateauedBots: plateauedBots,
      evolutionEvents: _evolutionEvents.length,
      activeAlerts: _alerts.length,
      tierDistribution: getTierDistribution()
    };
  }

  /**
   * Export full state for persistence.
   *
   * @returns {object} Serialized state
   */
  function exportState() {
    return {
      version: 1,
      exportedAt: _now(),
      bots: _bots,
      challengeTypes: _challengeTypes,
      evolutionEvents: _evolutionEvents,
      alerts: _alerts,
      lastEvolutionCheck: _lastEvolutionCheck
    };
  }

  /**
   * Import previously exported state.
   *
   * @param {object} state - Previously exported state
   * @returns {boolean} Success
   */
  function importState(state) {
    if (!state || state.version !== 1) return false;

    _bots = state.bots || Object.create(null);
    _challengeTypes = state.challengeTypes || Object.create(null);
    _evolutionEvents = state.evolutionEvents || [];
    _alerts = state.alerts || [];
    _lastEvolutionCheck = state.lastEvolutionCheck || 0;

    // Rebuild LRU trackers
    _botLru = new LruTracker();
    var botIds = Object.keys(_bots);
    for (var i = 0; i < botIds.length; i++) _botLru.push(botIds[i]);

    _challengeLru = new LruTracker();
    var ctIds = Object.keys(_challengeTypes);
    for (var j = 0; j < ctIds.length; j++) _challengeLru.push(ctIds[j]);

    return true;
  }

  /**
   * Reset all state.
   */
  function reset() {
    _bots = Object.create(null);
    _botLru = new LruTracker();
    _challengeTypes = Object.create(null);
    _challengeLru = new LruTracker();
    _evolutionEvents = [];
    _alerts = [];
    _lastEvolutionCheck = 0;
  }

  // ── Return Public Interface ─────────────────────────────────────

  return {
    recordAttempt: recordAttempt,
    getProfile: getProfile,
    predictVulnerability: predictVulnerability,
    getDefenseRecommendations: getDefenseRecommendations,
    getTierDistribution: getTierDistribution,
    getEvolutionEvents: getEvolutionEvents,
    getAlerts: getAlerts,
    compareBots: compareBots,
    getStats: getStats,
    exportState: exportState,
    importState: importState,
    reset: reset,
    CAPABILITY_DIMENSIONS: CAPABILITY_DIMENSIONS,
    SOPHISTICATION_TIERS: SOPHISTICATION_TIERS,
    VULNERABILITY_LEVELS: VULNERABILITY_LEVELS
  };
}

module.exports = { createBotCapabilityProfiler: createBotCapabilityProfiler };
