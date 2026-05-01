/**
 * BotAttributionEngine — Autonomous operator/campaign attribution engine.
 *
 * Attributes bot activity to specific operators and campaigns by analyzing
 * toolchain fingerprints, infrastructure patterns, and operational signatures.
 * While fraud-ring-detector.js finds human CAPTCHA farms and
 * bot-collective-intel.js detects swarm coordination, this engine focuses on
 * identifying the *operator behind the bots* — linking separate bot instances
 * across time to the same campaign or threat actor.
 *
 * Key capabilities:
 *   - Build 8-dimensional fingerprint vectors from bot activity
 *   - Attribute bots to operators via cosine similarity matching
 *   - Detect coordinated campaigns (multi-bot operations with shared goals)
 *   - Generate operator threat assessments with escalation recommendations
 *   - Track operator timelines and campaign lifecycle phases
 *   - Merge operator profiles when identified as the same actor
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/bot-attribution-engine
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _clamp = _shared._clamp;
var _posOpt = _shared._posOpt;
var _nnOpt = _shared._nnOpt;
var _cosineSimilarity = _shared._cosineSimilarity;
var _linearRegression = _shared._linearRegression;
var LruTracker = _shared.LruTracker;

// ── Constants ───────────────────────────────────────────────────────

/** 8 attribution dimensions for fingerprint vectors */
var ATTRIBUTION_DIMENSIONS = [
  "TOOLCHAIN_SIGNATURE",
  "INFRASTRUCTURE_PATTERN",
  "OPERATIONAL_CADENCE",
  "EVASION_STYLE",
  "TARGETING_STRATEGY",
  "RESOURCE_ALLOCATION",
  "EVOLUTION_TRAJECTORY",
  "ERROR_SIGNATURE"
];

/** Threat levels from lowest to highest */
var THREAT_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** Campaign lifecycle phases */
var CAMPAIGN_PHASES = ["PLANNING", "ACTIVE", "INTENSIFYING", "WINDING_DOWN", "DORMANT"];

/** Sophistication tiers for operators */
var SOPHISTICATION_TIERS = ["NOVICE", "COMPETENT", "SKILLED", "EXPERT", "ELITE"];

var DEFAULT_OPTIONS = {
  maxBots: 5000,
  maxOperators: 500,
  maxCampaigns: 200,
  fingerprintWindowMs: 604800000,       // 7 days
  attributionThresholdScore: 0.55,
  campaignDetectionWindowMs: 86400000,  // 24 hours
  operatorMergeThreshold: 0.80,
  maxEventsPerBot: 500,
  threatEscalationThreshold: 0.75
};

// ── Helpers ─────────────────────────────────────────────────────────

function _generateId(prefix) {
  var hex = "";
  for (var i = 0; i < 8; i++) {
    hex += Math.floor(Math.random() * 16).toString(16);
  }
  return (prefix || "id") + "_" + hex;
}

/**
 * Hash a string into a numeric value for fingerprint computation.
 * Simple djb2 variant.
 */
function _hashString(str) {
  if (!str) return 0;
  var h = 5381;
  for (var i = 0; i < str.length; i++) {
    h = ((h << 5) + h + str.charCodeAt(i)) & 0x7fffffff;
  }
  return h;
}

/**
 * Compute the centroid of an array of fingerprint vectors.
 */
function _centroid(vectors) {
  if (!vectors || vectors.length === 0) return null;
  var dims = ATTRIBUTION_DIMENSIONS.length;
  var result = [];
  var i, j;
  for (i = 0; i < dims; i++) {
    result[i] = 0;
  }
  for (j = 0; j < vectors.length; j++) {
    for (i = 0; i < dims; i++) {
      result[i] += (vectors[j][i] || 0);
    }
  }
  for (i = 0; i < dims; i++) {
    result[i] /= vectors.length;
  }
  return result;
}

// ── Factory ─────────────────────────────────────────────────────────

/**
 * Create a Bot Attribution Engine instance.
 *
 * @param {object} [options]
 * @param {number} [options.maxBots=5000]                Max tracked bot fingerprints
 * @param {number} [options.maxOperators=500]            Max tracked operators
 * @param {number} [options.maxCampaigns=200]            Max tracked campaigns
 * @param {number} [options.fingerprintWindowMs=604800000] Fingerprint data window (7d)
 * @param {number} [options.attributionThresholdScore=0.55] Min similarity for attribution
 * @param {number} [options.campaignDetectionWindowMs=86400000] Campaign activity window (24h)
 * @param {number} [options.operatorMergeThreshold=0.80] Similarity threshold for merge
 * @param {number} [options.maxEventsPerBot=500]         Max events stored per bot
 * @param {number} [options.threatEscalationThreshold=0.75] Threat score that triggers escalation
 * @returns {object} Bot Attribution Engine API
 */
function createBotAttributionEngine(options) {
  options = options || {};

  var maxBots = _posOpt(options.maxBots, DEFAULT_OPTIONS.maxBots);
  var maxOperators = _posOpt(options.maxOperators, DEFAULT_OPTIONS.maxOperators);
  var maxCampaigns = _posOpt(options.maxCampaigns, DEFAULT_OPTIONS.maxCampaigns);
  var fingerprintWindowMs = _posOpt(options.fingerprintWindowMs, DEFAULT_OPTIONS.fingerprintWindowMs);
  var attributionThresholdScore = options.attributionThresholdScore != null && options.attributionThresholdScore >= 0
    ? options.attributionThresholdScore : DEFAULT_OPTIONS.attributionThresholdScore;
  var campaignDetectionWindowMs = _posOpt(options.campaignDetectionWindowMs, DEFAULT_OPTIONS.campaignDetectionWindowMs);
  var operatorMergeThreshold = options.operatorMergeThreshold != null && options.operatorMergeThreshold >= 0
    ? options.operatorMergeThreshold : DEFAULT_OPTIONS.operatorMergeThreshold;
  var maxEventsPerBot = _posOpt(options.maxEventsPerBot, DEFAULT_OPTIONS.maxEventsPerBot);
  var threatEscalationThreshold = options.threatEscalationThreshold != null && options.threatEscalationThreshold >= 0
    ? options.threatEscalationThreshold : DEFAULT_OPTIONS.threatEscalationThreshold;

  // ── State ───────────────────────────────────────────────────────

  // botId -> { events: [], fingerprint: [], firstSeen, lastSeen, ips: {}, userAgents: {}, challengeTypes: {}, errorCodes: {}, successCount, failCount }
  var bots = Object.create(null);
  var botCount = 0;
  var botLru = new LruTracker();

  // operatorId -> { id, knownBots: [], campaigns: [], firstSeen, lastSeen, centroid: [], eventCount, threatLevel, sophisticationLevel }
  var operators = Object.create(null);
  var operatorCount = 0;

  // campaignId -> { id, operatorId, activeBots: [], targetedChallenges: [], startedAt, lastActivity, status, confidence }
  var campaigns = Object.create(null);
  var campaignCount = 0;

  // botId -> operatorId
  var botAssignments = Object.create(null);

  // operatorId -> [{ timestamp, event, details }]
  var operatorTimelines = Object.create(null);

  // ── Internal: Fingerprint Computation ─────────────────────────

  function _computeFingerprint(bot) {
    var fp = [];
    var now = _now();
    var windowStart = now - fingerprintWindowMs;

    // Filter events to window
    var events = [];
    var i;
    for (i = 0; i < bot.events.length; i++) {
      if (bot.events[i].timestamp >= windowStart) {
        events.push(bot.events[i]);
      }
    }
    if (events.length === 0) {
      for (i = 0; i < ATTRIBUTION_DIMENSIONS.length; i++) fp[i] = 0;
      return fp;
    }

    // 0: TOOLCHAIN_SIGNATURE — user agent diversity & hash patterns
    var uaKeys = Object.keys(bot.userAgents);
    var uaEntropy = uaKeys.length > 0 ? Math.min(uaKeys.length / 10, 1) : 0;
    var uaHashSum = 0;
    for (i = 0; i < uaKeys.length; i++) {
      uaHashSum += _hashString(uaKeys[i]);
    }
    fp[0] = _clamp((uaEntropy * 0.5) + ((uaHashSum % 1000) / 2000), 0, 1);

    // 1: INFRASTRUCTURE_PATTERN — IP diversity and range patterns
    var ipKeys = Object.keys(bot.ips);
    var ipDiversity = Math.min(ipKeys.length / 20, 1);
    var subnetSet = Object.create(null);
    for (i = 0; i < ipKeys.length; i++) {
      var parts = ipKeys[i].split(".");
      if (parts.length >= 3) {
        subnetSet[parts[0] + "." + parts[1] + "." + parts[2]] = true;
      }
    }
    var subnetCount = Object.keys(subnetSet).length;
    var subnetRatio = ipKeys.length > 0 ? subnetCount / ipKeys.length : 0;
    fp[1] = _clamp(ipDiversity * 0.6 + subnetRatio * 0.4, 0, 1);

    // 2: OPERATIONAL_CADENCE — timing regularity
    var intervals = [];
    for (i = 1; i < events.length; i++) {
      intervals.push(events[i].timestamp - events[i - 1].timestamp);
    }
    var cadenceRegularity = 0;
    if (intervals.length > 1) {
      var intMean = _mean(intervals);
      var intStd = _stddev(intervals);
      cadenceRegularity = intMean > 0 ? 1 - Math.min(intStd / intMean, 1) : 0;
    }
    // Hour distribution for timezone inference
    var hourBuckets = [];
    for (i = 0; i < 24; i++) hourBuckets[i] = 0;
    for (i = 0; i < events.length; i++) {
      var hour = new Date(events[i].timestamp).getUTCHours();
      hourBuckets[hour]++;
    }
    var maxHourCount = 0;
    for (i = 0; i < 24; i++) {
      if (hourBuckets[i] > maxHourCount) maxHourCount = hourBuckets[i];
    }
    var hourConcentration = events.length > 0 ? maxHourCount / events.length : 0;
    fp[2] = _clamp(cadenceRegularity * 0.6 + hourConcentration * 0.4, 0, 1);

    // 3: EVASION_STYLE — retry patterns after failure
    var retryCount = 0;
    var adaptiveCount = 0;
    for (i = 1; i < events.length; i++) {
      if (!events[i - 1].success && events[i].success) {
        retryCount++;
      }
      if (!events[i - 1].success && !events[i].success &&
          events[i].challengeType !== events[i - 1].challengeType) {
        adaptiveCount++;
      }
    }
    var totalPairs = Math.max(events.length - 1, 1);
    fp[3] = _clamp((retryCount / totalPairs) * 0.5 + (adaptiveCount / totalPairs) * 0.5, 0, 1);

    // 4: TARGETING_STRATEGY — challenge type focus
    var ctKeys = Object.keys(bot.challengeTypes);
    var ctTotal = 0;
    var ctMax = 0;
    for (i = 0; i < ctKeys.length; i++) {
      ctTotal += bot.challengeTypes[ctKeys[i]];
      if (bot.challengeTypes[ctKeys[i]] > ctMax) ctMax = bot.challengeTypes[ctKeys[i]];
    }
    var targetFocus = ctTotal > 0 ? ctMax / ctTotal : 0;
    var targetBreadth = Math.min(ctKeys.length / 10, 1);
    fp[4] = _clamp(targetFocus * 0.5 + targetBreadth * 0.5, 0, 1);

    // 5: RESOURCE_ALLOCATION — event density and burst patterns
    var windowSpan = events.length > 1
      ? events[events.length - 1].timestamp - events[0].timestamp
      : 1;
    var eventRate = windowSpan > 0 ? events.length / (windowSpan / 3600000) : 0;
    var burstWindows = 0;
    var burstSize = 60000; // 1-minute buckets
    var bucketMap = Object.create(null);
    for (i = 0; i < events.length; i++) {
      var bucket = Math.floor(events[i].timestamp / burstSize);
      bucketMap[bucket] = (bucketMap[bucket] || 0) + 1;
    }
    var bucketKeys = Object.keys(bucketMap);
    for (i = 0; i < bucketKeys.length; i++) {
      if (bucketMap[bucketKeys[i]] > 3) burstWindows++;
    }
    var burstRatio = bucketKeys.length > 0 ? burstWindows / bucketKeys.length : 0;
    fp[5] = _clamp(Math.min(eventRate / 100, 1) * 0.5 + burstRatio * 0.5, 0, 1);

    // 6: EVOLUTION_TRAJECTORY — capability change over time
    if (events.length >= 4) {
      var halfIdx = Math.floor(events.length / 2);
      var firstHalfSuccess = 0;
      var secondHalfSuccess = 0;
      for (i = 0; i < halfIdx; i++) {
        if (events[i].success) firstHalfSuccess++;
      }
      for (i = halfIdx; i < events.length; i++) {
        if (events[i].success) secondHalfSuccess++;
      }
      var firstRate = firstHalfSuccess / halfIdx;
      var secondRate = secondHalfSuccess / (events.length - halfIdx);
      fp[6] = _clamp(Math.abs(secondRate - firstRate) + (secondRate > firstRate ? 0.2 : 0), 0, 1);
    } else {
      fp[6] = 0;
    }

    // 7: ERROR_SIGNATURE — characteristic error patterns
    var errKeys = Object.keys(bot.errorCodes);
    var errDiversity = Math.min(errKeys.length / 8, 1);
    var errTotal = 0;
    var errMax = 0;
    for (i = 0; i < errKeys.length; i++) {
      errTotal += bot.errorCodes[errKeys[i]];
      if (bot.errorCodes[errKeys[i]] > errMax) errMax = bot.errorCodes[errKeys[i]];
    }
    var errDominance = errTotal > 0 ? errMax / errTotal : 0;
    fp[7] = _clamp(errDiversity * 0.4 + errDominance * 0.6, 0, 1);

    return fp;
  }

  function _findBestOperator(fingerprint) {
    var bestId = null;
    var bestSim = -1;
    var opKeys = Object.keys(operators);
    for (var i = 0; i < opKeys.length; i++) {
      var op = operators[opKeys[i]];
      if (op.centroid) {
        var sim = _cosineSimilarity(fingerprint, op.centroid);
        if (sim > bestSim) {
          bestSim = sim;
          bestId = opKeys[i];
        }
      }
    }
    if (bestSim >= attributionThresholdScore) {
      return { operatorId: bestId, confidence: bestSim };
    }
    return null;
  }

  function _createOperator(botId, fingerprint, timestamp) {
    if (operatorCount >= maxOperators) return null;
    var opId = _generateId("op");
    operators[opId] = {
      id: opId,
      knownBots: [botId],
      campaigns: [],
      firstSeen: timestamp,
      lastSeen: timestamp,
      centroid: fingerprint.slice(),
      eventCount: 1,
      threatLevel: "LOW",
      sophisticationLevel: "NOVICE"
    };
    operatorTimelines[opId] = [{ timestamp: timestamp, event: "OPERATOR_CREATED", details: { firstBot: botId } }];
    operatorCount++;
    return opId;
  }

  function _assignBotToOperator(botId, operatorId, fingerprint, timestamp) {
    var op = operators[operatorId];
    if (!op) return;
    if (botAssignments[botId] === operatorId) return;

    var oldOp = botAssignments[botId];
    if (oldOp && operators[oldOp]) {
      // Remove from old operator
      var oldBots = operators[oldOp].knownBots;
      var idx = -1;
      for (var k = 0; k < oldBots.length; k++) {
        if (oldBots[k] === botId) { idx = k; break; }
      }
      if (idx >= 0) oldBots.splice(idx, 1);
    }

    botAssignments[botId] = operatorId;
    var found = false;
    for (var j = 0; j < op.knownBots.length; j++) {
      if (op.knownBots[j] === botId) { found = true; break; }
    }
    if (!found) op.knownBots.push(botId);

    op.lastSeen = Math.max(op.lastSeen, timestamp);
    op.eventCount++;

    // Update centroid incrementally
    _updateCentroid(operatorId);

    // Update sophistication based on bot count
    _updateSophistication(operatorId);

    if (operatorTimelines[operatorId]) {
      operatorTimelines[operatorId].push({
        timestamp: timestamp,
        event: "BOT_ATTRIBUTED",
        details: { botId: botId }
      });
    }
  }

  function _updateCentroid(operatorId) {
    var op = operators[operatorId];
    if (!op) return;
    var vectors = [];
    for (var i = 0; i < op.knownBots.length; i++) {
      var b = bots[op.knownBots[i]];
      if (b && b.fingerprint) {
        vectors.push(b.fingerprint);
      }
    }
    var c = _centroid(vectors);
    if (c) op.centroid = c;
  }

  function _updateSophistication(operatorId) {
    var op = operators[operatorId];
    if (!op) return;
    var botNum = op.knownBots.length;
    var evtNum = op.eventCount;

    // Composite score based on scale and activity
    var scaleScore = Math.min(botNum / 20, 1);
    var activityScore = Math.min(evtNum / 100, 1);
    var composite = scaleScore * 0.5 + activityScore * 0.5;

    if (composite >= 0.8) op.sophisticationLevel = "ELITE";
    else if (composite >= 0.6) op.sophisticationLevel = "EXPERT";
    else if (composite >= 0.4) op.sophisticationLevel = "SKILLED";
    else if (composite >= 0.2) op.sophisticationLevel = "COMPETENT";
    else op.sophisticationLevel = "NOVICE";
  }

  function _evictOldestBot() {
    var evicted = botLru.evictOldest();
    if (evicted) {
      var opId = botAssignments[evicted];
      if (opId && operators[opId]) {
        var arr = operators[opId].knownBots;
        for (var i = 0; i < arr.length; i++) {
          if (arr[i] === evicted) { arr.splice(i, 1); break; }
        }
      }
      delete bots[evicted];
      delete botAssignments[evicted];
      botCount--;
    }
  }

  function _determineCampaignPhase(campaign) {
    var now = _now();
    var age = now - campaign.startedAt;
    var timeSinceActivity = now - campaign.lastActivity;

    if (timeSinceActivity > campaignDetectionWindowMs * 2) return "DORMANT";
    if (timeSinceActivity > campaignDetectionWindowMs) return "WINDING_DOWN";

    // Check if intensifying (growing bot count or recent burst)
    if (campaign.activeBots.length >= 5 && age < campaignDetectionWindowMs) return "INTENSIFYING";
    if (campaign.activeBots.length >= 3) return "ACTIVE";
    return "PLANNING";
  }

  // ── Public API ────────────────────────────────────────────────

  /**
   * Ingest a bot activity event.
   *
   * @param {object} event
   * @param {string} event.botId              Bot identifier
   * @param {number} [event.timestamp]        Event timestamp (defaults to now)
   * @param {string} [event.challengeType]    Challenge type attempted
   * @param {boolean} [event.success]         Whether the attempt succeeded
   * @param {number} [event.solveTimeMs]      Time taken to solve
   * @param {string} [event.ip]               IP address
   * @param {string} [event.userAgent]        User agent string
   * @param {string} [event.errorCode]        Error code if failed
   * @param {object} [event.metadata]         Additional metadata
   * @returns {{ botId: string, ingested: boolean }}
   */
  function ingestBotActivity(event) {
    if (!event || typeof event.botId !== "string" || !event.botId) {
      return { botId: null, ingested: false };
    }

    var botId = event.botId;
    var ts = typeof event.timestamp === "number" && event.timestamp > 0
      ? event.timestamp : _now();

    // Ensure bot exists
    if (!bots[botId]) {
      if (botCount >= maxBots) {
        _evictOldestBot();
      }
      bots[botId] = {
        events: [],
        fingerprint: null,
        firstSeen: ts,
        lastSeen: ts,
        ips: Object.create(null),
        userAgents: Object.create(null),
        challengeTypes: Object.create(null),
        errorCodes: Object.create(null),
        successCount: 0,
        failCount: 0
      };
      botCount++;
      botLru.push(botId);
    }

    var bot = bots[botId];
    botLru.touch(botId);

    // Evict oldest events
    if (bot.events.length >= maxEventsPerBot) {
      bot.events.splice(0, Math.floor(maxEventsPerBot * 0.2));
    }

    var record = {
      timestamp: ts,
      challengeType: event.challengeType || "unknown",
      success: !!event.success,
      solveTimeMs: typeof event.solveTimeMs === "number" ? event.solveTimeMs : 0,
      ip: event.ip || null,
      userAgent: event.userAgent || null,
      errorCode: event.errorCode || null
    };

    bot.events.push(record);
    bot.lastSeen = Math.max(bot.lastSeen, ts);

    if (record.ip) bot.ips[record.ip] = (bot.ips[record.ip] || 0) + 1;
    if (record.userAgent) bot.userAgents[record.userAgent] = (bot.userAgents[record.userAgent] || 0) + 1;
    if (record.challengeType) bot.challengeTypes[record.challengeType] = (bot.challengeTypes[record.challengeType] || 0) + 1;
    if (record.errorCode) bot.errorCodes[record.errorCode] = (bot.errorCodes[record.errorCode] || 0) + 1;

    if (record.success) bot.successCount++;
    else bot.failCount++;

    // Recompute fingerprint
    bot.fingerprint = _computeFingerprint(bot);

    return { botId: botId, ingested: true };
  }

  /**
   * Run attribution analysis on a bot.
   *
   * @param {string} botId
   * @returns {{ botId: string, operatorId: string|null, confidence: number, matchedDimensions: string[], fingerprint: number[] }|null}
   */
  function attributeBot(botId) {
    if (!bots[botId]) return null;

    var bot = bots[botId];
    var fp = bot.fingerprint || _computeFingerprint(bot);
    bot.fingerprint = fp;

    var ts = bot.lastSeen || _now();

    // Already assigned?
    if (botAssignments[botId] && operators[botAssignments[botId]]) {
      var existingOp = operators[botAssignments[botId]];
      var existingSim = _cosineSimilarity(fp, existingOp.centroid || fp);
      var matchedDims = _getMatchedDimensions(fp, existingOp.centroid || fp);
      return {
        botId: botId,
        operatorId: botAssignments[botId],
        confidence: _clamp(existingSim, 0, 1),
        matchedDimensions: matchedDims,
        fingerprint: fp.slice()
      };
    }

    // Find best matching operator
    var match = _findBestOperator(fp);
    if (match) {
      _assignBotToOperator(botId, match.operatorId, fp, ts);
      var dims = _getMatchedDimensions(fp, operators[match.operatorId].centroid);
      return {
        botId: botId,
        operatorId: match.operatorId,
        confidence: _clamp(match.confidence, 0, 1),
        matchedDimensions: dims,
        fingerprint: fp.slice()
      };
    }

    // Create new operator
    var newOpId = _createOperator(botId, fp, ts);
    if (newOpId) {
      botAssignments[botId] = newOpId;
      return {
        botId: botId,
        operatorId: newOpId,
        confidence: 1.0,
        matchedDimensions: ATTRIBUTION_DIMENSIONS.slice(),
        fingerprint: fp.slice()
      };
    }

    return {
      botId: botId,
      operatorId: null,
      confidence: 0,
      matchedDimensions: [],
      fingerprint: fp.slice()
    };
  }

  function _getMatchedDimensions(fp1, fp2) {
    var matched = [];
    var threshold = 0.1; // dimension considered matching if difference < threshold
    for (var i = 0; i < ATTRIBUTION_DIMENSIONS.length; i++) {
      var v1 = fp1[i] || 0;
      var v2 = fp2[i] || 0;
      if (Math.abs(v1 - v2) < threshold || (v1 > 0.01 && v2 > 0.01)) {
        matched.push(ATTRIBUTION_DIMENSIONS[i]);
      }
    }
    return matched;
  }

  /**
   * Get operator profile.
   *
   * @param {string} operatorId
   * @returns {object|null}
   */
  function identifyOperator(operatorId) {
    var op = operators[operatorId];
    if (!op) return null;

    // Compute infrastructure profile
    var allIps = Object.create(null);
    var allUAs = Object.create(null);
    var i, j, bot;
    for (i = 0; i < op.knownBots.length; i++) {
      bot = bots[op.knownBots[i]];
      if (!bot) continue;
      var ipKeys = Object.keys(bot.ips);
      for (j = 0; j < ipKeys.length; j++) {
        allIps[ipKeys[j]] = (allIps[ipKeys[j]] || 0) + bot.ips[ipKeys[j]];
      }
      var uaKeys = Object.keys(bot.userAgents);
      for (j = 0; j < uaKeys.length; j++) {
        allUAs[uaKeys[j]] = (allUAs[uaKeys[j]] || 0) + bot.userAgents[uaKeys[j]];
      }
    }

    return {
      operatorId: operatorId,
      knownBots: op.knownBots.slice(),
      campaigns: op.campaigns.slice(),
      firstSeen: op.firstSeen,
      lastSeen: op.lastSeen,
      sophisticationLevel: op.sophisticationLevel,
      infrastructureProfile: {
        uniqueIps: Object.keys(allIps).length,
        uniqueUserAgents: Object.keys(allUAs).length,
        topIps: _topN(allIps, 5),
        topUserAgents: _topN(allUAs, 3)
      },
      operationalPattern: {
        totalBots: op.knownBots.length,
        totalEvents: op.eventCount,
        activeDurationMs: op.lastSeen - op.firstSeen
      },
      threatLevel: op.threatLevel
    };
  }

  function _topN(map, n) {
    var entries = [];
    var keys = Object.keys(map);
    for (var i = 0; i < keys.length; i++) {
      entries.push({ key: keys[i], count: map[keys[i]] });
    }
    entries.sort(function (a, b) { return b.count - a.count; });
    return entries.slice(0, n);
  }

  /**
   * Detect active campaigns.
   *
   * @param {object} [opts]
   * @param {number} [opts.minBots=2]
   * @param {number} [opts.minConfidence=0.5]
   * @returns {Array<object>}
   */
  function detectCampaign(opts) {
    opts = opts || {};
    var minBots = _posOpt(opts.minBots, 2);
    var minConf = opts.minConfidence != null && opts.minConfidence >= 0
      ? opts.minConfidence : 0.5;

    var now = _now();
    var windowStart = now - campaignDetectionWindowMs;
    var detectedCampaigns = [];

    // For each operator, check if they have coordinated multi-bot activity
    var opKeys = Object.keys(operators);
    for (var i = 0; i < opKeys.length; i++) {
      var op = operators[opKeys[i]];
      if (op.knownBots.length < minBots) continue;

      // Find active bots in the window
      var activeBots = [];
      var targetedChallenges = Object.create(null);
      var latestActivity = 0;
      var earliestActivity = Infinity;

      for (var j = 0; j < op.knownBots.length; j++) {
        var bot = bots[op.knownBots[j]];
        if (!bot) continue;
        if (bot.lastSeen >= windowStart) {
          activeBots.push(op.knownBots[j]);
          if (bot.lastSeen > latestActivity) latestActivity = bot.lastSeen;
          if (bot.firstSeen < earliestActivity) earliestActivity = bot.firstSeen;
          var ctKeys = Object.keys(bot.challengeTypes);
          for (var k = 0; k < ctKeys.length; k++) {
            targetedChallenges[ctKeys[k]] = (targetedChallenges[ctKeys[k]] || 0) + bot.challengeTypes[ctKeys[k]];
          }
        }
      }

      if (activeBots.length < minBots) continue;

      // Confidence: based on fingerprint similarity among active bots
      var confidence = _computeCampaignConfidence(activeBots);
      if (confidence < minConf) continue;

      var campId = _generateId("camp");
      var camp = {
        campaignId: campId,
        operatorId: opKeys[i],
        activeBots: activeBots,
        targetedChallenges: Object.keys(targetedChallenges),
        startedAt: earliestActivity !== Infinity ? earliestActivity : now,
        lastActivity: latestActivity || now,
        status: "ACTIVE",
        confidence: Math.round(confidence * 1000) / 1000
      };

      camp.status = _determineCampaignPhase(camp);

      // Register campaign
      if (campaignCount < maxCampaigns) {
        campaigns[campId] = camp;
        campaignCount++;
        if (op.campaigns.indexOf(campId) < 0) {
          op.campaigns.push(campId);
        }
        if (operatorTimelines[opKeys[i]]) {
          operatorTimelines[opKeys[i]].push({
            timestamp: now,
            event: "CAMPAIGN_DETECTED",
            details: { campaignId: campId, activeBots: activeBots.length }
          });
        }
      }

      detectedCampaigns.push(camp);
    }

    return detectedCampaigns;
  }

  function _computeCampaignConfidence(botIds) {
    if (botIds.length < 2) return 0;
    var fps = [];
    for (var i = 0; i < botIds.length; i++) {
      var b = bots[botIds[i]];
      if (b && b.fingerprint) fps.push(b.fingerprint);
    }
    if (fps.length < 2) return 0;

    // Average pairwise cosine similarity
    var total = 0;
    var count = 0;
    for (var a = 0; a < fps.length - 1; a++) {
      for (var b2 = a + 1; b2 < fps.length; b2++) {
        total += _cosineSimilarity(fps[a], fps[b2]);
        count++;
      }
    }
    return count > 0 ? total / count : 0;
  }

  /**
   * Get operator activity timeline.
   *
   * @param {string} operatorId
   * @returns {Array<{timestamp: number, event: string, details: object}>|null}
   */
  function getOperatorTimeline(operatorId) {
    if (!operators[operatorId]) return null;
    var timeline = operatorTimelines[operatorId] || [];
    return timeline.slice().sort(function (a, b) { return a.timestamp - b.timestamp; });
  }

  /**
   * Perform autonomous threat assessment for an operator.
   *
   * @param {string} operatorId
   * @returns {object|null}
   */
  function assessThreatLevel(operatorId) {
    var op = operators[operatorId];
    if (!op) return null;

    var factors = [];

    // Factor 1: Scale (bot count)
    var scaleScore = _clamp(op.knownBots.length / 20, 0, 1);
    factors.push({ factor: "SCALE", weight: 0.25, score: scaleScore });

    // Factor 2: Persistence (duration)
    var durationMs = op.lastSeen - op.firstSeen;
    var persistScore = _clamp(durationMs / (7 * 86400000), 0, 1);
    factors.push({ factor: "PERSISTENCE", weight: 0.2, score: persistScore });

    // Factor 3: Success rate across bots
    var totalSuccess = 0;
    var totalAttempts = 0;
    for (var i = 0; i < op.knownBots.length; i++) {
      var bot = bots[op.knownBots[i]];
      if (bot) {
        totalSuccess += bot.successCount;
        totalAttempts += bot.successCount + bot.failCount;
      }
    }
    var successRate = totalAttempts > 0 ? totalSuccess / totalAttempts : 0;
    factors.push({ factor: "SUCCESS_RATE", weight: 0.2, score: successRate });

    // Factor 4: Evasion capability (from centroid)
    var evasionScore = op.centroid ? (op.centroid[3] || 0) : 0;
    factors.push({ factor: "EVASION", weight: 0.15, score: evasionScore });

    // Factor 5: Evolution (capability improvement)
    var evolutionScore = op.centroid ? (op.centroid[6] || 0) : 0;
    factors.push({ factor: "EVOLUTION", weight: 0.1, score: evolutionScore });

    // Factor 6: Campaign count
    var campScore = _clamp(op.campaigns.length / 5, 0, 1);
    factors.push({ factor: "CAMPAIGNS", weight: 0.1, score: campScore });

    // Compute weighted composite
    var composite = 0;
    for (var f = 0; f < factors.length; f++) {
      composite += factors[f].weight * factors[f].score;
    }
    composite = _clamp(composite, 0, 1);

    var threatLevel;
    if (composite >= 0.75) threatLevel = "CRITICAL";
    else if (composite >= 0.5) threatLevel = "HIGH";
    else if (composite >= 0.25) threatLevel = "MEDIUM";
    else threatLevel = "LOW";

    op.threatLevel = threatLevel;

    var recommendations = [];
    if (scaleScore > 0.5) recommendations.push("Deploy rate limiting on IPs associated with this operator");
    if (successRate > 0.6) recommendations.push("Increase challenge difficulty for targeted challenge types");
    if (evasionScore > 0.5) recommendations.push("Rotate challenge pool to invalidate learned evasion patterns");
    if (evolutionScore > 0.5) recommendations.push("Monitor for toolchain upgrades — operator is actively improving");
    if (composite >= threatEscalationThreshold) recommendations.push("ESCALATE: Threat score exceeds threshold — consider blocking operator infrastructure");

    var escalation = composite >= threatEscalationThreshold;

    if (operatorTimelines[operatorId]) {
      operatorTimelines[operatorId].push({
        timestamp: _now(),
        event: "THREAT_ASSESSED",
        details: { threatLevel: threatLevel, composite: Math.round(composite * 1000) / 1000, escalation: escalation }
      });
    }

    return {
      operatorId: operatorId,
      threatLevel: threatLevel,
      factors: factors,
      recommendations: recommendations,
      escalation: escalation
    };
  }

  /**
   * Merge two operator profiles.
   *
   * @param {string} operatorId1 - Operator to keep
   * @param {string} operatorId2 - Operator to merge into operatorId1
   * @returns {{ merged: boolean, resultOperatorId: string|null }}
   */
  function mergeOperators(operatorId1, operatorId2) {
    var op1 = operators[operatorId1];
    var op2 = operators[operatorId2];
    if (!op1 || !op2 || operatorId1 === operatorId2) {
      return { merged: false, resultOperatorId: null };
    }

    // Move all bots from op2 to op1
    for (var i = 0; i < op2.knownBots.length; i++) {
      var bid = op2.knownBots[i];
      botAssignments[bid] = operatorId1;
      var found = false;
      for (var j = 0; j < op1.knownBots.length; j++) {
        if (op1.knownBots[j] === bid) { found = true; break; }
      }
      if (!found) op1.knownBots.push(bid);
    }

    // Merge campaigns
    for (var c = 0; c < op2.campaigns.length; c++) {
      if (op1.campaigns.indexOf(op2.campaigns[c]) < 0) {
        op1.campaigns.push(op2.campaigns[c]);
      }
      if (campaigns[op2.campaigns[c]]) {
        campaigns[op2.campaigns[c]].operatorId = operatorId1;
      }
    }

    op1.firstSeen = Math.min(op1.firstSeen, op2.firstSeen);
    op1.lastSeen = Math.max(op1.lastSeen, op2.lastSeen);
    op1.eventCount += op2.eventCount;

    _updateCentroid(operatorId1);
    _updateSophistication(operatorId1);

    // Merge timelines
    var tl1 = operatorTimelines[operatorId1] || [];
    var tl2 = operatorTimelines[operatorId2] || [];
    tl1.push({ timestamp: _now(), event: "OPERATOR_MERGED", details: { mergedFrom: operatorId2 } });
    for (var t = 0; t < tl2.length; t++) {
      tl1.push(tl2[t]);
    }
    operatorTimelines[operatorId1] = tl1;

    // Remove op2
    delete operators[operatorId2];
    delete operatorTimelines[operatorId2];
    operatorCount--;

    return { merged: true, resultOperatorId: operatorId1 };
  }

  /**
   * Get engine summary statistics.
   *
   * @returns {object}
   */
  function getSummary() {
    var threatDist = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    var opKeys = Object.keys(operators);
    for (var i = 0; i < opKeys.length; i++) {
      var tl = operators[opKeys[i]].threatLevel || "LOW";
      threatDist[tl] = (threatDist[tl] || 0) + 1;
    }

    // Top operators by bot count
    var sorted = opKeys.slice().sort(function (a, b) {
      return (operators[b].knownBots.length) - (operators[a].knownBots.length);
    });
    var topOperators = [];
    for (var j = 0; j < Math.min(5, sorted.length); j++) {
      var op = operators[sorted[j]];
      topOperators.push({
        operatorId: sorted[j],
        botCount: op.knownBots.length,
        threatLevel: op.threatLevel,
        sophisticationLevel: op.sophisticationLevel
      });
    }

    // Count active campaigns
    var activeCampaigns = 0;
    var campKeys = Object.keys(campaigns);
    for (var k = 0; k < campKeys.length; k++) {
      var status = campaigns[campKeys[k]].status;
      if (status === "ACTIVE" || status === "INTENSIFYING") activeCampaigns++;
    }

    return {
      totalBots: botCount,
      totalOperators: operatorCount,
      totalCampaigns: campaignCount,
      activeCampaigns: activeCampaigns,
      threatDistribution: threatDist,
      topOperators: topOperators
    };
  }

  /**
   * Export full engine state.
   *
   * @returns {object}
   */
  function exportState() {
    var botsExport = Object.create(null);
    var bKeys = Object.keys(bots);
    for (var i = 0; i < bKeys.length; i++) {
      var b = bots[bKeys[i]];
      botsExport[bKeys[i]] = {
        events: b.events.slice(),
        fingerprint: b.fingerprint ? b.fingerprint.slice() : null,
        firstSeen: b.firstSeen,
        lastSeen: b.lastSeen,
        ips: _copyMap(b.ips),
        userAgents: _copyMap(b.userAgents),
        challengeTypes: _copyMap(b.challengeTypes),
        errorCodes: _copyMap(b.errorCodes),
        successCount: b.successCount,
        failCount: b.failCount
      };
    }

    var opsExport = Object.create(null);
    var oKeys = Object.keys(operators);
    for (var j = 0; j < oKeys.length; j++) {
      var op = operators[oKeys[j]];
      opsExport[oKeys[j]] = {
        id: op.id,
        knownBots: op.knownBots.slice(),
        campaigns: op.campaigns.slice(),
        firstSeen: op.firstSeen,
        lastSeen: op.lastSeen,
        centroid: op.centroid ? op.centroid.slice() : null,
        eventCount: op.eventCount,
        threatLevel: op.threatLevel,
        sophisticationLevel: op.sophisticationLevel
      };
    }

    var campsExport = Object.create(null);
    var cKeys = Object.keys(campaigns);
    for (var k = 0; k < cKeys.length; k++) {
      var c = campaigns[cKeys[k]];
      campsExport[cKeys[k]] = {
        id: c.id || cKeys[k],
        operatorId: c.operatorId,
        activeBots: c.activeBots.slice(),
        targetedChallenges: c.targetedChallenges.slice(),
        startedAt: c.startedAt,
        lastActivity: c.lastActivity,
        status: c.status,
        confidence: c.confidence
      };
    }

    var tlExport = Object.create(null);
    var tKeys = Object.keys(operatorTimelines);
    for (var t = 0; t < tKeys.length; t++) {
      tlExport[tKeys[t]] = operatorTimelines[tKeys[t]].slice();
    }

    return {
      version: 1,
      bots: botsExport,
      operators: opsExport,
      campaigns: campsExport,
      botAssignments: _copyMap(botAssignments),
      operatorTimelines: tlExport,
      botCount: botCount,
      operatorCount: operatorCount,
      campaignCount: campaignCount
    };
  }

  function _copyMap(obj) {
    var copy = Object.create(null);
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      copy[keys[i]] = obj[keys[i]];
    }
    return copy;
  }

  /**
   * Import engine state from a previously exported snapshot.
   *
   * @param {object} state
   */
  function importState(state) {
    if (!state || state.version !== 1) return;

    reset();

    var bKeys = Object.keys(state.bots || {});
    for (var i = 0; i < bKeys.length; i++) {
      var b = state.bots[bKeys[i]];
      bots[bKeys[i]] = {
        events: (b.events || []).slice(),
        fingerprint: b.fingerprint ? b.fingerprint.slice() : null,
        firstSeen: b.firstSeen,
        lastSeen: b.lastSeen,
        ips: _copyMap(b.ips || {}),
        userAgents: _copyMap(b.userAgents || {}),
        challengeTypes: _copyMap(b.challengeTypes || {}),
        errorCodes: _copyMap(b.errorCodes || {}),
        successCount: b.successCount || 0,
        failCount: b.failCount || 0
      };
      botLru.push(bKeys[i]);
    }
    botCount = bKeys.length;

    var oKeys = Object.keys(state.operators || {});
    for (var j = 0; j < oKeys.length; j++) {
      var op = state.operators[oKeys[j]];
      operators[oKeys[j]] = {
        id: op.id,
        knownBots: (op.knownBots || []).slice(),
        campaigns: (op.campaigns || []).slice(),
        firstSeen: op.firstSeen,
        lastSeen: op.lastSeen,
        centroid: op.centroid ? op.centroid.slice() : null,
        eventCount: op.eventCount || 0,
        threatLevel: op.threatLevel || "LOW",
        sophisticationLevel: op.sophisticationLevel || "NOVICE"
      };
    }
    operatorCount = oKeys.length;

    var cKeys = Object.keys(state.campaigns || {});
    for (var k = 0; k < cKeys.length; k++) {
      var c = state.campaigns[cKeys[k]];
      campaigns[cKeys[k]] = {
        id: c.id || cKeys[k],
        operatorId: c.operatorId,
        activeBots: (c.activeBots || []).slice(),
        targetedChallenges: (c.targetedChallenges || []).slice(),
        startedAt: c.startedAt,
        lastActivity: c.lastActivity,
        status: c.status || "DORMANT",
        confidence: c.confidence || 0
      };
    }
    campaignCount = cKeys.length;

    var aKeys = Object.keys(state.botAssignments || {});
    for (var a = 0; a < aKeys.length; a++) {
      botAssignments[aKeys[a]] = state.botAssignments[aKeys[a]];
    }

    var tKeys = Object.keys(state.operatorTimelines || {});
    for (var t = 0; t < tKeys.length; t++) {
      operatorTimelines[tKeys[t]] = (state.operatorTimelines[tKeys[t]] || []).slice();
    }
  }

  /**
   * Reset all engine state.
   */
  function reset() {
    var bKeys = Object.keys(bots);
    for (var i = 0; i < bKeys.length; i++) delete bots[bKeys[i]];
    botCount = 0;
    botLru = new LruTracker();

    var oKeys = Object.keys(operators);
    for (var j = 0; j < oKeys.length; j++) delete operators[oKeys[j]];
    operatorCount = 0;

    var cKeys = Object.keys(campaigns);
    for (var k = 0; k < cKeys.length; k++) delete campaigns[cKeys[k]];
    campaignCount = 0;

    var aKeys = Object.keys(botAssignments);
    for (var a = 0; a < aKeys.length; a++) delete botAssignments[aKeys[a]];

    var tKeys = Object.keys(operatorTimelines);
    for (var t = 0; t < tKeys.length; t++) delete operatorTimelines[tKeys[t]];
  }

  return {
    ingestBotActivity: ingestBotActivity,
    attributeBot: attributeBot,
    identifyOperator: identifyOperator,
    detectCampaign: detectCampaign,
    getOperatorTimeline: getOperatorTimeline,
    assessThreatLevel: assessThreatLevel,
    mergeOperators: mergeOperators,
    getSummary: getSummary,
    exportState: exportState,
    importState: importState,
    reset: reset,
    ATTRIBUTION_DIMENSIONS: ATTRIBUTION_DIMENSIONS,
    THREAT_LEVELS: THREAT_LEVELS,
    CAMPAIGN_PHASES: CAMPAIGN_PHASES,
    SOPHISTICATION_TIERS: SOPHISTICATION_TIERS
  };
}

module.exports = { createBotAttributionEngine: createBotAttributionEngine };
