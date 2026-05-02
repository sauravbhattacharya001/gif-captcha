/**
 * BotCollectiveIntelDetector — Autonomous bot swarm intelligence detection engine.
 *
 * Detects coordinated bot collectives by analyzing emergent swarm behaviors
 * that individual bot detection cannot catch. Focuses on:
 *   - Timing synchronization (inter-arrival cadence, phase-locked patterns)
 *   - Shared knowledge exploitation (collective challenge familiarity curves)
 *   - Collective learning rate (swarm skill improvement velocity)
 *   - Swarm topology inference (hub/spoke, mesh, hierarchical structures)
 *   - Communication signal detection (encoded signaling via timing/choices)
 *
 * Key capabilities:
 *   - Ingest solve events from multiple sessions
 *   - Detect swarm clusters via multi-dimensional behavioral correlation
 *   - Classify swarm topology (5 archetypes)
 *   - Track collective knowledge propagation speed
 *   - Estimate swarm size and coordination sophistication
 *   - Autonomous threat level assessment with escalation
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/bot-collective-intel
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

// ── Constants ───────────────────────────────────────────────────────

var SWARM_TOPOLOGIES = ["HUB_SPOKE", "MESH", "HIERARCHICAL", "PIPELINE", "INDEPENDENT"];

var THREAT_LEVELS = ["DORMANT", "PROBING", "COORDINATED", "SWARMING", "OVERWHELMING"];

var KNOWLEDGE_TYPES = ["CHALLENGE_SOLUTION", "TIMING_PATTERN", "EVASION_TACTIC", "ROTATION_EXPLOIT", "WEAKNESS_MAP"];

var DEFAULT_OPTIONS = {
  maxSessions: 5000,
  maxSwarms: 100,
  syncThresholdMs: 250,
  correlationThreshold: 0.65,
  minSwarmSize: 3,
  learningWindowMs: 3600000,      // 1 hour
  knowledgeDecayMs: 86400000,     // 24 hours
  topologyRecheckMs: 300000,      // 5 minutes
  maxEventsPerSession: 500
};

// ── Factory ─────────────────────────────────────────────────────────

/**
 * Create a Bot Collective Intelligence Detector instance.
 *
 * @param {object} [options]
 * @param {number} [options.maxSessions=5000]        Max tracked sessions
 * @param {number} [options.maxSwarms=100]           Max tracked swarms
 * @param {number} [options.syncThresholdMs=250]     Timing sync detection window
 * @param {number} [options.correlationThreshold=0.65] Min correlation to link sessions
 * @param {number} [options.minSwarmSize=3]          Min sessions to form a swarm
 * @param {number} [options.learningWindowMs=3600000] Window for learning rate calc
 * @param {number} [options.knowledgeDecayMs=86400000] Knowledge item half-life
 * @param {number} [options.topologyRecheckMs=300000] Min interval between topology recalcs
 * @param {number} [options.maxEventsPerSession=500] Max events stored per session
 * @returns {object} BotCollectiveIntelDetector instance
 */
function createBotCollectiveIntelDetector(options) {
  options = options || {};

  var maxSessions = _posOpt(options.maxSessions, DEFAULT_OPTIONS.maxSessions);
  var maxSwarms = _posOpt(options.maxSwarms, DEFAULT_OPTIONS.maxSwarms);
  var syncThresholdMs = _posOpt(options.syncThresholdMs, DEFAULT_OPTIONS.syncThresholdMs);
  var correlationThreshold = options.correlationThreshold != null && options.correlationThreshold >= 0
    ? options.correlationThreshold : DEFAULT_OPTIONS.correlationThreshold;
  var minSwarmSize = _posOpt(options.minSwarmSize, DEFAULT_OPTIONS.minSwarmSize);
  var learningWindowMs = _posOpt(options.learningWindowMs, DEFAULT_OPTIONS.learningWindowMs);
  var knowledgeDecayMs = _posOpt(options.knowledgeDecayMs, DEFAULT_OPTIONS.knowledgeDecayMs);
  var topologyRecheckMs = _posOpt(options.topologyRecheckMs, DEFAULT_OPTIONS.topologyRecheckMs);
  var maxEventsPerSession = _posOpt(options.maxEventsPerSession, DEFAULT_OPTIONS.maxEventsPerSession);

  // ── State ───────────────────────────────────────────────────────

  // sessionId -> { id, events[], solveTimes[], challengeResults{}, firstSeen, lastSeen, successRate }
  var sessions = Object.create(null);
  var sessionCount = 0;
  var sessionOrder = []; // insertion order for eviction

  // swarmId -> { id, members[], topology, confidence, knowledgePool[], learningRate, threatLevel, createdAt, updatedAt }
  var swarms = Object.create(null);
  var swarmCount = 0;
  var nextSwarmId = 1;

  // sessionId -> swarmId (reverse index)
  var sessionToSwarm = Object.create(null);

  // Behavior vector cache: sessionId -> { vector: number[], generation: number }
  var behaviorCache = Object.create(null);

  // Global collective knowledge observations
  var knowledgeEvents = []; // { type, challengeId, timestamp, sessionId, swarmId }
  var lastTopologyCheck = 0;

  // Stats
  var stats = {
    eventsIngested: 0,
    swarmsDetected: 0,
    swarmsActive: 0,
    peakSwarmSize: 0,
    knowledgePropagations: 0,
    threatEscalations: 0
  };

  // ── Helpers ─────────────────────────────────────────────────────

  function _generateSwarmId() {
    return "swarm_" + nextSwarmId++;
  }

  function _evictOldestSession() {
    if (sessionOrder.length === 0) return;
    var oldId = sessionOrder.shift();
    if (sessions[oldId]) {
      delete sessions[oldId];
      delete behaviorCache[oldId];
      sessionCount--;
      if (sessionToSwarm[oldId]) {
        _removeFromSwarm(oldId, sessionToSwarm[oldId]);
        delete sessionToSwarm[oldId];
      }
    }
  }

  function _removeFromSwarm(sessionId, swarmId) {
    var swarm = swarms[swarmId];
    if (!swarm) return;
    var idx = swarm.members.indexOf(sessionId);
    if (idx >= 0) swarm.members.splice(idx, 1);
    if (swarm.members.length < minSwarmSize) {
      delete swarms[swarmId];
      swarmCount--;
      stats.swarmsActive = swarmCount;
    }
  }

  /**
   * Compute timing synchronization score between two sessions.
   * Measures how often their events occur within syncThresholdMs of each other.
   */
  function _timingSyncScore(sessA, sessB) {
    var timesA = sessA.solveTimes;
    var timesB = sessB.solveTimes;
    if (timesA.length < 3 || timesB.length < 3) return 0;

    var syncCount = 0;
    var totalChecks = 0;
    var j = 0;

    for (var i = 0; i < timesA.length; i++) {
      while (j < timesB.length - 1 && timesB[j + 1] <= timesA[i]) j++;
      // Check nearest neighbor in B
      var nearestDist = Infinity;
      if (j < timesB.length) nearestDist = Math.abs(timesA[i] - timesB[j]);
      if (j + 1 < timesB.length) nearestDist = Math.min(nearestDist, Math.abs(timesA[i] - timesB[j + 1]));
      if (j > 0) nearestDist = Math.min(nearestDist, Math.abs(timesA[i] - timesB[j - 1]));

      if (nearestDist <= syncThresholdMs) syncCount++;
      totalChecks++;
    }

    return totalChecks > 0 ? syncCount / totalChecks : 0;
  }

  /**
   * Compute knowledge sharing score - how quickly challenge solutions propagate.
   * If session B solves a challenge shortly after session A (from same swarm),
   * that suggests knowledge sharing.
   */
  function _knowledgeSharingScore(sessA, sessB) {
    var resultsA = sessA.challengeResults;
    var resultsB = sessB.challengeResults;
    var sharedChallenges = 0;
    var rapidFollows = 0;

    var challengeIds = Object.keys(resultsA);
    for (var i = 0; i < challengeIds.length; i++) {
      var cid = challengeIds[i];
      if (resultsB[cid]) {
        sharedChallenges++;
        var timeDiff = Math.abs(resultsA[cid].timestamp - resultsB[cid].timestamp);
        // If B solved within 5 seconds of A, likely knowledge sharing
        if (timeDiff < 5000 && resultsA[cid].success && resultsB[cid].success) {
          rapidFollows++;
        }
      }
    }

    if (sharedChallenges < 2) return 0;
    return rapidFollows / sharedChallenges;
  }

  /**
   * Compute behavioral vector for a session (for cosine similarity).
   * Dimensions: avgSolveTime, successRate, eventCadence, burstFreq, challengeVariety
   * Uses per-session cache invalidated by event count (generation).
   */
  function _behaviorVector(sess) {
    var times = sess.solveTimes;
    if (times.length < 2) return [0, 0, 0, 0, 0];

    // Check cache — generation is event count, so vector is recomputed only on new events
    var gen = sess.events.length;
    var cached = behaviorCache[sess.id];
    if (cached && cached.generation === gen) return cached.vector;

    // Avg solve time (normalized to 0-1 range, cap at 30s)
    var solveSum = 0;
    var solveCount = 0;
    for (var s = 0; s < sess.events.length; s++) {
      var ms = sess.events[s].solveMs;
      if (ms > 0) { solveSum += ms; solveCount++; }
    }
    var avgTime = solveCount > 0 ? solveSum / solveCount : 0;
    var normAvgTime = _clamp(avgTime / 30000, 0, 1);

    // Success rate
    var successRate = sess.successRate;

    // Event cadence (avg inter-arrival time, normalized) + burst frequency
    var intervalSum = 0;
    var bursts = 0;
    var intervalCount = times.length - 1;
    for (var i = 1; i < times.length; i++) {
      var d = times[i] - times[i - 1];
      intervalSum += d;
      if (d < 2000) bursts++;
    }
    var avgCadence = intervalCount > 0 ? intervalSum / intervalCount : 60000;
    var normCadence = _clamp(avgCadence / 60000, 0, 1);
    var burstFreq = intervalCount > 0 ? bursts / intervalCount : 0;

    // Challenge variety (unique challenges / total)
    var uniqueChallenges = Object.keys(sess.challengeResults).length;
    var variety = sess.events.length > 0 ? Math.min(uniqueChallenges / sess.events.length, 1) : 0;

    var vec = [normAvgTime, successRate, normCadence, burstFreq, variety];
    behaviorCache[sess.id] = { vector: vec, generation: gen };
    return vec;
  }

  /**
   * Compute composite correlation score between two sessions.
   * Note: for hot-path bulk scoring in _checkSwarmMembership, we inline this
   * with cached vectors and early-exit. This function is kept for ad-hoc use.
   */
  function _correlationScore(sessA, sessB) {
    var vecA = _behaviorVector(sessA);
    var vecB = _behaviorVector(sessB);
    var behaviorSim = _cosineSimilarity(vecA, vecB);
    var timingSync = _timingSyncScore(sessA, sessB);
    var knowledgeShare = _knowledgeSharingScore(sessA, sessB);

    // Weighted composite
    return (timingSync * 0.35) + (knowledgeShare * 0.30) + (behaviorSim * 0.35);
  }

  /**
   * Infer swarm topology from member interaction patterns.
   */
  function _inferTopology(swarm) {
    var members = swarm.members;
    if (members.length < 3) return "INDEPENDENT";

    // Build adjacency strength matrix
    var n = members.length;
    var strengths = [];

    for (var i = 0; i < n; i++) {
      var rowSum = 0;
      for (var j = 0; j < n; j++) {
        if (i === j) continue;
        var sA = sessions[members[i]];
        var sB = sessions[members[j]];
        if (sA && sB) rowSum += _timingSyncScore(sA, sB);
      }
      strengths.push(rowSum);
    }

    var meanStrength = _mean(strengths);
    var stdStrength = _stddev(strengths);

    // High degree variance -> hub/spoke
    if (stdStrength > meanStrength * 0.8 && n >= 4) {
      return "HUB_SPOKE";
    }

    // All roughly equal connectivity -> mesh
    if (stdStrength < meanStrength * 0.3 && meanStrength > 0.3) {
      return "MESH";
    }

    // Check for pipeline (sequential timing pattern)
    var timeOrder = members.slice().sort(function (a, b) {
      var sA = sessions[a];
      var sB = sessions[b];
      if (!sA || !sB) return 0;
      return (sA.firstSeen || 0) - (sB.firstSeen || 0);
    });

    var seqCount = 0;
    for (var k = 1; k < timeOrder.length; k++) {
      var prev = sessions[timeOrder[k - 1]];
      var curr = sessions[timeOrder[k]];
      if (prev && curr && curr.firstSeen - prev.firstSeen < 5000) seqCount++;
    }
    if (seqCount > n * 0.6) return "PIPELINE";

    // Multi-level coordination -> hierarchical
    if (n >= 5 && stdStrength > meanStrength * 0.5) {
      return "HIERARCHICAL";
    }

    return "MESH";
  }

  /**
   * Compute collective learning rate for a swarm.
   * Measures how quickly the swarm's success rate improves over time.
   */
  function _computeLearningRate(swarm) {
    var now = _now();
    var windowStart = now - learningWindowMs;
    var members = swarm.members;

    // Collect time-bucketed success rates
    var bucketSize = learningWindowMs / 10;
    var buckets = [];
    for (var b = 0; b < 10; b++) buckets.push({ successes: 0, total: 0 });

    for (var i = 0; i < members.length; i++) {
      var sess = sessions[members[i]];
      if (!sess) continue;
      for (var j = 0; j < sess.events.length; j++) {
        var ev = sess.events[j];
        if (ev.timestamp < windowStart) continue;
        var bucketIdx = Math.floor((ev.timestamp - windowStart) / bucketSize);
        if (bucketIdx >= 0 && bucketIdx < 10) {
          buckets[bucketIdx].total++;
          if (ev.success) buckets[bucketIdx].successes++;
        }
      }
    }

    // Compute success rate per bucket and fit linear regression
    var rates = [];
    var xs = [];
    for (var bi = 0; bi < buckets.length; bi++) {
      if (buckets[bi].total >= 2) {
        rates.push(buckets[bi].successes / buckets[bi].total);
        xs.push(bi);
      }
    }

    if (rates.length < 3) return 0;

    var reg = _linearRegression(xs, rates);
    // Positive slope = swarm is learning (getting better)
    return _clamp(reg.slope * 10, -1, 1); // Normalize
  }

  /**
   * Assess threat level based on swarm characteristics.
   */
  function _assessThreatLevel(swarm) {
    var score = 0;

    // Size contribution (0-25)
    score += Math.min(swarm.members.length / 20, 1) * 25;

    // Coordination sophistication (0-25)
    var topoScores = { INDEPENDENT: 0, PIPELINE: 10, MESH: 15, HUB_SPOKE: 20, HIERARCHICAL: 25 };
    score += topoScores[swarm.topology] || 0;

    // Learning rate (0-25)
    score += Math.max(swarm.learningRate, 0) * 25;

    // Confidence (0-25)
    score += swarm.confidence * 25;

    // Map to threat level
    if (score < 15) return "DORMANT";
    if (score < 35) return "PROBING";
    if (score < 55) return "COORDINATED";
    if (score < 75) return "SWARMING";
    return "OVERWHELMING";
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Ingest a solve event from a session.
   *
   * @param {object} event
   * @param {string} event.sessionId - Unique session identifier
   * @param {string} event.challengeId - Challenge that was attempted
   * @param {boolean} event.success - Whether the solve was correct
   * @param {number} [event.solveMs] - Time taken to solve (ms)
   * @param {number} [event.timestamp] - Event timestamp (defaults to now)
   * @returns {object} { ingested: true, swarmDetected: boolean, swarmId: string|null }
   */
  function ingest(event) {
    if (!event || !event.sessionId || !event.challengeId) {
      return { ingested: false, error: "Missing sessionId or challengeId" };
    }

    var ts = event.timestamp || _now();
    var sessionId = String(event.sessionId);
    var challengeId = String(event.challengeId);
    var success = !!event.success;
    var solveMs = _nnOpt(event.solveMs, 0);

    // Get or create session
    var sess = sessions[sessionId];
    if (!sess) {
      if (sessionCount >= maxSessions) _evictOldestSession();
      sess = {
        id: sessionId,
        events: [],
        solveTimes: [],
        challengeResults: Object.create(null),
        firstSeen: ts,
        lastSeen: ts,
        successRate: 0,
        _totalSuccesses: 0,
        _totalAttempts: 0
      };
      sessions[sessionId] = sess;
      sessionOrder.push(sessionId);
      sessionCount++;
    }

    // Record event
    if (sess.events.length >= maxEventsPerSession) sess.events.shift();
    sess.events.push({ timestamp: ts, challengeId: challengeId, success: success, solveMs: solveMs });
    sess.solveTimes.push(ts);
    if (sess.solveTimes.length > maxEventsPerSession) sess.solveTimes.shift();

    sess.challengeResults[challengeId] = { timestamp: ts, success: success };
    sess.lastSeen = ts;
    sess._totalAttempts++;
    if (success) sess._totalSuccesses++;
    sess.successRate = sess._totalAttempts > 0 ? sess._totalSuccesses / sess._totalAttempts : 0;

    stats.eventsIngested++;

    // Track knowledge propagation
    if (success) {
      knowledgeEvents.push({ type: "CHALLENGE_SOLUTION", challengeId: challengeId, timestamp: ts, sessionId: sessionId });
      if (knowledgeEvents.length > 10000) knowledgeEvents = knowledgeEvents.slice(-5000);
    }

    // Check for swarm membership (only after enough data)
    var swarmDetected = false;
    var detectedSwarmId = null;

    if (sess.events.length >= 5) {
      var result = _checkSwarmMembership(sessionId);
      swarmDetected = result.detected;
      detectedSwarmId = result.swarmId;
    }

    return { ingested: true, swarmDetected: swarmDetected, swarmId: detectedSwarmId };
  }

  /**
   * Check if a session belongs to a swarm.
   * Optimized: pre-computes the target behavior vector once, skips sessions
   * with no time overlap (timing sync would be 0), and uses early-exit on
   * the behavioral similarity dimension before computing expensive timing/knowledge scores.
   */
  function _checkSwarmMembership(sessionId) {
    var sess = sessions[sessionId];
    if (!sess) return { detected: false, swarmId: null };

    // Already in a swarm?
    if (sessionToSwarm[sessionId]) {
      return { detected: true, swarmId: sessionToSwarm[sessionId] };
    }

    // Pre-compute target vector once for all comparisons
    var vecA = _behaviorVector(sess);
    var sessFirst = sess.firstSeen;
    var sessLast = sess.lastSeen;

    // Find correlated sessions
    var correlated = [];
    for (var i = 0; i < sessionOrder.length; i++) {
      var otherId = sessionOrder[i];
      if (otherId === sessionId) continue;
      var otherSess = sessions[otherId];
      if (!otherSess || otherSess.events.length < 5) continue;

      // Skip sessions with no time overlap — timing sync would be ~0
      if (otherSess.lastSeen < sessFirst - syncThresholdMs ||
          otherSess.firstSeen > sessLast + syncThresholdMs) continue;

      // Cheap behavioral similarity pre-check (weight=0.35, max contrib=0.35)
      var vecB = _behaviorVector(otherSess);
      var behaviorSim = _cosineSimilarity(vecA, vecB);
      // If even perfect timing+knowledge (0.65) + this behavior can't reach threshold, skip
      if (behaviorSim * 0.35 + 0.65 < correlationThreshold) continue;

      var timingSync = _timingSyncScore(sess, otherSess);
      var knowledgeShare = _knowledgeSharingScore(sess, otherSess);
      var score = (timingSync * 0.35) + (knowledgeShare * 0.30) + (behaviorSim * 0.35);
      if (score >= correlationThreshold) {
        correlated.push({ id: otherId, score: score });
      }
    }

    if (correlated.length < minSwarmSize - 1) {
      return { detected: false, swarmId: null };
    }

    // Check if correlated sessions already form a swarm
    for (var c = 0; c < correlated.length; c++) {
      var existingSwarmId = sessionToSwarm[correlated[c].id];
      if (existingSwarmId && swarms[existingSwarmId]) {
        // Add to existing swarm
        var existingSwarm = swarms[existingSwarmId];
        if (existingSwarm.members.indexOf(sessionId) < 0) {
          existingSwarm.members.push(sessionId);
          sessionToSwarm[sessionId] = existingSwarmId;
          existingSwarm.updatedAt = _now();
          if (existingSwarm.members.length > stats.peakSwarmSize) {
            stats.peakSwarmSize = existingSwarm.members.length;
          }
        }
        return { detected: true, swarmId: existingSwarmId };
      }
    }

    // Create new swarm
    if (swarmCount >= maxSwarms) {
      // Evict lowest confidence swarm
      var lowestId = null;
      var lowestConf = Infinity;
      var swarmIds = Object.keys(swarms);
      for (var si = 0; si < swarmIds.length; si++) {
        if (swarms[swarmIds[si]].confidence < lowestConf) {
          lowestConf = swarms[swarmIds[si]].confidence;
          lowestId = swarmIds[si];
        }
      }
      if (lowestId) {
        var evicted = swarms[lowestId];
        for (var m = 0; m < evicted.members.length; m++) {
          delete sessionToSwarm[evicted.members[m]];
        }
        delete swarms[lowestId];
        swarmCount--;
      }
    }

    var newSwarmId = _generateSwarmId();
    var memberIds = [sessionId];
    var avgScore = 0;
    for (var ci = 0; ci < correlated.length; ci++) {
      memberIds.push(correlated[ci].id);
      avgScore += correlated[ci].score;
    }
    avgScore = avgScore / correlated.length;

    var newSwarm = {
      id: newSwarmId,
      members: memberIds,
      topology: "INDEPENDENT",
      confidence: _clamp(avgScore, 0, 1),
      knowledgePool: [],
      learningRate: 0,
      threatLevel: "PROBING",
      sophisticationScore: 0,
      createdAt: _now(),
      updatedAt: _now()
    };

    swarms[newSwarmId] = newSwarm;
    swarmCount++;
    stats.swarmsDetected++;
    stats.swarmsActive = swarmCount;

    for (var mi = 0; mi < memberIds.length; mi++) {
      sessionToSwarm[memberIds[mi]] = newSwarmId;
    }

    if (memberIds.length > stats.peakSwarmSize) stats.peakSwarmSize = memberIds.length;

    // Initial topology & threat assessment
    newSwarm.topology = _inferTopology(newSwarm);
    newSwarm.learningRate = _computeLearningRate(newSwarm);
    newSwarm.threatLevel = _assessThreatLevel(newSwarm);

    return { detected: true, swarmId: newSwarmId };
  }

  /**
   * Run a full analysis pass on all known swarms.
   * Updates topology, learning rate, threat level, and knowledge propagation.
   *
   * @returns {object} { swarmsAnalyzed, escalations[], insights[] }
   */
  function analyze() {
    var now = _now();
    var escalations = [];
    var insights = [];
    var swarmsAnalyzed = 0;

    var swarmIds = Object.keys(swarms);
    for (var i = 0; i < swarmIds.length; i++) {
      var swarm = swarms[swarmIds[i]];
      if (!swarm) continue;
      swarmsAnalyzed++;

      // Update topology
      if (now - lastTopologyCheck > topologyRecheckMs) {
        var oldTopology = swarm.topology;
        swarm.topology = _inferTopology(swarm);
        if (oldTopology !== swarm.topology) {
          insights.push({
            swarmId: swarm.id,
            type: "TOPOLOGY_SHIFT",
            from: oldTopology,
            to: swarm.topology,
            timestamp: now
          });
        }
      }

      // Update learning rate
      var oldLR = swarm.learningRate;
      swarm.learningRate = _computeLearningRate(swarm);
      if (swarm.learningRate > 0.5 && oldLR <= 0.5) {
        insights.push({
          swarmId: swarm.id,
          type: "RAPID_LEARNING",
          learningRate: swarm.learningRate,
          timestamp: now
        });
      }

      // Update threat level
      var oldThreat = swarm.threatLevel;
      swarm.threatLevel = _assessThreatLevel(swarm);
      var oldIdx = THREAT_LEVELS.indexOf(oldThreat);
      var newIdx = THREAT_LEVELS.indexOf(swarm.threatLevel);
      if (newIdx > oldIdx) {
        escalations.push({
          swarmId: swarm.id,
          from: oldThreat,
          to: swarm.threatLevel,
          members: swarm.members.length,
          topology: swarm.topology,
          timestamp: now
        });
        stats.threatEscalations++;
      }

      // Detect knowledge propagation
      var propagations = _detectKnowledgePropagation(swarm);
      if (propagations > 0) {
        stats.knowledgePropagations += propagations;
        insights.push({
          swarmId: swarm.id,
          type: "KNOWLEDGE_PROPAGATION",
          count: propagations,
          timestamp: now
        });
      }

      // Compute sophistication score
      swarm.sophisticationScore = _computeSophistication(swarm);
      swarm.updatedAt = now;
    }

    lastTopologyCheck = now;

    return { swarmsAnalyzed: swarmsAnalyzed, escalations: escalations, insights: insights };
  }

  /**
   * Detect knowledge propagation within a swarm.
   */
  function _detectKnowledgePropagation(swarm) {
    var now = _now();
    var windowStart = now - learningWindowMs;
    var propagations = 0;
    var members = swarm.members;

    // Look for challenge solutions that spread through the swarm
    var challengeSolveOrder = Object.create(null); // challengeId -> [{sessionId, timestamp}]

    for (var i = 0; i < members.length; i++) {
      var sess = sessions[members[i]];
      if (!sess) continue;
      var cids = Object.keys(sess.challengeResults);
      for (var j = 0; j < cids.length; j++) {
        var result = sess.challengeResults[cids[j]];
        if (result.success && result.timestamp >= windowStart) {
          if (!challengeSolveOrder[cids[j]]) challengeSolveOrder[cids[j]] = [];
          challengeSolveOrder[cids[j]].push({ sessionId: members[i], timestamp: result.timestamp });
        }
      }
    }

    // Count challenges solved by multiple members in quick succession
    var cKeys = Object.keys(challengeSolveOrder);
    for (var k = 0; k < cKeys.length; k++) {
      var solvers = challengeSolveOrder[cKeys[k]];
      if (solvers.length < 3) continue;
      solvers.sort(function (a, b) { return a.timestamp - b.timestamp; });

      // If 3+ members solved within 10s, that's propagation
      var first = solvers[0].timestamp;
      var last = solvers[solvers.length - 1].timestamp;
      if (last - first < 10000) propagations++;
    }

    return propagations;
  }

  /**
   * Compute overall sophistication score for a swarm (0-100).
   */
  function _computeSophistication(swarm) {
    var score = 0;

    // Topology sophistication (0-20)
    var topoScores = { INDEPENDENT: 0, PIPELINE: 8, MESH: 12, HUB_SPOKE: 16, HIERARCHICAL: 20 };
    score += topoScores[swarm.topology] || 0;

    // Size (0-20)
    score += Math.min(swarm.members.length / 15, 1) * 20;

    // Learning rate (0-20)
    score += Math.max(swarm.learningRate, 0) * 20;

    // Knowledge propagation speed (0-20)
    var propScore = Math.min(stats.knowledgePropagations / 10, 1) * 20;
    score += propScore;

    // Coordination tightness - average pairwise sync (0-20)
    var totalSync = 0;
    var pairs = 0;
    var members = swarm.members;
    var sampleSize = Math.min(members.length, 8); // Cap for performance
    for (var i = 0; i < sampleSize; i++) {
      for (var j = i + 1; j < sampleSize; j++) {
        var sA = sessions[members[i]];
        var sB = sessions[members[j]];
        if (sA && sB) {
          totalSync += _timingSyncScore(sA, sB);
          pairs++;
        }
      }
    }
    var avgSync = pairs > 0 ? totalSync / pairs : 0;
    score += avgSync * 20;

    return Math.round(_clamp(score, 0, 100));
  }

  /**
   * Get a summary report of all detected swarms.
   *
   * @returns {object} { totalSwarms, swarms[], globalThreatLevel, stats }
   */
  function getReport() {
    var swarmList = [];
    var maxThreatIdx = 0;

    var swarmIds = Object.keys(swarms);
    for (var i = 0; i < swarmIds.length; i++) {
      var swarm = swarms[swarmIds[i]];
      if (!swarm) continue;

      var threatIdx = THREAT_LEVELS.indexOf(swarm.threatLevel);
      if (threatIdx > maxThreatIdx) maxThreatIdx = threatIdx;

      swarmList.push({
        id: swarm.id,
        members: swarm.members.length,
        topology: swarm.topology,
        confidence: Math.round(swarm.confidence * 100) / 100,
        learningRate: Math.round(swarm.learningRate * 1000) / 1000,
        threatLevel: swarm.threatLevel,
        sophisticationScore: swarm.sophisticationScore,
        createdAt: swarm.createdAt,
        updatedAt: swarm.updatedAt
      });
    }

    // Sort by threat level desc, then sophistication desc
    swarmList.sort(function (a, b) {
      var tidxA = THREAT_LEVELS.indexOf(a.threatLevel);
      var tidxB = THREAT_LEVELS.indexOf(b.threatLevel);
      if (tidxB !== tidxA) return tidxB - tidxA;
      return b.sophisticationScore - a.sophisticationScore;
    });

    return {
      totalSwarms: swarmCount,
      globalThreatLevel: THREAT_LEVELS[maxThreatIdx],
      swarms: swarmList,
      stats: {
        eventsIngested: stats.eventsIngested,
        sessionsTracked: sessionCount,
        swarmsDetected: stats.swarmsDetected,
        swarmsActive: stats.swarmsActive,
        peakSwarmSize: stats.peakSwarmSize,
        knowledgePropagations: stats.knowledgePropagations,
        threatEscalations: stats.threatEscalations
      }
    };
  }

  /**
   * Get detailed info about a specific swarm.
   *
   * @param {string} swarmId
   * @returns {object|null}
   */
  function getSwarm(swarmId) {
    var swarm = swarms[swarmId];
    if (!swarm) return null;

    var memberDetails = [];
    for (var i = 0; i < swarm.members.length; i++) {
      var sess = sessions[swarm.members[i]];
      if (sess) {
        memberDetails.push({
          id: sess.id,
          events: sess.events.length,
          successRate: Math.round(sess.successRate * 100) / 100,
          firstSeen: sess.firstSeen,
          lastSeen: sess.lastSeen
        });
      }
    }

    return {
      id: swarm.id,
      topology: swarm.topology,
      confidence: swarm.confidence,
      learningRate: swarm.learningRate,
      threatLevel: swarm.threatLevel,
      sophisticationScore: swarm.sophisticationScore,
      members: memberDetails,
      createdAt: swarm.createdAt,
      updatedAt: swarm.updatedAt
    };
  }

  /**
   * Get sessions currently flagged as part of any swarm.
   *
   * @returns {string[]} Array of session IDs
   */
  function getFlaggedSessions() {
    return Object.keys(sessionToSwarm);
  }

  /**
   * Export full state for persistence.
   *
   * @returns {object}
   */
  function exportState() {
    var sessExport = Object.create(null);
    var sIds = Object.keys(sessions);
    for (var i = 0; i < sIds.length; i++) {
      var s = sessions[sIds[i]];
      sessExport[sIds[i]] = {
        id: s.id,
        events: s.events,
        solveTimes: s.solveTimes,
        challengeResults: s.challengeResults,
        firstSeen: s.firstSeen,
        lastSeen: s.lastSeen,
        successRate: s.successRate,
        _totalSuccesses: s._totalSuccesses,
        _totalAttempts: s._totalAttempts
      };
    }

    return {
      version: 1,
      sessions: sessExport,
      sessionOrder: sessionOrder.slice(),
      swarms: JSON.parse(JSON.stringify(swarms)),
      sessionToSwarm: JSON.parse(JSON.stringify(sessionToSwarm)),
      nextSwarmId: nextSwarmId,
      knowledgeEvents: knowledgeEvents.slice(-1000),
      stats: JSON.parse(JSON.stringify(stats))
    };
  }

  /**
   * Import previously exported state.
   *
   * @param {object} state
   * @returns {boolean}
   */
  function importState(state) {
    if (!state || state.version !== 1) return false;

    sessions = Object.create(null);
    var sIds = Object.keys(state.sessions || {});
    for (var i = 0; i < sIds.length; i++) {
      sessions[sIds[i]] = state.sessions[sIds[i]];
    }
    sessionCount = sIds.length;
    sessionOrder = state.sessionOrder || sIds;

    swarms = Object.create(null);
    var swIds = Object.keys(state.swarms || {});
    for (var j = 0; j < swIds.length; j++) {
      swarms[swIds[j]] = state.swarms[swIds[j]];
    }
    swarmCount = swIds.length;

    sessionToSwarm = state.sessionToSwarm || Object.create(null);
    nextSwarmId = state.nextSwarmId || 1;
    knowledgeEvents = state.knowledgeEvents || [];
    stats = state.stats || stats;

    return true;
  }

  /**
   * Reset all state.
   */
  function reset() {
    sessions = Object.create(null);
    sessionCount = 0;
    sessionOrder = [];
    swarms = Object.create(null);
    swarmCount = 0;
    nextSwarmId = 1;
    sessionToSwarm = Object.create(null);
    behaviorCache = Object.create(null);
    knowledgeEvents = [];
    lastTopologyCheck = 0;
    stats = {
      eventsIngested: 0,
      swarmsDetected: 0,
      swarmsActive: 0,
      peakSwarmSize: 0,
      knowledgePropagations: 0,
      threatEscalations: 0
    };
  }

  return {
    ingest: ingest,
    analyze: analyze,
    getReport: getReport,
    getSwarm: getSwarm,
    getFlaggedSessions: getFlaggedSessions,
    exportState: exportState,
    importState: importState,
    reset: reset,
    SWARM_TOPOLOGIES: SWARM_TOPOLOGIES,
    THREAT_LEVELS: THREAT_LEVELS,
    KNOWLEDGE_TYPES: KNOWLEDGE_TYPES
  };
}

module.exports = { createBotCollectiveIntelDetector: createBotCollectiveIntelDetector };
