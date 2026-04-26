'use strict';

var _shared = require('./shared-utils');
var _now = _shared._now;
var _cosineSimilarity = _shared._cosineSimilarity;
var _decayFactor = _shared._decayFactor;

/**
 * createFraudRingDetector — detects coordinated CAPTCHA-solving rings by
 * clustering sessions that exhibit suspiciously similar behavioral patterns
 * across different IPs, user agents, or time windows.
 *
 * CAPTCHA farms often employ multiple human solvers working in shifts.
 * While individual sessions may look legitimate, the *coordination patterns*
 * betray them: similar solve timing distributions, synchronized activity
 * windows, shared challenge failure signatures, and correlated bursts.
 *
 * Features:
 * - Ingest session data with behavioral signals (timing, success rate, etc.)
 * - Cluster sessions into suspected rings using similarity analysis
 * - Score ring confidence based on multiple correlation dimensions
 * - Track ring evolution over time (members joining/leaving)
 * - Generate ring reports with evidence breakdown
 * - Export/import ring data as JSON
 * - Configurable similarity thresholds and minimum ring size
 *
 * No external dependencies.
 *
 * @param {object} [options]
 * @param {number} [options.similarityThreshold=0.70] Min similarity to link sessions (0–1)
 * @param {number} [options.minRingSize=3]            Min sessions to form a ring
 * @param {number} [options.maxSessions=2000]         Max tracked sessions
 * @param {number} [options.maxRings=200]             Max tracked rings
 * @param {number} [options.timeWindowMs=86400000]    Activity window for correlation (24h default)
 * @param {number} [options.decayHalfLifeMs=604800000] Ring confidence decay half-life (7d default)
 * @returns {object}
 */
function createFraudRingDetector(options) {
  options = options || {};

  var similarityThreshold = options.similarityThreshold != null && options.similarityThreshold >= 0
    ? options.similarityThreshold : 0.70;
  var minRingSize = options.minRingSize != null && options.minRingSize >= 2
    ? options.minRingSize : 3;
  var maxSessions = options.maxSessions != null && options.maxSessions > 0
    ? options.maxSessions : 2000;
  var maxRings = options.maxRings != null && options.maxRings > 0
    ? options.maxRings : 200;
  var timeWindowMs = options.timeWindowMs != null && options.timeWindowMs > 0
    ? options.timeWindowMs : 86400000;
  var decayHalfLifeMs = options.decayHalfLifeMs != null && options.decayHalfLifeMs > 0
    ? options.decayHalfLifeMs : 604800000;

  // sessionId -> { id, ip, userAgent, solves, signals, addedAt, _timingDist, _responseDist, _successRate }
  var sessions = Object.create(null);
  var sessionCount = 0;
  // Insertion-order tracking for O(1) oldest-session eviction.
  // Previously eviction scanned all sessions (O(n)) to find the oldest.
  var sessionInsertionOrder = [];

  // ringId -> { id, members: Set, confidence, evidence, createdAt, updatedAt }
  var rings = Object.create(null);
  var ringCount = 0;
  var nextRingId = 1;

  // Reverse index: sessionId -> [ringId, ...] for O(1) checkSession lookups.
  // Previously checkSession scanned every ring's member list.
  var sessionToRings = Object.create(null);

  // ── Helpers ──────────────────────────────────────────────────────

  function _generateId() {
    return 'ring_' + nextRingId++;
  }

  // _now, _cosineSimilarity, _decayFactor imported from shared-utils

  /**
   * Build a timing distribution vector from solve timestamps.
   * Buckets into 24 hour slots.
   */
  function _buildTimingDistribution(solves) {
    var dist = new Array(24);
    for (var i = 0; i < 24; i++) dist[i] = 0;
    if (!solves || solves.length === 0) return dist;

    for (var j = 0; j < solves.length; j++) {
      var ts = solves[j].timestamp || solves[j].ts || 0;
      var hour = new Date(ts).getUTCHours();
      dist[hour]++;
    }
    // Normalize
    var total = solves.length;
    for (var k = 0; k < 24; k++) dist[k] /= total;
    return dist;
  }

  /**
   * Build a solve-time histogram (response time buckets: 0-1s, 1-2s, ... 9-10s, 10s+).
   */
  function _buildResponseTimeDistribution(solves) {
    var buckets = 11; // 0-1, 1-2, ... 9-10, 10+
    var dist = new Array(buckets);
    for (var i = 0; i < buckets; i++) dist[i] = 0;
    if (!solves || solves.length === 0) return dist;

    var count = 0;
    for (var j = 0; j < solves.length; j++) {
      var rt = solves[j].responseTime || solves[j].solveTime || 0;
      if (rt <= 0) continue;
      var bucket = Math.min(Math.floor(rt / 1000), buckets - 1);
      dist[bucket]++;
      count++;
    }
    if (count > 0) {
      for (var k = 0; k < buckets; k++) dist[k] /= count;
    }
    return dist;
  }

  /**
   * Compute success rate from solves.
   */
  function _successRate(solves) {
    if (!solves || solves.length === 0) return 0;
    var success = 0;
    for (var i = 0; i < solves.length; i++) {
      if (solves[i].success || solves[i].correct) success++;
    }
    return success / solves.length;
  }

  /**
   * Precompute and cache distribution vectors on a session object.
   * Called once when a session is added or its solves are updated,
   * so detect() can skip redundant O(solves) distribution builds.
   * Before this change, detect() rebuilt distributions for every pair
   * comparison — O(n² × solves) total work.  Now it's O(n × solves)
   * at ingestion time and O(n²) with only vector lookups at detect time.
   */
  function _precomputeDistributions(session) {
    session._timingDist = _buildTimingDistribution(session.solves);
    session._responseDist = _buildResponseTimeDistribution(session.solves);
    session._successRate = _successRate(session.solves);
  }

  /**
   * Compute multi-dimensional similarity between two sessions.
   * Uses precomputed distributions when available (set by _precomputeDistributions).
   */
  function _sessionSimilarity(a, b) {
    var scores = [];
    var weights = [];

    // 1. Timing distribution similarity (when do they solve?)
    var tA = a._timingDist || _buildTimingDistribution(a.solves);
    var tB = b._timingDist || _buildTimingDistribution(b.solves);
    var timingSim = _cosineSimilarity(tA, tB);
    scores.push(timingSim);
    weights.push(0.30);

    // 2. Response time distribution similarity (how fast?)
    var rA = a._responseDist || _buildResponseTimeDistribution(a.solves);
    var rB = b._responseDist || _buildResponseTimeDistribution(b.solves);
    var responseSim = _cosineSimilarity(rA, rB);
    scores.push(responseSim);
    weights.push(0.30);

    // 3. Success rate similarity
    var srA = typeof a._successRate === 'number' ? a._successRate : _successRate(a.solves);
    var srB = typeof b._successRate === 'number' ? b._successRate : _successRate(b.solves);
    var successSim = 1 - Math.abs(srA - srB);
    scores.push(successSim);
    weights.push(0.20);

    // 4. Activity overlap (are they active in the same time windows?)
    var overlapSim = _activityOverlap(a.solves, b.solves);
    scores.push(overlapSim);
    weights.push(0.20);

    var totalWeight = 0, weighted = 0;
    for (var i = 0; i < scores.length; i++) {
      weighted += scores[i] * weights[i];
      totalWeight += weights[i];
    }

    return {
      overall: totalWeight > 0 ? weighted / totalWeight : 0,
      timing: timingSim,
      responseTime: responseSim,
      successRate: successSim,
      activityOverlap: overlapSim
    };
  }

  /**
   * Measure activity overlap between two sets of solves.
   */
  function _activityOverlap(solvesA, solvesB) {
    if (!solvesA || !solvesB || solvesA.length === 0 || solvesB.length === 0) return 0;

    // Bucket into time windows
    var windowSize = Math.max(timeWindowMs / 24, 3600000); // 1-hour min
    var bucketsA = Object.create(null);
    var bucketsB = Object.create(null);
    var allBuckets = Object.create(null);

    for (var i = 0; i < solvesA.length; i++) {
      var bA = Math.floor((solvesA[i].timestamp || solvesA[i].ts || 0) / windowSize);
      bucketsA[bA] = true;
      allBuckets[bA] = true;
    }
    for (var j = 0; j < solvesB.length; j++) {
      var bB = Math.floor((solvesB[j].timestamp || solvesB[j].ts || 0) / windowSize);
      bucketsB[bB] = true;
      allBuckets[bB] = true;
    }

    // Jaccard index
    var intersection = 0, union = 0;
    var keys = Object.keys(allBuckets);
    for (var k = 0; k < keys.length; k++) {
      var key = keys[k];
      if (bucketsA[key] && bucketsB[key]) intersection++;
      union++;
    }
    return union > 0 ? intersection / union : 0;
  }

  /**
   * Apply confidence decay based on age.
   */
  function _decayedConfidence(confidence, ageMs) {
    if (decayHalfLifeMs <= 0) return confidence;
    return confidence * _decayFactor(ageMs, decayHalfLifeMs);
  }

  // ── Public API ───────────────────────────────────────────────────

  /**
   * Add a session with its solve data for analysis.
   * @param {string} sessionId
   * @param {object} data - { ip, userAgent, solves: [{ timestamp, responseTime, success }], signals }
   */
  function addSession(sessionId, data) {
    if (!sessionId || typeof sessionId !== 'string') {
      throw new Error('sessionId is required');
    }
    data = data || {};

    if (sessions[sessionId]) {
      // Update existing
      var existing = sessions[sessionId];
      if (data.solves && Array.isArray(data.solves)) {
        existing.solves = existing.solves.concat(data.solves);
        if (existing.solves.length > 500) {
          existing.solves = existing.solves.slice(existing.solves.length - 500);
        }
      }
      if (data.signals && typeof data.signals === 'object') {
        if (!existing.signals) existing.signals = Object.create(null);
        var sigKeys = Object.keys(data.signals);
        for (var sk = 0; sk < sigKeys.length; sk++) {
          if (sigKeys[sk] !== '__proto__' && sigKeys[sk] !== 'constructor' && sigKeys[sk] !== 'prototype') {
            existing.signals[sigKeys[sk]] = data.signals[sigKeys[sk]];
          }
        }
      }
      existing.updatedAt = _now();
      // Re-derive cached distributions after solve data changes
      _precomputeDistributions(existing);
      return;
    }

    // Enforce max sessions — evict from insertion-order queue (O(1)
    // amortized).  Previously this scanned all sessions to find the
    // oldest addedAt timestamp, which was O(n) per eviction.
    while (sessionCount >= maxSessions && sessionInsertionOrder.length > 0) {
      var oldestId = sessionInsertionOrder.shift();
      if (sessions[oldestId]) {
        // Clean up ring index entries for evicted session
        if (sessionToRings[oldestId]) delete sessionToRings[oldestId];
        delete sessions[oldestId];
        sessionCount--;
      }
    }

    // Copy signals safely to prevent prototype pollution (CWE-1321)
    var safeSignals = Object.create(null);
    if (data.signals && typeof data.signals === 'object') {
      var dsk = Object.keys(data.signals);
      for (var dsi = 0; dsi < dsk.length; dsi++) {
        if (dsk[dsi] !== '__proto__' && dsk[dsi] !== 'constructor' && dsk[dsi] !== 'prototype') {
          safeSignals[dsk[dsi]] = data.signals[dsk[dsi]];
        }
      }
    }
    sessions[sessionId] = {
      id: sessionId,
      ip: data.ip || null,
      userAgent: data.userAgent || null,
      solves: Array.isArray(data.solves) ? data.solves.slice() : [],
      signals: safeSignals,
      addedAt: _now(),
      updatedAt: _now()
    };
    _precomputeDistributions(sessions[sessionId]);
    sessionInsertionOrder.push(sessionId);
    sessionCount++;
  }

  /**
   * Run ring detection across all sessions.
   * Uses greedy clustering: for each unassigned session, find all similar
   * sessions above threshold and form a ring if >= minRingSize.
   * @returns {Array} Array of detected rings
   */
  function detect() {
    var sessionIds = Object.keys(sessions);
    if (sessionIds.length < minRingSize) return [];

    // Precompute pairwise similarity
    var similarities = Object.create(null);
    for (var i = 0; i < sessionIds.length; i++) {
      for (var j = i + 1; j < sessionIds.length; j++) {
        var sim = _sessionSimilarity(sessions[sessionIds[i]], sessions[sessionIds[j]]);
        if (sim.overall >= similarityThreshold) {
          var key = sessionIds[i] + '|' + sessionIds[j];
          similarities[key] = sim;
        }
      }
    }

    // Build adjacency list
    var adj = Object.create(null);
    var simKeys = Object.keys(similarities);
    for (var s = 0; s < simKeys.length; s++) {
      var parts = simKeys[s].split('|');
      if (!adj[parts[0]]) adj[parts[0]] = [];
      if (!adj[parts[1]]) adj[parts[1]] = [];
      adj[parts[0]].push({ id: parts[1], sim: similarities[simKeys[s]] });
      adj[parts[1]].push({ id: parts[0], sim: similarities[simKeys[s]] });
    }

    // Connected components via BFS (index-based dequeue avoids O(n)
    // Array.shift(); total BFS is now O(V + E) instead of O(V² + E)).
    var visited = Object.create(null);
    var detectedRings = [];

    for (var n = 0; n < sessionIds.length; n++) {
      var sid = sessionIds[n];
      if (visited[sid] || !adj[sid]) continue;

      var component = [];
      var queue = [sid];
      var qHead = 0;          // pointer-based dequeue: O(1) per iteration
      visited[sid] = true;

      while (qHead < queue.length) {
        var current = queue[qHead++];
        component.push(current);
        var neighbors = adj[current] || [];
        for (var nb = 0; nb < neighbors.length; nb++) {
          if (!visited[neighbors[nb].id]) {
            visited[neighbors[nb].id] = true;
            queue.push(neighbors[nb].id);
          }
        }
      }

      if (component.length >= minRingSize) {
        // Calculate ring confidence using adjacency list directly.
        // Previous approach rebuilt 'idA|idB' pair-key strings for every
        // O(component²) pair and looked them up in the similarities map.
        // Using the adjacency list we only visit edges that actually exist
        // (O(E_component) instead of O(V_component²)) and avoid string
        // concatenation entirely.
        var totalSim = 0, pairCount = 0;
        var evidence = { timing: 0, responseTime: 0, successRate: 0, activityOverlap: 0 };
        var componentSet = Object.create(null);
        for (var cs = 0; cs < component.length; cs++) componentSet[component[cs]] = true;

        // Walk each component member's adjacency edges; since each edge
        // appears in both directions, count only when neighbor id > current
        // to avoid double-counting.
        for (var ci = 0; ci < component.length; ci++) {
          var cid = component[ci];
          var cNeighbors = adj[cid] || [];
          for (var cj = 0; cj < cNeighbors.length; cj++) {
            var nid = cNeighbors[cj].id;
            // Only count each undirected edge once (lexicographic tie-break)
            if (nid > cid && componentSet[nid]) {
              var edgeSim = cNeighbors[cj].sim;
              totalSim += edgeSim.overall;
              evidence.timing += edgeSim.timing;
              evidence.responseTime += edgeSim.responseTime;
              evidence.successRate += edgeSim.successRate;
              evidence.activityOverlap += edgeSim.activityOverlap;
              pairCount++;
            }
          }
        }
        if (pairCount > 0) {
          evidence.timing /= pairCount;
          evidence.responseTime /= pairCount;
          evidence.successRate /= pairCount;
          evidence.activityOverlap /= pairCount;
        }

        var confidence = pairCount > 0 ? totalSim / pairCount : 0;
        var uniqueIps = Object.create(null);
        for (var ci2 = 0; ci2 < component.length; ci2++) {
          if (sessions[component[ci2]].ip) uniqueIps[sessions[component[ci2]].ip] = true;
        }
        var ipDiversity = Object.keys(uniqueIps).length;

        // Boost confidence if IPs are diverse (multi-IP = stronger ring signal)
        if (ipDiversity > 1) {
          confidence = Math.min(1, confidence * (1 + 0.1 * Math.min(ipDiversity, 5)));
        }

        var ringId = _generateId();
        var now = _now();
        var ring = {
          id: ringId,
          members: component.slice(),
          size: component.length,
          confidence: Math.round(confidence * 1000) / 1000,
          ipDiversity: ipDiversity,
          evidence: evidence,
          createdAt: now,
          updatedAt: now
        };

        if (ringCount < maxRings) {
          rings[ringId] = ring;
          ringCount++;
          // Update reverse index for O(1) checkSession
          for (var mi = 0; mi < component.length; mi++) {
            if (!sessionToRings[component[mi]]) sessionToRings[component[mi]] = [];
            sessionToRings[component[mi]].push(ringId);
          }
        }

        detectedRings.push(ring);
      }
    }

    return detectedRings;
  }

  /**
   * Get a specific ring by ID.
   */
  function getRing(ringId) {
    return rings[ringId] || null;
  }

  /**
   * List all known rings, optionally with confidence decay applied.
   * @param {object} [opts]
   * @param {boolean} [opts.applyDecay=false]
   * @param {number} [opts.minConfidence=0]
   * @returns {Array}
   */
  function listRings(opts) {
    opts = opts || {};
    var applyDecay = opts.applyDecay || false;
    var minConf = opts.minConfidence || 0;
    var now = _now();

    var result = [];
    var rkeys = Object.keys(rings);
    for (var i = 0; i < rkeys.length; i++) {
      var r = rings[rkeys[i]];
      var conf = applyDecay ? _decayedConfidence(r.confidence, now - r.updatedAt) : r.confidence;
      if (conf >= minConf) {
        result.push({
          id: r.id,
          members: r.members.slice(),
          size: r.size,
          confidence: Math.round(conf * 1000) / 1000,
          ipDiversity: r.ipDiversity,
          evidence: Object.assign({}, r.evidence),
          createdAt: r.createdAt,
          updatedAt: r.updatedAt
        });
      }
    }

    result.sort(function (a, b) { return b.confidence - a.confidence; });
    return result;
  }

  /**
   * Check if a session belongs to any known ring.
   * Uses the sessionToRings reverse index for O(1) lookup instead of
   * scanning every ring's member list (previously O(rings × members)).
   * @param {string} sessionId
   * @returns {Array} rings containing this session
   */
  function checkSession(sessionId) {
    var found = [];
    var ringIds = sessionToRings[sessionId];
    if (!ringIds) return found;
    for (var i = 0; i < ringIds.length; i++) {
      var r = rings[ringIds[i]];
      if (r) {
        found.push({
          id: r.id,
          confidence: r.confidence,
          size: r.size,
          ipDiversity: r.ipDiversity
        });
      }
    }
    return found;
  }

  /**
   * Remove a ring by ID.
   */
  function removeRing(ringId) {
    var r = rings[ringId];
    if (r) {
      // Clean up reverse index
      for (var i = 0; i < r.members.length; i++) {
        var rids = sessionToRings[r.members[i]];
        if (rids) {
          var idx = rids.indexOf(ringId);
          if (idx !== -1) rids.splice(idx, 1);
          if (rids.length === 0) delete sessionToRings[r.members[i]];
        }
      }
      delete rings[ringId];
      ringCount--;
      return true;
    }
    return false;
  }

  /**
   * Clear all rings.
   */
  function clearRings() {
    rings = Object.create(null);
    ringCount = 0;
    sessionToRings = Object.create(null);
  }

  /**
   * Generate a summary report of all detected fraud rings.
   * @returns {object}
   */
  function report() {
    var ringList = listRings();
    var totalMembers = 0;
    var allIps = Object.create(null);

    for (var i = 0; i < ringList.length; i++) {
      totalMembers += ringList[i].size;
      for (var j = 0; j < ringList[i].members.length; j++) {
        var sid = ringList[i].members[j];
        if (sessions[sid] && sessions[sid].ip) {
          allIps[sessions[sid].ip] = true;
        }
      }
    }

    return {
      totalRings: ringList.length,
      totalMembers: totalMembers,
      uniqueIps: Object.keys(allIps).length,
      totalSessions: sessionCount,
      coverageRate: sessionCount > 0 ? Math.round((totalMembers / sessionCount) * 1000) / 1000 : 0,
      highConfidenceRings: ringList.filter(function (r) { return r.confidence >= 0.85; }).length,
      rings: ringList
    };
  }

  /**
   * Export all data as JSON-serializable object.
   * Strips internal cached distribution fields (_timingDist, _responseDist,
   * _successRate) to keep the export payload lean — they are recomputed
   * on import/addSession.
   */
  function exportData() {
    var exportedSessions = Object.create(null);
    var skeys = Object.keys(sessions);
    for (var i = 0; i < skeys.length; i++) {
      var s = sessions[skeys[i]];
      exportedSessions[skeys[i]] = {
        id: s.id,
        ip: s.ip,
        userAgent: s.userAgent,
        solves: s.solves,
        signals: s.signals,
        addedAt: s.addedAt,
        updatedAt: s.updatedAt
      };
    }
    return {
      sessions: exportedSessions,
      rings: JSON.parse(JSON.stringify(rings)),
      options: {
        similarityThreshold: similarityThreshold,
        minRingSize: minRingSize,
        maxSessions: maxSessions,
        maxRings: maxRings,
        timeWindowMs: timeWindowMs,
        decayHalfLifeMs: decayHalfLifeMs
      }
    };
  }

  /**
   * Import previously exported data.
   */
  /**
   * Reject keys that could cause prototype pollution (CWE-1321).
   * @param {string} key
   * @returns {boolean} true if safe
   */
  function _isSafeKey(key) {
    return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';
  }

  function importData(data) {
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid import data');
    }
    if (data.sessions && typeof data.sessions === 'object' && !Array.isArray(data.sessions)) {
      var skeys = Object.keys(data.sessions);
      // Sort by addedAt so we keep the most recent sessions when truncating
      skeys.sort(function (a, b) {
        var ta = (data.sessions[a] && data.sessions[a].addedAt) || 0;
        var tb = (data.sessions[b] && data.sessions[b].addedAt) || 0;
        return ta - tb;
      });
      for (var i = 0; i < skeys.length; i++) {
        if (!_isSafeKey(skeys[i])) continue;
        var imported = data.sessions[skeys[i]];
        if (!imported || typeof imported !== 'object') continue;
        sessions[skeys[i]] = imported;
        _precomputeDistributions(sessions[skeys[i]]);
        sessionInsertionOrder.push(skeys[i]);
      }
      sessionCount = Object.keys(sessions).length;
      // Enforce maxSessions: evict oldest entries to honour the limit
      while (sessionCount > maxSessions && sessionInsertionOrder.length > 0) {
        var evictId = sessionInsertionOrder.shift();
        if (sessions[evictId]) {
          if (sessionToRings[evictId]) delete sessionToRings[evictId];
          delete sessions[evictId];
          sessionCount--;
        }
      }
    }
    if (data.rings && typeof data.rings === 'object' && !Array.isArray(data.rings)) {
      var rkeys = Object.keys(data.rings);
      // Advance nextRingId past any imported ring IDs to prevent collisions
      for (var ri = 0; ri < rkeys.length; ri++) {
        var num = parseInt(rkeys[ri].replace('ring_', ''), 10);
        if (!isNaN(num) && num >= nextRingId) nextRingId = num + 1;
      }
      for (var j = 0; j < rkeys.length; j++) {
        if (!_isSafeKey(rkeys[j])) continue;
        var ring = data.rings[rkeys[j]];
        if (!ring || typeof ring !== 'object') continue;
        rings[rkeys[j]] = ring;
        // Rebuild reverse index
        var members = ring.members;
        if (Array.isArray(members)) {
          for (var m = 0; m < members.length; m++) {
            if (typeof members[m] === 'string' && _isSafeKey(members[m])) {
              if (!sessionToRings[members[m]]) sessionToRings[members[m]] = [];
              sessionToRings[members[m]].push(rkeys[j]);
            }
          }
        }
      }
      ringCount = Object.keys(rings).length;
    }
  }

  /**
   * Get statistics about the detector state.
   */
  function stats() {
    return {
      sessions: sessionCount,
      rings: ringCount,
      options: {
        similarityThreshold: similarityThreshold,
        minRingSize: minRingSize,
        maxSessions: maxSessions,
        maxRings: maxRings,
        timeWindowMs: timeWindowMs,
        decayHalfLifeMs: decayHalfLifeMs
      }
    };
  }

  return {
    addSession: addSession,
    detect: detect,
    getRing: getRing,
    listRings: listRings,
    checkSession: checkSession,
    removeRing: removeRing,
    clearRings: clearRings,
    report: report,
    exportData: exportData,
    importData: importData,
    stats: stats
  };
}

module.exports = { createFraudRingDetector: createFraudRingDetector };
