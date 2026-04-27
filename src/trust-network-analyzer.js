"use strict";

// ── Trust Network Analyzer ─────────────────────────────────────────
// Models trust relationships between sessions, detects Sybil attacks
// (coordinated fake sessions from a single entity), and autonomously
// propagates trust scores through a session graph.

var _shared = require('./shared-utils');
var LruTracker = _shared.LruTracker;
var _now = _shared._now;
var _clamp = _shared._clamp;

/**
 * createTrustNetworkAnalyzer — Builds a graph of session relationships,
 * propagates trust via iterative label propagation, and detects Sybil
 * clusters using behavioral similarity, timing correlation, and IP/fingerprint
 * overlap.
 *
 * @param {Object} [options]
 * @param {number} [options.maxNodes=2000]       Max tracked sessions
 * @param {number} [options.propagationRounds=5] Trust propagation iterations
 * @param {number} [options.sybilThreshold=0.75] Similarity threshold for Sybil edge
 * @param {number} [options.decayPerHour=0.02]   Trust decay rate per hour of inactivity
 * @param {number} [options.minClusterSize=3]    Min nodes to flag as Sybil cluster
 * @param {number} [options.maxEdgesPerNode=50]  Max edges per node
 * @param {number} [options.dampingFactor=0.85]  PageRank-style damping for propagation
 * @returns {Object} Trust network analyzer instance
 */
function createTrustNetworkAnalyzer(options) {
  options = options || {};

  var maxNodes = options.maxNodes > 0 ? options.maxNodes : 2000;
  var propagationRounds = options.propagationRounds > 0 ? options.propagationRounds : 5;
  var sybilThreshold = typeof options.sybilThreshold === "number" ? options.sybilThreshold : 0.75;
  var decayPerHour = typeof options.decayPerHour === "number" ? options.decayPerHour : 0.02;
  var minClusterSize = options.minClusterSize > 0 ? options.minClusterSize : 3;
  var maxEdgesPerNode = options.maxEdgesPerNode > 0 ? options.maxEdgesPerNode : 50;
  var dampingFactor = typeof options.dampingFactor === "number" ? options.dampingFactor : 0.85;

  // ── Node store ───────────────────────────────────────────────
  // Each node: { id, trust, ip, fingerprint, solves, timing[], behavioral{}, edges[], lastSeen, flagged }
  var nodes = Object.create(null);
  var nodeCount = 0;
  var lru = new LruTracker();
  var sybilClusters = [];
  var eventLog = [];
  var maxEventLog = 500;
  var autoMonitor = false;
  var monitorInterval = null;
  var onAlert = null;

  function _log(type, msg, data) {
    var entry = { ts: _now(), type: type, message: msg };
    if (data) entry.data = data;
    eventLog.push(entry);
    if (eventLog.length > maxEventLog) eventLog.shift();
    if (onAlert && (type === "sybil" || type === "alert")) {
      onAlert(entry);
    }
  }

  // ── Node management ──────────────────────────────────────────

  function addNode(id, meta) {
    meta = meta || {};
    if (nodes[id]) {
      // Update existing
      var n = nodes[id];
      if (meta.ip) n.ip = meta.ip;
      if (meta.fingerprint) n.fingerprint = meta.fingerprint;
      if (meta.trust != null) n.trust = _clamp(meta.trust, 0, 1);
      n.lastSeen = _now();
      lru.touch(id);
      return n;
    }
    // Evict if at capacity
    while (nodeCount >= maxNodes) {
      var oldest = lru.evictOldest();
      if (!oldest) break;
      _removeNode(oldest);
    }
    var node = {
      id: id,
      trust: meta.trust != null ? _clamp(meta.trust, 0, 1) : 0.5,
      ip: meta.ip || null,
      fingerprint: meta.fingerprint || null,
      solves: 0,
      timing: [],
      behavioral: {
        avgSolveMs: 0,
        mouseEntropy: 0,
        keystrokePattern: 0,
        scrollBehavior: 0
      },
      edges: [],
      lastSeen: _now(),
      flagged: false
    };
    nodes[id] = node;
    nodeCount++;
    lru.push(id);
    return node;
  }

  function _removeNode(id) {
    if (!nodes[id]) return;
    // Remove edges pointing to this node from neighbors
    var n = nodes[id];
    for (var i = 0; i < n.edges.length; i++) {
      var neighbor = nodes[n.edges[i].target];
      if (neighbor) {
        neighbor.edges = neighbor.edges.filter(function(e) { return e.target !== id; });
      }
    }
    delete nodes[id];
    nodeCount--;
    lru.remove(id);
  }

  function getNode(id) {
    return nodes[id] || null;
  }

  // ── Record solve event ───────────────────────────────────────

  function recordSolve(id, solveData) {
    solveData = solveData || {};
    var n = nodes[id];
    if (!n) n = addNode(id, solveData);

    n.solves++;
    n.lastSeen = _now();
    lru.touch(id);

    if (solveData.solveMs > 0) {
      n.timing.push(solveData.solveMs);
      if (n.timing.length > 100) n.timing.shift();
      // Update rolling average
      var sum = 0;
      for (var i = 0; i < n.timing.length; i++) sum += n.timing[i];
      n.behavioral.avgSolveMs = sum / n.timing.length;
    }
    if (typeof solveData.mouseEntropy === "number") n.behavioral.mouseEntropy = solveData.mouseEntropy;
    if (typeof solveData.keystrokePattern === "number") n.behavioral.keystrokePattern = solveData.keystrokePattern;
    if (typeof solveData.scrollBehavior === "number") n.behavioral.scrollBehavior = solveData.scrollBehavior;

    // Auto-discover edges based on similarity
    _discoverEdges(id);

    return n;
  }

  // ── Edge management ──────────────────────────────────────────

  function _behavioralSimilarity(a, b) {
    var dims = ["avgSolveMs", "mouseEntropy", "keystrokePattern", "scrollBehavior"];
    var dotProd = 0, magA = 0, magB = 0;
    for (var i = 0; i < dims.length; i++) {
      var va = a.behavioral[dims[i]] || 0;
      var vb = b.behavioral[dims[i]] || 0;
      dotProd += va * vb;
      magA += va * va;
      magB += vb * vb;
    }
    magA = Math.sqrt(magA);
    magB = Math.sqrt(magB);
    if (magA === 0 || magB === 0) return 0;
    return dotProd / (magA * magB);
  }

  function _timingCorrelation(a, b) {
    if (a.timing.length < 3 || b.timing.length < 3) return 0;
    // Pearson correlation on overlapping timing windows
    var len = Math.min(a.timing.length, b.timing.length, 20);
    var ta = a.timing.slice(-len);
    var tb = b.timing.slice(-len);
    var meanA = 0, meanB = 0;
    for (var i = 0; i < len; i++) { meanA += ta[i]; meanB += tb[i]; }
    meanA /= len; meanB /= len;
    var num = 0, denA = 0, denB = 0;
    for (var j = 0; j < len; j++) {
      var da = ta[j] - meanA, db = tb[j] - meanB;
      num += da * db;
      denA += da * da;
      denB += db * db;
    }
    if (denA === 0 || denB === 0) return 0;
    return num / Math.sqrt(denA * denB);
  }

  function _computeSimilarity(a, b) {
    var score = 0;
    var factors = 0;

    // IP match (strong signal)
    if (a.ip && b.ip && a.ip === b.ip) { score += 0.9; factors++; }
    else { factors++; } // still count as factor

    // Fingerprint match
    if (a.fingerprint && b.fingerprint && a.fingerprint === b.fingerprint) { score += 0.95; factors++; }
    else { factors++; }

    // Behavioral similarity
    var bSim = _behavioralSimilarity(a, b);
    score += bSim;
    factors++;

    // Timing correlation
    var tCorr = Math.max(0, _timingCorrelation(a, b));
    score += tCorr;
    factors++;

    return factors > 0 ? score / factors : 0;
  }

  function _discoverEdges(id) {
    var n = nodes[id];
    if (!n) return;
    var ids = Object.keys(nodes);
    for (var i = 0; i < ids.length; i++) {
      if (ids[i] === id) continue;
      var other = nodes[ids[i]];
      if (!other) continue;
      var sim = _computeSimilarity(n, other);
      if (sim >= sybilThreshold * 0.5) { // lower threshold for edge, higher for sybil
        _addEdge(id, ids[i], sim);
      }
    }
  }

  function _addEdge(fromId, toId, weight) {
    var a = nodes[fromId], b = nodes[toId];
    if (!a || !b) return;

    // Check if edge already exists, update weight
    for (var i = 0; i < a.edges.length; i++) {
      if (a.edges[i].target === toId) {
        a.edges[i].weight = weight;
        // Mirror
        for (var j = 0; j < b.edges.length; j++) {
          if (b.edges[j].target === fromId) b.edges[j].weight = weight;
        }
        return;
      }
    }

    if (a.edges.length >= maxEdgesPerNode || b.edges.length >= maxEdgesPerNode) return;

    a.edges.push({ target: toId, weight: weight });
    b.edges.push({ target: fromId, weight: weight });
  }

  // ── Trust propagation ────────────────────────────────────────

  function propagateTrust() {
    var ids = Object.keys(nodes);
    if (ids.length === 0) return;

    for (var round = 0; round < propagationRounds; round++) {
      var newTrust = Object.create(null);

      for (var i = 0; i < ids.length; i++) {
        var n = nodes[ids[i]];
        if (!n) continue;
        if (n.edges.length === 0) {
          newTrust[ids[i]] = n.trust;
          continue;
        }

        // Weighted average of neighbor trust
        var neighborSum = 0, weightSum = 0;
        for (var e = 0; e < n.edges.length; e++) {
          var neighbor = nodes[n.edges[e].target];
          if (!neighbor) continue;
          neighborSum += neighbor.trust * n.edges[e].weight;
          weightSum += n.edges[e].weight;
        }

        var neighborAvg = weightSum > 0 ? neighborSum / weightSum : n.trust;
        // PageRank-style: damping * neighborAvg + (1-damping) * ownTrust
        newTrust[ids[i]] = dampingFactor * neighborAvg + (1 - dampingFactor) * n.trust;
      }

      // Apply
      for (var j = 0; j < ids.length; j++) {
        if (newTrust[ids[j]] != null && nodes[ids[j]]) {
          nodes[ids[j]].trust = _clamp(newTrust[ids[j]], 0, 1);
        }
      }
    }

    // Apply time decay
    var now = _now();
    for (var k = 0; k < ids.length; k++) {
      var node = nodes[ids[k]];
      if (!node) continue;
      var hoursInactive = (now - node.lastSeen) / 3600000;
      if (hoursInactive > 0) {
        var decay = Math.max(0, 1 - decayPerHour * hoursInactive);
        node.trust = _clamp(node.trust * decay, 0, 1);
      }
    }

    _log("propagation", "Trust propagated across " + ids.length + " nodes (" + propagationRounds + " rounds)");
  }

  // ── Sybil detection ──────────────────────────────────────────

  function detectSybilClusters() {
    var ids = Object.keys(nodes);
    var visited = Object.create(null);
    var clusters = [];

    // BFS to find connected components with high similarity
    for (var i = 0; i < ids.length; i++) {
      if (visited[ids[i]]) continue;
      var cluster = [];
      var queue = [ids[i]];
      visited[ids[i]] = true;

      while (queue.length > 0) {
        var current = queue.shift();
        var n = nodes[current];
        if (!n) continue;
        cluster.push(current);

        for (var e = 0; e < n.edges.length; e++) {
          var edge = n.edges[e];
          if (visited[edge.target]) continue;
          if (edge.weight >= sybilThreshold) {
            visited[edge.target] = true;
            queue.push(edge.target);
          }
        }
      }

      if (cluster.length >= minClusterSize) {
        // Calculate cluster metrics
        var avgTrust = 0, avgSimilarity = 0, edgeCount = 0;
        var ips = Object.create(null), fps = Object.create(null);
        for (var c = 0; c < cluster.length; c++) {
          var cn = nodes[cluster[c]];
          if (!cn) continue;
          avgTrust += cn.trust;
          if (cn.ip) ips[cn.ip] = (ips[cn.ip] || 0) + 1;
          if (cn.fingerprint) fps[cn.fingerprint] = (fps[cn.fingerprint] || 0) + 1;
          for (var ce = 0; ce < cn.edges.length; ce++) {
            if (cluster.indexOf(cn.edges[ce].target) >= 0) {
              avgSimilarity += cn.edges[ce].weight;
              edgeCount++;
            }
          }
        }
        avgTrust /= cluster.length;
        avgSimilarity = edgeCount > 0 ? avgSimilarity / edgeCount : 0;

        // Confidence based on density and similarity
        var maxEdges = cluster.length * (cluster.length - 1);
        var density = maxEdges > 0 ? edgeCount / maxEdges : 0;
        var confidence = _clamp((avgSimilarity * 0.6 + density * 0.4), 0, 1);

        var sybilCluster = {
          id: "sybil-" + Date.now() + "-" + clusters.length,
          nodes: cluster,
          size: cluster.length,
          avgTrust: Math.round(avgTrust * 1000) / 1000,
          avgSimilarity: Math.round(avgSimilarity * 1000) / 1000,
          density: Math.round(density * 1000) / 1000,
          confidence: Math.round(confidence * 1000) / 1000,
          sharedIPs: Object.keys(ips).filter(function(ip) { return ips[ip] > 1; }),
          sharedFingerprints: Object.keys(fps).filter(function(fp) { return fps[fp] > 1; }),
          detectedAt: _now()
        };

        clusters.push(sybilCluster);

        // Flag nodes in cluster
        for (var f = 0; f < cluster.length; f++) {
          if (nodes[cluster[f]]) {
            nodes[cluster[f]].flagged = true;
            // Penalize trust
            nodes[cluster[f]].trust = _clamp(nodes[cluster[f]].trust * (1 - confidence * 0.5), 0, 1);
          }
        }

        _log("sybil", "Sybil cluster detected: " + cluster.length + " nodes, confidence=" + sybilCluster.confidence, {
          clusterId: sybilCluster.id,
          size: cluster.length
        });
      }
    }

    sybilClusters = clusters;
    return clusters;
  }

  // ── Network health metrics ───────────────────────────────────

  function getNetworkHealth() {
    var ids = Object.keys(nodes);
    if (ids.length === 0) {
      return { nodeCount: 0, edgeCount: 0, avgTrust: 0, flaggedCount: 0, density: 0, clusters: 0, healthScore: 1 };
    }
    var totalTrust = 0, totalEdges = 0, flagged = 0;
    for (var i = 0; i < ids.length; i++) {
      var n = nodes[ids[i]];
      if (!n) continue;
      totalTrust += n.trust;
      totalEdges += n.edges.length;
      if (n.flagged) flagged++;
    }
    var edgeCount = totalEdges / 2; // undirected
    var maxEdges = ids.length * (ids.length - 1) / 2;
    var density = maxEdges > 0 ? edgeCount / maxEdges : 0;
    var avgTrust = totalTrust / ids.length;
    var flaggedRatio = flagged / ids.length;

    // Health score: high trust, low flagged, moderate density
    var healthScore = _clamp(avgTrust * 0.4 + (1 - flaggedRatio) * 0.4 + (1 - Math.min(density * 5, 1)) * 0.2, 0, 1);

    return {
      nodeCount: ids.length,
      edgeCount: Math.round(edgeCount),
      avgTrust: Math.round(avgTrust * 1000) / 1000,
      flaggedCount: flagged,
      density: Math.round(density * 1000) / 1000,
      clusters: sybilClusters.length,
      healthScore: Math.round(healthScore * 1000) / 1000
    };
  }

  // ── Autonomous recommendations ───────────────────────────────

  function getRecommendations() {
    var health = getNetworkHealth();
    var recs = [];

    if (health.flaggedCount > 0) {
      recs.push({
        severity: health.flaggedCount > health.nodeCount * 0.3 ? "critical" : "warning",
        action: "investigate_sybil",
        message: health.flaggedCount + " sessions flagged as potential Sybil nodes. Review and consider blocking.",
        detail: "Flagged ratio: " + Math.round(health.flaggedCount / Math.max(health.nodeCount, 1) * 100) + "%"
      });
    }

    if (health.density > 0.5) {
      recs.push({
        severity: "warning",
        action: "suspicious_density",
        message: "Network density unusually high (" + Math.round(health.density * 100) + "%). Many sessions behave similarly.",
        detail: "Expected density < 10% for organic traffic"
      });
    }

    if (health.avgTrust < 0.3) {
      recs.push({
        severity: "critical",
        action: "low_trust_network",
        message: "Average network trust critically low (" + Math.round(health.avgTrust * 100) + "%). Increase CAPTCHA difficulty.",
        detail: "Consider enabling additional verification factors"
      });
    }

    if (sybilClusters.length > 3) {
      recs.push({
        severity: "critical",
        action: "multiple_sybil_clusters",
        message: sybilClusters.length + " Sybil clusters detected. Coordinated attack likely.",
        detail: "Enable rate limiting and IP-based throttling"
      });
    }

    if (health.nodeCount > maxNodes * 0.9) {
      recs.push({
        severity: "info",
        action: "capacity_warning",
        message: "Network approaching capacity (" + health.nodeCount + "/" + maxNodes + "). Old sessions being evicted.",
        detail: "Consider increasing maxNodes or reducing TTL"
      });
    }

    if (recs.length === 0) {
      recs.push({
        severity: "ok",
        action: "healthy",
        message: "Trust network healthy. No anomalies detected.",
        detail: "Trust avg: " + Math.round(health.avgTrust * 100) + "%, " + health.nodeCount + " active sessions"
      });
    }

    return recs;
  }

  // ── Auto-monitor ─────────────────────────────────────────────

  function startAutoMonitor(intervalMs, callback) {
    if (autoMonitor) stopAutoMonitor();
    intervalMs = intervalMs || 30000;
    onAlert = callback || null;
    autoMonitor = true;
    monitorInterval = setInterval(function() {
      propagateTrust();
      detectSybilClusters();
      var recs = getRecommendations();
      var critical = recs.filter(function(r) { return r.severity === "critical"; });
      if (critical.length > 0 && onAlert) {
        onAlert({ ts: _now(), type: "alert", recommendations: critical });
      }
    }, intervalMs);
    _log("monitor", "Auto-monitor started (interval=" + intervalMs + "ms)");
  }

  function stopAutoMonitor() {
    if (monitorInterval) clearInterval(monitorInterval);
    monitorInterval = null;
    autoMonitor = false;
    _log("monitor", "Auto-monitor stopped");
  }

  // ── Export ───────────────────────────────────────────────────

  function exportState() {
    var ids = Object.keys(nodes);
    var nodesArr = [];
    for (var i = 0; i < ids.length; i++) {
      var n = nodes[ids[i]];
      if (!n) continue;
      nodesArr.push({
        id: n.id,
        trust: n.trust,
        ip: n.ip,
        fingerprint: n.fingerprint,
        solves: n.solves,
        behavioral: Object.assign({}, n.behavioral),
        edges: n.edges.slice(),
        flagged: n.flagged,
        lastSeen: n.lastSeen
      });
    }
    return {
      nodes: nodesArr,
      clusters: sybilClusters.slice(),
      health: getNetworkHealth(),
      recommendations: getRecommendations(),
      eventLog: eventLog.slice(-100),
      config: {
        maxNodes: maxNodes,
        propagationRounds: propagationRounds,
        sybilThreshold: sybilThreshold,
        decayPerHour: decayPerHour,
        minClusterSize: minClusterSize,
        dampingFactor: dampingFactor
      }
    };
  }

  function importState(data) {
    if (!data || !Array.isArray(data.nodes)) return false;
    // Clear current
    nodes = Object.create(null);
    nodeCount = 0;
    lru = new LruTracker();

    for (var i = 0; i < data.nodes.length && i < maxNodes; i++) {
      var d = data.nodes[i];
      var n = addNode(d.id, { trust: d.trust, ip: d.ip, fingerprint: d.fingerprint });
      n.solves = d.solves || 0;
      n.behavioral = d.behavioral || n.behavioral;
      n.flagged = d.flagged || false;
      n.lastSeen = d.lastSeen || _now();
    }
    // Restore edges
    for (var j = 0; j < data.nodes.length && j < maxNodes; j++) {
      var dn = data.nodes[j];
      if (dn.edges && nodes[dn.id]) {
        for (var e = 0; e < dn.edges.length; e++) {
          if (nodes[dn.edges[e].target]) {
            _addEdge(dn.id, dn.edges[e].target, dn.edges[e].weight);
          }
        }
      }
    }
    if (data.clusters) sybilClusters = data.clusters;
    _log("import", "State imported: " + data.nodes.length + " nodes");
    return true;
  }

  // ── Reset ────────────────────────────────────────────────────

  function reset() {
    stopAutoMonitor();
    nodes = Object.create(null);
    nodeCount = 0;
    lru = new LruTracker();
    sybilClusters = [];
    eventLog = [];
    _log("reset", "Trust network reset");
  }

  return {
    addNode: addNode,
    getNode: getNode,
    recordSolve: recordSolve,
    propagateTrust: propagateTrust,
    detectSybilClusters: detectSybilClusters,
    getNetworkHealth: getNetworkHealth,
    getRecommendations: getRecommendations,
    startAutoMonitor: startAutoMonitor,
    stopAutoMonitor: stopAutoMonitor,
    exportState: exportState,
    importState: importState,
    reset: reset
  };
}

module.exports = { createTrustNetworkAnalyzer: createTrustNetworkAnalyzer };
