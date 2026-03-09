/**
 * GeoRiskScorer — Geographic risk analysis for CAPTCHA attempts.
 *
 * Scores requests based on geographic signals: country risk tiers,
 * IP-to-region velocity (impossible travel), datacenter/proxy detection
 * heuristics, geo-clustering anomalies, and per-region solve-rate baselines.
 *
 * No external dependencies — works with IP metadata you supply.
 *
 * @example
 *   var scorer = createGeoRiskScorer({ highRiskCountries: ['XX'] });
 *   var result = scorer.score({
 *     ip: '203.0.113.42',
 *     country: 'US',
 *     region: 'CA',
 *     city: 'San Francisco',
 *     lat: 37.77,
 *     lon: -122.42,
 *     isProxy: false,
 *     isDatacenter: false,
 *     timestamp: Date.now()
 *   });
 *   // result => { score: 0.15, level: 'low', factors: [...], action: 'allow' }
 */

"use strict";

// ── Haversine distance (km) ─────────────────────────────────────────
function _haversineKm(lat1, lon1, lat2, lon2) {
  var R = 6371;
  var dLat = (lat2 - lat1) * Math.PI / 180;
  var dLon = (lon2 - lon1) * Math.PI / 180;
  var a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// ── Default risk tiers ──────────────────────────────────────────────
var DEFAULT_HIGH_RISK = ["CN", "RU", "KP", "IR", "NG", "VN", "PK", "BD"];
var DEFAULT_MEDIUM_RISK = ["BR", "IN", "ID", "PH", "UA", "RO", "TH", "EG"];

// ── Thresholds ──────────────────────────────────────────────────────
var IMPOSSIBLE_TRAVEL_SPEED_KMH = 900; // faster than commercial flight
var SUSPICIOUS_TRAVEL_SPEED_KMH = 300;
var VELOCITY_WINDOW_MS = 3600000; // 1 hour

function createGeoRiskScorer(options) {
  options = options || {};

  var highRisk = options.highRiskCountries || DEFAULT_HIGH_RISK;
  var mediumRisk = options.mediumRiskCountries || DEFAULT_MEDIUM_RISK;
  var impossibleSpeedKmh = options.impossibleTravelSpeedKmh || IMPOSSIBLE_TRAVEL_SPEED_KMH;
  var suspiciousSpeedKmh = options.suspiciousTravelSpeedKmh || SUSPICIOUS_TRAVEL_SPEED_KMH;
  var velocityWindowMs = options.velocityWindowMs || VELOCITY_WINDOW_MS;
  var maxHistory = options.maxHistory || 500;
  var maxTrackedIPs = options.maxTrackedIPs || 10000;
  var maxTrackedSessions = options.maxTrackedSessions || 10000;
  var maxBlockedIPs = options.maxBlockedIPs || 50000;
  var maxAllowedIPs = options.maxAllowedIPs || 50000;
  var blocklistTTLMs = options.blocklistTTLMs || 86400000; // 24h default

  // Thresholds for action mapping
  var thresholds = options.thresholds || {};
  var blockThreshold = thresholds.block || 0.8;
  var challengeThreshold = thresholds.challenge || 0.5;
  var warnThreshold = thresholds.warn || 0.3;

  // IP history for velocity checks: Map<ip, {entries, lastAccess}>
  // Using Map for insertion-order iteration (LRU eviction)
  var _ipHistory = new Map();
  // Session history for geo-hopping: Map<sessionId, {entries, lastAccess}>
  var _sessionGeo = new Map();
  // Regional stats: { country: { attempts, solves } }
  var _regionStats = Object.create(null);
  // Custom blocklist/allowlist with TTL: Map<ip, timestamp>
  var _blockedIPs = new Map();
  var _allowedIPs = new Map();
  // Counter for throttling cleanup sweeps
  var _scoresSinceCleanup = 0;
  var CLEANUP_INTERVAL = 1000; // run cleanup every N scores

  var _totalScored = 0;
  var _totalBlocked = 0;
  var _totalChallenged = 0;

  // ── Helpers ──────────────────────────────────────────────────────

  function _clamp01(v) { return Math.max(0, Math.min(1, v)); }

  function _pushCapped(arr, item, cap) {
    arr.push(item);
    if (arr.length > cap) {
      // Splice from front in one call instead of repeated shift() — O(n) once vs O(k*n)
      arr.splice(0, arr.length - cap);
    }
  }

  /** Evict oldest entries from a Map when it exceeds maxSize. */
  function _evictLRU(map, maxSize) {
    if (map.size <= maxSize) return;
    var toDelete = map.size - maxSize;
    var iter = map.keys();
    for (var i = 0; i < toDelete; i++) {
      map.delete(iter.next().value);
    }
  }

  /** Remove expired entries (value < now) from a timestamp Map. */
  function _expireTTL(map, now) {
    var keysToDelete = [];
    map.forEach(function(ts, key) {
      if (ts < now) keysToDelete.push(key);
    });
    for (var i = 0; i < keysToDelete.length; i++) {
      map.delete(keysToDelete[i]);
    }
  }

  /** Periodic cleanup — called every CLEANUP_INTERVAL scores. */
  function _maybeCleanup() {
    _scoresSinceCleanup++;
    if (_scoresSinceCleanup < CLEANUP_INTERVAL) return;
    _scoresSinceCleanup = 0;
    var now = Date.now();
    _expireTTL(_blockedIPs, now);
    _expireTTL(_allowedIPs, now);
    _evictLRU(_ipHistory, maxTrackedIPs);
    _evictLRU(_sessionGeo, maxTrackedSessions);
  }

  function _toAction(score) {
    if (score >= blockThreshold) return "block";
    if (score >= challengeThreshold) return "challenge";
    if (score >= warnThreshold) return "warn";
    return "allow";
  }

  function _toLevel(score) {
    if (score >= blockThreshold) return "critical";
    if (score >= challengeThreshold) return "high";
    if (score >= warnThreshold) return "medium";
    return "low";
  }

  // ── Factor Evaluators ────────────────────────────────────────────

  function _countryRiskFactor(country) {
    if (!country) return { name: "country_unknown", score: 0.3, detail: "No country data" };
    var cc = country.toUpperCase();
    if (highRisk.indexOf(cc) !== -1) return { name: "country_high_risk", score: 0.4, detail: cc + " is high-risk" };
    if (mediumRisk.indexOf(cc) !== -1) return { name: "country_medium_risk", score: 0.2, detail: cc + " is medium-risk" };
    return { name: "country_ok", score: 0, detail: cc + " is low-risk" };
  }

  function _proxyFactor(meta) {
    var s = 0;
    var parts = [];
    if (meta.isProxy) { s += 0.35; parts.push("proxy"); }
    if (meta.isDatacenter) { s += 0.3; parts.push("datacenter"); }
    if (meta.isTor) { s += 0.4; parts.push("Tor"); }
    if (meta.isVpn) { s += 0.25; parts.push("VPN"); }
    if (s === 0) return { name: "proxy_none", score: 0, detail: "No proxy signals" };
    return { name: "proxy_detected", score: _clamp01(s), detail: parts.join(", ") + " detected" };
  }

  function _velocityFactor(ip, lat, lon, ts) {
    if (lat == null || lon == null || !ip) return null;
    var entry = _ipHistory.get(ip);
    var history = entry ? entry.entries : null;
    if (!history || history.length === 0) return null;
    var dominated = false;
    var worst = { name: "velocity_ok", score: 0, detail: "Normal travel speed" };
    for (var i = history.length - 1; i >= 0; i--) {
      var prev = history[i];
      if (ts - prev.ts > velocityWindowMs) break;
      var dt = (ts - prev.ts) / 3600000; // hours
      if (dt <= 0) continue;
      var dist = _haversineKm(prev.lat, prev.lon, lat, lon);
      var speed = dist / dt;
      if (speed > impossibleSpeedKmh) {
        return { name: "impossible_travel", score: 0.9, detail: Math.round(speed) + " km/h (" + Math.round(dist) + " km in " + Math.round(dt * 60) + " min)" };
      }
      if (speed > suspiciousSpeedKmh && !dominated) {
        worst = { name: "suspicious_travel", score: 0.4, detail: Math.round(speed) + " km/h" };
        dominated = true;
      }
    }
    return worst;
  }

  function _geoHoppingFactor(sessionId, country, ts) {
    if (!sessionId || !country) return null;
    var entry = _sessionGeo.get(sessionId);
    var hist = entry ? entry.entries : null;
    if (!hist || hist.length === 0) return null;
    var countries = Object.create(null);
    countries[country.toUpperCase()] = true;
    var recent = 0;
    for (var i = hist.length - 1; i >= 0; i--) {
      if (ts - hist[i].ts > velocityWindowMs) break;
      countries[hist[i].country] = true;
      recent++;
    }
    var uniqueCount = Object.keys(countries).length;
    if (uniqueCount >= 4) return { name: "geo_hopping_extreme", score: 0.8, detail: uniqueCount + " countries in window" };
    if (uniqueCount >= 3) return { name: "geo_hopping_high", score: 0.5, detail: uniqueCount + " countries in window" };
    if (uniqueCount >= 2) return { name: "geo_hopping_mild", score: 0.15, detail: uniqueCount + " countries in window" };
    return null;
  }

  function _regionalAnomalyFactor(country) {
    if (!country) return null;
    var cc = country.toUpperCase();
    var stats = _regionStats[cc];
    if (!stats || stats.attempts < 20) return null; // not enough data
    var solveRate = stats.solves / stats.attempts;
    if (solveRate < 0.1) return { name: "region_low_solve_rate", score: 0.35, detail: cc + " solve rate " + (solveRate * 100).toFixed(1) + "%" };
    if (solveRate < 0.3) return { name: "region_below_avg_solve", score: 0.15, detail: cc + " solve rate " + (solveRate * 100).toFixed(1) + "%" };
    return null;
  }

  // ── Main Scoring ─────────────────────────────────────────────────

  function score(meta) {
    if (!meta) throw new Error("GeoRiskScorer: meta object required");
    var ts = meta.timestamp || Date.now();
    var factors = [];

    // Allowlist/blocklist short-circuits
    var now = Date.now();
    if (meta.ip && _allowedIPs.has(meta.ip) && _allowedIPs.get(meta.ip) > now) {
      return { score: 0, level: "low", factors: [{ name: "ip_allowlisted", score: 0, detail: meta.ip }], action: "allow" };
    }
    if (meta.ip && _blockedIPs.has(meta.ip) && _blockedIPs.get(meta.ip) > now) {
      return { score: 1, level: "critical", factors: [{ name: "ip_blocklisted", score: 1, detail: meta.ip }], action: "block" };
    }
    // Clean up expired entries checked above
    if (meta.ip) {
      if (_allowedIPs.has(meta.ip) && _allowedIPs.get(meta.ip) <= now) _allowedIPs.delete(meta.ip);
      if (_blockedIPs.has(meta.ip) && _blockedIPs.get(meta.ip) <= now) _blockedIPs.delete(meta.ip);
    }

    // Evaluate all factors
    factors.push(_countryRiskFactor(meta.country));
    factors.push(_proxyFactor(meta));

    var vf = _velocityFactor(meta.ip, meta.lat, meta.lon, ts);
    if (vf) factors.push(vf);

    var ghf = _geoHoppingFactor(meta.sessionId, meta.country, ts);
    if (ghf) factors.push(ghf);

    var raf = _regionalAnomalyFactor(meta.country);
    if (raf) factors.push(raf);

    // Composite score: weighted max + average blend
    var maxScore = 0;
    var sum = 0;
    var count = 0;
    for (var i = 0; i < factors.length; i++) {
      if (factors[i].score > maxScore) maxScore = factors[i].score;
      sum += factors[i].score;
      count++;
    }
    var avg = count > 0 ? sum / count : 0;
    var composite = _clamp01(maxScore * 0.7 + avg * 0.3);

    var action = _toAction(composite);
    var level = _toLevel(composite);

    // Update history
    if (meta.ip && meta.lat != null && meta.lon != null) {
      var ipEntry = _ipHistory.get(meta.ip);
      if (!ipEntry) {
        ipEntry = { entries: [] };
      } else {
        // Re-insert to move to end (most recently used)
        _ipHistory.delete(meta.ip);
      }
      _pushCapped(ipEntry.entries, { lat: meta.lat, lon: meta.lon, ts: ts, country: (meta.country || "").toUpperCase() }, maxHistory);
      _ipHistory.set(meta.ip, ipEntry);
      _evictLRU(_ipHistory, maxTrackedIPs);
    }
    if (meta.sessionId && meta.country) {
      var sessEntry = _sessionGeo.get(meta.sessionId);
      if (!sessEntry) {
        sessEntry = { entries: [] };
      } else {
        _sessionGeo.delete(meta.sessionId);
      }
      _pushCapped(sessEntry.entries, { country: meta.country.toUpperCase(), ts: ts }, maxHistory);
      _sessionGeo.set(meta.sessionId, sessEntry);
      _evictLRU(_sessionGeo, maxTrackedSessions);
    }

    _totalScored++;
    if (action === "block") _totalBlocked++;
    if (action === "challenge") _totalChallenged++;

    _maybeCleanup();

    return { score: Math.round(composite * 1000) / 1000, level: level, factors: factors, action: action };
  }

  // ── Region Stats ─────────────────────────────────────────────────

  function recordAttempt(country, solved) {
    if (!country) return;
    var cc = country.toUpperCase();
    if (!_regionStats[cc]) _regionStats[cc] = { attempts: 0, solves: 0 };
    _regionStats[cc].attempts++;
    if (solved) _regionStats[cc].solves++;
  }

  function getRegionStats(country) {
    if (country) {
      var cc = country.toUpperCase();
      var s = _regionStats[cc];
      if (!s) return null;
      return {
        country: cc,
        attempts: s.attempts,
        solves: s.solves,
        solveRate: s.attempts > 0 ? Math.round((s.solves / s.attempts) * 1000) / 1000 : 0
      };
    }
    var result = [];
    var keys = Object.keys(_regionStats);
    for (var i = 0; i < keys.length; i++) {
      var st = _regionStats[keys[i]];
      result.push({
        country: keys[i],
        attempts: st.attempts,
        solves: st.solves,
        solveRate: st.attempts > 0 ? Math.round((st.solves / st.attempts) * 1000) / 1000 : 0
      });
    }
    result.sort(function (a, b) { return b.attempts - a.attempts; });
    return result;
  }

  // ── IP Management ────────────────────────────────────────────────

  function blockIP(ip, ttlMs) {
    var expiry = Date.now() + (ttlMs || blocklistTTLMs);
    _blockedIPs.set(ip, expiry);
    _evictLRU(_blockedIPs, maxBlockedIPs);
  }
  function allowIP(ip, ttlMs) {
    var expiry = Date.now() + (ttlMs || blocklistTTLMs);
    _allowedIPs.set(ip, expiry);
    _evictLRU(_allowedIPs, maxAllowedIPs);
  }
  function unblockIP(ip) { _blockedIPs.delete(ip); }
  function unallowIP(ip) { _allowedIPs.delete(ip); }
  function isBlocked(ip) {
    if (!_blockedIPs.has(ip)) return false;
    if (_blockedIPs.get(ip) < Date.now()) { _blockedIPs.delete(ip); return false; }
    return true;
  }
  function isAllowed(ip) {
    if (!_allowedIPs.has(ip)) return false;
    if (_allowedIPs.get(ip) < Date.now()) { _allowedIPs.delete(ip); return false; }
    return true;
  }

  // ── Batch Scoring ────────────────────────────────────────────────

  function scoreBatch(metas) {
    var results = [];
    for (var i = 0; i < metas.length; i++) {
      results.push(score(metas[i]));
    }
    return results;
  }

  // ── Risk Summary ─────────────────────────────────────────────────

  function summary() {
    return {
      totalScored: _totalScored,
      totalBlocked: _totalBlocked,
      totalChallenged: _totalChallenged,
      blockRate: _totalScored > 0 ? Math.round((_totalBlocked / _totalScored) * 1000) / 1000 : 0,
      challengeRate: _totalScored > 0 ? Math.round((_totalChallenged / _totalScored) * 1000) / 1000 : 0,
      trackedIPs: _ipHistory.size,
      trackedSessions: _sessionGeo.size,
      regionCount: Object.keys(_regionStats).length,
      blockedIPs: _blockedIPs.size,
      allowedIPs: _allowedIPs.size
    };
  }

  // ── Reset ────────────────────────────────────────────────────────

  function reset() {
    _ipHistory = new Map();
    _sessionGeo = new Map();
    _regionStats = Object.create(null);
    _blockedIPs = new Map();
    _allowedIPs = new Map();
    _totalScored = 0;
    _totalBlocked = 0;
    _totalChallenged = 0;
    _scoresSinceCleanup = 0;
  }

  /** Force a cleanup sweep — evict LRU entries and expire TTLs. */
  function cleanup() {
    var now = Date.now();
    _expireTTL(_blockedIPs, now);
    _expireTTL(_allowedIPs, now);
    _evictLRU(_ipHistory, maxTrackedIPs);
    _evictLRU(_sessionGeo, maxTrackedSessions);
  }

  return {
    score: score,
    scoreBatch: scoreBatch,
    recordAttempt: recordAttempt,
    getRegionStats: getRegionStats,
    blockIP: blockIP,
    allowIP: allowIP,
    unblockIP: unblockIP,
    unallowIP: unallowIP,
    isBlocked: isBlocked,
    isAllowed: isAllowed,
    summary: summary,
    reset: reset,
    cleanup: cleanup
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createGeoRiskScorer: createGeoRiskScorer };
}
