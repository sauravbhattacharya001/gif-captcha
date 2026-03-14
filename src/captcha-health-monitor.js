/**
 * CaptchaHealthMonitor — unified system health monitoring for gif-captcha.
 *
 * Aggregates signals from multiple subsystems (solve rates, response times,
 * pool levels, rate limiter pressure, bot detection rates, error counts)
 * into a single health status with configurable thresholds, alert history,
 * and actionable recommendations.
 *
 * Designed as the "ops dashboard heartbeat" — call monitor.check() periodically
 * and get a single health verdict: healthy / degraded / unhealthy / critical.
 *
 * Usage:
 *   var monitor = createCaptchaHealthMonitor({
 *     thresholds: { minSolveRate: 0.60, maxAvgResponseMs: 8000 }
 *   });
 *
 *   // Feed signals from other modules
 *   monitor.recordSolve({ solved: true, timeMs: 2100 });
 *   monitor.recordSolve({ solved: false, timeMs: 9500 });
 *   monitor.recordBotDetection({ blocked: true });
 *   monitor.recordPoolLevel({ available: 45, total: 100 });
 *   monitor.recordRateLimitHit({ key: '10.0.0.1' });
 *   monitor.recordError({ code: 'TIMEOUT', message: 'challenge generation timed out' });
 *
 *   var health = monitor.check();
 *   // health => {
 *   //   status: 'degraded',
 *   //   score: 62,
 *   //   signals: { solveRate: { ... }, responseTime: { ... }, ... },
 *   //   alerts: [ { level: 'warning', signal: 'solveRate', message: '...', ts: ... } ],
 *   //   recommendations: [ 'Solve rate (55%) is below 60% — check challenge difficulty' ],
 *   //   uptimeMs: 120000,
 *   //   checksPerformed: 5,
 *   //   lastCheckAt: 1710412800000
 *   // }
 *
 *   // Alert history
 *   var alerts = monitor.getAlerts({ level: 'critical', limit: 10 });
 *
 *   // Export/import for persistence
 *   var snapshot = monitor.exportJSON();
 *   var monitor2 = createCaptchaHealthMonitor();
 *   monitor2.importJSON(snapshot);
 *
 * @module captcha-health-monitor
 */

"use strict";

// ── Status Levels ────────────────────────────────────────────────────

var STATUS = Object.create(null);
STATUS.HEALTHY   = "healthy";
STATUS.DEGRADED  = "degraded";
STATUS.UNHEALTHY = "unhealthy";
STATUS.CRITICAL  = "critical";

var STATUS_RANK = Object.create(null);
STATUS_RANK[STATUS.HEALTHY]   = 0;
STATUS_RANK[STATUS.DEGRADED]  = 1;
STATUS_RANK[STATUS.UNHEALTHY] = 2;
STATUS_RANK[STATUS.CRITICAL]  = 3;

var ALERT_LEVEL = Object.create(null);
ALERT_LEVEL.INFO     = "info";
ALERT_LEVEL.WARNING  = "warning";
ALERT_LEVEL.CRITICAL = "critical";

// ── Signal Names ─────────────────────────────────────────────────────

var SIGNALS = Object.create(null);
SIGNALS.SOLVE_RATE      = "solveRate";
SIGNALS.RESPONSE_TIME   = "responseTime";
SIGNALS.POOL_LEVEL      = "poolLevel";
SIGNALS.BOT_RATE        = "botRate";
SIGNALS.RATE_LIMIT      = "rateLimitPressure";
SIGNALS.ERROR_RATE      = "errorRate";

// ── Default Thresholds ───────────────────────────────────────────────

var DEFAULT_THRESHOLDS = {
  // Solve rate: fraction of challenges solved successfully
  minSolveRate:         0.60,  // below = degraded
  criticalSolveRate:    0.30,  // below = critical

  // Average response time in ms
  maxAvgResponseMs:     8000,  // above = degraded
  criticalResponseMs:  15000,  // above = critical

  // Pool availability: fraction of challenges available
  minPoolLevel:         0.20,  // below = degraded
  criticalPoolLevel:    0.05,  // below = critical

  // Bot detection rate: fraction of checks that are bots
  maxBotRate:           0.40,  // above = degraded (under attack)
  criticalBotRate:      0.70,  // above = critical

  // Rate limit hit rate: fraction of requests that hit limits
  maxRateLimitRate:     0.15,  // above = degraded
  criticalRateLimitRate:0.40,  // above = critical

  // Error rate: fraction of operations that error
  maxErrorRate:         0.05,  // above = degraded
  criticalErrorRate:    0.15   // above = critical
};

var DEFAULT_WINDOW_MS     = 300000;  // 5 minutes
var DEFAULT_MAX_EVENTS    = 5000;
var DEFAULT_MAX_ALERTS    = 500;
var DEFAULT_MAX_CHECKS    = 1000;

// ── Helpers ──────────────────────────────────────────────────────────

function _now() { return Date.now(); }

function _pct(n, d) {
  return d === 0 ? 0 : n / d;
}

function _roundTo(v, decimals) {
  var f = Math.pow(10, decimals);
  return Math.round(v * f) / f;
}

function _evictOld(arr, cutoff) {
  while (arr.length > 0 && arr[0].ts < cutoff) {
    arr.shift();
  }
}

function _pruneToMax(arr, max) {
  if (arr.length > max) {
    arr.splice(0, arr.length - max);
  }
}

function _deepCopy(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function _merge(target, source) {
  for (var k in source) {
    if (Object.prototype.hasOwnProperty.call(source, k)) {
      target[k] = source[k];
    }
  }
  return target;
}

// ── Factory ──────────────────────────────────────────────────────────

/**
 * Create a new CAPTCHA health monitor.
 *
 * @param {Object} [options]
 * @param {Object} [options.thresholds]       Override default thresholds
 * @param {number} [options.windowMs=300000]  Rolling window for signal aggregation (ms)
 * @param {number} [options.maxEvents=5000]   Max events to keep per signal type
 * @param {number} [options.maxAlerts=500]    Max alerts to retain
 * @param {number} [options.maxChecks=1000]   Max check history entries
 * @param {Function} [options.nowFn]          Custom time function (for testing)
 * @returns {Object} Health monitor instance
 */
function createCaptchaHealthMonitor(options) {
  options = options || {};

  var thresholds = _merge(_deepCopy(DEFAULT_THRESHOLDS), options.thresholds || {});
  var windowMs   = options.windowMs  > 0 ? options.windowMs  : DEFAULT_WINDOW_MS;
  var maxEvents  = options.maxEvents > 0 ? options.maxEvents : DEFAULT_MAX_EVENTS;
  var maxAlerts  = options.maxAlerts > 0 ? options.maxAlerts : DEFAULT_MAX_ALERTS;
  var maxChecks  = options.maxChecks > 0 ? options.maxChecks : DEFAULT_MAX_CHECKS;
  var nowFn      = typeof options.nowFn === "function" ? options.nowFn : _now;

  // Event stores
  var solves      = [];  // { ts, solved, timeMs }
  var botChecks   = [];  // { ts, blocked }
  var poolSnapshots = []; // { ts, available, total }
  var rateLimitHits = []; // { ts, key }
  var errors      = [];  // { ts, code, message }
  var totalOps    = [];  // { ts }  -- all operations for error rate denominator

  // Alert history
  var alerts = [];

  // Check history
  var checkHistory = [];
  var checksPerformed = 0;
  var startedAt = nowFn();

  // ── Signal Computation ───────────────────────────────────────────

  function _windowCutoff() {
    return nowFn() - windowMs;
  }

  function _computeSolveRate() {
    var cutoff = _windowCutoff();
    var total = 0, solved = 0;
    for (var i = solves.length - 1; i >= 0; i--) {
      if (solves[i].ts < cutoff) break;
      total++;
      if (solves[i].solved) solved++;
    }
    var rate = _pct(solved, total);
    var status = STATUS.HEALTHY;
    if (total >= 3) {
      if (rate < thresholds.criticalSolveRate) status = STATUS.CRITICAL;
      else if (rate < thresholds.minSolveRate) status = STATUS.DEGRADED;
    }
    return {
      signal: SIGNALS.SOLVE_RATE,
      value: _roundTo(rate, 4),
      total: total,
      solved: solved,
      status: status,
      threshold: thresholds.minSolveRate,
      criticalThreshold: thresholds.criticalSolveRate
    };
  }

  function _computeResponseTime() {
    var cutoff = _windowCutoff();
    var times = [];
    for (var i = solves.length - 1; i >= 0; i--) {
      if (solves[i].ts < cutoff) break;
      if (solves[i].timeMs != null) times.push(solves[i].timeMs);
    }
    if (times.length === 0) {
      return {
        signal: SIGNALS.RESPONSE_TIME,
        value: 0,
        count: 0,
        p50: 0,
        p95: 0,
        p99: 0,
        status: STATUS.HEALTHY,
        threshold: thresholds.maxAvgResponseMs,
        criticalThreshold: thresholds.criticalResponseMs
      };
    }
    var sum = 0;
    for (var j = 0; j < times.length; j++) sum += times[j];
    var avg = sum / times.length;

    var sorted = times.slice().sort(function(a, b) { return a - b; });
    var p50 = _percentile(sorted, 50);
    var p95 = _percentile(sorted, 95);
    var p99 = _percentile(sorted, 99);

    var status = STATUS.HEALTHY;
    if (avg >= thresholds.criticalResponseMs) status = STATUS.CRITICAL;
    else if (avg >= thresholds.maxAvgResponseMs) status = STATUS.DEGRADED;

    return {
      signal: SIGNALS.RESPONSE_TIME,
      value: _roundTo(avg, 1),
      count: times.length,
      p50: _roundTo(p50, 1),
      p95: _roundTo(p95, 1),
      p99: _roundTo(p99, 1),
      status: status,
      threshold: thresholds.maxAvgResponseMs,
      criticalThreshold: thresholds.criticalResponseMs
    };
  }

  function _percentile(sorted, p) {
    if (sorted.length === 0) return 0;
    if (sorted.length === 1) return sorted[0];
    var idx = (p / 100) * (sorted.length - 1);
    var lo = Math.floor(idx);
    var hi = Math.ceil(idx);
    if (lo === hi) return sorted[lo];
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
  }

  function _computePoolLevel() {
    var cutoff = _windowCutoff();
    var latest = null;
    for (var i = poolSnapshots.length - 1; i >= 0; i--) {
      if (poolSnapshots[i].ts >= cutoff) {
        latest = poolSnapshots[i];
        break;
      }
    }
    if (!latest) {
      return {
        signal: SIGNALS.POOL_LEVEL,
        value: 1,
        available: 0,
        total: 0,
        status: STATUS.HEALTHY,
        threshold: thresholds.minPoolLevel,
        criticalThreshold: thresholds.criticalPoolLevel
      };
    }
    var level = latest.total > 0 ? latest.available / latest.total : 1;
    var status = STATUS.HEALTHY;
    if (level < thresholds.criticalPoolLevel) status = STATUS.CRITICAL;
    else if (level < thresholds.minPoolLevel) status = STATUS.DEGRADED;

    return {
      signal: SIGNALS.POOL_LEVEL,
      value: _roundTo(level, 4),
      available: latest.available,
      total: latest.total,
      status: status,
      threshold: thresholds.minPoolLevel,
      criticalThreshold: thresholds.criticalPoolLevel
    };
  }

  function _computeBotRate() {
    var cutoff = _windowCutoff();
    var total = 0, blocked = 0;
    for (var i = botChecks.length - 1; i >= 0; i--) {
      if (botChecks[i].ts < cutoff) break;
      total++;
      if (botChecks[i].blocked) blocked++;
    }
    var rate = _pct(blocked, total);
    var status = STATUS.HEALTHY;
    if (total >= 3) {
      if (rate >= thresholds.criticalBotRate) status = STATUS.CRITICAL;
      else if (rate >= thresholds.maxBotRate) status = STATUS.DEGRADED;
    }
    return {
      signal: SIGNALS.BOT_RATE,
      value: _roundTo(rate, 4),
      total: total,
      blocked: blocked,
      status: status,
      threshold: thresholds.maxBotRate,
      criticalThreshold: thresholds.criticalBotRate
    };
  }

  function _computeRateLimitPressure() {
    var cutoff = _windowCutoff();
    var hits = 0;
    for (var i = rateLimitHits.length - 1; i >= 0; i--) {
      if (rateLimitHits[i].ts < cutoff) break;
      hits++;
    }
    var ops = 0;
    for (var j = totalOps.length - 1; j >= 0; j--) {
      if (totalOps[j].ts < cutoff) break;
      ops++;
    }
    var rate = _pct(hits, ops);
    var status = STATUS.HEALTHY;
    if (ops >= 3) {
      if (rate >= thresholds.criticalRateLimitRate) status = STATUS.CRITICAL;
      else if (rate >= thresholds.maxRateLimitRate) status = STATUS.DEGRADED;
    }
    return {
      signal: SIGNALS.RATE_LIMIT,
      value: _roundTo(rate, 4),
      hits: hits,
      totalOps: ops,
      status: status,
      threshold: thresholds.maxRateLimitRate,
      criticalThreshold: thresholds.criticalRateLimitRate
    };
  }

  function _computeErrorRate() {
    var cutoff = _windowCutoff();
    var errCount = 0;
    for (var i = errors.length - 1; i >= 0; i--) {
      if (errors[i].ts < cutoff) break;
      errCount++;
    }
    var ops = 0;
    for (var j = totalOps.length - 1; j >= 0; j--) {
      if (totalOps[j].ts < cutoff) break;
      ops++;
    }
    var rate = _pct(errCount, ops);
    var status = STATUS.HEALTHY;
    if (ops >= 3) {
      if (rate >= thresholds.criticalErrorRate) status = STATUS.CRITICAL;
      else if (rate >= thresholds.maxErrorRate) status = STATUS.DEGRADED;
    }

    // Top error codes
    var codeCounts = Object.create(null);
    for (var k = errors.length - 1; k >= 0; k--) {
      if (errors[k].ts < cutoff) break;
      var c = errors[k].code || "UNKNOWN";
      codeCounts[c] = (codeCounts[c] || 0) + 1;
    }
    var topCodes = [];
    for (var code in codeCounts) {
      topCodes.push({ code: code, count: codeCounts[code] });
    }
    topCodes.sort(function(a, b) { return b.count - a.count; });

    return {
      signal: SIGNALS.ERROR_RATE,
      value: _roundTo(rate, 4),
      errors: errCount,
      totalOps: ops,
      topCodes: topCodes.slice(0, 5),
      status: status,
      threshold: thresholds.maxErrorRate,
      criticalThreshold: thresholds.criticalErrorRate
    };
  }

  // ── Health Score Computation ─────────────────────────────────────

  function _computeScore(signalResults) {
    var weights = Object.create(null);
    weights[SIGNALS.SOLVE_RATE]    = 25;
    weights[SIGNALS.RESPONSE_TIME] = 20;
    weights[SIGNALS.POOL_LEVEL]    = 15;
    weights[SIGNALS.BOT_RATE]      = 15;
    weights[SIGNALS.RATE_LIMIT]    = 10;
    weights[SIGNALS.ERROR_RATE]    = 15;

    var statusScores = Object.create(null);
    statusScores[STATUS.HEALTHY]   = 100;
    statusScores[STATUS.DEGRADED]  = 50;
    statusScores[STATUS.UNHEALTHY] = 25;
    statusScores[STATUS.CRITICAL]  = 0;

    var totalWeight = 0;
    var weightedScore = 0;

    for (var sig in signalResults) {
      if (!Object.prototype.hasOwnProperty.call(signalResults, sig)) continue;
      var w = weights[sig] || 10;
      totalWeight += w;
      weightedScore += w * (statusScores[signalResults[sig].status] || 0);
    }

    return totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 100;
  }

  function _worstStatus(signalResults) {
    var worst = STATUS.HEALTHY;
    for (var sig in signalResults) {
      if (!Object.prototype.hasOwnProperty.call(signalResults, sig)) continue;
      var s = signalResults[sig].status;
      if (STATUS_RANK[s] > STATUS_RANK[worst]) {
        worst = s;
      }
    }
    return worst;
  }

  // ── Recommendations Engine ───────────────────────────────────────

  function _generateRecommendations(signalResults) {
    var recs = [];
    var sr = signalResults[SIGNALS.SOLVE_RATE];
    if (sr && sr.status !== STATUS.HEALTHY && sr.total > 0) {
      var pctStr = Math.round(sr.value * 100) + "%";
      var thStr = Math.round(sr.threshold * 100) + "%";
      recs.push("Solve rate (" + pctStr + ") is below " + thStr +
        " \u2014 check challenge difficulty or consider easier alternatives");
    }

    var rt = signalResults[SIGNALS.RESPONSE_TIME];
    if (rt && rt.status !== STATUS.HEALTHY && rt.count > 0) {
      recs.push("Average response time (" + rt.value + "ms) exceeds " +
        rt.threshold + "ms \u2014 optimize challenge generation or increase pool size");
    }

    var pl = signalResults[SIGNALS.POOL_LEVEL];
    if (pl && pl.status !== STATUS.HEALTHY && pl.total > 0) {
      var lvl = Math.round(pl.value * 100) + "%";
      recs.push("Pool level (" + lvl + ") is low \u2014 trigger pool replenishment or increase generation rate");
    }

    var br = signalResults[SIGNALS.BOT_RATE];
    if (br && br.status !== STATUS.HEALTHY && br.total > 0) {
      var botPct = Math.round(br.value * 100) + "%";
      recs.push("Bot rate (" + botPct + ") is elevated \u2014 possible attack in progress; consider tightening rate limits");
    }

    var rl = signalResults[SIGNALS.RATE_LIMIT];
    if (rl && rl.status !== STATUS.HEALTHY && rl.totalOps > 0) {
      var rlPct = Math.round(rl.value * 100) + "%";
      recs.push("Rate limit trigger rate (" + rlPct + ") \u2014 review limit thresholds or investigate traffic spikes");
    }

    var er = signalResults[SIGNALS.ERROR_RATE];
    if (er && er.status !== STATUS.HEALTHY && er.totalOps > 0) {
      var erPct = Math.round(er.value * 100) + "%";
      var topMsg = "";
      if (er.topCodes && er.topCodes.length > 0) {
        topMsg = " (top: " + er.topCodes[0].code + " \u00d7 " + er.topCodes[0].count + ")";
      }
      recs.push("Error rate (" + erPct + ") is high" + topMsg +
        " \u2014 check logs for root cause");
    }

    return recs;
  }

  // ── Alert Management ─────────────────────────────────────────────

  function _emitAlerts(signalResults) {
    var ts = nowFn();
    var newAlerts = [];

    for (var sig in signalResults) {
      if (!Object.prototype.hasOwnProperty.call(signalResults, sig)) continue;
      var result = signalResults[sig];
      if (result.status === STATUS.CRITICAL) {
        newAlerts.push({
          level: ALERT_LEVEL.CRITICAL,
          signal: sig,
          message: sig + " is critical (value: " + result.value + ")",
          value: result.value,
          threshold: result.criticalThreshold,
          ts: ts
        });
      } else if (result.status === STATUS.DEGRADED) {
        newAlerts.push({
          level: ALERT_LEVEL.WARNING,
          signal: sig,
          message: sig + " is degraded (value: " + result.value + ")",
          value: result.value,
          threshold: result.threshold,
          ts: ts
        });
      }
    }

    for (var i = 0; i < newAlerts.length; i++) {
      alerts.push(newAlerts[i]);
    }
    _pruneToMax(alerts, maxAlerts);
    return newAlerts;
  }

  // ── Public: Record Events ────────────────────────────────────────

  function recordSolve(entry) {
    if (!entry || typeof entry !== "object") return;
    var ts = nowFn();
    solves.push({
      ts: ts,
      solved: !!entry.solved,
      timeMs: entry.timeMs != null ? entry.timeMs : null
    });
    totalOps.push({ ts: ts });
    _pruneToMax(solves, maxEvents);
    _pruneToMax(totalOps, maxEvents * 2);
  }

  function recordBotDetection(entry) {
    if (!entry || typeof entry !== "object") return;
    var ts = nowFn();
    botChecks.push({
      ts: ts,
      blocked: !!entry.blocked
    });
    totalOps.push({ ts: ts });
    _pruneToMax(botChecks, maxEvents);
    _pruneToMax(totalOps, maxEvents * 2);
  }

  function recordPoolLevel(entry) {
    if (!entry || typeof entry !== "object") return;
    var ts = nowFn();
    poolSnapshots.push({
      ts: ts,
      available: Math.max(0, entry.available || 0),
      total: Math.max(0, entry.total || 0)
    });
    _pruneToMax(poolSnapshots, maxEvents);
  }

  function recordRateLimitHit(entry) {
    if (!entry || typeof entry !== "object") return;
    var ts = nowFn();
    rateLimitHits.push({
      ts: ts,
      key: entry.key || "unknown"
    });
    _pruneToMax(rateLimitHits, maxEvents);
  }

  function recordError(entry) {
    if (!entry || typeof entry !== "object") return;
    var ts = nowFn();
    errors.push({
      ts: ts,
      code: entry.code || "UNKNOWN",
      message: entry.message || ""
    });
    totalOps.push({ ts: ts });
    _pruneToMax(errors, maxEvents);
    _pruneToMax(totalOps, maxEvents * 2);
  }

  function recordOperation() {
    totalOps.push({ ts: nowFn() });
    _pruneToMax(totalOps, maxEvents * 2);
  }

  // ── Public: Health Check ─────────────────────────────────────────

  function check() {
    var ts = nowFn();

    var cutoff = _windowCutoff();
    _evictOld(solves, cutoff);
    _evictOld(botChecks, cutoff);
    _evictOld(poolSnapshots, cutoff);
    _evictOld(rateLimitHits, cutoff);
    _evictOld(errors, cutoff);
    _evictOld(totalOps, cutoff);

    var signals = Object.create(null);
    signals[SIGNALS.SOLVE_RATE]    = _computeSolveRate();
    signals[SIGNALS.RESPONSE_TIME] = _computeResponseTime();
    signals[SIGNALS.POOL_LEVEL]    = _computePoolLevel();
    signals[SIGNALS.BOT_RATE]      = _computeBotRate();
    signals[SIGNALS.RATE_LIMIT]    = _computeRateLimitPressure();
    signals[SIGNALS.ERROR_RATE]    = _computeErrorRate();

    var score  = _computeScore(signals);
    var status = _worstStatus(signals);
    var newAlerts = _emitAlerts(signals);
    var recommendations = _generateRecommendations(signals);

    checksPerformed++;
    var result = {
      status:           status,
      score:            score,
      signals:          signals,
      alerts:           newAlerts,
      recommendations:  recommendations,
      uptimeMs:         ts - startedAt,
      checksPerformed:  checksPerformed,
      lastCheckAt:      ts
    };

    checkHistory.push({
      ts:     ts,
      status: status,
      score:  score
    });
    _pruneToMax(checkHistory, maxChecks);

    return result;
  }

  // ── Public: Alert Access ─────────────────────────────────────────

  function getAlerts(filterOpts) {
    filterOpts = filterOpts || {};
    var limit = filterOpts.limit > 0 ? filterOpts.limit : 50;

    var result = [];
    for (var i = alerts.length - 1; i >= 0 && result.length < limit; i--) {
      var a = alerts[i];
      if (filterOpts.level && a.level !== filterOpts.level) continue;
      if (filterOpts.signal && a.signal !== filterOpts.signal) continue;
      if (filterOpts.sinceMs && a.ts < filterOpts.sinceMs) continue;
      result.push(_deepCopy(a));
    }
    return result.reverse();
  }

  function getCheckHistory(limit) {
    limit = limit > 0 ? limit : 20;
    var start = Math.max(0, checkHistory.length - limit);
    return checkHistory.slice(start).map(_deepCopy);
  }

  // ── Public: Trend Analysis ───────────────────────────────────────

  function trend(lookback) {
    lookback = lookback > 0 ? lookback : 5;
    if (checkHistory.length < 2) {
      return { direction: "stable", current: null, previous: null };
    }

    var current = checkHistory[checkHistory.length - 1];
    var start = Math.max(0, checkHistory.length - 1 - lookback);
    var end = checkHistory.length - 1;
    var sum = 0;
    var count = 0;
    for (var i = start; i < end; i++) {
      sum += checkHistory[i].score;
      count++;
    }
    if (count === 0) {
      return { direction: "stable", current: current.score, previous: null };
    }
    var prevAvg = Math.round(sum / count);
    var diff = current.score - prevAvg;

    var direction;
    if (diff > 5) direction = "improving";
    else if (diff < -5) direction = "declining";
    else direction = "stable";

    return {
      direction: direction,
      current: current.score,
      previous: prevAvg,
      delta: diff
    };
  }

  // ── Public: Summary ──────────────────────────────────────────────

  function summary() {
    var h = check();
    var lines = [];
    lines.push("System Health: " + h.status.toUpperCase() + " (score: " + h.score + "/100)");
    lines.push("Uptime: " + _roundTo(h.uptimeMs / 1000, 0) + "s | Checks: " + h.checksPerformed);
    lines.push("");

    var signalNames = [
      SIGNALS.SOLVE_RATE, SIGNALS.RESPONSE_TIME, SIGNALS.POOL_LEVEL,
      SIGNALS.BOT_RATE, SIGNALS.RATE_LIMIT, SIGNALS.ERROR_RATE
    ];
    for (var i = 0; i < signalNames.length; i++) {
      var sig = h.signals[signalNames[i]];
      if (!sig) continue;
      var icon = sig.status === STATUS.HEALTHY ? "\u2713" :
                 sig.status === STATUS.CRITICAL ? "\u2717" : "!";
      lines.push("  [" + icon + "] " + sig.signal + ": " + sig.value +
        " (" + sig.status + ")");
    }

    if (h.recommendations.length > 0) {
      lines.push("");
      lines.push("Recommendations:");
      for (var j = 0; j < h.recommendations.length; j++) {
        lines.push("  \u2192 " + h.recommendations[j]);
      }
    }

    return lines.join("\n");
  }

  // ── Public: Reset ────────────────────────────────────────────────

  function reset() {
    solves.length = 0;
    botChecks.length = 0;
    poolSnapshots.length = 0;
    rateLimitHits.length = 0;
    errors.length = 0;
    totalOps.length = 0;
    alerts.length = 0;
    checkHistory.length = 0;
    checksPerformed = 0;
    startedAt = nowFn();
  }

  // ── Public: Export/Import ────────────────────────────────────────

  function exportJSON() {
    return JSON.stringify({
      version: 1,
      thresholds: thresholds,
      windowMs: windowMs,
      solves: solves,
      botChecks: botChecks,
      poolSnapshots: poolSnapshots,
      rateLimitHits: rateLimitHits,
      errors: errors,
      totalOps: totalOps,
      alerts: alerts,
      checkHistory: checkHistory,
      checksPerformed: checksPerformed,
      startedAt: startedAt,
      exportedAt: nowFn()
    });
  }

  function importJSON(json) {
    var data;
    try {
      data = JSON.parse(json);
    } catch (_) {
      return;
    }
    if (!data || data.version !== 1) return;

    if (Array.isArray(data.solves)) {
      solves.length = 0;
      for (var i = 0; i < data.solves.length; i++) solves.push(data.solves[i]);
    }
    if (Array.isArray(data.botChecks)) {
      botChecks.length = 0;
      for (var j = 0; j < data.botChecks.length; j++) botChecks.push(data.botChecks[j]);
    }
    if (Array.isArray(data.poolSnapshots)) {
      poolSnapshots.length = 0;
      for (var k = 0; k < data.poolSnapshots.length; k++) poolSnapshots.push(data.poolSnapshots[k]);
    }
    if (Array.isArray(data.rateLimitHits)) {
      rateLimitHits.length = 0;
      for (var m = 0; m < data.rateLimitHits.length; m++) rateLimitHits.push(data.rateLimitHits[m]);
    }
    if (Array.isArray(data.errors)) {
      errors.length = 0;
      for (var n = 0; n < data.errors.length; n++) errors.push(data.errors[n]);
    }
    if (Array.isArray(data.totalOps)) {
      totalOps.length = 0;
      for (var p = 0; p < data.totalOps.length; p++) totalOps.push(data.totalOps[p]);
    }
    if (Array.isArray(data.alerts)) {
      alerts.length = 0;
      for (var q = 0; q < data.alerts.length; q++) alerts.push(data.alerts[q]);
    }
    if (Array.isArray(data.checkHistory)) {
      checkHistory.length = 0;
      for (var r = 0; r < data.checkHistory.length; r++) checkHistory.push(data.checkHistory[r]);
    }
    if (typeof data.checksPerformed === "number") checksPerformed = data.checksPerformed;
    if (typeof data.startedAt === "number") startedAt = data.startedAt;
  }

  // ── Public: Stats ────────────────────────────────────────────────

  function stats() {
    return {
      solves: solves.length,
      botChecks: botChecks.length,
      poolSnapshots: poolSnapshots.length,
      rateLimitHits: rateLimitHits.length,
      errors: errors.length,
      totalOps: totalOps.length,
      alerts: alerts.length,
      checkHistory: checkHistory.length,
      checksPerformed: checksPerformed,
      uptimeMs: nowFn() - startedAt,
      windowMs: windowMs,
      maxEvents: maxEvents,
      thresholds: _deepCopy(thresholds)
    };
  }

  // ── Public API ───────────────────────────────────────────────────

  return {
    recordSolve:          recordSolve,
    recordBotDetection:   recordBotDetection,
    recordPoolLevel:      recordPoolLevel,
    recordRateLimitHit:   recordRateLimitHit,
    recordError:          recordError,
    recordOperation:      recordOperation,

    check:        check,
    summary:      summary,
    trend:        trend,

    getAlerts:        getAlerts,
    getCheckHistory:  getCheckHistory,
    stats:            stats,

    reset:      reset,
    exportJSON: exportJSON,
    importJSON: importJSON,

    STATUS:      STATUS,
    SIGNALS:     SIGNALS,
    ALERT_LEVEL: ALERT_LEVEL
  };
}

// ── Exports ──────────────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createCaptchaHealthMonitor: createCaptchaHealthMonitor };
}
