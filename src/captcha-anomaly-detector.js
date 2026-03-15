/**
 * CaptchaAnomalyDetector — Statistical anomaly detection for CAPTCHA metrics.
 *
 * Detects unusual patterns in CAPTCHA traffic using z-scores, IQR fences,
 * exponential moving averages, and changepoint detection. Monitors solve rates,
 * response times, traffic volume, failure bursts, and geographic distribution
 * shifts to flag potential bot attacks, system issues, or abuse patterns.
 *
 * No external dependencies.
 *
 * @example
 *   var detector = createAnomalyDetector({ sensitivity: 'medium' });
 *   detector.recordEvent({ type: 'solve', duration: 2400, success: true, country: 'US' });
 *   detector.recordEvent({ type: 'solve', duration: 150, success: true, country: 'US' });
 *   var report = detector.analyze();
 *   // report => { anomalies: [...], metrics: {...}, healthy: false }
 *
 * @module captcha-anomaly-detector
 */

"use strict";

// ── Sensitivity presets ─────────────────────────────────────────────
var SENSITIVITY_PRESETS = {
  low:    { zThreshold: 3.5, iqrMultiplier: 2.5, emaAlpha: 0.1, minSamples: 50, burstWindow: 120000, burstThreshold: 20 },
  medium: { zThreshold: 2.5, iqrMultiplier: 1.8, emaAlpha: 0.2, minSamples: 30, burstWindow: 60000,  burstThreshold: 10 },
  high:   { zThreshold: 2.0, iqrMultiplier: 1.5, emaAlpha: 0.3, minSamples: 15, burstWindow: 30000,  burstThreshold: 5  }
};

// ── Statistics helpers ──────────────────────────────────────────────

function _mean(arr) {
  if (!arr.length) return 0;
  var sum = 0;
  for (var i = 0; i < arr.length; i++) sum += arr[i];
  return sum / arr.length;
}

function _stddev(arr, avg) {
  if (arr.length < 2) return 0;
  if (avg === undefined) avg = _mean(arr);
  var sumSq = 0;
  for (var i = 0; i < arr.length; i++) {
    var d = arr[i] - avg;
    sumSq += d * d;
  }
  return Math.sqrt(sumSq / arr.length);
}

function _median(sorted) {
  if (!sorted.length) return 0;
  var mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function _percentile(sorted, p) {
  if (!sorted.length) return 0;
  var idx = (p / 100) * (sorted.length - 1);
  var lo = Math.floor(idx);
  var hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

function _sortedCopy(arr) {
  return arr.slice().sort(function (a, b) { return a - b; });
}

// ── Core factory ────────────────────────────────────────────────────

function createAnomalyDetector(options) {
  options = options || {};

  var sensitivityName = options.sensitivity || "medium";
  var preset = SENSITIVITY_PRESETS[sensitivityName] || SENSITIVITY_PRESETS.medium;

  var zThreshold     = options.zThreshold     || preset.zThreshold;
  var iqrMultiplier  = options.iqrMultiplier  || preset.iqrMultiplier;
  var emaAlpha       = options.emaAlpha       || preset.emaAlpha;
  var minSamples     = options.minSamples     || preset.minSamples;
  var burstWindow    = options.burstWindow    || preset.burstWindow;
  var burstThreshold = options.burstThreshold || preset.burstThreshold;
  var maxEvents      = options.maxEvents      || 10000;
  var windowMs       = options.windowMs       || 3600000; // 1 hour analysis window

  // ── Internal state ──────────────────────────────────────────────
  var events = [];
  var emaValues = {
    solveRate: null,
    avgDuration: null,
    trafficRate: null
  };
  var buckets = {}; // minute-level traffic buckets
  var countryDist = {}; // country → count
  var totalEvents = 0;
  var alertHistory = [];

  // ── Record an event ─────────────────────────────────────────────
  function recordEvent(evt) {
    if (!evt || typeof evt !== "object") return;
    var ts = evt.timestamp || Date.now();
    var entry = {
      type: evt.type || "solve",
      duration: typeof evt.duration === "number" ? evt.duration : null,
      success: evt.success !== false,
      country: evt.country || "unknown",
      ip: evt.ip || null,
      sessionId: evt.sessionId || null,
      timestamp: ts
    };

    events.push(entry);
    totalEvents++;

    // Track country distribution
    countryDist[entry.country] = (countryDist[entry.country] || 0) + 1;

    // Track minute-level bucket
    var minuteKey = Math.floor(ts / 60000);
    buckets[minuteKey] = (buckets[minuteKey] || 0) + 1;

    // Trim old events
    if (events.length > maxEvents) {
      events = events.slice(events.length - maxEvents);
    }
  }

  // ── Batch record ────────────────────────────────────────────────
  function recordEvents(evtArray) {
    if (!Array.isArray(evtArray)) return;
    for (var i = 0; i < evtArray.length; i++) {
      recordEvent(evtArray[i]);
    }
  }

  // ── Filter events to analysis window ────────────────────────────
  function _windowEvents(now) {
    var cutoff = now - windowMs;
    var result = [];
    for (var i = 0; i < events.length; i++) {
      if (events[i].timestamp >= cutoff) result.push(events[i]);
    }
    return result;
  }

  // ── Z-score anomaly check ───────────────────────────────────────
  function _zScoreCheck(values, label) {
    if (values.length < minSamples) return [];
    var avg = _mean(values);
    var sd = _stddev(values, avg);
    if (sd === 0) return [];

    var anomalies = [];
    for (var i = 0; i < values.length; i++) {
      var z = (values[i] - avg) / sd;
      if (Math.abs(z) > zThreshold) {
        anomalies.push({
          method: "z-score",
          metric: label,
          value: values[i],
          zScore: Math.round(z * 100) / 100,
          mean: Math.round(avg * 100) / 100,
          stddev: Math.round(sd * 100) / 100,
          severity: Math.abs(z) > zThreshold * 1.5 ? "critical" : "warning"
        });
      }
    }
    return anomalies;
  }

  // ── IQR fence anomaly check ─────────────────────────────────────
  function _iqrCheck(values, label) {
    if (values.length < minSamples) return [];
    var sorted = _sortedCopy(values);
    var q1 = _percentile(sorted, 25);
    var q3 = _percentile(sorted, 75);
    var iqr = q3 - q1;
    if (iqr === 0) return [];

    var lowerFence = q1 - iqrMultiplier * iqr;
    var upperFence = q3 + iqrMultiplier * iqr;

    var anomalies = [];
    for (var i = 0; i < values.length; i++) {
      if (values[i] < lowerFence || values[i] > upperFence) {
        anomalies.push({
          method: "iqr",
          metric: label,
          value: values[i],
          q1: Math.round(q1 * 100) / 100,
          q3: Math.round(q3 * 100) / 100,
          iqr: Math.round(iqr * 100) / 100,
          fence: values[i] < lowerFence ? "lower" : "upper",
          severity: values[i] < lowerFence - 2 * iqr || values[i] > upperFence + 2 * iqr ? "critical" : "warning"
        });
      }
    }
    return anomalies;
  }

  // ── EMA tracking ────────────────────────────────────────────────
  function _updateEma(key, newValue) {
    if (emaValues[key] === null) {
      emaValues[key] = newValue;
    } else {
      emaValues[key] = emaAlpha * newValue + (1 - emaAlpha) * emaValues[key];
    }
    return emaValues[key];
  }

  // ── Burst detection ─────────────────────────────────────────────
  function _detectBursts(windowEvents, now) {
    var recentCutoff = now - burstWindow;
    var recentCount = 0;
    var recentFailures = 0;
    for (var i = 0; i < windowEvents.length; i++) {
      if (windowEvents[i].timestamp >= recentCutoff) {
        recentCount++;
        if (!windowEvents[i].success) recentFailures++;
      }
    }

    var anomalies = [];
    if (recentCount >= burstThreshold) {
      anomalies.push({
        method: "burst",
        metric: "traffic_burst",
        count: recentCount,
        windowMs: burstWindow,
        severity: recentCount >= burstThreshold * 2 ? "critical" : "warning"
      });
    }
    if (recentFailures >= Math.ceil(burstThreshold * 0.7)) {
      anomalies.push({
        method: "burst",
        metric: "failure_burst",
        failures: recentFailures,
        total: recentCount,
        failureRate: recentCount > 0 ? Math.round(recentFailures / recentCount * 100) / 100 : 0,
        severity: "critical"
      });
    }
    return anomalies;
  }

  // ── Geo distribution shift ──────────────────────────────────────
  function _detectGeoShift(windowEvents) {
    if (windowEvents.length < minSamples) return [];

    // Split window in half and compare distributions
    var mid = Math.floor(windowEvents.length / 2);
    var firstHalf = {};
    var secondHalf = {};
    var i;

    for (i = 0; i < mid; i++) {
      var c1 = windowEvents[i].country;
      firstHalf[c1] = (firstHalf[c1] || 0) + 1;
    }
    for (i = mid; i < windowEvents.length; i++) {
      var c2 = windowEvents[i].country;
      secondHalf[c2] = (secondHalf[c2] || 0) + 1;
    }

    // Check for countries that appeared/disappeared or shifted >30%
    var allCountries = {};
    var key;
    for (key in firstHalf) allCountries[key] = true;
    for (key in secondHalf) allCountries[key] = true;

    var anomalies = [];
    var firstTotal = mid;
    var secondTotal = windowEvents.length - mid;

    for (key in allCountries) {
      var pct1 = ((firstHalf[key] || 0) / firstTotal) * 100;
      var pct2 = ((secondHalf[key] || 0) / secondTotal) * 100;
      var shift = Math.abs(pct2 - pct1);

      if (shift > 30) {
        anomalies.push({
          method: "geo_shift",
          metric: "country_distribution",
          country: key,
          previousPct: Math.round(pct1 * 10) / 10,
          currentPct: Math.round(pct2 * 10) / 10,
          shiftPct: Math.round(shift * 10) / 10,
          severity: shift > 50 ? "critical" : "warning"
        });
      }
    }
    return anomalies;
  }

  // ── Solve rate changepoint ──────────────────────────────────────
  function _detectSolveRateChange(windowEvents) {
    if (windowEvents.length < minSamples) return [];

    // Compare rolling solve rate across windows
    var chunkSize = Math.max(10, Math.floor(windowEvents.length / 5));
    var rates = [];
    for (var i = 0; i + chunkSize <= windowEvents.length; i += chunkSize) {
      var successes = 0;
      for (var j = i; j < i + chunkSize; j++) {
        if (windowEvents[j].success) successes++;
      }
      rates.push(successes / chunkSize);
    }

    if (rates.length < 3) return [];

    var anomalies = [];
    var avgRate = _mean(rates);
    var sd = _stddev(rates, avgRate);

    if (sd > 0) {
      var lastRate = rates[rates.length - 1];
      var z = (lastRate - avgRate) / sd;
      if (Math.abs(z) > zThreshold) {
        anomalies.push({
          method: "changepoint",
          metric: "solve_rate",
          currentRate: Math.round(lastRate * 1000) / 1000,
          baselineRate: Math.round(avgRate * 1000) / 1000,
          zScore: Math.round(z * 100) / 100,
          direction: z < 0 ? "declining" : "increasing",
          severity: Math.abs(z) > zThreshold * 1.5 ? "critical" : "warning"
        });
      }
    }
    return anomalies;
  }

  // ── Main analysis ───────────────────────────────────────────────
  function analyze(opts) {
    opts = opts || {};
    var now = opts.timestamp || Date.now();
    var windowEvts = _windowEvents(now);

    if (windowEvts.length === 0) {
      return {
        anomalies: [],
        metrics: { totalEvents: 0 },
        healthy: true,
        analyzedAt: now,
        windowMs: windowMs,
        sensitivity: sensitivityName
      };
    }

    // Extract metric arrays
    var durations = [];
    var successes = 0;
    for (var i = 0; i < windowEvts.length; i++) {
      if (windowEvts[i].duration !== null) durations.push(windowEvts[i].duration);
      if (windowEvts[i].success) successes++;
    }

    var solveRate = windowEvts.length > 0 ? successes / windowEvts.length : 0;
    var avgDuration = _mean(durations);

    // Update EMAs
    _updateEma("solveRate", solveRate);
    _updateEma("avgDuration", avgDuration);
    _updateEma("trafficRate", windowEvts.length);

    // Run all detectors
    var allAnomalies = [];
    allAnomalies = allAnomalies.concat(_zScoreCheck(durations, "response_time"));
    allAnomalies = allAnomalies.concat(_iqrCheck(durations, "response_time"));
    allAnomalies = allAnomalies.concat(_detectBursts(windowEvts, now));
    allAnomalies = allAnomalies.concat(_detectGeoShift(windowEvts));
    allAnomalies = allAnomalies.concat(_detectSolveRateChange(windowEvts));

    // Deduplicate by method+metric (keep highest severity)
    var seen = {};
    var deduped = [];
    for (var j = 0; j < allAnomalies.length; j++) {
      var a = allAnomalies[j];
      var key = a.method + ":" + a.metric;
      if (!seen[key] || a.severity === "critical") {
        if (seen[key]) {
          // Replace the existing one
          for (var k = 0; k < deduped.length; k++) {
            if (deduped[k].method + ":" + deduped[k].metric === key) {
              deduped[k] = a;
              break;
            }
          }
        } else {
          deduped.push(a);
        }
        seen[key] = true;
      }
    }

    var hasCritical = false;
    for (var m = 0; m < deduped.length; m++) {
      if (deduped[m].severity === "critical") hasCritical = true;
    }

    // Store in alert history
    if (deduped.length > 0) {
      alertHistory.push({
        timestamp: now,
        count: deduped.length,
        critical: hasCritical,
        anomalies: deduped
      });
      if (alertHistory.length > 100) alertHistory = alertHistory.slice(-100);
    }

    var sortedDurations = _sortedCopy(durations);

    return {
      anomalies: deduped,
      metrics: {
        totalEvents: windowEvts.length,
        solveRate: Math.round(solveRate * 1000) / 1000,
        avgDuration: Math.round(avgDuration * 100) / 100,
        medianDuration: Math.round(_median(sortedDurations) * 100) / 100,
        p95Duration: Math.round(_percentile(sortedDurations, 95) * 100) / 100,
        p99Duration: Math.round(_percentile(sortedDurations, 99) * 100) / 100,
        stddevDuration: Math.round(_stddev(durations, avgDuration) * 100) / 100,
        emaSolveRate: emaValues.solveRate !== null ? Math.round(emaValues.solveRate * 1000) / 1000 : null,
        emaAvgDuration: emaValues.avgDuration !== null ? Math.round(emaValues.avgDuration * 100) / 100 : null,
        emaTrafficRate: emaValues.trafficRate !== null ? Math.round(emaValues.trafficRate * 100) / 100 : null,
        countryBreakdown: _topCountries(windowEvts, 10)
      },
      healthy: deduped.length === 0,
      hasCritical: hasCritical,
      analyzedAt: now,
      windowMs: windowMs,
      sensitivity: sensitivityName
    };
  }

  // ── Top countries helper ────────────────────────────────────────
  function _topCountries(evts, n) {
    var counts = {};
    for (var i = 0; i < evts.length; i++) {
      var c = evts[i].country;
      counts[c] = (counts[c] || 0) + 1;
    }
    var entries = [];
    for (var key in counts) {
      entries.push({ country: key, count: counts[key], pct: Math.round(counts[key] / evts.length * 1000) / 10 });
    }
    entries.sort(function (a, b) { return b.count - a.count; });
    return entries.slice(0, n);
  }

  // ── Get alert history ───────────────────────────────────────────
  function getAlertHistory(limit) {
    limit = limit || 20;
    return alertHistory.slice(-limit);
  }

  // ── Get current EMA values ──────────────────────────────────────
  function getEmaSnapshot() {
    return {
      solveRate: emaValues.solveRate,
      avgDuration: emaValues.avgDuration,
      trafficRate: emaValues.trafficRate
    };
  }

  // ── Reset state ─────────────────────────────────────────────────
  function reset() {
    events = [];
    emaValues = { solveRate: null, avgDuration: null, trafficRate: null };
    buckets = {};
    countryDist = {};
    totalEvents = 0;
    alertHistory = [];
  }

  // ── Stats summary ───────────────────────────────────────────────
  function getStats() {
    return {
      totalEventsRecorded: totalEvents,
      currentBufferSize: events.length,
      maxEvents: maxEvents,
      alertsRaised: alertHistory.length,
      sensitivity: sensitivityName,
      config: {
        zThreshold: zThreshold,
        iqrMultiplier: iqrMultiplier,
        emaAlpha: emaAlpha,
        minSamples: minSamples,
        burstWindow: burstWindow,
        burstThreshold: burstThreshold,
        windowMs: windowMs
      }
    };
  }

  return {
    recordEvent: recordEvent,
    recordEvents: recordEvents,
    analyze: analyze,
    getAlertHistory: getAlertHistory,
    getEmaSnapshot: getEmaSnapshot,
    getStats: getStats,
    reset: reset
  };
}

// ── Exports ─────────────────────────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = { createAnomalyDetector: createAnomalyDetector };
}
