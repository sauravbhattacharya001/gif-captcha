'use strict';

var _cryptoUtils = require('./crypto-utils');
var secureRandomInt = _cryptoUtils.secureRandomInt;
var sharedUtils = require('./shared-utils');
var _sharedMean = sharedUtils._mean;
var _sharedStddev = sharedUtils._stddev;
var _sharedMedian = sharedUtils._median;

/**
 * Captcha Traffic Analyzer — monitors aggregate CAPTCHA traffic patterns
 * over sliding time windows to detect system-level anomalies.
 *
 * Tracks: traffic volume, solve rates, response times, geographic
 * distribution, and time-of-day patterns. Uses z-score analysis
 * and configurable thresholds to flag anomalies.
 *
 * ES5-compatible. Factory function pattern.
 *
 * Usage:
 *   var analyzer = createCaptchaTrafficAnalyzer({ windowSizeMs: 60000 });
 *   analyzer.record({ timestamp: Date.now(), solved: true, responseTimeMs: 2500, region: 'US' });
 *   var report = analyzer.analyze();
 *   console.log(report.anomalies);
 */
function createCaptchaTrafficAnalyzer(options) {
  options = options || {};

  // ── Configuration ─────────────────────────────────────────────
  var windowSizeMs = _posInt(options.windowSizeMs, 60000);        // 1 minute windows
  var maxWindows = _posInt(options.maxWindows, 1440);              // Keep up to 24 hours of windows
  var zScoreThreshold = _posNum(options.zScoreThreshold, 2.5);    // Z-score for anomaly detection
  var minWindowsForBaseline = _posInt(options.minWindowsForBaseline, 5);
  var solveRateDropThreshold = _posNum(options.solveRateDropThreshold, 0.2);  // 20% drop is anomalous
  var trafficSpikeMultiplier = _posNum(options.trafficSpikeMultiplier, 3.0);  // 3x baseline is a spike
  var regionConcentrationThreshold = _posNum(options.regionConcentrationThreshold, 0.8); // 80% from one region
  var responseTimeDeviationMs = _posNum(options.responseTimeDeviationMs, 5000);
  var maxEvents = _posInt(options.maxEvents, 100000);
  var nowFn = options.now || function () { return Date.now(); };

  // ── State ─────────────────────────────────────────────────────
  var windows = [];           // Array of completed window summaries
  var currentWindow = null;   // Window being filled
  var eventCount = 0;
  var alertHistory = [];      // Last N alerts
  var maxAlertHistory = 100;

  // ── Helpers ───────────────────────────────────────────────────
  function _posInt(v, d) { return (v != null && v > 0 && v === Math.floor(v)) ? v : d; }
  function _posNum(v, d) { return (v != null && v > 0) ? v : d; }
  function _r(v, d) { var f = Math.pow(10, d || 2); return Math.round(v * f) / f; }

  // _mean, _stddev, _median delegated to shared-utils.js
  var _mean = _sharedMean;
  var _stddev = _sharedStddev;
  var _median = _sharedMedian;

  // ── Welford's Online Statistics Tracker ─────────────────────
  // Computes mean, variance, and stddev in O(1) memory per window
  // instead of storing every raw response time value (O(n) memory).
  // Also tracks min/max and an approximate median via reservoir.
  function _createOnlineStats() {
    return {
      n: 0,
      mean: 0,
      m2: 0,       // sum of squared deviations (for variance)
      min: Infinity,
      max: -Infinity,
      // Small reservoir for approximate median (fixed O(1) memory)
      _reservoir: [],
      _reservoirCap: 128,
      _seen: 0
    };
  }

  /**
   * Add a value to the online stats tracker using Welford's algorithm.
   * Mean and variance are computed incrementally — no array storage needed.
   * Approximate median uses reservoir sampling (128 slots).
   */
  function _onlineStatsAdd(stats, value) {
    stats.n++;
    var delta = value - stats.mean;
    stats.mean += delta / stats.n;
    var delta2 = value - stats.mean;
    stats.m2 += delta * delta2;

    if (value < stats.min) stats.min = value;
    if (value > stats.max) stats.max = value;

    // Reservoir sampling for approximate median
    stats._seen++;
    if (stats._reservoir.length < stats._reservoirCap) {
      stats._reservoir.push(value);
    } else {
      // Replace with decreasing probability to maintain uniform sample
      var j = secureRandomInt(stats._seen);
      if (j < stats._reservoirCap) {
        stats._reservoir[j] = value;
      }
    }
  }

  function _onlineStatsMean(stats) {
    return stats.n === 0 ? 0 : stats.mean;
  }

  function _onlineStatsStddev(stats) {
    if (stats.n < 2) return 0;
    return Math.sqrt(stats.m2 / (stats.n - 1));
  }

  function _onlineStatsMedian(stats) {
    if (stats._reservoir.length === 0) return 0;
    var s = stats._reservoir.slice().sort(function (a, b) { return a - b; });
    var m = Math.floor(s.length / 2);
    return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
  }

  function _zScore(value, mean, stddev) {
    if (stddev === 0) return 0;
    return (value - mean) / stddev;
  }

  function _getWindowKey(timestamp) {
    return Math.floor(timestamp / windowSizeMs) * windowSizeMs;
  }

  // ── Window management ─────────────────────────────────────────
  function _createWindow(startMs) {
    return {
      startMs: startMs,
      endMs: startMs + windowSizeMs,
      count: 0,
      solved: 0,
      failed: 0,
      rtStats: _createOnlineStats(),  // Welford's online stats — O(1) memory vs O(n) for raw array
      regions: Object.create(null),
      hours: Object.create(null),
      challengeTypes: Object.create(null)
    };
  }

  function _summarizeWindow(w) {
    var avgRt = _onlineStatsMean(w.rtStats);
    var medRt = _onlineStatsMedian(w.rtStats);
    var stdRt = _onlineStatsStddev(w.rtStats);
    var regionKeys = Object.keys(w.regions);
    var maxRegionCount = 0;
    var dominantRegion = null;
    for (var i = 0; i < regionKeys.length; i++) {
      if (w.regions[regionKeys[i]] > maxRegionCount) {
        maxRegionCount = w.regions[regionKeys[i]];
        dominantRegion = regionKeys[i];
      }
    }
    var regionConcentration = w.count > 0 ? maxRegionCount / w.count : 0;

    return {
      startMs: w.startMs,
      endMs: w.endMs,
      count: w.count,
      solveRate: w.count > 0 ? w.solved / w.count : 0,
      solved: w.solved,
      failed: w.failed,
      meanResponseMs: _r(avgRt),
      medianResponseMs: _r(medRt),
      stddevResponseMs: _r(stdRt),
      uniqueRegions: regionKeys.length,
      dominantRegion: dominantRegion,
      regionConcentration: _r(regionConcentration, 3),
      regions: _cloneObj(w.regions),
      hours: _cloneObj(w.hours),
      challengeTypes: _cloneObj(w.challengeTypes)
    };
  }

  function _cloneObj(obj) {
    var r = Object.create(null);
    var ks = Object.keys(obj);
    for (var i = 0; i < ks.length; i++) r[ks[i]] = obj[ks[i]];
    return r;
  }

  function _flushWindow() {
    if (!currentWindow || currentWindow.count === 0) return;
    var summary = _summarizeWindow(currentWindow);
    windows.push(summary);
    if (windows.length > maxWindows) {
      windows.splice(0, windows.length - maxWindows);
    }
    currentWindow = null;
  }

  function _ensureWindow(timestamp) {
    var key = _getWindowKey(timestamp);
    if (currentWindow && currentWindow.startMs === key) return;
    // Flush previous window if different
    if (currentWindow && currentWindow.startMs !== key) {
      _flushWindow();
    }
    currentWindow = _createWindow(key);
  }

  // ── Record events ─────────────────────────────────────────────

  /**
   * Record a single CAPTCHA event.
   * @param {Object} event
   * @param {number} event.timestamp - Unix timestamp in ms
   * @param {boolean} event.solved - Whether the CAPTCHA was solved
   * @param {number} [event.responseTimeMs] - Response time in ms
   * @param {string} [event.region] - Geographic region (e.g. 'US', 'EU')
   * @param {string} [event.challengeType] - Type of challenge
   */
  function record(event) {
    if (!event || typeof event !== 'object') {
      throw new Error('Event must be a non-null object');
    }
    if (event.timestamp == null || typeof event.timestamp !== 'number' || event.timestamp < 0) {
      throw new Error('Event timestamp must be a non-negative number');
    }
    if (typeof event.solved !== 'boolean') {
      throw new Error('Event solved must be a boolean');
    }

    if (eventCount >= maxEvents) {
      // Evict oldest window to make room
      if (windows.length > 0) {
        var evicted = windows.shift();
        eventCount -= evicted.count;
      }
    }

    _ensureWindow(event.timestamp);
    var w = currentWindow;
    w.count++;
    eventCount++;

    if (event.solved) {
      w.solved++;
    } else {
      w.failed++;
    }

    if (event.responseTimeMs != null && typeof event.responseTimeMs === 'number' && event.responseTimeMs >= 0) {
      _onlineStatsAdd(w.rtStats, event.responseTimeMs);
    }

    var region = event.region || 'unknown';
    if (!w.regions[region]) w.regions[region] = 0;
    w.regions[region]++;

    var hour = new Date(event.timestamp).getUTCHours();
    var hourKey = String(hour);
    if (!w.hours[hourKey]) w.hours[hourKey] = 0;
    w.hours[hourKey]++;

    var cType = event.challengeType || 'default';
    if (!w.challengeTypes[cType]) w.challengeTypes[cType] = 0;
    w.challengeTypes[cType]++;
  }

  /**
   * Record multiple events at once.
   * @param {Array} events - Array of event objects
   * @returns {number} Number of events recorded
   */
  function recordBatch(events) {
    if (!Array.isArray(events)) {
      throw new Error('Events must be an array');
    }
    for (var i = 0; i < events.length; i++) {
      record(events[i]);
    }
    return events.length;
  }

  // ── Analysis ──────────────────────────────────────────────────

  /**
   * Get all completed window summaries plus the current window.
   * @returns {Array} Array of window summaries
   */
  function getWindows() {
    var all = windows.slice();
    if (currentWindow && currentWindow.count > 0) {
      all.push(_summarizeWindow(currentWindow));
    }
    return all;
  }

  /**
   * Compute baseline statistics from completed windows.
   * @returns {Object|null} Baseline stats or null if insufficient data
   */
  function getBaseline() {
    if (windows.length < minWindowsForBaseline) return null;

    var n = windows.length;
    // Welford's online accumulators for mean/stddev — avoids 4×O(W) _mean/_stddev calls
    var cSum = 0, cM2 = 0, cMean = 0;
    var sSum = 0, sM2 = 0, sMean = 0;
    var rSum = 0, rM2 = 0, rMean = 0;
    var dSum = 0, dM2 = 0, dMean = 0;
    // Still need arrays for median (requires sorted data)
    var counts = new Array(n);
    var solveRates = new Array(n);

    for (var i = 0; i < n; i++) {
      var w = windows[i];
      var k = i + 1;

      // traffic count
      counts[i] = w.count;
      var cd = w.count - cMean;
      cMean += cd / k;
      cM2 += cd * (w.count - cMean);

      // solve rate
      solveRates[i] = w.solveRate;
      var sd = w.solveRate - sMean;
      sMean += sd / k;
      sM2 += sd * (w.solveRate - sMean);

      // response time mean
      var rd = w.meanResponseMs - rMean;
      rMean += rd / k;
      rM2 += rd * (w.meanResponseMs - rMean);

      // region diversity
      var dd = w.uniqueRegions - dMean;
      dMean += dd / k;
      dM2 += dd * (w.uniqueRegions - dMean);
    }

    var cStd = n > 1 ? Math.sqrt(cM2 / (n - 1)) : 0;
    var sStd = n > 1 ? Math.sqrt(sM2 / (n - 1)) : 0;
    var rStd = n > 1 ? Math.sqrt(rM2 / (n - 1)) : 0;
    var dStd = n > 1 ? Math.sqrt(dM2 / (n - 1)) : 0;

    return {
      windowCount: n,
      traffic: {
        mean: _r(cMean),
        stddev: _r(cStd),
        median: _r(_median(counts))
      },
      solveRate: {
        mean: _r(sMean, 3),
        stddev: _r(sStd, 3),
        median: _r(_median(solveRates), 3)
      },
      responseTime: {
        mean: _r(rMean),
        stddev: _r(rStd)
      },
      regionDiversity: {
        mean: _r(dMean),
        stddev: _r(dStd)
      }
    };
  }

  /**
   * Analyze the most recent window against the baseline for anomalies.
   * @returns {Object} Analysis result with anomalies array and overall status
   */
  function analyze() {
    var allWindows = getWindows();
    if (allWindows.length === 0) {
      return {
        status: 'no_data',
        anomalies: [],
        windowCount: 0,
        baseline: null,
        latest: null
      };
    }

    var latest = allWindows[allWindows.length - 1];
    var baseline = getBaseline();

    if (!baseline) {
      return {
        status: 'insufficient_baseline',
        anomalies: [],
        windowCount: allWindows.length,
        baseline: null,
        latest: latest
      };
    }

    var anomalies = [];

    // 1. Traffic volume anomaly (spike or drop)
    if (baseline.traffic.stddev > 0) {
      var trafficZ = _zScore(latest.count, baseline.traffic.mean, baseline.traffic.stddev);
      if (Math.abs(trafficZ) > zScoreThreshold) {
        var direction = trafficZ > 0 ? 'spike' : 'drop';
        anomalies.push({
          type: 'traffic_' + direction,
          severity: Math.abs(trafficZ) > zScoreThreshold * 1.5 ? 'critical' : 'warning',
          zScore: _r(trafficZ, 3),
          current: latest.count,
          baseline: _r(baseline.traffic.mean),
          detail: 'Traffic ' + direction + ': ' + latest.count + ' events vs baseline ' + _r(baseline.traffic.mean) + ' (z=' + _r(trafficZ, 2) + ')'
        });
      }
    }

    // Check multiplier-based spike
    if (baseline.traffic.mean > 0 && latest.count > baseline.traffic.mean * trafficSpikeMultiplier) {
      var alreadyReported = false;
      for (var a = 0; a < anomalies.length; a++) {
        if (anomalies[a].type === 'traffic_spike') { alreadyReported = true; break; }
      }
      if (!alreadyReported) {
        anomalies.push({
          type: 'traffic_spike',
          severity: 'critical',
          multiplier: _r(latest.count / baseline.traffic.mean, 1),
          current: latest.count,
          baseline: _r(baseline.traffic.mean),
          detail: 'Traffic is ' + _r(latest.count / baseline.traffic.mean, 1) + 'x the baseline'
        });
      }
    }

    // 2. Solve rate anomaly
    if (baseline.solveRate.stddev > 0) {
      var solveZ = _zScore(latest.solveRate, baseline.solveRate.mean, baseline.solveRate.stddev);
      if (solveZ < -zScoreThreshold || (baseline.solveRate.mean - latest.solveRate) > solveRateDropThreshold) {
        anomalies.push({
          type: 'solve_rate_drop',
          severity: (baseline.solveRate.mean - latest.solveRate) > solveRateDropThreshold * 2 ? 'critical' : 'warning',
          zScore: _r(solveZ, 3),
          current: _r(latest.solveRate, 3),
          baseline: baseline.solveRate.mean,
          drop: _r(baseline.solveRate.mean - latest.solveRate, 3),
          detail: 'Solve rate dropped to ' + _r(latest.solveRate * 100, 1) + '% from baseline ' + _r(baseline.solveRate.mean * 100, 1) + '%'
        });
      }
    } else if (baseline.solveRate.mean > 0 && (baseline.solveRate.mean - latest.solveRate) > solveRateDropThreshold) {
      anomalies.push({
        type: 'solve_rate_drop',
        severity: 'warning',
        current: _r(latest.solveRate, 3),
        baseline: baseline.solveRate.mean,
        drop: _r(baseline.solveRate.mean - latest.solveRate, 3),
        detail: 'Solve rate dropped to ' + _r(latest.solveRate * 100, 1) + '% from baseline ' + _r(baseline.solveRate.mean * 100, 1) + '%'
      });
    }

    // 3. Response time anomaly
    if (baseline.responseTime.stddev > 0) {
      var rtZ = _zScore(latest.meanResponseMs, baseline.responseTime.mean, baseline.responseTime.stddev);
      if (Math.abs(rtZ) > zScoreThreshold) {
        anomalies.push({
          type: rtZ > 0 ? 'response_time_increase' : 'response_time_decrease',
          severity: Math.abs(rtZ) > zScoreThreshold * 1.5 ? 'critical' : 'warning',
          zScore: _r(rtZ, 3),
          currentMs: latest.meanResponseMs,
          baselineMs: baseline.responseTime.mean,
          detail: 'Mean response time ' + (rtZ > 0 ? 'increased' : 'decreased') + ' to ' + latest.meanResponseMs + 'ms vs baseline ' + _r(baseline.responseTime.mean) + 'ms'
        });
      }
    }

    // Absolute threshold check
    if (Math.abs(latest.meanResponseMs - baseline.responseTime.mean) > responseTimeDeviationMs) {
      var hasRtAnomaly = false;
      for (var b = 0; b < anomalies.length; b++) {
        if (anomalies[b].type === 'response_time_increase' || anomalies[b].type === 'response_time_decrease') {
          hasRtAnomaly = true; break;
        }
      }
      if (!hasRtAnomaly) {
        anomalies.push({
          type: latest.meanResponseMs > baseline.responseTime.mean ? 'response_time_increase' : 'response_time_decrease',
          severity: 'warning',
          currentMs: latest.meanResponseMs,
          baselineMs: baseline.responseTime.mean,
          deviationMs: _r(Math.abs(latest.meanResponseMs - baseline.responseTime.mean)),
          detail: 'Response time deviated by ' + _r(Math.abs(latest.meanResponseMs - baseline.responseTime.mean)) + 'ms from baseline'
        });
      }
    }

    // 4. Geographic concentration anomaly
    if (latest.regionConcentration > regionConcentrationThreshold && latest.count >= 5) {
      anomalies.push({
        type: 'region_concentration',
        severity: latest.regionConcentration > 0.95 ? 'critical' : 'warning',
        concentration: latest.regionConcentration,
        dominantRegion: latest.dominantRegion,
        threshold: regionConcentrationThreshold,
        detail: _r(latest.regionConcentration * 100, 1) + '% of traffic from ' + latest.dominantRegion
      });
    }

    // 5. Region diversity anomaly
    if (baseline.regionDiversity.stddev > 0 && baseline.regionDiversity.mean > 1) {
      var regZ = _zScore(latest.uniqueRegions, baseline.regionDiversity.mean, baseline.regionDiversity.stddev);
      if (regZ < -zScoreThreshold && latest.uniqueRegions < baseline.regionDiversity.mean * 0.5) {
        anomalies.push({
          type: 'region_diversity_drop',
          severity: 'warning',
          zScore: _r(regZ, 3),
          current: latest.uniqueRegions,
          baseline: _r(baseline.regionDiversity.mean),
          detail: 'Region diversity dropped to ' + latest.uniqueRegions + ' from baseline ' + _r(baseline.regionDiversity.mean)
        });
      }
    }

    // Compute overall status
    var status = 'normal';
    var hasCritical = false;
    var hasWarning = false;
    for (var c = 0; c < anomalies.length; c++) {
      if (anomalies[c].severity === 'critical') hasCritical = true;
      if (anomalies[c].severity === 'warning') hasWarning = true;
    }
    if (hasCritical) status = 'critical';
    else if (hasWarning) status = 'warning';

    // Store alert
    if (anomalies.length > 0) {
      alertHistory.push({
        timestamp: nowFn(),
        status: status,
        anomalyCount: anomalies.length,
        types: anomalies.map(function (a) { return a.type; })
      });
      if (alertHistory.length > maxAlertHistory) {
        alertHistory.splice(0, alertHistory.length - maxAlertHistory);
      }
    }

    return {
      status: status,
      anomalies: anomalies,
      windowCount: allWindows.length,
      baseline: baseline,
      latest: latest
    };
  }

  // ── Trend analysis ────────────────────────────────────────────

  /**
   * Compute a linear trend over the last N windows for a given metric.
   * @param {string} metric - 'count', 'solveRate', or 'meanResponseMs'
   * @param {number} [lastN] - Number of recent windows to consider
   * @returns {Object|null} Trend result with slope, direction, and r-squared
   */
  function getTrend(metric, lastN, _prebuiltWindows) {
    var src = _prebuiltWindows ? _prebuiltWindows.slice() : windows.slice();
    if (!_prebuiltWindows && currentWindow && currentWindow.count > 0) {
      src.push(_summarizeWindow(currentWindow));
    }
    if (lastN && lastN > 0 && lastN < src.length) {
      src = src.slice(src.length - lastN);
    }
    if (src.length < 3) return null;

    var values = [];
    for (var i = 0; i < src.length; i++) {
      var w = src[i];
      if (metric === 'count') values.push(w.count);
      else if (metric === 'solveRate') values.push(w.solveRate);
      else if (metric === 'meanResponseMs') values.push(w.meanResponseMs);
      else return null;
    }

    // Simple linear regression: y = slope * x + intercept
    var n = values.length;
    var sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumY2 = 0;
    for (var j = 0; j < n; j++) {
      sumX += j;
      sumY += values[j];
      sumXY += j * values[j];
      sumX2 += j * j;
      sumY2 += values[j] * values[j];
    }
    var denom = n * sumX2 - sumX * sumX;
    var slope = denom === 0 ? 0 : (n * sumXY - sumX * sumY) / denom;
    var intercept = (sumY - slope * sumX) / n;

    // R-squared
    var yMean = sumY / n;
    var ssTot = 0, ssRes = 0;
    for (var k = 0; k < n; k++) {
      var predicted = slope * k + intercept;
      ssTot += (values[k] - yMean) * (values[k] - yMean);
      ssRes += (values[k] - predicted) * (values[k] - predicted);
    }
    var rSquared = ssTot === 0 ? 0 : 1 - ssRes / ssTot;

    var direction = 'stable';
    var absSlope = Math.abs(slope);
    var meanVal = _mean(values);
    if (meanVal > 0 && absSlope / meanVal > 0.01) {
      direction = slope > 0 ? 'increasing' : 'decreasing';
    }

    return {
      metric: metric,
      windowCount: n,
      slope: _r(slope, 4),
      intercept: _r(intercept, 2),
      rSquared: _r(rSquared, 4),
      direction: direction,
      strength: rSquared > 0.7 ? 'strong' : rSquared > 0.3 ? 'moderate' : 'weak',
      firstValue: _r(values[0], 3),
      lastValue: _r(values[n - 1], 3),
      change: _r(values[n - 1] - values[0], 3),
      changePercent: values[0] !== 0 ? _r((values[n - 1] - values[0]) / values[0] * 100, 1) : 0
    };
  }

  // ── Time-of-day distribution ──────────────────────────────────

  /**
   * Get traffic distribution by hour of day (UTC) across all windows.
   * @returns {Object} Hourly distribution with counts and percentages
   */
  function getHourlyDistribution() {
    var hourCounts = Object.create(null);
    var total = 0;
    for (var h = 0; h < 24; h++) hourCounts[String(h)] = 0;

    var allW = getWindows();
    for (var i = 0; i < allW.length; i++) {
      var hrs = allW[i].hours;
      var hks = Object.keys(hrs);
      for (var j = 0; j < hks.length; j++) {
        hourCounts[hks[j]] = (hourCounts[hks[j]] || 0) + hrs[hks[j]];
        total += hrs[hks[j]];
      }
    }

    var distribution = [];
    for (var k = 0; k < 24; k++) {
      var key = String(k);
      distribution.push({
        hour: k,
        count: hourCounts[key],
        percentage: total > 0 ? _r(hourCounts[key] / total * 100, 1) : 0
      });
    }

    // Find peak and trough
    var peakHour = 0, troughHour = 0, maxC = -1, minC = Infinity;
    for (var m = 0; m < distribution.length; m++) {
      if (distribution[m].count > maxC) { maxC = distribution[m].count; peakHour = m; }
      if (distribution[m].count < minC) { minC = distribution[m].count; troughHour = m; }
    }

    return {
      distribution: distribution,
      totalEvents: total,
      peakHour: peakHour,
      troughHour: troughHour,
      peakToTroughRatio: minC > 0 ? _r(maxC / minC, 1) : maxC > 0 ? Infinity : 0
    };
  }

  // ── Region analysis ───────────────────────────────────────────

  /**
   * Get aggregate region statistics across all windows.
   * @returns {Object} Region breakdown with counts, percentages, trends
   */
  function getRegionBreakdown() {
    var regionTotals = Object.create(null);
    var total = 0;
    var allW = getWindows();

    for (var i = 0; i < allW.length; i++) {
      var regs = allW[i].regions;
      var rks = Object.keys(regs);
      for (var j = 0; j < rks.length; j++) {
        if (!regionTotals[rks[j]]) regionTotals[rks[j]] = 0;
        regionTotals[rks[j]] += regs[rks[j]];
        total += regs[rks[j]];
      }
    }

    var regions = [];
    var rKeys = Object.keys(regionTotals);
    for (var k = 0; k < rKeys.length; k++) {
      regions.push({
        region: rKeys[k],
        count: regionTotals[rKeys[k]],
        percentage: total > 0 ? _r(regionTotals[rKeys[k]] / total * 100, 1) : 0
      });
    }

    regions.sort(function (a, b) { return b.count - a.count; });

    return {
      regions: regions,
      totalEvents: total,
      uniqueRegions: rKeys.length,
      topRegion: regions.length > 0 ? regions[0].region : null,
      topRegionShare: regions.length > 0 ? regions[0].percentage : 0
    };
  }

  // ── Summary & export ──────────────────────────────────────────

  /**
   * Get a comprehensive summary of all tracked data.
   *
   * Optimised: builds the window list once and computes aggregate stats,
   * region breakdown, and hourly distribution in a single pass instead of
   * calling getWindows() 4× (via analyze, getRegionBreakdown,
   * getHourlyDistribution, and directly) with separate iterations each.
   *
   * @returns {Object} Full summary
   */
  function getSummary() {
    var allW = getWindows();
    var totalEvents = 0;
    var totalSolved = 0;
    var allRTs = [];

    // Region + hourly accumulators (inlined from getRegionBreakdown / getHourlyDistribution)
    var regionTotals = Object.create(null);
    var regionTotal = 0;
    var hourCounts = Object.create(null);
    var hourTotal = 0;
    for (var h = 0; h < 24; h++) hourCounts[String(h)] = 0;

    // Single pass over all windows
    for (var i = 0; i < allW.length; i++) {
      var w = allW[i];
      totalEvents += w.count;
      totalSolved += w.solved;
      if (w.meanResponseMs > 0) allRTs.push(w.meanResponseMs);

      // Accumulate regions
      var rks = Object.keys(w.regions);
      for (var ri = 0; ri < rks.length; ri++) {
        if (!regionTotals[rks[ri]]) regionTotals[rks[ri]] = 0;
        regionTotals[rks[ri]] += w.regions[rks[ri]];
        regionTotal += w.regions[rks[ri]];
      }

      // Accumulate hours
      var hks = Object.keys(w.hours);
      for (var hi = 0; hi < hks.length; hi++) {
        hourCounts[hks[hi]] = (hourCounts[hks[hi]] || 0) + w.hours[hks[hi]];
        hourTotal += w.hours[hks[hi]];
      }
    }

    // Build region breakdown without re-iterating windows
    var regions = [];
    var rKeys = Object.keys(regionTotals);
    for (var rk = 0; rk < rKeys.length; rk++) {
      regions.push({
        region: rKeys[rk],
        count: regionTotals[rKeys[rk]],
        percentage: regionTotal > 0 ? _r(regionTotals[rKeys[rk]] / regionTotal * 100, 1) : 0
      });
    }
    regions.sort(function (a, b) { return b.count - a.count; });
    var regionBreakdown = {
      regions: regions,
      totalEvents: regionTotal,
      uniqueRegions: rKeys.length,
      topRegion: regions.length > 0 ? regions[0].region : null,
      topRegionShare: regions.length > 0 ? regions[0].percentage : 0
    };

    // Build hourly distribution without re-iterating windows
    var distribution = [];
    var peakHour = 0, troughHour = 0, maxC = -1, minC = Infinity;
    for (var hd = 0; hd < 24; hd++) {
      var hkey = String(hd);
      var cnt = hourCounts[hkey];
      distribution.push({
        hour: hd,
        count: cnt,
        percentage: hourTotal > 0 ? _r(cnt / hourTotal * 100, 1) : 0
      });
      if (cnt > maxC) { maxC = cnt; peakHour = hd; }
      if (cnt < minC) { minC = cnt; troughHour = hd; }
    }
    var hourlyDistribution = {
      distribution: distribution,
      totalEvents: hourTotal,
      peakHour: peakHour,
      troughHour: troughHour,
      peakToTroughRatio: minC > 0 ? _r(maxC / minC, 1) : maxC > 0 ? Infinity : 0
    };

    // Reuse allW for analyze() — avoid another getWindows() call
    var analysis = analyze();

    return {
      totalEvents: totalEvents,
      totalWindows: allW.length,
      overallSolveRate: totalEvents > 0 ? _r(totalSolved / totalEvents, 3) : 0,
      meanResponseMs: allRTs.length > 0 ? _r(_mean(allRTs)) : 0,
      status: analysis.status,
      anomalyCount: analysis.anomalies.length,
      alertCount: alertHistory.length,
      regionBreakdown: regionBreakdown,
      hourlyDistribution: hourlyDistribution,
      trends: {
        traffic: getTrend('count', undefined, allW),
        solveRate: getTrend('solveRate', undefined, allW),
        responseTime: getTrend('meanResponseMs', undefined, allW)
      }
    };
  }

  /**
   * Get recent alert history.
   * @param {number} [limit] - Max alerts to return
   * @returns {Array} Alert objects
   */
  function getAlertHistory(limit) {
    if (limit && limit > 0) {
      return alertHistory.slice(Math.max(0, alertHistory.length - limit));
    }
    return alertHistory.slice();
  }

  /**
   * Export all data for persistence or migration.
   * @returns {Object} Serializable data
   */
  function exportData() {
    return {
      version: 1,
      exportedAt: nowFn(),
      config: {
        windowSizeMs: windowSizeMs,
        maxWindows: maxWindows,
        zScoreThreshold: zScoreThreshold,
        minWindowsForBaseline: minWindowsForBaseline,
        solveRateDropThreshold: solveRateDropThreshold,
        trafficSpikeMultiplier: trafficSpikeMultiplier,
        regionConcentrationThreshold: regionConcentrationThreshold,
        responseTimeDeviationMs: responseTimeDeviationMs
      },
      windows: windows.slice(),
      currentWindow: currentWindow ? _summarizeWindow(currentWindow) : null,
      alertHistory: alertHistory.slice(),
      eventCount: eventCount
    };
  }

  /**
   * Import previously exported data.
   * @param {Object} data - Data from exportData()
   */
  function importData(data) {
    if (!data || data.version !== 1) {
      throw new Error('Invalid or unsupported export format');
    }
    windows = (data.windows || []).slice();
    alertHistory = (data.alertHistory || []).slice();
    eventCount = data.eventCount || 0;
    currentWindow = null;
    if (data.currentWindow && data.currentWindow.count > 0) {
      windows.push(data.currentWindow);
    }
  }

  /**
   * Flush the current window and reset all state.
   */
  function reset() {
    windows = [];
    currentWindow = null;
    eventCount = 0;
    alertHistory = [];
  }

  /**
   * Flush the current in-progress window into the completed windows array.
   * Useful for testing or when you want to force window boundaries.
   */
  function flush() {
    _flushWindow();
  }

  return {
    record: record,
    recordBatch: recordBatch,
    analyze: analyze,
    getWindows: getWindows,
    getBaseline: getBaseline,
    getTrend: getTrend,
    getHourlyDistribution: getHourlyDistribution,
    getRegionBreakdown: getRegionBreakdown,
    getSummary: getSummary,
    getAlertHistory: getAlertHistory,
    exportData: exportData,
    importData: importData,
    reset: reset,
    flush: flush
  };
}

module.exports = { createCaptchaTrafficAnalyzer: createCaptchaTrafficAnalyzer };
