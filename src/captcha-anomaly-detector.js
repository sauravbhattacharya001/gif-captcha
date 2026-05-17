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

/**
 * A single CAPTCHA telemetry event consumed by the detector.
 *
 * @typedef {Object} CaptchaEvent
 * @property {string}  [type="solve"]    Event class, e.g. `"solve"`, `"issue"`, `"abandon"`.
 * @property {number}  [duration]        Response time in milliseconds. Required for response-time anomalies.
 * @property {boolean} [success=true]    Whether the user solved the challenge. Defaults to `true`.
 * @property {string}  [country="unknown"] ISO-3166 alpha-2 country code (or any stable label).
 * @property {string}  [ip]              Optional client IP for downstream auditing (not used in scoring).
 * @property {string}  [sessionId]       Optional session id (not used in scoring).
 * @property {number}  [timestamp=Date.now()] Event time in epoch milliseconds.
 */

/**
 * A flagged anomaly returned from {@link analyze}.
 *
 * Fields after `severity` vary by `method`:
 *   - `z-score`   → `value`, `zScore`, `mean`, `stddev`
 *   - `iqr`       → `value`, `q1`, `q3`, `iqr`, `fence` (`"lower"|"upper"`)
 *   - `burst`     → `count`, `windowMs` (traffic) or `failures`, `total`, `failureRate` (failure)
 *   - `geo_shift` → `country`, `previousPct`, `currentPct`, `shiftPct`
 *   - `changepoint` → `currentRate`, `baselineRate`, `zScore`, `direction`
 *
 * @typedef {Object} Anomaly
 * @property {("z-score"|"iqr"|"burst"|"geo_shift"|"changepoint")} method
 * @property {string} metric  Logical metric name (e.g. `"response_time"`, `"traffic_burst"`).
 * @property {("warning"|"critical")} severity
 */

/**
 * Aggregated metrics snapshot returned alongside anomalies.
 *
 * @typedef {Object} AnomalyMetrics
 * @property {number} totalEvents         Events inside the analysis window.
 * @property {number} [solveRate]         Success ratio in window, 0..1, rounded to 3dp.
 * @property {number} [avgDuration]       Mean response time (ms), rounded to 2dp.
 * @property {number} [medianDuration]    Median response time (ms), rounded to 2dp.
 * @property {number} [p95Duration]       95th percentile response time (ms).
 * @property {number} [p99Duration]       99th percentile response time (ms).
 * @property {number} [stddevDuration]    Std-dev of response time (ms).
 * @property {?number} [emaSolveRate]     EMA of solve rate (null until first analyze).
 * @property {?number} [emaAvgDuration]   EMA of average response time (null initially).
 * @property {?number} [emaTrafficRate]   EMA of window traffic count (null initially).
 * @property {Array<{country:string,count:number,pct:number}>} [countryBreakdown] Top countries (≤10), `pct` is percentage of window.
 */

/**
 * Output of {@link analyze}.
 *
 * @typedef {Object} AnalysisResult
 * @property {Anomaly[]} anomalies        Deduplicated anomalies (one per `method+metric`).
 * @property {AnomalyMetrics} metrics     Aggregate metrics for the window.
 * @property {boolean} healthy            `true` when `anomalies.length === 0`.
 * @property {boolean} [hasCritical]      `true` if any anomaly has severity `"critical"`.
 * @property {number}  analyzedAt         Epoch ms the analysis ran at.
 * @property {number}  windowMs           Analysis window length (ms).
 * @property {string}  sensitivity        Preset name used (`"low"|"medium"|"high"`) or `"medium"` fallback.
 */

/**
 * Options accepted by {@link createAnomalyDetector}. All fields are optional;
 * unspecified fields fall back to the chosen `sensitivity` preset.
 *
 * @typedef {Object} AnomalyDetectorOptions
 * @property {("low"|"medium"|"high")} [sensitivity="medium"] Preset bundle of thresholds.
 * @property {number} [zThreshold]      Absolute z-score above which a value is flagged.
 * @property {number} [iqrMultiplier]   Multiplier applied to IQR when building Tukey fences.
 * @property {number} [emaAlpha]        EMA smoothing factor (0..1). Larger = more reactive.
 * @property {number} [minSamples]      Minimum samples in window before a detector runs.
 * @property {number} [burstWindow]     Burst-detection window length (ms).
 * @property {number} [burstThreshold]  Event count in `burstWindow` that triggers a burst alert.
 * @property {number} [maxEvents=10000] Hard cap on retained events (oldest are dropped first).
 * @property {number} [windowMs=3600000] Analysis window length (ms), default 1 hour.
 */

"use strict";

// ── Shared statistics helpers (deduplicated — issue #91) ────────────
var _shared = require("./shared-utils");
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _median = _shared._median;
var _percentile = _shared._percentile;
var _medianSorted = _shared._medianSorted;
var _percentileSorted = _shared._percentileSorted;
var _sortedCopy = _shared._sortedCopy;
var _numAsc = _shared._numAsc;
var _sortedCopy = _shared._sortedCopy;

// ── Sensitivity presets ─────────────────────────────────────────────
var SENSITIVITY_PRESETS = {
  low:    { zThreshold: 3.5, iqrMultiplier: 2.5, emaAlpha: 0.1, minSamples: 50, burstWindow: 120000, burstThreshold: 20 },
  medium: { zThreshold: 2.5, iqrMultiplier: 1.8, emaAlpha: 0.2, minSamples: 30, burstWindow: 60000,  burstThreshold: 10 },
  high:   { zThreshold: 2.0, iqrMultiplier: 1.5, emaAlpha: 0.3, minSamples: 15, burstWindow: 30000,  burstThreshold: 5  }
};

// ── Core factory ────────────────────────────────────────────────────

/**
 * Create a new CAPTCHA anomaly detector.
 *
 * Internally maintains a rolling buffer of recent events, a country
 * histogram, per-minute traffic buckets, EMA state for solve rate /
 * average duration / traffic rate, and a bounded alert history.
 *
 * The returned object is stateful — call {@link reset} to clear it.
 *
 * @param {AnomalyDetectorOptions} [options]
 * @returns {{
 *   recordEvent: (evt: CaptchaEvent) => void,
 *   recordEvents: (evts: CaptchaEvent[]) => void,
 *   analyze: (opts?: { timestamp?: number }) => AnalysisResult,
 *   getAlertHistory: (limit?: number) => Array<{timestamp:number,count:number,critical:boolean,anomalies:Anomaly[]}>,
 *   getEmaSnapshot: () => {solveRate:?number,avgDuration:?number,trafficRate:?number},
 *   getStats: () => Object,
 *   reset: () => void
 * }}
 */
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
  /**
   * Record a single CAPTCHA event into the rolling buffer.
   *
   * Non-object / falsy inputs are silently ignored so callers can pipe
   * untrusted data through without try/catch. `timestamp` defaults to
   * `Date.now()` and the buffer is trimmed to `maxEvents` after insert.
   *
   * @param {CaptchaEvent} evt
   * @returns {void}
   */
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
  /**
   * Record a batch of events. Non-array inputs are ignored.
   *
   * @param {CaptchaEvent[]} evtArray
   * @returns {void}
   */
  function recordEvents(evtArray) {
    if (!Array.isArray(evtArray)) return;
    for (var i = 0; i < evtArray.length; i++) {
      recordEvent(evtArray[i]);
    }
  }

  // ── Filter events to analysis window ────────────────────────────
  // Events are appended in chronological order, so we use binary search
  // to find the cutoff index in O(log n) instead of scanning all events.
  /**
   * @private
   * @param {number} now Reference time (epoch ms).
   * @returns {CaptchaEvent[]} Events with `timestamp >= now - windowMs`.
   */
  function _windowEvents(now) {
    var cutoff = now - windowMs;
    // Binary search for the first event >= cutoff
    var lo = 0, hi = events.length;
    while (lo < hi) {
      var mid = (lo + hi) >>> 1;
      if (events[mid].timestamp < cutoff) lo = mid + 1;
      else hi = mid;
    }
    // lo is now the index of the first event in the window
    return events.slice(lo);
  }

  // ── Z-score anomaly check ───────────────────────────────────────
  // Only report the single most extreme outlier per metric since the
  // deduplication step in analyze() keeps at most one anomaly per
  // method+metric anyway.  This avoids allocating O(n) anomaly objects
  // when many values exceed the threshold (e.g. during a bot attack).
  //
  // Accepts optional pre-computed mean/stddev to avoid redundant
  // O(n) passes when the caller already has them (e.g. analyze()).
  /**
   * @private
   * @param {number[]} values
   * @param {string}  label  Metric label used in the returned anomaly.
   * @param {number}  [precomputedMean]
   * @param {number}  [precomputedSd]
   * @returns {Anomaly[]} Either an empty array or a single most-extreme outlier.
   */
  function _zScoreCheck(values, label, precomputedMean, precomputedSd) {
    if (values.length < minSamples) return [];
    var avg = precomputedMean !== undefined ? precomputedMean : _mean(values);
    var sd  = precomputedSd  !== undefined ? precomputedSd  : _stddev(values, avg);
    if (sd === 0) return [];

    var maxAbsZ = 0;
    var maxVal = 0;
    var maxZ = 0;
    for (var i = 0; i < values.length; i++) {
      var z = (values[i] - avg) / sd;
      var absZ = z < 0 ? -z : z;
      if (absZ > maxAbsZ) {
        maxAbsZ = absZ;
        maxVal = values[i];
        maxZ = z;
      }
    }
    if (maxAbsZ <= zThreshold) return [];
    return [{
      method: "z-score",
      metric: label,
      value: maxVal,
      zScore: Math.round(maxZ * 100) / 100,
      mean: Math.round(avg * 100) / 100,
      stddev: Math.round(sd * 100) / 100,
      severity: maxAbsZ > zThreshold * 1.5 ? "critical" : "warning"
    }];
  }

  // ── IQR fence anomaly check ─────────────────────────────────────
  // Like _zScoreCheck, only report the most extreme outlier since
  // dedup keeps one per method+metric.  Uses the already-sorted array
  // endpoints instead of scanning all values.
  //
  // Accepts an optional pre-sorted array to skip the O(n log n) sort
  // when the caller already has one (e.g. analyze()).
  /**
   * @private
   * @param {number[]} values
   * @param {string}   label
   * @param {number[]} [preSorted] Optional ascending-sorted copy of `values`.
   * @returns {Anomaly[]} Either an empty array or a single most-extreme outlier.
   */
  function _iqrCheck(values, label, preSorted) {
    if (values.length < minSamples) return [];
    var sorted = preSorted || _sortedCopy(values);
    // sorted is guaranteed ascending here -- use the *Sorted helpers to
    // skip the redundant slice().sort() that _percentile would do on each
    // call. _iqrCheck runs once per metric on every detect() invocation,
    // so this saves two N-log-N sorts per metric in the hot path.
    var q1 = _percentileSorted(sorted, 25);
    var q3 = _percentileSorted(sorted, 75);
    var iqr = q3 - q1;
    if (iqr === 0) return [];

    var lowerFence = q1 - iqrMultiplier * iqr;
    var upperFence = q3 + iqrMultiplier * iqr;

    // Since sorted is in ascending order, the most extreme lower outlier
    // is sorted[0] and the most extreme upper outlier is sorted[n-1].
    var low = sorted[0];
    var high = sorted[sorted.length - 1];
    var extremeVal, fence;

    // Pick whichever endpoint deviates more from its fence
    var lowDev = low < lowerFence ? lowerFence - low : 0;
    var highDev = high > upperFence ? high - upperFence : 0;

    if (lowDev === 0 && highDev === 0) return [];

    if (lowDev >= highDev) {
      extremeVal = low;
      fence = "lower";
    } else {
      extremeVal = high;
      fence = "upper";
    }

    var isCritical = fence === "lower"
      ? extremeVal < lowerFence - 2 * iqr
      : extremeVal > upperFence + 2 * iqr;

    return [{
      method: "iqr",
      metric: label,
      value: extremeVal,
      q1: Math.round(q1 * 100) / 100,
      q3: Math.round(q3 * 100) / 100,
      iqr: Math.round(iqr * 100) / 100,
      fence: fence,
      severity: isCritical ? "critical" : "warning"
    }];
  }

  // ── EMA tracking ────────────────────────────────────────────────
  /**
   * @private
   * Update one of the tracked EMA channels. First update seeds the EMA with
   * `newValue` directly so the running value is well-defined immediately.
   *
   * @param {("solveRate"|"avgDuration"|"trafficRate")} key
   * @param {number} newValue
   * @returns {number} The updated EMA value.
   */
  function _updateEma(key, newValue) {
    if (emaValues[key] === null) {
      emaValues[key] = newValue;
    } else {
      emaValues[key] = emaAlpha * newValue + (1 - emaAlpha) * emaValues[key];
    }
    return emaValues[key];
  }

  // ── Burst detection ─────────────────────────────────────────────
  // Uses binary search to find the burst window start since windowEvents
  // are sorted chronologically from _windowEvents — O(log n) vs O(n).
  /**
   * @private
   * Detect short-term spikes in either total traffic or failures.
   *
   * @param {CaptchaEvent[]} windowEvents Chronologically sorted window slice.
   * @param {number} now Reference time (epoch ms).
   * @returns {Anomaly[]} Zero, one, or two anomalies (`traffic_burst`, `failure_burst`).
   */
  function _detectBursts(windowEvents, now) {
    var recentCutoff = now - burstWindow;
    // Binary search for first event at or after recentCutoff
    var lo = 0, hi = windowEvents.length;
    while (lo < hi) {
      var mid = (lo + hi) >>> 1;
      if (windowEvents[mid].timestamp < recentCutoff) lo = mid + 1;
      else hi = mid;
    }
    var recentCount = windowEvents.length - lo;
    var recentFailures = 0;
    for (var i = lo; i < windowEvents.length; i++) {
      if (!windowEvents[i].success) recentFailures++;
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
  /**
   * @private
   * Split the window in half and emit one anomaly per country whose share
   * shifted by more than 30 percentage points between the two halves.
   *
   * @param {CaptchaEvent[]} windowEvents
   * @returns {Anomaly[]}
   */
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
  /**
   * @private
   * Chunk the window into ≥5 buckets and z-test the latest bucket's solve
   * rate against the historical mean of all buckets.
   *
   * @param {CaptchaEvent[]} windowEvents
   * @returns {Anomaly[]}
   */
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
  /**
   * Run every detector over the current analysis window and return the
   * deduplicated anomaly set plus an aggregate metrics snapshot.
   *
   * Side effects: updates EMAs and (if any anomalies fire) appends an
   * entry to the bounded alert history.
   *
   * @param {{timestamp?: number}} [opts] Override the reference time (epoch ms).
   * @returns {AnalysisResult}
   */
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

    // Pre-compute duration stats once — these are reused by both the
    // anomaly detectors (_zScoreCheck, _iqrCheck) and the metrics
    // output, avoiding redundant O(n) mean/stddev passes and an
    // extra O(n log n) sort.
    var sdDuration = _stddev(durations, avgDuration);
    var sortedDurations = _sortedCopy(durations);

    // Update EMAs
    _updateEma("solveRate", solveRate);
    _updateEma("avgDuration", avgDuration);
    _updateEma("trafficRate", windowEvts.length);

    // Run all detectors — pass pre-computed stats to avoid redundant work
    var allAnomalies = [];
    allAnomalies = allAnomalies.concat(_zScoreCheck(durations, "response_time", avgDuration, sdDuration));
    allAnomalies = allAnomalies.concat(_iqrCheck(durations, "response_time", sortedDurations));
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

    return {
      anomalies: deduped,
      metrics: {
        totalEvents: windowEvts.length,
        solveRate: Math.round(solveRate * 1000) / 1000,
        avgDuration: Math.round(avgDuration * 100) / 100,
        // sortedDurations is already ascending (see _sortedCopy above), so
        // route through the *Sorted helpers to avoid sorting it three more
        // times for the median/p95/p99 summary.
        medianDuration: Math.round(_medianSorted(sortedDurations) * 100) / 100,
        p95Duration: Math.round(_percentileSorted(sortedDurations, 95) * 100) / 100,
        p99Duration: Math.round(_percentileSorted(sortedDurations, 99) * 100) / 100,
        stddevDuration: Math.round(sdDuration * 100) / 100,
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
  /**
   * @private
   * @param {CaptchaEvent[]} evts
   * @param {number} n  Max number of entries to return.
   * @returns {Array<{country:string,count:number,pct:number}>}
   */
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
  /**
   * Return the most recent alert entries (oldest first). The history is
   * capped at 100 entries internally.
   *
   * @param {number} [limit=20]
   * @returns {Array<{timestamp:number,count:number,critical:boolean,anomalies:Anomaly[]}>}
   */
  function getAlertHistory(limit) {
    limit = limit || 20;
    return alertHistory.slice(-limit);
  }

  // ── Get current EMA values ──────────────────────────────────────
  /**
   * Snapshot of the current EMA values. Any field is `null` until the
   * corresponding metric has been observed at least once.
   *
   * @returns {{solveRate:?number,avgDuration:?number,trafficRate:?number}}
   */
  function getEmaSnapshot() {
    return {
      solveRate: emaValues.solveRate,
      avgDuration: emaValues.avgDuration,
      trafficRate: emaValues.trafficRate
    };
  }

  // ── Reset state ─────────────────────────────────────────────────
  /**
   * Clear every internal buffer (events, EMAs, country histogram, traffic
   * buckets, alert history). Configuration is preserved.
   *
   * @returns {void}
   */
  function reset() {
    events = [];
    emaValues = { solveRate: null, avgDuration: null, trafficRate: null };
    buckets = {};
    countryDist = {};
    totalEvents = 0;
    alertHistory = [];
  }

  // ── Stats summary ───────────────────────────────────────────────
  /**
   * Lightweight introspection helper: returns counters and the effective
   * configuration. Useful for dashboards/log lines.
   *
   * @returns {{
   *   totalEventsRecorded: number,
   *   currentBufferSize: number,
   *   maxEvents: number,
   *   alertsRaised: number,
   *   sensitivity: string,
   *   config: {
   *     zThreshold:number, iqrMultiplier:number, emaAlpha:number,
   *     minSamples:number, burstWindow:number, burstThreshold:number,
   *     windowMs:number
   *   }
   * }}
   */
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
