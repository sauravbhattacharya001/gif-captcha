'use strict';

/**
 * createCaptchaLoadTester — simulates concurrent CAPTCHA sessions to measure
 * throughput, latency distribution, error rates, and identify bottlenecks
 * under load.
 *
 * Use cases:
 * - Capacity planning: how many CAPTCHAs/sec can your setup handle?
 * - Regression testing: does a code change degrade performance?
 * - Stress testing: at what concurrency does error rate spike?
 * - SLA validation: do p95/p99 latencies stay within budget?
 *
 * @param {object} [options]
 * @param {function} options.handler           async (ctx) => result — the CAPTCHA handler to test
 * @param {number}   [options.concurrency=10]  max parallel requests
 * @param {number}   [options.totalRequests=100] total requests to send
 * @param {number}   [options.rampUpMs=0]      linear ramp-up period (ms)
 * @param {number}   [options.timeoutMs=5000]  per-request timeout
 * @param {number}   [options.thinkTimeMs=0]   delay between requests per worker
 * @param {function} [options.contextFactory]  () => ctx object for each request
 * @param {function} [options.onProgress]      (stats) => void, called periodically
 * @param {number}   [options.progressIntervalMs=1000] progress callback interval
 * @param {function} [options.now]             time source
 * @returns {object}
 */
function createCaptchaLoadTester(options) {
  options = options || {};

  if (typeof options.handler !== 'function') {
    throw new Error('handler function is required');
  }

  var handler = options.handler;
  var concurrency = _posInt(options.concurrency, 10);
  var totalRequests = _posInt(options.totalRequests, 100);
  var rampUpMs = options.rampUpMs != null && options.rampUpMs >= 0 ? options.rampUpMs : 0;
  var timeoutMs = _posInt(options.timeoutMs, 5000);
  var thinkTimeMs = options.thinkTimeMs != null && options.thinkTimeMs >= 0 ? options.thinkTimeMs : 0;
  var contextFactory = typeof options.contextFactory === 'function'
    ? options.contextFactory : function() { return {}; };
  var onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
  var progressIntervalMs = _posInt(options.progressIntervalMs, 1000);
  var _now = typeof options.now === 'function' ? options.now : function() { return Date.now(); };

  // ── State ──────────────────────────────────────────────────────

  var results = [];        // { latencyMs, success, error, workerId, requestIndex, startedAt }
  var isRunning = false;
  var isCancelled = false;
  var runHistory = [];     // past run summaries
  var scenarios = Object.create(null); // named scenario configs

  // ── Helpers ────────────────────────────────────────────────────

  function _posInt(v, def) {
    return v != null && v > 0 ? Math.floor(v) : def;
  }

  function _sleep(ms) {
    return new Promise(function(resolve) { setTimeout(resolve, ms); });
  }

  function _percentile(sorted, p) {
    if (sorted.length === 0) return 0;
    var idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)];
  }

  function _timeout(promise, ms) {
    return new Promise(function(resolve, reject) {
      var timer = setTimeout(function() {
        reject(new Error('Request timed out after ' + ms + 'ms'));
      }, ms);
      promise.then(function(v) { clearTimeout(timer); resolve(v); })
             .catch(function(e) { clearTimeout(timer); reject(e); });
    });
  }

  // ── Worker ─────────────────────────────────────────────────────

  function _runWorker(workerId, queue, startTime) {
    return new Promise(function(resolve) {
      function next() {
        if (isCancelled || queue.length === 0) {
          resolve();
          return;
        }

        var requestIndex = queue.shift();

        // Ramp-up delay: stagger worker start
        var rampDelay = 0;
        if (rampUpMs > 0 && concurrency > 1) {
          rampDelay = (rampUpMs / concurrency) * workerId;
        }

        var elapsed = _now() - startTime;
        var waitMs = Math.max(0, rampDelay - elapsed);

        _sleep(waitMs).then(function() {
          if (isCancelled) { resolve(); return; }

          var ctx = contextFactory();
          var reqStart = _now();

          _timeout(
            Promise.resolve().then(function() { return handler(ctx); }),
            timeoutMs
          ).then(function(res) {
            results.push({
              latencyMs: _now() - reqStart,
              success: true,
              error: null,
              workerId: workerId,
              requestIndex: requestIndex,
              startedAt: reqStart,
              result: res
            });
          }).catch(function(err) {
            results.push({
              latencyMs: _now() - reqStart,
              success: false,
              error: err.message || String(err),
              workerId: workerId,
              requestIndex: requestIndex,
              startedAt: reqStart,
              result: null
            });
          }).then(function() {
            if (thinkTimeMs > 0) {
              return _sleep(thinkTimeMs);
            }
          }).then(next);
        });
      }
      next();
    });
  }

  // ── Stats Computation ──────────────────────────────────────────

  function _computeStats(data, durationMs) {
    var total = data.length;
    if (total === 0) {
      return {
        totalRequests: 0, successful: 0, failed: 0,
        errorRate: 0, throughput: 0, durationMs: durationMs,
        latency: { min: 0, max: 0, mean: 0, median: 0, p75: 0, p90: 0, p95: 0, p99: 0, stdDev: 0 },
        errors: {}, workerStats: {}
      };
    }

    var successful = 0;
    var failed = 0;
    var latencies = [];
    var errorMap = Object.create(null);
    var workerMap = Object.create(null);

    for (var i = 0; i < total; i++) {
      var r = data[i];
      if (r.success) {
        successful++;
      } else {
        failed++;
        var key = r.error || 'unknown';
        errorMap[key] = (errorMap[key] || 0) + 1;
      }
      latencies.push(r.latencyMs);

      var wid = 'worker_' + r.workerId;
      if (!workerMap[wid]) {
        workerMap[wid] = { requests: 0, successes: 0, failures: 0, totalLatency: 0 };
      }
      workerMap[wid].requests++;
      workerMap[wid].totalLatency += r.latencyMs;
      if (r.success) workerMap[wid].successes++;
      else workerMap[wid].failures++;
    }

    latencies.sort(function(a, b) { return a - b; });

    var sum = 0;
    for (var j = 0; j < latencies.length; j++) sum += latencies[j];
    var mean = sum / latencies.length;

    var variance = 0;
    for (var k = 0; k < latencies.length; k++) {
      var diff = latencies[k] - mean;
      variance += diff * diff;
    }
    var stdDev = Math.sqrt(variance / latencies.length);

    // Worker avg latency
    var wKeys = Object.keys(workerMap);
    for (var w = 0; w < wKeys.length; w++) {
      var ws = workerMap[wKeys[w]];
      ws.avgLatencyMs = Math.round(ws.totalLatency / ws.requests * 100) / 100;
    }

    var durationSec = durationMs / 1000;

    return {
      totalRequests: total,
      successful: successful,
      failed: failed,
      errorRate: Math.round((failed / total) * 10000) / 100,
      throughput: durationSec > 0 ? Math.round((total / durationSec) * 100) / 100 : 0,
      durationMs: durationMs,
      latency: {
        min: latencies[0],
        max: latencies[latencies.length - 1],
        mean: Math.round(mean * 100) / 100,
        median: _percentile(latencies, 50),
        p75: _percentile(latencies, 75),
        p90: _percentile(latencies, 90),
        p95: _percentile(latencies, 95),
        p99: _percentile(latencies, 99),
        stdDev: Math.round(stdDev * 100) / 100
      },
      errors: errorMap,
      workerStats: workerMap
    };
  }

  // ── Bottleneck Detection ───────────────────────────────────────

  function _detectBottlenecks(stats) {
    var bottlenecks = [];

    // High error rate
    if (stats.errorRate > 10) {
      bottlenecks.push({
        type: 'high_error_rate',
        severity: stats.errorRate > 50 ? 'critical' : 'warning',
        message: 'Error rate is ' + stats.errorRate + '% (threshold: 10%)',
        value: stats.errorRate
      });
    }

    // High p95 vs median ratio (tail latency)
    if (stats.latency.median > 0) {
      var tailRatio = stats.latency.p95 / stats.latency.median;
      if (tailRatio > 5) {
        bottlenecks.push({
          type: 'tail_latency',
          severity: tailRatio > 10 ? 'critical' : 'warning',
          message: 'p95/median ratio is ' + Math.round(tailRatio * 10) / 10 + 'x (threshold: 5x)',
          value: tailRatio
        });
      }
    }

    // High stdDev relative to mean
    if (stats.latency.mean > 0) {
      var cv = stats.latency.stdDev / stats.latency.mean;
      if (cv > 1) {
        bottlenecks.push({
          type: 'high_variance',
          severity: 'warning',
          message: 'Coefficient of variation is ' + Math.round(cv * 100) / 100 + ' (threshold: 1.0)',
          value: cv
        });
      }
    }

    // Worker imbalance
    var wKeys = Object.keys(stats.workerStats);
    if (wKeys.length > 1) {
      var avgLatencies = wKeys.map(function(k) { return stats.workerStats[k].avgLatencyMs; });
      var maxWL = Math.max.apply(null, avgLatencies);
      var minWL = Math.min.apply(null, avgLatencies);
      if (minWL > 0) {
        var imbalance = maxWL / minWL;
        if (imbalance > 3) {
          bottlenecks.push({
            type: 'worker_imbalance',
            severity: 'warning',
            message: 'Worker latency imbalance ratio is ' + Math.round(imbalance * 10) / 10 + 'x',
            value: imbalance
          });
        }
      }
    }

    // Timeout dominance
    var timeoutErrors = stats.errors['Request timed out after ' + timeoutMs + 'ms'] || 0;
    if (timeoutErrors > 0 && stats.totalRequests > 0) {
      var timeoutPct = (timeoutErrors / stats.totalRequests) * 100;
      if (timeoutPct > 5) {
        bottlenecks.push({
          type: 'timeout_spike',
          severity: timeoutPct > 20 ? 'critical' : 'warning',
          message: Math.round(timeoutPct) + '% of requests timed out',
          value: timeoutPct
        });
      }
    }

    return bottlenecks;
  }

  // ── Grade ──────────────────────────────────────────────────────

  function _grade(stats, bottlenecks) {
    // A+ through F based on error rate + tail latency + bottleneck severity
    var score = 100;

    score -= stats.errorRate * 2;

    if (stats.latency.median > 0) {
      var tailR = stats.latency.p95 / stats.latency.median;
      if (tailR > 3) score -= (tailR - 3) * 5;
    }

    for (var i = 0; i < bottlenecks.length; i++) {
      score -= bottlenecks[i].severity === 'critical' ? 15 : 5;
    }

    score = Math.max(0, Math.min(100, score));

    if (score >= 95) return 'A+';
    if (score >= 85) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
  }

  // ── Public API ─────────────────────────────────────────────────

  /**
   * Run the load test. Returns a promise resolving to the full report.
   */
  function run(overrides) {
    if (isRunning) {
      return Promise.reject(new Error('Load test is already running'));
    }

    var cfg = overrides || {};
    var runConcurrency = _posInt(cfg.concurrency, concurrency);
    var runTotal = _posInt(cfg.totalRequests, totalRequests);
    var runRampUp = cfg.rampUpMs != null && cfg.rampUpMs >= 0 ? cfg.rampUpMs : rampUpMs;
    var runTimeout = _posInt(cfg.timeoutMs, timeoutMs);
    var runThinkTime = cfg.thinkTimeMs != null && cfg.thinkTimeMs >= 0 ? cfg.thinkTimeMs : thinkTimeMs;

    // Save original values and override for this run
    var origTimeout = timeoutMs;
    var origThinkTime = thinkTimeMs;
    timeoutMs = runTimeout;
    thinkTimeMs = runThinkTime;
    rampUpMs = runRampUp;

    isRunning = true;
    isCancelled = false;
    results = [];

    // Build queue
    var queue = [];
    for (var i = 0; i < runTotal; i++) queue.push(i);

    var startTime = _now();

    // Progress timer
    var progressTimer = null;
    if (onProgress) {
      progressTimer = setInterval(function() {
        onProgress(_computeStats(results, _now() - startTime));
      }, progressIntervalMs);
    }

    // Launch workers
    var workers = [];
    var workerCount = Math.min(runConcurrency, runTotal);
    for (var w = 0; w < workerCount; w++) {
      workers.push(_runWorker(w, queue, startTime));
    }

    return Promise.all(workers).then(function() {
      isRunning = false;
      if (progressTimer) clearInterval(progressTimer);

      // Restore
      timeoutMs = origTimeout;
      thinkTimeMs = origThinkTime;

      var duration = _now() - startTime;
      var stats = _computeStats(results, duration);
      var bottlenecks = _detectBottlenecks(stats);
      var grade = _grade(stats, bottlenecks);

      var report = {
        config: {
          concurrency: runConcurrency,
          totalRequests: runTotal,
          rampUpMs: runRampUp,
          timeoutMs: runTimeout,
          thinkTimeMs: runThinkTime
        },
        stats: stats,
        bottlenecks: bottlenecks,
        grade: grade,
        results: results,
        timestamp: startTime
      };

      runHistory.push({
        timestamp: startTime,
        config: report.config,
        grade: grade,
        stats: {
          totalRequests: stats.totalRequests,
          successful: stats.successful,
          failed: stats.failed,
          errorRate: stats.errorRate,
          throughput: stats.throughput,
          durationMs: stats.durationMs,
          medianLatency: stats.latency.median,
          p95Latency: stats.latency.p95
        },
        bottleneckCount: bottlenecks.length
      });

      return report;
    });
  }

  /**
   * Cancel a running test.
   */
  function cancel() {
    if (!isRunning) return false;
    isCancelled = true;
    return true;
  }

  /**
   * Run a stress test: incrementally increases concurrency to find the breaking point.
   * @param {object} [opts]
   * @param {number} [opts.startConcurrency=1]
   * @param {number} [opts.maxConcurrency=50]
   * @param {number} [opts.step=5]
   * @param {number} [opts.requestsPerLevel=50]
   * @param {number} [opts.errorRateThreshold=20]  stop when error rate exceeds this %
   * @returns {Promise<object>} stress report
   */
  function stress(opts) {
    opts = opts || {};
    var startC = _posInt(opts.startConcurrency, 1);
    var maxC = _posInt(opts.maxConcurrency, 50);
    var step = _posInt(opts.step, 5);
    var reqPerLevel = _posInt(opts.requestsPerLevel, 50);
    var errThreshold = opts.errorRateThreshold != null ? opts.errorRateThreshold : 20;

    var levels = [];
    var breakingPoint = null;

    function runLevel(c) {
      if (c > maxC || isCancelled) {
        return Promise.resolve();
      }

      return run({ concurrency: c, totalRequests: reqPerLevel }).then(function(report) {
        levels.push({
          concurrency: c,
          grade: report.grade,
          throughput: report.stats.throughput,
          errorRate: report.stats.errorRate,
          medianLatency: report.stats.latency.median,
          p95Latency: report.stats.latency.p95,
          bottlenecks: report.bottlenecks.length
        });

        if (report.stats.errorRate > errThreshold) {
          breakingPoint = c;
          return Promise.resolve();
        }

        var nextC = c === startC ? (startC + step) : (c + step);
        return runLevel(nextC);
      });
    }

    return runLevel(startC).then(function() {
      // Find optimal: highest throughput level with acceptable error rate
      var optimal = null;
      for (var i = levels.length - 1; i >= 0; i--) {
        if (levels[i].errorRate <= errThreshold) {
          if (!optimal || levels[i].throughput > optimal.throughput) {
            optimal = levels[i];
          }
        }
      }

      return {
        levels: levels,
        breakingPoint: breakingPoint,
        optimalConcurrency: optimal ? optimal.concurrency : startC,
        recommendation: breakingPoint
          ? 'System breaks at concurrency ' + breakingPoint + '. Optimal: ' + (optimal ? optimal.concurrency : startC)
          : 'System handled max concurrency ' + maxC + ' within error threshold'
      };
    });
  }

  /**
   * Compare two runs by their timestamps.
   */
  function compare(timestampA, timestampB) {
    var a = null, b = null;
    for (var i = 0; i < runHistory.length; i++) {
      if (runHistory[i].timestamp === timestampA) a = runHistory[i];
      if (runHistory[i].timestamp === timestampB) b = runHistory[i];
    }
    if (!a || !b) return null;

    var throughputDelta = a.stats.throughput > 0
      ? Math.round(((b.stats.throughput - a.stats.throughput) / a.stats.throughput) * 10000) / 100
      : 0;
    var latencyDelta = a.stats.medianLatency > 0
      ? Math.round(((b.stats.medianLatency - a.stats.medianLatency) / a.stats.medianLatency) * 10000) / 100
      : 0;

    return {
      runA: a,
      runB: b,
      deltas: {
        throughput: throughputDelta,
        medianLatency: latencyDelta,
        errorRate: Math.round((b.stats.errorRate - a.stats.errorRate) * 100) / 100,
        grade: { from: a.grade, to: b.grade }
      },
      regression: b.stats.errorRate > a.stats.errorRate * 1.5 || b.stats.p95Latency > (a.stats.p95Latency || 1) * 2,
      summary: throughputDelta >= 0
        ? 'Throughput improved by ' + throughputDelta + '%'
        : 'Throughput degraded by ' + Math.abs(throughputDelta) + '%'
    };
  }

  /**
   * Register a named scenario for quick reuse.
   */
  function registerScenario(name, config) {
    if (!name || typeof name !== 'string') throw new Error('Scenario name required');
    scenarios[name] = config;
  }

  /**
   * Run a registered scenario by name.
   */
  function runScenario(name) {
    var cfg = scenarios[name];
    if (!cfg) throw new Error('Unknown scenario: ' + name);
    return run(cfg);
  }

  /**
   * Generate a text report from run results.
   */
  function formatReport(report) {
    var s = report.stats;
    var lines = [
      '╔══════════════════════════════════════════════╗',
      '║        CAPTCHA Load Test Report              ║',
      '╚══════════════════════════════════════════════╝',
      '',
      'Grade: ' + report.grade,
      '',
      '── Configuration ──',
      '  Concurrency:    ' + report.config.concurrency,
      '  Total Requests: ' + report.config.totalRequests,
      '  Ramp-up:        ' + report.config.rampUpMs + 'ms',
      '  Timeout:        ' + report.config.timeoutMs + 'ms',
      '  Think Time:     ' + report.config.thinkTimeMs + 'ms',
      '',
      '── Results ──',
      '  Duration:       ' + s.durationMs + 'ms',
      '  Successful:     ' + s.successful + '/' + s.totalRequests,
      '  Failed:         ' + s.failed,
      '  Error Rate:     ' + s.errorRate + '%',
      '  Throughput:     ' + s.throughput + ' req/s',
      '',
      '── Latency ──',
      '  Min:    ' + s.latency.min + 'ms',
      '  Mean:   ' + s.latency.mean + 'ms',
      '  Median: ' + s.latency.median + 'ms',
      '  p75:    ' + s.latency.p75 + 'ms',
      '  p90:    ' + s.latency.p90 + 'ms',
      '  p95:    ' + s.latency.p95 + 'ms',
      '  p99:    ' + s.latency.p99 + 'ms',
      '  Max:    ' + s.latency.max + 'ms',
      '  StdDev: ' + s.latency.stdDev + 'ms',
    ];

    if (report.bottlenecks.length > 0) {
      lines.push('');
      lines.push('── Bottlenecks ──');
      for (var i = 0; i < report.bottlenecks.length; i++) {
        var b = report.bottlenecks[i];
        lines.push('  [' + b.severity.toUpperCase() + '] ' + b.message);
      }
    }

    if (Object.keys(s.errors).length > 0) {
      lines.push('');
      lines.push('── Errors ──');
      var eKeys = Object.keys(s.errors);
      for (var e = 0; e < eKeys.length; e++) {
        lines.push('  ' + s.errors[eKeys[e]] + 'x  ' + eKeys[e]);
      }
    }

    return lines.join('\n');
  }

  /**
   * Get run history.
   */
  function getHistory() {
    return runHistory.slice();
  }

  /**
   * Export state as JSON.
   */
  function exportState() {
    return JSON.stringify({
      history: runHistory,
      scenarios: scenarios
    });
  }

  /**
   * Import state from JSON.
   */
  function importState(json) {
    var data;
    if (typeof json === 'string') {
      try { data = JSON.parse(json); } catch (e) {
        throw new Error('importState: invalid JSON — ' + e.message);
      }
    } else {
      data = json;
    }
    if (data.history && Array.isArray(data.history)) {
      runHistory = data.history;
    }
    if (data.scenarios) {
      var sKeys = Object.keys(data.scenarios);
      for (var i = 0; i < sKeys.length; i++) {
        scenarios[sKeys[i]] = data.scenarios[sKeys[i]];
      }
    }
  }

  /**
   * Reset all state.
   */
  function reset() {
    results = [];
    runHistory = [];
    scenarios = Object.create(null);
    isCancelled = false;
  }

  return {
    run: run,
    cancel: cancel,
    stress: stress,
    compare: compare,
    registerScenario: registerScenario,
    runScenario: runScenario,
    formatReport: formatReport,
    getHistory: getHistory,
    exportState: exportState,
    importState: importState,
    reset: reset
  };
}

module.exports = { createCaptchaLoadTester: createCaptchaLoadTester };
