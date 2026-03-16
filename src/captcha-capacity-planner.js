/**
 * CaptchaCapacityPlanner — Infrastructure capacity planning for gif-captcha.
 *
 * Analyzes historical traffic data to forecast future demand, estimate
 * resource requirements, identify bottlenecks, and generate capacity
 * reports with actionable recommendations.
 *
 * Usage:
 *   const { createCapacityPlanner } = require('./captcha-capacity-planner');
 *   const planner = createCapacityPlanner({ maxRps: 1000 });
 *
 *   // Record traffic samples
 *   planner.recordSample({ timestamp: Date.now(), rps: 450, latencyMs: 85, errorRate: 0.02 });
 *   planner.recordSample({ timestamp: Date.now() + 3600000, rps: 520, latencyMs: 92, errorRate: 0.03 });
 *
 *   // Forecast future traffic
 *   const forecast = planner.forecast({ horizonHours: 24, intervalHours: 1 });
 *
 *   // Get capacity assessment
 *   const assessment = planner.assess();
 *
 *   // Generate scaling recommendations
 *   const recs = planner.recommend();
 *
 *   // Full report
 *   const report = planner.report({ format: 'text' }); // or 'json'
 *
 * @module captcha-capacity-planner
 */

"use strict";

// ── Constants ───────────────────────────────────────────────────────

var DEFAULT_MAX_RPS = 1000;
var DEFAULT_MAX_LATENCY_MS = 500;
var DEFAULT_MAX_ERROR_RATE = 0.05;
var DEFAULT_MAX_SAMPLES = 10000;
var DEFAULT_HEADROOM = 0.2; // 20% headroom
var HOUR_MS = 3600000;

// ── Health thresholds ───────────────────────────────────────────────

var HEALTH_LEVELS = {
  healthy: { label: 'Healthy', utilization: 0.6 },
  warning: { label: 'Warning', utilization: 0.8 },
  critical: { label: 'Critical', utilization: 0.95 },
  overloaded: { label: 'Overloaded', utilization: 1.0 }
};

// ── Helpers ─────────────────────────────────────────────────────────

function _clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }

function _mean(arr) {
  if (!arr.length) return 0;
  var s = 0;
  for (var i = 0; i < arr.length; i++) s += arr[i];
  return s / arr.length;
}

function _median(arr) {
  if (!arr.length) return 0;
  var sorted = arr.slice().sort(function (a, b) { return a - b; });
  var mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function _percentile(arr, p) {
  if (!arr.length) return 0;
  var sorted = arr.slice().sort(function (a, b) { return a - b; });
  var idx = (p / 100) * (sorted.length - 1);
  var lo = Math.floor(idx);
  var hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

function _stddev(arr) {
  if (arr.length < 2) return 0;
  var m = _mean(arr);
  var ss = 0;
  for (var i = 0; i < arr.length; i++) {
    var d = arr[i] - m;
    ss += d * d;
  }
  return Math.sqrt(ss / (arr.length - 1));
}

function _linearRegression(xs, ys) {
  var n = xs.length;
  if (n < 2) return { slope: 0, intercept: ys[0] || 0, r2: 0 };
  var sx = 0, sy = 0, sxy = 0, sxx = 0, syy = 0;
  for (var i = 0; i < n; i++) {
    sx += xs[i]; sy += ys[i];
    sxy += xs[i] * ys[i];
    sxx += xs[i] * xs[i];
    syy += ys[i] * ys[i];
  }
  var denom = n * sxx - sx * sx;
  if (denom === 0) return { slope: 0, intercept: sy / n, r2: 0 };
  var slope = (n * sxy - sx * sy) / denom;
  var intercept = (sy - slope * sx) / n;
  var ssTot = syy - (sy * sy) / n;
  var ssRes = 0;
  for (var j = 0; j < n; j++) {
    var pred = slope * xs[j] + intercept;
    ssRes += (ys[j] - pred) * (ys[j] - pred);
  }
  var r2 = ssTot > 0 ? 1 - ssRes / ssTot : 0;
  return { slope: slope, intercept: intercept, r2: r2 };
}

// ── Factory ─────────────────────────────────────────────────────────

function createCapacityPlanner(options) {
  var opts = options || {};
  var maxRps = opts.maxRps > 0 ? opts.maxRps : DEFAULT_MAX_RPS;
  var maxLatencyMs = opts.maxLatencyMs > 0 ? opts.maxLatencyMs : DEFAULT_MAX_LATENCY_MS;
  var maxErrorRate = opts.maxErrorRate > 0 ? opts.maxErrorRate : DEFAULT_MAX_ERROR_RATE;
  var maxSamples = opts.maxSamples > 0 ? opts.maxSamples : DEFAULT_MAX_SAMPLES;
  var headroom = opts.headroom >= 0 && opts.headroom <= 1 ? opts.headroom : DEFAULT_HEADROOM;

  var samples = [];

  // ── Record ──────────────────────────────────────────────────────

  function recordSample(sample) {
    if (!sample || typeof sample !== 'object') {
      throw new Error('Sample must be an object with timestamp, rps, latencyMs, errorRate');
    }
    var entry = {
      timestamp: typeof sample.timestamp === 'number' ? sample.timestamp : Date.now(),
      rps: Math.max(0, Number(sample.rps) || 0),
      latencyMs: Math.max(0, Number(sample.latencyMs) || 0),
      errorRate: _clamp(Number(sample.errorRate) || 0, 0, 1),
      cpuPercent: sample.cpuPercent != null ? _clamp(Number(sample.cpuPercent), 0, 100) : null,
      memoryPercent: sample.memoryPercent != null ? _clamp(Number(sample.memoryPercent), 0, 100) : null
    };
    samples.push(entry);
    // evict oldest if over limit
    while (samples.length > maxSamples) samples.shift();
    return entry;
  }

  function recordBatch(arr) {
    if (!Array.isArray(arr)) throw new Error('Batch must be an array');
    var results = [];
    for (var i = 0; i < arr.length; i++) results.push(recordSample(arr[i]));
    return results;
  }

  // ── Stats ───────────────────────────────────────────────────────

  function stats() {
    if (!samples.length) return null;
    var rpsArr = [], latArr = [], errArr = [], cpuArr = [], memArr = [];
    for (var i = 0; i < samples.length; i++) {
      rpsArr.push(samples[i].rps);
      latArr.push(samples[i].latencyMs);
      errArr.push(samples[i].errorRate);
      if (samples[i].cpuPercent != null) cpuArr.push(samples[i].cpuPercent);
      if (samples[i].memoryPercent != null) memArr.push(samples[i].memoryPercent);
    }
    return {
      sampleCount: samples.length,
      timeSpanMs: samples[samples.length - 1].timestamp - samples[0].timestamp,
      rps: { mean: _mean(rpsArr), median: _median(rpsArr), p95: _percentile(rpsArr, 95), max: Math.max.apply(null, rpsArr), stddev: _stddev(rpsArr) },
      latencyMs: { mean: _mean(latArr), median: _median(latArr), p95: _percentile(latArr, 95), max: Math.max.apply(null, latArr) },
      errorRate: { mean: _mean(errArr), max: Math.max.apply(null, errArr) },
      cpu: cpuArr.length ? { mean: _mean(cpuArr), p95: _percentile(cpuArr, 95), max: Math.max.apply(null, cpuArr) } : null,
      memory: memArr.length ? { mean: _mean(memArr), p95: _percentile(memArr, 95), max: Math.max.apply(null, memArr) } : null
    };
  }

  // ── Forecast ────────────────────────────────────────────────────

  function forecast(options) {
    var fopts = options || {};
    var horizonHours = fopts.horizonHours > 0 ? fopts.horizonHours : 24;
    var intervalHours = fopts.intervalHours > 0 ? fopts.intervalHours : 1;

    if (samples.length < 2) {
      return { error: 'Need at least 2 samples to forecast', points: [] };
    }

    var t0 = samples[0].timestamp;
    var xs = [], ys = [];
    for (var i = 0; i < samples.length; i++) {
      xs.push((samples[i].timestamp - t0) / HOUR_MS);
      ys.push(samples[i].rps);
    }
    var reg = _linearRegression(xs, ys);

    var lastT = samples[samples.length - 1].timestamp;
    var lastHour = (lastT - t0) / HOUR_MS;
    var points = [];
    var steps = Math.ceil(horizonHours / intervalHours);
    for (var s = 1; s <= steps; s++) {
      var h = lastHour + s * intervalHours;
      var predicted = Math.max(0, reg.slope * h + reg.intercept);
      points.push({
        timestamp: lastT + s * intervalHours * HOUR_MS,
        hoursFromNow: s * intervalHours,
        predictedRps: Math.round(predicted * 100) / 100,
        utilization: Math.round((predicted / maxRps) * 10000) / 10000
      });
    }

    // estimate when capacity is reached
    var timeToCapacityHours = null;
    if (reg.slope > 0) {
      var effectiveMax = maxRps * (1 - headroom);
      var currentRps = reg.slope * lastHour + reg.intercept;
      if (currentRps < effectiveMax) {
        timeToCapacityHours = Math.round(((effectiveMax - currentRps) / reg.slope) * 100) / 100;
      }
    }

    return {
      trend: {
        slope: Math.round(reg.slope * 10000) / 10000,
        direction: reg.slope > 0.1 ? 'growing' : reg.slope < -0.1 ? 'declining' : 'stable',
        r2: Math.round(reg.r2 * 10000) / 10000,
        confidence: reg.r2 > 0.7 ? 'high' : reg.r2 > 0.4 ? 'medium' : 'low'
      },
      timeToCapacityHours: timeToCapacityHours,
      points: points
    };
  }

  // ── Assess ──────────────────────────────────────────────────────

  function assess() {
    var s = stats();
    if (!s) return { status: 'no-data', message: 'No samples recorded' };

    var utilization = s.rps.p95 / maxRps;
    var peakUtilization = s.rps.max / maxRps;

    var status;
    if (peakUtilization >= HEALTH_LEVELS.overloaded.utilization) {
      status = 'overloaded';
    } else if (utilization >= HEALTH_LEVELS.critical.utilization) {
      status = 'critical';
    } else if (utilization >= HEALTH_LEVELS.warning.utilization) {
      status = 'warning';
    } else {
      status = 'healthy';
    }

    var bottlenecks = [];
    if (s.latencyMs.p95 > maxLatencyMs) {
      bottlenecks.push({ type: 'latency', message: 'P95 latency (' + Math.round(s.latencyMs.p95) + 'ms) exceeds threshold (' + maxLatencyMs + 'ms)', severity: 'high' });
    }
    if (s.errorRate.mean > maxErrorRate) {
      bottlenecks.push({ type: 'errors', message: 'Mean error rate (' + (s.errorRate.mean * 100).toFixed(1) + '%) exceeds threshold (' + (maxErrorRate * 100) + '%)', severity: 'high' });
    }
    if (s.cpu && s.cpu.p95 > 80) {
      bottlenecks.push({ type: 'cpu', message: 'P95 CPU (' + Math.round(s.cpu.p95) + '%) is high', severity: s.cpu.p95 > 90 ? 'critical' : 'medium' });
    }
    if (s.memory && s.memory.p95 > 85) {
      bottlenecks.push({ type: 'memory', message: 'P95 memory (' + Math.round(s.memory.p95) + '%) is high', severity: s.memory.p95 > 95 ? 'critical' : 'medium' });
    }

    return {
      status: status,
      utilization: Math.round(utilization * 10000) / 10000,
      peakUtilization: Math.round(peakUtilization * 10000) / 10000,
      effectiveCapacity: Math.round(maxRps * (1 - headroom)),
      currentP95Rps: Math.round(s.rps.p95 * 100) / 100,
      headroomRps: Math.round((maxRps * (1 - headroom) - s.rps.p95) * 100) / 100,
      bottlenecks: bottlenecks,
      stats: s
    };
  }

  // ── Recommend ───────────────────────────────────────────────────

  function recommend() {
    var a = assess();
    if (a.status === 'no-data') return { recommendations: [], assessment: a };

    var recs = [];
    var fc = samples.length >= 2 ? forecast({ horizonHours: 72 }) : null;

    // Scaling recommendations
    if (a.status === 'overloaded' || a.status === 'critical') {
      var scaleFactor = Math.ceil((a.currentP95Rps / (maxRps * (1 - headroom))) * 10) / 10;
      recs.push({
        priority: 'critical',
        category: 'scaling',
        action: 'Scale up immediately',
        detail: 'Current P95 RPS (' + a.currentP95Rps + ') exceeds safe capacity. Scale by ' + scaleFactor + 'x.',
        impact: 'high'
      });
    } else if (a.status === 'warning') {
      recs.push({
        priority: 'high',
        category: 'scaling',
        action: 'Plan capacity increase',
        detail: 'Utilization at ' + (a.utilization * 100).toFixed(1) + '%. Begin provisioning additional capacity.',
        impact: 'medium'
      });
    }

    // Growth-based recommendations
    if (fc && fc.timeToCapacityHours != null) {
      var daysToCapacity = Math.round(fc.timeToCapacityHours / 24 * 10) / 10;
      if (daysToCapacity < 7) {
        recs.push({
          priority: 'high',
          category: 'growth',
          action: 'Capacity exhaustion in ' + daysToCapacity + ' days',
          detail: 'At current growth rate (' + fc.trend.slope.toFixed(2) + ' rps/hour), capacity will be reached in ' + daysToCapacity + ' days.',
          impact: 'high'
        });
      } else if (daysToCapacity < 30) {
        recs.push({
          priority: 'medium',
          category: 'growth',
          action: 'Capacity exhaustion in ' + daysToCapacity + ' days',
          detail: 'Plan ahead for capacity increase based on ' + fc.trend.direction + ' traffic trend.',
          impact: 'medium'
        });
      }
    }

    // Latency recommendations
    for (var b = 0; b < a.bottlenecks.length; b++) {
      var bn = a.bottlenecks[b];
      if (bn.type === 'latency') {
        recs.push({
          priority: 'high',
          category: 'performance',
          action: 'Optimize latency',
          detail: bn.message + '. Consider caching, CDN, or reducing challenge complexity.',
          impact: 'high'
        });
      }
      if (bn.type === 'errors') {
        recs.push({
          priority: 'high',
          category: 'reliability',
          action: 'Investigate error rate',
          detail: bn.message + '. Check for failing dependencies or resource exhaustion.',
          impact: 'high'
        });
      }
      if (bn.type === 'cpu') {
        recs.push({
          priority: bn.severity === 'critical' ? 'critical' : 'medium',
          category: 'resources',
          action: 'CPU optimization needed',
          detail: bn.message + '. Profile GIF generation and consider pre-rendering.',
          impact: bn.severity === 'critical' ? 'high' : 'medium'
        });
      }
      if (bn.type === 'memory') {
        recs.push({
          priority: bn.severity === 'critical' ? 'critical' : 'medium',
          category: 'resources',
          action: 'Memory optimization needed',
          detail: bn.message + '. Check for leaks in challenge pools or session stores.',
          impact: bn.severity === 'critical' ? 'high' : 'medium'
        });
      }
    }

    // Low utilization
    if (a.utilization < 0.2 && fc && fc.trend.direction === 'declining') {
      recs.push({
        priority: 'low',
        category: 'cost',
        action: 'Consider scaling down',
        detail: 'Utilization at ' + (a.utilization * 100).toFixed(1) + '% with declining trend. Reduce instances to save costs.',
        impact: 'low'
      });
    }

    // Sort by priority
    var priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    recs.sort(function (a, b) { return (priorityOrder[a.priority] || 3) - (priorityOrder[b.priority] || 3); });

    return { recommendations: recs, assessment: a, forecast: fc };
  }

  // ── Scaling Scenarios ───────────────────────────────────────────

  function scenario(targetRps) {
    if (!targetRps || targetRps <= 0) throw new Error('targetRps must be positive');
    var a = assess();
    if (a.status === 'no-data') return null;

    var currentMax = maxRps;
    var scaleFactor = Math.ceil((targetRps / (currentMax * (1 - headroom))) * 100) / 100;
    var additionalInstances = Math.max(0, Math.ceil(scaleFactor) - 1);

    return {
      targetRps: targetRps,
      currentCapacity: currentMax,
      effectiveCapacity: Math.round(currentMax * (1 - headroom)),
      requiredCapacity: Math.round(targetRps / (1 - headroom)),
      scaleFactor: scaleFactor,
      additionalInstances: additionalInstances,
      totalInstances: additionalInstances + 1,
      canHandle: targetRps <= currentMax * (1 - headroom),
      estimatedLatencyImpact: targetRps > currentMax * 0.8 ? 'degraded' : 'nominal'
    };
  }

  // ── Hourly Profile ──────────────────────────────────────────────

  function hourlyProfile() {
    if (!samples.length) return [];
    var buckets = {};
    for (var i = 0; i < 24; i++) buckets[i] = [];
    for (var j = 0; j < samples.length; j++) {
      var hour = new Date(samples[j].timestamp).getUTCHours();
      buckets[hour].push(samples[j].rps);
    }
    var profile = [];
    for (var h = 0; h < 24; h++) {
      profile.push({
        hour: h,
        sampleCount: buckets[h].length,
        avgRps: buckets[h].length ? Math.round(_mean(buckets[h]) * 100) / 100 : 0,
        maxRps: buckets[h].length ? Math.max.apply(null, buckets[h]) : 0,
        utilization: buckets[h].length ? Math.round((_mean(buckets[h]) / maxRps) * 10000) / 10000 : 0
      });
    }
    return profile;
  }

  // ── Report ──────────────────────────────────────────────────────

  function report(options) {
    var ropts = options || {};
    var format = ropts.format || 'json';

    var data = {
      generated: new Date().toISOString(),
      config: { maxRps: maxRps, maxLatencyMs: maxLatencyMs, maxErrorRate: maxErrorRate, headroom: headroom },
      stats: stats(),
      assessment: assess(),
      forecast: samples.length >= 2 ? forecast({ horizonHours: ropts.horizonHours || 72 }) : null,
      recommendations: recommend().recommendations,
      hourlyProfile: hourlyProfile(),
      scenarios: ropts.scenarios ? ropts.scenarios.map(function (t) { return scenario(t); }) : undefined
    };

    if (format === 'json') return data;

    // Text format
    var lines = [];
    lines.push('═══════════════════════════════════════════');
    lines.push('  CAPTCHA CAPACITY PLANNING REPORT');
    lines.push('═══════════════════════════════════════════');
    lines.push('Generated: ' + data.generated);
    lines.push('');

    if (data.stats) {
      lines.push('── Traffic Statistics ──────────────────────');
      lines.push('  Samples: ' + data.stats.sampleCount);
      lines.push('  RPS — Mean: ' + data.stats.rps.mean.toFixed(1) + '  P95: ' + data.stats.rps.p95.toFixed(1) + '  Max: ' + data.stats.rps.max.toFixed(1));
      lines.push('  Latency — Mean: ' + data.stats.latencyMs.mean.toFixed(0) + 'ms  P95: ' + data.stats.latencyMs.p95.toFixed(0) + 'ms');
      lines.push('  Error Rate — Mean: ' + (data.stats.errorRate.mean * 100).toFixed(2) + '%');
      lines.push('');
    }

    var a = data.assessment;
    if (a.status !== 'no-data') {
      lines.push('── Capacity Assessment ────────────────────');
      lines.push('  Status: ' + a.status.toUpperCase());
      lines.push('  Utilization: ' + (a.utilization * 100).toFixed(1) + '%');
      lines.push('  Peak Utilization: ' + (a.peakUtilization * 100).toFixed(1) + '%');
      lines.push('  Effective Capacity: ' + a.effectiveCapacity + ' rps');
      lines.push('  Headroom: ' + a.headroomRps + ' rps');
      lines.push('');
    }

    if (data.forecast && data.forecast.trend) {
      lines.push('── Traffic Forecast ───────────────────────');
      lines.push('  Trend: ' + data.forecast.trend.direction + ' (' + data.forecast.trend.slope + ' rps/hour)');
      lines.push('  Confidence: ' + data.forecast.trend.confidence + ' (R²=' + data.forecast.trend.r2 + ')');
      if (data.forecast.timeToCapacityHours != null) {
        lines.push('  Time to Capacity: ' + (data.forecast.timeToCapacityHours / 24).toFixed(1) + ' days');
      }
      lines.push('');
    }

    if (data.recommendations.length) {
      lines.push('── Recommendations ────────────────────────');
      for (var r = 0; r < data.recommendations.length; r++) {
        var rec = data.recommendations[r];
        lines.push('  [' + rec.priority.toUpperCase() + '] ' + rec.action);
        lines.push('    ' + rec.detail);
      }
      lines.push('');
    }

    lines.push('═══════════════════════════════════════════');
    return lines.join('\n');
  }

  // ── Public API ──────────────────────────────────────────────────

  return {
    recordSample: recordSample,
    recordBatch: recordBatch,
    stats: stats,
    forecast: forecast,
    assess: assess,
    recommend: recommend,
    scenario: scenario,
    hourlyProfile: hourlyProfile,
    report: report,
    getSamples: function () { return samples.slice(); },
    clear: function () { samples.length = 0; }
  };
}

// ── Exports ─────────────────────────────────────────────────────────

module.exports = { createCapacityPlanner: createCapacityPlanner };
