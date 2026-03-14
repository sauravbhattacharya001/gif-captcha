/**
 * captcha-stats-collector.js — Collect and aggregate CAPTCHA solve metrics.
 *
 * Tracks solve attempts with time-windowed aggregation, percentile
 * calculations, success/failure breakdowns, and JSON/CSV export.
 *
 * Usage:
 *   const { createStatsCollector } = require('./captcha-stats-collector');
 *   const stats = createStatsCollector({ windowMs: 60000, maxWindows: 60 });
 *
 *   stats.record({ solved: true, timeMs: 2340, challengeType: 'sequence' });
 *   stats.record({ solved: false, timeMs: 8100, challengeType: 'pattern' });
 *
 *   const summary = stats.summary();       // current window summary
 *   const report  = stats.report();        // all windows
 *   const csv     = stats.exportCSV();     // CSV string
 *   const json    = stats.exportJSON();    // JSON string
 *
 * @module captcha-stats-collector
 */

"use strict";

/**
 * Compute percentile from a sorted array of numbers.
 * @param {number[]} sorted
 * @param {number} p - percentile 0-100
 * @returns {number|null}
 */
function percentile(sorted, p) {
  if (!sorted.length) return null;
  if (sorted.length === 1) return sorted[0];
  const idx = (p / 100) * (sorted.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

/**
 * @typedef {Object} RecordEntry
 * @property {boolean}  solved         - Whether the challenge was solved
 * @property {number}   timeMs         - Time taken in milliseconds
 * @property {string}   [challengeType] - Optional challenge type tag
 * @property {number}   [timestamp]    - Unix ms timestamp (auto-set if omitted)
 * @property {Object}   [meta]         - Arbitrary metadata
 */

/**
 * @typedef {Object} WindowBucket
 * @property {number}   start       - Window start timestamp
 * @property {number}   end         - Window end timestamp
 * @property {number}   total       - Total attempts
 * @property {number}   solved      - Successful solves
 * @property {number}   failed      - Failed attempts
 * @property {number[]} solveTimes  - All solve times (ms)
 * @property {Object}   byType      - Breakdown by challengeType
 */

/**
 * Create a stats collector instance.
 *
 * @param {Object} [options]
 * @param {number} [options.windowMs=60000]   - Window duration in ms (default 1 min)
 * @param {number} [options.maxWindows=60]    - Max windows to retain (default 60)
 * @param {number[]} [options.percentiles]    - Percentiles to compute (default [50,90,95,99])
 * @returns {Object} stats collector API
 */
function createStatsCollector(options = {}) {
  const windowMs = options.windowMs != null && options.windowMs > 0
    ? options.windowMs : 60000;
  const maxWindows = options.maxWindows != null && options.maxWindows > 0
    ? options.maxWindows : 60;
  const pctiles = Array.isArray(options.percentiles) && options.percentiles.length
    ? options.percentiles : [50, 90, 95, 99];

  /** @type {WindowBucket[]} */
  const windows = [];

  /** @type {RecordEntry[]} */
  const rawRecords = [];

  let lifetimeTotal = 0;
  let lifetimeSolved = 0;

  function _windowStart(ts) {
    return Math.floor(ts / windowMs) * windowMs;
  }

  function _getOrCreateWindow(ts) {
    const start = _windowStart(ts);
    const end = start + windowMs;
    // Most recent window is last — fast path
    if (windows.length > 0) {
      const last = windows[windows.length - 1];
      if (last.start === start) return last;
    }
    const bucket = {
      start,
      end,
      total: 0,
      solved: 0,
      failed: 0,
      solveTimes: [],
      byType: {}
    };
    windows.push(bucket);
    // Evict old windows
    if (windows.length > maxWindows) {
      var excess = windows.length - maxWindows;
      windows.splice(0, excess);
    }
    return bucket;
  }

  /**
   * Record a CAPTCHA attempt.
   * @param {RecordEntry} entry
   */
  function record(entry) {
    if (!entry || typeof entry !== "object") {
      throw new Error("record() requires an object with { solved, timeMs }");
    }
    if (typeof entry.solved !== "boolean") {
      throw new Error("record() requires entry.solved to be a boolean");
    }
    if (typeof entry.timeMs !== "number" || entry.timeMs < 0) {
      throw new Error("record() requires entry.timeMs to be a non-negative number");
    }

    const ts = entry.timestamp || Date.now();
    const bucket = _getOrCreateWindow(ts);

    bucket.total++;
    lifetimeTotal++;

    if (entry.solved) {
      bucket.solved++;
      lifetimeSolved++;
      bucket.solveTimes.push(entry.timeMs);
    } else {
      bucket.failed++;
    }

    // Per-type breakdown
    const type = entry.challengeType || "_default";
    if (!bucket.byType[type]) {
      bucket.byType[type] = { total: 0, solved: 0, failed: 0, solveTimes: [] };
    }
    const tb = bucket.byType[type];
    tb.total++;
    if (entry.solved) {
      tb.solved++;
      tb.solveTimes.push(entry.timeMs);
    } else {
      tb.failed++;
    }

    rawRecords.push({ ...entry, timestamp: ts });
    // Cap raw records at 10x maxWindows to bound memory
    if (rawRecords.length > maxWindows * 100) {
      var excess = rawRecords.length - maxWindows * 100;
      rawRecords.splice(0, excess);
    }
  }

  /**
   * Compute statistics for an array of solve times.
   * @param {number[]} times
   * @returns {Object}
   */
  function _computeTimeStats(times) {
    if (!times.length) {
      return { count: 0, min: null, max: null, mean: null, percentiles: {} };
    }
    const sorted = [...times].sort((a, b) => a - b);
    const sum = sorted.reduce((s, v) => s + v, 0);
    const result = {
      count: sorted.length,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      mean: Math.round((sum / sorted.length) * 100) / 100,
      percentiles: {}
    };
    for (const p of pctiles) {
      result.percentiles[`p${p}`] = Math.round(percentile(sorted, p) * 100) / 100;
    }
    return result;
  }

  /**
   * Get summary of the most recent window.
   * @returns {Object|null}
   */
  function summary() {
    if (!windows.length) return null;
    const w = windows[windows.length - 1];
    return {
      window: { start: w.start, end: w.end },
      total: w.total,
      solved: w.solved,
      failed: w.failed,
      solveRate: w.total ? Math.round((w.solved / w.total) * 10000) / 100 : 0,
      timing: _computeTimeStats(w.solveTimes),
      byType: Object.fromEntries(
        Object.entries(w.byType).map(([type, data]) => [
          type,
          {
            total: data.total,
            solved: data.solved,
            failed: data.failed,
            solveRate: data.total ? Math.round((data.solved / data.total) * 10000) / 100 : 0,
            timing: _computeTimeStats(data.solveTimes)
          }
        ])
      )
    };
  }

  /**
   * Get full report across all retained windows.
   * @returns {Object}
   */
  function report() {
    const allTimes = [];
    let totalAttempts = 0;
    let totalSolved = 0;
    const typeAgg = {};

    for (const w of windows) {
      totalAttempts += w.total;
      totalSolved += w.solved;
      allTimes.push(...w.solveTimes);

      for (const [type, data] of Object.entries(w.byType)) {
        if (!typeAgg[type]) {
          typeAgg[type] = { total: 0, solved: 0, failed: 0, solveTimes: [] };
        }
        typeAgg[type].total += data.total;
        typeAgg[type].solved += data.solved;
        typeAgg[type].failed += data.failed;
        typeAgg[type].solveTimes.push(...data.solveTimes);
      }
    }

    return {
      windowCount: windows.length,
      windowMs,
      lifetime: { total: lifetimeTotal, solved: lifetimeSolved },
      aggregate: {
        total: totalAttempts,
        solved: totalSolved,
        failed: totalAttempts - totalSolved,
        solveRate: totalAttempts
          ? Math.round((totalSolved / totalAttempts) * 10000) / 100
          : 0,
        timing: _computeTimeStats(allTimes)
      },
      byType: Object.fromEntries(
        Object.entries(typeAgg).map(([type, data]) => [
          type,
          {
            total: data.total,
            solved: data.solved,
            failed: data.failed,
            solveRate: data.total
              ? Math.round((data.solved / data.total) * 10000) / 100
              : 0,
            timing: _computeTimeStats(data.solveTimes)
          }
        ])
      ),
      windows: windows.map(w => ({
        start: w.start,
        end: w.end,
        total: w.total,
        solved: w.solved,
        failed: w.failed,
        solveRate: w.total ? Math.round((w.solved / w.total) * 10000) / 100 : 0
      }))
    };
  }

  /**
   * Export all windows as CSV string.
   * @returns {string}
   */
  function exportCSV() {
    const header = "window_start,window_end,total,solved,failed,solve_rate,p50_ms,p90_ms,p95_ms,p99_ms,mean_ms";
    const rows = windows.map(w => {
      const ts = _computeTimeStats(w.solveTimes);
      return [
        new Date(w.start).toISOString(),
        new Date(w.end).toISOString(),
        w.total,
        w.solved,
        w.failed,
        w.total ? Math.round((w.solved / w.total) * 10000) / 100 : 0,
        ts.percentiles.p50 ?? "",
        ts.percentiles.p90 ?? "",
        ts.percentiles.p95 ?? "",
        ts.percentiles.p99 ?? "",
        ts.mean ?? ""
      ].join(",");
    });
    return [header, ...rows].join("\n");
  }

  /**
   * Export full report as JSON string.
   * @param {number} [indent=2] - JSON indentation
   * @returns {string}
   */
  function exportJSON(indent = 2) {
    return JSON.stringify(report(), null, indent);
  }

  /**
   * Reset all collected data.
   */
  function reset() {
    windows.length = 0;
    rawRecords.length = 0;
    lifetimeTotal = 0;
    lifetimeSolved = 0;
  }

  /**
   * Get the number of retained windows.
   * @returns {number}
   */
  function windowCount() {
    return windows.length;
  }

  return {
    record,
    summary,
    report,
    exportCSV,
    exportJSON,
    reset,
    windowCount
  };
}

module.exports = { createStatsCollector, percentile };
