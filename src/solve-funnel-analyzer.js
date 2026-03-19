/**
 * solve-funnel-analyzer.js — CAPTCHA solve funnel analysis.
 *
 * Models the CAPTCHA user journey as a conversion funnel:
 *   Presented → Attempted → Completed → Solved
 *
 * Tracks drop-off between stages, supports cohort tagging,
 * time-based bucketing, and CSV/JSON export.
 *
 * Usage:
 *   const { createFunnelAnalyzer } = require('./solve-funnel-analyzer');
 *   const funnel = createFunnelAnalyzer();
 *
 *   funnel.record({ stage: 'presented', sessionId: 'a1', cohort: 'desktop' });
 *   funnel.record({ stage: 'attempted', sessionId: 'a1', cohort: 'desktop', timeMs: 1200 });
 *   funnel.record({ stage: 'completed', sessionId: 'a1', cohort: 'desktop', timeMs: 3400 });
 *   funnel.record({ stage: 'solved', sessionId: 'a1', cohort: 'desktop', timeMs: 3400 });
 *
 *   const report = funnel.report();         // full funnel report
 *   const cohorts = funnel.compareCohorts(); // side-by-side cohort comparison
 *   const csv = funnel.exportCSV();          // CSV export
 *   const json = funnel.exportJSON();        // JSON export
 *
 * @module solve-funnel-analyzer
 */

"use strict";

var csvUtils = require("./csv-utils");

const STAGES = ["presented", "attempted", "completed", "solved"];

function stageIndex(stage) {
  const idx = STAGES.indexOf(stage);
  if (idx === -1) throw new Error("Unknown stage: " + stage);
  return idx;
}

/**
 * Create a funnel analyzer instance.
 * @param {Object} [opts]
 * @param {number} [opts.bucketMs=3600000] - Time bucket size for trend analysis (default 1h)
 * @returns {Object} Funnel analyzer API
 */
function createFunnelAnalyzer(opts) {
  opts = opts || {};
  const bucketMs = opts.bucketMs || 3600000;

  // sessionId -> { cohort, stages: { stageName: { timestamp, timeMs } } }
  const sessions = new Map();
  // For time bucketing
  const records = [];

  function record(entry) {
    if (!entry || !entry.stage || !entry.sessionId) {
      throw new Error("record requires stage and sessionId");
    }
    stageIndex(entry.stage); // validate

    const ts = entry.timestamp || Date.now();
    const sessionId = entry.sessionId;

    if (!sessions.has(sessionId)) {
      sessions.set(sessionId, { cohort: entry.cohort || "default", stages: {} });
    }
    const session = sessions.get(sessionId);
    if (entry.cohort) session.cohort = entry.cohort;

    session.stages[entry.stage] = {
      timestamp: ts,
      timeMs: entry.timeMs || null,
    };

    records.push({
      sessionId,
      stage: entry.stage,
      cohort: session.cohort,
      timestamp: ts,
      timeMs: entry.timeMs || null,
    });
  }

  function _countByStage(filterFn) {
    const counts = {};
    STAGES.forEach(function (s) { counts[s] = 0; });

    sessions.forEach(function (session) {
      if (filterFn && !filterFn(session)) return;
      STAGES.forEach(function (s) {
        if (session.stages[s]) counts[s]++;
      });
    });
    return counts;
  }

  function _buildFunnel(counts) {
    const steps = [];
    for (var i = 0; i < STAGES.length; i++) {
      var stage = STAGES[i];
      var count = counts[stage];
      var prevCount = i === 0 ? count : counts[STAGES[i - 1]];
      var rate = prevCount > 0 ? count / prevCount : 0;
      var dropOff = prevCount > 0 ? 1 - rate : 0;
      var overallRate = counts[STAGES[0]] > 0 ? count / counts[STAGES[0]] : 0;
      steps.push({
        stage: stage,
        count: count,
        conversionRate: Math.round(rate * 10000) / 10000,
        dropOffRate: Math.round(dropOff * 10000) / 10000,
        overallRate: Math.round(overallRate * 10000) / 10000,
      });
    }
    return steps;
  }

  function _avgTimeByStage(filterFn) {
    var timeSums = {};
    var timeCounts = {};
    STAGES.forEach(function (s) { timeSums[s] = 0; timeCounts[s] = 0; });

    sessions.forEach(function (session) {
      if (filterFn && !filterFn(session)) return;
      STAGES.forEach(function (s) {
        if (session.stages[s] && session.stages[s].timeMs != null) {
          timeSums[s] += session.stages[s].timeMs;
          timeCounts[s]++;
        }
      });
    });

    var avgs = {};
    STAGES.forEach(function (s) {
      avgs[s] = timeCounts[s] > 0 ? Math.round(timeSums[s] / timeCounts[s]) : null;
    });
    return avgs;
  }

  function report() {
    var counts = _countByStage();
    var funnel = _buildFunnel(counts);
    var avgTimes = _avgTimeByStage();
    return {
      totalSessions: sessions.size,
      funnel: funnel,
      averageTimeMs: avgTimes,
      overallConversion: counts[STAGES[0]] > 0
        ? Math.round((counts[STAGES[STAGES.length - 1]] / counts[STAGES[0]]) * 10000) / 10000
        : 0,
    };
  }

  function compareCohorts() {
    // Find all cohorts
    var cohortSet = new Set();
    sessions.forEach(function (s) { cohortSet.add(s.cohort); });

    var result = {};
    cohortSet.forEach(function (cohort) {
      var counts = _countByStage(function (s) { return s.cohort === cohort; });
      var funnel = _buildFunnel(counts);
      var avgTimes = _avgTimeByStage(function (s) { return s.cohort === cohort; });
      var sessionCount = 0;
      sessions.forEach(function (s) { if (s.cohort === cohort) sessionCount++; });
      result[cohort] = {
        totalSessions: sessionCount,
        funnel: funnel,
        averageTimeMs: avgTimes,
        overallConversion: counts[STAGES[0]] > 0
          ? Math.round((counts[STAGES[STAGES.length - 1]] / counts[STAGES[0]]) * 10000) / 10000
          : 0,
      };
    });
    return result;
  }

  function trends() {
    if (records.length === 0) return [];
    var minTs = records[0].timestamp;
    var maxTs = records[records.length - 1].timestamp;
    // Bucket records
    var buckets = {};
    records.forEach(function (r) {
      var bk = Math.floor((r.timestamp - minTs) / bucketMs);
      if (!buckets[bk]) {
        buckets[bk] = { start: minTs + bk * bucketMs };
        STAGES.forEach(function (s) { buckets[bk][s] = 0; });
      }
      buckets[bk][r.stage]++;
    });

    var keys = Object.keys(buckets).map(Number).sort(function (a, b) { return a - b; });
    return keys.map(function (k) {
      var b = buckets[k];
      var conversion = b[STAGES[0]] > 0
        ? Math.round((b[STAGES[STAGES.length - 1]] / b[STAGES[0]]) * 10000) / 10000
        : 0;
      return {
        bucketStart: new Date(b.start).toISOString(),
        presented: b.presented,
        attempted: b.attempted,
        completed: b.completed,
        solved: b.solved,
        conversion: conversion,
      };
    });
  }

  function exportCSV() {
    var lines = ["sessionId,cohort,stage,timestamp,timeMs"];
    records.forEach(function (r) {
      lines.push(csvUtils.csvRow([r.sessionId, r.cohort, r.stage, new Date(r.timestamp).toISOString(), r.timeMs != null ? r.timeMs : ""]));
    });
    return lines.join("\n");
  }

  function exportJSON() {
    return JSON.stringify({
      report: report(),
      cohorts: compareCohorts(),
      trends: trends(),
      records: records.map(function (r) {
        return {
          sessionId: r.sessionId,
          cohort: r.cohort,
          stage: r.stage,
          timestamp: new Date(r.timestamp).toISOString(),
          timeMs: r.timeMs,
        };
      }),
    }, null, 2);
  }

  function reset() {
    sessions.clear();
    records.length = 0;
  }

  return {
    record: record,
    report: report,
    compareCohorts: compareCohorts,
    trends: trends,
    exportCSV: exportCSV,
    exportJSON: exportJSON,
    reset: reset,
    get sessionCount() { return sessions.size; },
    get recordCount() { return records.length; },
    STAGES: STAGES,
  };
}

module.exports = { createFunnelAnalyzer, STAGES };
