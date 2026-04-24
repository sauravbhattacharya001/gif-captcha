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
  const maxSessions = opts.maxSessions != null && opts.maxSessions > 0
    ? opts.maxSessions : 10000;
  const maxRecords = opts.maxRecords != null && opts.maxRecords > 0
    ? opts.maxRecords : maxSessions * 4;

  // sessionId -> { cohort, stages: { stageName: { timestamp, timeMs } } }
  const sessions = new Map();
  // Insertion order for LRU eviction when maxSessions is reached
  const sessionOrder = [];
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
      // Evict oldest sessions when at capacity (LRU)
      while (sessions.size >= maxSessions && sessionOrder.length > 0) {
        var evicted = sessionOrder.shift();
        sessions.delete(evicted);
      }
      sessions.set(sessionId, { cohort: entry.cohort || "default", stages: {} });
      sessionOrder.push(sessionId);
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

    // Evict oldest records when over capacity
    if (records.length > maxRecords) {
      records.splice(0, records.length - maxRecords);
    }
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
    // Single-pass: aggregate counts, time sums, and session counts per cohort.
    // Previously this called _countByStage + _avgTimeByStage + a session count
    // loop per cohort, iterating all sessions 3× per cohort — O(cohorts × sessions).
    // Now it's O(sessions) total regardless of cohort count.
    var cohortData = Object.create(null); // cohort -> { counts, timeSums, timeCounts, sessionCount }

    sessions.forEach(function (session) {
      var c = session.cohort;
      if (!cohortData[c]) {
        var d = { counts: {}, timeSums: {}, timeCounts: {}, sessionCount: 0 };
        for (var si = 0; si < STAGES.length; si++) {
          d.counts[STAGES[si]] = 0;
          d.timeSums[STAGES[si]] = 0;
          d.timeCounts[STAGES[si]] = 0;
        }
        cohortData[c] = d;
      }
      var cd = cohortData[c];
      cd.sessionCount++;
      for (var si2 = 0; si2 < STAGES.length; si2++) {
        var st = STAGES[si2];
        if (session.stages[st]) {
          cd.counts[st]++;
          if (session.stages[st].timeMs != null) {
            cd.timeSums[st] += session.stages[st].timeMs;
            cd.timeCounts[st]++;
          }
        }
      }
    });

    var result = {};
    var cohorts = Object.keys(cohortData);
    for (var ci = 0; ci < cohorts.length; ci++) {
      var cohort = cohorts[ci];
      var cd = cohortData[cohort];
      var funnel = _buildFunnel(cd.counts);
      var avgTimes = {};
      for (var si3 = 0; si3 < STAGES.length; si3++) {
        var s = STAGES[si3];
        avgTimes[s] = cd.timeCounts[s] > 0 ? Math.round(cd.timeSums[s] / cd.timeCounts[s]) : null;
      }
      result[cohort] = {
        totalSessions: cd.sessionCount,
        funnel: funnel,
        averageTimeMs: avgTimes,
        overallConversion: cd.counts[STAGES[0]] > 0
          ? Math.round((cd.counts[STAGES[STAGES.length - 1]] / cd.counts[STAGES[0]]) * 10000) / 10000
          : 0,
      };
    }
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
    sessionOrder.length = 0;
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
