/**
 * captcha-retention-analyzer.js — Analyze user retention through the CAPTCHA funnel.
 *
 * Tracks users through stages: Presented → Attempted → Solved → Returned (24h) → Returned (7d).
 * Produces cohort heatmaps, funnel conversion rates, and retention insights.
 *
 * Usage:
 *   const { createRetentionAnalyzer } = require('./captcha-retention-analyzer');
 *   const analyzer = createRetentionAnalyzer({ cohortWindow: 'weekly' });
 *
 *   analyzer.trackEvent('user123', 'presented', { difficulty: 'medium' });
 *   analyzer.trackEvent('user123', 'attempted', { difficulty: 'medium' });
 *   analyzer.trackEvent('user123', 'solved',    { difficulty: 'medium', timeMs: 3200 });
 *
 *   const funnel   = analyzer.getFunnel({ difficulty: 'medium' });
 *   const cohorts  = analyzer.getCohorts();
 *   const insights = analyzer.getInsights();
 *   const csv      = analyzer.exportCSV();
 *
 * @module captcha-retention-analyzer
 */

"use strict";

var csvUtils = require("./csv-utils");

var STAGES = ['presented', 'attempted', 'solved', 'returned_24h', 'returned_7d'];
var STAGE_LABELS = ['Presented', 'Attempted', 'Solved', 'Returned (24h)', 'Returned (7d)'];

/**
 * Create a retention analyzer instance.
 * @param {Object} [opts]
 * @param {'daily'|'weekly'|'monthly'} [opts.cohortWindow='weekly']
 * @param {number} [opts.returnWindow24h=86400000] - 24h in ms
 * @param {number} [opts.returnWindow7d=604800000] - 7d in ms
 * @returns {Object}
 */
function createRetentionAnalyzer(opts) {
    opts = opts || {};
    var cohortWindow = opts.cohortWindow || 'weekly';
    var returnWindow24h = opts.returnWindow24h || 86400000;
    var returnWindow7d = opts.returnWindow7d || 604800000;

    // userId -> { firstSeen, lastSeen, stages: Set, difficulty, cohort }
    var users = {};
    var events = [];

    function getCohortKey(date) {
        var d = new Date(date);
        if (cohortWindow === 'daily') {
            return d.toISOString().slice(0, 10);
        } else if (cohortWindow === 'monthly') {
            return d.toISOString().slice(0, 7);
        }
        // weekly: Monday-aligned
        var day = d.getDay();
        var diff = d.getDate() - day + (day === 0 ? -6 : 1);
        var monday = new Date(d.setDate(diff));
        return monday.toISOString().slice(0, 10);
    }

    /**
     * Track a user event in the funnel.
     * @param {string} userId
     * @param {string} stage - One of: presented, attempted, solved, returned_24h, returned_7d
     * @param {Object} [meta] - Optional metadata (difficulty, timeMs, etc.)
     */
    function trackEvent(userId, stage, meta) {
        if (STAGES.indexOf(stage) === -1) {
            throw new Error('Invalid stage: ' + stage + '. Must be one of: ' + STAGES.join(', '));
        }
        meta = meta || {};
        var now = Date.now();

        if (!users[userId]) {
            users[userId] = {
                firstSeen: now,
                lastSeen: now,
                stages: {},
                difficulty: meta.difficulty || 'unknown',
                cohort: getCohortKey(now)
            };
        }

        var user = users[userId];
        user.lastSeen = now;
        user.stages[stage] = now;

        if (meta.difficulty) {
            user.difficulty = meta.difficulty;
        }

        // Auto-detect returns based on time since solve
        if (stage === 'presented' && user.stages.solved) {
            var sinceSolve = now - user.stages.solved;
            if (sinceSolve >= returnWindow24h && !user.stages.returned_24h) {
                user.stages.returned_24h = now;
            }
            if (sinceSolve >= returnWindow7d && !user.stages.returned_7d) {
                user.stages.returned_7d = now;
            }
        }

        events.push({
            userId: userId,
            stage: stage,
            timestamp: now,
            meta: meta
        });
    }

    /**
     * Get funnel conversion data.
     * @param {Object} [filter]
     * @param {string} [filter.difficulty]
     * @returns {Array<{stage: string, count: number, rate: number}>}
     */
    function getFunnel(filter) {
        filter = filter || {};
        var filtered = Object.keys(users).filter(function(uid) {
            if (filter.difficulty && filter.difficulty !== 'all') {
                return users[uid].difficulty === filter.difficulty;
            }
            return true;
        });

        var total = filtered.length || 1;
        return STAGES.map(function(stage, i) {
            var count = filtered.filter(function(uid) {
                return !!users[uid].stages[stage];
            }).length;
            return {
                stage: STAGE_LABELS[i],
                count: count,
                rate: count / total
            };
        });
    }

    /**
     * Get cohort retention data.
     * @returns {Array<{cohort: string, initial: number, retentions: number[]}>}
     */
    function getCohorts() {
        var cohortMap = {};
        Object.keys(users).forEach(function(uid) {
            var u = users[uid];
            if (!cohortMap[u.cohort]) {
                cohortMap[u.cohort] = [];
            }
            cohortMap[u.cohort].push(u);
        });

        var cohortKeys = Object.keys(cohortMap).sort();
        return cohortKeys.map(function(key) {
            var members = cohortMap[key];
            var initial = members.length;
            var solved = members.filter(function(u) { return !!u.stages.solved; }).length;
            var ret24 = members.filter(function(u) { return !!u.stages.returned_24h; }).length;
            var ret7d = members.filter(function(u) { return !!u.stages.returned_7d; }).length;
            return {
                cohort: key,
                initial: initial,
                retentions: [
                    1.0,
                    initial > 0 ? solved / initial : 0,
                    initial > 0 ? ret24 / initial : 0,
                    initial > 0 ? ret7d / initial : 0
                ]
            };
        });
    }

    /**
     * Generate automated insights from the current data.
     * @returns {Array<{text: string, type: string}>}
     */
    function getInsights() {
        var funnel = getFunnel();
        var insights = [];
        var presented = funnel[0].count || 1;
        var attempted = funnel[1].count;
        var solved = funnel[2].count;
        var ret24 = funnel[3].count;
        var ret7d = funnel[4].count;

        var attemptRate = attempted / presented;
        var solveRate = solved / (attempted || 1);
        var retRate24 = ret24 / (solved || 1);
        var retRate7d = ret7d / (solved || 1);

        if (attemptRate < 0.8) {
            insights.push({ text: 'Low attempt rate (' + (attemptRate * 100).toFixed(1) + '%) — users may find the CAPTCHA intimidating.', type: 'warning' });
        }
        if (solveRate < 0.7) {
            insights.push({ text: 'Solve rate is ' + (solveRate * 100).toFixed(1) + '% — consider lowering difficulty.', type: 'warning' });
        }
        if (retRate24 > 0.6) {
            insights.push({ text: 'Strong 24h retention at ' + (retRate24 * 100).toFixed(1) + '%.', type: 'success' });
        }
        if (retRate7d < 0.3) {
            insights.push({ text: '7-day retention below 30% — CAPTCHA friction may be driving churn.', type: 'danger' });
        }

        // Difficulty comparison
        var diffs = ['easy', 'medium', 'hard', 'extreme'];
        var bestDiff = null, bestRet = 0;
        diffs.forEach(function(d) {
            var f = getFunnel({ difficulty: d });
            var s = f[2].count;
            var r = f[4].count;
            var rate = s > 0 ? r / s : 0;
            if (rate > bestRet) {
                bestRet = rate;
                bestDiff = d;
            }
        });
        if (bestDiff) {
            insights.push({ text: 'Best 7d retention by difficulty: "' + bestDiff + '" at ' + (bestRet * 100).toFixed(1) + '%.', type: 'info' });
        }

        return insights;
    }

    /**
     * Export funnel data as CSV.
     * @returns {string}
     */
    function exportCSV() {
        var funnel = getFunnel();
        var rows = [['Stage', 'Count', 'Rate']];
        funnel.forEach(function(s) {
            rows.push([s.stage, String(s.count), (s.rate * 100).toFixed(1) + '%']);
        });
        return csvUtils.toCsv(rows);
    }

    /**
     * Reset all data.
     */
    function reset() {
        users = {};
        events = [];
    }

    return {
        trackEvent: trackEvent,
        getFunnel: getFunnel,
        getCohorts: getCohorts,
        getInsights: getInsights,
        exportCSV: exportCSV,
        reset: reset,
        get eventCount() { return events.length; },
        get userCount() { return Object.keys(users).length; }
    };
}

module.exports = { createRetentionAnalyzer: createRetentionAnalyzer };
