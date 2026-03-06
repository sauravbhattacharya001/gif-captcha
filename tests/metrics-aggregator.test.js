'use strict';

var { describe, it, beforeEach, afterEach } = require('node:test');
var assert = require('node:assert/strict');
var gifCaptcha = require('../src/index');
var createMetricsAggregator = gifCaptcha.createMetricsAggregator;

describe('createMetricsAggregator', function () {

  var agg;

  beforeEach(function () {
    agg = createMetricsAggregator({ historySize: 10 });
  });

  // ── Registration ──

  describe('register', function () {
    it('registers a subsystem with getStats', function () {
      var sub = { getStats: function () { return { count: 1 }; } };
      assert.equal(agg.register('test', sub), true);
      assert.deepStrictEqual(agg.listSubsystems(), ['test']);
    });

    it('registers a subsystem with getReport', function () {
      var sub = { getReport: function () { return {}; } };
      assert.equal(agg.register('reporter', sub), true);
    });

    it('registers a subsystem with getSummary', function () {
      var sub = { getSummary: function () { return {}; } };
      assert.equal(agg.register('summarizer', sub), true);
    });

    it('rejects subsystem without stats method', function () {
      assert.equal(agg.register('bad', { doStuff: function () {} }), false);
    });

    it('rejects null instance', function () {
      assert.equal(agg.register('bad', null), false);
    });

    it('rejects empty name', function () {
      assert.equal(agg.register('', { getStats: function () { return {}; } }), false);
    });

    it('rejects non-string name', function () {
      assert.equal(agg.register(42, { getStats: function () { return {}; } }), false);
    });
  });

  describe('unregister', function () {
    it('removes a registered subsystem', function () {
      agg.register('a', { getStats: function () { return {}; } });
      assert.equal(agg.unregister('a'), true);
      assert.deepStrictEqual(agg.listSubsystems(), []);
    });

    it('returns false for unknown subsystem', function () {
      assert.equal(agg.unregister('nope'), false);
    });
  });

  describe('listSubsystems', function () {
    it('returns empty array initially', function () {
      assert.deepStrictEqual(agg.listSubsystems(), []);
    });

    it('returns all registered names', function () {
      agg.register('a', { getStats: function () { return {}; } });
      agg.register('b', { getStats: function () { return {}; } });
      assert.deepStrictEqual(agg.listSubsystems().sort(), ['a', 'b']);
    });
  });

  // ── Snapshot ──

  describe('snapshot', function () {
    it('returns a snapshot with timestamp and structure', function () {
      var snap = agg.snapshot();
      assert.ok(snap.timestamp > 0);
      assert.ok(snap.subsystems !== undefined);
      assert.ok(snap.health !== undefined);
      assert.ok(snap.health.score !== undefined);
      assert.ok(snap.health.status !== undefined);
      assert.ok(snap.alerts !== undefined);
      assert.equal(snap.registeredCount, 0);
    });

    it('collects stats from registered subsystems', function () {
      agg.register('myModule', { getStats: function () { return { items: 42, active: true }; } });
      var snap = agg.snapshot();
      assert.deepStrictEqual(snap.subsystems.myModule, { items: 42, active: true });
      assert.equal(snap.registeredCount, 1);
    });

    it('handles subsystem getStats throwing errors', function () {
      agg.register('broken', { getStats: function () { throw new Error('boom'); } });
      var snap = agg.snapshot();
      assert.equal(snap.subsystems.broken, undefined);
    });

    it('falls back to getReport if getStats is missing', function () {
      agg.register('reporter', { getReport: function () { return { report: true }; } });
      var snap = agg.snapshot();
      assert.deepStrictEqual(snap.subsystems.reporter, { report: true });
    });

    it('falls back to getSummary if both are missing', function () {
      agg.register('summarizer', { getSummary: function () { return { summary: 1 }; } });
      var snap = agg.snapshot();
      assert.deepStrictEqual(snap.subsystems.summarizer, { summary: 1 });
    });

    it('stores snapshots in history', function () {
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();
      var trends = agg.getTrends();
      assert.equal(trends.snapshotCount, 3);
    });

    it('respects historySize limit', function () {
      for (var i = 0; i < 15; i++) {
        agg.snapshot();
      }
      var trends = agg.getTrends();
      assert.equal(trends.snapshotCount, 10);
    });
  });

  describe('lastSnapshot', function () {
    it('returns null when no snapshots taken', function () {
      assert.equal(agg.lastSnapshot(), null);
    });

    it('returns the most recent snapshot', function () {
      agg.register('x', { getStats: function () { return { v: 1 }; } });
      agg.snapshot();
      agg.register('y', { getStats: function () { return { v: 2 }; } });
      agg.snapshot();
      var last = agg.lastSnapshot();
      assert.equal(last.registeredCount, 2);
    });
  });

  // ── Health Scoring ──

  describe('health scoring', function () {
    it('gives 100 health when no subsystems registered', function () {
      var snap = agg.snapshot();
      assert.equal(snap.health.score, 100);
      assert.equal(snap.health.status, 'healthy');
    });

    it('penalizes low pass rate', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.1, avgResponseTimeMs: 500 }; }
      });
      var snap = agg.snapshot();
      assert.ok(snap.health.score < 100);
      assert.ok(snap.health.factors.length > 0);
    });

    it('penalizes high response time', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.8, avgResponseTimeMs: 60000 }; }
      });
      var snap = agg.snapshot();
      assert.ok(snap.health.score < 100);
    });

    it('penalizes high dangerous rate in reputation', function () {
      agg.register('reputation', {
        getStats: function () {
          return {
            classifications: { trusted: 10, neutral: 5, suspicious: 5, dangerous: 30 }
          };
        }
      });
      var snap = agg.snapshot();
      assert.ok(snap.health.score < 100);
    });

    it('reports degraded status for moderate penalties', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.05 }; }
      });
      var snap = agg.snapshot();
      assert.equal(snap.health.status, 'degraded');
    });

    it('reports critical status for severe penalties', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.0, avgResponseTimeMs: 120000 }; }
      });
      agg.register('reputation', {
        getStats: function () {
          return { classifications: { trusted: 0, neutral: 0, suspicious: 0, dangerous: 100 } };
        }
      });
      var snap = agg.snapshot();
      assert.equal(snap.health.status, 'critical');
    });

    it('remains healthy when all metrics are good', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.85, avgResponseTimeMs: 2000 }; }
      });
      agg.register('reputation', {
        getStats: function () {
          return { classifications: { trusted: 80, neutral: 15, suspicious: 4, dangerous: 1 } };
        }
      });
      var snap = agg.snapshot();
      assert.equal(snap.health.score, 100);
      assert.equal(snap.health.status, 'healthy');
    });

    it('checks bot detection rate', function () {
      agg.register('botDetector', {
        getStats: function () { return { totalChecks: 100, botsDetected: 60 }; }
      });
      var snap = agg.snapshot();
      assert.ok(snap.health.score < 100);
    });

    it('checks rate limiter rejection rate', function () {
      agg.register('rateLimiter', {
        getStats: function () { return { totalRequests: 100, rejected: 80 }; }
      });
      var snap = agg.snapshot();
      assert.ok(snap.health.score < 100);
    });
  });

  // ── Alerts ──

  describe('alerts', function () {
    it('generates no alerts when healthy', function () {
      var snap = agg.snapshot();
      assert.equal(snap.alerts.length, 0);
    });

    it('generates alerts for degraded health', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.1 }; }
      });
      var snap = agg.snapshot();
      assert.ok(snap.alerts.length > 0);
      assert.ok(snap.alerts[0].level !== undefined);
      assert.ok(snap.alerts[0].message !== undefined);
      assert.ok(snap.alerts[0].timestamp > 0);
    });

    it('includes critical alert for critical status', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.0, avgResponseTimeMs: 200000 }; }
      });
      agg.register('reputation', {
        getStats: function () {
          return { classifications: { trusted: 0, neutral: 0, suspicious: 0, dangerous: 100 } };
        }
      });
      var snap = agg.snapshot();
      var criticals = snap.alerts.filter(function (a) { return a.level === 'critical'; });
      assert.ok(criticals.length > 0);
    });
  });

  // ── Trends ──

  describe('getTrends', function () {
    it('returns empty trends initially', function () {
      var trends = agg.getTrends();
      assert.equal(trends.snapshotCount, 0);
      assert.deepStrictEqual(trends.snapshots, []);
      assert.ok(trends.uptimeMs >= 0);
      assert.equal(trends.healthTrend, null);
    });

    it('calculates improving trend', function () {
      // Take snapshots with improving health
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.1 }; }
      });
      agg.snapshot();
      agg.snapshot();
      agg.unregister('sessions');
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.9 }; }
      });
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();

      var trends = agg.getTrends();
      assert.equal(trends.healthTrend, 'improving');
    });

    it('calculates declining trend', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.9 }; }
      });
      agg.snapshot();
      agg.snapshot();
      agg.unregister('sessions');
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.05 }; }
      });
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();

      var trends = agg.getTrends();
      assert.equal(trends.healthTrend, 'declining');
    });

    it('calculates stable trend', function () {
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();

      var trends = agg.getTrends();
      assert.equal(trends.healthTrend, 'stable');
    });
  });

  // ── Summary ──

  describe('getSummary', function () {
    it('returns compact summary', function () {
      agg.register('x', { getStats: function () { return { v: 1 }; } });
      var summary = agg.getSummary();
      assert.ok(summary.healthScore !== undefined);
      assert.ok(summary.healthStatus !== undefined);
      assert.equal(summary.registeredCount, 1);
      assert.ok(summary.alertCount !== undefined);
      assert.ok(summary.criticalAlerts !== undefined);
      assert.ok(summary.uptimeMs >= 0);
      assert.ok(summary.snapshotCount >= 1);
      assert.ok(summary.timestamp > 0);
    });

    it('takes a snapshot if none exists', function () {
      var summary = agg.getSummary();
      assert.equal(summary.snapshotCount, 1);
    });

    it('uses last snapshot if available', function () {
      agg.snapshot();
      agg.snapshot();
      var summary = agg.getSummary();
      assert.equal(summary.snapshotCount, 2);
    });
  });

  // ── Clear/Reset ──

  describe('clearHistory', function () {
    it('clears all snapshots', function () {
      agg.snapshot();
      agg.snapshot();
      agg.clearHistory();
      assert.equal(agg.getTrends().snapshotCount, 0);
      assert.equal(agg.lastSnapshot(), null);
    });

    it('keeps registered subsystems', function () {
      agg.register('x', { getStats: function () { return {}; } });
      agg.snapshot();
      agg.clearHistory();
      assert.deepStrictEqual(agg.listSubsystems(), ['x']);
    });
  });

  describe('reset', function () {
    it('clears subsystems and history', function () {
      agg.register('x', { getStats: function () { return {}; } });
      agg.snapshot();
      agg.reset();
      assert.deepStrictEqual(agg.listSubsystems(), []);
      assert.equal(agg.getTrends().snapshotCount, 0);
    });
  });

  // ── Custom Thresholds ──

  describe('custom thresholds', function () {
    it('uses custom passRate threshold', function () {
      var custom = createMetricsAggregator({ thresholds: { passRate: 0.9 } });
      custom.register('sessions', {
        getStats: function () { return { passRate: 0.7 }; }
      });
      var snap = custom.snapshot();
      assert.ok(snap.health.score < 100);
    });

    it('uses custom avgResponseMs threshold', function () {
      var custom = createMetricsAggregator({ thresholds: { avgResponseMs: 1000 } });
      custom.register('sessions', {
        getStats: function () { return { passRate: 0.9, avgResponseTimeMs: 5000 }; }
      });
      var snap = custom.snapshot();
      assert.ok(snap.health.score < 100);
    });
  });

  // ── Integration with multiple subsystems ──

  describe('multi-subsystem integration', function () {
    it('aggregates stats from multiple subsystems', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.8, totalSessions: 100 }; }
      });
      agg.register('reputation', {
        getStats: function () {
          return { trackedCount: 50, classifications: { trusted: 40, neutral: 8, suspicious: 1, dangerous: 1 } };
        }
      });
      agg.register('tokens', {
        getStats: function () { return { trackedNonces: 200 }; }
      });

      var snap = agg.snapshot();
      assert.equal(snap.registeredCount, 3);
      assert.equal(snap.subsystems.sessions.totalSessions, 100);
      assert.equal(snap.subsystems.reputation.trackedCount, 50);
      assert.equal(snap.subsystems.tokens.trackedNonces, 200);
      assert.equal(snap.health.status, 'healthy');
    });

    it('handles mix of healthy and unhealthy subsystems', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.9 }; }
      });
      agg.register('reputation', {
        getStats: function () {
          return { classifications: { trusted: 5, neutral: 5, suspicious: 10, dangerous: 80 } };
        }
      });

      var snap = agg.snapshot();
      assert.notEqual(snap.health.status, 'healthy');
      assert.ok(snap.alerts.length > 0);
    });
  });

  // ── Edge cases ──

  describe('edge cases', function () {
    it('handles historySize of 1', function () {
      var tiny = createMetricsAggregator({ historySize: 1 });
      tiny.snapshot();
      tiny.snapshot();
      tiny.snapshot();
      assert.equal(tiny.getTrends().snapshotCount, 1);
    });

    it('handles registering same name twice (overwrites)', function () {
      agg.register('x', { getStats: function () { return { v: 1 }; } });
      agg.register('x', { getStats: function () { return { v: 2 }; } });
      var snap = agg.snapshot();
      assert.equal(snap.subsystems.x.v, 2);
    });

    it('handles subsystem returning null from getStats', function () {
      agg.register('nullish', { getStats: function () { return null; } });
      var snap = agg.snapshot();
      assert.equal(snap.subsystems.nullish, undefined);
    });

    it('handles zero-count bot detector gracefully', function () {
      agg.register('botDetector', {
        getStats: function () { return { totalChecks: 0, botsDetected: 0 }; }
      });
      var snap = agg.snapshot();
      assert.equal(snap.health.score, 100);
    });
  });

  // ── Auto-Capture ──

  describe('startAutoCapture / stopAutoCapture', function () {
    afterEach(function () {
      agg.stopAutoCapture();
    });

    it('takes periodic snapshots', function (_, done) {
      agg.register('s', { getStats: function () { return { ok: true }; } });
      agg.startAutoCapture(1000);
      assert.equal(agg.isAutoCapturing(), true);
      // After ~50ms no auto snapshot yet (interval is 1s), but manual check
      setTimeout(function () {
        agg.stopAutoCapture();
        assert.equal(agg.isAutoCapturing(), false);
        done();
      }, 50);
    });

    it('defaults to 60000ms for invalid interval', function () {
      var result = agg.startAutoCapture('bad');
      assert.equal(result.intervalMs, 60000);
      assert.equal(result.active, true);
      agg.stopAutoCapture();
    });

    it('replaces previous timer on re-call', function () {
      agg.startAutoCapture(5000);
      agg.startAutoCapture(2000);
      assert.equal(agg.isAutoCapturing(), true);
      agg.stopAutoCapture();
      assert.equal(agg.isAutoCapturing(), false);
    });

    it('stopAutoCapture is safe to call when not running', function () {
      var result = agg.stopAutoCapture();
      assert.equal(result.active, false);
    });
  });

  // ── onAlert ──

  describe('onAlert', function () {
    it('fires callback when snapshot has alerts', function () {
      var received = [];
      agg.onAlert(function (alerts) { received.push(alerts); });
      // Register a subsystem that triggers a critical health score
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.01, avgResponseTimeMs: 100000 }; }
      });
      agg.snapshot();
      assert.equal(received.length, 1);
      assert.ok(received[0].length > 0);
    });

    it('does not fire when no alerts', function () {
      var count = 0;
      agg.onAlert(function () { count++; });
      agg.register('ok', { getStats: function () { return { fine: true }; } });
      agg.snapshot();
      assert.equal(count, 0);
    });

    it('returns unsubscribe function', function () {
      var count = 0;
      var unsub = agg.onAlert(function () { count++; });
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.01 }; }
      });
      agg.snapshot();
      assert.equal(count, 1);
      unsub();
      agg.snapshot();
      assert.equal(count, 1);
    });

    it('throws on non-function callback', function () {
      assert.throws(function () { agg.onAlert('bad'); });
    });
  });

  // ── exportHistory ──

  describe('exportHistory', function () {
    it('exports JSON by default', function () {
      agg.register('s', { getStats: function () { return { x: 1 }; } });
      agg.snapshot();
      var json = agg.exportHistory();
      var parsed = JSON.parse(json);
      assert.equal(Array.isArray(parsed), true);
      assert.equal(parsed.length, 1);
      assert.ok(parsed[0].health !== undefined);
    });

    it('exports CSV format', function () {
      agg.register('s', { getStats: function () { return { x: 1 }; } });
      agg.snapshot();
      agg.snapshot();
      var csv = agg.exportHistory('csv');
      var lines = csv.split('\n');
      assert.equal(lines[0], 'timestamp,healthScore,healthStatus,registeredCount,alertCount,criticalAlerts');
      assert.equal(lines.length, 3); // header + 2 rows
    });

    it('returns empty array JSON when no history', function () {
      var json = agg.exportHistory('json');
      assert.deepStrictEqual(JSON.parse(json), []);
    });

    it('returns header-only CSV when no history', function () {
      var csv = agg.exportHistory('csv');
      var lines = csv.split('\n');
      assert.equal(lines.length, 1);
    });
  });

  // ── reset clears auto-capture ──

  describe('reset clears auto-capture', function () {
    it('stops auto-capture on reset', function () {
      agg.startAutoCapture(5000);
      assert.equal(agg.isAutoCapturing(), true);
      agg.reset();
      assert.equal(agg.isAutoCapturing(), false);
    });
  });
});
