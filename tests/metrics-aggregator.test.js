'use strict';

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
      expect(agg.register('test', sub)).toBe(true);
      expect(agg.listSubsystems()).toEqual(['test']);
    });

    it('registers a subsystem with getReport', function () {
      var sub = { getReport: function () { return {}; } };
      expect(agg.register('reporter', sub)).toBe(true);
    });

    it('registers a subsystem with getSummary', function () {
      var sub = { getSummary: function () { return {}; } };
      expect(agg.register('summarizer', sub)).toBe(true);
    });

    it('rejects subsystem without stats method', function () {
      expect(agg.register('bad', { doStuff: function () {} })).toBe(false);
    });

    it('rejects null instance', function () {
      expect(agg.register('bad', null)).toBe(false);
    });

    it('rejects empty name', function () {
      expect(agg.register('', { getStats: function () { return {}; } })).toBe(false);
    });

    it('rejects non-string name', function () {
      expect(agg.register(42, { getStats: function () { return {}; } })).toBe(false);
    });
  });

  describe('unregister', function () {
    it('removes a registered subsystem', function () {
      agg.register('a', { getStats: function () { return {}; } });
      expect(agg.unregister('a')).toBe(true);
      expect(agg.listSubsystems()).toEqual([]);
    });

    it('returns false for unknown subsystem', function () {
      expect(agg.unregister('nope')).toBe(false);
    });
  });

  describe('listSubsystems', function () {
    it('returns empty array initially', function () {
      expect(agg.listSubsystems()).toEqual([]);
    });

    it('returns all registered names', function () {
      agg.register('a', { getStats: function () { return {}; } });
      agg.register('b', { getStats: function () { return {}; } });
      expect(agg.listSubsystems().sort()).toEqual(['a', 'b']);
    });
  });

  // ── Snapshot ──

  describe('snapshot', function () {
    it('returns a snapshot with timestamp and structure', function () {
      var snap = agg.snapshot();
      expect(snap.timestamp).toBeGreaterThan(0);
      expect(snap.subsystems).toBeDefined();
      expect(snap.health).toBeDefined();
      expect(snap.health.score).toBeDefined();
      expect(snap.health.status).toBeDefined();
      expect(snap.alerts).toBeDefined();
      expect(snap.registeredCount).toBe(0);
    });

    it('collects stats from registered subsystems', function () {
      agg.register('myModule', { getStats: function () { return { items: 42, active: true }; } });
      var snap = agg.snapshot();
      expect(snap.subsystems.myModule).toEqual({ items: 42, active: true });
      expect(snap.registeredCount).toBe(1);
    });

    it('handles subsystem getStats throwing errors', function () {
      agg.register('broken', { getStats: function () { throw new Error('boom'); } });
      var snap = agg.snapshot();
      expect(snap.subsystems.broken).toBeUndefined();
    });

    it('falls back to getReport if getStats is missing', function () {
      agg.register('reporter', { getReport: function () { return { report: true }; } });
      var snap = agg.snapshot();
      expect(snap.subsystems.reporter).toEqual({ report: true });
    });

    it('falls back to getSummary if both are missing', function () {
      agg.register('summarizer', { getSummary: function () { return { summary: 1 }; } });
      var snap = agg.snapshot();
      expect(snap.subsystems.summarizer).toEqual({ summary: 1 });
    });

    it('stores snapshots in history', function () {
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();
      var trends = agg.getTrends();
      expect(trends.snapshotCount).toBe(3);
    });

    it('respects historySize limit', function () {
      for (var i = 0; i < 15; i++) {
        agg.snapshot();
      }
      var trends = agg.getTrends();
      expect(trends.snapshotCount).toBe(10);
    });
  });

  describe('lastSnapshot', function () {
    it('returns null when no snapshots taken', function () {
      expect(agg.lastSnapshot()).toBeNull();
    });

    it('returns the most recent snapshot', function () {
      agg.register('x', { getStats: function () { return { v: 1 }; } });
      agg.snapshot();
      agg.register('y', { getStats: function () { return { v: 2 }; } });
      agg.snapshot();
      var last = agg.lastSnapshot();
      expect(last.registeredCount).toBe(2);
    });
  });

  // ── Health Scoring ──

  describe('health scoring', function () {
    it('gives 100 health when no subsystems registered', function () {
      var snap = agg.snapshot();
      expect(snap.health.score).toBe(100);
      expect(snap.health.status).toBe('healthy');
    });

    it('penalizes low pass rate', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.1, avgResponseTimeMs: 500 }; }
      });
      var snap = agg.snapshot();
      expect(snap.health.score).toBeLessThan(100);
      expect(snap.health.factors.length).toBeGreaterThan(0);
    });

    it('penalizes high response time', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.8, avgResponseTimeMs: 60000 }; }
      });
      var snap = agg.snapshot();
      expect(snap.health.score).toBeLessThan(100);
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
      expect(snap.health.score).toBeLessThan(100);
    });

    it('reports degraded status for moderate penalties', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.05 }; }
      });
      var snap = agg.snapshot();
      expect(snap.health.status).toBe('degraded');
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
      expect(snap.health.status).toBe('critical');
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
      expect(snap.health.score).toBe(100);
      expect(snap.health.status).toBe('healthy');
    });

    it('checks bot detection rate', function () {
      agg.register('botDetector', {
        getStats: function () { return { totalChecks: 100, botsDetected: 60 }; }
      });
      var snap = agg.snapshot();
      expect(snap.health.score).toBeLessThan(100);
    });

    it('checks rate limiter rejection rate', function () {
      agg.register('rateLimiter', {
        getStats: function () { return { totalRequests: 100, rejected: 80 }; }
      });
      var snap = agg.snapshot();
      expect(snap.health.score).toBeLessThan(100);
    });
  });

  // ── Alerts ──

  describe('alerts', function () {
    it('generates no alerts when healthy', function () {
      var snap = agg.snapshot();
      expect(snap.alerts.length).toBe(0);
    });

    it('generates alerts for degraded health', function () {
      agg.register('sessions', {
        getStats: function () { return { passRate: 0.1 }; }
      });
      var snap = agg.snapshot();
      expect(snap.alerts.length).toBeGreaterThan(0);
      expect(snap.alerts[0].level).toBeDefined();
      expect(snap.alerts[0].message).toBeDefined();
      expect(snap.alerts[0].timestamp).toBeGreaterThan(0);
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
      expect(criticals.length).toBeGreaterThan(0);
    });
  });

  // ── Trends ──

  describe('getTrends', function () {
    it('returns empty trends initially', function () {
      var trends = agg.getTrends();
      expect(trends.snapshotCount).toBe(0);
      expect(trends.snapshots).toEqual([]);
      expect(trends.uptimeMs).toBeGreaterThanOrEqual(0);
      expect(trends.healthTrend).toBeNull();
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
      expect(trends.healthTrend).toBe('improving');
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
      expect(trends.healthTrend).toBe('declining');
    });

    it('calculates stable trend', function () {
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();
      agg.snapshot();

      var trends = agg.getTrends();
      expect(trends.healthTrend).toBe('stable');
    });
  });

  // ── Summary ──

  describe('getSummary', function () {
    it('returns compact summary', function () {
      agg.register('x', { getStats: function () { return { v: 1 }; } });
      var summary = agg.getSummary();
      expect(summary.healthScore).toBeDefined();
      expect(summary.healthStatus).toBeDefined();
      expect(summary.registeredCount).toBe(1);
      expect(summary.alertCount).toBeDefined();
      expect(summary.criticalAlerts).toBeDefined();
      expect(summary.uptimeMs).toBeGreaterThanOrEqual(0);
      expect(summary.snapshotCount).toBeGreaterThanOrEqual(1);
      expect(summary.timestamp).toBeGreaterThan(0);
    });

    it('takes a snapshot if none exists', function () {
      var summary = agg.getSummary();
      expect(summary.snapshotCount).toBe(1);
    });

    it('uses last snapshot if available', function () {
      agg.snapshot();
      agg.snapshot();
      var summary = agg.getSummary();
      expect(summary.snapshotCount).toBe(2);
    });
  });

  // ── Clear/Reset ──

  describe('clearHistory', function () {
    it('clears all snapshots', function () {
      agg.snapshot();
      agg.snapshot();
      agg.clearHistory();
      expect(agg.getTrends().snapshotCount).toBe(0);
      expect(agg.lastSnapshot()).toBeNull();
    });

    it('keeps registered subsystems', function () {
      agg.register('x', { getStats: function () { return {}; } });
      agg.snapshot();
      agg.clearHistory();
      expect(agg.listSubsystems()).toEqual(['x']);
    });
  });

  describe('reset', function () {
    it('clears subsystems and history', function () {
      agg.register('x', { getStats: function () { return {}; } });
      agg.snapshot();
      agg.reset();
      expect(agg.listSubsystems()).toEqual([]);
      expect(agg.getTrends().snapshotCount).toBe(0);
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
      expect(snap.health.score).toBeLessThan(100);
    });

    it('uses custom avgResponseMs threshold', function () {
      var custom = createMetricsAggregator({ thresholds: { avgResponseMs: 1000 } });
      custom.register('sessions', {
        getStats: function () { return { passRate: 0.9, avgResponseTimeMs: 5000 }; }
      });
      var snap = custom.snapshot();
      expect(snap.health.score).toBeLessThan(100);
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
      expect(snap.registeredCount).toBe(3);
      expect(snap.subsystems.sessions.totalSessions).toBe(100);
      expect(snap.subsystems.reputation.trackedCount).toBe(50);
      expect(snap.subsystems.tokens.trackedNonces).toBe(200);
      expect(snap.health.status).toBe('healthy');
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
      expect(snap.health.status).not.toBe('healthy');
      expect(snap.alerts.length).toBeGreaterThan(0);
    });
  });

  // ── Edge cases ──

  describe('edge cases', function () {
    it('handles historySize of 1', function () {
      var tiny = createMetricsAggregator({ historySize: 1 });
      tiny.snapshot();
      tiny.snapshot();
      tiny.snapshot();
      expect(tiny.getTrends().snapshotCount).toBe(1);
    });

    it('handles registering same name twice (overwrites)', function () {
      agg.register('x', { getStats: function () { return { v: 1 }; } });
      agg.register('x', { getStats: function () { return { v: 2 }; } });
      var snap = agg.snapshot();
      expect(snap.subsystems.x.v).toBe(2);
    });

    it('handles subsystem returning null from getStats', function () {
      agg.register('nullish', { getStats: function () { return null; } });
      var snap = agg.snapshot();
      expect(snap.subsystems.nullish).toBeUndefined();
    });

    it('handles zero-count bot detector gracefully', function () {
      agg.register('botDetector', {
        getStats: function () { return { totalChecks: 0, botsDetected: 0 }; }
      });
      var snap = agg.snapshot();
      expect(snap.health.score).toBe(100);
    });
  });
});
