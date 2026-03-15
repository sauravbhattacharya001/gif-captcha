'use strict';

var assert = require('assert');
var createCaptchaTrafficAnalyzer = require('../src/captcha-traffic-analyzer').createCaptchaTrafficAnalyzer;

// ── Helpers ─────────────────────────────────────────────────────

var BASE_TS = 1700000000000; // Fixed base timestamp
var WINDOW = 60000;          // 1 minute

function makeEvent(opts) {
  return {
    timestamp: opts.timestamp || BASE_TS,
    solved: opts.solved !== undefined ? opts.solved : true,
    responseTimeMs: opts.responseTimeMs != null ? opts.responseTimeMs : 2000,
    region: opts.region || 'US',
    challengeType: opts.challengeType || 'gif'
  };
}

function fillWindows(analyzer, count, perWindow, opts) {
  opts = opts || {};
  for (var w = 0; w < count; w++) {
    for (var e = 0; e < perWindow; e++) {
      analyzer.record(makeEvent({
        timestamp: BASE_TS + w * WINDOW + e * 100,
        solved: opts.solved !== undefined ? opts.solved : true,
        responseTimeMs: opts.responseTimeMs || 2000,
        region: opts.region || 'US',
        challengeType: opts.challengeType || 'gif'
      }));
    }
    analyzer.flush();
  }
}

// ── Constructor ─────────────────────────────────────────────────

describe('CaptchaTrafficAnalyzer', function () {

  describe('constructor', function () {
    it('creates with default options', function () {
      var a = createCaptchaTrafficAnalyzer();
      assert.ok(a);
      assert.strictEqual(typeof a.record, 'function');
      assert.strictEqual(typeof a.analyze, 'function');
    });

    it('accepts custom options', function () {
      var a = createCaptchaTrafficAnalyzer({
        windowSizeMs: 30000,
        maxWindows: 100,
        zScoreThreshold: 3.0
      });
      assert.ok(a);
    });
  });

  // ── record ──────────────────────────────────────────────────

  describe('record', function () {
    it('records a valid event', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({}));
      var w = a.getWindows();
      assert.strictEqual(w.length, 1);
      assert.strictEqual(w[0].count, 1);
    });

    it('throws on null event', function () {
      var a = createCaptchaTrafficAnalyzer();
      assert.throws(function () { a.record(null); }, /non-null object/);
    });

    it('throws on missing timestamp', function () {
      var a = createCaptchaTrafficAnalyzer();
      assert.throws(function () { a.record({ solved: true }); }, /timestamp/);
    });

    it('throws on negative timestamp', function () {
      var a = createCaptchaTrafficAnalyzer();
      assert.throws(function () { a.record({ timestamp: -1, solved: true }); }, /timestamp/);
    });

    it('throws on missing solved field', function () {
      var a = createCaptchaTrafficAnalyzer();
      assert.throws(function () { a.record({ timestamp: BASE_TS }); }, /solved/);
    });

    it('counts solved and failed separately', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({ solved: true }));
      a.record(makeEvent({ solved: false, timestamp: BASE_TS + 1 }));
      var w = a.getWindows();
      assert.strictEqual(w[0].solved, 1);
      assert.strictEqual(w[0].failed, 1);
    });

    it('tracks regions', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({ region: 'US' }));
      a.record(makeEvent({ region: 'EU', timestamp: BASE_TS + 1 }));
      a.record(makeEvent({ region: 'US', timestamp: BASE_TS + 2 }));
      var w = a.getWindows();
      assert.strictEqual(w[0].regions['US'], 2);
      assert.strictEqual(w[0].regions['EU'], 1);
    });

    it('tracks challenge types', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({ challengeType: 'gif' }));
      a.record(makeEvent({ challengeType: 'text', timestamp: BASE_TS + 1 }));
      var w = a.getWindows();
      assert.strictEqual(w[0].challengeTypes['gif'], 1);
      assert.strictEqual(w[0].challengeTypes['text'], 1);
    });

    it('defaults region to unknown when not provided', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record({ timestamp: BASE_TS, solved: true, responseTimeMs: 1000 });
      var w = a.getWindows();
      assert.strictEqual(w[0].regions['unknown'], 1);
    });

    it('creates new window when timestamp crosses boundary', function () {
      var a = createCaptchaTrafficAnalyzer({ windowSizeMs: 60000 });
      a.record(makeEvent({ timestamp: BASE_TS }));
      a.record(makeEvent({ timestamp: BASE_TS + 70000 }));
      a.flush();
      var w = a.getWindows();
      // First window was flushed when second started, plus the second is current
      assert.ok(w.length >= 2);
    });
  });

  // ── recordBatch ─────────────────────────────────────────────

  describe('recordBatch', function () {
    it('records multiple events', function () {
      var a = createCaptchaTrafficAnalyzer();
      var count = a.recordBatch([
        makeEvent({ timestamp: BASE_TS }),
        makeEvent({ timestamp: BASE_TS + 1 }),
        makeEvent({ timestamp: BASE_TS + 2 })
      ]);
      assert.strictEqual(count, 3);
      assert.strictEqual(a.getWindows()[0].count, 3);
    });

    it('throws on non-array', function () {
      var a = createCaptchaTrafficAnalyzer();
      assert.throws(function () { a.recordBatch('not an array'); }, /array/);
    });
  });

  // ── getWindows ──────────────────────────────────────────────

  describe('getWindows', function () {
    it('returns empty array when no data', function () {
      var a = createCaptchaTrafficAnalyzer();
      assert.deepStrictEqual(a.getWindows(), []);
    });

    it('includes current window', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({}));
      assert.strictEqual(a.getWindows().length, 1);
    });

    it('includes both completed and current windows', function () {
      var a = createCaptchaTrafficAnalyzer();
      fillWindows(a, 3, 5);
      a.record(makeEvent({ timestamp: BASE_TS + 3 * WINDOW }));
      var w = a.getWindows();
      assert.strictEqual(w.length, 4); // 3 flushed + 1 current
    });
  });

  // ── getBaseline ─────────────────────────────────────────────

  describe('getBaseline', function () {
    it('returns null with insufficient windows', function () {
      var a = createCaptchaTrafficAnalyzer({ minWindowsForBaseline: 5 });
      fillWindows(a, 3, 10);
      assert.strictEqual(a.getBaseline(), null);
    });

    it('returns baseline stats with enough windows', function () {
      var a = createCaptchaTrafficAnalyzer({ minWindowsForBaseline: 5 });
      fillWindows(a, 6, 10);
      var b = a.getBaseline();
      assert.ok(b);
      assert.strictEqual(b.windowCount, 6);
      assert.strictEqual(b.traffic.mean, 10);
      assert.ok(b.solveRate.mean > 0);
    });

    it('computes correct traffic mean', function () {
      var a = createCaptchaTrafficAnalyzer({ minWindowsForBaseline: 3 });
      // 5, 10, 15 events in successive windows
      for (var i = 0; i < 5; i++) a.record(makeEvent({ timestamp: BASE_TS + i * 100 }));
      a.flush();
      for (var j = 0; j < 10; j++) a.record(makeEvent({ timestamp: BASE_TS + WINDOW + j * 100 }));
      a.flush();
      for (var k = 0; k < 15; k++) a.record(makeEvent({ timestamp: BASE_TS + 2 * WINDOW + k * 100 }));
      a.flush();

      var b = a.getBaseline();
      assert.strictEqual(b.traffic.mean, 10); // mean of 5,10,15
    });
  });

  // ── analyze ─────────────────────────────────────────────────

  describe('analyze', function () {
    it('returns no_data when empty', function () {
      var a = createCaptchaTrafficAnalyzer();
      var r = a.analyze();
      assert.strictEqual(r.status, 'no_data');
      assert.deepStrictEqual(r.anomalies, []);
    });

    it('returns insufficient_baseline with few windows', function () {
      var a = createCaptchaTrafficAnalyzer({ minWindowsForBaseline: 5 });
      fillWindows(a, 2, 10);
      a.record(makeEvent({ timestamp: BASE_TS + 2 * WINDOW }));
      var r = a.analyze();
      assert.strictEqual(r.status, 'insufficient_baseline');
    });

    it('returns normal when no anomalies', function () {
      var regions = ['US', 'EU', 'APAC', 'SA', 'AF'];
      var a = createCaptchaTrafficAnalyzer({ minWindowsForBaseline: 5 });
      // Build baseline with diverse regions
      for (var w = 0; w < 6; w++) {
        for (var e = 0; e < 10; e++) {
          a.record(makeEvent({
            timestamp: BASE_TS + w * WINDOW + e * 100,
            responseTimeMs: 2000,
            region: regions[e % regions.length]
          }));
        }
        a.flush();
      }
      // Add a latest window matching baseline pattern
      for (var i = 0; i < 10; i++) {
        a.record(makeEvent({
          timestamp: BASE_TS + 6 * WINDOW + i * 100,
          responseTimeMs: 2000,
          region: regions[i % regions.length]
        }));
      }
      var r = a.analyze();
      assert.strictEqual(r.status, 'normal');
      assert.strictEqual(r.anomalies.length, 0);
    });

    it('detects traffic spike', function () {
      var a = createCaptchaTrafficAnalyzer({
        minWindowsForBaseline: 5,
        trafficSpikeMultiplier: 3.0,
        zScoreThreshold: 2.0
      });
      fillWindows(a, 6, 10);
      // Spike: 50 events in latest window (5x baseline of 10)
      for (var i = 0; i < 50; i++) {
        a.record(makeEvent({ timestamp: BASE_TS + 6 * WINDOW + i * 100 }));
      }
      var r = a.analyze();
      var spikeAnomaly = r.anomalies.filter(function (an) { return an.type === 'traffic_spike'; });
      assert.ok(spikeAnomaly.length > 0);
    });

    it('detects traffic drop', function () {
      var a = createCaptchaTrafficAnalyzer({
        minWindowsForBaseline: 5,
        zScoreThreshold: 2.0
      });
      // Baseline with some variance: 48, 50, 52, 50, 48, 50
      var counts = [48, 50, 52, 50, 48, 50];
      for (var w = 0; w < counts.length; w++) {
        for (var e = 0; e < counts[w]; e++) {
          a.record(makeEvent({ timestamp: BASE_TS + w * WINDOW + e * 100 }));
        }
        a.flush();
      }
      // Drop: 2 events in latest (way below baseline ~50)
      a.record(makeEvent({ timestamp: BASE_TS + 6 * WINDOW }));
      a.record(makeEvent({ timestamp: BASE_TS + 6 * WINDOW + 1 }));
      var r = a.analyze();
      var dropAnomaly = r.anomalies.filter(function (an) { return an.type === 'traffic_drop'; });
      assert.ok(dropAnomaly.length > 0);
    });

    it('detects solve rate drop', function () {
      var a = createCaptchaTrafficAnalyzer({
        minWindowsForBaseline: 5,
        solveRateDropThreshold: 0.2
      });
      fillWindows(a, 6, 20, { solved: true }); // 100% solve rate baseline
      // Latest window: 20% solve rate
      for (var i = 0; i < 20; i++) {
        a.record(makeEvent({
          timestamp: BASE_TS + 6 * WINDOW + i * 100,
          solved: i < 4 // only 4 of 20 solved = 20%
        }));
      }
      var r = a.analyze();
      var srDrop = r.anomalies.filter(function (an) { return an.type === 'solve_rate_drop'; });
      assert.ok(srDrop.length > 0);
    });

    it('detects response time increase', function () {
      var a = createCaptchaTrafficAnalyzer({
        minWindowsForBaseline: 5,
        zScoreThreshold: 2.0,
        responseTimeDeviationMs: 3000
      });
      fillWindows(a, 6, 10, { responseTimeMs: 2000 });
      // Latest: response times at 15000ms
      for (var i = 0; i < 10; i++) {
        a.record(makeEvent({
          timestamp: BASE_TS + 6 * WINDOW + i * 100,
          responseTimeMs: 15000
        }));
      }
      var r = a.analyze();
      var rtIncrease = r.anomalies.filter(function (an) { return an.type === 'response_time_increase'; });
      assert.ok(rtIncrease.length > 0);
    });

    it('detects region concentration', function () {
      var a = createCaptchaTrafficAnalyzer({
        minWindowsForBaseline: 5,
        regionConcentrationThreshold: 0.8
      });
      var regions = ['US', 'EU', 'APAC', 'SA', 'AF'];
      for (var w = 0; w < 6; w++) {
        for (var e = 0; e < 10; e++) {
          a.record(makeEvent({
            timestamp: BASE_TS + w * WINDOW + e * 100,
            region: regions[e % regions.length]
          }));
        }
        a.flush();
      }
      // Latest: 95% from one region
      for (var j = 0; j < 20; j++) {
        a.record(makeEvent({
          timestamp: BASE_TS + 6 * WINDOW + j * 100,
          region: j < 19 ? 'CN' : 'US'
        }));
      }
      var r = a.analyze();
      var rcAnomaly = r.anomalies.filter(function (an) { return an.type === 'region_concentration'; });
      assert.ok(rcAnomaly.length > 0);
      assert.ok(rcAnomaly[0].dominantRegion === 'CN');
    });

    it('assigns severity critical for extreme anomalies', function () {
      var a = createCaptchaTrafficAnalyzer({
        minWindowsForBaseline: 5,
        trafficSpikeMultiplier: 3.0,
        zScoreThreshold: 2.0
      });
      fillWindows(a, 6, 10);
      // Extreme spike: 200 events
      for (var i = 0; i < 200; i++) {
        a.record(makeEvent({ timestamp: BASE_TS + 6 * WINDOW + i * 10 }));
      }
      var r = a.analyze();
      assert.strictEqual(r.status, 'critical');
    });

    it('stores alerts in history', function () {
      var a = createCaptchaTrafficAnalyzer({
        minWindowsForBaseline: 5,
        trafficSpikeMultiplier: 3.0
      });
      fillWindows(a, 6, 10);
      for (var i = 0; i < 50; i++) {
        a.record(makeEvent({ timestamp: BASE_TS + 6 * WINDOW + i * 100 }));
      }
      a.analyze();
      var alerts = a.getAlertHistory();
      assert.ok(alerts.length > 0);
      assert.ok(alerts[0].anomalyCount > 0);
    });
  });

  // ── getTrend ────────────────────────────────────────────────

  describe('getTrend', function () {
    it('returns null with fewer than 3 windows', function () {
      var a = createCaptchaTrafficAnalyzer();
      fillWindows(a, 2, 10);
      assert.strictEqual(a.getTrend('count'), null);
    });

    it('detects increasing traffic trend', function () {
      var a = createCaptchaTrafficAnalyzer();
      // Increasing: 5, 10, 15, 20, 25
      for (var w = 0; w < 5; w++) {
        var n = (w + 1) * 5;
        for (var e = 0; e < n; e++) {
          a.record(makeEvent({ timestamp: BASE_TS + w * WINDOW + e * 100 }));
        }
        a.flush();
      }
      var t = a.getTrend('count');
      assert.ok(t);
      assert.strictEqual(t.direction, 'increasing');
      assert.ok(t.slope > 0);
    });

    it('detects decreasing solve rate trend', function () {
      var a = createCaptchaTrafficAnalyzer();
      // Decreasing solve rate: 100%, 80%, 60%, 40%
      var solveRates = [1.0, 0.8, 0.6, 0.4];
      for (var w = 0; w < solveRates.length; w++) {
        for (var e = 0; e < 20; e++) {
          a.record(makeEvent({
            timestamp: BASE_TS + w * WINDOW + e * 100,
            solved: e < Math.round(solveRates[w] * 20)
          }));
        }
        a.flush();
      }
      var t = a.getTrend('solveRate');
      assert.ok(t);
      assert.strictEqual(t.direction, 'decreasing');
      assert.ok(t.slope < 0);
    });

    it('detects stable pattern', function () {
      var a = createCaptchaTrafficAnalyzer();
      fillWindows(a, 5, 10);
      var t = a.getTrend('count');
      assert.ok(t);
      assert.strictEqual(t.direction, 'stable');
    });

    it('returns null for invalid metric', function () {
      var a = createCaptchaTrafficAnalyzer();
      fillWindows(a, 5, 10);
      assert.strictEqual(a.getTrend('invalid'), null);
    });

    it('respects lastN parameter', function () {
      var a = createCaptchaTrafficAnalyzer();
      fillWindows(a, 10, 10);
      var t = a.getTrend('count', 3);
      assert.ok(t);
      assert.strictEqual(t.windowCount, 3);
    });

    it('computes r-squared', function () {
      var a = createCaptchaTrafficAnalyzer();
      // Perfect linear increase
      for (var w = 0; w < 5; w++) {
        var n = 10 + w * 10; // 10, 20, 30, 40, 50
        for (var e = 0; e < n; e++) {
          a.record(makeEvent({ timestamp: BASE_TS + w * WINDOW + e * 10 }));
        }
        a.flush();
      }
      var t = a.getTrend('count');
      assert.ok(t.rSquared >= 0.9); // Near-perfect linear fit
    });
  });

  // ── getHourlyDistribution ───────────────────────────────────

  describe('getHourlyDistribution', function () {
    it('returns all 24 hours', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({}));
      var d = a.getHourlyDistribution();
      assert.strictEqual(d.distribution.length, 24);
    });

    it('counts events correctly', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({}));
      a.record(makeEvent({ timestamp: BASE_TS + 1 }));
      var d = a.getHourlyDistribution();
      assert.strictEqual(d.totalEvents, 2);
    });

    it('identifies peak and trough hours', function () {
      var a = createCaptchaTrafficAnalyzer();
      // Record events at different hours
      for (var i = 0; i < 10; i++) {
        a.record(makeEvent({ timestamp: BASE_TS + i * 100 }));
      }
      var d = a.getHourlyDistribution();
      assert.ok(d.peakHour >= 0 && d.peakHour < 24);
      assert.ok(d.troughHour >= 0 && d.troughHour < 24);
    });
  });

  // ── getRegionBreakdown ──────────────────────────────────────

  describe('getRegionBreakdown', function () {
    it('aggregates region data', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({ region: 'US' }));
      a.record(makeEvent({ region: 'EU', timestamp: BASE_TS + 1 }));
      a.record(makeEvent({ region: 'US', timestamp: BASE_TS + 2 }));
      var r = a.getRegionBreakdown();
      assert.strictEqual(r.uniqueRegions, 2);
      assert.strictEqual(r.totalEvents, 3);
      assert.strictEqual(r.topRegion, 'US');
    });

    it('sorts by count descending', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({ region: 'EU' }));
      a.record(makeEvent({ region: 'US', timestamp: BASE_TS + 1 }));
      a.record(makeEvent({ region: 'US', timestamp: BASE_TS + 2 }));
      a.record(makeEvent({ region: 'US', timestamp: BASE_TS + 3 }));
      var r = a.getRegionBreakdown();
      assert.strictEqual(r.regions[0].region, 'US');
      assert.strictEqual(r.regions[0].count, 3);
    });
  });

  // ── getSummary ──────────────────────────────────────────────

  describe('getSummary', function () {
    it('returns comprehensive summary', function () {
      var a = createCaptchaTrafficAnalyzer({ minWindowsForBaseline: 3 });
      fillWindows(a, 5, 10, { responseTimeMs: 2000 });
      var s = a.getSummary();
      assert.strictEqual(s.totalEvents, 50);
      assert.strictEqual(s.totalWindows, 5);
      assert.ok(s.overallSolveRate > 0);
      assert.ok(s.regionBreakdown);
      assert.ok(s.hourlyDistribution);
      assert.ok(s.trends);
    });

    it('includes trend data', function () {
      var a = createCaptchaTrafficAnalyzer({ minWindowsForBaseline: 3 });
      fillWindows(a, 5, 10);
      var s = a.getSummary();
      assert.ok(s.trends.traffic);
      assert.ok(s.trends.solveRate);
    });
  });

  // ── export/import ───────────────────────────────────────────

  describe('exportData / importData', function () {
    it('round-trips data', function () {
      var a = createCaptchaTrafficAnalyzer();
      fillWindows(a, 5, 10);
      var exported = a.exportData();
      assert.strictEqual(exported.version, 1);
      assert.strictEqual(exported.windows.length, 5);

      var b = createCaptchaTrafficAnalyzer();
      b.importData(exported);
      assert.strictEqual(b.getWindows().length, 5);
    });

    it('throws on invalid format', function () {
      var a = createCaptchaTrafficAnalyzer();
      assert.throws(function () { a.importData(null); }, /Invalid/);
      assert.throws(function () { a.importData({ version: 99 }); }, /Invalid/);
    });

    it('preserves window data', function () {
      var a = createCaptchaTrafficAnalyzer();
      fillWindows(a, 3, 10);
      var exported = a.exportData();

      var b = createCaptchaTrafficAnalyzer();
      b.importData(exported);
      var w = b.getWindows();
      assert.strictEqual(w.length, 3);
      assert.strictEqual(w[0].count, 10);
    });
  });

  // ── reset ───────────────────────────────────────────────────

  describe('reset', function () {
    it('clears all state', function () {
      var a = createCaptchaTrafficAnalyzer();
      fillWindows(a, 5, 10);
      a.analyze();
      a.reset();
      assert.deepStrictEqual(a.getWindows(), []);
      assert.deepStrictEqual(a.getAlertHistory(), []);
    });
  });

  // ── flush ───────────────────────────────────────────────────

  describe('flush', function () {
    it('moves current window to completed', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({}));
      assert.strictEqual(a.getWindows().length, 1); // current
      a.flush();
      a.record(makeEvent({ timestamp: BASE_TS + WINDOW }));
      var w = a.getWindows();
      assert.strictEqual(w.length, 2); // flushed + current
    });
  });

  // ── getAlertHistory ─────────────────────────────────────────

  describe('getAlertHistory', function () {
    it('returns empty when no alerts', function () {
      var a = createCaptchaTrafficAnalyzer();
      assert.deepStrictEqual(a.getAlertHistory(), []);
    });

    it('respects limit parameter', function () {
      var a = createCaptchaTrafficAnalyzer({
        minWindowsForBaseline: 3,
        trafficSpikeMultiplier: 2.0
      });
      fillWindows(a, 4, 10);
      // Trigger multiple alerts
      for (var round = 0; round < 3; round++) {
        for (var i = 0; i < 50; i++) {
          a.record(makeEvent({ timestamp: BASE_TS + (5 + round) * WINDOW + i * 100 }));
        }
        a.analyze();
        a.flush();
      }
      var limited = a.getAlertHistory(2);
      assert.ok(limited.length <= 2);
    });
  });

  // ── edge cases ──────────────────────────────────────────────

  describe('edge cases', function () {
    it('handles zero response time', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({ responseTimeMs: 0 }));
      var w = a.getWindows();
      assert.strictEqual(w[0].meanResponseMs, 0);
    });

    it('handles single event', function () {
      var a = createCaptchaTrafficAnalyzer();
      a.record(makeEvent({}));
      var s = a.getSummary();
      assert.strictEqual(s.totalEvents, 1);
    });

    it('handles maxWindows eviction', function () {
      var a = createCaptchaTrafficAnalyzer({ maxWindows: 3 });
      fillWindows(a, 5, 5);
      var w = a.getWindows();
      assert.ok(w.length <= 3);
    });

    it('handles maxEvents eviction', function () {
      var a = createCaptchaTrafficAnalyzer({ maxEvents: 20 });
      fillWindows(a, 3, 10); // 30 events, max is 20
      // Should have evicted oldest window
      var s = a.getSummary();
      assert.ok(s.totalEvents <= 20);
    });
  });
});
