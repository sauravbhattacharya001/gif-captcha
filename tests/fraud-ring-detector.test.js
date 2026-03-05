var { describe, it, beforeEach } = require('node:test');
var assert = require('assert');
var lib = require('../src/index');

describe('createFraudRingDetector', function () {
  var detector;

  beforeEach(function () {
    detector = lib.createFraudRingDetector({
      minRingSize: 3,
      timingWindowMs: 5000,
      suspicionThreshold: 30,
      maxClients: 100,
      maxRings: 50
    });
  });

  // ── Construction ──

  describe('construction', function () {
    it('creates with defaults', function () {
      var d = lib.createFraudRingDetector();
      assert.ok(d);
      assert.ok(typeof d.recordEvent === 'function');
      assert.ok(typeof d.detectRings === 'function');
    });

    it('starts with empty stats', function () {
      var stats = detector.getStats();
      assert.strictEqual(stats.totalClients, 0);
      assert.strictEqual(stats.flaggedClients, 0);
      assert.strictEqual(stats.totalRings, 0);
    });
  });

  // ── recordEvent ──

  describe('recordEvent', function () {
    it('records a solve event', function () {
      var r = detector.recordEvent({ clientId: 'c1', type: 'solve', timestamp: 1000, ip: '1.2.3.4' });
      assert.ok(r);
      assert.strictEqual(r.clientId, 'c1');
      assert.strictEqual(r.type, 'solve');
    });

    it('returns null for invalid events', function () {
      assert.strictEqual(detector.recordEvent(null), null);
      assert.strictEqual(detector.recordEvent({}), null);
      assert.strictEqual(detector.recordEvent({ clientId: 'c1' }), null);
    });

    it('tracks multiple clients', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', timestamp: 1000 });
      detector.recordEvent({ clientId: 'c2', type: 'solve', timestamp: 2000 });
      assert.strictEqual(detector.getStats().totalClients, 2);
    });

    it('records fingerprints and IPs', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', ip: '1.2.3.4', fingerprint: 'fp1' });
      detector.recordEvent({ clientId: 'c1', type: 'solve', ip: '5.6.7.8', fingerprint: 'fp2' });
      var check = detector.checkClient('c1');
      assert.ok(check);
    });

    it('enforces maxClients LRU eviction', function () {
      var d = lib.createFraudRingDetector({ maxClients: 3 });
      d.recordEvent({ clientId: 'c1', type: 'solve', timestamp: 1 });
      d.recordEvent({ clientId: 'c2', type: 'solve', timestamp: 2 });
      d.recordEvent({ clientId: 'c3', type: 'solve', timestamp: 3 });
      d.recordEvent({ clientId: 'c4', type: 'solve', timestamp: 4 });
      assert.strictEqual(d.getStats().totalClients, 3);
      assert.strictEqual(d.checkClient('c1'), null); // evicted
    });
  });

  // ── findTimingClusters ──

  describe('findTimingClusters', function () {
    it('returns empty for no events', function () {
      assert.deepStrictEqual(detector.findTimingClusters(), []);
    });

    it('detects clients solving in same window', function () {
      var base = 100000;
      detector.recordEvent({ clientId: 'c1', type: 'solve', timestamp: base });
      detector.recordEvent({ clientId: 'c2', type: 'solve', timestamp: base + 1000 });
      detector.recordEvent({ clientId: 'c3', type: 'solve', timestamp: base + 2000 });
      var clusters = detector.findTimingClusters();
      assert.strictEqual(clusters.length, 1);
      assert.strictEqual(clusters[0].length, 3);
    });

    it('separates distinct timing windows', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', timestamp: 1000 });
      detector.recordEvent({ clientId: 'c2', type: 'solve', timestamp: 2000 });
      detector.recordEvent({ clientId: 'c3', type: 'solve', timestamp: 3000 });
      // Big gap
      detector.recordEvent({ clientId: 'c4', type: 'solve', timestamp: 50000 });
      detector.recordEvent({ clientId: 'c5', type: 'solve', timestamp: 51000 });
      detector.recordEvent({ clientId: 'c6', type: 'solve', timestamp: 52000 });
      var clusters = detector.findTimingClusters();
      assert.strictEqual(clusters.length, 2);
    });
  });

  // ── findSharedFingerprints ──

  describe('findSharedFingerprints', function () {
    it('returns empty when no fingerprints shared', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', fingerprint: 'fp1' });
      detector.recordEvent({ clientId: 'c2', type: 'solve', fingerprint: 'fp2' });
      assert.deepStrictEqual(detector.findSharedFingerprints(), []);
    });

    it('detects shared fingerprints', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', fingerprint: 'fp-shared' });
      detector.recordEvent({ clientId: 'c2', type: 'solve', fingerprint: 'fp-shared' });
      var groups = detector.findSharedFingerprints();
      assert.strictEqual(groups.length, 1);
      assert.strictEqual(groups[0].fingerprint, 'fp-shared');
      assert.strictEqual(groups[0].clients.length, 2);
    });
  });

  // ── findIPClusters ──

  describe('findIPClusters', function () {
    it('detects shared IPs', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', ip: '10.0.0.1' });
      detector.recordEvent({ clientId: 'c2', type: 'solve', ip: '10.0.0.1' });
      var clusters = detector.findIPClusters();
      assert.ok(clusters.length >= 1);
      var ipCluster = clusters.find(function(c) { return c.ip === '10.0.0.1'; });
      assert.ok(ipCluster);
      assert.strictEqual(ipCluster.clients.length, 2);
    });

    it('detects subnet clusters', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', ip: '192.168.1.10' });
      detector.recordEvent({ clientId: 'c2', type: 'solve', ip: '192.168.1.20' });
      detector.recordEvent({ clientId: 'c3', type: 'solve', ip: '192.168.1.30' });
      var clusters = detector.findIPClusters();
      var subnetCluster = clusters.find(function(c) { return c.subnet === '192.168.1'; });
      assert.ok(subnetCluster);
      assert.strictEqual(subnetCluster.clients.length, 3);
    });
  });

  // ── findSequentialPatterns ──

  describe('findSequentialPatterns', function () {
    it('detects rapid sequential solves', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', timestamp: 10000 });
      detector.recordEvent({ clientId: 'c2', type: 'solve', timestamp: 10500 });
      detector.recordEvent({ clientId: 'c3', type: 'solve', timestamp: 11000 });
      var patterns = detector.findSequentialPatterns();
      assert.ok(patterns.length >= 1);
    });

    it('returns empty for spaced-out solves', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', timestamp: 10000 });
      detector.recordEvent({ clientId: 'c2', type: 'solve', timestamp: 20000 });
      detector.recordEvent({ clientId: 'c3', type: 'solve', timestamp: 30000 });
      assert.deepStrictEqual(detector.findSequentialPatterns(), []);
    });
  });

  // ── computeRingScore ──

  describe('computeRingScore', function () {
    it('returns 0 for empty or single client', function () {
      assert.strictEqual(detector.computeRingScore([]).score, 0);
      assert.strictEqual(detector.computeRingScore(['c1']).score, 0);
    });

    it('scores higher for larger groups', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', timestamp: 1000 });
      detector.recordEvent({ clientId: 'c2', type: 'solve', timestamp: 1000 });
      detector.recordEvent({ clientId: 'c3', type: 'solve', timestamp: 1000 });
      var small = detector.computeRingScore(['c1', 'c2']);
      detector.recordEvent({ clientId: 'c4', type: 'solve', timestamp: 1000 });
      detector.recordEvent({ clientId: 'c5', type: 'solve', timestamp: 1000 });
      var big = detector.computeRingScore(['c1', 'c2', 'c3', 'c4', 'c5']);
      assert.ok(big.score >= small.score);
    });

    it('scores higher for shared fingerprints', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', fingerprint: 'same' });
      detector.recordEvent({ clientId: 'c2', type: 'solve', fingerprint: 'same' });
      detector.recordEvent({ clientId: 'c3', type: 'solve', fingerprint: 'same' });
      var result = detector.computeRingScore(['c1', 'c2', 'c3']);
      var fpFactor = result.factors.find(function(f) { return f.name === 'sharedFingerprint'; });
      assert.ok(fpFactor.score > 0);
    });

    it('has factors array', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve' });
      detector.recordEvent({ clientId: 'c2', type: 'solve' });
      var result = detector.computeRingScore(['c1', 'c2']);
      assert.ok(Array.isArray(result.factors));
      assert.ok(result.factors.length >= 4);
    });
  });

  // ── detectRings ──

  describe('detectRings', function () {
    it('returns empty for clean traffic', function () {
      detector.recordEvent({ clientId: 'c1', type: 'solve', timestamp: 1000, ip: '1.1.1.1', fingerprint: 'fp1' });
      detector.recordEvent({ clientId: 'c2', type: 'solve', timestamp: 100000, ip: '2.2.2.2', fingerprint: 'fp2' });
      var rings = detector.detectRings();
      assert.strictEqual(rings.length, 0);
    });

    it('detects a fraud ring from shared fingerprints + timing', function () {
      var base = 100000;
      for (var i = 1; i <= 5; i++) {
        detector.recordEvent({
          clientId: 'bot' + i, type: 'solve', timestamp: base + i * 100,
          ip: '10.0.0.' + i, fingerprint: 'bot-fp',
          responseTimeMs: 500 + Math.floor(i)
        });
      }
      var rings = detector.detectRings();
      assert.ok(rings.length >= 1, 'Should detect at least one ring');
      assert.ok(rings[0].size >= 3);
      assert.ok(rings[0].score >= 30);
    });

    it('assigns ring IDs to members', function () {
      var base = 200000;
      for (var i = 1; i <= 4; i++) {
        detector.recordEvent({ clientId: 'r' + i, type: 'solve', timestamp: base + i * 100, fingerprint: 'shared-fp', ip: '10.0.0.1' });
      }
      var rings = detector.detectRings();
      assert.ok(rings.length >= 1);
      var check = detector.checkClient('r1');
      assert.ok(check.isFlagged);
      assert.ok(check.ringId);
    });

    it('notifies ring callbacks', function () {
      var notified = [];
      detector.onRingDetected(function(ring) { notified.push(ring); });
      var base = 300000;
      for (var i = 1; i <= 4; i++) {
        detector.recordEvent({ clientId: 'n' + i, type: 'solve', timestamp: base + i * 50, fingerprint: 'notify-fp', ip: '10.0.0.1' });
      }
      detector.detectRings();
      assert.ok(notified.length >= 1);
    });
  });

  // ── checkClient ──

  describe('checkClient', function () {
    it('returns null for unknown client', function () {
      assert.strictEqual(detector.checkClient('unknown'), null);
    });

    it('returns unflagged for clean client', function () {
      detector.recordEvent({ clientId: 'clean1', type: 'solve', timestamp: 1000 });
      var check = detector.checkClient('clean1');
      assert.ok(check);
      assert.strictEqual(check.isFlagged, false);
    });
  });

  // ── Ring management ──

  describe('ring management', function () {
    function setupRing() {
      var base = 400000;
      for (var i = 1; i <= 5; i++) {
        detector.recordEvent({ clientId: 'mg' + i, type: 'solve', timestamp: base + i * 100, fingerprint: 'mg-fp', ip: '10.0.0.1' });
      }
      return detector.detectRings();
    }

    it('getRing returns null for unknown ring', function () {
      assert.strictEqual(detector.getRing('nonexistent'), null);
    });

    it('getRing returns detected ring', function () {
      var rings = setupRing();
      if (rings.length > 0) {
        var ring = detector.getRing(rings[0].id);
        assert.ok(ring);
        assert.strictEqual(ring.id, rings[0].id);
      }
    });

    it('listRings with status filter', function () {
      var rings = setupRing();
      if (rings.length > 0) {
        var active = detector.listRings({ status: 'active' });
        assert.ok(active.length >= 1);
        var dismissed = detector.listRings({ status: 'dismissed' });
        assert.strictEqual(dismissed.length, 0);
      }
    });

    it('dismissRing marks ring as dismissed', function () {
      var rings = setupRing();
      if (rings.length > 0) {
        assert.strictEqual(detector.dismissRing(rings[0].id), true);
        var ring = detector.getRing(rings[0].id);
        assert.strictEqual(ring.status, 'dismissed');
      }
    });

    it('dismissRing returns false for unknown ring', function () {
      assert.strictEqual(detector.dismissRing('nope'), false);
    });

    it('listRings with minScore filter', function () {
      var rings = setupRing();
      if (rings.length > 0) {
        var highScore = detector.listRings({ minScore: 90 });
        var lowScore = detector.listRings({ minScore: 1 });
        assert.ok(lowScore.length >= highScore.length);
      }
    });
  });

  // ── Stats ──

  describe('getStats', function () {
    it('counts flagged clients', function () {
      var base = 500000;
      for (var i = 1; i <= 4; i++) {
        detector.recordEvent({ clientId: 'st' + i, type: 'solve', timestamp: base + i * 100, fingerprint: 'st-fp', ip: '10.0.0.1' });
      }
      detector.recordEvent({ clientId: 'clean', type: 'solve', timestamp: 900000, ip: '99.99.99.99' });
      detector.detectRings();
      var stats = detector.getStats();
      assert.strictEqual(stats.totalClients, 5);
      assert.ok(stats.flaggedClients >= 3);
      assert.ok(typeof stats.flaggedPercent === 'number');
    });

    it('tracks ring counts', function () {
      var stats = detector.getStats();
      assert.strictEqual(stats.totalRings, 0);
      assert.strictEqual(stats.activeRings, 0);
    });
  });

  // ── State export/import ──

  describe('state management', function () {
    it('export/import roundtrip', function () {
      detector.recordEvent({ clientId: 'exp1', type: 'solve', timestamp: 1000, fingerprint: 'fp' });
      detector.recordEvent({ clientId: 'exp2', type: 'solve', timestamp: 1100, fingerprint: 'fp' });
      var state = detector.exportState();
      assert.ok(state.clients);
      assert.ok(Array.isArray(state.clientOrder));

      var d2 = lib.createFraudRingDetector();
      assert.strictEqual(d2.importState(state), true);
      assert.strictEqual(d2.getStats().totalClients, 2);
    });

    it('importState rejects invalid input', function () {
      assert.strictEqual(detector.importState(null), false);
      assert.strictEqual(detector.importState(42), false);
    });
  });

  // ── generateReport ──

  describe('generateReport', function () {
    it('generates empty report', function () {
      var report = detector.generateReport();
      assert.ok(report.includes('Fraud Ring Detection Report'));
      assert.ok(report.includes('Tracked Clients: 0'));
      assert.ok(report.includes('No active fraud rings detected'));
    });

    it('includes ring details when rings detected', function () {
      var base = 600000;
      for (var i = 1; i <= 5; i++) {
        detector.recordEvent({ clientId: 'rpt' + i, type: 'solve', timestamp: base + i * 100, fingerprint: 'rpt-fp', ip: '10.0.0.1' });
      }
      detector.detectRings();
      var report = detector.generateReport();
      assert.ok(report.includes('Active Rings'));
    });
  });

  // ── reset ──

  describe('reset', function () {
    it('clears all state', function () {
      detector.recordEvent({ clientId: 'r1', type: 'solve', timestamp: 1000 });
      detector.recordEvent({ clientId: 'r2', type: 'solve', timestamp: 2000 });
      detector.reset();
      assert.strictEqual(detector.getStats().totalClients, 0);
      assert.strictEqual(detector.getStats().totalRings, 0);
    });
  });

  // ── Edge cases ──

  describe('edge cases', function () {
    it('handles single client with many events', function () {
      for (var i = 0; i < 50; i++) {
        detector.recordEvent({ clientId: 'solo', type: 'solve', timestamp: 1000 + i * 100 });
      }
      var rings = detector.detectRings();
      assert.strictEqual(rings.length, 0); // One client can't form a ring
    });

    it('handles fail events without crashing', function () {
      detector.recordEvent({ clientId: 'f1', type: 'fail', timestamp: 1000 });
      detector.recordEvent({ clientId: 'f2', type: 'fail', timestamp: 1100 });
      detector.recordEvent({ clientId: 'f3', type: 'fail', timestamp: 1200 });
      var rings = detector.detectRings();
      assert.ok(Array.isArray(rings));
    });

    it('handles request events', function () {
      detector.recordEvent({ clientId: 'req1', type: 'request', timestamp: 1000 });
      assert.strictEqual(detector.getStats().totalClients, 1);
    });

    it('maxRings eviction works', function () {
      var d = lib.createFraudRingDetector({ maxRings: 2, minRingSize: 2, suspicionThreshold: 1 });
      // Create 3 separate rings
      for (var r = 0; r < 3; r++) {
        for (var i = 0; i < 3; i++) {
          d.recordEvent({ clientId: 'ring' + r + 'c' + i, type: 'solve', timestamp: r * 100000 + i * 100, fingerprint: 'ring' + r + '-fp', ip: '10.0.' + r + '.1' });
        }
        d.detectRings();
      }
      var stats = d.getStats();
      assert.ok(stats.totalRings <= 2);
    });

    it('callback errors are swallowed', function () {
      detector.onRingDetected(function() { throw new Error('boom'); });
      var base = 700000;
      for (var i = 1; i <= 4; i++) {
        detector.recordEvent({ clientId: 'cb' + i, type: 'solve', timestamp: base + i * 100, fingerprint: 'cb-fp', ip: '10.0.0.1' });
      }
      assert.doesNotThrow(function() { detector.detectRings(); });
    });
  });
});
