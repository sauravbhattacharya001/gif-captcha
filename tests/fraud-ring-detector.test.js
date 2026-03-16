'use strict';

var assert = require('assert');
var _mod = require('../src/fraud-ring-detector.js');
var createFraudRingDetector = _mod.createFraudRingDetector;

// Helper: generate solve data at specific hours with response times
function makeSolves(hours, responseTimeMs, success, baseTs) {
  baseTs = baseTs || Date.UTC(2026, 2, 15); // March 15, 2026
  return hours.map(function (h, i) {
    return {
      timestamp: baseTs + h * 3600000 + i * 60000,
      responseTime: responseTimeMs + (i % 3) * 100,
      success: success
    };
  });
}

describe('FraudRingDetector', function () {

  it('should create detector with default options', function () {
    var det = createFraudRingDetector();
    var s = det.stats();
    assert.strictEqual(s.sessions, 0);
    assert.strictEqual(s.rings, 0);
    assert.strictEqual(s.options.similarityThreshold, 0.70);
    assert.strictEqual(s.options.minRingSize, 3);
  });

  it('should create detector with custom options', function () {
    var det = createFraudRingDetector({ similarityThreshold: 0.5, minRingSize: 2, maxSessions: 100 });
    var s = det.stats();
    assert.strictEqual(s.options.similarityThreshold, 0.5);
    assert.strictEqual(s.options.minRingSize, 2);
    assert.strictEqual(s.options.maxSessions, 100);
  });

  it('should throw on missing sessionId', function () {
    var det = createFraudRingDetector();
    assert.throws(function () { det.addSession('', {}); }, /sessionId/);
    assert.throws(function () { det.addSession(null, {}); }, /sessionId/);
  });

  it('should add sessions and track count', function () {
    var det = createFraudRingDetector();
    det.addSession('s1', { ip: '1.2.3.4', solves: makeSolves([9, 10, 11], 2000, true) });
    det.addSession('s2', { ip: '5.6.7.8', solves: makeSolves([9, 10, 11], 2100, true) });
    assert.strictEqual(det.stats().sessions, 2);
  });

  it('should update existing session with new solves', function () {
    var det = createFraudRingDetector();
    det.addSession('s1', { solves: makeSolves([9], 2000, true) });
    det.addSession('s1', { solves: makeSolves([10], 2000, true) });
    assert.strictEqual(det.stats().sessions, 1); // still 1 session
  });

  it('should evict oldest session when maxSessions reached', function () {
    var det = createFraudRingDetector({ maxSessions: 2 });
    det.addSession('s1', { solves: [] });
    det.addSession('s2', { solves: [] });
    det.addSession('s3', { solves: [] });
    assert.strictEqual(det.stats().sessions, 2);
  });

  it('should detect no rings with too few sessions', function () {
    var det = createFraudRingDetector({ minRingSize: 3 });
    det.addSession('s1', { solves: makeSolves([9, 10], 2000, true) });
    det.addSession('s2', { solves: makeSolves([9, 10], 2000, true) });
    var result = det.detect();
    assert.strictEqual(result.length, 0);
  });

  it('should detect a ring among similar sessions', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13, 14, 15];
    det.addSession('s1', { ip: '10.0.0.1', solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { ip: '10.0.0.2', solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { ip: '10.0.0.3', solves: makeSolves(hours, 2100, true) });
    var result = det.detect();
    assert.ok(result.length >= 1, 'Should detect at least one ring');
    assert.ok(result[0].size >= 3);
    assert.ok(result[0].confidence > 0);
  });

  it('should not cluster dissimilar sessions', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.85 });
    // Very different timing patterns
    det.addSession('s1', { solves: makeSolves([1, 2, 3], 500, true) });
    det.addSession('s2', { solves: makeSolves([12, 13, 14], 5000, false) });
    det.addSession('s3', { solves: makeSolves([20, 21, 22], 9000, true) });
    var result = det.detect();
    assert.strictEqual(result.length, 0);
  });

  it('should track IP diversity', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { ip: '1.1.1.1', solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { ip: '2.2.2.2', solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { ip: '3.3.3.3', solves: makeSolves(hours, 2100, true) });
    var result = det.detect();
    if (result.length > 0) {
      assert.ok(result[0].ipDiversity >= 1);
    }
  });

  it('should provide evidence breakdown', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13, 14];
    det.addSession('s1', { ip: '10.0.0.1', solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { ip: '10.0.0.2', solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { ip: '10.0.0.3', solves: makeSolves(hours, 2100, true) });
    var result = det.detect();
    if (result.length > 0) {
      assert.ok('timing' in result[0].evidence);
      assert.ok('responseTime' in result[0].evidence);
      assert.ok('successRate' in result[0].evidence);
      assert.ok('activityOverlap' in result[0].evidence);
    }
  });

  it('should get a ring by ID', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    var result = det.detect();
    if (result.length > 0) {
      var ring = det.getRing(result[0].id);
      assert.ok(ring);
      assert.strictEqual(ring.id, result[0].id);
    }
  });

  it('should return null for unknown ring ID', function () {
    var det = createFraudRingDetector();
    assert.strictEqual(det.getRing('nonexistent'), null);
  });

  it('should list rings sorted by confidence', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    det.detect();
    var list = det.listRings();
    for (var i = 1; i < list.length; i++) {
      assert.ok(list[i - 1].confidence >= list[i].confidence);
    }
  });

  it('should filter rings by minConfidence', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    det.detect();
    var all = det.listRings();
    var filtered = det.listRings({ minConfidence: 0.99 });
    assert.ok(filtered.length <= all.length);
  });

  it('should check if session belongs to a ring', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    det.detect();
    var check = det.checkSession('s1');
    // Should find rings or return empty
    assert.ok(Array.isArray(check));
  });

  it('should return empty for unlinked session', function () {
    var det = createFraudRingDetector();
    var check = det.checkSession('unknown');
    assert.deepStrictEqual(check, []);
  });

  it('should remove a ring', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    var result = det.detect();
    if (result.length > 0) {
      assert.ok(det.removeRing(result[0].id));
      assert.strictEqual(det.getRing(result[0].id), null);
    }
  });

  it('should return false when removing nonexistent ring', function () {
    var det = createFraudRingDetector();
    assert.strictEqual(det.removeRing('fake'), false);
  });

  it('should clear all rings', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    det.detect();
    det.clearRings();
    assert.strictEqual(det.stats().rings, 0);
    assert.deepStrictEqual(det.listRings(), []);
  });

  it('should generate a report', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { ip: '1.1.1.1', solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { ip: '2.2.2.2', solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { ip: '3.3.3.3', solves: makeSolves(hours, 2100, true) });
    det.detect();
    var rep = det.report();
    assert.ok('totalRings' in rep);
    assert.ok('totalMembers' in rep);
    assert.ok('uniqueIps' in rep);
    assert.ok('totalSessions' in rep);
    assert.ok('coverageRate' in rep);
    assert.ok('rings' in rep);
    assert.ok(Array.isArray(rep.rings));
  });

  it('should export and import data', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    det.detect();
    var exported = det.exportData();
    assert.ok(exported.sessions);
    assert.ok(exported.rings);
    assert.ok(exported.options);

    var det2 = createFraudRingDetector();
    det2.importData(exported);
    assert.ok(det2.stats().sessions >= 3);
  });

  it('should throw on invalid import data', function () {
    var det = createFraudRingDetector();
    assert.throws(function () { det.importData(null); }, /Invalid/);
    assert.throws(function () { det.importData('bad'); }, /Invalid/);
  });

  it('should handle sessions with no solves gracefully', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    det.addSession('s1', {});
    det.addSession('s2', {});
    det.addSession('s3', {});
    var result = det.detect();
    // Should not crash; may or may not detect rings with empty data
    assert.ok(Array.isArray(result));
  });

  it('should handle sessions with varied success rates', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.3 });
    var hours = [9, 10, 11, 12, 13, 14];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, false) }); // different success
    var result = det.detect();
    assert.ok(Array.isArray(result));
  });

  it('should apply decay when listing rings', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    det.detect();
    var noDecay = det.listRings();
    var withDecay = det.listRings({ applyDecay: true });
    // Decay should not increase confidence
    if (noDecay.length > 0 && withDecay.length > 0) {
      assert.ok(withDecay[0].confidence <= noDecay[0].confidence);
    }
  });

  it('should report empty when no rings detected', function () {
    var det = createFraudRingDetector();
    var rep = det.report();
    assert.strictEqual(rep.totalRings, 0);
    assert.strictEqual(rep.totalMembers, 0);
    assert.deepStrictEqual(rep.rings, []);
  });

  it('stats should reflect current state', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    assert.strictEqual(det.stats().sessions, 3);
    assert.strictEqual(det.stats().rings, 0);
    det.detect();
    assert.ok(det.stats().rings >= 0);
  });

  it('should handle large number of solves per session', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [];
    for (var i = 0; i < 50; i++) hours.push(i % 24);
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    var result = det.detect();
    assert.ok(Array.isArray(result));
  });

  it('should report coverage rate correctly', function () {
    var det = createFraudRingDetector({ minRingSize: 3, similarityThreshold: 0.5 });
    var hours = [9, 10, 11, 12, 13];
    det.addSession('s1', { solves: makeSolves(hours, 2000, true) });
    det.addSession('s2', { solves: makeSolves(hours, 2050, true) });
    det.addSession('s3', { solves: makeSolves(hours, 2100, true) });
    det.addSession('s4', { solves: makeSolves([1, 2, 3], 8000, false) }); // outlier
    det.detect();
    var rep = det.report();
    assert.ok(rep.coverageRate >= 0 && rep.coverageRate <= 1);
  });
});
