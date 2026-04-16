'use strict';
var assert = require('assert');
var createResponseTimeProfiler = require('../src/response-time-profiler').createResponseTimeProfiler;

var _ts = 1000000;
function clock() { return _ts; }
function tick(ms) { _ts += (ms || 1000); }
function resetClock() { _ts = 1000000; }
function mp(o) { return createResponseTimeProfiler(Object.assign({ now: clock }, o || {})); }

describe('ResponseTimeProfiler', function () {
  beforeEach(resetClock);

  describe('factory', function () {
    it('creates with defaults', function () { var p = mp(); assert.ok(p); assert.equal(typeof p.record, 'function'); });
    it('accepts custom options', function () { assert.ok(mp({ botThresholdMs: 300 })); });
  });

  describe('record', function () {
    it('rejects missing responseTimeMs', function () { assert.throws(function () { mp().record({}); }, /responseTimeMs/); });
    it('rejects negative', function () { assert.throws(function () { mp().record({ sessionId: 's', responseTimeMs: -1, solved: true }); }, /non-negative/); });
    it('rejects missing sessionId', function () { assert.throws(function () { mp().record({ responseTimeMs: 1000, solved: true }); }, /sessionId/); });
    it('rejects missing solved', function () { assert.throws(function () { mp().record({ sessionId: 's', responseTimeMs: 1000 }); }, /solved/); });
    it('accepts valid', function () { var p = mp(); p.record({ sessionId: 's', responseTimeMs: 1500, solved: true }); assert.equal(p.getSummary().totalSolves, 1); });
    it('handles zero ms', function () { var p = mp(); p.record({ sessionId: 's', responseTimeMs: 0, solved: false }); assert.equal(p.getSummary().totalSolves, 1); });
  });

  describe('getTypeProfile', function () {
    it('null if insufficient', function () {
      var p = mp({ minSamples: 5 });
      for (var i = 0; i < 3; i++) { tick(); p.record({ sessionId: 's', type: 'img', responseTimeMs: 2000, solved: true }); }
      assert.equal(p.getTypeProfile('img'), null);
    });
    it('returns profile', function () {
      var p = mp({ minSamples: 5 });
      for (var i = 0; i < 10; i++) { tick(); p.record({ sessionId: 's', type: 'img', responseTimeMs: 1000 + i * 100, solved: i < 8 }); }
      var pr = p.getTypeProfile('img'); assert.equal(pr.sampleCount, 10); assert.equal(pr.solveCount, 8);
      assert.ok(pr.p5 <= pr.p25 && pr.p25 <= pr.p75 && pr.p75 <= pr.p95);
    });
    it('defaults to "default"', function () {
      var p = mp({ minSamples: 3 });
      for (var i = 0; i < 5; i++) { tick(); p.record({ sessionId: 's', responseTimeMs: 2000, solved: true }); }
      assert.equal(p.getTypeProfile().type, 'default');
    });
  });

  describe('getAllTypeProfiles', function () {
    it('returns all', function () {
      var p = mp({ minSamples: 3 });
      for (var i = 0; i < 5; i++) { tick(); p.record({ sessionId: 's', type: 'gif', responseTimeMs: 2000, solved: true }); p.record({ sessionId: 's', type: 'puzzle', responseTimeMs: 3000, solved: true }); }
      assert.equal(p.getAllTypeProfiles().length, 2);
    });
  });

  describe('detectAnomalies', function () {
    it('insufficient_data for 1', function () { var p = mp(); p.record({ sessionId: 's', responseTimeMs: 1000, solved: true }); assert.equal(p.detectAnomalies('s').classification, 'insufficient_data'); });
    it('detects too-fast', function () {
      var p = mp({ botThresholdMs: 500 });
      for (var i = 0; i < 5; i++) { tick(); p.record({ sessionId: 'b', responseTimeMs: 200, solved: true }); }
      assert.ok(p.detectAnomalies('b').anomalies.some(function (a) { return a.type === 'too_fast'; }));
    });
    it('detects too-consistent', function () {
      var p = mp({ minSamples: 5, consistencyThreshold: 0.1 });
      for (var i = 0; i < 15; i++) { tick(); p.record({ sessionId: 'f', responseTimeMs: 2000, solved: true }); }
      assert.ok(p.detectAnomalies('f').anomalies.some(function (a) { return a.type === 'too_consistent'; }));
    });
    it('detects burst', function () {
      var p = mp({ burstWindowMs: 5000, burstThreshold: 3 });
      for (var i = 0; i < 4; i++) { tick(1); p.record({ sessionId: 'b', responseTimeMs: 1500, solved: true }); }
      assert.ok(p.detectAnomalies('b').anomalies.some(function (a) { return a.type === 'burst_pattern'; }));
    });
    it('detects out-of-range', function () {
      var p = mp({ humanMinMs: 800 });
      for (var i = 0; i < 10; i++) { tick(); p.record({ sessionId: 'w', responseTimeMs: 100, solved: true }); }
      assert.ok(p.detectAnomalies('w').anomalies.some(function (a) { return a.type === 'out_of_human_range'; }));
    });
    it('no anomalies for human', function () {
      var p = mp(); var t = [1200, 2500, 1800, 3200, 1500, 2800, 2100, 1700, 3500, 2000];
      for (var i = 0; i < t.length; i++) { tick(t[i] + 2000); p.record({ sessionId: 'h', responseTimeMs: t[i], solved: i !== 3 }); }
      var r = p.detectAnomalies('h'); assert.equal(r.classification, 'human'); assert.equal(r.anomalies.length, 0);
    });
    it('throws for unknown', function () { assert.throws(function () { mp().detectAnomalies('x'); }, /Unknown/); });
  });

  describe('classifySession', function () {
    it('classifies bot', function () {
      var p = mp({ minSamples: 5 });
      for (var i = 0; i < 15; i++) { tick(100); p.record({ sessionId: 'b', responseTimeMs: 200, solved: true }); }
      var c = p.classifySession('b'); assert.equal(c.classification, 'bot'); assert.equal(c.humanLikelihood, 'low');
    });
    it('classifies human', function () {
      var p = mp(); var t = [1200, 2500, 1800, 3200, 1500, 2800, 2100, 1700, 3500, 2000];
      for (var i = 0; i < t.length; i++) { tick(t[i] + 2000); p.record({ sessionId: 'h', responseTimeMs: t[i], solved: i !== 3 }); }
      var c = p.classifySession('h'); assert.equal(c.classification, 'human'); assert.equal(c.humanLikelihood, 'high');
    });
    it('classifies solver farm', function () {
      var p = mp({ minSamples: 5, consistencyThreshold: 0.1 });
      for (var i = 0; i < 15; i++) { tick(5000); p.record({ sessionId: 'f', responseTimeMs: 2000, solved: true }); }
      assert.equal(p.classifySession('f').classification, 'solver_farm');
    });
    it('returns stats', function () {
      var p = mp(); tick(); p.record({ sessionId: 's', responseTimeMs: 1000, solved: true }); tick(); p.record({ sessionId: 's', responseTimeMs: 2000, solved: false });
      assert.equal(p.classifySession('s').stats.sampleSize, 2);
    });
    it('insufficient for 1', function () {
      var p = mp(); p.record({ sessionId: 's', responseTimeMs: 1500, solved: true });
      assert.equal(p.classifySession('s').classification, 'insufficient_data');
    });
  });

  describe('getHistogram', function () {
    it('null for <2', function () { var p = mp(); p.record({ sessionId: 's', responseTimeMs: 1000, solved: true }); assert.equal(p.getHistogram(), null); });
    it('generates bins', function () {
      var p = mp({ histogramBins: 5 });
      for (var i = 0; i < 20; i++) { tick(); p.record({ sessionId: 's', responseTimeMs: 1000 + i * 200, solved: true }); }
      var h = p.getHistogram(); assert.equal(h.bins.length, 5); assert.equal(h.bins.reduce(function (s, b) { return s + b.count; }, 0), 20);
    });
    it('handles same values', function () {
      var p = mp({ histogramBins: 5 });
      for (var i = 0; i < 10; i++) { tick(); p.record({ sessionId: 's', responseTimeMs: 2000, solved: true }); }
      assert.equal(p.getHistogram().totalSamples, 10);
    });
  });

  describe('getDifficultyCorrelation', function () {
    it('null if insufficient', function () {
      var p = mp({ minSamples: 10 });
      for (var i = 0; i < 5; i++) { tick(); p.record({ sessionId: 's', responseTimeMs: 1000, solved: true, difficulty: 5 }); }
      assert.equal(p.getDifficultyCorrelation(), null);
    });
    it('detects positive correlation', function () {
      var p = mp({ minSamples: 5 });
      for (var d = 1; d <= 10; d++) { tick(); p.record({ sessionId: 's', responseTimeMs: 500 + d * 300, solved: true, difficulty: d }); }
      var c = p.getDifficultyCorrelation(); assert.ok(c.correlation > 0.8); assert.equal(c.strength, 'strong');
    });
    it('handles zero denominator', function () {
      var p = mp({ minSamples: 5 });
      for (var i = 0; i < 10; i++) { tick(); p.record({ sessionId: 's', responseTimeMs: 1000 + i * 100, solved: true, difficulty: 5 }); }
      assert.equal(p.getDifficultyCorrelation().correlation, 0);
    });
  });

  describe('getInterSolveGaps', function () {
    it('null for <3', function () { var p = mp(); tick(); p.record({ sessionId: 's', responseTimeMs: 1000, solved: true }); tick(); p.record({ sessionId: 's', responseTimeMs: 1500, solved: true }); assert.equal(p.getInterSolveGaps('s'), null); });
    it('detects mechanical', function () {
      var p = mp(); for (var i = 0; i < 10; i++) { tick(5000); p.record({ sessionId: 'm', responseTimeMs: 1500, solved: true }); }
      assert.equal(p.getInterSolveGaps('m').regularity, 'mechanical');
    });
    it('detects natural', function () {
      var p = mp(); var d = [2000, 5000, 1000, 8000, 3000, 12000, 2000, 4000, 7000];
      for (var i = 0; i <= d.length; i++) { if (i > 0) tick(d[i - 1]); p.record({ sessionId: 'n', responseTimeMs: 1500, solved: true }); }
      assert.equal(p.getInterSolveGaps('n').regularity, 'natural');
    });
    it('throws for unknown', function () { assert.throws(function () { mp().getInterSolveGaps('x'); }, /Unknown/); });
  });

  describe('getSummary', function () {
    it('zeros for empty', function () { var s = mp().getSummary(); assert.equal(s.totalSessions, 0); assert.equal(s.totalSolves, 0); });
    it('aggregates', function () {
      var p = mp(); var t = [1200, 2500, 1800, 3200, 1500, 2800, 2100, 1700, 3500, 2000];
      for (var i = 0; i < 5; i++) { tick(3000); p.record({ sessionId: 'a', responseTimeMs: t[i], solved: true }); }
      for (var j = 5; j < 10; j++) { tick(3000); p.record({ sessionId: 'b', responseTimeMs: t[j], solved: j !== 8 }); }
      var s = p.getSummary(); assert.equal(s.totalSessions, 2); assert.equal(s.totalSolves, 10);
    });
  });

  describe('export/import', function () {
    it('round-trips', function () {
      var p1 = mp({ minSamples: 3 });
      for (var i = 0; i < 5; i++) { tick(); p1.record({ sessionId: 's', type: 'gif', responseTimeMs: 1000 + i * 100, solved: true, difficulty: i + 1 }); }
      var p2 = mp({ minSamples: 3 }); p2.importData(p1.exportData());
      assert.equal(p2.getTypeProfile('gif').sampleCount, 5);
    });
    it('rejects invalid', function () { assert.throws(function () { mp().importData({ version: 99 }); }, /unsupported/); });
    it('rejects null', function () { assert.throws(function () { mp().importData(null); }, /Invalid/); });
  });

  describe('reset', function () {
    it('clears all', function () {
      var p = mp(); for (var i = 0; i < 5; i++) { tick(); p.record({ sessionId: 's', responseTimeMs: 1500, solved: true }); }
      p.reset(); assert.equal(p.getSummary().totalSessions, 0);
    });
  });

  describe('eviction', function () {
    it('evicts oldest', function () {
      var p = mp({ maxSessions: 3 });
      tick(); p.record({ sessionId: 'old', responseTimeMs: 1000, solved: true });
      tick(); p.record({ sessionId: 'mid', responseTimeMs: 1000, solved: true });
      tick(); p.record({ sessionId: 'new', responseTimeMs: 1000, solved: true });
      tick(); p.record({ sessionId: 'newest', responseTimeMs: 1000, solved: true });
      assert.equal(p.getSummary().totalSessions, 3);
      assert.throws(function () { p.detectAnomalies('old'); }, /Unknown/);
    });
  });

  describe('trimming', function () {
    it('trims to maxSamples', function () {
      var p = mp({ maxSamples: 5, minSamples: 3 });
      for (var i = 0; i < 10; i++) { tick(); p.record({ sessionId: 's', responseTimeMs: 1000 + i * 100, solved: true }); }
      assert.equal(p.getTypeProfile().sampleCount, 5);
    });
  });
});
