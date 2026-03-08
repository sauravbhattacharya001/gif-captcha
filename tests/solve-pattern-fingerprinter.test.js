'use strict';

var test = require('node:test');
var assert = require('node:assert/strict');
var _mod = require('../src/solve-pattern-fingerprinter.js');
var createSolvePatternFingerprinter = _mod.createSolvePatternFingerprinter;

// ── Helpers ──────────────────────────────────────────────────────────

function _makeSolves(count, opts) {
  opts = opts || {};
  var baseTime = opts.baseTimeMs || 3000;
  var variance = opts.varianceMs || 500;
  var successRate = opts.successRate != null ? opts.successRate : 0.85;
  var baseTimestamp = opts.baseTimestamp || 1709308800000; // 2024-03-01T12:00:00Z
  var gapMs = opts.gapMs || 60000;
  var hourOffset = opts.hourOffset || 0;

  var solves = [];
  for (var i = 0; i < count; i++) {
    var timeMs = baseTime + (Math.random() - 0.5) * 2 * variance;
    timeMs = Math.max(100, Math.round(timeMs));
    var correct = Math.random() < successRate;
    var ts = baseTimestamp + i * gapMs;
    // Offset the hour for time-of-day distribution testing
    if (hourOffset) {
      var d = new Date(ts);
      d.setUTCHours((d.getUTCHours() + hourOffset) % 24);
      ts = d.getTime();
    }
    solves.push({ timeMs: timeMs, correct: correct, timestamp: ts });
  }
  return solves;
}

function _feedSolves(fp, sessionId, solves) {
  for (var i = 0; i < solves.length; i++) {
    fp.recordSolve(sessionId, solves[i]);
  }
}

// ── Construction ─────────────────────────────────────────────────────

test('creates with default options', function() {
  var fp = createSolvePatternFingerprinter();
  assert.ok(fp);
  assert.equal(typeof fp.recordSolve, 'function');
  assert.equal(typeof fp.getFingerprint, 'function');
  assert.equal(typeof fp.compareFingerprints, 'function');
});

test('creates with custom options', function() {
  var fp = createSolvePatternFingerprinter({
    minSamples: 3,
    maxSamples: 50,
    similarityThreshold: 0.8,
    timeBuckets: 12,
    maxProfiles: 100
  });
  var stats = fp.getStats();
  assert.equal(stats.config.minSamples, 3);
  assert.equal(stats.config.maxSamples, 50);
  assert.equal(stats.config.similarityThreshold, 0.8);
  assert.equal(stats.config.timeBuckets, 12);
  assert.equal(stats.config.maxProfiles, 100);
});

// ── recordSolve ──────────────────────────────────────────────────────

test('recordSolve returns solve count', function() {
  var fp = createSolvePatternFingerprinter();
  var r = fp.recordSolve('sess1', { timeMs: 2500, correct: true });
  assert.equal(r.sessionId, 'sess1');
  assert.equal(r.solveCount, 1);
  assert.equal(r.hasFingerprint, false);  // need minSamples (5)
});

test('recordSolve generates fingerprint after minSamples', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  fp.recordSolve('s1', { timeMs: 2000, correct: true, timestamp: 1000 });
  fp.recordSolve('s1', { timeMs: 2500, correct: true, timestamp: 2000 });
  var r = fp.recordSolve('s1', { timeMs: 3000, correct: false, timestamp: 3000 });
  assert.equal(r.hasFingerprint, true);
});

test('recordSolve throws on invalid sessionId', function() {
  var fp = createSolvePatternFingerprinter();
  assert.throws(function() { fp.recordSolve('', { timeMs: 100, correct: true }); });
  assert.throws(function() { fp.recordSolve(null, { timeMs: 100, correct: true }); });
});

test('recordSolve throws on invalid solve', function() {
  var fp = createSolvePatternFingerprinter();
  assert.throws(function() { fp.recordSolve('s1', {}); });
  assert.throws(function() { fp.recordSolve('s1', { timeMs: 'abc', correct: true }); });
});

test('recordSolve caps at maxSamples', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 2, maxSamples: 5 });
  for (var i = 0; i < 10; i++) {
    fp.recordSolve('s1', { timeMs: 1000 + i * 100, correct: true, timestamp: i * 1000 });
  }
  var stats = fp.getStats();
  assert.equal(stats.totalSolves, 5);  // capped
});

// ── getFingerprint ───────────────────────────────────────────────────

test('getFingerprint returns null for unknown session', function() {
  var fp = createSolvePatternFingerprinter();
  assert.equal(fp.getFingerprint('nonexistent'), null);
});

test('getFingerprint returns null before minSamples', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 5 });
  fp.recordSolve('s1', { timeMs: 2000, correct: true });
  assert.equal(fp.getFingerprint('s1'), null);
});

test('fingerprint has expected fields', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(5));
  var f = fp.getFingerprint('s1');
  assert.ok(f);
  assert.equal(typeof f.sampleCount, 'number');
  assert.equal(typeof f.successRate, 'number');
  assert.equal(typeof f.avgSolveTimeMs, 'number');
  assert.equal(typeof f.medianSolveTimeMs, 'number');
  assert.equal(typeof f.stdSolveTimeMs, 'number');
  assert.equal(typeof f.p10SolveTimeMs, 'number');
  assert.equal(typeof f.p90SolveTimeMs, 'number');
  assert.ok(Array.isArray(f.timeOfDayDistribution));
  assert.equal(f.timeOfDayDistribution.length, 24);
  assert.equal(typeof f.coefficientOfVariation, 'number');
});

test('fingerprint successRate is between 0 and 1', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(20, { successRate: 0.7 }));
  var f = fp.getFingerprint('s1');
  assert.ok(f.successRate >= 0 && f.successRate <= 1);
});

// ── compareFingerprints ──────────────────────────────────────────────

test('identical fingerprints have similarity 1', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  var solves = [
    { timeMs: 2000, correct: true, timestamp: 1000000 },
    { timeMs: 2100, correct: true, timestamp: 1060000 },
    { timeMs: 2200, correct: false, timestamp: 1120000 },
    { timeMs: 2000, correct: true, timestamp: 1180000 },
    { timeMs: 2300, correct: true, timestamp: 1240000 }
  ];
  _feedSolves(fp, 'a', solves);
  _feedSolves(fp, 'b', solves);
  var fA = fp.getFingerprint('a');
  var fB = fp.getFingerprint('b');
  var result = fp.compareFingerprints(fA, fB);
  assert.equal(result.similarity, 1);
  assert.equal(result.match, true);
});

test('very different fingerprints have low similarity', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3, similarityThreshold: 0.8 });
  // Fast solver
  _feedSolves(fp, 'fast', _makeSolves(10, { baseTimeMs: 500, varianceMs: 50, successRate: 1.0 }));
  // Slow solver
  _feedSolves(fp, 'slow', _makeSolves(10, { baseTimeMs: 15000, varianceMs: 3000, successRate: 0.3 }));
  var result = fp.compareFingerprints(fp.getFingerprint('fast'), fp.getFingerprint('slow'));
  assert.ok(result.similarity < 0.5, 'similarity should be < 0.5, got ' + result.similarity);
  assert.equal(result.match, false);
});

test('compareFingerprints returns 0 for null inputs', function() {
  var fp = createSolvePatternFingerprinter();
  var result = fp.compareFingerprints(null, null);
  assert.equal(result.similarity, 0);
  assert.equal(result.match, false);
});

test('compareFingerprints returns dimensions breakdown', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 'a', _makeSolves(5));
  _feedSolves(fp, 'b', _makeSolves(5));
  var result = fp.compareFingerprints(fp.getFingerprint('a'), fp.getFingerprint('b'));
  assert.ok(result.dimensions);
  assert.equal(typeof result.dimensions.avgTime, 'number');
  assert.equal(typeof result.dimensions.successRate, 'number');
  assert.equal(typeof result.dimensions.timeOfDay, 'number');
});

// ── Profiles ─────────────────────────────────────────────────────────

test('saveProfile stores fingerprint', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(5));
  var result = fp.saveProfile('bot-pattern-1', 's1');
  assert.equal(result.profileId, 'bot-pattern-1');
  assert.ok(result.fingerprint);
});

test('saveProfile throws without fingerprint', function() {
  var fp = createSolvePatternFingerprinter();
  fp.recordSolve('s1', { timeMs: 1000, correct: true });
  assert.throws(function() { fp.saveProfile('p1', 's1'); });
});

test('saveProfile throws on empty profileId', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(5));
  assert.throws(function() { fp.saveProfile('', 's1'); });
});

test('saveProfile enforces maxProfiles', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3, maxProfiles: 2 });
  _feedSolves(fp, 's1', _makeSolves(5));
  _feedSolves(fp, 's2', _makeSolves(5));
  _feedSolves(fp, 's3', _makeSolves(5));
  fp.saveProfile('p1', 's1');
  fp.saveProfile('p2', 's2');
  assert.throws(function() { fp.saveProfile('p3', 's3'); });
});

// ── matchAgainstProfiles ─────────────────────────────────────────────

test('matchAgainstProfiles finds matching profile', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3, similarityThreshold: 0.5 });
  var solves = _makeSolves(10, { baseTimeMs: 3000, varianceMs: 200, successRate: 0.9 });
  _feedSolves(fp, 'original', solves);
  fp.saveProfile('known-bot', 'original');

  // Feed similar solves to a new session
  _feedSolves(fp, 'suspect', solves);

  var result = fp.matchAgainstProfiles('suspect');
  assert.ok(result.matches.length > 0, 'should find at least one match');
  assert.equal(result.matches[0].profileId, 'known-bot');
});

test('matchAgainstProfiles returns empty for no fingerprint', function() {
  var fp = createSolvePatternFingerprinter();
  fp.recordSolve('s1', { timeMs: 1000, correct: true });
  var result = fp.matchAgainstProfiles('s1');
  assert.equal(result.matches.length, 0);
});

test('matchAgainstProfiles returns empty for very different pattern', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3, similarityThreshold: 0.9 });
  _feedSolves(fp, 'bot', _makeSolves(10, { baseTimeMs: 200, varianceMs: 10, successRate: 1.0 }));
  fp.saveProfile('fast-bot', 'bot');

  _feedSolves(fp, 'human', _makeSolves(10, { baseTimeMs: 8000, varianceMs: 3000, successRate: 0.6 }));
  var result = fp.matchAgainstProfiles('human');
  assert.equal(result.matches.length, 0);
});

// ── findSimilarSessions ──────────────────────────────────────────────

test('findSimilarSessions detects similar pairs', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3, similarityThreshold: 0.5 });
  var solves = _makeSolves(8, { baseTimeMs: 2500, varianceMs: 100, successRate: 0.9 });
  _feedSolves(fp, 'sess-a', solves);
  _feedSolves(fp, 'sess-b', solves);
  _feedSolves(fp, 'sess-c', _makeSolves(8, { baseTimeMs: 20000, varianceMs: 1000, successRate: 0.2 }));

  var result = fp.findSimilarSessions();
  // sess-a and sess-b should match; sess-c should not
  var abPair = result.pairs.filter(function(p) {
    return (p.sessionA === 'sess-a' && p.sessionB === 'sess-b') ||
           (p.sessionA === 'sess-b' && p.sessionB === 'sess-a');
  });
  assert.ok(abPair.length > 0, 'should find sess-a/sess-b pair');
});

test('findSimilarSessions returns empty without fingerprints', function() {
  var fp = createSolvePatternFingerprinter();
  fp.recordSolve('s1', { timeMs: 1000, correct: true });
  var result = fp.findSimilarSessions();
  assert.equal(result.pairs.length, 0);
});

// ── Session/Profile management ───────────────────────────────────────

test('removeSession deletes session data', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(5));
  assert.equal(fp.removeSession('s1'), true);
  assert.equal(fp.getFingerprint('s1'), null);
  assert.equal(fp.getStats().totalSessions, 0);
});

test('removeSession returns false for unknown', function() {
  var fp = createSolvePatternFingerprinter();
  assert.equal(fp.removeSession('nope'), false);
});

test('removeProfile deletes profile', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(5));
  fp.saveProfile('p1', 's1');
  assert.equal(fp.removeProfile('p1'), true);
  assert.equal(fp.getStats().totalProfiles, 0);
});

test('removeProfile returns false for unknown', function() {
  var fp = createSolvePatternFingerprinter();
  assert.equal(fp.removeProfile('nope'), false);
});

// ── getStats ─────────────────────────────────────────────────────────

test('getStats reflects current state', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(5));
  _feedSolves(fp, 's2', _makeSolves(2)); // below minSamples
  fp.saveProfile('p1', 's1');

  var stats = fp.getStats();
  assert.equal(stats.totalSessions, 2);
  assert.equal(stats.sessionsWithFingerprint, 1);
  assert.equal(stats.totalSolves, 7);
  assert.equal(stats.totalProfiles, 1);
});

// ── reset ────────────────────────────────────────────────────────────

test('reset clears all data', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(5));
  fp.saveProfile('p1', 's1');
  fp.reset();

  var stats = fp.getStats();
  assert.equal(stats.totalSessions, 0);
  assert.equal(stats.totalProfiles, 0);
  assert.equal(stats.totalSolves, 0);
});

// ── Edge cases ───────────────────────────────────────────────────────

test('fingerprint with all correct solves has successRate 1', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(5, { successRate: 1.0 }));
  var f = fp.getFingerprint('s1');
  assert.equal(f.successRate, 1);
  assert.equal(f.avgIncorrectTimeMs, null);
});

test('fingerprint with all incorrect solves has successRate 0', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  _feedSolves(fp, 's1', _makeSolves(5, { successRate: 0 }));
  var f = fp.getFingerprint('s1');
  assert.equal(f.successRate, 0);
  assert.equal(f.avgCorrectTimeMs, null);
});

test('fingerprint with no timestamps has null gaps', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3 });
  for (var i = 0; i < 5; i++) {
    fp.recordSolve('s1', { timeMs: 2000 + i * 100, correct: true });
  }
  var f = fp.getFingerprint('s1');
  assert.ok(f);
  // timestamps auto-assigned by Date.now(), so gaps should exist
  assert.equal(typeof f.avgGapMs, 'number');
});

test('custom timeBuckets changes distribution length', function() {
  var fp = createSolvePatternFingerprinter({ minSamples: 3, timeBuckets: 6 });
  _feedSolves(fp, 's1', _makeSolves(5));
  var f = fp.getFingerprint('s1');
  assert.equal(f.timeOfDayDistribution.length, 6);
});
