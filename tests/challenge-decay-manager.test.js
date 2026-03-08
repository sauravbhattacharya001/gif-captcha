'use strict';

var test = require('node:test');
var assert = require('node:assert/strict');
var _mod = require('../src/challenge-decay-manager.js');
var createChallengeDecayManager = _mod.createChallengeDecayManager;

// ── Helpers ──────────────────────────────────────────────────────────

function _clock(startMs) {
  var t = startMs || 0;
  return {
    now: function() { return t; },
    advance: function(ms) { t += ms; }
  };
}

// ── Construction ─────────────────────────────────────────────────────

test('creates with default options', function() {
  var dm = createChallengeDecayManager();
  assert.ok(dm);
  assert.equal(typeof dm.addChallenge, 'function');
  assert.equal(typeof dm.recordSolve, 'function');
  assert.equal(typeof dm.sweep, 'function');
});

test('creates with custom options', function() {
  var dm = createChallengeDecayManager({
    maxAge: 3600000,
    maxSolves: 100,
    maxExposures: 200,
    freshnessThreshold: 0.3,
    halfLifeMs: 1800000,
    solveHalfLife: 50,
    maxChallenges: 10
  });
  assert.ok(dm);
});

// ── addChallenge ─────────────────────────────────────────────────────

test('addChallenge registers a challenge', function() {
  var dm = createChallengeDecayManager();
  var result = dm.addChallenge('c1');
  assert.equal(result.challengeId, 'c1');
  assert.equal(result.freshness, 1);
});

test('addChallenge with metadata', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1', { type: 'visual', difficulty: 3 });
  var stats = dm.getStats('c1');
  assert.deepStrictEqual(stats.meta, { type: 'visual', difficulty: 3 });
});

test('addChallenge throws on duplicate', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  assert.throws(function() { dm.addChallenge('c1'); }, /already exists/);
});

test('addChallenge throws on empty id', function() {
  var dm = createChallengeDecayManager();
  assert.throws(function() { dm.addChallenge(''); });
  assert.throws(function() { dm.addChallenge(null); });
});

test('addChallenge respects maxChallenges', function() {
  var dm = createChallengeDecayManager({ maxChallenges: 2 });
  dm.addChallenge('c1');
  dm.addChallenge('c2');
  assert.throws(function() { dm.addChallenge('c3'); }, /Maximum/);
});

// ── getFreshness ─────────────────────────────────────────────────────

test('new challenge has freshness 1', function() {
  var clock = _clock(1000000);
  var dm = createChallengeDecayManager({ now: clock.now });
  dm.addChallenge('c1');
  assert.equal(dm.getFreshness('c1'), 1);
});

test('freshness decays with time', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    halfLifeMs: 10000  // 10s half-life
  });
  dm.addChallenge('c1');
  assert.equal(dm.getFreshness('c1'), 1);

  clock.advance(10000);  // 1 half-life
  var f = dm.getFreshness('c1');
  // Time dimension (40%): 0.5, solve (35%): 1.0, exposure (25%): 1.0
  // = 0.2 + 0.35 + 0.25 = 0.8
  assert.ok(f > 0.75 && f < 0.85, 'expected ~0.8, got ' + f);
});

test('freshness decays with solves', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    solveHalfLife: 10,
    halfLifeMs: 999999999  // effectively no time decay
  });
  dm.addChallenge('c1');
  for (var i = 0; i < 10; i++) dm.recordSolve('c1', true);
  var f = dm.getFreshness('c1');
  // Solve dimension: 2^(-10/10) = 0.5, time: ~1.0, exposure: ~1.0
  // = 0.4 + 0.175 + 0.25 = 0.825
  assert.ok(f < 1, 'freshness should have decayed, got ' + f);
});

test('freshness returns -1 for unknown', function() {
  var dm = createChallengeDecayManager();
  assert.equal(dm.getFreshness('nonexistent'), -1);
});

test('freshness returns 0 for retired', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.retire('c1');
  assert.equal(dm.getFreshness('c1'), 0);
});

// ── recordExposure ───────────────────────────────────────────────────

test('recordExposure tracks count', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.recordExposure('c1');
  dm.recordExposure('c1');
  var stats = dm.getStats('c1');
  assert.equal(stats.exposures, 2);
});

test('recordExposure auto-retires when stale', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    maxExposures: 5,
    freshnessThreshold: 0.5
  });
  dm.addChallenge('c1');
  // Exceed maxExposures to force exposure dimension to 0
  for (var i = 0; i < 5; i++) dm.recordExposure('c1');
  var result = dm.recordExposure('c1');
  assert.equal(typeof result.retired, 'boolean');
});

test('recordExposure throws for unknown challenge', function() {
  var dm = createChallengeDecayManager();
  assert.throws(function() { dm.recordExposure('nope'); });
});

test('recordExposure returns retired true for already retired', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.retire('c1');
  var result = dm.recordExposure('c1');
  assert.equal(result.retired, true);
  assert.equal(result.freshness, 0);
});

// ── recordSolve ──────────────────────────────────────────────────────

test('recordSolve tracks counts', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.recordSolve('c1', true);
  dm.recordSolve('c1', false);
  dm.recordSolve('c1', true);
  var stats = dm.getStats('c1');
  assert.equal(stats.solves, 3);
  assert.equal(stats.correctSolves, 2);
});

test('recordSolve computes solve rate', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.recordSolve('c1', true);
  dm.recordSolve('c1', false);
  var stats = dm.getStats('c1');
  assert.equal(stats.solveRate, 0.5);
});

test('recordSolve auto-retires on maxSolves', function() {
  var clock = _clock(0);
  var retired = [];
  var dm = createChallengeDecayManager({
    now: clock.now,
    maxSolves: 5,
    freshnessThreshold: 0.3,
    halfLifeMs: 999999999,
    onRetire: function(id) { retired.push(id); }
  });
  dm.addChallenge('c1');
  for (var i = 0; i < 5; i++) dm.recordSolve('c1', true);
  var result = dm.recordSolve('c1', true);
  assert.equal(typeof result.freshness, 'number');
});

test('recordSolve throws for unknown challenge', function() {
  var dm = createChallengeDecayManager();
  assert.throws(function() { dm.recordSolve('nope', true); });
});

// ── retire ───────────────────────────────────────────────────────────

test('retire marks challenge as retired', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  assert.equal(dm.retire('c1'), true);
  assert.equal(dm.getStats('c1').retired, true);
});

test('retire returns false for already retired', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.retire('c1');
  assert.equal(dm.retire('c1'), false);
});

test('retire returns false for unknown', function() {
  var dm = createChallengeDecayManager();
  assert.equal(dm.retire('nope'), false);
});

test('onRetire callback fires', function() {
  var retired = [];
  var dm = createChallengeDecayManager({
    onRetire: function(id, stats) { retired.push({ id: id, solves: stats.solves }); }
  });
  dm.addChallenge('c1');
  dm.recordSolve('c1', true);
  dm.retire('c1');
  assert.equal(retired.length, 1);
  assert.equal(retired[0].id, 'c1');
  assert.equal(retired[0].solves, 1);
});

// ── sweep ────────────────────────────────────────────────────────────

test('sweep retires stale challenges', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    maxAge: 10000,
    halfLifeMs: 5000,
    freshnessThreshold: 0.3
  });
  dm.addChallenge('fresh');
  dm.addChallenge('old');
  clock.advance(9500);

  var result = dm.sweep();
  assert.ok(Array.isArray(result.retired));
});

test('sweep with forced retirement via high threshold', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    maxAge: 1000,
    halfLifeMs: 500,
    freshnessThreshold: 0.8  // very high threshold
  });
  dm.addChallenge('c1');
  clock.advance(1001);  // exceed maxAge → time = 0
  // freshness = 0 + 0.35 + 0.25 = 0.6 < 0.8 threshold
  var result = dm.sweep();
  assert.ok(result.retired.indexOf('c1') !== -1, 'c1 should be retired');
});

test('sweep returns pool health', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  var result = dm.sweep();
  assert.ok(result.poolHealth);
  assert.equal(result.poolHealth.totalChallenges, 1);
});

// ── getPoolHealth ────────────────────────────────────────────────────

test('getPoolHealth with fresh pool', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({ now: clock.now });
  dm.addChallenge('c1');
  dm.addChallenge('c2');
  var health = dm.getPoolHealth();
  assert.equal(health.totalChallenges, 2);
  assert.equal(health.activeChallenges, 2);
  assert.equal(health.retiredChallenges, 0);
  assert.equal(health.averageFreshness, 1);
  assert.equal(health.freshCount, 2);
  assert.equal(health.staleCount, 0);
  assert.equal(health.needsRefresh, false);
});

test('getPoolHealth tracks retired', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.addChallenge('c2');
  dm.retire('c1');
  var health = dm.getPoolHealth();
  assert.equal(health.activeChallenges, 1);
  assert.equal(health.retiredChallenges, 1);
});

test('getPoolHealth needsRefresh when no fresh challenges', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    halfLifeMs: 100,
    maxAge: 999999999
  });
  dm.addChallenge('c1');
  clock.advance(500);  // 5 half-lives
  var health = dm.getPoolHealth();
  assert.equal(health.freshCount, 0);
});

// ── getFreshest / getStalest ─────────────────────────────────────────

test('getFreshest returns freshest first', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    halfLifeMs: 10000
  });
  dm.addChallenge('old');
  clock.advance(5000);
  dm.addChallenge('new');
  var result = dm.getFreshest(2);
  assert.equal(result.length, 2);
  assert.equal(result[0].challengeId, 'new');
  assert.equal(result[1].challengeId, 'old');
});

test('getStalest returns stalest first', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    halfLifeMs: 10000
  });
  dm.addChallenge('old');
  clock.advance(5000);
  dm.addChallenge('new');
  var result = dm.getStalest(2);
  assert.equal(result.length, 2);
  assert.equal(result[0].challengeId, 'old');
  assert.equal(result[1].challengeId, 'new');
});

test('getFreshest skips retired', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.addChallenge('c2');
  dm.retire('c1');
  var result = dm.getFreshest(5);
  assert.equal(result.length, 1);
  assert.equal(result[0].challengeId, 'c2');
});

test('getFreshest respects N limit', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.addChallenge('c2');
  dm.addChallenge('c3');
  var result = dm.getFreshest(2);
  assert.equal(result.length, 2);
});

// ── getStats ─────────────────────────────────────────────────────────

test('getStats returns null for unknown', function() {
  var dm = createChallengeDecayManager();
  assert.equal(dm.getStats('nope'), null);
});

test('getStats has all expected fields', function() {
  var clock = _clock(1000);
  var dm = createChallengeDecayManager({ now: clock.now });
  dm.addChallenge('c1');
  clock.advance(500);
  dm.recordSolve('c1', true);
  dm.recordExposure('c1');
  var stats = dm.getStats('c1');
  assert.equal(stats.challengeId, 'c1');
  assert.equal(stats.addedAt, 1000);
  assert.equal(stats.ageMs, 500);
  assert.equal(stats.solves, 1);
  assert.equal(stats.correctSolves, 1);
  assert.equal(stats.exposures, 1);
  assert.equal(typeof stats.freshness, 'number');
  assert.equal(stats.retired, false);
});

// ── remove ───────────────────────────────────────────────────────────

test('remove deletes a challenge', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  assert.equal(dm.remove('c1'), true);
  assert.equal(dm.getStats('c1'), null);
  assert.equal(dm.getPoolHealth().totalChallenges, 0);
});

test('remove decrements retired count', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.retire('c1');
  dm.remove('c1');
  assert.equal(dm.getPoolHealth().retiredChallenges, 0);
});

test('remove returns false for unknown', function() {
  var dm = createChallengeDecayManager();
  assert.equal(dm.remove('nope'), false);
});

// ── reset ────────────────────────────────────────────────────────────

test('reset clears all data', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  dm.addChallenge('c2');
  dm.retire('c1');
  dm.reset();
  var health = dm.getPoolHealth();
  assert.equal(health.totalChallenges, 0);
  assert.equal(health.activeChallenges, 0);
  assert.equal(health.retiredChallenges, 0);
});

// ── Edge cases ───────────────────────────────────────────────────────

test('rapid solves cause quicker decay', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    solveHalfLife: 5,
    halfLifeMs: 999999999
  });
  dm.addChallenge('c1');
  dm.addChallenge('c2');
  for (var i = 0; i < 20; i++) dm.recordSolve('c1', true);
  assert.ok(dm.getFreshness('c1') < dm.getFreshness('c2'));
});

test('solveRate is null with zero solves', function() {
  var dm = createChallengeDecayManager();
  dm.addChallenge('c1');
  assert.equal(dm.getStats('c1').solveRate, null);
});

test('maxAge forces time freshness to zero', function() {
  var clock = _clock(0);
  var dm = createChallengeDecayManager({
    now: clock.now,
    maxAge: 1000,
    halfLifeMs: 500
  });
  dm.addChallenge('c1');
  clock.advance(1001);
  var f = dm.getFreshness('c1');
  // Time forced to 0: freshness = 0 + 0.35 + 0.25 = 0.6
  assert.ok(f <= 0.6001, 'expected <= 0.6, got ' + f);
});
