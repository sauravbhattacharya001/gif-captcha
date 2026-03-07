var { describe, it, beforeEach } = require('node:test');
var assert = require('node:assert/strict');
var { createChallengeAnalytics } = require('../src/index');

describe('createChallengeAnalytics', function () {
  var analytics;

  beforeEach(function () {
    analytics = createChallengeAnalytics({ maxChallenges: 100, maxEventsPerChallenge: 50 });
  });

  describe('record', function () {
    it('records a valid event', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 500 });
      var stats = analytics.getChallengeStats('c1');
      assert.equal(stats.totalEvents, 1);
      assert.equal(stats.correct, 1);
    });

    it('throws on missing challengeId', function () {
      assert.throws(function () {
        analytics.record({ correct: true });
      }, /challengeId/);
    });

    it('throws on missing correct when not abandoned', function () {
      assert.throws(function () {
        analytics.record({ challengeId: 'c1', timeMs: 100 });
      }, /correct/);
    });

    it('allows abandoned without correct', function () {
      analytics.record({ challengeId: 'c1', abandoned: true, timeMs: 0 });
      var stats = analytics.getChallengeStats('c1');
      assert.equal(stats.abandoned, 1);
    });

    it('evicts oldest when maxChallenges exceeded', function () {
      var small = createChallengeAnalytics({ maxChallenges: 2 });
      small.record({ challengeId: 'a', correct: true, timeMs: 100 });
      small.record({ challengeId: 'b', correct: true, timeMs: 100 });
      small.record({ challengeId: 'c', correct: true, timeMs: 100 });
      assert.equal(small.getChallengeStats('a'), null);
      assert.notEqual(small.getChallengeStats('c'), null);
    });

    it('trims events per challenge to maxEventsPerChallenge', function () {
      var small = createChallengeAnalytics({ maxEventsPerChallenge: 3 });
      for (var i = 0; i < 5; i++) {
        small.record({ challengeId: 'c1', correct: true, timeMs: i * 100 });
      }
      assert.equal(small.getChallengeStats('c1').totalEvents, 3);
    });
  });

  describe('getChallengeStats', function () {
    it('returns null for unknown challenge', function () {
      assert.equal(analytics.getChallengeStats('nope'), null);
    });

    it('computes correct solve rate', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 500 });
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 600 });
      analytics.record({ challengeId: 'c1', correct: false, timeMs: 800 });
      var stats = analytics.getChallengeStats('c1');
      assert.equal(stats.solveRate, 0.6667);
      assert.equal(stats.attempted, 3);
    });

    it('computes abandon rate correctly', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 500 });
      analytics.record({ challengeId: 'c1', abandoned: true });
      analytics.record({ challengeId: 'c1', abandoned: true });
      var stats = analytics.getChallengeStats('c1');
      assert.equal(stats.abandonRate, 0.6667);
      assert.equal(stats.abandoned, 2);
    });

    it('includes timing stats', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 300 });
      analytics.record({ challengeId: 'c1', correct: false, timeMs: 500 });
      var stats = analytics.getChallengeStats('c1');
      assert.equal(stats.timing.count, 3);
      assert.equal(stats.timing.mean, 300);
      assert.equal(stats.timing.min, 100);
      assert.equal(stats.timing.max, 500);
    });

    it('separates correct and incorrect timing', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      analytics.record({ challengeId: 'c1', correct: false, timeMs: 900 });
      var stats = analytics.getChallengeStats('c1');
      assert.equal(stats.correctTiming.mean, 100);
      assert.equal(stats.incorrectTiming.mean, 900);
    });

    it('tracks average difficulty', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100, difficulty: 3 });
      analytics.record({ challengeId: 'c1', correct: false, timeMs: 200, difficulty: 5 });
      var stats = analytics.getChallengeStats('c1');
      assert.equal(stats.avgDifficulty, 4);
    });

    it('returns null avgDifficulty when no difficulty recorded', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      assert.equal(analytics.getChallengeStats('c1').avgDifficulty, null);
    });
  });

  describe('ranking', function () {
    beforeEach(function () {
      // Easy challenge
      for (var i = 0; i < 10; i++) {
        analytics.record({ challengeId: 'easy', correct: true, timeMs: 200 });
      }
      // Hard challenge
      for (var i = 0; i < 8; i++) {
        analytics.record({ challengeId: 'hard', correct: false, timeMs: 1000 });
      }
      analytics.record({ challengeId: 'hard', correct: true, timeMs: 900 });
      analytics.record({ challengeId: 'hard', correct: true, timeMs: 800 });
      // Medium challenge
      for (var i = 0; i < 6; i++) {
        analytics.record({ challengeId: 'medium', correct: true, timeMs: 500 });
        analytics.record({ challengeId: 'medium', correct: false, timeMs: 600 });
      }
    });

    it('ranks by solveRate ascending by default', function () {
      var result = analytics.ranking();
      assert.equal(result[0].challengeId, 'hard');
      assert.equal(result[result.length - 1].challengeId, 'easy');
    });

    it('ranks descending when specified', function () {
      var result = analytics.ranking({ order: 'desc' });
      assert.equal(result[0].challengeId, 'easy');
    });

    it('respects minEvents filter', function () {
      analytics.record({ challengeId: 'tiny', correct: true, timeMs: 100 });
      var result = analytics.ranking({ minEvents: 5 });
      var ids = result.map(function (r) { return r.challengeId; });
      assert.equal(ids.indexOf('tiny'), -1);
    });

    it('respects limit', function () {
      var result = analytics.ranking({ limit: 2 });
      assert.equal(result.length, 2);
    });

    it('sorts by avgTime', function () {
      var result = analytics.ranking({ sortBy: 'avgTime', order: 'asc' });
      assert.ok(result[0].timing.mean <= result[1].timing.mean);
    });

    it('sorts by totalEvents descending', function () {
      var result = analytics.ranking({ sortBy: 'totalEvents', order: 'desc' });
      assert.ok(result[0].totalEvents >= result[1].totalEvents);
    });
  });

  describe('poolStats', function () {
    it('returns zeros when empty', function () {
      var stats = analytics.poolStats();
      assert.equal(stats.totalChallenges, 0);
      assert.equal(stats.totalEvents, 0);
      assert.equal(stats.overallSolveRate, 0);
    });

    it('aggregates across challenges', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      analytics.record({ challengeId: 'c2', correct: false, timeMs: 200 });
      var stats = analytics.poolStats();
      assert.equal(stats.totalChallenges, 2);
      assert.equal(stats.totalEvents, 2);
      assert.equal(stats.overallSolveRate, 0.5);
    });

    it('includes diversity scoring', function () {
      for (var i = 0; i < 5; i++) {
        analytics.record({ challengeId: 'c' + i, correct: i % 2 === 0, timeMs: 100 });
        analytics.record({ challengeId: 'c' + i, correct: true, timeMs: 100 });
        analytics.record({ challengeId: 'c' + i, correct: false, timeMs: 100 });
      }
      var stats = analytics.poolStats();
      assert.ok(stats.diversity);
      assert.equal(typeof stats.diversity.score, 'number');
      assert.ok(['low', 'moderate', 'high', 'insufficient data'].indexOf(stats.diversity.label) >= 0);
    });
  });

  describe('flagged', function () {
    it('flags too-easy challenges', function () {
      for (var i = 0; i < 15; i++) {
        analytics.record({ challengeId: 'trivial', correct: true, timeMs: 50 });
      }
      var flags = analytics.flagged({ tooEasy: 0.95, minEvents: 10 });
      assert.equal(flags.tooEasy.length, 1);
      assert.equal(flags.tooEasy[0].challengeId, 'trivial');
    });

    it('flags too-hard challenges', function () {
      for (var i = 0; i < 15; i++) {
        analytics.record({ challengeId: 'impossible', correct: false, timeMs: 5000 });
      }
      var flags = analytics.flagged({ tooHard: 0.15, minEvents: 10 });
      assert.equal(flags.tooHard.length, 1);
      assert.equal(flags.tooHard[0].challengeId, 'impossible');
    });

    it('flags high-abandon challenges', function () {
      for (var i = 0; i < 12; i++) {
        analytics.record({ challengeId: 'confusing', abandoned: true });
      }
      for (var j = 0; j < 3; j++) {
        analytics.record({ challengeId: 'confusing', correct: true, timeMs: 500 });
      }
      var flags = analytics.flagged({ highAbandon: 0.4, minEvents: 10 });
      assert.equal(flags.highAbandon.length, 1);
    });

    it('skips challenges below minEvents', function () {
      analytics.record({ challengeId: 'new', correct: true, timeMs: 100 });
      var flags = analytics.flagged({ minEvents: 10 });
      assert.equal(flags.tooEasy.length, 0);
      assert.equal(flags.tooHard.length, 0);
    });

    it('uses custom thresholds', function () {
      for (var i = 0; i < 10; i++) {
        analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      }
      var flags = analytics.flagged({ tooEasy: 0.8, minEvents: 5 });
      assert.equal(flags.tooEasy.length, 1);
    });
  });

  describe('difficultyEffectiveness', function () {
    it('returns empty when no difficulty data', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      assert.equal(analytics.difficultyEffectiveness().length, 0);
    });

    it('groups by difficulty level', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100, difficulty: 1 });
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 200, difficulty: 1 });
      analytics.record({ challengeId: 'c1', correct: false, timeMs: 500, difficulty: 5 });
      analytics.record({ challengeId: 'c1', correct: false, timeMs: 600, difficulty: 5 });
      var result = analytics.difficultyEffectiveness();
      assert.equal(result.length, 2);
      assert.equal(result[0].difficulty, 1);
      assert.equal(result[0].solveRate, 1);
      assert.equal(result[1].difficulty, 5);
      assert.equal(result[1].solveRate, 0);
    });

    it('excludes abandoned events', function () {
      analytics.record({ challengeId: 'c1', abandoned: true, difficulty: 3 });
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100, difficulty: 3 });
      var result = analytics.difficultyEffectiveness();
      assert.equal(result[0].count, 1);
    });

    it('is sorted by difficulty ascending', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100, difficulty: 5 });
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100, difficulty: 1 });
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100, difficulty: 3 });
      var result = analytics.difficultyEffectiveness();
      assert.ok(result[0].difficulty < result[1].difficulty);
      assert.ok(result[1].difficulty < result[2].difficulty);
    });
  });

  describe('hourlyPatterns', function () {
    it('returns 24 hourly buckets', function () {
      var result = analytics.hourlyPatterns();
      assert.equal(result.length, 24);
      assert.equal(result[0].hour, 0);
      assert.equal(result[23].hour, 23);
    });

    it('counts events in the correct hour', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      var result = analytics.hourlyPatterns();
      var currentHour = new Date().getHours();
      assert.equal(result[currentHour].count, 1);
      assert.equal(result[currentHour].solveRate, 1);
    });
  });

  describe('exportState / importState', function () {
    it('round-trips state correctly', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      analytics.record({ challengeId: 'c2', correct: false, timeMs: 500 });
      var state = analytics.exportState();
      assert.equal(state.version, 1);

      analytics.reset();
      assert.equal(analytics.getChallengeStats('c1'), null);

      analytics.importState(state);
      var stats = analytics.getChallengeStats('c1');
      assert.equal(stats.totalEvents, 1);
      assert.equal(stats.correct, 1);
    });

    it('throws on invalid state', function () {
      assert.throws(function () {
        analytics.importState(null);
      }, /Invalid state/);
    });

    it('throws on missing challenges', function () {
      assert.throws(function () {
        analytics.importState({ version: 1 });
      }, /challenges/);
    });
  });

  describe('reset', function () {
    it('clears all data', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      analytics.reset();
      assert.equal(analytics.getChallengeStats('c1'), null);
      assert.equal(analytics.poolStats().totalChallenges, 0);
    });
  });

  describe('getStats', function () {
    it('returns same as poolStats for compatibility', function () {
      analytics.record({ challengeId: 'c1', correct: true, timeMs: 100 });
      var stats = analytics.getStats();
      var pool = analytics.poolStats();
      assert.equal(stats.totalChallenges, pool.totalChallenges);
      assert.equal(stats.overallSolveRate, pool.overallSolveRate);
    });
  });
});
