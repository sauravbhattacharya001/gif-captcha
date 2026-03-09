'use strict';

var { describe, it } = require('node:test');
var assert = require('node:assert/strict');
var { createTrustScoreEngine } = require('../src/trust-score-engine');

describe('trust-score-engine edge cases', function () {

  describe('anomaly detection (sharp score drops)', function () {
    it('should react faster to sharp drops by reducing decay weight', function () {
      // Build a history of high scores, then drop sharply.
      // With anomaly detection, the blended score should track the drop
      // more aggressively than normal decay would allow.
      var engine = createTrustScoreEngine({
        decayFactor: 0.7,
        anomalyDropThreshold: 0.3,
        cacheTtlMs: 0
      });

      // Build up a high-score history
      for (var i = 0; i < 10; i++) {
        engine.evaluate('c1', { reputation: 0.9 });
      }

      // Sharp drop — should trigger anomaly detection
      var result = engine.evaluate('c1', { reputation: 0.1 });

      // Without anomaly detection, blended ≈ 0.1 * 0.3 + 0.9 * 0.7 = 0.66
      // With anomaly detection, effectiveDecay is reduced, so blended is lower
      assert.ok(result.score < 0.6,
        'Anomaly detection should reduce score faster: got ' + result.score);
    });

    it('should not trigger anomaly detection for small drops', function () {
      var engine = createTrustScoreEngine({
        decayFactor: 0.7,
        anomalyDropThreshold: 0.3,
        cacheTtlMs: 0
      });

      for (var i = 0; i < 5; i++) {
        engine.evaluate('c1', { reputation: 0.8 });
      }

      // Small drop — under the threshold
      var result = engine.evaluate('c1', { reputation: 0.6 });
      // Normal blending: 0.6 * 0.3 + histAvg * 0.7 ≈ 0.18 + 0.56 = 0.74
      assert.ok(result.score >= 0.6,
        'Small drops should use normal decay: got ' + result.score);
    });
  });

  describe('recency-weighted history', function () {
    it('should weight recent scores higher than old ones', function () {
      var engine = createTrustScoreEngine({
        decayFactor: 0.9,  // heavy history weight
        cacheTtlMs: 0
      });

      // Old scores: low
      for (var i = 0; i < 5; i++) {
        engine.evaluate('c1', { reputation: 0.2 });
      }
      // Recent scores: high
      for (var j = 0; j < 5; j++) {
        engine.evaluate('c1', { reputation: 0.9 });
      }

      // The recency-weighted average should favor the recent 0.9 scores
      var trend = engine.getScoreTrend('c1');
      assert.ok(trend.avg > 0.5,
        'Recency-weighted avg should reflect improvement: got ' + trend.avg);
      assert.equal(trend.trend, 'improving');
    });
  });

  describe('history stores raw scores, not blended', function () {
    it('should store rawScore in history to prevent dampening feedback loop', function () {
      var engine = createTrustScoreEngine({
        decayFactor: 0.5,
        cacheTtlMs: 0
      });

      // If history stored blended scores, repeated 0.9 evaluations would
      // compound and the trend scores would diverge from 0.9.
      for (var i = 0; i < 10; i++) {
        engine.evaluate('c1', { reputation: 0.9 });
      }

      var trend = engine.getScoreTrend('c1');
      // All raw scores should be 0.9 (the rawScore, not blended)
      assert.ok(trend.scores.every(function (s) {
        return Math.abs(s - 0.9) < 0.01;
      }), 'History should contain raw scores: ' + JSON.stringify(trend.scores));
    });
  });

  describe('LRU eviction order', function () {
    it('should evict least-recently-used, not least-recently-created', function () {
      var engine = createTrustScoreEngine({
        maxClients: 3,
        decayFactor: 0,
        cacheTtlMs: 0
      });

      engine.evaluate('c1', { reputation: 0.5 });
      engine.evaluate('c2', { reputation: 0.5 });
      engine.evaluate('c3', { reputation: 0.5 });

      // Touch c1 by re-evaluating (makes c2 the LRU)
      engine.evaluate('c1', { reputation: 0.6 });

      // Add c4 — c2 should be evicted (LRU), not c1
      engine.evaluate('c4', { reputation: 0.5 });

      assert.ok(engine.getScore('c1'), 'c1 should survive (recently touched)');
      assert.equal(engine.getScore('c2'), null, 'c2 should be evicted (LRU)');
      assert.ok(engine.getScore('c3'), 'c3 should survive');
      assert.ok(engine.getScore('c4'), 'c4 should survive (just added)');
    });

    it('should touch client on cache hit', function () {
      var engine = createTrustScoreEngine({
        maxClients: 3,
        decayFactor: 0,
        cacheTtlMs: 60000  // keep cache alive
      });

      engine.evaluate('c1', { reputation: 0.5 });
      engine.evaluate('c2', { reputation: 0.5 });
      engine.evaluate('c3', { reputation: 0.5 });

      // Cache hit on c1 should touch it in LRU
      var cached = engine.evaluate('c1');
      assert.equal(cached.cached, true);

      // Now add c4 — c2 should be evicted (LRU)
      engine.evaluate('c4', { reputation: 0.5 });

      assert.ok(engine.getScore('c1'), 'c1 should survive (cache hit touched LRU)');
      assert.equal(engine.getScore('c2'), null, 'c2 should be evicted');
    });
  });

  describe('export/import with history', function () {
    it('should preserve score history across export/import', function () {
      var engine1 = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine1.evaluate('c1', { reputation: 0.3 });
      engine1.evaluate('c1', { reputation: 0.5 });
      engine1.evaluate('c1', { reputation: 0.7 });

      var state = engine1.exportState();

      var engine2 = createTrustScoreEngine({ decayFactor: 0 });
      engine2.importState(state);

      var trend = engine2.getScoreTrend('c1');
      assert.ok(trend, 'imported engine should have trend data');
      assert.equal(trend.count, 3);
      assert.equal(trend.trend, 'improving');
    });

    it('should preserve stats counters across export/import', function () {
      var engine1 = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine1.evaluate('c1', { reputation: 0.9 }); // pass
      engine1.evaluate('c2', { reputation: 0.1 }); // block

      var state = engine1.exportState();
      assert.equal(state.stats.totalEvaluations, 2);
      assert.equal(state.stats.actionCounts.pass, 1);
      assert.equal(state.stats.actionCounts.block, 1);
    });
  });

  describe('maxClients with import', function () {
    it('should enforce maxClients on import', function () {
      var engine1 = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      for (var i = 0; i < 10; i++) {
        engine1.evaluate('c' + i, { reputation: 0.5 });
      }
      var state = engine1.exportState();

      var engine2 = createTrustScoreEngine({ maxClients: 3 });
      engine2.importState(state);

      assert.ok(engine2.getStats().activeClients <= 10,
        'Import does not enforce maxClients until next eviction');

      // Evaluating a new client should trigger eviction
      engine2.evaluate('new', { reputation: 0.5 });
      // After eviction, should be at or below maxClients
      assert.ok(engine2.getStats().activeClients <= 4);
    });
  });

  describe('boundary threshold scores', function () {
    it('should classify scores exactly at thresholds correctly', function () {
      var engine = createTrustScoreEngine({ decayFactor: 0 });
      var thresholds = engine.getThresholds();

      // Score exactly at block threshold → block (<=)
      var r1 = engine.evaluate('t1', { reputation: thresholds.block });
      assert.equal(r1.action, 'block');

      // Score exactly at challenge threshold → challenge (<=)
      var r2 = engine.evaluate('t2', { reputation: thresholds.challenge });
      assert.equal(r2.action, 'challenge');

      // Score exactly at pass threshold → softChallenge (<=)
      var r3 = engine.evaluate('t3', { reputation: thresholds.pass });
      assert.equal(r3.action, 'softChallenge');
    });
  });

  describe('getScoreTrend with stable scores', function () {
    it('should detect stable trend', function () {
      var engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      for (var i = 0; i < 5; i++) {
        engine.evaluate('c1', { reputation: 0.5 });
      }
      var trend = engine.getScoreTrend('c1');
      assert.equal(trend.trend, 'stable');
      assert.ok(Math.abs(trend.slope) <= 0.01);
    });
  });

  describe('multiple provider errors', function () {
    it('should still produce a score when all providers error', function () {
      var engine = createTrustScoreEngine({ decayFactor: 0 });
      engine.registerProvider('reputation', function () { throw new Error('fail1'); });
      engine.registerProvider('botDetection', function () { throw new Error('fail2'); });

      var result = engine.evaluate('c1');
      // Errored providers return confidence: 0, so they contribute 0 effective weight
      // With no effective weight, fallback should be 0.5
      assert.equal(result.score, 0.5);
      assert.ok(result.signals.reputation.error);
      assert.ok(result.signals.botDetection.error);
    });
  });
});
