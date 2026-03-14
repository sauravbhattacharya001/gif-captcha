'use strict';

var { describe, it, beforeEach } = require('node:test');
var assert = require('node:assert/strict');
var gifCaptcha = require('../src/index');
var createTrustScoreEngine = gifCaptcha.createTrustScoreEngine;

describe('createTrustScoreEngine', function () {

  var engine;

  beforeEach(function () {
    engine = createTrustScoreEngine();
  });

  describe('initialization', function () {
    it('should create an engine with default settings', function () {
      assert.ok(engine);
      assert.equal(typeof engine.evaluate, 'function');
      assert.equal(typeof engine.registerProvider, 'function');
      var stats = engine.getStats();
      assert.equal(stats.totalEvaluations, 0);
      assert.equal(stats.activeClients, 0);
    });

    it('should accept custom weights', function () {
      var e = createTrustScoreEngine({ weights: { reputation: 3, botDetection: 2 } });
      var w = e.getWeights();
      assert.equal(w.reputation, 3);
      assert.equal(w.botDetection, 2);
    });

    it('should accept custom thresholds', function () {
      var e = createTrustScoreEngine({ thresholds: { block: 0.1, challenge: 0.4, pass: 0.8 } });
      var t = e.getThresholds();
      assert.equal(t.block, 0.1);
      assert.equal(t.challenge, 0.4);
      assert.equal(t.pass, 0.8);
    });

    it('should allow custom signal names in weights', function () {
      var e = createTrustScoreEngine({ weights: { customSignal: 5 } });
      var w = e.getWeights();
      assert.equal(w.customSignal, 5);
    });
  });

  describe('registerProvider / unregisterProvider', function () {
    it('should register a provider and use it during evaluation', function () {
      engine.registerProvider('reputation', function () {
        return { score: 0.9, confidence: 1, detail: 'good rep' };
      });
      var result = engine.evaluate('client1');
      assert.ok(result.signals.reputation);
      assert.equal(result.signals.reputation.score, 0.9);
    });

    it('should ignore invalid provider registrations', function () {
      engine.registerProvider('', function () { return { score: 1 }; });
      engine.registerProvider('test', 'not a function');
      var result = engine.evaluate('client1');
      assert.equal(Object.keys(result.signals).length, 0);
    });

    it('should unregister a provider', function () {
      engine.registerProvider('test', function () { return { score: 1 }; });
      engine.unregisterProvider('test');
      var result = engine.evaluate('client1');
      assert.equal(result.signals.test, undefined);
    });
  });

  describe('evaluate', function () {
    it('should return 0.5 when no signals are available', function () {
      var result = engine.evaluate('client1');
      assert.equal(result.score, 0.5);
      assert.equal(result.action, 'challenge');
      assert.equal(result.cached, false);
    });

    it('should return error for invalid clientId', function () {
      var result = engine.evaluate('');
      assert.equal(result.score, 0);
      assert.equal(result.action, 'block');
      assert.ok(result.error);
    });

    it('should compute weighted average from multiple providers', function () {
      engine = createTrustScoreEngine({
        weights: { a: 1, b: 1 },
        decayFactor: 0 // no history blending
      });
      engine.registerProvider('a', function () { return { score: 0.8 }; });
      engine.registerProvider('b', function () { return { score: 0.6 }; });
      var result = engine.evaluate('client1');
      assert.equal(result.rawScore, 0.7);
    });

    it('should weight signals by configured weights', function () {
      engine = createTrustScoreEngine({
        weights: { a: 3, b: 1 },
        decayFactor: 0
      });
      engine.registerProvider('a', function () { return { score: 1.0 }; });
      engine.registerProvider('b', function () { return { score: 0.0 }; });
      var result = engine.evaluate('client1');
      // (1.0 * 3 + 0.0 * 1) / (3 + 1) = 0.75
      assert.equal(result.rawScore, 0.75);
    });

    it('should scale weight by confidence', function () {
      engine = createTrustScoreEngine({
        weights: { a: 1, b: 1 },
        decayFactor: 0
      });
      engine.registerProvider('a', function () { return { score: 1.0, confidence: 1.0 }; });
      engine.registerProvider('b', function () { return { score: 0.0, confidence: 0.5 }; });
      var result = engine.evaluate('client1');
      // (1.0 * 1.0 + 0.0 * 0.5) / (1.0 + 0.5) = 0.667
      assert.ok(Math.abs(result.rawScore - 0.667) < 0.01);
    });

    it('should clamp scores to 0-1 range', function () {
      engine.registerProvider('test', function () { return { score: 5.0 }; });
      var result = engine.evaluate('client1');
      assert.equal(result.signals.test.score, 1.0);
    });

    it('should handle provider errors gracefully', function () {
      engine.registerProvider('failing', function () { throw new Error('boom'); });
      var result = engine.evaluate('client1');
      assert.ok(result.signals.failing);
      assert.equal(result.signals.failing.score, 0.5);
      assert.equal(result.signals.failing.confidence, 0);
      assert.ok(result.signals.failing.error);
    });

    it('should accept manual signal overrides as numbers', function () {
      engine = createTrustScoreEngine({ decayFactor: 0 });
      var result = engine.evaluate('client1', { reputation: 0.9 });
      assert.equal(result.signals.reputation.score, 0.9);
      assert.equal(result.signals.reputation.detail, 'manual override');
    });

    it('should accept manual signal overrides as objects', function () {
      engine = createTrustScoreEngine({ decayFactor: 0 });
      var result = engine.evaluate('client1', {
        reputation: { score: 0.8, confidence: 0.7, detail: 'from API' }
      });
      assert.equal(result.signals.reputation.score, 0.8);
      assert.equal(result.signals.reputation.confidence, 0.7);
    });

    it('should override providers with manual signals', function () {
      engine = createTrustScoreEngine({ decayFactor: 0 });
      engine.registerProvider('reputation', function () { return { score: 0.1 }; });
      var result = engine.evaluate('client1', { reputation: 0.9 });
      assert.equal(result.signals.reputation.score, 0.9);
    });

    it('should include breakdown sorted by contribution', function () {
      engine = createTrustScoreEngine({
        weights: { a: 1, b: 2 },
        decayFactor: 0
      });
      engine.registerProvider('a', function () { return { score: 0.5 }; });
      engine.registerProvider('b', function () { return { score: 0.8 }; });
      var result = engine.evaluate('client1');
      assert.ok(result.breakdown.length >= 2);
      assert.equal(result.breakdown[0].signal, 'b'); // higher contribution
    });

    it('should ignore signals with zero weight', function () {
      engine = createTrustScoreEngine({
        weights: { a: 1, b: 0 },
        decayFactor: 0
      });
      engine.registerProvider('a', function () { return { score: 0.8 }; });
      engine.registerProvider('b', function () { return { score: 0.1 }; });
      var result = engine.evaluate('client1');
      assert.equal(result.rawScore, 0.8);
    });
  });

  describe('action determination', function () {
    it('should return "block" for very low scores', function () {
      engine = createTrustScoreEngine({ decayFactor: 0 });
      var result = engine.evaluate('c1', { reputation: 0.1 });
      assert.equal(result.action, 'block');
    });

    it('should return "challenge" for low-medium scores', function () {
      engine = createTrustScoreEngine({ decayFactor: 0 });
      var result = engine.evaluate('c1', { reputation: 0.4 });
      assert.equal(result.action, 'challenge');
    });

    it('should return "softChallenge" for medium scores', function () {
      engine = createTrustScoreEngine({ decayFactor: 0 });
      var result = engine.evaluate('c1', { reputation: 0.6 });
      assert.equal(result.action, 'softChallenge');
    });

    it('should return "pass" for high scores', function () {
      engine = createTrustScoreEngine({ decayFactor: 0 });
      var result = engine.evaluate('c1', { reputation: 0.9 });
      assert.equal(result.action, 'pass');
    });

    it('should use custom thresholds', function () {
      engine = createTrustScoreEngine({
        thresholds: { block: 0.1, challenge: 0.3, pass: 0.5 },
        decayFactor: 0
      });
      var result = engine.evaluate('c1', { reputation: 0.6 });
      assert.equal(result.action, 'pass');
    });
  });

  describe('caching', function () {
    it('should cache results within TTL', function () {
      engine = createTrustScoreEngine({ cacheTtlMs: 60000, decayFactor: 0 });
      engine.registerProvider('test', function () { return { score: 0.8 }; });
      engine.evaluate('c1');
      var cached = engine.evaluate('c1');
      assert.equal(cached.cached, true);
      assert.equal(cached.score, engine.evaluate('c1').score);
    });

    it('should invalidate cache', function () {
      engine = createTrustScoreEngine({ cacheTtlMs: 60000, decayFactor: 0 });
      engine.registerProvider('test', function () { return { score: 0.8 }; });
      engine.evaluate('c1');
      engine.invalidate('c1');
      var result = engine.evaluate('c1');
      assert.equal(result.cached, false);
    });
  });

  describe('getScore', function () {
    it('should return null for unknown client', function () {
      assert.equal(engine.getScore('unknown'), null);
    });

    it('should return cached score info', function () {
      engine = createTrustScoreEngine({ decayFactor: 0 });
      engine.evaluate('c1', { reputation: 0.8 });
      var s = engine.getScore('c1');
      assert.equal(s.clientId, 'c1');
      assert.equal(typeof s.score, 'number');
      assert.equal(typeof s.age, 'number');
    });
  });

  describe('getScoreTrend', function () {
    it('should return null for unknown client', function () {
      assert.equal(engine.getScoreTrend('unknown'), null);
    });

    it('should return null with less than 2 history entries', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.5 });
      assert.equal(engine.getScoreTrend('c1'), null);
    });

    it('should compute trend from history', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.3 });
      engine.evaluate('c1', { reputation: 0.5 });
      engine.evaluate('c1', { reputation: 0.7 });
      var trend = engine.getScoreTrend('c1');
      assert.ok(trend);
      assert.equal(trend.trend, 'improving');
      assert.ok(trend.slope > 0);
      assert.equal(trend.count, 3);
    });

    it('should detect declining trends', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.9 });
      engine.evaluate('c1', { reputation: 0.5 });
      engine.evaluate('c1', { reputation: 0.2 });
      var trend = engine.getScoreTrend('c1');
      assert.equal(trend.trend, 'declining');
      assert.ok(trend.slope < 0);
    });

    it('should respect lastN parameter', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      for (var i = 0; i < 10; i++) {
        engine.evaluate('c1', { reputation: i * 0.1 });
      }
      var trend = engine.getScoreTrend('c1', 3);
      assert.equal(trend.count, 3);
    });
  });

  describe('clearClient', function () {
    it('should remove all data for a client', function () {
      engine.evaluate('c1', { reputation: 0.5 });
      engine.clearClient('c1');
      assert.equal(engine.getScore('c1'), null);
      assert.equal(engine.getStats().activeClients, 0);
    });
  });

  describe('setThresholds / setWeights', function () {
    it('should update thresholds dynamically', function () {
      engine.setThresholds({ block: 0.15, pass: 0.85 });
      var t = engine.getThresholds();
      assert.equal(t.block, 0.15);
      assert.equal(t.pass, 0.85);
    });

    it('should update weights dynamically', function () {
      engine.setWeights({ reputation: 5 });
      assert.equal(engine.getWeights().reputation, 5);
    });

    it('should handle null/undefined gracefully', function () {
      engine.setThresholds(null);
      engine.setWeights(undefined);
      // Should not throw
      assert.ok(true);
    });
  });

  describe('getStats', function () {
    it('should track evaluation counts', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.9 });
      engine.evaluate('c2', { reputation: 0.1 });
      var stats = engine.getStats();
      assert.equal(stats.totalEvaluations, 2);
      assert.equal(stats.activeClients, 2);
    });

    it('should track action counts', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.9 });
      engine.evaluate('c2', { reputation: 0.1 });
      var stats = engine.getStats();
      assert.equal(stats.actionCounts.pass, 1);
      assert.equal(stats.actionCounts.block, 1);
    });

    it('should compute average score', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.8 });
      engine.evaluate('c2', { reputation: 0.4 });
      var stats = engine.getStats();
      assert.ok(stats.averageScore > 0);
    });

    it('should track score buckets', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.9 }); // high
      engine.evaluate('c2', { reputation: 0.6 }); // medium
      engine.evaluate('c3', { reputation: 0.3 }); // low
      engine.evaluate('c4', { reputation: 0.1 }); // veryLow
      var stats = engine.getStats();
      assert.equal(stats.scoreBuckets.high, 1);
      assert.equal(stats.scoreBuckets.medium, 1);
      assert.equal(stats.scoreBuckets.low, 1);
      assert.equal(stats.scoreBuckets.veryLow, 1);
    });
  });

  describe('getLowScoreClients', function () {
    it('should return clients below threshold sorted by score', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.1 });
      engine.evaluate('c2', { reputation: 0.3 });
      engine.evaluate('c3', { reputation: 0.9 });
      var low = engine.getLowScoreClients(0.5);
      assert.equal(low.length, 2);
      assert.equal(low[0].clientId, 'c1');
      assert.equal(low[1].clientId, 'c2');
    });

    it('should use default threshold of 0.5', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.3 });
      var low = engine.getLowScoreClients();
      assert.equal(low.length, 1);
    });
  });

  describe('batchEvaluate', function () {
    it('should evaluate multiple clients', function () {
      engine = createTrustScoreEngine({ decayFactor: 0 });
      var results = engine.batchEvaluate(['c1', 'c2', 'c3'], { reputation: 0.7 });
      assert.equal(results.length, 3);
      assert.equal(results[0].clientId, 'c1');
    });

    it('should return empty for non-array input', function () {
      var results = engine.batchEvaluate('not array');
      assert.deepEqual(results, []);
    });
  });

  describe('compareClients', function () {
    it('should return null if client not found', function () {
      assert.equal(engine.compareClients('a', 'b'), null);
    });

    it('should compare two evaluated clients', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.9, botDetection: 0.8 });
      engine.evaluate('c2', { reputation: 0.3, botDetection: 0.5 });
      var cmp = engine.compareClients('c1', 'c2');
      assert.ok(cmp);
      assert.ok(cmp.scoreDiff > 0);
      assert.ok(cmp.signalComparison.length >= 2);
    });
  });

  describe('exportState / importState', function () {
    it('should export and import state', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.8 });
      engine.evaluate('c2', { reputation: 0.4 });
      var state = engine.exportState();
      assert.ok(state.clients.c1);
      assert.ok(state.clients.c2);

      var engine2 = createTrustScoreEngine();
      engine2.importState(state);
      var s = engine2.getScore('c1');
      assert.ok(s);
      assert.equal(s.clientId, 'c1');
    });

    it('should handle empty import gracefully', function () {
      engine.importState(null);
      engine.importState({});
      assert.equal(engine.getStats().activeClients, 0);
    });
  });

  describe('reset', function () {
    it('should clear all state', function () {
      engine = createTrustScoreEngine({ decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.5 });
      engine.evaluate('c2', { reputation: 0.5 });
      engine.reset();
      var stats = engine.getStats();
      assert.equal(stats.totalEvaluations, 0);
      assert.equal(stats.activeClients, 0);
    });
  });

  describe('LRU eviction', function () {
    it('should evict oldest clients when maxClients exceeded', function () {
      engine = createTrustScoreEngine({ maxClients: 3, decayFactor: 0, cacheTtlMs: 0 });
      engine.evaluate('c1', { reputation: 0.5 });
      engine.evaluate('c2', { reputation: 0.5 });
      engine.evaluate('c3', { reputation: 0.5 });
      engine.evaluate('c4', { reputation: 0.5 });
      assert.equal(engine.getStats().activeClients, 3);
      assert.equal(engine.getScore('c1'), null); // evicted
      assert.ok(engine.getScore('c4')); // kept
    });
  });

  describe('history blending', function () {
    it('should blend with historical average when decayFactor > 0', function () {
      engine = createTrustScoreEngine({ decayFactor: 0.5, cacheTtlMs: 0 });
      // First eval: no history, raw score used
      engine.evaluate('c1', { reputation: 0.8 });
      // Second eval: blended with history
      var result = engine.evaluate('c1', { reputation: 0.2 });
      // blended = 0.2 * 0.5 + histAvg * 0.5
      // histAvg from first entry, so blend toward first score
      assert.ok(result.score > 0.2);
      assert.ok(result.score < 0.8);
    });
  });

  describe('history limit', function () {
    it('should cap history at maxHistory', function () {
      engine = createTrustScoreEngine({ maxHistory: 5, decayFactor: 0, cacheTtlMs: 0 });
      for (var i = 0; i < 10; i++) {
        engine.evaluate('c1', { reputation: i * 0.1 });
      }
      var trend = engine.getScoreTrend('c1');
      assert.equal(trend.count, 5);
    });
  });

  describe('integration: multi-provider scenario', function () {
    it('should produce sensible scores with realistic signals', function () {
      engine = createTrustScoreEngine({
        weights: { reputation: 2, botDetection: 3, fingerprint: 1, rateLimit: 2 },
        decayFactor: 0
      });

      engine.registerProvider('reputation', function (id) {
        if (id === 'good') return { score: 0.95, confidence: 1 };
        return { score: 0.2, confidence: 0.8 };
      });
      engine.registerProvider('botDetection', function (id) {
        if (id === 'good') return { score: 0.9, confidence: 1 };
        return { score: 0.1, confidence: 0.9 };
      });
      engine.registerProvider('fingerprint', function (id) {
        if (id === 'good') return { score: 0.85, confidence: 0.7 };
        return { score: 0.3, confidence: 0.5 };
      });
      engine.registerProvider('rateLimit', function (id) {
        if (id === 'good') return { score: 1.0, confidence: 1 };
        return { score: 0.0, confidence: 1 };
      });

      var goodResult = engine.evaluate('good');
      var badResult = engine.evaluate('bad');

      assert.ok(goodResult.score > 0.8, 'Good client should have high score');
      assert.equal(goodResult.action, 'pass');
      assert.ok(badResult.score < 0.3, 'Bad client should have low score');
      assert.equal(badResult.action, 'block');

      var cmp = engine.compareClients('good', 'bad');
      assert.ok(cmp.scoreDiff > 0.5, 'Score difference should be large');
    });
  });
});
