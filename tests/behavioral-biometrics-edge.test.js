'use strict';

var { describe, it } = require('node:test');
var assert = require('node:assert/strict');
var { createBehavioralBiometrics } = require('../src/behavioral-biometrics');

describe('behavioral-biometrics edge cases', function () {

  describe('mouse analysis with degenerate data', function () {

    it('handles identical consecutive points (zero distance)', function () {
      var bb = createBehavioralBiometrics({ minMouseEvents: 3 });
      // All points at same location — speed/angle/curvature all zero
      for (var i = 0; i < 10; i++) {
        bb.recordMouseMove(100, 100, 1000 + i * 50);
      }
      var result = bb.analyzeMouseMovement();
      assert.equal(result.sufficient, true);
      // Bot-like: no speed variation, no angle variation
      assert.ok(result.score < 0.3, 'identical points should score low (bot-like)');
    });

    it('handles zero dt between events gracefully', function () {
      var bb = createBehavioralBiometrics({ minMouseEvents: 3 });
      // Same timestamp for all events — dt=0 means no speed samples
      bb.recordMouseMove(0, 0, 1000);
      bb.recordMouseMove(10, 10, 1000);
      bb.recordMouseMove(20, 20, 1000);
      bb.recordMouseMove(30, 30, 1000);
      bb.recordMouseMove(40, 40, 1000);
      var result = bb.analyzeMouseMovement();
      // Should not throw; dt<=0 is skipped, so no speeds → insufficient
      assert.equal(result.sufficient, false);
      assert.equal(result.score, 0);
    });

    it('handles single-axis movement (perfectly straight line)', function () {
      var bb = createBehavioralBiometrics({ minMouseEvents: 3 });
      for (var i = 0; i < 10; i++) {
        bb.recordMouseMove(i * 10, 0, 1000 + i * 100);
      }
      var result = bb.analyzeMouseMovement();
      assert.equal(result.sufficient, true);
      // Straight line: low angle entropy, low curvature
      assert.ok(result.metrics.angleEntropy < 0.5, 'straight line should have low angle entropy');
    });

    it('minMouseEvents boundary: exactly at minimum', function () {
      var bb = createBehavioralBiometrics({ minMouseEvents: 5 });
      for (var i = 0; i < 5; i++) {
        bb.recordMouseMove(i * 20, i * 15 + Math.sin(i) * 10, 1000 + i * 100);
      }
      var result = bb.analyzeMouseMovement();
      assert.equal(result.sufficient, true);
      assert.equal(result.eventCount, 5);
    });

    it('minMouseEvents boundary: one below minimum', function () {
      var bb = createBehavioralBiometrics({ minMouseEvents: 5 });
      for (var i = 0; i < 4; i++) {
        bb.recordMouseMove(i * 20, i * 15, 1000 + i * 100);
      }
      var result = bb.analyzeMouseMovement();
      assert.equal(result.sufficient, false);
      assert.equal(result.score, 0);
    });
  });

  describe('click analysis edge cases', function () {

    it('all clicks at same position scores as bot-like', function () {
      var bb = createBehavioralBiometrics({ minClickEvents: 2 });
      for (var i = 0; i < 5; i++) {
        bb.recordClick(100, 200, 'left', 1000 + i * 500);
      }
      var result = bb.analyzeClicks();
      assert.equal(result.sufficient, true);
      // High duplicate ratio should lower the score
      assert.ok(result.metrics.duplicateRatio > 0.5, 'same-position clicks should have high duplicate ratio');
    });

    it('perfectly regular click intervals score lower', function () {
      var bb = createBehavioralBiometrics({ minClickEvents: 2 });
      for (var i = 0; i < 10; i++) {
        bb.recordClick(i * 30, i * 20, 'left', 1000 + i * 500);  // exactly 500ms apart
      }
      var result = bb.analyzeClicks();
      assert.equal(result.sufficient, true);
      // Perfect intervals → low CV → low intervalScore component
      assert.ok(result.metrics.intervalCV < 0.1, 'regular intervals should have near-zero CV');
    });

    it('clicks are capped at maxEvents', function () {
      var bb = createBehavioralBiometrics({ maxEvents: 5, minClickEvents: 2 });
      for (var i = 0; i < 20; i++) {
        bb.recordClick(i, i, 'left', 1000 + i * 100);
      }
      assert.equal(bb.getEventCounts().clicks, 5);
    });
  });

  describe('keystroke analysis edge cases', function () {

    it('out-of-human-range durations score lower', function () {
      var bb = createBehavioralBiometrics({ collectKeystrokes: true, minKeystrokeEvents: 3 });
      // Very short durations (1ms) — below human range
      bb.recordKeystroke(1, 1000);
      bb.recordKeystroke(1, 1100);
      bb.recordKeystroke(1, 1200);
      bb.recordKeystroke(1, 1300);
      var result = bb.analyzeKeystrokes();
      assert.equal(result.sufficient, true);
      assert.ok(result.metrics.humanRangeRatio < 0.5, 'sub-30ms durations should be flagged as non-human');
    });

    it('all-human-range durations get high rangeScore', function () {
      var bb = createBehavioralBiometrics({ collectKeystrokes: true, minKeystrokeEvents: 3 });
      var durations = [80, 120, 150, 90, 200, 100];
      for (var i = 0; i < durations.length; i++) {
        bb.recordKeystroke(durations[i], 1000 + i * 300);
      }
      var result = bb.analyzeKeystrokes();
      assert.equal(result.metrics.humanRangeRatio, 1);
    });
  });

  describe('scroll analysis edge cases', function () {

    it('all same-direction scrolls get lower direction score', function () {
      var bb = createBehavioralBiometrics();
      for (var i = 0; i < 10; i++) {
        bb.recordScroll(100, 1000 + i * 200);  // always positive deltaY
      }
      var result = bb.analyzeScrolls();
      assert.equal(result.sufficient, true);
      assert.equal(result.metrics.directionChanges, 0);
    });

    it('alternating scroll direction scores higher', function () {
      var bb = createBehavioralBiometrics();
      for (var i = 0; i < 10; i++) {
        bb.recordScroll(i % 2 === 0 ? 100 : -100, 1000 + i * 200);
      }
      var result = bb.analyzeScrolls();
      assert.ok(result.metrics.directionChanges >= 5);
      assert.ok(result.score > 0.3, 'direction changes should increase score');
    });

    it('exactly 2 scroll events is sufficient', function () {
      var bb = createBehavioralBiometrics();
      bb.recordScroll(50, 1000);
      bb.recordScroll(-30, 1200);
      var result = bb.analyzeScrolls();
      assert.equal(result.sufficient, true);
      assert.equal(result.eventCount, 2);
    });
  });

  describe('combined analyze edge cases', function () {

    it('mixed sufficient/insufficient signals normalize weights', function () {
      var bb = createBehavioralBiometrics({ minMouseEvents: 5, minClickEvents: 100 });
      // Add enough mouse events, not enough clicks
      for (var i = 0; i < 10; i++) {
        bb.recordMouseMove(i * 20 + Math.random() * 10, i * 15 + Math.random() * 10, 1000 + i * 100);
      }
      bb.recordClick(10, 20, 'left', 1000);  // only 1 click, need 100
      var result = bb.analyze();
      assert.equal(result.signals.mouse.sufficient, true);
      assert.equal(result.signals.clicks.sufficient, false);
      assert.equal(result.signalCount, 1);  // only mouse counted
      assert.ok(result.score > 0, 'should have non-zero score from mouse alone');
    });

    it('exportEvents returns copies not references', function () {
      var bb = createBehavioralBiometrics();
      bb.recordMouseMove(1, 2, 1000);
      var exported = bb.exportEvents();
      exported.mouse.push({ x: 99, y: 99, t: 9999 });
      assert.equal(bb.getEventCounts().mouse, 1, 'modifying export should not affect internal state');
    });
  });

  describe('getRiskLevel thresholds', function () {

    it('high human score returns low risk', function () {
      var bb = createBehavioralBiometrics({ humanScoreThreshold: 0.3, minMouseEvents: 3, minClickEvents: 2 });
      // Simulate human-like varied mouse movements
      var points = [
        [0, 0], [15, 22], [45, 18], [60, 55], [30, 70],
        [80, 40], [95, 85], [50, 100], [120, 60], [10, 90]
      ];
      for (var i = 0; i < points.length; i++) {
        bb.recordMouseMove(points[i][0], points[i][1], 1000 + i * 150);
      }
      bb.recordClick(15, 22, 'left', 1200);
      bb.recordClick(60, 55, 'left', 1800);
      bb.recordClick(95, 85, 'left', 2900);
      var risk = bb.getRiskLevel();
      assert.ok(['low', 'medium'].includes(risk.risk), 'human-like patterns should not be high risk');
    });
  });
});
