'use strict';

var { describe, it } = require('node:test');
var assert = require('node:assert/strict');
var { secureRandom, secureRandomHex, secureRandomInt } = require('../src/crypto-utils');

describe('crypto-utils', function () {

  describe('secureRandom', function () {
    it('returns a number', function () {
      var val = secureRandom();
      assert.equal(typeof val, 'number');
    });

    it('returns values in [0, 1)', function () {
      for (var i = 0; i < 200; i++) {
        var val = secureRandom();
        assert.ok(val >= 0, 'value should be >= 0, got ' + val);
        assert.ok(val < 1, 'value should be < 1, got ' + val);
      }
    });

    it('produces varying outputs (not stuck on a single value)', function () {
      var seen = new Set();
      for (var i = 0; i < 50; i++) {
        seen.add(secureRandom());
      }
      // With 50 calls, should see at least 10 distinct values
      assert.ok(seen.size >= 10, 'expected >= 10 distinct values, got ' + seen.size);
    });
  });

  describe('secureRandomHex', function () {
    it('returns a string of the requested length', function () {
      var lengths = [1, 2, 8, 16, 32, 64];
      for (var i = 0; i < lengths.length; i++) {
        var hex = secureRandomHex(lengths[i]);
        assert.equal(typeof hex, 'string');
        assert.equal(hex.length, lengths[i], 'expected length ' + lengths[i] + ', got ' + hex.length);
      }
    });

    it('returns only valid hex characters', function () {
      for (var i = 0; i < 50; i++) {
        var hex = secureRandomHex(32);
        assert.match(hex, /^[0-9a-f]+$/, 'invalid hex: ' + hex);
      }
    });

    it('produces varying outputs', function () {
      var seen = new Set();
      for (var i = 0; i < 30; i++) {
        seen.add(secureRandomHex(16));
      }
      assert.ok(seen.size >= 15, 'expected >= 15 distinct hex strings, got ' + seen.size);
    });

    it('handles odd lengths correctly', function () {
      var hex = secureRandomHex(7);
      assert.equal(hex.length, 7);
      assert.match(hex, /^[0-9a-f]+$/);
    });

    it('handles length 0 edge case', function () {
      var hex = secureRandomHex(0);
      assert.equal(hex.length, 0);
    });
  });

  describe('secureRandomInt', function () {
    it('returns an integer', function () {
      var val = secureRandomInt(100);
      assert.equal(typeof val, 'number');
      assert.equal(val, Math.floor(val), 'should be an integer');
    });

    it('returns values in [0, exclusiveMax)', function () {
      var max = 10;
      for (var i = 0; i < 200; i++) {
        var val = secureRandomInt(max);
        assert.ok(val >= 0, 'value should be >= 0, got ' + val);
        assert.ok(val < max, 'value should be < ' + max + ', got ' + val);
      }
    });

    it('with exclusiveMax=1 always returns 0', function () {
      for (var i = 0; i < 50; i++) {
        assert.equal(secureRandomInt(1), 0);
      }
    });

    it('covers the range for small exclusiveMax', function () {
      var max = 5;
      var seen = new Set();
      for (var i = 0; i < 200; i++) {
        seen.add(secureRandomInt(max));
      }
      // With 200 samples from [0,5), should hit all 5 values
      assert.equal(seen.size, max, 'expected all ' + max + ' values, got ' + seen.size);
    });

    it('works with large exclusiveMax', function () {
      var val = secureRandomInt(1000000);
      assert.ok(val >= 0 && val < 1000000);
    });
  });

  describe('distribution quality', function () {
    it('secureRandom is roughly uniform (chi-squared sanity check)', function () {
      // Bucket 1000 samples into 10 bins, check no bin is wildly off
      var bins = new Array(10).fill(0);
      var n = 1000;
      for (var i = 0; i < n; i++) {
        var bucket = Math.floor(secureRandom() * 10);
        if (bucket >= 10) bucket = 9; // edge case for val very close to 1
        bins[bucket]++;
      }
      var expected = n / 10;
      for (var b = 0; b < bins.length; b++) {
        // Each bin should be within 50% of expected (very loose — just catches gross failures)
        assert.ok(
          bins[b] > expected * 0.5 && bins[b] < expected * 1.5,
          'bin ' + b + ' has ' + bins[b] + ' (expected ~' + expected + ')'
        );
      }
    });

    it('secureRandomInt distribution is roughly uniform', function () {
      var max = 6;
      var counts = new Array(max).fill(0);
      var n = 600;
      for (var i = 0; i < n; i++) {
        counts[secureRandomInt(max)]++;
      }
      var expected = n / max;
      for (var v = 0; v < max; v++) {
        assert.ok(
          counts[v] > expected * 0.4 && counts[v] < expected * 1.6,
          'value ' + v + ' has count ' + counts[v] + ' (expected ~' + expected + ')'
        );
      }
    });
  });
});
