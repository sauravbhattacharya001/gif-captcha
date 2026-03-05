/**
 * Tests for createBotDetector — honeypot and behavioral bot detection.
 */
var gifCaptcha = require('../src/index');

const { describe, test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

describe('createBotDetector', function () {
  var detector;

  beforeEach(function () {
    detector = gifCaptcha.createBotDetector();
  });

  // ── Factory & Configuration ───────────────────────────────────

  describe('factory', function () {
    test('creates with default options', function () {
      var config = detector.getConfig();
      assert.deepStrictEqual(config.honeypotFields, ['hp_email', 'hp_url', 'hp_phone']);
      assert.strictEqual(config.minTimeOnPageMs, 3000);
      assert.strictEqual(config.maxTimeOnPageMs, 600000);
      assert.strictEqual(config.minMouseMovements, 3);
      assert.strictEqual(config.minKeystrokeVariance, 10);
      assert.strictEqual(config.botThreshold, 60);
      assert.strictEqual(config.suspiciousThreshold, 40);
    });

    test('accepts custom options', function () {
      var custom = gifCaptcha.createBotDetector({
        honeypotFields: ['trap1'],
        minTimeOnPageMs: 1000,
        maxTimeOnPageMs: 120000,
        minMouseMovements: 5,
        minKeystrokeVariance: 20,
        botThreshold: 70,
        suspiciousThreshold: 50,
      });
      var config = custom.getConfig();
      assert.deepStrictEqual(config.honeypotFields, ['trap1']);
      assert.strictEqual(config.minTimeOnPageMs, 1000);
      assert.strictEqual(config.botThreshold, 70);
      assert.strictEqual(config.suspiciousThreshold, 50);
    });

    test('getHoneypotFields returns a copy', function () {
      var fields = detector.getHoneypotFields();
      fields.push('injected');
      assert.ok(!(detector.getHoneypotFields()).includes('injected'));
    });
  });

  // ── Honeypot Analysis ─────────────────────────────────────────

  describe('analyzeHoneypots', function () {
    test('clean when all honeypot fields are empty', function () {
      var result = detector.analyzeHoneypots({ hp_email: '', hp_url: '', hp_phone: '' });
      assert.strictEqual(result.clean, true);
      assert.strictEqual(result.score, 0);
      assert.deepStrictEqual(result.filled, []);
    });

    test('detects filled honeypot field', function () {
      var result = detector.analyzeHoneypots({ hp_email: 'bot@spam.com', hp_url: '', hp_phone: '' });
      assert.strictEqual(result.clean, false);
      assert.strictEqual(result.score, 100);
      assert.deepStrictEqual(result.filled, ['hp_email']);
    });

    test('detects multiple filled fields', function () {
      var result = detector.analyzeHoneypots({ hp_email: 'x', hp_url: 'y', hp_phone: '' });
      assert.deepStrictEqual(result.filled, ['hp_email', 'hp_url']);
      assert.strictEqual(result.score, 100);
    });

    test('ignores whitespace-only values', function () {
      var result = detector.analyzeHoneypots({ hp_email: '   ', hp_url: '' });
      assert.strictEqual(result.clean, true);
      assert.deepStrictEqual(result.filled, []);
    });

    test('handles null/undefined values gracefully', function () {
      var result = detector.analyzeHoneypots({ hp_email: null, hp_url: undefined });
      assert.strictEqual(result.clean, true);
    });

    test('handles missing honeypotValues object', function () {
      var result = detector.analyzeHoneypots(null);
      assert.strictEqual(result.clean, true);
      assert.strictEqual(result.score, 0);
    });

    test('ignores unknown field names', function () {
      var result = detector.analyzeHoneypots({ unknown_field: 'bot data' });
      assert.strictEqual(result.clean, true);
    });

    test('uses custom honeypot fields', function () {
      var custom = gifCaptcha.createBotDetector({ honeypotFields: ['trap'] });
      var result = custom.analyzeHoneypots({ trap: 'filled!' });
      assert.strictEqual(result.clean, false);
      assert.deepStrictEqual(result.filled, ['trap']);
    });
  });

  // ── Mouse Movement Analysis ───────────────────────────────────

  describe('analyzeMouseMovements', function () {
    test('flags no mouse data as suspicious', function () {
      var result = detector.analyzeMouseMovements([]);
      assert.ok((result.score) >= (70));
      assert.ok((result.flags).includes('no_mouse_data'));
      assert.strictEqual(result.count, 0);
    });

    test('flags null input', function () {
      var result = detector.analyzeMouseMovements(null);
      assert.ok((result.flags).includes('no_mouse_data'));
    });

    test('scores low for human-like varied movement', function () {
      // Organic mouse path with varied directions
      var movements = [
        { x: 10, y: 20, t: 100 },
        { x: 50, y: 30, t: 150 },
        { x: 45, y: 80, t: 200 },
        { x: 100, y: 60, t: 250 },
        { x: 80, y: 120, t: 300 },
        { x: 130, y: 90, t: 350 },
        { x: 120, y: 150, t: 400 },
        { x: 200, y: 100, t: 450 },
      ];
      var result = detector.analyzeMouseMovements(movements);
      assert.ok((result.score) < (40));
      assert.strictEqual(result.count, 8);
      assert.ok((result.entropy) > (1.0));
    });

    test('flags linear movement as suspicious', function () {
      // Perfectly straight diagonal line
      var movements = [];
      for (var i = 0; i < 10; i++) {
        movements.push({ x: i * 10, y: i * 10, t: i * 50 });
      }
      var result = detector.analyzeMouseMovements(movements);
      assert.strictEqual(result.isLinear, true);
      assert.ok((result.flags).includes('linear_movement'));
      assert.ok((result.score) > (20));
    });

    test('flags too few movements', function () {
      var result = detector.analyzeMouseMovements([
        { x: 10, y: 20, t: 100 },
        { x: 50, y: 80, t: 200 },
      ]);
      assert.ok((result.flags).includes('too_few_movements'));
    });

    test('flags identical timestamps', function () {
      var movements = [
        { x: 10, y: 20, t: 100 },
        { x: 50, y: 80, t: 100 },
        { x: 90, y: 30, t: 100 },
        { x: 120, y: 60, t: 100 },
      ];
      var result = detector.analyzeMouseMovements(movements);
      assert.ok((result.flags).includes('identical_timestamps'));
    });

    test('entropy is 0 for single direction', function () {
      var movements = [
        { x: 0, y: 0, t: 0 },
        { x: 10, y: 0, t: 50 },
        { x: 20, y: 0, t: 100 },
        { x: 30, y: 0, t: 150 },
      ];
      var result = detector.analyzeMouseMovements(movements);
      assert.strictEqual(result.entropy, 0);
      assert.strictEqual(result.isLinear, true);
    });

    test('score capped at 100', function () {
      // Worst case: few movements, linear, identical timestamps
      var movements = [
        { x: 0, y: 0, t: 100 },
        { x: 10, y: 10, t: 100 },
        { x: 20, y: 20, t: 100 },
      ];
      var result = detector.analyzeMouseMovements(movements);
      assert.ok((result.score) <= (100));
    });
  });

  // ── Keystroke Analysis ────────────────────────────────────────

  describe('analyzeKeystrokes', function () {
    test('flags no keystroke data', function () {
      var result = detector.analyzeKeystrokes([]);
      assert.ok((result.flags).includes('no_keystroke_data'));
      assert.strictEqual(result.count, 0);
    });

    test('scores low for human-like typing', function () {
      // Realistic typing: 60-120ms holds, 100-250ms intervals
      var keystrokes = [
        { key: 'h', downAt: 0, upAt: 80 },
        { key: 'e', downAt: 150, upAt: 220 },
        { key: 'l', downAt: 300, upAt: 370 },
        { key: 'l', downAt: 500, upAt: 580 },
        { key: 'o', downAt: 620, upAt: 700 },
      ];
      var result = detector.analyzeKeystrokes(keystrokes);
      assert.ok((result.score) < (30));
      assert.ok((result.avgHoldMs) > (50));
      assert.ok((result.intervalVariance) > (10));
    });

    test('flags impossibly fast typing', function () {
      var keystrokes = [
        { key: 'a', downAt: 0, upAt: 5 },
        { key: 'b', downAt: 10, upAt: 15 },
        { key: 'c', downAt: 20, upAt: 25 },
        { key: 'd', downAt: 30, upAt: 35 },
      ];
      var result = detector.analyzeKeystrokes(keystrokes);
      assert.ok((result.flags).includes('impossibly_fast_typing'));
      assert.ok((result.avgHoldMs) < (20));
    });

    test('flags zero hold times (scripted input)', function () {
      var keystrokes = [
        { key: 'a', downAt: 100, upAt: 100 },
        { key: 'b', downAt: 200, upAt: 200 },
        { key: 'c', downAt: 300, upAt: 300 },
      ];
      var result = detector.analyzeKeystrokes(keystrokes);
      assert.ok((result.flags).includes('zero_hold_times'));
      assert.ok((result.score) >= (35));
    });

    test('flags uniform typing rhythm', function () {
      // Perfectly even 100ms intervals
      var keystrokes = [
        { key: 'a', downAt: 0, upAt: 50 },
        { key: 'b', downAt: 100, upAt: 150 },
        { key: 'c', downAt: 200, upAt: 250 },
        { key: 'd', downAt: 300, upAt: 350 },
      ];
      var result = detector.analyzeKeystrokes(keystrokes);
      assert.ok((result.flags).includes('uniform_typing_rhythm'));
      assert.strictEqual(result.intervalVariance, 0);
    });

    test('handles single keystroke', function () {
      var result = detector.analyzeKeystrokes([{ key: 'x', downAt: 100, upAt: 200 }]);
      assert.strictEqual(result.count, 1);
      assert.strictEqual(result.avgHoldMs, 100);
      assert.strictEqual(result.intervalVariance, 0);
    });

    test('flags simulated variance with fast keys', function () {
      // Very fast typing but with artificially injected variance
      var keystrokes = [
        { key: 'a', downAt: 0, upAt: 10 },
        { key: 'b', downAt: 500, upAt: 510 },
        { key: 'c', downAt: 502, upAt: 512 },
        { key: 'd', downAt: 1500, upAt: 1510 },
      ];
      var result = detector.analyzeKeystrokes(keystrokes);
      assert.ok((result.flags).includes('simulated_variance'));
    });
  });

  // ── Timing Analysis ───────────────────────────────────────────

  describe('analyzeTiming', function () {
    test('scores low for normal page time', function () {
      var result = detector.analyzeTiming(10000, 2000);
      assert.strictEqual(result.score, 0);
      assert.deepStrictEqual(result.flags, []);
    });

    test('flags too-fast page completion', function () {
      var result = detector.analyzeTiming(1000);
      assert.ok((result.score) >= (40));
      assert.ok((result.flags).includes('too_fast'));
    });

    test('flags stale session', function () {
      var result = detector.analyzeTiming(700000);
      assert.ok((result.flags).includes('stale_session'));
    });

    test('flags instant first interaction', function () {
      var result = detector.analyzeTiming(10000, 50);
      assert.ok((result.flags).includes('instant_interaction'));
    });

    test('flags very fast first interaction', function () {
      var result = detector.analyzeTiming(10000, 300);
      assert.ok((result.flags).includes('very_fast_first_interaction'));
    });

    test('handles missing timing data', function () {
      var result = detector.analyzeTiming(0);
      assert.ok((result.flags).includes('no_timing_data'));
    });

    test('handles negative time', function () {
      var result = detector.analyzeTiming(-100);
      assert.ok((result.flags).includes('no_timing_data'));
    });

    test('handles null', function () {
      var result = detector.analyzeTiming(null);
      assert.ok((result.flags).includes('no_timing_data'));
    });

    test('custom minTimeOnPageMs is respected', function () {
      var custom = gifCaptcha.createBotDetector({ minTimeOnPageMs: 1000 });
      // 1500ms > 1000ms minimum, so no too_fast flag
      var result = custom.analyzeTiming(1500);
      assert.ok(!(result.flags).includes('too_fast'));
    });
  });

  // ── Scroll Analysis ───────────────────────────────────────────

  describe('analyzeScroll', function () {
    test('flags no scroll data (mild suspicion)', function () {
      var result = detector.analyzeScroll([]);
      assert.ok((result.flags).includes('no_scroll_data'));
      assert.strictEqual(result.score, 20);
    });

    test('scores low for normal scrolling', function () {
      var result = detector.analyzeScroll([
        { y: 0, t: 0 },
        { y: 100, t: 500 },
        { y: 250, t: 1200 },
        { y: 400, t: 2000 },
        { y: 350, t: 2800 },
      ]);
      assert.ok((result.score) < (20));
      assert.strictEqual(result.count, 5);
    });

    test('flags no actual scrolling (all same Y)', function () {
      var result = detector.analyzeScroll([
        { y: 0, t: 0 },
        { y: 0, t: 100 },
        { y: 0, t: 200 },
      ]);
      assert.ok((result.flags).includes('no_actual_scrolling'));
    });

    test('flags uniform scroll timing', function () {
      var result = detector.analyzeScroll([
        { y: 0, t: 0 },
        { y: 100, t: 100 },
        { y: 200, t: 200 },
        { y: 300, t: 300 },
        { y: 400, t: 400 },
      ]);
      assert.ok((result.flags).includes('uniform_scroll_timing'));
    });

    test('handles null', function () {
      var result = detector.analyzeScroll(null);
      assert.ok((result.flags).includes('no_scroll_data'));
    });
  });

  // ── JS Token Verification ────────────────────────────────────

  describe('JS token', function () {
    test('getJsToken returns 32-char token', function () {
      var token = detector.getJsToken();
      assert.strictEqual(typeof token, 'string');
      assert.strictEqual(token.length, 32);
    });

    test('valid token passes verification', function () {
      var token = detector.getJsToken('session1');
      var result = detector.analyze({
        jsToken: token,
        sessionId: 'session1',
        timeOnPageMs: 10000,
      });
      assert.ok(!(result.flags).includes('invalid_js_token'));
      assert.strictEqual(result.breakdown.jsVerification, 0);
    });

    test('token is one-time use', function () {
      var token = detector.getJsToken('session2');
      // First use: valid
      var r1 = detector.analyze({ jsToken: token, sessionId: 'session2', timeOnPageMs: 10000 });
      assert.strictEqual(r1.breakdown.jsVerification, 0);
      // Second use: invalid (token consumed)
      var token2 = token; // same token
      var r2 = detector.analyze({ jsToken: token2, sessionId: 'session2', timeOnPageMs: 10000 });
      assert.ok((r2.flags).includes('invalid_js_token'));
    });

    test('wrong token fails', function () {
      detector.getJsToken();
      var result = detector.analyze({ jsToken: 'wrong-token', timeOnPageMs: 10000 });
      assert.ok((result.flags).includes('invalid_js_token'));
      assert.strictEqual(result.breakdown.jsVerification, 80);
    });

    test('missing token is flagged', function () {
      var result = detector.analyze({ timeOnPageMs: 10000 });
      assert.ok((result.flags).includes('no_js_token'));
    });

    test('session-bound tokens do not cross sessions', function () {
      var token = detector.getJsToken('sessionA');
      var result = detector.analyze({ jsToken: token, sessionId: 'sessionB', timeOnPageMs: 10000 });
      assert.ok((result.flags).includes('invalid_js_token'));
    });
  });

  // ── Full Analysis ─────────────────────────────────────────────

  describe('analyze (composite)', function () {
    test('human-like signals produce low score', function () {
      var token = detector.getJsToken();
      var result = detector.analyze({
        honeypotValues: { hp_email: '', hp_url: '', hp_phone: '' },
        mouseMovements: [
          { x: 10, y: 20, t: 100 },
          { x: 50, y: 30, t: 180 },
          { x: 45, y: 80, t: 250 },
          { x: 100, y: 60, t: 340 },
          { x: 80, y: 120, t: 420 },
          { x: 130, y: 90, t: 500 },
        ],
        keystrokes: [
          { key: 'h', downAt: 1000, upAt: 1080 },
          { key: 'e', downAt: 1200, upAt: 1270 },
          { key: 'l', downAt: 1450, upAt: 1530 },
          { key: 'l', downAt: 1600, upAt: 1690 },
          { key: 'o', downAt: 1800, upAt: 1880 },
        ],
        timeOnPageMs: 15000,
        firstInteractionMs: 3000,
        jsToken: token,
        scrollEvents: [
          { y: 0, t: 0 },
          { y: 100, t: 800 },
          { y: 250, t: 1500 },
          { y: 400, t: 2300 },
        ],
      });
      assert.strictEqual(result.verdict, 'human');
      assert.strictEqual(result.isBot, false);
      assert.ok((result.score) < (40));
    });

    test('bot-like signals produce high score', function () {
      var result = detector.analyze({
        honeypotValues: { hp_email: '', hp_url: '', hp_phone: '' },
        mouseMovements: [], // no mouse at all
        keystrokes: [
          { key: 'a', downAt: 0, upAt: 0 },
          { key: 'b', downAt: 50, upAt: 50 },
          { key: 'c', downAt: 100, upAt: 100 },
          { key: 'd', downAt: 150, upAt: 150 },
        ],
        timeOnPageMs: 500, // way too fast
        firstInteractionMs: 10, // instant
      });
      assert.ok((result.score) >= (55));
      assert.notStrictEqual(result.verdict, 'human');
    });

    test('honeypot triggers instant bot verdict', function () {
      var result = detector.analyze({
        honeypotValues: { hp_email: 'spam@bot.com' },
        timeOnPageMs: 60000,
        mouseMovements: [
          { x: 10, y: 20, t: 100 },
          { x: 50, y: 80, t: 200 },
          { x: 90, y: 30, t: 300 },
          { x: 120, y: 60, t: 400 },
        ],
      });
      assert.strictEqual(result.score, 100);
      assert.strictEqual(result.isBot, true);
      assert.strictEqual(result.verdict, 'bot');
      assert.ok((result.flags).includes('honeypot_filled:hp_email'));
    });

    test('mixed signals produce intermediate score', function () {
      var result = detector.analyze({
        honeypotValues: {},
        mouseMovements: [
          { x: 0, y: 0, t: 0 },
          { x: 10, y: 10, t: 50 },
          { x: 20, y: 20, t: 100 },
        ],
        keystrokes: [
          { key: 'a', downAt: 0, upAt: 80 },
          { key: 'b', downAt: 200, upAt: 280 },
        ],
        timeOnPageMs: 10000,
      });
      // With some bot-like mouse (linear, few) but human-like timing and keys,
      // score should be between 0 and 100 (not fully human, not full bot)
      assert.ok((result.score) > (0));
      assert.ok((result.score) < (100));
    });

    test('breakdown contains all signal scores', function () {
      var result = detector.analyze({ timeOnPageMs: 10000 });
      assert.notStrictEqual((result.breakdown)["honeypot"], undefined);
      assert.notStrictEqual((result.breakdown)["mouse"], undefined);
      assert.notStrictEqual((result.breakdown)["keystrokes"], undefined);
      assert.notStrictEqual((result.breakdown)["timing"], undefined);
      assert.notStrictEqual((result.breakdown)["scroll"], undefined);
      assert.notStrictEqual((result.breakdown)["jsVerification"], undefined);
    });

    test('handles empty signals object', function () {
      var result = detector.analyze({});
      assert.strictEqual(typeof result.score, 'number');
      assert.ok((['human', 'suspicious', 'bot']).includes(result.verdict));
    });

    test('handles null signals', function () {
      var result = detector.analyze(null);
      assert.strictEqual(typeof result.score, 'number');
    });

    test('flags array includes all detected issues', function () {
      var result = detector.analyze({
        timeOnPageMs: 500,
        mouseMovements: [],
        keystrokes: [],
      });
      assert.ok((result.flags.length) > (0));
      assert.ok((result.flags).includes('no_mouse_data'));
      assert.ok((result.flags).includes('too_fast'));
    });

    test('score is rounded to 1 decimal', function () {
      var result = detector.analyze({ timeOnPageMs: 10000 });
      var decimals = (result.score.toString().split('.')[1] || '').length;
      assert.ok((decimals) <= (1));
    });
  });

  // ── Custom Thresholds ─────────────────────────────────────────

  describe('custom thresholds', function () {
    test('higher botThreshold is more lenient', function () {
      var lenient = gifCaptcha.createBotDetector({ botThreshold: 90 });
      var result = lenient.analyze({
        mouseMovements: [],
        keystrokes: [],
        timeOnPageMs: 500,
      });
      // With a 90 threshold, moderate bot signals might not trigger
      assert.ok((result.score) < (90));
      // But should still be flagged as suspicious
      assert.strictEqual(result.isSuspicious, true);
    });

    test('lower suspiciousThreshold is stricter', function () {
      var strict = gifCaptcha.createBotDetector({ suspiciousThreshold: 10 });
      var result = strict.analyze({ timeOnPageMs: 10000 });
      assert.strictEqual(result.isSuspicious, true);
    });
  });

  // ── Edge Cases ────────────────────────────────────────────────

  describe('edge cases', function () {
    test('prototype pollution safe: __proto__ as honeypot value key', function () {
      var result = detector.analyzeHoneypots({ __proto__: 'injected' });
      // Should not crash or pollute Object prototype
      assert.strictEqual(result.clean, true);
      assert.strictEqual({}.injected, undefined);
    });

    test('prototype pollution safe: constructor as honeypot value key', function () {
      var result = detector.analyzeHoneypots({ constructor: 'injected' });
      assert.strictEqual(result.clean, true);
    });

    test('very large mouse movement array', function () {
      var movements = [];
      for (var i = 0; i < 1000; i++) {
        movements.push({ x: Math.random() * 500, y: Math.random() * 500, t: i * 16 });
      }
      var result = detector.analyzeMouseMovements(movements);
      assert.strictEqual(result.count, 1000);
      assert.ok((result.entropy) > (0));
    });

    test('stationary mouse (no dx/dy)', function () {
      var movements = [
        { x: 100, y: 100, t: 0 },
        { x: 100, y: 100, t: 50 },
        { x: 100, y: 100, t: 100 },
      ];
      var result = detector.analyzeMouseMovements(movements);
      assert.strictEqual(result.entropy, 0);
    });

    test('single keystroke with large hold', function () {
      var result = detector.analyzeKeystrokes([
        { key: 'space', downAt: 0, upAt: 5000 },
      ]);
      assert.strictEqual(result.avgHoldMs, 5000);
      assert.strictEqual(result.score, 0); // single key, not suspicious
    });
  });
});
