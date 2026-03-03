/**
 * Tests for createBotDetector — honeypot and behavioral bot detection.
 */
var gifCaptcha = require('../src/index');

describe('createBotDetector', function () {
  var detector;

  beforeEach(function () {
    detector = gifCaptcha.createBotDetector();
  });

  // ── Factory & Configuration ───────────────────────────────────

  describe('factory', function () {
    test('creates with default options', function () {
      var config = detector.getConfig();
      expect(config.honeypotFields).toEqual(['hp_email', 'hp_url', 'hp_phone']);
      expect(config.minTimeOnPageMs).toBe(3000);
      expect(config.maxTimeOnPageMs).toBe(600000);
      expect(config.minMouseMovements).toBe(3);
      expect(config.minKeystrokeVariance).toBe(10);
      expect(config.botThreshold).toBe(60);
      expect(config.suspiciousThreshold).toBe(40);
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
      expect(config.honeypotFields).toEqual(['trap1']);
      expect(config.minTimeOnPageMs).toBe(1000);
      expect(config.botThreshold).toBe(70);
      expect(config.suspiciousThreshold).toBe(50);
    });

    test('getHoneypotFields returns a copy', function () {
      var fields = detector.getHoneypotFields();
      fields.push('injected');
      expect(detector.getHoneypotFields()).not.toContain('injected');
    });
  });

  // ── Honeypot Analysis ─────────────────────────────────────────

  describe('analyzeHoneypots', function () {
    test('clean when all honeypot fields are empty', function () {
      var result = detector.analyzeHoneypots({ hp_email: '', hp_url: '', hp_phone: '' });
      expect(result.clean).toBe(true);
      expect(result.score).toBe(0);
      expect(result.filled).toEqual([]);
    });

    test('detects filled honeypot field', function () {
      var result = detector.analyzeHoneypots({ hp_email: 'bot@spam.com', hp_url: '', hp_phone: '' });
      expect(result.clean).toBe(false);
      expect(result.score).toBe(100);
      expect(result.filled).toEqual(['hp_email']);
    });

    test('detects multiple filled fields', function () {
      var result = detector.analyzeHoneypots({ hp_email: 'x', hp_url: 'y', hp_phone: '' });
      expect(result.filled).toEqual(['hp_email', 'hp_url']);
      expect(result.score).toBe(100);
    });

    test('ignores whitespace-only values', function () {
      var result = detector.analyzeHoneypots({ hp_email: '   ', hp_url: '' });
      expect(result.clean).toBe(true);
      expect(result.filled).toEqual([]);
    });

    test('handles null/undefined values gracefully', function () {
      var result = detector.analyzeHoneypots({ hp_email: null, hp_url: undefined });
      expect(result.clean).toBe(true);
    });

    test('handles missing honeypotValues object', function () {
      var result = detector.analyzeHoneypots(null);
      expect(result.clean).toBe(true);
      expect(result.score).toBe(0);
    });

    test('ignores unknown field names', function () {
      var result = detector.analyzeHoneypots({ unknown_field: 'bot data' });
      expect(result.clean).toBe(true);
    });

    test('uses custom honeypot fields', function () {
      var custom = gifCaptcha.createBotDetector({ honeypotFields: ['trap'] });
      var result = custom.analyzeHoneypots({ trap: 'filled!' });
      expect(result.clean).toBe(false);
      expect(result.filled).toEqual(['trap']);
    });
  });

  // ── Mouse Movement Analysis ───────────────────────────────────

  describe('analyzeMouseMovements', function () {
    test('flags no mouse data as suspicious', function () {
      var result = detector.analyzeMouseMovements([]);
      expect(result.score).toBeGreaterThanOrEqual(70);
      expect(result.flags).toContain('no_mouse_data');
      expect(result.count).toBe(0);
    });

    test('flags null input', function () {
      var result = detector.analyzeMouseMovements(null);
      expect(result.flags).toContain('no_mouse_data');
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
      expect(result.score).toBeLessThan(40);
      expect(result.count).toBe(8);
      expect(result.entropy).toBeGreaterThan(1.0);
    });

    test('flags linear movement as suspicious', function () {
      // Perfectly straight diagonal line
      var movements = [];
      for (var i = 0; i < 10; i++) {
        movements.push({ x: i * 10, y: i * 10, t: i * 50 });
      }
      var result = detector.analyzeMouseMovements(movements);
      expect(result.isLinear).toBe(true);
      expect(result.flags).toContain('linear_movement');
      expect(result.score).toBeGreaterThan(20);
    });

    test('flags too few movements', function () {
      var result = detector.analyzeMouseMovements([
        { x: 10, y: 20, t: 100 },
        { x: 50, y: 80, t: 200 },
      ]);
      expect(result.flags).toContain('too_few_movements');
    });

    test('flags identical timestamps', function () {
      var movements = [
        { x: 10, y: 20, t: 100 },
        { x: 50, y: 80, t: 100 },
        { x: 90, y: 30, t: 100 },
        { x: 120, y: 60, t: 100 },
      ];
      var result = detector.analyzeMouseMovements(movements);
      expect(result.flags).toContain('identical_timestamps');
    });

    test('entropy is 0 for single direction', function () {
      var movements = [
        { x: 0, y: 0, t: 0 },
        { x: 10, y: 0, t: 50 },
        { x: 20, y: 0, t: 100 },
        { x: 30, y: 0, t: 150 },
      ];
      var result = detector.analyzeMouseMovements(movements);
      expect(result.entropy).toBe(0);
      expect(result.isLinear).toBe(true);
    });

    test('score capped at 100', function () {
      // Worst case: few movements, linear, identical timestamps
      var movements = [
        { x: 0, y: 0, t: 100 },
        { x: 10, y: 10, t: 100 },
        { x: 20, y: 20, t: 100 },
      ];
      var result = detector.analyzeMouseMovements(movements);
      expect(result.score).toBeLessThanOrEqual(100);
    });
  });

  // ── Keystroke Analysis ────────────────────────────────────────

  describe('analyzeKeystrokes', function () {
    test('flags no keystroke data', function () {
      var result = detector.analyzeKeystrokes([]);
      expect(result.flags).toContain('no_keystroke_data');
      expect(result.count).toBe(0);
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
      expect(result.score).toBeLessThan(30);
      expect(result.avgHoldMs).toBeGreaterThan(50);
      expect(result.intervalVariance).toBeGreaterThan(10);
    });

    test('flags impossibly fast typing', function () {
      var keystrokes = [
        { key: 'a', downAt: 0, upAt: 5 },
        { key: 'b', downAt: 10, upAt: 15 },
        { key: 'c', downAt: 20, upAt: 25 },
        { key: 'd', downAt: 30, upAt: 35 },
      ];
      var result = detector.analyzeKeystrokes(keystrokes);
      expect(result.flags).toContain('impossibly_fast_typing');
      expect(result.avgHoldMs).toBeLessThan(20);
    });

    test('flags zero hold times (scripted input)', function () {
      var keystrokes = [
        { key: 'a', downAt: 100, upAt: 100 },
        { key: 'b', downAt: 200, upAt: 200 },
        { key: 'c', downAt: 300, upAt: 300 },
      ];
      var result = detector.analyzeKeystrokes(keystrokes);
      expect(result.flags).toContain('zero_hold_times');
      expect(result.score).toBeGreaterThanOrEqual(35);
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
      expect(result.flags).toContain('uniform_typing_rhythm');
      expect(result.intervalVariance).toBe(0);
    });

    test('handles single keystroke', function () {
      var result = detector.analyzeKeystrokes([{ key: 'x', downAt: 100, upAt: 200 }]);
      expect(result.count).toBe(1);
      expect(result.avgHoldMs).toBe(100);
      expect(result.intervalVariance).toBe(0);
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
      expect(result.flags).toContain('simulated_variance');
    });
  });

  // ── Timing Analysis ───────────────────────────────────────────

  describe('analyzeTiming', function () {
    test('scores low for normal page time', function () {
      var result = detector.analyzeTiming(10000, 2000);
      expect(result.score).toBe(0);
      expect(result.flags).toEqual([]);
    });

    test('flags too-fast page completion', function () {
      var result = detector.analyzeTiming(1000);
      expect(result.score).toBeGreaterThanOrEqual(40);
      expect(result.flags).toContain('too_fast');
    });

    test('flags stale session', function () {
      var result = detector.analyzeTiming(700000);
      expect(result.flags).toContain('stale_session');
    });

    test('flags instant first interaction', function () {
      var result = detector.analyzeTiming(10000, 50);
      expect(result.flags).toContain('instant_interaction');
    });

    test('flags very fast first interaction', function () {
      var result = detector.analyzeTiming(10000, 300);
      expect(result.flags).toContain('very_fast_first_interaction');
    });

    test('handles missing timing data', function () {
      var result = detector.analyzeTiming(0);
      expect(result.flags).toContain('no_timing_data');
    });

    test('handles negative time', function () {
      var result = detector.analyzeTiming(-100);
      expect(result.flags).toContain('no_timing_data');
    });

    test('handles null', function () {
      var result = detector.analyzeTiming(null);
      expect(result.flags).toContain('no_timing_data');
    });

    test('custom minTimeOnPageMs is respected', function () {
      var custom = gifCaptcha.createBotDetector({ minTimeOnPageMs: 1000 });
      // 1500ms > 1000ms minimum, so no too_fast flag
      var result = custom.analyzeTiming(1500);
      expect(result.flags).not.toContain('too_fast');
    });
  });

  // ── Scroll Analysis ───────────────────────────────────────────

  describe('analyzeScroll', function () {
    test('flags no scroll data (mild suspicion)', function () {
      var result = detector.analyzeScroll([]);
      expect(result.flags).toContain('no_scroll_data');
      expect(result.score).toBe(20);
    });

    test('scores low for normal scrolling', function () {
      var result = detector.analyzeScroll([
        { y: 0, t: 0 },
        { y: 100, t: 500 },
        { y: 250, t: 1200 },
        { y: 400, t: 2000 },
        { y: 350, t: 2800 },
      ]);
      expect(result.score).toBeLessThan(20);
      expect(result.count).toBe(5);
    });

    test('flags no actual scrolling (all same Y)', function () {
      var result = detector.analyzeScroll([
        { y: 0, t: 0 },
        { y: 0, t: 100 },
        { y: 0, t: 200 },
      ]);
      expect(result.flags).toContain('no_actual_scrolling');
    });

    test('flags uniform scroll timing', function () {
      var result = detector.analyzeScroll([
        { y: 0, t: 0 },
        { y: 100, t: 100 },
        { y: 200, t: 200 },
        { y: 300, t: 300 },
        { y: 400, t: 400 },
      ]);
      expect(result.flags).toContain('uniform_scroll_timing');
    });

    test('handles null', function () {
      var result = detector.analyzeScroll(null);
      expect(result.flags).toContain('no_scroll_data');
    });
  });

  // ── JS Token Verification ────────────────────────────────────

  describe('JS token', function () {
    test('getJsToken returns 32-char token', function () {
      var token = detector.getJsToken();
      expect(typeof token).toBe('string');
      expect(token.length).toBe(32);
    });

    test('valid token passes verification', function () {
      var token = detector.getJsToken('session1');
      var result = detector.analyze({
        jsToken: token,
        sessionId: 'session1',
        timeOnPageMs: 10000,
      });
      expect(result.flags).not.toContain('invalid_js_token');
      expect(result.breakdown.jsVerification).toBe(0);
    });

    test('token is one-time use', function () {
      var token = detector.getJsToken('session2');
      // First use: valid
      var r1 = detector.analyze({ jsToken: token, sessionId: 'session2', timeOnPageMs: 10000 });
      expect(r1.breakdown.jsVerification).toBe(0);
      // Second use: invalid (token consumed)
      var token2 = token; // same token
      var r2 = detector.analyze({ jsToken: token2, sessionId: 'session2', timeOnPageMs: 10000 });
      expect(r2.flags).toContain('invalid_js_token');
    });

    test('wrong token fails', function () {
      detector.getJsToken();
      var result = detector.analyze({ jsToken: 'wrong-token', timeOnPageMs: 10000 });
      expect(result.flags).toContain('invalid_js_token');
      expect(result.breakdown.jsVerification).toBe(80);
    });

    test('missing token is flagged', function () {
      var result = detector.analyze({ timeOnPageMs: 10000 });
      expect(result.flags).toContain('no_js_token');
    });

    test('session-bound tokens do not cross sessions', function () {
      var token = detector.getJsToken('sessionA');
      var result = detector.analyze({ jsToken: token, sessionId: 'sessionB', timeOnPageMs: 10000 });
      expect(result.flags).toContain('invalid_js_token');
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
      expect(result.verdict).toBe('human');
      expect(result.isBot).toBe(false);
      expect(result.score).toBeLessThan(40);
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
      expect(result.score).toBeGreaterThanOrEqual(55);
      expect(result.verdict).not.toBe('human');
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
      expect(result.score).toBe(100);
      expect(result.isBot).toBe(true);
      expect(result.verdict).toBe('bot');
      expect(result.flags).toContain('honeypot_filled:hp_email');
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
      expect(result.score).toBeGreaterThan(0);
      expect(result.score).toBeLessThan(100);
    });

    test('breakdown contains all signal scores', function () {
      var result = detector.analyze({ timeOnPageMs: 10000 });
      expect(result.breakdown).toHaveProperty('honeypot');
      expect(result.breakdown).toHaveProperty('mouse');
      expect(result.breakdown).toHaveProperty('keystrokes');
      expect(result.breakdown).toHaveProperty('timing');
      expect(result.breakdown).toHaveProperty('scroll');
      expect(result.breakdown).toHaveProperty('jsVerification');
    });

    test('handles empty signals object', function () {
      var result = detector.analyze({});
      expect(typeof result.score).toBe('number');
      expect(['human', 'suspicious', 'bot']).toContain(result.verdict);
    });

    test('handles null signals', function () {
      var result = detector.analyze(null);
      expect(typeof result.score).toBe('number');
    });

    test('flags array includes all detected issues', function () {
      var result = detector.analyze({
        timeOnPageMs: 500,
        mouseMovements: [],
        keystrokes: [],
      });
      expect(result.flags.length).toBeGreaterThan(0);
      expect(result.flags).toContain('no_mouse_data');
      expect(result.flags).toContain('too_fast');
    });

    test('score is rounded to 1 decimal', function () {
      var result = detector.analyze({ timeOnPageMs: 10000 });
      var decimals = (result.score.toString().split('.')[1] || '').length;
      expect(decimals).toBeLessThanOrEqual(1);
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
      expect(result.score).toBeLessThan(90);
      // But should still be flagged as suspicious
      expect(result.isSuspicious).toBe(true);
    });

    test('lower suspiciousThreshold is stricter', function () {
      var strict = gifCaptcha.createBotDetector({ suspiciousThreshold: 10 });
      var result = strict.analyze({ timeOnPageMs: 10000 });
      expect(result.isSuspicious).toBe(true);
    });
  });

  // ── Edge Cases ────────────────────────────────────────────────

  describe('edge cases', function () {
    test('prototype pollution safe: __proto__ as honeypot value key', function () {
      var result = detector.analyzeHoneypots({ __proto__: 'injected' });
      // Should not crash or pollute Object prototype
      expect(result.clean).toBe(true);
      expect({}.injected).toBeUndefined();
    });

    test('prototype pollution safe: constructor as honeypot value key', function () {
      var result = detector.analyzeHoneypots({ constructor: 'injected' });
      expect(result.clean).toBe(true);
    });

    test('very large mouse movement array', function () {
      var movements = [];
      for (var i = 0; i < 1000; i++) {
        movements.push({ x: Math.random() * 500, y: Math.random() * 500, t: i * 16 });
      }
      var result = detector.analyzeMouseMovements(movements);
      expect(result.count).toBe(1000);
      expect(result.entropy).toBeGreaterThan(0);
    });

    test('stationary mouse (no dx/dy)', function () {
      var movements = [
        { x: 100, y: 100, t: 0 },
        { x: 100, y: 100, t: 50 },
        { x: 100, y: 100, t: 100 },
      ];
      var result = detector.analyzeMouseMovements(movements);
      expect(result.entropy).toBe(0);
    });

    test('single keystroke with large hold', function () {
      var result = detector.analyzeKeystrokes([
        { key: 'space', downAt: 0, upAt: 5000 },
      ]);
      expect(result.avgHoldMs).toBe(5000);
      expect(result.score).toBe(0); // single key, not suspicious
    });
  });
});
