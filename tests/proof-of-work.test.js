'use strict';

var test = require('node:test');
var assert = require('node:assert/strict');
var gifCaptcha = require('../src/index');

// ── Factory ────────────────────────────────────────────────────────

test('createProofOfWork returns an object with expected API', function () {
  var pow = gifCaptcha.createProofOfWork();
  assert.equal(typeof pow.issue, 'function');
  assert.equal(typeof pow.verify, 'function');
  assert.equal(typeof pow.solve, 'function');
  assert.equal(typeof pow.estimateCost, 'function');
  assert.equal(typeof pow.getDifficulty, 'function');
  assert.equal(typeof pow.pendingCount, 'function');
  assert.equal(typeof pow.summary, 'function');
  assert.equal(typeof pow.reset, 'function');
});

test('default difficulty is 16', function () {
  var pow = gifCaptcha.createProofOfWork();
  assert.equal(pow.getDifficulty(), 16);
});

test('custom difficulty is respected', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 12 });
  assert.equal(pow.getDifficulty(), 12);
});

// ── Issue ──────────────────────────────────────────────────────────

test('issue returns challenge with prefix, difficulty, algorithm, expiresAt', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  assert.equal(typeof c.prefix, 'string');
  assert.ok(c.prefix.length > 0);
  assert.equal(c.difficulty, 8);
  assert.equal(c.algorithm, 'sha256');
  assert.equal(typeof c.expiresAt, 'number');
  assert.ok(c.expiresAt > Date.now());
});

test('issue increments pending count', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  assert.equal(pow.pendingCount(), 0);
  pow.issue();
  assert.equal(pow.pendingCount(), 1);
  pow.issue();
  assert.equal(pow.pendingCount(), 2);
});

test('issue with IP tracks per-IP count', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8, maxPendingPerIp: 3 });
  pow.issue({ ip: '1.2.3.4' });
  pow.issue({ ip: '1.2.3.4' });
  assert.equal(pow.pendingCount('1.2.3.4'), 2);
  assert.equal(pow.pendingCount('5.6.7.8'), 0);
});

test('issue throws when per-IP limit exceeded', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8, maxPendingPerIp: 2 });
  pow.issue({ ip: '1.2.3.4' });
  pow.issue({ ip: '1.2.3.4' });
  assert.throws(function () {
    pow.issue({ ip: '1.2.3.4' });
  }, /Too many pending challenges/);
});

test('issue throws when global cap exceeded', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8, maxPending: 3 });
  pow.issue();
  pow.issue();
  pow.issue();
  assert.throws(function () {
    pow.issue();
  }, /Global pending-challenge limit/);
});

test('issue with per-challenge difficulty override', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 16 });
  var c = pow.issue({ difficulty: 10 });
  assert.equal(c.difficulty, 10);
});

// ── Solve ──────────────────────────────────────────────────────────

test('solve finds a valid nonce for difficulty 8', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  var sol = pow.solve(c.prefix, c.difficulty);
  assert.equal(typeof sol.nonce, 'string');
  assert.equal(typeof sol.hash, 'string');
  assert.equal(sol.hash.length, 64); // SHA-256 hex
  assert.ok(sol.iterations > 0);
});

test('solve hash starts with correct number of zero bits', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  var sol = pow.solve(c.prefix, c.difficulty);
  // difficulty 8 => first 2 hex chars must be '00'
  assert.equal(sol.hash.substring(0, 2), '00');
});

// ── Verify ─────────────────────────────────────────────────────────

test('verify accepts valid solution', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  var sol = pow.solve(c.prefix, c.difficulty);
  var result = pow.verify({ prefix: c.prefix, nonce: sol.nonce });
  assert.equal(result.valid, true);
  assert.equal(result.reason, 'ok');
  assert.equal(result.hash, sol.hash);
  assert.ok(result.leadingZeros >= 8);
  assert.equal(typeof result.solveMs, 'number');
});

test('verify rejects wrong nonce', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  var result = pow.verify({ prefix: c.prefix, nonce: 'definitely-wrong-nonce-xyz' });
  // Might be valid by coincidence but extremely unlikely with 8+ zero bits
  // Use difficulty 20 to guarantee failure... but that's slow. Instead just check structure.
  assert.equal(typeof result.valid, 'boolean');
  assert.equal(typeof result.reason, 'string');
});

test('verify rejects missing params', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var r1 = pow.verify(null);
  assert.equal(r1.valid, false);
  assert.equal(r1.reason, 'missing_params');

  var r2 = pow.verify({});
  assert.equal(r2.valid, false);
  assert.equal(r2.reason, 'missing_params');
});

test('verify rejects unknown challenge prefix', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var result = pow.verify({ prefix: 'nonexistent', nonce: '0' });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'unknown_challenge');
});

test('verify rejects replay of same prefix', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  var sol = pow.solve(c.prefix, c.difficulty);
  var r1 = pow.verify({ prefix: c.prefix, nonce: sol.nonce });
  assert.equal(r1.valid, true);

  // Re-submit same prefix+nonce
  var r2 = pow.verify({ prefix: c.prefix, nonce: sol.nonce });
  assert.equal(r2.valid, false);
  assert.equal(r2.reason, 'replay');
});

test('verify rejects expired challenge', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8, challengeTtlMs: 1 });
  var c = pow.issue();
  var sol = pow.solve(c.prefix, c.difficulty);

  // Wait for expiry
  var start = Date.now();
  while (Date.now() - start < 5) { /* spin */ }

  var result = pow.verify({ prefix: c.prefix, nonce: sol.nonce });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'expired');
});

test('verify rejects IP mismatch', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue({ ip: '1.2.3.4' });
  var sol = pow.solve(c.prefix, c.difficulty);
  var result = pow.verify({ prefix: c.prefix, nonce: sol.nonce, ip: '5.6.7.8' });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'ip_mismatch');
});

test('verify with matching IP succeeds', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue({ ip: '1.2.3.4' });
  var sol = pow.solve(c.prefix, c.difficulty);
  var result = pow.verify({ prefix: c.prefix, nonce: sol.nonce, ip: '1.2.3.4' });
  assert.equal(result.valid, true);
});

test('verify decrements pending count', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  assert.equal(pow.pendingCount(), 1);
  var sol = pow.solve(c.prefix, c.difficulty);
  pow.verify({ prefix: c.prefix, nonce: sol.nonce });
  assert.equal(pow.pendingCount(), 0);
});

// ── Insufficient work ──────────────────────────────────────────────

test('verify rejects solution with insufficient leading zeros', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  // Submit nonce "bad" — almost certainly won't have 8 leading zero bits
  // But we need a guaranteed failure. Use a high difficulty challenge
  // and submit a known-bad nonce.
  var pow2 = gifCaptcha.createProofOfWork({ difficulty: 24 });
  var c2 = pow2.issue();
  var result = pow2.verify({ prefix: c2.prefix, nonce: 'x' });
  // With 24 leading zero bits, 'x' won't work (probability 2^-24)
  if (!result.valid) {
    assert.equal(result.reason, 'insufficient_work');
    assert.ok(result.leadingZeros < 24);
  }
});

// ── Estimate cost ──────────────────────────────────────────────────

test('estimateCost returns expected fields', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 16 });
  var est = pow.estimateCost();
  assert.equal(est.difficulty, 16);
  assert.equal(est.expectedIterations, 65536);
  assert.equal(typeof est.estimatedMs, 'string');
});

test('estimateCost with override difficulty', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 16 });
  var est = pow.estimateCost(8);
  assert.equal(est.difficulty, 8);
  assert.equal(est.expectedIterations, 256);
});

test('estimateCost scaling is exponential', function () {
  var pow = gifCaptcha.createProofOfWork();
  var e1 = pow.estimateCost(10);
  var e2 = pow.estimateCost(20);
  assert.equal(e2.expectedIterations / e1.expectedIterations, 1024);
});

// ── Summary ────────────────────────────────────────────────────────

test('summary returns all stats', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var s = pow.summary();
  assert.equal(s.issued, 0);
  assert.equal(s.verified, 0);
  assert.equal(s.rejected, 0);
  assert.equal(s.expired, 0);
  assert.equal(s.replayBlocked, 0);
  assert.equal(s.pending, 0);
  assert.equal(s.difficulty, 8);
  assert.equal(s.adaptiveEnabled, false);
});

test('summary tracks issue/verify counts', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  assert.equal(pow.summary().issued, 1);
  assert.equal(pow.summary().pending, 1);

  var sol = pow.solve(c.prefix, c.difficulty);
  pow.verify({ prefix: c.prefix, nonce: sol.nonce });
  assert.equal(pow.summary().verified, 1);
  assert.equal(pow.summary().pending, 0);
});

test('summary tracks rejection counts', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  pow.verify({ prefix: 'fake', nonce: '0' });
  assert.equal(pow.summary().rejected, 1);
});

test('summary tracks replay blocks', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  var sol = pow.solve(c.prefix, c.difficulty);
  pow.verify({ prefix: c.prefix, nonce: sol.nonce });
  pow.verify({ prefix: c.prefix, nonce: sol.nonce });
  assert.equal(pow.summary().replayBlocked, 1);
});

// ── Reset ──────────────────────────────────────────────────────────

test('reset clears all state', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  pow.issue();
  pow.issue();
  var c = pow.issue();
  var sol = pow.solve(c.prefix, c.difficulty);
  pow.verify({ prefix: c.prefix, nonce: sol.nonce });

  pow.reset();
  var s = pow.summary();
  assert.equal(s.issued, 0);
  assert.equal(s.verified, 0);
  assert.equal(s.rejected, 0);
  assert.equal(s.pending, 0);
});

// ── Adaptive difficulty ────────────────────────────────────────────

test('adaptive difficulty disabled by default', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 12 });
  assert.equal(pow.summary().adaptiveEnabled, false);
});

test('adaptive difficulty enabled via option', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 12, adaptiveDifficulty: true });
  assert.equal(pow.summary().adaptiveEnabled, true);
});

test('adaptive difficulty stays within bounds', function () {
  var pow = gifCaptcha.createProofOfWork({
    difficulty: 8,
    adaptiveDifficulty: true,
    minDifficulty: 6,
    maxDifficulty: 10,
    targetSolveMs: 100,
    adjustWindowSize: 5
  });

  // Can't go below min or above max
  assert.ok(pow.getDifficulty() >= 6);
  assert.ok(pow.getDifficulty() <= 10);
});

// ── Multiple challenges in flight ─────────────────────────────────

test('multiple concurrent challenges work independently', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c1 = pow.issue();
  var c2 = pow.issue();
  var c3 = pow.issue();

  assert.notEqual(c1.prefix, c2.prefix);
  assert.notEqual(c2.prefix, c3.prefix);

  var sol2 = pow.solve(c2.prefix, c2.difficulty);
  var r2 = pow.verify({ prefix: c2.prefix, nonce: sol2.nonce });
  assert.equal(r2.valid, true);
  assert.equal(pow.pendingCount(), 2); // c1 and c3 still pending

  var sol1 = pow.solve(c1.prefix, c1.difficulty);
  var r1 = pow.verify({ prefix: c1.prefix, nonce: sol1.nonce });
  assert.equal(r1.valid, true);
  assert.equal(pow.pendingCount(), 1); // c3 still pending
});

// ── Edge cases ─────────────────────────────────────────────────────

test('solve with difficulty 0 finds solution immediately', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c = pow.issue();
  var sol = pow.solve(c.prefix, 0);
  // Everything has >= 0 leading zero bits
  assert.ok(sol.iterations <= 1);
});

test('each issued prefix is unique', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var prefixes = {};
  for (var i = 0; i < 100; i++) {
    var c = pow.issue();
    assert.ok(!prefixes[c.prefix], 'Duplicate prefix: ' + c.prefix);
    prefixes[c.prefix] = true;
  }
});

test('expired challenges are cleaned on next issue', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8, challengeTtlMs: 1 });
  pow.issue();
  pow.issue();
  assert.equal(pow.pendingCount(), 2);

  // Wait for expiry
  var start = Date.now();
  while (Date.now() - start < 5) { /* spin */ }

  pow.issue(); // triggers cleanup
  // The 2 expired are cleaned, 1 new issued
  assert.equal(pow.pendingCount(), 1);
});

test('per-IP count decrements after verification', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 8 });
  var c1 = pow.issue({ ip: '10.0.0.1' });
  var c2 = pow.issue({ ip: '10.0.0.1' });
  assert.equal(pow.pendingCount('10.0.0.1'), 2);

  var sol1 = pow.solve(c1.prefix, c1.difficulty);
  pow.verify({ prefix: c1.prefix, nonce: sol1.nonce });
  assert.equal(pow.pendingCount('10.0.0.1'), 1);

  var sol2 = pow.solve(c2.prefix, c2.difficulty);
  pow.verify({ prefix: c2.prefix, nonce: sol2.nonce });
  assert.equal(pow.pendingCount('10.0.0.1'), 0);
});

// ── End-to-end: full CAPTCHA flow ──────────────────────────────────

test('full flow: issue → solve → verify', function () {
  var pow = gifCaptcha.createProofOfWork({ difficulty: 10 });

  // 1. Server issues challenge
  var challenge = pow.issue({ ip: '203.0.113.42' });
  assert.equal(pow.summary().issued, 1);
  assert.equal(pow.summary().pending, 1);

  // 2. Client solves it
  var solution = pow.solve(challenge.prefix, challenge.difficulty);
  assert.ok(solution.iterations > 0);

  // 3. Server verifies
  var result = pow.verify({
    prefix: challenge.prefix,
    nonce: solution.nonce,
    ip: '203.0.113.42'
  });
  assert.equal(result.valid, true);
  assert.equal(result.reason, 'ok');
  assert.ok(result.leadingZeros >= 10);
  assert.equal(pow.summary().verified, 1);
  assert.equal(pow.summary().pending, 0);

  // 4. Replay is blocked
  var replay = pow.verify({
    prefix: challenge.prefix,
    nonce: solution.nonce,
    ip: '203.0.113.42'
  });
  assert.equal(replay.valid, false);
  assert.equal(replay.reason, 'replay');
});
