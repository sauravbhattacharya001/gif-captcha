/**
 * Tests for createTokenVerifier - HMAC-signed CAPTCHA verification tokens.
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { createTokenVerifier } = require('../src/index');

const TEST_SECRET = 'this-is-a-test-secret-key-32chars';
const TEST_IP = '192.168.1.100';

function makeVerifier(overrides) {
  return createTokenVerifier(Object.assign({ secret: TEST_SECRET }, overrides || {}));
}

function makeToken(verifier, overrides) {
  return verifier.issueToken(Object.assign({
    sessionId: 'sess_test123',
    score: 0.85,
    difficulty: 50,
    ip: TEST_IP,
  }, overrides || {}));
}

// == Constructor validation ==

describe('createTokenVerifier - constructor', function () {
  it('throws without secret', function () {
    assert.throws(function () { createTokenVerifier({}); }, /secret/i);
  });

  it('throws with non-string secret', function () {
    assert.throws(function () { createTokenVerifier({ secret: 12345 }); }, /secret/i);
  });

  it('throws with short secret (< 16 chars)', function () {
    assert.throws(function () { createTokenVerifier({ secret: 'short' }); }, /16 characters/);
  });

  it('accepts valid 16-char secret', function () {
    const v = createTokenVerifier({ secret: '1234567890123456' });
    assert.ok(v);
    assert.ok(typeof v.issueToken === 'function');
  });

  it('creates with default options', function () {
    const v = makeVerifier();
    const stats = v.getStats();
    assert.equal(stats.tokenTtlMs, 300000);
    assert.equal(stats.maxUses, 1);
    assert.equal(stats.ipBound, true);
    assert.equal(stats.maxCapacity, 10000);
    assert.equal(stats.trackedNonces, 0);
  });

  it('accepts custom options', function () {
    const v = makeVerifier({ tokenTtlMs: 60000, maxTokenUses: 3, bindIp: false, maxUsedTokens: 500 });
    const stats = v.getStats();
    assert.equal(stats.tokenTtlMs, 60000);
    assert.equal(stats.maxUses, 3);
    assert.equal(stats.ipBound, false);
    assert.equal(stats.maxCapacity, 500);
  });
});

// == Token issuance ==

describe('createTokenVerifier - issueToken', function () {
  let verifier;

  beforeEach(function () {
    verifier = makeVerifier();
  });

  it('issues a token with correct structure', function () {
    const result = makeToken(verifier);
    assert.ok(result.token);
    assert.ok(typeof result.token === 'string');
    assert.ok(result.expiresAt > Date.now());
    const parts = result.token.split('.');
    assert.equal(parts.length, 2);
    assert.ok(parts[1].length === 64);
  });

  it('tokens have unique nonces', function () {
    const t1 = makeToken(verifier);
    const t2 = makeToken(verifier);
    assert.notEqual(t1.token, t2.token);
  });

  it('throws on missing sessionId', function () {
    assert.throws(function () {
      verifier.issueToken({ score: 0.5, difficulty: 30 });
    }, /sessionId/);
  });

  it('throws on invalid score (> 1)', function () {
    assert.throws(function () {
      verifier.issueToken({ sessionId: 's1', score: 1.5, difficulty: 30 });
    }, /score/);
  });

  it('throws on invalid score (negative)', function () {
    assert.throws(function () {
      verifier.issueToken({ sessionId: 's1', score: -0.1, difficulty: 30 });
    }, /score/);
  });

  it('throws on missing difficulty', function () {
    assert.throws(function () {
      verifier.issueToken({ sessionId: 's1', score: 0.5 });
    }, /difficulty/);
  });

  it('throws on negative difficulty', function () {
    assert.throws(function () {
      verifier.issueToken({ sessionId: 's1', score: 0.5, difficulty: -1 });
    }, /difficulty/);
  });

  it('accepts metadata in token', function () {
    const result = verifier.issueToken({
      sessionId: 's1', score: 0.9, difficulty: 40, ip: TEST_IP,
      metadata: { userId: 'u123', action: 'signup' },
    });
    const verified = verifier.verifyToken(result.token, { ip: TEST_IP });
    assert.ok(verified.valid);
    assert.equal(verified.payload.metadata.userId, 'u123');
    assert.equal(verified.payload.metadata.action, 'signup');
  });

  it('throws on metadata with > 10 keys', function () {
    const meta = {};
    for (let i = 0; i < 11; i++) meta['key' + i] = 'val';
    assert.throws(function () {
      verifier.issueToken({ sessionId: 's1', score: 0.5, difficulty: 30, metadata: meta });
    }, /10 keys/);
  });

  it('filters non-primitive metadata values', function () {
    const result = verifier.issueToken({
      sessionId: 's1', score: 0.5, difficulty: 30, ip: TEST_IP,
      metadata: { valid: 'yes', count: 42, flag: true, nested: { bad: true } },
    });
    const verified = verifier.verifyToken(result.token, { ip: TEST_IP });
    assert.ok(verified.valid);
    assert.equal(verified.payload.metadata.valid, 'yes');
    assert.equal(verified.payload.metadata.count, 42);
    assert.equal(verified.payload.metadata.flag, true);
    assert.equal(verified.payload.metadata.nested, undefined);
  });

  it('expiresAt reflects custom TTL', function () {
    const v = makeVerifier({ tokenTtlMs: 60000 });
    const before = Date.now();
    const result = makeToken(v);
    assert.ok(result.expiresAt >= before + 59000);
    assert.ok(result.expiresAt <= before + 61000);
  });
});

// == Token verification ==

describe('createTokenVerifier - verifyToken', function () {
  let verifier;

  beforeEach(function () {
    verifier = makeVerifier();
  });

  it('verifies a valid token', function () {
    const { token } = makeToken(verifier);
    const result = verifier.verifyToken(token, { ip: TEST_IP });
    assert.ok(result.valid);
    assert.equal(result.payload.sessionId, 'sess_test123');
    assert.equal(result.payload.score, 0.85);
    assert.equal(result.payload.difficulty, 50);
    assert.ok(result.payload.issuedAt > 0);
    assert.ok(result.payload.expiresAt > result.payload.issuedAt);
  });

  it('rejects missing token', function () {
    const result = verifier.verifyToken(null);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'missing_token');
  });

  it('rejects empty string', function () {
    const result = verifier.verifyToken('');
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'missing_token');
  });

  it('rejects malformed token (no dot)', function () {
    const result = verifier.verifyToken('nodottoken');
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'malformed_token');
  });

  it('rejects malformed token (too many dots)', function () {
    const result = verifier.verifyToken('a.b.c');
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'malformed_token');
  });

  it('rejects tampered signature', function () {
    const { token } = makeToken(verifier);
    const parts = token.split('.');
    const tampered = parts[0] + '.0000000000000000000000000000000000000000000000000000000000000000';
    const result = verifier.verifyToken(tampered, { ip: TEST_IP });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'invalid_signature');
  });

  it('rejects tampered payload', function () {
    const { token } = makeToken(verifier);
    const parts = token.split('.');
    const tampered = Buffer.from('{"sid":"hacked"}').toString('base64url') + '.' + parts[1];
    const result = verifier.verifyToken(tampered, { ip: TEST_IP });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'invalid_signature');
  });

  it('rejects token from different secret', function () {
    const v2 = makeVerifier({ secret: 'different-secret-key!!' });
    const { token } = makeToken(v2);
    const result = verifier.verifyToken(token, { ip: TEST_IP });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'invalid_signature');
  });

  it('rejects expired token', function () {
    const v = makeVerifier({ tokenTtlMs: 1 });
    const { token } = makeToken(v);
    const start = Date.now();
    while (Date.now() - start < 5) { /* spin */ }
    const result = v.verifyToken(token, { ip: TEST_IP });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'token_expired');
  });
});

// == IP binding ==

describe('createTokenVerifier - IP binding', function () {
  it('rejects token from different IP', function () {
    const v = makeVerifier({ bindIp: true });
    const { token } = makeToken(v, { ip: '10.0.0.1' });
    const result = v.verifyToken(token, { ip: '10.0.0.2' });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'ip_mismatch');
  });

  it('accepts token from same IP', function () {
    const v = makeVerifier({ bindIp: true });
    const { token } = makeToken(v, { ip: '10.0.0.1' });
    const result = v.verifyToken(token, { ip: '10.0.0.1' });
    assert.ok(result.valid);
  });

  it('skips IP check when bindIp is false', function () {
    const v = makeVerifier({ bindIp: false });
    const { token } = makeToken(v, { ip: '10.0.0.1' });
    const result = v.verifyToken(token, { ip: '99.99.99.99' });
    assert.ok(result.valid);
  });

  it('handles missing IP gracefully (no IP in issue or verify)', function () {
    const v = makeVerifier({ bindIp: true });
    const { token } = v.issueToken({ sessionId: 's1', score: 0.5, difficulty: 30 });
    // No IP on either side - ipHash is 'none' which skips check
    const result = v.verifyToken(token);
    assert.ok(result.valid);
  });
});

// == Replay protection ==

describe('createTokenVerifier - replay protection', function () {
  it('rejects token on second use (maxTokenUses=1)', function () {
    const v = makeVerifier({ maxTokenUses: 1 });
    const { token } = makeToken(v);
    const r1 = v.verifyToken(token, { ip: TEST_IP });
    assert.ok(r1.valid);
    const r2 = v.verifyToken(token, { ip: TEST_IP });
    assert.equal(r2.valid, false);
    assert.equal(r2.reason, 'token_already_used');
  });

  it('allows multiple uses when maxTokenUses > 1', function () {
    const v = makeVerifier({ maxTokenUses: 3 });
    const { token } = makeToken(v);
    assert.ok(v.verifyToken(token, { ip: TEST_IP }).valid);
    assert.ok(v.verifyToken(token, { ip: TEST_IP }).valid);
    assert.ok(v.verifyToken(token, { ip: TEST_IP }).valid);
    const r4 = v.verifyToken(token, { ip: TEST_IP });
    assert.equal(r4.valid, false);
    assert.equal(r4.reason, 'token_already_used');
  });

  it('allows unlimited uses when maxTokenUses=0', function () {
    const v = makeVerifier({ maxTokenUses: 0 });
    const { token } = makeToken(v);
    for (let i = 0; i < 10; i++) {
      assert.ok(v.verifyToken(token, { ip: TEST_IP }).valid);
    }
  });

  it('evicts oldest nonces when capacity exceeded', function () {
    const v = makeVerifier({ maxUsedTokens: 2 });
    const tokens = [];
    // Issue and verify 3 tokens (capacity is 2)
    for (let i = 0; i < 3; i++) {
      const t = v.issueToken({ sessionId: 's' + i, score: 0.5, difficulty: 30, ip: TEST_IP });
      tokens.push(t.token);
      v.verifyToken(t.token, { ip: TEST_IP }); // consume nonce
    }
    // token[0] nonce evicted, so re-verify should succeed
    const r0 = v.verifyToken(tokens[0], { ip: TEST_IP });
    assert.ok(r0.valid, 'evicted nonce should allow re-verification');
    // token[2] nonce still tracked, re-verify should fail
    const r2 = v.verifyToken(tokens[2], { ip: TEST_IP });
    assert.equal(r2.valid, false);
    assert.equal(r2.reason, 'token_already_used');
  });

  it('clearUsedTokens resets all nonces', function () {
    const v = makeVerifier();
    const { token } = makeToken(v);
    v.verifyToken(token, { ip: TEST_IP });
    assert.equal(v.getStats().trackedNonces, 1);
    v.clearUsedTokens();
    assert.equal(v.getStats().trackedNonces, 0);
    assert.ok(v.verifyToken(token, { ip: TEST_IP }).valid);
  });
});

// == issueFromSession ==

describe('createTokenVerifier - issueFromSession', function () {
  let verifier;

  beforeEach(function () {
    verifier = makeVerifier();
  });

  it('issues token from passed session result', function () {
    const sessionResult = { done: true, passed: true, passRate: 0.833, correctCount: 5, totalAnswered: 6, nextDifficulty: 60 };
    const result = verifier.issueFromSession(sessionResult, 'sess_abc', { ip: TEST_IP });
    assert.ok(result);
    assert.ok(result.token);
    const verified = verifier.verifyToken(result.token, { ip: TEST_IP });
    assert.ok(verified.valid);
    assert.equal(verified.payload.sessionId, 'sess_abc');
    assert.equal(verified.payload.score, 0.833);
    assert.equal(verified.payload.difficulty, 60);
  });

  it('returns null for failed session', function () {
    const result = verifier.issueFromSession({ done: true, passed: false }, 'sess_fail');
    assert.equal(result, null);
  });

  it('returns null for incomplete session', function () {
    const result = verifier.issueFromSession({ done: false, passed: null }, 'sess_inc');
    assert.equal(result, null);
  });

  it('returns null for null input', function () {
    const result = verifier.issueFromSession(null, 'sess_null');
    assert.equal(result, null);
  });

  it('calculates score from correctCount when passRate missing', function () {
    const sessionResult = { done: true, passed: true, correctCount: 3, totalAnswered: 4, nextDifficulty: 45 };
    const result = verifier.issueFromSession(sessionResult, 'sess_calc', { ip: TEST_IP });
    assert.ok(result);
    const verified = verifier.verifyToken(result.token, { ip: TEST_IP });
    assert.ok(verified.valid);
    assert.equal(verified.payload.score, 0.75);
  });

  it('passes metadata through', function () {
    const result = verifier.issueFromSession(
      { done: true, passed: true, passRate: 1.0, correctCount: 3, totalAnswered: 3, nextDifficulty: 30 },
      'sess_meta',
      { ip: TEST_IP, metadata: { page: '/signup' } }
    );
    const verified = verifier.verifyToken(result.token, { ip: TEST_IP });
    assert.equal(verified.payload.metadata.page, '/signup');
  });
});

// == getStats ==

describe('createTokenVerifier - getStats', function () {
  it('tracks nonce count correctly', function () {
    const v = makeVerifier();
    assert.equal(v.getStats().trackedNonces, 0);
    const t1 = makeToken(v);
    v.verifyToken(t1.token, { ip: TEST_IP });
    assert.equal(v.getStats().trackedNonces, 1);
    const t2 = makeToken(v);
    v.verifyToken(t2.token, { ip: TEST_IP });
    assert.equal(v.getStats().trackedNonces, 2);
  });

  it('does not count failed verifications', function () {
    const v = makeVerifier();
    v.verifyToken('garbage.token', {});
    assert.equal(v.getStats().trackedNonces, 0);
  });
});

// == Edge cases ==

describe('createTokenVerifier - edge cases', function () {
  it('handles score of exactly 0', function () {
    const v = makeVerifier();
    const result = v.issueToken({ sessionId: 's1', score: 0, difficulty: 10, ip: TEST_IP });
    const verified = v.verifyToken(result.token, { ip: TEST_IP });
    assert.ok(verified.valid);
    assert.equal(verified.payload.score, 0);
  });

  it('handles score of exactly 1', function () {
    const v = makeVerifier();
    const result = v.issueToken({ sessionId: 's1', score: 1, difficulty: 100, ip: TEST_IP });
    const verified = v.verifyToken(result.token, { ip: TEST_IP });
    assert.ok(verified.valid);
    assert.equal(verified.payload.score, 1);
  });

  it('handles difficulty of 0', function () {
    const v = makeVerifier();
    const result = v.issueToken({ sessionId: 's1', score: 0.5, difficulty: 0, ip: TEST_IP });
    const verified = v.verifyToken(result.token, { ip: TEST_IP });
    assert.ok(verified.valid);
    assert.equal(verified.payload.difficulty, 0);
  });

  it('preserves empty metadata as empty object', function () {
    const v = makeVerifier();
    const result = v.issueToken({ sessionId: 's1', score: 0.5, difficulty: 30, ip: TEST_IP, metadata: {} });
    const verified = v.verifyToken(result.token, { ip: TEST_IP });
    assert.ok(verified.valid);
    assert.deepEqual(verified.payload.metadata, {});
  });

  it('no metadata yields empty object in payload', function () {
    const v = makeVerifier();
    const result = v.issueToken({ sessionId: 's1', score: 0.5, difficulty: 30, ip: TEST_IP });
    const verified = v.verifyToken(result.token, { ip: TEST_IP });
    assert.ok(verified.valid);
    assert.deepEqual(verified.payload.metadata, {});
  });

  it('non-number token type returns missing_token', function () {
    const v = makeVerifier();
    assert.equal(v.verifyToken(42).valid, false);
    assert.equal(v.verifyToken(42).reason, 'missing_token');
  });
});
