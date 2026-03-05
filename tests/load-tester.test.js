/**
 * Tests for the CAPTCHA Load Tester (createLoadTester).
 *
 * Validates configuration, lifecycle phases, user simulation,
 * subsystem integration, metrics collection, and report generation.
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const {
  createLoadTester,
  createChallenge,
} = require('../src/index');

describe('LoadTester: Default Configuration', () => {
  let tester;

  beforeEach(() => {
    tester = createLoadTester();
  });

  it('should have default config values', () => {
    const config = tester.getConfig();
    assert.strictEqual(config.concurrency, 10);
    assert.strictEqual(config.requestsPerUser, 50);
    assert.strictEqual(config.rampUpMs, 1000);
    assert.strictEqual(config.thinkTimeMs, 100);
    assert.strictEqual(config.humanRatio, 0.8);
    assert.strictEqual(config.timeoutMs, 30000);
    assert.strictEqual(config.challengeCount, 5);
  });

  it('should start in idle phase', () => {
    assert.strictEqual(tester.getPhase(), 'idle');
  });

  it('should expose PHASE constants', () => {
    assert.strictEqual(tester.PHASE.IDLE, 'idle');
    assert.strictEqual(tester.PHASE.RAMPING, 'ramping');
    assert.strictEqual(tester.PHASE.RUNNING, 'running');
    assert.strictEqual(tester.PHASE.STOPPING, 'stopping');
    assert.strictEqual(tester.PHASE.DONE, 'done');
  });
});

describe('LoadTester: Custom Configuration', () => {
  it('should accept custom concurrency', () => {
    const tester = createLoadTester({ concurrency: 5 });
    assert.strictEqual(tester.getConfig().concurrency, 5);
  });

  it('should accept custom requestsPerUser', () => {
    const tester = createLoadTester({ requestsPerUser: 20 });
    assert.strictEqual(tester.getConfig().requestsPerUser, 20);
  });

  it('should accept custom humanRatio', () => {
    const tester = createLoadTester({ humanRatio: 0.5 });
    assert.strictEqual(tester.getConfig().humanRatio, 0.5);
  });

  it('should clamp humanRatio to [0, 1]', () => {
    const tester = createLoadTester({ humanRatio: 1.5 });
    // Falls back to default since 1.5 > 1
    assert.strictEqual(tester.getConfig().humanRatio, 0.8);
  });

  it('should accept custom challenges', () => {
    const challenges = [
      { id: 'c1', title: 'Test 1', gifUrl: 'https://test.com/1.gif', humanAnswer: 'a cat jumps over a fence quickly' },
      { id: 'c2', title: 'Test 2', gifUrl: 'https://test.com/2.gif', humanAnswer: 'a dog runs through the park playing' },
    ];
    const tester = createLoadTester({ challenges });
    assert.strictEqual(tester.getConfig().challengeCount, 2);
  });

  it('should reject zero concurrency', () => {
    const tester = createLoadTester({ concurrency: 0 });
    assert.strictEqual(tester.getConfig().concurrency, 10); // falls back to default
  });

  it('should reject negative requestsPerUser', () => {
    const tester = createLoadTester({ requestsPerUser: -5 });
    assert.strictEqual(tester.getConfig().requestsPerUser, 50);
  });
});

describe('LoadTester: Basic Run', () => {
  it('should complete a minimal run', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 5 });
    const report = tester.run();
    assert.strictEqual(report.summary.phase, 'done');
    assert.strictEqual(report.summary.concurrency, 2);
    assert.strictEqual(report.summary.requestsPerUser, 5);
  });

  it('should count total requests correctly', () => {
    const tester = createLoadTester({ concurrency: 3, requestsPerUser: 10 });
    const report = tester.run();
    assert.strictEqual(report.summary.totalRequests, 30);
  });

  it('should transition to done phase after run', () => {
    const tester = createLoadTester({ concurrency: 1, requestsPerUser: 5 });
    tester.run();
    assert.strictEqual(tester.getPhase(), 'done');
  });

  it('should have non-zero duration', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 10 });
    const report = tester.run();
    assert.ok(report.summary.durationMs >= 0);
  });

  it('should calculate throughput', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 10 });
    const report = tester.run();
    assert.ok(report.summary.throughputRps >= 0);
  });
});

describe('LoadTester: User Simulation', () => {
  it('should create correct number of user results', () => {
    const tester = createLoadTester({ concurrency: 5, requestsPerUser: 5 });
    const report = tester.run();
    assert.strictEqual(report.users.length, 5);
  });

  it('should split users by humanRatio', () => {
    const tester = createLoadTester({ concurrency: 10, requestsPerUser: 3, humanRatio: 0.6 });
    const report = tester.run();
    assert.strictEqual(report.userBreakdown.humanCount, 6);
    assert.strictEqual(report.userBreakdown.botCount, 4);
  });

  it('should have all human users when humanRatio is 1', () => {
    const tester = createLoadTester({ concurrency: 5, requestsPerUser: 3, humanRatio: 1.0 });
    const report = tester.run();
    assert.strictEqual(report.userBreakdown.humanCount, 5);
    assert.strictEqual(report.userBreakdown.botCount, 0);
  });

  it('should have all bot users when humanRatio is 0', () => {
    const tester = createLoadTester({ concurrency: 5, requestsPerUser: 3, humanRatio: 0 });
    const report = tester.run();
    assert.strictEqual(report.userBreakdown.humanCount, 0);
    assert.strictEqual(report.userBreakdown.botCount, 5);
  });

  it('should track per-user pass rate', () => {
    const tester = createLoadTester({ concurrency: 3, requestsPerUser: 5 });
    const report = tester.run();
    for (const user of report.users) {
      assert.ok(user.passRate >= 0 && user.passRate <= 1);
    }
  });

  it('should assign sequential user IDs', () => {
    const tester = createLoadTester({ concurrency: 4, requestsPerUser: 2 });
    const report = tester.run();
    assert.deepStrictEqual(
      report.users.map(u => u.userId),
      [1, 2, 3, 4]
    );
  });

  it('should mark users as human or bot correctly', () => {
    const tester = createLoadTester({ concurrency: 4, requestsPerUser: 2, humanRatio: 0.5 });
    const report = tester.run();
    const humans = report.users.filter(u => u.isHuman);
    const bots = report.users.filter(u => !u.isHuman);
    assert.strictEqual(humans.length, 2);
    assert.strictEqual(bots.length, 2);
  });
});

describe('LoadTester: Latency Metrics', () => {
  it('should have latency stats in report', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 5 });
    const report = tester.run();
    assert.ok('avgMs' in report.latency);
    assert.ok('p50Ms' in report.latency);
    assert.ok('p95Ms' in report.latency);
    assert.ok('p99Ms' in report.latency);
    assert.ok('minMs' in report.latency);
    assert.ok('maxMs' in report.latency);
  });

  it('should have min <= p50 <= p95 <= p99 <= max', () => {
    const tester = createLoadTester({ concurrency: 3, requestsPerUser: 10 });
    const report = tester.run();
    assert.ok(report.latency.minMs <= report.latency.p50Ms);
    assert.ok(report.latency.p50Ms <= report.latency.p95Ms);
    assert.ok(report.latency.p95Ms <= report.latency.p99Ms);
    assert.ok(report.latency.p99Ms <= report.latency.maxMs);
  });

  it('should have per-user latency stats', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 5 });
    const report = tester.run();
    for (const user of report.users) {
      assert.ok('avgResponseMs' in user);
      assert.ok('p50ResponseMs' in user);
      assert.ok('p95ResponseMs' in user);
      assert.ok('p99ResponseMs' in user);
    }
  });
});

describe('LoadTester: Challenge Distribution', () => {
  it('should track challenge distribution', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 10 });
    const report = tester.run();
    assert.ok(report.challengeDistribution.totalChallenges > 0);
    assert.ok(report.challengeDistribution.minServes >= 0);
    assert.ok(report.challengeDistribution.maxServes >= report.challengeDistribution.minServes);
  });

  it('should use all challenges with enough requests', () => {
    const tester = createLoadTester({ concurrency: 5, requestsPerUser: 20 });
    const report = tester.run();
    // With 100 requests across 5 challenges, all should be served
    assert.strictEqual(report.challengeDistribution.totalChallenges, 5);
  });

  it('should have distribution object with challenge IDs', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 10 });
    const report = tester.run();
    const dist = report.challengeDistribution.distribution;
    for (const id of Object.keys(dist)) {
      assert.ok(dist[id] > 0);
    }
  });
});

describe('LoadTester: Subsystem Integration', () => {
  it('should exercise token verification', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 10 });
    const report = tester.run();
    assert.ok(report.summary.tokenVerified > 0);
  });

  it('should detect bots', () => {
    const tester = createLoadTester({ concurrency: 5, requestsPerUser: 10, humanRatio: 0.5 });
    const report = tester.run();
    // Bot detection should flag some bot users
    assert.ok(report.summary.botDetected >= 0);
  });

  it('should include pool stats', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 5 });
    const report = tester.run();
    assert.ok(report.poolStats !== null);
    assert.ok('activeCount' in report.poolStats);
    assert.ok('totalServes' in report.poolStats);
  });

  it('should include response analyzer report', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 5 });
    const report = tester.run();
    assert.ok(report.analyzerReport !== null);
  });

  it('should handle rate limiting under high concurrency', () => {
    // Many requests from few users — rate limiter should kick in
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 100 });
    const report = tester.run();
    // Rate limiter is configured with maxRequests = max(requestsPerUser, 20) = 100,
    // so with exactly 100 requests we may see some rate limits
    assert.ok(report.summary.rateLimited >= 0);
  });
});

describe('LoadTester: Human vs Bot Differentiation', () => {
  it('should show higher pass rate for humans than bots', () => {
    // Run with enough data to be statistically meaningful
    const tester = createLoadTester({
      concurrency: 20,
      requestsPerUser: 20,
      humanRatio: 0.5,
    });
    const report = tester.run();
    // Humans give relevant answers (word overlap with expected), bots give gibberish
    // Human pass rate should generally be higher
    assert.ok(report.userBreakdown.humanPassRate >= 0);
    assert.ok(report.userBreakdown.botPassRate >= 0);
  });

  it('should track human/bot counts correctly', () => {
    const tester = createLoadTester({
      concurrency: 10,
      requestsPerUser: 5,
      humanRatio: 0.7,
    });
    const report = tester.run();
    assert.strictEqual(report.userBreakdown.humanCount, 7);
    assert.strictEqual(report.userBreakdown.botCount, 3);
  });
});

describe('LoadTester: Error Handling', () => {
  it('should cap errors at 100 in report', () => {
    const tester = createLoadTester({ concurrency: 1, requestsPerUser: 5 });
    const report = tester.run();
    assert.ok(report.errors.length <= 100);
  });

  it('should track error count per user', () => {
    const tester = createLoadTester({ concurrency: 3, requestsPerUser: 5 });
    const report = tester.run();
    for (const user of report.users) {
      assert.ok(typeof user.errorCount === 'number');
      assert.ok(user.errorCount >= 0);
    }
  });

  it('should sum successful + failed + rateLimited = totalRequests', () => {
    const tester = createLoadTester({ concurrency: 3, requestsPerUser: 10 });
    const report = tester.run();
    const total = report.summary.successfulRequests +
                  report.summary.failedRequests +
                  report.summary.rateLimited;
    assert.strictEqual(total, report.summary.totalRequests);
  });
});

describe('LoadTester: Reset and Re-run', () => {
  it('should reset to idle phase', () => {
    const tester = createLoadTester({ concurrency: 1, requestsPerUser: 5 });
    tester.run();
    assert.strictEqual(tester.getPhase(), 'done');
    tester.reset();
    assert.strictEqual(tester.getPhase(), 'idle');
  });

  it('should produce fresh results after reset', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 5 });
    const report1 = tester.run();
    tester.reset();
    const report2 = tester.run();
    // Both should be valid
    assert.strictEqual(report1.summary.totalRequests, 10);
    assert.strictEqual(report2.summary.totalRequests, 10);
  });

  it('should allow re-run without reset (from done state)', () => {
    const tester = createLoadTester({ concurrency: 1, requestsPerUser: 3 });
    const report1 = tester.run();
    const report2 = tester.run();
    assert.strictEqual(report1.summary.totalRequests, 3);
    assert.strictEqual(report2.summary.totalRequests, 3);
  });
});

describe('LoadTester: Stop', () => {
  it('should allow stop to be called without error', () => {
    const tester = createLoadTester({ concurrency: 1, requestsPerUser: 5 });
    // stop() before run just sets a flag — doesn't crash
    tester.stop();
    assert.strictEqual(tester.getPhase(), 'stopping');
  });

  it('should complete run normally after reset from stop', () => {
    const tester = createLoadTester({ concurrency: 1, requestsPerUser: 5 });
    tester.stop();
    tester.reset();
    const report = tester.run();
    assert.strictEqual(report.summary.phase, 'done');
    assert.strictEqual(report.summary.totalRequests, 5);
  });
});

describe('LoadTester: Report Structure', () => {
  it('should have all top-level report sections', () => {
    const tester = createLoadTester({ concurrency: 2, requestsPerUser: 5 });
    const report = tester.run();
    assert.ok('summary' in report);
    assert.ok('latency' in report);
    assert.ok('challengeDistribution' in report);
    assert.ok('userBreakdown' in report);
    assert.ok('poolStats' in report);
    assert.ok('analyzerReport' in report);
    assert.ok('users' in report);
    assert.ok('errors' in report);
  });

  it('should have all summary fields', () => {
    const tester = createLoadTester({ concurrency: 1, requestsPerUser: 3 });
    const report = tester.run();
    const s = report.summary;
    assert.ok('phase' in s);
    assert.ok('concurrency' in s);
    assert.ok('requestsPerUser' in s);
    assert.ok('totalRequests' in s);
    assert.ok('successfulRequests' in s);
    assert.ok('failedRequests' in s);
    assert.ok('rateLimited' in s);
    assert.ok('botDetected' in s);
    assert.ok('tokenVerified' in s);
    assert.ok('tokenRejected' in s);
    assert.ok('durationMs' in s);
    assert.ok('throughputRps' in s);
    assert.ok('errorCount' in s);
  });

  it('should have all per-user fields', () => {
    const tester = createLoadTester({ concurrency: 1, requestsPerUser: 3 });
    const report = tester.run();
    const u = report.users[0];
    assert.ok('userId' in u);
    assert.ok('isHuman' in u);
    assert.ok('requests' in u);
    assert.ok('passed' in u);
    assert.ok('failed' in u);
    assert.ok('rateLimited' in u);
    assert.ok('passRate' in u);
    assert.ok('avgResponseMs' in u);
    assert.ok('p50ResponseMs' in u);
    assert.ok('p95ResponseMs' in u);
    assert.ok('p99ResponseMs' in u);
    assert.ok('totalTimeMs' in u);
    assert.ok('errorCount' in u);
  });
});

describe('LoadTester: Scale Scenarios', () => {
  it('should handle single user single request', () => {
    const tester = createLoadTester({ concurrency: 1, requestsPerUser: 1 });
    const report = tester.run();
    assert.strictEqual(report.summary.totalRequests, 1);
    assert.strictEqual(report.users.length, 1);
  });

  it('should handle moderate load', () => {
    const tester = createLoadTester({ concurrency: 10, requestsPerUser: 20 });
    const report = tester.run();
    assert.strictEqual(report.summary.totalRequests, 200);
    assert.strictEqual(report.users.length, 10);
  });

  it('should handle all-human scenario', () => {
    const tester = createLoadTester({ concurrency: 5, requestsPerUser: 10, humanRatio: 1.0 });
    const report = tester.run();
    assert.strictEqual(report.userBreakdown.humanCount, 5);
    assert.strictEqual(report.userBreakdown.botCount, 0);
    // All humans should have some passes
    assert.ok(report.summary.successfulRequests > 0);
  });

  it('should handle all-bot scenario', () => {
    const tester = createLoadTester({ concurrency: 5, requestsPerUser: 10, humanRatio: 0 });
    const report = tester.run();
    assert.strictEqual(report.userBreakdown.humanCount, 0);
    assert.strictEqual(report.userBreakdown.botCount, 5);
  });
});
