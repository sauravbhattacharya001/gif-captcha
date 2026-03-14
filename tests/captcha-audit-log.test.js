/**
 * Tests for captcha-audit-log.js
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { createAuditLog, VALID_EVENTS, SEVERITY } = require('../src/captcha-audit-log');

describe('createAuditLog', () => {
  let log;

  beforeEach(() => {
    log = createAuditLog();
  });

  describe('record()', () => {
    it('should record an event and return frozen entry', () => {
      const entry = log.record('captcha.generated', { challengeId: 'c1' });
      assert.equal(entry.event, 'captcha.generated');
      assert.equal(entry.data.challengeId, 'c1');
      assert.equal(entry.severity, 'info');
      assert.ok(entry.id > 0);
      assert.ok(entry.timestamp > 0);
      assert.ok(Object.isFrozen(entry));
      assert.ok(Object.isFrozen(entry.data));
    });

    it('should throw on empty event', () => {
      assert.throws(() => log.record(''), /non-empty string/);
      assert.throws(() => log.record('  '), /non-empty string/);
    });

    it('should throw on non-string event', () => {
      assert.throws(() => log.record(123), /non-empty string/);
      assert.throws(() => log.record(null), /non-empty string/);
    });

    it('should assign default severity from map', () => {
      assert.equal(log.record('captcha.failed', {}).severity, 'warn');
      assert.equal(log.record('pool.exhausted', {}).severity, 'error');
      assert.equal(log.record('captcha.served', {}).severity, 'debug');
    });

    it('should allow custom severity override', () => {
      const e = log.record('captcha.solved', {}, { severity: 'critical' });
      assert.equal(e.severity, 'critical');
    });

    it('should throw on invalid severity', () => {
      assert.throws(() => log.record('captcha.solved', {}, { severity: 'mega' }), /Invalid severity/);
    });

    it('should record actor and correlationId', () => {
      const e = log.record('config.changed', { key: 'x' }, { actor: 'admin', correlationId: 'tx-1' });
      assert.equal(e.actor, 'admin');
      assert.equal(e.correlationId, 'tx-1');
    });

    it('should accept custom timestamp via now option', () => {
      const e = log.record('captcha.solved', {}, { now: 1000 });
      assert.equal(e.timestamp, 1000);
    });

    it('should allow unknown events when strictEvents=false', () => {
      assert.doesNotThrow(() => log.record('custom.event', {}));
    });

    it('should reject unknown events when strictEvents=true', () => {
      const strict = createAuditLog({ strictEvents: true });
      assert.throws(() => strict.record('custom.event', {}), /Unknown audit event/);
    });

    it('should call onRecord callback', () => {
      const received = [];
      const log2 = createAuditLog({ onRecord: e => received.push(e) });
      log2.record('captcha.solved', {});
      assert.equal(received.length, 1);
      assert.equal(received[0].event, 'captcha.solved');
    });

    it('should not throw if onRecord callback throws', () => {
      const log2 = createAuditLog({ onRecord: () => { throw new Error('boom'); } });
      assert.doesNotThrow(() => log2.record('captcha.solved', {}));
    });

    it('should handle null data', () => {
      const e = log.record('captcha.solved', null);
      assert.deepEqual(e.data, {});
    });
  });

  describe('maxEntries enforcement', () => {
    it('should cap at maxEntries', () => {
      const small = createAuditLog({ maxEntries: 3 });
      small.record('captcha.solved', { n: 1 });
      small.record('captcha.solved', { n: 2 });
      small.record('captcha.solved', { n: 3 });
      small.record('captcha.solved', { n: 4 });
      assert.equal(small.size(), 3);
      assert.equal(small.all()[0].data.n, 2); // oldest dropped
    });
  });

  describe('retention enforcement', () => {
    it('should purge old entries on access', () => {
      const log2 = createAuditLog({ retentionMs: 5000 });
      log2.record('captcha.solved', {}, { now: Date.now() - 10000 });
      log2.record('captcha.solved', {}, { now: Date.now() });
      assert.equal(log2.size(), 1);
    });
  });

  describe('query()', () => {
    beforeEach(() => {
      log.record('captcha.generated', { challengeId: 'c1', ip: '1.1.1.1' }, { now: 1000, actor: 'sys', correlationId: 'tx1' });
      log.record('captcha.solved', { challengeId: 'c1', ip: '1.1.1.1' }, { now: 2000, actor: 'user1', correlationId: 'tx1' });
      log.record('captcha.failed', { challengeId: 'c2', ip: '2.2.2.2' }, { now: 3000, actor: 'user2', correlationId: 'tx2' });
      log.record('rate.limited', { ip: '2.2.2.2' }, { now: 4000, actor: 'sys' });
    });

    it('should return all entries with no filters', () => {
      assert.equal(log.query().length, 4);
    });

    it('should filter by event', () => {
      const r = log.query({ event: 'captcha.failed' });
      assert.equal(r.length, 1);
      assert.equal(r[0].data.challengeId, 'c2');
    });

    it('should filter by eventPrefix', () => {
      assert.equal(log.query({ eventPrefix: 'captcha.' }).length, 3);
      assert.equal(log.query({ eventPrefix: 'rate.' }).length, 1);
    });

    it('should filter by severity', () => {
      assert.equal(log.query({ severity: 'warn' }).length, 2);
    });

    it('should filter by minSeverity', () => {
      assert.equal(log.query({ minSeverity: 'warn' }).length, 2);
      assert.equal(log.query({ minSeverity: 'info' }).length, 4);
    });

    it('should filter by since', () => {
      assert.equal(log.query({ since: 3000 }).length, 2);
    });

    it('should filter by until', () => {
      assert.equal(log.query({ until: 2000 }).length, 2);
    });

    it('should filter by actor', () => {
      assert.equal(log.query({ actor: 'sys' }).length, 2);
    });

    it('should filter by correlationId', () => {
      assert.equal(log.query({ correlationId: 'tx1' }).length, 2);
    });

    it('should filter by ip', () => {
      assert.equal(log.query({ ip: '2.2.2.2' }).length, 2);
    });

    it('should filter by challengeId', () => {
      assert.equal(log.query({ challengeId: 'c1' }).length, 2);
    });

    it('should support limit', () => {
      assert.equal(log.query({ limit: 2 }).length, 2);
    });

    it('should support desc order', () => {
      const r = log.query({ order: 'desc' });
      assert.equal(r[0].timestamp, 4000);
      assert.equal(r[3].timestamp, 1000);
    });

    it('should combine multiple filters', () => {
      const r = log.query({ eventPrefix: 'captcha.', ip: '1.1.1.1' });
      assert.equal(r.length, 2);
    });
  });

  describe('stats()', () => {
    it('should return aggregate statistics', () => {
      log.record('captcha.generated', { challengeId: 'c1', ip: '1.1.1.1' }, { now: 1000, actor: 'a1' });
      log.record('captcha.solved', { challengeId: 'c1', ip: '1.1.1.1' }, { now: 2000, actor: 'a2' });
      log.record('captcha.failed', { challengeId: 'c2', ip: '2.2.2.2' }, { now: 3000 });

      const s = log.stats();
      assert.equal(s.totalEntries, 3);
      assert.equal(s.byEvent['captcha.generated'], 1);
      assert.equal(s.byEvent['captcha.solved'], 1);
      assert.equal(s.byEvent['captcha.failed'], 1);
      assert.equal(s.uniqueActors, 2);
      assert.equal(s.uniqueIps, 2);
      assert.equal(s.uniqueChallenges, 2);
      assert.equal(s.oldestTimestamp, 1000);
      assert.equal(s.newestTimestamp, 3000);
      assert.equal(s.spanMs, 2000);
    });

    it('should return zero stats for empty log', () => {
      const s = log.stats();
      assert.equal(s.totalEntries, 0);
      assert.equal(s.spanMs, 0);
    });
  });

  describe('traceChallenge()', () => {
    it('should return all entries for a challenge', () => {
      log.record('captcha.generated', { challengeId: 'c1' });
      log.record('captcha.solved', { challengeId: 'c1' });
      log.record('captcha.failed', { challengeId: 'c2' });
      assert.equal(log.traceChallenge('c1').length, 2);
    });

    it('should return empty for unknown challengeId', () => {
      assert.deepEqual(log.traceChallenge('nope'), []);
    });

    it('should return empty for falsy input', () => {
      assert.deepEqual(log.traceChallenge(''), []);
      assert.deepEqual(log.traceChallenge(null), []);
    });
  });

  describe('traceCorrelation()', () => {
    it('should return all entries with given correlationId', () => {
      log.record('captcha.generated', {}, { correlationId: 'tx1' });
      log.record('captcha.solved', {}, { correlationId: 'tx1' });
      log.record('captcha.failed', {}, { correlationId: 'tx2' });
      assert.equal(log.traceCorrelation('tx1').length, 2);
    });

    it('should return empty for falsy input', () => {
      assert.deepEqual(log.traceCorrelation(''), []);
    });
  });

  describe('exportCSV()', () => {
    it('should produce valid CSV', () => {
      log.record('captcha.solved', { challengeId: 'c1' }, { now: 1000, actor: 'u1' });
      const csv = log.exportCSV();
      const lines = csv.split('\n');
      assert.equal(lines[0], 'id,timestamp,event,severity,actor,correlationId,data');
      assert.ok(lines[1].includes('captcha.solved'));
      assert.ok(lines[1].includes('u1'));
    });

    it('should accept filters', () => {
      log.record('captcha.solved', {});
      log.record('captcha.failed', {});
      const csv = log.exportCSV({ event: 'captcha.solved' });
      assert.equal(csv.split('\n').length, 2); // header + 1 row
    });

    it('should escape commas and quotes in CSV', () => {
      log.record('captcha.solved', { note: 'a,b' }, { actor: 'has"quote' });
      const csv = log.exportCSV();
      assert.ok(csv.includes('"a,b"') || csv.includes('has""quote'));
    });
  });

  describe('exportJSON()', () => {
    it('should produce valid JSON', () => {
      log.record('captcha.solved', { challengeId: 'c1' });
      const json = log.exportJSON();
      const parsed = JSON.parse(json);
      assert.ok(Array.isArray(parsed));
      assert.equal(parsed.length, 1);
      assert.equal(parsed[0].event, 'captcha.solved');
    });

    it('should accept filters', () => {
      log.record('captcha.solved', {});
      log.record('captcha.failed', {});
      const parsed = JSON.parse(log.exportJSON({ event: 'captcha.failed' }));
      assert.equal(parsed.length, 1);
    });
  });

  describe('importJSON()', () => {
    it('should import entries from JSON', () => {
      const data = JSON.stringify([
        { event: 'captcha.solved', timestamp: 5000, data: { x: 1 } },
        { event: 'captcha.failed', timestamp: 6000 },
      ]);
      const count = log.importJSON(data);
      assert.equal(count, 2);
      assert.equal(log.size(), 2);
    });

    it('should skip entries missing event or timestamp', () => {
      const data = JSON.stringify([
        { event: 'captcha.solved', timestamp: 5000 },
        { timestamp: 6000 },
        { event: 'captcha.failed' },
      ]);
      assert.equal(log.importJSON(data), 1);
    });

    it('should throw on non-array JSON', () => {
      assert.throws(() => log.importJSON('{}'), /Expected JSON array/);
    });
  });

  describe('purge()', () => {
    it('should purge all entries when no filters', () => {
      log.record('captcha.solved', {});
      log.record('captcha.failed', {});
      const n = log.purge();
      assert.equal(n, 2);
      // purge records an admin.purge entry
      assert.equal(log.size(), 1);
      assert.equal(log.all()[0].event, 'admin.purge');
    });

    it('should purge by event type', () => {
      log.record('captcha.solved', {});
      log.record('captcha.failed', {});
      log.record('captcha.solved', {});
      const n = log.purge({ event: 'captcha.solved' });
      assert.equal(n, 2);
    });

    it('should purge by before timestamp', () => {
      log.record('captcha.solved', {}, { now: 1000 });
      log.record('captcha.solved', {}, { now: 5000 });
      const n = log.purge({ before: 3000 });
      assert.equal(n, 1);
    });

    it('should not record admin.purge if nothing was purged', () => {
      const before = log.size();
      log.purge({ event: 'nonexistent' });
      assert.equal(log.size(), before);
    });
  });

  describe('VALID_EVENTS and SEVERITY exports', () => {
    it('should expose valid events', () => {
      assert.ok(log.VALID_EVENTS.includes('captcha.solved'));
      assert.ok(VALID_EVENTS.includes('rate.limited'));
    });

    it('should expose severity constants', () => {
      assert.equal(SEVERITY.DEBUG, 'debug');
      assert.equal(SEVERITY.CRITICAL, 'critical');
    });
  });

  describe('size() and all()', () => {
    it('should track size correctly', () => {
      assert.equal(log.size(), 0);
      log.record('captcha.solved', {});
      assert.equal(log.size(), 1);
    });

    it('should return snapshot from all()', () => {
      log.record('captcha.solved', {});
      const snapshot = log.all();
      assert.equal(snapshot.length, 1);
      // Mutating snapshot shouldn't affect log
      snapshot.length = 0;
      assert.equal(log.size(), 1);
    });
  });
});
