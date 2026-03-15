/**
 * Tests for CaptchaIncidentManager
 */

"use strict";

const { createIncidentManager } = require('../src/captcha-incident-manager');

describe('CaptchaIncidentManager', () => {
  let mgr;
  let time;

  beforeEach(() => {
    time = 1000000;
    mgr = createIncidentManager({
      autoEscalateMs: 0, // disable timers in tests
      clock: () => time
    });
  });

  afterEach(() => {
    if (mgr) mgr.destroy();
  });

  describe('create', () => {
    test('creates incident with default severity', () => {
      const id = mgr.create({ title: 'Test incident' });
      expect(id).toMatch(/^INC-/);
      const inc = mgr.get(id);
      expect(inc.title).toBe('Test incident');
      expect(inc.severity).toBe('medium');
      expect(inc.state).toBe('open');
      expect(inc.source).toBe('manual');
    });

    test('creates incident with custom severity and source', () => {
      const id = mgr.create({ title: 'Bot surge', severity: 'critical', source: 'anomaly-detector' });
      const inc = mgr.get(id);
      expect(inc.severity).toBe('critical');
      expect(inc.source).toBe('anomaly-detector');
    });

    test('throws on missing title', () => {
      expect(() => mgr.create({})).toThrow('title is required');
    });

    test('throws on invalid severity', () => {
      expect(() => mgr.create({ title: 'x', severity: 'mega' })).toThrow('Invalid severity');
    });

    test('stores signals and metadata', () => {
      const id = mgr.create({ title: 'Low solve rate', signals: { solveRate: 0.3 }, metadata: { region: 'EU' } });
      const inc = mgr.get(id);
      expect(inc.signals.solveRate).toBe(0.3);
      expect(inc.metadata.region).toBe('EU');
    });

    test('auto-matches runbook from title', () => {
      const id = mgr.create({ title: 'Solve rate dropped to 35%' });
      expect(mgr.get(id).runbook).not.toBeNull();
      expect(mgr.get(id).runbook.title).toBe('Solve Rate Drop');
    });

    test('auto-matches bot runbook', () => {
      const id = mgr.create({ title: 'Bot traffic surge detected' });
      expect(mgr.get(id).runbook.title).toBe('Bot Traffic Surge');
    });

    test('respects maxOpenIncidents', () => {
      const small = createIncidentManager({ autoEscalateMs: 0, maxOpenIncidents: 2, clock: () => time });
      small.create({ title: 'A' });
      small.create({ title: 'B' });
      expect(() => small.create({ title: 'C' })).toThrow('Max open incidents');
      small.destroy();
    });

    test('has timeline entry on creation', () => {
      const id = mgr.create({ title: 'X' });
      expect(mgr.get(id).timeline).toHaveLength(1);
      expect(mgr.get(id).timeline[0].action).toBe('created');
    });
  });

  describe('state transitions', () => {
    let id;
    beforeEach(() => {
      id = mgr.create({ title: 'Test flow' });
    });

    test('acknowledge sets responder and TTA', () => {
      time += 5000;
      mgr.acknowledge(id, { responder: 'alice' });
      const inc = mgr.get(id);
      expect(inc.state).toBe('acknowledged');
      expect(inc.responder).toBe('alice');
      expect(inc.ttaMs).toBe(5000);
    });

    test('full lifecycle: open → acknowledged → investigating → mitigating → resolved → closed', () => {
      mgr.acknowledge(id, { responder: 'bob' });
      mgr.investigate(id);
      mgr.mitigate(id);
      time += 10000;
      mgr.resolve(id, { resolution: 'Fixed it' });
      mgr.close(id);
      const inc = mgr.get(id);
      expect(inc.state).toBe('closed');
      expect(inc.resolution).toBe('Fixed it');
      expect(inc.ttrMs).toBe(10000);
    });

    test('cannot go backward', () => {
      mgr.acknowledge(id);
      expect(() => mgr.acknowledge(id)).toThrow();
    });

    test('cannot resolve then go to investigating', () => {
      mgr.acknowledge(id);
      mgr.resolve(id);
      expect(() => mgr.investigate(id)).toThrow();
    });
  });

  describe('escalate / de-escalate', () => {
    test('escalates severity', () => {
      const id = mgr.create({ title: 'E', severity: 'low' });
      mgr.escalate(id, 'high', 'Getting worse');
      expect(mgr.get(id).severity).toBe('high');
      expect(mgr.get(id).timeline.some(e => e.action === 'escalated')).toBe(true);
    });

    test('cannot escalate to same or lower', () => {
      const id = mgr.create({ title: 'E', severity: 'high' });
      expect(() => mgr.escalate(id, 'low')).toThrow();
      expect(() => mgr.escalate(id, 'high')).toThrow();
    });

    test('de-escalates severity', () => {
      const id = mgr.create({ title: 'D', severity: 'critical' });
      mgr.deescalate(id, 'medium', 'Calming down');
      expect(mgr.get(id).severity).toBe('medium');
    });

    test('cannot de-escalate to same or higher', () => {
      const id = mgr.create({ title: 'D', severity: 'low' });
      expect(() => mgr.deescalate(id, 'high')).toThrow();
    });
  });

  describe('notes', () => {
    test('adds note with author', () => {
      const id = mgr.create({ title: 'N' });
      mgr.addNote(id, 'Checking logs', 'alice');
      const inc = mgr.get(id);
      expect(inc.notes).toHaveLength(1);
      expect(inc.notes[0].text).toBe('Checking logs');
      expect(inc.notes[0].author).toBe('alice');
    });
  });

  describe('queries', () => {
    test('listOpen returns only non-resolved sorted by severity', () => {
      const a = mgr.create({ title: 'Low one', severity: 'low' });
      const b = mgr.create({ title: 'Critical one', severity: 'critical' });
      const c = mgr.create({ title: 'Resolved', severity: 'high' });
      mgr.acknowledge(c);
      mgr.resolve(c);
      const open = mgr.listOpen();
      expect(open).toHaveLength(2);
      expect(open[0].severity).toBe('critical');
    });

    test('listAll filters by severity', () => {
      mgr.create({ title: 'A', severity: 'low' });
      mgr.create({ title: 'B', severity: 'high' });
      mgr.create({ title: 'C', severity: 'low' });
      const lows = mgr.listAll({ severity: 'low' });
      expect(lows).toHaveLength(2);
    });

    test('listAll filters by state', () => {
      const id = mgr.create({ title: 'A' });
      mgr.create({ title: 'B' });
      mgr.acknowledge(id);
      expect(mgr.listAll({ state: 'acknowledged' })).toHaveLength(1);
    });

    test('listAll respects limit', () => {
      for (let i = 0; i < 10; i++) mgr.create({ title: 'I' + i });
      expect(mgr.listAll({ limit: 3 })).toHaveLength(3);
    });

    test('get returns null for unknown id', () => {
      expect(mgr.get('INC-FAKE')).toBeNull();
    });
  });

  describe('stats', () => {
    test('computes stats correctly', () => {
      const a = mgr.create({ title: 'A' });
      time += 2000;
      mgr.acknowledge(a, { responder: 'x' });
      time += 3000;
      mgr.resolve(a);
      mgr.create({ title: 'B', severity: 'critical' });

      const s = mgr.stats();
      expect(s.total).toBe(2);
      expect(s.open).toBe(1);
      expect(s.resolved).toBe(1);
      expect(s.avgTtaMs).toBe(2000);
      expect(s.avgTtrMs).toBe(5000);
    });
  });

  describe('postmortem', () => {
    test('generates markdown postmortem', () => {
      const id = mgr.create({ title: 'Solve rate incident', severity: 'high', source: 'health-monitor', signals: { solveRate: 0.35 } });
      time += 1000;
      mgr.acknowledge(id, { responder: 'ops' });
      mgr.addNote(id, 'Found bot cluster from AS1234', 'ops');
      time += 5000;
      mgr.resolve(id, { resolution: 'Blocked AS1234, rotated pool' });

      const pm = mgr.generatePostmortem(id);
      expect(pm).toContain('# Postmortem: Solve rate incident');
      expect(pm).toContain('**Severity:** high');
      expect(pm).toContain('solveRate');
      expect(pm).toContain('Blocked AS1234');
      expect(pm).toContain('## Timeline');
      expect(pm).toContain('## Action Items');
      expect(pm).toContain('Solve Rate Drop'); // auto-matched runbook
    });

    test('throws for unknown incident', () => {
      expect(() => mgr.generatePostmortem('INC-NOPE')).toThrow();
    });
  });

  describe('export/import', () => {
    test('exportJSON and importJSON round-trip', () => {
      mgr.create({ title: 'X' });
      mgr.create({ title: 'Y' });
      const json = mgr.exportJSON();

      const mgr2 = createIncidentManager({ autoEscalateMs: 0 });
      const count = mgr2.importJSON(json);
      expect(count).toBe(2);
      expect(mgr2.listAll()).toHaveLength(2);
      mgr2.destroy();
    });

    test('exportCSV has headers and rows', () => {
      mgr.create({ title: 'A' });
      const csv = mgr.exportCSV();
      const lines = csv.split('\n');
      expect(lines[0]).toContain('id,title,severity');
      expect(lines).toHaveLength(2);
    });

    test('importJSON throws on non-array', () => {
      expect(() => mgr.importJSON('{}')).toThrow('Expected array');
    });
  });

  describe('purgeResolved', () => {
    test('purges old resolved incidents', () => {
      const id = mgr.create({ title: 'Old' });
      mgr.acknowledge(id);
      mgr.resolve(id);
      time += 100000;
      const purged = mgr.purgeResolved(50000);
      expect(purged).toBe(1);
      expect(mgr.get(id)).toBeNull();
    });

    test('does not purge recent resolved', () => {
      const id = mgr.create({ title: 'Recent' });
      mgr.acknowledge(id);
      mgr.resolve(id);
      time += 100;
      const purged = mgr.purgeResolved(50000);
      expect(purged).toBe(0);
    });
  });

  describe('runbooks', () => {
    test('listRunbooks returns all default runbooks', () => {
      const rbs = mgr.listRunbooks();
      expect(rbs.length).toBeGreaterThanOrEqual(5);
      expect(rbs.some(r => r.slug === 'bot-surge')).toBe(true);
    });

    test('getRunbook returns runbook by slug', () => {
      const rb = mgr.getRunbook('bot-surge');
      expect(rb.title).toBe('Bot Traffic Surge');
      expect(rb.steps.length).toBeGreaterThan(0);
    });

    test('getRunbook returns null for unknown', () => {
      expect(mgr.getRunbook('nonexistent')).toBeNull();
    });

    test('custom runbooks merge with defaults', () => {
      const custom = createIncidentManager({
        autoEscalateMs: 0,
        runbooks: { 'custom-rb': { title: 'Custom', steps: ['Step 1'] } }
      });
      expect(custom.getRunbook('custom-rb').title).toBe('Custom');
      expect(custom.getRunbook('bot-surge')).not.toBeNull();
      custom.destroy();
    });
  });

  describe('auto-escalation', () => {
    test('auto-escalates unacknowledged incidents', (done) => {
      let escalated = false;
      const fast = createIncidentManager({
        autoEscalateMs: 100,
        onEscalate: (inc) => { escalated = true; }
      });
      const id = fast.create({ title: 'Slow response', severity: 'low' });
      setTimeout(() => {
        expect(escalated).toBe(true);
        const inc = fast.get(id);
        expect(inc.severity).toBe('medium');
        expect(inc.timeline.some(e => e.action === 'auto-escalated')).toBe(true);
        fast.destroy();
        done();
      }, 150);
    });

    test('acknowledging cancels auto-escalation', (done) => {
      let escalated = false;
      const fast = createIncidentManager({
        autoEscalateMs: 100,
        onEscalate: () => { escalated = true; }
      });
      const id = fast.create({ title: 'Quick ack', severity: 'low' });
      fast.acknowledge(id, { responder: 'fast-responder' });
      setTimeout(() => {
        expect(escalated).toBe(false);
        fast.destroy();
        done();
      }, 200);
    });
  });
});
