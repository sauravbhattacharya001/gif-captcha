'use strict';

var _ref = require('../src/bot-signature-database');
var createBotSignatureDatabase = _ref.createBotSignatureDatabase;

// Helper: create a session profile matching a farm pattern
function farmProfile() {
  return {
    avgSolveTimeMs: 8200,
    solveTimeStdDev: 2100,
    successRate: 0.91,
    burstRate: 5.5,
    retryPattern: 'immediate',
    timeOfDaySkew: flatDist(24),
    consistencyScore: 0.63,
    hesitationRatio: 0.12
  };
}

function botProfile() {
  return {
    avgSolveTimeMs: 1100,
    solveTimeStdDev: 280,
    successRate: 0.33,
    burstRate: 28,
    retryPattern: 'immediate',
    timeOfDaySkew: flatDist(24),
    consistencyScore: 0.94,
    hesitationRatio: 0.0
  };
}

function humanProfile() {
  return {
    avgSolveTimeMs: 15000,
    solveTimeStdDev: 8000,
    successRate: 0.78,
    burstRate: 1.5,
    retryPattern: 'delayed',
    timeOfDaySkew: daytimeDist(24),
    consistencyScore: 0.25,
    hesitationRatio: 0.40
  };
}

function flatDist(n) {
  var arr = [];
  for (var i = 0; i < n; i++) arr.push(1 / n);
  return arr;
}

function daytimeDist(n) {
  var arr = [];
  for (var i = 0; i < n; i++) arr.push(i >= 8 && i <= 22 ? 1 / 15 : 0);
  return arr;
}

describe('createBotSignatureDatabase', function () {
  test('creates with default signatures loaded', function () {
    var db = createBotSignatureDatabase();
    var sigs = db.listSignatures();
    expect(sigs.length).toBe(6);
  });

  test('creates empty when loadDefaults=false', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    expect(db.listSignatures().length).toBe(0);
  });

  test('addSignature creates a new signature', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    var sig = db.addSignature({
      name: 'Test Bot',
      category: 'automated',
      profile: { avgSolveTimeMs: 500, successRate: 0.2 }
    });
    expect(sig.id).toBeTruthy();
    expect(sig.name).toBe('Test Bot');
    expect(sig.category).toBe('automated');
  });

  test('addSignature with custom id', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    db.addSignature({ id: 'my-bot', profile: { avgSolveTimeMs: 100 } });
    expect(db.getSignature('my-bot')).not.toBeNull();
  });

  test('addSignature throws without profile', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    expect(function () { db.addSignature({ name: 'No profile' }); }).toThrow();
  });

  test('addSignature throws at max capacity', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false, maxSignatures: 2 });
    db.addSignature({ id: 'a', profile: { avgSolveTimeMs: 1 } });
    db.addSignature({ id: 'b', profile: { avgSolveTimeMs: 2 } });
    expect(function () {
      db.addSignature({ id: 'c', profile: { avgSolveTimeMs: 3 } });
    }).toThrow(/Maximum/);
  });

  test('removeSignature removes existing', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    db.addSignature({ id: 'x', profile: { avgSolveTimeMs: 1 } });
    expect(db.removeSignature('x')).toBe(true);
    expect(db.getSignature('x')).toBeNull();
  });

  test('removeSignature returns false for unknown', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    expect(db.removeSignature('nope')).toBe(false);
  });

  test('listSignatures filters by category', function () {
    var db = createBotSignatureDatabase();
    var farms = db.listSignatures({ category: 'farm' });
    expect(farms.length).toBeGreaterThan(0);
    farms.forEach(function (s) { expect(s.category).toBe('farm'); });
  });

  test('listSignatures filters by severity', function () {
    var db = createBotSignatureDatabase();
    var crits = db.listSignatures({ severity: 'critical' });
    expect(crits.length).toBeGreaterThan(0);
    crits.forEach(function (s) { expect(s.severity).toBe('critical'); });
  });

  test('listSignatures filters by tag', function () {
    var db = createBotSignatureDatabase();
    var ml = db.listSignatures({ tag: 'ml' });
    expect(ml.length).toBeGreaterThan(0);
  });

  test('matchSession detects farm pattern', function () {
    var db = createBotSignatureDatabase();
    var result = db.matchSession(farmProfile());
    expect(result.matched).toBe(true);
    expect(result.topMatch.category).toBe('farm');
  });

  test('matchSession detects OCR bot', function () {
    var db = createBotSignatureDatabase();
    var result = db.matchSession(botProfile());
    expect(result.matched).toBe(true);
    expect(result.topMatch.category).toBe('automated');
  });

  test('matchSession does not match genuine human', function () {
    var db = createBotSignatureDatabase();
    var result = db.matchSession(humanProfile());
    expect(result.matched).toBe(false);
  });

  test('matchSession respects threshold override', function () {
    var db = createBotSignatureDatabase();
    var result = db.matchSession(humanProfile(), { threshold: 0.1 });
    expect(result.matched).toBe(true); // low threshold matches anything
  });

  test('matchSession respects topN', function () {
    var db = createBotSignatureDatabase();
    var result = db.matchSession(farmProfile(), { topN: 1 });
    expect(result.matches.length).toBeLessThanOrEqual(1);
  });

  test('matchSession category filter', function () {
    var db = createBotSignatureDatabase();
    var result = db.matchSession(farmProfile(), { category: 'replay' });
    // should not match farm signatures when filtering to replay
    result.matches.forEach(function (m) { expect(m.category).toBe('replay'); });
  });

  test('batchMatch processes multiple sessions', function () {
    var db = createBotSignatureDatabase();
    var result = db.batchMatch([farmProfile(), humanProfile(), botProfile()]);
    expect(result.total).toBe(3);
    expect(result.matchedCount).toBeGreaterThanOrEqual(2);
    expect(result.matchRate).toBeGreaterThan(0);
  });

  test('getStats returns correct counts', function () {
    var db = createBotSignatureDatabase();
    db.matchSession(farmProfile());
    db.matchSession(humanProfile());
    var s = db.getStats();
    expect(s.totalChecks).toBe(2);
    expect(s.signatureCount).toBe(6);
  });

  test('getHistory records matches', function () {
    var db = createBotSignatureDatabase();
    db.matchSession(farmProfile());
    var h = db.getHistory();
    expect(h.length).toBe(1);
    expect(h[0].result.matched).toBe(true);
  });

  test('getHistory onlyMatched filter', function () {
    var db = createBotSignatureDatabase();
    db.matchSession(farmProfile());
    db.matchSession(humanProfile());
    var h = db.getHistory({ onlyMatched: true });
    expect(h.length).toBe(1);
  });

  test('getHistory limit', function () {
    var db = createBotSignatureDatabase();
    for (var i = 0; i < 5; i++) db.matchSession(farmProfile());
    var h = db.getHistory({ limit: 2 });
    expect(h.length).toBe(2);
  });

  test('exportDatabase returns valid structure', function () {
    var db = createBotSignatureDatabase();
    var exp = db.exportDatabase();
    expect(exp.version).toBe(1);
    expect(exp.signatures.length).toBe(6);
    expect(exp.stats.signatureCount).toBe(6);
  });

  test('importDatabase merges signatures', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    var data = {
      signatures: [
        { id: 'imp-1', name: 'Imported', category: 'farm', profile: { avgSolveTimeMs: 5000 } }
      ]
    };
    var result = db.importDatabase(data);
    expect(result.imported).toBe(1);
    expect(db.getSignature('imp-1')).not.toBeNull();
  });

  test('importDatabase skips duplicates on merge', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    db.addSignature({ id: 'dup', profile: { avgSolveTimeMs: 1 } });
    var data = { signatures: [{ id: 'dup', profile: { avgSolveTimeMs: 2 } }] };
    var result = db.importDatabase(data, { merge: true });
    expect(result.skipped).toBe(1);
  });

  test('importDatabase replace mode clears existing', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    db.addSignature({ id: 'old', profile: { avgSolveTimeMs: 1 } });
    var data = { signatures: [{ id: 'new', profile: { avgSolveTimeMs: 2 } }] };
    db.importDatabase(data, { merge: false });
    expect(db.getSignature('old')).toBeNull();
    expect(db.getSignature('new')).not.toBeNull();
  });

  test('importDatabase throws on invalid format', function () {
    var db = createBotSignatureDatabase();
    expect(function () { db.importDatabase({}); }).toThrow(/Invalid/);
  });

  test('reset clears and reloads defaults', function () {
    var db = createBotSignatureDatabase();
    db.addSignature({ id: 'extra', profile: { avgSolveTimeMs: 1 } });
    db.matchSession(farmProfile());
    db.reset();
    expect(db.getSignature('extra')).toBeNull();
    expect(db.listSignatures().length).toBe(6);
    expect(db.getStats().totalChecks).toBe(0);
  });

  test('textReport generates readable output', function () {
    var db = createBotSignatureDatabase();
    db.matchSession(farmProfile());
    var report = db.textReport();
    expect(report).toContain('Bot Signature Database Report');
    expect(report).toContain('Detection Rate');
    expect(report).toContain('By Category');
  });

  test('CATEGORIES is immutable copy', function () {
    var db = createBotSignatureDatabase();
    db.CATEGORIES.push('hacked');
    var db2 = createBotSignatureDatabase();
    expect(db2.CATEGORIES).not.toContain('hacked');
  });

  test('unknown category defaults to unknown', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false });
    var sig = db.addSignature({ category: 'alien', profile: { avgSolveTimeMs: 1 } });
    expect(sig.category).toBe('unknown');
  });

  test('similarity scores are bounded 0-1', function () {
    var db = createBotSignatureDatabase();
    var result = db.matchSession(farmProfile());
    result.matches.forEach(function (m) {
      expect(m.similarity).toBeGreaterThanOrEqual(0);
      expect(m.similarity).toBeLessThanOrEqual(1);
    });
  });

  test('match increments signature matchCount', function () {
    var db = createBotSignatureDatabase();
    var before = db.getSignature('captcha-farm-basic').matchCount;
    db.matchSession(farmProfile());
    var after = db.getSignature('captcha-farm-basic').matchCount;
    expect(after).toBeGreaterThan(before);
  });

  test('history respects maxHistory', function () {
    var db = createBotSignatureDatabase({ maxHistory: 3 });
    for (var i = 0; i < 5; i++) db.matchSession(farmProfile());
    expect(db.getHistory().length).toBe(3);
  });

  test('update existing signature at max capacity', function () {
    var db = createBotSignatureDatabase({ loadDefaults: false, maxSignatures: 1 });
    db.addSignature({ id: 'only', profile: { avgSolveTimeMs: 100 } });
    // Should allow update of same id
    var updated = db.addSignature({ id: 'only', name: 'Updated', profile: { avgSolveTimeMs: 200 } });
    expect(updated.name).toBe('Updated');
  });

  test('replay bot detection with fast timing', function () {
    var db = createBotSignatureDatabase();
    var result = db.matchSession({
      avgSolveTimeMs: 210,
      solveTimeStdDev: 55,
      successRate: 0.38,
      burstRate: 58,
      retryPattern: 'none',
      timeOfDaySkew: flatDist(24),
      consistencyScore: 0.97,
      hesitationRatio: 0.0
    });
    expect(result.matched).toBe(true);
    expect(result.topMatch.category).toBe('replay');
  });
});
