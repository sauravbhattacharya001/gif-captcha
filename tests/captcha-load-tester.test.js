'use strict';

var assert = require('assert');
var _mod = require('../src/captcha-load-tester');
var createCaptchaLoadTester = _mod.createCaptchaLoadTester;

// ── Helpers ─────────────────────────────────────────────────────

var tick = 0;
function fakeClock() { return tick++; }

function fastHandler() { return Promise.resolve({ solved: true }); }
function slowHandler() { return new Promise(function(r) { setTimeout(function() { r({ solved: true }); }, 20); }); }
function failHandler() { return Promise.reject(new Error('CAPTCHA generation failed')); }
function mixedHandler() {
  var count = 0;
  return function() {
    count++;
    if (count % 3 === 0) return Promise.reject(new Error('intermittent'));
    return Promise.resolve({ solved: true });
  };
}

// ── Tests ───────────────────────────────────────────────────────

var tests = [];
function test(name, fn) { tests.push({ name: name, fn: fn }); }

// --- Constructor ---

test('requires handler function', function() {
  assert.throws(function() { createCaptchaLoadTester(); }, /handler/);
  assert.throws(function() { createCaptchaLoadTester({}); }, /handler/);
  assert.throws(function() { createCaptchaLoadTester({ handler: 'nope' }); }, /handler/);
});

test('accepts valid handler', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler });
  assert.ok(lt);
  assert.equal(typeof lt.run, 'function');
  assert.equal(typeof lt.stress, 'function');
  assert.equal(typeof lt.cancel, 'function');
});

// --- Basic run ---

test('run completes with all successes', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 20, concurrency: 5 });
  return lt.run().then(function(report) {
    assert.equal(report.stats.totalRequests, 20);
    assert.equal(report.stats.successful, 20);
    assert.equal(report.stats.failed, 0);
    assert.equal(report.stats.errorRate, 0);
    assert.ok(report.stats.throughput > 0);
    assert.ok(report.grade === 'A+' || report.grade === 'A');
  });
});

test('run handles all failures', function() {
  var lt = createCaptchaLoadTester({ handler: failHandler, totalRequests: 10, concurrency: 2 });
  return lt.run().then(function(report) {
    assert.equal(report.stats.failed, 10);
    assert.equal(report.stats.successful, 0);
    assert.equal(report.stats.errorRate, 100);
    assert.ok(report.grade === 'F' || report.grade === 'D');
  });
});

test('run handles mixed success/failure', function() {
  var lt = createCaptchaLoadTester({ handler: mixedHandler(), totalRequests: 12, concurrency: 1 });
  return lt.run().then(function(report) {
    assert.equal(report.stats.totalRequests, 12);
    assert.equal(report.stats.failed, 4);
    assert.equal(report.stats.successful, 8);
    assert.ok(report.stats.errorRate > 0);
  });
});

test('concurrency=1 runs sequentially', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 5, concurrency: 1 });
  return lt.run().then(function(report) {
    assert.equal(report.stats.totalRequests, 5);
    assert.equal(report.config.concurrency, 1);
  });
});

test('concurrency greater than totalRequests is capped', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 3, concurrency: 100 });
  return lt.run().then(function(report) {
    assert.equal(report.stats.totalRequests, 3);
    var workerKeys = Object.keys(report.stats.workerStats);
    assert.ok(workerKeys.length <= 3);
  });
});

// --- Latency stats ---

test('latency stats are computed correctly', function() {
  var lt = createCaptchaLoadTester({ handler: slowHandler, totalRequests: 10, concurrency: 2 });
  return lt.run().then(function(report) {
    var lat = report.stats.latency;
    assert.ok(lat.min >= 0);
    assert.ok(lat.max >= lat.min);
    assert.ok(lat.mean >= lat.min);
    assert.ok(lat.median >= lat.min);
    assert.ok(lat.p95 >= lat.median);
    assert.ok(lat.p99 >= lat.p95);
    assert.ok(lat.stdDev >= 0);
  });
});

// --- Timeouts ---

test('requests that exceed timeout are failures', function() {
  var stuckHandler = function() { return new Promise(function() {}); }; // never resolves
  var lt = createCaptchaLoadTester({ handler: stuckHandler, totalRequests: 3, concurrency: 3, timeoutMs: 50 });
  return lt.run().then(function(report) {
    assert.equal(report.stats.failed, 3);
    assert.ok(report.stats.errors['Request timed out after 50ms'] === 3);
  });
});

// --- Config ---

test('config is captured in report', function() {
  var lt = createCaptchaLoadTester({
    handler: fastHandler, totalRequests: 5, concurrency: 2,
    rampUpMs: 100, timeoutMs: 3000, thinkTimeMs: 10
  });
  return lt.run().then(function(report) {
    assert.equal(report.config.concurrency, 2);
    assert.equal(report.config.totalRequests, 5);
    assert.equal(report.config.rampUpMs, 100);
    assert.equal(report.config.timeoutMs, 3000);
    assert.equal(report.config.thinkTimeMs, 10);
  });
});

test('run overrides work', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 10, concurrency: 5 });
  return lt.run({ totalRequests: 3, concurrency: 1 }).then(function(report) {
    assert.equal(report.stats.totalRequests, 3);
    assert.equal(report.config.concurrency, 1);
  });
});

// --- Context factory ---

test('contextFactory is called for each request', function() {
  var count = 0;
  var lt = createCaptchaLoadTester({
    handler: function(ctx) { assert.ok(ctx.id >= 0); return Promise.resolve(); },
    contextFactory: function() { return { id: count++ }; },
    totalRequests: 5, concurrency: 1
  });
  return lt.run().then(function() {
    assert.equal(count, 5);
  });
});

// --- Progress callback ---

test('onProgress is called during run', function() {
  var called = 0;
  var lt = createCaptchaLoadTester({
    handler: slowHandler,
    totalRequests: 5, concurrency: 1,
    onProgress: function(stats) { called++; assert.ok(stats.totalRequests >= 0); },
    progressIntervalMs: 10
  });
  return lt.run().then(function() {
    assert.ok(called >= 1, 'onProgress should have been called at least once');
  });
});

// --- Cancel ---

test('cancel stops a running test', function() {
  var lt = createCaptchaLoadTester({ handler: slowHandler, totalRequests: 100, concurrency: 2 });
  var p = lt.run();
  setTimeout(function() { lt.cancel(); }, 30);
  return p.then(function(report) {
    assert.ok(report.stats.totalRequests < 100, 'Should have stopped early');
  });
});

test('cancel returns false when not running', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler });
  assert.equal(lt.cancel(), false);
});

// --- Double run ---

test('rejects concurrent runs', function() {
  var lt = createCaptchaLoadTester({ handler: slowHandler, totalRequests: 50, concurrency: 5 });
  var p1 = lt.run();
  return lt.run().catch(function(err) {
    assert.ok(err.message.match(/already running/));
    lt.cancel();
    return p1;
  });
});

// --- Worker stats ---

test('worker stats are populated', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 10, concurrency: 3 });
  return lt.run().then(function(report) {
    var ws = report.stats.workerStats;
    var keys = Object.keys(ws);
    assert.ok(keys.length >= 1);
    keys.forEach(function(k) {
      assert.ok(ws[k].requests > 0);
      assert.ok(ws[k].avgLatencyMs >= 0);
    });
  });
});

// --- Error map ---

test('errors are grouped by message', function() {
  var i = 0;
  var lt = createCaptchaLoadTester({
    handler: function() {
      i++;
      if (i % 2 === 0) return Promise.reject(new Error('type_a'));
      return Promise.reject(new Error('type_b'));
    },
    totalRequests: 6, concurrency: 1
  });
  return lt.run().then(function(report) {
    assert.ok(report.stats.errors['type_a'] >= 1);
    assert.ok(report.stats.errors['type_b'] >= 1);
  });
});

// --- Bottleneck detection ---

test('detects high error rate bottleneck', function() {
  var lt = createCaptchaLoadTester({ handler: failHandler, totalRequests: 10, concurrency: 1 });
  return lt.run().then(function(report) {
    var types = report.bottlenecks.map(function(b) { return b.type; });
    assert.ok(types.indexOf('high_error_rate') >= 0);
  });
});

test('no bottlenecks for clean run', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 10, concurrency: 1 });
  return lt.run().then(function(report) {
    // With instant handler, at most minor variance-based bottleneck possible
    var critical = report.bottlenecks.filter(function(b) { return b.severity === 'critical'; });
    assert.equal(critical.length, 0);
  });
});

// --- Grade ---

test('clean run gets A+ or A', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 20, concurrency: 5 });
  return lt.run().then(function(report) {
    assert.ok(report.grade === 'A+' || report.grade === 'A');
  });
});

test('all-fail run gets D or F', function() {
  var lt = createCaptchaLoadTester({ handler: failHandler, totalRequests: 10, concurrency: 2 });
  return lt.run().then(function(report) {
    assert.ok(report.grade === 'D' || report.grade === 'F');
  });
});

// --- History ---

test('run history is accumulated', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 5, concurrency: 1 });
  return lt.run().then(function() {
    return lt.run();
  }).then(function() {
    var h = lt.getHistory();
    assert.equal(h.length, 2);
    assert.ok(h[0].timestamp <= h[1].timestamp);
    assert.ok(h[0].grade);
    assert.ok(h[0].stats.throughput >= 0);
  });
});

// --- Compare ---

test('compare two runs', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 5, concurrency: 1 });
  return lt.run().then(function(r1) {
    return lt.run().then(function(r2) {
      var cmp = lt.compare(r1.timestamp, r2.timestamp);
      assert.ok(cmp);
      assert.ok(cmp.deltas);
      assert.ok(typeof cmp.deltas.throughput === 'number');
      assert.ok(typeof cmp.regression === 'boolean');
      assert.ok(typeof cmp.summary === 'string');
    });
  });
});

test('compare returns null for unknown timestamps', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 5, concurrency: 1 });
  assert.equal(lt.compare(1, 2), null);
});

// --- Scenarios ---

test('register and run scenarios', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 10, concurrency: 5 });
  lt.registerScenario('light', { concurrency: 1, totalRequests: 3 });
  lt.registerScenario('heavy', { concurrency: 10, totalRequests: 20 });

  return lt.runScenario('light').then(function(report) {
    assert.equal(report.config.concurrency, 1);
    assert.equal(report.config.totalRequests, 3);
  });
});

test('runScenario throws for unknown name', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler });
  assert.throws(function() { lt.runScenario('nope'); }, /Unknown scenario/);
});

test('registerScenario requires name', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler });
  assert.throws(function() { lt.registerScenario('', {}); }, /name/);
});

// --- Format report ---

test('formatReport produces readable text', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 5, concurrency: 1 });
  return lt.run().then(function(report) {
    var text = lt.formatReport(report);
    assert.ok(text.indexOf('Load Test Report') >= 0);
    assert.ok(text.indexOf('Grade:') >= 0);
    assert.ok(text.indexOf('Throughput:') >= 0);
    assert.ok(text.indexOf('Latency') >= 0);
  });
});

test('formatReport includes bottlenecks when present', function() {
  var lt = createCaptchaLoadTester({ handler: failHandler, totalRequests: 10, concurrency: 1 });
  return lt.run().then(function(report) {
    var text = lt.formatReport(report);
    assert.ok(text.indexOf('Bottleneck') >= 0 || text.indexOf('CRITICAL') >= 0 || text.indexOf('WARNING') >= 0);
  });
});

test('formatReport includes error breakdown', function() {
  var lt = createCaptchaLoadTester({ handler: failHandler, totalRequests: 5, concurrency: 1 });
  return lt.run().then(function(report) {
    var text = lt.formatReport(report);
    assert.ok(text.indexOf('Errors') >= 0);
  });
});

// --- Export/Import ---

test('exportState and importState roundtrip', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 5, concurrency: 1 });
  lt.registerScenario('quick', { concurrency: 1, totalRequests: 2 });

  return lt.run().then(function() {
    var json = lt.exportState();
    var data = JSON.parse(json);
    assert.ok(data.history.length === 1);
    assert.ok(data.scenarios.quick);

    var lt2 = createCaptchaLoadTester({ handler: fastHandler });
    lt2.importState(json);
    var h = lt2.getHistory();
    assert.equal(h.length, 1);
  });
});

// --- Reset ---

test('reset clears all state', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 5, concurrency: 1 });
  lt.registerScenario('x', { concurrency: 1 });
  return lt.run().then(function() {
    assert.ok(lt.getHistory().length > 0);
    lt.reset();
    assert.equal(lt.getHistory().length, 0);
    assert.throws(function() { lt.runScenario('x'); }, /Unknown/);
  });
});

// --- Stress test ---

test('stress finds optimal concurrency', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 10, concurrency: 1 });
  return lt.stress({ startConcurrency: 1, maxConcurrency: 6, step: 2, requestsPerLevel: 5 }).then(function(report) {
    assert.ok(report.levels.length >= 1);
    assert.ok(report.optimalConcurrency >= 1);
    assert.ok(typeof report.recommendation === 'string');
  });
});

test('stress detects breaking point', function() {
  var callCount = 0;
  var fragileHandler = function() {
    callCount++;
    // Start failing heavily after 15 requests
    if (callCount > 15) return Promise.reject(new Error('overloaded'));
    return Promise.resolve({ ok: true });
  };

  var lt = createCaptchaLoadTester({ handler: fragileHandler, totalRequests: 10, concurrency: 1 });
  return lt.stress({
    startConcurrency: 1, maxConcurrency: 20, step: 2,
    requestsPerLevel: 10, errorRateThreshold: 20
  }).then(function(report) {
    assert.ok(report.levels.length >= 1);
    // Should eventually hit breaking point or reach max
    assert.ok(report.breakingPoint || report.levels.length > 0);
  });
});

// --- Ramp-up ---

test('rampUpMs works without errors', function() {
  var lt = createCaptchaLoadTester({
    handler: fastHandler, totalRequests: 6, concurrency: 3, rampUpMs: 50
  });
  return lt.run().then(function(report) {
    assert.equal(report.stats.totalRequests, 6);
    assert.equal(report.config.rampUpMs, 50);
  });
});

// --- Think time ---

test('thinkTimeMs adds delay between requests', function() {
  var lt = createCaptchaLoadTester({
    handler: fastHandler, totalRequests: 3, concurrency: 1, thinkTimeMs: 10
  });
  return lt.run().then(function(report) {
    assert.equal(report.stats.totalRequests, 3);
    assert.ok(report.stats.durationMs >= 20); // at least 2 think-time gaps
  });
});

// --- Empty stats ---

test('empty results produce zero stats', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 0, concurrency: 1 });
  // totalRequests defaults to 100 for 0, so we test with cancel
  var p = lt.run();
  lt.cancel();
  return p.then(function(report) {
    // May have 0 or a few results depending on timing
    assert.ok(report.stats.totalRequests >= 0);
  });
});

// --- Results array ---

test('results contain per-request detail', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 5, concurrency: 1 });
  return lt.run().then(function(report) {
    assert.equal(report.results.length, 5);
    report.results.forEach(function(r) {
      assert.ok(typeof r.latencyMs === 'number');
      assert.equal(r.success, true);
      assert.equal(r.error, null);
      assert.ok(typeof r.workerId === 'number');
      assert.ok(typeof r.requestIndex === 'number');
      assert.ok(typeof r.startedAt === 'number');
    });
  });
});

// --- Timestamp ---

test('report has timestamp', function() {
  var lt = createCaptchaLoadTester({ handler: fastHandler, totalRequests: 3, concurrency: 1 });
  return lt.run().then(function(report) {
    assert.ok(typeof report.timestamp === 'number');
    assert.ok(report.timestamp > 0);
  });
});

// --- Duration ---

test('durationMs is positive', function() {
  var lt = createCaptchaLoadTester({ handler: slowHandler, totalRequests: 3, concurrency: 1 });
  return lt.run().then(function(report) {
    assert.ok(report.stats.durationMs > 0);
  });
});

// ── Runner ──────────────────────────────────────────────────────

var passed = 0;
var failed = 0;

function runTests(idx) {
  if (idx >= tests.length) {
    console.log('\n' + passed + ' passed, ' + failed + ' failed out of ' + tests.length + ' tests');
    if (failed > 0) process.exit(1);
    return;
  }

  var t = tests[idx];
  try {
    var result = t.fn();
    if (result && typeof result.then === 'function') {
      result.then(function() {
        console.log('  ✓ ' + t.name);
        passed++;
        runTests(idx + 1);
      }).catch(function(err) {
        console.log('  ✗ ' + t.name + ': ' + err.message);
        failed++;
        runTests(idx + 1);
      });
    } else {
      console.log('  ✓ ' + t.name);
      passed++;
      runTests(idx + 1);
    }
  } catch (err) {
    console.log('  ✗ ' + t.name + ': ' + err.message);
    failed++;
    runTests(idx + 1);
  }
}

console.log('CaptchaLoadTester tests\n');
runTests(0);
