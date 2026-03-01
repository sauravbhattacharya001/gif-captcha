/**
 * Tests for the Batch Validator page (batch.html)
 *
 * Validates CSV/JSON parsing, validation logic, result rendering,
 * export functionality, and security headers.
 */

const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const BATCH_HTML = fs.readFileSync(path.join(__dirname, '..', 'batch.html'), 'utf8');
const LIB_JS = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');

/** Create a fresh jsdom instance with batch.html loaded */
function createBatchDOM() {
  // Inject the library source inline before the page's inline scripts
  // Replace the external script tag with inline library code
  const patchedHtml = BATCH_HTML.replace(
    '<script src="src/index.js"></script>',
    '<script>' + LIB_JS + '</script>'
  );
  const dom = new JSDOM(patchedHtml, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/batch.html',
  });
  // Mock canvas context (jsdom doesn't support Canvas)
  dom.window.HTMLCanvasElement.prototype.getContext = function () {
    return {
      scale: function () {},
      beginPath: function () {},
      arc: function () {},
      closePath: function () {},
      fill: function () {},
      fillRect: function () {},
      fillText: function () {},
      save: function () {},
      restore: function () {},
      translate: function () {},
      rotate: function () {},
      fillStyle: '',
      font: '',
      textAlign: '',
      textBaseline: '',
    };
  };
  // Mock scrollIntoView
  dom.window.Element.prototype.scrollIntoView = function () {};
  // Mock URL methods
  dom.window.URL.createObjectURL = function () { return 'blob:test'; };
  dom.window.URL.revokeObjectURL = function () {};
  return dom;
}

// ── Challenge Data ──

describe('Batch: Challenge Data', function () {
  let dom, window;

  before(function () {
    dom = createBatchDOM();
    window = dom.window;
  });

  it('should have 10 challenges defined', function () {
    assert.equal(window.challenges.length, 10);
  });

  it('should have challengeMap for all IDs', function () {
    for (let i = 1; i <= 10; i++) {
      assert.ok(window.challengeMap[i], 'Missing challenge ' + i);
    }
  });

  it('each challenge should have required fields', function () {
    for (const c of window.challenges) {
      assert.ok(c.id !== undefined, 'Missing id');
      assert.ok(c.title, 'Missing title for id ' + c.id);
      assert.ok(c.humanAnswer, 'Missing humanAnswer for id ' + c.id);
      assert.ok(Array.isArray(c.requiredKeywords), 'Missing requiredKeywords for id ' + c.id);
      assert.ok(c.requiredKeywords.length > 0, 'Empty requiredKeywords for id ' + c.id);
    }
  });
});

// ── Tab Switching ──

describe('Batch: Tab Switching', function () {
  let dom, window;

  beforeEach(function () {
    dom = createBatchDOM();
    window = dom.window;
  });

  it('CSV tab should be active by default', function () {
    const csvTab = window.document.querySelector('[data-tab="csv"]');
    assert.ok(csvTab.classList.contains('active'));
    assert.ok(!window.document.getElementById('csvTab').classList.contains('hidden'));
    assert.ok(window.document.getElementById('jsonTab').classList.contains('hidden'));
    assert.ok(window.document.getElementById('fileTab').classList.contains('hidden'));
  });

  it('switchTab to json should show JSON tab', function () {
    window.switchTab('json');
    assert.ok(window.document.querySelector('[data-tab="json"]').classList.contains('active'));
    assert.ok(!window.document.querySelector('[data-tab="csv"]').classList.contains('active'));
    assert.ok(!window.document.getElementById('jsonTab').classList.contains('hidden'));
    assert.ok(window.document.getElementById('csvTab').classList.contains('hidden'));
  });

  it('switchTab to file should show file tab', function () {
    window.switchTab('file');
    assert.ok(!window.document.getElementById('fileTab').classList.contains('hidden'));
    assert.ok(window.document.getElementById('csvTab').classList.contains('hidden'));
  });

  it('switchTab back to csv restores CSV tab', function () {
    window.switchTab('json');
    window.switchTab('csv');
    assert.ok(window.document.querySelector('[data-tab="csv"]').classList.contains('active'));
    assert.ok(!window.document.getElementById('csvTab').classList.contains('hidden'));
  });
});

// ── CSV Parsing ──

describe('Batch: CSV Parsing', function () {
  let dom, window;

  before(function () {
    dom = createBatchDOM();
    window = dom.window;
  });

  it('should parse valid CSV with all columns', function () {
    const csv = 'challenge_id,respondent_id,answer,response_time_ms\n1,user1,test answer,3000\n2,user1,another,4000';
    const results = window.parseCSV(csv);
    assert.equal(results.length, 2);
    assert.equal(results[0].challenge_id, 1);
    assert.equal(results[0].respondent_id, 'user1');
    assert.equal(results[0].answer, 'test answer');
    assert.equal(results[0].response_time_ms, 3000);
  });

  it('should default respondent_id to unknown when column missing', function () {
    const csv = 'challenge_id,answer\n1,test answer';
    const results = window.parseCSV(csv);
    assert.equal(results.length, 1);
    assert.equal(results[0].respondent_id, 'unknown');
  });

  it('should default response_time_ms to 0 when column missing', function () {
    const csv = 'challenge_id,answer\n1,test answer';
    const results = window.parseCSV(csv);
    assert.equal(results[0].response_time_ms, 0);
  });

  it('should return empty for header-only CSV', function () {
    const results = window.parseCSV('challenge_id,answer');
    assert.equal(results.length, 0);
  });

  it('should skip blank lines', function () {
    const csv = 'challenge_id,answer\n1,hello\n\n2,world\n';
    const results = window.parseCSV(csv);
    assert.equal(results.length, 2);
  });

  it('should handle case-insensitive headers', function () {
    const csv = 'Challenge_ID,Answer\n1,test';
    const results = window.parseCSV(csv);
    assert.equal(results.length, 1);
  });
});

// ── CSV Line Parsing ──

describe('Batch: CSV Line Parsing', function () {
  let dom, window;

  before(function () {
    dom = createBatchDOM();
    window = dom.window;
  });

  it('should handle quoted fields with commas', function () {
    const cols = window.parseCSVLine('1,"hello, world",test');
    assert.equal(cols.length, 3);
    assert.equal(cols[1], 'hello, world');
  });

  it('should handle escaped quotes inside quoted fields', function () {
    const cols = window.parseCSVLine('1,"say ""hello""",test');
    assert.equal(cols[1], 'say "hello"');
  });

  it('should handle simple unquoted fields', function () {
    const cols = window.parseCSVLine('1,user1,simple answer,3000');
    assert.equal(cols.length, 4);
    assert.equal(cols[2], 'simple answer');
  });

  it('should handle empty fields', function () {
    const cols = window.parseCSVLine('1,,answer,');
    assert.equal(cols.length, 4);
    assert.equal(cols[1], '');
  });
});

// ── JSON Parsing ──

describe('Batch: JSON Parsing', function () {
  let dom, window;

  before(function () {
    dom = createBatchDOM();
    window = dom.window;
    window.alert = function () {}; // suppress alerts
  });

  it('should parse valid JSON array', function () {
    const results = window.parseJSON('[{"challenge_id": 1, "answer": "test"}]');
    assert.equal(results.length, 1);
    assert.equal(results[0].challenge_id, 1);
    assert.equal(results[0].answer, 'test');
  });

  it('should set defaults for missing fields', function () {
    const results = window.parseJSON('[{"challenge_id": 1, "answer": "test"}]');
    assert.equal(results[0].respondent_id, 'unknown');
    assert.equal(results[0].response_time_ms, 0);
  });

  it('should return empty for non-array JSON', function () {
    const results = window.parseJSON('{"challenge_id": 1}');
    assert.equal(results.length, 0);
  });

  it('should return empty for invalid JSON', function () {
    const results = window.parseJSON('{invalid}');
    assert.equal(results.length, 0);
  });

  it('should parse all fields when present', function () {
    const results = window.parseJSON('[{"challenge_id": 5, "respondent_id": "alice", "answer": "dog wins", "response_time_ms": 4500}]');
    assert.equal(results[0].challenge_id, 5);
    assert.equal(results[0].respondent_id, 'alice');
    assert.equal(results[0].answer, 'dog wins');
    assert.equal(results[0].response_time_ms, 4500);
  });
});

// ── Sample Data ──

describe('Batch: Sample Data', function () {
  let dom, window;

  beforeEach(function () {
    dom = createBatchDOM();
    window = dom.window;
  });

  it('loadSampleCSV should populate textarea with valid CSV', function () {
    window.loadSampleCSV();
    const val = window.document.getElementById('csvInput').value;
    assert.ok(val.includes('challenge_id'), 'Missing header');
    assert.ok(val.includes('human_01'), 'Missing human respondent');
    assert.ok(val.includes('bot_01'), 'Missing bot respondent');
    // Should be parseable
    const results = window.parseCSV(val);
    assert.ok(results.length >= 10, 'Sample should have at least 10 rows, got ' + results.length);
  });

  it('loadSampleJSON should populate textarea with valid JSON', function () {
    window.loadSampleJSON();
    const val = window.document.getElementById('jsonInput').value;
    const parsed = JSON.parse(val);
    assert.ok(Array.isArray(parsed));
    assert.ok(parsed.length > 0);
    assert.ok(parsed[0].challenge_id !== undefined);
  });

  it('clearInput should clear both textareas', function () {
    window.document.getElementById('csvInput').value = 'some data';
    window.document.getElementById('jsonInput').value = 'some data';
    window.clearInput();
    assert.equal(window.document.getElementById('csvInput').value, '');
    assert.equal(window.document.getElementById('jsonInput').value, '');
  });
});

// ── Validation Logic ──

describe('Batch: Validation', function () {
  let dom, window;

  beforeEach(function () {
    dom = createBatchDOM();
    window = dom.window;
    window.alert = function () {};
  });

  it('should validate CSV responses and show results', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,respondent_id,answer,response_time_ms\n' +
      '1,user1,One person shot a gun that said BANG and the other shot BOOM,3200';
    window.runValidation();
    assert.ok(!window.document.getElementById('results').classList.contains('hidden'));
    assert.equal(window.validationResults.length, 1);
  });

  it('should validate JSON responses', function () {
    window.switchTab('json');
    window.document.getElementById('jsonInput').value =
      '[{"challenge_id": 1, "respondent_id": "u1", "answer": "One shot BANG another BOOM guns", "response_time_ms": 3200}]';
    window.runValidation();
    assert.equal(window.validationResults.length, 1);
  });

  it('should mark good answers as pass', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n' +
      '1,One person shot a gun BANG and the other shot BOOM both had trick guns';
    window.runValidation();
    assert.equal(window.validationResults[0].passed, true);
  });

  it('should mark bad answers as fail', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n' +
      '1,I cannot view animated GIF images';
    window.runValidation();
    assert.equal(window.validationResults[0].passed, false);
  });

  it('should handle unknown challenge IDs gracefully', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n999,some answer';
    window.runValidation();
    assert.equal(window.validationResults[0].passed, false);
    assert.ok(window.validationResults[0].challenge_title.includes('Unknown'));
    assert.ok(window.validationResults[0].reason.includes('Unknown'));
  });

  it('should respect similarity threshold', function () {
    window.document.getElementById('threshold').value = '0.99';
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n1,something about shooting guns';
    window.runValidation();
    assert.equal(window.validationResults[0].passed, false);
  });

  it('keyword mode all should require all keywords', function () {
    window.document.getElementById('keywordMode').value = 'all';
    window.document.getElementById('threshold').value = '0.01';
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n1,someone shot but nothing else';
    window.runValidation();
    // Has "shot" but not "gun"
    assert.equal(window.validationResults[0].keywordMatch, false);
  });

  it('keyword mode any should accept partial keyword match', function () {
    window.document.getElementById('keywordMode').value = 'any';
    window.document.getElementById('threshold').value = '0.01';
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n1,a toy gun appeared';
    window.runValidation();
    assert.equal(window.validationResults[0].keywordMatch, true);
  });

  it('should compute similarity scores between 0 and 1', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n' +
      '1,One person shot BANG the other shot BOOM trick guns';
    window.runValidation();
    const sim = window.validationResults[0].similarity;
    assert.ok(sim > 0, 'Similarity should be > 0, got ' + sim);
    assert.ok(sim <= 1, 'Similarity should be <= 1, got ' + sim);
  });

  it('should handle multiple respondents', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,respondent_id,answer\n' +
      '1,alice,shot BANG BOOM guns\n' +
      '1,bob,I cannot view GIF images\n' +
      '2,alice,rappers roller skates away';
    window.runValidation();
    assert.equal(window.validationResults.length, 3);
  });
});

// ── Results Rendering ──

describe('Batch: Results Rendering', function () {
  let dom, window;

  beforeEach(function () {
    dom = createBatchDOM();
    window = dom.window;
    window.alert = function () {};
  });

  it('should show overview cards with correct total', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n' +
      '1,shot BANG BOOM guns\n' +
      '2,I cannot view GIF\n' +
      '3,Skateboarder does trick and flies up in the air';
    window.runValidation();
    const cards = window.document.getElementById('overviewCards').innerHTML;
    assert.ok(cards.includes('3'), 'Should show total of 3');
  });

  it('should render correct number of table rows', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n1,test1\n2,test2\n3,test3';
    window.runValidation();
    const rows = window.document.querySelectorAll('#resultsBody tr');
    assert.equal(rows.length, 3);
  });

  it('should show PASS and FAIL badges', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,answer\n' +
      '1,One person shot a gun BANG the other BOOM both trick guns\n' +
      '1,I cannot view GIF images';
    window.runValidation();
    const badges = window.document.querySelectorAll('#resultsBody .badge');
    assert.equal(badges.length, 2);
    const texts = Array.from(badges).map(function (b) { return b.textContent; });
    assert.ok(texts.includes('PASS'), 'Should have PASS badge');
    assert.ok(texts.includes('FAIL'), 'Should have FAIL badge');
  });

  it('should render respondent bars', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,respondent_id,answer\n' +
      '1,alice,shot BANG BOOM guns\n' +
      '1,bob,I cannot view';
    window.runValidation();
    const bars = window.document.querySelectorAll('#respondentBars .bar-row');
    assert.equal(bars.length, 2);
  });

  it('should render aggregate stats section', function () {
    window.document.getElementById('csvInput').value =
      'challenge_id,respondent_id,answer,response_time_ms\n' +
      '1,u1,shot BANG guns,3000\n' +
      '2,u1,rappers skate,4000\n' +
      '1,u2,I cannot view,200';
    window.runValidation();
    const stats = window.document.getElementById('aggregateStats').innerHTML;
    assert.ok(stats.includes('2'), 'Should show 2 unique respondents');
  });
});

// ── Export ──

describe('Batch: Export', function () {
  let dom, window;

  beforeEach(function () {
    dom = createBatchDOM();
    window = dom.window;
    window.alert = function () {};
  });

  it('exportCSV should produce CSV with headers', function () {
    let captured = null;
    window.downloadFile = function (fn, content) { captured = { fn: fn, content: content }; };
    window.document.getElementById('csvInput').value = 'challenge_id,answer\n1,test answer';
    window.runValidation();
    window.exportCSV();
    assert.ok(captured, 'downloadFile should have been called');
    assert.ok(captured.fn.includes('.csv'));
    assert.ok(captured.content.includes('challenge_id'));
    assert.ok(captured.content.includes('similarity'));
    assert.ok(captured.content.includes('passed'));
  });

  it('exportJSON should produce valid JSON', function () {
    let captured = null;
    window.downloadFile = function (fn, content) { captured = { fn: fn, content: content }; };
    window.document.getElementById('csvInput').value = 'challenge_id,answer\n1,test answer';
    window.runValidation();
    window.exportJSON();
    assert.ok(captured, 'downloadFile should have been called');
    assert.ok(captured.fn.includes('.json'));
    const parsed = JSON.parse(captured.content);
    assert.ok(Array.isArray(parsed));
    assert.equal(parsed.length, 1);
    assert.ok(parsed[0].challenge_id !== undefined);
    assert.ok(parsed[0].similarity !== undefined);
  });

  it('export with no results should not call downloadFile', function () {
    let called = false;
    window.downloadFile = function () { called = true; };
    window.validationResults = [];
    window.exportCSV();
    window.exportJSON();
    assert.equal(called, false);
  });
});

// ── Security ──

describe('Batch: Security', function () {
  let dom;

  before(function () {
    dom = createBatchDOM();
  });

  it('should have CSP meta tag', function () {
    const meta = dom.window.document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(meta, 'CSP meta tag should exist');
    assert.ok(meta.content.includes('script-src'));
    assert.ok(meta.content.includes("frame-ancestors 'none'"));
  });

  it('should have referrer policy', function () {
    const meta = dom.window.document.querySelector('meta[name="referrer"]');
    assert.ok(meta, 'Referrer policy should exist');
    assert.equal(meta.content, 'no-referrer');
  });

  it('should load shared.css', function () {
    const link = dom.window.document.querySelector('link[href="shared.css"]');
    assert.ok(link, 'Should reference shared.css');
  });
});
