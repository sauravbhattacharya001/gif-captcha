/**
 * Tests for the Response Time Analyzer page (timing.html)
 *
 * Validates challenge data, timer logic, statistics computation,
 * result rendering, export functionality, usability assessment,
 * and security headers.
 */

const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const TIMING_HTML = fs.readFileSync(path.join(__dirname, '..', 'timing.html'), 'utf8');
const SHARED_JS = fs.readFileSync(path.join(__dirname, '..', 'shared.js'), 'utf8');

/** Create a fresh jsdom instance with timing.html loaded */
function createTimingDOM() {
  const patchedHtml = TIMING_HTML.replace(
    '<script src="shared.js"></script>',
    '<script>' + SHARED_JS + '</script>'
  );
  const dom = new JSDOM(patchedHtml, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/timing.html',
  });
  // Mock canvas
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
      clearRect: function () {},
      moveTo: function () {},
      lineTo: function () {},
      stroke: function () {},
      roundRect: function () {},
      fillStyle: '',
      font: '',
      textAlign: '',
      textBaseline: '',
      strokeStyle: '',
      lineWidth: 0,
    };
  };
  // Mock getBoundingClientRect for canvas
  dom.window.HTMLCanvasElement.prototype.getBoundingClientRect = function () {
    return { width: 300, height: 200, top: 0, left: 0, bottom: 200, right: 300 };
  };
  dom.window.Element.prototype.scrollIntoView = function () {};
  dom.window.URL.createObjectURL = function () { return 'blob:test'; };
  dom.window.URL.revokeObjectURL = function () {};
  return dom;
}

// ── Challenge Data ──

describe('Timing: Challenge Data', function () {
  let dom, window;

  before(function () {
    dom = createTimingDOM();
    window = dom.window;
  });

  it('should have 10 challenges', function () {
    assert.equal(window.challenges.length, 10);
  });

  it('each challenge has required fields', function () {
    for (const c of window.challenges) {
      assert.ok(c.id, 'Missing id');
      assert.ok(c.title, 'Missing title');
      assert.ok(c.category, 'Missing category');
      assert.ok(c.gifUrl, 'Missing gifUrl');
      assert.ok(c.humanAnswer, 'Missing humanAnswer');
      assert.ok(Array.isArray(c.keywords), 'keywords must be array');
      assert.ok(c.keywords.length >= 2, 'need at least 2 keywords');
    }
  });

  it('each challenge has a valid category', function () {
    const validCategories = [
      'Narrative Twist', 'Physical Comedy', 'Social Subversion',
      'Animal Behavior', 'Visual Trick', 'Optical Illusion'
    ];
    for (const c of window.challenges) {
      assert.ok(validCategories.includes(c.category),
        c.title + ' has invalid category: ' + c.category);
    }
  });

  it('challenge IDs are sequential 1-10', function () {
    for (let i = 0; i < 10; i++) {
      assert.equal(window.challenges[i].id, i + 1);
    }
  });

  it('GIF URLs use HTTPS', function () {
    for (const c of window.challenges) {
      assert.ok(c.gifUrl.startsWith('https://'), c.title + ' uses non-HTTPS URL');
    }
  });

  it('keywords are all lowercase strings', function () {
    for (const c of window.challenges) {
      for (const kw of c.keywords) {
        assert.equal(typeof kw, 'string');
        assert.equal(kw, kw.toLowerCase(), 'Keyword should be lowercase: ' + kw);
      }
    }
  });
});

// ── Statistics Computation ──

describe('Timing: computeStats', function () {
  let dom, window;

  before(function () {
    dom = createTimingDOM();
    window = dom.window;
  });

  it('should compute correct stats for simple dataset', function () {
    var stats = window.computeStats([1000, 2000, 3000, 4000, 5000]);
    assert.equal(stats.mean, 3000);
    assert.equal(stats.median, 3000);
    assert.equal(stats.min, 1000);
    assert.equal(stats.max, 5000);
    assert.equal(stats.total, 15000);
  });

  it('should handle single value', function () {
    var stats = window.computeStats([5000]);
    assert.equal(stats.mean, 5000);
    assert.equal(stats.median, 5000);
    assert.equal(stats.min, 5000);
    assert.equal(stats.max, 5000);
    assert.equal(stats.stdDev, 0);
  });

  it('should handle empty array', function () {
    var stats = window.computeStats([]);
    assert.equal(stats.mean, 0);
    assert.equal(stats.median, 0);
    assert.equal(stats.total, 0);
  });

  it('should compute standard deviation', function () {
    var stats = window.computeStats([2000, 4000, 4000, 4000, 5000, 5000, 7000, 9000]);
    assert.ok(stats.stdDev > 0, 'stdDev should be positive');
    assert.ok(stats.stdDev < stats.max, 'stdDev should be less than max');
  });

  it('should compute percentiles', function () {
    var times = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000];
    var stats = window.computeStats(times);
    assert.ok(stats.p25 >= 2000 && stats.p25 <= 4000, 'p25 out of range: ' + stats.p25);
    assert.ok(stats.p75 >= 7000 && stats.p75 <= 9000, 'p75 out of range: ' + stats.p75);
  });

  it('should sort input without mutating original', function () {
    var original = [5000, 1000, 3000, 2000, 4000];
    var copy = original.slice();
    window.computeStats(original);
    assert.deepEqual(original, copy);
  });

  it('should handle identical values', function () {
    var stats = window.computeStats([3000, 3000, 3000]);
    assert.equal(stats.mean, 3000);
    assert.equal(stats.median, 3000);
    assert.equal(stats.stdDev, 0);
    assert.equal(stats.min, 3000);
    assert.equal(stats.max, 3000);
  });
});

// ── Time Formatting ──

describe('Timing: formatTime', function () {
  let dom, window;

  before(function () {
    dom = createTimingDOM();
    window = dom.window;
  });

  it('formats milliseconds to seconds', function () {
    assert.equal(window.formatTime(5000), '5.0s');
    assert.equal(window.formatTime(12500), '12.5s');
  });

  it('formats over 60s to minutes', function () {
    var result = window.formatTime(90000);
    assert.ok(result.includes('m'), 'Should contain "m": ' + result);
  });

  it('handles zero', function () {
    assert.equal(window.formatTime(0), '0.0s');
  });

  it('handles small values', function () {
    assert.equal(window.formatTime(100), '0.1s');
  });
});

// ── DOM Structure ──

describe('Timing: DOM Structure', function () {
  let dom, document;

  before(function () {
    dom = createTimingDOM();
    document = dom.window.document;
  });

  it('has intro screen', function () {
    assert.ok(document.getElementById('introScreen'));
  });

  it('has challenge screen (hidden)', function () {
    var el = document.getElementById('challengeScreen');
    assert.ok(el);
    assert.ok(el.classList.contains('hidden'));
  });

  it('has results screen (hidden)', function () {
    var el = document.getElementById('resultsScreen');
    assert.ok(el);
    assert.ok(el.classList.contains('hidden'));
  });

  it('has timer display', function () {
    assert.ok(document.getElementById('timerDisplay'));
  });

  it('has textarea for answers', function () {
    var ta = document.getElementById('userAnswer');
    assert.ok(ta);
    assert.equal(ta.tagName, 'TEXTAREA');
    assert.equal(ta.getAttribute('maxlength'), '500');
  });

  it('has submit button (initially disabled)', function () {
    var btn = document.getElementById('submitBtn');
    assert.ok(btn);
    assert.ok(btn.disabled);
  });

  it('has progress bar', function () {
    assert.ok(document.getElementById('progressFill'));
  });

  it('has chart canvases', function () {
    assert.ok(document.getElementById('barChart'));
    assert.ok(document.getElementById('scatterChart'));
  });

  it('has stats grid container', function () {
    assert.ok(document.getElementById('statsGrid'));
  });

  it('has breakdown table', function () {
    assert.ok(document.getElementById('breakdownBody'));
  });

  it('has category breakdown container', function () {
    assert.ok(document.getElementById('categoryBreakdown'));
  });

  it('has usability assessment container', function () {
    assert.ok(document.getElementById('usabilityAssessment'));
  });
});

// ── Navigation ──

describe('Timing: Navigation', function () {
  let dom, document;

  before(function () {
    dom = createTimingDOM();
    document = dom.window.document;
  });

  it('has links to other pages', function () {
    var links = document.querySelectorAll('.nav-links a');
    assert.ok(links.length >= 4, 'Should have at least 4 nav links');
  });

  it('has link back to case study', function () {
    var links = document.querySelectorAll('.nav-links a');
    var found = false;
    for (var i = 0; i < links.length; i++) {
      if (links[i].getAttribute('href') === 'index.html') found = true;
    }
    assert.ok(found, 'Should link to index.html');
  });
});

// ── Security Headers ──

describe('Timing: Security', function () {
  let dom, document;

  before(function () {
    dom = createTimingDOM();
    document = dom.window.document;
  });

  it('has Content-Security-Policy meta tag', function () {
    var csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp);
    var content = csp.getAttribute('content');
    assert.ok(content.includes("default-src 'none'"), 'CSP should default to none');
    assert.ok(content.includes("script-src"), 'CSP should include script-src');
    assert.ok(content.includes("frame-ancestors 'none'"), 'CSP should block framing');
  });

  it('has referrer policy meta tag', function () {
    var ref = document.querySelector('meta[name="referrer"]');
    assert.ok(ref);
    assert.equal(ref.getAttribute('content'), 'no-referrer');
  });
});

// ── Start Flow ──

describe('Timing: Start Flow', function () {
  let dom, window, document;

  beforeEach(function () {
    dom = createTimingDOM();
    window = dom.window;
    document = dom.window.document;
  });

  it('startTiming hides intro and shows challenge', function () {
    window.startTiming();
    assert.ok(document.getElementById('introScreen').classList.contains('hidden'));
    assert.ok(!document.getElementById('challengeScreen').classList.contains('hidden'));
    assert.ok(!document.getElementById('progressContainer').classList.contains('hidden'));
  });

  it('startTiming resets state', function () {
    window.startTiming();
    assert.equal(window.currentIndex, 0);
    assert.equal(window.results.length, 0);
  });

  it('loadChallenge sets challenge number', function () {
    window.startTiming();
    assert.equal(document.getElementById('challengeNumber').textContent, '1');
    assert.equal(document.getElementById('challengeLabel').textContent, '1 / 10');
  });

  it('loadChallenge sets category badge', function () {
    window.startTiming();
    var cat = document.getElementById('challengeCategory').textContent;
    assert.ok(cat.length > 0, 'Category should be set');
  });

  it('loadChallenge clears textarea', function () {
    window.startTiming();
    assert.equal(document.getElementById('userAnswer').value, '');
  });
});

// ── Submit / Skip Flow ──

describe('Timing: Submit and Skip', function () {
  let dom, window;

  beforeEach(function () {
    dom = createTimingDOM();
    window = dom.window;
    // Simulate timer start
    window.timerStart = Date.now() - 5000; // 5 seconds ago
    window.currentIndex = 0;
    window.results = [];
  });

  it('submitAnswer records result with timing', function () {
    window.document.getElementById('userAnswer').value = 'The person shoots early in the duel';
    window.submitAnswer();
    assert.equal(window.results.length, 1);
    assert.ok(window.results[0].timeMs >= 0);
    assert.equal(window.results[0].id, 1);
    assert.equal(window.results[0].title, 'Duel Plot Twist');
  });

  it('submitAnswer detects correct answer (keyword matching)', function () {
    window.document.getElementById('userAnswer').value = 'He shoots early breaking the duel rules';
    window.submitAnswer();
    assert.equal(window.results[0].status, 'correct');
    assert.ok(window.results[0].keywordsMatched >= 2);
  });

  it('submitAnswer detects wrong answer (insufficient keywords)', function () {
    window.document.getElementById('userAnswer').value = 'Something random happens';
    window.submitAnswer();
    assert.equal(window.results[0].status, 'wrong');
  });

  it('skipChallenge records skipped status', function () {
    window.skipChallenge();
    assert.equal(window.results.length, 1);
    assert.equal(window.results[0].status, 'skipped');
    assert.equal(window.results[0].answer, '');
  });

  it('skipChallenge still records timing', function () {
    window.skipChallenge();
    assert.ok(window.results[0].timeMs >= 0);
  });

  it('submitting advances to next challenge', function () {
    window.document.getElementById('userAnswer').value = 'Test answer here';
    window.submitAnswer();
    assert.equal(window.currentIndex, 1);
  });

  it('skipping advances to next challenge', function () {
    window.skipChallenge();
    assert.equal(window.currentIndex, 1);
  });
});

// ── Results Display ──

describe('Timing: Results Rendering', function () {
  let dom, window, document;

  before(function () {
    dom = createTimingDOM();
    window = dom.window;
    document = dom.window.document;

    // Populate mock results
    window.results = [
      { id: 1, title: 'Test 1', category: 'Narrative Twist', timeMs: 8000, answer: 'answer', status: 'correct', keywordsMatched: 3, keywordsTotal: 5 },
      { id: 2, title: 'Test 2', category: 'Social Subversion', timeMs: 15000, answer: 'answer', status: 'correct', keywordsMatched: 2, keywordsTotal: 4 },
      { id: 3, title: 'Test 3', category: 'Physical Comedy', timeMs: 22000, answer: '', status: 'skipped', keywordsMatched: 0, keywordsTotal: 4 },
      { id: 4, title: 'Test 4', category: 'Animal Behavior', timeMs: 12000, answer: 'wrong', status: 'wrong', keywordsMatched: 0, keywordsTotal: 5 },
      { id: 5, title: 'Test 5', category: 'Visual Trick', timeMs: 10000, answer: 'answer', status: 'correct', keywordsMatched: 3, keywordsTotal: 4 },
    ];

    window.showResults();
  });

  it('shows results screen', function () {
    assert.ok(!document.getElementById('resultsScreen').classList.contains('hidden'));
  });

  it('hides challenge screen', function () {
    assert.ok(document.getElementById('challengeScreen').classList.contains('hidden'));
  });

  it('renders stat cards', function () {
    var grid = document.getElementById('statsGrid');
    assert.ok(grid.innerHTML.length > 0);
    assert.ok(grid.querySelectorAll('.stat-card').length >= 6);
  });

  it('renders breakdown table rows', function () {
    var rows = document.querySelectorAll('#breakdownBody tr');
    assert.equal(rows.length, 5);
  });

  it('renders correct badges', function () {
    var badges = document.querySelectorAll('.badge-correct');
    assert.equal(badges.length, 3);  // 3 correct results
  });

  it('renders skipped badges', function () {
    var badges = document.querySelectorAll('.badge-skipped');
    assert.equal(badges.length, 1);
  });

  it('renders wrong badges', function () {
    var badges = document.querySelectorAll('.badge-wrong');
    assert.equal(badges.length, 1);
  });

  it('renders category breakdown', function () {
    var cats = document.querySelectorAll('.category-row');
    assert.ok(cats.length >= 4, 'Should have at least 4 categories');
  });

  it('renders usability assessment', function () {
    var assessment = document.getElementById('usabilityAssessment');
    assert.ok(assessment.innerHTML.length > 0);
    assert.ok(assessment.innerHTML.includes('Median solve time'));
    assert.ok(assessment.innerHTML.includes('Accuracy'));
  });
});

// ── Usability Grading ──

describe('Timing: Usability Grading', function () {
  let dom, window, document;

  beforeEach(function () {
    dom = createTimingDOM();
    window = dom.window;
    document = dom.window.document;
  });

  it('grades "A" for fast + accurate', function () {
    window.renderUsability(
      { total: 50000, mean: 5000, median: 5000, stdDev: 1000, min: 3000, max: 8000, p25: 4000, p75: 6000 },
      9, 10
    );
    var html = document.getElementById('usabilityAssessment').innerHTML;
    assert.ok(html.includes('A'), 'Should grade A');
    assert.ok(html.includes('Excellent'));
  });

  it('grades "B" for moderate speed + accuracy', function () {
    window.renderUsability(
      { total: 150000, mean: 15000, median: 15000, stdDev: 3000, min: 8000, max: 25000, p25: 12000, p75: 18000 },
      7, 10
    );
    var html = document.getElementById('usabilityAssessment').innerHTML;
    assert.ok(html.includes('B'), 'Should grade B');
    assert.ok(html.includes('Good'));
  });

  it('grades "C" for slow + low accuracy', function () {
    window.renderUsability(
      { total: 250000, mean: 25000, median: 25000, stdDev: 5000, min: 15000, max: 35000, p25: 20000, p75: 30000 },
      5, 10
    );
    var html = document.getElementById('usabilityAssessment').innerHTML;
    assert.ok(html.includes('C'), 'Should grade C');
    assert.ok(html.includes('Acceptable'));
  });

  it('grades "D" for very slow', function () {
    window.renderUsability(
      { total: 400000, mean: 40000, median: 40000, stdDev: 8000, min: 25000, max: 55000, p25: 35000, p75: 45000 },
      3, 10
    );
    var html = document.getElementById('usabilityAssessment').innerHTML;
    assert.ok(html.includes('D'), 'Should grade D');
    assert.ok(html.includes('Poor'));
  });

  it('grades "F" for extremely slow', function () {
    window.renderUsability(
      { total: 500000, mean: 50000, median: 50000, stdDev: 10000, min: 35000, max: 65000, p25: 45000, p75: 55000 },
      2, 10
    );
    var html = document.getElementById('usabilityAssessment').innerHTML;
    assert.ok(html.includes('F'), 'Should grade F');
    assert.ok(html.includes('Unusable'));
  });
});

// ── Export Functions ──

describe('Timing: Export', function () {
  let dom, window;

  before(function () {
    dom = createTimingDOM();
    window = dom.window;
    window.results = [
      { id: 1, title: 'Test', category: 'Narrative Twist', timeMs: 5000, answer: 'test answer', status: 'correct', keywordsMatched: 3, keywordsTotal: 5 },
    ];
  });

  it('exportJSON creates blob download', function () {
    var clicked = false;
    var origCreate = window.document.createElement.bind(window.document);
    // The function creates an anchor and clicks it — just verify no throws
    assert.doesNotThrow(function () {
      window.exportJSON();
    });
  });

  it('exportCSV creates blob download', function () {
    assert.doesNotThrow(function () {
      window.exportCSV();
    });
  });
});

// ── Retry ──

describe('Timing: Retry', function () {
  let dom, window, document;

  before(function () {
    dom = createTimingDOM();
    window = dom.window;
    document = dom.window.document;
  });

  it('retry shows intro and hides results', function () {
    document.getElementById('resultsScreen').classList.remove('hidden');
    document.getElementById('introScreen').classList.add('hidden');
    window.retry();
    assert.ok(!document.getElementById('introScreen').classList.contains('hidden'));
    assert.ok(document.getElementById('resultsScreen').classList.contains('hidden'));
  });
});
