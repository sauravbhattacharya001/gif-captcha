/**
 * Tests for the GIF CAPTCHA Cognitive Load Analyzer (cognitive-load.html)
 *
 * Validates cognitive data integrity, statistics computation,
 * AI capability model, DOM rendering, sorting, and chart setup.
 */

const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const RAW_HTML = fs.readFileSync(path.join(__dirname, '..', 'cognitive-load.html'), 'utf8');
const SHARED_JS = fs.readFileSync(path.join(__dirname, '..', 'shared.js'), 'utf8');

// Inject shared.js inline (jsdom can't fetch external scripts)
const HTML = RAW_HTML.replace(
  '<script src="shared.js"></script>',
  '<script>' + SHARED_JS + '</script>'
);

function createDOM() {
  const dom = new JSDOM(HTML, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/cognitive-load.html',
  });
  return dom;
}

// ===== Cognitive Data Integrity =====

describe('Cognitive Load: Data Integrity', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('should have exactly 10 CAPTCHA entries', () => {
    assert.equal(window.cognitiveData.length, 10);
  });

  it('challenge IDs are sequential 1-10', () => {
    for (let i = 0; i < 10; i++) {
      assert.equal(window.cognitiveData[i].id, i + 1);
    }
  });

  it('each entry has all required fields', () => {
    const fields = ['id', 'title', 'category', 'ratings', 'keyDemand', 'whyHard'];
    for (const c of window.cognitiveData) {
      for (const f of fields) {
        assert.ok(c[f] !== undefined && c[f] !== '',
          `CAPTCHA ${c.id} missing field: ${f}`);
      }
    }
  });

  it('each entry has all 6 dimension ratings', () => {
    const dims = ['visual', 'temporal', 'cultural', 'humor', 'spatial', 'narrative'];
    for (const c of window.cognitiveData) {
      for (const d of dims) {
        assert.ok(typeof c.ratings[d] === 'number',
          `CAPTCHA ${c.id} missing rating: ${d}`);
      }
    }
  });

  it('all ratings are between 1 and 10', () => {
    for (const c of window.cognitiveData) {
      for (const [dim, val] of Object.entries(c.ratings)) {
        assert.ok(val >= 1 && val <= 10,
          `CAPTCHA ${c.id}.${dim} = ${val} is out of range`);
      }
    }
  });

  it('titles are unique', () => {
    const titles = window.cognitiveData.map(c => c.title);
    assert.equal(new Set(titles).size, titles.length);
  });

  it('categories match known set', () => {
    const known = new Set(['narrative', 'social', 'physical', 'animal', 'illusion']);
    for (const c of window.cognitiveData) {
      assert.ok(known.has(c.category),
        `CAPTCHA ${c.id} has unknown category: ${c.category}`);
    }
  });
});

// ===== Dimensions Definition =====

describe('Cognitive Load: Dimensions', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('should define exactly 6 dimensions', () => {
    assert.equal(window.DIMENSIONS.length, 6);
  });

  it('each dimension has key, label, color, emoji, desc', () => {
    for (const d of window.DIMENSIONS) {
      assert.ok(d.key, 'missing key');
      assert.ok(d.label, 'missing label');
      assert.ok(d.color, 'missing color');
      assert.ok(d.emoji, 'missing emoji');
      assert.ok(d.desc, 'missing desc');
    }
  });

  it('dimension keys are unique', () => {
    const keys = window.DIMENSIONS.map(d => d.key);
    assert.equal(new Set(keys).size, keys.length);
  });

  it('dimension keys match rating keys in data', () => {
    const dimKeys = new Set(window.DIMENSIONS.map(d => d.key));
    const ratingKeys = new Set(Object.keys(window.cognitiveData[0].ratings));
    assert.deepEqual(dimKeys, ratingKeys);
  });
});

// ===== AI Capability Model =====

describe('Cognitive Load: AI Capability', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('AI_CAPABILITY has scores for all 6 dimensions', () => {
    const dims = ['visual', 'temporal', 'cultural', 'humor', 'spatial', 'narrative'];
    for (const d of dims) {
      assert.ok(typeof window.AI_CAPABILITY[d] === 'number',
        `Missing AI capability for: ${d}`);
    }
  });

  it('AI scores are between 0 and 10', () => {
    for (const [dim, val] of Object.entries(window.AI_CAPABILITY)) {
      assert.ok(val >= 0 && val <= 10,
        `AI ${dim} = ${val} is out of range`);
    }
  });

  it('AI humor score is lowest (known weakness)', () => {
    const scores = Object.entries(window.AI_CAPABILITY);
    const sorted = scores.sort((a, b) => a[1] - b[1]);
    assert.equal(sorted[0][0], 'humor');
  });

  it('AI visual score is highest (known strength)', () => {
    const scores = Object.entries(window.AI_CAPABILITY);
    const sorted = scores.sort((a, b) => b[1] - a[1]);
    assert.equal(sorted[0][0], 'visual');
  });
});

// ===== Statistics Computation =====

describe('Cognitive Load: Statistics', () => {
  let dom, window, stats;

  before(() => {
    dom = createDOM();
    window = dom.window;
    stats = window.stats;
  });

  it('computes dimension averages', () => {
    assert.ok(stats.dimAvg, 'dimAvg not computed');
    assert.ok(typeof stats.dimAvg.visual === 'number');
    assert.ok(typeof stats.dimAvg.humor === 'number');
  });

  it('dimension averages are between 1 and 10', () => {
    for (const [dim, val] of Object.entries(stats.dimAvg)) {
      assert.ok(val >= 1 && val <= 10,
        `dimAvg.${dim} = ${val} is out of range`);
    }
  });

  it('computes total average load', () => {
    assert.ok(typeof stats.totalLoad === 'number');
    assert.ok(stats.totalLoad >= 1 && stats.totalLoad <= 10);
  });

  it('total load matches manual calculation', () => {
    let sum = 0, count = 0;
    for (const c of window.cognitiveData) {
      for (const v of Object.values(c.ratings)) {
        sum += v;
        count++;
      }
    }
    const expected = sum / count;
    // The totalLoad is avg of per-captcha avgs, which should be equal
    // when all captchas have the same number of dimensions
    assert.ok(Math.abs(stats.totalLoad - expected) < 0.01);
  });

  it('computes per-CAPTCHA avgLoad', () => {
    for (const c of window.cognitiveData) {
      assert.ok(typeof c.avgLoad === 'number',
        `CAPTCHA ${c.id} missing avgLoad`);
      assert.ok(c.avgLoad >= 1 && c.avgLoad <= 10);
    }
  });

  it('avgLoad is correct for first CAPTCHA', () => {
    const c = window.cognitiveData[0]; // Duel Plot Twist
    const expected = (6 + 8 + 7 + 9 + 4 + 9) / 6; // 7.17
    assert.ok(Math.abs(c.avgLoad - expected) < 0.01);
  });

  it('computes gap analysis sorted by gap size', () => {
    assert.ok(Array.isArray(stats.gaps));
    assert.equal(stats.gaps.length, 6);
    // Should be sorted descending by gap
    for (let i = 1; i < stats.gaps.length; i++) {
      assert.ok(stats.gaps[i - 1].gap >= stats.gaps[i].gap,
        'gaps not sorted descending');
    }
  });

  it('gap = avg - aiCap for each dimension', () => {
    for (const g of stats.gaps) {
      assert.ok(Math.abs(g.gap - (g.avg - g.aiCap)) < 0.001);
    }
  });

  it('dimension max values are valid', () => {
    for (const [dim, val] of Object.entries(stats.dimMax)) {
      assert.ok(val >= 1 && val <= 10);
      assert.ok(val >= stats.dimAvg[dim]);
    }
  });

  it('dimension min values are valid', () => {
    for (const [dim, val] of Object.entries(stats.dimMin)) {
      assert.ok(val >= 1 && val <= 10);
      assert.ok(val <= stats.dimAvg[dim]);
    }
  });
});

// ===== DOM Rendering =====

describe('Cognitive Load: DOM Rendering', () => {
  let dom, doc;

  before(() => {
    dom = createDOM();
    doc = dom.window.document;
  });

  it('renders overview cards', () => {
    const cards = doc.getElementById('overviewCards');
    assert.ok(cards);
    assert.ok(cards.innerHTML.includes('Average Cognitive Load'));
    assert.ok(cards.innerHTML.includes('Highest Load'));
    assert.ok(cards.innerHTML.includes('Lowest Load'));
  });

  it('renders dimension legend with 6 items', () => {
    const legend = doc.getElementById('dimensionLegend');
    assert.ok(legend);
    const items = legend.querySelectorAll('.legend-item');
    assert.equal(items.length, 6);
  });

  it('renders gap table with 6 rows', () => {
    const tbody = doc.getElementById('gapTableBody');
    assert.ok(tbody);
    const rows = tbody.querySelectorAll('tr');
    assert.equal(rows.length, 6);
  });

  it('renders research insight', () => {
    const insight = doc.getElementById('insightText');
    assert.ok(insight);
    assert.ok(insight.innerHTML.length > 50);
    assert.ok(insight.innerHTML.includes('capability gap'));
  });

  it('renders 10 CAPTCHA cards', () => {
    const container = doc.getElementById('captchaCards');
    assert.ok(container);
    const cards = container.querySelectorAll('.captcha-card');
    assert.equal(cards.length, 10);
  });

  it('each card has title and score badge', () => {
    const cards = doc.querySelectorAll('.captcha-card');
    for (const card of cards) {
      const title = card.querySelector('.card-title');
      const score = card.querySelector('.card-score');
      assert.ok(title && title.textContent.length > 0);
      assert.ok(score && score.textContent.length > 0);
    }
  });

  it('each card has 6 dimension bars', () => {
    const cards = doc.querySelectorAll('.captcha-card');
    for (const card of cards) {
      const bars = card.querySelectorAll('.dim-bar-row');
      assert.equal(bars.length, 6);
    }
  });

  it('each card has a mini radar canvas', () => {
    const cards = doc.querySelectorAll('.captcha-card');
    for (const card of cards) {
      const canvas = card.querySelector('canvas');
      assert.ok(canvas);
    }
  });

  it('renders sort controls with 5 buttons', () => {
    const buttons = doc.querySelectorAll('.sort-btn');
    assert.equal(buttons.length, 5);
  });

  it('default sort is "By ID" (active)', () => {
    const active = doc.querySelector('.sort-btn.active');
    assert.ok(active);
    assert.equal(active.getAttribute('data-sort'), 'id');
  });
});

// ===== Navigation =====

describe('Cognitive Load: Navigation', () => {
  let dom, doc;

  before(() => {
    dom = createDOM();
    doc = dom.window.document;
  });

  it('has navigation links to all pages', () => {
    const navLinks = doc.querySelectorAll('.nav-links a');
    const hrefs = Array.from(navLinks).map(a => a.getAttribute('href'));
    assert.ok(hrefs.includes('index.html'));
    assert.ok(hrefs.includes('demo.html'));
    assert.ok(hrefs.includes('analysis.html'));
    assert.ok(hrefs.includes('benchmark.html'));
  });

  it('page title is correct', () => {
    assert.ok(doc.title.includes('Cognitive Load'));
  });

  it('has Content-Security-Policy meta tag', () => {
    const csp = doc.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp);
    assert.ok(csp.getAttribute('content').includes("default-src 'none'"));
  });
});

// ===== Score Classification =====

describe('Cognitive Load: Score Classification', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('Mirror Illusion has high visual rating (10)', () => {
    const mirror = window.cognitiveData.find(c => c.title === 'Mirror Illusion');
    assert.equal(mirror.ratings.visual, 10);
    assert.equal(mirror.ratings.spatial, 10);
  });

  it('Road Rage Hug has high humor rating (9)', () => {
    const rr = window.cognitiveData.find(c => c.title === 'Road Rage Hug');
    assert.equal(rr.ratings.humor, 9);
  });

  it('Highway Drift has high temporal rating (9)', () => {
    const hd = window.cognitiveData.find(c => c.title === 'Highway Drift');
    assert.equal(hd.ratings.temporal, 9);
  });

  it('high-load CAPTCHAs get score-high class', () => {
    const highLoad = window.cognitiveData.filter(c => c.avgLoad >= 7);
    if (highLoad.length > 0) {
      const doc = dom.window.document;
      const card = doc.querySelector('.captcha-card[data-id="' + highLoad[0].id + '"]');
      const badge = card.querySelector('.card-score');
      assert.ok(badge.classList.contains('score-high'));
    }
  });

  it('low-load CAPTCHAs get score-low class', () => {
    const lowLoad = window.cognitiveData.filter(c => c.avgLoad < 5);
    if (lowLoad.length > 0) {
      const doc = dom.window.document;
      const card = doc.querySelector('.captcha-card[data-id="' + lowLoad[0].id + '"]');
      const badge = card.querySelector('.card-score');
      assert.ok(badge.classList.contains('score-low'));
    }
  });
});

// ===== Chart Canvases =====

describe('Cognitive Load: Charts', () => {
  let dom, doc;

  before(() => {
    dom = createDOM();
    doc = dom.window.document;
  });

  it('distribution chart canvas exists', () => {
    const canvas = doc.getElementById('distributionChart');
    assert.ok(canvas);
    assert.equal(canvas.tagName, 'CANVAS');
  });

  it('gap chart canvas exists', () => {
    const canvas = doc.getElementById('gapChart');
    assert.ok(canvas);
    assert.equal(canvas.tagName, 'CANVAS');
  });

  it('distribution chart has ARIA label', () => {
    const canvas = doc.getElementById('distributionChart');
    assert.ok(canvas.getAttribute('aria-label').includes('cognitive load'));
  });

  it('gap chart has ARIA label', () => {
    const canvas = doc.getElementById('gapChart');
    assert.ok(canvas.getAttribute('aria-label').includes('human'));
  });
});

// ===== Accessibility =====

describe('Cognitive Load: Accessibility', () => {
  let dom, doc;

  before(() => {
    dom = createDOM();
    doc = dom.window.document;
  });

  it('main has role=main', () => {
    const main = doc.querySelector('[role="main"]');
    assert.ok(main);
  });

  it('dimension legend has role=list', () => {
    const legend = doc.getElementById('dimensionLegend');
    assert.equal(legend.getAttribute('role'), 'list');
  });

  it('legend items have role=listitem', () => {
    const items = doc.querySelectorAll('.legend-item');
    for (const item of items) {
      assert.equal(item.getAttribute('role'), 'listitem');
    }
  });

  it('sort controls have role=group', () => {
    const controls = doc.querySelector('.sort-controls');
    assert.equal(controls.getAttribute('role'), 'group');
  });

  it('gap table has aria-label', () => {
    const table = doc.getElementById('gapTable');
    assert.ok(table.getAttribute('aria-label').includes('gap'));
  });

  it('page has lang=en', () => {
    assert.equal(doc.documentElement.lang, 'en');
  });
});

// ===== Data Consistency =====

describe('Cognitive Load: Data Consistency', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('all CAPTCHAs have non-empty keyDemand', () => {
    for (const c of window.cognitiveData) {
      assert.ok(c.keyDemand.length > 10,
        `CAPTCHA ${c.id} keyDemand too short`);
    }
  });

  it('all CAPTCHAs have non-empty whyHard', () => {
    for (const c of window.cognitiveData) {
      assert.ok(c.whyHard.length > 10,
        `CAPTCHA ${c.id} whyHard too short`);
    }
  });

  it('gap analysis identifies humor as biggest gap', () => {
    // humor has lowest AI score (2.5) with moderate CAPTCHA demand
    const humorGap = window.stats.gaps.find(g => g.key === 'humor');
    assert.ok(humorGap);
    assert.ok(humorGap.gap > 3, 'Humor gap should be significant');
  });

  it('most gaps are non-negative (CAPTCHA demand >= AI capability)', () => {
    const positiveGaps = window.stats.gaps.filter(g => g.gap >= 0);
    // At least 4 of 6 dimensions should have positive gap
    assert.ok(positiveGaps.length >= 4,
      `Only ${positiveGaps.length} positive gaps — AI may be too strong`);
  });

  it('dimension averages sum correctly', () => {
    for (const d of window.DIMENSIONS) {
      let sum = 0;
      for (const c of window.cognitiveData) {
        sum += c.ratings[d.key];
      }
      const expected = sum / window.cognitiveData.length;
      assert.ok(Math.abs(window.stats.dimAvg[d.key] - expected) < 0.001);
    }
  });
});
