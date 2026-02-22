/**
 * Tests for the GIF CAPTCHA Accessibility Audit (accessibility.html)
 *
 * Validates accessibility data integrity, score computation,
 * WCAG criteria, recommendations, DOM rendering, sorting, and charts.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const RAW_HTML = fs.readFileSync(path.join(__dirname, '..', 'accessibility.html'), 'utf8');
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
    url: 'https://example.com/accessibility.html',
  });
  return dom;
}

// ===== Accessibility Data Integrity =====

describe('Accessibility: Data Integrity', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('should have exactly 5 accessibility dimensions', () => {
    assert.equal(window.A11Y_DIMS.length, 5);
  });

  it('dimensions have required properties', () => {
    for (const d of window.A11Y_DIMS) {
      assert.ok(d.key, 'key missing');
      assert.ok(d.label, 'label missing');
      assert.ok(d.color, 'color missing');
      assert.ok(d.emoji, 'emoji missing');
      assert.ok(d.desc, 'desc missing');
    }
  });

  it('dimension keys are unique', () => {
    const keys = window.A11Y_DIMS.map(d => d.key);
    assert.equal(new Set(keys).size, keys.length);
  });

  it('dimension keys include motion, visual, cognitive, cultural, temporal', () => {
    const keys = new Set(window.A11Y_DIMS.map(d => d.key));
    for (const k of ['cognitive', 'cultural', 'motion', 'temporal', 'visual']) {
      assert.ok(keys.has(k), `missing key: ${k}`);
    }
  });

  it('should have exactly 10 CAPTCHAs', () => {
    assert.equal(window.a11yData.length, 10);
  });

  it('CAPTCHA IDs are sequential 1-10', () => {
    for (let i = 0; i < 10; i++) {
      assert.equal(window.a11yData[i].id, i + 1);
    }
  });

  it('each CAPTCHA has barriers for all dimensions', () => {
    const dimKeys = window.A11Y_DIMS.map(d => d.key);
    for (const c of window.a11yData) {
      for (const k of dimKeys) {
        assert.ok(k in c.barriers, `${c.title} missing barrier ${k}`);
        assert.ok(c.barriers[k] >= 1 && c.barriers[k] <= 10,
          `${c.title}.${k} = ${c.barriers[k]} out of 1-10 range`);
      }
    }
  });

  it('each CAPTCHA has a title', () => {
    for (const c of window.a11yData) {
      assert.ok(c.title && c.title.length > 0);
    }
  });

  it('each CAPTCHA has a category', () => {
    for (const c of window.a11yData) {
      assert.ok(c.category && c.category.length > 0);
    }
  });

  it('each CAPTCHA has at least one issue', () => {
    for (const c of window.a11yData) {
      assert.ok(c.issues.length >= 1, `${c.title} has no issues`);
    }
  });

  it('issues have valid severity levels', () => {
    const valid = new Set(['high', 'medium', 'low']);
    for (const c of window.a11yData) {
      for (const i of c.issues) {
        assert.ok(valid.has(i.severity), `${c.title}: invalid severity ${i.severity}`);
        assert.ok(i.text && i.text.length > 0, `${c.title}: empty issue text`);
      }
    }
  });

  it('every CAPTCHA has at least one high or medium issue', () => {
    for (const c of window.a11yData) {
      const important = c.issues.filter(i => i.severity === 'high' || i.severity === 'medium');
      assert.ok(important.length >= 1, `${c.title} has no high/medium issues`);
    }
  });
});

// ===== WCAG Criteria =====

describe('Accessibility: WCAG Criteria', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('has at least 8 WCAG criteria', () => {
    assert.ok(window.wcagCriteria.length >= 8);
  });

  it('each criterion has required properties', () => {
    for (const w of window.wcagCriteria) {
      assert.ok(w.id, 'id missing');
      assert.ok(w.name, 'name missing');
      assert.ok(w.level, 'level missing');
      assert.ok(w.status, 'status missing');
      assert.ok(w.notes, 'notes missing');
    }
  });

  it('levels are valid (A, AA, AAA)', () => {
    const valid = new Set(['A', 'AA', 'AAA']);
    for (const w of window.wcagCriteria) {
      assert.ok(valid.has(w.level), `invalid level: ${w.level}`);
    }
  });

  it('statuses are valid (pass, fail, partial)', () => {
    const valid = new Set(['pass', 'fail', 'partial']);
    for (const w of window.wcagCriteria) {
      assert.ok(valid.has(w.status), `invalid status: ${w.status}`);
    }
  });

  it('has at least one pass and one fail', () => {
    const statuses = window.wcagCriteria.map(w => w.status);
    assert.ok(statuses.includes('pass'), 'no pass found');
    assert.ok(statuses.includes('fail'), 'no fail found');
  });

  it('criterion IDs follow WCAG format (X.X.X)', () => {
    for (const w of window.wcagCriteria) {
      assert.match(w.id, /^\d+\.\d+\.\d+$/, `invalid format: ${w.id}`);
    }
  });

  it('includes Non-text Content (1.1.1)', () => {
    const found = window.wcagCriteria.find(w => w.id === '1.1.1');
    assert.ok(found, 'missing 1.1.1');
    assert.equal(found.status, 'fail');
  });

  it('includes Pause Stop Hide (2.2.2)', () => {
    const found = window.wcagCriteria.find(w => w.id === '2.2.2');
    assert.ok(found, 'missing 2.2.2');
    assert.equal(found.status, 'fail');
  });

  it('Timing Adjustable (2.2.1) passes since no time limit', () => {
    const found = window.wcagCriteria.find(w => w.id === '2.2.1');
    assert.ok(found);
    assert.equal(found.status, 'pass');
  });
});

// ===== Recommendations =====

describe('Accessibility: Recommendations', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('has at least 6 recommendations', () => {
    assert.ok(window.recommendations.length >= 6);
  });

  it('each recommendation has required properties', () => {
    for (const r of window.recommendations) {
      assert.ok(r.emoji, 'emoji missing');
      assert.ok(r.title, 'title missing');
      assert.ok(r.desc, 'desc missing');
      assert.ok(r.impact, 'impact missing');
    }
  });

  it('impacts are valid (high, medium)', () => {
    const valid = new Set(['high', 'medium']);
    for (const r of window.recommendations) {
      assert.ok(valid.has(r.impact), `invalid impact: ${r.impact}`);
    }
  });

  it('has at least 3 high-impact recommendations', () => {
    const high = window.recommendations.filter(r => r.impact === 'high');
    assert.ok(high.length >= 3, `only ${high.length} high-impact recs`);
  });

  it('recommendations mention WCAG criteria', () => {
    const withWcag = window.recommendations.filter(r => r.wcag);
    assert.ok(withWcag.length >= 4, 'at least 4 should reference WCAG');
  });
});

// ===== Score Computation =====

describe('Accessibility: Score Computation', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('computeScores populates score on each CAPTCHA', () => {
    for (const c of window.a11yData) {
      assert.equal(typeof c.score, 'number');
      assert.ok(c.score >= 0 && c.score <= 100, `${c.title}: score ${c.score}`);
    }
  });

  it('computeScores populates avgBarrier on each CAPTCHA', () => {
    for (const c of window.a11yData) {
      assert.equal(typeof c.avgBarrier, 'number');
      assert.ok(c.avgBarrier >= 1 && c.avgBarrier <= 10, `${c.title}: avg ${c.avgBarrier}`);
    }
  });

  it('score = 100 - (avgBarrier * 10) rounded', () => {
    for (const c of window.a11yData) {
      const expected = Math.round(100 - (c.avgBarrier * 10));
      assert.equal(c.score, expected, `${c.title}: got ${c.score} expected ${expected}`);
    }
  });

  it('issueCount counts high + medium issues', () => {
    for (const c of window.a11yData) {
      const expected = c.issues.filter(i => i.severity === 'high' || i.severity === 'medium').length;
      assert.equal(c.issueCount, expected, `${c.title}: got ${c.issueCount} expected ${expected}`);
    }
  });

  it('stats has dimension averages for all dimensions', () => {
    for (const d of window.A11Y_DIMS) {
      assert.equal(typeof window.stats.dimAvg[d.key], 'number');
      assert.ok(window.stats.dimAvg[d.key] > 0, `${d.key} avg is 0`);
    }
  });

  it('stats totalScore is within valid range', () => {
    assert.ok(window.stats.totalScore > 0);
    assert.ok(window.stats.totalScore < 100);
  });

  it('stats highIssues is a non-negative integer', () => {
    assert.ok(window.stats.highIssues >= 0);
    assert.ok(Number.isInteger(window.stats.highIssues));
  });

  it('scoreGrade returns Good for >= 70', () => {
    assert.equal(window.scoreGrade(70).grade, 'Good');
    assert.equal(window.scoreGrade(80).grade, 'Good');
    assert.equal(window.scoreGrade(100).grade, 'Good');
  });

  it('scoreGrade returns Fair for 50-69', () => {
    assert.equal(window.scoreGrade(50).grade, 'Fair');
    assert.equal(window.scoreGrade(60).grade, 'Fair');
    assert.equal(window.scoreGrade(69).grade, 'Fair');
  });

  it('scoreGrade returns Poor for 30-49', () => {
    assert.equal(window.scoreGrade(30).grade, 'Poor');
    assert.equal(window.scoreGrade(40).grade, 'Poor');
    assert.equal(window.scoreGrade(49).grade, 'Poor');
  });

  it('scoreGrade returns Bad for < 30', () => {
    assert.equal(window.scoreGrade(0).grade, 'Bad');
    assert.equal(window.scoreGrade(20).grade, 'Bad');
    assert.equal(window.scoreGrade(29).grade, 'Bad');
  });

  it('scoreGrade cls matches grade name', () => {
    assert.equal(window.scoreGrade(80).cls, 'score-good');
    assert.equal(window.scoreGrade(60).cls, 'score-ok');
    assert.equal(window.scoreGrade(40).cls, 'score-poor');
    assert.equal(window.scoreGrade(20).cls, 'score-bad');
  });
});

// ===== Specific CAPTCHA Analysis =====

describe('Accessibility: Specific CAPTCHAs', () => {
  let dom, window;

  before(() => {
    dom = createDOM();
    window = dom.window;
  });

  it('Highway Drift has the highest motion barrier (10)', () => {
    const highway = window.a11yData.find(c => c.id === 8);
    assert.equal(highway.barriers.motion, 10);
    for (const c of window.a11yData) {
      assert.ok(highway.barriers.motion >= c.barriers.motion);
    }
  });

  it('Mirror Illusion has the highest visual barrier (10)', () => {
    const mirror = window.a11yData.find(c => c.id === 7);
    assert.equal(mirror.barriers.visual, 10);
  });

  it('Parent Dog has the highest cognitive barrier (9)', () => {
    const parent = window.a11yData.find(c => c.id === 6);
    assert.equal(parent.barriers.cognitive, 9);
  });

  it('Highway Drift is the least accessible (lowest score)', () => {
    const sorted = window.a11yData.slice().sort((a, b) => a.score - b.score);
    assert.equal(sorted[0].title, 'Highway Drift');
  });

  it('Tic Tac Toe Dog is the most accessible (highest score)', () => {
    const sorted = window.a11yData.slice().sort((a, b) => b.score - a.score);
    assert.equal(sorted[0].title, 'Tic Tac Toe Dog');
  });

  it('Highway Drift gets Poor or Bad grade (worst performer)', () => {
    const highway = window.a11yData.find(c => c.id === 8);
    const grade = window.scoreGrade(highway.score).grade;
    assert.ok(grade === 'Poor' || grade === 'Bad', `expected Poor or Bad, got ${grade}`);
  });

  it('Mirror Illusion has low motion but high visual', () => {
    const mirror = window.a11yData.find(c => c.id === 7);
    assert.ok(mirror.barriers.motion <= 3);
    assert.equal(mirror.barriers.visual, 10);
  });

  it('Skateboarder has high motion and temporal barriers', () => {
    const sk = window.a11yData.find(c => c.id === 3);
    assert.ok(sk.barriers.motion >= 8);
    assert.ok(sk.barriers.temporal >= 7);
  });

  it('Road Rage Hug and Rappers have high cultural barriers', () => {
    const rr = window.a11yData.find(c => c.id === 9);
    const rap = window.a11yData.find(c => c.id === 2);
    assert.ok(rr.barriers.cultural >= 7);
    assert.ok(rap.barriers.cultural >= 7);
  });

  it('physical CAPTCHAs (3, 8) have higher motion than narrative (1, 10)', () => {
    const sk = window.a11yData.find(c => c.id === 3);
    const hw = window.a11yData.find(c => c.id === 8);
    const duel = window.a11yData.find(c => c.id === 1);
    const cake = window.a11yData.find(c => c.id === 10);
    const physAvg = (sk.barriers.motion + hw.barriers.motion) / 2;
    const narrAvg = (duel.barriers.motion + cake.barriers.motion) / 2;
    assert.ok(physAvg > narrAvg, `physical ${physAvg} should > narrative ${narrAvg}`);
  });
});

// ===== DOM Rendering =====

describe('Accessibility: DOM Rendering', () => {
  let dom, doc;

  before(() => {
    dom = createDOM();
    doc = dom.window.document;
  });

  it('page title contains Accessibility Audit', () => {
    assert.ok(doc.title.includes('Accessibility Audit'));
  });

  it('has CSP meta tag', () => {
    const csp = doc.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp);
  });

  it('has referrer policy', () => {
    const ref = doc.querySelector('meta[name="referrer"]');
    assert.ok(ref);
  });

  it('overview cards are rendered (>= 4)', () => {
    const cards = doc.getElementById('overviewCards');
    assert.ok(cards);
    assert.ok(cards.querySelectorAll('.overview-card').length >= 4);
  });

  it('overview contains score /100', () => {
    const text = doc.getElementById('overviewCards').textContent;
    assert.match(text, /\/100/);
  });

  it('dimension legend has 5 badges', () => {
    const legend = doc.getElementById('dimensionLegend');
    assert.ok(legend);
    assert.equal(legend.querySelectorAll('.dim-badge').length, 5);
  });

  it('WCAG table has at least 8 rows', () => {
    const rows = doc.querySelectorAll('#wcagBody tr');
    assert.ok(rows.length >= 8);
  });

  it('WCAG table shows pass and fail icons', () => {
    const body = doc.getElementById('wcagBody').textContent;
    assert.ok(body.includes('✅'));
    assert.ok(body.includes('❌'));
  });

  it('insight box is populated with barrier text', () => {
    const insight = doc.getElementById('insightText').innerHTML;
    assert.ok(insight.length > 50);
    assert.ok(insight.includes('barrier'));
  });

  it('renders 10 CAPTCHA cards', () => {
    const cards = doc.querySelectorAll('.captcha-card');
    assert.equal(cards.length, 10);
  });

  it('each card has a score badge', () => {
    const badges = doc.querySelectorAll('.score-badge');
    assert.equal(badges.length, 10);
  });

  it('each card has 5 bar rows (one per dimension)', () => {
    const cards = doc.querySelectorAll('.captcha-card');
    for (const card of cards) {
      assert.equal(card.querySelectorAll('.bar-row').length, 5);
    }
  });

  it('each card has issues section', () => {
    assert.equal(doc.querySelectorAll('.card-issues').length, 10);
  });

  it('recommendation cards are rendered (>= 6)', () => {
    const recs = doc.querySelectorAll('.rec-card');
    assert.ok(recs.length >= 6);
  });

  it('has 5 sort buttons', () => {
    assert.equal(doc.querySelectorAll('.sort-btn').length, 5);
  });

  it('default sort is By ID (active)', () => {
    const active = doc.querySelector('.sort-btn.active');
    assert.ok(active);
    assert.equal(active.getAttribute('data-sort'), 'id');
  });

  it('has navigation links including Home', () => {
    const nav = doc.querySelector('.nav-links');
    assert.ok(nav);
    assert.ok(nav.textContent.includes('Home'));
  });

  it('main element has role=main', () => {
    assert.ok(doc.querySelector('main[role="main"]'));
  });

  it('overview cards have ARIA label', () => {
    const overview = doc.getElementById('overviewCards');
    assert.ok(overview.getAttribute('aria-label').includes('overview'));
  });

  it('score chart canvas exists', () => {
    assert.ok(doc.getElementById('scoreChart'));
  });

  it('radar chart canvas exists', () => {
    assert.ok(doc.getElementById('radarChart'));
  });

  it('footer links to case study', () => {
    const footer = doc.querySelector('footer');
    assert.ok(footer);
    const link = footer.querySelector('a');
    assert.equal(link.getAttribute('href'), 'index.html');
  });

  it('loads shared.css', () => {
    assert.ok(doc.querySelector('link[href="shared.css"]'));
  });

  it('has lang=en', () => {
    assert.equal(doc.documentElement.getAttribute('lang'), 'en');
  });
});

// ===== Sort Functionality =====

describe('Accessibility: Sort', () => {
  let dom, doc;

  before(() => {
    dom = createDOM();
    doc = dom.window.document;
  });

  it('clicking score-desc sorts highest first', () => {
    const btn = doc.querySelector('.sort-btn[data-sort="score-desc"]');
    btn.click();
    const badges = doc.querySelectorAll('.score-badge');
    const scores = Array.from(badges).map(b => parseInt(b.textContent));
    for (let i = 1; i < scores.length; i++) {
      assert.ok(scores[i] <= scores[i - 1], `${scores[i]} > ${scores[i-1]} at index ${i}`);
    }
  });

  it('clicking score-asc sorts lowest first', () => {
    const btn = doc.querySelector('.sort-btn[data-sort="score-asc"]');
    btn.click();
    const badges = doc.querySelectorAll('.score-badge');
    const scores = Array.from(badges).map(b => parseInt(b.textContent));
    for (let i = 1; i < scores.length; i++) {
      assert.ok(scores[i] >= scores[i - 1], `${scores[i]} < ${scores[i-1]} at index ${i}`);
    }
  });

  it('clicking id sorts by CAPTCHA ID', () => {
    // First sort differently, then back to id
    doc.querySelector('.sort-btn[data-sort="score-desc"]').click();
    doc.querySelector('.sort-btn[data-sort="id"]').click();
    const ids = Array.from(doc.querySelectorAll('.card-id')).map(el => {
      const m = el.textContent.match(/#(\d+)/);
      return m ? parseInt(m[1]) : 0;
    });
    for (let i = 1; i < ids.length; i++) {
      assert.ok(ids[i] > ids[i - 1], `id ${ids[i]} not > ${ids[i-1]}`);
    }
  });

  it('active class moves to clicked button', () => {
    const btns = doc.querySelectorAll('.sort-btn');
    btns[2].click();
    assert.ok(btns[2].classList.contains('active'), 'clicked btn not active');
    assert.ok(!btns[0].classList.contains('active'), 'first btn still active');
  });

  it('motion sort puts highest motion barrier first', () => {
    doc.querySelector('.sort-btn[data-sort="motion"]').click();
    const cards = doc.querySelectorAll('.captcha-card');
    // First card should be Highway Drift (id 8, motion 10)
    const firstId = cards[0].querySelector('.card-id').textContent;
    assert.ok(firstId.includes('#8'), `expected #8 first, got ${firstId}`);
  });
});

// ===== HTML Structure =====

describe('Accessibility: HTML Structure', () => {
  it('has DOCTYPE', () => {
    assert.match(RAW_HTML, /<!DOCTYPE html>/i);
  });

  it('has charset UTF-8', () => {
    assert.match(RAW_HTML, /charset="UTF-8"/i);
  });

  it('has viewport meta', () => {
    assert.match(RAW_HTML, /name="viewport"/i);
  });

  it('canvases have aria-label', () => {
    const dom = createDOM();
    const canvases = dom.window.document.querySelectorAll('canvas[aria-label]');
    assert.ok(canvases.length >= 2, `only ${canvases.length} canvases with aria-label`);
  });

  it('references shared.js', () => {
    assert.match(RAW_HTML, /src="shared\.js"/);
  });

  it('references shared.css', () => {
    assert.match(RAW_HTML, /href="shared\.css"/);
  });
});
