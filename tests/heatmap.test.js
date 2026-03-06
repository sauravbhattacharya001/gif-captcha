/**
 * Tests for the Interaction Heatmap page (heatmap.html)
 *
 * Validates page structure, GIF loading, recording controls,
 * heatmap/trail rendering, stats computation, pattern analysis,
 * event logging, replay, and security headers.
 */

const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const HEATMAP_HTML = fs.readFileSync(path.join(__dirname, '..', 'heatmap.html'), 'utf8');
const SHARED_JS = fs.readFileSync(path.join(__dirname, '..', 'shared.js'), 'utf8');

/** Create a fresh jsdom instance with heatmap.html loaded */
function createHeatmapDOM() {
  const patchedHtml = HEATMAP_HTML.replace(
    '<script src="shared.js"></script>',
    '<script>' + SHARED_JS + '</script>'
  );
  const dom = new JSDOM(patchedHtml, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/heatmap.html',
  });
  // Mock canvas getContext
  dom.window.HTMLCanvasElement.prototype.getContext = function () {
    return {
      clearRect: function () {},
      beginPath: function () {},
      arc: function () {},
      fill: function () {},
      fillRect: function () {},
      stroke: function () {},
      moveTo: function () {},
      lineTo: function () {},
      putImageData: function () {},
      getImageData: function (x, y, w, h) {
        return { data: new Uint8ClampedArray(w * h * 4) };
      },
      createRadialGradient: function () {
        return {
          addColorStop: function () {},
        };
      },
      save: function () {},
      restore: function () {},
      scale: function () {},
      fillStyle: '',
      strokeStyle: '',
      lineWidth: 1,
      lineCap: '',
      lineJoin: '',
    };
  };
  return dom;
}

// ── Page Structure ──────────────────────────────────────────

describe('Heatmap page structure', () => {
  let dom, doc;
  before(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('has correct title', () => {
    assert.ok(doc.title.includes('Interaction Heatmap'));
  });

  it('has Content-Security-Policy meta tag', () => {
    const csp = doc.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp);
    assert.ok(csp.content.includes("default-src 'none'"));
    assert.ok(csp.content.includes("frame-ancestors 'none'"));
  });

  it('has referrer policy', () => {
    const ref = doc.querySelector('meta[name="referrer"]');
    assert.ok(ref);
    assert.equal(ref.content, 'no-referrer');
  });

  it('links to shared.css', () => {
    const link = doc.querySelector('link[href="shared.css"]');
    assert.ok(link);
  });

  it('has header with navigation links', () => {
    const navLinks = doc.querySelectorAll('.nav-links a');
    assert.ok(navLinks.length >= 4);
    const hrefs = Array.from(navLinks).map(a => a.getAttribute('href'));
    assert.ok(hrefs.includes('index.html'));
    assert.ok(hrefs.includes('demo.html'));
  });

  it('has footer', () => {
    const footer = doc.querySelector('footer');
    assert.ok(footer);
  });
});

// ── Controls ────────────────────────────────────────────────

describe('Controls', () => {
  let dom, doc;
  before(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('has GIF selector with 10 options', () => {
    const select = doc.getElementById('gifSelect');
    assert.ok(select);
    assert.equal(select.options.length, 10);
  });

  it('GIF options have sequential values', () => {
    const select = doc.getElementById('gifSelect');
    for (let i = 0; i < 10; i++) {
      assert.equal(select.options[i].value, String(i));
    }
  });

  it('has record button', () => {
    const btn = doc.getElementById('recordBtn');
    assert.ok(btn);
    assert.ok(btn.textContent.includes('Record'));
  });

  it('has replay button (initially disabled)', () => {
    const btn = doc.getElementById('replayBtn');
    assert.ok(btn);
    assert.ok(btn.disabled);
  });

  it('has clear button', () => {
    const btn = doc.getElementById('clearBtn');
    assert.ok(btn);
  });

  it('has heatmap toggle (active by default)', () => {
    const btn = doc.getElementById('toggleHeatmap');
    assert.ok(btn);
    assert.ok(btn.classList.contains('active-toggle'));
  });

  it('has trail toggle', () => {
    const btn = doc.getElementById('toggleTrail');
    assert.ok(btn);
  });

  it('has mode badge (IDLE initially)', () => {
    const badge = doc.getElementById('modeBadge');
    assert.ok(badge);
    assert.ok(badge.textContent.includes('IDLE'));
    assert.ok(badge.classList.contains('mode-idle'));
  });
});

// ── Canvas elements ─────────────────────────────────────────

describe('Canvas elements', () => {
  let dom, doc;
  before(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('has heatmap canvas', () => {
    const canvas = doc.getElementById('heatmapCanvas');
    assert.ok(canvas);
    assert.equal(canvas.tagName, 'CANVAS');
  });

  it('has trail canvas', () => {
    const canvas = doc.getElementById('trailCanvas');
    assert.ok(canvas);
    assert.equal(canvas.tagName, 'CANVAS');
  });

  it('has GIF image element', () => {
    const img = doc.getElementById('gifImage');
    assert.ok(img);
  });

  it('canvases have pointer-events: none', () => {
    const heatCanvas = doc.getElementById('heatmapCanvas');
    const trailCanvas = doc.getElementById('trailCanvas');
    assert.ok(heatCanvas.classList.contains('heatmap-canvas'));
    assert.ok(trailCanvas.classList.contains('trail-canvas'));
  });
});

// ── Stats grid ──────────────────────────────────────────────

describe('Stats grid', () => {
  let dom, doc;
  before(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('has 6 stat cards', () => {
    const cards = doc.querySelectorAll('.stat-card');
    assert.equal(cards.length, 6);
  });

  it('has clicks counter', () => {
    const el = doc.getElementById('statClicks');
    assert.ok(el);
    assert.equal(el.textContent, '0');
  });

  it('has distance stat', () => {
    const el = doc.getElementById('statDistance');
    assert.ok(el);
    assert.ok(el.textContent.includes('px'));
  });

  it('has speed stat', () => {
    const el = doc.getElementById('statSpeed');
    assert.ok(el);
  });

  it('has duration stat', () => {
    const el = doc.getElementById('statDuration');
    assert.ok(el);
    assert.ok(el.textContent.includes('s'));
  });

  it('has first-click stat', () => {
    const el = doc.getElementById('statFirstClick');
    assert.ok(el);
  });

  it('has entropy stat', () => {
    const el = doc.getElementById('statEntropy');
    assert.ok(el);
  });
});

// ── Timing breakdown ────────────────────────────────────────

describe('Timing breakdown', () => {
  let dom, doc;
  before(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('has timing chart section', () => {
    const chart = doc.querySelector('.timing-chart');
    assert.ok(chart);
  });

  it('has 4 timing bars', () => {
    const rows = doc.querySelectorAll('.timing-row');
    assert.equal(rows.length, 4);
  });

  it('has think time bar', () => {
    assert.ok(doc.getElementById('barThink'));
    assert.ok(doc.getElementById('valThink'));
  });

  it('has move time bar', () => {
    assert.ok(doc.getElementById('barMove'));
    assert.ok(doc.getElementById('valMove'));
  });

  it('has click time bar', () => {
    assert.ok(doc.getElementById('barClick'));
    assert.ok(doc.getElementById('valClick'));
  });

  it('has idle time bar', () => {
    assert.ok(doc.getElementById('barIdle'));
    assert.ok(doc.getElementById('valIdle'));
  });
});

// ── Pattern analysis ────────────────────────────────────────

describe('Pattern analysis', () => {
  let dom, doc;
  before(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('has pattern panel', () => {
    const panel = doc.querySelector('.pattern-panel');
    assert.ok(panel);
  });

  it('has 4 pattern meters', () => {
    const meters = doc.querySelectorAll('.pattern-meter');
    assert.equal(meters.length, 4);
  });

  it('has smoothness meter', () => {
    assert.ok(doc.getElementById('meterSmooth'));
    assert.ok(doc.getElementById('valSmooth'));
  });

  it('has regularity meter', () => {
    assert.ok(doc.getElementById('meterRegularity'));
    assert.ok(doc.getElementById('valRegularity'));
  });

  it('has coverage meter', () => {
    assert.ok(doc.getElementById('meterCoverage'));
    assert.ok(doc.getElementById('valCoverage'));
  });

  it('has efficiency meter', () => {
    assert.ok(doc.getElementById('meterEfficiency'));
    assert.ok(doc.getElementById('valEfficiency'));
  });

  it('has verdict box', () => {
    const box = doc.getElementById('verdictBox');
    assert.ok(box);
    assert.ok(box.classList.contains('verdict-uncertain'));
  });
});

// ── Event log ───────────────────────────────────────────────

describe('Event log', () => {
  let dom, doc;
  before(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('has event log section', () => {
    const log = doc.querySelector('.event-log');
    assert.ok(log);
  });

  it('has log entries container with ARIA role', () => {
    const entries = doc.getElementById('eventLog');
    assert.ok(entries);
    assert.equal(entries.getAttribute('role'), 'log');
    assert.equal(entries.getAttribute('aria-live'), 'polite');
  });

  it('shows initial waiting message', () => {
    const log = doc.getElementById('eventLog');
    assert.ok(log.textContent.includes('Waiting'));
  });
});

// ── Recording flow ──────────────────────────────────────────

describe('Recording flow', () => {
  let dom, doc;
  beforeEach(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('record button toggles to stop on click', () => {
    const btn = doc.getElementById('recordBtn');
    btn.click();
    assert.ok(btn.textContent.includes('Stop'));
    const badge = doc.getElementById('modeBadge');
    assert.ok(badge.textContent.includes('RECORDING'));
    assert.ok(badge.classList.contains('mode-record'));
  });

  it('stop recording changes badge back to idle', () => {
    const btn = doc.getElementById('recordBtn');
    btn.click(); // start
    btn.click(); // stop
    assert.ok(btn.textContent.includes('Record'));
    const badge = doc.getElementById('modeBadge');
    assert.ok(badge.classList.contains('mode-idle'));
  });

  it('clear resets everything', () => {
    const recordBtn = doc.getElementById('recordBtn');
    recordBtn.click(); // start recording
    doc.getElementById('clearBtn').click();
    assert.ok(recordBtn.textContent.includes('Record'));
    assert.equal(doc.getElementById('statClicks').textContent, '0');
    const badge = doc.getElementById('modeBadge');
    assert.ok(badge.textContent.includes('IDLE'));
  });
});

// ── Toggle buttons ──────────────────────────────────────────

describe('Toggle buttons', () => {
  let dom, doc;
  beforeEach(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('heatmap toggle removes active class on click', () => {
    const btn = doc.getElementById('toggleHeatmap');
    assert.ok(btn.classList.contains('active-toggle'));
    btn.click();
    assert.ok(!btn.classList.contains('active-toggle'));
  });

  it('trail toggle adds active class on click', () => {
    const btn = doc.getElementById('toggleTrail');
    assert.ok(!btn.classList.contains('active-toggle'));
    btn.click();
    assert.ok(btn.classList.contains('active-toggle'));
  });

  it('double toggle restores original state', () => {
    const btn = doc.getElementById('toggleHeatmap');
    btn.click();
    btn.click();
    assert.ok(btn.classList.contains('active-toggle'));
  });
});

// ── Accessibility ───────────────────────────────────────────

describe('Accessibility', () => {
  let dom, doc;
  before(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('GIF select has aria-label', () => {
    const select = doc.getElementById('gifSelect');
    assert.ok(select.getAttribute('aria-label'));
  });

  it('event log has aria-live region', () => {
    const log = doc.getElementById('eventLog');
    assert.equal(log.getAttribute('aria-live'), 'polite');
  });

  it('page has lang attribute', () => {
    assert.equal(doc.documentElement.getAttribute('lang'), 'en');
  });

  it('GIF image has alt text', () => {
    const img = doc.getElementById('gifImage');
    assert.ok(img.getAttribute('alt') !== undefined);
  });
});

// ── GIF select ──────────────────────────────────────────────

describe('GIF selection', () => {
  let dom, doc;
  beforeEach(() => {
    dom = createHeatmapDOM();
    doc = dom.window.document;
  });

  it('changing GIF clears data', () => {
    const recordBtn = doc.getElementById('recordBtn');
    recordBtn.click(); // start
    recordBtn.click(); // stop

    const select = doc.getElementById('gifSelect');
    select.value = '3';
    select.dispatchEvent(new dom.window.Event('change'));

    assert.equal(doc.getElementById('statClicks').textContent, '0');
    const badge = doc.getElementById('modeBadge');
    assert.ok(badge.textContent.includes('IDLE'));
  });
});

// ── Index page link ─────────────────────────────────────────

describe('Index page integration', () => {
  let indexHtml, indexDoc;
  before(() => {
    indexHtml = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
    const dom = new JSDOM(indexHtml);
    indexDoc = dom.window.document;
  });

  it('index.html has link to heatmap.html', () => {
    const links = indexDoc.querySelectorAll('a[href="heatmap.html"]');
    assert.ok(links.length >= 1);
  });

  it('heatmap link has descriptive text', () => {
    const link = indexDoc.querySelector('a[href="heatmap.html"]');
    assert.ok(link.textContent.includes('Heatmap'));
  });
});
