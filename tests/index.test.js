/**
 * Tests for the GIF CAPTCHA case study page (index.html)
 *
 * Validates static content, table structure, link integrity,
 * and security headers.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const INDEX_HTML = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

function createIndexDOM() {
  return new JSDOM(INDEX_HTML, {
    url: 'https://example.com/index.html',
  });
}

describe('Index: Page Structure', () => {
  let dom, document;

  before(() => {
    dom = createIndexDOM();
    document = dom.window.document;
  });

  it('should have a page title', () => {
    assert.ok(document.title.includes('GIF CAPTCHA'), 'Title should mention GIF CAPTCHA');
  });

  it('should have an h1 heading', () => {
    const h1 = document.querySelector('h1');
    assert.ok(h1, 'Page should have an h1');
    assert.ok(h1.textContent.includes('GIF CAPTCHA'));
  });

  it('should have a methodology section', () => {
    const h2s = Array.from(document.querySelectorAll('h2'));
    const methodology = h2s.find(h => h.textContent.includes('Methodology'));
    assert.ok(methodology, 'Should have Methodology section');
  });

  it('should have a results section', () => {
    const h2s = Array.from(document.querySelectorAll('h2'));
    const results = h2s.find(h => h.textContent.includes('Results'));
    assert.ok(results, 'Should have Results section');
  });
});

describe('Index: Results Table', () => {
  let dom, document;

  before(() => {
    dom = createIndexDOM();
    document = dom.window.document;
  });

  it('should have a results table with 10 data rows', () => {
    const table = document.querySelector('table');
    assert.ok(table, 'Results table should exist');
    const rows = table.querySelectorAll('tbody tr');
    assert.equal(rows.length, 10, 'Should have 10 GIF result rows');
  });

  it('all results should show CAPTCHA PASS', () => {
    const badges = document.querySelectorAll('.badge-pass');
    assert.equal(badges.length, 10, 'All 10 should be CAPTCHA PASS');
    assert.equal(document.querySelectorAll('.badge-fail').length, 0, 'No failures');
  });

  it('table should have correct column headers', () => {
    const headers = Array.from(document.querySelectorAll('table thead th'))
      .map(th => th.textContent.trim());
    assert.ok(headers.includes('#'));
    assert.ok(headers.includes('GIF'));
    assert.ok(headers.includes('Human Response'));
    assert.ok(headers.includes('GPT-4 Response'));
    assert.ok(headers.includes('Result'));
  });
});

describe('Index: Key Findings', () => {
  let dom, document;

  before(() => {
    dom = createIndexDOM();
    document = dom.window.document;
  });

  it('should have original 2023 finding', () => {
    const findings = document.querySelectorAll('.finding');
    assert.ok(findings.length >= 1, 'Should have at least one finding');
    const successFinding = document.querySelector('.finding.success');
    assert.ok(successFinding, 'Should have a success finding');
    assert.ok(successFinding.textContent.includes('10/10'),
      'Should mention 10/10 score');
  });

  it('should have 2025 update warning', () => {
    const warningFinding = document.querySelector('.finding.warning');
    assert.ok(warningFinding, 'Should have a warning finding');
    assert.ok(warningFinding.textContent.includes('2025'),
      'Should mention 2025 update');
    assert.ok(warningFinding.textContent.includes('no longer sufficient'),
      'Should note GIF CAPTCHAs are weakening');
  });
});

describe('Index: Navigation Links', () => {
  let dom, document;

  before(() => {
    dom = createIndexDOM();
    document = dom.window.document;
  });

  it('should have link to demo page', () => {
    const demoLink = document.querySelector('a[href="demo.html"]');
    assert.ok(demoLink, 'Should link to demo.html');
  });

  it('should have link to analysis page', () => {
    const analysisLink = document.querySelector('a[href="analysis.html"]');
    assert.ok(analysisLink, 'Should link to analysis.html');
  });

  it('should have link to GitHub repo', () => {
    const links = Array.from(document.querySelectorAll('a'));
    const githubLink = links.find(a =>
      a.href.includes('github.com/sauravbhattacharya001/gif-captcha'));
    assert.ok(githubLink, 'Should link to GitHub repo');
  });

  it('external links should have rel="noopener noreferrer"', () => {
    const externalLinks = document.querySelectorAll('a[href^="https://"]');
    for (const link of externalLinks) {
      assert.ok(link.rel.includes('noopener'),
        `External link ${link.href} missing noopener`);
    }
  });
});

describe('Index: Security', () => {
  let dom, document;

  before(() => {
    dom = createIndexDOM();
    document = dom.window.document;
  });

  it('should have Content-Security-Policy', () => {
    const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp, 'CSP meta tag should exist');
  });

  it('CSP should block scripts (no script-src)', () => {
    const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    // index.html has no scripts, so CSP should not allow scripts
    assert.ok(!csp.content.includes('script-src') || csp.content.includes("default-src 'none'"),
      'Index page should have restrictive script policy');
  });

  it('should have referrer policy', () => {
    const ref = document.querySelector('meta[name="referrer"]');
    assert.ok(ref, 'Referrer policy meta tag should exist');
  });

  it('should not have form-action allowing arbitrary targets', () => {
    const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp.content.includes("form-action 'none'") || csp.content.includes("form-action 'self'"),
      'Form action should be restricted');
  });
});

describe('Index: Accessibility', () => {
  let dom, document;

  before(() => {
    dom = createIndexDOM();
    document = dom.window.document;
  });

  it('should have lang attribute on html', () => {
    assert.equal(document.documentElement.getAttribute('lang'), 'en');
  });

  it('should have charset UTF-8', () => {
    const meta = document.querySelector('meta[charset]');
    assert.ok(meta, 'Should have charset meta');
    assert.equal(meta.getAttribute('charset'), 'UTF-8');
  });

  it('should have viewport meta tag', () => {
    const viewport = document.querySelector('meta[name="viewport"]');
    assert.ok(viewport, 'Should have viewport meta');
    assert.ok(viewport.content.includes('width=device-width'));
  });
});
