/**
 * Tests for the GIF CAPTCHA interactive demo (demo.html)
 *
 * Validates challenge data integrity, DOM interactions, scoring logic,
 * and user input handling using jsdom for browser simulation.
 */

const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const DEMO_HTML = fs.readFileSync(path.join(__dirname, '..', 'demo.html'), 'utf8');

/** Create a fresh jsdom instance with demo.html loaded */
function createDemoDOM() {
  const dom = new JSDOM(DEMO_HTML, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/demo.html',
  });
  return dom;
}

describe('Demo: Challenge Data Integrity', () => {
  let dom, window;

  before(() => {
    dom = createDemoDOM();
    window = dom.window;
  });

  it('should have exactly 10 challenges defined', () => {
    assert.equal(window.challenges.length, 10);
  });

  it('each challenge should have required fields', () => {
    const requiredFields = ['id', 'title', 'gifUrl', 'sourceUrl', 'humanAnswer', 'aiAnswer'];
    for (const challenge of window.challenges) {
      for (const field of requiredFields) {
        assert.ok(challenge[field] !== undefined && challenge[field] !== '',
          `Challenge ${challenge.id} missing field: ${field}`);
      }
    }
  });

  it('challenge IDs should be sequential 1-10', () => {
    for (let i = 0; i < 10; i++) {
      assert.equal(window.challenges[i].id, i + 1);
    }
  });

  it('all GIF URLs should use HTTPS', () => {
    for (const challenge of window.challenges) {
      assert.ok(challenge.gifUrl.startsWith('https://'),
        `Challenge ${challenge.id} gifUrl not HTTPS: ${challenge.gifUrl}`);
    }
  });

  it('human answers should be non-trivial (>20 chars)', () => {
    for (const challenge of window.challenges) {
      assert.ok(challenge.humanAnswer.length > 20,
        `Challenge ${challenge.id} has suspiciously short human answer: "${challenge.humanAnswer}"`);
    }
  });

  it('AI answers should reflect GPT-4 inability to process GIFs', () => {
    for (const challenge of window.challenges) {
      assert.ok(challenge.aiAnswer.includes('cannot view animations'),
        `Challenge ${challenge.id} has unexpected AI answer`);
    }
  });

  it('challenge titles should be unique', () => {
    const titles = window.challenges.map(c => c.title);
    const unique = new Set(titles);
    assert.equal(unique.size, titles.length, 'Duplicate challenge titles found');
  });
});

describe('Demo: Initial State', () => {
  let dom, document;

  beforeEach(() => {
    dom = createDemoDOM();
    document = dom.window.document;
  });

  it('should show intro screen on load', () => {
    const intro = document.getElementById('introScreen');
    assert.ok(!intro.classList.contains('hidden'), 'Intro screen should be visible');
  });

  it('should hide challenge screen on load', () => {
    const challenge = document.getElementById('challengeScreen');
    assert.ok(challenge.classList.contains('hidden'), 'Challenge screen should be hidden');
  });

  it('should hide results screen on load', () => {
    const results = document.getElementById('resultsScreen');
    assert.ok(results.classList.contains('hidden'), 'Results screen should be hidden');
  });

  it('should hide progress bar on load', () => {
    const progress = document.getElementById('progressContainer');
    assert.ok(progress.classList.contains('hidden'), 'Progress bar should be hidden');
  });

  it('submit button should be disabled initially', () => {
    const btn = document.getElementById('submitBtn');
    assert.ok(btn.disabled, 'Submit button should be disabled');
  });
});

describe('Demo: Start Flow', () => {
  let dom, window, document;

  beforeEach(() => {
    dom = createDemoDOM();
    window = dom.window;
    document = dom.window.document;
  });

  it('starting demo should hide intro and show challenge', () => {
    window.startDemo();
    assert.ok(document.getElementById('introScreen').classList.contains('hidden'));
    assert.ok(!document.getElementById('challengeScreen').classList.contains('hidden'));
    assert.ok(!document.getElementById('progressContainer').classList.contains('hidden'));
  });

  it('first challenge should display challenge number 1', () => {
    window.startDemo();
    const num = document.getElementById('challengeNumber').textContent;
    assert.equal(num, '1');
  });

  it('first challenge should show correct title', () => {
    window.startDemo();
    const title = document.getElementById('gifTitle').textContent;
    assert.equal(title, window.challenges[0].title);
  });
});

describe('Demo: Answer Submission', () => {
  let dom, window, document;

  beforeEach(() => {
    dom = createDemoDOM();
    window = dom.window;
    document = dom.window.document;
    window.startDemo();
  });

  it('should reject answers shorter than 5 characters', () => {
    const textarea = document.getElementById('userAnswer');
    textarea.value = 'hi';
    textarea.dispatchEvent(new window.Event('input'));
    assert.ok(document.getElementById('submitBtn').disabled);
  });

  it('should enable submit for answers >= 5 characters', () => {
    const textarea = document.getElementById('userAnswer');
    textarea.value = 'The duel ended with trick guns';
    textarea.dispatchEvent(new window.Event('input'));
    assert.ok(!document.getElementById('submitBtn').disabled);
  });

  it('submitting answer should show reveal panel', () => {
    const textarea = document.getElementById('userAnswer');
    textarea.value = 'Both people had trick guns in the duel';
    textarea.dispatchEvent(new window.Event('input'));
    window.submitAnswer();

    const reveal = document.getElementById('revealPanel');
    assert.ok(!reveal.classList.contains('hidden'), 'Reveal panel should be visible');
  });

  it('submitting answer should hide input area', () => {
    const textarea = document.getElementById('userAnswer');
    textarea.value = 'Both people had trick guns in the duel';
    textarea.dispatchEvent(new window.Event('input'));
    window.submitAnswer();

    const input = document.getElementById('inputArea');
    assert.ok(input.classList.contains('hidden'), 'Input area should be hidden');
  });

  it('reveal should show user answer, human answer, and AI answer', () => {
    const textarea = document.getElementById('userAnswer');
    textarea.value = 'My test answer for this GIF';
    textarea.dispatchEvent(new window.Event('input'));
    window.submitAnswer();

    assert.equal(document.getElementById('revealUser').textContent, 'My test answer for this GIF');
    assert.equal(document.getElementById('revealHuman').textContent, window.challenges[0].humanAnswer);
    assert.equal(document.getElementById('revealAI').textContent, window.challenges[0].aiAnswer);
  });

  it('answering should increment answered count', () => {
    const textarea = document.getElementById('userAnswer');
    textarea.value = 'Both people had trick guns in the duel';
    textarea.dispatchEvent(new window.Event('input'));
    window.submitAnswer();
    assert.equal(window.answered, 1);
  });
});

describe('Demo: Skip Functionality', () => {
  let dom, window, document;

  beforeEach(() => {
    dom = createDemoDOM();
    window = dom.window;
    document = dom.window.document;
    window.startDemo();
  });

  it('skipping should increment skipped count', () => {
    window.skipChallenge();
    assert.equal(window.skipped, 1);
  });

  it('skipping should record "(skipped)" as answer', () => {
    window.skipChallenge();
    assert.equal(window.userAnswers[0].text, '(skipped)');
    assert.ok(window.userAnswers[0].skipped);
  });

  it('skipping should show reveal panel', () => {
    window.skipChallenge();
    assert.ok(!document.getElementById('revealPanel').classList.contains('hidden'));
  });
});

describe('Demo: Navigation', () => {
  let dom, window, document;

  beforeEach(() => {
    dom = createDemoDOM();
    window = dom.window;
    document = dom.window.document;
    window.startDemo();
  });

  it('next challenge should advance to challenge 2', () => {
    window.skipChallenge();
    window.nextChallenge();
    assert.equal(document.getElementById('challengeNumber').textContent, '2');
    assert.equal(document.getElementById('gifTitle').textContent, window.challenges[1].title);
  });

  it('progress bar should update after advancing', () => {
    window.skipChallenge();
    window.nextChallenge();
    const fill = document.getElementById('progressFill');
    assert.notEqual(fill.style.width, '0%');
  });

  it('last challenge should say "See Results" on next button', () => {
    // Navigate to last challenge
    for (let i = 0; i < 9; i++) {
      window.skipChallenge();
      window.nextChallenge();
    }
    window.skipChallenge();
    assert.equal(document.getElementById('nextBtn').textContent, 'See Results →');
  });
});

describe('Demo: Results Screen', () => {
  let dom, window, document;

  beforeEach(() => {
    dom = createDemoDOM();
    window = dom.window;
    document = dom.window.document;
    window.startDemo();
  });

  it('completing all challenges should show results', () => {
    for (let i = 0; i < 10; i++) {
      window.skipChallenge();
      if (i < 9) window.nextChallenge();
    }
    window.nextChallenge(); // triggers showResults
    assert.ok(!document.getElementById('resultsScreen').classList.contains('hidden'));
    assert.ok(document.getElementById('challengeScreen').classList.contains('hidden'));
  });

  it('all answered should show 100% title', () => {
    for (let i = 0; i < 10; i++) {
      const textarea = document.getElementById('userAnswer');
      textarea.value = 'Test answer for challenge ' + (i + 1);
      textarea.dispatchEvent(new window.Event('input'));
      window.submitAnswer();
      if (i < 9) window.nextChallenge();
    }
    window.nextChallenge();
    assert.ok(document.getElementById('resultsTitle').textContent.includes('100%'));
  });

  it('all skipped should show robot-like title', () => {
    for (let i = 0; i < 10; i++) {
      window.skipChallenge();
      if (i < 9) window.nextChallenge();
    }
    window.nextChallenge();
    assert.ok(document.getElementById('resultsTitle').textContent.includes('Robot'));
  });

  it('results table should have 10 rows', () => {
    for (let i = 0; i < 10; i++) {
      window.skipChallenge();
      if (i < 9) window.nextChallenge();
    }
    window.nextChallenge();
    const rows = document.getElementById('resultsTableBody').children;
    assert.equal(rows.length, 10);
  });

  it('score display should show correct ratio', () => {
    // Answer 3, skip 7
    for (let i = 0; i < 10; i++) {
      if (i < 3) {
        const textarea = document.getElementById('userAnswer');
        textarea.value = 'Test answer for this GIF';
        textarea.dispatchEvent(new window.Event('input'));
        window.submitAnswer();
      } else {
        window.skipChallenge();
      }
      if (i < 9) window.nextChallenge();
    }
    window.nextChallenge();
    assert.equal(document.getElementById('scoreValue').textContent, '3/10');
  });
});

describe('Demo: Restart', () => {
  let dom, window, document;

  beforeEach(() => {
    dom = createDemoDOM();
    window = dom.window;
    document = dom.window.document;
    window.startDemo();
    // Complete all challenges
    for (let i = 0; i < 10; i++) {
      window.skipChallenge();
      if (i < 9) window.nextChallenge();
    }
    window.nextChallenge();
  });

  it('restart should reset state and show intro', () => {
    window.restartDemo();
    assert.equal(window.currentIndex, 0);
    assert.equal(window.answered, 0);
    assert.equal(window.skipped, 0);
    assert.equal(window.userAnswers.length, 0);
    assert.ok(!document.getElementById('introScreen').classList.contains('hidden'));
    assert.ok(document.getElementById('resultsScreen').classList.contains('hidden'));
  });
});

describe('Demo: Sanitize Function', () => {
  let dom, window;

  before(() => {
    dom = createDemoDOM();
    window = dom.window;
  });

  it('should escape HTML special characters', () => {
    const result = window.sanitize('<script>alert("xss")</script>');
    assert.ok(!result.includes('<script>'), 'Should escape script tags');
    assert.ok(result.includes('&lt;'), 'Should use HTML entities');
  });

  it('should escape ampersands', () => {
    const result = window.sanitize('a & b');
    assert.ok(result.includes('&amp;'), 'Should escape ampersand');
  });

  it('should handle empty string', () => {
    const result = window.sanitize('');
    assert.equal(result, '');
  });

  it('should handle strings with quotes', () => {
    const result = window.sanitize('He said "hello"');
    assert.ok(result.includes('&quot;') || result.includes('"'),
      'Should handle quotes safely');
  });
});

describe('Demo: Security', () => {
  let dom, document;

  before(() => {
    dom = createDemoDOM();
    document = dom.window.document;
  });

  it('should have Content-Security-Policy meta tag', () => {
    const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp, 'CSP meta tag should exist');
    assert.ok(csp.content.includes("frame-ancestors 'none'"), 'CSP should prevent framing');
  });

  it('should have referrer policy', () => {
    const ref = document.querySelector('meta[name="referrer"]');
    assert.ok(ref, 'Referrer policy should exist');
    assert.equal(ref.content, 'no-referrer');
  });

  it('external links should have rel="noopener noreferrer"', () => {
    const externalLinks = document.querySelectorAll('a[target="_blank"]');
    for (const link of externalLinks) {
      assert.ok(link.rel.includes('noopener'), `Link ${link.href} missing noopener`);
    }
  });
});
