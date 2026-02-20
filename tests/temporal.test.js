/**
 * Tests for the Temporal Sequence Challenge (temporal.html)
 *
 * Validates challenge data integrity, scoring algorithms, DOM interactions,
 * drag-and-drop ordering, and results calculations using jsdom.
 */

const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const TEMPORAL_HTML = fs.readFileSync(path.join(__dirname, '..', 'temporal.html'), 'utf8');

/** Create a fresh jsdom instance with temporal.html loaded */
function createTemporalDOM() {
  const dom = new JSDOM(TEMPORAL_HTML, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/temporal.html',
  });
  return dom;
}

describe('Temporal: Challenge Data Integrity', () => {
  let dom, window, TC;

  before(() => {
    dom = createTemporalDOM();
    window = dom.window;
    TC = window.TemporalChallenge;
  });

  it('should have exactly 10 challenges defined', () => {
    assert.equal(TC._challenges.length, 10);
  });

  it('each challenge should have required fields', () => {
    const requiredFields = ['id', 'title', 'gifUrl', 'sourceUrl', 'events', 'aiNote'];
    for (const challenge of TC._challenges) {
      for (const field of requiredFields) {
        assert.ok(challenge[field] !== undefined && challenge[field] !== '',
          `Challenge ${challenge.id} missing field: ${field}`);
      }
    }
  });

  it('each challenge should have exactly 4 events', () => {
    for (const challenge of TC._challenges) {
      assert.equal(challenge.events.length, 4,
        `Challenge ${challenge.id} ("${challenge.title}") should have 4 events, has ${challenge.events.length}`);
    }
  });

  it('challenge IDs should be sequential 1-10', () => {
    for (let i = 0; i < 10; i++) {
      assert.equal(TC._challenges[i].id, i + 1);
    }
  });

  it('each event text should be non-empty', () => {
    for (const challenge of TC._challenges) {
      for (let i = 0; i < challenge.events.length; i++) {
        assert.ok(challenge.events[i].trim().length > 0,
          `Challenge ${challenge.id} event ${i} is empty`);
      }
    }
  });

  it('each challenge should have a non-empty AI note', () => {
    for (const challenge of TC._challenges) {
      assert.ok(challenge.aiNote.trim().length > 10,
        `Challenge ${challenge.id} aiNote is too short`);
    }
  });

  it('GIF URLs should use HTTPS', () => {
    for (const challenge of TC._challenges) {
      assert.ok(challenge.gifUrl.startsWith('https://'),
        `Challenge ${challenge.id} gifUrl should use HTTPS: ${challenge.gifUrl}`);
    }
  });

  it('events within a challenge should all be unique', () => {
    for (const challenge of TC._challenges) {
      const unique = new Set(challenge.events);
      assert.equal(unique.size, challenge.events.length,
        `Challenge ${challenge.id} has duplicate events`);
    }
  });
});

describe('Temporal: Scoring Algorithm (_scoreOrder)', () => {
  let TC;

  before(() => {
    const dom = createTemporalDOM();
    TC = dom.window.TemporalChallenge;
  });

  it('should return 100 for perfect order', () => {
    const correct = ['A', 'B', 'C', 'D'];
    assert.equal(TC._scoreOrder(correct, correct), 100);
  });

  it('should return 0 for completely reversed order', () => {
    const correct = ['A', 'B', 'C', 'D'];
    const reversed = ['D', 'C', 'B', 'A'];
    assert.equal(TC._scoreOrder(reversed, correct), 0);
  });

  it('should return intermediate score for partial order', () => {
    const correct = ['A', 'B', 'C', 'D'];
    const partial = ['A', 'C', 'B', 'D']; // One swap: B and C
    const score = TC._scoreOrder(partial, correct);
    assert.ok(score > 0 && score < 100,
      `Partial order should score between 0 and 100, got ${score}`);
  });

  it('should score higher for fewer inversions', () => {
    const correct = ['A', 'B', 'C', 'D'];
    const oneSwap = ['A', 'C', 'B', 'D']; // 1 inversion
    const twoSwaps = ['B', 'A', 'D', 'C']; // 2 inversions
    const scoreOne = TC._scoreOrder(oneSwap, correct);
    const scoreTwo = TC._scoreOrder(twoSwaps, correct);
    assert.ok(scoreOne > scoreTwo,
      `One-swap (${scoreOne}) should score higher than two-swaps (${scoreTwo})`);
  });

  it('should handle single swap correctly', () => {
    const correct = ['A', 'B', 'C', 'D'];
    const swapped = ['B', 'A', 'C', 'D']; // Only first two swapped
    const score = TC._scoreOrder(swapped, correct);
    // 6 pairs: (B,A)=wrong, (B,C)=right, (B,D)=right, (A,C)=right, (A,D)=right, (C,D)=right
    // 5 concordant out of 6 = 83%
    assert.equal(score, 83);
  });

  it('should score with actual challenge data', () => {
    const c = TC._challenges[0];
    assert.equal(TC._scoreOrder(c.events, c.events), 100);
  });

  it('should handle all same-position but wrong pairs', () => {
    const correct = ['A', 'B', 'C', 'D'];
    // Shift by 1: [B, C, D, A] — has some concordant, some not
    const shifted = ['B', 'C', 'D', 'A'];
    const score = TC._scoreOrder(shifted, correct);
    assert.ok(score >= 0 && score <= 100);
  });
});

describe('Temporal: Exact Matches (_exactMatches)', () => {
  let TC;

  before(() => {
    const dom = createTemporalDOM();
    TC = dom.window.TemporalChallenge;
  });

  it('should return 4 for perfect match', () => {
    const order = ['A', 'B', 'C', 'D'];
    assert.equal(TC._exactMatches(order, order), 4);
  });

  it('should return 0 when nothing matches', () => {
    const correct = ['A', 'B', 'C', 'D'];
    const wrong = ['D', 'C', 'B', 'A'];
    assert.equal(TC._exactMatches(wrong, correct), 0);
  });

  it('should return correct count for partial matches', () => {
    const correct = ['A', 'B', 'C', 'D'];
    const partial = ['A', 'C', 'B', 'D']; // A and D in position
    assert.equal(TC._exactMatches(partial, correct), 2);
  });

  it('should handle single position match', () => {
    const correct = ['A', 'B', 'C', 'D'];
    const oneMatch = ['A', 'D', 'B', 'C']; // Only A in position
    assert.equal(TC._exactMatches(oneMatch, correct), 1);
  });
});

describe('Temporal: Shuffle Algorithm (_shuffleArray)', () => {
  let TC;

  before(() => {
    const dom = createTemporalDOM();
    TC = dom.window.TemporalChallenge;
  });

  it('should return array of same length', () => {
    const arr = [1, 2, 3, 4, 5];
    const shuffled = TC._shuffleArray(arr);
    assert.equal(shuffled.length, arr.length);
  });

  it('should contain all original elements', () => {
    const arr = ['A', 'B', 'C', 'D'];
    const shuffled = TC._shuffleArray(arr);
    assert.deepEqual(shuffled.sort(), arr.slice().sort());
  });

  it('should not modify the original array', () => {
    const arr = [1, 2, 3, 4];
    const original = arr.slice();
    TC._shuffleArray(arr);
    assert.deepEqual(arr, original);
  });

  it('should produce a different order at least sometimes (statistical)', () => {
    const arr = [1, 2, 3, 4, 5, 6, 7, 8];
    let different = false;
    for (let i = 0; i < 20; i++) {
      const shuffled = TC._shuffleArray(arr);
      if (shuffled.join(',') !== arr.join(',')) {
        different = true;
        break;
      }
    }
    assert.ok(different, 'Shuffle should produce a different order at least once in 20 tries');
  });

  it('should handle single-element array', () => {
    const arr = ['only'];
    const shuffled = TC._shuffleArray(arr);
    assert.deepEqual(shuffled, ['only']);
  });

  it('should handle empty array', () => {
    const shuffled = TC._shuffleArray([]);
    assert.deepEqual(shuffled, []);
  });
});

describe('Temporal: DOM - Initial State', () => {
  let dom, window, doc;

  before(() => {
    dom = createTemporalDOM();
    window = dom.window;
    doc = window.document;
  });

  it('should show intro screen by default', () => {
    const intro = doc.getElementById('introScreen');
    assert.ok(!intro.classList.contains('hidden'), 'Intro should be visible');
  });

  it('should hide challenge screen by default', () => {
    const challenge = doc.getElementById('challengeScreen');
    assert.ok(challenge.classList.contains('hidden'), 'Challenge should be hidden');
  });

  it('should hide progress bar by default', () => {
    const progress = doc.getElementById('progressContainer');
    assert.ok(progress.classList.contains('hidden'), 'Progress should be hidden');
  });

  it('should hide results screen by default', () => {
    const results = doc.getElementById('resultsScreen');
    assert.ok(results.classList.contains('hidden'), 'Results should be hidden');
  });

  it('should have a start button in intro', () => {
    const btn = doc.querySelector('.intro .btn-primary');
    assert.ok(btn, 'Start button should exist');
    assert.ok(btn.textContent.includes('Start'), 'Button should say Start');
  });

  it('should have navigation links', () => {
    const links = doc.querySelectorAll('.nav-links a');
    assert.ok(links.length >= 4, 'Should have at least 4 nav links');
  });

  it('should have correct page title', () => {
    assert.ok(doc.title.includes('Temporal'), 'Title should mention Temporal');
  });

  it('should include Content-Security-Policy meta tag', () => {
    const csp = doc.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp, 'CSP meta tag should exist');
  });

  it('should have research note in intro', () => {
    const note = doc.querySelector('.research-note');
    assert.ok(note, 'Research note should exist');
    assert.ok(note.textContent.includes('Temporal'), 'Research note should mention temporal');
  });
});

describe('Temporal: DOM - Challenge Flow', () => {
  let dom, window, doc, TC;

  beforeEach(() => {
    dom = createTemporalDOM();
    window = dom.window;
    doc = window.document;
    TC = window.TemporalChallenge;
  });

  it('should show challenge screen after start', () => {
    TC.start();
    assert.ok(!doc.getElementById('challengeScreen').classList.contains('hidden'));
    assert.ok(doc.getElementById('introScreen').classList.contains('hidden'));
    assert.ok(!doc.getElementById('progressContainer').classList.contains('hidden'));
  });

  it('should show first challenge after start', () => {
    TC.start();
    assert.equal(doc.getElementById('challengeNumber').textContent, '1');
  });

  it('should render 4 sequence items', () => {
    TC.start();
    const items = doc.querySelectorAll('.sequence-item');
    assert.equal(items.length, 4);
  });

  it('should show correct title for first challenge', () => {
    TC.start();
    assert.equal(doc.getElementById('gifTitle').textContent, TC._challenges[0].title);
  });

  it('should number items 1-4', () => {
    TC.start();
    const nums = doc.querySelectorAll('.order-num');
    for (let i = 0; i < 4; i++) {
      assert.equal(nums[i].textContent, String(i + 1));
    }
  });

  it('should have drag handles on each item', () => {
    TC.start();
    const handles = doc.querySelectorAll('.drag-handle');
    assert.equal(handles.length, 4);
  });

  it('should have move buttons on each item', () => {
    TC.start();
    const upBtns = doc.querySelectorAll('.move-btn');
    assert.equal(upBtns.length, 8); // 4 items × 2 buttons (up + down)
  });

  it('should hide feedback panel initially', () => {
    TC.start();
    assert.ok(doc.getElementById('feedbackPanel').classList.contains('hidden'));
  });

  it('should show sequence area initially', () => {
    TC.start();
    assert.ok(!doc.getElementById('sequenceArea').classList.contains('hidden'));
  });
});

describe('Temporal: DOM - Submit and Feedback', () => {
  let dom, window, doc, TC;

  beforeEach(() => {
    dom = createTemporalDOM();
    window = dom.window;
    doc = window.document;
    TC = window.TemporalChallenge;
    TC.start();
  });

  it('should show feedback after submit', () => {
    TC.submit();
    assert.ok(!doc.getElementById('feedbackPanel').classList.contains('hidden'));
    assert.ok(doc.getElementById('sequenceArea').classList.contains('hidden'));
  });

  it('should show correct order in feedback', () => {
    TC.submit();
    const items = doc.querySelectorAll('.correct-item');
    assert.equal(items.length, 4);
  });

  it('should show AI note in feedback', () => {
    TC.submit();
    const aiNote = doc.querySelector('.ai-note');
    assert.ok(aiNote, 'AI note should be present');
    assert.ok(aiNote.textContent.includes('AI'), 'Should mention AI');
  });

  it('should show feedback header with score', () => {
    TC.submit();
    const header = doc.querySelector('.feedback-header');
    assert.ok(header, 'Feedback header should exist');
    assert.ok(header.querySelector('.feedback-score'), 'Score should be visible');
  });

  it('should show "Next Challenge" button after submit', () => {
    TC.submit();
    const nextBtn = doc.getElementById('nextBtn');
    assert.ok(nextBtn.textContent.includes('Next'));
  });

  it('should advance to next challenge on next()', () => {
    TC.submit();
    TC.next();
    assert.equal(doc.getElementById('challengeNumber').textContent, '2');
  });

  it('should update progress bar', () => {
    TC.submit();
    TC.next();
    const fill = doc.getElementById('progressFill');
    assert.ok(parseFloat(fill.style.width) > 0, 'Progress should advance');
  });
});

describe('Temporal: DOM - Skip', () => {
  let dom, window, doc, TC;

  beforeEach(() => {
    dom = createTemporalDOM();
    window = dom.window;
    doc = window.document;
    TC = window.TemporalChallenge;
    TC.start();
  });

  it('should show feedback after skip', () => {
    TC.skip();
    assert.ok(!doc.getElementById('feedbackPanel').classList.contains('hidden'));
  });

  it('should show "Skipped" in feedback', () => {
    TC.skip();
    const text = doc.querySelector('.feedback-text');
    assert.ok(text.textContent.includes('Skipped'));
  });

  it('should show 0% score for skip', () => {
    TC.skip();
    const score = doc.querySelector('.feedback-score');
    assert.ok(score.textContent.includes('0%'));
  });
});

describe('Temporal: DOM - Shuffle', () => {
  let dom, window, doc, TC;

  beforeEach(() => {
    dom = createTemporalDOM();
    window = dom.window;
    doc = window.document;
    TC = window.TemporalChallenge;
    TC.start();
  });

  it('should maintain 4 items after shuffle', () => {
    TC.shuffle();
    const items = doc.querySelectorAll('.sequence-item');
    assert.equal(items.length, 4);
  });

  it('should keep same event texts after shuffle', () => {
    const beforeTexts = Array.from(doc.querySelectorAll('.event-text')).map(function(el) { return el.textContent; }).sort();
    TC.shuffle();
    const afterTexts = Array.from(doc.querySelectorAll('.event-text')).map(function(el) { return el.textContent; }).sort();
    assert.deepEqual(afterTexts, beforeTexts);
  });

  it('should re-number items after shuffle', () => {
    TC.shuffle();
    const nums = doc.querySelectorAll('.order-num');
    for (let i = 0; i < 4; i++) {
      assert.equal(nums[i].textContent, String(i + 1));
    }
  });
});

describe('Temporal: DOM - Results Screen', () => {
  let dom, window, doc, TC;

  beforeEach(() => {
    dom = createTemporalDOM();
    window = dom.window;
    doc = window.document;
    TC = window.TemporalChallenge;
    TC.start();
  });

  it('should show results after all 10 challenges', () => {
    for (let i = 0; i < 10; i++) {
      TC.submit();
      TC.next();
    }
    assert.ok(!doc.getElementById('resultsScreen').classList.contains('hidden'));
    assert.ok(doc.getElementById('challengeScreen').classList.contains('hidden'));
  });

  it('should show "See Results" on last challenge', () => {
    for (let i = 0; i < 9; i++) {
      TC.submit();
      TC.next();
    }
    // Now on challenge 10
    TC.submit();
    const btn = doc.getElementById('nextBtn');
    assert.ok(btn.textContent.includes('Results'));
  });

  it('should show score percentage in results', () => {
    for (let i = 0; i < 10; i++) {
      TC.submit();
      TC.next();
    }
    const scoreEl = doc.querySelector('.score-display');
    assert.ok(scoreEl, 'Score display should exist');
    assert.ok(scoreEl.textContent.includes('%'), 'Should show percentage');
  });

  it('should show 3 stat cards', () => {
    for (let i = 0; i < 10; i++) {
      TC.submit();
      TC.next();
    }
    const cards = doc.querySelectorAll('.result-card');
    assert.equal(cards.length, 3);
  });

  it('should show per-challenge breakdown', () => {
    for (let i = 0; i < 10; i++) {
      TC.submit();
      TC.next();
    }
    const items = doc.querySelectorAll('.breakdown-item');
    assert.equal(items.length, 10);
  });

  it('should show skipped count when challenges skipped', () => {
    for (let i = 0; i < 10; i++) {
      if (i < 3) TC.skip(); else TC.submit();
      TC.next();
    }
    const resultsHTML = doc.getElementById('resultsScreen').innerHTML;
    assert.ok(resultsHTML.includes('3/10') || resultsHTML.includes('3'),
      'Should show 3 skipped');
  });

  it('should show research note in results', () => {
    for (let i = 0; i < 10; i++) {
      TC.submit();
      TC.next();
    }
    const research = doc.querySelector('.results-research');
    assert.ok(research, 'Research note should exist');
  });
});

describe('Temporal: DOM - Restart', () => {
  let dom, window, doc, TC;

  beforeEach(() => {
    dom = createTemporalDOM();
    window = dom.window;
    doc = window.document;
    TC = window.TemporalChallenge;
  });

  it('should show intro screen after restart', () => {
    TC.start();
    for (let i = 0; i < 10; i++) {
      TC.submit();
      TC.next();
    }
    TC.restart();
    assert.ok(!doc.getElementById('introScreen').classList.contains('hidden'));
    assert.ok(doc.getElementById('resultsScreen').classList.contains('hidden'));
  });

  it('should allow starting again after restart', () => {
    TC.start();
    TC.submit();
    TC.next();
    TC.restart();
    TC.start();
    assert.equal(doc.getElementById('challengeNumber').textContent, '1');
  });
});

describe('Temporal: Accessibility', () => {
  let dom, doc;

  before(() => {
    dom = createTemporalDOM();
    doc = dom.window.document;
  });

  it('should have lang attribute on html element', () => {
    assert.equal(doc.documentElement.getAttribute('lang'), 'en');
  });

  it('should have viewport meta tag', () => {
    const viewport = doc.querySelector('meta[name="viewport"]');
    assert.ok(viewport, 'Viewport meta tag should exist');
  });

  it('should have role=list on sequence list', () => {
    assert.equal(doc.getElementById('sequenceList').getAttribute('role'), 'list');
  });

  it('should have aria-label on sequence list', () => {
    const label = doc.getElementById('sequenceList').getAttribute('aria-label');
    assert.ok(label, 'Sequence list should have aria-label');
  });

  it('move buttons should have aria-labels', () => {
    dom.window.TemporalChallenge.start();
    const btns = doc.querySelectorAll('.move-btn');
    btns.forEach(function(btn) {
      assert.ok(btn.getAttribute('aria-label'), 'Move button should have aria-label');
    });
  });
});
