/**
 * Tests for the GIF CAPTCHA Workshop / Generator (generator.html)
 *
 * Validates challenge CRUD, form validation, import/export logic,
 * preview flow, URL import, sanitization, and local storage persistence.
 */

const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const GENERATOR_HTML = fs.readFileSync(path.join(__dirname, '..', 'generator.html'), 'utf8');

/** Create a fresh jsdom instance with generator.html loaded */
function createGeneratorDOM() {
  const dom = new JSDOM(GENERATOR_HTML, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/generator.html',
    resources: 'usable',
  });
  return dom;
}

/** Add a challenge via the form programmatically */
function addChallenge(window, opts) {
  opts = opts || {};
  window.openAddForm();
  window.document.getElementById('inputTitle').value = opts.title || 'Test Challenge';
  window.document.getElementById('inputGifUrl').value = opts.gifUrl || 'https://example.com/test.gif';
  window.document.getElementById('inputSourceUrl').value = opts.sourceUrl || '';
  window.document.getElementById('inputExpected').value = opts.expected || 'This is the expected unexpected event description';
  window.document.getElementById('inputDifficulty').value = opts.difficulty || 5;
  if (opts.category) {
    window.selectedCategory = opts.category;
  }
  window.saveChallenge();
}

describe('Generator: Initial State', () => {
  let dom, document;

  beforeEach(() => {
    dom = createGeneratorDOM();
    document = dom.window.document;
  });

  it('should show Build tab as active by default', () => {
    const buildTab = document.querySelector('[data-tab="build"]');
    assert.ok(buildTab.classList.contains('active'));
  });

  it('should show empty state when no challenges exist', () => {
    const empty = document.getElementById('emptyState');
    assert.ok(!empty.classList.contains('hidden'), 'Empty state should be visible');
  });

  it('should have 0 challenges initially', () => {
    assert.equal(dom.window.challenges.length, 0);
  });

  it('should hide the add form initially', () => {
    const form = document.getElementById('addForm');
    assert.ok(form.classList.contains('hidden'));
  });

  it('should show 0 in stats bar', () => {
    assert.equal(document.getElementById('statCount').textContent, '0');
    assert.equal(document.getElementById('statCategories').textContent, '0');
    assert.equal(document.getElementById('statAvgDiff').textContent, '—');
  });
});

describe('Generator: Add Challenge', () => {
  let dom, window, document;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
    document = dom.window.document;
  });

  it('openAddForm should show the form', () => {
    window.openAddForm();
    assert.ok(!document.getElementById('addForm').classList.contains('hidden'));
  });

  it('closeAddForm should hide the form', () => {
    window.openAddForm();
    window.closeAddForm();
    assert.ok(document.getElementById('addForm').classList.contains('hidden'));
  });

  it('should add a challenge with valid data', () => {
    addChallenge(window);
    assert.equal(window.challenges.length, 1);
    assert.equal(window.challenges[0].title, 'Test Challenge');
  });

  it('should hide empty state after adding a challenge', () => {
    addChallenge(window);
    assert.ok(document.getElementById('emptyState').classList.contains('hidden'));
  });

  it('should update stats after adding', () => {
    addChallenge(window, { category: 'narrative', difficulty: 8 });
    assert.equal(document.getElementById('statCount').textContent, '1');
    assert.equal(document.getElementById('statCategories').textContent, '1');
    assert.equal(document.getElementById('statAvgDiff').textContent, '8.0');
  });

  it('should add multiple challenges', () => {
    addChallenge(window, { title: 'One' });
    addChallenge(window, { title: 'Two' });
    addChallenge(window, { title: 'Three' });
    assert.equal(window.challenges.length, 3);
  });
});

describe('Generator: Form Validation', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
  });

  it('should reject empty title', () => {
    window.openAddForm();
    window.document.getElementById('inputTitle').value = '';
    window.document.getElementById('inputGifUrl').value = 'https://example.com/test.gif';
    window.document.getElementById('inputExpected').value = 'A valid expected answer';
    window.saveChallenge();
    assert.equal(window.challenges.length, 0);
  });

  it('should reject empty GIF URL', () => {
    window.openAddForm();
    window.document.getElementById('inputTitle').value = 'Test';
    window.document.getElementById('inputGifUrl').value = '';
    window.document.getElementById('inputExpected').value = 'A valid expected answer';
    window.saveChallenge();
    assert.equal(window.challenges.length, 0);
  });

  it('should reject non-HTTPS GIF URL', () => {
    window.openAddForm();
    window.document.getElementById('inputTitle').value = 'Test';
    window.document.getElementById('inputGifUrl').value = 'http://example.com/test.gif';
    window.document.getElementById('inputExpected').value = 'A valid expected answer';
    window.saveChallenge();
    assert.equal(window.challenges.length, 0);
  });

  it('should reject empty expected answer', () => {
    window.openAddForm();
    window.document.getElementById('inputTitle').value = 'Test';
    window.document.getElementById('inputGifUrl').value = 'https://example.com/test.gif';
    window.document.getElementById('inputExpected').value = '';
    window.saveChallenge();
    assert.equal(window.challenges.length, 0);
  });

  it('should reject expected answer shorter than 10 chars', () => {
    window.openAddForm();
    window.document.getElementById('inputTitle').value = 'Test';
    window.document.getElementById('inputGifUrl').value = 'https://example.com/test.gif';
    window.document.getElementById('inputExpected').value = 'Too short';
    window.saveChallenge();
    assert.equal(window.challenges.length, 0);
  });
});

describe('Generator: Edit Challenge', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
    addChallenge(window, { title: 'Original Title' });
  });

  it('editChallenge should populate form with existing data', () => {
    window.editChallenge(0);
    assert.equal(window.document.getElementById('inputTitle').value, 'Original Title');
    assert.equal(window.editingIndex, 0);
  });

  it('saving edit should update existing challenge', () => {
    window.editChallenge(0);
    window.document.getElementById('inputTitle').value = 'Updated Title';
    window.saveChallenge();
    assert.equal(window.challenges[0].title, 'Updated Title');
    assert.equal(window.challenges.length, 1); // Should NOT add new
  });
});

describe('Generator: Delete Challenge', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
    addChallenge(window, { title: 'First' });
    addChallenge(window, { title: 'Second' });
    addChallenge(window, { title: 'Third' });
  });

  it('should remove the correct challenge', () => {
    window.deleteChallenge(1);
    assert.equal(window.challenges.length, 2);
    assert.equal(window.challenges[0].title, 'First');
    assert.equal(window.challenges[1].title, 'Third');
  });

  it('should show empty state when all deleted', () => {
    window.deleteChallenge(0);
    window.deleteChallenge(0);
    window.deleteChallenge(0);
    assert.equal(window.challenges.length, 0);
    assert.ok(!window.document.getElementById('emptyState').classList.contains('hidden'));
  });
});

describe('Generator: Move Challenge', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
    addChallenge(window, { title: 'A' });
    addChallenge(window, { title: 'B' });
    addChallenge(window, { title: 'C' });
  });

  it('should move challenge down', () => {
    window.moveChallenge(0, 1);
    assert.equal(window.challenges[0].title, 'B');
    assert.equal(window.challenges[1].title, 'A');
  });

  it('should move challenge up', () => {
    window.moveChallenge(2, -1);
    assert.equal(window.challenges[1].title, 'C');
    assert.equal(window.challenges[2].title, 'B');
  });

  it('should not move past boundaries', () => {
    window.moveChallenge(0, -1); // Can't move first up
    assert.equal(window.challenges[0].title, 'A');
    window.moveChallenge(2, 1); // Can't move last down
    assert.equal(window.challenges[2].title, 'C');
  });
});

describe('Generator: Category Selection', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
  });

  it('should select a category', () => {
    window.openAddForm();
    var chip = window.document.querySelector('[data-cat="narrative"]');
    window.selectCategory(chip);
    assert.equal(window.selectedCategory, 'narrative');
  });

  it('should toggle category off on second click', () => {
    window.openAddForm();
    var chip = window.document.querySelector('[data-cat="narrative"]');
    window.selectCategory(chip);
    window.selectCategory(chip);
    assert.equal(window.selectedCategory, '');
  });

  it('should save category with challenge', () => {
    addChallenge(window, { category: 'animal' });
    assert.equal(window.challenges[0].category, 'animal');
  });
});

describe('Generator: Load Sample Set', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
  });

  it('should load 5 sample challenges', () => {
    window.loadSampleSet();
    assert.equal(window.challenges.length, 5);
  });

  it('sample challenges should have valid data', () => {
    window.loadSampleSet();
    for (const c of window.challenges) {
      assert.ok(c.title.length > 0);
      assert.ok(c.gifUrl.startsWith('https://'));
      assert.ok(c.expectedAnswer.length > 10);
      assert.ok(c.difficulty >= 1 && c.difficulty <= 10);
    }
  });

  it('sample set should replace existing challenges', () => {
    addChallenge(window, { title: 'Existing' });
    window.loadSampleSet();
    assert.equal(window.challenges.length, 5);
    assert.notEqual(window.challenges[0].title, 'Existing');
  });
});

describe('Generator: Export', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
    addChallenge(window, { title: 'Export Test', category: 'visual', difficulty: 7 });
  });

  it('getExportData should return properly formatted array', () => {
    var data = window.getExportData();
    assert.equal(data.length, 1);
    assert.equal(data[0].id, 1);
    assert.equal(data[0].title, 'Export Test');
    assert.equal(data[0].category, 'visual');
    assert.equal(data[0].difficulty, 7);
  });

  it('export data should include expectedAnswer', () => {
    var data = window.getExportData();
    assert.ok(data[0].expectedAnswer.length > 0);
  });

  it('export data should have sequential IDs', () => {
    addChallenge(window, { title: 'Second' });
    addChallenge(window, { title: 'Third' });
    var data = window.getExportData();
    assert.equal(data[0].id, 1);
    assert.equal(data[1].id, 2);
    assert.equal(data[2].id, 3);
  });

  it('updateExportPreview should produce valid JSON', () => {
    window.switchTab('export');
    var preview = window.document.getElementById('exportPreview').textContent;
    var parsed = JSON.parse(preview);
    assert.ok(Array.isArray(parsed));
    assert.equal(parsed.length, 1);
  });
});

describe('Generator: Import', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
  });

  it('should import valid JSON array', () => {
    var data = [
      { title: 'Imported 1', gifUrl: 'https://example.com/1.gif', expectedAnswer: 'Something unexpected happened here' },
      { title: 'Imported 2', gifUrl: 'https://example.com/2.gif', expectedAnswer: 'Another unexpected event occurred' }
    ];
    window.document.getElementById('importInput').value = JSON.stringify(data);
    window.importJSON();
    assert.equal(window.challenges.length, 2);
    assert.equal(window.challenges[0].title, 'Imported 1');
  });

  it('should reject non-array JSON', () => {
    window.document.getElementById('importInput').value = '{"title": "not an array"}';
    window.importJSON();
    assert.equal(window.challenges.length, 0);
  });

  it('should reject empty array', () => {
    window.document.getElementById('importInput').value = '[]';
    window.importJSON();
    assert.equal(window.challenges.length, 0);
  });

  it('should reject invalid JSON', () => {
    window.document.getElementById('importInput').value = 'not json at all';
    window.importJSON();
    assert.equal(window.challenges.length, 0);
  });

  it('should handle missing fields gracefully with defaults', () => {
    var data = [{ title: 'Minimal' }];
    window.document.getElementById('importInput').value = JSON.stringify(data);
    window.importJSON();
    assert.equal(window.challenges.length, 1);
    assert.equal(window.challenges[0].title, 'Minimal');
    assert.equal(window.challenges[0].difficulty, 5);
  });

  it('should support humanAnswer field as expectedAnswer fallback', () => {
    var data = [{ title: 'Old Format', gifUrl: 'https://example.com/1.gif', humanAnswer: 'A human described this event in the GIF' }];
    window.document.getElementById('importInput').value = JSON.stringify(data);
    window.importJSON();
    assert.equal(window.challenges[0].expectedAnswer, 'A human described this event in the GIF');
  });
});

describe('Generator: Preview Flow', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
    addChallenge(window, { title: 'Preview 1' });
    addChallenge(window, { title: 'Preview 2' });
  });

  it('should show empty state in preview when no challenges', () => {
    window.challenges = [];
    window.switchTab('preview');
    assert.ok(!window.document.getElementById('previewEmpty').classList.contains('hidden'));
  });

  it('should show preview intro when challenges exist', () => {
    window.switchTab('preview');
    assert.ok(window.document.getElementById('previewEmpty').classList.contains('hidden'));
    assert.ok(!window.document.getElementById('previewIntro').classList.contains('hidden'));
  });

  it('startPreview should show challenge view', () => {
    window.switchTab('preview');
    window.startPreview();
    assert.ok(window.document.getElementById('previewIntro').classList.contains('hidden'));
    assert.ok(!window.document.getElementById('previewChallenge').classList.contains('hidden'));
    assert.equal(window.pvIndex, 0);
  });

  it('previewSkip should record skipped answer', () => {
    window.switchTab('preview');
    window.startPreview();
    window.previewSkip();
    assert.equal(window.pvSkipped, 1);
    assert.ok(window.pvAnswers[0].skipped);
  });

  it('previewNext should advance to next challenge', () => {
    window.switchTab('preview');
    window.startPreview();
    window.previewSkip();
    window.previewNext();
    assert.equal(window.pvIndex, 1);
  });

  it('completing all challenges should show results', () => {
    window.switchTab('preview');
    window.startPreview();
    window.previewSkip();
    window.previewNext();
    window.previewSkip();
    window.previewNext();
    assert.ok(!window.document.getElementById('previewResults').classList.contains('hidden'));
  });
});

describe('Generator: Sanitize Function', () => {
  let dom, window;

  before(() => {
    dom = createGeneratorDOM();
    window = dom.window;
  });

  it('should escape HTML tags', () => {
    var result = window.sanitize('<script>alert("xss")</script>');
    assert.ok(!result.includes('<script>'));
    assert.ok(result.includes('&lt;'));
  });

  it('should escape ampersands', () => {
    var result = window.sanitize('a & b');
    assert.ok(result.includes('&amp;'));
  });

  it('should handle empty string', () => {
    assert.equal(window.sanitize(''), '');
  });
});

describe('Generator: Security', () => {
  let dom, document;

  before(() => {
    dom = createGeneratorDOM();
    document = dom.window.document;
  });

  it('should have Content-Security-Policy meta tag', () => {
    var csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp);
    assert.ok(csp.content.includes("frame-ancestors 'none'"));
  });

  it('should have referrer policy', () => {
    var ref = document.querySelector('meta[name="referrer"]');
    assert.ok(ref);
    assert.equal(ref.content, 'no-referrer');
  });

  it('should have proper charset', () => {
    var charset = document.querySelector('meta[charset]');
    assert.ok(charset);
    assert.equal(charset.getAttribute('charset'), 'UTF-8');
  });
});

describe('Generator: Tab Navigation', () => {
  let dom, window, document;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
    document = dom.window.document;
  });

  it('should switch to preview tab', () => {
    window.switchTab('preview');
    assert.ok(document.querySelector('[data-tab="preview"]').classList.contains('active'));
    assert.ok(document.getElementById('tab-preview').classList.contains('active'));
    assert.ok(!document.getElementById('tab-build').classList.contains('active'));
  });

  it('should switch to export tab', () => {
    window.switchTab('export');
    assert.ok(document.querySelector('[data-tab="export"]').classList.contains('active'));
    assert.ok(document.getElementById('tab-export').classList.contains('active'));
  });

  it('should switch back to build tab', () => {
    window.switchTab('preview');
    window.switchTab('build');
    assert.ok(document.querySelector('[data-tab="build"]').classList.contains('active'));
    assert.ok(document.getElementById('tab-build').classList.contains('active'));
  });
});

describe('Generator: Round-trip Export/Import', () => {
  let dom, window;

  beforeEach(() => {
    dom = createGeneratorDOM();
    window = dom.window;
  });

  it('should survive a JSON round-trip', () => {
    addChallenge(window, { title: 'Round Trip', category: 'illusion', difficulty: 9 });
    addChallenge(window, { title: 'Second One', category: 'narrative', difficulty: 3 });

    var exported = window.getExportData();
    var json = JSON.stringify(exported);

    // Clear and reimport
    window.challenges = [];
    window.document.getElementById('importInput').value = json;
    window.importJSON();

    assert.equal(window.challenges.length, 2);
    assert.equal(window.challenges[0].title, 'Round Trip');
    assert.equal(window.challenges[0].category, 'illusion');
    assert.equal(window.challenges[0].difficulty, 9);
    assert.equal(window.challenges[1].title, 'Second One');
  });
});
