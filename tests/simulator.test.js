/**
 * Tests for the GIF CAPTCHA AI Response Simulator (simulator.html)
 *
 * Validates model data, CAPTCHA response data, DOM rendering, 
 * model switching, heatmap, and chart initialization.
 */

const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const SIM_HTML = fs.readFileSync(path.join(__dirname, '..', 'simulator.html'), 'utf8');

/** Create a fresh jsdom instance with simulator.html loaded */
function createSimDOM() {
  const dom = new JSDOM(SIM_HTML, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/simulator.html',
  });
  return dom;
}

describe('Simulator: Model Data Integrity', () => {
  let dom, window;

  before(() => {
    dom = createSimDOM();
    window = dom.window;
  });

  it('should define exactly 5 AI models', () => {
    assert.equal(window.models.length, 5);
  });

  it('each model should have required fields', () => {
    const requiredFields = ['id', 'name', 'year', 'color', 'desc', 'capabilities'];
    for (const model of window.models) {
      for (const field of requiredFields) {
        assert.ok(model[field] !== undefined, `Model ${model.name} missing field: ${field}`);
      }
    }
  });

  it('each model should have all 6 capability dimensions', () => {
    const capKeys = ['frameAnalysis', 'motionTracking', 'narrativeComp', 'culturalContext', 'humorDetection', 'objectRecog'];
    for (const model of window.models) {
      for (const key of capKeys) {
        assert.ok(typeof model.capabilities[key] === 'number', `Model ${model.name} missing capability: ${key}`);
        assert.ok(model.capabilities[key] >= 0 && model.capabilities[key] <= 10, `Model ${model.name} capability ${key} out of range: ${model.capabilities[key]}`);
      }
    }
  });

  it('GPT-4 should have zero vision capabilities', () => {
    const gpt4 = window.models.find(m => m.id === 'gpt4');
    assert.equal(gpt4.capabilities.frameAnalysis, 0);
    assert.equal(gpt4.capabilities.motionTracking, 0);
    assert.equal(gpt4.capabilities.objectRecog, 0);
  });

  it('each model should have unique id', () => {
    const ids = window.models.map(m => m.id);
    assert.equal(new Set(ids).size, ids.length);
  });

  it('model scores should be precomputed', () => {
    for (const model of window.models) {
      assert.ok(typeof model.solved === 'number', `Model ${model.name} missing solved count`);
      assert.ok(typeof model.partial === 'number', `Model ${model.name} missing partial count`);
      assert.ok(typeof model.blocked === 'number', `Model ${model.name} missing blocked count`);
      assert.equal(model.solved + model.partial + model.blocked, 10, `Model ${model.name} scores don't sum to 10`);
    }
  });
});

describe('Simulator: CAPTCHA Data Integrity', () => {
  let dom, window;

  before(() => {
    dom = createSimDOM();
    window = dom.window;
  });

  it('should define exactly 10 CAPTCHAs', () => {
    assert.equal(window.captchas.length, 10);
  });

  it('each CAPTCHA should have required fields', () => {
    const requiredFields = ['id', 'title', 'category', 'humanAnswer', 'requiredCapabilities', 'responses'];
    for (const c of window.captchas) {
      for (const field of requiredFields) {
        assert.ok(c[field] !== undefined, `CAPTCHA ${c.title} missing field: ${field}`);
      }
    }
  });

  it('each CAPTCHA should have responses for all 5 models', () => {
    const modelIds = ['gpt4', 'gpt4v', 'gpt4o', 'claude35', 'gemini15'];
    for (const c of window.captchas) {
      for (const modelId of modelIds) {
        assert.ok(c.responses[modelId], `CAPTCHA ${c.title} missing response for ${modelId}`);
      }
    }
  });

  it('each response should have result, response, and reasoning', () => {
    for (const c of window.captchas) {
      for (const [modelId, resp] of Object.entries(c.responses)) {
        assert.ok(['blocked', 'partial', 'solved'].includes(resp.result), `CAPTCHA ${c.title} / ${modelId}: invalid result "${resp.result}"`);
        assert.ok(resp.response.length > 0, `CAPTCHA ${c.title} / ${modelId}: empty response`);
        assert.ok(resp.reasoning.length > 0, `CAPTCHA ${c.title} / ${modelId}: empty reasoning`);
      }
    }
  });

  it('GPT-4 should be blocked on all 10 CAPTCHAs', () => {
    for (const c of window.captchas) {
      assert.equal(c.responses.gpt4.result, 'blocked', `GPT-4 should be blocked on CAPTCHA ${c.title}`);
    }
  });

  it('GPT-4 should always give the same "cannot view animations" response', () => {
    const expectedSnippet = 'cannot view animations';
    for (const c of window.captchas) {
      assert.ok(c.responses.gpt4.response.includes(expectedSnippet), `GPT-4 response for CAPTCHA ${c.title} should mention "${expectedSnippet}"`);
    }
  });

  it('CAPTCHAs should have valid categories', () => {
    const validCategories = ['narrative', 'physical', 'animal', 'visual', 'social', 'illusion'];
    for (const c of window.captchas) {
      assert.ok(validCategories.includes(c.category), `CAPTCHA ${c.title} has invalid category: ${c.category}`);
    }
  });

  it('required capabilities should have all 6 dimensions', () => {
    const capKeys = ['frameAnalysis', 'motionTracking', 'narrativeComp', 'culturalContext', 'humorDetection', 'objectRecog'];
    for (const c of window.captchas) {
      for (const key of capKeys) {
        assert.ok(typeof c.requiredCapabilities[key] === 'number', `CAPTCHA ${c.title} missing required capability: ${key}`);
        assert.ok(c.requiredCapabilities[key] >= 0 && c.requiredCapabilities[key] <= 10, `CAPTCHA ${c.title} capability ${key} out of range`);
      }
    }
  });

  it('CAPTCHA IDs should be sequential 1-10', () => {
    for (let i = 0; i < 10; i++) {
      assert.equal(window.captchas[i].id, i + 1);
    }
  });
});

describe('Simulator: DOM Rendering', () => {
  let dom, document;

  beforeEach(() => {
    dom = createSimDOM();
    document = dom.window.document;
  });

  it('should render model selector with 5 buttons', () => {
    const buttons = document.querySelectorAll('.model-btn');
    assert.equal(buttons.length, 5);
  });

  it('should start with GPT-4 selected', () => {
    const active = document.querySelector('.model-btn.active');
    assert.ok(active);
    assert.equal(active.dataset.model, 'gpt4');
  });

  it('should render 4 overview cards', () => {
    const cards = document.querySelectorAll('.overview-card');
    assert.equal(cards.length, 4);
  });

  it('should render 10 response cards', () => {
    const cards = document.querySelectorAll('.response-card');
    assert.equal(cards.length, 10);
  });

  it('response cards should start collapsed', () => {
    const expanded = document.querySelectorAll('.response-card.expanded');
    assert.equal(expanded.length, 0);
  });

  it('clicking a response card header should expand it', () => {
    const card = document.querySelector('.response-card');
    const header = card.querySelector('.card-header');
    header.click();
    assert.ok(card.classList.contains('expanded'));
  });

  it('clicking an expanded card header should collapse it', () => {
    const card = document.querySelector('.response-card');
    const header = card.querySelector('.card-header');
    header.click(); // expand
    header.click(); // collapse
    assert.ok(!card.classList.contains('expanded'));
  });

  it('should render heatmap table with rows', () => {
    const table = document.getElementById('heatmapTable');
    assert.ok(table);
    const rows = table.querySelectorAll('tr');
    assert.ok(rows.length >= 11); // header + 10 CAPTCHAs + totals
  });

  it('heatmap should have 7 columns (CAPTCHA name + 5 models + Human)', () => {
    const headers = document.querySelectorAll('#heatmapTable th');
    assert.equal(headers.length, 7);
  });

  it('should render effectiveness chart canvas', () => {
    const canvas = document.getElementById('effectivenessChart');
    assert.ok(canvas);
  });

  it('should render capability radar canvas', () => {
    const canvas = document.getElementById('capabilityRadar');
    assert.ok(canvas);
  });

  it('all GPT-4 response cards should show CAPTCHA PASS', () => {
    const badges = document.querySelectorAll('.result-badge');
    badges.forEach(badge => {
      assert.equal(badge.textContent, 'CAPTCHA PASS');
    });
  });
});

describe('Simulator: Model Switching', () => {
  let dom, document, window;

  beforeEach(() => {
    dom = createSimDOM();
    document = dom.window.document;
    window = dom.window;
  });

  it('clicking a different model button should switch selection', () => {
    const buttons = document.querySelectorAll('.model-btn');
    const gpt4oBtn = Array.from(buttons).find(b => b.dataset.model === 'gpt4o');
    gpt4oBtn.click();
    assert.ok(gpt4oBtn.classList.contains('active'));
    // Previous should be deactivated
    const gpt4Btn = Array.from(buttons).find(b => b.dataset.model === 'gpt4');
    assert.ok(!gpt4Btn.classList.contains('active'));
  });

  it('switching to GPT-4o should show some solved CAPTCHAs', () => {
    const buttons = document.querySelectorAll('.model-btn');
    const gpt4oBtn = Array.from(buttons).find(b => b.dataset.model === 'gpt4o');
    gpt4oBtn.click();
    const badges = document.querySelectorAll('.result-badge');
    const solved = Array.from(badges).filter(b => b.textContent === 'AI SOLVED');
    assert.ok(solved.length > 0, 'GPT-4o should solve at least some CAPTCHAs');
  });

  it('switching to Gemini 1.5 should show more solved than GPT-4V', () => {
    const gemini = window.models.find(m => m.id === 'gemini15');
    const gpt4v = window.models.find(m => m.id === 'gpt4v');
    assert.ok(gemini.solved > gpt4v.solved, 'Gemini 1.5 should solve more CAPTCHAs than GPT-4V');
  });

  it('overview should update when model changes', () => {
    const buttons = document.querySelectorAll('.model-btn');
    const geminiBtn = Array.from(buttons).find(b => b.dataset.model === 'gemini15');
    geminiBtn.click();
    const cards = document.querySelectorAll('.overview-card .card-value');
    // First card shows blocked count
    const blockedText = cards[0].textContent;
    assert.ok(blockedText.includes('/10'));
  });
});

describe('Simulator: Scoring Logic', () => {
  let window;

  before(() => {
    const dom = createSimDOM();
    window = dom.window;
  });

  it('GPT-4 should solve 0 CAPTCHAs', () => {
    const gpt4 = window.models.find(m => m.id === 'gpt4');
    assert.equal(gpt4.solved, 0);
    assert.equal(gpt4.blocked, 10);
  });

  it('Gemini 1.5 should solve more than GPT-4V', () => {
    const gemini = window.models.find(m => m.id === 'gemini15');
    const gpt4v = window.models.find(m => m.id === 'gpt4v');
    assert.ok(gemini.solved > gpt4v.solved);
  });

  it('no model should solve all 10 CAPTCHAs', () => {
    for (const model of window.models) {
      assert.ok(model.solved < 10, `${model.name} should not solve all CAPTCHAs`);
    }
  });

  it('models should show progressive improvement over time', () => {
    const gpt4 = window.models.find(m => m.id === 'gpt4');
    const gpt4v = window.models.find(m => m.id === 'gpt4v');
    const gpt4o = window.models.find(m => m.id === 'gpt4o');
    assert.ok(gpt4.solved <= gpt4v.solved, 'GPT-4V should solve >= GPT-4');
    assert.ok(gpt4v.solved <= gpt4o.solved, 'GPT-4o should solve >= GPT-4V');
  });

  it('CAPTCHA #6 (Parent Dog) should be hardest — blocked by most models', () => {
    const c = window.captchas.find(c => c.id === 6);
    let blockedCount = 0;
    for (const resp of Object.values(c.responses)) {
      if (resp.result === 'blocked') blockedCount++;
    }
    assert.ok(blockedCount >= 4, 'CAPTCHA #6 should be blocked by at least 4 models');
  });

  it('CAPTCHA #3 (Flying Skateboarder) should be easiest — solved by most models', () => {
    const c = window.captchas.find(c => c.id === 3);
    let solvedCount = 0;
    for (const resp of Object.values(c.responses)) {
      if (resp.result === 'solved') solvedCount++;
    }
    assert.ok(solvedCount >= 2, 'CAPTCHA #3 should be solved by at least 2 models');
  });

  it('effectiveness should equal 10 minus solved', () => {
    for (const model of window.models) {
      assert.equal(model.effectiveness, 10 - model.solved);
    }
  });
});

describe('Simulator: Capability Labels', () => {
  let window;

  before(() => {
    const dom = createSimDOM();
    window = dom.window;
  });

  it('should define labels for all 6 capability dimensions', () => {
    assert.equal(Object.keys(window.capLabels).length, 6);
  });

  it('capKeys should match capLabels keys', () => {
    const expected = Object.keys(window.capLabels);
    assert.equal(window.capKeys.length, expected.length);
    for (let i = 0; i < expected.length; i++) {
      assert.equal(window.capKeys[i], expected[i]);
    }
  });
});

describe('Simulator: Navigation Links', () => {
  let document;

  before(() => {
    const dom = createSimDOM();
    document = dom.window.document;
  });

  it('should have navigation links to other pages', () => {
    const navLinks = document.querySelectorAll('.nav-links a');
    assert.ok(navLinks.length >= 4);
    const hrefs = Array.from(navLinks).map(a => a.getAttribute('href'));
    assert.ok(hrefs.includes('index.html'));
    assert.ok(hrefs.includes('demo.html'));
    assert.ok(hrefs.includes('analysis.html'));
    assert.ok(hrefs.includes('generator.html'));
  });

  it('should have footer links', () => {
    const footerLinks = document.querySelectorAll('footer a');
    assert.ok(footerLinks.length >= 4);
  });
});
