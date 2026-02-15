/**
 * Tests for the GIF CAPTCHA research analysis page (analysis.html)
 *
 * Validates data integrity, chart data consistency, category taxonomy,
 * model comparison logic, and structural correctness.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const ANALYSIS_HTML = fs.readFileSync(path.join(__dirname, '..', 'analysis.html'), 'utf8');

function createAnalysisDOM() {
  const dom = new JSDOM(ANALYSIS_HTML, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/analysis.html',
  });
  return dom;
}

describe('Analysis: GIF Data Integrity', () => {
  let dom, window;

  before(() => {
    dom = createAnalysisDOM();
    window = dom.window;
  });

  it('should have exactly 10 GIF data entries', () => {
    assert.equal(window.gifData.length, 10);
  });

  it('each GIF should have required analysis fields', () => {
    const required = [
      'id', 'title', 'category', 'categories', 'difficulty',
      'aiDifficulty2025', 'humanAnswer', 'whyItWorks',
      'keyChallenge', 'cognitiveSkills'
    ];
    for (const gif of window.gifData) {
      for (const field of required) {
        assert.ok(gif[field] !== undefined,
          `GIF ${gif.id} (${gif.title}) missing field: ${field}`);
      }
    }
  });

  it('difficulty ratings should be 1-10', () => {
    for (const gif of window.gifData) {
      assert.ok(gif.difficulty >= 1 && gif.difficulty <= 10,
        `GIF ${gif.id} difficulty ${gif.difficulty} out of range`);
      assert.ok(gif.aiDifficulty2025 >= 1 && gif.aiDifficulty2025 <= 10,
        `GIF ${gif.id} 2025 difficulty ${gif.aiDifficulty2025} out of range`);
    }
  });

  it('2025 AI difficulty should be lower than or equal to 2023 for all GIFs', () => {
    for (const gif of window.gifData) {
      assert.ok(gif.aiDifficulty2025 <= gif.difficulty,
        `GIF ${gif.id}: 2025 difficulty (${gif.aiDifficulty2025}) should not exceed 2023 (${gif.difficulty})`);
    }
  });

  it('each GIF should have at least one cognitive skill', () => {
    for (const gif of window.gifData) {
      assert.ok(gif.cognitiveSkills.length > 0,
        `GIF ${gif.id} has no cognitive skills listed`);
    }
  });

  it('primary category should be included in categories array', () => {
    for (const gif of window.gifData) {
      assert.ok(gif.categories.includes(gif.category),
        `GIF ${gif.id}: primary category "${gif.category}" not in categories array`);
    }
  });
});

describe('Analysis: Category Taxonomy', () => {
  let dom, window;

  before(() => {
    dom = createAnalysisDOM();
    window = dom.window;
  });

  it('should define exactly 6 categories', () => {
    assert.equal(Object.keys(window.categories).length, 6);
  });

  it('each category should have label, color, and bgColor', () => {
    for (const [key, cat] of Object.entries(window.categories)) {
      assert.ok(cat.label, `Category ${key} missing label`);
      assert.ok(cat.color, `Category ${key} missing color`);
      assert.ok(cat.bgColor, `Category ${key} missing bgColor`);
    }
  });

  it('all GIF categories should reference valid category keys', () => {
    const validKeys = Object.keys(window.categories);
    for (const gif of window.gifData) {
      assert.ok(validKeys.includes(gif.category),
        `GIF ${gif.id} has invalid primary category: ${gif.category}`);
      for (const cat of gif.categories) {
        assert.ok(validKeys.includes(cat),
          `GIF ${gif.id} has invalid secondary category: ${cat}`);
      }
    }
  });

  it('expected category labels should match', () => {
    const expected = {
      narrative: 'Narrative Twist',
      physical: 'Physical Comedy',
      animal: 'Animal Behavior',
      visual: 'Visual Trick',
      social: 'Social Subversion',
      illusion: 'Optical Illusion',
    };
    for (const [key, label] of Object.entries(expected)) {
      assert.equal(window.categories[key].label, label);
    }
  });
});

describe('Analysis: Model Comparison Data', () => {
  let dom, window;

  before(() => {
    dom = createAnalysisDOM();
    window = dom.window;
  });

  it('should have model data for all 6 categories', () => {
    const categoryKeys = Object.keys(window.categories);
    for (const key of categoryKeys) {
      assert.ok(window.modelData[key],
        `Missing model data for category: ${key}`);
    }
  });

  it('each model entry should have scores for all 5 compared entities', () => {
    const entities = ['gpt4', 'gpt4o', 'claude', 'gemini', 'human'];
    for (const [cat, data] of Object.entries(window.modelData)) {
      for (const entity of entities) {
        assert.ok(data[entity] !== undefined,
          `Model data for ${cat} missing score for ${entity}`);
      }
    }
  });

  it('GPT-4 (2023) scores should all be 0 (could not process GIFs)', () => {
    for (const [cat, data] of Object.entries(window.modelData)) {
      assert.equal(data.gpt4, 0,
        `GPT-4 should score 0 for ${cat} (could not process visual content)`);
    }
  });

  it('human scores should be highest for every category', () => {
    for (const [cat, data] of Object.entries(window.modelData)) {
      assert.ok(data.human >= data.gpt4o,
        `Human should score >= GPT-4o in ${cat}`);
      assert.ok(data.human >= data.claude,
        `Human should score >= Claude in ${cat}`);
      assert.ok(data.human >= data.gemini,
        `Human should score >= Gemini in ${cat}`);
    }
  });

  it('all model scores should be in 0-10 range', () => {
    for (const [cat, data] of Object.entries(window.modelData)) {
      for (const [model, score] of Object.entries(data)) {
        assert.ok(score >= 0 && score <= 10,
          `${model} score ${score} for ${cat} out of range`);
      }
    }
  });

  it('2024+ models should score higher than GPT-4 in all categories', () => {
    for (const [cat, data] of Object.entries(window.modelData)) {
      assert.ok(data.gpt4o >= data.gpt4,
        `GPT-4o should score >= GPT-4 in ${cat}`);
    }
  });
});

describe('Analysis: Radar Chart Dimensions', () => {
  let dom, window;

  before(() => {
    dom = createAnalysisDOM();
    window = dom.window;
  });

  it('should have 6 radar dimensions', () => {
    assert.equal(window.radarDimensions.length, 6);
  });

  it('each dimension should have label, human, gpt4, and gpt4o scores', () => {
    for (const dim of window.radarDimensions) {
      assert.ok(dim.label, 'Dimension missing label');
      assert.ok(dim.human !== undefined, `${dim.label} missing human score`);
      assert.ok(dim.gpt4 !== undefined, `${dim.label} missing gpt4 score`);
      assert.ok(dim.gpt4o !== undefined, `${dim.label} missing gpt4o score`);
    }
  });

  it('human should outperform GPT-4o in all dimensions', () => {
    for (const dim of window.radarDimensions) {
      assert.ok(dim.human >= dim.gpt4o,
        `Human (${dim.human}) should score >= GPT-4o (${dim.gpt4o}) in ${dim.label}`);
    }
  });

  it('GPT-4o should outperform GPT-4 in all dimensions', () => {
    for (const dim of window.radarDimensions) {
      assert.ok(dim.gpt4o >= dim.gpt4,
        `GPT-4o (${dim.gpt4o}) should score >= GPT-4 (${dim.gpt4}) in ${dim.label}`);
    }
  });

  it('all scores should be in 0-10 range', () => {
    for (const dim of window.radarDimensions) {
      for (const key of ['human', 'gpt4', 'gpt4o']) {
        assert.ok(dim[key] >= 0 && dim[key] <= 10,
          `${dim.label} ${key} score ${dim[key]} out of range`);
      }
    }
  });
});

describe('Analysis: DOM Structure', () => {
  let dom, document;

  before(() => {
    dom = createAnalysisDOM();
    document = dom.window.document;
  });

  it('should have 4 summary stat cards', () => {
    const cards = document.querySelectorAll('.summary-card');
    assert.equal(cards.length, 4);
  });

  it('should have 7 filter tabs (all + 6 categories)', () => {
    const tabs = document.querySelectorAll('.filter-tab');
    assert.equal(tabs.length, 7);
  });

  it('should have canvas elements for charts', () => {
    assert.ok(document.getElementById('categoryChart'), 'Missing category chart canvas');
    assert.ok(document.getElementById('difficultyChart'), 'Missing difficulty chart canvas');
    assert.ok(document.getElementById('radarChart'), 'Missing radar chart canvas');
  });

  it('should have navigation links to other pages', () => {
    const links = document.querySelectorAll('.nav-links a');
    const hrefs = Array.from(links).map(l => l.getAttribute('href'));
    assert.ok(hrefs.includes('index.html'), 'Missing link to case study');
    assert.ok(hrefs.includes('demo.html'), 'Missing link to demo');
  });

  it('should have Content-Security-Policy', () => {
    const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp, 'Missing CSP meta tag');
  });
});

describe('Analysis: Cross-Page Data Consistency', () => {
  let demoDOM, analysisDOM;

  before(() => {
    demoDOM = createDemoDOM();
    analysisDOM = createAnalysisDOM();
  });

  function createDemoDOM() {
    const html = fs.readFileSync(path.join(__dirname, '..', 'demo.html'), 'utf8');
    return new JSDOM(html, {
      runScripts: 'dangerously',
      pretendToBeVisual: true,
      url: 'https://example.com/demo.html',
    });
  }

  it('analysis and demo should have same number of GIFs', () => {
    assert.equal(
      analysisDOM.window.gifData.length,
      demoDOM.window.challenges.length,
      'GIF count mismatch between analysis and demo'
    );
  });

  it('GIF titles should be consistent between demo and analysis', () => {
    // Analysis uses more descriptive titles (e.g., "Rappers Roller Skating" vs "Rappers")
    // Check that they share significant common words
    for (let i = 0; i < 10; i++) {
      const analysisTitle = analysisDOM.window.gifData[i].title.toLowerCase();
      const demoTitle = demoDOM.window.challenges[i].title.toLowerCase();
      const analysisWords = analysisTitle.split(/\s+/);
      const demoWords = demoTitle.split(/\s+/);
      // At least one significant word (>2 chars) must overlap
      const overlap = demoWords.filter(w => w.length > 2 && analysisWords.includes(w));
      assert.ok(overlap.length > 0,
        `No common words between analysis="${analysisDOM.window.gifData[i].title}" and demo="${demoDOM.window.challenges[i].title}"`);
    }
  });

  it('human answers should match between demo and analysis', () => {
    for (let i = 0; i < 10; i++) {
      assert.equal(
        analysisDOM.window.gifData[i].humanAnswer,
        demoDOM.window.challenges[i].humanAnswer,
        `Human answer mismatch at GIF ${i + 1}`
      );
    }
  });
});
