/**
 * Tests for the GIF CAPTCHA Response Time Benchmark (benchmark.html)
 *
 * Validates challenge data, timer logic, statistics calculation,
 * result rendering, AI comparison, and DOM interactions.
 */

const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const BENCH_HTML_RAW = fs.readFileSync(path.join(__dirname, '..', 'benchmark.html'), 'utf8');
const SHARED_JS = fs.readFileSync(path.join(__dirname, '..', 'shared.js'), 'utf8');

// Inject shared.js inline so jsdom can execute it (jsdom can't fetch external scripts from fake URLs)
const BENCH_HTML = BENCH_HTML_RAW.replace(
  '<script src="shared.js"></script>',
  '<script>' + SHARED_JS + '</script>'
);

/** Create a fresh jsdom instance with benchmark.html loaded */
function createBenchDOM() {
  const dom = new JSDOM(BENCH_HTML, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://example.com/benchmark.html',
  });
  return dom;
}

// ===== Challenge Data Integrity =====

describe('Benchmark: Challenge Data', () => {
  let dom, window;

  before(() => {
    dom = createBenchDOM();
    window = dom.window;
  });

  it('should have exactly 10 challenges', () => {
    assert.equal(window.benchmarkChallenges.length, 10);
  });

  it('each challenge has required fields', () => {
    const fields = ['id', 'title', 'gifUrl', 'sourceUrl', 'humanAnswer', 'category'];
    for (const c of window.benchmarkChallenges) {
      for (const f of fields) {
        assert.ok(c[f] !== undefined && c[f] !== '',
          `Challenge ${c.id} missing field: ${f}`);
      }
    }
  });

  it('challenge IDs are sequential 1-10', () => {
    for (let i = 0; i < 10; i++) {
      assert.equal(window.benchmarkChallenges[i].id, i + 1);
    }
  });

  it('all GIF URLs use HTTPS', () => {
    for (const c of window.benchmarkChallenges) {
      assert.ok(c.gifUrl.startsWith('https://'), `${c.title} has non-HTTPS URL`);
    }
  });

  it('categories are valid', () => {
    const valid = ['narrative', 'social', 'physical', 'animal', 'illusion'];
    for (const c of window.benchmarkChallenges) {
      assert.ok(valid.includes(c.category),
        `${c.title} has invalid category: ${c.category}`);
    }
  });

  it('getChallenges returns the challenge array', () => {
    const challenges = window.Benchmark.getChallenges();
    assert.equal(challenges.length, 10);
    assert.equal(challenges[0].title, 'Duel Plot Twist');
  });
});

// ===== AI Processing Benchmarks =====

describe('Benchmark: AI Processing Times', () => {
  let dom, window;

  before(() => {
    dom = createBenchDOM();
    window = dom.window;
  });

  it('has 5 AI models', () => {
    assert.equal(window.aiProcessingTimes.length, 5);
  });

  it('each AI entry has name, time, color, accuracy', () => {
    for (const ai of window.aiProcessingTimes) {
      assert.ok(ai.name, 'AI entry missing name');
      assert.ok(typeof ai.time === 'number' && ai.time > 0, 'AI entry needs positive time');
      assert.ok(ai.color, 'AI entry missing color');
      assert.ok(typeof ai.accuracy === 'number', 'AI entry missing accuracy');
    }
  });

  it('AI accuracy is lower than typical human accuracy', () => {
    for (const ai of window.aiProcessingTimes) {
      assert.ok(ai.accuracy < 50, `${ai.name} accuracy too high: ${ai.accuracy}`);
    }
  });

  it('getAIBenchmarks returns the AI data', () => {
    const benchmarks = window.Benchmark.getAIBenchmarks();
    assert.equal(benchmarks.length, 5);
  });
});

// ===== Format Time Utility =====

describe('Benchmark: formatTime', () => {
  let Benchmark;

  before(() => {
    const dom = createBenchDOM();
    Benchmark = dom.window.Benchmark;
  });

  it('formats milliseconds under 1000', () => {
    assert.equal(Benchmark.formatTime(500), '500ms');
    assert.equal(Benchmark.formatTime(0), '0ms');
    assert.equal(Benchmark.formatTime(999), '999ms');
  });

  it('formats seconds (1000-59999ms)', () => {
    assert.equal(Benchmark.formatTime(1000), '1.0s');
    assert.equal(Benchmark.formatTime(5500), '5.5s');
    assert.equal(Benchmark.formatTime(15000), '15.0s');
  });

  it('formats minutes (60000ms+)', () => {
    assert.equal(Benchmark.formatTime(60000), '1.0m');
    assert.equal(Benchmark.formatTime(90000), '1.5m');
  });
});

// ===== Speed Class Utility =====

describe('Benchmark: speedClass', () => {
  let Benchmark;

  before(() => {
    const dom = createBenchDOM();
    Benchmark = dom.window.Benchmark;
  });

  it('classifies fast (<5s)', () => {
    assert.equal(Benchmark.speedClass(3000), 'fast');
    assert.equal(Benchmark.speedClass(4999), 'fast');
  });

  it('classifies medium (5-15s)', () => {
    assert.equal(Benchmark.speedClass(5000), 'medium');
    assert.equal(Benchmark.speedClass(10000), 'medium');
    assert.equal(Benchmark.speedClass(14999), 'medium');
  });

  it('classifies slow (15s+)', () => {
    assert.equal(Benchmark.speedClass(15000), 'slow');
    assert.equal(Benchmark.speedClass(30000), 'slow');
  });
});

// ===== Statistics Calculation =====

describe('Benchmark: calcStats', () => {
  let dom, Benchmark;

  beforeEach(() => {
    dom = createBenchDOM();
    Benchmark = dom.window.Benchmark;
  });

  it('returns zero stats for empty results', () => {
    Benchmark._setResults([]);
    const stats = Benchmark.calcStats();
    assert.equal(stats.avgTime, 0);
    assert.equal(stats.accuracy, 0);
    assert.equal(stats.answered, 0);
  });

  it('returns zero stats for all-skipped results', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 5000, skipped: true, answer: '' },
      { challengeId: 2, title: 'B', category: 'social', time: 3000, skipped: true, answer: '' }
    ]);
    const stats = Benchmark.calcStats();
    assert.equal(stats.avgTime, 0);
    assert.equal(stats.answered, 0);
    assert.equal(stats.skipped, 2);
  });

  it('calculates correct average for answered results', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 4000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 6000, skipped: false, answer: 'y' }
    ]);
    const stats = Benchmark.calcStats();
    assert.equal(stats.avgTime, 5000);
  });

  it('calculates correct median for odd count', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 2000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 8000, skipped: false, answer: 'y' },
      { challengeId: 3, title: 'C', category: 'physical', time: 5000, skipped: false, answer: 'z' }
    ]);
    const stats = Benchmark.calcStats();
    assert.equal(stats.medianTime, 5000);
  });

  it('calculates correct median for even count', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 2000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 4000, skipped: false, answer: 'y' },
      { challengeId: 3, title: 'C', category: 'physical', time: 6000, skipped: false, answer: 'z' },
      { challengeId: 4, title: 'D', category: 'animal', time: 8000, skipped: false, answer: 'w' }
    ]);
    const stats = Benchmark.calcStats();
    assert.equal(stats.medianTime, 5000); // (4000 + 6000) / 2
  });

  it('finds fastest and slowest', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 3000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 12000, skipped: false, answer: 'y' },
      { challengeId: 3, title: 'C', category: 'physical', time: 7000, skipped: false, answer: 'z' }
    ]);
    const stats = Benchmark.calcStats();
    assert.equal(stats.fastestTime, 3000);
    assert.equal(stats.slowestTime, 12000);
  });

  it('calculates accuracy correctly with skips', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 3000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 5000, skipped: true, answer: '' },
      { challengeId: 3, title: 'C', category: 'physical', time: 4000, skipped: false, answer: 'z' },
      { challengeId: 4, title: 'D', category: 'animal', time: 6000, skipped: true, answer: '' }
    ]);
    const stats = Benchmark.calcStats();
    assert.equal(stats.accuracy, 50); // 2/4
    assert.equal(stats.answered, 2);
    assert.equal(stats.skipped, 2);
  });

  it('excludes skipped from avg/median but includes in totalTime', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 4000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 10000, skipped: true, answer: '' }
    ]);
    const stats = Benchmark.calcStats();
    assert.equal(stats.avgTime, 4000); // only answered
    assert.equal(stats.totalTime, 14000); // both
  });

  it('calculates total time across all results', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 3000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 7000, skipped: false, answer: 'y' }
    ]);
    const stats = Benchmark.calcStats();
    assert.equal(stats.totalTime, 10000);
  });
});

// ===== DOM Structure =====

describe('Benchmark: HTML Structure', () => {
  let dom, doc;

  before(() => {
    dom = createBenchDOM();
    doc = dom.window.document;
  });

  it('has correct page title', () => {
    assert.ok(doc.title.includes('Response Time Benchmark'));
  });

  it('has intro screen visible by default', () => {
    const intro = doc.getElementById('introScreen');
    assert.ok(intro);
    assert.ok(!intro.classList.contains('hidden'));
  });

  it('has challenge screen hidden by default', () => {
    const challenge = doc.getElementById('challengeScreen');
    assert.ok(challenge);
    assert.ok(challenge.classList.contains('hidden'));
  });

  it('has results screen hidden by default', () => {
    const results = doc.getElementById('resultsScreen');
    assert.ok(results);
    assert.ok(results.classList.contains('hidden'));
  });

  it('has start button', () => {
    const btn = doc.getElementById('startBtn');
    assert.ok(btn);
    assert.ok(btn.textContent.includes('Start'));
  });

  it('has timer display', () => {
    const timer = doc.getElementById('timerDisplay');
    assert.ok(timer);
    assert.ok(timer.classList.contains('timer-display'));
  });

  it('has answer textarea with aria-label', () => {
    const textarea = doc.getElementById('userAnswer');
    assert.ok(textarea);
    assert.equal(textarea.getAttribute('aria-label'), 'Your answer');
  });

  it('has submit and skip buttons', () => {
    const submit = doc.getElementById('submitBtn');
    assert.ok(submit);
    assert.ok(submit.textContent.includes('Submit'));

    const skipBtns = doc.querySelectorAll('.skip-link');
    assert.ok(skipBtns.length > 0);
  });

  it('has progress bar elements', () => {
    assert.ok(doc.getElementById('progressContainer'));
    assert.ok(doc.getElementById('progressFill'));
    assert.ok(doc.getElementById('progressText'));
    assert.ok(doc.getElementById('progressAccuracy'));
  });

  it('has results sections', () => {
    assert.ok(doc.getElementById('statsGrid'));
    assert.ok(doc.getElementById('breakdownBody'));
    assert.ok(doc.getElementById('speedChart'));
    assert.ok(doc.getElementById('aiComparisonBars'));
    assert.ok(doc.getElementById('difficultyList'));
    assert.ok(doc.getElementById('insightBox'));
  });

  it('has accuracy badge', () => {
    const badge = doc.getElementById('accuracyBadge');
    assert.ok(badge);
    assert.ok(badge.classList.contains('accuracy-badge'));
  });

  it('has CSP meta tag', () => {
    const csp = doc.querySelector('meta[http-equiv="Content-Security-Policy"]');
    assert.ok(csp);
    assert.ok(csp.content.includes("default-src 'none'"));
  });

  it('has referrer policy', () => {
    const ref = doc.querySelector('meta[name="referrer"]');
    assert.ok(ref);
    assert.equal(ref.content, 'no-referrer');
  });

  it('links to shared stylesheet', () => {
    const link = doc.querySelector('link[rel="stylesheet"][href="shared.css"]');
    assert.ok(link);
  });

  it('includes shared.js functionality', () => {
    // shared.js is inlined for testing; verify sanitize function exists
    assert.ok(typeof dom.window.sanitize === 'function');
  });

  it('has navigation links', () => {
    const navLinks = doc.querySelectorAll('.nav-links a');
    assert.ok(navLinks.length >= 3);
    const hrefs = Array.from(navLinks).map(a => a.href);
    assert.ok(hrefs.some(h => h.includes('index.html')));
    assert.ok(hrefs.some(h => h.includes('demo.html')));
  });

  it('has footer', () => {
    const footer = doc.querySelector('footer');
    assert.ok(footer);
    assert.ok(footer.textContent.includes('GIF CAPTCHA'));
  });
});

// ===== Rendering Functions =====

describe('Benchmark: Result Rendering', () => {
  let dom, Benchmark, doc;

  beforeEach(() => {
    dom = createBenchDOM();
    Benchmark = dom.window.Benchmark;
    doc = dom.window.document;
  });

  it('renderStatsGrid creates 6 stat cards', () => {
    const stats = { avgTime: 5000, medianTime: 4500, fastestTime: 2000, slowestTime: 12000, accuracy: 80, totalTime: 50000 };
    Benchmark._renderStatsGrid(stats);
    const cards = doc.querySelectorAll('#statsGrid .stat-card');
    assert.equal(cards.length, 6);
  });

  it('stat cards show formatted values', () => {
    const stats = { avgTime: 5000, medianTime: 4500, fastestTime: 2000, slowestTime: 12000, accuracy: 80, totalTime: 50000 };
    Benchmark._renderStatsGrid(stats);
    const values = doc.querySelectorAll('#statsGrid .stat-value');
    const texts = Array.from(values).map(v => v.textContent);
    assert.ok(texts.some(t => t.includes('5.0s'))); // avg
    assert.ok(texts.some(t => t.includes('80%'))); // accuracy
  });

  it('renderBreakdown creates table rows', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'Test A', category: 'narrative', time: 3000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'Test B', category: 'social', time: 5000, skipped: true, answer: '' }
    ]);
    Benchmark._renderBreakdown();
    const rows = doc.querySelectorAll('#breakdownBody tr');
    assert.equal(rows.length, 2);
  });

  it('breakdown shows correct status icons', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 3000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 5000, skipped: true, answer: '' }
    ]);
    Benchmark._renderBreakdown();
    const statusCells = doc.querySelectorAll('#breakdownBody .status-icon');
    assert.equal(statusCells[0].textContent, '✅');
    assert.equal(statusCells[1].textContent, '⏭️');
  });

  it('breakdown has time bars with speed classes', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 3000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 20000, skipped: false, answer: 'y' }
    ]);
    Benchmark._renderBreakdown();
    const bars = doc.querySelectorAll('#breakdownBody .time-bar');
    assert.ok(bars[0].classList.contains('fast'));
    assert.ok(bars[1].classList.contains('slow'));
  });

  it('renderDifficultyRanking sorts by time descending', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'Fast', category: 'narrative', time: 2000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'Slow', category: 'social', time: 15000, skipped: false, answer: 'y' },
      { challengeId: 3, title: 'Medium', category: 'physical', time: 7000, skipped: false, answer: 'z' }
    ]);
    Benchmark._renderDifficultyRanking();
    const items = doc.querySelectorAll('#difficultyList li');
    assert.equal(items.length, 3);
    assert.ok(items[0].textContent.includes('Slow'));   // hardest first
    assert.ok(items[2].textContent.includes('Fast'));   // easiest last
  });

  it('renderDifficultyRanking excludes skipped', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 3000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 5000, skipped: true, answer: '' }
    ]);
    Benchmark._renderDifficultyRanking();
    const items = doc.querySelectorAll('#difficultyList li');
    assert.equal(items.length, 1);
  });

  it('renderDifficultyRanking shows category tags', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 3000, skipped: false, answer: 'x' }
    ]);
    Benchmark._renderDifficultyRanking();
    const tag = doc.querySelector('#difficultyList .tag');
    assert.ok(tag);
    assert.ok(tag.classList.contains('tag-narrative'));
  });

  it('renderInsight produces text for high accuracy', () => {
    const stats = { avgTime: 5000, accuracy: 90, skipped: 0, answered: 10, totalTime: 50000 };
    Benchmark._renderInsight(stats);
    const text = doc.getElementById('insightText').textContent;
    assert.ok(text.includes('Impressive'));
    assert.ok(text.includes('90%'));
  });

  it('renderInsight produces text for moderate accuracy', () => {
    const stats = { avgTime: 12000, accuracy: 65, skipped: 2, answered: 8, totalTime: 100000 };
    Benchmark._renderInsight(stats);
    const text = doc.getElementById('insightText').textContent;
    assert.ok(text.includes('65%'));
  });

  it('renderInsight mentions abandonment for mostly-skipped', () => {
    const stats = { avgTime: 20000, accuracy: 20, skipped: 8, answered: 2, totalTime: 200000 };
    Benchmark._renderInsight(stats);
    const text = doc.getElementById('insightText').textContent;
    assert.ok(text.includes('skipped') || text.includes('abandonment'));
  });

  it('renderAIComparison creates bars for human + 5 AI models', () => {
    const stats = { avgTime: 8000, accuracy: 70 };
    Benchmark._renderAIComparison(stats);
    const bars = doc.querySelectorAll('#aiComparisonBars .ai-bar');
    assert.equal(bars.length, 6); // 1 human + 5 AI
  });

  it('AI comparison shows human bar first', () => {
    const stats = { avgTime: 8000, accuracy: 70 };
    Benchmark._renderAIComparison(stats);
    const firstBar = doc.querySelector('#aiComparisonBars .ai-bar .ai-name');
    assert.ok(firstBar.textContent.includes('You'));
  });

  it('AI comparison includes accuracy labels', () => {
    const stats = { avgTime: 8000, accuracy: 70 };
    Benchmark._renderAIComparison(stats);
    const labels = doc.querySelectorAll('#aiComparisonBars .ai-time-label');
    assert.ok(labels[0].textContent.includes('70% acc'));
    assert.ok(labels[1].textContent.includes('0% acc')); // GPT-4 2023
  });

  it('renderDifficultyRanking shows fallback for empty results', () => {
    Benchmark._setResults([]);
    Benchmark._renderDifficultyRanking();
    const list = doc.getElementById('difficultyList');
    assert.ok(list.textContent.includes('No answered'));
  });
});

// ===== State Management =====

describe('Benchmark: State Management', () => {
  let dom, Benchmark;

  beforeEach(() => {
    dom = createBenchDOM();
    Benchmark = dom.window.Benchmark;
  });

  it('getResults returns results array', () => {
    assert.ok(Array.isArray(Benchmark.getResults()));
    assert.equal(Benchmark.getResults().length, 0);
  });

  it('_setResults updates results and counters', () => {
    Benchmark._setResults([
      { challengeId: 1, title: 'A', category: 'narrative', time: 3000, skipped: false, answer: 'x' },
      { challengeId: 2, title: 'B', category: 'social', time: 5000, skipped: true, answer: '' }
    ]);
    assert.equal(Benchmark.getResults().length, 2);
    const stats = Benchmark.calcStats();
    assert.equal(stats.answered, 1);
    assert.equal(stats.skipped, 1);
  });
});

// ===== Index page link =====

describe('Benchmark: Index Page Integration', () => {
  let doc;

  before(() => {
    const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
    const dom = new JSDOM(indexHtml, { url: 'https://example.com/' });
    doc = dom.window.document;
  });

  it('index.html links to benchmark.html', () => {
    const links = doc.querySelectorAll('a[href="benchmark.html"]');
    assert.ok(links.length > 0, 'No link to benchmark.html found on index page');
  });

  it('benchmark link has descriptive text', () => {
    const link = doc.querySelector('a[href="benchmark.html"]');
    assert.ok(link.textContent.includes('Benchmark') || link.textContent.includes('Response Time'));
  });
});
