/**
 * Tests for the GIF CAPTCHA Effectiveness Dashboard (effectiveness.html)
 *
 * Validates scoring logic, matrix generation, category grouping,
 * model vulnerability, correlation, insights, and overview computations.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const HTML = fs.readFileSync(path.join(__dirname, '..', 'effectiveness.html'), 'utf8');

function createDOM() {
    const dom = new JSDOM(HTML, {
        runScripts: 'dangerously',
        pretendToBeVisual: true,
        url: 'https://example.com/effectiveness.html',
    });
    return dom;
}

describe('Effectiveness: calcEffectiveness', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('returns difference when human > AI', () => {
        assert.equal(w.calcEffectiveness(90, 30), 60);
    });
    it('returns 0 when AI equals human', () => {
        assert.equal(w.calcEffectiveness(50, 50), 0);
    });
    it('clamps to 0 when AI > human', () => {
        assert.equal(w.calcEffectiveness(30, 80), 0);
    });
    it('clamps to 100 when difference exceeds 100', () => {
        assert.equal(w.calcEffectiveness(150, 10), 100);
    });
    it('returns 100 for (100, 0)', () => {
        assert.equal(w.calcEffectiveness(100, 0), 100);
    });
    it('returns 0 for (0, 0)', () => {
        assert.equal(w.calcEffectiveness(0, 0), 0);
    });
    it('handles negative AI quality', () => {
        assert.equal(w.calcEffectiveness(50, -10), 60);
    });
    it('handles large values clamped to 100', () => {
        assert.equal(w.calcEffectiveness(200, 50), 100);
    });
});

describe('Effectiveness: buildMatrix', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('returns correct number of rows with real data', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        assert.equal(m.length, 10);
    });
    it('each row has 5 model scores', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        for (const row of m) {
            assert.equal(Object.keys(row.scores).length, 5);
        }
    });
    it('all scores are 0-100', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        for (const row of m) {
            for (const s of Object.values(row.scores)) {
                assert.ok(s >= 0 && s <= 100, `Score ${s} out of range`);
            }
        }
    });
    it('computes correct scores for simple input', () => {
        const caps = [{ id: 1, title: 'T', category: 'C', responses: { m1: { quality: 20 }, m2: { quality: 50 } } }];
        const mods = [{ id: 'm1' }, { id: 'm2' }];
        const m = w.buildMatrix(caps, mods, 90);
        assert.equal(m[0].scores.m1, 70);
        assert.equal(m[0].scores.m2, 40);
    });
    it('computes row average', () => {
        const caps = [{ id: 1, title: 'T', category: 'C', responses: { m1: { quality: 20 }, m2: { quality: 50 } } }];
        const mods = [{ id: 'm1' }, { id: 'm2' }];
        const m = w.buildMatrix(caps, mods, 90);
        assert.equal(m[0].avg, 55);
    });
    it('clamps scores to 0 when AI > human', () => {
        const caps = [{ id: 1, title: 'T', category: 'C', responses: { m1: { quality: 100 } } }];
        const m = w.buildMatrix(caps, [{ id: 'm1' }], 50);
        assert.equal(m[0].scores.m1, 0);
    });
    it('handles missing model response (defaults quality 0)', () => {
        const caps = [{ id: 1, title: 'T', category: 'C', responses: {} }];
        const m = w.buildMatrix(caps, [{ id: 'x' }], 80);
        assert.equal(m[0].scores.x, 80);
    });
    it('handles empty captchas array', () => {
        const m = w.buildMatrix([], [{ id: 'x' }], 90);
        assert.equal(m.length, 0);
    });
    it('preserves id, title, category', () => {
        const caps = [{ id: 42, title: 'Hello', category: 'World', responses: { m: { quality: 0 } } }];
        const m = w.buildMatrix(caps, [{ id: 'm' }], 90);
        assert.equal(m[0].id, 42);
        assert.equal(m[0].title, 'Hello');
        assert.equal(m[0].category, 'World');
    });
});

describe('Effectiveness: calcModelAverages', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('computes averages correctly', () => {
        const matrix = [{ scores: { a: 60, b: 80 } }, { scores: { a: 40, b: 20 } }];
        const avgs = w.calcModelAverages(matrix, [{ id: 'a' }, { id: 'b' }]);
        assert.equal(avgs.a, 50);
        assert.equal(avgs.b, 50);
    });
    it('handles single row', () => {
        const avgs = w.calcModelAverages([{ scores: { x: 75 } }], [{ id: 'x' }]);
        assert.equal(avgs.x, 75);
    });
    it('works with real data', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const avgs = w.calcModelAverages(m, w.models);
        for (const model of w.models) {
            assert.ok(avgs[model.id] >= 0 && avgs[model.id] <= 100);
        }
    });
    it('GPT-4 has highest effectiveness (all blocked)', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const avgs = w.calcModelAverages(m, w.models);
        assert.equal(avgs.gpt4, 90);
    });
});

describe('Effectiveness: groupByCategory', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('groups and averages correctly', () => {
        const matrix = [{ category: 'A', avg: 60 }, { category: 'A', avg: 80 }, { category: 'B', avg: 40 }];
        const g = w.groupByCategory(matrix);
        assert.equal(g.A, 70);
        assert.equal(g.B, 40);
    });
    it('handles single category', () => {
        const g = w.groupByCategory([{ category: 'X', avg: 55 }]);
        assert.equal(g.X, 55);
        assert.equal(Object.keys(g).length, 1);
    });
    it('all same category averages correctly', () => {
        const g = w.groupByCategory([{ category: 'Z', avg: 10 }, { category: 'Z', avg: 20 }, { category: 'Z', avg: 30 }]);
        assert.equal(g.Z, 20);
    });
    it('works with real data - has multiple categories', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const g = w.groupByCategory(m);
        assert.ok(Object.keys(g).length > 1);
    });
});

describe('Effectiveness: findHardestCaptcha', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('finds captcha with highest avg effectiveness', () => {
        const h = w.findHardestCaptcha([{ id: 1, avg: 50 }, { id: 2, avg: 90 }, { id: 3, avg: 70 }]);
        assert.equal(h.id, 2);
    });
    it('handles single element', () => {
        assert.equal(w.findHardestCaptcha([{ id: 5, avg: 42 }]).id, 5);
    });
    it('works with real data', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const h = w.findHardestCaptcha(m);
        assert.ok(h.id > 0);
    });
});

describe('Effectiveness: findMostEffectiveCategory', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('finds highest category', () => {
        assert.equal(w.findMostEffectiveCategory({ A: 50, B: 80, C: 30 }), 'B');
    });
    it('handles single category', () => {
        assert.equal(w.findMostEffectiveCategory({ X: 42 }), 'X');
    });
});

describe('Effectiveness: calcHumanSuccessRate', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('returns 100 for all captchas', () => {
        assert.equal(w.calcHumanSuccessRate(w.captchas), 100);
    });
    it('returns 100 for empty array', () => {
        assert.equal(w.calcHumanSuccessRate([]), 100);
    });
});

describe('Effectiveness: calcAIBestCaseRate', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('counts captchas where any model solves', () => {
        const caps = [
            { responses: { a: { result: 'solved' }, b: { result: 'blocked' } } },
            { responses: { a: { result: 'blocked' }, b: { result: 'blocked' } } },
            { responses: { a: { result: 'partial' }, b: { result: 'solved' } } },
        ];
        assert.equal(w.calcAIBestCaseRate(caps, [{ id: 'a' }, { id: 'b' }]), 67);
    });
    it('returns 0 when none solved', () => {
        assert.equal(w.calcAIBestCaseRate([{ responses: { a: { result: 'blocked' } } }], [{ id: 'a' }]), 0);
    });
    it('returns 100 when all solved', () => {
        const caps = [{ responses: { a: { result: 'solved' } } }, { responses: { a: { result: 'solved' } } }];
        assert.equal(w.calcAIBestCaseRate(caps, [{ id: 'a' }]), 100);
    });
    it('works with real data', () => {
        const rate = w.calcAIBestCaseRate(w.captchas, w.models);
        assert.ok(rate > 0 && rate <= 100);
    });
});

describe('Effectiveness: calcAvgHumanAIGap', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('computes average of min effectiveness per row', () => {
        const matrix = [{ scores: { a: 80, b: 40 } }, { scores: { a: 60, b: 20 } }];
        assert.equal(w.calcAvgHumanAIGap(matrix, [{ id: 'a' }, { id: 'b' }]), 30);
    });
    it('handles single model', () => {
        assert.equal(w.calcAvgHumanAIGap([{ scores: { a: 50 } }], [{ id: 'a' }]), 50);
    });
    it('works with real data - positive gap', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        assert.ok(w.calcAvgHumanAIGap(m, w.models) > 0);
    });
});

describe('Effectiveness: findModelVulnerability', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('finds weakest and strongest captchas', () => {
        const matrix = [{ id: 1, scores: { m: 30 } }, { id: 2, scores: { m: 90 } }, { id: 3, scores: { m: 60 } }];
        const v = w.findModelVulnerability(matrix, 'm');
        assert.equal(v.weakest.id, 1);
        assert.equal(v.strongest.id, 2);
        assert.equal(v.minEff, 30);
        assert.equal(v.maxEff, 90);
    });
    it('handles single captcha', () => {
        const v = w.findModelVulnerability([{ id: 5, scores: { x: 42 } }], 'x');
        assert.equal(v.weakest.id, 5);
        assert.equal(v.strongest.id, 5);
    });
    it('works for each real model', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        for (const model of w.models) {
            const v = w.findModelVulnerability(m, model.id);
            assert.ok(v.weakest);
            assert.ok(v.strongest);
            assert.ok(v.minEff <= v.maxEff);
        }
    });
});

describe('Effectiveness: calcCorrelation', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('perfect positive correlation', () => {
        assert.ok(Math.abs(w.calcCorrelation([1, 2, 3], [10, 20, 30]) - 1) < 0.0001);
    });
    it('perfect negative correlation', () => {
        assert.ok(Math.abs(w.calcCorrelation([1, 2, 3], [30, 20, 10]) - (-1)) < 0.0001);
    });
    it('returns 0 for constant y', () => {
        assert.equal(w.calcCorrelation([1, 2, 3], [5, 5, 5]), 0);
    });
    it('returns 0 for empty arrays', () => {
        assert.equal(w.calcCorrelation([], []), 0);
    });
    it('returns 0 for single element', () => {
        assert.equal(w.calcCorrelation([5], [10]), 0);
    });
    it('real data correlation is between -1 and 1', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const r = w.calcCorrelation(w.captchas.map(c => c.difficulty), m.map(r => r.avg));
        assert.ok(r >= -1 && r <= 1);
    });
});

describe('Effectiveness: generateInsights', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('returns array of strings', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const catAvgs = w.groupByCategory(m);
        const insights = w.generateInsights(m, w.models, catAvgs, w.captchas);
        assert.ok(Array.isArray(insights));
        assert.ok(insights.length > 0);
    });
    it('contains most effective CAPTCHA', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const insights = w.generateInsights(m, w.models, w.groupByCategory(m), w.captchas);
        assert.ok(insights.some(i => i.includes('Most effective CAPTCHA')));
    });
    it('contains least effective CAPTCHA', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const insights = w.generateInsights(m, w.models, w.groupByCategory(m), w.captchas);
        assert.ok(insights.some(i => i.includes('Least effective CAPTCHA')));
    });
    it('contains vulnerability info', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const insights = w.generateInsights(m, w.models, w.groupByCategory(m), w.captchas);
        assert.ok(insights.some(i => i.includes('vulnerable')));
    });
    it('contains correlation info', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const insights = w.generateInsights(m, w.models, w.groupByCategory(m), w.captchas);
        assert.ok(insights.some(i => i.includes('correlation')));
    });
    it('contains strategy recommendation', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const insights = w.generateInsights(m, w.models, w.groupByCategory(m), w.captchas);
        assert.ok(insights.some(i => i.includes('Recommended')));
    });
    it('contains category ranking', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const insights = w.generateInsights(m, w.models, w.groupByCategory(m), w.captchas);
        assert.ok(insights.some(i => i.includes('Category effectiveness ranking')));
    });
});

describe('Effectiveness: Edge cases', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('all zero AI quality gives max effectiveness', () => {
        const m = w.buildMatrix([{ id: 1, title: 'T', category: 'C', responses: { m: { quality: 0 } } }], [{ id: 'm' }], 90);
        assert.equal(m[0].scores.m, 90);
    });
    it('all perfect AI quality gives zero effectiveness', () => {
        const m = w.buildMatrix([{ id: 1, title: 'T', category: 'C', responses: { m: { quality: 90 } } }], [{ id: 'm' }], 90);
        assert.equal(m[0].scores.m, 0);
    });
    it('equal human and AI quality', () => {
        assert.equal(w.calcEffectiveness(50, 50), 0);
    });
    it('missing response data defaults to quality 0', () => {
        const m = w.buildMatrix([{ id: 1, title: 'T', category: 'C', responses: {} }], [{ id: 'x' }], 80);
        assert.equal(m[0].scores.x, 80);
    });
    it('very large quality values clamped to 100', () => {
        assert.equal(w.calcEffectiveness(200, 50), 100);
    });
});

describe('Effectiveness: scoreColor', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('green for high scores', () => {
        assert.ok(w.scoreColor(70).includes('green'));
        assert.ok(w.scoreColor(100).includes('green'));
    });
    it('yellow for moderate scores', () => {
        assert.ok(w.scoreColor(40).includes('yellow'));
        assert.ok(w.scoreColor(69).includes('yellow'));
    });
    it('red for low scores', () => {
        assert.ok(w.scoreColor(0).includes('red'));
        assert.ok(w.scoreColor(39).includes('red'));
    });
});

describe('Effectiveness: scoreBg', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('green bg for high scores', () => {
        assert.ok(w.scoreBg(80).includes('63, 185, 80'));
    });
    it('yellow bg for moderate', () => {
        assert.ok(w.scoreBg(50).includes('210, 153, 34'));
    });
    it('red bg for low', () => {
        assert.ok(w.scoreBg(10).includes('248, 81, 73'));
    });
});

describe('Effectiveness: Integration - full 10x5 matrix', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('matrix has 10 rows', () => {
        assert.equal(w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY).length, 10);
    });
    it('each row has 5 model scores', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        for (const row of m) assert.equal(Object.keys(row.scores).length, 5);
    });
    it('GPT-4 has highest effectiveness (worst AI)', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        assert.equal(w.calcModelAverages(m, w.models).gpt4, 90);
    });
    it('Gemini 1.5 has lowest effectiveness (best AI)', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const avgs = w.calcModelAverages(m, w.models);
        for (const model of w.models) {
            if (model.id !== 'gemini15') assert.ok(avgs[model.id] >= avgs.gemini15);
        }
    });
});

describe('Effectiveness: Overview card computations', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('human success rate is 100%', () => {
        assert.equal(w.calcHumanSuccessRate(w.captchas), 100);
    });
    it('AI best-case rate is reasonable', () => {
        const rate = w.calcAIBestCaseRate(w.captchas, w.models);
        assert.ok(rate > 0 && rate <= 100);
    });
    it('avg gap is positive', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        assert.ok(w.calcAvgHumanAIGap(m, w.models) > 0);
    });
    it('hardest captcha exists with valid avg', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const h = w.findHardestCaptcha(m);
        assert.ok(h && h.avg > 0);
    });
    it('most effective category is a string', () => {
        const m = w.buildMatrix(w.captchas, w.models, w.HUMAN_QUALITY);
        const best = w.findMostEffectiveCategory(w.groupByCategory(m));
        assert.equal(typeof best, 'string');
    });
});

describe('Effectiveness: DOM rendering', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('overview grid has 5 cards', () => {
        const cards = w.document.querySelectorAll('#overviewGrid .overview-card');
        assert.equal(cards.length, 5);
    });
    it('matrix table has rows', () => {
        const rows = w.document.querySelectorAll('#effectivenessMatrix tbody tr');
        assert.ok(rows.length >= 10); // 10 data + 1 avg row
    });
    it('model cards rendered', () => {
        const cards = w.document.querySelectorAll('#modelCards .model-card');
        assert.equal(cards.length, 5);
    });
    it('insights list has items', () => {
        const items = w.document.querySelectorAll('#insightsList li');
        assert.ok(items.length >= 5);
    });
});

describe('Effectiveness: Data integrity', () => {
    let w;
    before(() => { w = createDOM().window; });

    it('has exactly 10 captchas', () => {
        assert.equal(w.captchas.length, 10);
    });
    it('has exactly 5 models', () => {
        assert.equal(w.models.length, 5);
    });
    it('each captcha has difficulty 1-5', () => {
        for (const c of w.captchas) {
            assert.ok(c.difficulty >= 1 && c.difficulty <= 5, `CAPTCHA ${c.id} difficulty ${c.difficulty} out of range`);
        }
    });
    it('each captcha has expectedKeywords array', () => {
        for (const c of w.captchas) {
            assert.ok(Array.isArray(c.expectedKeywords), `CAPTCHA ${c.id} missing expectedKeywords`);
            assert.ok(c.expectedKeywords.length > 0);
        }
    });
    it('each captcha has responses for all 5 models', () => {
        for (const c of w.captchas) {
            for (const m of w.models) {
                assert.ok(c.responses[m.id], `CAPTCHA ${c.id} missing response for ${m.id}`);
            }
        }
    });
    it('each response has quality 0-100', () => {
        for (const c of w.captchas) {
            for (const m of w.models) {
                const q = c.responses[m.id].quality;
                assert.ok(q >= 0 && q <= 100, `CAPTCHA ${c.id} model ${m.id} quality ${q} out of range`);
            }
        }
    });
    it('HUMAN_QUALITY is 90', () => {
        assert.equal(w.HUMAN_QUALITY, 90);
    });
});
