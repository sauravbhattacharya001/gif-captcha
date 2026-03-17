/**
 * Tests for the User Feedback Collector module.
 *
 * Validates feedback storage, statistics computation, sentiment scoring,
 * bar chart data generation, export formatting, and embed code generation.
 */

// ── Module (extracted for testing) ──
function createFeedbackCollector() {
    var storage = [];

    function loadFeedback() { return storage.slice(); }

    function saveFeedback(data) { storage = data.slice(); }

    function addFeedback(entry) {
        if (!entry.ease && !entry.sentiment && !entry.speed) {
            return { ok: false, error: 'Please answer at least one question.' };
        }
        var record = {
            id: entry.id || Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
            timestamp: entry.timestamp || new Date().toISOString(),
            ease: entry.ease || 0,
            sentiment: entry.sentiment || '',
            speed: entry.speed || '',
            issues: entry.issues || [],
            comment: entry.comment || ''
        };
        storage.unshift(record);
        return { ok: true, record: record };
    }

    function clearFeedback() { storage = []; }

    function computeStats() {
        var data = storage;
        var total = data.length;
        if (!total) return { total: 0, avgEase: 0, nps: 0, easeDistribution: {}, sentimentCounts: {}, speedCounts: {}, issueCounts: {} };

        var easeSum = 0, easeCount = 0;
        var easeDist = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
        var sentimentCounts = { frustrated: 0, confused: 0, neutral: 0, fine: 0, delighted: 0 };
        var speedCounts = { instant: 0, quick: 0, moderate: 0, slow: 0, 'gave-up': 0 };
        var issueCounts = {};

        data.forEach(function (d) {
            if (d.ease) { easeSum += d.ease; easeCount++; easeDist[d.ease] = (easeDist[d.ease] || 0) + 1; }
            if (d.sentiment && sentimentCounts[d.sentiment] !== undefined) sentimentCounts[d.sentiment]++;
            if (d.speed && speedCounts[d.speed] !== undefined) speedCounts[d.speed]++;
            (d.issues || []).forEach(function (i) { issueCounts[i] = (issueCounts[i] || 0) + 1; });
        });

        var avgEase = easeCount ? easeSum / easeCount : 0;
        var positive = sentimentCounts.fine + sentimentCounts.delighted;
        var negative = sentimentCounts.frustrated + sentimentCounts.confused;
        var nps = Math.round(((positive - negative) / total) * 100);

        return { total: total, avgEase: avgEase, nps: nps, easeDistribution: easeDist, sentimentCounts: sentimentCounts, speedCounts: speedCounts, issueCounts: issueCounts };
    }

    function getComments(limit) {
        return storage.filter(function (d) { return d.comment; }).slice(0, limit || 20);
    }

    function exportCsv() {
        var header = 'id,timestamp,ease,sentiment,speed,issues,comment';
        var rows = [header].concat(storage.map(function (d) {
            return [d.id, d.timestamp, d.ease || '', d.sentiment || '', d.speed || '',
                (d.issues || []).join(';'),
                '"' + (d.comment || '').replace(/"/g, '""') + '"'].join(',');
        }));
        return rows.join('\n');
    }

    function exportJson() {
        return JSON.stringify(storage, null, 2);
    }

    function generateEmbedCode(config) {
        var theme = config.theme || 'dark';
        var accent = config.accent || '#58a6ff';
        var compact = config.compact || false;
        var questions = config.questions || ['ease', 'sentiment', 'speed', 'issues', 'freetext'];
        return '<div id="captcha-feedback" data-theme="' + theme + '" data-accent="' + accent +
            '" data-compact="' + compact + '" data-questions="' + questions.join(',') + '"></div>\n' +
            '<script src="https://sauravbhattacharya001.github.io/gif-captcha/feedback-widget.js"><\/script>';
    }

    function sentimentClass(sentiment) {
        if (sentiment === 'delighted' || sentiment === 'fine') return 'positive';
        if (sentiment === 'neutral') return 'neutral';
        return 'negative';
    }

    function timeSince(ts) {
        var diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
        if (diff < 60) return diff + 's ago';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return Math.floor(diff / 86400) + 'd ago';
    }

    return {
        loadFeedback: loadFeedback, saveFeedback: saveFeedback, addFeedback: addFeedback,
        clearFeedback: clearFeedback, computeStats: computeStats, getComments: getComments,
        exportCsv: exportCsv, exportJson: exportJson, generateEmbedCode: generateEmbedCode,
        sentimentClass: sentimentClass, timeSince: timeSince
    };
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { createFeedbackCollector: createFeedbackCollector };
}

// ── Tests ──
var assert = require('assert');
var fc = createFeedbackCollector();

// --- Submission Validation ---
(function testRejectsEmptySubmission() {
    var r = fc.addFeedback({});
    assert.strictEqual(r.ok, false);
    assert.ok(r.error.includes('at least one'));
})();

(function testAcceptsEaseOnly() {
    fc.clearFeedback();
    var r = fc.addFeedback({ ease: 4 });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.record.ease, 4);
})();

(function testAcceptsSentimentOnly() {
    fc.clearFeedback();
    var r = fc.addFeedback({ sentiment: 'fine' });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.record.sentiment, 'fine');
})();

(function testAcceptsSpeedOnly() {
    fc.clearFeedback();
    var r = fc.addFeedback({ speed: 'quick' });
    assert.strictEqual(r.ok, true);
})();

(function testNewFeedbackPrepended() {
    fc.clearFeedback();
    fc.addFeedback({ ease: 3, id: 'first' });
    fc.addFeedback({ ease: 5, id: 'second' });
    var data = fc.loadFeedback();
    assert.strictEqual(data[0].id, 'second');
    assert.strictEqual(data[1].id, 'first');
})();

// --- Statistics ---
(function testStatsEmpty() {
    fc.clearFeedback();
    var s = fc.computeStats();
    assert.strictEqual(s.total, 0);
    assert.strictEqual(s.avgEase, 0);
    assert.strictEqual(s.nps, 0);
})();

(function testAvgEase() {
    fc.clearFeedback();
    fc.addFeedback({ ease: 5 });
    fc.addFeedback({ ease: 3 });
    fc.addFeedback({ ease: 4 });
    var s = fc.computeStats();
    assert.strictEqual(s.total, 3);
    assert.strictEqual(s.avgEase, 4);
})();

(function testEaseDistribution() {
    fc.clearFeedback();
    fc.addFeedback({ ease: 5 });
    fc.addFeedback({ ease: 5 });
    fc.addFeedback({ ease: 3 });
    var s = fc.computeStats();
    assert.strictEqual(s.easeDistribution[5], 2);
    assert.strictEqual(s.easeDistribution[3], 1);
    assert.strictEqual(s.easeDistribution[1], 0);
})();

(function testSentimentCounts() {
    fc.clearFeedback();
    fc.addFeedback({ sentiment: 'delighted' });
    fc.addFeedback({ sentiment: 'fine' });
    fc.addFeedback({ sentiment: 'frustrated' });
    var s = fc.computeStats();
    assert.strictEqual(s.sentimentCounts.delighted, 1);
    assert.strictEqual(s.sentimentCounts.fine, 1);
    assert.strictEqual(s.sentimentCounts.frustrated, 1);
})();

(function testNpsPositive() {
    fc.clearFeedback();
    fc.addFeedback({ sentiment: 'delighted' });
    fc.addFeedback({ sentiment: 'fine' });
    fc.addFeedback({ sentiment: 'neutral' });
    var s = fc.computeStats();
    // positive=2, negative=0, total=3 → NPS = 67
    assert.strictEqual(s.nps, 67);
})();

(function testNpsNegative() {
    fc.clearFeedback();
    fc.addFeedback({ sentiment: 'frustrated' });
    fc.addFeedback({ sentiment: 'confused' });
    fc.addFeedback({ sentiment: 'fine' });
    var s = fc.computeStats();
    // positive=1, negative=2, total=3 → NPS = -33
    assert.strictEqual(s.nps, -33);
})();

(function testSpeedCounts() {
    fc.clearFeedback();
    fc.addFeedback({ speed: 'instant' });
    fc.addFeedback({ speed: 'instant' });
    fc.addFeedback({ speed: 'slow' });
    var s = fc.computeStats();
    assert.strictEqual(s.speedCounts.instant, 2);
    assert.strictEqual(s.speedCounts.slow, 1);
})();

(function testIssueCounts() {
    fc.clearFeedback();
    fc.addFeedback({ ease: 3, issues: ['slow-loading', 'mobile-issues'] });
    fc.addFeedback({ ease: 4, issues: ['slow-loading'] });
    fc.addFeedback({ ease: 5, issues: ['no-issues'] });
    var s = fc.computeStats();
    assert.strictEqual(s.issueCounts['slow-loading'], 2);
    assert.strictEqual(s.issueCounts['mobile-issues'], 1);
    assert.strictEqual(s.issueCounts['no-issues'], 1);
})();

// --- Comments ---
(function testGetComments() {
    fc.clearFeedback();
    fc.addFeedback({ ease: 5, comment: 'Great!' });
    fc.addFeedback({ ease: 4 });
    fc.addFeedback({ ease: 3, comment: 'OK' });
    var comments = fc.getComments();
    assert.strictEqual(comments.length, 2);
    assert.strictEqual(comments[0].comment, 'OK');
})();

(function testGetCommentsLimit() {
    fc.clearFeedback();
    for (var i = 0; i < 10; i++) fc.addFeedback({ ease: 3, comment: 'Comment ' + i });
    var comments = fc.getComments(3);
    assert.strictEqual(comments.length, 3);
})();

// --- Export ---
(function testExportCsvHeader() {
    fc.clearFeedback();
    fc.addFeedback({ ease: 5, sentiment: 'fine', speed: 'quick', issues: ['no-issues'], comment: 'Nice' });
    var csv = fc.exportCsv();
    var lines = csv.split('\n');
    assert.strictEqual(lines[0], 'id,timestamp,ease,sentiment,speed,issues,comment');
    assert.ok(lines[1].includes('5'));
    assert.ok(lines[1].includes('fine'));
    assert.ok(lines[1].includes('"Nice"'));
})();

(function testExportCsvEscapesQuotes() {
    fc.clearFeedback();
    fc.addFeedback({ ease: 4, comment: 'Said "hello"' });
    var csv = fc.exportCsv();
    assert.ok(csv.includes('""hello""'));
})();

(function testExportJson() {
    fc.clearFeedback();
    fc.addFeedback({ ease: 3 });
    var json = fc.exportJson();
    var parsed = JSON.parse(json);
    assert.strictEqual(parsed.length, 1);
    assert.strictEqual(parsed[0].ease, 3);
})();

// --- Embed Code ---
(function testEmbedCodeDefault() {
    var code = fc.generateEmbedCode({});
    assert.ok(code.includes('data-theme="dark"'));
    assert.ok(code.includes('data-accent="#58a6ff"'));
    assert.ok(code.includes('feedback-widget.js'));
})();

(function testEmbedCodeCustom() {
    var code = fc.generateEmbedCode({ theme: 'light', accent: '#ff0000', compact: true, questions: ['ease', 'sentiment'] });
    assert.ok(code.includes('data-theme="light"'));
    assert.ok(code.includes('data-accent="#ff0000"'));
    assert.ok(code.includes('data-compact="true"'));
    assert.ok(code.includes('data-questions="ease,sentiment"'));
})();

// --- Sentiment Class ---
(function testSentimentClassPositive() {
    assert.strictEqual(fc.sentimentClass('delighted'), 'positive');
    assert.strictEqual(fc.sentimentClass('fine'), 'positive');
})();

(function testSentimentClassNeutral() {
    assert.strictEqual(fc.sentimentClass('neutral'), 'neutral');
})();

(function testSentimentClassNegative() {
    assert.strictEqual(fc.sentimentClass('frustrated'), 'negative');
    assert.strictEqual(fc.sentimentClass('confused'), 'negative');
})();

// --- Time Since ---
(function testTimeSinceSeconds() {
    var ts = new Date(Date.now() - 30000).toISOString();
    var result = fc.timeSince(ts);
    assert.ok(result.endsWith('s ago'));
})();

(function testTimeSinceMinutes() {
    var ts = new Date(Date.now() - 300000).toISOString();
    var result = fc.timeSince(ts);
    assert.ok(result.endsWith('m ago'));
})();

(function testTimeSinceHours() {
    var ts = new Date(Date.now() - 7200000).toISOString();
    var result = fc.timeSince(ts);
    assert.ok(result.endsWith('h ago'));
})();

(function testTimeSinceDays() {
    var ts = new Date(Date.now() - 172800000).toISOString();
    var result = fc.timeSince(ts);
    assert.ok(result.endsWith('d ago'));
})();

// --- Full Workflow ---
(function testFullWorkflow() {
    fc.clearFeedback();
    assert.strictEqual(fc.computeStats().total, 0);
    fc.addFeedback({ ease: 5, sentiment: 'delighted', speed: 'instant', issues: ['no-issues'], comment: 'Amazing!' });
    fc.addFeedback({ ease: 2, sentiment: 'frustrated', speed: 'slow', issues: ['hard-to-read', 'mobile-issues'], comment: 'Bad experience' });
    fc.addFeedback({ ease: 4, sentiment: 'fine', speed: 'quick', issues: ['no-issues'] });

    var s = fc.computeStats();
    assert.strictEqual(s.total, 3);
    assert.ok(Math.abs(s.avgEase - 3.67) < 0.01);
    assert.strictEqual(s.sentimentCounts.delighted, 1);
    assert.strictEqual(s.speedCounts.instant, 1);
    assert.strictEqual(s.issueCounts['no-issues'], 2);

    var comments = fc.getComments();
    assert.strictEqual(comments.length, 2);

    var csv = fc.exportCsv();
    assert.strictEqual(csv.split('\n').length, 4); // header + 3 rows

    fc.clearFeedback();
    assert.strictEqual(fc.loadFeedback().length, 0);
})();

(function testMixedPartialResponses() {
    fc.clearFeedback();
    fc.addFeedback({ ease: 4 });
    fc.addFeedback({ sentiment: 'neutral' });
    fc.addFeedback({ speed: 'moderate' });
    var s = fc.computeStats();
    assert.strictEqual(s.total, 3);
    assert.strictEqual(s.avgEase, 4); // only 1 ease response
    assert.strictEqual(s.sentimentCounts.neutral, 1);
    assert.strictEqual(s.speedCounts.moderate, 1);
})();

console.log('All 30 feedback collector tests passed ✓');
