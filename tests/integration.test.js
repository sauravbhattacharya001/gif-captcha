/**
 * Integration tests for the gif-captcha pipeline.
 *
 * Tests interactions between modules that form typical usage patterns:
 *   createChallenge → createPoolManager → pickChallenges
 *   createSecurityScorer driven by real challenge pools
 *   createSetAnalyzer → createDifficultyCalibrator flow
 *   createResponseAnalyzer + createBotDetector composing verdicts
 *   createAttemptTracker wrapping validateAnswer
 */
var gifCaptcha = require('../src/index');

// ── Test Helpers ────────────────────────────────────────────────────

function makeChallenges(count) {
  var challenges = [];
  var actions = ['falls down', 'dances wildly', 'trips over a cat',
    'walks into glass', 'slips on ice', 'does a backflip',
    'catches a ball', 'drops their phone', 'falls off chair',
    'runs into door'];
  var keywords = ['falls', 'dances', 'trips', 'walks', 'slips',
    'backflip', 'catches', 'drops', 'falls', 'runs'];
  for (var i = 1; i <= count; i++) {
    challenges.push(gifCaptcha.createChallenge({
      id: i,
      title: 'Challenge ' + i,
      gifUrl: 'https://example.com/gif' + i + '.gif',
      humanAnswer: 'A person ' + actions[i % 10],
      aiAnswer: 'A person is standing in a room',
      keywords: [keywords[i % 10]],
    }));
  }
  return challenges;
}

// ── Challenge → Pool Manager ───────────────────────────────────────

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');

describe('pipeline: challenge → pool manager', function () {

  test('challenges created by createChallenge work with pool.add + pool.pick', function () {
    var challenges = makeChallenges(10);
    var pool = gifCaptcha.createPoolManager();
    pool.add(challenges);
    var selected = pool.pick(3);
    assert.strictEqual((selected).length, 3);
    selected.forEach(function (c) {
      assert.notStrictEqual((c)["id"], undefined);
      assert.notStrictEqual((c)["gifUrl"], undefined);
      assert.notStrictEqual((c)["humanAnswer"], undefined);
      assert.strictEqual(Object.isFrozen(c), true);
    });
  });

  test('pool.pick returns unique challenges', function () {
    var challenges = makeChallenges(10);
    var pool = gifCaptcha.createPoolManager();
    pool.add(challenges);
    var selected = pool.pick(5);
    var ids = selected.map(function (c) { return c.id; });
    var unique = ids.filter(function (id, i) { return ids.indexOf(id) === i; });
    assert.strictEqual((unique).length, 5);
  });

  test('pool.recordResult updates challenge stats', function () {
    var challenges = makeChallenges(5);
    var pool = gifCaptcha.createPoolManager();
    pool.add(challenges);

    // pick first to register as served
    pool.pick(1);
    pool.recordResult(challenges[0].id, true, 3000);
    pool.recordResult(challenges[0].id, false, 2000);

    var stats = pool.getStats(challenges[0].id);
    assert.ok(stats);
    assert.ok((stats.passes) >= (1));
  });

  test('pool-selected challenges work with pickChallenges', function () {
    var challenges = makeChallenges(20);
    var picked = gifCaptcha.pickChallenges(challenges, 5);
    assert.strictEqual((picked).length, 5);
    picked.forEach(function (c) {
      assert.match(c.gifUrl, /^https:\/\//);
      assert.strictEqual(typeof c.humanAnswer, 'string');
      assert.ok((c.humanAnswer.length) > (0));
    });
  });

  test('pool summary reflects added challenges', function () {
    var challenges = makeChallenges(8);
    var pool = gifCaptcha.createPoolManager();
    pool.add(challenges);
    var summary = pool.getSummary();
    assert.ok(summary);
    assert.strictEqual(summary.activeCount, 8);
    assert.strictEqual(summary.retiredCount, 0);
  });
});

// ── Challenge → Session Manager ────────────────────────────────────

describe('pipeline: challenge → session manager', function () {

  test('session manager starts and tracks challenge progression', function () {
    var session = gifCaptcha.createSessionManager({
      challengesPerSession: 3,
      passThreshold: 0.67,
    });

    var challenges = makeChallenges(10);
    var sess = session.startSession(challenges);
    assert.notStrictEqual((sess)["sessionId"], undefined);
    assert.strictEqual(sess.totalChallenges, 3);
    assert.strictEqual(sess.challengeIndex, 0);
  });

  test('session completes as passed with all correct responses', function () {
    var session = gifCaptcha.createSessionManager({
      challengesPerSession: 3,
      passThreshold: 0.67,
    });

    var challenges = makeChallenges(10);
    var sess = session.startSession(challenges);

    for (var i = 0; i < 3; i++) {
      var result = session.submitResponse(sess.sessionId, true, 3000 + i * 500);
      if (i < 2) {
        assert.strictEqual(result.done, false);
      } else {
        assert.strictEqual(result.done, true);
        assert.strictEqual(result.passed, true);
      }
    }
  });

  test('session completes as failed with all wrong responses', function () {
    var session = gifCaptcha.createSessionManager({
      challengesPerSession: 3,
      passThreshold: 0.67,
    });

    var challenges = makeChallenges(10);
    var sess = session.startSession(challenges);

    var lastResult;
    for (var i = 0; i < 3; i++) {
      lastResult = session.submitResponse(sess.sessionId, false, 5000);
    }

    assert.strictEqual(lastResult.done, true);
    assert.strictEqual(lastResult.passed, false);
  });

  test('session difficulty escalates on correct responses', function () {
    var session = gifCaptcha.createSessionManager({
      challengesPerSession: 3,
      passThreshold: 0.67,
      escalateDifficulty: true,
      difficultyStep: 15,
      baseDifficulty: 30,
    });

    var challenges = makeChallenges(10);
    var sess = session.startSession(challenges);

    var r1 = session.submitResponse(sess.sessionId, true, 3000);
    assert.ok((r1.nextDifficulty) > (30));
  });

  test('session tracks correct and total answered', function () {
    var session = gifCaptcha.createSessionManager({
      challengesPerSession: 3,
      passThreshold: 0.67,
    });

    var challenges = makeChallenges(10);
    var sess = session.startSession(challenges);

    session.submitResponse(sess.sessionId, true, 3000);
    session.submitResponse(sess.sessionId, false, 4000);
    var r = session.submitResponse(sess.sessionId, true, 5000);

    assert.strictEqual(r.correctCount, 2);
    assert.strictEqual(r.totalAnswered, 3);
  });
});

// ── Challenge Pool → Security Scorer ───────────────────────────────

describe('pipeline: challenge pool → security scorer', function () {

  test('security scorer analyzes a full challenge pool', function () {
    var challenges = makeChallenges(10);
    var scorer = gifCaptcha.createSecurityScorer(challenges);
    var report = scorer.getReport();

    assert.notStrictEqual((report)["score"], undefined);
    assert.notStrictEqual((report)["grade"], undefined);
    assert.ok((report.score) >= (0));
    assert.ok((report.score) <= (100));
  });

  test('security scorer getDimensions returns array of dimensions', function () {
    var challenges = makeChallenges(10);
    var scorer = gifCaptcha.createSecurityScorer(challenges);
    var dims = scorer.getDimensions();

    assert.strictEqual(Array.isArray(dims), true);
    assert.ok((dims.length) > (0));

    dims.forEach(function (dim) {
      assert.notStrictEqual((dim)["name"], undefined);
      assert.notStrictEqual((dim)["score"], undefined);
      assert.ok((dim.score) >= (0));
      assert.ok((dim.score) <= (100));
    });
  });

  test('getDimension returns individual dimension by name', function () {
    var challenges = makeChallenges(10);
    var scorer = gifCaptcha.createSecurityScorer(challenges);

    var dim = scorer.getDimension('AI Resistance');
    assert.notStrictEqual((dim)["score"], undefined);
    assert.notStrictEqual((dim)["name"], undefined);
    assert.strictEqual(dim.name, 'AI Resistance');
  });

  test('isSecure returns boolean for challenge pool', function () {
    var challenges = makeChallenges(10);
    var scorer = gifCaptcha.createSecurityScorer(challenges);
    assert.strictEqual(typeof scorer.isSecure(), 'boolean');
  });

  test('vulnerabilities are actionable', function () {
    var challenges = makeChallenges(10);
    var scorer = gifCaptcha.createSecurityScorer(challenges);
    var vulns = scorer.getVulnerabilities();

    assert.strictEqual(Array.isArray(vulns), true);
    vulns.forEach(function (v) {
      assert.notStrictEqual((v)["dimension"], undefined);
      assert.notStrictEqual((v)["severity"], undefined);
      assert.notStrictEqual((v)["description"], undefined);
      assert.ok((['critical', 'high', 'medium', 'low']).includes(v.severity));
    });
  });

  test('recommendations reference vulnerability dimensions', function () {
    var challenges = makeChallenges(10);
    var scorer = gifCaptcha.createSecurityScorer(challenges);
    var recs = scorer.getRecommendations();
    var vulns = scorer.getVulnerabilities();

    assert.strictEqual(Array.isArray(recs), true);
    var vulnDims = vulns.map(function (v) { return v.dimension; });
    var recDims = recs.map(function (r) { return r.dimension; });
    var overlap = recDims.filter(function (d) { return vulnDims.indexOf(d) !== -1; });
    if (vulns.length > 0) {
      assert.ok((overlap.length) > (0));
    }
  });
});

// ── Challenges → Set Analyzer → Calibrator ─────────────────────────

describe('pipeline: challenges → set analyzer → calibrator', function () {

  test('set analyzer generateReport has expected structure', function () {
    var challenges = makeChallenges(10);
    var analyzer = gifCaptcha.createSetAnalyzer(challenges);
    var report = analyzer.generateReport();

    assert.notStrictEqual((report)["challengeCount"], undefined);
    assert.strictEqual(report.challengeCount, 10);
    assert.notStrictEqual((report)["diversity"], undefined);
    assert.notStrictEqual((report.diversity)["score"], undefined);
  });

  test('set analyzer detects similar pairs in challenge pool', function () {
    var challenges = makeChallenges(10);
    var analyzer = gifCaptcha.createSetAnalyzer(challenges);
    var pairs = analyzer.findSimilarPairs(0.3);

    assert.strictEqual(Array.isArray(pairs), true);
  });

  test('set analyzer quality issues are structured objects', function () {
    var challenges = makeChallenges(5);
    var analyzer = gifCaptcha.createSetAnalyzer(challenges);
    var issues = analyzer.qualityIssues();

    assert.strictEqual(Array.isArray(issues), true);
    issues.forEach(function (issue) {
      assert.strictEqual(typeof issue, 'object');
      assert.notStrictEqual((issue)["type"], undefined);
      assert.notStrictEqual((issue)["message"], undefined);
    });
  });

  test('set analyzer diversity score is available', function () {
    var challenges = makeChallenges(10);
    var analyzer = gifCaptcha.createSetAnalyzer(challenges);
    var scoreResult = analyzer.diversityScore();

    // diversityScore returns an object with score property
    assert.ok(scoreResult);
    assert.strictEqual(typeof scoreResult, 'object');
    assert.notStrictEqual((scoreResult)["score"], undefined);
    assert.ok((scoreResult.score) >= (0));
    assert.ok((scoreResult.score) <= (100));
  });

  test('calibrator generates report from challenge pool', function () {
    var challenges = makeChallenges(10);
    var calibrator = gifCaptcha.createDifficultyCalibrator(challenges);
    var report = calibrator.generateReport();

    assert.ok(report);
    assert.strictEqual(typeof report, 'object');
  });

  test('calibrator tracks responses with proper argument format', function () {
    var challenges = makeChallenges(5);
    var calibrator = gifCaptcha.createDifficultyCalibrator(challenges);

    // recordResponse expects (string id, {timeMs, correct})
    calibrator.recordResponse('1', { timeMs: 3000, correct: true });
    calibrator.recordResponse('1', { timeMs: 8000, correct: false });
    calibrator.recordResponse('2', { timeMs: 2000, correct: true });

    assert.strictEqual(calibrator.totalResponses(), 3);
    assert.strictEqual(calibrator.responseCount('1'), 2);
    assert.strictEqual(calibrator.responseCount('2'), 1);
  });

  test('calibrator difficulty distribution reflects recorded data', function () {
    var challenges = makeChallenges(5);
    var calibrator = gifCaptcha.createDifficultyCalibrator(challenges);

    for (var i = 0; i < 10; i++) {
      calibrator.recordResponse('1', { timeMs: 2000 + i * 100, correct: true });
    }

    var dist = calibrator.getDifficultyDistribution();
    assert.ok(dist);
    assert.strictEqual(typeof dist, 'object');
  });

  test('calibrator findOutliers returns array', function () {
    var challenges = makeChallenges(5);
    var calibrator = gifCaptcha.createDifficultyCalibrator(challenges);

    // Record varied responses
    for (var i = 0; i < 20; i++) {
      calibrator.recordResponse('1', { timeMs: 3000, correct: true });
    }
    calibrator.recordResponse('2', { timeMs: 100, correct: true });

    var outliers = calibrator.findOutliers();
    assert.strictEqual(Array.isArray(outliers), true);
  });
});

// ── Response Analyzer + Bot Detector Composition ───────────────────

describe('pipeline: response analyzer + bot detector', function () {

  test('both flag obvious bot behavior', function () {
    var analyzer = gifCaptcha.createResponseAnalyzer();
    var detector = gifCaptcha.createBotDetector();

    var submissions = [
      { response: 'cat', timeMs: 100 },
      { response: 'cat', timeMs: 100 },
      { response: 'cat', timeMs: 100 },
    ];

    var analyzerResult = analyzer.scoreSubmissions(submissions);
    var detectorResult = detector.analyze({
      timeOnPageMs: 200,
      mouseMovements: [],
      keystrokes: [],
    });

    assert.notStrictEqual(analyzerResult.verdict, 'likely_human');
    assert.notStrictEqual(detectorResult.verdict, 'human');
  });

  test('both accept likely-human behavior', function () {
    var analyzer = gifCaptcha.createResponseAnalyzer();
    var detector = gifCaptcha.createBotDetector();

    var token = detector.getJsToken();

    var submissions = [
      { response: 'A man suddenly trips over his shoelace and falls down the stairs', timeMs: 4500 },
      { response: 'The cat unexpectedly jumps onto the keyboard and starts typing', timeMs: 6200 },
      { response: 'A dog hilariously chases its own tail and then falls over dizzy', timeMs: 5800 },
    ];

    var analyzerResult = analyzer.scoreSubmissions(submissions);

    var detectorResult = detector.analyze({
      honeypotValues: { hp_email: '', hp_url: '', hp_phone: '' },
      mouseMovements: [
        { x: 10, y: 20, t: 100 },
        { x: 50, y: 30, t: 180 },
        { x: 45, y: 80, t: 250 },
        { x: 100, y: 60, t: 340 },
        { x: 80, y: 120, t: 420 },
        { x: 130, y: 90, t: 500 },
      ],
      keystrokes: [
        { key: 'A', downAt: 1000, upAt: 1080 },
        { key: ' ', downAt: 1200, upAt: 1270 },
        { key: 'm', downAt: 1450, upAt: 1530 },
        { key: 'a', downAt: 1600, upAt: 1690 },
        { key: 'n', downAt: 1800, upAt: 1880 },
      ],
      timeOnPageMs: 20000,
      firstInteractionMs: 3000,
      jsToken: token,
      scrollEvents: [
        { y: 0, t: 0 },
        { y: 100, t: 800 },
        { y: 250, t: 1500 },
      ],
    });

    assert.strictEqual(analyzerResult.verdict, 'likely_human');
    assert.strictEqual(detectorResult.verdict, 'human');
  });

  test('fast submissions flagged by both analyzers', function () {
    var analyzer = gifCaptcha.createResponseAnalyzer({ minResponseTimeMs: 500 });
    var detector = gifCaptcha.createBotDetector({ minTimeOnPageMs: 2000 });

    var timingResult = analyzer.analyzeTiming([100, 150, 80, 120]);
    var detectorTiming = detector.analyzeTiming(300);

    assert.ok((timingResult.tooFastCount) > (0));
    assert.ok((detectorTiming.flags).includes('too_fast'));
  });

  test('duplicate response detection returns proper structure', function () {
    var analyzer = gifCaptcha.createResponseAnalyzer();

    var dupes = analyzer.detectDuplicateResponses([
      'A cat falls down', 'A cat falls down', 'Something else entirely'
    ]);

    assert.notStrictEqual((dupes)["duplicateCount"], undefined);
    assert.ok((dupes.duplicateCount) > (0));
    assert.notStrictEqual((dupes)["duplicatePairs"], undefined);
    assert.ok((dupes.duplicatePairs.length) > (0));
    assert.notStrictEqual((dupes)["uniqueRatio"], undefined);
    assert.ok((dupes.uniqueRatio) < (1));
  });

  test('no duplicates detected for diverse responses', function () {
    var analyzer = gifCaptcha.createResponseAnalyzer();

    var dupes = analyzer.detectDuplicateResponses([
      'A man falls off a ladder hitting every rung',
      'A cat chases a laser pointer around the room',
      'A dog catches a frisbee mid-air'
    ]);

    assert.strictEqual(dupes.duplicateCount, 0);
    assert.strictEqual(dupes.uniqueRatio, 1);
  });
});

// ── Attempt Tracker + validateAnswer ───────────────────────────────

describe('pipeline: attempt tracker + validateAnswer', function () {

  test('tracker wraps validateAnswer correctly', function () {
    var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 3 });

    var result = tracker.validateAnswer(
      'a person falls down',
      'A person falls down',
      'challenge-1'
    );

    assert.strictEqual(result.passed, true);
    assert.strictEqual(result.locked, false);
    assert.strictEqual(result.attemptsRemaining, 2);
  });

  test('tracker locks after max failed attempts', function () {
    var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2, lockoutMs: 5000 });

    tracker.validateAnswer('wrong', 'right answer here', 'q1');
    var second = tracker.validateAnswer('still wrong', 'right answer here', 'q1');

    assert.strictEqual(second.locked, true);
    assert.ok((second.lockoutRemainingMs) > (0));

    var blocked = tracker.validateAnswer('right answer here', 'right answer here', 'q1');
    assert.strictEqual(blocked.locked, true);
    assert.strictEqual(blocked.passed, false);
  });

  test('different challenge IDs tracked independently', function () {
    var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 2 });

    tracker.validateAnswer('wrong', 'answer1', 'q1');
    tracker.validateAnswer('wrong', 'answer1', 'q1');

    var q2result = tracker.validateAnswer('answer two here', 'answer two here', 'q2');
    assert.strictEqual(q2result.passed, true);
    assert.strictEqual(q2result.locked, false);
  });

  test('tracker stats reflect validation history', function () {
    var tracker = gifCaptcha.createAttemptTracker({ maxAttempts: 5 });

    tracker.validateAnswer('wrong1', 'correct answer', 'q1');
    tracker.validateAnswer('wrong2', 'correct answer', 'q1');

    var stats = tracker.getStats('q1');
    assert.strictEqual(stats.attempts, 2);
    assert.strictEqual(stats.isLocked, false);
  });

  test('tracker config matches initialization', function () {
    var tracker = gifCaptcha.createAttemptTracker({
      maxAttempts: 3,
      lockoutMs: 10000,
      exponentialBackoff: false,
    });

    var config = tracker.getConfig();
    assert.strictEqual(config.maxAttempts, 3);
    assert.strictEqual(config.lockoutMs, 10000);
    assert.strictEqual(config.exponentialBackoff, false);
  });
});

// ── Full End-to-End Pipeline ───────────────────────────────────────

describe('full pipeline: create → pool → session → analyze → score', function () {

  test('end-to-end human flow produces consistent results', function () {
    // 1. Create challenge pool
    var challenges = makeChallenges(10);

    // 2. Pool manages challenges
    var pool = gifCaptcha.createPoolManager();
    pool.add(challenges);
    var selected = pool.pick(3);
    assert.strictEqual((selected).length, 3);

    // 3. Start session
    var session = gifCaptcha.createSessionManager({
      challengesPerSession: 3,
      passThreshold: 0.67,
    });
    var sess = session.startSession(challenges);

    // 4. Submit correct responses
    var responses = [];
    var result;
    for (var i = 0; i < 3; i++) {
      result = session.submitResponse(sess.sessionId, true, 3000 + i * 1000);
      responses.push({ response: selected[i].humanAnswer, timeMs: 3000 + i * 1000 });
    }

    // 5. Verify session passed
    assert.strictEqual(result.done, true);
    assert.strictEqual(result.passed, true);

    // 6. Analyze response quality
    var analyzer = gifCaptcha.createResponseAnalyzer();
    var analysis = analyzer.scoreSubmissions(responses);
    assert.strictEqual(analysis.verdict, 'likely_human');

    // 7. Security score the pool
    var scorer = gifCaptcha.createSecurityScorer(challenges);
    var report = scorer.getReport();
    assert.ok((report.score) >= (0));
    assert.ok((report.score) <= (100));
  });

  test('end-to-end bot flow is detected across all modules', function () {
    var analyzer = gifCaptcha.createResponseAnalyzer();
    var botResponses = [
      { response: 'image shows activity', timeMs: 50 },
      { response: 'image shows activity', timeMs: 50 },
      { response: 'image shows activity', timeMs: 50 },
    ];

    var analysis = analyzer.scoreSubmissions(botResponses);
    assert.strictEqual(analysis.verdict, 'likely_bot');
    assert.ok((analysis.flags).includes('duplicate_responses'));
    assert.ok((analysis.flags).includes('fast_responses'));
  });

  test('security scorer + set analyzer provide complementary insights', function () {
    var challenges = makeChallenges(10);

    var scorer = gifCaptcha.createSecurityScorer(challenges);
    var analyzer = gifCaptcha.createSetAnalyzer(challenges);

    var secReport = scorer.getReport();
    var setReport = analyzer.generateReport();

    // Both analyze the same 10 challenges
    assert.strictEqual(setReport.challengeCount, 10);
    assert.ok((secReport.score) >= (0));

    // Set analyzer diversity and security scorer scores are complementary
    assert.notStrictEqual((setReport)["diversity"], undefined);
    assert.notStrictEqual((setReport.diversity)["score"], undefined);
  });
});
