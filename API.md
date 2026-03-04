# API Reference

Complete API documentation for gif-captcha. All functions are exported from the main module.

```js
const gifCaptcha = require('gif-captcha');
// or import individual functions
const { createChallenge, createAttemptTracker, createSessionManager } = require('gif-captcha');
```

## Table of Contents

- [Utility Functions](#utility-functions)
  - [sanitize](#sanitize)
  - [createSanitizer](#createsanitizer)
  - [isSafeUrl](#issafeurl)
  - [textSimilarity](#textsimilarity)
  - [validateAnswer](#validateanswer)
  - [secureRandomInt](#securerandomint)
- [Challenge Management](#challenge-management)
  - [createChallenge](#createchallenge)
  - [pickChallenges](#pickchallenges)
  - [createAttemptTracker](#createattempttracker)
  - [createPoolManager](#createpoolmanager)
- [Analysis & Calibration](#analysis--calibration)
  - [createSetAnalyzer](#createsetanalyzer)
  - [createDifficultyCalibrator](#createdifficultycalibrator)
  - [createSecurityScorer](#createsecurityscorer)
  - [createResponseAnalyzer](#createresponseanalyzer)
- [Session & Security](#session--security)
  - [createSessionManager](#createsessionmanager)
  - [createTokenVerifier](#createtokenverifier)
- [Bot Detection & Reputation](#bot-detection--reputation)
  - [createBotDetector](#createbotdetector)
  - [createReputationTracker](#createreputationtracker)
  - [createChallengeRouter](#createchallengerouter)

---

## Utility Functions

### `sanitize(str)`

Strip HTML tags and trim whitespace from a string.

```js
sanitize('<b>hello</b>  ');  // => 'hello'
```

### `createSanitizer()`

Create a reusable sanitizer with extended XSS protection.

**Returns:** `{ sanitize(str), escapeHtml(str), stripTags(str) }`

```js
const s = createSanitizer();
s.sanitize('<script>alert(1)</script>');  // => 'alert(1)'
s.escapeHtml('<div>');                    // => '&lt;div&gt;'
```

### `isSafeUrl(url)`

Check if a URL is safe (HTTP/HTTPS, no javascript: or data: URIs).

```js
isSafeUrl('https://example.com');     // => true
isSafeUrl('javascript:alert(1)');     // => false
```

### `textSimilarity(a, b)`

Compute normalized Levenshtein similarity between two strings (0-1).

```js
textSimilarity('hello', 'hallo');  // => 0.8
```

### `validateAnswer(challenge, userAnswer, threshold)`

Check if a user's answer matches the challenge's expected answer.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `challenge` | Object | — | Challenge object with `humanAnswer` and `keywords` |
| `userAnswer` | string | — | User's submitted answer |
| `threshold` | number | `0.6` | Minimum similarity score to pass |

**Returns:** `{ passed: boolean, score: number, hasKeywords: boolean }`

### `secureRandomInt(min, max)`

Generate a cryptographically secure random integer in `[min, max]`.

---

## Challenge Management

### `createChallenge(opts)`

Create a CAPTCHA challenge object.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `opts.id` | string | Yes | Unique challenge identifier |
| `opts.title` | string | No | Display title |
| `opts.gifUrl` | string | Yes | URL to the GIF image |
| `opts.humanAnswer` | string | Yes | Expected human answer |
| `opts.aiAnswer` | string | No | AI-generated answer for comparison |
| `opts.keywords` | string[] | No | Required keywords in answer |
| `opts.difficulty` | number | No | Difficulty level (1-5) |

**Returns:** Frozen challenge object.

### `pickChallenges(challenges, count)`

Randomly select `count` challenges from an array without replacement.

### `createAttemptTracker(options)`

Track and rate-limit CAPTCHA solve attempts per challenge.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxAttempts` | number | `5` | Max attempts before lockout |
| `lockoutMs` | number | `30000` | Base lockout duration (ms) |
| `exponentialBackoff` | boolean | `true` | Double lockout on each violation |
| `maxLockoutMs` | number | `300000` | Maximum lockout duration (ms) |

**Methods:**

| Method | Description |
|--------|-------------|
| `isLocked(challengeId)` | Check if challenge is locked out |
| `recordAttempt(challengeId)` | Record an attempt, return `{ allowed, attemptsRemaining, lockoutRemainingMs }` |
| `validateAnswer(challengeId, challenge, answer, threshold)` | Record attempt + validate in one call |
| `resetChallenge(challengeId)` | Reset attempts for one challenge |
| `resetAll()` | Reset all tracking state |
| `getStats()` | Get aggregate attempt statistics |
| `getConfig()` | Get current configuration |

```js
const tracker = createAttemptTracker({ maxAttempts: 3 });
const result = tracker.recordAttempt('challenge-1');
// { allowed: true, attemptsRemaining: 2, lockoutRemainingMs: 0, attemptNumber: 1 }
```

### `createPoolManager(options)`

Manage a pool of active challenges with automatic retirement.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxServes` | number | `100` | Max times a challenge is served before retirement |
| `minPassRate` | number | `0.3` | Retire if pass rate drops below this |
| `maxPassRate` | number | `0.95` | Retire if pass rate exceeds this (too easy) |
| `minPoolSize` | number | `3` | Minimum active pool size |

**Methods:**

| Method | Description |
|--------|-------------|
| `add(challenges)` | Add challenge(s) to the pool |
| `pick(count)` | Pick random active challenges |
| `recordResult(id, passed)` | Record a solve/fail result |
| `enforceRetirement()` | Check and retire over-served or poor-performing challenges |
| `reinstate(id)` | Re-activate a retired challenge |
| `getStats()` | Pool statistics |
| `getSummary()` | Per-challenge summary |
| `exportState()` / `importState(state)` | Persistence |

---

## Analysis & Calibration

### `createSetAnalyzer(challenges)`

Analyze a set of challenges for quality, diversity, and security issues.

**Methods:**

| Method | Description |
|--------|-------------|
| `answerLengthStats()` | Min/max/mean/median answer lengths |
| `keywordCoverage()` | Keyword usage frequency and coverage |
| `findSimilarPairs(threshold)` | Find pairs with answers above similarity threshold |
| `detectDuplicates()` | Find exact and near-duplicate challenges |
| `diversityScore()` | Overall diversity metric (0-1) |
| `answerComplexity()` | Per-challenge complexity analysis |
| `qualityIssues()` | Detect potential quality problems |
| `generateReport()` | Full analysis report |
| `size` | Number of challenges |

### `createDifficultyCalibrator(challenges)`

Calibrate challenge difficulty based on recorded human responses.

**Methods:**

| Method | Description |
|--------|-------------|
| `recordResponse(challengeId, { timeMs, correct, skipped? })` | Record a response |
| `recordBatch(responses)` | Record multiple responses |
| `getStats(challengeId)` | Response statistics for a challenge |
| `calibrateDifficulty(challengeId)` | Compute recommended difficulty (1-5) |
| `calibrateAll()` | Calibrate all challenges |
| `findOutliers(threshold?)` | Find too-easy or too-hard challenges |
| `getDifficultyDistribution()` | Distribution across difficulty levels |
| `generateReport()` | Full calibration report |
| `reset()` | Clear all recorded data |
| `responseCount(id)` / `totalResponses()` | Response counts |

```js
const calibrator = createDifficultyCalibrator(challenges);
calibrator.recordResponse('c1', { timeMs: 5000, correct: true });
calibrator.recordResponse('c1', { timeMs: 8000, correct: false });
const diff = calibrator.calibrateDifficulty('c1');
// { challengeId: 'c1', difficulty: 3, confidence: 0.65, ... }
```

### `createSecurityScorer(challenges)`

Score a CAPTCHA set across multiple security dimensions.

**Methods:**

| Method | Description |
|--------|-------------|
| `getReport()` | Full security report with overall score |
| `getDimensions()` | All dimension scores |
| `getDimension(name)` | Score for a specific dimension |
| `getVulnerabilities()` | List of detected vulnerabilities |
| `getRecommendations()` | Actionable security recommendations |
| `isSecure(threshold?)` | Whether the set meets minimum security bar |
| `reset()` | Recompute scores |

### `createResponseAnalyzer(opts)`

Analyze response patterns for anomalies and bot-like behavior.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `minResponseTimeMs` | number | `800` | Responses faster than this are suspicious |
| `maxTimingCvThreshold` | number | `0.15` | CV below this suggests automated responses |
| `duplicateThreshold` | number | `0.85` | Similarity above this flags as duplicate |
| `minWordDiversity` | number | `0.4` | Word diversity below this is suspicious |

**Methods:**

| Method | Description |
|--------|-------------|
| `analyzeTiming(responseTimes)` | Analyze timing patterns |
| `analyzeResponse(response)` | Analyze a single text response |
| `detectDuplicateResponses(responses)` | Find duplicate/near-duplicate answers |
| `scoreSubmissions(submissions)` | Score a batch for legitimacy |
| `getConfig()` | Current analyzer configuration |

---

## Session & Security

### `createSessionManager(options)`

Manage CAPTCHA sessions with configurable challenge counts and timeouts.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `challengeCount` | number | `3` | Challenges per session |
| `timeoutMs` | number | `300000` | Session timeout (5 min) |
| `passThreshold` | number | `0.6` | Fraction of correct answers to pass |

**Methods:**

| Method | Description |
|--------|-------------|
| `startSession(challenges)` | Create a new session, returns session object |
| `submitResponse(sessionId, challengeId, answer)` | Submit an answer |
| `getSession(sessionId)` | Get session state |
| `invalidateSession(sessionId)` | End a session early |
| `getStats()` | Aggregate session statistics |
| `getConfig()` | Current configuration |

### `createTokenVerifier(options)`

Stateless CAPTCHA verification via HMAC-SHA256 signed tokens.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secret` | string | *required* | HMAC signing key |
| `ttlMs` | number | `300000` | Token time-to-live (5 min) |
| `bindIp` | boolean | `false` | Bind token to client IP |
| `maxNonces` | number | `10000` | LRU nonce cache size for replay protection |

**Methods:**

| Method | Description |
|--------|-------------|
| `issueToken(payload?)` | Issue a signed token with optional metadata |
| `verifyToken(token, options?)` | Verify token signature, expiry, replay, and IP binding |
| `issueFromSession(sessionManager, sessionId)` | Issue token from a completed session |
| `getStats()` | Verification statistics |
| `clearUsedTokens()` | Reset the replay-protection nonce cache |

```js
const verifier = createTokenVerifier({ secret: 'my-secret', ttlMs: 60000 });
const token = verifier.issueToken({ userId: 'abc' });
const result = verifier.verifyToken(token);
// { valid: true, payload: { userId: 'abc' }, ... }
```

---

## Bot Detection & Reputation

### `createBotDetector(options)`

Multi-signal bot detection using honeypots, mouse/keyboard analysis, and timing.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `honeypotWeight` | number | `0.3` | Weight for honeypot signal |
| `mouseWeight` | number | `0.2` | Weight for mouse movement entropy |
| `keystrokeWeight` | number | `0.15` | Weight for keystroke dynamics |
| `timingWeight` | number | `0.2` | Weight for page timing |
| `scrollWeight` | number | `0.05` | Weight for scroll behavior |
| `jsTokenWeight` | number | `0.1` | Weight for JS token verification |
| `threshold` | number | `0.5` | Score above this is flagged as bot |

**Methods:**

| Method | Description |
|--------|-------------|
| `analyze(data)` | Full multi-signal analysis → `{ score, isBot, signals }` |
| `analyzeHoneypots(fields)` | Check honeypot fields |
| `analyzeMouseMovements(events)` | Analyze mouse entropy and patterns |
| `analyzeKeystrokes(events)` | Analyze keystroke timing dynamics |
| `analyzeTiming(data)` | Analyze page load and interaction timing |
| `analyzeScroll(events)` | Analyze scroll patterns |
| `getJsToken()` | Generate a JS verification token |
| `getHoneypotFields()` | Get honeypot field names to embed in forms |
| `getConfig()` | Current detector configuration |

### `createReputationTracker(options)`

Cross-session IP/device reputation tracking with decay and trust scoring.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `initialScore` | number | `0.5` | Starting reputation for unknown identifiers |
| `solveWeight` | number | `0.1` | Score increase per solve |
| `failWeight` | number | `0.15` | Score decrease per fail |
| `timeoutWeight` | number | `0.05` | Score decrease per timeout |
| `decayMs` | number | `86400000` | Time constant for exponential decay (24h) |
| `burstThreshold` | number | `10` | Events in window to trigger burst penalty |
| `burstWindow` | number | `60000` | Burst detection window (1 min) |
| `burstPenalty` | number | `0.2` | Score penalty for burst behavior |
| `maxEntries` | number | `10000` | LRU eviction limit |

**Methods:**

| Method | Description |
|--------|-------------|
| `recordSolve(id)` / `recordFail(id)` / `recordTimeout(id)` | Record events |
| `getReputation(id)` | Get current score and history |
| `getAction(id)` | Get recommended action (`allow`/`block`/`challenge`/`challenge_hard`) |
| `addToAllowlist(id)` / `addToBlocklist(id)` | Manage lists |
| `removeFromAllowlist(id)` / `removeFromBlocklist(id)` | Remove from lists |
| `isAllowlisted(id)` / `isBlocklisted(id)` | Check list membership |
| `setTag(id, key, value)` / `getTag(id, key)` | Attach metadata |
| `getStats()` | Aggregate statistics |
| `forget(id)` | Remove an identifier's history |
| `reset()` | Clear all state |
| `exportData()` / `importData(data)` | Persistence |

### `createChallengeRouter(options)`

Intelligent CAPTCHA difficulty routing based on reputation and history.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `difficulties` | Object | `{ trivial:1, easy:2, medium:3, hard:4, extreme:5 }` | Difficulty levels |
| `defaultDifficulty` | number | `2` | Starting difficulty for unknown clients |
| `maxEscalation` | number | `5` | Maximum difficulty level |
| `escalateAfterFails` | number | `2` | Consecutive fails to trigger escalation |
| `deescalateAfterPasses` | number | `3` | Consecutive passes to trigger de-escalation |
| `reputationWeight` | number | `0.6` | Weight for reputation signal (0-1) |
| `historyWeight` | number | `0.4` | Weight for attempt history signal (0-1) |
| `blockThreshold` | number | `0.15` | Block clients with reputation below this |
| `trustThreshold` | number | `0.85` | Trust clients with reputation above this |
| `rules` | Array | `[]` | Custom routing rules `[{ name, test(id, ctx, client), difficulty, priority }]` |

**Methods:**

| Method | Description |
|--------|-------------|
| `route(identifier, context?)` | Route a client → `{ action, difficulty, difficultyName, reason }` |
| `recordResult(identifier, passed)` | Update client state after solve |
| `getClientInfo(identifier)` | Client routing state |
| `getKnownClients()` | All known client identifiers |
| `forgetClient(identifier)` | Remove a client's state |
| `resetClientLevel(identifier)` | Reset difficulty without clearing stats |
| `getRecentDecisions(count?)` | Recent routing decisions |
| `getClientDecisions(identifier, count?)` | Decisions for a specific client |
| `getStats()` | Aggregate routing statistics |
| `getConfig()` | Current router configuration |
| `routeBatch(requests)` | Route multiple clients at once |
| `exportState()` / `importState(state)` | Persistence |
| `reset()` | Clear all state |

```js
const router = createChallengeRouter({ defaultDifficulty: 2 });

// Integrate with reputation tracker
const rep = reputationTracker.getReputation(clientIP);
const decision = router.route(clientIP, {
  reputationScore: rep.score,
  reputationAction: reputationTracker.getAction(clientIP).action,
});
// decision: { action: 'challenge', difficulty: 3, difficultyName: 'medium', reason: 'escalated' }

// Record result and let the router adapt
router.recordResult(clientIP, true);

// Custom rules for special cases
const router2 = createChallengeRouter({
  rules: [{
    name: 'tor_exit_node',
    test: (id, ctx) => ctx.isTor === true,
    difficulty: 5,
    priority: 10,
  }],
});
```

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `GIF_MAX_RETRIES` | `3` | Default max retries for GIF loading |
| `GIF_RETRY_DELAY_MS` | `1000` | Default delay between retries (ms) |
