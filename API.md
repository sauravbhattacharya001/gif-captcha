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
- [GIF Loading](#gif-loading)
  - [loadGifWithRetry](#loadgifwithretrycontainer-challenge-attempt)
  - [installRoundRectPolyfill](#installroundrectpolyfill)
- [Rate Limiting](#rate-limiting)
  - [createRateLimiter](#createratelimiteroptions)
- [Client Fingerprinting](#client-fingerprinting)
  - [createClientFingerprinter](#createclientfingerprinteroptions)
- [Incident Correlation](#incident-correlation)
  - [createIncidentCorrelator](#createincidentcorrelatoroptions)
- [Adaptive Timeout](#adaptive-timeout)
  - [createAdaptiveTimeout](#createadaptivetimeoutoptions)
- [Audit Trail](#audit-trail)
  - [createAuditTrail](#createaudittrailoptions)
- [Session Recording](#session-recording)
  - [createSessionRecorder](#createsessionrecorderoptions)
- [Load Testing](#load-testing)
  - [createLoadTester](#createloadtesteroptions)
- [A/B Experiment Runner](#ab-experiment-runner)
  - [createABExperimentRunner](#createabexperimentrunneroptions)
- [Fraud Ring Detection](#fraud-ring-detection)
  - [createFraudRingDetector](#createfraudringdetectoroptions)
- [Compliance Reporting](#compliance-reporting)
  - [createComplianceReporter](#createcompliancereporteroptions)
- [Metrics Aggregation](#metrics-aggregation)
  - [createMetricsAggregator](#createmetricsaggregatoroptions)
- [Trust Score Engine](#trust-score-engine)
  - [createTrustScoreEngine](#createtrustscoreengineoptions)
- [Event Emitter](#event-emitter)
  - [createEventEmitter](#createeventemitteroptions)
- [Internationalization (i18n)](#internationalization-i18n)
  - [createI18n](#createi18noptions)
- [Accessibility Auditor](#accessibility-auditor)
  - [createAccessibilityAuditor](#createaccessibilityauditoroptions)
- [Configuration Validator](#configuration-validator)
  - [createConfigValidator](#createconfigvalidatoroptions)
- [Challenge Analytics](#challenge-analytics)
  - [createChallengeAnalytics](#createchallengeanalyticsoptions)
- [Geographic Risk Scorer](#geographic-risk-scorer)
  - [createGeoRiskScorer](#creategeoriskscoreroptions)
- [Proof of Work](#proof-of-work)
  - [createProofOfWork](#createproofofworkoptions)
- [Behavioral Biometrics](#behavioral-biometrics)
  - [createBehavioralBiometrics](#createbehavioralbiometricsoptions)
- [Challenge Decay Manager](#challenge-decay-manager)
  - [createChallengeDecayManager](#createchallengedecaymanageroptions)
- [Solve Pattern Fingerprinter](#solve-pattern-fingerprinter)
  - [createSolvePatternFingerprinter](#createsolvepatternfingerprinteroptions)
- [Constants](#constants)

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

## GIF Loading

### `loadGifWithRetry(container, challenge, attempt)`

Load a GIF image into a DOM container with automatic retry on failure.
Shows a fallback with a link or hint after exhausting retries.

| Parameter | Type | Description |
|-----------|------|-------------|
| `container` | `HTMLElement` | DOM element to render into |
| `challenge` | `Object` | Challenge object |
| `challenge.title` | `string` | Human-readable challenge title |
| `challenge.gifUrl` | `string` | URL of the GIF image |
| `challenge.sourceUrl` | `string?` | Original source URL for fallback link |
| `attempt` | `number?` | Current attempt, 0-indexed (default `0`) |

```js
loadGifWithRetry(document.getElementById('captcha'), {
  title: 'Select the dancing cat',
  gifUrl: 'https://example.com/cat.gif',
  sourceUrl: 'https://example.com/original'
});
```

### `installRoundRectPolyfill()`

Install a `roundRect` polyfill for `CanvasRenderingContext2D`. No-op if already available or not in a browser environment.

```js
installRoundRectPolyfill(); // Safe to call multiple times
```

---

## Rate Limiting

### `createRateLimiter(options)`

Sliding-window rate limiter with burst detection, allowlists/blocklists, and per-client tracking.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `windowMs` | `number` | `60000` | Time window in ms |
| `maxRequests` | `number` | `10` | Max requests per window |
| `burstThreshold` | `number` | `5` | Requests within burst window to trigger burst detection |
| `burstWindowMs` | `number` | `5000` | Burst detection window in ms |
| `maxDelay` | `number` | `30000` | Maximum delay for rate-limited clients (ms) |
| `baseDelay` | `number` | `1000` | Base delay for rate-limited clients (ms) |
| `maxClients` | `number` | `10000` | Maximum tracked clients (LRU eviction) |

**Returns:** `{ check, checkBatch, peek, resetClient, allow, block, unlist, getStats, topClients, exportState, importState, reset, getConfig }`

```js
const limiter = createRateLimiter({ maxRequests: 5, windowMs: 60000 });

const result = limiter.check('client-123');
// { allowed: true, remaining: 4, retryAfterMs: 0 }

limiter.block('abusive-ip');   // Permanently block a client
limiter.allow('trusted-ip');   // Permanently allow a client

const stats = limiter.getStats();
// { totalClients, blockedClients, allowedClients, ... }
```

---

## Client Fingerprinting

### `createClientFingerprinter(options)`

Browser fingerprinting for CAPTCHA sessions. Combines user agent, screen size, timezone, language, and other signals to identify and track clients.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxFingerprints` | `number` | `10000` | Maximum stored fingerprints (LRU eviction) |
| `ttlMs` | `number` | `86400000` | Fingerprint TTL in ms (24 hours) |
| `suspiciousChangeThreshold` | `number` | `5` | Fingerprint changes before flagging as suspicious |
| `changeWindowMs` | `number` | `3600000` | Window for tracking changes (1 hour) |

**Returns:** `{ identify, findSimilar, getFingerprint, getStats, exportState, importState, reset, getConfig }`

```js
const fp = createClientFingerprinter();

const result = fp.identify({
  userAgent: 'Mozilla/5.0...',
  screen: '1920x1080',
  timezone: 'America/New_York',
  language: 'en-US'
});
// { fingerprintId, isNew, suspiciousChanges, ... }

const similar = fp.findSimilar(result.fingerprintId);
// Clients with similar fingerprint signals
```

---

## Incident Correlation

### `createIncidentCorrelator(options)`

Correlates security signals (failed CAPTCHAs, rate limit hits, fingerprint anomalies) into incidents for investigation.

**Returns:** `{ ingest, getIncident, getClientIncident, closeIncident, queryIncidents, getStats, reset, exportState, SIGNAL_TYPES, SEVERITY }`

```js
const correlator = createIncidentCorrelator();

correlator.ingest({
  type: 'captcha_failure',
  clientId: 'client-123',
  severity: 'warning',
  metadata: { attempts: 5 }
});

const incidents = correlator.queryIncidents({ status: 'open' });
const stats = correlator.getStats();
```

---

## Adaptive Timeout

### `createAdaptiveTimeout(options)`

Calculates per-client CAPTCHA timeouts based on observed response latencies. Slower clients get more time; fast bots get tighter windows.

**Returns:** `{ calculate, recordResponse, recordLatency, getClientLatency, getBaseline, getStats, exportState, importState, reset, getConfig }`

```js
const timeout = createAdaptiveTimeout();

// Record actual response times
timeout.recordResponse('client-123', 3500);
timeout.recordResponse('client-123', 4200);

// Get an adapted timeout for this client
const ms = timeout.calculate('client-123');
// Returns a timeout tuned to the client's observed speed
```

---

## Audit Trail

### `createAuditTrail(options)`

Immutable event log for CAPTCHA operations. Records challenges, verifications, administrative actions, and security events in a ring buffer.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxEntries` | `number` | `10000` | Maximum stored events (ring buffer) |
| `includeMetadata` | `boolean` | `true` | Attach extra metadata to events |
| `onEvent` | `Function?` | — | Optional callback for each event |
| `enabledTypes` | `string[]?` | — | If set, only record these event types |

**Returns:** Audit trail instance with event recording and querying.

```js
const audit = createAuditTrail({ maxEntries: 5000 });

audit.record('challenge_issued', {
  clientId: 'client-123',
  challengeType: 'gif-selection'
});

const events = audit.query({ type: 'challenge_issued', since: Date.now() - 3600000 });
```

---

## Session Recording

### `createSessionRecorder(options)`

Records full CAPTCHA session timelines for replay, analysis, and comparison. Captures challenges, inputs, submissions, results, and custom events.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxSessions` | `number` | `1000` | Maximum stored sessions |
| `sessionTimeoutMs` | `number` | `300000` | Session timeout (5 minutes) |
| `captureInputs` | `boolean` | `true` | Whether to capture input events |
| `onSessionEnd` | `Function?` | — | Callback when a session ends |
| `tags` | `string[]?` | `[]` | Default tags for new sessions |

**Returns:** `{ startSession, endSession, recordChallenge, recordInput, recordSubmission, recordResult, recordSkip, recordRefresh, recordError, recordCustom, getSession, addTags, querySessions, createReplay, compareSessions, getAnalytics, mergedTimeline, exportState, importState, getStats, deleteSession, reset, EVENT_TYPES }`

```js
const recorder = createSessionRecorder();

const session = recorder.startSession('client-123');
recorder.recordChallenge(session.id, { type: 'gif-selection', difficulty: 3 });
recorder.recordSubmission(session.id, { answer: 'cat', timeMs: 3200 });
recorder.recordResult(session.id, { passed: true });
recorder.endSession(session.id);

const replay = recorder.createReplay(session.id);
const analytics = recorder.getAnalytics();
```

---

## Load Testing

### `createLoadTester(options)`

Simulates concurrent CAPTCHA traffic for performance testing. Generates a mix of human-like and bot-like request patterns.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `concurrency` | `number` | `10` | Concurrent simulated users |
| `requestsPerUser` | `number` | `50` | Requests per simulated user |
| `rampUpMs` | `number` | `1000` | Ramp-up period in ms |
| `thinkTimeMs` | `number` | `100` | Simulated think time between requests |
| `humanRatio` | `number` | `0.8` | Fraction of users behaving like humans (0–1) |

**Returns:** `{ run, stop, reset, getConfig, getPhase, PHASE }`

```js
const tester = createLoadTester({
  concurrency: 50,
  requestsPerUser: 100,
  humanRatio: 0.7
});

const results = tester.run(handleRequest);
// { totalRequests, successRate, avgResponseMs, p99ResponseMs, ... }
```

---

## A/B Experiment Runner

### `createABExperimentRunner(options)`

Run A/B tests on CAPTCHA configurations. Tracks assignments, conversion events, and performs statistical analysis with optional early stopping.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxExperiments` | `number` | `50` | Maximum concurrent experiments |
| `significanceLevel` | `number` | `0.05` | Default p-value threshold |
| `minSampleSize` | `number` | `30` | Minimum samples before analysis |
| `earlyStoppingEnabled` | `boolean` | `true` | Stop early when results are significant |
| `earlyStoppingConfidence` | `number` | `0.01` | p-value for early stopping |

**Returns:** `{ createExperiment, assignUser, recordEvent, analyzeExperiment, stopExperiment, getExperiment, listExperiments, deleteExperiment, getAssignmentCounts, onResult, exportState, importState, textReport }`

```js
const ab = createABExperimentRunner();

ab.createExperiment('timeout-test', {
  variants: ['short-timeout', 'long-timeout'],
  trafficSplit: [0.5, 0.5]
});

const variant = ab.assignUser('timeout-test', 'user-123');
// 'short-timeout' or 'long-timeout'

ab.recordEvent('timeout-test', 'user-123', { converted: true, timeMs: 4200 });

const analysis = ab.analyzeExperiment('timeout-test');
// { significant, pValue, winner, sampleSizes, ... }

console.log(ab.textReport('timeout-test'));
```

---

## Fraud Ring Detection

### `createFraudRingDetector(options)`

Detects coordinated bot attacks by clustering clients that share fingerprints, timing patterns, IP addresses, or sequential behavior. Uses union-find for efficient cluster detection.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxClients` | `number` | `5000` | Maximum tracked clients |
| `timingWindowMs` | `number` | `5000` | Window for timing correlation |
| `minRingSize` | `number` | `3` | Minimum clients to form a ring |
| `suspicionThreshold` | `number` | `60` | Score threshold to flag a ring |
| `signalDecayMs` | `number` | `3600000` | Signal decay period (1 hour) |
| `maxRings` | `number` | `200` | Maximum tracked rings |

**Returns:** `{ recordEvent, detectRings, checkClient, getRing, listRings, dismissRing, onRingDetected, getStats, findTimingClusters, findSharedFingerprints, findIPClusters, findSequentialPatterns, computeRingScore, exportState, importState, generateReport, reset }`

```js
const detector = createFraudRingDetector({ minRingSize: 3 });

detector.recordEvent('client-1', { ip: '1.2.3.4', fingerprint: 'fp-A', timestamp: Date.now() });
detector.recordEvent('client-2', { ip: '1.2.3.4', fingerprint: 'fp-A', timestamp: Date.now() + 50 });
detector.recordEvent('client-3', { ip: '1.2.3.5', fingerprint: 'fp-A', timestamp: Date.now() + 100 });

const rings = detector.detectRings();
// [{ id, members: ['client-1', 'client-2', 'client-3'], score: 85, signals: [...] }]

detector.onRingDetected(ring => console.log('Ring detected!', ring));
```

---

## Compliance Reporting

### `createComplianceReporter(options)`

Generates compliance reports for CAPTCHA configurations against accessibility, security, and privacy standards.

**Returns:** `{ generateReport, getRecommendedConfig, compareReports, formatReportText, formatReportHtml, SEVERITY, CATEGORY }`

```js
const reporter = createComplianceReporter();

const report = reporter.generateReport({
  challengeTypes: ['gif-selection'],
  timeoutMs: 30000,
  maxAttempts: 5,
  hasAudioAlternative: true
});
// { score, grade, findings: [{ category, severity, message, recommendation }] }

const text = reporter.formatReportText(report);
const html = reporter.formatReportHtml(report);
const recommended = reporter.getRecommendedConfig();
```

---

## Metrics Aggregation

### `createMetricsAggregator(options)`

Aggregates metrics from multiple CAPTCHA subsystems (rate limiter, bot detector, etc.) into unified snapshots with trend analysis and alerting.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `historySize` | `number` | `60` | Number of snapshots to retain |
| `thresholds.passRate` | `number` | `0.3` | Alert if pass rate drops below this |
| `thresholds.avgResponseMs` | `number` | `30000` | Alert if avg response exceeds this |
| `thresholds.dangerousRate` | `number` | `0.25` | Alert on high dangerous activity rate |
| `thresholds.botDetectionRate` | `number` | `0.4` | Alert on high bot detection rate |

**Returns:** `{ register, unregister, listSubsystems, snapshot, lastSnapshot, getTrends, getSummary, clearHistory, reset, startAutoCapture, stopAutoCapture, isAutoCapturing, onAlert, exportHistory }`

```js
const aggregator = createMetricsAggregator();

// Register subsystems to collect from
aggregator.register('rateLimiter', () => limiter.getStats());
aggregator.register('botDetector', () => botDetector.getStats());

// Take a snapshot
const snap = aggregator.snapshot();
// { timestamp, subsystems: { rateLimiter: {...}, botDetector: {...} }, alerts: [...] }

// Auto-capture every 10 seconds
aggregator.startAutoCapture(10000);

// Get trends over time
const trends = aggregator.getTrends();

// Alert callback
aggregator.onAlert(alert => console.warn('ALERT:', alert));
```

---

## Trust Score Engine

### `createTrustScoreEngine(options)`

Composite trust scoring that combines signals from multiple providers (reputation, fingerprint, bot detection, rate limiting, response quality, behavior entropy) into a single 0–100 trust score per client.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `weights.reputation` | `number` | `1.0` | Weight for reputation signal |
| `weights.fingerprint` | `number` | `1.0` | Weight for fingerprint signal |
| `weights.botDetection` | `number` | `1.0` | Weight for bot detection signal |
| `weights.rateLimit` | `number` | `1.0` | Weight for rate limit signal |
| `weights.responseQuality` | `number` | `1.0` | Weight for response quality signal |
| `weights.behaviorEntropy` | `number` | `1.0` | Weight for behavior entropy signal |

**Returns:** `{ registerProvider, unregisterProvider, evaluate, batchEvaluate, getScore, getScoreTrend, invalidate, clearClient, setThresholds, getThresholds, setWeights, getWeights, getStats, getLowScoreClients, compareClients, exportState, importState, reset }`

```js
const trust = createTrustScoreEngine();

// Register signal providers
trust.registerProvider('reputation', clientId => reputation.getScore(clientId));
trust.registerProvider('botDetection', clientId => botDetector.check(clientId));

// Evaluate a client
const score = trust.evaluate('client-123');
// { score: 72, grade: 'B', providers: { reputation: 85, botDetection: 60 }, decision: 'allow' }

// Set thresholds for automatic decisions
trust.setThresholds({ block: 20, challenge: 50, allow: 70 });

// Track trends
const trend = trust.getScoreTrend('client-123');
// { direction: 'declining', scores: [...], change: -15 }

// Find suspicious clients
const lowScore = trust.getLowScoreClients(30);
```

---

## Event Emitter

### `createEventEmitter(options)`

Lightweight pub/sub event emitter for CAPTCHA lifecycle hooks. Supports `on`, `once`, `off`, wildcards, and piping between emitters.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxListeners` | `number` | `50` | Max listeners per event (0 = unlimited) |
| `onError` | `Function?` | — | Error handler for listener exceptions |

```js
const emitter = createEventEmitter();

emitter.on('challenge:issued', data => console.log('Issued:', data));
emitter.once('session:end', data => console.log('Session ended'));
emitter.on('*', (event, data) => console.log(`[${event}]`, data));

emitter.emit('challenge:issued', { type: 'gif-selection', clientId: 'c-1' });
```

---

## Internationalization (i18n)

### `createI18n(options)`

Multi-language support for CAPTCHA UI strings — instructions, errors, accessibility text. Ships with 12 built-in locales. Supports interpolation (`{name}` placeholders) and runtime locale registration.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `locale` | `string` | `"en"` | Active locale code |
| `fallbackLocale` | `string` | `"en"` | Fallback when key is missing in active locale |
| `locales` | `Object?` | — | Extra locale maps to merge (key → translations object) |

**Built-in locales:** en, es, fr, de, pt, ja, zh, ko, ar, hi, ru, it

**Returns:** `{ t, addLocale, setLocale, getLocale, getAvailableLocales, hasKey, exportCatalog }`

```js
const i18n = createI18n({ locale: "es" });
i18n.t("instructions");                    // "Selecciona la imagen correcta..."
i18n.t("timer.remaining", { seconds: 30 }); // "Tiempo restante: 30 segundos"
i18n.setLocale("fr");
i18n.addLocale("th", { instructions: "เลือกภาพ..." });
```

---

## Accessibility Auditor

### `createAccessibilityAuditor(options)`

Audits CAPTCHA configuration and DOM structure against WCAG 2.1 accessibility guidelines. Checks for alt text, keyboard navigation, color contrast, focus management, audio alternatives, and screen reader compatibility.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `level` | `string` | `"AA"` | WCAG conformance level (`"A"`, `"AA"`, `"AAA"`) |
| `includeRecommendations` | `boolean` | `true` | Include best-practice recommendations |

**Returns:** `{ audit, summarize, listRules }`

```js
const auditor = createAccessibilityAuditor({ level: "AA" });

const results = auditor.audit(captchaConfig);
// [{ pass: false, severity: "error", message: "...", recommendation: "..." }, ...]

const summary = auditor.summarize(results);
// { total: 12, passed: 9, failed: 3, errors: 1, warnings: 2 }

const rules = auditor.listRules();
```

---

## Configuration Validator

### `createConfigValidator(options)`

Validates CAPTCHA deployment configuration objects against known constraints. Catches misconfigurations — type errors, insecure defaults, range violations, deprecated fields — before they silently degrade security or usability in production.

**Returns:** `{ validate, rules }`

```js
const validator = createConfigValidator();

const result = validator.validate({
  secret: "short",           // too short for HMAC
  tokenTtlMs: -100,          // negative TTL
  maxAttempts: 0,            // disables attempt limits
});

result.valid;      // false
result.errors;     // [{ id: "token.secret.weak", message: "...", severity: "error" }]
result.warnings;   // [{ id: "...", message: "...", severity: "warning" }]
result.summary;    // "2 errors, 1 warning, 0 info"

const rules = validator.rules();
// [{ id: "token.secret.weak", module: "tokenVerifier", severity: "error" }, ...]
```

---

## Challenge Analytics

### `createChallengeAnalytics(options)`

Tracks solve rates, timing distributions, difficulty effectiveness, and hourly patterns across challenges. Supports LRU eviction for long-running deployments.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxChallenges` | `number` | `1000` | Maximum tracked challenges (LRU eviction) |

**Returns:** `{ record, getChallengeStats, ranking, poolStats, flagged, difficultyEffectiveness, hourlyPatterns, exportState, importState, getStats, reset }`

```js
const analytics = createChallengeAnalytics();

analytics.record({
  challengeId: "cat-gif-01",
  event: "correct",
  solveTimeMs: 3200,
  difficulty: 3
});

const stats = analytics.getChallengeStats("cat-gif-01");
// { solveRate: 0.72, abandonRate: 0.15, timing: { mean: 3400, ... } }

const top = analytics.ranking("solveRate", { limit: 5 });
const flagged = analytics.flagged({ minSolveRate: 0.95 });
const patterns = analytics.hourlyPatterns();
```

---

## Geographic Risk Scorer

### `createGeoRiskScorer(options)`

Scores CAPTCHA attempts based on geographic signals — country risk tiers, VPN/proxy/Tor detection, distance anomalies, and IP reputation. Supports manual block/allow lists per IP.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `highRiskCountries` | `string[]` | Built-in list | ISO country codes considered high-risk |
| `blockedCountries` | `string[]` | `[]` | Countries to block outright |
| `vpnPenalty` | `number` | `30` | Score penalty for VPN/proxy detection |
| `torPenalty` | `number` | `50` | Score penalty for Tor exit nodes |

**Returns:** `{ score, scoreBatch, recordAttempt, getRegionStats, blockIP, allowIP, unblockIP, unallowIP, isBlocked, isAllowed, summary, reset }`

```js
const geo = createGeoRiskScorer();

const risk = geo.score({
  ip: "198.51.100.42",
  country: "NG",
  isVpn: true
});
// { name: "high_risk_country", score: 60, detail: "NG is high-risk" }

geo.blockIP("10.0.0.1");
geo.isBlocked("10.0.0.1"); // true

const stats = geo.getRegionStats();
```

---

## Proof of Work

### `createProofOfWork(options)`

SHA-256 hash-based proof-of-work challenges. Clients must find a nonce that produces a hash with N leading zero bits, proving computational effort. Adaptive difficulty adjusts based on solve times.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `difficulty` | `number` | `16` | Required leading zero bits |
| `challengeTtlMs` | `number` | `60000` | Challenge expiration (1 minute) |
| `maxPending` | `number` | `1000` | Max outstanding challenges |
| `adaptiveDifficulty` | `boolean` | `false` | Auto-adjust difficulty from solve times |
| `bindIp` | `boolean` | `true` | Bind challenges to originating IP |

**Returns:** `{ issue, verify, solve, estimateCost, getDifficulty, pendingCount, summary, reset }`

```js
const pow = createProofOfWork({ difficulty: 16 });

// Server: issue challenge
const challenge = pow.issue({ ip: "192.0.2.1" });
// { prefix: "a1b2c3...", difficulty: 16, algorithm: "sha256", expiresAt: ... }

// Client: solve it
const solution = pow.solve(challenge.prefix, challenge.difficulty);
// { nonce: "...", hash: "0000...", iterations: 42310 }

// Server: verify
const result = pow.verify({
  prefix: challenge.prefix,
  nonce: solution.nonce,
  ip: "192.0.2.1"
});
// { valid: true, reason: "ok", hash: "0000...", leadingZeros: 17 }
```

---

## Behavioral Biometrics

### `createBehavioralBiometrics(options)`

*Separate module: `require('gif-captcha/src/behavioral-biometrics')`*

Collects and analyzes mouse movements, clicks, keystrokes, and scroll events to distinguish human interaction patterns from bot automation. Produces per-channel risk scores and an overall bot probability.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxEvents` | `number` | `500` | Maximum events stored per channel |
| `minEventsForAnalysis` | `number` | `5` | Minimum events before analysis is meaningful |
| `clickTimingWindowMs` | `number` | `200` | Window for double-click detection |

**Returns:** `{ recordMouseMove, recordClick, recordKeystroke, recordScroll, analyze, analyzeMouseMovement, analyzeClicks, analyzeKeystrokes, analyzeScrolls, getRiskLevel, getEventCounts, exportEvents, reset }`

```js
const { createBehavioralBiometrics } = require('gif-captcha/src/behavioral-biometrics');
const bio = createBehavioralBiometrics();

bio.recordMouseMove({ x: 100, y: 200, timestamp: Date.now() });
bio.recordClick({ x: 150, y: 220, timestamp: Date.now() });
bio.recordKeystroke({ key: "a", timestamp: Date.now() });

const result = bio.analyze();
// { botProbability: 0.12, riskLevel: "low", mouse: {...}, clicks: {...}, ... }
```

---

## Challenge Decay Manager

### `createChallengeDecayManager(options)`

*Separate module: `require('gif-captcha/src/challenge-decay-manager')`*

Tracks challenge freshness and automates rotation. Monitors exposure counts, solve rates, and time-since-last-use to identify stale challenges that bots may have learned. Supports sweep-based batch retirement.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxAge` | `number` | `86400000` | Max age before staleness (24h) |
| `maxExposures` | `number` | `100` | Max exposures before staleness |
| `minSolveRate` | `number` | `0.1` | Solve rate below this triggers flag |
| `maxSolveRate` | `number` | `0.95` | Solve rate above this triggers flag (too easy / leaked) |

**Returns:** `{ addChallenge, recordExposure, recordSolve, retire, getStats, getFreshness, sweep, getPoolHealth, getFreshest, getStalest, remove, reset }`

```js
const { createChallengeDecayManager } = require('gif-captcha/src/challenge-decay-manager');
const decay = createChallengeDecayManager({ maxExposures: 50 });

decay.addChallenge("cat-01", { category: "animals" });
decay.recordExposure("cat-01");
decay.recordSolve("cat-01", true);

const health = decay.getPoolHealth();
// { total: 1, fresh: 1, stale: 0, retired: 0, avgFreshness: 0.95 }

const stale = decay.sweep(); // returns retired challenge IDs
```

---

## Solve Pattern Fingerprinter

### `createSolvePatternFingerprinter(options)`

*Separate module: `require('gif-captcha/src/solve-pattern-fingerprinter')`*

Builds behavioral fingerprints from CAPTCHA solve patterns — timing sequences, accuracy rates, difficulty preferences — to detect shared bot accounts or solve farms. Supports profile storage and cross-session similarity matching.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxSessions` | `number` | `500` | Maximum sessions tracked |
| `maxProfiles` | `number` | `100` | Maximum saved profiles |
| `similarityThreshold` | `number` | `0.8` | Threshold for "similar" fingerprints |

**Returns:** `{ recordSolve, getFingerprint, compareFingerprints, saveProfile, matchAgainstProfiles, findSimilarSessions, removeSession, removeProfile, getStats, reset }`

```js
const { createSolvePatternFingerprinter } = require('gif-captcha/src/solve-pattern-fingerprinter');
const fp = createSolvePatternFingerprinter();

fp.recordSolve("session-1", { correct: true, timeMs: 3200, difficulty: 3 });
fp.recordSolve("session-1", { correct: true, timeMs: 2800, difficulty: 4 });

const print = fp.getFingerprint("session-1");
fp.saveProfile("known-bot-1", print);

const matches = fp.matchAgainstProfiles(fp.getFingerprint("session-2"));
// [{ profileId: "known-bot-1", similarity: 0.92 }]
```

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `GIF_MAX_RETRIES` | `3` | Default max retries for GIF loading |
| `GIF_RETRY_DELAY_MS` | `1000` | Default delay between retries (ms) |
