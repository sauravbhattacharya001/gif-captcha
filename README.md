<div align="center">

# 🎞️ GIF CAPTCHA

**Can animated GIFs distinguish humans from AI?**

A research case study and full-stack CAPTCHA system exploring GIF-based human verification against large language models.

[![CI](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/ci.yml/badge.svg)](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/sauravbhattacharya001/gif-captcha/graph/badge.svg)](https://codecov.io/gh/sauravbhattacharya001/gif-captcha)
[![CodeQL](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/codeql.yml/badge.svg)](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/codeql.yml)
[![Docker](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/docker.yml/badge.svg)](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/docker.yml)
[![GitHub Pages](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/pages.yml/badge.svg)](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/pages.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/gif-captcha)](https://www.npmjs.com/package/gif-captcha)
[![npm downloads](https://img.shields.io/npm/dm/gif-captcha)](https://www.npmjs.com/package/gif-captcha)
![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![GitHub repo size](https://img.shields.io/github/repo-size/sauravbhattacharya001/gif-captcha)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[**Live Demo →**](https://sauravbhattacharya001.github.io/gif-captcha/) · [**API Docs →**](API.md) · [**npm →**](https://www.npmjs.com/package/gif-captcha)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [API Reference](#api-reference)
  - [Core — Challenge Lifecycle](#core--challenge-lifecycle)
  - [Challenge Management](#challenge-management)
  - [Security & Bot Detection](#security--bot-detection)
  - [Session & Trust](#session--trust)
  - [Analytics & Monitoring](#analytics--monitoring)
  - [Compliance & Audit](#compliance--audit)
  - [Advanced Threat Intelligence](#advanced-threat-intelligence)
  - [Challenge Evolution & Ecosystem](#challenge-evolution--ecosystem)
  - [Experimentation & Operations](#experimentation--operations)
- [Server Integration](#server-integration)
- [Interactive Platform](#interactive-platform)
- [Tech Stack](#tech-stack)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Future Research](#future-research)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This project started as a simple question: *can GPT-4 describe what happens in a GIF?* The answer in 2023 was a resounding **no** — text-only LLMs scored 0/10 on GIF CAPTCHAs requiring narrative comprehension of animated sequences.

What began as a research case study has grown into a **full CAPTCHA platform** with 40+ interactive tools, a Node.js/browser library, bot detection, trust scoring, session management, and a comprehensive security stack.

### Research Timeline

| Year | Finding |
|------|---------|
| **2023** | GPT-4 (text-only) scored **0/10** — could not process animated visual content at all |
| **2025–26** | Multimodal LLMs (GPT-4o, Claude 3.5/4, Gemini 2.x) can now process GIFs and describe basic events |
| **Frontier** | CAPTCHAs requiring **comedic timing**, **cultural subversion**, and understanding *why something is unexpected* remain the hardest challenge for AI |

### Original Experiment Results

10 GIFs with narrative twists were presented to GPT-4. Humans described the unexpected events easily. GPT-4 couldn't process any of them:

| # | GIF Description | Human | GPT-4 |
|---|----------------|:-----:|:-----:|
| 1 | Duel plot twist | ✅ | ❌ |
| 2 | Rappers roller skating | ✅ | ❌ |
| 3 | Flying skateboarder | ✅ | ❌ |
| 4 | Banana mascot dance-off | ✅ | ❌ |
| 5 | Tic Tac Toe dog | ✅ | ❌ |
| 6 | Parent dog sacrifice | ✅ | ❌ |
| 7 | Mirror hand illusion | ✅ | ❌ |
| 8 | Highway 180° drift | ✅ | ❌ |
| 9 | Road rage hug | ✅ | ❌ |
| 10 | Birthday cake face cover | ✅ | ❌ |

> GPT-4's response to every test: *"I currently cannot view animations, including animated GIFs, so I can't provide real-time descriptions of events within them."*

## Installation

### npm

```bash
npm install gif-captcha
```

### Docker

```bash
docker run -p 8080:80 ghcr.io/sauravbhattacharya001/gif-captcha
```

### From Source

```bash
git clone https://github.com/sauravbhattacharya001/gif-captcha.git
cd gif-captcha
npm install
npm test
```

## Quick Start

### Node.js

```javascript
const gifCaptcha = require("gif-captcha");

// Create a challenge
const challenge = gifCaptcha.createChallenge({
  id: 1,
  title: "Surprise Ending",
  gifUrl: "https://example.com/twist.gif",
  humanAnswer: "The cat fell off the table unexpectedly",
});

// Validate user answer (fuzzy matching with Jaccard similarity)
const result = gifCaptcha.validateAnswer(userAnswer, challenge.humanAnswer, {
  threshold: 0.3,
  requiredKeywords: ["cat", "fell"],
});
console.log(result); // { passed: true, score: 0.75, hasKeywords: true }
```

### Browser (CDN)

```html
<script src="https://unpkg.com/gif-captcha/src/index.js"></script>
<script>
  const challenge = gifCaptcha.createChallenge({ /* ... */ });
  gifCaptcha.loadGifWithRetry(container, challenge);
</script>
```

### CLI

```bash
npx gif-captcha serve    # Launch local demo server
npx gif-captcha validate # Validate challenge JSON files
```

## Architecture

The library is organized into five functional layers, each composable and independently usable:

```
┌─────────────────────────────────────────────────────────┐
│                  Application Layer                       │
│  Express/Fastify middleware · Browser widget · CLI       │
├─────────────────────────────────────────────────────────┤
│                  Orchestration Layer                     │
│  ChallengeRouter · ChallengeAutopilot · ABExperiment    │
│  ChallengeRotationScheduler · ChallengePoolManager      │
├─────────────────────────────────────────────────────────┤
│             Threat Intelligence Layer                   │
│  BotMimicryDetector · BotAttributionEngine              │
│  BotCapabilityProfiler · BotCollectiveIntelDetector     │
│  AttackEvolutionTracker · ThreatIntelFusion             │
│  DeceptionCampaignOrchestrator · DefensePostureOptimizer│
│  BotAdversarialPlaybookEngine                           │
├─────────────────────────────────────────────────────────┤
│               Security & Trust Layer                    │
│  BotDetector · TrustScoreEngine · FraudRingDetector     │
│  GeoRiskScorer · RateLimiter · HoneypotInjector         │
│  TokenVerifier · ReplayDetector · ProofOfWork           │
├─────────────────────────────────────────────────────────┤
│            Challenge Evolution Layer                    │
│  ChallengeGeneticsLab · ChallengeRetirementEngine       │
│  ChallengeDifficultyCurveEngine · EcosystemHealthEngine │
│  ChallengeDecayManager · AdaptiveDifficultyTuner        │
├─────────────────────────────────────────────────────────┤
│              Analytics & Monitoring Layer                │
│  MetricsAggregator · HealthMonitor · TrafficAnalyzer    │
│  AuditTrail · IncidentManager · ComplianceReporter      │
│  StatsCollector · FunnelAnalyzer · ResponseTimeProfiler  │
├─────────────────────────────────────────────────────────┤
│                    Core Layer                           │
│  createChallenge · validateAnswer · pickChallenges       │
│  sanitize · textSimilarity · loadGifWithRetry            │
│  secureRandomInt · crypto-utils · shared-utils           │
└─────────────────────────────────────────────────────────┘
```

See [docs/architecture.html](https://sauravbhattacharya001.github.io/gif-captcha/docs/architecture.html) for detailed module interactions and data flow diagrams.

## API Reference

The library exports **100+ functions and factories** across ten domains. See [API.md](API.md) for full documentation.

### Core — Challenge Lifecycle

| Function | Purpose |
|----------|---------|
| `createChallenge` | Build a CAPTCHA challenge object with metadata |
| `validateAnswer` | Fuzzy-match user answer via Jaccard similarity + keyword matching |
| `pickChallenges` | Randomly select N challenges from a pool |
| `textSimilarity` | Compute Jaccard similarity between two text strings |
| `sanitize` | Sanitize untrusted input for safe HTML rendering |
| `createSanitizer` | Create a reusable sanitizer with custom allow-lists |
| `isSafeUrl` | Validate URLs against protocol and domain allow-lists |
| `loadGifWithRetry` | Load a GIF into a DOM container with exponential backoff |
| `secureRandomInt` | Cryptographically secure random integer generation |
| `installRoundRectPolyfill` | Canvas roundRect polyfill for older browsers |

### Challenge Management

| Function | Purpose |
|----------|---------|
| `createPoolManager` | Manage challenge pool lifecycle (add, retire, refresh) |
| `createChallengePoolManager` | Extended pool management with capacity planning |
| `createChallengeRouter` | Route challenges by difficulty, risk level, and user history |
| `createChallengeRotationScheduler` | Schedule automatic challenge rotation and retirement |
| `createChallengeAutopilot` | Autonomous challenge selection with adaptive difficulty |
| `createChallengeDecayManager` | Track challenge effectiveness decay over time |
| `createChallengeTemplateEngine` | Generate challenges from parameterized templates |
| `createSetAnalyzer` | Analyze challenge set quality, diversity, and coverage |
| `createDifficultyCalibrator` | Auto-calibrate challenge difficulty from solve data |
| `createAdaptiveDifficultyTuner` | Real-time difficulty tuning based on user performance |
| `analyzeDiversity` / `shannonEntropy` / `simpsonsIndex` / `giniSimpson` | Statistical diversity metrics for challenge sets |

### Security & Bot Detection

| Function | Purpose |
|----------|---------|
| `createBotDetector` | Behavioral bot detection (timing, mouse, keyboard patterns) |
| `createTokenVerifier` | Cryptographic CAPTCHA token generation and verification |
| `createRateLimiter` | Token-bucket rate limiting for solve attempts |
| `createCaptchaRateLimiter` | Advanced rate limiting with sliding windows and IP tracking |
| `createFraudRingDetector` | Detect coordinated fraud via session correlation |
| `createGeoRiskScorer` | Geographic risk scoring by country and region |
| `createHoneypotInjector` | Inject hidden honeypot fields to trap bots |
| `createProofOfWork` | Proof-of-work challenge generation and verification |
| `createClientFingerprinter` | Browser/device fingerprinting for session binding |
| `createBotSignatureDatabase` | Known bot signature matching and updates |
| `createSecurityScorer` | Score overall CAPTCHA security posture |
| `createCaptchaStrengthScorer` | Score individual challenge cryptographic strength |
| `createReplayDetector` | Detect replayed or reused challenge tokens |

### Session & Trust

| Function | Purpose |
|----------|---------|
| `createSessionManager` | Track user sessions with risk scoring |
| `createReputationTracker` | Track user reputation across sessions |
| `createTrustScoreEngine` | Multi-signal trust scoring (behavior, history, geo) |
| `createSessionRiskAggregator` | Aggregate risk signals across a session |
| `createAttemptTracker` | Track and rate-limit per-user solve attempts |
| `createBehavioralBiometrics` | Mouse/keyboard/touch biometric profiling |
| `createDeviceCohortAnalyzer` | Group and analyze sessions by device characteristics |
| `createSolvePatternFingerprinter` | Fingerprint solve patterns to detect automation |
| `createAdaptiveTimeout` | Dynamic timeout adjustment based on challenge complexity |

### Analytics & Monitoring

| Function | Purpose |
|----------|---------|
| `createMetricsAggregator` | Aggregate solve rates, timing, and error metrics |
| `createCaptchaHealthMonitor` | Monitor system health with alerting thresholds |
| `createCaptchaTrafficAnalyzer` | Analyze traffic patterns and detect anomalies |
| `createAnomalyDetector` | Statistical anomaly detection in CAPTCHA metrics |
| `createStatsCollector` | Collect and export per-challenge statistics |
| `createResponseAnalyzer` | Analyze user response quality and patterns |
| `createResponseTimeProfiler` | Profile solve time distributions |
| `createFunnelAnalyzer` | Track conversion through the solve funnel |
| `createChallengeAnalytics` | Per-challenge performance analytics |
| `createCaptchaFatigueDetector` | Detect user fatigue from repeated challenges |
| `createCapacityPlanner` | Forecast infrastructure capacity needs |
| `createLoadTester` / `createCaptchaLoadTester` | Simulate load and measure throughput |

### Compliance & Audit

| Function | Purpose |
|----------|---------|
| `createAuditTrail` | Tamper-evident audit trail with hash chaining |
| `createAuditLog` | Structured audit logging with retention policies |
| `createComplianceReporter` | GDPR/CCPA/SOC2 compliance report generation |
| `createAccessibilityAuditor` | WCAG 2.1 compliance evaluation |
| `createAccessibilityAnalyzer` | Detailed accessibility gap analysis |
| `createIncidentManager` | Security incident tracking and response |
| `createIncidentCorrelator` | Correlate incidents across sessions and time |
| `createSessionRecorder` / `createSessionReplay` | Record and replay user sessions |
| `WebhookDispatcher` | Send event notifications to external webhooks |

### Advanced Threat Intelligence

| Function | Purpose |
|----------|---------|
| `createBotMimicryDetector` | Detect bots that deliberately imitate human behavior — uncanny valley analysis, consistency paradox, fatigue immunity detection |
| `createBotAttributionEngine` | Attribute bot activity to operators/campaigns via 8-dimensional fingerprint vectors and cosine similarity matching |
| `createBotCapabilityProfiler` | Build per-bot capability profiles across 8 skill dimensions, classify sophistication tiers, predict challenge vulnerability |
| `createBotCollectiveIntelDetector` | Detect coordinated bot swarms via timing synchronization, collective learning rate, and swarm topology inference |
| `createAttackEvolutionTracker` | Track how bot attack strategies evolve, detect learning curves, predict time-to-compromise, recommend preemptive rotations |
| `createThreatIntelFusion` | Correlate signals from 6 detection subsystems into unified threat assessments with autonomous defense posture management |
| `createDeceptionCampaignOrchestrator` | Design multi-phase trap sequences exploiting bot weaknesses — 7 deception tactics with autonomous profiling |
| `createDefensePostureOptimizer` | Multi-objective Pareto optimization across 6 defense dimensions (catch rate, friction, latency, diversity, coverage, fatigue) |
| `createBotAdversarialPlaybookEngine` | Autonomous red-team simulation — generates attack scenarios across 10 categories, simulates against current defenses, identifies gaps, produces prioritized countermeasure playbooks with resilience scoring |

### Challenge Evolution & Ecosystem

| Function | Purpose |
|----------|---------|
| `createChallengeGeneticsLab` | Breed more effective challenges via genetic algorithms — tournament selection, crossover, mutation, elitism |
| `createChallengeEcosystemHealthEngine` | Model the challenge pool as a biological ecosystem — biodiversity indices, predator-prey dynamics, extinction risk |
| `createChallengeDifficultyCurveEngine` | Model difficulty-vs-outcome curves for humans and bots separately, find optimal difficulty sweet spot |
| `createChallengeRetirementEngine` | Detect compromised challenges via effectiveness decay, burst attacks, and cross-challenge correlation — 4-tier lifecycle grading |

### Experimentation & Operations

| Function | Purpose |
|----------|---------|
| `createABExperimentRunner` | Run A/B experiments with statistical significance |
| `createI18n` | Internationalization for challenge text and UI |
| `createCaptchaLocalizationManager` | Locale-aware challenge localization |
| `createConfigValidator` | Validate configuration objects against schemas |
| `createExportFormatter` | Export data in CSV, JSON, and Markdown formats |
| `createEventEmitter` | Internal pub/sub event bus for module communication |
| `csvEscape` / `csvRow` | CSV formatting utilities |
| `secureRandomInt` / `secureRandomFloat` / `secureRandomChoice` | Cryptographically secure random utilities (shared via `crypto-utils`) |

## Server Integration

### Express Middleware

```javascript
const express = require("express");
const gifCaptcha = require("gif-captcha");

const app = express();
const sessions = gifCaptcha.createSessionManager({ maxSessions: 10000 });
const rateLimiter = gifCaptcha.createRateLimiter({ maxAttempts: 5, windowMs: 60000 });
const tokenVerifier = gifCaptcha.createTokenVerifier({ secret: process.env.CAPTCHA_SECRET });

// Issue a challenge
app.get("/captcha/challenge", (req, res) => {
  const session = sessions.create(req.ip);
  const challenge = gifCaptcha.pickChallenges(pool, 1)[0];
  const token = tokenVerifier.sign({ sessionId: session.id, challengeId: challenge.id });
  res.json({ gifUrl: challenge.gifUrl, token });
});

// Validate the answer
app.post("/captcha/verify", express.json(), (req, res) => {
  if (!rateLimiter.check(req.ip)) return res.status(429).json({ error: "Too many attempts" });
  const payload = tokenVerifier.verify(req.body.token);
  if (!payload) return res.status(400).json({ error: "Invalid token" });
  const result = gifCaptcha.validateAnswer(req.body.answer, challenges[payload.challengeId].humanAnswer);
  res.json({ passed: result.passed, score: result.score });
});
```

### Fastify Plugin

```javascript
const gifCaptcha = require("gif-captcha");

async function captchaPlugin(fastify) {
  const botDetector = gifCaptcha.createBotDetector({ honeypotFields: ["email2"] });
  const trust = gifCaptcha.createTrustScoreEngine();

  fastify.addHook("preHandler", async (request, reply) => {
    if (request.routeOptions.config?.captcha) {
      const botScore = botDetector.analyze(request.body?._behavioral);
      const trustScore = trust.evaluate(request.ip, request.headers);
      if (botScore.isBot || trustScore < 0.3) {
        reply.code(403).send({ error: "Blocked" });
      }
    }
  });
}
```

## Interactive Platform

The [live site](https://sauravbhattacharya001.github.io/gif-captcha/) hosts **90+ interactive tools** organized into five categories:

### 🔬 Research & Analysis

| Tool | Description |
|------|-------------|
| [Case Study](https://sauravbhattacharya001.github.io/gif-captcha/) | Full results table, findings, and methodology |
| [Analysis Dashboard](https://sauravbhattacharya001.github.io/gif-captcha/analysis.html) | Taxonomy, radar charts, multi-model comparison, AI timeline |
| [AI Simulator](https://sauravbhattacharya001.github.io/gif-captcha/simulator.html) | See how 5 AI models respond to each CAPTCHA |
| [Multi-Model Comparison](https://sauravbhattacharya001.github.io/gif-captcha/comparison.html) | Side-by-side model performance with capability radar |
| [Effectiveness Dashboard](https://sauravbhattacharya001.github.io/gif-captcha/effectiveness.html) | Detection rates, discrimination power over time |
| [Cognitive Load Analyzer](https://sauravbhattacharya001.github.io/gif-captcha/cognitive-load.html) | 6-dimension cognitive complexity per CAPTCHA |
| [Cognitive Fingerprint](https://sauravbhattacharya001.github.io/gif-captcha/cognitive-fingerprint.html) | Behavioral fingerprinting through cognitive patterns |
| [Research Paper](https://sauravbhattacharya001.github.io/gif-captcha/research-paper.html) | Formal write-up of findings |
| [Entropy Analyzer](https://sauravbhattacharya001.github.io/gif-captcha/entropy.html) | Challenge entropy and randomness analysis |
| [Diversity Analyzer](https://sauravbhattacharya001.github.io/gif-captcha/diversity-analyzer.html) | Challenge set diversity metrics (Shannon, Simpson, Gini) |
| [Solve Histogram](https://sauravbhattacharya001.github.io/gif-captcha/solve-histogram.html) | Solve time distribution visualization |
| [Timing Analysis](https://sauravbhattacharya001.github.io/gif-captcha/timing.html) | Response timing pattern analysis |
| [Heatmap](https://sauravbhattacharya001.github.io/gif-captcha/heatmap.html) | Visual heatmap of interaction patterns |

### 🎮 Interactive Challenges

| Tool | Description |
|------|-------------|
| [Demo](https://sauravbhattacharya001.github.io/gif-captcha/demo.html) | Take the GIF CAPTCHA challenge yourself |
| [Temporal Challenge](https://sauravbhattacharya001.github.io/gif-captcha/temporal.html) | Drag-and-drop event ordering with Kendall Tau scoring |
| [Daily Challenge](https://sauravbhattacharya001.github.io/gif-captcha/daily.html) | Fresh challenge every day with streak tracking |
| [Streak Mode](https://sauravbhattacharya001.github.io/gif-captcha/streak.html) | How many GIFs can you describe in a row? |
| [Benchmark](https://sauravbhattacharya001.github.io/gif-captcha/benchmark.html) | Timed solve challenge with precision metrics |
| [Competitive Mode](https://sauravbhattacharya001.github.io/gif-captcha/competitive.html) | Head-to-head CAPTCHA solving |
| [Escape Room](https://sauravbhattacharya001.github.io/gif-captcha/escape-room.html) | Puzzle-style CAPTCHA challenges |
| [Speed Arena](https://sauravbhattacharya001.github.io/gif-captcha/speed-arena.html) | Race against the clock |
| [Bot or Human?](https://sauravbhattacharya001.github.io/gif-captcha/bot-or-human.html) | Interactive bot-vs-human classification game |
| [Leaderboard](https://sauravbhattacharya001.github.io/gif-captcha/leaderboard.html) | Global ranking of CAPTCHA solvers |
| [My Stats](https://sauravbhattacharya001.github.io/gif-captcha/my-stats.html) | Personal solve statistics and history |
| [Gallery](https://sauravbhattacharya001.github.io/gif-captcha/gallery.html) | Challenge gallery browser |

### 🛠️ Configuration & Development

| Tool | Description |
|------|-------------|
| [CAPTCHA Workshop](https://sauravbhattacharya001.github.io/gif-captcha/generator.html) | Create, test, and export custom challenge sets |
| [CAPTCHA Designer](https://sauravbhattacharya001.github.io/gif-captcha/designer.html) | Visual challenge design tool |
| [Playground](https://sauravbhattacharya001.github.io/gif-captcha/playground.html) | Experiment with challenge configurations |
| [A/B Configurator](https://sauravbhattacharya001.github.io/gif-captcha/abtest.html) | Design experiments with statistical rigor |
| [A/B Dashboard](https://sauravbhattacharya001.github.io/gif-captcha/ab-test-dashboard.html) | View A/B experiment results and significance |
| [Theme Builder](https://sauravbhattacharya001.github.io/gif-captcha/theme-builder.html) | Visual CAPTCHA theme customization |
| [Embed Generator](https://sauravbhattacharya001.github.io/gif-captcha/embed.html) | Generate copy-paste HTML/JS embed snippets |
| [Integration Wizard](https://sauravbhattacharya001.github.io/gif-captcha/integration-wizard.html) | Step-by-step integration setup |
| [Config Editor](https://sauravbhattacharya001.github.io/gif-captcha/config.html) | Configuration management UI |
| [Frame Inspector](https://sauravbhattacharya001.github.io/gif-captcha/frame-inspector.html) | Frame-by-frame GIF analysis with AI perspective |
| [Difficulty Planner](https://sauravbhattacharya001.github.io/gif-captcha/difficulty-planner.html) | Plan challenge difficulty curves |
| [Adaptive Difficulty](https://sauravbhattacharya001.github.io/gif-captcha/adaptive-difficulty.html) | Real-time difficulty adjustment dashboard |
| [Cost Calculator](https://sauravbhattacharya001.github.io/gif-captcha/cost-calculator.html) | Estimate deployment costs |
| [Batch Operations](https://sauravbhattacharya001.github.io/gif-captcha/batch.html) | Bulk challenge operations |
| [Feedback](https://sauravbhattacharya001.github.io/gif-captcha/feedback.html) | User feedback collection |
| [Directory](https://sauravbhattacharya001.github.io/gif-captcha/directory.html) | Full tool directory and navigation |

### 🔒 Security & Monitoring

| Tool | Description |
|------|-------------|
| [Dashboard](https://sauravbhattacharya001.github.io/gif-captcha/dashboard.html) | Central monitoring dashboard |
| [Trust Dashboard](https://sauravbhattacharya001.github.io/gif-captcha/trust-dashboard.html) | Trust score monitoring |
| [Trust Network](https://sauravbhattacharya001.github.io/gif-captcha/trust-network.html) | Trust relationship graph visualization |
| [Bot Signatures](https://sauravbhattacharya001.github.io/gif-captcha/bot-signatures.html) | Known bot signature database |
| [Bot Attribution](https://sauravbhattacharya001.github.io/gif-captcha/bot-attribution.html) | Trace bot activity back to operators/campaigns |
| [Bot Capability Profiler](https://sauravbhattacharya001.github.io/gif-captcha/bot-capability-profiler.html) | Analyze bot sophistication tiers and skill vectors |
| [Fraud Ring Detector](https://sauravbhattacharya001.github.io/gif-captcha/fraud-rings.html) | Coordinated fraud visualization |
| [Geo Risk Map](https://sauravbhattacharya001.github.io/gif-captcha/geo-risk-map.html) | Geographic risk heatmap |
| [Biometrics Lab](https://sauravbhattacharya001.github.io/gif-captcha/biometrics-lab.html) | Behavioral biometrics analysis |
| [Fingerprint Explorer](https://sauravbhattacharya001.github.io/gif-captcha/fingerprint-explorer.html) | Device and browser fingerprint viewer |
| [Audit Log](https://sauravbhattacharya001.github.io/gif-captcha/audit-log.html) | Tamper-evident audit trail browser |
| [Honeypot Designer](https://sauravbhattacharya001.github.io/gif-captcha/honeypot-designer.html) | Honeypot trap designer with bot simulation |
| [Threat Radar](https://sauravbhattacharya001.github.io/gif-captcha/threat-radar.html) | Real-time threat visualization |
| [Threat Index](https://sauravbhattacharya001.github.io/gif-captcha/threat-index.html) | Threat severity index and trending |
| [Threat Feed](https://sauravbhattacharya001.github.io/gif-captcha/threat-feed.html) | Live threat intelligence feed |
| [Threat Intel Fusion](https://sauravbhattacharya001.github.io/gif-captcha/threat-intel-fusion.html) | Multi-source threat signal correlation |
| [Incident Timeline](https://sauravbhattacharya001.github.io/gif-captcha/incident-timeline.html) | Security incident history |
| [Forensic Investigator](https://sauravbhattacharya001.github.io/gif-captcha/forensic-investigator.html) | Deep-dive forensic analysis tools |
| [Replay Detector](https://sauravbhattacharya001.github.io/gif-captcha/replay-detector.html) | Token replay detection viewer |
| [Session Replay](https://sauravbhattacharya001.github.io/gif-captcha/session-replay.html) | Replay recorded user sessions |
| [Rate Limiter](https://sauravbhattacharya001.github.io/gif-captcha/rate-limiter.html) | Rate limiting configuration |
| [Proof of Work](https://sauravbhattacharya001.github.io/gif-captcha/pow-calibrator.html) | PoW difficulty calibration |
| [Queue Manager](https://sauravbhattacharya001.github.io/gif-captcha/queue-manager.html) | Challenge queue management |
| [Compliance](https://sauravbhattacharya001.github.io/gif-captcha/compliance.html) | Regulatory compliance reporting |
| [Accessibility Audit](https://sauravbhattacharya001.github.io/gif-captcha/accessibility.html) | WCAG 2.1 compliance evaluation |
| [CAPTCHA Health Monitor](https://sauravbhattacharya001.github.io/gif-captcha/captcha-health-monitor.html) | System health and alerting |
| [Performance Profiler](https://sauravbhattacharya001.github.io/gif-captcha/performance-profiler.html) | Performance metrics and bottleneck analysis |
| [Response Time Profiler](https://sauravbhattacharya001.github.io/gif-captcha/response-time-profiler.html) | Solve time distribution profiling |
| [Load Tester](https://sauravbhattacharya001.github.io/gif-captcha/load-tester.html) | Simulate load and measure throughput |
| [Funnel](https://sauravbhattacharya001.github.io/gif-captcha/funnel.html) | Solve funnel analytics |
| [Journey Map](https://sauravbhattacharya001.github.io/gif-captcha/journey-map.html) | User journey visualization |

### 🧬 Advanced Defense & Evolution

| Tool | Description |
|------|-------------|
| [Arms Race](https://sauravbhattacharya001.github.io/gif-captcha/arms-race.html) | Bot-vs-defender arms race simulation |
| [Attack Evolution](https://sauravbhattacharya001.github.io/gif-captcha/attack-evolution.html) | Track how attack strategies evolve over time |
| [Attack Predictor](https://sauravbhattacharya001.github.io/gif-captcha/attack-predictor.html) | Predict next attack vectors |
| [Adversarial Trainer](https://sauravbhattacharya001.github.io/gif-captcha/adversarial-trainer.html) | Train challenges against adversarial bots |
| [Challenge Genetics Lab](https://sauravbhattacharya001.github.io/gif-captcha/challenge-genetics-lab.html) | Breed challenges via genetic algorithms |
| [Challenge Retirement](https://sauravbhattacharya001.github.io/gif-captcha/challenge-retirement.html) | Challenge lifecycle and retirement management |
| [Challenge Autopilot](https://sauravbhattacharya001.github.io/gif-captcha/challenge-autopilot.html) | Autonomous challenge selection and rotation |
| [Rotation Scheduler](https://sauravbhattacharya001.github.io/gif-captcha/rotation-scheduler.html) | Schedule automatic challenge rotations |
| [Mutation Lab](https://sauravbhattacharya001.github.io/gif-captcha/mutation-lab.html) | Mutate challenge parameters experimentally |
| [Decay Simulator](https://sauravbhattacharya001.github.io/gif-captcha/decay-simulator.html) | Simulate challenge effectiveness decay |
| [Resistance Analyzer](https://sauravbhattacharya001.github.io/gif-captcha/resistance.html) | Analyze bot resistance to challenge types |
| [Immune System](https://sauravbhattacharya001.github.io/gif-captcha/immune-system.html) | Adaptive immune response visualization |
| [Swarm Intelligence](https://sauravbhattacharya001.github.io/gif-captcha/swarm-intelligence.html) | Bot swarm behavior analysis |
| [Collective Intel](https://sauravbhattacharya001.github.io/gif-captcha/collective-intel.html) | Collective intelligence dashboard |
| [Deception Campaign](https://sauravbhattacharya001.github.io/gif-captcha/deception-campaign.html) | Orchestrate multi-phase deception traps |
| [Defense Strategist](https://sauravbhattacharya001.github.io/gif-captcha/defense-strategist.html) | Defense strategy optimization |
| [Canary Deployer](https://sauravbhattacharya001.github.io/gif-captcha/canary-deployer.html) | Deploy canary challenges to detect new threats |
| [Fleet Orchestrator](https://sauravbhattacharya001.github.io/gif-captcha/fleet-orchestrator.html) | Multi-instance fleet management |
| [Fleet](https://sauravbhattacharya001.github.io/gif-captcha/fleet.html) | Fleet status and operations |

## Tech Stack

| Technology | Purpose |
|-----------|---------|
| **JavaScript** | Core CAPTCHA library (UMD — browser + Node.js) |
| **HTML5 / CSS3** | 40+ interactive tool pages, dark theme |
| **GitHub Pages** | Static site hosting |
| **Docker** | Containerized deployment (nginx-alpine) |
| **npm** | Package distribution |
| **GitHub Actions** | CI, CodeQL, Docker build, Pages deploy |

## Testing

112 test files covering all 55 modules. See [TESTING.md](TESTING.md) for the full guide.

```bash
npm test                # Run all tests
npm run test:coverage   # Coverage (80% lines, 70% functions, 90% branches)
```

## Project Structure

```
gif-captcha/
├── src/                 # Core library (55 modules)
│   ├── index.js         # Main entry point (UMD)
│   ├── shared-utils.js  # Shared utilities (LruTracker, clamp, etc.)
│   ├── crypto-utils.js  # Shared cryptographic random helpers
│   ├── bot-*.js         # Bot detection, attribution, profiling, swarm detection, adversarial playbooks
│   ├── challenge-*.js   # Challenge lifecycle, genetics, rotation, difficulty
│   ├── captcha-*.js     # Analytics, health, compliance, rate limiting
│   └── ...              # Trust scoring, session management, threat intel, etc.
├── tests/               # 112 test files
├── docs/                # HTML documentation site
├── bin/                 # CLI entry point
├── .github/             # CI, CodeQL, Docker, Pages, dependabot, templates
├── *.html               # 91 interactive tool pages
├── shared.css           # Dark theme styles
├── shared.js            # Browser shared utilities
├── Dockerfile           # Production container (nginx-alpine)
└── nginx-security.conf  # Hardened nginx config
```

## Future Research

- **Narrative surprise detection** — Can AI identify *why* something is unexpected, not just *what* happened?
- **Adversarial GIF generation** — Procedurally create GIFs that exploit frame-by-frame vs. continuous processing gaps
- **Cultural context CAPTCHAs** — Leverage culture-specific humor requiring lived experience
- **Real-time generation** — Unique animated challenges per session to prevent lookup attacks
- **Multi-model benchmarking** — Extend testing to latest multimodal models with native video input

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR guidelines.

## License

[MIT](LICENSE) — Saurav Bhattacharya

---

<div align="center">

**[Live Demo](https://sauravbhattacharya001.github.io/gif-captcha/)** · **[npm Package](https://www.npmjs.com/package/gif-captcha)** · **[API Docs](API.md)** · **[Report Issue](https://github.com/sauravbhattacharya001/gif-captcha/issues)**

</div>
