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

## API Reference

The library exports 13 factory functions. See [API.md](API.md) for full documentation.

| Function | Purpose |
|----------|---------|
| `createChallenge` | Build a CAPTCHA challenge object |
| `validateAnswer` | Fuzzy-match user answer against expected answer |
| `createPoolManager` | Manage challenge pool lifecycle |
| `createSessionManager` | Track user sessions with risk scoring |
| `createBotDetector` | Behavioral bot detection (timing, mouse, keyboard) |
| `createTokenVerifier` | Cryptographic CAPTCHA token verification |
| `createReputationTracker` | Track user reputation across sessions |
| `createChallengeRouter` | Route challenges by difficulty and risk |
| `createSetAnalyzer` | Analyze challenge set quality and coverage |
| `createDifficultyCalibrator` | Auto-calibrate challenge difficulty |
| `createSecurityScorer` | Score CAPTCHA security posture |
| `createAttemptTracker` | Track and rate-limit solve attempts |
| `pickChallenges` | Randomly select N challenges from a pool |
| `sanitize` | Sanitize untrusted input for safe HTML rendering |

## Interactive Platform

The [live site](https://sauravbhattacharya001.github.io/gif-captcha/) hosts **40+ interactive tools** organized into four categories:

### 🔬 Research & Analysis

| Tool | Description |
|------|-------------|
| [Case Study](https://sauravbhattacharya001.github.io/gif-captcha/) | Full results table, findings, and methodology |
| [Analysis Dashboard](https://sauravbhattacharya001.github.io/gif-captcha/analysis.html) | Taxonomy, radar charts, multi-model comparison, AI timeline |
| [AI Simulator](https://sauravbhattacharya001.github.io/gif-captcha/simulator.html) | See how 5 AI models respond to each CAPTCHA |
| [Multi-Model Comparison](https://sauravbhattacharya001.github.io/gif-captcha/comparison.html) | Side-by-side model performance with capability radar |
| [Effectiveness Dashboard](https://sauravbhattacharya001.github.io/gif-captcha/effectiveness.html) | Detection rates, discrimination power over time |
| [Cognitive Load Analyzer](https://sauravbhattacharya001.github.io/gif-captcha/cognitive-load.html) | 6-dimension cognitive complexity per CAPTCHA |
| [Research Paper](https://sauravbhattacharya001.github.io/gif-captcha/research-paper.html) | Formal write-up of findings |

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

### 🛠️ Configuration & Development

| Tool | Description |
|------|-------------|
| [CAPTCHA Workshop](https://sauravbhattacharya001.github.io/gif-captcha/generator.html) | Create, test, and export custom challenge sets |
| [Playground](https://sauravbhattacharya001.github.io/gif-captcha/playground.html) | Experiment with challenge configurations |
| [A/B Configurator](https://sauravbhattacharya001.github.io/gif-captcha/abtest.html) | Design experiments with statistical rigor |
| [Theme Builder](https://sauravbhattacharya001.github.io/gif-captcha/theme-builder.html) | Visual CAPTCHA theme customization |
| [Embed Generator](https://sauravbhattacharya001.github.io/gif-captcha/embed.html) | Generate copy-paste HTML/JS embed snippets |
| [Integration Wizard](https://sauravbhattacharya001.github.io/gif-captcha/integration-wizard.html) | Step-by-step integration setup |
| [Frame Inspector](https://sauravbhattacharya001.github.io/gif-captcha/frame-inspector.html) | Frame-by-frame GIF analysis with AI perspective |
| [Difficulty Planner](https://sauravbhattacharya001.github.io/gif-captcha/difficulty-planner.html) | Plan challenge difficulty curves |
| [Cost Calculator](https://sauravbhattacharya001.github.io/gif-captcha/cost-calculator.html) | Estimate deployment costs |

### 🔒 Security & Monitoring

| Tool | Description |
|------|-------------|
| [Trust Dashboard](https://sauravbhattacharya001.github.io/gif-captcha/trust-dashboard.html) | Trust score monitoring |
| [Bot Signatures](https://sauravbhattacharya001.github.io/gif-captcha/bot-signatures.html) | Known bot signature database |
| [Fraud Ring Detector](https://sauravbhattacharya001.github.io/gif-captcha/fraud-rings.html) | Coordinated fraud visualization |
| [Geo Risk Map](https://sauravbhattacharya001.github.io/gif-captcha/geo-risk-map.html) | Geographic risk heatmap |
| [Audit Log](https://sauravbhattacharya001.github.io/gif-captcha/audit-log.html) | Tamper-evident audit trail browser |
| [Honeypot Designer](https://sauravbhattacharya001.github.io/gif-captcha/honeypot-designer.html) | Honeypot trap designer with bot simulation |
| [Threat Radar](https://sauravbhattacharya001.github.io/gif-captcha/threat-radar.html) | Real-time threat visualization |
| [Incident Timeline](https://sauravbhattacharya001.github.io/gif-captcha/incident-timeline.html) | Security incident history |
| [Rate Limiter](https://sauravbhattacharya001.github.io/gif-captcha/rate-limiter.html) | Rate limiting configuration |
| [Compliance](https://sauravbhattacharya001.github.io/gif-captcha/compliance.html) | Regulatory compliance reporting |
| [Accessibility Audit](https://sauravbhattacharya001.github.io/gif-captcha/accessibility.html) | WCAG 2.1 compliance evaluation |

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

96 test files covering all modules. See [TESTING.md](TESTING.md) for the full guide.

```bash
npm test                # Run all tests
npm run test:coverage   # Coverage (80% lines, 70% functions, 90% branches)
```

## Project Structure

```
gif-captcha/
├── src/                 # Core library (40+ modules)
│   ├── index.js         # Main entry point (UMD)
│   ├── shared-utils.js  # Shared utilities
│   └── ...              # Bot detection, trust scoring, session management, etc.
├── tests/               # 96 test files
├── docs/                # HTML documentation site
├── bin/                 # CLI entry point
├── *.html               # 40+ interactive tool pages
├── shared.css           # Dark theme styles
├── shared.js            # Browser shared utilities
├── Dockerfile           # Production container
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
