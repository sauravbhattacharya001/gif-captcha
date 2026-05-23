# Contributing to GIF CAPTCHA

Thanks for your interest in contributing to GIF CAPTCHA! This project explores whether animated GIF-based CAPTCHAs can distinguish humans from AI, and there are several meaningful ways to help.

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Development Guide](#development-guide)
- [Project Architecture](#project-architecture)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Research Contributions](#research-contributions)

## Ways to Contribute

### 🔬 Research
- **New GIF test cases**: Find GIFs with unexpected twists and test them against current AI models
- **Model benchmarking**: Run the GIF CAPTCHA test against newer multimodal models (GPT-4o, Claude 3.5 Sonnet, Gemini 2.0, etc.) and report results
- **Adversarial GIF generation**: Design GIFs that specifically exploit frame-by-frame vs. continuous processing gaps
- **Category analysis**: Propose new cognitive categories or refine the existing taxonomy

### 🐛 Bug Reports
- GIFs that no longer load (external CDN links break over time)
- Rendering issues on specific browsers or screen sizes
- Chart rendering problems in the analysis dashboard
- Accessibility issues

### ✨ Feature Ideas
- New visualizations for the analysis dashboard
- Improved interactive demo mechanics
- Accessibility improvements
- Performance optimizations

### 📝 Documentation
- Improve clarity of research findings
- Add citations to related CAPTCHA research
- Fix typos or outdated information

## Getting Started

### Prerequisites

- A modern web browser (Chrome, Firefox, Safari, Edge)
- Git
- (Optional) Node.js for HTML validation: `npm install -g htmlhint`
- (Optional) Docker for container testing

### Setup

```bash
# Clone the repository
git clone https://github.com/sauravbhattacharya001/gif-captcha.git
cd gif-captcha

# Install dev dependencies (for tests and coverage)
npm install

# Open directly in your browser
start index.html     # Windows
open index.html      # macOS
xdg-open index.html  # Linux
```

No build step required for the front-end — the project is pure HTML/CSS/JS. The npm dependencies are only needed for running tests and code coverage.

### Running Tests

```bash
# Run the test suite
npm test

# Run tests with coverage report
npm run test:coverage

# Check coverage thresholds (80% lines, 70% functions, 90% branches)
npm run coverage:check
```

Tests use Node.js built-in test runner with `jsdom` for DOM simulation. Coverage is powered by [c8](https://github.com/bcoe/c8).

### Validation

```bash
# Validate HTML
npx htmlhint index.html demo.html analysis.html

# Test Docker build
docker build -t gif-captcha .
docker run -p 8080:80 gif-captcha
# Visit http://localhost:8080
```

## Development Guide

### Pages Overview

| File | Purpose | Key Features |
|------|---------|-------------|
| `index.html` | Case study results | Results table, key findings, 2025 update |
| `demo.html` | Interactive demo | 10 GIF challenges, scoring, reveal panels |
| `analysis.html` | Research dashboard | Canvas charts, radar diagram, taxonomy filters, timeline |

### Making Changes

1. **Edit HTML files directly** — no compilation needed
2. **Refresh your browser** to see changes
3. **Test responsive layouts** using browser DevTools (resize to 480px, 768px, and full width)
4. **Check all three pages** if your change affects shared elements (navigation, color variables, etc.)

### Docker Testing

```bash
docker build -t gif-captcha .
docker run -p 8080:80 gif-captcha
```

This serves the site through nginx with security headers from `nginx-security.conf`.

## Project Architecture

```
gif-captcha/
├── index.html              # Main case study (static HTML + CSS)
├── demo.html               # Interactive demo (10 GIF challenges, scoring)
├── analysis.html            # Research dashboard (Canvas 2D charts, radar, taxonomy)
├── shared.js               # Shared front-end utilities
├── bin/gif-captcha.js       # CLI entry point
├── src/                     # Core library (53 modules)
│   ├── index.js             # Main entry — exports core API + SetAnalyzer
│   └── shared-utils.js      # Shared helpers (LruTracker, sanitizer, stats, crypto)
├── tests/                   # Node built-in test runner + jsdom (120+ test files)
├── docs/                    # Documentation site (architecture, deployment, modules)
├── Dockerfile               # nginx:alpine container
├── nginx-security.conf      # Security headers for Docker deployment
└── .github/
    ├── workflows/           # CI, Pages, Docker, CodeQL, publish, dependency-review
    └── ISSUE_TEMPLATE/      # Bug, feature, research, integration, security templates
```

### Design Decisions

- **Self-contained pages**: Each HTML file includes all its CSS and JS inline. This avoids external dependencies and simplifies deployment
- **No JavaScript frameworks**: Vanilla JS only, for simplicity and zero build overhead
- **Canvas 2D for charts**: The analysis page renders charts with the Canvas API rather than a charting library, keeping the project dependency-free
- **Dark theme**: GitHub-inspired dark color scheme using CSS custom properties
- **Factory pattern**: Most `src/` modules export a `create*()` factory function rather than classes, keeping state encapsulated and testable

### Module Catalog (src/)

All 53 backend modules organized by functional domain. Each module is independently testable and follows the factory-function pattern.

#### Core & Utilities

| Module | Export | Purpose |
|--------|--------|---------|
| `index.js` | `createSetAnalyzer`, core API | Main entry point — re-exports shared-utils + SetAnalyzer |
| `shared-utils.js` | `LruTracker`, `sanitize`, stats helpers | Shared LRU cache, sanitization, crypto, math utilities |
| `config-validator.js` | `createConfigValidator`, `createChallengeAnalytics` | Schema validation for config objects + challenge analytics |
| `crypto-utils.js` | HMAC, token generation | Cryptographic utilities (HMAC signing, secure tokens) |
| `csv-utils.js` | CSV export/import | CSV serialization and parsing |
| `i18n.js` | `createI18n` | Localization and internationalization |
| `captcha-export-formatter.js` | `createExportFormatter` | Multi-format export (JSON, CSV, PDF-ready) |

#### Bot Detection & Attribution

| Module | Export | Purpose |
|--------|--------|---------|
| `bot-attribution-engine.js` | `createBotAttributionEngine` | Attributes solve attempts to known bot families |
| `bot-capability-profiler.js` | `createBotCapabilityProfiler` | Profiles what each bot class can/cannot defeat |
| `bot-collective-intel.js` | `createBotCollectiveIntelDetector` | Detects coordinated bot swarms via behavioral correlation |
| `bot-signature-database.js` | `createBotSignatureDatabase` | Stores and matches bot behavioral fingerprints |
| `behavioral-biometrics.js` | `createBehavioralBiometrics` | Mouse/keyboard/touch behavioral analysis |
| `solve-pattern-fingerprinter.js` | `createSolvePatternFingerprinter` | Fingerprints solve patterns for bot/human classification |
| `fraud-ring-detector.js` | `createFraudRingDetector` | Graph-based detection of coordinated fraud rings |

#### Challenge Management

| Module | Export | Purpose |
|--------|--------|---------|
| `challenge-pool-manager.js` | `createChallengePoolManager` | Manages active challenge inventory and selection |
| `challenge-rotation-scheduler.js` | `createRotationScheduler` | Schedules when challenges rotate in/out |
| `challenge-retirement-engine.js` | `ChallengeRetirementEngine` | Retires compromised or stale challenges |
| `challenge-decay-manager.js` | `createChallengeDecayManager` | Tracks effectiveness decay over time |
| `challenge-difficulty-curve-engine.js` | `createDifficultyCurveEngine` | Adaptive difficulty scaling per user/session |
| `challenge-diversity-analyzer.js` | `createDiversityAnalyzer` | Ensures challenge sets have cognitive diversity |
| `challenge-template-engine.js` | `createTemplateEngine` | Template-based challenge generation |
| `challenge-genetics-lab.js` | `createGeneticsLab` | Genetic algorithm for evolving challenge parameters |
| `challenge-ecosystem-health.js` | `ChallengeEcosystemHealthEngine` | Holistic health scoring across the challenge pool |
| `challenge-autopilot.js` | `createChallengeAutopilot` | Autonomous challenge lifecycle management |
| `adaptive-difficulty-tuner.js` | `createAdaptiveDifficultyTuner` | Real-time difficulty adjustment per user risk level |

#### Security & Threat Intelligence

| Module | Export | Purpose |
|--------|--------|---------|
| `threat-intel-fusion.js` | `createThreatIntelFusion` | Fuses signals from multiple detection engines |
| `attack-evolution-tracker.js` | `createAttackEvolutionTracker` | Tracks how attack methods evolve over time |
| `geo-risk-scorer.js` | `createGeoRiskScorer` | Geographic risk scoring with O(1) country lookups |
| `captcha-replay-detector.js` | `CaptchaReplayDetector` | Detects replayed/reused CAPTCHA tokens |
| `honeypot-injector.js` | `createHoneypotInjector` | Injects honeypot challenges to trap bots |
| `deception-campaign-orchestrator.js` | `createDeceptionCampaign` | Orchestrates multi-stage deception campaigns |
| `defense-posture-optimizer.js` | `createDefensePostureOptimizer` | Pareto-optimal defense configuration tuning |

#### Session & Trust

| Module | Export | Purpose |
|--------|--------|---------|
| `trust-score-engine.js` | `createTrustScoreEngine` | Per-user trust scoring with decay and history |
| `session-risk-aggregator.js` | `createSessionRiskAggregator` | Aggregates risk signals across a session |
| `captcha-session-replay.js` | `createSessionReplay` | Records and replays solve sessions for analysis |
| `captcha-rate-limiter.js` | `createRateLimiter` | Token-bucket rate limiting per IP/session |

#### Monitoring & Analytics

| Module | Export | Purpose |
|--------|--------|---------|
| `captcha-stats-collector.js` | `createStatsCollector`, `percentile` | Real-time metrics collection and percentile computation |
| `captcha-health-monitor.js` | `createHealthMonitor` | System health checks and alerting |
| `captcha-anomaly-detector.js` | `createAnomalyDetector` | Statistical anomaly detection in solve patterns |
| `captcha-traffic-analyzer.js` | `createCaptchaTrafficAnalyzer` | Traffic pattern analysis and trending |
| `captcha-fatigue-detector.js` | `createFatigueDetector` | Detects user fatigue from repeated challenges |
| `captcha-load-tester.js` | `createCaptchaLoadTester` | Synthetic load generation for performance testing |
| `response-time-profiler.js` | `createResponseTimeProfiler` | Per-challenge response time distribution analysis |
| `solve-funnel-analyzer.js` | `createFunnelAnalyzer`, `STAGES` | Solve-attempt funnel with stage-level drop-off analysis |
| `ab-experiment-runner.js` | `createABExperimentRunner` | A/B experiment framework for challenge variants |
| `captcha-capacity-planner.js` | `createCapacityPlanner` | Forecasts infrastructure needs based on traffic |

#### Compliance & Operations

| Module | Export | Purpose |
|--------|--------|---------|
| `compliance-reporter.js` | `createComplianceReporter` | GDPR/CCPA/accessibility compliance reporting |
| `captcha-audit-log.js` | `createAuditLog`, `VALID_EVENTS`, `SEVERITY` | Immutable audit trail with severity levels |
| `captcha-incident-manager.js` | `createIncidentManager` | Incident lifecycle management (create/escalate/resolve) |
| `captcha-accessibility-analyzer.js` | `createAccessibilityAnalyzer` | WCAG compliance analysis for CAPTCHA challenges |
| `captcha-localization-manager.js` | `createLocalizationManager` | Per-locale string management and fallback |
| `webhook-dispatcher.js` | `createWebhookDispatcher` | Event-driven webhook delivery with retry and rate limiting |
| `captcha-strength-scorer.js` | `createStrengthScorer` | Composite strength scoring for challenge effectiveness |

### Front-End Pages (91 HTML files)

Beyond the three core pages, the project includes specialized dashboards and tools:

| Category | Pages | Examples |
|----------|-------|----------|
| **Core** | 3 | `index.html`, `demo.html`, `analysis.html` |
| **Bot Intelligence** | 8 | `bot-or-human.html`, `bot-signatures.html`, `fraud-rings.html`, `swarm-intelligence.html` |
| **Challenge Management** | 10 | `designer.html`, `generator.html`, `gallery.html`, `mutation-lab.html`, `escape-room.html` |
| **Analytics & Dashboards** | 12 | `dashboard.html`, `heatmap.html`, `funnel.html`, `benchmark.html`, `daily.html` |
| **Security & Threat** | 9 | `threat-radar.html`, `threat-feed.html`, `immune-system.html`, `honeypot-designer.html` |
| **Operations** | 8 | `queue-manager.html`, `fleet.html`, `config.html`, `audit-log.html`, `compliance.html` |
| **Testing & Profiling** | 7 | `load-tester.html`, `performance-profiler.html`, `ab-test-dashboard.html`, `simulator.html` |
| **Trust & Sessions** | 6 | `trust-dashboard.html`, `trust-network.html`, `session-replay.html`, `journey-map.html` |
| **Research & Docs** | 5 | `research-paper.html`, `cognitive-load.html`, `cognitive-fingerprint.html`, `comparison.html` |
| **Other** | 23 | `embed.html`, `playground.html`, `directory.html`, `theme-builder.html`, etc. |

Each page is self-contained (inline CSS/JS) and follows the same dark-theme design system. When modifying shared visual elements (color variables, navigation), check all pages for consistency.

## Coding Standards

### HTML

- Use semantic elements (`<header>`, `<nav>`, `<main>`, `<section>`, `<footer>`)
- Maintain proper heading hierarchy (`h1` → `h2` → `h3`)
- Include `alt` attributes on images
- Keep Content-Security-Policy meta tags consistent across pages

### CSS

- Use CSS custom properties from `:root` — don't hardcode color values
- Follow existing naming conventions (`.finding`, `.badge`, `.tag-{category}`)
- Support responsive breakpoints at 768px and 480px
- Maintain accessible contrast ratios (WCAG AA minimum)

### JavaScript

- Use `var` declarations (for consistency with existing code and broad compatibility)
- No external libraries or CDN imports
- Follow the existing data-driven pattern: define data arrays/objects, then render from them
- Use `sanitize()` helper for user-generated content to prevent XSS

### Content-Security-Policy

All pages enforce strict CSP via `<meta>` tags:
- `style-src 'unsafe-inline'` — inline styles only
- `script-src 'unsafe-inline'` — inline scripts only (demo.html and analysis.html)
- `img-src https:` — HTTPS images only
- `frame-ancestors 'none'` — no iframe embedding

Don't add external script or stylesheet sources — they'll be blocked.

## Submitting Changes

### Testing Requirements

The test suite has **120+ test files** covering all `src/` modules. Before submitting:

1. **Run the full suite**: `npm test` — all tests must pass
2. **Check coverage**: `npm run test:coverage` — thresholds enforced (80% lines, 70% functions, 90% branches)
3. **New modules require tests**: Add `tests/<module-name>.test.js` for any new `src/` module
4. **Test naming**: Use descriptive `test()` or `describe()` blocks matching the module's public API surface
5. **DOM tests**: Use `jsdom` (already a dev dependency) for any front-end DOM interaction tests

See [TESTING.md](TESTING.md) for the full testing guide, conventions, and coverage gap inventory.

### Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b your-feature`
3. **Make your changes** following the coding standards above
4. **Run tests**: `npm test` — all tests must pass
5. **Validate HTML**: `npx htmlhint index.html demo.html analysis.html`
6. **Test visually**: Open all three pages, check responsive layouts
6. **Commit** with a clear message: `git commit -m "Add temporal analysis chart to analysis dashboard"`
7. **Push** and open a Pull Request

### PR Guidelines

- Keep PRs focused — one feature or fix per PR
- Include screenshots for visual changes
- Describe what you changed and why
- If adding new research data, cite your sources

### Branch Protection Policy

The `main` branch is the only long-lived branch and is protected with the following rules (configured via the GitHub API):

| Rule | Setting | Why |
|------|---------|-----|
| `required_linear_history` | **on** | History stays bisectable — no merge commits, squash or rebase only. |
| `required_conversation_resolution` | **on** | Every PR review comment must be resolved before merge, so reviewer concerns are never silently dropped. |
| `allow_force_pushes` | **off** | Published history is immutable — releases pinned to a commit can't be silently rewritten. |
| `allow_deletions` | **off** | Prevents accidental branch deletion. |

If you propose changing this policy, open an issue first — these rules are part of the supply-chain story for the published npm package.

### Commit Messages

Use clear, descriptive commit messages:
- `Fix broken Tenor GIF URL for duel challenge`
- `Add GPT-4o benchmark results to comparison table`
- `Improve radar chart accessibility with ARIA labels`

## Research Contributions

If you've tested the GIF CAPTCHAs against a new AI model:

1. **Open an issue** using the "Research Question" template
2. Include:
   - Model name and version
   - Date of testing
   - Results for each of the 10 GIFs (pass/fail + model response)
   - Any interesting observations
3. We'll review the data and potentially add it to the analysis dashboard

### Adding New GIF Test Cases

When proposing new GIFs for the test suite:

1. The GIF must contain a **clear unexpected event** requiring temporal comprehension
2. Categorize it using the existing taxonomy (Narrative Twist, Physical Comedy, Animal Behavior, Visual Trick, Social Subversion, Optical Illusion) or propose a new category
3. Provide the human baseline description
4. Test against at least one AI model and include results
5. Host the GIF on a reliable CDN (Giphy, Tenor) for longevity

---

## Security Vulnerabilities

**Do NOT open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions, scope, and response timelines.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code — be kind, constructive, and respectful. Report unacceptable behavior to [@sauravbhattacharya001](https://github.com/sauravbhattacharya001).

## Questions?

Open an issue or start a discussion. We're happy to help!
