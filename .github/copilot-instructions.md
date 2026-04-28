# Copilot Instructions for gif-captcha

## Project Overview

**GIF CAPTCHA** is a dual-purpose project:

1. **Node.js SDK** (`src/`, `bin/`) — A full-featured CAPTCHA security library with 40+ modules covering rate limiting, bot detection, behavioral biometrics, fraud detection, compliance reporting, and challenge management.
2. **Static research site** (root HTML pages, `docs/`) — 60+ self-contained HTML pages including the original research case study, interactive demos, dashboards, and analysis tools. Deployed via GitHub Pages.

## Architecture

### Node.js SDK (`src/`)

The SDK is organized as 40+ independent modules following a consistent pattern:

```
src/
├── index.js                      # Main entry point — exports all public modules
├── shared-utils.js               # Shared utilities (LruTracker, _clamp, _now, etc.)
├── captcha-rate-limiter.js       # Token bucket + leaky bucket rate limiting
├── trust-score-engine.js         # Multi-signal trust scoring with LRU eviction
├── session-risk-aggregator.js    # Weighted risk signal aggregation per session
├── behavioral-biometrics.js      # Keystroke/mouse/touch behavioral analysis
├── bot-signature-database.js     # Known bot signature matching
├── fraud-ring-detector.js        # Graph-based fraud ring detection
├── geo-risk-scorer.js            # IP geolocation risk assessment
├── captcha-anomaly-detector.js   # Statistical anomaly detection
├── captcha-health-monitor.js     # System health monitoring with alert rules
├── captcha-audit-log.js          # Tamper-evident audit logging
├── compliance-reporter.js        # GDPR/CCPA compliance report generation
├── captcha-incident-manager.js   # Security incident lifecycle management
├── solve-funnel-analyzer.js      # Conversion funnel analysis with LRU eviction
├── captcha-load-tester.js        # Load testing with concurrent request simulation
├── captcha-stats-collector.js    # Metrics collection and aggregation
├── webhook-dispatcher.js         # Webhook notification delivery with retries
├── challenge-pool-manager.js     # Challenge pool lifecycle and rotation
├── challenge-rotation-scheduler.js # Time-based challenge rotation
├── challenge-decay-manager.js    # Challenge difficulty decay over time
├── challenge-template-engine.js  # Template-based challenge generation
├── challenge-autopilot.js        # Autonomous challenge management
├── challenge-diversity-analyzer.js # Challenge set diversity metrics
├── ab-experiment-runner.js       # A/B testing experiment framework
├── adaptive-difficulty-tuner.js  # Real-time difficulty adjustment
├── captcha-capacity-planner.js   # Capacity planning and forecasting
├── captcha-fatigue-detector.js   # User fatigue detection
├── captcha-replay-detector.js    # Replay attack detection
├── captcha-session-replay.js     # Session replay recording
├── solve-pattern-fingerprinter.js # Solve pattern fingerprinting
├── captcha-strength-scorer.js    # Challenge strength scoring
├── captcha-traffic-analyzer.js   # Traffic pattern analysis
├── captcha-export-formatter.js   # Data export (CSV, JSON, etc.)
├── captcha-accessibility-analyzer.js # Accessibility compliance analysis
├── captcha-localization-manager.js # i18n/l10n management
├── config-validator.js           # Configuration schema validation
├── crypto-utils.js               # Cryptographic utilities (HMAC, timing-safe compare)
├── csv-utils.js                  # CSV parsing and generation
├── honeypot-injector.js          # Honeypot field injection
├── i18n.js                       # Internationalization strings
└── response-time-profiler.js     # Response time distribution profiling
```

### Key Patterns

- **Module pattern**: Each `src/*.js` file exports a class or factory function via `module.exports`
- **No external runtime deps**: The SDK has zero production dependencies — only `c8` and `jsdom` as dev deps
- **Shared utilities**: Common code (LRU, clamping, timestamps) lives in `shared-utils.js` — import from there, don't duplicate
- **Constructor validation**: Modules validate constructor options and throw `TypeError`/`RangeError` for invalid config
- **Bounded memory**: Modules with growing state use LRU eviction, `maxSessions`, `maxRecords`, or similar caps
- **Immutable returns**: Public methods return copies (`.slice()`, spread) rather than internal references

### Static Site (HTML pages)

- **60+ self-contained HTML pages** in the project root and `docs/`
- Each page includes its own `<style>` and `<script>` — no external CSS/JS dependencies
- Dark theme (GitHub-inspired) using CSS custom properties
- Canvas 2D API for charts and visualizations
- CSP meta tags block external script loading by design
- JavaScript uses `var` declarations for browser compatibility

### CLI (`bin/gif-captcha.js`)

A command-line interface wrapping the SDK for batch operations, health checks, and report generation.

## Testing

```bash
# Run all tests (node:test built-in runner — NO jest/mocha)
node --test tests/*.test.js

# Run with coverage
npm run test:coverage

# Run a specific test file
node --test tests/captcha-rate-limiter.test.js

# Syntax-check a source file
node -c src/some-module.js
```

**Test framework**: Node.js built-in `node:test` with `node:assert`. NOT Jest. NOT Mocha.

**Test conventions**:
- Test files: `tests/<module-name>.test.js`
- Use `const { describe, it, beforeEach } = require('node:test')`
- Use `const assert = require('node:assert/strict')`
- Each test file imports its module directly: `const MyModule = require('../src/my-module.js')`
- Tests are pure unit tests — no network, no filesystem, no timers
- ~3300 tests across ~100 test files; ~3100 passing (some pre-existing failures)

**Pre-existing failures**: Some tests fail due to known issues. Your changes must not introduce NEW failures. Run the relevant test file before and after your changes to verify.

## npm Scripts

| Script | Command | Purpose |
|--------|---------|---------|
| `test` | `node --test tests/*.test.js` | Run all tests |
| `test:coverage` | `c8 ... node --test tests/*.test.js` | Tests with coverage report |
| `coverage` | `c8 ... node --test tests/*.test.js` | Coverage (text + lcov) |
| `coverage:check` | `c8 check-coverage --lines 80 --functions 70 --branches 90` | Enforce coverage thresholds |

## Code Style & Conventions

### JavaScript (SDK)
- CommonJS modules (`require`/`module.exports`)
- `'use strict'` at top of each file
- Constructor functions or ES6 classes — both patterns exist
- Prefer descriptive variable names; prefix private members with `_`
- JSDoc comments on public methods
- No semicolon style varies — follow the existing file's convention
- Error handling: throw typed errors (`TypeError`, `RangeError`) for invalid inputs

### JavaScript (HTML pages)
- `var` declarations (browser compatibility)
- Inline `<script>` blocks — no external files
- Canvas 2D API for charts (include `roundRect` polyfill)

### CSS (HTML pages)
- CSS custom properties in `:root` for theming
- Responsive breakpoints at 768px and 480px
- BEM-ish class naming: `.finding`, `.badge-pass`, `.tag-security`

## When Making Changes

### SDK changes (`src/`)
1. **Check existing tests**: Run `node --test tests/<module>.test.js` before AND after changes
2. **Add tests for new code**: New public methods need tests in the corresponding test file
3. **Syntax-check**: `node -c src/<file>.js` before committing
4. **Import from shared-utils**: Don't duplicate LRU, clamping, or timestamp logic
5. **Bound memory growth**: Any new data structure that grows must have eviction/cap
6. **No new deps**: The SDK must remain zero-dependency for production

### HTML page changes
1. **Self-contained**: Don't add external CSS/JS — CSP blocks it
2. **Dark theme**: Use existing CSS variables from `:root`
3. **Validate**: `npx htmlhint <page>.html`
4. **Responsive**: Test at 480px, 768px, and desktop widths
5. **Use `var`**: Follow existing JavaScript convention in HTML pages

### General
- Run `node --test tests/*.test.js` to verify no new failures introduced
- Commit messages: conventional commits preferred (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`)
- Keep the Docker build working: `docker build -t gif-captcha-test .`
