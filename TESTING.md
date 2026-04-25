# Testing Guide

Comprehensive testing guide for gif-captcha. The project has **96 test files** covering all modules — from core utilities to security engines, challenge management, and analytics.

## Quick Start

```bash
# Install dependencies
npm install

# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Check coverage thresholds (80% lines, 70% functions, 90% branches)
npm run coverage:check
```

## Test Runner

Tests use Node.js's built-in test runner (`node:test`) — no external test framework required. Test files follow the pattern `tests/<module>.test.js`.

```bash
# Run a specific test file
node --test tests/trust-score-engine.test.js

# Run tests matching a pattern
node --test tests/captcha-*.test.js

# Run with verbose output
node --test --test-reporter=spec tests/fraud-ring-detector.test.js
```

## Coverage

Coverage is measured with [c8](https://github.com/bcoe/c8):

```bash
# Text summary + LCOV + JSON
npm run test:coverage

# Reports are generated in:
#   ./coverage/lcov-report/index.html   (browsable HTML)
#   ./coverage/lcov.info                (for CI upload)
#   ./coverage/coverage-summary.json    (for badges)
```

**Thresholds** (enforced by `npm run coverage:check`):

| Metric    | Threshold |
|-----------|-----------|
| Lines     | 80%       |
| Functions | 70%       |
| Branches  | 90%       |

## Test Organization

Tests are organized by module area. Each source file in `src/` has a corresponding test file in `tests/`.

### Core & Utilities

| Test File | Module | What It Tests |
|-----------|--------|---------------|
| `index.test.js` | `index.js` | Main entry point, page structure, results table |
| `shared-utils.test.js` | `shared-utils.js` | LRU tracker, clamping, timestamp helpers |
| `crypto-utils.test.js` | `crypto-utils.js` | HMAC generation, token signing, secure random |
| `config-validator.test.js` | `config-validator.js` | Schema validation, defaults, type checking |
| `csv-utils.test.js` | `csv-utils.js` | CSV parsing, escaping, export formatting |
| `core-edge-cases.test.js` | Various | Edge cases across core modules |

### Security & Trust

| Test File | Module | What It Tests |
|-----------|--------|---------------|
| `trust-score-engine.test.js` | `trust-score-engine.js` | Score computation, decay, factor weighting |
| `trust-score-engine-edge.test.js` | `trust-score-engine.js` | Edge cases, boundary conditions |
| `behavioral-biometrics.test.js` | `behavioral-biometrics.js` | Mouse/keyboard pattern analysis |
| `behavioral-biometrics-edge.test.js` | `behavioral-biometrics.js` | Edge cases in biometric analysis |
| `bot-signature-database.test.js` | `bot-signature-database.js` | Known bot pattern matching |
| `bot-detector.test.js` | Client-side detection | Bot fingerprinting and scoring |
| `fraud-ring-detector.test.js` | `fraud-ring-detector.js` | Ring detection, graph analysis, import/export |
| `captcha-replay-detector.test.js` | `captcha-replay-detector.js` | Token reuse prevention |
| `honeypot-injector.test.js` | `honeypot-injector.js` | Hidden field injection, trap detection |
| `solve-pattern-fingerprinter.test.js` | `solve-pattern-fingerprinter.js` | Solve behavior clustering |
| `geo-risk-scorer.test.js` | `geo-risk-scorer.js` | Country/IP risk scoring |
| `geo-risk-scorer-extended.test.js` | `geo-risk-scorer.js` | VPN, proxy, and Tor detection |
| `session-risk-aggregator.test.js` | `session-risk-aggregator.js` | Cross-signal risk aggregation |
| `captcha-rate-limiter.test.js` | `captcha-rate-limiter.js` | Rate limiting, sliding windows |
| `security-scorer.test.js` | Security scoring | Overall security posture scoring |
| `security-hardening.test.js` | Hardening | Input sanitization, XSS prevention |
| `token-verifier.test.js` | Token verification | CAPTCHA token validity |

### Challenge Management

| Test File | Module | What It Tests |
|-----------|--------|---------------|
| `challenge-pool-manager.test.js` | `challenge-pool-manager.js` | Pool sizing, eviction, refresh |
| `pool-manager.test.js` | Pool management | Basic pool operations |
| `pool-manager-extended.test.js` | Pool management | Advanced pool scenarios |
| `challenge-rotation-scheduler.test.js` | `challenge-rotation-scheduler.js` | Scheduled rotation, staleness |
| `challenge-template-engine.test.js` | `challenge-template-engine.js` | Template rendering, variable substitution |
| `challenge-diversity-analyzer.test.js` | `challenge-diversity-analyzer.js` | Diversity metrics, entropy |
| `challenge-decay-manager.test.js` | `challenge-decay-manager.js` | Challenge expiry, TTL management |
| `challenge-analytics.test.js` | Challenge analytics | Solve rates, timing distributions |
| `challenge-router.test.js` | Challenge routing | Difficulty-based routing |
| `attempt-tracker.test.js` | Attempt tracking | Retry limits, lockout |
| `adaptive-difficulty-tuner.test.js` | `adaptive-difficulty-tuner.js` | Dynamic difficulty adjustment |

### Analytics & Monitoring

| Test File | Module | What It Tests |
|-----------|--------|---------------|
| `captcha-stats-collector.test.js` | `captcha-stats-collector.js` | Metrics collection, aggregation |
| `captcha-traffic-analyzer.test.js` | `captcha-traffic-analyzer.js` | Traffic patterns, anomalies |
| `captcha-anomaly-detector.test.js` | `captcha-anomaly-detector.js` | Statistical anomaly detection |
| `solve-funnel-analyzer.test.js` | `solve-funnel-analyzer.js` | Conversion funnel analysis |
| `response-time-profiler.test.js` | `response-time-profiler.js` | Latency percentiles, profiling |
| `captcha-health-monitor.test.js` | `captcha-health-monitor.js` | Health checks, uptime tracking |
| `heatmap.test.js` | Heatmap | Click/interaction heatmaps |
| `metrics-aggregator.test.js` | Metrics | Cross-module metric aggregation |

### Operations & Infrastructure

| Test File | Module | What It Tests |
|-----------|--------|---------------|
| `captcha-incident-manager.test.js` | `captcha-incident-manager.js` | Incident lifecycle, escalation |
| `captcha-capacity-planner.test.js` | `captcha-capacity-planner.js` | Load forecasting, scaling |
| `captcha-load-tester.test.js` | `captcha-load-tester.js` | Synthetic load generation |
| `captcha-audit-log.test.js` | `captcha-audit-log.js` | Audit trail, compliance logging |
| `captcha-export-formatter.test.js` | `captcha-export-formatter.js` | Data export (JSON, CSV, PDF) |
| `captcha-session-replay.test.js` | `captcha-session-replay.js` | Session recording, playback |
| `webhook-dispatcher.test.js` | `webhook-dispatcher.js` | Event webhook delivery, retries |
| `compliance-reporter.test.js` | `compliance-reporter.js` | GDPR/regulatory compliance |
| `captcha-fatigue-detector.test.js` | `captcha-fatigue-detector.js` | User fatigue patterns |

### Accessibility & Internationalization

| Test File | Module | What It Tests |
|-----------|--------|---------------|
| `captcha-accessibility-analyzer.test.js` | `captcha-accessibility-analyzer.js` | WCAG compliance analysis |
| `captcha-localization-manager.test.js` | `captcha-localization-manager.js` | Multi-language support |
| `accessibility.test.js` | Accessibility | Screen reader, keyboard nav |
| `accessibility-auditor.test.js` | Accessibility audit | ARIA attributes, contrast |
| `cognitive-load.test.js` | Cognitive load | Mental effort estimation |
| `i18n.test.js` | `i18n.js` | Internationalization |
| `i18n-extended.test.js` | `i18n.js` | RTL, pluralization, fallbacks |

### Integration & Performance

| Test File | Module | What It Tests |
|-----------|--------|---------------|
| `integration.test.js` | Full pipeline | End-to-end CAPTCHA flow |
| `benchmark.test.js` | Performance | Throughput, memory, latency |
| `perf-caching.test.js` | Caching | Cache hit rates, eviction |
| `demo.test.js` | Demo page | Demo page functionality |
| `simulator.test.js` | Simulation | Attack simulation scenarios |

## Writing Tests

### Conventions

1. **File naming**: `tests/<source-module-name>.test.js`
2. **Import pattern**: Use `node:test` and `node:assert`
3. **Structure**: Use `describe()` for grouping, `it()` for individual cases
4. **No mocks framework**: Tests use plain JS stubs or the modules directly

### Example Test

```js
const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { createSomeModule } = require('../src/some-module');

describe('SomeModule', () => {
  let instance;

  beforeEach(() => {
    instance = createSomeModule({ /* config */ });
  });

  it('should handle the happy path', () => {
    const result = instance.doThing('input');
    assert.strictEqual(result.status, 'ok');
  });

  it('should reject invalid input', () => {
    assert.throws(() => instance.doThing(null), {
      message: /invalid input/i,
    });
  });

  it('should handle edge cases', () => {
    const result = instance.doThing('');
    assert.strictEqual(result.status, 'empty');
  });
});
```

### What to Test

- **Happy path**: Normal inputs produce expected outputs
- **Edge cases**: Empty inputs, boundary values, very large inputs
- **Error handling**: Invalid inputs throw or return error states
- **State management**: LRU eviction, TTL expiry, counter overflow
- **Concurrency**: Multiple rapid calls don't corrupt shared state
- **Security**: Injection attempts, overflow, prototype pollution

## CI Integration

Tests run automatically on every push and PR via GitHub Actions (`.github/workflows/ci.yml`). Coverage results are uploaded to Codecov.

The CI pipeline:
1. Installs dependencies (`npm ci`)
2. Runs linting
3. Runs the full test suite with coverage
4. Checks coverage thresholds
5. Uploads coverage to Codecov
