'use strict';

var gifCaptcha = require('../src/index');
var createComplianceReporter = gifCaptcha.createComplianceReporter;

describe('createComplianceReporter', function () {

  var reporter;

  beforeEach(function () {
    reporter = createComplianceReporter();
  });

  // ── Factory ─────────────────────────────────────────────────────

  test('returns object with expected methods', function () {
    expect(typeof reporter.generateReport).toBe('function');
    expect(typeof reporter.getRecommendedConfig).toBe('function');
    expect(typeof reporter.compareReports).toBe('function');
    expect(typeof reporter.formatReportText).toBe('function');
  });

  test('exposes SEVERITY and CATEGORY constants', function () {
    expect(reporter.SEVERITY.CRITICAL).toBe('critical');
    expect(reporter.SEVERITY.PASS).toBe('pass');
    expect(reporter.CATEGORY.ACCESSIBILITY).toBe('accessibility');
    expect(reporter.CATEGORY.SECURITY).toBe('security');
  });

  test('custom options are respected', function () {
    var custom = createComplianceReporter({
      systemName: 'my-captcha',
      maxDataRetentionDays: 7,
      minSolveRatePercent: 80
    });
    var report = custom.generateReport({ dataRetentionDays: 10 });
    // 10 days exceeds 7-day limit
    var prv001 = report.findings.find(function (f) { return f.id === 'PRV-001'; });
    expect(prv001.severity).toBe('warning');
    expect(report.system).toBe('my-captcha');
  });

  // ── generateReport ──────────────────────────────────────────────

  describe('generateReport', function () {

    test('returns valid report structure', function () {
      var report = reporter.generateReport();
      expect(report).toHaveProperty('system');
      expect(report).toHaveProperty('generatedAt');
      expect(report).toHaveProperty('overallScore');
      expect(report).toHaveProperty('grade');
      expect(report).toHaveProperty('totalFindings');
      expect(report).toHaveProperty('passed');
      expect(report).toHaveProperty('criticals');
      expect(report).toHaveProperty('warnings');
      expect(report).toHaveProperty('categoryScores');
      expect(report).toHaveProperty('findings');
      expect(Array.isArray(report.findings)).toBe(true);
    });

    test('default config scores poorly', function () {
      var report = reporter.generateReport({}, {});
      expect(report.overallScore).toBeLessThan(50);
      expect(report.criticals).toBeGreaterThan(0);
    });

    test('recommended config scores well', function () {
      var config = reporter.getRecommendedConfig();
      var metrics = {
        totalChallenges: 1000,
        totalSolves: 850,
        totalFailures: 100,
        avgSolveTimeMs: 8000,
        p95SolveTimeMs: 25000,
        botAttempts: 200,
        botBlocked: 195,
        uptimePercent: 99.9,
        avgResponseTimeMs: 120,
        errorCount: 2
      };
      var report = reporter.generateReport(config, metrics);
      expect(report.overallScore).toBeGreaterThanOrEqual(90);
      expect(report.grade).toBe('A');
      expect(report.criticals).toBe(0);
    });

    test('all findings have required properties', function () {
      var report = reporter.generateReport();
      report.findings.forEach(function (f) {
        expect(f).toHaveProperty('id');
        expect(f).toHaveProperty('category');
        expect(f).toHaveProperty('title');
        expect(f).toHaveProperty('description');
        expect(f).toHaveProperty('severity');
      });
    });

    test('generatedAt is valid ISO timestamp', function () {
      var report = reporter.generateReport();
      expect(new Date(report.generatedAt).toISOString()).toBe(report.generatedAt);
    });

    // ── Accessibility checks ────────────────────────────────────

    test('ACC-001: audioAlternative true = pass', function () {
      var report = reporter.generateReport({ audioAlternative: true });
      var f = report.findings.find(function (x) { return x.id === 'ACC-001'; });
      expect(f.severity).toBe('pass');
    });

    test('ACC-001: audioAlternative false = critical', function () {
      var report = reporter.generateReport({ audioAlternative: false });
      var f = report.findings.find(function (x) { return x.id === 'ACC-001'; });
      expect(f.severity).toBe('critical');
    });

    test('ACC-002: keyboard navigable', function () {
      var report = reporter.generateReport({ keyboardNavigable: true });
      var f = report.findings.find(function (x) { return x.id === 'ACC-002'; });
      expect(f.severity).toBe('pass');
    });

    test('ACC-003: ariaLabel present = pass', function () {
      var report = reporter.generateReport({ ariaLabel: 'CAPTCHA' });
      var f = report.findings.find(function (x) { return x.id === 'ACC-003'; });
      expect(f.severity).toBe('pass');
    });

    test('ACC-004: high contrast = pass', function () {
      var report = reporter.generateReport({ colorContrast: 7.0 });
      var f = report.findings.find(function (x) { return x.id === 'ACC-004'; });
      expect(f.severity).toBe('pass');
    });

    test('ACC-004: low contrast = critical', function () {
      var report = reporter.generateReport({ colorContrast: 2.0 });
      var f = report.findings.find(function (x) { return x.id === 'ACC-004'; });
      expect(f.severity).toBe('critical');
    });

    test('ACC-004: borderline contrast = warning', function () {
      var report = reporter.generateReport({ colorContrast: 3.5 });
      var f = report.findings.find(function (x) { return x.id === 'ACC-004'; });
      expect(f.severity).toBe('warning');
    });

    test('ACC-005: time limit with extend = pass', function () {
      var report = reporter.generateReport({ timeLimitMs: 30000, canExtendTime: true });
      var f = report.findings.find(function (x) { return x.id === 'ACC-005'; });
      expect(f.severity).toBe('pass');
    });

    test('ACC-005: time limit without extend = warning', function () {
      var report = reporter.generateReport({ timeLimitMs: 30000, canExtendTime: false });
      var f = report.findings.find(function (x) { return x.id === 'ACC-005'; });
      expect(f.severity).toBe('warning');
    });

    test('ACC-006: 3+ languages = pass', function () {
      var report = reporter.generateReport({ supportedLanguages: ['en', 'es', 'fr'] });
      var f = report.findings.find(function (x) { return x.id === 'ACC-006'; });
      expect(f.severity).toBe('pass');
    });

    test('ACC-006: 1 language = info', function () {
      var report = reporter.generateReport({ supportedLanguages: ['en'] });
      var f = report.findings.find(function (x) { return x.id === 'ACC-006'; });
      expect(f.severity).toBe('info');
    });

    // ── Privacy checks ──────────────────────────────────────────

    test('PRV-001: retention within limit = pass', function () {
      var report = reporter.generateReport({ dataRetentionDays: 14 });
      var f = report.findings.find(function (x) { return x.id === 'PRV-001'; });
      expect(f.severity).toBe('pass');
    });

    test('PRV-001: no retention policy = critical', function () {
      var report = reporter.generateReport({});
      var f = report.findings.find(function (x) { return x.id === 'PRV-001'; });
      expect(f.severity).toBe('critical');
    });

    test('PRV-001: retention exceeds limit = warning', function () {
      var report = reporter.generateReport({ dataRetentionDays: 90 });
      var f = report.findings.find(function (x) { return x.id === 'PRV-001'; });
      expect(f.severity).toBe('warning');
    });

    test('PRV-002: consent required = pass', function () {
      var report = reporter.generateReport({ consentRequired: true });
      var f = report.findings.find(function (x) { return x.id === 'PRV-002'; });
      expect(f.severity).toBe('pass');
    });

    test('PRV-004: deletion supported = pass', function () {
      var report = reporter.generateReport({ deletionSupported: true });
      var f = report.findings.find(function (x) { return x.id === 'PRV-004'; });
      expect(f.severity).toBe('pass');
    });

    test('PRV-004: no deletion = critical', function () {
      var report = reporter.generateReport({ deletionSupported: false });
      var f = report.findings.find(function (x) { return x.id === 'PRV-004'; });
      expect(f.severity).toBe('critical');
    });

    // ── Security checks ─────────────────────────────────────────

    test('SEC-001: rate limit enabled = pass', function () {
      var report = reporter.generateReport({ rateLimitEnabled: true });
      var f = report.findings.find(function (x) { return x.id === 'SEC-001'; });
      expect(f.severity).toBe('pass');
    });

    test('SEC-002: token signed = pass', function () {
      var report = reporter.generateReport({ tokenSigned: true });
      var f = report.findings.find(function (x) { return x.id === 'SEC-002'; });
      expect(f.severity).toBe('pass');
    });

    test('SEC-003: httpsOnly = pass', function () {
      var report = reporter.generateReport({ httpsOnly: true });
      var f = report.findings.find(function (x) { return x.id === 'SEC-003'; });
      expect(f.severity).toBe('pass');
    });

    test('SEC-005: max attempts 5 = pass', function () {
      var report = reporter.generateReport({ maxAttempts: 5 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-005'; });
      expect(f.severity).toBe('pass');
    });

    test('SEC-005: max attempts 20 = warning', function () {
      var report = reporter.generateReport({ maxAttempts: 20 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-005'; });
      expect(f.severity).toBe('warning');
    });

    test('SEC-005: no attempt limit = critical', function () {
      var report = reporter.generateReport({ maxAttempts: 0 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-005'; });
      expect(f.severity).toBe('critical');
    });

    test('SEC-007: good bot block rate = pass', function () {
      var report = reporter.generateReport({}, { botAttempts: 100, botBlocked: 95 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-007'; });
      expect(f.severity).toBe('pass');
    });

    test('SEC-007: poor bot block rate = critical', function () {
      var report = reporter.generateReport({}, { botAttempts: 100, botBlocked: 50 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-007'; });
      expect(f.severity).toBe('critical');
    });

    test('SEC-007: no bot data = info', function () {
      var report = reporter.generateReport({}, { botAttempts: 0, botBlocked: 0 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-007'; });
      expect(f.severity).toBe('info');
    });

    // ── Operational checks ──────────────────────────────────────

    test('OPS-001: good solve rate = pass', function () {
      var report = reporter.generateReport({}, { totalChallenges: 100, totalSolves: 85 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-001'; });
      expect(f.severity).toBe('pass');
    });

    test('OPS-001: poor solve rate = critical', function () {
      var report = reporter.generateReport({}, { totalChallenges: 100, totalSolves: 40 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-001'; });
      expect(f.severity).toBe('critical');
    });

    test('OPS-003: fast solve time = pass', function () {
      var report = reporter.generateReport({}, { avgSolveTimeMs: 5000 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-003'; });
      expect(f.severity).toBe('pass');
    });

    test('OPS-003: slow solve time = critical', function () {
      var report = reporter.generateReport({}, { avgSolveTimeMs: 120000 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-003'; });
      expect(f.severity).toBe('critical');
    });

    test('OPS-005: high uptime = pass', function () {
      var report = reporter.generateReport({}, { uptimePercent: 99.9 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-005'; });
      expect(f.severity).toBe('pass');
    });

    test('OPS-005: low uptime = critical', function () {
      var report = reporter.generateReport({}, { uptimePercent: 95 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-005'; });
      expect(f.severity).toBe('critical');
    });

    test('OPS-006: fast response = pass', function () {
      var report = reporter.generateReport({}, { avgResponseTimeMs: 100 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-006'; });
      expect(f.severity).toBe('pass');
    });

    test('OPS-007: low error rate = pass', function () {
      var report = reporter.generateReport({}, { totalChallenges: 10000, errorCount: 5 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-007'; });
      expect(f.severity).toBe('pass');
    });

    test('OPS-007: high error rate = critical', function () {
      var report = reporter.generateReport({}, { totalChallenges: 100, errorCount: 10 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-007'; });
      expect(f.severity).toBe('critical');
    });

    // ── Scoring ─────────────────────────────────────────────────

    test('grade A for score >= 90', function () {
      var config = reporter.getRecommendedConfig();
      var metrics = {
        totalChallenges: 1000, totalSolves: 900, totalFailures: 50,
        avgSolveTimeMs: 5000, p95SolveTimeMs: 15000,
        botAttempts: 100, botBlocked: 98,
        uptimePercent: 99.9, avgResponseTimeMs: 100, errorCount: 1
      };
      var report = reporter.generateReport(config, metrics);
      expect(report.grade).toBe('A');
    });

    test('category scores are 0-100', function () {
      var report = reporter.generateReport();
      var cats = ['accessibility', 'privacy', 'security', 'operational'];
      cats.forEach(function (cat) {
        expect(report.categoryScores[cat].score).toBeGreaterThanOrEqual(0);
        expect(report.categoryScores[cat].score).toBeLessThanOrEqual(100);
      });
    });

    test('findings count matches totals', function () {
      var report = reporter.generateReport();
      var counted = report.passed + report.criticals + report.warnings;
      // Some might be INFO
      expect(counted).toBeLessThanOrEqual(report.totalFindings);
    });
  });

  // ── getRecommendedConfig ────────────────────────────────────────

  describe('getRecommendedConfig', function () {

    test('returns complete config object', function () {
      var config = reporter.getRecommendedConfig();
      expect(config.audioAlternative).toBe(true);
      expect(config.keyboardNavigable).toBe(true);
      expect(config.tokenSigned).toBe(true);
      expect(config.httpsOnly).toBe(true);
      expect(config.rateLimitEnabled).toBe(true);
      expect(config.maxAttempts).toBe(5);
    });

    test('recommended config passes all checks when metrics are good', function () {
      var config = reporter.getRecommendedConfig();
      var metrics = {
        totalChallenges: 500, totalSolves: 400, totalFailures: 50,
        avgSolveTimeMs: 8000, p95SolveTimeMs: 20000,
        botAttempts: 50, botBlocked: 48,
        uptimePercent: 99.95, avgResponseTimeMs: 80, errorCount: 0
      };
      var report = reporter.generateReport(config, metrics);
      expect(report.criticals).toBe(0);
    });

    test('respects custom maxDataRetentionDays', function () {
      var custom = createComplianceReporter({ maxDataRetentionDays: 7 });
      var config = custom.getRecommendedConfig();
      expect(config.dataRetentionDays).toBe(7);
    });
  });

  // ── compareReports ──────────────────────────────────────────────

  describe('compareReports', function () {

    test('detects improvements', function () {
      var oldReport = reporter.generateReport({}, {});
      var config = reporter.getRecommendedConfig();
      var newReport = reporter.generateReport(config, {
        totalChallenges: 100, totalSolves: 85, totalFailures: 10,
        botAttempts: 50, botBlocked: 48, uptimePercent: 99.9,
        avgResponseTimeMs: 100, errorCount: 0, avgSolveTimeMs: 5000, p95SolveTimeMs: 15000
      });

      var diff = reporter.compareReports(oldReport, newReport);
      expect(diff.improved).toBeGreaterThan(0);
      expect(diff.newScore).toBeGreaterThan(diff.oldScore);
      expect(diff.scoreDelta).toBeGreaterThan(0);
    });

    test('detects regressions', function () {
      var config = reporter.getRecommendedConfig();
      var goodReport = reporter.generateReport(config, {
        totalChallenges: 100, totalSolves: 85, totalFailures: 10,
        botAttempts: 50, botBlocked: 48, uptimePercent: 99.9,
        avgResponseTimeMs: 100, errorCount: 0, avgSolveTimeMs: 5000, p95SolveTimeMs: 15000
      });
      var badReport = reporter.generateReport({}, {});

      var diff = reporter.compareReports(goodReport, badReport);
      expect(diff.regressed).toBeGreaterThan(0);
      expect(diff.scoreDelta).toBeLessThan(0);
    });

    test('handles identical reports', function () {
      var report = reporter.generateReport({ audioAlternative: true });
      var diff = reporter.compareReports(report, report);
      expect(diff.improved).toBe(0);
      expect(diff.regressed).toBe(0);
      expect(diff.unchanged).toBeGreaterThan(0);
      expect(diff.scoreDelta).toBe(0);
    });

    test('handles null reports', function () {
      var diff = reporter.compareReports(null, null);
      expect(diff.error).toBe('invalid_reports');
    });
  });

  // ── formatReportText ────────────────────────────────────────────

  describe('formatReportText', function () {

    test('formats report as text', function () {
      var report = reporter.generateReport();
      var text = reporter.formatReportText(report);
      expect(text).toContain('CAPTCHA Compliance Report');
      expect(text).toContain('Overall Score:');
      expect(text).toContain('Grade:');
    });

    test('includes action items for non-passing checks', function () {
      var report = reporter.generateReport({});
      var text = reporter.formatReportText(report);
      expect(text).toContain('[CRITICAL]');
    });

    test('shows no action items when all pass', function () {
      var config = reporter.getRecommendedConfig();
      var metrics = {
        totalChallenges: 1000, totalSolves: 900, totalFailures: 50,
        avgSolveTimeMs: 5000, p95SolveTimeMs: 15000,
        botAttempts: 100, botBlocked: 98,
        uptimePercent: 99.9, avgResponseTimeMs: 100, errorCount: 1
      };
      var report = reporter.generateReport(config, metrics);
      var text = reporter.formatReportText(report);
      expect(text).toContain('No action items');
    });

    test('handles null report', function () {
      expect(reporter.formatReportText(null)).toBe('');
    });

    test('includes category scores', function () {
      var report = reporter.generateReport();
      var text = reporter.formatReportText(report);
      expect(text).toContain('Accessibility:');
      expect(text).toContain('Privacy:');
      expect(text).toContain('Security:');
      expect(text).toContain('Operational:');
    });
  });
});
