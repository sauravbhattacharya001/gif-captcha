'use strict';

var { describe, it, beforeEach } = require('node:test');
var assert = require('node:assert/strict');
var gifCaptcha = require('../src/index');
var createComplianceReporter = gifCaptcha.createComplianceReporter;

describe('createComplianceReporter', function () {

  var reporter;

  beforeEach(function () {
    reporter = createComplianceReporter();
  });

  // ── Factory ─────────────────────────────────────────────────────

  it('returns object with expected methods', function () {
    assert.equal(typeof reporter.generateReport, 'function');
    assert.equal(typeof reporter.getRecommendedConfig, 'function');
    assert.equal(typeof reporter.compareReports, 'function');
    assert.equal(typeof reporter.formatReportText, 'function');
  });

  it('exposes SEVERITY and CATEGORY constants', function () {
    assert.equal(reporter.SEVERITY.CRITICAL, 'critical');
    assert.equal(reporter.SEVERITY.PASS, 'pass');
    assert.equal(reporter.CATEGORY.ACCESSIBILITY, 'accessibility');
    assert.equal(reporter.CATEGORY.SECURITY, 'security');
  });

  it('custom options are respected', function () {
    var custom = createComplianceReporter({
      systemName: 'my-captcha',
      maxDataRetentionDays: 7,
      minSolveRatePercent: 80
    });
    var report = custom.generateReport({ dataRetentionDays: 10 });
    // 10 days exceeds 7-day limit
    var prv001 = report.findings.find(function (f) { return f.id === 'PRV-001'; });
    assert.equal(prv001.severity, 'warning');
    assert.equal(report.system, 'my-captcha');
  });

  // ── generateReport ──────────────────────────────────────────────

  describe('generateReport', function () {

    it('returns valid report structure', function () {
      var report = reporter.generateReport();
      assert.ok('system' in report);
      assert.ok('generatedAt' in report);
      assert.ok('overallScore' in report);
      assert.ok('grade' in report);
      assert.ok('totalFindings' in report);
      assert.ok('passed' in report);
      assert.ok('criticals' in report);
      assert.ok('warnings' in report);
      assert.ok('categoryScores' in report);
      assert.ok('findings' in report);
      assert.equal(Array.isArray(report.findings), true);
    });

    it('default config scores poorly', function () {
      var report = reporter.generateReport({}, {});
      assert.ok(report.overallScore < 50);
      assert.ok(report.criticals > 0);
    });

    it('recommended config scores well', function () {
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
      assert.ok(report.overallScore >= 90, 'score should be >= 90, got ' + report.overallScore);
      assert.equal(report.grade, 'A');
      assert.equal(report.criticals, 0);
    });

    it('all findings have required properties', function () {
      var report = reporter.generateReport();
      report.findings.forEach(function (f) {
        assert.ok('id' in f, 'finding missing id');
        assert.ok('category' in f, 'finding missing category');
        assert.ok('title' in f, 'finding missing title');
        assert.ok('description' in f, 'finding missing description');
        assert.ok('severity' in f, 'finding missing severity');
      });
    });

    it('generatedAt is valid ISO timestamp', function () {
      var report = reporter.generateReport();
      assert.equal(new Date(report.generatedAt).toISOString(), report.generatedAt);
    });

    // ── Accessibility checks ────────────────────────────────────

    it('ACC-001: audioAlternative true = pass', function () {
      var report = reporter.generateReport({ audioAlternative: true });
      var f = report.findings.find(function (x) { return x.id === 'ACC-001'; });
      assert.equal(f.severity, 'pass');
    });

    it('ACC-001: audioAlternative false = critical', function () {
      var report = reporter.generateReport({ audioAlternative: false });
      var f = report.findings.find(function (x) { return x.id === 'ACC-001'; });
      assert.equal(f.severity, 'critical');
    });

    it('ACC-002: keyboard navigable', function () {
      var report = reporter.generateReport({ keyboardNavigable: true });
      var f = report.findings.find(function (x) { return x.id === 'ACC-002'; });
      assert.equal(f.severity, 'pass');
    });

    it('ACC-003: ariaLabel present = pass', function () {
      var report = reporter.generateReport({ ariaLabel: 'CAPTCHA' });
      var f = report.findings.find(function (x) { return x.id === 'ACC-003'; });
      assert.equal(f.severity, 'pass');
    });

    it('ACC-004: high contrast = pass', function () {
      var report = reporter.generateReport({ colorContrast: 7.0 });
      var f = report.findings.find(function (x) { return x.id === 'ACC-004'; });
      assert.equal(f.severity, 'pass');
    });

    it('ACC-004: low contrast = critical', function () {
      var report = reporter.generateReport({ colorContrast: 2.0 });
      var f = report.findings.find(function (x) { return x.id === 'ACC-004'; });
      assert.equal(f.severity, 'critical');
    });

    it('ACC-004: borderline contrast = warning', function () {
      var report = reporter.generateReport({ colorContrast: 3.5 });
      var f = report.findings.find(function (x) { return x.id === 'ACC-004'; });
      assert.equal(f.severity, 'warning');
    });

    it('ACC-005: time limit with extend = pass', function () {
      var report = reporter.generateReport({ timeLimitMs: 30000, canExtendTime: true });
      var f = report.findings.find(function (x) { return x.id === 'ACC-005'; });
      assert.equal(f.severity, 'pass');
    });

    it('ACC-005: time limit without extend = warning', function () {
      var report = reporter.generateReport({ timeLimitMs: 30000, canExtendTime: false });
      var f = report.findings.find(function (x) { return x.id === 'ACC-005'; });
      assert.equal(f.severity, 'warning');
    });

    it('ACC-006: 3+ languages = pass', function () {
      var report = reporter.generateReport({ supportedLanguages: ['en', 'es', 'fr'] });
      var f = report.findings.find(function (x) { return x.id === 'ACC-006'; });
      assert.equal(f.severity, 'pass');
    });

    it('ACC-006: 1 language = info', function () {
      var report = reporter.generateReport({ supportedLanguages: ['en'] });
      var f = report.findings.find(function (x) { return x.id === 'ACC-006'; });
      assert.equal(f.severity, 'info');
    });

    // ── Privacy checks ──────────────────────────────────────────

    it('PRV-001: retention within limit = pass', function () {
      var report = reporter.generateReport({ dataRetentionDays: 14 });
      var f = report.findings.find(function (x) { return x.id === 'PRV-001'; });
      assert.equal(f.severity, 'pass');
    });

    it('PRV-001: no retention policy = critical', function () {
      var report = reporter.generateReport({});
      var f = report.findings.find(function (x) { return x.id === 'PRV-001'; });
      assert.equal(f.severity, 'critical');
    });

    it('PRV-001: retention exceeds limit = warning', function () {
      var report = reporter.generateReport({ dataRetentionDays: 90 });
      var f = report.findings.find(function (x) { return x.id === 'PRV-001'; });
      assert.equal(f.severity, 'warning');
    });

    it('PRV-002: consent required = pass', function () {
      var report = reporter.generateReport({ consentRequired: true });
      var f = report.findings.find(function (x) { return x.id === 'PRV-002'; });
      assert.equal(f.severity, 'pass');
    });

    it('PRV-004: deletion supported = pass', function () {
      var report = reporter.generateReport({ deletionSupported: true });
      var f = report.findings.find(function (x) { return x.id === 'PRV-004'; });
      assert.equal(f.severity, 'pass');
    });

    it('PRV-004: no deletion = critical', function () {
      var report = reporter.generateReport({ deletionSupported: false });
      var f = report.findings.find(function (x) { return x.id === 'PRV-004'; });
      assert.equal(f.severity, 'critical');
    });

    // ── Security checks ─────────────────────────────────────────

    it('SEC-001: rate limit enabled = pass', function () {
      var report = reporter.generateReport({ rateLimitEnabled: true });
      var f = report.findings.find(function (x) { return x.id === 'SEC-001'; });
      assert.equal(f.severity, 'pass');
    });

    it('SEC-002: token signed = pass', function () {
      var report = reporter.generateReport({ tokenSigned: true });
      var f = report.findings.find(function (x) { return x.id === 'SEC-002'; });
      assert.equal(f.severity, 'pass');
    });

    it('SEC-003: httpsOnly = pass', function () {
      var report = reporter.generateReport({ httpsOnly: true });
      var f = report.findings.find(function (x) { return x.id === 'SEC-003'; });
      assert.equal(f.severity, 'pass');
    });

    it('SEC-005: max attempts 5 = pass', function () {
      var report = reporter.generateReport({ maxAttempts: 5 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-005'; });
      assert.equal(f.severity, 'pass');
    });

    it('SEC-005: max attempts 20 = warning', function () {
      var report = reporter.generateReport({ maxAttempts: 20 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-005'; });
      assert.equal(f.severity, 'warning');
    });

    it('SEC-005: no attempt limit = critical', function () {
      var report = reporter.generateReport({ maxAttempts: 0 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-005'; });
      assert.equal(f.severity, 'critical');
    });

    it('SEC-007: good bot block rate = pass', function () {
      var report = reporter.generateReport({}, { botAttempts: 100, botBlocked: 95 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-007'; });
      assert.equal(f.severity, 'pass');
    });

    it('SEC-007: poor bot block rate = critical', function () {
      var report = reporter.generateReport({}, { botAttempts: 100, botBlocked: 50 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-007'; });
      assert.equal(f.severity, 'critical');
    });

    it('SEC-007: no bot data = info', function () {
      var report = reporter.generateReport({}, { botAttempts: 0, botBlocked: 0 });
      var f = report.findings.find(function (x) { return x.id === 'SEC-007'; });
      assert.equal(f.severity, 'info');
    });

    // ── Operational checks ──────────────────────────────────────

    it('OPS-001: good solve rate = pass', function () {
      var report = reporter.generateReport({}, { totalChallenges: 100, totalSolves: 85 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-001'; });
      assert.equal(f.severity, 'pass');
    });

    it('OPS-001: poor solve rate = critical', function () {
      var report = reporter.generateReport({}, { totalChallenges: 100, totalSolves: 40 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-001'; });
      assert.equal(f.severity, 'critical');
    });

    it('OPS-003: fast solve time = pass', function () {
      var report = reporter.generateReport({}, { avgSolveTimeMs: 5000 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-003'; });
      assert.equal(f.severity, 'pass');
    });

    it('OPS-003: slow solve time = critical', function () {
      var report = reporter.generateReport({}, { avgSolveTimeMs: 120000 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-003'; });
      assert.equal(f.severity, 'critical');
    });

    it('OPS-005: high uptime = pass', function () {
      var report = reporter.generateReport({}, { uptimePercent: 99.9 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-005'; });
      assert.equal(f.severity, 'pass');
    });

    it('OPS-005: low uptime = critical', function () {
      var report = reporter.generateReport({}, { uptimePercent: 95 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-005'; });
      assert.equal(f.severity, 'critical');
    });

    it('OPS-006: fast response = pass', function () {
      var report = reporter.generateReport({}, { avgResponseTimeMs: 100 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-006'; });
      assert.equal(f.severity, 'pass');
    });

    it('OPS-007: low error rate = pass', function () {
      var report = reporter.generateReport({}, { totalChallenges: 10000, errorCount: 5 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-007'; });
      assert.equal(f.severity, 'pass');
    });

    it('OPS-007: high error rate = critical', function () {
      var report = reporter.generateReport({}, { totalChallenges: 100, errorCount: 10 });
      var f = report.findings.find(function (x) { return x.id === 'OPS-007'; });
      assert.equal(f.severity, 'critical');
    });

    // ── Scoring ─────────────────────────────────────────────────

    it('grade A for score >= 90', function () {
      var config = reporter.getRecommendedConfig();
      var metrics = {
        totalChallenges: 1000, totalSolves: 900, totalFailures: 50,
        avgSolveTimeMs: 5000, p95SolveTimeMs: 15000,
        botAttempts: 100, botBlocked: 98,
        uptimePercent: 99.9, avgResponseTimeMs: 100, errorCount: 1
      };
      var report = reporter.generateReport(config, metrics);
      assert.equal(report.grade, 'A');
    });

    it('category scores are 0-100', function () {
      var report = reporter.generateReport();
      var cats = ['accessibility', 'privacy', 'security', 'operational'];
      cats.forEach(function (cat) {
        assert.ok(report.categoryScores[cat].score >= 0, cat + ' score >= 0');
        assert.ok(report.categoryScores[cat].score <= 100, cat + ' score <= 100');
      });
    });

    it('findings count matches totals', function () {
      var report = reporter.generateReport();
      var counted = report.passed + report.criticals + report.warnings;
      // Some might be INFO
      assert.ok(counted <= report.totalFindings);
    });
  });

  // ── getRecommendedConfig ────────────────────────────────────────

  describe('getRecommendedConfig', function () {

    it('returns complete config object', function () {
      var config = reporter.getRecommendedConfig();
      assert.equal(config.audioAlternative, true);
      assert.equal(config.keyboardNavigable, true);
      assert.equal(config.tokenSigned, true);
      assert.equal(config.httpsOnly, true);
      assert.equal(config.rateLimitEnabled, true);
      assert.equal(config.maxAttempts, 5);
    });

    it('recommended config passes all checks when metrics are good', function () {
      var config = reporter.getRecommendedConfig();
      var metrics = {
        totalChallenges: 500, totalSolves: 400, totalFailures: 50,
        avgSolveTimeMs: 8000, p95SolveTimeMs: 20000,
        botAttempts: 50, botBlocked: 48,
        uptimePercent: 99.95, avgResponseTimeMs: 80, errorCount: 0
      };
      var report = reporter.generateReport(config, metrics);
      assert.equal(report.criticals, 0);
    });

    it('respects custom maxDataRetentionDays', function () {
      var custom = createComplianceReporter({ maxDataRetentionDays: 7 });
      var config = custom.getRecommendedConfig();
      assert.equal(config.dataRetentionDays, 7);
    });
  });

  // ── compareReports ──────────────────────────────────────────────

  describe('compareReports', function () {

    it('detects improvements', function () {
      var oldReport = reporter.generateReport({}, {});
      var config = reporter.getRecommendedConfig();
      var newReport = reporter.generateReport(config, {
        totalChallenges: 100, totalSolves: 85, totalFailures: 10,
        botAttempts: 50, botBlocked: 48, uptimePercent: 99.9,
        avgResponseTimeMs: 100, errorCount: 0, avgSolveTimeMs: 5000, p95SolveTimeMs: 15000
      });

      var diff = reporter.compareReports(oldReport, newReport);
      assert.ok(diff.improved > 0);
      assert.ok(diff.newScore > diff.oldScore);
      assert.ok(diff.scoreDelta > 0);
    });

    it('detects regressions', function () {
      var config = reporter.getRecommendedConfig();
      var goodReport = reporter.generateReport(config, {
        totalChallenges: 100, totalSolves: 85, totalFailures: 10,
        botAttempts: 50, botBlocked: 48, uptimePercent: 99.9,
        avgResponseTimeMs: 100, errorCount: 0, avgSolveTimeMs: 5000, p95SolveTimeMs: 15000
      });
      var badReport = reporter.generateReport({}, {});

      var diff = reporter.compareReports(goodReport, badReport);
      assert.ok(diff.regressed > 0);
      assert.ok(diff.scoreDelta < 0);
    });

    it('handles identical reports', function () {
      var report = reporter.generateReport({ audioAlternative: true });
      var diff = reporter.compareReports(report, report);
      assert.equal(diff.improved, 0);
      assert.equal(diff.regressed, 0);
      assert.ok(diff.unchanged > 0);
      assert.equal(diff.scoreDelta, 0);
    });

    it('handles null reports', function () {
      var diff = reporter.compareReports(null, null);
      assert.equal(diff.error, 'invalid_reports');
    });
  });

  // ── formatReportText ────────────────────────────────────────────

  describe('formatReportText', function () {

    it('formats report as text', function () {
      var report = reporter.generateReport();
      var text = reporter.formatReportText(report);
      assert.ok(text.includes('CAPTCHA Compliance Report'));
      assert.ok(text.includes('Overall Score:'));
      assert.ok(text.includes('Grade:'));
    });

    it('includes action items for non-passing checks', function () {
      var report = reporter.generateReport({});
      var text = reporter.formatReportText(report);
      assert.ok(text.includes('[CRITICAL]'));
    });

    it('shows no action items when all pass', function () {
      var config = reporter.getRecommendedConfig();
      var metrics = {
        totalChallenges: 1000, totalSolves: 900, totalFailures: 50,
        avgSolveTimeMs: 5000, p95SolveTimeMs: 15000,
        botAttempts: 100, botBlocked: 98,
        uptimePercent: 99.9, avgResponseTimeMs: 100, errorCount: 1
      };
      var report = reporter.generateReport(config, metrics);
      var text = reporter.formatReportText(report);
      assert.ok(text.includes('No action items'));
    });

    it('handles null report', function () {
      assert.equal(reporter.formatReportText(null), '');
    });

    it('includes category scores', function () {
      var report = reporter.generateReport();
      var text = reporter.formatReportText(report);
      assert.ok(text.includes('Accessibility:'));
      assert.ok(text.includes('Privacy:'));
      assert.ok(text.includes('Security:'));
      assert.ok(text.includes('Operational:'));
    });
  });

  // ── HTML Report Rendering ─────────────────────────────────────────

  describe('formatReportHtml', function () {
    it('returns a complete HTML document', function () {
      var report = reporter.generateReport(reporter.getRecommendedConfig(), { totalChallenges: 1000, totalSolves: 900, totalFailures: 100 });
      var html = reporter.formatReportHtml(report);
      assert.ok(html.includes('<!DOCTYPE html>'));
      assert.ok(html.includes('</html>'));
      assert.ok(html.includes('<title>'));
    });

    it('includes system name and grade', function () {
      var report = reporter.generateReport(reporter.getRecommendedConfig());
      var html = reporter.formatReportHtml(report);
      assert.ok(html.includes('gif-captcha'));
      assert.ok(html.includes(report.grade));
      assert.ok(html.includes(String(report.overallScore)));
    });

    it('includes all four category score sections', function () {
      var report = reporter.generateReport(reporter.getRecommendedConfig());
      var html = reporter.formatReportHtml(report);
      assert.ok(html.includes('Accessibility'));
      assert.ok(html.includes('Privacy'));
      assert.ok(html.includes('Security'));
      assert.ok(html.includes('Operational'));
    });

    it('includes finding IDs and titles', function () {
      var report = reporter.generateReport({});
      var html = reporter.formatReportHtml(report);
      assert.ok(html.includes('ACC-001'));
      assert.ok(html.includes('SEC-001'));
      assert.ok(html.includes('PRV-001'));
    });

    it('color-codes severity badges', function () {
      var report = reporter.generateReport({});
      var html = reporter.formatReportHtml(report);
      // Critical findings should have red badge
      assert.ok(html.includes('#dc3545'));
      assert.ok(html.includes('critical'));
    });

    it('includes recommendations for failing checks', function () {
      var report = reporter.generateReport({});
      var html = reporter.formatReportHtml(report);
      assert.ok(html.includes('\u{1F4A1}'));
    });

    it('supports dark mode option', function () {
      var report = reporter.generateReport(reporter.getRecommendedConfig());
      var lightHtml = reporter.formatReportHtml(report, { darkMode: false });
      var darkHtml = reporter.formatReportHtml(report, { darkMode: true });
      assert.ok(darkHtml.includes('#1a1a2e'));
      assert.ok(!lightHtml.includes('#1a1a2e'));
    });

    it('supports custom title', function () {
      var report = reporter.generateReport(reporter.getRecommendedConfig());
      var html = reporter.formatReportHtml(report, { title: 'My Custom Audit' });
      assert.ok(html.includes('My Custom Audit'));
    });

    it('can hide timestamp', function () {
      var report = reporter.generateReport(reporter.getRecommendedConfig());
      var html = reporter.formatReportHtml(report, { includeTimestamp: false });
      assert.ok(!html.includes('Generated 20'));
    });

    it('returns empty string for null report', function () {
      assert.equal(reporter.formatReportHtml(null), '');
    });

    it('escapes HTML in findings to prevent XSS', function () {
      var customReporter = createComplianceReporter({ systemName: '<script>alert(1)</script>' });
      var report = customReporter.generateReport({});
      var html = customReporter.formatReportHtml(report);
      assert.ok(!html.includes('<script>alert(1)</script>'));
      assert.ok(html.includes('&lt;script&gt;'));
    });

    it('shows passed count and total findings count', function () {
      var config = reporter.getRecommendedConfig();
      var report = reporter.generateReport(config);
      var html = reporter.formatReportHtml(report);
      assert.ok(html.includes(String(report.passed)));
      assert.ok(html.includes('Findings (' + report.totalFindings + ')'));
    });
  });
});
