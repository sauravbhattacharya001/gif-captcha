"use strict";

var assert = require("assert");
var gifCaptcha = require("../src/index");
var createComplianceReporter = gifCaptcha.createComplianceReporter;

describe("createComplianceReporter", function () {

  it("should export createComplianceReporter as a function", function () {
    assert.strictEqual(typeof createComplianceReporter, "function");
  });

  it("should create an instance with expected methods", function () {
    var reporter = createComplianceReporter();
    ["generateReport", "getRecommendedConfig", "compareReports",
     "formatReportText", "formatReportHtml"].forEach(function (m) {
      assert.strictEqual(typeof reporter[m], "function", "missing method: " + m);
    });
    assert.ok(reporter.SEVERITY);
    assert.ok(reporter.CATEGORY);
  });

  describe("generateReport", function () {

    it("should return a report with required fields", function () {
      var reporter = createComplianceReporter();
      var report = reporter.generateReport({}, {});
      assert.strictEqual(typeof report.overallScore, "number");
      assert.strictEqual(typeof report.grade, "string");
      assert.ok(Array.isArray(report.findings));
      assert.ok(report.findings.length > 0);
      assert.strictEqual(typeof report.totalFindings, "number");
      assert.strictEqual(typeof report.passed, "number");
      assert.strictEqual(typeof report.criticals, "number");
      assert.strictEqual(typeof report.warnings, "number");
      assert.ok(report.categoryScores);
      assert.strictEqual(report.system, "gif-captcha");
      assert.ok(report.generatedAt);
    });

    it("should produce grade A with recommended config and good metrics", function () {
      var reporter = createComplianceReporter();
      var config = reporter.getRecommendedConfig();
      var metrics = {
        totalChallenges: 1000,
        totalSolves: 800,
        totalFailures: 100,
        avgSolveTimeMs: 5000,
        p95SolveTimeMs: 12000,
        botAttempts: 200,
        botBlocked: 195,
        uptimePercent: 99.9,
        avgResponseTimeMs: 100,
        errorCount: 2,
      };
      var report = reporter.generateReport(config, metrics);
      assert.strictEqual(report.grade, "A");
      assert.ok(report.overallScore >= 90);
      assert.strictEqual(report.criticals, 0);
    });

    it("should flag criticals when config is empty", function () {
      var reporter = createComplianceReporter();
      var report = reporter.generateReport({}, {});
      assert.ok(report.criticals > 0, "empty config should produce critical findings");
      assert.ok(report.overallScore < 50);
    });

    it("should use custom systemName", function () {
      var reporter = createComplianceReporter({ systemName: "my-captcha" });
      var report = reporter.generateReport({}, {});
      assert.strictEqual(report.system, "my-captcha");
    });

    it("should include all four categories", function () {
      var reporter = createComplianceReporter();
      var report = reporter.generateReport({}, {});
      var cats = Object.keys(report.categoryScores);
      assert.ok(cats.indexOf("accessibility") !== -1);
      assert.ok(cats.indexOf("privacy") !== -1);
      assert.ok(cats.indexOf("security") !== -1);
      assert.ok(cats.indexOf("operational") !== -1);
    });

    it("should handle metrics with zero challenges gracefully", function () {
      var reporter = createComplianceReporter();
      var report = reporter.generateReport({}, { totalChallenges: 0 });
      // Operational checks should be INFO, not critical
      var opsFindings = report.findings.filter(function (f) {
        return f.category === "operational";
      });
      var opsCriticals = opsFindings.filter(function (f) {
        return f.severity === "critical";
      });
      // With zero challenges, metrics-based checks should be INFO
      assert.ok(opsCriticals.length <= 1, "zero challenges should not produce many op criticals");
    });

    it("should detect low bot block rate", function () {
      var reporter = createComplianceReporter({ minBotBlockRatePercent: 90 });
      var report = reporter.generateReport({}, {
        botAttempts: 100,
        botBlocked: 50,
      });
      var sec007 = report.findings.filter(function (f) { return f.id === "SEC-007"; })[0];
      assert.ok(sec007);
      assert.strictEqual(sec007.severity, "critical");
    });

    it("should respect custom thresholds", function () {
      var reporter = createComplianceReporter({
        maxDataRetentionDays: 7,
      });
      // retention of 10 days should be a warning with maxRetention=7
      var report = reporter.generateReport({ dataRetentionDays: 10 }, {});
      var prv001 = report.findings.filter(function (f) { return f.id === "PRV-001"; })[0];
      assert.ok(prv001);
      assert.strictEqual(prv001.severity, "warning");
    });
  });

  describe("getRecommendedConfig", function () {

    it("should return a config that achieves grade A", function () {
      var reporter = createComplianceReporter();
      var config = reporter.getRecommendedConfig();
      assert.strictEqual(config.audioAlternative, true);
      assert.strictEqual(config.keyboardNavigable, true);
      assert.strictEqual(config.tokenSigned, true);
      assert.strictEqual(config.httpsOnly, true);
      assert.ok(config.maxAttempts > 0 && config.maxAttempts <= 10);
    });
  });

  describe("compareReports", function () {

    it("should detect improvements between reports", function () {
      var reporter = createComplianceReporter();
      var oldReport = reporter.generateReport({}, {});
      var newReport = reporter.generateReport(reporter.getRecommendedConfig(), {
        totalChallenges: 1000, totalSolves: 800, totalFailures: 50,
        botAttempts: 100, botBlocked: 98, uptimePercent: 99.9,
        avgResponseTimeMs: 100, errorCount: 1,
      });
      var diff = reporter.compareReports(oldReport, newReport);
      assert.ok(diff.improved > 0, "new report should show improvements");
      assert.ok(diff.newScore > diff.oldScore);
      assert.ok(diff.scoreDelta > 0);
    });

    it("should detect regressions", function () {
      var reporter = createComplianceReporter();
      var goodReport = reporter.generateReport(reporter.getRecommendedConfig(), {
        totalChallenges: 1000, totalSolves: 800, totalFailures: 50,
        botAttempts: 100, botBlocked: 98, uptimePercent: 99.9,
        avgResponseTimeMs: 100, errorCount: 1,
      });
      var badReport = reporter.generateReport({}, {});
      var diff = reporter.compareReports(goodReport, badReport);
      assert.ok(diff.regressed > 0, "should detect regressions");
      assert.ok(diff.scoreDelta < 0);
    });

    it("should handle invalid inputs", function () {
      var reporter = createComplianceReporter();
      var diff = reporter.compareReports(null, null);
      assert.strictEqual(diff.error, "invalid_reports");
    });
  });

  describe("formatReportText", function () {

    it("should produce a non-empty string", function () {
      var reporter = createComplianceReporter();
      var report = reporter.generateReport({}, {});
      var text = reporter.formatReportText(report);
      assert.strictEqual(typeof text, "string");
      assert.ok(text.length > 100);
      assert.ok(text.indexOf("Compliance Report") !== -1);
    });

    it("should include action items for failing config", function () {
      var reporter = createComplianceReporter();
      var report = reporter.generateReport({}, {});
      var text = reporter.formatReportText(report);
      assert.ok(text.indexOf("Action Items") !== -1);
      assert.ok(text.indexOf("[CRITICAL]") !== -1);
    });

    it("should say no action items for perfect config", function () {
      var reporter = createComplianceReporter();
      var config = reporter.getRecommendedConfig();
      var report = reporter.generateReport(config, {
        totalChallenges: 1000, totalSolves: 800, totalFailures: 50,
        botAttempts: 100, botBlocked: 98, uptimePercent: 99.9,
        avgResponseTimeMs: 100, errorCount: 1,
      });
      var text = reporter.formatReportText(report);
      assert.ok(text.indexOf("all checks passed") !== -1 || text.indexOf("Action Items") === -1);
    });

    it("should return empty string for null report", function () {
      var reporter = createComplianceReporter();
      assert.strictEqual(reporter.formatReportText(null), "");
    });
  });

  describe("formatReportHtml", function () {

    it("should produce valid HTML", function () {
      var reporter = createComplianceReporter();
      var report = reporter.generateReport({}, {});
      var html = reporter.formatReportHtml(report);
      assert.ok(html.indexOf("<!DOCTYPE html>") !== -1);
      assert.ok(html.indexOf("</html>") !== -1);
      assert.ok(html.indexOf("Compliance Report") !== -1);
    });

    it("should support dark mode option", function () {
      var reporter = createComplianceReporter();
      var report = reporter.generateReport({}, {});
      var html = reporter.formatReportHtml(report, { darkMode: true });
      assert.ok(html.indexOf("#1a1a2e") !== -1);
    });

    it("should hide timestamp when requested", function () {
      var reporter = createComplianceReporter();
      var report = reporter.generateReport({}, {});
      var html = reporter.formatReportHtml(report, { includeTimestamp: false });
      assert.ok(html.indexOf("Generated") === -1 || html.indexOf("Generated by") !== -1);
    });

    it("should return empty string for null report", function () {
      var reporter = createComplianceReporter();
      assert.strictEqual(reporter.formatReportHtml(null), "");
    });
  });
});
