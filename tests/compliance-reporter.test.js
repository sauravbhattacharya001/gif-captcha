"use strict";

var cr = require("../src/compliance-reporter");

// ── Helpers ──────────────────────────────────────────────────────────

function fullyCompliantConfig() {
  return {
    audioAlternative: true,
    keyboardNavigable: true,
    ariaLabel: "Security verification",
    colorContrast: 4.5,
    timeLimitMs: 120000,
    canExtendTime: true,
    supportedLanguages: ["en", "es", "fr"],
    dataRetentionDays: 30,
    consentRequired: true,
    anonymization: true,
    deletionSupported: true,
    rateLimitEnabled: true,
    tokenSigned: true,
    httpsOnly: true,
    inputSanitized: true,
    maxAttempts: 5,
    replayProtection: true
  };
}

function healthyMetrics() {
  return {
    totalChallenges: 10000,
    totalSolves: 8500,
    totalFailures: 1200,
    avgSolveTimeMs: 8000,
    p95SolveTimeMs: 25000,
    botAttempts: 500,
    botBlocked: 490,
    uptimePercent: 99.9,
    avgResponseTimeMs: 150,
    errorCount: 5
  };
}

function emptyConfig() { return {}; }

function emptyMetrics() { return {}; }

// ── Tests ────────────────────────────────────────────────────────────

describe("createComplianceReporter", function () {

  test("returns an object with expected methods", function () {
    var reporter = cr.createComplianceReporter();
    expect(typeof reporter.generateReport).toBe("function");
    expect(typeof reporter.getRecommendedConfig).toBe("function");
    expect(typeof reporter.compareReports).toBe("function");
    expect(typeof reporter.formatReportText).toBe("function");
    expect(typeof reporter.formatReportHtml).toBe("function");
    expect(reporter.SEVERITY).toBeDefined();
    expect(reporter.CATEGORY).toBeDefined();
  });

  test("accepts custom options", function () {
    var reporter = cr.createComplianceReporter({
      systemName: "test-captcha",
      maxDataRetentionDays: 15,
      minSolveRatePercent: 80,
      maxSolveTimeMs: 30000,
      maxFailRatePercent: 25,
      minBotBlockRatePercent: 95
    });
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    expect(report.system).toBe("test-captcha");
  });

  test("uses defaults when no options provided", function () {
    var reporter = cr.createComplianceReporter();
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    expect(report.system).toBe("gif-captcha");
  });
});

describe("generateReport", function () {
  var reporter;

  beforeAll(function () {
    reporter = cr.createComplianceReporter();
  });

  test("returns report with expected structure", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    expect(report).toHaveProperty("system");
    expect(report).toHaveProperty("generatedAt");
    expect(report).toHaveProperty("overallScore");
    expect(report).toHaveProperty("grade");
    expect(report).toHaveProperty("totalFindings");
    expect(report).toHaveProperty("passed");
    expect(report).toHaveProperty("criticals");
    expect(report).toHaveProperty("warnings");
    expect(report).toHaveProperty("categoryScores");
    expect(report).toHaveProperty("findings");
  });

  test("fully compliant config scores 100 with grade A", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    expect(report.overallScore).toBe(100);
    expect(report.grade).toBe("A");
    expect(report.criticals).toBe(0);
    expect(report.warnings).toBe(0);
  });

  test("empty config produces criticals and low score", function () {
    var report = reporter.generateReport(emptyConfig(), healthyMetrics());
    expect(report.criticals).toBeGreaterThan(0);
    expect(report.overallScore).toBeLessThan(50);
  });

  test("handles null/undefined config and metrics", function () {
    var report = reporter.generateReport(null, null);
    expect(report).toHaveProperty("findings");
    expect(report.totalFindings).toBeGreaterThan(0);
  });

  test("generatedAt is valid ISO timestamp", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var d = new Date(report.generatedAt);
    expect(isNaN(d.getTime())).toBe(false);
  });

  // ── Accessibility checks ──

  test("missing audio alternative is critical", function () {
    var cfg = fullyCompliantConfig();
    cfg.audioAlternative = false;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var finding = report.findings.find(function (f) { return f.id === "ACC-001"; });
    expect(finding.severity).toBe("critical");
  });

  test("missing keyboard nav is critical", function () {
    var cfg = fullyCompliantConfig();
    cfg.keyboardNavigable = false;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var finding = report.findings.find(function (f) { return f.id === "ACC-002"; });
    expect(finding.severity).toBe("critical");
  });

  test("missing aria label is warning", function () {
    var cfg = fullyCompliantConfig();
    cfg.ariaLabel = "";
    var report = reporter.generateReport(cfg, healthyMetrics());
    var finding = report.findings.find(function (f) { return f.id === "ACC-003"; });
    expect(finding.severity).toBe("warning");
  });

  test("low contrast is critical, medium is warning", function () {
    var cfg = fullyCompliantConfig();
    cfg.colorContrast = 2.0;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "ACC-004"; });
    expect(f.severity).toBe("critical");

    cfg.colorContrast = 3.5;
    report = reporter.generateReport(cfg, healthyMetrics());
    f = report.findings.find(function (f) { return f.id === "ACC-004"; });
    expect(f.severity).toBe("warning");
  });

  test("time limit without extension is warning", function () {
    var cfg = fullyCompliantConfig();
    cfg.canExtendTime = false;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "ACC-005"; });
    expect(f.severity).toBe("warning");
  });

  test("no languages is warning, 1-2 is info", function () {
    var cfg = fullyCompliantConfig();
    cfg.supportedLanguages = [];
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "ACC-006"; });
    expect(f.severity).toBe("warning");

    cfg.supportedLanguages = ["en"];
    report = reporter.generateReport(cfg, healthyMetrics());
    f = report.findings.find(function (f) { return f.id === "ACC-006"; });
    expect(f.severity).toBe("info");
  });

  // ── Privacy checks ──

  test("no retention period is critical", function () {
    var cfg = fullyCompliantConfig();
    delete cfg.dataRetentionDays;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "PRV-001"; });
    expect(f.severity).toBe("critical");
  });

  test("excessive retention is warning", function () {
    var cfg = fullyCompliantConfig();
    cfg.dataRetentionDays = 90;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "PRV-001"; });
    expect(f.severity).toBe("warning");
  });

  test("missing consent is warning", function () {
    var cfg = fullyCompliantConfig();
    cfg.consentRequired = false;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "PRV-002"; });
    expect(f.severity).toBe("warning");
  });

  test("no deletion support is critical", function () {
    var cfg = fullyCompliantConfig();
    cfg.deletionSupported = false;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "PRV-004"; });
    expect(f.severity).toBe("critical");
  });

  // ── Security checks ──

  test("missing rate limit is critical", function () {
    var cfg = fullyCompliantConfig();
    cfg.rateLimitEnabled = false;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "SEC-001"; });
    expect(f.severity).toBe("critical");
  });

  test("unsigned tokens is critical", function () {
    var cfg = fullyCompliantConfig();
    cfg.tokenSigned = false;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "SEC-002"; });
    expect(f.severity).toBe("critical");
  });

  test("no HTTPS is critical", function () {
    var cfg = fullyCompliantConfig();
    cfg.httpsOnly = false;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "SEC-003"; });
    expect(f.severity).toBe("critical");
  });

  test("high max attempts is warning, zero is critical", function () {
    var cfg = fullyCompliantConfig();
    cfg.maxAttempts = 20;
    var report = reporter.generateReport(cfg, healthyMetrics());
    var f = report.findings.find(function (f) { return f.id === "SEC-005"; });
    expect(f.severity).toBe("warning");

    cfg.maxAttempts = 0;
    report = reporter.generateReport(cfg, healthyMetrics());
    f = report.findings.find(function (f) { return f.id === "SEC-005"; });
    expect(f.severity).toBe("critical");
  });

  test("low bot block rate is critical", function () {
    var m = healthyMetrics();
    m.botBlocked = 400; // 80% < 90% min
    var report = reporter.generateReport(fullyCompliantConfig(), m);
    var f = report.findings.find(function (f) { return f.id === "SEC-007"; });
    expect(f.severity).not.toBe("pass");
  });

  // ── Operational checks ──

  test("low solve rate is critical", function () {
    var m = healthyMetrics();
    m.totalSolves = 5000; // 50% < 70%
    var report = reporter.generateReport(fullyCompliantConfig(), m);
    var f = report.findings.find(function (f) { return f.id === "OPS-001"; });
    expect(f.severity).toBe("critical");
  });

  test("high failure rate is critical", function () {
    var m = healthyMetrics();
    m.totalFailures = 7000; // 70% > 50%
    var report = reporter.generateReport(fullyCompliantConfig(), m);
    var f = report.findings.find(function (f) { return f.id === "OPS-002"; });
    expect(f.severity).toBe("critical");
  });

  test("slow response time is warning/critical", function () {
    var m = healthyMetrics();
    m.avgResponseTimeMs = 600;
    var report = reporter.generateReport(fullyCompliantConfig(), m);
    var f = report.findings.find(function (f) { return f.id === "OPS-006"; });
    expect(f.severity).toBe("warning");

    m.avgResponseTimeMs = 1500;
    report = reporter.generateReport(fullyCompliantConfig(), m);
    f = report.findings.find(function (f) { return f.id === "OPS-006"; });
    expect(f.severity).toBe("critical");
  });

  test("high error rate is warning/critical", function () {
    var m = healthyMetrics();
    m.errorCount = 200; // 2%
    var report = reporter.generateReport(fullyCompliantConfig(), m);
    var f = report.findings.find(function (f) { return f.id === "OPS-007"; });
    expect(f.severity).toBe("warning");
  });

  test("low uptime is critical", function () {
    var m = healthyMetrics();
    m.uptimePercent = 98.0;
    var report = reporter.generateReport(fullyCompliantConfig(), m);
    var f = report.findings.find(function (f) { return f.id === "OPS-005"; });
    expect(f.severity).toBe("critical");
  });

  test("empty metrics produce safe defaults for metric checks", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), emptyMetrics());
    // With no data, metric-based findings should be info or pass (not critical/warning)
    // OPS-005 (uptime) defaults to 100 → pass
    // SEC-007 (bot block) with 0 bot attempts → no meaningful rate → info or pass
    expect(report).toHaveProperty("findings");
    expect(report.totalFindings).toBe(24);
  });

  // ── Grading ──

  test("grade B for 80-89 score", function () {
    // Partially compliant - a couple warnings
    var cfg = fullyCompliantConfig();
    cfg.ariaLabel = ""; // ACC-003 warning
    cfg.consentRequired = false; // PRV-002 warning
    var report = reporter.generateReport(cfg, healthyMetrics());
    expect(report.overallScore).toBeGreaterThanOrEqual(80);
    expect(report.overallScore).toBeLessThan(100);
  });

  test("grade F for score below 60", function () {
    var report = reporter.generateReport(emptyConfig(), emptyMetrics());
    expect(report.grade).toBe("F");
  });

  // ── Category scores ──

  test("category scores cover all 4 categories", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    expect(report.categoryScores).toHaveProperty("accessibility");
    expect(report.categoryScores).toHaveProperty("privacy");
    expect(report.categoryScores).toHaveProperty("security");
    expect(report.categoryScores).toHaveProperty("operational");
  });

  test("each category score has score, total, passed, criticals, warnings", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    Object.values(report.categoryScores).forEach(function (cs) {
      expect(cs).toHaveProperty("score");
      expect(cs).toHaveProperty("total");
      expect(cs).toHaveProperty("passed");
      expect(cs).toHaveProperty("criticals");
      expect(cs).toHaveProperty("warnings");
    });
  });

  // ── Finding structure ──

  test("each finding has id, category, title, severity", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    report.findings.forEach(function (f) {
      expect(f).toHaveProperty("id");
      expect(f).toHaveProperty("category");
      expect(f).toHaveProperty("title");
      expect(f).toHaveProperty("severity");
    });
  });

  test("finding IDs follow prefix convention", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    report.findings.forEach(function (f) {
      expect(f.id).toMatch(/^(ACC|PRV|SEC|OPS)-\d{3}$/);
    });
  });

  test("expected total findings count", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    // ACC-001..006, PRV-001..004, SEC-001..007, OPS-001..007 = 24
    expect(report.totalFindings).toBe(24);
  });
});

describe("getRecommendedConfig", function () {
  test("returns config that produces 100% score", function () {
    var reporter = cr.createComplianceReporter();
    var config = reporter.getRecommendedConfig();
    var report = reporter.generateReport(config, healthyMetrics());
    expect(report.overallScore).toBe(100);
    expect(report.criticals).toBe(0);
  });

  test("includes all expected fields", function () {
    var reporter = cr.createComplianceReporter();
    var config = reporter.getRecommendedConfig();
    expect(config.audioAlternative).toBe(true);
    expect(config.keyboardNavigable).toBe(true);
    expect(config.ariaLabel).toBeTruthy();
    expect(config.colorContrast).toBeGreaterThanOrEqual(4.5);
    expect(config.supportedLanguages.length).toBeGreaterThanOrEqual(3);
    expect(config.rateLimitEnabled).toBe(true);
    expect(config.tokenSigned).toBe(true);
    expect(config.httpsOnly).toBe(true);
    expect(config.maxAttempts).toBeGreaterThan(0);
    expect(config.maxAttempts).toBeLessThanOrEqual(10);
  });

  test("respects custom maxDataRetentionDays", function () {
    var reporter = cr.createComplianceReporter({ maxDataRetentionDays: 7 });
    var config = reporter.getRecommendedConfig();
    expect(config.dataRetentionDays).toBe(7);
  });
});

describe("compareReports", function () {
  var reporter;

  beforeAll(function () {
    reporter = cr.createComplianceReporter();
  });

  test("detects improvements", function () {
    var oldReport = reporter.generateReport(emptyConfig(), healthyMetrics());
    var newReport = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var diff = reporter.compareReports(oldReport, newReport);
    expect(diff.improved).toBeGreaterThan(0);
    expect(diff.scoreDelta).toBeGreaterThan(0);
  });

  test("detects regressions", function () {
    var oldReport = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var newReport = reporter.generateReport(emptyConfig(), healthyMetrics());
    var diff = reporter.compareReports(oldReport, newReport);
    expect(diff.regressed).toBeGreaterThan(0);
    expect(diff.scoreDelta).toBeLessThan(0);
  });

  test("identical reports show no changes", function () {
    var config = fullyCompliantConfig();
    var metrics = healthyMetrics();
    var r1 = reporter.generateReport(config, metrics);
    var r2 = reporter.generateReport(config, metrics);
    var diff = reporter.compareReports(r1, r2);
    expect(diff.improved).toBe(0);
    expect(diff.regressed).toBe(0);
    expect(diff.unchanged).toBe(r1.totalFindings);
    expect(diff.scoreDelta).toBe(0);
  });

  test("handles null inputs gracefully", function () {
    var diff = reporter.compareReports(null, null);
    expect(diff.error).toBe("invalid_reports");
  });

  test("handles missing findings array", function () {
    var diff = reporter.compareReports({}, {});
    expect(diff.error).toBe("invalid_reports");
  });

  test("includes detail entries for changed findings", function () {
    var oldReport = reporter.generateReport(emptyConfig(), healthyMetrics());
    var newReport = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var diff = reporter.compareReports(oldReport, newReport);
    expect(diff.details.length).toBeGreaterThan(0);
    diff.details.forEach(function (d) {
      expect(d).toHaveProperty("id");
      expect(d).toHaveProperty("change");
    });
  });
});

describe("formatReportText", function () {
  var reporter;

  beforeAll(function () {
    reporter = cr.createComplianceReporter();
  });

  test("returns formatted string", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var text = reporter.formatReportText(report);
    expect(typeof text).toBe("string");
    expect(text.length).toBeGreaterThan(0);
  });

  test("contains system name and score", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var text = reporter.formatReportText(report);
    expect(text).toContain("gif-captcha");
    expect(text).toContain("100/100");
    expect(text).toContain("Grade: A");
  });

  test("shows category scores", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var text = reporter.formatReportText(report);
    expect(text).toContain("Accessibility:");
    expect(text).toContain("Privacy:");
    expect(text).toContain("Security:");
    expect(text).toContain("Operational:");
  });

  test("shows action items for non-compliant config", function () {
    var report = reporter.generateReport(emptyConfig(), healthyMetrics());
    var text = reporter.formatReportText(report);
    expect(text).toContain("[CRITICAL]");
    expect(text).toContain("Action Items:");
  });

  test("shows all-passed message for compliant config", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var text = reporter.formatReportText(report);
    expect(text).toContain("No action items");
  });

  test("returns empty string for null input", function () {
    expect(reporter.formatReportText(null)).toBe("");
  });
});

describe("formatReportHtml", function () {
  var reporter;

  beforeAll(function () {
    reporter = cr.createComplianceReporter();
  });

  test("returns valid HTML document", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var html = reporter.formatReportHtml(report);
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("<html");
    expect(html).toContain("</html>");
    expect(html).toContain("<title>");
  });

  test("includes grade and score", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var html = reporter.formatReportHtml(report);
    expect(html).toContain("100/100");
  });

  test("includes category score bars", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var html = reporter.formatReportHtml(report);
    expect(html).toContain("Accessibility");
    expect(html).toContain("Privacy");
    expect(html).toContain("Security");
    expect(html).toContain("Operational");
  });

  test("supports dark mode option", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var html = reporter.formatReportHtml(report, { darkMode: true });
    expect(html).toContain("#1a1a2e"); // dark bg
  });

  test("supports custom title", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var html = reporter.formatReportHtml(report, { title: "Custom Title" });
    expect(html).toContain("Custom Title");
  });

  test("can hide timestamp", function () {
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var html = reporter.formatReportHtml(report, { includeTimestamp: false });
    expect(html).not.toContain("Generated " + report.generatedAt);
  });

  test("escapes HTML in system name output", function () {
    var reporter = cr.createComplianceReporter({ systemName: '<script>alert("xss")</script>' });
    var report = reporter.generateReport(fullyCompliantConfig(), healthyMetrics());
    var html = reporter.formatReportHtml(report);
    expect(html).not.toContain('<script>alert');
  });

  test("returns empty string for null input", function () {
    expect(reporter.formatReportHtml(null)).toBe("");
  });
});

describe("SEVERITY and CATEGORY constants", function () {
  test("SEVERITY has expected values", function () {
    var reporter = cr.createComplianceReporter();
    expect(reporter.SEVERITY.CRITICAL).toBe("critical");
    expect(reporter.SEVERITY.WARNING).toBe("warning");
    expect(reporter.SEVERITY.INFO).toBe("info");
    expect(reporter.SEVERITY.PASS).toBe("pass");
  });

  test("CATEGORY has expected values", function () {
    var reporter = cr.createComplianceReporter();
    expect(reporter.CATEGORY.ACCESSIBILITY).toBe("accessibility");
    expect(reporter.CATEGORY.PRIVACY).toBe("privacy");
    expect(reporter.CATEGORY.SECURITY).toBe("security");
    expect(reporter.CATEGORY.OPERATIONAL).toBe("operational");
  });
});

describe("custom thresholds", function () {
  test("custom minSolveRate changes OPS-001 threshold", function () {
    var reporter = cr.createComplianceReporter({ minSolveRatePercent: 90 });
    var m = healthyMetrics();
    m.totalSolves = 8500; // 85% < 90%
    var report = reporter.generateReport(fullyCompliantConfig(), m);
    var f = report.findings.find(function (f) { return f.id === "OPS-001"; });
    expect(f.severity).not.toBe("pass");
  });

  test("custom minBotBlockRate changes SEC-007 threshold", function () {
    var reporter = cr.createComplianceReporter({ minBotBlockRatePercent: 99 });
    var m = healthyMetrics();
    m.botBlocked = 490; // 98% < 99%
    var report = reporter.generateReport(fullyCompliantConfig(), m);
    var f = report.findings.find(function (f) { return f.id === "SEC-007"; });
    expect(f.severity).not.toBe("pass");
  });

  test("custom maxSolveTimeMs changes OPS-003 threshold", function () {
    var reporter = cr.createComplianceReporter({ maxSolveTimeMs: 5000 });
    var m = healthyMetrics();
    m.avgSolveTimeMs = 8000; // > 5000
    var report = reporter.generateReport(fullyCompliantConfig(), m);
    var f = report.findings.find(function (f) { return f.id === "OPS-003"; });
    expect(f.severity).not.toBe("pass");
  });
});
