var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var { createAccessibilityAuditor } = require("../src/index");

describe("createAccessibilityAuditor", function () {

  describe("initialization", function () {
    it("should create with default AA level", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({});
      assert.equal(report.level, "AA");
    });

    it("should accept A level", function () {
      var auditor = createAccessibilityAuditor({ level: "A" });
      var report = auditor.audit({});
      assert.equal(report.level, "A");
    });

    it("should accept AAA level", function () {
      var auditor = createAccessibilityAuditor({ level: "AAA" });
      var report = auditor.audit({});
      assert.equal(report.level, "AAA");
    });

    it("should throw on invalid level", function () {
      assert.throws(function () {
        createAccessibilityAuditor({ level: "B" });
      }, /Conformance level/);
    });

    it("should be case-insensitive for level", function () {
      var auditor = createAccessibilityAuditor({ level: "aa" });
      var report = auditor.audit({});
      assert.equal(report.level, "AA");
    });
  });

  describe("audit — perfect config", function () {
    it("should pass all AA checks with good config", function () {
      var auditor = createAccessibilityAuditor({ level: "AA" });
      var report = auditor.audit({
        hasAltText: true,
        hasKeyboardNav: true,
        hasAudioFallback: true,
        timeoutMs: 30000,
        flashesPerSecond: 1,
        animationDurationMs: 3000,
        hasFocusIndicator: true,
        hasErrorMessages: true,
        contrastRatio: 5.0,
        hasNonColorCues: true,
        touchTargetPx: 48,
        maxAttempts: 5,
        hasSkipOption: true,
      });
      assert.equal(report.errorCount, 0);
      assert.equal(report.conformant, true);
      assert.ok(report.score >= 0.9);
      assert.ok(report.grade === "A" || report.grade === "A+");
    });
  });

  describe("audit — individual rules", function () {
    it("should flag missing alt text as error", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ hasAltText: false });
      var issue = report.issues.find(function (i) { return i.rule === "text-alternatives"; });
      assert.ok(issue);
      assert.equal(issue.severity, "error");
      assert.equal(issue.wcag, "1.1.1");
    });

    it("should flag missing keyboard nav as error", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ hasKeyboardNav: false });
      var issue = report.issues.find(function (i) { return i.rule === "keyboard-nav"; });
      assert.ok(issue);
      assert.equal(issue.severity, "error");
    });

    it("should flag short timeout as warning", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ timeoutMs: 10000 });
      var issue = report.issues.find(function (i) { return i.rule === "sufficient-time"; });
      assert.ok(issue);
      assert.equal(issue.severity, "warning");
    });

    it("should pass timeout when 0 (no limit)", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ timeoutMs: 0 });
      var passed = report.passed.find(function (p) { return p.rule === "sufficient-time"; });
      assert.ok(passed);
    });

    it("should flag high flash rate as error", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ flashesPerSecond: 4 });
      var issue = report.issues.find(function (i) { return i.rule === "seizure-safety"; });
      assert.ok(issue);
      assert.equal(issue.severity, "error");
    });

    it("should flag missing focus indicator", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ hasFocusIndicator: false });
      var issue = report.issues.find(function (i) { return i.rule === "focus-indicator"; });
      assert.ok(issue);
      assert.equal(issue.severity, "error");
    });

    it("should flag low contrast ratio", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ contrastRatio: 3.0 });
      var issue = report.issues.find(function (i) { return i.rule === "contrast-ratio"; });
      assert.ok(issue);
      assert.equal(issue.severity, "warning");
    });

    it("should flag small touch targets", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ touchTargetPx: 20 });
      var issue = report.issues.find(function (i) { return i.rule === "touch-target"; });
      assert.ok(issue);
    });

    it("should flag missing audio fallback as warning at AA", function () {
      var auditor = createAccessibilityAuditor({ level: "AA" });
      var report = auditor.audit({ hasAudioFallback: false });
      var issue = report.issues.find(function (i) { return i.rule === "audio-fallback"; });
      assert.ok(issue);
      assert.equal(issue.severity, "warning");
    });

    it("should flag low retry limit", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ maxAttempts: 1 });
      var issue = report.issues.find(function (i) { return i.rule === "retry-limit"; });
      assert.ok(issue);
    });
  });

  describe("audit — level filtering", function () {
    it("should skip AAA rules when auditing at AA level", function () {
      var auditor = createAccessibilityAuditor({ level: "AA" });
      var report = auditor.audit({ hasSkipOption: false });
      var skipIssue = report.issues.find(function (i) { return i.rule === "skip-option"; });
      assert.equal(skipIssue, undefined);
    });

    it("should include AAA rules at AAA level", function () {
      var auditor = createAccessibilityAuditor({ level: "AAA" });
      var report = auditor.audit({ hasSkipOption: false });
      var skipIssue = report.issues.find(function (i) { return i.rule === "skip-option"; });
      assert.ok(skipIssue);
    });
  });

  describe("audit — strict mode", function () {
    it("should promote warnings to errors in strict mode", function () {
      var auditor = createAccessibilityAuditor({ strict: true });
      var report = auditor.audit({ timeoutMs: 10000 });
      var issue = report.issues.find(function (i) { return i.rule === "sufficient-time"; });
      assert.ok(issue);
      assert.equal(issue.severity, "error");
    });
  });

  describe("audit — grading", function () {
    it("should grade F when most checks fail", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({
        hasAltText: false,
        hasKeyboardNav: false,
        hasAudioFallback: false,
        timeoutMs: 5000,
        flashesPerSecond: 5,
        hasFocusIndicator: false,
        hasErrorMessages: false,
        contrastRatio: 2.0,
        hasNonColorCues: false,
        touchTargetPx: 10,
        maxAttempts: 1,
      });
      assert.ok(report.score < 0.5);
      assert.equal(report.grade, "F");
      assert.equal(report.conformant, false);
    });
  });

  describe("summarize", function () {
    it("should produce readable text summary", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({ hasKeyboardNav: false });
      var text = auditor.summarize(report);
      assert.ok(text.includes("WCAG"));
      assert.ok(text.includes("Grade"));
      assert.ok(text.includes("keyboard"));
    });

    it("should show conformant message when no errors", function () {
      var auditor = createAccessibilityAuditor();
      var report = auditor.audit({
        hasAltText: true,
        hasKeyboardNav: true,
        hasFocusIndicator: true,
        hasErrorMessages: true,
        hasNonColorCues: true,
        contrastRatio: 5.0,
        timeoutMs: 30000,
        touchTargetPx: 48,
        maxAttempts: 5,
        hasAudioFallback: true,
      });
      var text = auditor.summarize(report);
      assert.ok(text.includes("No critical"));
    });
  });

  describe("listRules", function () {
    it("should list all available rules", function () {
      var auditor = createAccessibilityAuditor();
      var rules = auditor.listRules();
      assert.ok(rules.length >= 10);
      assert.ok(rules[0].id);
      assert.ok(rules[0].wcag);
      assert.ok(rules[0].level);
    });
  });
});
