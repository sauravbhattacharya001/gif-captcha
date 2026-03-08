"use strict";

var assert = require("assert");
var gifCaptcha = require("../src/index");
var createDeviceCohortAnalyzer = gifCaptcha.createDeviceCohortAnalyzer;

describe("createDeviceCohortAnalyzer", function () {

  it("should export createDeviceCohortAnalyzer", function () {
    assert.strictEqual(typeof createDeviceCohortAnalyzer, "function");
  });

  it("should create an instance with all methods", function () {
    var dca = createDeviceCohortAnalyzer();
    ["record","getCohortProfile","getAllProfiles","compareCohorts","summary","reset","exportState","importState"].forEach(function(m) {
      assert.strictEqual(typeof dca[m], "function");
    });
  });

  describe("record", function () {
    it("should throw on missing session", function () {
      var dca = createDeviceCohortAnalyzer();
      assert.throws(function () { dca.record(); }, /session is required/);
    });

    it("should throw on invalid solveTimeMs", function () {
      var dca = createDeviceCohortAnalyzer();
      assert.throws(function () { dca.record({ solveTimeMs: -1 }); }, /solveTimeMs/);
      assert.throws(function () { dca.record({ solveTimeMs: "abc" }); }, /solveTimeMs/);
    });

    it("should record a mobile session", function () {
      var dca = createDeviceCohortAnalyzer();
      var res = dca.record({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)", solveTimeMs: 2000, solved: true });
      assert.strictEqual(res.category, "mobile");
      assert.strictEqual(res.capability, "low");
      assert.ok(res.cohortKey);
    });

    it("should record a desktop session", function () {
      var dca = createDeviceCohortAnalyzer();
      var res = dca.record({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", deviceInfo: { screenWidth: 1920, memory: 16 }, solveTimeMs: 1500, solved: true });
      assert.strictEqual(res.category, "desktop");
      assert.strictEqual(res.capability, "high");
    });

    it("should detect bot user-agent", function () {
      var dca = createDeviceCohortAnalyzer();
      var res = dca.record({ userAgent: "Googlebot/2.1", solveTimeMs: 100, solved: true });
      assert.strictEqual(res.category, "bot");
    });

    it("should classify unknown user-agent", function () {
      var dca = createDeviceCohortAnalyzer();
      var res = dca.record({ userAgent: "CustomAgent/1.0", solveTimeMs: 1000, solved: true });
      assert.strictEqual(res.category, "unknown");
    });

    it("should handle null user-agent", function () {
      var dca = createDeviceCohortAnalyzer();
      var res = dca.record({ solveTimeMs: 1000, solved: true });
      assert.strictEqual(res.category, "unknown");
    });

    it("should classify capability tiers", function () {
      var dca = createDeviceCohortAnalyzer();
      assert.strictEqual(dca.record({ userAgent: "Windows", deviceInfo: { screenWidth: 1920, memory: 16 }, solveTimeMs: 1000, solved: true }).capability, "high");
      assert.strictEqual(dca.record({ userAgent: "Windows", deviceInfo: { screenWidth: 1024, memory: 4 }, solveTimeMs: 1000, solved: true }).capability, "mid");
      assert.strictEqual(dca.record({ userAgent: "Windows", deviceInfo: { screenWidth: 320, memory: 1 }, solveTimeMs: 1000, solved: true }).capability, "low");
    });

    it("should detect bot-speed anomaly", function () {
      var dca = createDeviceCohortAnalyzer({ minCohortSize: 1 });
      var res = dca.record({ userAgent: "iPhone", solveTimeMs: 50, solved: true });
      assert.ok(res.anomalies.some(function (a) { return a.type === "bot_speed"; }));
    });

    it("should detect suspicious-speed anomaly", function () {
      var dca = createDeviceCohortAnalyzer({ minCohortSize: 1 });
      var res = dca.record({ userAgent: "iPhone", solveTimeMs: 300, solved: true });
      assert.ok(res.anomalies.some(function (a) { return a.type === "suspicious_speed"; }));
    });

    it("should detect z-score outlier", function () {
      var dca = createDeviceCohortAnalyzer({ minCohortSize: 3 });
      for (var i = 0; i < 10; i++) dca.record({ userAgent: "iPhone", solveTimeMs: 2000 + i * 10, solved: true });
      var res = dca.record({ userAgent: "iPhone", solveTimeMs: 50000, solved: true });
      assert.ok(res.anomalies.some(function (a) { return a.type === "zscore_outlier"; }));
    });

    it("should detect cohort-wide suspicious pattern", function () {
      var dca = createDeviceCohortAnalyzer({ minCohortSize: 5 });
      for (var i = 0; i < 6; i++) dca.record({ userAgent: "Android", solveTimeMs: 100, solved: true });
      var res = dca.record({ userAgent: "Android", solveTimeMs: 100, solved: true });
      assert.ok(res.anomalies.some(function (a) { return a.type === "cohort_suspicious"; }));
    });

    it("should not detect z-score anomalies below minCohortSize", function () {
      var dca = createDeviceCohortAnalyzer({ minCohortSize: 10 });
      for (var i = 0; i < 3; i++) {
        var res = dca.record({ userAgent: "iPhone", solveTimeMs: 2000, solved: true });
        assert.ok(!res.anomalies.some(function (a) { return a.type === "zscore_outlier" || a.type === "cohort_suspicious"; }));
      }
    });
  });

  describe("getCohortProfile", function () {
    it("should return null for unknown cohort", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().getCohortProfile("x:y"), null);
    });

    it("should return profile with timing stats", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 5; i++) dca.record({ userAgent: "Windows NT", deviceInfo: { screenWidth: 1920, memory: 16 }, solveTimeMs: 1000 + i * 100, solved: i < 4, ip: "1.2.3." + i });
      var p = dca.getCohortProfile("desktop:high");
      assert.ok(p);
      assert.strictEqual(p.category, "desktop");
      assert.strictEqual(p.sessionCount, 5);
      assert.strictEqual(p.uniqueIPs, 5);
      assert.ok(p.timing.mean > 0);
      assert.ok(p.timing.median > 0);
      assert.ok(typeof p.risk.level === "string");
    });

    it("should flag bot category", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 5; i++) dca.record({ userAgent: "Googlebot/2.1", solveTimeMs: 2000, solved: true });
      var p = dca.getCohortProfile("bot:low");
      assert.ok(p.risk.factors.some(function (f) { return f.indexOf("bot") !== -1; }));
    });

    it("should flag low variance", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 10; i++) dca.record({ userAgent: "iPhone", solveTimeMs: 1000, solved: true });
      var p = dca.getCohortProfile("mobile:low");
      assert.ok(p.risk.factors.some(function (f) { return f.indexOf("variance") !== -1 || f.indexOf("CV") !== -1; }));
    });

    it("should flag near-perfect solve rate", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 10; i++) dca.record({ userAgent: "iPhone", solveTimeMs: 2000, solved: true });
      var p = dca.getCohortProfile("mobile:low");
      assert.ok(p.risk.factors.some(function (f) { return f.indexOf("solve rate") !== -1; }));
    });

    it("should flag high sessions-per-IP", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 30; i++) dca.record({ userAgent: "iPhone", solveTimeMs: 2000 + i * 50, solved: i % 3 !== 0, ip: "1.2.3.4" });
      var p = dca.getCohortProfile("mobile:low");
      assert.ok(p.risk.factors.some(function (f) { return f.indexOf("sessions-per-IP") !== -1; }));
    });
  });

  describe("getAllProfiles", function () {
    it("should sort by risk by default", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 5; i++) {
        dca.record({ userAgent: "iPhone", solveTimeMs: 2000 + i * 200, solved: i % 2 === 0 });
        dca.record({ userAgent: "Googlebot", solveTimeMs: 100, solved: true });
      }
      var profiles = dca.getAllProfiles();
      assert.ok(profiles.length >= 2);
      assert.ok(profiles[0].risk.score >= profiles[profiles.length - 1].risk.score);
    });

    it("should filter by minRisk", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 5; i++) {
        dca.record({ userAgent: "iPhone", solveTimeMs: 3000, solved: i % 2 === 0 });
        dca.record({ userAgent: "Googlebot", solveTimeMs: 100, solved: true });
      }
      dca.getAllProfiles({ minRisk: "high" }).forEach(function (p) {
        assert.ok(p.risk.level === "high" || p.risk.level === "critical");
      });
    });

    it("should sort by count", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 10; i++) dca.record({ userAgent: "iPhone", solveTimeMs: 2000, solved: true });
      for (var j = 0; j < 3; j++) dca.record({ userAgent: "Windows", solveTimeMs: 2000, solved: true });
      var profiles = dca.getAllProfiles({ sortBy: "count" });
      assert.ok(profiles[0].sessionCount >= profiles[profiles.length - 1].sessionCount);
    });

    it("should sort by name", function () {
      var dca = createDeviceCohortAnalyzer();
      dca.record({ userAgent: "Windows", solveTimeMs: 2000, solved: true });
      dca.record({ userAgent: "iPhone", solveTimeMs: 2000, solved: true });
      var profiles = dca.getAllProfiles({ sortBy: "name" });
      assert.ok(profiles[0].cohortKey <= profiles[profiles.length - 1].cohortKey);
    });
  });

  describe("compareCohorts", function () {
    it("should return null if cohort missing", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().compareCohorts("a:b", "c:d"), null);
    });

    it("should compare two cohorts", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 5; i++) {
        dca.record({ userAgent: "iPhone", solveTimeMs: 2000 + i * 10, solved: true });
        dca.record({ userAgent: "Windows", deviceInfo: { screenWidth: 1920, memory: 16 }, solveTimeMs: 2000 + i * 10, solved: true });
      }
      var cmp = dca.compareCohorts("mobile:low", "desktop:high");
      assert.ok(cmp);
      assert.ok(typeof cmp.similarity === "number");
      assert.ok(Array.isArray(cmp.spoofingIndicators));
    });

    it("should detect spoofing", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 10; i++) {
        dca.record({ userAgent: "iPhone", solveTimeMs: 1500, solved: true });
        dca.record({ userAgent: "Googlebot", solveTimeMs: 1500, solved: true });
      }
      var cmp = dca.compareCohorts("mobile:low", "bot:low");
      assert.ok(cmp.spoofingIndicators.length > 0);
      assert.strictEqual(cmp.verdict, "suspicious");
    });
  });

  describe("summary", function () {
    it("should return fleet summary", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 5; i++) dca.record({ userAgent: "iPhone", solveTimeMs: 2000, solved: true });
      var s = dca.summary();
      assert.strictEqual(s.totalSessions, 5);
      assert.strictEqual(s.totalCohorts, 1);
      assert.ok(s.sessionsByCategory.mobile === 5);
      assert.ok(Array.isArray(s.profiles));
    });

    it("should count anomalies", function () {
      var dca = createDeviceCohortAnalyzer({ minCohortSize: 1 });
      dca.record({ userAgent: "iPhone", solveTimeMs: 50, solved: true });
      assert.ok(dca.summary().totalAnomalies >= 1);
    });
  });

  describe("reset", function () {
    it("should clear all data", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 5; i++) dca.record({ userAgent: "iPhone", solveTimeMs: 2000, solved: true });
      dca.reset();
      assert.strictEqual(dca.summary().totalSessions, 0);
    });
  });

  describe("export/import", function () {
    it("should round-trip state", function () {
      var dca = createDeviceCohortAnalyzer();
      for (var i = 0; i < 5; i++) dca.record({ userAgent: "iPhone", solveTimeMs: 2000, solved: true });
      var dca2 = createDeviceCohortAnalyzer();
      dca2.importState(dca.exportState());
      assert.strictEqual(dca.summary().totalSessions, dca2.summary().totalSessions);
    });

    it("should throw on invalid state", function () {
      var dca = createDeviceCohortAnalyzer();
      assert.throws(function () { dca.importState(null); }, /Invalid/);
      assert.throws(function () { dca.importState({}); }, /Invalid/);
    });
  });

  describe("LRU eviction", function () {
    it("should evict oldest cohort", function () {
      var dca = createDeviceCohortAnalyzer({ maxCohorts: 2 });
      dca.record({ userAgent: "iPhone", solveTimeMs: 2000, solved: true });
      dca.record({ userAgent: "Windows", solveTimeMs: 2000, solved: true });
      dca.record({ userAgent: "Googlebot", solveTimeMs: 2000, solved: true });
      assert.strictEqual(dca.getCohortProfile("mobile:low"), null);
      assert.ok(dca.getCohortProfile("bot:low"));
    });
  });

  describe("maxSessionsPerCohort", function () {
    it("should cap sessions", function () {
      var dca = createDeviceCohortAnalyzer({ maxSessionsPerCohort: 5 });
      for (var i = 0; i < 10; i++) dca.record({ userAgent: "iPhone", solveTimeMs: 1000 + i * 100, solved: true });
      assert.ok(dca.exportState().cohorts["mobile:low"].sessions.length <= 5);
    });
  });

  describe("device classification edge cases", function () {
    it("should detect headless", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().record({ userAgent: "HeadlessChrome/90", solveTimeMs: 1000, solved: true }).category, "bot");
    });
    it("should detect puppeteer", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().record({ userAgent: "Puppeteer/1", solveTimeMs: 1000, solved: true }).category, "bot");
    });
    it("should detect selenium", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().record({ userAgent: "Selenium/4", solveTimeMs: 1000, solved: true }).category, "bot");
    });
    it("should classify Android as mobile", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().record({ userAgent: "Linux; Android 13", solveTimeMs: 1000, solved: true }).category, "mobile");
    });
    it("should classify iPad as mobile", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().record({ userAgent: "iPad; CPU OS 16", solveTimeMs: 1000, solved: true }).category, "mobile");
    });
    it("should classify Mac as desktop", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().record({ userAgent: "Macintosh; Intel", solveTimeMs: 1000, solved: true }).category, "desktop");
    });
    it("should classify CrOS as desktop", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().record({ userAgent: "X11; CrOS x86_64", solveTimeMs: 1000, solved: true }).category, "desktop");
    });
    it("should handle solveTimeMs of 0", function () {
      var res = createDeviceCohortAnalyzer({ minCohortSize: 1 }).record({ userAgent: "iPhone", solveTimeMs: 0, solved: false });
      assert.strictEqual(res.category, "mobile");
    });
    it("should default attempts to 1", function () {
      var dca = createDeviceCohortAnalyzer();
      dca.record({ userAgent: "iPhone", solveTimeMs: 1000, solved: true });
      assert.strictEqual(dca.exportState().cohorts["mobile:low"].sessions[0].attempts, 1);
    });
    it("should use provided attempts", function () {
      var dca = createDeviceCohortAnalyzer();
      dca.record({ userAgent: "iPhone", solveTimeMs: 1000, solved: true, attempts: 3 });
      assert.strictEqual(dca.exportState().cohorts["mobile:low"].sessions[0].attempts, 3);
    });
    it("should handle mid capability", function () {
      assert.strictEqual(createDeviceCohortAnalyzer().record({ userAgent: "Windows", deviceInfo: { screenWidth: 1024, memory: 6 }, solveTimeMs: 1000, solved: true }).capability, "mid");
    });
  });
});
