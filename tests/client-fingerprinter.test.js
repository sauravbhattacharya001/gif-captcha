/**
 * Tests for createClientFingerprinter
 */
"use strict";

var gifCaptcha = require("../src/index.js");
var createClientFingerprinter = gifCaptcha.createClientFingerprinter;

// ── Helper: sample signals ──────────────────────────────────────────

function sampleSignals(overrides) {
  var base = {
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    screenWidth: 1920,
    screenHeight: 1080,
    timezone: "America/Los_Angeles",
    language: "en-US",
    platform: "Win32",
    colorDepth: 24,
    touchSupport: false,
    canvasHash: "abc123def456",
    webglVendor: "NVIDIA Corporation",
    fonts: ["Arial", "Verdana", "Times New Roman"],
  };
  if (overrides) {
    for (var k in overrides) {
      if (overrides.hasOwnProperty(k)) base[k] = overrides[k];
    }
  }
  return base;
}

// ── Basic creation ──────────────────────────────────────────────────

describe("createClientFingerprinter", function () {
  it("should create a fingerprinter with default options", function () {
    var fp = createClientFingerprinter();
    expect(fp).toBeDefined();
    expect(typeof fp.identify).toBe("function");
    expect(typeof fp.findSimilar).toBe("function");
    expect(typeof fp.getFingerprint).toBe("function");
    expect(typeof fp.getStats).toBe("function");
    expect(typeof fp.exportState).toBe("function");
    expect(typeof fp.importState).toBe("function");
    expect(typeof fp.reset).toBe("function");
    expect(typeof fp.getConfig).toBe("function");
  });

  it("should accept custom options", function () {
    var fp = createClientFingerprinter({
      maxFingerprints: 500,
      ttlMs: 3600000,
      suspiciousChangeThreshold: 3,
      changeWindowMs: 600000,
    });
    var config = fp.getConfig();
    expect(config.maxFingerprints).toBe(500);
    expect(config.ttlMs).toBe(3600000);
    expect(config.suspiciousChangeThreshold).toBe(3);
    expect(config.changeWindowMs).toBe(600000);
  });
});

// ── identify ────────────────────────────────────────────────────────

describe("identify", function () {
  it("should return a fingerprint result for valid signals", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals());
    expect(result.fingerprintHash).toBeDefined();
    expect(typeof result.fingerprintHash).toBe("string");
    expect(result.isNew).toBe(true);
    expect(result.visits).toBe(1);
    expect(result.riskScore).toBeDefined();
    expect(result.riskLevel).toBeDefined();
    expect(result.signals).toBeDefined();
  });

  it("should recognize returning visitors", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    fp.identify(signals);
    var result = fp.identify(signals);
    expect(result.isNew).toBe(false);
    expect(result.visits).toBe(2);
  });

  it("should track visit count across multiple visits", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    for (var i = 0; i < 10; i++) {
      fp.identify(signals);
    }
    var result = fp.identify(signals);
    expect(result.visits).toBe(11);
  });

  it("should distinguish different signal sets", function () {
    var fp = createClientFingerprinter();
    var r1 = fp.identify(sampleSignals());
    var r2 = fp.identify(sampleSignals({ screenWidth: 2560, screenHeight: 1440 }));
    expect(r1.fingerprintHash).not.toBe(r2.fingerprintHash);
  });

  it("should handle empty/null signals", function () {
    var fp = createClientFingerprinter();
    var r1 = fp.identify({});
    expect(r1.fingerprintHash).toBeDefined();
    expect(r1.isNew).toBe(true);

    var r2 = fp.identify(null);
    expect(r2.fingerprintHash).toBeDefined();
  });

  it("should track IP metadata", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals(), { ip: "1.2.3.4" });
    expect(result.fingerprintHash).toBeDefined();
    var info = fp.getFingerprint(result.fingerprintHash);
    expect(info.uniqueIps).toBe(1);
  });

  it("should count multiple IPs per fingerprint", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    fp.identify(signals, { ip: "1.2.3.4" });
    fp.identify(signals, { ip: "5.6.7.8" });
    var hash = fp.identify(signals, { ip: "9.10.11.12" }).fingerprintHash;
    var info = fp.getFingerprint(hash);
    expect(info.uniqueIps).toBe(3);
  });

  it("should produce consistent hashes for same signals", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    var r1 = fp.identify(signals);
    var r2 = fp.identify(signals);
    expect(r1.fingerprintHash).toBe(r2.fingerprintHash);
  });

  it("should normalize language to lowercase", function () {
    var fp = createClientFingerprinter();
    var r1 = fp.identify(sampleSignals({ language: "EN-US" }));
    var r2 = fp.identify(sampleSignals({ language: "en-us" }));
    expect(r1.fingerprintHash).toBe(r2.fingerprintHash);
  });
});

// ── Bot detection ───────────────────────────────────────────────────

describe("bot detection", function () {
  it("should detect headless browser", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "Mozilla/5.0 HeadlessChrome/91.0" }));
    expect(result.botSignals).toContain("headless-browser");
    expect(result.riskScore).toBeGreaterThan(0);
  });

  it("should detect PhantomJS", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "Mozilla/5.0 PhantomJS/2.1" }));
    expect(result.botSignals).toContain("phantomjs");
  });

  it("should detect Selenium", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "Selenium WebDriver" }));
    expect(result.botSignals).toContain("selenium");
  });

  it("should detect Puppeteer", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "Chrome Puppeteer" }));
    expect(result.botSignals).toContain("puppeteer");
  });

  it("should detect SwiftShader GPU", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ webglVendor: "Google SwiftShader" }));
    expect(result.botSignals).toContain("swiftshader-gpu");
  });

  it("should detect software renderer", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ webglVendor: "Mesa/X.org llvmpipe" }));
    expect(result.botSignals).toContain("software-renderer");
  });

  it("should detect zero screen dimensions", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ screenWidth: 0, screenHeight: 0 }));
    expect(result.botSignals).toContain("zero-screen");
  });

  it("should detect zero color depth", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ colorDepth: 0 }));
    expect(result.botSignals).toContain("zero-color-depth");
  });

  it("should flag multiple bot signals with higher risk", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({
      userAgent: "HeadlessChrome Selenium",
      webglVendor: "SwiftShader",
      screenWidth: 0,
      screenHeight: 0,
    }));
    expect(result.botSignals.length).toBeGreaterThanOrEqual(3);
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
    expect(result.riskLevel).toBe("high");
  });

  it("should return empty botSignals for normal browsers", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals());
    expect(result.botSignals.length).toBe(0);
    expect(result.riskLevel).toBe("low");
  });
});

// ── Identity change detection ───────────────────────────────────────

describe("identity change detection", function () {
  it("should not flag few identity changes", function () {
    var fp = createClientFingerprinter({ suspiciousChangeThreshold: 5 });
    fp.identify(sampleSignals({ canvasHash: "a1" }), { ip: "1.1.1.1" });
    fp.identify(sampleSignals({ canvasHash: "a2" }), { ip: "1.1.1.1" });
    var result = fp.identify(sampleSignals({ canvasHash: "a3" }), { ip: "1.1.1.1" });
    expect(result.identityChanges.suspicious).toBe(false);
    expect(result.identityChanges.changes).toBeLessThan(5);
  });

  it("should flag many identity changes from same IP", function () {
    var fp = createClientFingerprinter({ suspiciousChangeThreshold: 3 });
    fp.identify(sampleSignals({ canvasHash: "x1" }), { ip: "2.2.2.2" });
    fp.identify(sampleSignals({ canvasHash: "x2" }), { ip: "2.2.2.2" });
    var result = fp.identify(sampleSignals({ canvasHash: "x3" }), { ip: "2.2.2.2" });
    expect(result.identityChanges.suspicious).toBe(true);
    expect(result.identityChanges.changes).toBeGreaterThanOrEqual(3);
  });

  it("should not count same fingerprint as a change", function () {
    var fp = createClientFingerprinter({ suspiciousChangeThreshold: 3 });
    var signals = sampleSignals();
    fp.identify(signals, { ip: "3.3.3.3" });
    fp.identify(signals, { ip: "3.3.3.3" });
    fp.identify(signals, { ip: "3.3.3.3" });
    var result = fp.identify(signals, { ip: "3.3.3.3" });
    expect(result.identityChanges.suspicious).toBe(false);
  });

  it("should return not suspicious when no IP provided", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals());
    expect(result.identityChanges.suspicious).toBe(false);
  });
});

// ── findSimilar ─────────────────────────────────────────────────────

describe("findSimilar", function () {
  it("should find exact matches", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    fp.identify(signals);
    var similar = fp.findSimilar(signals);
    expect(similar.length).toBe(1);
    expect(similar[0].similarity).toBe(1);
  });

  it("should find partially matching fingerprints", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals());
    // Only change one signal
    var modified = sampleSignals({ canvasHash: "different_hash" });
    var similar = fp.findSimilar(modified, 0.5);
    expect(similar.length).toBeGreaterThanOrEqual(1);
    expect(similar[0].similarity).toBeGreaterThan(0.5);
    expect(similar[0].similarity).toBeLessThan(1);
  });

  it("should respect similarity threshold", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals());
    var similar = fp.findSimilar(sampleSignals({ canvasHash: "x" }), 1.0);
    expect(similar.length).toBe(0);
  });

  it("should return empty for no matches", function () {
    var fp = createClientFingerprinter();
    var similar = fp.findSimilar(sampleSignals());
    expect(similar.length).toBe(0);
  });

  it("should sort results by similarity descending", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals());
    fp.identify(sampleSignals({ canvasHash: "x", webglVendor: "y" }));
    var query = sampleSignals({ canvasHash: "x" });
    var similar = fp.findSimilar(query, 0.3);
    if (similar.length >= 2) {
      expect(similar[0].similarity).toBeGreaterThanOrEqual(similar[1].similarity);
    }
  });
});

// ── getFingerprint ──────────────────────────────────────────────────

describe("getFingerprint", function () {
  it("should return details for known fingerprint", function () {
    var fp = createClientFingerprinter();
    var r = fp.identify(sampleSignals(), { ip: "1.1.1.1" });
    var info = fp.getFingerprint(r.fingerprintHash);
    expect(info).not.toBeNull();
    expect(info.fingerprintHash).toBe(r.fingerprintHash);
    expect(info.visits).toBe(1);
    expect(info.uniqueIps).toBe(1);
    expect(info.signals).toBeDefined();
  });

  it("should return null for unknown hash", function () {
    var fp = createClientFingerprinter();
    expect(fp.getFingerprint("nonexistent")).toBeNull();
  });
});

// ── getStats ────────────────────────────────────────────────────────

describe("getStats", function () {
  it("should return empty stats initially", function () {
    var fp = createClientFingerprinter();
    var stats = fp.getStats();
    expect(stats.totalFingerprints).toBe(0);
    expect(stats.totalVisits).toBe(0);
    expect(stats.uniqueIps).toBe(0);
  });

  it("should aggregate stats correctly", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals(), { ip: "1.1.1.1" });
    fp.identify(sampleSignals(), { ip: "2.2.2.2" });
    fp.identify(sampleSignals({ canvasHash: "other" }), { ip: "1.1.1.1" });
    var stats = fp.getStats();
    expect(stats.totalFingerprints).toBe(2);
    expect(stats.totalVisits).toBe(3);
    expect(stats.uniqueIps).toBe(2);
  });
});

// ── State persistence ───────────────────────────────────────────────

describe("state persistence", function () {
  it("should export and import state", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals(), { ip: "1.1.1.1" });
    fp.identify(sampleSignals({ platform: "MacIntel" }), { ip: "2.2.2.2" });
    var state = fp.exportState();

    var fp2 = createClientFingerprinter();
    fp2.importState(state);
    var stats = fp2.getStats();
    expect(stats.totalFingerprints).toBe(2);
    expect(stats.totalVisits).toBe(2);
  });

  it("should handle importing empty/null state", function () {
    var fp = createClientFingerprinter();
    fp.importState(null);
    fp.importState({});
    expect(fp.getStats().totalFingerprints).toBe(0);
  });
});

// ── reset ───────────────────────────────────────────────────────────

describe("reset", function () {
  it("should clear all state", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals());
    fp.identify(sampleSignals({ canvasHash: "x" }));
    fp.reset();
    expect(fp.getStats().totalFingerprints).toBe(0);
    expect(fp.getStats().totalVisits).toBe(0);
  });
});

// ── LRU eviction ────────────────────────────────────────────────────

describe("LRU eviction", function () {
  it("should evict oldest entries when over capacity", function () {
    var fp = createClientFingerprinter({ maxFingerprints: 3 });
    fp.identify(sampleSignals({ canvasHash: "a" }));
    fp.identify(sampleSignals({ canvasHash: "b" }));
    fp.identify(sampleSignals({ canvasHash: "c" }));
    // This should evict the first
    fp.identify(sampleSignals({ canvasHash: "d" }));
    var stats = fp.getStats();
    expect(stats.totalFingerprints).toBeLessThanOrEqual(4);
  });
});

// ── Risk scoring ────────────────────────────────────────────────────

describe("risk scoring", function () {
  it("should assign low risk to normal fingerprint", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals());
    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe("low");
  });

  it("should assign medium risk for single bot signal", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "HeadlessChrome" }));
    expect(result.riskScore).toBeGreaterThanOrEqual(20);
    expect(["low", "medium", "high"]).toContain(result.riskLevel);
  });

  it("should cap risk score at 100", function () {
    var fp = createClientFingerprinter({ suspiciousChangeThreshold: 2 });
    fp.identify(sampleSignals({ canvasHash: "z1", userAgent: "HeadlessChrome Selenium Puppeteer PhantomJS" }), { ip: "9.9.9.9" });
    fp.identify(sampleSignals({ canvasHash: "z2", userAgent: "HeadlessChrome Selenium Puppeteer PhantomJS" }), { ip: "9.9.9.9" });
    var result = fp.identify(sampleSignals({ canvasHash: "z3", userAgent: "HeadlessChrome Selenium Puppeteer PhantomJS", webglVendor: "SwiftShader" }), { ip: "9.9.9.9" });
    expect(result.riskScore).toBeLessThanOrEqual(100);
  });
});

// ── config ──────────────────────────────────────────────────────────

describe("getConfig", function () {
  it("should return default configuration", function () {
    var fp = createClientFingerprinter();
    var config = fp.getConfig();
    expect(config.maxFingerprints).toBe(10000);
    expect(config.ttlMs).toBe(86400000);
    expect(config.suspiciousChangeThreshold).toBe(5);
    expect(config.signalWeights).toBeDefined();
    expect(config.signalWeights.userAgent).toBe(0.15);
  });

  it("should return custom signal weights", function () {
    var fp = createClientFingerprinter({
      signalWeights: { userAgent: 0.5 },
    });
    var config = fp.getConfig();
    expect(config.signalWeights.userAgent).toBe(0.5);
    expect(config.signalWeights.screen).toBe(0.10); // default kept
  });
});
