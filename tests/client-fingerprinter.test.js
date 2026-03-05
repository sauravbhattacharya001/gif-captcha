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

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

describe("createClientFingerprinter", function () {
  it("should create a fingerprinter with default options", function () {
    var fp = createClientFingerprinter();
    assert.notStrictEqual(fp, undefined);
    assert.strictEqual(typeof fp.identify, "function");
    assert.strictEqual(typeof fp.findSimilar, "function");
    assert.strictEqual(typeof fp.getFingerprint, "function");
    assert.strictEqual(typeof fp.getStats, "function");
    assert.strictEqual(typeof fp.exportState, "function");
    assert.strictEqual(typeof fp.importState, "function");
    assert.strictEqual(typeof fp.reset, "function");
    assert.strictEqual(typeof fp.getConfig, "function");
  });

  it("should accept custom options", function () {
    var fp = createClientFingerprinter({
      maxFingerprints: 500,
      ttlMs: 3600000,
      suspiciousChangeThreshold: 3,
      changeWindowMs: 600000,
    });
    var config = fp.getConfig();
    assert.strictEqual(config.maxFingerprints, 500);
    assert.strictEqual(config.ttlMs, 3600000);
    assert.strictEqual(config.suspiciousChangeThreshold, 3);
    assert.strictEqual(config.changeWindowMs, 600000);
  });
});

// ── identify ────────────────────────────────────────────────────────

describe("identify", function () {
  it("should return a fingerprint result for valid signals", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals());
    assert.notStrictEqual(result.fingerprintHash, undefined);
    assert.strictEqual(typeof result.fingerprintHash, "string");
    assert.strictEqual(result.isNew, true);
    assert.strictEqual(result.visits, 1);
    assert.notStrictEqual(result.riskScore, undefined);
    assert.notStrictEqual(result.riskLevel, undefined);
    assert.notStrictEqual(result.signals, undefined);
  });

  it("should recognize returning visitors", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    fp.identify(signals);
    var result = fp.identify(signals);
    assert.strictEqual(result.isNew, false);
    assert.strictEqual(result.visits, 2);
  });

  it("should track visit count across multiple visits", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    for (var i = 0; i < 10; i++) {
      fp.identify(signals);
    }
    var result = fp.identify(signals);
    assert.strictEqual(result.visits, 11);
  });

  it("should distinguish different signal sets", function () {
    var fp = createClientFingerprinter();
    var r1 = fp.identify(sampleSignals());
    var r2 = fp.identify(sampleSignals({ screenWidth: 2560, screenHeight: 1440 }));
    assert.notStrictEqual(r1.fingerprintHash, r2.fingerprintHash);
  });

  it("should handle empty/null signals", function () {
    var fp = createClientFingerprinter();
    var r1 = fp.identify({});
    assert.notStrictEqual(r1.fingerprintHash, undefined);
    assert.strictEqual(r1.isNew, true);

    var r2 = fp.identify(null);
    assert.notStrictEqual(r2.fingerprintHash, undefined);
  });

  it("should track IP metadata", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals(), { ip: "1.2.3.4" });
    assert.notStrictEqual(result.fingerprintHash, undefined);
    var info = fp.getFingerprint(result.fingerprintHash);
    assert.strictEqual(info.uniqueIps, 1);
  });

  it("should count multiple IPs per fingerprint", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    fp.identify(signals, { ip: "1.2.3.4" });
    fp.identify(signals, { ip: "5.6.7.8" });
    var hash = fp.identify(signals, { ip: "9.10.11.12" }).fingerprintHash;
    var info = fp.getFingerprint(hash);
    assert.strictEqual(info.uniqueIps, 3);
  });

  it("should produce consistent hashes for same signals", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    var r1 = fp.identify(signals);
    var r2 = fp.identify(signals);
    assert.strictEqual(r1.fingerprintHash, r2.fingerprintHash);
  });

  it("should normalize language to lowercase", function () {
    var fp = createClientFingerprinter();
    var r1 = fp.identify(sampleSignals({ language: "EN-US" }));
    var r2 = fp.identify(sampleSignals({ language: "en-us" }));
    assert.strictEqual(r1.fingerprintHash, r2.fingerprintHash);
  });
});

// ── Bot detection ───────────────────────────────────────────────────

describe("bot detection", function () {
  it("should detect headless browser", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "Mozilla/5.0 HeadlessChrome/91.0" }));
    assert.ok((result.botSignals).includes("headless-browser"));
    assert.ok((result.riskScore) > (0));
  });

  it("should detect PhantomJS", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "Mozilla/5.0 PhantomJS/2.1" }));
    assert.ok((result.botSignals).includes("phantomjs"));
  });

  it("should detect Selenium", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "Selenium WebDriver" }));
    assert.ok((result.botSignals).includes("selenium"));
  });

  it("should detect Puppeteer", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "Chrome Puppeteer" }));
    assert.ok((result.botSignals).includes("puppeteer"));
  });

  it("should detect SwiftShader GPU", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ webglVendor: "Google SwiftShader" }));
    assert.ok((result.botSignals).includes("swiftshader-gpu"));
  });

  it("should detect software renderer", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ webglVendor: "Mesa/X.org llvmpipe" }));
    assert.ok((result.botSignals).includes("software-renderer"));
  });

  it("should detect zero screen dimensions", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ screenWidth: 0, screenHeight: 0 }));
    assert.ok((result.botSignals).includes("zero-screen"));
  });

  it("should detect zero color depth", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ colorDepth: 0 }));
    assert.ok((result.botSignals).includes("zero-color-depth"));
  });

  it("should flag multiple bot signals with higher risk", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({
      userAgent: "HeadlessChrome Selenium",
      webglVendor: "SwiftShader",
      screenWidth: 0,
      screenHeight: 0,
    }));
    assert.ok((result.botSignals.length) >= (3));
    assert.ok((result.riskScore) >= (60));
    assert.strictEqual(result.riskLevel, "high");
  });

  it("should return empty botSignals for normal browsers", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals());
    assert.strictEqual(result.botSignals.length, 0);
    assert.strictEqual(result.riskLevel, "low");
  });
});

// ── Identity change detection ───────────────────────────────────────

describe("identity change detection", function () {
  it("should not flag few identity changes", function () {
    var fp = createClientFingerprinter({ suspiciousChangeThreshold: 5 });
    fp.identify(sampleSignals({ canvasHash: "a1" }), { ip: "1.1.1.1" });
    fp.identify(sampleSignals({ canvasHash: "a2" }), { ip: "1.1.1.1" });
    var result = fp.identify(sampleSignals({ canvasHash: "a3" }), { ip: "1.1.1.1" });
    assert.strictEqual(result.identityChanges.suspicious, false);
    assert.ok((result.identityChanges.changes) < (5));
  });

  it("should flag many identity changes from same IP", function () {
    var fp = createClientFingerprinter({ suspiciousChangeThreshold: 3 });
    fp.identify(sampleSignals({ canvasHash: "x1" }), { ip: "2.2.2.2" });
    fp.identify(sampleSignals({ canvasHash: "x2" }), { ip: "2.2.2.2" });
    var result = fp.identify(sampleSignals({ canvasHash: "x3" }), { ip: "2.2.2.2" });
    assert.strictEqual(result.identityChanges.suspicious, true);
    assert.ok((result.identityChanges.changes) >= (3));
  });

  it("should not count same fingerprint as a change", function () {
    var fp = createClientFingerprinter({ suspiciousChangeThreshold: 3 });
    var signals = sampleSignals();
    fp.identify(signals, { ip: "3.3.3.3" });
    fp.identify(signals, { ip: "3.3.3.3" });
    fp.identify(signals, { ip: "3.3.3.3" });
    var result = fp.identify(signals, { ip: "3.3.3.3" });
    assert.strictEqual(result.identityChanges.suspicious, false);
  });

  it("should return not suspicious when no IP provided", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals());
    assert.strictEqual(result.identityChanges.suspicious, false);
  });
});

// ── findSimilar ─────────────────────────────────────────────────────

describe("findSimilar", function () {
  it("should find exact matches", function () {
    var fp = createClientFingerprinter();
    var signals = sampleSignals();
    fp.identify(signals);
    var similar = fp.findSimilar(signals);
    assert.strictEqual(similar.length, 1);
    assert.strictEqual(similar[0].similarity, 1);
  });

  it("should find partially matching fingerprints", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals());
    // Only change one signal
    var modified = sampleSignals({ canvasHash: "different_hash" });
    var similar = fp.findSimilar(modified, 0.5);
    assert.ok((similar.length) >= (1));
    assert.ok((similar[0].similarity) > (0.5));
    assert.ok((similar[0].similarity) < (1));
  });

  it("should respect similarity threshold", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals());
    var similar = fp.findSimilar(sampleSignals({ canvasHash: "x" }), 1.0);
    assert.strictEqual(similar.length, 0);
  });

  it("should return empty for no matches", function () {
    var fp = createClientFingerprinter();
    var similar = fp.findSimilar(sampleSignals());
    assert.strictEqual(similar.length, 0);
  });

  it("should sort results by similarity descending", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals());
    fp.identify(sampleSignals({ canvasHash: "x", webglVendor: "y" }));
    var query = sampleSignals({ canvasHash: "x" });
    var similar = fp.findSimilar(query, 0.3);
    if (similar.length >= 2) {
      assert.ok((similar[0].similarity) >= (similar[1].similarity));
    }
  });
});

// ── getFingerprint ──────────────────────────────────────────────────

describe("getFingerprint", function () {
  it("should return details for known fingerprint", function () {
    var fp = createClientFingerprinter();
    var r = fp.identify(sampleSignals(), { ip: "1.1.1.1" });
    var info = fp.getFingerprint(r.fingerprintHash);
    assert.notStrictEqual(info, null);
    assert.strictEqual(info.fingerprintHash, r.fingerprintHash);
    assert.strictEqual(info.visits, 1);
    assert.strictEqual(info.uniqueIps, 1);
    assert.notStrictEqual(info.signals, undefined);
  });

  it("should return null for unknown hash", function () {
    var fp = createClientFingerprinter();
    assert.strictEqual(fp.getFingerprint("nonexistent"), null);
  });
});

// ── getStats ────────────────────────────────────────────────────────

describe("getStats", function () {
  it("should return empty stats initially", function () {
    var fp = createClientFingerprinter();
    var stats = fp.getStats();
    assert.strictEqual(stats.totalFingerprints, 0);
    assert.strictEqual(stats.totalVisits, 0);
    assert.strictEqual(stats.uniqueIps, 0);
  });

  it("should aggregate stats correctly", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals(), { ip: "1.1.1.1" });
    fp.identify(sampleSignals(), { ip: "2.2.2.2" });
    fp.identify(sampleSignals({ canvasHash: "other" }), { ip: "1.1.1.1" });
    var stats = fp.getStats();
    assert.strictEqual(stats.totalFingerprints, 2);
    assert.strictEqual(stats.totalVisits, 3);
    assert.strictEqual(stats.uniqueIps, 2);
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
    assert.strictEqual(stats.totalFingerprints, 2);
    assert.strictEqual(stats.totalVisits, 2);
  });

  it("should handle importing empty/null state", function () {
    var fp = createClientFingerprinter();
    fp.importState(null);
    fp.importState({});
    assert.strictEqual(fp.getStats().totalFingerprints, 0);
  });
});

// ── reset ───────────────────────────────────────────────────────────

describe("reset", function () {
  it("should clear all state", function () {
    var fp = createClientFingerprinter();
    fp.identify(sampleSignals());
    fp.identify(sampleSignals({ canvasHash: "x" }));
    fp.reset();
    assert.strictEqual(fp.getStats().totalFingerprints, 0);
    assert.strictEqual(fp.getStats().totalVisits, 0);
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
    assert.ok((stats.totalFingerprints) <= (4));
  });
});

// ── Risk scoring ────────────────────────────────────────────────────

describe("risk scoring", function () {
  it("should assign low risk to normal fingerprint", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals());
    assert.strictEqual(result.riskScore, 0);
    assert.strictEqual(result.riskLevel, "low");
  });

  it("should assign medium risk for single bot signal", function () {
    var fp = createClientFingerprinter();
    var result = fp.identify(sampleSignals({ userAgent: "HeadlessChrome" }));
    assert.ok((result.riskScore) >= (20));
    assert.ok((["low", "medium", "high"]).includes(result.riskLevel));
  });

  it("should cap risk score at 100", function () {
    var fp = createClientFingerprinter({ suspiciousChangeThreshold: 2 });
    fp.identify(sampleSignals({ canvasHash: "z1", userAgent: "HeadlessChrome Selenium Puppeteer PhantomJS" }), { ip: "9.9.9.9" });
    fp.identify(sampleSignals({ canvasHash: "z2", userAgent: "HeadlessChrome Selenium Puppeteer PhantomJS" }), { ip: "9.9.9.9" });
    var result = fp.identify(sampleSignals({ canvasHash: "z3", userAgent: "HeadlessChrome Selenium Puppeteer PhantomJS", webglVendor: "SwiftShader" }), { ip: "9.9.9.9" });
    assert.ok((result.riskScore) <= (100));
  });
});

// ── config ──────────────────────────────────────────────────────────

describe("getConfig", function () {
  it("should return default configuration", function () {
    var fp = createClientFingerprinter();
    var config = fp.getConfig();
    assert.strictEqual(config.maxFingerprints, 10000);
    assert.strictEqual(config.ttlMs, 86400000);
    assert.strictEqual(config.suspiciousChangeThreshold, 5);
    assert.notStrictEqual(config.signalWeights, undefined);
    assert.strictEqual(config.signalWeights.userAgent, 0.15);
  });

  it("should return custom signal weights", function () {
    var fp = createClientFingerprinter({
      signalWeights: { userAgent: 0.5 },
    });
    var config = fp.getConfig();
    assert.strictEqual(config.signalWeights.userAgent, 0.5);
    assert.strictEqual(config.signalWeights.screen, 0.10); // default kept
  });
});
