/**
 * Tests for Behavioral Biometrics Analyzer
 */

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { createBehavioralBiometrics } = require("../src/behavioral-biometrics");

// Helper: generate human-like mouse trail
function humanMouseTrail(analyzer, n, baseTime) {
  var t = baseTime || 1000;
  var x = 100, y = 100;
  for (var i = 0; i < n; i++) {
    x += Math.sin(i * 0.5) * 20 + (Math.random() - 0.5) * 10;
    y += Math.cos(i * 0.3) * 15 + (Math.random() - 0.5) * 8;
    t += 15 + Math.random() * 30;
    analyzer.recordMouseMove(x, y, t);
  }
}

// Helper: generate bot-like mouse trail (straight line, constant speed)
function botMouseTrail(analyzer, n, baseTime) {
  var t = baseTime || 1000;
  for (var i = 0; i < n; i++) {
    analyzer.recordMouseMove(100 + i * 5, 100 + i * 5, t + i * 16);
  }
}

describe("createBehavioralBiometrics", function () {
  it("returns an analyzer with expected API", function () {
    var b = createBehavioralBiometrics();
    assert.equal(typeof b.recordMouseMove, "function");
    assert.equal(typeof b.recordClick, "function");
    assert.equal(typeof b.recordKeystroke, "function");
    assert.equal(typeof b.recordScroll, "function");
    assert.equal(typeof b.analyze, "function");
    assert.equal(typeof b.getRiskLevel, "function");
    assert.equal(typeof b.reset, "function");
    assert.equal(typeof b.getEventCounts, "function");
    assert.equal(typeof b.exportEvents, "function");
  });

  it("starts with zero events", function () {
    var b = createBehavioralBiometrics();
    var counts = b.getEventCounts();
    assert.equal(counts.total, 0);
    assert.equal(counts.mouse, 0);
    assert.equal(counts.clicks, 0);
  });

  it("records mouse events", function () {
    var b = createBehavioralBiometrics();
    b.recordMouseMove(10, 20, 1000);
    b.recordMouseMove(30, 40, 1020);
    assert.equal(b.getEventCounts().mouse, 2);
  });

  it("respects maxEvents limit", function () {
    var b = createBehavioralBiometrics({ maxEvents: 3 });
    for (var i = 0; i < 10; i++) b.recordMouseMove(i, i, 1000 + i);
    assert.equal(b.getEventCounts().mouse, 3);
  });

  it("records click events", function () {
    var b = createBehavioralBiometrics();
    b.recordClick(50, 60, "left", 1000);
    b.recordClick(70, 80, "right", 1100);
    assert.equal(b.getEventCounts().clicks, 2);
  });

  it("ignores keystrokes when collectKeystrokes is false", function () {
    var b = createBehavioralBiometrics();
    b.recordKeystroke(100, 1000);
    assert.equal(b.getEventCounts().keystrokes, 0);
  });

  it("records keystrokes when collectKeystrokes is true", function () {
    var b = createBehavioralBiometrics({ collectKeystrokes: true });
    b.recordKeystroke(100, 1000);
    b.recordKeystroke(80, 1200);
    assert.equal(b.getEventCounts().keystrokes, 2);
  });

  it("records scroll events", function () {
    var b = createBehavioralBiometrics();
    b.recordScroll(100, 1000);
    b.recordScroll(-50, 1200);
    assert.equal(b.getEventCounts().scrolls, 2);
  });

  it("reset clears all events", function () {
    var b = createBehavioralBiometrics();
    b.recordMouseMove(10, 20, 1000);
    b.recordClick(30, 40, "left", 1100);
    b.recordScroll(50, 1200);
    b.reset();
    assert.equal(b.getEventCounts().total, 0);
  });
});

describe("analyzeMouseMovement", function () {
  it("returns insufficient when too few events", function () {
    var b = createBehavioralBiometrics();
    b.recordMouseMove(10, 20, 1000);
    var result = b.analyzeMouseMovement();
    assert.equal(result.sufficient, false);
    assert.equal(result.score, 0);
  });

  it("scores human-like mouse movement higher", function () {
    var b = createBehavioralBiometrics();
    humanMouseTrail(b, 30);
    var result = b.analyzeMouseMovement();
    assert.equal(result.sufficient, true);
    assert.ok(result.score > 0, "human trail should have positive score");
    assert.ok(result.metrics.speedCV > 0, "should have speed variability");
  });

  it("scores bot-like movement lower than human-like", function () {
    var human = createBehavioralBiometrics();
    humanMouseTrail(human, 30);
    var humanScore = human.analyzeMouseMovement().score;

    var bot = createBehavioralBiometrics();
    botMouseTrail(bot, 30);
    var botScore = bot.analyzeMouseMovement().score;

    assert.ok(humanScore > botScore, "human score (" + humanScore + ") should exceed bot score (" + botScore + ")");
  });

  it("includes metrics in result", function () {
    var b = createBehavioralBiometrics();
    humanMouseTrail(b, 20);
    var result = b.analyzeMouseMovement();
    assert.ok("speedMean" in result.metrics);
    assert.ok("speedStddev" in result.metrics);
    assert.ok("angleEntropy" in result.metrics);
    assert.ok("curvatureRatio" in result.metrics);
  });
});

describe("analyzeClicks", function () {
  it("returns insufficient with fewer than minClicks", function () {
    var b = createBehavioralBiometrics();
    b.recordClick(10, 20, "left", 1000);
    assert.equal(b.analyzeClicks().sufficient, false);
  });

  it("scores varied click positions and timing higher", function () {
    var b = createBehavioralBiometrics();
    b.recordClick(50, 60, "left", 1000);
    b.recordClick(200, 150, "left", 1800);
    b.recordClick(80, 300, "left", 2900);
    b.recordClick(400, 100, "left", 3500);
    var result = b.analyzeClicks();
    assert.equal(result.sufficient, true);
    assert.ok(result.score > 0);
  });

  it("detects duplicate click positions as bot-like", function () {
    var b = createBehavioralBiometrics();
    for (var i = 0; i < 5; i++) b.recordClick(100, 100, "left", 1000 + i * 100);
    var result = b.analyzeClicks();
    assert.ok(result.metrics.duplicateRatio > 0, "duplicate clicks should be flagged");
  });
});

describe("analyzeKeystrokes", function () {
  it("returns insufficient when collectKeystrokes is off", function () {
    var b = createBehavioralBiometrics();
    assert.equal(b.analyzeKeystrokes().sufficient, false);
  });

  it("analyzes keystroke timing when enabled", function () {
    var b = createBehavioralBiometrics({ collectKeystrokes: true });
    b.recordKeystroke(80, 1000);
    b.recordKeystroke(120, 1250);
    b.recordKeystroke(95, 1480);
    b.recordKeystroke(110, 1700);
    var result = b.analyzeKeystrokes();
    assert.equal(result.sufficient, true);
    assert.ok(result.score > 0);
    assert.ok(result.metrics.humanRangeRatio > 0);
  });
});

describe("analyzeScrolls", function () {
  it("returns insufficient with <2 scroll events", function () {
    var b = createBehavioralBiometrics();
    b.recordScroll(100, 1000);
    assert.equal(b.analyzeScrolls().sufficient, false);
  });

  it("scores direction changes as more human-like", function () {
    var b = createBehavioralBiometrics();
    b.recordScroll(100, 1000);
    b.recordScroll(-50, 1200);
    b.recordScroll(80, 1500);
    b.recordScroll(-30, 1700);
    var result = b.analyzeScrolls();
    assert.equal(result.sufficient, true);
    assert.ok(result.metrics.directionChanges >= 2);
  });
});

describe("analyze (combined)", function () {
  it("returns combined analysis with all signal types", function () {
    var b = createBehavioralBiometrics({ collectKeystrokes: true });
    humanMouseTrail(b, 20);
    b.recordClick(50, 60, "left", 2000);
    b.recordClick(200, 150, "left", 2800);
    b.recordClick(80, 300, "left", 3900);
    b.recordKeystroke(80, 4000);
    b.recordKeystroke(120, 4250);
    b.recordKeystroke(95, 4480);
    b.recordScroll(100, 5000);
    b.recordScroll(-50, 5200);
    b.recordScroll(80, 5500);

    var result = b.analyze();
    assert.ok(result.score >= 0 && result.score <= 1);
    assert.equal(typeof result.isLikelyHuman, "boolean");
    assert.ok(result.signalCount >= 3, "should have at least 3 signal types");
    assert.ok(result.totalEvents > 0);
    assert.equal(typeof result.threshold, "number");
  });

  it("marks no-data sessions as not human", function () {
    var b = createBehavioralBiometrics();
    var result = b.analyze();
    assert.equal(result.score, 0);
    assert.equal(result.isLikelyHuman, false);
    assert.equal(result.signalCount, 0);
  });

  it("respects custom humanScoreThreshold", function () {
    var b = createBehavioralBiometrics({ humanScoreThreshold: 0.9 });
    humanMouseTrail(b, 10);
    var result = b.analyze();
    assert.equal(result.threshold, 0.9);
  });
});

describe("getRiskLevel", function () {
  it("returns high risk with no data", function () {
    var b = createBehavioralBiometrics();
    var risk = b.getRiskLevel();
    assert.equal(risk.risk, "high");
    assert.ok(risk.reason.includes("No behavioral data"));
  });

  it("returns a risk level with data", function () {
    var b = createBehavioralBiometrics();
    humanMouseTrail(b, 30);
    b.recordClick(50, 60, "left", 3000);
    b.recordClick(200, 150, "left", 3800);
    b.recordClick(80, 300, "left", 4900);
    var risk = b.getRiskLevel();
    assert.ok(["low", "medium", "high"].indexOf(risk.risk) >= 0);
    assert.ok(typeof risk.score === "number");
    assert.ok(typeof risk.reason === "string");
  });
});

describe("exportEvents", function () {
  it("exports a copy of all events", function () {
    var b = createBehavioralBiometrics();
    b.recordMouseMove(10, 20, 1000);
    b.recordClick(30, 40, "left", 1100);
    b.recordScroll(50, 1200);

    var exported = b.exportEvents();
    assert.equal(exported.mouse.length, 1);
    assert.equal(exported.clicks.length, 1);
    assert.equal(exported.scrolls.length, 1);
    assert.equal(exported.keystrokes.length, 0);
    assert.ok(exported.exportedAt > 0);

    // Should be a copy, not a reference
    exported.mouse.push({ x: 99, y: 99, t: 9999 });
    assert.equal(b.getEventCounts().mouse, 1);
  });
});
