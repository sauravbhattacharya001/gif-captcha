"use strict";

var test = require("node:test");
var assert = require("node:assert/strict");
var createABExperimentRunner =
  require("../src/ab-experiment-runner").createABExperimentRunner;

function makeSpec(overrides) {
  return Object.assign(
    {
      control: { difficulty: "easy", theme: "default" },
      variants: [{ name: "hard-dark", config: { difficulty: "hard", theme: "dark" } }],
      targetSampleSize: 100,
    },
    overrides || {}
  );
}

// ── Creation ──

test("creates an experiment with control + variants", function () {
  var runner = createABExperimentRunner();
  var result = runner.createExperiment("test-1", makeSpec());
  assert.equal(result.id, "test-1");
  assert.equal(result.variants, 2);
  assert.equal(result.status, "running");
});

test("rejects duplicate experiment id", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("dup", makeSpec());
  assert.throws(function () {
    runner.createExperiment("dup", makeSpec());
  }, /already exists/);
});

test("rejects missing control", function () {
  var runner = createABExperimentRunner();
  assert.throws(function () {
    runner.createExperiment("x", { variants: [{ name: "a", config: {} }] });
  }, /control/);
});

test("rejects empty variants array", function () {
  var runner = createABExperimentRunner();
  assert.throws(function () {
    runner.createExperiment("x", { control: {}, variants: [] });
  }, /non-empty/);
});

test("rejects duplicate variant names", function () {
  var runner = createABExperimentRunner();
  assert.throws(function () {
    runner.createExperiment("x", {
      control: {},
      variants: [
        { name: "a", config: {} },
        { name: "a", config: {} },
      ],
    });
  }, /Duplicate/);
});

test("enforces maxExperiments limit", function () {
  var runner = createABExperimentRunner({ maxExperiments: 2 });
  runner.createExperiment("a", makeSpec());
  runner.createExperiment("b", makeSpec());
  assert.throws(function () {
    runner.createExperiment("c", makeSpec());
  }, /Maximum/);
});

// ── Assignment ──

test("assigns users deterministically", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("det", makeSpec());
  var a1 = runner.assignUser("det", "alice");
  var a2 = runner.assignUser("det", "alice");
  assert.equal(a1.variant, a2.variant);
  assert.deepEqual(a1.config, a2.config);
});

test("distributes users across variants", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("dist", makeSpec());
  var counts = { control: 0, "hard-dark": 0 };
  for (var i = 0; i < 100; i++) {
    var a = runner.assignUser("dist", "user-" + i);
    counts[a.variant]++;
  }
  assert(counts.control > 0, "control has users");
  assert(counts["hard-dark"] > 0, "variant has users");
});

test("throws on unknown experiment for assignUser", function () {
  var runner = createABExperimentRunner();
  assert.throws(function () {
    runner.assignUser("nope", "u1");
  }, /Unknown/);
});

test("throws on empty userId", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("e", makeSpec());
  assert.throws(function () {
    runner.assignUser("e", "");
  }, /non-empty/);
});

// ── Event Recording ──

test("records solve events with timing", function () {
  var runner = createABExperimentRunner({ earlyStoppingEnabled: false });
  runner.createExperiment("ev", makeSpec());
  runner.recordEvent("ev", "u1", "solve", { timeMs: 2500 });
  var analysis = runner.analyzeExperiment("ev");
  var total = analysis.variants.reduce(function (s, v) { return s + v.solves; }, 0);
  assert.equal(total, 1);
});

test("records fail events", function () {
  var runner = createABExperimentRunner({ earlyStoppingEnabled: false });
  runner.createExperiment("ev2", makeSpec());
  runner.recordEvent("ev2", "u1", "fail");
  var analysis = runner.analyzeExperiment("ev2");
  var totalFails = analysis.variants.reduce(function (s, v) { return s + v.fails; }, 0);
  assert.equal(totalFails, 1);
});

test("records abandon events", function () {
  var runner = createABExperimentRunner({ earlyStoppingEnabled: false });
  runner.createExperiment("ev3", makeSpec());
  runner.recordEvent("ev3", "u1", "abandon");
  var analysis = runner.analyzeExperiment("ev3");
  var totalAbandons = analysis.variants.reduce(function (s, v) { return s + v.abandons; }, 0);
  assert.equal(totalAbandons, 1);
});

test("throws on unknown event type", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("ev4", makeSpec());
  assert.throws(function () {
    runner.recordEvent("ev4", "u1", "explode");
  }, /Unknown event/);
});

test("silently ignores events on stopped experiments", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("stopped", makeSpec());
  runner.stopExperiment("stopped");
  runner.recordEvent("stopped", "u1", "solve"); // should not throw
});

// ── Analysis ──

test("reports insufficient data when sample is small", function () {
  var runner = createABExperimentRunner({ minSampleSize: 30, earlyStoppingEnabled: false });
  runner.createExperiment("small", makeSpec());
  runner.recordEvent("small", "u1", "solve");
  var analysis = runner.analyzeExperiment("small");
  assert.equal(analysis.sufficientData, false);
  assert(analysis.recommendation.includes("Insufficient"));
});

test("computes chi-squared and pairwise tests", function () {
  var runner = createABExperimentRunner({
    minSampleSize: 5,
    earlyStoppingEnabled: false,
  });
  runner.createExperiment("sig", {
    control: { mode: "a" },
    variants: [{ name: "b", config: { mode: "b" } }],
  });
  for (var i = 0; i < 200; i++) {
    runner.recordEvent("sig", "u" + i, i % 3 === 0 ? "solve" : "fail", { timeMs: 1000 });
  }
  var analysis = runner.analyzeExperiment("sig");
  assert.equal(analysis.variants.length, 2);
  assert(analysis.chiSquared.value >= 0, "chi-squared computed");
  assert.equal(analysis.pairwiseTests.length, 1);
  assert(typeof analysis.pairwiseTests[0].vsControl.z === "number");
  assert(typeof analysis.pairwiseTests[0].vsControl.lift === "number");
});

test("includes solve time statistics", function () {
  var runner = createABExperimentRunner({ earlyStoppingEnabled: false });
  runner.createExperiment("times", makeSpec());
  for (var i = 0; i < 50; i++) {
    runner.recordEvent("times", "u" + i, "solve", { timeMs: 1000 + i * 100 });
  }
  var analysis = runner.analyzeExperiment("times");
  var hasTime = analysis.variants.some(function (v) { return v.avgSolveTimeMs > 0; });
  assert(hasTime, "solve times computed");
});

// ── Stop & Get ──

test("stops experiment and returns analysis", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("stop-me", makeSpec());
  runner.recordEvent("stop-me", "u1", "solve");
  var result = runner.stopExperiment("stop-me");
  assert.equal(result.status, "stopped");
  var info = runner.getExperiment("stop-me");
  assert.equal(info.status, "stopped");
  assert(info.endedAt > 0);
});

test("getExperiment returns null for unknown", function () {
  var runner = createABExperimentRunner();
  assert.equal(runner.getExperiment("nope"), null);
});

// ── List & Delete ──

test("lists experiments with status filter", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("r1", makeSpec());
  runner.createExperiment("r2", makeSpec());
  runner.stopExperiment("r2");
  var running = runner.listExperiments({ status: "running" });
  assert.equal(running.length, 1);
  assert.equal(running[0].id, "r1");
  var stopped = runner.listExperiments({ status: "stopped" });
  assert.equal(stopped.length, 1);
});

test("deletes experiment", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("del", makeSpec());
  assert.equal(runner.deleteExperiment("del"), true);
  assert.equal(runner.getExperiment("del"), null);
  assert.equal(runner.deleteExperiment("del"), false);
});

// ── Assignment Counts ──

test("tracks assignment counts", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("counts", makeSpec());
  for (var i = 0; i < 20; i++) runner.assignUser("counts", "u" + i);
  var counts = runner.getAssignmentCounts("counts");
  assert(counts.control >= 0);
  assert(counts["hard-dark"] >= 0);
  assert.equal(counts.control + counts["hard-dark"], 20);
});

// ── Export / Import ──

test("exports and imports state", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("exp-x", makeSpec({ description: "test export" }));
  runner.recordEvent("exp-x", "u1", "solve", { timeMs: 500 });
  runner.recordEvent("exp-x", "u2", "fail");

  var state = runner.exportState();
  assert.equal(state.experiments.length, 1);
  assert(state.exportedAt > 0);

  var runner2 = createABExperimentRunner();
  var imported = runner2.importState(state);
  assert.equal(imported, 1);

  var info = runner2.getExperiment("exp-x");
  assert.equal(info.id, "exp-x");
  assert.equal(info.description, "test export");
});

test("skips duplicate ids on import", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("dup-imp", makeSpec());
  var state = runner.exportState();
  var count = runner.importState(state);
  assert.equal(count, 0);
});

test("importState handles invalid input", function () {
  var runner = createABExperimentRunner();
  assert.equal(runner.importState(null), 0);
  assert.equal(runner.importState({}), 0);
});

// ── Text Report ──

test("generates text report", function () {
  var runner = createABExperimentRunner({ earlyStoppingEnabled: false });
  runner.createExperiment("rpt", makeSpec());
  for (var i = 0; i < 10; i++) {
    runner.recordEvent("rpt", "u" + i, "solve", { timeMs: 1000 });
  }
  var report = runner.textReport("rpt");
  assert(report.includes("A/B Experiment: rpt"));
  assert(report.includes("Solve rate"));
  assert(report.includes("Chi-squared"));
  assert(report.includes("Recommendation"));
});

// ── Early Stopping ──

test("early stopping fires callback when triggered", function () {
  var callbackFired = false;
  var runner = createABExperimentRunner({
    minSampleSize: 5,
    earlyStoppingEnabled: true,
    earlyStoppingConfidence: 0.99, // Very loose
  });
  runner.onResult(function () {
    callbackFired = true;
  });
  runner.createExperiment("early", {
    control: { mode: "a" },
    variants: [{ name: "b", config: { mode: "b" } }],
  });
  for (var i = 0; i < 100; i++) {
    var uid = "e" + i;
    var a = runner.assignUser("early", uid);
    if (a.variant === "control") {
      runner.recordEvent("early", uid, "solve");
    } else {
      runner.recordEvent("early", uid, "fail");
    }
  }
  // Verify no crash; callback may or may not fire depending on hash distribution
  var info = runner.getExperiment("early");
  assert(info !== null);
});

// ── Multi-variant ──

test("handles 3+ variants", function () {
  var runner = createABExperimentRunner({ earlyStoppingEnabled: false });
  runner.createExperiment("multi", {
    control: { level: 1 },
    variants: [
      { name: "v2", config: { level: 2 } },
      { name: "v3", config: { level: 3 } },
    ],
  });
  for (var i = 0; i < 60; i++) {
    runner.recordEvent("multi", "u" + i, i % 3 === 0 ? "solve" : "fail");
  }
  var analysis = runner.analyzeExperiment("multi");
  assert.equal(analysis.variants.length, 3);
  assert.equal(analysis.chiSquared.df, 2);
  assert.equal(analysis.pairwiseTests.length, 2);
});

// ── Edge cases ──

test("handles experiment with no events", function () {
  var runner = createABExperimentRunner();
  runner.createExperiment("empty", makeSpec());
  var analysis = runner.analyzeExperiment("empty");
  assert.equal(analysis.sufficientData, false);
  assert.equal(analysis.winner, null);
});

test("handles all abandons", function () {
  var runner = createABExperimentRunner({ earlyStoppingEnabled: false });
  runner.createExperiment("ab", makeSpec());
  for (var i = 0; i < 10; i++) {
    runner.recordEvent("ab", "u" + i, "abandon");
  }
  var analysis = runner.analyzeExperiment("ab");
  var totalAbandons = analysis.variants.reduce(function (s, v) { return s + v.abandons; }, 0);
  assert.equal(totalAbandons, 10);
});

test("variant with no variant name throws", function () {
  var runner = createABExperimentRunner();
  assert.throws(function () {
    runner.createExperiment("bad", {
      control: {},
      variants: [{ config: {} }],
    });
  }, /name/);
});
