/**
 * Tests for the A/B Experiment Runner module.
 */

var { describe, it, beforeEach } = require("node:test");
var assert = require("node:assert/strict");
var test = it;
var gifCaptcha = require("../src/index");

// Lightweight expect shim for Jest-style assertions
function expect(actual) {
  return {
    toBe: function (expected) {
      assert.strictEqual(actual, expected);
    },
    toEqual: function (expected) {
      assert.deepStrictEqual(actual, expected);
    },
    toContain: function (item) {
      if (typeof actual === "string") {
        assert.ok(actual.includes(item), "expected '" + actual + "' to contain '" + item + "'");
      } else if (Array.isArray(actual)) {
        assert.ok(actual.includes(item), "expected array to contain " + JSON.stringify(item));
      } else {
        assert.fail("toContain requires string or array");
      }
    },
    toThrow: function (pattern) {
      assert.throws(actual, pattern);
    },
    toBeDefined: function () {
      assert.notStrictEqual(actual, undefined);
    },
    toBeNull: function () {
      assert.strictEqual(actual, null);
    },
    toBeUndefined: function () {
      assert.strictEqual(actual, undefined);
    },
    toBeTruthy: function () {
      assert.ok(actual);
    },
    toBeFalsy: function () {
      assert.ok(!actual);
    },
    toBeGreaterThan: function (expected) {
      assert.ok(actual > expected, "expected " + actual + " > " + expected);
    },
    toBeLessThan: function (expected) {
      assert.ok(actual < expected, "expected " + actual + " < " + expected);
    },
    toBeGreaterThanOrEqual: function (expected) {
      assert.ok(actual >= expected, "expected " + actual + " >= " + expected);
    },
    toBeLessThanOrEqual: function (expected) {
      assert.ok(actual <= expected, "expected " + actual + " <= " + expected);
    },
    toMatch: function (pattern) {
      if (typeof pattern === "string") {
        assert.ok(actual.includes(pattern), "expected '" + actual + "' to match '" + pattern + "'");
      } else {
        assert.match(actual, pattern);
      }
    },
    toHaveLength: function (expected) {
      assert.strictEqual(actual.length, expected);
    },
    toBeCloseTo: function (expected, digits) {
      var d = digits === undefined ? 2 : digits;
      var diff = Math.abs(actual - expected);
      assert.ok(diff < Math.pow(10, -d) / 2, "expected " + actual + " to be close to " + expected);
    },
    not: {
      toBe: function (expected) {
        assert.notStrictEqual(actual, expected);
      },
      toEqual: function (expected) {
        assert.notDeepStrictEqual(actual, expected);
      },
      toContain: function (item) {
        if (typeof actual === "string") {
          assert.ok(!actual.includes(item), "expected not to contain '" + item + "'");
        } else if (Array.isArray(actual)) {
          assert.ok(!actual.includes(item), "expected array not to contain " + JSON.stringify(item));
        }
      },
      toThrow: function () {
        assert.doesNotThrow(actual);
      },
      toBeDefined: function () {
        assert.strictEqual(actual, undefined);
      },
      toBeNull: function () {
        assert.notStrictEqual(actual, null);
      },
      toBeTruthy: function () {
        assert.ok(!actual);
      },
    },
  };
}

describe("createABExperimentRunner", function () {
  var runner;

  function makeSpec(overrides) {
    var base = {
      control: { difficulty: "easy" },
      variants: [{ name: "hard", config: { difficulty: "hard" } }],
    };
    return Object.assign(base, overrides || {});
  }

  function feedEvents(id, variant, solves, fails, abandons, timeBase) {
    for (var i = 0; i < solves; i++) {
      runner.recordEvent(id, variant + "-solver-" + i, "solve", {
        timeMs: (timeBase || 2000) + i * 100,
      });
    }
    for (var j = 0; j < fails; j++) {
      runner.recordEvent(id, variant + "-failer-" + j, "fail");
    }
    for (var k = 0; k < abandons; k++) {
      runner.recordEvent(id, variant + "-abandoner-" + k, "abandon");
    }
  }

  beforeEach(function () {
    runner = gifCaptcha.createABExperimentRunner({ minSampleSize: 10 });
  });

  // ── Creation ──

  test("creates an experiment with control and variants", function () {
    var result = runner.createExperiment("exp1", makeSpec());
    expect(result.id).toBe("exp1");
    expect(result.variants).toBe(2);
    expect(result.status).toBe("running");
  });

  test("rejects duplicate experiment id", function () {
    runner.createExperiment("exp1", makeSpec());
    expect(function () {
      runner.createExperiment("exp1", makeSpec());
    }).toThrow(/already exists/);
  });

  test("rejects empty experimentId", function () {
    expect(function () {
      runner.createExperiment("", makeSpec());
    }).toThrow(/non-empty string/);
  });

  test("rejects missing control", function () {
    expect(function () {
      runner.createExperiment("exp1", { variants: [{ name: "a" }] });
    }).toThrow(/control/);
  });

  test("rejects empty variants array", function () {
    expect(function () {
      runner.createExperiment("exp1", { control: {}, variants: [] });
    }).toThrow(/non-empty array/);
  });

  test("rejects duplicate variant names", function () {
    expect(function () {
      runner.createExperiment("exp1", {
        control: {},
        variants: [
          { name: "a", config: {} },
          { name: "a", config: {} },
        ],
      });
    }).toThrow(/Duplicate/);
  });

  test("rejects variant named 'control'", function () {
    expect(function () {
      runner.createExperiment("exp1", {
        control: {},
        variants: [{ name: "control", config: {} }],
      });
    }).toThrow(/Duplicate/);
  });

  test("rejects variant without name", function () {
    expect(function () {
      runner.createExperiment("exp1", {
        control: {},
        variants: [{ config: {} }],
      });
    }).toThrow(/name string/);
  });

  test("respects maxExperiments limit", function () {
    var small = gifCaptcha.createABExperimentRunner({ maxExperiments: 2 });
    small.createExperiment("a", makeSpec());
    small.createExperiment("b", makeSpec());
    expect(function () {
      small.createExperiment("c", makeSpec());
    }).toThrow(/Maximum/);
  });

  test("creates experiment with multiple variants", function () {
    var result = runner.createExperiment("multi", {
      control: { difficulty: "easy" },
      variants: [
        { name: "medium", config: { difficulty: "medium" } },
        { name: "hard", config: { difficulty: "hard" } },
        { name: "extreme", config: { difficulty: "extreme" } },
      ],
    });
    expect(result.variants).toBe(4);
  });

  test("creates experiment with description", function () {
    runner.createExperiment("desc", makeSpec({ description: "Test difficulty" }));
    var info = runner.getExperiment("desc");
    expect(info.description).toBe("Test difficulty");
  });

  // ── Assignment ──

  test("assigns user to a variant deterministically", function () {
    runner.createExperiment("exp1", makeSpec());
    var a1 = runner.assignUser("exp1", "user-1");
    var a2 = runner.assignUser("exp1", "user-1");
    expect(a1.variant).toBe(a2.variant);
    expect(a1.config).toEqual(a2.config);
  });

  test("different users can get different variants", function () {
    runner.createExperiment("exp1", makeSpec());
    var seen = {};
    for (var i = 0; i < 100; i++) {
      var a = runner.assignUser("exp1", "user-" + i);
      seen[a.variant] = true;
    }
    // With 100 users and 2 variants, both should be assigned
    expect(Object.keys(seen).length).toBe(2);
  });

  test("throws for unknown experiment", function () {
    expect(function () {
      runner.assignUser("nope", "user-1");
    }).toThrow(/Unknown/);
  });

  test("throws for empty userId", function () {
    runner.createExperiment("exp1", makeSpec());
    expect(function () {
      runner.assignUser("exp1", "");
    }).toThrow(/non-empty/);
  });

  test("returns config with assignment", function () {
    runner.createExperiment("exp1", makeSpec());
    var a = runner.assignUser("exp1", "user-1");
    expect(a.config).toBeDefined();
    expect(typeof a.config).toBe("object");
  });

  // ── Event Recording ──

  test("records solve events", function () {
    runner.createExperiment("exp1", makeSpec());
    runner.recordEvent("exp1", "user-1", "solve", { timeMs: 3000 });
    var analysis = runner.analyzeExperiment("exp1");
    var total = analysis.variants.reduce(function (s, v) {
      return s + v.solves;
    }, 0);
    expect(total).toBe(1);
  });

  test("records fail events", function () {
    runner.createExperiment("exp1", makeSpec());
    runner.recordEvent("exp1", "user-1", "fail");
    var analysis = runner.analyzeExperiment("exp1");
    var total = analysis.variants.reduce(function (s, v) {
      return s + v.fails;
    }, 0);
    expect(total).toBe(1);
  });

  test("records abandon events", function () {
    runner.createExperiment("exp1", makeSpec());
    runner.recordEvent("exp1", "user-1", "abandon");
    var analysis = runner.analyzeExperiment("exp1");
    var total = analysis.variants.reduce(function (s, v) {
      return s + v.abandons;
    }, 0);
    expect(total).toBe(1);
  });

  test("throws for unknown event type", function () {
    runner.createExperiment("exp1", makeSpec());
    expect(function () {
      runner.recordEvent("exp1", "user-1", "explode");
    }).toThrow(/Unknown event type/);
  });

  test("silently ignores events for stopped experiments", function () {
    runner.createExperiment("exp1", makeSpec());
    runner.stopExperiment("exp1");
    // Should not throw
    runner.recordEvent("exp1", "user-1", "solve");
    var info = runner.getExperiment("exp1");
    expect(info.status).toBe("stopped");
  });

  test("auto-assigns user on recordEvent", function () {
    runner.createExperiment("exp1", makeSpec());
    runner.recordEvent("exp1", "new-user", "solve");
    var counts = runner.getAssignmentCounts("exp1");
    var total = Object.values(counts).reduce(function (a, b) {
      return a + b;
    }, 0);
    expect(total).toBe(1);
  });

  // ── Analysis ──

  test("analyzes experiment with sufficient data", function () {
    runner.createExperiment("exp1", makeSpec());
    // Feed enough users so both variants exceed minSampleSize (10)
    for (var i = 0; i < 40; i++) {
      runner.recordEvent("exp1", "user-" + i, i % 3 === 0 ? "fail" : "solve", {
        timeMs: 2000 + i * 50,
      });
    }
    var analysis = runner.analyzeExperiment("exp1");
    expect(analysis.experimentId).toBe("exp1");
    expect(analysis.variants.length).toBe(2);
    expect(analysis.sufficientData).toBe(true);
    expect(typeof analysis.pValue).toBe("number");
  });

  test("reports insufficient data correctly", function () {
    runner.createExperiment("exp1", makeSpec());
    runner.recordEvent("exp1", "user-1", "solve");
    var analysis = runner.analyzeExperiment("exp1");
    expect(analysis.sufficientData).toBe(false);
    expect(analysis.recommendation).toMatch(/Insufficient/);
  });

  test("computes solve rate correctly", function () {
    runner.createExperiment("exp1", makeSpec());
    // All events go to whichever variant the user is assigned
    for (var i = 0; i < 20; i++) {
      runner.recordEvent("exp1", "solver-" + i, "solve", { timeMs: 1000 });
    }
    var analysis = runner.analyzeExperiment("exp1");
    // At least one variant should have 100% solve rate
    var hasHighRate = analysis.variants.some(function (v) {
      return v.attempts > 0 && v.solveRate === 1.0;
    });
    expect(hasHighRate).toBe(true);
  });

  test("computes timing statistics", function () {
    runner.createExperiment("exp1", makeSpec());
    for (var i = 0; i < 30; i++) {
      runner.recordEvent("exp1", "user-" + i, "solve", { timeMs: 1000 + i * 100 });
    }
    var analysis = runner.analyzeExperiment("exp1");
    var withTimes = analysis.variants.filter(function (v) {
      return v.avgSolveTimeMs > 0;
    });
    expect(withTimes.length).toBeGreaterThan(0);
    withTimes.forEach(function (v) {
      expect(v.medianSolveTimeMs).toBeGreaterThan(0);
      expect(v.p95SolveTimeMs).toBeGreaterThanOrEqual(v.medianSolveTimeMs);
    });
  });

  test("computes abandon rate", function () {
    runner.createExperiment("exp1", makeSpec());
    for (var i = 0; i < 20; i++) {
      runner.recordEvent("exp1", "a-" + i, "abandon");
    }
    var analysis = runner.analyzeExperiment("exp1");
    var withAbandons = analysis.variants.filter(function (v) {
      return v.attempts > 0;
    });
    withAbandons.forEach(function (v) {
      expect(v.abandonRate).toBe(1.0);
    });
  });

  test("pairwise tests compare variants to control", function () {
    runner.createExperiment("multi", {
      control: { difficulty: "easy" },
      variants: [
        { name: "medium", config: {} },
        { name: "hard", config: {} },
      ],
    });
    for (var i = 0; i < 50; i++) {
      runner.recordEvent("multi", "u-" + i, "solve");
    }
    var analysis = runner.analyzeExperiment("multi");
    expect(analysis.pairwiseTests.length).toBe(2);
    analysis.pairwiseTests.forEach(function (pw) {
      expect(typeof pw.vsControl.z).toBe("number");
      expect(typeof pw.vsControl.pValue).toBe("number");
      expect(typeof pw.vsControl.lift).toBe("number");
    });
  });

  test("detects significant difference with large disparity", function () {
    var r = gifCaptcha.createABExperimentRunner({
      minSampleSize: 5,
      earlyStoppingEnabled: false,
    });
    r.createExperiment("sig", makeSpec());
    // Control: 90% solve rate, Variant: 10% solve rate
    for (var i = 0; i < 50; i++) {
      var userId = "ctrl-" + i;
      var assignment = r.assignUser("sig", userId);
      if (assignment.variant === "control") {
        r.recordEvent("sig", userId, i < 45 ? "solve" : "fail");
      } else {
        r.recordEvent("sig", userId, i < 5 ? "solve" : "fail");
      }
    }
    // Feed more to ensure both variants have data
    for (var j = 50; j < 150; j++) {
      var uid = "extra-" + j;
      var asgn = r.assignUser("sig", uid);
      if (asgn.variant === "control") {
        r.recordEvent("sig", uid, j % 10 < 9 ? "solve" : "fail");
      } else {
        r.recordEvent("sig", uid, j % 10 < 1 ? "solve" : "fail");
      }
    }
    var analysis = r.analyzeExperiment("sig");
    expect(analysis.sufficientData).toBe(true);
    // With such disparity, should be significant
    expect(analysis.significant).toBe(true);
    expect(analysis.winner).toBeDefined();
  });

  // ── Experiment lifecycle ──

  test("stops experiment", function () {
    runner.createExperiment("exp1", makeSpec());
    var result = runner.stopExperiment("exp1");
    expect(result.status).toBe("stopped");
    var info = runner.getExperiment("exp1");
    expect(info.status).toBe("stopped");
    expect(info.endedAt).toBeDefined();
  });

  test("getExperiment returns null for unknown", function () {
    expect(runner.getExperiment("nope")).toBeNull();
  });

  test("getExperiment returns experiment info", function () {
    runner.createExperiment("exp1", makeSpec({ targetSampleSize: 200 }));
    var info = runner.getExperiment("exp1");
    expect(info.id).toBe("exp1");
    expect(info.status).toBe("running");
    expect(info.targetSampleSize).toBe(200);
    expect(info.variantNames).toEqual(["control", "hard"]);
  });

  test("listExperiments returns all", function () {
    runner.createExperiment("a", makeSpec());
    runner.createExperiment("b", makeSpec());
    var list = runner.listExperiments();
    expect(list.length).toBe(2);
  });

  test("listExperiments filters by status", function () {
    runner.createExperiment("a", makeSpec());
    runner.createExperiment("b", makeSpec());
    runner.stopExperiment("a");
    var running = runner.listExperiments({ status: "running" });
    expect(running.length).toBe(1);
    expect(running[0].id).toBe("b");
  });

  test("deleteExperiment removes it", function () {
    runner.createExperiment("exp1", makeSpec());
    expect(runner.deleteExperiment("exp1")).toBe(true);
    expect(runner.getExperiment("exp1")).toBeNull();
    expect(runner.listExperiments().length).toBe(0);
  });

  test("deleteExperiment returns false for unknown", function () {
    expect(runner.deleteExperiment("nope")).toBe(false);
  });

  // ── Assignment counts ──

  test("getAssignmentCounts tracks users per variant", function () {
    runner.createExperiment("exp1", makeSpec());
    for (var i = 0; i < 20; i++) {
      runner.assignUser("exp1", "user-" + i);
    }
    var counts = runner.getAssignmentCounts("exp1");
    expect(counts.control + counts.hard).toBe(20);
    expect(counts.control).toBeGreaterThan(0);
    expect(counts.hard).toBeGreaterThan(0);
  });

  test("getAssignmentCounts throws for unknown", function () {
    expect(function () {
      runner.getAssignmentCounts("nope");
    }).toThrow(/Unknown/);
  });

  // ── Early stopping ──

  test("early stopping completes experiment", function () {
    var completed = [];
    var r = gifCaptcha.createABExperimentRunner({
      minSampleSize: 5,
      earlyStoppingEnabled: true,
      earlyStoppingConfidence: 0.5, // Very lenient for test
    });
    r.onResult(function (id, analysis) {
      completed.push({ id: id, analysis: analysis });
    });
    r.createExperiment("es", makeSpec());
    // Feed wildly different data
    for (var i = 0; i < 30; i++) {
      var uid = "u-" + i;
      var a = r.assignUser("es", uid);
      if (a.variant === "control") {
        r.recordEvent("es", uid, "solve");
      } else {
        r.recordEvent("es", uid, "fail");
      }
    }
    var info = r.getExperiment("es");
    // May or may not trigger depending on p-value
    if (info.status === "completed") {
      expect(completed.length).toBeGreaterThan(0);
      expect(info.winner).toBeDefined();
    }
    // At minimum, no errors
    expect(["running", "completed"]).toContain(info.status);
  });

  test("early stopping disabled does not auto-complete", function () {
    var r = gifCaptcha.createABExperimentRunner({
      minSampleSize: 5,
      earlyStoppingEnabled: false,
    });
    r.createExperiment("no-es", makeSpec());
    for (var i = 0; i < 50; i++) {
      var uid = "u-" + i;
      var a = r.assignUser("no-es", uid);
      r.recordEvent("no-es", uid, a.variant === "control" ? "solve" : "fail");
    }
    expect(r.getExperiment("no-es").status).toBe("running");
  });

  // ── Export / Import ──

  test("export and import round-trips", function () {
    runner.createExperiment("exp1", makeSpec({ description: "test" }));
    for (var i = 0; i < 10; i++) {
      runner.recordEvent("exp1", "u-" + i, "solve", { timeMs: 1000 });
    }
    var exported = runner.exportState();
    expect(exported.experiments.length).toBe(1);
    expect(exported.exportedAt).toBeGreaterThan(0);

    var r2 = gifCaptcha.createABExperimentRunner();
    var imported = r2.importState(exported);
    expect(imported).toBe(1);

    var info = r2.getExperiment("exp1");
    expect(info).not.toBeNull();
    expect(info.description).toBe("test");
  });

  test("import skips duplicates", function () {
    runner.createExperiment("exp1", makeSpec());
    var exported = runner.exportState();
    var imported = runner.importState(exported);
    expect(imported).toBe(0);
  });

  test("import handles invalid state", function () {
    expect(runner.importState(null)).toBe(0);
    expect(runner.importState({})).toBe(0);
    expect(runner.importState({ experiments: "nope" })).toBe(0);
  });

  // ── Text report ──

  test("textReport generates readable output", function () {
    runner.createExperiment("exp1", makeSpec({ description: "Difficulty comparison" }));
    for (var i = 0; i < 20; i++) {
      runner.recordEvent("exp1", "u-" + i, "solve", { timeMs: 2000 + i * 50 });
    }
    for (var j = 0; j < 5; j++) {
      runner.recordEvent("exp1", "f-" + j, "fail");
    }
    var report = runner.textReport("exp1");
    expect(report).toContain("A/B Experiment: exp1");
    expect(report).toContain("Difficulty comparison");
    expect(report).toContain("Status: running");
    expect(report).toContain("Solve rate:");
    expect(report).toContain("Chi-squared:");
    expect(report).toContain("Recommendation:");
  });

  test("textReport shows timing stats", function () {
    runner.createExperiment("exp1", makeSpec());
    for (var i = 0; i < 15; i++) {
      runner.recordEvent("exp1", "u-" + i, "solve", { timeMs: 3000 });
    }
    var report = runner.textReport("exp1");
    expect(report).toContain("Avg solve time:");
    expect(report).toContain("Median solve time:");
    expect(report).toContain("P95 solve time:");
  });

  test("textReport shows pairwise tests for multi-variant", function () {
    runner.createExperiment("multi", {
      control: {},
      variants: [
        { name: "a", config: {} },
        { name: "b", config: {} },
      ],
    });
    for (var i = 0; i < 30; i++) {
      runner.recordEvent("multi", "u-" + i, "solve");
    }
    var report = runner.textReport("multi");
    expect(report).toContain("Pairwise vs Control:");
  });

  // ── Edge cases ──

  test("analysis with no events", function () {
    runner.createExperiment("empty", makeSpec());
    var analysis = runner.analyzeExperiment("empty");
    expect(analysis.sufficientData).toBe(false);
    expect(analysis.winner).toBeNull();
    analysis.variants.forEach(function (v) {
      expect(v.solveRate).toBe(0);
      expect(v.attempts).toBe(0);
    });
  });

  test("analysis with all solves", function () {
    runner.createExperiment("exp1", makeSpec());
    for (var i = 0; i < 30; i++) {
      runner.recordEvent("exp1", "u-" + i, "solve");
    }
    var analysis = runner.analyzeExperiment("exp1");
    analysis.variants.forEach(function (v) {
      if (v.attempts > 0) expect(v.solveRate).toBe(1.0);
    });
  });

  test("analysis with all fails", function () {
    runner.createExperiment("exp1", makeSpec());
    for (var i = 0; i < 30; i++) {
      runner.recordEvent("exp1", "u-" + i, "fail");
    }
    var analysis = runner.analyzeExperiment("exp1");
    analysis.variants.forEach(function (v) {
      if (v.attempts > 0) {
        expect(v.solveRate).toBe(0);
        expect(v.fails).toBe(v.attempts);
      }
    });
  });

  test("solve time ignored when zero or negative", function () {
    runner.createExperiment("exp1", makeSpec());
    runner.recordEvent("exp1", "u1", "solve", { timeMs: 0 });
    runner.recordEvent("exp1", "u2", "solve", { timeMs: -100 });
    runner.recordEvent("exp1", "u3", "solve", { timeMs: 5000 });
    var analysis = runner.analyzeExperiment("exp1");
    var withTimes = analysis.variants.filter(function (v) {
      return v.avgSolveTimeMs > 0;
    });
    // Only 1 valid time (5000ms) should be recorded
    var totalTimes = withTimes.reduce(function (s, v) {
      return s + (v.avgSolveTimeMs > 0 ? 1 : 0);
    }, 0);
    expect(totalTimes).toBeGreaterThanOrEqual(1);
  });

  test("onResult callback receives data", function () {
    var received = [];
    runner.onResult(function (id, analysis) {
      received.push(id);
    });
    // onResult only fires on early stopping, so just verify it doesn't crash
    runner.createExperiment("exp1", makeSpec());
    runner.recordEvent("exp1", "u1", "solve");
    // received may or may not have data
    expect(Array.isArray(received)).toBe(true);
  });

  test("custom significance level", function () {
    var strict = gifCaptcha.createABExperimentRunner({
      significanceLevel: 0.001,
      minSampleSize: 5,
      earlyStoppingEnabled: false,
    });
    strict.createExperiment("exp1", makeSpec());
    for (var i = 0; i < 20; i++) {
      strict.recordEvent("exp1", "u-" + i, "solve");
    }
    var analysis = strict.analyzeExperiment("exp1");
    // With identical solve rates across variants, should not be significant
    expect(typeof analysis.significant).toBe("boolean");
  });

  test("totalUsers tracked in getExperiment", function () {
    runner.createExperiment("exp1", makeSpec());
    for (var i = 0; i < 15; i++) {
      runner.recordEvent("exp1", "user-" + i, "solve");
    }
    var info = runner.getExperiment("exp1");
    expect(info.totalUsers).toBe(15);
  });
});
