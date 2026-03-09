"use strict";

var _mod = require("../src/challenge-rotation-scheduler");
var createChallengeRotationScheduler = _mod.createChallengeRotationScheduler;

describe("createChallengeRotationScheduler", function () {
  var scheduler;

  afterEach(function () {
    if (scheduler) {
      try { scheduler.stop(); } catch (_) {}
      try { scheduler.reset(); } catch (_) {}
    }
  });

  // ── Construction ──────────────────────────────────────────

  describe("construction", function () {
    test("creates with default options", function () {
      scheduler = createChallengeRotationScheduler();
      expect(scheduler.getStrategy()).toBe("round-robin");
      expect(scheduler.isRunning()).toBe(false);
      expect(scheduler.getCurrentType()).toBeNull();
    });

    test("accepts custom options", function () {
      scheduler = createChallengeRotationScheduler({
        strategy: "weighted-random",
        rotationIntervalMs: 120000,
        cooldownMs: 5000,
      });
      expect(scheduler.getStrategy()).toBe("weighted-random");
    });

    test("throws on invalid strategy", function () {
      expect(function () {
        createChallengeRotationScheduler({ strategy: "bad" });
      }).toThrow(/Invalid strategy/);
    });
  });

  // ── Challenge type management ─────────────────────────────

  describe("addChallengeType", function () {
    beforeEach(function () {
      scheduler = createChallengeRotationScheduler();
    });

    test("adds a type with defaults", function () {
      var result = scheduler.addChallengeType({ id: "color_shape" });
      expect(result.id).toBe("color_shape");
      expect(result.weight).toBe(1);
      expect(result.enabled).toBe(true);
    });

    test("adds a type with custom weight", function () {
      var result = scheduler.addChallengeType({ id: "seq", weight: 5 });
      expect(result.weight).toBe(5);
    });

    test("throws on missing id", function () {
      expect(function () { scheduler.addChallengeType({}); }).toThrow();
      expect(function () { scheduler.addChallengeType({ id: "" }); }).toThrow();
      expect(function () { scheduler.addChallengeType(null); }).toThrow();
    });

    test("throws on duplicate id", function () {
      scheduler.addChallengeType({ id: "a" });
      expect(function () { scheduler.addChallengeType({ id: "a" }); }).toThrow(/already registered/);
    });

    test("trims whitespace from id", function () {
      var result = scheduler.addChallengeType({ id: "  padded  " });
      expect(result.id).toBe("padded");
    });

    test("defaults enabled to true", function () {
      var result = scheduler.addChallengeType({ id: "t1" });
      expect(result.enabled).toBe(true);
    });

    test("can add disabled type", function () {
      var result = scheduler.addChallengeType({ id: "t1", enabled: false });
      expect(result.enabled).toBe(false);
    });
  });

  describe("removeChallengeType", function () {
    beforeEach(function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
    });

    test("removes existing type", function () {
      expect(scheduler.removeChallengeType("a")).toBe(true);
      expect(scheduler.getTypes().length).toBe(1);
    });

    test("returns false for nonexistent", function () {
      expect(scheduler.removeChallengeType("nope")).toBe(false);
    });

    test("triggers rotation if removed type was current", function () {
      scheduler.start();
      var current = scheduler.getCurrentType();
      scheduler.removeChallengeType(current);
      // Should rotate to remaining type
      expect(scheduler.getCurrentType()).not.toBeNull();
    });
  });

  describe("setTypeEnabled / setTypeWeight", function () {
    beforeEach(function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
    });

    test("disables type", function () {
      expect(scheduler.setTypeEnabled("a", false)).toBe(true);
      var types = scheduler.getTypes();
      var a = types.find(function (t) { return t.id === "a"; });
      expect(a.enabled).toBe(false);
    });

    test("returns false for nonexistent type", function () {
      expect(scheduler.setTypeEnabled("nope", true)).toBe(false);
    });

    test("triggers rotation when current type is disabled", function () {
      scheduler.start();
      var current = scheduler.getCurrentType();
      scheduler.setTypeEnabled(current, false);
      expect(scheduler.getCurrentType()).not.toBe(current);
    });

    test("updates weight", function () {
      expect(scheduler.setTypeWeight("a", 10)).toBe(true);
      var a = scheduler.getTypes().find(function (t) { return t.id === "a"; });
      expect(a.weight).toBe(10);
    });

    test("throws on invalid weight", function () {
      expect(function () { scheduler.setTypeWeight("a", -1); }).toThrow();
      expect(function () { scheduler.setTypeWeight("a", 0); }).toThrow();
    });

    test("returns false for nonexistent type weight", function () {
      expect(scheduler.setTypeWeight("nope", 5)).toBe(false);
    });
  });

  describe("getTypes", function () {
    test("returns empty array initially", function () {
      scheduler = createChallengeRotationScheduler();
      expect(scheduler.getTypes()).toEqual([]);
    });

    test("includes stats for each type", function () {
      scheduler = createChallengeRotationScheduler();
      scheduler.addChallengeType({ id: "a" });
      scheduler.recordSolve("a", true, 1000);
      var types = scheduler.getTypes();
      expect(types[0].stats).toBeDefined();
      expect(types[0].stats.total).toBe(1);
      expect(types[0].stats.solved).toBe(1);
    });

    test("marks active type", function () {
      scheduler = createChallengeRotationScheduler();
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();
      var types = scheduler.getTypes();
      var active = types.filter(function (t) { return t.active; });
      expect(active.length).toBe(1);
    });
  });

  // ── Rotation strategies ───────────────────────────────────

  describe("round-robin rotation", function () {
    beforeEach(function () {
      scheduler = createChallengeRotationScheduler({ strategy: "round-robin", cooldownMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.addChallengeType({ id: "c" });
      scheduler.start();
    });

    test("cycles through types in order", function () {
      var first = scheduler.getCurrentType();
      expect(first).toBe("a");

      scheduler.rotate(true);
      expect(scheduler.getCurrentType()).toBe("b");

      scheduler.rotate(true);
      expect(scheduler.getCurrentType()).toBe("c");

      scheduler.rotate(true);
      expect(scheduler.getCurrentType()).toBe("a");
    });

    test("skips disabled types", function () {
      scheduler.setTypeEnabled("b", false);
      scheduler.rotate(true);
      // Should skip b, go to c
      expect(["a", "c"]).toContain(scheduler.getCurrentType());
    });
  });

  describe("weighted-random rotation", function () {
    test("picks based on weights (deterministic seed)", function () {
      scheduler = createChallengeRotationScheduler({
        strategy: "weighted-random",
        cooldownMs: 0,
        seed: 42,
      });
      scheduler.addChallengeType({ id: "heavy", weight: 100 });
      scheduler.addChallengeType({ id: "light", weight: 1 });
      scheduler.start();

      // With weight 100:1, most rotations should land on 'heavy'
      var heavyCount = 0;
      for (var i = 0; i < 20; i++) {
        scheduler.rotate(true);
        if (scheduler.getCurrentType() === "heavy") heavyCount++;
      }
      expect(heavyCount).toBeGreaterThanOrEqual(10);
    });

    test("avoids picking same type twice in a row", function () {
      scheduler = createChallengeRotationScheduler({
        strategy: "weighted-random",
        cooldownMs: 0,
        seed: 123,
      });
      scheduler.addChallengeType({ id: "a", weight: 1 });
      scheduler.addChallengeType({ id: "b", weight: 1 });
      scheduler.start();

      for (var i = 0; i < 10; i++) {
        var before = scheduler.getCurrentType();
        scheduler.rotate(true);
        expect(scheduler.getCurrentType()).not.toBe(before);
      }
    });
  });

  describe("performance-based rotation", function () {
    test("picks type with solve rate closest to target band", function () {
      scheduler = createChallengeRotationScheduler({
        strategy: "performance-based",
        cooldownMs: 0,
        targetSolveRateMin: 0.5,
        targetSolveRateMax: 0.8,
      });
      scheduler.addChallengeType({ id: "easy" });
      scheduler.addChallengeType({ id: "medium" });
      scheduler.addChallengeType({ id: "hard" });
      scheduler.start(); // starts on "easy"

      // Make 'medium' have ~65% solve rate (in target band, midpoint=0.65)
      for (var i = 0; i < 20; i++) {
        scheduler.recordSolve("medium", i < 13, 2000);
      }
      // Make 'hard' have 20% solve rate (far from target)
      for (var k = 0; k < 20; k++) {
        scheduler.recordSolve("hard", k < 4, 5000);
      }

      // Current is "easy" (no stats = defaults to midpoint).
      // Rotate should pick the non-current type closest to midpoint.
      // "medium" (0.65) vs "hard" (0.20) — medium wins.
      scheduler.rotate(true);
      expect(scheduler.getCurrentType()).toBe("medium");
    });
  });

  // ── Solve tracking ────────────────────────────────────────

  describe("recordSolve", function () {
    beforeEach(function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "test" });
    });

    test("records and tracks solve stats", function () {
      scheduler.recordSolve("test", true, 3000);
      scheduler.recordSolve("test", false, 5000);
      var stats = scheduler.getTypeStats("test");
      expect(stats.total).toBe(2);
      expect(stats.solved).toBe(1);
      expect(stats.failed).toBe(1);
      expect(stats.solveRate).toBe(0.5);
      expect(stats.avgTimeMs).toBe(4000);
    });

    test("throws on invalid typeId", function () {
      expect(function () { scheduler.recordSolve("", true); }).toThrow();
      expect(function () { scheduler.recordSolve(null, true); }).toThrow();
    });

    test("throws on non-boolean solved", function () {
      expect(function () { scheduler.recordSolve("test", "yes"); }).toThrow();
    });

    test("handles solve without time", function () {
      scheduler.recordSolve("test", true);
      var stats = scheduler.getTypeStats("test");
      expect(stats.avgTimeMs).toBeNull();
    });

    test("records solves for unregistered types", function () {
      scheduler.recordSolve("unknown", true, 1000);
      var stats = scheduler.getTypeStats("unknown");
      expect(stats.total).toBe(1);
    });
  });

  describe("solve-count-based rotation", function () {
    test("rotates after N solves", function () {
      scheduler = createChallengeRotationScheduler({
        cooldownMs: 0,
        rotationAfterSolves: 5,
        rotationIntervalMs: 0,
      });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();
      expect(scheduler.getCurrentType()).toBe("a");

      for (var i = 0; i < 4; i++) {
        scheduler.recordSolve("a", true, 1000);
      }
      expect(scheduler.getCurrentType()).toBe("a"); // not yet

      scheduler.recordSolve("a", true, 1000); // 5th solve
      expect(scheduler.getCurrentType()).toBe("b"); // rotated
    });
  });

  describe("emergency rotation", function () {
    test("triggers on high solve rate", function () {
      scheduler = createChallengeRotationScheduler({
        cooldownMs: 0,
        emergencySolveRateThreshold: 0.9,
        emergencyMinSamples: 5,
        rotationIntervalMs: 0,
      });
      scheduler.addChallengeType({ id: "compromised" });
      scheduler.addChallengeType({ id: "fresh" });
      scheduler.start();
      expect(scheduler.getCurrentType()).toBe("compromised");

      // 5 consecutive solves = 100% rate > 0.9 threshold
      for (var i = 0; i < 5; i++) {
        scheduler.recordSolve("compromised", true, 500);
      }
      expect(scheduler.getCurrentType()).toBe("fresh");
    });
  });

  // ── Cooldown ──────────────────────────────────────────────

  describe("cooldown", function () {
    test("respects cooldown on manual rotate", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 999999 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();

      var result = scheduler.rotate();
      expect(result.reason).toBe("cooldown_active");
      expect(scheduler.getCurrentType()).toBe("a");
    });

    test("force=true bypasses cooldown", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 999999 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();

      var result = scheduler.rotate(true);
      expect(result.reason).toBe("manual");
      expect(scheduler.getCurrentType()).toBe("b");
    });
  });

  // ── Event system ──────────────────────────────────────────

  describe("events", function () {
    test("emits rotation event", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();

      var events = [];
      scheduler.on("rotation", function (data) { events.push(data); });
      scheduler.rotate(true);
      expect(events.length).toBe(1);
      expect(events[0].from).toBe("a");
      expect(events[0].to).toBe("b");
    });

    test("unsubscribes with off", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();

      var count = 0;
      var handler = function () { count++; };
      scheduler.on("rotation", handler);
      scheduler.rotate(true);
      expect(count).toBe(1);

      scheduler.off("rotation", handler);
      scheduler.rotate(true);
      expect(count).toBe(1); // not incremented
    });

    test("emits start event", function () {
      scheduler = createChallengeRotationScheduler();
      scheduler.addChallengeType({ id: "a" });
      var started = false;
      scheduler.on("start", function () { started = true; });
      scheduler.start();
      expect(started).toBe(true);
    });

    test("emits stop event", function () {
      scheduler = createChallengeRotationScheduler();
      scheduler.addChallengeType({ id: "a" });
      scheduler.start();
      var stopped = false;
      scheduler.on("stop", function () { stopped = true; });
      scheduler.stop();
      expect(stopped).toBe(true);
    });

    test("listener errors do not propagate", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();

      scheduler.on("rotation", function () { throw new Error("boom"); });
      expect(function () { scheduler.rotate(true); }).not.toThrow();
    });
  });

  // ── Strategy switching ────────────────────────────────────

  describe("setStrategy", function () {
    test("switches strategy at runtime", function () {
      scheduler = createChallengeRotationScheduler();
      scheduler.setStrategy("weighted-random");
      expect(scheduler.getStrategy()).toBe("weighted-random");
    });

    test("throws on invalid strategy", function () {
      scheduler = createChallengeRotationScheduler();
      expect(function () { scheduler.setStrategy("bad"); }).toThrow();
    });
  });

  // ── State persistence ─────────────────────────────────────

  describe("exportState / importState", function () {
    test("roundtrip preserves state", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "a", weight: 3 });
      scheduler.addChallengeType({ id: "b", weight: 2 });
      scheduler.start();
      scheduler.rotate(true);

      var state = scheduler.exportState();
      expect(state.types.length).toBe(2);
      expect(state.currentTypeId).toBe("b");
      expect(state.totalRotations).toBeGreaterThan(0);

      var fresh = createChallengeRotationScheduler({ cooldownMs: 0 });
      fresh.importState(state);
      expect(fresh.getCurrentType()).toBe("b");
      expect(fresh.getTypes().length).toBe(2);
    });

    test("importState throws on invalid input", function () {
      scheduler = createChallengeRotationScheduler();
      expect(function () { scheduler.importState(null); }).toThrow();
      expect(function () { scheduler.importState("bad"); }).toThrow();
    });
  });

  describe("reset", function () {
    test("clears all state", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.start();
      scheduler.recordSolve("a", true, 1000);
      scheduler.reset();

      expect(scheduler.getTypes()).toEqual([]);
      expect(scheduler.getCurrentType()).toBeNull();
      expect(scheduler.isRunning()).toBe(false);
      expect(scheduler.getSummary().totalRotations).toBe(0);
    });
  });

  // ── getSummary ────────────────────────────────────────────

  describe("getSummary", function () {
    test("returns comprehensive summary", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();
      scheduler.rotate(true);

      var summary = scheduler.getSummary();
      expect(summary.strategy).toBe("round-robin");
      expect(summary.running).toBe(true);
      expect(summary.currentType).toBeDefined();
      expect(summary.totalTypes).toBe(2);
      expect(summary.enabledTypes).toBe(2);
      expect(summary.totalRotations).toBeGreaterThan(0);
      expect(summary.recentRotations.length).toBeGreaterThan(0);
    });
  });

  // ── Edge cases ────────────────────────────────────────────

  describe("edge cases", function () {
    test("rotate with no types returns null", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      var result = scheduler.rotate(true);
      expect(result.to).toBeNull();
      expect(result.reason).toBe("no_enabled_types");
    });

    test("rotate with single type stays on it", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0 });
      scheduler.addChallengeType({ id: "only" });
      scheduler.start();
      scheduler.rotate(true);
      expect(scheduler.getCurrentType()).toBe("only");
    });

    test("start is idempotent", function () {
      scheduler = createChallengeRotationScheduler();
      scheduler.addChallengeType({ id: "a" });
      scheduler.start();
      scheduler.start(); // no-op
      expect(scheduler.isRunning()).toBe(true);
    });

    test("stop is safe when not running", function () {
      scheduler = createChallengeRotationScheduler();
      expect(function () { scheduler.stop(); }).not.toThrow();
    });

    test("getTypeStats for unknown type returns zeros", function () {
      scheduler = createChallengeRotationScheduler();
      var stats = scheduler.getTypeStats("nonexistent");
      expect(stats.total).toBe(0);
      expect(stats.solveRate).toBeNull();
    });
  });
});
