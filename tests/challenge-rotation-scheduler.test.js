var { describe, it, beforeEach, afterEach, mock } = require("node:test");
var assert = require("node:assert/strict");
var { createChallengeRotationScheduler } = require("../src/challenge-rotation-scheduler");

describe("createChallengeRotationScheduler", function () {
  var scheduler;

  afterEach(function () {
    if (scheduler) {
      try { scheduler.stop(); } catch (_) {}
      try { scheduler.reset(); } catch (_) {}
    }
  });

  describe("construction", function () {
    it("should create with default options", function () {
      scheduler = createChallengeRotationScheduler();
      assert.equal(scheduler.getStrategy(), "round-robin");
      assert.equal(scheduler.isRunning(), false);
      assert.equal(scheduler.getCurrentType(), null);
    });

    it("should accept custom strategy", function () {
      scheduler = createChallengeRotationScheduler({ strategy: "weighted-random", seed: 42 });
      assert.equal(scheduler.getStrategy(), "weighted-random");
    });

    it("should reject invalid strategy", function () {
      assert.throws(function () {
        createChallengeRotationScheduler({ strategy: "invalid" });
      }, /Invalid strategy/);
    });
  });

  describe("challenge type management", function () {
    beforeEach(function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, seed: 42 });
    });

    it("should add a challenge type", function () {
      var result = scheduler.addChallengeType({ id: "color_shape", weight: 3 });
      assert.equal(result.id, "color_shape");
      assert.equal(result.weight, 3);
      assert.equal(result.enabled, true);
    });

    it("should reject empty id", function () {
      assert.throws(function () {
        scheduler.addChallengeType({ id: "" });
      }, /non-empty string id/);
    });

    it("should reject missing id", function () {
      assert.throws(function () {
        scheduler.addChallengeType({});
      }, /non-empty string id/);
    });

    it("should reject duplicate ids", function () {
      scheduler.addChallengeType({ id: "a" });
      assert.throws(function () {
        scheduler.addChallengeType({ id: "a" });
      }, /already registered/);
    });

    it("should default weight to 1", function () {
      var result = scheduler.addChallengeType({ id: "a" });
      assert.equal(result.weight, 1);
    });

    it("should default enabled to true", function () {
      var result = scheduler.addChallengeType({ id: "a" });
      assert.equal(result.enabled, true);
    });

    it("should allow disabled types", function () {
      var result = scheduler.addChallengeType({ id: "a", enabled: false });
      assert.equal(result.enabled, false);
    });

    it("should remove a challenge type", function () {
      scheduler.addChallengeType({ id: "a" });
      assert.equal(scheduler.removeChallengeType("a"), true);
      assert.equal(scheduler.getTypes().length, 0);
    });

    it("should return false removing nonexistent type", function () {
      assert.equal(scheduler.removeChallengeType("nope"), false);
    });

    it("should rotate when active type is removed", function () {
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();
      assert.equal(scheduler.getCurrentType(), "a");
      scheduler.removeChallengeType("a");
      assert.equal(scheduler.getCurrentType(), "b");
    });

    it("should enable/disable types", function () {
      scheduler.addChallengeType({ id: "a" });
      scheduler.setTypeEnabled("a", false);
      var types = scheduler.getTypes();
      assert.equal(types[0].enabled, false);
    });

    it("should return false for unknown type enable", function () {
      assert.equal(scheduler.setTypeEnabled("nope", true), false);
    });

    it("should update weight", function () {
      scheduler.addChallengeType({ id: "a", weight: 1 });
      scheduler.setTypeWeight("a", 5);
      assert.equal(scheduler.getTypes()[0].weight, 5);
    });

    it("should reject invalid weight", function () {
      scheduler.addChallengeType({ id: "a" });
      assert.throws(function () {
        scheduler.setTypeWeight("a", 0);
      }, /positive number/);
    });

    it("should reject negative weight", function () {
      scheduler.addChallengeType({ id: "a" });
      assert.throws(function () {
        scheduler.setTypeWeight("a", -1);
      }, /positive number/);
    });

    it("should return false for unknown type weight", function () {
      assert.equal(scheduler.setTypeWeight("nope", 5), false);
    });
  });

  describe("rotation - round-robin", function () {
    beforeEach(function () {
      scheduler = createChallengeRotationScheduler({
        strategy: "round-robin",
        cooldownMs: 0,
        rotationIntervalMs: 0,
      });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.addChallengeType({ id: "c" });
    });

    it("should start with first enabled type", function () {
      scheduler.start();
      assert.equal(scheduler.getCurrentType(), "a");
    });

    it("should cycle through types in order", function () {
      scheduler.start();
      assert.equal(scheduler.getCurrentType(), "a");
      scheduler.rotate(true);
      assert.equal(scheduler.getCurrentType(), "b");
      scheduler.rotate(true);
      assert.equal(scheduler.getCurrentType(), "c");
      scheduler.rotate(true);
      assert.equal(scheduler.getCurrentType(), "a");
    });

    it("should skip disabled types", function () {
      scheduler.start();
      scheduler.setTypeEnabled("b", false);
      scheduler.rotate(true); // a -> c (skips b)
      assert.equal(scheduler.getCurrentType(), "c");
    });
  });

  describe("rotation - weighted-random", function () {
    it("should pick from enabled types", function () {
      scheduler = createChallengeRotationScheduler({
        strategy: "weighted-random",
        cooldownMs: 0,
        seed: 42,
      });
      scheduler.addChallengeType({ id: "a", weight: 1 });
      scheduler.addChallengeType({ id: "b", weight: 100 });
      scheduler.start();

      // Rotate many times; "b" should be picked at least once
      var pickedB = false;
      for (var i = 0; i < 20; i++) {
        scheduler.rotate(true);
        if (scheduler.getCurrentType() === "b") pickedB = true;
      }
      assert.ok(pickedB, "weighted-random should pick high-weight type");
    });
  });

  describe("rotation - performance-based", function () {
    it("should rotate to a different type", function () {
      scheduler = createChallengeRotationScheduler({
        strategy: "performance-based",
        cooldownMs: 0,
        targetSolveRateMin: 0.5,
        targetSolveRateMax: 0.8,
        statsWindowMs: 600000,
        emergencySolveRateThreshold: 0, // disable emergency rotation
        rotationIntervalMs: 0,
        rotationAfterSolves: 0,
      });
      scheduler.addChallengeType({ id: "easy" });
      scheduler.addChallengeType({ id: "medium" });
      scheduler.start();
      assert.equal(scheduler.getCurrentType(), "easy");

      // Record solves — easy is 100%, medium is ~65%
      for (var i = 0; i < 20; i++) {
        scheduler.recordSolve("easy", true, 1000);
        scheduler.recordSolve("medium", i < 13, 3000);
      }

      scheduler.rotate(true);
      // Performance-based skips current ("easy") and picks "medium"
      assert.equal(scheduler.getCurrentType(), "medium");
    });
  });

  describe("cooldown", function () {
    it("should respect cooldown on non-forced rotation", function () {
      scheduler = createChallengeRotationScheduler({
        cooldownMs: 999999, // very long cooldown
        rotationIntervalMs: 0,
      });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start(); // sets lastRotationTime

      var result = scheduler.rotate(false);
      assert.equal(result.reason, "cooldown_active");
      assert.equal(result.to, "a"); // no change
    });

    it("should bypass cooldown with force=true", function () {
      scheduler = createChallengeRotationScheduler({
        cooldownMs: 999999,
        rotationIntervalMs: 0,
      });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();

      var result = scheduler.rotate(true);
      assert.equal(result.to, "b");
    });
  });

  describe("solve tracking", function () {
    beforeEach(function () {
      scheduler = createChallengeRotationScheduler({
        cooldownMs: 0,
        statsWindowMs: 600000,
        rotationIntervalMs: 0,
      });
      scheduler.addChallengeType({ id: "a" });
    });

    it("should track solve stats", function () {
      scheduler.recordSolve("a", true, 3000);
      scheduler.recordSolve("a", false, 5000);
      scheduler.recordSolve("a", true, 2000);

      var stats = scheduler.getTypeStats("a");
      assert.equal(stats.total, 3);
      assert.equal(stats.solved, 2);
      assert.equal(stats.failed, 1);
      assert.ok(Math.abs(stats.solveRate - 0.667) < 0.01);
    });

    it("should reject non-string typeId", function () {
      assert.throws(function () {
        scheduler.recordSolve(123, true);
      }, /non-empty string/);
    });

    it("should reject non-boolean solved", function () {
      assert.throws(function () {
        scheduler.recordSolve("a", "yes");
      }, /must be a boolean/);
    });

    it("should handle unregistered typeId gracefully", function () {
      // Should not throw — creates history for unknown type
      scheduler.recordSolve("unknown_type", true, 1000);
      var stats = scheduler.getTypeStats("unknown_type");
      assert.equal(stats.total, 1);
    });
  });

  describe("emergency rotation", function () {
    it("should trigger on high solve rate", function () {
      scheduler = createChallengeRotationScheduler({
        cooldownMs: 0,
        emergencySolveRateThreshold: 0.9,
        emergencyMinSamples: 5,
        statsWindowMs: 600000,
        rotationIntervalMs: 0,
      });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();
      assert.equal(scheduler.getCurrentType(), "a");

      // Record enough solves to trigger emergency
      for (var i = 0; i < 15; i++) {
        scheduler.recordSolve("a", true, 500);
      }
      // Should have rotated away from "a"
      assert.equal(scheduler.getCurrentType(), "b");
    });
  });

  describe("solve-count rotation", function () {
    it("should rotate after N solves", function () {
      scheduler = createChallengeRotationScheduler({
        cooldownMs: 0,
        rotationAfterSolves: 3,
        rotationIntervalMs: 0,
      });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();
      assert.equal(scheduler.getCurrentType(), "a");

      scheduler.recordSolve("a", true, 1000);
      scheduler.recordSolve("a", false, 2000);
      assert.equal(scheduler.getCurrentType(), "a"); // only 2 solves

      scheduler.recordSolve("a", true, 1500); // 3rd solve triggers rotation
      assert.equal(scheduler.getCurrentType(), "b");
    });
  });

  describe("event system", function () {
    it("should emit rotation events", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();

      var events = [];
      scheduler.on("rotation", function (data) { events.push(data); });
      scheduler.rotate(true);

      assert.equal(events.length, 1);
      assert.equal(events[0].from, "a");
      assert.equal(events[0].to, "b");
      assert.equal(events[0].reason, "manual");
    });

    it("should unsubscribe with off", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();

      var count = 0;
      var handler = function () { count++; };
      scheduler.on("rotation", handler);
      scheduler.rotate(true);
      assert.equal(count, 1);

      scheduler.off("rotation", handler);
      scheduler.rotate(true);
      assert.equal(count, 1); // no increment
    });

    it("should swallow listener errors", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();

      scheduler.on("rotation", function () { throw new Error("boom"); });
      // Should not throw
      assert.doesNotThrow(function () {
        scheduler.rotate(true);
      });
    });

    it("should reject non-function handlers", function () {
      scheduler = createChallengeRotationScheduler();
      assert.throws(function () {
        scheduler.on("rotation", "not a function");
      }, /must be a function/);
    });
  });

  describe("state export/import", function () {
    it("should round-trip state", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a", weight: 2 });
      scheduler.addChallengeType({ id: "b", weight: 3 });
      scheduler.start();
      scheduler.rotate(true);

      var state = scheduler.exportState();
      assert.equal(state.currentTypeId, "b");
      assert.equal(state.types.length, 2);
      assert.equal(state.totalRotations, 1);

      // Import into new scheduler
      var s2 = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      s2.importState(state);
      assert.equal(s2.getCurrentType(), "b");
      assert.equal(s2.getTypes().length, 2);
    });

    it("should reject non-object state", function () {
      scheduler = createChallengeRotationScheduler();
      assert.throws(function () {
        scheduler.importState(null);
      }, /non-null object/);
    });
  });

  describe("strategy change at runtime", function () {
    it("should change strategy", function () {
      scheduler = createChallengeRotationScheduler({ strategy: "round-robin" });
      assert.equal(scheduler.getStrategy(), "round-robin");
      scheduler.setStrategy("weighted-random");
      assert.equal(scheduler.getStrategy(), "weighted-random");
    });

    it("should reject invalid strategy change", function () {
      scheduler = createChallengeRotationScheduler();
      assert.throws(function () {
        scheduler.setStrategy("nope");
      }, /Invalid strategy/);
    });
  });

  describe("start/stop", function () {
    it("should track running state", function () {
      scheduler = createChallengeRotationScheduler({ rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      assert.equal(scheduler.isRunning(), false);
      scheduler.start();
      assert.equal(scheduler.isRunning(), true);
      scheduler.stop();
      assert.equal(scheduler.isRunning(), false);
    });

    it("should be idempotent on double start", function () {
      scheduler = createChallengeRotationScheduler({ rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.start();
      scheduler.start(); // no error
      assert.equal(scheduler.isRunning(), true);
    });
  });

  describe("getSummary", function () {
    it("should return summary info", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();
      scheduler.rotate(true);

      var summary = scheduler.getSummary();
      assert.equal(summary.strategy, "round-robin");
      assert.equal(summary.running, true);
      assert.equal(summary.totalTypes, 2);
      assert.equal(summary.enabledTypes, 2);
      assert.equal(summary.totalRotations, 1);
    });
  });

  describe("reset", function () {
    it("should clear all state", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.start();
      scheduler.reset();

      assert.equal(scheduler.isRunning(), false);
      assert.equal(scheduler.getCurrentType(), null);
      assert.equal(scheduler.getTypes().length, 0);
    });
  });

  describe("edge cases", function () {
    it("should handle rotation with no types", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      var result = scheduler.rotate(true);
      assert.equal(result.to, null);
      assert.equal(result.reason, "no_enabled_types");
    });

    it("should handle rotation with single type", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "only" });
      scheduler.start();
      var result = scheduler.rotate(true);
      assert.equal(result.to, "only");
    });

    it("should handle all types disabled", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();
      scheduler.setTypeEnabled("a", false);
      scheduler.setTypeEnabled("b", false);
      var result = scheduler.rotate(true);
      assert.equal(result.to, null);
    });

    it("should handle disabling current type triggers rotation", function () {
      scheduler = createChallengeRotationScheduler({ cooldownMs: 0, rotationIntervalMs: 0 });
      scheduler.addChallengeType({ id: "a" });
      scheduler.addChallengeType({ id: "b" });
      scheduler.start();
      assert.equal(scheduler.getCurrentType(), "a");
      scheduler.setTypeEnabled("a", false);
      assert.equal(scheduler.getCurrentType(), "b");
    });
  });
});
