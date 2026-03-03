// @ts-check
"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  createChallenge,
  pickChallenges,
  secureRandomInt,
} = require("../src/index");

// ── Object.freeze tests ────────────────────────────────────────────

describe("createChallenge returns frozen object", function () {
  it("should return a frozen object", function () {
    const challenge = createChallenge({
      id: "freeze-1",
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "test answer",
    });
    assert.ok(Object.isFrozen(challenge), "Challenge object should be frozen");
  });

  it("should prevent mutation of gifUrl", function () {
    const challenge = createChallenge({
      id: "freeze-2",
      gifUrl: "https://example.com/safe.gif",
      humanAnswer: "test answer",
    });
    // In strict mode, assignment to frozen property throws TypeError
    assert.throws(
      function () {
        challenge.gifUrl = "https://evil.com/bypass.gif";
      },
      TypeError,
      "Should throw when trying to mutate gifUrl"
    );
    assert.equal(challenge.gifUrl, "https://example.com/safe.gif");
  });

  it("should prevent mutation of humanAnswer", function () {
    const challenge = createChallenge({
      id: "freeze-3",
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "original answer",
    });
    assert.throws(
      function () {
        challenge.humanAnswer = "tampered answer";
      },
      TypeError,
      "Should throw when trying to mutate humanAnswer"
    );
    assert.equal(challenge.humanAnswer, "original answer");
  });

  it("should prevent adding new properties", function () {
    const challenge = createChallenge({
      id: "freeze-4",
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "test answer",
    });
    assert.throws(
      function () {
        challenge.maliciousProp = "injected";
      },
      TypeError,
      "Should throw when adding new properties"
    );
    assert.equal(challenge.maliciousProp, undefined);
  });

  it("should prevent deletion of properties", function () {
    const challenge = createChallenge({
      id: "freeze-5",
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "test answer",
    });
    assert.throws(
      function () {
        delete challenge.id;
      },
      TypeError,
      "Should throw when deleting properties"
    );
    assert.equal(challenge.id, "freeze-5");
  });

  it("should still have all expected properties after freeze", function () {
    const challenge = createChallenge({
      id: "freeze-6",
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "correct",
      title: "My Challenge",
      sourceUrl: "https://source.com",
      aiAnswer: "ai guess",
      keywords: ["word1", "word2"],
    });
    assert.equal(challenge.id, "freeze-6");
    assert.equal(challenge.title, "My Challenge");
    assert.equal(challenge.gifUrl, "https://example.com/test.gif");
    assert.equal(challenge.sourceUrl, "https://source.com");
    assert.equal(challenge.humanAnswer, "correct");
    assert.equal(challenge.aiAnswer, "ai guess");
    assert.deepEqual(challenge.keywords, ["word1", "word2"]);
  });
});

// ── secureRandomInt tests ──────────────────────────────────────────

describe("secureRandomInt", function () {
  it("should be exported as a function", function () {
    assert.equal(typeof secureRandomInt, "function");
  });

  it("should return values in range [0, max) for max=1", function () {
    for (let i = 0; i < 20; i++) {
      const val = secureRandomInt(1);
      assert.equal(val, 0, "secureRandomInt(1) should always return 0");
    }
  });

  it("should return values in range [0, max) for max=10", function () {
    for (let i = 0; i < 100; i++) {
      const val = secureRandomInt(10);
      assert.ok(val >= 0, `Value ${val} should be >= 0`);
      assert.ok(val < 10, `Value ${val} should be < 10`);
      assert.equal(
        val,
        Math.floor(val),
        `Value ${val} should be an integer`
      );
    }
  });

  it("should return values in range [0, max) for max=2", function () {
    const seen = new Set();
    for (let i = 0; i < 50; i++) {
      const val = secureRandomInt(2);
      assert.ok(val === 0 || val === 1, `Value ${val} should be 0 or 1`);
      seen.add(val);
    }
    // Statistical: with 50 trials, probability of not seeing both 0 and 1 is (1/2)^49 ≈ 0
    assert.equal(seen.size, 2, "Should produce both 0 and 1 over 50 trials");
  });

  it("should return values in range [0, max) for large max", function () {
    for (let i = 0; i < 50; i++) {
      const val = secureRandomInt(1000000);
      assert.ok(val >= 0, `Value ${val} should be >= 0`);
      assert.ok(val < 1000000, `Value ${val} should be < 1000000`);
      assert.equal(val, Math.floor(val), "Should be integer");
    }
  });

  it("should produce varied output (not constant)", function () {
    const values = new Set();
    for (let i = 0; i < 30; i++) {
      values.add(secureRandomInt(1000));
    }
    // With max=1000 and 30 trials, we should see at least 10 unique values
    assert.ok(
      values.size >= 5,
      `Expected at least 5 unique values, got ${values.size}`
    );
  });
});

// ── pickChallenges with secure random ──────────────────────────────

describe("pickChallenges with secure random", function () {
  const pool = [];
  for (let i = 1; i <= 20; i++) {
    pool.push(
      createChallenge({
        id: "pick-" + i,
        gifUrl: "https://example.com/" + i + ".gif",
        humanAnswer: "answer " + i,
      })
    );
  }

  it("should still return the correct number of challenges", function () {
    const picked = pickChallenges(pool, 5);
    assert.equal(picked.length, 5);
  });

  it("should return unique challenges", function () {
    const picked = pickChallenges(pool, 10);
    const ids = picked.map(function (c) {
      return c.id;
    });
    const uniqueIds = new Set(ids);
    assert.equal(uniqueIds.size, 10, "All picked challenges should be unique");
  });

  it("should not modify the original pool", function () {
    const originalIds = pool.map(function (c) {
      return c.id;
    });
    pickChallenges(pool, 5);
    const afterIds = pool.map(function (c) {
      return c.id;
    });
    assert.deepEqual(afterIds, originalIds, "Pool should not be modified");
  });

  it("should produce different orderings across calls (statistical)", function () {
    // Run pickChallenges 10 times picking all 20 and check that at least
    // 2 different orderings are produced
    const orderings = [];
    for (let i = 0; i < 10; i++) {
      const picked = pickChallenges(pool, 20);
      orderings.push(
        picked
          .map(function (c) {
            return c.id;
          })
          .join(",")
      );
    }
    const uniqueOrderings = new Set(orderings);
    assert.ok(
      uniqueOrderings.size >= 2,
      `Expected at least 2 unique orderings out of 10 runs, got ${uniqueOrderings.size}`
    );
  });

  it("should handle count=1", function () {
    const picked = pickChallenges(pool, 1);
    assert.equal(picked.length, 1);
  });

  it("should handle pool of size 1", function () {
    const singlePool = [
      createChallenge({
        id: "solo",
        gifUrl: "https://example.com/solo.gif",
        humanAnswer: "solo answer",
      }),
    ];
    const picked = pickChallenges(singlePool, 1);
    assert.equal(picked.length, 1);
    assert.equal(picked[0].id, "solo");
  });

  it("picked challenges should also be frozen", function () {
    const picked = pickChallenges(pool, 3);
    picked.forEach(function (challenge) {
      assert.ok(
        Object.isFrozen(challenge),
        `Challenge ${challenge.id} should be frozen`
      );
    });
  });
});

// ── Prototype Pollution Prevention ─────────────────────────────────

const {
  createAttemptTracker,
  createSessionManager,
  createPoolManager,
  createDifficultyCalibrator,
} = require("../src/index");

describe("prototype pollution prevention in AttemptTracker", function () {
  const dangerousKeys = ["__proto__", "constructor", "toString", "valueOf", "hasOwnProperty"];

  dangerousKeys.forEach(function (key) {
    it(`should safely handle challengeId="${key}" without polluting Object.prototype`, function () {
      const tracker = createAttemptTracker({ maxAttempts: 3, lockoutMs: 1000 });
      const originalProto = Object.getPrototypeOf({});

      // Record attempts with dangerous key
      const result = tracker.recordAttempt(key);
      assert.strictEqual(result.allowed, true);

      // Verify Object.prototype is not polluted
      const testObj = {};
      assert.strictEqual(testObj.attempts, undefined, `Object.prototype.attempts should not be set by key "${key}"`);
      assert.strictEqual(testObj.lockoutUntil, undefined, `Object.prototype.lockoutUntil should not be set by key "${key}"`);

      // Verify tracker still works correctly
      const status = tracker.isLocked(key);
      assert.strictEqual(status.locked, false);
    });
  });

  it("should track attempts independently for dangerous keys", function () {
    const tracker = createAttemptTracker({ maxAttempts: 3 });

    tracker.recordAttempt("__proto__");
    tracker.recordAttempt("constructor");
    tracker.recordAttempt("normal-id");

    // Each should have its own count
    const proto = tracker.isLocked("__proto__");
    const ctor = tracker.isLocked("constructor");
    const normal = tracker.isLocked("normal-id");

    assert.strictEqual(proto.locked, false);
    assert.strictEqual(ctor.locked, false);
    assert.strictEqual(normal.locked, false);
  });

  it("should lock out dangerous keys after max attempts", function () {
    const tracker = createAttemptTracker({ maxAttempts: 2, lockoutMs: 5000 });

    tracker.recordAttempt("__proto__");
    const second = tracker.recordAttempt("__proto__");

    assert.strictEqual(second.allowed, false, "__proto__ should be locked after 2 attempts");
    assert.ok(second.lockoutRemainingMs > 0);
  });
});

describe("prototype pollution prevention in SessionManager", function () {
  it("should not pollute Object.prototype when accessing crafted session IDs", function () {
    const mgr = createSessionManager({ challengesPerSession: 2 });

    // Start a session normally
    const session = mgr.startSession({ userId: "test" });

    // Try to access __proto__ as a session ID — should return error, not crash
    const result = mgr.submitResponse("__proto__", true);
    assert.strictEqual(result.error, "session_not_found");

    // Try getSession with dangerous key
    const protoSession = mgr.getSession("__proto__");
    assert.strictEqual(protoSession, null);

    // Verify Object.prototype is clean
    const testObj = {};
    assert.strictEqual(testObj.status, undefined);
    assert.strictEqual(testObj.createdAt, undefined);
  });

  it("should not pollute prototype when invalidating crafted session IDs", function () {
    const mgr = createSessionManager();
    const result = mgr.invalidateSession("constructor");
    assert.strictEqual(result, false, "invalidating non-existent crafted session should return false");
  });
});

describe("prototype pollution prevention in PoolManager", function () {
  it("should safely add challenges with dangerous IDs", function () {
    const mgr = createPoolManager();

    // Add challenges with dangerous IDs
    const added = mgr.add([
      { id: "__proto__", humanAnswer: "test" },
      { id: "constructor", humanAnswer: "test2" },
      { id: "normal", humanAnswer: "test3" },
    ]);

    assert.strictEqual(added, 3);

    // Verify Object.prototype is clean
    const testObj = {};
    assert.strictEqual(testObj.challenge, undefined);
    assert.strictEqual(testObj.serves, undefined);

    // Verify stats work
    const stats = mgr.getStats();
    assert.strictEqual(stats.length, 3);
  });

  it("should record results for dangerous-ID challenges without pollution", function () {
    const mgr = createPoolManager();
    mgr.add({ id: "__proto__", humanAnswer: "test" });

    mgr.recordResult("__proto__", true);
    mgr.recordResult("__proto__", false);

    const stats = mgr.getStats();
    const entry = stats.find(function (s) { return s.id === "__proto__"; });
    assert.ok(entry);
    assert.strictEqual(entry.passes, 1);
    assert.strictEqual(entry.fails, 1);
  });
});

describe("prototype pollution prevention in DifficultyCalibrator", function () {
  it("should safely handle challengeIds matching prototype keys", function () {
    const challenges = [
      { id: "c1", humanAnswer: "test" },
      { id: "c2", humanAnswer: "test2" },
    ];
    const calibrator = createDifficultyCalibrator(challenges);

    // Record response with dangerous key
    calibrator.recordResponse("__proto__", { timeMs: 500, correct: true });
    calibrator.recordResponse("constructor", { timeMs: 300, correct: false });

    // Verify Object.prototype is clean
    const testObj = {};
    assert.strictEqual(testObj[0], undefined);

    // Stats should work for those keys
    const protoStats = calibrator.getStats("__proto__");
    assert.ok(protoStats);
    assert.strictEqual(protoStats.totalResponses, 1);
    assert.strictEqual(protoStats.correctCount, 1);
  });
});
