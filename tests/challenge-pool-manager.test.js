/**
 * Tests for ChallengePoolManager
 */

"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/challenge-pool-manager.js");
var createChallengePoolManager = mod.createChallengePoolManager;

var counter = 0;
function makeFactory() {
  counter = 0;
  return function(tier) {
    counter++;
    return { id: "ch-" + counter, tier: tier, difficulty: tier };
  };
}

// ── Validation ──────────────────────────────────────────────────────

test("throws without factory", function() {
  assert.throws(function() { createChallengePoolManager({}); }, /factory must be a function/);
});

test("throws with invalid targetSize", function() {
  assert.throws(function() {
    createChallengePoolManager({ factory: function(){}, targetSize: -1 });
  }, /targetSize/);
});

test("throws with empty tiers array", function() {
  assert.throws(function() {
    createChallengePoolManager({ factory: function(){}, tiers: [] });
  }, /tiers must be a non-empty array/);
});

test("throws with non-string tier", function() {
  assert.throws(function() {
    createChallengePoolManager({ factory: function(){}, tiers: [123] });
  }, /each tier must be a non-empty string/);
});

// ── Basic take ──────────────────────────────────────────────────────

test("take from empty pool generates on demand", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 5, minSize: 0, priorityReserve: 0 });
  var ch = pool.take("easy");
  assert.ok(ch);
  assert.strictEqual(ch.tier, "easy");
});

test("take returns null for unknown tier", function() {
  var pool = createChallengePoolManager({ factory: makeFactory() });
  assert.strictEqual(pool.take("impossible"), null);
});

test("take from warmed pool returns pre-generated challenge", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 5, minSize: 0, priorityReserve: 0 });
  pool.warmUp();
  var ch = pool.take("medium");
  assert.ok(ch);
  assert.strictEqual(ch.tier, "medium");
});

// ── Warm up ─────────────────────────────────────────────────────────

test("warmUp fills all tiers to target", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 10, tiers: ["a", "b"] });
  var result = pool.warmUp();
  assert.strictEqual(result.a, 10);
  assert.strictEqual(result.b, 10);
  assert.strictEqual(pool.size("a"), 10);
  assert.strictEqual(pool.size("b"), 10);
});

test("warmUp is idempotent", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 5, tiers: ["x"] });
  pool.warmUp();
  var result = pool.warmUp();
  assert.strictEqual(result.x, 0);
});

// ── Size ────────────────────────────────────────────────────────────

test("size returns 0 for unknown tier", function() {
  var pool = createChallengePoolManager({ factory: makeFactory() });
  assert.strictEqual(pool.size("nope"), 0);
});

test("size decreases after take", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 5, minSize: 0, priorityReserve: 0 });
  pool.warmUp();
  assert.strictEqual(pool.size("easy"), 5);
  pool.take("easy");
  assert.strictEqual(pool.size("easy"), 4);
});

// ── Expiry ──────────────────────────────────────────────────────────

test("expired challenges are purged", function() {
  var time = 1000000;
  var pool = createChallengePoolManager({
    factory: makeFactory(),
    targetSize: 5,
    minSize: 0,
    maxAge: 1000,
    priorityReserve: 0,
    nowFn: function() { return time; }
  });
  pool.warmUp();
  assert.strictEqual(pool.size("easy"), 5);
  time += 2000; // exceed maxAge
  assert.strictEqual(pool.size("easy"), 0);
});

test("maxAge 0 means no expiry", function() {
  var time = 1000000;
  var pool = createChallengePoolManager({
    factory: makeFactory(),
    targetSize: 3,
    maxAge: 0,
    priorityReserve: 0,
    nowFn: function() { return time; }
  });
  pool.warmUp();
  time += 999999999;
  assert.strictEqual(pool.size("easy"), 3);
});

// ── Replenish ───────────────────────────────────────────────────────

test("replenish fills tiers below minSize", function() {
  var pool = createChallengePoolManager({
    factory: makeFactory(),
    targetSize: 10,
    minSize: 5,
    replenishBatch: 10,
    priorityReserve: 0
  });
  pool.warmUp();
  // Drain to below minSize
  for (var i = 0; i < 8; i++) pool.take("easy");
  assert.strictEqual(pool.size("easy"), 2);
  var result = pool.replenish();
  assert.ok(result.replenished.indexOf("easy") >= 0);
  assert.ok(pool.size("easy") > 2);
});

test("replenish does nothing when pools are full", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 5, minSize: 2 });
  pool.warmUp();
  var result = pool.replenish();
  assert.strictEqual(result.replenished.length, 0);
});

// ── Priority reserve ────────────────────────────────────────────────

test("non-priority take blocked when at reserve level", function() {
  var pool = createChallengePoolManager({
    factory: makeFactory(),
    targetSize: 5,
    minSize: 0,
    priorityReserve: 3,
    tiers: ["t"]
  });
  pool.warmUp();
  // Take until 3 remain
  pool.take("t", { priority: true });
  pool.take("t", { priority: true });
  assert.strictEqual(pool.size("t"), 3);
  // Non-priority should be blocked
  var ch = pool.take("t");
  assert.strictEqual(ch, null);
  // Priority should work
  ch = pool.take("t", { priority: true });
  assert.ok(ch);
});

// ── Health ──────────────────────────────────────────────────────────

test("health reports healthy when full", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 10, tiers: ["a"] });
  pool.warmUp();
  var h = pool.health();
  assert.strictEqual(h.status, "healthy");
  assert.strictEqual(h.tierHealth.a, "healthy");
  assert.strictEqual(h.total, 10);
});

test("health reports critical when empty", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 10, minSize: 5, tiers: ["a"], priorityReserve: 0 });
  var h = pool.health();
  assert.strictEqual(h.status, "critical");
  assert.ok(h.warnings.some(function(w) { return w.indexOf("EMPTY") >= 0; }));
});

test("health reports degraded when low", function() {
  var pool = createChallengePoolManager({
    factory: makeFactory(),
    targetSize: 10,
    minSize: 1,
    tiers: ["a"],
    priorityReserve: 0
  });
  pool.warmUp();
  for (var i = 0; i < 5; i++) pool.take("a");
  var h = pool.health();
  assert.strictEqual(h.tierHealth.a, "degraded");
});

// ── Stats ───────────────────────────────────────────────────────────

test("getStats tracks generation and serving", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 3, tiers: ["x"], priorityReserve: 0 });
  pool.warmUp();
  pool.take("x");
  pool.take("x");
  var s = pool.getStats();
  assert.strictEqual(s.totalGenerated, 3);
  assert.strictEqual(s.totalServed, 2);
  assert.strictEqual(s.servedByTier.x, 2);
});

test("resetStats clears counters", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 3, tiers: ["x"], priorityReserve: 0 });
  pool.warmUp();
  pool.take("x");
  pool.resetStats();
  var s = pool.getStats();
  assert.strictEqual(s.totalGenerated, 0);
  assert.strictEqual(s.totalServed, 0);
});

// ── Drain ───────────────────────────────────────────────────────────

test("drain single tier", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 5, tiers: ["a", "b"] });
  pool.warmUp();
  var count = pool.drain("a");
  assert.strictEqual(count, 5);
  assert.strictEqual(pool.size("a"), 0);
  assert.strictEqual(pool.size("b"), 5);
});

test("drain all tiers", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 3, tiers: ["a", "b"] });
  pool.warmUp();
  var count = pool.drain();
  assert.strictEqual(count, 6);
  assert.strictEqual(pool.size("a"), 0);
  assert.strictEqual(pool.size("b"), 0);
});

test("drain unknown tier returns 0", function() {
  var pool = createChallengePoolManager({ factory: makeFactory() });
  assert.strictEqual(pool.drain("nope"), 0);
});

// ── Peek ────────────────────────────────────────────────────────────

test("peek returns challenge without removing", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 3, tiers: ["a"], priorityReserve: 0 });
  pool.warmUp();
  var ch = pool.peek("a");
  assert.ok(ch);
  assert.strictEqual(pool.size("a"), 3);
  // peek returns same one
  assert.deepStrictEqual(pool.peek("a"), ch);
});

test("peek returns null for empty pool", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), tiers: ["a"] });
  assert.strictEqual(pool.peek("a"), null);
});

test("peek returns null for unknown tier", function() {
  var pool = createChallengePoolManager({ factory: makeFactory() });
  assert.strictEqual(pool.peek("nope"), null);
});

// ── getTiers ────────────────────────────────────────────────────────

test("getTiers returns configured tiers", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), tiers: ["x", "y", "z"] });
  assert.deepStrictEqual(pool.getTiers(), ["x", "y", "z"]);
});

// ── Export / Import ─────────────────────────────────────────────────

test("exportPool and importPool round-trip", function() {
  var pool1 = createChallengePoolManager({ factory: makeFactory(), targetSize: 3, tiers: ["a"], maxAge: 0 });
  pool1.warmUp();
  var exported = pool1.exportPool();
  assert.strictEqual(exported.a.length, 3);

  var pool2 = createChallengePoolManager({ factory: makeFactory(), targetSize: 10, tiers: ["a"], maxAge: 0 });
  var imported = pool2.importPool(exported);
  assert.strictEqual(imported, 3);
  assert.strictEqual(pool2.size("a"), 3);
});

test("importPool skips expired entries", function() {
  var time = 1000000;
  var pool = createChallengePoolManager({
    factory: makeFactory(),
    targetSize: 10,
    tiers: ["a"],
    maxAge: 1000,
    nowFn: function() { return time; }
  });
  var count = pool.importPool({ a: [{ challenge: { id: "old" }, createdAt: 1000 }] });
  assert.strictEqual(count, 0);
});

test("importPool handles null/invalid data", function() {
  var pool = createChallengePoolManager({ factory: makeFactory() });
  assert.strictEqual(pool.importPool(null), 0);
  assert.strictEqual(pool.importPool("garbage"), 0);
});

test("importPool respects maxPoolSize", function() {
  var pool = createChallengePoolManager({
    factory: makeFactory(),
    targetSize: 5,
    maxPoolSize: 2,
    tiers: ["a"],
    maxAge: 0
  });
  var data = {
    a: [
      { challenge: { id: "1" }, createdAt: Date.now() },
      { challenge: { id: "2" }, createdAt: Date.now() },
      { challenge: { id: "3" }, createdAt: Date.now() }
    ]
  };
  var count = pool.importPool(data);
  assert.strictEqual(count, 2);
});

// ── Random tier take ────────────────────────────────────────────────

test("take without tier picks randomly", function() {
  var pool = createChallengePoolManager({ factory: makeFactory(), targetSize: 5, priorityReserve: 0 });
  pool.warmUp();
  var ch = pool.take();
  assert.ok(ch);
  assert.ok(["easy", "medium", "hard"].indexOf(ch.tier) >= 0);
});

// ── maxPoolSize cap ─────────────────────────────────────────────────

test("warmUp respects maxPoolSize", function() {
  var pool = createChallengePoolManager({
    factory: makeFactory(),
    targetSize: 100,
    maxPoolSize: 5,
    tiers: ["a"]
  });
  pool.warmUp();
  assert.strictEqual(pool.size("a"), 5);
});

// ── Factory returning null ──────────────────────────────────────────

test("factory returning null is skipped", function() {
  var calls = 0;
  var pool = createChallengePoolManager({
    factory: function() { calls++; return calls <= 2 ? null : { id: "ok" }; },
    targetSize: 3,
    tiers: ["a"],
    priorityReserve: 0
  });
  pool.warmUp();
  assert.strictEqual(pool.size("a"), 1); // only 3rd call succeeded
});

test("take from empty pool with null factory returns null", function() {
  var pool = createChallengePoolManager({
    factory: function() { return null; },
    targetSize: 5,
    tiers: ["a"],
    priorityReserve: 0
  });
  assert.strictEqual(pool.take("a"), null);
});

// ── Health hitRate ───────────────────────────────────────────────────

test("health hitRate reflects misses", function() {
  var pool = createChallengePoolManager({
    factory: makeFactory(),
    targetSize: 2,
    minSize: 0,
    priorityReserve: 0,
    tiers: ["a"]
  });
  pool.warmUp();
  pool.take("a");
  pool.take("a");
  pool.take("a"); // miss + emergency gen
  var h = pool.health();
  assert.ok(h.stats.hitRate < 100);
  assert.strictEqual(h.stats.missCount, 1);
});
