"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const {
  _posOpt,
  _nnOpt,
  LruTracker,
  secureRandomInt,
  _constantTimeEqual,
  _clamp,
  _numAsc,
  _mean,
  _median,
  _stddev,
  _populationStddev,
  _percentile,
  sanitize,
  isSafeUrl,
  textSimilarity,
  validateAnswer,
  createChallenge,
  createAttemptTracker,
} = require("../src/shared-utils");

// ── _posOpt / _nnOpt ───────────────────────────────────────────

describe("_posOpt", () => {
  it("returns value when positive", () => assert.equal(_posOpt(5, 10), 5));
  it("returns fallback for 0", () => assert.equal(_posOpt(0, 10), 10));
  it("returns fallback for null", () => assert.equal(_posOpt(null, 7), 7));
  it("returns fallback for negative", () => assert.equal(_posOpt(-3, 7), 7));
});

describe("_nnOpt", () => {
  it("returns 0 when val is 0", () => assert.equal(_nnOpt(0, 10), 0));
  it("returns fallback for null", () => assert.equal(_nnOpt(null, 5), 5));
  it("returns fallback for negative", () => assert.equal(_nnOpt(-1, 5), 5));
  it("returns value when positive", () => assert.equal(_nnOpt(3, 5), 3));
});

// ── LruTracker ──────────────────────────────────────────────────

describe("LruTracker", () => {
  let lru;
  beforeEach(() => { lru = new LruTracker(); });

  it("push and length", () => {
    lru.push("a");
    lru.push("b");
    assert.equal(lru.length, 2);
    assert.ok(lru.has("a"));
    assert.ok(lru.has("b"));
  });

  it("push duplicate touches instead of adding", () => {
    lru.push("a"); lru.push("b"); lru.push("a");
    assert.equal(lru.length, 2);
    assert.deepEqual(lru.toArray(), ["b", "a"]);
  });

  it("evictOldest returns oldest key", () => {
    lru.push("x"); lru.push("y"); lru.push("z");
    assert.equal(lru.evictOldest(), "x");
    assert.equal(lru.length, 2);
    assert.ok(!lru.has("x"));
  });

  it("evictOldest returns undefined when empty", () => {
    assert.equal(lru.evictOldest(), undefined);
  });

  it("touch moves to end", () => {
    lru.push("a"); lru.push("b"); lru.push("c");
    lru.touch("a");
    assert.deepEqual(lru.toArray(), ["b", "c", "a"]);
  });

  it("touch is no-op for missing key", () => {
    lru.push("a");
    lru.touch("missing");
    assert.deepEqual(lru.toArray(), ["a"]);
  });

  it("touch is no-op for tail", () => {
    lru.push("a"); lru.push("b");
    lru.touch("b");
    assert.deepEqual(lru.toArray(), ["a", "b"]);
  });

  it("remove returns true/false correctly", () => {
    lru.push("a"); lru.push("b");
    assert.ok(lru.remove("a"));
    assert.ok(!lru.remove("a"));
    assert.equal(lru.length, 1);
  });

  it("remove head, middle, tail correctly", () => {
    lru.push("a"); lru.push("b"); lru.push("c");
    lru.remove("b"); // middle
    assert.deepEqual(lru.toArray(), ["a", "c"]);
    lru.remove("c"); // tail
    assert.deepEqual(lru.toArray(), ["a"]);
    lru.remove("a"); // only/head
    assert.equal(lru.length, 0);
  });

  it("clear resets everything", () => {
    lru.push("a"); lru.push("b");
    lru.clear();
    assert.equal(lru.length, 0);
    assert.ok(!lru.has("a"));
  });

  it("fromArray restores state", () => {
    lru.fromArray(["x", "y", "z"]);
    assert.equal(lru.length, 3);
    assert.deepEqual(lru.toArray(), ["x", "y", "z"]);
    assert.equal(lru.evictOldest(), "x");
  });
});

// ── secureRandomInt ─────────────────────────────────────────────

describe("secureRandomInt", () => {
  it("returns values in [0, max)", () => {
    for (let i = 0; i < 100; i++) {
      const v = secureRandomInt(10);
      assert.ok(v >= 0 && v < 10, `got ${v}`);
    }
  });

  it("returns 0 for max=1", () => {
    assert.equal(secureRandomInt(1), 0);
  });
});

// ── _constantTimeEqual ──────────────────────────────────────────

describe("_constantTimeEqual", () => {
  it("returns true for identical strings", () => assert.ok(_constantTimeEqual("abc", "abc")));
  it("returns false for different strings", () => assert.ok(!_constantTimeEqual("abc", "abd")));
  it("returns false for different lengths", () => assert.ok(!_constantTimeEqual("ab", "abc")));
  it("returns false for non-strings", () => {
    assert.ok(!_constantTimeEqual(null, "a"));
    assert.ok(!_constantTimeEqual("a", 123));
  });
  it("handles empty strings", () => assert.ok(_constantTimeEqual("", "")));
});

// ── Math helpers ────────────────────────────────────────────────

describe("_clamp", () => {
  it("clamps below lower bound", () => assert.equal(_clamp(-5, 0, 10), 0));
  it("clamps above upper bound", () => assert.equal(_clamp(15, 0, 10), 10));
  it("passes through in range", () => assert.equal(_clamp(5, 0, 10), 5));
});

describe("_numAsc", () => {
  it("sorts ascending", () => assert.deepEqual([3,1,2].sort(_numAsc), [1,2,3]));
});

describe("_mean", () => {
  it("returns 0 for empty", () => assert.equal(_mean([]), 0));
  it("computes correctly", () => assert.equal(_mean([2, 4, 6]), 4));
});

describe("_median", () => {
  it("returns 0 for empty", () => assert.equal(_median([]), 0));
  it("odd length", () => assert.equal(_median([3, 1, 2]), 2));
  it("even length", () => assert.equal(_median([1, 2, 3, 4]), 2.5));
});

describe("_stddev", () => {
  it("returns 0 for fewer than 2 elements", () => assert.equal(_stddev([5]), 0));
  it("computes sample stddev", () => {
    const s = _stddev([2, 4, 4, 4, 5, 5, 7, 9]);
    assert.ok(Math.abs(s - 2.138) < 0.01, `expected ~2.138, got ${s}`);
  });
});

describe("_populationStddev", () => {
  it("returns 0 for fewer than 2 elements", () => assert.equal(_populationStddev([]), 0));
  it("computes population stddev (smaller than sample)", () => {
    const data = [2, 4, 4, 4, 5, 5, 7, 9];
    assert.ok(_populationStddev(data) < _stddev(data));
  });
});

describe("_percentile", () => {
  it("returns 0 for empty", () => assert.equal(_percentile([], 50), 0));
  it("p0 returns min", () => assert.equal(_percentile([1,2,3,4,5], 0), 1));
  it("p100 returns max", () => assert.equal(_percentile([1,2,3,4,5], 100), 5));
  it("p50 returns median", () => assert.equal(_percentile([1,2,3,4,5], 50), 3));
});

// ── sanitize / isSafeUrl ────────────────────────────────────────

describe("sanitize", () => {
  it("escapes HTML entities", () => {
    assert.equal(sanitize('<script>alert("xss")</script>'), '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
  });
  it("escapes ampersands", () => assert.equal(sanitize("a&b"), "a&amp;b"));
  it("escapes single quotes", () => assert.ok(sanitize("it's").includes("&#39;")));
});

describe("isSafeUrl", () => {
  it("allows https URLs", () => assert.ok(isSafeUrl("https://example.com/img.gif")));
  it("allows http URLs", () => assert.ok(isSafeUrl("http://example.com/img.gif")));
  it("allows relative paths", () => assert.ok(isSafeUrl("/images/foo.gif")));
  it("allows protocol-relative", () => assert.ok(isSafeUrl("//cdn.example.com/img.gif")));
  it("rejects javascript:", () => assert.ok(!isSafeUrl("javascript:alert(1)")));
  it("rejects data:", () => assert.ok(!isSafeUrl("data:text/html,<h1>hi</h1>")));
  it("rejects vbscript:", () => assert.ok(!isSafeUrl("vbscript:msgbox")));
  it("rejects null/empty", () => {
    assert.ok(!isSafeUrl(null));
    assert.ok(!isSafeUrl(""));
    assert.ok(!isSafeUrl("   "));
  });
});

// ── textSimilarity / validateAnswer ─────────────────────────────

describe("textSimilarity", () => {
  it("returns 1 for identical strings", () => assert.equal(textSimilarity("cat dog", "cat dog"), 1));
  it("returns 0 for no overlap", () => assert.equal(textSimilarity("cat", "dog"), 0));
  it("returns 0 for empty inputs", () => assert.equal(textSimilarity("", "hello"), 0));
  it("is case-insensitive", () => assert.equal(textSimilarity("Cat", "cat"), 1));
  it("partial overlap gives 0 < score < 1", () => {
    const s = textSimilarity("big red cat", "small red cat");
    assert.ok(s > 0 && s < 1);
  });
});

describe("validateAnswer", () => {
  it("passes with high similarity", () => {
    const r = validateAnswer("a running cat", "a running cat");
    assert.ok(r.passed);
    assert.equal(r.score, 1);
  });

  it("fails with low similarity", () => {
    const r = validateAnswer("blue sky", "red car driving fast");
    assert.ok(!r.passed);
  });

  it("respects requiredKeywords", () => {
    const r = validateAnswer("a running cat", "a running cat", { requiredKeywords: ["dog"] });
    assert.ok(!r.passed);
    assert.ok(!r.hasKeywords);
  });

  it("custom threshold", () => {
    const r = validateAnswer("cat", "cat dog bird", { threshold: 0.9 });
    assert.ok(!r.passed); // similarity too low for 0.9 threshold
  });
});

// ── createChallenge ─────────────────────────────────────────────

describe("createChallenge", () => {
  it("creates a frozen challenge object", () => {
    const c = createChallenge({ id: 1, gifUrl: "https://x.com/a.gif", humanAnswer: "a cat" });
    assert.equal(c.id, 1);
    assert.ok(Object.isFrozen(c));
  });

  it("throws on missing required fields", () => {
    assert.throws(() => createChallenge({}));
    assert.throws(() => createChallenge({ id: 1 }));
  });

  it("throws on unsafe gifUrl", () => {
    assert.throws(() => createChallenge({ id: 1, gifUrl: "javascript:alert(1)", humanAnswer: "x" }));
  });

  it("defaults optional fields", () => {
    const c = createChallenge({ id: 1, gifUrl: "/img.gif", humanAnswer: "test", title: "T" });
    assert.equal(c.sourceUrl, "#");
    assert.equal(c.aiAnswer, "");
    assert.deepEqual(c.keywords, []);
  });
});

// ── createAttemptTracker ────────────────────────────────────────

describe("createAttemptTracker", () => {
  it("allows attempts up to max", () => {
    const t = createAttemptTracker({ maxAttempts: 3, lockoutMs: 1000 });
    assert.ok(t.recordAttempt("c1").allowed);
    assert.ok(t.recordAttempt("c1").allowed);
    const r3 = t.recordAttempt("c1");
    assert.ok(!r3.allowed); // 3rd attempt triggers lockout
    assert.ok(r3.lockoutRemainingMs > 0);
  });

  it("locks out after max attempts", () => {
    const t = createAttemptTracker({ maxAttempts: 2, lockoutMs: 100000 });
    t.recordAttempt("c1");
    t.recordAttempt("c1");
    const status = t.isLocked("c1");
    assert.ok(status.locked);
  });

  it("trackedValidate rejects when locked", () => {
    const t = createAttemptTracker({ maxAttempts: 1, lockoutMs: 100000 });
    t.recordAttempt("c1"); // triggers lockout
    const r = t.validateAnswer("answer", "answer", "c1");
    assert.ok(!r.passed);
    assert.ok(r.locked);
  });

  it("trackedValidate validates when allowed", () => {
    const t = createAttemptTracker({ maxAttempts: 5 });
    const r = t.validateAnswer("running cat", "running cat", "c1");
    assert.ok(r.passed);
    assert.ok(!r.locked);
  });

  it("resetChallenge clears state", () => {
    const t = createAttemptTracker({ maxAttempts: 1, lockoutMs: 100000 });
    t.recordAttempt("c1");
    t.resetChallenge("c1");
    assert.ok(!t.isLocked("c1").locked);
  });

  it("resetAll clears all state", () => {
    const t = createAttemptTracker({ maxAttempts: 1, lockoutMs: 100000 });
    t.recordAttempt("c1");
    t.recordAttempt("c2");
    t.resetAll();
    assert.ok(!t.isLocked("c1").locked);
    assert.ok(!t.isLocked("c2").locked);
  });

  it("getConfig returns configuration", () => {
    const t = createAttemptTracker({ maxAttempts: 3, lockoutMs: 5000 });
    const c = t.getConfig();
    assert.equal(c.maxAttempts, 3);
    assert.equal(c.lockoutMs, 5000);
  });

  it("getStats returns attempt info", () => {
    const t = createAttemptTracker({ maxAttempts: 5 });
    t.recordAttempt("c1");
    t.recordAttempt("c1");
    const s = t.getStats("c1");
    assert.equal(s.attempts, 2);
    assert.ok(!s.isLocked);
  });

  it("throws when challengeId is null for trackedValidate", () => {
    const t = createAttemptTracker();
    assert.throws(() => t.validateAnswer("a", "b", null));
  });
});
