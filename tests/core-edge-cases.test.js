const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  validateAnswer,
  textSimilarity,
  createChallenge,
  pickChallenges,
  sanitize,
  isSafeUrl,
} = require("../src/index");

// ── validateAnswer edge cases ───────────────────────────────────────

describe("validateAnswer — edge cases", function () {
  it("passes with exact match and default threshold", function () {
    var result = validateAnswer("a cat sitting on a mat", "a cat sitting on a mat");
    assert.equal(result.passed, true);
    assert.equal(result.score, 1);
  });

  it("fails with completely unrelated answer", function () {
    var result = validateAnswer("purple elephant dancing", "cat sitting on mat");
    assert.equal(result.passed, false);
    assert.equal(result.score, 0);
  });

  it("handles null user answer gracefully", function () {
    var result = validateAnswer(null, "expected answer");
    assert.equal(result.passed, false);
    assert.equal(result.score, 0);
  });

  it("handles undefined user answer gracefully", function () {
    var result = validateAnswer(undefined, "expected answer");
    assert.equal(result.passed, false);
    assert.equal(result.score, 0);
  });

  it("handles empty string user answer", function () {
    var result = validateAnswer("", "expected answer");
    assert.equal(result.passed, false);
    assert.equal(result.score, 0);
  });

  it("handles null expected answer gracefully", function () {
    var result = validateAnswer("some answer", null);
    assert.equal(result.passed, false);
    assert.equal(result.score, 0);
  });

  it("uses custom threshold", function () {
    // "cat" matches 1 out of 3 words = 0.33 Jaccard
    var result = validateAnswer("cat", "cat on mat", { threshold: 0.2 });
    assert.equal(result.passed, true);
    assert.ok(result.score >= 0.2);
  });

  it("fails custom high threshold with partial match", function () {
    var result = validateAnswer("cat", "cat on mat", { threshold: 0.9 });
    assert.equal(result.passed, false);
  });

  it("threshold=0 passes any non-empty answer", function () {
    var result = validateAnswer("anything", "completely different", { threshold: 0 });
    assert.equal(result.passed, true);
  });

  it("requires all keywords present", function () {
    var result = validateAnswer("the cat sat", "cat on mat", {
      threshold: 0.1,
      requiredKeywords: ["cat", "sat"],
    });
    assert.equal(result.hasKeywords, true);
    assert.equal(result.passed, true);
  });

  it("fails when keyword is missing", function () {
    var result = validateAnswer("the cat sat", "cat on mat", {
      threshold: 0.1,
      requiredKeywords: ["dog"],
    });
    assert.equal(result.hasKeywords, false);
    assert.equal(result.passed, false);
  });

  it("keyword check is case insensitive", function () {
    var result = validateAnswer("A Cat Jumped", "cat jumped", {
      threshold: 0.1,
      requiredKeywords: ["CAT"],
    });
    assert.equal(result.hasKeywords, true);
  });

  it("passes with score above threshold and keywords present", function () {
    var result = validateAnswer("man riding bicycle fast", "man riding bicycle", {
      threshold: 0.5,
      requiredKeywords: ["bicycle"],
    });
    assert.equal(result.passed, true);
    assert.equal(result.hasKeywords, true);
    assert.ok(result.score >= 0.5);
  });

  it("fails when score OK but keywords missing", function () {
    var result = validateAnswer("man riding bicycle fast", "man riding bicycle", {
      threshold: 0.3,
      requiredKeywords: ["car"],
    });
    assert.equal(result.passed, false);
    assert.ok(result.score >= 0.3);
    assert.equal(result.hasKeywords, false);
  });

  it("empty requiredKeywords array means no keyword check", function () {
    var result = validateAnswer("cat", "cat on mat", {
      threshold: 0.1,
      requiredKeywords: [],
    });
    assert.equal(result.hasKeywords, true);
    assert.equal(result.passed, true);
  });

  it("handles numeric inputs via coercion", function () {
    var result = validateAnswer(42, "42");
    assert.equal(typeof result.score, "number");
  });
});

// ── textSimilarity edge cases ───────────────────────────────────────

describe("textSimilarity — edge cases", function () {
  it("returns 1 for identical strings", function () {
    assert.equal(textSimilarity("hello world", "hello world"), 1);
  });

  it("returns 0 for completely different words", function () {
    assert.equal(textSimilarity("alpha beta", "gamma delta"), 0);
  });

  it("is case insensitive", function () {
    assert.equal(textSimilarity("Hello World", "hello world"), 1);
  });

  it("handles extra whitespace", function () {
    var score = textSimilarity("hello   world", "hello world");
    assert.equal(score, 1);
  });

  it("handles leading/trailing whitespace", function () {
    var score = textSimilarity("  hello world  ", "hello world");
    assert.equal(score, 1);
  });

  it("returns 0 for empty first string", function () {
    assert.equal(textSimilarity("", "hello"), 0);
  });

  it("returns 0 for empty second string", function () {
    assert.equal(textSimilarity("hello", ""), 0);
  });

  it("returns 0 for both empty strings", function () {
    assert.equal(textSimilarity("", ""), 0);
  });

  it("returns 0 for null inputs", function () {
    assert.equal(textSimilarity(null, "hello"), 0);
    assert.equal(textSimilarity("hello", null), 0);
    assert.equal(textSimilarity(null, null), 0);
  });

  it("returns 0 for undefined inputs", function () {
    assert.equal(textSimilarity(undefined, "hello"), 0);
    assert.equal(textSimilarity("hello", undefined), 0);
  });

  it("computes Jaccard index correctly for partial overlap", function () {
    // "cat sat" vs "cat mat" → intersection={cat}, union={cat,sat,mat} → 1/3
    var score = textSimilarity("cat sat", "cat mat");
    assert.ok(Math.abs(score - 1 / 3) < 0.01);
  });

  it("handles single word matching", function () {
    var score = textSimilarity("cat", "cat");
    assert.equal(score, 1);
  });

  it("handles single word not matching", function () {
    assert.equal(textSimilarity("cat", "dog"), 0);
  });

  it("handles duplicate words in input", function () {
    // "cat cat" → {cat}, "cat dog" → {cat, dog}, intersection={cat}, union={cat,dog} → 0.5
    var score = textSimilarity("cat cat", "cat dog");
    assert.equal(score, 0.5);
  });

  it("handles long strings with many words", function () {
    var a = "the quick brown fox jumps over the lazy dog";
    var b = "the quick brown fox";
    var score = textSimilarity(a, b);
    assert.ok(score > 0);
    assert.ok(score < 1);
  });
});

// ── createChallenge edge cases ──────────────────────────────────────

describe("createChallenge — edge cases", function () {
  it("creates frozen object", function () {
    var c = createChallenge({
      id: 1,
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "a cat",
    });
    assert.ok(Object.isFrozen(c));
  });

  it("rejects javascript: gifUrl", function () {
    assert.throws(function () {
      createChallenge({
        id: 1,
        gifUrl: "javascript:alert(1)",
        humanAnswer: "test",
      });
    }, /safe/i);
  });

  it("rejects data: gifUrl", function () {
    assert.throws(function () {
      createChallenge({
        id: 1,
        gifUrl: "data:text/html,test",
        humanAnswer: "test",
      });
    }, /safe/i);
  });

  it("rejects unsafe sourceUrl", function () {
    assert.throws(function () {
      createChallenge({
        id: 1,
        gifUrl: "https://example.com/test.gif",
        sourceUrl: "javascript:void(0)",
        humanAnswer: "test",
      });
    }, /safe/i);
  });

  it("allows sourceUrl='#' (special case)", function () {
    var c = createChallenge({
      id: 1,
      gifUrl: "https://example.com/test.gif",
      sourceUrl: "#",
      humanAnswer: "test",
    });
    assert.equal(c.sourceUrl, "#");
  });

  it("defaults sourceUrl to '#' when not provided", function () {
    var c = createChallenge({
      id: 1,
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "test",
    });
    assert.equal(c.sourceUrl, "#");
  });

  it("defaults aiAnswer to empty string", function () {
    var c = createChallenge({
      id: 1,
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "test",
    });
    assert.equal(c.aiAnswer, "");
  });

  it("defaults keywords to empty array", function () {
    var c = createChallenge({
      id: 1,
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "test",
    });
    assert.deepEqual(c.keywords, []);
  });

  it("preserves keywords array", function () {
    var c = createChallenge({
      id: 1,
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "test",
      keywords: ["cat", "dog"],
    });
    assert.deepEqual(c.keywords, ["cat", "dog"]);
  });

  it("throws when id is missing", function () {
    assert.throws(function () {
      createChallenge({ gifUrl: "https://x.com/a.gif", humanAnswer: "a" });
    }, /requires/i);
  });

  it("throws when gifUrl is missing", function () {
    assert.throws(function () {
      createChallenge({ id: 1, humanAnswer: "a" });
    }, /requires/i);
  });

  it("throws when humanAnswer is missing", function () {
    assert.throws(function () {
      createChallenge({ id: 1, gifUrl: "https://x.com/a.gif" });
    }, /requires/i);
  });

  it("throws when opts is null", function () {
    assert.throws(function () {
      createChallenge(null);
    }, /requires/i);
  });

  it("accepts string id", function () {
    var c = createChallenge({
      id: "abc-123",
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "test",
    });
    assert.equal(c.id, "abc-123");
  });

  it("accepts relative gifUrl", function () {
    var c = createChallenge({
      id: 1,
      gifUrl: "/images/test.gif",
      humanAnswer: "test",
    });
    assert.equal(c.gifUrl, "/images/test.gif");
  });
});

// ── pickChallenges edge cases ───────────────────────────────────────

describe("pickChallenges — edge cases", function () {
  var pool = [
    { id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }, { id: 5 },
    { id: 6 }, { id: 7 }, { id: 8 }, { id: 9 }, { id: 10 },
  ];

  it("returns empty array for null pool", function () {
    assert.deepEqual(pickChallenges(null, 3), []);
  });

  it("returns empty array for non-array pool", function () {
    assert.deepEqual(pickChallenges("not an array", 3), []);
  });

  it("returns empty array for empty pool", function () {
    assert.deepEqual(pickChallenges([], 3), []);
  });

  it("caps count at pool size", function () {
    var result = pickChallenges(pool.slice(0, 3), 10);
    assert.equal(result.length, 3);
  });

  it("returns all unique items", function () {
    var result = pickChallenges(pool, 10);
    var ids = result.map(function (c) { return c.id; });
    assert.equal(new Set(ids).size, 10);
  });

  it("does not mutate original pool", function () {
    var original = pool.slice();
    pickChallenges(pool, 5);
    assert.deepEqual(pool, original);
  });

  it("defaults count to 5", function () {
    var result = pickChallenges(pool);
    assert.equal(result.length, 5);
  });

  it("handles count=0 (defaults to 5 since 0 is falsy)", function () {
    var result = pickChallenges(pool, 0);
    assert.equal(result.length, 5); // 0 || 5 = 5
  });

  it("handles single-element pool", function () {
    var result = pickChallenges([{ id: 99 }], 1);
    assert.equal(result.length, 1);
    assert.equal(result[0].id, 99);
  });

  it("produces varied orderings (not always identical)", function () {
    // Run 10 times and check we get at least 2 different orderings
    var orderings = new Set();
    for (var i = 0; i < 10; i++) {
      var result = pickChallenges(pool, 5);
      orderings.add(result.map(function (c) { return c.id; }).join(","));
    }
    assert.ok(orderings.size >= 2, "Expected varied orderings, got " + orderings.size);
  });
});

// ── sanitize edge cases ─────────────────────────────────────────────

describe("sanitize — additional edge cases", function () {
  it("escapes nested HTML tags", function () {
    var result = sanitize("<script><b>bold</b></script>");
    assert.ok(!result.includes("<script>"));
    assert.ok(!result.includes("<b>"));
  });

  it("handles strings with only special characters", function () {
    var result = sanitize("&<>\"'");
    assert.ok(!result.includes("&<"));
    assert.ok(result.includes("&amp;"));
  });

  it("handles very long strings without error", function () {
    var long = "x".repeat(100000);
    var result = sanitize(long);
    assert.equal(result.length, 100000);
  });

  it("preserves unicode characters", function () {
    var result = sanitize("Hello 🌍 café ñ");
    assert.ok(result.includes("🌍"));
    assert.ok(result.includes("café"));
    assert.ok(result.includes("ñ"));
  });

  it("handles string with newlines and tabs", function () {
    var result = sanitize("line1\nline2\ttab");
    assert.ok(result.includes("\n"));
    assert.ok(result.includes("\t"));
  });
});
