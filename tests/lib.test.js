/* ── gif-captcha library tests ───────────────────────────────────── */
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const gifCaptcha = require("../src/index.js");

// ── sanitize ────────────────────────────────────────────────────────

describe("sanitize", () => {
  it("should escape HTML entities", () => {
    assert.equal(gifCaptcha.sanitize("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("should escape ampersands", () => {
    assert.equal(gifCaptcha.sanitize("foo & bar"), "foo &amp; bar");
  });

  it("should escape quotes", () => {
    assert.equal(gifCaptcha.sanitize('"hello"'), "&quot;hello&quot;");
  });

  it("should escape single quotes", () => {
    assert.equal(gifCaptcha.sanitize("it's"), "it&#39;s");
  });

  it("should handle empty string", () => {
    assert.equal(gifCaptcha.sanitize(""), "");
  });

  it("should handle plain text unchanged", () => {
    assert.equal(gifCaptcha.sanitize("hello world"), "hello world");
  });

  it("should handle multiple special chars", () => {
    const input = '<img src="x" onerror="alert(\'XSS\')">';
    const result = gifCaptcha.sanitize(input);
    assert.ok(!result.includes("<"));
    assert.ok(!result.includes(">"));
  });
});

// ── createSanitizer ─────────────────────────────────────────────────

describe("createSanitizer", () => {
  it("should return an object with sanitize function", () => {
    const s = gifCaptcha.createSanitizer();
    assert.equal(typeof s.sanitize, "function");
  });

  it("should escape HTML", () => {
    const s = gifCaptcha.createSanitizer();
    assert.equal(s.sanitize("<b>bold</b>"), "&lt;b&gt;bold&lt;/b&gt;");
  });
});

// ── textSimilarity ──────────────────────────────────────────────────

describe("textSimilarity", () => {
  it("should return 1 for identical strings", () => {
    assert.equal(gifCaptcha.textSimilarity("hello world", "hello world"), 1);
  });

  it("should return 0 for completely different strings", () => {
    assert.equal(gifCaptcha.textSimilarity("cat dog", "fish bird"), 0);
  });

  it("should return partial score for overlapping words", () => {
    const score = gifCaptcha.textSimilarity("the cat sat", "the dog sat");
    assert.ok(score > 0.3);
    assert.ok(score < 1);
  });

  it("should be case insensitive", () => {
    assert.equal(gifCaptcha.textSimilarity("Hello World", "hello world"), 1);
  });

  it("should return 0 for null/empty inputs", () => {
    assert.equal(gifCaptcha.textSimilarity(null, "test"), 0);
    assert.equal(gifCaptcha.textSimilarity("test", null), 0);
    assert.equal(gifCaptcha.textSimilarity("", ""), 0);
  });

  it("should handle single word matches", () => {
    const score = gifCaptcha.textSimilarity("hello", "hello");
    assert.equal(score, 1);
  });
});

// ── validateAnswer ──────────────────────────────────────────────────

describe("validateAnswer", () => {
  it("should pass for matching answers", () => {
    const result = gifCaptcha.validateAnswer(
      "the cat jumped over the fence",
      "the cat jumped over the fence"
    );
    assert.equal(result.passed, true);
    assert.equal(result.score, 1);
  });

  it("should fail for completely wrong answers", () => {
    const result = gifCaptcha.validateAnswer(
      "I cannot view images",
      "the cat jumped over the fence"
    );
    assert.equal(result.passed, false);
    assert.ok(result.score < 0.3);
  });

  it("should pass for partial matches above threshold", () => {
    const result = gifCaptcha.validateAnswer(
      "a cat jumped over something",
      "the cat jumped over the fence",
      { threshold: 0.3 }
    );
    assert.equal(result.passed, true);
    assert.ok(result.score >= 0.3);
  });

  it("should check required keywords", () => {
    const result = gifCaptcha.validateAnswer(
      "the dog ran away",
      "the cat jumped over the fence",
      { threshold: 0.1, requiredKeywords: ["cat"] }
    );
    assert.equal(result.hasKeywords, false);
    assert.equal(result.passed, false);
  });

  it("should pass with matching keywords", () => {
    const result = gifCaptcha.validateAnswer(
      "the cat was there",
      "the cat jumped over the fence",
      { threshold: 0.1, requiredKeywords: ["cat"] }
    );
    assert.equal(result.hasKeywords, true);
  });

  it("should use default threshold of 0.3", () => {
    const result = gifCaptcha.validateAnswer("same words", "same words");
    assert.equal(result.passed, true);
    assert.equal(result.score, 1);
  });
});

// ── createChallenge ─────────────────────────────────────────────────

describe("createChallenge", () => {
  it("should create a valid challenge object", () => {
    const c = gifCaptcha.createChallenge({
      id: 1,
      title: "Test Challenge",
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "Something happened",
    });
    assert.equal(c.id, 1);
    assert.equal(c.title, "Test Challenge");
    assert.equal(c.gifUrl, "https://example.com/test.gif");
    assert.equal(c.humanAnswer, "Something happened");
    assert.equal(c.sourceUrl, "#");
    assert.equal(c.aiAnswer, "");
    assert.deepEqual(c.keywords, []);
  });

  it("should include optional fields", () => {
    const c = gifCaptcha.createChallenge({
      id: 2,
      title: "Full Challenge",
      gifUrl: "https://example.com/full.gif",
      sourceUrl: "https://example.com/source",
      humanAnswer: "A thing happened",
      aiAnswer: "I cannot view images",
      keywords: ["thing", "happened"],
    });
    assert.equal(c.sourceUrl, "https://example.com/source");
    assert.equal(c.aiAnswer, "I cannot view images");
    assert.deepEqual(c.keywords, ["thing", "happened"]);
  });

  it("should throw without required fields", () => {
    assert.throws(() => gifCaptcha.createChallenge(null));
    assert.throws(() => gifCaptcha.createChallenge({}));
    assert.throws(() => gifCaptcha.createChallenge({ id: 1 }));
    assert.throws(() => gifCaptcha.createChallenge({ id: 1, gifUrl: "x" }));
  });

  it("should default title if not provided", () => {
    const c = gifCaptcha.createChallenge({
      id: 42,
      gifUrl: "https://example.com/test.gif",
      humanAnswer: "answer",
    });
    assert.equal(c.title, "Challenge 42");
  });
});

// ── pickChallenges ──────────────────────────────────────────────────

describe("pickChallenges", () => {
  const pool = Array.from({ length: 10 }, (_, i) =>
    gifCaptcha.createChallenge({
      id: i + 1,
      gifUrl: `https://example.com/${i}.gif`,
      humanAnswer: `Answer ${i}`,
    })
  );

  it("should pick the requested number of challenges", () => {
    const picked = gifCaptcha.pickChallenges(pool, 3);
    assert.equal(picked.length, 3);
  });

  it("should not exceed pool size", () => {
    const picked = gifCaptcha.pickChallenges(pool, 100);
    assert.equal(picked.length, 10);
  });

  it("should return unique challenges", () => {
    const picked = gifCaptcha.pickChallenges(pool, 5);
    const ids = new Set(picked.map((c) => c.id));
    assert.equal(ids.size, 5);
  });

  it("should return empty for empty pool", () => {
    assert.deepEqual(gifCaptcha.pickChallenges([], 5), []);
    assert.deepEqual(gifCaptcha.pickChallenges(null, 5), []);
  });

  it("should default count to 5", () => {
    const picked = gifCaptcha.pickChallenges(pool);
    assert.equal(picked.length, 5);
  });

  it("should not modify the original pool", () => {
    const original = pool.slice();
    gifCaptcha.pickChallenges(pool, 3);
    assert.deepEqual(pool, original);
  });
});

// ── Constants ───────────────────────────────────────────────────────

describe("constants", () => {
  it("should export GIF retry constants", () => {
    assert.equal(typeof gifCaptcha.GIF_MAX_RETRIES, "number");
    assert.equal(typeof gifCaptcha.GIF_RETRY_DELAY_MS, "number");
    assert.ok(gifCaptcha.GIF_MAX_RETRIES >= 1);
    assert.ok(gifCaptcha.GIF_RETRY_DELAY_MS >= 100);
  });
});

// ── Module exports ──────────────────────────────────────────────────

describe("module exports", () => {
  it("should export all expected functions", () => {
    assert.equal(typeof gifCaptcha.sanitize, "function");
    assert.equal(typeof gifCaptcha.createSanitizer, "function");
    assert.equal(typeof gifCaptcha.isSafeUrl, "function");
    assert.equal(typeof gifCaptcha.loadGifWithRetry, "function");
    assert.equal(typeof gifCaptcha.textSimilarity, "function");
    assert.equal(typeof gifCaptcha.validateAnswer, "function");
    assert.equal(typeof gifCaptcha.createChallenge, "function");
    assert.equal(typeof gifCaptcha.pickChallenges, "function");
    assert.equal(typeof gifCaptcha.installRoundRectPolyfill, "function");
  });
});

// ── isSafeUrl ───────────────────────────────────────────────────────

describe("isSafeUrl", () => {
  // ── Valid URLs ──

  it("should accept https URLs", () => {
    assert.equal(gifCaptcha.isSafeUrl("https://example.com/image.gif"), true);
  });

  it("should accept http URLs", () => {
    assert.equal(gifCaptcha.isSafeUrl("http://example.com/image.gif"), true);
  });

  it("should accept protocol-relative URLs", () => {
    assert.equal(gifCaptcha.isSafeUrl("//cdn.example.com/image.gif"), true);
  });

  it("should accept absolute paths", () => {
    assert.equal(gifCaptcha.isSafeUrl("/images/captcha.gif"), true);
  });

  it("should accept relative paths", () => {
    assert.equal(gifCaptcha.isSafeUrl("images/captcha.gif"), true);
  });

  it("should accept URLs with query strings", () => {
    assert.equal(gifCaptcha.isSafeUrl("https://example.com/img.gif?retry=1"), true);
  });

  it("should accept URLs with fragments", () => {
    assert.equal(gifCaptcha.isSafeUrl("https://example.com/img.gif#top"), true);
  });

  it("should accept URLs with ports", () => {
    assert.equal(gifCaptcha.isSafeUrl("https://example.com:8080/img.gif"), true);
  });

  // ── Dangerous schemes ──

  it("should reject javascript: URLs", () => {
    assert.equal(gifCaptcha.isSafeUrl("javascript:alert(1)"), false);
  });

  it("should reject JAVASCRIPT: URLs (case-insensitive)", () => {
    assert.equal(gifCaptcha.isSafeUrl("JAVASCRIPT:alert(1)"), false);
  });

  it("should reject jAvAsCrIpT: URLs (mixed case)", () => {
    assert.equal(gifCaptcha.isSafeUrl("jAvAsCrIpT:alert(1)"), false);
  });

  it("should reject data: URLs", () => {
    assert.equal(gifCaptcha.isSafeUrl("data:text/html,<script>alert(1)</script>"), false);
  });

  it("should reject data: image URLs (even base64)", () => {
    assert.equal(gifCaptcha.isSafeUrl("data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"), false);
  });

  it("should reject vbscript: URLs", () => {
    assert.equal(gifCaptcha.isSafeUrl("vbscript:msgbox('xss')"), false);
  });

  it("should reject blob: URLs", () => {
    assert.equal(gifCaptcha.isSafeUrl("blob:https://example.com/uuid"), false);
  });

  it("should reject file: URLs", () => {
    assert.equal(gifCaptcha.isSafeUrl("file:///etc/passwd"), false);
  });

  it("should reject ftp: URLs", () => {
    assert.equal(gifCaptcha.isSafeUrl("ftp://example.com/file"), false);
  });

  // ── Bypass attempts ──

  it("should reject javascript: with leading whitespace", () => {
    assert.equal(gifCaptcha.isSafeUrl("  javascript:alert(1)"), false);
  });

  it("should reject javascript: with leading tab", () => {
    assert.equal(gifCaptcha.isSafeUrl("\tjavascript:alert(1)"), false);
  });

  it("should reject javascript: with leading newline", () => {
    assert.equal(gifCaptcha.isSafeUrl("\njavascript:alert(1)"), false);
  });

  it("should reject javascript: with leading null byte", () => {
    assert.equal(gifCaptcha.isSafeUrl("\x00javascript:alert(1)"), false);
  });

  it("should reject javascript: with leading control chars", () => {
    assert.equal(gifCaptcha.isSafeUrl("\x01\x02\x03javascript:alert(1)"), false);
  });

  // ── Invalid inputs ──

  it("should reject null", () => {
    assert.equal(gifCaptcha.isSafeUrl(null), false);
  });

  it("should reject undefined", () => {
    assert.equal(gifCaptcha.isSafeUrl(undefined), false);
  });

  it("should reject empty string", () => {
    assert.equal(gifCaptcha.isSafeUrl(""), false);
  });

  it("should reject whitespace-only string", () => {
    assert.equal(gifCaptcha.isSafeUrl("   "), false);
  });

  it("should reject non-string types", () => {
    assert.equal(gifCaptcha.isSafeUrl(42), false);
    assert.equal(gifCaptcha.isSafeUrl(true), false);
    assert.equal(gifCaptcha.isSafeUrl({}), false);
  });
});

// ── createChallenge URL validation ──────────────────────────────────

describe("createChallenge URL validation", () => {
  it("should reject javascript: gifUrl", () => {
    assert.throws(
      () => gifCaptcha.createChallenge({ id: 1, gifUrl: "javascript:alert(1)", humanAnswer: "test" }),
      /safe HTTP/
    );
  });

  it("should reject data: gifUrl", () => {
    assert.throws(
      () => gifCaptcha.createChallenge({ id: 1, gifUrl: "data:image/gif;base64,abc", humanAnswer: "test" }),
      /safe HTTP/
    );
  });

  it("should accept valid https gifUrl", () => {
    const challenge = gifCaptcha.createChallenge({
      id: 1,
      gifUrl: "https://example.com/cat.gif",
      humanAnswer: "a cat",
    });
    assert.equal(challenge.gifUrl, "https://example.com/cat.gif");
  });

  it("should reject javascript: sourceUrl", () => {
    assert.throws(
      () => gifCaptcha.createChallenge({
        id: 1,
        gifUrl: "https://example.com/cat.gif",
        humanAnswer: "a cat",
        sourceUrl: "javascript:alert(1)",
      }),
      /sourceUrl must be a safe/
    );
  });

  it("should accept # as sourceUrl (default fallback)", () => {
    const challenge = gifCaptcha.createChallenge({
      id: 1,
      gifUrl: "https://example.com/cat.gif",
      humanAnswer: "a cat",
      sourceUrl: "#",
    });
    assert.equal(challenge.sourceUrl, "#");
  });

  it("should accept valid https sourceUrl", () => {
    const challenge = gifCaptcha.createChallenge({
      id: 1,
      gifUrl: "https://example.com/cat.gif",
      humanAnswer: "a cat",
      sourceUrl: "https://giphy.com/cat",
    });
    assert.equal(challenge.sourceUrl, "https://giphy.com/cat");
  });
});
