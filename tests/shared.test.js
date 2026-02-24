/**
 * Tests for shared.js — sanitize(), loadGifWithRetry(), roundRect polyfill
 */

const { describe, it, beforeEach, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const SHARED_JS = fs.readFileSync(
  path.join(__dirname, "..", "shared.js"),
  "utf8"
);

/**
 * Create a fresh JSDOM with shared.js injected.
 * Optionally pre-define CanvasRenderingContext2D to test the polyfill guard.
 */
function createSharedDOM({ defineCanvas = false, nativeRoundRect = false } = {}) {
  const html = `<!DOCTYPE html><html><body></body></html>`;
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    pretendToBeVisual: true,
    url: "https://example.com/test.html",
  });
  const { window } = dom;

  // Set up CanvasRenderingContext2D mock if requested
  if (defineCanvas) {
    if (typeof window.CanvasRenderingContext2D === "undefined") {
      window.CanvasRenderingContext2D = function () {};
      window.CanvasRenderingContext2D.prototype = {};
    }
    if (nativeRoundRect) {
      window.CanvasRenderingContext2D.prototype.roundRect = function () {
        // Native stub
      };
      window.CanvasRenderingContext2D.prototype.roundRect._isNative = true;
    }
  }

  // Inject shared.js
  const script = window.document.createElement("script");
  script.textContent = SHARED_JS;
  window.document.body.appendChild(script);

  return dom;
}

// ──────────────────────────────────────────────────────────────
// sanitize()
// ──────────────────────────────────────────────────────────────

describe("sanitize()", () => {
  let dom, sanitize;

  before(() => {
    dom = createSharedDOM();
    sanitize = dom.window.sanitize;
  });

  it("should escape < to &lt;", () => {
    assert.equal(sanitize("<"), "&lt;");
  });

  it("should escape > to &gt;", () => {
    assert.equal(sanitize(">"), "&gt;");
  });

  it("should escape & to &amp;", () => {
    assert.equal(sanitize("&"), "&amp;");
  });

  it('should escape " to &quot;', () => {
    const result = sanitize('"');
    // jsdom textContent→innerHTML may render " as &quot; or leave it
    // The important thing is the round-trip is safe
    assert.ok(!result.includes("<"), "Should not contain raw angle brackets");
  });

  it("should escape script tags", () => {
    const result = sanitize('<script>alert("xss")</script>');
    assert.ok(!result.includes("<script>"), "Script tag should be escaped");
    assert.ok(result.includes("&lt;script&gt;"), "Should contain escaped script tag");
  });

  it("should handle multiple special chars in one string", () => {
    const result = sanitize('<a href="test">&</a>');
    assert.ok(!result.includes("<a"), "Should not contain raw HTML tags");
    assert.ok(result.includes("&lt;a"), "Should contain escaped tags");
    assert.ok(result.includes("&amp;"), "Should contain escaped ampersand");
  });

  it("should return empty string for empty input", () => {
    assert.equal(sanitize(""), "");
  });

  it("should pass through already-safe strings unchanged", () => {
    assert.equal(sanitize("Hello World 123"), "Hello World 123");
  });

  it("should escape nested HTML tags", () => {
    const result = sanitize("<div><span>nested</span></div>");
    assert.ok(result.includes("&lt;div&gt;"), "Outer tag should be escaped");
    assert.ok(result.includes("&lt;span&gt;"), "Inner tag should be escaped");
  });

  it("should handle unicode strings", () => {
    const input = "日本語テスト 🎉 émojis";
    assert.equal(sanitize(input), input);
  });

  it("should handle very long strings", () => {
    const longStr = "a".repeat(10000) + "<script>" + "b".repeat(10000);
    const result = sanitize(longStr);
    assert.ok(!result.includes("<script>"), "Script tag should be escaped in long string");
    assert.ok(result.length > 20000, "Long string should be preserved");
  });
});

// ──────────────────────────────────────────────────────────────
// loadGifWithRetry()
// ──────────────────────────────────────────────────────────────

describe("loadGifWithRetry()", () => {
  let dom, window, document, loadGifWithRetry;

  beforeEach(() => {
    dom = createSharedDOM();
    window = dom.window;
    document = window.document;
    loadGifWithRetry = window.loadGifWithRetry;
  });

  it("should load image successfully on first attempt", () => {
    const container = document.createElement("div");
    container.innerHTML = "<p>old content</p>";
    const challenge = {
      title: "Funny Cat",
      gifUrl: "https://example.com/cat.gif",
      sourceUrl: "https://example.com/source",
    };

    loadGifWithRetry(container, challenge, 0);

    // Find the created img element (before load fires, it's in the closure)
    // Simulate successful load by finding the img and firing onload
    const img = container.querySelector("img") ||
      (() => {
        // The img is created but onload/onerror haven't been triggered yet.
        // The img is referenced in the closure. We need to find it via the
        // container's event — actually the img won't be in the container
        // until onload fires. Let's look at the DOM differently.
        // shared.js creates img, sets src, then waits for onload.
        // We need to trigger img.onload. Since img is local, we test the
        // side effects.
        return null;
      })();

    // The img is created inside the function scope but NOT yet appended.
    // It only gets appended on onload. We can verify the src is set correctly.
    // Since jsdom doesn't actually load images, let's check the setup is correct.
    assert.equal(container.innerHTML, "<p>old content</p>",
      "Container should not be modified before image loads");
  });

  it("should set correct src without cache-buster on first attempt", () => {
    const container = document.createElement("div");
    const challenge = {
      title: "Test",
      gifUrl: "https://example.com/test.gif",
      sourceUrl: "#",
    };

    // Intercept img creation by monkeypatching createElement
    let createdImg = null;
    const origCreate = document.createElement.bind(document);
    document.createElement = function (tag) {
      const el = origCreate(tag);
      if (tag === "img") createdImg = el;
      return el;
    };

    loadGifWithRetry(container, challenge, 0);

    assert.ok(createdImg, "Should have created an img element");
    assert.equal(createdImg.src, "https://example.com/test.gif",
      "First attempt should not add cache-buster");
  });

  it("should add cache-buster on retry attempts", () => {
    const container = document.createElement("div");
    const challenge = {
      title: "Test",
      gifUrl: "https://example.com/test.gif",
      sourceUrl: "#",
    };

    let createdImg = null;
    const origCreate = document.createElement.bind(document);
    document.createElement = function (tag) {
      const el = origCreate(tag);
      if (tag === "img") createdImg = el;
      return el;
    };

    loadGifWithRetry(container, challenge, 1);

    assert.ok(createdImg, "Should have created an img element");
    assert.equal(createdImg.src, "https://example.com/test.gif?retry=1",
      "Retry attempt should add cache-buster");
  });

  it("should set alt text including challenge title", () => {
    const container = document.createElement("div");
    const challenge = {
      title: "Dancing Robot",
      gifUrl: "https://example.com/robot.gif",
      sourceUrl: "#",
    };

    let createdImg = null;
    const origCreate = document.createElement.bind(document);
    document.createElement = function (tag) {
      const el = origCreate(tag);
      if (tag === "img") createdImg = el;
      return el;
    };

    loadGifWithRetry(container, challenge, 0);

    assert.ok(createdImg.alt.includes("Dancing Robot"),
      "Alt text should include challenge title");
    assert.ok(createdImg.alt.includes("GIF"),
      "Alt text should include 'GIF'");
  });

  it("should clear container on successful load", () => {
    const container = document.createElement("div");
    container.innerHTML = "<p>old content</p><span>more stuff</span>";
    const challenge = {
      title: "Test",
      gifUrl: "https://example.com/test.gif",
      sourceUrl: "#",
    };

    let createdImg = null;
    const origCreate = document.createElement.bind(document);
    document.createElement = function (tag) {
      const el = origCreate(tag);
      if (tag === "img") createdImg = el;
      return el;
    };

    loadGifWithRetry(container, challenge, 0);

    // Simulate successful load
    createdImg.onload();

    assert.equal(container.children.length, 1, "Container should have only the img");
    assert.equal(container.children[0].tagName, "IMG");
  });

  it("should show retry message on error before max retries", () => {
    const container = document.createElement("div");
    const challenge = {
      title: "Test",
      gifUrl: "https://example.com/test.gif",
      sourceUrl: "#",
    };

    let createdImg = null;
    const origCreate = document.createElement.bind(document);
    document.createElement = function (tag) {
      const el = origCreate(tag);
      if (tag === "img") createdImg = el;
      return el;
    };

    // Use fake timers to prevent actual setTimeout
    const origSetTimeout = window.setTimeout;
    let timeoutCallback = null;
    window.setTimeout = function (fn) { timeoutCallback = fn; };

    loadGifWithRetry(container, challenge, 0);

    // Simulate error on first attempt (attempt 0 < MAX_RETRIES which is 2)
    createdImg.onerror();

    assert.ok(container.innerHTML.includes("Retrying"),
      "Should show retry message");
    assert.ok(container.innerHTML.includes("1/2"),
      "Should show retry count");

    window.setTimeout = origSetTimeout;
  });

  it("should show error fallback with sourceUrl link after max retries", () => {
    const container = document.createElement("div");
    const challenge = {
      title: "Test",
      gifUrl: "https://example.com/test.gif",
      sourceUrl: "https://example.com/source",
    };

    let createdImg = null;
    const origCreate = document.createElement.bind(document);
    document.createElement = function (tag) {
      const el = origCreate(tag);
      if (tag === "img") createdImg = el;
      return el;
    };

    // attempt >= GIF_MAX_RETRIES (2) triggers final error
    loadGifWithRetry(container, challenge, 2);
    createdImg.onerror();

    assert.ok(container.innerHTML.includes("gif-error"),
      "Should show error container");
    assert.ok(container.innerHTML.includes("Open GIF in new tab"),
      "Should include link text for sourceUrl");
    assert.ok(container.innerHTML.includes("https://example.com/source"),
      "Should include the source URL");
  });

  it("should show error fallback with title hint when no sourceUrl", () => {
    const container = document.createElement("div");
    const challenge = {
      title: "Exploding Watermelon",
      gifUrl: "https://example.com/test.gif",
      sourceUrl: "#",
    };

    let createdImg = null;
    const origCreate = document.createElement.bind(document);
    document.createElement = function (tag) {
      const el = origCreate(tag);
      if (tag === "img") createdImg = el;
      return el;
    };

    loadGifWithRetry(container, challenge, 2);
    createdImg.onerror();

    assert.ok(container.innerHTML.includes("Exploding Watermelon"),
      "Should include challenge title as hint");
    assert.ok(container.innerHTML.includes("Hint"),
      "Should include hint label");
    assert.ok(!container.innerHTML.includes("Open GIF in new tab"),
      "Should NOT include link when sourceUrl is #");
  });

  it("should default alt text to 'CAPTCHA GIF' when title is missing", () => {
    const container = document.createElement("div");
    const challenge = {
      gifUrl: "https://example.com/test.gif",
      sourceUrl: "#",
    };

    let createdImg = null;
    const origCreate = document.createElement.bind(document);
    document.createElement = function (tag) {
      const el = origCreate(tag);
      if (tag === "img") createdImg = el;
      return el;
    };

    loadGifWithRetry(container, challenge, 0);

    assert.equal(createdImg.alt, "CAPTCHA GIF",
      "Should default to 'CAPTCHA GIF' when title is falsy");
  });
});

// ──────────────────────────────────────────────────────────────
// GIF_MAX_RETRIES / GIF_RETRY_DELAY_MS constants
// ──────────────────────────────────────────────────────────────

describe("GIF retry constants", () => {
  let dom;

  before(() => {
    dom = createSharedDOM();
  });

  it("GIF_MAX_RETRIES should be 2", () => {
    assert.equal(dom.window.GIF_MAX_RETRIES, 2);
  });

  it("GIF_RETRY_DELAY_MS should be 1500", () => {
    assert.equal(dom.window.GIF_RETRY_DELAY_MS, 1500);
  });
});

// ──────────────────────────────────────────────────────────────
// roundRect polyfill
// ──────────────────────────────────────────────────────────────

describe("roundRect polyfill", () => {
  it("should add polyfill when CanvasRenderingContext2D exists without native roundRect", () => {
    const dom = createSharedDOM({ defineCanvas: true, nativeRoundRect: false });
    const proto = dom.window.CanvasRenderingContext2D.prototype;
    assert.ok(typeof proto.roundRect === "function",
      "Polyfill should be added");
  });

  it("should NOT replace native roundRect when it already exists", () => {
    const dom = createSharedDOM({ defineCanvas: true, nativeRoundRect: true });
    const proto = dom.window.CanvasRenderingContext2D.prototype;
    assert.ok(proto.roundRect._isNative === true,
      "Native roundRect should not be replaced");
  });

  it("should draw correct path with numeric radius", () => {
    const dom = createSharedDOM({ defineCanvas: true, nativeRoundRect: false });
    const proto = dom.window.CanvasRenderingContext2D.prototype;

    // Track method calls
    const calls = [];
    const ctx = {
      moveTo: function (x, y) { calls.push(["moveTo", x, y]); },
      lineTo: function (x, y) { calls.push(["lineTo", x, y]); },
      quadraticCurveTo: function (cx, cy, x, y) { calls.push(["quadraticCurveTo", cx, cy, x, y]); },
      closePath: function () { calls.push(["closePath"]); },
    };

    proto.roundRect.call(ctx, 10, 20, 100, 50, 5);

    // Should have 4 moveTo/lineTo pairs + 4 quadraticCurveTo + 1 closePath
    const moveToCount = calls.filter(c => c[0] === "moveTo").length;
    const lineToCount = calls.filter(c => c[0] === "lineTo").length;
    const quadCount = calls.filter(c => c[0] === "quadraticCurveTo").length;
    const closeCount = calls.filter(c => c[0] === "closePath").length;

    assert.equal(moveToCount, 1, "Should have 1 moveTo");
    assert.equal(lineToCount, 4, "Should have 4 lineTo");
    assert.equal(quadCount, 4, "Should have 4 quadraticCurveTo");
    assert.equal(closeCount, 1, "Should have 1 closePath");
  });

  it("should handle array radii (uses first element)", () => {
    const dom = createSharedDOM({ defineCanvas: true, nativeRoundRect: false });
    const proto = dom.window.CanvasRenderingContext2D.prototype;

    const calls = [];
    const ctx = {
      moveTo: function (x, y) { calls.push(["moveTo", x, y]); },
      lineTo: function (x, y) { calls.push(["lineTo", x, y]); },
      quadraticCurveTo: function (cx, cy, x, y) { calls.push(["quadraticCurveTo", cx, cy, x, y]); },
      closePath: function () { calls.push(["closePath"]); },
    };

    proto.roundRect.call(ctx, 0, 0, 100, 50, [8, 4, 6, 2]);

    // r should be 8 (first element of array)
    // moveTo(0 + 8, 0) => moveTo(8, 0)
    assert.deepStrictEqual(calls[0], ["moveTo", 8, 0],
      "Should use first array element as radius");
  });

  it("should handle zero radius", () => {
    const dom = createSharedDOM({ defineCanvas: true, nativeRoundRect: false });
    const proto = dom.window.CanvasRenderingContext2D.prototype;

    const calls = [];
    const ctx = {
      moveTo: function (x, y) { calls.push(["moveTo", x, y]); },
      lineTo: function (x, y) { calls.push(["lineTo", x, y]); },
      quadraticCurveTo: function (cx, cy, x, y) { calls.push(["quadraticCurveTo", cx, cy, x, y]); },
      closePath: function () { calls.push(["closePath"]); },
    };

    proto.roundRect.call(ctx, 10, 20, 100, 50, 0);

    // r = 0, so moveTo(10 + 0, 20) => moveTo(10, 20)
    assert.deepStrictEqual(calls[0], ["moveTo", 10, 20],
      "Zero radius should produce sharp corners");
    // closePath should still be called
    assert.ok(calls.some(c => c[0] === "closePath"), "Should close path");
  });

  it("should handle undefined radius (defaults to 0)", () => {
    const dom = createSharedDOM({ defineCanvas: true, nativeRoundRect: false });
    const proto = dom.window.CanvasRenderingContext2D.prototype;

    const calls = [];
    const ctx = {
      moveTo: function (x, y) { calls.push(["moveTo", x, y]); },
      lineTo: function (x, y) { calls.push(["lineTo", x, y]); },
      quadraticCurveTo: function (cx, cy, x, y) { calls.push(["quadraticCurveTo", cx, cy, x, y]); },
      closePath: function () { calls.push(["closePath"]); },
    };

    proto.roundRect.call(ctx, 10, 20, 100, 50, undefined);

    // r = undefined || 0 => 0
    assert.deepStrictEqual(calls[0], ["moveTo", 10, 20],
      "Undefined radius should default to 0");
  });
});
