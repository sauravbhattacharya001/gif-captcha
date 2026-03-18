"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { WebhookDispatcher } = require("../src/webhook-dispatcher");

describe("WebhookDispatcher", () => {
  let dispatcher;

  beforeEach(() => {
    dispatcher = new WebhookDispatcher();
  });

  // ── Registration ────────────────────────────────────────────────

  describe("register", () => {
    it("registers a webhook and returns an id", () => {
      const result = dispatcher.register({ url: "https://example.com/hook" });
      assert.match(result.id, /^wh_/);
    });

    it("throws on missing URL", () => {
      assert.throws(() => dispatcher.register({}), /URL is required/);
    });

    it("throws on invalid URL", () => {
      assert.throws(() => dispatcher.register({ url: "not-a-url" }), /Invalid webhook URL/);
    });

    it("throws on unknown event type", () => {
      assert.throws(() => dispatcher.register({ url: "https://x.com", events: ["bogus"] }), /Unknown event type/);
    });

    it("enforces max webhook limit", () => {
      const d = new WebhookDispatcher({ maxWebhooks: 2 });
      d.register({ url: "https://a.com" });
      d.register({ url: "https://b.com" });
      assert.throws(() => d.register({ url: "https://c.com" }), /Maximum webhook limit/);
    });

    // ── SSRF Protection ───────────────────────────────────────────

    it("blocks localhost URLs (SSRF)", () => {
      assert.throws(() => dispatcher.register({ url: "http://localhost/hook" }), /SSRF protection/);
      assert.throws(() => dispatcher.register({ url: "https://localhost:8080/hook" }), /SSRF protection/);
    });

    it("blocks 127.x.x.x loopback (SSRF)", () => {
      assert.throws(() => dispatcher.register({ url: "http://127.0.0.1/hook" }), /SSRF protection/);
      assert.throws(() => dispatcher.register({ url: "http://127.0.0.255:3000/" }), /SSRF protection/);
    });

    it("blocks RFC 1918 private ranges (SSRF)", () => {
      assert.throws(() => dispatcher.register({ url: "http://10.0.0.1/hook" }), /SSRF protection/);
      assert.throws(() => dispatcher.register({ url: "http://172.16.0.1/hook" }), /SSRF protection/);
      assert.throws(() => dispatcher.register({ url: "http://172.31.255.255/hook" }), /SSRF protection/);
      assert.throws(() => dispatcher.register({ url: "http://192.168.1.1/hook" }), /SSRF protection/);
    });

    it("blocks cloud metadata endpoint 169.254.169.254 (SSRF)", () => {
      assert.throws(() => dispatcher.register({ url: "http://169.254.169.254/latest/meta-data/" }), /SSRF protection/);
    });

    it("blocks IPv6 loopback and private ranges (SSRF)", () => {
      assert.throws(() => dispatcher.register({ url: "http://[::1]/hook" }), /SSRF protection/);
      assert.throws(() => dispatcher.register({ url: "http://[fe80::1]/hook" }), /SSRF protection/);
      assert.throws(() => dispatcher.register({ url: "http://[fc00::1]/hook" }), /SSRF protection/);
      assert.throws(() => dispatcher.register({ url: "http://[fd12:3456::1]/hook" }), /SSRF protection/);
    });

    it("allows public internet URLs", () => {
      assert.doesNotThrow(() => dispatcher.register({ url: "https://hooks.slack.com/services/T00/B00/xxx" }));
      assert.doesNotThrow(() => dispatcher.register({ url: "https://8.8.8.8/hook" }));
    });

    it("registers with custom events filter", () => {
      const { id } = dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      const wh = dispatcher.list().find(w => w.id === id);
      assert.deepEqual(wh.events, ["captcha.solved"]);
    });

    it("registers with secret and description", () => {
      const { id } = dispatcher.register({
        url: "https://x.com",
        secret: "s3cret",
        description: "My hook",
      });
      const wh = dispatcher.list().find(w => w.id === id);
      assert.equal(wh.description, "My hook");
    });
  });

  // ── Unregister ──────────────────────────────────────────────────

  describe("unregister", () => {
    it("removes a webhook", () => {
      const { id } = dispatcher.register({ url: "https://x.com" });
      assert.equal(dispatcher.unregister(id), true);
      assert.equal(dispatcher.list().length, 0);
    });

    it("returns false for unknown id", () => {
      assert.equal(dispatcher.unregister("nope"), false);
    });
  });

  // ── setActive ───────────────────────────────────────────────────

  describe("setActive", () => {
    it("disables and re-enables a webhook", () => {
      const { id } = dispatcher.register({ url: "https://x.com" });
      dispatcher.setActive(id, false);
      assert.equal(dispatcher.list()[0].active, false);
      dispatcher.setActive(id, true);
      assert.equal(dispatcher.list()[0].active, true);
    });

    it("throws for unknown webhook", () => {
      assert.throws(() => dispatcher.setActive("nope", false), /not found/);
    });
  });

  // ── list ────────────────────────────────────────────────────────

  describe("list", () => {
    it("returns all registered webhooks", () => {
      dispatcher.register({ url: "https://a.com" });
      dispatcher.register({ url: "https://b.com" });
      assert.equal(dispatcher.list().length, 2);
    });

    it("returns copies (not references)", () => {
      dispatcher.register({ url: "https://a.com" });
      const list = dispatcher.list();
      list[0].url = "modified";
      assert.equal(dispatcher.list()[0].url, "https://a.com");
    });
  });

  // ── Dispatch (no transport) ─────────────────────────────────────

  describe("dispatch without httpPost", () => {
    it("returns no_transport status", async () => {
      dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await dispatcher.dispatch("captcha.solved", { id: "abc" });
      assert.equal(results.length, 1);
      assert.equal(results[0].status, "no_transport");
    });

    it("rejects unknown event types", async () => {
      await assert.rejects(() => dispatcher.dispatch("bogus", {}), /Unknown event type/);
    });

    it("returns empty array when paused", async () => {
      dispatcher.register({ url: "https://x.com" });
      dispatcher.pause();
      const results = await dispatcher.dispatch("captcha.solved", {});
      assert.deepEqual(results, []);
    });

    it("skips inactive webhooks", async () => {
      const { id } = dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      dispatcher.setActive(id, false);
      const results = await dispatcher.dispatch("captcha.solved", {});
      assert.deepEqual(results, []);
    });

    it("only dispatches to matching event subscriptions", async () => {
      dispatcher.register({ url: "https://a.com", events: ["captcha.solved"] });
      dispatcher.register({ url: "https://b.com", events: ["captcha.failed"] });
      const results = await dispatcher.dispatch("captcha.solved", {});
      assert.equal(results.length, 1);
    });
  });

  // ── Dispatch with mock transport ────────────────────────────────

  describe("dispatch with httpPost", () => {
    it("delivers successfully on 200", async () => {
      const d = new WebhookDispatcher({
        httpPost: async () => ({ status: 200, body: "OK" }),
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await d.dispatch("captcha.solved", { foo: 1 });
      assert.equal(results[0].status, "delivered");
      assert.equal(results[0].statusCode, 200);
    });

    it("retries on 500 and eventually fails", async () => {
      let calls = 0;
      const d = new WebhookDispatcher({
        maxRetries: 2,
        baseDelayMs: 1,
        httpPost: async () => { calls++; return { status: 500 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await d.dispatch("captcha.solved", {});
      assert.equal(results[0].status, "failed");
      assert.equal(calls, 2);
    });

    it("retries on network error", async () => {
      let calls = 0;
      const d = new WebhookDispatcher({
        maxRetries: 2,
        baseDelayMs: 1,
        httpPost: async () => { calls++; throw new Error("ECONNREFUSED"); },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await d.dispatch("captcha.solved", {});
      assert.equal(results[0].status, "error");
      assert.equal(results[0].error, "ECONNREFUSED");
      assert.equal(calls, 2);
    });

    it("succeeds on retry after initial failure", async () => {
      let calls = 0;
      const d = new WebhookDispatcher({
        maxRetries: 3,
        baseDelayMs: 1,
        httpPost: async () => { calls++; if (calls < 2) return { status: 500 }; return { status: 200 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await d.dispatch("captcha.solved", {});
      assert.equal(results[0].status, "delivered");
      assert.equal(results[0].attempt, 2);
    });

    it("includes HMAC signature when secret is set", async () => {
      let capturedHeaders = {};
      const d = new WebhookDispatcher({
        httpPost: async (url, headers) => { capturedHeaders = headers; return { status: 200 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"], secret: "test-secret" });
      await d.dispatch("captcha.solved", { x: 1 });
      assert.match(capturedHeaders["X-GifCaptcha-Signature"], /^sha256=[a-f0-9]{64}$/);
    });

    it("does not include signature without secret", async () => {
      let capturedHeaders = {};
      const d = new WebhookDispatcher({
        httpPost: async (url, headers) => { capturedHeaders = headers; return { status: 200 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      await d.dispatch("captcha.solved", {});
      assert.equal(capturedHeaders["X-GifCaptcha-Signature"], undefined);
    });

    it("includes custom headers", async () => {
      let capturedHeaders = {};
      const d = new WebhookDispatcher({
        httpPost: async (url, headers) => { capturedHeaders = headers; return { status: 200 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"], headers: { "X-Custom": "val" } });
      await d.dispatch("captcha.solved", {});
      assert.equal(capturedHeaders["X-Custom"], "val");
    });
  });

  // ── Rate Limiting ───────────────────────────────────────────────

  describe("rate limiting", () => {
    it("rate limits after exceeding per-minute limit", async () => {
      const d = new WebhookDispatcher({
        rateLimitPerMinute: 2,
        httpPost: async () => ({ status: 200 }),
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      await d.dispatch("captcha.solved", {});
      await d.dispatch("captcha.solved", {});
      const results = await d.dispatch("captcha.solved", {});
      assert.equal(results[0].status, "rate_limited");
    });
  });

  // ── Payload Size ────────────────────────────────────────────────

  describe("payload size limit", () => {
    it("rejects oversized payloads", async () => {
      const d = new WebhookDispatcher({ payloadMaxBytes: 50 });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      await assert.rejects(() => d.dispatch("captcha.solved", { big: "x".repeat(100) }), /maximum size/);
    });
  });

  // ── Delivery Log ───────────────────────────────────────────────

  describe("delivery log", () => {
    it("logs deliveries", async () => {
      dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      await dispatcher.dispatch("captcha.solved", {});
      const log = dispatcher.getDeliveryLog();
      assert.equal(log.length, 1);
      assert.equal(log[0].event, "captcha.solved");
    });

    it("filters by webhookId", async () => {
      const { id: id1 } = dispatcher.register({ url: "https://a.com", events: ["captcha.solved"] });
      dispatcher.register({ url: "https://b.com", events: ["captcha.solved"] });
      await dispatcher.dispatch("captcha.solved", {});
      const log = dispatcher.getDeliveryLog({ webhookId: id1 });
      assert.equal(log.length, 1);
    });

    it("filters by status", async () => {
      dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      await dispatcher.dispatch("captcha.solved", {});
      const log = dispatcher.getDeliveryLog({ status: "no_transport" });
      assert.equal(log.length, 1);
    });

    it("respects limit", async () => {
      dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      await dispatcher.dispatch("captcha.solved", {});
      await dispatcher.dispatch("captcha.solved", {});
      await dispatcher.dispatch("captcha.solved", {});
      const log = dispatcher.getDeliveryLog({ limit: 2 });
      assert.equal(log.length, 2);
    });

    it("trims log when exceeding maxLogSize", async () => {
      const d = new WebhookDispatcher({ maxLogSize: 5 });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      for (let i = 0; i < 8; i++) await d.dispatch("captcha.solved", {});
      assert.ok(d.getDeliveryLog().length <= 5);
    });
  });

  // ── getStats ────────────────────────────────────────────────────

  describe("getStats", () => {
    it("returns stats for a webhook", async () => {
      const d = new WebhookDispatcher({
        httpPost: async () => ({ status: 200 }),
      });
      const { id } = d.register({ url: "https://x.com", events: ["captcha.solved", "captcha.failed"] });
      await d.dispatch("captcha.solved", {});
      await d.dispatch("captcha.failed", {});
      const stats = d.getStats(id);
      assert.equal(stats.totalSent, 2);
      assert.equal(stats.byEvent["captcha.solved"].delivered, 1);
    });

    it("throws for unknown webhook", () => {
      assert.throws(() => dispatcher.getStats("nope"), /not found/);
    });
  });

  // ── Pause / Resume ──────────────────────────────────────────────

  describe("pause/resume", () => {
    it("pauses and resumes dispatch", () => {
      assert.equal(dispatcher.isPaused(), false);
      dispatcher.pause();
      assert.equal(dispatcher.isPaused(), true);
      dispatcher.resume();
      assert.equal(dispatcher.isPaused(), false);
    });
  });

  // ── Signature Verification ──────────────────────────────────────

  describe("verifySignature", () => {
    it("verifies valid signature", () => {
      const payload = '{"event":"test"}';
      const secret = "my-secret";
      const sig = "sha256=" + require("crypto").createHmac("sha256", secret).update(payload).digest("hex");
      assert.equal(WebhookDispatcher.verifySignature(payload, sig, secret), true);
    });

    it("rejects invalid signature", () => {
      assert.equal(WebhookDispatcher.verifySignature('{"event":"test"}', "sha256=bad", "secret"), false);
    });

    it("returns false for missing params", () => {
      assert.equal(WebhookDispatcher.verifySignature(null, null, null), false);
    });
  });

  // ── EVENT_TYPES constant ────────────────────────────────────────

  describe("EVENT_TYPES", () => {
    it("exports all expected event types", () => {
      assert.ok(WebhookDispatcher.EVENT_TYPES.includes("captcha.created"));
      assert.ok(WebhookDispatcher.EVENT_TYPES.includes("captcha.solved"));
      assert.ok(WebhookDispatcher.EVENT_TYPES.includes("trust.updated"));
      assert.equal(WebhookDispatcher.EVENT_TYPES.length, 10);
    });
  });
});
