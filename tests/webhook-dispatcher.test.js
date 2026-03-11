"use strict";

const { WebhookDispatcher } = require("../src/webhook-dispatcher");

describe("WebhookDispatcher", () => {
  let dispatcher;

  beforeEach(() => {
    dispatcher = new WebhookDispatcher();
  });

  // ── Registration ────────────────────────────────────────────────

  describe("register", () => {
    test("registers a webhook and returns an id", () => {
      const result = dispatcher.register({ url: "https://example.com/hook" });
      expect(result.id).toMatch(/^wh_/);
    });

    test("throws on missing URL", () => {
      expect(() => dispatcher.register({})).toThrow("URL is required");
    });

    test("throws on invalid URL", () => {
      expect(() => dispatcher.register({ url: "not-a-url" })).toThrow("Invalid webhook URL");
    });

    test("throws on unknown event type", () => {
      expect(() => dispatcher.register({ url: "https://x.com", events: ["bogus"] })).toThrow("Unknown event type");
    });

    test("enforces max webhook limit", () => {
      const d = new WebhookDispatcher({ maxWebhooks: 2 });
      d.register({ url: "https://a.com" });
      d.register({ url: "https://b.com" });
      expect(() => d.register({ url: "https://c.com" })).toThrow("Maximum webhook limit");
    });

    test("registers with custom events filter", () => {
      const { id } = dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      const wh = dispatcher.list().find(w => w.id === id);
      expect(wh.events).toEqual(["captcha.solved"]);
    });

    test("registers with secret and description", () => {
      const { id } = dispatcher.register({
        url: "https://x.com",
        secret: "s3cret",
        description: "My hook",
      });
      const wh = dispatcher.list().find(w => w.id === id);
      expect(wh.description).toBe("My hook");
    });
  });

  // ── Unregister ──────────────────────────────────────────────────

  describe("unregister", () => {
    test("removes a webhook", () => {
      const { id } = dispatcher.register({ url: "https://x.com" });
      expect(dispatcher.unregister(id)).toBe(true);
      expect(dispatcher.list()).toHaveLength(0);
    });

    test("returns false for unknown id", () => {
      expect(dispatcher.unregister("nope")).toBe(false);
    });
  });

  // ── setActive ───────────────────────────────────────────────────

  describe("setActive", () => {
    test("disables and re-enables a webhook", () => {
      const { id } = dispatcher.register({ url: "https://x.com" });
      dispatcher.setActive(id, false);
      expect(dispatcher.list()[0].active).toBe(false);
      dispatcher.setActive(id, true);
      expect(dispatcher.list()[0].active).toBe(true);
    });

    test("throws for unknown webhook", () => {
      expect(() => dispatcher.setActive("nope", false)).toThrow("not found");
    });
  });

  // ── list ────────────────────────────────────────────────────────

  describe("list", () => {
    test("returns all registered webhooks", () => {
      dispatcher.register({ url: "https://a.com" });
      dispatcher.register({ url: "https://b.com" });
      expect(dispatcher.list()).toHaveLength(2);
    });

    test("returns copies (not references)", () => {
      dispatcher.register({ url: "https://a.com" });
      const list = dispatcher.list();
      list[0].url = "modified";
      expect(dispatcher.list()[0].url).toBe("https://a.com");
    });
  });

  // ── Dispatch (no transport) ─────────────────────────────────────

  describe("dispatch without httpPost", () => {
    test("returns no_transport status", async () => {
      dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await dispatcher.dispatch("captcha.solved", { id: "abc" });
      expect(results).toHaveLength(1);
      expect(results[0].status).toBe("no_transport");
    });

    test("rejects unknown event types", async () => {
      await expect(dispatcher.dispatch("bogus", {})).rejects.toThrow("Unknown event type");
    });

    test("returns empty array when paused", async () => {
      dispatcher.register({ url: "https://x.com" });
      dispatcher.pause();
      const results = await dispatcher.dispatch("captcha.solved", {});
      expect(results).toEqual([]);
    });

    test("skips inactive webhooks", async () => {
      const { id } = dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      dispatcher.setActive(id, false);
      const results = await dispatcher.dispatch("captcha.solved", {});
      expect(results).toEqual([]);
    });

    test("only dispatches to matching event subscriptions", async () => {
      dispatcher.register({ url: "https://a.com", events: ["captcha.solved"] });
      dispatcher.register({ url: "https://b.com", events: ["captcha.failed"] });
      const results = await dispatcher.dispatch("captcha.solved", {});
      expect(results).toHaveLength(1);
    });
  });

  // ── Dispatch with mock transport ────────────────────────────────

  describe("dispatch with httpPost", () => {
    test("delivers successfully on 200", async () => {
      const d = new WebhookDispatcher({
        httpPost: async () => ({ status: 200, body: "OK" }),
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await d.dispatch("captcha.solved", { foo: 1 });
      expect(results[0].status).toBe("delivered");
      expect(results[0].statusCode).toBe(200);
    });

    test("retries on 500 and eventually fails", async () => {
      let calls = 0;
      const d = new WebhookDispatcher({
        maxRetries: 2,
        baseDelayMs: 1,
        httpPost: async () => { calls++; return { status: 500 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await d.dispatch("captcha.solved", {});
      expect(results[0].status).toBe("failed");
      expect(calls).toBe(2);
    });

    test("retries on network error", async () => {
      let calls = 0;
      const d = new WebhookDispatcher({
        maxRetries: 2,
        baseDelayMs: 1,
        httpPost: async () => { calls++; throw new Error("ECONNREFUSED"); },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await d.dispatch("captcha.solved", {});
      expect(results[0].status).toBe("error");
      expect(results[0].error).toBe("ECONNREFUSED");
      expect(calls).toBe(2);
    });

    test("succeeds on retry after initial failure", async () => {
      let calls = 0;
      const d = new WebhookDispatcher({
        maxRetries: 3,
        baseDelayMs: 1,
        httpPost: async () => { calls++; if (calls < 2) return { status: 500 }; return { status: 200 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      const results = await d.dispatch("captcha.solved", {});
      expect(results[0].status).toBe("delivered");
      expect(results[0].attempt).toBe(2);
    });

    test("includes HMAC signature when secret is set", async () => {
      let capturedHeaders = {};
      const d = new WebhookDispatcher({
        httpPost: async (url, headers) => { capturedHeaders = headers; return { status: 200 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"], secret: "test-secret" });
      await d.dispatch("captcha.solved", { x: 1 });
      expect(capturedHeaders["X-GifCaptcha-Signature"]).toMatch(/^sha256=[a-f0-9]{64}$/);
    });

    test("does not include signature without secret", async () => {
      let capturedHeaders = {};
      const d = new WebhookDispatcher({
        httpPost: async (url, headers) => { capturedHeaders = headers; return { status: 200 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      await d.dispatch("captcha.solved", {});
      expect(capturedHeaders["X-GifCaptcha-Signature"]).toBeUndefined();
    });

    test("includes custom headers", async () => {
      let capturedHeaders = {};
      const d = new WebhookDispatcher({
        httpPost: async (url, headers) => { capturedHeaders = headers; return { status: 200 }; },
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"], headers: { "X-Custom": "val" } });
      await d.dispatch("captcha.solved", {});
      expect(capturedHeaders["X-Custom"]).toBe("val");
    });
  });

  // ── Rate Limiting ───────────────────────────────────────────────

  describe("rate limiting", () => {
    test("rate limits after exceeding per-minute limit", async () => {
      const d = new WebhookDispatcher({
        rateLimitPerMinute: 2,
        httpPost: async () => ({ status: 200 }),
      });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      await d.dispatch("captcha.solved", {});
      await d.dispatch("captcha.solved", {});
      const results = await d.dispatch("captcha.solved", {});
      expect(results[0].status).toBe("rate_limited");
    });
  });

  // ── Payload Size ────────────────────────────────────────────────

  describe("payload size limit", () => {
    test("rejects oversized payloads", async () => {
      const d = new WebhookDispatcher({ payloadMaxBytes: 50 });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      await expect(d.dispatch("captcha.solved", { big: "x".repeat(100) })).rejects.toThrow("maximum size");
    });
  });

  // ── Delivery Log ───────────────────────────────────────────────

  describe("delivery log", () => {
    test("logs deliveries", async () => {
      dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      await dispatcher.dispatch("captcha.solved", {});
      const log = dispatcher.getDeliveryLog();
      expect(log).toHaveLength(1);
      expect(log[0].event).toBe("captcha.solved");
    });

    test("filters by webhookId", async () => {
      const { id: id1 } = dispatcher.register({ url: "https://a.com", events: ["captcha.solved"] });
      dispatcher.register({ url: "https://b.com", events: ["captcha.solved"] });
      await dispatcher.dispatch("captcha.solved", {});
      const log = dispatcher.getDeliveryLog({ webhookId: id1 });
      expect(log).toHaveLength(1);
    });

    test("filters by status", async () => {
      dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      await dispatcher.dispatch("captcha.solved", {});
      const log = dispatcher.getDeliveryLog({ status: "no_transport" });
      expect(log).toHaveLength(1);
    });

    test("respects limit", async () => {
      dispatcher.register({ url: "https://x.com", events: ["captcha.solved"] });
      await dispatcher.dispatch("captcha.solved", {});
      await dispatcher.dispatch("captcha.solved", {});
      await dispatcher.dispatch("captcha.solved", {});
      const log = dispatcher.getDeliveryLog({ limit: 2 });
      expect(log).toHaveLength(2);
    });

    test("trims log when exceeding maxLogSize", async () => {
      const d = new WebhookDispatcher({ maxLogSize: 5 });
      d.register({ url: "https://x.com", events: ["captcha.solved"] });
      for (let i = 0; i < 8; i++) await d.dispatch("captcha.solved", {});
      expect(d.getDeliveryLog().length).toBeLessThanOrEqual(5);
    });
  });

  // ── getStats ────────────────────────────────────────────────────

  describe("getStats", () => {
    test("returns stats for a webhook", async () => {
      const d = new WebhookDispatcher({
        httpPost: async () => ({ status: 200 }),
      });
      const { id } = d.register({ url: "https://x.com", events: ["captcha.solved", "captcha.failed"] });
      await d.dispatch("captcha.solved", {});
      await d.dispatch("captcha.failed", {});
      const stats = d.getStats(id);
      expect(stats.totalSent).toBe(2);
      expect(stats.byEvent["captcha.solved"].delivered).toBe(1);
    });

    test("throws for unknown webhook", () => {
      expect(() => dispatcher.getStats("nope")).toThrow("not found");
    });
  });

  // ── Pause / Resume ──────────────────────────────────────────────

  describe("pause/resume", () => {
    test("pauses and resumes dispatch", () => {
      expect(dispatcher.isPaused()).toBe(false);
      dispatcher.pause();
      expect(dispatcher.isPaused()).toBe(true);
      dispatcher.resume();
      expect(dispatcher.isPaused()).toBe(false);
    });
  });

  // ── Signature Verification ──────────────────────────────────────

  describe("verifySignature", () => {
    test("verifies valid signature", () => {
      const payload = '{"event":"test"}';
      const secret = "my-secret";
      const sig = "sha256=" + require("crypto").createHmac("sha256", secret).update(payload).digest("hex");
      expect(WebhookDispatcher.verifySignature(payload, sig, secret)).toBe(true);
    });

    test("rejects invalid signature", () => {
      expect(WebhookDispatcher.verifySignature('{"event":"test"}', "sha256=bad", "secret")).toBe(false);
    });

    test("returns false for missing params", () => {
      expect(WebhookDispatcher.verifySignature(null, null, null)).toBe(false);
    });
  });

  // ── EVENT_TYPES constant ────────────────────────────────────────

  describe("EVENT_TYPES", () => {
    test("exports all expected event types", () => {
      expect(WebhookDispatcher.EVENT_TYPES).toContain("captcha.created");
      expect(WebhookDispatcher.EVENT_TYPES).toContain("captcha.solved");
      expect(WebhookDispatcher.EVENT_TYPES).toContain("trust.updated");
      expect(WebhookDispatcher.EVENT_TYPES.length).toBe(10);
    });
  });
});
