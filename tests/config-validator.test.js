"use strict";

var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var gifCaptcha = require("../src/index");

describe("createConfigValidator", function () {
  // ── API surface ───────────────────────────────────────────────

  it("should return an object with validate and rules", function () {
    var v = gifCaptcha.createConfigValidator();
    assert.strictEqual(typeof v.validate, "function");
    assert.strictEqual(typeof v.rules, "function");
  });

  it("rules() should return array of rule descriptors", function () {
    var v = gifCaptcha.createConfigValidator();
    var r = v.rules();
    assert.ok(Array.isArray(r));
    assert.ok(r.length > 0);
    r.forEach(function (rule) {
      assert.ok(rule.id, "rule has id");
      assert.ok(rule.module, "rule has module");
      assert.ok(rule.field, "rule has field");
      assert.ok(rule.severity, "rule has severity");
    });
  });

  // ── Empty/valid config ────────────────────────────────────────

  it("should pass with empty config", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({});
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.errors.length, 0);
  });

  it("should pass with null/undefined config", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate(null);
    assert.strictEqual(result.valid, true);
  });

  it("result should have expected shape", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({});
    assert.ok("valid" in result);
    assert.ok("errors" in result);
    assert.ok("warnings" in result);
    assert.ok("info" in result);
    assert.ok("summary" in result);
    assert.ok(Array.isArray(result.errors));
    assert.ok(Array.isArray(result.warnings));
    assert.ok(typeof result.summary === "string");
  });

  // ── AttemptTracker rules ──────────────────────────────────────

  it("should error on non-numeric maxAttempts", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxAttempts: "five" });
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.some(function (e) { return e.id === "attempt.maxAttempts.type"; }));
  });

  it("should error on maxAttempts < 1", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxAttempts: 0 });
    assert.strictEqual(result.valid, false);
  });

  it("should warn on maxAttempts = 1", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxAttempts: 1 });
    assert.ok(result.warnings.some(function (w) { return w.id === "attempt.maxAttempts.low"; }));
  });

  it("should pass on valid maxAttempts", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxAttempts: 5 });
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.errors.length, 0);
  });

  it("should error on negative lockoutMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ lockoutMs: -1 });
    assert.strictEqual(result.valid, false);
  });

  it("should warn on very short lockoutMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ lockoutMs: 500 });
    assert.ok(result.warnings.some(function (w) { return w.id === "attempt.lockoutMs.short"; }));
  });

  it("should warn on very long lockoutMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ lockoutMs: 7200000 }); // 2 hours
    assert.ok(result.warnings.some(function (w) { return w.id === "attempt.lockoutMs.long"; }));
  });

  // ── TokenVerifier rules ───────────────────────────────────────

  it("should error on non-string secret", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ secret: 12345 });
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.some(function (e) { return e.id === "token.secret.missing"; }));
  });

  it("should error on short secret", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ secret: "short" });
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.some(function (e) { return e.id === "token.secret.weak"; }));
  });

  it("should warn on low-entropy secret", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ secret: "aaaaaaaaaaaaaaaa" }); // 16 chars but 1 unique
    assert.ok(result.warnings.some(function (w) { return w.id === "token.secret.entropy"; }));
  });

  it("should pass on good secret", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ secret: "a3b9f2c7d1e8g5h4k6m0n7p2q9r1s5t3" });
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.errors.length, 0);
    assert.ok(!result.warnings.some(function (w) { return w.id === "token.secret.entropy"; }));
  });

  it("should error on non-positive ttlMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ ttlMs: 0 });
    assert.strictEqual(result.valid, false);
  });

  it("should warn on very short ttlMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ ttlMs: 5000 });
    assert.ok(result.warnings.some(function (w) { return w.id === "token.ttlMs.short"; }));
  });

  // ── BotDetector rules ────────────────────────────────────────

  it("should error on botThreshold out of range", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ botThreshold: 150 });
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.some(function (e) { return e.id === "bot.threshold.range"; }));
  });

  it("should error when suspiciousThreshold >= botThreshold", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ botThreshold: 50, suspiciousThreshold: 60 });
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.some(function (e) { return e.id === "bot.threshold.inverted"; }));
  });

  it("should pass with correct threshold ordering", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ botThreshold: 60, suspiciousThreshold: 30 });
    assert.ok(!result.errors.some(function (e) { return e.id === "bot.threshold.inverted"; }));
  });

  it("should error on negative minMouseMovements", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ minMouseMovements: -1 });
    assert.strictEqual(result.valid, false);
  });

  it("should error on negative minTimeOnPageMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ minTimeOnPageMs: -100 });
    assert.strictEqual(result.valid, false);
  });

  // ── DifficultyCalibrator rules ────────────────────────────────

  it("should error on minPassRate out of range", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ minPassRate: 1.5 });
    assert.strictEqual(result.valid, false);
  });

  it("should error when minPassRate >= maxPassRate", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ minPassRate: 0.8, maxPassRate: 0.5 });
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.some(function (e) { return e.id === "difficulty.passRate.inverted"; }));
  });

  it("should error when baseDifficulty > maxDifficulty", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ baseDifficulty: 80, maxDifficulty: 50 });
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.some(function (e) { return e.id === "difficulty.base.exceeds.max"; }));
  });

  it("should pass with correct difficulty ordering", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ baseDifficulty: 30, maxDifficulty: 90 });
    assert.ok(!result.errors.some(function (e) { return e.id === "difficulty.base.exceeds.max"; }));
  });

  // ── RateLimiter rules ────────────────────────────────────────

  it("should error on non-positive windowMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ windowMs: 0 });
    assert.strictEqual(result.valid, false);
  });

  it("should error on non-positive maxRequests", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxRequests: 0 });
    assert.strictEqual(result.valid, false);
  });

  it("should warn on overly aggressive rate limiting", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxRequests: 1, windowMs: 60000 }); // 1 req/min
    assert.ok(result.warnings.some(function (w) { return w.id === "rate.maxRequests.aggressive"; }));
  });

  it("should not warn on reasonable rate limits", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxRequests: 10, windowMs: 60000 }); // 10 req/min
    assert.ok(!result.warnings.some(function (w) { return w.id === "rate.maxRequests.aggressive"; }));
  });

  // ── ReputationTracker rules ──────────────────────────────────

  it("should error on inverted reputation thresholds", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({
      trustedThreshold: 0.2,
      suspiciousThreshold: 0.5,
      blockThreshold: 0.1
    });
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.some(function (e) { return e.id === "reputation.threshold.inverted"; }));
  });

  it("should pass with correct reputation thresholds", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({
      trustedThreshold: 0.8,
      suspiciousThreshold: 0.3,
      blockThreshold: 0.1
    });
    assert.ok(!result.errors.some(function (e) { return e.id === "reputation.threshold.inverted"; }));
  });

  it("should error on out-of-range initialScore", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ initialScore: 1.5 });
    assert.strictEqual(result.valid, false);
  });

  it("should warn on very low maxEntries", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxEntries: 10 });
    assert.ok(result.warnings.some(function (w) { return w.id === "reputation.maxEntries.low"; }));
  });

  // ── PoolManager rules ────────────────────────────────────────

  it("should error on non-positive rotationIntervalMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ rotationIntervalMs: 0 });
    assert.strictEqual(result.valid, false);
  });

  it("should warn on very fast rotation", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ rotationIntervalMs: 5000 }); // 5 seconds
    assert.ok(result.warnings.some(function (w) { return w.id === "pool.rotation.fast"; }));
  });

  // ── AdaptiveTimeout rules ────────────────────────────────────

  it("should error on non-positive baseTimeoutMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ baseTimeoutMs: 0 });
    assert.strictEqual(result.valid, false);
  });

  it("should warn on very short baseTimeoutMs", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ baseTimeoutMs: 3000 });
    assert.ok(result.warnings.some(function (w) { return w.id === "timeout.base.short"; }));
  });

  // ── General rules ────────────────────────────────────────────

  it("should error on passThreshold out of range", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ passThreshold: 2.0 });
    assert.strictEqual(result.valid, false);
  });

  it("should warn on extremely high passThreshold", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ passThreshold: 0.99 });
    assert.ok(result.warnings.some(function (w) { return w.id === "general.passThreshold.extreme"; }));
  });

  it("should warn on extremely low passThreshold", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ passThreshold: 0.1 });
    assert.ok(result.warnings.some(function (w) { return w.id === "general.passThreshold.extreme"; }));
  });

  it("should warn on excessive challengeCount", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ challengeCount: 20 });
    assert.ok(result.warnings.some(function (w) { return w.id === "general.challenges.count"; }));
  });

  // ── Module filtering ──────────────────────────────────────────

  it("should filter by module", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate(
      { maxAttempts: "bad", secret: 123, minPassRate: 5 },
      { module: "tokenVerifier" }
    );
    // Only token errors, not attempt or difficulty errors
    result.errors.forEach(function (e) {
      assert.strictEqual(e.module, "tokenVerifier");
    });
  });

  // ── Ignore option ─────────────────────────────────────────────

  it("should skip ignored rule IDs", function () {
    var v = gifCaptcha.createConfigValidator({ ignore: ["attempt.maxAttempts.type"] });
    var result = v.validate({ maxAttempts: "bad" });
    assert.ok(!result.errors.some(function (e) { return e.id === "attempt.maxAttempts.type"; }));
  });

  // ── Strict mode ───────────────────────────────────────────────

  it("strict mode should promote warnings to errors", function () {
    var v = gifCaptcha.createConfigValidator({ strict: true });
    var result = v.validate({ lockoutMs: 500 }); // normally a warning
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.some(function (e) { return e.id === "attempt.lockoutMs.short"; }));
    assert.strictEqual(result.warnings.length, 0);
  });

  it("strict mode with valid config should pass", function () {
    var v = gifCaptcha.createConfigValidator({ strict: true });
    var result = v.validate({});
    assert.strictEqual(result.valid, true);
  });

  // ── Summary messages ──────────────────────────────────────────

  it("summary should say valid with no issues for clean config", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({});
    assert.ok(result.summary.includes("Valid"));
    assert.ok(result.summary.includes("no issues"));
  });

  it("summary should mention warnings when present", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxAttempts: 1 });
    assert.ok(result.summary.includes("warning"));
  });

  it("summary should say invalid when errors present", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxAttempts: "bad" });
    assert.ok(result.summary.includes("Invalid"));
    assert.ok(result.summary.includes("error"));
  });

  // ── Multiple issues at once ──────────────────────────────────

  it("should report multiple issues from different modules", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({
      maxAttempts: "bad",       // error
      secret: "short",          // error
      botThreshold: 150,        // error
      lockoutMs: 500,           // warning
      passThreshold: 0.99       // warning
    });
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.length >= 3);
    assert.ok(result.warnings.length >= 1);
  });

  // ── Finding structure ─────────────────────────────────────────

  it("finding should have id, module, field, severity, message", function () {
    var v = gifCaptcha.createConfigValidator();
    var result = v.validate({ maxAttempts: "bad" });
    var finding = result.errors[0];
    assert.ok(finding.id);
    assert.ok(finding.module);
    assert.ok(finding.field);
    assert.ok(finding.severity);
    assert.ok(finding.message);
    assert.strictEqual(finding.severity, "error");
  });
});
