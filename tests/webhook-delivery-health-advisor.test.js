"use strict";

var assert = require("assert");
var test = require("node:test");
var mod = require("../src/webhook-delivery-health-advisor");

function mk(opts) { return mod.createWebhookDeliveryHealthAdvisor(opts || {}); }

function ep(id, url) { return { id: id, url: url || ("https://example.com/" + id) }; }

function entry(over) {
  var e = {
    webhookId: "wh1",
    event: "captcha.solved",
    status: "delivered",
    attempts: 1,
    statusCode: 200,
    timestamp: 1_700_000_000_000,
  };
  if (over) Object.keys(over).forEach(function (k) { e[k] = over[k]; });
  return e;
}

test("factory exposes expected API", function () {
  var a = mk();
  ["analyze", "formatText", "formatMarkdown", "formatJson"]
    .forEach(function (m) { assert.strictEqual(typeof a[m], "function", m); });
  assert.ok(a.DEFAULT_OPTIONS && typeof a.DEFAULT_OPTIONS === "object");
});

test("empty inputs -> healthy grade A, NO_DELIVERY_ACTIVITY or NO_WEBHOOK_ENDPOINTS_REGISTERED", function () {
  var a = mk();
  var r = a.analyze({ deliveryLog: [], endpoints: [] });
  assert.strictEqual(r.summary.grade, "A");
  assert.strictEqual(r.summary.band, "HEALTHY");
  assert.deepStrictEqual(r.findings, []);
  assert.ok(r.insights.indexOf("NO_WEBHOOK_ENDPOINTS_REGISTERED") !== -1);
  assert.strictEqual(r.playbook[0].id, "NO_WEBHOOK_ACTION_NEEDED");
});

test("idle registered endpoint -> IDLE/P2 finding", function () {
  var a = mk();
  var r = a.analyze({
    deliveryLog: [],
    endpoints: [ep("wh1")],
  });
  assert.strictEqual(r.findings.length, 1);
  assert.strictEqual(r.findings[0].verdict, "IDLE");
  assert.strictEqual(r.findings[0].priority, "P2");
  assert.ok(r.playbook.some(function (a) { return a.id === "CONFIRM_IDLE_ENDPOINTS"; }));
});

test("dead endpoint (all failures) -> DEAD_ENDPOINT P0 + disable action", function () {
  var a = mk();
  var log = [];
  for (var i = 0; i < 12; i++) {
    log.push(entry({ status: "failed", attempts: 4, statusCode: 500,
                     timestamp: 1_700_000_000_000 + i * 1000 }));
  }
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  var f = r.findings[0];
  assert.strictEqual(f.verdict, "DEAD_ENDPOINT");
  assert.strictEqual(f.priority, "P0");
  assert.ok(r.playbook.some(function (a) { return a.id === "DISABLE_DEAD_ENDPOINTS"; }));
  assert.ok(["D", "F"].indexOf(r.summary.grade) !== -1);
  assert.ok(r.summary.band === "DEGRADED" || r.summary.band === "CRITICAL");
});

test("auth failures (3x 401) short-circuit to AUTH_FAILURE P0", function () {
  var a = mk();
  var log = [
    entry({ status: "failed", statusCode: 401, timestamp: 1 }),
    entry({ status: "failed", statusCode: 401, timestamp: 2 }),
    entry({ status: "failed", statusCode: 403, timestamp: 3 }),
  ];
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  assert.strictEqual(r.findings[0].verdict, "AUTH_FAILURE");
  assert.strictEqual(r.findings[0].priority, "P0");
  assert.ok(r.playbook.some(function (a) { return a.id === "ROTATE_OR_FIX_WEBHOOK_SECRETS"; }));
});

test("retry storm -> mean attempts >= 2.5 with healthy success", function () {
  var a = mk();
  var log = [];
  for (var i = 0; i < 6; i++) {
    log.push(entry({ status: "delivered", attempts: 3,
                     timestamp: 1_700_000_000_000 + i * 1000 }));
  }
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  assert.strictEqual(r.findings[0].verdict, "RETRY_STORM");
  assert.ok(r.playbook.some(function (a) { return a.id === "TUNE_BACKOFF_OR_TIMEOUT"; }));
});

test("rate-limit-heavy endpoint surfaces RATE_LIMITED_HEAVY", function () {
  var a = mk();
  var log = [];
  for (var i = 0; i < 6; i++) {
    log.push(entry({ status: "delivered", timestamp: 1_700_000_000_000 + i }));
  }
  for (var j = 0; j < 4; j++) {
    log.push(entry({ status: "rate_limited", timestamp: 1_700_000_001_000 + j }));
  }
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  assert.strictEqual(r.findings[0].verdict, "RATE_LIMITED_HEAVY");
  assert.ok(r.playbook.some(function (a) { return a.id === "NEGOTIATE_RATE_LIMIT_OR_BATCH"; }));
});

test("unregistered traffic -> UNREGISTERED_TRAFFIC + reconcile action", function () {
  var a = mk();
  var log = [entry({ webhookId: "wh_ghost", status: "delivered" })];
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  var ghost = r.findings.filter(function (f) { return f.webhookId === "wh_ghost"; })[0];
  assert.ok(ghost, "ghost finding present");
  assert.strictEqual(ghost.verdict, "UNREGISTERED_TRAFFIC");
  assert.ok(r.playbook.some(function (a) { return a.id === "RECONCILE_UNREGISTERED_TRAFFIC"; }));
});

test("slow recovery: 5 trailing failures with prior success", function () {
  var a = mk();
  var log = [entry({ status: "delivered", timestamp: 1 })];
  for (var i = 1; i <= 5; i++) {
    log.push(entry({ status: "failed", statusCode: 500, timestamp: 1 + i }));
  }
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  // 6 attempted entries, success_rate 1/6 ≈ 16.7% -> DEGRADED short-circuits;
  // but min_attempts=10 so DEGRADED doesn't trigger. Falls through to slow_recovery.
  assert.strictEqual(r.findings[0].verdict, "SLOW_RECOVERY");
  assert.ok(r.playbook.some(function (a) { return a.id === "INVESTIGATE_SLOW_RECOVERY"; }));
});

test("flapping: many alternations", function () {
  var a = mk();
  var log = [];
  for (var i = 0; i < 8; i++) {
    log.push(entry({ status: i % 2 === 0 ? "delivered" : "failed",
                     statusCode: i % 2 === 0 ? 200 : 500,
                     timestamp: 1_700_000_000_000 + i * 1000 }));
  }
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  // 8 attempted -> below min_attempts (10) so success_rate path doesn't trigger.
  // Alternations = 7 -> FLAPPING.
  assert.strictEqual(r.findings[0].verdict, "FLAPPING");
});

test("healthy mixed fleet -> grade A/B, fleet success healthy insight", function () {
  var a = mk();
  var log = [];
  for (var i = 0; i < 20; i++) {
    log.push(entry({ status: "delivered", attempts: 1,
                     timestamp: 1_700_000_000_000 + i * 1000 }));
  }
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  assert.strictEqual(r.findings[0].verdict, "HEALTHY");
  assert.ok(["A", "B"].indexOf(r.summary.grade) !== -1);
  assert.ok(r.insights.indexOf("FLEET_SUCCESS_RATE_HEALTHY") !== -1);
});

test("risk_appetite=cautious adds SCHEDULE_WEBHOOK_REVIEW at grade C/D/F", function () {
  var a = mk();
  var log = [];
  for (var i = 0; i < 12; i++) {
    log.push(entry({ status: "failed", statusCode: 500, attempts: 4,
                     timestamp: 1_700_000_000_000 + i * 1000 }));
  }
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] },
                    { risk_appetite: "cautious" });
  assert.ok(r.playbook.some(function (a) { return a.id === "SCHEDULE_WEBHOOK_REVIEW"; }));
});

test("risk_appetite=aggressive trims P3 noise when P0/P1 present", function () {
  var a = mk();
  var log = [
    entry({ status: "failed", statusCode: 401, timestamp: 1 }),
    entry({ status: "failed", statusCode: 401, timestamp: 2 }),
    entry({ status: "failed", statusCode: 401, timestamp: 3 }),
  ];
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1"), ep("wh2")] },
                    { risk_appetite: "aggressive" });
  assert.ok(r.playbook.length >= 1);
  assert.ok(!r.playbook.some(function (a) { return a.id === "NO_WEBHOOK_ACTION_NEEDED"; }));
  assert.strictEqual(r.risk_appetite, "aggressive");
});

test("renderers produce non-empty strings with required sections", function () {
  var a = mk();
  var log = [];
  for (var i = 0; i < 12; i++) {
    log.push(entry({ status: "failed", statusCode: 500, attempts: 3,
                     timestamp: 1_700_000_000_000 + i * 1000 }));
  }
  var r = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  var t = a.formatText(r);
  assert.ok(t.indexOf("VERDICT:") === 0);
  assert.ok(t.indexOf("Playbook:") !== -1);
  assert.ok(t.indexOf("Insights:") !== -1);
  var md = a.formatMarkdown(r);
  ["## Summary", "## Endpoints", "## Playbook", "## Insights"].forEach(function (h) {
    assert.ok(md.indexOf(h) !== -1, "markdown missing " + h);
  });
  var j = a.formatJson(r);
  assert.strictEqual(j, a.formatJson(r), "json byte-stable across calls");
  var parsed = JSON.parse(j);
  assert.ok(parsed.summary && parsed.findings && parsed.playbook && parsed.insights);
});

test("deterministic across runs with same now()", function () {
  var fixedNow = 1_700_000_010_000;
  var a = mk({ now: function () { return fixedNow; } });
  var log = [
    entry({ status: "delivered", timestamp: 1 }),
    entry({ status: "failed", statusCode: 500, timestamp: 2 }),
  ];
  var r1 = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  var r2 = a.analyze({ deliveryLog: log, endpoints: [ep("wh1")] });
  assert.strictEqual(a.formatJson(r1), a.formatJson(r2));
});

test("does not mutate input log/endpoints", function () {
  var a = mk();
  var endpoints = [ep("wh1")];
  var log = [entry({ status: "delivered" }), entry({ status: "failed", statusCode: 500 })];
  var logBefore = JSON.stringify(log);
  var epBefore = JSON.stringify(endpoints);
  a.analyze({ deliveryLog: log, endpoints: endpoints });
  assert.strictEqual(JSON.stringify(log), logBefore);
  assert.strictEqual(JSON.stringify(endpoints), epBefore);
});
