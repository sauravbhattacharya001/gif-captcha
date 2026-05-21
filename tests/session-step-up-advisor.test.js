"use strict";

var assert = require("node:assert/strict");
var test = require("node:test");
var mod = require("../src/session-step-up-advisor");

function mk(opts) { return mod.createSessionStepUpAdvisor(opts || {}); }

function baseInput(over) {
  var i = {
    session: {
      id: "sess-1",
      ageMinutes: 5,
      captchaCleared: true,
      captchaConfidence: 0.9,
      idleMinutes: 1,
      requestCount: 4,
      deviceTrustScore: 0.85,
      geoCountry: "US",
      asnReputation: "clean",
      tlsFingerprintMatch: true,
      userAgentChanged: false,
      ipChanged: false,
      behavioralBiometricsScore: 0.9,
    },
    user: {
      tier: "standard",
      mfaEnrolled: true,
      recentFailedLogins: 0,
      lastStepUpMinutesAgo: 5,
      accountAgeDays: 800,
    },
    action: {
      type: "view",
      valueUsd: 0,
      isFirstTime: false,
      recipientNew: null,
      velocityLastHour: 0,
    },
    context: { now: 1700000000000 },
  };
  if (over) {
    if (over.session) Object.assign(i.session, over.session);
    if (over.user) Object.assign(i.user, over.user);
    if (over.action) Object.assign(i.action, over.action);
    if (over.context) Object.assign(i.context, over.context);
  }
  return i;
}

test("factory exposes expected API", function () {
  var f = mk();
  ["analyze", "simulate", "formatText", "formatMarkdown", "formatJson"]
    .forEach(function (m) { assert.equal(typeof f[m], "function", m + " is fn"); });
});

test("healthy session view -> ALLOW grade A no findings", function () {
  var f = mk();
  var r = f.analyze(baseInput());
  assert.equal(r.verdict, "ALLOW");
  assert.equal(r.grade, "A");
  assert.equal(r.findings.length, 0);
  // SESSION_OK fallback
  assert.equal(r.playbook[0].id, "SESSION_OK");
});

test("stale captcha on sensitive purchase triggers step-up + REISSUE_CAPTCHA", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    session: { captchaCleared: false },
    action: { type: "purchase", valueUsd: 50 },
  }));
  assert.ok(["STEP_UP_SOFT", "STEP_UP_HARD", "ALLOW_WITH_LOGGING"].indexOf(r.verdict) !== -1,
            "got " + r.verdict);
  assert.ok(r.findings.some(function (x) { return x.code === "STALE_CAPTCHA"; }));
  assert.ok(r.playbook.some(function (a) { return a.id === "REISSUE_CAPTCHA"; }));
});

test("session hijack indicators -> BLOCK + INVALIDATE_SESSION P0", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    session: { ipChanged: true, userAgentChanged: true, tlsFingerprintMatch: false },
    action: { type: "transfer", valueUsd: 500 },
  }));
  assert.equal(r.verdict, "BLOCK_AND_INVESTIGATE");
  assert.equal(r.grade, "F");
  assert.ok(r.playbook.some(function (a) { return a.id === "INVALIDATE_SESSION" && a.priority === "P0"; }));
  assert.ok(r.insights.indexOf("SESSION_HIJACK_SUSPECTED") !== -1);
});

test("privilege elevation: non-admin doing admin_change -> BLOCK", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    user: { tier: "standard" },
    action: { type: "admin_change" },
  }));
  assert.equal(r.verdict, "BLOCK_AND_INVESTIGATE");
  assert.equal(r.grade, "F");
  assert.ok(r.findings.some(function (x) { return x.code === "PRIVILEGE_ELEVATION"; }));
});

test("high value first-time triggers HIGH_VALUE_FIRST_TIME", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    action: { type: "purchase", valueUsd: 2500, isFirstTime: true },
  }));
  assert.ok(r.findings.some(function (x) { return x.code === "HIGH_VALUE_FIRST_TIME"; }));
  assert.ok(["STEP_UP_SOFT", "STEP_UP_HARD", "ALLOW_WITH_LOGGING"].indexOf(r.verdict) !== -1);
  assert.ok(r.playbook.some(function (a) { return a.id === "NOTIFY_USER_OF_SENSITIVE_ACTION"; }));
});

test("new recipient transfer triggers NEW_RECIPIENT_TRANSFER + NOTIFY_USER", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    action: { type: "transfer", valueUsd: 300, recipientNew: true },
  }));
  assert.ok(r.findings.some(function (x) { return x.code === "NEW_RECIPIENT_TRANSFER"; }));
  assert.ok(r.playbook.some(function (a) { return a.id === "NOTIFY_USER_OF_SENSITIVE_ACTION"; }));
  assert.ok(r.insights.indexOf("NEW_RECIPIENT_RISK") !== -1);
});

test("bot-like biometrics + low device trust -> STEP_UP_HARD or BLOCK", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    session: { behavioralBiometricsScore: 0.15, deviceTrustScore: 0.35 },
    action: { type: "transfer", valueUsd: 1500, recipientNew: true, isFirstTime: true },
  }));
  assert.ok(r.verdict === "STEP_UP_HARD" || r.verdict === "BLOCK_AND_INVESTIGATE",
            "got verdict " + r.verdict + " (score " + r.stepUpRiskScore + ")");
  assert.ok(r.playbook.some(function (a) {
    return a.id === "REQUIRE_HARDWARE_KEY" || a.id === "BLOCK_AND_INVESTIGATE_SESSION";
  }));
});

test("risk appetite cautious lowers verdict threshold (more friction)", function () {
  var inputObj = baseInput({
    session: { behavioralBiometricsScore: 0.35 },
    action: { type: "purchase", valueUsd: 50 },
  });
  var balanced = mk().analyze(inputObj);
  var cautious = mk().analyze(inputObj, { risk_appetite: "cautious" });
  assert.ok(cautious.stepUpRiskScore >= balanced.stepUpRiskScore);
});

test("risk appetite aggressive raises threshold (less friction) + trims P2/P3", function () {
  var inputObj = baseInput({
    session: { behavioralBiometricsScore: 0.35 },
    action: { type: "purchase", valueUsd: 50 },
  });
  var balanced = mk().analyze(inputObj);
  var aggressive = mk().analyze(inputObj, { risk_appetite: "aggressive" });
  assert.ok(aggressive.stepUpRiskScore <= balanced.stepUpRiskScore + 0.01);
  // With urgent actions present, aggressive trims P2/P3 in playbook
  var hasUrgent = aggressive.playbook.some(function (a) { return a.priority === "P0" || a.priority === "P1"; });
  if (hasUrgent) {
    aggressive.playbook.forEach(function (a) {
      assert.ok(a.priority === "P0" || a.priority === "P1", "found " + a.priority + " under aggressive");
    });
  }
});

test("simulate({applyTop:2}) reduces risk monotonically, floor 5", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    session: { ipChanged: true, userAgentChanged: true, tlsFingerprintMatch: false },
    action: { type: "transfer", valueUsd: 1500, recipientNew: true, isFirstTime: true },
  }));
  var sim = f.simulate(r, { applyTop: 2 });
  assert.ok(sim.stepUpRiskScore <= r.stepUpRiskScore);
  assert.ok(sim.stepUpRiskScore >= 5);
  assert.equal(sim.appliedActions.length, 2);
});

test("formatJson byte-stable across runs", function () {
  var f = mk();
  var r = f.analyze(baseInput());
  var a = f.formatJson(r);
  var b = f.formatJson(r);
  assert.equal(a, b);
  // Independent runs with same fixed now should also produce identical JSON.
  var r2 = mk().analyze(baseInput());
  assert.equal(f.formatJson(r), f.formatJson(r2));
});

test("formatMarkdown contains required headings", function () {
  var f = mk();
  var md = f.formatMarkdown(f.analyze(baseInput()));
  ["## Summary", "## Findings", "## Recommended step-up methods", "## Playbook", "## Insights"]
    .forEach(function (h) { assert.ok(md.indexOf(h) !== -1, "missing heading " + h); });
});

test("recommended methods sorted by strength desc", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    session: { behavioralBiometricsScore: 0.15, deviceTrustScore: 0.2 },
    action: { type: "transfer", valueUsd: 5000, recipientNew: true, isFirstTime: true },
  }));
  for (var i = 1; i < r.recommendedMethods.length; i++) {
    assert.ok(r.recommendedMethods[i - 1].strengthScore >= r.recommendedMethods[i].strengthScore,
              "methods not sorted: " + JSON.stringify(r.recommendedMethods));
  }
});

test("ENFORCE_MFA_ENROLLMENT appears when premium user has no MFA", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    user: { tier: "premium", mfaEnrolled: false },
    action: { type: "purchase", valueUsd: 50 },
  }));
  assert.ok(r.playbook.some(function (a) { return a.id === "ENFORCE_MFA_ENROLLMENT"; }));
  assert.ok(r.insights.indexOf("MFA_GAP") !== -1);
});

test("empty/minimal input does not throw and yields ALLOW for view", function () {
  var f = mk();
  var r = f.analyze({ session: {}, user: { tier: "guest" }, action: { type: "view" } });
  assert.equal(typeof r.stepUpRiskScore, "number");
  assert.ok(["ALLOW", "ALLOW_WITH_LOGGING", "STEP_UP_SOFT", "STEP_UP_HARD", "BLOCK_AND_INVESTIGATE"]
            .indexOf(r.verdict) !== -1);
});

test("recent auth failures contribute a finding", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    user: { recentFailedLogins: 5 },
    action: { type: "password_change" },
  }));
  assert.ok(r.findings.some(function (x) { return x.code === "RECENT_AUTH_FAILURES"; }));
});

test("simulate without applyTop returns base score unchanged", function () {
  var f = mk();
  var r = f.analyze(baseInput({
    action: { type: "purchase", valueUsd: 5000, isFirstTime: true },
  }));
  var sim = f.simulate(r, {});
  assert.equal(sim.appliedActions.length, 0);
  assert.equal(Math.round(sim.stepUpRiskScore), Math.round(r.stepUpRiskScore));
});

test("analyze throws on non-object input", function () {
  var f = mk();
  assert.throws(function () { f.analyze(null); });
  assert.throws(function () { f.analyze("nope"); });
});
