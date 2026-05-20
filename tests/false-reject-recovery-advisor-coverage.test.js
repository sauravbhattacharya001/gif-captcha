"use strict";

/**
 * Additional coverage for src/false-reject-recovery-advisor.js
 *
 * Existing tests focus on the analyze() path.  These tests target uncovered
 * branches reported by c8 (lines ~466, 499-506, 511 and surrounding):
 *
 *  - formatText/formatMarkdown/formatJson with null input
 *  - formatMarkdown playbook population branch (non-empty playbook)
 *  - formatMarkdown insights branch (non-empty insights)
 *  - formatMarkdown empty-playbook & empty-insights fallback messages
 *  - simulate() with no playbook applied (applyTop = 0)
 *  - simulate() invalid input error path
 *  - createFalseRejectRecoveryAdvisor option merging via withDefaults
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const mod = require("../src/false-reject-recovery-advisor");

function recoverableSession(i) {
  // Heuristic: a session likely to land in the "recoverable" bucket — high
  // trust + biometrics, low geo risk, with accessibility alt-paths available.
  return {
    id: "rec-" + i,
    lastVerdict: "fail",
    attempts: 2,
    biometricsScore: 0.85,
    trustScore: 0.8,
    retryCount: 1,
    challengeType: "gif-frames",
    difficulty: 7,
    completionTimeMs: 9000,
    deviceClass: "mobile",
    accessibilityNeeds: ["motor"],
    geoRiskScore: 0.05,
    hadAudioAlt: true,
    hadTextAlt: false,
  };
}

function writeOffSession(i) {
  return {
    id: "wo-" + i,
    lastVerdict: "fail",
    attempts: 5,
    biometricsScore: 0.1,
    trustScore: 0.05,
    retryCount: 0,
    challengeType: "gif-frames",
    difficulty: 9,
    completionTimeMs: 500,
    deviceClass: "desktop",
    accessibilityNeeds: [],
    geoRiskScore: 0.95,
    hadAudioAlt: false,
    hadTextAlt: false,
  };
}

test("format* handle null reports gracefully (line 437/468/518 guards)", () => {
  assert.equal(mod.formatText(null), "");
  assert.equal(mod.formatMarkdown(null), "");
  // formatJson does not short-circuit on null — it stringifies it.  Verify it
  // simply returns the string "null" and does not throw.
  assert.equal(typeof mod.formatJson(null), "string");
});

test("formatMarkdown renders populated playbook + insights branches", () => {
  // Hand-roll a report with a populated playbook + insights so we deterministically
  // exercise the non-empty branches of formatMarkdown (lines ~499-506 and ~511).
  // Using analyze() here would be fragile because the heuristic thresholds
  // shift over time and could intermittently produce empty arrays.
  const populated = {
    generatedAt: "2026-01-01T00:00:00.000Z",
    riskAppetite: "balanced",
    overall: {
      sessionCount: 3,
      recoverableCount: 2,
      writeOffCount: 1,
      recoverableShare: 0.667,
      estimatedRecoverableHumans: 1.4,
      p0Count: 1,
    },
    band: "mid",
    grade: "B",
    recoveryVerdicts: [
      { sessionId: "s1", verdict: "RECOVERABLE", priority: "P1", recoveryScore: 72.5,
        confidence: 0.81, suggestedAction: "offer_audio" },
    ],
    playbook: [
      { id: "offer_audio_alt", priority: "P1", owner: "product", blastRadius: "low",
        reversibility: "reversible", label: "Offer audio alternative for motor-impaired users",
        reason: "3 sessions with motor accessibility need + no audio alt",
        estRiskDelta: 0.05, sessionIds: ["s1", "s2", "s3"] },
      { id: "lower_difficulty", priority: "P2", owner: "ml", blastRadius: "med",
        reversibility: "reversible", label: "Auto-lower difficulty after 2 fails",
        reason: "Recurring fail-at-9 pattern on mobile",
        estRiskDelta: 0.03, sessionIds: ["s4"] },
    ],
    insights: [
      "Recoverable share trending up over last 3 windows",
      "P0 backlog concentrated in mobile + high-geo-risk segment",
    ],
  };

  const md = mod.formatMarkdown(populated);
  assert.ok(md.includes("# False-Reject Recovery Report"));
  assert.ok(md.includes("## Playbook"));
  assert.ok(md.includes("## Insights"));
  assert.ok(md.includes("offer_audio_alt"));
  assert.ok(md.includes("lower_difficulty"));
  assert.ok(md.includes("Recoverable share trending up"));
  // Must NOT contain the empty-state fallbacks when populated
  assert.ok(!md.includes("_No actions recommended._"));
  assert.ok(!md.includes("_No notable insights._"));
});

test("formatMarkdown renders empty-playbook / empty-insights fallbacks", () => {
  // Hand-rolled minimal report that exercises the empty branches without
  // depending on whether analyze() happens to produce empty arrays.
  const empty = {
    generatedAt: "2026-01-01T00:00:00.000Z",
    riskAppetite: "conservative",
    overall: {
      sessionCount: 0,
      recoverableCount: 0,
      writeOffCount: 0,
      recoverableShare: 0,
      estimatedRecoverableHumans: 0,
      p0Count: 0,
    },
    band: "low",
    grade: "F",
    recoveryVerdicts: [],
    playbook: [],
    insights: [],
  };
  const md = mod.formatMarkdown(empty);
  assert.ok(md.includes("_No actions recommended._"));
  assert.ok(md.includes("_No notable insights._"));
});

test("formatText covers populated playbook + insights paths", () => {
  const advisor = mod.createFalseRejectRecoveryAdvisor();
  const sessions = [
    recoverableSession(0),
    recoverableSession(1),
    writeOffSession(0),
  ];
  const report = advisor.analyze({ sessions });
  const txt = mod.formatText(report);
  assert.ok(txt.includes("False-Reject Recovery Report"));
  assert.ok(txt.includes("Sessions:"));
  assert.ok(txt.includes("Insights:"));
});

test("simulate(applyTop=0) returns base metrics with no applied actions", () => {
  const advisor = mod.createFalseRejectRecoveryAdvisor();
  const sessions = [recoverableSession(0), recoverableSession(1)];
  const report = advisor.analyze({ sessions });
  const sim = advisor.simulate(report, { applyTop: 0 });
  assert.equal(sim.appliedActions.length, 0);
  // No actions applied → projected share should equal the (rounded) base share
  assert.equal(sim.recoverableShare, Math.round(report.overall.recoverableShare * 1000) / 1000);
  assert.equal(typeof sim.band, "string");
  assert.equal(typeof sim.grade, "string");
});

test("simulate() throws on invalid report input", () => {
  assert.throws(() => mod.simulate(null, { applyTop: 1 }), TypeError);
  assert.throws(() => mod.simulate({}, { applyTop: 1 }), TypeError);
  assert.throws(() => mod.simulate({ playbook: "not-an-array" }, { applyTop: 1 }), TypeError);
});

test("createFalseRejectRecoveryAdvisor merges per-call options over defaults", () => {
  // Defaults set conservative risk; per-call balanced should win.  We don't
  // assert specific numeric outputs (heuristics may evolve) — just that the
  // reported riskAppetite reflects the call-time override.
  const advisor = mod.createFalseRejectRecoveryAdvisor({ risk_appetite: "cautious" });
  const sessions = [recoverableSession(0)];
  const reportA = advisor.analyze({ sessions });
  assert.equal(reportA.riskAppetite, "cautious");
  // Per-call options should win over factory defaults (withDefaults merge).
  const reportB = advisor.analyze({ sessions }, { risk_appetite: "aggressive" });
  assert.equal(reportB.riskAppetite, "aggressive");
});

test("formatJson produces stable, parseable output", () => {
  const advisor = mod.createFalseRejectRecoveryAdvisor();
  const sessions = [recoverableSession(0), recoverableSession(1)];
  const report = advisor.analyze({ sessions });
  const j1 = mod.formatJson(report);
  const j2 = mod.formatJson(report);
  assert.equal(j1, j2, "formatJson must be deterministic (stable key ordering)");
  const parsed = JSON.parse(j1);
  assert.equal(parsed.overall.sessionCount, 2);
});
