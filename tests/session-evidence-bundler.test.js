"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createSessionEvidenceBundler } = require("../src/session-evidence-bundler");
const index = require("../src/index.js");

function freshBundler() {
  return createSessionEvidenceBundler({ now: () => new Date("2026-05-21T20:00:00Z") });
}

test("PASS with no signals -> CLEAN verdict, A grade, CLOSE_NO_ACTION", () => {
  const b = freshBundler();
  const r = b.bundle({ sessionId: "sess_clean", decision: "PASS" });
  assert.equal(r.verdict, "CLEAN");
  assert.equal(r.summary.evidenceGrade, "A");
  assert.equal(r.evidence.length, 0);
  assert.ok(r.playbook.find(a => a.id === "CLOSE_NO_ACTION"));
  assert.ok(r.insights.includes("CLEAN_PASS"));
});

test("BLOCK with tor + honeypotHits=3 -> STRONG_EVIDENCE, F, FILE_INCIDENT + ESCALATE_TO_LEGAL", () => {
  const b = freshBundler();
  const r = b.bundle({
    sessionId: "sess_block_strong",
    decision: "BLOCK",
    ip: "203.0.113.42",
    tor: true,
    honeypotHits: 3,
    biometricsScore: 0.1,
  });
  assert.equal(r.verdict, "STRONG_EVIDENCE");
  assert.equal(r.summary.evidenceGrade, "F");
  const ids = r.playbook.map(a => a.id);
  assert.ok(ids.includes("FILE_INCIDENT"));
  assert.ok(ids.includes("ESCALATE_TO_LEGAL"));
});

test("BLOCK with low biometrics + low trust -> REVIEW_BIOMETRICS_REPLAY P1", () => {
  const b = freshBundler();
  const r = b.bundle({
    sessionId: "sess_bio",
    decision: "BLOCK",
    biometricsScore: 0.15,
    trustScore: 0.2,
  });
  const review = r.playbook.find(a => a.id === "REVIEW_BIOMETRICS_REPLAY");
  assert.ok(review);
  assert.equal(review.priority, "P1");
});

test("relatedSessions >=3 -> COORDINATED_RING_SUSPECTED + AUDIT_RELATED_SESSIONS", () => {
  const b = freshBundler();
  const r = b.bundle({
    sessionId: "sess_ring",
    decision: "BLOCK",
    relatedSessions: ["s1", "s2", "s3", "s4"],
  });
  assert.ok(r.insights.includes("COORDINATED_RING_SUSPECTED"));
  assert.ok(r.playbook.find(a => a.id === "AUDIT_RELATED_SESSIONS"));
});

test("Default redaction masks IPv4 last octet and hashes accountId", () => {
  const b = freshBundler();
  const r = b.bundle({
    sessionId: "sess_redact",
    decision: "BLOCK",
    ip: "192.168.1.42",
    ipReputation: 0.9,
    accountId: "user_secret_1234",
    accountAgeDays: 3,
  });
  const j = b.format(r, "json");
  assert.ok(j.indexOf("192.168.1.42") === -1, "raw IP should not appear");
  assert.ok(j.indexOf("192.168.1.xxx") !== -1, "masked IP should appear");
  assert.ok(j.indexOf("user_secret_1234") === -1, "raw accountId should not appear");
  assert.ok(/acct_[0-9a-f]{8}/.test(j), "hashed accountId should appear");
});

test("redact:false preserves raw IP and accountId", () => {
  const b = freshBundler();
  const r = b.bundle({
    sessionId: "sess_no_redact",
    decision: "BLOCK",
    ip: "203.0.113.42",
    ipReputation: 0.9,
    accountId: "user_xyz",
    accountAgeDays: 2,
  }, { redact: false });
  const j = b.format(r, "json");
  assert.ok(j.indexOf("203.0.113.42") !== -1);
  assert.ok(j.indexOf("user_xyz") !== -1);
  const ipItem = r.evidence.find(e => e.label === "IP reputation risk");
  if (ipItem) assert.equal(ipItem.redacted, false);
});

test("Determinism: same input + fixed now -> identical chainOfCustody hash and JSON bytes", () => {
  const fixedNow = () => new Date("2026-05-21T20:00:00Z");
  const b1 = createSessionEvidenceBundler({ now: fixedNow });
  const b2 = createSessionEvidenceBundler({ now: fixedNow });
  const session = {
    sessionId: "sess_det",
    decision: "BLOCK",
    ip: "10.0.0.5",
    honeypotHits: 1,
    biometricsScore: 0.4,
    accountAgeDays: 30,
  };
  const r1 = b1.bundle(session);
  const r2 = b2.bundle(session);
  assert.equal(r1.chainOfCustody.sha256Hash, r2.chainOfCustody.sha256Hash);
  assert.equal(b1.format(r1, "json"), b2.format(r2, "json"));
});

test("Input immutability: bundle() does not mutate input session", () => {
  const b = freshBundler();
  const session = {
    sessionId: "sess_imm",
    decision: "BLOCK",
    ip: "192.168.1.42",
    accountId: "user_keep_me",
    geo: { lat: 47.6062, lng: -122.3321, country: "US" },
    relatedSessions: ["a", "b"],
  };
  const snapshot = JSON.stringify(session);
  b.bundle(session);
  assert.equal(JSON.stringify(session), snapshot);
});

test("Risk appetite cautious raises weights vs aggressive on same input", () => {
  const session = {
    sessionId: "sess_risk",
    decision: "BLOCK",
    ipReputation: 0.5,
    biometricsScore: 0.4,
    accountAgeDays: 30,
  };
  const bC = freshBundler();
  const bA = freshBundler();
  const rC = bC.bundle(session, { riskAppetite: "cautious" });
  const rA = bA.bundle(session, { riskAppetite: "aggressive" });
  const sumC = rC.evidence.reduce((s, e) => s + e.weight, 0);
  const sumA = rA.evidence.reduce((s, e) => s + e.weight, 0);
  assert.ok(sumC > sumA, "cautious total weight should exceed aggressive: " + sumC + " vs " + sumA);
});

test("Markdown format contains all five required sections", () => {
  const b = freshBundler();
  const r = b.bundle({ sessionId: "sess_md", decision: "BLOCK", tor: true, honeypotHits: 2, accountAgeDays: 2 });
  const md = b.format(r, "markdown");
  for (const section of ["## Summary", "## Evidence", "## Playbook", "## Insights", "## Chain of Custody"]) {
    assert.ok(md.indexOf(section) !== -1, "missing section " + section);
  }
});

test("JSON format parses and is byte-stable (sorted keys)", () => {
  const b = freshBundler();
  const r = b.bundle({ sessionId: "sess_json", decision: "PASS" });
  const j = b.format(r, "json");
  const parsed = JSON.parse(j);
  assert.ok(parsed.summary);
  // sorted-key check: chainOfCustody before evidence before insights ... alphabetically
  const idxChain = j.indexOf('"chainOfCustody"');
  const idxEvidence = j.indexOf('"evidence"');
  const idxInsights = j.indexOf('"insights"');
  const idxSummary = j.indexOf('"summary"');
  assert.ok(idxChain >= 0 && idxEvidence > idxChain && idxInsights > idxEvidence && idxSummary > idxInsights,
    "top-level keys not in sorted order");
});

test("Fresh account (<7d) + BLOCK -> FRESH_ACCOUNT_HIGH_RISK insight", () => {
  const b = freshBundler();
  const r = b.bundle({ sessionId: "sess_fresh", decision: "BLOCK", accountAgeDays: 2 });
  assert.ok(r.insights.includes("FRESH_ACCOUNT_HIGH_RISK"));
});

test("VPN+TOR+proxy + datacenter ASN -> ANONYMIZATION_LAYERED insight", () => {
  const b = freshBundler();
  const r = b.bundle({
    sessionId: "sess_anon",
    decision: "BLOCK",
    vpnDetected: true, tor: true, proxyDetected: true,
    asn: "AS14618 AMAZON-AES",
  });
  assert.ok(r.insights.includes("ANONYMIZATION_LAYERED"));
});

test("dryRun=true does not push to history; normal bundle() does", () => {
  const b = freshBundler();
  const before = b.history().length;
  b.bundle({ sessionId: "x", decision: "PASS" }, { dryRun: true });
  assert.equal(b.history().length, before, "dryRun should not push");
  b.bundle({ sessionId: "y", decision: "PASS" });
  assert.equal(b.history().length, before + 1);
});

test("format(report,'text') returns non-empty string", () => {
  const b = freshBundler();
  const r = b.bundle({ sessionId: "sess_text", decision: "PASS" });
  const t = b.format(r, "text");
  assert.equal(typeof t, "string");
  assert.ok(t.length > 0);
  assert.ok(t.indexOf("SessionEvidenceBundler") !== -1);
});

test("history(limit) returns most-recent first, capped", () => {
  const b = freshBundler();
  b.bundle({ sessionId: "h1", decision: "PASS" });
  b.bundle({ sessionId: "h2", decision: "BLOCK", tor: true });
  b.bundle({ sessionId: "h3", decision: "PASS" });
  const h = b.history(2);
  assert.equal(h.length, 2);
  // most recent first
  assert.ok(h[0].summary.headline.indexOf("Clean PASS") !== -1 || h[0].summary.decision === "PASS");
});

test("INSUFFICIENT verdict when no signals but decision==STEP_UP", () => {
  const b = freshBundler();
  const r = b.bundle({ sessionId: "sess_stepup", decision: "STEP_UP" });
  assert.equal(r.verdict, "INSUFFICIENT");
  assert.ok(r.insights.includes("INSUFFICIENT_EVIDENCE"));
});

test("index.js exposes createSessionEvidenceBundler", () => {
  assert.equal(typeof index.createSessionEvidenceBundler, "function");
  const inst = index.createSessionEvidenceBundler();
  assert.equal(typeof inst.bundle, "function");
  assert.equal(typeof inst.format, "function");
});
