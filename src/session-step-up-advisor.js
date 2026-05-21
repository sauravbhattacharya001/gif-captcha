"use strict";

/**
 * SessionStepUpAdvisor - Agentic step-up authentication decision advisor
 * for gif-captcha.
 *
 * Operates AFTER a user has cleared a CAPTCHA and is about to perform a
 * sensitive action (purchase, transfer, password change, api key issue,
 * admin change, data export, add recipient). Decides whether to ALLOW,
 * LOG, soft step-up, hard step-up, or BLOCK and investigate.
 *
 * Sibling to FalseRejectRecoveryAdvisor (per-session false-reject) and
 * HumanVerificationConfidenceAuditor (per-session trust). This module is
 * outcome-oriented: it answers "given everything we know about this
 * session right now, what authentication friction should we apply to
 * THIS sensitive request?"
 *
 * Pure JS, no deps, deterministic given inputs + risk_appetite + now.
 *
 * @module session-step-up-advisor
 */

var DEFAULT_RISK = "balanced";
var VALID_RISKS = { cautious: 1.15, balanced: 1.0, aggressive: 0.85 };
var PRIORITY_RANK = { P0: 0, P1: 1, P2: 2, P3: 3 };

var SENSITIVE_TYPES = {
  view: 0,
  purchase: 2,
  transfer: 3,
  password_change: 3,
  api_key_issue: 3,
  admin_change: 4,
  export_data: 2,
  add_recipient: 2,
};

// Step-up methods catalogue. strengthScore: how hard to forge. frictionScore: user pain.
var METHODS = {
  hardware_key:      { id: "hardware_key",      label: "Hardware security key (FIDO2/WebAuthn)", strengthScore: 95, frictionScore: 45 },
  biometric_reauth:  { id: "biometric_reauth",  label: "Re-authenticate with platform biometric", strengthScore: 85, frictionScore: 25 },
  totp:              { id: "totp",              label: "Time-based one-time password (TOTP)",     strengthScore: 75, frictionScore: 35 },
  push_notify:       { id: "push_notify",       label: "Push notification to enrolled device",    strengthScore: 70, frictionScore: 20 },
  email_link:        { id: "email_link",        label: "Magic link to verified email",            strengthScore: 55, frictionScore: 40 },
  fresh_visual_captcha: { id: "fresh_visual_captcha", label: "Issue a fresh visual CAPTCHA",      strengthScore: 45, frictionScore: 30 },
  recaptcha_v3:      { id: "recaptcha_v3",      label: "Run an invisible risk-score CAPTCHA",     strengthScore: 35, frictionScore: 5  },
  sms_otp:           { id: "sms_otp",           label: "SMS one-time code (deprecated, weak)",    strengthScore: 30, frictionScore: 40 },
  security_question: { id: "security_question", label: "Knowledge-based security question",       strengthScore: 20, frictionScore: 35 },
};

function _clamp(n, lo, hi) {
  if (typeof n !== "number" || !isFinite(n)) return lo;
  if (n < lo) return lo;
  if (n > hi) return hi;
  return n;
}

function _num(v, fallback) {
  if (typeof v === "number" && isFinite(v)) return v;
  return fallback;
}

function _bool(v) { return v === true; }

function _normRisk(r) {
  if (r && VALID_RISKS[r] != null) return r;
  return DEFAULT_RISK;
}

function _stableStringify(value) {
  var seen = new WeakSet();
  function visit(v) {
    if (v === null || typeof v !== "object") return v;
    if (seen.has(v)) return null;
    seen.add(v);
    if (Array.isArray(v)) return v.map(visit);
    var out = {};
    Object.keys(v).sort().forEach(function (k) { out[k] = visit(v[k]); });
    return out;
  }
  return JSON.stringify(visit(value), null, 2);
}

// ---------------------------------------------------------------------------
// Detectors. Each returns null OR { code, severity, reason }.
// ---------------------------------------------------------------------------

function _detectStaleCaptcha(session, action) {
  var sens = SENSITIVE_TYPES[action.type] || 0;
  if (!_bool(session.captchaCleared)) {
    return { code: "STALE_CAPTCHA", severity: 65, reason: "CAPTCHA not cleared for this session" };
  }
  var ageMin = _num(session.ageMinutes, 0);
  if (sens >= 2 && ageMin > 60) {
    return { code: "STALE_CAPTCHA", severity: 50, reason: "CAPTCHA cleared >60min ago but action is sensitive" };
  }
  return null;
}

function _detectLowCaptchaConfidence(session) {
  var c = _num(session.captchaConfidence, 1);
  if (c < 0.55) {
    return { code: "LOW_CAPTCHA_CONFIDENCE", severity: 55, reason: "CAPTCHA confidence " + c + " < 0.55" };
  }
  return null;
}

function _detectBiometricsBotLike(session) {
  var s = _num(session.behavioralBiometricsScore, 1);
  if (s < 0.4) {
    return { code: "BIOMETRICS_BOT_LIKE", severity: 70, reason: "Behavioral biometrics score " + s + " < 0.4" };
  }
  return null;
}

function _detectDeviceLowTrust(session) {
  var t = _num(session.deviceTrustScore, 1);
  if (t < 0.4) {
    return { code: "DEVICE_LOW_TRUST", severity: 45, reason: "Device trust score " + t + " < 0.4" };
  }
  return null;
}

function _detectSessionHijack(session) {
  var hits = 0;
  if (_bool(session.ipChanged)) hits++;
  if (_bool(session.userAgentChanged)) hits++;
  if (session.tlsFingerprintMatch === false) hits++;
  if (hits >= 2) {
    return {
      code: "SESSION_HIJACK_INDICATORS",
      severity: 95,
      reason: hits + " of {ipChanged, userAgentChanged, tlsFingerprintMatch=false} fired mid-session",
    };
  }
  return null;
}

function _detectHighValueFirstTime(action) {
  if (_num(action.valueUsd, 0) >= 1000 && _bool(action.isFirstTime)) {
    return {
      code: "HIGH_VALUE_FIRST_TIME",
      severity: 60,
      reason: "Action value $" + action.valueUsd + " on first-time " + action.type,
    };
  }
  return null;
}

function _detectNewRecipientTransfer(action) {
  if ((action.type === "transfer" || action.type === "add_recipient") && action.recipientNew === true) {
    return {
      code: "NEW_RECIPIENT_TRANSFER",
      severity: 70,
      reason: action.type + " to a never-seen recipient",
    };
  }
  return null;
}

function _detectAbnormalVelocity(action) {
  var sens = SENSITIVE_TYPES[action.type] || 0;
  if (sens >= 2 && _num(action.velocityLastHour, 0) > 5) {
    return {
      code: "ABNORMAL_VELOCITY",
      severity: 50,
      reason: action.velocityLastHour + " similar sensitive actions in last hour",
    };
  }
  return null;
}

function _detectRiskyAsnOrGeo(session) {
  if (session.asnReputation === "risky") {
    return { code: "RISKY_ASN_OR_GEO", severity: 50, reason: "Originating ASN flagged as risky" };
  }
  return null;
}

function _detectStaleStepUp(user, action) {
  if (action.type !== "admin_change" && action.type !== "api_key_issue") return null;
  var last = user.lastStepUpMinutesAgo;
  if (last == null || _num(last, 999) > 30) {
    return {
      code: "STALE_STEP_UP",
      severity: 50,
      reason: "No fresh step-up within 30min before privileged action",
    };
  }
  return null;
}

function _detectRecentAuthFailures(user) {
  var n = _num(user.recentFailedLogins, 0);
  if (n >= 3) {
    return { code: "RECENT_AUTH_FAILURES", severity: 60, reason: n + " failed logins in last 24h" };
  }
  return null;
}

function _detectPrivilegeElevation(user, action) {
  if (action.type === "admin_change" && user.tier !== "admin") {
    return {
      code: "PRIVILEGE_ELEVATION",
      severity: 100,
      reason: "Non-admin user (" + user.tier + ") attempting admin_change",
    };
  }
  return null;
}

function _runDetectors(input) {
  var session = input.session || {};
  var user = input.user || {};
  var action = input.action || {};
  var raw = [
    _detectStaleCaptcha(session, action),
    _detectLowCaptchaConfidence(session),
    _detectBiometricsBotLike(session),
    _detectDeviceLowTrust(session),
    _detectSessionHijack(session),
    _detectHighValueFirstTime(action),
    _detectNewRecipientTransfer(action),
    _detectAbnormalVelocity(action),
    _detectRiskyAsnOrGeo(session),
    _detectStaleStepUp(user, action),
    _detectRecentAuthFailures(user),
    _detectPrivilegeElevation(user, action),
  ];
  return raw.filter(function (f) { return f != null; });
}

// ---------------------------------------------------------------------------
// Scoring / verdict.
// ---------------------------------------------------------------------------

function _scoreFindings(findings, riskMult) {
  if (findings.length === 0) return 0;
  var sevs = findings.map(function (f) { return f.severity; }).sort(function (a, b) { return b - a; });
  var top = sevs[0];
  var rest = 0;
  for (var i = 1; i < sevs.length; i++) rest += sevs[i];
  var raw = top + 0.4 * Math.min(rest, 60);
  return _clamp(raw * riskMult, 0, 100);
}

function _verdictFor(score, findings, risk) {
  // Critical short-circuits.
  var codes = findings.map(function (f) { return f.code; });
  if (codes.indexOf("SESSION_HIJACK_INDICATORS") !== -1) return "BLOCK_AND_INVESTIGATE";
  if (codes.indexOf("PRIVILEGE_ELEVATION") !== -1) return "BLOCK_AND_INVESTIGATE";

  // Threshold ladder, shifted by risk appetite.
  var shift = risk === "cautious" ? -10 : (risk === "aggressive" ? 10 : 0);
  if (score >= 86 + shift) return "BLOCK_AND_INVESTIGATE";
  if (score >= 66 + shift) return "STEP_UP_HARD";
  if (score >= 46 + shift) return "STEP_UP_SOFT";
  if (score >= 25 + shift) return "ALLOW_WITH_LOGGING";
  return "ALLOW";
}

function _gradeFor(score, verdict) {
  if (verdict === "BLOCK_AND_INVESTIGATE") return "F";
  if (score >= 80) return "F";
  if (score >= 60) return "D";
  if (score >= 40) return "C";
  if (score >= 20) return "B";
  return "A";
}

// ---------------------------------------------------------------------------
// Recommended step-up methods per verdict.
// ---------------------------------------------------------------------------

function _recommendedMethods(verdict, user, action) {
  var ids;
  switch (verdict) {
    case "BLOCK_AND_INVESTIGATE":
      // Even on block, suggest the methods that would unblock once cleared.
      ids = ["hardware_key", "biometric_reauth"];
      break;
    case "STEP_UP_HARD":
      ids = ["hardware_key", "biometric_reauth", "totp", "email_link"];
      break;
    case "STEP_UP_SOFT":
      ids = ["totp", "push_notify", "biometric_reauth", "email_link", "fresh_visual_captcha"];
      break;
    case "ALLOW_WITH_LOGGING":
      ids = ["recaptcha_v3", "push_notify"];
      break;
    default:
      ids = [];
  }

  if (!_bool(user.mfaEnrolled)) {
    // Without MFA, only the methods that don't require pre-enrollment.
    ids = ids.filter(function (id) {
      return id === "email_link" || id === "fresh_visual_captcha" || id === "recaptcha_v3" ||
             id === "security_question" || id === "sms_otp";
    });
    if (verdict === "STEP_UP_HARD" || verdict === "BLOCK_AND_INVESTIGATE") {
      if (ids.indexOf("email_link") === -1) ids.push("email_link");
    }
  }

  var pool = ids.map(function (id) { return METHODS[id]; }).filter(Boolean);
  pool.sort(function (a, b) {
    if (b.strengthScore !== a.strengthScore) return b.strengthScore - a.strengthScore;
    if (a.frictionScore !== b.frictionScore) return a.frictionScore - b.frictionScore;
    return a.id < b.id ? -1 : 1;
  });
  return pool.map(function (m) {
    return {
      id: m.id,
      label: m.label,
      strengthScore: m.strengthScore,
      userFrictionScore: m.frictionScore,
      reason: _methodReason(m.id, verdict, user),
    };
  });
}

function _methodReason(id, verdict, user) {
  if (id === "hardware_key") return "Phishing-resistant; recommended for privileged or high-value actions";
  if (id === "biometric_reauth") return "Low friction, strong device-bound proof of presence";
  if (id === "totp") return "Strong shared-secret OTP; works offline";
  if (id === "push_notify") return "Lowest friction strong factor for enrolled devices";
  if (id === "email_link") return _bool(user.mfaEnrolled)
    ? "Fallback if no enrolled second factor available"
    : "Only out-of-band factor available (user has no MFA enrolled)";
  if (id === "fresh_visual_captcha") return "Refresh human-presence proof before continuing";
  if (id === "recaptcha_v3") return "Invisible risk score, near-zero user friction";
  if (id === "sms_otp") return "Use only if no stronger factor is available (SMS is weak)";
  if (id === "security_question") return "Last-resort knowledge factor";
  return "Recommended for current verdict " + verdict;
}

// ---------------------------------------------------------------------------
// Playbook.
// ---------------------------------------------------------------------------

function _buildPlaybook(findings, verdict, user, action, risk, grade) {
  var codes = findings.map(function (f) { return f.code; });
  var has = function (c) { return codes.indexOf(c) !== -1; };
  var actions = [];

  if (verdict === "BLOCK_AND_INVESTIGATE") {
    actions.push({
      id: "BLOCK_AND_INVESTIGATE_SESSION",
      priority: "P0",
      label: "Block this action and open an investigation",
      reason: "Verdict is BLOCK_AND_INVESTIGATE based on detected signals",
      owner: "security",
      blastRadius: 4,
      reversibility: "medium",
      relatedSignals: codes.slice(),
    });
  }

  if (has("SESSION_HIJACK_INDICATORS")) {
    actions.push({
      id: "INVALIDATE_SESSION",
      priority: "P0",
      label: "Invalidate session and force fresh login from a known device",
      reason: "Multiple session-hijack indicators fired together",
      owner: "security",
      blastRadius: 5,
      reversibility: "low",
      relatedSignals: ["SESSION_HIJACK_INDICATORS"],
    });
  }

  if (verdict === "STEP_UP_HARD" &&
      (action.type === "admin_change" || action.type === "api_key_issue" || action.type === "transfer")) {
    actions.push({
      id: "REQUIRE_HARDWARE_KEY",
      priority: "P0",
      label: "Require hardware security key (WebAuthn/FIDO2) before proceeding",
      reason: "High-risk privileged or fund-moving action under STEP_UP_HARD verdict",
      owner: "security",
      blastRadius: 3,
      reversibility: "high",
      relatedSignals: codes.slice(),
    });
  }

  if (verdict === "STEP_UP_SOFT") {
    actions.push({
      id: "REQUIRE_TOTP_OR_PUSH",
      priority: "P1",
      label: "Require TOTP code or approved push notification",
      reason: "Verdict is STEP_UP_SOFT; cheap but strong second factor",
      owner: "auth",
      blastRadius: 2,
      reversibility: "high",
      relatedSignals: codes.slice(),
    });
  }

  if (has("STALE_CAPTCHA") || has("LOW_CAPTCHA_CONFIDENCE")) {
    actions.push({
      id: "REISSUE_CAPTCHA",
      priority: "P1",
      label: "Issue a fresh visual CAPTCHA before allowing the action",
      reason: "Existing CAPTCHA evidence is stale or low-confidence",
      owner: "ux",
      blastRadius: 1,
      reversibility: "high",
      relatedSignals: codes.filter(function (c) {
        return c === "STALE_CAPTCHA" || c === "LOW_CAPTCHA_CONFIDENCE";
      }),
    });
  }

  if (has("HIGH_VALUE_FIRST_TIME") || has("NEW_RECIPIENT_TRANSFER")) {
    actions.push({
      id: "NOTIFY_USER_OF_SENSITIVE_ACTION",
      priority: "P1",
      label: "Send out-of-band notification (email/push) about this sensitive action",
      reason: "First-time high-value or new-recipient action; user should see it instantly",
      owner: "notifications",
      blastRadius: 1,
      reversibility: "high",
      relatedSignals: codes.filter(function (c) {
        return c === "HIGH_VALUE_FIRST_TIME" || c === "NEW_RECIPIENT_TRANSFER";
      }),
    });
  }

  if (verdict === "ALLOW_WITH_LOGGING") {
    actions.push({
      id: "LOG_FOR_REVIEW",
      priority: "P2",
      label: "Allow but log the session+action for offline review",
      reason: "Risk is non-trivial but below step-up threshold",
      owner: "ops",
      blastRadius: 1,
      reversibility: "high",
      relatedSignals: codes.slice(),
    });
  }

  if (!_bool(user.mfaEnrolled) && (user.tier === "premium" || user.tier === "admin")) {
    actions.push({
      id: "ENFORCE_MFA_ENROLLMENT",
      priority: "P2",
      label: "Force MFA enrollment for " + user.tier + " users",
      reason: "Privileged user has no MFA enrolled — every sensitive action is one slip from compromise",
      owner: "security",
      blastRadius: 2,
      reversibility: "high",
      relatedSignals: ["NO_MFA"],
    });
  }

  if (risk === "cautious" && (grade === "C" || grade === "D" || grade === "F")) {
    actions.push({
      id: "SCHEDULE_STEP_UP_AUDIT",
      priority: "P2",
      label: "Schedule a step-up policy audit for this user/action combo",
      reason: "Cautious appetite + middling/poor grade — confirm thresholds are tuned",
      owner: "security",
      blastRadius: 1,
      reversibility: "high",
      relatedSignals: codes.slice(),
    });
  }

  if (actions.length === 0) {
    actions.push({
      id: "SESSION_OK",
      priority: "P3",
      label: "Session and action look healthy; no step-up needed",
      reason: "No detectors fired and verdict is ALLOW",
      owner: "ops",
      blastRadius: 1,
      reversibility: "high",
      relatedSignals: [],
    });
  }

  // Dedup by id.
  var seen = Object.create(null);
  var deduped = [];
  actions.forEach(function (a) {
    if (!seen[a.id]) { seen[a.id] = true; deduped.push(a); }
  });

  // Aggressive trims P3 fallback and lone P2 when P0/P1 present.
  if (risk === "aggressive") {
    var hasUrgent = deduped.some(function (a) { return a.priority === "P0" || a.priority === "P1"; });
    if (hasUrgent) {
      deduped = deduped.filter(function (a) {
        if (a.priority === "P3") return false;
        if (a.priority === "P2") return false;
        return true;
      });
    }
  }

  deduped.sort(function (a, b) {
    var pa = PRIORITY_RANK[a.priority] != null ? PRIORITY_RANK[a.priority] : 9;
    var pb = PRIORITY_RANK[b.priority] != null ? PRIORITY_RANK[b.priority] : 9;
    if (pa !== pb) return pa - pb;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

  return deduped;
}

// ---------------------------------------------------------------------------
// Insights.
// ---------------------------------------------------------------------------

function _buildInsights(findings, user) {
  var codes = findings.map(function (f) { return f.code; });
  var has = function (c) { return codes.indexOf(c) !== -1; };
  var insights = [];
  if (has("SESSION_HIJACK_INDICATORS")) insights.push("SESSION_HIJACK_SUSPECTED");
  if (has("HIGH_VALUE_FIRST_TIME")) insights.push("HIGH_VALUE_RISK");
  if (has("NEW_RECIPIENT_TRANSFER")) insights.push("NEW_RECIPIENT_RISK");
  if (has("STALE_CAPTCHA") || has("STALE_STEP_UP")) insights.push("STALE_AUTH_CONTEXT");
  if (has("BIOMETRICS_BOT_LIKE") || has("DEVICE_LOW_TRUST")) insights.push("DEVICE_OR_BIOMETRICS_CONCERN");
  if (!_bool(user.mfaEnrolled) && (user.tier === "premium" || user.tier === "admin")) insights.push("MFA_GAP");
  if (insights.length === 0) insights.push("HEALTHY_SESSION");
  return insights;
}

// ---------------------------------------------------------------------------
// Top-level analyze / simulate.
// ---------------------------------------------------------------------------

var ACTION_RISK_DELTA = {
  BLOCK_AND_INVESTIGATE_SESSION: -60,
  INVALIDATE_SESSION: -60,
  REQUIRE_HARDWARE_KEY: -35,
  REQUIRE_TOTP_OR_PUSH: -25,
  REISSUE_CAPTCHA: -15,
  NOTIFY_USER_OF_SENSITIVE_ACTION: -10,
  ENFORCE_MFA_ENROLLMENT: -8,
  LOG_FOR_REVIEW: -3,
  SCHEDULE_STEP_UP_AUDIT: -2,
  SESSION_OK: 0,
};

function analyze(input, opts) {
  if (!input || typeof input !== "object") {
    throw new TypeError("analyze() requires an input object");
  }
  var session = input.session || {};
  var user = input.user || {};
  var action = input.action || {};
  if (action.type == null) action.type = "view";

  var risk = _normRisk(opts && opts.risk_appetite);
  var riskMult = VALID_RISKS[risk];
  var nowRaw = (input.context && input.context.now != null)
    ? input.context.now
    : (opts && opts.now != null ? opts.now : Date.now());
  var nowMs = (nowRaw instanceof Date) ? nowRaw.getTime() : Number(nowRaw);

  var findings = _runDetectors(input);
  var score = _scoreFindings(findings, riskMult);
  var rounded = Math.round(score * 100) / 100;
  var verdict = _verdictFor(score, findings, risk);
  var grade = _gradeFor(score, verdict);
  var methods = _recommendedMethods(verdict, user, action);
  var playbook = _buildPlaybook(findings, verdict, user, action, risk, grade);
  var insights = _buildInsights(findings, user);

  return {
    schemaVersion: 1,
    generatedAt: new Date(nowMs).toISOString(),
    riskAppetite: risk,
    sessionId: session.id != null ? String(session.id) : null,
    actionType: action.type,
    stepUpRiskScore: rounded,
    verdict: verdict,
    grade: grade,
    findings: findings.map(function (f) {
      return {
        code: f.code,
        severity: f.severity,
        reason: f.reason,
        priority: f.severity >= 90 ? "P0" : (f.severity >= 60 ? "P1" : (f.severity >= 35 ? "P2" : "P3")),
      };
    }),
    recommendedMethods: methods,
    playbook: playbook,
    insights: insights,
  };
}

function simulate(report, opts) {
  if (!report || !Array.isArray(report.playbook)) {
    throw new TypeError("simulate() requires a report with a playbook");
  }
  var applyTop = Math.max(0, _num(opts && opts.applyTop, 0));
  var baseScore = _num(report.stepUpRiskScore, 0);
  var projected = baseScore;
  var applied = [];
  var n = Math.min(applyTop, report.playbook.length);
  for (var i = 0; i < n; i++) {
    var action = report.playbook[i];
    var delta = (ACTION_RISK_DELTA[action.id] || 0) * Math.pow(0.85, i);
    projected += delta;
    applied.push({
      id: action.id,
      priority: action.priority,
      appliedDelta: Math.round(delta * 100) / 100,
    });
  }
  projected = _clamp(projected, 5, 100);
  // Re-derive verdict/grade purely from projected score under same risk shift.
  var risk = report.riskAppetite || "balanced";
  var shift = risk === "cautious" ? -10 : (risk === "aggressive" ? 10 : 0);
  var newVerdict;
  if (projected >= 86 + shift) newVerdict = "BLOCK_AND_INVESTIGATE";
  else if (projected >= 66 + shift) newVerdict = "STEP_UP_HARD";
  else if (projected >= 46 + shift) newVerdict = "STEP_UP_SOFT";
  else if (projected >= 25 + shift) newVerdict = "ALLOW_WITH_LOGGING";
  else newVerdict = "ALLOW";
  return {
    stepUpRiskScore: Math.round(projected * 100) / 100,
    verdict: newVerdict,
    grade: _gradeFor(projected, newVerdict),
    appliedActions: applied,
  };
}

// ---------------------------------------------------------------------------
// Renderers.
// ---------------------------------------------------------------------------

function formatText(report) {
  if (!report) return "";
  var lines = [];
  lines.push("Session Step-Up Advisor Report");
  lines.push("==============================");
  lines.push("Generated: " + report.generatedAt + "  Risk: " + report.riskAppetite);
  lines.push("Session: " + (report.sessionId || "(none)") + "  Action: " + report.actionType);
  lines.push("Score: " + report.stepUpRiskScore + "  Verdict: " + report.verdict + "  Grade: " + report.grade);
  lines.push("");
  lines.push("Findings (" + report.findings.length + "):");
  report.findings.forEach(function (f) {
    lines.push("  - [" + f.priority + "] " + f.code + " (sev " + f.severity + ") - " + f.reason);
  });
  lines.push("");
  lines.push("Recommended step-up methods (" + report.recommendedMethods.length + "):");
  report.recommendedMethods.forEach(function (m) {
    lines.push("  - " + m.label + "  (strength " + m.strengthScore + ", friction " + m.userFrictionScore + ")");
  });
  lines.push("");
  lines.push("Playbook (" + report.playbook.length + "):");
  report.playbook.forEach(function (a) {
    lines.push("  [" + a.priority + "] " + a.id + " (owner=" + a.owner + ", blast=" + a.blastRadius + ") - " + a.label);
  });
  lines.push("");
  lines.push("Insights:");
  report.insights.forEach(function (s) { lines.push("  - " + s); });
  return lines.join("\n");
}

function formatMarkdown(report) {
  if (!report) return "";
  var out = [];
  out.push("# Session Step-Up Advisor Report");
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Field | Value |");
  out.push("|---|---|");
  out.push("| Generated | " + report.generatedAt + " |");
  out.push("| Risk appetite | " + report.riskAppetite + " |");
  out.push("| Session | " + (report.sessionId || "(none)") + " |");
  out.push("| Action | " + report.actionType + " |");
  out.push("| Step-up risk score | " + report.stepUpRiskScore + " |");
  out.push("| Verdict | " + report.verdict + " |");
  out.push("| Grade | " + report.grade + " |");
  out.push("");
  out.push("## Findings");
  out.push("");
  if (report.findings.length === 0) {
    out.push("_No risk signals detected._");
  } else {
    out.push("| Priority | Code | Severity | Reason |");
    out.push("|---|---|---|---|");
    report.findings.forEach(function (f) {
      out.push("| " + f.priority + " | " + f.code + " | " + f.severity + " | " + f.reason + " |");
    });
  }
  out.push("");
  out.push("## Recommended step-up methods");
  out.push("");
  if (report.recommendedMethods.length === 0) {
    out.push("_No step-up required._");
  } else {
    out.push("| Method | Strength | User friction | Reason |");
    out.push("|---|---|---|---|");
    report.recommendedMethods.forEach(function (m) {
      out.push("| " + m.label + " | " + m.strengthScore + " | " + m.userFrictionScore + " | " + m.reason + " |");
    });
  }
  out.push("");
  out.push("## Playbook");
  out.push("");
  if (report.playbook.length === 0) {
    out.push("_No actions recommended._");
  } else {
    out.push("| Priority | Action | Owner | Blast | Reversibility | Label |");
    out.push("|---|---|---|---|---|---|");
    report.playbook.forEach(function (a) {
      out.push("| " + a.priority + " | " + a.id + " | " + a.owner + " | " + a.blastRadius +
               " | " + a.reversibility + " | " + a.label + " |");
    });
  }
  out.push("");
  out.push("## Insights");
  out.push("");
  report.insights.forEach(function (s) { out.push("- " + s); });
  return out.join("\n");
}

function formatJson(report) {
  return _stableStringify(report);
}

// ---------------------------------------------------------------------------
// Factory.
// ---------------------------------------------------------------------------

function createSessionStepUpAdvisor(opts) {
  var defaults = (opts && typeof opts === "object") ? opts : {};
  function withDefaults(callOpts) {
    return Object.assign({}, defaults, callOpts || {});
  }
  return {
    analyze: function (input, callOpts) { return analyze(input, withDefaults(callOpts)); },
    simulate: function (report, callOpts) { return simulate(report, callOpts || {}); },
    formatText: formatText,
    formatMarkdown: formatMarkdown,
    formatJson: formatJson,
  };
}

module.exports = {
  createSessionStepUpAdvisor: createSessionStepUpAdvisor,
  analyze: analyze,
  simulate: simulate,
  formatText: formatText,
  formatMarkdown: formatMarkdown,
  formatJson: formatJson,
  METHODS: METHODS,
};
