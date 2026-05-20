"use strict";

/**
 * BlockedSessionAppealAdjudicator - Agentic post-BLOCK appeal evaluator for gif-captcha.
 *
 * 7th agentic sibling. Fills a gap in the existing line-up:
 *   - false-reject-recovery-advisor : pre-decision recovery for ambiguous sessions
 *   - human-verification-confidence-auditor : post-PASS false-accept audit
 *   - blocked-session-appeal-adjudicator (THIS) : post-BLOCK appeal evaluator
 *
 * Given a blocked session and the evidence the appellant has submitted, returns a
 * verdict and recommended actions describing whether to overturn the block, reduce
 * it to a lighter penalty, request more evidence, maintain it, or escalate to a
 * human reviewer.
 *
 * API:
 *   var adv = createBlockedSessionAppealAdjudicator({ riskAppetite, now });
 *   var report = adv.adjudicate(appeal);
 *   var text = adv.format(report, "text" | "md" | "markdown" | "json");
 *
 * Pure JS, no deps, ES5-flavored, deterministic given inputs + risk_appetite + now.
 * Never mutates the input appeal.
 *
 * @module blocked-session-appeal-adjudicator
 */

var DEFAULT_RISK = "balanced";
var RISK_MULT = {
  cautious:   { conf: 0.92, risk: 1.10 },
  balanced:   { conf: 1.00, risk: 1.00 },
  aggressive: { conf: 1.08, risk: 0.90 },
};

var VALID_BLOCK_REASONS = {
  BOT_SUSPECTED: 1, HONEYPOT_TRIPPED: 1, PROXY_DETECTED: 1, GEO_RISK_HIGH: 1,
  RATE_LIMIT: 1, FAST_SOLVE: 1, POW_BYPASS_ATTEMPT: 1, OTHER: 1,
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
  if (r && RISK_MULT[r]) return r;
  return DEFAULT_RISK;
}

function _addReason(reasons, code, label, weight, evidence) {
  reasons.push({
    code: code,
    label: label,
    weight: weight,
    evidence: evidence == null ? "" : String(evidence),
  });
}

function _scoreAppeal(appeal) {
  var os = (appeal && appeal.originalSignals) || {};
  var ev = (appeal && appeal.appealEvidence) || {};
  var ctx = (appeal && appeal.context) || {};
  var reasons = [];
  var confidence = 50;
  var risk = 0; // additive risk on top of (100 - confidence) baseline

  // Positive evidence (from the appellant)
  if (_bool(ev.retrySolved)) {
    confidence += 20;
    _addReason(reasons, "RETRY_SOLVED", "User re-solved a fresh challenge", +20, "retrySolved=true");
  }
  var rt = _num(ev.retrySolveTimeMs, -1);
  if (rt >= 2000 && rt <= 15000) {
    confidence += 5;
    _addReason(reasons, "HUMAN_RETRY_TIMING", "Retry solve time in human range", +5, rt + "ms");
  } else if (rt >= 0 && rt < 800) {
    confidence -= 15;
    _addReason(reasons, "SUSPICIOUSLY_FAST_RETRY", "Retry solve time suspiciously fast", -15, rt + "ms");
  }
  var rb = _num(ev.retryBiometricsScore, -1);
  if (rb >= 0.7) {
    confidence += 12;
    _addReason(reasons, "STRONG_RETRY_BIOMETRICS", "Retry biometrics look strongly human", +12, rb);
  } else if (rb >= 0 && rb < 0.3) {
    confidence -= 10;
    _addReason(reasons, "WEAK_RETRY_BIOMETRICS", "Retry biometrics look bot-like", -10, rb);
  }
  switch (ev.secondaryProofSubmitted) {
    case "oauth":
      confidence += 18;
      _addReason(reasons, "SECONDARY_PROOF_OAUTH", "Verified via OAuth", +18, "oauth");
      break;
    case "email_verify":
      confidence += 10;
      _addReason(reasons, "SECONDARY_PROOF_EMAIL_VERIFY", "Verified via email", +10, "email_verify");
      break;
    case "sms_verify":
      confidence += 12;
      _addReason(reasons, "SECONDARY_PROOF_SMS_VERIFY", "Verified via SMS", +12, "sms_verify");
      break;
    case "human_review":
      confidence += 25;
      _addReason(reasons, "SECONDARY_PROOF_HUMAN_REVIEW", "Cleared by human reviewer", +25, "human_review");
      break;
    default: break;
  }
  var age = _num(ev.accountAgeDays, -1);
  if (age >= 180) {
    confidence += 8;
    _addReason(reasons, "MATURE_ACCOUNT", "Account >= 180 days old", +8, age + "d");
  } else if (age >= 30) {
    confidence += 4;
    _addReason(reasons, "ESTABLISHED_ACCOUNT", "Account >= 30 days old", +4, age + "d");
  }
  var prior = _num(ev.prior30dSuccessfulSolves, -1);
  if (prior >= 5) {
    confidence += 8;
    _addReason(reasons, "HISTORY_OF_HUMAN_SOLVES", "5+ prior successful solves in 30d", +8, prior);
  }
  if (_bool(ev.geoNowMatchesProfile)) {
    confidence += 6;
    _addReason(reasons, "GEO_MATCHES_PROFILE", "Current geo matches user profile", +6, "true");
  }
  if (_bool(ev.ipChanged) && ev.geoNowMatchesProfile === false) {
    confidence -= 8;
    _addReason(reasons, "GEO_INCONSISTENCY", "IP changed and geo no longer matches profile", -8, "ipChanged+geoMismatch");
  }
  if (_bool(ev.userStatementProvided)) {
    confidence += 2;
    _addReason(reasons, "USER_STATEMENT_PROVIDED", "User submitted a written statement", +2, "true");
  }

  // Negative signals carried from block-time
  if (_bool(os.proxyDetected)) {
    confidence -= 8;
    _addReason(reasons, "PROXY_AT_BLOCK_TIME", "Proxy/VPN detected at block time", -8, "true");
  }
  var geo = _num(os.geoRiskScore, 0);
  if (geo >= 0.7) {
    confidence -= 8;
    _addReason(reasons, "HIGH_GEO_RISK_AT_BLOCK", "High geo risk at block time", -8, geo);
  }
  var iprep = _num(os.ipReputationScore, 0);
  if (iprep >= 0.7) {
    confidence -= 12;
    _addReason(reasons, "BAD_IP_REPUTATION", "IP reputation poor at block time", -12, iprep);
  }
  if (_bool(os.powBypassSuspicion)) {
    confidence -= 25;
    _addReason(reasons, "POW_BYPASS_PATTERN", "Proof-of-work bypass pattern at block time", -25, "true");
  }
  var ua = _num(os.userAgentSuspicionScore, 0);
  if (ua >= 0.7) {
    confidence -= 8;
    _addReason(reasons, "SUSPICIOUS_USER_AGENT", "Suspicious user-agent at block time", -8, ua);
  }
  var bio = _num(os.biometricsScore, -1);
  if (bio >= 0 && bio <= 0.2) {
    confidence -= 10;
    _addReason(reasons, "WEAK_ORIGINAL_BIOMETRICS", "Original biometrics looked bot-like", -10, bio);
  }
  var appeals = _num(ctx.appealsThisMonthForUser, 0);
  if (appeals >= 10) {
    confidence -= 25;
    _addReason(reasons, "CHRONIC_APPEALER", "10+ appeals this month", -25, appeals);
  } else if (appeals >= 5) {
    confidence -= 15;
    _addReason(reasons, "FREQUENT_APPEALER", "5+ appeals this month", -15, appeals);
  }

  // Residual risk modifiers
  if (appeal && appeal.blockReason === "POW_BYPASS_ATTEMPT") {
    risk += 15;
    _addReason(reasons, "RESIDUAL_RISK_POW_BYPASS", "Block reason was POW bypass", +15, "POW_BYPASS_ATTEMPT");
  } else if (appeal && appeal.blockReason === "HONEYPOT_TRIPPED") {
    risk += 10;
    _addReason(reasons, "RESIDUAL_RISK_HONEYPOT", "Block reason was honeypot trip", +10, "HONEYPOT_TRIPPED");
  }
  var fac = _num(ctx.falseAcceptCostUsd, 0);
  var frc = _num(ctx.falseRejectCostUsd, 0);
  if (fac > frc * 5 && fac > 0) {
    risk += 5;
    _addReason(reasons, "COST_ASYMMETRY", "False-accept cost dominates", +5, fac + " vs " + frc);
  }

  return { confidenceRaw: confidence, riskAdditive: risk, reasons: reasons };
}

function _verdictFor(conf, risk, appeal) {
  var blockReason = appeal && appeal.blockReason;
  var ev = (appeal && appeal.appealEvidence) || {};
  var ctx = (appeal && appeal.context) || {};
  var chronic = _num(ctx.appealsThisMonthForUser, 0) >= 5;

  if (risk >= 70) return "MAINTAIN_BLOCK";
  if (blockReason === "POW_BYPASS_ATTEMPT" && conf < 75) return "MAINTAIN_BLOCK";
  if (chronic && conf < 65) return "MAINTAIN_BLOCK";

  if (risk >= 50 && risk <= 69 && conf >= 40 && conf <= 70 && !ev.secondaryProofSubmitted) {
    return "ESCALATE_TO_HUMAN_REVIEW";
  }

  if (conf >= 30 && conf <= 55 && !ev.secondaryProofSubmitted && !_bool(ev.retrySolved)) {
    return "REQUEST_MORE_EVIDENCE";
  }

  if (conf >= 55 && conf <= 75 && risk < 50) return "REDUCE_PENALTY";
  if (conf >= 75 && risk < 40) return "OVERTURN_BLOCK";

  return "REQUEST_MORE_EVIDENCE";
}

function _gradeFor(verdict, conf, risk) {
  if (verdict === "MAINTAIN_BLOCK" && conf < 30) return "F";
  if (verdict === "MAINTAIN_BLOCK") return "D";
  if (verdict === "REQUEST_MORE_EVIDENCE" && conf < 40) return "D";
  if (verdict === "REQUEST_MORE_EVIDENCE" || verdict === "ESCALATE_TO_HUMAN_REVIEW") return "C";
  if (verdict === "REDUCE_PENALTY") return "B";
  if (verdict === "OVERTURN_BLOCK" && risk < 25) return "A";
  if (verdict === "OVERTURN_BLOCK") return "B";
  return "C";
}

function _buildInsights(appeal, conf, risk, reasonCodes, verdict) {
  var ev = (appeal && appeal.appealEvidence) || {};
  var os = (appeal && appeal.originalSignals) || {};
  var ctx = (appeal && appeal.context) || {};
  var ins = [];
  if (_num(ctx.appealsThisMonthForUser, 0) >= 5) ins.push("CHRONIC_APPEALER");
  if (_bool(ev.retrySolved) && (
        ev.secondaryProofSubmitted === "oauth" ||
        ev.secondaryProofSubmitted === "human_review" ||
        ev.secondaryProofSubmitted === "sms_verify")) {
    ins.push("FRESH_EVIDENCE_STRONG");
  }
  if (_bool(os.powBypassSuspicion)) ins.push("POW_BYPASS_PATTERN");
  if (_bool(ev.ipChanged) && ev.geoNowMatchesProfile === false) ins.push("GEO_INCONSISTENCY");
  var fac = _num(ctx.falseAcceptCostUsd, 0);
  var frc = _num(ctx.falseRejectCostUsd, 0);
  if (frc > fac * 3 && frc > 0) ins.push("HIGH_FALSE_REJECT_COST");
  if ((verdict === "OVERTURN_BLOCK" || verdict === "REDUCE_PENALTY") && conf >= 80) {
    ins.push("LIKELY_FALSE_BLOCK");
  }
  if (!_bool(ev.retrySolved) && !ev.secondaryProofSubmitted &&
      (_num(ev.retryBiometricsScore, -1) < 0)) {
    ins.push("NO_NEW_EVIDENCE");
  }
  return ins;
}

function _buildActions(verdict, conf, reasonCodes, insights, appeal) {
  var ev = (appeal && appeal.appealEvidence) || {};
  var actions = [];

  if (verdict === "OVERTURN_BLOCK") {
    actions.push({
      id: "LIFT_BLOCK_NOW", priority: "P0", label: "Lift the block immediately",
      reason: "Appeal evidence is strong and residual risk is low",
      owner: "system", blastRadius: 2, reversibility: "medium",
    });
  } else if (verdict === "ESCALATE_TO_HUMAN_REVIEW") {
    actions.push({
      id: "ROUTE_TO_HUMAN_REVIEWER", priority: "P0",
      label: "Route appeal to a human reviewer",
      reason: "Confidence and risk are both moderate; needs human judgement",
      owner: "human_reviewer", blastRadius: 3, reversibility: "high",
    });
  } else if (verdict === "MAINTAIN_BLOCK") {
    actions.push({
      id: "MAINTAIN_BLOCK_AND_NOTIFY_USER", priority: "P0",
      label: "Maintain block and notify the user of the decision",
      reason: "Residual risk is too high to overturn",
      owner: "system", blastRadius: 4, reversibility: "medium",
    });
  } else if (verdict === "REDUCE_PENALTY") {
    actions.push({
      id: "LIFT_BLOCK_WITH_STEP_UP_CHALLENGE", priority: "P1",
      label: "Lift block but require a step-up challenge next session",
      reason: "Appeal credible but residual risk warrants extra friction",
      owner: "system", blastRadius: 2, reversibility: "high",
    });
  }

  if (verdict === "REQUEST_MORE_EVIDENCE" && !ev.secondaryProofSubmitted) {
    actions.push({
      id: "REQUEST_SECONDARY_PROOF", priority: "P1",
      label: "Ask user for OAuth/email/SMS verification",
      reason: "Appeal needs an out-of-band signal to clear",
      owner: "user", blastRadius: 1, reversibility: "high",
    });
  }

  if (reasonCodes.GEO_INCONSISTENCY) {
    actions.push({
      id: "ATTACH_GEO_VERIFICATION", priority: "P1",
      label: "Ask user to confirm location via secondary device",
      reason: "Geo inconsistency between block-time and appeal-time",
      owner: "user", blastRadius: 1, reversibility: "high",
    });
  }

  // P2: log unless verdict is a clear overturn with very high confidence
  var skipLog = (verdict === "OVERTURN_BLOCK" && conf >= 90);
  if (!skipLog) {
    actions.push({
      id: "LOG_FOR_TRAINING_DATA", priority: "P2",
      label: "Log appeal + verdict for adjudicator training data",
      reason: "Borderline case worth keeping for future calibration",
      owner: "system", blastRadius: 1, reversibility: "high",
    });
  }

  var hasChronic = insights.indexOf("CHRONIC_APPEALER") !== -1;
  var hasPow = insights.indexOf("POW_BYPASS_PATTERN") !== -1;
  if (hasChronic || hasPow) {
    actions.push({
      id: "WATCHLIST_USER_FOR_30D", priority: "P2",
      label: "Add user/session to 30-day watchlist",
      reason: hasPow ? "POW bypass pattern observed at block time" : "Chronic appealer",
      owner: "system", blastRadius: 2, reversibility: "high",
    });
  }

  // P3 fallback only when nothing actionable beyond P2 logging
  var anyP01 = false;
  for (var i = 0; i < actions.length; i++) {
    if (actions[i].priority === "P0" || actions[i].priority === "P1") { anyP01 = true; break; }
  }
  if (!anyP01) {
    actions.push({
      id: "APPEAL_PROCESS_HEALTHY", priority: "P3",
      label: "No further action needed",
      reason: "Adjudication settled without escalation",
      owner: "system", blastRadius: 1, reversibility: "high",
    });
  }

  // Dedup by id (preserve first), then P0-first stable sort.
  var seen = Object.create(null);
  var deduped = [];
  actions.forEach(function (a) { if (!seen[a.id]) { seen[a.id] = true; deduped.push(a); } });
  var prio = { P0: 0, P1: 1, P2: 2, P3: 3 };
  deduped.sort(function (a, b) {
    var pa = prio[a.priority] != null ? prio[a.priority] : 9;
    var pb = prio[b.priority] != null ? prio[b.priority] : 9;
    if (pa !== pb) return pa - pb;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
  return deduped;
}

function _summary(report) {
  return "Appeal " + report.sessionId + " verdict=" + report.verdict +
         " grade=" + report.grade +
         " conf=" + report.appealConfidence +
         " risk=" + report.appealRisk;
}

function _stableStringify(value) {
  var seen;
  function visit(v) {
    if (v === null || typeof v !== "object") {
      if (typeof v === "number" && !isFinite(v)) return null;
      return v;
    }
    if (seen.indexOf(v) !== -1) return null;
    seen.push(v);
    var out;
    if (Array.isArray(v)) {
      out = v.map(visit);
    } else {
      out = {};
      Object.keys(v).sort().forEach(function (k) { out[k] = visit(v[k]); });
    }
    seen.pop();
    return out;
  }
  seen = [];
  return JSON.stringify(visit(value), null, 2);
}

function adjudicate(appeal, opts) {
  if (!appeal || typeof appeal !== "object") {
    throw new TypeError("adjudicate() requires an appeal object");
  }
  if (!appeal.sessionId) {
    throw new TypeError("appeal.sessionId is required");
  }
  if (!VALID_BLOCK_REASONS[appeal.blockReason]) {
    throw new TypeError("appeal.blockReason must be one of: " +
      Object.keys(VALID_BLOCK_REASONS).join(", "));
  }
  var risk = _normRisk(opts && opts.risk_appetite);
  var mult = RISK_MULT[risk];
  var now = (opts && typeof opts.now === "number") ? opts.now :
            (opts && typeof opts.now === "function") ? opts.now() :
            Date.now();

  var scored = _scoreAppeal(appeal);
  var conf = scored.confidenceRaw * mult.conf;
  var rsk = (100 - scored.confidenceRaw + scored.riskAdditive) * mult.risk;
  conf = Math.round(_clamp(conf, 0, 100));
  rsk = Math.round(_clamp(rsk, 0, 100));

  var verdict = _verdictFor(conf, rsk, appeal);
  var grade = _gradeFor(verdict, conf, rsk);

  var reasonCodes = Object.create(null);
  scored.reasons.forEach(function (r) { reasonCodes[r.code] = true; });

  var insights = _buildInsights(appeal, conf, rsk, reasonCodes, verdict);
  var actions = _buildActions(verdict, conf, reasonCodes, insights, appeal);

  var report = {
    schemaVersion: 1,
    generatedAt: new Date(now).toISOString(),
    riskAppetite: risk,
    sessionId: appeal.sessionId,
    blockReason: appeal.blockReason,
    verdict: verdict,
    appealConfidence: conf,
    appealRisk: rsk,
    grade: grade,
    reasons: scored.reasons,
    recommendedActions: actions,
    insights: insights,
    summary: "",
  };
  report.summary = _summary(report);
  return report;
}

function formatText(report) {
  if (!report) return "";
  var lines = [];
  lines.push("Blocked-Session Appeal Adjudication");
  lines.push("====================================");
  lines.push(report.summary);
  lines.push("Generated: " + report.generatedAt + "  Risk appetite: " + report.riskAppetite);
  lines.push("Block reason: " + report.blockReason);
  lines.push("");
  lines.push("Reasons (" + report.reasons.length + "):");
  report.reasons.forEach(function (r) {
    var sign = r.weight >= 0 ? "+" : "";
    lines.push("  - [" + r.code + "] " + sign + r.weight + "  " + r.label +
               (r.evidence ? "  (" + r.evidence + ")" : ""));
  });
  lines.push("");
  lines.push("Recommended actions (" + report.recommendedActions.length + "):");
  report.recommendedActions.forEach(function (a) {
    lines.push("  [" + a.priority + "] " + a.id + " (owner=" + a.owner +
               ", blast=" + a.blastRadius + ", reversibility=" + a.reversibility + ")");
    lines.push("    " + a.label);
    lines.push("    reason: " + a.reason);
  });
  lines.push("");
  lines.push("Insights:");
  if (report.insights.length === 0) {
    lines.push("  (none)");
  } else {
    report.insights.forEach(function (s) { lines.push("  - " + s); });
  }
  return lines.join("\n");
}

function formatMarkdown(report) {
  if (!report) return "";
  var out = [];
  out.push("# Blocked-Session Appeal Adjudication");
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Field | Value |");
  out.push("|---|---|");
  out.push("| Session | " + report.sessionId + " |");
  out.push("| Block reason | " + report.blockReason + " |");
  out.push("| Verdict | " + report.verdict + " |");
  out.push("| Grade | " + report.grade + " |");
  out.push("| Appeal confidence | " + report.appealConfidence + " |");
  out.push("| Appeal risk | " + report.appealRisk + " |");
  out.push("| Risk appetite | " + report.riskAppetite + " |");
  out.push("| Generated | " + report.generatedAt + " |");
  out.push("");
  out.push("## Reasons");
  out.push("");
  if (report.reasons.length === 0) {
    out.push("_(none)_");
  } else {
    out.push("| Code | Weight | Evidence | Label |");
    out.push("|---|---|---|---|");
    report.reasons.forEach(function (r) {
      var sign = r.weight >= 0 ? "+" : "";
      out.push("| " + r.code + " | " + sign + r.weight + " | " +
               (r.evidence || "") + " | " + r.label + " |");
    });
  }
  out.push("");
  out.push("## Recommended Actions");
  out.push("");
  if (report.recommendedActions.length === 0) {
    out.push("_No actions recommended._");
  } else {
    out.push("| Priority | Label | Owner | Blast | Reversibility | Reason |");
    out.push("|---|---|---|---|---|---|");
    report.recommendedActions.forEach(function (a) {
      out.push("| " + a.priority + " | " + a.label + " | " + a.owner + " | " +
               a.blastRadius + " | " + a.reversibility + " | " + a.reason + " |");
    });
  }
  out.push("");
  out.push("## Insights");
  out.push("");
  if (report.insights.length === 0) {
    out.push("- (none)");
  } else {
    report.insights.forEach(function (s) { out.push("- " + s); });
  }
  return out.join("\n");
}

function formatJson(report) {
  return _stableStringify(report);
}

function format(report, kind) {
  switch ((kind || "text").toLowerCase()) {
    case "md":
    case "markdown":
      return formatMarkdown(report);
    case "json":
      return formatJson(report);
    case "text":
    default:
      return formatText(report);
  }
}

function createBlockedSessionAppealAdjudicator(opts) {
  var defaults = (opts && typeof opts === "object") ? opts : {};
  function withDefaults(callOpts) {
    var merged = {};
    Object.keys(defaults).forEach(function (k) { merged[k] = defaults[k]; });
    if (callOpts) Object.keys(callOpts).forEach(function (k) { merged[k] = callOpts[k]; });
    if (defaults.riskAppetite && !merged.risk_appetite) merged.risk_appetite = defaults.riskAppetite;
    if (defaults.now && !merged.now) merged.now = defaults.now;
    return merged;
  }
  return {
    adjudicate: function (appeal, callOpts) { return adjudicate(appeal, withDefaults(callOpts)); },
    format: format,
    formatText: formatText,
    formatMarkdown: formatMarkdown,
    formatJson: formatJson,
  };
}

module.exports = {
  createBlockedSessionAppealAdjudicator: createBlockedSessionAppealAdjudicator,
  adjudicate: adjudicate,
  format: format,
  formatText: formatText,
  formatMarkdown: formatMarkdown,
  formatJson: formatJson,
};
