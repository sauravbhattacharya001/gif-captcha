"use strict";

/**
 * FalseRejectRecoveryAdvisor - Agentic per-session recovery advisor for gif-captcha.
 *
 * Sibling to UserAbandonmentForecaster (cohort-level UX-friction forecaster); this
 * module operates per failed/ambiguous session and answers: "did we just reject a
 * real human, and what should we do about *this* session right now?"
 *
 * Inputs (analyze({ sessions, attemptHistory?, defaults? }, { risk_appetite?, now? })):
 *   sessions: [{ id, lastVerdict, attempts, biometricsScore (0..1), trustScore (0..1),
 *               retryCount, challengeType, difficulty, completionTimeMs, deviceClass,
 *               accessibilityNeeds?:[], geoRiskScore?:0..1, errorReason?,
 *               hadAudioAlt?, hadTextAlt? }]
 *   attemptHistory (optional): [{ sessionId, success, timestampMs }]
 *
 * Recovery score formula (clamped 0..100):
 *   base 50
 *   + 30 * (biometricsScore - 0.5) * 2
 *   + 20 * trustScore
 *   - 25 * geoRiskScore
 *   + 10 if accessibilityNeeds.length && (!hadAudioAlt || !hadTextAlt)
 *   + min(5*retryCount, 15)
 *   - 10 if completionTimeMs > 30000
 *   - 8  if !challengeType
 *   then multiplied by risk-appetite multiplier (cautious 1.10 / balanced 1.0 / aggressive 0.85).
 *
 * Verdict ladder (first matching, highest priority first):
 *   WRITE_OFF                — biometrics<0.4 AND geoRisk>=0.6
 *   RETRY_DIFFERENT_TYPE     — biometrics>=0.7 AND accessibility need not met
 *   RETRY_EASIER             — biometrics>=0.7 AND geoRisk<0.3 AND difficulty>=6
 *   OFFER_FALLBACK           — biometrics>=0.7 AND retryCount>=3
 *   ESCALATE_MANUAL_REVIEW   — biometrics in (0.4..0.7) AND ambiguous trust (0.3..0.7)
 *   MONITOR                  — default.
 *
 * Pure JS, no deps, deterministic given inputs + risk_appetite + now.
 *
 * @module false-reject-recovery-advisor
 */

var DEFAULT_RISK = "balanced";
var VALID_RISKS = { cautious: 1.10, balanced: 1.0, aggressive: 0.85 };

var BAND_CUTOFFS = { CALM: 0.20, WATCH: 0.40, ELEVATED: 0.60, HIGH: 0.80 };

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

function _normRisk(r) {
  if (r && VALID_RISKS[r] != null) return r;
  return DEFAULT_RISK;
}

function _scoreSession(s, riskMult) {
  var bio = _clamp(_num(s.biometricsScore, 0.5), 0, 1);
  var trust = _clamp(_num(s.trustScore, 0.5), 0, 1);
  var geo = _clamp(_num(s.geoRiskScore, 0), 0, 1);
  var retry = _clamp(_num(s.retryCount, 0), 0, 50);
  var compMs = _num(s.completionTimeMs, 0);
  var needs = Array.isArray(s.accessibilityNeeds) ? s.accessibilityNeeds : [];
  var hadAudio = !!s.hadAudioAlt;
  var hadText = !!s.hadTextAlt;

  var score = 50;
  score += 30 * (bio - 0.5) * 2;          // -30..+30
  score += 20 * trust;                    // 0..+20
  score -= 25 * geo;                      // -25..0
  if (needs.length > 0 && (!hadAudio || !hadText)) score += 10;
  score += Math.min(5 * retry, 15);
  if (compMs > 30000) score -= 10;
  if (!s.challengeType) score -= 8;

  score = score * riskMult;
  return _clamp(score, 0, 100);
}

function _classifyVerdict(s) {
  var bio = _clamp(_num(s.biometricsScore, 0.5), 0, 1);
  var trust = _clamp(_num(s.trustScore, 0.5), 0, 1);
  var geo = _clamp(_num(s.geoRiskScore, 0), 0, 1);
  var retry = _clamp(_num(s.retryCount, 0), 0, 50);
  var diff = _num(s.difficulty, 5);
  var needs = Array.isArray(s.accessibilityNeeds) ? s.accessibilityNeeds : [];
  var hadAudio = !!s.hadAudioAlt;
  var hadText = !!s.hadTextAlt;
  var accessUnmet = needs.length > 0 && (!hadAudio || !hadText);

  if (bio < 0.4 && geo >= 0.6) return "WRITE_OFF";
  if (bio >= 0.7 && accessUnmet) return "RETRY_DIFFERENT_TYPE";
  if (bio >= 0.7 && geo < 0.3 && diff >= 6) return "RETRY_EASIER";
  if (bio >= 0.7 && retry >= 3) return "OFFER_FALLBACK";
  if (bio >= 0.4 && bio < 0.7 && trust >= 0.3 && trust < 0.7) return "ESCALATE_MANUAL_REVIEW";
  return "MONITOR";
}

function _reasonsFor(s, verdict) {
  var reasons = [];
  var bio = _num(s.biometricsScore, 0.5);
  var geo = _num(s.geoRiskScore, 0);
  var diff = _num(s.difficulty, 5);
  var retry = _num(s.retryCount, 0);
  var needs = Array.isArray(s.accessibilityNeeds) ? s.accessibilityNeeds : [];
  if (bio >= 0.7) reasons.push("HIGH_BIOMETRICS");
  else if (bio < 0.4) reasons.push("LOW_BIOMETRICS");
  else reasons.push("MID_BIOMETRICS");
  if (geo >= 0.6) reasons.push("HIGH_GEO_RISK");
  else if (geo < 0.3) reasons.push("LOW_GEO_RISK");
  if (diff >= 6) reasons.push("HIGH_DIFFICULTY");
  if (retry >= 3) reasons.push("RETRY_FATIGUE");
  if (needs.length > 0 && (!s.hadAudioAlt || !s.hadTextAlt)) reasons.push("ACCESSIBILITY_UNMET");
  if (s.completionTimeMs && s.completionTimeMs > 30000) reasons.push("SLOW_COMPLETION");
  if (verdict === "WRITE_OFF") reasons.push("BOT_LIKELY");
  if (verdict === "RETRY_DIFFERENT_TYPE") reasons.push("ACCESSIBILITY_FALSE_REJECT");
  if (verdict === "RETRY_EASIER") reasons.push("DIFFICULTY_OVERCALIBRATED");
  return reasons;
}

function _suggestedAction(verdict, s) {
  switch (verdict) {
    case "RETRY_EASIER":
      return "drop difficulty by 1-2 notches and re-issue challenge";
    case "RETRY_DIFFERENT_TYPE":
      return "switch to audio or text-alt challenge variant";
    case "OFFER_FALLBACK":
      return "offer email/SMS fallback or human review queue";
    case "ESCALATE_MANUAL_REVIEW":
      return "send to human-in-loop reviewer";
    case "WRITE_OFF":
      return "log decision, do not pursue";
    default:
      return "passive monitor on next attempt";
  }
}

function _priorityFor(verdict, score) {
  if ((verdict === "RETRY_EASIER" || verdict === "RETRY_DIFFERENT_TYPE") && score >= 70) return "P0";
  if ((verdict === "RETRY_EASIER" || verdict === "RETRY_DIFFERENT_TYPE") && score >= 50) return "P1";
  if (verdict === "OFFER_FALLBACK") return score >= 70 ? "P0" : "P1";
  if (verdict === "ESCALATE_MANUAL_REVIEW") return "P2";
  if (verdict === "WRITE_OFF") return "P3";
  return "P3";
}

function _confidence(s, attemptHistory) {
  var c = 0.6;
  var attempts = _num(s.attempts, 0);
  if (attempts >= 2) c += 0.2;
  if (Array.isArray(attemptHistory) && attemptHistory.length > 0) c += 0.1;
  var bio = _num(s.biometricsScore, 0.5);
  if (bio <= 0.2 || bio >= 0.8) c += 0.1;
  return _clamp(c, 0, 1);
}

function _bandFor(share) {
  if (share < BAND_CUTOFFS.CALM) return "CALM";
  if (share < BAND_CUTOFFS.WATCH) return "WATCH";
  if (share < BAND_CUTOFFS.ELEVATED) return "ELEVATED";
  if (share < BAND_CUTOFFS.HIGH) return "HIGH";
  return "CRITICAL";
}

function _gradeFor(recoverableShare, p0Count) {
  if (recoverableShare >= 0.5 || p0Count >= 5) return "F";
  if (recoverableShare >= 0.3) return "D";
  if (recoverableShare >= 0.2) return "C";
  if (recoverableShare >= 0.1) return "B";
  return "A";
}

function _buildPlaybook(verdicts, sessions) {
  var bySessionId = Object.create(null);
  sessions.forEach(function (s) { bySessionId[s.id] = s; });

  var grouped = {
    RETRY_EASIER: [], RETRY_DIFFERENT_TYPE: [], OFFER_FALLBACK: [],
    ESCALATE_MANUAL_REVIEW: [], WRITE_OFF: [], MONITOR: [],
  };
  verdicts.forEach(function (v) {
    if (grouped[v.verdict]) grouped[v.verdict].push(v);
  });

  var actions = [];

  if (grouped.RETRY_EASIER.length >= 3) {
    actions.push({
      id: "LOWER_DEFAULT_DIFFICULTY",
      priority: "P0",
      label: "Lower default challenge difficulty by 1 notch",
      reason: grouped.RETRY_EASIER.length + " humans look real but were beaten by current difficulty",
      owner: "product",
      blastRadius: 4,
      reversibility: "high",
      estRiskDelta: -0.18,
      sessionIds: grouped.RETRY_EASIER.map(function (v) { return v.sessionId; }),
    });
  }

  if (grouped.RETRY_DIFFERENT_TYPE.length >= 2) {
    actions.push({
      id: "ENABLE_ACCESSIBLE_CHALLENGE",
      priority: "P0",
      label: "Enable audio/text-alt challenge variants for accessibility cohorts",
      reason: grouped.RETRY_DIFFERENT_TYPE.length + " accessibility false-rejects detected",
      owner: "accessibility",
      blastRadius: 3,
      reversibility: "high",
      estRiskDelta: -0.14,
      sessionIds: grouped.RETRY_DIFFERENT_TYPE.map(function (v) { return v.sessionId; }),
    });
  }

  if (grouped.OFFER_FALLBACK.length >= 2) {
    actions.push({
      id: "ADD_FALLBACK_CHANNEL",
      priority: "P1",
      label: "Wire email/SMS fallback for retry-fatigued humans",
      reason: grouped.OFFER_FALLBACK.length + " humans hit retry fatigue with strong biometrics",
      owner: "product",
      blastRadius: 3,
      reversibility: "medium",
      estRiskDelta: -0.10,
      sessionIds: grouped.OFFER_FALLBACK.map(function (v) { return v.sessionId; }),
    });
  }

  if (grouped.ESCALATE_MANUAL_REVIEW.length >= 3) {
    actions.push({
      id: "STAFF_MANUAL_REVIEW_QUEUE",
      priority: "P1",
      label: "Staff or expand manual-review queue",
      reason: grouped.ESCALATE_MANUAL_REVIEW.length + " ambiguous sessions queued for review",
      owner: "ops",
      blastRadius: 2,
      reversibility: "high",
      estRiskDelta: -0.07,
      sessionIds: grouped.ESCALATE_MANUAL_REVIEW.map(function (v) { return v.sessionId; }),
    });
  }

  var midBand = verdicts.filter(function (v) {
    var s = bySessionId[v.sessionId];
    if (!s) return false;
    var b = _num(s.biometricsScore, 0.5);
    return b >= 0.4 && b < 0.7;
  });
  if (midBand.length >= 4) {
    actions.push({
      id: "AUDIT_BIOMETRICS_THRESHOLD",
      priority: "P2",
      label: "Audit biometrics scoring threshold — many mid-band scores",
      reason: midBand.length + " sessions in ambiguous biometrics band",
      owner: "security",
      blastRadius: 2,
      reversibility: "high",
      estRiskDelta: -0.04,
      sessionIds: midBand.map(function (v) { return v.sessionId; }),
    });
  }

  var geoFalse = sessions.filter(function (s) {
    return _num(s.geoRiskScore, 0) >= 0.6 && _num(s.biometricsScore, 0.5) >= 0.7;
  });
  if (geoFalse.length >= 2) {
    actions.push({
      id: "INVESTIGATE_GEO_FALSE_POSITIVES",
      priority: "P2",
      label: "Investigate geo-risk false positives (humans flagged by region)",
      reason: geoFalse.length + " sessions: high biometrics but high geo-risk",
      owner: "security",
      blastRadius: 2,
      reversibility: "high",
      estRiskDelta: -0.05,
      sessionIds: geoFalse.map(function (s) { return s.id; }),
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

function _buildInsights(verdicts, sessions) {
  var insights = [];
  var hardBeatHuman = sessions.filter(function (s) {
    return _num(s.biometricsScore, 0.5) >= 0.7 && _num(s.difficulty, 5) >= 8;
  });
  if (hardBeatHuman.length > 0) {
    insights.push(hardBeatHuman.length + " sessions look human but were rejected at difficulty>=8");
  }

  var accessFalse = verdicts.filter(function (v) { return v.verdict === "RETRY_DIFFERENT_TYPE"; });
  if (accessFalse.length > 0) {
    insights.push(accessFalse.length + " accessibility false-rejects");
  }

  var mobile = sessions.filter(function (s) { return s.deviceClass === "mobile"; });
  if (mobile.length > 0) {
    var mobileFR = mobile.filter(function (s) { return _num(s.biometricsScore, 0.5) >= 0.6; }).length;
    var pct = Math.round((mobileFR / mobile.length) * 100);
    insights.push("Mobile false-reject rate " + pct + "% (" + mobileFR + "/" + mobile.length + ")");
  }

  var geoFalse = sessions.filter(function (s) {
    return _num(s.geoRiskScore, 0) >= 0.6 && _num(s.biometricsScore, 0.5) >= 0.7;
  });
  if (geoFalse.length >= 2) {
    insights.push(geoFalse.length + " geo false-positives (human + high geo-risk)");
  }
  return insights;
}

function _stableStringify(value) {
  function visit(v) {
    if (v === null || typeof v !== "object") return v;
    if (Array.isArray(v)) return v.map(visit);
    var out = {};
    Object.keys(v).sort().forEach(function (k) { out[k] = visit(v[k]); });
    return out;
  }
  return JSON.stringify(visit(value), null, 2);
}

function analyze(input, opts) {
  if (!input || typeof input !== "object") {
    throw new TypeError("analyze() requires an input object");
  }
  if (!Array.isArray(input.sessions)) {
    throw new TypeError("input.sessions must be an array");
  }
  var sessions = input.sessions;
  var attemptHistory = Array.isArray(input.attemptHistory) ? input.attemptHistory : null;
  var risk = _normRisk(opts && opts.risk_appetite);
  var riskMult = VALID_RISKS[risk];
  var now = (opts && typeof opts.now === "number") ? opts.now : Date.now();

  var verdicts = sessions.map(function (s) {
    if (!s || s.id == null) {
      throw new TypeError("each session must have an id");
    }
    var verdict = _classifyVerdict(s);
    var score = _scoreSession(s, riskMult);
    var priority = _priorityFor(verdict, score);
    return {
      sessionId: s.id,
      verdict: verdict,
      priority: priority,
      recoveryScore: Math.round(score * 100) / 100,
      reasons: _reasonsFor(s, verdict),
      suggestedAction: _suggestedAction(verdict, s),
      confidence: Math.round(_confidence(s, attemptHistory) * 100) / 100,
    };
  });

  var recoverable = verdicts.filter(function (v) { return v.verdict !== "WRITE_OFF"; });
  var writeOff = verdicts.filter(function (v) { return v.verdict === "WRITE_OFF"; });
  var p0Count = verdicts.filter(function (v) { return v.priority === "P0"; }).length;

  var estimatedRecoverableHumans = recoverable.reduce(function (acc, v) {
    return acc + (v.recoveryScore / 100);
  }, 0);
  estimatedRecoverableHumans = Math.round(estimatedRecoverableHumans * 100) / 100;

  var recoverableShare = sessions.length > 0
    ? (recoverable.length / sessions.length)
    : 0;

  var overall = {
    sessionCount: sessions.length,
    recoverableCount: recoverable.length,
    writeOffCount: writeOff.length,
    recoverableShare: Math.round(recoverableShare * 1000) / 1000,
    estimatedRecoverableHumans: estimatedRecoverableHumans,
    p0Count: p0Count,
  };

  var playbook = _buildPlaybook(verdicts, sessions);
  var insights = _buildInsights(verdicts, sessions);

  return {
    schemaVersion: 1,
    generatedAt: new Date(now).toISOString(),
    riskAppetite: risk,
    overall: overall,
    band: _bandFor(recoverableShare),
    grade: _gradeFor(recoverableShare, p0Count),
    recoveryVerdicts: verdicts,
    playbook: playbook,
    insights: insights,
  };
}

function simulate(report, opts) {
  if (!report || !Array.isArray(report.playbook)) {
    throw new TypeError("simulate() requires a report with a playbook");
  }
  var applyTop = Math.max(0, _num(opts && opts.applyTop, 0));
  var baseShare = report.overall.recoverableShare;
  var applied = [];
  var projected = baseShare;
  for (var i = 0; i < Math.min(applyTop, report.playbook.length); i++) {
    var action = report.playbook[i];
    var delta = (action.estRiskDelta || 0) * Math.pow(0.85, i);
    projected = projected + delta;
    applied.push({
      id: action.id,
      priority: action.priority,
      appliedDelta: Math.round(delta * 10000) / 10000,
    });
  }
  projected = _clamp(projected, 0, 1);
  return {
    recoverableShare: Math.round(projected * 1000) / 1000,
    band: _bandFor(projected),
    grade: _gradeFor(projected, report.overall.p0Count),
    appliedActions: applied,
  };
}

function formatText(report) {
  if (!report) return "";
  var lines = [];
  lines.push("False-Reject Recovery Report");
  lines.push("============================");
  lines.push("Generated: " + report.generatedAt + "  Risk: " + report.riskAppetite);
  lines.push("Sessions: " + report.overall.sessionCount +
             " | Recoverable: " + report.overall.recoverableCount +
             " | WriteOff: " + report.overall.writeOffCount +
             " | Band: " + report.band + " | Grade: " + report.grade);
  lines.push("Estimated recoverable humans: " + report.overall.estimatedRecoverableHumans);
  lines.push("");
  lines.push("Per-session verdicts (top " + Math.min(20, report.recoveryVerdicts.length) + "):");
  report.recoveryVerdicts.slice(0, 20).forEach(function (v) {
    lines.push("  - " + v.sessionId + " [" + v.priority + "] " + v.verdict +
               " score=" + v.recoveryScore +
               " conf=" + v.confidence +
               " -> " + v.suggestedAction);
  });
  lines.push("");
  lines.push("Playbook (" + report.playbook.length + "):");
  report.playbook.forEach(function (a) {
    lines.push("  [" + a.priority + "] " + a.id + " (owner=" + a.owner +
               ", blast=" + a.blastRadius + ") - " + a.label);
  });
  lines.push("");
  lines.push("Insights:");
  report.insights.forEach(function (s) { lines.push("  - " + s); });
  return lines.join("\n");
}

function formatMarkdown(report) {
  if (!report) return "";
  var out = [];
  out.push("# False-Reject Recovery Report");
  out.push("");
  out.push("| Field | Value |");
  out.push("|---|---|");
  out.push("| Generated | " + report.generatedAt + " |");
  out.push("| Risk appetite | " + report.riskAppetite + " |");
  out.push("| Sessions | " + report.overall.sessionCount + " |");
  out.push("| Recoverable | " + report.overall.recoverableCount + " |");
  out.push("| Write-off | " + report.overall.writeOffCount + " |");
  out.push("| Recoverable share | " + report.overall.recoverableShare + " |");
  out.push("| Est. recoverable humans | " + report.overall.estimatedRecoverableHumans + " |");
  out.push("| Band | " + report.band + " |");
  out.push("| Grade | " + report.grade + " |");
  out.push("");
  out.push("## Sessions");
  out.push("");
  out.push("| Session | Verdict | Priority | Score | Confidence | Suggested Action |");
  out.push("|---|---|---|---|---|---|");
  report.recoveryVerdicts.slice(0, 20).forEach(function (v) {
    out.push("| " + v.sessionId + " | " + v.verdict + " | " + v.priority + " | " +
             v.recoveryScore + " | " + v.confidence + " | " + v.suggestedAction + " |");
  });
  out.push("");
  out.push("## Playbook");
  out.push("");
  if (report.playbook.length === 0) {
    out.push("_No actions recommended._");
  } else {
    report.playbook.forEach(function (a) {
      out.push("- **[" + a.priority + "] " + a.id + "** — " + a.label +
               " _(owner: " + a.owner + ", blast: " + a.blastRadius +
               ", reversibility: " + a.reversibility + ")_  ");
      out.push("  - reason: " + a.reason);
      out.push("  - estRiskDelta: " + a.estRiskDelta + ", sessions: " + a.sessionIds.length);
    });
  }
  out.push("");
  out.push("## Insights");
  out.push("");
  if (report.insights.length === 0) {
    out.push("_No notable insights._");
  } else {
    report.insights.forEach(function (s) { out.push("- " + s); });
  }
  return out.join("\n");
}

function formatJson(report) {
  return _stableStringify(report);
}

function createFalseRejectRecoveryAdvisor(opts) {
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
  createFalseRejectRecoveryAdvisor: createFalseRejectRecoveryAdvisor,
  analyze: analyze,
  simulate: simulate,
  formatText: formatText,
  formatMarkdown: formatMarkdown,
  formatJson: formatJson,
};
