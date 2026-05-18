"use strict";

/**
 * HumanVerificationConfidenceAuditor - Agentic post-PASS confidence auditor for gif-captcha.
 *
 * Sibling/mirror to FalseRejectRecoveryAdvisor: FRA asks "did we wrongly reject a human?"
 * This module asks "did we wrongly admit a bot?" for sessions we already verified, and
 * recommends retroactive blocks, step-up challenges, or manual review.
 *
 * analyze({ verifications, recentDefenseSignals?, defaults? }, { risk_appetite?, now? })
 *
 * Pure JS, no deps, deterministic given inputs + risk_appetite + now. Never mutates inputs.
 *
 * @module human-verification-confidence-auditor
 */

var DEFAULT_RISK = "balanced";
var VALID_RISKS = { cautious: 1.15, balanced: 1.0, aggressive: 0.85 };

// highRiskShare band cutoffs (0..1)
var BAND_CUTOFFS = { CALM: 0.10, WATCH: 0.20, ELEVATED: 0.35, HIGH: 0.50 };

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
  if (r && Object.prototype.hasOwnProperty.call(VALID_RISKS, r)) return r;
  return DEFAULT_RISK;
}

function _bandShiftFor(risk) {
  if (risk === "cautious") return -0.05;
  if (risk === "aggressive") return 0.05;
  return 0;
}

function _bandFor(share, risk) {
  var shift = _bandShiftFor(risk);
  var s = _clamp(share + shift, 0, 1);
  if (s < BAND_CUTOFFS.CALM) return "CALM";
  if (s < BAND_CUTOFFS.WATCH) return "WATCH";
  if (s < BAND_CUTOFFS.ELEVATED) return "ELEVATED";
  if (s < BAND_CUTOFFS.HIGH) return "HIGH";
  return "CRITICAL";
}

function _deepCopy(v) {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(_deepCopy);
  var out = {};
  Object.keys(v).forEach(function (k) { out[k] = _deepCopy(v[k]); });
  return out;
}

function _scoreSession(s, riskMult, defenseBump) {
  var reasons = [];
  var score = 20;
  reasons.push({ code: "BASELINE", label: "Baseline post-verification suspicion", delta: 20 });

  var geo = _num(s.geoRiskScore, 0);
  if (geo > 0) {
    var d = 25 * geo;
    score += d;
    reasons.push({ code: "GEO_RISK", label: "Geo-risk score", delta: +Number(d.toFixed(2)) });
  }
  var ipr = _num(s.ipReputation, 0);
  if (ipr > 0) {
    var d2 = 20 * ipr;
    score += d2;
    reasons.push({ code: "IP_REPUTATION", label: "IP reputation penalty", delta: +Number(d2.toFixed(2)) });
  }
  if (s.proxyVpnFlag) {
    score += 15;
    reasons.push({ code: "PROXY_VPN", label: "Proxy/VPN flag", delta: 15 });
  }
  if (s.userAgentSuspicious) {
    score += 12;
    reasons.push({ code: "UA_SUSPICIOUS", label: "Suspicious user-agent", delta: 12 });
  }

  var solveT = _num(s.solveTimeMs, null);
  var expSolve = _num(s.expectedSolveTimeMs, null);
  var attemptCount = _num(s.attemptCount, 1);
  if (solveT != null && expSolve != null && expSolve > 0) {
    if (solveT < 0.4 * expSolve) {
      score += 20;
      reasons.push({ code: "FAST_SOLVE", label: "Solve time well below expected", delta: 20 });
    } else if (
      attemptCount === 1 &&
      solveT >= 0.7 * expSolve &&
      solveT <= 1.5 * expSolve
    ) {
      score -= 8;
      reasons.push({ code: "NATURAL_PACING", label: "Single attempt with natural solve pacing", delta: -8 });
    }
  }

  var powT = _num(s.powDurationMs, null);
  var expPow = _num(s.expectedPowMs, null);
  if (powT != null && expPow != null && expPow > 0 && powT < 0.5 * expPow) {
    score += 12;
    reasons.push({ code: "POW_BYPASS", label: "Proof-of-work duration under threshold", delta: 12 });
  }

  var prevFail = _num(s.previousFailureRate, 0);
  if (prevFail > 0) {
    var d3 = 15 * prevFail;
    score += d3;
    reasons.push({ code: "PRIOR_FAILURES", label: "Prior session failure rate", delta: +Number(d3.toFixed(2)) });
  }

  var accountAge = _num(s.accountAgeDays, null);
  if (accountAge != null && accountAge < 1) {
    score += 10;
    reasons.push({ code: "FRESH_ACCOUNT", label: "Account age < 1 day", delta: 10 });
  }

  var bio = _num(s.biometricsScore, 0.5);
  if (bio < 0.35) {
    score += 10;
    reasons.push({ code: "LOW_BIOMETRICS", label: "Low biometrics score on a PASS", delta: 10 });
  }

  var trust = _num(s.trustScore, 0.5);
  var trustAdj = -15 * (trust - 0.5) * 2;
  if (trustAdj !== 0) {
    score += trustAdj;
    reasons.push({ code: "TRUST_OFFSET", label: "Trust score offset", delta: +Number(trustAdj.toFixed(2)) });
  }

  score *= riskMult;

  if (defenseBump.baselineBump > 0) {
    score += defenseBump.baselineBump;
    reasons.push({
      code: "ACTIVE_ATTACK_BUMP",
      label: "Active attack profile / surge bump",
      delta: +Number(defenseBump.baselineBump.toFixed(2)),
    });
  }
  if (defenseBump.honeypotBump > 0) {
    score += defenseBump.honeypotBump;
    reasons.push({
      code: "HONEYPOT_PRESSURE",
      label: "Elevated honeypot hit rate in window",
      delta: defenseBump.honeypotBump,
    });
  }

  score = _clamp(score, 0, 100);

  reasons.sort(function (a, b) {
    var ax = Math.abs(b.delta) - Math.abs(a.delta);
    if (ax !== 0) return ax;
    return a.code < b.code ? -1 : a.code > b.code ? 1 : 0;
  });

  return { score: +Number(score.toFixed(2)), reasons: reasons };
}

function _verdictFor(s, score) {
  var bio = _num(s.biometricsScore, 0.5);
  var trust = _num(s.trustScore, 0.5);
  if (score >= 80) return "HIGH_RISK_RETROACTIVE_BLOCK";
  if (score >= 60) return "STEP_UP_CHALLENGE_NEXT";
  if (score >= 40 && trust < 0.6) return "FLAG_FOR_HUMAN_REVIEW";
  if (score >= 25) return "MONITOR_ELEVATED";
  if (score < 25 && bio >= 0.7) return "ACCEPTED_HIGH_CONFIDENCE";
  return "ACCEPTED";
}

function _priorityFor(verdict) {
  switch (verdict) {
    case "HIGH_RISK_RETROACTIVE_BLOCK": return "P0";
    case "STEP_UP_CHALLENGE_NEXT": return "P1";
    case "FLAG_FOR_HUMAN_REVIEW": return "P2";
    case "MONITOR_ELEVATED": return "P2";
    case "ACCEPTED_HIGH_CONFIDENCE": return "P3";
    default: return "P3";
  }
}

function _suggestedActionsFor(verdict, reasons) {
  var has = function (code) { return reasons.some(function (r) { return r.code === code; }); };
  var out = [];
  switch (verdict) {
    case "HIGH_RISK_RETROACTIVE_BLOCK":
      out.push("Invalidate the verified token for this session");
      out.push("Block the IP/device fingerprint pending review");
      break;
    case "STEP_UP_CHALLENGE_NEXT":
      out.push("Require a step-up challenge on the next sensitive action");
      out.push("Increase difficulty tier for this user for next 24h");
      break;
    case "FLAG_FOR_HUMAN_REVIEW":
      out.push("Route to manual review queue with full evidence pack");
      break;
    case "MONITOR_ELEVATED":
      out.push("Tag session and watch next 3 actions for divergence");
      break;
    case "ACCEPTED_HIGH_CONFIDENCE":
      out.push("Whitelist for soft-friction reduction next session");
      break;
    default:
      out.push("Standard monitoring");
  }
  if (has("POW_BYPASS")) out.push("Validate PoW server-side; reject cached nonces");
  if (has("FAST_SOLVE")) out.push("Replay-check submitted solution against known-good library");
  return out;
}

function _buildPlaybook(verdicts, defaults, riskAppetite, sessions) {
  var actions = [];
  var byVerdict = {};
  verdicts.forEach(function (v) {
    byVerdict[v.verdict] = byVerdict[v.verdict] || [];
    byVerdict[v.verdict].push(v.id);
  });

  var total = verdicts.length;
  var highRiskCount = (byVerdict.HIGH_RISK_RETROACTIVE_BLOCK || []).length +
    (byVerdict.STEP_UP_CHALLENGE_NEXT || []).length;
  var highRiskShare = total > 0 ? highRiskCount / total : 0;

  function avg(field) {
    if (!sessions.length) return 0;
    var n = 0, s = 0;
    sessions.forEach(function (x) {
      var v = _num(x[field], null);
      if (v != null) { s += v; n += 1; }
    });
    return n ? s / n : 0;
  }
  var avgIpRep = avg("ipReputation");
  var avgGeo = avg("geoRiskScore");
  var fastPowCount = sessions.filter(function (s) {
    var p = _num(s.powDurationMs, null);
    var e = _num(s.expectedPowMs, null);
    return p != null && e != null && e > 0 && p < 0.5 * e;
  }).length;

  if ((byVerdict.HIGH_RISK_RETROACTIVE_BLOCK || []).length > 0) {
    actions.push({
      id: "INVALIDATE_RECENT_PASSES",
      priority: "P0",
      label: "Invalidate recent PASS tokens for flagged sessions",
      reason: "One or more sessions exceeded the retroactive-block risk floor.",
      owner: "security",
      blastRadius: 4,
      reversibility: "low",
      sessionIds: byVerdict.HIGH_RISK_RETROACTIVE_BLOCK.slice(),
      estRiskDelta: -18,
    });
  }

  if (highRiskShare >= 0.25) {
    actions.push({
      id: "RAISE_GLOBAL_DIFFICULTY",
      priority: "P0",
      label: "Raise global challenge difficulty one tier",
      reason: ">=25% of recent passes look risk-elevated; tighten the floor for everyone.",
      owner: "platform",
      blastRadius: 3,
      reversibility: "high",
      sessionIds: (byVerdict.HIGH_RISK_RETROACTIVE_BLOCK || []).concat(byVerdict.STEP_UP_CHALLENGE_NEXT || []),
      estRiskDelta: -12,
    });
  }

  if ((byVerdict.STEP_UP_CHALLENGE_NEXT || []).length > 0) {
    actions.push({
      id: "ENABLE_STEP_UP_CHANNEL",
      priority: "P1",
      label: "Enable step-up challenge channel for flagged users",
      reason: "Mid-risk sessions need a second factor before sensitive actions.",
      owner: "product",
      blastRadius: 2,
      reversibility: "high",
      sessionIds: byVerdict.STEP_UP_CHALLENGE_NEXT.slice(),
      estRiskDelta: -8,
    });
  }

  if (avgIpRep >= 0.5) {
    actions.push({
      id: "INVESTIGATE_IP_REPUTATION_FEED",
      priority: "P1",
      label: "Investigate the upstream IP-reputation feed",
      reason: "Mean IP reputation across this window is >= 0.5; either the feed is hot or we're under spray.",
      owner: "security",
      blastRadius: 2,
      reversibility: "high",
      sessionIds: sessions
        .filter(function (s) { return _num(s.ipReputation, 0) >= 0.5; })
        .map(function (s) { return s.id; }),
      estRiskDelta: -6,
    });
  }

  if (fastPowCount >= 2) {
    actions.push({
      id: "AUDIT_POW_VALIDATION",
      priority: "P1",
      label: "Audit proof-of-work validation pipeline",
      reason: "Multiple sessions completed PoW under half the expected duration.",
      owner: "platform",
      blastRadius: 2,
      reversibility: "medium",
      sessionIds: sessions
        .filter(function (s) {
          var p = _num(s.powDurationMs, null);
          var e = _num(s.expectedPowMs, null);
          return p != null && e != null && e > 0 && p < 0.5 * e;
        })
        .map(function (s) { return s.id; }),
      estRiskDelta: -7,
    });
  }

  if ((byVerdict.FLAG_FOR_HUMAN_REVIEW || []).length > 0) {
    actions.push({
      id: "ROUTE_TO_MANUAL_REVIEW_QUEUE",
      priority: "P2",
      label: "Route flagged sessions to manual review",
      reason: "Mid-risk sessions with low trust need a human in the loop.",
      owner: "ops",
      blastRadius: 1,
      reversibility: "high",
      sessionIds: byVerdict.FLAG_FOR_HUMAN_REVIEW.slice(),
      estRiskDelta: -4,
    });
  }

  if (avgGeo >= 0.4) {
    actions.push({
      id: "TIGHTEN_GEO_ALLOWLIST",
      priority: "P2",
      label: "Tighten geo allowlist / require step-up by region",
      reason: "Mean geo-risk score across this window is elevated.",
      owner: "security",
      blastRadius: 2,
      reversibility: "high",
      sessionIds: sessions
        .filter(function (s) { return _num(s.geoRiskScore, 0) >= 0.4; })
        .map(function (s) { return s.id; }),
      estRiskDelta: -5,
    });
  }

  if (actions.length === 0) {
    actions.push({
      id: "MAINTAIN_OBSERVABILITY",
      priority: "P3",
      label: "Maintain observability; no intervention required",
      reason: "Portfolio looks within tolerance — keep watching.",
      owner: "platform",
      blastRadius: 1,
      reversibility: "high",
      sessionIds: [],
      estRiskDelta: 0,
    });
  }

  // Dedup by id and order by priority then id.
  var seen = {};
  var deduped = [];
  actions.forEach(function (a) {
    if (seen[a.id]) return;
    seen[a.id] = true;
    deduped.push(a);
  });
  var prioRank = { P0: 0, P1: 1, P2: 2, P3: 3 };
  deduped.sort(function (a, b) {
    var pa = prioRank[a.priority] - prioRank[b.priority];
    if (pa !== 0) return pa;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

  return { actions: deduped, highRiskShare: highRiskShare };
}

function _gradeFor(highRiskShare, portfolioRisk, hasP0) {
  if (hasP0 || highRiskShare >= 0.30 || portfolioRisk >= 70) return "F";
  if (highRiskShare >= 0.20 || portfolioRisk >= 55) return "D";
  if (highRiskShare >= 0.10 || portfolioRisk >= 40) return "C";
  if (portfolioRisk >= 25) return "B";
  return "A";
}

function _buildInsights(sessions, verdicts, recentDefenseSignals, portfolioRisk) {
  var insights = [];
  var hasAttack = recentDefenseSignals && recentDefenseSignals.activeAttackProfile;
  if (hasAttack && portfolioRisk >= 40) {
    insights.push({
      code: "ACTIVE_ATTACK_AMPLIFIER",
      label: "Active attack profile present and elevating portfolio risk",
      detail: "Profile: " + String(recentDefenseSignals.activeAttackProfile),
    });
  }
  var avgIp = 0, ipN = 0;
  sessions.forEach(function (s) {
    var v = _num(s.ipReputation, null);
    if (v != null) { avgIp += v; ipN += 1; }
  });
  avgIp = ipN ? avgIp / ipN : 0;
  if (avgIp >= 0.5) {
    insights.push({ code: "IP_REPUTATION_CLUSTER", label: "Average IP reputation >= 0.5", detail: "avg=" + avgIp.toFixed(2) });
  }
  var fastSolve = sessions.filter(function (s) {
    var solveT = _num(s.solveTimeMs, null);
    var exp = _num(s.expectedSolveTimeMs, null);
    return solveT != null && exp != null && exp > 0 && solveT < 0.4 * exp;
  }).length;
  if (fastSolve >= 3) {
    insights.push({ code: "FAST_SOLVE_PATTERN", label: "3+ sessions with solve < 40% of expected", detail: "count=" + fastSolve });
  }
  var fastPow = sessions.filter(function (s) {
    var p = _num(s.powDurationMs, null);
    var e = _num(s.expectedPowMs, null);
    return p != null && e != null && e > 0 && p < 0.5 * e;
  }).length;
  if (fastPow >= 2) {
    insights.push({ code: "POW_BYPASS_PATTERN", label: "2+ sessions with PoW under half expected", detail: "count=" + fastPow });
  }
  var proxyCount = sessions.filter(function (s) { return !!s.proxyVpnFlag; }).length;
  if (proxyCount >= 3) {
    insights.push({ code: "PROXY_VPN_CLUSTER", label: "3+ sessions flagged proxy/VPN", detail: "count=" + proxyCount });
  }
  var lowTrust = sessions.filter(function (s) { return _num(s.trustScore, 1) < 0.4; }).length;
  if (sessions.length > 0 && lowTrust / sessions.length >= 0.5) {
    insights.push({
      code: "LOW_TRUST_BURST",
      label: ">=50% of sessions had trustScore < 0.4",
      detail: "ratio=" + (lowTrust / sessions.length).toFixed(2),
    });
  }
  if (insights.length === 0) {
    insights.push({ code: "HEALTHY_PORTFOLIO", label: "No suspicious cross-session signals", detail: "" });
  }
  insights.sort(function (a, b) { return a.code < b.code ? -1 : a.code > b.code ? 1 : 0; });
  return insights;
}

function _stableStringify(value, indent) {
  var pad = indent || 2;
  function s(v, depth) {
    if (v === null) return "null";
    if (typeof v === "number") return isFinite(v) ? String(v) : "null";
    if (typeof v === "boolean") return v ? "true" : "false";
    if (typeof v === "string") return JSON.stringify(v);
    if (typeof v === "undefined") return "null";
    var spacer = " ".repeat(pad * depth);
    var inner = " ".repeat(pad * (depth + 1));
    if (Array.isArray(v)) {
      if (v.length === 0) return "[]";
      var parts = v.map(function (x) { return inner + s(x, depth + 1); });
      return "[\n" + parts.join(",\n") + "\n" + spacer + "]";
    }
    if (typeof v === "object") {
      var keys = Object.keys(v).sort();
      if (keys.length === 0) return "{}";
      var lines = keys.map(function (k) {
        return inner + JSON.stringify(k) + ": " + s(v[k], depth + 1);
      });
      return "{\n" + lines.join(",\n") + "\n" + spacer + "}";
    }
    return "null";
  }
  return s(value, 0);
}

function createHumanVerificationConfidenceAuditor() {
  function analyze(input, opts) {
    input = input || {};
    opts = opts || {};
    var risk = _normRisk(opts.risk_appetite);
    var riskMult = VALID_RISKS[risk];

    var verifications = Array.isArray(input.verifications) ? input.verifications : [];
    var sessions = verifications.map(_deepCopy);
    var rds = input.recentDefenseSignals ? _deepCopy(input.recentDefenseSignals) : null;

    var baselineBump = 0;
    var honeypotBump = 0;
    if (rds && rds.activeAttackProfile) {
      baselineBump = (typeof rds.surgeFactor === "number" && isFinite(rds.surgeFactor) ? rds.surgeFactor : 1.0) * 8;
    }
    if (rds && typeof rds.honeypotHitRate === "number" && rds.honeypotHitRate >= 0.05) {
      honeypotBump = 10;
    }
    var defenseBump = { baselineBump: baselineBump, honeypotBump: honeypotBump };

    var verdicts = sessions.map(function (s) {
      var scored = _scoreSession(s, riskMult, defenseBump);
      var verdict = _verdictFor(s, scored.score);
      var priority = _priorityFor(verdict);
      var suggested = _suggestedActionsFor(verdict, scored.reasons);
      return {
        id: String(s.id),
        verdict: verdict,
        falseAcceptRisk: scored.score,
        priority: priority,
        reasons: scored.reasons,
        suggestedActions: suggested,
      };
    });

    var portfolioRisk = verdicts.length
      ? +Number(verdicts.reduce(function (a, v) { return a + v.falseAcceptRisk; }, 0) / verdicts.length).toFixed(2)
      : 0;

    var pb = _buildPlaybook(verdicts, input.defaults || {}, risk, sessions);
    var hasP0 = pb.actions.some(function (a) { return a.priority === "P0"; });
    var band = _bandFor(pb.highRiskShare, risk);
    var grade = _gradeFor(pb.highRiskShare, portfolioRisk, hasP0);
    var insights = _buildInsights(sessions, verdicts, rds, portfolioRisk);

    var overall = {
      sessionCount: verdicts.length,
      highRiskCount: verdicts.filter(function (v) {
        return v.verdict === "HIGH_RISK_RETROACTIVE_BLOCK" || v.verdict === "STEP_UP_CHALLENGE_NEXT";
      }).length,
      highRiskShare: +Number(pb.highRiskShare).toFixed(4),
      portfolioRisk: portfolioRisk,
      band: band,
      grade: grade,
    };

    return {
      generatedAt: typeof opts.now === "number" ? opts.now : 0,
      risk_appetite: risk,
      overall: overall,
      band: band,
      grade: grade,
      portfolioRisk: portfolioRisk,
      verifications: verdicts,
      playbook: pb.actions,
      insights: insights,
    };
  }

  function simulate(report, opts) {
    opts = opts || {};
    var applyTop = typeof opts.applyTop === "number" ? opts.applyTop : 3;
    if (!report || !Array.isArray(report.playbook)) {
      return { projectedPortfolioRisk: 0, projectedBand: "CALM", projectedGrade: "A", appliedActions: [] };
    }
    var applied = report.playbook.slice(0, applyTop);
    var projected = report.portfolioRisk;
    var diminishing = 1.0;
    var details = [];
    applied.forEach(function (a, i) {
      var delta = (a.estRiskDelta || 0) * diminishing;
      projected += delta;
      details.push({
        id: a.id,
        priority: a.priority,
        rawDelta: a.estRiskDelta || 0,
        appliedDelta: +Number(delta).toFixed(3),
      });
      diminishing *= 0.85;
    });
    projected = _clamp(projected, 0, 100);
    var risk = report.risk_appetite || DEFAULT_RISK;
    var hrShare = report.overall ? report.overall.highRiskShare : 0;
    var projectedBand = _bandFor(hrShare, risk);
    // Improve grade if portfolioRisk dropped enough; recompute with simulated risk and no P0 if INVALIDATE applied.
    var simulatedHasP0 = !applied.some(function (a) { return a.id === "INVALIDATE_RECENT_PASSES" || a.id === "RAISE_GLOBAL_DIFFICULTY"; }) &&
      report.playbook.some(function (a) { return a.priority === "P0"; });
    var projectedGrade = _gradeFor(hrShare, projected, simulatedHasP0);
    return {
      projectedPortfolioRisk: +Number(projected).toFixed(2),
      projectedBand: projectedBand,
      projectedGrade: projectedGrade,
      appliedActions: details,
    };
  }

  function formatText(report) {
    if (!report) return "";
    var lines = [];
    lines.push("HumanVerificationConfidenceAuditor: " + report.band + " (grade " + report.grade + ") portfolioRisk=" + report.portfolioRisk);
    lines.push("Sessions: " + report.overall.sessionCount + " | High-risk: " + report.overall.highRiskCount + " (" + (report.overall.highRiskShare * 100).toFixed(1) + "%)");
    lines.push("");
    lines.push("Per-session:");
    report.verifications.forEach(function (v) {
      var topReason = v.reasons.length ? v.reasons[0].label : "";
      lines.push("  [" + v.priority + "] " + v.id + " -> " + v.verdict + " (risk=" + v.falseAcceptRisk + ") " + topReason);
    });
    lines.push("");
    lines.push("Playbook:");
    report.playbook.forEach(function (a) {
      lines.push("  [" + a.priority + "] " + a.id + " (" + a.owner + ", blast=" + a.blastRadius + ", " + a.reversibility + ") - " + a.label);
    });
    lines.push("");
    lines.push("Insights:");
    report.insights.forEach(function (i) {
      lines.push("  - " + i.code + ": " + i.label + (i.detail ? " (" + i.detail + ")" : ""));
    });
    return lines.join("\n");
  }

  function formatMarkdown(report) {
    if (!report) return "";
    var lines = [];
    lines.push("# Human Verification Confidence Auditor");
    lines.push("");
    lines.push("## Summary");
    lines.push("");
    lines.push("| Field | Value |");
    lines.push("| --- | --- |");
    lines.push("| Band | " + report.band + " |");
    lines.push("| Grade | " + report.grade + " |");
    lines.push("| Portfolio risk | " + report.portfolioRisk + " |");
    lines.push("| Sessions | " + report.overall.sessionCount + " |");
    lines.push("| High-risk count | " + report.overall.highRiskCount + " |");
    lines.push("| High-risk share | " + (report.overall.highRiskShare * 100).toFixed(1) + "% |");
    lines.push("| Risk appetite | " + report.risk_appetite + " |");
    lines.push("");
    lines.push("## Sessions");
    lines.push("");
    lines.push("| id | verdict | risk | priority | top reason |");
    lines.push("| --- | --- | --- | --- | --- |");
    report.verifications.forEach(function (v) {
      var top = v.reasons.length ? v.reasons[0].label : "";
      lines.push("| " + v.id + " | " + v.verdict + " | " + v.falseAcceptRisk + " | " + v.priority + " | " + top + " |");
    });
    lines.push("");
    lines.push("## Playbook");
    lines.push("");
    lines.push("| priority | id | owner | blastRadius | reversibility | label |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    report.playbook.forEach(function (a) {
      lines.push("| " + a.priority + " | " + a.id + " | " + a.owner + " | " + a.blastRadius + " | " + a.reversibility + " | " + a.label + " |");
    });
    lines.push("");
    lines.push("## Insights");
    lines.push("");
    report.insights.forEach(function (i) {
      lines.push("- **" + i.code + "** - " + i.label + (i.detail ? " (" + i.detail + ")" : ""));
    });
    return lines.join("\n");
  }

  function formatJson(report) {
    return _stableStringify(report || {}, 2);
  }

  return {
    analyze: analyze,
    simulate: simulate,
    formatText: formatText,
    formatMarkdown: formatMarkdown,
    formatJson: formatJson,
  };
}

module.exports = {
  createHumanVerificationConfidenceAuditor: createHumanVerificationConfidenceAuditor,
};
