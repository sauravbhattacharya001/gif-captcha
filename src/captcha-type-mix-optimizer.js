"use strict";

/**
 * CaptchaTypeMixOptimizer - Agentic per-CAPTCHA-type triage + portfolio mix optimizer.
 *
 * 7th sibling in the gif-captcha agentic family (alongside attack-response-playbook,
 * attack-forecaster, user-abandonment-forecaster, false-reject-recovery-advisor,
 * human-verification-confidence-auditor, and honeypot-effectiveness-advisor).
 *
 * Given the telemetry of a portfolio of deployed CAPTCHA challenge types
 * (text / image / audio / puzzle / slider / behavioral / pow / honeypot / other)
 * it classifies each type and produces a portfolio-level playbook describing
 * which types to scale, keep, monitor, rework, reduce, or retire, plus a
 * concrete recommended share allocation (% of impressions) per type.
 *
 * Pure JS, zero deps, deterministic given inputs + risk_appetite + now.
 * Never mutates inputs (deep-copies into work arrays).
 *
 * Public API:
 *   createCaptchaTypeMixOptimizer() => {
 *     analyze({ types, defaults? }, { risk_appetite?, now? }) -> report,
 *     recommendMix(report, { totalBudgetPct? }) -> { allocations, rationale },
 *     formatText(report), formatMarkdown(report), formatJson(report)
 *   }
 *
 * @module captcha-type-mix-optimizer
 */

var DEFAULT_RISK = "balanced";
var VALID_RISKS = { cautious: 1.10, balanced: 1.0, aggressive: 0.92 };

var BAND_CUTOFFS = { CALM: 20, WATCH: 35, ELEVATED: 55, HIGH: 75 };

var VALID_KINDS = {
  text: 1, image: 1, audio: 1, puzzle: 1, slider: 1,
  behavioral: 1, pow: 1, honeypot: 1, other: 1,
};

var DEFAULTS = {
  minImpressionsForVerdict: 100,
  costHotspotUsdPer1k: 3.0,
  costAuditUsdPer1k: 1.5,
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

function _str(v, fallback) {
  if (typeof v === "string" && v.length > 0) return v;
  return fallback;
}

function _bool(v) { return v === true; }

function _round(n, places) {
  var f = Math.pow(10, places || 0);
  return Math.round(n * f) / f;
}

function _normRisk(r) {
  if (r && Object.prototype.hasOwnProperty.call(VALID_RISKS, r)) return r;
  return DEFAULT_RISK;
}

function _deepCopyType(t) {
  return {
    id: _str(t && t.id, "type_unknown"),
    kind: (t && VALID_KINDS[t.kind]) ? t.kind : "other",
    currentSharePct: _clamp(_num(t && t.currentSharePct, 0), 0, 100),
    impressions: Math.max(0, Math.floor(_num(t && t.impressions, 0))),
    solves: Math.max(0, Math.floor(_num(t && t.solves, 0))),
    failures: Math.max(0, Math.floor(_num(t && t.failures, 0))),
    abandonments: Math.max(0, Math.floor(_num(t && t.abandonments, 0))),
    avgSolveSeconds: Math.max(0, _num(t && t.avgSolveSeconds, 0)),
    botPassRate: _clamp(_num(t && t.botPassRate, 0), 0, 1),
    accessibilityScore: _clamp(_num(t && t.accessibilityScore, 1), 0, 1),
    costUsdPer1k: Math.max(0, _num(t && t.costUsdPer1k, 0)),
    a11yIncidents: Math.max(0, Math.floor(_num(t && t.a11yIncidents, 0))),
    userComplaintRate: _clamp(_num(t && t.userComplaintRate, 0), 0, 1),
    recentTrend: _clamp(_num(t && t.recentTrend, 0), -1, 1),
    isFallbackOnly: _bool(t && t.isFallbackOnly),
  };
}

function _assessOne(t, defaults) {
  var impressions = t.impressions;
  var enoughData = impressions >= defaults.minImpressionsForVerdict;
  var successRate = impressions > 0 ? t.solves / impressions : 0;
  var failureRate = impressions > 0 ? t.failures / impressions : 0;
  var abandonRate = impressions > 0 ? t.abandonments / impressions : 0;
  var effectiveness = _clamp(successRate * (1 - t.botPassRate), 0, 1);
  var solveTimeBurden = _clamp(t.avgSolveSeconds / 30, 0, 1);
  var burden = _clamp(
    abandonRate * 0.5 + solveTimeBurden * 0.4 + t.userComplaintRate * 0.5 + (1 - t.accessibilityScore) * 0.3,
    0,
    2
  );

  // Risk components (sum to 100 weight-max).
  var rBot = t.botPassRate * 40;
  var rTrend = Math.max(0, t.recentTrend) * 15;
  var rFail = failureRate * 15;
  var rA11y = Math.min(1, t.a11yIncidents / 20) * 10;
  var rAbandon = abandonRate * 10;
  var rEff = (1 - effectiveness) * 10;
  var rawRisk = rBot + rTrend + rFail + rA11y + rAbandon + rEff;
  // pre-appetite raw is used later for monotonicity; appetite applied at portfolio scoring time.

  // Reasons (structured codes).
  var reasons = [];
  if (!enoughData) reasons.push({ code: "INSUFFICIENT_DATA", detail: "impressions<" + defaults.minImpressionsForVerdict });
  if (t.botPassRate >= 0.25) reasons.push({ code: "HIGH_BOT_PASS", detail: "botPassRate=" + _round(t.botPassRate, 3) });
  if (enoughData && effectiveness < 0.30) reasons.push({ code: "LOW_EFFECTIVENESS", detail: "eff=" + _round(effectiveness, 3) });
  if (enoughData && abandonRate >= 0.25) reasons.push({ code: "HIGH_ABANDONMENT", detail: "abandon=" + _round(abandonRate, 3) });
  if (t.avgSolveSeconds >= 20) reasons.push({ code: "SLOW_SOLVE", detail: t.avgSolveSeconds + "s avg" });
  if (t.accessibilityScore < 0.5 || t.a11yIncidents >= 5) reasons.push({ code: "ACCESSIBILITY_GAP", detail: "a11y=" + _round(t.accessibilityScore, 2) + " incidents=" + t.a11yIncidents });
  if (t.recentTrend >= 0.3) reasons.push({ code: "RISING_ATTACK_PRESSURE", detail: "trend=" + _round(t.recentTrend, 2) });
  if (t.costUsdPer1k >= DEFAULTS.costHotspotUsdPer1k) reasons.push({ code: "COST_INEFFICIENT", detail: "$" + _round(t.costUsdPer1k, 2) + "/1k" });
  if (enoughData && effectiveness >= 0.6 && t.botPassRate < 0.05 && abandonRate < 0.20) reasons.push({ code: "SOLID_PERFORMER", detail: "eff=" + _round(effectiveness, 3) });
  if (t.isFallbackOnly) reasons.push({ code: "FALLBACK_ONLY_ROLE", detail: "fallback-only" });

  // Verdict ladder (most severe wins).
  var verdict;
  if (enoughData && (effectiveness < 0.15 || t.botPassRate >= 0.50 || t.a11yIncidents >= 10)) {
    verdict = "RETIRE";
  } else if (enoughData && (t.botPassRate >= 0.30 || abandonRate >= 0.40)) {
    verdict = "REDUCE";
  } else if (enoughData && (effectiveness < 0.40 || (t.accessibilityScore < 0.5 && t.a11yIncidents >= 3))) {
    verdict = "REWORK";
  } else if (enoughData && effectiveness >= 0.6 && t.botPassRate < 0.05 && abandonRate < 0.20 && t.accessibilityScore >= 0.7) {
    verdict = "SCALE_UP";
  } else if (!enoughData) {
    verdict = "MONITOR";
  } else if (effectiveness >= 0.45 && t.botPassRate < 0.15) {
    verdict = "KEEP";
  } else {
    verdict = "MONITOR";
  }

  // Priority bucket.
  var priority;
  if ((verdict === "RETIRE" && t.currentSharePct > 0) || t.botPassRate >= 0.50) {
    priority = "P0";
  } else if (verdict === "REDUCE" || verdict === "REWORK") {
    priority = "P1";
  } else if (verdict === "MONITOR") {
    priority = "P2";
  } else {
    priority = "P3";
  }

  return {
    id: t.id,
    kind: t.kind,
    currentSharePct: t.currentSharePct,
    impressions: impressions,
    successRate: _round(successRate, 4),
    failureRate: _round(failureRate, 4),
    abandonRate: _round(abandonRate, 4),
    effectiveness: _round(effectiveness, 4),
    burden: _round(burden, 4),
    botPassRate: t.botPassRate,
    accessibilityScore: t.accessibilityScore,
    a11yIncidents: t.a11yIncidents,
    avgSolveSeconds: t.avgSolveSeconds,
    costUsdPer1k: t.costUsdPer1k,
    recentTrend: t.recentTrend,
    isFallbackOnly: t.isFallbackOnly,
    rawRisk: _round(_clamp(rawRisk, 0, 100), 2),
    verdict: verdict,
    priority: priority,
    reasons: reasons,
  };
}

function _portfolioMetrics(assessments) {
  var totalShare = 0;
  var weightedEff = 0;
  var weightedBurden = 0;
  var weightedCost = 0;
  var weightedRisk = 0;
  var sumSq = 0;
  var maxShare = 0;
  var activeKinds = {};
  var topShareItem = null;
  for (var i = 0; i < assessments.length; i++) {
    var a = assessments[i];
    var s = a.currentSharePct;
    totalShare += s;
    var f = s / 100;
    weightedEff += a.effectiveness * f;
    weightedBurden += a.burden * f;
    weightedCost += a.costUsdPer1k * f;
    weightedRisk += a.rawRisk * f;
    sumSq += f * f;
    if (s > maxShare) { maxShare = s; topShareItem = a; }
    if (s >= 5) activeKinds[a.kind] = (activeKinds[a.kind] || 0) + s;
  }
  var diversityScore = _clamp(1 - sumSq, 0, 1);
  return {
    totalShare: _round(totalShare, 2),
    weightedEffectiveness: _round(weightedEff, 4),
    weightedBurden: _round(weightedBurden, 4),
    weightedCostUsdPer1k: _round(weightedCost, 4),
    weightedRiskRaw: _round(weightedRisk, 2),
    diversityScore: _round(diversityScore, 4),
    maxShare: _round(maxShare, 2),
    topShareItem: topShareItem,
    activeKinds: activeKinds,
  };
}

function _bandFor(risk) {
  if (risk < BAND_CUTOFFS.CALM) return "CALM";
  if (risk < BAND_CUTOFFS.WATCH) return "WATCH";
  if (risk < BAND_CUTOFFS.ELEVATED) return "ELEVATED";
  if (risk < BAND_CUTOFFS.HIGH) return "HIGH";
  return "CRITICAL";
}

function _gradeFor(band, p0Count) {
  if (band === "CRITICAL" || p0Count >= 3) return "F";
  if (band === "HIGH" || p0Count >= 2) return "D";
  if (band === "ELEVATED" || p0Count >= 1) return "C";
  if (band === "WATCH") return "B";
  return "A";
}

function _buildInsights(assessments, metrics, defaults) {
  var insights = [];
  // INSUFFICIENT_DATA_OR_BAD_INPUT: share-sum off.
  if (assessments.length > 0 && Math.abs(metrics.totalShare - 100) > 5) {
    insights.push({
      code: "INSUFFICIENT_DATA_OR_BAD_INPUT",
      severity: "low",
      message: "currentSharePct sums to " + metrics.totalShare + " (expected ~100)",
    });
  }
  // LEAKY_TYPE_DOMINANT
  if (metrics.topShareItem && metrics.topShareItem.currentSharePct >= 20 && metrics.topShareItem.botPassRate >= 0.30) {
    insights.push({
      code: "LEAKY_TYPE_DOMINANT",
      severity: "high",
      message: "Top-share type '" + metrics.topShareItem.id + "' has botPassRate=" + _round(metrics.topShareItem.botPassRate, 3),
    });
  }
  // ACCESSIBILITY_DEBT
  var a11yCount = 0;
  for (var i = 0; i < assessments.length; i++) {
    if (assessments[i].accessibilityScore < 0.5 && assessments[i].currentSharePct >= 10) a11yCount++;
  }
  if (a11yCount >= 2) insights.push({ code: "ACCESSIBILITY_DEBT", severity: "medium", message: a11yCount + " kinds with a11y<0.5 and share>=10%" });
  // OVER_CONCENTRATED
  if (metrics.maxShare >= 70) insights.push({ code: "OVER_CONCENTRATED", severity: "medium", message: "max share=" + metrics.maxShare + "%" });
  // UNDER_DIVERSIFIED
  var activeCount = Object.keys(metrics.activeKinds).length;
  if (assessments.length > 0 && activeCount < 3) insights.push({ code: "UNDER_DIVERSIFIED", severity: "medium", message: activeCount + " active kinds with share>=5%" });
  // RISING_ATTACK_FRONT
  var risingCount = 0;
  for (var j = 0; j < assessments.length; j++) if (assessments[j].recentTrend >= 0.3) risingCount++;
  if (risingCount >= 2) insights.push({ code: "RISING_ATTACK_FRONT", severity: "high", message: risingCount + " types with rising attack pressure" });
  // BEHAVIORAL_LAYER_MISSING
  var hasBehavioralLayer = false;
  for (var k = 0; k < assessments.length; k++) {
    var a = assessments[k];
    if ((a.kind === "behavioral" || a.kind === "honeypot") && a.currentSharePct >= 5) { hasBehavioralLayer = true; break; }
  }
  if (!hasBehavioralLayer && assessments.length > 0) {
    insights.push({ code: "BEHAVIORAL_LAYER_MISSING", severity: "medium", message: "No behavioral/honeypot kind has share>=5%" });
  }
  // COST_HOTSPOT
  var costHot = false;
  for (var m = 0; m < assessments.length; m++) {
    if (assessments[m].costUsdPer1k >= defaults.costHotspotUsdPer1k) { costHot = true; break; }
  }
  if (costHot) insights.push({ code: "COST_HOTSPOT", severity: "low", message: "At least one type has costUsdPer1k>=$" + defaults.costHotspotUsdPer1k });
  return insights;
}

function _buildPlaybook(assessments, metrics, band, riskAppetite, defaults) {
  var actions = [];
  var idCounter = 0;
  function add(action) {
    action.id = "act_" + (++idCounter);
    actions.push(action);
  }

  var retireIds = [];
  var reduceIds = [];
  var reworkA11yIds = [];
  var scaleIds = [];
  var monitorIds = [];
  var leakyReduceIds = [];
  for (var i = 0; i < assessments.length; i++) {
    var a = assessments[i];
    if (a.verdict === "RETIRE" && a.currentSharePct > 0) retireIds.push(a.id);
    if (a.verdict === "REDUCE") {
      reduceIds.push(a.id);
      if (a.botPassRate >= 0.30) leakyReduceIds.push(a.id);
    }
    if ((a.verdict === "REWORK" || a.verdict === "RETIRE") && (a.accessibilityScore < 0.5 || a.a11yIncidents >= 5)) reworkA11yIds.push(a.id);
    if (a.verdict === "SCALE_UP") scaleIds.push(a.id);
    if (a.verdict === "MONITOR") monitorIds.push(a.id);
  }

  if (retireIds.length > 0) {
    add({
      priority: "P0", code: "RETIRE_FAILED_TYPE", label: "Retire failed CAPTCHA types",
      reason: "Types " + retireIds.join(",") + " classified RETIRE.",
      owner: "security", blastRadius: 4, reversibility: "medium", targetTypeIds: retireIds.slice(),
    });
  }
  if (leakyReduceIds.length > 0) {
    add({
      priority: "P0", code: "REDUCE_SHARE_OF_LEAKY", label: "Reduce share of leaky types",
      reason: "Bot pass rate >= 0.30 for " + leakyReduceIds.join(","),
      owner: "security", blastRadius: 3, reversibility: "high", targetTypeIds: leakyReduceIds.slice(),
    });
  }
  if (reworkA11yIds.length > 0) {
    add({
      priority: "P1", code: "REWORK_FOR_ACCESSIBILITY", label: "Rework types for accessibility",
      reason: "Accessibility incidents >=5 or a11y<0.5 for " + reworkA11yIds.join(","),
      owner: "ux", blastRadius: 3, reversibility: "medium", targetTypeIds: reworkA11yIds.slice(),
    });
  }
  var soleKindHigh = (metrics.maxShare >= 80);
  if (metrics.diversityScore < 0.4 || soleKindHigh) {
    add({
      priority: "P1", code: "DIVERSIFY_PORTFOLIO", label: "Diversify CAPTCHA portfolio",
      reason: "diversityScore=" + metrics.diversityScore + ", maxShare=" + metrics.maxShare + "%",
      owner: "security_arch", blastRadius: 4, reversibility: "medium", targetTypeIds: [],
    });
  }
  if (scaleIds.length > 0) {
    add({
      priority: "P1", code: "SCALE_PROVEN_PERFORMER", label: "Scale proven performers",
      reason: "SCALE_UP verdict on " + scaleIds.join(","),
      owner: "platform", blastRadius: 2, reversibility: "high", targetTypeIds: scaleIds.slice(),
    });
  }
  var hasLayer = false;
  for (var i2 = 0; i2 < assessments.length; i2++) {
    var aa = assessments[i2];
    if ((aa.kind === "behavioral" || aa.kind === "honeypot") && aa.currentSharePct >= 5) { hasLayer = true; break; }
  }
  if (!hasLayer && assessments.length > 0) {
    add({
      priority: "P1", code: "ADD_BEHAVIORAL_OR_HONEYPOT_LAYER", label: "Add behavioral or honeypot layer",
      reason: "No behavioral/honeypot kind has share>=5%.",
      owner: "security", blastRadius: 2, reversibility: "high", targetTypeIds: [],
    });
  }
  // MIGRATE_OFF_TEXT_CAPTCHA
  var textMigrateIds = [];
  for (var i3 = 0; i3 < assessments.length; i3++) {
    var ta = assessments[i3];
    if (ta.kind === "text" && ta.accessibilityScore < 0.5 && ta.currentSharePct >= 10) textMigrateIds.push(ta.id);
  }
  if (textMigrateIds.length > 0) {
    add({
      priority: "P2", code: "MIGRATE_OFF_TEXT_CAPTCHA", label: "Migrate off accessibility-poor text CAPTCHA",
      reason: "text-kind with a11y<0.5 and share>=10%: " + textMigrateIds.join(","),
      owner: "ux", blastRadius: 3, reversibility: "medium", targetTypeIds: textMigrateIds,
    });
  }
  if (metrics.weightedCostUsdPer1k >= defaults.costAuditUsdPer1k) {
    add({
      priority: "P2", code: "AUDIT_COST_INEFFICIENT", label: "Audit cost-inefficient mix",
      reason: "weightedCostUsdPer1k=$" + metrics.weightedCostUsdPer1k + " >= audit threshold $" + defaults.costAuditUsdPer1k,
      owner: "platform", blastRadius: 2, reversibility: "high", targetTypeIds: [],
    });
  }
  if (monitorIds.length > 0) {
    add({
      priority: "P3", code: "MONITOR_BORDERLINE", label: "Monitor borderline types",
      reason: "MONITOR verdict on " + monitorIds.join(","),
      owner: "ops", blastRadius: 1, reversibility: "high", targetTypeIds: monitorIds.slice(),
    });
  }

  var hasP0 = false, hasP1 = false, hasP2 = false;
  for (var p = 0; p < actions.length; p++) {
    if (actions[p].priority === "P0") hasP0 = true;
    if (actions[p].priority === "P1") hasP1 = true;
    if (actions[p].priority === "P2") hasP2 = true;
  }
  if (!hasP0 && !hasP1 && !hasP2) {
    add({
      priority: "P3", code: "HOLD_HEALTHY_MIX", label: "Hold current healthy mix",
      reason: "No P0/P1/P2 actions triggered.",
      owner: "ops", blastRadius: 1, reversibility: "high", targetTypeIds: [],
    });
  }

  // Risk-appetite shaping.
  if (riskAppetite === "aggressive") {
    actions = actions.filter(function (a) { return a.priority !== "P3"; });
  } else if (riskAppetite === "cautious" && hasP0) {
    add({
      priority: "P2", code: "SOLICIT_SECURITY_REVIEW", label: "Solicit security architecture review",
      reason: "Cautious mode + P0 actions present.",
      owner: "security_arch", blastRadius: 2, reversibility: "high", targetTypeIds: [],
    });
  }

  // P0-first stable ordering by priority then insertion order.
  var rank = { P0: 0, P1: 1, P2: 2, P3: 3 };
  actions.sort(function (a, b) {
    var d = rank[a.priority] - rank[b.priority];
    if (d !== 0) return d;
    return parseInt(a.id.slice(4), 10) - parseInt(b.id.slice(4), 10);
  });
  return actions;
}

function _summary(assessments, metrics, band, grade, p0Count) {
  return {
    totalTypes: assessments.length,
    totalShare: metrics.totalShare,
    weightedEffectiveness: metrics.weightedEffectiveness,
    weightedBurden: metrics.weightedBurden,
    weightedCostUsdPer1k: metrics.weightedCostUsdPer1k,
    diversityScore: metrics.diversityScore,
    maxShare: metrics.maxShare,
    band: band,
    grade: grade,
    p0Count: p0Count,
  };
}

function _hasAnyKindWithBigLeak(assessments) {
  for (var i = 0; i < assessments.length; i++) {
    if (assessments[i].botPassRate >= 0.70 && assessments[i].currentSharePct >= 20) return true;
  }
  return false;
}

function createCaptchaTypeMixOptimizer() {

  function analyze(input, opts) {
    opts = opts || {};
    var riskAppetite = _normRisk(opts.risk_appetite);
    var nowMs = _num(opts.now, Date.now());

    var defaults = {
      minImpressionsForVerdict: _num(input && input.defaults && input.defaults.minImpressionsForVerdict, DEFAULTS.minImpressionsForVerdict),
      costHotspotUsdPer1k: _num(input && input.defaults && input.defaults.costHotspotUsdPer1k, DEFAULTS.costHotspotUsdPer1k),
      costAuditUsdPer1k: _num(input && input.defaults && input.defaults.costAuditUsdPer1k, DEFAULTS.costAuditUsdPer1k),
    };

    var rawTypes = (input && Array.isArray(input.types)) ? input.types : [];
    var copies = [];
    for (var i = 0; i < rawTypes.length; i++) copies.push(_deepCopyType(rawTypes[i]));

    var assessments = [];
    for (var j = 0; j < copies.length; j++) assessments.push(_assessOne(copies[j], defaults));

    var metrics = _portfolioMetrics(assessments);

    // Apply risk_appetite multiplier to portfolio risk.
    var mult = VALID_RISKS[riskAppetite];
    var portfolioRisk = _clamp(metrics.weightedRiskRaw * mult, 0, 100);
    var band = assessments.length === 0 ? "CALM" : _bandFor(portfolioRisk);

    var p0Count = 0;
    for (var k = 0; k < assessments.length; k++) if (assessments[k].priority === "P0") p0Count++;

    var grade;
    if (assessments.length === 0) grade = "A";
    else if (_hasAnyKindWithBigLeak(assessments)) grade = "F";
    else grade = _gradeFor(band, p0Count);

    var insights = _buildInsights(assessments, metrics, defaults);
    if (assessments.length === 0) {
      insights.push({ code: "HEALTHY_PORTFOLIO", severity: "low", message: "No CAPTCHA types provided; portfolio considered empty/CALM." });
      insights.push({ code: "SOLID_PORTFOLIO", severity: "low", message: "No P0 actions; mix considered healthy." });
    } else if (band === "CALM" && p0Count === 0) {
      insights.push({ code: "SOLID_PORTFOLIO", severity: "low", message: "Band CALM and no P0 actions." });
    }

    var playbook = _buildPlaybook(assessments, metrics, band, riskAppetite, defaults);

    var summary = _summary(assessments, metrics, band, grade, p0Count);
    summary.portfolioRisk = _round(portfolioRisk, 2);

    return {
      version: 1,
      generatedAt: nowMs,
      riskAppetite: riskAppetite,
      band: band,
      grade: grade,
      summary: summary,
      perType: assessments,
      insights: insights,
      playbook: playbook,
    };
  }

  function recommendMix(report, opts) {
    opts = opts || {};
    var totalBudgetPct = _num(opts.totalBudgetPct, 100);
    if (totalBudgetPct <= 0) totalBudgetPct = 100;

    var actionMap = {
      SCALE_UP: { mult: 1.5, action: "SCALE", absoluteCap: 20 },
      KEEP: { mult: 1.0, action: "KEEP", absoluteCap: 0 },
      MONITOR: { mult: 0.9, action: "KEEP", absoluteCap: 0 },
      REWORK: { mult: 0.7, action: "SHRINK", absoluteCap: 0 },
      REDUCE: { mult: 0.5, action: "SHRINK", absoluteCap: 0 },
      RETIRE: { mult: 0.0, action: "REPLACE", absoluteCap: 0 },
    };

    var per = (report && report.perType) ? report.perType : [];
    var raw = [];
    var sumRaw = 0;
    for (var i = 0; i < per.length; i++) {
      var a = per[i];
      var m = actionMap[a.verdict] || actionMap.KEEP;
      var rawShare = a.currentSharePct * m.mult;
      // Cap absolute upward delta for SCALE_UP.
      if (m.absoluteCap > 0 && (rawShare - a.currentSharePct) > m.absoluteCap) {
        rawShare = a.currentSharePct + m.absoluteCap;
      }
      if (rawShare < 0) rawShare = 0;
      raw.push({ a: a, rawShare: rawShare, action: m.action });
      sumRaw += rawShare;
    }

    var allocations = [];
    var sumAlloc = 0;
    for (var j = 0; j < raw.length; j++) {
      var row = raw[j];
      var normalized = sumRaw > 0 ? (row.rawShare / sumRaw) * totalBudgetPct : 0;
      var rounded = _round(normalized, 1);
      sumAlloc += rounded;
      allocations.push({
        typeId: row.a.id,
        kind: row.a.kind,
        currentPct: row.a.currentSharePct,
        recommendedPct: rounded,
        deltaPct: _round(rounded - row.a.currentSharePct, 1),
        action: row.action,
      });
    }
    // Deterministic last-bucket adjust to make sum exact.
    if (allocations.length > 0) {
      var drift = _round(totalBudgetPct - sumAlloc, 1);
      // Apply drift to the largest non-zero allocation deterministically (highest recommendedPct, then typeId tiebreak).
      var idx = -1;
      var bestVal = -1;
      var bestKey = null;
      for (var p = 0; p < allocations.length; p++) {
        var v = allocations[p].recommendedPct;
        var keyCmp = allocations[p].typeId;
        if (v > bestVal || (v === bestVal && (bestKey === null || keyCmp < bestKey))) {
          bestVal = v;
          bestKey = keyCmp;
          idx = p;
        }
      }
      if (idx >= 0) {
        allocations[idx].recommendedPct = _round(allocations[idx].recommendedPct + drift, 1);
        allocations[idx].deltaPct = _round(allocations[idx].recommendedPct - allocations[idx].currentPct, 1);
      }
    }

    var rationale = "Allocated " + totalBudgetPct + "% across " + allocations.length + " types using verdict-driven multipliers (RETIRE->0, REDUCE x0.5, REWORK x0.7, MONITOR x0.9, KEEP x1.0, SCALE_UP x1.5 +20pct cap), renormalized proportionally.";

    return { allocations: allocations, rationale: rationale };
  }

  // ---- Renderers ----------------------------------------------------------

  function _stableStringify(obj) {
    return JSON.stringify(obj, function (key, value) {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        var keys = Object.keys(value).sort();
        var out = {};
        for (var i = 0; i < keys.length; i++) out[keys[i]] = value[keys[i]];
        return out;
      }
      return value;
    }, 2);
  }

  function formatJson(report) {
    return _stableStringify(report);
  }

  function formatText(report) {
    var lines = [];
    lines.push("CaptchaTypeMixOptimizer - band=" + report.band + " grade=" + report.grade + " (" + report.summary.totalTypes + " types, risk=" + report.summary.portfolioRisk + ")");
    lines.push("");
    lines.push("Per-type:");
    for (var i = 0; i < report.perType.length; i++) {
      var a = report.perType[i];
      lines.push("  - " + a.id + " (" + a.kind + ") share=" + a.currentSharePct + "% eff=" + a.effectiveness + " bot=" + a.botPassRate + " a11y=" + a.accessibilityScore + " verdict=" + a.verdict + " [" + a.priority + "]");
    }
    lines.push("");
    lines.push("Playbook:");
    for (var j = 0; j < report.playbook.length; j++) {
      var p = report.playbook[j];
      lines.push("  [" + p.priority + "] " + p.code + " - " + p.label + " (owner=" + p.owner + ", blast=" + p.blastRadius + ", rev=" + p.reversibility + ")");
    }
    lines.push("");
    lines.push("Insights:");
    for (var k = 0; k < report.insights.length; k++) {
      lines.push("  * " + report.insights[k].code + ": " + report.insights[k].message);
    }
    return lines.join("\n");
  }

  function formatMarkdown(report) {
    var lines = [];
    lines.push("## Headline");
    lines.push("");
    lines.push("Band **" + report.band + "**, grade **" + report.grade + "**, risk " + report.summary.portfolioRisk + ", diversity " + report.summary.diversityScore + ".");
    lines.push("");
    lines.push("## Per-type");
    lines.push("");
    lines.push("| id | kind | share% | eff | bot | a11y | abandon | verdict | priority |");
    lines.push("|----|------|--------|-----|-----|------|---------|---------|----------|");
    for (var i = 0; i < report.perType.length; i++) {
      var a = report.perType[i];
      lines.push("| " + a.id + " | " + a.kind + " | " + a.currentSharePct + " | " + a.effectiveness + " | " + a.botPassRate + " | " + a.accessibilityScore + " | " + a.abandonRate + " | " + a.verdict + " | " + a.priority + " |");
    }
    lines.push("");
    lines.push("## Playbook");
    lines.push("");
    lines.push("| priority | code | label | owner | blast | rev |");
    lines.push("|----------|------|-------|-------|-------|-----|");
    for (var j = 0; j < report.playbook.length; j++) {
      var p = report.playbook[j];
      lines.push("| " + p.priority + " | " + p.code + " | " + p.label + " | " + p.owner + " | " + p.blastRadius + " | " + p.reversibility + " |");
    }
    lines.push("");
    lines.push("## Insights");
    lines.push("");
    for (var k = 0; k < report.insights.length; k++) {
      lines.push("- **" + report.insights[k].code + "** (" + report.insights[k].severity + "): " + report.insights[k].message);
    }
    return lines.join("\n");
  }

  return {
    analyze: analyze,
    recommendMix: recommendMix,
    formatText: formatText,
    formatMarkdown: formatMarkdown,
    formatJson: formatJson,
  };
}

module.exports = {
  createCaptchaTypeMixOptimizer: createCaptchaTypeMixOptimizer,
};
