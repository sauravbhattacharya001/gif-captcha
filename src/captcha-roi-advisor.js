"use strict";

/**
 * CaptchaROIAdvisor — Agentic cost-effectiveness advisor for gif-captcha.
 *
 * Seventh sibling in the gif-captcha agentic family (alongside attack-response-playbook,
 * attack-forecaster, user-abandonment-forecaster, false-reject-recovery-advisor,
 * human-verification-confidence-auditor, and honeypot-effectiveness-advisor).
 *
 * Analyzes per-challenge-type ROI by correlating security outcomes (bot block rate,
 * false positive rate) against costs (compute time, bandwidth, user drop-off rate,
 * support tickets) and recommends budget/resource allocation adjustments.
 *
 * Pure JS, zero deps, deterministic given inputs + risk_appetite + now.
 * Never mutates inputs (deep-copies into work arrays).
 *
 * Public API:
 *   createCaptchaROIAdvisor() => {
 *     analyze({ challengeTypes, portfolio? }, { risk_appetite?, now? }) -> report,
 *     simulate(report, { applyTop }) -> projection,
 *     formatText(report), formatMarkdown(report), formatJson(report)
 *   }
 *
 * @module captcha-roi-advisor
 */

var DEFAULT_RISK = "balanced";
var VALID_RISKS = { cautious: 1.15, balanced: 1.0, aggressive: 0.85 };

// ── Verdicts ──────────────────────────────────────────────────────────────────
var VERDICTS = {
  HIGH_ROI: "HIGH_ROI",
  POSITIVE_ROI: "POSITIVE_ROI",
  MARGINAL: "MARGINAL",
  NEGATIVE_ROI: "NEGATIVE_ROI",
  COST_SINK: "COST_SINK",
  INSUFFICIENT_DATA: "INSUFFICIENT_DATA"
};

// ── Priorities ────────────────────────────────────────────────────────────────
var PRIORITIES = { P0: 0, P1: 1, P2: 2, P3: 3 };

// ── Reason Codes ──────────────────────────────────────────────────────────────
var REASONS = {
  HIGH_BLOCK_LOW_COST: "HIGH_BLOCK_LOW_COST",
  GOOD_SECURITY_MODERATE_COST: "GOOD_SECURITY_MODERATE_COST",
  HIGH_FALSE_POSITIVE: "HIGH_FALSE_POSITIVE",
  HIGH_DROPOFF: "HIGH_DROPOFF",
  LOW_BLOCK_RATE: "LOW_BLOCK_RATE",
  EXCESSIVE_COMPUTE: "EXCESSIVE_COMPUTE",
  HIGH_SUPPORT_COST: "HIGH_SUPPORT_COST",
  BANDWIDTH_HEAVY: "BANDWIDTH_HEAVY",
  LOW_VOLUME: "LOW_VOLUME",
  MISSING_METRICS: "MISSING_METRICS"
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function _clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }

function _deepCopy(arr) {
  return JSON.parse(JSON.stringify(arr));
}

function _sortedJson(obj) {
  return JSON.stringify(obj, function (key, value) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      var sorted = {};
      Object.keys(value).sort().forEach(function (k) { sorted[k] = value[k]; });
      return sorted;
    }
    return value;
  }, 2);
}

// ── Scoring ───────────────────────────────────────────────────────────────────

function _computeROIScore(ct) {
  // Security benefit score 0-100
  var blockBenefit = (ct.botBlockRate || 0) * 60; // max 60
  var fpPenalty = (ct.falsePositiveRate || 0) * 40; // max ~40 at 100% fp
  var securityScore = _clamp(blockBenefit - fpPenalty, 0, 100);

  // Cost score 0-100 (lower cost = higher score)
  var computePenalty = _clamp((ct.avgComputeMs || 0) / 50, 0, 30); // 50ms per point, cap 30
  var bandwidthPenalty = _clamp((ct.avgBandwidthKb || 0) / 100, 0, 20); // 100kb per point, cap 20
  var dropoffPenalty = (ct.userDropoffRate || 0) * 30; // max 30
  var supportPenalty = _clamp((ct.supportTicketsPerK || 0) / 2, 0, 20); // 2 tickets/k per point, cap 20
  var costScore = _clamp(100 - computePenalty - bandwidthPenalty - dropoffPenalty - supportPenalty, 0, 100);

  // Combined ROI = weighted blend
  var roi = securityScore * 0.6 + costScore * 0.4;
  return { roi: roi, securityScore: securityScore, costScore: costScore };
}

function _assignVerdict(roi, appetiteMult) {
  var adjusted = roi * (2 - appetiteMult); // cautious lowers threshold (easier to flag), aggressive raises
  if (adjusted >= 70) return VERDICTS.HIGH_ROI;
  if (adjusted >= 55) return VERDICTS.POSITIVE_ROI;
  if (adjusted >= 40) return VERDICTS.MARGINAL;
  if (adjusted >= 20) return VERDICTS.NEGATIVE_ROI;
  return VERDICTS.COST_SINK;
}

function _assignPriority(verdict) {
  switch (verdict) {
    case VERDICTS.COST_SINK: return PRIORITIES.P0;
    case VERDICTS.NEGATIVE_ROI: return PRIORITIES.P1;
    case VERDICTS.MARGINAL: return PRIORITIES.P2;
    case VERDICTS.INSUFFICIENT_DATA: return PRIORITIES.P2;
    default: return PRIORITIES.P3;
  }
}

function _collectReasons(ct, scores) {
  var reasons = [];
  if (ct.botBlockRate >= 0.8 && scores.costScore >= 70) reasons.push(REASONS.HIGH_BLOCK_LOW_COST);
  if (ct.botBlockRate >= 0.6 && scores.costScore >= 40 && scores.costScore < 70) reasons.push(REASONS.GOOD_SECURITY_MODERATE_COST);
  if ((ct.falsePositiveRate || 0) >= 0.10) reasons.push(REASONS.HIGH_FALSE_POSITIVE);
  if ((ct.userDropoffRate || 0) >= 0.20) reasons.push(REASONS.HIGH_DROPOFF);
  if ((ct.botBlockRate || 0) < 0.40) reasons.push(REASONS.LOW_BLOCK_RATE);
  if ((ct.avgComputeMs || 0) >= 1000) reasons.push(REASONS.EXCESSIVE_COMPUTE);
  if ((ct.supportTicketsPerK || 0) >= 5) reasons.push(REASONS.HIGH_SUPPORT_COST);
  if ((ct.avgBandwidthKb || 0) >= 1500) reasons.push(REASONS.BANDWIDTH_HEAVY);
  if ((ct.servedCount || 0) < 100) reasons.push(REASONS.LOW_VOLUME);
  return reasons;
}

// ── Playbook ──────────────────────────────────────────────────────────────────

function _buildPlaybook(findings, appetite) {
  var actions = [];
  var seen = {};

  var costSinks = findings.filter(function (f) { return f.verdict === VERDICTS.COST_SINK; });
  var negatives = findings.filter(function (f) { return f.verdict === VERDICTS.NEGATIVE_ROI; });
  var marginals = findings.filter(function (f) { return f.verdict === VERDICTS.MARGINAL; });
  var highFP = findings.filter(function (f) { return f.reasons.indexOf(REASONS.HIGH_FALSE_POSITIVE) >= 0; });
  var highDropoff = findings.filter(function (f) { return f.reasons.indexOf(REASONS.HIGH_DROPOFF) >= 0; });
  var heavyCompute = findings.filter(function (f) { return f.reasons.indexOf(REASONS.EXCESSIVE_COMPUTE) >= 0; });
  var lowBlock = findings.filter(function (f) { return f.reasons.indexOf(REASONS.LOW_BLOCK_RATE) >= 0; });

  function _add(id, priority, label, reason, owner, blastRadius, reversibility, relatedIds) {
    if (seen[id]) return;
    seen[id] = true;
    actions.push({
      id: id,
      priority: priority,
      label: label,
      reason: reason,
      owner: owner,
      blastRadius: blastRadius,
      reversibility: reversibility,
      relatedChallengeTypes: relatedIds || []
    });
  }

  if (costSinks.length >= 1) {
    _add("RETIRE_COST_SINK_CHALLENGES", PRIORITIES.P0,
      "Retire cost-sink challenge types",
      "Challenge types with negative security ROI consuming resources without blocking bots",
      "security_ops", 4, "medium",
      costSinks.map(function (f) { return f.id; }));
  }

  if (highFP.length >= 2) {
    _add("INVESTIGATE_FALSE_POSITIVE_CLUSTER", PRIORITIES.P0,
      "Investigate high false-positive cluster",
      "Multiple challenge types rejecting legitimate users at elevated rates",
      "product", 3, "high",
      highFP.map(function (f) { return f.id; }));
  }

  if (lowBlock.length >= 2) {
    _add("AUDIT_INEFFECTIVE_CHALLENGES", PRIORITIES.P0,
      "Audit ineffective challenge types",
      "Multiple challenge types failing to block bots adequately",
      "security_ops", 4, "medium",
      lowBlock.map(function (f) { return f.id; }));
  }

  if (negatives.length >= 1) {
    _add("REDESIGN_NEGATIVE_ROI_CHALLENGES", PRIORITIES.P1,
      "Redesign or replace negative-ROI challenges",
      "Challenge types where costs outweigh security benefits",
      "engineering", 3, "medium",
      negatives.map(function (f) { return f.id; }));
  }

  if (heavyCompute.length >= 1) {
    _add("OPTIMIZE_COMPUTE_HEAVY_CHALLENGES", PRIORITIES.P1,
      "Optimize compute-heavy challenge generation",
      "Challenge types using excessive server resources for generation",
      "engineering", 2, "high",
      heavyCompute.map(function (f) { return f.id; }));
  }

  if (highDropoff.length >= 1) {
    _add("REDUCE_USER_FRICTION", PRIORITIES.P1,
      "Reduce user friction on high-dropoff challenges",
      "Challenge types causing significant user abandonment",
      "product", 3, "high",
      highDropoff.map(function (f) { return f.id; }));
  }

  if (marginals.length >= 2) {
    _add("CONSOLIDATE_MARGINAL_CHALLENGES", PRIORITIES.P2,
      "Consolidate or improve marginal-ROI challenges",
      "Multiple challenge types operating near break-even — consolidate to reduce operational surface",
      "security_ops", 2, "high",
      marginals.map(function (f) { return f.id; }));
  }

  if (appetite === "cautious") {
    var grade = _portfolioGrade(findings);
    if (grade === "C" || grade === "D" || grade === "F") {
      _add("SCHEDULE_ROI_AUDIT", PRIORITIES.P2,
        "Schedule comprehensive ROI audit",
        "Portfolio health below threshold — recommend formal cost-benefit review",
        "ops", 1, "high", []);
    }
  }

  if (actions.length === 0 || (appetite !== "aggressive" && !seen["PORTFOLIO_HEALTHY"])) {
    _add("PORTFOLIO_HEALTHY", PRIORITIES.P3,
      "Maintain current challenge portfolio",
      "ROI across challenge types is acceptable",
      "ops", 1, "high", []);
  }

  // Aggressive trims P3 when P0/P1 present
  if (appetite === "aggressive") {
    var hasHighPriority = actions.some(function (a) { return a.priority <= PRIORITIES.P1; });
    if (hasHighPriority) {
      actions = actions.filter(function (a) { return a.priority <= PRIORITIES.P2; });
    }
  }

  actions.sort(function (a, b) {
    if (a.priority !== b.priority) return a.priority - b.priority;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

  return actions;
}

// ── Insights ──────────────────────────────────────────────────────────────────

function _deriveInsights(findings, portfolio) {
  var insights = [];
  var costSinks = findings.filter(function (f) { return f.verdict === VERDICTS.COST_SINK; }).length;
  var highROI = findings.filter(function (f) { return f.verdict === VERDICTS.HIGH_ROI; }).length;
  var negatives = findings.filter(function (f) { return f.verdict === VERDICTS.NEGATIVE_ROI; }).length;
  var highFP = findings.filter(function (f) { return f.reasons.indexOf(REASONS.HIGH_FALSE_POSITIVE) >= 0; }).length;

  if (costSinks >= 2) insights.push("COST_SINK_CLUSTER");
  if (negatives + costSinks >= findings.length * 0.5 && findings.length >= 3) insights.push("PORTFOLIO_INEFFICIENT");
  if (highFP >= 3) insights.push("FALSE_POSITIVE_EPIDEMIC");
  if (highROI >= findings.length * 0.7 && findings.length >= 3) insights.push("STRONG_PORTFOLIO");
  if (portfolio.totalCostPerK > 500) insights.push("HIGH_AGGREGATE_COST");
  if (portfolio.meanBlockRate < 0.5) insights.push("LOW_OVERALL_SECURITY");
  if (portfolio.meanBlockRate >= 0.8 && portfolio.meanFPRate < 0.05) insights.push("EXCELLENT_SECURITY_POSTURE");

  if (insights.length === 0) insights.push("BALANCED_PORTFOLIO");
  return insights;
}

// ── Grade ─────────────────────────────────────────────────────────────────────

function _portfolioGrade(findings) {
  if (findings.length === 0) return "A";
  var costSinks = findings.filter(function (f) { return f.verdict === VERDICTS.COST_SINK; }).length;
  var negatives = findings.filter(function (f) { return f.verdict === VERDICTS.NEGATIVE_ROI; }).length;
  var meanROI = findings.reduce(function (s, f) { return s + f.roiScore; }, 0) / findings.length;

  if (costSinks >= 2 || meanROI < 25) return "F";
  if (costSinks >= 1 || negatives >= 2 || meanROI < 40) return "D";
  if (negatives >= 1 || meanROI < 55) return "C";
  if (meanROI < 70) return "B";
  return "A";
}

// ── Portfolio Metrics ─────────────────────────────────────────────────────────

function _portfolioMetrics(findings) {
  if (findings.length === 0) {
    return { totalCostPerK: 0, meanBlockRate: 0, meanFPRate: 0, meanROI: 0, count: 0 };
  }
  var totalCost = 0;
  var totalBlock = 0;
  var totalFP = 0;
  var totalROI = 0;
  findings.forEach(function (f) {
    totalCost += f.costPerK || 0;
    totalBlock += f.botBlockRate || 0;
    totalFP += f.falsePositiveRate || 0;
    totalROI += f.roiScore;
  });
  return {
    totalCostPerK: totalCost,
    meanBlockRate: totalBlock / findings.length,
    meanFPRate: totalFP / findings.length,
    meanROI: totalROI / findings.length,
    count: findings.length
  };
}

// ── Simulate ──────────────────────────────────────────────────────────────────

function _simulate(report, opts) {
  var applyTop = (opts && opts.applyTop) || 3;
  var actions = report.playbook.slice(0, applyTop);
  var currentScore = report.portfolioScore;
  var lift = 0;
  for (var i = 0; i < actions.length; i++) {
    var weight = actions[i].priority === PRIORITIES.P0 ? 12
      : actions[i].priority === PRIORITIES.P1 ? 7
      : actions[i].priority === PRIORITIES.P2 ? 3 : 1;
    lift += weight * Math.pow(0.85, i);
  }
  var projected = _clamp(currentScore + lift, 0, 100);
  return {
    currentScore: currentScore,
    projectedScore: projected,
    lift: projected - currentScore,
    actionsApplied: actions.length
  };
}

// ── Renderers ─────────────────────────────────────────────────────────────────

function _formatText(report) {
  var lines = [];
  lines.push("CAPTCHA ROI ADVISOR — grade=" + report.grade + " score=" +
    report.portfolioScore.toFixed(1) + " P0=" +
    report.playbook.filter(function (a) { return a.priority === 0; }).length +
    " P1=" + report.playbook.filter(function (a) { return a.priority === 1; }).length);
  lines.push("");
  report.findings.forEach(function (f) {
    lines.push("  [" + f.verdict + "] " + f.id + " — ROI=" + f.roiScore.toFixed(1) +
      " security=" + f.securityScore.toFixed(1) + " cost=" + f.costScore.toFixed(1));
  });
  lines.push("");
  lines.push("Playbook:");
  report.playbook.forEach(function (a) {
    lines.push("  P" + a.priority + " " + a.label);
  });
  lines.push("");
  lines.push("Insights: " + report.insights.join(", "));
  return lines.join("\n");
}

function _formatMarkdown(report) {
  var lines = [];
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|--------|-------|");
  lines.push("| Grade | " + report.grade + " |");
  lines.push("| Portfolio Score | " + report.portfolioScore.toFixed(1) + " |");
  lines.push("| Challenge Types | " + report.findings.length + " |");
  lines.push("| Mean Block Rate | " + (report.portfolio.meanBlockRate * 100).toFixed(1) + "% |");
  lines.push("| Mean FP Rate | " + (report.portfolio.meanFPRate * 100).toFixed(1) + "% |");
  lines.push("");
  lines.push("## Challenge Types");
  lines.push("");
  lines.push("| ID | Verdict | ROI | Security | Cost | Priority |");
  lines.push("|----|---------|-----|----------|------|----------|");
  report.findings.forEach(function (f) {
    lines.push("| " + f.id + " | " + f.verdict + " | " + f.roiScore.toFixed(1) +
      " | " + f.securityScore.toFixed(1) + " | " + f.costScore.toFixed(1) +
      " | P" + f.priority + " |");
  });
  lines.push("");
  lines.push("## Playbook");
  lines.push("");
  lines.push("| Priority | Action | Owner | Blast |");
  lines.push("|----------|--------|-------|-------|");
  report.playbook.forEach(function (a) {
    lines.push("| P" + a.priority + " | " + a.label + " | " + a.owner + " | " + a.blastRadius + " |");
  });
  lines.push("");
  lines.push("## Insights");
  lines.push("");
  report.insights.forEach(function (ins) {
    lines.push("- " + ins);
  });
  return lines.join("\n");
}

function _formatJson(report) {
  return _sortedJson(report);
}

// ── Main Factory ──────────────────────────────────────────────────────────────

function createCaptchaROIAdvisor() {

  function analyze(input, options) {
    var opts = options || {};
    var appetite = opts.risk_appetite || DEFAULT_RISK;
    if (!VALID_RISKS[appetite]) throw new Error("Invalid risk_appetite: " + appetite);
    var appetiteMult = VALID_RISKS[appetite];
    var nowFn = opts.now || function () { return Date.now(); };
    var ts = typeof nowFn === "function" ? nowFn() : nowFn;

    var challengeTypes = _deepCopy((input && input.challengeTypes) || []);

    if (challengeTypes.length === 0) {
      return {
        findings: [],
        playbook: [{ id: "NO_DATA", priority: PRIORITIES.P3, label: "No challenge data provided", reason: "Empty input", owner: "ops", blastRadius: 1, reversibility: "high", relatedChallengeTypes: [] }],
        insights: ["NO_DATA_PROVIDED"],
        portfolio: { totalCostPerK: 0, meanBlockRate: 0, meanFPRate: 0, meanROI: 0, count: 0 },
        portfolioScore: 100,
        grade: "A",
        timestamp: ts
      };
    }

    var findings = [];
    challengeTypes.forEach(function (ct) {
      if (!ct.id) return;

      // Check for insufficient data
      if ((ct.servedCount || 0) < 50 || ct.botBlockRate == null) {
        findings.push({
          id: ct.id,
          verdict: VERDICTS.INSUFFICIENT_DATA,
          roiScore: 50,
          securityScore: 50,
          costScore: 50,
          costPerK: 0,
          botBlockRate: ct.botBlockRate || 0,
          falsePositiveRate: ct.falsePositiveRate || 0,
          priority: PRIORITIES.P2,
          reasons: [REASONS.MISSING_METRICS]
        });
        return;
      }

      var scores = _computeROIScore(ct);
      var verdict = _assignVerdict(scores.roi, appetiteMult);
      var priority = _assignPriority(verdict);
      var reasons = _collectReasons(ct, scores);

      // Compute cost-per-thousand metric
      var costPerK = ((ct.avgComputeMs || 0) * 0.01) + ((ct.avgBandwidthKb || 0) * 0.005) +
        ((ct.supportTicketsPerK || 0) * 10) + ((ct.userDropoffRate || 0) * 50);

      findings.push({
        id: ct.id,
        verdict: verdict,
        roiScore: Math.round(scores.roi * 10) / 10,
        securityScore: Math.round(scores.securityScore * 10) / 10,
        costScore: Math.round(scores.costScore * 10) / 10,
        costPerK: Math.round(costPerK * 10) / 10,
        botBlockRate: ct.botBlockRate || 0,
        falsePositiveRate: ct.falsePositiveRate || 0,
        priority: priority,
        reasons: reasons
      });
    });

    // Sort: priority asc, roiScore asc, id asc
    findings.sort(function (a, b) {
      if (a.priority !== b.priority) return a.priority - b.priority;
      if (a.roiScore !== b.roiScore) return a.roiScore - b.roiScore;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });

    var portfolio = _portfolioMetrics(findings);
    var grade = _portfolioGrade(findings);
    var playbook = _buildPlaybook(findings, appetite);
    var insights = _deriveInsights(findings, portfolio);
    var portfolioScore = portfolio.meanROI;

    return {
      findings: findings,
      playbook: playbook,
      insights: insights,
      portfolio: portfolio,
      portfolioScore: Math.round(portfolioScore * 10) / 10,
      grade: grade,
      timestamp: ts
    };
  }

  function simulate(report, opts) {
    return _simulate(report, opts);
  }

  function formatText(report) { return _formatText(report); }
  function formatMarkdown(report) { return _formatMarkdown(report); }
  function formatJson(report) { return _formatJson(report); }

  return {
    analyze: analyze,
    simulate: simulate,
    formatText: formatText,
    formatMarkdown: formatMarkdown,
    formatJson: formatJson
  };
}

module.exports = { createCaptchaROIAdvisor: createCaptchaROIAdvisor };
