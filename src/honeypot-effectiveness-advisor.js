"use strict";

/**
 * HoneypotEffectivenessAdvisor - Agentic per-honeypot triage + portfolio playbook.
 *
 * Sixth sibling in the gif-captcha agentic family (alongside attack-response-playbook,
 * attack-forecaster, user-abandonment-forecaster, false-reject-recovery-advisor, and
 * human-verification-confidence-auditor).
 *
 * Given the telemetry of deployed honeypot traps (invisible fields, fake submit
 * buttons, fake CAPTCHA challenges, timing traps, geo decoys, JS-execution traps,
 * mouse traps), it classifies each honeypot and produces a portfolio-level
 * playbook describing which traps to keep, rotate, redesign, or retire.
 *
 * Pure JS, zero deps, deterministic given inputs + risk_appetite + now.
 * Never mutates inputs (deep-copies into work arrays).
 *
 * Public API:
 *   createHoneypotEffectivenessAdvisor() => {
 *     analyze({ honeypots, defaults? }, { risk_appetite?, now? }) -> report,
 *     simulate(report, { applyTop }) -> projection,
 *     formatText(report), formatMarkdown(report), formatJson(report)
 *   }
 *
 * @module honeypot-effectiveness-advisor
 */

var DEFAULT_RISK = "balanced";
var VALID_RISKS = { cautious: 0.92, balanced: 1.0, aggressive: 1.08 };

var BAND_CUTOFFS = { CALM: 0.10, WATCH: 0.20, ELEVATED: 0.35, HIGH: 0.50 };

var DEFAULTS = {
  minImpressionsForVerdict: 50,
  falsePositiveCeiling: 0.02,
  decayDays: 30,
};

var VALID_TYPES = {
  invisible_field: 1,
  fake_submit: 1,
  fake_challenge: 1,
  timing_trap: 1,
  geo_decoy: 1,
  js_execution_trap: 1,
  mouse_trap: 1,
  other: 1,
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
  if (v instanceof Date) return v.toISOString();
  var out = {};
  Object.keys(v).forEach(function (k) { out[k] = _deepCopy(v[k]); });
  return out;
}

function _normType(t) {
  if (typeof t === "string" && VALID_TYPES[t]) return t;
  return "other";
}

function _toEpochMs(v) {
  if (v == null) return null;
  if (typeof v === "number" && isFinite(v)) return v;
  if (typeof v === "string") {
    var n = Date.parse(v);
    if (!isNaN(n)) return n;
  }
  if (v instanceof Date) return v.getTime();
  return null;
}

function _ageDays(deployedAt, now) {
  var dep = _toEpochMs(deployedAt);
  if (dep == null) return 0;
  var ms = Math.max(0, now - dep);
  return +Number(ms / (1000 * 60 * 60 * 24)).toFixed(2);
}

function _mergeDefaults(input) {
  var d = {};
  Object.keys(DEFAULTS).forEach(function (k) { d[k] = DEFAULTS[k]; });
  if (input && typeof input === "object") {
    Object.keys(DEFAULTS).forEach(function (k) {
      var v = _num(input[k], null);
      if (v != null && v > 0) d[k] = v;
    });
  }
  return d;
}

// ---------------------------------------------------------------------------
// Per-honeypot scoring + verdict
// ---------------------------------------------------------------------------

function _rates(h) {
  var imp = Math.max(0, _num(h.totalImpressions, 0));
  var bot = Math.max(0, _num(h.botHits, 0));
  var confirmed = Math.max(0, _num(h.confirmedBotHits, 0));
  var human = Math.max(0, _num(h.humanHits, 0));
  var botCatchRate = imp > 0 ? bot / imp : 0;
  var falsePositiveRate = imp > 0 ? human / imp : 0;
  var confirmedBotRate = bot > 0 ? confirmed / bot : 0;
  var confirmedBotShare = imp > 0 ? confirmed / imp : 0;
  return {
    impressions: imp,
    botHits: bot,
    confirmedBotHits: confirmed,
    humanHits: human,
    botCatchRate: botCatchRate,
    falsePositiveRate: falsePositiveRate,
    confirmedBotRate: confirmedBotRate,
    confirmedBotShare: confirmedBotShare,
  };
}

function _scoreHoneypot(h, rates, ageDays, riskMult, defaults) {
  var reasons = [];

  var baseCatch = rates.botCatchRate * 100;
  var fpPenalty = rates.falsePositiveRate * 200;
  var confirmedBonus = rates.confirmedBotShare * 20;

  var decayPenalty = 0;
  var trend = _num(h.recentTrend, null);
  if (trend != null && trend < 1) {
    // trend < 1 means slowing down; trend of 0.4 -> heavy decay
    decayPenalty = (1 - _clamp(trend, 0, 1)) * 30;
  }
  if (ageDays >= defaults.decayDays && rates.botCatchRate < 0.05) {
    decayPenalty += 15;
  }

  var diversityBonus = 0;
  var uniqIPs = _num(h.uniqueIPs, 0);
  var uniqUA = _num(h.uniqueUserAgents, 0);
  if (rates.botHits > 0) {
    var ipDiv = uniqIPs / rates.botHits;
    var uaDiv = uniqUA / rates.botHits;
    var avgDiv = (_clamp(ipDiv, 0, 1) + _clamp(uaDiv, 0, 1)) / 2;
    diversityBonus = avgDiv * 10;
  }

  var raw = baseCatch - fpPenalty + confirmedBonus - decayPenalty + diversityBonus;
  var score = _clamp(raw * riskMult, 0, 100);

  if (rates.botCatchRate >= 0.30) {
    reasons.push({ code: "HIGH_CATCH_RATE", label: "Bot catch rate >= 30%", weight: +baseCatch.toFixed(2) });
  } else if (rates.botCatchRate >= 0.10) {
    reasons.push({ code: "HIGH_CATCH_RATE", label: "Bot catch rate >= 10%", weight: +baseCatch.toFixed(2) });
  } else if (rates.impressions >= defaults.minImpressionsForVerdict) {
    reasons.push({ code: "LOW_CATCH_RATE", label: "Bot catch rate below threshold", weight: -10 });
  }
  if (rates.confirmedBotRate >= 0.5 && rates.botHits >= 10) {
    reasons.push({ code: "HIGH_CONFIRMED_BOT_RATE", label: "Most bot hits later confirmed bot", weight: +confirmedBonus.toFixed(2) });
  }
  if (rates.falsePositiveRate > defaults.falsePositiveCeiling) {
    reasons.push({ code: "RISING_FALSE_POSITIVES", label: "False-positive rate above ceiling", weight: -Number(fpPenalty.toFixed(2)) });
  }
  if (h.isAccessibilityRisk && rates.humanHits > 0) {
    reasons.push({ code: "ACCESSIBILITY_RISK", label: "Accessibility-risky trap caught humans", weight: -25 });
  }
  if (rates.botHits >= 20 && uniqIPs > 0 && (uniqIPs / rates.botHits) < 0.10) {
    reasons.push({ code: "FINGERPRINTED_BY_BOTS", label: "Very few unique IPs vs hits - bots learned the trap", weight: -20 });
  }
  if (decayPenalty > 0) {
    reasons.push({ code: "DECAY_DETECTED", label: "Catch rate decay / falling recent trend", weight: -Number(decayPenalty.toFixed(2)) });
  }
  if (rates.botCatchRate > 0.80 && uniqUA > 0 && uniqUA <= 2) {
    reasons.push({ code: "NARROW_ATTACKER_BASE", label: "High catch rate but only 1-2 user agents", weight: -5 });
  }
  var lastHit = _toEpochMs(h.lastTrippedAt);
  if (lastHit != null && ageDays >= defaults.decayDays && rates.botCatchRate < 0.01) {
    reasons.push({ code: "STALE_NO_RECENT_HITS", label: "Stale honeypot with negligible recent traffic", weight: -8 });
  }
  if (rates.impressions < defaults.minImpressionsForVerdict) {
    reasons.push({ code: "INSUFFICIENT_SAMPLE", label: "Below minimum impressions for verdict", weight: 0 });
  }

  reasons.sort(function (a, b) {
    var ax = Math.abs(b.weight) - Math.abs(a.weight);
    if (ax !== 0) return ax;
    return a.code < b.code ? -1 : a.code > b.code ? 1 : 0;
  });

  return { score: +Number(score).toFixed(2), reasons: reasons };
}

function _verdictFor(h, rates, ageDays, defaults) {
  var humanRate = rates.falsePositiveRate;
  var hasEnoughImpressions = rates.impressions >= defaults.minImpressionsForVerdict;

  if ((h.isAccessibilityRisk && rates.humanHits > 0) || humanRate > defaults.falsePositiveCeiling) {
    return "DISABLE_FALSE_POSITIVE_RISK";
  }
  if (rates.botHits >= 20 && _num(h.uniqueIPs, 0) > 0 && (_num(h.uniqueIPs, 0) / rates.botHits) < 0.10) {
    return "BLOCK_REVERSE_FINGERPRINT";
  }
  if (rates.botCatchRate > 0.80 && _num(h.uniqueUserAgents, 0) > 0 && _num(h.uniqueUserAgents, 0) <= 2 && rates.botHits >= 10) {
    return "INVESTIGATE_ANOMALY";
  }
  if (!hasEnoughImpressions) {
    return "INSUFFICIENT_DATA";
  }
  var trend = _num(h.recentTrend, null);
  if (rates.botCatchRate < 0.01 && ageDays >= defaults.decayDays) {
    return "RETIRE_LOW_VALUE";
  }
  if ((trend != null && trend < 0.5) ||
      (ageDays >= defaults.decayDays && rates.botCatchRate < 0.05 && rates.botCatchRate > 0)) {
    return "ROTATE_OR_REDESIGN";
  }
  if (rates.botCatchRate >= 0.30 && rates.confirmedBotRate >= 0.50) {
    return "KEEP_HIGH_PERFORMER";
  }
  if (rates.botCatchRate >= 0.10 && humanRate <= defaults.falsePositiveCeiling) {
    return "KEEP_PERFORMING";
  }
  if (rates.botCatchRate < 0.01) {
    return "RETIRE_LOW_VALUE";
  }
  return "KEEP_PERFORMING";
}

function _priorityFor(verdict) {
  switch (verdict) {
    case "DISABLE_FALSE_POSITIVE_RISK": return "P0";
    case "BLOCK_REVERSE_FINGERPRINT": return "P1";
    case "INVESTIGATE_ANOMALY": return "P1";
    case "ROTATE_OR_REDESIGN": return "P2";
    case "RETIRE_LOW_VALUE": return "P2";
    case "KEEP_PERFORMING": return "P3";
    case "KEEP_HIGH_PERFORMER": return "P3";
    case "INSUFFICIENT_DATA": return "P3";
    default: return "P3";
  }
}

function _suggestedActionFor(verdict) {
  switch (verdict) {
    case "DISABLE_FALSE_POSITIVE_RISK": return "Disable immediately; humans (possibly via assistive tech) are tripping it";
    case "BLOCK_REVERSE_FINGERPRINT": return "Rotate the trap shape/name; bots have a signature for it";
    case "INVESTIGATE_ANOMALY": return "Investigate - high catch rate from a narrow attacker base";
    case "ROTATE_OR_REDESIGN": return "Redesign or rotate to a new shape; effectiveness is decaying";
    case "RETIRE_LOW_VALUE": return "Retire to reduce maintenance noise";
    case "KEEP_PERFORMING": return "Keep; performing within tolerance";
    case "KEEP_HIGH_PERFORMER": return "Keep and consider cloning the design across more pages";
    case "INSUFFICIENT_DATA": return "Wait for more impressions before deciding";
    default: return "Standard monitoring";
  }
}

// ---------------------------------------------------------------------------
// Portfolio playbook
// ---------------------------------------------------------------------------

function _buildPlaybook(verdicts, honeypots, defaults, riskAppetite, portfolioRiskScore) {
  var actions = [];
  var byVerdict = {};
  verdicts.forEach(function (v) {
    byVerdict[v.verdict] = byVerdict[v.verdict] || [];
    byVerdict[v.verdict].push(v.id);
  });

  var disableAccess = [];
  var disableFP = [];
  verdicts.forEach(function (v) {
    if (v.verdict === "DISABLE_FALSE_POSITIVE_RISK") {
      var src = honeypots.find(function (h) { return String(h.id) === v.id; });
      if (src && src.isAccessibilityRisk) disableAccess.push(v.id);
      else disableFP.push(v.id);
    }
  });

  if (disableAccess.length > 0) {
    actions.push({
      id: "DISABLE_ACCESSIBILITY_BREAKING_TRAPS",
      priority: "P0",
      label: "Disable accessibility-breaking honeypots",
      reason: "Assistive-tech users can trip these traps; legal and UX risk.",
      owner: "accessibility",
      blastRadius: 5,
      reversibility: "low",
      honeypotIds: disableAccess.slice().sort(),
      estRiskDelta: -22,
    });
  }
  if (disableFP.length > 0) {
    actions.push({
      id: "DISABLE_HIGH_FALSE_POSITIVE_TRAPS",
      priority: "P0",
      label: "Disable high-false-positive honeypots",
      reason: "False-positive rate exceeds the configured ceiling; humans are getting blocked.",
      owner: "ux",
      blastRadius: 4,
      reversibility: "medium",
      honeypotIds: disableFP.slice().sort(),
      estRiskDelta: -18,
    });
  }

  if ((byVerdict.BLOCK_REVERSE_FINGERPRINT || []).length > 0) {
    actions.push({
      id: "ROTATE_FINGERPRINTED_HONEYPOTS",
      priority: "P1",
      label: "Rotate honeypots the bots have fingerprinted",
      reason: "Hits cluster around a tiny set of IPs - the trap is a known signature now.",
      owner: "security",
      blastRadius: 3,
      reversibility: "high",
      honeypotIds: byVerdict.BLOCK_REVERSE_FINGERPRINT.slice().sort(),
      estRiskDelta: -14,
    });
  }
  if ((byVerdict.ROTATE_OR_REDESIGN || []).length > 0) {
    actions.push({
      id: "REDESIGN_DECAYED_TRAPS",
      priority: "P1",
      label: "Redesign or rotate decayed traps",
      reason: "Catch rate or recent trend has collapsed; refresh the trap shape.",
      owner: "security",
      blastRadius: 3,
      reversibility: "high",
      honeypotIds: byVerdict.ROTATE_OR_REDESIGN.slice().sort(),
      estRiskDelta: -10,
    });
  }
  if ((byVerdict.INVESTIGATE_ANOMALY || []).length > 0) {
    actions.push({
      id: "INVESTIGATE_NARROW_ATTACKER",
      priority: "P1",
      label: "Investigate narrow attacker base",
      reason: "One or two user agents are driving most of the catches - likely a single actor.",
      owner: "security",
      blastRadius: 2,
      reversibility: "high",
      honeypotIds: byVerdict.INVESTIGATE_ANOMALY.slice().sort(),
      estRiskDelta: -8,
    });
  }
  if ((byVerdict.RETIRE_LOW_VALUE || []).length > 0) {
    actions.push({
      id: "RETIRE_DEAD_HONEYPOTS",
      priority: "P2",
      label: "Retire dead honeypots to cut maintenance noise",
      reason: "These traps are aged and effectively never catch bots.",
      owner: "platform",
      blastRadius: 1,
      reversibility: "high",
      honeypotIds: byVerdict.RETIRE_LOW_VALUE.slice().sort(),
      estRiskDelta: -3,
    });
  }

  // Diversity: too many of same type AND we are already rotating something
  var typeCounts = {};
  honeypots.forEach(function (h) {
    var t = _normType(h.type);
    typeCounts[t] = (typeCounts[t] || 0) + 1;
  });
  var dominantType = null;
  var dominantCount = 0;
  Object.keys(typeCounts).forEach(function (t) {
    if (typeCounts[t] > dominantCount) {
      dominantCount = typeCounts[t];
      dominantType = t;
    }
  });
  var monoculture = honeypots.length >= 3 && (dominantCount / honeypots.length) >= 0.7;
  if (monoculture && (byVerdict.ROTATE_OR_REDESIGN || byVerdict.BLOCK_REVERSE_FINGERPRINT)) {
    actions.push({
      id: "DIVERSIFY_HONEYPOT_TYPES",
      priority: "P2",
      label: "Diversify honeypot types",
      reason: ">=70% of deployed traps are the same type (" + dominantType + ") - bots only need one bypass.",
      owner: "security",
      blastRadius: 2,
      reversibility: "high",
      honeypotIds: [],
      estRiskDelta: -5,
    });
  }

  var insufficient = (byVerdict.INSUFFICIENT_DATA || []).length;
  if (honeypots.length > 0 && (insufficient / honeypots.length) >= 0.30) {
    actions.push({
      id: "INSTRUMENT_MORE_TELEMETRY",
      priority: "P2",
      label: "Instrument more telemetry on under-sampled honeypots",
      reason: ">=30% of honeypots lack enough impressions to verdict.",
      owner: "platform",
      blastRadius: 1,
      reversibility: "high",
      honeypotIds: (byVerdict.INSUFFICIENT_DATA || []).slice().sort(),
      estRiskDelta: -2,
    });
  }

  if (actions.length === 0) {
    actions.push({
      id: "HEALTHY_PORTFOLIO",
      priority: "P3",
      label: "Honeypot portfolio is healthy; no intervention required",
      reason: "No honeypots tripped any priority verdict.",
      owner: "platform",
      blastRadius: 1,
      reversibility: "high",
      honeypotIds: [],
      estRiskDelta: 0,
    });
  }

  // Risk-appetite-specific tweaks
  if (riskAppetite === "aggressive") {
    var hasHighPrio = actions.some(function (a) { return a.priority === "P0" || a.priority === "P1"; });
    if (hasHighPrio) {
      actions = actions.filter(function (a) {
        if (a.id === "HEALTHY_PORTFOLIO") return false;
        if (a.priority === "P2") {
          var p2Count = actions.filter(function (x) { return x.priority === "P2"; }).length;
          if (p2Count === 1) return false;
        }
        return true;
      });
    }
  }
  if (riskAppetite === "cautious") {
    // Grade is computed downstream; we add a scheduling reminder when portfolioRiskScore is elevated.
    if (portfolioRiskScore >= 30) {
      actions.push({
        id: "SCHEDULE_HONEYPOT_AUDIT",
        priority: "P2",
        label: "Schedule a quarterly honeypot audit",
        reason: "Cautious appetite + elevated portfolio risk - keep humans in the loop.",
        owner: "security",
        blastRadius: 1,
        reversibility: "high",
        honeypotIds: [],
        estRiskDelta: -2,
      });
    }
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

  return deduped;
}

function _portfolioMetrics(honeypotResults) {
  if (!honeypotResults.length) {
    return {
      portfolioBotCatchRate: 0,
      portfolioFalsePositiveRate: 0,
      portfolioConfirmedBotRate: 0,
    };
  }
  var totalImp = 0, totalBot = 0, totalHuman = 0, totalConfirmed = 0;
  honeypotResults.forEach(function (r) {
    totalImp += r._raw.impressions;
    totalBot += r._raw.botHits;
    totalHuman += r._raw.humanHits;
    totalConfirmed += r._raw.confirmedBotHits;
  });
  return {
    portfolioBotCatchRate: totalImp > 0 ? +Number(totalBot / totalImp).toFixed(4) : 0,
    portfolioFalsePositiveRate: totalImp > 0 ? +Number(totalHuman / totalImp).toFixed(4) : 0,
    portfolioConfirmedBotRate: totalBot > 0 ? +Number(totalConfirmed / totalBot).toFixed(4) : 0,
  };
}

function _gradeFor(highRiskShare, hasP0, p0Count, portfolioFpr, defaults, hasAccessibilityFailure) {
  if (hasAccessibilityFailure) return "F";
  if (portfolioFpr > defaults.falsePositiveCeiling * 2) return "F";
  if (p0Count >= 3) return "F";
  if (hasP0) return "D";
  if (highRiskShare >= 0.30) return "D";
  if (highRiskShare >= 0.15) return "C";
  if (highRiskShare >= 0.05) return "B";
  return "A";
}

function _portfolioRiskScore(honeypotResults, portfolioFpr, defaults) {
  if (!honeypotResults.length) return 0;
  var p0 = honeypotResults.filter(function (r) { return r.priority === "P0"; }).length;
  var p1 = honeypotResults.filter(function (r) { return r.priority === "P1"; }).length;
  var total = honeypotResults.length;
  var hr = (p0 + p1) / total;
  var fprOver = Math.max(0, portfolioFpr - defaults.falsePositiveCeiling) / Math.max(0.0001, defaults.falsePositiveCeiling);
  var score = hr * 80 + Math.min(20, fprOver * 20) + p0 * 5;
  return +Number(_clamp(score, 0, 100)).toFixed(2);
}

function _buildInsights(honeypotResults, honeypots, portfolioMetrics) {
  var insights = [];
  var totalHits = honeypotResults.length;

  if (honeypotResults.some(function (r) {
    return r.verdict === "DISABLE_FALSE_POSITIVE_RISK" &&
      honeypots.find(function (h) { return String(h.id) === r.id && h.isAccessibilityRisk; });
  })) {
    insights.push({
      code: "ACCESSIBILITY_GAP_DETECTED",
      label: "At least one honeypot is failing accessibility-affected users",
      detail: "",
    });
  }

  var fingerprinted = honeypotResults.filter(function (r) {
    return r.reasons.some(function (x) { return x.code === "FINGERPRINTED_BY_BOTS"; });
  }).length;
  if (fingerprinted >= 2) {
    insights.push({
      code: "BOTS_LEARNING_HONEYPOTS",
      label: "Multiple honeypots show fingerprinting signatures",
      detail: "count=" + fingerprinted,
    });
  }

  if (honeypots.length >= 3) {
    var typeCounts = {};
    honeypots.forEach(function (h) {
      var t = _normType(h.type);
      typeCounts[t] = (typeCounts[t] || 0) + 1;
    });
    var maxT = null, maxC = 0;
    Object.keys(typeCounts).forEach(function (t) {
      if (typeCounts[t] > maxC) { maxC = typeCounts[t]; maxT = t; }
    });
    if ((maxC / honeypots.length) >= 0.7) {
      insights.push({
        code: "HONEYPOT_TYPE_MONOCULTURE",
        label: ">=70% of honeypots are the same type",
        detail: "type=" + maxT + " ratio=" + (maxC / honeypots.length).toFixed(2),
      });
    }
  }

  if (portfolioMetrics.portfolioBotCatchRate >= 0.20) {
    insights.push({
      code: "HIGH_PORTFOLIO_CATCH_RATE",
      label: "Portfolio bot catch rate is high",
      detail: "rate=" + portfolioMetrics.portfolioBotCatchRate.toFixed(3),
    });
  }

  var dead = honeypotResults.filter(function (r) { return r.verdict === "RETIRE_LOW_VALUE"; }).length;
  if (dead >= 3) {
    insights.push({
      code: "DEAD_HONEYPOT_BACKLOG",
      label: "3+ honeypots are flagged for retirement",
      detail: "count=" + dead,
    });
  }

  var insufficient = honeypotResults.filter(function (r) { return r.verdict === "INSUFFICIENT_DATA"; }).length;
  if (totalHits > 0 && (insufficient / totalHits) >= 0.30) {
    insights.push({
      code: "TELEMETRY_GAP",
      label: ">=30% of honeypots lack enough telemetry to verdict",
      detail: "count=" + insufficient,
    });
  }

  if (insights.length === 0) {
    insights.push({
      code: "HEALTHY_PORTFOLIO",
      label: "Honeypot portfolio is healthy",
      detail: "",
    });
  }

  insights.sort(function (a, b) { return a.code < b.code ? -1 : a.code > b.code ? 1 : 0; });
  return insights;
}

// ---------------------------------------------------------------------------
// Stable JSON serializer (recursive sorted keys, 2-space indent)
// ---------------------------------------------------------------------------

function _stableStringify(value, indent) {
  var pad = indent || 2;
  function s(v, depth) {
    if (v === null) return "null";
    if (typeof v === "number") return isFinite(v) ? String(v) : "null";
    if (typeof v === "boolean") return v ? "true" : "false";
    if (typeof v === "string") return JSON.stringify(v);
    if (typeof v === "undefined") return "null";
    if (v instanceof Date) return JSON.stringify(v.toISOString());
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

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

function createHoneypotEffectivenessAdvisor() {
  function analyze(input, opts) {
    input = input || {};
    opts = opts || {};
    var risk = _normRisk(opts.risk_appetite);
    var riskMult = VALID_RISKS[risk];
    var now = typeof opts.now === "number" && isFinite(opts.now) ? opts.now : Date.now();
    var defaults = _mergeDefaults(input.defaults);

    var honeypotsRaw = Array.isArray(input.honeypots) ? input.honeypots : [];
    var honeypots = honeypotsRaw.map(_deepCopy);

    var results = honeypots.map(function (h) {
      var rates = _rates(h);
      var ageDays = _ageDays(h.deployedAt, now);
      var scored = _scoreHoneypot(h, rates, ageDays, riskMult, defaults);
      var verdict = _verdictFor(h, rates, ageDays, defaults);
      var priority = _priorityFor(verdict);
      var suggested = _suggestedActionFor(verdict);
      return {
        id: String(h.id),
        type: _normType(h.type),
        verdict: verdict,
        priority: priority,
        effectivenessScore: scored.score,
        botCatchRate: +Number(rates.botCatchRate).toFixed(4),
        falsePositiveRate: +Number(rates.falsePositiveRate).toFixed(4),
        confirmedBotRate: +Number(rates.confirmedBotRate).toFixed(4),
        ageDays: ageDays,
        reasons: scored.reasons,
        suggestedAction: suggested,
        _raw: rates,
      };
    });

    var portfolioMetrics = _portfolioMetrics(results);
    var p0 = results.filter(function (r) { return r.priority === "P0"; }).length;
    var p1 = results.filter(function (r) { return r.priority === "P1"; }).length;
    var p2 = results.filter(function (r) { return r.priority === "P2"; }).length;
    var p3 = results.filter(function (r) { return r.priority === "P3"; }).length;
    var total = results.length;
    var highRiskShare = total > 0 ? +Number((p0 + p1) / total).toFixed(4) : 0;
    var portfolioRisk = _portfolioRiskScore(results, portfolioMetrics.portfolioFalsePositiveRate, defaults);
    var hasAccessibilityFailure = results.some(function (r) {
      return r.verdict === "DISABLE_FALSE_POSITIVE_RISK" &&
        honeypots.find(function (h) { return String(h.id) === r.id && h.isAccessibilityRisk; });
    });
    var grade = _gradeFor(highRiskShare, p0 > 0, p0, portfolioMetrics.portfolioFalsePositiveRate, defaults, hasAccessibilityFailure);
    var band = _bandFor(highRiskShare, risk);
    var playbook = _buildPlaybook(results, honeypots, defaults, risk, portfolioRisk);
    var insights = _buildInsights(results, honeypots, portfolioMetrics);

    // Strip private _raw before returning per-honeypot
    var publicHoneypots = results.map(function (r) {
      var c = {};
      Object.keys(r).forEach(function (k) { if (k !== "_raw") c[k] = r[k]; });
      return c;
    });

    var summary = {
      totalHoneypots: total,
      p0Count: p0,
      p1Count: p1,
      p2Count: p2,
      p3Count: p3,
      highRiskShare: highRiskShare,
      portfolioBotCatchRate: portfolioMetrics.portfolioBotCatchRate,
      portfolioFalsePositiveRate: portfolioMetrics.portfolioFalsePositiveRate,
      portfolioConfirmedBotRate: portfolioMetrics.portfolioConfirmedBotRate,
      riskScore: portfolioRisk,
      band: band,
      grade: grade,
    };

    return {
      generatedAt: now,
      risk_appetite: risk,
      defaults: defaults,
      summary: summary,
      band: band,
      grade: grade,
      riskScore: portfolioRisk,
      honeypots: publicHoneypots,
      playbook: playbook,
      insights: insights,
    };
  }

  function simulate(report, opts) {
    opts = opts || {};
    var applyTop = typeof opts.applyTop === "number" && opts.applyTop > 0 ? Math.floor(opts.applyTop) : 3;
    if (!report || !Array.isArray(report.playbook) || report.playbook.length === 0) {
      return {
        projectedRiskScore: report ? report.riskScore || 0 : 0,
        projectedBand: report ? report.band || "CALM" : "CALM",
        projectedGrade: report ? report.grade || "A" : "A",
        appliedActions: [],
      };
    }
    var applied = report.playbook.slice(0, applyTop);
    var projected = report.riskScore || 0;
    var diminishing = 1.0;
    var details = [];
    applied.forEach(function (a) {
      var raw = a.estRiskDelta || 0;
      var delta = raw * diminishing;
      projected += delta;
      details.push({
        id: a.id,
        priority: a.priority,
        rawDelta: raw,
        appliedDelta: +Number(delta).toFixed(3),
      });
      diminishing *= 0.85;
    });
    projected = Math.max(5, _clamp(projected, 0, 100));
    var risk = report.risk_appetite || DEFAULT_RISK;
    var hrShare = report.summary ? report.summary.highRiskShare : 0;
    var anyP0 = report.playbook.some(function (a) { return a.priority === "P0"; });
    var appliedP0 = applied.some(function (a) { return a.priority === "P0"; });
    var stillP0 = anyP0 && !appliedP0;
    var defaults = report.defaults || DEFAULTS;
    var portFpr = report.summary ? report.summary.portfolioFalsePositiveRate : 0;
    var hasAccessibilityFailure = anyP0 && !appliedP0 && report.playbook.some(function (a) { return a.id === "DISABLE_ACCESSIBILITY_BREAKING_TRAPS"; });
    var projectedGrade = _gradeFor(hrShare, stillP0, stillP0 ? 1 : 0, portFpr, defaults, hasAccessibilityFailure);
    var projectedBand = _bandFor(hrShare, risk);
    return {
      projectedRiskScore: +Number(projected).toFixed(2),
      projectedBand: projectedBand,
      projectedGrade: projectedGrade,
      appliedActions: details,
    };
  }

  function formatText(report) {
    if (!report) return "";
    var lines = [];
    lines.push("HoneypotEffectivenessAdvisor: " + report.band + " (grade " + report.grade + ") riskScore=" + report.riskScore);
    var s = report.summary;
    lines.push("Honeypots: " + s.totalHoneypots +
      " | P0=" + s.p0Count + " P1=" + s.p1Count + " P2=" + s.p2Count + " P3=" + s.p3Count);
    lines.push("Portfolio bot-catch=" + (s.portfolioBotCatchRate * 100).toFixed(2) + "% " +
      "false-positive=" + (s.portfolioFalsePositiveRate * 100).toFixed(2) + "% " +
      "confirmed-bot=" + (s.portfolioConfirmedBotRate * 100).toFixed(2) + "%");
    lines.push("");
    lines.push("Top honeypots:");
    var sorted = report.honeypots.slice().sort(function (a, b) {
      var pr = { P0: 0, P1: 1, P2: 2, P3: 3 };
      var pa = pr[a.priority] - pr[b.priority];
      if (pa !== 0) return pa;
      return a.id < b.id ? -1 : 1;
    }).slice(0, 10);
    sorted.forEach(function (h) {
      var topReason = h.reasons.length ? h.reasons[0].label : "";
      lines.push("  [" + h.priority + "] " + h.id + " (" + h.type + ") -> " + h.verdict +
        " score=" + h.effectivenessScore + " catch=" + (h.botCatchRate * 100).toFixed(1) + "%" +
        (topReason ? " | " + topReason : ""));
    });
    lines.push("");
    lines.push("Playbook:");
    report.playbook.forEach(function (a) {
      lines.push("  [" + a.priority + "] " + a.id + " (" + a.owner +
        ", blast=" + a.blastRadius + ", " + a.reversibility + ") - " + a.label);
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
    var s = report.summary;
    lines.push("# Honeypot Effectiveness Advisor");
    lines.push("");
    lines.push("## Summary");
    lines.push("");
    lines.push("| Field | Value |");
    lines.push("| --- | --- |");
    lines.push("| Band | " + report.band + " |");
    lines.push("| Grade | " + report.grade + " |");
    lines.push("| Risk score | " + report.riskScore + " |");
    lines.push("| Total honeypots | " + s.totalHoneypots + " |");
    lines.push("| P0/P1/P2/P3 | " + s.p0Count + " / " + s.p1Count + " / " + s.p2Count + " / " + s.p3Count + " |");
    lines.push("| High-risk share | " + (s.highRiskShare * 100).toFixed(1) + "% |");
    lines.push("| Portfolio bot-catch rate | " + (s.portfolioBotCatchRate * 100).toFixed(2) + "% |");
    lines.push("| Portfolio false-positive rate | " + (s.portfolioFalsePositiveRate * 100).toFixed(2) + "% |");
    lines.push("| Risk appetite | " + report.risk_appetite + " |");
    lines.push("");
    lines.push("## Honeypots");
    lines.push("");
    lines.push("| id | type | verdict | priority | score | catch% | FP% | top reason |");
    lines.push("| --- | --- | --- | --- | --- | --- | --- | --- |");
    report.honeypots.forEach(function (h) {
      var top = h.reasons.length ? h.reasons[0].label : "";
      lines.push("| " + h.id + " | " + h.type + " | " + h.verdict + " | " + h.priority +
        " | " + h.effectivenessScore + " | " + (h.botCatchRate * 100).toFixed(1) +
        " | " + (h.falsePositiveRate * 100).toFixed(2) + " | " + top + " |");
    });
    lines.push("");
    lines.push("## Playbook");
    lines.push("");
    lines.push("| priority | id | owner | blastRadius | reversibility | label |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    report.playbook.forEach(function (a) {
      lines.push("| " + a.priority + " | " + a.id + " | " + a.owner +
        " | " + a.blastRadius + " | " + a.reversibility + " | " + a.label + " |");
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

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    createHoneypotEffectivenessAdvisor: createHoneypotEffectivenessAdvisor,
  };
}

if (typeof window !== "undefined") {
  window.HoneypotEffectivenessAdvisor = { createHoneypotEffectivenessAdvisor: createHoneypotEffectivenessAdvisor };
}
