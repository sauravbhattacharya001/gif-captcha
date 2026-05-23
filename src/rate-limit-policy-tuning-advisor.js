"use strict";

/**
 * RateLimitPolicyTuningAdvisor - Agentic per-policy rate-limit auto-tuner.
 *
 * Complements (does not duplicate) captcha-rate-limiter (which enforces).
 * Audits recent decision/limiter telemetry and recommends knob changes:
 * windowMs, maxRequests, banThreshold, banDurationMs, capacity.
 *
 * Sibling to webhook-delivery-health-advisor, cross-session-linkage-advisor,
 * session-evidence-bundler, honeypot-effectiveness-advisor, etc.
 *
 * Pure JS, zero deps, deterministic given inputs + risk_appetite + now.
 * Never mutates inputs.
 *
 * Public API:
 *   createRateLimitPolicyTuningAdvisor() => {
 *     analyze({ policies, decisions, events }, { risk_appetite?, now? }) -> report,
 *     simulate(report, { applyTopN? }) -> projection,
 *     formatText(report), formatMarkdown(report), formatJson(report)
 *   }
 *
 * @module rate-limit-policy-tuning-advisor
 */

var DEFAULT_RISK = "balanced";
var RISK_MULT = { cautious: 1.15, balanced: 1.0, aggressive: 0.85 };

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

function _clamp(n, lo, hi) {
  if (!isFinite(n)) return lo;
  if (n < lo) return lo;
  if (n > hi) return hi;
  return n;
}

function _normRisk(r) {
  if (r && Object.prototype.hasOwnProperty.call(RISK_MULT, r)) return r;
  return DEFAULT_RISK;
}

function _deepCopy(v) {
  if (v === null || v === undefined) return v;
  if (typeof v !== "object") return v;
  if (v instanceof Date) return new Date(v.getTime());
  if (Array.isArray(v)) return v.map(_deepCopy);
  var out = {};
  Object.keys(v).forEach(function (k) { out[k] = _deepCopy(v[k]); });
  return out;
}

function _num(v, dflt) {
  var n = Number(v);
  return isFinite(n) ? n : dflt;
}

function _median(arr) {
  if (!arr || arr.length === 0) return 0;
  var sorted = arr.slice().sort(function (a, b) { return a - b; });
  var m = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[m - 1] + sorted[m]) / 2 : sorted[m];
}

// -----------------------------------------------------------------
// Stable JSON serializer
// -----------------------------------------------------------------

function _stableStringify(value, indent) {
  var pad = indent || 2;
  var seen = new WeakSet();
  function s(v, depth) {
    if (v === null) return "null";
    if (typeof v === "number") return isFinite(v) ? String(v) : "null";
    if (typeof v === "boolean") return v ? "true" : "false";
    if (typeof v === "string") return JSON.stringify(v);
    if (typeof v === "undefined") return "null";
    if (v instanceof Date) return JSON.stringify(v.toISOString());
    if (typeof v === "object") {
      if (seen.has(v)) return "null";
      seen.add(v);
      var spacer = " ".repeat(pad * depth);
      var inner = " ".repeat(pad * (depth + 1));
      if (Array.isArray(v)) {
        if (v.length === 0) { seen.delete(v); return "[]"; }
        var parts = v.map(function (x) { return inner + s(x, depth + 1); });
        seen.delete(v);
        return "[\n" + parts.join(",\n") + "\n" + spacer + "]";
      }
      var keys = Object.keys(v).sort();
      if (keys.length === 0) { seen.delete(v); return "{}"; }
      var lines = keys.map(function (k) {
        return inner + JSON.stringify(k) + ": " + s(v[k], depth + 1);
      });
      seen.delete(v);
      return "{\n" + lines.join(",\n") + "\n" + spacer + "}";
    }
    return "null";
  }
  return s(value, 0);
}

// -----------------------------------------------------------------
// Per-policy analytics
// -----------------------------------------------------------------

function _policyStats(policy, decisions, events) {
  var pid = String(policy.id);
  var pDec = decisions.filter(function (d) { return String(d.policyId) === pid; });
  var pEv = events.filter(function (e) { return String(e.policyId) === pid; });

  var total = pDec.length;
  var allowed = 0, rateLimited = 0, banned = 0;
  var botHits = 0, botAllowed = 0;
  var humanHits = 0, humanRateLimited = 0, humanBanned = 0;
  var rlTimestamps = [];

  // Repeat-offender tracking: keys that get rate_limited then allowed again later.
  var keySeq = Object.create(null);
  var repeatOffenders = 0;
  var seenOffender = Object.create(null);

  pDec.forEach(function (d) {
    var outcome = d.outcome;
    if (outcome === "allowed") allowed++;
    else if (outcome === "rate_limited") rateLimited++;
    else if (outcome === "banned") banned++;

    if (d.isBot) {
      botHits++;
      if (outcome === "allowed") botAllowed++;
    }
    if (d.isHuman) {
      humanHits++;
      if (outcome === "rate_limited") humanRateLimited++;
      if (outcome === "banned") humanBanned++;
    }

    if (outcome === "rate_limited") {
      var ts = _num(d.ts, 0);
      if (ts) rlTimestamps.push(ts);
    }

    var key = d.key != null ? String(d.key) : null;
    if (key) {
      var hist = keySeq[key] || (keySeq[key] = []);
      hist.push(outcome);
    }
  });

  Object.keys(keySeq).forEach(function (k) {
    var hist = keySeq[k];
    var rlCount = 0;
    for (var i = 0; i < hist.length; i++) {
      if (hist[i] === "rate_limited") rlCount++;
      else if (hist[i] === "allowed" && rlCount >= 3 && !seenOffender[k]) {
        repeatOffenders++;
        seenOffender[k] = 1;
        break;
      }
    }
  });

  // Median inter-arrival for rate-limited events
  rlTimestamps.sort(function (a, b) { return a - b; });
  var gaps = [];
  for (var i = 1; i < rlTimestamps.length; i++) gaps.push(rlTimestamps[i] - rlTimestamps[i - 1]);
  var medianGapMs = _median(gaps);

  var evictions = 0;
  var memoryPressure = 0;
  pEv.forEach(function (e) {
    if (e.type === "eviction") evictions++;
    else if (e.type === "memory_pressure") memoryPressure++;
    else if (e.type === "cleanup") {/* informational */}
  });

  var botAllowRate = botHits > 0 ? botAllowed / botHits : 0;
  var humanRateLimitRate = humanHits > 0 ? humanRateLimited / humanHits : 0;
  var bannedHumanRate = banned > 0 ? humanBanned / banned : 0;

  return {
    total: total,
    allowed: allowed,
    rateLimited: rateLimited,
    banned: banned,
    botHits: botHits,
    botAllowed: botAllowed,
    botAllowRate: botAllowRate,
    humanHits: humanHits,
    humanRateLimited: humanRateLimited,
    humanRateLimitRate: humanRateLimitRate,
    humanBanned: humanBanned,
    bannedHumanRate: bannedHumanRate,
    repeatOffenders: repeatOffenders,
    medianRateLimitedGapMs: medianGapMs,
    evictions: evictions,
    memoryPressure: memoryPressure,
  };
}

// -----------------------------------------------------------------
// Verdict ladder
// -----------------------------------------------------------------

function _verdictAndChanges(policy, stats) {
  // Returns { verdict, severity, reasons[], changes[] }
  var changes = [];
  var reasons = [];

  if (stats.total === 0) {
    return { verdict: "UNUSED_POLICY", severity: 5, reasons: ["No decisions observed over horizon"], changes: [] };
  }
  if (stats.total < 5) {
    return { verdict: "INSUFFICIENT_DATA", severity: 15, reasons: ["Only " + stats.total + " decisions observed"], changes: [] };
  }

  // POLICY_TOO_LAX (P0)
  if (stats.botAllowRate >= 0.25 && stats.botHits >= 10) {
    reasons.push("Bot allow-through rate " + (stats.botAllowRate * 100).toFixed(1) + "% >= 25%");
    var curMax = _num(policy.maxRequests, 10);
    var curBan = _num(policy.banThreshold, 3);
    changes.push({ field: "maxRequests", current: curMax, suggested: Math.max(1, Math.floor(curMax * 0.7)), reason: "Reduce allowance to throttle bots" });
    changes.push({ field: "banThreshold", current: curBan, suggested: Math.max(2, curBan - 1), reason: "Ban repeat bot offenders sooner" });
    return { verdict: "POLICY_TOO_LAX", severity: 85, reasons: reasons, changes: changes };
  }

  // POLICY_TOO_STRICT (P0)
  if (stats.humanRateLimitRate >= 0.15 && stats.humanHits >= 20) {
    reasons.push("Human throttle rate " + (stats.humanRateLimitRate * 100).toFixed(1) + "% >= 15%");
    var curMax2 = _num(policy.maxRequests, 10);
    changes.push({ field: "maxRequests", current: curMax2, suggested: Math.ceil(curMax2 * 1.3), reason: "Relax limit to reduce human friction" });
    return { verdict: "POLICY_TOO_STRICT", severity: 80, reasons: reasons, changes: changes };
  }

  // BAN_THRESHOLD_TOO_LOW (P1)
  if (stats.banned >= 5 && stats.bannedHumanRate >= 0.20) {
    reasons.push("Banned humans " + (stats.bannedHumanRate * 100).toFixed(1) + "% of bans");
    var curBan2 = _num(policy.banThreshold, 3);
    changes.push({ field: "banThreshold", current: curBan2, suggested: curBan2 + 1, reason: "Avoid banning legitimate humans" });
    return { verdict: "BAN_THRESHOLD_TOO_LOW", severity: 60, reasons: reasons, changes: changes };
  }

  // BAN_THRESHOLD_TOO_HIGH (P1)
  if (stats.repeatOffenders >= 5) {
    reasons.push("Repeat offenders " + stats.repeatOffenders + " >= 5");
    var curBan3 = _num(policy.banThreshold, 3);
    var curDur = _num(policy.banDurationMs, 300000);
    changes.push({ field: "banThreshold", current: curBan3, suggested: Math.max(2, curBan3 - 1), reason: "Ban repeat offenders sooner" });
    changes.push({ field: "banDurationMs", current: curDur, suggested: Math.floor(curDur * 0.5), reason: "Shorter bans suffice if applied earlier" });
    return { verdict: "BAN_THRESHOLD_TOO_HIGH", severity: 55, reasons: reasons, changes: changes };
  }

  // WINDOW_TOO_SHORT (P2)
  var curWindow = _num(policy.windowMs, 60000);
  var curMaxR = _num(policy.maxRequests, 10);
  if (stats.rateLimited >= 3 && stats.medianRateLimitedGapMs > 0 &&
      stats.medianRateLimitedGapMs < curWindow * 0.2 && curMaxR <= 20) {
    reasons.push("Bursty rate-limits: median gap " + Math.round(stats.medianRateLimitedGapMs) + "ms < windowMs*0.2");
    changes.push({ field: "windowMs", current: curWindow, suggested: Math.floor(curWindow * 1.5), reason: "Widen window to smooth bursts" });
    return { verdict: "WINDOW_TOO_SHORT", severity: 40, reasons: reasons, changes: changes };
  }

  // EVICTION_PRESSURE (P2)
  if (stats.evictions >= 2 || stats.memoryPressure >= 1) {
    reasons.push("Eviction/memory pressure events=" + (stats.evictions + stats.memoryPressure));
    var curCap = _num(policy.capacity, 0);
    if (curCap > 0) {
      changes.push({ field: "capacity", current: curCap, suggested: Math.ceil(curCap * 1.5), reason: "Expand key store capacity" });
    }
    return { verdict: "EVICTION_PRESSURE", severity: 35, reasons: reasons, changes: changes };
  }

  return { verdict: "HEALTHY", severity: 5, reasons: ["Policy operating within healthy bounds"], changes: [] };
}

function _priorityFor(verdict) {
  switch (verdict) {
    case "POLICY_TOO_LAX":
    case "POLICY_TOO_STRICT":
      return "P0";
    case "BAN_THRESHOLD_TOO_LOW":
    case "BAN_THRESHOLD_TOO_HIGH":
      return "P1";
    case "WINDOW_TOO_SHORT":
    case "EVICTION_PRESSURE":
    case "INSUFFICIENT_DATA":
      return "P2";
    case "UNUSED_POLICY":
    case "HEALTHY":
    default:
      return "P3";
  }
}

function _scoreForFinding(severity, riskMult) {
  // riskScore = top_severity + 0.4*min(rest, 60)  (we only have one verdict, so just severity)
  var s = severity * riskMult;
  return _clamp(s, 0, 100);
}

// -----------------------------------------------------------------
// Portfolio scoring
// -----------------------------------------------------------------

function _portfolioRiskScore(policies) {
  if (policies.length === 0) return 0;
  var scores = policies.map(function (p) { return p.risk_score; });
  scores.sort(function (a, b) { return b - a; });
  var worst = scores[0];
  var top3 = scores.slice(0, 3);
  var mean = top3.reduce(function (a, b) { return a + b; }, 0) / top3.length;
  return +Number(Math.max(worst * 0.7, mean)).toFixed(2);
}

function _gradeFor(policies, portfolioRisk) {
  var anyCriticalP0 = policies.some(function (p) {
    return p.priority === "P0" && (p._criticality || 3) >= 4;
  });
  if (anyCriticalP0 || portfolioRisk >= 75) return "F";
  if (portfolioRisk >= 55) return "D";
  if (portfolioRisk >= 35) return "C";
  if (portfolioRisk >= 18) return "B";
  return "A";
}

// -----------------------------------------------------------------
// Playbook
// -----------------------------------------------------------------

function _buildPlaybook(policies, risk, grade) {
  var actions = [];

  function ids(verdict) {
    return policies.filter(function (p) { return p.verdict === verdict; }).map(function (p) { return p.id; });
  }
  function any(verdict) { return ids(verdict).length > 0; }
  function count(verdict) { return ids(verdict).length; }

  var ESTIMATES = {
    TIGHTEN_LAX_POLICIES: -25,
    RELAX_OVER_STRICT_POLICIES: -18,
    RAISE_BAN_THRESHOLD: -10,
    LOWER_BAN_THRESHOLD: -8,
    WIDEN_RATE_LIMIT_WINDOWS: -6,
    EXPAND_KEY_CAPACITY: -5,
    RETIRE_UNUSED_POLICIES: -3,
    COLLECT_MORE_DECISION_TELEMETRY: -2,
    SCHEDULE_RATE_LIMIT_AUDIT: -2,
    MAINTAIN_RATE_LIMIT_HEALTH: 0,
  };

  function action(id, priority, owner, blast, rev, label, reason, policyIds, suggestedValue) {
    var a = {
      id: id,
      priority: priority,
      label: label,
      reason: reason,
      owner: owner,
      blastRadius: blast,
      reversibility: rev,
      policyIds: policyIds || [],
      estRiskDelta: ESTIMATES[id] || 0,
    };
    if (suggestedValue !== undefined) a.suggestedValue = suggestedValue;
    actions.push(a);
  }

  if (any("POLICY_TOO_LAX")) {
    action("TIGHTEN_LAX_POLICIES", "P0", "ops", 4, "low",
      "Tighten policies allowing too many bots through",
      "Bot allow-through rate exceeds 25% on " + count("POLICY_TOO_LAX") + " policy(ies)",
      ids("POLICY_TOO_LAX"));
  }
  if (any("POLICY_TOO_STRICT")) {
    action("RELAX_OVER_STRICT_POLICIES", "P0", "ops", 3, "high",
      "Relax policies throttling legitimate humans",
      "Human throttle rate >= 15% on " + count("POLICY_TOO_STRICT") + " policy(ies)",
      ids("POLICY_TOO_STRICT"));
  }
  if (any("BAN_THRESHOLD_TOO_LOW")) {
    action("RAISE_BAN_THRESHOLD", "P1", "ops", 2, "high",
      "Raise ban threshold to reduce wrongful bans",
      "Humans appearing in ban list at >= 20% rate",
      ids("BAN_THRESHOLD_TOO_LOW"));
  }
  if (any("BAN_THRESHOLD_TOO_HIGH")) {
    action("LOWER_BAN_THRESHOLD", "P1", "ops", 2, "high",
      "Lower ban threshold to catch repeat offenders sooner",
      "Repeat offenders detected on " + count("BAN_THRESHOLD_TOO_HIGH") + " policy(ies)",
      ids("BAN_THRESHOLD_TOO_HIGH"));
  }
  if (any("WINDOW_TOO_SHORT")) {
    action("WIDEN_RATE_LIMIT_WINDOWS", "P2", "ops", 2, "high",
      "Widen rate-limit windows for bursty traffic",
      "Median rate-limit gap < windowMs*0.2 on " + count("WINDOW_TOO_SHORT") + " policy(ies)",
      ids("WINDOW_TOO_SHORT"));
  }
  if (any("EVICTION_PRESSURE")) {
    action("EXPAND_KEY_CAPACITY", "P2", "platform", 3, "high",
      "Expand key-store capacity to relieve eviction pressure",
      "Eviction/memory-pressure events observed",
      ids("EVICTION_PRESSURE"));
  }
  if (count("UNUSED_POLICY") >= 2) {
    action("RETIRE_UNUSED_POLICIES", "P2", "ops", 1, "high",
      "Retire policies with no recent traffic",
      count("UNUSED_POLICY") + " policies received zero decisions",
      ids("UNUSED_POLICY"));
  }
  // Majority insufficient data
  if (policies.length > 0) {
    var insufCount = count("INSUFFICIENT_DATA");
    if (insufCount >= Math.ceil(policies.length / 2) && insufCount >= 1) {
      action("COLLECT_MORE_DECISION_TELEMETRY", "P2", "data_steward", 1, "high",
        "Collect more decision telemetry for confident tuning",
        insufCount + "/" + policies.length + " policies lack enough decisions",
        ids("INSUFFICIENT_DATA"));
    }
  }
  if (risk === "cautious" && (grade === "C" || grade === "D" || grade === "F")) {
    action("SCHEDULE_RATE_LIMIT_AUDIT", "P2", "ops", 1, "high",
      "Schedule a manual rate-limit audit",
      "Cautious appetite + grade " + grade,
      []);
  }

  // Fallback P3
  if (actions.length === 0) {
    action("MAINTAIN_RATE_LIMIT_HEALTH", "P3", "ops", 1, "high",
      "Maintain current rate-limit policies",
      "No findings; portfolio healthy",
      []);
  }

  // Aggressive trimming: drop P3 + lone P2 when P0/P1 present
  if (risk === "aggressive") {
    var hasHigher = actions.some(function (a) { return a.priority === "P0" || a.priority === "P1"; });
    if (hasHigher) {
      actions = actions.filter(function (a) {
        if (a.priority === "P3") return false;
        return true;
      });
      var p2s = actions.filter(function (a) { return a.priority === "P2"; });
      if (p2s.length === 1) {
        actions = actions.filter(function (a) { return a.priority !== "P2"; });
      }
    }
  }

  // P0-first then by id
  var order = { P0: 0, P1: 1, P2: 2, P3: 3 };
  actions.sort(function (a, b) {
    var d = order[a.priority] - order[b.priority];
    if (d !== 0) return d;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

  return actions;
}

// -----------------------------------------------------------------
// Insights
// -----------------------------------------------------------------

function _buildInsights(policies, totals) {
  var insights = [];
  function cnt(v) { return policies.filter(function (p) { return p.verdict === v; }).length; }

  if (policies.length === 0) {
    insights.push({ code: "EMPTY_INPUT", label: "No policies provided", detail: "" });
    return insights;
  }

  if (cnt("POLICY_TOO_LAX") >= 2) {
    insights.push({ code: "LAX_POLICY_CLUSTER", label: "Multiple policies are too lax", detail: "count=" + cnt("POLICY_TOO_LAX") });
  }
  if (totals.totalBotHits > 0) {
    var globalBotAllow = totals.totalBotAllowed / totals.totalBotHits;
    if (globalBotAllow >= 0.20) {
      insights.push({ code: "BOT_BREAKTHROUGH_PATTERN", label: "Bots breaking through portfolio-wide", detail: "rate=" + (globalBotAllow * 100).toFixed(1) + "%" });
    }
  }
  if (cnt("POLICY_TOO_STRICT") >= 2) {
    insights.push({ code: "HUMAN_FRICTION_PATTERN", label: "Multiple policies frustrate humans", detail: "count=" + cnt("POLICY_TOO_STRICT") });
  }
  if (cnt("BAN_THRESHOLD_TOO_HIGH") >= 3 || totals.totalRepeatOffenders >= 10) {
    insights.push({ code: "BAN_LIST_THRASHING", label: "Repeat offenders cycling through ban list", detail: "repeatOffenders=" + totals.totalRepeatOffenders });
  }
  if (cnt("EVICTION_PRESSURE") >= 1) {
    insights.push({ code: "KEY_STORE_OVERFLOW", label: "Key store under eviction pressure", detail: "count=" + cnt("EVICTION_PRESSURE") });
  }
  if (cnt("UNUSED_POLICY") / policies.length >= 0.5) {
    insights.push({ code: "DEAD_POLICY_PORTFOLIO", label: ">=50% of policies have no recent traffic", detail: "unused=" + cnt("UNUSED_POLICY") });
  }
  if (insights.length === 0) {
    insights.push({ code: "HEALTHY_RATE_LIMITING", label: "Rate-limit portfolio is healthy", detail: "" });
  }
  insights.sort(function (a, b) { return a.code < b.code ? -1 : a.code > b.code ? 1 : 0; });
  return insights;
}

// -----------------------------------------------------------------
// Factory
// -----------------------------------------------------------------

function createRateLimitPolicyTuningAdvisor() {

  function analyze(input, opts) {
    input = input || {};
    opts = opts || {};
    var risk = _normRisk(opts.risk_appetite);
    var riskMult = RISK_MULT[risk];
    var now = typeof opts.now === "number" && isFinite(opts.now) ? opts.now : Date.now();

    var policiesRaw = Array.isArray(input.policies) ? input.policies : [];
    var decisionsRaw = Array.isArray(input.decisions) ? input.decisions : [];
    var eventsRaw = Array.isArray(input.events) ? input.events : [];

    var policies = policiesRaw.map(_deepCopy);
    var decisions = decisionsRaw.map(_deepCopy);
    var events = eventsRaw.map(_deepCopy);

    var results = policies.map(function (p) {
      var stats = _policyStats(p, decisions, events);
      var verdictInfo = _verdictAndChanges(p, stats);
      var priority = _priorityFor(verdictInfo.verdict);
      var riskScore = _scoreForFinding(verdictInfo.severity, riskMult);
      return {
        id: String(p.id),
        scope: p.scope || "unknown",
        algorithm: p.algorithm || "unknown",
        verdict: verdictInfo.verdict,
        priority: priority,
        risk_score: +Number(riskScore).toFixed(2),
        reasons: verdictInfo.reasons,
        suggestedChanges: verdictInfo.changes,
        stats: {
          decisions: stats.total,
          allowed: stats.allowed,
          rateLimited: stats.rateLimited,
          banned: stats.banned,
          botHits: stats.botHits,
          botAllowed: stats.botAllowed,
          botAllowRate: +Number(stats.botAllowRate).toFixed(4),
          humanHits: stats.humanHits,
          humanRateLimited: stats.humanRateLimited,
          humanRateLimitRate: +Number(stats.humanRateLimitRate).toFixed(4),
          repeatOffenders: stats.repeatOffenders,
          medianRateLimitedGapMs: Math.round(stats.medianRateLimitedGapMs),
          evictions: stats.evictions,
          memoryPressure: stats.memoryPressure,
        },
        _criticality: _num(p.criticality, 3),
      };
    });

    var portfolioRisk = _portfolioRiskScore(results);
    var grade = _gradeFor(results, portfolioRisk);
    var playbook = _buildPlaybook(results, risk, grade);

    var totals = {
      totalBotHits: results.reduce(function (a, r) { return a + r.stats.botHits; }, 0),
      totalBotAllowed: results.reduce(function (a, r) { return a + r.stats.botAllowed; }, 0),
      totalRepeatOffenders: results.reduce(function (a, r) { return a + r.stats.repeatOffenders; }, 0),
    };
    var insights = _buildInsights(results, totals);

    var p0 = results.filter(function (r) { return r.priority === "P0"; }).length;
    var p1 = results.filter(function (r) { return r.priority === "P1"; }).length;
    var p2 = results.filter(function (r) { return r.priority === "P2"; }).length;
    var p3 = results.filter(function (r) { return r.priority === "P3"; }).length;

    var publicResults = results.map(function (r) {
      var c = {};
      Object.keys(r).forEach(function (k) { if (k !== "_criticality") c[k] = r[k]; });
      return c;
    });

    var headline = "VERDICT: grade=" + grade + " policies=" + results.length +
      " P0=" + p0 + " P1=" + p1 + " portfolio_risk=" + portfolioRisk.toFixed(2);

    return {
      generatedAt: now,
      risk_appetite: risk,
      summary: {
        totalPolicies: results.length,
        p0Count: p0,
        p1Count: p1,
        p2Count: p2,
        p3Count: p3,
        portfolio_risk_score: portfolioRisk,
        grade: grade,
        headline: headline,
      },
      grade: grade,
      portfolio_risk_score: portfolioRisk,
      policies: publicResults,
      playbook: playbook,
      insights: insights,
    };
  }

  function simulate(report, opts) {
    opts = opts || {};
    var applyTop = typeof opts.applyTopN === "number" && opts.applyTopN > 0 ? Math.floor(opts.applyTopN) : 3;
    // Deep-copy report (snapshot guard)
    var snapshot = JSON.parse(JSON.stringify(report || {}));
    if (!snapshot.playbook || snapshot.playbook.length === 0) {
      return {
        projectedPortfolioRisk: snapshot.portfolio_risk_score || 0,
        projectedGrade: snapshot.grade || "A",
        appliedActions: [],
      };
    }
    var applied = snapshot.playbook.slice(0, applyTop);
    var projected = snapshot.portfolio_risk_score || 0;
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

    // Recompute grade as if portfolio_risk dropped (assume P0 critical assets resolved when P0 applied)
    var anyP0Left = snapshot.playbook.some(function (a) { return a.priority === "P0"; }) &&
      !applied.some(function (a) { return a.priority === "P0"; });
    var projectedGrade;
    if (anyP0Left && projected >= 55) projectedGrade = "F";
    else if (projected >= 75) projectedGrade = "F";
    else if (projected >= 55) projectedGrade = "D";
    else if (projected >= 35) projectedGrade = "C";
    else if (projected >= 18) projectedGrade = "B";
    else projectedGrade = "A";

    return {
      projectedPortfolioRisk: +Number(projected).toFixed(2),
      projectedGrade: projectedGrade,
      appliedActions: details,
    };
  }

  function formatText(report) {
    if (!report) return "";
    var lines = [];
    lines.push(report.summary.headline);
    lines.push("Risk appetite: " + report.risk_appetite);
    lines.push("");
    lines.push("Top findings:");
    var top = report.policies.slice().sort(function (a, b) { return b.risk_score - a.risk_score; }).slice(0, 5);
    top.forEach(function (p) {
      lines.push("  [" + p.priority + "] " + p.id + " (" + p.scope + ") -> " + p.verdict + " risk=" + p.risk_score);
    });
    lines.push("");
    lines.push("Playbook (" + report.playbook.length + "):");
    report.playbook.slice(0, 8).forEach(function (a) {
      lines.push("  [" + a.priority + "] " + a.id + " - " + a.label);
    });
    return lines.join("\n");
  }

  function formatMarkdown(report) {
    if (!report) return "";
    var lines = [];
    lines.push("# Rate-Limit Policy Tuning Report");
    lines.push("");
    lines.push("## Summary");
    lines.push("");
    lines.push("| Metric | Value |");
    lines.push("| --- | --- |");
    lines.push("| Grade | " + report.grade + " |");
    lines.push("| Portfolio risk | " + report.portfolio_risk_score + " |");
    lines.push("| Policies | " + report.summary.totalPolicies + " |");
    lines.push("| P0 / P1 / P2 / P3 | " + report.summary.p0Count + " / " + report.summary.p1Count + " / " + report.summary.p2Count + " / " + report.summary.p3Count + " |");
    lines.push("| Risk appetite | " + report.risk_appetite + " |");
    lines.push("");
    lines.push("## Policies");
    lines.push("");
    if (report.policies.length === 0) {
      lines.push("_No policies provided._");
    } else {
      lines.push("| ID | Scope | Verdict | Priority | Risk | Reasons |");
      lines.push("| --- | --- | --- | --- | --- | --- |");
      report.policies.forEach(function (p) {
        lines.push("| " + p.id + " | " + p.scope + " | " + p.verdict + " | " + p.priority + " | " + p.risk_score + " | " + (p.reasons || []).join("; ") + " |");
      });
    }
    lines.push("");
    lines.push("## Playbook");
    lines.push("");
    if (report.playbook.length === 0) {
      lines.push("_No actions._");
    } else {
      lines.push("| Priority | ID | Owner | Label | Reason |");
      lines.push("| --- | --- | --- | --- | --- |");
      report.playbook.forEach(function (a) {
        lines.push("| " + a.priority + " | " + a.id + " | " + a.owner + " | " + a.label + " | " + a.reason + " |");
      });
    }
    lines.push("");
    lines.push("## Insights");
    lines.push("");
    report.insights.forEach(function (i) {
      lines.push("- **" + i.code + "**: " + i.label + (i.detail ? " (" + i.detail + ")" : ""));
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
  createRateLimitPolicyTuningAdvisor: createRateLimitPolicyTuningAdvisor,
};
