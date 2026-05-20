/**
 * UserAbandonmentForecaster - Agentic UX-friction forecaster for gif-captcha.
 *
 * Sibling to AttackForecaster (bot-side) and CaptchaFatigueDetector (user-side).
 * Where most gif-captcha modules ask "is this a bot?", this one asks "are we
 * losing real humans to friction?" and surfaces interventions that trade
 * tiny amounts of security headroom for measurable conversion.
 *
 * Inputs:
 *   - funnelStages: [{stage, count}] for the 5 canonical stages
 *   - cohorts: [{id,label,sampleSize,completionRate,avgTimeToCompleteMs,retryRate,notes?}]
 *   - currentDifficulty: 1..10
 *   - accessibilityFlags: {hasAudioAlt,hasTextAlt,supportsScreenReader,lowMotion}
 *   - recentLatencyP95Ms: number
 *   - recentTimeoutRate: 0..1
 *   - deviceMixSample: [{id,device:'mobile'|'desktop'|'tablet',completionRate}]
 *
 * Outputs:
 *   {
 *     abandonmentRisk: 0..100,
 *     band: 'CALM'|'WATCH'|'ELEVATED'|'HIGH'|'CRITICAL',
 *     grade: 'A'..'F',
 *     funnel: [{stage,count,dropOffPct}],
 *     contributions: {funnel,difficulty,latency,timeout,accessibility,mobile,cohortDispersion},
 *     cohortVerdicts: [{id,label,verdict,reasons[],suggestedActions[]}],
 *     playbook: [{id,priority,label,reason,owner,blastRadius,reversibility,estRiskDelta,meta?}],
 *     insights: [string],
 *     summary: {primaryDriver,riskAppetite}
 *   }
 *
 * Pure JS, no external deps. Deterministic.
 *
 * @module user-abandonment-forecaster
 */

"use strict";

var STAGES = ["presented", "started", "first_interaction", "submitted", "verified"];
var STAGE_WEIGHTS = {
  "presented->started": 0.35,
  "started->first_interaction": 0.20,
  "first_interaction->submitted": 0.20,
  "submitted->verified": 0.25,
};

var BAND_CUTOFFS_BALANCED = { CALM: 20, WATCH: 40, ELEVATED: 60, HIGH: 80 };

function clamp(n, lo, hi) {
  if (n < lo) return lo;
  if (n > hi) return hi;
  return n;
}

function isFiniteNum(n) { return typeof n === "number" && isFinite(n); }

function _validate(input) {
  if (!input || typeof input !== "object") {
    throw new TypeError("analyze() requires an input object");
  }
  if (!Array.isArray(input.funnelStages)) {
    throw new TypeError("input.funnelStages must be an array");
  }
  if (!Array.isArray(input.cohorts)) {
    throw new TypeError("input.cohorts must be an array");
  }
}

function _bandCutoffs(riskAppetite) {
  var shift = riskAppetite === "cautious" ? -5 : riskAppetite === "aggressive" ? 5 : 0;
  return {
    CALM: BAND_CUTOFFS_BALANCED.CALM + shift,
    WATCH: BAND_CUTOFFS_BALANCED.WATCH + shift,
    ELEVATED: BAND_CUTOFFS_BALANCED.ELEVATED + shift,
    HIGH: BAND_CUTOFFS_BALANCED.HIGH + shift,
  };
}

function _classifyBand(risk, cuts) {
  if (risk < cuts.CALM) return "CALM";
  if (risk < cuts.WATCH) return "WATCH";
  if (risk < cuts.ELEVATED) return "ELEVATED";
  if (risk < cuts.HIGH) return "HIGH";
  return "CRITICAL";
}

function _gradeFromBand(band) {
  return band === "CALM" ? "A"
       : band === "WATCH" ? "B"
       : band === "ELEVATED" ? "C"
       : band === "HIGH" ? "D"
       : "F";
}

function _computeFunnel(stages) {
  // Build a map keyed by stage; fill missing with last known count (no drop assumed).
  var byStage = {};
  stages.forEach(function (s) {
    if (s && typeof s.stage === "string" && isFiniteNum(s.count)) {
      byStage[s.stage] = Math.max(0, s.count);
    }
  });
  var out = [];
  var prev = null;
  for (var i = 0; i < STAGES.length; i++) {
    var st = STAGES[i];
    var c = Object.prototype.hasOwnProperty.call(byStage, st) ? byStage[st] : (prev == null ? 0 : prev);
    var dropOffPct = 0;
    if (prev != null && prev > 0) {
      dropOffPct = clamp(((prev - c) / prev) * 100, 0, 100);
    }
    out.push({ stage: st, count: c, dropOffPct: Math.round(dropOffPct * 10) / 10 });
    prev = c;
  }
  return out;
}

function _funnelContribution(funnel) {
  // Weighted sum of marginal drops (0..100 each) into 0..100 contribution.
  var total = 0;
  for (var i = 1; i < funnel.length; i++) {
    var key = funnel[i - 1].stage + "->" + funnel[i].stage;
    var w = STAGE_WEIGHTS[key] || 0;
    total += w * funnel[i].dropOffPct;
  }
  return clamp(total, 0, 100);
}

function _difficultyContribution(d) {
  if (!isFiniteNum(d) || d <= 6) return 0;
  // 7->10, 8->22, 9->36, 10->50
  return clamp((d - 6) * (d - 6) * 4, 0, 60);
}

function _latencyContribution(ms) {
  if (!isFiniteNum(ms) || ms <= 2500) return 0;
  if (ms >= 5000) return clamp(40 + (ms - 5000) / 200, 40, 70);
  // 2500..5000 -> 0..40 linear
  return clamp(((ms - 2500) / 2500) * 40, 0, 40);
}

function _timeoutContribution(rate) {
  if (!isFiniteNum(rate) || rate <= 0.05) return 0;
  return clamp((rate - 0.05) * 500, 0, 60);
}

function _accessibilityContribution(flags) {
  if (!flags || typeof flags !== "object") return 0;
  var gaps = 0;
  if (!flags.hasAudioAlt) gaps++;
  if (!flags.hasTextAlt) gaps++;
  if (!flags.supportsScreenReader) gaps++;
  if (!flags.lowMotion) gaps++;
  return gaps * 8; // 0..32
}

function _mobilePenalty(deviceMix) {
  if (!Array.isArray(deviceMix) || !deviceMix.length) {
    return { value: 0, triggered: false, gap: 0 };
  }
  var mob = [], desk = [];
  deviceMix.forEach(function (e) {
    if (!e || !isFiniteNum(e.completionRate)) return;
    if (e.device === "mobile") mob.push(e.completionRate);
    else if (e.device === "desktop") desk.push(e.completionRate);
  });
  if (!mob.length || !desk.length) return { value: 0, triggered: false, gap: 0 };
  var avg = function (arr) { return arr.reduce(function (a, b) { return a + b; }, 0) / arr.length; };
  var mAvg = avg(mob), dAvg = avg(desk);
  var gap = dAvg - mAvg;
  if (gap < 0.15) return { value: 0, triggered: false, gap: gap };
  // gap 0.15->10, 0.25->25, 0.35->40
  var v = clamp((gap - 0.15) * 250 + 10, 10, 50);
  return { value: v, triggered: true, gap: gap };
}

function _cohortDispersion(cohorts) {
  var rates = cohorts.filter(function (c) {
    return c && isFiniteNum(c.completionRate) && (c.sampleSize == null || c.sampleSize >= 30);
  }).map(function (c) { return c.completionRate; });
  if (rates.length < 2) return 0;
  var mean = rates.reduce(function (a, b) { return a + b; }, 0) / rates.length;
  var variance = rates.reduce(function (acc, r) { return acc + (r - mean) * (r - mean); }, 0) / rates.length;
  var stddev = Math.sqrt(variance);
  // stddev 0.05->5, 0.10->15, 0.20->30
  return clamp(stddev * 150, 0, 30);
}

function _classifyCohort(c) {
  if (!c || typeof c !== "object") {
    return { id: null, label: "(unknown)", verdict: "INSUFFICIENT_DATA", reasons: ["SMALL_SAMPLE"], suggestedActions: [] };
  }
  var id = c.id == null ? null : String(c.id);
  var label = c.label == null ? (id || "(unknown)") : String(c.label);
  var reasons = [];
  if (!isFiniteNum(c.sampleSize) || c.sampleSize < 30) {
    return { id: id, label: label, verdict: "INSUFFICIENT_DATA", reasons: ["SMALL_SAMPLE"], suggestedActions: [] };
  }
  var cr = isFiniteNum(c.completionRate) ? c.completionRate : 0;
  var rr = isFiniteNum(c.retryRate) ? c.retryRate : 0;
  var avg = isFiniteNum(c.avgTimeToCompleteMs) ? c.avgTimeToCompleteMs : 0;
  if (cr < 0.50) reasons.push("LOW_COMPLETION");
  else if (cr < 0.70) reasons.push("LOW_COMPLETION");
  if (rr > 0.30) reasons.push("HIGH_RETRY");
  if (avg > 12000) reasons.push("SLOW_COMPLETION");
  var verdict;
  if (cr < 0.50) verdict = "LOSING";
  else if (cr < 0.70 || rr > 0.30) verdict = "AT_RISK";
  else if (cr < 0.85) verdict = "WATCH";
  else if (rr <= 0.15) verdict = "HEALTHY";
  else verdict = "WATCH";
  var suggested = [];
  if (verdict === "LOSING") suggested.push("INVESTIGATE_COHORT");
  if (reasons.indexOf("HIGH_RETRY") >= 0) suggested.push("OFFER_RETRY_WITH_DIFFERENT_TYPE");
  if (reasons.indexOf("SLOW_COMPLETION") >= 0) suggested.push("SHORTEN_CHALLENGE_LENGTH");
  return { id: id, label: label, verdict: verdict, reasons: reasons, suggestedActions: suggested };
}

// Catalogue. Each action: trigger(ctx) -> bool, build(ctx) -> action
var ACTION_CATALOGUE = [
  {
    id: "LOWER_DIFFICULTY_ONE_NOTCH",
    priority: "P0",
    label: "Lower challenge difficulty by one notch",
    owner: "ux",
    blastRadius: 3,
    reversibility: "high",
    estRiskDelta: -12,
    trigger: function (ctx) { return ctx.risk >= 70 && ctx.currentDifficulty >= 7; },
    reason: function () { return "High abandonment risk combined with difficulty >=7"; },
  },
  {
    id: "ADD_AUDIO_ALT",
    priority: "P0",
    label: "Add audio alternative challenge",
    owner: "accessibility",
    blastRadius: 2,
    reversibility: "high",
    estRiskDelta: -8,
    trigger: function (ctx) { return !ctx.flags.hasAudioAlt && ctx.hasLosingCohort; },
    reason: function () { return "Missing audio alt and at least one cohort is LOSING"; },
  },
  {
    id: "ADD_TEXT_ALT",
    priority: "P0",
    label: "Add text-based alternative challenge",
    owner: "accessibility",
    blastRadius: 2,
    reversibility: "high",
    estRiskDelta: -7,
    trigger: function (ctx) { return !ctx.flags.hasTextAlt && ctx.risk >= 60; },
    reason: function () { return "Missing text alt while risk is HIGH+"; },
  },
  {
    id: "MOBILE_OPTIMIZED_CHALLENGE_SET",
    priority: "P0",
    label: "Roll out mobile-optimized challenge set",
    owner: "ux",
    blastRadius: 4,
    reversibility: "medium",
    estRiskDelta: -10,
    trigger: function (ctx) { return ctx.mobile.triggered; },
    reason: function (ctx) {
      return "Mobile completion lags desktop by " + Math.round(ctx.mobile.gap * 100) + " pts";
    },
  },
  {
    id: "ENABLE_SCREEN_READER_SUPPORT",
    priority: "P1",
    label: "Enable screen-reader support",
    owner: "accessibility",
    blastRadius: 2,
    reversibility: "high",
    estRiskDelta: -5,
    trigger: function (ctx) { return !ctx.flags.supportsScreenReader && ctx.risk >= 40; },
    reason: function () { return "Screen-reader unsupported with risk >=40"; },
  },
  {
    id: "HONOR_PREFERS_REDUCED_MOTION",
    priority: "P1",
    label: "Honor prefers-reduced-motion media query",
    owner: "accessibility",
    blastRadius: 1,
    reversibility: "high",
    estRiskDelta: -4,
    trigger: function (ctx) { return !ctx.flags.lowMotion && ctx.currentDifficulty >= 6; },
    reason: function () { return "Animated challenges at difficulty >=6 without reduced-motion respect"; },
  },
  {
    id: "WARM_CHALLENGE_CACHE",
    priority: "P1",
    label: "Warm challenge cache and CDN",
    owner: "platform",
    blastRadius: 2,
    reversibility: "high",
    estRiskDelta: -6,
    trigger: function (ctx) { return ctx.latencyMs > 2500; },
    reason: function (ctx) { return "P95 challenge latency " + Math.round(ctx.latencyMs) + "ms"; },
  },
  {
    id: "RAISE_TIMEOUT_THRESHOLD",
    priority: "P1",
    label: "Raise client-side timeout threshold",
    owner: "platform",
    blastRadius: 2,
    reversibility: "high",
    estRiskDelta: -5,
    trigger: function (ctx) { return ctx.timeoutRate > 0.05; },
    reason: function (ctx) { return "Timeout rate " + (ctx.timeoutRate * 100).toFixed(1) + "%"; },
  },
  {
    id: "SHORTEN_CHALLENGE_LENGTH",
    priority: "P2",
    label: "Shorten average challenge length",
    owner: "ux",
    blastRadius: 3,
    reversibility: "medium",
    estRiskDelta: -4,
    trigger: function (ctx) { return ctx.slowCohorts >= 2; },
    reason: function (ctx) { return ctx.slowCohorts + " cohorts have avg solve >12s"; },
  },
  {
    id: "SHOW_PROGRESS_INDICATOR",
    priority: "P2",
    label: "Show challenge progress indicator",
    owner: "ux",
    blastRadius: 1,
    reversibility: "high",
    estRiskDelta: -3,
    trigger: function (ctx) {
      var f = ctx.funnel;
      for (var i = 1; i < f.length; i++) {
        if (f[i - 1].stage === "started" && f[i].stage === "first_interaction") {
          return f[i].dropOffPct > 25;
        }
      }
      return false;
    },
    reason: function () { return "Drop between started -> first_interaction >25%"; },
  },
  {
    id: "OFFER_RETRY_WITH_DIFFERENT_TYPE",
    priority: "P2",
    label: "Offer retry with a different challenge type",
    owner: "ux",
    blastRadius: 2,
    reversibility: "high",
    estRiskDelta: -4,
    trigger: function (ctx) { return ctx.highRetryCohorts >= 1; },
    reason: function (ctx) { return ctx.highRetryCohorts + " cohort(s) with retryRate >30%"; },
  },
];

function _buildPlaybook(ctx, cohortVerdicts) {
  var actions = [];
  var seen = {};
  ACTION_CATALOGUE.forEach(function (def) {
    if (!def.trigger(ctx)) return;
    if (seen[def.id]) return;
    seen[def.id] = true;
    actions.push({
      id: def.id,
      priority: def.priority,
      label: def.label,
      reason: def.reason(ctx),
      owner: def.owner,
      blastRadius: def.blastRadius,
      reversibility: def.reversibility,
      estRiskDelta: def.estRiskDelta,
    });
  });
  // INVESTIGATE_COHORT per LOSING cohort.
  cohortVerdicts.forEach(function (cv) {
    if (cv.verdict !== "LOSING") return;
    actions.push({
      id: "INVESTIGATE_COHORT",
      priority: "P0",
      label: "Investigate losing cohort: " + cv.label,
      reason: "Cohort " + cv.label + " is below 50% completion",
      owner: "ux",
      blastRadius: 1,
      reversibility: "high",
      estRiskDelta: -3,
      meta: { cohortId: cv.id },
    });
  });
  // P0 first, stable within priority.
  var rank = { P0: 0, P1: 1, P2: 2 };
  actions.sort(function (a, b) { return rank[a.priority] - rank[b.priority]; });
  return actions;
}

function _insights(ctx, cohortVerdicts) {
  var out = [];
  if (ctx.mobile.triggered) {
    out.push("Mobile users are abandoning at " + Math.round(ctx.mobile.gap * 100) + " pts higher than desktop.");
  }
  var gaps = 0;
  ["hasAudioAlt", "hasTextAlt", "supportsScreenReader", "lowMotion"].forEach(function (k) {
    if (!ctx.flags[k]) gaps++;
  });
  if (gaps >= 2) out.push("Accessibility gap stack: " + gaps + " missing flags compound friction.");
  var contribs = ctx.contributions;
  var total = ctx.risk || 1;
  if (contribs.latency / total > 0.30 && contribs.latency >= 10) {
    out.push("Latency is the dominant friction driver.");
  }
  if (contribs.difficulty / total > 0.30 && contribs.difficulty >= 10) {
    out.push("Difficulty-induced abandonment likely.");
  }
  if (contribs.cohortDispersion >= 15) {
    out.push("Cohort dispersion: one or more underserved segments dragging the portfolio.");
  }
  var losing = cohortVerdicts.filter(function (cv) { return cv.verdict === "LOSING"; });
  if (losing.length >= 1) {
    out.push(losing.length + " cohort(s) classified LOSING (completion <50%).");
  }
  return out;
}

function _primaryDriver(contribs) {
  var keys = Object.keys(contribs);
  var best = keys[0];
  for (var i = 1; i < keys.length; i++) {
    if (contribs[keys[i]] > contribs[best]) best = keys[i];
  }
  return best;
}

function createUserAbandonmentForecaster(opts) {
  opts = opts || {};
  var riskAppetite = opts.riskAppetite || "balanced";
  if (["cautious", "balanced", "aggressive"].indexOf(riskAppetite) < 0) {
    throw new TypeError("riskAppetite must be cautious|balanced|aggressive");
  }

  function analyze(input) {
    _validate(input);
    var funnel = _computeFunnel(input.funnelStages);
    var flags = input.accessibilityFlags || {};
    var latencyMs = isFiniteNum(input.recentLatencyP95Ms) ? input.recentLatencyP95Ms : 0;
    var timeoutRate = isFiniteNum(input.recentTimeoutRate) ? input.recentTimeoutRate : 0;
    var difficulty = isFiniteNum(input.currentDifficulty) ? input.currentDifficulty : 5;

    var mobile = _mobilePenalty(input.deviceMixSample);
    var contribs = {
      funnel: _funnelContribution(funnel),
      difficulty: _difficultyContribution(difficulty),
      latency: _latencyContribution(latencyMs),
      timeout: _timeoutContribution(timeoutRate),
      accessibility: _accessibilityContribution(flags),
      mobile: mobile.value,
      cohortDispersion: _cohortDispersion(input.cohorts),
    };
    // Weighted blend into 0..100. Use a saturating sum.
    var raw = contribs.funnel * 0.45
      + contribs.difficulty * 0.20
      + contribs.latency * 0.40
      + contribs.timeout * 0.40
      + contribs.accessibility * 0.50
      + contribs.mobile * 0.50
      + contribs.cohortDispersion * 0.60;
    var risk = clamp(Math.round(raw), 0, 100);

    var cuts = _bandCutoffs(riskAppetite);
    var band = _classifyBand(risk, cuts);
    var grade = _gradeFromBand(band);

    var cohortVerdicts = (input.cohorts || []).map(_classifyCohort);

    // Hard floor: catastrophic mobile gap -> F
    if (mobile.gap > 0.25) grade = "F";

    var slowCohorts = cohortVerdicts.filter(function (cv) {
      return cv.reasons.indexOf("SLOW_COMPLETION") >= 0;
    }).length;
    var highRetryCohorts = cohortVerdicts.filter(function (cv) {
      return cv.reasons.indexOf("HIGH_RETRY") >= 0;
    }).length;
    var hasLosingCohort = cohortVerdicts.some(function (cv) { return cv.verdict === "LOSING"; });

    var ctx = {
      risk: risk,
      currentDifficulty: difficulty,
      flags: {
        hasAudioAlt: !!flags.hasAudioAlt,
        hasTextAlt: !!flags.hasTextAlt,
        supportsScreenReader: !!flags.supportsScreenReader,
        lowMotion: !!flags.lowMotion,
      },
      latencyMs: latencyMs,
      timeoutRate: timeoutRate,
      mobile: mobile,
      funnel: funnel,
      slowCohorts: slowCohorts,
      highRetryCohorts: highRetryCohorts,
      hasLosingCohort: hasLosingCohort,
      contributions: contribs,
    };
    var playbook = _buildPlaybook(ctx, cohortVerdicts);
    var insights = _insights(ctx, cohortVerdicts);

    return {
      abandonmentRisk: risk,
      band: band,
      grade: grade,
      funnel: funnel,
      contributions: contribs,
      cohortVerdicts: cohortVerdicts,
      playbook: playbook,
      insights: insights,
      summary: {
        primaryDriver: _primaryDriver(contribs),
        riskAppetite: riskAppetite,
      },
    };
  }

  function simulate(report, opts2) {
    if (!report || !Array.isArray(report.playbook)) {
      throw new TypeError("simulate() requires a report returned by analyze()");
    }
    opts2 = opts2 || {};
    var n = isFiniteNum(opts2.applyTop) ? Math.max(0, Math.floor(opts2.applyTop)) : 3;
    var top = report.playbook.slice(0, n);
    var risk = report.abandonmentRisk;
    var applied = [];
    for (var i = 0; i < top.length; i++) {
      var damp = Math.pow(0.85, i);
      var delta = top[i].estRiskDelta * damp;
      risk += delta;
      applied.push({ id: top[i].id, projectedDelta: Math.round(delta * 10) / 10 });
    }
    risk = clamp(Math.round(risk), 0, 100);
    var cuts = _bandCutoffs(riskAppetite);
    var band = _classifyBand(risk, cuts);
    return {
      abandonmentRisk: risk,
      band: band,
      grade: _gradeFromBand(band),
      appliedActions: applied,
    };
  }

  // ��� Renderers ���
  function formatText(report) {
    var lines = [];
    lines.push("USER ABANDONMENT FORECAST");
    lines.push("=========================");
    lines.push("Risk: " + report.abandonmentRisk + "/100  Band: " + report.band + "  Grade: " + report.grade);
    lines.push("Primary driver: " + report.summary.primaryDriver + "  (appetite: " + report.summary.riskAppetite + ")");
    lines.push("");
    lines.push("Cohort verdicts (top 5):");
    report.cohortVerdicts.slice(0, 5).forEach(function (cv) {
      lines.push("  - [" + cv.verdict + "] " + cv.label + (cv.reasons.length ? "  (" + cv.reasons.join(", ") + ")" : ""));
    });
    lines.push("");
    lines.push("Playbook (top 10):");
    report.playbook.slice(0, 10).forEach(function (a) {
      lines.push("  [" + a.priority + "] " + a.label + "  - " + a.reason + "  (owner=" + a.owner + ", deltaRisk=" + a.estRiskDelta + ")");
    });
    if (report.insights.length) {
      lines.push("");
      lines.push("Insights:");
      report.insights.forEach(function (s) { lines.push("  * " + s); });
    }
    return lines.join("\n");
  }

  function formatMarkdown(report) {
    var lines = [];
    lines.push("# User Abandonment Forecast");
    lines.push("");
    lines.push("## Summary");
    lines.push("");
    lines.push("- **Risk:** " + report.abandonmentRisk + "/100");
    lines.push("- **Band:** " + report.band);
    lines.push("- **Grade:** " + report.grade);
    lines.push("- **Primary driver:** " + report.summary.primaryDriver);
    lines.push("- **Risk appetite:** " + report.summary.riskAppetite);
    lines.push("");
    lines.push("## Risk Breakdown");
    lines.push("");
    lines.push("| Contribution | Value |");
    lines.push("|---|---|");
    Object.keys(report.contributions).forEach(function (k) {
      lines.push("| " + k + " | " + Math.round(report.contributions[k] * 10) / 10 + " |");
    });
    lines.push("");
    lines.push("## Cohort Verdicts");
    lines.push("");
    lines.push("| Cohort | Verdict | Reasons |");
    lines.push("|---|---|---|");
    report.cohortVerdicts.forEach(function (cv) {
      lines.push("| " + cv.label + " | " + cv.verdict + " | " + cv.reasons.join(", ") + " |");
    });
    lines.push("");
    lines.push("## Playbook");
    lines.push("");
    report.playbook.forEach(function (a) {
      lines.push("- **[" + a.priority + "] " + a.label + "** - " + a.reason + " _(owner: " + a.owner + ", delta: " + a.estRiskDelta + ")_");
    });
    if (report.insights.length) {
      lines.push("");
      lines.push("## Insights");
      lines.push("");
      report.insights.forEach(function (s) { lines.push("- " + s); });
    }
    return lines.join("\n");
  }

  function _sortedStringify(obj, indent) {
    var seen = new WeakSet();
    function helper(val) {
      if (val === null || typeof val !== "object") return val;
      if (seen.has(val)) return null;
      seen.add(val);
      if (Array.isArray(val)) return val.map(helper);
      var out = {};
      Object.keys(val).sort().forEach(function (k) { out[k] = helper(val[k]); });
      return out;
    }
    return JSON.stringify(helper(obj), null, indent);
  }

  function formatJson(report) {
    return _sortedStringify(report, 2);
  }

  return {
    analyze: analyze,
    simulate: simulate,
    formatText: formatText,
    formatMarkdown: formatMarkdown,
    formatJson: formatJson,
  };
}

module.exports = { createUserAbandonmentForecaster: createUserAbandonmentForecaster };
