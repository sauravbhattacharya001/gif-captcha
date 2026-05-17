/**
 * AttackResponsePlaybookGenerator - Agentic response planner for gif-captcha.
 *
 * Takes anomaly signals from CaptchaAnomalyDetector (or raw metrics) and
 * synthesizes a ranked, time-boxed response playbook: classifies the attack
 * profile, recommends concrete actions (with owner, ETA, predicted impact,
 * rollback steps), estimates confidence/blast radius, and can simulate what
 * happens if the top actions are applied.
 *
 * Designed to bridge the gap between "detector raises an anomaly" and "ops
 * actually does something about it" — without needing a human to translate
 * each signal into a checklist.
 *
 * Pure JS, no external dependencies. Works in Node 18+ and the browser.
 *
 * @example
 *   const { createAttackResponsePlaybook } = require('./attack-response-playbook');
 *   const planner = createAttackResponsePlaybook({ riskAppetite: 'balanced' });
 *
 *   const playbook = planner.generate({
 *     anomalies: [
 *       { type: 'solve_rate_drop', severity: 'high', value: 0.32, baseline: 0.78 },
 *       { type: 'traffic_spike', severity: 'critical', value: 9200, baseline: 1100 },
 *       { type: 'geo_shift', severity: 'medium', value: { from: 'US', to: 'RU' } }
 *     ],
 *     context: { currentRpm: 9200, openIncidents: 1, recentlyRotated: false }
 *   });
 *
 *   console.log(planner.formatAs(playbook, 'md'));
 *   const sim = planner.simulate(playbook, { applyTop: 3 });
 *
 * @module attack-response-playbook
 */

"use strict";

// ─── Attack profile classification ─────────────────────────────────
// Heuristic mapping of (anomaly type, severity) → attack archetype.
// Profiles are ordered from most-specific to most-general so the first
// match wins.

var ATTACK_PROFILES = [
  {
    id: "credential_stuffing",
    label: "Credential stuffing wave",
    indicators: ["solve_rate_drop", "failure_burst", "ip_concentration"],
    minIndicators: 2,
    description:
      "High volume of failed challenge attempts from a narrow IP/ASN range, " +
      "consistent with automated credential stuffing.",
  },
  {
    id: "distributed_bot_swarm",
    label: "Distributed bot swarm",
    indicators: ["traffic_spike", "fingerprint_collision", "geo_shift"],
    minIndicators: 2,
    description:
      "Spike in traffic with diverse but suspiciously similar fingerprints, " +
      "frequently from a new geography. Typical of botnet rentals.",
  },
  {
    id: "slow_burn_probe",
    label: "Slow-burn reconnaissance",
    indicators: ["response_time_drift", "solve_rate_drop"],
    minIndicators: 1,
    requiresAbsence: ["traffic_spike"],
    description:
      "Quiet, sustained drift in metrics with no traffic spike — likely a " +
      "low-and-slow probe trying to stay under rate-limit thresholds.",
  },
  {
    id: "volumetric_ddos",
    label: "Volumetric flood",
    indicators: ["traffic_spike", "response_time_drift"],
    minIndicators: 2,
    description:
      "Sudden traffic spike paired with response-time degradation. " +
      "Defenses should prioritize shedding load before solving identity.",
  },
  {
    id: "geo_shift_anomaly",
    label: "Geographic shift",
    indicators: ["geo_shift"],
    minIndicators: 1,
    description:
      "Traffic origin distribution changed materially. May indicate routing " +
      "via proxy/VPN pool, or a legitimate marketing wave.",
  },
  {
    id: "generic_degradation",
    label: "Generic health degradation",
    indicators: [],
    minIndicators: 0,
    description:
      "Anomalies present but no clean attack signature. Treat as health " +
      "incident and gather more telemetry before escalating.",
  },
];

// ─── Action catalogue ──────────────────────────────────────────────
// Each action declares: id, label, category, baseImpact (0–1 expected
// reduction of bad traffic / restoration of solve rate), effortMinutes,
// reversibility ('instant' | 'fast' | 'slow'), blastRadius
// ('targeted' | 'segment' | 'global'), owner, rollback steps, and
// the profile ids it applies to (or "*" for any).

var ACTION_CATALOG = [
  {
    id: "enable_pow",
    label: "Enable proof-of-work prefilter",
    category: "throttle",
    profiles: ["distributed_bot_swarm", "volumetric_ddos", "credential_stuffing"],
    baseImpact: 0.55,
    effortMinutes: 2,
    reversibility: "instant",
    blastRadius: "global",
    owner: "captcha-ops",
    rollback: ["Disable PoW via createProofOfWork({ enabled: false })"],
  },
  {
    id: "tighten_rate_limits",
    label: "Tighten per-IP/per-session rate limits",
    category: "throttle",
    profiles: ["credential_stuffing", "volumetric_ddos", "slow_burn_probe"],
    baseImpact: 0.45,
    effortMinutes: 3,
    reversibility: "instant",
    blastRadius: "segment",
    owner: "captcha-ops",
    rollback: ["Restore previous limits via createCaptchaRateLimiter.reset()"],
  },
  {
    id: "rotate_challenge_pool",
    label: "Rotate challenge pool & retire compromised templates",
    category: "rotate",
    profiles: ["distributed_bot_swarm", "credential_stuffing", "slow_burn_probe"],
    baseImpact: 0.5,
    effortMinutes: 10,
    reversibility: "fast",
    blastRadius: "global",
    owner: "challenge-curator",
    rollback: ["Re-enable previous templates from challenge-decay-manager snapshot"],
  },
  {
    id: "geo_throttle",
    label: "Throttle or challenge traffic from shifted geography",
    category: "geo",
    profiles: ["geo_shift_anomaly", "distributed_bot_swarm"],
    baseImpact: 0.35,
    effortMinutes: 5,
    reversibility: "fast",
    blastRadius: "segment",
    owner: "captcha-ops",
    rollback: ["Remove geo override in createGeoRiskScorer"],
  },
  {
    id: "raise_difficulty",
    label: "Raise adaptive difficulty floor by one tier",
    category: "difficulty",
    profiles: ["credential_stuffing", "distributed_bot_swarm", "slow_burn_probe"],
    baseImpact: 0.3,
    effortMinutes: 1,
    reversibility: "instant",
    blastRadius: "global",
    owner: "captcha-ops",
    rollback: ["createAdaptiveDifficultyTuner.lowerFloor()"],
  },
  {
    id: "enable_honeypots",
    label: "Inject honeypot challenges to fingerprint bots",
    category: "intel",
    profiles: ["credential_stuffing", "distributed_bot_swarm", "slow_burn_probe"],
    baseImpact: 0.2,
    effortMinutes: 4,
    reversibility: "fast",
    blastRadius: "targeted",
    owner: "captcha-research",
    rollback: ["Disable via createHoneypotInjector({ enabled: false })"],
  },
  {
    id: "open_incident",
    label: "Open a tracked incident & page on-call",
    category: "incident",
    profiles: ["*"],
    baseImpact: 0.0,
    effortMinutes: 2,
    reversibility: "instant",
    blastRadius: "targeted",
    owner: "on-call",
    rollback: ["mgr.resolve(id, { resolution: 'false alarm' })"],
  },
  {
    id: "snapshot_telemetry",
    label: "Snapshot telemetry for forensic review",
    category: "intel",
    profiles: ["*"],
    baseImpact: 0.0,
    effortMinutes: 3,
    reversibility: "instant",
    blastRadius: "targeted",
    owner: "captcha-research",
    rollback: ["No rollback needed — read-only snapshot"],
  },
  {
    id: "shed_load",
    label: "Shed 25% of incoming requests at the edge",
    category: "throttle",
    profiles: ["volumetric_ddos"],
    baseImpact: 0.6,
    effortMinutes: 1,
    reversibility: "instant",
    blastRadius: "global",
    owner: "edge-ops",
    rollback: ["Restore full admission via edge config rollback"],
  },
];

// ─── Risk-appetite tuning ──────────────────────────────────────────
// Multipliers applied to action scoring.

var RISK_PRESETS = {
  cautious: { impactWeight: 0.5, effortPenalty: 1.4, blastPenalty: 1.6 },
  balanced: { impactWeight: 1.0, effortPenalty: 1.0, blastPenalty: 1.0 },
  aggressive: { impactWeight: 1.4, effortPenalty: 0.7, blastPenalty: 0.6 },
};

var SEVERITY_WEIGHT = { low: 0.25, medium: 0.5, high: 0.8, critical: 1.0 };

function _clamp(x, lo, hi) {
  if (x < lo) return lo;
  if (x > hi) return hi;
  return x;
}

function _severityWeight(sev) {
  return SEVERITY_WEIGHT[String(sev || "").toLowerCase()] || 0.4;
}

function _blastPenalty(radius) {
  if (radius === "global") return 1.0;
  if (radius === "segment") return 0.5;
  return 0.2; // targeted
}

function _matchProfile(anomalies) {
  var indicatorSet = {};
  anomalies.forEach(function (a) {
    if (a && a.type) indicatorSet[a.type] = true;
  });

  for (var i = 0; i < ATTACK_PROFILES.length; i++) {
    var p = ATTACK_PROFILES[i];
    if (p.requiresAbsence) {
      var blocked = p.requiresAbsence.some(function (t) { return !!indicatorSet[t]; });
      if (blocked) continue;
    }
    if (p.minIndicators === 0) return p; // generic fallback
    var matches = p.indicators.filter(function (t) { return !!indicatorSet[t]; }).length;
    if (matches >= p.minIndicators) return p;
  }
  return ATTACK_PROFILES[ATTACK_PROFILES.length - 1];
}

function _overallSeverity(anomalies) {
  if (!anomalies.length) return 0;
  var max = 0;
  var sum = 0;
  anomalies.forEach(function (a) {
    var w = _severityWeight(a && a.severity);
    if (w > max) max = w;
    sum += w;
  });
  // Blend peak with breadth so a single critical doesn't drown out 5 mediums.
  return _clamp(0.65 * max + 0.35 * (sum / anomalies.length), 0, 1);
}

function _scoreAction(action, profile, severity, risk, context) {
  var profileFit =
    action.profiles.indexOf("*") !== -1 ||
    action.profiles.indexOf(profile.id) !== -1
      ? 1.0
      : 0.3;

  var impact = action.baseImpact * risk.impactWeight * (0.5 + 0.5 * severity);
  var effortCost = (action.effortMinutes / 10) * risk.effortPenalty;
  var blastCost = _blastPenalty(action.blastRadius) * risk.blastPenalty;

  // Context modifiers
  if (context && context.recentlyRotated && action.id === "rotate_challenge_pool") {
    impact *= 0.4; // recently rotated → diminishing returns
  }
  if (context && context.openIncidents > 0 && action.id === "open_incident") {
    impact -= 0.2; // already an open incident
  }

  var raw = profileFit * impact - 0.15 * effortCost - 0.2 * blastCost;
  return _clamp(raw, -1, 1);
}

function _priorityBucket(score) {
  if (score >= 0.55) return "P0";
  if (score >= 0.35) return "P1";
  if (score >= 0.15) return "P2";
  return "P3";
}

function _confidence(profile, anomalies) {
  if (profile.minIndicators === 0) return 0.35; // generic fallback
  var hits = profile.indicators.filter(function (t) {
    return anomalies.some(function (a) { return a && a.type === t; });
  }).length;
  var ratio = profile.indicators.length
    ? hits / profile.indicators.length
    : 0.5;
  return _clamp(0.4 + 0.5 * ratio, 0, 0.95);
}

function _validateOptions(opts) {
  var risk = (opts && opts.riskAppetite) || "balanced";
  if (!RISK_PRESETS[risk]) {
    throw new Error(
      "riskAppetite must be one of: cautious, balanced, aggressive (got '" +
        risk + "')"
    );
  }
  return { riskAppetite: risk, maxActions: (opts && opts.maxActions) || 8 };
}

function _validateInput(input) {
  if (!input || typeof input !== "object") {
    throw new TypeError("generate() requires an object with 'anomalies'");
  }
  var anomalies = input.anomalies;
  if (!Array.isArray(anomalies)) {
    throw new TypeError("'anomalies' must be an array");
  }
  anomalies.forEach(function (a, i) {
    if (!a || typeof a.type !== "string") {
      throw new TypeError("anomalies[" + i + "].type must be a string");
    }
  });
  return { anomalies: anomalies, context: input.context || {} };
}

// ─── Public factory ─────────────────────────────────────────────────

function createAttackResponsePlaybook(options) {
  var opts = _validateOptions(options);

  function generate(input) {
    var v = _validateInput(input);
    var profile = _matchProfile(v.anomalies);
    var severity = _overallSeverity(v.anomalies);
    var confidence = _confidence(profile, v.anomalies);
    var risk = RISK_PRESETS[opts.riskAppetite];

    var scored = ACTION_CATALOG.map(function (a) {
      var s = _scoreAction(a, profile, severity, risk, v.context);
      return {
        id: a.id,
        label: a.label,
        category: a.category,
        score: Number(s.toFixed(3)),
        priority: _priorityBucket(s),
        etaMinutes: a.effortMinutes,
        reversibility: a.reversibility,
        blastRadius: a.blastRadius,
        owner: a.owner,
        predictedImpact: Number(
          (a.baseImpact * (0.5 + 0.5 * severity)).toFixed(2)
        ),
        rollback: a.rollback.slice(),
      };
    });

    scored.sort(function (a, b) {
      if (b.score !== a.score) return b.score - a.score;
      return a.etaMinutes - b.etaMinutes;
    });

    var recommended = scored.filter(function (a) {
      return a.score > 0;
    }).slice(0, opts.maxActions);

    return {
      generatedAt: Date.now(),
      profile: {
        id: profile.id,
        label: profile.label,
        description: profile.description,
        confidence: Number(confidence.toFixed(2)),
      },
      severity: Number(severity.toFixed(2)),
      anomaliesConsidered: v.anomalies.length,
      riskAppetite: opts.riskAppetite,
      actions: recommended,
      rejected: scored.filter(function (a) { return a.score <= 0; }).length,
    };
  }

  function simulate(playbook, simOpts) {
    if (!playbook || !Array.isArray(playbook.actions)) {
      throw new TypeError("simulate() requires a playbook with 'actions'");
    }
    var applyTop = (simOpts && simOpts.applyTop) || playbook.actions.length;
    var slice = playbook.actions.slice(0, applyTop);

    // Diminishing-returns combination: 1 - Π(1 - impact_i)
    var residual = 1;
    slice.forEach(function (a) {
      residual *= 1 - _clamp(a.predictedImpact, 0, 1);
    });
    var projectedReduction = 1 - residual;
    var totalEta = slice.reduce(function (acc, a) { return acc + a.etaMinutes; }, 0);
    var hasGlobal = slice.some(function (a) { return a.blastRadius === "global"; });

    return {
      appliedActions: slice.length,
      projectedReduction: Number(projectedReduction.toFixed(2)),
      projectedResidualRisk: Number((1 - projectedReduction).toFixed(2)),
      totalEtaMinutes: totalEta,
      affectsAllUsers: hasGlobal,
      summary:
        slice.length === 0
          ? "No actions selected — no projected change."
          : "Applying top " + slice.length + " action(s) projected to reduce " +
            "bad traffic by ~" + Math.round(projectedReduction * 100) + "% over " +
            totalEta + " min" + (hasGlobal ? " (global blast radius)." : "."),
    };
  }

  function explain(playbook) {
    if (!playbook) return "";
    return (
      "Profile: " + playbook.profile.label +
      " (confidence " + Math.round(playbook.profile.confidence * 100) + "%). " +
      "Severity " + playbook.severity + "/1.0 across " +
      playbook.anomaliesConsidered + " anomaly signal(s). " +
      "Risk appetite: " + playbook.riskAppetite + ". " +
      playbook.actions.length + " action(s) recommended, " +
      playbook.rejected + " rejected by scoring."
    );
  }

  function formatAs(playbook, format) {
    var fmt = String(format || "md").toLowerCase();
    if (fmt === "json") return JSON.stringify(playbook, null, 2);
    if (fmt === "text") return _formatText(playbook);
    if (fmt === "csv") return _formatCsv(playbook);
    if (fmt === "md" || fmt === "markdown") return _formatMd(playbook);
    throw new Error("Unknown format: " + format + " (use md|json|text|csv)");
  }

  return {
    generate: generate,
    simulate: simulate,
    explain: explain,
    formatAs: formatAs,
    // Read-only introspection for tests / docs
    listProfiles: function () { return ATTACK_PROFILES.map(function (p) { return p.id; }); },
    listActions: function () { return ACTION_CATALOG.map(function (a) { return a.id; }); },
  };
}

// ─── Formatters ─────────────────────────────────────────────────────

function _formatMd(p) {
  var lines = [];
  lines.push("# Attack Response Playbook");
  lines.push("");
  lines.push("- **Profile:** " + p.profile.label +
    " (`" + p.profile.id + "`, confidence " +
    Math.round(p.profile.confidence * 100) + "%)");
  lines.push("- **Severity:** " + p.severity + " / 1.0");
  lines.push("- **Risk appetite:** " + p.riskAppetite);
  lines.push("- **Signals considered:** " + p.anomaliesConsidered);
  lines.push("");
  lines.push("> " + p.profile.description);
  lines.push("");
  if (!p.actions.length) {
    lines.push("_No actions scored above threshold — gather more telemetry._");
    return lines.join("\n");
  }
  lines.push("## Recommended Actions");
  lines.push("");
  lines.push("| # | Priority | Action | Owner | ETA | Reversibility | Blast |");
  lines.push("|---|----------|--------|-------|-----|---------------|-------|");
  p.actions.forEach(function (a, i) {
    lines.push("| " + (i + 1) + " | " + a.priority + " | " + a.label +
      " | " + a.owner + " | " + a.etaMinutes + "m | " + a.reversibility +
      " | " + a.blastRadius + " |");
  });
  lines.push("");
  lines.push("## Rollback Steps");
  lines.push("");
  p.actions.forEach(function (a, i) {
    lines.push("### " + (i + 1) + ". " + a.label);
    a.rollback.forEach(function (step) {
      lines.push("- " + step);
    });
  });
  return lines.join("\n");
}

function _formatText(p) {
  var out = [];
  out.push("Attack Response Playbook");
  out.push("Profile: " + p.profile.label + " (confidence " +
    Math.round(p.profile.confidence * 100) + "%)");
  out.push("Severity: " + p.severity + "  Risk appetite: " + p.riskAppetite);
  out.push("");
  if (!p.actions.length) {
    out.push("No actions recommended.");
    return out.join("\n");
  }
  p.actions.forEach(function (a, i) {
    out.push((i + 1) + ". [" + a.priority + "] " + a.label);
    out.push("   owner=" + a.owner + " eta=" + a.etaMinutes + "m" +
      " reversibility=" + a.reversibility + " blast=" + a.blastRadius +
      " impact=" + a.predictedImpact);
  });
  return out.join("\n");
}

function _csvField(v) {
  var s = String(v == null ? "" : v);
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function _formatCsv(p) {
  var rows = [
    ["rank", "priority", "id", "label", "owner", "eta_minutes",
     "reversibility", "blast_radius", "predicted_impact", "score"].join(","),
  ];
  p.actions.forEach(function (a, i) {
    rows.push([
      i + 1, a.priority, a.id, _csvField(a.label), a.owner, a.etaMinutes,
      a.reversibility, a.blastRadius, a.predictedImpact, a.score,
    ].join(","));
  });
  return rows.join("\n");
}

module.exports = {
  createAttackResponsePlaybook: createAttackResponsePlaybook,
  // Exposed for unit testing / advanced users
  _internals: {
    ATTACK_PROFILES: ATTACK_PROFILES,
    ACTION_CATALOG: ACTION_CATALOG,
    RISK_PRESETS: RISK_PRESETS,
  },
};
