/**
 * AttackForecaster - Proactive escalation forecaster for gif-captcha.
 *
 * The reactive counterpart to this module is AttackResponsePlaybookGenerator,
 * which answers: "given the anomalies happening *right now*, what should ops
 * do?". AttackForecaster answers the prior question:
 *
 *   "Given the last N minutes of anomaly + metric snapshots, what is the
 *    probability that we will be in a worse state in T minutes from now,
 *    which attack profile is rising, how much lead time do we have before
 *    SLA breach, and what pre-emptive actions would dampen that forecast?"
 *
 * The goal is to flip the team's posture from reactive ("fight the fire that
 * is here") to anticipatory ("the curves are bending; pre-stage these three
 * cheap mitigations so we never need to fight the fire at all"). It is
 * designed to feed directly into AttackResponsePlaybookGenerator: the
 * pre-emptive actions it recommends are drawn from the same playbook
 * vocabulary, just selected for "buy time / dampen trajectory" rather than
 * "stop the active attack".
 *
 * No external dependencies. Deterministic. Works in Node 18+ and the browser.
 *
 * @example
 *   const { createAttackForecaster } = require('./attack-forecaster');
 *   const fc = createAttackForecaster({ horizonMinutes: 15, riskAppetite: 'balanced' });
 *
 *   // Push periodic snapshots (e.g. once per minute from your detector)
 *   fc.recordSnapshot({
 *     timestamp: Date.now() - 5 * 60_000,
 *     anomalies: [{ type: 'traffic_spike', severity: 'low' }],
 *     metrics: { trafficRpm: 1400, solveRate: 0.74, p95Duration: 2600, errorRate: 0.04, geoEntropy: 2.1 }
 *   });
 *   // ...more snapshots...
 *
 *   const report = fc.forecast();
 *   console.log(fc.formatAs(report, 'md'));
 *
 *   // What if we pre-stage the top 2 cheap mitigations now?
 *   const sim = fc.simulate(report, { applyTop: 2 });
 *
 * @module attack-forecaster
 */

"use strict";

// ── Metric trajectory thresholds ─────────────────────────────────────
// These are the "would breach" lines we project against. Each entry
// declares the metric key, the direction that is bad ('up' or 'down'),
// the breach value, and the per-minute "alarming slope" used as a
// soft normalising scale (so a metric moving at exactly that slope
// contributes ~1.0 to the breach margin per minute of horizon).
var METRIC_THRESHOLDS = {
  trafficRpm:   { dir: "up",   breach: 5000, slope: 200,  weight: 1.0, label: "Traffic (req/min)" },
  solveRate:    { dir: "down", breach: 0.55, slope: 0.02, weight: 1.0, label: "Solve rate" },
  p95Duration:  { dir: "up",   breach: 4000, slope: 150,  weight: 0.8, label: "p95 challenge duration (ms)" },
  errorRate:    { dir: "up",   breach: 0.15, slope: 0.01, weight: 0.9, label: "Error rate" },
  geoEntropy:   { dir: "down", breach: 1.2,  slope: 0.05, weight: 0.5, label: "Geographic entropy (nats)" },
};

// ── Anomaly-type → profile bias ───────────────────────────────────
// Used for forecasting which profile is *rising*, independent of which
// profile the AttackResponsePlaybookGenerator would pick for the
// current instant. Each indicator contributes to one or more profiles
// with a weight in [0,1].
var PROFILE_BIAS = {
  solve_rate_drop:        { credential_stuffing: 0.6, slow_burn_probe: 0.5, generic_degradation: 0.2 },
  failure_burst:          { credential_stuffing: 0.7, generic_degradation: 0.2 },
  ip_concentration:       { credential_stuffing: 0.6 },
  traffic_spike:          { distributed_bot_swarm: 0.55, volumetric_ddos: 0.7 },
  fingerprint_collision:  { distributed_bot_swarm: 0.65 },
  geo_shift:              { geo_shift_anomaly: 0.7, distributed_bot_swarm: 0.4 },
  response_time_drift:    { volumetric_ddos: 0.55, slow_burn_probe: 0.45, generic_degradation: 0.2 },
};

var PROFILE_LABELS = {
  credential_stuffing:    "Credential stuffing wave",
  distributed_bot_swarm:  "Distributed bot swarm",
  slow_burn_probe:        "Slow-burn reconnaissance",
  volumetric_ddos:        "Volumetric flood",
  geo_shift_anomaly:      "Geographic shift",
  generic_degradation:    "Generic health degradation",
};

// ── Pre-emptive action catalogue ─────────────────────────────────
// Distinct from ACTION_CATALOG in attack-response-playbook.js: these
// are dampener moves chosen specifically because they are cheap, fast,
// reversible, and *reduce trajectory* (lowering slope or pushing the
// breach threshold further out) without committing to a full
// containment posture. Each action declares which forecasted profile
// it dampens, the expected slope dampening per metric (multiplier in
// [0,1] applied to the projected slope), effort, blast radius, and the
// owner who needs to be paged to actually do it.
var PREEMPTIVE_ACTIONS = [
  {
    id: "warm_pow_cache",
    label: "Pre-warm proof-of-work cache (no user impact yet)",
    profiles: ["distributed_bot_swarm", "volumetric_ddos", "credential_stuffing"],
    dampens: { trafficRpm: 0.85, errorRate: 0.9 },
    effortMinutes: 2,
    blastRadius: "targeted",
    reversibility: "instant",
    owner: "captcha-ops",
    note: "Loads PoW worker pool so a switch-on later takes <100ms.",
  },
  {
    id: "stage_rate_limit_template",
    label: "Stage tighter rate-limit template (do not enable)",
    profiles: ["credential_stuffing", "volumetric_ddos", "slow_burn_probe"],
    dampens: { trafficRpm: 0.9, errorRate: 0.95 },
    effortMinutes: 3,
    blastRadius: "targeted",
    reversibility: "instant",
    owner: "captcha-ops",
    note: "createCaptchaRateLimiter.stage(profile) - one-click apply.",
  },
  {
    id: "increase_sampling",
    label: "Raise telemetry sampling rate 5× for next 30 min",
    profiles: ["slow_burn_probe", "geo_shift_anomaly", "generic_degradation"],
    dampens: { /* observation only; no trajectory dampening */ },
    effortMinutes: 1,
    blastRadius: "targeted",
    reversibility: "instant",
    owner: "captcha-research",
    note: "Reduces uncertainty band on next forecast cycle.",
  },
  {
    id: "preload_geo_overrides",
    label: "Pre-load geo-throttle overrides for rising regions",
    profiles: ["geo_shift_anomaly", "distributed_bot_swarm"],
    dampens: { trafficRpm: 0.92, geoEntropy: 1.05 },
    effortMinutes: 4,
    blastRadius: "targeted",
    reversibility: "fast",
    owner: "captcha-ops",
    note: "createGeoRiskScorer.preloadOverrides([...]) - inert until armed.",
  },
  {
    id: "raise_difficulty_one_notch",
    label: "Raise adaptive difficulty floor by one notch (soft)",
    profiles: ["credential_stuffing", "distributed_bot_swarm", "slow_burn_probe"],
    dampens: { solveRate: 1.05, errorRate: 1.02 }, // mild downside on solveRate slope
    effortMinutes: 1,
    blastRadius: "segment",
    reversibility: "instant",
    owner: "captcha-ops",
    note: "Trades ~3% human friction for slope reduction on bots.",
  },
  {
    id: "notify_oncall_pre_alert",
    label: "Send pre-alert to on-call (informational, no page)",
    profiles: ["*"],
    dampens: {},
    effortMinutes: 1,
    blastRadius: "targeted",
    reversibility: "instant",
    owner: "captcha-ops",
    note: "Shrinks human response latency if the forecast resolves true.",
  },
  {
    id: "snapshot_baseline",
    label: "Snapshot current baseline for post-incident diff",
    profiles: ["*"],
    dampens: {},
    effortMinutes: 2,
    blastRadius: "targeted",
    reversibility: "instant",
    owner: "captcha-research",
    note: "Cheap, always-correct — never harmful to do early.",
  },
  {
    id: "prime_honeypots",
    label: "Prime honeypot challenges (load templates, do not inject)",
    profiles: ["credential_stuffing", "distributed_bot_swarm", "slow_burn_probe"],
    dampens: {},
    effortMinutes: 3,
    blastRadius: "targeted",
    reversibility: "instant",
    owner: "captcha-research",
    note: "Cuts time-to-fingerprint when actual injection is needed.",
  },
];

// ── Risk-appetite tuning ─────────────────────────────────────────
// These shift two things:
//   1. The probability threshold for each forecast band.
//   2. The score weighting (cautious values dampening more aggressively;
//      aggressive tolerates more risk before pre-staging).
var RISK_PRESETS = {
  cautious:   { bandShift: -0.10, dampenWeight: 1.3, effortPenalty: 0.7, maxActions: 5 },
  balanced:   { bandShift:  0.00, dampenWeight: 1.0, effortPenalty: 1.0, maxActions: 4 },
  aggressive: { bandShift: +0.10, dampenWeight: 0.7, effortPenalty: 1.3, maxActions: 3 },
};

var BANDS = [
  { id: "calm",      label: "Calm",      minProb: 0.00 },
  { id: "watch",     label: "Watch",     minProb: 0.30 },
  { id: "elevated",  label: "Elevated",  minProb: 0.50 },
  { id: "high",      label: "High",      minProb: 0.70 },
  { id: "critical",  label: "Critical",  minProb: 0.85 },
];

var SEVERITY_WEIGHT = { low: 0.25, medium: 0.5, high: 0.8, critical: 1.0 };

// ── Helpers ─────────────────────────────────────────────────────
function _clamp(x, lo, hi) {
  if (typeof x !== "number" || !isFinite(x)) return lo;
  if (x < lo) return lo;
  if (x > hi) return hi;
  return x;
}

function _sigmoid(x) { return 1 / (1 + Math.exp(-x)); }

function _severityWeight(sev) {
  return SEVERITY_WEIGHT[String(sev || "").toLowerCase()] || 0.4;
}

// Simple linear regression returning {slope, intercept} on points
// [{x, y}]. Slope is units-of-y per unit-of-x (minutes). Safe with <2
// points: slope=0, intercept=last-y.
function _linregress(points) {
  var n = points.length;
  if (n === 0) return { slope: 0, intercept: 0 };
  if (n === 1) return { slope: 0, intercept: points[0].y };
  var sx = 0, sy = 0, sxy = 0, sxx = 0;
  for (var i = 0; i < n; i++) {
    sx += points[i].x; sy += points[i].y;
    sxy += points[i].x * points[i].y;
    sxx += points[i].x * points[i].x;
  }
  var denom = (n * sxx) - (sx * sx);
  if (denom === 0) return { slope: 0, intercept: sy / n };
  var slope = ((n * sxy) - (sx * sy)) / denom;
  var intercept = (sy - slope * sx) / n;
  return { slope: slope, intercept: intercept };
}

// Compute breach margin contribution for a single metric:
//   - direction-aware "how many alarming-slope-equivalents" the projected
//     value is past the breach threshold.
// Returns { contribution, current, projected, slopePerMin, leadTimeMin }
function _projectMetric(metricKey, snapshots, horizonMinutes) {
  var thresh = METRIC_THRESHOLDS[metricKey];
  if (!thresh) return null;

  // Build (minutesAgo, value) points where x is minutes-from-now (newest = 0).
  var pts = [];
  var now = snapshots[snapshots.length - 1].timestamp;
  for (var i = 0; i < snapshots.length; i++) {
    var v = snapshots[i].metrics ? snapshots[i].metrics[metricKey] : undefined;
    if (typeof v !== "number" || !isFinite(v)) continue;
    var minutes = (snapshots[i].timestamp - now) / 60000; // newest = 0, older = negative
    pts.push({ x: minutes, y: v });
  }
  if (pts.length === 0) return null;

  var reg = _linregress(pts);
  var current = pts[pts.length - 1].y;
  var projected = reg.intercept + reg.slope * horizonMinutes; // x=horizon
  // (intercept is value-at-x=0; slope is per-minute toward the future)

  // Direction-aware breach distance & margin in slope-equivalents.
  var distNow, distProjected;
  if (thresh.dir === "up") {
    distNow = thresh.breach - current;       // positive = still safe
    distProjected = thresh.breach - projected;
  } else {
    distNow = current - thresh.breach;       // positive = still safe
    distProjected = projected - thresh.breach;
  }

  // Contribution: how far past the line (in slope-equivalents) the
  // *projected* value sits. Negative means safe. We clamp the safe
  // side gently so far-from-breach metrics don't crowd out a single
  // metric that is genuinely trending toward breach.
  var contribution = _clamp(-distProjected / Math.max(thresh.slope, 1e-9), -1, 6);

  // Lead time: when does the trajectory cross the threshold?
  var leadTimeMin = null;
  if (distNow > 0) {
    // currently safe; compute crossing time if slope is moving badly
    var movingBadly = (thresh.dir === "up" && reg.slope > 0) || (thresh.dir === "down" && reg.slope < 0);
    if (movingBadly) {
      var absSlope = Math.abs(reg.slope);
      if (absSlope > 0) leadTimeMin = distNow / absSlope;
    }
  } else {
    leadTimeMin = 0; // already breached
  }

  return {
    key: metricKey,
    label: thresh.label,
    weight: thresh.weight,
    direction: thresh.dir,
    breach: thresh.breach,
    current: current,
    projected: projected,
    slopePerMin: reg.slope,
    leadTimeMin: leadTimeMin,
    contribution: contribution,
  };
}

// Score how much each profile is "rising" by weighting anomalies by
// recency (newest snapshots weigh more) and severity.
function _projectProfiles(snapshots) {
  var scores = {}; // profile → weighted score
  var n = snapshots.length;
  for (var i = 0; i < n; i++) {
    var recencyWeight = (i + 1) / n; // 1/n .. 1.0
    var anoms = snapshots[i].anomalies || [];
    for (var j = 0; j < anoms.length; j++) {
      var a = anoms[j];
      if (!a || !a.type) continue;
      var bias = PROFILE_BIAS[a.type];
      if (!bias) continue;
      var sev = _severityWeight(a.severity);
      for (var profileId in bias) {
        if (Object.prototype.hasOwnProperty.call(bias, profileId)) {
          scores[profileId] = (scores[profileId] || 0) + bias[profileId] * sev * recencyWeight;
        }
      }
    }
  }
  return scores;
}

// ── Factory ──────────────────────────────────────────────────────
function createAttackForecaster(options) {
  options = options || {};

  var horizonMinutes  = options.horizonMinutes  || 15;
  var maxSnapshots    = options.maxSnapshots    || 60;
  var riskAppetite    = options.riskAppetite    || "balanced";
  var minSnapshots    = options.minSnapshots    || 3;
  var nowFn           = options.now             || function () { return Date.now(); };

  if (!RISK_PRESETS[riskAppetite]) riskAppetite = "balanced";

  var snapshots = [];

  function reset() { snapshots = []; }

  function recordSnapshot(snap) {
    if (!snap || typeof snap !== "object") return;
    var ts = (typeof snap.timestamp === "number") ? snap.timestamp : nowFn();
    var entry = {
      timestamp: ts,
      anomalies: Array.isArray(snap.anomalies) ? snap.anomalies.slice() : [],
      metrics: (snap.metrics && typeof snap.metrics === "object") ? Object.assign({}, snap.metrics) : {},
    };
    // Fast path: in normal operation timestamps are monotonically
    // non-decreasing (nowFn defaults to Date.now()), so we only need
    // to fix ordering when a caller pushes an older snapshot. This
    // avoids an O(n log n) sort on every recordSnapshot() call, which
    // dominated CPU when ingesting high-frequency telemetry.
    var n = snapshots.length;
    if (n === 0 || entry.timestamp >= snapshots[n - 1].timestamp) {
      snapshots.push(entry);
    } else {
      // Binary search for the correct insertion index, then splice.
      // Out-of-order arrivals are expected to be rare, so the splice
      // cost is acceptable and we keep the invariant cheaply.
      var lo = 0, hi = n;
      while (lo < hi) {
        var mid = (lo + hi) >>> 1;
        if (snapshots[mid].timestamp <= entry.timestamp) lo = mid + 1;
        else hi = mid;
      }
      snapshots.splice(lo, 0, entry);
    }
    // Keep newest, drop oldest if over cap.
    if (snapshots.length > maxSnapshots) {
      snapshots.splice(0, snapshots.length - maxSnapshots);
    }
  }

  function _bandForProb(prob) {
    var preset = RISK_PRESETS[riskAppetite];
    var adjusted = _clamp(prob - preset.bandShift, 0, 1);
    var pick = BANDS[0];
    for (var i = 0; i < BANDS.length; i++) {
      if (adjusted >= BANDS[i].minProb) pick = BANDS[i];
    }
    return pick;
  }

  function _rankPreemptiveActions(forecast) {
    var preset = RISK_PRESETS[riskAppetite];
    var topProfile = forecast.predictedProfile;
    var ranked = [];
    for (var i = 0; i < PREEMPTIVE_ACTIONS.length; i++) {
      var act = PREEMPTIVE_ACTIONS[i];
      var applies = act.profiles.indexOf("*") !== -1 || act.profiles.indexOf(topProfile) !== -1;
      if (!applies) continue;

      // Score: how much would this action dampen the projected
      // breach contribution if applied now? Sum across metrics it
      // dampens, weighted by the metric's contribution to the forecast.
      var dampenScore = 0;
      var dampensList = [];
      for (var key in act.dampens) {
        if (!Object.prototype.hasOwnProperty.call(act.dampens, key)) continue;
        var mult = act.dampens[key];
        var proj = forecast.metricProjections[key];
        if (!proj) continue;
        // Positive contribution means metric heading bad; multiplier
        // <1 dampens it; >1 slightly worsens. Score = contribution *
        // (1 - mult). Note: contribution can be negative (safe), in
        // which case we want to *not* count dampening as a benefit.
        var benefit = Math.max(0, proj.contribution) * (1 - mult);
        dampenScore += benefit * proj.weight;
        dampensList.push(key + " ×" + mult.toFixed(2));
      }
      dampenScore *= preset.dampenWeight;

      // Pure-intel actions (no dampening) still earn a baseline score
      // proportional to forecast probability — they reduce uncertainty.
      if (Object.keys(act.dampens).length === 0) {
        dampenScore = 0.15 * forecast.escalationProbability;
      }

      // Effort penalty (multiplicative).
      var effortFactor = 1 / (1 + (act.effortMinutes / 10) * preset.effortPenalty);
      var finalScore = dampenScore * effortFactor;

      ranked.push({
        id: act.id,
        label: act.label,
        owner: act.owner,
        effortMinutes: act.effortMinutes,
        blastRadius: act.blastRadius,
        reversibility: act.reversibility,
        note: act.note,
        dampens: dampensList,
        score: finalScore,
      });
    }
    ranked.sort(function (a, b) { return b.score - a.score; });
    // Cap by risk appetite.
    var cap = RISK_PRESETS[riskAppetite].maxActions;
    var top = ranked.slice(0, cap);
    // Assign P0/P1/P2 priorities by relative score.
    for (var p = 0; p < top.length; p++) {
      top[p].priority = p === 0 ? "P0" : (p <= 1 ? "P1" : "P2");
    }
    return top;
  }

  function forecast() {
    var ts = nowFn();
    if (snapshots.length < minSnapshots) {
      return {
        horizonMinutes: horizonMinutes,
        riskAppetite: riskAppetite,
        timestamp: ts,
        snapshotCount: snapshots.length,
        sufficient: false,
        reason: "Insufficient snapshots (have " + snapshots.length +
                ", need >= " + minSnapshots + "). Forecast skipped.",
        escalationProbability: 0,
        band: BANDS[0],
        predictedProfile: null,
        predictedProfileLabel: null,
        metricProjections: {},
        leadTimeMinutes: null,
        confidence: 0,
        preemptiveActions: [],
        reasons: [],
      };
    }

    // 1. Project each metric forward.
    var projections = {};
    var weightedBreachSum = 0;
    var weightSum = 0;
    var minLead = null;
    var leadMetric = null;
    for (var key in METRIC_THRESHOLDS) {
      if (!Object.prototype.hasOwnProperty.call(METRIC_THRESHOLDS, key)) continue;
      var proj = _projectMetric(key, snapshots, horizonMinutes);
      if (!proj) continue;
      projections[key] = proj;
      weightedBreachSum += proj.contribution * proj.weight;
      weightSum += proj.weight;
      if (proj.leadTimeMin !== null && proj.contribution > -0.5) {
        if (minLead === null || proj.leadTimeMin < minLead) {
          minLead = proj.leadTimeMin;
          leadMetric = key;
        }
      }
    }
    var meanContribution = weightSum > 0 ? (weightedBreachSum / weightSum) : 0;

    // 2. Anomaly-trajectory uplift: more anomalies in recent snapshots → bump.
    var recent = snapshots.slice(-Math.min(5, snapshots.length));
    var older = snapshots.slice(0, Math.max(1, snapshots.length - recent.length));
    var recentAnomLoad = 0;
    for (var r = 0; r < recent.length; r++) {
      var rs = recent[r].anomalies || [];
      for (var ri = 0; ri < rs.length; ri++) recentAnomLoad += _severityWeight(rs[ri].severity);
    }
    recentAnomLoad = recentAnomLoad / Math.max(1, recent.length);
    var olderAnomLoad = 0;
    for (var o = 0; o < older.length; o++) {
      var os = older[o].anomalies || [];
      for (var oi = 0; oi < os.length; oi++) olderAnomLoad += _severityWeight(os[oi].severity);
    }
    olderAnomLoad = olderAnomLoad / Math.max(1, older.length);
    var anomalyDelta = recentAnomLoad - olderAnomLoad;

    // 3. Escalation probability via logistic on combined signal.
    //    Calibrated so meanContribution ~ 0 → ~0.3, ~1 → ~0.7, ~2 → ~0.87.
    var rawSignal = (meanContribution * 1.0) + (anomalyDelta * 0.8) - 0.8;
    var prob = _clamp(_sigmoid(rawSignal), 0, 1);

    // 4. Confidence: more snapshots + tighter slope agreement → higher.
    var coverageConfidence = _clamp(snapshots.length / 12, 0.1, 1.0);
    var slopeAgreement = 0;
    var slopeCount = 0;
    for (var pk in projections) {
      if (Object.prototype.hasOwnProperty.call(projections, pk)) {
        slopeAgreement += projections[pk].contribution > 0 ? 1 : 0;
        slopeCount++;
      }
    }
    var consensus = slopeCount > 0 ? Math.abs((slopeAgreement / slopeCount) - 0.5) * 2 : 0;
    var confidence = _clamp(0.4 * coverageConfidence + 0.6 * consensus, 0, 1);

    // 5. Predicted rising profile.
    var profileScores = _projectProfiles(snapshots);
    var topProfile = null;
    var topProfileScore = 0;
    for (var pid in profileScores) {
      if (Object.prototype.hasOwnProperty.call(profileScores, pid)) {
        if (profileScores[pid] > topProfileScore) {
          topProfileScore = profileScores[pid];
          topProfile = pid;
        }
      }
    }
    if (!topProfile) topProfile = "generic_degradation";

    // 6. Build human-readable reasons.
    var reasons = [];
    for (var rk in projections) {
      if (!Object.prototype.hasOwnProperty.call(projections, rk)) continue;
      var p2 = projections[rk];
      if (p2.contribution > 0.3) {
        reasons.push(
          p2.label + " trending toward breach: " +
          p2.current.toFixed(2) + " → " + p2.projected.toFixed(2) +
          " (slope " + (p2.slopePerMin >= 0 ? "+" : "") + p2.slopePerMin.toFixed(3) + "/min, " +
          (p2.leadTimeMin !== null ? "ETA " + p2.leadTimeMin.toFixed(1) + " min" : "already breached") + ")"
        );
      }
    }
    if (anomalyDelta > 0.2) {
      reasons.push("Anomaly load rising: recent window " + recentAnomLoad.toFixed(2) +
                   " vs older " + olderAnomLoad.toFixed(2) + " per snapshot.");
    }
    if (topProfileScore > 0) {
      reasons.push("Indicator pattern suggests rising profile: " +
                   (PROFILE_LABELS[topProfile] || topProfile) +
                   " (score " + topProfileScore.toFixed(2) + ").");
    }

    var report = {
      horizonMinutes: horizonMinutes,
      riskAppetite: riskAppetite,
      timestamp: ts,
      snapshotCount: snapshots.length,
      sufficient: true,
      escalationProbability: prob,
      band: _bandForProb(prob),
      predictedProfile: topProfile,
      predictedProfileLabel: PROFILE_LABELS[topProfile] || topProfile,
      profileScores: profileScores,
      metricProjections: projections,
      leadTimeMinutes: minLead,
      leadTimeMetric: leadMetric,
      confidence: confidence,
      meanContribution: meanContribution,
      anomalyDelta: anomalyDelta,
      reasons: reasons,
      preemptiveActions: [],
    };

    report.preemptiveActions = _rankPreemptiveActions(report);
    return report;
  }

  // Simulate applying the top-K pre-emptive actions and recompute the
  // forecast on a virtual snapshot whose metrics have had the action
  // dampeners folded into the projected slope. This does NOT mutate
  // recorded history; it returns a hypothetical "what if we acted now?"
  // report so ops can see the marginal benefit.
  function simulate(report, opts) {
    opts = opts || {};
    if (!report || !report.sufficient) {
      return {
        baseline: report,
        applied: [],
        simulated: report,
        deltaProbability: 0,
        deltaBand: null,
        note: "Baseline insufficient — nothing to simulate.",
      };
    }
    var applyTop = Math.max(0, opts.applyTop != null ? opts.applyTop : 2);
    var picks = report.preemptiveActions.slice(0, applyTop);

    // Combine dampening multipliers per metric (multiplicative).
    var combined = {};
    for (var i = 0; i < picks.length; i++) {
      var actDef = null;
      for (var k = 0; k < PREEMPTIVE_ACTIONS.length; k++) {
        if (PREEMPTIVE_ACTIONS[k].id === picks[i].id) { actDef = PREEMPTIVE_ACTIONS[k]; break; }
      }
      if (!actDef) continue;
      for (var key in actDef.dampens) {
        if (!Object.prototype.hasOwnProperty.call(actDef.dampens, key)) continue;
        combined[key] = (combined[key] != null ? combined[key] : 1) * actDef.dampens[key];
      }
    }

    // Build a simulated projections set and re-derive probability.
    var simProjections = {};
    var weightedBreachSum = 0;
    var weightSum = 0;
    for (var pk in report.metricProjections) {
      if (!Object.prototype.hasOwnProperty.call(report.metricProjections, pk)) continue;
      var base = report.metricProjections[pk];
      var dampener = combined[pk] != null ? combined[pk] : 1;
      // Apply dampener to slope-equivalent contribution. Conceptually
      // this is "what if the slope from now on were multiplied by
      // dampener (for 'down' direction metrics, multiplier >1 worsens)".
      var simContribution = base.contribution * dampener;
      simProjections[pk] = Object.assign({}, base, { contribution: simContribution, dampener: dampener });
      weightedBreachSum += simContribution * base.weight;
      weightSum += base.weight;
    }
    var simMean = weightSum > 0 ? weightedBreachSum / weightSum : 0;
    var simSignal = (simMean * 1.0) + (report.anomalyDelta * 0.8) - 0.8;
    var simProb = _clamp(_sigmoid(simSignal), 0, 1);
    var simBand = _bandForProb(simProb);

    return {
      baseline: report,
      applied: picks,
      simulated: Object.assign({}, report, {
        escalationProbability: simProb,
        band: simBand,
        metricProjections: simProjections,
        meanContribution: simMean,
        reasons: report.reasons.slice().concat([
          "Simulated after applying " + picks.length + " pre-emptive action(s): " +
          picks.map(function (p) { return p.id; }).join(", "),
        ]),
      }),
      deltaProbability: simProb - report.escalationProbability,
      deltaBand: simBand.id !== report.band.id
        ? { from: report.band.id, to: simBand.id }
        : null,
      note: picks.length === 0
        ? "No actions applied."
        : "Lower probability is better; negative deltaProbability = good.",
    };
  }

  // ── Formatters ───────────────────────────────────────────────
  function _formatPct(x) { return (x * 100).toFixed(1) + "%"; }

  function formatText(report) {
    if (!report || !report.sufficient) {
      return "[AttackForecaster] " + (report && report.reason ? report.reason : "no report.");
    }
    var lines = [];
    lines.push("=== AttackForecaster (horizon " + report.horizonMinutes + " min, appetite " + report.riskAppetite + ") ===");
    lines.push("Snapshots: " + report.snapshotCount +
               "  |  Escalation probability: " + _formatPct(report.escalationProbability) +
               "  |  Band: " + report.band.label.toUpperCase() +
               "  |  Confidence: " + _formatPct(report.confidence));
    lines.push("Predicted rising profile: " + (report.predictedProfileLabel || "?"));
    if (report.leadTimeMinutes !== null) {
      lines.push("Earliest projected breach: " + report.leadTimeMetric +
                 " in ~" + report.leadTimeMinutes.toFixed(1) + " min");
    } else {
      lines.push("Earliest projected breach: none within horizon");
    }
    if (report.reasons.length > 0) {
      lines.push("");
      lines.push("Why:");
      for (var i = 0; i < report.reasons.length; i++) lines.push("  - " + report.reasons[i]);
    }
    if (report.preemptiveActions.length > 0) {
      lines.push("");
      lines.push("Pre-emptive actions (apply now to dampen forecast):");
      for (var j = 0; j < report.preemptiveActions.length; j++) {
        var a = report.preemptiveActions[j];
        lines.push("  " + a.priority + " [" + a.owner + ", " + a.effortMinutes + " min, " +
                   a.blastRadius + "/" + a.reversibility + "] " + a.label);
        if (a.note) lines.push("       " + a.note);
        if (a.dampens && a.dampens.length > 0) lines.push("       dampens: " + a.dampens.join(", "));
      }
    } else {
      lines.push("");
      lines.push("No pre-emptive actions recommended at current band.");
    }
    return lines.join("\n");
  }

  function formatMarkdown(report) {
    if (!report || !report.sufficient) {
      return "_AttackForecaster: " + (report && report.reason ? report.reason : "no report.") + "_";
    }
    var lines = [];
    lines.push("# Attack Forecast");
    lines.push("");
    lines.push("- **Horizon:** " + report.horizonMinutes + " min");
    lines.push("- **Risk appetite:** `" + report.riskAppetite + "`");
    lines.push("- **Snapshots:** " + report.snapshotCount);
    lines.push("- **Escalation probability:** **" + _formatPct(report.escalationProbability) + "** (band: **" + report.band.label + "**)");
    lines.push("- **Confidence:** " + _formatPct(report.confidence));
    lines.push("- **Predicted rising profile:** " + (report.predictedProfileLabel || "?"));
    if (report.leadTimeMinutes !== null) {
      lines.push("- **Earliest breach:** `" + report.leadTimeMetric + "` in ~" + report.leadTimeMinutes.toFixed(1) + " min");
    }
    if (report.reasons.length > 0) {
      lines.push("");
      lines.push("## Why");
      for (var i = 0; i < report.reasons.length; i++) lines.push("- " + report.reasons[i]);
    }
    if (report.preemptiveActions.length > 0) {
      lines.push("");
      lines.push("## Pre-emptive Actions");
      lines.push("");
      lines.push("| Priority | Action | Owner | Effort | Blast | Reversibility |");
      lines.push("|---|---|---|---|---|---|");
      for (var j = 0; j < report.preemptiveActions.length; j++) {
        var a = report.preemptiveActions[j];
        lines.push("| " + a.priority + " | " + a.label + " | `" + a.owner + "` | " +
                   a.effortMinutes + " min | " + a.blastRadius + " | " + a.reversibility + " |");
      }
    }
    return lines.join("\n");
  }

  function formatAs(report, format) {
    var f = String(format || "text").toLowerCase();
    if (f === "json") return JSON.stringify(report, null, 2);
    if (f === "md" || f === "markdown") return formatMarkdown(report);
    return formatText(report);
  }

  return {
    recordSnapshot: recordSnapshot,
    forecast: forecast,
    simulate: simulate,
    formatAs: formatAs,
    formatText: formatText,
    formatMarkdown: formatMarkdown,
    reset: reset,
    // Introspection (mostly for tests):
    _snapshots: function () { return snapshots.slice(); },
    _config: function () {
      return {
        horizonMinutes: horizonMinutes,
        maxSnapshots: maxSnapshots,
        riskAppetite: riskAppetite,
        minSnapshots: minSnapshots,
      };
    },
  };
}

module.exports = {
  createAttackForecaster: createAttackForecaster,
  // Exposed for advanced users / tests:
  PREEMPTIVE_ACTIONS: PREEMPTIVE_ACTIONS,
  METRIC_THRESHOLDS: METRIC_THRESHOLDS,
  PROFILE_BIAS: PROFILE_BIAS,
  RISK_PRESETS: RISK_PRESETS,
  BANDS: BANDS,
};
