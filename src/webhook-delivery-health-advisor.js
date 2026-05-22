"use strict";

/**
 * WebhookDeliveryHealthAdvisor - Agentic per-endpoint health advisor for
 * gif-captcha webhook delivery logs.
 *
 * Operates on the entries emitted by WebhookDispatcher.getDeliveryLog() (or
 * any compatible array of {webhookId, event, status, attempts, statusCode?,
 * error?, timestamp?} objects) plus the registered endpoint list from
 * WebhookDispatcher.list(). Produces:
 *   - per-endpoint EndpointFinding with verdict + reasons + recommendations,
 *   - a portfolio summary with grade A-F and band HEALTHY/WATCH/DEGRADED/CRITICAL,
 *   - a deduped, priority-ordered playbook (P0-first),
 *   - insights bullets, and
 *   - text / markdown / json renderers (byte-stable JSON).
 *
 * Verdict ladder (first matching, highest priority first):
 *   DEAD_ENDPOINT       - >=10 attempts, success_rate < 0.05  (P0)
 *   DEGRADED            - >=10 attempts, success_rate < 0.50  (P0)
 *   RETRY_STORM         - mean attempts per delivery >= 2.5   (P1)
 *   RATE_LIMITED_HEAVY  - rate_limited >= 30% of attempts     (P1)
 *   FLAPPING            - >=3 alternations between ok and fail (P1)
 *   AUTH_FAILURE        - >=3 deliveries with statusCode in {401, 403} (P0)
 *   SLOW_RECOVERY       - last_failure newer than last_success AND
 *                         consecutive_failures >= 5            (P1)
 *   IDLE                - 0 attempts in window                 (P2)
 *   UNREGISTERED_TRAFFIC- log has webhookId not in registry    (P1)
 *   HEALTHY             - default (P3)
 *
 * Risk appetite (cautious | balanced | aggressive):
 *   cautious   -> thresholds * 0.80 (smaller signals qualify), adds
 *                 SCHEDULE_WEBHOOK_REVIEW when grade in {C,D,F}.
 *   aggressive -> thresholds * 1.30, trims P3 + lone P2 actions when any
 *                 P0/P1 exists in the playbook.
 *
 * Pure JS, stdlib only, deterministic given inputs + risk_appetite + now.
 *
 * @module webhook-delivery-health-advisor
 */

var DEFAULT_RISK = "balanced";
var RISK_MULTIPLIERS = { cautious: 0.80, balanced: 1.0, aggressive: 1.30 };

var DEFAULT_OPTIONS = {
  min_attempts_for_verdict: 10,
  dead_success_rate: 0.05,
  degraded_success_rate: 0.50,
  retry_storm_mean_attempts: 2.5,
  rate_limited_share: 0.30,
  auth_failure_min: 3,
  flap_min_alternations: 3,
  slow_recovery_consecutive: 5,
  idle_window_ms: 60 * 60 * 1000,
  top_n: 10,
};

var BAND_BOUNDS = { HEALTHY: 15, WATCH: 35, DEGRADED: 60 };
// score >= DEGRADED+ -> CRITICAL

function _clamp(n, lo, hi) {
  if (typeof n !== "number" || !isFinite(n)) return lo;
  if (n < lo) return lo;
  if (n > hi) return hi;
  return n;
}

function _isObj(x) { return x && typeof x === "object" && !Array.isArray(x); }

function _toTs(v, fallbackNow) {
  if (typeof v === "number" && isFinite(v)) return v;
  if (typeof v === "string") {
    var t = Date.parse(v);
    if (!isNaN(t)) return t;
  }
  return fallbackNow;
}

function _normaliseEntry(raw, now) {
  if (!_isObj(raw)) return null;
  var status = typeof raw.status === "string" ? raw.status : "unknown";
  var attempts = typeof raw.attempts === "number" && raw.attempts > 0
    ? Math.floor(raw.attempts) : 1;
  var statusCode = (typeof raw.statusCode === "number" && isFinite(raw.statusCode))
    ? Math.floor(raw.statusCode) : null;
  return {
    webhookId: typeof raw.webhookId === "string" ? raw.webhookId : "unknown",
    event: typeof raw.event === "string" ? raw.event : "unknown",
    status: status,
    attempts: attempts,
    statusCode: statusCode,
    error: typeof raw.error === "string" ? raw.error : null,
    timestamp: _toTs(raw.timestamp, now),
  };
}

function _isSuccess(e) { return e.status === "delivered"; }
function _isFailure(e) {
  return e.status === "failed" || e.status === "error";
}
function _isRateLimited(e) { return e.status === "rate_limited"; }

// ─── Per-endpoint aggregation ───────────────────────────────────────────────

function _aggregate(entries) {
  var byId = new Map();
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var slot = byId.get(e.webhookId);
    if (!slot) {
      slot = {
        webhookId: e.webhookId,
        total: 0,
        delivered: 0,
        failed: 0,
        rate_limited: 0,
        auth_failures: 0,        // 401/403
        attempts_sum: 0,
        last_success_ts: null,
        last_failure_ts: null,
        consecutive_failures: 0, // tail-end run of failures
        alternations: 0,
        events: new Set(),
        status_codes: {},
      };
      byId.set(e.webhookId, slot);
    }
    slot.total += 1;
    slot.attempts_sum += e.attempts;
    slot.events.add(e.event);
    if (e.statusCode != null) {
      var key = String(e.statusCode);
      slot.status_codes[key] = (slot.status_codes[key] || 0) + 1;
      if (e.statusCode === 401 || e.statusCode === 403) slot.auth_failures += 1;
    }
    if (_isSuccess(e)) {
      slot.delivered += 1;
      if (slot.last_success_ts == null || e.timestamp > slot.last_success_ts) {
        slot.last_success_ts = e.timestamp;
      }
    } else if (_isFailure(e)) {
      slot.failed += 1;
      if (slot.last_failure_ts == null || e.timestamp > slot.last_failure_ts) {
        slot.last_failure_ts = e.timestamp;
      }
    } else if (_isRateLimited(e)) {
      slot.rate_limited += 1;
    }
  }

  // Compute alternations + consecutive_failures from a time-ordered timeline.
  var perId = {};
  byId.forEach(function (slot, id) {
    var timeline = entries
      .filter(function (e) { return e.webhookId === id; })
      .slice()
      .sort(function (a, b) { return a.timestamp - b.timestamp; });
    var prevOk = null;
    var alts = 0;
    var trailingFail = 0;
    for (var i = 0; i < timeline.length; i++) {
      var t = timeline[i];
      if (_isSuccess(t)) {
        if (prevOk === false) alts += 1;
        prevOk = true;
        trailingFail = 0;
      } else if (_isFailure(t)) {
        if (prevOk === true) alts += 1;
        prevOk = false;
        trailingFail += 1;
      }
    }
    slot.alternations = alts;
    slot.consecutive_failures = trailingFail;
    slot.events = Array.from(slot.events).sort();
    perId[id] = slot;
  });
  return perId;
}

// ─── Verdict + scoring ──────────────────────────────────────────────────────

function _verdictAndScore(slot, opts, now, registered) {
  var reasons = [];
  var attempted = slot.delivered + slot.failed; // exclude rate_limited from rate
  var success_rate = attempted > 0 ? slot.delivered / attempted : null;
  var mean_attempts = slot.total > 0 ? slot.attempts_sum / slot.total : 0;
  var rate_share = slot.total > 0 ? slot.rate_limited / slot.total : 0;
  var verdict = "HEALTHY";
  var priority = "P3";
  var score = 0;

  var minAttempts = opts.min_attempts_for_verdict;
  var deadRate = opts.dead_success_rate;
  var degRate = opts.degraded_success_rate;

  if (!registered) {
    verdict = "UNREGISTERED_TRAFFIC";
    priority = "P1";
    score = 55;
    reasons.push("delivery log contains webhookId not present in registry");
    return { verdict: verdict, priority: priority, score: score, reasons: reasons,
             success_rate: success_rate, mean_attempts: mean_attempts,
             rate_limited_share: rate_share };
  }

  if (slot.total === 0) {
    verdict = "IDLE";
    priority = "P2";
    score = 12;
    reasons.push("no deliveries in window");
    return { verdict: verdict, priority: priority, score: score, reasons: reasons,
             success_rate: success_rate, mean_attempts: mean_attempts,
             rate_limited_share: rate_share };
  }

  // AUTH_FAILURE has its own short-circuit (P0) when frequent.
  if (slot.auth_failures >= opts.auth_failure_min) {
    verdict = "AUTH_FAILURE";
    priority = "P0";
    score = 85;
    reasons.push(slot.auth_failures + " auth-rejected deliveries (401/403)");
    return { verdict: verdict, priority: priority, score: score, reasons: reasons,
             success_rate: success_rate, mean_attempts: mean_attempts,
             rate_limited_share: rate_share };
  }

  if (attempted >= minAttempts && success_rate != null) {
    if (success_rate < deadRate) {
      verdict = "DEAD_ENDPOINT"; priority = "P0"; score = 90;
      reasons.push("success rate " + (success_rate * 100).toFixed(1) + "% over "
                   + attempted + " attempts");
      return { verdict: verdict, priority: priority, score: score, reasons: reasons,
               success_rate: success_rate, mean_attempts: mean_attempts,
               rate_limited_share: rate_share };
    }
    if (success_rate < degRate) {
      verdict = "DEGRADED"; priority = "P0"; score = 70;
      reasons.push("success rate " + (success_rate * 100).toFixed(1) + "% over "
                   + attempted + " attempts");
    }
  }

  if (slot.consecutive_failures >= opts.slow_recovery_consecutive &&
      slot.last_failure_ts != null &&
      (slot.last_success_ts == null || slot.last_failure_ts > slot.last_success_ts) &&
      verdict === "HEALTHY") {
    verdict = "SLOW_RECOVERY"; priority = "P1"; score = 60;
    reasons.push(slot.consecutive_failures + " consecutive failures at tail");
  }

  if (mean_attempts >= opts.retry_storm_mean_attempts && verdict === "HEALTHY") {
    verdict = "RETRY_STORM"; priority = "P1"; score = 50;
    reasons.push("mean attempts/delivery " + mean_attempts.toFixed(2));
  }

  if (rate_share >= opts.rate_limited_share && verdict === "HEALTHY") {
    verdict = "RATE_LIMITED_HEAVY"; priority = "P1"; score = 45;
    reasons.push((rate_share * 100).toFixed(1) + "% of deliveries rate-limited");
  }

  if (slot.alternations >= opts.flap_min_alternations && verdict === "HEALTHY") {
    verdict = "FLAPPING"; priority = "P1"; score = 50;
    reasons.push(slot.alternations + " ok/fail alternations");
  }

  if (verdict === "DEGRADED" && mean_attempts >= opts.retry_storm_mean_attempts) {
    reasons.push("compounded by retry storm (mean " + mean_attempts.toFixed(2) + ")");
    score = Math.max(score, 75);
  }

  if (verdict === "HEALTHY") {
    score = 5;
    reasons.push("success rate " +
      (success_rate == null ? "n/a" : (success_rate * 100).toFixed(1) + "%") +
      " over " + attempted + " attempts");
  }

  return { verdict: verdict, priority: priority, score: score, reasons: reasons,
           success_rate: success_rate, mean_attempts: mean_attempts,
           rate_limited_share: rate_share };
}

// ─── Playbook ───────────────────────────────────────────────────────────────

var PRIORITY_RANK = { P0: 0, P1: 1, P2: 2, P3: 3 };

function _buildPlaybook(findings, summary, riskAppetite) {
  var actions = [];
  function add(a) { actions.push(a); }

  var deads = findings.filter(function (f) { return f.verdict === "DEAD_ENDPOINT"; });
  var degraded = findings.filter(function (f) { return f.verdict === "DEGRADED"; });
  var auths = findings.filter(function (f) { return f.verdict === "AUTH_FAILURE"; });
  var retries = findings.filter(function (f) { return f.verdict === "RETRY_STORM"; });
  var rates = findings.filter(function (f) { return f.verdict === "RATE_LIMITED_HEAVY"; });
  var slows = findings.filter(function (f) { return f.verdict === "SLOW_RECOVERY"; });
  var flaps = findings.filter(function (f) { return f.verdict === "FLAPPING"; });
  var idles = findings.filter(function (f) { return f.verdict === "IDLE"; });
  var ghosts = findings.filter(function (f) { return f.verdict === "UNREGISTERED_TRAFFIC"; });

  function ids(arr) { return arr.map(function (x) { return x.webhookId; }).sort(); }

  if (deads.length) {
    add({ id: "DISABLE_DEAD_ENDPOINTS", priority: "P0",
          label: "Disable or unregister " + deads.length + " dead webhook endpoint(s)",
          reason: "Success rate under " + (DEFAULT_OPTIONS.dead_success_rate * 100) +
                  "% over the verdict window — every delivery wastes retries and log space.",
          owner: "platform_ops", blast_radius: 3, reversibility: "high",
          related_endpoints: ids(deads) });
  }
  if (auths.length) {
    add({ id: "ROTATE_OR_FIX_WEBHOOK_SECRETS", priority: "P0",
          label: "Rotate secrets / re-issue credentials for " + auths.length +
                 " auth-failing endpoint(s)",
          reason: "Persistent 401/403 responses indicate the receiver no longer trusts our signature.",
          owner: "integration_owner", blast_radius: 2, reversibility: "high",
          related_endpoints: ids(auths) });
  }
  if (degraded.length) {
    add({ id: "OPEN_DEGRADED_DELIVERY_INCIDENT", priority: "P0",
          label: "Open incident for " + degraded.length + " degraded endpoint(s)",
          reason: "Success rate below " + (DEFAULT_OPTIONS.degraded_success_rate * 100) +
                  "% across the verdict window.",
          owner: "oncall", blast_radius: 3, reversibility: "high",
          related_endpoints: ids(degraded) });
  }
  if (retries.length) {
    add({ id: "TUNE_BACKOFF_OR_TIMEOUT", priority: "P1",
          label: "Tune backoff/timeout for " + retries.length + " retry-storming endpoint(s)",
          reason: "Mean attempts per delivery exceeds " +
                  DEFAULT_OPTIONS.retry_storm_mean_attempts +
                  " — receivers are slow or flaky and we are amplifying load.",
          owner: "platform_ops", blast_radius: 2, reversibility: "high",
          related_endpoints: ids(retries) });
  }
  if (rates.length) {
    add({ id: "NEGOTIATE_RATE_LIMIT_OR_BATCH", priority: "P1",
          label: "Negotiate higher rate limits or batch events for " +
                 rates.length + " endpoint(s)",
          reason: ">= " + (DEFAULT_OPTIONS.rate_limited_share * 100) +
                  "% of deliveries hit our own rate limiter.",
          owner: "integration_owner", blast_radius: 2, reversibility: "high",
          related_endpoints: ids(rates) });
  }
  if (slows.length) {
    add({ id: "INVESTIGATE_SLOW_RECOVERY", priority: "P1",
          label: "Investigate slow-recovery tail on " + slows.length + " endpoint(s)",
          reason: "Multiple consecutive failures at the tail with no recovery delivery.",
          owner: "oncall", blast_radius: 2, reversibility: "high",
          related_endpoints: ids(slows) });
  }
  if (flaps.length) {
    add({ id: "STABILISE_FLAPPING_ENDPOINT", priority: "P1",
          label: "Stabilise " + flaps.length + " flapping endpoint(s)",
          reason: "Repeated ok/fail alternations suggest intermittent receiver issues.",
          owner: "integration_owner", blast_radius: 2, reversibility: "high",
          related_endpoints: ids(flaps) });
  }
  if (ghosts.length) {
    add({ id: "RECONCILE_UNREGISTERED_TRAFFIC", priority: "P1",
          label: "Reconcile " + ghosts.length + " unregistered webhook id(s) in the log",
          reason: "Delivery log references endpoints not present in the registry.",
          owner: "platform_ops", blast_radius: 1, reversibility: "high",
          related_endpoints: ids(ghosts) });
  }
  if (idles.length) {
    add({ id: "CONFIRM_IDLE_ENDPOINTS", priority: "P2",
          label: "Confirm " + idles.length + " idle endpoint(s) are still wanted",
          reason: "No deliveries within the idle window — receiver may have been retired.",
          owner: "integration_owner", blast_radius: 1, reversibility: "high",
          related_endpoints: ids(idles) });
  }

  if (riskAppetite === "cautious" &&
      (summary.grade === "C" || summary.grade === "D" || summary.grade === "F")) {
    add({ id: "SCHEDULE_WEBHOOK_REVIEW", priority: "P2",
          label: "Schedule a webhook delivery review",
          reason: "Grade " + summary.grade + " under cautious posture warrants a scheduled review.",
          owner: "platform_ops", blast_radius: 1, reversibility: "high",
          related_endpoints: [] });
  }

  if (!actions.length) {
    add({ id: "NO_WEBHOOK_ACTION_NEEDED", priority: "P3",
          label: "No webhook action needed",
          reason: "All endpoints are healthy across the window.",
          owner: "platform_ops", blast_radius: 1, reversibility: "high",
          related_endpoints: [] });
  }

  // Dedupe by id, keep highest priority occurrence.
  var byId = {};
  for (var i = 0; i < actions.length; i++) {
    var a = actions[i];
    var existing = byId[a.id];
    if (!existing || PRIORITY_RANK[a.priority] < PRIORITY_RANK[existing.priority]) {
      byId[a.id] = a;
    }
  }
  actions = Object.keys(byId).map(function (k) { return byId[k]; });

  if (riskAppetite === "aggressive") {
    var hasUrgent = actions.some(function (a) {
      return a.priority === "P0" || a.priority === "P1";
    });
    if (hasUrgent) {
      var p2s = actions.filter(function (a) { return a.priority === "P2"; });
      actions = actions.filter(function (a) {
        if (a.priority === "P3") return false;
        if (a.priority === "P2" && p2s.length === 1) return false;
        return true;
      });
      if (!actions.length) {
        actions.push({ id: "NO_WEBHOOK_ACTION_NEEDED", priority: "P3",
          label: "No webhook action needed",
          reason: "Aggressive posture trimmed lower-priority noise.",
          owner: "platform_ops", blast_radius: 1, reversibility: "high",
          related_endpoints: [] });
      }
    }
  }

  actions.sort(function (a, b) {
    var pa = PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority];
    if (pa !== 0) return pa;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
  return actions;
}

// ─── Insights ───────────────────────────────────────────────────────────────

function _buildInsights(findings, summary) {
  var insights = [];
  if (summary.total_endpoints === 0) {
    insights.push("NO_WEBHOOK_ENDPOINTS_REGISTERED");
    return insights;
  }
  if (summary.total_attempts === 0) {
    insights.push("NO_DELIVERY_ACTIVITY");
    return insights;
  }
  var dead = findings.filter(function (f) { return f.verdict === "DEAD_ENDPOINT"; });
  var auth = findings.filter(function (f) { return f.verdict === "AUTH_FAILURE"; });
  var degraded = findings.filter(function (f) { return f.verdict === "DEGRADED"; });
  var idle = findings.filter(function (f) { return f.verdict === "IDLE"; });
  var ghosts = findings.filter(function (f) { return f.verdict === "UNREGISTERED_TRAFFIC"; });

  if (dead.length >= 2) insights.push("MULTIPLE_DEAD_ENDPOINTS:" + dead.length);
  if (auth.length) insights.push("AUTH_FAILURES_PRESENT:" + auth.length);
  if (degraded.length) insights.push("DEGRADED_ENDPOINTS:" + degraded.length);
  if (ghosts.length) insights.push("UNREGISTERED_TRAFFIC:" + ghosts.length);
  if (idle.length && idle.length === summary.total_endpoints) {
    insights.push("ENTIRE_FLEET_IDLE");
  } else if (idle.length) {
    insights.push("IDLE_ENDPOINTS:" + idle.length);
  }
  if (summary.fleet_success_rate != null) {
    if (summary.fleet_success_rate < 0.5) insights.push("FLEET_SUCCESS_RATE_LOW");
    else if (summary.fleet_success_rate >= 0.95) insights.push("FLEET_SUCCESS_RATE_HEALTHY");
  }
  if (!insights.length) insights.push("HEALTHY_WEBHOOK_FLEET");
  return insights;
}

// ─── Summary + grade ────────────────────────────────────────────────────────

function _grade(summary, findings) {
  var p0 = findings.filter(function (f) { return f.priority === "P0"; }).length;
  var p1 = findings.filter(function (f) { return f.priority === "P1"; }).length;
  var maxScore = findings.reduce(function (m, f) {
    return f.score > m ? f.score : m;
  }, 0);
  if (p0 >= 2 || maxScore >= 85) return "F";
  if (p0 >= 1 || maxScore >= 65) return "D";
  if (p1 >= 2 || maxScore >= 45) return "C";
  if (p1 >= 1 || maxScore >= 20) return "B";
  return "A";
}

function _band(score) {
  if (score < BAND_BOUNDS.HEALTHY) return "HEALTHY";
  if (score < BAND_BOUNDS.WATCH) return "WATCH";
  if (score < BAND_BOUNDS.DEGRADED) return "DEGRADED";
  return "CRITICAL";
}

function _summarise(findings, registry, entries) {
  var total_endpoints = registry.length;
  var total_attempts = entries.reduce(function (n, e) { return n + e.attempts; }, 0);
  var delivered = entries.filter(_isSuccess).length;
  var failed = entries.filter(_isFailure).length;
  var rate_limited = entries.filter(_isRateLimited).length;
  var attempted = delivered + failed;
  var fleet_success_rate = attempted > 0 ? delivered / attempted : null;
  var topScore = findings.reduce(function (m, f) { return f.score > m ? f.score : m; }, 0);
  var summary = {
    total_endpoints: total_endpoints,
    total_deliveries_logged: entries.length,
    total_attempts: total_attempts,
    delivered: delivered,
    failed: failed,
    rate_limited: rate_limited,
    fleet_success_rate: fleet_success_rate,
    overall_risk: topScore,
    band: _band(topScore),
    grade: "A",
  };
  summary.grade = _grade(summary, findings);
  return summary;
}

// ─── Renderers ──────────────────────────────────────────────────────────────

function _fmtRate(r) {
  if (r == null) return "n/a";
  return (r * 100).toFixed(1) + "%";
}

function _toText(report) {
  var s = report.summary;
  var lines = [];
  lines.push("VERDICT: grade " + s.grade + " (" + s.band + ") -- " +
             report.findings.length + " endpoints, " + s.total_deliveries_logged +
             " deliveries, fleet success " + _fmtRate(s.fleet_success_rate));
  lines.push("");
  lines.push("Top findings:");
  var top = report.findings.slice(0, report.options.top_n);
  if (!top.length) lines.push("  (none)");
  top.forEach(function (f) {
    lines.push("  - " + f.webhookId + "  [" + f.verdict + " " + f.priority +
               "]  success=" + _fmtRate(f.success_rate) +
               "  mean_attempts=" + f.mean_attempts.toFixed(2) +
               "  reason=" + f.reasons.join("; "));
  });
  lines.push("");
  lines.push("Playbook:");
  report.playbook.forEach(function (a) {
    lines.push("  - [" + a.priority + "] " + a.id + " :: " + a.label);
  });
  lines.push("");
  lines.push("Insights:");
  report.insights.forEach(function (i) { lines.push("  - " + i); });
  return lines.join("\n");
}

function _mdEscape(s) { return String(s).replace(/\|/g, "\\|"); }

function _toMarkdown(report) {
  var s = report.summary;
  var out = [];
  out.push("## Summary");
  out.push("");
  out.push("| metric | value |");
  out.push("| --- | --- |");
  out.push("| grade | " + s.grade + " |");
  out.push("| band | " + s.band + " |");
  out.push("| total_endpoints | " + s.total_endpoints + " |");
  out.push("| total_deliveries_logged | " + s.total_deliveries_logged + " |");
  out.push("| total_attempts | " + s.total_attempts + " |");
  out.push("| delivered | " + s.delivered + " |");
  out.push("| failed | " + s.failed + " |");
  out.push("| rate_limited | " + s.rate_limited + " |");
  out.push("| fleet_success_rate | " + _fmtRate(s.fleet_success_rate) + " |");
  out.push("| overall_risk | " + s.overall_risk + " |");
  out.push("");
  out.push("## Endpoints");
  out.push("");
  out.push("| webhookId | verdict | priority | success | mean_attempts | rate_limited | reasons |");
  out.push("| --- | --- | --- | --- | --- | --- | --- |");
  var top = report.findings.slice(0, report.options.top_n);
  if (!top.length) {
    out.push("| _no endpoints_ |  |  |  |  |  |  |");
  }
  top.forEach(function (f) {
    out.push("| " + _mdEscape(f.webhookId) +
             " | " + f.verdict +
             " | " + f.priority +
             " | " + _fmtRate(f.success_rate) +
             " | " + f.mean_attempts.toFixed(2) +
             " | " + _fmtRate(f.rate_limited_share) +
             " | " + _mdEscape(f.reasons.join("; ")) + " |");
  });
  out.push("");
  out.push("## Playbook");
  out.push("");
  out.push("| id | priority | owner | label |");
  out.push("| --- | --- | --- | --- |");
  if (!report.playbook.length) out.push("| _none_ |  |  |  |");
  report.playbook.forEach(function (a) {
    out.push("| " + a.id + " | " + a.priority + " | " + a.owner + " | " +
             _mdEscape(a.label) + " |");
  });
  out.push("");
  out.push("## Insights");
  out.push("");
  if (!report.insights.length) out.push("- _none_");
  report.insights.forEach(function (i) { out.push("- " + i); });
  return out.join("\n");
}

function _sortedStringify(obj) {
  function inner(v) {
    if (v === null || typeof v !== "object") return v;
    if (Array.isArray(v)) return v.map(inner);
    var keys = Object.keys(v).sort();
    var out = {};
    keys.forEach(function (k) { out[k] = inner(v[k]); });
    return out;
  }
  return JSON.stringify(inner(obj), null, 2);
}

function _toJson(report) { return _sortedStringify(report); }

// ─── Public factory ─────────────────────────────────────────────────────────

function createWebhookDeliveryHealthAdvisor(userOptions) {
  var options = {};
  Object.keys(DEFAULT_OPTIONS).forEach(function (k) {
    options[k] = (userOptions && typeof userOptions[k] === "number" && userOptions[k] > 0)
      ? userOptions[k] : DEFAULT_OPTIONS[k];
  });
  var nowFn = (userOptions && typeof userOptions.now === "function")
    ? userOptions.now : function () { return Date.now(); };

  function analyze(input, ctx) {
    if (!_isObj(input)) input = {};
    var rawLog = Array.isArray(input.deliveryLog) ? input.deliveryLog : [];
    var registry = Array.isArray(input.endpoints) ? input.endpoints.slice() : [];
    var risk = (ctx && typeof ctx.risk_appetite === "string" &&
                RISK_MULTIPLIERS[ctx.risk_appetite] != null)
      ? ctx.risk_appetite : DEFAULT_RISK;
    var now = (ctx && typeof ctx.now === "number") ? ctx.now : nowFn();

    // Apply risk multiplier to threshold options.
    var mult = RISK_MULTIPLIERS[risk];
    var thresholds = {};
    Object.keys(options).forEach(function (k) {
      thresholds[k] = options[k];
    });
    thresholds.dead_success_rate = options.dead_success_rate * (1 / mult); // lower = stricter
    thresholds.degraded_success_rate = options.degraded_success_rate * (1 / mult);
    thresholds.retry_storm_mean_attempts = options.retry_storm_mean_attempts * mult;
    thresholds.rate_limited_share = options.rate_limited_share * mult;
    thresholds.auth_failure_min = Math.max(1, Math.ceil(options.auth_failure_min * mult));
    thresholds.flap_min_alternations = Math.max(1, Math.ceil(options.flap_min_alternations * mult));
    thresholds.slow_recovery_consecutive =
      Math.max(1, Math.ceil(options.slow_recovery_consecutive * mult));

    // Normalise entries.
    var entries = [];
    for (var i = 0; i < rawLog.length; i++) {
      var n = _normaliseEntry(rawLog[i], now);
      if (n) entries.push(n);
    }

    var registeredIds = {};
    registry.forEach(function (ep) {
      if (ep && typeof ep.id === "string") registeredIds[ep.id] = ep;
    });

    var perId = _aggregate(entries);
    var seen = {};
    Object.keys(perId).forEach(function (id) { seen[id] = true; });

    // Ensure every registered endpoint appears (idle case).
    registry.forEach(function (ep) {
      if (!ep || typeof ep.id !== "string") return;
      if (!perId[ep.id]) {
        perId[ep.id] = {
          webhookId: ep.id, total: 0, delivered: 0, failed: 0, rate_limited: 0,
          auth_failures: 0, attempts_sum: 0, last_success_ts: null,
          last_failure_ts: null, consecutive_failures: 0, alternations: 0,
          events: [], status_codes: {},
        };
      }
    });

    var findings = Object.keys(perId).map(function (id) {
      var slot = perId[id];
      var isRegistered = !!registeredIds[id] || id === "unknown" && false;
      // "unknown" sentinel = malformed entry; treat as registered=false so it
      // surfaces as UNREGISTERED_TRAFFIC.
      if (id === "unknown") isRegistered = false;
      else isRegistered = !!registeredIds[id];
      var v = _verdictAndScore(slot, thresholds, now, isRegistered);
      return {
        webhookId: id,
        url: registeredIds[id] ? registeredIds[id].url || null : null,
        verdict: v.verdict,
        priority: v.priority,
        score: v.score,
        success_rate: v.success_rate,
        mean_attempts: v.mean_attempts,
        rate_limited_share: v.rate_limited_share,
        total: slot.total,
        delivered: slot.delivered,
        failed: slot.failed,
        rate_limited: slot.rate_limited,
        auth_failures: slot.auth_failures,
        consecutive_failures: slot.consecutive_failures,
        alternations: slot.alternations,
        last_success_ts: slot.last_success_ts,
        last_failure_ts: slot.last_failure_ts,
        events: Array.isArray(slot.events) ? slot.events.slice() : [],
        status_codes: Object.assign({}, slot.status_codes),
        reasons: v.reasons,
      };
    });

    findings.sort(function (a, b) {
      if (b.score !== a.score) return b.score - a.score;
      return a.webhookId < b.webhookId ? -1 : a.webhookId > b.webhookId ? 1 : 0;
    });

    var summary = _summarise(findings, registry, entries);
    var playbook = _buildPlaybook(findings, summary, risk);
    var insights = _buildInsights(findings, summary);

    return {
      generated_at: now,
      risk_appetite: risk,
      options: thresholds,
      summary: summary,
      findings: findings,
      playbook: playbook,
      insights: insights,
    };
  }

  return {
    analyze: analyze,
    formatText: function (report) { return _toText(report); },
    formatMarkdown: function (report) { return _toMarkdown(report); },
    formatJson: function (report) { return _toJson(report); },
    DEFAULT_OPTIONS: Object.assign({}, DEFAULT_OPTIONS),
  };
}

module.exports = {
  createWebhookDeliveryHealthAdvisor: createWebhookDeliveryHealthAdvisor,
};
