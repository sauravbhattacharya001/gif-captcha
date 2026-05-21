"use strict";

/**
 * SessionEvidenceBundler — post-decision (PASS/BLOCK/STEP_UP/CHALLENGE) evidence-pack
 * assembler. Produces a compact, ranked, redacted evidence dossier with
 * deterministic chain-of-custody hash for compliance / dispute / SOC review.
 *
 * Pure CommonJS, zero deps. Deterministic. Never mutates input.
 */

var crypto = require("crypto");

var BUNDLER_VERSION = "1.0.0";
var VALID_RISKS = { cautious: 1.15, balanced: 1.0, aggressive: 0.85 };
var PRIORITY_RANK = { P0: 0, P1: 1, P2: 2, P3: 3 };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function _clamp(n, lo, hi) {
  if (typeof n !== "number" || isNaN(n)) return lo;
  return Math.max(lo, Math.min(hi, n));
}

function _normRisk(r) {
  if (r && Object.prototype.hasOwnProperty.call(VALID_RISKS, r)) return r;
  return "balanced";
}

function _deepCopy(v) {
  if (v === undefined) return undefined;
  try {
    return JSON.parse(JSON.stringify(v));
  } catch (e) {
    return null;
  }
}

function _isObj(v) {
  return v !== null && typeof v === "object";
}

function _stableStringify(value) {
  var seen = new WeakSet();
  function replacer(key, v) {
    if (_isObj(v)) {
      if (seen.has(v)) return "[Circular]";
      seen.add(v);
      if (!Array.isArray(v)) {
        var sorted = {};
        Object.keys(v).sort().forEach(function (k) { sorted[k] = v[k]; });
        return sorted;
      }
    }
    return v;
  }
  return JSON.stringify(value, replacer, 2);
}

function _sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

function _maskIp(ip) {
  if (typeof ip !== "string" || !ip) return ip;
  if (ip.indexOf(":") !== -1) {
    // IPv6 -- mask last 4 segments
    var parts = ip.split(":");
    if (parts.length <= 4) return "xxxx:xxxx";
    return parts.slice(0, parts.length - 4).join(":") + ":xxxx:xxxx:xxxx:xxxx";
  }
  var dot = ip.split(".");
  if (dot.length === 4) return dot.slice(0, 3).join(".") + ".xxx";
  return ip;
}

function _hashAccount(id) {
  if (id === undefined || id === null || id === "") return id;
  return "acct_" + _sha256(String(id)).slice(0, 8);
}

function _scrubEmails(s) {
  if (typeof s !== "string") return s;
  return s.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[email-redacted]");
}

function _truncateUa(ua) {
  if (typeof ua !== "string") return ua;
  if (ua.length <= 60) return ua;
  return ua.slice(0, 60) + "...";
}

function _round1(n) {
  if (typeof n !== "number" || isNaN(n)) return n;
  return Math.round(n * 10) / 10;
}

function _redactSignal(category, raw, doRedact) {
  if (!doRedact) return { value: raw, redacted: false };
  var copy = _deepCopy(raw);
  var didRedact = false;
  if (!_isObj(copy)) {
    if (typeof copy === "string") {
      var scrubbed = _scrubEmails(copy);
      if (scrubbed !== copy) didRedact = true;
      return { value: scrubbed, redacted: didRedact };
    }
    return { value: copy, redacted: false };
  }
  if (typeof copy.ip === "string") { copy.ip = _maskIp(copy.ip); didRedact = true; }
  if (copy.accountId !== undefined) { copy.accountId = _hashAccount(copy.accountId); didRedact = true; }
  if (copy.userAgent && typeof copy.userAgent === "string" && copy.userAgent.length > 60) {
    copy.userAgent = _truncateUa(copy.userAgent); didRedact = true;
  }
  if (_isObj(copy.geo)) {
    if (typeof copy.geo.lat === "number") { copy.geo.lat = _round1(copy.geo.lat); didRedact = true; }
    if (typeof copy.geo.lng === "number") { copy.geo.lng = _round1(copy.geo.lng); didRedact = true; }
  }
  if (typeof copy.notes === "string") {
    var ns = _scrubEmails(copy.notes);
    if (ns !== copy.notes) { copy.notes = ns; didRedact = true; }
  }
  return { value: copy, redacted: didRedact };
}

// ---------------------------------------------------------------------------
// Evidence scoring
// ---------------------------------------------------------------------------

function _priorityForWeight(w) {
  if (w >= 75) return "P0";
  if (w >= 50) return "P1";
  if (w >= 25) return "P2";
  return "P3";
}

function _evidence(idx, category, label, summary, weight, confidence, rawSignal, doRedact) {
  var redacted = _redactSignal(category, rawSignal, doRedact);
  return {
    id: "EV" + String(idx).padStart(3, "0"),
    category: category,
    weight: _clamp(Math.round(weight), 0, 100),
    priority: _priorityForWeight(weight),
    label: label,
    summary: summary,
    confidence: _clamp(confidence, 0, 1),
    rawSignal: redacted.value,
    redacted: redacted.redacted,
  };
}

function _gatherEvidence(session, riskMult, doRedact) {
  var items = [];
  var idx = 1;

  // Network
  if (typeof session.ipReputation === "number") {
    var ipRep = _clamp(session.ipReputation, 0, 1);
    // ipReputation: 1 = bad, 0 = good (treat as risk score)
    var w = ipRep * 85;
    if (w >= 10) {
      items.push(_evidence(idx++, "network", "IP reputation risk",
        "IP reputation score " + ipRep.toFixed(2), w * riskMult, 0.8,
        { ip: session.ip, ipReputation: ipRep, asn: session.asn }, doRedact));
    }
  }
  if (session.proxyDetected === true) {
    items.push(_evidence(idx++, "network", "Proxy detected",
      "Session originated through a proxy", 45 * riskMult, 0.75,
      { ip: session.ip, proxyDetected: true }, doRedact));
  }
  if (session.vpnDetected === true) {
    items.push(_evidence(idx++, "network", "VPN detected",
      "Session originated through a VPN endpoint", 40 * riskMult, 0.7,
      { ip: session.ip, vpnDetected: true }, doRedact));
  }
  if (session.tor === true) {
    items.push(_evidence(idx++, "network", "Tor exit node",
      "Traffic exited via the Tor network", 80 * riskMult, 0.9,
      { ip: session.ip, tor: true }, doRedact));
  }

  // Geo
  if (typeof session.geoRiskScore === "number" && session.geoRiskScore > 0) {
    var gw = _clamp(session.geoRiskScore, 0, 1) * 80;
    if (gw >= 10) {
      items.push(_evidence(idx++, "geo", "Geo-risk elevated",
        "Geographic risk score " + session.geoRiskScore.toFixed(2),
        gw * riskMult, 0.7,
        { geo: session.geo, geoRiskScore: session.geoRiskScore }, doRedact));
    }
  }

  // Behavioral / biometrics
  if (typeof session.biometricsScore === "number") {
    var b = _clamp(session.biometricsScore, 0, 1);
    var bw;
    if (b < 0.3) bw = 75;
    else if (b < 0.5) bw = 55;
    else if (b < 0.7) bw = 30;
    else bw = 10;
    items.push(_evidence(idx++, "biometrics", "Biometric confidence",
      "Behavioral biometrics score " + b.toFixed(2), bw * riskMult, 0.85,
      { biometricsScore: b, captchaType: session.captchaType }, doRedact));
  }

  // Account
  if (typeof session.accountAgeDays === "number" && session.accountAgeDays < 7) {
    items.push(_evidence(idx++, "account", "Fresh account",
      "Account is " + session.accountAgeDays + " day(s) old", 55 * riskMult, 0.95,
      { accountId: session.accountId, accountAgeDays: session.accountAgeDays }, doRedact));
  }
  if (typeof session.priorFailures === "number" && session.priorFailures >= 5) {
    items.push(_evidence(idx++, "account", "Repeated prior failures",
      session.priorFailures + " prior failures on record", 65 * riskMult, 0.85,
      { accountId: session.accountId, priorFailures: session.priorFailures }, doRedact));
  }

  // Honeypot
  if (typeof session.honeypotHits === "number" && session.honeypotHits > 0) {
    var hw = Math.min(95, session.honeypotHits * 35);
    items.push(_evidence(idx++, "honeypot", "Honeypot triggered",
      session.honeypotHits + " honeypot field(s) interacted with",
      hw * riskMult, 0.98,
      { honeypotHits: session.honeypotHits }, doRedact));
  }

  // Anomalies pass-through
  if (Array.isArray(session.anomalies)) {
    session.anomalies.forEach(function (a) {
      if (!_isObj(a)) return;
      var sev = typeof a.severity === "number" ? a.severity : 30;
      items.push(_evidence(idx++, "anomalies",
        "Anomaly: " + (a.code || "UNKNOWN"),
        a.evidence ? String(a.evidence).slice(0, 120) : "anomaly signal",
        sev * riskMult, 0.7, a, doRedact));
    });
  }

  // Temporal — rapid solves
  if (Array.isArray(session.attempts)) {
    var fast = session.attempts.filter(function (at) {
      return _isObj(at) && typeof at.durationMs === "number" && at.durationMs < 2000;
    });
    if (fast.length > 0) {
      items.push(_evidence(idx++, "temporal", "Sub-2s captcha solve(s)",
        fast.length + " attempt(s) solved in <2s",
        Math.min(70, 40 + (fast.length - 1) * 10) * riskMult, 0.75,
        { rapidAttempts: fast.length, sampleDurations: fast.slice(0, 3).map(function(a){return a.durationMs;}) },
        doRedact));
    }
  }

  // Crosslink
  if (Array.isArray(session.relatedSessions) && session.relatedSessions.length >= 2) {
    var rsW = session.relatedSessions.length >= 5 ? 80 : 50;
    items.push(_evidence(idx++, "crosslink", "Related sessions",
      session.relatedSessions.length + " related session(s) identified",
      rsW * riskMult, 0.65,
      { relatedSessions: session.relatedSessions.slice(0, 10) }, doRedact));
  }

  // Device fingerprint (low-weight context)
  if (typeof session.deviceFingerprint === "string" && session.deviceFingerprint.length > 0) {
    items.push(_evidence(idx++, "device", "Device fingerprint captured",
      "fp=" + session.deviceFingerprint.slice(0, 12), 15 * riskMult, 0.6,
      { deviceFingerprint: session.deviceFingerprint, userAgent: session.userAgent }, doRedact));
  }

  // Sort: priority then weight desc then id
  items.sort(function (a, b) {
    var pa = PRIORITY_RANK[a.priority];
    var pb = PRIORITY_RANK[b.priority];
    if (pa !== pb) return pa - pb;
    if (a.weight !== b.weight) return b.weight - a.weight;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

  // Re-clamp weights after multiplier
  items.forEach(function (it) { it.weight = _clamp(Math.round(it.weight), 0, 100); });
  return items;
}

// ---------------------------------------------------------------------------
// Insights
// ---------------------------------------------------------------------------

function _isDatacenterAsn(asn) {
  if (!asn) return false;
  var s = String(asn).toLowerCase();
  return /(aws|amazon|google|microsoft|digitalocean|linode|hetzner|ovh|datacenter|colo|cloud)/.test(s);
}

function _computeInsights(session, evidence, decision, totalSignals) {
  var insights = [];
  if (Array.isArray(session.relatedSessions) && session.relatedSessions.length >= 3) {
    insights.push("COORDINATED_RING_SUSPECTED");
  }
  if (decision === "BLOCK") {
    var avgConf = evidence.length === 0 ? 0 :
      evidence.reduce(function (s, e) { return s + e.confidence; }, 0) / evidence.length;
    if (avgConf >= 0.7 && evidence.length >= 1) insights.push("HIGH_CONFIDENCE_BLOCK");
    else if (evidence.length > 0) insights.push("LOW_CONFIDENCE_BLOCK");
  }
  if ((session.vpnDetected || session.tor || session.proxyDetected) && _isDatacenterAsn(session.asn)) {
    insights.push("ANONYMIZATION_LAYERED");
  }
  if (typeof session.accountAgeDays === "number" && session.accountAgeDays < 7 && decision !== "PASS") {
    insights.push("FRESH_ACCOUNT_HIGH_RISK");
  }
  if (typeof session.biometricsScore === "number" &&
      session.biometricsScore >= 0.3 && session.biometricsScore <= 0.6) {
    insights.push("BIOMETRICS_INCONCLUSIVE");
  }
  // Geo-velocity check
  if (Array.isArray(session.attempts) && session.attempts.length >= 2 && _isObj(session.geo)) {
    // simple heuristic: if any attempt has its own geo and distance > 500km within < 60s, impossible
    var hasVelocity = session.attempts.some(function (a) {
      if (!_isObj(a) || !_isObj(a.geo) || typeof a.geo.lat !== "number") return false;
      var dlat = a.geo.lat - session.geo.lat;
      var dlng = (a.geo.lng || 0) - (session.geo.lng || 0);
      var distKm = Math.sqrt(dlat * dlat + dlng * dlng) * 111;
      return distKm > 500 && typeof a.durationMs === "number" && a.durationMs < 60000;
    });
    if (hasVelocity) insights.push("GEO_VELOCITY_IMPOSSIBLE");
  }
  if (decision === "PASS" && evidence.length === 0) insights.push("CLEAN_PASS");
  if (totalSignals === 0) insights.push("INSUFFICIENT_EVIDENCE");
  return insights;
}

// ---------------------------------------------------------------------------
// Playbook
// ---------------------------------------------------------------------------

function _buildPlaybook(session, evidence, decision, insights) {
  var actions = [];
  var p0Items = evidence.filter(function (e) { return e.priority === "P0"; });
  var hasP0 = p0Items.length > 0;
  var anyP01 = evidence.some(function (e) { return e.priority === "P0" || e.priority === "P1"; });
  var ev = function (cat) { return evidence.filter(function (e) { return e.category === cat; }).map(function (e) { return e.id; }); };
  var allP0Ids = p0Items.map(function (e) { return e.id; });

  function addAction(id, priority, label, reason, owner, blastRadius, reversibility, relatedEvidenceIds) {
    actions.push({
      id: id, priority: priority, label: label, reason: reason,
      owner: owner, blastRadius: blastRadius, reversibility: reversibility,
      relatedEvidenceIds: relatedEvidenceIds || [],
    });
  }

  if (hasP0) {
    addAction("FILE_INCIDENT", "P0", "File security incident",
      "P0 evidence present — escalate to SOC incident queue",
      "soc_analyst", 3, "medium", allP0Ids);
  }

  var avgConf = evidence.length === 0 ? 0 :
    evidence.reduce(function (s, e) { return s + e.confidence; }, 0) / evidence.length;

  if (decision === "BLOCK") {
    if (avgConf >= 0.7 && evidence.length >= 1) {
      addAction("NOTIFY_USER_OF_BLOCK", "P0", "Notify user of decision",
        "High-confidence block — issue user-facing notice with appeal path",
        "support", 2, "high", allP0Ids);
    } else if (evidence.length > 0) {
      addAction("OPEN_DISPUTE_TICKET", "P0", "Open dispute ticket",
        "Low-confidence block — pre-open dispute ticket to handle inbound appeal",
        "support", 2, "high", []);
    }
  }

  // Account takeover indicators
  var honeyHits = typeof session.honeypotHits === "number" ? session.honeypotHits : 0;
  var fresh = typeof session.accountAgeDays === "number" && session.accountAgeDays < 7;
  if (honeyHits >= 2 && fresh) {
    addAction("ESCALATE_TO_LEGAL", "P0", "Escalate to legal/compliance",
      "Honeypot abuse on fresh account — possible account-takeover or fraud",
      "legal", 4, "low", ev("honeypot").concat(ev("account")));
  } else if (honeyHits >= 2) {
    addAction("ESCALATE_TO_LEGAL", "P0", "Escalate to legal/compliance",
      honeyHits + " honeypot interactions — likely automated abuse",
      "legal", 4, "low", ev("honeypot"));
  }

  if (ev("account").length > 0) {
    addAction("ROTATE_CREDENTIALS", "P1", "Rotate / force re-auth",
      "Account-related evidence present — recommend forcing credential reset",
      "soc_analyst", 2, "medium", ev("account"));
  }
  if (Array.isArray(session.relatedSessions) && session.relatedSessions.length >= 2) {
    addAction("AUDIT_RELATED_SESSIONS", "P1", "Audit related sessions",
      session.relatedSessions.length + " linked session(s) — sweep for shared infra",
      "soc_analyst", 3, "medium", ev("crosslink"));
  }
  if (anyP01) {
    addAction("PRESERVE_LOG_EVIDENCE", "P1", "Preserve raw log evidence",
      "Snapshot raw events + indices for chain-of-custody before rotation",
      "compliance", 1, "high", []);
  }
  if (typeof session.biometricsScore === "number" && session.biometricsScore < 0.3) {
    addAction("REVIEW_BIOMETRICS_REPLAY", "P1", "Replay biometrics trace",
      "Biometrics score " + session.biometricsScore.toFixed(2) + " — likely automation",
      "soc_analyst", 1, "high", ev("biometrics"));
  }

  if (decision === "BLOCK" && typeof session.biometricsScore === "number" && evidence.length >= 2) {
    addAction("TRAINING_DATA_CANDIDATE", "P2", "Tag as training data candidate",
      "Strong-evidence block — label session for classifier retraining",
      "product", 1, "high", []);
  }
  if (decision === "BLOCK" && typeof session.trustScore === "number" && session.trustScore >= 0.7) {
    addAction("DOCUMENT_FALSE_POSITIVE", "P2", "Document possible false positive",
      "Trust score " + session.trustScore.toFixed(2) + " but decision=BLOCK — investigate conflict",
      "product", 2, "high", []);
  }

  if (decision === "PASS" && evidence.length === 0) {
    addAction("CLOSE_NO_ACTION", "P3", "Close — no action required",
      "Clean PASS with no signals", "soc_analyst", 1, "high", []);
  }

  // Dedupe by id (first wins)
  var seen = {};
  var deduped = [];
  actions.forEach(function (a) {
    if (seen[a.id]) return;
    seen[a.id] = true;
    deduped.push(a);
  });

  // Sort by priority then id
  deduped.sort(function (a, b) {
    var pa = PRIORITY_RANK[a.priority];
    var pb = PRIORITY_RANK[b.priority];
    if (pa !== pb) return pa - pb;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
  return deduped;
}

// ---------------------------------------------------------------------------
// Verdict + grade
// ---------------------------------------------------------------------------

function _verdict(evidence, totalSignals, decision, riskAppetite) {
  if (totalSignals === 0) {
    if (decision === "PASS") return "CLEAN";
    return "INSUFFICIENT";
  }
  var maxW = evidence.reduce(function (m, e) { return e.weight > m ? e.weight : m; }, 0);
  var strongCut = 75, modCut = 50, weakCut = 25;
  if (riskAppetite === "cautious") { strongCut -= 10; modCut -= 10; weakCut -= 5; }
  if (riskAppetite === "aggressive") { strongCut += 10; modCut += 10; weakCut += 5; }
  if (maxW >= strongCut) return "STRONG_EVIDENCE";
  if (maxW >= modCut) return "MODERATE_EVIDENCE";
  if (maxW >= weakCut) return "WEAK_EVIDENCE";
  return "INSUFFICIENT";
}

function _grade(evidence, session) {
  var totalW = evidence.reduce(function (s, e) { return s + e.weight; }, 0);
  // Force F: honeypot+tor combo, or honeypotHits>=2 with P0 honeypot evidence
  var honeyP0 = evidence.some(function (e) { return e.category === "honeypot" && e.priority === "P0"; });
  var torP0 = evidence.some(function (e) { return e.category === "network" && e.label === "Tor exit node" && e.priority === "P0"; });
  if (honeyP0 && torP0) return "F";
  if ((session.honeypotHits || 0) >= 2 && honeyP0) return "F";
  if (evidence.length === 0 || totalW <= 15) return "A";
  if (totalW <= 35) return "B";
  if (totalW <= 55) return "C";
  if (totalW <= 75) return "D";
  return "F";
}

// ---------------------------------------------------------------------------
// Public: bundle()
// ---------------------------------------------------------------------------

function _bundleImpl(session, options) {
  options = options || {};
  var risk = _normRisk(options.riskAppetite);
  var riskMult = VALID_RISKS[risk];
  var doRedact = options.redact !== false;
  var now = (options.now && typeof options.now === "function") ? options.now() : new Date();
  var generatedAt = (now instanceof Date) ? now.toISOString() : String(now);

  var snapshot = _deepCopy(session) || {};
  var evidence = _gatherEvidence(snapshot, riskMult, doRedact);
  var totalSignals = evidence.length;

  var decision = snapshot.decision || "UNKNOWN";
  var insights = _computeInsights(snapshot, evidence, decision, totalSignals);
  var playbook = _buildPlaybook(snapshot, evidence, decision, insights);

  var p0Count = evidence.filter(function (e) { return e.priority === "P0"; }).length;
  var p1Count = evidence.filter(function (e) { return e.priority === "P1"; }).length;
  var grade = _grade(evidence, snapshot);
  var verdict = _verdict(evidence, totalSignals, decision, risk);

  var headline;
  if (verdict === "CLEAN") headline = "Clean PASS — no findings";
  else if (verdict === "INSUFFICIENT") headline = "Insufficient evidence";
  else headline = verdict + " for decision=" + decision + " (grade " + grade + ", " + p0Count + " P0 / " + p1Count + " P1)";

  var summary = {
    sessionId: doRedact ? (snapshot.sessionId ? String(snapshot.sessionId).slice(0, 8) + "..." : null) : (snapshot.sessionId || null),
    decision: decision,
    evidenceGrade: grade,
    totalSignals: totalSignals,
    p0Count: p0Count,
    p1Count: p1Count,
    headline: headline,
    generatedAt: generatedAt,
  };

  var report = {
    summary: summary,
    verdict: verdict,
    evidence: evidence,
    playbook: playbook,
    insights: insights,
    chainOfCustody: null, // set below from canonical hash of the rest
    riskAppetite: risk,
    bundlerVersion: BUNDLER_VERSION,
  };

  // Canonical hash over evidence + playbook + insights + summary fields (excl generatedAt for stability across clocks? -> include it; user passes fixed now for determinism tests).
  var canonical = _stableStringify({
    summary: summary,
    verdict: verdict,
    evidence: evidence,
    playbook: playbook,
    insights: insights,
    riskAppetite: risk,
    bundlerVersion: BUNDLER_VERSION,
  });
  report.chainOfCustody = {
    sha256Hash: _sha256(canonical),
    bundlerVersion: BUNDLER_VERSION,
    generatedAt: generatedAt,
    signalCount: totalSignals,
  };
  return report;
}

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

function _formatText(report) {
  var lines = [];
  var s = report.summary;
  lines.push("SessionEvidenceBundler v" + report.bundlerVersion);
  lines.push("Summary: " + s.headline);
  lines.push("  session=" + (s.sessionId || "?") + " decision=" + s.decision + " grade=" + s.evidenceGrade +
    " verdict=" + report.verdict + " signals=" + s.totalSignals + " (P0=" + s.p0Count + " P1=" + s.p1Count + ")");
  lines.push("");
  lines.push("Evidence:");
  if (report.evidence.length === 0) lines.push("  None");
  report.evidence.forEach(function (e) {
    lines.push("  [" + e.priority + "] " + e.id + " " + e.category + " w=" + e.weight + " conf=" + e.confidence.toFixed(2) + " — " + e.label + ": " + e.summary);
  });
  lines.push("");
  lines.push("Playbook:");
  if (report.playbook.length === 0) lines.push("  None");
  report.playbook.forEach(function (a) {
    lines.push("  [" + a.priority + "] " + a.id + " (" + a.owner + ", blast=" + a.blastRadius + ", rev=" + a.reversibility + ") — " + a.label + ": " + a.reason);
  });
  lines.push("");
  lines.push("Insights: " + (report.insights.length ? report.insights.join(", ") : "None"));
  lines.push("");
  lines.push("Chain of Custody:");
  lines.push("  sha256=" + report.chainOfCustody.sha256Hash);
  lines.push("  generatedAt=" + report.chainOfCustody.generatedAt + " signalCount=" + report.chainOfCustody.signalCount);
  return lines.join("\n");
}

function _formatMarkdown(report) {
  var s = report.summary;
  var out = [];
  out.push("## Summary");
  out.push("");
  out.push("| Field | Value |");
  out.push("| --- | --- |");
  out.push("| Session | " + (s.sessionId || "?") + " |");
  out.push("| Decision | " + s.decision + " |");
  out.push("| Verdict | " + report.verdict + " |");
  out.push("| Grade | " + s.evidenceGrade + " |");
  out.push("| Signals | " + s.totalSignals + " (P0=" + s.p0Count + " P1=" + s.p1Count + ") |");
  out.push("| Headline | " + s.headline + " |");
  out.push("");
  out.push("## Evidence");
  out.push("");
  if (report.evidence.length === 0) {
    out.push("None");
  } else {
    out.push("| Priority | ID | Category | Weight | Confidence | Label | Summary |");
    out.push("| --- | --- | --- | --- | --- | --- | --- |");
    report.evidence.forEach(function (e) {
      out.push("| " + e.priority + " | " + e.id + " | " + e.category + " | " + e.weight +
        " | " + e.confidence.toFixed(2) + " | " + e.label + " | " + e.summary + " |");
    });
  }
  out.push("");
  out.push("## Playbook");
  out.push("");
  if (report.playbook.length === 0) {
    out.push("None");
  } else {
    out.push("| Priority | Action | Owner | Blast | Reversibility | Reason |");
    out.push("| --- | --- | --- | --- | --- | --- |");
    report.playbook.forEach(function (a) {
      out.push("| " + a.priority + " | " + a.label + " | " + a.owner + " | " + a.blastRadius + " | " + a.reversibility + " | " + a.reason + " |");
    });
  }
  out.push("");
  out.push("## Insights");
  out.push("");
  if (report.insights.length === 0) {
    out.push("- None");
  } else {
    report.insights.forEach(function (i) { out.push("- " + i); });
  }
  out.push("");
  out.push("## Chain of Custody");
  out.push("");
  out.push("```");
  out.push("sha256:    " + report.chainOfCustody.sha256Hash);
  out.push("version:   " + report.chainOfCustody.bundlerVersion);
  out.push("generated: " + report.chainOfCustody.generatedAt);
  out.push("signals:   " + report.chainOfCustody.signalCount);
  out.push("```");
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

function createSessionEvidenceBundler(globalOpts) {
  var defaults = (globalOpts && typeof globalOpts === "object") ? globalOpts : {};
  var historyLimit = typeof defaults.historyLimit === "number" ? defaults.historyLimit : 50;
  var history = [];
  var config = Object.assign({ riskAppetite: "balanced", redact: true }, defaults);
  var listeners = [];

  function _notify() {
    listeners.slice().forEach(function (fn) {
      try { fn(); } catch (e) { /* swallow */ }
    });
  }

  return {
    bundle: function (session, callOpts) {
      var merged = Object.assign({}, config, callOpts || {});
      var report = _bundleImpl(session, merged);
      if (!merged.dryRun) {
        history.unshift(report);
        if (history.length > historyLimit) history.length = historyLimit;
        _notify();
      }
      return report;
    },
    format: function (report, fmt) {
      var f = (fmt || "text").toLowerCase();
      if (f === "json") return _stableStringify(report);
      if (f === "md" || f === "markdown") return _formatMarkdown(report);
      return _formatText(report);
    },
    history: function (limit) {
      var n = typeof limit === "number" ? Math.max(0, limit) : history.length;
      return history.slice(0, n);
    },
    getConfig: function () { return Object.assign({}, config); },
    setConfig: function (next) {
      if (next && typeof next === "object") {
        config = Object.assign({}, config, next);
        _notify();
      }
      return Object.assign({}, config);
    },
    onChange: function (fn) {
      if (typeof fn !== "function") return function () {};
      listeners.push(fn);
      return function () {
        var i = listeners.indexOf(fn);
        if (i >= 0) listeners.splice(i, 1);
      };
    },
    _reset: function () {
      history.length = 0;
      listeners.length = 0;
    },
  };
}

module.exports = {
  createSessionEvidenceBundler: createSessionEvidenceBundler,
  BUNDLER_VERSION: BUNDLER_VERSION,
};
