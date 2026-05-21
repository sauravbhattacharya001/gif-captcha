"use strict";

/**
 * CrossSessionLinkageAdvisor - 9th agentic sibling for gif-captcha.
 *
 * Distinct from existing siblings:
 *   - attack-response-playbook            (cross-anomaly reactive playbook)
 *   - attack-forecaster                   (forward escalation forecaster)
 *   - user-abandonment-forecaster         (UX-friction forecaster)
 *   - false-reject-recovery-advisor       (per-session FR recovery)
 *   - human-verification-confidence-auditor (post-PASS false-accept audit)
 *   - honeypot-effectiveness-advisor      (honeypot tuning)
 *   - blocked-session-appeal-adjudicator  (post-BLOCK appeal evaluator)
 *   - session-step-up-advisor             (per-session step-up auth)
 *
 * fraud-ring-detector is a graph traversal over financial/account links.
 * CrossSessionLinkageAdvisor sits one layer up the funnel: given a recent
 * batch of CAPTCHA sessions, cluster them into suspected actor groups
 * (botnets, residential-proxy subnets, NAT'd offices, shared fingerprints,
 * behavioral twins) and emit an explainable, risk-appetite-aware playbook
 * the SOC can act on as a fleet (block subnet, flag ASN, force step-up
 * for cohort, raise difficulty, send to manual review).
 *
 * API:
 *   var adv = createCrossSessionLinkageAdvisor({ riskAppetite, now });
 *   var report = adv.analyze(sessions);     // never mutates input
 *   var text   = adv.format(report, "text" | "md" | "markdown" | "json");
 *
 * Pure JS, no deps, ES5-flavored. Deterministic given fixed inputs +
 * risk_appetite + now. JSON output is byte-stable via deep sorted-keys
 * serialization.
 *
 * @module cross-session-linkage-advisor
 */

var DEFAULT_RISK = "balanced";
var RISK_MULT = {
  cautious:   { thresholdShift: -1, strengthShift: +10, portfolio: 1.15 },
  balanced:   { thresholdShift:  0, strengthShift:   0, portfolio: 1.00 },
  aggressive: { thresholdShift: +1, strengthShift: -10, portfolio: 0.85 }
};

function _clamp(n, lo, hi) {
  if (typeof n !== "number" || !isFinite(n)) return lo;
  if (n < lo) return lo;
  if (n > hi) return hi;
  return n;
}

function _num(v, fb) {
  if (typeof v === "number" && isFinite(v)) return v;
  return fb;
}

function _str(v, fb) {
  if (typeof v === "string" && v.length) return v;
  return fb;
}

function _normRisk(r) { return (r && RISK_MULT[r]) ? r : DEFAULT_RISK; }

function _deriveCidr24(ip) {
  if (typeof ip !== "string" || !ip.length) return null;
  // IPv4 only for /24 derivation
  var parts = ip.split(".");
  if (parts.length !== 4) return null;
  for (var i = 0; i < 4; i++) {
    var n = parseInt(parts[i], 10);
    if (!(n >= 0 && n <= 255 && String(n) === parts[i].replace(/^0+(?=\d)/, ""))) return null;
  }
  return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
}

function _normSession(s) {
  if (!s || typeof s !== "object") return null;
  var sid = _str(s.sessionId, null);
  if (!sid) return null;
  var ip = _str(s.ip, null);
  var cidr = _str(s.ipv4Cidr24, null);
  if (!cidr && ip) cidr = _deriveCidr24(ip);
  return {
    sessionId: sid,
    ip: ip,
    ipv4Cidr24: cidr,
    asn: _str(s.asn, null),
    asnOrg: _str(s.asnOrg, null),
    userAgent: _str(s.userAgent, null),
    fingerprintHash: _str(s.fingerprintHash, null),
    deviceCohortKey: _str(s.deviceCohortKey, null),
    solveTimeMs: _num(s.solveTimeMs, null),
    solveSuccessful: s.solveSuccessful === true,
    solvePatternFingerprint: _str(s.solvePatternFingerprint, null),
    biometricsScore: _num(s.biometricsScore, null),
    geoCountry: _str(s.geoCountry, null),
    blockedReason: _str(s.blockedReason, null),
    ts: _num(s.ts, null)
  };
}

// Simple deterministic 32-bit hash so we don't need 'crypto' for group ids.
function _hash32(str) {
  var h = 2166136261 >>> 0;
  for (var i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return ("00000000" + h.toString(16)).slice(-8);
}

function _groupId(prefix, memberIds) {
  var sorted = memberIds.slice().sort();
  return prefix + "-" + _hash32(sorted.join("|"));
}

function _addReason(arr, code, label, weight, evidence) {
  arr.push({ code: code, label: label, weight: weight, evidence: evidence == null ? "" : String(evidence) });
}

// ---------------- Linkage detectors ----------------

function _detectCoordinatedBotnet(sessions, minMembers) {
  // Same IP AND same UA AND timing within 8% (or fingerprint exact match)
  var byIpUa = Object.create(null);
  for (var i = 0; i < sessions.length; i++) {
    var s = sessions[i];
    if (!s.ip || !s.userAgent) continue;
    var key = s.ip + "||" + s.userAgent;
    (byIpUa[key] = byIpUa[key] || []).push(s);
  }
  var groups = [];
  Object.keys(byIpUa).forEach(function (k) {
    var bucket = byIpUa[k];
    if (bucket.length < minMembers) return;
    // Timing tightness
    var times = bucket.map(function (b) { return b.solveTimeMs; }).filter(function (t) { return t != null; });
    var tight = false;
    if (times.length >= 2) {
      var min = Math.min.apply(null, times);
      var max = Math.max.apply(null, times);
      if (min > 0 && (max - min) / min <= 0.08) tight = true;
    }
    // Or same fingerprint hash
    var fps = {};
    bucket.forEach(function (b) { if (b.fingerprintHash) fps[b.fingerprintHash] = (fps[b.fingerprintHash] || 0) + 1; });
    var fpMax = 0; Object.keys(fps).forEach(function (k2) { if (fps[k2] > fpMax) fpMax = fps[k2]; });
    if (tight || fpMax >= minMembers) {
      groups.push({ kind: "COORDINATED_BOTNET", members: bucket, evidence: { ipUa: k, tightTiming: tight, fpMax: fpMax } });
    }
  });
  return groups;
}

function _detectSubnetCluster(sessions, minMembers) {
  // Same /24, varied UAs (>=2 distinct UAs) — residential proxy / botnet rotation
  var byCidr = Object.create(null);
  for (var i = 0; i < sessions.length; i++) {
    var s = sessions[i];
    if (!s.ipv4Cidr24) continue;
    (byCidr[s.ipv4Cidr24] = byCidr[s.ipv4Cidr24] || []).push(s);
  }
  var groups = [];
  Object.keys(byCidr).forEach(function (k) {
    var bucket = byCidr[k];
    if (bucket.length < minMembers) return;
    var uas = {};
    bucket.forEach(function (b) { if (b.userAgent) uas[b.userAgent] = 1; });
    var nUas = Object.keys(uas).length;
    // Skip if all share single UA (that's COORDINATED_BOTNET territory, captured above)
    if (nUas < 2) return;
    groups.push({ kind: "SUBNET_CLUSTER", members: bucket, evidence: { cidr: k, distinctUas: nUas } });
  });
  return groups;
}

function _detectAsnFleet(sessions, minMembers) {
  // Same ASN, distinct IPs (>=3), high failure rate or suspicious cohort
  var byAsn = Object.create(null);
  for (var i = 0; i < sessions.length; i++) {
    var s = sessions[i];
    if (!s.asn) continue;
    (byAsn[s.asn] = byAsn[s.asn] || []).push(s);
  }
  var groups = [];
  Object.keys(byAsn).forEach(function (k) {
    var bucket = byAsn[k];
    if (bucket.length < minMembers) return;
    var ips = {};
    bucket.forEach(function (b) { if (b.ip) ips[b.ip] = 1; });
    var distinctIps = Object.keys(ips).length;
    if (distinctIps < 3) return;
    var fails = 0;
    bucket.forEach(function (b) { if (!b.solveSuccessful) fails++; });
    var failRate = bucket.length > 0 ? fails / bucket.length : 0;
    if (failRate < 0.30) return;
    groups.push({ kind: "ASN_FLEET", members: bucket, evidence: { asn: k, distinctIps: distinctIps, failRate: Math.round(failRate * 1000) / 1000 } });
  });
  return groups;
}

function _detectDeviceCohortDuplicate(sessions, minMembers) {
  // Same fingerprint hash across >=2 sessions
  var byFp = Object.create(null);
  for (var i = 0; i < sessions.length; i++) {
    var s = sessions[i];
    if (!s.fingerprintHash) continue;
    (byFp[s.fingerprintHash] = byFp[s.fingerprintHash] || []).push(s);
  }
  var groups = [];
  Object.keys(byFp).forEach(function (k) {
    var bucket = byFp[k];
    if (bucket.length < minMembers) return;
    groups.push({ kind: "DEVICE_COHORT_DUPLICATE", members: bucket, evidence: { fingerprintHash: k, count: bucket.length } });
  });
  return groups;
}

function _detectBehavioralTwin(sessions, minMembers) {
  // Identical solvePatternFingerprint AND solve times within 5%
  var byPattern = Object.create(null);
  for (var i = 0; i < sessions.length; i++) {
    var s = sessions[i];
    if (!s.solvePatternFingerprint || s.solveTimeMs == null) continue;
    (byPattern[s.solvePatternFingerprint] = byPattern[s.solvePatternFingerprint] || []).push(s);
  }
  var groups = [];
  Object.keys(byPattern).forEach(function (k) {
    var bucket = byPattern[k];
    if (bucket.length < minMembers) return;
    var times = bucket.map(function (b) { return b.solveTimeMs; });
    var min = Math.min.apply(null, times);
    var max = Math.max.apply(null, times);
    if (min <= 0) return;
    var spread = (max - min) / min;
    if (spread > 0.05) return;
    groups.push({ kind: "BEHAVIORAL_TWIN", members: bucket, evidence: { solvePatternFingerprint: k, spread: Math.round(spread * 10000) / 10000 } });
  });
  return groups;
}

function _detectSharedProxy(sessions, minMembers, claimedByBotnet) {
  // Same IP, >=2 distinct UAs, mixed pass/fail — looks like NAT'd office
  var byIp = Object.create(null);
  for (var i = 0; i < sessions.length; i++) {
    var s = sessions[i];
    if (!s.ip) continue;
    if (claimedByBotnet[s.sessionId]) continue; // exclude botnet members
    (byIp[s.ip] = byIp[s.ip] || []).push(s);
  }
  var groups = [];
  Object.keys(byIp).forEach(function (k) {
    var bucket = byIp[k];
    if (bucket.length < minMembers) return;
    var uas = {};
    bucket.forEach(function (b) { if (b.userAgent) uas[b.userAgent] = 1; });
    if (Object.keys(uas).length < 2) return;
    var passes = 0, fails = 0;
    bucket.forEach(function (b) { if (b.solveSuccessful) passes++; else fails++; });
    if (passes === 0 || fails === 0) return;
    groups.push({ kind: "SHARED_PROXY", members: bucket, evidence: { ip: k, passes: passes, fails: fails, distinctUas: Object.keys(uas).length } });
  });
  return groups;
}

function _detectWeakAsnLinkage(sessions, minMembers, claimed) {
  // ASN-only linkage with no other signals
  var byAsn = Object.create(null);
  for (var i = 0; i < sessions.length; i++) {
    var s = sessions[i];
    if (!s.asn || claimed[s.sessionId]) continue;
    (byAsn[s.asn] = byAsn[s.asn] || []).push(s);
  }
  var groups = [];
  Object.keys(byAsn).forEach(function (k) {
    var bucket = byAsn[k];
    if (bucket.length < minMembers) return;
    groups.push({ kind: "WEAK_LINKAGE", members: bucket, evidence: { asn: k, count: bucket.length } });
  });
  return groups;
}

// ---------------- Scoring ----------------

var VERDICT_BASE_STRENGTH = {
  COORDINATED_BOTNET: 90,
  SUBNET_CLUSTER: 78,
  ASN_FLEET: 62,
  DEVICE_COHORT_DUPLICATE: 58,
  BEHAVIORAL_TWIN: 60,
  SHARED_PROXY: 30,
  WEAK_LINKAGE: 18
};

var VERDICT_PRIORITY = {
  COORDINATED_BOTNET: "P0",
  SUBNET_CLUSTER: "P0",
  ASN_FLEET: "P1",
  DEVICE_COHORT_DUPLICATE: "P1",
  BEHAVIORAL_TWIN: "P1",
  SHARED_PROXY: "P2",
  WEAK_LINKAGE: "P3"
};

var VERDICT_RECOMMENDED_ACTION = {
  COORDINATED_BOTNET: "BLOCK_GROUP_NOW",
  SUBNET_CLUSTER: "BLOCK_SUBNET",
  ASN_FLEET: "FLAG_ASN_FOR_REVIEW",
  DEVICE_COHORT_DUPLICATE: "FORCE_STEP_UP_GROUP",
  BEHAVIORAL_TWIN: "FORCE_STEP_UP_GROUP",
  SHARED_PROXY: "MONITOR_GROUP",
  WEAK_LINKAGE: "MONITOR_GROUP"
};

var VERDICT_BLAST = {
  COORDINATED_BOTNET: 4,
  SUBNET_CLUSTER: 5,
  ASN_FLEET: 4,
  DEVICE_COHORT_DUPLICATE: 2,
  BEHAVIORAL_TWIN: 2,
  SHARED_PROXY: 1,
  WEAK_LINKAGE: 1
};

var VERDICT_REVERSIBILITY = {
  COORDINATED_BOTNET: "medium",
  SUBNET_CLUSTER: "medium",
  ASN_FLEET: "high",
  DEVICE_COHORT_DUPLICATE: "high",
  BEHAVIORAL_TWIN: "high",
  SHARED_PROXY: "high",
  WEAK_LINKAGE: "high"
};

function _verdictFpRate(v) {
  if (v === "SHARED_PROXY") return "high";
  if (v === "WEAK_LINKAGE") return "high";
  if (v === "ASN_FLEET") return "medium";
  return "low";
}

function _buildGroupRecord(raw, riskKey) {
  var mult = RISK_MULT[riskKey];
  var members = raw.members;
  var memberIds = members.map(function (m) { return m.sessionId; }).sort();
  var verdict = raw.kind;
  var base = VERDICT_BASE_STRENGTH[verdict];
  // size bonus
  var sizeBonus = Math.min(15, (members.length - 2) * 3);
  var strength = _clamp(base + sizeBonus + mult.strengthShift, 0, 100);

  var reasons = [];
  switch (verdict) {
    case "COORDINATED_BOTNET":
      _addReason(reasons, "SHARED_IP_AND_UA", "All members share the same IP and User-Agent", 35, raw.evidence.ipUa);
      if (raw.evidence.tightTiming) _addReason(reasons, "TIGHT_SOLVE_TIMING", "Solve times within 8% across members", 30, "tight");
      if (raw.evidence.fpMax >= 2) _addReason(reasons, "SHARED_FINGERPRINT", raw.evidence.fpMax + " members share fingerprint", 25, "fpMax=" + raw.evidence.fpMax);
      break;
    case "SUBNET_CLUSTER":
      _addReason(reasons, "SAME_SUBNET", "Members share /24 subnet", 30, raw.evidence.cidr);
      _addReason(reasons, "VARIED_USER_AGENTS", raw.evidence.distinctUas + " distinct UAs (proxy rotation pattern)", 20, "distinctUas=" + raw.evidence.distinctUas);
      break;
    case "ASN_FLEET":
      _addReason(reasons, "SAME_ASN_FLEET", "Members share ASN " + raw.evidence.asn, 20, "asn=" + raw.evidence.asn);
      _addReason(reasons, "HIGH_FAIL_RATE_ON_ASN", "Failure rate " + (raw.evidence.failRate * 100).toFixed(1) + "% on this ASN", 20, "failRate=" + raw.evidence.failRate);
      break;
    case "DEVICE_COHORT_DUPLICATE":
      _addReason(reasons, "DUPLICATE_FINGERPRINT", "Identical device fingerprint across " + raw.evidence.count + " sessions", 30, raw.evidence.fingerprintHash);
      break;
    case "BEHAVIORAL_TWIN":
      _addReason(reasons, "IDENTICAL_SOLVE_PATTERN", "Identical solve-pattern fingerprint and timing within 5%", 30, raw.evidence.solvePatternFingerprint);
      _addReason(reasons, "TIMING_SPREAD_LOW", "Spread " + (raw.evidence.spread * 100).toFixed(2) + "%", 15, "spread=" + raw.evidence.spread);
      break;
    case "SHARED_PROXY":
      _addReason(reasons, "SHARED_IP_VARIED_UAS", raw.evidence.distinctUas + " UAs sharing IP " + raw.evidence.ip, 10, "ip=" + raw.evidence.ip);
      _addReason(reasons, "MIXED_OUTCOMES", "Mixed pass/fail outcomes — likely NAT'd office", 5, raw.evidence.passes + "/" + raw.evidence.fails);
      break;
    case "WEAK_LINKAGE":
      _addReason(reasons, "ASN_ONLY", "Only ASN is shared — generic linkage", 5, raw.evidence.asn);
      break;
  }

  return {
    groupId: _groupId(verdict.toLowerCase().split("_")[0], memberIds),
    verdict: verdict,
    priority: VERDICT_PRIORITY[verdict],
    memberSessionIds: memberIds,
    memberCount: memberIds.length,
    linkage_strength: strength,
    recommended_action: VERDICT_RECOMMENDED_ACTION[verdict],
    expected_fp_rate: _verdictFpRate(verdict),
    blast_radius: VERDICT_BLAST[verdict],
    reversibility: VERDICT_REVERSIBILITY[verdict],
    reasons: reasons,
    evidence: raw.evidence
  };
}

// ---------------- Playbook + insights ----------------

function _buildPlaybook(groups, riskKey) {
  var actions = [];
  var byVerdict = {};
  groups.forEach(function (g) { (byVerdict[g.verdict] = byVerdict[g.verdict] || []).push(g); });

  function add(id, priority, label, reason, owner, blast, reversibility, ids) {
    actions.push({
      id: id, priority: priority, label: label, reason: reason,
      owner: owner, blast_radius: blast, reversibility: reversibility,
      related_group_ids: ids ? ids.slice().sort() : []
    });
  }

  if (byVerdict.COORDINATED_BOTNET) {
    add("BLOCK_TOP_BOTNET", "P0",
        "Block all sessions in coordinated botnet groups",
        "Sessions share IP+UA with tight timing/fingerprint — high-confidence coordinated automation",
        "security_ops", 4, "medium",
        byVerdict.COORDINATED_BOTNET.map(function (g) { return g.groupId; }));
  }
  if (byVerdict.SUBNET_CLUSTER) {
    add("BLOCK_SUSPICIOUS_SUBNETS", "P0",
        "Block /24 subnets fronting rotating UAs",
        "Residential-proxy rotation pattern on /24 — block the subnet, not individual sessions",
        "security_ops", 5, "medium",
        byVerdict.SUBNET_CLUSTER.map(function (g) { return g.groupId; }));
  }
  if (byVerdict.ASN_FLEET) {
    add("FLAG_ASNS_FOR_REVIEW", "P1",
        "Flag involved ASNs for SOC review",
        "ASN-wide failure clusters — escalate to SOC, raise difficulty for that ASN",
        "soc_analyst", 4, "high",
        byVerdict.ASN_FLEET.map(function (g) { return g.groupId; }));
  }
  var stepUpIds = [];
  if (byVerdict.DEVICE_COHORT_DUPLICATE) stepUpIds = stepUpIds.concat(byVerdict.DEVICE_COHORT_DUPLICATE.map(function (g) { return g.groupId; }));
  if (byVerdict.BEHAVIORAL_TWIN) stepUpIds = stepUpIds.concat(byVerdict.BEHAVIORAL_TWIN.map(function (g) { return g.groupId; }));
  if (stepUpIds.length) {
    add("STEP_UP_ALL_LINKED_SESSIONS", "P1",
        "Force step-up auth across linked cohorts",
        "Members share fingerprint or behavioral twin — require additional verification",
        "platform", 2, "high", stepUpIds);
  }
  if (byVerdict.DEVICE_COHORT_DUPLICATE || byVerdict.BEHAVIORAL_TWIN || byVerdict.ASN_FLEET) {
    add("RAISE_DIFFICULTY_FOR_COHORTS", "P1",
        "Raise CAPTCHA difficulty for affected device cohorts and ASNs",
        "Lift bar for cohorts implicated in linkage groups without blanket blocks",
        "platform", 3, "high",
        groups.filter(function (g) { return g.verdict === "DEVICE_COHORT_DUPLICATE" || g.verdict === "BEHAVIORAL_TWIN" || g.verdict === "ASN_FLEET"; }).map(function (g) { return g.groupId; }));
  }
  var manualReviewIds = groups
    .filter(function (g) { return (g.priority === "P0" || g.priority === "P1") && g.expected_fp_rate !== "low"; })
    .map(function (g) { return g.groupId; });
  if (manualReviewIds.length) {
    add("SCALE_OUT_MANUAL_REVIEW", "P2",
        "Queue ambiguous high-FP linkage groups for human review",
        "Some P0/P1 groups have medium/high expected false-positive rate — humans should triage before blanket blocks",
        "soc_analyst", 2, "high", manualReviewIds);
  }
  if (riskKey === "cautious" && actions.length === 0) {
    add("MONITOR_FOR_LINKAGE", "P2",
        "Monitor for emerging linkage even though none detected this batch",
        "Cautious risk_appetite — keep watching",
        "soc_analyst", 1, "high", []);
  }
  if (actions.length === 0) {
    add("NO_LINKAGE_ACTION", "P3",
        "No linkage action required",
        "No suspicious linkage groups in this batch",
        "platform", 1, "high", []);
  }

  // dedupe by id, P0-first
  var seen = {};
  var deduped = [];
  actions.forEach(function (a) {
    if (seen[a.id]) return;
    seen[a.id] = 1;
    deduped.push(a);
  });
  var pri = { P0: 0, P1: 1, P2: 2, P3: 3 };
  deduped.sort(function (a, b) {
    var pa = pri[a.priority] != null ? pri[a.priority] : 9;
    var pb = pri[b.priority] != null ? pri[b.priority] : 9;
    if (pa !== pb) return pa - pb;
    return a.id < b.id ? -1 : 1;
  });
  if (riskKey === "aggressive") {
    // trim NO_LINKAGE_ACTION when something else is present
    var hasReal = deduped.some(function (a) { return a.id !== "NO_LINKAGE_ACTION" && a.id !== "MONITOR_FOR_LINKAGE"; });
    if (hasReal) {
      deduped = deduped.filter(function (a) { return a.id !== "NO_LINKAGE_ACTION" && a.priority !== "P3"; });
    }
  }
  return deduped;
}

function _buildInsights(groups, sessions) {
  var insights = [];
  var has = function (v) { return groups.some(function (g) { return g.verdict === v; }); };

  if (has("COORDINATED_BOTNET")) insights.push({ code: "BOTNET_PRESENT", label: "Coordinated botnet detected", severity: "critical" });
  if (has("SUBNET_CLUSTER")) insights.push({ code: "RESIDENTIAL_PROXY_PATTERN", label: "Subnet-rotation / residential-proxy pattern detected", severity: "critical" });
  if (has("DEVICE_COHORT_DUPLICATE") || has("BEHAVIORAL_TWIN")) insights.push({ code: "SHARED_FINGERPRINT_FLEET", label: "Multiple sessions share fingerprint or solve pattern", severity: "high" });
  if (has("SHARED_PROXY")) insights.push({ code: "SHARED_PROXY_PATTERN", label: "Mixed-outcome shared IP — looks like NAT'd office", severity: "info" });
  if (groups.length === 0) insights.push({ code: "NO_LINKAGE_DETECTED", label: "No suspicious cross-session linkage", severity: "info" });
  if (sessions.length < 5) insights.push({ code: "SPARSE_INPUT", label: "Fewer than 5 sessions — linkage detection is unreliable", severity: "info" });

  // sort deterministically by code
  insights.sort(function (a, b) { return a.code < b.code ? -1 : a.code > b.code ? 1 : 0; });
  return insights;
}

// ---------------- Byte-stable JSON ----------------

function _sortedDeep(v) {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(_sortedDeep);
  var out = {};
  Object.keys(v).sort().forEach(function (k) { out[k] = _sortedDeep(v[k]); });
  return out;
}

function _stableJson(o) { return JSON.stringify(_sortedDeep(o), null, 2); }

// ---------------- Formatters ----------------

function _toText(report) {
  var lines = [];
  lines.push("CrossSessionLinkageAdvisor report");
  lines.push("=================================");
  lines.push("Summary: totalSessions=" + report.summary.totalSessions +
             " totalGroups=" + report.summary.totalGroups +
             " isolated=" + report.summary.isolatedSessions +
             " P0=" + report.summary.p0Groups +
             " P1=" + report.summary.p1Groups +
             " grade=" + report.summary.grade +
             " risk=" + report.summary.portfolio_risk_score);
  lines.push("");
  lines.push("Groups:");
  if (!report.groups.length) lines.push("  (none)");
  report.groups.forEach(function (g) {
    lines.push("  - [" + g.priority + "] " + g.verdict + " " + g.groupId +
               " strength=" + g.linkage_strength +
               " action=" + g.recommended_action +
               " members=" + g.memberCount);
  });
  lines.push("");
  lines.push("Playbook:");
  report.playbook.forEach(function (a) {
    lines.push("  - [" + a.priority + "] " + a.id + " (" + a.owner + ", blast=" + a.blast_radius + ", " + a.reversibility + "): " + a.label);
  });
  lines.push("");
  lines.push("Insights:");
  if (!report.insights.length) lines.push("  (none)");
  report.insights.forEach(function (i) {
    lines.push("  - " + i.code + " [" + i.severity + "] " + i.label);
  });
  return lines.join("\n");
}

function _toMarkdown(report) {
  var lines = [];
  lines.push("# Cross-Session Linkage Advisor");
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|---|---|");
  lines.push("| Total sessions | " + report.summary.totalSessions + " |");
  lines.push("| Total groups | " + report.summary.totalGroups + " |");
  lines.push("| Isolated sessions | " + report.summary.isolatedSessions + " |");
  lines.push("| P0 groups | " + report.summary.p0Groups + " |");
  lines.push("| P1 groups | " + report.summary.p1Groups + " |");
  lines.push("| Portfolio risk | " + report.summary.portfolio_risk_score + " |");
  lines.push("| Grade | " + report.summary.grade + " |");
  lines.push("| Risk appetite | " + report.summary.riskAppetite + " |");
  lines.push("");
  lines.push("## Groups");
  lines.push("");
  if (!report.groups.length) {
    lines.push("_None._");
  } else {
    lines.push("| Priority | Verdict | Group | Strength | Members | Action | FP risk |");
    lines.push("|---|---|---|---:|---:|---|---|");
    report.groups.forEach(function (g) {
      lines.push("| " + g.priority + " | " + g.verdict + " | " + g.groupId +
                 " | " + g.linkage_strength + " | " + g.memberCount + " | " +
                 g.recommended_action + " | " + g.expected_fp_rate + " |");
    });
  }
  lines.push("");
  lines.push("## Playbook");
  lines.push("");
  lines.push("| Priority | Action | Owner | Blast | Reversibility | Reason |");
  lines.push("|---|---|---|---:|---|---|");
  report.playbook.forEach(function (a) {
    lines.push("| " + a.priority + " | " + a.id + " | " + a.owner +
               " | " + a.blast_radius + " | " + a.reversibility + " | " + a.reason + " |");
  });
  lines.push("");
  lines.push("## Insights");
  lines.push("");
  if (!report.insights.length) {
    lines.push("_None._");
  } else {
    report.insights.forEach(function (i) {
      lines.push("- **" + i.code + "** [" + i.severity + "] — " + i.label);
    });
  }
  return lines.join("\n");
}

// ---------------- Main ----------------

function createCrossSessionLinkageAdvisor(opts) {
  opts = opts || {};
  var riskAppetiteDefault = _normRisk(opts.riskAppetite);
  var nowFn = (typeof opts.now === "function") ? opts.now : function () { return Date.now(); };

  function analyze(sessionsIn, perCallOpts) {
    perCallOpts = perCallOpts || {};
    var riskKey = _normRisk(perCallOpts.riskAppetite || riskAppetiteDefault);
    var risk = RISK_MULT[riskKey];

    var input = Array.isArray(sessionsIn) ? sessionsIn : [];
    // Deep copy so we never mutate caller
    var snapshot = JSON.parse(JSON.stringify(input));
    var sessions = [];
    for (var i = 0; i < snapshot.length; i++) {
      var n = _normSession(snapshot[i]);
      if (n) sessions.push(n);
    }

    // Per-detector thresholds (modulated by appetite)
    var minBotnet      = Math.max(2, 3 + risk.thresholdShift);
    var minSubnet      = Math.max(2, 3 + risk.thresholdShift);
    var minAsnFleet    = Math.max(3, 5 + risk.thresholdShift);
    var minFingerprint = Math.max(2, 2 + risk.thresholdShift);
    var minTwin        = Math.max(2, 2 + risk.thresholdShift);
    var minSharedProxy = Math.max(2, 3 + risk.thresholdShift);
    var minWeak        = Math.max(3, 5 + risk.thresholdShift);

    var raws = [];
    var botnets = _detectCoordinatedBotnet(sessions, minBotnet);
    raws = raws.concat(botnets);
    var claimedByBotnet = {};
    botnets.forEach(function (g) { g.members.forEach(function (m) { claimedByBotnet[m.sessionId] = 1; }); });

    raws = raws.concat(_detectSubnetCluster(sessions, minSubnet));
    raws = raws.concat(_detectAsnFleet(sessions, minAsnFleet));
    raws = raws.concat(_detectDeviceCohortDuplicate(sessions, minFingerprint));
    raws = raws.concat(_detectBehavioralTwin(sessions, minTwin));
    raws = raws.concat(_detectSharedProxy(sessions, minSharedProxy, claimedByBotnet));

    // Track all claimed members so far for weak ASN check
    var claimedAny = {};
    raws.forEach(function (g) { g.members.forEach(function (m) { claimedAny[m.sessionId] = 1; }); });
    raws = raws.concat(_detectWeakAsnLinkage(sessions, minWeak, claimedAny));

    // Build records
    var groups = raws.map(function (r) { return _buildGroupRecord(r, riskKey); });

    // Sort deterministically
    var pri = { P0: 0, P1: 1, P2: 2, P3: 3 };
    groups.sort(function (a, b) {
      var pa = pri[a.priority] != null ? pri[a.priority] : 9;
      var pb = pri[b.priority] != null ? pri[b.priority] : 9;
      if (pa !== pb) return pa - pb;
      if (b.linkage_strength !== a.linkage_strength) return b.linkage_strength - a.linkage_strength;
      return a.groupId < b.groupId ? -1 : 1;
    });

    // Portfolio risk
    var top = 0, sumTop3 = 0;
    var sorted = groups.slice().sort(function (a, b) { return b.linkage_strength - a.linkage_strength; });
    if (sorted.length) top = sorted[0].linkage_strength;
    for (var k = 0; k < Math.min(3, sorted.length); k++) sumTop3 += sorted[k].linkage_strength;
    var meanTop3 = sorted.length ? sumTop3 / Math.min(3, sorted.length) : 0;
    var portfolio = _clamp(Math.round((top * 0.6 + meanTop3 * 0.4) * risk.portfolio), 0, 100);

    // Grade
    var p0 = groups.filter(function (g) { return g.priority === "P0"; }).length;
    var p1 = groups.filter(function (g) { return g.priority === "P1"; }).length;
    var grade;
    if (p0 > 0 || portfolio >= 80) grade = "F";
    else if (p1 > 0 || portfolio >= 60) grade = "D";
    else if (portfolio >= 40) grade = "C";
    else if (portfolio >= 20) grade = "B";
    else grade = "A";

    // Isolated sessions
    var claimed = {};
    groups.forEach(function (g) { g.memberSessionIds.forEach(function (id) { claimed[id] = 1; }); });
    var isolated = 0;
    sessions.forEach(function (s) { if (!claimed[s.sessionId]) isolated++; });

    var summary = {
      totalSessions: sessions.length,
      totalGroups: groups.length,
      isolatedSessions: isolated,
      p0Groups: p0,
      p1Groups: p1,
      portfolio_risk_score: portfolio,
      grade: grade,
      riskAppetite: riskKey
    };

    var playbook = _buildPlaybook(groups, riskKey);
    var insights = _buildInsights(groups, sessions);

    return {
      generated_at: nowFn(),
      summary: summary,
      groups: groups,
      playbook: playbook,
      insights: insights
    };
  }

  function format(report, fmt) {
    if (!report || typeof report !== "object") return "";
    var f = String(fmt || "text").toLowerCase();
    if (f === "json") return _stableJson(report);
    if (f === "md" || f === "markdown") return _toMarkdown(report);
    return _toText(report);
  }

  return { analyze: analyze, format: format };
}

module.exports = {
  createCrossSessionLinkageAdvisor: createCrossSessionLinkageAdvisor,
  _internal: { _deriveCidr24: _deriveCidr24, _hash32: _hash32, _sortedDeep: _sortedDeep }
};
