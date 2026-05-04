/**
 * BotAdversarialPlaybookEngine — Autonomous red-team simulation engine.
 *
 * Generates synthetic attack scenarios, simulates them against current
 * defense configurations, identifies defense gaps/vulnerabilities, and
 * produces prioritized defensive playbooks with countermeasures.
 *
 * Key capabilities:
 *   - 10 attack scenario templates (credential stuffing, distributed solving,
 *     timing mimicry, CAPTCHA farm, browser automation, OCR attacks, session
 *     replay, token harvesting, rate-limit evasion, social engineering)
 *   - Defense configuration profiling (maps active defenses to coverage)
 *   - Attack simulation with success probability estimation
 *   - Gap analysis identifying undefended attack vectors
 *   - Prioritized playbook generation with effort/impact scoring
 *   - Defense evolution tracking over time
 *   - Composite resilience scoring 0-100
 *   - Autonomous insight generation
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/bot-adversarial-playbook
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _clamp = _shared._clamp;
var _posOpt = _shared._posOpt;
var _nnOpt = _shared._nnOpt;
var _linearRegression = _shared._linearRegression;
var LruTracker = _shared.LruTracker;

var _cryptoUtils = require("./crypto-utils");
var secureRandomHex = _cryptoUtils.secureRandomHex;

// ── Constants ───────────────────────────────────────────────────────

/** Attack sophistication tiers */
var SOPHISTICATION_TIERS = ["SCRIPT_KIDDIE", "AMATEUR", "PROFESSIONAL", "ADVANCED", "NATION_STATE"];

/** Resilience grades */
var RESILIENCE_GRADES = ["CRITICAL", "WEAK", "MODERATE", "STRONG", "FORTRESS"];

/** Attack scenario categories */
var ATTACK_CATEGORIES = [
  "credential_stuffing",
  "distributed_solving",
  "timing_mimicry",
  "captcha_farm",
  "browser_automation",
  "ocr_attack",
  "session_replay",
  "token_harvesting",
  "rate_limit_evasion",
  "social_engineering"
];

/** Built-in attack scenario templates */
var ATTACK_TEMPLATES = {
  credential_stuffing: {
    name: "Credential Stuffing Blitz",
    category: "credential_stuffing",
    sophistication: 2,
    description: "High-volume automated attempts using leaked credential lists with rotating proxies",
    tactics: ["proxy_rotation", "credential_list", "parallel_sessions", "fast_retry"],
    targetedDefenses: ["rate_limiter", "ip_reputation", "behavioral_biometrics", "fraud_ring_detector"],
    baseSuccessRate: 0.35,
    volumePerMinute: 500,
    costPerAttempt: 0.001
  },
  distributed_solving: {
    name: "Distributed Solver Network",
    category: "distributed_solving",
    sophistication: 3,
    description: "Coordinated botnet distributing CAPTCHA challenges across thousands of nodes",
    tactics: ["ip_diversity", "timing_randomization", "user_agent_rotation", "geographic_spread"],
    targetedDefenses: ["bot_collective_intel", "fingerprinting", "anomaly_detector", "trust_score"],
    baseSuccessRate: 0.55,
    volumePerMinute: 200,
    costPerAttempt: 0.01
  },
  timing_mimicry: {
    name: "Human Timing Mimicry",
    category: "timing_mimicry",
    sophistication: 4,
    description: "ML-trained bots that replicate precise human solving timing distributions",
    tactics: ["gaussian_timing", "fatigue_simulation", "mouse_jitter", "hesitation_patterns"],
    targetedDefenses: ["bot_mimicry_detector", "behavioral_biometrics", "micro_pattern_analysis", "cognitive_load"],
    baseSuccessRate: 0.65,
    volumePerMinute: 30,
    costPerAttempt: 0.05
  },
  captcha_farm: {
    name: "Human CAPTCHA Farm",
    category: "captcha_farm",
    sophistication: 3,
    description: "Real humans solving CAPTCHAs in sweatshop conditions, relayed via API",
    tactics: ["real_human_solving", "api_relay", "solve_caching", "batch_solving"],
    targetedDefenses: ["response_time_profiler", "session_continuity", "proof_of_work", "trust_network"],
    baseSuccessRate: 0.85,
    volumePerMinute: 50,
    costPerAttempt: 0.003
  },
  browser_automation: {
    name: "Headless Browser Army",
    category: "browser_automation",
    sophistication: 2,
    description: "Puppeteer/Playwright bots with anti-detection patches and stealth plugins",
    tactics: ["stealth_plugin", "canvas_spoofing", "webgl_fingerprint_randomization", "timezone_matching"],
    targetedDefenses: ["client_fingerprinter", "honeypot_injector", "proof_of_work", "behavioral_biometrics"],
    baseSuccessRate: 0.45,
    volumePerMinute: 100,
    costPerAttempt: 0.005
  },
  ocr_attack: {
    name: "GIF OCR Pipeline",
    category: "ocr_attack",
    sophistication: 3,
    description: "Custom vision model trained on GIF frames to extract answer text/patterns",
    tactics: ["frame_extraction", "ml_classification", "ensemble_models", "active_learning"],
    targetedDefenses: ["challenge_diversity", "adaptive_difficulty", "challenge_rotation", "visual_complexity"],
    baseSuccessRate: 0.40,
    volumePerMinute: 150,
    costPerAttempt: 0.008
  },
  session_replay: {
    name: "Session Replay Attack",
    category: "session_replay",
    sophistication: 2,
    description: "Capturing and replaying valid sessions with modified payloads",
    tactics: ["session_capture", "token_replay", "response_injection", "timing_adjustment"],
    targetedDefenses: ["replay_detector", "token_verifier", "session_binding", "nonce_validation"],
    baseSuccessRate: 0.25,
    volumePerMinute: 300,
    costPerAttempt: 0.0005
  },
  token_harvesting: {
    name: "Token Harvest & Reuse",
    category: "token_harvesting",
    sophistication: 3,
    description: "Solving CAPTCHAs once and stockpiling tokens for later bulk use",
    tactics: ["token_stockpiling", "delayed_use", "cross_session_reuse", "expiry_exploitation"],
    targetedDefenses: ["token_verifier", "expiry_enforcement", "single_use_tokens", "session_binding"],
    baseSuccessRate: 0.30,
    volumePerMinute: 400,
    costPerAttempt: 0.002
  },
  rate_limit_evasion: {
    name: "Rate Limit Evasion Suite",
    category: "rate_limit_evasion",
    sophistication: 2,
    description: "Systematic probing and evasion of rate limiting through IP rotation and timing",
    tactics: ["slow_and_low", "ip_rotation", "header_manipulation", "distributed_sourcing"],
    targetedDefenses: ["rate_limiter", "traffic_analyzer", "anomaly_detector", "geo_risk_scorer"],
    baseSuccessRate: 0.50,
    volumePerMinute: 80,
    costPerAttempt: 0.003
  },
  social_engineering: {
    name: "Social Engineering Relay",
    category: "social_engineering",
    sophistication: 4,
    description: "Tricking legitimate users into solving CAPTCHAs for the attacker via phishing",
    tactics: ["phishing_page", "iframe_embedding", "reward_incentive", "urgent_pretext"],
    targetedDefenses: ["origin_validation", "referrer_checking", "visual_indicators", "user_education"],
    baseSuccessRate: 0.60,
    volumePerMinute: 20,
    costPerAttempt: 0.10
  }
};

/** Defense capability catalog */
var DEFENSE_CATALOG = {
  rate_limiter: { name: "Rate Limiter", category: "volume", effectiveness: 0.7 },
  ip_reputation: { name: "IP Reputation", category: "identity", effectiveness: 0.6 },
  behavioral_biometrics: { name: "Behavioral Biometrics", category: "behavior", effectiveness: 0.8 },
  fraud_ring_detector: { name: "Fraud Ring Detector", category: "coordination", effectiveness: 0.75 },
  bot_collective_intel: { name: "Bot Collective Intelligence", category: "coordination", effectiveness: 0.7 },
  fingerprinting: { name: "Client Fingerprinting", category: "identity", effectiveness: 0.65 },
  anomaly_detector: { name: "Anomaly Detector", category: "behavior", effectiveness: 0.7 },
  trust_score: { name: "Trust Score Engine", category: "reputation", effectiveness: 0.75 },
  bot_mimicry_detector: { name: "Bot Mimicry Detector", category: "behavior", effectiveness: 0.85 },
  micro_pattern_analysis: { name: "Micro-Pattern Analysis", category: "behavior", effectiveness: 0.8 },
  cognitive_load: { name: "Cognitive Load Analysis", category: "behavior", effectiveness: 0.6 },
  response_time_profiler: { name: "Response Time Profiler", category: "timing", effectiveness: 0.65 },
  session_continuity: { name: "Session Continuity Check", category: "session", effectiveness: 0.7 },
  proof_of_work: { name: "Proof of Work", category: "cost", effectiveness: 0.8 },
  trust_network: { name: "Trust Network", category: "reputation", effectiveness: 0.7 },
  client_fingerprinter: { name: "Client Fingerprinter", category: "identity", effectiveness: 0.7 },
  honeypot_injector: { name: "Honeypot Injector", category: "deception", effectiveness: 0.6 },
  challenge_diversity: { name: "Challenge Diversity", category: "challenge", effectiveness: 0.7 },
  adaptive_difficulty: { name: "Adaptive Difficulty", category: "challenge", effectiveness: 0.75 },
  challenge_rotation: { name: "Challenge Rotation", category: "challenge", effectiveness: 0.65 },
  visual_complexity: { name: "Visual Complexity", category: "challenge", effectiveness: 0.6 },
  replay_detector: { name: "Replay Detector", category: "session", effectiveness: 0.85 },
  token_verifier: { name: "Token Verifier", category: "session", effectiveness: 0.8 },
  session_binding: { name: "Session Binding", category: "session", effectiveness: 0.75 },
  nonce_validation: { name: "Nonce Validation", category: "session", effectiveness: 0.7 },
  expiry_enforcement: { name: "Expiry Enforcement", category: "session", effectiveness: 0.7 },
  single_use_tokens: { name: "Single-Use Tokens", category: "session", effectiveness: 0.8 },
  traffic_analyzer: { name: "Traffic Analyzer", category: "volume", effectiveness: 0.65 },
  geo_risk_scorer: { name: "Geo Risk Scorer", category: "identity", effectiveness: 0.6 },
  origin_validation: { name: "Origin Validation", category: "session", effectiveness: 0.7 },
  referrer_checking: { name: "Referrer Checking", category: "session", effectiveness: 0.5 },
  visual_indicators: { name: "Visual Indicators", category: "ux", effectiveness: 0.4 },
  user_education: { name: "User Education", category: "ux", effectiveness: 0.3 }
};

var DEFAULT_OPTIONS = {
  maxSimulations: 5000,
  maxPlaybooks: 200,
  maxInsights: 200,
  maxSnapshots: 100,
  simulationRounds: 1000,
  weights: {
    gapCoverage: 0.30,
    simulationSurvival: 0.30,
    defenseDepth: 0.20,
    adaptability: 0.20
  }
};

// ── Helpers ─────────────────────────────────────────────────────────

function _uid() {
  return "ap_" + Date.now().toString(36) + "_" + secureRandomHex(8);
}

function _sophisticationTier(level) {
  var idx = _clamp(Math.round(level), 0, SOPHISTICATION_TIERS.length - 1);
  return SOPHISTICATION_TIERS[idx];
}

function _resilienceGrade(score) {
  if (score < 20) return RESILIENCE_GRADES[0];
  if (score < 40) return RESILIENCE_GRADES[1];
  if (score < 60) return RESILIENCE_GRADES[2];
  if (score < 80) return RESILIENCE_GRADES[3];
  return RESILIENCE_GRADES[4];
}

function _objKeys(o) {
  if (!o) return [];
  return Object.keys(o);
}

function _arrUnique(arr) {
  var seen = {};
  var result = [];
  for (var i = 0; i < arr.length; i++) {
    if (!seen[arr[i]]) {
      seen[arr[i]] = true;
      result.push(arr[i]);
    }
  }
  return result;
}

// ── Engine 1: Attack Scenario Generator ─────────────────────────────

function _generateScenarios(opts) {
  var scenarios = [];
  var categories = ATTACK_CATEGORIES;
  for (var i = 0; i < categories.length; i++) {
    var template = ATTACK_TEMPLATES[categories[i]];
    if (!template) continue;
    scenarios.push({
      id: _uid(),
      category: template.category,
      name: template.name,
      description: template.description,
      sophistication: template.sophistication,
      sophisticationTier: _sophisticationTier(template.sophistication),
      tactics: template.tactics.slice(),
      targetedDefenses: template.targetedDefenses.slice(),
      baseSuccessRate: template.baseSuccessRate,
      volumePerMinute: template.volumePerMinute,
      costPerAttempt: template.costPerAttempt,
      monthlyAttackCost: template.costPerAttempt * template.volumePerMinute * 60 * 24 * 30,
      timestamp: _now()
    });
  }
  return scenarios;
}

// ── Engine 2: Defense Profiler ──────────────────────────────────────

function _profileDefenses(activeDefenses) {
  var profile = {
    active: [],
    coverage: {},
    categoryStrength: {},
    totalDefenses: 0,
    maxPossibleDefenses: _objKeys(DEFENSE_CATALOG).length
  };

  var catScores = {};
  var catCounts = {};

  for (var i = 0; i < activeDefenses.length; i++) {
    var defId = activeDefenses[i];
    var def = DEFENSE_CATALOG[defId];
    if (!def) continue;

    profile.active.push({
      id: defId,
      name: def.name,
      category: def.category,
      effectiveness: def.effectiveness
    });
    profile.coverage[defId] = def.effectiveness;
    profile.totalDefenses++;

    if (!catScores[def.category]) {
      catScores[def.category] = 0;
      catCounts[def.category] = 0;
    }
    catScores[def.category] += def.effectiveness;
    catCounts[def.category]++;
  }

  var cats = _objKeys(catScores);
  for (var c = 0; c < cats.length; c++) {
    var cat = cats[c];
    profile.categoryStrength[cat] = {
      totalEffectiveness: catScores[cat],
      count: catCounts[cat],
      averageEffectiveness: catScores[cat] / catCounts[cat]
    };
  }

  return profile;
}

// ── Engine 3: Attack Simulator ──────────────────────────────────────

function _simulateAttack(scenario, defenseProfile, rounds) {
  var effectiveDefenseScore = 0;
  var matchedDefenses = [];
  var unmatchedDefenses = [];

  for (var i = 0; i < scenario.targetedDefenses.length; i++) {
    var defId = scenario.targetedDefenses[i];
    if (defenseProfile.coverage[defId] != null) {
      effectiveDefenseScore += defenseProfile.coverage[defId];
      matchedDefenses.push(defId);
    } else {
      unmatchedDefenses.push(defId);
    }
  }

  var maxDefenseScore = scenario.targetedDefenses.length;
  var coverageRatio = maxDefenseScore > 0 ? effectiveDefenseScore / maxDefenseScore : 0;

  // Sophistication modifier: higher sophistication reduces defense effectiveness
  var sophMod = 1 - (scenario.sophistication * 0.08);
  var adjustedCoverage = coverageRatio * _clamp(sophMod, 0.4, 1);

  // Simulate rounds
  var attackSuccesses = 0;
  var defenseBlocks = 0;
  var rng = scenario.baseSuccessRate;

  for (var r = 0; r < rounds; r++) {
    // Pseudo-random simulation using deterministic-ish approach
    var attackRoll = (Math.sin(r * 12.9898 + scenario.baseSuccessRate * 78.233) * 43758.5453) % 1;
    if (attackRoll < 0) attackRoll = -attackRoll;

    var defenseRoll = adjustedCoverage;
    // Add some variance
    var variance = (Math.sin(r * 43.2319 + defenseRoll * 29.193) * 21879.3277) % 1;
    if (variance < 0) variance = -variance;
    defenseRoll = defenseRoll * (0.7 + variance * 0.6);

    if (attackRoll < rng && defenseRoll < 0.5) {
      attackSuccesses++;
    } else {
      defenseBlocks++;
    }
  }

  var attackSuccessRate = attackSuccesses / rounds;
  var defenseBlockRate = defenseBlocks / rounds;

  return {
    scenarioId: scenario.id,
    scenarioName: scenario.name,
    category: scenario.category,
    sophistication: scenario.sophistication,
    rounds: rounds,
    attackSuccesses: attackSuccesses,
    defenseBlocks: defenseBlocks,
    attackSuccessRate: Math.round(attackSuccessRate * 1000) / 1000,
    defenseBlockRate: Math.round(defenseBlockRate * 1000) / 1000,
    coverageRatio: Math.round(coverageRatio * 1000) / 1000,
    matchedDefenses: matchedDefenses,
    unmatchedDefenses: unmatchedDefenses,
    gapCount: unmatchedDefenses.length,
    estimatedDamagePerMonth: Math.round(attackSuccessRate * scenario.volumePerMinute * 60 * 24 * 30),
    verdict: attackSuccessRate > 0.6 ? "VULNERABLE" :
             attackSuccessRate > 0.4 ? "AT_RISK" :
             attackSuccessRate > 0.2 ? "DEFENDED" : "FORTIFIED",
    timestamp: _now()
  };
}

// ── Engine 4: Gap Analyzer ──────────────────────────────────────────

function _analyzeGaps(simulations, defenseProfile) {
  var gaps = [];
  var defenseHits = {};
  var categoryGaps = {};

  for (var i = 0; i < simulations.length; i++) {
    var sim = simulations[i];
    for (var j = 0; j < sim.unmatchedDefenses.length; j++) {
      var defId = sim.unmatchedDefenses[j];
      if (!defenseHits[defId]) {
        defenseHits[defId] = { count: 0, scenarios: [], totalSuccessRate: 0 };
      }
      defenseHits[defId].count++;
      defenseHits[defId].scenarios.push(sim.category);
      defenseHits[defId].totalSuccessRate += sim.attackSuccessRate;

      var def = DEFENSE_CATALOG[defId];
      if (def) {
        var cat = def.category;
        if (!categoryGaps[cat]) categoryGaps[cat] = 0;
        categoryGaps[cat]++;
      }
    }
  }

  var gapIds = _objKeys(defenseHits);
  for (var g = 0; g < gapIds.length; g++) {
    var gid = gapIds[g];
    var info = defenseHits[gid];
    var catalogEntry = DEFENSE_CATALOG[gid];
    gaps.push({
      defenseId: gid,
      defenseName: catalogEntry ? catalogEntry.name : gid,
      category: catalogEntry ? catalogEntry.category : "unknown",
      effectiveness: catalogEntry ? catalogEntry.effectiveness : 0,
      exposedScenarios: info.count,
      affectedCategories: _arrUnique(info.scenarios),
      averageExposure: Math.round((info.totalSuccessRate / info.count) * 1000) / 1000,
      severity: info.count >= 3 ? "CRITICAL" :
                info.count >= 2 ? "HIGH" :
                "MEDIUM"
    });
  }

  // Sort by severity then exposure
  gaps.sort(function(a, b) {
    var sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
    var sa = sevOrder[a.severity] != null ? sevOrder[a.severity] : 3;
    var sb = sevOrder[b.severity] != null ? sevOrder[b.severity] : 3;
    if (sa !== sb) return sa - sb;
    return b.averageExposure - a.averageExposure;
  });

  return {
    gaps: gaps,
    totalGaps: gaps.length,
    categoryGaps: categoryGaps,
    criticalGaps: gaps.filter(function(g) { return g.severity === "CRITICAL"; }).length,
    highGaps: gaps.filter(function(g) { return g.severity === "HIGH"; }).length,
    mediumGaps: gaps.filter(function(g) { return g.severity === "MEDIUM"; }).length
  };
}

// ── Engine 5: Playbook Generator ────────────────────────────────────

var EFFORT_LEVELS = { low: 1, medium: 2, high: 3 };

function _generatePlaybook(gapAnalysis, simulations) {
  var actions = [];
  var gaps = gapAnalysis.gaps;

  for (var i = 0; i < gaps.length; i++) {
    var gap = gaps[i];
    var effort = gap.effectiveness > 0.75 ? "high" :
                 gap.effectiveness > 0.5 ? "medium" : "low";
    var impact = Math.round(gap.averageExposure * gap.effectiveness * 100);

    actions.push({
      priority: i + 1,
      action: "Deploy " + gap.defenseName,
      defenseId: gap.defenseId,
      category: gap.category,
      effort: effort,
      effortScore: EFFORT_LEVELS[effort],
      impactScore: _clamp(impact, 1, 100),
      roi: Math.round(impact / EFFORT_LEVELS[effort]),
      mitigates: gap.affectedCategories,
      severity: gap.severity,
      rationale: "Closes " + gap.exposedScenarios + " attack vector(s) with " +
                 Math.round(gap.averageExposure * 100) + "% average exposure"
    });
  }

  // Sort by ROI descending for optimal prioritization
  actions.sort(function(a, b) { return b.roi - a.roi; });

  // Re-assign priorities after ROI sort
  for (var p = 0; p < actions.length; p++) {
    actions[p].priority = p + 1;
  }

  // Quick-win identification
  var quickWins = actions.filter(function(a) { return a.effort === "low" && a.impactScore >= 30; });
  var strategicMoves = actions.filter(function(a) { return a.effort === "high" && a.impactScore >= 60; });

  // Vulnerability summary
  var vulnCount = 0;
  var riskCount = 0;
  var defendedCount = 0;
  for (var s = 0; s < simulations.length; s++) {
    if (simulations[s].verdict === "VULNERABLE") vulnCount++;
    else if (simulations[s].verdict === "AT_RISK") riskCount++;
    else defendedCount++;
  }

  return {
    actions: actions,
    totalActions: actions.length,
    quickWins: quickWins,
    strategicMoves: strategicMoves,
    summary: {
      vulnerableScenarios: vulnCount,
      atRiskScenarios: riskCount,
      defendedScenarios: defendedCount,
      totalScenarios: simulations.length
    },
    timestamp: _now()
  };
}

// ── Engine 6: Resilience Scorer ─────────────────────────────────────

function _scoreResilience(simulations, gapAnalysis, defenseProfile, weights) {
  // Gap coverage: how many defenses are active vs needed
  var allNeeded = {};
  for (var i = 0; i < simulations.length; i++) {
    var sim = simulations[i];
    for (var j = 0; j < sim.matchedDefenses.length; j++) {
      allNeeded[sim.matchedDefenses[j]] = true;
    }
    for (var k = 0; k < sim.unmatchedDefenses.length; k++) {
      allNeeded[sim.unmatchedDefenses[k]] = true;
    }
  }
  var neededCount = _objKeys(allNeeded).length;
  var coveredCount = 0;
  var neededKeys = _objKeys(allNeeded);
  for (var n = 0; n < neededKeys.length; n++) {
    if (defenseProfile.coverage[neededKeys[n]] != null) coveredCount++;
  }
  var gapCoverageScore = neededCount > 0 ? (coveredCount / neededCount) * 100 : 50;

  // Simulation survival: inverse of average attack success rate
  var successRates = [];
  for (var s = 0; s < simulations.length; s++) {
    successRates.push(simulations[s].attackSuccessRate);
  }
  var avgSuccess = successRates.length > 0 ? _mean(successRates) : 0.5;
  var survivalScore = (1 - avgSuccess) * 100;

  // Defense depth: variety of defense categories
  var activeCats = _objKeys(defenseProfile.categoryStrength);
  var allCats = ["volume", "identity", "behavior", "coordination", "reputation", "timing",
                 "session", "cost", "deception", "challenge", "ux"];
  var depthScore = allCats.length > 0 ? (activeCats.length / allCats.length) * 100 : 0;

  // Adaptability: inverse of critical gap ratio
  var criticalRatio = gapAnalysis.totalGaps > 0 ?
    gapAnalysis.criticalGaps / gapAnalysis.totalGaps : 0;
  var adaptScore = (1 - criticalRatio) * 100;

  var w = weights;
  var composite = _clamp(Math.round(
    gapCoverageScore * w.gapCoverage +
    survivalScore * w.simulationSurvival +
    depthScore * w.defenseDepth +
    adaptScore * w.adaptability
  ), 0, 100);

  return {
    composite: composite,
    grade: _resilienceGrade(composite),
    dimensions: {
      gapCoverage: Math.round(gapCoverageScore),
      simulationSurvival: Math.round(survivalScore),
      defenseDepth: Math.round(depthScore),
      adaptability: Math.round(adaptScore)
    },
    weights: {
      gapCoverage: w.gapCoverage,
      simulationSurvival: w.simulationSurvival,
      defenseDepth: w.defenseDepth,
      adaptability: w.adaptability
    }
  };
}

// ── Engine 7: Insight Generator ─────────────────────────────────────

function _generateInsights(simulations, gapAnalysis, playbook, resilience, defenseProfile) {
  var insights = [];
  var ts = _now();

  // Most dangerous attack
  var worstSim = null;
  for (var i = 0; i < simulations.length; i++) {
    if (!worstSim || simulations[i].attackSuccessRate > worstSim.attackSuccessRate) {
      worstSim = simulations[i];
    }
  }
  if (worstSim) {
    insights.push({
      type: "threat_alert",
      severity: worstSim.attackSuccessRate > 0.6 ? "CRITICAL" : "HIGH",
      message: "Most dangerous attack: \"" + worstSim.scenarioName + "\" with " +
               Math.round(worstSim.attackSuccessRate * 100) + "% success rate" +
               (worstSim.gapCount > 0 ? " (" + worstSim.gapCount + " defense gaps)" : ""),
      timestamp: ts
    });
  }

  // Quick wins available
  if (playbook.quickWins.length > 0) {
    insights.push({
      type: "opportunity",
      severity: "INFO",
      message: playbook.quickWins.length + " quick-win defense(s) available with low effort and high impact. " +
               "Top: " + playbook.quickWins[0].action + " (ROI: " + playbook.quickWins[0].roi + ")",
      timestamp: ts
    });
  }

  // Critical gaps warning
  if (gapAnalysis.criticalGaps > 0) {
    insights.push({
      type: "vulnerability",
      severity: "CRITICAL",
      message: gapAnalysis.criticalGaps + " critical defense gap(s) detected — " +
               "these defenses are needed against 3+ attack scenarios",
      timestamp: ts
    });
  }

  // Defense depth assessment
  var activeCats = _objKeys(defenseProfile.categoryStrength).length;
  if (activeCats < 4) {
    insights.push({
      type: "depth_warning",
      severity: "HIGH",
      message: "Defense depth is shallow: only " + activeCats + " category(s) covered. " +
               "Diversify across behavior, identity, session, and challenge categories",
      timestamp: ts
    });
  }

  // Resilience trend
  if (resilience.composite < 40) {
    insights.push({
      type: "resilience_alert",
      severity: "CRITICAL",
      message: "Overall resilience score is " + resilience.composite + "/100 (" + resilience.grade + "). " +
               "Immediate defensive improvements required",
      timestamp: ts
    });
  } else if (resilience.composite >= 80) {
    insights.push({
      type: "resilience_positive",
      severity: "INFO",
      message: "Strong resilience posture at " + resilience.composite + "/100 (" + resilience.grade + "). " +
               "Continue monitoring for emerging threats",
      timestamp: ts
    });
  }

  // High-sophistication threat readiness
  var advancedThreats = simulations.filter(function(s) { return s.sophistication >= 4; });
  var advancedVuln = advancedThreats.filter(function(s) { return s.verdict === "VULNERABLE"; });
  if (advancedVuln.length > 0) {
    insights.push({
      type: "advanced_threat",
      severity: "HIGH",
      message: "Vulnerable to " + advancedVuln.length + " advanced/nation-state attack(s). " +
               "Consider deploying specialized behavioral analysis",
      timestamp: ts
    });
  }

  // Cost analysis
  var totalMonthlyDamage = 0;
  for (var d = 0; d < simulations.length; d++) {
    totalMonthlyDamage += simulations[d].estimatedDamagePerMonth;
  }
  if (totalMonthlyDamage > 100000) {
    insights.push({
      type: "cost_alert",
      severity: "HIGH",
      message: "Estimated " + totalMonthlyDamage.toLocaleString() + " successful attacks/month across all vectors. " +
               "Prioritize defense investment",
      timestamp: ts
    });
  }

  return insights;
}

// ── Main Constructor ────────────────────────────────────────────────

/**
 * Create a new BotAdversarialPlaybookEngine instance.
 *
 * @param {Object} [options]
 * @param {number} [options.maxSimulations=5000]
 * @param {number} [options.maxPlaybooks=200]
 * @param {number} [options.maxInsights=200]
 * @param {number} [options.maxSnapshots=100]
 * @param {number} [options.simulationRounds=1000]
 * @param {Object} [options.weights]
 * @returns {Object} Engine instance
 */
function createBotAdversarialPlaybookEngine(options) {
  var opts = options || {};
  var maxSimulations = _posOpt(opts.maxSimulations, DEFAULT_OPTIONS.maxSimulations);
  var maxPlaybooks = _posOpt(opts.maxPlaybooks, DEFAULT_OPTIONS.maxPlaybooks);
  var maxInsights = _posOpt(opts.maxInsights, DEFAULT_OPTIONS.maxInsights);
  var maxSnapshots = _posOpt(opts.maxSnapshots, DEFAULT_OPTIONS.maxSnapshots);
  var simulationRounds = _posOpt(opts.simulationRounds, DEFAULT_OPTIONS.simulationRounds);

  var weights = {};
  var wIn = opts.weights || {};
  weights.gapCoverage = _nnOpt(wIn.gapCoverage, DEFAULT_OPTIONS.weights.gapCoverage);
  weights.simulationSurvival = _nnOpt(wIn.simulationSurvival, DEFAULT_OPTIONS.weights.simulationSurvival);
  weights.defenseDepth = _nnOpt(wIn.defenseDepth, DEFAULT_OPTIONS.weights.defenseDepth);
  weights.adaptability = _nnOpt(wIn.adaptability, DEFAULT_OPTIONS.weights.adaptability);

  // State
  var _simulations = [];
  var _simulationLru = new LruTracker();
  var _playbooks = [];
  var _playbookLru = new LruTracker();
  var _insights = [];
  var _snapshots = [];
  var _snapshotLru = new LruTracker();

  /**
   * Run a full adversarial assessment against specified active defenses.
   *
   * @param {string[]} activeDefenses - Array of defense IDs currently deployed
   * @returns {Object} Full assessment with scenarios, simulations, gaps, playbook, resilience, insights
   */
  function runAssessment(activeDefenses) {
    if (!Array.isArray(activeDefenses)) {
      throw new Error("activeDefenses must be an array of defense IDs");
    }

    // Generate attack scenarios
    var scenarios = _generateScenarios(opts);

    // Profile active defenses
    var defenseProfile = _profileDefenses(activeDefenses);

    // Simulate each attack
    var simResults = [];
    for (var i = 0; i < scenarios.length; i++) {
      var sim = _simulateAttack(scenarios[i], defenseProfile, simulationRounds);

      // Store simulation
      while (_simulationLru.length >= maxSimulations) {
        var old = _simulationLru.evictOldest();
        for (var x = 0; x < _simulations.length; x++) {
          if (_simulations[x].scenarioId === old) {
            _simulations.splice(x, 1);
            break;
          }
        }
      }
      _simulations.push(sim);
      _simulationLru.push(sim.scenarioId);
      simResults.push(sim);
    }

    // Gap analysis
    var gapAnalysis = _analyzeGaps(simResults, defenseProfile);

    // Generate playbook
    var playbook = _generatePlaybook(gapAnalysis, simResults);

    // Store playbook
    while (_playbookLru.length >= maxPlaybooks) {
      var oldPb = _playbookLru.evictOldest();
      for (var pb = 0; pb < _playbooks.length; pb++) {
        if (_playbooks[pb].id === oldPb) {
          _playbooks.splice(pb, 1);
          break;
        }
      }
    }
    var pbId = _uid();
    playbook.id = pbId;
    _playbooks.push(playbook);
    _playbookLru.push(pbId);

    // Resilience score
    var resilience = _scoreResilience(simResults, gapAnalysis, defenseProfile, weights);

    // Insights
    var newInsights = _generateInsights(simResults, gapAnalysis, playbook, resilience, defenseProfile);
    for (var ins = 0; ins < newInsights.length; ins++) {
      _insights.push(newInsights[ins]);
      while (_insights.length > maxInsights) _insights.shift();
    }

    // Snapshot for evolution tracking
    var snapshot = {
      id: _uid(),
      timestamp: _now(),
      activeDefenses: activeDefenses.slice(),
      defenseCount: defenseProfile.totalDefenses,
      resilience: resilience,
      vulnerableCount: playbook.summary.vulnerableScenarios,
      atRiskCount: playbook.summary.atRiskScenarios,
      defendedCount: playbook.summary.defendedScenarios,
      totalGaps: gapAnalysis.totalGaps,
      criticalGaps: gapAnalysis.criticalGaps
    };
    while (_snapshotLru.length >= maxSnapshots) {
      var oldSnap = _snapshotLru.evictOldest();
      for (var sn = 0; sn < _snapshots.length; sn++) {
        if (_snapshots[sn].id === oldSnap) {
          _snapshots.splice(sn, 1);
          break;
        }
      }
    }
    _snapshots.push(snapshot);
    _snapshotLru.push(snapshot.id);

    return {
      scenarios: scenarios,
      defenseProfile: defenseProfile,
      simulations: simResults,
      gapAnalysis: gapAnalysis,
      playbook: playbook,
      resilience: resilience,
      insights: newInsights,
      snapshot: snapshot
    };
  }

  /**
   * Simulate a single attack scenario against specified defenses.
   *
   * @param {string} category - Attack category from ATTACK_CATEGORIES
   * @param {string[]} activeDefenses - Active defense IDs
   * @returns {Object} Simulation result
   */
  function simulateScenario(category, activeDefenses) {
    if (!ATTACK_TEMPLATES[category]) {
      throw new Error("Unknown attack category: " + category);
    }
    if (!Array.isArray(activeDefenses)) {
      throw new Error("activeDefenses must be an array");
    }

    var template = ATTACK_TEMPLATES[category];
    var scenario = {
      id: _uid(),
      category: template.category,
      name: template.name,
      description: template.description,
      sophistication: template.sophistication,
      tactics: template.tactics.slice(),
      targetedDefenses: template.targetedDefenses.slice(),
      baseSuccessRate: template.baseSuccessRate,
      volumePerMinute: template.volumePerMinute,
      costPerAttempt: template.costPerAttempt
    };

    var defenseProfile = _profileDefenses(activeDefenses);
    return _simulateAttack(scenario, defenseProfile, simulationRounds);
  }

  /**
   * Get the defense evolution timeline.
   *
   * @returns {Object[]} Array of snapshots showing resilience evolution
   */
  function getEvolution() {
    return _snapshots.slice();
  }

  /**
   * Get all insights generated so far.
   *
   * @returns {Object[]} Array of insight objects
   */
  function getInsights() {
    return _insights.slice();
  }

  /**
   * Get available attack categories.
   *
   * @returns {string[]} Attack category names
   */
  function getAttackCategories() {
    return ATTACK_CATEGORIES.slice();
  }

  /**
   * Get the defense catalog.
   *
   * @returns {Object} Defense capability catalog
   */
  function getDefenseCatalog() {
    var result = {};
    var keys = _objKeys(DEFENSE_CATALOG);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      result[k] = {
        name: DEFENSE_CATALOG[k].name,
        category: DEFENSE_CATALOG[k].category,
        effectiveness: DEFENSE_CATALOG[k].effectiveness
      };
    }
    return result;
  }

  /**
   * Get fleet health summary across all tracked assessments.
   *
   * @returns {Object} Fleet summary
   */
  function getFleetHealth() {
    if (_snapshots.length === 0) {
      return {
        assessments: 0,
        latestResilience: null,
        trend: "UNKNOWN",
        message: "No assessments recorded yet"
      };
    }

    var latest = _snapshots[_snapshots.length - 1];
    var trend = "STABLE";

    if (_snapshots.length >= 2) {
      var prev = _snapshots[_snapshots.length - 2];
      var delta = latest.resilience.composite - prev.resilience.composite;
      if (delta > 5) trend = "IMPROVING";
      else if (delta < -5) trend = "DEGRADING";
    }

    // Compute average resilience across snapshots
    var scores = [];
    for (var i = 0; i < _snapshots.length; i++) {
      scores.push(_snapshots[i].resilience.composite);
    }

    return {
      assessments: _snapshots.length,
      latestResilience: latest.resilience,
      averageResilience: Math.round(_mean(scores)),
      trend: trend,
      latestGaps: latest.totalGaps,
      latestCriticalGaps: latest.criticalGaps
    };
  }

  /**
   * Export full engine state for persistence.
   *
   * @returns {Object} Serializable state object
   */
  function exportState() {
    return {
      simulations: _simulations.slice(),
      playbooks: _playbooks.slice(),
      insights: _insights.slice(),
      snapshots: _snapshots.slice(),
      simulationOrder: _simulationLru.toArray(),
      playbookOrder: _playbookLru.toArray(),
      snapshotOrder: _snapshotLru.toArray()
    };
  }

  /**
   * Import previously exported state.
   *
   * @param {Object} state - State from exportState()
   */
  function importState(state) {
    if (!state || typeof state !== "object") {
      throw new Error("state must be an object");
    }

    _simulations = Array.isArray(state.simulations) ? state.simulations.slice() : [];
    _playbooks = Array.isArray(state.playbooks) ? state.playbooks.slice() : [];
    _insights = Array.isArray(state.insights) ? state.insights.slice() : [];
    _snapshots = Array.isArray(state.snapshots) ? state.snapshots.slice() : [];

    _simulationLru = new LruTracker();
    _playbookLru = new LruTracker();
    _snapshotLru = new LruTracker();

    if (Array.isArray(state.simulationOrder)) {
      for (var i = 0; i < state.simulationOrder.length; i++) {
        _simulationLru.push(state.simulationOrder[i]);
      }
    }
    if (Array.isArray(state.playbookOrder)) {
      for (var j = 0; j < state.playbookOrder.length; j++) {
        _playbookLru.push(state.playbookOrder[j]);
      }
    }
    if (Array.isArray(state.snapshotOrder)) {
      for (var k = 0; k < state.snapshotOrder.length; k++) {
        _snapshotLru.push(state.snapshotOrder[k]);
      }
    }
  }

  return {
    runAssessment: runAssessment,
    simulateScenario: simulateScenario,
    getEvolution: getEvolution,
    getInsights: getInsights,
    getAttackCategories: getAttackCategories,
    getDefenseCatalog: getDefenseCatalog,
    getFleetHealth: getFleetHealth,
    exportState: exportState,
    importState: importState
  };
}

// ── Exports ─────────────────────────────────────────────────────────

module.exports = {
  createBotAdversarialPlaybookEngine: createBotAdversarialPlaybookEngine,
  ATTACK_CATEGORIES: ATTACK_CATEGORIES,
  ATTACK_TEMPLATES: ATTACK_TEMPLATES,
  DEFENSE_CATALOG: DEFENSE_CATALOG,
  SOPHISTICATION_TIERS: SOPHISTICATION_TIERS,
  RESILIENCE_GRADES: RESILIENCE_GRADES
};
