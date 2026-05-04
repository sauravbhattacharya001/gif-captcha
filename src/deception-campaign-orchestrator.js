/**
 * DeceptionCampaignOrchestrator — Autonomous multi-phase deception campaigns
 * to detect, profile, and fingerprint sophisticated bots.
 *
 * Designs and executes coordinated trap sequences that exploit bot behavioral
 * weaknesses: predictability, lack of genuine curiosity, timing uniformity,
 * and inability to exhibit authentic frustration or satisfaction.
 *
 * Key capabilities:
 *   - 7 deception tactic types (honeypot, delay trap, impossible challenge,
 *     curiosity bait, frustration test, consistency probe, social proof trap)
 *   - Multi-phase campaign design with configurable phase ordering
 *   - Autonomous suspect profiling from campaign observations
 *   - Bot confidence scoring with evidence chain per suspect
 *   - Campaign effectiveness tracking and self-improvement
 *   - Adaptive difficulty — campaigns get harder as bots adapt
 *   - Full state export/import for persistence
 *
 * No external dependencies — pure ES5 JavaScript.
 *
 * @module gif-captcha/deception-campaign-orchestrator
 */

"use strict";

var _shared = require("./shared-utils");
var _now = _shared._now;
var _mean = _shared._mean;
var _stddev = _shared._stddev;
var _clamp = _shared._clamp;
var _posOpt = _shared._posOpt;
var _nnOpt = _shared._nnOpt;

var _crypto = require("./crypto-utils");
var secureRandomHex = _crypto.secureRandomHex;

// ── Constants ───────────────────────────────────────────────────────

var TACTIC_TYPES = [
  "HONEYPOT",           // invisible or hidden-field traps
  "DELAY_TRAP",         // measure reaction to artificial delays
  "IMPOSSIBLE_CHALLENGE", // unsolvable captchas that humans skip/complain about
  "CURIOSITY_BAIT",     // optional elements humans explore, bots ignore
  "FRUSTRATION_TEST",   // repeated challenges that humans show frustration patterns
  "CONSISTENCY_PROBE",  // same challenge twice to check behavioral consistency
  "SOCIAL_PROOF_TRAP"   // fake social cues (e.g. "98% got this right") to detect scripted responses
];

var CAMPAIGN_PHASES = ["RECON", "ENGAGE", "PROFILE", "CONFIRM", "VERDICT"];

var SUSPECT_VERDICTS = ["HUMAN", "LIKELY_HUMAN", "UNCERTAIN", "LIKELY_BOT", "BOT"];

var MAX_CAMPAIGNS = 500;
var MAX_SUSPECTS = 2000;
var MAX_OBSERVATIONS = 100; // per suspect
var MAX_COMPLETED_CAMPAIGNS = 200;

// ── Tactic Templates ────────────────────────────────────────────────

var TACTIC_TEMPLATES = {
  HONEYPOT: {
    description: "Deploy invisible interaction traps",
    botSignal: "interacted with hidden element",
    humanSignal: "ignored hidden element",
    weight: 0.9
  },
  DELAY_TRAP: {
    description: "Insert artificial delays and measure reaction patterns",
    botSignal: "uniform wait time across delays",
    humanSignal: "variable reaction to delays (frustration, exploration)",
    weight: 0.7
  },
  IMPOSSIBLE_CHALLENGE: {
    description: "Present unsolvable challenges to observe response",
    botSignal: "attempted solution with confidence",
    humanSignal: "hesitation, skip, or complaint behavior",
    weight: 0.85
  },
  CURIOSITY_BAIT: {
    description: "Offer optional exploration paths",
    botSignal: "ignored all optional elements",
    humanSignal: "explored at least some optional content",
    weight: 0.6
  },
  FRUSTRATION_TEST: {
    description: "Repeat challenges to measure frustration curve",
    botSignal: "flat emotional response curve",
    humanSignal: "escalating frustration indicators",
    weight: 0.75
  },
  CONSISTENCY_PROBE: {
    description: "Re-present identical challenges at different times",
    botSignal: "identical response timing and content",
    humanSignal: "natural variation in responses",
    weight: 0.8
  },
  SOCIAL_PROOF_TRAP: {
    description: "Display fake social signals to detect scripted behavior",
    botSignal: "response unaffected by social cues",
    humanSignal: "response influenced by perceived peer behavior",
    weight: 0.5
  }
};

// ── DeceptionCampaignOrchestrator ───────────────────────────────────

/**
 * Create a new DeceptionCampaignOrchestrator instance.
 *
 * @param {Object} [options]
 * @param {number} [options.maxCampaigns=500]         Max active campaigns
 * @param {number} [options.maxSuspects=2000]          Max tracked suspects
 * @param {number} [options.maxObservations=100]       Max observations per suspect
 * @param {number} [options.botThreshold=0.7]          Bot confidence threshold for verdict
 * @param {number} [options.humanThreshold=0.3]        Human confidence threshold for verdict
 * @param {number} [options.adaptiveRate=0.05]         Learning rate for tactic effectiveness
 * @param {number} [options.decayHalfLifeMs=86400000]  Signal decay half-life (default 24h)
 */
function DeceptionCampaignOrchestrator(options) {
  var opts = options || {};
  this._maxCampaigns = _posOpt(opts.maxCampaigns, MAX_CAMPAIGNS);
  this._maxSuspects = _posOpt(opts.maxSuspects, MAX_SUSPECTS);
  this._maxObservations = _posOpt(opts.maxObservations, MAX_OBSERVATIONS);
  this._botThreshold = opts.botThreshold != null ? opts.botThreshold : 0.7;
  this._humanThreshold = opts.humanThreshold != null ? opts.humanThreshold : 0.3;
  this._adaptiveRate = opts.adaptiveRate != null ? opts.adaptiveRate : 0.05;
  this._decayHalfLifeMs = _posOpt(opts.decayHalfLifeMs, 86400000);

  // Active campaigns: id → campaign object
  this._campaigns = Object.create(null);
  this._campaignCount = 0;
  // Insertion-order queue for O(1) oldest-campaign eviction (replaces O(n) scan)
  this._campaignInsertionOrder = [];

  // Completed campaigns (ring buffer for analysis)
  this._completed = [];

  // Suspect profiles: sessionId → profile
  this._suspects = Object.create(null);
  this._suspectCount = 0;
  // Insertion-order queue for O(1) oldest-suspect eviction (replaces O(n) scan)
  this._suspectInsertionOrder = [];

  // Tactic effectiveness scores (learned over time)
  this._tacticEffectiveness = {};
  for (var i = 0; i < TACTIC_TYPES.length; i++) {
    this._tacticEffectiveness[TACTIC_TYPES[i]] = {
      deployments: 0,
      correctDetections: 0,
      falsePositives: 0,
      falseNegatives: 0,
      effectiveness: 0.5 // starts neutral
    };
  }

  // Global stats
  this._stats = {
    totalCampaignsCreated: 0,
    totalCampaignsCompleted: 0,
    totalObservations: 0,
    totalBotsDetected: 0,
    totalHumansCleared: 0,
    totalFalsePositives: 0
  };
}

// ── Campaign Design ─────────────────────────────────────────────────

/**
 * Design a new deception campaign targeting a session.
 *
 * @param {string} sessionId    - Target session identifier
 * @param {Object} [options]
 * @param {string[]} [options.tactics]  - Specific tactics to use (default: auto-select)
 * @param {number}   [options.phases]   - Number of phases (1-5, default: 3)
 * @param {string}   [options.strategy] - "aggressive" | "subtle" | "adaptive" (default: "adaptive")
 * @returns {Object} Campaign descriptor
 */
DeceptionCampaignOrchestrator.prototype.designCampaign = function (sessionId, options) {
  if (!sessionId || typeof sessionId !== "string") {
    throw new Error("sessionId is required");
  }

  if (this._campaignCount >= this._maxCampaigns) {
    this._evictOldestCampaign();
  }

  var opts = options || {};
  var numPhases = _clamp(opts.phases || 3, 1, 5);
  var strategy = opts.strategy || "adaptive";
  var tactics = opts.tactics || this._selectTactics(strategy, numPhases);

  var campaignId = "camp_" + secureRandomHex(12);
  var now = _now();

  // Build phase plan
  var phases = [];
  var phaseNames = CAMPAIGN_PHASES.slice(0, numPhases);
  for (var i = 0; i < phaseNames.length; i++) {
    var phaseTactics = this._assignTacticsToPhase(phaseNames[i], tactics, i, numPhases);
    phases.push({
      name: phaseNames[i],
      tactics: phaseTactics,
      status: i === 0 ? "ACTIVE" : "PENDING",
      startedAt: i === 0 ? now : null,
      completedAt: null,
      observations: []
    });
  }

  var campaign = {
    id: campaignId,
    sessionId: sessionId,
    strategy: strategy,
    phases: phases,
    currentPhase: 0,
    status: "ACTIVE",
    createdAt: now,
    updatedAt: now,
    completedAt: null,
    verdict: null
  };

  this._campaigns[campaignId] = campaign;
  this._campaignInsertionOrder.push(campaignId);
  this._campaignCount++;
  this._stats.totalCampaignsCreated++;

  // Ensure suspect profile exists
  this._ensureSuspect(sessionId);

  return {
    campaignId: campaignId,
    sessionId: sessionId,
    strategy: strategy,
    phases: phases.map(function (p) {
      return { name: p.name, tactics: p.tactics.map(function (t) { return t.type; }), status: p.status };
    }),
    status: "ACTIVE"
  };
};

/**
 * Auto-select tactics based on strategy and phase count.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._selectTactics = function (strategy, numPhases) {
  var selected = [];
  var pool = TACTIC_TYPES.slice();

  if (strategy === "aggressive") {
    // Use high-weight tactics first
    pool.sort(function (a, b) {
      return TACTIC_TEMPLATES[b].weight - TACTIC_TEMPLATES[a].weight;
    });
    selected = pool.slice(0, Math.min(numPhases + 2, pool.length));
  } else if (strategy === "subtle") {
    // Use low-weight, hard-to-detect tactics
    pool.sort(function (a, b) {
      return TACTIC_TEMPLATES[a].weight - TACTIC_TEMPLATES[b].weight;
    });
    selected = pool.slice(0, Math.min(numPhases + 1, pool.length));
  } else {
    // Adaptive: pick based on learned effectiveness
    var self = this;
    pool.sort(function (a, b) {
      return self._tacticEffectiveness[b].effectiveness - self._tacticEffectiveness[a].effectiveness;
    });
    selected = pool.slice(0, Math.min(numPhases + 2, pool.length));
  }

  return selected;
};

/**
 * Assign tactics to a specific phase.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._assignTacticsToPhase = function (phaseName, tactics, phaseIndex, totalPhases) {
  var assigned = [];
  var startIdx, endIdx;

  if (totalPhases === 1) {
    // Single phase gets all tactics
    for (var i = 0; i < tactics.length; i++) {
      assigned.push(this._createTacticInstance(tactics[i]));
    }
  } else {
    // Distribute tactics across phases
    var perPhase = Math.ceil(tactics.length / totalPhases);
    startIdx = phaseIndex * perPhase;
    endIdx = Math.min(startIdx + perPhase, tactics.length);
    // Always include at least one tactic per phase
    if (startIdx >= tactics.length) {
      startIdx = tactics.length - 1;
      endIdx = tactics.length;
    }
    for (var j = startIdx; j < endIdx; j++) {
      assigned.push(this._createTacticInstance(tactics[j]));
    }
  }

  return assigned;
};

/**
 * Create a tactic instance with deployment metadata.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._createTacticInstance = function (tacticType) {
  var template = TACTIC_TEMPLATES[tacticType];
  return {
    type: tacticType,
    description: template.description,
    weight: template.weight,
    deployed: false,
    deployedAt: null,
    triggered: false,
    triggeredAt: null,
    result: null
  };
};

// ── Observation Recording ───────────────────────────────────────────

/**
 * Record an observation from a deception tactic.
 *
 * @param {string} campaignId   - Campaign identifier
 * @param {string} tacticType   - Which tactic produced the observation
 * @param {Object} observation  - Observation data
 * @param {string} observation.behavior   - What the subject did
 * @param {number} observation.responseTimeMs - Response latency
 * @param {boolean} [observation.interactedWithTrap] - Did they interact with the trap?
 * @param {number} [observation.consistencyScore]    - How consistent with prior behavior (0-1)
 * @param {Object} [observation.metadata]  - Additional context
 * @returns {Object} Updated campaign status
 */
DeceptionCampaignOrchestrator.prototype.recordObservation = function (campaignId, tacticType, observation) {
  var campaign = this._campaigns[campaignId];
  if (!campaign) {
    throw new Error("Campaign not found: " + campaignId);
  }
  if (campaign.status !== "ACTIVE") {
    throw new Error("Campaign is not active: " + campaign.status);
  }
  if (TACTIC_TYPES.indexOf(tacticType) === -1) {
    throw new Error("Unknown tactic type: " + tacticType);
  }
  if (!observation || typeof observation !== "object") {
    throw new Error("observation must be an object");
  }

  var now = _now();
  var phase = campaign.phases[campaign.currentPhase];

  // Find tactic in current phase
  var tactic = null;
  for (var i = 0; i < phase.tactics.length; i++) {
    if (phase.tactics[i].type === tacticType) {
      tactic = phase.tactics[i];
      break;
    }
  }

  // Build observation record
  var record = {
    tacticType: tacticType,
    timestamp: now,
    behavior: observation.behavior || "unknown",
    responseTimeMs: _nnOpt(observation.responseTimeMs, 0),
    interactedWithTrap: !!observation.interactedWithTrap,
    consistencyScore: observation.consistencyScore != null ? _clamp(observation.consistencyScore, 0, 1) : null,
    metadata: observation.metadata || {}
  };

  // Score this observation for bot likelihood
  record.botSignalStrength = this._scoreBotSignal(tacticType, record);

  phase.observations.push(record);
  this._stats.totalObservations++;
  campaign.updatedAt = now;

  if (tactic) {
    tactic.triggered = true;
    tactic.triggeredAt = now;
    tactic.result = record.botSignalStrength > 0.5 ? "BOT_SIGNAL" : "HUMAN_SIGNAL";
  }

  // Update suspect profile
  this._updateSuspectProfile(campaign.sessionId, record);

  // Check if phase is complete (all tactics triggered or enough observations)
  var allTriggered = true;
  for (var j = 0; j < phase.tactics.length; j++) {
    if (!phase.tactics[j].triggered) { allTriggered = false; break; }
  }

  if (allTriggered) {
    return this._advancePhase(campaignId);
  }

  return {
    campaignId: campaignId,
    phase: phase.name,
    phaseProgress: phase.observations.length + "/" + phase.tactics.length,
    botSignalStrength: record.botSignalStrength,
    status: "ACTIVE"
  };
};

/**
 * Score how strongly an observation signals bot behavior.
 * @private
 * @returns {number} Bot signal strength 0-1
 */
DeceptionCampaignOrchestrator.prototype._scoreBotSignal = function (tacticType, record) {
  var score = 0;
  var template = TACTIC_TEMPLATES[tacticType];

  switch (tacticType) {
    case "HONEYPOT":
      // Bots interact with hidden elements; humans don't
      score = record.interactedWithTrap ? 0.95 : 0.05;
      break;

    case "DELAY_TRAP":
      // Bots have suspiciously uniform response times
      // Very fast (<100ms) or perfectly round numbers are suspicious
      if (record.responseTimeMs < 100) {
        score = 0.8;
      } else if (record.responseTimeMs % 1000 === 0) {
        score = 0.6;
      } else {
        score = 0.2;
      }
      break;

    case "IMPOSSIBLE_CHALLENGE":
      // Bots attempt to solve unsolvable challenges confidently
      if (record.behavior === "attempted_solution") {
        score = 0.85;
      } else if (record.behavior === "skipped" || record.behavior === "complained") {
        score = 0.1;
      } else {
        score = 0.4;
      }
      break;

    case "CURIOSITY_BAIT":
      // Humans explore; bots focus on the task
      if (record.interactedWithTrap) {
        score = 0.1; // explored = human signal
      } else {
        score = 0.6;
      }
      break;

    case "FRUSTRATION_TEST":
      // Flat response curve = bot
      if (record.consistencyScore != null) {
        // High consistency in frustration test = bot (no frustration escalation)
        score = record.consistencyScore * 0.8;
      } else {
        score = 0.4;
      }
      break;

    case "CONSISTENCY_PROBE":
      // Identical responses = bot
      if (record.consistencyScore != null) {
        // Perfect consistency (1.0) is suspicious
        score = record.consistencyScore > 0.95 ? 0.9 : record.consistencyScore * 0.6;
      } else {
        score = 0.4;
      }
      break;

    case "SOCIAL_PROOF_TRAP":
      // Bots aren't influenced by social cues
      if (record.interactedWithTrap) {
        score = 0.2; // influenced = human-like
      } else {
        score = 0.55;
      }
      break;

    default:
      score = 0.5;
  }

  // Apply tactic weight
  return _clamp(score * template.weight + (1 - template.weight) * 0.5, 0, 1);
};

// ── Phase Management ────────────────────────────────────────────────

/**
 * Advance a campaign to the next phase.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._advancePhase = function (campaignId) {
  var campaign = this._campaigns[campaignId];
  var now = _now();

  // Complete current phase
  campaign.phases[campaign.currentPhase].status = "COMPLETED";
  campaign.phases[campaign.currentPhase].completedAt = now;

  // Move to next phase
  campaign.currentPhase++;
  campaign.updatedAt = now;

  if (campaign.currentPhase >= campaign.phases.length) {
    // All phases complete — render verdict
    return this._completeCampaign(campaignId);
  }

  // Activate next phase
  campaign.phases[campaign.currentPhase].status = "ACTIVE";
  campaign.phases[campaign.currentPhase].startedAt = now;

  return {
    campaignId: campaignId,
    phase: campaign.phases[campaign.currentPhase].name,
    phaseProgress: "0/" + campaign.phases[campaign.currentPhase].tactics.length,
    status: "ACTIVE",
    message: "Advanced to phase: " + campaign.phases[campaign.currentPhase].name
  };
};

/**
 * Complete a campaign and render a verdict.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._completeCampaign = function (campaignId) {
  var campaign = this._campaigns[campaignId];
  var now = _now();

  campaign.status = "COMPLETED";
  campaign.completedAt = now;
  campaign.updatedAt = now;

  // Collect all observations across phases
  var allObs = [];
  for (var i = 0; i < campaign.phases.length; i++) {
    allObs = allObs.concat(campaign.phases[i].observations);
  }

  // Calculate aggregate bot confidence
  var signals = [];
  for (var j = 0; j < allObs.length; j++) {
    signals.push(allObs[j].botSignalStrength);
  }

  var botConfidence = signals.length > 0 ? _mean(signals) : 0.5;
  var signalVariance = signals.length > 1 ? _stddev(signals) : 0;

  // Render verdict
  var verdict;
  if (botConfidence >= this._botThreshold) {
    verdict = "BOT";
    this._stats.totalBotsDetected++;
  } else if (botConfidence >= (this._botThreshold + this._humanThreshold) / 2) {
    verdict = "LIKELY_BOT";
  } else if (botConfidence <= this._humanThreshold) {
    verdict = "HUMAN";
    this._stats.totalHumansCleared++;
  } else if (botConfidence <= (this._botThreshold + this._humanThreshold) / 2) {
    verdict = "LIKELY_HUMAN";
  } else {
    verdict = "UNCERTAIN";
  }

  campaign.verdict = {
    classification: verdict,
    botConfidence: Math.round(botConfidence * 1000) / 1000,
    signalVariance: Math.round(signalVariance * 1000) / 1000,
    observationCount: allObs.length,
    evidenceChain: this._buildEvidenceChain(allObs)
  };

  // Update suspect with campaign verdict
  var suspect = this._suspects[campaign.sessionId];
  if (suspect) {
    suspect.campaignVerdicts.push({
      campaignId: campaignId,
      verdict: verdict,
      botConfidence: botConfidence,
      timestamp: now
    });
    suspect.lastVerdict = verdict;
    suspect.lastVerdictAt = now;
    suspect.overallBotConfidence = this._computeOverallConfidence(suspect);
  }

  // Archive to completed
  this._completed.unshift({
    campaignId: campaignId,
    sessionId: campaign.sessionId,
    strategy: campaign.strategy,
    verdict: verdict,
    botConfidence: botConfidence,
    duration: now - campaign.createdAt,
    observationCount: allObs.length,
    completedAt: now
  });
  if (this._completed.length > MAX_COMPLETED_CAMPAIGNS) {
    this._completed.length = MAX_COMPLETED_CAMPAIGNS;
  }

  // Update tactic effectiveness from this campaign's results
  this._updateTacticEffectiveness(campaign, verdict);

  this._stats.totalCampaignsCompleted++;

  // Remove from active
  delete this._campaigns[campaignId];
  this._campaignCount--;

  return {
    campaignId: campaignId,
    status: "COMPLETED",
    verdict: campaign.verdict
  };
};

/**
 * Build an evidence chain from observations.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._buildEvidenceChain = function (observations) {
  var evidence = [];
  for (var i = 0; i < observations.length; i++) {
    var obs = observations[i];
    var template = TACTIC_TEMPLATES[obs.tacticType];
    evidence.push({
      tactic: obs.tacticType,
      signal: obs.botSignalStrength > 0.5 ? "BOT" : "HUMAN",
      strength: Math.round(obs.botSignalStrength * 100) / 100,
      detail: obs.botSignalStrength > 0.5 ? template.botSignal : template.humanSignal,
      timestamp: obs.timestamp
    });
  }
  // Sort by strength descending
  evidence.sort(function (a, b) { return b.strength - a.strength; });
  return evidence;
};

// ── Suspect Profiling ───────────────────────────────────────────────

/**
 * Ensure a suspect profile exists.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._ensureSuspect = function (sessionId) {
  if (this._suspects[sessionId]) return;

  if (this._suspectCount >= this._maxSuspects) {
    this._evictOldestSuspect();
  }

  this._suspects[sessionId] = {
    sessionId: sessionId,
    firstSeen: _now(),
    lastSeen: _now(),
    observations: [],
    campaignVerdicts: [],
    lastVerdict: null,
    lastVerdictAt: null,
    overallBotConfidence: 0.5,
    behavioralProfile: {
      avgResponseTimeMs: null,
      responseTimeVariance: null,
      trapInteractionRate: null,
      curiosityScore: null,
      frustrationCurve: null,
      consistencyPattern: null
    },
    // Incremental accumulators — O(1) profile updates instead of O(obs) rescan
    _accum: {
      rtSum: 0, rtSumSq: 0, rtCount: 0,
      trapInteractions: 0, trapCount: 0,
      consistencySum: 0, consistencyCount: 0
    }
  };
  this._suspectInsertionOrder.push(sessionId);
  this._suspectCount++;
};

/**
 * Update a suspect's behavioral profile from a new observation.
 *
 * Refactored: uses incremental accumulators (_accum) so each call is O(1)
 * instead of rescanning all observations (previously O(observations)).
 * When observations overflow the max buffer we subtract the evicted
 * observation's contribution from the accumulators to stay accurate.
 *
 * @private
 */
DeceptionCampaignOrchestrator.prototype._updateSuspectProfile = function (sessionId, record) {
  var suspect = this._suspects[sessionId];
  if (!suspect) return;

  suspect.lastSeen = record.timestamp;
  var acc = suspect._accum;

  // If buffer is full, subtract the evicted (oldest) observation's contribution
  if (suspect.observations.length >= this._maxObservations) {
    var evicted = suspect.observations.shift();
    if (evicted.responseTimeMs > 0) {
      acc.rtSum -= evicted.responseTimeMs;
      acc.rtSumSq -= evicted.responseTimeMs * evicted.responseTimeMs;
      acc.rtCount--;
    }
    if (evicted.tacticType === "HONEYPOT" || evicted.tacticType === "CURIOSITY_BAIT" || evicted.tacticType === "SOCIAL_PROOF_TRAP") {
      acc.trapCount--;
      if (evicted.interactedWithTrap) acc.trapInteractions--;
    }
    if (evicted.consistencyScore != null) {
      acc.consistencySum -= evicted.consistencyScore;
      acc.consistencyCount--;
    }
  }

  suspect.observations.push(record);

  // Add new observation's contribution
  if (record.responseTimeMs > 0) {
    acc.rtSum += record.responseTimeMs;
    acc.rtSumSq += record.responseTimeMs * record.responseTimeMs;
    acc.rtCount++;
  }
  if (record.tacticType === "HONEYPOT" || record.tacticType === "CURIOSITY_BAIT" || record.tacticType === "SOCIAL_PROOF_TRAP") {
    acc.trapCount++;
    if (record.interactedWithTrap) acc.trapInteractions++;
  }
  if (record.consistencyScore != null) {
    acc.consistencySum += record.consistencyScore;
    acc.consistencyCount++;
  }

  // Derive profile from accumulators — O(1)
  var profile = suspect.behavioralProfile;
  if (acc.rtCount > 0) {
    var mean = acc.rtSum / acc.rtCount;
    profile.avgResponseTimeMs = Math.round(mean);
    profile.responseTimeVariance = acc.rtCount > 1
      ? Math.round(Math.sqrt((acc.rtSumSq - acc.rtSum * acc.rtSum / acc.rtCount) / (acc.rtCount - 1)) * 100) / 100
      : 0;
  }
  if (acc.trapCount > 0) {
    profile.trapInteractionRate = Math.round((acc.trapInteractions / acc.trapCount) * 1000) / 1000;
  }
  if (acc.consistencyCount > 0) {
    profile.consistencyPattern = Math.round((acc.consistencySum / acc.consistencyCount) * 1000) / 1000;
  }
};

/**
 * Compute overall bot confidence for a suspect across campaigns.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._computeOverallConfidence = function (suspect) {
  if (suspect.campaignVerdicts.length === 0) return 0.5;

  var now = _now();
  var weightedSum = 0;
  var weightSum = 0;

  for (var i = 0; i < suspect.campaignVerdicts.length; i++) {
    var v = suspect.campaignVerdicts[i];
    var age = now - v.timestamp;
    var decay = Math.pow(0.5, age / this._decayHalfLifeMs);
    weightedSum += v.botConfidence * decay;
    weightSum += decay;
  }

  return weightSum > 0 ? _clamp(weightedSum / weightSum, 0, 1) : 0.5;
};

// ── Tactic Effectiveness Learning ───────────────────────────────────

/**
 * Update tactic effectiveness based on a completed campaign.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._updateTacticEffectiveness = function (campaign, verdict) {
  var isBot = verdict === "BOT" || verdict === "LIKELY_BOT";

  for (var i = 0; i < campaign.phases.length; i++) {
    var phase = campaign.phases[i];
    for (var j = 0; j < phase.tactics.length; j++) {
      var tactic = phase.tactics[j];
      if (!tactic.triggered) continue;

      var eff = this._tacticEffectiveness[tactic.type];
      eff.deployments++;

      var predictedBot = tactic.result === "BOT_SIGNAL";
      if (predictedBot && isBot) {
        eff.correctDetections++;
      } else if (predictedBot && !isBot) {
        eff.falsePositives++;
      } else if (!predictedBot && isBot) {
        eff.falseNegatives++;
      }

      // Update effectiveness with learning rate
      var total = eff.correctDetections + eff.falsePositives + eff.falseNegatives;
      if (total > 0) {
        var accuracy = eff.correctDetections / total;
        eff.effectiveness = eff.effectiveness * (1 - this._adaptiveRate) + accuracy * this._adaptiveRate;
      }
    }
  }
};

// ── Query API ───────────────────────────────────────────────────────

/**
 * Get the current status of a campaign.
 *
 * @param {string} campaignId
 * @returns {Object|null}
 */
DeceptionCampaignOrchestrator.prototype.getCampaignStatus = function (campaignId) {
  var campaign = this._campaigns[campaignId];
  if (!campaign) return null;

  var phase = campaign.phases[campaign.currentPhase];
  return {
    campaignId: campaignId,
    sessionId: campaign.sessionId,
    strategy: campaign.strategy,
    status: campaign.status,
    currentPhase: phase ? phase.name : null,
    phaseIndex: campaign.currentPhase,
    totalPhases: campaign.phases.length,
    totalObservations: this._countCampaignObs(campaign),
    createdAt: campaign.createdAt,
    updatedAt: campaign.updatedAt
  };
};

/**
 * Get a suspect's full profile.
 *
 * @param {string} sessionId
 * @returns {Object|null}
 */
DeceptionCampaignOrchestrator.prototype.getSuspectProfile = function (sessionId) {
  var suspect = this._suspects[sessionId];
  if (!suspect) return null;

  return {
    sessionId: suspect.sessionId,
    firstSeen: suspect.firstSeen,
    lastSeen: suspect.lastSeen,
    observationCount: suspect.observations.length,
    campaignCount: suspect.campaignVerdicts.length,
    lastVerdict: suspect.lastVerdict,
    overallBotConfidence: Math.round(this._computeOverallConfidence(suspect) * 1000) / 1000,
    behavioralProfile: JSON.parse(JSON.stringify(suspect.behavioralProfile))
  };
};

/**
 * Get learned tactic effectiveness rankings.
 *
 * @returns {Object[]} Tactics sorted by effectiveness
 */
DeceptionCampaignOrchestrator.prototype.getTacticRankings = function () {
  var rankings = [];
  for (var type in this._tacticEffectiveness) {
    if (!this._tacticEffectiveness.hasOwnProperty(type)) continue;
    var eff = this._tacticEffectiveness[type];
    rankings.push({
      tactic: type,
      effectiveness: Math.round(eff.effectiveness * 1000) / 1000,
      deployments: eff.deployments,
      correctDetections: eff.correctDetections,
      falsePositives: eff.falsePositives,
      falseNegatives: eff.falseNegatives
    });
  }
  rankings.sort(function (a, b) { return b.effectiveness - a.effectiveness; });
  return rankings;
};

/**
 * Get campaign history (completed campaigns).
 *
 * @param {number} [limit=20]
 * @returns {Object[]}
 */
DeceptionCampaignOrchestrator.prototype.getCampaignHistory = function (limit) {
  var n = _posOpt(limit, 20);
  return this._completed.slice(0, n);
};

/**
 * Get aggregate statistics.
 *
 * @returns {Object}
 */
DeceptionCampaignOrchestrator.prototype.getStats = function () {
  var stats = JSON.parse(JSON.stringify(this._stats));
  stats.activeCampaigns = this._campaignCount;
  stats.trackedSuspects = this._suspectCount;

  // Detection rates
  var total = stats.totalBotsDetected + stats.totalHumansCleared;
  stats.detectionRate = total > 0 ? Math.round((stats.totalBotsDetected / total) * 1000) / 1000 : 0;
  stats.falsePositiveRate = total > 0 ? Math.round((stats.totalFalsePositives / total) * 1000) / 1000 : 0;

  // Top tactic
  var rankings = this.getTacticRankings();
  stats.topTactic = rankings.length > 0 ? rankings[0].tactic : null;

  return stats;
};

/**
 * Report a false positive (session was actually human).
 *
 * @param {string} sessionId
 * @returns {boolean} Whether the suspect was found and corrected
 */
DeceptionCampaignOrchestrator.prototype.reportFalsePositive = function (sessionId) {
  var suspect = this._suspects[sessionId];
  if (!suspect) return false;

  this._stats.totalFalsePositives++;

  // Correct the suspect's profile
  suspect.lastVerdict = "HUMAN";
  suspect.lastVerdictAt = _now();

  // Recalibrate tactic effectiveness for related campaigns
  for (var i = 0; i < suspect.campaignVerdicts.length; i++) {
    var cv = suspect.campaignVerdicts[i];
    if (cv.verdict === "BOT" || cv.verdict === "LIKELY_BOT") {
      cv.verdict = "HUMAN";
      cv.botConfidence = 0.1;
    }
  }

  suspect.overallBotConfidence = this._computeOverallConfidence(suspect);
  return true;
};

// ── Eviction ────────────────────────────────────────────────────────

/**
 * Evict the oldest campaign using the insertion-order queue.
 * O(1) amortized — replaces O(n) full-scan of all campaigns.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._evictOldestCampaign = function () {
  while (this._campaignInsertionOrder.length > 0) {
    var candidateId = this._campaignInsertionOrder.shift();
    if (this._campaigns[candidateId]) {
      delete this._campaigns[candidateId];
      this._campaignCount--;
      return;
    }
    // Already removed (completed) — skip stale entry
  }
};

/**
 * Evict the oldest suspect using the insertion-order queue.
 * O(1) amortized — replaces O(n) full-scan of all suspects.
 * @private
 */
DeceptionCampaignOrchestrator.prototype._evictOldestSuspect = function () {
  while (this._suspectInsertionOrder.length > 0) {
    var candidateId = this._suspectInsertionOrder.shift();
    if (this._suspects[candidateId]) {
      delete this._suspects[candidateId];
      this._suspectCount--;
      return;
    }
    // Already removed — skip stale entry
  }
};

/** @private */
DeceptionCampaignOrchestrator.prototype._countCampaignObs = function (campaign) {
  var count = 0;
  for (var i = 0; i < campaign.phases.length; i++) {
    count += campaign.phases[i].observations.length;
  }
  return count;
};

// ── State Export / Import ───────────────────────────────────────────

/**
 * Export full state for persistence.
 * @returns {Object}
 */
DeceptionCampaignOrchestrator.prototype.exportState = function () {
  return {
    version: 1,
    campaigns: JSON.parse(JSON.stringify(this._campaigns)),
    campaignCount: this._campaignCount,
    suspects: JSON.parse(JSON.stringify(this._suspects)),
    suspectCount: this._suspectCount,
    completed: this._completed.slice(),
    tacticEffectiveness: JSON.parse(JSON.stringify(this._tacticEffectiveness)),
    stats: JSON.parse(JSON.stringify(this._stats))
  };
};

/**
 * Import previously exported state.
 * @param {Object} state
 */
var _isSafeKey = _shared._isSafeKey;
var _safeCloneDict = _shared._safeCloneDict;

/**
 * Deep-clone a value via JSON round-trip.  Returns the fallback when
 * the input is falsy.  Ensures that imported objects do not share
 * references with caller-controlled data (CWE-915) and that any
 * prototype-chain poisoning or getter/setter traps on the source
 * object are stripped (CWE-1321).
 * @param {*} val
 * @param {*} fallback
 * @returns {*}
 */
function _safeClone(val, fallback) {
  if (!val) return fallback;
  return JSON.parse(JSON.stringify(val));
}

DeceptionCampaignOrchestrator.prototype.importState = function (state) {
  if (!state || state.version !== 1) {
    throw new Error("Invalid state version");
  }

  // Deep-clone all imported structures to prevent:
  //  1. Prototype-chain poisoning (CWE-1321): imported {} inherits
  //     from Object.prototype — attacker-controlled properties on
  //     the prototype propagate into internal lookups.
  //  2. Object-reference leakage (CWE-915): caller retains a live
  //     reference to internal state, allowing post-import mutation.
  //  3. Getter/setter traps: crafted objects with accessor
  //     descriptors can execute arbitrary code when properties
  //     are read during campaign processing.
  this._campaigns = _safeCloneDict(state.campaigns);
  this._campaignCount = typeof state.campaignCount === "number" ? state.campaignCount : 0;
  this._suspects = _safeCloneDict(state.suspects);
  this._suspectCount = typeof state.suspectCount === "number" ? state.suspectCount : 0;
  this._completed = _safeClone(state.completed, []);
  // Rebuild insertion-order queues from imported keys
  this._campaignInsertionOrder = Object.keys(this._campaigns);
  this._suspectInsertionOrder = Object.keys(this._suspects);
  if (state.tacticEffectiveness) {
    this._tacticEffectiveness = _safeClone(state.tacticEffectiveness, this._tacticEffectiveness);
  }
  if (state.stats) {
    this._stats = _safeClone(state.stats, this._stats);
  }
};

// ── Autonomous Campaign Recommendations ─────────────────────────────

/**
 * Analyze a session's behavior and recommend whether to launch a deception campaign.
 *
 * @param {string} sessionId
 * @param {Object} sessionSignals  - Current session behavioral signals
 * @param {number} [sessionSignals.requestRate]       - Requests per minute
 * @param {number} [sessionSignals.avgResponseTimeMs] - Average response time
 * @param {boolean} [sessionSignals.hasMouseMovement] - Mouse movement detected
 * @param {boolean} [sessionSignals.hasKeystrokes]    - Keystroke patterns detected
 * @param {number} [sessionSignals.failedAttempts]    - Failed CAPTCHA attempts
 * @returns {Object} Recommendation with suspicion score and suggested strategy
 */
DeceptionCampaignOrchestrator.prototype.recommendCampaign = function (sessionId, sessionSignals) {
  var signals = sessionSignals || {};
  var suspicionScore = 0;
  var reasons = [];

  // High request rate
  if (signals.requestRate != null && signals.requestRate > 10) {
    suspicionScore += 0.3;
    reasons.push("High request rate: " + signals.requestRate + "/min");
  }

  // Very fast or very uniform response times
  if (signals.avgResponseTimeMs != null && signals.avgResponseTimeMs < 200) {
    suspicionScore += 0.25;
    reasons.push("Suspiciously fast responses: " + signals.avgResponseTimeMs + "ms avg");
  }

  // No mouse movement
  if (signals.hasMouseMovement === false) {
    suspicionScore += 0.2;
    reasons.push("No mouse movement detected");
  }

  // No keystroke patterns
  if (signals.hasKeystrokes === false) {
    suspicionScore += 0.15;
    reasons.push("No keystroke patterns detected");
  }

  // Multiple failed attempts
  if (signals.failedAttempts != null && signals.failedAttempts > 3) {
    suspicionScore += 0.1;
    reasons.push("Multiple failed attempts: " + signals.failedAttempts);
  }

  suspicionScore = _clamp(suspicionScore, 0, 1);

  // Check existing suspect data
  var existingSuspect = this._suspects[sessionId];
  if (existingSuspect && existingSuspect.overallBotConfidence > 0.5) {
    suspicionScore = _clamp(suspicionScore + 0.2, 0, 1);
    reasons.push("Prior suspicious activity (confidence: " + Math.round(existingSuspect.overallBotConfidence * 100) + "%)");
  }

  // Recommend strategy based on suspicion level
  var recommendation;
  if (suspicionScore >= 0.7) {
    recommendation = { launch: true, strategy: "aggressive", phases: 4 };
  } else if (suspicionScore >= 0.4) {
    recommendation = { launch: true, strategy: "adaptive", phases: 3 };
  } else if (suspicionScore >= 0.2) {
    recommendation = { launch: true, strategy: "subtle", phases: 2 };
  } else {
    recommendation = { launch: false, strategy: null, phases: 0 };
  }

  return {
    sessionId: sessionId,
    suspicionScore: Math.round(suspicionScore * 1000) / 1000,
    reasons: reasons,
    recommendation: recommendation,
    existingSuspect: !!existingSuspect
  };
};

// ── Module Exports ──────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    DeceptionCampaignOrchestrator: DeceptionCampaignOrchestrator,
    TACTIC_TYPES: TACTIC_TYPES,
    CAMPAIGN_PHASES: CAMPAIGN_PHASES,
    SUSPECT_VERDICTS: SUSPECT_VERDICTS,
    TACTIC_TEMPLATES: TACTIC_TEMPLATES
  };
}
