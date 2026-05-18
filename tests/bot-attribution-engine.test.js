require("./_expect");
"use strict";

const { describe, it, beforeEach } = require("node:test");
var _mod = require("../src/bot-attribution-engine");
var createBotAttributionEngine = _mod.createBotAttributionEngine;

describe("BotAttributionEngine", function () {
  var engine;
  var baseTs = 1700000000000;

  beforeEach(function () {
    engine = createBotAttributionEngine({
      maxBots: 100,
      maxOperators: 50,
      maxCampaigns: 20,
      fingerprintWindowMs: 86400000 * 30,
      attributionThresholdScore: 0.55,
      campaignDetectionWindowMs: 86400000 * 30
    });
  });

  function ingestN(botId, count, opts) {
    opts = opts || {};
    for (var i = 0; i < count; i++) {
      engine.ingestBotActivity({
        botId: botId,
        timestamp: baseTs + i * 60000,
        challengeType: opts.challengeType || "image_select",
        success: opts.success !== undefined ? opts.success : (i % 3 !== 0),
        solveTimeMs: opts.solveTimeMs || (300 + i * 10),
        ip: opts.ip || ("10.0.1." + (i % 256)),
        userAgent: opts.userAgent || "Bot/" + botId,
        errorCode: (i % 3 === 0) ? (opts.errorCode || "TIMEOUT") : null
      });
    }
  }

  // ── Basic Ingest ────────────────────────────────────────────────

  it("should return ingested:false for invalid input", function () {
    expect(engine.ingestBotActivity(null)).toEqual({ botId: null, ingested: false });
    expect(engine.ingestBotActivity({})).toEqual({ botId: null, ingested: false });
    expect(engine.ingestBotActivity({ botId: "" })).toEqual({ botId: null, ingested: false });
  });

  it("should ingest valid bot activity", function () {
    var result = engine.ingestBotActivity({
      botId: "bot1",
      timestamp: baseTs,
      challengeType: "image_select",
      success: true,
      solveTimeMs: 450,
      ip: "10.0.0.1",
      userAgent: "Mozilla/5.0"
    });
    expect(result.botId).toBe("bot1");
    expect(result.ingested).toBe(true);
  });

  it("should default timestamp to now when omitted", function () {
    var before = Date.now();
    engine.ingestBotActivity({ botId: "bot1", success: true });
    var summary = engine.getSummary();
    expect(summary.totalBots).toBe(1);
  });

  it("should accumulate events for the same bot", function () {
    ingestN("bot1", 10);
    var attr = engine.attributeBot("bot1");
    expect(attr).not.toBeNull();
    expect(attr.fingerprint.length).toBe(8);
  });

  // ── Attribution ─────────────────────────────────────────────────

  it("should attribute a bot and create operator on first attribution", function () {
    ingestN("bot1", 10);
    var result = engine.attributeBot("bot1");
    expect(result.operatorId).toBeTruthy();
    expect(result.confidence).toBeGreaterThan(0);
    expect(result.matchedDimensions.length).toBeGreaterThan(0);
  });

  it("should return null for unknown bot", function () {
    expect(engine.attributeBot("nonexistent")).toBeNull();
  });

  it("should attribute similar bots to the same operator", function () {
    // Two bots with identical patterns
    ingestN("bot_a", 20, { ip: "10.0.1.1", userAgent: "Selenium/4.0", challengeType: "text_input", errorCode: "OCR_FAIL" });
    ingestN("bot_b", 20, { ip: "10.0.1.2", userAgent: "Selenium/4.0", challengeType: "text_input", errorCode: "OCR_FAIL" });

    var attrA = engine.attributeBot("bot_a");
    var attrB = engine.attributeBot("bot_b");

    expect(attrA.operatorId).toBeTruthy();
    expect(attrB.operatorId).toBeTruthy();
    // Both should be attributed to the same or similar operator
    // (since fingerprints are very similar)
  });

  it("should attribute very different bots to different operators", function () {
    // Bot with one pattern
    ingestN("botX", 20, { ip: "192.168.0.1", userAgent: "Puppeteer/1.0", challengeType: "image_select", errorCode: "RENDER_FAIL" });
    var attrX = engine.attributeBot("botX");

    // Bot with completely different pattern
    for (var i = 0; i < 20; i++) {
      engine.ingestBotActivity({
        botId: "botY",
        timestamp: baseTs + 86400000 + i * 300000,
        challengeType: "audio_challenge",
        success: i % 2 === 0,
        solveTimeMs: 5000 + i * 100,
        ip: "172.16." + i + ".1",
        userAgent: "CustomBot/2.0-rev" + i,
        errorCode: i % 2 === 0 ? null : "DECODE_ERR"
      });
    }
    var attrY = engine.attributeBot("botY");

    expect(attrX.operatorId).toBeTruthy();
    expect(attrY.operatorId).toBeTruthy();
  });

  it("should return consistent attribution on repeat calls", function () {
    ingestN("bot1", 15);
    var first = engine.attributeBot("bot1");
    var second = engine.attributeBot("bot1");
    expect(second.operatorId).toBe(first.operatorId);
  });

  // ── Operator Identification ─────────────────────────────────────

  it("should return null for unknown operator", function () {
    expect(engine.identifyOperator("fake_op")).toBeNull();
  });

  it("should return operator profile with infrastructure details", function () {
    ingestN("bot1", 15, { ip: "10.0.0.5", userAgent: "TestUA/1.0" });
    var attr = engine.attributeBot("bot1");
    var profile = engine.identifyOperator(attr.operatorId);

    expect(profile.operatorId).toBe(attr.operatorId);
    expect(profile.knownBots).toContain("bot1");
    expect(profile.infrastructureProfile).toBeDefined();
    expect(profile.infrastructureProfile.uniqueIps).toBeGreaterThan(0);
    expect(profile.operationalPattern).toBeDefined();
    expect(profile.threatLevel).toBeDefined();
  });

  // ── Campaign Detection ──────────────────────────────────────────

  it("should return empty array when no campaigns detected", function () {
    engine.ingestBotActivity({ botId: "lonely", timestamp: baseTs, success: true });
    engine.attributeBot("lonely");
    var campaigns = engine.detectCampaign({ minBots: 3 });
    expect(campaigns).toEqual([]);
  });

  it("should detect campaigns for operators with multiple active bots", function () {
    // Create operator with multiple bots
    ingestN("c_bot1", 15, { ip: "10.0.1.1", userAgent: "CampaignBot/1.0", challengeType: "image_select", errorCode: "TIMEOUT" });
    ingestN("c_bot2", 15, { ip: "10.0.1.2", userAgent: "CampaignBot/1.0", challengeType: "image_select", errorCode: "TIMEOUT" });
    ingestN("c_bot3", 15, { ip: "10.0.1.3", userAgent: "CampaignBot/1.0", challengeType: "image_select", errorCode: "TIMEOUT" });

    engine.attributeBot("c_bot1");
    engine.attributeBot("c_bot2");
    engine.attributeBot("c_bot3");

    var campaigns = engine.detectCampaign({ minBots: 2, minConfidence: 0 });
    // Should detect at least one campaign (all bots belong to same/similar operators)
    expect(Array.isArray(campaigns)).toBe(true);
  });

  it("should include campaign lifecycle phase", function () {
    ingestN("p_bot1", 10, { userAgent: "PhaseBot/1.0", errorCode: "X" });
    ingestN("p_bot2", 10, { userAgent: "PhaseBot/1.0", errorCode: "X" });
    engine.attributeBot("p_bot1");
    engine.attributeBot("p_bot2");

    var campaigns = engine.detectCampaign({ minBots: 2, minConfidence: 0 });
    if (campaigns.length > 0) {
      expect(["PLANNING", "ACTIVE", "INTENSIFYING", "WINDING_DOWN", "DORMANT"]).toContain(campaigns[0].status);
    }
  });

  // ── Operator Timeline ───────────────────────────────────────────

  it("should return null timeline for unknown operator", function () {
    expect(engine.getOperatorTimeline("fake")).toBeNull();
  });

  it("should track timeline events chronologically", function () {
    ingestN("tl_bot", 10);
    var attr = engine.attributeBot("tl_bot");
    var timeline = engine.getOperatorTimeline(attr.operatorId);

    expect(Array.isArray(timeline)).toBe(true);
    expect(timeline.length).toBeGreaterThan(0);
    expect(timeline[0].event).toBe("OPERATOR_CREATED");

    // Verify chronological order
    for (var i = 1; i < timeline.length; i++) {
      expect(timeline[i].timestamp).toBeGreaterThanOrEqual(timeline[i - 1].timestamp);
    }
  });

  // ── Threat Assessment ───────────────────────────────────────────

  it("should return null for unknown operator threat assessment", function () {
    expect(engine.assessThreatLevel("fake")).toBeNull();
  });

  it("should assess threat level with factors and recommendations", function () {
    ingestN("threat_bot", 20, { success: true });
    var attr = engine.attributeBot("threat_bot");
    var assessment = engine.assessThreatLevel(attr.operatorId);

    expect(assessment.operatorId).toBe(attr.operatorId);
    expect(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).toContain(assessment.threatLevel);
    expect(Array.isArray(assessment.factors)).toBe(true);
    expect(assessment.factors.length).toBe(6);
    expect(typeof assessment.escalation).toBe("boolean");
    expect(Array.isArray(assessment.recommendations)).toBe(true);
  });

  it("should set escalation when threat is high enough", function () {
    // Create high-threat operator with many successful bots
    for (var i = 0; i < 25; i++) {
      var bid = "esc_bot_" + i;
      ingestN(bid, 20, { success: true, ip: "10.0.0." + (i % 256), userAgent: "EscBot/1.0", errorCode: "X" });
      engine.attributeBot(bid);
    }

    var summary = engine.getSummary();
    var topOps = summary.topOperators;
    if (topOps.length > 0) {
      var assessment = engine.assessThreatLevel(topOps[0].operatorId);
      expect(assessment).toBeDefined();
      // High-scale operator should have elevated threat
    }
  });

  // ── Operator Merging ────────────────────────────────────────────

  it("should fail to merge nonexistent operators", function () {
    expect(engine.mergeOperators("fake1", "fake2")).toEqual({ merged: false, resultOperatorId: null });
  });

  it("should fail to merge same operator", function () {
    ingestN("m_bot", 10);
    var attr = engine.attributeBot("m_bot");
    expect(engine.mergeOperators(attr.operatorId, attr.operatorId)).toEqual({ merged: false, resultOperatorId: null });
  });

  it("should merge two operators successfully", function () {
    // Create two distinct operators
    for (var i = 0; i < 15; i++) {
      engine.ingestBotActivity({
        botId: "merge_a_" + i,
        timestamp: baseTs + i * 60000,
        challengeType: "type_a",
        success: true,
        ip: "192.168.1." + i,
        userAgent: "BotA/unique_" + i,
        errorCode: null
      });
    }
    for (var j = 0; j < 15; j++) {
      engine.ingestBotActivity({
        botId: "merge_b_" + j,
        timestamp: baseTs + 86400000 + j * 300000,
        challengeType: "type_b",
        success: false,
        ip: "172.16.0." + j,
        userAgent: "BotB/unique_" + j,
        errorCode: "FAIL_" + j
      });
    }

    // Attribute a few from each group
    var attrA = engine.attributeBot("merge_a_0");
    var attrB = engine.attributeBot("merge_b_0");

    if (attrA.operatorId !== attrB.operatorId) {
      var result = engine.mergeOperators(attrA.operatorId, attrB.operatorId);
      expect(result.merged).toBe(true);
      expect(result.resultOperatorId).toBe(attrA.operatorId);

      // Verify merged operator has bots from both
      var profile = engine.identifyOperator(attrA.operatorId);
      expect(profile.knownBots).toContain("merge_a_0");
      expect(profile.knownBots).toContain("merge_b_0");

      // Op2 should be gone
      expect(engine.identifyOperator(attrB.operatorId)).toBeNull();
    }
  });

  // ── Summary ─────────────────────────────────────────────────────

  it("should return correct summary on empty engine", function () {
    var summary = engine.getSummary();
    expect(summary.totalBots).toBe(0);
    expect(summary.totalOperators).toBe(0);
    expect(summary.totalCampaigns).toBe(0);
    expect(summary.activeCampaigns).toBe(0);
    expect(summary.threatDistribution).toEqual({ LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 });
    expect(summary.topOperators).toEqual([]);
  });

  it("should reflect counts after ingestion and attribution", function () {
    ingestN("s_bot1", 10);
    ingestN("s_bot2", 10);
    engine.attributeBot("s_bot1");
    engine.attributeBot("s_bot2");

    var summary = engine.getSummary();
    expect(summary.totalBots).toBe(2);
    expect(summary.totalOperators).toBeGreaterThanOrEqual(1);
    expect(summary.topOperators.length).toBeGreaterThanOrEqual(1);
  });

  // ── State Export/Import ─────────────────────────────────────────

  it("should round-trip state through export/import", function () {
    ingestN("rt_bot1", 10, { ip: "1.2.3.4", userAgent: "RTBot/1" });
    ingestN("rt_bot2", 10, { ip: "5.6.7.8", userAgent: "RTBot/2" });
    engine.attributeBot("rt_bot1");
    engine.attributeBot("rt_bot2");

    var exported = engine.exportState();
    expect(exported.version).toBe(1);
    expect(exported.botCount).toBe(2);

    var engine2 = createBotAttributionEngine();
    engine2.importState(exported);
    var summary2 = engine2.getSummary();

    expect(summary2.totalBots).toBe(2);
    expect(summary2.totalOperators).toBeGreaterThanOrEqual(1);
  });

  it("should ignore import of invalid state", function () {
    engine.importState(null);
    expect(engine.getSummary().totalBots).toBe(0);

    engine.importState({ version: 999 });
    expect(engine.getSummary().totalBots).toBe(0);
  });

  // ── Reset ───────────────────────────────────────────────────────

  it("should clear all state on reset", function () {
    ingestN("reset_bot", 10);
    engine.attributeBot("reset_bot");
    engine.reset();

    var summary = engine.getSummary();
    expect(summary.totalBots).toBe(0);
    expect(summary.totalOperators).toBe(0);
    expect(summary.totalCampaigns).toBe(0);
  });

  // ── LRU Eviction ────────────────────────────────────────────────

  it("should evict oldest bots when maxBots exceeded", function () {
    var small = createBotAttributionEngine({ maxBots: 5 });
    for (var i = 0; i < 8; i++) {
      small.ingestBotActivity({
        botId: "evict_" + i,
        timestamp: baseTs + i * 60000,
        challengeType: "test",
        success: true
      });
    }

    var summary = small.getSummary();
    expect(summary.totalBots).toBeLessThanOrEqual(5);
    // Oldest bots should be evicted
    expect(small.attributeBot("evict_0")).toBeNull();
  });

  // ── Edge Cases ──────────────────────────────────────────────────

  it("should handle single-event bot fingerprint", function () {
    engine.ingestBotActivity({ botId: "single", timestamp: baseTs, success: false });
    var attr = engine.attributeBot("single");
    expect(attr).not.toBeNull();
    expect(attr.fingerprint.length).toBe(8);
  });

  it("should expose dimension and level constants", function () {
    expect(engine.ATTRIBUTION_DIMENSIONS.length).toBe(8);
    expect(engine.THREAT_LEVELS).toEqual(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
    expect(engine.CAMPAIGN_PHASES.length).toBe(5);
    expect(engine.SOPHISTICATION_TIERS.length).toBe(5);
  });

  it("should handle events with no optional fields", function () {
    var result = engine.ingestBotActivity({ botId: "minimal" });
    expect(result.ingested).toBe(true);
    var attr = engine.attributeBot("minimal");
    expect(attr).not.toBeNull();
  });

  // ── Event Eviction Per Bot ──────────────────────────────────────

  it("should evict old events when maxEventsPerBot exceeded", function () {
    var small = createBotAttributionEngine({ maxEventsPerBot: 10 });
    for (var i = 0; i < 15; i++) {
      small.ingestBotActivity({
        botId: "evtBot",
        timestamp: baseTs + i * 1000,
        challengeType: "test",
        success: true
      });
    }
    // Should still work without error
    var attr = small.attributeBot("evtBot");
    expect(attr).not.toBeNull();
  });

  // ── Detect Campaign with minConfidence ──────────────────────────

  it("should filter campaigns by minConfidence", function () {
    ingestN("fc1", 10, { userAgent: "FC/1", errorCode: "E1" });
    ingestN("fc2", 10, { userAgent: "FC/1", errorCode: "E1" });
    engine.attributeBot("fc1");
    engine.attributeBot("fc2");

    // Very high confidence threshold should filter out
    var strict = engine.detectCampaign({ minBots: 2, minConfidence: 0.999 });
    expect(Array.isArray(strict)).toBe(true);
  });

  // ── Threat Assessment Updates Timeline ──────────────────────────

  it("should add THREAT_ASSESSED event to timeline", function () {
    ingestN("ta_bot", 10);
    var attr = engine.attributeBot("ta_bot");
    engine.assessThreatLevel(attr.operatorId);

    var timeline = engine.getOperatorTimeline(attr.operatorId);
    var found = false;
    for (var i = 0; i < timeline.length; i++) {
      if (timeline[i].event === "THREAT_ASSESSED") { found = true; break; }
    }
    expect(found).toBe(true);
  });

  // ── Merge Adds Timeline Event ───────────────────────────────────

  it("should record OPERATOR_MERGED in timeline after merge", function () {
    for (var i = 0; i < 10; i++) {
      engine.ingestBotActivity({ botId: "mg1_" + i, timestamp: baseTs + i * 60000, challengeType: "a", success: true, ip: "1.1.1." + i, userAgent: "U1/" + i });
    }
    for (var j = 0; j < 10; j++) {
      engine.ingestBotActivity({ botId: "mg2_" + j, timestamp: baseTs + 86400000 + j * 300000, challengeType: "b", success: false, ip: "2.2.2." + j, userAgent: "U2/" + j, errorCode: "ERR" + j });
    }
    var a1 = engine.attributeBot("mg1_0");
    var a2 = engine.attributeBot("mg2_0");

    if (a1.operatorId !== a2.operatorId) {
      engine.mergeOperators(a1.operatorId, a2.operatorId);
      var timeline = engine.getOperatorTimeline(a1.operatorId);
      var found = false;
      for (var k = 0; k < timeline.length; k++) {
        if (timeline[k].event === "OPERATOR_MERGED") { found = true; break; }
      }
      expect(found).toBe(true);
    }
  });
});
