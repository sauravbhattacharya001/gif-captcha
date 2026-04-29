"use strict";

var assert = require("assert");
var DCO = require("../src/deception-campaign-orchestrator");
var DeceptionCampaignOrchestrator = DCO.DeceptionCampaignOrchestrator;
var TACTIC_TYPES = DCO.TACTIC_TYPES;
var CAMPAIGN_PHASES = DCO.CAMPAIGN_PHASES;

describe("DeceptionCampaignOrchestrator", function () {

  var orch;
  beforeEach(function () {
    orch = new DeceptionCampaignOrchestrator();
  });

  // ── Construction ──────────────────────────────────────────────────

  describe("constructor", function () {
    it("creates with default options", function () {
      assert.ok(orch);
      var stats = orch.getStats();
      assert.strictEqual(stats.totalCampaignsCreated, 0);
      assert.strictEqual(stats.activeCampaigns, 0);
    });

    it("accepts custom options", function () {
      var custom = new DeceptionCampaignOrchestrator({
        maxCampaigns: 10,
        botThreshold: 0.8,
        humanThreshold: 0.2
      });
      assert.ok(custom);
    });
  });

  // ── Campaign Design ───────────────────────────────────────────────

  describe("designCampaign", function () {
    it("creates a campaign with default settings", function () {
      var result = orch.designCampaign("session-1");
      assert.ok(result.campaignId);
      assert.strictEqual(result.sessionId, "session-1");
      assert.strictEqual(result.strategy, "adaptive");
      assert.strictEqual(result.status, "ACTIVE");
      assert.ok(result.phases.length > 0);
    });

    it("creates aggressive campaign", function () {
      var result = orch.designCampaign("session-2", { strategy: "aggressive", phases: 4 });
      assert.strictEqual(result.strategy, "aggressive");
      assert.strictEqual(result.phases.length, 4);
    });

    it("creates subtle campaign", function () {
      var result = orch.designCampaign("session-3", { strategy: "subtle", phases: 2 });
      assert.strictEqual(result.strategy, "subtle");
      assert.strictEqual(result.phases.length, 2);
    });

    it("clamps phases to 1-5", function () {
      var result = orch.designCampaign("session-4", { phases: 10 });
      assert.ok(result.phases.length <= 5);
    });

    it("throws on missing sessionId", function () {
      assert.throws(function () { orch.designCampaign(""); }, /sessionId/);
      assert.throws(function () { orch.designCampaign(null); }, /sessionId/);
    });

    it("allows custom tactics", function () {
      var result = orch.designCampaign("session-5", {
        tactics: ["HONEYPOT", "DELAY_TRAP"],
        phases: 1
      });
      assert.ok(result.phases[0].tactics.length > 0);
    });

    it("evicts oldest campaign when at capacity", function () {
      var small = new DeceptionCampaignOrchestrator({ maxCampaigns: 2 });
      small.designCampaign("s1");
      small.designCampaign("s2");
      // Third should evict first
      small.designCampaign("s3");
      assert.strictEqual(small.getStats().activeCampaigns, 2);
    });

    it("increments stats", function () {
      orch.designCampaign("s1");
      orch.designCampaign("s2");
      assert.strictEqual(orch.getStats().totalCampaignsCreated, 2);
    });
  });

  // ── Observation Recording ─────────────────────────────────────────

  describe("recordObservation", function () {
    var campaignId;
    var firstTactic;

    beforeEach(function () {
      var result = orch.designCampaign("session-obs", { phases: 1, tactics: ["HONEYPOT", "DELAY_TRAP"] });
      campaignId = result.campaignId;
      firstTactic = result.phases[0].tactics[0];
    });

    it("records a honeypot observation", function () {
      var result = orch.recordObservation(campaignId, "HONEYPOT", {
        behavior: "clicked_hidden",
        responseTimeMs: 50,
        interactedWithTrap: true
      });
      assert.ok(result);
      assert.ok(result.botSignalStrength > 0.5);
    });

    it("records a delay trap observation", function () {
      var result = orch.recordObservation(campaignId, "DELAY_TRAP", {
        behavior: "waited",
        responseTimeMs: 1000
      });
      assert.ok(result);
    });

    it("throws on unknown campaign", function () {
      assert.throws(function () {
        orch.recordObservation("fake-id", "HONEYPOT", { behavior: "test" });
      }, /Campaign not found/);
    });

    it("throws on unknown tactic type", function () {
      assert.throws(function () {
        orch.recordObservation(campaignId, "FAKE_TACTIC", { behavior: "test" });
      }, /Unknown tactic/);
    });

    it("throws on invalid observation", function () {
      assert.throws(function () {
        orch.recordObservation(campaignId, "HONEYPOT", null);
      }, /observation must be/);
    });

    it("advances phase when all tactics triggered", function () {
      orch.recordObservation(campaignId, "HONEYPOT", {
        behavior: "ignored",
        interactedWithTrap: false
      });
      var result = orch.recordObservation(campaignId, "DELAY_TRAP", {
        behavior: "waited",
        responseTimeMs: 1500
      });
      // Single phase campaign should complete
      assert.strictEqual(result.status, "COMPLETED");
      assert.ok(result.verdict);
    });
  });

  // ── Bot Signal Scoring ────────────────────────────────────────────

  describe("bot signal scoring", function () {
    var campaignId;

    beforeEach(function () {
      var result = orch.designCampaign("score-test", {
        phases: 1,
        tactics: ["HONEYPOT", "IMPOSSIBLE_CHALLENGE", "CURIOSITY_BAIT", "FRUSTRATION_TEST", "CONSISTENCY_PROBE", "SOCIAL_PROOF_TRAP", "DELAY_TRAP"]
      });
      campaignId = result.campaignId;
    });

    it("honeypot interaction scores high bot signal", function () {
      var result = orch.recordObservation(campaignId, "HONEYPOT", {
        behavior: "clicked",
        interactedWithTrap: true
      });
      assert.ok(result.botSignalStrength > 0.7);
    });

    it("honeypot non-interaction scores low bot signal", function () {
      var result = orch.recordObservation(campaignId, "HONEYPOT", {
        behavior: "ignored",
        interactedWithTrap: false
      });
      assert.ok(result.botSignalStrength < 0.3);
    });

    it("impossible challenge attempted scores high", function () {
      var result = orch.recordObservation(campaignId, "IMPOSSIBLE_CHALLENGE", {
        behavior: "attempted_solution"
      });
      assert.ok(result.botSignalStrength > 0.6);
    });

    it("impossible challenge skipped scores low", function () {
      var result = orch.recordObservation(campaignId, "IMPOSSIBLE_CHALLENGE", {
        behavior: "skipped"
      });
      assert.ok(result.botSignalStrength < 0.4);
    });

    it("curiosity bait explored scores low bot signal", function () {
      var result = orch.recordObservation(campaignId, "CURIOSITY_BAIT", {
        behavior: "explored",
        interactedWithTrap: true
      });
      assert.ok(result.botSignalStrength < 0.4);
    });

    it("very fast delay trap response scores high", function () {
      var result = orch.recordObservation(campaignId, "DELAY_TRAP", {
        behavior: "instant",
        responseTimeMs: 50
      });
      assert.ok(result.botSignalStrength > 0.5);
    });

    it("high consistency in frustration test scores bot", function () {
      var result = orch.recordObservation(campaignId, "FRUSTRATION_TEST", {
        behavior: "flat",
        consistencyScore: 0.95
      });
      assert.ok(result.botSignalStrength > 0.5);
    });

    it("perfect consistency probe scores high bot", function () {
      var result = orch.recordObservation(campaignId, "CONSISTENCY_PROBE", {
        behavior: "identical",
        consistencyScore: 0.99
      });
      assert.ok(result.botSignalStrength > 0.5);
    });

    it("social proof interaction scores human-like", function () {
      var result = orch.recordObservation(campaignId, "SOCIAL_PROOF_TRAP", {
        behavior: "influenced",
        interactedWithTrap: true
      });
      assert.ok(result.botSignalStrength < 0.5);
    });
  });

  // ── Campaign Completion & Verdicts ────────────────────────────────

  describe("campaign verdicts", function () {
    it("detects a bot through high bot signals", function () {
      var result = orch.designCampaign("bot-session", {
        phases: 1,
        tactics: ["HONEYPOT", "IMPOSSIBLE_CHALLENGE"]
      });
      orch.recordObservation(result.campaignId, "HONEYPOT", {
        behavior: "clicked_hidden",
        interactedWithTrap: true
      });
      var final = orch.recordObservation(result.campaignId, "IMPOSSIBLE_CHALLENGE", {
        behavior: "attempted_solution"
      });
      assert.strictEqual(final.status, "COMPLETED");
      assert.ok(final.verdict.classification === "BOT" || final.verdict.classification === "LIKELY_BOT");
      assert.ok(final.verdict.botConfidence > 0.5);
      assert.ok(final.verdict.evidenceChain.length === 2);
    });

    it("clears a human through low bot signals", function () {
      var result = orch.designCampaign("human-session", {
        phases: 1,
        tactics: ["HONEYPOT", "CURIOSITY_BAIT"]
      });
      orch.recordObservation(result.campaignId, "HONEYPOT", {
        behavior: "ignored",
        interactedWithTrap: false
      });
      var final = orch.recordObservation(result.campaignId, "CURIOSITY_BAIT", {
        behavior: "explored",
        interactedWithTrap: true
      });
      assert.strictEqual(final.status, "COMPLETED");
      assert.ok(final.verdict.classification === "HUMAN" || final.verdict.classification === "LIKELY_HUMAN");
      assert.ok(final.verdict.botConfidence < 0.5);
    });

    it("updates suspect profile with verdict", function () {
      var result = orch.designCampaign("profile-test", {
        phases: 1,
        tactics: ["HONEYPOT"]
      });
      orch.recordObservation(result.campaignId, "HONEYPOT", {
        behavior: "clicked",
        interactedWithTrap: true
      });
      var profile = orch.getSuspectProfile("profile-test");
      assert.ok(profile);
      assert.ok(profile.lastVerdict);
    });

    it("archives completed campaigns", function () {
      var result = orch.designCampaign("archive-test", {
        phases: 1,
        tactics: ["HONEYPOT"]
      });
      orch.recordObservation(result.campaignId, "HONEYPOT", {
        behavior: "clicked",
        interactedWithTrap: true
      });
      var history = orch.getCampaignHistory();
      assert.ok(history.length > 0);
      assert.strictEqual(history[0].sessionId, "archive-test");
    });
  });

  // ── Multi-Phase Campaigns ─────────────────────────────────────────

  describe("multi-phase campaigns", function () {
    it("advances through multiple phases", function () {
      var result = orch.designCampaign("multi-phase", {
        phases: 2,
        tactics: ["HONEYPOT", "DELAY_TRAP", "IMPOSSIBLE_CHALLENGE", "CURIOSITY_BAIT"]
      });
      var campaignId = result.campaignId;

      // Phase 1
      var tacticsInPhase1 = result.phases[0].tactics;
      for (var i = 0; i < tacticsInPhase1.length; i++) {
        orch.recordObservation(campaignId, tacticsInPhase1[i], {
          behavior: "test",
          responseTimeMs: 500
        });
      }

      // Check if we're still in the campaign (either advanced or completed)
      var status = orch.getCampaignStatus(campaignId);
      if (status) {
        // Still active, complete phase 2
        var tacticsInPhase2 = result.phases[1].tactics;
        for (var j = 0; j < tacticsInPhase2.length; j++) {
          var r = orch.recordObservation(campaignId, tacticsInPhase2[j], {
            behavior: "test",
            responseTimeMs: 500
          });
          if (r.status === "COMPLETED") break;
        }
      }

      // Campaign should be completed now
      assert.ok(orch.getCampaignHistory().length > 0);
    });
  });

  // ── Suspect Profiling ─────────────────────────────────────────────

  describe("suspect profiling", function () {
    it("builds behavioral profile from observations", function () {
      var result = orch.designCampaign("profile-build", {
        phases: 1,
        tactics: ["HONEYPOT", "DELAY_TRAP"]
      });
      orch.recordObservation(result.campaignId, "HONEYPOT", {
        behavior: "ignored",
        interactedWithTrap: false,
        responseTimeMs: 1200
      });
      orch.recordObservation(result.campaignId, "DELAY_TRAP", {
        behavior: "waited",
        responseTimeMs: 800
      });

      var profile = orch.getSuspectProfile("profile-build");
      assert.ok(profile);
      assert.ok(profile.behavioralProfile.avgResponseTimeMs > 0);
      assert.strictEqual(profile.observationCount, 2);
    });

    it("returns null for unknown suspect", function () {
      assert.strictEqual(orch.getSuspectProfile("nobody"), null);
    });

    it("tracks trap interaction rate", function () {
      var result = orch.designCampaign("trap-rate", {
        phases: 1,
        tactics: ["HONEYPOT", "CURIOSITY_BAIT"]
      });
      orch.recordObservation(result.campaignId, "HONEYPOT", {
        behavior: "clicked",
        interactedWithTrap: true
      });
      orch.recordObservation(result.campaignId, "CURIOSITY_BAIT", {
        behavior: "ignored",
        interactedWithTrap: false
      });
      var profile = orch.getSuspectProfile("trap-rate");
      assert.ok(profile.behavioralProfile.trapInteractionRate != null);
    });

    it("evicts oldest suspect when at capacity", function () {
      var small = new DeceptionCampaignOrchestrator({ maxSuspects: 2, maxCampaigns: 10 });
      small.designCampaign("s1");
      small.designCampaign("s2");
      small.designCampaign("s3");
      assert.strictEqual(small.getStats().trackedSuspects, 2);
    });
  });

  // ── Tactic Rankings ───────────────────────────────────────────────

  describe("tactic rankings", function () {
    it("returns all tactic types", function () {
      var rankings = orch.getTacticRankings();
      assert.strictEqual(rankings.length, TACTIC_TYPES.length);
    });

    it("starts with neutral effectiveness", function () {
      var rankings = orch.getTacticRankings();
      for (var i = 0; i < rankings.length; i++) {
        assert.strictEqual(rankings[i].effectiveness, 0.5);
      }
    });

    it("updates effectiveness after campaign completion", function () {
      // Run a campaign that detects a bot
      var result = orch.designCampaign("learn-test", {
        phases: 1,
        tactics: ["HONEYPOT"]
      });
      orch.recordObservation(result.campaignId, "HONEYPOT", {
        behavior: "clicked",
        interactedWithTrap: true
      });

      var rankings = orch.getTacticRankings();
      var honeypot = rankings.find(function (r) { return r.tactic === "HONEYPOT"; });
      assert.ok(honeypot.deployments > 0);
    });
  });

  // ── Campaign Recommendations ──────────────────────────────────────

  describe("recommendCampaign", function () {
    it("recommends aggressive for high suspicion", function () {
      var rec = orch.recommendCampaign("suspicious", {
        requestRate: 20,
        avgResponseTimeMs: 50,
        hasMouseMovement: false,
        hasKeystrokes: false,
        failedAttempts: 5
      });
      assert.ok(rec.suspicionScore > 0.6);
      assert.strictEqual(rec.recommendation.launch, true);
      assert.strictEqual(rec.recommendation.strategy, "aggressive");
    });

    it("does not recommend for normal behavior", function () {
      var rec = orch.recommendCampaign("normal", {
        requestRate: 2,
        avgResponseTimeMs: 3000,
        hasMouseMovement: true,
        hasKeystrokes: true,
        failedAttempts: 0
      });
      assert.ok(rec.suspicionScore < 0.2);
      assert.strictEqual(rec.recommendation.launch, false);
    });

    it("factors in existing suspect data", function () {
      // First, create a suspect with a prior bot verdict
      var result = orch.designCampaign("repeat-offender", {
        phases: 1,
        tactics: ["HONEYPOT"]
      });
      orch.recordObservation(result.campaignId, "HONEYPOT", {
        behavior: "clicked",
        interactedWithTrap: true
      });

      var rec = orch.recommendCampaign("repeat-offender", {
        requestRate: 5,
        avgResponseTimeMs: 500
      });
      assert.ok(rec.existingSuspect);
      // Should be more suspicious due to prior history
      assert.ok(rec.suspicionScore > 0);
    });

    it("returns subtle for mild suspicion", function () {
      var rec = orch.recommendCampaign("mild", {
        hasMouseMovement: false
      });
      assert.ok(rec.suspicionScore >= 0.2);
      assert.strictEqual(rec.recommendation.launch, true);
      assert.strictEqual(rec.recommendation.strategy, "subtle");
    });
  });

  // ── False Positive Reporting ──────────────────────────────────────

  describe("reportFalsePositive", function () {
    it("corrects a false positive", function () {
      var result = orch.designCampaign("fp-test", {
        phases: 1,
        tactics: ["HONEYPOT"]
      });
      orch.recordObservation(result.campaignId, "HONEYPOT", {
        behavior: "clicked",
        interactedWithTrap: true
      });

      var corrected = orch.reportFalsePositive("fp-test");
      assert.strictEqual(corrected, true);

      var profile = orch.getSuspectProfile("fp-test");
      assert.strictEqual(profile.lastVerdict, "HUMAN");
      assert.strictEqual(orch.getStats().totalFalsePositives, 1);
    });

    it("returns false for unknown session", function () {
      assert.strictEqual(orch.reportFalsePositive("nobody"), false);
    });
  });

  // ── State Export / Import ─────────────────────────────────────────

  describe("state export/import", function () {
    it("round-trips state", function () {
      orch.designCampaign("state-test");
      var state = orch.exportState();
      assert.strictEqual(state.version, 1);
      assert.ok(state.campaigns);
      assert.ok(state.suspects);

      var orch2 = new DeceptionCampaignOrchestrator();
      orch2.importState(state);
      assert.strictEqual(orch2.getStats().totalCampaignsCreated, 1);
    });

    it("throws on invalid state version", function () {
      assert.throws(function () {
        orch.importState({ version: 99 });
      }, /Invalid state version/);
    });
  });

  // ── Stats ─────────────────────────────────────────────────────────

  describe("getStats", function () {
    it("includes top tactic", function () {
      var stats = orch.getStats();
      assert.ok(stats.topTactic);
    });

    it("tracks detection rate", function () {
      // Bot campaign
      var r1 = orch.designCampaign("det-bot", { phases: 1, tactics: ["HONEYPOT"] });
      orch.recordObservation(r1.campaignId, "HONEYPOT", { behavior: "clicked", interactedWithTrap: true });

      // Human campaign
      var r2 = orch.designCampaign("det-human", { phases: 1, tactics: ["HONEYPOT"] });
      orch.recordObservation(r2.campaignId, "HONEYPOT", { behavior: "ignored", interactedWithTrap: false });

      var stats = orch.getStats();
      assert.ok(stats.totalCampaignsCompleted >= 2);
    });
  });

  // ── Campaign Status ───────────────────────────────────────────────

  describe("getCampaignStatus", function () {
    it("returns status for active campaign", function () {
      var result = orch.designCampaign("status-test");
      var status = orch.getCampaignStatus(result.campaignId);
      assert.ok(status);
      assert.strictEqual(status.status, "ACTIVE");
      assert.strictEqual(status.sessionId, "status-test");
    });

    it("returns null for unknown campaign", function () {
      assert.strictEqual(orch.getCampaignStatus("fake"), null);
    });
  });

  // ── Campaign History ──────────────────────────────────────────────

  describe("getCampaignHistory", function () {
    it("respects limit parameter", function () {
      for (var i = 0; i < 5; i++) {
        var r = orch.designCampaign("hist-" + i, { phases: 1, tactics: ["HONEYPOT"] });
        orch.recordObservation(r.campaignId, "HONEYPOT", { behavior: "test", interactedWithTrap: true });
      }
      var history = orch.getCampaignHistory(3);
      assert.ok(history.length <= 3);
    });

    it("returns most recent first", function () {
      var r1 = orch.designCampaign("first", { phases: 1, tactics: ["HONEYPOT"] });
      orch.recordObservation(r1.campaignId, "HONEYPOT", { behavior: "test", interactedWithTrap: true });

      var r2 = orch.designCampaign("second", { phases: 1, tactics: ["HONEYPOT"] });
      orch.recordObservation(r2.campaignId, "HONEYPOT", { behavior: "test", interactedWithTrap: true });

      var history = orch.getCampaignHistory();
      assert.strictEqual(history[0].sessionId, "second");
    });
  });

  // ── Constants ─────────────────────────────────────────────────────

  describe("exported constants", function () {
    it("exports TACTIC_TYPES", function () {
      assert.ok(Array.isArray(TACTIC_TYPES));
      assert.strictEqual(TACTIC_TYPES.length, 7);
    });

    it("exports CAMPAIGN_PHASES", function () {
      assert.ok(Array.isArray(CAMPAIGN_PHASES));
      assert.strictEqual(CAMPAIGN_PHASES.length, 5);
    });
  });
});
