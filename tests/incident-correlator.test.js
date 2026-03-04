var { describe, it, beforeEach } = require("node:test");
var assert = require("node:assert/strict");
var { createIncidentCorrelator } = require("../src/index");

describe("createIncidentCorrelator", function () {
  var correlator;

  beforeEach(function () {
    correlator = createIncidentCorrelator();
  });

  // ── Basic signal ingestion ──────────────────────────────────

  describe("ingest", function () {
    it("creates a new incident from first signal", function () {
      var r = correlator.ingest({
        type: "challenge_failed",
        clientId: "client-1",
      });
      assert.equal(r.incidentId, 1);
      assert.equal(r.severity, "info");
      assert.equal(r.isNew, true);
      assert.equal(r.escalated, false);
    });

    it("groups signals from same client into one incident", function () {
      var r1 = correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      var r2 = correlator.ingest({ type: "rate_limited", clientId: "c1", timestamp: 2000 });
      assert.equal(r1.incidentId, r2.incidentId);
      assert.equal(r2.isNew, false);
    });

    it("creates separate incidents for different clients", function () {
      var r1 = correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      var r2 = correlator.ingest({ type: "challenge_failed", clientId: "c2" });
      assert.notEqual(r1.incidentId, r2.incidentId);
    });

    it("returns error for missing type", function () {
      assert.ok(correlator.ingest({ clientId: "c1" }).error);
    });

    it("returns error for missing clientId", function () {
      assert.ok(correlator.ingest({ type: "challenge_failed" }).error);
    });

    it("returns error for null input", function () {
      assert.ok(correlator.ingest(null).error);
    });
  });

  // ── Severity escalation ─────────────────────────────────────

  describe("severity escalation", function () {
    it("starts at INFO", function () {
      var r = correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      assert.equal(r.severity, "info");
    });

    it("escalates to WARNING at threshold", function () {
      var last;
      for (var i = 0; i < 3; i++) {
        last = correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 + i });
      }
      assert.equal(last.severity, "warning");
      assert.equal(last.escalated, true);
    });

    it("escalates to HIGH at threshold", function () {
      var last;
      for (var i = 0; i < 6; i++) {
        last = correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 + i });
      }
      assert.equal(last.severity, "high");
    });

    it("escalates to CRITICAL at threshold", function () {
      var last;
      for (var i = 0; i < 10; i++) {
        last = correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 + i });
      }
      assert.equal(last.severity, "critical");
    });

    it("weighted signals escalate faster", function () {
      var last;
      for (var i = 0; i < 3; i++) {
        last = correlator.ingest({
          type: "bot_detected", clientId: "c1", weight: 2, timestamp: 1000 + i,
        });
      }
      assert.equal(last.severity, "high");
    });

    it("respects custom thresholds", function () {
      var c = createIncidentCorrelator({
        thresholds: { warning: 2, high: 4, critical: 6 },
      });
      c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      var r = c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1001 });
      assert.equal(r.severity, "warning");
    });
  });

  // ── Correlation window ──────────────────────────────────────

  describe("correlation window", function () {
    it("closes incident after window expires", function () {
      var c = createIncidentCorrelator({ correlationWindowMs: 5000 });
      var r1 = c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      var r2 = c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 7000 });
      assert.notEqual(r2.incidentId, r1.incidentId);
      assert.equal(r2.isNew, true);
    });

    it("keeps incident open within window", function () {
      var c = createIncidentCorrelator({ correlationWindowMs: 5000 });
      var r1 = c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      var r2 = c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 4000 });
      assert.equal(r2.incidentId, r1.incidentId);
    });

    it("sliding window extends with each signal", function () {
      var c = createIncidentCorrelator({ correlationWindowMs: 5000 });
      c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 4000 });
      var r3 = c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 8000 });
      assert.equal(r3.isNew, false);
    });
  });

  // ── Callbacks ───────────────────────────────────────────────

  describe("callbacks", function () {
    it("fires onAlert at WARNING", function () {
      var alerts = [];
      var c = createIncidentCorrelator({
        onAlert: function (inc) { alerts.push(inc); },
      });
      for (var i = 0; i < 3; i++) {
        c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 + i });
      }
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].severity, "warning");
    });

    it("fires onAlert on each escalation level", function () {
      var alerts = [];
      var c = createIncidentCorrelator({
        onAlert: function (inc) { alerts.push(inc); },
      });
      for (var i = 0; i < 10; i++) {
        c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 + i });
      }
      assert.equal(alerts.length, 3);
    });

    it("fires onEscalation with old severity", function () {
      var escalations = [];
      var c = createIncidentCorrelator({
        onEscalation: function (inc, old) { escalations.push({ severity: inc.severity, old: old }); },
      });
      for (var i = 0; i < 3; i++) {
        c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 + i });
      }
      assert.equal(escalations.length, 1);
      assert.equal(escalations[0].old, "info");
      assert.equal(escalations[0].severity, "warning");
    });

    it("swallows callback errors", function () {
      var c = createIncidentCorrelator({
        onAlert: function () { throw new Error("boom"); },
      });
      for (var i = 0; i < 3; i++) {
        c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 + i });
      }
      // Should not throw
    });
  });

  // ── Incident retrieval ──────────────────────────────────────

  describe("getIncident", function () {
    it("returns incident by ID", function () {
      var r = correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      var inc = correlator.getIncident(r.incidentId);
      assert.ok(inc);
      assert.equal(inc.id, r.incidentId);
      assert.equal(inc.clientId, "c1");
      assert.equal(inc.signalCount, 1);
    });

    it("returns null for unknown ID", function () {
      assert.equal(correlator.getIncident(999), null);
    });

    it("includes signal details", function () {
      correlator.ingest({
        type: "bot_detected", clientId: "c1",
        description: "honeypot triggered", metadata: { score: 0.95 },
      });
      var inc = correlator.getIncident(1);
      assert.equal(inc.signals[0].type, "bot_detected");
      assert.equal(inc.signals[0].description, "honeypot triggered");
    });
  });

  describe("getClientIncident", function () {
    it("returns active incident for client", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      var inc = correlator.getClientIncident("c1");
      assert.ok(inc);
      assert.equal(inc.clientId, "c1");
    });

    it("returns null for unknown client", function () {
      assert.equal(correlator.getClientIncident("unknown"), null);
    });

    it("returns null after incident is closed", function () {
      var r = correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      correlator.closeIncident(r.incidentId);
      assert.equal(correlator.getClientIncident("c1"), null);
    });
  });

  // ── Close incident ──────────────────────────────────────────

  describe("closeIncident", function () {
    it("closes an open incident", function () {
      var r = correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      assert.equal(correlator.closeIncident(r.incidentId), true);
      assert.equal(correlator.getIncident(r.incidentId).status, "closed");
    });

    it("returns false for unknown incident", function () {
      assert.equal(correlator.closeIncident(999), false);
    });

    it("new signals after close create new incident", function () {
      var r1 = correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      correlator.closeIncident(r1.incidentId);
      var r2 = correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 2000 });
      assert.notEqual(r2.incidentId, r1.incidentId);
      assert.equal(r2.isNew, true);
    });
  });

  // ── Query incidents ─────────────────────────────────────────

  describe("queryIncidents", function () {
    it("returns all incidents by default", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      correlator.ingest({ type: "challenge_failed", clientId: "c2" });
      assert.equal(correlator.queryIncidents().length, 2);
    });

    it("filters by severity", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      for (var i = 0; i < 3; i++) {
        correlator.ingest({ type: "challenge_failed", clientId: "c2", timestamp: 1000 + i });
      }
      var warnings = correlator.queryIncidents({ severity: "warning" });
      assert.equal(warnings.length, 1);
      assert.equal(warnings[0].clientId, "c2");
    });

    it("filters by minimum severity", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      for (var i = 0; i < 6; i++) {
        correlator.ingest({ type: "challenge_failed", clientId: "c2", timestamp: 1000 + i });
      }
      assert.equal(correlator.queryIncidents({ minSeverity: "high" }).length, 1);
    });

    it("filters by status", function () {
      var r = correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      correlator.ingest({ type: "challenge_failed", clientId: "c2" });
      correlator.closeIncident(r.incidentId);
      assert.equal(correlator.queryIncidents({ status: "open" }).length, 1);
      assert.equal(correlator.queryIncidents({ status: "closed" }).length, 1);
    });

    it("filters by timestamp", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      correlator.ingest({ type: "challenge_failed", clientId: "c2", timestamp: 5000 });
      assert.equal(correlator.queryIncidents({ since: 3000 }).length, 1);
    });

    it("respects limit", function () {
      for (var i = 0; i < 10; i++) {
        correlator.ingest({ type: "challenge_failed", clientId: "c" + i });
      }
      assert.equal(correlator.queryIncidents({ limit: 3 }).length, 3);
    });

    it("returns newest first", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      correlator.ingest({ type: "challenge_failed", clientId: "c2", timestamp: 2000 });
      var results = correlator.queryIncidents();
      assert.equal(results[0].clientId, "c2");
      assert.equal(results[1].clientId, "c1");
    });
  });

  // ── Stats ───────────────────────────────────────────────────

  describe("getStats", function () {
    it("tracks total signals", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      correlator.ingest({ type: "bot_detected", clientId: "c1" });
      assert.equal(correlator.getStats().totalSignals, 2);
    });

    it("tracks signals by type", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      correlator.ingest({ type: "challenge_failed", clientId: "c2" });
      correlator.ingest({ type: "bot_detected", clientId: "c1" });
      var s = correlator.getStats();
      assert.equal(s.signalsByType.challenge_failed, 2);
      assert.equal(s.signalsByType.bot_detected, 1);
    });

    it("tracks incidents by severity", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      for (var i = 0; i < 3; i++) {
        correlator.ingest({ type: "challenge_failed", clientId: "c2", timestamp: 1000 + i });
      }
      var s = correlator.getStats();
      assert.equal(s.incidentsBySeverity.info, 1);
      assert.equal(s.incidentsBySeverity.warning, 1);
    });

    it("tracks active incidents", function () {
      var r = correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      correlator.ingest({ type: "challenge_failed", clientId: "c2" });
      correlator.closeIncident(r.incidentId);
      assert.equal(correlator.getStats().activeIncidents, 1);
    });

    it("tracks alerts and escalations", function () {
      for (var i = 0; i < 6; i++) {
        correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 + i });
      }
      var s = correlator.getStats();
      assert.equal(s.totalEscalations, 2);
      assert.equal(s.totalAlerts, 2);
    });
  });

  // ── LRU eviction ────────────────────────────────────────────

  describe("eviction", function () {
    it("evicts oldest incidents when over maxIncidents", function () {
      var c = createIncidentCorrelator({ maxIncidents: 3 });
      for (var i = 0; i < 5; i++) {
        c.ingest({ type: "challenge_failed", clientId: "c" + i });
      }
      assert.equal(c.getIncident(1), null);
      assert.equal(c.getIncident(2), null);
      assert.ok(c.getIncident(3));
      assert.ok(c.getIncident(5));
    });
  });

  // ── Signal cap per incident ─────────────────────────────────

  describe("maxSignalsPerIncident", function () {
    it("caps stored signals but still counts", function () {
      var c = createIncidentCorrelator({ maxSignalsPerIncident: 3 });
      for (var i = 0; i < 5; i++) {
        c.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 + i });
      }
      var inc = c.getIncident(1);
      assert.equal(inc.signals.length, 3);
      assert.equal(inc.signalCount, 5);
    });
  });

  // ── Reset ───────────────────────────────────────────────────

  describe("reset", function () {
    it("clears all state", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      correlator.reset();
      assert.equal(correlator.getStats().totalSignals, 0);
      assert.equal(correlator.getStats().totalIncidents, 0);
      assert.equal(correlator.queryIncidents().length, 0);
    });

    it("resets incident IDs", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      correlator.reset();
      var r = correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      assert.equal(r.incidentId, 1);
    });
  });

  // ── Export state ────────────────────────────────────────────

  describe("exportState", function () {
    it("includes incidents and stats", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1" });
      correlator.ingest({ type: "bot_detected", clientId: "c2" });
      var state = correlator.exportState();
      assert.equal(state.incidents.length, 2);
      assert.equal(state.stats.totalSignals, 2);
      assert.equal(state.config.correlationWindowMs, 60000);
    });
  });

  // ── Constants ───────────────────────────────────────────────

  describe("constants", function () {
    it("exposes SIGNAL_TYPES", function () {
      assert.equal(correlator.SIGNAL_TYPES.CHALLENGE_FAILED, "challenge_failed");
      assert.equal(correlator.SIGNAL_TYPES.BOT_DETECTED, "bot_detected");
      assert.equal(correlator.SIGNAL_TYPES.RATE_LIMITED, "rate_limited");
      assert.equal(correlator.SIGNAL_TYPES.TOKEN_REPLAY, "token_replay");
    });

    it("exposes SEVERITY", function () {
      assert.equal(correlator.SEVERITY.INFO, "info");
      assert.equal(correlator.SEVERITY.WARNING, "warning");
      assert.equal(correlator.SEVERITY.HIGH, "high");
      assert.equal(correlator.SEVERITY.CRITICAL, "critical");
    });
  });

  // ── Multi-type correlation ──────────────────────────────────

  describe("multi-type signal correlation", function () {
    it("tracks signal type distribution in incident", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      correlator.ingest({ type: "rate_limited", clientId: "c1", timestamp: 1001 });
      correlator.ingest({ type: "bot_detected", clientId: "c1", timestamp: 1002 });
      var inc = correlator.getIncident(1);
      assert.equal(inc.signalTypes.challenge_failed, 1);
      assert.equal(inc.signalTypes.rate_limited, 1);
      assert.equal(inc.signalTypes.bot_detected, 1);
    });

    it("calculates incident duration", function () {
      correlator.ingest({ type: "challenge_failed", clientId: "c1", timestamp: 1000 });
      correlator.ingest({ type: "bot_detected", clientId: "c1", timestamp: 5000 });
      var inc = correlator.getIncident(1);
      assert.equal(inc.durationMs, 4000);
    });
  });
});
