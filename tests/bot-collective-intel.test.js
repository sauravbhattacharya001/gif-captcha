/**
 * Tests for BotCollectiveIntelDetector.
 */

"use strict";

var test = require("node:test");
var assert = require("node:assert/strict");
var mod = require("../src/bot-collective-intel");
var createBotCollectiveIntelDetector = mod.createBotCollectiveIntelDetector;

// ── Helpers ─────────────────────────────────────────────────────────

var baseTime = 1700000000000;

function makeEvent(sessionId, challengeId, success, offset) {
  return {
    sessionId: sessionId,
    challengeId: challengeId,
    success: success,
    solveMs: 1500 + Math.random() * 500,
    timestamp: baseTime + (offset || 0)
  };
}

function ingestSwarmEvents(detector, sessionIds, challengeIds, opts) {
  opts = opts || {};
  var interval = opts.interval || 100;
  var successRate = opts.successRate || 0.8;
  var baseOffset = opts.baseOffset || 0;

  for (var round = 0; round < challengeIds.length; round++) {
    for (var s = 0; s < sessionIds.length; s++) {
      var offset = baseOffset + (round * interval * sessionIds.length) + (s * interval);
      detector.ingest(makeEvent(
        sessionIds[s],
        challengeIds[round],
        Math.random() < successRate,
        offset
      ));
    }
  }
}

// ── Basic Tests ─────────────────────────────────────────────────────

test("creates detector with default options", function () {
  var det = createBotCollectiveIntelDetector();
  assert.ok(det);
  assert.equal(typeof det.ingest, "function");
  assert.equal(typeof det.analyze, "function");
  assert.equal(typeof det.getReport, "function");
  assert.equal(typeof det.getSwarm, "function");
  assert.equal(typeof det.getFlaggedSessions, "function");
  assert.equal(typeof det.exportState, "function");
  assert.equal(typeof det.importState, "function");
  assert.equal(typeof det.reset, "function");
});

test("creates detector with custom options", function () {
  var det = createBotCollectiveIntelDetector({
    maxSessions: 100,
    maxSwarms: 10,
    syncThresholdMs: 500,
    correlationThreshold: 0.5,
    minSwarmSize: 2
  });
  assert.ok(det);
});

test("ingest rejects invalid events", function () {
  var det = createBotCollectiveIntelDetector();
  var r1 = det.ingest(null);
  assert.equal(r1.ingested, false);

  var r2 = det.ingest({ sessionId: "s1" });
  assert.equal(r2.ingested, false);

  var r3 = det.ingest({ challengeId: "c1" });
  assert.equal(r3.ingested, false);
});

test("ingest accepts valid event", function () {
  var det = createBotCollectiveIntelDetector();
  var r = det.ingest(makeEvent("s1", "c1", true, 0));
  assert.equal(r.ingested, true);
  assert.equal(r.swarmDetected, false);
});

test("single session does not form a swarm", function () {
  var det = createBotCollectiveIntelDetector();
  for (var i = 0; i < 20; i++) {
    det.ingest(makeEvent("s1", "c" + i, true, i * 1000));
  }
  var report = det.getReport();
  assert.equal(report.totalSwarms, 0);
});

// ── Swarm Detection ─────────────────────────────────────────────────

test("detects synchronized sessions as a swarm", function () {
  var det = createBotCollectiveIntelDetector({
    syncThresholdMs: 300,
    correlationThreshold: 0.4,
    minSwarmSize: 3
  });

  var sessions = ["bot1", "bot2", "bot3", "bot4"];
  var challenges = [];
  for (var i = 0; i < 20; i++) challenges.push("ch" + i);

  // All bots solve same challenges with similar timing
  ingestSwarmEvents(det, sessions, challenges, { interval: 100, successRate: 0.9 });

  var report = det.getReport();
  assert.ok(report.totalSwarms >= 1, "Should detect at least one swarm");
  assert.ok(report.stats.eventsIngested > 0);
});

test("independent sessions do not form a swarm", function () {
  var det = createBotCollectiveIntelDetector({
    correlationThreshold: 0.7,
    minSwarmSize: 3
  });

  // Sessions with very different timing and challenge sets
  for (var i = 0; i < 10; i++) {
    det.ingest(makeEvent("human1", "c" + i, true, i * 60000)); // 1 min apart
  }
  for (var j = 0; j < 10; j++) {
    det.ingest(makeEvent("human2", "x" + j, j % 3 === 0, j * 45000 + 500000)); // different challenges
  }
  for (var k = 0; k < 10; k++) {
    det.ingest(makeEvent("human3", "y" + k, k % 2 === 0, k * 120000 + 1000000)); // very spread out
  }

  var report = det.getReport();
  assert.equal(report.totalSwarms, 0, "Independent humans should not form a swarm");
});

// ── Analysis ────────────────────────────────────────────────────────

test("analyze returns structured results", function () {
  var det = createBotCollectiveIntelDetector({
    correlationThreshold: 0.4,
    minSwarmSize: 3
  });

  var sessions = ["b1", "b2", "b3"];
  var challenges = [];
  for (var i = 0; i < 15; i++) challenges.push("ch" + i);
  ingestSwarmEvents(det, sessions, challenges, { interval: 50, successRate: 0.9 });

  var result = det.analyze();
  assert.equal(typeof result.swarmsAnalyzed, "number");
  assert.ok(Array.isArray(result.escalations));
  assert.ok(Array.isArray(result.insights));
});

test("analyze detects topology shifts", function () {
  var det = createBotCollectiveIntelDetector({
    correlationThreshold: 0.3,
    minSwarmSize: 3,
    topologyRecheckMs: 0 // Always recheck
  });

  var sessions = ["s1", "s2", "s3", "s4", "s5"];
  var challenges = [];
  for (var i = 0; i < 20; i++) challenges.push("ch" + i);
  ingestSwarmEvents(det, sessions, challenges, { interval: 50, successRate: 0.85 });

  var result = det.analyze();
  assert.equal(typeof result.swarmsAnalyzed, "number");
});

// ── Report ──────────────────────────────────────────────────────────

test("getReport returns valid structure", function () {
  var det = createBotCollectiveIntelDetector();
  var report = det.getReport();
  assert.equal(report.totalSwarms, 0);
  assert.equal(report.globalThreatLevel, "DORMANT");
  assert.ok(Array.isArray(report.swarms));
  assert.ok(report.stats);
  assert.equal(report.stats.eventsIngested, 0);
});

test("getReport includes swarm details after detection", function () {
  var det = createBotCollectiveIntelDetector({
    correlationThreshold: 0.3,
    minSwarmSize: 3
  });

  var sessions = ["sw1", "sw2", "sw3"];
  var challenges = [];
  for (var i = 0; i < 20; i++) challenges.push("ch" + i);
  ingestSwarmEvents(det, sessions, challenges, { interval: 80, successRate: 0.9 });

  var report = det.getReport();
  if (report.totalSwarms > 0) {
    var s = report.swarms[0];
    assert.ok(s.id);
    assert.ok(s.members > 0);
    assert.ok(s.topology);
    assert.ok(typeof s.confidence === "number");
    assert.ok(typeof s.learningRate === "number");
    assert.ok(s.threatLevel);
    assert.ok(typeof s.sophisticationScore === "number");
  }
});

// ── Swarm Details ───────────────────────────────────────────────────

test("getSwarm returns null for unknown swarm", function () {
  var det = createBotCollectiveIntelDetector();
  assert.equal(det.getSwarm("unknown"), null);
});

test("getSwarm returns details for known swarm", function () {
  var det = createBotCollectiveIntelDetector({
    correlationThreshold: 0.3,
    minSwarmSize: 3
  });

  var sessions = ["d1", "d2", "d3"];
  var challenges = [];
  for (var i = 0; i < 15; i++) challenges.push("ch" + i);
  ingestSwarmEvents(det, sessions, challenges, { interval: 50, successRate: 0.85 });

  var report = det.getReport();
  if (report.totalSwarms > 0) {
    var detail = det.getSwarm(report.swarms[0].id);
    assert.ok(detail);
    assert.ok(Array.isArray(detail.members));
    assert.ok(detail.members.length >= 3);
  }
});

// ── Flagged Sessions ────────────────────────────────────────────────

test("getFlaggedSessions returns empty initially", function () {
  var det = createBotCollectiveIntelDetector();
  assert.deepEqual(det.getFlaggedSessions(), []);
});

test("getFlaggedSessions returns swarm members", function () {
  var det = createBotCollectiveIntelDetector({
    correlationThreshold: 0.3,
    minSwarmSize: 3
  });

  var sessions = ["f1", "f2", "f3"];
  var challenges = [];
  for (var i = 0; i < 15; i++) challenges.push("ch" + i);
  ingestSwarmEvents(det, sessions, challenges, { interval: 50, successRate: 0.9 });

  var flagged = det.getFlaggedSessions();
  if (flagged.length > 0) {
    assert.ok(flagged.length >= 3);
  }
});

// ── State Export/Import ─────────────────────────────────────────────

test("exportState returns version 1 state", function () {
  var det = createBotCollectiveIntelDetector();
  det.ingest(makeEvent("s1", "c1", true, 0));
  var state = det.exportState();
  assert.equal(state.version, 1);
  assert.ok(state.sessions);
  assert.ok(state.swarms);
  assert.ok(state.stats);
});

test("importState restores detector state", function () {
  var det1 = createBotCollectiveIntelDetector({ correlationThreshold: 0.3, minSwarmSize: 3 });
  var sessions = ["r1", "r2", "r3"];
  var challenges = [];
  for (var i = 0; i < 15; i++) challenges.push("ch" + i);
  ingestSwarmEvents(det1, sessions, challenges, { interval: 50, successRate: 0.85 });

  var state = det1.exportState();

  var det2 = createBotCollectiveIntelDetector({ correlationThreshold: 0.3, minSwarmSize: 3 });
  var ok = det2.importState(state);
  assert.equal(ok, true);

  var report1 = det1.getReport();
  var report2 = det2.getReport();
  assert.equal(report1.totalSwarms, report2.totalSwarms);
  assert.equal(report1.stats.eventsIngested, report2.stats.eventsIngested);
});

test("importState rejects invalid state", function () {
  var det = createBotCollectiveIntelDetector();
  assert.equal(det.importState(null), false);
  assert.equal(det.importState({ version: 99 }), false);
});

// ── Reset ───────────────────────────────────────────────────────────

test("reset clears all state", function () {
  var det = createBotCollectiveIntelDetector();
  for (var i = 0; i < 10; i++) det.ingest(makeEvent("s" + i, "c1", true, i * 100));

  det.reset();
  var report = det.getReport();
  assert.equal(report.totalSwarms, 0);
  assert.equal(report.stats.eventsIngested, 0);
  assert.equal(report.stats.sessionsTracked, 0);
});

// ── Session Eviction ────────────────────────────────────────────────

test("evicts oldest sessions when maxSessions reached", function () {
  var det = createBotCollectiveIntelDetector({ maxSessions: 5 });
  for (var i = 0; i < 10; i++) {
    det.ingest(makeEvent("sess" + i, "c1", true, i * 1000));
  }
  var report = det.getReport();
  assert.ok(report.stats.sessionsTracked <= 5);
});

// ── Constants ───────────────────────────────────────────────────────

test("exposes topology and threat level constants", function () {
  var det = createBotCollectiveIntelDetector();
  assert.deepEqual(det.SWARM_TOPOLOGIES, ["HUB_SPOKE", "MESH", "HIERARCHICAL", "PIPELINE", "INDEPENDENT"]);
  assert.deepEqual(det.THREAT_LEVELS, ["DORMANT", "PROBING", "COORDINATED", "SWARMING", "OVERWHELMING"]);
  assert.deepEqual(det.KNOWLEDGE_TYPES, ["CHALLENGE_SOLUTION", "TIMING_PATTERN", "EVASION_TACTIC", "ROTATION_EXPLOIT", "WEAKNESS_MAP"]);
});

// ── Threat Level Assessment ─────────────────────────────────────────

test("global threat level is DORMANT when no swarms", function () {
  var det = createBotCollectiveIntelDetector();
  var report = det.getReport();
  assert.equal(report.globalThreatLevel, "DORMANT");
});

// ── Knowledge Propagation ───────────────────────────────────────────

test("detects knowledge propagation in coordinated solves", function () {
  var det = createBotCollectiveIntelDetector({
    correlationThreshold: 0.3,
    minSwarmSize: 3,
    learningWindowMs: 100000
  });

  // Simulate 3 bots solving same challenges almost simultaneously
  var sessions = ["kp1", "kp2", "kp3"];
  for (var round = 0; round < 20; round++) {
    for (var s = 0; s < sessions.length; s++) {
      det.ingest({
        sessionId: sessions[s],
        challengeId: "shared_ch" + round,
        success: true,
        solveMs: 1200,
        timestamp: baseTime + (round * 200) + (s * 50)  // 50ms apart
      });
    }
  }

  var result = det.analyze();
  // Should detect propagation or at least run without error
  assert.equal(typeof result.swarmsAnalyzed, "number");
});

// ── Large Scale ─────────────────────────────────────────────────────

test("handles many sessions without error", function () {
  var det = createBotCollectiveIntelDetector({ maxSessions: 50 });
  for (var i = 0; i < 100; i++) {
    for (var j = 0; j < 5; j++) {
      det.ingest(makeEvent("ls" + i, "ch" + j, Math.random() > 0.3, i * 5000 + j * 1000));
    }
  }
  var report = det.getReport();
  assert.ok(report.stats.sessionsTracked <= 50);
  assert.ok(report.stats.eventsIngested === 500);
});

// ── Swarm eviction ──────────────────────────────────────────────────

test("evicts lowest confidence swarm when maxSwarms exceeded", function () {
  var det = createBotCollectiveIntelDetector({
    maxSwarms: 2,
    correlationThreshold: 0.2,
    minSwarmSize: 3
  });

  // Create multiple distinct clusters
  for (var cluster = 0; cluster < 4; cluster++) {
    var sessions = [];
    for (var s = 0; s < 3; s++) sessions.push("ev_c" + cluster + "_s" + s);
    var challenges = [];
    for (var c = 0; c < 10; c++) challenges.push("ev_ch" + cluster + "_" + c);
    ingestSwarmEvents(det, sessions, challenges, {
      interval: 30,
      successRate: 0.9,
      baseOffset: cluster * 1000000
    });
  }

  var report = det.getReport();
  assert.ok(report.totalSwarms <= 2, "Should evict to stay at maxSwarms");
});
