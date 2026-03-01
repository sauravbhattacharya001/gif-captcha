const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { createSessionManager } = require("../src/index");

describe("createSessionManager", function () {
  describe("initialization", function () {
    it("returns object with expected methods", function () {
      var mgr = createSessionManager();
      assert.equal(typeof mgr.startSession, "function");
      assert.equal(typeof mgr.submitResponse, "function");
      assert.equal(typeof mgr.getSession, "function");
      assert.equal(typeof mgr.invalidateSession, "function");
      assert.equal(typeof mgr.getStats, "function");
      assert.equal(typeof mgr.getConfig, "function");
    });

    it("uses default config when no options given", function () {
      var mgr = createSessionManager();
      var cfg = mgr.getConfig();
      assert.equal(cfg.challengesPerSession, 3);
      assert.equal(cfg.passThreshold, 0.67);
      assert.equal(cfg.sessionTimeoutMs, 300000);
      assert.equal(cfg.escalateDifficulty, true);
      assert.equal(cfg.difficultyStep, 15);
      assert.equal(cfg.baseDifficulty, 30);
      assert.equal(cfg.maxDifficulty, 95);
      assert.equal(cfg.maxSessions, 1000);
    });

    it("accepts custom config", function () {
      var mgr = createSessionManager({
        challengesPerSession: 5,
        passThreshold: 0.8,
        sessionTimeoutMs: 60000,
        escalateDifficulty: false,
        difficultyStep: 10,
        baseDifficulty: 50,
        maxDifficulty: 80,
        maxSessions: 100,
      });
      var cfg = mgr.getConfig();
      assert.equal(cfg.challengesPerSession, 5);
      assert.equal(cfg.passThreshold, 0.8);
      assert.equal(cfg.sessionTimeoutMs, 60000);
      assert.equal(cfg.escalateDifficulty, false);
      assert.equal(cfg.difficultyStep, 10);
      assert.equal(cfg.baseDifficulty, 50);
      assert.equal(cfg.maxDifficulty, 80);
      assert.equal(cfg.maxSessions, 100);
    });

    it("sanitizes invalid config values to defaults", function () {
      var mgr = createSessionManager({
        challengesPerSession: -1,
        passThreshold: 2,
        sessionTimeoutMs: 0,
        maxSessions: -5,
      });
      var cfg = mgr.getConfig();
      assert.equal(cfg.challengesPerSession, 3);
      assert.equal(cfg.passThreshold, 0.67);
      assert.equal(cfg.sessionTimeoutMs, 300000);
      assert.equal(cfg.maxSessions, 1000);
    });
  });

  describe("startSession", function () {
    it("returns session info with id and initial difficulty", function () {
      var mgr = createSessionManager({ baseDifficulty: 30 });
      var result = mgr.startSession();
      assert.ok(result.sessionId.startsWith("sess_"));
      assert.equal(result.difficulty, 30);
      assert.equal(result.challengeIndex, 0);
      assert.equal(result.totalChallenges, 3);
    });

    it("creates unique session IDs", function () {
      var mgr = createSessionManager();
      var ids = new Set();
      for (var i = 0; i < 20; i++) {
        ids.add(mgr.startSession().sessionId);
      }
      assert.equal(ids.size, 20);
    });

    it("accepts metadata", function () {
      var mgr = createSessionManager();
      var result = mgr.startSession({ userId: "u123", ip: "1.2.3.4" });
      var session = mgr.getSession(result.sessionId);
      assert.equal(session.metadata.userId, "u123");
      assert.equal(session.metadata.ip, "1.2.3.4");
    });

    it("works with no metadata argument", function () {
      var mgr = createSessionManager();
      var result = mgr.startSession();
      var session = mgr.getSession(result.sessionId);
      assert.deepEqual(session.metadata, {});
    });
  });

  describe("submitResponse", function () {
    var mgr;

    beforeEach(function () {
      mgr = createSessionManager({ challengesPerSession: 3, passThreshold: 0.67 });
    });

    it("records a correct answer", function () {
      var session = mgr.startSession();
      var result = mgr.submitResponse(session.sessionId, true);
      assert.equal(result.done, false);
      assert.equal(result.passed, null);
      assert.equal(result.correctCount, 1);
      assert.equal(result.totalAnswered, 1);
      assert.equal(result.challengeIndex, 1);
    });

    it("records an incorrect answer", function () {
      var session = mgr.startSession();
      var result = mgr.submitResponse(session.sessionId, false);
      assert.equal(result.done, false);
      assert.equal(result.correctCount, 0);
      assert.equal(result.totalAnswered, 1);
    });

    it("completes session with pass when threshold met", function () {
      // passThreshold=0.67, need 2/3 = 0.667 which is < 0.67
      // Use passThreshold=0.6 to ensure 2/3 passes
      var mgr2 = createSessionManager({ challengesPerSession: 3, passThreshold: 0.6 });
      var session = mgr2.startSession();
      mgr2.submitResponse(session.sessionId, true);
      mgr2.submitResponse(session.sessionId, true);
      var result = mgr2.submitResponse(session.sessionId, false);
      assert.equal(result.done, true);
      assert.equal(result.passed, true);
      assert.equal(result.correctCount, 2);
      assert.ok(result.passRate >= 0.6);
    });

    it("completes session with fail when threshold not met", function () {
      var session = mgr.startSession();
      mgr.submitResponse(session.sessionId, false);
      mgr.submitResponse(session.sessionId, false);
      var result = mgr.submitResponse(session.sessionId, true);
      assert.equal(result.done, true);
      assert.equal(result.passed, false);
      assert.equal(result.correctCount, 1);
    });

    it("returns error for unknown session", function () {
      var result = mgr.submitResponse("nonexistent", true);
      assert.equal(result.error, "session_not_found");
    });

    it("returns error for completed session", function () {
      var session = mgr.startSession();
      mgr.submitResponse(session.sessionId, true);
      mgr.submitResponse(session.sessionId, true);
      mgr.submitResponse(session.sessionId, true);
      var result = mgr.submitResponse(session.sessionId, true);
      assert.equal(result.error, "session_passed");
    });

    it("records response time when provided", function () {
      var session = mgr.startSession();
      mgr.submitResponse(session.sessionId, true, 1500);
      var state = mgr.getSession(session.sessionId);
      assert.equal(state.results[0].responseTimeMs, 1500);
    });

    it("handles missing response time gracefully", function () {
      var session = mgr.startSession();
      mgr.submitResponse(session.sessionId, true);
      var state = mgr.getSession(session.sessionId);
      assert.equal(state.results[0].responseTimeMs, null);
    });
  });

  describe("difficulty escalation", function () {
    it("increases difficulty after correct answer", function () {
      var mgr = createSessionManager({
        challengesPerSession: 5,
        baseDifficulty: 30,
        difficultyStep: 15,
      });
      var session = mgr.startSession();
      var r1 = mgr.submitResponse(session.sessionId, true);
      assert.equal(r1.nextDifficulty, 45); // 30 + 15
    });

    it("decreases difficulty after wrong answer (half step)", function () {
      var mgr = createSessionManager({
        challengesPerSession: 5,
        baseDifficulty: 30,
        difficultyStep: 14,
      });
      var session = mgr.startSession();
      mgr.submitResponse(session.sessionId, true); // 30 → 44
      var r2 = mgr.submitResponse(session.sessionId, false); // 44 → 37
      assert.equal(r2.nextDifficulty, 37); // 44 - 7
    });

    it("does not go below base difficulty", function () {
      var mgr = createSessionManager({
        challengesPerSession: 5,
        baseDifficulty: 30,
        difficultyStep: 20,
      });
      var session = mgr.startSession();
      var r1 = mgr.submitResponse(session.sessionId, false);
      assert.equal(r1.nextDifficulty, 30); // stays at base
    });

    it("caps at max difficulty", function () {
      var mgr = createSessionManager({
        challengesPerSession: 5,
        baseDifficulty: 80,
        difficultyStep: 20,
        maxDifficulty: 95,
      });
      var session = mgr.startSession();
      var r1 = mgr.submitResponse(session.sessionId, true); // 80 → 95 (capped)
      assert.equal(r1.nextDifficulty, 95);
    });

    it("does not escalate when disabled", function () {
      var mgr = createSessionManager({
        challengesPerSession: 5,
        baseDifficulty: 30,
        escalateDifficulty: false,
      });
      var session = mgr.startSession();
      var r1 = mgr.submitResponse(session.sessionId, true);
      assert.equal(r1.nextDifficulty, 30);
      var r2 = mgr.submitResponse(session.sessionId, true);
      assert.equal(r2.nextDifficulty, 30);
    });
  });

  describe("getSession", function () {
    it("returns null for unknown session", function () {
      var mgr = createSessionManager();
      assert.equal(mgr.getSession("nonexistent"), null);
    });

    it("returns full session state", function () {
      var mgr = createSessionManager({ challengesPerSession: 3 });
      var s = mgr.startSession({ userId: "u1" });
      mgr.submitResponse(s.sessionId, true, 1200);
      var state = mgr.getSession(s.sessionId);
      assert.equal(state.sessionId, s.sessionId);
      assert.equal(state.status, "active");
      assert.equal(state.challengeIndex, 1);
      assert.equal(state.totalChallenges, 3);
      assert.equal(state.correctCount, 1);
      assert.equal(state.avgResponseTimeMs, 1200);
      assert.equal(state.results.length, 1);
      assert.ok(state.remainingMs > 0);
      assert.ok(state.createdAt > 0);
    });

    it("computes average response time across responses", function () {
      var mgr = createSessionManager({ challengesPerSession: 3 });
      var s = mgr.startSession();
      mgr.submitResponse(s.sessionId, true, 1000);
      mgr.submitResponse(s.sessionId, true, 2000);
      var state = mgr.getSession(s.sessionId);
      assert.equal(state.avgResponseTimeMs, 1500);
    });

    it("returns results as a copy (not mutable reference)", function () {
      var mgr = createSessionManager({ challengesPerSession: 3 });
      var s = mgr.startSession();
      mgr.submitResponse(s.sessionId, true);
      var state1 = mgr.getSession(s.sessionId);
      state1.results.push({ fake: true });
      var state2 = mgr.getSession(s.sessionId);
      assert.equal(state2.results.length, 1); // original unchanged
    });
  });

  describe("invalidateSession", function () {
    it("cancels an active session", function () {
      var mgr = createSessionManager();
      var s = mgr.startSession();
      assert.equal(mgr.invalidateSession(s.sessionId), true);
      var state = mgr.getSession(s.sessionId);
      assert.equal(state.status, "cancelled");
    });

    it("returns false for unknown session", function () {
      var mgr = createSessionManager();
      assert.equal(mgr.invalidateSession("nonexistent"), false);
    });

    it("does not change already completed sessions", function () {
      var mgr = createSessionManager({ challengesPerSession: 1, passThreshold: 1 });
      var s = mgr.startSession();
      mgr.submitResponse(s.sessionId, true);
      mgr.invalidateSession(s.sessionId);
      var state = mgr.getSession(s.sessionId);
      assert.equal(state.status, "passed"); // stays passed
    });

    it("prevents further responses after cancellation", function () {
      var mgr = createSessionManager();
      var s = mgr.startSession();
      mgr.invalidateSession(s.sessionId);
      var result = mgr.submitResponse(s.sessionId, true);
      assert.equal(result.error, "session_cancelled");
    });
  });

  describe("session timeout", function () {
    it("expires session after timeout", function () {
      var mgr = createSessionManager({ sessionTimeoutMs: 1 });
      var s = mgr.startSession();
      // Session created with timeout=1ms — by the time we check, it's expired
      // Wait a tick to ensure expiry
      var start = Date.now();
      while (Date.now() - start < 5) { /* spin */ }
      var state = mgr.getSession(s.sessionId);
      assert.equal(state.status, "expired");
      assert.equal(state.remainingMs, 0);
    });

    it("submitResponse returns error for expired session", function () {
      var mgr = createSessionManager({ sessionTimeoutMs: 1 });
      var s = mgr.startSession();
      var start = Date.now();
      while (Date.now() - start < 5) { /* spin */ }
      var result = mgr.submitResponse(s.sessionId, true);
      assert.equal(result.error, "session_expired");
    });
  });

  describe("getStats", function () {
    it("returns zeros for empty manager", function () {
      var mgr = createSessionManager();
      var stats = mgr.getStats();
      assert.equal(stats.totalSessions, 0);
      assert.equal(stats.active, 0);
      assert.equal(stats.passed, 0);
      assert.equal(stats.failed, 0);
      assert.equal(stats.passRate, 0);
    });

    it("tracks session outcomes", function () {
      var mgr = createSessionManager({ challengesPerSession: 1, passThreshold: 1 });
      var s1 = mgr.startSession();
      mgr.submitResponse(s1.sessionId, true); // passed

      var s2 = mgr.startSession();
      mgr.submitResponse(s2.sessionId, false); // failed

      mgr.startSession(); // active

      var stats = mgr.getStats();
      assert.equal(stats.totalSessions, 3);
      assert.equal(stats.passed, 1);
      assert.equal(stats.failed, 1);
      assert.equal(stats.active, 1);
      assert.equal(stats.passRate, 0.5);
    });

    it("computes average response time across all sessions", function () {
      var mgr = createSessionManager({ challengesPerSession: 1, passThreshold: 1 });
      var s1 = mgr.startSession();
      mgr.submitResponse(s1.sessionId, true, 1000);
      var s2 = mgr.startSession();
      mgr.submitResponse(s2.sessionId, true, 3000);
      var stats = mgr.getStats();
      assert.equal(stats.avgResponseTimeMs, 2000);
    });

    it("tracks cancelled sessions", function () {
      var mgr = createSessionManager();
      var s = mgr.startSession();
      mgr.invalidateSession(s.sessionId);
      var stats = mgr.getStats();
      assert.equal(stats.cancelled, 1);
    });
  });

  describe("pass threshold edge cases", function () {
    it("threshold=0 always passes", function () {
      var mgr = createSessionManager({ challengesPerSession: 3, passThreshold: 0 });
      var s = mgr.startSession();
      mgr.submitResponse(s.sessionId, false);
      mgr.submitResponse(s.sessionId, false);
      var result = mgr.submitResponse(s.sessionId, false);
      assert.equal(result.passed, true);
    });

    it("threshold=1 requires all correct", function () {
      var mgr = createSessionManager({ challengesPerSession: 3, passThreshold: 1 });
      var s = mgr.startSession();
      mgr.submitResponse(s.sessionId, true);
      mgr.submitResponse(s.sessionId, true);
      var result = mgr.submitResponse(s.sessionId, false);
      assert.equal(result.passed, false);
    });

    it("threshold=1 passes with all correct", function () {
      var mgr = createSessionManager({ challengesPerSession: 2, passThreshold: 1 });
      var s = mgr.startSession();
      mgr.submitResponse(s.sessionId, true);
      var result = mgr.submitResponse(s.sessionId, true);
      assert.equal(result.passed, true);
    });
  });

  describe("single-challenge session", function () {
    it("completes in one response", function () {
      var mgr = createSessionManager({ challengesPerSession: 1 });
      var s = mgr.startSession();
      var result = mgr.submitResponse(s.sessionId, true);
      assert.equal(result.done, true);
      assert.equal(result.passed, true);
      assert.equal(result.totalAnswered, 1);
    });
  });

  describe("multi-challenge flow", function () {
    it("handles full 5-challenge session", function () {
      var mgr = createSessionManager({ challengesPerSession: 5, passThreshold: 0.6 });
      var s = mgr.startSession();
      // 3 correct, 2 wrong = 60% = pass
      mgr.submitResponse(s.sessionId, true);
      mgr.submitResponse(s.sessionId, false);
      mgr.submitResponse(s.sessionId, true);
      mgr.submitResponse(s.sessionId, false);
      var result = mgr.submitResponse(s.sessionId, true);
      assert.equal(result.done, true);
      assert.equal(result.passed, true);
      assert.equal(result.correctCount, 3);
      assert.equal(result.passRate, 0.6);
    });
  });

  describe("difficulty records in results", function () {
    it("records difficulty at time of each answer", function () {
      var mgr = createSessionManager({
        challengesPerSession: 3,
        baseDifficulty: 30,
        difficultyStep: 15,
      });
      var s = mgr.startSession();
      mgr.submitResponse(s.sessionId, true);  // difficulty 30
      mgr.submitResponse(s.sessionId, true);  // difficulty 45
      mgr.submitResponse(s.sessionId, true);  // difficulty 60
      var state = mgr.getSession(s.sessionId);
      assert.equal(state.results[0].difficulty, 30);
      assert.equal(state.results[1].difficulty, 45);
      assert.equal(state.results[2].difficulty, 60);
    });
  });
});
