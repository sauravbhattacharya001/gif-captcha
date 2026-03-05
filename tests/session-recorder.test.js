/**
 * Tests for createSessionRecorder
 */
"use strict";

var gifCaptcha;
try {
  gifCaptcha = require("../src/index");
} catch (e) {
  gifCaptcha = require("../src/index.js");
}

var createSessionRecorder = gifCaptcha.createSessionRecorder;

describe("createSessionRecorder", function () {

  // ── Basic creation ──

  it("should create a recorder with default options", function () {
    var rec = createSessionRecorder();
    expect(rec).toBeDefined();
    expect(typeof rec.startSession).toBe("function");
    expect(typeof rec.endSession).toBe("function");
    expect(typeof rec.recordChallenge).toBe("function");
    expect(typeof rec.getStats).toBe("function");
    expect(Array.isArray(rec.EVENT_TYPES)).toBe(true);
  });

  it("should expose all expected event types", function () {
    var rec = createSessionRecorder();
    expect(rec.EVENT_TYPES.length).toBeGreaterThanOrEqual(14);
    expect(rec.EVENT_TYPES).toContain("session.start");
    expect(rec.EVENT_TYPES).toContain("session.end");
    expect(rec.EVENT_TYPES).toContain("answer.correct");
    expect(rec.EVENT_TYPES).toContain("input.keystroke");
  });

  // ── Session lifecycle ──

  it("should start a session and return an id", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession({ clientId: "c1" });
    expect(id).toMatch(/^rec_/);
    var session = rec.getSession(id);
    expect(session).not.toBeNull();
    expect(session.status).toBe("active");
    expect(session.metadata.clientId).toBe("c1");
  });

  it("should auto-create session.start event", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    var session = rec.getSession(id);
    expect(session.events.length).toBe(1);
    expect(session.events[0].type).toBe("session.start");
    expect(session.events[0].seq).toBe(0);
  });

  it("should end a session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.endSession(id, "completed");
    var session = rec.getSession(id);
    expect(session.status).toBe("completed");
    expect(session.endedAt).toBeDefined();
    expect(session.duration).toBeGreaterThanOrEqual(0);
    var lastEvent = session.events[session.events.length - 1];
    expect(lastEvent.type).toBe("session.end");
  });

  it("should not end an already-ended session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.endSession(id);
    var session = rec.getSession(id);
    var evCount = session.events.length;
    rec.endSession(id);
    expect(session.events.length).toBe(evCount);
  });

  it("should fire onSessionEnd callback", function () {
    var captured = null;
    var rec = createSessionRecorder({ onSessionEnd: function (s) { captured = s; } });
    var id = rec.startSession();
    rec.endSession(id);
    expect(captured).not.toBeNull();
    expect(captured.id).toBe(id);
  });

  // ── Event recording ──

  it("should record challenges", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, { type: "gif", difficulty: "hard" });
    var session = rec.getSession(id);
    expect(session.challengeCount).toBe(1);
    expect(session.events[1].type).toBe("challenge.served");
    expect(session.events[1].data.difficulty).toBe("hard");
  });

  it("should record user input", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordInput(id, "keystroke", { key: "a" });
    rec.recordInput(id, "click", { x: 10, y: 20 });
    var session = rec.getSession(id);
    expect(session.inputCount).toBe(2);
    expect(session.events[1].type).toBe("input.keystroke");
    expect(session.events[2].type).toBe("input.click");
  });

  it("should skip input recording when captureInputs is false", function () {
    var rec = createSessionRecorder({ captureInputs: false });
    var id = rec.startSession();
    rec.recordInput(id, "keystroke", { key: "a" });
    var session = rec.getSession(id);
    expect(session.inputCount).toBe(0);
    expect(session.events.length).toBe(1); // only session.start
  });

  it("should record submissions", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordSubmission(id, { answer: "cat" });
    var session = rec.getSession(id);
    expect(session.events[1].type).toBe("answer.submitted");
    expect(session.events[1].data.answer).toBe("cat");
  });

  it("should record correct result", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordResult(id, true, { score: 100 });
    var session = rec.getSession(id);
    expect(session.outcome).toBe("correct");
    expect(session.events[1].type).toBe("answer.correct");
  });

  it("should record incorrect result", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordResult(id, false);
    var session = rec.getSession(id);
    expect(session.outcome).toBe("incorrect");
    expect(session.events[1].type).toBe("answer.incorrect");
  });

  it("should record skip", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordSkip(id);
    var session = rec.getSession(id);
    expect(session.outcome).toBe("skipped");
    expect(session.events[1].type).toBe("challenge.skipped");
  });

  it("should record refresh", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordRefresh(id, { reason: "too hard" });
    var session = rec.getSession(id);
    expect(session.events[1].type).toBe("challenge.refreshed");
  });

  it("should record errors", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordError(id, "Network timeout");
    var session = rec.getSession(id);
    expect(session.events[1].type).toBe("error");
    expect(session.events[1].data.message).toBe("Network timeout");
  });

  it("should record custom events", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordCustom(id, { action: "scroll", distance: 200 });
    var session = rec.getSession(id);
    expect(session.events[1].type).toBe("custom");
    expect(session.events[1].data.action).toBe("scroll");
  });

  it("should not record events on ended sessions", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.endSession(id);
    var evCount = rec.getSession(id).events.length;
    rec.recordChallenge(id, {});
    expect(rec.getSession(id).events.length).toBe(evCount);
  });

  it("should not record events on non-existent sessions", function () {
    var rec = createSessionRecorder();
    // Should not throw
    rec.recordChallenge("fake_id", {});
    rec.recordInput("fake_id", "click");
    rec.recordResult("fake_id", true);
  });

  // ── Tags ──

  it("should apply default tags", function () {
    var rec = createSessionRecorder({ tags: ["qa", "v2"] });
    var id = rec.startSession();
    var session = rec.getSession(id);
    expect(session.tags).toContain("qa");
    expect(session.tags).toContain("v2");
  });

  it("should add tags to a session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.addTags(id, ["regression", "mobile"]);
    var session = rec.getSession(id);
    expect(session.tags).toContain("regression");
    expect(session.tags).toContain("mobile");
  });

  it("should not duplicate tags", function () {
    var rec = createSessionRecorder({ tags: ["qa"] });
    var id = rec.startSession();
    rec.addTags(id, ["qa", "new"]);
    var session = rec.getSession(id);
    var qaCount = session.tags.filter(function (t) { return t === "qa"; }).length;
    expect(qaCount).toBe(1);
  });

  // ── Query ──

  it("should query sessions by status", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    var id2 = rec.startSession();
    rec.endSession(id1, "completed");
    expect(rec.querySessions({ status: "completed" }).length).toBe(1);
    expect(rec.querySessions({ status: "active" }).length).toBe(1);
  });

  it("should query sessions by outcome", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordResult(id1, true);
    var id2 = rec.startSession();
    rec.recordResult(id2, false);
    expect(rec.querySessions({ outcome: "correct" }).length).toBe(1);
    expect(rec.querySessions({ outcome: "incorrect" }).length).toBe(1);
  });

  it("should query sessions by tag", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.addTags(id1, ["mobile"]);
    rec.startSession();
    expect(rec.querySessions({ tag: "mobile" }).length).toBe(1);
  });

  it("should query sessions by clientId", function () {
    var rec = createSessionRecorder();
    rec.startSession({ clientId: "user1" });
    rec.startSession({ clientId: "user2" });
    expect(rec.querySessions({ clientId: "user1" }).length).toBe(1);
  });

  it("should respect query limit", function () {
    var rec = createSessionRecorder();
    for (var i = 0; i < 10; i++) rec.startSession();
    expect(rec.querySessions({ limit: 3 }).length).toBe(3);
  });

  it("should query by minEvents", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordChallenge(id1, {});
    rec.recordChallenge(id1, {});
    rec.startSession(); // only 1 event (session.start)
    expect(rec.querySessions({ minEvents: 3 }).length).toBe(1);
  });

  // ── Replay ──

  it("should create a replay iterator", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    rec.recordSubmission(id, { answer: "x" });
    rec.recordResult(id, true);
    rec.endSession(id);

    var replay = rec.createReplay(id);
    expect(replay).not.toBeNull();
    expect(replay.progress().total).toBe(5);
    expect(replay.progress().percent).toBe(0);
  });

  it("should step through events with next()", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    rec.endSession(id);

    var replay = rec.createReplay(id);
    var e1 = replay.next();
    expect(e1.type).toBe("session.start");
    var e2 = replay.next();
    expect(e2.type).toBe("challenge.served");
    var e3 = replay.next();
    expect(e3.type).toBe("session.end");
    expect(replay.next()).toBeNull();
  });

  it("should peek without advancing", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    var replay = rec.createReplay(id);
    var p1 = replay.peek();
    var p2 = replay.peek();
    expect(p1).toBe(p2);
    expect(replay.progress().current).toBe(0);
  });

  it("should reset replay to beginning", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    var replay = rec.createReplay(id);
    replay.next();
    replay.next();
    replay.reset();
    expect(replay.progress().current).toBe(0);
    expect(replay.next().type).toBe("session.start");
  });

  it("should jump to specific step", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    rec.recordSubmission(id, {});
    var replay = rec.createReplay(id);
    replay.jumpTo(2);
    expect(replay.next().type).toBe("answer.submitted");
  });

  it("should get remaining events", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    rec.endSession(id);
    var replay = rec.createReplay(id);
    replay.next(); // skip session.start
    var remaining = replay.remaining();
    expect(remaining.length).toBe(2);
    expect(remaining[0].type).toBe("challenge.served");
  });

  it("should return null for non-existent session replay", function () {
    var rec = createSessionRecorder();
    expect(rec.createReplay("fake")).toBeNull();
  });

  // ── Compare ──

  it("should compare two sessions", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordChallenge(id1, {});
    rec.recordResult(id1, true);
    rec.endSession(id1);

    var id2 = rec.startSession();
    rec.recordChallenge(id2, {});
    rec.recordChallenge(id2, {});
    rec.recordResult(id2, false);
    rec.endSession(id2);

    var cmp = rec.compareSessions(id1, id2);
    expect(cmp).not.toBeNull();
    expect(cmp.sessionA.id).toBe(id1);
    expect(cmp.sessionB.id).toBe(id2);
    expect(cmp.sameOutcome).toBe(false);
    expect(cmp.eventDiffs.length).toBeGreaterThan(0);
  });

  it("should return null when comparing with non-existent session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    expect(rec.compareSessions(id, "fake")).toBeNull();
    expect(rec.compareSessions("fake", id)).toBeNull();
  });

  // ── Analytics ──

  it("should compute analytics across sessions", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordChallenge(id1, {});
    rec.recordResult(id1, true);
    rec.endSession(id1);

    var id2 = rec.startSession();
    rec.recordChallenge(id2, {});
    rec.recordResult(id2, false);
    rec.endSession(id2);

    var analytics = rec.getAnalytics();
    expect(analytics.totalSessions).toBe(2);
    expect(analytics.outcomes.correct).toBe(1);
    expect(analytics.outcomes.incorrect).toBe(1);
    expect(analytics.successRate).toBe(50);
    expect(analytics.avgChallenges).toBe(1);
  });

  it("should compute analytics for empty state", function () {
    var rec = createSessionRecorder();
    var analytics = rec.getAnalytics();
    expect(analytics.totalSessions).toBe(0);
    expect(analytics.avgDuration).toBe(0);
  });

  it("should compute analytics with filters", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession({ clientId: "a" });
    rec.recordResult(id1, true);
    rec.endSession(id1);

    var id2 = rec.startSession({ clientId: "b" });
    rec.recordResult(id2, false);
    rec.endSession(id2);

    var analytics = rec.getAnalytics({ clientId: "a" });
    expect(analytics.totalSessions).toBe(1);
    expect(analytics.successRate).toBe(100);
  });

  // ── Merged timeline ──

  it("should merge timelines from multiple sessions", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordChallenge(id1, {});
    var id2 = rec.startSession();
    rec.recordChallenge(id2, {});

    var timeline = rec.mergedTimeline([id1, id2]);
    expect(timeline.length).toBe(4);
    // Should be sorted by timestamp
    for (var i = 1; i < timeline.length; i++) {
      expect(timeline[i].event.timestamp).toBeGreaterThanOrEqual(timeline[i - 1].event.timestamp);
    }
  });

  it("should limit merged timeline", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordChallenge(id1, {});
    rec.recordChallenge(id1, {});
    var timeline = rec.mergedTimeline([id1], 2);
    expect(timeline.length).toBe(2);
  });

  // ── LRU eviction ──

  it("should evict oldest sessions when maxSessions reached", function () {
    var rec = createSessionRecorder({ maxSessions: 3 });
    var id1 = rec.startSession();
    rec.startSession();
    rec.startSession();
    rec.startSession(); // should evict id1
    expect(rec.getSession(id1)).toBeNull();
    expect(rec.getStats().totalEvicted).toBe(1);
  });

  // ── Delete ──

  it("should delete a session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    expect(rec.deleteSession(id)).toBe(true);
    expect(rec.getSession(id)).toBeNull();
    expect(rec.deleteSession(id)).toBe(false);
  });

  // ── Export / Import ──

  it("should export and import state", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession({ clientId: "c1" });
    rec.recordChallenge(id1, { type: "gif" });
    rec.recordResult(id1, true);
    rec.endSession(id1);

    var state = rec.exportState();
    expect(state.sessions.length).toBe(1);
    expect(state.totalRecorded).toBe(1);

    var rec2 = createSessionRecorder();
    rec2.importState(state);
    var session = rec2.getSession(id1);
    expect(session).not.toBeNull();
    expect(session.outcome).toBe("correct");
    expect(session.events.length).toBe(4);
  });

  it("should respect maxSessions on import", function () {
    var rec = createSessionRecorder();
    for (var i = 0; i < 10; i++) rec.startSession();
    var state = rec.exportState();

    var rec2 = createSessionRecorder({ maxSessions: 5 });
    rec2.importState(state);
    expect(rec2.getStats().activeSessions).toBe(5);
  });

  it("should handle invalid import gracefully", function () {
    var rec = createSessionRecorder();
    rec.startSession();
    rec.importState(null);
    rec.importState({});
    rec.importState({ sessions: "bad" });
    // Should not throw
  });

  // ── Stats ──

  it("should report stats", function () {
    var rec = createSessionRecorder({ maxSessions: 500, sessionTimeoutMs: 60000 });
    rec.startSession();
    rec.startSession();
    var stats = rec.getStats();
    expect(stats.activeSessions).toBe(2);
    expect(stats.totalRecorded).toBe(2);
    expect(stats.maxSessions).toBe(500);
    expect(stats.sessionTimeoutMs).toBe(60000);
    expect(stats.captureInputs).toBe(true);
  });

  // ── Reset ──

  it("should reset all state", function () {
    var rec = createSessionRecorder();
    rec.startSession();
    rec.startSession();
    rec.reset();
    expect(rec.getStats().activeSessions).toBe(0);
    expect(rec.getStats().totalRecorded).toBe(0);
    expect(rec.querySessions().length).toBe(0);
  });

  // ── Full workflow ──

  it("should handle a complete CAPTCHA session workflow", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession({ clientId: "user123", userAgent: "Chrome" });
    rec.addTags(id, ["production", "desktop"]);
    rec.recordChallenge(id, { type: "gif", difficulty: "medium", challengeId: "ch1" });
    rec.recordInput(id, "focus");
    rec.recordInput(id, "keystroke", { key: "d" });
    rec.recordInput(id, "keystroke", { key: "o" });
    rec.recordInput(id, "keystroke", { key: "g" });
    rec.recordSubmission(id, { answer: "dog", challengeId: "ch1" });
    rec.recordResult(id, true, { confidence: 0.95 });
    rec.endSession(id, "completed");

    var session = rec.getSession(id);
    expect(session.status).toBe("completed");
    expect(session.outcome).toBe("correct");
    expect(session.challengeCount).toBe(1);
    expect(session.inputCount).toBe(4);
    expect(session.tags).toContain("production");
    expect(session.events.length).toBe(9);

    // Replay
    var replay = rec.createReplay(id);
    var types = [];
    var ev;
    while ((ev = replay.next()) !== null) types.push(ev.type);
    expect(types).toEqual([
      "session.start", "challenge.served", "input.focus",
      "input.keystroke", "input.keystroke", "input.keystroke",
      "answer.submitted", "answer.correct", "session.end"
    ]);

    // Analytics
    var analytics = rec.getAnalytics();
    expect(analytics.totalSessions).toBe(1);
    expect(analytics.successRate).toBe(100);
  });

  it("should handle multi-challenge session with refresh", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, { id: "ch1" });
    rec.recordRefresh(id, { reason: "too hard" });
    rec.recordChallenge(id, { id: "ch2" });
    rec.recordSubmission(id, { answer: "cat" });
    rec.recordResult(id, true);
    rec.endSession(id);

    var session = rec.getSession(id);
    expect(session.challengeCount).toBe(2);
    expect(session.outcome).toBe("correct");
  });

  // ── Event elapsed times ──

  it("should track elapsed time in events", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    var session = rec.getSession(id);
    expect(session.events[1].elapsed).toBeGreaterThanOrEqual(0);
    expect(typeof session.events[1].timestamp).toBe("number");
  });

  // ── Input type fallback ──

  it("should use custom type for unknown input types", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordInput(id, "swipe", { direction: "left" });
    var session = rec.getSession(id);
    expect(session.events[1].type).toBe("custom");
  });

  // ── Multiple unique IDs ──

  it("should generate unique session IDs", function () {
    var rec = createSessionRecorder();
    var ids = new Set();
    for (var i = 0; i < 50; i++) ids.add(rec.startSession());
    expect(ids.size).toBe(50);
  });
});
