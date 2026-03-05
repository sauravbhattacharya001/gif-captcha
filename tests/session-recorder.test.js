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

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

describe("createSessionRecorder", function () {

  // ── Basic creation ──

  it("should create a recorder with default options", function () {
    var rec = createSessionRecorder();
    assert.notStrictEqual(rec, undefined);
    assert.strictEqual(typeof rec.startSession, "function");
    assert.strictEqual(typeof rec.endSession, "function");
    assert.strictEqual(typeof rec.recordChallenge, "function");
    assert.strictEqual(typeof rec.getStats, "function");
    assert.strictEqual(Array.isArray(rec.EVENT_TYPES), true);
  });

  it("should expose all expected event types", function () {
    var rec = createSessionRecorder();
    assert.ok((rec.EVENT_TYPES.length) >= (14));
    assert.ok((rec.EVENT_TYPES).includes("session.start"));
    assert.ok((rec.EVENT_TYPES).includes("session.end"));
    assert.ok((rec.EVENT_TYPES).includes("answer.correct"));
    assert.ok((rec.EVENT_TYPES).includes("input.keystroke"));
  });

  // ── Session lifecycle ──

  it("should start a session and return an id", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession({ clientId: "c1" });
    assert.match(id, /^rec_/);
    var session = rec.getSession(id);
    assert.notStrictEqual(session, null);
    assert.strictEqual(session.status, "active");
    assert.strictEqual(session.metadata.clientId, "c1");
  });

  it("should auto-create session.start event", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    var session = rec.getSession(id);
    assert.strictEqual(session.events.length, 1);
    assert.strictEqual(session.events[0].type, "session.start");
    assert.strictEqual(session.events[0].seq, 0);
  });

  it("should end a session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.endSession(id, "completed");
    var session = rec.getSession(id);
    assert.strictEqual(session.status, "completed");
    assert.notStrictEqual(session.endedAt, undefined);
    assert.ok((session.duration) >= (0));
    var lastEvent = session.events[session.events.length - 1];
    assert.strictEqual(lastEvent.type, "session.end");
  });

  it("should not end an already-ended session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.endSession(id);
    var session = rec.getSession(id);
    var evCount = session.events.length;
    rec.endSession(id);
    assert.strictEqual(session.events.length, evCount);
  });

  it("should fire onSessionEnd callback", function () {
    var captured = null;
    var rec = createSessionRecorder({ onSessionEnd: function (s) { captured = s; } });
    var id = rec.startSession();
    rec.endSession(id);
    assert.notStrictEqual(captured, null);
    assert.strictEqual(captured.id, id);
  });

  // ── Event recording ──

  it("should record challenges", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, { type: "gif", difficulty: "hard" });
    var session = rec.getSession(id);
    assert.strictEqual(session.challengeCount, 1);
    assert.strictEqual(session.events[1].type, "challenge.served");
    assert.strictEqual(session.events[1].data.difficulty, "hard");
  });

  it("should record user input", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordInput(id, "keystroke", { key: "a" });
    rec.recordInput(id, "click", { x: 10, y: 20 });
    var session = rec.getSession(id);
    assert.strictEqual(session.inputCount, 2);
    assert.strictEqual(session.events[1].type, "input.keystroke");
    assert.strictEqual(session.events[2].type, "input.click");
  });

  it("should skip input recording when captureInputs is false", function () {
    var rec = createSessionRecorder({ captureInputs: false });
    var id = rec.startSession();
    rec.recordInput(id, "keystroke", { key: "a" });
    var session = rec.getSession(id);
    assert.strictEqual(session.inputCount, 0);
    assert.strictEqual(session.events.length, 1); // only session.start
  });

  it("should record submissions", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordSubmission(id, { answer: "cat" });
    var session = rec.getSession(id);
    assert.strictEqual(session.events[1].type, "answer.submitted");
    assert.strictEqual(session.events[1].data.answer, "cat");
  });

  it("should record correct result", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordResult(id, true, { score: 100 });
    var session = rec.getSession(id);
    assert.strictEqual(session.outcome, "correct");
    assert.strictEqual(session.events[1].type, "answer.correct");
  });

  it("should record incorrect result", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordResult(id, false);
    var session = rec.getSession(id);
    assert.strictEqual(session.outcome, "incorrect");
    assert.strictEqual(session.events[1].type, "answer.incorrect");
  });

  it("should record skip", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordSkip(id);
    var session = rec.getSession(id);
    assert.strictEqual(session.outcome, "skipped");
    assert.strictEqual(session.events[1].type, "challenge.skipped");
  });

  it("should record refresh", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordRefresh(id, { reason: "too hard" });
    var session = rec.getSession(id);
    assert.strictEqual(session.events[1].type, "challenge.refreshed");
  });

  it("should record errors", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordError(id, "Network timeout");
    var session = rec.getSession(id);
    assert.strictEqual(session.events[1].type, "error");
    assert.strictEqual(session.events[1].data.message, "Network timeout");
  });

  it("should record custom events", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordCustom(id, { action: "scroll", distance: 200 });
    var session = rec.getSession(id);
    assert.strictEqual(session.events[1].type, "custom");
    assert.strictEqual(session.events[1].data.action, "scroll");
  });

  it("should not record events on ended sessions", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.endSession(id);
    var evCount = rec.getSession(id).events.length;
    rec.recordChallenge(id, {});
    assert.strictEqual(rec.getSession(id).events.length, evCount);
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
    assert.ok((session.tags).includes("qa"));
    assert.ok((session.tags).includes("v2"));
  });

  it("should add tags to a session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.addTags(id, ["regression", "mobile"]);
    var session = rec.getSession(id);
    assert.ok((session.tags).includes("regression"));
    assert.ok((session.tags).includes("mobile"));
  });

  it("should not duplicate tags", function () {
    var rec = createSessionRecorder({ tags: ["qa"] });
    var id = rec.startSession();
    rec.addTags(id, ["qa", "new"]);
    var session = rec.getSession(id);
    var qaCount = session.tags.filter(function (t) { return t === "qa"; }).length;
    assert.strictEqual(qaCount, 1);
  });

  // ── Query ──

  it("should query sessions by status", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    var id2 = rec.startSession();
    rec.endSession(id1, "completed");
    assert.strictEqual(rec.querySessions({ status: "completed" }).length, 1);
    assert.strictEqual(rec.querySessions({ status: "active" }).length, 1);
  });

  it("should query sessions by outcome", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordResult(id1, true);
    var id2 = rec.startSession();
    rec.recordResult(id2, false);
    assert.strictEqual(rec.querySessions({ outcome: "correct" }).length, 1);
    assert.strictEqual(rec.querySessions({ outcome: "incorrect" }).length, 1);
  });

  it("should query sessions by tag", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.addTags(id1, ["mobile"]);
    rec.startSession();
    assert.strictEqual(rec.querySessions({ tag: "mobile" }).length, 1);
  });

  it("should query sessions by clientId", function () {
    var rec = createSessionRecorder();
    rec.startSession({ clientId: "user1" });
    rec.startSession({ clientId: "user2" });
    assert.strictEqual(rec.querySessions({ clientId: "user1" }).length, 1);
  });

  it("should respect query limit", function () {
    var rec = createSessionRecorder();
    for (var i = 0; i < 10; i++) rec.startSession();
    assert.strictEqual(rec.querySessions({ limit: 3 }).length, 3);
  });

  it("should query by minEvents", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordChallenge(id1, {});
    rec.recordChallenge(id1, {});
    rec.startSession(); // only 1 event (session.start)
    assert.strictEqual(rec.querySessions({ minEvents: 3 }).length, 1);
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
    assert.notStrictEqual(replay, null);
    assert.strictEqual(replay.progress().total, 5);
    assert.strictEqual(replay.progress().percent, 0);
  });

  it("should step through events with next()", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    rec.endSession(id);

    var replay = rec.createReplay(id);
    var e1 = replay.next();
    assert.strictEqual(e1.type, "session.start");
    var e2 = replay.next();
    assert.strictEqual(e2.type, "challenge.served");
    var e3 = replay.next();
    assert.strictEqual(e3.type, "session.end");
    assert.strictEqual(replay.next(), null);
  });

  it("should peek without advancing", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    var replay = rec.createReplay(id);
    var p1 = replay.peek();
    var p2 = replay.peek();
    assert.strictEqual(p1, p2);
    assert.strictEqual(replay.progress().current, 0);
  });

  it("should reset replay to beginning", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    var replay = rec.createReplay(id);
    replay.next();
    replay.next();
    replay.reset();
    assert.strictEqual(replay.progress().current, 0);
    assert.strictEqual(replay.next().type, "session.start");
  });

  it("should jump to specific step", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    rec.recordSubmission(id, {});
    var replay = rec.createReplay(id);
    replay.jumpTo(2);
    assert.strictEqual(replay.next().type, "answer.submitted");
  });

  it("should get remaining events", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    rec.endSession(id);
    var replay = rec.createReplay(id);
    replay.next(); // skip session.start
    var remaining = replay.remaining();
    assert.strictEqual(remaining.length, 2);
    assert.strictEqual(remaining[0].type, "challenge.served");
  });

  it("should return null for non-existent session replay", function () {
    var rec = createSessionRecorder();
    assert.strictEqual(rec.createReplay("fake"), null);
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
    assert.notStrictEqual(cmp, null);
    assert.strictEqual(cmp.sessionA.id, id1);
    assert.strictEqual(cmp.sessionB.id, id2);
    assert.strictEqual(cmp.sameOutcome, false);
    assert.ok((cmp.eventDiffs.length) > (0));
  });

  it("should return null when comparing with non-existent session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    assert.strictEqual(rec.compareSessions(id, "fake"), null);
    assert.strictEqual(rec.compareSessions("fake", id), null);
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
    assert.strictEqual(analytics.totalSessions, 2);
    assert.strictEqual(analytics.outcomes.correct, 1);
    assert.strictEqual(analytics.outcomes.incorrect, 1);
    assert.strictEqual(analytics.successRate, 50);
    assert.strictEqual(analytics.avgChallenges, 1);
  });

  it("should compute analytics for empty state", function () {
    var rec = createSessionRecorder();
    var analytics = rec.getAnalytics();
    assert.strictEqual(analytics.totalSessions, 0);
    assert.strictEqual(analytics.avgDuration, 0);
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
    assert.strictEqual(analytics.totalSessions, 1);
    assert.strictEqual(analytics.successRate, 100);
  });

  // ── Merged timeline ──

  it("should merge timelines from multiple sessions", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordChallenge(id1, {});
    var id2 = rec.startSession();
    rec.recordChallenge(id2, {});

    var timeline = rec.mergedTimeline([id1, id2]);
    assert.strictEqual(timeline.length, 4);
    // Should be sorted by timestamp
    for (var i = 1; i < timeline.length; i++) {
      assert.ok((timeline[i].event.timestamp) >= (timeline[i - 1].event.timestamp));
    }
  });

  it("should limit merged timeline", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession();
    rec.recordChallenge(id1, {});
    rec.recordChallenge(id1, {});
    var timeline = rec.mergedTimeline([id1], 2);
    assert.strictEqual(timeline.length, 2);
  });

  // ── LRU eviction ──

  it("should evict oldest sessions when maxSessions reached", function () {
    var rec = createSessionRecorder({ maxSessions: 3 });
    var id1 = rec.startSession();
    rec.startSession();
    rec.startSession();
    rec.startSession(); // should evict id1
    assert.strictEqual(rec.getSession(id1), null);
    assert.strictEqual(rec.getStats().totalEvicted, 1);
  });

  // ── Delete ──

  it("should delete a session", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    assert.strictEqual(rec.deleteSession(id), true);
    assert.strictEqual(rec.getSession(id), null);
    assert.strictEqual(rec.deleteSession(id), false);
  });

  // ── Export / Import ──

  it("should export and import state", function () {
    var rec = createSessionRecorder();
    var id1 = rec.startSession({ clientId: "c1" });
    rec.recordChallenge(id1, { type: "gif" });
    rec.recordResult(id1, true);
    rec.endSession(id1);

    var state = rec.exportState();
    assert.strictEqual(state.sessions.length, 1);
    assert.strictEqual(state.totalRecorded, 1);

    var rec2 = createSessionRecorder();
    rec2.importState(state);
    var session = rec2.getSession(id1);
    assert.notStrictEqual(session, null);
    assert.strictEqual(session.outcome, "correct");
    assert.strictEqual(session.events.length, 4);
  });

  it("should respect maxSessions on import", function () {
    var rec = createSessionRecorder();
    for (var i = 0; i < 10; i++) rec.startSession();
    var state = rec.exportState();

    var rec2 = createSessionRecorder({ maxSessions: 5 });
    rec2.importState(state);
    assert.strictEqual(rec2.getStats().activeSessions, 5);
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
    assert.strictEqual(stats.activeSessions, 2);
    assert.strictEqual(stats.totalRecorded, 2);
    assert.strictEqual(stats.maxSessions, 500);
    assert.strictEqual(stats.sessionTimeoutMs, 60000);
    assert.strictEqual(stats.captureInputs, true);
  });

  // ── Reset ──

  it("should reset all state", function () {
    var rec = createSessionRecorder();
    rec.startSession();
    rec.startSession();
    rec.reset();
    assert.strictEqual(rec.getStats().activeSessions, 0);
    assert.strictEqual(rec.getStats().totalRecorded, 0);
    assert.strictEqual(rec.querySessions().length, 0);
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
    assert.strictEqual(session.status, "completed");
    assert.strictEqual(session.outcome, "correct");
    assert.strictEqual(session.challengeCount, 1);
    assert.strictEqual(session.inputCount, 4);
    assert.ok((session.tags).includes("production"));
    assert.strictEqual(session.events.length, 9);

    // Replay
    var replay = rec.createReplay(id);
    var types = [];
    var ev;
    while ((ev = replay.next()) !== null) types.push(ev.type);
    assert.deepStrictEqual(types, [
      "session.start", "challenge.served", "input.focus",
      "input.keystroke", "input.keystroke", "input.keystroke",
      "answer.submitted", "answer.correct", "session.end"
    ]);

    // Analytics
    var analytics = rec.getAnalytics();
    assert.strictEqual(analytics.totalSessions, 1);
    assert.strictEqual(analytics.successRate, 100);
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
    assert.strictEqual(session.challengeCount, 2);
    assert.strictEqual(session.outcome, "correct");
  });

  // ── Event elapsed times ──

  it("should track elapsed time in events", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordChallenge(id, {});
    var session = rec.getSession(id);
    assert.ok((session.events[1].elapsed) >= (0));
    assert.strictEqual(typeof session.events[1].timestamp, "number");
  });

  // ── Input type fallback ──

  it("should use custom type for unknown input types", function () {
    var rec = createSessionRecorder();
    var id = rec.startSession();
    rec.recordInput(id, "swipe", { direction: "left" });
    var session = rec.getSession(id);
    assert.strictEqual(session.events[1].type, "custom");
  });

  // ── Multiple unique IDs ──

  it("should generate unique session IDs", function () {
    var rec = createSessionRecorder();
    var ids = new Set();
    for (var i = 0; i < 50; i++) ids.add(rec.startSession());
    assert.strictEqual(ids.size, 50);
  });
});
