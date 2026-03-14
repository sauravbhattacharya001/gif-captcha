/**
 * Tests for captcha-session-replay.js
 */

"use strict";

const { createSessionReplay } = require("../src/captcha-session-replay");

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL:", msg);
    failed++;
  } else {
    passed++;
  }
}

function assertThrows(fn, msg) {
  try { fn(); assert(false, msg + " (should throw)"); }
  catch (_) { passed++; }
}

// ── Basic session lifecycle ─────────────────────────────────────────

(function testStartAndEnd() {
  const r = createSessionReplay();
  const id = r.startSession({ challengeType: "sequence", userId: "u1" });
  assert(typeof id === "string", "startSession returns string ID");

  const s = r.getSession(id);
  assert(s.status === "recording", "status is recording");
  assert(s.metadata.challengeType === "sequence", "metadata stored");
  assert(s.events.length === 0, "no events yet");

  r.endSession(id, { solved: true });
  const s2 = r.getSession(id);
  assert(s2.status === "completed", "status is completed");
  assert(s2.result.solved === true, "result stored");
  assert(s2.endedAt >= s2.startedAt, "endedAt set");
})();

// ── Record events ───────────────────────────────────────────────────

(function testRecordEvents() {
  const r = createSessionReplay();
  const id = r.startSession();

  const e1 = r.recordEvent(id, "mouse_move", { x: 10, y: 20 });
  assert(e1.seq === 0, "first event seq=0");
  assert(e1.type === "mouse_move", "event type stored");
  assert(e1.data.x === 10, "event data stored");
  assert(typeof e1.timestamp === "number", "timestamp recorded");

  r.recordEvent(id, "click", { x: 15, y: 25 });
  r.recordEvent(id, "solve_attempt", { answer: "A", correct: true });

  const s = r.getSession(id);
  assert(s.events.length === 3, "3 events recorded");
})();

// ── Invalid event type ──────────────────────────────────────────────

(function testInvalidEventType() {
  const r = createSessionReplay();
  const id = r.startSession();
  assertThrows(function() { r.recordEvent(id, "invalid_type", {}); },
    "invalid event type");
})();

// ── Cannot record after end ─────────────────────────────────────────

(function testNoRecordAfterEnd() {
  const r = createSessionReplay();
  const id = r.startSession();
  r.endSession(id);
  assertThrows(function() { r.recordEvent(id, "click", {}); },
    "record after end");
})();

// ── Abandon session ─────────────────────────────────────────────────

(function testAbandon() {
  const r = createSessionReplay();
  const id = r.startSession();
  r.recordEvent(id, "mouse_move", { x: 0, y: 0 });
  r.abandonSession(id);
  const s = r.getSession(id);
  assert(s.status === "abandoned", "abandoned status");
})();

// ── Session stats ───────────────────────────────────────────────────

(function testSessionStats() {
  const r = createSessionReplay();
  const id = r.startSession({ challengeType: "pattern" });
  r.recordEvent(id, "mouse_move", { x: 1, y: 1 });
  r.recordEvent(id, "click", { x: 2, y: 2 });
  r.recordEvent(id, "solve_attempt", { correct: true });
  r.recordEvent(id, "solve_attempt", { correct: false });
  r.recordEvent(id, "double_click", { x: 3, y: 3 });
  r.endSession(id, { solved: true });

  const st = r.sessionStats(id);
  assert(st.totalEvents === 5, "total events");
  assert(st.clicks === 2, "clicks (click + double_click)");
  assert(st.mouseMoves === 1, "mouse moves");
  assert(st.solveAttempts === 2, "solve attempts");
  assert(st.correctAttempts === 1, "correct attempts");
  assert(st.accuracy === 0.5, "accuracy 50%");
  assert(st.durationMs >= 0, "duration >= 0");
})();

// ── List sessions with filters ──────────────────────────────────────

(function testListSessions() {
  const r = createSessionReplay();
  const id1 = r.startSession({ challengeType: "sequence" });
  r.recordEvent(id1, "click", {});
  r.recordEvent(id1, "click", {});
  r.endSession(id1);

  const id2 = r.startSession({ challengeType: "pattern" });
  r.recordEvent(id2, "click", {});
  r.abandonSession(id2);

  const id3 = r.startSession({ challengeType: "sequence" });

  const all = r.listSessions();
  assert(all.length === 3, "3 total sessions");

  const completed = r.listSessions({ status: "completed" });
  assert(completed.length === 1, "1 completed");

  const seqOnly = r.listSessions({ challengeType: "sequence" });
  assert(seqOnly.length === 2, "2 sequence sessions");

  const minEvents = r.listSessions({ minEvents: 2 });
  assert(minEvents.length === 1, "1 session with >= 2 events");
})();

// ── Playback ────────────────────────────────────────────────────────

(function testPlayback() {
  const r = createSessionReplay();
  const id = r.startSession();
  r.recordEvent(id, "mouse_move", { x: 0 });
  r.recordEvent(id, "click", { x: 1 });
  r.recordEvent(id, "mouse_move", { x: 2 });
  r.recordEvent(id, "solve_attempt", { correct: true });
  r.endSession(id);

  const pb = r.createPlayback(id, { speed: 2.0 });
  assert(pb.total() === 4, "playback total");
  assert(pb.position() === 0, "starts at 0");
  assert(!pb.done(), "not done");

  const e1 = pb.next();
  assert(e1.type === "mouse_move", "first event");
  assert(pb.position() === 1, "position advanced");

  pb.next(); pb.next(); pb.next();
  assert(pb.done(), "done after all events");
  assert(pb.next() === null, "null after done");

  pb.reset();
  assert(pb.position() === 0, "reset works");
  assert(pb.speed() === 2.0, "speed preserved");
})();

// ── Playback with filter ────────────────────────────────────────────

(function testPlaybackFilter() {
  const r = createSessionReplay();
  const id = r.startSession();
  r.recordEvent(id, "mouse_move", { x: 0 });
  r.recordEvent(id, "click", { x: 1 });
  r.recordEvent(id, "mouse_move", { x: 2 });
  r.endSession(id);

  const pb = r.createPlayback(id, { filterTypes: ["click"] });
  assert(pb.total() === 1, "filtered to clicks only");
  const e = pb.next();
  assert(e.type === "click", "only click event");
})();

// ── Playback pause/resume ───────────────────────────────────────────

(function testPlaybackPauseResume() {
  const r = createSessionReplay();
  const id = r.startSession();
  r.recordEvent(id, "click", {});
  r.recordEvent(id, "click", {});
  r.endSession(id);

  const pb = r.createPlayback(id);
  pb.pause();
  assert(pb.next() === null, "paused returns null");
  pb.resume();
  assert(pb.next() !== null, "resumed returns event");
})();

// ── Compare sessions ────────────────────────────────────────────────

(function testCompare() {
  const r = createSessionReplay();
  const id1 = r.startSession({ challengeType: "a" });
  r.recordEvent(id1, "click", {});
  r.endSession(id1, { solved: true });

  const id2 = r.startSession({ challengeType: "b" });
  r.recordEvent(id2, "click", {});
  r.recordEvent(id2, "click", {});
  r.recordEvent(id2, "mouse_move", {});
  r.endSession(id2, { solved: true });

  const cmp = r.compareSessions(id1, id2);
  assert(cmp.sessions.length === 2, "two session ids");
  assert(cmp.eventCountDiff === -2, "event count diff");
  assert(cmp.stats.length === 2, "both stats included");
})();

// ── Search events ───────────────────────────────────────────────────

(function testSearchEvents() {
  const r = createSessionReplay();
  const id1 = r.startSession();
  r.recordEvent(id1, "click", { target: "frame-1" });
  r.recordEvent(id1, "mouse_move", { x: 5 });
  r.endSession(id1);

  const id2 = r.startSession();
  r.recordEvent(id2, "click", { target: "frame-2" });
  r.endSession(id2);

  const clicks = r.searchEvents({ eventType: "click" });
  assert(clicks.length === 2, "found 2 clicks");

  const limited = r.searchEvents({ eventType: "click", limit: 1 });
  assert(limited.length === 1, "limit works");

  const completedOnly = r.searchEvents({ eventType: "click", sessionStatus: "completed" });
  assert(completedOnly.length === 2, "all completed");
})();

// ── Delete session ──────────────────────────────────────────────────

(function testDelete() {
  const r = createSessionReplay();
  const id = r.startSession();
  r.endSession(id);
  assert(r.deleteSession(id) === true, "delete returns true");
  assert(r.getSession(id) === null, "session gone");
  assert(r.deleteSession(id) === false, "double delete returns false");
})();

// ── Clear ───────────────────────────────────────────────────────────

(function testClear() {
  const r = createSessionReplay();
  r.startSession(); r.startSession();
  r.clear();
  assert(r.listSessions().length === 0, "all cleared");
})();

// ── Aggregate stats ─────────────────────────────────────────────────

(function testAggregateStats() {
  const r = createSessionReplay();
  const id1 = r.startSession();
  r.recordEvent(id1, "click", {});
  r.endSession(id1, { solved: true });

  const id2 = r.startSession();
  r.recordEvent(id2, "click", {});
  r.recordEvent(id2, "click", {});
  r.endSession(id2, { solved: false });

  const id3 = r.startSession();
  r.abandonSession(id3);

  const agg = r.aggregateStats();
  assert(agg.totalSessions === 3, "total 3");
  assert(agg.completed === 2, "2 completed");
  assert(agg.abandoned === 1, "1 abandoned");
  assert(agg.solvedCount === 1, "1 solved");
  assert(agg.solveRate === 0.5, "50% solve rate");
  assert(agg.totalEvents === 3, "3 total events");
})();

// ── Export/Import JSON ──────────────────────────────────────────────

(function testExportImport() {
  const r1 = createSessionReplay();
  const id = r1.startSession({ challengeType: "test" });
  r1.recordEvent(id, "click", { x: 1 });
  r1.recordEvent(id, "solve_attempt", { correct: true });
  r1.endSession(id, { solved: true });

  const json = r1.exportJSON();
  assert(typeof json === "string", "export returns string");

  const r2 = createSessionReplay();
  const count = r2.importJSON(json);
  assert(count === 1, "imported 1 session");

  const s = r2.getSession(id);
  assert(s !== null, "session accessible after import");
  assert(s.events.length === 2, "events preserved");
  assert(s.metadata.challengeType === "test", "metadata preserved");
})();

// ── Import dedup ────────────────────────────────────────────────────

(function testImportDedup() {
  const r = createSessionReplay();
  const id = r.startSession();
  r.endSession(id);

  const json = r.exportJSON();
  const count = r.importJSON(json);
  assert(count === 0, "duplicate not re-imported");
})();

// ── Max sessions eviction ───────────────────────────────────────────

(function testMaxSessions() {
  const r = createSessionReplay({ maxSessions: 3 });
  const id1 = r.startSession(); r.endSession(id1);
  const id2 = r.startSession(); r.endSession(id2);
  const id3 = r.startSession(); r.endSession(id3);
  const id4 = r.startSession(); r.endSession(id4);

  assert(r.listSessions().length === 3, "max sessions enforced");
  assert(r.getSession(id1) === null, "oldest evicted");
  assert(r.getSession(id4) !== null, "newest kept");
})();

// ── Max events per session ──────────────────────────────────────────

(function testMaxEvents() {
  const r = createSessionReplay({ maxEventsPerSession: 3 });
  const id = r.startSession();
  r.recordEvent(id, "click", {});
  r.recordEvent(id, "click", {});
  r.recordEvent(id, "click", {});
  assertThrows(function() { r.recordEvent(id, "click", {}); },
    "max events exceeded");
})();

// ── Session not found ───────────────────────────────────────────────

(function testNotFound() {
  const r = createSessionReplay();
  assertThrows(function() { r.recordEvent("nope", "click", {}); }, "record not found");
  assertThrows(function() { r.endSession("nope"); }, "end not found");
  assertThrows(function() { r.sessionStats("nope"); }, "stats not found");
  assert(r.getSession("nope") === null, "getSession returns null");
})();

// ── Text report ─────────────────────────────────────────────────────

(function testTextReport() {
  const r = createSessionReplay();
  const id = r.startSession({ challengeType: "sequence" });
  r.recordEvent(id, "click", {});
  r.recordEvent(id, "solve_attempt", { correct: true });
  r.endSession(id, { solved: true });

  const report = r.textReport();
  assert(report.includes("Session Replay Report"), "has title");
  assert(report.includes("Total Sessions: 1"), "has count");
  assert(report.includes("sequence"), "has challenge type");
})();

// ── VALID_EVENT_TYPES exposed ───────────────────────────────────────

(function testEventTypes() {
  const r = createSessionReplay();
  assert(r.VALID_EVENT_TYPES instanceof Set, "event types is a Set");
  assert(r.VALID_EVENT_TYPES.has("click"), "has click");
  assert(r.VALID_EVENT_TYPES.has("solve_attempt"), "has solve_attempt");
  assert(r.VALID_EVENT_TYPES.size === 20, "20 event types");
})();

// ── Playback seek ───────────────────────────────────────────────────

(function testPlaybackSeek() {
  const r = createSessionReplay();
  const id = r.startSession();
  r.recordEvent(id, "click", {});
  r.recordEvent(id, "click", {});
  r.recordEvent(id, "click", {});
  r.endSession(id);

  const pb = r.createPlayback(id);
  pb.seek(2);
  assert(pb.position() === 2, "seeked to 2");
  pb.next();
  assert(pb.done(), "done after last");
})();

// ── No timestamps mode ─────────────────────────────────────────────

(function testNoTimestamps() {
  const r = createSessionReplay({ recordTimestamps: false });
  const id = r.startSession();
  const e = r.recordEvent(id, "click", { x: 1 });
  assert(e.timestamp === undefined, "no timestamp when disabled");
  assert(e.elapsed === undefined, "no elapsed when disabled");
})();

// ── Summary ─────────────────────────────────────────────────────────

console.log("\n" + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
