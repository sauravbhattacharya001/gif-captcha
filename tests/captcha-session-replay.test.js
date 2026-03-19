/**
 * Jest tests for captcha-session-replay.js
 *
 * Migrated from test/captcha-session-replay.test.js which used a custom
 * assert runner incompatible with Jest (no test()/describe() blocks).
 */

"use strict";

const { createSessionReplay } = require("../src/captcha-session-replay");

describe("captcha-session-replay", () => {

  describe("session lifecycle", () => {
    test("startSession returns string ID and sets recording status", () => {
      const r = createSessionReplay();
      const id = r.startSession({ challengeType: "sequence", userId: "u1" });
      expect(typeof id).toBe("string");

      const s = r.getSession(id);
      expect(s.status).toBe("recording");
      expect(s.metadata.challengeType).toBe("sequence");
      expect(s.events).toHaveLength(0);
    });

    test("endSession sets completed status and stores result", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      r.endSession(id, { solved: true });
      const s = r.getSession(id);
      expect(s.status).toBe("completed");
      expect(s.result.solved).toBe(true);
      expect(s.endedAt).toBeGreaterThanOrEqual(s.startedAt);
    });

    test("abandonSession sets abandoned status", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      r.recordEvent(id, "mouse_move", { x: 0, y: 0 });
      r.abandonSession(id);
      expect(r.getSession(id).status).toBe("abandoned");
    });
  });

  describe("event recording", () => {
    test("records events with sequence numbers and timestamps", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      const e1 = r.recordEvent(id, "mouse_move", { x: 10, y: 20 });
      expect(e1.seq).toBe(0);
      expect(e1.type).toBe("mouse_move");
      expect(e1.data.x).toBe(10);
      expect(typeof e1.timestamp).toBe("number");

      r.recordEvent(id, "click", { x: 15, y: 25 });
      r.recordEvent(id, "solve_attempt", { answer: "A", correct: true });
      expect(r.getSession(id).events).toHaveLength(3);
    });

    test("rejects invalid event types", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      expect(() => r.recordEvent(id, "invalid_type", {})).toThrow();
    });

    test("cannot record after session ends", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      r.endSession(id);
      expect(() => r.recordEvent(id, "click", {})).toThrow();
    });
  });

  describe("session stats", () => {
    test("computes correct event type counts and accuracy", () => {
      const r = createSessionReplay();
      const id = r.startSession({ challengeType: "pattern" });
      r.recordEvent(id, "mouse_move", { x: 1, y: 1 });
      r.recordEvent(id, "click", { x: 2, y: 2 });
      r.recordEvent(id, "solve_attempt", { correct: true });
      r.recordEvent(id, "solve_attempt", { correct: false });
      r.recordEvent(id, "double_click", { x: 3, y: 3 });
      r.endSession(id, { solved: true });

      const st = r.sessionStats(id);
      expect(st.totalEvents).toBe(5);
      expect(st.clicks).toBe(2); // click + double_click
      expect(st.mouseMoves).toBe(1);
      expect(st.solveAttempts).toBe(2);
      expect(st.correctAttempts).toBe(1);
      expect(st.accuracy).toBe(0.5);
      expect(st.durationMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe("list and filter sessions", () => {
    test("filters by status, challengeType, and minEvents", () => {
      const r = createSessionReplay();
      const id1 = r.startSession({ challengeType: "sequence" });
      r.recordEvent(id1, "click", {});
      r.recordEvent(id1, "click", {});
      r.endSession(id1);

      const id2 = r.startSession({ challengeType: "pattern" });
      r.recordEvent(id2, "click", {});
      r.abandonSession(id2);

      r.startSession({ challengeType: "sequence" });

      expect(r.listSessions()).toHaveLength(3);
      expect(r.listSessions({ status: "completed" })).toHaveLength(1);
      expect(r.listSessions({ challengeType: "sequence" })).toHaveLength(2);
      expect(r.listSessions({ minEvents: 2 })).toHaveLength(1);
    });
  });

  describe("playback", () => {
    test("iterates events in order with position tracking", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      r.recordEvent(id, "mouse_move", { x: 0 });
      r.recordEvent(id, "click", { x: 1 });
      r.recordEvent(id, "mouse_move", { x: 2 });
      r.recordEvent(id, "solve_attempt", { correct: true });
      r.endSession(id);

      const pb = r.createPlayback(id, { speed: 2.0 });
      expect(pb.total()).toBe(4);
      expect(pb.position()).toBe(0);
      expect(pb.done()).toBe(false);

      const e1 = pb.next();
      expect(e1.type).toBe("mouse_move");
      expect(pb.position()).toBe(1);

      pb.next(); pb.next(); pb.next();
      expect(pb.done()).toBe(true);
      expect(pb.next()).toBeNull();

      pb.reset();
      expect(pb.position()).toBe(0);
      expect(pb.speed()).toBe(2.0);
    });

    test("filters by event type", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      r.recordEvent(id, "mouse_move", { x: 0 });
      r.recordEvent(id, "click", { x: 1 });
      r.recordEvent(id, "mouse_move", { x: 2 });
      r.endSession(id);

      const pb = r.createPlayback(id, { filterTypes: ["click"] });
      expect(pb.total()).toBe(1);
      expect(pb.next().type).toBe("click");
    });

    test("pause prevents iteration, resume allows it", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      r.recordEvent(id, "click", {});
      r.recordEvent(id, "click", {});
      r.endSession(id);

      const pb = r.createPlayback(id);
      pb.pause();
      expect(pb.next()).toBeNull();
      pb.resume();
      expect(pb.next()).not.toBeNull();
    });

    test("seek jumps to position", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      r.recordEvent(id, "click", {});
      r.recordEvent(id, "click", {});
      r.recordEvent(id, "click", {});
      r.endSession(id);

      const pb = r.createPlayback(id);
      pb.seek(2);
      expect(pb.position()).toBe(2);
      pb.next();
      expect(pb.done()).toBe(true);
    });
  });

  describe("compare sessions", () => {
    test("returns event count diff and both stats", () => {
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
      expect(cmp.sessions).toHaveLength(2);
      expect(cmp.eventCountDiff).toBe(-2);
      expect(cmp.stats).toHaveLength(2);
    });
  });

  describe("search events", () => {
    test("finds events across sessions with limit", () => {
      const r = createSessionReplay();
      const id1 = r.startSession();
      r.recordEvent(id1, "click", { target: "frame-1" });
      r.recordEvent(id1, "mouse_move", { x: 5 });
      r.endSession(id1);

      const id2 = r.startSession();
      r.recordEvent(id2, "click", { target: "frame-2" });
      r.endSession(id2);

      expect(r.searchEvents({ eventType: "click" })).toHaveLength(2);
      expect(r.searchEvents({ eventType: "click", limit: 1 })).toHaveLength(1);
      expect(r.searchEvents({ eventType: "click", sessionStatus: "completed" })).toHaveLength(2);
    });
  });

  describe("delete and clear", () => {
    test("deleteSession removes session", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      r.endSession(id);
      expect(r.deleteSession(id)).toBe(true);
      expect(r.getSession(id)).toBeNull();
      expect(r.deleteSession(id)).toBe(false);
    });

    test("clear removes all sessions", () => {
      const r = createSessionReplay();
      r.startSession(); r.startSession();
      r.clear();
      expect(r.listSessions()).toHaveLength(0);
    });
  });

  describe("aggregate stats", () => {
    test("computes totals, solve rate, and event counts", () => {
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
      expect(agg.totalSessions).toBe(3);
      expect(agg.completed).toBe(2);
      expect(agg.abandoned).toBe(1);
      expect(agg.solvedCount).toBe(1);
      expect(agg.solveRate).toBe(0.5);
      expect(agg.totalEvents).toBe(3);
    });
  });

  describe("export/import JSON", () => {
    test("roundtrips sessions via JSON", () => {
      const r1 = createSessionReplay();
      const id = r1.startSession({ challengeType: "test" });
      r1.recordEvent(id, "click", { x: 1 });
      r1.recordEvent(id, "solve_attempt", { correct: true });
      r1.endSession(id, { solved: true });

      const json = r1.exportJSON();
      expect(typeof json).toBe("string");

      const r2 = createSessionReplay();
      expect(r2.importJSON(json)).toBe(1);

      const s = r2.getSession(id);
      expect(s).not.toBeNull();
      expect(s.events).toHaveLength(2);
      expect(s.metadata.challengeType).toBe("test");
    });

    test("skips duplicate sessions on import", () => {
      const r = createSessionReplay();
      const id = r.startSession();
      r.endSession(id);
      const json = r.exportJSON();
      expect(r.importJSON(json)).toBe(0);
    });
  });

  describe("capacity limits", () => {
    test("maxSessions evicts oldest", () => {
      const r = createSessionReplay({ maxSessions: 3 });
      const id1 = r.startSession(); r.endSession(id1);
      const id2 = r.startSession(); r.endSession(id2);
      const id3 = r.startSession(); r.endSession(id3);
      const id4 = r.startSession(); r.endSession(id4);

      expect(r.listSessions()).toHaveLength(3);
      expect(r.getSession(id1)).toBeNull();
      expect(r.getSession(id4)).not.toBeNull();
    });

    test("maxEventsPerSession throws on overflow", () => {
      const r = createSessionReplay({ maxEventsPerSession: 3 });
      const id = r.startSession();
      r.recordEvent(id, "click", {});
      r.recordEvent(id, "click", {});
      r.recordEvent(id, "click", {});
      expect(() => r.recordEvent(id, "click", {})).toThrow();
    });
  });

  describe("error handling", () => {
    test("throws on unknown session ID", () => {
      const r = createSessionReplay();
      expect(() => r.recordEvent("nope", "click", {})).toThrow();
      expect(() => r.endSession("nope")).toThrow();
      expect(() => r.sessionStats("nope")).toThrow();
      expect(r.getSession("nope")).toBeNull();
    });
  });

  describe("text report", () => {
    test("includes title and session info", () => {
      const r = createSessionReplay();
      const id = r.startSession({ challengeType: "sequence" });
      r.recordEvent(id, "click", {});
      r.recordEvent(id, "solve_attempt", { correct: true });
      r.endSession(id, { solved: true });

      const report = r.textReport();
      expect(report).toContain("Session Replay Report");
      expect(report).toContain("Total Sessions: 1");
      expect(report).toContain("sequence");
    });
  });

  describe("VALID_EVENT_TYPES", () => {
    test("exposes valid event types as a Set", () => {
      const r = createSessionReplay();
      expect(r.VALID_EVENT_TYPES).toBeInstanceOf(Set);
      expect(r.VALID_EVENT_TYPES.has("click")).toBe(true);
      expect(r.VALID_EVENT_TYPES.has("solve_attempt")).toBe(true);
      expect(r.VALID_EVENT_TYPES.size).toBe(20);
    });
  });

  describe("options", () => {
    test("recordTimestamps: false omits timestamps", () => {
      const r = createSessionReplay({ recordTimestamps: false });
      const id = r.startSession();
      const e = r.recordEvent(id, "click", { x: 1 });
      expect(e.timestamp).toBeUndefined();
      expect(e.elapsed).toBeUndefined();
    });
  });
});
