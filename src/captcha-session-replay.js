/**
 * captcha-session-replay.js — Record and replay CAPTCHA interaction sessions.
 *
 * Captures granular user interaction events during CAPTCHA solving for
 * research analysis, debugging, and behavioral study. Sessions can be
 * exported, imported, filtered, compared, and replayed at variable speed.
 *
 * Usage:
 *   const { createSessionReplay } = require('./captcha-session-replay');
 *   const replay = createSessionReplay({ maxSessions: 500 });
 *
 *   const sid = replay.startSession({ challengeType: 'sequence', userId: 'u1' });
 *   replay.recordEvent(sid, 'mouse_move', { x: 120, y: 45 });
 *   replay.recordEvent(sid, 'click', { x: 130, y: 50, target: 'frame-3' });
 *   replay.recordEvent(sid, 'solve_attempt', { answer: 'ABC', correct: true });
 *   replay.endSession(sid, { solved: true });
 *
 *   const session = replay.getSession(sid);
 *   const playback = replay.createPlayback(sid, { speed: 2.0 });
 *   const stats = replay.sessionStats(sid);
 *   const comparison = replay.compareSessions(sid1, sid2);
 *   const json = replay.exportJSON();
 *   replay.importJSON(json);
 *
 * @module captcha-session-replay
 */

"use strict";

// ── Event Types ─────────────────────────────────────────────────────

const VALID_EVENT_TYPES = new Set([
  "mouse_move",
  "mouse_down",
  "mouse_up",
  "click",
  "double_click",
  "scroll",
  "key_down",
  "key_up",
  "focus",
  "blur",
  "touch_start",
  "touch_end",
  "drag_start",
  "drag_end",
  "solve_attempt",
  "hint_request",
  "frame_change",
  "pause",
  "resume",
  "custom",
]);

// ── Helpers ─────────────────────────────────────────────────────────

let _idCounter = 0;
function _genId() {
  return "sess_" + Date.now().toString(36) + "_" + (++_idCounter).toString(36);
}

function _now() {
  return Date.now();
}

function _cloneDeep(obj) {
  return JSON.parse(JSON.stringify(obj));
}

// ── Session Replay Factory ──────────────────────────────────────────

/**
 * Create a session replay recorder/player.
 *
 * @param {Object} [options]
 * @param {number} [options.maxSessions=500]   Max stored sessions (LRU eviction)
 * @param {number} [options.maxEventsPerSession=10000] Max events per session
 * @param {boolean} [options.recordTimestamps=true] Include timestamps in events
 * @returns {Object} Session replay API
 */
function createSessionReplay(options) {
  const opts = Object.assign(
    {},
    { maxSessions: 500, maxEventsPerSession: 10000, recordTimestamps: true },
    options || {}
  );

  const sessions = new Map(); // id -> session
  const order = []; // insertion order for LRU

  // ── Internal ────────────────────────────────────────────────────

  function _evict() {
    while (sessions.size > opts.maxSessions && order.length > 0) {
      const oldest = order.shift();
      sessions.delete(oldest);
    }
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Start a new recording session.
   * @param {Object} [metadata] - Challenge type, user ID, difficulty, etc.
   * @returns {string} Session ID
   */
  function startSession(metadata) {
    const id = _genId();
    const session = {
      id: id,
      status: "recording",
      startedAt: _now(),
      endedAt: null,
      metadata: metadata ? _cloneDeep(metadata) : {},
      events: [],
      result: null,
    };
    sessions.set(id, session);
    order.push(id);
    _evict();
    return id;
  }

  /**
   * Record an interaction event in a session.
   * @param {string} sessionId
   * @param {string} eventType - One of VALID_EVENT_TYPES
   * @param {Object} [data] - Event payload (coordinates, keys, etc.)
   * @returns {Object} The recorded event
   */
  function recordEvent(sessionId, eventType, data) {
    const session = sessions.get(sessionId);
    if (!session) throw new Error("Session not found: " + sessionId);
    if (session.status !== "recording")
      throw new Error("Session is not recording: " + sessionId);
    if (!VALID_EVENT_TYPES.has(eventType))
      throw new Error("Invalid event type: " + eventType);
    if (session.events.length >= opts.maxEventsPerSession)
      throw new Error("Max events reached for session: " + sessionId);

    const event = {
      seq: session.events.length,
      type: eventType,
      data: data ? _cloneDeep(data) : {},
    };
    if (opts.recordTimestamps) {
      event.timestamp = _now();
      event.elapsed = event.timestamp - session.startedAt;
    }
    session.events.push(event);
    return _cloneDeep(event);
  }

  /**
   * End a recording session.
   * @param {string} sessionId
   * @param {Object} [result] - Outcome (solved, score, etc.)
   * @returns {Object} Session summary
   */
  function endSession(sessionId, result) {
    const session = sessions.get(sessionId);
    if (!session) throw new Error("Session not found: " + sessionId);
    if (session.status !== "recording")
      throw new Error("Session is not recording: " + sessionId);

    session.status = "completed";
    session.endedAt = _now();
    session.result = result ? _cloneDeep(result) : {};
    return sessionSummary(sessionId);
  }

  /**
   * Abandon a session without completing it.
   * @param {string} sessionId
   */
  function abandonSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) throw new Error("Session not found: " + sessionId);
    session.status = "abandoned";
    session.endedAt = _now();
  }

  /**
   * Get a full session by ID.
   * @param {string} sessionId
   * @returns {Object|null}
   */
  function getSession(sessionId) {
    const s = sessions.get(sessionId);
    return s ? _cloneDeep(s) : null;
  }

  /**
   * Get session summary (without full event list).
   * @param {string} sessionId
   * @returns {Object}
   */
  function sessionSummary(sessionId) {
    const s = sessions.get(sessionId);
    if (!s) throw new Error("Session not found: " + sessionId);
    return {
      id: s.id,
      status: s.status,
      startedAt: s.startedAt,
      endedAt: s.endedAt,
      durationMs: s.endedAt ? s.endedAt - s.startedAt : _now() - s.startedAt,
      eventCount: s.events.length,
      metadata: _cloneDeep(s.metadata),
      result: s.result ? _cloneDeep(s.result) : null,
    };
  }

  /**
   * Compute detailed stats for a session.
   * @param {string} sessionId
   * @returns {Object}
   */
  function sessionStats(sessionId) {
    const s = sessions.get(sessionId);
    if (!s) throw new Error("Session not found: " + sessionId);

    const typeCounts = {};
    let clicks = 0;
    let moves = 0;
    let solveAttempts = 0;
    let correctAttempts = 0;
    const intervals = [];

    for (let i = 0; i < s.events.length; i++) {
      const e = s.events[i];
      typeCounts[e.type] = (typeCounts[e.type] || 0) + 1;
      if (e.type === "click" || e.type === "double_click") clicks++;
      if (e.type === "mouse_move") moves++;
      if (e.type === "solve_attempt") {
        solveAttempts++;
        if (e.data && e.data.correct) correctAttempts++;
      }
      if (i > 0 && e.timestamp && s.events[i - 1].timestamp) {
        intervals.push(e.timestamp - s.events[i - 1].timestamp);
      }
    }

    const avgInterval =
      intervals.length > 0
        ? intervals.reduce((a, b) => a + b, 0) / intervals.length
        : 0;

    return {
      sessionId: s.id,
      status: s.status,
      durationMs: (s.endedAt || _now()) - s.startedAt,
      totalEvents: s.events.length,
      eventTypes: typeCounts,
      clicks: clicks,
      mouseMoves: moves,
      solveAttempts: solveAttempts,
      correctAttempts: correctAttempts,
      accuracy: solveAttempts > 0 ? correctAttempts / solveAttempts : null,
      avgEventIntervalMs: Math.round(avgInterval),
      eventsPerSecond:
        s.endedAt && s.endedAt > s.startedAt
          ? Number(
              (
                (s.events.length / (s.endedAt - s.startedAt)) *
                1000
              ).toFixed(2)
            )
          : null,
    };
  }

  /**
   * List all sessions, optionally filtered.
   * @param {Object} [filter]
   * @param {string} [filter.status] - recording|completed|abandoned
   * @param {string} [filter.challengeType] - metadata.challengeType match
   * @param {number} [filter.minEvents] - minimum event count
   * @param {number} [filter.since] - timestamp lower bound
   * @returns {Object[]} Array of session summaries
   */
  function listSessions(filter) {
    const f = filter || {};
    const results = [];
    for (const s of sessions.values()) {
      if (f.status && s.status !== f.status) continue;
      if (
        f.challengeType &&
        (!s.metadata || s.metadata.challengeType !== f.challengeType)
      )
        continue;
      if (f.minEvents && s.events.length < f.minEvents) continue;
      if (f.since && s.startedAt < f.since) continue;
      results.push({
        id: s.id,
        status: s.status,
        startedAt: s.startedAt,
        endedAt: s.endedAt,
        eventCount: s.events.length,
        metadata: _cloneDeep(s.metadata),
      });
    }
    return results;
  }

  /**
   * Create a playback iterator for a session.
   * @param {string} sessionId
   * @param {Object} [options]
   * @param {number} [options.speed=1.0] - Playback speed multiplier
   * @param {number} [options.startAt=0] - Start from event index
   * @param {string[]} [options.filterTypes] - Only include these event types
   * @returns {Object} Playback controller
   */
  function createPlayback(sessionId, options) {
    const s = sessions.get(sessionId);
    if (!s) throw new Error("Session not found: " + sessionId);
    const popts = Object.assign({}, { speed: 1.0, startAt: 0 }, options || {});
    const filterSet = popts.filterTypes
      ? new Set(popts.filterTypes)
      : null;

    let events = s.events.slice();
    if (filterSet) {
      events = events.filter(function (e) {
        return filterSet.has(e.type);
      });
    }

    let cursor = Math.max(0, Math.min(popts.startAt, events.length));
    let paused = false;

    return {
      /** Total events in playback */
      total: function () {
        return events.length;
      },
      /** Current position */
      position: function () {
        return cursor;
      },
      /** Whether playback is done */
      done: function () {
        return cursor >= events.length;
      },
      /** Get next event with adjusted delay */
      next: function () {
        if (paused || cursor >= events.length) return null;
        const event = _cloneDeep(events[cursor]);
        let delayMs = 0;
        if (cursor > 0 && events[cursor].elapsed != null && events[cursor - 1].elapsed != null) {
          delayMs = (events[cursor].elapsed - events[cursor - 1].elapsed) / popts.speed;
        }
        event.playbackDelay = Math.max(0, Math.round(delayMs));
        cursor++;
        return event;
      },
      /** Pause playback */
      pause: function () {
        paused = true;
      },
      /** Resume playback */
      resume: function () {
        paused = false;
      },
      /** Seek to position */
      seek: function (pos) {
        cursor = Math.max(0, Math.min(pos, events.length));
      },
      /** Reset to beginning */
      reset: function () {
        cursor = Math.max(0, Math.min(popts.startAt, events.length));
        paused = false;
      },
      /** Get current speed */
      speed: function () {
        return popts.speed;
      },
    };
  }

  /**
   * Compare two sessions side-by-side.
   * @param {string} id1
   * @param {string} id2
   * @returns {Object} Comparison report
   */
  function compareSessions(id1, id2) {
    const s1 = sessionStats(id1);
    const s2 = sessionStats(id2);
    const sess1 = sessions.get(id1);
    const sess2 = sessions.get(id2);

    return {
      sessions: [s1.sessionId, s2.sessionId],
      durationDiff: s1.durationMs - s2.durationMs,
      eventCountDiff: s1.totalEvents - s2.totalEvents,
      clicksDiff: s1.clicks - s2.clicks,
      mouseMoveDiff: s1.mouseMoves - s2.mouseMoves,
      accuracyDiff:
        s1.accuracy != null && s2.accuracy != null
          ? Number((s1.accuracy - s2.accuracy).toFixed(4))
          : null,
      faster: s1.durationMs < s2.durationMs ? s1.sessionId : s2.sessionId,
      moreAccurate:
        s1.accuracy != null && s2.accuracy != null
          ? s1.accuracy >= s2.accuracy
            ? s1.sessionId
            : s2.sessionId
          : null,
      stats: [s1, s2],
      metadata: [
        sess1 ? _cloneDeep(sess1.metadata) : {},
        sess2 ? _cloneDeep(sess2.metadata) : {},
      ],
    };
  }

  /**
   * Search events across all sessions.
   * @param {Object} query
   * @param {string} [query.eventType] - Filter by event type
   * @param {string} [query.sessionStatus] - Filter by session status
   * @param {Function} [query.predicate] - Custom filter on event data
   * @param {number} [query.limit=100] - Max results
   * @returns {Object[]} Matching events with session context
   */
  function searchEvents(query) {
    const q = query || {};
    const limit = q.limit || 100;
    const results = [];

    for (const s of sessions.values()) {
      if (q.sessionStatus && s.status !== q.sessionStatus) continue;
      for (const e of s.events) {
        if (q.eventType && e.type !== q.eventType) continue;
        if (q.predicate && !q.predicate(e)) continue;
        results.push({
          sessionId: s.id,
          challengeType: s.metadata ? s.metadata.challengeType : null,
          event: _cloneDeep(e),
        });
        if (results.length >= limit) return results;
      }
    }
    return results;
  }

  /**
   * Delete a session.
   * @param {string} sessionId
   * @returns {boolean}
   */
  function deleteSession(sessionId) {
    const idx = order.indexOf(sessionId);
    if (idx !== -1) order.splice(idx, 1);
    return sessions.delete(sessionId);
  }

  /**
   * Clear all sessions.
   */
  function clear() {
    sessions.clear();
    order.length = 0;
  }

  /**
   * Get aggregate stats across all completed sessions.
   * @returns {Object}
   */
  function aggregateStats() {
    let total = 0;
    let completed = 0;
    let abandoned = 0;
    let totalDuration = 0;
    let totalEvents = 0;
    let solved = 0;

    for (const s of sessions.values()) {
      total++;
      if (s.status === "completed") {
        completed++;
        if (s.endedAt) totalDuration += s.endedAt - s.startedAt;
        if (s.result && s.result.solved) solved++;
      }
      if (s.status === "abandoned") abandoned++;
      totalEvents += s.events.length;
    }

    return {
      totalSessions: total,
      completed: completed,
      abandoned: abandoned,
      recording: total - completed - abandoned,
      solvedCount: solved,
      solveRate: completed > 0 ? Number((solved / completed).toFixed(4)) : null,
      avgDurationMs:
        completed > 0 ? Math.round(totalDuration / completed) : null,
      avgEventsPerSession:
        total > 0 ? Number((totalEvents / total).toFixed(1)) : null,
      totalEvents: totalEvents,
    };
  }

  /**
   * Export all sessions to JSON string.
   * @param {Object} [filter] - Same as listSessions filter
   * @returns {string}
   */
  function exportJSON(filter) {
    const ids = listSessions(filter).map(function (s) {
      return s.id;
    });
    const data = ids.map(function (id) {
      return sessions.get(id);
    }).filter(Boolean).map(_cloneDeep);
    return JSON.stringify({ version: 1, exportedAt: _now(), sessions: data }, null, 2);
  }

  /**
   * Import sessions from JSON string.
   * @param {string} jsonStr
   * @returns {number} Number of sessions imported
   */
  function importJSON(jsonStr) {
    const data = JSON.parse(jsonStr);
    if (!data || !Array.isArray(data.sessions))
      throw new Error("Invalid import format");
    let count = 0;
    for (const s of data.sessions) {
      if (!s.id || !s.events) continue;
      if (sessions.has(s.id)) continue; // skip duplicates
      sessions.set(s.id, _cloneDeep(s));
      order.push(s.id);
      count++;
    }
    _evict();
    return count;
  }

  /**
   * Generate a text report of aggregate and per-session stats.
   * @returns {string}
   */
  function textReport() {
    const agg = aggregateStats();
    const lines = [
      "=== CAPTCHA Session Replay Report ===",
      "",
      "Total Sessions: " + agg.totalSessions,
      "  Completed:    " + agg.completed,
      "  Abandoned:    " + agg.abandoned,
      "  Recording:    " + agg.recording,
      "  Solved:       " + agg.solvedCount,
      "  Solve Rate:   " + (agg.solveRate != null ? (agg.solveRate * 100).toFixed(1) + "%" : "N/A"),
      "  Avg Duration: " + (agg.avgDurationMs != null ? agg.avgDurationMs + "ms" : "N/A"),
      "  Avg Events:   " + (agg.avgEventsPerSession || "N/A"),
      "  Total Events: " + agg.totalEvents,
      "",
      "--- Per-Session Breakdown ---",
    ];

    for (const s of sessions.values()) {
      if (s.status !== "completed") continue;
      const st = sessionStats(s.id);
      lines.push(
        "",
        "Session: " + s.id,
        "  Type:      " + (s.metadata.challengeType || "unknown"),
        "  Duration:  " + st.durationMs + "ms",
        "  Events:    " + st.totalEvents,
        "  Clicks:    " + st.clicks,
        "  Moves:     " + st.mouseMoves,
        "  Attempts:  " + st.solveAttempts,
        "  Accuracy:  " + (st.accuracy != null ? (st.accuracy * 100).toFixed(1) + "%" : "N/A"),
        "  Events/s:  " + (st.eventsPerSecond || "N/A")
      );
    }

    return lines.join("\n");
  }

  return {
    startSession: startSession,
    recordEvent: recordEvent,
    endSession: endSession,
    abandonSession: abandonSession,
    getSession: getSession,
    sessionSummary: sessionSummary,
    sessionStats: sessionStats,
    listSessions: listSessions,
    createPlayback: createPlayback,
    compareSessions: compareSessions,
    searchEvents: searchEvents,
    deleteSession: deleteSession,
    clear: clear,
    aggregateStats: aggregateStats,
    exportJSON: exportJSON,
    importJSON: importJSON,
    textReport: textReport,
    VALID_EVENT_TYPES: VALID_EVENT_TYPES,
  };
}

module.exports = { createSessionReplay };
