require("./_expect");
const { describe, test } = require("node:test");
/**
 * solve-funnel-analyzer-edge.test.js - Additional edge-case coverage
 * for the CAPTCHA solve-funnel analyzer.
 *
 * The base solve-funnel-analyzer.test.js covers happy paths. This file
 * focuses on:
 *   - LRU eviction under maxSessions pressure
 *   - records[] capping under maxRecords pressure
 *   - cohort handling on sessions that never set a cohort, default cohort
 *     name, and cohort overrides across many sessions
 *   - trends bucketing with explicit timestamps spanning multiple bucketMs
 *   - exportCSV header on empty analyzer, exportJSON shape on empty analyzer
 *   - report invariants when only later funnel stages are recorded
 *     (overallConversion must remain 0 when presented count is 0)
 *   - reset() interaction with subsequent record() calls (no stale eviction)
 *   - timeMs aggregation when some sessions omit timeMs
 *
 * These directly exercise branches that the base tests skip and should
 * raise meaningful line/branch coverage without being redundant.
 */

"use strict";

const { createFunnelAnalyzer, STAGES } = require("../src/solve-funnel-analyzer");

describe("solve-funnel-analyzer edge cases", () => {
  test("LRU-evicts oldest sessions once maxSessions is exceeded", () => {
    const f = createFunnelAnalyzer({ maxSessions: 3 });
    f.record({ stage: "presented", sessionId: "s1" });
    f.record({ stage: "presented", sessionId: "s2" });
    f.record({ stage: "presented", sessionId: "s3" });
    expect(f.sessionCount).toBe(3);

    // Adding a 4th session must evict s1 (oldest).
    f.record({ stage: "presented", sessionId: "s4" });
    expect(f.sessionCount).toBe(3);

    const rep = f.report();
    expect(rep.totalSessions).toBe(3);
    // s4 is present, s1 evicted -> overall stays correct
    expect(rep.funnel[0].count).toBe(3);
  });

  test("re-recording an evicted sessionId creates a new session, not a resurrection", () => {
    const f = createFunnelAnalyzer({ maxSessions: 2 });
    f.record({ stage: "presented", sessionId: "a", cohort: "c1" });
    f.record({ stage: "attempted", sessionId: "a", cohort: "c1" });
    f.record({ stage: "presented", sessionId: "b" });
    // Evict 'a':
    f.record({ stage: "presented", sessionId: "c" });
    expect(f.sessionCount).toBe(2);

    // Now re-record 'a' as a brand new session. It should have a clean
    // stages map (no leftover 'attempted' from before eviction).
    f.record({ stage: "presented", sessionId: "a", cohort: "c2" });
    const rep = f.report();
    // funnel: presented=2 (b+a after evicting c) , attempted=0
    const attempted = rep.funnel.find((s) => s.stage === "attempted");
    expect(attempted.count).toBe(0);
  });

  test("records[] is capped by maxRecords without losing newest entries", () => {
    const f = createFunnelAnalyzer({ maxSessions: 50, maxRecords: 5 });
    for (let i = 0; i < 20; i++) {
      f.record({ stage: "presented", sessionId: "s" + i });
    }
    expect(f.recordCount).toBe(5);
    // exportCSV is built from records[]; verify newest sessions are retained.
    const csv = f.exportCSV();
    const lines = csv.split("\n");
    expect(lines.length).toBe(6); // 1 header + 5 records
    // Last line corresponds to s19 (most recent)
    expect(lines[lines.length - 1]).toContain("s19");
    // s0 must have been dropped
    expect(csv).not.toContain(",s0,");
  });

  test("compareCohorts segments sessions even when cohort never explicitly set", () => {
    const f = createFunnelAnalyzer();
    f.record({ stage: "presented", sessionId: "x" });
    f.record({ stage: "presented", sessionId: "y", cohort: "mobile" });
    f.record({ stage: "solved", sessionId: "y", cohort: "mobile" });

    const cohorts = f.compareCohorts();
    expect(Object.keys(cohorts).sort()).toEqual(["default", "mobile"]);
    expect(cohorts.default.totalSessions).toBe(1);
    expect(cohorts.mobile.totalSessions).toBe(1);
    expect(cohorts.mobile.overallConversion).toBe(1);
    expect(cohorts.default.overallConversion).toBe(0);
  });

  test("compareCohorts returns empty object when no sessions recorded", () => {
    const f = createFunnelAnalyzer();
    expect(f.compareCohorts()).toEqual({});
  });

  test("trends bucketing groups records by explicit timestamp across multiple bucketMs", () => {
    const f = createFunnelAnalyzer({ bucketMs: 1000 });
    const t0 = 1_700_000_000_000;
    // Bucket 0
    f.record({ stage: "presented", sessionId: "s1", timestamp: t0 + 100 });
    f.record({ stage: "solved", sessionId: "s1", timestamp: t0 + 200 });
    // Bucket 2 (skip bucket 1 entirely)
    f.record({ stage: "presented", sessionId: "s2", timestamp: t0 + 2100 });
    f.record({ stage: "attempted", sessionId: "s2", timestamp: t0 + 2200 });

    const t = f.trends();
    // Two non-empty buckets, sorted ascending
    expect(t.length).toBe(2);
    expect(t[0].presented).toBe(1);
    expect(t[0].solved).toBe(1);
    expect(t[0].conversion).toBe(1);
    expect(t[1].presented).toBe(1);
    expect(t[1].solved).toBe(0);
    expect(t[1].conversion).toBe(0);
    // bucketStart of second bucket must be 2s after first
    const start0 = Date.parse(t[0].bucketStart);
    const start1 = Date.parse(t[1].bucketStart);
    expect(start1 - start0).toBe(2000);
  });

  test("exportCSV on empty analyzer returns just the header row", () => {
    const f = createFunnelAnalyzer();
    const csv = f.exportCSV();
    expect(csv).toBe("sessionId,cohort,stage,timestamp,timeMs");
  });

  test("exportJSON on empty analyzer has well-formed empty structures", () => {
    const f = createFunnelAnalyzer();
    const parsed = JSON.parse(f.exportJSON());
    expect(parsed.report.totalSessions).toBe(0);
    expect(parsed.cohorts).toEqual({});
    expect(parsed.trends).toEqual([]);
    expect(parsed.records).toEqual([]);
  });

  test("overallConversion stays 0 when no 'presented' records exist", () => {
    const f = createFunnelAnalyzer();
    // A bot may slip directly into 'solved' (synthetic / replay); the
    // analyzer must not divide by zero or report Infinity.
    f.record({ stage: "solved", sessionId: "ghost" });
    const rep = f.report();
    expect(rep.overallConversion).toBe(0);
    const solvedStep = rep.funnel.find((s) => s.stage === "solved");
    expect(solvedStep.count).toBe(1);
    // First step has no prior, conversionRate is treated as 1 for the head
    expect(rep.funnel[0].conversionRate).toBe(0);
  });

  test("reset() lets subsequent records start cleanly with no stale eviction", () => {
    const f = createFunnelAnalyzer({ maxSessions: 2 });
    f.record({ stage: "presented", sessionId: "a" });
    f.record({ stage: "presented", sessionId: "b" });
    expect(f.sessionCount).toBe(2);
    f.reset();
    expect(f.sessionCount).toBe(0);
    expect(f.recordCount).toBe(0);

    // Re-add 2 sessions; nothing from the pre-reset queue should evict them.
    f.record({ stage: "presented", sessionId: "c" });
    f.record({ stage: "presented", sessionId: "d" });
    expect(f.sessionCount).toBe(2);
    // Adding a 3rd should evict 'c' (post-reset oldest), not be a no-op.
    f.record({ stage: "presented", sessionId: "e" });
    expect(f.sessionCount).toBe(2);
    const rep = f.report();
    expect(rep.funnel[0].count).toBe(2);
  });

  test("averageTimeMs ignores records that omit timeMs", () => {
    const f = createFunnelAnalyzer();
    f.record({ stage: "attempted", sessionId: "s1", timeMs: 1000 });
    f.record({ stage: "attempted", sessionId: "s2" }); // no timeMs
    f.record({ stage: "attempted", sessionId: "s3", timeMs: 3000 });
    const rep = f.report();
    expect(rep.averageTimeMs.attempted).toBe(2000); // (1000+3000)/2
    expect(rep.averageTimeMs.presented).toBe(null);
  });

  test("cohort override updates session cohort and reroutes future aggregation", () => {
    const f = createFunnelAnalyzer();
    f.record({ stage: "presented", sessionId: "u", cohort: "anon" });
    // Later record reassigns the cohort (e.g. after login)
    f.record({ stage: "solved", sessionId: "u", cohort: "loggedin" });

    const c = f.compareCohorts();
    // The session is owned by 'loggedin' now; 'anon' should not see this
    // session counted in its funnel.
    expect(c.loggedin.totalSessions).toBe(1);
    expect(c.loggedin.overallConversion).toBe(1);
    // 'anon' cohort no longer exists as a session, but the early record
    // does live on under records[] (snapshotted with cohort at record time).
    expect(c.anon).toBeUndefined();
  });

  test("invalid stage in record() does not corrupt internal state", () => {
    const f = createFunnelAnalyzer();
    expect(() =>
      f.record({ stage: "bogus", sessionId: "x" })
    ).toThrow(/Unknown stage/);
    expect(f.sessionCount).toBe(0);
    expect(f.recordCount).toBe(0);
  });
});
