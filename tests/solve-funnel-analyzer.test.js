/**
 * solve-funnel-analyzer.test.js — Tests for the CAPTCHA solve funnel analyzer.
 */

"use strict";

const { createFunnelAnalyzer, STAGES } = require("../src/solve-funnel-analyzer");

describe("createFunnelAnalyzer", () => {
  let funnel;

  beforeEach(() => {
    funnel = createFunnelAnalyzer();
  });

  test("exports STAGES array", () => {
    expect(STAGES).toEqual(["presented", "attempted", "completed", "solved"]);
  });

  test("starts empty", () => {
    expect(funnel.sessionCount).toBe(0);
    expect(funnel.recordCount).toBe(0);
    const r = funnel.report();
    expect(r.totalSessions).toBe(0);
    expect(r.overallConversion).toBe(0);
  });

  test("throws on missing stage or sessionId", () => {
    expect(() => funnel.record({})).toThrow();
    expect(() => funnel.record({ stage: "presented" })).toThrow();
    expect(() => funnel.record({ sessionId: "a" })).toThrow();
  });

  test("throws on unknown stage", () => {
    expect(() => funnel.record({ stage: "unknown", sessionId: "a" })).toThrow("Unknown stage");
  });

  test("records a full funnel session", () => {
    funnel.record({ stage: "presented", sessionId: "s1", timestamp: 1000 });
    funnel.record({ stage: "attempted", sessionId: "s1", timestamp: 2000, timeMs: 1000 });
    funnel.record({ stage: "completed", sessionId: "s1", timestamp: 3000, timeMs: 2000 });
    funnel.record({ stage: "solved", sessionId: "s1", timestamp: 4000, timeMs: 2000 });

    expect(funnel.sessionCount).toBe(1);
    expect(funnel.recordCount).toBe(4);

    const r = funnel.report();
    expect(r.totalSessions).toBe(1);
    expect(r.overallConversion).toBe(1);
    expect(r.funnel).toHaveLength(4);
    r.funnel.forEach((step) => {
      expect(step.count).toBe(1);
      expect(step.conversionRate).toBe(1);
      expect(step.dropOffRate).toBe(0);
    });
  });

  test("calculates drop-off correctly", () => {
    // 3 presented, 2 attempted, 1 completed, 1 solved
    ["s1", "s2", "s3"].forEach((id) =>
      funnel.record({ stage: "presented", sessionId: id, timestamp: 1000 })
    );
    ["s1", "s2"].forEach((id) =>
      funnel.record({ stage: "attempted", sessionId: id, timestamp: 2000 })
    );
    funnel.record({ stage: "completed", sessionId: "s1", timestamp: 3000 });
    funnel.record({ stage: "solved", sessionId: "s1", timestamp: 4000 });

    const r = funnel.report();
    expect(r.funnel[0].count).toBe(3); // presented
    expect(r.funnel[1].count).toBe(2); // attempted
    expect(r.funnel[1].dropOffRate).toBeCloseTo(0.3333, 3);
    expect(r.funnel[2].count).toBe(1); // completed
    expect(r.funnel[2].dropOffRate).toBe(0.5);
    expect(r.funnel[3].count).toBe(1); // solved
    expect(r.funnel[3].dropOffRate).toBe(0);
    expect(r.overallConversion).toBeCloseTo(0.3333, 3);
  });

  test("average time per stage", () => {
    funnel.record({ stage: "presented", sessionId: "s1", timestamp: 1000 });
    funnel.record({ stage: "attempted", sessionId: "s1", timestamp: 2000, timeMs: 500 });
    funnel.record({ stage: "presented", sessionId: "s2", timestamp: 1000 });
    funnel.record({ stage: "attempted", sessionId: "s2", timestamp: 2000, timeMs: 1500 });

    const r = funnel.report();
    expect(r.averageTimeMs.attempted).toBe(1000);
    expect(r.averageTimeMs.presented).toBeNull();
  });

  test("cohort comparison", () => {
    funnel.record({ stage: "presented", sessionId: "d1", cohort: "desktop", timestamp: 1000 });
    funnel.record({ stage: "solved", sessionId: "d1", cohort: "desktop", timestamp: 2000 });
    funnel.record({ stage: "presented", sessionId: "m1", cohort: "mobile", timestamp: 1000 });
    funnel.record({ stage: "presented", sessionId: "m2", cohort: "mobile", timestamp: 1000 });

    const c = funnel.compareCohorts();
    expect(Object.keys(c)).toContain("desktop");
    expect(Object.keys(c)).toContain("mobile");
    expect(c.desktop.totalSessions).toBe(1);
    expect(c.desktop.overallConversion).toBe(1);
    expect(c.mobile.totalSessions).toBe(2);
    expect(c.mobile.overallConversion).toBe(0);
  });

  test("default cohort is 'default'", () => {
    funnel.record({ stage: "presented", sessionId: "x", timestamp: 1000 });
    const c = funnel.compareCohorts();
    expect(Object.keys(c)).toEqual(["default"]);
  });

  test("trends bucketing", () => {
    const f = createFunnelAnalyzer({ bucketMs: 1000 });
    f.record({ stage: "presented", sessionId: "s1", timestamp: 100 });
    f.record({ stage: "solved", sessionId: "s1", timestamp: 200 });
    f.record({ stage: "presented", sessionId: "s2", timestamp: 1500 });

    const t = f.trends();
    expect(t.length).toBeGreaterThanOrEqual(2);
    expect(t[0].presented).toBe(1);
    expect(t[0].solved).toBe(1);
    expect(t[0].conversion).toBe(1);
  });

  test("exportCSV format", () => {
    funnel.record({ stage: "presented", sessionId: "s1", timestamp: 1000 });
    const csv = funnel.exportCSV();
    const lines = csv.split("\n");
    expect(lines[0]).toBe("sessionId,cohort,stage,timestamp,timeMs");
    expect(lines[1]).toContain("s1");
    expect(lines[1]).toContain("presented");
  });

  test("exportJSON returns valid JSON", () => {
    funnel.record({ stage: "presented", sessionId: "s1", timestamp: 1000 });
    const parsed = JSON.parse(funnel.exportJSON());
    expect(parsed.report).toBeDefined();
    expect(parsed.cohorts).toBeDefined();
    expect(parsed.trends).toBeDefined();
    expect(parsed.records).toHaveLength(1);
  });

  test("reset clears all data", () => {
    funnel.record({ stage: "presented", sessionId: "s1", timestamp: 1000 });
    funnel.reset();
    expect(funnel.sessionCount).toBe(0);
    expect(funnel.recordCount).toBe(0);
  });

  test("overall rate tracks from presented", () => {
    funnel.record({ stage: "presented", sessionId: "s1", timestamp: 1000 });
    funnel.record({ stage: "presented", sessionId: "s2", timestamp: 1000 });
    funnel.record({ stage: "attempted", sessionId: "s1", timestamp: 2000 });
    funnel.record({ stage: "attempted", sessionId: "s2", timestamp: 2000 });
    funnel.record({ stage: "completed", sessionId: "s1", timestamp: 3000 });

    const r = funnel.report();
    expect(r.funnel[2].overallRate).toBe(0.5); // 1 completed / 2 presented
  });

  test("handles multiple records for same session-stage (last wins)", () => {
    funnel.record({ stage: "presented", sessionId: "s1", timestamp: 1000 });
    funnel.record({ stage: "presented", sessionId: "s1", timestamp: 2000 });
    expect(funnel.sessionCount).toBe(1);
    expect(funnel.recordCount).toBe(2);
    // Still counts as 1 in funnel
    const r = funnel.report();
    expect(r.funnel[0].count).toBe(1);
  });

  test("large funnel with many sessions", () => {
    for (let i = 0; i < 100; i++) {
      funnel.record({ stage: "presented", sessionId: "s" + i, timestamp: i * 100 });
      if (i < 80) funnel.record({ stage: "attempted", sessionId: "s" + i, timestamp: i * 100 + 10 });
      if (i < 50) funnel.record({ stage: "completed", sessionId: "s" + i, timestamp: i * 100 + 20 });
      if (i < 30) funnel.record({ stage: "solved", sessionId: "s" + i, timestamp: i * 100 + 30 });
    }
    const r = funnel.report();
    expect(r.totalSessions).toBe(100);
    expect(r.funnel[0].count).toBe(100);
    expect(r.funnel[1].count).toBe(80);
    expect(r.funnel[2].count).toBe(50);
    expect(r.funnel[3].count).toBe(30);
    expect(r.overallConversion).toBe(0.3);
  });

  test("cohort updated by later record", () => {
    funnel.record({ stage: "presented", sessionId: "s1", cohort: "a", timestamp: 1000 });
    funnel.record({ stage: "attempted", sessionId: "s1", cohort: "b", timestamp: 2000 });
    const c = funnel.compareCohorts();
    expect(Object.keys(c)).toEqual(["b"]);
  });

  test("empty trends returns empty array", () => {
    expect(funnel.trends()).toEqual([]);
  });
});
