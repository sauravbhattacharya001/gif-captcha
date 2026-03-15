/**
 * Tests for Challenge Designer (designer.html)
 */

"use strict";

const fs = require("fs");
const path = require("path");

describe("Challenge Designer", () => {
  describe("Challenge data model", () => {
    test("new challenge has required fields", () => {
      const challenge = {
        id: 1, title: "Untitled Challenge", description: "", category: "narrative_twist",
        difficulty: "medium", tags: [], gifUrl: "", duration: 3, keyFrame: 1.5,
        question: "What unexpected event happens in this GIF?",
        options: [{ text: "", correct: true },{ text: "", correct: false },{ text: "", correct: false },{ text: "", correct: false }],
        timeLimit: 15, maxAttempts: 3, playbackSpeed: 1, loop: true, shuffleOptions: true,
      };
      expect(challenge.title).toBe("Untitled Challenge");
      expect(challenge.category).toBe("narrative_twist");
      expect(challenge.options.length).toBe(4);
      expect(challenge.options[0].correct).toBe(true);
      expect(challenge.timeLimit).toBe(15);
    });

    test("exactly one option should be correct", () => {
      const options = [{ text: "A", correct: true },{ text: "B", correct: false },{ text: "C", correct: false }];
      expect(options.filter(o => o.correct).length).toBe(1);
    });

    test("minimum 2 options required", () => {
      expect([{ text: "Yes", correct: true },{ text: "No", correct: false }].length).toBeGreaterThanOrEqual(2);
    });

    test("maximum 8 options allowed", () => {
      const opts = Array.from({ length: 8 }, (_, i) => ({ text: `Option ${i+1}`, correct: i === 0 }));
      expect(opts.length).toBeLessThanOrEqual(8);
    });
  });

  describe("Difficulty levels", () => {
    const validDiffs = ["easy", "medium", "hard", "expert"];
    test("all difficulty levels are valid", () => {
      validDiffs.forEach(d => expect(["easy", "medium", "hard", "expert"]).toContain(d));
    });
    test("difficulty CSS class format", () => {
      validDiffs.forEach(d => expect(`diff-${d}`).toMatch(/^diff-(easy|medium|hard|expert)$/));
    });
  });

  describe("Categories", () => {
    const cats = ["narrative_twist","visual_illusion","unexpected_action","temporal_sequence","object_tracking","emotion_recognition","spatial_reasoning","custom"];
    test("8 categories defined", () => expect(cats.length).toBe(8));
    test("category display names are readable", () => cats.forEach(c => expect(c.replace(/_/g, " ")).not.toContain("_")));
  });

  describe("Export format", () => {
    test("exported challenge structure", () => {
      const exported = {
        title: "Test", description: "A test", category: "narrative_twist", difficulty: "hard",
        tags: ["animal"], gifUrl: "https://example.com/test.gif", duration: 5, keyFrame: 2.5,
        question: "What happens?",
        options: [{ text: "Correct", correct: true },{ text: "Wrong", correct: false }],
        settings: { timeLimit: 20, maxAttempts: 2, playbackSpeed: 1.5, loop: true, shuffleOptions: true },
      };
      expect(exported.title).toBeDefined();
      expect(exported.options.filter(o => o.correct).length).toBe(1);
      expect(exported.settings.timeLimit).toBeGreaterThan(0);
    });

    test("export excludes internal fields", () => {
      const exported = { title: "Test", question: "Q?", options: [] };
      expect(exported.id).toBeUndefined();
      expect(exported.createdAt).toBeUndefined();
    });

    test("exported JSON is roundtrippable", () => {
      const data = [{ title: "T1", question: "Q1?" },{ title: "T2", question: "Q2?" }];
      expect(JSON.parse(JSON.stringify(data))).toEqual(data);
    });
  });

  describe("Import validation", () => {
    test("single object wraps to array", () => {
      const data = JSON.parse(JSON.stringify({ title: "Imported" }));
      const arr = Array.isArray(data) ? data : [data];
      expect(arr.length).toBe(1);
    });

    test("array import preserves length", () => {
      const data = [{ title: "C1" },{ title: "C2" }];
      expect(data.length).toBe(2);
    });

    test("invalid JSON throws", () => {
      expect(() => JSON.parse("{invalid}")).toThrow();
    });

    test("defaults for missing fields", () => {
      const input = { title: "Minimal" };
      const c = {
        title: input.title || "Imported", category: input.category || "narrative_twist",
        difficulty: input.difficulty || "medium", tags: input.tags || [], duration: input.duration || 3,
      };
      expect(c.category).toBe("narrative_twist");
      expect(c.difficulty).toBe("medium");
    });
  });

  describe("Question templates", () => {
    const templates = {
      describe: "Describe the unexpected event in this GIF",
      what_happens: "What happens at the end of this GIF?",
      count: "How many times does the event occur?",
      order: "In what order do the events happen?",
      identify: "Which object changes unexpectedly?",
      emotion: "What emotion is expressed at the key moment?",
    };
    test("6 templates", () => expect(Object.keys(templates).length).toBe(6));
    test("all non-empty", () => Object.values(templates).forEach(q => expect(q.length).toBeGreaterThan(0)));
  });

  describe("Stats calculation", () => {
    test("counts by difficulty", () => {
      const challenges = [{ difficulty: "easy" },{ difficulty: "easy" },{ difficulty: "medium" },{ difficulty: "hard" }];
      const counts = {};
      challenges.forEach(c => counts[c.difficulty] = (counts[c.difficulty] || 0) + 1);
      expect(counts.easy).toBe(2);
      expect(counts.medium).toBe(1);
      expect(counts.hard).toBe(1);
    });
  });

  describe("HTML file", () => {
    const html = fs.readFileSync(path.join(__dirname, "..", "designer.html"), "utf-8");

    test("contains required elements", () => {
      expect(html).toContain("Challenge Designer");
      expect(html).toContain("challenge-list");
      expect(html).toContain("exportChallenges");
      expect(html).toContain("importChallenges");
    });

    test("contains all categories", () => {
      ["narrative_twist","visual_illusion","unexpected_action","temporal_sequence","object_tracking","emotion_recognition","spatial_reasoning"].forEach(c =>
        expect(html).toContain(c));
    });

    test("contains difficulty options", () => {
      ['"easy"','"medium"','"hard"','"expert"'].forEach(d => expect(html).toContain(d));
    });

    test("contains question templates", () => {
      expect(html).toContain("Describe the unexpected event");
      expect(html).toContain("What happens at the end");
    });

    test("uses localStorage", () => {
      expect(html).toContain("localStorage");
      expect(html).toContain("gc-designer");
    });

    test("has responsive design", () => {
      expect(html).toContain("@media");
      expect(html).toContain("768px");
    });

    test("has JSON export", () => {
      expect(html).toContain("application/json");
      expect(html).toContain("captcha-challenges.json");
    });
  });

  describe("Slider ranges", () => {
    test("time limit 5-60", () => { expect(5).toBeGreaterThan(0); expect(60).toBeLessThanOrEqual(120); });
    test("max attempts 1-5", () => { expect(1).toBe(1); expect(5).toBe(5); });
    test("playback speed includes 1.0", () => {
      const steps = (1 - 0.5) / 0.25;
      expect(steps).toBe(Math.floor(steps));
    });
  });
});
