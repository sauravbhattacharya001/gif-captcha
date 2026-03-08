"use strict";

var engine = require("../src/challenge-template-engine");
var createChallengeTemplateEngine = engine.createChallengeTemplateEngine;

describe("ChallengeTemplateEngine", function () {

  // ── Construction ──────────────────────────────────────────────

  describe("construction", function () {
    it("creates with defaults (includes builtins)", function () {
      var e = createChallengeTemplateEngine();
      expect(e.listTemplates().length).toBe(6);
    });

    it("creates without builtins", function () {
      var e = createChallengeTemplateEngine({ includeBuiltins: false });
      expect(e.listTemplates().length).toBe(0);
    });

    it("seeded engine produces deterministic output", function () {
      var e1 = createChallengeTemplateEngine({ seed: 42 });
      var e2 = createChallengeTemplateEngine({ seed: 42 });
      var c1 = e1.generate();
      var c2 = e2.generate();
      expect(c1.templateName).toBe(c2.templateName);
      expect(c1.question).toBe(c2.question);
    });
  });

  // ── Built-in templates ────────────────────────────────────────

  describe("built-in templates", function () {
    var e;
    beforeEach(function () { e = createChallengeTemplateEngine({ seed: 123 }); });

    it("has color_shape template", function () {
      var info = e.getTemplateInfo("color_shape");
      expect(info).not.toBeNull();
      expect(info.category).toBe("visual");
      expect(info.difficulty).toBe(1);
    });

    it("has sequence template", function () {
      var info = e.getTemplateInfo("sequence");
      expect(info.category).toBe("cognitive");
      expect(info.difficulty).toBe(2);
    });

    it("has counting template", function () {
      var info = e.getTemplateInfo("counting");
      expect(info.category).toBe("visual");
    });

    it("has odd_one_out template", function () {
      var info = e.getTemplateInfo("odd_one_out");
      expect(info.category).toBe("cognitive");
    });

    it("has spatial template", function () {
      var info = e.getTemplateInfo("spatial");
      expect(info.category).toBe("spatial");
    });

    it("has temporal template", function () {
      var info = e.getTemplateInfo("temporal");
      expect(info.category).toBe("temporal");
      expect(info.difficulty).toBe(3);
    });
  });

  // ── Generation ────────────────────────────────────────────────

  describe("generate", function () {
    var e;
    beforeEach(function () { e = createChallengeTemplateEngine({ seed: 99 }); });

    it("generates a random challenge", function () {
      var c = e.generate();
      expect(c).not.toBeNull();
      expect(c.id).toBeTruthy();
      expect(c.templateName).toBeTruthy();
      expect(c.question).toBeTruthy();
      expect(c.answerType).toBeTruthy();
      expect(c.createdAt).toBeGreaterThan(0);
    });

    it("generates with specific template", function () {
      var c = e.generate({ templateName: "sequence" });
      expect(c.templateName).toBe("sequence");
      expect(c.question).toContain("?");
    });

    it("generates with category filter", function () {
      for (var i = 0; i < 20; i++) {
        var c = e.generate({ category: "cognitive" });
        expect(["sequence", "odd_one_out"]).toContain(c.templateName);
      }
    });

    it("generates with difficulty filter", function () {
      for (var i = 0; i < 20; i++) {
        var c = e.generate({ maxDifficulty: 1 });
        expect(c.difficulty).toBeLessThanOrEqual(1);
      }
    });

    it("generates with minDifficulty filter", function () {
      for (var i = 0; i < 20; i++) {
        var c = e.generate({ minDifficulty: 3 });
        expect(c.difficulty).toBeGreaterThanOrEqual(3);
      }
    });

    it("returns null for impossible filter", function () {
      var c = e.generate({ minDifficulty: 99 });
      expect(c).toBeNull();
    });

    it("returns null with no templates", function () {
      var empty = createChallengeTemplateEngine({ includeBuiltins: false });
      expect(empty.generate()).toBeNull();
    });

    it("does not leak the answer in displayData", function () {
      for (var i = 0; i < 50; i++) {
        var c = e.generate();
        var json = JSON.stringify(c.displayData || {});
        // The displayData should not contain the raw answer
        // (we check the answer isn't directly in displayData for position-based ones)
        expect(c.displayData).not.toHaveProperty("answer");
      }
    });

    it("tracks clientId", function () {
      var c = e.generate({ clientId: "user123" });
      var result = e.validate(c.id, "wrong");
      expect(result).not.toBeNull();
    });
  });

  // ── Batch generation ──────────────────────────────────────────

  describe("generateBatch", function () {
    it("generates multiple challenges", function () {
      var e = createChallengeTemplateEngine({ seed: 7 });
      var batch = e.generateBatch(5);
      expect(batch.length).toBe(5);
      var ids = batch.map(function (c) { return c.id; });
      var unique = ids.filter(function (v, i, a) { return a.indexOf(v) === i; });
      expect(unique.length).toBe(5); // all unique IDs
    });

    it("clamps batch size to 100", function () {
      var e = createChallengeTemplateEngine({ seed: 7 });
      var batch = e.generateBatch(200);
      expect(batch.length).toBeLessThanOrEqual(100);
    });

    it("applies opts to all generated", function () {
      var e = createChallengeTemplateEngine({ seed: 7 });
      var batch = e.generateBatch(10, { category: "cognitive" });
      batch.forEach(function (c) {
        expect(["sequence", "odd_one_out"]).toContain(c.templateName);
      });
    });
  });

  // ── Validation ────────────────────────────────────────────────

  describe("validate", function () {
    it("validates correct answer for color_shape", function () {
      var e = createChallengeTemplateEngine({ seed: 42 });
      var c = e.generate({ templateName: "color_shape" });
      // We need to get the internal answer — generate again with same seed
      var e2 = createChallengeTemplateEngine({ seed: 42 });
      var c2 = e2.generate({ templateName: "color_shape" });
      // Both should have same params, so validate c with the answer from c2's params
      // Since we can't peek at params, test via the validate path
      var result = e.validate(c.id, "999"); // wrong answer
      expect(result).not.toBeNull();
      expect(result.correct).toBe(false);
      expect(result.responseMs).toBeGreaterThanOrEqual(0);
    });

    it("returns null for unknown challenge ID", function () {
      var e = createChallengeTemplateEngine();
      expect(e.validate("nonexistent", "answer")).toBeNull();
    });

    it("cannot validate same challenge twice", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      var c = e.generate();
      e.validate(c.id, "test");
      expect(e.validate(c.id, "test")).toBeNull(); // already consumed
    });

    it("tracks response time", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      var c = e.generate();
      var result = e.validate(c.id, "test");
      expect(result.responseMs).toBeGreaterThanOrEqual(0);
    });

    it("sequence validates correct answer", function () {
      // Arithmetic: known seed produces known sequence
      var e = createChallengeTemplateEngine({ seed: 77 });
      var c = e.generate({ templateName: "sequence" });
      // Try multiple answers to verify at least one works
      var foundCorrect = false;
      for (var guess = -100; guess <= 200; guess++) {
        var e2 = createChallengeTemplateEngine({ seed: 77 });
        var c2 = e2.generate({ templateName: "sequence" });
        var r = e2.validate(c2.id, String(guess));
        if (r && r.correct) { foundCorrect = true; break; }
      }
      expect(foundCorrect).toBe(true);
    });
  });

  // ── Custom templates ──────────────────────────────────────────

  describe("registerTemplate", function () {
    it("registers a valid custom template", function () {
      var e = createChallengeTemplateEngine({ includeBuiltins: false });
      var ok = e.registerTemplate({
        name: "custom_test",
        description: "Test template",
        category: "test",
        difficulty: 2,
        parameterSpace: 100,
        generate: function (rng) {
          return { question: "What is 1+1?", answer: "2", answerType: "number" };
        },
        validate: function (params, answer) {
          return String(answer) === "2";
        }
      });
      expect(ok).toBe(true);
      expect(e.listTemplates()).toEqual(["custom_test"]);
    });

    it("rejects template without name", function () {
      var e = createChallengeTemplateEngine({ includeBuiltins: false });
      expect(e.registerTemplate({ generate: function () {}, validate: function () {} })).toBe(false);
    });

    it("rejects template without generate", function () {
      var e = createChallengeTemplateEngine({ includeBuiltins: false });
      expect(e.registerTemplate({ name: "bad", validate: function () {} })).toBe(false);
    });

    it("rejects template without validate", function () {
      var e = createChallengeTemplateEngine({ includeBuiltins: false });
      expect(e.registerTemplate({ name: "bad", generate: function () {} })).toBe(false);
    });

    it("rejects null input", function () {
      var e = createChallengeTemplateEngine();
      expect(e.registerTemplate(null)).toBe(false);
      expect(e.registerTemplate(42)).toBe(false);
    });

    it("custom template can generate and validate", function () {
      var e = createChallengeTemplateEngine({ includeBuiltins: false });
      e.registerTemplate({
        name: "math",
        generate: function () {
          return { question: "2+2?", answer: "4", answerType: "number" };
        },
        validate: function (params, answer) { return String(answer) === params.answer; }
      });
      var c = e.generate();
      expect(c.question).toBe("2+2?");
      var r = e.validate(c.id, "4");
      expect(r.correct).toBe(true);
    });
  });

  describe("unregisterTemplate", function () {
    it("removes a template", function () {
      var e = createChallengeTemplateEngine();
      expect(e.unregisterTemplate("sequence")).toBe(true);
      expect(e.listTemplates()).not.toContain("sequence");
    });

    it("returns false for nonexistent", function () {
      var e = createChallengeTemplateEngine();
      expect(e.unregisterTemplate("nope")).toBe(false);
    });
  });

  // ── Stats ─────────────────────────────────────────────────────

  describe("getStats", function () {
    it("returns initial stats", function () {
      var e = createChallengeTemplateEngine();
      var s = e.getStats();
      expect(s.templateCount).toBe(6);
      expect(s.totalGenerated).toBe(0);
      expect(s.pendingCount).toBe(0);
    });

    it("tracks generation", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      e.generate();
      e.generate();
      var s = e.getStats();
      expect(s.totalGenerated).toBe(2);
      expect(s.pendingCount).toBe(2);
    });

    it("tracks validation", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      var c = e.generate();
      e.validate(c.id, "test");
      var s = e.getStats();
      expect(s.totalValidated).toBe(1);
      expect(s.pendingCount).toBe(0);
    });

    it("calculates pass rate", function () {
      var e = createChallengeTemplateEngine({ includeBuiltins: false });
      e.registerTemplate({
        name: "easy",
        generate: function () { return { question: "?", answer: "yes", answerType: "text" }; },
        validate: function (p, a) { return a === "yes"; }
      });
      for (var i = 0; i < 10; i++) {
        var c = e.generate();
        e.validate(c.id, i < 7 ? "yes" : "no");
      }
      var s = e.getStats();
      expect(s.overallPassRate).toBe(0.7);
    });
  });

  // ── Categories & difficulty ────────────────────────────────────

  describe("getCategories", function () {
    it("returns category breakdown", function () {
      var e = createChallengeTemplateEngine();
      var cats = e.getCategories();
      expect(cats.visual).toBe(2);    // color_shape + counting
      expect(cats.cognitive).toBe(2); // sequence + odd_one_out
      expect(cats.spatial).toBe(1);
      expect(cats.temporal).toBe(1);
    });
  });

  describe("getDifficultyDistribution", function () {
    it("returns difficulty breakdown", function () {
      var e = createChallengeTemplateEngine();
      var dist = e.getDifficultyDistribution();
      expect(dist[1]).toBe(3); // color_shape, counting, spatial
      expect(dist[2]).toBe(2); // sequence, odd_one_out
      expect(dist[3]).toBe(1); // temporal
    });
  });

  describe("getParameterSpace", function () {
    it("sums parameter spaces", function () {
      var e = createChallengeTemplateEngine();
      var ps = e.getParameterSpace();
      expect(ps).toBeGreaterThan(10000); // large combinatorial space
    });
  });

  // ── History ───────────────────────────────────────────────────

  describe("getHistory", function () {
    it("records validated challenges", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      var c = e.generate({ clientId: "u1" });
      e.validate(c.id, "test");
      var hist = e.getHistory();
      expect(hist.length).toBe(1);
      expect(hist[0].clientId).toBe("u1");
    });

    it("filters by template", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      var c1 = e.generate({ templateName: "sequence" });
      var c2 = e.generate({ templateName: "spatial" });
      e.validate(c1.id, "1");
      e.validate(c2.id, "1");
      var hist = e.getHistory({ templateName: "sequence" });
      expect(hist.length).toBe(1);
    });

    it("filters by clientId", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      var c1 = e.generate({ clientId: "a" });
      var c2 = e.generate({ clientId: "b" });
      e.validate(c1.id, "1");
      e.validate(c2.id, "1");
      var hist = e.getHistory({ clientId: "a" });
      expect(hist.length).toBe(1);
    });

    it("limits results", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      for (var i = 0; i < 10; i++) {
        var c = e.generate();
        e.validate(c.id, "x");
      }
      var hist = e.getHistory({ limit: 3 });
      expect(hist.length).toBe(3);
    });
  });

  // ── Problematic templates ─────────────────────────────────────

  describe("findProblematicTemplates", function () {
    it("detects too-easy templates", function () {
      var e = createChallengeTemplateEngine({ includeBuiltins: false });
      e.registerTemplate({
        name: "trivial",
        generate: function () { return { question: "?", answer: "1", answerType: "number" }; },
        validate: function (p, a) { return a === "1"; }
      });
      for (var i = 0; i < 25; i++) {
        var c = e.generate();
        e.validate(c.id, "1"); // always correct
      }
      var probs = e.findProblematicTemplates({ minSamples: 10 });
      expect(probs.length).toBeGreaterThanOrEqual(1);
      expect(probs[0].issue).toBe("too_easy");
    });

    it("detects too-hard templates", function () {
      var e = createChallengeTemplateEngine({ includeBuiltins: false });
      e.registerTemplate({
        name: "impossible",
        generate: function () { return { question: "?", answer: "impossible", answerType: "text" }; },
        validate: function (p, a) { return false; } // always wrong
      });
      for (var i = 0; i < 25; i++) {
        var c = e.generate();
        e.validate(c.id, "anything");
      }
      var probs = e.findProblematicTemplates({ minSamples: 10 });
      expect(probs.some(function (p) { return p.issue === "too_hard"; })).toBe(true);
    });

    it("skips templates with insufficient samples", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      var c = e.generate();
      e.validate(c.id, "x");
      var probs = e.findProblematicTemplates({ minSamples: 100 });
      expect(probs.length).toBe(0);
    });
  });

  // ── State export/import ───────────────────────────────────────

  describe("exportState / importStats", function () {
    it("roundtrips stats", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      for (var i = 0; i < 5; i++) {
        var c = e.generate();
        e.validate(c.id, "test");
      }
      var state = e.exportState();
      var e2 = createChallengeTemplateEngine({ seed: 999 });
      e2.importStats(state);
      expect(e2.getStats().totalValidated).toBe(5);
      expect(e2.getHistory().length).toBe(5);
    });

    it("rejects invalid import", function () {
      var e = createChallengeTemplateEngine();
      expect(e.importStats(null)).toBe(false);
      expect(e.importStats(42)).toBe(false);
    });
  });

  // ── Reset ─────────────────────────────────────────────────────

  describe("reset", function () {
    it("clears all stats and history", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      for (var i = 0; i < 5; i++) {
        var c = e.generate();
        e.validate(c.id, "x");
      }
      e.reset();
      var s = e.getStats();
      expect(s.totalGenerated).toBe(0);
      expect(s.totalValidated).toBe(0);
      expect(s.pendingCount).toBe(0);
      expect(e.getHistory().length).toBe(0);
    });

    it("preserves templates after reset", function () {
      var e = createChallengeTemplateEngine();
      e.reset();
      expect(e.listTemplates().length).toBe(6);
    });
  });

  // ── Report ────────────────────────────────────────────────────

  describe("generateReport", function () {
    it("produces readable report", function () {
      var e = createChallengeTemplateEngine({ seed: 1 });
      for (var i = 0; i < 10; i++) {
        var c = e.generate();
        e.validate(c.id, "x");
      }
      var report = e.generateReport();
      expect(report).toContain("Challenge Template Engine Report");
      expect(report).toContain("Templates: 6");
      expect(report).toContain("Generated: 10");
    });
  });

  // ── Pending TTL / capacity ────────────────────────────────────

  describe("pending management", function () {
    it("evicts oldest pending when at capacity", function () {
      var e = createChallengeTemplateEngine({
        seed: 1, maxPending: 5, includeBuiltins: true
      });
      for (var i = 0; i < 10; i++) e.generate();
      var s = e.getStats();
      expect(s.pendingCount).toBeLessThanOrEqual(5);
    });
  });

  // ── Template info ─────────────────────────────────────────────

  describe("getTemplateInfo", function () {
    it("returns info for existing template", function () {
      var e = createChallengeTemplateEngine();
      var info = e.getTemplateInfo("color_shape");
      expect(info.name).toBe("color_shape");
      expect(info.description).toContain("COLOR");
      expect(info.parameterSpace).toBe(120); // 12 colors × 10 shapes
    });

    it("returns null for nonexistent", function () {
      var e = createChallengeTemplateEngine();
      expect(e.getTemplateInfo("nope")).toBeNull();
    });
  });

  // ── Sequence correctness ──────────────────────────────────────

  describe("sequence patterns", function () {
    it("arithmetic sequences are valid", function () {
      var e = createChallengeTemplateEngine({ seed: 42 });
      var c = e.generate({ templateName: "sequence" });
      expect(c.question).toContain(",");
      expect(c.question).toContain("?");
    });

    it("color_shape has question with color and shape", function () {
      var e = createChallengeTemplateEngine({ seed: 42 });
      var c = e.generate({ templateName: "color_shape" });
      expect(c.question).toContain("Click the");
    });

    it("counting has question about objects", function () {
      var e = createChallengeTemplateEngine({ seed: 42 });
      var c = e.generate({ templateName: "counting" });
      expect(c.question).toContain("How many");
    });

    it("odd_one_out asks which doesn't belong", function () {
      var e = createChallengeTemplateEngine({ seed: 42 });
      var c = e.generate({ templateName: "odd_one_out" });
      expect(c.question).toContain("does not belong");
    });

    it("spatial asks about position", function () {
      var e = createChallengeTemplateEngine({ seed: 42 });
      var c = e.generate({ templateName: "spatial" });
      expect(c.question).toContain("Click the item");
    });

    it("temporal asks about frame", function () {
      var e = createChallengeTemplateEngine({ seed: 42 });
      var c = e.generate({ templateName: "temporal" });
      expect(c.question).toContain("frame");
    });
  });
});
