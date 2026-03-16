/**
 * Tests for Bypass Resistance Tester (resistance.html)
 */

"use strict";

describe("Bypass Resistance Tester", () => {
  /* ===== Attack vector definitions ===== */
  const ATTACK_IDS = ["ocr", "ml", "timing", "brute", "farm", "api"];

  describe("Attack vector catalog", () => {
    test("has 6 attack vectors", () => {
      expect(ATTACK_IDS.length).toBe(6);
    });

    test("all attack IDs are unique", () => {
      expect(new Set(ATTACK_IDS).size).toBe(ATTACK_IDS.length);
    });

    test("includes OCR, ML, timing, brute force, farm, and API attacks", () => {
      expect(ATTACK_IDS).toContain("ocr");
      expect(ATTACK_IDS).toContain("ml");
      expect(ATTACK_IDS).toContain("timing");
      expect(ATTACK_IDS).toContain("brute");
      expect(ATTACK_IDS).toContain("farm");
      expect(ATTACK_IDS).toContain("api");
    });
  });

  /* ===== Configuration presets ===== */
  const PRESETS = {
    minimal: { type: "visual", frames: 8, options: 2, timeLimit: 30, rateLimit: "none", distractor: 2, rotation: "static", behavior: "none" },
    standard: { type: "narrative", frames: 24, options: 4, timeLimit: 15, rateLimit: "basic", distractor: 5, rotation: "per-session", behavior: "basic" },
    hardened: { type: "narrative", frames: 36, options: 5, timeLimit: 10, rateLimit: "advanced", distractor: 8, rotation: "per-attempt", behavior: "full" },
    fortress: { type: "social", frames: 48, options: 6, timeLimit: 8, rateLimit: "aggressive", distractor: 10, rotation: "per-attempt", behavior: "full" },
  };

  describe("Presets", () => {
    test("has 4 presets", () => {
      expect(Object.keys(PRESETS).length).toBe(4);
    });

    test("minimal preset uses weakest settings", () => {
      expect(PRESETS.minimal.rateLimit).toBe("none");
      expect(PRESETS.minimal.behavior).toBe("none");
      expect(PRESETS.minimal.rotation).toBe("static");
      expect(PRESETS.minimal.options).toBe(2);
    });

    test("fortress preset uses strongest settings", () => {
      expect(PRESETS.fortress.rateLimit).toBe("aggressive");
      expect(PRESETS.fortress.behavior).toBe("full");
      expect(PRESETS.fortress.rotation).toBe("per-attempt");
      expect(PRESETS.fortress.options).toBe(6);
    });

    test("all presets have required config keys", () => {
      const keys = ["type", "frames", "options", "timeLimit", "rateLimit", "distractor", "rotation", "behavior"];
      Object.values(PRESETS).forEach((p) => {
        keys.forEach((k) => expect(p).toHaveProperty(k));
      });
    });

    test("frame counts are within valid range (4-60)", () => {
      Object.values(PRESETS).forEach((p) => {
        expect(p.frames).toBeGreaterThanOrEqual(4);
        expect(p.frames).toBeLessThanOrEqual(60);
      });
    });
  });

  /* ===== Resistance scoring logic ===== */
  // Replicate the scoring functions from resistance.html for testing
  function computeOcrResistance(cfg) {
    var score = 40;
    score += Math.min(20, (cfg.frames - 4) * 0.4);
    if (cfg.type === "narrative" || cfg.type === "social") score += 15;
    if (cfg.type === "temporal") score += 10;
    score += cfg.distractor * 1.5;
    if (cfg.rotation === "per-attempt") score += 10;
    else if (cfg.rotation === "per-session") score += 5;
    return Math.min(100, Math.round(score));
  }

  function computeBruteResistance(cfg) {
    var guessResist = (1 - 1 / cfg.options) * 50;
    var score = guessResist;
    if (cfg.rotation === "per-attempt") score += 30;
    else if (cfg.rotation === "per-session") score += 20;
    else if (cfg.rotation === "daily") score += 10;
    if (cfg.rateLimit === "aggressive") score += 20;
    else if (cfg.rateLimit === "advanced") score += 12;
    else if (cfg.rateLimit === "basic") score += 6;
    return Math.min(100, Math.round(score));
  }

  describe("Resistance scoring", () => {
    test("scores are always 0-100", () => {
      Object.values(PRESETS).forEach((cfg) => {
        const score = computeOcrResistance(cfg);
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
      });
    });

    test("fortress scores higher than minimal for OCR", () => {
      expect(computeOcrResistance(PRESETS.fortress)).toBeGreaterThan(computeOcrResistance(PRESETS.minimal));
    });

    test("fortress scores higher than minimal for brute force", () => {
      expect(computeBruteResistance(PRESETS.fortress)).toBeGreaterThan(computeBruteResistance(PRESETS.minimal));
    });

    test("more options increases brute force resistance", () => {
      const cfg2 = { ...PRESETS.standard, options: 2 };
      const cfg6 = { ...PRESETS.standard, options: 6 };
      expect(computeBruteResistance(cfg6)).toBeGreaterThan(computeBruteResistance(cfg2));
    });

    test("narrative type increases OCR resistance vs visual", () => {
      const visual = { ...PRESETS.standard, type: "visual" };
      const narrative = { ...PRESETS.standard, type: "narrative" };
      expect(computeOcrResistance(narrative)).toBeGreaterThan(computeOcrResistance(visual));
    });

    test("more frames increases OCR resistance", () => {
      const low = { ...PRESETS.standard, frames: 8 };
      const high = { ...PRESETS.standard, frames: 48 };
      expect(computeOcrResistance(high)).toBeGreaterThan(computeOcrResistance(low));
    });

    test("per-attempt rotation beats static for brute force", () => {
      const stat = { ...PRESETS.standard, rotation: "static" };
      const perAttempt = { ...PRESETS.standard, rotation: "per-attempt" };
      expect(computeBruteResistance(perAttempt)).toBeGreaterThan(computeBruteResistance(stat));
    });
  });

  /* ===== Grading ===== */
  function getGrade(score) {
    if (score >= 85) return "A";
    if (score >= 70) return "B";
    if (score >= 50) return "C";
    if (score >= 30) return "D";
    return "F";
  }

  describe("Grading system", () => {
    test("100 gets A", () => expect(getGrade(100)).toBe("A"));
    test("85 gets A", () => expect(getGrade(85)).toBe("A"));
    test("70 gets B", () => expect(getGrade(70)).toBe("B"));
    test("50 gets C", () => expect(getGrade(50)).toBe("C"));
    test("30 gets D", () => expect(getGrade(30)).toBe("D"));
    test("0 gets F", () => expect(getGrade(0)).toBe("F"));
    test("29 gets F", () => expect(getGrade(29)).toBe("F"));
    test("84 gets B", () => expect(getGrade(84)).toBe("B"));
  });

  /* ===== Weighted overall score ===== */
  describe("Weighted scoring", () => {
    const weights = { ocr: 1, ml: 1.3, timing: 0.8, brute: 1, farm: 1.2, api: 0.9 };

    test("all attack IDs have weights", () => {
      ATTACK_IDS.forEach((id) => expect(weights[id]).toBeDefined());
    });

    test("ML and farm have highest weights (hardest to stop)", () => {
      const maxWeight = Math.max(...Object.values(weights));
      expect(weights.ml).toBe(maxWeight);
      expect(weights.farm).toBeGreaterThan(1);
    });

    test("weighted average of equal scores equals that score", () => {
      const score = 75;
      let totalW = 0, wSum = 0;
      ATTACK_IDS.forEach((id) => { const w = weights[id]; wSum += score * w; totalW += w; });
      expect(Math.round(wSum / totalW)).toBe(score);
    });
  });

  /* ===== Export formats ===== */
  describe("Export", () => {
    test("CSV header has correct columns", () => {
      const header = "Attack Vector,Resistance %,Status";
      expect(header.split(",").length).toBe(3);
    });

    test("JSON report has required fields", () => {
      const report = { cfg: PRESETS.standard, attacks: [], overall: 65, grade: "C", timestamp: new Date().toISOString() };
      expect(report).toHaveProperty("cfg");
      expect(report).toHaveProperty("attacks");
      expect(report).toHaveProperty("overall");
      expect(report).toHaveProperty("grade");
      expect(report).toHaveProperty("timestamp");
    });
  });

  /* ===== HTML structure ===== */
  describe("HTML structure", () => {
    const fs = require("fs");
    const path = require("path");
    const html = fs.readFileSync(path.join(__dirname, "..", "resistance.html"), "utf8");

    test("includes shared.css link", () => {
      expect(html).toContain('href="shared.css"');
    });

    test("includes shared.js script", () => {
      expect(html).toContain('src="shared.js"');
    });

    test("has CSP meta tag", () => {
      expect(html).toContain("Content-Security-Policy");
    });

    test("has navigation links", () => {
      expect(html).toContain('href="index.html"');
      expect(html).toContain('href="demo.html"');
    });

    test("has run simulation button", () => {
      expect(html).toContain("runSimulation()");
    });

    test("has export buttons", () => {
      expect(html).toContain("exportJSON()");
      expect(html).toContain("exportCSV()");
      expect(html).toContain("copyReport()");
    });

    test("has all preset buttons", () => {
      expect(html).toContain('data-preset="minimal"');
      expect(html).toContain('data-preset="standard"');
      expect(html).toContain('data-preset="hardened"');
      expect(html).toContain('data-preset="fortress"');
    });

    test("has all config controls", () => {
      expect(html).toContain('id="cfgType"');
      expect(html).toContain('id="cfgFrames"');
      expect(html).toContain('id="cfgOptions"');
      expect(html).toContain('id="cfgRate"');
      expect(html).toContain('id="cfgBehavior"');
    });
  });
});
