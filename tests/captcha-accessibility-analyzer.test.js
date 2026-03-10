var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var { createAccessibilityAnalyzer } = require("../src/captcha-accessibility-analyzer.js");

describe("createAccessibilityAnalyzer", function () {
  it("returns expected API", function () {
    var a = createAccessibilityAnalyzer();
    assert.equal(typeof a.registerChallenge, "function");
    assert.equal(typeof a.analyze, "function");
    assert.equal(typeof a.quickAudit, "function");
  });
  it("defaults to WCAG_AA", function () {
    assert.equal(createAccessibilityAnalyzer().getConfig().standard, "WCAG_AA");
  });
  it("accepts custom standard", function () {
    assert.equal(createAccessibilityAnalyzer({ standard: "WCAG_AAA" }).getConfig().standard, "WCAG_AAA");
  });
});

describe("registerChallenge", function () {
  it("stores and retrieves", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "c1", type: "image" });
    assert.equal(a.getChallenge("c1").type, "image");
  });
  it("throws without id", function () {
    assert.throws(function () { createAccessibilityAnalyzer().registerChallenge({}); }, /id/);
  });
  it("lists all", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "c1" }); a.registerChallenge({ id: "c2" });
    assert.equal(a.listChallenges().length, 2);
  });
  it("removes", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "c1" });
    assert.ok(a.removeChallenge("c1"));
    assert.equal(a.getChallenge("c1"), null);
  });
  it("remove unknown returns false", function () {
    assert.equal(createAccessibilityAnalyzer().removeChallenge("x"), false);
  });
});

describe("analyze — empty", function () {
  it("passes with no challenges", function () {
    var r = createAccessibilityAnalyzer().analyze();
    assert.equal(r.challengeCount, 0);
    assert.equal(r.score, 100);
    assert.ok(r.passed);
  });
});

describe("analyze — alternatives", function () {
  it("flags visual-only without alt", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "v1", type: "image", visualOnly: true });
    var r = a.analyze();
    assert.ok(r.findings.some(function (f) { return f.criterion === "alternatives" && f.severity === "critical"; }));
  });
  it("passes with audio alt", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "v1", type: "image", hasAudioAlternative: true });
    var crit = a.analyze().findings.filter(function (f) { return f.criterion === "alternatives" && f.severity === "critical"; });
    assert.equal(crit.length, 0);
  });
});

describe("analyze — cognitive load", function () {
  it("flags complex puzzle", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "p1", type: "puzzle", complexity: 8, steps: 3 });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "cognitiveLoad"; }));
  });
  it("flags cultural knowledge", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "c1", type: "image", requiresCulturalKnowledge: true });
    assert.ok(a.analyze().findings.some(function (f) { return f.message.indexOf("cultural") >= 0; }));
  });
});

describe("analyze — time limit", function () {
  it("flags too-short time", function () {
    var a = createAccessibilityAnalyzer({ standard: "WCAG_AA" });
    a.registerChallenge({ id: "t1", type: "text", timeLimitSeconds: 15 });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "timeLimit" && f.severity === "major"; }));
  });
  it("passes with sufficient time", function () {
    var a = createAccessibilityAnalyzer({ standard: "WCAG_A" });
    a.registerChallenge({ id: "t1", type: "text", timeLimitSeconds: 120 });
    var majors = a.analyze().findings.filter(function (f) { return f.criterion === "timeLimit" && f.severity === "major"; });
    assert.equal(majors.length, 0);
  });
});

describe("analyze — keyboard", function () {
  it("flags drag as poorly accessible", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "d1", type: "drag", keyboardNavigable: false });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "keyboardNav" && f.severity === "critical"; }));
  });
  it("flags no focus indicator", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "f1", type: "image", focusVisible: false });
    assert.ok(a.analyze().findings.some(function (f) { return f.message.indexOf("focus") >= 0; }));
  });
});

describe("analyze — color contrast", function () {
  it("flags low contrast", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "cc1", type: "text", foregroundColor: "#999", backgroundColor: "#AAA" });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "colorContrast"; }));
  });
  it("passes with good contrast", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "cc2", type: "text", foregroundColor: "#000", backgroundColor: "#FFF" });
    var fails = a.analyze().findings.filter(function (f) { return f.criterion === "colorContrast"; });
    assert.equal(fails.length, 0);
  });
});

describe("analyze — screen reader", function () {
  it("flags missing ARIA", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "s1", type: "image" });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "screenReader" && f.message.indexOf("ARIA") >= 0; }));
  });
  it("passes with full ARIA", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "s2", type: "text", ariaLabel: "CAPTCHA", roleAttribute: "group", liveRegion: true });
    var crit = a.analyze().findings.filter(function (f) { return f.criterion === "screenReader" && f.severity === "critical"; });
    assert.equal(crit.length, 0);
  });
});

describe("analyze — motor skill", function () {
  it("flags high-precision drag", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "m1", type: "drag", precision: "high" });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "motorSkill" && f.severity === "major"; }));
  });
  it("flags small target", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "m2", type: "click", targetSize: 20 });
    assert.ok(a.analyze().findings.some(function (f) { return f.message.indexOf("Target size") >= 0; }));
  });
});

describe("analyze — instructions & errors", function () {
  it("flags missing instructions", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "i1", type: "image" });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "instructions"; }));
  });
  it("flags missing error message", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "e1", type: "image" });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "errorRecovery"; }));
  });
  it("flags no retries", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "e2", type: "image", retryAllowed: false });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "errorRecovery" && f.message.indexOf("retri") >= 0; }));
  });
});

describe("report structure", function () {
  it("includes required fields", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "x", type: "text" });
    var r = a.analyze();
    assert.ok(r.timestamp); assert.equal(r.standard, "WCAG_AA");
    assert.equal(typeof r.score, "number"); assert.ok(r.criterionScores);
    assert.ok(Array.isArray(r.findings)); assert.ok(r.summary);
  });
  it("well-configured challenge scores high", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({
      id: "good", type: "text", hasAudioAlternative: true, hasTextAlternative: true,
      instructions: "Type the word", errorMessage: "Wrong", ariaLabel: "CAPTCHA",
      roleAttribute: "group", liveRegion: true, foregroundColor: "#000", backgroundColor: "#FFF"
    });
    var r = a.analyze();
    assert.ok(r.score >= 70);
  });
});

describe("quickAudit", function () {
  it("analyzes without persisting", function () {
    var a = createAccessibilityAnalyzer();
    var r = a.quickAudit({ type: "drag", precision: "high", visualOnly: true });
    assert.equal(r.challengeCount, 1);
    assert.equal(a.listChallenges().length, 0);
  });
});

describe("compareReports", function () {
  it("detects improvement", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "c1", type: "image", visualOnly: true });
    var r1 = a.analyze();
    a.removeChallenge("c1");
    a.registerChallenge({ id: "c1", type: "image", hasAudioAlternative: true, ariaLabel: "CAPTCHA", instructions: "Click", errorMessage: "Wrong" });
    var r2 = a.analyze();
    var cmp = a.compareReports(r1, r2);
    assert.ok(cmp.improved);
    assert.ok(cmp.scoreDelta > 0);
  });
  it("null reports returns null", function () {
    assert.equal(createAccessibilityAnalyzer().compareReports(null, null), null);
  });
});

describe("history", function () {
  it("tracks runs", function () {
    var a = createAccessibilityAnalyzer();
    a.analyze(); a.analyze();
    assert.equal(a.getHistory().length, 2);
  });
});

describe("exportJSON", function () {
  it("returns valid JSON", function () {
    var a = createAccessibilityAnalyzer();
    a.registerChallenge({ id: "c1" }); a.analyze();
    var p = JSON.parse(a.exportJSON());
    assert.ok(p.config); assert.ok(p.challenges);
  });
});

describe("utils", function () {
  it("contrastRatio black/white ~21", function () {
    var r = createAccessibilityAnalyzer().utils.contrastRatio("#000", "#FFF");
    assert.ok(r >= 20.5 && r <= 21.1);
  });
  it("contrastRatio same = 1", function () {
    assert.equal(createAccessibilityAnalyzer().utils.contrastRatio("#F00", "#F00"), 1);
  });
  it("parseHex 6-char", function () {
    assert.deepEqual(createAccessibilityAnalyzer().utils.parseHex("#FF8000"), { r: 255, g: 128, b: 0 });
  });
  it("parseHex invalid null", function () {
    assert.equal(createAccessibilityAnalyzer().utils.parseHex("nope"), null);
  });
  it("cognitiveLoad checkbox low", function () {
    assert.ok(createAccessibilityAnalyzer().utils.cognitiveLoadScore({ type: "checkbox" }) <= 20);
  });
  it("cognitiveLoad puzzle high", function () {
    assert.ok(createAccessibilityAnalyzer().utils.cognitiveLoadScore({ type: "puzzle", complexity: 8, steps: 3 }) >= 60);
  });
  it("keyboardScore text = 100", function () {
    assert.equal(createAccessibilityAnalyzer().utils.keyboardScore({ type: "text" }), 100);
  });
  it("keyboardScore drag < 70", function () {
    assert.ok(createAccessibilityAnalyzer().utils.keyboardScore({ type: "drag" }) <= 70);
  });
  it("motorScore checkbox low", function () {
    assert.ok(createAccessibilityAnalyzer().utils.motorScore({ type: "checkbox" }) <= 10);
  });
  it("motorScore drag+precision high", function () {
    assert.ok(createAccessibilityAnalyzer().utils.motorScore({ type: "drag", precision: "high" }) >= 50);
  });
  it("screenReader full ARIA high", function () {
    assert.ok(createAccessibilityAnalyzer().utils.screenReaderScore({ ariaLabel: "x", roleAttribute: "g", liveRegion: true }) >= 90);
  });
  it("screenReader visual-only canvas low", function () {
    assert.ok(createAccessibilityAnalyzer().utils.screenReaderScore({ type: "image", usesCanvas: true, visualOnly: true }) <= 30);
  });
});

describe("custom rules", function () {
  it("includes custom findings", function () {
    var a = createAccessibilityAnalyzer({
      customRules: [function (cs) { return cs.map(function (c) { return { criterion: "custom", severity: "info", challenge: c.id, message: "Custom" }; }); }]
    });
    a.registerChallenge({ id: "c1" });
    assert.ok(a.analyze().findings.some(function (f) { return f.criterion === "custom"; }));
  });
});

describe("scoring modes", function () {
  it("equal mode works", function () {
    var a = createAccessibilityAnalyzer({ scoringMode: "equal" });
    a.registerChallenge({ id: "c1", type: "checkbox", ariaLabel: "x" });
    var r = a.analyze();
    assert.ok(r.score > 0);
  });
});
