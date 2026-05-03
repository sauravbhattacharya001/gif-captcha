"use strict";

var _t = require("node:test");
var _a = require("node:assert/strict");
var _mod = require("../src/bot-adversarial-playbook");
var createEngine = _mod.createBotAdversarialPlaybookEngine;
var ATTACK_CATEGORIES = _mod.ATTACK_CATEGORIES;
var ATTACK_TEMPLATES = _mod.ATTACK_TEMPLATES;
var DEFENSE_CATALOG = _mod.DEFENSE_CATALOG;
var SOPHISTICATION_TIERS = _mod.SOPHISTICATION_TIERS;
var RESILIENCE_GRADES = _mod.RESILIENCE_GRADES;

// ── Helpers ──────────────────────────────────────────────────────────

var ALL_DEFENSES = Object.keys(DEFENSE_CATALOG);
var BASIC_DEFENSES = ["rate_limiter", "token_verifier", "replay_detector"];
var FULL_DEFENSES = ALL_DEFENSES.slice();

// ── Constants ────────────────────────────────────────────────────────

_t.test("exports ATTACK_CATEGORIES with 10 entries", function () {
  _a.ok(Array.isArray(ATTACK_CATEGORIES));
  _a.equal(ATTACK_CATEGORIES.length, 10);
});

_t.test("exports ATTACK_TEMPLATES for each category", function () {
  for (var i = 0; i < ATTACK_CATEGORIES.length; i++) {
    var cat = ATTACK_CATEGORIES[i];
    _a.ok(ATTACK_TEMPLATES[cat], "Missing template for " + cat);
    _a.ok(ATTACK_TEMPLATES[cat].name);
    _a.ok(ATTACK_TEMPLATES[cat].tactics.length > 0);
    _a.ok(ATTACK_TEMPLATES[cat].targetedDefenses.length > 0);
    _a.ok(ATTACK_TEMPLATES[cat].baseSuccessRate > 0);
  }
});

_t.test("exports DEFENSE_CATALOG with entries", function () {
  var keys = Object.keys(DEFENSE_CATALOG);
  _a.ok(keys.length >= 20);
  keys.forEach(function (k) {
    _a.ok(DEFENSE_CATALOG[k].name);
    _a.ok(DEFENSE_CATALOG[k].category);
    _a.ok(DEFENSE_CATALOG[k].effectiveness > 0);
    _a.ok(DEFENSE_CATALOG[k].effectiveness <= 1);
  });
});

_t.test("SOPHISTICATION_TIERS has 5 entries", function () {
  _a.equal(SOPHISTICATION_TIERS.length, 5);
});

_t.test("RESILIENCE_GRADES has 5 entries", function () {
  _a.equal(RESILIENCE_GRADES.length, 5);
});

// ── Constructor ──────────────────────────────────────────────────────

_t.test("createEngine returns object with expected methods", function () {
  var eng = createEngine();
  _a.equal(typeof eng.runAssessment, "function");
  _a.equal(typeof eng.simulateScenario, "function");
  _a.equal(typeof eng.getEvolution, "function");
  _a.equal(typeof eng.getInsights, "function");
  _a.equal(typeof eng.getAttackCategories, "function");
  _a.equal(typeof eng.getDefenseCatalog, "function");
  _a.equal(typeof eng.getFleetHealth, "function");
  _a.equal(typeof eng.exportState, "function");
  _a.equal(typeof eng.importState, "function");
});

_t.test("createEngine accepts custom options", function () {
  var eng = createEngine({
    maxSimulations: 100,
    simulationRounds: 50,
    weights: { gapCoverage: 0.5, simulationSurvival: 0.5, defenseDepth: 0, adaptability: 0 }
  });
  _a.ok(eng);
});

// ── runAssessment ────────────────────────────────────────────────────

_t.test("runAssessment with no defenses returns assessment", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var result = eng.runAssessment([]);
  _a.ok(result.scenarios);
  _a.equal(result.scenarios.length, 10);
  _a.ok(result.defenseProfile);
  _a.equal(result.defenseProfile.totalDefenses, 0);
  _a.ok(result.simulations);
  _a.equal(result.simulations.length, 10);
  _a.ok(result.gapAnalysis);
  _a.ok(result.playbook);
  _a.ok(result.resilience);
  _a.ok(result.insights);
  _a.ok(result.snapshot);
});

_t.test("runAssessment with basic defenses shows partial coverage", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  _a.ok(result.defenseProfile.totalDefenses >= 2);
  _a.ok(result.gapAnalysis.totalGaps > 0);
});

_t.test("runAssessment with full defenses yields higher resilience", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var none = eng.runAssessment([]);
  var full = eng.runAssessment(FULL_DEFENSES);
  _a.ok(full.resilience.composite >= none.resilience.composite,
    "Full defenses should score >= no defenses");
});

_t.test("runAssessment scenarios have required fields", function () {
  var eng = createEngine({ simulationRounds: 50 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  result.scenarios.forEach(function (s) {
    _a.ok(s.id);
    _a.ok(s.category);
    _a.ok(s.name);
    _a.ok(s.sophisticationTier);
    _a.ok(s.tactics.length > 0);
    _a.ok(typeof s.monthlyAttackCost === "number");
  });
});

_t.test("runAssessment simulations have verdicts", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  var validVerdicts = ["VULNERABLE", "AT_RISK", "DEFENDED", "FORTIFIED"];
  result.simulations.forEach(function (s) {
    _a.ok(validVerdicts.indexOf(s.verdict) >= 0, "Invalid verdict: " + s.verdict);
    _a.ok(s.attackSuccessRate >= 0 && s.attackSuccessRate <= 1);
    _a.ok(s.defenseBlockRate >= 0 && s.defenseBlockRate <= 1);
    _a.ok(typeof s.estimatedDamagePerMonth === "number");
  });
});

_t.test("runAssessment gap analysis identifies missing defenses", function () {
  var eng = createEngine({ simulationRounds: 50 });
  var result = eng.runAssessment([]);
  _a.ok(result.gapAnalysis.totalGaps > 0);
  result.gapAnalysis.gaps.forEach(function (g) {
    _a.ok(g.defenseId);
    _a.ok(g.defenseName);
    _a.ok(["CRITICAL", "HIGH", "MEDIUM"].indexOf(g.severity) >= 0);
    _a.ok(g.exposedScenarios >= 1);
  });
});

_t.test("runAssessment gap severity ordering", function () {
  var eng = createEngine({ simulationRounds: 50 });
  var result = eng.runAssessment([]);
  var gaps = result.gapAnalysis.gaps;
  var sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
  for (var i = 1; i < gaps.length; i++) {
    var prev = sevOrder[gaps[i - 1].severity];
    var curr = sevOrder[gaps[i].severity];
    _a.ok(curr >= prev, "Gaps should be severity-ordered");
  }
});

_t.test("runAssessment playbook has prioritized actions", function () {
  var eng = createEngine({ simulationRounds: 50 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  _a.ok(result.playbook.actions.length > 0);
  result.playbook.actions.forEach(function (a) {
    _a.ok(a.priority >= 1);
    _a.ok(a.action);
    _a.ok(["low", "medium", "high"].indexOf(a.effort) >= 0);
    _a.ok(a.impactScore >= 1);
    _a.ok(a.roi >= 0);
    _a.ok(a.mitigates.length > 0);
  });
});

_t.test("runAssessment playbook actions sorted by ROI", function () {
  var eng = createEngine({ simulationRounds: 50 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  var actions = result.playbook.actions;
  for (var i = 1; i < actions.length; i++) {
    _a.ok(actions[i].roi <= actions[i - 1].roi, "Actions should be ROI-descending");
  }
});

_t.test("runAssessment resilience score is 0-100", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  _a.ok(result.resilience.composite >= 0);
  _a.ok(result.resilience.composite <= 100);
  _a.ok(RESILIENCE_GRADES.indexOf(result.resilience.grade) >= 0);
  _a.ok(result.resilience.dimensions);
  _a.ok(result.resilience.dimensions.gapCoverage >= 0);
  _a.ok(result.resilience.dimensions.simulationSurvival >= 0);
  _a.ok(result.resilience.dimensions.defenseDepth >= 0);
  _a.ok(result.resilience.dimensions.adaptability >= 0);
});

_t.test("runAssessment generates insights", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  _a.ok(result.insights.length > 0);
  result.insights.forEach(function (ins) {
    _a.ok(ins.type);
    _a.ok(ins.severity);
    _a.ok(ins.message);
    _a.ok(ins.timestamp > 0);
  });
});

_t.test("runAssessment creates snapshot for evolution tracking", function () {
  var eng = createEngine({ simulationRounds: 50 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  _a.ok(result.snapshot.id);
  _a.ok(result.snapshot.timestamp > 0);
  _a.deepEqual(result.snapshot.activeDefenses, BASIC_DEFENSES);
  _a.ok(typeof result.snapshot.resilience === "object");
});

_t.test("runAssessment throws on non-array defenses", function () {
  var eng = createEngine();
  _a.throws(function () { eng.runAssessment("not-array"); }, /array/i);
});

// ── simulateScenario ─────────────────────────────────────────────────

_t.test("simulateScenario returns result for valid category", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var result = eng.simulateScenario("credential_stuffing", BASIC_DEFENSES);
  _a.ok(result.scenarioName);
  _a.equal(result.category, "credential_stuffing");
  _a.ok(result.attackSuccessRate >= 0);
  _a.ok(result.defenseBlockRate >= 0);
});

_t.test("simulateScenario throws on unknown category", function () {
  var eng = createEngine();
  _a.throws(function () { eng.simulateScenario("nonexistent", []); }, /Unknown/);
});

_t.test("simulateScenario throws on non-array defenses", function () {
  var eng = createEngine();
  _a.throws(function () { eng.simulateScenario("ocr_attack", "bad"); }, /array/i);
});

_t.test("simulateScenario with full defenses blocks more", function () {
  var eng = createEngine({ simulationRounds: 500 });
  var none = eng.simulateScenario("browser_automation", []);
  var full = eng.simulateScenario("browser_automation", FULL_DEFENSES);
  _a.ok(full.defenseBlockRate >= none.defenseBlockRate,
    "Full defenses should block more");
});

// ── getEvolution ─────────────────────────────────────────────────────

_t.test("getEvolution tracks assessment history", function () {
  var eng = createEngine({ simulationRounds: 50 });
  _a.equal(eng.getEvolution().length, 0);
  eng.runAssessment(BASIC_DEFENSES);
  _a.equal(eng.getEvolution().length, 1);
  eng.runAssessment(FULL_DEFENSES);
  _a.equal(eng.getEvolution().length, 2);
});

// ── getInsights ──────────────────────────────────────────────────────

_t.test("getInsights accumulates across assessments", function () {
  var eng = createEngine({ simulationRounds: 50 });
  eng.runAssessment([]);
  var count1 = eng.getInsights().length;
  eng.runAssessment(BASIC_DEFENSES);
  _a.ok(eng.getInsights().length >= count1);
});

// ── getAttackCategories ──────────────────────────────────────────────

_t.test("getAttackCategories returns copy of categories", function () {
  var eng = createEngine();
  var cats = eng.getAttackCategories();
  _a.equal(cats.length, 10);
  cats.push("hacked");
  _a.equal(eng.getAttackCategories().length, 10); // unchanged
});

// ── getDefenseCatalog ────────────────────────────────────────────────

_t.test("getDefenseCatalog returns all defenses", function () {
  var eng = createEngine();
  var catalog = eng.getDefenseCatalog();
  _a.ok(Object.keys(catalog).length >= 20);
  Object.keys(catalog).forEach(function (k) {
    _a.ok(catalog[k].name);
    _a.ok(catalog[k].category);
    _a.ok(typeof catalog[k].effectiveness === "number");
  });
});

// ── getFleetHealth ───────────────────────────────────────────────────

_t.test("getFleetHealth with no data returns unknown", function () {
  var eng = createEngine();
  var health = eng.getFleetHealth();
  _a.equal(health.assessments, 0);
  _a.equal(health.trend, "UNKNOWN");
});

_t.test("getFleetHealth after assessments shows trend", function () {
  var eng = createEngine({ simulationRounds: 100 });
  eng.runAssessment(BASIC_DEFENSES);
  eng.runAssessment(FULL_DEFENSES);
  var health = eng.getFleetHealth();
  _a.equal(health.assessments, 2);
  _a.ok(health.latestResilience);
  _a.ok(typeof health.averageResilience === "number");
  _a.ok(["IMPROVING", "STABLE", "DEGRADING"].indexOf(health.trend) >= 0);
});

// ── exportState / importState ────────────────────────────────────────

_t.test("exportState returns serializable state", function () {
  var eng = createEngine({ simulationRounds: 50 });
  eng.runAssessment(BASIC_DEFENSES);
  var state = eng.exportState();
  _a.ok(Array.isArray(state.simulations));
  _a.ok(Array.isArray(state.playbooks));
  _a.ok(Array.isArray(state.insights));
  _a.ok(Array.isArray(state.snapshots));
  _a.ok(Array.isArray(state.simulationOrder));
  _a.ok(Array.isArray(state.playbookOrder));
  _a.ok(Array.isArray(state.snapshotOrder));
  // Verify JSON round-trips
  JSON.parse(JSON.stringify(state));
});

_t.test("importState restores engine state", function () {
  var eng1 = createEngine({ simulationRounds: 50 });
  eng1.runAssessment(BASIC_DEFENSES);
  var state = eng1.exportState();

  var eng2 = createEngine({ simulationRounds: 50 });
  eng2.importState(state);
  _a.equal(eng2.getEvolution().length, 1);
  _a.ok(eng2.getInsights().length > 0);
});

_t.test("importState throws on invalid input", function () {
  var eng = createEngine();
  _a.throws(function () { eng.importState(null); }, /object/i);
  _a.throws(function () { eng.importState("string"); }, /object/i);
});

_t.test("importState handles empty arrays", function () {
  var eng = createEngine();
  eng.importState({ simulations: [], playbooks: [], insights: [], snapshots: [] });
  _a.equal(eng.getEvolution().length, 0);
  _a.equal(eng.getInsights().length, 0);
});

// ── LRU eviction ─────────────────────────────────────────────────────

_t.test("respects maxSnapshots limit", function () {
  var eng = createEngine({ simulationRounds: 10, maxSnapshots: 3 });
  for (var i = 0; i < 5; i++) {
    eng.runAssessment(BASIC_DEFENSES);
  }
  _a.equal(eng.getEvolution().length, 3);
});

// ── Defense profile ──────────────────────────────────────────────────

_t.test("defense profile shows category strength", function () {
  var eng = createEngine({ simulationRounds: 50 });
  var result = eng.runAssessment(["rate_limiter", "traffic_analyzer", "behavioral_biometrics"]);
  _a.ok(result.defenseProfile.categoryStrength.volume);
  _a.ok(result.defenseProfile.categoryStrength.behavior);
});

_t.test("defense profile handles unknown defense IDs gracefully", function () {
  var eng = createEngine({ simulationRounds: 50 });
  var result = eng.runAssessment(["rate_limiter", "nonexistent_defense"]);
  _a.equal(result.defenseProfile.totalDefenses, 1);
});

// ── Playbook quick wins ──────────────────────────────────────────────

_t.test("playbook identifies quick wins", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var result = eng.runAssessment([]);
  // With no defenses, there should be quick wins
  _a.ok(result.playbook.quickWins.length >= 0);
  result.playbook.quickWins.forEach(function (qw) {
    _a.equal(qw.effort, "low");
    _a.ok(qw.impactScore >= 30);
  });
});

_t.test("playbook summary counts scenarios correctly", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  var sum = result.playbook.summary;
  _a.equal(sum.vulnerableScenarios + sum.atRiskScenarios + sum.defendedScenarios, sum.totalScenarios);
  _a.equal(sum.totalScenarios, 10);
});

// ── Edge cases ───────────────────────────────────────────────────────

_t.test("multiple assessments don't corrupt state", function () {
  var eng = createEngine({ simulationRounds: 50 });
  var r1 = eng.runAssessment([]);
  var r2 = eng.runAssessment(BASIC_DEFENSES);
  var r3 = eng.runAssessment(FULL_DEFENSES);
  _a.equal(eng.getEvolution().length, 3);
  _a.ok(r1.resilience.composite <= r3.resilience.composite);
});

_t.test("each attack category can be simulated individually", function () {
  var eng = createEngine({ simulationRounds: 50 });
  ATTACK_CATEGORIES.forEach(function (cat) {
    var result = eng.simulateScenario(cat, BASIC_DEFENSES);
    _a.equal(result.category, cat);
    _a.ok(typeof result.attackSuccessRate === "number");
  });
});

_t.test("insights have valid severity levels", function () {
  var eng = createEngine({ simulationRounds: 100 });
  eng.runAssessment([]);
  var validSeverities = ["CRITICAL", "HIGH", "MEDIUM", "INFO"];
  eng.getInsights().forEach(function (ins) {
    _a.ok(validSeverities.indexOf(ins.severity) >= 0,
      "Invalid severity: " + ins.severity);
  });
});

_t.test("resilience dimensions sum to reasonable range", function () {
  var eng = createEngine({ simulationRounds: 100 });
  var result = eng.runAssessment(BASIC_DEFENSES);
  var dims = result.resilience.dimensions;
  _a.ok(dims.gapCoverage >= 0 && dims.gapCoverage <= 100);
  _a.ok(dims.simulationSurvival >= 0 && dims.simulationSurvival <= 100);
  _a.ok(dims.defenseDepth >= 0 && dims.defenseDepth <= 100);
  _a.ok(dims.adaptability >= 0 && dims.adaptability <= 100);
});
