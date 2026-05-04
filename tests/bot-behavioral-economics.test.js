"use strict";

var test = require("node:test");
var assert = require("node:assert/strict");
var BBE = require("../src/bot-behavioral-economics");
var BotBehavioralEconomicsEngine = BBE.BotBehavioralEconomicsEngine;
var HEALTH_TIERS = BBE.HEALTH_TIERS;

// ── Helpers ─────────────────────────────────────────────────────────

function makeEngine(opts) {
  return new BotBehavioralEconomicsEngine(opts);
}

function seedAttempts(engine, count, opts) {
  opts = opts || {};
  var botId = opts.botId || "bot-1";
  var challengeType = opts.challengeType || "gif-motion";
  var difficulty = opts.difficulty != null ? opts.difficulty : 0.5;
  var solveRate = opts.solveRate != null ? opts.solveRate : 0.3;
  var baseTime = opts.baseTime || Date.now() - 86400000;

  for (var i = 0; i < count; i++) {
    engine.recordAttempt({
      botId: botId,
      challengeType: challengeType,
      difficulty: difficulty,
      solved: Math.random() < solveRate,
      solveTimeMs: 500 + Math.random() * 2000,
      timestamp: baseTime + i * 1000
    });
  }
}

// ── Constructor Tests ───────────────────────────────────────────────

test("constructor: creates with default options", function () {
  var e = makeEngine();
  assert.ok(e instanceof BotBehavioralEconomicsEngine);
  assert.equal(e._maxAttempts, 10000);
  assert.equal(e._maxBots, 500);
});

test("constructor: respects custom options", function () {
  var e = makeEngine({ maxAttempts: 100, maxBots: 10, costPerAttempt: 2.5, valuePerSolve: 20 });
  assert.equal(e._maxAttempts, 100);
  assert.equal(e._maxBots, 10);
  assert.equal(e._costPerAttempt, 2.5);
  assert.equal(e._valuePerSolve, 20);
});

test("HEALTH_TIERS: has 5 tiers in correct order", function () {
  assert.equal(HEALTH_TIERS.length, 5);
  assert.equal(HEALTH_TIERS[0], "PROHIBITIVE");
  assert.equal(HEALTH_TIERS[4], "BANKRUPT");
});

// ── Recording Tests ─────────────────────────────────────────────────

test("recordAttempt: stores valid attempt", function () {
  var e = makeEngine();
  e.recordAttempt({
    botId: "bot-1",
    challengeType: "gif-motion",
    difficulty: 0.5,
    solved: true,
    solveTimeMs: 1200
  });
  assert.equal(e._attempts.length, 1);
  assert.equal(e._attempts[0].botId, "bot-1");
  assert.equal(e._attempts[0].solved, true);
});

test("recordAttempt: rejects missing botId", function () {
  var e = makeEngine();
  assert.throws(function () {
    e.recordAttempt({ challengeType: "x", difficulty: 0.5, solved: false });
  }, /botId/);
});

test("recordAttempt: rejects missing challengeType", function () {
  var e = makeEngine();
  assert.throws(function () {
    e.recordAttempt({ botId: "b1", difficulty: 0.5, solved: false });
  }, /challengeType/);
});

test("recordAttempt: rejects missing difficulty", function () {
  var e = makeEngine();
  assert.throws(function () {
    e.recordAttempt({ botId: "b1", challengeType: "x", solved: false });
  }, /difficulty/);
});

test("recordAttempt: rejects __proto__ botId", function () {
  var e = makeEngine();
  assert.throws(function () {
    e.recordAttempt({ botId: "__proto__", challengeType: "x", difficulty: 0.5, solved: false });
  }, /Dangerous/);
});

test("recordAttempt: clamps difficulty to 0-1", function () {
  var e = makeEngine();
  e.recordAttempt({ botId: "b1", challengeType: "x", difficulty: 1.5, solved: false });
  assert.equal(e._attempts[0].difficulty, 1);
  e.recordAttempt({ botId: "b1", challengeType: "x", difficulty: -0.5, solved: false });
  assert.equal(e._attempts[1].difficulty, 0);
});

test("recordAttempt: enforces maxAttempts limit", function () {
  var e = makeEngine({ maxAttempts: 5 });
  for (var i = 0; i < 10; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "x", difficulty: 0.5, solved: false, timestamp: i });
  }
  assert.equal(e._attempts.length, 5);
});

test("recordAttempt: enforces maxBots via LRU eviction", function () {
  var e = makeEngine({ maxBots: 3 });
  for (var i = 0; i < 5; i++) {
    e.recordAttempt({ botId: "bot-" + i, challengeType: "x", difficulty: 0.5, solved: false });
  }
  assert.equal(e._botLru.length, 3);
  assert.ok(!e._botAttempts["bot-0"]);
  assert.ok(!e._botAttempts["bot-1"]);
  assert.ok(e._botAttempts["bot-4"]);
});

test("recordAttempt: updates challenge stats correctly", function () {
  var e = makeEngine();
  e.recordAttempt({ botId: "b1", challengeType: "gif", difficulty: 0.3, solved: true, solveTimeMs: 1000 });
  e.recordAttempt({ botId: "b1", challengeType: "gif", difficulty: 0.5, solved: false });
  var cs = e._challengeStats["gif"];
  assert.equal(cs.attempts, 2);
  assert.equal(cs.solves, 1);
  assert.ok(cs.totalValue > 0);
});

test("recordDefenseAction: stores valid action", function () {
  var e = makeEngine();
  e.recordDefenseAction({ challengeType: "gif", difficultyBefore: 0.3, difficultyAfter: 0.7 });
  assert.equal(e._defenseActions.length, 1);
  assert.equal(e._defenseActions[0].difficultyAfter, 0.7);
});

test("recordDefenseAction: rejects missing challengeType", function () {
  var e = makeEngine();
  assert.throws(function () {
    e.recordDefenseAction({ difficultyBefore: 0.3, difficultyAfter: 0.7 });
  });
});

// ── Attack Cost Analysis ────────────────────────────────────────────

test("analyzeAttackCosts: returns empty on insufficient data", function () {
  var e = makeEngine();
  var result = e.analyzeAttackCosts();
  assert.equal(result.analyzedTypes, 0);
});

test("analyzeAttackCosts: computes costs for seeded data", function () {
  var e = makeEngine();
  seedAttempts(e, 20, { solveRate: 0.5, difficulty: 0.4 });
  var result = e.analyzeAttackCosts();
  assert.ok(result.analyzedTypes > 0);
  var ct = result.challengeTypes["gif-motion"];
  assert.ok(ct);
  assert.ok(ct.attempts >= 20);
  assert.ok(ct.solveRate > 0);
  assert.ok(ct.totalCost > 0);
  assert.equal(typeof ct.roi, "number");
  assert.equal(typeof ct.profitable, "boolean");
});

test("analyzeAttackCosts: high difficulty makes attacks unprofitable", function () {
  var e = makeEngine({ costPerAttempt: 5, valuePerSolve: 10 });
  // Hard challenge, low solve rate
  for (var i = 0; i < 20; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "hard", difficulty: 0.9, solved: i < 1 });
  }
  var result = e.analyzeAttackCosts();
  var ct = result.challengeTypes["hard"];
  assert.ok(ct);
  assert.ok(ct.roi < 0, "High difficulty should make attacks unprofitable");
});

// ── Arbitrage Detection ─────────────────────────────────────────────

test("detectArbitrage: finds no arbitrage on empty state", function () {
  var e = makeEngine();
  var result = e.detectArbitrage();
  assert.equal(result.arbitrageCount, 0);
  assert.equal(result.hasArbitrage, false);
});

test("detectArbitrage: finds arbitrage on easy profitable challenges", function () {
  var e = makeEngine({ costPerAttempt: 1, valuePerSolve: 20 });
  // Easy challenge with high solve rate = high ROI
  for (var i = 0; i < 20; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "easy", difficulty: 0.1, solved: true });
  }
  // Hard challenge with low solve rate
  for (var j = 0; j < 20; j++) {
    e.recordAttempt({ botId: "b1", challengeType: "hard", difficulty: 0.9, solved: false });
  }
  var result = e.detectArbitrage();
  assert.ok(result.hasArbitrage);
  assert.ok(result.opportunities.length > 0);
  assert.equal(result.opportunities[0].challengeType, "easy");
});

test("detectArbitrage: includes temporal windows on difficulty reductions", function () {
  var e = makeEngine();
  seedAttempts(e, 10);
  e.recordDefenseAction({ challengeType: "gif-motion", difficultyBefore: 0.8, difficultyAfter: 0.3 });
  var result = e.detectArbitrage();
  assert.ok(result.temporalWindows.length > 0);
  assert.equal(result.temporalWindows[0].type, "DIFFICULTY_REDUCTION");
});

// ── Deterrence Analysis ─────────────────────────────────────────────

test("analyzeDeterrence: returns coverage metrics", function () {
  var e = makeEngine();
  // Low difficulty = high solve rate
  for (var i = 0; i < 10; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.1, solved: true });
  }
  // High difficulty = low solve rate
  for (var j = 0; j < 10; j++) {
    e.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.9, solved: false });
  }
  var result = e.analyzeDeterrence();
  assert.ok(result.totalAnalyzed > 0);
  assert.equal(typeof result.coverage, "number");
  var ct = result.challengeTypes["t1"];
  assert.ok(ct);
  assert.equal(typeof ct.priceElasticity, "number");
  assert.equal(typeof ct.breakEvenSolveRate, "number");
});

test("analyzeDeterrence: identifies deterred challenges", function () {
  var e = makeEngine({ costPerAttempt: 5, valuePerSolve: 10 });
  // All attempts at high difficulty, all fail
  for (var i = 0; i < 10; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "hard", difficulty: 0.8, solved: false });
  }
  var result = e.analyzeDeterrence();
  // With 0% solve rate at high difficulty, should find deterrence
  if (result.challengeTypes["hard"]) {
    assert.equal(typeof result.challengeTypes["hard"].isDeterred, "boolean");
  }
});

// ── Resource Allocation ─────────────────────────────────────────────

test("analyzeResourceAllocation: tracks bot allocation", function () {
  var e = makeEngine();
  seedAttempts(e, 15, { botId: "b1", challengeType: "t1" });
  seedAttempts(e, 5, { botId: "b1", challengeType: "t2" });
  var result = e.analyzeResourceAllocation();
  assert.ok(result.totalBots > 0);
  var b1 = result.bots["b1"];
  assert.ok(b1);
  assert.ok(b1.concentration > 0.5, "Bot should be concentrated on t1");
  assert.equal(b1.challengeTypes, 2);
});

test("analyzeResourceAllocation: computes Gini concentration", function () {
  var e = makeEngine();
  seedAttempts(e, 50, { botId: "b1", challengeType: "t1" });
  seedAttempts(e, 5, { botId: "b2", challengeType: "t2" });
  var result = e.analyzeResourceAllocation();
  assert.ok(result.giniConcentration >= 0);
  assert.ok(result.giniConcentration <= 1);
});

test("analyzeResourceAllocation: detects reallocations", function () {
  var e = makeEngine();
  var base = Date.now() - 100000;
  // First half: all on t1
  for (var i = 0; i < 10; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.5, solved: false, timestamp: base + i * 100 });
  }
  // Second half: all on t2
  for (var j = 0; j < 10; j++) {
    e.recordAttempt({ botId: "b1", challengeType: "t2", difficulty: 0.5, solved: false, timestamp: base + 10000 + j * 100 });
  }
  var result = e.analyzeResourceAllocation();
  var b1 = result.bots["b1"];
  assert.ok(b1);
  assert.ok(b1.reallocations > 0, "Should detect reallocation from t1 to t2");
});

// ── Market Equilibrium ──────────────────────────────────────────────

test("findEquilibrium: returns equilibria per challenge type", function () {
  var e = makeEngine();
  seedAttempts(e, 20, { difficulty: 0.5, solveRate: 0.3 });
  var result = e.findEquilibrium();
  assert.ok(result.analyzedTypes > 0);
  assert.ok(result.marketState);
  var ct = result.challengeTypes["gif-motion"];
  assert.ok(ct);
  assert.equal(typeof ct.equilibriumDifficulty, "number");
  assert.equal(typeof ct.isConverged, "boolean");
  assert.ok(["DEFENDER", "ATTACKER", "NEUTRAL"].indexOf(ct.advantage) >= 0);
});

test("findEquilibrium: detects attacker-dominant market", function () {
  var e = makeEngine({ costPerAttempt: 0.1, valuePerSolve: 100 });
  // Very cheap attacks, very high value = attacker dominant
  for (var i = 0; i < 10; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.2, solved: true });
  }
  var result = e.findEquilibrium();
  var ct = result.challengeTypes["t1"];
  if (ct) {
    assert.ok(ct.attackerUtility > 0);
  }
});

// ── Scoring ─────────────────────────────────────────────────────────

test("score: returns default 50/CONTESTED on empty state", function () {
  var e = makeEngine();
  var s = e.score();
  assert.equal(s.score, 50);
  assert.equal(s.tier, "CONTESTED");
  assert.equal(s.confidence, 0);
});

test("score: returns valid score and tier with data", function () {
  var e = makeEngine();
  seedAttempts(e, 50, { solveRate: 0.3 });
  var s = e.score();
  assert.ok(s.score >= 0 && s.score <= 100);
  assert.ok(HEALTH_TIERS.indexOf(s.tier) >= 0);
  assert.ok(s.confidence > 0);
  assert.ok(s.components);
  assert.equal(typeof s.components.attackRoi, "number");
  assert.equal(typeof s.components.arbitrage, "number");
  assert.equal(typeof s.components.deterrence, "number");
  assert.equal(typeof s.components.equilibrium, "number");
});

test("score: low solve rate yields higher score", function () {
  var eHard = makeEngine({ costPerAttempt: 5, valuePerSolve: 10 });
  for (var i = 0; i < 20; i++) {
    eHard.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.8, solved: false });
  }

  var eEasy = makeEngine({ costPerAttempt: 1, valuePerSolve: 20 });
  for (var j = 0; j < 20; j++) {
    eEasy.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.2, solved: true });
  }

  assert.ok(eHard.score().score >= eEasy.score().score,
    "Hard challenges should score higher (better for defender)");
});

test("score: tiers are correctly assigned", function () {
  var e = makeEngine();
  // Seed with all failures = very good for defender
  for (var i = 0; i < 20; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.9, solved: false });
  }
  var s = e.score();
  assert.ok(s.score >= 40, "All failures should give decent score, got " + s.score);
});

// ── Insight Generation ──────────────────────────────────────────────

test("generateInsights: returns info on empty state", function () {
  var e = makeEngine();
  var insights = e.generateInsights();
  assert.ok(insights.length > 0);
  assert.equal(insights[0].type, "INFO");
  assert.equal(insights[0].category, "data");
});

test("generateInsights: generates arbitrage warnings", function () {
  var e = makeEngine({ costPerAttempt: 1, valuePerSolve: 20 });
  for (var i = 0; i < 20; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "easy", difficulty: 0.1, solved: true });
  }
  for (var j = 0; j < 20; j++) {
    e.recordAttempt({ botId: "b1", challengeType: "hard", difficulty: 0.9, solved: false });
  }
  var insights = e.generateInsights();
  var arbInsights = insights.filter(function (ins) { return ins.category === "arbitrage"; });
  assert.ok(arbInsights.length > 0, "Should generate arbitrage insights");
});

test("generateInsights: sorted by priority", function () {
  var e = makeEngine({ costPerAttempt: 1, valuePerSolve: 20 });
  for (var i = 0; i < 30; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.1, solved: true });
  }
  var insights = e.generateInsights();
  if (insights.length >= 2) {
    var priorityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    for (var j = 1; j < insights.length; j++) {
      assert.ok(
        (priorityOrder[insights[j].priority] || 3) >= (priorityOrder[insights[j - 1].priority] || 3),
        "Insights should be sorted by priority"
      );
    }
  }
});

test("generateInsights: includes recommendations", function () {
  var e = makeEngine({ costPerAttempt: 1, valuePerSolve: 20 });
  for (var i = 0; i < 20; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "easy", difficulty: 0.1, solved: true });
  }
  var insights = e.generateInsights();
  var withRec = insights.filter(function (ins) { return ins.recommendation; });
  assert.ok(withRec.length > 0, "Some insights should have recommendations");
});

// ── Full Report ─────────────────────────────────────────────────────

test("analyze: returns full report structure", function () {
  var e = makeEngine();
  seedAttempts(e, 20);
  var report = e.analyze();
  assert.ok(report.attackCosts);
  assert.ok(report.arbitrage);
  assert.ok(report.deterrence);
  assert.ok(report.resourceAllocation);
  assert.ok(report.equilibrium);
  assert.ok(report.health);
  assert.ok(report.insights);
  assert.ok(report.meta);
  assert.equal(typeof report.meta.totalAttempts, "number");
  assert.equal(typeof report.meta.generatedAt, "number");
});

// ── State Export/Import ─────────────────────────────────────────────

test("exportState: returns serializable state", function () {
  var e = makeEngine();
  seedAttempts(e, 10);
  var state = e.exportState();
  assert.equal(state.version, 1);
  assert.ok(Array.isArray(state.attempts));
  assert.equal(state.attempts.length, 10);
  assert.ok(Array.isArray(state.botLru));
  assert.ok(Array.isArray(state.challengeLru));
});

test("importState: restores state correctly", function () {
  var e1 = makeEngine();
  seedAttempts(e1, 15);
  e1.recordDefenseAction({ challengeType: "gif-motion", difficultyBefore: 0.3, difficultyAfter: 0.7 });
  var state = e1.exportState();

  var e2 = makeEngine();
  e2.importState(state);
  assert.equal(e2._attempts.length, 15);
  assert.equal(e2._defenseActions.length, 1);
  assert.ok(e2._botAttempts["bot-1"]);
});

test("importState: roundtrip preserves analysis", function () {
  var e1 = makeEngine();
  seedAttempts(e1, 30, { solveRate: 0.4 });
  var s1 = e1.score();
  var state = e1.exportState();

  var e2 = makeEngine();
  e2.importState(state);
  var s2 = e2.score();
  assert.equal(s1.score, s2.score);
  assert.equal(s1.tier, s2.tier);
});

test("importState: rejects prototype pollution in botLru", function () {
  var e = makeEngine();
  var state = {
    version: 1,
    attempts: [],
    botAttempts: {},
    challengeStats: {},
    defenseActions: [],
    botLru: ["__proto__", "safe-bot"],
    challengeLru: []
  };
  e.importState(state);
  assert.ok(!e._botLru.has("__proto__"));
  assert.ok(e._botLru.has("safe-bot"));
});

test("importState: rejects non-object state", function () {
  var e = makeEngine();
  assert.throws(function () {
    e.importState("not an object");
  }, /state must be an object/);
});

test("importState: handles empty state gracefully", function () {
  var e = makeEngine();
  e.importState({});
  assert.equal(e._attempts.length, 0);
  assert.equal(e._defenseActions.length, 0);
});

// ── Edge Cases ──────────────────────────────────────────────────────

test("edge: single attempt produces minimal analysis", function () {
  var e = makeEngine({ minSamplesForAnalysis: 1 });
  e.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.5, solved: true });
  var costs = e.analyzeAttackCosts();
  assert.ok(costs.challengeTypes["t1"]);
});

test("edge: all solves successful", function () {
  var e = makeEngine();
  for (var i = 0; i < 10; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.3, solved: true });
  }
  var costs = e.analyzeAttackCosts();
  var ct = costs.challengeTypes["t1"];
  assert.equal(ct.solveRate, 1);
  assert.ok(ct.roi > 0, "100% solve rate should be profitable");
});

test("edge: all solves failed", function () {
  var e = makeEngine();
  for (var i = 0; i < 10; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "t1", difficulty: 0.8, solved: false });
  }
  var costs = e.analyzeAttackCosts();
  var ct = costs.challengeTypes["t1"];
  assert.equal(ct.solveRate, 0);
  assert.equal(ct.costPerSolve, null);
  assert.equal(ct.roi, -1);
});

test("edge: multiple bots attacking same challenge", function () {
  var e = makeEngine();
  for (var i = 0; i < 5; i++) {
    for (var j = 0; j < 5; j++) {
      e.recordAttempt({ botId: "bot-" + i, challengeType: "t1", difficulty: 0.5, solved: j < 2 });
    }
  }
  var alloc = e.analyzeResourceAllocation();
  assert.equal(alloc.totalBots, 5);
  assert.ok(alloc.globalDistribution["t1"]);
  assert.equal(alloc.globalDistribution["t1"].share, 1);
});

test("edge: multiple challenge types with varying difficulty", function () {
  var e = makeEngine();
  var difficulties = [0.1, 0.3, 0.5, 0.7, 0.9];
  for (var i = 0; i < difficulties.length; i++) {
    for (var j = 0; j < 10; j++) {
      e.recordAttempt({
        botId: "b1",
        challengeType: "type-" + i,
        difficulty: difficulties[i],
        solved: difficulties[i] < 0.5
      });
    }
  }
  var report = e.analyze();
  assert.ok(report.meta.totalChallengeTypes >= 5);
  assert.ok(report.insights.length > 0);
});

test("edge: challenge type LRU eviction", function () {
  var e = makeEngine({ maxChallengeTypes: 3 });
  for (var i = 0; i < 5; i++) {
    e.recordAttempt({ botId: "b1", challengeType: "ct-" + i, difficulty: 0.5, solved: false });
  }
  assert.equal(e._challengeLru.length, 3);
  assert.ok(!e._challengeStats["ct-0"]);
  assert.ok(!e._challengeStats["ct-1"]);
  assert.ok(e._challengeStats["ct-4"]);
});
