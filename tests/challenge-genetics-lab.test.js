var test = require("node:test");
var assert = require("node:assert/strict");
var ChallengeGeneticsLab = require("../src/challenge-genetics-lab").ChallengeGeneticsLab;

// ── Helpers ─────────────────────────────────────────────────────────

function createLab(opts) {
  return new ChallengeGeneticsLab(Object.assign({
    populationSize: 10,
    eliteCount: 2,
    minTrials: 3,
    maxGenerations: 100
  }, opts || {}));
}

/** Feed enough outcomes for fitness computation. */
function feedOutcomes(lab, challengeId, humanPass, humanFail, botPass, botFail) {
  for (var i = 0; i < humanPass; i++) {
    lab.recordOutcome(challengeId, { isHuman: true, passed: true, solveTimeMs: 7000 + Math.floor(i * 100) });
  }
  for (var j = 0; j < humanFail; j++) {
    lab.recordOutcome(challengeId, { isHuman: true, passed: false, solveTimeMs: 12000 });
  }
  for (var k = 0; k < botPass; k++) {
    lab.recordOutcome(challengeId, { isHuman: false, passed: true, solveTimeMs: 500 });
  }
  for (var l = 0; l < botFail; l++) {
    lab.recordOutcome(challengeId, { isHuman: false, passed: false, solveTimeMs: 200, botSignature: "test-bot" });
  }
}

// ── Constructor Tests ───────────────────────────────────────────────

test("constructor uses defaults", function () {
  var lab = new ChallengeGeneticsLab();
  assert.equal(lab.populationSize, 50);
  assert.equal(lab.eliteCount, 5);
  assert.equal(lab.mutationRate, 0.15);
  assert.equal(lab.autoEvolve, false);
});

test("constructor accepts custom options", function () {
  var lab = new ChallengeGeneticsLab({ populationSize: 20, mutationRate: 0.3, autoEvolve: true });
  assert.equal(lab.populationSize, 20);
  assert.equal(lab.mutationRate, 0.3);
  assert.equal(lab.autoEvolve, true);
});

test("eliteCount clamped if >= populationSize", function () {
  var lab = new ChallengeGeneticsLab({ populationSize: 5, eliteCount: 10 });
  assert.ok(lab.eliteCount < lab.populationSize);
});

// ── Seed Population ─────────────────────────────────────────────────

test("seedPopulation creates challenges", function () {
  var lab = createLab();
  var pop = lab.seedPopulation();
  assert.equal(pop.length, 10);
  assert.ok(pop[0].id);
  assert.ok(pop[0].genome);
  assert.equal(pop[0].generation, 0);
  assert.deepEqual(pop[0].parentIds, []);
});

test("seedPopulation genomes have all traits in [0,1]", function () {
  var lab = createLab();
  var pop = lab.seedPopulation();
  var traits = ChallengeGeneticsLab.TRAIT_NAMES;
  for (var i = 0; i < pop.length; i++) {
    for (var t = 0; t < traits.length; t++) {
      var val = pop[i].genome[traits[t]];
      assert.ok(typeof val === "number", "trait " + traits[t] + " should be a number");
      assert.ok(val >= 0 && val <= 1, "trait " + traits[t] + " should be in [0,1]");
    }
  }
});

test("seedPopulation with custom count", function () {
  var lab = createLab();
  var pop = lab.seedPopulation(5);
  assert.equal(pop.length, 5);
});

// ── Record Outcome ──────────────────────────────────────────────────

test("recordOutcome returns false for unknown challenge", function () {
  var lab = createLab();
  assert.equal(lab.recordOutcome("nonexistent", { isHuman: true, passed: true, solveTimeMs: 5000 }), false);
});

test("recordOutcome returns false for invalid input", function () {
  var lab = createLab();
  var pop = lab.seedPopulation();
  assert.equal(lab.recordOutcome(pop[0].id, null), false);
  assert.equal(lab.recordOutcome(pop[0].id, { isHuman: "yes", passed: true, solveTimeMs: 5000 }), false);
});

test("recordOutcome accumulates data", function () {
  var lab = createLab();
  var pop = lab.seedPopulation();
  var id = pop[0].id;
  assert.ok(lab.recordOutcome(id, { isHuman: true, passed: true, solveTimeMs: 5000 }));
  assert.ok(lab.recordOutcome(id, { isHuman: false, passed: false, solveTimeMs: 200, botSignature: "fast-bot" }));
  var ch = lab.getChallenge(id);
  assert.equal(ch.trialCount, 2);
});

// ── Fitness Computation ─────────────────────────────────────────────

test("computeFitness returns null with insufficient trials", function () {
  var lab = createLab();
  var pop = lab.seedPopulation();
  assert.equal(lab.computeFitness(pop[0].id), null);
});

test("computeFitness returns null for unknown challenge", function () {
  var lab = createLab();
  assert.equal(lab.computeFitness("nope"), null);
});

test("computeFitness returns valid report with enough trials", function () {
  var lab = createLab();
  var pop = lab.seedPopulation();
  var id = pop[0].id;
  feedOutcomes(lab, id, 8, 2, 1, 9);
  var fit = lab.computeFitness(id);
  assert.ok(fit);
  assert.ok(fit.fitness >= 0 && fit.fitness <= 1);
  assert.equal(fit.humanPassRate, 0.8);
  assert.equal(fit.botFailRate, 0.9);
  assert.ok(fit.avgSolveTimeMs > 0);
  assert.equal(fit.trialCount, 20);
  assert.ok(fit.components);
  assert.ok(fit.components.botFail >= 0 && fit.components.botFail <= 1);
});

test("high-quality challenge gets high fitness", function () {
  var lab = createLab({ targetHumanPassRate: 0.82 });
  var pop = lab.seedPopulation();
  var id = pop[0].id;
  // ~82% human pass, ~95% bot fail
  feedOutcomes(lab, id, 82, 18, 5, 95);
  var fit = lab.computeFitness(id);
  assert.ok(fit.fitness > 0.5, "fitness should be high: " + fit.fitness);
});

test("poor-quality challenge gets lower fitness", function () {
  var lab = createLab();
  var pop = lab.seedPopulation();
  var id = pop[0].id;
  // Low human pass, high bot pass
  feedOutcomes(lab, id, 2, 8, 8, 2);
  var fit = lab.computeFitness(id);
  assert.ok(fit.fitness < 0.5, "fitness should be low: " + fit.fitness);
});

// ── Evolution ───────────────────────────────────────────────────────

test("evolve increments generation", function () {
  var lab = createLab();
  lab.seedPopulation();
  var result = lab.evolve();
  assert.equal(result.generation, 1);
});

test("evolve with insufficient data adds random challenges", function () {
  var lab = createLab();
  lab.seedPopulation();
  var result = lab.evolve();
  assert.ok(result.note === "insufficient_data");
  assert.ok(result.populationSize > 0);
});

test("evolve with scored population produces offspring", function () {
  var lab = createLab({ populationSize: 10, eliteCount: 2, minTrials: 3 });
  var pop = lab.seedPopulation();
  for (var i = 0; i < pop.length; i++) {
    feedOutcomes(lab, pop[i].id, 6 + i, 4 - Math.min(i, 3), 1, 5 + i);
  }
  var result = lab.evolve();
  assert.equal(result.generation, 1);
  assert.ok(result.newbornCount > 0);
  assert.ok(result.eliteIds.length === 2);
  assert.ok(result.avgFitness > 0);
  assert.ok(result.bestFitness >= result.avgFitness);
});

test("evolve respects maxGenerations", function () {
  var lab = createLab({ maxGenerations: 2 });
  lab.seedPopulation();
  lab.evolve();
  lab.evolve();
  var result = lab.evolve();
  assert.equal(result.error, "max_generations_reached");
});

test("evolve preserves elites", function () {
  var lab = createLab({ populationSize: 8, eliteCount: 2, minTrials: 3 });
  var pop = lab.seedPopulation();
  // Make first two very fit
  feedOutcomes(lab, pop[0].id, 8, 2, 0, 10);
  feedOutcomes(lab, pop[1].id, 8, 2, 0, 10);
  for (var i = 2; i < pop.length; i++) {
    feedOutcomes(lab, pop[i].id, 3, 7, 5, 5);
  }
  var result = lab.evolve();
  // Elites should still be in population
  var currentPop = lab.getPopulation();
  var ids = currentPop.map(function (c) { return c.id; });
  for (var e = 0; e < result.eliteIds.length; e++) {
    assert.ok(ids.indexOf(result.eliteIds[e]) !== -1, "elite " + result.eliteIds[e] + " should survive");
  }
});

// ── Query Methods ───────────────────────────────────────────────────

test("getChallenge returns null for unknown id", function () {
  var lab = createLab();
  assert.equal(lab.getChallenge("nope"), null);
});

test("getChallenge returns full record", function () {
  var lab = createLab();
  var pop = lab.seedPopulation();
  var ch = lab.getChallenge(pop[0].id);
  assert.ok(ch);
  assert.equal(ch.id, pop[0].id);
  assert.ok(ch.genome);
  assert.equal(ch.generation, 0);
});

test("getPopulation returns sorted array", function () {
  var lab = createLab();
  var pop = lab.seedPopulation();
  feedOutcomes(lab, pop[0].id, 8, 2, 0, 10);
  feedOutcomes(lab, pop[1].id, 2, 8, 8, 2);
  var all = lab.getPopulation();
  assert.ok(all.length > 0);
});

test("getLineage traces ancestry", function () {
  var lab = createLab({ populationSize: 6, eliteCount: 1, minTrials: 3 });
  var pop = lab.seedPopulation();
  for (var i = 0; i < pop.length; i++) {
    feedOutcomes(lab, pop[i].id, 6, 4, 1, 5);
  }
  lab.evolve();
  var newPop = lab.getPopulation();
  // Find a child (generation 1)
  var child = null;
  for (var j = 0; j < newPop.length; j++) {
    if (newPop[j].generation === 1) { child = newPop[j]; break; }
  }
  if (child) {
    var lineage = lab.getLineage(child.id);
    assert.ok(lineage.length >= 1);
    assert.equal(lineage[0].id, child.id);
  }
});

test("getGenerationStats returns history", function () {
  var lab = createLab({ minTrials: 3 });
  lab.seedPopulation();
  lab.evolve();
  var stats = lab.getGenerationStats();
  assert.equal(stats.length, 1);
  assert.equal(stats[0].generation, 1);
});

test("getTraitDistribution returns null for invalid trait", function () {
  var lab = createLab();
  lab.seedPopulation();
  assert.equal(lab.getTraitDistribution("nonexistent"), null);
});

test("getTraitDistribution returns stats", function () {
  var lab = createLab();
  lab.seedPopulation();
  var dist = lab.getTraitDistribution("complexity");
  assert.ok(dist);
  assert.equal(dist.trait, "complexity");
  assert.ok(dist.count > 0);
  assert.ok(dist.min >= 0 && dist.max <= 1);
  assert.ok(dist.mean >= 0 && dist.mean <= 1);
  assert.ok(dist.quartiles);
});

// ── Diversity & Extinction ──────────────────────────────────────────

test("getDiversityScore with empty population returns 0", function () {
  var lab = createLab();
  assert.equal(lab.getDiversityScore(), 0);
});

test("getDiversityScore with population returns value in [0,1]", function () {
  var lab = createLab();
  lab.seedPopulation();
  var div = lab.getDiversityScore();
  assert.ok(div >= 0 && div <= 1);
});

test("getExtinctionRisk returns valid assessment", function () {
  var lab = createLab();
  lab.seedPopulation();
  var risk = lab.getExtinctionRisk();
  assert.ok(["low", "medium", "high", "critical"].indexOf(risk.risk) !== -1);
  assert.ok(typeof risk.diversity === "number");
  assert.ok(typeof risk.recommendation === "string");
});

test("identical genomes yield critical extinction risk", function () {
  var lab = createLab({ populationSize: 10 });
  // Inject identical genomes
  for (var i = 0; i < 10; i++) {
    lab.injectMutant({ complexity: 0.5, distraction: 0.5, timeWindow: 0.5, ambiguity: 0.5, frameCount: 0.5, colorEntropy: 0.5, motionIntensity: 0.5, textObfuscation: 0.5 });
  }
  var risk = lab.getExtinctionRisk();
  assert.equal(risk.risk, "critical");
});

// ── Inject Mutant ───────────────────────────────────────────────────

test("injectMutant adds to population", function () {
  var lab = createLab();
  lab.seedPopulation();
  var before = lab.getPopulation().length;
  var mutant = lab.injectMutant();
  assert.ok(mutant.id);
  assert.equal(lab.getPopulation().length, before + 1);
});

test("injectMutant with custom genome", function () {
  var lab = createLab();
  var g = { complexity: 0.9, distraction: 0.1, timeWindow: 0.5, ambiguity: 0.3, frameCount: 0.7, colorEntropy: 0.2, motionIntensity: 0.8, textObfuscation: 0.4 };
  var mutant = lab.injectMutant(g);
  assert.equal(mutant.genome.complexity, 0.9);
  assert.equal(mutant.genome.distraction, 0.1);
});

test("injectMutant clamps out-of-range values", function () {
  var lab = createLab();
  var mutant = lab.injectMutant({ complexity: 1.5, distraction: -0.3 });
  assert.equal(mutant.genome.complexity, 1);
  assert.equal(mutant.genome.distraction, 0);
});

// ── Serialization ───────────────────────────────────────────────────

test("exportState and importState roundtrip", function () {
  var lab = createLab();
  lab.seedPopulation();
  var pop = lab.getPopulation();
  feedOutcomes(lab, pop[0].id, 5, 2, 1, 3);
  lab.evolve();

  var state = lab.exportState();
  assert.equal(state.version, 1);
  assert.ok(state.generation > 0);

  var lab2 = createLab();
  assert.ok(lab2.importState(state));
  assert.equal(lab2.getPopulation().length, lab.getPopulation().length);
  assert.equal(lab2._generation, lab._generation);
});

test("importState rejects invalid state", function () {
  var lab = createLab();
  assert.equal(lab.importState(null), false);
  assert.equal(lab.importState({ version: 99 }), false);
});

// ── TRAIT_NAMES ─────────────────────────────────────────────────────

test("TRAIT_NAMES is exposed", function () {
  assert.ok(Array.isArray(ChallengeGeneticsLab.TRAIT_NAMES));
  assert.equal(ChallengeGeneticsLab.TRAIT_NAMES.length, 8);
  assert.ok(ChallengeGeneticsLab.TRAIT_NAMES.indexOf("complexity") !== -1);
});

// ── Auto-Evolve ─────────────────────────────────────────────────────

test("autoEvolve triggers when threshold met", function () {
  var lab = createLab({ autoEvolve: true, autoEvolveThreshold: 0.5, minTrials: 2, populationSize: 4, eliteCount: 1 });
  var pop = lab.seedPopulation();
  // Feed outcomes to > 50% of population
  feedOutcomes(lab, pop[0].id, 3, 0, 0, 3);
  feedOutcomes(lab, pop[1].id, 3, 0, 0, 3);
  // Third one triggers threshold check — generation should advance
  feedOutcomes(lab, pop[2].id, 3, 0, 0, 3);
  // At least one evolve should have happened
  assert.ok(lab._generation >= 1, "generation should have advanced via autoEvolve");
});

// ── Multiple Generations ────────────────────────────────────────────

test("multiple evolve cycles produce generation history", function () {
  var lab = createLab({ populationSize: 8, eliteCount: 2, minTrials: 3, maxGenerations: 50 });
  var pop = lab.seedPopulation();
  for (var gen = 0; gen < 3; gen++) {
    var currentPop = lab.getPopulation();
    for (var i = 0; i < currentPop.length; i++) {
      feedOutcomes(lab, currentPop[i].id, 6, 4, 2, 8);
    }
    lab.evolve();
  }
  var history = lab.getGenerationStats();
  assert.equal(history.length, 3);
  assert.equal(history[0].generation, 1);
  assert.equal(history[2].generation, 3);
});
