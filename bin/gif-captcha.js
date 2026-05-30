#!/usr/bin/env node

"use strict";

var gifCaptcha = require("../src/index");
var { secureRandomInt } = require("../src/crypto-utils");

/**
 * Cryptographically secure Fisher–Yates shuffle.
 *
 * Replaces the previous `arr.sort(() => Math.random() - 0.5)` pattern, which
 * was both biased (sort comparators must be transitive) and predictable
 * (Math.random is not a CSPRNG — CWE-330).
 *
 * This module ships sample CAPTCHA challenges in `SAMPLE_GIFS`; using a
 * predictable shuffle would let an attacker mirror the CLI's output and
 * pre-compute likely challenge orderings. The library's own crypto-utils
 * explicitly forbids Math.random for any CAPTCHA-touching code, so the CLI
 * must hold the same line.
 *
 * @template T
 * @param {T[]} arr - Array to shuffle (returned, mutated in place).
 * @returns {T[]}
 */
function secureShuffle(arr) {
  for (var i = arr.length - 1; i > 0; i--) {
    var j = secureRandomInt(i + 1);
    var tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
  return arr;
}

var args = process.argv.slice(2);
var command = args[0];

function flag(name) {
  var idx = args.indexOf("--" + name);
  if (idx === -1) return undefined;
  return args[idx + 1];
}

function hasFlag(name) {
  return args.indexOf("--" + name) !== -1;
}

function printUsage() {
  console.log([
    "",
    "  gif-captcha — CLI for the gif-captcha library",
    "",
    "  Usage: gif-captcha <command> [options]",
    "",
    "  Commands:",
    "",
    "    generate [--count N]",
    "        Generate N sample CAPTCHA challenges (default: 1, max: 10)",
    "",
    "    validate --answer <text> --expected <text> [--threshold N]",
    "        Validate an answer against the expected answer",
    "",
    "    benchmark [--rounds N] [--sessions N]",
    "        Run a quick benchmark of core operations",
    "",
    "    pool [--size N] [--refill N]",
    "        Create and inspect a challenge pool",
    "",
    "    trust --ip <ip>",
    "        Look up trust score for a client IP",
    "",
    "    stats [--challenges N]",
    "        Generate challenges and show set analysis stats",
    "",
    "    info",
    "        Show library version and available modules",
    "",
    "    doctor [--verbose]",
    "        Run diagnostic checks on the CAPTCHA system (modules, perf, config health)",
    "",
    "    config-export [--format json|env|yaml] [--output <path>] [--profile minimal|standard|hardened]",
    "        Export a deployment configuration template with all tunable options",
    "",
    "  Examples:",
    "    gif-captcha generate --count 5",
    "    gif-captcha validate --answer \"dog plays\" --expected \"dog playing tic tac toe\"",
    "    gif-captcha benchmark --rounds 1000",
    "    gif-captcha trust --ip 203.0.113.42",
    "    gif-captcha stats --challenges 20",
    "    gif-captcha doctor --verbose",
    "",
  ].join("\n"));
}

// ── Commands ──

var SAMPLE_GIFS = [
  { id: "duel", gifUrl: "https://example.com/duel.gif", humanAnswer: "plot twist in a duel scene", title: "Duel Plot Twist", keywords: ["duel", "twist"] },
  { id: "rappers", gifUrl: "https://example.com/rappers.gif", humanAnswer: "rappers start roller skating", title: "Rappers Skating", keywords: ["rappers", "skating"] },
  { id: "skateboarder", gifUrl: "https://example.com/skate.gif", humanAnswer: "skateboarder appears to fly", title: "Flying Skateboarder", keywords: ["skateboard", "flying"] },
  { id: "banana", gifUrl: "https://example.com/banana.gif", humanAnswer: "banana mascot does a dance-off", title: "Banana Dance-Off", keywords: ["banana", "dance"] },
  { id: "dog-ttt", gifUrl: "https://example.com/dog.gif", humanAnswer: "dog plays tic tac toe", title: "Tic Tac Toe Dog", keywords: ["dog", "game"] },
  { id: "parent-dog", gifUrl: "https://example.com/parent.gif", humanAnswer: "parent dog sacrifices for puppies", title: "Parent Dog Sacrifice", keywords: ["dog", "sacrifice"] },
  { id: "mirror", gifUrl: "https://example.com/mirror.gif", humanAnswer: "mirror creates hand illusion", title: "Mirror Hand Illusion", keywords: ["mirror", "illusion"] },
  { id: "drift", gifUrl: "https://example.com/drift.gif", humanAnswer: "car does a 180 degree drift on highway", title: "Highway Drift", keywords: ["car", "drift"] },
  { id: "road-rage", gifUrl: "https://example.com/hug.gif", humanAnswer: "road rage turns into a hug", title: "Road Rage Hug", keywords: ["road", "hug"] },
  { id: "cake", gifUrl: "https://example.com/cake.gif", humanAnswer: "birthday cake pushed in face", title: "Cake Face Cover", keywords: ["cake", "birthday"] },
];

function cmdGenerate() {
  var count = parseInt(flag("count") || "1", 10);
  if (count > SAMPLE_GIFS.length) count = SAMPLE_GIFS.length;

  // Pick random challenges from samples using a CSPRNG-backed shuffle.
  // Math.random is forbidden in CAPTCHA paths (CWE-330) — see crypto-utils.js.
  var shuffled = secureShuffle(SAMPLE_GIFS.slice());
  var challenges = [];
  for (var i = 0; i < count; i++) {
    var s = shuffled[i];
    challenges.push(gifCaptcha.createChallenge(s));
  }

  console.log("\n  Generated " + count + " challenge(s)\n");
  challenges.forEach(function (ch, idx) {
    console.log("  #" + (idx + 1));
    console.log("    ID:         " + ch.id);
    console.log("    Title:      " + ch.title);
    console.log("    GIF URL:    " + ch.gifUrl);
    console.log("    Keywords:   " + (ch.keywords || []).join(", "));
    console.log("");
  });
}

function cmdValidate() {
  var answer = flag("answer");
  var expected = flag("expected");
  var threshold = parseFloat(flag("threshold") || "0.5");

  if (!answer || !expected) {
    console.error("\n  Error: --answer and --expected are required\n");
    process.exit(1);
  }

  var result = gifCaptcha.validateAnswer(answer, expected, { threshold: threshold });

  console.log("\n  Validation Result");
  console.log("  ─────────────────");
  console.log("  Answer:     \"" + answer + "\"");
  console.log("  Expected:   \"" + expected + "\"");
  console.log("  Similarity: " + (result.score != null ? result.score.toFixed(3) : "N/A"));
  console.log("  Passed:     " + (result.passed ? "✅ Yes" : "❌ No"));
  console.log("  Threshold:  " + threshold);
  console.log("");
}

function cmdBenchmark() {
  var rounds = parseInt(flag("rounds") || "1000", 10);
  var sessions = parseInt(flag("sessions") || "100", 10);

  console.log("\n  Running benchmark (" + rounds + " rounds, " + sessions + " sessions)...\n");

  // Benchmark: createChallenge
  var t0 = Date.now();
  for (var i = 0; i < rounds; i++) {
    gifCaptcha.createChallenge({ id: "bench-" + i, gifUrl: "https://example.com/b.gif", humanAnswer: "test answer" });
  }
  var challTime = Date.now() - t0;

  // Benchmark: validateAnswer
  var t1 = Date.now();
  for (var j = 0; j < rounds; j++) {
    gifCaptcha.validateAnswer("the dog plays tic tac toe", "dog playing tic tac toe");
  }
  var valTime = Date.now() - t1;

  // Benchmark: textSimilarity
  var t2 = Date.now();
  for (var k = 0; k < rounds; k++) {
    gifCaptcha.textSimilarity("a flying skateboarder", "someone skateboarding through the air");
  }
  var simTime = Date.now() - t2;

  // Benchmark: session creation
  var t3 = Date.now();
  for (var s = 0; s < sessions; s++) {
    gifCaptcha.createSessionManager({ maxSessions: 50 });
  }
  var sessTime = Date.now() - t3;

  console.log("  Results:");
  console.log("  ────────");
  console.log("  createChallenge  × " + rounds + "   → " + challTime + "ms (" + (challTime / rounds).toFixed(3) + "ms/op)");
  console.log("  validateAnswer   × " + rounds + "   → " + valTime + "ms (" + (valTime / rounds).toFixed(3) + "ms/op)");
  console.log("  textSimilarity   × " + rounds + "   → " + simTime + "ms (" + (simTime / rounds).toFixed(3) + "ms/op)");
  console.log("  sessionManager   × " + sessions + "   → " + sessTime + "ms (" + (sessTime / sessions).toFixed(3) + "ms/op)");
  console.log("");
}

function cmdPool() {
  var size = parseInt(flag("size") || "10", 10);
  var refill = parseInt(flag("refill") || "5", 10);

  var pool = gifCaptcha.createPoolManager({
    maxSize: size,
    refillThreshold: refill,
  });

  // Seed the pool
  for (var i = 0; i < size; i++) {
    var ch = gifCaptcha.createChallenge({ id: "pool-" + (i + 1), gifUrl: "https://example.com/p" + i + ".gif", humanAnswer: "answer " + (i + 1) });
    pool.add(ch);
  }

  var stats = pool.stats ? pool.stats() : { size: size };

  console.log("\n  Challenge Pool");
  console.log("  ──────────────");
  console.log("  Max size:         " + size);
  console.log("  Refill threshold: " + refill);
  console.log("  Current size:     " + (stats.size || stats.total || size));
  console.log("");
}

function cmdTrust() {
  var ip = flag("ip");
  if (!ip) {
    console.error("\n  Error: --ip is required\n");
    process.exit(1);
  }

  var engine = gifCaptcha.createTrustScoreEngine();

  // Evaluate the IP
  var score = engine.evaluate ? engine.evaluate(ip) : null;
  var scoreVal = engine.getScore ? engine.getScore(ip) : null;

  console.log("\n  Trust Score for " + ip);
  console.log("  ─────────────────" + "─".repeat(ip.length));
  if (scoreVal != null && typeof scoreVal === "object") {
    Object.keys(scoreVal).forEach(function (k) {
      var v = typeof scoreVal[k] === "number" ? scoreVal[k].toFixed(3) : String(scoreVal[k]);
      console.log("  " + k + ": " + v);
    });
  } else if (scoreVal != null) {
    console.log("  Score: " + (typeof scoreVal === "number" ? scoreVal.toFixed(3) : scoreVal));
  } else {
    console.log("  (No prior history — client is unknown)");
    console.log("  Default action: challenge");
  }
  var thresholds = engine.getThresholds ? engine.getThresholds() : null;
  if (thresholds) {
    console.log("\n  Thresholds:");
    Object.keys(thresholds).forEach(function (k) {
      console.log("    " + k + ": " + thresholds[k]);
    });
  }
  console.log("");
}

function cmdStats() {
  var count = parseInt(flag("challenges") || "10", 10);
  var challenges = [];
  for (var i = 0; i < count; i++) {
    challenges.push(gifCaptcha.createChallenge({
      id: "stat-" + (i + 1),
      gifUrl: "https://example.com/s" + i + ".gif",
      humanAnswer: "answer " + (i + 1),
    }));
  }

  var analyzer = gifCaptcha.createSetAnalyzer(challenges);
  var summary = analyzer.summary ? analyzer.summary() : null;

  console.log("\n  Challenge Set Analysis (" + count + " challenges)");
  console.log("  ──────────────────────────");
  if (summary && typeof summary === "object") {
    Object.keys(summary).forEach(function (k) {
      var v = summary[k];
      if (typeof v === "number") v = v.toFixed(3);
      else if (typeof v === "object") v = JSON.stringify(v);
      console.log("  " + k + ": " + v);
    });
  } else {
    console.log("  Total challenges: " + count);
    challenges.forEach(function (ch, idx) {
      console.log("    " + (idx + 1) + ". " + ch.title + " [" + ch.id + "]");
    });
  }
  console.log("");
}

function cmdInfo() {
  var pkg;
  try { pkg = require("../package.json"); } catch (e) { pkg = {}; }

  var modules = Object.keys(gifCaptcha).filter(function (k) {
    return typeof gifCaptcha[k] === "function";
  });

  console.log("\n  gif-captcha v" + (pkg.version || "unknown"));
  console.log("  ────────────────");
  console.log("  Available modules (" + modules.length + "):\n");
  modules.forEach(function (m) {
    console.log("    • " + m);
  });
  console.log("");
}

function cmdDoctor() {
  var verbose = hasFlag("verbose");
  var pkg;
  try { pkg = require("../package.json"); } catch (e) { pkg = {}; }

  var checks = [];
  var warnings = [];
  var errors = [];

  console.log("\n  🩺 gif-captcha Doctor v" + (pkg.version || "unknown"));
  console.log("  ════════════════════════════════\n");

  // 1. Module availability
  console.log("  📦 Module Availability");
  console.log("  ──────────────────────");
  var expectedModules = [
    "createChallenge", "validateAnswer", "textSimilarity",
    "createSessionManager", "createPoolManager", "createTrustScoreEngine",
    "createSetAnalyzer", "createRateLimiter", "createStrengthScorer",
    "createAuditLog", "createStatsCollector", "createHealthMonitor",
    "createIncidentManager", "createExportFormatter", "createLoadTester",
    "createAnomalyDetector", "createTrafficAnalyzer", "createCapacityPlanner",
    "createLocalizationManager", "createFatigueDetector", "createComplianceReporter",
    "createSessionReplay", "createWebhookDispatcher", "createBotSignatureDatabase",
    "createAdaptiveDifficultyTuner", "createBehavioralBiometrics",
    "createGeoRiskScorer", "createHoneypotInjector", "createFraudRingDetector",
    "createSolveFunnelAnalyzer", "createSolvePatternFingerprinter",
    "createChallengeDecayManager", "createChallengeRotationScheduler",
    "createChallengeTemplateEngine", "createResponseTimeProfiler",
    "createSessionRiskAggregator", "createABExperimentRunner",
    "createAccessibilityAnalyzer"
  ];

  var present = 0;
  var missing = 0;
  expectedModules.forEach(function (mod) {
    var exists = typeof gifCaptcha[mod] === "function";
    if (exists) {
      present++;
      if (verbose) console.log("    ✅ " + mod);
    } else {
      missing++;
      warnings.push("Missing module: " + mod);
      console.log("    ⚠️  " + mod + " — not found");
    }
  });

  // Also count any extra exported functions
  var allFns = Object.keys(gifCaptcha).filter(function (k) {
    return typeof gifCaptcha[k] === "function";
  });
  var extras = allFns.length - present;
  console.log("\n    Found: " + present + "/" + expectedModules.length + " expected modules");
  if (extras > 0) console.log("    Extra exports: " + extras);
  checks.push({ name: "Modules", status: missing === 0 ? "pass" : "warn", detail: present + "/" + expectedModules.length });
  console.log("");

  // 2. Core functionality test
  console.log("  🔧 Core Functionality");
  console.log("  ─────────────────────");

  // createChallenge
  try {
    var ch = gifCaptcha.createChallenge({ id: "doc-1", gifUrl: "https://example.com/test.gif", humanAnswer: "test" });
    if (ch && ch.id) {
      console.log("    ✅ createChallenge works");
      checks.push({ name: "createChallenge", status: "pass" });
    } else {
      throw new Error("No challenge returned");
    }
  } catch (e) {
    console.log("    ❌ createChallenge failed: " + e.message);
    errors.push("createChallenge: " + e.message);
    checks.push({ name: "createChallenge", status: "fail" });
  }

  // validateAnswer
  try {
    var res = gifCaptcha.validateAnswer("dog plays", "dog playing tic tac toe");
    if (res && typeof res.passed === "boolean") {
      console.log("    ✅ validateAnswer works (score: " + (res.score != null ? res.score.toFixed(3) : "N/A") + ")");
      checks.push({ name: "validateAnswer", status: "pass" });
    } else {
      throw new Error("Invalid result shape");
    }
  } catch (e) {
    console.log("    ❌ validateAnswer failed: " + e.message);
    errors.push("validateAnswer: " + e.message);
    checks.push({ name: "validateAnswer", status: "fail" });
  }

  // textSimilarity
  try {
    var sim = gifCaptcha.textSimilarity("hello world", "hello earth");
    if (typeof sim === "number") {
      console.log("    ✅ textSimilarity works (similarity: " + sim.toFixed(3) + ")");
      checks.push({ name: "textSimilarity", status: "pass" });
    } else {
      throw new Error("Non-numeric result");
    }
  } catch (e) {
    console.log("    ❌ textSimilarity failed: " + e.message);
    errors.push("textSimilarity: " + e.message);
    checks.push({ name: "textSimilarity", status: "fail" });
  }

  // sessionManager
  try {
    var sm = gifCaptcha.createSessionManager({ maxSessions: 10 });
    if (sm) {
      console.log("    ✅ createSessionManager works");
      checks.push({ name: "createSessionManager", status: "pass" });
    }
  } catch (e) {
    console.log("    ❌ createSessionManager failed: " + e.message);
    errors.push("createSessionManager: " + e.message);
    checks.push({ name: "createSessionManager", status: "fail" });
  }

  // poolManager
  try {
    var pm = gifCaptcha.createPoolManager({ maxSize: 5 });
    if (pm) {
      console.log("    ✅ createPoolManager works");
      checks.push({ name: "createPoolManager", status: "pass" });
    }
  } catch (e) {
    console.log("    ❌ createPoolManager failed: " + e.message);
    errors.push("createPoolManager: " + e.message);
    checks.push({ name: "createPoolManager", status: "fail" });
  }
  console.log("");

  // 3. Performance quick-check
  console.log("  ⚡ Performance Quick-Check");
  console.log("  ──────────────────────────");
  var perfRounds = 500;

  var t0 = Date.now();
  for (var i = 0; i < perfRounds; i++) {
    gifCaptcha.createChallenge({ id: "perf-" + i, gifUrl: "https://example.com/p.gif", humanAnswer: "test" });
  }
  var createMs = Date.now() - t0;
  var createPer = (createMs / perfRounds).toFixed(3);

  var t1 = Date.now();
  for (var j = 0; j < perfRounds; j++) {
    gifCaptcha.validateAnswer("dog plays tic tac toe", "dog playing tic tac toe");
  }
  var valMs = Date.now() - t1;
  var valPer = (valMs / perfRounds).toFixed(3);

  var t2 = Date.now();
  for (var k = 0; k < perfRounds; k++) {
    gifCaptcha.textSimilarity("skateboarder flies through air", "someone skateboarding and appearing to fly");
  }
  var simMs = Date.now() - t2;
  var simPer = (simMs / perfRounds).toFixed(3);

  console.log("    createChallenge:  " + createPer + " ms/op (" + perfRounds + " rounds)");
  console.log("    validateAnswer:   " + valPer + " ms/op (" + perfRounds + " rounds)");
  console.log("    textSimilarity:   " + simPer + " ms/op (" + perfRounds + " rounds)");

  var perfOk = parseFloat(valPer) < 1.0 && parseFloat(createPer) < 1.0;
  if (perfOk) {
    console.log("    ✅ Performance looks good");
    checks.push({ name: "Performance", status: "pass" });
  } else {
    console.log("    ⚠️  Some operations are slow (>1ms/op)");
    warnings.push("Slow operations detected");
    checks.push({ name: "Performance", status: "warn" });
  }
  console.log("");

  // 4. Validation edge cases
  console.log("  🧪 Validation Edge Cases");
  console.log("  ────────────────────────");
  var edgeCases = [
    { answer: "", expected: "test", desc: "empty answer" },
    { answer: "test", expected: "", desc: "empty expected" },
    { answer: "DOG PLAYS", expected: "dog plays", desc: "case insensitivity" },
    { answer: "  spaced  out  ", expected: "spaced out", desc: "extra whitespace" },
    { answer: "exact match", expected: "exact match", desc: "exact match" },
  ];
  var edgePass = 0;
  edgeCases.forEach(function (ec) {
    try {
      var r = gifCaptcha.validateAnswer(ec.answer, ec.expected);
      if (r && typeof r.passed === "boolean") {
        edgePass++;
        if (verbose) console.log("    ✅ " + ec.desc + " → passed=" + r.passed + " score=" + (r.score != null ? r.score.toFixed(3) : "N/A"));
      }
    } catch (e) {
      console.log("    ❌ " + ec.desc + " threw: " + e.message);
      errors.push("Edge case '" + ec.desc + "': " + e.message);
    }
  });
  console.log("    " + edgePass + "/" + edgeCases.length + " edge cases handled gracefully");
  checks.push({ name: "Edge Cases", status: edgePass === edgeCases.length ? "pass" : "warn", detail: edgePass + "/" + edgeCases.length });
  console.log("");

  // 5. Node.js environment
  console.log("  🖥️  Environment");
  console.log("  ───────────────");
  console.log("    Node.js: " + process.version);
  console.log("    Platform: " + process.platform + " " + process.arch);
  console.log("    Memory: " + Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + " MB used / " + Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + " MB total");
  checks.push({ name: "Environment", status: "pass" });
  console.log("");

  // Summary
  var passCount = checks.filter(function (c) { return c.status === "pass"; }).length;
  var warnCount = checks.filter(function (c) { return c.status === "warn"; }).length;
  var failCount = checks.filter(function (c) { return c.status === "fail"; }).length;

  console.log("  ══════════════════════════════════");
  console.log("  📊 Summary");
  console.log("  ──────────");
  console.log("    ✅ Passed:   " + passCount);
  if (warnCount > 0) console.log("    ⚠️  Warnings: " + warnCount);
  if (failCount > 0) console.log("    ❌ Failed:   " + failCount);
  console.log("");

  if (warnings.length > 0) {
    console.log("  ⚠️  Warnings:");
    warnings.forEach(function (w) { console.log("    • " + w); });
    console.log("");
  }
  if (errors.length > 0) {
    console.log("  ❌ Errors:");
    errors.forEach(function (e) { console.log("    • " + e); });
    console.log("");
  }

  if (failCount === 0 && warnCount === 0) {
    console.log("  🎉 Everything looks healthy! Your CAPTCHA system is ready.\n");
  } else if (failCount === 0) {
    console.log("  👍 System is functional with minor warnings.\n");
  } else {
    console.log("  🔴 Critical issues found. Please review the errors above.\n");
    process.exit(1);
  }
}

function cmdConfigExport() {
  var format = flag("format") || "json";
  var output = flag("output");
  var profile = flag("profile") || "standard";

  if (["json", "env", "yaml"].indexOf(format) === -1) {
    console.error("\n  Error: --format must be json, env, or yaml\n");
    process.exit(1);
  }
  if (["minimal", "standard", "hardened"].indexOf(profile) === -1) {
    console.error("\n  Error: --profile must be minimal, standard, or hardened\n");
    process.exit(1);
  }

  var profiles = {
    minimal: {
      challenge: { poolSize: 20, timeoutMs: 30000, maxAttempts: 5 },
      validation: { threshold: 0.5, caseSensitive: false },
      rateLimit: { windowMs: 60000, maxRequests: 30 },
      session: { maxSessions: 500, ttlMs: 600000 },
      trust: { initialScore: 50, decayRate: 0.1 },
      security: { proofOfWork: false, honeypot: false, replayProtection: true },
      monitoring: { statsEnabled: false, auditLog: false, healthCheck: true },
    },
    standard: {
      challenge: { poolSize: 50, timeoutMs: 30000, maxAttempts: 3, rotationIntervalMs: 3600000, decayEnabled: true },
      validation: { threshold: 0.6, caseSensitive: false, trimWhitespace: true },
      rateLimit: { windowMs: 60000, maxRequests: 20, burstMax: 5, blockDurationMs: 300000 },
      session: { maxSessions: 1000, ttlMs: 600000, cleanupIntervalMs: 60000 },
      trust: { initialScore: 50, decayRate: 0.05, boostOnPass: 10, penaltyOnFail: 15, minScore: 0, maxScore: 100 },
      security: { proofOfWork: true, powDifficulty: 4, honeypot: true, replayProtection: true, maxAnswerLength: 500 },
      monitoring: { statsEnabled: true, auditLog: true, healthCheck: true, anomalyDetection: true },
      adaptive: { enabled: true, minDifficulty: 1, maxDifficulty: 10, adjustInterval: 50 },
    },
    hardened: {
      challenge: { poolSize: 100, timeoutMs: 20000, maxAttempts: 2, rotationIntervalMs: 1800000, decayEnabled: true, retireAfterSolves: 50 },
      validation: { threshold: 0.7, caseSensitive: false, trimWhitespace: true, minAnswerLength: 3 },
      rateLimit: { windowMs: 60000, maxRequests: 10, burstMax: 3, blockDurationMs: 600000, ipWhitelist: [] },
      session: { maxSessions: 2000, ttlMs: 300000, cleanupIntervalMs: 30000, maxSessionsPerIp: 5 },
      trust: { initialScore: 30, decayRate: 0.08, boostOnPass: 5, penaltyOnFail: 25, minScore: 0, maxScore: 100, blockBelowScore: 10 },
      security: { proofOfWork: true, powDifficulty: 6, honeypot: true, replayProtection: true, maxAnswerLength: 300, botSignatureDb: true, behavioralBiometrics: true },
      monitoring: { statsEnabled: true, auditLog: true, healthCheck: true, anomalyDetection: true, incidentManager: true, webhookAlerts: true },
      adaptive: { enabled: true, minDifficulty: 3, maxDifficulty: 10, adjustInterval: 25, escalateOnFailStreak: 3 },
      geo: { enabled: true, highRiskRegions: [], blockTor: true, blockDatacenters: true },
    },
  };

  var config = profiles[profile];

  var result;
  if (format === "json") {
    result = JSON.stringify(config, null, 2);
  } else if (format === "env") {
    result = configToEnv(config, "GIF_CAPTCHA");
  } else {
    result = configToYaml(config, 0);
  }

  if (output) {
    var fs = require("fs");
    var path = require("path");
    var resolved = path.resolve(output);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, result + "\n", "utf8");
    console.log("\n  ✅ Configuration exported to " + resolved);
    console.log("     Profile: " + profile + " | Format: " + format + "\n");
  } else {
    console.log(result);
  }
}

function configToEnv(obj, prefix) {
  var lines = [];
  Object.keys(obj).forEach(function (section) {
    var sectionPrefix = prefix + "_" + section.toUpperCase();
    if (typeof obj[section] === "object" && obj[section] !== null && !Array.isArray(obj[section])) {
      Object.keys(obj[section]).forEach(function (key) {
        var envKey = sectionPrefix + "_" + key.replace(/([A-Z])/g, "_$1").toUpperCase();
        var val = obj[section][key];
        if (Array.isArray(val)) val = val.join(",");
        lines.push(envKey + "=" + val);
      });
    } else {
      var envKey2 = sectionPrefix.replace(/([A-Z])/g, "_$1").toUpperCase();
      lines.push(envKey2 + "=" + obj[section]);
    }
  });
  return lines.join("\n");
}

function configToYaml(obj, indent) {
  var lines = [];
  var pad = "  ".repeat(indent);
  Object.keys(obj).forEach(function (key) {
    var val = obj[key];
    if (typeof val === "object" && val !== null && !Array.isArray(val)) {
      lines.push(pad + key + ":");
      lines.push(configToYaml(val, indent + 1));
    } else if (Array.isArray(val)) {
      lines.push(pad + key + ": [" + val.map(function (v) { return JSON.stringify(v); }).join(", ") + "]");
    } else if (typeof val === "string") {
      lines.push(pad + key + ": \"" + val + "\"");
    } else {
      lines.push(pad + key + ": " + val);
    }
  });
  return lines.join("\n");
}

// ── Dispatch ──

switch (command) {
  case "generate":  cmdGenerate(); break;
  case "validate":  cmdValidate(); break;
  case "benchmark": cmdBenchmark(); break;
  case "pool":      cmdPool();      break;
  case "trust":     cmdTrust();     break;
  case "stats":     cmdStats();     break;
  case "info":      cmdInfo();      break;
  case "doctor":    cmdDoctor();    break;
  case "config-export": cmdConfigExport(); break;
  case "--help": case "-h": case "help": case undefined:
    printUsage();
    break;
  default:
    console.error("\n  Unknown command: " + command);
    printUsage();
    process.exit(1);
}
