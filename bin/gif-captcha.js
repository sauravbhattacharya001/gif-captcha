#!/usr/bin/env node

"use strict";

var gifCaptcha = require("../src/index");

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
    "  Examples:",
    "    gif-captcha generate --count 5",
    "    gif-captcha validate --answer \"dog plays\" --expected \"dog playing tic tac toe\"",
    "    gif-captcha benchmark --rounds 1000",
    "    gif-captcha trust --ip 203.0.113.42",
    "    gif-captcha stats --challenges 20",
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

  // Pick random challenges from samples
  var shuffled = SAMPLE_GIFS.slice().sort(function () { return Math.random() - 0.5; });
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

// ── Dispatch ──

switch (command) {
  case "generate":  cmdGenerate(); break;
  case "validate":  cmdValidate(); break;
  case "benchmark": cmdBenchmark(); break;
  case "pool":      cmdPool();      break;
  case "trust":     cmdTrust();     break;
  case "stats":     cmdStats();     break;
  case "info":      cmdInfo();      break;
  case "--help": case "-h": case "help": case undefined:
    printUsage();
    break;
  default:
    console.error("\n  Unknown command: " + command);
    printUsage();
    process.exit(1);
}
