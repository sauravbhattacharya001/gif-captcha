"use strict";

/**
 * Regression test for CWE-330 (Use of Insufficiently Random Values) in the
 * gif-captcha CLI.
 *
 * History: the `generate` command originally selected sample challenges via
 *   `arr.sort(() => Math.random() - 0.5)`
 * which is both biased and predictable. The library's crypto-utils.js
 * explicitly forbids Math.random in CAPTCHA-touching code, and the CLI must
 * hold the same line — otherwise an attacker can replay the CLI to enumerate
 * likely orderings.
 *
 * This test asserts:
 *   1. The CLI source no longer contains `Math.random` (string-level guard).
 *   2. `generate --count N` produces N distinct challenges (sanity check the
 *      shuffle keeps the unique-pick semantics).
 *   3. The shuffle distribution is not stuck — running twice with N == pool
 *      size usually produces different orderings (probabilistic, but with
 *      10! orderings the false-positive rate is < 1 in 3.6M).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const CLI = path.join(__dirname, "..", "bin", "gif-captcha.js");

function runCli(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    timeout: 15000,
  });
  if (r.status !== 0) {
    throw new Error(
      `CLI exited ${r.status}: ${r.stderr || r.stdout || "(no output)"}`
    );
  }
  return r.stdout;
}

function extractIds(stdout) {
  const ids = [];
  const re = /^\s*ID:\s+(\S+)/gm;
  let m;
  while ((m = re.exec(stdout)) !== null) ids.push(m[1]);
  return ids;
}

test("CLI source contains no Math.random (CWE-330 guard)", () => {
  const src = fs.readFileSync(CLI, "utf8");
  // Allow the word inside comments by stripping line/block comments first.
  const stripped = src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
  assert.ok(
    !/Math\.random\s*\(/.test(stripped),
    "bin/gif-captcha.js must not call Math.random() — use crypto-utils.secureRandomInt instead (CWE-330)."
  );
});

test("generate --count N returns N distinct sample challenges", () => {
  const out = runCli(["generate", "--count", "10"]);
  const ids = extractIds(out);
  assert.equal(ids.length, 10, "expected 10 challenge ids in output");
  const unique = new Set(ids);
  assert.equal(unique.size, ids.length, "challenges must be unique (no duplicates in shuffle)");
});

test("generate --count clamps to sample pool size", () => {
  const out = runCli(["generate", "--count", "999"]);
  const ids = extractIds(out);
  // SAMPLE_GIFS has 10 entries.
  assert.equal(ids.length, 10, "count should clamp to SAMPLE_GIFS length (10)");
});

test("shuffle produces different orderings across runs (not stuck)", () => {
  // Probabilistic: with 10! orderings, the chance of identical output across
  // 5 runs by chance is < 1 in 600k. If this ever flakes, investigate.
  const orderings = new Set();
  for (let i = 0; i < 5; i++) {
    const ids = extractIds(runCli(["generate", "--count", "10"]));
    orderings.add(ids.join(","));
  }
  assert.ok(
    orderings.size > 1,
    "expected at least 2 distinct orderings across 5 runs; shuffle appears deterministic"
  );
});
