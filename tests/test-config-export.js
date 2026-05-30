"use strict";

var { execFileSync } = require("child_process");
var path = require("path");
var fs = require("fs");
var os = require("os");

var CLI = path.resolve(__dirname, "..", "bin", "gif-captcha.js");

function run(args) {
  return execFileSync(process.execPath, [CLI].concat(args), { encoding: "utf8" });
}

// --- JSON format tests ---
var jsonOut = run(["config-export", "--format", "json", "--profile", "standard"]);
var parsed = JSON.parse(jsonOut);
console.assert(parsed.challenge.poolSize === 50, "standard poolSize");
console.assert(parsed.security.proofOfWork === true, "standard pow");
console.assert(parsed.adaptive.enabled === true, "standard adaptive");

// --- env format tests ---
var envOut = run(["config-export", "--format", "env", "--profile", "minimal"]);
console.assert(envOut.includes("GIF_CAPTCHA_CHALLENGE_POOL_SIZE=20"), "env poolSize");
console.assert(envOut.includes("GIF_CAPTCHA_SECURITY_HONEYPOT=false"), "env honeypot");

// --- yaml format tests ---
var yamlOut = run(["config-export", "--format", "yaml", "--profile", "hardened"]);
console.assert(yamlOut.includes("powDifficulty: 6"), "yaml pow difficulty");
console.assert(yamlOut.includes("blockTor: true"), "yaml blockTor");

// --- profiles differ ---
var minJson = JSON.parse(run(["config-export", "--format", "json", "--profile", "minimal"]));
var hardJson = JSON.parse(run(["config-export", "--format", "json", "--profile", "hardened"]));
console.assert(minJson.challenge.poolSize < hardJson.challenge.poolSize, "hardened > minimal pool");
console.assert(!minJson.geo, "minimal has no geo");
console.assert(hardJson.geo.blockTor === true, "hardened has geo");

// --- --output writes file ---
var tmpFile = path.join(os.tmpdir(), "gif-captcha-config-test-" + Date.now() + ".json");
run(["config-export", "--format", "json", "--profile", "standard", "--output", tmpFile]);
var written = JSON.parse(fs.readFileSync(tmpFile, "utf8"));
console.assert(written.challenge.poolSize === 50, "file output correct");
fs.unlinkSync(tmpFile);

// --- invalid format errors ---
try {
  run(["config-export", "--format", "xml"]);
  console.assert(false, "should have thrown");
} catch (e) {
  console.assert(e.status !== 0, "exits non-zero on bad format");
}

// --- invalid profile errors ---
try {
  run(["config-export", "--profile", "ultra"]);
  console.assert(false, "should have thrown");
} catch (e) {
  console.assert(e.status !== 0, "exits non-zero on bad profile");
}

console.log("All config-export tests passed (" + 10 + " assertions)");
