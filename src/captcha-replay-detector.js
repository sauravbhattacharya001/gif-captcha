/**
 * captcha-replay-detector.js — CAPTCHA Replay Attack Detection Engine.
 *
 * Detects replay attacks, timing anomalies, solution pattern reuse,
 * and suspicious fingerprint clusters. Provides composite threat
 * scoring with optional auto-block mode.
 *
 * @module captcha-replay-detector
 */

"use strict";

var EventEmitter = require("events");
var crypto = require("crypto");
var _shared = require("./shared-utils");
var _clamp = _shared._clamp;

// ── Defaults ────────────────────────────────────────────────────────
var DEFAULTS = {
  windowMs: 10 * 60 * 1000,   // 10 minute sliding window
  maxTokens: 50000,            // max tracked tokens
  minSolveMs: 800,             // fastest plausible human solve
  threatThreshold: 70,         // auto-block above this score
  autoBlock: false,
  weights: {
    tokenReplay: 40,
    timingAnomaly: 25,
    patternMatch: 25,
    fingerprintCluster: 10
  }
};

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Hash a string for compact storage.
 * @param {string} s
 * @returns {string}
 */
function _hash(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 16);
}

/**
 * Current timestamp in ms.
 * @returns {number}
 */
function _now() { return Date.now(); }


// ── CaptchaReplayDetector ───────────────────────────────────────────

/**
 * CAPTCHA Replay Attack Detector.
 *
 * Tracks solution tokens, solve timings, answer patterns, and
 * behavioral fingerprints to identify replay and automation attacks.
 *
 * @class
 * @extends EventEmitter
 * @param {Object} [opts]
 * @param {number} [opts.windowMs=600000]      Sliding window (ms)
 * @param {number} [opts.maxTokens=50000]       Max tracked tokens
 * @param {number} [opts.minSolveMs=800]        Min plausible solve time
 * @param {number} [opts.threatThreshold=70]    Auto-block threshold
 * @param {boolean} [opts.autoBlock=false]      Enable auto-blocking
 * @param {Object}  [opts.weights]              Signal weights (sum to 100)
 */
function CaptchaReplayDetector(opts) {
  EventEmitter.call(this);
  var o = opts || {};
  this.windowMs = o.windowMs != null ? o.windowMs : DEFAULTS.windowMs;
  this.maxTokens = o.maxTokens != null ? o.maxTokens : DEFAULTS.maxTokens;
  this.minSolveMs = o.minSolveMs != null ? o.minSolveMs : DEFAULTS.minSolveMs;
  this.threatThreshold = o.threatThreshold != null ? o.threatThreshold : DEFAULTS.threatThreshold;
  this.autoBlock = !!o.autoBlock;
  this.weights = Object.assign({}, DEFAULTS.weights, o.weights || {});

  // State
  this._tokens = new Map();        // hash → timestamp of first use
  this._sessions = new Map();      // sessionId → { solves[], flags[], threatScores[], blocked }
  this._ipAnswers = new Map();     // answerHash → Set<ip>
  this._fingerprints = new Map();  // fpHash → Set<sessionId>
  this._stats = { totalSolves: 0, replaysDetected: 0, timingAnomalies: 0, patternsMatched: 0, sessionsBlocked: 0 };
}

CaptchaReplayDetector.prototype = Object.create(EventEmitter.prototype);
CaptchaReplayDetector.prototype.constructor = CaptchaReplayDetector;

/**
 * Prune expired tokens outside the sliding window.
 * @private
 */
CaptchaReplayDetector.prototype._prune = function () {
  var cutoff = _now() - this.windowMs;
  var tokens = this._tokens;
  if (tokens.size <= this.maxTokens) return;
  var keys = Array.from(tokens.keys());
  for (var i = 0; i < keys.length; i++) {
    if (tokens.get(keys[i]) < cutoff) tokens.delete(keys[i]);
  }
};

/**
 * Ensure a session record exists.
 * @private
 * @param {string} sessionId
 * @returns {Object}
 */
CaptchaReplayDetector.prototype._ensureSession = function (sessionId) {
  if (!this._sessions.has(sessionId)) {
    this._sessions.set(sessionId, { solves: [], flags: [], threatScores: [], blocked: false });
  }
  return this._sessions.get(sessionId);
};

/**
 * Record a CAPTCHA solve attempt and evaluate for replay/attack signals.
 *
 * @param {string} sessionId  Unique session identifier
 * @param {string} token      Solution token
 * @param {number} solveTimeMs Time taken to solve (ms)
 * @param {string} ip         Client IP address
 * @param {string} [fingerprint] Behavioral fingerprint string
 * @returns {{ allowed: boolean, threatScore: number, flags: string[], details: Object }}
 */
CaptchaReplayDetector.prototype.recordSolve = function (sessionId, token, solveTimeMs, ip, fingerprint) {
  this._prune();
  this._stats.totalSolves++;

  var session = this._ensureSession(sessionId);
  var flags = [];
  var details = {};
  var signals = { tokenReplay: 0, timingAnomaly: 0, patternMatch: 0, fingerprintCluster: 0 };

  // ── 1. Token Replay Detection ──
  var tokenHash = _hash(token);
  if (this._tokens.has(tokenHash)) {
    signals.tokenReplay = 1;
    flags.push("token-replay");
    details.tokenFirstSeen = this._tokens.get(tokenHash);
    this._stats.replaysDetected++;
    this.emit("replay-detected", { sessionId: sessionId, token: tokenHash, ip: ip });
  }
  this._tokens.set(tokenHash, _now());

  // ── 2. Timing Anomaly Detection ──
  if (solveTimeMs < this.minSolveMs) {
    signals.timingAnomaly = 1;
    flags.push("timing-anomaly");
    details.solveTimeMs = solveTimeMs;
    details.minExpected = this.minSolveMs;
    this._stats.timingAnomalies++;
    this.emit("timing-anomaly", { sessionId: sessionId, solveTimeMs: solveTimeMs, ip: ip });
  } else if (session.solves.length >= 2) {
    // Check for suspiciously identical timing (variance < 10ms across last 5 solves)
    var recent = session.solves.slice(-4).map(function (s) { return s.solveTimeMs; });
    recent.push(solveTimeMs);
    if (recent.length >= 3) {
      var mean = recent.reduce(function (a, b) { return a + b; }, 0) / recent.length;
      var variance = recent.reduce(function (a, b) { return a + (b - mean) * (b - mean); }, 0) / recent.length;
      if (variance < 100) { // std dev < 10ms — unnaturally consistent
        signals.timingAnomaly = Math.max(signals.timingAnomaly, 0.7);
        if (flags.indexOf("timing-anomaly") === -1) flags.push("timing-anomaly");
        details.timingVariance = variance;
        this._stats.timingAnomalies++;
      }
    }
  }

  // ── 3. Solution Pattern Matching ──
  var answerHash = _hash(token + ":" + solveTimeMs);
  if (!this._ipAnswers.has(answerHash)) this._ipAnswers.set(answerHash, new Set());
  this._ipAnswers.get(answerHash).add(ip);
  if (this._ipAnswers.get(answerHash).size > 1) {
    signals.patternMatch = Math.min(this._ipAnswers.get(answerHash).size / 5, 1);
    flags.push("pattern-match");
    details.matchingIPs = this._ipAnswers.get(answerHash).size;
    this._stats.patternsMatched++;
    this.emit("pattern-match", { sessionId: sessionId, ips: this._ipAnswers.get(answerHash).size, ip: ip });
  }

  // ── 4. Fingerprint Clustering ──
  if (fingerprint) {
    var fpHash = _hash(fingerprint);
    if (!this._fingerprints.has(fpHash)) this._fingerprints.set(fpHash, new Set());
    this._fingerprints.get(fpHash).add(sessionId);
    if (this._fingerprints.get(fpHash).size > 3) {
      signals.fingerprintCluster = Math.min((this._fingerprints.get(fpHash).size - 3) / 7, 1);
      flags.push("fingerprint-cluster");
      details.clusterSize = this._fingerprints.get(fpHash).size;
    }
  }

  // ── Composite Threat Score ──
  var w = this.weights;
  var threatScore = _clamp(Math.round(
    signals.tokenReplay * w.tokenReplay +
    signals.timingAnomaly * w.timingAnomaly +
    signals.patternMatch * w.patternMatch +
    signals.fingerprintCluster * w.fingerprintCluster
  ), 0, 100);

  // Record
  session.solves.push({ token: tokenHash, solveTimeMs: solveTimeMs, ip: ip, ts: _now(), threatScore: threatScore });
  session.flags = session.flags.concat(flags);
  session.threatScores.push(threatScore);

  // ── Auto-Block ──
  var allowed = true;
  if (session.blocked) {
    allowed = false;
  } else if (this.autoBlock && threatScore >= this.threatThreshold) {
    session.blocked = true;
    allowed = false;
    this._stats.sessionsBlocked++;
    this.emit("auto-blocked", { sessionId: sessionId, threatScore: threatScore, flags: flags });
  }

  return { allowed: allowed, threatScore: threatScore, flags: flags, details: details };
};

/**
 * Get threat profile for a session.
 * @param {string} sessionId
 * @returns {Object|null}
 */
CaptchaReplayDetector.prototype.getSessionProfile = function (sessionId) {
  var s = this._sessions.get(sessionId);
  if (!s) return null;
  var scores = s.threatScores;
  var avg = scores.length ? Math.round(scores.reduce(function (a, b) { return a + b; }, 0) / scores.length) : 0;
  var max = scores.length ? Math.max.apply(null, scores) : 0;
  // Unique flags
  var unique = [];
  for (var i = 0; i < s.flags.length; i++) {
    if (unique.indexOf(s.flags[i]) === -1) unique.push(s.flags[i]);
  }
  return {
    sessionId: sessionId,
    solveCount: s.solves.length,
    blocked: s.blocked,
    avgThreatScore: avg,
    maxThreatScore: max,
    flags: unique,
    solves: s.solves
  };
};

/**
 * Get aggregate detection statistics.
 * @returns {Object}
 */
CaptchaReplayDetector.prototype.getStats = function () {
  return Object.assign({}, this._stats, {
    activeSessions: this._sessions.size,
    trackedTokens: this._tokens.size,
    replayRate: this._stats.totalSolves ? +(this._stats.replaysDetected / this._stats.totalSolves * 100).toFixed(2) : 0
  });
};

/**
 * Clear all detection state.
 */
CaptchaReplayDetector.prototype.reset = function () {
  this._tokens.clear();
  this._sessions.clear();
  this._ipAnswers.clear();
  this._fingerprints.clear();
  this._stats = { totalSolves: 0, replaysDetected: 0, timingAnomalies: 0, patternsMatched: 0, sessionsBlocked: 0 };
};

module.exports = { CaptchaReplayDetector: CaptchaReplayDetector };
