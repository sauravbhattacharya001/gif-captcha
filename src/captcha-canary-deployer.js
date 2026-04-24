"use strict";

// ── CAPTCHA Canary Deployer ─────────────────────────────────────
// Autonomous canary CAPTCHA deployment for early bot capability detection.
// Canaries act as sentinel challenges that detect when bots develop
// new solving capabilities before they impact production CAPTCHAs.

const crypto = require("crypto");

/**
 * @typedef {Object} CanaryConfig
 * @property {number} frameCount    - Number of GIF frames (3–12)
 * @property {number} noiseLevel    - Visual noise intensity (0–1)
 * @property {number} distortion    - Geometric distortion (0–1)
 * @property {number} colorComplexity - Color palette complexity (1–5)
 * @property {number} animationSpeed  - Animation speed multiplier (0.1–3)
 */

/**
 * @typedef {Object} SolveAttempt
 * @property {boolean} isBot
 * @property {number}  solveTimeMs
 * @property {boolean} correct
 * @property {number}  timestamp
 */

/**
 * @typedef {Object} Canary
 * @property {string}        id
 * @property {string}        name
 * @property {CanaryConfig}  config
 * @property {number}        deployedAt
 * @property {string}        status       - "active" | "retired" | "compromised"
 * @property {SolveAttempt[]} solveHistory
 */

class CanaryDeployer {
  constructor() {
    /** @type {Map<string, Canary>} */
    this._canaries = new Map();
    /** @type {Array<{ts:number, botRate:number}>} */
    this._capabilityHistory = [];
  }

  /**
   * Deploy a new canary CAPTCHA with the given configuration.
   * @param {Partial<CanaryConfig> & {name?: string}} config
   * @returns {Canary}
   */
  deployCanary(config = {}) {
    const id = crypto.randomBytes(8).toString("hex");
    const canary = {
      id,
      name: config.name || `canary-${id.slice(0, 6)}`,
      config: {
        frameCount: _clamp(config.frameCount || 6, 3, 12),
        noiseLevel: _clamp(config.noiseLevel || 0.3, 0, 1),
        distortion: _clamp(config.distortion || 0.3, 0, 1),
        colorComplexity: _clamp(config.colorComplexity || 2, 1, 5),
        animationSpeed: _clamp(config.animationSpeed || 1, 0.1, 3),
      },
      deployedAt: Date.now(),
      status: "active",
      solveHistory: [],
    };
    this._canaries.set(id, canary);
    return canary;
  }

  /**
   * Record a solve attempt against a canary.
   * @param {string} canaryId
   * @param {{isBot:boolean, solveTimeMs:number, correct:boolean}} attempt
   */
  recordSolveAttempt(canaryId, { isBot, solveTimeMs, correct }) {
    const c = this._canaries.get(canaryId);
    if (!c) throw new Error(`Unknown canary: ${canaryId}`);
    c.solveHistory.push({ isBot: !!isBot, solveTimeMs, correct: !!correct, timestamp: Date.now() });
  }

  /**
   * Analyze a single canary's effectiveness.
   * @param {string} canaryId
   * @returns {{humanPassRate:number, botPassRate:number, detectionGap:number, trend:string, totalAttempts:number}}
   */
  analyzeCanary(canaryId) {
    const c = this._canaries.get(canaryId);
    if (!c) throw new Error(`Unknown canary: ${canaryId}`);
    const h = c.solveHistory;
    const humans = h.filter(a => !a.isBot);
    const bots = h.filter(a => a.isBot);
    const humanPass = humans.length ? humans.filter(a => a.correct).length / humans.length : 0;
    const botPass = bots.length ? bots.filter(a => a.correct).length / bots.length : 0;
    const gap = humanPass - botPass;

    // Trend: compare last 25% of bot attempts vs first 25%
    let trend = "stable";
    if (bots.length >= 8) {
      const q = Math.floor(bots.length / 4);
      const earlyRate = bots.slice(0, q).filter(a => a.correct).length / q;
      const lateRate = bots.slice(-q).filter(a => a.correct).length / q;
      if (lateRate - earlyRate > 0.1) trend = "rising";
      else if (earlyRate - lateRate > 0.1) trend = "falling";
    }

    return { humanPassRate: humanPass, botPassRate: botPass, detectionGap: gap, trend, totalAttempts: h.length };
  }

  /**
   * Get fleet-wide status overview.
   * @returns {{total:number, active:number, compromised:number, retired:number, avgDetectionGap:number, canaries:Array}}
   */
  getFleetStatus() {
    const all = [...this._canaries.values()];
    const active = all.filter(c => c.status === "active");
    const analyses = active.map(c => ({ ...this.analyzeCanary(c.id), id: c.id, name: c.name, status: c.status, config: c.config, deployedAt: c.deployedAt }));
    const avgGap = analyses.length ? analyses.reduce((s, a) => s + a.detectionGap, 0) / analyses.length : 0;
    return {
      total: all.length,
      active: active.length,
      compromised: all.filter(c => c.status === "compromised").length,
      retired: all.filter(c => c.status === "retired").length,
      avgDetectionGap: avgGap,
      canaries: all.map(c => ({ ...this.analyzeCanary(c.id), id: c.id, name: c.name, status: c.status, config: c.config, deployedAt: c.deployedAt })),
    };
  }

  /**
   * Autonomous rotation: retire compromised canaries and spawn harder replacements.
   * @returns {{retired:string[], deployed:Canary[]}}
   */
  autoRotate() {
    const retired = [];
    const deployed = [];
    for (const c of this._canaries.values()) {
      if (c.status !== "active") continue;
      const analysis = this.analyzeCanary(c.id);
      if (analysis.totalAttempts < 10) continue; // need minimum data
      if (analysis.detectionGap < 0.1 || analysis.trend === "rising") {
        c.status = analysis.detectionGap < 0.05 ? "compromised" : "retired";
        retired.push(c.id);
        // Spawn harder replacement
        const newCanary = this.deployCanary({
          name: `canary-${crypto.randomBytes(3).toString("hex")}`,
          frameCount: Math.min(12, c.config.frameCount + 1),
          noiseLevel: Math.min(1, c.config.noiseLevel + 0.1),
          distortion: Math.min(1, c.config.distortion + 0.05),
          colorComplexity: Math.min(5, c.config.colorComplexity + 0.5),
          animationSpeed: Math.max(0.1, c.config.animationSpeed - 0.1),
        });
        deployed.push(newCanary);
      }
    }
    return { retired, deployed };
  }

  /**
   * Detect sudden bot capability shifts by comparing recent vs historical rates.
   * @returns {{shift:boolean, magnitude:number, direction:string, details:string}}
   */
  detectCapabilityShift() {
    const active = [...this._canaries.values()].filter(c => c.status === "active");
    if (active.length === 0) return { shift: false, magnitude: 0, direction: "none", details: "No active canaries" };

    let recentBotRate = 0, historicalBotRate = 0, count = 0;
    for (const c of active) {
      const bots = c.solveHistory.filter(a => a.isBot);
      if (bots.length < 10) continue;
      const mid = Math.floor(bots.length / 2);
      const oldRate = bots.slice(0, mid).filter(a => a.correct).length / mid;
      const newRate = bots.slice(mid).filter(a => a.correct).length / (bots.length - mid);
      historicalBotRate += oldRate;
      recentBotRate += newRate;
      count++;
    }
    if (count === 0) return { shift: false, magnitude: 0, direction: "none", details: "Insufficient data" };
    historicalBotRate /= count;
    recentBotRate /= count;

    const mag = Math.abs(recentBotRate - historicalBotRate);
    const dir = recentBotRate > historicalBotRate ? "improving" : "degrading";
    this._capabilityHistory.push({ ts: Date.now(), botRate: recentBotRate });

    return {
      shift: mag > 0.15,
      magnitude: mag,
      direction: dir,
      details: mag > 0.15
        ? `⚠️ Significant bot capability ${dir}: ${(mag * 100).toFixed(1)}% change detected`
        : `Bot capability ${dir} by ${(mag * 100).toFixed(1)}% (within normal range)`,
    };
  }

  /**
   * Generate proactive insights and recommendations.
   * @returns {Array<{type:string, severity:string, message:string}>}
   */
  getProactiveInsights() {
    const insights = [];
    const fleet = this.getFleetStatus();

    if (fleet.active === 0) {
      insights.push({ type: "coverage", severity: "critical", message: "No active canaries deployed — bot capability changes will go undetected. Deploy canaries immediately." });
    }
    if (fleet.compromised > fleet.total * 0.3) {
      insights.push({ type: "breach", severity: "high", message: `${fleet.compromised} of ${fleet.total} canaries compromised — bots are rapidly adapting. Escalate difficulty parameters across the fleet.` });
    }
    if (fleet.avgDetectionGap < 0.2 && fleet.active > 0) {
      insights.push({ type: "gap", severity: "high", message: `Average detection gap is only ${(fleet.avgDetectionGap * 100).toFixed(1)}% — canaries are losing effectiveness. Consider deploying novel challenge types.` });
    }
    const rising = fleet.canaries.filter(c => c.trend === "rising" && c.status === "active");
    if (rising.length > 0) {
      insights.push({ type: "trend", severity: "medium", message: `${rising.length} canary(s) show rising bot success rates — capability evolution in progress.` });
    }
    if (fleet.active > 0 && fleet.active < 3) {
      insights.push({ type: "diversity", severity: "medium", message: "Fleet has fewer than 3 active canaries — deploy more for better coverage across difficulty dimensions." });
    }
    const shift = this.detectCapabilityShift();
    if (shift.shift) {
      insights.push({ type: "shift", severity: "critical", message: shift.details });
    }
    if (insights.length === 0) {
      insights.push({ type: "ok", severity: "info", message: "Fleet is healthy — all canaries maintaining good detection gaps with stable bot success rates." });
    }
    return insights;
  }
}

function _clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

module.exports = { CanaryDeployer };
