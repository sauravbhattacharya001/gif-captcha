/**
 * captcha-accessibility-analyzer.js
 *
 * Evaluates CAPTCHA configurations against accessibility standards (WCAG 2.1,
 * ADA, EN 301 549).  Checks alternative challenges, cognitive load, time
 * limits, keyboard navigability, color contrast, screen reader compatibility,
 * and motor-skill demands.  Produces a scored report with per-criterion
 * pass/fail verdicts and actionable remediation suggestions.
 *
 * Usage:
 *   var analyzer = createAccessibilityAnalyzer({ standard: 'WCAG_AA' });
 *   analyzer.registerChallenge({ id: 'main', type: 'image', ... });
 *   var report = analyzer.analyze();
 *   console.log(report.score, report.grade, report.findings);
 *
 * IIFE pattern — works in Node.js (CommonJS) and browser globals.
 */
;(function () {
  "use strict";

  var STANDARDS = {
    WCAG_A:   { level: "A",   timeLimitMin: 20, requireAlt: false, contrastMin: 3.0 },
    WCAG_AA:  { level: "AA",  timeLimitMin: 30, requireAlt: true,  contrastMin: 4.5 },
    WCAG_AA_LARGE: { level: "AA-large", timeLimitMin: 30, requireAlt: true, contrastMin: 3.0 },
    WCAG_AAA: { level: "AAA", timeLimitMin: 60, requireAlt: true,  contrastMin: 7.0 },
    ADA:      { level: "ADA", timeLimitMin: 30, requireAlt: true,  contrastMin: 4.5 },
    EN301549: { level: "EN",  timeLimitMin: 30, requireAlt: true,  contrastMin: 4.5 }
  };

  var SEVERITY = { critical: 4, major: 3, moderate: 2, minor: 1, info: 0 };

  var CRITERION_WEIGHTS = {
    alternatives: 15, cognitiveLoad: 15, timeLimit: 12, keyboardNav: 12,
    colorContrast: 10, screenReader: 12, motorSkill: 10, instructions: 7, errorRecovery: 7
  };

  function _clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
  function _grade(s) { if (s >= 90) return "A"; if (s >= 80) return "B"; if (s >= 65) return "C"; if (s >= 50) return "D"; return "F"; }
  function _now() { return new Date().toISOString(); }
  function _uid() { var h = 0, s = _now() + Math.random().toString(36); for (var i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0; } return "f-" + Math.abs(h).toString(36); }

  function _parseHex(hex) {
    if (typeof hex !== "string") return null;
    hex = hex.replace(/^#/, "");
    if (hex.length === 3) hex = hex[0]+hex[0]+hex[1]+hex[1]+hex[2]+hex[2];
    if (hex.length !== 6) return null;
    var n = parseInt(hex, 16); if (isNaN(n)) return null;
    return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
  }

  function _luminance(rgb) {
    function ch(c) { c = c / 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }
    return 0.2126 * ch(rgb.r) + 0.7152 * ch(rgb.g) + 0.0722 * ch(rgb.b);
  }

  function _contrastRatio(hex1, hex2) {
    var c1 = _parseHex(hex1), c2 = _parseHex(hex2);
    if (!c1 || !c2) return 1;
    var l1 = _luminance(c1), l2 = _luminance(c2);
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
  }

  function _cognitiveLoadScore(c) {
    var s = 0, type = (c.type || "").toLowerCase();
    var tl = { checkbox: 10, text: 20, math: 40, audio: 30, image: 35, gif: 45, puzzle: 55, drag: 50, click: 25, slider: 20, custom: 35 };
    s += tl[type] || 30;
    if (c.complexity) s += _clamp(c.complexity, 0, 10) * 3;
    if (c.timeLimitSeconds && c.timeLimitSeconds < 30) s += 15;
    if (c.steps && c.steps > 1) s += (c.steps - 1) * 8;
    if (c.requiresReading) s += 10;
    if (c.requiresCulturalKnowledge) s += 15;
    return _clamp(s, 0, 100);
  }

  function _keyboardScore(c) {
    var s = 100, type = (c.type || "").toLowerCase();
    if (type === "drag" || type === "slider") s -= 40;
    if (type === "click" && !c.keyboardAlternative) s -= 30;
    if (type === "puzzle") s -= 25;
    if (type === "gif" && !c.keyboardAlternative) s -= 20;
    if (c.keyboardNavigable === false) s -= 30;
    if (c.focusVisible === false) s -= 15;
    if (c.tabOrder === false) s -= 15;
    return _clamp(s, 0, 100);
  }

  function _motorScore(c) {
    var s = 0, type = (c.type || "").toLowerCase();
    if (type === "drag") s += 45; if (type === "slider") s += 30;
    if (type === "click") s += 15; if (type === "puzzle") s += 35;
    if (c.precision === "high") s += 20; else if (c.precision === "medium") s += 10;
    if (c.targetSize && c.targetSize < 44) s += 15;
    if (c.requiresDoubleTap) s += 10; if (c.requiresLongPress) s += 15;
    return _clamp(s, 0, 100);
  }

  function _screenReaderScore(c) {
    var s = 100;
    if (!c.ariaLabel && !c.ariaDescribedBy) s -= 25;
    if (!c.altText && (c.type === "image" || c.type === "gif")) s -= 20;
    if (c.usesCanvas && !c.canvasFallback) s -= 20;
    if (!c.roleAttribute) s -= 10;
    if (!c.liveRegion) s -= 10;
    if (c.visualOnly) s -= 30;
    return _clamp(s, 0, 100);
  }

  function createAccessibilityAnalyzer(options) {
    options = options || {};
    var standardKey = (options.standard || "WCAG_AA").toUpperCase();
    var standard = STANDARDS[standardKey] || STANDARDS.WCAG_AA;
    var challenges = Object.create(null);
    var config = { standard: standardKey, customRules: options.customRules || [], scoringMode: options.scoringMode || "weighted" };
    var history = [];

    function registerChallenge(def) {
      if (!def || !def.id) throw new Error("Challenge definition must include an 'id' property.");
      var id = String(def.id);
      challenges[id] = {
        id: id, type: (def.type || "custom").toLowerCase(),
        timeLimitSeconds: def.timeLimitSeconds || null,
        hasAudioAlternative: !!def.hasAudioAlternative, hasTextAlternative: !!def.hasTextAlternative,
        complexity: def.complexity || 0, steps: def.steps || 1,
        requiresReading: !!def.requiresReading, requiresCulturalKnowledge: !!def.requiresCulturalKnowledge,
        keyboardNavigable: def.keyboardNavigable !== false, keyboardAlternative: !!def.keyboardAlternative,
        focusVisible: def.focusVisible !== false, tabOrder: def.tabOrder !== false,
        ariaLabel: def.ariaLabel || null, ariaDescribedBy: def.ariaDescribedBy || null,
        altText: def.altText || null, roleAttribute: def.roleAttribute || null,
        liveRegion: !!def.liveRegion, usesCanvas: !!def.usesCanvas, canvasFallback: !!def.canvasFallback,
        visualOnly: !!def.visualOnly, precision: def.precision || "low",
        targetSize: def.targetSize || 44, requiresDoubleTap: !!def.requiresDoubleTap,
        requiresLongPress: !!def.requiresLongPress,
        foregroundColor: def.foregroundColor || null, backgroundColor: def.backgroundColor || null,
        instructions: def.instructions || null, errorMessage: def.errorMessage || null,
        retryAllowed: def.retryAllowed !== false, refreshAvailable: def.refreshAvailable !== false,
        skipOption: !!def.skipOption
      };
      return challenges[id];
    }

    function removeChallenge(id) { if (!challenges[id]) return false; delete challenges[id]; return true; }
    function getChallenge(id) { return challenges[id] || null; }
    function listChallenges() { var r = [], ids = Object.keys(challenges); for (var i = 0; i < ids.length; i++) r.push(challenges[ids[i]]); return r; }

    function _makeFinding(criterion, severity, challengeId, message, wcag, remediation) {
      return { id: _uid(), criterion: criterion, severity: severity, challenge: challengeId, message: message, wcag: wcag, remediation: remediation };
    }

    function _checkAlternatives(list) {
      var findings = [], hasAudio = false, hasText = false;
      for (var i = 0; i < list.length; i++) {
        if (list[i].hasAudioAlternative) hasAudio = true;
        if (list[i].hasTextAlternative) hasText = true;
        if (list[i].visualOnly && !list[i].hasAudioAlternative && !list[i].hasTextAlternative)
          findings.push(_makeFinding("alternatives", "critical", list[i].id, "Visual-only challenge '" + list[i].id + "' has no alternative for blind/low-vision users.", "1.1.1", "Provide an audio or text-based alternative."));
      }
      if (standard.requireAlt && !hasAudio && !hasText && list.length > 0)
        findings.push(_makeFinding("alternatives", "critical", null, "No alternative challenge types (audio/text) available. " + standardKey + " requires at least one.", "1.1.1", "Add an audio or text-based CAPTCHA option."));
      var score = 100;
      if (!hasAudio && !hasText && list.length > 0) score -= 50;
      if (!hasAudio && list.length > 0) score -= 15;
      if (!hasText && list.length > 0) score -= 15;
      var vo = 0; for (var j = 0; j < list.length; j++) { if (list[j].visualOnly) vo++; }
      if (list.length > 0 && vo === list.length) score -= 20;
      return { score: _clamp(score, 0, 100), findings: findings };
    }

    function _checkCognitiveLoad(list) {
      var findings = [], total = 0;
      for (var i = 0; i < list.length; i++) {
        var load = _cognitiveLoadScore(list[i]); total += load;
        if (load > 70) findings.push(_makeFinding("cognitiveLoad", "major", list[i].id, "Challenge '" + list[i].id + "' has high cognitive load (" + load + "/100).", "3.3.7", "Simplify or offer easier alternative."));
        else if (load > 50) findings.push(_makeFinding("cognitiveLoad", "moderate", list[i].id, "Challenge '" + list[i].id + "' has moderate cognitive load (" + load + "/100).", "3.3.7", "Consider reducing complexity."));
        if (list[i].requiresCulturalKnowledge) findings.push(_makeFinding("cognitiveLoad", "moderate", list[i].id, "Challenge '" + list[i].id + "' requires cultural knowledge.", "3.1.1", "Use universally recognizable imagery."));
      }
      return { score: _clamp(100 - (list.length > 0 ? total / list.length : 0), 0, 100), findings: findings };
    }

    function _checkTimeLimit(list) {
      var findings = [], minT = standard.timeLimitMin, tight = 0;
      for (var i = 0; i < list.length; i++) {
        if (!list[i].timeLimitSeconds) continue;
        if (list[i].timeLimitSeconds < minT) { tight++; findings.push(_makeFinding("timeLimit", "major", list[i].id, "Time limit (" + list[i].timeLimitSeconds + "s) below " + standardKey + " minimum (" + minT + "s).", "2.2.1", "Increase to at least " + minT + "s.")); }
        else if (list[i].timeLimitSeconds < minT * 2) findings.push(_makeFinding("timeLimit", "minor", list[i].id, "Time limit (" + list[i].timeLimitSeconds + "s) may be tight for some users.", "2.2.1", "Consider time extension option."));
      }
      return { score: list.length > 0 ? _clamp(100 - (tight / list.length) * 60, 0, 100) : 100, findings: findings };
    }

    function _checkKeyboard(list) {
      var findings = [], total = 0;
      for (var i = 0; i < list.length; i++) {
        var ks = _keyboardScore(list[i]); total += ks;
        if (ks < 50) findings.push(_makeFinding("keyboardNav", "critical", list[i].id, "Challenge '" + list[i].id + "' is poorly keyboard-accessible (score: " + ks + "/100).", "2.1.1", "Add keyboard navigation or alternative."));
        else if (ks < 80) findings.push(_makeFinding("keyboardNav", "moderate", list[i].id, "Challenge '" + list[i].id + "' has limited keyboard support (score: " + ks + "/100).", "2.1.1", "Ensure focus indicators and tab order."));
        if (list[i].focusVisible === false) findings.push(_makeFinding("keyboardNav", "major", list[i].id, "No visible focus indicator on '" + list[i].id + "'.", "2.4.7", "Add visible focus ring."));
      }
      return { score: _clamp(list.length > 0 ? total / list.length : 100, 0, 100), findings: findings };
    }

    function _checkColorContrast(list) {
      var findings = [], fails = 0, checked = 0;
      for (var i = 0; i < list.length; i++) {
        if (!list[i].foregroundColor || !list[i].backgroundColor) continue; checked++;
        var ratio = _contrastRatio(list[i].foregroundColor, list[i].backgroundColor);
        if (ratio < standard.contrastMin) { fails++; findings.push(_makeFinding("colorContrast", ratio < 3.0 ? "critical" : "major", list[i].id, "Contrast ratio " + ratio.toFixed(2) + ":1 below " + standardKey + " minimum (" + standard.contrastMin + ":1).", "1.4.3", "Adjust colors to " + standard.contrastMin + ":1.")); }
      }
      return { score: checked > 0 ? _clamp(100 - (fails / checked) * 80, 0, 100) : 100, findings: findings };
    }

    function _checkScreenReader(list) {
      var findings = [], total = 0;
      for (var i = 0; i < list.length; i++) {
        var srs = _screenReaderScore(list[i]); total += srs;
        if (srs < 50) findings.push(_makeFinding("screenReader", "critical", list[i].id, "Challenge '" + list[i].id + "' poorly compatible with screen readers (score: " + srs + "/100).", "4.1.2", "Add ARIA labels, roles, live regions."));
        if (!list[i].ariaLabel && !list[i].ariaDescribedBy) findings.push(_makeFinding("screenReader", "major", list[i].id, "Challenge '" + list[i].id + "' has no ARIA label or describedby.", "4.1.2", "Add aria-label or aria-describedby."));
      }
      return { score: _clamp(list.length > 0 ? total / list.length : 100, 0, 100), findings: findings };
    }

    function _checkMotorSkill(list) {
      var findings = [], total = 0;
      for (var i = 0; i < list.length; i++) {
        var ms = _motorScore(list[i]); total += ms;
        if (ms > 60) findings.push(_makeFinding("motorSkill", "major", list[i].id, "Challenge '" + list[i].id + "' has high motor demands (" + ms + "/100).", "2.5.1", "Provide low-dexterity alternative."));
        if (list[i].targetSize && list[i].targetSize < 44) findings.push(_makeFinding("motorSkill", "moderate", list[i].id, "Target size (" + list[i].targetSize + "px) below 44px minimum.", "2.5.5", "Increase to 44x44 CSS pixels."));
      }
      return { score: _clamp(100 - (list.length > 0 ? total / list.length : 0), 0, 100), findings: findings };
    }

    function _checkInstructions(list) {
      var findings = [], missing = 0;
      for (var i = 0; i < list.length; i++) {
        if (!list[i].instructions) { missing++; findings.push(_makeFinding("instructions", "moderate", list[i].id, "Challenge '" + list[i].id + "' has no instructions.", "3.3.2", "Provide clear instructions.")); }
      }
      return { score: list.length > 0 ? _clamp(100 - (missing / list.length) * 60, 0, 100) : 100, findings: findings };
    }

    function _checkErrorRecovery(list) {
      var findings = [], issues = 0;
      for (var i = 0; i < list.length; i++) {
        if (!list[i].errorMessage) { issues++; findings.push(_makeFinding("errorRecovery", "moderate", list[i].id, "No error message for '" + list[i].id + "'.", "3.3.1", "Add descriptive error message.")); }
        if (!list[i].retryAllowed) { issues++; findings.push(_makeFinding("errorRecovery", "major", list[i].id, "Challenge '" + list[i].id + "' does not allow retries.", "3.3.1", "Allow retry after failure.")); }
        if (!list[i].refreshAvailable) findings.push(_makeFinding("errorRecovery", "minor", list[i].id, "No refresh option for '" + list[i].id + "'.", "3.3.1", "Add 'Get new challenge' button."));
      }
      return { score: list.length > 0 ? _clamp(100 - (issues / (list.length * 2)) * 60, 0, 100) : 100, findings: findings };
    }

    function analyze() {
      var cl = listChallenges();
      var checks = {
        alternatives: _checkAlternatives(cl), cognitiveLoad: _checkCognitiveLoad(cl),
        timeLimit: _checkTimeLimit(cl), keyboardNav: _checkKeyboard(cl),
        colorContrast: _checkColorContrast(cl), screenReader: _checkScreenReader(cl),
        motorSkill: _checkMotorSkill(cl), instructions: _checkInstructions(cl),
        errorRecovery: _checkErrorRecovery(cl)
      };
      var allFindings = [];
      for (var r = 0; r < config.customRules.length; r++) {
        if (typeof config.customRules[r] === "function") {
          var rf = config.customRules[r](cl);
          if (rf) for (var k = 0; k < rf.length; k++) allFindings.push(rf[k]);
        }
      }
      var keys = Object.keys(checks);
      for (var ci = 0; ci < keys.length; ci++) {
        var fs = checks[keys[ci]].findings;
        for (var fi = 0; fi < fs.length; fi++) allFindings.push(fs[fi]);
      }
      var totalScore;
      if (config.scoringMode === "equal") {
        var sum = 0; for (var si = 0; si < keys.length; si++) sum += checks[keys[si]].score;
        totalScore = keys.length > 0 ? sum / keys.length : 100;
      } else {
        var ws = 0, tw = 0;
        for (var wi = 0; wi < keys.length; wi++) { var w = CRITERION_WEIGHTS[keys[wi]] || 10; ws += checks[keys[wi]].score * w; tw += w; }
        totalScore = tw > 0 ? ws / tw : 100;
      }
      totalScore = Math.round(_clamp(totalScore, 0, 100) * 10) / 10;
      var sev = { critical: 0, major: 0, moderate: 0, minor: 0, info: 0 };
      for (var sci = 0; sci < allFindings.length; sci++) sev[allFindings[sci].severity || "info"]++;
      var summary = ["Accessibility score: " + totalScore + "/100 (Grade " + _grade(totalScore) + ")", "Standard: " + standardKey, "Challenges: " + cl.length];
      if (sev.critical > 0) summary.push("CRITICAL: " + sev.critical);
      if (sev.major > 0) summary.push("Major: " + sev.major);
      if (sev.moderate > 0) summary.push("Moderate: " + sev.moderate);
      summary.push(sev.critical === 0 && sev.major === 0 ? "Result: PASS" : "Result: FAIL");
      var report = {
        timestamp: _now(), standard: standardKey, standardLevel: standard.level,
        challengeCount: cl.length, score: totalScore, grade: _grade(totalScore),
        passed: sev.critical === 0 && sev.major === 0,
        criterionScores: Object.create(null), findings: allFindings,
        severityCounts: sev, summary: summary.join("\n")
      };
      for (var csi = 0; csi < keys.length; csi++) report.criterionScores[keys[csi]] = checks[keys[csi]].score;
      history.push(report); if (history.length > 100) history.shift();
      return report;
    }

    function quickAudit(def) {
      var tid = def.id || "_qa_" + Date.now(); def.id = tid;
      registerChallenge(def); var r = analyze(); removeChallenge(tid); return r;
    }

    function compareReports(a, b) {
      if (!a || !b) return null;
      var delta = Object.create(null), keys = Object.keys(a.criterionScores || {});
      for (var i = 0; i < keys.length; i++) delta[keys[i]] = (b.criterionScores[keys[i]] || 0) - (a.criterionScores[keys[i]] || 0);
      return { scoreDelta: b.score - a.score, gradeBefore: a.grade, gradeAfter: b.grade, criterionDeltas: delta, findingsDelta: b.findings.length - a.findings.length, improved: b.score > a.score };
    }

    function exportJSON() {
      return JSON.stringify({ config: config, challenges: listChallenges(), lastReport: history.length > 0 ? history[history.length - 1] : null }, null, 2);
    }

    function getConfig() {
      return { standard: config.standard, scoringMode: config.scoringMode, customRulesCount: config.customRules.length, criterionWeights: JSON.parse(JSON.stringify(CRITERION_WEIGHTS)) };
    }

    return {
      registerChallenge: registerChallenge, removeChallenge: removeChallenge,
      getChallenge: getChallenge, listChallenges: listChallenges,
      analyze: analyze, quickAudit: quickAudit,
      compareReports: compareReports, getHistory: function () { return history.slice(); },
      exportJSON: exportJSON, getConfig: getConfig,
      utils: { contrastRatio: _contrastRatio, cognitiveLoadScore: _cognitiveLoadScore, keyboardScore: _keyboardScore, motorScore: _motorScore, screenReaderScore: _screenReaderScore, parseHex: _parseHex, luminance: _luminance }
    };
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { createAccessibilityAnalyzer: createAccessibilityAnalyzer };
  } else if (typeof window !== "undefined") {
    window.createAccessibilityAnalyzer = createAccessibilityAnalyzer;
  }
})();
