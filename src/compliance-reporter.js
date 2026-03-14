"use strict";


// ── Compliance Report Generator ───────────────────────────────────────

/**
 * Creates a compliance report generator that evaluates CAPTCHA system
 * configuration and runtime metrics against accessibility, security,
 * privacy, and operational standards.
 *
 * Checks against:
 * - WCAG 2.1 AA accessibility guidelines
 * - GDPR / privacy data-retention requirements
 * - OWASP bot-mitigation best practices
 * - Operational health thresholds
 *
 * @param {Object} [options] - Generator configuration
 * @param {string} [options.systemName="gif-captcha"] - System identifier for reports
 * @param {number} [options.maxDataRetentionDays=30] - GDPR data retention limit in days
 * @param {number} [options.minSolveRatePercent=70] - Minimum acceptable human solve rate
 * @param {number} [options.maxSolveTimeMs=60000] - Maximum acceptable solve time
 * @param {number} [options.maxFailRatePercent=50] - Maximum acceptable failure rate
 * @param {number} [options.minBotBlockRatePercent=90] - Minimum bot detection rate
 * @returns {Object} Compliance report generator instance
 */
/**
 * Count severity occurrences across an array of findings.
 * @param {Object[]} findings - Array of finding objects with .severity
 * @param {Object} SEV - Severity constants (PASS, CRITICAL, WARNING, INFO)
 * @returns {{ passed: number, criticals: number, warnings: number, infos: number }}
 */
function _countSeverities(findings, SEV) {
  var passed = 0, criticals = 0, warnings = 0, infos = 0;
  for (var i = 0; i < findings.length; i++) {
    var s = findings[i].severity;
    if (s === SEV.PASS) passed++;
    else if (s === SEV.CRITICAL) criticals++;
    else if (s === SEV.WARNING) warnings++;
    else if (s === SEV.INFO) infos++;
  }
  return { passed: passed, criticals: criticals, warnings: warnings, infos: infos };
}

/**
 * Compute per-category compliance scores from findings.
 * @param {Object[]} findings - Array of finding objects with .category and .severity
 * @param {Object} SEV - Severity constants
 * @returns {Object} Map of category -> { score, total, passed, criticals, warnings }
 */
function _computeAllCategoryScores(findings, SEV) {
  var buckets = Object.create(null);
  for (var i = 0; i < findings.length; i++) {
    var cat = findings[i].category;
    if (!buckets[cat]) buckets[cat] = [];
    buckets[cat].push(findings[i]);
  }
  var scores = Object.create(null);
  var cats = Object.keys(buckets);
  for (var c = 0; c < cats.length; c++) {
    var catName = cats[c];
    var items = buckets[catName];
    var counts = _countSeverities(items, SEV);
    var scorable = items.length - counts.infos;
    var score = scorable > 0 ? Math.round((counts.passed / scorable) * 100) : 100;
    scores[catName] = {
      score: score,
      total: items.length,
      passed: counts.passed,
      criticals: counts.criticals,
      warnings: counts.warnings
    };
  }
  return scores;
}

/**
 * Compute a weighted average score from category scores and weight map.
 * @param {Object} categoryScores - Map of category -> { score }
 * @param {Object} weights - Map of category -> weight (number)
 * @returns {number} Weighted average (0-100), rounded
 */
function _weightedAverage(categoryScores, weights) {
  var total = 0, weightSum = 0;
  var cats = Object.keys(weights);
  for (var i = 0; i < cats.length; i++) {
    var cat = cats[i];
    if (categoryScores[cat]) {
      total += categoryScores[cat].score * weights[cat];
      weightSum += weights[cat];
    }
  }
  return weightSum > 0 ? Math.round(total / weightSum) : 0;
}

function createComplianceReporter(options) {
  options = options || {};
  var systemName = options.systemName || "gif-captcha";
  var maxRetentionDays = options.maxDataRetentionDays > 0 ? options.maxDataRetentionDays : 30;
  var minSolveRate = typeof options.minSolveRatePercent === "number" ? options.minSolveRatePercent : 70;
  var maxSolveTimeMs = options.maxSolveTimeMs > 0 ? options.maxSolveTimeMs : 60000;
  var maxFailRate = typeof options.maxFailRatePercent === "number" ? options.maxFailRatePercent : 50;
  var minBotBlockRate = typeof options.minBotBlockRatePercent === "number" ? options.minBotBlockRatePercent : 90;

  var SEVERITY = { CRITICAL: "critical", WARNING: "warning", INFO: "info", PASS: "pass" };
  var CATEGORY = {
    ACCESSIBILITY: "accessibility",
    PRIVACY: "privacy",
    SECURITY: "security",
    OPERATIONAL: "operational"
  };

  /**
   * Run all compliance checks against provided configuration and metrics.
   *
   * @param {Object} config - CAPTCHA system configuration
   * @param {boolean} [config.audioAlternative] - Whether audio CAPTCHA is available
   * @param {boolean} [config.keyboardNavigable] - Whether CAPTCHA is keyboard-navigable
   * @param {string} [config.ariaLabel] - ARIA label for the CAPTCHA element
   * @param {number} [config.colorContrast] - Color contrast ratio (e.g. 4.5)
   * @param {number} [config.timeLimitMs] - Time limit given to solve
   * @param {boolean} [config.canExtendTime] - Whether user can extend time
   * @param {string[]} [config.supportedLanguages] - List of supported locale codes
   * @param {number} [config.dataRetentionDays] - How long data is retained
   * @param {boolean} [config.consentRequired] - Whether consent is collected
   * @param {boolean} [config.anonymization] - Whether data is anonymised
   * @param {boolean} [config.deletionSupported] - Whether right-to-delete is supported
   * @param {boolean} [config.rateLimitEnabled] - Whether rate limiting is active
   * @param {boolean} [config.tokenSigned] - Whether tokens use HMAC signing
   * @param {boolean} [config.httpsOnly] - Whether HTTPS is enforced
   * @param {boolean} [config.inputSanitized] - Whether input is sanitised
   * @param {number} [config.maxAttempts] - Max attempts before lockout
   * @param {boolean} [config.replayProtection] - Whether replay attacks are prevented
   * @param {Object} [metrics] - Runtime metrics snapshot
   * @param {number} [metrics.totalChallenges] - Total challenges served
   * @param {number} [metrics.totalSolves] - Successful solves
   * @param {number} [metrics.totalFailures] - Failed attempts
   * @param {number} [metrics.avgSolveTimeMs] - Average solve time in ms
   * @param {number} [metrics.p95SolveTimeMs] - P95 solve time in ms
   * @param {number} [metrics.botAttempts] - Detected bot attempts
   * @param {number} [metrics.botBlocked] - Blocked bot attempts
   * @param {number} [metrics.uptimePercent] - System uptime percentage
   * @param {number} [metrics.avgResponseTimeMs] - Average server response time
   * @param {number} [metrics.errorCount] - Server error count
   * @returns {Object} Compliance report
   */
  function generateReport(config, metrics) {
    config = config || {};
    metrics = metrics || {};
    var findings = [];
    var now = new Date();

    // ── Accessibility Checks (WCAG 2.1 AA) ─────────────────────────

    findings.push({
      id: "ACC-001",
      category: CATEGORY.ACCESSIBILITY,
      title: "Audio alternative available",
      description: "WCAG 1.1.1: Non-text content must have a text or audio alternative",
      severity: config.audioAlternative ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.audioAlternative ? null : "Enable audio CAPTCHA alternative for visually impaired users"
    });

    findings.push({
      id: "ACC-002",
      category: CATEGORY.ACCESSIBILITY,
      title: "Keyboard navigation support",
      description: "WCAG 2.1.1: All functionality must be operable through a keyboard",
      severity: config.keyboardNavigable ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.keyboardNavigable ? null : "Ensure CAPTCHA can be completed using keyboard only"
    });

    findings.push({
      id: "ACC-003",
      category: CATEGORY.ACCESSIBILITY,
      title: "ARIA labelling",
      description: "WCAG 4.1.2: UI components must have accessible names and roles",
      severity: config.ariaLabel ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.ariaLabel ? null : "Add aria-label or aria-labelledby to the CAPTCHA container"
    });

    var contrast = typeof config.colorContrast === "number" ? config.colorContrast : 0;
    findings.push({
      id: "ACC-004",
      category: CATEGORY.ACCESSIBILITY,
      title: "Color contrast ratio",
      description: "WCAG 1.4.3: Text must have a contrast ratio of at least 4.5:1",
      severity: contrast >= 4.5 ? SEVERITY.PASS : contrast >= 3 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: contrast >= 4.5 ? null : "Increase color contrast to at least 4.5:1 (current: " + contrast.toFixed(1) + ":1)"
    });

    var hasTimeLimit = typeof config.timeLimitMs === "number" && config.timeLimitMs > 0;
    findings.push({
      id: "ACC-005",
      category: CATEGORY.ACCESSIBILITY,
      title: "Time limit accommodation",
      description: "WCAG 2.2.1: Users must be able to turn off, adjust, or extend time limits",
      severity: !hasTimeLimit || config.canExtendTime ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: hasTimeLimit && !config.canExtendTime ? "Allow users to request additional time to complete the CAPTCHA" : null
    });

    var langCount = Array.isArray(config.supportedLanguages) ? config.supportedLanguages.length : 0;
    findings.push({
      id: "ACC-006",
      category: CATEGORY.ACCESSIBILITY,
      title: "Multilingual support",
      description: "WCAG 3.1.1: Default language must be programmatically determinable",
      severity: langCount >= 3 ? SEVERITY.PASS : langCount >= 1 ? SEVERITY.INFO : SEVERITY.WARNING,
      recommendation: langCount < 3 ? "Support at least 3 languages for broader accessibility (" + langCount + " currently configured)" : null
    });

    // ── Privacy Checks (GDPR) ───────────────────────────────────────

    var retDays = typeof config.dataRetentionDays === "number" ? config.dataRetentionDays : -1;
    findings.push({
      id: "PRV-001",
      category: CATEGORY.PRIVACY,
      title: "Data retention policy",
      description: "GDPR Art. 5(1)(e): Data must not be kept longer than necessary",
      severity: retDays >= 0 && retDays <= maxRetentionDays ? SEVERITY.PASS : retDays < 0 ? SEVERITY.CRITICAL : SEVERITY.WARNING,
      recommendation: retDays < 0 ? "Define a data retention period (max " + maxRetentionDays + " days recommended)"
        : retDays > maxRetentionDays ? "Reduce retention from " + retDays + " to " + maxRetentionDays + " days or less" : null
    });

    findings.push({
      id: "PRV-002",
      category: CATEGORY.PRIVACY,
      title: "User consent collection",
      description: "GDPR Art. 6: Processing requires a lawful basis (consent for CAPTCHAs)",
      severity: config.consentRequired ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.consentRequired ? null : "Collect explicit consent before processing CAPTCHA interaction data"
    });

    findings.push({
      id: "PRV-003",
      category: CATEGORY.PRIVACY,
      title: "Data anonymisation",
      description: "GDPR Art. 25: Data protection by design and default",
      severity: config.anonymization ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.anonymization ? null : "Anonymise or pseudonymise stored CAPTCHA interaction data"
    });

    findings.push({
      id: "PRV-004",
      category: CATEGORY.PRIVACY,
      title: "Right to deletion",
      description: "GDPR Art. 17: Users have the right to erasure of personal data",
      severity: config.deletionSupported ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.deletionSupported ? null : "Implement data deletion endpoint for GDPR Art. 17 compliance"
    });

    // ── Security Checks (OWASP) ─────────────────────────────────────

    findings.push({
      id: "SEC-001",
      category: CATEGORY.SECURITY,
      title: "Rate limiting enabled",
      description: "OWASP: Implement rate limiting to prevent automated attacks",
      severity: config.rateLimitEnabled ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.rateLimitEnabled ? null : "Enable request rate limiting to prevent brute-force attacks"
    });

    findings.push({
      id: "SEC-002",
      category: CATEGORY.SECURITY,
      title: "Token signing (HMAC)",
      description: "OWASP: Validate CAPTCHA tokens server-side with cryptographic signatures",
      severity: config.tokenSigned ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.tokenSigned ? null : "Use HMAC-signed tokens for stateless CAPTCHA validation"
    });

    findings.push({
      id: "SEC-003",
      category: CATEGORY.SECURITY,
      title: "HTTPS enforcement",
      description: "OWASP: Encrypt all CAPTCHA traffic to prevent interception",
      severity: config.httpsOnly ? SEVERITY.PASS : SEVERITY.CRITICAL,
      recommendation: config.httpsOnly ? null : "Enforce HTTPS for all CAPTCHA endpoints"
    });

    findings.push({
      id: "SEC-004",
      category: CATEGORY.SECURITY,
      title: "Input sanitisation",
      description: "OWASP: Sanitise all user input to prevent injection attacks",
      severity: config.inputSanitized ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.inputSanitized ? null : "Sanitise CAPTCHA answer input before processing"
    });

    var maxAttempts = typeof config.maxAttempts === "number" ? config.maxAttempts : 0;
    findings.push({
      id: "SEC-005",
      category: CATEGORY.SECURITY,
      title: "Attempt limiting / lockout",
      description: "OWASP: Lock out after repeated failures to prevent brute force",
      severity: maxAttempts > 0 && maxAttempts <= 10 ? SEVERITY.PASS : maxAttempts > 10 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: maxAttempts <= 0 ? "Configure a maximum attempt limit (recommended: 3-5)"
        : maxAttempts > 10 ? "Reduce max attempts from " + maxAttempts + " to 5 or fewer" : null
    });

    findings.push({
      id: "SEC-006",
      category: CATEGORY.SECURITY,
      title: "Replay protection",
      description: "Prevent reuse of solved CAPTCHA tokens",
      severity: config.replayProtection ? SEVERITY.PASS : SEVERITY.WARNING,
      recommendation: config.replayProtection ? null : "Implement one-time-use tokens to prevent replay attacks"
    });

    var botBlockRate = 0;
    if (metrics.botAttempts > 0) {
      botBlockRate = (metrics.botBlocked / metrics.botAttempts) * 100;
    }
    findings.push({
      id: "SEC-007",
      category: CATEGORY.SECURITY,
      title: "Bot detection effectiveness",
      description: "Bot block rate should be at least " + minBotBlockRate + "%",
      severity: metrics.botAttempts === 0 ? SEVERITY.INFO
        : botBlockRate >= minBotBlockRate ? SEVERITY.PASS
        : botBlockRate >= minBotBlockRate * 0.8 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: metrics.botAttempts > 0 && botBlockRate < minBotBlockRate
        ? "Bot block rate is " + botBlockRate.toFixed(1) + "% (target: " + minBotBlockRate + "%)" : null
    });

    // ── Operational Checks ──────────────────────────────────────────

    var solveRate = 0;
    if (metrics.totalChallenges > 0) {
      solveRate = (metrics.totalSolves / metrics.totalChallenges) * 100;
    }
    findings.push({
      id: "OPS-001",
      category: CATEGORY.OPERATIONAL,
      title: "Human solve rate",
      description: "Solve rate should be at least " + minSolveRate + "% to avoid user frustration",
      severity: metrics.totalChallenges === 0 ? SEVERITY.INFO
        : solveRate >= minSolveRate ? SEVERITY.PASS
        : solveRate >= minSolveRate * 0.8 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: metrics.totalChallenges > 0 && solveRate < minSolveRate
        ? "Solve rate is " + solveRate.toFixed(1) + "% (target: " + minSolveRate + "%). Consider reducing difficulty." : null
    });

    var failRate = 0;
    if (metrics.totalChallenges > 0) {
      failRate = (metrics.totalFailures / metrics.totalChallenges) * 100;
    }
    findings.push({
      id: "OPS-002",
      category: CATEGORY.OPERATIONAL,
      title: "Failure rate within threshold",
      description: "Failure rate should be below " + maxFailRate + "%",
      severity: metrics.totalChallenges === 0 ? SEVERITY.INFO
        : failRate <= maxFailRate ? SEVERITY.PASS
        : failRate <= maxFailRate * 1.2 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: metrics.totalChallenges > 0 && failRate > maxFailRate
        ? "Failure rate is " + failRate.toFixed(1) + "% (threshold: " + maxFailRate + "%)" : null
    });

    var avgTime = typeof metrics.avgSolveTimeMs === "number" ? metrics.avgSolveTimeMs : 0;
    findings.push({
      id: "OPS-003",
      category: CATEGORY.OPERATIONAL,
      title: "Average solve time acceptable",
      description: "Solve time should be under " + (maxSolveTimeMs / 1000) + "s",
      severity: avgTime <= 0 ? SEVERITY.INFO
        : avgTime <= maxSolveTimeMs ? SEVERITY.PASS
        : avgTime <= maxSolveTimeMs * 1.5 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: avgTime > maxSolveTimeMs
        ? "Average solve time is " + (avgTime / 1000).toFixed(1) + "s (target: " + (maxSolveTimeMs / 1000) + "s)" : null
    });

    var p95Time = typeof metrics.p95SolveTimeMs === "number" ? metrics.p95SolveTimeMs : 0;
    findings.push({
      id: "OPS-004",
      category: CATEGORY.OPERATIONAL,
      title: "P95 solve time acceptable",
      description: "95th percentile solve time should be under " + (maxSolveTimeMs * 2 / 1000) + "s",
      severity: p95Time <= 0 ? SEVERITY.INFO
        : p95Time <= maxSolveTimeMs * 2 ? SEVERITY.PASS
        : p95Time <= maxSolveTimeMs * 3 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: p95Time > maxSolveTimeMs * 2
        ? "P95 solve time is " + (p95Time / 1000).toFixed(1) + "s — consider simplifying hard challenges" : null
    });

    var uptime = typeof metrics.uptimePercent === "number" ? metrics.uptimePercent : 100;
    findings.push({
      id: "OPS-005",
      category: CATEGORY.OPERATIONAL,
      title: "System availability",
      description: "Uptime should be at least 99.5%",
      severity: uptime >= 99.5 ? SEVERITY.PASS : uptime >= 99 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: uptime < 99.5 ? "Uptime is " + uptime.toFixed(2) + "% (target: 99.5%)" : null
    });

    var responseTime = typeof metrics.avgResponseTimeMs === "number" ? metrics.avgResponseTimeMs : 0;
    findings.push({
      id: "OPS-006",
      category: CATEGORY.OPERATIONAL,
      title: "Server response time",
      description: "Average response time should be under 500ms",
      severity: responseTime <= 0 ? SEVERITY.INFO
        : responseTime <= 500 ? SEVERITY.PASS
        : responseTime <= 1000 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: responseTime > 500 ? "Average response time is " + responseTime + "ms (target: <500ms)" : null
    });

    var errCount = typeof metrics.errorCount === "number" ? metrics.errorCount : 0;
    var errRate = metrics.totalChallenges > 0 ? (errCount / metrics.totalChallenges) * 100 : 0;
    findings.push({
      id: "OPS-007",
      category: CATEGORY.OPERATIONAL,
      title: "Error rate",
      description: "Server error rate should be below 1%",
      severity: metrics.totalChallenges === 0 ? SEVERITY.INFO
        : errRate <= 1 ? SEVERITY.PASS
        : errRate <= 5 ? SEVERITY.WARNING : SEVERITY.CRITICAL,
      recommendation: errRate > 1 ? "Error rate is " + errRate.toFixed(2) + "% (" + errCount + " errors)" : null
    });

    // ── Compute Scores ──────────────────────────────────────────────

    var categoryScores = _computeAllCategoryScores(findings, SEVERITY);

    // Overall score: weighted average (security 35%, privacy 25%, accessibility 25%, operational 15%)
    var weights = { security: 35, privacy: 25, accessibility: 25, operational: 15 };
    var overallScore = _weightedAverage(categoryScores, weights);
    var grade = overallScore >= 90 ? "A" : overallScore >= 80 ? "B" : overallScore >= 70 ? "C" : overallScore >= 60 ? "D" : "F";

    var counts = _countSeverities(findings, SEVERITY);
    var totalCriticals = counts.criticals;
    var totalWarnings = counts.warnings;
    var totalPassed = counts.passed;

    return {
      system: systemName,
      generatedAt: now.toISOString(),
      overallScore: overallScore,
      grade: grade,
      totalFindings: findings.length,
      passed: totalPassed,
      criticals: totalCriticals,
      warnings: totalWarnings,
      categoryScores: categoryScores,
      findings: findings
    };
  }

  /**
   * Generate a minimal configuration template that would achieve a passing score.
   * Useful for bootstrapping new CAPTCHA deployments.
   *
   * @returns {Object} Recommended configuration object
   */
  function getRecommendedConfig() {
    return {
      audioAlternative: true,
      keyboardNavigable: true,
      ariaLabel: "Security verification",
      colorContrast: 4.5,
      timeLimitMs: 120000,
      canExtendTime: true,
      supportedLanguages: ["en", "es", "fr"],
      dataRetentionDays: maxRetentionDays,
      consentRequired: true,
      anonymization: true,
      deletionSupported: true,
      rateLimitEnabled: true,
      tokenSigned: true,
      httpsOnly: true,
      inputSanitized: true,
      maxAttempts: 5,
      replayProtection: true
    };
  }

  /**
   * Compare two reports and return a diff summary showing improvements
   * and regressions between audits.
   *
   * @param {Object} oldReport - Previous compliance report
   * @param {Object} newReport - Current compliance report
   * @returns {Object} Diff summary with improved, regressed, and unchanged counts
   */
  function compareReports(oldReport, newReport) {
    if (!oldReport || !newReport || !oldReport.findings || !newReport.findings) {
      return { error: "invalid_reports", improved: 0, regressed: 0, unchanged: 0, details: [] };
    }
    var oldMap = Object.create(null);
    for (var oi = 0; oi < oldReport.findings.length; oi++) {
      oldMap[oldReport.findings[oi].id] = oldReport.findings[oi].severity;
    }

    var severityRank = Object.create(null);
    severityRank[SEVERITY.PASS] = 0;
    severityRank[SEVERITY.INFO] = 1;
    severityRank[SEVERITY.WARNING] = 2;
    severityRank[SEVERITY.CRITICAL] = 3;

    var improved = 0, regressed = 0, unchanged = 0;
    var details = [];
    for (var ni = 0; ni < newReport.findings.length; ni++) {
      var finding = newReport.findings[ni];
      var oldSev = oldMap[finding.id];
      if (oldSev === undefined) {
        details.push({ id: finding.id, change: "new", severity: finding.severity });
        continue;
      }
      var oldRank = severityRank[oldSev] !== undefined ? severityRank[oldSev] : 1;
      var newRank = severityRank[finding.severity] !== undefined ? severityRank[finding.severity] : 1;
      if (newRank < oldRank) {
        improved++;
        details.push({ id: finding.id, change: "improved", from: oldSev, to: finding.severity });
      } else if (newRank > oldRank) {
        regressed++;
        details.push({ id: finding.id, change: "regressed", from: oldSev, to: finding.severity });
      } else {
        unchanged++;
      }
    }

    return {
      oldScore: oldReport.overallScore,
      newScore: newReport.overallScore,
      scoreDelta: newReport.overallScore - oldReport.overallScore,
      improved: improved,
      regressed: regressed,
      unchanged: unchanged,
      details: details
    };
  }

  /**
   * Format a report as a plain-text summary suitable for terminal output or logging.
   *
   * @param {Object} report - Compliance report from generateReport()
   * @returns {string} Formatted text report
   */
  function formatReportText(report) {
    if (!report) return "";
    var lines = [];
    lines.push("=== CAPTCHA Compliance Report ===");
    lines.push("System: " + report.system);
    lines.push("Generated: " + report.generatedAt);
    lines.push("Overall Score: " + report.overallScore + "/100 (Grade: " + report.grade + ")");
    lines.push("");

    var cats = ["accessibility", "privacy", "security", "operational"];
    for (var ci = 0; ci < cats.length; ci++) {
      var cat = cats[ci];
      var cs = report.categoryScores[cat];
      if (!cs) continue;
      lines.push("  " + cat.charAt(0).toUpperCase() + cat.slice(1) + ": " + cs.score + "/100 (" + cs.passed + "/" + cs.total + " passed)");
    }
    lines.push("");

    var actionItems = [];
    for (var fi = 0; fi < report.findings.length; fi++) {
      var f = report.findings[fi];
      if (f.severity === SEVERITY.CRITICAL || f.severity === SEVERITY.WARNING) {
        actionItems.push(f);
      }
    }

    if (actionItems.length > 0) {
      lines.push("Action Items:");
      for (var ai = 0; ai < actionItems.length; ai++) {
        var item = actionItems[ai];
        var icon = item.severity === SEVERITY.CRITICAL ? "[CRITICAL]" : "[WARNING]";
        lines.push("  " + icon + " " + item.id + " " + item.title);
        if (item.recommendation) {
          lines.push("    -> " + item.recommendation);
        }
      }
    } else {
      lines.push("No action items - all checks passed!");
    }

    return lines.join("\n");
  }

  /**
   * Render a compliance report as a self-contained HTML page with inline
   * CSS styling, color-coded severity badges, category score bars, and
   * a summary dashboard. The output is a complete HTML document that can
   * be saved to a file and opened in any browser.
   *
   * @param {Object} report - Compliance report from generateReport()
   * @param {Object} [htmlOptions] - Rendering options
   * @param {string} [htmlOptions.title] - Custom page title
   * @param {boolean} [htmlOptions.darkMode=false] - Use dark colour scheme
   * @param {boolean} [htmlOptions.includeTimestamp=true] - Show generation timestamp
   * @returns {string} Complete HTML document string
   */
  function formatReportHtml(report, htmlOptions) {
    if (!report) return "";
    htmlOptions = htmlOptions || {};
    var title = htmlOptions.title || "CAPTCHA Compliance Report — " + (report.system || "System");
    var dark = !!htmlOptions.darkMode;
    var showTime = htmlOptions.includeTimestamp !== false;

    // Colour palette
    var bg = dark ? "#1a1a2e" : "#f8f9fa";
    var cardBg = dark ? "#16213e" : "#ffffff";
    var textColor = dark ? "#e0e0e0" : "#333333";
    var mutedText = dark ? "#a0a0a0" : "#6c757d";
    var borderColor = dark ? "#2a2a4a" : "#dee2e6";

    var severityColors = {
      critical: { bg: "#dc3545", text: "#fff" },
      warning:  { bg: "#ffc107", text: "#333" },
      info:     { bg: "#17a2b8", text: "#fff" },
      pass:     { bg: "#28a745", text: "#fff" }
    };

    var gradeColors = {
      A: "#28a745", B: "#5cb85c", C: "#ffc107", D: "#fd7e14", F: "#dc3545"
    };

    var gradeColor = gradeColors[report.grade] || "#6c757d";

    // Build category score bars
    var cats = ["accessibility", "privacy", "security", "operational"];
    var catLabels = { accessibility: "Accessibility", privacy: "Privacy", security: "Security", operational: "Operational" };
    var catIcons = { accessibility: "♿", privacy: "🔒", security: "🛡️", operational: "⚙️" };

    var scoreBarsHtml = "";
    for (var ci = 0; ci < cats.length; ci++) {
      var cat = cats[ci];
      var cs = report.categoryScores[cat];
      if (!cs) continue;
      var barColor = cs.score >= 80 ? "#28a745" : cs.score >= 60 ? "#ffc107" : "#dc3545";
      scoreBarsHtml += '<div style="margin-bottom:12px">'
        + '<div style="display:flex;justify-content:space-between;margin-bottom:4px">'
        + '<span>' + catIcons[cat] + ' ' + catLabels[cat] + '</span>'
        + '<span style="font-weight:600">' + cs.score + '/100</span>'
        + '</div>'
        + '<div style="background:' + borderColor + ';border-radius:8px;height:10px;overflow:hidden">'
        + '<div style="width:' + cs.score + '%;height:100%;background:' + barColor + ';border-radius:8px;transition:width 0.5s"></div>'
        + '</div>'
        + '<div style="font-size:12px;color:' + mutedText + ';margin-top:2px">'
        + cs.passed + '/' + cs.total + ' passed'
        + (cs.criticals > 0 ? ' · ' + cs.criticals + ' critical' : '')
        + (cs.warnings > 0 ? ' · ' + cs.warnings + ' warning' : '')
        + '</div></div>';
    }

    // Build findings table
    var findingsHtml = "";
    // Sort: critical first, then warning, info, pass
    var sortedFindings = report.findings.slice().sort(function (a, b) {
      var order = { critical: 0, warning: 1, info: 2, pass: 3 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    });

    for (var fi = 0; fi < sortedFindings.length; fi++) {
      var f = sortedFindings[fi];
      var sc = severityColors[f.severity] || severityColors.info;
      var recHtml = f.recommendation
        ? '<div style="margin-top:6px;padding:8px 12px;background:' + (dark ? "#1a1a2e" : "#f1f3f5")
          + ';border-left:3px solid ' + sc.bg + ';border-radius:4px;font-size:13px">💡 ' + escapeHtml(f.recommendation) + '</div>'
        : '';

      findingsHtml += '<div style="padding:14px 16px;border-bottom:1px solid ' + borderColor + '">'
        + '<div style="display:flex;align-items:center;gap:10px">'
        + '<span style="display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;text-transform:uppercase;background:'
        + sc.bg + ';color:' + sc.text + '">' + f.severity + '</span>'
        + '<span style="font-size:12px;color:' + mutedText + '">' + escapeHtml(f.id) + '</span>'
        + '<span style="font-weight:600">' + escapeHtml(f.title) + '</span>'
        + '</div>'
        + '<div style="margin-top:4px;font-size:13px;color:' + mutedText + '">' + escapeHtml(f.description) + '</div>'
        + recHtml
        + '</div>';
    }

    // Summary counters
    var summaryItems = [
      { label: "Passed", value: report.passed, color: "#28a745" },
      { label: "Critical", value: report.criticals, color: "#dc3545" },
      { label: "Warnings", value: report.warnings, color: "#ffc107" },
      { label: "Total Checks", value: report.totalFindings, color: mutedText }
    ];
    var summaryHtml = "";
    for (var si = 0; si < summaryItems.length; si++) {
      var s = summaryItems[si];
      summaryHtml += '<div style="text-align:center;flex:1;min-width:100px">'
        + '<div style="font-size:28px;font-weight:700;color:' + s.color + '">' + s.value + '</div>'
        + '<div style="font-size:12px;color:' + mutedText + '">' + s.label + '</div></div>';
    }

    var html = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
      + '<meta name="viewport" content="width=device-width,initial-scale=1">'
      + '<title>' + escapeHtml(title) + '</title>'
      + '<style>'
      + 'body{margin:0;padding:20px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;'
      + 'background:' + bg + ';color:' + textColor + '}'
      + '.card{background:' + cardBg + ';border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,' + (dark ? '0.3' : '0.08') + ');margin-bottom:20px;overflow:hidden}'
      + '.card-header{padding:16px 20px;font-weight:600;font-size:16px;border-bottom:1px solid ' + borderColor + '}'
      + '.card-body{padding:20px}'
      + '@media print{body{background:#fff;color:#333}.card{box-shadow:none;border:1px solid #ddd}}'
      + '</style></head><body>'
      + '<div style="max-width:900px;margin:0 auto">'
      // Header
      + '<div style="text-align:center;margin-bottom:24px">'
      + '<h1 style="margin:0 0 4px 0;font-size:24px">' + escapeHtml(report.system) + ' Compliance Report</h1>'
      + (showTime ? '<div style="color:' + mutedText + ';font-size:13px">Generated ' + escapeHtml(report.generatedAt) + '</div>' : '')
      + '</div>'
      // Grade circle + summary
      + '<div class="card"><div class="card-body" style="display:flex;align-items:center;gap:24px;flex-wrap:wrap">'
      + '<div style="flex-shrink:0;text-align:center">'
      + '<div style="width:90px;height:90px;border-radius:50%;border:4px solid ' + gradeColor
      + ';display:flex;flex-direction:column;align-items:center;justify-content:center">'
      + '<div style="font-size:32px;font-weight:800;color:' + gradeColor + '">' + report.grade + '</div>'
      + '<div style="font-size:12px;color:' + mutedText + '">' + report.overallScore + '/100</div>'
      + '</div></div>'
      + '<div style="display:flex;flex-wrap:wrap;flex:1;gap:8px">' + summaryHtml + '</div>'
      + '</div></div>'
      // Category scores
      + '<div class="card"><div class="card-header">Category Scores</div><div class="card-body">'
      + scoreBarsHtml
      + '</div></div>'
      // Findings
      + '<div class="card"><div class="card-header">Findings (' + report.totalFindings + ')</div>'
      + findingsHtml
      + '</div>'
      // Footer
      + '<div style="text-align:center;padding:16px;font-size:12px;color:' + mutedText + '">'
      + 'Generated by gif-captcha compliance reporter'
      + '</div></div></body></html>';

    return html;
  }

  /**
   * Escape HTML special characters to prevent XSS in generated reports.
   * @param {string} str - Raw string
   * @returns {string} HTML-safe string
   */
  function escapeHtml(str) {
    if (typeof str !== "string") return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  return {
    generateReport: generateReport,
    getRecommendedConfig: getRecommendedConfig,
    compareReports: compareReports,
    formatReportText: formatReportText,
    formatReportHtml: formatReportHtml,
    SEVERITY: SEVERITY,
    CATEGORY: CATEGORY
  };
}


module.exports = { createComplianceReporter: createComplianceReporter };
