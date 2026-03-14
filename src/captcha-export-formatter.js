/**
 * captcha-export-formatter.js — Research-friendly data export for CAPTCHA studies.
 *
 * Converts CAPTCHA trial data into formats commonly used in academic research:
 * LaTeX tables, R data frames, SPSS-compatible CSV, BibTeX entries, and
 * research paper appendix snippets.
 *
 * Usage:
 *   const { createExportFormatter } = require('./captcha-export-formatter');
 *   const fmt = createExportFormatter();
 *
 *   fmt.addTrial({ participant: 'P01', solved: true, timeMs: 2340, challengeType: 'sequence', attempts: 1 });
 *   fmt.addTrial({ participant: 'P01', solved: false, timeMs: 8100, challengeType: 'pattern', attempts: 3 });
 *
 *   const latex  = fmt.toLatex();          // LaTeX table (booktabs)
 *   const rCode  = fmt.toR();             // R data.frame code
 *   const spss   = fmt.toSPSS();          // SPSS-compatible CSV with codebook
 *   const bibtex = fmt.toBibTeX({ title: 'GIF CAPTCHA Study', author: 'Doe, J.', year: '2026' });
 *   const appendix = fmt.toAppendix();    // Full research appendix (LaTeX)
 *   const summary  = fmt.descriptiveStats(); // Descriptive statistics table
 *
 * @module captcha-export-formatter
 */

"use strict";

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function mean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stddev(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  return Math.sqrt(arr.reduce((s, v) => s + (v - m) ** 2, 0) / (arr.length - 1));
}

function median(arr) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = (p / 100) * (sorted.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

function escapeLatex(str) {
  return String(str)
    .replace(/\\/g, '\\textbackslash{}')
    .replace(/[&%$#_{}~^]/g, m => '\\' + m);
}

function round(n, dp = 2) {
  return Number(n.toFixed(dp));
}

/* ------------------------------------------------------------------ */
/*  Trial schema                                                       */
/* ------------------------------------------------------------------ */

/**
 * @typedef {Object} Trial
 * @property {string}  participant     - Participant ID
 * @property {boolean} solved          - Whether challenge was solved
 * @property {number}  timeMs          - Response time in ms
 * @property {string}  challengeType   - Challenge type tag
 * @property {number}  [attempts]      - Number of attempts (default 1)
 * @property {string}  [difficulty]    - easy | medium | hard
 * @property {string}  [device]        - desktop | mobile | tablet
 * @property {number}  [timestamp]     - Unix ms timestamp
 * @property {Object}  [meta]          - Arbitrary metadata
 */

function validateTrial(t) {
  if (!t || typeof t !== 'object') throw new Error('Trial must be an object');
  if (typeof t.participant !== 'string' || !t.participant.trim())
    throw new Error('Trial requires non-empty participant string');
  if (typeof t.solved !== 'boolean') throw new Error('Trial requires boolean solved');
  if (typeof t.timeMs !== 'number' || t.timeMs < 0)
    throw new Error('Trial requires non-negative numeric timeMs');
  if (typeof t.challengeType !== 'string' || !t.challengeType.trim())
    throw new Error('Trial requires non-empty challengeType string');
}

/* ------------------------------------------------------------------ */
/*  createExportFormatter                                              */
/* ------------------------------------------------------------------ */

function createExportFormatter(opts = {}) {
  const trials = [];
  const createdAt = opts.createdAt || Date.now();

  /* ---- add / bulk add ---- */

  function addTrial(t) {
    validateTrial(t);
    trials.push({
      participant: t.participant.trim(),
      solved: t.solved,
      timeMs: t.timeMs,
      challengeType: t.challengeType.trim(),
      attempts: typeof t.attempts === 'number' && t.attempts >= 1 ? Math.floor(t.attempts) : 1,
      difficulty: ['easy', 'medium', 'hard'].includes(t.difficulty) ? t.difficulty : null,
      device: ['desktop', 'mobile', 'tablet'].includes(t.device) ? t.device : null,
      timestamp: typeof t.timestamp === 'number' ? t.timestamp : Date.now(),
      meta: t.meta || {},
    });
  }

  function addTrials(arr) {
    if (!Array.isArray(arr)) throw new Error('addTrials expects an array');
    arr.forEach(addTrial);
  }

  function getTrials() { return [...trials]; }
  function count() { return trials.length; }
  function clear() { trials.length = 0; }

  /* ---- descriptive statistics ---- */

  function descriptiveStats(filter) {
    const data = filter ? trials.filter(filter) : trials;
    if (!data.length) return null;
    const times = data.map(t => t.timeMs).sort((a, b) => a - b);
    const solved = data.filter(t => t.solved);
    const attempts = data.map(t => t.attempts);
    const types = [...new Set(data.map(t => t.challengeType))];
    const participants = [...new Set(data.map(t => t.participant))];

    const byType = {};
    for (const type of types) {
      const sub = data.filter(t => t.challengeType === type);
      const st = sub.map(t => t.timeMs).sort((a, b) => a - b);
      byType[type] = {
        n: sub.length,
        solveRate: round(sub.filter(t => t.solved).length / sub.length, 4),
        meanTimeMs: round(mean(st)),
        sdTimeMs: round(stddev(st)),
        medianTimeMs: round(median(st)),
      };
    }

    return {
      n: data.length,
      participants: participants.length,
      challengeTypes: types.length,
      solveRate: round(solved.length / data.length, 4),
      meanTimeMs: round(mean(times)),
      sdTimeMs: round(stddev(times)),
      medianTimeMs: round(median(times)),
      p25TimeMs: round(percentile(times, 25)),
      p75TimeMs: round(percentile(times, 75)),
      p95TimeMs: round(percentile(times, 95)),
      minTimeMs: times[0],
      maxTimeMs: times[times.length - 1],
      meanAttempts: round(mean(attempts)),
      byType,
    };
  }

  /* ---- LaTeX ---- */

  function toLatex(options = {}) {
    if (!trials.length) return '% No trial data';
    const caption = options.caption || 'CAPTCHA Trial Results';
    const label = options.label || 'tab:captcha-results';
    const stats = descriptiveStats();

    const lines = [];
    lines.push('\\begin{table}[htbp]');
    lines.push('\\centering');
    lines.push(`\\caption{${escapeLatex(caption)}}`);
    lines.push(`\\label{${label}}`);
    lines.push('\\begin{tabular}{@{}llrrrrr@{}}');
    lines.push('\\toprule');
    lines.push('Type & N & Solve Rate & Mean (ms) & SD (ms) & Median (ms) & P95 (ms) \\\\');
    lines.push('\\midrule');

    for (const [type, s] of Object.entries(stats.byType)) {
      const data = trials.filter(t => t.challengeType === type);
      const sorted = data.map(t => t.timeMs).sort((a, b) => a - b);
      const p95 = round(percentile(sorted, 95));
      lines.push(`${escapeLatex(type)} & ${s.n} & ${(s.solveRate * 100).toFixed(1)}\\% & ${s.meanTimeMs} & ${s.sdTimeMs} & ${s.medianTimeMs} & ${p95} \\\\`);
    }

    lines.push('\\midrule');
    lines.push(`\\textbf{Overall} & ${stats.n} & ${(stats.solveRate * 100).toFixed(1)}\\% & ${stats.meanTimeMs} & ${stats.sdTimeMs} & ${stats.medianTimeMs} & ${stats.p95TimeMs} \\\\`);
    lines.push('\\bottomrule');
    lines.push('\\end{tabular}');
    lines.push('\\end{table}');

    return lines.join('\n');
  }

  /* ---- R ---- */

  function toR(varName = 'captcha_data') {
    if (!trials.length) return `# No trial data\n${varName} <- data.frame()`;
    const lines = [];
    lines.push(`# CAPTCHA trial data — ${trials.length} observations`);
    lines.push(`# Generated ${new Date(createdAt).toISOString()}`);
    lines.push('');

    const participant = trials.map(t => `"${t.participant}"`);
    const solved = trials.map(t => t.solved ? 'TRUE' : 'FALSE');
    const timeMs = trials.map(t => t.timeMs);
    const type = trials.map(t => `"${t.challengeType}"`);
    const attempts = trials.map(t => t.attempts);

    lines.push(`${varName} <- data.frame(`);
    lines.push(`  participant = c(${participant.join(', ')}),`);
    lines.push(`  solved = c(${solved.join(', ')}),`);
    lines.push(`  time_ms = c(${timeMs.join(', ')}),`);
    lines.push(`  challenge_type = factor(c(${type.join(', ')})),`);
    lines.push(`  attempts = c(${attempts.join(', ')}),`);
    lines.push(`  stringsAsFactors = FALSE`);
    lines.push(`)`);
    lines.push('');
    lines.push(`# Quick summary`);
    lines.push(`summary(${varName})`);
    lines.push(`table(${varName}$challenge_type, ${varName}$solved)`);

    // Add difficulty/device if present
    if (trials.some(t => t.difficulty)) {
      lines.push('');
      const diff = trials.map(t => t.difficulty ? `"${t.difficulty}"` : 'NA');
      lines.push(`${varName}$difficulty <- factor(c(${diff.join(', ')}), levels = c("easy", "medium", "hard"), ordered = TRUE)`);
    }
    if (trials.some(t => t.device)) {
      lines.push('');
      const dev = trials.map(t => t.device ? `"${t.device}"` : 'NA');
      lines.push(`${varName}$device <- factor(c(${dev.join(', ')}))`);
    }

    return lines.join('\n');
  }

  /* ---- SPSS-compatible CSV + codebook ---- */

  function toSPSS() {
    if (!trials.length) return { csv: '', codebook: '' };

    // Header
    const headers = ['participant', 'solved', 'time_ms', 'challenge_type', 'attempts', 'difficulty', 'device', 'timestamp'];
    const csvLines = [headers.join(',')];

    for (const t of trials) {
      csvLines.push([
        `"${t.participant}"`,
        t.solved ? 1 : 0,
        t.timeMs,
        `"${t.challengeType}"`,
        t.attempts,
        t.difficulty ? `"${t.difficulty}"` : '',
        t.device ? `"${t.device}"` : '',
        t.timestamp,
      ].join(','));
    }

    const codebook = [
      'VARIABLE LABELS',
      '  participant "Participant identifier"',
      '  solved "Challenge outcome (0=failed, 1=solved)"',
      '  time_ms "Response time in milliseconds"',
      '  challenge_type "CAPTCHA challenge type"',
      '  attempts "Number of attempts"',
      '  difficulty "Challenge difficulty level"',
      '  device "Device type used"',
      '  timestamp "Unix timestamp (ms)".',
      '',
      'VALUE LABELS',
      '  solved 0 "Failed" 1 "Solved"',
      '  difficulty "easy" "Easy" "medium" "Medium" "hard" "Hard"',
      '  device "desktop" "Desktop" "mobile" "Mobile" "tablet" "Tablet".',
    ].join('\n');

    return { csv: csvLines.join('\n'), codebook };
  }

  /* ---- BibTeX ---- */

  function toBibTeX(entry = {}) {
    const key = entry.key || 'gifcaptcha' + (entry.year || '2026');
    const fields = {
      title: entry.title || 'GIF-based CAPTCHA: An Experimental Study',
      author: entry.author || 'Anonymous',
      year: entry.year || '2026',
      institution: entry.institution || '',
      note: entry.note || `Dataset: ${trials.length} trials, ${new Set(trials.map(t => t.participant)).size} participants`,
      ...entry.extra,
    };

    const type = entry.type || 'misc';
    const lines = [`@${type}{${key},`];
    for (const [k, v] of Object.entries(fields)) {
      if (v) lines.push(`  ${k} = {${v}},`);
    }
    lines.push('}');
    return lines.join('\n');
  }

  /* ---- Full appendix ---- */

  function toAppendix(options = {}) {
    if (!trials.length) return '% No trial data for appendix';
    const stats = descriptiveStats();
    const title = options.title || 'CAPTCHA Experimental Data';

    const lines = [];
    lines.push(`\\section*{Appendix: ${escapeLatex(title)}}`);
    lines.push('');

    // Dataset overview
    lines.push('\\subsection*{Dataset Overview}');
    lines.push('\\begin{itemize}');
    lines.push(`  \\item Total trials: ${stats.n}`);
    lines.push(`  \\item Participants: ${stats.participants}`);
    lines.push(`  \\item Challenge types: ${stats.challengeTypes}`);
    lines.push(`  \\item Overall solve rate: ${(stats.solveRate * 100).toFixed(1)}\\%`);
    lines.push(`  \\item Mean response time: ${stats.meanTimeMs} ms (SD = ${stats.sdTimeMs})`);
    lines.push('\\end{itemize}');
    lines.push('');

    // Summary table
    lines.push(toLatex({ caption: 'Summary Statistics by Challenge Type', label: 'tab:appendix-summary' }));
    lines.push('');

    // Per-participant table
    lines.push('\\begin{table}[htbp]');
    lines.push('\\centering');
    lines.push('\\caption{Per-Participant Performance}');
    lines.push('\\label{tab:appendix-participants}');
    lines.push('\\begin{tabular}{@{}lrrrr@{}}');
    lines.push('\\toprule');
    lines.push('Participant & Trials & Solve Rate & Mean Time (ms) & Mean Attempts \\\\');
    lines.push('\\midrule');

    const participants = [...new Set(trials.map(t => t.participant))].sort();
    for (const p of participants) {
      const pt = trials.filter(t => t.participant === p);
      const sr = round(pt.filter(t => t.solved).length / pt.length, 4);
      const mt = round(mean(pt.map(t => t.timeMs)));
      const ma = round(mean(pt.map(t => t.attempts)));
      lines.push(`${escapeLatex(p)} & ${pt.length} & ${(sr * 100).toFixed(1)}\\% & ${mt} & ${ma} \\\\`);
    }

    lines.push('\\bottomrule');
    lines.push('\\end{tabular}');
    lines.push('\\end{table}');

    return lines.join('\n');
  }

  /* ---- JSON / import ---- */

  function toJSON(pretty = true) {
    const obj = {
      exportedAt: new Date().toISOString(),
      trialCount: trials.length,
      stats: descriptiveStats(),
      trials: trials.map(t => ({ ...t })),
    };
    return pretty ? JSON.stringify(obj, null, 2) : JSON.stringify(obj);
  }

  function importJSON(str) {
    const parsed = typeof str === 'string' ? JSON.parse(str) : str;
    if (!parsed || !Array.isArray(parsed.trials)) throw new Error('Invalid export JSON: missing trials array');
    addTrials(parsed.trials);
    return parsed.trials.length;
  }

  /* ---- public API ---- */

  return {
    addTrial,
    addTrials,
    getTrials,
    count,
    clear,
    descriptiveStats,
    toLatex,
    toR,
    toSPSS,
    toBibTeX,
    toAppendix,
    toJSON,
    importJSON,
  };
}

module.exports = { createExportFormatter };
