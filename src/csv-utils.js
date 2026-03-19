/**
 * csv-utils.js — Shared CSV formatting utilities for gif-captcha.
 *
 * Consolidates the CSV escape logic that was previously only in
 * captcha-audit-log.js.  Other modules (solve-funnel-analyzer,
 * captcha-stats-collector) were writing CSV with raw .join(",")
 * and no escaping, leaving them vulnerable to CSV injection (CWE-1236).
 *
 * All modules that produce CSV output should import from here.
 *
 * @module gif-captcha/csv-utils
 */

"use strict";

/**
 * Escape a value for safe inclusion in a CSV field.
 *
 * Prevents CSV injection (CWE-1236): spreadsheet applications interpret
 * leading =, +, -, @, \t, \r as formulas.  These are prefixed with a
 * single-quote (standard Excel "text" escape) and quoted.
 *
 * Also handles values containing commas, double-quotes, or newlines.
 *
 * @param {*} val - Value to escape (coerced to string; null/undefined → "")
 * @returns {string} Safe CSV field value
 */
function csvEscape(val) {
  if (val == null) return "";
  var s = String(val);
  // CWE-1236: prefix formula-triggering characters
  if (/^[=+\-@\t\r]/.test(s)) {
    s = "'" + s;
  }
  if (s.indexOf(",") !== -1 || s.indexOf('"') !== -1 || s.indexOf("\n") !== -1 || s.indexOf("'") !== -1) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

/**
 * Build a CSV row from an array of values, escaping each field.
 *
 * @param {Array} fields - Array of field values
 * @returns {string} Comma-separated, properly escaped CSV row
 */
function csvRow(fields) {
  var parts = [];
  for (var i = 0; i < fields.length; i++) {
    parts.push(csvEscape(fields[i]));
  }
  return parts.join(",");
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    csvEscape: csvEscape,
    csvRow: csvRow,
  };
}
