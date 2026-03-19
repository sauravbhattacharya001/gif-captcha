/**
 * csv-utils.test.js — Tests for CSV escape and row formatting utilities.
 *
 * Covers: standard escaping, CSV injection prevention (CWE-1236),
 * null/undefined handling, unicode, multi-line values, and csvRow composition.
 */

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { csvEscape, csvRow } = require("../src/csv-utils");

describe("csvEscape", function () {
  // ── Basic values ──────────────────────────────────────────────────

  it("returns empty string for null", function () {
    assert.equal(csvEscape(null), "");
  });

  it("returns empty string for undefined", function () {
    assert.equal(csvEscape(undefined), "");
  });

  it("passes through a plain string unchanged", function () {
    assert.equal(csvEscape("hello"), "hello");
  });

  it("coerces numbers to string", function () {
    assert.equal(csvEscape(42), "42");
    assert.equal(csvEscape(0), "0");
    assert.equal(csvEscape(-3.14), "\"'-3.14\"");  // leading minus → prefixed + quoted (contains ')
  });

  it("coerces boolean to string", function () {
    assert.equal(csvEscape(true), "true");
    assert.equal(csvEscape(false), "false");
  });

  // ── Quoting for special characters ────────────────────────────────

  it("quotes values containing commas", function () {
    assert.equal(csvEscape("a,b"), '"a,b"');
  });

  it("quotes and escapes values containing double quotes", function () {
    assert.equal(csvEscape('say "hi"'), '"say ""hi"""');
  });

  it("quotes values containing newlines", function () {
    assert.equal(csvEscape("line1\nline2"), '"line1\nline2"');
  });

  // ── CWE-1236 CSV injection prevention ────────────────────────────

  it("prefixes leading = to prevent formula injection", function () {
    var result = csvEscape("=SUM(A1:A10)");
    assert.ok(result.startsWith("\"'="), "should prefix with ' and quote: " + result);
  });

  it("prefixes leading + to prevent formula injection", function () {
    var result = csvEscape("+cmd|' /C notepad'");
    assert.ok(result.startsWith("\"'+"), "should prefix with ' and quote: " + result);
  });

  it("prefixes leading - to prevent formula injection", function () {
    var result = csvEscape("-1+1");
    assert.ok(result.startsWith("\"'-"), "should prefix: " + result);
  });

  it("prefixes leading @ to prevent formula injection", function () {
    var result = csvEscape("@SUM(A1)");
    assert.ok(result.startsWith("\"'@"), "should prefix: " + result);
  });

  it("prefixes leading tab character", function () {
    var result = csvEscape("\tcmd");
    assert.ok(result.includes("'"), "should prefix tab-leading values");
  });

  it("prefixes leading carriage return", function () {
    var result = csvEscape("\rcmd");
    assert.ok(result.includes("'"), "should prefix CR-leading values");
  });

  // ── Edge cases ────────────────────────────────────────────────────

  it("handles empty string", function () {
    assert.equal(csvEscape(""), "");
  });

  it("handles unicode content", function () {
    assert.equal(csvEscape("こんにちは"), "こんにちは");
  });

  it("handles unicode with comma", function () {
    assert.equal(csvEscape("名前,値"), '"名前,値"');
  });

  it("handles very long strings without error", function () {
    var long = "a".repeat(100000);
    assert.equal(csvEscape(long), long);
  });

  it("handles string with only special chars", function () {
    assert.equal(csvEscape(","), '","');
  });
});

describe("csvRow", function () {
  it("joins simple values with commas", function () {
    assert.equal(csvRow(["a", "b", "c"]), "a,b,c");
  });

  it("escapes individual fields", function () {
    assert.equal(csvRow(["hello", "a,b", "c"]), 'hello,"a,b",c');
  });

  it("handles empty array", function () {
    assert.equal(csvRow([]), "");
  });

  it("handles single element", function () {
    assert.equal(csvRow(["only"]), "only");
  });

  it("handles mixed types", function () {
    var row = csvRow([1, null, true, "text", undefined]);
    assert.equal(row, "1,,true,text,");
  });

  it("handles injection attempts in row context", function () {
    var row = csvRow(["=HYPERLINK(\"http://evil.com\")", "safe", "+cmd|' /C calc'"]);
    // Both dangerous fields should be prefixed
    assert.ok(row.includes("'="), "should neutralize = injection");
    assert.ok(row.includes("'+"), "should neutralize + injection");
    // The safe field should remain untouched
    assert.ok(row.includes(",safe,"), "safe field should be plain");
  });
});
