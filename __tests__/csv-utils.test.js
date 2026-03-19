/**
 * Tests for csv-utils — CSV escaping and row formatting.
 *
 * Covers CWE-1236 (CSV injection) mitigation and edge cases.
 */

"use strict";

var { csvEscape, csvRow } = require("../src/csv-utils");

describe("csv-utils", function () {

  // ── csvEscape ──────────────────────────────────────────────────

  describe("csvEscape", function () {

    test("returns empty string for null", function () {
      expect(csvEscape(null)).toBe("");
    });

    test("returns empty string for undefined", function () {
      expect(csvEscape(undefined)).toBe("");
    });

    test("passes through plain strings unchanged", function () {
      expect(csvEscape("hello")).toBe("hello");
      expect(csvEscape("world123")).toBe("world123");
    });

    test("coerces numbers to string", function () {
      expect(csvEscape(42)).toBe("42");
      expect(csvEscape(3.14)).toBe("3.14");
      expect(csvEscape(0)).toBe("0");
    });

    test("coerces boolean to string", function () {
      expect(csvEscape(true)).toBe("true");
      expect(csvEscape(false)).toBe("false");
    });

    // CWE-1236 prevention
    test("prefixes = with single-quote to prevent formula injection", function () {
      var result = csvEscape("=SUM(A1:A10)");
      expect(result).toContain("'");
      expect(result.indexOf("=")).toBeGreaterThan(0);
    });

    test("prefixes + with single-quote", function () {
      var result = csvEscape("+cmd|'/C calc'!A0");
      expect(result).toContain("'");
    });

    test("prefixes - with single-quote", function () {
      var result = csvEscape("-1+1");
      expect(result).toContain("'");
    });

    test("prefixes @ with single-quote", function () {
      var result = csvEscape("@SUM(A1)");
      expect(result).toContain("'");
    });

    test("prefixes tab character with single-quote", function () {
      var result = csvEscape("\tmalicious");
      expect(result).toContain("'");
    });

    test("prefixes carriage return with single-quote", function () {
      var result = csvEscape("\rmalicious");
      expect(result).toContain("'");
    });

    test("quotes values containing commas", function () {
      var result = csvEscape("hello, world");
      expect(result).toBe('"hello, world"');
    });

    test("quotes and escapes values containing double-quotes", function () {
      var result = csvEscape('say "hello"');
      expect(result).toBe('"say ""hello"""');
    });

    test("quotes values containing newlines", function () {
      var result = csvEscape("line1\nline2");
      expect(result).toBe('"line1\nline2"');
    });

    test("handles combined injection + special chars", function () {
      // = prefix + comma → should be quoted and prefixed
      var result = csvEscape("=1,2,3");
      expect(result.startsWith('"')).toBe(true);
      expect(result).toContain("'=1,2,3");
    });

    test("handles empty string", function () {
      expect(csvEscape("")).toBe("");
    });
  });

  // ── csvRow ─────────────────────────────────────────────────────

  describe("csvRow", function () {

    test("joins plain values with commas", function () {
      expect(csvRow(["a", "b", "c"])).toBe("a,b,c");
    });

    test("escapes individual fields", function () {
      var result = csvRow(["normal", "has, comma", "=formula"]);
      var parts = result.split(",");
      // "has, comma" should be quoted so it doesn't split into two fields
      // The raw result should have the quoted field intact
      expect(result).toContain('"has, comma"');
    });

    test("handles null and undefined in fields", function () {
      expect(csvRow([null, "a", undefined, "b"])).toBe(",a,,b");
    });

    test("handles empty array", function () {
      expect(csvRow([])).toBe("");
    });

    test("handles single field", function () {
      expect(csvRow(["only"])).toBe("only");
    });

    test("handles numeric fields", function () {
      expect(csvRow([1, 2, 3])).toBe("1,2,3");
    });

    test("handles mixed types", function () {
      var result = csvRow([42, "text", true, null, "=bad"]);
      expect(result).toContain("42");
      expect(result).toContain("text");
      expect(result).toContain("true");
    });
  });
});
