/**
 * Tests for crypto-utils — Shared cryptographic random utilities.
 *
 * Validates secureRandom, secureRandomHex, and secureRandomInt produce
 * correctly bounded, unique values using crypto.randomBytes.
 */

"use strict";

var { secureRandom, secureRandomHex, secureRandomInt } = require("../src/crypto-utils");

describe("crypto-utils", function () {

  // ── secureRandom ──────────────────────────────────────────────

  describe("secureRandom", function () {

    test("returns a number", function () {
      expect(typeof secureRandom()).toBe("number");
    });

    test("returns value in [0, 1)", function () {
      for (var i = 0; i < 100; i++) {
        var v = secureRandom();
        expect(v).toBeGreaterThanOrEqual(0);
        expect(v).toBeLessThan(1);
      }
    });

    test("produces varying values (not constant)", function () {
      var values = new Set();
      for (var i = 0; i < 20; i++) {
        values.add(secureRandom());
      }
      // Should have more than 1 unique value
      expect(values.size).toBeGreaterThan(1);
    });
  });

  // ── secureRandomHex ───────────────────────────────────────────

  describe("secureRandomHex", function () {

    test("returns string of requested length", function () {
      expect(secureRandomHex(8).length).toBe(8);
      expect(secureRandomHex(16).length).toBe(16);
      expect(secureRandomHex(32).length).toBe(32);
      expect(secureRandomHex(1).length).toBe(1);
    });

    test("returns only hex characters", function () {
      var hex = secureRandomHex(64);
      expect(/^[0-9a-f]+$/.test(hex)).toBe(true);
    });

    test("produces unique values", function () {
      var a = secureRandomHex(16);
      var b = secureRandomHex(16);
      expect(a).not.toBe(b);
    });

    test("handles odd lengths", function () {
      expect(secureRandomHex(3).length).toBe(3);
      expect(secureRandomHex(7).length).toBe(7);
    });
  });

  // ── secureRandomInt ───────────────────────────────────────────

  describe("secureRandomInt", function () {

    test("returns integer in [0, exclusiveMax)", function () {
      for (var i = 0; i < 100; i++) {
        var v = secureRandomInt(10);
        expect(Number.isInteger(v)).toBe(true);
        expect(v).toBeGreaterThanOrEqual(0);
        expect(v).toBeLessThan(10);
      }
    });

    test("returns 0 when exclusiveMax is 1", function () {
      for (var i = 0; i < 20; i++) {
        expect(secureRandomInt(1)).toBe(0);
      }
    });

    test("covers range (distribution check)", function () {
      var seen = new Set();
      for (var i = 0; i < 200; i++) {
        seen.add(secureRandomInt(5));
      }
      // With 200 tries and max=5, should hit all values 0-4
      expect(seen.size).toBe(5);
    });

    test("handles large exclusiveMax", function () {
      var v = secureRandomInt(1000000);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1000000);
    });
  });
});
