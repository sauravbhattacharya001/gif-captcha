/**
 * crypto-utils.test.js — Tests for shared cryptographic random utilities.
 *
 * Covers: secureRandom range/type, secureRandomHex length/charset,
 * secureRandomInt bounds, and statistical distribution sanity checks.
 */

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { secureRandom, secureRandomHex, secureRandomInt } = require("../src/crypto-utils");

describe("secureRandom", function () {
  it("returns a number", function () {
    assert.equal(typeof secureRandom(), "number");
  });

  it("returns values in [0, 1)", function () {
    for (var i = 0; i < 1000; i++) {
      var val = secureRandom();
      assert.ok(val >= 0, "should be >= 0, got " + val);
      assert.ok(val < 1, "should be < 1, got " + val);
    }
  });

  it("produces varied output (not constant)", function () {
    var values = new Set();
    for (var i = 0; i < 100; i++) values.add(secureRandom());
    assert.ok(values.size > 90, "expected >90 unique values from 100 calls, got " + values.size);
  });
});

describe("secureRandomHex", function () {
  it("returns a string of the requested length", function () {
    assert.equal(secureRandomHex(8).length, 8);
    assert.equal(secureRandomHex(16).length, 16);
    assert.equal(secureRandomHex(32).length, 32);
    assert.equal(secureRandomHex(1).length, 1);
  });

  it("returns only hex characters", function () {
    for (var i = 0; i < 50; i++) {
      var hex = secureRandomHex(64);
      assert.match(hex, /^[0-9a-f]+$/, "should be lowercase hex: " + hex);
    }
  });

  it("handles odd lengths correctly", function () {
    assert.equal(secureRandomHex(3).length, 3);
    assert.equal(secureRandomHex(7).length, 7);
  });

  it("produces varied output", function () {
    var values = new Set();
    for (var i = 0; i < 50; i++) values.add(secureRandomHex(16));
    assert.ok(values.size > 45, "expected >45 unique values from 50 calls");
  });
});

describe("secureRandomInt", function () {
  it("returns an integer", function () {
    var val = secureRandomInt(100);
    assert.equal(val, Math.floor(val));
  });

  it("stays within [0, exclusiveMax)", function () {
    for (var i = 0; i < 1000; i++) {
      var val = secureRandomInt(10);
      assert.ok(val >= 0, "should be >= 0");
      assert.ok(val < 10, "should be < 10, got " + val);
    }
  });

  it("works with exclusiveMax of 1 (always returns 0)", function () {
    for (var i = 0; i < 100; i++) {
      assert.equal(secureRandomInt(1), 0);
    }
  });

  it("covers the full range over many samples", function () {
    var seen = new Set();
    for (var i = 0; i < 1000; i++) seen.add(secureRandomInt(5));
    assert.equal(seen.size, 5, "expected all values 0-4 to appear, got " + [...seen].sort());
  });

  it("works with large exclusiveMax", function () {
    for (var i = 0; i < 100; i++) {
      var val = secureRandomInt(1000000);
      assert.ok(val >= 0 && val < 1000000);
    }
  });
});
