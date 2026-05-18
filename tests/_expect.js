"use strict";

/**
 * Minimal Jest-compatible `expect` shim for use under node:test.
 *
 * Background
 * ----------
 * Some test files in this repo were originally written assuming a Jest-like
 * environment (`expect(value).toBe(...)`, `.toEqual(...)`, etc.) but the
 * project's test runner is `node --test` and there is no Jest dependency.
 * That left ~500 tests crashing with `expect is not defined` instead of
 * actually validating behavior.
 *
 * This shim implements just enough of the Jest matcher surface used by those
 * tests on top of `node:assert/strict`, so they run as real tests with real
 * pass/fail signal. It is intentionally tiny — not a Jest replacement, just
 * a compatibility bridge for the matcher subset we actually use:
 *
 *   .toBe, .toEqual, .toBeDefined, .toBeUndefined, .toBeNull, .toBeTruthy,
 *   .toBeGreaterThan, .toBeGreaterThanOrEqual, .toBeLessThan,
 *   .toBeLessThanOrEqual, .toBeCloseTo, .toBeInstanceOf,
 *   .toContain, .toHaveLength, .toHaveProperty, .toMatch, .toThrow
 *
 * Each matcher also supports `.not.<matcher>(...)`.
 *
 * Side effect: setting `globalThis.expect` makes `expect(...)` available
 * directly inside any test file that does `require('./_expect')`.
 */

const assert = require("node:assert/strict");

function isPlainObject(v) {
  return v !== null && typeof v === "object";
}

function hasNestedProperty(obj, path) {
  if (!isPlainObject(obj)) return false;
  const parts = Array.isArray(path)
    ? path.slice()
    : String(path).split(".");
  let cur = obj;
  for (const key of parts) {
    if (cur === null || cur === undefined) return false;
    if (!(key in Object(cur))) return false;
    cur = cur[key];
  }
  return true;
}

function getNestedProperty(obj, path) {
  const parts = Array.isArray(path)
    ? path.slice()
    : String(path).split(".");
  let cur = obj;
  for (const key of parts) {
    if (cur === null || cur === undefined) return undefined;
    cur = cur[key];
  }
  return cur;
}

function makeMatchers(actual, negated) {
  function check(condition, message) {
    const ok = negated ? !condition : condition;
    if (!ok) {
      throw new assert.AssertionError({
        message,
        actual,
        expected: undefined,
        operator: negated ? "not" : "expect",
      });
    }
  }

  const api = {
    toBe(expected) {
      const condition = Object.is(actual, expected);
      check(
        condition,
        `expected ${JSON.stringify(actual)} ${negated ? "not " : ""}to be ${JSON.stringify(expected)}`,
      );
    },
    toEqual(expected) {
      let condition = true;
      try {
        assert.deepStrictEqual(actual, expected);
      } catch {
        condition = false;
      }
      check(
        condition,
        `expected values ${negated ? "not " : ""}to deep-equal`,
      );
    },
    toBeDefined() {
      check(actual !== undefined, `expected value ${negated ? "not " : ""}to be defined`);
    },
    toBeUndefined() {
      check(actual === undefined, `expected value ${negated ? "not " : ""}to be undefined`);
    },
    toBeNull() {
      check(actual === null, `expected value ${negated ? "not " : ""}to be null`);
    },
    toBeTruthy() {
      check(Boolean(actual), `expected value ${negated ? "not " : ""}to be truthy`);
    },
    toBeFalsy() {
      check(!actual, `expected value ${negated ? "not " : ""}to be falsy`);
    },
    toBeGreaterThan(n) {
      check(actual > n, `expected ${actual} ${negated ? "not " : ""}to be > ${n}`);
    },
    toBeGreaterThanOrEqual(n) {
      check(actual >= n, `expected ${actual} ${negated ? "not " : ""}to be >= ${n}`);
    },
    toBeLessThan(n) {
      check(actual < n, `expected ${actual} ${negated ? "not " : ""}to be < ${n}`);
    },
    toBeLessThanOrEqual(n) {
      check(actual <= n, `expected ${actual} ${negated ? "not " : ""}to be <= ${n}`);
    },
    toBeCloseTo(expected, precision) {
      const digits = precision == null ? 2 : precision;
      const diff = Math.abs(actual - expected);
      const tolerance = Math.pow(10, -digits) / 2;
      check(
        diff < tolerance,
        `expected ${actual} ${negated ? "not " : ""}to be close to ${expected} (precision ${digits})`,
      );
    },
    toBeInstanceOf(ctor) {
      check(
        actual instanceof ctor,
        `expected value ${negated ? "not " : ""}to be instance of ${ctor && ctor.name}`,
      );
    },
    toContain(item) {
      let condition;
      if (typeof actual === "string") {
        condition = actual.indexOf(item) !== -1;
      } else if (Array.isArray(actual) || (actual && typeof actual.length === "number")) {
        condition = Array.prototype.indexOf.call(actual, item) !== -1;
      } else if (actual instanceof Set || actual instanceof Map) {
        condition = actual.has(item);
      } else {
        condition = false;
      }
      check(condition, `expected collection ${negated ? "not " : ""}to contain ${JSON.stringify(item)}`);
    },
    toHaveLength(len) {
      const got = actual == null ? undefined : actual.length;
      check(got === len, `expected length ${len}, got ${got}`);
    },
    toHaveProperty(path, value) {
      const has = hasNestedProperty(actual, path);
      if (arguments.length < 2) {
        check(has, `expected object ${negated ? "not " : ""}to have property "${path}"`);
        return;
      }
      let condition = has;
      if (condition) {
        try {
          assert.deepStrictEqual(getNestedProperty(actual, path), value);
        } catch {
          condition = false;
        }
      }
      check(
        condition,
        `expected object ${negated ? "not " : ""}to have property "${path}" with given value`,
      );
    },
    toMatch(pattern) {
      let condition;
      if (pattern instanceof RegExp) {
        condition = pattern.test(String(actual));
      } else {
        condition = String(actual).indexOf(String(pattern)) !== -1;
      }
      check(
        condition,
        `expected "${actual}" ${negated ? "not " : ""}to match ${pattern}`,
      );
    },
    toThrow(expected) {
      if (typeof actual !== "function") {
        throw new assert.AssertionError({
          message: "expect(fn).toThrow requires a function",
          actual: typeof actual,
          expected: "function",
        });
      }
      let threw = false;
      let error;
      try {
        actual();
      } catch (e) {
        threw = true;
        error = e;
      }
      if (!expected) {
        check(threw, `expected function ${negated ? "not " : ""}to throw`);
        return;
      }
      let condition = threw;
      if (condition && expected) {
        if (expected instanceof RegExp) {
          condition = expected.test(error && error.message);
        } else if (typeof expected === "string") {
          condition = error && String(error.message).indexOf(expected) !== -1;
        } else if (typeof expected === "function") {
          condition = error instanceof expected;
        }
      }
      check(
        condition,
        `expected function ${negated ? "not " : ""}to throw matching ${expected}`,
      );
    },
  };

  // Provide aliases used occasionally.
  api.toStrictEqual = api.toEqual;
  return api;
}

function expect(actual) {
  const api = makeMatchers(actual, false);
  Object.defineProperty(api, "not", {
    get() {
      return makeMatchers(actual, true);
    },
  });
  return api;
}

// Make expect callable as a bare global inside any file that requires this.
if (!globalThis.expect) {
  globalThis.expect = expect;
}

module.exports = { expect };
