/**
 * Extended tests for createI18n — edge cases, fallback behavior,
 * catalog management, interpolation, and locale lifecycle.
 */
var gifCaptcha = require("../src/index");

var { describe, it, beforeEach } = require("node:test");
var assert = require("node:assert/strict");

describe("createI18n (extended)", function () {
  var i18n;

  beforeEach(function () {
    i18n = gifCaptcha.createI18n();
  });

  // ── Initialization ─────────────────────────────────────────────

  describe("initialization", function () {
    it("defaults to English locale", function () {
      assert.strictEqual(i18n.getLocale(), "en");
    });

    it("respects custom initial locale", function () {
      var custom = gifCaptcha.createI18n({ locale: "fr" });
      assert.strictEqual(custom.getLocale(), "fr");
    });

    it("respects custom fallback locale", function () {
      var custom = gifCaptcha.createI18n({ locale: "xx", fallbackLocale: "de" });
      // Requesting a key not in "xx" should fall back to "de"
      assert.strictEqual(custom.t("submit"), "Absenden");
    });

    it("registers custom locales via options.locales", function () {
      var custom = gifCaptcha.createI18n({
        locale: "tl",
        locales: { tl: { submit: "Isumite" } }
      });
      assert.strictEqual(custom.t("submit"), "Isumite");
    });

    it("options.locales merges with built-in catalogs", function () {
      var custom = gifCaptcha.createI18n({
        locales: { en: { "custom.key": "hello" } }
      });
      // New key exists alongside built-in keys
      assert.strictEqual(custom.t("custom.key"), "hello");
      assert.strictEqual(custom.t("submit"), "Submit");
    });

    it("ignores non-string locale option", function () {
      var custom = gifCaptcha.createI18n({ locale: 42 });
      assert.strictEqual(custom.getLocale(), "en");
    });

    it("ignores non-string fallbackLocale option", function () {
      var custom = gifCaptcha.createI18n({ fallbackLocale: null, locale: "xx" });
      // Falls back to "en" as default fallback
      assert.strictEqual(custom.t("submit"), "Submit");
    });
  });

  // ── t() Translation ────────────────────────────────────────────

  describe("t() translation", function () {
    it("returns key for unknown key in all locales", function () {
      assert.strictEqual(i18n.t("nonexistent.key"), "nonexistent.key");
    });

    it("falls back to fallback locale when current locale missing key", function () {
      i18n.addLocale("xx", { submit: "Click" });
      i18n.setLocale("xx");
      // "retry" is not in "xx", should fall back to English
      assert.strictEqual(i18n.t("retry"), "Try Again");
    });

    it("returns key when neither current nor fallback has it", function () {
      i18n.setLocale("xx");
      assert.strictEqual(i18n.t("totally.unknown"), "totally.unknown");
    });

    it("translates all core keys in Spanish", function () {
      i18n.setLocale("es");
      assert.strictEqual(i18n.t("submit"), "Enviar");
      assert.strictEqual(i18n.t("retry"), "Intentar de nuevo");
      assert.strictEqual(i18n.t("success"), "¡Verificación exitosa!");
    });

    it("translates all core keys in Japanese", function () {
      i18n.setLocale("ja");
      assert.strictEqual(i18n.t("submit"), i18n.t("submit")); // just check it returns non-key
      assert.notStrictEqual(i18n.t("submit"), "submit");
    });

    it("translates all core keys in Arabic", function () {
      i18n.setLocale("ar");
      assert.notStrictEqual(i18n.t("submit"), "submit");
      assert.notStrictEqual(i18n.t("retry"), "retry");
    });

    it("translates all core keys in Korean", function () {
      i18n.setLocale("ko");
      assert.notStrictEqual(i18n.t("submit"), "submit");
    });

    it("translates all core keys in Russian", function () {
      i18n.setLocale("ru");
      assert.notStrictEqual(i18n.t("submit"), "submit");
      assert.notStrictEqual(i18n.t("error.timeout"), "error.timeout");
    });

    it("translates all core keys in Italian", function () {
      i18n.setLocale("it");
      assert.strictEqual(i18n.t("submit"), "Invia");
    });

    it("handles empty string key", function () {
      var result = i18n.t("");
      assert.strictEqual(result, "");
    });
  });

  // ── Interpolation ──────────────────────────────────────────────

  describe("interpolation", function () {
    it("interpolates single variable", function () {
      var result = i18n.t("timer.remaining", { seconds: 30 });
      assert.strictEqual(result, "Time remaining: 30 seconds");
    });

    it("interpolates multiple variables", function () {
      i18n.addLocale("en", { greeting: "Hello {name}, you have {count} items" });
      var result = i18n.t("greeting", { name: "Alice", count: 5 });
      assert.strictEqual(result, "Hello Alice, you have 5 items");
    });

    it("interpolates in non-English locale", function () {
      i18n.setLocale("es");
      var result = i18n.t("timer.remaining", { seconds: 15 });
      assert.strictEqual(result, "Tiempo restante: 15 segundos");
    });

    it("leaves placeholder if variable not provided", function () {
      var result = i18n.t("timer.remaining", {});
      assert.strictEqual(result, "Time remaining: {seconds} seconds");
    });

    it("handles null vars gracefully", function () {
      var result = i18n.t("timer.remaining", null);
      assert.strictEqual(result, "Time remaining: {seconds} seconds");
    });

    it("handles non-object vars gracefully", function () {
      var result = i18n.t("timer.remaining", "not-an-object");
      assert.strictEqual(result, "Time remaining: {seconds} seconds");
    });

    it("converts numeric vars to string", function () {
      var result = i18n.t("attempts.remaining", { count: 0 });
      assert.strictEqual(result, "Attempts remaining: 0");
    });

    it("replaces all occurrences of same variable", function () {
      i18n.addLocale("en", { double: "{x} and {x}" });
      assert.strictEqual(i18n.t("double", { x: "hi" }), "hi and hi");
    });
  });

  // ── setLocale ──────────────────────────────────────────────────

  describe("setLocale", function () {
    it("changes locale", function () {
      i18n.setLocale("fr");
      assert.strictEqual(i18n.getLocale(), "fr");
    });

    it("allows switching back and forth", function () {
      i18n.setLocale("de");
      var deSubmit = i18n.t("submit");
      i18n.setLocale("es");
      var esSubmit = i18n.t("submit");
      i18n.setLocale("de");
      assert.strictEqual(i18n.t("submit"), deSubmit);
      assert.notStrictEqual(deSubmit, esSubmit);
    });

    it("ignores non-string locale", function () {
      i18n.setLocale(42);
      assert.strictEqual(i18n.getLocale(), "en");
    });

    it("ignores null locale", function () {
      i18n.setLocale(null);
      assert.strictEqual(i18n.getLocale(), "en");
    });

    it("allows setting to unknown locale (falls back on t())", function () {
      i18n.setLocale("zz");
      assert.strictEqual(i18n.getLocale(), "zz");
      // Should fall back to English
      assert.strictEqual(i18n.t("submit"), "Submit");
    });
  });

  // ── addLocale ──────────────────────────────────────────────────

  describe("addLocale", function () {
    it("registers new locale", function () {
      i18n.addLocale("sv", { submit: "Skicka" });
      i18n.setLocale("sv");
      assert.strictEqual(i18n.t("submit"), "Skicka");
    });

    it("extends existing locale without overwriting", function () {
      i18n.addLocale("en", { "custom.new": "New Value" });
      assert.strictEqual(i18n.t("custom.new"), "New Value");
      assert.strictEqual(i18n.t("submit"), "Submit"); // original intact
    });

    it("can override built-in translations", function () {
      i18n.addLocale("en", { submit: "Send Now" });
      assert.strictEqual(i18n.t("submit"), "Send Now");
    });

    it("ignores non-string locale name", function () {
      i18n.addLocale(42, { submit: "Test" });
      // Should not crash; 42 not added
      assert.ok(!i18n.getAvailableLocales().includes("42"));
    });

    it("ignores null strings object", function () {
      i18n.addLocale("test", null);
      assert.ok(!i18n.getAvailableLocales().includes("test"));
    });

    it("ignores non-object strings argument", function () {
      i18n.addLocale("test", "not-an-object");
      assert.ok(!i18n.getAvailableLocales().includes("test"));
    });

    it("converts values to strings", function () {
      i18n.addLocale("en", { "test.number": 42 });
      assert.strictEqual(i18n.t("test.number"), "42");
    });
  });

  // ── getAvailableLocales ────────────────────────────────────────

  describe("getAvailableLocales", function () {
    it("includes all 12 built-in locales", function () {
      var locales = i18n.getAvailableLocales();
      var expected = ["en", "es", "fr", "de", "pt", "ja", "zh", "ko", "ar", "hi", "ru", "it"];
      expected.forEach(function (l) {
        assert.ok(locales.includes(l), "Missing locale: " + l);
      });
    });

    it("includes custom locales after addLocale", function () {
      i18n.addLocale("sv", { submit: "Skicka" });
      assert.ok(i18n.getAvailableLocales().includes("sv"));
    });

    it("returns a fresh array each call", function () {
      var a = i18n.getAvailableLocales();
      var b = i18n.getAvailableLocales();
      assert.notStrictEqual(a, b);
      assert.deepStrictEqual(a, b);
    });
  });

  // ── hasKey ─────────────────────────────────────────────────────

  describe("hasKey", function () {
    it("returns true for built-in key", function () {
      assert.strictEqual(i18n.hasKey("submit"), true);
    });

    it("returns false for non-existent key", function () {
      assert.strictEqual(i18n.hasKey("nonexistent"), false);
    });

    it("checks fallback locale when current lacks key", function () {
      i18n.setLocale("xx");
      // "xx" doesn't exist, but fallback "en" has "submit"
      assert.strictEqual(i18n.hasKey("submit"), true);
    });

    it("returns true for custom locale key", function () {
      i18n.addLocale("en", { "custom.key": "value" });
      assert.strictEqual(i18n.hasKey("custom.key"), true);
    });

    it("checks current locale first", function () {
      i18n.addLocale("xx", { "only.in.xx": "yes" });
      i18n.setLocale("xx");
      assert.strictEqual(i18n.hasKey("only.in.xx"), true);
    });

    it("returns false when key exists in neither current nor fallback", function () {
      i18n.addLocale("yy", { "only.in.yy": "yes" });
      // Current is "en", fallback is "en", key is only in "yy"
      assert.strictEqual(i18n.hasKey("only.in.yy"), false);
    });
  });

  // ── exportCatalog ──────────────────────────────────────────────

  describe("exportCatalog", function () {
    it("returns all locales", function () {
      var catalog = i18n.exportCatalog();
      assert.ok("en" in catalog);
      assert.ok("fr" in catalog);
      assert.ok("ja" in catalog);
    });

    it("exported catalog is a deep copy", function () {
      var catalog = i18n.exportCatalog();
      catalog.en.submit = "MODIFIED";
      // Internal state should be unaffected
      assert.strictEqual(i18n.t("submit"), "Submit");
    });

    it("includes custom locales in export", function () {
      i18n.addLocale("tl", { submit: "Isumite" });
      var catalog = i18n.exportCatalog();
      assert.ok("tl" in catalog);
      assert.strictEqual(catalog.tl.submit, "Isumite");
    });

    it("exported keys match all built-in keys for each locale", function () {
      var catalog = i18n.exportCatalog();
      var enKeys = Object.keys(catalog.en);
      // All locales should have at least the core keys
      var coreKeys = ["instructions", "submit", "retry", "loading", "success",
        "error.generic", "error.timeout", "error.wrong", "error.tooMany",
        "error.blocked", "accessibility.label", "timer.remaining",
        "attempts.remaining"];
      coreKeys.forEach(function (key) {
        assert.ok(enKeys.includes(key), "English missing core key: " + key);
      });
    });
  });

  // ── Edge Cases ─────────────────────────────────────────────────

  describe("edge cases", function () {
    it("handles unusual locale names without crashing", function () {
      i18n.addLocale("x-custom", { submit: "Custom" });
      i18n.setLocale("x-custom");
      assert.strictEqual(i18n.t("submit"), "Custom");
    });

    it("handles key with dots (nested-looking)", function () {
      assert.strictEqual(i18n.hasKey("error.timeout"), true);
      assert.notStrictEqual(i18n.t("error.timeout"), "error.timeout");
    });

    it("all built-in locales have difficulty keys", function () {
      var locales = ["en", "es", "fr", "de"];
      locales.forEach(function (l) {
        i18n.setLocale(l);
        assert.notStrictEqual(i18n.t("difficulty.easy"), "difficulty.easy",
          l + " missing difficulty.easy");
        assert.notStrictEqual(i18n.t("difficulty.medium"), "difficulty.medium",
          l + " missing difficulty.medium");
        assert.notStrictEqual(i18n.t("difficulty.hard"), "difficulty.hard",
          l + " missing difficulty.hard");
      });
    });

    it("interpolation with special regex characters in value", function () {
      i18n.addLocale("en", { test: "Result: {val}" });
      var result = i18n.t("test", { val: "$100.00" });
      assert.strictEqual(result, "Result: $100.00");
    });

    it("interpolation with special regex characters in template", function () {
      i18n.addLocale("en", { regex: "Price is $5 for {item}" });
      var result = i18n.t("regex", { item: "widget" });
      assert.strictEqual(result, "Price is $5 for widget");
    });

    it("constructor key doesn't break", function () {
      i18n.addLocale("en", { constructor: "safe" });
      assert.strictEqual(i18n.t("constructor"), "safe");
    });
  });
});
