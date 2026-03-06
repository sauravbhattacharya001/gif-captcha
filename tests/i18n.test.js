"use strict";

var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var { createI18n } = require("../src/index");

describe("createI18n", function () {
  it("returns English by default", function () {
    var i18n = createI18n();
    assert.equal(i18n.t("submit"), "Submit");
    assert.equal(i18n.getLocale(), "en");
  });

  it("translates to specified locale", function () {
    var i18n = createI18n({ locale: "es" });
    assert.equal(i18n.t("submit"), "Enviar");
    assert.equal(i18n.t("success"), "¡Verificación exitosa!");
  });

  it("falls back to English for missing keys", function () {
    var i18n = createI18n({ locale: "pt" });
    assert.equal(i18n.t("instructions.audio"), "Listen to the audio and type what you hear.");
  });

  it("returns key itself when not found in any locale", function () {
    var i18n = createI18n();
    assert.equal(i18n.t("nonexistent.key"), "nonexistent.key");
  });

  it("interpolates variables", function () {
    var i18n = createI18n();
    assert.equal(i18n.t("timer.remaining", { seconds: 30 }), "Time remaining: 30 seconds");
    assert.equal(i18n.t("attempts.remaining", { count: 3 }), "Attempts remaining: 3");
  });

  it("interpolates in non-English locales", function () {
    var i18n = createI18n({ locale: "ja" });
    assert.equal(i18n.t("timer.remaining", { seconds: 15 }), "残り時間: 15秒");
  });

  it("setLocale changes active locale", function () {
    var i18n = createI18n();
    assert.equal(i18n.t("submit"), "Submit");
    i18n.setLocale("fr");
    assert.equal(i18n.t("submit"), "Soumettre");
    assert.equal(i18n.getLocale(), "fr");
  });

  it("addLocale registers new locale", function () {
    var i18n = createI18n();
    i18n.addLocale("th", { submit: "ส่ง", retry: "ลองอีกครั้ง" });
    i18n.setLocale("th");
    assert.equal(i18n.t("submit"), "ส่ง");
    assert.equal(i18n.t("success"), "Verification successful!");
  });

  it("addLocale extends existing locale", function () {
    var i18n = createI18n();
    i18n.addLocale("en", { "custom.key": "Custom Value" });
    assert.equal(i18n.t("custom.key"), "Custom Value");
    assert.equal(i18n.t("submit"), "Submit");
  });

  it("getAvailableLocales lists all locales", function () {
    var i18n = createI18n();
    var locales = i18n.getAvailableLocales();
    assert.ok(locales.includes("en"));
    assert.ok(locales.includes("es"));
    assert.ok(locales.includes("ja"));
    assert.ok(locales.includes("ar"));
    assert.ok(locales.length >= 12);
  });

  it("hasKey checks current and fallback locale", function () {
    var i18n = createI18n({ locale: "pt" });
    assert.ok(i18n.hasKey("submit"));
    assert.ok(i18n.hasKey("instructions.audio"));
    assert.ok(!i18n.hasKey("nonexistent"));
  });

  it("exportCatalog returns all translations", function () {
    var i18n = createI18n();
    var catalog = i18n.exportCatalog();
    assert.equal(typeof catalog.en, "object");
    assert.equal(catalog.en.submit, "Submit");
    assert.equal(catalog.de.submit, "Absenden");
  });

  it("accepts custom locales via options", function () {
    var i18n = createI18n({
      locale: "sv",
      locales: { sv: { submit: "Skicka", retry: "Försök igen" } }
    });
    assert.equal(i18n.t("submit"), "Skicka");
    assert.ok(i18n.getAvailableLocales().includes("sv"));
  });

  it("all 12 built-in locales have core keys", function () {
    var i18n = createI18n();
    var coreKeys = ["instructions", "submit", "retry", "success", "error.timeout"];
    var locales = ["en", "es", "fr", "de", "pt", "ja", "zh", "ko", "ar", "hi", "ru", "it"];
    for (var i = 0; i < locales.length; i++) {
      i18n.setLocale(locales[i]);
      for (var j = 0; j < coreKeys.length; j++) {
        assert.ok(i18n.hasKey(coreKeys[j]), locales[i] + " missing " + coreKeys[j]);
      }
    }
  });
});
