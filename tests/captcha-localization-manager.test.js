"use strict";

var assert = require('assert');
var _mod = require('../src/captcha-localization-manager');
var createCaptchaLocalizationManager = _mod.createCaptchaLocalizationManager;

describe('CaptchaLocalizationManager', function () {

  // ── Construction ────────────────────────────────────────────────

  it('should create with defaults', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.ok(mgr);
    assert.strictEqual(typeof mgr.t, 'function');
  });

  it('should accept custom default locale', function () {
    var mgr = createCaptchaLocalizationManager({ defaultLocale: 'es' });
    var result = mgr.t('ui.submit');
    assert.strictEqual(result, 'Enviar');
  });

  it('should merge user translations at construction', function () {
    var mgr = createCaptchaLocalizationManager({
      translations: { en: { 'custom.key': 'Hello' } }
    });
    assert.strictEqual(mgr.t('custom.key'), 'Hello');
  });

  // ── Basic translation ──────────────────────────────────────────

  it('should translate English keys', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.t('ui.submit'), 'Submit');
    assert.strictEqual(mgr.t('success.verified'), 'Verification successful!');
  });

  it('should translate to specified locale', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.t('ui.submit', { locale: 'fr' }), 'Soumettre');
    assert.strictEqual(mgr.t('ui.submit', { locale: 'de' }), 'Absenden');
    assert.strictEqual(mgr.t('ui.submit', { locale: 'ja' }), '送信');
  });

  it('should return key if translation not found', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.t('nonexistent.key'), 'nonexistent.key');
  });

  // ── Interpolation ─────────────────────────────────────────────

  it('should interpolate variables', function () {
    var mgr = createCaptchaLocalizationManager();
    var result = mgr.t('challenge.click_shape', { color: 'red', shape: 'circle' });
    assert.strictEqual(result, 'Click the red circle');
  });

  it('should interpolate with vars object', function () {
    var mgr = createCaptchaLocalizationManager();
    var result = mgr.t('error.too_many_attempts', { vars: { seconds: 30 } });
    assert.strictEqual(result, 'Too many attempts. Please wait 30 seconds.');
  });

  it('should keep placeholder if var not provided', function () {
    var mgr = createCaptchaLocalizationManager();
    var result = mgr.t('challenge.click_shape', { color: 'blue' });
    assert.ok(result.indexOf('blue') >= 0);
    assert.ok(result.indexOf('{{shape}}') >= 0);
  });

  // ── Pluralization ─────────────────────────────────────────────

  it('should handle English pluralization', function () {
    var mgr = createCaptchaLocalizationManager();
    var one = mgr.t('plural.object', { count: 1 });
    var many = mgr.t('plural.object', { count: 5 });
    assert.strictEqual(one, '1 object');
    assert.strictEqual(many, '5 objects');
  });

  it('should handle Russian pluralization (3 forms)', function () {
    var mgr = createCaptchaLocalizationManager();
    var one = mgr.t('plural.object', { locale: 'ru', count: 1 });
    var few = mgr.t('plural.object', { locale: 'ru', count: 3 });
    var many = mgr.t('plural.object', { locale: 'ru', count: 5 });
    assert.strictEqual(one, '1 объект');
    assert.strictEqual(few, '3 объекта');
    assert.strictEqual(many, '5 объектов');
  });

  it('should handle Japanese (no plural)', function () {
    var mgr = createCaptchaLocalizationManager();
    var one = mgr.t('plural.object', { locale: 'ja', count: 1 });
    var many = mgr.t('plural.object', { locale: 'ja', count: 99 });
    assert.strictEqual(one, '1個');
    assert.strictEqual(many, '99個');
  });

  // ── Locale detection ──────────────────────────────────────────

  it('should detect locale from Accept-Language header', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.detectLocale('fr-FR,fr;q=0.9,en;q=0.5'), 'fr');
    assert.strictEqual(mgr.detectLocale('de-DE,de;q=0.9'), 'de');
    assert.strictEqual(mgr.detectLocale('ja'), 'ja');
  });

  it('should fall back to default for unsupported locale', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.detectLocale('xx-XX'), 'en');
  });

  it('should handle empty Accept-Language', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.detectLocale(''), 'en');
    assert.strictEqual(mgr.detectLocale(null), 'en');
  });

  // ── Fallback chains ───────────────────────────────────────────

  it('should build fallback chain for regional locale', function () {
    var mgr = createCaptchaLocalizationManager();
    var chain = mgr.buildFallbackChain('pt-BR');
    assert.ok(chain.indexOf('pt-br') >= 0);
    assert.ok(chain.indexOf('pt') >= 0);
    assert.ok(chain.indexOf('en') >= 0);
  });

  it('should fall back from unsupported regional to base', function () {
    var mgr = createCaptchaLocalizationManager();
    var result = mgr.t('ui.submit', { locale: 'es-MX' });
    assert.strictEqual(result, 'Enviar');  // Falls back to 'es'
  });

  // ── RTL detection ─────────────────────────────────────────────

  it('should detect RTL locales', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.isRTL('ar'), true);
    assert.strictEqual(mgr.isRTL('en'), false);
    assert.strictEqual(mgr.isRTL('fr'), false);
  });

  it('should return correct direction', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.getDirection('ar'), 'rtl');
    assert.strictEqual(mgr.getDirection('en'), 'ltr');
  });

  // ── Management API ────────────────────────────────────────────

  it('should add translations at runtime', function () {
    var mgr = createCaptchaLocalizationManager();
    mgr.addTranslations('sv', { 'ui.submit': 'Skicka' });
    assert.strictEqual(mgr.t('ui.submit', { locale: 'sv' }), 'Skicka');
    assert.ok(mgr.getLocales().indexOf('sv') >= 0);
  });

  it('should remove a locale', function () {
    var mgr = createCaptchaLocalizationManager();
    mgr.removeLocale('it');
    assert.ok(mgr.getLocales().indexOf('it') < 0);
  });

  it('should not allow removing en', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.throws(function () { mgr.removeLocale('en'); });
  });

  it('should add custom plural rule', function () {
    var mgr = createCaptchaLocalizationManager();
    mgr.addTranslations('test', { 'plural.item': 'zero|one|many' });
    mgr.addPluralRule('test', function (n) { return n === 0 ? 0 : n === 1 ? 1 : 2; });
    assert.strictEqual(mgr.t('plural.item', { locale: 'test', count: 0 }), 'zero');
    assert.strictEqual(mgr.t('plural.item', { locale: 'test', count: 1 }), 'one');
    assert.strictEqual(mgr.t('plural.item', { locale: 'test', count: 7 }), 'many');
  });

  // ── Coverage report ───────────────────────────────────────────

  it('should generate coverage report', function () {
    var mgr = createCaptchaLocalizationManager();
    var report = mgr.coverageReport();
    assert.ok(report.totalKeys > 0);
    assert.strictEqual(report.locales.en.coverage, 100);
    assert.ok(report.locales.fr.coverage > 0);
  });

  it('should show missing keys for partial locales', function () {
    var mgr = createCaptchaLocalizationManager();
    mgr.addTranslations('xx', { 'ui.submit': 'X' });
    var report = mgr.coverageReport();
    assert.ok(report.locales.xx.missing.length > 0);
    assert.ok(report.locales.xx.coverage < 100);
  });

  // ── Translate all ─────────────────────────────────────────────

  it('should translate all keys for a locale', function () {
    var mgr = createCaptchaLocalizationManager();
    var all = mgr.translateAll('es');
    assert.strictEqual(all['ui.submit'], 'Enviar');
    assert.ok(Object.keys(all).length > 10);
  });

  // ── Normalize locale ──────────────────────────────────────────

  it('should normalize locale strings', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.normalizeLocale('EN_US'), 'en-us');
    assert.strictEqual(mgr.normalizeLocale('fr-FR'), 'fr-fr');
    assert.strictEqual(mgr.normalizeLocale(null), 'en');
  });

  // ── All 12 built-in locales ───────────────────────────────────

  it('should have 12 built-in locales', function () {
    var mgr = createCaptchaLocalizationManager();
    var locales = mgr.getLocales();
    assert.ok(locales.length >= 12);
    ['en', 'es', 'fr', 'de', 'pt', 'it', 'ja', 'ko', 'zh', 'ar', 'hi', 'ru'].forEach(function (l) {
      assert.ok(locales.indexOf(l) >= 0, 'Missing locale: ' + l);
    });
  });

  // ── Edge cases ────────────────────────────────────────────────

  it('should handle translate alias', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.strictEqual(mgr.translate('ui.submit'), mgr.t('ui.submit'));
  });

  it('should throw on invalid addTranslations args', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.throws(function () { mgr.addTranslations('', {}); });
    assert.throws(function () { mgr.addTranslations('en', null); });
  });

  it('should throw on invalid plural rule', function () {
    var mgr = createCaptchaLocalizationManager();
    assert.throws(function () { mgr.addPluralRule('en', 'not a function'); });
  });
});
