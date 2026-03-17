/**
 * competitive.test.js — Tests for the Competitive Analysis page data integrity.
 */

"use strict";

// ── Inline data for validation (mirrors competitive.html) ──

var PROVIDER_IDS = ['gif-captcha', 'recaptcha-v3', 'hcaptcha', 'turnstile', 'friendly-captcha', 'mtcaptcha'];

var DIMENSION_IDS = [
    'botResistance', 'aiResistance', 'replayProtection', 'accessibility',
    'solveSpeed', 'userFriction', 'noTracking', 'gdprCompliance',
    'selfHostable', 'customization', 'documentation', 'openSource'
];

var SCORES = {
    'gif-captcha':      { botResistance: 7, aiResistance: 8, replayProtection: 7, accessibility: 8, solveSpeed: 7, userFriction: 7, noTracking: 10, gdprCompliance: 10, selfHostable: 10, customization: 9, documentation: 7, openSource: 10 },
    'recaptcha-v3':     { botResistance: 9, aiResistance: 8, replayProtection: 9, accessibility: 6, solveSpeed: 9, userFriction: 9, noTracking: 2, gdprCompliance: 5, selfHostable: 0, customization: 3, documentation: 9, openSource: 0 },
    'hcaptcha':         { botResistance: 8, aiResistance: 7, replayProtection: 8, accessibility: 7, solveSpeed: 6, userFriction: 6, noTracking: 6, gdprCompliance: 7, selfHostable: 0, customization: 5, documentation: 8, openSource: 0 },
    'turnstile':        { botResistance: 8, aiResistance: 7, replayProtection: 9, accessibility: 8, solveSpeed: 10, userFriction: 10, noTracking: 5, gdprCompliance: 7, selfHostable: 0, customization: 4, documentation: 8, openSource: 0 },
    'friendly-captcha': { botResistance: 6, aiResistance: 5, replayProtection: 7, accessibility: 9, solveSpeed: 8, userFriction: 9, noTracking: 8, gdprCompliance: 9, selfHostable: 0, customization: 5, documentation: 7, openSource: 3 },
    'mtcaptcha':        { botResistance: 7, aiResistance: 6, replayProtection: 7, accessibility: 7, solveSpeed: 7, userFriction: 7, noTracking: 7, gdprCompliance: 8, selfHostable: 0, customization: 6, documentation: 6, openSource: 0 }
};

var FEATURES = [
    'Invisible Mode', 'Visual Challenge', 'Proof-of-Work', 'Self-Hosted',
    'No Third-Party JS', 'GDPR-Safe by Default', 'Custom Challenges',
    'Audio Fallback', 'Analytics Dashboard', 'Open Source',
    'Rate Limiting Built-in', 'Enterprise Support'
];

// ── Tests ──

describe('Competitive Analysis Data', function () {
    test('all providers have score entries', function () {
        PROVIDER_IDS.forEach(function (id) {
            expect(SCORES).toHaveProperty(id);
        });
    });

    test('all scores are within 0-10 range', function () {
        PROVIDER_IDS.forEach(function (pid) {
            DIMENSION_IDS.forEach(function (did) {
                var val = SCORES[pid][did];
                expect(val).toBeGreaterThanOrEqual(0);
                expect(val).toBeLessThanOrEqual(10);
            });
        });
    });

    test('every provider has all dimension scores', function () {
        PROVIDER_IDS.forEach(function (pid) {
            DIMENSION_IDS.forEach(function (did) {
                expect(typeof SCORES[pid][did]).toBe('number');
            });
        });
    });

    test('gif-captcha is the only fully self-hostable provider', function () {
        expect(SCORES['gif-captcha'].selfHostable).toBe(10);
        PROVIDER_IDS.filter(function (id) { return id !== 'gif-captcha'; }).forEach(function (id) {
            expect(SCORES[id].selfHostable).toBe(0);
        });
    });

    test('gif-captcha has perfect privacy scores', function () {
        expect(SCORES['gif-captcha'].noTracking).toBe(10);
        expect(SCORES['gif-captcha'].gdprCompliance).toBe(10);
        expect(SCORES['gif-captcha'].openSource).toBe(10);
    });

    test('feature count is 12', function () {
        expect(FEATURES.length).toBe(12);
    });

    test('dimension count is 12', function () {
        expect(DIMENSION_IDS.length).toBe(12);
    });

    test('provider count is 6', function () {
        expect(PROVIDER_IDS.length).toBe(6);
    });

    test('average scores are computable for all providers', function () {
        PROVIDER_IDS.forEach(function (pid) {
            var total = 0;
            DIMENSION_IDS.forEach(function (did) { total += SCORES[pid][did]; });
            var avg = total / DIMENSION_IDS.length;
            expect(avg).toBeGreaterThan(0);
            expect(avg).toBeLessThanOrEqual(10);
        });
    });

    test('gif-captcha ranks highest in privacy composite', function () {
        var privacyDims = ['noTracking', 'gdprCompliance', 'selfHostable', 'openSource'];
        function privacyScore(pid) {
            var t = 0;
            privacyDims.forEach(function (d) { t += SCORES[pid][d]; });
            return t;
        }
        var gifPrivacy = privacyScore('gif-captcha');
        PROVIDER_IDS.filter(function (id) { return id !== 'gif-captcha'; }).forEach(function (id) {
            expect(gifPrivacy).toBeGreaterThan(privacyScore(id));
        });
    });

    test('no provider has all zeros', function () {
        PROVIDER_IDS.forEach(function (pid) {
            var total = 0;
            DIMENSION_IDS.forEach(function (did) { total += SCORES[pid][did]; });
            expect(total).toBeGreaterThan(0);
        });
    });

    test('scores are integers', function () {
        PROVIDER_IDS.forEach(function (pid) {
            DIMENSION_IDS.forEach(function (did) {
                expect(Number.isInteger(SCORES[pid][did])).toBe(true);
            });
        });
    });

    test('dimension groups cover security, usability, privacy', function () {
        var groups = { security: 0, usability: 0, privacy: 0 };
        var DIMENSIONS = [
            { id: 'botResistance', group: 'security' },
            { id: 'aiResistance', group: 'security' },
            { id: 'replayProtection', group: 'security' },
            { id: 'accessibility', group: 'usability' },
            { id: 'solveSpeed', group: 'usability' },
            { id: 'userFriction', group: 'usability' },
            { id: 'noTracking', group: 'privacy' },
            { id: 'gdprCompliance', group: 'privacy' },
            { id: 'selfHostable', group: 'privacy' },
            { id: 'customization', group: 'usability' },
            { id: 'documentation', group: 'usability' },
            { id: 'openSource', group: 'privacy' }
        ];
        DIMENSIONS.forEach(function (d) { groups[d.group]++; });
        expect(groups.security).toBe(3);
        expect(groups.usability).toBe(5);
        expect(groups.privacy).toBe(4);
    });

    test('turnstile has highest usability composite', function () {
        var usabilityDims = ['accessibility', 'solveSpeed', 'userFriction', 'customization', 'documentation'];
        function usabilityScore(pid) {
            var t = 0;
            usabilityDims.forEach(function (d) { t += SCORES[pid][d]; });
            return t;
        }
        var ts = usabilityScore('turnstile');
        PROVIDER_IDS.filter(function (id) { return id !== 'turnstile'; }).forEach(function (id) {
            expect(ts).toBeGreaterThanOrEqual(usabilityScore(id));
        });
    });
});
