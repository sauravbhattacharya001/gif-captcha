/**
 * Tests for the A/B Testing Configurator module.
 *
 * Validates sample size calculations, normal quantile approximation,
 * CAPTCHA profile data, comparison logic, and verdict generation.
 */

// ── Module (extracted for testing) ──
function createABTestCalculator() {
    // Approximation of the standard normal inverse CDF
    function normalQuantile(p) {
        if (p <= 0) return -Infinity;
        if (p >= 1) return Infinity;
        if (p === 0.5) return 0;
        var sign = p < 0.5 ? -1 : 1;
        var t = p < 0.5 ? p : 1 - p;
        t = Math.sqrt(-2 * Math.log(t));
        var c0 = 2.515517, c1 = 0.802853, c2 = 0.010328;
        var d1 = 1.432788, d2 = 0.189269, d3 = 0.001308;
        return sign * (t - (c0 + c1 * t + c2 * t * t) /
               (1 + d1 * t + d2 * t * t + d3 * t * t * t));
    }

    // Sample size for two-proportion z-test
    function calcSampleSize(p1, p2, alpha, beta) {
        var za = normalQuantile(1 - alpha / 2);
        var zb = normalQuantile(beta);
        var pBar = (p1 + p2) / 2;
        var num = Math.pow(za * Math.sqrt(2 * pBar * (1 - pBar)) +
                   zb * Math.sqrt(p1 * (1 - p1) + p2 * (1 - p2)), 2);
        var denom = Math.pow(p1 - p2, 2);
        return Math.ceil(num / denom);
    }

    // Composite score for CAPTCHA type
    function compositeScore(profile) {
        return profile.botBlockRate * 0.4 + profile.humanPassRate * 0.2 +
               (1 - profile.dropoffRate) * 0.25 + profile.accessibilityScore * 0.15;
    }

    // Duration estimate
    function estimateDuration(perGroup, dailyTraffic, splitRatio) {
        var minGroupTraffic = dailyTraffic * Math.min(splitRatio, 1 - splitRatio);
        return Math.ceil(perGroup / minGroupTraffic);
    }

    // Format duration
    function formatDuration(days) {
        if (days <= 1) return '1 day';
        if (days < 7) return days + ' days';
        var weeks = Math.ceil(days / 7);
        return days + ' days (~' + weeks + ' week' + (weeks === 1 ? '' : 's') + ')';
    }

    // Adjusted conversion rate
    function adjustedConversion(baseCR, dropoffRate) {
        return baseCR * (1 - dropoffRate);
    }

    return {
        normalQuantile: normalQuantile,
        calcSampleSize: calcSampleSize,
        compositeScore: compositeScore,
        estimateDuration: estimateDuration,
        formatDuration: formatDuration,
        adjustedConversion: adjustedConversion
    };
}

if (typeof module !== 'undefined') module.exports = { createABTestCalculator: createABTestCalculator };


// ── Tests ──

describe('createABTestCalculator', function() {
    var calc;

    beforeEach(function() {
        calc = createABTestCalculator();
    });

    // ── normalQuantile ──

    describe('normalQuantile', function() {
        test('returns 0 for p=0.5', function() {
            expect(calc.normalQuantile(0.5)).toBe(0);
        });

        test('returns -Infinity for p=0', function() {
            expect(calc.normalQuantile(0)).toBe(-Infinity);
        });

        test('returns Infinity for p=1', function() {
            expect(calc.normalQuantile(1)).toBe(Infinity);
        });

        test('p=0.975 ≈ 1.96 (for 95% CI)', function() {
            expect(calc.normalQuantile(0.975)).toBeCloseTo(1.96, 1);
        });

        test('p=0.995 ≈ 2.576 (for 99% CI)', function() {
            expect(calc.normalQuantile(0.995)).toBeCloseTo(2.576, 1);
        });

        test('p=0.95 ≈ 1.645 (one-sided 95%)', function() {
            expect(calc.normalQuantile(0.95)).toBeCloseTo(1.645, 1);
        });

        test('p=0.025 ≈ -1.96 (symmetric)', function() {
            expect(calc.normalQuantile(0.025)).toBeCloseTo(-1.96, 1);
        });

        test('symmetry: q(p) = -q(1-p)', function() {
            var p = 0.8;
            expect(calc.normalQuantile(p) + calc.normalQuantile(1 - p)).toBeCloseTo(0, 5);
        });

        test('monotonically increasing', function() {
            var vals = [0.1, 0.3, 0.5, 0.7, 0.9];
            for (var i = 1; i < vals.length; i++) {
                expect(calc.normalQuantile(vals[i])).toBeGreaterThan(calc.normalQuantile(vals[i-1]));
            }
        });
    });

    // ── calcSampleSize ──

    describe('calcSampleSize', function() {
        test('returns positive integer', function() {
            var n = calc.calcSampleSize(0.035, 0.0385, 0.05, 0.80);
            expect(n).toBeGreaterThan(0);
            expect(Number.isInteger(n)).toBe(true);
        });

        test('higher confidence requires more samples', function() {
            var n95 = calc.calcSampleSize(0.05, 0.06, 0.05, 0.80);
            var n99 = calc.calcSampleSize(0.05, 0.06, 0.01, 0.80);
            expect(n99).toBeGreaterThan(n95);
        });

        test('higher power requires more samples', function() {
            var n80 = calc.calcSampleSize(0.05, 0.06, 0.05, 0.80);
            var n90 = calc.calcSampleSize(0.05, 0.06, 0.05, 0.90);
            expect(n90).toBeGreaterThan(n80);
        });

        test('smaller effect size requires more samples', function() {
            var nBig = calc.calcSampleSize(0.05, 0.07, 0.05, 0.80);   // 40% relative change
            var nSmall = calc.calcSampleSize(0.05, 0.055, 0.05, 0.80); // 10% relative change
            expect(nSmall).toBeGreaterThan(nBig);
        });

        test('zero difference would give very large sample', function() {
            // p1 very close to p2 — should be huge
            var n = calc.calcSampleSize(0.05, 0.05001, 0.05, 0.80);
            expect(n).toBeGreaterThan(100000);
        });

        test('large effect size needs small sample', function() {
            var n = calc.calcSampleSize(0.10, 0.30, 0.05, 0.80);
            expect(n).toBeLessThan(200);
        });

        test('typical scenario: 3.5% → 3.85% (10% lift)', function() {
            var n = calc.calcSampleSize(0.035, 0.0385, 0.05, 0.80);
            // Should be in a reasonable range (tens of thousands)
            expect(n).toBeGreaterThan(5000);
            expect(n).toBeLessThan(500000);
        });
    });

    // ── compositeScore ──

    describe('compositeScore', function() {
        test('perfect profile scores 1.0', function() {
            var profile = { botBlockRate: 1, humanPassRate: 1, dropoffRate: 0, accessibilityScore: 1 };
            expect(calc.compositeScore(profile)).toBeCloseTo(1.0, 5);
        });

        test('worst profile scores 0.0', function() {
            var profile = { botBlockRate: 0, humanPassRate: 0, dropoffRate: 1, accessibilityScore: 0 };
            // 0*0.4 + 0*0.2 + (1-1)*0.25 + 0*0.15 = 0
            expect(calc.compositeScore(profile)).toBeCloseTo(0, 5);
        });

        test('weights sum correctly (0.4 + 0.2 + 0.25 + 0.15 = 1)', function() {
            // All metrics at 0.5
            var profile = { botBlockRate: 0.5, humanPassRate: 0.5, dropoffRate: 0.5, accessibilityScore: 0.5 };
            var expected = 0.5 * 0.4 + 0.5 * 0.2 + 0.5 * 0.25 + 0.5 * 0.15;
            expect(calc.compositeScore(profile)).toBeCloseTo(expected, 5);
        });

        test('bot block rate has highest weight', function() {
            var base = { botBlockRate: 0.5, humanPassRate: 0.5, dropoffRate: 0.5, accessibilityScore: 0.5 };
            var highBot = Object.assign({}, base, { botBlockRate: 1.0 });
            var highPass = Object.assign({}, base, { humanPassRate: 1.0 });
            expect(calc.compositeScore(highBot) - calc.compositeScore(base))
                .toBeGreaterThan(calc.compositeScore(highPass) - calc.compositeScore(base));
        });

        test('GIF CAPTCHA scores higher than text CAPTCHA', function() {
            var gif = { botBlockRate: 0.97, humanPassRate: 0.92, dropoffRate: 0.08, accessibilityScore: 0.45 };
            var text = { botBlockRate: 0.65, humanPassRate: 0.85, dropoffRate: 0.12, accessibilityScore: 0.30 };
            expect(calc.compositeScore(gif)).toBeGreaterThan(calc.compositeScore(text));
        });
    });

    // ── estimateDuration ──

    describe('estimateDuration', function() {
        test('1000 per group, 500/day = 2 days', function() {
            expect(calc.estimateDuration(1000, 1000, 0.5)).toBe(2);
        });

        test('70/30 split uses smaller group for duration', function() {
            // 1000 traffic, 70/30 split → smallest group gets 300/day
            var d = calc.estimateDuration(1000, 1000, 0.7);
            expect(d).toBe(Math.ceil(1000 / 300));
        });

        test('50/50 split is most efficient', function() {
            var d50 = calc.estimateDuration(1000, 1000, 0.5);
            var d80 = calc.estimateDuration(1000, 1000, 0.8);
            expect(d50).toBeLessThanOrEqual(d80);
        });

        test('higher traffic = shorter duration', function() {
            var d1 = calc.estimateDuration(5000, 1000, 0.5);
            var d2 = calc.estimateDuration(5000, 10000, 0.5);
            expect(d2).toBeLessThan(d1);
        });

        test('returns at least 1 day', function() {
            expect(calc.estimateDuration(1, 1000000, 0.5)).toBe(1);
        });
    });

    // ── formatDuration ──

    describe('formatDuration', function() {
        test('1 day', function() {
            expect(calc.formatDuration(1)).toBe('1 day');
        });

        test('3 days (no weeks)', function() {
            expect(calc.formatDuration(3)).toBe('3 days');
        });

        test('7 days shows weeks', function() {
            expect(calc.formatDuration(7)).toContain('1 week');
        });

        test('14 days shows 2 weeks', function() {
            expect(calc.formatDuration(14)).toContain('2 weeks');
        });

        test('10 days shows 2 weeks (ceiling)', function() {
            expect(calc.formatDuration(10)).toContain('2 weeks');
        });

        test('0 or negative returns 1 day', function() {
            expect(calc.formatDuration(0)).toBe('1 day');
        });
    });

    // ── adjustedConversion ──

    describe('adjustedConversion', function() {
        test('no drop-off returns base CR', function() {
            expect(calc.adjustedConversion(0.05, 0)).toBe(0.05);
        });

        test('10% drop-off reduces CR by 10%', function() {
            expect(calc.adjustedConversion(0.10, 0.10)).toBeCloseTo(0.09, 5);
        });

        test('100% drop-off gives 0 CR', function() {
            expect(calc.adjustedConversion(0.05, 1.0)).toBe(0);
        });

        test('GIF CAPTCHA (8% drop-off) on 3.5% CR', function() {
            var adj = calc.adjustedConversion(0.035, 0.08);
            expect(adj).toBeCloseTo(0.0322, 3);
        });

        test('slider (3% drop-off) is less impactful', function() {
            var gif = calc.adjustedConversion(0.05, 0.08);
            var slider = calc.adjustedConversion(0.05, 0.03);
            expect(slider).toBeGreaterThan(gif);
        });
    });

    // ── Integration: end-to-end scenario ──

    describe('end-to-end', function() {
        test('typical GIF vs text test plan', function() {
            var baseCR = 0.035;
            var gifDropoff = 0.08;
            var textDropoff = 0.12;
            var mdeRel = 0.10;

            var crA = calc.adjustedConversion(baseCR, gifDropoff);
            var crB = crA * (1 + mdeRel);

            var perGroup = calc.calcSampleSize(crA, crB, 0.05, 0.80);
            expect(perGroup).toBeGreaterThan(0);

            var days = calc.estimateDuration(perGroup, 1000, 0.5);
            expect(days).toBeGreaterThan(0);

            var duration = calc.formatDuration(days);
            expect(typeof duration).toBe('string');
        });

        test('high-traffic site needs fewer days', function() {
            var p1 = 0.05;
            var p2 = 0.055;
            var n = calc.calcSampleSize(p1, p2, 0.05, 0.80);

            var daysLow = calc.estimateDuration(n, 100, 0.5);
            var daysHigh = calc.estimateDuration(n, 100000, 0.5);

            expect(daysHigh).toBeLessThan(daysLow);
        });

        test('invisible vs GIF: invisible has higher composite', function() {
            var invisible = { botBlockRate: 0.82, humanPassRate: 0.99, dropoffRate: 0.01, accessibilityScore: 0.95 };
            var gif = { botBlockRate: 0.97, humanPassRate: 0.92, dropoffRate: 0.08, accessibilityScore: 0.45 };

            var iScore = calc.compositeScore(invisible);
            var gScore = calc.compositeScore(gif);

            // Invisible wins on UX/accessibility despite lower bot block
            // Actually let's compute: invisible = 0.82*0.4 + 0.99*0.2 + 0.99*0.25 + 0.95*0.15 = 0.328+0.198+0.2475+0.1425 = 0.916
            // GIF = 0.97*0.4 + 0.92*0.2 + 0.92*0.25 + 0.45*0.15 = 0.388+0.184+0.23+0.0675 = 0.8695
            expect(iScore).toBeGreaterThan(gScore);
        });
    });
});
