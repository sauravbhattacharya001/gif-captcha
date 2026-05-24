/* Regression tests for the cached-word-set / smaller-side-iteration
 * optimization of createSetAnalyzer's Jaccard similarity (run 4448).
 *
 * The optimization changed the shape of the cached entries returned by the
 * internal _getWordSets() from a bare hash {word:true} to {lookup, keys, size},
 * and switched _jaccardSets() to iterate the *smaller* set's keys against the
 * *larger* set's lookup. These tests pin down the externally observable
 * behavior so a future refactor cannot silently regress correctness.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const gifCaptcha = require("../src/index.js");

function ch(id, title, answer) {
  return {
    id: id,
    title: title,
    gifUrl: "x.gif",
    sourceUrl: "#",
    humanAnswer: answer,
    aiAnswer: "",
    keywords: [],
  };
}

describe("createSetAnalyzer: Jaccard similarity (perf-cache regression)", () => {
  it("computes identical similarity matrix regardless of pair ordering (symmetry)", () => {
    const a = ch("a", "A", "a b c d e f");
    const b = ch("b", "B", "a b x y");
    const c = ch("c", "C", "a b c");
    const analyzer = gifCaptcha.createSetAnalyzer([a, b, c]);

    // findSimilarPairs uses the full pairwise matrix; pull every score out.
    const pairs = analyzer.findSimilarPairs(0);
    const map = new Map();
    pairs.forEach((p) => {
      map.set(p.idA + "|" + p.idB, p.similarity);
      // also store the reversed key
      map.set(p.idB + "|" + p.idA, p.similarity);
    });

    // Manually verify Jaccard for each pair using set semantics.
    const tokenize = (s) => new Set(s.toLowerCase().split(/\s+/).filter(Boolean));
    const jaccard = (s1, s2) => {
      const A = tokenize(s1);
      const B = tokenize(s2);
      let inter = 0;
      A.forEach((w) => { if (B.has(w)) inter++; });
      const union = A.size + B.size - inter;
      return union === 0 ? 0 : inter / union;
    };

    assert.equal(map.get("a|b"), jaccard(a.humanAnswer, b.humanAnswer));
    assert.equal(map.get("a|c"), jaccard(a.humanAnswer, c.humanAnswer));
    assert.equal(map.get("b|c"), jaccard(b.humanAnswer, c.humanAnswer));
    // Symmetry: (a,b) and (b,a) must yield the same value.
    assert.equal(map.get("a|b"), map.get("b|a"));
  });

  it("handles lopsided pairs (1-word vs 50-word answers) without NaN/Infinity", () => {
    const tiny = ch("tiny", "Tiny", "cat");
    const huge = ch("huge", "Huge",
      "the quick brown fox jumps over the lazy dog under a bright " +
      "summer sky filled with cumulus clouds while a cat watches " +
      "from the window of a small wooden cabin nestled in the hills " +
      "surrounded by pine trees and wildflowers in the meadow"
    );

    const analyzer = gifCaptcha.createSetAnalyzer([tiny, huge]);
    const pairs = analyzer.findSimilarPairs(0);
    assert.equal(pairs.length, 1);
    const sim = pairs[0].similarity;
    assert.ok(Number.isFinite(sim), "similarity must be finite");
    assert.ok(sim > 0 && sim < 1, "similarity must be in (0,1) for overlapping sets");
    // tiny has 1 unique word ("cat"); huge has "cat" plus many more.
    // |intersection| = 1, |union| = |huge unique words|.
    // Just sanity-check it's small (well below the 0.6 default threshold).
    assert.ok(sim < 0.1, "lopsided pair similarity should be small: got " + sim);
  });

  it("treats empty-answer challenges as similarity 0 with everything", () => {
    // Empty/whitespace humanAnswer => empty word set => 0 intersection.
    // We construct the empty-answer challenge AFTER createChallenge would
    // normally guard, so go through the analyzer directly.
    const empty = ch("e", "Empty", "   ");
    const real = ch("r", "Real", "a cat on a mat");

    const analyzer = gifCaptcha.createSetAnalyzer([empty, real]);
    const pairs = analyzer.findSimilarPairs(0);
    // Should produce one pair with similarity exactly 0.
    assert.equal(pairs.length, 1);
    assert.equal(pairs[0].similarity, 0);
  });

  it("dedupes repeated tokens within a single answer (set semantics, not multiset)", () => {
    // "cat cat cat" should be treated identically to "cat".
    const a = ch("a", "A", "cat cat cat");
    const b = ch("b", "B", "cat");
    const c = ch("c", "C", "cat dog");

    const analyzer = gifCaptcha.createSetAnalyzer([a, b, c]);
    const pairs = analyzer.findSimilarPairs(0);
    const get = (x, y) =>
      pairs.find((p) => (p.idA === x && p.idB === y) || (p.idA === y && p.idB === x)).similarity;

    // a vs b: both reduce to {cat} -> similarity 1
    assert.equal(get("a", "b"), 1);
    // a vs c: {cat} vs {cat, dog} -> 1/2
    assert.equal(get("a", "c"), 0.5);
    // b vs c: same as a vs c
    assert.equal(get("b", "c"), 0.5);
  });

  it("is order-invariant when challenges are reversed (smaller-side iteration sanity)", () => {
    // Build a set, then build the reverse, and check the resulting pair
    // similarities match. This exercises the branch that picks the smaller
    // side to iterate \u2014 if it accidentally consulted the wrong lookup, the
    // values would diverge between orderings.
    const cs = [
      ch("1", "T1", "alpha beta"),
      ch("2", "T2", "beta gamma delta"),
      ch("3", "T3", "delta epsilon zeta eta"),
      ch("4", "T4", "alpha gamma epsilon"),
    ];
    const forward = gifCaptcha.createSetAnalyzer(cs);
    const reverse = gifCaptcha.createSetAnalyzer(cs.slice().reverse());

    const fPairs = forward.findSimilarPairs(0);
    const rPairs = reverse.findSimilarPairs(0);

    const key = (p) => [p.idA, p.idB].sort().join("|");
    const fMap = new Map(fPairs.map((p) => [key(p), p.similarity]));
    const rMap = new Map(rPairs.map((p) => [key(p), p.similarity]));

    assert.equal(fMap.size, rMap.size);
    fMap.forEach((sim, k) => {
      assert.equal(rMap.get(k), sim, "pair " + k + " differs between orderings");
    });
  });

  it("scales to 100+ challenges without crashing and yields a usable diversity score", () => {
    const challenges = [];
    for (let i = 0; i < 120; i++) {
      challenges.push(ch("c" + i, "T" + i,
        "word" + (i % 17) + " word" + (i % 13) + " word" + (i % 11) + " word" + (i % 7)));
    }
    const analyzer = gifCaptcha.createSetAnalyzer(challenges);
    const t0 = Date.now();
    const score = analyzer.diversityScore();
    const dt = Date.now() - t0;

    assert.ok(score.score >= 0 && score.score <= 100, "diversity score in range");
    assert.ok(Number.isFinite(score.breakdown.answerDiversity));
    // Generous upper bound; the actual run on this host is ~10ms. The point
    // is to fail loudly if a future regression makes the O(n^2) loop allocate
    // wildly.
    assert.ok(dt < 5000, "diversityScore over 120 challenges took " + dt + "ms (>5000ms)");
  });
});
