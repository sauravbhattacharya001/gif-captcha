/**
 * Tests for captcha-export-formatter.js
 */

"use strict";

const { createExportFormatter } = require('../src/captcha-export-formatter');

function assert(cond, msg) { if (!cond) throw new Error(`FAIL: ${msg}`); }
function assertThrows(fn, msg) { try { fn(); throw new Error(`FAIL (no throw): ${msg}`); } catch (e) { if (e.message.startsWith('FAIL')) throw e; } }

const sampleTrials = [
  { participant: 'P01', solved: true, timeMs: 2340, challengeType: 'sequence', attempts: 1, difficulty: 'easy', device: 'desktop' },
  { participant: 'P01', solved: false, timeMs: 8100, challengeType: 'pattern', attempts: 3, difficulty: 'hard', device: 'desktop' },
  { participant: 'P02', solved: true, timeMs: 3200, challengeType: 'sequence', attempts: 1, difficulty: 'easy', device: 'mobile' },
  { participant: 'P02', solved: true, timeMs: 4500, challengeType: 'pattern', attempts: 2, difficulty: 'medium', device: 'mobile' },
  { participant: 'P03', solved: false, timeMs: 9000, challengeType: 'sequence', attempts: 2, difficulty: 'hard', device: 'tablet' },
  { participant: 'P03', solved: true, timeMs: 1800, challengeType: 'motion', attempts: 1, difficulty: 'easy', device: 'desktop' },
];

let passed = 0;

// 1. creation
(() => {
  const fmt = createExportFormatter();
  assert(fmt.count() === 0, 'starts empty');
  passed++;
})();

// 2. addTrial
(() => {
  const fmt = createExportFormatter();
  fmt.addTrial(sampleTrials[0]);
  assert(fmt.count() === 1, 'count after add');
  passed++;
})();

// 3. addTrials bulk
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  assert(fmt.count() === 6, 'bulk add count');
  passed++;
})();

// 4. validation - missing participant
(() => {
  const fmt = createExportFormatter();
  assertThrows(() => fmt.addTrial({ solved: true, timeMs: 100, challengeType: 'x' }), 'missing participant');
  passed++;
})();

// 5. validation - missing solved
(() => {
  const fmt = createExportFormatter();
  assertThrows(() => fmt.addTrial({ participant: 'P', timeMs: 100, challengeType: 'x' }), 'missing solved');
  passed++;
})();

// 6. validation - negative timeMs
(() => {
  const fmt = createExportFormatter();
  assertThrows(() => fmt.addTrial({ participant: 'P', solved: true, timeMs: -1, challengeType: 'x' }), 'negative time');
  passed++;
})();

// 7. validation - missing challengeType
(() => {
  const fmt = createExportFormatter();
  assertThrows(() => fmt.addTrial({ participant: 'P', solved: true, timeMs: 100 }), 'missing type');
  passed++;
})();

// 8. validation - not an object
(() => {
  const fmt = createExportFormatter();
  assertThrows(() => fmt.addTrial(null), 'null trial');
  passed++;
})();

// 9. getTrials returns copy
(() => {
  const fmt = createExportFormatter();
  fmt.addTrial(sampleTrials[0]);
  const t = fmt.getTrials();
  t.push({});
  assert(fmt.count() === 1, 'getTrials is a copy');
  passed++;
})();

// 10. clear
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  fmt.clear();
  assert(fmt.count() === 0, 'clear empties');
  passed++;
})();

// 11. descriptiveStats basics
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const s = fmt.descriptiveStats();
  assert(s.n === 6, 'stats n');
  assert(s.participants === 3, 'stats participants');
  assert(s.challengeTypes === 3, 'stats types');
  passed++;
})();

// 12. descriptiveStats solve rate
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const s = fmt.descriptiveStats();
  assert(Math.abs(s.solveRate - 4/6) < 0.01, 'solve rate');
  passed++;
})();

// 13. descriptiveStats byType
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const s = fmt.descriptiveStats();
  assert(s.byType.sequence.n === 3, 'byType sequence n');
  assert(s.byType.pattern.n === 2, 'byType pattern n');
  assert(s.byType.motion.n === 1, 'byType motion n');
  passed++;
})();

// 14. descriptiveStats with filter
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const s = fmt.descriptiveStats(t => t.solved);
  assert(s.n === 4, 'filtered stats n');
  passed++;
})();

// 15. descriptiveStats empty
(() => {
  const fmt = createExportFormatter();
  assert(fmt.descriptiveStats() === null, 'empty stats null');
  passed++;
})();

// 16. toLatex contains booktabs
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const tex = fmt.toLatex();
  assert(tex.includes('\\toprule'), 'has toprule');
  assert(tex.includes('\\midrule'), 'has midrule');
  assert(tex.includes('\\bottomrule'), 'has bottomrule');
  passed++;
})();

// 17. toLatex contains types
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const tex = fmt.toLatex();
  assert(tex.includes('sequence'), 'latex has sequence');
  assert(tex.includes('pattern'), 'latex has pattern');
  passed++;
})();

// 18. toLatex custom caption
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const tex = fmt.toLatex({ caption: 'My Study' });
  assert(tex.includes('My Study'), 'custom caption');
  passed++;
})();

// 19. toLatex empty
(() => {
  const fmt = createExportFormatter();
  assert(fmt.toLatex().includes('No trial'), 'empty latex');
  passed++;
})();

// 20. toR contains data.frame
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const r = fmt.toR();
  assert(r.includes('data.frame'), 'R has data.frame');
  assert(r.includes('captcha_data'), 'R var name');
  passed++;
})();

// 21. toR custom var name
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const r = fmt.toR('my_df');
  assert(r.includes('my_df <-'), 'custom R var');
  passed++;
})();

// 22. toR includes difficulty column
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const r = fmt.toR();
  assert(r.includes('difficulty'), 'R has difficulty');
  passed++;
})();

// 23. toR includes device column
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const r = fmt.toR();
  assert(r.includes('device'), 'R has device');
  passed++;
})();

// 24. toR empty
(() => {
  const fmt = createExportFormatter();
  const r = fmt.toR();
  assert(r.includes('data.frame()'), 'empty R');
  passed++;
})();

// 25. toSPSS csv headers
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const { csv, codebook } = fmt.toSPSS();
  assert(csv.startsWith('participant,'), 'SPSS csv headers');
  assert(codebook.includes('VARIABLE LABELS'), 'has codebook');
  passed++;
})();

// 26. toSPSS row count
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const { csv } = fmt.toSPSS();
  const rows = csv.split('\n');
  assert(rows.length === 7, 'SPSS 6 data rows + header');
  passed++;
})();

// 27. toSPSS solved encoding
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const { csv } = fmt.toSPSS();
  const row1 = csv.split('\n')[1];
  assert(row1.includes(',1,'), 'solved=true -> 1');
  const row2 = csv.split('\n')[2];
  assert(row2.includes(',0,'), 'solved=false -> 0');
  passed++;
})();

// 28. toSPSS empty
(() => {
  const fmt = createExportFormatter();
  const { csv, codebook } = fmt.toSPSS();
  assert(csv === '', 'empty SPSS csv');
  assert(codebook === '', 'empty SPSS codebook');
  passed++;
})();

// 29. toBibTeX
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const bib = fmt.toBibTeX({ title: 'Test', author: 'Smith, J.', year: '2026' });
  assert(bib.includes('@misc{'), 'bibtex type');
  assert(bib.includes('Smith, J.'), 'bibtex author');
  assert(bib.includes('6 trials'), 'bibtex note with count');
  passed++;
})();

// 30. toBibTeX custom type and key
(() => {
  const fmt = createExportFormatter();
  fmt.addTrial(sampleTrials[0]);
  const bib = fmt.toBibTeX({ type: 'article', key: 'mykey2026' });
  assert(bib.includes('@article{mykey2026,'), 'custom type+key');
  passed++;
})();

// 31. toAppendix structure
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const app = fmt.toAppendix();
  assert(app.includes('\\section*{Appendix'), 'appendix section');
  assert(app.includes('Dataset Overview'), 'overview subsection');
  assert(app.includes('Per-Participant'), 'participant table');
  passed++;
})();

// 32. toAppendix has all participants
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const app = fmt.toAppendix();
  assert(app.includes('P01'), 'has P01');
  assert(app.includes('P02'), 'has P02');
  assert(app.includes('P03'), 'has P03');
  passed++;
})();

// 33. toAppendix empty
(() => {
  const fmt = createExportFormatter();
  assert(fmt.toAppendix().includes('No trial'), 'empty appendix');
  passed++;
})();

// 34. toJSON roundtrip
(() => {
  const fmt = createExportFormatter();
  fmt.addTrials(sampleTrials);
  const json = fmt.toJSON();
  const parsed = JSON.parse(json);
  assert(parsed.trialCount === 6, 'json trialCount');
  assert(parsed.trials.length === 6, 'json trials array');
  passed++;
})();

// 35. importJSON
(() => {
  const fmt1 = createExportFormatter();
  fmt1.addTrials(sampleTrials);
  const json = fmt1.toJSON();

  const fmt2 = createExportFormatter();
  const imported = fmt2.importJSON(json);
  assert(imported === 6, 'imported count');
  assert(fmt2.count() === 6, 'fmt2 count after import');
  passed++;
})();

// 36. importJSON invalid
(() => {
  const fmt = createExportFormatter();
  assertThrows(() => fmt.importJSON('{}'), 'invalid json import');
  passed++;
})();

// 37. attempts default to 1
(() => {
  const fmt = createExportFormatter();
  fmt.addTrial({ participant: 'P', solved: true, timeMs: 100, challengeType: 'x' });
  assert(fmt.getTrials()[0].attempts === 1, 'default attempts');
  passed++;
})();

// 38. invalid difficulty ignored
(() => {
  const fmt = createExportFormatter();
  fmt.addTrial({ participant: 'P', solved: true, timeMs: 100, challengeType: 'x', difficulty: 'extreme' });
  assert(fmt.getTrials()[0].difficulty === null, 'invalid difficulty null');
  passed++;
})();

// 39. invalid device ignored
(() => {
  const fmt = createExportFormatter();
  fmt.addTrial({ participant: 'P', solved: true, timeMs: 100, challengeType: 'x', device: 'fridge' });
  assert(fmt.getTrials()[0].device === null, 'invalid device null');
  passed++;
})();

// 40. addTrials non-array throws
(() => {
  const fmt = createExportFormatter();
  assertThrows(() => fmt.addTrials('nope'), 'non-array addTrials');
  passed++;
})();

// 41. LaTeX escapes special chars
(() => {
  const fmt = createExportFormatter();
  fmt.addTrial({ participant: 'P&1', solved: true, timeMs: 100, challengeType: 'a_b' });
  const tex = fmt.toLatex();
  assert(tex.includes('a\\_b'), 'underscore escaped');
  passed++;
})();

// 42. toJSON non-pretty
(() => {
  const fmt = createExportFormatter();
  fmt.addTrial(sampleTrials[0]);
  const json = fmt.toJSON(false);
  assert(!json.includes('\n'), 'compact json');
  passed++;
})();

console.log(`\n✅ All ${passed}/42 tests passed`);
