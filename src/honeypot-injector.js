'use strict';

// Use cryptographic randomness for honeypot IDs and strategy selection.
// Math.random() is predictable (CWE-330) — an attacker who can predict
// which fields are honeypots can avoid them entirely, defeating the purpose.
var _secureRandomInt = require('./crypto-utils').secureRandomInt;


/**
 * createHoneypotInjector — invisible decoy CAPTCHA challenge injection for bot detection.
 *
 * Generates hidden "honeypot" challenges that real users never see or interact with,
 * but automated solvers attempt to solve. Any interaction with a honeypot field is
 * a strong bot signal. Supports multiple concealment strategies, trap tracking,
 * per-session and fleet-level analytics, and confidence scoring.
 *
 * Concealment strategies:
 *   - "css-hidden"     : visually hidden via CSS (display:none / opacity:0 / off-screen)
 *   - "aria-hidden"    : hidden from screen readers and visual UI
 *   - "tab-excluded"   : removed from tab order (tabindex=-1) + zero dimensions
 *   - "decoy-label"    : visible label with invisible input (catches label-scanning bots)
 *   - "temporal"       : injected after delay (catches bots that parse initial HTML)
 *
 * @param {object} [options]
 * @param {string[]} [options.strategies]         Concealment strategies to use (default: all)
 * @param {number}   [options.maxTraps=50]        Max active traps tracked
 * @param {number}   [options.trapTTLMs=300000]   Trap expiry (default: 5 minutes)
 * @param {number}   [options.maxTrippedHistory=500] Max tripped records retained
 * @param {string[]} [options.fieldNames]         Custom decoy field names
 * @param {number}   [options.temporalDelayMs=2000] Delay for temporal strategy injection
 * @returns {object}
 */
function createHoneypotInjector(options) {
  options = options || {};

  var ALL_STRATEGIES = ['css-hidden', 'aria-hidden', 'tab-excluded', 'decoy-label', 'temporal'];
  var strategies = _validateStrategies(options.strategies) || ALL_STRATEGIES.slice();
  var maxTraps = (options.maxTraps != null && options.maxTraps > 0) ? Math.floor(options.maxTraps) : 50;
  var trapTTLMs = (options.trapTTLMs != null && options.trapTTLMs > 0) ? options.trapTTLMs : 300000;
  var maxTrippedHistory = (options.maxTrippedHistory != null && options.maxTrippedHistory > 0)
    ? Math.floor(options.maxTrippedHistory) : 500;
  var temporalDelayMs = (options.temporalDelayMs != null && options.temporalDelayMs >= 0)
    ? options.temporalDelayMs : 2000;

  var DEFAULT_FIELD_NAMES = [
    'website', 'url', 'homepage', 'company_url', 'fax_number',
    'middle_name', 'nickname', 'title_2', 'address_line_3',
    'phone_ext', 'secondary_email', 'confirm_age', 'referral_code'
  ];
  var fieldNames = Array.isArray(options.fieldNames) && options.fieldNames.length > 0
    ? options.fieldNames.slice() : DEFAULT_FIELD_NAMES.slice();

  var traps = Object.create(null);
  var trapCount = 0;
  var trippedHistory = [];
  var stats = {
    totalCreated: 0, totalChecked: 0, totalTripped: 0,
    totalClean: 0, totalExpired: 0,
    byStrategy: Object.create(null), bySession: Object.create(null)
  };
  for (var i = 0; i < ALL_STRATEGIES.length; i++) {
    stats.byStrategy[ALL_STRATEGIES[i]] = { created: 0, tripped: 0, checked: 0 };
  }

  function _validateStrategies(strats) {
    if (!Array.isArray(strats) || strats.length === 0) return null;
    var valid = [];
    for (var j = 0; j < strats.length; j++) {
      if (ALL_STRATEGIES.indexOf(strats[j]) !== -1 && valid.indexOf(strats[j]) === -1) valid.push(strats[j]);
    }
    return valid.length > 0 ? valid : null;
  }

  function _generateId() {
    var chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    var id = 'hp_';
    for (var k = 0; k < 12; k++) id += chars.charAt(_secureRandomInt(chars.length));
    return id;
  }

  function _pickFieldName() { return fieldNames[_secureRandomInt(fieldNames.length)]; }
  function _pickStrategy() { return strategies[_secureRandomInt(strategies.length)]; }

  function _evictExpired() {
    var now = Date.now(), keys = Object.keys(traps);
    for (var m = 0; m < keys.length; m++) {
      if (now - traps[keys[m]].createdAt > trapTTLMs) { delete traps[keys[m]]; trapCount--; stats.totalExpired++; }
    }
  }

  function _evictOldest() {
    var keys = Object.keys(traps);
    if (keys.length === 0) return;
    var oldestKey = keys[0], oldestTime = traps[keys[0]].createdAt;
    for (var n = 1; n < keys.length; n++) {
      if (traps[keys[n]].createdAt < oldestTime) { oldestKey = keys[n]; oldestTime = traps[keys[n]].createdAt; }
    }
    delete traps[oldestKey]; trapCount--;
  }

  function _escapeAttr(str) {
    return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function _randomLabel() {
    var labels = ['Website', 'Your URL', 'Homepage', 'Fax', 'Alternate Email', 'Company Website', 'Secondary Phone', 'Referral'];
    return labels[_secureRandomInt(labels.length)];
  }

  function _generateHTML(fieldName, strategy, trapId) {
    var inputAttrs = 'name="' + _escapeAttr(fieldName) + '" id="' + _escapeAttr(trapId) + '" autocomplete="off" data-hp="1"';
    switch (strategy) {
      case 'css-hidden':
        return '<div style="position:absolute;left:-9999px;top:-9999px;width:0;height:0;overflow:hidden;opacity:0;"><input type="text" ' + inputAttrs + ' tabindex="-1" /></div>';
      case 'aria-hidden':
        return '<div aria-hidden="true" style="display:none;"><input type="text" ' + inputAttrs + ' tabindex="-1" /></div>';
      case 'tab-excluded':
        return '<input type="text" ' + inputAttrs + ' tabindex="-1" style="width:0;height:0;border:0;padding:0;margin:0;position:absolute;" />';
      case 'decoy-label':
        return '<div style="position:absolute;left:-9999px;"><label for="' + _escapeAttr(trapId) + '">' + _randomLabel() + '</label><input type="text" ' + inputAttrs + ' tabindex="-1" /></div>';
      case 'temporal':
        return '<div id="' + _escapeAttr(trapId) + '_wrap" style="display:none;" data-hp-delay="' + temporalDelayMs + '"><input type="text" ' + inputAttrs + ' tabindex="-1" /></div><script>setTimeout(function(){var e=document.getElementById("' + _escapeAttr(trapId) + '_wrap");if(e)e.style.display="";},' + temporalDelayMs + ')</script>';
      default:
        return '<div style="display:none;"><input type="text" ' + inputAttrs + ' /></div>';
    }
  }

  function _looksAutomated(value) {
    var s = String(value);
    if (/^https?:\/\//i.test(s)) return true;
    if (s.length > 100) return true;
    if (/<[a-z]/i.test(s)) return true;
    if (s.length > 5 && s.length < 30) {
      var chars = Object.create(null);
      for (var p = 0; p < s.length; p++) chars[s[p]] = 1;
      if (Object.keys(chars).length / s.length > 0.85) return true;
    }
    return false;
  }

  function createTrap(opts) {
    if (!opts || typeof opts.sessionId !== 'string' || opts.sessionId.length === 0) throw new Error('sessionId is required');
    _evictExpired();
    while (trapCount >= maxTraps) _evictOldest();
    var strategy = (opts.strategy && ALL_STRATEGIES.indexOf(opts.strategy) !== -1) ? opts.strategy : _pickStrategy();
    var fieldName = (typeof opts.fieldName === 'string' && opts.fieldName.length > 0) ? opts.fieldName : _pickFieldName();
    var id = _generateId(), now = Date.now();
    var html = _generateHTML(fieldName, strategy, id);
    traps[id] = { id: id, sessionId: opts.sessionId, fieldName: fieldName, strategy: strategy, html: html, createdAt: now, checked: false, tripped: false };
    trapCount++;
    stats.totalCreated++;
    if (stats.byStrategy[strategy]) stats.byStrategy[strategy].created++;
    if (!stats.bySession[opts.sessionId]) stats.bySession[opts.sessionId] = { created: 0, tripped: 0, checked: 0, clean: 0 };
    stats.bySession[opts.sessionId].created++;
    return { id: id, fieldName: fieldName, strategy: strategy, html: html, createdAt: now };
  }

  function createTrapSet(opts) {
    if (!opts || typeof opts.sessionId !== 'string' || opts.sessionId.length === 0) throw new Error('sessionId is required');
    var count = (opts.count != null && opts.count > 0) ? Math.min(Math.floor(opts.count), strategies.length) : Math.min(3, strategies.length);
    var usedStrategies = strategies.slice(), results = [];
    for (var q = 0; q < count; q++) {
      var idx = _secureRandomInt(usedStrategies.length);
      var strat = usedStrategies.splice(idx, 1)[0];
      if (!strat) strat = _pickStrategy();
      results.push(createTrap({ sessionId: opts.sessionId, strategy: strat }));
    }
    return results;
  }

  function check(opts) {
    if (!opts || typeof opts.trapId !== 'string') throw new Error('trapId is required');
    stats.totalChecked++;
    var trap = traps[opts.trapId];
    if (!trap) return { tripped: false, confidence: 0, trapId: opts.trapId, strategy: null, detail: 'unknown_trap' };
    if (stats.byStrategy[trap.strategy]) stats.byStrategy[trap.strategy].checked++;
    if (stats.bySession[trap.sessionId]) stats.bySession[trap.sessionId].checked++;
    trap.checked = true;
    var value = opts.value, hasValue = (value !== undefined && value !== null && value !== '');
    if (hasValue) {
      trap.tripped = true; stats.totalTripped++;
      if (stats.byStrategy[trap.strategy]) stats.byStrategy[trap.strategy].tripped++;
      if (stats.bySession[trap.sessionId]) stats.bySession[trap.sessionId].tripped++;
      trippedHistory.push({ trapId: trap.id, sessionId: trap.sessionId, value: String(value).substring(0, 200), timestamp: Date.now(), strategy: trap.strategy, fieldName: trap.fieldName });
      if (trippedHistory.length > maxTrippedHistory) trippedHistory.splice(0, trippedHistory.length - maxTrippedHistory);
      var confidence = _looksAutomated(value) ? 0.99 : 0.95;
      return { tripped: true, confidence: confidence, trapId: trap.id, strategy: trap.strategy, detail: 'honeypot_triggered', sessionId: trap.sessionId };
    }
    stats.totalClean++;
    if (stats.bySession[trap.sessionId]) stats.bySession[trap.sessionId].clean++;
    return { tripped: false, confidence: 0, trapId: trap.id, strategy: trap.strategy, detail: 'clean' };
  }

  function checkBatch(checks) {
    if (!Array.isArray(checks)) throw new Error('checks must be an array');
    var results = [], trippedCount = 0, maxConf = 0;
    for (var r = 0; r < checks.length; r++) {
      var res = check(checks[r]); results.push(res);
      if (res.tripped) { trippedCount++; if (res.confidence > maxConf) maxConf = res.confidence; }
    }
    var confidence = maxConf;
    if (trippedCount > 1) confidence = Math.min(1, maxConf + (trippedCount - 1) * 0.01);
    var verdict = trippedCount === 0 ? 'human' : (trippedCount >= 2 ? 'definite_bot' : 'likely_bot');
    return { results: results, anyTripped: trippedCount > 0, trippedCount: trippedCount, total: checks.length, confidence: confidence, verdict: verdict };
  }

  function getSessionScore(sessionId) {
    if (typeof sessionId !== 'string' || sessionId.length === 0) throw new Error('sessionId is required');
    var s = stats.bySession[sessionId];
    if (!s) return { sessionId: sessionId, traps: 0, checked: 0, tripped: 0, clean: 0, botProbability: 0, verdict: 'unknown' };
    var botProb = s.checked > 0 ? (s.tripped > 0 ? Math.min(0.99, 0.9 + s.tripped * 0.02) : 0) : 0;
    var verdict = s.checked > 0 ? (s.tripped > 0 ? 'bot' : 'human') : 'unknown';
    return { sessionId: sessionId, traps: s.created, checked: s.checked, tripped: s.tripped, clean: s.clean, botProbability: botProb, verdict: verdict };
  }

  function getStrategyStats() {
    var result = [], keys = Object.keys(stats.byStrategy);
    for (var t = 0; t < keys.length; t++) {
      var st = stats.byStrategy[keys[t]];
      result.push({ strategy: keys[t], created: st.created, checked: st.checked, tripped: st.tripped, tripRate: st.checked > 0 ? +(st.tripped / st.checked).toFixed(4) : 0 });
    }
    result.sort(function (a, b) { return b.tripRate - a.tripRate; });
    return result;
  }

  function getTrap(trapId) {
    _evictExpired();
    var t = traps[trapId];
    if (!t) return null;
    return { id: t.id, sessionId: t.sessionId, fieldName: t.fieldName, strategy: t.strategy, createdAt: t.createdAt, checked: t.checked, tripped: t.tripped };
  }

  function getTrippedHistory(limit) {
    var n = (limit != null && limit > 0) ? Math.floor(limit) : 20;
    return trippedHistory.slice(-n);
  }

  function summary() {
    _evictExpired();
    var activeCount = Object.keys(traps).length;
    var strategyStats = getStrategyStats();
    var bestStrategy = strategyStats.length > 0 ? strategyStats[0].strategy : null;
    var sessionKeys = Object.keys(stats.bySession), botSessions = 0;
    for (var u = 0; u < sessionKeys.length; u++) { if (stats.bySession[sessionKeys[u]].tripped > 0) botSessions++; }
    return {
      activeTraps: activeCount, totalCreated: stats.totalCreated, totalChecked: stats.totalChecked,
      totalTripped: stats.totalTripped, totalClean: stats.totalClean, totalExpired: stats.totalExpired,
      tripRate: stats.totalChecked > 0 ? +(stats.totalTripped / stats.totalChecked).toFixed(4) : 0,
      sessions: sessionKeys.length, botSessions: botSessions,
      botRate: sessionKeys.length > 0 ? +(botSessions / sessionKeys.length).toFixed(4) : 0,
      bestStrategy: bestStrategy, strategies: strategyStats
    };
  }

  function generateReport() {
    var s = summary();
    var lines = ['=== Honeypot Injector Report ===', '', 'Active Traps:   ' + s.activeTraps,
      'Total Created:  ' + s.totalCreated, 'Total Checked:  ' + s.totalChecked,
      'Total Tripped:  ' + s.totalTripped + ' (' + (s.tripRate * 100).toFixed(1) + '%)',
      'Total Clean:    ' + s.totalClean, 'Total Expired:  ' + s.totalExpired, '',
      'Sessions:       ' + s.sessions, 'Bot Sessions:   ' + s.botSessions + ' (' + (s.botRate * 100).toFixed(1) + '%)',
      '', '--- Strategy Effectiveness ---'];
    for (var v = 0; v < s.strategies.length; v++) {
      var st = s.strategies[v];
      lines.push('  ' + st.strategy + ': ' + st.tripped + '/' + st.checked + ' tripped (' + (st.tripRate * 100).toFixed(1) + '%)');
    }
    if (s.bestStrategy) { lines.push(''); lines.push('Best Strategy:  ' + s.bestStrategy); }
    return lines.join('\n');
  }

  function exportState() {
    return { stats: JSON.parse(JSON.stringify(stats)), trippedHistory: trippedHistory.slice(), trapCount: trapCount };
  }

  function importState(state) {
    if (!state || typeof state !== 'object') throw new Error('state must be an object');
    if (state.stats) {
      stats.totalCreated = state.stats.totalCreated || 0; stats.totalChecked = state.stats.totalChecked || 0;
      stats.totalTripped = state.stats.totalTripped || 0; stats.totalClean = state.stats.totalClean || 0;
      stats.totalExpired = state.stats.totalExpired || 0;
      if (state.stats.byStrategy) { var bk = Object.keys(state.stats.byStrategy); for (var w = 0; w < bk.length; w++) stats.byStrategy[bk[w]] = state.stats.byStrategy[bk[w]]; }
      if (state.stats.bySession) { var sk = Object.keys(state.stats.bySession); for (var x = 0; x < sk.length; x++) stats.bySession[sk[x]] = state.stats.bySession[sk[x]]; }
    }
    if (Array.isArray(state.trippedHistory)) trippedHistory = state.trippedHistory.slice();
  }

  function reset() {
    traps = Object.create(null); trapCount = 0; trippedHistory = [];
    stats.totalCreated = 0; stats.totalChecked = 0; stats.totalTripped = 0;
    stats.totalClean = 0; stats.totalExpired = 0; stats.bySession = Object.create(null);
    for (var y = 0; y < ALL_STRATEGIES.length; y++) stats.byStrategy[ALL_STRATEGIES[y]] = { created: 0, tripped: 0, checked: 0 };
  }

  return {
    createTrap: createTrap, createTrapSet: createTrapSet, check: check, checkBatch: checkBatch,
    getSessionScore: getSessionScore, getStrategyStats: getStrategyStats, getTrap: getTrap,
    getTrippedHistory: getTrippedHistory, summary: summary, generateReport: generateReport,
    exportState: exportState, importState: importState, reset: reset
  };
}

module.exports = { createHoneypotInjector: createHoneypotInjector };
