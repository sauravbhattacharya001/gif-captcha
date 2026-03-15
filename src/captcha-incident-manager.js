/**
 * CaptchaIncidentManager — Incident lifecycle management for gif-captcha.
 *
 * Creates, tracks, escalates, and resolves incidents triggered by health
 * monitors, anomaly detectors, or manual reports. Provides severity levels,
 * auto-escalation timers, runbook references, timeline tracking, and
 * postmortem report generation.
 *
 * Usage:
 *   const { createIncidentManager } = require('./captcha-incident-manager');
 *   const mgr = createIncidentManager({
 *     autoEscalateMs: 300000,  // escalate after 5 min unacknowledged
 *     maxOpenIncidents: 50
 *   });
 *
 *   const id = mgr.create({
 *     title: 'Solve rate dropped below 40%',
 *     severity: 'high',
 *     source: 'health-monitor',
 *     signals: { solveRate: 0.38, avgResponseMs: 9200 }
 *   });
 *
 *   mgr.acknowledge(id, { responder: 'ops-team' });
 *   mgr.addNote(id, 'Investigating — appears to be new bot wave');
 *   mgr.escalate(id, 'critical', 'Bot volume still increasing');
 *   mgr.resolve(id, { resolution: 'Blocked IP range, rotated challenge pool' });
 *
 *   const postmortem = mgr.generatePostmortem(id);
 *   const open = mgr.listOpen();
 *   const stats = mgr.stats();
 *
 * @module captcha-incident-manager
 */

"use strict";

// ── Severity levels (ordered) ───────────────────────────────────────
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const SEVERITY_INDEX = {};
SEVERITIES.forEach(function (s, i) { SEVERITY_INDEX[s] = i; });

// ── Incident states ────────────────────────────────────────────────
const STATES = ['open', 'acknowledged', 'investigating', 'mitigating', 'resolved', 'closed'];
const STATE_INDEX = {};
STATES.forEach(function (s, i) { STATE_INDEX[s] = i; });

// ── Default runbooks ───────────────────────────────────────────────
const DEFAULT_RUNBOOKS = {
  'solve-rate-drop': {
    title: 'Solve Rate Drop',
    steps: [
      'Check anomaly detector for bot burst signals',
      'Review challenge difficulty settings',
      'Inspect pool freshness and rotation schedule',
      'Consider temporarily raising difficulty or enabling honeypots',
      'Monitor for 15 min after changes'
    ]
  },
  'response-time-spike': {
    title: 'Response Time Spike',
    steps: [
      'Check server resource utilization (CPU, memory)',
      'Review GIF generation pipeline for bottlenecks',
      'Check pool levels — low pools cause on-demand generation',
      'Scale horizontally or reduce GIF complexity',
      'Enable caching if not already active'
    ]
  },
  'bot-surge': {
    title: 'Bot Traffic Surge',
    steps: [
      'Review rate limiter thresholds',
      'Check geo-risk scorer for concentrated origins',
      'Enable aggressive honeypot injection',
      'Consider temporary IP/ASN blocks',
      'Rotate challenge templates immediately'
    ]
  },
  'pool-exhaustion': {
    title: 'Challenge Pool Exhaustion',
    steps: [
      'Trigger immediate pool replenishment',
      'Check generator for errors or timeouts',
      'Increase pool size configuration',
      'Enable fallback challenge type',
      'Review consumption rate vs generation rate'
    ]
  },
  'error-spike': {
    title: 'Error Rate Spike',
    steps: [
      'Check application logs for stack traces',
      'Review recent deployments or config changes',
      'Verify external dependencies (storage, CDN)',
      'Restart affected services if hung',
      'Roll back recent changes if error persists'
    ]
  }
};

// ── Helpers ─────────────────────────────────────────────────────────

var _nextId = 0;
function _generateId() {
  _nextId += 1;
  return 'INC-' + Date.now().toString(36).toUpperCase() + '-' + _nextId;
}

function _now() { return Date.now(); }

function _validSeverity(s) {
  return SEVERITIES.indexOf(s) !== -1;
}

function _validState(s) {
  return STATES.indexOf(s) !== -1;
}

function _duration(startMs, endMs) {
  var ms = (endMs || _now()) - startMs;
  if (ms < 1000) return ms + 'ms';
  if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
  if (ms < 3600000) return (ms / 60000).toFixed(1) + 'min';
  return (ms / 3600000).toFixed(1) + 'h';
}

// ── Factory ─────────────────────────────────────────────────────────

/**
 * @param {Object} [opts]
 * @param {number} [opts.autoEscalateMs=300000] — auto-escalate unacknowledged after this time
 * @param {number} [opts.maxOpenIncidents=50]
 * @param {Object} [opts.runbooks] — custom runbooks keyed by slug
 * @param {Function} [opts.onEscalate] — callback(incident) when auto-escalation fires
 * @param {Function} [opts.onStateChange] — callback(incident, oldState, newState)
 * @param {Function} [opts.clock] — custom clock for testing
 */
function createIncidentManager(opts) {
  opts = opts || {};
  var autoEscalateMs = opts.autoEscalateMs != null ? opts.autoEscalateMs : 300000;
  var maxOpen = opts.maxOpenIncidents || 50;
  var clock = opts.clock || _now;
  var onEscalate = opts.onEscalate || null;
  var onStateChange = opts.onStateChange || null;

  var runbooks = {};
  // Merge defaults + custom
  Object.keys(DEFAULT_RUNBOOKS).forEach(function (k) {
    runbooks[k] = DEFAULT_RUNBOOKS[k];
  });
  if (opts.runbooks) {
    Object.keys(opts.runbooks).forEach(function (k) {
      runbooks[k] = opts.runbooks[k];
    });
  }

  var incidents = {};      // id → incident
  var escalationTimers = {}; // id → timer handle

  // ── Incident creation ───────────────────────────────────────────

  /**
   * Create a new incident.
   * @param {Object} params
   * @param {string} params.title
   * @param {string} [params.severity='medium']
   * @param {string} [params.source] — originating module
   * @param {Object} [params.signals] — triggering metric values
   * @param {string} [params.runbook] — runbook slug to attach
   * @param {Object} [params.metadata] — arbitrary extra data
   * @returns {string} incident ID
   */
  function create(params) {
    if (!params || !params.title) throw new Error('Incident title is required');
    var sev = params.severity || 'medium';
    if (!_validSeverity(sev)) throw new Error('Invalid severity: ' + sev);

    var openCount = Object.keys(incidents).filter(function (k) {
      return incidents[k].state === 'open' || incidents[k].state === 'acknowledged' || incidents[k].state === 'investigating' || incidents[k].state === 'mitigating';
    }).length;
    if (openCount >= maxOpen) throw new Error('Max open incidents reached (' + maxOpen + ')');

    var id = _generateId();
    var now = clock();
    var incident = {
      id: id,
      title: params.title,
      severity: sev,
      state: 'open',
      source: params.source || 'manual',
      signals: params.signals || {},
      metadata: params.metadata || {},
      runbook: params.runbook ? (runbooks[params.runbook] || null) : _autoMatchRunbook(params.title),
      timeline: [
        { ts: now, action: 'created', detail: 'Incident created — severity: ' + sev }
      ],
      notes: [],
      createdAt: now,
      acknowledgedAt: null,
      resolvedAt: null,
      closedAt: null,
      responder: null,
      resolution: null,
      ttaMs: null,   // time to acknowledge
      ttrMs: null    // time to resolve
    };

    incidents[id] = incident;

    // Auto-escalation timer for unacknowledged incidents
    if (autoEscalateMs > 0 && SEVERITY_INDEX[sev] < SEVERITY_INDEX['critical']) {
      _setEscalationTimer(id);
    }

    return id;
  }

  function _autoMatchRunbook(title) {
    var t = title.toLowerCase();
    if (t.indexOf('solve rate') !== -1 || t.indexOf('solve_rate') !== -1) return runbooks['solve-rate-drop'] || null;
    if (t.indexOf('response time') !== -1 || t.indexOf('latency') !== -1) return runbooks['response-time-spike'] || null;
    if (t.indexOf('bot') !== -1 || t.indexOf('surge') !== -1) return runbooks['bot-surge'] || null;
    if (t.indexOf('pool') !== -1 || t.indexOf('exhaust') !== -1) return runbooks['pool-exhaustion'] || null;
    if (t.indexOf('error') !== -1) return runbooks['error-spike'] || null;
    return null;
  }

  function _setEscalationTimer(id) {
    if (escalationTimers[id]) clearTimeout(escalationTimers[id]);
    escalationTimers[id] = setTimeout(function () {
      var inc = incidents[id];
      if (inc && inc.state === 'open') {
        var newSev = SEVERITIES[Math.min(SEVERITY_INDEX[inc.severity] + 1, SEVERITIES.length - 1)];
        var oldSev = inc.severity;
        inc.severity = newSev;
        inc.timeline.push({
          ts: clock(),
          action: 'auto-escalated',
          detail: 'Unacknowledged for ' + _duration(inc.createdAt, clock()) + ' — severity ' + oldSev + ' → ' + newSev
        });
        if (onEscalate) onEscalate(inc);
        // Set another timer if still not critical
        if (SEVERITY_INDEX[newSev] < SEVERITY_INDEX['critical']) {
          _setEscalationTimer(id);
        }
      }
      delete escalationTimers[id];
    }, autoEscalateMs);
  }

  // ── State transitions ───────────────────────────────────────────

  function _transition(id, newState, extras) {
    var inc = incidents[id];
    if (!inc) throw new Error('Incident not found: ' + id);
    var oldState = inc.state;
    if (STATE_INDEX[newState] <= STATE_INDEX[oldState]) {
      throw new Error('Cannot transition from ' + oldState + ' to ' + newState);
    }
    inc.state = newState;
    inc.timeline.push({
      ts: clock(),
      action: 'state-change',
      detail: oldState + ' → ' + newState + (extras && extras.reason ? ' — ' + extras.reason : '')
    });
    if (onStateChange) onStateChange(inc, oldState, newState);
    return inc;
  }

  function acknowledge(id, params) {
    params = params || {};
    var inc = _transition(id, 'acknowledged', params);
    inc.acknowledgedAt = clock();
    inc.ttaMs = inc.acknowledgedAt - inc.createdAt;
    inc.responder = params.responder || 'unknown';
    inc.timeline.push({
      ts: clock(),
      action: 'acknowledged',
      detail: 'Acknowledged by ' + inc.responder + ' (TTA: ' + _duration(inc.createdAt, inc.acknowledgedAt) + ')'
    });
    if (escalationTimers[id]) {
      clearTimeout(escalationTimers[id]);
      delete escalationTimers[id];
    }
    return inc;
  }

  function investigate(id, params) {
    params = params || {};
    return _transition(id, 'investigating', params);
  }

  function mitigate(id, params) {
    params = params || {};
    return _transition(id, 'mitigating', params);
  }

  function resolve(id, params) {
    params = params || {};
    var inc = _transition(id, 'resolved', params);
    inc.resolvedAt = clock();
    inc.ttrMs = inc.resolvedAt - inc.createdAt;
    inc.resolution = params.resolution || 'No resolution provided';
    inc.timeline.push({
      ts: clock(),
      action: 'resolved',
      detail: 'Resolved (TTR: ' + _duration(inc.createdAt, inc.resolvedAt) + ') — ' + inc.resolution
    });
    return inc;
  }

  function close(id, params) {
    params = params || {};
    var inc = _transition(id, 'closed', params);
    inc.closedAt = clock();
    return inc;
  }

  // ── Severity changes ────────────────────────────────────────────

  function escalate(id, newSeverity, reason) {
    var inc = incidents[id];
    if (!inc) throw new Error('Incident not found: ' + id);
    if (!_validSeverity(newSeverity)) throw new Error('Invalid severity: ' + newSeverity);
    if (SEVERITY_INDEX[newSeverity] <= SEVERITY_INDEX[inc.severity]) {
      throw new Error('Can only escalate to higher severity (current: ' + inc.severity + ')');
    }
    var old = inc.severity;
    inc.severity = newSeverity;
    inc.timeline.push({
      ts: clock(),
      action: 'escalated',
      detail: 'Severity ' + old + ' → ' + newSeverity + (reason ? ' — ' + reason : '')
    });
    return inc;
  }

  function deescalate(id, newSeverity, reason) {
    var inc = incidents[id];
    if (!inc) throw new Error('Incident not found: ' + id);
    if (!_validSeverity(newSeverity)) throw new Error('Invalid severity: ' + newSeverity);
    if (SEVERITY_INDEX[newSeverity] >= SEVERITY_INDEX[inc.severity]) {
      throw new Error('Can only de-escalate to lower severity (current: ' + inc.severity + ')');
    }
    var old = inc.severity;
    inc.severity = newSeverity;
    inc.timeline.push({
      ts: clock(),
      action: 'de-escalated',
      detail: 'Severity ' + old + ' → ' + newSeverity + (reason ? ' — ' + reason : '')
    });
    return inc;
  }

  // ── Notes ───────────────────────────────────────────────────────

  function addNote(id, text, author) {
    var inc = incidents[id];
    if (!inc) throw new Error('Incident not found: ' + id);
    var note = { ts: clock(), text: text, author: author || 'system' };
    inc.notes.push(note);
    inc.timeline.push({ ts: note.ts, action: 'note', detail: (author || 'system') + ': ' + text });
    return note;
  }

  // ── Queries ─────────────────────────────────────────────────────

  function get(id) {
    return incidents[id] || null;
  }

  function listOpen() {
    return Object.keys(incidents).map(function (k) { return incidents[k]; }).filter(function (inc) {
      return inc.state !== 'resolved' && inc.state !== 'closed';
    }).sort(function (a, b) {
      return SEVERITY_INDEX[b.severity] - SEVERITY_INDEX[a.severity] || a.createdAt - b.createdAt;
    });
  }

  function listAll(filterOpts) {
    filterOpts = filterOpts || {};
    var list = Object.keys(incidents).map(function (k) { return incidents[k]; });

    if (filterOpts.severity) {
      list = list.filter(function (inc) { return inc.severity === filterOpts.severity; });
    }
    if (filterOpts.state) {
      list = list.filter(function (inc) { return inc.state === filterOpts.state; });
    }
    if (filterOpts.source) {
      list = list.filter(function (inc) { return inc.source === filterOpts.source; });
    }
    if (filterOpts.since) {
      list = list.filter(function (inc) { return inc.createdAt >= filterOpts.since; });
    }
    if (filterOpts.until) {
      list = list.filter(function (inc) { return inc.createdAt <= filterOpts.until; });
    }

    list.sort(function (a, b) { return b.createdAt - a.createdAt; });

    if (filterOpts.limit) list = list.slice(0, filterOpts.limit);
    return list;
  }

  // ── Statistics ──────────────────────────────────────────────────

  function stats() {
    var all = Object.keys(incidents).map(function (k) { return incidents[k]; });
    var bySeverity = {};
    var byState = {};
    var ttaValues = [];
    var ttrValues = [];

    SEVERITIES.forEach(function (s) { bySeverity[s] = 0; });
    STATES.forEach(function (s) { byState[s] = 0; });

    all.forEach(function (inc) {
      bySeverity[inc.severity] = (bySeverity[inc.severity] || 0) + 1;
      byState[inc.state] = (byState[inc.state] || 0) + 1;
      if (inc.ttaMs != null) ttaValues.push(inc.ttaMs);
      if (inc.ttrMs != null) ttrValues.push(inc.ttrMs);
    });

    function avg(arr) {
      if (!arr.length) return null;
      var s = 0; for (var i = 0; i < arr.length; i++) s += arr[i];
      return s / arr.length;
    }

    function median(arr) {
      if (!arr.length) return null;
      var sorted = arr.slice().sort(function (a, b) { return a - b; });
      var mid = Math.floor(sorted.length / 2);
      return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    return {
      total: all.length,
      open: byState.open + byState.acknowledged + byState.investigating + byState.mitigating,
      resolved: byState.resolved + byState.closed,
      bySeverity: bySeverity,
      byState: byState,
      avgTtaMs: avg(ttaValues),
      medianTtaMs: median(ttaValues),
      avgTtrMs: avg(ttrValues),
      medianTtrMs: median(ttrValues)
    };
  }

  // ── Postmortem ──────────────────────────────────────────────────

  function generatePostmortem(id) {
    var inc = incidents[id];
    if (!inc) throw new Error('Incident not found: ' + id);

    var lines = [];
    lines.push('# Postmortem: ' + inc.title);
    lines.push('');
    lines.push('**Incident ID:** ' + inc.id);
    lines.push('**Severity:** ' + inc.severity);
    lines.push('**Source:** ' + inc.source);
    lines.push('**State:** ' + inc.state);
    lines.push('**Created:** ' + new Date(inc.createdAt).toISOString());
    if (inc.acknowledgedAt) lines.push('**Acknowledged:** ' + new Date(inc.acknowledgedAt).toISOString());
    if (inc.resolvedAt) lines.push('**Resolved:** ' + new Date(inc.resolvedAt).toISOString());
    if (inc.ttaMs != null) lines.push('**Time to Acknowledge:** ' + _duration(0, inc.ttaMs));
    if (inc.ttrMs != null) lines.push('**Time to Resolve:** ' + _duration(0, inc.ttrMs));
    lines.push('**Responder:** ' + (inc.responder || 'N/A'));
    lines.push('');

    // Signals
    lines.push('## Triggering Signals');
    if (Object.keys(inc.signals).length === 0) {
      lines.push('No signals recorded.');
    } else {
      Object.keys(inc.signals).forEach(function (k) {
        lines.push('- **' + k + ':** ' + JSON.stringify(inc.signals[k]));
      });
    }
    lines.push('');

    // Timeline
    lines.push('## Timeline');
    inc.timeline.forEach(function (entry) {
      lines.push('- `' + new Date(entry.ts).toISOString() + '` [' + entry.action + '] ' + entry.detail);
    });
    lines.push('');

    // Notes
    if (inc.notes.length > 0) {
      lines.push('## Investigation Notes');
      inc.notes.forEach(function (n) {
        lines.push('- `' + new Date(n.ts).toISOString() + '` (' + n.author + '): ' + n.text);
      });
      lines.push('');
    }

    // Runbook
    if (inc.runbook) {
      lines.push('## Runbook: ' + inc.runbook.title);
      inc.runbook.steps.forEach(function (step, i) {
        lines.push((i + 1) + '. ' + step);
      });
      lines.push('');
    }

    // Resolution
    lines.push('## Resolution');
    lines.push(inc.resolution || '_Incident not yet resolved._');
    lines.push('');

    // Action items placeholder
    lines.push('## Action Items');
    lines.push('- [ ] Review root cause');
    lines.push('- [ ] Update runbooks if needed');
    lines.push('- [ ] Add monitoring for early detection');
    lines.push('- [ ] Share findings with team');

    return lines.join('\n');
  }

  // ── Export / Import ─────────────────────────────────────────────

  function exportJSON() {
    return JSON.stringify(Object.keys(incidents).map(function (k) { return incidents[k]; }), null, 2);
  }

  function importJSON(json) {
    var data = typeof json === 'string' ? JSON.parse(json) : json;
    if (!Array.isArray(data)) throw new Error('Expected array of incidents');
    data.forEach(function (inc) {
      if (inc.id) incidents[inc.id] = inc;
    });
    return data.length;
  }

  function exportCSV() {
    var headers = ['id', 'title', 'severity', 'state', 'source', 'responder', 'createdAt', 'acknowledgedAt', 'resolvedAt', 'ttaMs', 'ttrMs', 'resolution'];
    var rows = [headers.join(',')];
    Object.keys(incidents).forEach(function (k) {
      var inc = incidents[k];
      rows.push([
        inc.id,
        '"' + (inc.title || '').replace(/"/g, '""') + '"',
        inc.severity,
        inc.state,
        inc.source,
        inc.responder || '',
        inc.createdAt,
        inc.acknowledgedAt || '',
        inc.resolvedAt || '',
        inc.ttaMs != null ? inc.ttaMs : '',
        inc.ttrMs != null ? inc.ttrMs : '',
        '"' + (inc.resolution || '').replace(/"/g, '""') + '"'
      ].join(','));
    });
    return rows.join('\n');
  }

  // ── Cleanup ─────────────────────────────────────────────────────

  function purgeResolved(olderThanMs) {
    var cutoff = clock() - (olderThanMs || 86400000);
    var purged = 0;
    Object.keys(incidents).forEach(function (k) {
      var inc = incidents[k];
      if ((inc.state === 'resolved' || inc.state === 'closed') && inc.resolvedAt && inc.resolvedAt < cutoff) {
        delete incidents[k];
        purged++;
      }
    });
    return purged;
  }

  function destroy() {
    Object.keys(escalationTimers).forEach(function (k) {
      clearTimeout(escalationTimers[k]);
    });
    escalationTimers = {};
    incidents = {};
  }

  // ── Runbook access ──────────────────────────────────────────────

  function getRunbook(slug) {
    return runbooks[slug] || null;
  }

  function listRunbooks() {
    return Object.keys(runbooks).map(function (k) {
      return { slug: k, title: runbooks[k].title, steps: runbooks[k].steps.length };
    });
  }

  return {
    create: create,
    get: get,
    acknowledge: acknowledge,
    investigate: investigate,
    mitigate: mitigate,
    resolve: resolve,
    close: close,
    escalate: escalate,
    deescalate: deescalate,
    addNote: addNote,
    listOpen: listOpen,
    listAll: listAll,
    stats: stats,
    generatePostmortem: generatePostmortem,
    exportJSON: exportJSON,
    importJSON: importJSON,
    exportCSV: exportCSV,
    purgeResolved: purgeResolved,
    getRunbook: getRunbook,
    listRunbooks: listRunbooks,
    destroy: destroy
  };
}

module.exports = { createIncidentManager: createIncidentManager };
