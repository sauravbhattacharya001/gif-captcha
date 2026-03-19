/**
 * captcha-audit-log.js — Structured audit trail for CAPTCHA lifecycle events.
 *
 * Provides an immutable, queryable log of all CAPTCHA operations including
 * generation, solve attempts, failures, rate-limit hits, and admin actions.
 * Supports retention policies, search/filter, and JSON/CSV export.
 *
 * Usage:
 *   const { createAuditLog } = require('./captcha-audit-log');
 *   const log = createAuditLog({ maxEntries: 10000, retentionMs: 86400000 });
 *
 *   log.record('captcha.generated', { challengeId: 'abc', type: 'sequence' });
 *   log.record('captcha.solved',    { challengeId: 'abc', timeMs: 2340, ip: '1.2.3.4' });
 *   log.record('captcha.failed',    { challengeId: 'abc', reason: 'wrong_answer' });
 *   log.record('rate.limited',      { ip: '1.2.3.4', limit: 10 });
 *
 *   const entries = log.query({ event: 'captcha.failed', since: Date.now() - 3600000 });
 *   const stats   = log.stats();
 *   const csv     = log.exportCSV();
 *   const json    = log.exportJSON();
 *
 * @module captcha-audit-log
 */

"use strict";

var csvUtils = require("./csv-utils");

/**
 * Known event types for validation.
 */
const VALID_EVENTS = [
  'captcha.generated',
  'captcha.served',
  'captcha.solved',
  'captcha.failed',
  'captcha.expired',
  'captcha.refreshed',
  'rate.limited',
  'rate.warned',
  'pool.replenished',
  'pool.exhausted',
  'session.created',
  'session.destroyed',
  'config.changed',
  'admin.purge',
  'admin.export',
  'webhook.sent',
  'webhook.failed',
];

/**
 * Severity levels for audit entries.
 */
const SEVERITY = {
  DEBUG: 'debug',
  INFO: 'info',
  WARN: 'warn',
  ERROR: 'error',
  CRITICAL: 'critical',
};

const DEFAULT_SEVERITY_MAP = {
  'captcha.generated': SEVERITY.INFO,
  'captcha.served': SEVERITY.DEBUG,
  'captcha.solved': SEVERITY.INFO,
  'captcha.failed': SEVERITY.WARN,
  'captcha.expired': SEVERITY.INFO,
  'captcha.refreshed': SEVERITY.INFO,
  'rate.limited': SEVERITY.WARN,
  'rate.warned': SEVERITY.INFO,
  'pool.replenished': SEVERITY.DEBUG,
  'pool.exhausted': SEVERITY.ERROR,
  'session.created': SEVERITY.DEBUG,
  'session.destroyed': SEVERITY.DEBUG,
  'config.changed': SEVERITY.WARN,
  'admin.purge': SEVERITY.WARN,
  'admin.export': SEVERITY.INFO,
  'webhook.sent': SEVERITY.DEBUG,
  'webhook.failed': SEVERITY.ERROR,
};

let _nextId = 1;

/**
 * Create an audit log entry.
 * @param {string} event
 * @param {Object} data
 * @param {Object} opts
 * @returns {Object}
 */
function createEntry(event, data, opts) {
  const now = opts.now || Date.now();
  return Object.freeze({
    id: _nextId++,
    timestamp: now,
    event,
    severity: opts.severity || DEFAULT_SEVERITY_MAP[event] || SEVERITY.INFO,
    data: data ? Object.freeze({ ...data }) : Object.freeze({}),
    actor: opts.actor || null,
    correlationId: opts.correlationId || null,
  });
}

/**
 * CSV escaping delegated to shared csv-utils module.
 * @see csv-utils.js
 */
var csvEscape = csvUtils.csvEscape;

/**
 * Create a CAPTCHA audit log.
 *
 * @param {Object} [options]
 * @param {number} [options.maxEntries=10000] - Maximum entries to retain
 * @param {number} [options.retentionMs=0]    - Auto-purge entries older than this (0 = no auto-purge)
 * @param {boolean} [options.strictEvents=false] - Reject unknown event types
 * @param {Function} [options.onRecord]       - Callback on each record
 * @returns {Object}
 */
function createAuditLog(options = {}) {
  const maxEntries = Math.max(1, options.maxEntries || 10000);
  const retentionMs = Math.max(0, options.retentionMs || 0);
  const strictEvents = options.strictEvents || false;
  const onRecord = typeof options.onRecord === 'function' ? options.onRecord : null;

  /** @type {Object[]} */
  let entries = [];

  /**
   * Purge entries exceeding maxEntries or retention policy.
   */
  function _enforce() {
    if (retentionMs > 0) {
      const cutoff = Date.now() - retentionMs;
      entries = entries.filter(e => e.timestamp >= cutoff);
    }
    if (entries.length > maxEntries) {
      entries = entries.slice(entries.length - maxEntries);
    }
  }

  /**
   * Record an audit event.
   * @param {string} event - Event type (e.g. 'captcha.solved')
   * @param {Object} [data] - Arbitrary event data
   * @param {Object} [opts] - Extra options: severity, actor, correlationId, now
   * @returns {Object} The created entry
   */
  function record(event, data, opts = {}) {
    if (typeof event !== 'string' || !event.trim()) {
      throw new Error('Audit event type must be a non-empty string');
    }
    if (strictEvents && !VALID_EVENTS.includes(event)) {
      throw new Error(`Unknown audit event type: ${event}`);
    }
    if (opts.severity && !Object.values(SEVERITY).includes(opts.severity)) {
      throw new Error(`Invalid severity: ${opts.severity}`);
    }
    const entry = createEntry(event, data, opts);
    entries.push(entry);
    _enforce();
    if (onRecord) {
      try { onRecord(entry); } catch (_) { /* swallow callback errors */ }
    }
    return entry;
  }

  /**
   * Query audit entries with filters.
   * @param {Object} [filters]
   * @param {string} [filters.event]         - Exact event type
   * @param {string} [filters.eventPrefix]   - Event prefix (e.g. 'captcha.')
   * @param {string} [filters.severity]      - Exact severity
   * @param {string} [filters.minSeverity]   - Minimum severity level
   * @param {number} [filters.since]         - Entries after this timestamp
   * @param {number} [filters.until]         - Entries before this timestamp
   * @param {string} [filters.actor]         - Actor filter
   * @param {string} [filters.correlationId] - Correlation ID filter
   * @param {string} [filters.ip]            - IP in data
   * @param {string} [filters.challengeId]   - challengeId in data
   * @param {number} [filters.limit]         - Max entries to return
   * @param {string} [filters.order]         - 'asc' (default) or 'desc'
   * @returns {Object[]}
   */
  function query(filters = {}) {
    _enforce();
    const severityOrder = [SEVERITY.DEBUG, SEVERITY.INFO, SEVERITY.WARN, SEVERITY.ERROR, SEVERITY.CRITICAL];
    let result = entries;

    if (filters.event) {
      result = result.filter(e => e.event === filters.event);
    }
    if (filters.eventPrefix) {
      result = result.filter(e => e.event.startsWith(filters.eventPrefix));
    }
    if (filters.severity) {
      result = result.filter(e => e.severity === filters.severity);
    }
    if (filters.minSeverity) {
      const minIdx = severityOrder.indexOf(filters.minSeverity);
      if (minIdx >= 0) {
        result = result.filter(e => severityOrder.indexOf(e.severity) >= minIdx);
      }
    }
    if (filters.since != null) {
      result = result.filter(e => e.timestamp >= filters.since);
    }
    if (filters.until != null) {
      result = result.filter(e => e.timestamp <= filters.until);
    }
    if (filters.actor) {
      result = result.filter(e => e.actor === filters.actor);
    }
    if (filters.correlationId) {
      result = result.filter(e => e.correlationId === filters.correlationId);
    }
    if (filters.ip) {
      result = result.filter(e => e.data && e.data.ip === filters.ip);
    }
    if (filters.challengeId) {
      result = result.filter(e => e.data && e.data.challengeId === filters.challengeId);
    }
    if (filters.order === 'desc') {
      result = result.slice().reverse();
    }
    if (filters.limit != null && filters.limit > 0) {
      result = result.slice(0, filters.limit);
    }
    return result;
  }

  /**
   * Get aggregate statistics.
   * @returns {Object}
   */
  function stats() {
    _enforce();
    const byEvent = {};
    const bySeverity = {};
    let oldest = null;
    let newest = null;

    for (const e of entries) {
      byEvent[e.event] = (byEvent[e.event] || 0) + 1;
      bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
      if (oldest === null || e.timestamp < oldest) oldest = e.timestamp;
      if (newest === null || e.timestamp > newest) newest = e.timestamp;
    }

    const uniqueActors = new Set(entries.filter(e => e.actor).map(e => e.actor)).size;
    const uniqueIps = new Set(entries.filter(e => e.data && e.data.ip).map(e => e.data.ip)).size;
    const uniqueChallenges = new Set(
      entries.filter(e => e.data && e.data.challengeId).map(e => e.data.challengeId)
    ).size;

    return {
      totalEntries: entries.length,
      byEvent,
      bySeverity,
      uniqueActors,
      uniqueIps,
      uniqueChallenges,
      oldestTimestamp: oldest,
      newestTimestamp: newest,
      spanMs: oldest != null && newest != null ? newest - oldest : 0,
    };
  }

  /**
   * Get entries for a specific challenge across its lifecycle.
   * @param {string} challengeId
   * @returns {Object[]}
   */
  function traceChallenge(challengeId) {
    if (!challengeId) return [];
    return entries.filter(e => e.data && e.data.challengeId === challengeId);
  }

  /**
   * Get entries correlated by correlationId.
   * @param {string} correlationId
   * @returns {Object[]}
   */
  function traceCorrelation(correlationId) {
    if (!correlationId) return [];
    return entries.filter(e => e.correlationId === correlationId);
  }

  /**
   * Export all entries (or filtered) as CSV.
   * @param {Object} [filters] - Same filters as query()
   * @returns {string}
   */
  function exportCSV(filters) {
    const data = filters ? query(filters) : entries;
    const header = 'id,timestamp,event,severity,actor,correlationId,data';
    const rows = data.map(e =>
      [
        e.id,
        new Date(e.timestamp).toISOString(),
        csvEscape(e.event),
        e.severity,
        csvEscape(e.actor || ''),
        csvEscape(e.correlationId || ''),
        csvEscape(JSON.stringify(e.data)),
      ].join(',')
    );
    return [header, ...rows].join('\n');
  }

  /**
   * Export all entries (or filtered) as JSON.
   * @param {Object} [filters] - Same filters as query()
   * @returns {string}
   */
  function exportJSON(filters) {
    const data = filters ? query(filters) : entries;
    return JSON.stringify(data, null, 2);
  }

  /**
   * Import entries from a JSON string (merge).
   * @param {string} jsonStr
   * @returns {number} Number of entries imported
   */
  function importJSON(jsonStr) {
    const imported = JSON.parse(jsonStr);
    if (!Array.isArray(imported)) throw new Error('Expected JSON array');
    let count = 0;
    for (const item of imported) {
      if (!item.event || typeof item.event !== 'string' || !item.event.trim()) continue;
      if (!item.timestamp || typeof item.timestamp !== 'number') continue;
      // Respect strictEvents setting — reject unknown event types on import
      // just as record() does.  Without this check an attacker could inject
      // arbitrary event types via a crafted JSON file, bypassing validation.
      if (strictEvents && !VALID_EVENTS.includes(item.event)) continue;
      // Validate severity if present
      const sev = item.severity && Object.values(SEVERITY).includes(item.severity)
        ? item.severity : SEVERITY.INFO;
      const entry = Object.freeze({
        id: _nextId++,
        timestamp: item.timestamp,
        event: item.event,
        severity: sev,
        data: item.data && typeof item.data === 'object' && !Array.isArray(item.data)
          ? Object.freeze({ ...item.data }) : Object.freeze({}),
        actor: typeof item.actor === 'string' ? item.actor : null,
        correlationId: typeof item.correlationId === 'string' ? item.correlationId : null,
      });
      entries.push(entry);
      count++;
    }
    _enforce();
    return count;
  }

  /**
   * Purge entries matching filters, or all if no filters.
   * @param {Object} [filters] - event, before (timestamp)
   * @returns {number} Number of entries purged
   */
  function purge(filters = {}) {
    const before = entries.length;
    if (!filters.event && filters.before == null) {
      entries = [];
    } else {
      entries = entries.filter(e => {
        if (filters.event && e.event === filters.event) return false;
        if (filters.before != null && e.timestamp < filters.before) return false;
        return true;
      });
    }
    const purged = before - entries.length;
    if (purged > 0) {
      record('admin.purge', { purgedCount: purged, filters });
    }
    return purged;
  }

  /**
   * Get the total number of entries.
   * @returns {number}
   */
  function size() {
    _enforce();
    return entries.length;
  }

  /**
   * Get all entries (snapshot).
   * @returns {Object[]}
   */
  function all() {
    _enforce();
    return entries.slice();
  }

  return {
    record,
    query,
    stats,
    traceChallenge,
    traceCorrelation,
    exportCSV,
    exportJSON,
    importJSON,
    purge,
    size,
    all,
    VALID_EVENTS,
    SEVERITY,
  };
}

module.exports = { createAuditLog, VALID_EVENTS, SEVERITY };
