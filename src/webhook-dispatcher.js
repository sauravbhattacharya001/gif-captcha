"use strict";

/**
 * Webhook Dispatcher — sends CAPTCHA lifecycle event notifications
 * to registered HTTP endpoints.
 *
 * Features:
 * - Register/unregister webhook URLs with event filters
 * - Retry with exponential backoff on failures
 * - HMAC-SHA256 signature verification for payload integrity
 * - Rate limiting per endpoint to prevent flooding
 * - Delivery logging with success/failure tracking
 * - Configurable timeout and max retries
 *
 * @module webhook-dispatcher
 */

const crypto = require("crypto");
const { _posOpt } = require("./option-utils");

// ── Default Config ──────────────────────────────────────────────────

const DEFAULTS = {
  maxRetries: 3,
  baseDelayMs: 1000,
  timeoutMs: 5000,
  maxWebhooks: 50,
  rateLimitPerMinute: 60,
  payloadMaxBytes: 65536,
};

// ── Event Types ─────────────────────────────────────────────────────

const EVENT_TYPES = [
  "captcha.created",
  "captcha.solved",
  "captcha.failed",
  "captcha.expired",
  "captcha.suspicious",
  "captcha.blocked",
  "session.started",
  "session.completed",
  "trust.updated",
  "rate.exceeded",
];

// ── SSRF Protection ─────────────────────────────────────────────────

/**
 * Private/reserved IPv4 and IPv6 ranges that must be blocked to prevent
 * Server-Side Request Forgery (SSRF) attacks via webhook registration.
 *
 * Covers RFC 1918, loopback, link-local, multicast, and cloud metadata
 * endpoints (169.254.169.254).
 */
const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,                           // IPv4 loopback
  /^10\./,                            // RFC 1918 Class A
  /^172\.(1[6-9]|2\d|3[01])\./,      // RFC 1918 Class B
  /^192\.168\./,                      // RFC 1918 Class C
  /^169\.254\./,                      // Link-local / cloud metadata
  /^0\./,                             // "This" network
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // RFC 6598 (CGNAT)
  /^198\.1[89]\./,                    // RFC 2544 benchmarking
  /^192\.0\.0\./,                     // IETF protocol assignments
  /^192\.0\.2\./,                     // TEST-NET-1
  /^198\.51\.100\./,                  // TEST-NET-2
  /^203\.0\.113\./,                   // TEST-NET-3
  /^\[?::1\]?$/,                      // IPv6 loopback
  /^\[?fe80:/i,                       // IPv6 link-local
  /^\[?fc00:/i,                       // IPv6 unique local (ULA)
  /^\[?fd/i,                          // IPv6 ULA
];

/**
 * Check whether a URL targets a private/internal host.
 * Returns true if the URL should be blocked (SSRF risk).
 *
 * @param {string} urlStr - The webhook URL to validate
 * @returns {boolean}
 */
function _isBlockedUrl(urlStr) {
  var parsed;
  try {
    parsed = new URL(urlStr);
  } catch (e) {
    return true; // Unparseable → block
  }
  var hostname = parsed.hostname;
  // Strip IPv6 brackets for pattern matching
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    hostname = hostname.slice(1, -1);
  }
  for (var i = 0; i < BLOCKED_HOST_PATTERNS.length; i++) {
    if (BLOCKED_HOST_PATTERNS[i].test(hostname)) return true;
  }
  return false;
}

// ── Webhook Dispatcher ─────────────────────────────────────────────

function WebhookDispatcher(options) {
  options = options || {};
  this._maxRetries = _posOpt(options.maxRetries, DEFAULTS.maxRetries);
  this._baseDelayMs = _posOpt(options.baseDelayMs, DEFAULTS.baseDelayMs);
  this._timeoutMs = _posOpt(options.timeoutMs, DEFAULTS.timeoutMs);
  this._maxWebhooks = _posOpt(options.maxWebhooks, DEFAULTS.maxWebhooks);
  this._rateLimitPerMinute = _posOpt(options.rateLimitPerMinute, DEFAULTS.rateLimitPerMinute);
  this._payloadMaxBytes = _posOpt(options.payloadMaxBytes, DEFAULTS.payloadMaxBytes);

  // httpPost: async function(url, headers, body) => { status, body }
  // Must be injected — no hard dependency on any HTTP lib
  this._httpPost = options.httpPost || null;

  this._webhooks = new Map(); // id → webhook config
  this._deliveryLog = []; // recent deliveries
  this._maxLogSize = _posOpt(options.maxLogSize, 500);
  this._rateBuckets = new Map(); // webhookId → { count, windowStart }
  this._idCounter = 0;
  this._paused = false;
}

// ── Helpers ─────────────────────────────────────────────────────────

function _generateId(counter) {
  return "wh_" + Date.now().toString(36) + "_" + counter;
}

function _signPayload(payload, secret) {
  if (!secret) return null;
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

// ── Registration ────────────────────────────────────────────────────

/**
 * Register a webhook endpoint.
 *
 * @param {Object} config
 * @param {string} config.url - The endpoint URL
 * @param {string[]} [config.events] - Event types to subscribe to (default: all)
 * @param {string} [config.secret] - HMAC secret for signature verification
 * @param {string} [config.description] - Human-readable description
 * @param {Object} [config.headers] - Extra headers to include
 * @returns {{ id: string }} The registered webhook ID
 */
WebhookDispatcher.prototype.register = function (config) {
  if (!config || !config.url) {
    throw new Error("Webhook URL is required");
  }
  if (typeof config.url !== "string" || !/^https?:\/\//i.test(config.url)) {
    throw new Error("Invalid webhook URL: must start with http:// or https://");
  }
  if (_isBlockedUrl(config.url)) {
    throw new Error(
      "Webhook URL targets a private/reserved network address (SSRF protection). " +
      "Only public internet endpoints are allowed."
    );
  }
  if (this._webhooks.size >= this._maxWebhooks) {
    throw new Error("Maximum webhook limit reached (" + this._maxWebhooks + ")");
  }

  var events = config.events || EVENT_TYPES.slice();
  // Validate event types
  for (var i = 0; i < events.length; i++) {
    if (EVENT_TYPES.indexOf(events[i]) === -1) {
      throw new Error("Unknown event type: " + events[i]);
    }
  }

  var id = _generateId(++this._idCounter);
  this._webhooks.set(id, {
    id: id,
    url: config.url,
    events: events,
    secret: config.secret || null,
    description: config.description || "",
    headers: config.headers || {},
    active: true,
    createdAt: Date.now(),
    stats: { sent: 0, failed: 0, lastDelivery: null },
  });

  return { id: id };
};

/**
 * Unregister a webhook by ID.
 * @param {string} id
 * @returns {boolean}
 */
WebhookDispatcher.prototype.unregister = function (id) {
  return this._webhooks.delete(id);
};

/**
 * Enable or disable a webhook without removing it.
 * @param {string} id
 * @param {boolean} active
 */
WebhookDispatcher.prototype.setActive = function (id, active) {
  var wh = this._webhooks.get(id);
  if (!wh) throw new Error("Webhook not found: " + id);
  wh.active = !!active;
};

/**
 * List all registered webhooks.
 * @returns {Object[]}
 */
WebhookDispatcher.prototype.list = function () {
  var result = [];
  this._webhooks.forEach(function (wh) {
    result.push({
      id: wh.id,
      url: wh.url,
      events: wh.events.slice(),
      active: wh.active,
      description: wh.description,
      stats: Object.assign({}, wh.stats),
      createdAt: wh.createdAt,
    });
  });
  return result;
};

// ── Rate Limiting ───────────────────────────────────────────────────

WebhookDispatcher.prototype._checkRateLimit = function (id) {
  var now = Date.now();
  var bucket = this._rateBuckets.get(id);
  if (!bucket || now - bucket.windowStart > 60000) {
    this._rateBuckets.set(id, { count: 1, windowStart: now });
    return true;
  }
  if (bucket.count >= this._rateLimitPerMinute) {
    return false;
  }
  bucket.count++;
  return true;
};

// ── Dispatch ────────────────────────────────────────────────────────

/**
 * Dispatch an event to all matching webhooks.
 *
 * @param {string} eventType - One of EVENT_TYPES
 * @param {Object} data - Event payload data
 * @returns {Promise<Object[]>} Delivery results
 */
WebhookDispatcher.prototype.dispatch = function (eventType, data) {
  if (this._paused) return Promise.resolve([]);
  if (EVENT_TYPES.indexOf(eventType) === -1) {
    return Promise.reject(new Error("Unknown event type: " + eventType));
  }

  var self = this;
  var payload = JSON.stringify({
    event: eventType,
    timestamp: new Date().toISOString(),
    data: data || {},
  });

  if (Buffer.byteLength(payload) > this._payloadMaxBytes) {
    return Promise.reject(new Error("Payload exceeds maximum size"));
  }

  var targets = [];
  this._webhooks.forEach(function (wh) {
    if (wh.active && wh.events.indexOf(eventType) !== -1) {
      targets.push(wh);
    }
  });

  if (targets.length === 0) return Promise.resolve([]);

  var deliveries = targets.map(function (wh) {
    return self._deliver(wh, eventType, payload);
  });

  return Promise.all(deliveries);
};

/**
 * Deliver payload to a single webhook with retries.
 * @private
 */
WebhookDispatcher.prototype._deliver = function (wh, eventType, payload) {
  var self = this;

  if (!this._checkRateLimit(wh.id)) {
    var result = {
      webhookId: wh.id,
      event: eventType,
      status: "rate_limited",
      timestamp: Date.now(),
    };
    self._addLog(result);
    return Promise.resolve(result);
  }

  if (!this._httpPost) {
    // No HTTP transport — log as skipped
    var skipped = {
      webhookId: wh.id,
      event: eventType,
      status: "no_transport",
      timestamp: Date.now(),
    };
    self._addLog(skipped);
    return Promise.resolve(skipped);
  }

  var headers = Object.assign({}, wh.headers, {
    "Content-Type": "application/json",
    "X-GifCaptcha-Event": eventType,
    "X-GifCaptcha-Timestamp": new Date().toISOString(),
  });

  var signature = _signPayload(payload, wh.secret);
  if (signature) {
    headers["X-GifCaptcha-Signature"] = "sha256=" + signature;
  }

  return self._attemptDelivery(wh, headers, payload, eventType, 0);
};

/**
 * Attempt delivery with exponential backoff retries.
 * @private
 */
WebhookDispatcher.prototype._attemptDelivery = function (wh, headers, payload, eventType, attempt) {
  var self = this;

  return this._httpPost(wh.url, headers, payload)
    .then(function (response) {
      var success = response && response.status >= 200 && response.status < 300;
      wh.stats.lastDelivery = Date.now();

      if (success) {
        wh.stats.sent++;
        var result = {
          webhookId: wh.id,
          event: eventType,
          status: "delivered",
          statusCode: response.status,
          attempt: attempt + 1,
          timestamp: Date.now(),
        };
        self._addLog(result);
        return result;
      }

      // Non-2xx — retry if attempts remain
      if (attempt < self._maxRetries - 1) {
        var delay = self._baseDelayMs * Math.pow(2, attempt);
        return new Promise(function (resolve) {
          setTimeout(function () {
            resolve(self._attemptDelivery(wh, headers, payload, eventType, attempt + 1));
          }, delay);
        });
      }

      wh.stats.failed++;
      var failResult = {
        webhookId: wh.id,
        event: eventType,
        status: "failed",
        statusCode: response.status,
        attempts: attempt + 1,
        timestamp: Date.now(),
      };
      self._addLog(failResult);
      return failResult;
    })
    .catch(function (err) {
      if (attempt < self._maxRetries - 1) {
        var delay = self._baseDelayMs * Math.pow(2, attempt);
        return new Promise(function (resolve) {
          setTimeout(function () {
            resolve(self._attemptDelivery(wh, headers, payload, eventType, attempt + 1));
          }, delay);
        });
      }

      wh.stats.failed++;
      var errorResult = {
        webhookId: wh.id,
        event: eventType,
        status: "error",
        error: err.message,
        attempts: attempt + 1,
        timestamp: Date.now(),
      };
      self._addLog(errorResult);
      return errorResult;
    });
};

// ── Delivery Log ────────────────────────────────────────────────────

WebhookDispatcher.prototype._addLog = function (entry) {
  this._deliveryLog.push(entry);
  if (this._deliveryLog.length > this._maxLogSize) {
    this._deliveryLog = this._deliveryLog.slice(-Math.floor(this._maxLogSize * 0.8));
  }
};

/**
 * Get delivery log, optionally filtered.
 * @param {Object} [filter]
 * @param {string} [filter.webhookId]
 * @param {string} [filter.event]
 * @param {string} [filter.status]
 * @param {number} [filter.limit]
 * @returns {Object[]}
 */
WebhookDispatcher.prototype.getDeliveryLog = function (filter) {
  var log = this._deliveryLog;
  filter = filter || {};

  if (filter.webhookId) {
    log = log.filter(function (e) { return e.webhookId === filter.webhookId; });
  }
  if (filter.event) {
    log = log.filter(function (e) { return e.event === filter.event; });
  }
  if (filter.status) {
    log = log.filter(function (e) { return e.status === filter.status; });
  }

  if (filter.limit && filter.limit > 0) {
    log = log.slice(-filter.limit);
  }

  return log.slice();
};

/**
 * Get delivery statistics for a specific webhook.
 * @param {string} id
 * @returns {Object}
 */
WebhookDispatcher.prototype.getStats = function (id) {
  var wh = this._webhooks.get(id);
  if (!wh) throw new Error("Webhook not found: " + id);
  var log = this._deliveryLog.filter(function (e) { return e.webhookId === id; });
  var byEvent = {};
  log.forEach(function (e) {
    if (!byEvent[e.event]) byEvent[e.event] = { delivered: 0, failed: 0, rate_limited: 0 };
    if (e.status === "delivered") byEvent[e.event].delivered++;
    else if (e.status === "failed" || e.status === "error") byEvent[e.event].failed++;
    else if (e.status === "rate_limited") byEvent[e.event].rate_limited++;
  });
  return {
    id: id,
    url: wh.url,
    active: wh.active,
    totalSent: wh.stats.sent,
    totalFailed: wh.stats.failed,
    lastDelivery: wh.stats.lastDelivery,
    byEvent: byEvent,
  };
};

// ── Pause / Resume ──────────────────────────────────────────────────

WebhookDispatcher.prototype.pause = function () { this._paused = true; };
WebhookDispatcher.prototype.resume = function () { this._paused = false; };
WebhookDispatcher.prototype.isPaused = function () { return this._paused; };

// ── Verify Signature (static helper for consumers) ─────────────────

/**
 * Verify a webhook payload signature.
 * Consumers of the webhook can use this to validate authenticity.
 *
 * @param {string} payload - Raw JSON payload string
 * @param {string} signature - The X-GifCaptcha-Signature header value
 * @param {string} secret - The shared secret
 * @returns {boolean}
 */
WebhookDispatcher.verifySignature = function (payload, signature, secret) {
  if (!payload || !signature || !secret) return false;
  var expected = "sha256=" + crypto.createHmac("sha256", secret).update(payload).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch (e) {
    return false; // Length mismatch
  }
};

// ── Exports ─────────────────────────────────────────────────────────

WebhookDispatcher.EVENT_TYPES = EVENT_TYPES;
WebhookDispatcher.DEFAULTS = DEFAULTS;

module.exports = { WebhookDispatcher: WebhookDispatcher };
