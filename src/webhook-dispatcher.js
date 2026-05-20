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
const { secureRandomHex } = require("./crypto-utils");
const { _posOpt } = require("./shared-utils");

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
  /^0\.0\.0\.0$/,                     // Unspecified address
  /^\[?::ffff:/i,                     // IPv6-mapped IPv4
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

  // Block non-HTTP(S) protocols
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return true;

  // Block URLs with credentials (potential redirect-based SSRF)
  if (parsed.username || parsed.password) return true;

  var hostname = parsed.hostname;
  // Strip IPv6 brackets for pattern matching
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    hostname = hostname.slice(1, -1);
  }

  // Normalise IP addresses to catch octal, hex, and decimal bypass attempts.
  // Examples that would bypass string-based regex checks:
  //   0x7f000001          → 127.0.0.1  (hex)
  //   2130706433          → 127.0.0.1  (decimal)
  //   0177.0.0.1          → 127.0.0.1  (octal)
  //   ::ffff:127.0.0.1    → 127.0.0.1  (IPv6-mapped IPv4)
  //   ::ffff:10.0.0.1     → 10.0.0.1   (IPv6-mapped IPv4)
  var normalised = _normaliseIp(hostname);
  if (normalised) {
    hostname = normalised;
  }

  for (var i = 0; i < BLOCKED_HOST_PATTERNS.length; i++) {
    if (BLOCKED_HOST_PATTERNS[i].test(hostname)) return true;
  }

  // Block IPv6-mapped IPv4 that resolved to a private IPv4
  if (/^::ffff:/i.test(hostname)) {
    var mapped = hostname.replace(/^::ffff:/i, "");
    for (var j = 0; j < BLOCKED_HOST_PATTERNS.length; j++) {
      if (BLOCKED_HOST_PATTERNS[j].test(mapped)) return true;
    }
  }

  return false;
}

/**
 * Attempt to normalise non-standard IP representations to dotted-decimal.
 * Returns the normalised IPv4 string, or null if hostname is not an IP.
 *
 * Handles:
 *  - Single decimal integer (2130706433 → 127.0.0.1)
 *  - Octal octets (0177.0.0.01 → 127.0.0.1)
 *  - Hex integer (0x7f000001 → 127.0.0.1)
 *  - IPv6-mapped IPv4 (::ffff:127.0.0.1 → 127.0.0.1)
 *
 * @param {string} hostname
 * @returns {string|null} Normalised dotted-decimal IPv4, or null
 */
function _normaliseIp(hostname) {
  if (!hostname) return null;

  // IPv6-mapped IPv4 — extract the v4 portion
  var mappedMatch = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(hostname);
  if (mappedMatch) return mappedMatch[1];

  // Single hex integer (0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(hostname)) {
    var n = parseInt(hostname, 16);
    if (n >= 0 && n <= 0xffffffff) {
      return _intToIp(n);
    }
  }

  // Single decimal integer (2130706433)
  if (/^\d{4,10}$/.test(hostname)) {
    var d = parseInt(hostname, 10);
    if (d >= 0 && d <= 0xffffffff) {
      return _intToIp(d);
    }
  }

  // Dotted notation with possible octal octets (0177.0.0.01)
  var parts = hostname.split(".");
  if (parts.length === 4) {
    var hasOctal = false;
    var octets = [];
    for (var i = 0; i < 4; i++) {
      var p = parts[i];
      var val;
      if (/^0[0-7]+$/.test(p)) {
        // Octal
        val = parseInt(p, 8);
        hasOctal = true;
      } else if (/^0x[0-9a-f]+$/i.test(p)) {
        val = parseInt(p, 16);
        hasOctal = true;
      } else if (/^\d+$/.test(p)) {
        val = parseInt(p, 10);
      } else {
        return null; // Not a numeric IP
      }
      if (val < 0 || val > 255) return null;
      octets.push(val);
    }
    if (hasOctal) return octets.join(".");
  }

  return null;
}

/**
 * Convert a 32-bit integer to dotted-decimal IPv4.
 * @param {number} n
 * @returns {string}
 */
function _intToIp(n) {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join(".");
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
  this._paused = false;
}

// ── Helpers ─────────────────────────────────────────────────────────

function _generateId() {
  return "wh_" + secureRandomHex(12) + "_" + Date.now().toString(36);
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

  var id = _generateId();
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

/**
 * Check and consume one rate-limit token for a webhook.
 * Resets the window when more than 60 seconds have elapsed since the window start.
 *
 * @private
 * @param {string} id - Webhook identifier
 * @returns {boolean} True if the delivery is within rate limits
 */
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
    // Remove oldest 20% in place instead of creating a new array
    this._deliveryLog.splice(0, Math.ceil(this._maxLogSize * 0.2));
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

/**
 * Pause all webhook dispatching. Events fired while paused are silently dropped.
 */
WebhookDispatcher.prototype.pause = function () { this._paused = true; };

/**
 * Resume webhook dispatching after a pause.
 */
WebhookDispatcher.prototype.resume = function () { this._paused = false; };

/**
 * Check whether dispatching is currently paused.
 * @returns {boolean}
 */
WebhookDispatcher.prototype.isPaused = function () { return this._paused; };

// ── Verify Signature (static helper for consumers) ─────────────────

/**
 * Verify a webhook payload signature.
 * Consumers of the webhook can use this to validate authenticity.
 *
 * Hardening notes:
 *  - Strict type checks: only `string` payload/signature/secret are accepted.
 *    Buffer/object inputs are rejected outright rather than coerced via
 *    `Buffer.from(...)`, which previously could lead to unintended behaviour
 *    when an attacker supplied an object with a custom `toString()`.
 *  - Length-oracle resistant: when the supplied signature has a different
 *    byte length than the expected `sha256=<hex>` value, we still perform a
 *    same-length `timingSafeEqual(expBuf, expBuf)` call before returning
 *    false, so the rejection time does not vary with signature length
 *    (CWE-208 - Observable Timing Discrepancy).
 *  - HMAC computation is wrapped in try/catch so that malformed secrets
 *    (e.g. wrong type slipped past validation in older runtimes) cannot
 *    leak via an uncaught exception.
 *
 * @param {string} payload   - Raw JSON payload string
 * @param {string} signature - The X-GifCaptcha-Signature header value
 *                             (must be the full `sha256=<hex>` form)
 * @param {string} secret    - The shared secret
 * @returns {boolean} true if the signature is valid for (payload, secret)
 */
WebhookDispatcher.verifySignature = function (payload, signature, secret) {
  // Strict type validation - no coercion of objects/Buffers into strings.
  if (typeof payload !== "string" ||
      typeof signature !== "string" ||
      typeof secret !== "string") {
    return false;
  }
  if (payload.length === 0 || signature.length === 0 || secret.length === 0) {
    return false;
  }

  // Compute expected signature. Wrapped in try/catch in case createHmac
  // throws on an unsupported runtime or pathological secret.
  var expected;
  try {
    expected = "sha256=" + crypto.createHmac("sha256", secret).update(payload).digest("hex");
  } catch (e) {
    return false;
  }

  var sigBuf, expBuf;
  try {
    sigBuf = Buffer.from(signature, "utf8");
    expBuf = Buffer.from(expected, "utf8");
  } catch (e) {
    return false;
  }

  // Length-mismatch path: still perform a constant-time comparison against
  // a same-length buffer so the rejection time does not depend on how far
  // the lengths diverge. This closes a length-oracle side channel.
  if (sigBuf.length !== expBuf.length) {
    try { crypto.timingSafeEqual(expBuf, expBuf); } catch (_e) { /* ignore */ }
    return false;
  }

  try {
    return crypto.timingSafeEqual(sigBuf, expBuf);
  } catch (e) {
    return false;
  }
};

// ── Exports ─────────────────────────────────────────────────────────

WebhookDispatcher.EVENT_TYPES = EVENT_TYPES;
WebhookDispatcher.DEFAULTS = DEFAULTS;

module.exports = { WebhookDispatcher: WebhookDispatcher };
