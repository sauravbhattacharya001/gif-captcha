/**
 * Behavioral Biometrics Analyzer for gif-captcha
 *
 * Collects and analyzes mouse movement, click dynamics, and interaction
 * timing patterns to build behavioral signatures that distinguish humans
 * from bots. Works client-side to augment CAPTCHA challenges with
 * passive behavioral signals.
 *
 * @module gif-captcha/behavioral-biometrics
 */

"use strict";

// ── Statistics Helpers ──────────────────────────────────────────────

function mean(arr) {
  if (!arr || arr.length === 0) return 0;
  var sum = 0;
  for (var i = 0; i < arr.length; i++) sum += arr[i];
  return sum / arr.length;
}

function stddev(arr) {
  if (!arr || arr.length < 2) return 0;
  var m = mean(arr);
  var sqDiffs = 0;
  for (var i = 0; i < arr.length; i++) {
    var d = arr[i] - m;
    sqDiffs += d * d;
  }
  return Math.sqrt(sqDiffs / (arr.length - 1));
}


function entropy(arr) {
  if (!arr || arr.length < 2) return 0;
  var min = arr[0], max = arr[0];
  for (var i = 1; i < arr.length; i++) {
    if (arr[i] < min) min = arr[i];
    if (arr[i] > max) max = arr[i];
  }
  if (max === min) return 0;
  var buckets = Math.min(10, arr.length);
  var width = (max - min) / buckets;
  var counts = new Array(buckets);
  for (var j = 0; j < buckets; j++) counts[j] = 0;
  for (var k = 0; k < arr.length; k++) {
    var idx = Math.min(Math.floor((arr[k] - min) / width), buckets - 1);
    counts[idx]++;
  }
  var h = 0;
  for (var b = 0; b < buckets; b++) {
    if (counts[b] > 0) {
      var p = counts[b] / arr.length;
      h -= p * Math.log2(p);
    }
  }
  return h;
}

// ── Behavioral Biometrics Analyzer ──────────────────────────────────

/**
 * Create a behavioral biometrics analyzer.
 *
 * @param {Object} [options]
 * @param {number} [options.maxEvents=500]         Max events to buffer
 * @param {number} [options.humanScoreThreshold=0.5] Score above which session is likely human
 * @param {number} [options.minMouseEvents=5]      Min mouse events for analysis
 * @param {number} [options.minClickEvents=2]      Min click events for analysis
 * @param {number} [options.minKeystrokeEvents=3]  Min keystroke events for analysis
 * @param {boolean} [options.collectKeystrokes=false] Whether to collect keystroke timing
 * @returns {Object} Analyzer instance
 */
function createBehavioralBiometrics(options) {
  var opts = options || {};
  var maxEvents = (opts.maxEvents != null && opts.maxEvents > 0) ? opts.maxEvents : 500;
  var humanThreshold = (opts.humanScoreThreshold != null) ? opts.humanScoreThreshold : 0.5;
  var minMouse = (opts.minMouseEvents != null && opts.minMouseEvents > 0) ? opts.minMouseEvents : 5;
  var minClicks = (opts.minClickEvents != null && opts.minClickEvents > 0) ? opts.minClickEvents : 2;
  var minKeystrokes = (opts.minKeystrokeEvents != null && opts.minKeystrokeEvents > 0) ? opts.minKeystrokeEvents : 3;
  var collectKeystrokes = !!opts.collectKeystrokes;

  // Event buffers
  var mouseEvents = [];
  var clickEvents = [];
  var keystrokeEvents = [];
  var scrollEvents = [];

  // ── Recording ─────────────────────────────────────────────────

  /**
   * Record a mouse movement event.
   * @param {number} x - X coordinate
   * @param {number} y - Y coordinate
   * @param {number} [timestamp] - Event time (ms), defaults to Date.now()
   */
  function recordMouseMove(x, y, timestamp) {
    if (mouseEvents.length >= maxEvents) return;
    mouseEvents.push({
      x: x, y: y,
      t: timestamp != null ? timestamp : Date.now()
    });
  }

  /**
   * Record a click event.
   * @param {number} x - X coordinate
   * @param {number} y - Y coordinate
   * @param {string} [button='left'] - Button used
   * @param {number} [timestamp]
   */
  function recordClick(x, y, button, timestamp) {
    if (clickEvents.length >= maxEvents) return;
    clickEvents.push({
      x: x, y: y,
      button: button || "left",
      t: timestamp != null ? timestamp : Date.now()
    });
  }

  /**
   * Record a keystroke timing event (only timing, not the key itself).
   * @param {number} duration - Key hold duration in ms
   * @param {number} [timestamp]
   */
  function recordKeystroke(duration, timestamp) {
    if (!collectKeystrokes) return;
    if (keystrokeEvents.length >= maxEvents) return;
    keystrokeEvents.push({
      duration: duration,
      t: timestamp != null ? timestamp : Date.now()
    });
  }

  /**
   * Record a scroll event.
   * @param {number} deltaY - Scroll amount
   * @param {number} [timestamp]
   */
  function recordScroll(deltaY, timestamp) {
    if (scrollEvents.length >= maxEvents) return;
    scrollEvents.push({
      deltaY: deltaY,
      t: timestamp != null ? timestamp : Date.now()
    });
  }

  // ── Mouse Analysis ────────────────────────────────────────────

  function analyzeMouseMovement() {
    if (mouseEvents.length < minMouse) {
      return { sufficient: false, score: 0 };
    }

    var speeds = [];
    var angles = [];
    var accelerations = [];
    var curvatures = [];

    for (var i = 1; i < mouseEvents.length; i++) {
      var dx = mouseEvents[i].x - mouseEvents[i - 1].x;
      var dy = mouseEvents[i].y - mouseEvents[i - 1].y;
      var dt = mouseEvents[i].t - mouseEvents[i - 1].t;
      if (dt <= 0) continue;

      var dist = Math.sqrt(dx * dx + dy * dy);
      var speed = dist / dt;
      speeds.push(speed);
      angles.push(Math.atan2(dy, dx));

      if (speeds.length >= 2) {
        var accel = Math.abs(speed - speeds[speeds.length - 2]) / dt;
        accelerations.push(accel);
      }

      // Curvature from 3 consecutive points
      if (i >= 2) {
        var p0 = mouseEvents[i - 2];
        var p1 = mouseEvents[i - 1];
        var p2 = mouseEvents[i];
        var ax = p1.x - p0.x, ay = p1.y - p0.y;
        var bx = p2.x - p1.x, by = p2.y - p1.y;
        var cross = Math.abs(ax * by - ay * bx);
        var denom = Math.pow(ax * ax + ay * ay, 1.5);
        curvatures.push(denom > 0 ? cross / denom : 0);
      }
    }

    if (speeds.length === 0) return { sufficient: false, score: 0 };

    // Human indicators:
    // 1. Speed variability (bots often have constant speed)
    var speedCV = mean(speeds) > 0 ? stddev(speeds) / mean(speeds) : 0;
    var speedScore = Math.min(speedCV / 0.8, 1.0);

    // 2. Angle variability (bots move in straight lines)
    var angleEntropy = entropy(angles);
    var angleScore = Math.min(angleEntropy / 2.5, 1.0);

    // 3. Acceleration variability (humans accelerate/decelerate naturally)
    var accelVariability = accelerations.length > 1 ? stddev(accelerations) : 0;
    var accelScore = Math.min(accelVariability / 0.005, 1.0);

    // 4. Curvature presence (humans follow curved paths)
    var curvaturePresence = 0;
    for (var c = 0; c < curvatures.length; c++) {
      if (curvatures[c] > 0.001) curvaturePresence++;
    }
    var curvatureScore = curvatures.length > 0 ? curvaturePresence / curvatures.length : 0;

    var overall = (speedScore * 0.3 + angleScore * 0.3 + accelScore * 0.2 + curvatureScore * 0.2);

    return {
      sufficient: true,
      score: Math.round(overall * 1000) / 1000,
      eventCount: mouseEvents.length,
      metrics: {
        speedMean: Math.round(mean(speeds) * 1000) / 1000,
        speedStddev: Math.round(stddev(speeds) * 1000) / 1000,
        speedCV: Math.round(speedCV * 1000) / 1000,
        angleEntropy: Math.round(angleEntropy * 1000) / 1000,
        accelerationStddev: Math.round((accelerations.length > 0 ? stddev(accelerations) : 0) * 10000) / 10000,
        curvatureRatio: Math.round(curvatureScore * 1000) / 1000
      }
    };
  }

  // ── Click Analysis ────────────────────────────────────────────

  function analyzeClicks() {
    if (clickEvents.length < minClicks) {
      return { sufficient: false, score: 0 };
    }

    var intervals = [];
    var positions = [];
    for (var i = 0; i < clickEvents.length; i++) {
      positions.push({ x: clickEvents[i].x, y: clickEvents[i].y });
      if (i > 0) {
        intervals.push(clickEvents[i].t - clickEvents[i - 1].t);
      }
    }

    // 1. Click interval variability (bots click at regular intervals)
    var intervalCV = intervals.length > 0 && mean(intervals) > 0
      ? stddev(intervals) / mean(intervals)
      : 0;
    var intervalScore = Math.min(intervalCV / 0.5, 1.0);

    // 2. Position spread (bots often click exact same spot)
    var xs = [], ys = [];
    for (var j = 0; j < positions.length; j++) {
      xs.push(positions[j].x);
      ys.push(positions[j].y);
    }
    var posSpread = stddev(xs) + stddev(ys);
    var posScore = Math.min(posSpread / 100, 1.0);

    // 3. No two clicks at exact same position (bot signature)
    var uniquePositions = Object.create(null);
    var duplicates = 0;
    for (var k = 0; k < positions.length; k++) {
      var key = positions[k].x + "," + positions[k].y;
      if (uniquePositions[key]) duplicates++;
      uniquePositions[key] = true;
    }
    var uniqueScore = positions.length > 0 ? 1 - (duplicates / positions.length) : 0;

    var overall = (intervalScore * 0.4 + posScore * 0.3 + uniqueScore * 0.3);

    return {
      sufficient: true,
      score: Math.round(overall * 1000) / 1000,
      eventCount: clickEvents.length,
      metrics: {
        intervalMean: Math.round(mean(intervals) * 100) / 100,
        intervalCV: Math.round(intervalCV * 1000) / 1000,
        positionSpread: Math.round(posSpread * 100) / 100,
        duplicateRatio: positions.length > 0 ? Math.round((duplicates / positions.length) * 1000) / 1000 : 0
      }
    };
  }

  // ── Keystroke Analysis ────────────────────────────────────────

  function analyzeKeystrokes() {
    if (!collectKeystrokes || keystrokeEvents.length < minKeystrokes) {
      return { sufficient: false, score: 0 };
    }

    var durations = [];
    var intervals = [];
    for (var i = 0; i < keystrokeEvents.length; i++) {
      durations.push(keystrokeEvents[i].duration);
      if (i > 0) {
        intervals.push(keystrokeEvents[i].t - keystrokeEvents[i - 1].t);
      }
    }

    // 1. Hold duration variability
    var durationCV = mean(durations) > 0 ? stddev(durations) / mean(durations) : 0;
    var durationScore = Math.min(durationCV / 0.6, 1.0);

    // 2. Inter-key interval variability
    var intervalCV = intervals.length > 0 && mean(intervals) > 0
      ? stddev(intervals) / mean(intervals)
      : 0;
    var intervalScore = Math.min(intervalCV / 0.5, 1.0);

    // 3. Duration within human range (50-300ms typical)
    var inRange = 0;
    for (var j = 0; j < durations.length; j++) {
      if (durations[j] >= 30 && durations[j] <= 500) inRange++;
    }
    var rangeScore = durations.length > 0 ? inRange / durations.length : 0;

    var overall = (durationScore * 0.35 + intervalScore * 0.35 + rangeScore * 0.3);

    return {
      sufficient: true,
      score: Math.round(overall * 1000) / 1000,
      eventCount: keystrokeEvents.length,
      metrics: {
        durationMean: Math.round(mean(durations) * 100) / 100,
        durationCV: Math.round(durationCV * 1000) / 1000,
        intervalCV: Math.round(intervalCV * 1000) / 1000,
        humanRangeRatio: Math.round(rangeScore * 1000) / 1000
      }
    };
  }

  // ── Scroll Analysis ───────────────────────────────────────────

  function analyzeScrolls() {
    if (scrollEvents.length < 2) {
      return { sufficient: false, score: 0 };
    }

    var deltas = [];
    var intervals = [];
    for (var i = 0; i < scrollEvents.length; i++) {
      deltas.push(Math.abs(scrollEvents[i].deltaY));
      if (i > 0) {
        intervals.push(scrollEvents[i].t - scrollEvents[i - 1].t);
      }
    }

    // Variability in scroll deltas (humans scroll irregularly)
    var deltaCV = mean(deltas) > 0 ? stddev(deltas) / mean(deltas) : 0;
    var deltaScore = Math.min(deltaCV / 0.5, 1.0);

    // Direction changes (humans scroll up and down)
    var dirChanges = 0;
    for (var j = 1; j < scrollEvents.length; j++) {
      if ((scrollEvents[j].deltaY > 0) !== (scrollEvents[j - 1].deltaY > 0)) {
        dirChanges++;
      }
    }
    var dirScore = scrollEvents.length > 1 ? Math.min(dirChanges / (scrollEvents.length * 0.3), 1.0) : 0;

    var overall = (deltaScore * 0.5 + dirScore * 0.5);

    return {
      sufficient: true,
      score: Math.round(overall * 1000) / 1000,
      eventCount: scrollEvents.length,
      metrics: {
        deltaMean: Math.round(mean(deltas) * 100) / 100,
        deltaCV: Math.round(deltaCV * 1000) / 1000,
        directionChanges: dirChanges
      }
    };
  }

  // ── Combined Analysis ─────────────────────────────────────────

  /**
   * Run full behavioral analysis and return a combined human-likeness score.
   * @returns {Object} Analysis result with per-signal and combined scores
   */
  function analyze() {
    var mouse = analyzeMouseMovement();
    var clicks = analyzeClicks();
    var keystrokes = analyzeKeystrokes();
    var scrolls = analyzeScrolls();

    var signals = [];
    var weights = [];

    if (mouse.sufficient) { signals.push(mouse.score); weights.push(0.4); }
    if (clicks.sufficient) { signals.push(clicks.score); weights.push(0.25); }
    if (keystrokes.sufficient) { signals.push(keystrokes.score); weights.push(0.2); }
    if (scrolls.sufficient) { signals.push(scrolls.score); weights.push(0.15); }

    var combined = 0;
    if (signals.length > 0) {
      var totalWeight = 0;
      for (var i = 0; i < signals.length; i++) totalWeight += weights[i];
      for (var j = 0; j < signals.length; j++) combined += signals[j] * (weights[j] / totalWeight);
    }

    combined = Math.round(combined * 1000) / 1000;

    return {
      score: combined,
      isLikelyHuman: combined >= humanThreshold,
      signalCount: signals.length,
      signals: {
        mouse: mouse,
        clicks: clicks,
        keystrokes: keystrokes,
        scrolls: scrolls
      },
      threshold: humanThreshold,
      totalEvents: mouseEvents.length + clickEvents.length + keystrokeEvents.length + scrollEvents.length
    };
  }

  /**
   * Get a compact risk assessment.
   * @returns {Object} { risk: 'low'|'medium'|'high', score, reason }
   */
  function getRiskLevel() {
    var result = analyze();
    var risk, reason;

    if (result.signalCount === 0) {
      risk = "high";
      reason = "No behavioral data collected";
    } else if (result.score >= 0.7) {
      risk = "low";
      reason = "Strong human behavioral patterns detected";
    } else if (result.score >= humanThreshold) {
      risk = "medium";
      reason = "Some human patterns but inconclusive";
    } else {
      risk = "high";
      reason = "Behavioral patterns suggest automation";
    }

    return {
      risk: risk,
      score: result.score,
      reason: reason,
      signalCount: result.signalCount
    };
  }

  /**
   * Reset all collected events.
   */
  function reset() {
    mouseEvents.length = 0;
    clickEvents.length = 0;
    keystrokeEvents.length = 0;
    scrollEvents.length = 0;
  }

  /**
   * Get event counts.
   * @returns {Object}
   */
  function getEventCounts() {
    return {
      mouse: mouseEvents.length,
      clicks: clickEvents.length,
      keystrokes: keystrokeEvents.length,
      scrolls: scrollEvents.length,
      total: mouseEvents.length + clickEvents.length + keystrokeEvents.length + scrollEvents.length
    };
  }

  /**
   * Export collected events for server-side verification.
   * @returns {Object} Serializable event data
   */
  function exportEvents() {
    return {
      mouse: mouseEvents.slice(),
      clicks: clickEvents.slice(),
      keystrokes: collectKeystrokes ? keystrokeEvents.slice() : [],
      scrolls: scrollEvents.slice(),
      exportedAt: Date.now()
    };
  }

  return {
    recordMouseMove: recordMouseMove,
    recordClick: recordClick,
    recordKeystroke: recordKeystroke,
    recordScroll: recordScroll,
    analyze: analyze,
    analyzeMouseMovement: analyzeMouseMovement,
    analyzeClicks: analyzeClicks,
    analyzeKeystrokes: analyzeKeystrokes,
    analyzeScrolls: analyzeScrolls,
    getRiskLevel: getRiskLevel,
    getEventCounts: getEventCounts,
    exportEvents: exportEvents,
    reset: reset
  };
}

// ── Exports ─────────────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createBehavioralBiometrics: createBehavioralBiometrics };
}
