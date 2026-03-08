"use strict";

/**
 * ChallengeTemplateEngine — procedural challenge generation from templates.
 *
 * Instead of a fixed set of GIF challenges, this engine generates infinite
 * variations from parameterized templates.  Each template defines a question
 * pattern, parameter slots, and validation logic.  This makes bot training
 * exponentially harder because the challenge space is combinatorial.
 *
 * Built-in template types:
 *   - color_shape: "Click the [COLOR] [SHAPE]"
 *   - sequence:    "What comes next: [A, B, C, ?]"
 *   - counting:    "How many [OBJECT]s are in the image?"
 *   - odd_one_out: "Which item does not belong?"
 *   - spatial:     "Click the item in the [POSITION]"
 *   - temporal:    "Which frame shows [EVENT]?"
 *
 * Usage:
 *   var engine = createChallengeTemplateEngine();
 *   engine.registerTemplate({ ... });   // or use built-ins
 *   var challenge = engine.generate();  // random from all templates
 *   var result = engine.validate(challenge.id, userAnswer);
 *
 * @module gif-captcha/challenge-template-engine
 */

// ── Deterministic PRNG (xorshift32) for reproducible generation ─────

function _xorshift32(seed) {
  var state = seed | 0 || 1;
  return function () {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return (state >>> 0) / 4294967296;
  };
}

// ── Built-in parameter pools ────────────────────────────────────────

var COLORS = [
  "red", "blue", "green", "yellow", "purple", "orange",
  "pink", "cyan", "brown", "gray", "white", "black"
];

var SHAPES = [
  "circle", "square", "triangle", "star", "diamond",
  "hexagon", "pentagon", "oval", "rectangle", "heart"
];

var POSITIONS = [
  "top-left", "top-center", "top-right",
  "middle-left", "center", "middle-right",
  "bottom-left", "bottom-center", "bottom-right"
];

var OBJECTS = [
  "cat", "dog", "bird", "tree", "car", "house",
  "flower", "ball", "fish", "butterfly", "cloud", "sun"
];

var EVENTS = [
  "appears", "disappears", "changes color", "moves left",
  "moves right", "rotates", "grows", "shrinks", "flashes"
];

// ── Counter for unique IDs ──────────────────────────────────────────

var _globalCounter = 0;

function _uniqueId() {
  _globalCounter++;
  return "ct_" + Date.now().toString(36) + "_" + _globalCounter.toString(36);
}

// ── Utility ─────────────────────────────────────────────────────────

function _pick(arr, rng) {
  return arr[Math.floor(rng() * arr.length)];
}

function _pickN(arr, n, rng) {
  var copy = arr.slice();
  var result = [];
  n = Math.min(n, copy.length);
  for (var i = 0; i < n; i++) {
    var idx = Math.floor(rng() * copy.length);
    result.push(copy[idx]);
    copy.splice(idx, 1);
  }
  return result;
}

function _shuffle(arr, rng) {
  var copy = arr.slice();
  for (var i = copy.length - 1; i > 0; i--) {
    var j = Math.floor(rng() * (i + 1));
    var tmp = copy[i]; copy[i] = copy[j]; copy[j] = tmp;
  }
  return copy;
}

// ── Sequence generators ─────────────────────────────────────────────

var SEQUENCE_GENERATORS = {
  arithmetic: function (rng) {
    var start = Math.floor(rng() * 20) + 1;
    var step = Math.floor(rng() * 5) + 1;
    if (rng() < 0.3) step = -step;
    var seq = [];
    for (var i = 0; i < 4; i++) seq.push(start + step * i);
    return { shown: seq.slice(0, 3), answer: seq[3], hint: "arithmetic" };
  },
  geometric: function (rng) {
    var start = Math.floor(rng() * 5) + 1;
    var ratio = Math.floor(rng() * 3) + 2;
    var seq = [];
    for (var i = 0; i < 4; i++) seq.push(start * Math.pow(ratio, i));
    return { shown: seq.slice(0, 3), answer: seq[3], hint: "geometric" };
  },
  fibonacci: function (rng) {
    var a = Math.floor(rng() * 5) + 1;
    var b = Math.floor(rng() * 5) + a;
    var seq = [a, b];
    for (var i = 2; i < 5; i++) seq.push(seq[i - 1] + seq[i - 2]);
    return { shown: seq.slice(0, 4), answer: seq[4], hint: "additive" };
  },
  square: function (rng) {
    var offset = Math.floor(rng() * 3) + 1;
    var seq = [];
    for (var i = 0; i < 5; i++) seq.push((offset + i) * (offset + i));
    return { shown: seq.slice(0, 4), answer: seq[4], hint: "square numbers" };
  }
};

// ── Built-in template definitions ───────────────────────────────────

function _builtinTemplates() {
  return {
    color_shape: {
      name: "color_shape",
      description: "Click the [COLOR] [SHAPE]",
      category: "visual",
      difficulty: 1,
      parameterSpace: COLORS.length * SHAPES.length,
      generate: function (rng) {
        var targetColor = _pick(COLORS, rng);
        var targetShape = _pick(SHAPES, rng);
        var distractorCount = Math.floor(rng() * 3) + 3; // 3-5
        var distractors = [];
        for (var i = 0; i < distractorCount; i++) {
          var dc, ds;
          do {
            dc = _pick(COLORS, rng);
            ds = _pick(SHAPES, rng);
          } while (dc === targetColor && ds === targetShape);
          distractors.push({ color: dc, shape: ds });
        }
        var position = Math.floor(rng() * (distractorCount + 1));
        return {
          question: "Click the " + targetColor + " " + targetShape,
          target: { color: targetColor, shape: targetShape, position: position },
          distractors: distractors,
          answer: String(position),
          answerType: "position"
        };
      },
      validate: function (params, userAnswer) {
        return String(userAnswer) === String(params.answer);
      }
    },

    sequence: {
      name: "sequence",
      description: "What comes next in the sequence?",
      category: "cognitive",
      difficulty: 2,
      parameterSpace: 10000,
      generate: function (rng) {
        var types = Object.keys(SEQUENCE_GENERATORS);
        var type = _pick(types, rng);
        var seq = SEQUENCE_GENERATORS[type](rng);
        return {
          question: "What comes next: " + seq.shown.join(", ") + ", ?",
          shown: seq.shown,
          answer: String(seq.answer),
          answerType: "number",
          hint: seq.hint
        };
      },
      validate: function (params, userAnswer) {
        return String(userAnswer).trim() === String(params.answer);
      }
    },

    counting: {
      name: "counting",
      description: "How many [OBJECT]s are in the image?",
      category: "visual",
      difficulty: 1,
      parameterSpace: OBJECTS.length * 10,
      generate: function (rng) {
        var target = _pick(OBJECTS, rng);
        var count = Math.floor(rng() * 8) + 1; // 1-8
        var otherObjects = [];
        var otherCount = Math.floor(rng() * 5) + 2;
        for (var i = 0; i < otherCount; i++) {
          var obj;
          do { obj = _pick(OBJECTS, rng); } while (obj === target);
          otherObjects.push({ object: obj, count: Math.floor(rng() * 4) + 1 });
        }
        return {
          question: "How many " + target + (count > 1 ? "s" : "") + " are there?",
          target: target,
          targetCount: count,
          others: otherObjects,
          answer: String(count),
          answerType: "number"
        };
      },
      validate: function (params, userAnswer) {
        return String(userAnswer).trim() === String(params.answer);
      }
    },

    odd_one_out: {
      name: "odd_one_out",
      description: "Which item does not belong?",
      category: "cognitive",
      difficulty: 2,
      parameterSpace: 5000,
      generate: function (rng) {
        // Pick a category (color or shape), select N from same group + 1 outlier
        var useColors = rng() < 0.5;
        var pool = useColors ? COLORS : SHAPES;
        var groupItems = _pickN(pool, 3, rng);
        var oddPool = useColors ? SHAPES : COLORS;
        var oddItem = _pick(oddPool, rng);
        var items = groupItems.concat([oddItem]);
        items = _shuffle(items, rng);
        var oddIndex = items.indexOf(oddItem);
        return {
          question: "Which item does not belong?",
          items: items,
          oddItem: oddItem,
          oddIndex: oddIndex,
          category: useColors ? "colors" : "shapes",
          answer: String(oddIndex),
          answerType: "index"
        };
      },
      validate: function (params, userAnswer) {
        return String(userAnswer).trim() === String(params.answer);
      }
    },

    spatial: {
      name: "spatial",
      description: "Click the item in the [POSITION]",
      category: "spatial",
      difficulty: 1,
      parameterSpace: POSITIONS.length * OBJECTS.length,
      generate: function (rng) {
        var targetPos = _pick(POSITIONS, rng);
        var targetObj = _pick(OBJECTS, rng);
        var others = [];
        var usedPositions = [targetPos];
        var availablePositions = POSITIONS.filter(function (p) { return p !== targetPos; });
        var otherCount = Math.min(Math.floor(rng() * 4) + 2, availablePositions.length);
        for (var i = 0; i < otherCount; i++) {
          var pos = availablePositions[i];
          usedPositions.push(pos);
          others.push({ object: _pick(OBJECTS, rng), position: pos });
        }
        return {
          question: "Click the item in the " + targetPos.replace(/-/g, " "),
          target: { object: targetObj, position: targetPos },
          others: others,
          answer: targetPos,
          answerType: "position"
        };
      },
      validate: function (params, userAnswer) {
        return String(userAnswer).trim().toLowerCase() ===
               String(params.answer).toLowerCase();
      }
    },

    temporal: {
      name: "temporal",
      description: "Which frame shows [EVENT]?",
      category: "temporal",
      difficulty: 3,
      parameterSpace: OBJECTS.length * EVENTS.length * 10,
      generate: function (rng) {
        var subject = _pick(OBJECTS, rng);
        var event = _pick(EVENTS, rng);
        var totalFrames = Math.floor(rng() * 6) + 4; // 4-9
        var targetFrame = Math.floor(rng() * totalFrames);
        var frames = [];
        for (var i = 0; i < totalFrames; i++) {
          frames.push({
            index: i,
            description: i === targetFrame
              ? subject + " " + event
              : _pick(OBJECTS, rng) + " is still"
          });
        }
        return {
          question: "Which frame shows the " + subject + " " + event + "?",
          subject: subject,
          event: event,
          frames: frames,
          targetFrame: targetFrame,
          answer: String(targetFrame),
          answerType: "frame_index"
        };
      },
      validate: function (params, userAnswer) {
        return String(userAnswer).trim() === String(params.answer);
      }
    }
  };
}

// ── Main factory ────────────────────────────────────────────────────

/**
 * Create a ChallengeTemplateEngine.
 *
 * @param {Object} [options]
 * @param {boolean} [options.includeBuiltins=true] - Include 6 built-in templates
 * @param {number}  [options.maxPending=10000]     - Max pending (unvalidated) challenges
 * @param {number}  [options.pendingTtlMs=300000]  - Pending challenge TTL (5 min)
 * @param {number}  [options.seed]                 - PRNG seed for reproducibility
 * @param {number}  [options.maxHistory=1000]      - Max completed challenge history
 * @returns {Object} Engine instance
 */
function createChallengeTemplateEngine(options) {
  options = options || {};
  var includeBuiltins = options.includeBuiltins !== false;
  var maxPending = options.maxPending > 0 ? options.maxPending : 10000;
  var pendingTtlMs = options.pendingTtlMs > 0 ? options.pendingTtlMs : 300000;
  var maxHistory = options.maxHistory > 0 ? options.maxHistory : 1000;

  var rng = typeof options.seed === "number"
    ? _xorshift32(options.seed)
    : function () { return Math.random(); };

  // ── State ───────────────────────────────────────────────────────

  var templates = {};     // name → template definition
  var templateNames = []; // ordered list for random selection
  var pending = {};       // challengeId → { templateName, params, createdAt }
  var pendingCount = 0;
  var history = [];       // completed challenges (ring buffer)
  var historyIndex = 0;

  // Per-template stats
  var stats = {};  // name → { generated, validated, passed, failed, avgResponseMs }

  // ── Init built-ins ──────────────────────────────────────────────

  if (includeBuiltins) {
    var builtins = _builtinTemplates();
    var bKeys = Object.keys(builtins);
    for (var bi = 0; bi < bKeys.length; bi++) {
      _registerInternal(bKeys[bi], builtins[bKeys[bi]]);
    }
  }

  // ── Template registration ───────────────────────────────────────

  function _registerInternal(name, tmpl) {
    templates[name] = tmpl;
    if (templateNames.indexOf(name) === -1) {
      templateNames.push(name);
    }
    if (!stats[name]) {
      stats[name] = {
        generated: 0, validated: 0, passed: 0, failed: 0,
        totalResponseMs: 0, avgResponseMs: 0
      };
    }
  }

  /**
   * Register a custom template.
   *
   * @param {Object} template
   * @param {string} template.name         - Unique template identifier
   * @param {string} [template.description] - Human-readable description
   * @param {string} [template.category]   - Category (visual/cognitive/spatial/temporal)
   * @param {number} [template.difficulty] - 1 (easy) to 5 (hard)
   * @param {number} [template.parameterSpace] - Approximate # of unique combos
   * @param {Function} template.generate   - function(rng) → params
   * @param {Function} template.validate   - function(params, answer) → boolean
   * @returns {boolean} true if registered
   */
  function registerTemplate(template) {
    if (!template || typeof template !== "object") return false;
    if (!template.name || typeof template.name !== "string") return false;
    if (typeof template.generate !== "function") return false;
    if (typeof template.validate !== "function") return false;

    _registerInternal(template.name, {
      name: template.name,
      description: template.description || "",
      category: template.category || "custom",
      difficulty: template.difficulty > 0 ? template.difficulty : 1,
      parameterSpace: template.parameterSpace || 0,
      generate: template.generate,
      validate: template.validate
    });
    return true;
  }

  /**
   * Unregister a template by name.
   *
   * @param {string} name
   * @returns {boolean} true if removed
   */
  function unregisterTemplate(name) {
    if (!templates[name]) return false;
    delete templates[name];
    var idx = templateNames.indexOf(name);
    if (idx !== -1) templateNames.splice(idx, 1);
    return true;
  }

  // ── Cleanup expired pending ─────────────────────────────────────

  function _cleanupExpired() {
    var now = Date.now();
    var ids = Object.keys(pending);
    for (var i = 0; i < ids.length; i++) {
      if (now - pending[ids[i]].createdAt > pendingTtlMs) {
        delete pending[ids[i]];
        pendingCount--;
      }
    }
  }

  // ── Challenge generation ────────────────────────────────────────

  /**
   * Generate a challenge from a random (or specific) template.
   *
   * @param {Object} [opts]
   * @param {string} [opts.templateName] - Specific template; random if omitted
   * @param {string} [opts.category]     - Filter by category before random pick
   * @param {number} [opts.minDifficulty] - Minimum difficulty filter
   * @param {number} [opts.maxDifficulty] - Maximum difficulty filter
   * @param {string} [opts.clientId]     - Client identifier for tracking
   * @returns {Object|null} Challenge object {id, templateName, question, params, createdAt} or null
   */
  function generate(opts) {
    opts = opts || {};
    if (templateNames.length === 0) return null;

    // Evict oldest pending if at capacity
    if (pendingCount >= maxPending) {
      _cleanupExpired();
      // If still full, evict oldest
      if (pendingCount >= maxPending) {
        var oldest = null, oldestId = null;
        var pids = Object.keys(pending);
        for (var pi = 0; pi < pids.length; pi++) {
          if (!oldest || pending[pids[pi]].createdAt < oldest) {
            oldest = pending[pids[pi]].createdAt;
            oldestId = pids[pi];
          }
        }
        if (oldestId) { delete pending[oldestId]; pendingCount--; }
      }
    }

    // Select template
    var name = opts.templateName;
    if (!name || !templates[name]) {
      var candidates = templateNames.slice();

      if (opts.category) {
        candidates = candidates.filter(function (n) {
          return templates[n].category === opts.category;
        });
      }
      if (typeof opts.minDifficulty === "number") {
        var minD = opts.minDifficulty;
        candidates = candidates.filter(function (n) {
          return templates[n].difficulty >= minD;
        });
      }
      if (typeof opts.maxDifficulty === "number") {
        var maxD = opts.maxDifficulty;
        candidates = candidates.filter(function (n) {
          return templates[n].difficulty <= maxD;
        });
      }
      if (candidates.length === 0) return null;
      name = _pick(candidates, rng);
    }

    var tmpl = templates[name];
    var params = tmpl.generate(rng);
    var id = _uniqueId();

    pending[id] = {
      templateName: name,
      params: params,
      createdAt: Date.now(),
      clientId: opts.clientId || null
    };
    pendingCount++;

    stats[name].generated++;

    return {
      id: id,
      templateName: name,
      category: tmpl.category,
      difficulty: tmpl.difficulty,
      question: params.question,
      answerType: params.answerType,
      // Include display-relevant data but NOT the answer
      displayData: _extractDisplayData(params),
      createdAt: pending[id].createdAt
    };
  }

  /**
   * Generate multiple challenges at once (batch).
   *
   * @param {number} count - Number of challenges
   * @param {Object} [opts] - Same as generate() opts
   * @returns {Array} Array of challenge objects
   */
  function generateBatch(count, opts) {
    count = Math.max(1, Math.min(count, 100));
    var results = [];
    for (var i = 0; i < count; i++) {
      var c = generate(opts);
      if (c) results.push(c);
    }
    return results;
  }

  function _extractDisplayData(params) {
    var data = {};
    // Include things needed for rendering, exclude the answer
    if (params.distractors) data.distractors = params.distractors;
    if (params.target && typeof params.target === "object") {
      // For color_shape: include target descriptor but not position
      data.targetDescription = {};
      if (params.target.color) data.targetDescription.color = params.target.color;
      if (params.target.shape) data.targetDescription.shape = params.target.shape;
      if (params.target.object) data.targetDescription.object = params.target.object;
      if (params.target.position && params.answerType !== "position") {
        data.targetDescription.position = params.target.position;
      }
    }
    if (params.items) data.items = params.items;
    if (params.shown) data.shown = params.shown;
    if (params.frames) data.frames = params.frames;
    if (params.others) data.others = params.others;
    if (params.targetCount !== undefined) data.itemCount = "?"; // don't leak
    return data;
  }

  // ── Validation ──────────────────────────────────────────────────

  /**
   * Validate a challenge answer.
   *
   * @param {string} challengeId - The challenge ID from generate()
   * @param {*}      userAnswer  - The user's answer
   * @returns {Object} { valid, correct, challengeId, templateName, responseMs } or null if not found
   */
  function validate(challengeId, userAnswer) {
    if (!pending[challengeId]) return null;

    var entry = pending[challengeId];
    var tmpl = templates[entry.templateName];
    if (!tmpl) {
      delete pending[challengeId];
      pendingCount--;
      return null;
    }

    var responseMs = Date.now() - entry.createdAt;
    var correct = tmpl.validate(entry.params, userAnswer);

    // Update stats
    var st = stats[entry.templateName];
    st.validated++;
    if (correct) st.passed++; else st.failed++;
    st.totalResponseMs += responseMs;
    st.avgResponseMs = Math.round(st.totalResponseMs / st.validated);

    // Add to history
    var record = {
      challengeId: challengeId,
      templateName: entry.templateName,
      category: tmpl.category,
      difficulty: tmpl.difficulty,
      correct: correct,
      responseMs: responseMs,
      clientId: entry.clientId,
      createdAt: entry.createdAt,
      validatedAt: Date.now()
    };

    if (history.length < maxHistory) {
      history.push(record);
    } else {
      history[historyIndex % maxHistory] = record;
    }
    historyIndex++;

    // Remove from pending
    delete pending[challengeId];
    pendingCount--;

    return {
      valid: true,
      correct: correct,
      challengeId: challengeId,
      templateName: entry.templateName,
      responseMs: responseMs
    };
  }

  // ── Stats & reporting ──────────────────────────────────────────

  /**
   * Get stats for all templates.
   *
   * @returns {Object} Per-template stats plus totals
   */
  function getStats() {
    var totalGenerated = 0, totalPassed = 0, totalFailed = 0;
    var perTemplate = {};

    for (var i = 0; i < templateNames.length; i++) {
      var name = templateNames[i];
      var st = stats[name];
      perTemplate[name] = {
        generated: st.generated,
        validated: st.validated,
        passed: st.passed,
        failed: st.failed,
        passRate: st.validated > 0
          ? Math.round(st.passed / st.validated * 1000) / 1000 : 0,
        avgResponseMs: st.avgResponseMs,
        category: templates[name].category,
        difficulty: templates[name].difficulty,
        parameterSpace: templates[name].parameterSpace
      };
      totalGenerated += st.generated;
      totalPassed += st.passed;
      totalFailed += st.failed;
    }

    return {
      templateCount: templateNames.length,
      totalGenerated: totalGenerated,
      totalValidated: totalPassed + totalFailed,
      totalPassed: totalPassed,
      totalFailed: totalFailed,
      overallPassRate: (totalPassed + totalFailed) > 0
        ? Math.round(totalPassed / (totalPassed + totalFailed) * 1000) / 1000 : 0,
      pendingCount: pendingCount,
      historySize: Math.min(history.length, maxHistory),
      perTemplate: perTemplate
    };
  }

  /**
   * Get the difficulty distribution: how many templates at each level.
   *
   * @returns {Object} { 1: count, 2: count, ... }
   */
  function getDifficultyDistribution() {
    var dist = {};
    for (var i = 0; i < templateNames.length; i++) {
      var d = templates[templateNames[i]].difficulty;
      dist[d] = (dist[d] || 0) + 1;
    }
    return dist;
  }

  /**
   * Get the total parameter space across all templates.
   *
   * @returns {number} Combined parameter space size
   */
  function getParameterSpace() {
    var total = 0;
    for (var i = 0; i < templateNames.length; i++) {
      total += templates[templateNames[i]].parameterSpace || 0;
    }
    return total;
  }

  /**
   * Get challenge categories with counts.
   *
   * @returns {Object} { category: count, ... }
   */
  function getCategories() {
    var cats = {};
    for (var i = 0; i < templateNames.length; i++) {
      var cat = templates[templateNames[i]].category;
      cats[cat] = (cats[cat] || 0) + 1;
    }
    return cats;
  }

  /**
   * List all registered template names.
   *
   * @returns {Array<string>}
   */
  function listTemplates() {
    return templateNames.slice();
  }

  /**
   * Get details for a specific template.
   *
   * @param {string} name
   * @returns {Object|null} Template info (without generate/validate functions)
   */
  function getTemplateInfo(name) {
    var t = templates[name];
    if (!t) return null;
    return {
      name: t.name,
      description: t.description,
      category: t.category,
      difficulty: t.difficulty,
      parameterSpace: t.parameterSpace,
      stats: stats[name] ? {
        generated: stats[name].generated,
        validated: stats[name].validated,
        passed: stats[name].passed,
        failed: stats[name].failed,
        passRate: stats[name].validated > 0
          ? Math.round(stats[name].passed / stats[name].validated * 1000) / 1000 : 0,
        avgResponseMs: stats[name].avgResponseMs
      } : null
    };
  }

  /**
   * Get completed challenge history.
   *
   * @param {Object} [opts]
   * @param {string} [opts.templateName] - Filter by template
   * @param {string} [opts.clientId]     - Filter by client
   * @param {boolean} [opts.correctOnly] - Only correct answers
   * @param {number}  [opts.limit]       - Max results
   * @returns {Array} History records
   */
  function getHistory(opts) {
    opts = opts || {};
    var results = history.slice();

    if (opts.templateName) {
      results = results.filter(function (r) {
        return r.templateName === opts.templateName;
      });
    }
    if (opts.clientId) {
      results = results.filter(function (r) {
        return r.clientId === opts.clientId;
      });
    }
    if (opts.correctOnly) {
      results = results.filter(function (r) { return r.correct; });
    }
    if (opts.limit > 0) {
      results = results.slice(-opts.limit);
    }
    return results;
  }

  /**
   * Identify templates that may be compromised (unusual pass rates).
   *
   * @param {Object} [opts]
   * @param {number} [opts.minSamples=20]    - Minimum validates before judging
   * @param {number} [opts.suspiciousRate=0.95] - Pass rate above this is suspicious
   * @param {number} [opts.tooHardRate=0.15]    - Pass rate below this is too hard
   * @returns {Array} Array of { name, issue, passRate, samples }
   */
  function findProblematicTemplates(opts) {
    opts = opts || {};
    var minSamples = opts.minSamples > 0 ? opts.minSamples : 20;
    var suspiciousRate = typeof opts.suspiciousRate === "number" ? opts.suspiciousRate : 0.95;
    var tooHardRate = typeof opts.tooHardRate === "number" ? opts.tooHardRate : 0.15;

    var problems = [];
    for (var i = 0; i < templateNames.length; i++) {
      var name = templateNames[i];
      var st = stats[name];
      if (st.validated < minSamples) continue;

      var passRate = st.passed / st.validated;
      if (passRate >= suspiciousRate) {
        problems.push({
          name: name, issue: "too_easy",
          passRate: Math.round(passRate * 1000) / 1000,
          samples: st.validated
        });
      } else if (passRate <= tooHardRate) {
        problems.push({
          name: name, issue: "too_hard",
          passRate: Math.round(passRate * 1000) / 1000,
          samples: st.validated
        });
      }

      // Check for suspiciously fast responses (bots)
      if (st.avgResponseMs < 500 && st.validated >= minSamples) {
        problems.push({
          name: name, issue: "suspiciously_fast",
          avgResponseMs: st.avgResponseMs,
          samples: st.validated
        });
      }
    }
    return problems;
  }

  /**
   * Export engine state for persistence.
   *
   * @returns {Object} Serializable state
   */
  function exportState() {
    return {
      stats: JSON.parse(JSON.stringify(stats)),
      history: history.slice(),
      historyIndex: historyIndex,
      templateNames: templateNames.slice(),
      pendingCount: pendingCount
    };
  }

  /**
   * Import previously exported stats (preserves templates, restores counters).
   *
   * @param {Object} state - From exportState()
   * @returns {boolean}
   */
  function importStats(state) {
    if (!state || typeof state !== "object") return false;
    if (state.stats) {
      var sKeys = Object.keys(state.stats);
      for (var i = 0; i < sKeys.length; i++) {
        if (stats[sKeys[i]]) {
          stats[sKeys[i]] = state.stats[sKeys[i]];
        }
      }
    }
    if (Array.isArray(state.history)) {
      history = state.history.slice();
      historyIndex = state.historyIndex || history.length;
    }
    return true;
  }

  /**
   * Reset all stats and history.
   */
  function reset() {
    var names = Object.keys(stats);
    for (var i = 0; i < names.length; i++) {
      stats[names[i]] = {
        generated: 0, validated: 0, passed: 0, failed: 0,
        totalResponseMs: 0, avgResponseMs: 0
      };
    }
    pending = {};
    pendingCount = 0;
    history = [];
    historyIndex = 0;
  }

  /**
   * Generate a human-readable summary report.
   *
   * @returns {string}
   */
  function generateReport() {
    var s = getStats();
    var lines = [
      "=== Challenge Template Engine Report ===",
      "",
      "Templates: " + s.templateCount,
      "Parameter space: " + getParameterSpace().toLocaleString() + " unique combinations",
      "Categories: " + Object.keys(getCategories()).join(", "),
      "",
      "Generated: " + s.totalGenerated,
      "Validated: " + s.totalValidated,
      "Pass rate: " + (s.overallPassRate * 100).toFixed(1) + "%",
      "Pending:   " + s.pendingCount,
      ""
    ];

    var names = templateNames.slice().sort();
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var st = s.perTemplate[name];
      lines.push(
        "[" + name + "] " +
        "cat=" + st.category +
        " diff=" + st.difficulty +
        " gen=" + st.generated +
        " pass=" + st.passRate * 100 + "%" +
        " avg=" + st.avgResponseMs + "ms"
      );
    }

    var problems = findProblematicTemplates();
    if (problems.length > 0) {
      lines.push("");
      lines.push("⚠ Issues:");
      for (var pi = 0; pi < problems.length; pi++) {
        var p = problems[pi];
        lines.push("  - " + p.name + ": " + p.issue +
          (p.passRate !== undefined ? " (" + p.passRate * 100 + "%)" : "") +
          (p.avgResponseMs !== undefined ? " (" + p.avgResponseMs + "ms)" : ""));
      }
    }

    return lines.join("\n");
  }

  // ── Public API ──────────────────────────────────────────────────

  return {
    registerTemplate: registerTemplate,
    unregisterTemplate: unregisterTemplate,
    generate: generate,
    generateBatch: generateBatch,
    validate: validate,
    getStats: getStats,
    getHistory: getHistory,
    getTemplateInfo: getTemplateInfo,
    listTemplates: listTemplates,
    getCategories: getCategories,
    getDifficultyDistribution: getDifficultyDistribution,
    getParameterSpace: getParameterSpace,
    findProblematicTemplates: findProblematicTemplates,
    exportState: exportState,
    importStats: importStats,
    reset: reset,
    generateReport: generateReport
  };
}

// ── UMD export ──────────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createChallengeTemplateEngine: createChallengeTemplateEngine };
} else if (typeof window !== "undefined") {
  window.createChallengeTemplateEngine = createChallengeTemplateEngine;
}
