"use strict";

var { describe, it } = require("node:test");
var assert = require("node:assert/strict");
var gifCaptcha = require("../src/index");

describe("createEventEmitter", function () {
  it("should create an emitter with expected API", function () {
    var em = gifCaptcha.createEventEmitter();
    assert.strictEqual(typeof em.on, "function");
    assert.strictEqual(typeof em.once, "function");
    assert.strictEqual(typeof em.off, "function");
    assert.strictEqual(typeof em.emit, "function");
    assert.strictEqual(typeof em.listeners, "function");
    assert.strictEqual(typeof em.removeAll, "function");
    assert.strictEqual(typeof em.pipe, "function");
  });

  it("should fire handlers and return count", function () {
    var em = gifCaptcha.createEventEmitter();
    var called = 0;
    em.on("challenge.created", function () { called++; });
    em.on("challenge.created", function () { called++; });
    var count = em.emit("challenge.created", { id: "a" });
    assert.strictEqual(count, 2);
    assert.strictEqual(called, 2);
  });

  it("on() should return unsubscribe function", function () {
    var em = gifCaptcha.createEventEmitter();
    var called = 0;
    var unsub = em.on("x", function () { called++; });
    em.emit("x");
    assert.strictEqual(called, 1);
    unsub();
    em.emit("x");
    assert.strictEqual(called, 1);
  });

  it("once() should fire only once", function () {
    var em = gifCaptcha.createEventEmitter();
    var called = 0;
    em.once("y", function () { called++; });
    em.emit("y");
    em.emit("y");
    assert.strictEqual(called, 1);
  });

  it("off() should remove a specific handler", function () {
    var em = gifCaptcha.createEventEmitter();
    var called = 0;
    var fn = function () { called++; };
    em.on("z", fn);
    em.off("z", fn);
    em.emit("z");
    assert.strictEqual(called, 0);
  });

  it("should pass data to handlers", function () {
    var em = gifCaptcha.createEventEmitter();
    var received = null;
    em.on("challenge.passed", function (d) { received = d; });
    em.emit("challenge.passed", { score: 0.95 });
    assert.deepStrictEqual(received, { score: 0.95 });
  });

  it("wildcard * should receive all events", function () {
    var em = gifCaptcha.createEventEmitter();
    var events = [];
    em.on("*", function (envelope) { events.push(envelope); });
    em.emit("a", 1);
    em.emit("b", 2);
    assert.strictEqual(events.length, 2);
    assert.strictEqual(events[0].event, "a");
    assert.strictEqual(events[0].data, 1);
    assert.strictEqual(events[1].event, "b");
  });

  it("listeners() should return handler functions", function () {
    var em = gifCaptcha.createEventEmitter();
    var fn1 = function () {};
    var fn2 = function () {};
    em.on("e", fn1);
    em.on("e", fn2);
    var list = em.listeners("e");
    assert.strictEqual(list.length, 2);
    assert.strictEqual(list[0], fn1);
  });

  it("removeAll() should clear all handlers", function () {
    var em = gifCaptcha.createEventEmitter();
    em.on("a", function () {});
    em.on("b", function () {});
    em.removeAll();
    assert.strictEqual(em.listeners("a").length, 0);
    assert.strictEqual(em.listeners("b").length, 0);
  });

  it("removeAll(event) should clear only that event", function () {
    var em = gifCaptcha.createEventEmitter();
    em.on("a", function () {});
    em.on("b", function () {});
    em.removeAll("a");
    assert.strictEqual(em.listeners("a").length, 0);
    assert.strictEqual(em.listeners("b").length, 1);
  });

  it("pipe() should forward events to another emitter", function () {
    var em1 = gifCaptcha.createEventEmitter();
    var em2 = gifCaptcha.createEventEmitter();
    var received = null;
    em2.on("test", function (d) { received = d; });
    em1.pipe(em2);
    em1.emit("test", "hello");
    assert.strictEqual(received, "hello");
  });

  it("pipe() unpipe should stop forwarding", function () {
    var em1 = gifCaptcha.createEventEmitter();
    var em2 = gifCaptcha.createEventEmitter();
    var count = 0;
    em2.on("x", function () { count++; });
    var unpipe = em1.pipe(em2);
    em1.emit("x");
    assert.strictEqual(count, 1);
    unpipe();
    em1.emit("x");
    assert.strictEqual(count, 1);
  });

  it("maxListeners should limit subscriptions", function () {
    var errors = [];
    var em = gifCaptcha.createEventEmitter({
      maxListeners: 2,
      onError: function (e) { errors.push(e); }
    });
    em.on("e", function () {});
    em.on("e", function () {});
    em.on("e", function () {}); // should trigger error
    assert.strictEqual(em.listeners("e").length, 2);
    assert.strictEqual(errors.length, 1);
  });

  it("onError should catch listener exceptions", function () {
    var errors = [];
    var em = gifCaptcha.createEventEmitter({
      onError: function (e) { errors.push(e); }
    });
    em.on("e", function () { throw new Error("boom"); });
    var count = em.emit("e");
    assert.strictEqual(count, 1);
    assert.strictEqual(errors.length, 1);
    assert.strictEqual(errors[0].message, "boom");
  });

  it("should handle emit with no listeners gracefully", function () {
    var em = gifCaptcha.createEventEmitter();
    assert.strictEqual(em.emit("nonexistent"), 0);
  });

  it("should handle invalid arguments gracefully", function () {
    var em = gifCaptcha.createEventEmitter();
    var unsub = em.on(123, "notfn");
    assert.strictEqual(typeof unsub, "function");
    unsub(); // should not throw
    em.off("nope", function () {}); // should not throw
  });
});
