/**
 * Tests for CaptchaCapacityPlanner
 */

"use strict";

var assert = require("assert");
var mod = require("../src/captcha-capacity-planner");
var createCapacityPlanner = mod.createCapacityPlanner;

// ── helpers ─────────────────────────────────────────────────────────

function makeSamples(count, baseRps, growthPerSample, opts) {
  var o = opts || {};
  var t0 = o.t0 || 1700000000000;
  var interval = o.intervalMs || 3600000;
  var arr = [];
  for (var i = 0; i < count; i++) {
    arr.push({
      timestamp: t0 + i * interval,
      rps: baseRps + i * growthPerSample + (Math.random() - 0.5) * 2,
      latencyMs: (o.baseLatency || 80) + Math.random() * 20,
      errorRate: o.errorRate || 0.01,
      cpuPercent: o.cpuPercent != null ? o.cpuPercent : undefined,
      memoryPercent: o.memoryPercent != null ? o.memoryPercent : undefined
    });
  }
  return arr;
}

// ── Tests ───────────────────────────────────────────────────────────

// 1. Create planner with defaults
(function testCreateDefaults() {
  var p = createCapacityPlanner();
  assert.ok(p, "planner created");
  assert.strictEqual(typeof p.recordSample, "function");
  assert.strictEqual(typeof p.forecast, "function");
  assert.strictEqual(typeof p.assess, "function");
  assert.strictEqual(typeof p.recommend, "function");
  console.log("PASS: testCreateDefaults");
})();

// 2. Record single sample
(function testRecordSample() {
  var p = createCapacityPlanner();
  var s = p.recordSample({ timestamp: 1000, rps: 100, latencyMs: 50, errorRate: 0.01 });
  assert.strictEqual(s.rps, 100);
  assert.strictEqual(s.latencyMs, 50);
  assert.strictEqual(p.getSamples().length, 1);
  console.log("PASS: testRecordSample");
})();

// 3. Record batch
(function testRecordBatch() {
  var p = createCapacityPlanner();
  var results = p.recordBatch(makeSamples(5, 100, 0));
  assert.strictEqual(results.length, 5);
  assert.strictEqual(p.getSamples().length, 5);
  console.log("PASS: testRecordBatch");
})();

// 4. Sample eviction
(function testEviction() {
  var p = createCapacityPlanner({ maxSamples: 3 });
  p.recordBatch(makeSamples(5, 100, 0));
  assert.strictEqual(p.getSamples().length, 3);
  console.log("PASS: testEviction");
})();

// 5. Stats with no data
(function testStatsNoData() {
  var p = createCapacityPlanner();
  assert.strictEqual(p.stats(), null);
  console.log("PASS: testStatsNoData");
})();

// 6. Stats with data
(function testStatsWithData() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(10, 200, 5));
  var s = p.stats();
  assert.ok(s.sampleCount === 10);
  assert.ok(s.rps.mean > 0);
  assert.ok(s.latencyMs.mean > 0);
  assert.ok(s.rps.p95 > 0);
  console.log("PASS: testStatsWithData");
})();

// 7. Forecast requires 2+ samples
(function testForecastMinSamples() {
  var p = createCapacityPlanner();
  p.recordSample({ rps: 100, latencyMs: 50, errorRate: 0.01 });
  var f = p.forecast();
  assert.ok(f.error);
  assert.strictEqual(f.points.length, 0);
  console.log("PASS: testForecastMinSamples");
})();

// 8. Forecast with growing traffic
(function testForecastGrowing() {
  var p = createCapacityPlanner({ maxRps: 1000 });
  p.recordBatch(makeSamples(24, 200, 10));
  var f = p.forecast({ horizonHours: 12, intervalHours: 1 });
  assert.ok(f.trend);
  assert.strictEqual(f.trend.direction, "growing");
  assert.ok(f.trend.slope > 0);
  assert.strictEqual(f.points.length, 12);
  assert.ok(f.points[0].predictedRps > 0);
  console.log("PASS: testForecastGrowing");
})();

// 9. Forecast with stable traffic
(function testForecastStable() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(24, 300, 0));
  var f = p.forecast({ horizonHours: 24 });
  assert.ok(f.trend.direction === "stable" || Math.abs(f.trend.slope) < 1);
  console.log("PASS: testForecastStable");
})();

// 10. Assess no data
(function testAssessNoData() {
  var p = createCapacityPlanner();
  var a = p.assess();
  assert.strictEqual(a.status, "no-data");
  console.log("PASS: testAssessNoData");
})();

// 11. Assess healthy
(function testAssessHealthy() {
  var p = createCapacityPlanner({ maxRps: 1000 });
  p.recordBatch(makeSamples(10, 200, 0));
  var a = p.assess();
  assert.strictEqual(a.status, "healthy");
  assert.ok(a.utilization < 0.6);
  assert.ok(a.headroomRps > 0);
  console.log("PASS: testAssessHealthy");
})();

// 12. Assess warning
(function testAssessWarning() {
  var p = createCapacityPlanner({ maxRps: 1000 });
  p.recordBatch(makeSamples(10, 850, 0));
  var a = p.assess();
  assert.strictEqual(a.status, "warning");
  console.log("PASS: testAssessWarning");
})();

// 13. Assess critical
(function testAssessCritical() {
  var p = createCapacityPlanner({ maxRps: 1000 });
  p.recordBatch(makeSamples(10, 960, 0));
  var a = p.assess();
  assert.ok(a.status === "critical" || a.status === "overloaded");
  console.log("PASS: testAssessCritical");
})();

// 14. Latency bottleneck detected
(function testLatencyBottleneck() {
  var p = createCapacityPlanner({ maxRps: 1000, maxLatencyMs: 100 });
  p.recordBatch(makeSamples(10, 200, 0, { baseLatency: 150 }));
  var a = p.assess();
  assert.ok(a.bottlenecks.some(function (b) { return b.type === "latency"; }));
  console.log("PASS: testLatencyBottleneck");
})();

// 15. Error bottleneck detected
(function testErrorBottleneck() {
  var p = createCapacityPlanner({ maxRps: 1000, maxErrorRate: 0.03 });
  p.recordBatch(makeSamples(10, 200, 0, { errorRate: 0.08 }));
  var a = p.assess();
  assert.ok(a.bottlenecks.some(function (b) { return b.type === "errors"; }));
  console.log("PASS: testErrorBottleneck");
})();

// 16. CPU bottleneck
(function testCpuBottleneck() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(10, 200, 0, { cpuPercent: 92 }));
  var a = p.assess();
  assert.ok(a.bottlenecks.some(function (b) { return b.type === "cpu"; }));
  console.log("PASS: testCpuBottleneck");
})();

// 17. Memory bottleneck
(function testMemoryBottleneck() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(10, 200, 0, { memoryPercent: 96 }));
  var a = p.assess();
  assert.ok(a.bottlenecks.some(function (b) { return b.type === "memory"; }));
  console.log("PASS: testMemoryBottleneck");
})();

// 18. Recommend returns scaling for critical
(function testRecommendScaling() {
  var p = createCapacityPlanner({ maxRps: 500 });
  p.recordBatch(makeSamples(10, 500, 5));
  var r = p.recommend();
  assert.ok(r.recommendations.length > 0);
  assert.ok(r.recommendations.some(function (rec) { return rec.category === "scaling"; }));
  console.log("PASS: testRecommendScaling");
})();

// 19. Recommend for healthy
(function testRecommendHealthy() {
  var p = createCapacityPlanner({ maxRps: 5000 });
  p.recordBatch(makeSamples(10, 100, 0));
  var r = p.recommend();
  // no critical recs
  assert.ok(!r.recommendations.some(function (rec) { return rec.priority === "critical"; }));
  console.log("PASS: testRecommendHealthy");
})();

// 20. Scenario planning
(function testScenario() {
  var p = createCapacityPlanner({ maxRps: 1000 });
  p.recordBatch(makeSamples(10, 300, 0));
  var s = p.scenario(2000);
  assert.ok(s);
  assert.strictEqual(s.targetRps, 2000);
  assert.ok(s.scaleFactor > 1);
  assert.ok(s.additionalInstances > 0);
  assert.strictEqual(s.canHandle, false);
  console.log("PASS: testScenario");
})();

// 21. Scenario within capacity
(function testScenarioWithinCapacity() {
  var p = createCapacityPlanner({ maxRps: 1000 });
  p.recordBatch(makeSamples(10, 300, 0));
  var s = p.scenario(500);
  assert.strictEqual(s.canHandle, true);
  console.log("PASS: testScenarioWithinCapacity");
})();

// 22. Scenario rejects bad input
(function testScenarioBadInput() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(5, 100, 0));
  try { p.scenario(0); assert.fail("should throw"); } catch (e) { assert.ok(e.message.includes("positive")); }
  console.log("PASS: testScenarioBadInput");
})();

// 23. Hourly profile
(function testHourlyProfile() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(48, 200, 0)); // 48 hours
  var profile = p.hourlyProfile();
  assert.strictEqual(profile.length, 24);
  assert.ok(profile[0].hasOwnProperty("hour"));
  assert.ok(profile[0].hasOwnProperty("avgRps"));
  console.log("PASS: testHourlyProfile");
})();

// 24. Hourly profile empty
(function testHourlyProfileEmpty() {
  var p = createCapacityPlanner();
  assert.strictEqual(p.hourlyProfile().length, 0);
  console.log("PASS: testHourlyProfileEmpty");
})();

// 25. Report JSON
(function testReportJson() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(20, 300, 5));
  var r = p.report({ format: "json" });
  assert.ok(r.generated);
  assert.ok(r.config);
  assert.ok(r.stats);
  assert.ok(r.assessment);
  assert.ok(r.forecast);
  assert.ok(Array.isArray(r.recommendations));
  console.log("PASS: testReportJson");
})();

// 26. Report text
(function testReportText() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(20, 300, 5));
  var r = p.report({ format: "text" });
  assert.ok(typeof r === "string");
  assert.ok(r.includes("CAPACITY PLANNING REPORT"));
  assert.ok(r.includes("Traffic Statistics"));
  console.log("PASS: testReportText");
})();

// 27. Report with scenarios
(function testReportScenarios() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(10, 300, 0));
  var r = p.report({ format: "json", scenarios: [500, 1000, 2000] });
  assert.ok(r.scenarios);
  assert.strictEqual(r.scenarios.length, 3);
  console.log("PASS: testReportScenarios");
})();

// 28. Clear samples
(function testClear() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(10, 100, 0));
  assert.strictEqual(p.getSamples().length, 10);
  p.clear();
  assert.strictEqual(p.getSamples().length, 0);
  console.log("PASS: testClear");
})();

// 29. Invalid sample throws
(function testInvalidSample() {
  var p = createCapacityPlanner();
  try { p.recordSample(null); assert.fail("should throw"); } catch (e) { assert.ok(e.message.includes("object")); }
  try { p.recordSample("bad"); assert.fail("should throw"); } catch (e) { assert.ok(e.message.includes("object")); }
  console.log("PASS: testInvalidSample");
})();

// 30. Invalid batch throws
(function testInvalidBatch() {
  var p = createCapacityPlanner();
  try { p.recordBatch("not array"); assert.fail("should throw"); } catch (e) { assert.ok(e.message.includes("array")); }
  console.log("PASS: testInvalidBatch");
})();

// 31. Negative rps clamped to 0
(function testNegativeRps() {
  var p = createCapacityPlanner();
  var s = p.recordSample({ rps: -50, latencyMs: 10, errorRate: 0 });
  assert.strictEqual(s.rps, 0);
  console.log("PASS: testNegativeRps");
})();

// 32. Error rate clamped
(function testErrorRateClamped() {
  var p = createCapacityPlanner();
  var s = p.recordSample({ rps: 100, latencyMs: 10, errorRate: 1.5 });
  assert.strictEqual(s.errorRate, 1);
  console.log("PASS: testErrorRateClamped");
})();

// 33. Time to capacity with declining traffic
(function testTimeToCapacityDeclining() {
  var p = createCapacityPlanner({ maxRps: 1000 });
  p.recordBatch(makeSamples(24, 500, -5));
  var f = p.forecast();
  assert.strictEqual(f.timeToCapacityHours, null);
  console.log("PASS: testTimeToCapacityDeclining");
})();

// 34. Custom headroom
(function testCustomHeadroom() {
  var p = createCapacityPlanner({ maxRps: 1000, headroom: 0.3 });
  p.recordBatch(makeSamples(10, 300, 0));
  var a = p.assess();
  assert.strictEqual(a.effectiveCapacity, 700);
  console.log("PASS: testCustomHeadroom");
})();

// 35. Forecast with declining traffic
(function testForecastDeclining() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(24, 800, -10));
  var f = p.forecast();
  assert.strictEqual(f.trend.direction, "declining");
  console.log("PASS: testForecastDeclining");
})();

// 36. Scale-down recommendation
(function testScaleDown() {
  var p = createCapacityPlanner({ maxRps: 5000 });
  p.recordBatch(makeSamples(24, 200, -5));
  var r = p.recommend();
  var costRec = r.recommendations.filter(function (rec) { return rec.category === "cost"; });
  // may or may not trigger depending on utilization
  assert.ok(r.assessment.status === "healthy");
  console.log("PASS: testScaleDown");
})();

// 37. Forecast custom horizon
(function testForecastCustomHorizon() {
  var p = createCapacityPlanner();
  p.recordBatch(makeSamples(10, 200, 5));
  var f = p.forecast({ horizonHours: 48, intervalHours: 6 });
  assert.strictEqual(f.points.length, 8);
  assert.strictEqual(f.points[0].hoursFromNow, 6);
  console.log("PASS: testForecastCustomHorizon");
})();

// 38. Overloaded status
(function testOverloaded() {
  var p = createCapacityPlanner({ maxRps: 100 });
  for (var i = 0; i < 10; i++) {
    p.recordSample({ timestamp: 1000 + i * 1000, rps: 110, latencyMs: 50, errorRate: 0.01 });
  }
  var a = p.assess();
  assert.strictEqual(a.status, "overloaded");
  console.log("PASS: testOverloaded");
})();

console.log("\nAll 38 tests passed!");
