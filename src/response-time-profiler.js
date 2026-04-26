'use strict';

// ── Shared utilities (from shared-utils.js — issue #91) ──────────────
var _sharedUtils = require("./shared-utils");
var _cryptoUtils = require("./crypto-utils");
var LruTracker = _sharedUtils.LruTracker;
var _posOpt = _sharedUtils._posOpt;
var _mean = _sharedUtils._mean;
var _median = _sharedUtils._median;
var _medianSorted = _sharedUtils._medianSorted;
var _stddev = _sharedUtils._stddev;
var _percentileSorted = _sharedUtils._percentileSorted;
var _percentile = _sharedUtils._percentile;

/**
 * Response Time Profiler for CAPTCHA systems.
 *
 * Builds per-challenge-type timing profiles, detects anomalies in individual
 * sessions (too-fast solves, mechanical consistency, burst patterns), and
 * classifies solvers as human/bot/solver_farm/suspicious. Supports histograms,
 * difficulty-correlation analysis, inter-solve gap analysis, and full
 * import/export of profiling data.
 *
 * @param {Object} [options]
 * @param {number} [options.minSamples=10] - Minimum samples before generating profiles
 * @param {number} [options.maxSamples=1000] - Maximum samples to retain per challenge type
 * @param {number} [options.botThresholdMs=500] - Solves faster than this are flagged as bot-like
 * @param {number} [options.humanMinMs=800] - Lower bound of expected human response time
 * @param {number} [options.humanMaxMs=30000] - Upper bound of expected human response time
 * @param {number} [options.consistencyThreshold=0.1] - CV below this flags mechanical consistency
 * @param {number} [options.burstWindowMs=5000] - Time window for burst detection
 * @param {number} [options.burstThreshold=3] - Solves within burst window to flag
 * @param {number} [options.histogramBins=20] - Number of histogram bins
 * @param {number} [options.maxSessions=500] - Maximum tracked sessions (LRU eviction)
 * @param {Function} [options.now] - Clock function; defaults to Date.now
 * @returns {Object} Profiler instance
 */
// _posOpt imported from shared-utils above

function createResponseTimeProfiler(options) {
  options = options || {};
  var minSamples        = _posOpt(options.minSamples, 10);
  var maxSamples        = _posOpt(options.maxSamples, 1000);
  var botThresholdMs    = _posOpt(options.botThresholdMs, 500);
  var humanMinMs        = _posOpt(options.humanMinMs, 800);
  var humanMaxMs        = _posOpt(options.humanMaxMs, 30000);
  var consistencyThreshold = _posOpt(options.consistencyThreshold, 0.1);
  var burstWindowMs     = _posOpt(options.burstWindowMs, 5000);
  var burstThreshold    = _posOpt(options.burstThreshold, 3);
  var histogramBins     = _posOpt(options.histogramBins, 20);
  var maxSessions       = _posOpt(options.maxSessions, 500);
  var nowFn = options.now || function () { return Date.now(); };

  var typeProfiles = Object.create(null);
  var sessions = Object.create(null);
  var sessionCount = 0;
  var sessionLru = new LruTracker();

  var _numAsc = _sharedUtils._numAsc;
  var _sortedCopy = _sharedUtils._sortedCopy;
  function _pctSorted(s,p) { return _percentileSorted(s, p); }
  function _pct(a,p) { return _percentile(a, p); }
  function _r(v,d) { var f=Math.pow(10,d||2); return Math.round(v*f)/f; }

  /**
   * Record a CAPTCHA solve attempt with timing data.
   *
   * @param {Object} entry
   * @param {string} entry.sessionId - Unique session identifier
   * @param {number} entry.responseTimeMs - Time taken to solve (ms, non-negative)
   * @param {boolean} entry.solved - Whether the attempt was solved correctly
   * @param {string} [entry.type='default'] - Challenge type for per-type profiling
   * @param {number} [entry.difficulty] - Difficulty level for correlation analysis
   * @throws {Error} If required fields are missing or invalid
   */
  function record(entry) {
    if (!entry||typeof entry.responseTimeMs!=='number'||entry.responseTimeMs<0) throw new Error('responseTimeMs must be a non-negative number');
    if (!entry.sessionId) throw new Error('sessionId is required');
    if (typeof entry.solved!=='boolean') throw new Error('solved must be a boolean');
    var type=entry.type||'default', ts=nowFn();
    if (!typeProfiles[type]) typeProfiles[type]={times:[],solved:[],difficulties:[]};
    var p=typeProfiles[type]; p.times.push(entry.responseTimeMs); p.solved.push(entry.solved);
    if (entry.difficulty!=null) p.difficulties.push(entry.difficulty);
    // Trim oldest entries when over capacity. Uses splice(0, excess)
    // instead of repeated shift() to avoid O(n) per call overhead.
    if (p.times.length > maxSamples) {
      var excess = p.times.length - maxSamples;
      p.times.splice(0, excess);
      p.solved.splice(0, excess);
    }
    if (p.difficulties.length > maxSamples) {
      p.difficulties.splice(0, p.difficulties.length - maxSamples);
    }
    if (!sessions[entry.sessionId]) {
      if (sessionCount>=maxSessions) { var oldest=sessionLru.evictOldest(); if(oldest){delete sessions[oldest];sessionCount--;} }
      sessions[entry.sessionId]={solves:[],classification:null}; sessionCount++; sessionLru.push(entry.sessionId);
    } else {
      sessionLru.touch(entry.sessionId);
    }
    sessions[entry.sessionId].solves.push({time:entry.responseTimeMs,type:type,solved:entry.solved,difficulty:entry.difficulty||null,ts:ts});
    sessions[entry.sessionId].classification=null;
  }

  /**
   * Get statistical profile for a challenge type (mean, median, stddev, percentiles, solve rate).
   *
   * @param {string} [type='default'] - Challenge type
   * @returns {?Object} Profile object or null if insufficient samples
   */
  function getTypeProfile(type) {
    type=type||'default'; var p=typeProfiles[type]; if (!p||p.times.length<minSamples) return null;
    var t=p.times,avg=_mean(t),sd=_stddev(t,avg);
    // Sort once and reuse for median + all percentiles (was 6 separate sorts)
    var sorted=_sortedCopy(t);
    var med=_medianSorted(sorted);
    var sc=0; for(var i=0;i<p.solved.length;i++){if(p.solved[i])sc++;}
    return {type:type,sampleCount:t.length,mean:_r(avg),median:_r(med),stddev:_r(sd),cv:avg>0?_r(sd/avg,3):0,
      min:sorted[0],max:sorted[sorted.length-1],p5:_r(_pctSorted(sorted,5)),p25:_r(_pctSorted(sorted,25)),p75:_r(_pctSorted(sorted,75)),p95:_r(_pctSorted(sorted,95)),p99:_r(_pctSorted(sorted,99)),
      solveRate:_r(sc/t.length,3),solveCount:sc,failCount:t.length-sc};
  }

  function getAllTypeProfiles() { var r=[],ks=Object.keys(typeProfiles); for(var i=0;i<ks.length;i++){var p=getTypeProfile(ks[i]);if(p)r.push(p);} return r; }

  /**
   * Detect timing anomalies in a session (too-fast, too-consistent, burst, out-of-range).
   *
   * @param {string} sessionId - Session to analyze
   * @returns {{ anomalies: Array, riskScore: number, classification: string }}
   * @throws {Error} If session is unknown
   */
  function detectAnomalies(sessionId) {
    if (!sessions[sessionId]) throw new Error('Unknown session: '+sessionId);
    var solves=sessions[sessionId].solves; if (solves.length<2) return {anomalies:[],riskScore:0,classification:'insufficient_data'};
    var anomalies=[],times=solves.map(function(s){return s.time;}),avg=_mean(times),sd=_stddev(times,avg),cv=avg>0?sd/avg:0;
    var fc=0; for(var i=0;i<times.length;i++){if(times[i]<botThresholdMs)fc++;}
    if(fc>0) anomalies.push({type:'too_fast',severity:fc/times.length>0.5?'critical':'warning',detail:fc+' of '+times.length+' solves under '+botThresholdMs+'ms',count:fc,ratio:_r(fc/times.length,3)});
    if(times.length>=minSamples&&cv<consistencyThreshold) anomalies.push({type:'too_consistent',severity:cv<consistencyThreshold/2?'critical':'warning',detail:'CV='+_r(cv,4)+' (threshold: '+consistencyThreshold+')',cv:_r(cv,4)});
    var ts=solves.map(function(s){return s.ts;}).sort(function(a,b){return a-b;}),mb=0;
    // Sliding window O(n) burst detection — replaces O(n²) nested loop.
    // Both pointers advance monotonically through the sorted timestamps.
    for(var j=0,left=0;j<ts.length;j++){while(ts[j]-ts[left]>burstWindowMs)left++;var c=j-left+1;if(c>mb)mb=c;}
    if(mb>=burstThreshold) anomalies.push({type:'burst_pattern',severity:mb>=burstThreshold*2?'critical':'warning',detail:mb+' solves within '+burstWindowMs+'ms window',burstSize:mb});
    var oor=0;for(var m=0;m<times.length;m++){if(times[m]<humanMinMs||times[m]>humanMaxMs)oor++;}
    if(oor>times.length*0.3) anomalies.push({type:'out_of_human_range',severity:oor/times.length>0.6?'critical':'warning',detail:oor+' of '+times.length+' outside '+humanMinMs+'-'+humanMaxMs+'ms',count:oor,ratio:_r(oor/times.length,3)});
    var rs=0;for(var n=0;n<anomalies.length;n++){rs+=anomalies[n].severity==='critical'?30:15;}
    return {anomalies:anomalies,riskScore:Math.min(100,rs),classification:_classify(anomalies)};
  }

  function _classify(anomalies) {
    var hf=false,hc=false,hb=false;
    for(var i=0;i<anomalies.length;i++){if(anomalies[i].type==='too_fast')hf=true;if(anomalies[i].type==='too_consistent')hc=true;if(anomalies[i].type==='burst_pattern')hb=true;}
    if(hf&&hc)return 'bot';if(hc&&!hf)return 'solver_farm';if(hf&&!hc)return 'bot';if(hb)return 'suspicious';if(!anomalies.length)return 'human';return 'uncertain';
  }

  /**
   * Classify a session as human, bot, solver_farm, suspicious, or uncertain.
   *
   * @param {string} sessionId - Session to classify
   * @returns {{ classification: string, confidence: number, humanLikelihood: string, evidence: Array<string>, stats: Object, anomalies: Array }}
   * @throws {Error} If session is unknown
   */
  function classifySession(sessionId) {
    if(!sessions[sessionId])throw new Error('Unknown session: '+sessionId);
    var solves=sessions[sessionId].solves;if(solves.length<2)return{classification:'insufficient_data',confidence:0,evidence:[]};
    var times=solves.map(function(s){return s.time;}),avg=_mean(times),sd=_stddev(times,avg),cv=avg>0?sd/avg:0,med=_median(times);
    var ar=detectAnomalies(sessionId),ev=[],conf=0;
    if(cv>0.3&&med>=humanMinMs&&med<=humanMaxMs){ev.push('natural_timing_variance');conf+=25;}
    if(avg>=humanMinMs&&avg<=humanMaxMs){ev.push('human_range_mean');conf+=20;}
    if(avg<botThresholdMs){ev.push('sub_bot_threshold_mean');conf-=40;}
    if(cv<consistencyThreshold&&times.length>=minSamples){ev.push('mechanical_consistency');conf-=30;}
    if(avg>=humanMinMs&&avg<=humanMaxMs&&cv<consistencyThreshold*2){ev.push('farm_like_consistency');conf-=15;}
    var sc2=0;for(var si2=0;si2<solves.length;si2++){if(solves[si2].solved)sc2++;}
    var sr=sc2/solves.length;
    if(sr>0.95&&times.length>=minSamples){ev.push('near_perfect_solve_rate');conf-=10;}
    var cls=ar.classification;if(cls==='human')conf=Math.max(conf,50);
    var result={classification:cls,confidence:Math.min(100,Math.max(0,Math.abs(conf))),humanLikelihood:cls==='human'?'high':cls==='uncertain'?'medium':'low',
      evidence:ev,stats:{mean:_r(avg),median:_r(med),stddev:_r(sd),cv:_r(cv,3),solveRate:_r(sr,3),sampleSize:times.length},anomalies:ar.anomalies};
    // Cache classification so getSummary can skip redundant anomaly detection
    sessions[sessionId].classification=result;
    return result;
  }

  /**
   * Generate a response-time histogram for a challenge type.
   *
   * @param {string} [type='default'] - Challenge type
   * @returns {?Object} Histogram with bins, bin width, and range; null if < 2 samples
   */
  function getHistogram(type) {
    type=type||'default';var p=typeProfiles[type];if(!p||p.times.length<2)return null;
    var t=p.times,mn=t[0],mx=t[0];for(var mi=1;mi<t.length;mi++){if(t[mi]<mn)mn=t[mi];if(t[mi]>mx)mx=t[mi];}if(mn===mx)mx=mn+1;
    var bw=(mx-mn)/histogramBins,bins=[];
    for(var i=0;i<histogramBins;i++)bins.push({rangeStart:_r(mn+i*bw),rangeEnd:_r(mn+(i+1)*bw),count:0});
    for(var j=0;j<t.length;j++){var idx=Math.min(Math.floor((t[j]-mn)/bw),histogramBins-1);bins[idx].count++;}
    return{type:type,bins:bins,binWidth:_r(bw),totalSamples:t.length,range:{min:_r(mn),max:_r(mx)}};
  }

  /**
   * Compute Pearson correlation between difficulty level and response time.
   *
   * @param {string} [type='default'] - Challenge type
   * @returns {?Object} Correlation coefficient, strength, direction, and per-difficulty breakdown; null if insufficient data
   */
  function getDifficultyCorrelation(type) {
    type=type||'default';var p=typeProfiles[type];if(!p||p.difficulties.length<minSamples)return null;
    var n=Math.min(p.times.length,p.difficulties.length),xs=p.difficulties.slice(0,n),ys=p.times.slice(0,n);
    var sX=0,sY=0,sXY=0,sX2=0,sY2=0;for(var i=0;i<n;i++){sX+=xs[i];sY+=ys[i];sXY+=xs[i]*ys[i];sX2+=xs[i]*xs[i];sY2+=ys[i]*ys[i];}
    var den=Math.sqrt((n*sX2-sX*sX)*(n*sY2-sY*sY)),r=den===0?0:(n*sXY-sX*sY)/den;
    var bd=Object.create(null);for(var j=0;j<n;j++){var d=xs[j];if(!bd[d])bd[d]=[];bd[d].push(ys[j]);}
    var bk=[];var dks=Object.keys(bd).sort(function(a,b){return+a- +b;});
    for(var k=0;k<dks.length;k++){var dt=bd[dks[k]];bk.push({difficulty:+dks[k],count:dt.length,meanMs:_r(_mean(dt)),medianMs:_r(_median(dt))});}
    var ar=Math.abs(r),str=ar>=0.7?'strong':ar>=0.4?'moderate':ar>=0.2?'weak':'negligible';
    return{type:type,correlation:_r(r,4),strength:str,direction:r>0.05?'positive':r<-0.05?'negative':'none',sampleCount:n,byDifficulty:bk,
      interpretation:r>0.2?'Higher difficulty increases response time (expected)':r<-0.2?'Higher difficulty decreases response time (unusual — may indicate bots targeting hard challenges)':'No significant relationship between difficulty and response time'};
  }

  /**
   * Analyze inter-solve time gaps for a session to detect mechanical regularity.
   *
   * @param {string} sessionId - Session to analyze
   * @returns {?Object} Gap statistics with regularity classification; null if < 3 solves
   * @throws {Error} If session is unknown
   */
  function getInterSolveGaps(sessionId) {
    if(!sessions[sessionId])throw new Error('Unknown session: '+sessionId);
    var solves=sessions[sessionId].solves;if(solves.length<3)return null;
    var gaps=[];for(var i=1;i<solves.length;i++)gaps.push(solves[i].ts-solves[i-1].ts);
    var avg=_mean(gaps),sd=_stddev(gaps,avg),cv=avg>0?sd/avg:0;
    return{sessionId:sessionId,gapCount:gaps.length,mean:_r(avg),median:_r(_median(gaps)),stddev:_r(sd),cv:_r(cv,3),
      min:gaps.reduce(function(a,b){return a<b?a:b},gaps[0]),max:gaps.reduce(function(a,b){return a>b?a:b},gaps[0]),regularity:cv<0.2?'mechanical':cv<0.5?'semi_regular':'natural'};
  }

  function exportData() {
    var ep={},ks=Object.keys(typeProfiles);for(var i=0;i<ks.length;i++){ep[ks[i]]={times:typeProfiles[ks[i]].times.slice(),solved:typeProfiles[ks[i]].solved.slice(),difficulties:typeProfiles[ks[i]].difficulties.slice()};}
    var es={},sk=Object.keys(sessions);for(var j=0;j<sk.length;j++){es[sk[j]]={solves:sessions[sk[j]].solves.slice()};}
    return{version:1,exportedAt:nowFn(),typeProfiles:ep,sessions:es,config:{minSamples:minSamples,maxSamples:maxSamples,botThresholdMs:botThresholdMs,humanMinMs:humanMinMs,humanMaxMs:humanMaxMs,consistencyThreshold:consistencyThreshold,burstWindowMs:burstWindowMs,burstThreshold:burstThreshold,histogramBins:histogramBins}};
  }

  function importData(data) {
    if(!data||data.version!==1)throw new Error('Invalid or unsupported export format');
    var ks=Object.keys(data.typeProfiles||{});for(var i=0;i<ks.length;i++){var s=data.typeProfiles[ks[i]];typeProfiles[ks[i]]={times:s.times.slice(),solved:s.solved.slice(),difficulties:(s.difficulties||[]).slice()};}
    var sk=Object.keys(data.sessions||{});for(var j=0;j<sk.length;j++){sessions[sk[j]]={solves:data.sessions[sk[j]].solves.slice(),classification:null};sessionLru.push(sk[j]);}
    sessionCount=Object.keys(sessions).length;
  }

  /**
   * Reservoir sampling for approximate median — O(1) memory instead of
   * collecting all response times into an array (O(N) memory + O(N log N)
   * sort).  Uses the same pattern as captcha-traffic-analyzer.js's Welford
   * online stats.  Reservoir size 256 gives a tight approximation while
   * keeping memory bounded regardless of total solve count.
   */
  var _RESERVOIR_CAP = 256;

  function getSummary() {
    var ts=0,td=0,timeSum=0;var cls={human:0,bot:0,solver_farm:0,suspicious:0,uncertain:0,insufficient_data:0};
    // Reservoir sampling for approximate median — avoids O(N) array + O(N log N) sort
    var reservoir=[];var seen=0;
    var sk=Object.keys(sessions);for(var i=0;i<sk.length;i++){var s=sessions[sk[i]];ts+=s.solves.length;for(var j=0;j<s.solves.length;j++){var t=s.solves[j].time;timeSum+=t;if(s.solves[j].solved)td++;
        // Reservoir sampling: uniform random sample of up to _RESERVOIR_CAP values
        seen++;if(reservoir.length<_RESERVOIR_CAP){reservoir.push(t);}else{var ri=_cryptoUtils.secureRandomInt(seen);if(ri<_RESERVOIR_CAP)reservoir[ri]=t;}}
      // Use cached classification when available (set by classifySession,
      // cleared to null by record). Avoids redundant O(solves) anomaly
      // detection for sessions whose data hasn't changed since last classify.
      var c=s.classification||classifySession(sk[i]);
      cls[c.classification]=(cls[c.classification]||0)+1;}
    var approxMedian=0;if(reservoir.length>0){reservoir.sort(function(a,b){return a-b;});approxMedian=_medianSorted(reservoir);}
    return{totalSessions:sk.length,totalSolves:ts,overallSolveRate:ts>0?_r(td/ts,3):0,meanResponseMs:ts>0?_r(timeSum/ts):0,medianResponseMs:_r(approxMedian),challengeTypes:Object.keys(typeProfiles).length,classifications:cls};
  }

  function reset() {
    var tk=Object.keys(typeProfiles);for(var i=0;i<tk.length;i++)delete typeProfiles[tk[i]];
    var sk=Object.keys(sessions);for(var j=0;j<sk.length;j++)delete sessions[sk[j]];sessionCount=0;
    sessionLru=new LruTracker();
  }

  return{record:record,getTypeProfile:getTypeProfile,getAllTypeProfiles:getAllTypeProfiles,detectAnomalies:detectAnomalies,classifySession:classifySession,
    getHistogram:getHistogram,getDifficultyCorrelation:getDifficultyCorrelation,getInterSolveGaps:getInterSolveGaps,getSummary:getSummary,
    exportData:exportData,importData:importData,reset:reset};
}

module.exports = { createResponseTimeProfiler: createResponseTimeProfiler };
