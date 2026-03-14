'use strict';

/**
 * Response Time Profiler for CAPTCHA systems.
 * Builds timing profiles, detects anomalies, classifies solver behavior.
 */
function createResponseTimeProfiler(options) {
  options = options || {};
  var minSamples = (options.minSamples != null && options.minSamples > 0) ? options.minSamples : 10;
  var maxSamples = (options.maxSamples != null && options.maxSamples > 0) ? options.maxSamples : 1000;
  var botThresholdMs = (options.botThresholdMs != null && options.botThresholdMs > 0) ? options.botThresholdMs : 500;
  var humanMinMs = (options.humanMinMs != null && options.humanMinMs > 0) ? options.humanMinMs : 800;
  var humanMaxMs = (options.humanMaxMs != null && options.humanMaxMs > 0) ? options.humanMaxMs : 30000;
  var consistencyThreshold = (options.consistencyThreshold != null && options.consistencyThreshold > 0) ? options.consistencyThreshold : 0.1;
  var burstWindowMs = (options.burstWindowMs != null && options.burstWindowMs > 0) ? options.burstWindowMs : 5000;
  var burstThreshold = (options.burstThreshold != null && options.burstThreshold > 0) ? options.burstThreshold : 3;
  var histogramBins = (options.histogramBins != null && options.histogramBins > 0) ? options.histogramBins : 20;
  var maxSessions = (options.maxSessions != null && options.maxSessions > 0) ? options.maxSessions : 500;
  var nowFn = options.now || function () { return Date.now(); };

  var typeProfiles = Object.create(null);
  var sessions = Object.create(null);
  var sessionCount = 0;

  function _mean(a) { if (!a.length) return 0; var s=0; for (var i=0;i<a.length;i++) s+=a[i]; return s/a.length; }
  function _median(a) { if (!a.length) return 0; var s=a.slice().sort(function(x,y){return x-y}); var m=Math.floor(s.length/2); return s.length%2?s[m]:(s[m-1]+s[m])/2; }
  function _stddev(a,avg) { if (a.length<2) return 0; if (avg==null) avg=_mean(a); var s=0; for (var i=0;i<a.length;i++) s+=(a[i]-avg)*(a[i]-avg); return Math.sqrt(s/(a.length-1)); }
  function _pct(a,p) { if (!a.length) return 0; var s=a.slice().sort(function(x,y){return x-y}); var i=(p/100)*(s.length-1); var l=Math.floor(i),u=Math.ceil(i); return l===u?s[l]:s[l]+(i-l)*(s[u]-s[l]); }
  function _r(v,d) { var f=Math.pow(10,d||2); return Math.round(v*f)/f; }

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
      if (sessionCount>=maxSessions) { var oldest=null,oldTs=Infinity,ks=Object.keys(sessions); for(var i=0;i<ks.length;i++){var s=sessions[ks[i]];if(s.solves.length>0&&s.solves[0].ts<oldTs){oldTs=s.solves[0].ts;oldest=ks[i];}} if(oldest){delete sessions[oldest];sessionCount--;} }
      sessions[entry.sessionId]={solves:[],classification:null}; sessionCount++;
    }
    sessions[entry.sessionId].solves.push({time:entry.responseTimeMs,type:type,solved:entry.solved,difficulty:entry.difficulty||null,ts:ts});
    sessions[entry.sessionId].classification=null;
  }

  function getTypeProfile(type) {
    type=type||'default'; var p=typeProfiles[type]; if (!p||p.times.length<minSamples) return null;
    var t=p.times,avg=_mean(t),sd=_stddev(t,avg),med=_median(t),sc=p.solved.filter(function(s){return s;}).length;
    return {type:type,sampleCount:t.length,mean:_r(avg),median:_r(med),stddev:_r(sd),cv:avg>0?_r(sd/avg,3):0,
      min:Math.min.apply(null,t),max:Math.max.apply(null,t),p5:_r(_pct(t,5)),p25:_r(_pct(t,25)),p75:_r(_pct(t,75)),p95:_r(_pct(t,95)),p99:_r(_pct(t,99)),
      solveRate:_r(sc/t.length,3),solveCount:sc,failCount:t.length-sc};
  }

  function getAllTypeProfiles() { var r=[],ks=Object.keys(typeProfiles); for(var i=0;i<ks.length;i++){var p=getTypeProfile(ks[i]);if(p)r.push(p);} return r; }

  function detectAnomalies(sessionId) {
    if (!sessions[sessionId]) throw new Error('Unknown session: '+sessionId);
    var solves=sessions[sessionId].solves; if (solves.length<2) return {anomalies:[],riskScore:0,classification:'insufficient_data'};
    var anomalies=[],times=solves.map(function(s){return s.time;}),avg=_mean(times),sd=_stddev(times,avg),cv=avg>0?sd/avg:0;
    var fc=0; for(var i=0;i<times.length;i++){if(times[i]<botThresholdMs)fc++;}
    if(fc>0) anomalies.push({type:'too_fast',severity:fc/times.length>0.5?'critical':'warning',detail:fc+' of '+times.length+' solves under '+botThresholdMs+'ms',count:fc,ratio:_r(fc/times.length,3)});
    if(times.length>=minSamples&&cv<consistencyThreshold) anomalies.push({type:'too_consistent',severity:cv<consistencyThreshold/2?'critical':'warning',detail:'CV='+_r(cv,4)+' (threshold: '+consistencyThreshold+')',cv:_r(cv,4)});
    var ts=solves.map(function(s){return s.ts;}).sort(function(a,b){return a-b;}),mb=0;
    for(var j=0;j<ts.length;j++){var c=0;for(var k=j;k<ts.length;k++){if(ts[k]-ts[j]<=burstWindowMs)c++;else break;}if(c>mb)mb=c;}
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
    var sr=solves.filter(function(s){return s.solved;}).length/solves.length;
    if(sr>0.95&&times.length>=minSamples){ev.push('near_perfect_solve_rate');conf-=10;}
    var cls=ar.classification;if(cls==='human')conf=Math.max(conf,50);
    return{classification:cls,confidence:Math.min(100,Math.max(0,Math.abs(conf))),humanLikelihood:cls==='human'?'high':cls==='uncertain'?'medium':'low',
      evidence:ev,stats:{mean:_r(avg),median:_r(med),stddev:_r(sd),cv:_r(cv,3),solveRate:_r(sr,3),sampleSize:times.length},anomalies:ar.anomalies};
  }

  function getHistogram(type) {
    type=type||'default';var p=typeProfiles[type];if(!p||p.times.length<2)return null;
    var t=p.times,mn=Math.min.apply(null,t),mx=Math.max.apply(null,t);if(mn===mx)mx=mn+1;
    var bw=(mx-mn)/histogramBins,bins=[];
    for(var i=0;i<histogramBins;i++)bins.push({rangeStart:_r(mn+i*bw),rangeEnd:_r(mn+(i+1)*bw),count:0});
    for(var j=0;j<t.length;j++){var idx=Math.min(Math.floor((t[j]-mn)/bw),histogramBins-1);bins[idx].count++;}
    return{type:type,bins:bins,binWidth:_r(bw),totalSamples:t.length,range:{min:_r(mn),max:_r(mx)}};
  }

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

  function getInterSolveGaps(sessionId) {
    if(!sessions[sessionId])throw new Error('Unknown session: '+sessionId);
    var solves=sessions[sessionId].solves;if(solves.length<3)return null;
    var gaps=[];for(var i=1;i<solves.length;i++)gaps.push(solves[i].ts-solves[i-1].ts);
    var avg=_mean(gaps),sd=_stddev(gaps,avg),cv=avg>0?sd/avg:0;
    return{sessionId:sessionId,gapCount:gaps.length,mean:_r(avg),median:_r(_median(gaps)),stddev:_r(sd),cv:_r(cv,3),
      min:Math.min.apply(null,gaps),max:Math.max.apply(null,gaps),regularity:cv<0.2?'mechanical':cv<0.5?'semi_regular':'natural'};
  }

  function exportData() {
    var ep={},ks=Object.keys(typeProfiles);for(var i=0;i<ks.length;i++){ep[ks[i]]={times:typeProfiles[ks[i]].times.slice(),solved:typeProfiles[ks[i]].solved.slice(),difficulties:typeProfiles[ks[i]].difficulties.slice()};}
    var es={},sk=Object.keys(sessions);for(var j=0;j<sk.length;j++){es[sk[j]]={solves:sessions[sk[j]].solves.slice()};}
    return{version:1,exportedAt:nowFn(),typeProfiles:ep,sessions:es,config:{minSamples:minSamples,maxSamples:maxSamples,botThresholdMs:botThresholdMs,humanMinMs:humanMinMs,humanMaxMs:humanMaxMs,consistencyThreshold:consistencyThreshold,burstWindowMs:burstWindowMs,burstThreshold:burstThreshold,histogramBins:histogramBins}};
  }

  function importData(data) {
    if(!data||data.version!==1)throw new Error('Invalid or unsupported export format');
    var ks=Object.keys(data.typeProfiles||{});for(var i=0;i<ks.length;i++){var s=data.typeProfiles[ks[i]];typeProfiles[ks[i]]={times:s.times.slice(),solved:s.solved.slice(),difficulties:(s.difficulties||[]).slice()};}
    var sk=Object.keys(data.sessions||{});for(var j=0;j<sk.length;j++){sessions[sk[j]]={solves:data.sessions[sk[j]].solves.slice(),classification:null};}
    sessionCount=Object.keys(sessions).length;
  }

  function getSummary() {
    var ts=0,td=0,at=[];var cls={human:0,bot:0,solver_farm:0,suspicious:0,uncertain:0,insufficient_data:0};
    var sk=Object.keys(sessions);for(var i=0;i<sk.length;i++){var s=sessions[sk[i]];ts+=s.solves.length;for(var j=0;j<s.solves.length;j++){at.push(s.solves[j].time);if(s.solves[j].solved)td++;}var c=classifySession(sk[i]);cls[c.classification]=(cls[c.classification]||0)+1;}
    return{totalSessions:sk.length,totalSolves:ts,overallSolveRate:ts>0?_r(td/ts,3):0,meanResponseMs:at.length>0?_r(_mean(at)):0,medianResponseMs:at.length>0?_r(_median(at)):0,challengeTypes:Object.keys(typeProfiles).length,classifications:cls};
  }

  function reset() {
    var tk=Object.keys(typeProfiles);for(var i=0;i<tk.length;i++)delete typeProfiles[tk[i]];
    var sk=Object.keys(sessions);for(var j=0;j<sk.length;j++)delete sessions[sk[j]];sessionCount=0;
  }

  return{record:record,getTypeProfile:getTypeProfile,getAllTypeProfiles:getAllTypeProfiles,detectAnomalies:detectAnomalies,classifySession:classifySession,
    getHistogram:getHistogram,getDifficultyCorrelation:getDifficultyCorrelation,getInterSolveGaps:getInterSolveGaps,getSummary:getSummary,
    exportData:exportData,importData:importData,reset:reset};
}

module.exports = { createResponseTimeProfiler: createResponseTimeProfiler };
