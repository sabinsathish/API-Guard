const { getIo } = require('./socketService');
const http = require('http');

// ── Dual-axis entity store (keys: 'ip:x.x.x.x' or 'user:username') ─────────
const entities = new Map();

// ── Tuning ──────────────────────────────────────────────────────────────────
const MAX_SCORE     = 100;
const DECAY_RATE    = 0.8;   // points/second decay
const BLOCK_MS      = 5 * 60 * 1000;

// Threat level thresholds for Final Risk Score
const LEVELS = { LOW: 20, MEDIUM: 40, HIGH: 70, CRITICAL: 90 };

// Scoring weights (Rule Engine)
const WEIGHTS = {
  REQUEST:       0.5,
  ERROR_4XX:     2.5,
  ERROR_5XX:     6.0,
  BROKEN_AUTH:   18.0,
  BURST_PENALTY: 2.5,
  SQL_INJECTION: 35.0,
  XSS_PAYLOAD:   30.0,
  ROUTE_SCAN:    15.0,
  ADMIN_PROBE:   20.0,
};

// ── Patterns ─────────────────────────────────────────────────────────────────
const SQL_PATTERNS = [
  /(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bunion\b|\bexec\b)/i,
  /('|\"|;|--|\/\*|\*\/)/,
  /(or\s+1\s*=\s*1|and\s+1\s*=\s*0)/i,
  /xp_cmdshell|information_schema/i,
];
const XSS_PATTERNS = [
  /<script[\s>]/i,
  /javascript:/i,
  /on\w+\s*=/i,
  /eval\s*\(|setTimeout\s*\(|setInterval\s*\(/i,
  /<iframe|<object|<embed/i,
];
const SCAN_PATHS = [
  '/admin', '/phpmyadmin', '/.env', '/config', '/wp-admin',
  '/etc/passwd', '/proc/', '/.git', '/backup', '/dump',
  '/shell', '/cmd', '/cgi-bin',
];

// ── State helpers ────────────────────────────────────────────────────────────
class ThreatEngine {

  static _getState(entityId) {
    if (!entities.has(entityId)) {
      entities.set(entityId, { 
        ruleScore: 0, 
        mlScore: 0, 
        finalScore: 0,
        lastUpdate: Date.now(), 
        blockUntil: 0, 
        reqs10s: 0,
        reqLog: [] // Rolling 5m window
      });
    }
    const s = entities.get(entityId);
    this._decay(s);
    return s;
  }

  static _decay(s) {
    const now = Date.now();
    const sec = (now - s.lastUpdate) / 1000;
    if (sec > 0) {
      s.ruleScore = Math.max(0, s.ruleScore - sec * DECAY_RATE);
      s.reqs10s   = Math.max(0, s.reqs10s - sec * 2);
      s.lastUpdate = now;
      this._calcFinalScore(s);
    }
  }

  static _calcFinalScore(s) {
    // 65% Rules / 35% ML Model
    s.finalScore = Math.min(100, Math.floor(0.65 * s.ruleScore + 0.35 * s.mlScore));
  }

  static _applyPoints(entityId, points, reason) {
    const s = this._getState(entityId);
    if (s.blockUntil > Date.now()) { s.blockUntil = Date.now() + BLOCK_MS; return s; }

    const prevFinal = s.finalScore;
    s.ruleScore = Math.min(MAX_SCORE, s.ruleScore + points);
    
    this._calcFinalScore(s);
    const level = this.getLevel(s.finalScore);

    // Rule-engine dominant cause labeling
    let dominantReason = reason;
    if (s.mlScore > 70 && points < 5) dominantReason = "Behavioral Anomaly (ML)";

    // Output Threat Events when final score crosses a threshold
    const crossed = (t) => prevFinal < t && s.finalScore >= t;

    if (crossed(LEVELS.CRITICAL)) {
      s.blockUntil = Date.now() + BLOCK_MS;
      this._emit('CRITICAL', entityId, dominantReason, s, 'CRITICAL — block');
    } else if (crossed(LEVELS.HIGH)) {
      s.blockUntil = Date.now() + BLOCK_MS;
      this._emit('HIGH', entityId, dominantReason, s, 'HIGH — 5min block');
    } else if (crossed(LEVELS.MEDIUM)) {
      this._emit('MEDIUM', entityId, dominantReason, s, 'MEDIUM — throttled');
    } else if (crossed(LEVELS.LOW)) {
      this._emit('LOW', entityId, dominantReason, s, 'LOW — logged');
    }

    const io = getIo();
    if (io) io.emit('score_update', { 
      entityId, 
      ruleScore: Math.floor(s.ruleScore), 
      mlScore: Math.floor(s.mlScore), 
      finalScore: s.finalScore, 
      level, 
      reason: dominantReason 
    });
    return s;
  }

  // ── Logging & ML Feature Extraction ─────────────────────────────────────────

  static trackRequestForML(entityId, reqData) {
    const s = this._getState(entityId);
    const now = Date.now();
    s.reqLog.push({ ...reqData, time: now });

    // Clean logs older than 5m (300,000ms)
    s.reqLog = s.reqLog.filter(x => now - x.time < 300000);

    // Re-eval ML Score asynchronously every 15 logged requests
    if (s.reqLog.length % 15 === 0) {
      this._fetchMLScoreAsync(entityId);
    }
  }

  static _extractFeatures(logBuffer) {
    const now = Date.now();
    let r1m = 0, r5m = 0;
    let _4xx = 0, _5xx = 0, _401 = 0, _403 = 0, _404 = 0;
    let authFail = 0, tokenChg = 0;
    let adminHits = 0, sensitiveHits = 0;
    let bytesSum = 0, payloadSum = 0, latSum = 0, maxLat = 0;
    let cGet = 0, cPost = 0;
    const eps = new Set(), meths = new Set(), uas = new Set(), tokens = new Set();
    const intervals = [];

    let lastTime = null;
    for (const x of logBuffer) {
        if (now - x.time < 60000) r1m++;
        r5m++;

        if (x.status >= 400 && x.status < 500) _4xx++;
        if (x.status >= 500) _5xx++;
        if (x.status === 401) _401++;
        if (x.status === 403) _403++;
        if (x.status === 404) _404++;
        
        if (x.method === 'GET') cGet++;
        if (x.method === 'POST') cPost++;

        if (x.isAuthFailed) authFail++;
        
        if (x.token) tokens.add(x.token);
        if (x.ua) uas.add(x.ua);
        eps.add(x.path);
        meths.add(x.method);

        if (x.path.includes('/admin')) adminHits++;
        if (x.path.includes('profile') || x.path.includes('order')) sensitiveHits++;

        bytesSum += (x.bytes || 0);
        payloadSum += (x.payloadSize || 0);
        if (x.latency) {
          latSum += x.latency;
          if (x.latency > maxLat) maxLat = x.latency;
        }

        if (lastTime) intervals.push(x.time - lastTime);
        lastTime = x.time;
    }

    const n = Math.max(1, logBuffer.length);
    let avgInt = 0, stdInt = 0;
    if (intervals.length > 0) {
        avgInt = intervals.reduce((a,b)=>a+b, 0) / intervals.length;
        stdInt = Math.sqrt(intervals.map(x => Math.pow(x - avgInt, 2)).reduce((a,b)=>a+b,0) / intervals.length);
    }

    return {
        req_count_1m: r1m,
        req_count_5m: r5m,
        avg_req_interval: avgInt,
        std_req_interval: stdInt,
        burst_max_5s: Math.min(150, r1m / 12), 
        unique_endpoints: eps.size,
        unique_methods: meths.size,
        get_ratio: cGet / n,
        post_ratio: cPost / n,
        '4xx_count': _4xx,
        '5xx_count': _5xx,
        '401_count': _401,
        '403_count': _403,
        '404_count': _404,
        avg_latency: latSum / n,
        max_latency: maxLat,
        bytes_sent: bytesSum,
        avg_payload_size: payloadSum / n,
        failed_auth_count: authFail,
        token_changes: tokens.size,
        distinct_user_agents: uas.size,
        admin_route_hits: adminHits,
        sensitive_route_hits: sensitiveHits
    };
  }

  static _fetchMLScoreAsync(entityId) {
    const s = this._getState(entityId);
    if (!s || s.reqLog.length < 5) return; // not enough data

    const features = this._extractFeatures(s.reqLog);
    const postData = JSON.stringify(features);

    const req = http.request({
        hostname: '127.0.0.1', port: 5002, path: '/predict', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) }
    }, (res) => {
        let rawData = '';
        res.on('data', chunk => { rawData += chunk; });
        res.on('end', () => {
            try {
                const parsed = JSON.parse(rawData);
                s.mlScore = parsed.mlScore || 0;
                this._calcFinalScore(s);
                // Trigger any potential UI updates if there's a big shift
                if (s.finalScore >= LEVELS.HIGH) this._applyPoints(entityId, 0, 'ML_ANOMALY_TRIGGER');
            } catch (e) {} 
        });
    });
    req.on('error', () => { /* ML server down, fallback to Rules only */ });
    req.write(postData);
    req.end();
  }


  // ── Public evaluation API (Rules Engine Trigger) ───────────────────────────
  static evaluateRequest(entityId) {
    const s = this._getState(entityId);
    s.reqs10s += 1;
    let pts = WEIGHTS.REQUEST;
    if (s.reqs10s > 15) pts += WEIGHTS.BURST_PENALTY;
    return this._applyPoints(entityId, pts, 'HIGH_VELOCITY');
  }

  static evaluateOutcome(entityId, status) {
    if (status >= 500) return this._applyPoints(entityId, WEIGHTS.ERROR_5XX, '5XX_ERROR');
    if (status >= 400 && status !== 401 && status !== 403)
      return this._applyPoints(entityId, WEIGHTS.ERROR_4XX, '4XX_ERROR');
  }

  static evaluateBrokenAuth(entityId, subtype, detail) {
    return this._applyPoints(entityId, WEIGHTS.BROKEN_AUTH, `BROKEN_AUTH:${subtype}`);
  }

  static evaluateSqlInjection(entityId) {
    return this._applyPoints(entityId, WEIGHTS.SQL_INJECTION, 'SQL_INJECTION_ATTEMPT');
  }

  static evaluateXss(entityId) {
    return this._applyPoints(entityId, WEIGHTS.XSS_PAYLOAD, 'XSS_PAYLOAD_DETECTED');
  }

  static evaluateRouteScan(entityId, path) {
    const pts = path.includes('admin') ? WEIGHTS.ADMIN_PROBE : WEIGHTS.ROUTE_SCAN;
    return this._applyPoints(entityId, pts, `ROUTE_SCAN:${path}`);
  }

  static evaluateRepeated401(entityId) {
    return this._applyPoints(entityId, WEIGHTS.BROKEN_AUTH * 0.6, 'REPEATED_401_403');
  }

  static isBlocked(entityId) {
    const s = this._getState(entityId);
    if (s.blockUntil > Date.now()) return true;
    if (s.blockUntil > 0) s.blockUntil = 0;
    return false;
  }

  static getLevel(score) {
    if (score >= LEVELS.CRITICAL) return 'CRITICAL';
    if (score >= LEVELS.HIGH)     return 'HIGH';
    if (score >= LEVELS.MEDIUM)   return 'MEDIUM';
    if (score >= LEVELS.LOW)      return 'LOW';
    return 'NORMAL';
  }

  static scanPayload(entityId, text) {
    if (!text || typeof text !== 'string') return;
    if (SQL_PATTERNS.some(p => p.test(text))) this.evaluateSqlInjection(entityId);
    if (XSS_PATTERNS.some(p => p.test(text))) this.evaluateXss(entityId);
  }

  static isScanPath(path) {
    return SCAN_PATHS.some(s => path.toLowerCase().startsWith(s));
  }

  static getBlockList() {
    const now = Date.now();
    return [...entities.entries()]
      .filter(([, s]) => s.blockUntil > now)
      .map(([id, s]) => ({ entityId: id, remainingSec: Math.round((s.blockUntil - now) / 1000), score: s.finalScore }));
  }

  static getAllActive() {
    return [...entities.entries()].map(([id, s]) => ({
      ip: id, 
      ruleScore: Math.floor(s.ruleScore),
      mlScore: Math.floor(s.mlScore),
      score: s.finalScore, 
      classification: this.getLevel(s.finalScore)
    }));
  }

  static _emit(level, entityId, reason, s, action) {
    const io = getIo();
    if (io) io.emit('threat', {
      type:    level === 'CRITICAL' || level === 'HIGH' ? `${entityId.startsWith('user:') ? 'USER' : 'IP'}_BLOCKED` : 'SUSPICIOUS_ACTIVITY',
      level,   
      entityId,
      ip:      entityId,
      reason,  
      ruleScore: Math.floor(s.ruleScore),
      mlScore:   Math.floor(s.mlScore),
      score:     s.finalScore,
      action,  
      status: 403,
      time:    new Date().toISOString()
    });
  }
}

module.exports = ThreatEngine;
