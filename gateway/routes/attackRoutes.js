/**
 * Attack Simulation Routes  (/demo/*)
 *
 * KEY FIX: All /api requests now carry a valid JWT so they pass auth
 * and reach the rate-limiter / threat-detector / ip-blocker for real.
 * Brute-force and broken-auth use intentionally bad credentials / tokens.
 */

const express = require('express');
const http    = require('http');
const path    = require('path');
const { spawn } = require('child_process');
const router  = express.Router();
const jwt     = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'super-secure-secret';

// ── Shared state ──────────────────────────────────────────────────────────────
let demoRunning  = false;
let pythonProc   = null;
let cachedToken  = null;   // valid JWT for /api requests

// Track recently-seen attacker IPs for the UI
const recentIPs   = new Map(); // ip → { count, lastSeen, blocked }
const blockedIpsSet = new Set();

// ── Token cache (get once, reuse) ─────────────────────────────────────────────
async function getToken() {
  if (cachedToken) {
    try { jwt.verify(cachedToken, JWT_SECRET); return cachedToken; } catch { cachedToken = null; }
  }
  const res = await gatewayReq({ method: 'POST', path: '/auth/login', ip: '127.0.0.1',
    body: { username: 'admin', password: 'password123' } });
  try { cachedToken = JSON.parse(res.body).token; } catch { cachedToken = null; }
  return cachedToken;
}

// ── Internal HTTP helper ───────────────────────────────────────────────────────
function gatewayReq({ method = 'GET', path: reqPath, ip, token, body } = {}) {
  return new Promise(resolve => {
    const postBody = body ? JSON.stringify(body) : undefined;
    const opts = {
      hostname: 'localhost', port: 3000,
      path: reqPath, method,
      headers: {
        'Content-Type':    'application/json',
        'X-Forwarded-For': ip,
        'User-Agent':      `AttackBot/1.0 ip=${ip}`,
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      }
    };
    if (postBody) opts.headers['Content-Length'] = Buffer.byteLength(postBody);
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        trackIP(ip, res.statusCode);
        resolve({ status: res.statusCode, body: data });
      });
    });
    req.on('error', () => resolve({ status: 0, body: 'error' }));
    if (postBody) req.write(postBody);
    req.end();
  });
}

// Track IPs for /demo/active-ips endpoint
function trackIP(ip, status) {
  const r = recentIPs.get(ip) || { count: 0, lastSeen: 0, statuses: {} };
  r.count++;
  r.lastSeen = Date.now();
  r.statuses[status] = (r.statuses[status] || 0) + 1;
  if (status === 403) r.blocked = true;
  recentIPs.set(ip, r);
  if (recentIPs.size > 500) {
    const oldest = [...recentIPs.entries()].sort((a,b) => a[1].lastSeen - b[1].lastSeen)[0];
    recentIPs.delete(oldest[0]);
  }
}

const randIp = () => `${r(10,220)}.${r(0,255)}.${r(0,255)}.${r(1,254)}`;
function r(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }
const sleep = ms => new Promise(res => setTimeout(res, ms));
const emit  = msg => { const { getIo } = require('../services/socketService'); const io = getIo(); if (io) io.emit('demo_status', msg); };

// ── GET /demo/active-entities — live IP & User table ─────────────────────────
router.get('/active-entities', (_, res) => {
  const ThreatEngine = require('../services/threatEngine');
  const now  = Date.now();
  
  // Clean up recentIPs map based on lastSeen
  for (const [k, v] of recentIPs.entries()) {
    if (now - v.lastSeen > 30000) recentIPs.delete(k);
  }

  const allActive = ThreatEngine.getAllActive().map(state => {
    // Merge with tracked stats if we have them from attackRoutes generator
    const stats = recentIPs.get(state.ip) || { count: 1, statuses: {} };
    return {
      id: state.ip.replace(/^(ip:|user:)/, ''),
      originalId: state.ip,
      type: state.ip.startsWith('user:') ? 'user' : 'ip',
      score: state.score,
      classification: state.classification,
      blocked: ThreatEngine.isBlocked(state.ip),
      count: stats.count,
      statuses: stats.statuses
    };
  });

  const ips   = allActive.filter(a => a.type === 'ip').sort((a,b) => b.score - a.score).slice(0, 30);
  const users = allActive.filter(a => a.type === 'user').sort((a,b) => b.score - a.score).slice(0, 30);

  res.json({ ips, users });
});

// ── POST /demo/normal ─────────────────────────────────────────────────────────
router.post('/normal', async (req, res) => {
  const count = Math.min(req.body?.count || 15, 50);
  res.json({ started: true, mode: 'NORMAL', requests: count });
  const token = await getToken();
  const ip    = randIp();
  for (let i = 0; i < count; i++) {
    await gatewayReq({ path: '/api/external/posts/1', ip, token });
    await sleep(200);
  }
});

// ── POST /demo/rate-abuse — ONE IP floods fast ────────────────────────────────
router.post('/rate-abuse', async (req, res) => {
  const count = Math.min(req.body?.count || 100, 250);
  res.json({ started: true, mode: 'RATE_ABUSE', requests: count });
  const token   = await getToken();
  const ip      = randIp();
  const promises = Array.from({ length: count }, () => gatewayReq({ path: '/api/external/posts', ip, token }));
  await Promise.allSettled(promises);
});

// ── POST /demo/brute-force — many IPs, bad creds ──────────────────────────────
router.post('/brute-force', async (req, res) => {
  const count   = Math.min(req.body?.count || 40, 150);
  res.json({ started: true, mode: 'BRUTE_FORCE', requests: count });
  const users   = ['root','admin','administrator','superuser','ubuntu','operator','sysadmin','guest','test','oracle'];
  const pawds   = ['123456','password','admin123','letmein','qwerty','abc123','111111','monkey','dragon','master'];
  for (let i = 0; i < count; i++) {
    const ip = randIp();   // different IP per attempt — shows in the IP table
    gatewayReq({ method: 'POST', path: '/auth/login', ip,
      body: { username: users[i % users.length], password: pawds[i % pawds.length] }
    });
    await sleep(60);
  }
});

// ── POST /demo/broken-auth — expired/weak/forged tokens ──────────────────────
router.post('/broken-auth', async (req, res) => {
  const attempts = 24;
  res.json({ started: true, mode: 'BROKEN_AUTH', attempts });
  const expiredToken = jwt.sign({ user: 'attacker' }, JWT_SECRET, { expiresIn: -1 });
  const weakTokens   = () => `apikey${r(1,9999)}`;
  const forgedToken  = jwt.sign({ user: 'hacker', role: 'admin' }, 'wrong-secret', { expiresIn: '2h' });
  const tokens = [expiredToken, weakTokens(), forgedToken, null];
  for (let i = 0; i < attempts; i++) {
    const token = tokens[i % 4];
    const ip    = randIp();
    gatewayReq({ path: '/api/external/posts', ip, token: token || undefined });
    await sleep(120);
  }
});

// ── POST /demo/dos — many IPs flood simultaneously ──────────────────────────────────
router.post('/dos', async (req, res) => {
  const threads = Math.min(req.body?.threads || 50, 100);
  const burst   = Math.min(req.body?.burst   || 6,  20);
  res.json({ started: true, mode: 'DOS_ATTACK', threads, totalRequests: threads * burst });
  const token    = await getToken();
  const promises = [];
  for (let t = 0; t < threads; t++) {
    const ip = randIp();
    for (let b = 0; b < burst; b++) {
      promises.push(gatewayReq({ path: '/api/external/posts', ip, token }));
    }
  }
  Promise.allSettled(promises);
});

// ── POST /demo/run-demo — full 5-phase automated demo ────────────────────────
router.post('/run-demo', async (req, res) => {
  if (demoRunning) return res.status(409).json({ error: 'Demo already running' });
  demoRunning = true;
  res.json({ started: true, mode: 'FULL_DEMO' });
  recentIPs.clear();

  try {
    // Phase 1 — Normal
    emit({ phase: 'NORMAL', msg: '📡 Phase 1/5 — Normal Traffic: legitimate requests at ~5 req/s' });
    const token  = await getToken();
    const normIp = randIp();
    for (let i = 0; i < 20; i++) { await gatewayReq({ path: '/api/external/posts/1', ip: normIp, token }); await sleep(200); }
    await sleep(1000);

    // Phase 2 — Rate Abuse
    emit({ phase: 'RATE_ABUSE', msg: '⚡ Phase 2/5 — Rate Abuse: single IP hammering the API' });
    await sleep(500);
    const abuseIp = randIp();
    const abusePs = Array.from({ length: 120 }, () => gatewayReq({ path: '/api/external/posts', ip: abuseIp, token }));
    await Promise.allSettled(abusePs);
    await sleep(2000);

    // Phase 3 — Brute Force
    emit({ phase: 'BRUTE_FORCE', msg: '🔑 Phase 3/5 — Brute Force: 35 different IPs trying to log in' });
    await sleep(500);
    const bfUsers = ['root','admin','superuser','ubuntu','ops','test','guest'];
    const bfPawds = ['123456','password','admin','letmein','qwerty','abc123'];
    // 5 IPs doing 7 attempts each (Total 35)
    for (let ipIdx = 0; ipIdx < 5; ipIdx++) {
      const targetIp = randIp();
      for (let attempt = 0; attempt < 7; attempt++) {
        gatewayReq({ method: 'POST', path: '/auth/login', ip: targetIp,
          body: { username: bfUsers[attempt % bfUsers.length], password: bfPawds[attempt % bfPawds.length] }
        });
        await sleep(50);
      }
      await sleep(200);
    }
    await sleep(2000);

    // Phase 4 — Broken Auth
    emit({ phase: 'BROKEN_AUTH', msg: '🔓 Phase 4/5 — Broken Auth: expired, weak, and forged tokens' });
    await sleep(500);
    const expTok = jwt.sign({ user: 'x' }, JWT_SECRET, { expiresIn: -1 });
    const frgTok = jwt.sign({ user: 'hacker' }, 'wrong-key');
    const badToks = [expTok, `apikey${r(1,99)}`, frgTok, undefined];
    for (let i = 0; i < 20; i++) {
      gatewayReq({ path: '/api/external/posts', ip: randIp(), token: badToks[i % 4] });
      await sleep(120);
    }
    await sleep(2000);

    // Phase 5 — DoS
    emit({ phase: 'DOS', msg: '💥 Phase 5/5 — DoS Flood: 60 different IPs attacking simultaneously' });
    await sleep(500);
    const dosToken = await getToken();
    const dosPs    = [];
    for (let t = 0; t < 60; t++) {
      const dip = randIp();
      for (let b = 0; b < 6; b++) dosPs.push(gatewayReq({ path: '/api/external/posts', ip: dip, token: dosToken }));
    }
    await Promise.allSettled(dosPs);
    await sleep(1000);

    emit({ phase: 'COMPLETE', msg: '✅ Full Demo complete! All 5 attack phases executed.' });
  } finally {
    demoRunning = false;
  }
});

// ── POST /demo/sql-inject — SQL injection payloads ──────────────────────────────
router.post('/sql-inject', async (req, res) => {
  res.json({ started: true, mode: 'SQL_INJECTION', attempts: 6 });
  const token = await getToken();
  const payloads = [
    `/api/external/posts?id=1' OR '1'='1`,
    `/api/external/posts?search='; DROP TABLE users; --`,
    `/api/internal/products?filter=1 UNION SELECT * FROM users`,
    `/api/external/users?id=1; exec xp_cmdshell('whoami')`,
    `/api/external/posts?name=admin'--`,
    `/api/internal/products?q=1 AND 1=1 --`,
  ];
  for (const path of payloads) { gatewayReq({ path, ip: randIp(), token }); await sleep(400); }
});

// ── POST /demo/xss — XSS payload attempts ───────────────────────────────────────────
router.post('/xss', async (req, res) => {
  res.json({ started: true, mode: 'XSS_ATTACK', attempts: 5 });
  const token = await getToken();
  const payloads = [
    `/api/external/posts?q=${encodeURIComponent('<script>alert("xss")</script>')}`,
    `/api/external/posts?name=${encodeURIComponent('javascript:void(document.cookie)')}`,
    `/api/external/posts?comment=${encodeURIComponent('<img src=x onerror=alert(1)>')}`,
    `/api/external/posts?data=${encodeURIComponent('<iframe src="javascript:alert(1)">')}`,
    `/api/external/users?q=${encodeURIComponent('onmouseover=alert(1)')}`,
  ];
  for (const path of payloads) { gatewayReq({ path, ip: randIp(), token }); await sleep(400); }
});

// ── POST /demo/admin-probe — unprivileged user tries admin routes ────────────────
router.post('/admin-probe', async (req, res) => {
  res.json({ started: true, mode: 'ADMIN_PROBE', attempts: 8 });
  const token = await getToken(); // viewer token
  const paths = [
    '/api/internal/admin/dashboard',
    '/api/internal/admin/user/1',
    '/admin', '/.env', '/config', '/phpmyadmin', '/wp-admin', '/.git/config'
  ];
  for (const path of paths) { gatewayReq({ path, ip: randIp(), token }); await sleep(300); }
});

// ── POST /demo/scrape — external API scraping flood ────────────────────────────
router.post('/scrape', async (req, res) => {
  const count = Math.min(req.body?.count || 80, 200);
  res.json({ started: true, mode: 'EXTERNAL_SCRAPING', requests: count });
  const scrapePaths = ['/api/external/posts', '/api/external/users', '/api/external/comments', '/api/external/store/products'];
  const ip = randIp();
  for (let i = 0; i < count; i++) {
    gatewayReq({ path: scrapePaths[i % scrapePaths.length], ip });
    await sleep(50);
  }
});

// ── POST /demo/brute-force — Individual trigger ────────────────────────────────
router.post('/brute-force', async (req, res) => {
  res.json({ started: true, mode: 'BRUTE_FORCE' });
  const bfUsers = ['root','admin','superuser','ubuntu','ops','test','guest'];
  const bfPawds = ['123456','password','admin','letmein','qwerty','abc123'];
  const targetIp = randIp();
  for (let attempt = 0; attempt < 8; attempt++) {
    gatewayReq({ method: 'POST', path: '/auth/login', ip: targetIp,
      body: { username: bfUsers[attempt % bfUsers.length], password: bfPawds[attempt % bfPawds.length] }
    });
    await sleep(80);
  }
});

// ── POST /demo/dos — Individual trigger (Intense) ──────────────────────────────
router.post('/dos', async (req, res) => {
  res.json({ started: true, mode: 'DOS_FLOOD' });
  const token = await getToken();
  const dip = randIp();
  const dosPs = [];
  // Send 100 requests quickly from a single IP to trigger block
  for (let i = 0; i < 100; i++) {
    dosPs.push(gatewayReq({ path: '/api/external/posts', ip: dip, token }));
    if (i % 20 === 0) await sleep(20);
  }
  await Promise.allSettled(dosPs);
});

// ── POST /demo/route-scan — Individual trigger ────────────────────────────────
router.post('/route-scan', async (req, res) => {
  res.json({ started: true, mode: 'ROUTE_SCAN' });
  const token = await getToken();
  const targetIp = randIp();
  const paths = ['/admin', '/.env', '/config', '/phpmyadmin', '/wp-admin', '/.git/config', '/api/internal/admin/dashboard'];
  for (const p of paths) {
    gatewayReq({ path: p, ip: targetIp, token });
    await sleep(200);
  }
});

// ── GET /demo/run-python?mode=X&duration=N — stream attack.py via SSE ─────────
router.get('/run-python', (req, res) => {
  const mode     = ['normal','rate_abuse','brute_force','dos','demo'].includes(req.query.mode) ? req.query.mode : 'demo';
  const duration = parseInt(req.query.duration) || 10;

  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders?.();

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  const scriptPath = path.join(__dirname, '../../attacker/attack.py');
  const args       = [scriptPath, mode, '--duration', String(duration), '--host', 'http://localhost:3000'];

  send({ type: 'start', msg: `▶ Spawning: python ${args.join(' ')}` });

  let proc;
  try {
    proc = spawn('python', args, { env: { ...process.env, PYTHONIOENCODING: 'utf-8' } });
    pythonProc = proc;
  } catch (e) {
    send({ type: 'error', msg: `Failed to start Python: ${e.message}` });
    res.end();
    return;
  }

  // Strip ANSI color codes for clean output
  const stripAnsi = s => s.replace(/\x1b\[[0-9;]*[mGKHF]/g, '');

  proc.stdout.on('data', chunk => send({ type: 'stdout', msg: stripAnsi(chunk.toString()) }));
  proc.stderr.on('data', chunk => send({ type: 'stderr', msg: stripAnsi(chunk.toString()) }));
  proc.on('close',  code => { send({ type: 'done', code }); res.end(); pythonProc = null; });
  proc.on('error',  err  => { send({ type: 'error', msg: err.message }); res.end(); pythonProc = null; });

  req.on('close', () => { try { proc.kill(); } catch {} pythonProc = null; });
});

// ── POST /demo/stop-python ────────────────────────────────────────────────────
router.post('/stop-python', (_, res) => {
  if (pythonProc) { try { pythonProc.kill(); } catch {} pythonProc = null; }
  demoRunning = false;
  res.json({ stopped: true });
});

router.get('/status', (_, res) => res.json({ demoRunning, pythonRunning: !!pythonProc }));
router.post('/stop',  (_, res) => { demoRunning = false; res.json({ stopped: true }); });

module.exports = router;
