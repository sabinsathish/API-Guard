const ThreatEngine = require('../services/threatEngine');
const { getIo }    = require('../services/socketService');

const PUBLIC = ['/auth', '/health', '/logs', '/dashboard', '/socket.io', '/', '/attack', '/demo', '/api/blocked-ips', '/attacker', '/login', '/api-tester'];

// Emergency global DoS failsafe
let globalCount = 0, globalWindowStart = Date.now();
const GLOBAL_DOS_LIMIT = 200;

const threatIdentifier = (req, res, next) => {
  const isPublic = PUBLIC.some(p => p === '/' ? req.path === '/' : req.path.startsWith(p));
  if (isPublic) return next();

  const ip  = req.clientIp || req.ip || '0.0.0.0';
  const now = Date.now();

  // 1. Global DoS failsafe
  if (now - globalWindowStart < 1000) {
    globalCount++;
    if (globalCount > GLOBAL_DOS_LIMIT) {
      ThreatEngine._emit('CRITICAL', `ip:${ip}`, 'GLOBAL_DOS', 100, 'Emergency DoS failsafe triggered');
      return res.status(503).json({ error: 'Service temporarily unavailable' });
    }
  } else { globalCount = 1; globalWindowStart = now; }

  // 2. Route scanning detection
  if (ThreatEngine.isScanPath(req.path)) {
    ThreatEngine.evaluateRouteScan(`ip:${ip}`, req.path);
  }

  // 3. Payload scanning (SQL injection, XSS)
  const bodyStr  = req.body   ? JSON.stringify(req.body)           : '';
  const queryStr = req.query  ? JSON.stringify(req.query)          : '';
  const fullStr  = bodyStr + ' ' + queryStr + ' ' + req.url;
  ThreatEngine.scanPayload(`ip:${ip}`, fullStr);

  // 4. IP-based scoring
  const ipState   = ThreatEngine.evaluateRequest(`ip:${ip}`);
  let   userState = null;
  const blocked   = ipState.score >= 70;

  // 5. User-identity scoring (post-auth)
  if (req.user?.username) {
    userState = ThreatEngine.evaluateRequest(`user:${req.user.username}`);
  }

  if (blocked || (userState && userState.score >= 70)) {
    const level = ThreatEngine.getLevel(Math.max(ipState.score, userState?.score || 0));
    return res.status(403).json({
      error:     'Blocked by Threat Identifier',
      riskScore: Math.floor(Math.max(ipState.score, userState?.score || 0)),
      level
    });
  }

  if (!req.threatType) req.threatType = 'NONE';

  // 6. Post-response outcome evaluation and ML tracking
  const startTime = Date.now();
  res.on('finish', () => {
    const latency = Date.now() - startTime;
    const payloadSize = req.headers['content-length'] ? parseInt(req.headers['content-length'], 10) : 0;
    const bytesSent = res.getHeader('content-length') ? parseInt(res.getHeader('content-length'), 10) : 0;
    const isAuthFailed = (res.statusCode === 401 || res.statusCode === 403);
    const token = req.headers['authorization']?.split(' ')[1] || null;

    const reqData = {
      path: req.path,
      method: req.method,
      status: res.statusCode,
      latency,
      bytes: bytesSent,
      payloadSize,
      isAuthFailed,
      ua: req.headers['user-agent'] || '',
      token
    };

    ThreatEngine.trackRequestForML(`ip:${ip}`, reqData);
    if (req.user?.username) ThreatEngine.trackRequestForML(`user:${req.user.username}`, reqData);

    ThreatEngine.evaluateOutcome(`ip:${ip}`, res.statusCode);
    if (req.user?.username) ThreatEngine.evaluateOutcome(`user:${req.user.username}`, res.statusCode);
    
    // Repeated 401/403 tracking
    if (isAuthFailed) ThreatEngine.evaluateRepeated401(`ip:${ip}`);
  });

  next();
};

module.exports = threatIdentifier;
