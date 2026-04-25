const ThreatEngine = require('../services/threatEngine');
const { getIo }    = require('../services/socketService');

const PUBLIC = ['/auth', '/health', '/logs', '/dashboard', '/socket.io', '/', '/attack', '/demo', '/api/blocked-ips', '/attacker', '/login', '/api-tester'];

// ── Per-route windows ────────────────────────────────────────────────────────
const windows = new Map();  // key → { count, windowStart }

function getWindow(key) {
  const now = Date.now();
  let rec = windows.get(key);
  if (!rec || now - rec.windowStart >= rec.windowMs) {
    rec = { count: 0, windowStart: now, windowMs: rec?.windowMs || 60000 };
    windows.set(key, rec);
  }
  rec.count++;
  return rec;
}

// ── Limits (requests per window) ────────────────────────────────────────────
const LIMITS = {
  default:       { soft: 80,  hard: 120, windowMs: 60000 },  // 80/min soft, 120/min hard
  'POST:/auth/login': { soft: 4,   hard: 6,   windowMs: 60000 },  // brute-force guard
  'POST:/api/internal/orders': { soft: 8, hard: 12, windowMs: 60000 },
  '/api/external': { soft: 40, hard: 60, windowMs: 60000 },       // external API scraping guard
  '/api/internal': { soft: 80, hard: 120, windowMs: 60000 },
};

function getLimit(req) {
  const routeKey = `${req.method}:${req.path}`;
  if (LIMITS[routeKey]) return LIMITS[routeKey];
  if (req.path.startsWith('/api/external')) return LIMITS['/api/external'];
  if (req.path.startsWith('/api/internal')) return LIMITS['/api/internal'];
  return LIMITS.default;
}

const rateLimiter = (req, res, next) => {
  const isPublic = PUBLIC.some(p => p === '/' ? req.path === '/' : req.path.startsWith(p));
  if (isPublic) return next();

  const ip     = req.clientIp || req.ip || '0.0.0.0';
  const limit  = getLimit(req);
  const winKey = `${ip}:${req.method}:${req.path.split('/').slice(0, 4).join('/')}`;
  const rec    = getWindow(winKey);
  rec.windowMs = limit.windowMs;

  req.rateInfo = { count: rec.count, soft: limit.soft, hard: limit.hard };

  // Hard block
  if (rec.count > limit.hard) {
    req.threatType = 'RATE_ABUSE';
    ThreatEngine.evaluateBrokenAuth(`ip:${ip}`, 'RATE_ABUSE', `${rec.count} req/window (hard limit ${limit.hard})`);
    const io = getIo();
    if (io) io.emit('threat', { type: 'RATE_ABUSE', ip, status: 429, time: new Date().toISOString() });
    return res.status(429).json({ error: 'Rate limit exceeded — too many requests', retryAfter: Math.ceil(limit.windowMs / 1000) });
  }

  // Soft limit
  if (rec.count > limit.soft) {
    req.threatType = 'RATE_LIMIT';
    const io = getIo();
    if (io) io.emit('threat', { type: 'RATE_LIMIT', ip, status: 429, time: new Date().toISOString() });
    return res.status(429).json({ error: 'Too many requests — slow down', retryAfter: Math.ceil(limit.windowMs / 1000) });
  }

  next();
};

// Legacy compat
const recordFailedLogin = (ip) => ThreatEngine.evaluateBrokenAuth(`ip:${ip}`, 'FAILED_LOGIN', 'Legacy call');

module.exports = rateLimiter;
module.exports.recordFailedLogin = recordFailedLogin;
