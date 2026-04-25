const { getIo } = require('../services/socketService');

const PUBLIC = ['/auth', '/health', '/logs', '/dashboard', '/socket.io', '/'];

// Global rolling window for DoS detection across ALL IPs
let globalCount       = 0;
let globalWindowStart = Date.now();
const GLOBAL_DOS_LIMIT = 150;  // requests/second across whole server

const threatDetector = (req, res, next) => {
  const isPublic = PUBLIC.some(p => p === '/' ? req.path === '/' : req.path.startsWith(p));
  if (isPublic) return next();

  const ip  = req.clientIp || req.ip || '0.0.0.0';
  const now = Date.now();

  // ── Global DoS sweep ─────────────────────────────────────────────────────
  if (now - globalWindowStart < 1000) {
    globalCount++;
    if (globalCount > GLOBAL_DOS_LIMIT) {
      req.threatType = 'DOS_ATTACK';
      if (req.blockIp) req.blockIp();
      const io = getIo();
      if (io) io.emit('threat', { type: 'DOS_ATTACK', ip, status: 503, time: new Date().toISOString() });
      return res.status(503).json({ error: 'DoS detected — service temporarily unavailable' });
    }
  } else {
    globalCount = 1;
    globalWindowStart = now;
  }

  // threatType may already be set by rateLimiter (RATE_ABUSE, RATE_LIMIT)
  if (!req.threatType) req.threatType = 'NONE';

  next();
};

module.exports = threatDetector;
