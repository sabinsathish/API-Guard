const ThreatEngine = require('../services/threatEngine');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secure-secret';

// ── ONLY these are truly always open (no login = no block check possible) ────
const ALWAYS_OPEN = [
  '/auth', '/health', '/logs', '/login',
  '/socket.io', '/api/blocked-ips'
];

// ── Admin-only pages: never blocked even if IP is blocked ─────────────────────
const ADMIN_PAGES = ['/dashboard', '/admin'];

const ipBlocker = (req, res, next) => {
  const ip = req.ip || '0.0.0.0';
  req.clientIp = ip;

  // ── RULE 1: Always open paths — no check at all ───────────────────────────
  const isAlwaysOpen = ALWAYS_OPEN.some(p => req.path.startsWith(p));
  if (isAlwaysOpen) return next();

  // ── RULE 2: Admin pages — never blocked (admin safety) ───────────────────
  const isAdminPage = ADMIN_PAGES.some(p => req.path.startsWith(p));
  if (isAdminPage) return next();

  // ── RULE 3: Check USER block first (works across devices) ────────────────
  try {
    const header = req.headers.authorization;
    if (header && header.startsWith('Bearer ')) {
      const token = header.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      const username = decoded.username;

      if (username && ThreatEngine.isBlocked(`user:${username}`)) {
        const state = ThreatEngine._getState(`user:${username}`);
        ThreatEngine._emitThreat('BLOCKED_USER_ACCESS', ip, 'THREAT',
          `Blocked user "${username}" tried to access from ${ip}`);

        // Auto-block the new IP too
        ThreatEngine._applyPoints(`ip:${ip}`, 100,
          'Device used by blocked user account');

        return res.status(403).json({
          error: `Account "${username}" is blocked due to suspicious activity`,
          unblockAt: new Date(state.blockUntil).toISOString(),
          currentRiskScore: Math.floor(state.finalScore || 0)
        });
      }
    }
  } catch (err) {
    // Bad token — auth middleware will handle it
  }

  // ── RULE 4: Check IP block ────────────────────────────────────────────────
  if (ThreatEngine.isBlocked(`ip:${ip}`)) {
    const state = ThreatEngine._getState(`ip:${ip}`);
    ThreatEngine._emitThreat('BLOCKED_IP_ACCESS', ip, 'THREAT',
      'Connection refused - IP is blocked');

    return res.status(403).json({
      error: 'IP blocked due to sustained suspicious activity',
      unblockAt: new Date(state.blockUntil).toISOString(),
      currentRiskScore: Math.floor(state.finalScore || 0)
    });
  }

  next();
};

const getBlockedList = () => ThreatEngine.getBlockList();

module.exports = ipBlocker;
module.exports.getBlockedList = getBlockedList;