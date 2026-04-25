const ThreatEngine = require('../services/threatEngine');

const PUBLIC = ['/auth', '/health', '/logs', '/dashboard', '/socket.io', '/', '/attack', '/demo', '/api/blocked-ips'];

const ipBlocker = (req, res, next) => {
  // Respects X-Forwarded-For when trust proxy is on
  const ip  = req.ip || '0.0.0.0';
  req.clientIp = ip;

  // Skip block enforcement for public/internal paths
  const isPublic = PUBLIC.some(p => p === '/' ? req.path === '/' : req.path.startsWith(p));
  if (isPublic) return next();

  // ── Enforce block using ThreatEngine ────────────────────────────────────
  if (ThreatEngine.isBlocked(`ip:${ip}`)) {
    const state = ThreatEngine._getState(`ip:${ip}`); // Get block time
    ThreatEngine._emitThreat('BLOCKED_IP_ACCESS', ip, 'THREAT', 'Connection refused - IP is blocked');
    
    return res.status(403).json({
      error: 'IP blocked due to sustained suspicious activity',
      unblockAt: new Date(state.blockUntil).toISOString(),
      currentRiskScore: Math.floor(state.score)
    });
  }

  next();
};

// Export so /api/blocked-ips can list them
const getBlockedList = () => {
  return ThreatEngine.getBlockList();
};

module.exports = ipBlocker;
module.exports.getBlockedList = getBlockedList;
