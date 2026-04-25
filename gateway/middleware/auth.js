const jwt        = require('jsonwebtoken');
const ThreatEngine = require('../services/threatEngine');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secure-secret';
const PUBLIC = ['/auth', '/health', '/logs', '/dashboard', '/socket.io', '/', '/attack', '/demo', '/api/blocked-ips', '/attacker', '/login', '/api-tester'];

// Routes that require auth before reaching internal/external APIs
const PROTECTED_PREFIXES = ['/api/internal/orders', '/api/internal/profile', '/api/internal/admin'];

const authMiddleware = (req, res, next) => {
  const isPublic = PUBLIC.some(p => req.path === p || req.path.startsWith(p));
  if (isPublic || !req.path.startsWith('/api')) return next();

  // External routes: auth optional (just rate-limited) unless in protected list
  const needsAuth = PROTECTED_PREFIXES.some(p => req.path.startsWith(p));
  if (!needsAuth && req.path.startsWith('/api/external')) return next();
  if (!needsAuth && !req.path.startsWith('/api/internal')) return next();

  const ip     = req.clientIp || req.ip || '0.0.0.0';
  const header = req.headers.authorization;

  if (!header || !header.startsWith('Bearer ')) {
    ThreatEngine.evaluateBrokenAuth(`ip:${ip}`, 'MISSING_TOKEN', 'No Authorization header');
    return res.status(401).json({ error: 'Unauthorized — Bearer token required' });
  }

  const token  = header.split(' ')[1];
  const isWeak = /^[a-z]{1,8}$|^\d+$|^(test|demo|admin|token|key|api)$/i.test(token);
  if (isWeak) {
    ThreatEngine.evaluateBrokenAuth(`ip:${ip}`, 'WEAK_TOKEN', token);
    return res.status(401).json({ error: 'Unauthorized — weak or predictable token rejected' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    // Forward user context to internal backend via headers
    req.forwardedUserHeaders = {
      'X-User-Id':   req.user.id || req.user.username,
      'X-Username':  req.user.username,
      'X-User-Role': req.user.role || 'viewer',
    };
    next();
  } catch (err) {
    const subtype = err.name === 'TokenExpiredError' ? 'EXPIRED_TOKEN' : 'INVALID_TOKEN';
    ThreatEngine.evaluateBrokenAuth(`ip:${ip}`, subtype, err.message);
    return res.status(401).json({ error: `Unauthorized — ${err.message}` });
  }
};

module.exports = authMiddleware;
