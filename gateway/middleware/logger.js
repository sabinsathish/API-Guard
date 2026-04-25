const Log = require('../models/Log');
const { getIo } = require('../services/socketService');

const SKIP = ['/health', '/logs', '/socket.io', '/dashboard', '/attack', '/demo', '/api/blocked-ips'];

const logger = (req, res, next) => {
  if (SKIP.some(p => req.path.startsWith(p))) return next();

  const startMs = Date.now();

  res.on('finish', async () => {
    const responseMs = Date.now() - startMs;
    const entry = {
      ip:         req.clientIp || req.ip || '0.0.0.0',
      endpoint:   req.originalUrl || req.url,
      method:     req.method,
      status:     res.statusCode,
      responseMs,
      userAgent:  req.get('user-agent') || '',
      threatType: req.threatType || 'NONE',
      provider:   req.extProviderName || 'system',
      sourceType: req.sourceType || 'static_route',
      targetHost: req.extProviderHost || ''
    };

    // Save to MongoDB (fire-and-forget)
    try { await Log.create(entry); } catch (_) {}

    // Push to dashboard
    const io = getIo();
    if (io) io.emit('traffic', { ...entry, time: new Date().toISOString() });
  });

  next();
};

module.exports = logger;
