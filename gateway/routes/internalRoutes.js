/**
 * Internal Routes — proxies /api/internal/* → http://localhost:5000/*
 * Strips the /api/internal prefix and injects trusted user headers.
 */
const { createProxyMiddleware } = require('http-proxy-middleware');

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:5000';

const internalProxy = createProxyMiddleware({
  target:      BACKEND_URL,
  changeOrigin: true,
  pathRewrite:  { '^/api/internal': '' },

  // Inject user context headers so backend can trust them
  on: {
    proxyReq: (proxyReq, req) => {
      req.extProviderName = 'Internal-Backend';
      req.extProviderHost = BACKEND_URL;
      req.sourceType = 'internal_proxy';

      if (req.forwardedUserHeaders) {
        Object.entries(req.forwardedUserHeaders).forEach(([k, v]) => {
          proxyReq.setHeader(k, v);
        });
      }
      proxyReq.setHeader('X-Gateway-Source', 'secure-api-gateway');
      proxyReq.setHeader('X-Request-Id', `gw-${Date.now()}`);
    },
    error: (err, req, res) => {
      console.error('[internal-proxy] error:', err.message);
      res.status(502).json({ error: 'Internal backend unavailable', detail: err.message });
    }
  }
});

module.exports = internalProxy;
