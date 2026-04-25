/**
 * External Routes — smart proxy to JSONPlaceholder and DummyJSON
 *
 * /api/external/posts     → https://jsonplaceholder.typicode.com/posts
 * /api/external/users     → https://jsonplaceholder.typicode.com/users
 * /api/external/comments  → https://jsonplaceholder.typicode.com/comments
 * /api/external/store     → https://dummyjson.com (e.g. /store/products → /products)
 */
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const router  = express.Router();

// ── JSONPlaceholder proxy ────────────────────────────────────────────────────
const jsonPlaceholderProxy = createProxyMiddleware({
  target:      'https://jsonplaceholder.typicode.com',
  changeOrigin: true,
  pathRewrite:  { '^/api/external': '' },
  on: {
    proxyReq: (proxyReq, req) => {
      req.extProviderName = 'JSONPlaceholder';
      req.extProviderHost = 'https://jsonplaceholder.typicode.com';
      req.sourceType = 'static_external';
    },
    error: (err, req, res) => res.status(502).json({ error: 'JSONPlaceholder unavailable', detail: err.message })
  }
});

// ── DummyJSON proxy ────────────────────────────────────────────────────────
const dummyJsonProxy = createProxyMiddleware({
  target:      'https://dummyjson.com',
  changeOrigin: true,
  pathRewrite:  { '^/api/external/store': '' },
  on: {
    proxyReq: (proxyReq, req) => {
      req.extProviderName = 'DummyJSON';
      req.extProviderHost = 'https://dummyjson.com';
      req.sourceType = 'static_external';
    },
    error: (err, req, res) => res.status(502).json({ error: 'DummyJSON unavailable', detail: err.message })
  }
});

const registryService = require('../services/registryService');

// Route to correct upstream manually first (backward compatibility)
router.use('/store', dummyJsonProxy);
// The old jsonplaceholder proxy intercepted EVERYTHING at '/'. 
// We must only intercept exactly '/' or specific routes if we want dynamic generic proxies under '/:service'.
// Wait! If jsonplaceholder is mounted at '/', it will match everything!
// We'll move jsonplaceholder to only match if there's no dynamic match, but express order matters.
// Let's create the dynamic proxy first, and fallback to jsonplaceholder if not found.

router.use('/:service', (req, res, next) => {
  const service = req.params.service;
  
  // If requesting a hardcoded route that somehow got here, skip handles
  if (service === 'store') return next();

  const apiConfig = registryService.getApiConfig(service);
  
  if (!apiConfig) {
    // Before introducing dynamic APIs, all other traffic went to jsonPlaceholderProxy.
    // To preserve 100% backward compatibility, we MUST proxy to JSONPlaceholder if not found in registry.
    return jsonPlaceholderProxy(req, res, next);
  }

  if (!apiConfig.enabled) {
    return res.status(403).json({ error: `Provider '${apiConfig.name}' disabled` });
  }

  // Pass tracking metadata for the Logger/Metrics
  req.extProviderName = apiConfig.name;
  req.extProviderHost = apiConfig.target;
  req.sourceType = 'dynamic_external';

  // Build a one-off proxy or caching it would be better. For simplicity and robustness, creating it on the fly:
  const dynamicProxy = createProxyMiddleware({
    target: apiConfig.target,
    changeOrigin: true,
    pathRewrite: { [`^/api/external/${service}`]: '' },
    on: {
      error: (err, req, res) => res.status(502).json({ error: `Provider ${apiConfig.name} unavailable`, detail: err.message }),
      proxyReq: (proxyReq, req, res) => {
        // Inject optional API keys gracefully
        if (apiConfig.apiKey && apiConfig.headerName) {
          proxyReq.setHeader(apiConfig.headerName, apiConfig.apiKey);
        }
      }
    }
  });

  return dynamicProxy(req, res, next);
});

// For absolute root (/) which jsonPlaceholder typically handled:
router.use('/', jsonPlaceholderProxy);

module.exports = router;
