const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const router = express.Router();

router.use('/', createProxyMiddleware({
  target: 'https://jsonplaceholder.typicode.com',
  changeOrigin: true,
  pathRewrite: {
    '^/api': '', // we will map /api to / in jsonplaceholder
  },
}));

module.exports = router;
