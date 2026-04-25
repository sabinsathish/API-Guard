const express = require('express');
const router = express.Router();
const registryService = require('../services/registryService');
const { getIo } = require('../services/socketService');

// Admin middleware - reuse logic to ensure only admins can register APIs
// If the main auth middleware sets req.user and req.user.role, check it.
router.use((req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required to register APIs' });
  }
  next();
});

router.post('/register-api', (req, res) => {
  try {
    const apiData = req.body;
    
    // Attempt to register
    const entry = registryService.addApi(apiData);

    // Notify dashboard to update via socket
    const io = getIo();
    if (io) {
      io.emit('api_registered', registryService.getAllApis());
    }

    res.status(201).json({
      message: 'API successfully registered',
      api: {
        name: entry.name,
        target: entry.target,
        route: `/api/external/${entry.name}`,
        createdAt: entry.createdAt
      }
    });

  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/list-apis', (req, res) => {
  // Safe list without exposing apiKey
  const safeList = registryService.getAllApis().map(a => ({
    name: a.name,
    target: a.target,
    enabled: a.enabled,
    hasKey: !!a.apiKey,
    createdAt: a.createdAt
  }));
  res.json(safeList);
});

module.exports = router;
