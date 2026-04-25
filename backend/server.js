/**
 * Internal Backend — Port 5000
 * Reuses gateway's node_modules for convenience (no separate npm install needed).
 */
const path = require('path');
// Fall back to gateway's node_modules if local ones don't exist
process.env.NODE_PATH = path.join(__dirname, '../gateway/node_modules');
require('module').Module._initPaths();

const express = require('express');
const cors    = require('cors');
const app     = express();

app.use(express.json());
app.use(cors({ origin: 'http://localhost:3000' }));

// ── Middleware: Read trusted gateway headers ────────────────────────────────
const trustGateway = (req, res, next) => {
  // Gateway stamps these after verifying JWT
  req.gatewayUser = {
    id:       req.headers['x-user-id']   || null,
    username: req.headers['x-username']  || null,
    role:     req.headers['x-user-role'] || 'anonymous',
  };
  next();
};

const requireAuth = (req, res, next) => {
  if (!req.gatewayUser.id) return res.status(401).json({ error: 'Unauthorized — no gateway user context' });
  next();
};

const requireAdmin = (req, res, next) => {
  if (req.gatewayUser.role !== 'admin') return res.status(403).json({ error: 'Forbidden — admin role required' });
  next();
};

app.use(trustGateway);

// ════════════════════════════════════════════════
// PUBLIC ROUTES
// ════════════════════════════════════════════════
app.get('/products', (req, res) => {
  res.json({
    source: 'Internal API — Products Service',
    count: 10,
    data: [
      { id: 1, name: 'Secure Cloud Storage',   price: 49.99,  category: 'Cloud',      stock: 120 },
      { id: 2, name: 'Firewall Pro License',   price: 299.00, category: 'Security',   stock: 45  },
      { id: 3, name: 'VPN Enterprise Suite',   price: 199.99, category: 'Network',    stock: 88  },
      { id: 4, name: 'API Gateway Starter',    price: 0,      category: 'Gateway',    stock: 999 },
      { id: 5, name: 'Threat Monitor Addon',   price: 79.99,  category: 'Monitoring', stock: 200 },
      { id: 6, name: 'SOC Dashboard License',  price: 149.99, category: 'Dashboard',  stock: 67  },
      { id: 7, name: 'JWT Auth SDK',           price: 29.99,  category: 'Auth',       stock: 500 },
      { id: 8, name: 'Redis Rate Limiter',     price: 59.99,  category: 'Infra',      stock: 150 },
      { id: 9, name: 'Log Aggregator Suite',   price: 89.99,  category: 'Logging',    stock: 90  },
      { id:10, name: 'Zero-Trust Access Mgr',  price: 399.99, category: 'Security',   stock: 30  },
    ]
  });
});

app.get('/users/public', (req, res) => {
  res.json({
    source: 'Internal API — Users Service (Public)',
    data: [
      { id: 1, username: 'alice_dev',   role: 'analyst', department: 'Engineering' },
      { id: 2, username: 'bob_ops',     role: 'viewer',  department: 'Operations'  },
      { id: 3, username: 'carol_sec',   role: 'admin',   department: 'Security'    },
      { id: 4, username: 'dave_infra',  role: 'analyst', department: 'Infra'       },
    ]
  });
});

// ════════════════════════════════════════════════
// PROTECTED ROUTES (require valid JWT via gateway)
// ════════════════════════════════════════════════
app.post('/orders', requireAuth, (req, res) => {
  const { productId, quantity } = req.body || {};
  if (!productId || !quantity) return res.status(400).json({ error: 'productId and quantity are required' });
  res.status(201).json({
    source: 'Internal API — Orders Service',
    order: {
      id:         `ORD-${Date.now()}`,
      productId,
      quantity,
      placedBy:   req.gatewayUser.username,
      status:     'confirmed',
      timestamp:  new Date().toISOString(),
    }
  });
});

app.get('/profile', requireAuth, (req, res) => {
  res.json({
    source: 'Internal API — User Profile',
    profile: {
      id:         req.gatewayUser.id,
      username:   req.gatewayUser.username,
      role:       req.gatewayUser.role,
      lastActive: new Date().toISOString(),
      permissions: req.gatewayUser.role === 'admin'
        ? ['read', 'write', 'delete', 'admin']
        : ['read', 'write'],
    }
  });
});

// ════════════════════════════════════════════════
// ADMIN ROUTES (require admin role)
// ════════════════════════════════════════════════
app.get('/admin/dashboard', requireAuth, requireAdmin, (req, res) => {
  res.json({
    source: 'Internal API — Admin Dashboard',
    stats: {
      totalUsers:    4,
      activeOrders:  17,
      revenue:       '$12,840.00',
      threatAlerts:  3,
      systemStatus:  'operational',
      serverUptime:  process.uptime(),
    },
    recentActivity: [
      { type: 'login',   user: 'alice_dev',  time: new Date(Date.now() - 120000).toISOString() },
      { type: 'order',   user: 'bob_ops',    time: new Date(Date.now() - 300000).toISOString() },
      { type: 'threat',  user: 'unknown_ip', time: new Date(Date.now() - 600000).toISOString() },
    ]
  });
});

app.delete('/admin/user/:id', requireAuth, requireAdmin, (req, res) => {
  res.json({
    source: 'Internal API — Admin User Management',
    message: `User ${req.params.id} deleted by ${req.gatewayUser.username}`,
    deletedBy: req.gatewayUser.username,
    timestamp: new Date().toISOString(),
  });
});

// ── Health check ───────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', service: 'internal-backend', port: 5000 }));

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: `No route: ${req.method} ${req.path}` }));

const PORT = process.env.BACKEND_PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n  ╔════════════════════════════════════════╗`);
  console.log(`  ║  🔧 Internal Backend — Port ${PORT}        ║`);
  console.log(`  ║  Products, Orders, Profile, Admin       ║`);
  console.log(`  ╚════════════════════════════════════════╝\n`);
});
