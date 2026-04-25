require('dotenv').config();
const express    = require('express');
const http       = require('http');
const path       = require('path');
const cors       = require('cors');
const mongoose   = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const fs         = require('fs');

const socketService    = require('./services/socketService');
const metricsService   = require('./services/metricsService');
const ipBlocker        = require('./middleware/ipBlocker');
const logger           = require('./middleware/logger');
const rateLimiter      = require('./middleware/rateLimiter');
const authMiddleware   = require('./middleware/auth');
const threatIdentifier = require('./middleware/threatIdentifier');

const authRoutes     = require('./routes/authRoutes');
const internalProxy  = require('./routes/internalRoutes');
const externalRoutes = require('./routes/externalRoutes');
const attackRoutes   = require('./routes/attackRoutes');

const app    = express();
const server = http.createServer(app);

// ── Trust proxy (for X-Forwarded-For in multi-IP attack simulation) ───────────
app.set('trust proxy', true);

// ── Core setup ────────────────────────────────────────────────────────────────
socketService.init(server);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','PATCH','OPTIONS'] }));

// Hide Express fingerprint
app.disable('x-powered-by');

// ── Metrics tracking ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.on('finish', () => {
    const source = req.path.startsWith('/api/internal') ? 'internal'
                 : req.path.startsWith('/api/external') ? 'external'
                 : null;
    if (source) metricsService.record({ ip: req.clientIp || req.ip, path: req.path, status: res.statusCode, source });
  });
  next();
});

// ── SECURITY MIDDLEWARE PIPELINE ──────────────────────────────────────────────
app.use(logger);
app.use(ipBlocker);
app.use(rateLimiter);
app.use(authMiddleware);
app.use(threatIdentifier);

// ── Static pages ──────────────────────────────────────────────────────────────
app.get('/', (_, res) => res.redirect('/login/'));
app.use('/login',      express.static(path.join(__dirname, '../login')));
app.use('/dashboard',  express.static(path.join(__dirname, '../dashboard')));
app.use('/attack',     express.static(path.join(__dirname, '../attack-ui')));
app.use('/attacker',   express.static(path.join(__dirname, '../attacker-ui')));
app.use('/api-tester', express.static(path.join(__dirname, '../api-tester')));

// ── Auth & Admin routes ────────────────────────────────────────────────────────
app.use('/auth', authRoutes);
app.use('/admin', require('./routes/adminRoutes'));

// ── Simulation routes ─────────────────────────────────────────────────────────
app.use('/demo', attackRoutes);

// ── Utility routes ────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() }));
app.get('/api/blocked-ips', (_, res) => {
  const { getBlockedList } = require('./middleware/ipBlocker');
  res.json(getBlockedList());
});
app.get('/api/metrics', (_, res) => res.json(metricsService.getSnapshot()));
app.get('/logs', (_, res) => {
  const Log = require('./models/Log');
  Log.find().sort({ timestamp: -1 }).limit(200)
    .then(docs => res.json(docs)).catch(() => res.json([]));
});

// ── SMART API ROUTER ──────────────────────────────────────────────────────────
app.use('/api/internal', internalProxy);    // → localhost:5000
app.use('/api/external', externalRoutes);   // → JSONPlaceholder / DummyJSON

// Legacy: keep /api/posts etc. working by redirecting (backward compat)
app.use('/api', (req, res) => res.redirect(`/api/external${req.path}`));

// ── 404 catch-all ────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` }));

// ── DATABASE + START ──────────────────────────────────────────────────────────
const startServer = async () => {
  try {
    const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/secureGateway';
    try {
      await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 2000 });
      console.log('✅ Persistent MongoDB connected!');
    } catch {
      console.log('⚠️  MongoDB not found — starting portable database…');
      const dbPath = path.join(__dirname, '../database');
      if (!fs.existsSync(dbPath)) fs.mkdirSync(dbPath);
      const mongod = await MongoMemoryServer.create({ 
        instance: { 
          dbPath, 
          storageEngine: 'wiredTiger',
          port: 27018 // Fixed port for consistency
        } 
      });
      const uri = mongod.getUri();
      await mongoose.connect(uri, { dbName: 'secureGateway' });
      console.log(`✅ Portable DB started! Data at: ${dbPath}`);
      console.log(`🔗 Connect via MongoDB Compass: ${uri}`);
    }

    const { seedDefaultUser } = require('./models/User');
    await seedDefaultUser();

    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      console.log(`
  ╔══════════════════════════════════════════════════════════╗
  ║  🛡️  Hybrid Multi-Source Secure API Gateway              ║
  ╠══════════════════════════════════════════════════════════╣
  ║  🌐 Gateway   : http://localhost:${PORT}                    ║
  ║  🔑 Login     : http://localhost:${PORT}/login               ║
  ║  📊 Dashboard : http://localhost:${PORT}/dashboard           ║
  ║  🧪 API Tester: http://localhost:${PORT}/api-tester          ║
  ║  ⚔️  Attack UI : http://localhost:${PORT}/attack             ║
  ╠══════════════════════════════════════════════════════════╣
  ║  INTERNAL API : /api/internal/* → localhost:5000         ║
  ║  EXTERNAL API : /api/external/* → JSONPlaceholder/Dummy  ║
  ╚══════════════════════════════════════════════════════════╝
      `);
      
      // Auto-start ML Prediction microservice
      const { spawn } = require('child_process');
      const mlScript = path.join(__dirname, '../ml/predict.py');
      const mlProc = spawn('python', ['-u', mlScript]);
      
      mlProc.stdout.on('data', d => console.log(`[ML-Service] ${d.toString().trim()}`));
      mlProc.stderr.on('data', d => console.error(`[ML-Service] ${d.toString().trim()}`));
      mlProc.on('error', err => console.error('[ML-Service] Failed to start Python server. Is python installed?', err.message));
      
      process.on('SIGINT', () => { mlProc.kill(); process.exit(); });
      process.on('SIGTERM', () => { mlProc.kill(); process.exit(); });
    });
  } catch (err) {
    console.error('Startup error:', err.message);
    process.exit(1);
  }
};

startServer();
