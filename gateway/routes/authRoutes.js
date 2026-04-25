const jwt = require('jsonwebtoken');
const express = require('express');
const router = express.Router();
const { User } = require('../models/User');
const ThreatEngine = require('../services/threatEngine');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secure-secret';

// ── POST /auth/login ──────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  const ip = req.clientIp || req.ip || '0.0.0.0';

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = await User.findOne({ username });
  if (!user || !(await user.verifyPassword(password))) {
    ThreatEngine.evaluateBrokenAuth(`ip:${ip}`, 'FAILED_LOGIN', `Bad credentials for user: ${username}`);
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // Update last login
  user.lastLogin = new Date();
  await user.save();

  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, expiresIn: 3600, username: user.username, role: user.role });
});

// ── POST /auth/register ───────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { username, password, role } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (await User.findOne({ username })) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  const user = await User.createUser(username, password, role || 'viewer');
  res.status(201).json({ message: `User "${username}" registered successfully`, role: user.role });
});

// ── GET /auth/users — list registered users (no passwords) ───────────────────
router.get('/users', async (req, res) => {
  const users = await User.find({}, 'username role createdAt lastLogin');
  res.json(users);
});

// ── DELETE /auth/users/:username ─────────────────────────────────────────────
router.delete('/users/:username', async (req, res) => {
  const result = await User.deleteOne({ username: req.params.username });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'User not found' });
  res.json({ message: `User "${req.params.username}" deleted` });
});

// ── Demo broken auth tokens (for attack simulation) ──────────────────────────
router.get('/expired-token', (_, res) => {
  const token = jwt.sign({ username: 'attacker' }, JWT_SECRET, { expiresIn: -1 });
  res.json({ token, note: 'This token is already expired. Using it will trigger BROKEN_AUTH.' });
});

router.get('/weak-token', (_, res) => {
  const token = `apikey${Math.floor(Math.random() * 100)}`;
  res.json({ token, note: 'Predictable/weak token. Gateway will reject as BROKEN_AUTH.' });
});

router.get('/forged-token', (_, res) => {
  const token = jwt.sign({ username: 'hacker', role: 'admin' }, 'wrong-secret', { expiresIn: '1h' });
  res.json({ token, note: 'Signed with wrong secret — gateway will reject as BROKEN_AUTH.' });
});

module.exports = router;
