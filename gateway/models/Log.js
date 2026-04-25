const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  ip:          { type: String, required: true },
  endpoint:    { type: String, required: true },
  method:      { type: String, required: true },
  status:      { type: Number, required: true },
  responseMs:  { type: Number, default: 0 },
  threatType:  {
    type: String,
    enum: ['NONE','RATE_LIMIT','RATE_ABUSE','BRUTE_FORCE','DOS_ATTACK',
           'IP_BLOCKED','BLOCKED_IP_ACCESS','BROKEN_AUTH'],
    default: 'NONE'
  },
  userAgent:   { type: String, default: '' },
  provider:    { type: String, default: 'system' },
  sourceType:  { type: String, default: 'static_route' },
  targetHost:  { type: String, default: '' },
  timestamp:   { type: Date, default: Date.now }
});

// Removed TTL index to allow for long-term ML training data
// logSchema.index({ timestamp: 1 }, { expireAfterSeconds: 3600 });

module.exports = mongoose.model('Log', logSchema);
