const mongoose = require('mongoose');
const Log = require('./models/Log');

const MONGO_URI = 'mongodb://127.0.0.1:27018/secureGateway';

async function checkLogs() {
  try {
    await mongoose.connect(MONGO_URI);
    const count = await Log.countDocuments();
    console.log(`Total logs in PORTABLE DB: ${count}`);
    const latest = await Log.find().sort({ timestamp: -1 }).limit(10);
    latest.forEach(l => {
      console.log(`[${l.timestamp.toISOString()}] ${l.method} ${l.endpoint} -> ${l.provider} (${l.sourceType})`);
    });
    process.exit(0);
  } catch (err) {
    console.error('Error connecting to 27018:', err.message);
    process.exit(1);
  }
}

checkLogs();
