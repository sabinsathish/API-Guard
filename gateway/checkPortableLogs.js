const mongoose = require('mongoose');
const Log = require('./models/Log');

const PORTABLE_URI = 'mongodb://127.0.0.1:27018/secureGateway';

async function checkPortableLogs() {
  try {
    await mongoose.connect(PORTABLE_URI, { serverSelectionTimeoutMS: 2000 });
    const count = await Log.countDocuments();
    console.log(`Total logs in PORTABLE (27018): ${count}`);
    const latest = await Log.find().sort({ timestamp: -1 }).limit(5);
    console.log('Latest 5 portable logs:', JSON.stringify(latest, null, 2));
    process.exit(0);
  } catch (err) {
    console.error('Portable DB (27018) not running or empty:', err.message);
    process.exit(1);
  }
}

checkPortableLogs();
