const mongoose = require('mongoose');
const Log = require('./models/Log');

const MONGO_URI = 'mongodb://127.0.0.1:27017/secureGateway';

async function checkLogs() {
  try {
    await mongoose.connect(MONGO_URI);
    const count = await Log.countDocuments();
    console.log(`Total logs in 27017: ${count}`);
    const latest = await Log.find().sort({ timestamp: -1 }).limit(5);
    console.log('Latest 5 logs:', JSON.stringify(latest, null, 2));
    process.exit(0);
  } catch (err) {
    console.error('Error connecting to 27017:', err.message);
    process.exit(1);
  }
}

checkLogs();
