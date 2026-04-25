const mongoose = require('mongoose');
const path = require('path');

// Try both possible ports (Standard 27017 and Portable 27018)
const uris = [
  'mongodb://127.0.0.1:27017/secureGateway',
  'mongodb://127.0.0.1:27018/secureGateway'
];

async function unblockAll() {
  console.log('🛡️  Running Emergency Unblock…');
  
  for (const uri of uris) {
    try {
      const conn = await mongoose.createConnection(uri, { serverSelectionTimeoutMS: 2000 }).asPromise();
      const BlockedIP = conn.model('BlockedIP', new mongoose.Schema({ ip: String }));
      
      const result = await BlockedIP.deleteMany({});
      console.log(`✅ Success on ${uri}: Removed ${result.deletedCount} blocked IPs.`);
      await conn.close();
    } catch (err) {
      console.log(`ℹ️  Skipping ${uri}: ${err.message}`);
    }
  }
  console.log('\n✨ All blocks cleared! You can now access the login page again.');
  process.exit(0);
}

unblockAll();
