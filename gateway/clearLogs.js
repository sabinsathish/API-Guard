const mongoose = require('mongoose');
require('dotenv').config();

const clearLogs = async () => {
  // Use the fixed portable port or the ENV variable
  const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27018/secureGateway';
  
  console.log('🧹 Connecting to database to clear logs...');
  try {
    await mongoose.connect(MONGO_URI);
    const Log = require('./models/Log');
    
    const count = await Log.countDocuments();
    if (count === 0) {
      print('✨ Database is already clean.');
    } else {
      await Log.deleteMany({});
      console.log(`✅ Successfully deleted ${count} logs.`);
    }
  } catch (err) {
    console.error('❌ Error clearing logs:', err.message);
    console.log('Tip: Make sure your gateway server is running!');
  } finally {
    await mongoose.disconnect();
    process.exit();
  }
};

clearLogs();
