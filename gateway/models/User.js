const mongoose = require('mongoose');
const crypto   = require('crypto'); // Built-in Node.js — no install needed

const userSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 30 },
  hash:      { type: String, required: true },  // PBKDF2 hash
  salt:      { type: String, required: true },  // random salt
  role:      { type: String, enum: ['admin', 'analyst', 'viewer'], default: 'viewer' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

// Hash a plain-text password with a random salt
function hashPassword(plain, salt) {
  if (!salt) salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(plain, salt, 10000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

// Verify a plain-text password against stored hash/salt
userSchema.methods.verifyPassword = function (plain) {
  const { hash } = hashPassword(plain, this.salt);
  return hash === this.hash;
};

// Static helper — convenience for creating users
userSchema.statics.createUser = async function (username, password, role = 'viewer') {
  const { hash, salt } = hashPassword(password);
  return this.create({ username, hash, salt, role });
};

const User = mongoose.model('User', userSchema);

// Seed default admin if no users exist
async function seedDefaultUser() {
  const count = await User.countDocuments();
  if (count === 0) {
    await User.createUser('admin', 'Admin@123', 'admin');
    console.log('✅ Default admin user seeded. Login: admin / Admin@123');
  }
}

module.exports = { User, seedDefaultUser };
