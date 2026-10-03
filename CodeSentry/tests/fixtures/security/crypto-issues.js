// Insecure cryptographic practices
const crypto = require('crypto');

// Weak: MD5 for password hashing
function hashPasswordWeak(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Weak: No salt for password hashing
function hashPasswordNoSalt(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Weak: Hardcoded encryption key
const ENCRYPTION_KEY = 'YOUR_ENCRYPTION_KEY_HERE';

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Weak: Insecure random number generation
function generateToken() {
  return Math.random().toString(36).substring(2); // Predictable
}

// Weak: ECB mode for encryption
function encryptECB(text) {
  const cipher = crypto.createCipheriv('aes-256-ecb', ENCRYPTION_KEY, null);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted.toString('hex');
}

// Vulnerable: Timing attack on comparison
function verifyToken(input, secret) {
  return input === secret; // Not constant-time
}

// Vulnerable: Weak key derivation
function deriveKey(password) {
  return crypto.createHash('sha256').update(password).digest('hex'); // No iterations, no salt
}

module.exports = {
  hashPasswordWeak, hashPasswordNoSalt, encrypt, generateToken,
  encryptECB, verifyToken, deriveKey
};
