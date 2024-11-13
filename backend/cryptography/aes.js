const crypto = require('crypto');

const algorithm = 'aes-256-cbc';
const ivLength = 16; // AES block size is 16 bytes

function encrypt(message, secretKey) {
  if (secretKey.length !== 32) {
    throw new Error('Secret key must be 32 bytes long');
  }

  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(ciphertext, secretKey) {
  if (secretKey.length !== 32) {
    throw new Error('Secret key must be 32 bytes long');
  }

  const parts = ciphertext.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey), iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encrypt, decrypt };