const crypto = require('crypto');

// Generate RSA key pair
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 3072,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  return { publicKey, privateKey };
}

// Encrypt a message using RSA public key
function encrypt(message, publicKey) {
  const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(message));
  return encrypted.toString('base64');
}

// Decrypt a message using RSA private key
function decrypt(encryptedMessage, privateKey) {
  const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encryptedMessage, 'base64'));
  return decrypted.toString('utf8');
}

module.exports = { generateKeyPair, encrypt, decrypt };
