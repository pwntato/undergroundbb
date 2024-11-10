const CryptoJS = require('crypto-js');

function encrypt(message, secretKey) {
  if (secretKey.length !== 32) {
    throw new Error('Secret key must be 32 bytes long');
  }
  const ciphertext = CryptoJS.AES.encrypt(message, secretKey).toString();
  return ciphertext;
}

function decrypt(ciphertext, secretKey) {
  if (secretKey.length !== 32) {
    throw new Error('Secret key must be 32 bytes long');
  }
  const bytes = CryptoJS.AES.decrypt(ciphertext, secretKey);
  const originalText = bytes.toString(CryptoJS.enc.Utf8);
  return originalText;
}

module.exports = { encrypt, decrypt };
