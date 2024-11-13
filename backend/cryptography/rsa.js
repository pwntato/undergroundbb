const crypto = require('crypto');

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

function encrypt(message, publicKey) {
  const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(message));
  return encrypted.toString('base64');
}

function decrypt(encryptedMessage, privateKey) {
  const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encryptedMessage, 'base64'));
  return decrypted.toString('utf8');
}

function verifyKeyPair(publicKey, privateKey) {
  const testMessage = 'I am the very model of a modern Major-General';
  try {
    const encryptedMessage = encrypt(testMessage, publicKey);
    const decryptedMessage = decrypt(encryptedMessage, privateKey);
    return decryptedMessage === testMessage;
  } catch (error) {
    return false;
  }
}

module.exports = { generateKeyPair, encrypt, decrypt, verifyKeyPair };
