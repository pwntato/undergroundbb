const crypto = require('crypto');

function createHash(input) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHash('sha3-256').update(salt + input).digest('hex');
  return { salt, hash };
}

function verifyHash(input, salt, hash) {
  const inputHash = crypto.createHash('sha3-256').update(salt + input).digest('hex');
  return inputHash === hash;
}

module.exports = { createHash, verifyHash };
