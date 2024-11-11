const crypto = require('crypto');

function createHash(input) {
  return crypto.createHash('sha3-256').update(input).digest('hex');
}

module.exports = { createHash };
