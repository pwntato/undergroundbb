const pool = require('../db');
const { verifyHash } = require('../cryptography/hash');
const { decrypt } = require('../cryptography/aes');
const { verifyKeyPair } = require('../cryptography/rsa');

async function login(username, password, session) {
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (result.rows.length === 0) {
    throw new Error('Invalid username or password');
  }

  const user = result.rows[0];

  const isValidPassword = verifyHash(password, user.salt, user.hash);
  if (!isValidPassword) {
    throw new Error('Invalid username or password');
  }

  const decryptedPrivateKey = decrypt(user.private_key, user.hash);

  const isValidKeyPair = verifyKeyPair(user.public_key, decryptedPrivateKey);
  if (!isValidKeyPair) {
    throw new Error('Invalid username or password');
  }

  session.privateKey = decryptedPrivateKey;

  return true;
}

module.exports = { login };
