const pool = require('../db');
const { createHash } = require('../cryptography/hash');
const { decrypt } = require('../cryptography/aes');
const { verifyKeyPair } = require('../cryptography/rsa');

async function login(username, password, session) {
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (result.rows.length === 0) {
    throw new Error('Invalid username or password');
  }

  const user = result.rows[0];

  const hash = createHash(password, user.salt);
  const decryptedPrivateKey = decrypt(user.private_key, hash);

  const isValidKeyPair = verifyKeyPair(user.public_key, decryptedPrivateKey);
  if (!isValidKeyPair) {
    throw new Error('Invalid username or password');
  }

  session.privateKey = decryptedPrivateKey;
  session.username = username;
  session.userUuid = user.uuid;

  return true;
}

function isLoggedIn(session) {
  return session.privateKey !== undefined && session.privateKey !== null;
}

module.exports = { login, isLoggedIn };
