const pool = require('../db');
const crypto = require('crypto');
const { createHash } = require('../cryptography/hash');
const { decrypt, encrypt } = require('../cryptography/aes');
const { verifyKeyPair } = require('../cryptography/rsa');

async function login(username, password, session, res) {
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

  const token = crypto.randomBytes(32);
  sessionPrivateKey = encrypt(decryptedPrivateKey, token);

  res.cookie('token', token.toString('base64'), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 30 * 60 * 1000 // 30 minutes
  });

  session.sessionPrivateKey = sessionPrivateKey;
  session.username = username;
  session.userUuid = user.uuid;

  return true;
}

function isLoggedIn(session) {
  return session.privateKey !== undefined && session.privateKey !== null;
}

function logout(session, res) {
  res.clearCookie('token');
  session.destroy((err) => {
    if (err) {
      console.error('Failed to log out:', err);
      if (!res.headersSent) {
        return res.status(500).json({ error: 'Failed to log out' });
      }
    }
    if (!res.headersSent) {
      res.json({ message: 'Logout successful' });
    }
  });
}

module.exports = { login, isLoggedIn, logout };
