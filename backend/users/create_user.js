const pool = require('../db');
const { createHash } = require('../cryptography/hash');
const { encrypt } = require('../cryptography/aes');
const { generateKeyPair } = require('../cryptography/rsa');

async function isUsernameAvailable(username) {
  const result = await pool.query('SELECT COUNT(*) FROM users WHERE username = $1', [username]);
  return result.rows[0].count === '0';
}

function validatePassword(password) {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  if (
    password.length < minLength ||
    !hasUpperCase ||
    !hasLowerCase ||
    !hasNumber
  ) {
    throw new Error('Password must be at least 8 characters long and include at least an uppercase letter, a lowercase letter, and a number');
  }
}

async function createUser(username, password) {
  if (!(await isUsernameAvailable(username))) {
    throw new Error('Username is already taken');
  }

  validatePassword(password);

  const { salt, hash } = createHash(password);
  const { publicKey, privateKey } = generateKeyPair();
  const encryptedPrivateKey = encrypt(privateKey, hash);

  await pool.query(
    'INSERT INTO users (username, email, public_key, private_key, salt) VALUES ($1, $2, $3, $4, $5)',
    [username, null, publicKey, encryptedPrivateKey, salt]
  );
}

module.exports = { isUsernameAvailable, validatePassword, createUser };
