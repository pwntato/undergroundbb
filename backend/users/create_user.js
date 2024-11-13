const pool = require('../db');
const { createHash } = require('../cryptography/hash');
const { encrypt } = require('../cryptography/aes');
const { generateKeyPair } = require('../cryptography/rsa');

async function isUsernameAvailable(username) {
  const result = await pool.query('SELECT COUNT(*) FROM users WHERE username = $1', [username]);
  return result.rows[0].count === '0';
}

async function createUser(username, password) {
  if (!(await isUsernameAvailable(username))) {
    throw new Error('Username is already taken');
  }

  const { salt, hash } = createHash(password);
  const { publicKey, privateKey } = generateKeyPair();
  const encryptedPrivateKey = encrypt(privateKey, hash);

  await pool.query(
    'INSERT INTO users (username, email, public_key, private_key, salt) VALUES ($1, $2, $3, $4, $5)',
    [username, '', publicKey, encryptedPrivateKey, salt]
  );
}

module.exports = { isUsernameAvailable, createUser };
