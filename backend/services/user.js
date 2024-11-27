const pool = require('../db');
const { createHash } = require('../cryptography/hash');
const { encrypt, decrypt } = require('../cryptography/aes');
const { generateKeyPair, verifyKeyPair } = require('../cryptography/rsa');

const getUserByUuid = async (uuid) => {
  const result = await pool.query('SELECT * FROM users WHERE uuid = $1', [uuid]);
  if (result.rows.length === 0) {
    return null;
  }
  return result.rows[0];
};

const getUserGroups = async (userUuid) => {
  const result = await pool.query(
    `SELECT g.* FROM groups g
     JOIN membership m ON g.id = m.group_id
     JOIN users u ON m.user_id = u.id
     WHERE u.uuid = $1`,
    [userUuid]
  );
  return result.rows.map(row => row.uuid);
};

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

  const updateUser = async (uuid, { email, bio, hidden }) => {
    await pool.query(
      'UPDATE users SET email = $1, bio = $2, hidden = $3 WHERE uuid = $4',
      [email, bio, hidden, uuid]
    );
  };

  async function changePassword(username, oldPassword, newPassword) {
    validatePassword(newPassword);

    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      throw new Error('User not found');
    }
  
    const user = result.rows[0];
  
    const oldHash = createHash(oldPassword, user.salt);
    const decryptedPrivateKey = decrypt(user.private_key, oldHash);
    const isValidKeyPair = verifyKeyPair(user.public_key, decryptedPrivateKey);
    if (!isValidKeyPair) {
      throw new Error('Invalid old password');
    }
  
    const { salt, hash: newHash } = createHash(newPassword);
    const encryptedPrivateKey = encrypt(decryptedPrivateKey, newHash);
  
    await pool.query(
      'UPDATE users SET salt = $1, private_key = $2 WHERE username = $3',
      [salt, encryptedPrivateKey, username]
    );
  
    return true;
  }
  
module.exports = { 
  getUserByUuid, 
  getUserGroups, 
  isUsernameAvailable, 
  validatePassword, 
  createUser, 
  updateUser, 
  changePassword
};
