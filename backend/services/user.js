const pool = require("../db");
const { createHash } = require("../cryptography/hash");
const { encrypt, decrypt } = require("../cryptography/aes");
const { generateKeyPair, verifyKeyPair } = require("../cryptography/rsa");

const getUserByUuidUnsafe = async (uuid) => {
  const result = await pool.query("SELECT * FROM users WHERE uuid = $1", [
    uuid,
  ]);
  if (result.rows.length === 0) {
    return null;
  }
  return result.rows[0];
};

const getUserByUuid = async (uuid) => {
  const user = await getUserByUuidUnsafe(uuid);
  if (!user) {
    return null;
  }
  if (user.hidden) {
    delete user.bio;
  }
  delete user.hidden;
  delete user.salt;
  delete user.private_key;
  delete user.public_key;
  delete user.email;
  return user;
};

const getUserByUsername = async (username) => {
  const result = await pool.query(
    "SELECT username, id, uuid, bio, hidden, created_at FROM users WHERE LOWER(username) = LOWER($1)",
    [username]
  );
  if (result.rows.length === 0) {
    return null;
  }
  const user = result.rows[0];
  if (user.hidden) {
    delete user.bio;
  }
  delete user.hidden;
  delete user.salt;
  delete user.private_key;
  delete user.public_key;
  delete user.email;
  return user;
};

const getUserGroups = async (userUuid) => {
  const result = await pool.query(
    `SELECT g.uuid, g.name FROM groups g
     JOIN membership m ON g.id = m.group_id
     JOIN users u ON m.user_id = u.id
     WHERE u.uuid = $1`,
    [userUuid]
  );
  return result.rows;
};

async function isUsernameAvailable(username) {
  const result = await pool.query(
    "SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER($1)",
    [username]
  );
  return result.rows[0].count === "0";
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
    throw new Error(
      "Password must be at least 8 characters long and include at least an uppercase letter, a lowercase letter, and a number"
    );
  }
}

async function createUser(username, password) {
  if (!(await isUsernameAvailable(username))) {
    throw new Error("Username is already taken");
  }

  validatePassword(password);

  const { salt, hash } = createHash(password);
  const { publicKey, privateKey } = generateKeyPair();
  const encryptedPrivateKey = encrypt(privateKey, hash);

  await pool.query(
    "INSERT INTO users (username, email, public_key, private_key, salt, hidden) VALUES ($1, $2, $3, $4, $5, $6)",
    [username, null, publicKey, encryptedPrivateKey, salt, false]
  );
}

const updateUser = async (uuid, { email, bio, hidden }) => {
  await pool.query(
    "UPDATE users SET email = $1, bio = $2, hidden = $3 WHERE uuid = $4",
    [null, bio, false, uuid]
  );
};

async function changePassword(username, oldPassword, newPassword) {
  validatePassword(newPassword);

  const result = await pool.query("SELECT * FROM users WHERE LOWER(username) = LOWER($1)", [
    username,
  ]);
  if (result.rows.length === 0) {
    throw new Error("User not found");
  }

  const user = result.rows[0];

  const oldHash = createHash(oldPassword, user.salt);
  const decryptedPrivateKey = decrypt(user.private_key, oldHash);
  const isValidKeyPair = verifyKeyPair(user.public_key, decryptedPrivateKey);
  if (!isValidKeyPair) {
    throw new Error("Invalid old password");
  }

  const { salt, hash: newHash } = createHash(newPassword);
  const encryptedPrivateKey = encrypt(decryptedPrivateKey, newHash);

  await pool.query(
    "UPDATE users SET salt = $1, private_key = $2 WHERE username = $3",
    [salt, encryptedPrivateKey, username]
  );

  return true;
}

module.exports = {
  getUserByUuidUnsafe,
  getUserByUuid,
  getUserByUsername,
  getUserGroups,
  isUsernameAvailable,
  validatePassword,
  createUser,
  updateUser,
  changePassword,
};
