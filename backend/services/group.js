const pool = require("../db");
const { randomKey, decrypt: decryptAes } = require("../cryptography/aes");
const { encrypt, decrypt: decryptRsa } = require("../cryptography/rsa");
const { getUserByUuidUnsafe } = require("./user");
const { getUserRoleInGroup } = require("./membership");

const createGroup = async (userUuid, name, description) => {
  const client = await pool.connect();
  try {
    if (await getGroupByName(name)) {
      throw new Error("Group with that name already exists");
    }

    await client.query("BEGIN");

    const groupResult = await client.query(
      "INSERT INTO groups (name, description, hidden, trust_trace) VALUES ($1, $2, true, true) RETURNING id, uuid",
      [name, description]
    );
    const groupId = groupResult.rows[0].id;
    const groupUuid = groupResult.rows[0].uuid;

    const user = await getUserByUuidUnsafe(userUuid);
    if (!user) {
      throw new Error("User not found");
    }

    const groupKey = randomKey();
    const groupKeyHex = groupKey.toString("hex");

    const encryptedGroupKey = encrypt(groupKeyHex, user.public_key);

    await client.query(
      "INSERT INTO membership (role, encrypted_group_key, invited_by, user_id, group_id) VALUES ($1, $2, $3, $4, $5)",
      ["admin", encryptedGroupKey, null, user.id, groupId]
    );

    await client.query("COMMIT");
    return groupUuid;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};

const getGroupByUuid = async (uuid) => {
  const result = await pool.query(
    "SELECT id, name, description, created_at, hidden, trust_trace FROM groups WHERE uuid = $1",
    [uuid]
  );
  if (result.rows.length === 0) {
    return null;
  }
  return result.rows[0];
};

const getGroupByName = async (name) => {
  const result = await pool.query(
    "SELECT id, uuid, name, description, created_at, hidden, trust_trace FROM groups WHERE LOWER(name) = LOWER($1)",
    [name]
  );
  if (result.rows.length === 0) {
    return null;
  }
  return result.rows[0];
};

const editGroup = async (uuid, name, description, hidden, trust_trace) => {
  const fields = [];
  const values = [uuid];

  if (name != null) {
    if (getGroupByName(name)) {
      throw new Error("Group with that name already exists");
    }
    
    fields.push("name = $" + (fields.length + 2));
    values.push(name);
  }
  if (description != null) {
    fields.push("description = $" + (fields.length + 2));
    values.push(description);
  }
  if (hidden != null) {
    fields.push("hidden = $" + (fields.length + 2));
    values.push(hidden);
  }
  if (trust_trace != null) {
    fields.push("trust_trace = $" + (fields.length + 2));
    values.push(trust_trace);
  }

  if (fields.length === 0) {
    throw new Error("No fields to update");
  }

  const query = `UPDATE groups SET ${fields.join(
    ", "
  )} WHERE uuid = $1 RETURNING uuid`;
  const result = await pool.query(query, values);

  if (result.rows.length === 0) {
    throw new Error("Group not found");
  }
};

const inviteUserToGroup = async (
  groupUuid,
  userUuid,
  decryptedGroupKey,
  inviteRole
) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const groupResult = await client.query(
      "SELECT id FROM groups WHERE uuid = $1",
      [groupUuid]
    );
    if (groupResult.rows.length === 0) {
      throw new Error("Group not found");
    }
    const groupId = groupResult.rows[0].id;

    const userResult = await client.query(
      "SELECT id, public_key FROM users WHERE uuid = $1",
      [userUuid]
    );
    if (userResult.rows.length === 0) {
      throw new Error("User not found");
    }
    const user = userResult.rows[0];

    const encryptedGroupKey = encrypt(decryptedGroupKey, user.public_key);

    await client.query(
      "INSERT INTO membership (role, encrypted_group_key, invited_by, user_id, group_id) VALUES ($1, $2, $3, $4, $5)",
      [inviteRole, encryptedGroupKey, null, user.id, groupId]
    );

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};

const getUsersInGroup = async (groupUuid, currentUserUuid) => {
  const client = await pool.connect();
  try {
    const groupResult = await client.query(
      "SELECT id FROM groups WHERE uuid = $1",
      [groupUuid]
    );
    if (groupResult.rows.length === 0) {
      throw new Error("Group not found");
    }
    const groupId = groupResult.rows[0].id;

    const currentUserResult = await client.query(
      "SELECT id FROM users WHERE uuid = $1",
      [currentUserUuid]
    );
    if (currentUserResult.rows.length === 0) {
      throw new Error("Current user not found");
    }
    const currentUserId = currentUserResult.rows[0].id;

    const currentUserRoleResult = await client.query(
      "SELECT role FROM membership WHERE user_id = $1 AND group_id = $2",
      [currentUserId, groupId]
    );
    if (
      currentUserRoleResult.rows.length === 0 ||
      currentUserRoleResult.rows[0].role !== "admin"
    ) {
      throw new Error("Current user is not an admin of the group");
    }

    const usersResult = await client.query(
      `SELECT u.uuid, u.username, m.role FROM users u
       JOIN membership m ON u.id = m.user_id
       WHERE m.group_id = $1`,
      [groupId]
    );

    return usersResult.rows;
  } finally {
    client.release();
  }
};

const verifyUserMembershipAndDecryptGroupKey = async (
  user,
  groupUuid,
  encryptedPrivateKey,
  tokenBase64
) => {
  const token = Buffer.from(tokenBase64, "base64");
  const decryptedPrivateKey = decryptAes(encryptedPrivateKey, token);

  const { role, encrypted_group_key: encryptedGroupKey } =
    await getUserRoleInGroup(user.id, groupUuid);
  if (!role || role === "banned") {
    throw new Error("User is not a member of the group");
  }

  const decryptedGroupKey = decryptRsa(encryptedGroupKey, decryptedPrivateKey);
  const decryptedGroupKeyHex = Buffer.from(decryptedGroupKey, "hex");

  return { role, decryptedGroupKeyHex };
};

const getPostCountSinceLastLogin = async (groupUuid, userUuid) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      `SELECT COUNT(*) FROM posts p
       JOIN groups g ON p.group_id = g.id
       JOIN users u ON p.creator_id = u.id
       WHERE g.uuid = $1 AND u.uuid = $2 AND p.created_at > u.last_login AND p.parent_post_id IS NULL`,
      [groupUuid, userUuid]
    );

    return parseInt(result.rows[0].count, 10);
  } catch (error) {
    throw error;
  } finally {
    client.release();
  }
};

const getUserGroups = async (userUuid) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      `SELECT g.uuid, g.name 
       FROM groups g
       JOIN membership m ON g.id = m.group_id
       JOIN users u ON m.user_id = u.id
       WHERE u.uuid = $1`,
      [userUuid]
    );

    return result.rows;
  } catch (error) {
    throw error;
  } finally {
    client.release();
  }
};

module.exports = {
  createGroup,
  getGroupByUuid,
  getGroupByName,
  editGroup,
  inviteUserToGroup,
  getUsersInGroup,
  verifyUserMembershipAndDecryptGroupKey,
  getPostCountSinceLastLogin,
  getUserGroups,
};
