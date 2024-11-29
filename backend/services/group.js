const pool = require("../db");
const { randomKey } = require("../cryptography/aes");
const { encrypt } = require("../cryptography/rsa");
const { getUserByUuid } = require("./user");

const createGroup = async (userUuid, name, description) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const groupResult = await client.query(
      "INSERT INTO groups (name, description, hidden, trust_trace) VALUES ($1, $2, true, true) RETURNING id, uuid",
      [name, description]
    );
    const groupId = groupResult.rows[0].id;
    const groupUuid = groupResult.rows[0].uuid;

    const user = await getUserByUuid(userUuid);
    if (!user) {
      throw new Error("User not found");
    }

    const groupKey = randomKey();

    const encryptedGroupKey = encrypt(groupKey, user.public_key);

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
    "SELECT name, description, created_at FROM groups WHERE uuid = $1",
    [uuid]
  );
  if (result.rows.length === 0) {
    return null;
  }
  return result.rows[0];
};

const editGroup = async (uuid, name, description, hidden, trust_trace) => {
  const result = await pool.query(
    "UPDATE groups SET name = $1, description = $2, hidden = $3, trust_trace = $4 WHERE uuid = $5 RETURNING uuid",
    [name, description, hidden, trust_trace, uuid]
  );
  if (result.rows.length === 0) {
    throw new Error("Group not found");
  }
};

module.exports = { createGroup, getGroupByUuid, editGroup };
