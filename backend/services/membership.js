const pool = require("../db");

const getUserRoleInGroup = async (userId, groupUuid) => {
  const result = await pool.query(
    `SELECT role, encrypted_group_key FROM membership m
     JOIN groups g ON m.group_id = g.id
     WHERE m.user_id = $1 AND g.uuid = $2`,
    [userId, groupUuid]
  );

  if (result.rows.length === 0) {
    return null;
  }

  return result.rows[0];
};

const updateUserRoleInGroup = async (currentUserUuid, targetUserUuid, groupUuid, newRole) => {
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
    if (currentUserRoleResult.rows.length === 0 || currentUserRoleResult.rows[0].role !== 'admin') {
      throw new Error("Current user is not an admin of the group");
    }

    const targetUserResult = await client.query(
      "SELECT id FROM users WHERE uuid = $1",
      [targetUserUuid]
    );
    if (targetUserResult.rows.length === 0) {
      throw new Error("Target user not found");
    }
    const targetUserId = targetUserResult.rows[0].id;

    await client.query(
      "UPDATE membership SET role = $1 WHERE user_id = $2 AND group_id = $3",
      [newRole, targetUserId, groupId]
    );

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};

module.exports = { getUserRoleInGroup, updateUserRoleInGroup };
