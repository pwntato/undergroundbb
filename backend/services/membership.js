const pool = require("../db");

const getUserRoleInGroup = async (userId, groupUuid) => {
  const result = await pool.query(
    `SELECT role FROM membership m
     JOIN groups g ON m.group_id = g.id
     WHERE m.user_id = $1 AND g.uuid = $2`,
    [userId, groupUuid]
  );

  if (result.rows.length === 0) {
    return null;
  }

  return result.rows[0].role;
};

module.exports = { getUserRoleInGroup };
