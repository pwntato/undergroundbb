const pool = require('../db');

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

module.exports = { getUserByUuid, getUserGroups };
