const pool = require('../db');
const { encrypt } = require('../cryptography/aes');

const createPost = async (title, body, userId, groupId, decryptedGroupKey, parentPostId = null) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const encryptedTitle = encrypt(title, decryptedGroupKey);
    const encryptedBody = encrypt(body, decryptedGroupKey);

    const result = await client.query(
      `INSERT INTO posts (title, body, creator_id, group_id, parent_post_id) 
       VALUES ($1, $2, $3, $4, $5) RETURNING id, title, body, creator_id, group_id, parent_post_id, created_at, last_edited, pinned`,
      [encryptedTitle, encryptedBody, userId, groupId, parentPostId]
    );

    await client.query("COMMIT");
    return result.rows[0];
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};

module.exports = { createPost };
