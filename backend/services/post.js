const pool = require("../db");
const { encrypt, decrypt } = require("../cryptography/aes");

const createPost = async (
  title,
  body,
  userId,
  groupId,
  decryptedGroupKey,
  parentPostId = null
) => {
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

const getPosts = async (
  groupUuid,
  decryptedGroupKey,
  offset = 0,
  limit = 50,
  parentUuid = null
) => {
  const client = await pool.connect();
  try {
    const queryParams = [groupUuid, limit, parseInt(offset)];
    let query = `
      SELECT 
        p.id, p.uuid, p.title, p.body, p.created_at, 
        u.username, u.uuid as user_uuid, 
        g.name as group_name, g.uuid as group_uuid
      FROM posts p
      JOIN users u ON p.creator_id = u.id
      LEFT JOIN groups g ON p.group_id = g.id
      WHERE g.uuid = $1 AND p.parent_post_id ${
        !parentUuid || parentUuid.length < 36
          ? "IS NULL"
          : "= (SELECT id FROM posts WHERE uuid = $4)"
      }
    `;

    if (parentUuid && parentUuid.length >= 36) {
      queryParams.push(parentUuid);
    }

    query += ` ORDER BY p.created_at DESC LIMIT $2 OFFSET $3`;

    const result = await client.query(query, queryParams);

    const posts = result.rows.map((post) => {
      const decryptedTitle = decrypt(post.title, decryptedGroupKey);
      const decryptedBody = decrypt(post.body, decryptedGroupKey);
      return {
        id: post.id,
        uuid: post.uuid,
        title: decryptedTitle,
        body: decryptedBody,
        created_at: post.created_at,
        author: {
          username: post.username,
          uuid: post.user_uuid,
        },
        group: {
          name: post.group_name,
          uuid: post.group_uuid,
        },
      };
    });

    return posts;
  } catch (error) {
    throw error;
  } finally {
    client.release();
  }
};

const getPostByUuid = async (postUuid) => {
  const client = await pool.connect();
  try {
    const query = `
      SELECT 
        p.id, p.uuid, p.title, p.body, p.created_at, 
        u.username, u.uuid as user_uuid, 
        g.name as group_name, g.uuid as group_uuid
      FROM posts p
      JOIN users u ON p.creator_id = u.id
      LEFT JOIN groups g ON p.group_id = g.id
      WHERE p.uuid = $1
    `;
    const result = await client.query(query, [postUuid]);

    if (result.rows.length === 0) {
      throw new Error("Post not found");
    }
    const post = result.rows[0];

    return {
      id: post.id,
      uuid: post.uuid,
      title: post.title,
      body: post.body,
      created_at: post.created_at,
      author: {
        username: post.username,
        uuid: post.user_uuid,
      },
      group: {
        name: post.group_name,
        uuid: post.group_uuid,
      },
    };
  } catch (error) {
    throw error;
  } finally {
    client.release();
  }
};

module.exports = { createPost, getPosts, getPostByUuid };
