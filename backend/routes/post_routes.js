const express = require("express");
const pool = require("../db");
const { Buffer } = require("buffer");
const {
  createPost,
  getPosts,
  getPostByUuid,
  deletePost,
} = require("../services/post");
const { getUserByUuid } = require("../services/user");
const { getUserRoleInGroup } = require("../services/membership");
const { decrypt: decryptAes } = require("../cryptography/aes");
const { decrypt: decryptRsa } = require("../cryptography/rsa");
const {
  getGroupByUuid,
  verifyUserMembershipAndDecryptGroupKey,
} = require("../services/group");

const router = express.Router();

router.post("/create-post", async (req, res) => {
  try {
    const { title, body, groupId: groupUuid, parentPostUuid } = req.body;
    const { userUuid, sessionPrivateKey: encryptedPrivateKey } = req.session;
    const tokenBase64 = req.cookies.token;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const user = await getUserByUuid(userUuid);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const token = Buffer.from(tokenBase64, "base64");
    const decryptedPrivateKey = decryptAes(encryptedPrivateKey, token);

    const { role, encrypted_group_key: encryptedGroupKey } =
      await getUserRoleInGroup(user.id, groupUuid);
    if (!role) {
      return res
        .status(403)
        .json({ error: "User is not a member of the group" });
    }

    const decryptedGroupKey = decryptRsa(
      encryptedGroupKey,
      decryptedPrivateKey
    );
    const decryptedGroupKeyHex = Buffer.from(decryptedGroupKey, "hex");

    const { id: groupId } = await getGroupByUuid(groupUuid);

    let parentPostId = null;
    if (parentPostUuid) {
      const parentPostResult = await pool.query(
        "SELECT id FROM posts WHERE uuid = $1",
        [parentPostUuid]
      );
      if (parentPostResult.rows.length > 0) {
        parentPostId = parentPostResult.rows[0].id;
      }
    }

    const post = await createPost(
      title,
      body,
      user.id,
      groupId,
      decryptedGroupKeyHex,
      parentPostId
    );
    res.status(201).json(post);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creating post" });
  }
});

router.get("/posts", async (req, res) => {
  const limit = 10;

  try {
    const { groupUuid, parentUuid = null, offset = 0 } = req.query;
    const { userUuid, sessionPrivateKey: encryptedPrivateKey } = req.session;
    const tokenBase64 = req.cookies.token;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const user = await getUserByUuid(userUuid);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const { decryptedGroupKeyHex } =
      await verifyUserMembershipAndDecryptGroupKey(
        user,
        groupUuid,
        encryptedPrivateKey,
        tokenBase64
      );

    const posts = await getPosts(
      groupUuid,
      decryptedGroupKeyHex,
      offset,
      limit,
      parentUuid
    );

    // Check if there are more posts after the current page
    const hasMore = posts.length === limit;

    res.json({
      posts,
      pagination: {
        current: offset,
        previous: offset - limit >= 0 ? offset - limit : null,
        next: hasMore ? offset + limit : null,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching posts" });
  }
});

router.get("/post/:uuid", async (req, res) => {
  try {
    const { uuid: postUuid } = req.params;
    const { userUuid, sessionPrivateKey: encryptedPrivateKey } = req.session;
    const tokenBase64 = req.cookies.token;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const user = await getUserByUuid(userUuid);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const post = await getPostByUuid(postUuid);
    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }

    const { decryptedGroupKeyHex } =
      await verifyUserMembershipAndDecryptGroupKey(
        user,
        post.group.uuid,
        encryptedPrivateKey,
        tokenBase64
      );

    const decryptedPost = {
      ...post,
      title: decryptAes(post.title, decryptedGroupKeyHex),
      body: decryptAes(post.body, decryptedGroupKeyHex),
    };

    res.json(decryptedPost);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching post" });
  }
});

router.delete("/post/:postUuid", async (req, res) => {
  try {
    const { postUuid } = req.params;
    const { userUuid, sessionPrivateKey: encryptedPrivateKey } = req.session;
    const tokenBase64 = req.cookies.token;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const user = await getUserByUuid(userUuid);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get post's group to get the group key
    const postResult = await pool.query(
      `SELECT g.uuid as group_uuid
       FROM posts p 
       JOIN groups g ON p.group_id = g.id
       WHERE p.uuid = $1`,
      [postUuid]
    );

    if (postResult.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const { decryptedGroupKeyHex } = await verifyUserMembershipAndDecryptGroupKey(
      user,
      postResult.rows[0].group_uuid,
      encryptedPrivateKey,
      tokenBase64
    );

    await deletePost(postUuid, user.id, decryptedGroupKeyHex);
    res.status(200).json({ message: "Post deleted successfully" });
  } catch (error) {
    if (error.message === "Post not found") {
      res.status(404).json({ error: error.message });
    } else if (error.message === "Unauthorized to delete this post") {
      res.status(403).json({ error: error.message });
    } else {
      console.error(error);
      res.status(500).json({ error: "Error deleting post" });
    }
  }
});

module.exports = router;
