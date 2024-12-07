const express = require("express");
const { Buffer } = require("buffer");
const { createPost, getPosts, getPostByUuid } = require("../services/post");
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
    const { title, body, groupId: groupUuid, parentPostId } = req.body;
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
    const { groupUuid, parentId = null, offset = 0 } = req.query;
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
      parentId
    );

    res.json({
      posts,
      pagination: {
        current: offset,
        previous: offset - limit,
        next: offset + limit,
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

    console.log("post", post);
    const { role, decryptedGroupKeyHex } =
      await verifyUserMembershipAndDecryptGroupKey(
        user,
        post.group.uuid,
        encryptedPrivateKey,
        tokenBase64
      );
    if (!role || role === "banned") {
      return res
        .status(403)
        .json({ error: "User is not a member of the group" });
    }

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

module.exports = router;
