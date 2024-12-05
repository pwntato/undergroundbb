const express = require("express");
const { Buffer } = require("buffer");
const { createPost, getPosts } = require("../services/post");
const { getUserByUuid } = require("../services/user");
const { getUserRoleInGroup } = require("../services/membership");
const { decrypt: decryptAes } = require("../cryptography/aes");
const { decrypt: decryptRsa } = require("../cryptography/rsa");
const { getGroupByUuid } = require("../services/group");

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
  try {
    const { groupUuid, parentId = null, limit = 10, offset = 0 } = req.query;
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

    const { role, encrypted_group_key: encryptedGroupKey } = await getUserRoleInGroup(user.id, groupUuid);
    if (!role) {
      return res.status(403).json({ error: "User is not a member of the group" });
    }

    const decryptedGroupKey = decryptRsa(encryptedGroupKey, decryptedPrivateKey);
    const decryptedGroupKeyHex = Buffer.from(decryptedGroupKey, "hex");

    const posts = await getPosts(groupUuid, decryptedGroupKeyHex, parseInt(offset), parseInt(limit), parentId);

    const nextOffset = parseInt(offset) + parseInt(limit);
    const prevOffset = parseInt(offset) - parseInt(limit);

    const nextPageToken = posts.length === parseInt(limit) ? Buffer.from(`${groupUuid}:${nextOffset}:${limit}:${parentId}`).toString('base64') : null;
    const prevPageToken = parseInt(offset) > 0 ? Buffer.from(`${groupUuid}:${prevOffset}:${limit}:${parentId}`).toString('base64') : null;
    const currentPageToken = Buffer.from(`${groupUuid}:${offset}:${limit}:${parentId}`).toString('base64');

    res.json({
      posts,
      tokens: {
        current: currentPageToken,
        previous: prevPageToken,
        next: nextPageToken
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching posts" });
  }
});

module.exports = router;