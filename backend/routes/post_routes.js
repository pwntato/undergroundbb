const express = require("express");
const { createPost } = require("../services/post");
const { getUserByUuid } = require("../services/user");
const { getUserRoleInGroup } = require("../services/membership");
const { decrypt: decryptAes } = require("../cryptography/aes");
const { decrypt: decryptRsa } = require("../cryptography/rsa");
const { Buffer } = require("buffer");

const router = express.Router();

router.post("/create-post", async (req, res) => {
  try {
    const { title, body, groupId, parentPostId } = req.body;
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

    const { role, encrypted_group_key: encryptedGroupKey } = await getUserRoleInGroup(user.id, groupId);
    if (!role) {
      return res.status(403).json({ error: "User is not a member of the group" });
    }

    const decryptedGroupKey = decryptRsa(encryptedGroupKey, decryptedPrivateKey);

    const post = await createPost(title, body, user.id, groupId, decryptedGroupKey, parentPostId);
    res.status(201).json(post);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creating post" });
  }
});

module.exports = router;
