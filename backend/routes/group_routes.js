const express = require("express");
const {
  createGroup,
  getGroupByUuid,
  editGroup,
  inviteUserToGroup,
  getUsersInGroup,
  getUserGroups,
  getPostCountSinceLastLogin,
} = require("../services/group");
const { getUserByUuid, getUserByUuidUnsafe } = require("../services/user");
const {
  getUserRoleInGroup,
  updateUserRoleInGroup,
} = require("../services/membership");
const { decrypt: decryptAes } = require("../cryptography/aes");
const { decrypt: decryptRsa } = require("../cryptography/rsa");
const { Buffer } = require("buffer");

const router = express.Router();

router.post("/create-group", async (req, res) => {
  try {
    const { name, description } = req.body;
    const { userUuid } = req.session;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const user = await getUserByUuidUnsafe(userUuid);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const groupUuid = await createGroup(userUuid, name, description);

    res.status(201).json({ message: "Group created successfully", groupUuid });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creating group" });
  }
});

router.get("/group/:uuid/role", async (req, res) => {
  try {
    const { uuid } = req.params;
    const { userUuid } = req.session;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const user = await getUserByUuid(userUuid);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const { role } = await getUserRoleInGroup(user.id, uuid);
    if (!role) {
      return res.status(404).json({ error: "User not in group" });
    }

    res.json({ role: role });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching user role in group" });
  }
});

router.post("/group/:uuid/invite", async (req, res) => {
  try {
    const { uuid } = req.params;
    const { userUuid, inviteRole } = req.body;
    const {
      userUuid: currentUserUuid,
      sessionPrivateKey: encryptedPrivateKey,
    } = req.session;
    const tokenBase64 = req.cookies.token;

    if (!currentUserUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const currentUser = await getUserByUuid(currentUserUuid);
    if (!currentUser) {
      return res.status(404).json({ error: "User not found" });
    }

    const {
      role: currentUserRole,
      encrypted_group_key: currentUserEncryptedGroupKey,
    } = await getUserRoleInGroup(currentUser.id, uuid);
    if (currentUserRole !== "admin" && currentUserRole !== "ambassador") {
      return res
        .status(403)
        .json({ error: "User does not have permission to invite users" });
    }

    const token = Buffer.from(tokenBase64, "base64");
    const decryptedPrivateKey = decryptAes(encryptedPrivateKey, token);
    const decryptedGroupKey = decryptRsa(
      currentUserEncryptedGroupKey,
      decryptedPrivateKey
    );

    await inviteUserToGroup(
      uuid,
      userUuid,
      decryptedGroupKey,
      !inviteRole || currentUserRole === "ambassador" ? "member" : inviteRole
    );

    res.json({ message: "User invited successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error inviting user" });
  }
});

router.get("/group/:uuid/users", async (req, res) => {
  try {
    const { uuid } = req.params;
    const { userUuid } = req.session;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const users = await getUsersInGroup(uuid, userUuid);

    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching users in group" });
  }
});

router.post("/group/:uuid/update-role", async (req, res) => {
  try {
    const { uuid } = req.params;
    const { targetUserUuid, newRole } = req.body;
    const { userUuid } = req.session;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const user = await getUserByUuid(userUuid);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const { role: userRole } = await getUserRoleInGroup(user.id, uuid);
    if (userRole !== "admin") {
      return res
        .status(403)
        .json({ error: "User is not an admin of the group" });
    }

    await updateUserRoleInGroup(userUuid, targetUserUuid, uuid, newRole);

    res.json({ message: "User role updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error updating user role" });
  }
});

router.get("/group/:uuid", async (req, res) => {
  try {
    const { uuid } = req.params;
    const group = await getGroupByUuid(uuid);

    if (!group) {
      return res.status(404).json({ error: "Group not found" });
    }

    res.json({
      name: group.name,
      description: group.description,
      created_at: group.created_at,
      hidden: group.hidden,
      trust_trace: group.trust_trace,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching group" });
  }
});

router.get("/user-groups", async (req, res) => {
  try {
    const { userUuid } = req.session;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const userGroups = await getUserGroups(userUuid);
    const groupsWithPostCounts = await Promise.all(
      userGroups.map(async (group) => {
        const postCount = await getPostCountSinceLastLogin(
          group.uuid,
          userUuid
        );
        return { uuid: group.uuid, name: group.name, recentPosts: postCount };
      })
    );

    groupsWithPostCounts.sort((a, b) => b.recentPosts - a.recentPosts);

    res.json(groupsWithPostCounts);
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ error: "Error fetching user groups with recent posts" });
  }
});

router.put("/group/:uuid", async (req, res) => {
  try {
    const { uuid } = req.params;
    const { name, description, hidden, trust_trace } = req.body;
    const { userUuid } = req.session;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const user = await getUserByUuid(userUuid);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const { role: userRole } = await getUserRoleInGroup(user.id, uuid);
    if (userRole !== "admin") {
      return res
        .status(403)
        .json({ error: "User is not an admin of the group" });
    }

    await editGroup(uuid, name, description, true, true);

    res.json({ message: "Group updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error updating group" });
  }
});

module.exports = router;
