const express = require("express");
const { createGroup, getGroupByUuid } = require("../services/group");
const { getUserByUuid } = require("../services/user");

const router = express.Router();

router.post("/create-group", async (req, res) => {
  try {
    const { name, description } = req.body;
    const { userUuid } = req.session;

    if (!userUuid) {
      return res.status(401).json({ error: "User not logged in" });
    }

    const user = await getUserByUuid(userUuid);
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
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching group" });
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

    const userRole = await getUserRoleInGroup(user.id, uuid);
    if (userRole !== 'admin') {
      return res.status(403).json({ error: "User is not an admin of the group" });
    }

    await editGroup(uuid, name, description, hidden, trust_trace);

    res.json({ message: "Group updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error updating group" });
  }
});

module.exports = router;
