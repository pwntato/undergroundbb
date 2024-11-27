const express = require('express');
const { createGroup } = require('../services/group');
const { getUserByUuid } = require('../services/user');

const router = express.Router();

router.post('/create-group', async (req, res) => {
  try {
    const { name, description } = req.body;
    const { userUuid } = req.session;

    if (!userUuid) {
      return res.status(401).json({ error: 'User not logged in' });
    }

    const user = await getUserByUuid(userUuid);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const groupUuid = await createGroup(userUuid, name, description);

    res.status(201).json({ message: 'Group created successfully', groupUuid });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error creating group' });
  }
});

module.exports = router;
