const express = require('express');
const { login, logout } = require('../services/login');
const { getUserByUuid, getUserGroups, isUsernameAvailable, validatePassword, createUser, updateUser, changePassword } = require('../services/user');

const router = express.Router();

router.get('/check-username/:username', async (req, res) => {
  try {
    const username = req.params.username;
    const available = await isUsernameAvailable(username);
    res.json({ available });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error checking if username available" });
  }
});

router.post('/validate-password', (req, res) => {
  const { password } = req.body;

  try {
    validatePassword(password);
    return res.status(200).json({ message: 'Password is valid' });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

router.post('/create-user', async (req, res) => {
  try {
    const { username, password } = req.body;
    await createUser(username, password);
    res.status(201).json({ message: 'User created successfully', username });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error creating user" });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const { session } = req;
    await login(username, password, session, res);
    res.json({ message: 'Login successful', username });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error logging in" });
  }
});

router.post('/logout', (req, res) => {
  try {
    const { session } = req;
    logout(session, res);
    res.json({ message: 'Logout successful' });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error logging out" });
  }
});

router.get('/user/:uuid', async (req, res) => {
  try {
    const ERROR_STRING = 'User not found';
    const { uuid } = req.params;
    const { session } = req;
    const currentUserUuid = session.userUuid;

    const user = await getUserByUuid(uuid);
    if (user) {
      // const isCurrentUser = user.uuid === currentUserUuid;
      // const isHidden = user.hidden;
      // const currentUserGroups = await getUserGroups(currentUserUuid);
      // const targetUserGroups = await getUserGroups(user.uuid);
      // const isMemberOfSameGroup = currentUserGroups.some(group =>
      //   targetUserGroups.includes(group)
      // );
      
      if (true || isCurrentUser || ! isHidden || isMemberOfSameGroup) {
        return res.json({ username: user.username, uuid: user.uuid });
      }
    }
    return res.status(404).json({ error: ERROR_STRING });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error getting user" });
  }
});

router.get('/current-user', async (req, res) => {
  try {
    const { session } = req;
    const currentUserUuid = session.userUuid;

    if (!currentUserUuid) {
      return res.status(401).json({ error: 'User not logged in' });
    }

    const user = await getUserByUuid(currentUserUuid);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { username, email, bio, hidden, created_at } = user;

    const groups = await getUserGroups(currentUserUuid);
    const groupMap = groups.reduce((map, group) => {
      map[group.uuid] = group.name;
      return map;
    }, {});

    return res.json({ username, email, bio, hidden, created_at, groups: groupMap });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error getting current user" });
  }
});

router.put('/current-user', async (req, res) => {
  try {
    const { session } = req;
    const currentUserUuid = session.userUuid;

    if (!currentUserUuid) {
      return res.status(401).json({ error: 'User not logged in' });
    }

    const { email, bio, hidden } = req.body;

    const user = await getUserByUuid(currentUserUuid);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    await updateUser(currentUserUuid, { email, bio, hidden });

    return res.json({ message: 'User updated successfully' });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error updating user" });
  }
});

router.put('/change-password', async (req, res) => {
  try {
    const user = await getUserByUuid(req.session.userUuid);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const { oldPassword, newPassword } = req.body;
    await changePassword(user.username, oldPassword, newPassword);
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.log(error);
    res.status(200).json({ error: error.message });
  }
});

module.exports = router;
