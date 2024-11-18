const express = require('express');
const { isUsernameAvailable, validatePassword, createUser } = require('../users/create_user');
const { isLoggedIn, login } = require('../users/login');
const { getUserByUuid, getUserGroups } = require('../users/user');

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

router.get('/is-logged-in', (req, res) => {
  try {
    const { session } = req;
    const loggedIn = isLoggedIn(session);
    if (loggedIn) {
      res.json({ loggedIn: true, username: session.username });
    } else {
      res.json({ loggedIn: false });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error checking login status" });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const session = req.session;
    await login(username, password, session);
    res.json({ message: 'Login successful', username });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error logging in" });
  }
});

router.get('/user/:uuid', async (req, res) => {
  try {
    const ERROR_STRING = 'User not found';
    const { uuid } = req.params;
    const session = req.session;
    const currentUserUuid = session.userUuid;

    const user = await getUserByUuid(uuid);
    console.log(currentUserUuid);
    console.log(session.username);
    if (user) {
      const isCurrentUser = user.uuid === currentUserUuid;
      const isHidden = user.hidden;
      const currentUserGroups = await getUserGroups(currentUserUuid);
      const targetUserGroups = await getUserGroups(user.uuid);
      const isMemberOfSameGroup = currentUserGroups.some(group =>
        targetUserGroups.includes(group)
      );
      // A console.log to log all the variables in the if statement with key/value pairs
      console.log({ isCurrentUser: isCurrentUser, isHidden: isHidden, isMemberOfSameGroup: isMemberOfSameGroup });
      
      if (isCurrentUser || ! isHidden || isMemberOfSameGroup) {
        return res.json({ username: user.username, uuid: user.uuid });
      }
      
    }
    return res.status(404).json({ error: ERROR_STRING });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error getting user" });
  }
});

module.exports = router;
