const express = require('express');
const { isUsernameAvailable, validatePassword, createUser } = require('../users/create_user');
const { isLoggedIn, loginUser } = require('../users/login');

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
    await loginUser(username, password, session);
    res.json({ message: 'Login successful', username });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error logging in" });
  }
});

module.exports = router;
