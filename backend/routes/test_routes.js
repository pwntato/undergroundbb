const express = require('express');
const router = express.Router();
const pool = require('../db');

router.get('/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT username FROM users');
    res.send(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

router.get('/time', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.send(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

module.exports = router;
