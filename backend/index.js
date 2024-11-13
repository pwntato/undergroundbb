const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redis = require('redis');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());

const isDevelopment = process.env.NODE_ENV === 'development';

const pool = new Pool({
  user: process.env.POSTGRES_USER,
  host: process.env.POSTGRES_HOST,
  database: process.env.POSTGRES_DB,
  password: process.env.POSTGRES_PASSWORD,
  port: 5432,
});

const redisClient = redis.createClient({
  url: `redis://:${process.env.REDIS_PASSWORD}@${process.env.REDIS_HOST}:6379`
});

redisClient.connect().catch(console.error);

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: !isDevelopment,
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000 // 30 minutes
  }
}));

app.get('/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT username FROM users');
    res.send(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.get('/time', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.send(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
