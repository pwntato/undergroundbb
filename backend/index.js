const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redis = require('redis');
const cors = require('cors');
const pool = require('./db');
const testRoutes = require('./routes/test_routes');

const app = express();
app.use(cors());

const isDevelopment = process.env.NODE_ENV === 'development';

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

app.use('/test', testRoutes);

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
