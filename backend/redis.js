const session = require("express-session");
const RedisStore = require("connect-redis").default;
const redis = require("redis");

const redisClient = redis.createClient({
  url: `redis://:${process.env.REDIS_PASSWORD}@${process.env.REDIS_HOST}:6379`,
});

redisClient.connect().catch(console.error);

const sessionMiddleware = session({
  store: new RedisStore({ client: redisClient }),
  name: "sessionID",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: process.env.SESSION_TIMEOUT_HOURS * 60 * 60 * 1000,
  },
});

module.exports = { sessionMiddleware, redisClient };
