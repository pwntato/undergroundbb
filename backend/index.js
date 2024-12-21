const express = require('express');
const cors = require('cors');
const sessionMiddleware = require('./redis').sessionMiddleware;
const cookieParser = require('cookie-parser');
const userRoutes = require('./routes/user_routes');
const groupRoutes = require('./routes/group_routes');
const postRoutes = require('./routes/post_routes');

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  methods: ['POST', 'PUT', 'GET', 'OPTIONS', 'HEAD'],
  credentials: true
}));
app.use(sessionMiddleware);
app.use(cookieParser());

app.use('/api/users', userRoutes);
app.use('/api/groups', groupRoutes);
app.use('/api/posts', postRoutes);

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
