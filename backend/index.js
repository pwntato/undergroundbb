const express = require('express');
const cors = require('cors');
const sessionMiddleware = require('./redis').sessionMiddleware;
const cookieParser = require('cookie-parser');
const userRoutes = require('./routes/user_routes');

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

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
