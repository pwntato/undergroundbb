const express = require('express');
const cors = require('cors');
const sessionMiddleware = require('./redis').sessionMiddleware;
const testRoutes = require('./routes/test_routes');

const app = express();
app.use(cors());
app.use(sessionMiddleware);

app.use('/test', testRoutes);

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
