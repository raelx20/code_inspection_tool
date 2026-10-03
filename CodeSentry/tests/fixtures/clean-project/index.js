const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.json({ message: 'Hello World' });
});

app.get('/user/:id', async (req, res) => {
  const userId = req.params.id;
  // Using parameterized query
  const user = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
  res.json(user);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;