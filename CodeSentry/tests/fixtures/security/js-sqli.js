const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // SQL injection: user input directly interpolated into query
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  db.query(query, (err, result) => {
    if (err) {
      res.status(500).send('Error');
    } else {
      res.json(result);
    }
  });
});

app.get('/search', (req, res) => {
  const term = req.query.q;
  // Another SQL injection variant
  const sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'";
  db.query(sql, (err, rows) => {
    res.json(rows || []);
  });
});

app.listen(3000);
