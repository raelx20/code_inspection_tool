const express = require('express');
const app = express();

// Hardcoded credentials
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'admin123';

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  
  // SQL injection vulnerability
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  db.query(query, (err, result) => {
    if (err) {
      res.status(500).send('Error');
    } else {
      res.json(result);
    }
  });
});

app.post('/execute', (req, res) => {
  const code = req.body.code;
  
  // Command injection vulnerability
  eval(code);
  
  res.json({ success: true });
});

app.get('/file/:filename', (req, res) => {
  const filename = req.params.filename;
  
  // Path traversal vulnerability
  const filePath = `/uploads/${filename}`;
  res.sendFile(filePath);
});

// Unused variable
const unusedVariable = 'this is never used';

// Missing error handling
app.listen(3000);