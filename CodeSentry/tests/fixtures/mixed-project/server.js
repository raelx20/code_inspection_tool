const express = require('express');
const app = express();

// Mixed issues
const SECRET_KEY = 'super-secret-key-123';

app.get('/api/user/:id', (req, res) => {
  const userId = req.params.id;
  
  // SQL injection
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  // Missing input validation
  if (!userId) {
    return res.status(400).send('Missing user ID');
  }
  
  // Unprotected route
  db.query(query, (err, result) => {
    if (err) {
      console.log(err); // Logging sensitive info
      return res.status(500).send('Internal Server Error');
    }
    res.json(result);
  });
});

app.post('/api/execute', (req, res) => {
  const { code } = req.body;
  
  // Command injection
  const result = eval(code);
  res.json({ result });
});

// Performance issue: nested loops
app.get('/api/match', (req, res) => {
  const items = [1, 2, 3, 4, 5];
  const targets = [1, 2, 3, 4, 5];
  
  for (let i = 0; i < items.length; i++) {
    for (let j = 0; j < targets.length; j++) {
      if (items[i] === targets[j]) {
        console.log('Found match');
      }
    }
  }
  
  res.json({ matches: items.length });
});

// Resource leak
app.get('/api/file', (req, res) => {
  const fs = require('fs');
  const stream = fs.createReadStream('/large-file.txt');
  
  // Missing error handling
  stream.on('data', (chunk) => {
    res.write(chunk);
  });
  
  stream.on('end', () => {
    res.end();
  });
});

app.listen(3000);