const express = require('express');
const path = require('path');
const app = express();

app.get('/files/:filename', (req, res) => {
  const filename = req.params.filename;
  // Path traversal: user input used directly in file path
  const filePath = path.join('/uploads', filename);
  res.sendFile(filePath);
});

app.get('/download', (req, res) => {
  const file = req.query.file;
  // Another path traversal
  res.download(`/data/${file}`);
});

app.listen(3000);
