const { exec } = require('child_process');
const express = require('express');
const app = express();

app.post('/run', (req, res) => {
  const userInput = req.body.command;
  // Command injection: user input passed directly to shell
  exec(userInput, (error, stdout, stderr) => {
    res.json({ output: stdout, error: stderr });
  });
});

app.post('/ping', (req, res) => {
  const host = req.body.host;
  // Command injection via template literal
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

app.listen(3000);
