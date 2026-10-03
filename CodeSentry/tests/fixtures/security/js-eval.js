const express = require('express');
const app = express();

app.post('/calculate', (req, res) => {
  const expression = req.body.expr;
  // Unsafe eval: executes arbitrary user code
  const result = eval(expression);
  res.json({ result });
});

app.post('/template', (req, res) => {
  const data = req.body;
  // Unsafe eval with user data in scope
  const output = eval('`' + data.template + '`');
  res.send(output);
});

app.listen(3000);
