const express = require('express');
const router = express.Router();
const db = require('./database');

// Critical: SQL Injection via multiple patterns
router.get('/users', async (req, res) => {
  const { name, role, sort } = req.query;

  // Pattern 1: String concatenation
  const q1 = `SELECT * FROM users WHERE name = '${name}'`;

  // Pattern 2: Template literal
  const q2 = `SELECT * FROM users WHERE role = '${role}' ORDER BY ${sort}`;

  // Pattern 3: Dynamic table/column
  const q3 = `SELECT * FROM ${req.query.table} WHERE id = ${req.body.id}`;

  // Pattern 4: IN clause injection
  const ids = req.query.ids.split(',');
  const q4 = `SELECT * FROM users WHERE id IN (${ids.join(',')})`;
});

// Critical: NoSQL Injection (MongoDB)
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // MongoDB operator injection
  const user = await User.findOne({
    username: username,  // Attacker sends: {"$gt": ""}
    password: password   // Attacker sends: {"$gt": ""}
  });

  // Another NoSQL injection pattern
  const query = {
    $where: `this.username === '${username}'`
  };
});

// Critical: LDAP Injection
router.get('/search', (req, res) => {
  const searchTerm = req.query.q;

  // LDAP injection
  const filter = `(cn=*)${searchTerm}*)`;
  ldapClient.search(filter, (err, result) => {
    res.json(result);
  });
});

// Critical: XPath Injection
router.get('/xml-user', (req, res) => {
  const userId = req.query.id;

  // XPath injection
  const xpath = `//user[id='${userId}']`;
  const result = doc.selectSingleNode(xpath);
  res.json(result);
});

// Critical: Command Injection via multiple vectors
const { exec, spawn } = require('child_process');

router.post('/backup', (req, res) => {
  const { filename } = req.body;

  // Direct command injection
  exec(`tar -czf backup.tar.gz ${filename}`, (err, stdout) => {
    res.send(stdout);
  });
});

router.get('/convert', (req, res) => {
  const input = req.query.file;

  // spawn with shell injection
  const convert = spawn('convert', [input, 'output.png'], {
    shell: true  // Enables shell interpretation
  });
});

module.exports = router;
