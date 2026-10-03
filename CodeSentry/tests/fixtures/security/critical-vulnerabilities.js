// Critical: Insecure deserialization
const deserialize = require('node-serialize');

// Unsafe: Object injection via deserialization
router.post('/update-profile', (req, res) => {
  const userData = req.body.data;

  // Attacker can inject __proto__.isAdmin = true
  const profile = deserialize.unserialize(userData);
  updateUser(profile);
});

// Unsafe: eval() with user input
router.post('/calculate', (req, res) => {
  const expression = req.body.expression;

  // Direct code execution
  const result = eval(expression);
  res.json({ result });
});

// Unsafe: Function constructor with user input
router.get('/dynamic', (req, res) => {
  const code = req.query.code;

  // Dynamic function execution
  const fn = new Function('return ' + code)();
  res.json({ result: fn });
});

// Unsafe: JSON.parse without validation
function processConfig(configString) {
  try {
    const config = JSON.parse(configString);
    // No schema validation, allows prototype pollution
    Object.assign(global, config);
  } catch (e) {
    console.error('Parse error');
  }
}

// Unsafe: Regular expression DoS (ReDoS)
function validateEmail(email) {
  // Vulnerable regex pattern
  const regex = /^([a-zA-Z0-9]+)@([a-zA-Z0-9]+)\.([a-zA-Z]{2,})$/;
  return regex.test(email);
}

// Unsafe: require() with user input
router.get('/load-module', (req, res) => {
  const moduleName = req.query.module;

  // Attacker can load arbitrary modules
  const mod = require(moduleName);
  res.json(mod);
});

// Unsafe: child_process with user input
const { exec } = require('child_process');

router.post('/ping', (req, res) => {
  const host = req.body.host;

  // Command injection
  exec(`ping -c 4 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

// Unsafe: fs operations with user input
const fs = require('fs');
const path = require('path');

router.get('/read', (req, res) => {
  const file = req.query.file;

  // Path traversal
  const filePath = path.join(__dirname, 'uploads', file);
  const content = fs.readFileSync(filePath, 'utf8');
  res.send(content);
});

// Unsafe: open redirect
router.get('/redirect', (req, res) => {
  const url = req.query.url;

  // Open redirect vulnerability
  res.redirect(url);
});

// Unsafe: CORS misconfiguration
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); // Allows any origin
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// Unsafe: Insecure session configuration
app.use(session({
  secret: 'weak-secret', // Weak session secret
  cookie: {
    secure: false, // Not HTTPS only
    httpOnly: false, // Accessible via JavaScript
    maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year - too long
  }
}));

// Unsafe: Information disclosure in errors
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack, // Exposes stack trace
    query: req.query, // Exposes query parameters
    body: req.body    // Exposes request body
  });
});

// Unsafe: Directory listing enabled
app.use('/uploads', express.static('uploads', { dotfiles: 'allow' }));

// Unsafe: Missing security headers
// Should use helmet or set manually:
// X-Content-Type-Options: nosniff
// X-Frame-Options: DENY
// X-XSS-Protection: 1; mode=block
// Strict-Transport-Security: max-age=31536000; includeSubDomains

module.exports = router;
