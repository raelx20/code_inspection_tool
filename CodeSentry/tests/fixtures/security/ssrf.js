const http = require('http');
const https = require('https');

// SSRF: User-controlled URL fetch
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  const response = await fetch(url);
  const data = await response.text();
  res.send(data);
});

// SSRF: Internal network access
app.get('/proxy', (req, res) => {
  const target = req.query.target;
  http.get(target, (proxyRes) => {
    let body = '';
    proxyRes.on('data', (chunk) => body += chunk);
    proxyRes.on('end', () => res.send(body));
  });
});

// SSRF via file:// protocol
app.get('/read-file', (req, res) => {
  const filePath = req.query.path;
  const fs = require('fs');
  fs.readFile(filePath, (err, data) => {
    if (err) res.status(500).send('Error');
    else res.send(data);
  });
});

// SSRF with DNS rebinding potential
app.get('/ping', (req, res) => {
  const host = req.query.host;
  const dns = require('dns');
  dns.resolve4(host, (err, addresses) => {
    if (err) res.status(500).send('DNS error');
    else res.json({ addresses });
  });
});

app.listen(3000);
