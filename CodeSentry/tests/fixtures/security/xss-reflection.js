const express = require('express');
const app = express();

// XSS: Unsanitized user input in HTML response
app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.send(`<h1>Hello, ${name}!</h1>`);
});

// XSS: Direct HTML injection via innerHTML-like pattern
app.get('/comment', (req, res) => {
  const comment = req.body.comment;
  const html = `<div class="comment">${comment}</div>`;
  res.send(html);
});

// XSS: DOM manipulation with user data
app.get('/profile', (req, res) => {
  const bio = req.query.bio;
  res.send(`<script>document.getElementById('bio').innerHTML = '${bio}';</script>`);
});

// XSS: Reflected in attribute
app.get('/redirect', (req, res) => {
  const url = req.query.next;
  res.send(`<a href="${url}">Click here</a>`);
});

app.listen(3000);
