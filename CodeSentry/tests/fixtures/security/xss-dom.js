// DOM-based XSS vulnerabilities
const { JSDOM } = require('jsdom');

function renderUserContent(userInput) {
  const dom = new JSDOM(`<div id="output"></div>`);
  const document = dom.window.document;

  // DOM XSS: setting innerHTML with unsanitized input
  document.getElementById('output').innerHTML = userInput;

  return dom.serialize();
}

function createLink(url, text) {
  // DOM XSS via attribute injection
  return `<a href="${url}">${text}</a>`;
}

function setSearchResults(query, results) {
  // DOM XSS in dynamic script
  const script = `
    var searchQuery = "${query}";
    var results = ${JSON.stringify(results)};
    document.title = "Results for " + searchQuery;
  `;
  return script;
}

module.exports = { renderUserContent, createLink, setSearchResults };
