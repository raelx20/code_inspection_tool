const fs = require('fs');

async function readConfig(path) {
  // Synchronous call in async function
  const data = fs.readFileSync(path, 'utf-8');
  return JSON.parse(data);
}

function loadAllFiles(dir) {
  const files = fs.readdirSync(dir);
  const contents = [];
  // Multiple sync calls
  for (const file of files) {
    const content = fs.readFileSync(`${dir}/${file}`, 'utf-8');
    contents.push(content);
  }
  return contents;
}

module.exports = { readConfig, loadAllFiles };
