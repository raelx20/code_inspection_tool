const fs = require('fs');

function readFile(path) {
  // Stream created without close/destroy
  const stream = fs.createReadStream(path);
  
  stream.on('data', (chunk) => {
    console.log(chunk);
  });
  
  stream.on('end', () => {
    console.log('done');
  });
  // No stream.close() or stream.destroy() call
}

function writeFile(path, data) {
  const writeStream = fs.createWriteStream(path);
  writeStream.write(data);
  // No close() call
}

module.exports = { readFile, writeFile };
