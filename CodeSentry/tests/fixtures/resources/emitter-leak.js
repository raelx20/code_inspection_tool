// Memory leak: Event emitter without cleanup
const EventEmitter = require('events');

class ConnectionPool extends EventEmitter {
  constructor() {
    super();
    this.connections = [];
  }

  addConnection(conn) {
    this.connections.push(conn);
    conn.on('data', (chunk) => {
      this.emit('data', chunk);
    });
    conn.on('error', (err) => {
      this.emit('error', err);
    });
    // Listeners never removed when connection closes
  }

  removeConnection(conn) {
    const idx = this.connections.indexOf(conn);
    if (idx > -1) {
      this.connections.splice(idx, 1);
      // Forgot to remove listeners - memory leak
    }
  }
}

// Memory leak: Promise chain without proper handling
function processQueue(queue) {
  const results = [];
  queue.forEach((item, i) => {
    results.push(
      processItem(item).then(result => {
        results[i] = result;
        // Closure keeps reference to results array
      })
    );
  });
  return Promise.all(results);
}

// Memory leak: Stream not properly closed
function readLargeFile(filePath) {
  const fs = require('fs');
  const stream = fs.createReadStream(filePath);
  const chunks = [];

  stream.on('data', (chunk) => {
    chunks.push(chunk);
  });

  stream.on('end', () => {
    // Stream not destroyed, listeners not removed
    return Buffer.concat(chunks);
  });

  // No error handling or stream cleanup
}

// Memory leak: Recursive function without proper base case handling
function processData(nodes, visited = new Set()) {
  const results = [];
  for (const node of nodes) {
    if (!visited.has(node.id)) {
      visited.add(node.id);
      // If node.children is circular, visited keeps growing
      const childResults = processData(node.children || [], visited);
      results.push(...childResults);
    }
  }
  return results;
}

module.exports = { ConnectionPool, processQueue, readLargeFile, processData };
