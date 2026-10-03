// Inefficiency: Unbounded data structures
class DataStore {
  constructor() {
    this.cache = new Map();
    this.queue = [];
  }

  addToCache(key, value) {
    this.cache.set(key, value); // No size limit, no eviction
  }

  enqueue(item) {
    this.queue.push(item); // Queue grows unbounded
  }

  dequeue() {
    return this.queue.shift(); // O(n) operation on every dequeue
  }
}

// Inefficiency: Blocking operations
function processLargeDataset(data) {
  const results = [];
  for (let i = 0; i < data.length; i++) {
    // Synchronous CPU-intensive operation
    const hash = require('crypto').createHash('sha256')
      .update(JSON.stringify(data[i]))
      .digest('hex');
    results.push(hash);
  }
  return results;
}

// Inefficiency: Not using streams for large data
async function copyFile(source, dest) {
  const fs = require('fs').promises;
  const data = await fs.readFile(source); // Loads entire file into memory
  await fs.writeFile(dest, data);
}

// Inefficiency: Repeated database queries
async function getUserWithPosts(userId) {
  const user = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
  const posts = await db.query('SELECT * FROM posts WHERE userId = ?', [userId]);
  const comments = await db.query('SELECT * FROM comments WHERE userId = ?', [userId]);
  // 3 separate queries instead of JOIN or single query
}

// Inefficiency: Creating new objects/functions in hot paths
function createHandler() {
  return function(req, res) {
    const util = require('util'); // Required on every request
    const formatted = util.format(req.url);
    res.send(formatted);
  };
}

// Inefficiency: Not caching expensive computations
function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2); // Recomputes same values
}

// Inefficiency: Using array methods instead of loops for simple operations
function sumArray(arr) {
  return arr.reduce((sum, val) => sum + val, 0); // Slower than for loop for large arrays
}

// Inefficiency: Excessive string operations
function buildQueryString(params) {
  let query = '';
  for (const [key, value] of Object.entries(params)) {
    query += `${key}=${encodeURIComponent(value)}&`; // String concatenation
  }
  return query.slice(0, -1); // Extra operation to remove trailing &
}

module.exports = { DataStore, processLargeDataset, copyFile, getUserWithPosts, fibonacci, sumArray, buildQueryString };
