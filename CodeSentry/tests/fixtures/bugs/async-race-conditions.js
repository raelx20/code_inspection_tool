// Bug: Race condition in async operations
class Counter {
  constructor() {
    this.count = 0;
  }

  async increment() {
    const current = this.count;
    await someAsyncOperation();
    this.count = current + 1; // Race condition: stale read
  }

  async decrement() {
    const current = this.count;
    await someAsyncOperation();
    this.count = current - 1; // Race condition
  }
}

// Bug: Unhandled promise rejection
async function riskyOperation() {
  const data = await fetchExternalAPI();
  return data.json(); // If fetch fails, rejection unhandled
}

// Bug: Incorrect async/await in loop
async function processItems(items) {
  const results = [];
  items.forEach(async (item) => {
    const result = await processItem(item);
    results.push(result); // Push happens after function returns
  });
  return results; // Always empty
}

// Bug: Double callback invocation
function saveUser(user, callback) {
  if (!user.name) {
    return callback(new Error('Name required'));
  }
  db.save(user, (err) => {
    if (err) {
      return callback(err);
    }
    callback(null, user);
  });
  // If db.save is async and throws, callback called twice
}

// Bug: Event listener memory leak from anonymous functions
function setupHandlers(emitter) {
  emitter.on('data', (msg) => console.log('data:', msg));
  emitter.on('error', (err) => console.error(err));
  // Handlers can never be removed (anonymous functions)
}

// Bug: Missing await causes undefined
async function getUserName(id) {
  const user = db.findUser(id); // Missing await
  return user.name; // user is a Promise, not the actual user
}

// Bug: Incorrect Promise chaining
function fetchData() {
  return fetch('/api/data')
    .then(res => res.json())
    .catch(err => console.log(err))
    .then(data => data.results); // data may be undefined if catch ran
}

// Bug: Stale closure in loop
for (var i = 0; i < 5; i++) {
  setTimeout(() => {
    console.log(i); // Always prints 5
  }, 1000);
}

module.exports = { Counter, riskyOperation, processItems, saveUser, setupHandlers, getUserName, fetchData };
