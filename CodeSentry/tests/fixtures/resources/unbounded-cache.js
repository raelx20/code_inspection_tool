// Unbounded cache - no eviction
const cache = new Map();

function getFromCache(key) {
  return cache.get(key);
}

function setCache(key, value) {
  cache.set(key, value);
  // No size limit, no eviction, grows indefinitely
}

const userData = {};

function storeUser(id, data) {
  userData[id] = data;
  // Object grows without bound
}

module.exports = { getFromCache, setCache, storeUser };
