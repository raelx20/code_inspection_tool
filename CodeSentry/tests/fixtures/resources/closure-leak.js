// Memory leak: Unreleased references in closures
function createRequestHandler() {
  const largeData = Buffer.alloc(10 * 1024 * 1024); // 10MB buffer

  return function handler(req, res) {
    // Closure retains largeData even after request completes
    console.log('Processing request');
    res.send('Done');
  };
}

// Memory leak: Event listener accumulation
class EventBus {
  constructor() {
    this.listeners = {};
  }

  on(event, callback) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(callback);
    // Never removed - accumulates over time
  }

  emit(event, data) {
    (this.listeners[event] || []).forEach(cb => cb(data));
  }
}

// Memory leak: Growing array without cleanup
const requestLog = [];
function logRequest(req) {
  requestLog.push({
    url: req.url,
    timestamp: Date.now(),
    headers: { ...req.headers },
    body: req.body
  });
  // requestLog grows indefinitely
}

// Memory leak: Timer not cleared
function startPolling() {
  const data = [];
  const interval = setInterval(() => {
    data.push(new Array(1000).fill(0));
    // interval never cleared, data grows
  }, 100);
  return { data };
}

// Memory leak: Global cache without eviction
const globalCache = {};
function cacheResponse(key, value) {
  globalCache[key] = value;
  // No TTL, no size limit, no eviction
}

module.exports = { createRequestHandler, EventBus, logRequest, startPolling, cacheResponse };
