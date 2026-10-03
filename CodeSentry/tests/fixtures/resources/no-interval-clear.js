// setInterval without clearInterval - resource leak
function startPolling() {
  setInterval(() => {
    console.log('polling...');
    fetchData();
  }, 5000);
}

function startMonitoring() {
  const intervalId = setInterval(() => {
    checkHealth();
  }, 10000);
  // intervalId never used with clearInterval
}

function fetchData() { return {}; }
function checkHealth() {}

module.exports = { startPolling, startMonitoring };
