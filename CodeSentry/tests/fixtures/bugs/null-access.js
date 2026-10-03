function getUserName(user) {
  // Potential null access without check
  return user.profile.name;
}

function processItems(items) {
  const first = items[0];
  // Accessing property of potentially undefined
  return first.value.toUpperCase();
}

function connect(config) {
  const host = config.database.host;
  const port = config.database.port;
  // No null checks on nested access
  return `${host}:${port}`;
}

module.exports = { getUserName, processItems, connect };
