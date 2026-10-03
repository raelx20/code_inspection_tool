// Prototype pollution vulnerabilities
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Vulnerable: No key validation allows __proto__ pollution
function updateUserSettings(userId, settings) {
  const user = getUser(userId);
  merge(user, settings);
  return user;
}

// Vulnerable: Direct prototype access
function setConfig(obj, path, value) {
  const keys = path.split('.');
  let current = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    current = current[keys[i]];
  }
  current[keys[keys.length - 1]] = value;
}

// Vulnerable: JSON.parse without sanitization
function processInput(jsonString) {
  const data = JSON.parse(jsonString);
  const config = {};
  merge(config, data); // Attacker can inject __proto__.isAdmin = true
  return config;
}

module.exports = { merge, updateUserSettings, setConfig, processInput };
