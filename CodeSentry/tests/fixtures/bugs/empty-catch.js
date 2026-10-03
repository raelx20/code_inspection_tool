function parseData(input) {
  try {
    const data = JSON.parse(input);
    return data;
  } catch (e) {
    // Empty catch block - silently swallows the error
  }
}

function fetchData(url) {
  try {
    const response = http.get(url);
    return response;
  } catch (err) {
    // Another empty catch
  }
}

function validateUser(user) {
  try {
    if (!user.name) throw new Error('Name required');
    if (!user.email) throw new Error('Email required');
    return true;
  } catch (e) {
    // Swallowed validation error
    return false;
  }
}

module.exports = { parseData, fetchData, validateUser };
