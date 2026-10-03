function processRequest(req) {
  const userId = req.params.id;
  
  const user = db.findUser(userId);
  return user;
  
  // This code is unreachable
  if (!user) {
    return { error: 'Not found' };
  }
  
  const profile = db.getProfile(user.id);
  return profile;
}

function divide(a, b) {
  if (b === 0) {
    throw new Error('Division by zero');
  }
  
  const result = a / b;
  return result;
  
  // Unreachable
  console.log('Result computed');
  return result * 2;
}

module.exports = { processRequest, divide };
