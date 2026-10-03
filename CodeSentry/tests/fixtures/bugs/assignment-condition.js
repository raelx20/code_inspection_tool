function processUser(user) {
  // Assignment in condition (= instead of ===)
  if (user.active = true) {
    return 'active';
  }
  return 'inactive';
}

function findItem(items, target) {
  let item;
  // Assignment in while condition
  while (item = items.pop()) {
    if (item.id === target) {
      return item;
    }
  }
  return null;
}

module.exports = { processUser, findItem };
