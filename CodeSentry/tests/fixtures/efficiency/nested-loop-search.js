function findMatches(items, targets) {
  const matches = [];
  // O(n^2): nested loops with array search
  for (let i = 0; i < items.length; i++) {
    for (let j = 0; j < targets.length; j++) {
      if (items[i] === targets[j]) {
        matches.push(items[i]);
      }
    }
  }
  return matches;
}

function removeDuplicates(arr) {
  const result = [];
  // O(n^2): includes() in loop
  for (let i = 0; i < arr.length; i++) {
    if (!result.includes(arr[i])) {
      result.push(arr[i]);
    }
  }
  return result;
}

module.exports = { findMatches, removeDuplicates };
