function processItems(items) {
  const results = [];
  // Off-by-one: <= should be <
  for (let i = 0; i <= items.length; i++) {
    results.push(items[i]);
  }
  return results;
}

function sumArray(arr) {
  let total = 0;
  // Off-by-one in reverse loop
  for (let i = arr.length; i >= 0; i--) {
    total += arr[i];
  }
  return total;
}

module.exports = { processItems, sumArray };
