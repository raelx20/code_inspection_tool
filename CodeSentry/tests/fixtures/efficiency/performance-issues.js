// Inefficiency: O(n²) nested loop search
function findCommonElements(arr1, arr2) {
  const common = [];
  for (let i = 0; i < arr1.length; i++) {
    for (let j = 0; j < arr2.length; j++) {
      if (arr1[i] === arr2[j]) {
        common.push(arr1[i]);
      }
    }
  }
  return common;
}

// Inefficiency: Repeated array.includes in loop
function filterUnique(items) {
  const result = [];
  for (const item of items) {
    if (!result.includes(item)) { // O(n) check each time
      result.push(item);
    }
  }
  return result;
}

// Inefficiency: String concatenation in loop
function buildReport(items) {
  let report = '';
  for (const item of items) {
    report += item.name + ': ' + item.value + '\n'; // Creates new string each iteration
  }
  return report;
}

// Inefficiency: Recomputing in loop
function processMatrix(matrix) {
  const results = [];
  for (let i = 0; i < matrix.length; i++) {
    const sum = matrix[i].reduce((a, b) => a + b, 0); // Recomputes reduce each time
    const avg = sum / matrix[i].length;
    results.push(avg);
  }
  return results;
}

// Inefficiency: Unnecessary object spread in loop
function mergeObjects(objects) {
  let result = {};
  for (const obj of objects) {
    result = { ...result, ...obj }; // Creates new object each iteration
  }
  return result;
}

// Inefficiency: Sync file operations in loop
const fs = require('fs');
function readFiles(filePaths) {
  const contents = [];
  for (const path of filePaths) {
    const content = fs.readFileSync(path, 'utf8'); // Blocks event loop
    contents.push(content);
  }
  return contents;
}

// Inefficiency: Repeated regex compilation
function validateInputs(inputs) {
  const results = [];
  for (const input of inputs) {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/; // Recompiled each iteration
    results.push(regex.test(input));
  }
  return results;
}

// Inefficiency: Unnecessary Promise wrapping
function getData() {
  return new Promise((resolve) => {
    resolve(db.query('SELECT * FROM users')); // Already returns Promise
  });
}

// Inefficiency: Blocking event loop with CPU-intensive task
function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2); // No memoization, exponential time
}

// Inefficiency: Creating large arrays unnecessarily
function generateReport(data) {
  const temp = new Array(data.length * 2).fill(0); // Over-allocated, mostly unused
  return data.map(item => ({ ...item, processed: true }));
}

module.exports = {
  findCommonElements, filterUnique, buildReport, processMatrix,
  mergeObjects, readFiles, validateInputs, getData, fibonacci, generateReport
};
