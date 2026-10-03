// Bug: Type coercion issues
function add(a, b) {
  return a + b; // "1" + 1 = "11" instead of 2
}

function isPositive(num) {
  return num > 0; // -0 > 0 is false, NaN > 0 is false
}

// Bug: Array method misuse
const items = [1, 2, 3, 4, 5];
const found = items.find(item => item === 3); // Returns 3, not index
const index = items.findIndex(item => item === 3); // Correct for index

// Bug: Object reference confusion
function updateUser(user) {
  const updated = user;
  updated.name = 'New Name'; // Mutates original user object
  return updated;
}

// Bug: parseInt radix missing
function parseId(str) {
  return parseInt(str); // "08" parsed as octal in old JS
}

// Bug: for...in on array (includes prototype properties)
function sumArray(arr) {
  let sum = 0;
  for (let key in arr) {
    sum += arr[key]; // Iterates over prototype properties too
  }
  return sum;
}

// Bug: Missing hasOwnProperty check
function cloneObject(obj) {
  const clone = {};
  for (let key in obj) {
    clone[key] = obj[key]; // Includes inherited properties
  }
  return clone;
}

// Bug: Arrow function with arguments object
const arrowFunc = () => {
  return arguments; // arguments is from outer scope, not this function
};

// Bug: Implicit global variable
function createGlobal() {
  temp = 10; // Implicit global, no var/let/const
}

module.exports = { add, isPositive, updateUser, parseId, sumArray, cloneObject, createGlobal };
