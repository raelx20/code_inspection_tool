function checkValue(x) {
  // Loose equality: == instead of ===
  if (x == 0) {
    return 'zero';
  }
  
  if (x == '') {
    return 'empty';
  }
  
  if (x == null) {
    return 'null or undefined';
  }
  
  return 'other';
}

function compareIds(id1, id2) {
  // Comparing number to string with ==
  if (id1 == id2) {
    return true;
  }
  return false;
}

module.exports = { checkValue, compareIds };
