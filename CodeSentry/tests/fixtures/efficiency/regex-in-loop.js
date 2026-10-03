function validateInputs(inputs) {
  const results = [];
  // Regex compiled inside loop
  for (let i = 0; i < inputs.length; i++) {
    const regex = new RegExp(`^${inputs[i].pattern}$`);
    results.push(regex.test(inputs[i].value));
  }
  return results;
}

function searchLines(lines, patterns) {
  const matches = [];
  // new RegExp in nested loop
  for (const line of lines) {
    for (const pattern of patterns) {
      const re = new RegExp(pattern);
      if (re.test(line)) {
        matches.push(line);
      }
    }
  }
  return matches;
}

module.exports = { validateInputs, searchLines };
