function analyzeEfficiency(filePath, content) {
  const isPy = (filePath || '').endsWith('.py') || (filePath || '').endsWith('.pyw');
  if (isPy) {
    // JavaScript AST and brace-syntax checks do not apply to Python code
    return [];
  }

  const findings = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim();

    checkNestedLoopSearch(lines, i, findings, filePath);
    checkStringConcatInLoop(lines, i, findings, filePath);
    checkSyncInAsync(trimmed, lineNum, findings, filePath);
    checkRegexInLoop(lines, i, findings, filePath);
    checkRepeatedArrayTraversal(lines, i, findings, filePath);
  }

  return findings;
}

function checkNestedLoopSearch(lines, lineIndex, findings, filePath) {
  const line = lines[lineIndex];
  const lineNum = lineIndex + 1;

  const isOuterLoop = /^(for|while)\s*\(/.test(line.trim());
  if (!isOuterLoop) return;

  let braceCount = 0;
  let foundInnerLoop = false;
  let foundArraySearch = false;
  let innerLoopLine = 0;

  for (let j = lineIndex + 1; j < Math.min(lineIndex + 30, lines.length); j++) {
    const inner = lines[j].trim();
    braceCount += (inner.match(/{/g) || []).length;
    braceCount -= (inner.match(/}/g) || []).length;

    if (braceCount < 0) break;

    if (!foundInnerLoop && /^(for|while)\s*\(/.test(inner)) {
      foundInnerLoop = true;
      innerLoopLine = j + 1;
    }

    if (foundInnerLoop) {
      const searchPatterns = [
        /\.indexOf\(/,
        /\.includes\(/,
        /\.find\(/,
        /\.findIndex\(/,
        /\.some\(/,
        /\.filter\(/,
        /[!=]==?\s*\w+\[[\w.]+\]/,
      ];

      for (const pattern of searchPatterns) {
        if (pattern.test(inner)) {
          foundArraySearch = true;
          break;
        }
      }

      if (foundArraySearch) break;
    }
  }

  if (foundInnerLoop && foundArraySearch) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'nested-loop-search',
      message: 'O(n\u00B2) pattern: array search method inside nested loop',
      severity: 'MEDIUM',
      category: 'efficiency',
      suggestedFix: 'Use a Set or Map for O(1) lookups instead of repeated array searches.',
    });
  }
}

function checkStringConcatInLoop(lines, lineIndex, findings, filePath) {
  const line = lines[lineIndex];
  const trimmed = line.trim();
  const isLoop = /^(for|while)\s*\(/.test(trimmed);
  if (!isLoop) return;

  const concatPattern = /\+=\s*['"`]/;
  let braceCount = 0;
  let inBody = false;

  for (let j = lineIndex; j < Math.min(lineIndex + 30, lines.length); j++) {
    const bodyLine = lines[j];
    braceCount += (bodyLine.match(/{/g) || []).length;
    braceCount -= (bodyLine.match(/}/g) || []).length;

    if (j > lineIndex && braceCount > 0) inBody = true;
    if (braceCount <= 0 && j > lineIndex) break;

    if (inBody && concatPattern.test(bodyLine)) {
      findings.push({
        file: filePath,
        line: lineIndex + 1,
        column: null,
        rule: 'string-concat-loop',
        message: 'String concatenation with += in loop body may be inefficient',
        severity: 'LOW',
        category: 'efficiency',
        suggestedFix: 'Collect parts in an array and join() at the end.',
      });
      return;
    }
  }
}

function checkSyncInAsync(line, lineNum, findings, filePath) {
  const syncPatterns = [
    /fs\.readFileSync\s*\(/,
    /fs\.writeFileSync\s*\(/,
    /fs\.statSync\s*\(/,
    /fs\.readdirSync\s*\(/,
    /fs\.existsSync\s*\(/,
    /fs\.mkdirSync\s*\(/,
    /fs\.unlinkSync\s*\(/,
  ];

  for (const pattern of syncPatterns) {
    if (pattern.test(line)) {
      findings.push({
        file: filePath,
        line: lineNum,
        column: null,
        rule: 'sync-in-async',
        message: 'Synchronous filesystem call may block the event loop',
        severity: 'MEDIUM',
        category: 'efficiency',
        suggestedFix: 'Use the async variant (fs.promises or fs.promises.*) instead.',
      });
      return;
    }
  }
}

function checkRegexInLoop(lines, lineIndex, findings, filePath) {
  const line = lines[lineIndex];
  const trimmed = line.trim();
  const isLoop = /^(for|while)\s*\(/.test(trimmed);
  if (!isLoop) return;

  let braceCount = 0;
  let inBody = false;

  for (let j = lineIndex; j < Math.min(lineIndex + 30, lines.length); j++) {
    const bodyLine = lines[j];
    braceCount += (bodyLine.match(/{/g) || []).length;
    braceCount -= (bodyLine.match(/}/g) || []).length;

    if (j > lineIndex && braceCount > 0) inBody = true;
    if (braceCount <= 0 && j > lineIndex) break;

    if (inBody && /new\s+RegExp\s*\(/.test(bodyLine)) {
      findings.push({
        file: filePath,
        line: lineIndex + 1,
        column: null,
        rule: 'regex-in-loop',
        message: 'Regex compilation inside loop — compile once outside the loop',
        severity: 'LOW',
        category: 'efficiency',
        suggestedFix: 'Move RegExp creation outside the loop and reuse the compiled regex.',
      });
      return;
    }
  }
}

function checkRepeatedArrayTraversal(lines, lineIndex, findings, filePath) {
  const line = lines[lineIndex];
  const lineNum = lineIndex + 1;

  const arrayMethods = ['.filter(', '.map(', '.reduce(', '.find(', '.some(', '.every('];
  const hasArrayMethod = arrayMethods.some(m => line.includes(m));
  if (!hasArrayMethod) return;

  // Check if same array is traversed multiple times in nearby lines
  const arrayNameMatch = line.match(/(\w+)\.(?:filter|map|reduce|find|some|every)\(/);
  if (!arrayNameMatch) return;

  const arrayName = arrayNameMatch[1];
  let traversalCount = 0;

  for (let j = Math.max(0, lineIndex - 5); j < Math.min(lines.length, lineIndex + 10); j++) {
    if (lines[j].includes(`${arrayName}.filter(`) ||
        lines[j].includes(`${arrayName}.map(`) ||
        lines[j].includes(`${arrayName}.reduce(`) ||
        lines[j].includes(`${arrayName}.find(`)) {
      traversalCount++;
    }
  }

  if (traversalCount >= 3) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'repeated-array-traversal',
      message: `Array "${arrayName}" traversed ${traversalCount} times in close proximity`,
      severity: 'LOW',
      category: 'efficiency',
      suggestedFix: 'Combine multiple traversals into a single pass where possible.',
    });
  }
}

module.exports = {
  analyzeEfficiency,
};
