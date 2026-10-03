function analyzeResources(filePath, content) {
  const findings = [];
  const lines = content.split('\n');
  const fullContent = content;
  const isPy = (filePath || '').endsWith('.py') || (filePath || '').endsWith('.pyw');

  if (isPy) {
    checkPythonOpenNoWith(lines, findings, filePath);
    checkUnboundedCache(fullContent, lines, findings, filePath);
  } else {
    checkSetIntervalNoClear(fullContent, lines, findings, filePath);
    checkAddEventListenerNoRemove(fullContent, lines, findings, filePath);
    checkStreamNoClose(fullContent, lines, findings, filePath);
    checkUnboundedCache(fullContent, lines, findings, filePath);
    checksetTimeoutAccumulation(lines, findings, filePath);
  }

  return findings;
}

function checkSetIntervalNoClear(content, lines, findings, filePath) {
  const intervalCalls = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = line.match(/setInterval\s*\(/);
    if (match) {
      intervalCalls.push({ line: i + 1, col: match.index + 1 });
    }
  }

  for (const call of intervalCalls) {
    const hasClear = content.includes('clearInterval(') ||
                     content.includes('clearTimeout(');

    if (!hasClear) {
      findings.push({
        file: filePath,
        line: call.line,
        column: call.col,
        rule: 'setinterval-no-clear',
        message: 'setInterval called without corresponding clearInterval — potential resource leak',
        severity: 'HIGH',
        category: 'resources',
        suggestedFix: 'Store the interval ID and call clearInterval() when the interval is no longer needed.',
      });
    }
  }
}

function checkAddEventListenerNoRemove(content, lines, findings, filePath) {
  const addCalls = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = line.match(/\.addEventListener\s*\(/);
    if (match) {
      addCalls.push({ line: i + 1, col: match.index + 1 });
    }
  }

  for (const call of addCalls) {
    const hasRemove = content.includes('.removeEventListener(');
    if (!hasRemove) {
      findings.push({
        file: filePath,
        line: call.line,
        column: call.col,
        rule: 'listener-no-remove',
        message: 'Event listener added without removeEventListener — potential memory leak',
        severity: 'MEDIUM',
        category: 'resources',
        suggestedFix: 'Store the listener reference and call removeEventListener() during cleanup.',
      });
    }
  }
}

function checkStreamNoClose(content, lines, findings, filePath) {
  const streamPatterns = [
    /fs\.createReadStream\s*\(/,
    /fs\.createWriteStream\s*\(/,
  ];

  const codeLines = lines.filter(l => {
    const t = l.trim();
    return !t.startsWith('//') && !t.startsWith('/*') && !t.startsWith('*');
  });
  const codeContent = codeLines.join('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of streamPatterns) {
      const match = line.match(pattern);
      if (match) {
        const hasClose = codeContent.includes('.close(') ||
                         codeContent.includes('.destroy(');

        if (!hasClose) {
          findings.push({
            file: filePath,
            line: i + 1,
            column: match.index + 1,
            rule: 'stream-no-close',
            message: 'Stream created without explicit close/destroy — potential resource leak',
            severity: 'MEDIUM',
            category: 'resources',
            suggestedFix: 'Ensure stream is closed in a finally block or error handler.',
          });
        }
        break;
      }
    }
  }
}

function checkPythonOpenNoWith(lines, findings, filePath) {
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (/^open\s*\(/.test(trimmed) || /=\s*open\s*\(/.test(trimmed)) {
      const isInWith = /^\s+/.test(line) && i > 0 && /with\s+/.test(lines[i - 1]);
      const hasWith = trimmed.startsWith('with ');

      if (!isInWith && !hasWith) {
        const hasClose = lines.some((l, idx) =>
          idx > i && idx < i + 20 && /\.close\(\)/.test(l)
        );

        if (!hasClose) {
          findings.push({
            file: filePath,
            line: i + 1,
            column: null,
            rule: 'py-open-no-with',
            message: 'File opened without "with" statement — resource may not be properly closed',
            severity: 'MEDIUM',
            category: 'resources',
            suggestedFix: 'Use "with open(...) as f:" to ensure automatic file closure.',
          });
        }
      }
    }
  }
}

function checkUnboundedCache(content, lines, findings, filePath) {
  const patterns = [
    { regex: /(?:global|module\.exports|var|let|const)\s+(\w+)\s*=\s*(?:new\s+)?(?:Map|Set|WeakMap)\s*\(/, type: 'Map/Set' },
    { regex: /(?:global|module\.exports|var|let|const)\s+(\w+)\s*=\s*\{\s*\}/, type: 'object' },
  ];

  for (const { regex, type } of patterns) {
    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(regex);
      if (match) {
        const name = match[1];
        const hasEviction = content.includes(`${name}.delete(`) ||
                           content.includes(`${name}.clear(`) ||
                           content.includes('LRU') ||
                           content.includes('lru');

        if (!hasEviction) {
          findings.push({
            file: filePath,
            line: i + 1,
            column: null,
            rule: 'unbounded-cache',
            message: `Collection "${name}" (${type}) has no apparent eviction — potential unbounded growth`,
            severity: 'LOW',
            category: 'resources',
            suggestedFix: 'Add size limits or eviction logic (e.g., LRU cache, max size checks).',
          });
        }
      }
    }
  }
}

function checksetTimeoutAccumulation(lines, findings, filePath) {
  let inLoop = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (/^(for|while)\s*\(/.test(trimmed)) {
      inLoop = true;
    }

    if (inLoop && /setTimeout\s*\(/.test(trimmed)) {
      findings.push({
        file: filePath,
        line: i + 1,
        column: null,
        rule: 'timeout-accumulation',
        message: 'setTimeout inside loop — timers accumulate and may cause resource issues',
        severity: 'MEDIUM',
        category: 'resources',
        suggestedFix: 'Consider using setInterval or scheduling timers outside the loop.',
      });
      inLoop = false;
    }

    if (trimmed === '}' && inLoop) {
      inLoop = false;
    }
  }
}

module.exports = {
  analyzeResources,
};
