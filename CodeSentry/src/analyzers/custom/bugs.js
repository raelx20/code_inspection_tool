// ── Python built-in names that should never be flagged as undefined ──
const PYTHON_BUILTINS = new Set([
  'print', 'len', 'range', 'int', 'str', 'float', 'bool', 'list', 'dict',
  'set', 'tuple', 'type', 'isinstance', 'issubclass', 'id', 'input', 'open',
  'abs', 'all', 'any', 'bin', 'chr', 'dir', 'divmod', 'enumerate', 'eval',
  'exec', 'filter', 'format', 'frozenset', 'getattr', 'globals', 'hasattr',
  'hash', 'help', 'hex', 'iter', 'locals', 'map', 'max', 'min', 'next',
  'object', 'oct', 'ord', 'pow', 'property', 'repr', 'reversed', 'round',
  'setattr', 'slice', 'sorted', 'staticmethod', 'sum', 'super', 'vars',
  'zip', 'True', 'False', 'None', 'NotImplementedError', 'Exception',
  'ValueError', 'TypeError', 'KeyError', 'IndexError', 'AttributeError',
  'RuntimeError', 'ImportError', 'OSError', 'IOError', 'FileNotFoundError',
  'StopIteration', 'GeneratorExit', 'SystemExit', 'BaseException',
  '__name__', '__file__', '__doc__', '__all__', '__init__', 'self', 'cls',
]);

// ── Well-known Flask/Django framework functions ──
const FLASK_FUNCTIONS = new Set([
  'Flask', 'request', 'jsonify', 'send_file', 'send_from_directory',
  'redirect', 'url_for', 'render_template', 'abort', 'make_response',
  'Response', 'Blueprint', 'g', 'session', 'flash', 'current_app',
]);

const DJANGO_FUNCTIONS = new Set([
  'HttpResponse', 'JsonResponse', 'render', 'redirect', 'get_object_or_404',
  'get_list_or_404', 'reverse', 'reverse_lazy',
]);

function analyzeBugs(filePath, content) {
  const findings = [];
  const lines = content.split('\n');
  const isPy = (filePath || '').endsWith('.py') || (filePath || '').endsWith('.pyw');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim();

    checkEmptyCatch(lines, i, findings, filePath);
    checkSwallowedError(trimmed, lineNum, findings, filePath);
    checkAssignmentInCondition(trimmed, lineNum, findings, filePath);
    checkLooseEquality(trimmed, lineNum, findings, filePath);
    checkOffByOne(trimmed, lineNum, findings, filePath);
    checkUnreachableCode(trimmed, lines, i, findings, filePath);
    checkAlwaysTrueFalse(trimmed, lineNum, findings, filePath);
    checkDuplicateCondition(lines, i, findings, filePath);
  }

  // ── Whole-file diagnostics (matches VS Code / Pylance / Ruff) ──
  if (isPy) {
    checkPyUndefinedVariables(lines, findings, filePath, content);
    checkPyUnusedImports(lines, findings, filePath, content);
    checkPyMissingFrameworkImports(lines, findings, filePath, content);
  }

  return findings;
}

function checkEmptyCatch(lines, lineIndex, findings, filePath) {
  const line = lines[lineIndex];
  const lineNum = lineIndex + 1;

  const catchMatch = line.match(/catch\s*(?:\([^)]*\))?\s*\{\s*$/);
  if (!catchMatch) return;

  let braceCount = 1;
  const bodyLines = [];

  for (let j = lineIndex + 1; j < Math.min(lineIndex + 10, lines.length); j++) {
    const bodyLine = lines[j];
    braceCount += (bodyLine.match(/{/g) || []).length;
    braceCount -= (bodyLine.match(/}/g) || []).length;
    bodyLines.push(bodyLine.trim());

    if (braceCount <= 0) {
      const bodyContent = bodyLines.join(' ')
        .replace(/\/\/.*$/gm, '')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .trim();

      if (!bodyContent || bodyContent === '}') {
        findings.push({
          file: filePath,
          line: lineNum,
          column: null,
          rule: 'empty-catch',
          message: 'Empty catch block swallows errors silently',
          severity: 'HIGH',
          category: 'bugs',
          suggestedFix: 'Add error handling, logging, or rethrow the error.',
        });
      }
      return;
    }
  }
}

function checkSwallowedError(line, lineNum, findings, filePath) {
  const patterns = [
    /catch\s*\([^)]*\)\s*\{\s*(?:\/\/.*|\/\*.*\*\/\s*)*\}/,
    /catch\s*\([^)]*\)\s*\{\s*\/\/\s*(?:ignore|swallow|suppress|silent|noop|do nothing)/i,
  ];

  for (const pattern of patterns) {
    if (pattern.test(line)) {
      findings.push({
        file: filePath,
        line: lineNum,
        column: null,
        rule: 'swallowed-error',
        message: 'Error is caught but appears to be silently ignored',
        severity: 'MEDIUM',
        category: 'bugs',
        suggestedFix: 'Log the error or handle it meaningfully.',
      });
      return;
    }
  }
}

function checkAssignmentInCondition(line, lineNum, findings, filePath) {
  const isPy = (filePath || '').endsWith('.py') || (filePath || '').endsWith('.pyw');
  const patterns = isPy ? [
    /(?:if|elif|while)\s+[a-zA-Z_]\w*\s*=[^=!<>\n:]+/,
  ] : [
    /if\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*=[^=!]/,
    /while\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*=[^=!]/,
    /if\s*\(\s*\([^)]*\b[a-zA-Z_$][a-zA-Z0-9_$]*\s*=[^=!]/,
  ];

  for (const pattern of patterns) {
    if (pattern.test(line)) {
      const eqSym = isPy ? '==' : '===';
      findings.push({
        file: filePath,
        line: lineNum,
        column: null,
        rule: 'assignment-in-condition',
        message: `Assignment in condition — likely should be comparison (${eqSym})`,
        severity: 'HIGH',
        category: 'bugs',
        suggestedFix: `Use ${eqSym} for comparison, or move assignment outside the condition.`,
      });
      return;
    }
  }
}

function checkLooseEquality(line, lineNum, findings, filePath) {
  const isPy = (filePath || '').endsWith('.py') || (filePath || '').endsWith('.pyw');
  if (isPy) {
    // In Python, == is standard equality, NOT loose equality.
    // Only flag comparisons to None, True, False (PEP8 E711, E712)
    const pyMatch = line.match(/\b([a-zA-Z_]\w*)\s*(==|!=)\s*(None|True|False)\b/) ||
                    line.match(/\b(None|True|False)\s*(==|!=)\s*([a-zA-Z_]\w*)\b/);
    if (pyMatch) {
      const op = pyMatch[2];
      const target = (pyMatch[3] === 'None' || pyMatch[3] === 'True' || pyMatch[3] === 'False') ? pyMatch[3] : pyMatch[1];
      const isNeg = op === '!=';
      findings.push({
        file: filePath,
        line: lineNum,
        column: null,
        rule: target === 'None' ? 'E711' : 'E712',
        message: `Comparison to ${target} should use '${isNeg ? 'is not' : 'is'}' rather than '${op}'`,
        severity: 'LOW',
        category: 'bugs',
        suggestedFix: `Use 'is ${target}' or 'is not ${target}' for singleton comparison.`,
      });
    }
    return;
  }

  if (line.includes('===')) return;
  if (line.includes('!==')) return;

  const match = line.match(/[^!=<>]==(?!=)/);
  if (match) {
    const context = line.substring(0, 80);
    if (context.includes('//') || context.includes('*')) return;

    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'loose-equality',
      message: 'Loose equality (==) used instead of strict equality (===)',
      severity: 'LOW',
      category: 'bugs',
      suggestedFix: 'Use === or !== for type-safe comparisons.',
    });
  }
}

function checkOffByOne(line, lineNum, findings, filePath) {
  const patterns = [
    /for\s*\([^)]*<=\s*(?:arr|items|data|results|list|elements|values|array)\.length/,
    /for\s*\([^)]*<=\s*(?:str|string|text|input|buffer)\.length/,
    /range\s*\(\s*(?:0\s*,\s*)?len\s*\([^)]+\)\s*\+\s*1\s*\)/,
  ];

  for (const pattern of patterns) {
    if (pattern.test(line)) {
      findings.push({
        file: filePath,
        line: lineNum,
        column: null,
        rule: 'off-by-one',
        message: 'Potential off-by-one loop boundary error',
        severity: 'HIGH',
        category: 'bugs',
        suggestedFix: 'Check loop boundary condition (use < length or range(len(...))).',
      });
      return;
    }
  }
}

function checkUnreachableCode(line, lines, lineIndex, findings, filePath) {
  const lineNum = lineIndex + 1;
  if (!line || line.startsWith('//') || line.startsWith('/*') || line === '}' || line === '{') return;
  if (line.startsWith('@') || /^def\s+/.test(line) || /^class\s+/.test(line) || /^function\s+/.test(line)) return;

  let prevIndex = lineIndex - 1;
  while (prevIndex >= 0) {
    const prevTrimmed = lines[prevIndex].trim();
    if (prevTrimmed === '' || prevTrimmed.startsWith('//') || prevTrimmed.startsWith('/*') || prevTrimmed.startsWith('*')) {
      prevIndex--;
      continue;
    }
    break;
  }
  if (prevIndex < 0) return;
  const prevLine = lines[prevIndex].trim();
  const rawPrevLine = lines[prevIndex];
  const rawCurrLine = lines[lineIndex];

  if (!prevLine) return;

  // Check indentation: if current line is at a lower indentation level than previous line,
  // it has exited the block or function, so it is not unreachable.
  const prevIndent = (rawPrevLine.match(/^(\s*)/)[1] || '').length;
  const currIndent = (rawCurrLine.match(/^(\s*)/)[1] || '').length;
  if (currIndent < prevIndent) return;

  const terminatorPattern = /^(return|throw|break|continue)\b/;
  if (terminatorPattern.test(prevLine) && !prevLine.endsWith('{') && !prevLine.endsWith(',')) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'unreachable-code',
      message: 'Code appears to be unreachable after return/throw/break/continue',
      severity: 'MEDIUM',
      category: 'bugs',
      suggestedFix: 'Remove unreachable code or fix control flow.',
    });
  }
}

function checkAlwaysTrueFalse(line, lineNum, findings, filePath) {
  const patterns = [
    { regex: /if\s*\(\s*true\s*\)/, message: 'Always-true condition (if (true))' },
    { regex: /if\s*\(\s*false\s*\)/, message: 'Always-false condition (if (false))' },
    { regex: /while\s*\(\s*true\s*\)/, msg: 'Infinite loop (while (true)) — verify intentional' },
    { regex: /while\s*\(\s*false\s*\)/, message: 'Dead code — while (false) never executes' },
  ];

  for (const { regex, message, msg } of patterns) {
    if (regex.test(line)) {
      findings.push({
        file: filePath,
        line: lineNum,
        column: null,
        rule: 'always-true-false',
        message: message || msg,
        severity: 'MEDIUM',
        category: 'bugs',
        suggestedFix: 'Review control flow logic.',
      });
      return;
    }
  }
}

function checkDuplicateCondition(lines, lineIndex, findings, filePath) {
  const line = lines[lineIndex].trim();
  const lineNum = lineIndex + 1;

  const ifMatch = line.match(/^if\s*\((.+)\)\s*\{?$/);
  if (!ifMatch) return;

  const condition = ifMatch[1].trim();

  // Check all subsequent if/else-if lines for the same condition
  for (let j = lineIndex + 1; j < Math.min(lineIndex + 100, lines.length); j++) {
    const otherLine = lines[j].trim();

    const otherIfMatch = otherLine.match(/^}?\s*else\s+if\s*\((.+)\)\s*\{?$/);
    if (otherIfMatch) {
      const otherCondition = otherIfMatch[1].trim();
      if (condition === otherCondition) {
        findings.push({
          file: filePath,
          line: lineNum,
          column: null,
          rule: 'duplicate-condition',
          message: 'Duplicate condition in if/else-if chain',
          severity: 'MEDIUM',
          category: 'bugs',
          suggestedFix: 'Remove or consolidate the duplicate branch.',
        });
        return;
      }
      continue;
    }

    // If we hit a closing brace or a non-else-if line at the same indent level, stop
    if (otherLine === '}' || (otherLine.startsWith('if') && !otherLine.startsWith('else'))) break;
  }
}

// ── VS Code / Pylance-Equivalent: Python Undefined Variable Detection (F821) ──
function checkPyUndefinedVariables(lines, findings, filePath, content) {
  // Collect all defined names: imports, assignments, function defs, class defs, decorators, function params
  const definedNames = new Set();

  // Collect imported names
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    // import X, Y
    const importMatch = trimmed.match(/^import\s+(.+)/);
    if (importMatch && !importMatch[1].startsWith('(')) {
      for (const mod of importMatch[1].split(',')) {
        const asMatch = mod.trim().match(/(\w+)(?:\s+as\s+(\w+))?/);
        if (asMatch) definedNames.add(asMatch[2] || asMatch[1]);
      }
    }
    // from X import Y, Z
    const fromMatch = trimmed.match(/^from\s+\S+\s+import\s+(.+)/);
    if (fromMatch) {
      for (const name of fromMatch[1].split(',')) {
        const asMatch = name.trim().match(/(\w+)(?:\s+as\s+(\w+))?/);
        if (asMatch) definedNames.add(asMatch[2] || asMatch[1]);
      }
    }
    // def name(params):
    const defMatch = trimmed.match(/^def\s+(\w+)\s*\(([^)]*)\)/);
    if (defMatch) {
      definedNames.add(defMatch[1]);
      // Add function parameters
      for (const param of defMatch[2].split(',')) {
        const pName = param.trim().replace(/[=:].*/,'').replace(/^\*+/,'').trim();
        if (pName && /^\w+$/.test(pName)) definedNames.add(pName);
      }
    }
    // class name:
    const classMatch = trimmed.match(/^class\s+(\w+)/);
    if (classMatch) definedNames.add(classMatch[1]);
    // Assignment: name = ...
    const assignMatch = trimmed.match(/^(\w+)\s*=/);
    if (assignMatch && !trimmed.startsWith('if ') && !trimmed.startsWith('elif ') && !trimmed.startsWith('while ')) {
      definedNames.add(assignMatch[1]);
    }
    // for name in ...:
    const forMatch = trimmed.match(/^for\s+(\w+)\s+in\b/);
    if (forMatch) definedNames.add(forMatch[1]);
    // with ... as name:
    const withMatch = trimmed.match(/\bas\s+(\w+)\s*:/);
    if (withMatch) definedNames.add(withMatch[1]);
    // @decorator
    const decoMatch = trimmed.match(/^@(\w+)/);
    if (decoMatch) definedNames.add(decoMatch[1]);
  }

  // Scan for function calls and attribute accesses that reference undefined names
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('import ') || trimmed.startsWith('from ') || trimmed.startsWith('def ') || trimmed.startsWith('class ') || trimmed.startsWith('@')) continue;

    // Find standalone identifiers used as function calls or before .method()
    // Pattern: identifier.method(  or  identifier(  at beginning of expression
    const callPatterns = [
      /\b([a-zA-Z_]\w*)\.(?:execute|query|run|send|close|commit|rollback|fetchone|fetchall|cursor|connect)\s*\(/g,
      /\b([a-zA-Z_]\w*)\s*\(/g,
    ];

    for (const pattern of callPatterns) {
      let match;
      while ((match = pattern.exec(trimmed)) !== null) {
        const name = match[1];
        if (definedNames.has(name) || PYTHON_BUILTINS.has(name)) continue;
        // Skip if it looks like a method call on self/cls or a chained attribute
        const before = trimmed.substring(0, match.index);
        if (before.endsWith('.') || before.endsWith('self.') || before.endsWith('cls.')) continue;
        // Skip decorators, string literals, comments
        if (before.includes('#')) continue;

        findings.push({
          file: filePath,
          line: i + 1,
          column: null,
          rule: 'undefined-variable',
          message: `Undefined variable '${name}' — name is not defined in this scope`,
          severity: 'HIGH',
          category: 'bugs',
          suggestedFix: `Define '${name}' or import it (e.g., from a module or framework).`,
        });
        break; // One finding per line to avoid duplicates
      }
    }
  }
}

// ── VS Code / Ruff-Equivalent: Python Unused Import Detection (F401) ──
function checkPyUnusedImports(lines, findings, filePath, content) {
  const imports = []; // { name, line, module }

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();

    // import X
    const importMatch = trimmed.match(/^import\s+(\w+)(?:\s+as\s+(\w+))?$/);
    if (importMatch) {
      imports.push({
        name: importMatch[2] || importMatch[1],
        module: importMatch[1],
        line: i + 1,
      });
      continue;
    }

    // from X import Y, Z
    const fromMatch = trimmed.match(/^from\s+\S+\s+import\s+(.+)/);
    if (fromMatch) {
      for (const name of fromMatch[1].split(',')) {
        const asMatch = name.trim().match(/(\w+)(?:\s+as\s+(\w+))?/);
        if (asMatch) {
          imports.push({
            name: asMatch[2] || asMatch[1],
            module: asMatch[1],
            line: i + 1,
          });
        }
      }
    }
  }

  // Check if each import is used anywhere in the file (outside import lines)
  for (const imp of imports) {
    // Count occurrences of the name in non-import lines
    let usageCount = 0;
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (trimmed.startsWith('import ') || trimmed.startsWith('from ')) continue;
      // Check if the name appears as a word boundary match
      const regex = new RegExp(`\\b${imp.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
      if (regex.test(lines[i])) {
        usageCount++;
      }
    }

    if (usageCount === 0) {
      findings.push({
        file: filePath,
        line: imp.line,
        column: null,
        rule: 'F401',
        message: `'${imp.module}' imported but unused`,
        severity: 'LOW',
        category: 'bugs',
        suggestedFix: `Remove unused import '${imp.module}' or use it in the code.`,
      });
    }
  }
}

// ── VS Code / Pylance-Equivalent: Python Missing Framework Import Detection ──
function checkPyMissingFrameworkImports(lines, findings, filePath, content) {
  // Determine which framework(s) are in use
  const hasFlask = content.includes('from flask') || content.includes('import flask');
  const hasDjango = content.includes('from django') || content.includes('import django');

  // Collect all imported names
  const importedNames = new Set();
  for (const line of lines) {
    const trimmed = line.trim();
    const fromMatch = trimmed.match(/^from\s+\S+\s+import\s+(.+)/);
    if (fromMatch) {
      for (const name of fromMatch[1].split(',')) {
        const asMatch = name.trim().match(/(\w+)(?:\s+as\s+(\w+))?/);
        if (asMatch) importedNames.add(asMatch[2] || asMatch[1]);
      }
    }
    const importMatch = trimmed.match(/^import\s+(\w+)/);
    if (importMatch) importedNames.add(importMatch[1]);
  }

  // Check for framework function usage without import
  const frameworkFns = hasFlask ? FLASK_FUNCTIONS : hasDjango ? DJANGO_FUNCTIONS : null;
  if (!frameworkFns) return;
  const frameworkModule = hasFlask ? 'flask' : 'django.shortcuts';

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('import') || trimmed.startsWith('from')) continue;

    for (const fn of frameworkFns) {
      if (importedNames.has(fn)) continue;
      // Check if the function is called or referenced on this line
      const regex = new RegExp(`\\b${fn}\\b\\s*\\(`);
      if (regex.test(trimmed)) {
        findings.push({
          file: filePath,
          line: i + 1,
          column: null,
          rule: 'missing-import',
          message: `'${fn}' is used but not imported from '${frameworkModule}'`,
          severity: 'HIGH',
          category: 'bugs',
          suggestedFix: `Add '${fn}' to the import statement: from ${frameworkModule} import ..., ${fn}`,
        });
      }
    }
  }
}

module.exports = {
  analyzeBugs,
};
