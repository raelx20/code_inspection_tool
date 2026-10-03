'use strict';

/**
 * Built-in Custom Security Analyzer for CodeSentry
 *
 * Provides native, fast deterministic security analysis for JavaScript,
 * TypeScript, and Python without requiring external tools (Semgrep/Bandit).
 */

function analyzeSecurity(filePath, content) {
  const findings = [];
  const lines = content.split('\n');
  const ext = (filePath.split('.').pop() || '').toLowerCase();
  const isPython = ext === 'py' || ext === 'pyw';
  const isJsTs = ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'].includes(ext);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim();

    // Skip empty lines or pure comment lines
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#')) {
      continue;
    }

    if (isJsTs) {
      checkJsSqlInjection(line, lineNum, findings, filePath);
      checkJsEval(line, lineNum, findings, filePath);
      checkJsCommandInjection(line, lineNum, findings, filePath);
      checkJsPathTraversal(line, lineNum, findings, filePath);
      checkJsCryptoIssues(line, lineNum, findings, filePath);
      checkJsXssAndPrototype(line, lineNum, findings, filePath);
    }

    if (isPython) {
      checkPySqlInjection(line, lineNum, findings, filePath);
      checkPyEvalExec(line, lineNum, findings, filePath);
      checkPyCommandInjection(line, lineNum, findings, filePath);
      checkPyCryptoIssues(line, lineNum, findings, filePath);
    }

    // Common rules (both JS/TS and Python)
    checkHardcodedSecrets(line, lineNum, findings, filePath);
  }

  return findings;
}

// ── JavaScript / TypeScript Security Rules ───────────────────────────────────

function checkJsSqlInjection(line, lineNum, findings, filePath) {
  // Query with template literals: db.query(`SELECT ... ${...}`) or const query = `SELECT ... ${...}`
  if (/(?:db|connection|pool|client)\.(?:query|execute)\s*\(\s*`[^`]*\$\{[^}]+\}/i.test(line) ||
      /(?:const|let|var)\s+\w+\s*=\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^`]*\$\{[^}]+\}/i.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'sql-injection-template',
      message: 'Direct variable interpolation in SQL query permits SQL injection',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Use parameterized queries (e.g. $1, ?, or named parameters) instead of string interpolation.',
    });
    return;
  }

  // Query with string concatenation: db.query("SELECT ... " + id) or const sql = "SELECT ... " + id
  if (/(?:db|connection|pool|client)\.(?:query|execute)\s*\(\s*(?:['"].*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*?['"]\s*\+|\b(?:sql|query)\b\s*\+)/i.test(line) ||
      /(?:const|let|var)\s+\w+\s*=\s*['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^'"]*['"]\s*\+/i.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'sql-injection-concat',
      message: 'SQL query constructed via string concatenation allows SQL injection',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Replace string concatenation with parameterized prepared statements.',
    });
  }
}

function checkJsEval(line, lineNum, findings, filePath) {
  // eval(expr)
  if (/\beval\s*\([^)]+\)/.test(line) && !line.includes('//') && !line.includes('typeof eval')) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'code-injection-eval',
      message: 'Direct invocation of eval() allows arbitrary code execution',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Use JSON.parse(), a safe parser, or dedicated math evaluation library instead of eval().',
    });
    return;
  }

  // new Function(...)
  if (/new\s+Function\s*\(/.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'code-injection-function',
      message: 'Dynamic Function constructor constructor permits arbitrary code execution',
      severity: 'HIGH',
      category: 'security',
      suggestedFix: 'Avoid dynamic Function constructor; refactor logic to static functions.',
    });
  }
}

function checkJsCommandInjection(line, lineNum, findings, filePath) {
  // child_process.exec with template string or concatenation
  if (/(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}|['"][^'"]*['"]\s*\+)/.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'command-injection',
      message: 'child_process.exec() with concatenated user input permits OS command injection',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Use execFile() or spawn() with discrete argument arrays without a shell.',
    });
  }
}

function checkJsPathTraversal(line, lineNum, findings, filePath) {
  // path.join with req.params or req.query directly in sendFile or download
  if (/(?:res\.sendFile|res\.download|fs\.readFile|fs\.readFileSync)\s*\(\s*(?:path\.join\([^)]*(?:req\.|params\.|query\.)|\`\/[^\`]*\$\{[^}]+\}\`)/i.test(line) ||
      /(?:res\.sendFile|res\.download)\s*\(\s*(?:filePath|file)\s*\)/i.test(line) && line.includes('file')) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'path-traversal',
      message: 'Potential directory traversal vulnerability in file path resolution',
      severity: 'HIGH',
      category: 'security',
      suggestedFix: 'Sanitize filename and ensure resolved path resides strictly within the allowed base directory.',
    });
  }
}

function checkJsCryptoIssues(line, lineNum, findings, filePath) {
  // Weak hashes (MD5, SHA1)
  if (/crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/i.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'weak-crypto-hash',
      message: 'Weak or broken cryptographic hashing algorithm (MD5/SHA1)',
      severity: 'MEDIUM',
      category: 'security',
      suggestedFix: 'Upgrade to a collision-resistant hash like SHA-256 (sha256) or SHA-512.',
    });
  }
}

function checkJsXssAndPrototype(line, lineNum, findings, filePath) {
  // Prototype pollution
  if (/\[\s*['"]__proto__['"]\s*\]|\.__proto__\s*=/.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'prototype-pollution',
      message: 'Direct modification of __proto__ can lead to prototype pollution vulnerabilities',
      severity: 'HIGH',
      category: 'security',
      suggestedFix: 'Use Map or Object.create(null) for unconstrained key-value lookups.',
    });
  }

  // dangerouslySetInnerHTML
  if (/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'xss-dangerously-set-inner-html',
      message: 'dangerouslySetInnerHTML with unsanitized content exposes the application to Cross-Site Scripting (XSS)',
      severity: 'HIGH',
      category: 'security',
      suggestedFix: 'Sanitize HTML content using DOMPurify before rendering, or use text bindings.',
    });
  }
}

// ── Python Security Rules ───────────────────────────────────────────────────

function checkPySqlInjection(line, lineNum, findings, filePath) {
  // cursor.execute(f"SELECT ... {var}") or query = f"SELECT ... {var}"
  if (/(?:cursor|db|conn|connection)\.execute\s*\(\s*f['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^'"]*\{[^}]+\}/i.test(line) ||
      /^\s*(?:\w+\s*=\s*)?f['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^'"]*\{[^}]+\}/i.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'py-sql-injection-fstring',
      message: 'Python f-string formatted SQL query allows SQL injection',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Pass parameters as a tuple in cursor.execute(sql, (param1, param2)).',
    });
    return;
  }

  // cursor.execute("SELECT ... %s" % var) or sql = "SELECT ... " + var
  if (/(?:cursor|db|conn|connection)\.execute\s*\(\s*['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^'"]*['"]\s*(?:\%|\+)/i.test(line) ||
      /^\s*\w+\s*=\s*['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^'"]*['"]\s*(?:\%|\+)/i.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'py-sql-injection-concat',
      message: 'String concatenation or % formatting in SQL statement permits SQL injection',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Use parameterized SQL syntax: cursor.execute("SELECT ... WHERE id = %s", (user_id,)).',
    });
  }
}

function checkPyEvalExec(line, lineNum, findings, filePath) {
  // eval(...) or exec(...)
  if (/\b(?:eval|exec)\s*\([^)]+\)/.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'py-code-injection',
      message: 'Usage of eval() or exec() executes unvalidated code dynamically',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Use ast.literal_eval() for safe data parsing, or avoid dynamic evaluation.',
    });
  }
}

function checkPyCommandInjection(line, lineNum, findings, filePath) {
  // os.system or subprocess with shell=True
  if (/\bos\.system\s*\([^)]+\)/.test(line) ||
      /\bsubprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True[^)]*\)/.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'py-command-injection',
      message: 'Command execution via os.system or shell=True exposes the shell to command injection',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Pass arguments as a list without shell=True: subprocess.run(["command", arg1, arg2]).',
    });
  }
}

function checkPyCryptoIssues(line, lineNum, findings, filePath) {
  if (/hashlib\.(?:md5|sha1)\s*\(/.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'py-weak-crypto-hash',
      message: 'Insecure MD5/SHA1 hash detected in Python cryptography',
      severity: 'MEDIUM',
      category: 'security',
      suggestedFix: 'Upgrade to hashlib.sha256() or hashlib.sha512().',
    });
  }
}

// ── Common Security Rules ───────────────────────────────────────────────────

function checkHardcodedSecrets(line, lineNum, findings, filePath) {
  // AWS Access Key ID: AKIA[0-9A-Z]{16}
  if (/\b(AKIA[0-9A-Z]{16})\b/.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'hardcoded-aws-key',
      message: 'Hardcoded AWS Access Key ID detected',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Store credentials in environment variables or use an IAM secret store.',
    });
    return;
  }

  // GitHub Personal Access Token: ghp_[a-zA-Z0-9]{36}
  if (/\bghp_[0-9a-zA-Z]{36}\b/.test(line)) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'hardcoded-github-token',
      message: 'Hardcoded GitHub Personal Access Token detected',
      severity: 'BLOCKER',
      category: 'security',
      suggestedFix: 'Revoke this token immediately and reference it via process.env.GITHUB_TOKEN.',
    });
    return;
  }

  // Generic hardcoded secrets: const API_KEY = '...' or password = '...'
  const secretPattern = /(?:(?:API|SECRET|AUTH|ACCESS|PRIVATE)[_-]?(?:KEY|TOKEN|SECRET)|(?:DB_|DATABASE_)PASSWORD)\s*[:=]\s*['"]([^'"]{6,})['"]/i;
  const match = line.match(secretPattern);
  if (match && !line.includes('process.env') && !line.includes('os.environ') && !line.includes('your-') && !line.includes('placeholder')) {
    findings.push({
      file: filePath,
      line: lineNum,
      column: null,
      rule: 'hardcoded-secret',
      message: 'Potential hardcoded secret or credential detected in source code',
      severity: 'HIGH',
      category: 'security',
      suggestedFix: 'Move sensitive credentials to a protected .env file or environment variable.',
    });
  }
}

module.exports = {
  analyzeSecurity,
};
