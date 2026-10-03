'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { AlterationReporter } = require('../../../src/cli/alteration-report');
const { validateSyntax } = require('../../../src/cli/fixer');

describe('AlterationReporter', () => {
  it('should initialize with default options', () => {
    const reporter = new AlterationReporter({ projectPath: '/test/project' });
    assert.strictEqual(reporter.projectPath, '/test/project');
    assert.strictEqual(reporter.entries.length, 0);
  });

  it('should record applied and skipped entries', () => {
    const reporter = new AlterationReporter({ projectPath: '/test/project', model: 'minimax/minimax-m3' });
    reporter.setScanMeta({ totalFindings: 2, startTime: Date.now() - 500 });

    reporter.addEntry({
      file: 'app.py',
      finding: { line: 10, rule: 'F821', message: "Undefined name 'db'" },
      fix: {
        oldSnippet: 'result = db.execute(query)',
        newSnippet: 'result = db.execute(query)',
        explanation: 'Added database mock definition',
      },
      method: 'deterministic',
      status: 'applied',
    });

    reporter.addEntry({
      file: 'app.py',
      finding: { line: 20, rule: 'complex-refactor', message: 'Manual refactor required' },
      status: 'skipped',
      reason: 'Too ambiguous for auto-repair',
    });

    assert.strictEqual(reporter.entries.length, 2);
    const md = reporter.generateMarkdown();
    assert.ok(md.includes('CODE-ALTERATION-REPORT'));
    assert.ok(md.includes('F821'));
    assert.ok(md.includes('Added database mock definition'));
    assert.ok(md.includes('Manual refactor required'));
  });

  it('should write report to CODE-ALTERATION-REPORT.md', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codesentry-rep-'));
    const reporter = new AlterationReporter({ projectPath: tmpDir });
    reporter.addEntry({
      file: 'test.js',
      finding: { line: 1, rule: 'eqeqeq', message: 'Use ===' },
      fix: { oldSnippet: 'a == b', newSnippet: 'a === b', explanation: 'Use strict equality' },
      method: 'deterministic',
      status: 'applied',
    });

    const reportPath = reporter.writeReport();
    assert.ok(fs.existsSync(reportPath));
    const content = fs.readFileSync(reportPath, 'utf8');
    assert.ok(content.includes('CODE-ALTERATION-REPORT'));
    assert.ok(content.includes('a === b'));

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

describe('validateSyntax in fixer.js', () => {
  it('should validate valid JavaScript code', () => {
    const res = validateSyntax('test.js', 'const a = 1; function test() { return a + 2; }');
    assert.strictEqual(res.valid, true);
  });

  it('should reject invalid JavaScript syntax', () => {
    const res = validateSyntax('test.js', 'const a = ; function test(');
    assert.strictEqual(res.valid, false);
    assert.ok(res.error.includes('SyntaxError'));
  });

  it('should validate valid Python code', () => {
    const res = validateSyntax('app.py', 'def hello():\n    return "world"\n');
    assert.strictEqual(res.valid, true);
  });

  it('should reject invalid Python syntax (indentation or syntax error)', () => {
    const res = validateSyntax('app.py', 'def hello(\n    return "world"');
    assert.strictEqual(res.valid, false);
    assert.ok(res.error.includes('SyntaxError'));
  });
});
