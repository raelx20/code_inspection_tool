const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { analyzeBugs } = require('../../src/analyzers/custom/bugs');
const { analyzeEfficiency } = require('../../src/analyzers/custom/efficiency');
const { analyzeResources } = require('../../src/analyzers/custom/resources');
const { analyzeSecurity } = require('../../src/analyzers/custom/security');

const FIXTURES = path.join(__dirname, '..', 'fixtures');

function readFixture(category, filename) {
  const fp = path.join(FIXTURES, category, filename);
  return fs.readFileSync(fp, 'utf-8');
}

describe('Custom Analyzers', () => {
  describe('Bugs Analyzer', () => {
    it('should detect off-by-one errors', () => {
      const content = readFixture('bugs', 'off-by-one.js');
      const findings = analyzeBugs('bugs/off-by-one.js', content);
      const offByOne = findings.filter(f => f.rule === 'off-by-one');
      assert.ok(offByOne.length > 0, 'should detect off-by-one');
      assert.equal(offByOne[0].severity, 'HIGH');
      assert.equal(offByOne[0].category, 'bugs');
    });

    it('should detect empty catch blocks', () => {
      const content = readFixture('bugs', 'empty-catch.js');
      const findings = analyzeBugs('bugs/empty-catch.js', content);
      const emptyCatch = findings.filter(f => f.rule === 'empty-catch');
      assert.ok(emptyCatch.length > 0, 'should detect empty catch');
      assert.equal(emptyCatch[0].severity, 'HIGH');
    });

    it('should detect unreachable code', () => {
      const content = readFixture('bugs', 'unreachable-code.js');
      const findings = analyzeBugs('bugs/unreachable-code.js', content);
      const unreachable = findings.filter(f => f.rule === 'unreachable-code');
      assert.ok(unreachable.length > 0, 'should detect unreachable code');
    });

    it('should detect loose equality', () => {
      const content = readFixture('bugs', 'loose-equality.js');
      const findings = analyzeBugs('bugs/loose-equality.js', content);
      const loose = findings.filter(f => f.rule === 'loose-equality');
      assert.ok(loose.length > 0, 'should detect loose equality');
    });

    it('should detect assignment in condition', () => {
      const content = readFixture('bugs', 'assignment-condition.js');
      const findings = analyzeBugs('bugs/assignment-condition.js', content);
      const assignment = findings.filter(f => f.rule === 'assignment-in-condition');
      assert.ok(assignment.length > 0, 'should detect assignment in condition');
      assert.equal(assignment[0].severity, 'HIGH');
    });

    it('should detect duplicate conditions', () => {
      const content = readFixture('bugs', 'duplicate-condition.js');
      const findings = analyzeBugs('bugs/duplicate-condition.js', content);
      const dupes = findings.filter(f => f.rule === 'duplicate-condition');
      assert.ok(dupes.length > 0, 'should detect duplicate conditions');
    });

    it('should detect Python assignment in condition and off-by-one', () => {
      const content = readFixture('bugs', 'py-bugs.py');
      const findings = analyzeBugs('bugs/py-bugs.py', content);
      const assignment = findings.filter(f => f.rule === 'assignment-in-condition');
      assert.ok(assignment.length >= 2, 'should detect Python assignment in condition');
      const offByOne = findings.filter(f => f.rule === 'off-by-one');
      assert.ok(offByOne.length > 0, 'should detect Python off-by-one');
    });

    it('should not crash on clean code', () => {
      const content = readFixture('clean-project', 'index.js');
      const findings = analyzeBugs('clean-project/index.js', content);
      assert.ok(Array.isArray(findings));
    });
  });

  describe('Efficiency Analyzer', () => {
    it('should detect nested loop search pattern', () => {
      const content = readFixture('efficiency', 'nested-loop-search.js');
      const findings = analyzeEfficiency('efficiency/nested-loop-search.js', content);
      const nested = findings.filter(f => f.rule === 'nested-loop-search');
      assert.ok(nested.length > 0, 'should detect nested loop search');
      assert.equal(nested[0].category, 'efficiency');
    });

    it('should detect string concatenation in loop', () => {
      const content = readFixture('efficiency', 'string-concat-loop.js');
      const findings = analyzeEfficiency('efficiency/string-concat-loop.js', content);
      const stringConcat = findings.filter(f => f.rule === 'string-concat-loop');
      assert.ok(stringConcat.length > 0, 'should detect string concat in loop');
    });

    it('should detect sync calls in async context', () => {
      const content = readFixture('efficiency', 'sync-in-async.js');
      const findings = analyzeEfficiency('efficiency/sync-in-async.js', content);
      const syncCalls = findings.filter(f => f.rule === 'sync-in-async');
      assert.ok(syncCalls.length > 0, 'should detect sync in async');
      assert.equal(syncCalls[0].severity, 'MEDIUM');
    });

    it('should detect regex in loop', () => {
      const content = readFixture('efficiency', 'regex-in-loop.js');
      const findings = analyzeEfficiency('efficiency/regex-in-loop.js', content);
      const regexInLoop = findings.filter(f => f.rule === 'regex-in-loop');
      assert.ok(regexInLoop.length > 0, 'should detect regex in loop');
    });
  });

  describe('Resources Analyzer', () => {
    it('should detect setInterval without clearInterval', () => {
      const content = readFixture('resources', 'no-interval-clear.js');
      const findings = analyzeResources('resources/no-interval-clear.js', content);
      const interval = findings.filter(f => f.rule === 'setinterval-no-clear');
      assert.ok(interval.length > 0, 'should detect setInterval without clearInterval');
      assert.equal(interval[0].severity, 'HIGH');
      assert.equal(interval[0].category, 'resources');
    });

    it('should detect event listeners without cleanup', () => {
      const content = readFixture('resources', 'listener-no-remove.js');
      const findings = analyzeResources('resources/listener-no-remove.js', content);
      const listeners = findings.filter(f => f.rule === 'listener-no-remove');
      assert.ok(listeners.length > 0, 'should detect listener without remove');
    });

    it('should detect streams without close', () => {
      const content = readFixture('resources', 'stream-no-close.js');
      const findings = analyzeResources('resources/stream-no-close.js', content);
      const streams = findings.filter(f => f.rule === 'stream-no-close');
      assert.ok(streams.length > 0, 'should detect stream without close');
    });

    it('should detect Python open without with', () => {
      const content = readFixture('resources', 'py-open-no-with.py');
      const findings = analyzeResources('resources/py-open-no-with.py', content);
      const pyOpen = findings.filter(f => f.rule === 'py-open-no-with');
      assert.ok(pyOpen.length > 0, 'should detect Python open without with');
    });

    it('should detect unbounded cache', () => {
      const content = readFixture('resources', 'unbounded-cache.js');
      const findings = analyzeResources('resources/unbounded-cache.js', content);
      const cache = findings.filter(f => f.rule === 'unbounded-cache');
      assert.ok(cache.length > 0, 'should detect unbounded cache');
    });
  });

  describe('Security Analyzer', () => {
    it('should detect SQL injection in JavaScript', () => {
      const content = readFixture('security', 'js-sqli.js');
      const findings = analyzeSecurity('security/js-sqli.js', content);
      const sqli = findings.filter(f => f.category === 'security' && f.rule.includes('sql-injection'));
      assert.ok(sqli.length > 0, 'should detect SQL injection');
      assert.equal(sqli[0].severity, 'BLOCKER');
    });

    it('should detect eval code injection', () => {
      const content = readFixture('security', 'js-eval.js');
      const findings = analyzeSecurity('security/js-eval.js', content);
      const ev = findings.filter(f => f.rule === 'code-injection-eval');
      assert.ok(ev.length > 0, 'should detect eval injection');
      assert.equal(ev[0].severity, 'BLOCKER');
    });

    it('should detect command injection', () => {
      const content = readFixture('security', 'js-command-inj.js');
      const findings = analyzeSecurity('security/js-command-inj.js', content);
      const cmd = findings.filter(f => f.rule === 'command-injection');
      assert.ok(cmd.length > 0, 'should detect command injection');
    });

    it('should detect path traversal', () => {
      const content = readFixture('security', 'js-path-traversal.js');
      const findings = analyzeSecurity('security/js-path-traversal.js', content);
      const pt = findings.filter(f => f.rule === 'path-traversal');
      assert.ok(pt.length > 0, 'should detect path traversal');
    });

    it('should detect hardcoded secrets', () => {
      const content = readFixture('security', 'js-hardcoded.js');
      const findings = analyzeSecurity('security/js-hardcoded.js', content);
      const sec = findings.filter(f => f.rule.includes('hardcoded'));
      assert.ok(sec.length > 0, 'should detect hardcoded secrets');
    });

    it('should detect Python SQL injection', () => {
      const content = readFixture('security', 'py-sqli.py');
      const findings = analyzeSecurity('security/py-sqli.py', content);
      const sqli = findings.filter(f => f.rule.includes('sql-injection'));
      assert.ok(sqli.length > 0, 'should detect Python SQL injection');
    });

    it('should detect Python eval and exec', () => {
      const content = readFixture('security', 'py-eval.py');
      const findings = analyzeSecurity('security/py-eval.py', content);
      const ev = findings.filter(f => f.rule === 'py-code-injection');
      assert.ok(ev.length > 0, 'should detect Python eval');
    });
  });

  describe('Finding Structure', () => {
    it('all findings should have required fields', () => {
      const files = [
        { cat: 'bugs', file: 'off-by-one.js', analyzer: analyzeBugs },
        { cat: 'efficiency', file: 'nested-loop-search.js', analyzer: analyzeEfficiency },
        { cat: 'resources', file: 'no-interval-clear.js', analyzer: analyzeResources },
      ];

      for (const { cat, file, analyzer } of files) {
        const content = readFixture(cat, file);
        const findings = analyzer(`${cat}/${file}`, content);
        for (const f of findings) {
          assert.ok(f.file, 'finding should have file');
          assert.ok(f.line, 'finding should have line');
          assert.ok(f.rule, 'finding should have rule');
          assert.ok(f.message, 'finding should have message');
          assert.ok(f.severity, 'finding should have severity');
          assert.ok(f.category, 'finding should have category');
        }
      }
    });
  });
});
