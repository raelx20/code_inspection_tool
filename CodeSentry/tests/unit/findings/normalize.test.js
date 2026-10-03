const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  normalize,
  registerNormalizer,
  normalizeEslint,
  normalizeBandit,
  normalizeSemgrep,
  normalizeRuff,
  normalizeTypescript,
} = require('../../../src/findings/normalize');
const { isValidFinding } = require('../../../src/findings/schema');

describe('Normalization', () => {
  describe('normalizeEslint', () => {
    it('should convert ESLint results to findings', () => {
      const input = [
        {
          filePath: 'src/index.js',
          ruleId: 'no-unused-vars',
          severity: 2,
          message: { message: "'x' is defined but never used" },
          line: 10,
          column: 5,
        },
      ];
      const findings = normalizeEslint(input);
      assert.equal(findings.length, 1);
      assert.ok(isValidFinding(findings[0]));
      assert.equal(findings[0].tool, 'eslint');
      assert.equal(findings[0].file, 'src/index.js');
      assert.equal(findings[0].line, 10);
      assert.equal(findings[0].rule, 'no-unused-vars');
    });

    it('should map error severity to BLOCKER', () => {
      const input = [{ filePath: 'a.js', ruleId: 'rule', severity: 2, message: { message: 'err' }, line: 1 }];
      const findings = normalizeEslint(input);
      assert.equal(findings[0].severity, 'BLOCKER');
    });

    it('should map warning severity to HIGH', () => {
      const input = [{ filePath: 'a.js', ruleId: 'rule', severity: 1, message: { message: 'warn' }, line: 1 }];
      const findings = normalizeEslint(input);
      assert.equal(findings[0].severity, 'HIGH');
    });

    it('should skip severity 0 (off)', () => {
      const input = [{ filePath: 'a.js', ruleId: 'rule', severity: 0, message: { message: 'off' }, line: 1 }];
      const findings = normalizeEslint(input);
      assert.equal(findings.length, 0);
    });

    it('should return empty array for non-array input', () => {
      assert.deepEqual(normalizeEslint(null), []);
      assert.deepEqual(normalizeEslint(undefined), []);
    });
  });

  describe('normalizeBandit', () => {
    it('should convert Bandit results to findings', () => {
      const input = [
        {
          filename: 'app.py',
          test_id: 'B307',
          issue_severity: 'HIGH',
          issue_confidence: 'HIGH',
          issue_text: 'Use of exec',
          line_number: 42,
        },
      ];
      const findings = normalizeBandit(input);
      assert.equal(findings.length, 1);
      assert.ok(isValidFinding(findings[0]));
      assert.equal(findings[0].tool, 'bandit');
      assert.equal(findings[0].category, 'security');
      assert.equal(findings[0].severity, 'HIGH');
      assert.equal(findings[0].file, 'app.py');
      assert.equal(findings[0].line, 42);
      assert.equal(findings[0].rule, 'B307');
      assert.equal(findings[0].confidence, 'high');
    });

    it('should map medium severity correctly', () => {
      const input = [{ filename: 'a.py', test_id: 'B101', issue_severity: 'MEDIUM', issue_confidence: 'LOW', issue_text: 'assert', line_number: 5 }];
      const findings = normalizeBandit(input);
      assert.equal(findings[0].severity, 'MEDIUM');
      assert.equal(findings[0].confidence, 'low');
    });

    it('should return empty array for non-array input', () => {
      assert.deepEqual(normalizeBandit(null), []);
    });
  });

  describe('normalizeSemgrep', () => {
    it('should convert Semgrep results to findings', () => {
      const input = [
        {
          path: 'src/app.js',
          check_id: 'javascript.lang.security.audit.eval',
          severity: 'HIGH',
          message: 'Detected eval',
          start: { line: 15, col: 1 },
        },
      ];
      const findings = normalizeSemgrep(input);
      assert.equal(findings.length, 1);
      assert.ok(isValidFinding(findings[0]));
      assert.equal(findings[0].tool, 'semgrep');
      assert.equal(findings[0].file, 'src/app.js');
      assert.equal(findings[0].line, 15);
      assert.equal(findings[0].column, 1);
      assert.equal(findings[0].rule, 'javascript.lang.security.audit.eval');
    });

    it('should return empty array for non-array input', () => {
      assert.deepEqual(normalizeSemgrep(undefined), []);
    });
  });

  describe('normalizeRuff', () => {
    it('should convert Ruff results to findings', () => {
      const input = [
        {
          filename: 'main.py',
          code: 'F841',
          message: 'Local variable is assigned to but never used',
          location: { row: 10, column: 5 },
        },
      ];
      const findings = normalizeRuff(input);
      assert.equal(findings.length, 1);
      assert.ok(isValidFinding(findings[0]));
      assert.equal(findings[0].tool, 'ruff');
      assert.equal(findings[0].file, 'main.py');
      assert.equal(findings[0].line, 10);
      assert.equal(findings[0].rule, 'F841');
    });

    it('should map S-prefixed rules to security category', () => {
      const input = [{ filename: 'a.py', code: 'S101', message: 'assert', location: { row: 1, column: 1 } }];
      const findings = normalizeRuff(input);
      assert.equal(findings[0].category, 'security');
    });
  });

  describe('normalizeTypescript', () => {
    it('should convert TypeScript diagnostics to findings', () => {
      const input = [
        {
          code: 2322,
          category: 'error',
          messageText: 'Type string is not assignable',
          file: { fileName: 'src/app.ts' },
          start: { line: 20, character: 5 },
        },
      ];
      const findings = normalizeTypescript(input);
      assert.equal(findings.length, 1);
      assert.ok(isValidFinding(findings[0]));
      assert.equal(findings[0].tool, 'typescript');
      assert.equal(findings[0].rule, 'TS2322');
      assert.equal(findings[0].severity, 'HIGH');
    });
  });

  describe('normalize (dispatcher)', () => {
    it('should dispatch to the correct normalizer', () => {
      const input = [{ filePath: 'a.js', ruleId: 'rule', severity: 1, message: { message: 'msg' }, line: 1 }];
      const findings = normalize('eslint', input);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].tool, 'eslint');
    });

    it('should throw for unknown tool', () => {
      assert.throws(
        () => normalize('unknown-tool', []),
        /No normalizer registered/
      );
    });

    it('should throw with tool name in error message', () => {
      assert.throws(
        () => normalize('mytool', []),
        /No normalizer registered for tool: "mytool"/
      );
    });
  });

  describe('registerNormalizer', () => {
    it('should register a custom normalizer', () => {
      const customNormalizer = (results) => {
        return results.map(r => ({
          id: 'custom-1',
          tool: 'custom',
          category: 'bug',
          severity: 'LOW',
          file: r.file,
          line: r.line,
          column: null,
          rule: 'custom-rule',
          message: r.message,
          suggestedFix: null,
          confidence: 'medium',
          fingerprint: 'fp-1',
          source: { tool: 'custom', ruleId: 'custom-rule', analyzerVersion: null },
        }));
      };
      registerNormalizer('custom', customNormalizer);
      const findings = normalize('custom', [{ file: 'a.js', line: 1, message: 'test' }]);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].tool, 'custom');
    });

    it('should throw if normalizer is not a function', () => {
      assert.throws(
        () => registerNormalizer('bad', 'not-a-function'),
        /must be a function/
      );
    });
  });

  describe('failure handling', () => {
    it('should handle malformed ESLint results gracefully', () => {
      const input = [
        { filePath: 'a.js' },
        { filePath: 'b.js', ruleId: 'rule', severity: 1, message: { message: 'ok' }, line: 5 },
      ];
      const findings = normalizeEslint(input);
      assert.ok(findings.length >= 1, 'should still produce findings from valid entries');
    });

    it('should handle empty results from any tool', () => {
      assert.deepEqual(normalizeEslint([]), []);
      assert.deepEqual(normalizeBandit([]), []);
      assert.deepEqual(normalizeSemgrep([]), []);
      assert.deepEqual(normalizeRuff([]), []);
      assert.deepEqual(normalizeTypescript([]), []);
    });
  });
});
