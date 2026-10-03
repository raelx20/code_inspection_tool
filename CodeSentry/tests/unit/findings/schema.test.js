const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  createFinding,
  isValidFinding,
  generateId,
  generateFingerprint,
  SEVERITIES,
  CATEGORIES,
  TOOLS,
} = require('../../../src/findings/schema');

describe('Finding Schema', () => {
  describe('createFinding', () => {
    it('should create a valid finding with required fields', () => {
      const finding = createFinding({
        tool: 'eslint',
        category: 'bug',
        file: 'src/index.js',
        message: 'Unused variable',
      });

      assert.ok(finding.id, 'should have an id');
      assert.equal(finding.tool, 'eslint');
      assert.equal(finding.category, 'bugs');
      assert.equal(finding.legacyCategory, 'bug');
      assert.equal(finding.severity, 'MEDIUM');
      assert.equal(finding.file, 'src/index.js');
      assert.equal(finding.message, 'Unused variable');
      assert.equal(finding.line, null);
      assert.equal(finding.column, null);
      assert.equal(finding.rule, null);
      assert.equal(finding.suggestedFix, null);
      assert.equal(finding.confidence, 'medium');
      assert.ok(finding.fingerprint, 'should have a fingerprint');
    });

    it('should create a finding with all optional fields', () => {
      const finding = createFinding({
        tool: 'bandit',
        category: 'vulnerability',
        severity: 'HIGH',
        file: 'app.py',
        line: 42,
        column: 10,
        rule: 'B307',
        message: 'Use of exec',
        suggestedFix: 'Use subprocess instead',
        confidence: 'high',
      });

      assert.equal(finding.tool, 'bandit');
      assert.equal(finding.category, 'security');
      assert.equal(finding.legacyCategory, 'vulnerability');
      assert.equal(finding.severity, 'HIGH');
      assert.equal(finding.file, 'app.py');
      assert.equal(finding.line, 42);
      assert.equal(finding.column, 10);
      assert.equal(finding.rule, 'B307');
      assert.equal(finding.message, 'Use of exec');
      assert.equal(finding.suggestedFix, 'Use subprocess instead');
      assert.equal(finding.confidence, 'high');
    });

    it('should generate deterministic ids for same input', () => {
      const f1 = createFinding({ tool: 'eslint', category: 'bug', file: 'a.js', message: 'err1', line: 10 });
      const f2 = createFinding({ tool: 'eslint', category: 'bug', file: 'a.js', message: 'err1', line: 10 });
      assert.equal(f1.id, f2.id);
    });

    it('should generate different ids for different input', () => {
      const f1 = createFinding({ tool: 'eslint', category: 'bug', file: 'a.js', message: 'err1', line: 10 });
      const f2 = createFinding({ tool: 'eslint', category: 'bug', file: 'b.js', message: 'err1', line: 10 });
      assert.notEqual(f1.id, f2.id);
    });

    it('should generate fingerprints based on file, line, category', () => {
      const f1 = createFinding({ tool: 'eslint', category: 'bug', file: 'a.js', message: 'msg1', line: 10 });
      const f2 = createFinding({ tool: 'semgrep', category: 'bug', file: 'a.js', message: 'msg2', line: 10 });
      assert.equal(f1.fingerprint, f2.fingerprint, 'same file+line+category should produce same fingerprint');
    });

    it('should generate different fingerprints for different categories', () => {
      const f1 = createFinding({ tool: 'eslint', category: 'bug', file: 'a.js', message: 'msg1', line: 10 });
      const f2 = createFinding({ tool: 'eslint', category: 'vulnerability', file: 'a.js', message: 'msg1', line: 10 });
      assert.notEqual(f1.fingerprint, f2.fingerprint);
    });

    it('should coerce line and column to numbers', () => {
      const finding = createFinding({
        tool: 'eslint',
        category: 'bug',
        file: 'a.js',
        message: 'msg',
        line: '15',
        column: '3',
      });
      assert.equal(finding.line, 15);
      assert.equal(finding.column, 3);
    });

    it('should throw on missing tool', () => {
      assert.throws(
        () => createFinding({ category: 'bug', file: 'a.js', message: 'msg' }),
        /Invalid tool/
      );
    });

    it('should throw on invalid tool', () => {
      assert.throws(
        () => createFinding({ tool: 'unknown', category: 'bug', file: 'a.js', message: 'msg' }),
        /Invalid tool/
      );
    });

    it('should throw on missing category', () => {
      assert.throws(
        () => createFinding({ tool: 'eslint', file: 'a.js', message: 'msg' }),
        /Invalid category/
      );
    });

    it('should throw on invalid category', () => {
      assert.throws(
        () => createFinding({ tool: 'eslint', category: 'invalid', file: 'a.js', message: 'msg' }),
        /Invalid category/
      );
    });

    it('should throw on missing file', () => {
      assert.throws(
        () => createFinding({ tool: 'eslint', category: 'bug', message: 'msg' }),
        /file path/
      );
    });

    it('should throw on missing message', () => {
      assert.throws(
        () => createFinding({ tool: 'eslint', category: 'bug', file: 'a.js' }),
        /message/
      );
    });

    it('should throw on invalid severity', () => {
      assert.throws(
        () => createFinding({ tool: 'eslint', category: 'bug', file: 'a.js', message: 'msg', severity: 'CRITICAL' }),
        /Invalid severity/
      );
    });

    it('should accept all valid severities', () => {
      for (const sev of SEVERITIES) {
        const f = createFinding({ tool: 'eslint', category: 'bug', file: 'a.js', message: 'msg', severity: sev });
        assert.equal(f.severity, sev);
      }
    });

    it('should accept all valid categories', () => {
      for (const cat of CATEGORIES) {
        const f = createFinding({ tool: 'eslint', category: cat, file: 'a.js', message: 'msg' });
        assert.ok(CATEGORIES.includes(f.category), `Category ${f.category} should be valid`);
      }
    });

    it('should accept all valid tools', () => {
      for (const t of TOOLS) {
        const f = createFinding({ tool: t, category: 'bug', file: 'a.js', message: 'msg' });
        assert.equal(f.tool, t);
      }
    });
  });

  describe('isValidFinding', () => {
    it('should return true for valid finding', () => {
      const f = createFinding({ tool: 'eslint', category: 'bug', file: 'a.js', message: 'msg' });
      assert.ok(isValidFinding(f));
    });

    it('should return false for null', () => {
      assert.equal(isValidFinding(null), false);
    });

    it('should return false for non-object', () => {
      assert.equal(isValidFinding('string'), false);
    });

    it('should return false for missing required fields', () => {
      assert.equal(isValidFinding({ id: '123' }), false);
    });
  });

  describe('generateId', () => {
    it('should produce consistent output', () => {
      const id1 = generateId('eslint', 'a.js', 10, 'no-unused-vars');
      const id2 = generateId('eslint', 'a.js', 10, 'no-unused-vars');
      assert.equal(id1, id2);
    });

    it('should produce 16-char hex string', () => {
      const id = generateId('eslint', 'a.js', 10, 'rule');
      assert.equal(id.length, 16);
      assert.match(id, /^[0-9a-f]{16}$/);
    });
  });

  describe('generateFingerprint', () => {
    it('should produce consistent output', () => {
      const fp1 = generateFingerprint('a.js', 10, 'bug');
      const fp2 = generateFingerprint('a.js', 10, 'bug');
      assert.equal(fp1, fp2);
    });

    it('should differ when category changes', () => {
      const fp1 = generateFingerprint('a.js', 10, 'bug');
      const fp2 = generateFingerprint('a.js', 10, 'vulnerability');
      assert.notEqual(fp1, fp2);
    });
  });
});
