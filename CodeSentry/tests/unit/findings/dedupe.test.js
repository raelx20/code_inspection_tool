const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { deduplicate, keepHighestSeverity, getDuplicateGroups } = require('../../../src/findings/dedupe');
const { createFinding } = require('../../../src/findings/schema');

function makeFinding(overrides) {
  return createFinding({
    tool: 'eslint',
    category: 'bug',
    file: 'src/a.js',
    message: 'test finding',
    line: 10,
    ...overrides,
  });
}

describe('Deduplication', () => {
  describe('deduplicate', () => {
    it('should return empty array for empty input', () => {
      assert.deepEqual(deduplicate([]), []);
    });

    it('should return empty array for null input', () => {
      assert.deepEqual(deduplicate(null), []);
    });

    it('should return same findings if no duplicates', () => {
      const f1 = makeFinding({ file: 'a.js', line: 10 });
      const f2 = makeFinding({ file: 'b.js', line: 20 });
      const result = deduplicate([f1, f2]);
      assert.equal(result.length, 2);
    });

    it('should remove duplicate findings with same fingerprint', () => {
      const f1 = makeFinding({ tool: 'eslint', file: 'a.js', line: 10, category: 'bug' });
      const f2 = makeFinding({ tool: 'semgrep', file: 'a.js', line: 10, category: 'bug' });
      const result = deduplicate([f1, f2]);
      assert.equal(result.length, 1);
    });

    it('should keep highest severity when deduplicating', () => {
      const f1 = makeFinding({ tool: 'eslint', file: 'a.js', line: 10, category: 'bug', severity: 'LOW' });
      const f2 = makeFinding({ tool: 'semgrep', file: 'a.js', line: 10, category: 'bug', severity: 'HIGH' });
      const result = deduplicate([f1, f2]);
      assert.equal(result.length, 1);
      assert.equal(result[0].severity, 'HIGH');
    });

    it('should keep BLOCKER over everything', () => {
      const f1 = makeFinding({ tool: 'eslint', file: 'a.js', line: 10, category: 'bug', severity: 'LOW' });
      const f2 = makeFinding({ tool: 'bandit', file: 'a.js', line: 10, category: 'bug', severity: 'BLOCKER' });
      const result = deduplicate([f1, f2]);
      assert.equal(result[0].severity, 'BLOCKER');
    });

    it('should preserve all unique findings across categories', () => {
      const f1 = makeFinding({ file: 'a.js', line: 10, category: 'bug' });
      const f2 = makeFinding({ file: 'a.js', line: 10, category: 'vulnerability' });
      const result = deduplicate([f1, f2]);
      assert.equal(result.length, 2);
    });

    it('should handle large groups correctly', () => {
      const findings = [
        makeFinding({ tool: 'eslint', file: 'a.js', line: 10, category: 'bug', severity: 'LOW' }),
        makeFinding({ tool: 'semgrep', file: 'a.js', line: 10, category: 'bug', severity: 'MEDIUM' }),
        makeFinding({ tool: 'bandit', file: 'a.js', line: 10, category: 'bug', severity: 'BLOCKER' }),
        makeFinding({ tool: 'ruff', file: 'a.js', line: 10, category: 'bug', severity: 'HIGH' }),
      ];
      const result = deduplicate(findings);
      assert.equal(result.length, 1);
      assert.equal(result[0].severity, 'BLOCKER');
    });
  });

  describe('keepHighestSeverity', () => {
    it('should return the finding with highest severity', () => {
      const f1 = makeFinding({ severity: 'LOW' });
      const f2 = makeFinding({ severity: 'HIGH' });
      const f3 = makeFinding({ severity: 'MEDIUM' });
      assert.equal(keepHighestSeverity([f1, f2, f3]).severity, 'HIGH');
    });

    it('should return first finding if all same severity', () => {
      const f1 = makeFinding({ severity: 'MEDIUM' });
      const f2 = makeFinding({ severity: 'MEDIUM' });
      assert.equal(keepHighestSeverity([f1, f2]).id, f1.id);
    });
  });

  describe('getDuplicateGroups', () => {
    it('should return empty array when no duplicates', () => {
      const f1 = makeFinding({ file: 'a.js', line: 10 });
      const f2 = makeFinding({ file: 'b.js', line: 20 });
      assert.deepEqual(getDuplicateGroups([f1, f2]), []);
    });

    it('should return groups of duplicates', () => {
      const f1 = makeFinding({ tool: 'eslint', file: 'a.js', line: 10, category: 'bug' });
      const f2 = makeFinding({ tool: 'semgrep', file: 'a.js', line: 10, category: 'bug' });
      const groups = getDuplicateGroups([f1, f2]);
      assert.equal(groups.length, 1);
      assert.equal(groups[0].length, 2);
    });
  });
});
