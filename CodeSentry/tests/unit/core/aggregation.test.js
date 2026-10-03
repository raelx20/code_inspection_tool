const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { aggregate } = require('../../../src/core/aggregation');
const { createFinding } = require('../../../src/findings/schema');

function makeFinding(overrides) {
  return createFinding({
    tool: 'eslint',
    category: 'bug',
    file: 'src/a.js',
    message: 'test',
    line: 1,
    ...overrides,
  });
}

describe('Aggregation', () => {
  it('should return zero counts for empty findings', () => {
    const result = aggregate([]);
    assert.equal(result.total, 0);
    assert.deepEqual(result.bySeverity, { BLOCKER: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });
    assert.deepEqual(result.byCategory, {});
    assert.deepEqual(result.byTool, {});
    assert.deepEqual(result.byFile, {});
  });

  it('should throw for non-array input', () => {
    assert.throws(() => aggregate(null), /must be an array/);
    assert.throws(() => aggregate('not-array'), /must be an array/);
  });

  it('should count severities correctly', () => {
    const findings = [
      makeFinding({ severity: 'BLOCKER' }),
      makeFinding({ severity: 'HIGH' }),
      makeFinding({ severity: 'HIGH' }),
      makeFinding({ severity: 'MEDIUM' }),
      makeFinding({ severity: 'MEDIUM' }),
      makeFinding({ severity: 'MEDIUM' }),
      makeFinding({ severity: 'LOW' }),
      makeFinding({ severity: 'LOW' }),
      makeFinding({ severity: 'LOW' }),
      makeFinding({ severity: 'LOW' }),
    ];

    const result = aggregate(findings);
    assert.equal(result.total, 10);
    assert.equal(result.bySeverity.BLOCKER, 1);
    assert.equal(result.bySeverity.HIGH, 2);
    assert.equal(result.bySeverity.MEDIUM, 3);
    assert.equal(result.bySeverity.LOW, 4);
    assert.equal(result.bySeverity.INFO, 0);
  });

  it('should count categories correctly', () => {
    const findings = [
      makeFinding({ category: 'bug' }),
      makeFinding({ category: 'bug' }),
      makeFinding({ category: 'vulnerability' }),
    ];
    const result = aggregate(findings);
    assert.equal(result.byCategory.bugs, 2);
    assert.equal(result.byCategory.security, 1);
  });

  it('should count tools correctly', () => {
    const findings = [
      makeFinding({ tool: 'eslint' }),
      makeFinding({ tool: 'eslint' }),
      makeFinding({ tool: 'bandit' }),
    ];
    const result = aggregate(findings);
    assert.equal(result.byTool.eslint, 2);
    assert.equal(result.byTool.bandit, 1);
  });

  it('should count files correctly', () => {
    const findings = [
      makeFinding({ file: 'a.js' }),
      makeFinding({ file: 'a.js' }),
      makeFinding({ file: 'b.js' }),
    ];
    const result = aggregate(findings);
    assert.equal(result.byFile['a.js'], 2);
    assert.equal(result.byFile['b.js'], 1);
  });

  it('should handle the exact distribution: 1 BLOCKER, 2 HIGH, 3 MEDIUM, 4 LOW', () => {
    const findings = [
      makeFinding({ severity: 'BLOCKER' }),
      makeFinding({ severity: 'HIGH' }),
      makeFinding({ severity: 'HIGH' }),
      makeFinding({ severity: 'MEDIUM' }),
      makeFinding({ severity: 'MEDIUM' }),
      makeFinding({ severity: 'MEDIUM' }),
      makeFinding({ severity: 'LOW' }),
      makeFinding({ severity: 'LOW' }),
      makeFinding({ severity: 'LOW' }),
      makeFinding({ severity: 'LOW' }),
    ];
    const result = aggregate(findings);
    assert.equal(result.total, 10);
    assert.equal(result.bySeverity.BLOCKER, 1);
    assert.equal(result.bySeverity.HIGH, 2);
    assert.equal(result.bySeverity.MEDIUM, 3);
    assert.equal(result.bySeverity.LOW, 4);
  });
});
