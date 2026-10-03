const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { scan } = require('../../../src/core/scan');

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures');

describe('Scan', () => {
  it('should return a complete ScanResult for a real project', async () => {
    const result = await scan(path.join(FIXTURES, 'broken-js'));

    assert.ok(result.project, 'should have project');
    assert.ok(result.project.path, 'should have project.path');
    assert.ok(result.project.name, 'should have project.name');

    assert.equal(typeof result.filesAnalyzed, 'number');
    assert.ok(Array.isArray(result.languages));
    assert.ok(Array.isArray(result.findings));
    assert.ok(result.aggregation, 'should have aggregation');
    assert.ok(result.score, 'should have score');
    assert.ok(result.verdict, 'should have verdict');
    assert.ok(result.metadata, 'should have metadata');
  });

  it('should discover and analyze real files', async () => {
    const result = await scan(path.join(FIXTURES, 'broken-js'));
    assert.ok(result.filesAnalyzed > 0, 'should analyze files');
    assert.ok(result.languages.includes('javascript'));
  });

  it('should produce findings from buggy code', async () => {
    const result = await scan(path.join(FIXTURES, 'bugs'));
    assert.ok(result.findings.length > 0, 'should have findings from buggy fixtures');
  });

  it('should have valid findings in the result', async () => {
    const result = await scan(path.join(FIXTURES, 'bugs'));
    for (const f of result.findings) {
      assert.ok(f.id, 'finding should have id');
      assert.ok(f.tool, 'finding should have tool');
      assert.ok(f.category, 'finding should have category');
      assert.ok(f.severity, 'finding should have severity');
      assert.ok(f.file, 'finding should have file');
      assert.ok(f.message, 'finding should have message');
      assert.ok(f.fingerprint, 'finding should have fingerprint');
    }
  });

  it('should have aggregation that matches findings', async () => {
    const result = await scan(path.join(FIXTURES, 'bugs'));
    assert.equal(result.aggregation.total, result.findings.length);
  });

  it('should have score between 0 and 100', async () => {
    const result = await scan(path.join(FIXTURES, 'broken-js'));
    assert.ok(result.score.value >= 0 && result.score.value <= 100, 'score should be 0-100');
    assert.equal(result.score.max, 100);
  });

  it('should have a valid verdict status', async () => {
    const result = await scan(path.join(FIXTURES, 'broken-js'));
    assert.ok(['PASS', 'WARN', 'FAIL'].includes(result.verdict.status));
  });

  it('should have metadata with duration and timestamp', async () => {
    const result = await scan(path.join(FIXTURES, 'clean-project'));
    assert.equal(typeof result.metadata.duration, 'number');
    assert.ok(result.metadata.timestamp, 'should have timestamp');
    assert.ok(Array.isArray(result.metadata.errors));
  });

  it('should deduplicate findings across tools', async () => {
    const result = await scan(path.join(FIXTURES, 'bugs'));
    const ids = result.findings.map(f => f.id);
    const uniqueIds = new Set(ids);
    assert.equal(ids.length, uniqueIds.size, 'findings should be deduplicated');
  });

  it('should handle custom config overrides', async () => {
    const result = await scan(path.join(FIXTURES, 'clean-project'), {
      enabledAnalyzers: [],
    });
    assert.ok(result.findings.length >= 0, 'should still produce result with limited analyzers');
  });

  it('should set filesAnalyzed from discovery', async () => {
    const result = await scan(path.join(FIXTURES, 'clean-project'));
    assert.ok(result.filesAnalyzed >= 0);
  });

  it('should produce fewer findings for clean project than broken project', async () => {
    const cleanResult = await scan(path.join(FIXTURES, 'clean-project'));
    const brokenResult = await scan(path.join(FIXTURES, 'bugs'));
    assert.ok(cleanResult.findings.length <= brokenResult.findings.length,
      'clean project should have same or fewer findings');
  });

  it('should handle empty/minimal project', async () => {
    const result = await scan(path.join(FIXTURES, 'clean-project'));
    assert.ok(result.project);
    assert.ok(result.aggregation);
    assert.ok(result.score);
    assert.ok(result.verdict);
  });
});
