const test = require('node:test');
const assert = require('node:assert');
const { evaluateDeployReadiness } = require('../../../src/core/deployguard');
const { analyzeDeployGuard } = require('../../../src/analyzers/custom/deployguard');

test('DeployGuard - Pre-Deployment Readiness & Infrastructure Gate', async (t) => {
  await t.test('evaluates clean deployment as PASSED with 100% readiness', () => {
    const result = evaluateDeployReadiness([], []);
    assert.strictEqual(result.status, 'PASSED');
    assert.strictEqual(result.readinessScore, 100);
    assert.strictEqual(result.metrics.blockers, 0);
  });

  await t.test('evaluates blockers as BLOCKED gate status', () => {
    const findings = [
      { tool: 'deployguard', severity: 'BLOCKER', ruleId: 'deployguard-docker-env-secret', message: 'Secret in ENV' },
    ];
    const result = evaluateDeployReadiness(findings, ['Dockerfile']);
    assert.strictEqual(result.status, 'BLOCKED');
    assert.ok(result.readinessScore <= 70);
    assert.strictEqual(result.metrics.blockers, 1);
  });

  await t.test('evaluates high severity issues as WARNING gate status', () => {
    const findings = [
      { tool: 'deployguard', severity: 'HIGH', ruleId: 'deployguard-docker-root', message: 'Root user' },
    ];
    const result = evaluateDeployReadiness(findings, ['Dockerfile']);
    assert.strictEqual(result.status, 'WARNING');
    assert.ok(result.readinessScore >= 80);
    assert.strictEqual(result.metrics.high, 1);
  });

  await t.test('flags committed .env files as blockers', () => {
    const files = ['.env', 'src/app.js'];
    const findings = analyzeDeployGuard(files, '.');
    const envFinding = findings.find((f) => f.ruleId === 'deployguard-committed-env');
    assert.ok(envFinding !== undefined, 'Expected committed-env finding');
    assert.strictEqual(envFinding.severity, 'BLOCKER');
  });

  await t.test('excludes test and fixture paths from readiness evaluation', () => {
    const findings = [
      { file: 'tests/fixtures/security/injection-attacks.js', category: 'security', severity: 'BLOCKER', ruleId: 'code-injection-eval' },
      { file: 'tests/unit/cli/report.test.js', category: 'security', severity: 'BLOCKER', ruleId: 'code-injection-eval' },
      { file: 'CodeSentry/tests/fixtures/security/py-sqli.py', category: 'security', severity: 'BLOCKER', ruleId: 'py-sql-injection-concat' },
    ];
    const result = evaluateDeployReadiness(findings, []);
    assert.strictEqual(result.metrics.blockers, 0);
    assert.strictEqual(result.readinessScore, 100);
    assert.strictEqual(result.status, 'PASSED');
  });

  await t.test('still counts production findings without a file path', () => {
    const findings = [
      { category: 'security', severity: 'BLOCKER', ruleId: 'hardcoded-aws-key' },
    ];
    const result = evaluateDeployReadiness(findings, []);
    assert.strictEqual(result.metrics.blockers, 1);
    assert.strictEqual(result.status, 'BLOCKED');
  });
});
