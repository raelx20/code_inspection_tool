const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createReportGenerator } = require('../../../src/cli/report');

describe('ReportGenerator', () => {
  const mockScanResult = {
    project: {
      name: 'test-app',
      path: '/path/to/test-app',
    },
    filesAnalyzed: 3,
    languages: ['javascript', 'python'],
    metadata: {
      timestamp: '2026-09-08T00:00:00.000Z',
      duration: 1250,
      errors: [],
    },
    verdict: {
      status: 'WARN',
      message: 'Codebase has moderate issues that should be addressed.',
    },
    score: {
      value: 82,
      max: 100,
      breakdown: {
        HIGH: 10,
        MEDIUM: 8,
      },
    },
    aggregation: {
      total: 2,
      bySeverity: {
        BLOCKER: 0,
        HIGH: 1,
        MEDIUM: 1,
        LOW: 0,
        INFO: 0,
      },
      byCategory: {
        security: 1,
        bugs: 1,
      },
    },
    findings: [
      {
        file: 'src/index.js',
        line: 12,
        severity: 'HIGH',
        category: 'security',
        rule: 'no-eval',
        tool: 'eslint',
        message: 'eval() is forbidden due to code injection risks.',
        suggestedFix: 'Refactor without eval.',
        aiAnalysis: {
          model: 'openrouter/free',
          confidence: 0.95,
          falsePositiveProbability: 0.05,
          explanation: 'Dynamic execution can execute untrusted user input.',
          impact: 'Remote code execution vulnerability.',
          suggestedFix: 'Use JSON.parse or safe dispatch table.',
        },
      },
      {
        file: 'src/utils.py',
        line: 45,
        severity: 'MEDIUM',
        category: 'bugs',
        rule: 'F841',
        tool: 'ruff',
        message: 'Variable assigned but never used.',
        suggestedFix: 'Remove variable.',
        aiAnalysis: {
          model: 'openrouter/free',
          confidence: 0.85,
          falsePositiveProbability: 0.1,
          explanation: 'Dead code detected.',
          impact: 'Minor memory and clarity overhead.',
          suggestedFix: 'Delete the unused variable.',
        },
      },
    ],
  };

  it('should generate a comprehensive markdown report file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codesentry-test-'));
    const reportGen = createReportGenerator({
      outputDir: tmpDir,
      filename: 'custom-report.md',
    });

    const reportPath = reportGen.generate(mockScanResult);
    assert.equal(reportPath, path.join(tmpDir, 'custom-report.md'));
    assert.ok(fs.existsSync(reportPath));

    const content = fs.readFileSync(reportPath, 'utf-8');
    // Verify core sections
    assert.ok(content.includes('# 🛡️ CodeSentry Analysis Report'));
    assert.ok(content.includes('Executive Summary'));
    assert.ok(content.includes('Score Card'));
    assert.ok(content.includes('Findings by Severity'));
    assert.ok(content.includes('Findings by Category'));
    assert.ok(content.includes('Detailed Findings by File'));
    assert.ok(content.includes('Top Risks'));
    assert.ok(content.includes('AI Analysis Summary'));
    assert.ok(content.includes('Remediation Plan'));
    assert.ok(content.includes('Report Metadata'));

    // Verify finding details and AI analysis
    assert.ok(content.includes('no-eval'));
    assert.ok(content.includes('Remote code execution vulnerability'));
    assert.ok(content.includes('Confidence | 95%'));

    // Clean up
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should auto-generate filename when filename is not specified', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codesentry-test-'));
    const reportGen = createReportGenerator({
      outputDir: tmpDir,
    });

    const reportPath = reportGen.generate(mockScanResult);
    assert.ok(fs.existsSync(reportPath));
    assert.equal(path.basename(reportPath), 'codesentry-report.md');

    // Clean up
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should handle scan result with no findings gracefully', () => {
    const emptyResult = {
      project: { name: 'clean-app', path: '/clean' },
      filesAnalyzed: 5,
      languages: ['javascript'],
      metadata: { timestamp: new Date().toISOString(), duration: 100, errors: [] },
      verdict: { status: 'PASS', message: 'Clean codebase.' },
      score: { value: 100, max: 100 },
      aggregation: { total: 0, bySeverity: {}, byCategory: {} },
      findings: [],
    };

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codesentry-test-'));
    const reportGen = createReportGenerator({ outputDir: tmpDir, filename: 'clean.md' });
    const reportPath = reportGen.generate(emptyResult);
    const content = fs.readFileSync(reportPath, 'utf-8');

    assert.ok(content.includes('No findings detected'));
    assert.ok(content.includes('Score**: **100** / 100'));

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
