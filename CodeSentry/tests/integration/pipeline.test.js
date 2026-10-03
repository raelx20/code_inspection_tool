const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { scan } = require('../../src/core/scan');
const { createFinding, isValidFinding } = require('../../src/findings/schema');
const { normalize, registerNormalizer } = require('../../src/findings/normalize');
const { deduplicate } = require('../../src/findings/dedupe');
const { aggregate } = require('../../src/core/aggregation');

registerNormalizer('codesentry', function normalizeCodesentry(rawResults) {
  if (!Array.isArray(rawResults)) return [];
  return rawResults.map(r => {
    try {
      return createFinding({
        tool: 'codesentry',
        category: r.category || 'bugs',
        severity: r.severity || 'MEDIUM',
        file: r.file || 'unknown',
        line: r.line || null,
        column: r.column || null,
        rule: r.rule || null,
        message: r.message || '',
        suggestedFix: r.suggestedFix || null,
      });
    } catch {
      return null;
    }
  }).filter(Boolean);
});

const FIXTURES = path.join(__dirname, '..', 'fixtures');

describe('Pipeline Integration', () => {
  describe('Full Scan Pipeline', () => {
    it('should complete a full scan with real project', async () => {
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

    it('should handle empty project gracefully', async () => {
      const result = await scan(path.join(FIXTURES, 'clean-project'));

      assert.ok(result.project);
      assert.equal(typeof result.filesAnalyzed, 'number');
      assert.ok(Array.isArray(result.findings));
      assert.equal(typeof result.aggregation.total, 'number');
    });
  });

  describe('Finding Pipeline', () => {
    it('should normalize findings from different tools', () => {
      const eslintResults = [
        {
          filePath: 'src/app.js',
          ruleId: 'no-unused-vars',
          severity: 2,
          message: { message: 'Unused variable' },
          line: 10,
        },
      ];

      const banditResults = [
        {
          filename: 'app.py',
          test_id: 'B307',
          issue_severity: 'HIGH',
          issue_confidence: 'HIGH',
          issue_text: 'Use of exec',
          line_number: 42,
        },
      ];

      const eslintFindings = normalize('eslint', eslintResults);
      const banditFindings = normalize('bandit', banditResults);

      assert.equal(eslintFindings.length, 1);
      assert.equal(banditFindings.length, 1);

      assert.ok(isValidFinding(eslintFindings[0]));
      assert.ok(isValidFinding(banditFindings[0]));

      assert.equal(eslintFindings[0].tool, 'eslint');
      assert.equal(banditFindings[0].tool, 'bandit');
    });

    it('should deduplicate findings across tools', () => {
      const findings = [
        createFinding({
          tool: 'eslint',
          category: 'bug',
          file: 'src/app.js',
          message: 'Unused variable',
          line: 10,
        }),
        createFinding({
          tool: 'semgrep',
          category: 'bug',
          file: 'src/app.js',
          message: 'Unused variable detected',
          line: 10,
        }),
      ];

      const deduped = deduplicate(findings);

      assert.equal(deduped.length, 1);
      assert.ok(isValidFinding(deduped[0]));
    });

    it('should aggregate findings correctly', () => {
      const findings = [
        createFinding({
          tool: 'eslint',
          category: 'security',
          file: 'src/app.js',
          message: 'Security issue',
          line: 10,
          severity: 'HIGH',
        }),
        createFinding({
          tool: 'bandit',
          category: 'bugs',
          file: 'src/utils.js',
          message: 'Bug',
          line: 20,
          severity: 'MEDIUM',
        }),
      ];

      const result = aggregate(findings);

      assert.equal(result.total, 2);
      assert.equal(result.bySeverity.HIGH, 1);
      assert.equal(result.bySeverity.MEDIUM, 1);
      assert.equal(result.byCategory.security, 1);
      assert.equal(result.byCategory.bugs, 1);
    });

    it('should normalize codesentry custom analyzer findings', () => {
      const rawResults = [
        {
          file: 'src/app.js',
          line: 10,
          column: null,
          rule: 'empty-catch',
          message: 'Empty catch block',
          severity: 'HIGH',
          category: 'bugs',
          suggestedFix: 'Handle errors',
          analyzer: 'bugs',
        },
      ];

      const findings = normalize('codesentry', rawResults);
      assert.equal(findings.length, 1);
      assert.ok(isValidFinding(findings[0]));
      assert.equal(findings[0].tool, 'codesentry');
      assert.equal(findings[0].category, 'bugs');
    });
  });

  describe('AI Integration', () => {
    it('should work with mock OpenRouter AI client and default factory', async () => {
      const { createAIClient } = require('../../src/analyzers/ai/client');
      const { createPromptGenerator } = require('../../src/analyzers/ai/prompt');
      const { createAIResponseParser } = require('../../src/analyzers/ai/parser');

      const client = createAIClient({ mockMode: true });
      const promptGen = createPromptGenerator();
      const parser = createAIResponseParser();

      const finding = createFinding({
        tool: 'semgrep',
        category: 'security',
        file: 'src/app.js',
        message: 'SQL injection vulnerability',
        line: 42,
        severity: 'HIGH',
      });

      const prompt = promptGen.generateFindingAnalysisPrompt(finding, 'const query = `SELECT * FROM users WHERE id = ${userId}`;');
      const response = await client.analyze(prompt);
      const parsed = parser.parse(response);

      assert.ok(parsed.explanation);
      assert.ok(parsed.severity);
      assert.ok(typeof parsed.confidence === 'number');
      assert.ok(typeof parsed.falsePositiveProbability === 'number');
      assert.ok(parsed.impact);
      assert.ok(parsed.suggestedFix);
    });

    it('should work with mock OpenRouter AI client and default factory', async () => {
      const { createAIClient } = require('../../src/analyzers/ai/client');
      const { createPromptGenerator } = require('../../src/analyzers/ai/prompt');
      const { createAIResponseParser } = require('../../src/analyzers/ai/parser');

      const client = createAIClient({ mockMode: true });
      const promptGen = createPromptGenerator();
      const parser = createAIResponseParser();

      const finding = createFinding({
        tool: 'codesentry',
        category: 'security',
        file: 'src/app.js',
        message: 'eval() code injection vulnerability',
        line: 12,
        severity: 'HIGH',
      });

      const prompt = promptGen.generateFindingAnalysisPrompt(finding, 'eval(userInput);');
      const response = await client.analyze(prompt);
      const parsed = parser.parse(response);

      assert.ok(parsed.explanation);
      assert.equal(parsed.severity, 'HIGH');
      assert.ok(typeof parsed.confidence === 'number');
      assert.ok(typeof parsed.falsePositiveProbability === 'number');
      assert.ok(parsed.impact);
      assert.ok(parsed.suggestedFix);
    });
  });

  describe('CLI Integration', () => {
    it('should parse command line arguments', () => {
      const { createCommandParser } = require('../../src/cli/commands');

      const parser = createCommandParser();

      const parsed1 = parser.parse(['scan', './my-project']);
      assert.equal(parsed1.command, 'scan');
      assert.equal(parsed1.projectPath, './my-project');

      const parsed2 = parser.parse(['scan', '--json', '--severity', 'HIGH']);
      assert.equal(parsed2.command, 'scan');
      assert.equal(parsed2.options.json, true);
      assert.equal(parsed2.options.severity, 'HIGH');

      const parsed3 = parser.parse(['--help']);
      assert.equal(parsed3.command, 'help');
    });

    it('should format scan results', () => {
      const { createFormatter } = require('../../src/cli/formatter');
      const { aggregate } = require('../../src/core/aggregation');

      const formatter = createFormatter();

      const findings = [
        createFinding({
          tool: 'eslint',
          category: 'security',
          file: 'src/app.js',
          message: 'Security issue',
          line: 10,
          severity: 'HIGH',
        }),
      ];

      const result = {
        project: { path: '/tmp/test', name: 'test' },
        filesAnalyzed: 10,
        languages: ['javascript'],
        findings,
        aggregation: aggregate(findings),
        score: { value: 80, max: 100 },
        verdict: { status: 'PASS', message: 'All good' },
      };

      const summaryLines = formatter.formatSummary(result);
      assert.ok(summaryLines.length > 0);

      const findingLines = formatter.formatFindings(findings);
      assert.ok(findingLines.length > 0);
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed findings gracefully', () => {
      const findings = [
        { invalid: 'finding' },
        createFinding({
          tool: 'eslint',
          category: 'bug',
          file: 'src/app.js',
          message: 'Valid finding',
          line: 10,
        }),
      ];

      const deduped = deduplicate(findings);
      assert.ok(deduped.length >= 1);
    });

    it('should handle empty analyzer results', () => {
      const eslintFindings = normalize('eslint', []);
      const banditFindings = normalize('bandit', []);

      assert.equal(eslintFindings.length, 0);
      assert.equal(banditFindings.length, 0);
    });

    it('should handle AI failures gracefully', async () => {
      const { createOpenRouterClient } = require('../../src/analyzers/ai/openrouter');

      const client = createOpenRouterClient({ mockMode: true });

      const response = await client.analyze('Invalid prompt');
      assert.ok(response);
    });
  });
});
