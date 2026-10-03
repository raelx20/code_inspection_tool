const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { discover } = require('../../src/discovery/discover');
const { detectLanguage, isSupportedFile } = require('../../src/discovery/language');
const { enumerateFiles } = require('../../src/discovery/files');
const { loadIgnorePatterns, shouldIgnore } = require('../../src/discovery/ignore');
const { runCustomAnalyzers } = require('../../src/analyzers/custom/index');
const { normalize, registerNormalizer } = require('../../src/findings/normalize');
const { deduplicate } = require('../../src/findings/dedupe');
const { aggregate } = require('../../src/core/aggregation');
const { score } = require('../../src/core/scoring');
const { verdict } = require('../../src/core/verdict');
const { createFinding } = require('../../src/findings/schema');

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

describe('Discovery', () => {
  describe('Language Detection', () => {
    it('should detect JavaScript files', () => {
      assert.equal(detectLanguage('app.js'), 'javascript');
      assert.equal(detectLanguage('component.jsx'), 'javascript');
      assert.equal(detectLanguage('index.mjs'), 'javascript');
    });

    it('should detect TypeScript files', () => {
      assert.equal(detectLanguage('app.ts'), 'typescript');
      assert.equal(detectLanguage('component.tsx'), 'typescript');
    });

    it('should detect Python files', () => {
      assert.equal(detectLanguage('app.py'), 'python');
      assert.equal(detectLanguage('script.pyw'), 'python');
    });

    it('should return null for unsupported files', () => {
      assert.equal(detectLanguage('readme.md'), null);
      assert.equal(detectLanguage('style.css'), null);
      assert.equal(detectLanguage('data.json'), null);
    });

    it('isSupportedFile should work correctly', () => {
      assert.equal(isSupportedFile('app.js'), true);
      assert.equal(isSupportedFile('app.py'), true);
      assert.equal(isSupportedFile('readme.md'), false);
    });
  });

  describe('File Enumeration', () => {
    it('should enumerate files in a project', () => {
      const files = enumerateFiles(path.join(FIXTURES, 'clean-project'));
      assert.ok(files.length > 0);
      assert.ok(files.some(f => f.endsWith('index.js')));
    });

    it('should skip node_modules', () => {
      const files = enumerateFiles(path.join(FIXTURES, 'clean-project'));
      assert.ok(!files.some(f => f.includes('node_modules')));
    });
  });

  describe('Ignore Patterns', () => {
    it('should load default ignore patterns', () => {
      const patterns = loadIgnorePatterns(path.join(FIXTURES, 'clean-project'));
      assert.ok(patterns.includes('node_modules'));
      assert.ok(patterns.includes('.git'));
    });

    it('should match ignore patterns', () => {
      const patterns = ['node_modules', '.git', 'dist'];
      assert.equal(shouldIgnore('src/node_modules/pkg/file.js', patterns), true);
      assert.equal(shouldIgnore('.git/config', patterns), true);
      assert.equal(shouldIgnore('src/app.js', patterns), false);
    });
  });

  describe('Full Discovery', () => {
    it('should discover files in clean-project', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'clean-project') });
      assert.ok(result.files.length > 0);
      assert.ok(result.languages.includes('javascript'));
      assert.ok(result.fileMap.javascript.length > 0);
    });

    it('should discover files in broken-js', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'broken-js') });
      assert.ok(result.files.length > 0);
      assert.ok(result.languages.includes('javascript'));
    });

    it('should discover files in mixed-project', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'mixed-project') });
      assert.ok(result.files.length > 0);
    });
  });
});

describe('End-to-End Fixture Tests', () => {
  describe('Security Fixtures', () => {
    it('JS SQL injection fixture should be discovered', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'security') });
      assert.ok(result.files.some(f => f.includes('js-sqli.js')));
    });

    it('Python fixtures should be discovered', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'security') });
      assert.ok(result.languages.includes('python'));
    });
  });

  describe('Custom Analyzer → Normalize → Aggregate Pipeline', () => {
    it('should produce valid findings from bugs fixtures', async () => {
      const discovery = await discover({ projectPath: path.join(FIXTURES, 'bugs') });
      const customResult = await runCustomAnalyzers(discovery, {
        projectPath: path.join(FIXTURES, 'bugs'),
      });

      assert.ok(customResult.rawResults.length > 0, 'should have findings from bugs fixtures');

      const normalized = normalize('codesentry', customResult.rawResults);
      assert.ok(normalized.length > 0, 'should normalize findings');

      for (const f of normalized) {
        assert.ok(f.id, 'should have id');
        assert.ok(f.tool, 'should have tool');
        assert.ok(f.category, 'should have category');
        assert.ok(f.severity, 'should have severity');
        assert.ok(f.file, 'should have file');
        assert.ok(f.message, 'should have message');
      }
    });

    it('should produce valid findings from efficiency fixtures', async () => {
      const discovery = await discover({ projectPath: path.join(FIXTURES, 'efficiency') });
      const customResult = await runCustomAnalyzers(discovery, {
        projectPath: path.join(FIXTURES, 'efficiency'),
      });

      assert.ok(customResult.rawResults.length > 0, 'should have findings');

      const normalized = normalize('codesentry', customResult.rawResults);
      const deduped = deduplicate(normalized);
      const agg = aggregate(deduped);
      const s = score(agg);
      const v = verdict(s);

      assert.ok(agg.total > 0);
      assert.ok(s.value >= 0 && s.value <= 100);
      assert.ok(['PASS', 'WARN', 'FAIL'].includes(v.status));
    });

    it('should produce valid findings from resource fixtures', async () => {
      const discovery = await discover({ projectPath: path.join(FIXTURES, 'resources') });
      const customResult = await runCustomAnalyzers(discovery, {
        projectPath: path.join(FIXTURES, 'resources'),
      });

      assert.ok(customResult.rawResults.length > 0, 'should have findings');

      const normalized = normalize('codesentry', customResult.rawResults);
      const deduped = deduplicate(normalized);
      const agg = aggregate(deduped);

      assert.ok(agg.total > 0);
      assert.ok(agg.byCategory.resources > 0 || agg.byCategory.bugs > 0 || agg.byCategory.efficiency > 0);
    });

    it('clean project should produce fewer findings than broken project', async () => {
      const cleanDiscovery = await discover({ projectPath: path.join(FIXTURES, 'clean-project') });
      const cleanResult = await runCustomAnalyzers(cleanDiscovery, {
        projectPath: path.join(FIXTURES, 'clean-project'),
      });

      const brokenDiscovery = await discover({ projectPath: path.join(FIXTURES, 'bugs') });
      const brokenResult = await runCustomAnalyzers(brokenDiscovery, {
        projectPath: path.join(FIXTURES, 'bugs'),
      });

      assert.ok(cleanResult.rawResults.length < brokenResult.rawResults.length,
        'clean project should have fewer findings');
    });
  });
});
