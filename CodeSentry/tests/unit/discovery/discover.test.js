const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { discover } = require('../../../src/discovery/discover');
const { detectLanguage, isSupportedFile, getSupportedExtensions, SUPPORTED_LANGUAGES } = require('../../../src/discovery/language');
const { enumerateFiles, SKIP_DIRS } = require('../../../src/discovery/files');
const { loadIgnorePatterns, shouldIgnore, DEFAULT_IGNORE_PATTERNS } = require('../../../src/discovery/ignore');

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures');

describe('Discovery Module', () => {
  describe('Language', () => {
    it('should detect all supported JavaScript extensions', () => {
      assert.equal(detectLanguage('a.js'), 'javascript');
      assert.equal(detectLanguage('a.jsx'), 'javascript');
      assert.equal(detectLanguage('a.mjs'), 'javascript');
      assert.equal(detectLanguage('a.cjs'), 'javascript');
    });

    it('should detect all supported TypeScript extensions', () => {
      assert.equal(detectLanguage('a.ts'), 'typescript');
      assert.equal(detectLanguage('a.tsx'), 'typescript');
      assert.equal(detectLanguage('a.mts'), 'typescript');
      assert.equal(detectLanguage('a.cts'), 'typescript');
    });

    it('should detect Python extensions', () => {
      assert.equal(detectLanguage('a.py'), 'python');
      assert.equal(detectLanguage('a.pyw'), 'python');
    });

    it('should return supported extensions list', () => {
      const exts = getSupportedExtensions();
      assert.ok(exts.includes('.js'));
      assert.ok(exts.includes('.ts'));
      assert.ok(exts.includes('.py'));
    });

    it('should have correct supported languages', () => {
      assert.ok(SUPPORTED_LANGUAGES.includes('javascript'));
      assert.ok(SUPPORTED_LANGUAGES.includes('typescript'));
      assert.ok(SUPPORTED_LANGUAGES.includes('python'));
    });
  });

  describe('Files', () => {
    it('should enumerate files from clean-project', () => {
      const files = enumerateFiles(path.join(FIXTURES, 'clean-project'));
      assert.ok(files.length > 0);
      assert.ok(files.some(f => f.endsWith('index.js')));
    });

    it('should enumerate files from broken-js', () => {
      const files = enumerateFiles(path.join(FIXTURES, 'broken-js'));
      assert.ok(files.some(f => f.endsWith('app.js')));
    });

    it('should enumerate files from broken-python', () => {
      const files = enumerateFiles(path.join(FIXTURES, 'broken-python'));
      assert.ok(files.some(f => f.endsWith('app.py')));
    });

    it('should skip default ignore directories', () => {
      assert.ok(SKIP_DIRS.has('node_modules'));
      assert.ok(SKIP_DIRS.has('.git'));
      assert.ok(SKIP_DIRS.has('dist'));
      assert.ok(SKIP_DIRS.has('__pycache__'));
    });

    it('should handle maxDepth option', () => {
      const files = enumerateFiles(path.join(FIXTURES), { maxDepth: 1 });
      assert.ok(Array.isArray(files));
    });
  });

  describe('Ignore', () => {
    it('should have default ignore patterns', () => {
      assert.ok(DEFAULT_IGNORE_PATTERNS.includes('node_modules'));
      assert.ok(DEFAULT_IGNORE_PATTERNS.includes('.git'));
    });

    it('should load ignore patterns from project', () => {
      const patterns = loadIgnorePatterns(path.join(FIXTURES, 'clean-project'));
      assert.ok(Array.isArray(patterns));
      assert.ok(patterns.length > 0);
    });

    it('should match directory names', () => {
      const patterns = ['node_modules', 'dist', 'build'];
      assert.equal(shouldIgnore('src/node_modules/pkg/index.js', patterns), true);
      assert.equal(shouldIgnore('dist/bundle.js', patterns), true);
      assert.equal(shouldIgnore('src/app.js', patterns), false);
    });

    it('should match exact directory names in path', () => {
      const patterns = ['.git'];
      assert.equal(shouldIgnore('.git/config', patterns), true);
      assert.equal(shouldIgnore('src/.gitignore', patterns), false);
    });
  });

  describe('Discover', () => {
    it('should discover clean-project', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'clean-project') });
      assert.ok(result.files.length > 0);
      assert.ok(result.languages.length > 0);
      assert.ok(result.fileMap);
      assert.equal(result.projectPath, path.join(FIXTURES, 'clean-project'));
    });

    it('should discover broken-js', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'broken-js') });
      assert.ok(result.files.length > 0);
      assert.ok(result.languages.includes('javascript'));
    });

    it('should discover broken-python', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'broken-python') });
      assert.ok(result.files.length > 0);
      assert.ok(result.languages.includes('python'));
    });

    it('should discover mixed-project', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'mixed-project') });
      assert.ok(result.files.length > 0);
      assert.ok(result.languages.includes('javascript'));
    });

    it('should discover all fixture categories', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES) });
      assert.ok(result.files.length > 5, 'should find files across all fixture dirs');
      assert.ok(result.languages.length >= 2, 'should detect multiple languages');
    });

    it('should return relative paths in files array', async () => {
      const result = await discover({ projectPath: path.join(FIXTURES, 'clean-project') });
      for (const f of result.files) {
        assert.ok(!path.isAbsolute(f), 'files should be relative paths');
      }
    });
  });
});
