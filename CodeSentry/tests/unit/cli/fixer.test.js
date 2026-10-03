'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  generateRuleFix,
  generateFix,
  formatDiffPreview,
  applyFixToFile,
  batchFixFile,
} = require('../../../src/cli/fixer');

describe('Fixer Engine', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codesentry-fixer-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  describe('generateRuleFix', () => {
    it('should generate fix for loose equality', () => {
      const code = 'if (user.id == targetId) { doSomething(); }';
      const finding = {
        rule: 'loose-equality',
        line: 1,
        message: 'Use === instead of ==',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'if (user.id === targetId) { doSomething(); }');
    });

    it('should generate fix for off-by-one boundary', () => {
      const code = 'for (let i = 0; i <= items.length; i++) {';
      const finding = {
        rule: 'off-by-one',
        line: 1,
        message: 'Off-by-one loop error',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'for (let i = 0; i < items.length; i++) {');
    });

    it('should generate fix for empty catch block', () => {
      const code = 'try { dangerous(); } catch (err) {\n}';
      const finding = {
        rule: 'empty-catch',
        line: 1,
        message: 'Empty catch block',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.ok(fix.newSnippet.includes('console.error(err);'));
    });

    it('should generate fix for hardcoded secret', () => {
      const code = "const API_KEY = 'secret-token-12345';";
      const finding = {
        rule: 'hardcoded-secret',
        line: 1,
        message: 'Hardcoded secret detected',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.ok(fix.newSnippet.includes('process.env.API_KEY'));
    });

    it('should generate fix for Python assignment in condition', () => {
      const code = '    if status = "active":';
      const finding = {
        file: 'app.py',
        rule: 'assignment-in-condition',
        line: 1,
        message: 'Assignment in condition',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, '    if status == "active":');
    });

    it('should generate fix for assignment in condition with property access', () => {
      const code = 'if (user.active = true) {';
      const finding = {
        file: 'app.js',
        rule: 'assignment-in-condition',
        line: 1,
        message: 'Assignment in condition',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'if (user.active === true) {');
    });

    it('should generate fix for Flask debug mode and host binding', () => {
      const code = "app.run(debug=True, host='0.0.0.0')";
      const debugFinding = {
        file: 'app.py',
        rule: 'avoid_app_run_with_debug',
        line: 1,
        message: 'Flask debug=True enabled',
      };
      const debugFix = generateRuleFix(debugFinding, code);
      assert.ok(debugFix);
      assert.ok(debugFix.newSnippet.includes('debug=False'));

      const hostFinding = {
        file: 'app.py',
        rule: 'avoid_app_run_with_bad_host',
        line: 1,
        message: 'Running flask app with host 0.0.0.0',
      };
      const hostFix = generateRuleFix(hostFinding, code);
      assert.ok(hostFix);
      assert.ok(hostFix.newSnippet.includes("host='127.0.0.1'"));
    });

    it('should generate fix for Bandit B105 hardcoded password in Python', () => {
      const code = 'DB_PASSWORD = "admin123"';
      const finding = {
        file: 'app.py',
        rule: 'B105',
        line: 1,
        message: "Possible hardcoded password: 'admin123'",
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, "DB_PASSWORD = os.environ.get('DB_PASSWORD', '')");
    });

    it('should generate fix for Python off-by-one range loop', () => {
      const code = 'for i in range(len(items) + 1):';
      const finding = {
        file: 'app.py',
        rule: 'off-by-one',
        line: 1,
        message: 'Potential off-by-one error',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'for i in range(len(items)):');
    });

    it('should generate fix for Python f-string SQL injection', () => {
      const code = 'query = f"SELECT * FROM users WHERE id = \'{user_id}\'"';
      const finding = {
        file: 'app.py',
        rule: 'B608',
        line: 1,
        message: 'Possible SQL injection vector',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.ok(fix.newSnippet.includes('%s'));
      assert.ok(!fix.newSnippet.includes('f"'));
    });

    it('should generate fix for Python unsafe eval', () => {
      const code = 'result = eval(user_input)';
      const finding = {
        file: 'app.py',
        rule: 'B307',
        line: 1,
        message: 'Use of possibly insecure function',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'result = ast.literal_eval(user_input)');
    });

    it('should generate fix for Python unsafe pickle deserialization', () => {
      const code = 'result = pickle.loads(data)';
      const finding = {
        file: 'app.py',
        rule: 'B301',
        line: 1,
        message: 'Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'result = json.loads(data)');
    });

    it('should simultaneously fix debug=True and host 0.0.0.0 in compound Flask app.run', () => {
      const code = "app.run(debug=True, host='0.0.0.0')";
      const finding = {
        file: 'app.py',
        rule: 'B201',
        line: 1,
        message: 'A Flask app appears to be run with debug=True',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, "app.run(debug=False, host='127.0.0.1')");
    });

    it('should generate fix for Ruff UP006 deprecated typing generics', () => {
      const code = 'def parse_data(items: List[str]) -> Dict[str, int]:';
      const finding = {
        file: 'app.py',
        rule: 'UP006',
        line: 1,
        message: 'Use `list` instead of `List` for type annotation',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'def parse_data(items: list[str]) -> dict[str, int]:');
    });

    it('should generate fix for Ruff E722 bare except', () => {
      const code = 'try:\n    do_work()\nexcept:';
      const finding = {
        file: 'app.py',
        rule: 'E722',
        line: 3,
        message: 'Do not use bare `except`',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'except Exception:');
    });

    it('should generate fix for Ruff B006 mutable default arguments', () => {
      const code = 'def append_item(item, list_items=[]):';
      const finding = {
        file: 'app.py',
        rule: 'B006',
        line: 1,
        message: 'Do not use mutable data structures for argument defaults',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'def append_item(item, list_items=None):');
    });

    it('should generate fix for Bandit B113 requests call without timeout', () => {
      const code = 'response = requests.get("https://api.example.com/data")';
      const finding = {
        file: 'app.py',
        rule: 'B113',
        line: 1,
        message: 'Requests call without timeout',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'response = requests.get("https://api.example.com/data", timeout=10)');
    });

    it('should generate fix for Ruff SIM103 return condition directly', () => {
      const code = 'def is_active(user):\n    if user.enabled:\n        return True\n    else:\n        return False';
      const finding = {
        file: 'app.py',
        rule: 'SIM103',
        line: 2,
        message: 'Return the condition directly',
      };
      const fix = generateRuleFix(finding, code);
      assert.ok(fix);
      assert.equal(fix.newSnippet, '    return bool(user.enabled)');
    });
  });

  describe('formatDiffPreview', () => {
    it('should render diff card with file, issue, and +/- changes', () => {
      const finding = {
        file: 'src/app.js',
        line: 42,
        severity: 'HIGH',
        message: 'Loose equality check',
      };
      const fix = {
        oldSnippet: 'if (a == b)',
        newSnippet: 'if (a === b)',
        explanation: 'Use strict equality',
      };
      const preview = formatDiffPreview(finding, fix);
      assert.ok(preview.includes('src/app.js'));
      assert.ok(preview.includes('IMPROVEMENT PREVIEW'));
      assert.ok(preview.includes('if (a == b)'));
      assert.ok(preview.includes('if (a === b)'));
    });
  });

  describe('applyFixToFile', () => {
    it('should accurately update file content on disk', () => {
      const targetFile = path.join(tempDir, 'sample.js');
      const original = 'const a = 1;\nif (x == y) {\n  return a;\n}\n';
      fs.writeFileSync(targetFile, original, 'utf8');

      const finding = {
        file: targetFile,
        line: 2,
        rule: 'loose-equality',
        message: 'Loose equality',
      };
      const fix = {
        oldSnippet: 'if (x == y) {',
        newSnippet: 'if (x === y) {',
      };

      const result = applyFixToFile(tempDir, finding, fix);
      assert.equal(result.success, true);

      const updated = fs.readFileSync(targetFile, 'utf8');
      assert.ok(updated.includes('if (x === y) {'));
      assert.ok(!updated.includes('if (x == y) {'));
    });
  });

  describe('generateFix with AI Model Cascading', () => {
    it('should prioritize deterministic rule fix when available', async () => {
      const targetFile = path.join(tempDir, 'types.py');
      fs.writeFileSync(targetFile, 'def fn(x: List[int]):\n    pass\n', 'utf8');

      const finding = {
        file: targetFile,
        rule: 'UP006',
        line: 1,
        message: 'Use list instead of List',
      };

      const fix = await generateFix(tempDir, finding, { noAi: true });
      assert.ok(fix);
      assert.equal(fix.newSnippet, 'def fn(x: list[int]):');
    });

    it('should cascade to AI repairCode when rule fix is unavailable', async () => {
      const targetFile = path.join(tempDir, 'custom.js');
      fs.writeFileSync(targetFile, 'function complex() {\n  const unhandled = 1;\n}\n', 'utf8');

      const mockAiClient = {
        async repairCode({ finding, fileContent, preferredModel }) {
          return {
            oldSnippet: 'const unhandled = 1;',
            newSnippet: 'const handled = 2;',
            explanation: 'Fixed custom issue via AI repair',
            modelUsed: 'minimax/minimax-m3:free',
            switchedFrom: preferredModel !== 'minimax/minimax-m3:free' ? preferredModel : null,
          };
        },
      };

      const finding = {
        file: targetFile,
        rule: 'unknown-custom-rule',
        line: 2,
        message: 'Custom unhandled rule',
      };

      const fix = await generateFix(tempDir, finding, {
        aiClient: mockAiClient,
        preferredModel: 'poolside/laguna-s-2.1:free',
      });

      assert.ok(fix);
      assert.equal(fix.oldSnippet, 'const unhandled = 1;');
      assert.equal(fix.newSnippet, 'const handled = 2;');
      assert.equal(fix.modelUsed, 'minimax/minimax-m3:free');
      assert.equal(fix.switchedFrom, 'poolside/laguna-s-2.1:free');
    });
  });

  describe('batchFixFile (Holistic File Repair)', () => {
    it('should repair multiple deterministic findings in one pass and write once to disk', async () => {
      const targetFile = path.join(tempDir, 'batch-sample.js');
      const original = [
        'function test() {',
        '  if (a == b) {',
        '    for (let i = 0; i <= items.length; i++) {',
        '      console.log(items[i]);',
        '    }',
        '  }',
        '}',
      ].join('\n');
      fs.writeFileSync(targetFile, original, 'utf8');

      const findings = [
        {
          file: targetFile,
          rule: 'loose-equality',
          line: 2,
          message: 'Use === instead of ==',
        },
        {
          file: targetFile,
          rule: 'off-by-one',
          line: 3,
          message: 'Off-by-one loop boundary',
        },
      ];

      const res = await batchFixFile(tempDir, targetFile, findings, { noAi: true });
      assert.equal(res.applied.length, 2);
      assert.equal(res.skipped.length, 0);

      const updated = fs.readFileSync(targetFile, 'utf8');
      assert.ok(updated.includes('if (a === b) {'));
      assert.ok(updated.includes('for (let i = 0; i < items.length; i++) {'));
    });

    it('should combine deterministic fixes and send unresolved findings to AI batch repair', async () => {
      const targetFile = path.join(tempDir, 'hybrid-sample.py');
      const original = [
        'import os',
        'def process(data):',
        '    if status == None:',
        '        custom_unhandled_call(data)',
      ].join('\n');
      fs.writeFileSync(targetFile, original, 'utf8');

      let batchPromptReceived = null;
      const mockAiClient = {
        async repairFileBatch({ file, fileContent, findings, preferredModel, onModelSwitch }) {
          batchPromptReceived = { file, findings, preferredModel };
          return {
            fixes: [
              {
                oldSnippet: 'custom_unhandled_call(data)',
                newSnippet: 'safe_sanitized_call(data)',
                explanation: 'Replaced unhandled call with sanitized alternative',
              },
            ],
            modelUsed: 'minimax/minimax-m3:free',
          };
        },
      };

      const findings = [
        {
          file: targetFile,
          rule: 'E711',
          line: 3,
          message: 'Comparison to None should be "is None"',
        },
        {
          file: targetFile,
          rule: 'custom-unhandled',
          line: 4,
          message: 'Unsanitized data call',
        },
      ];

      const res = await batchFixFile(tempDir, targetFile, findings, {
        aiClient: mockAiClient,
        preferredModel: 'minimax/minimax-m3:free',
      });

      assert.equal(res.applied.length, 2);
      assert.ok(batchPromptReceived);
      // Deterministic fix should have resolved E711, leaving custom-unhandled for AI
      assert.equal(batchPromptReceived.findings.length, 1);
      assert.equal(batchPromptReceived.findings[0].rule, 'custom-unhandled');

      const updated = fs.readFileSync(targetFile, 'utf8');
      assert.ok(updated.includes('if status is None:'));
      assert.ok(updated.includes('safe_sanitized_call(data)'));
    });

    it('should notify onModelSwitch when token limits expire during batch repair', async () => {
      const targetFile = path.join(tempDir, 'switch-sample.js');
      fs.writeFileSync(targetFile, 'const x = raw_input();\n', 'utf8');

      let switchNotification = null;
      const mockAiClient = {
        async repairFileBatch({ onModelSwitch }) {
          if (typeof onModelSwitch === 'function') {
            onModelSwitch({
              failedModel: 'minimax/minimax-m3:free',
              nextModel: 'deepseek/deepseek-chat',
              error: 'API error 429: Token rate limit exceeded',
              isTokenExpire: true,
            });
          }
          return {
            fixes: [
              {
                oldSnippet: 'const x = raw_input();',
                newSnippet: 'const x = sanitize(raw_input());',
                explanation: 'Sanitized input',
              },
            ],
            modelUsed: 'deepseek/deepseek-chat',
            switchedFrom: 'minimax/minimax-m3:free',
          };
        },
      };

      const findings = [
        {
          file: targetFile,
          rule: 'tainted-input',
          line: 1,
          message: 'Tainted input',
        },
      ];

      const res = await batchFixFile(tempDir, targetFile, findings, {
        aiClient: mockAiClient,
        preferredModel: 'minimax/minimax-m3:free',
        onModelSwitch: (event) => {
          switchNotification = event;
        },
      });

      assert.ok(res);
      assert.equal(res.modelUsed, 'deepseek/deepseek-chat');
      assert.equal(res.switchedFrom, 'minimax/minimax-m3:free');
      assert.ok(switchNotification);
      assert.equal(switchNotification.failedModel, 'minimax/minimax-m3:free');
      assert.equal(switchNotification.nextModel, 'deepseek/deepseek-chat');
      assert.equal(switchNotification.isTokenExpire, true);
    });

    it('should return gracefully if file does not exist', async () => {
      const missingFile = path.join(tempDir, 'nonexistent.js');
      const findings = [{ file: missingFile, rule: 'foo', line: 1, message: 'bar' }];
      const res = await batchFixFile(tempDir, missingFile, findings);
      assert.ok(res.error);
      assert.equal(res.applied.length, 0);
      assert.equal(res.skipped.length, 1);
    });
  });
});
