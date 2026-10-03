const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createCommandParser, COMMANDS } = require('../../../src/cli/commands');

describe('CommandParser', () => {
  it('should parse default scan command with no extra flags', () => {
    const parser = createCommandParser();
    const parsed = parser.parse(['scan']);
    assert.equal(parsed.command, COMMANDS.SCAN);
    assert.equal(parsed.options.noAi, undefined);
    assert.equal(parsed.options.noReport, undefined);
  });

  it('should parse --no-ai flag', () => {
    const parser = createCommandParser();
    const parsed = parser.parse(['scan', '.', '--no-ai']);
    assert.equal(parsed.command, COMMANDS.SCAN);
    assert.equal(parsed.options.noAi, true);
  });

  it('should parse --no-report flag', () => {
    const parser = createCommandParser();
    const parsed = parser.parse(['scan', '.', '--no-report']);
    assert.equal(parsed.command, COMMANDS.SCAN);
    assert.equal(parsed.options.noReport, true);
  });

  it('should parse --report-file flag', () => {
    const parser = createCommandParser();
    const parsed = parser.parse(['scan', '.', '--report-file', 'custom-report.md']);
    assert.equal(parsed.command, COMMANDS.SCAN);
    assert.equal(parsed.options.reportFile, 'custom-report.md');
  });

  it('should parse --ai-model flag', () => {
    const parser = createCommandParser();
    const parsed = parser.parse(['scan', '.', '--ai-model', 'custom/model:free']);
    assert.equal(parsed.command, COMMANDS.SCAN);
    assert.equal(parsed.options.aiModel, 'custom/model:free');
  });

  it('should parse model command', () => {
    const parser = createCommandParser();
    const parsed = parser.parse(['model']);
    assert.equal(parsed.command, COMMANDS.MODEL);
  });

  it('should parse auth and login commands', () => {
    const parser = createCommandParser();
    const parsedAuth = parser.parse(['auth']);
    assert.equal(parsedAuth.command, COMMANDS.AUTH);

    const parsedLogin = parser.parse(['login']);
    assert.equal(parsedLogin.command, COMMANDS.AUTH);
  });

  it('should display updated help text indicating defaults and auth command', () => {
    const parser = createCommandParser();
    const help = parser.getHelp();
    assert.ok(help.includes('--no-ai'));
    assert.ok(help.includes('--no-report'));
    assert.ok(help.includes('--report-file'));
    assert.ok(help.includes('ON by default'));
    assert.ok(help.includes('model'));
    assert.ok(help.includes('auth'));
    assert.ok(help.includes('--fix'));
    assert.ok(help.includes('--yes'));
  });

  it('should parse --fix and --auto-fix flags', () => {
    const parser = createCommandParser();
    const parsed1 = parser.parse(['scan', '.', '--fix']);
    assert.equal(parsed1.options.fix, true);

    const parsed2 = parser.parse(['scan', '.', '--auto-fix']);
    assert.equal(parsed2.options.fix, true);
  });

  it('should parse --yes and -y flags enabling automated repair without manual approval', () => {
    const parser = createCommandParser();
    const parsed1 = parser.parse(['scan', '.', '--yes']);
    assert.equal(parsed1.options.yes, true);
    assert.equal(parsed1.options.fix, true);

    const parsed2 = parser.parse(['scan', '.', '-y']);
    assert.equal(parsed2.options.yes, true);
    assert.equal(parsed2.options.fix, true);
  });
});
