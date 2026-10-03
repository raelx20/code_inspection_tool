const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createConfig, DEFAULTS } = require('../../../src/core/config');
const path = require('node:path');

describe('Config', () => {
  it('should return defaults when no overrides provided', () => {
    const config = createConfig();
    assert.equal(config.projectPath, path.resolve(process.cwd()));
    assert.deepEqual(config.enabledAnalyzers, DEFAULTS.enabledAnalyzers);
    assert.equal(config.aiEnabled, true);
    assert.equal(config.severityThreshold, 'LOW');
    assert.equal(config.failOn, null);
  });

  it('should override defaults with provided values', () => {
    const config = createConfig({
      projectPath: '/tmp/test',
      aiEnabled: false,
      severityThreshold: 'HIGH',
      failOn: 'BLOCKER',
      validatePath: false,
    });
    assert.equal(config.projectPath, path.resolve('/tmp/test'));
    assert.equal(config.aiEnabled, false);
    assert.equal(config.severityThreshold, 'HIGH');
    assert.equal(config.failOn, 'BLOCKER');
  });

  it('should resolve projectPath to absolute', () => {
    const config = createConfig({ projectPath: 'relative/path', validatePath: false });
    assert.ok(path.isAbsolute(config.projectPath));
  });

  it('should freeze the config object', () => {
    const config = createConfig();
    config.newProp = 'test';
    assert.equal(config.newProp, undefined, 'frozen object should reject new properties');
  });

  it('should throw on invalid projectPath', () => {
    assert.throws(() => createConfig({ projectPath: 123 }), /projectPath must be/);
  });

  it('should throw on invalid enabledAnalyzers', () => {
    assert.throws(() => createConfig({ enabledAnalyzers: 'not-array' }), /must be an array/);
  });

  it('should throw on invalid aiEnabled', () => {
    assert.throws(() => createConfig({ aiEnabled: 'yes' }), /must be a boolean/);
  });

  it('should throw on invalid severityThreshold', () => {
    assert.throws(() => createConfig({ severityThreshold: 'CRITICAL' }), /Invalid severityThreshold/);
  });

  it('should throw on invalid failOn', () => {
    assert.throws(() => createConfig({ failOn: 'EXTREME' }), /Invalid failOn/);
  });

  it('should accept null for failOn', () => {
    const config = createConfig({ failOn: null });
    assert.equal(config.failOn, null);
  });

  it('should accept all valid severity levels for failOn', () => {
    const levels = ['BLOCKER', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    for (const level of levels) {
      const config = createConfig({ failOn: level });
      assert.equal(config.failOn, level);
    }
  });
});
