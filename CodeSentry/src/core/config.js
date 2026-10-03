const path = require('node:path');
const fs = require('node:fs');

const DEFAULTS = {
  projectPath: process.cwd(),
  enabledAnalyzers: ['eslint', 'typescript', 'ruff', 'bandit', 'semgrep'],
  aiEnabled: true,
  aiProvider: process.env.AI_PROVIDER || 'openrouter',
  aiModel: null,
  aiApiKey: null,
  severityThreshold: 'LOW',
  failOn: null,
  ignorePatterns: ['node_modules', '.git', 'dist', 'build', '__pycache__'],
  validatePath: true,
};

const SEVERITY_LEVELS = ['BLOCKER', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function createConfig(overrides = {}) {
  const config = { ...DEFAULTS, ...overrides };

  if (!config.projectPath || typeof config.projectPath !== 'string') {
    throw new Error('projectPath must be a non-empty string');
  }
  config.projectPath = path.resolve(config.projectPath);

  // Validate project path exists and is a directory (if enabled)
  if (config.validatePath) {
    try {
      const stats = fs.statSync(config.projectPath);
      if (!stats.isDirectory()) {
        throw new Error(`projectPath must be a directory: ${config.projectPath}`);
      }
    } catch (err) {
      if (err.code === 'ENOENT') {
        throw new Error(`projectPath does not exist: ${config.projectPath}`);
      }
      throw err;
    }
  }

  if (!Array.isArray(config.enabledAnalyzers)) {
    throw new Error('enabledAnalyzers must be an array');
  }

  if (typeof config.aiEnabled !== 'boolean') {
    throw new Error('aiEnabled must be a boolean');
  }

  if (config.severityThreshold && !SEVERITY_LEVELS.includes(config.severityThreshold)) {
    throw new Error(`Invalid severityThreshold: "${config.severityThreshold}"`);
  }

  if (config.failOn && !SEVERITY_LEVELS.includes(config.failOn)) {
    throw new Error(`Invalid failOn: "${config.failOn}"`);
  }

  if (!Array.isArray(config.ignorePatterns)) {
    throw new Error('ignorePatterns must be an array');
  }

  return Object.freeze(config);
}

module.exports = {
  createConfig,
  DEFAULTS,
  SEVERITY_LEVELS,
};
