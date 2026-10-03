const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_IGNORE_PATTERNS = [
  'node_modules',
  '.git',
  'dist',
  'build',
  '__pycache__',
  '.venv',
  'venv',
  'coverage',
  '.next',
  '.nuxt',
  'vendor',
  '.cache',
  '.nyc_output',
];

function loadIgnorePatterns(projectPath) {
  const ignoreFile = path.join(projectPath, '.codesentryignore');
  const patterns = [...DEFAULT_IGNORE_PATTERNS];

  try {
    const content = fs.readFileSync(ignoreFile, 'utf-8');
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      patterns.push(trimmed);
    }
  } catch {
    // No .codesentryignore file, use defaults only
  }

  return patterns;
}

function shouldIgnore(filePath, patterns, projectPath) {
  const relativePath = projectPath
    ? path.relative(projectPath, filePath)
    : filePath;

  const normalizedRelative = relativePath.replace(/\\/g, '/');

  for (const pattern of patterns) {
    const normalizedPattern = pattern.replace(/\\/g, '/');
    const cleanPattern = normalizedPattern.replace(/\/+$/, '');

    if (normalizedPattern.includes('*')) {
      if (matchGlob(normalizedRelative, normalizedPattern)) return true;
    } else {
      const parts = normalizedRelative.split('/');
      for (const part of parts) {
        if (part === cleanPattern) return true;
      }
      if (normalizedRelative === cleanPattern) return true;
      if (normalizedRelative.startsWith(cleanPattern + '/')) return true;
      if (normalizedRelative.endsWith('/' + cleanPattern)) return true;
      if (normalizedRelative.includes('/' + cleanPattern + '/')) return true;
    }
  }

  return false;
}

function matchGlob(str, pattern) {
  const regexStr = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '<<STARSTAR>>')
    .replace(/\*/g, '[^/]*')
    .replace(/<<STARSTAR>>/g, '.*');

  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(str);
}

module.exports = {
  loadIgnorePatterns,
  shouldIgnore,
  DEFAULT_IGNORE_PATTERNS,
};
