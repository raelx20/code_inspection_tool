const fs = require('node:fs');
const path = require('node:path');

const SKIP_DIRS = new Set([
  '.git',
  '.svn',
  '.hg',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '__pycache__',
  '.venv',
  'venv',
  '.env',
  'coverage',
  '.nyc_output',
  '.cache',
  '.temp',
  '.tmp',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
  '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.woff', '.woff2', '.ttf', '.eot',
  '.sqlite', '.db',
]);

function enumerateFiles(projectPath, options = {}) {
  const { maxDepth = 10, includeBinary = false } = options;
  const results = [];

  function walk(currentPath, depth) {
    if (depth > maxDepth) return;

    let entries;
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      if (entry.isDirectory()) {
        const dirName = path.basename(fullPath);
        if (SKIP_DIRS.has(dirName)) continue;
        if (dirName.startsWith('.') && dirName !== '.') continue;
        walk(fullPath, depth + 1);
        continue;
      }

      if (!entry.isFile() && !entry.isSymbolicLink()) continue;

      const ext = path.extname(fullPath).toLowerCase();
      if (!includeBinary && BINARY_EXTENSIONS.has(ext)) continue;

      results.push(fullPath);
    }
  }

  walk(projectPath, 0);
  return results;
}

module.exports = {
  enumerateFiles,
  SKIP_DIRS,
  BINARY_EXTENSIONS,
};
