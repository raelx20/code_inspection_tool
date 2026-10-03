const path = require('node:path');

const EXTENSION_MAP = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.py': 'python',
  '.pyw': 'python',
};

const SUPPORTED_LANGUAGES = [...new Set(Object.values(EXTENSION_MAP))];

function getLanguageFromExtension(ext) {
  const normalized = ext.toLowerCase();
  return EXTENSION_MAP[normalized] || null;
}

function detectLanguage(filePath) {
  const ext = path.extname(filePath);
  return getLanguageFromExtension(ext);
}

function getSupportedExtensions() {
  return Object.keys(EXTENSION_MAP);
}

function isSupportedFile(filePath) {
  return detectLanguage(filePath) !== null;
}

module.exports = {
  detectLanguage,
  getLanguageFromExtension,
  getSupportedExtensions,
  isSupportedFile,
  EXTENSION_MAP,
  SUPPORTED_LANGUAGES,
};
