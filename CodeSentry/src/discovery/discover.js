const path = require('node:path');
const { enumerateFiles } = require('./files');
const { loadIgnorePatterns, shouldIgnore } = require('./ignore');
const { detectLanguage, SUPPORTED_LANGUAGES } = require('./language');

async function discover(config) {
  const projectPath = config.projectPath || process.cwd();

  const allFiles = enumerateFiles(projectPath);
  const ignorePatterns = loadIgnorePatterns(projectPath);

  const files = [];
  const languageMap = {};

  for (const lang of SUPPORTED_LANGUAGES) {
    languageMap[lang] = [];
  }

  for (const filePath of allFiles) {
    if (shouldIgnore(filePath, ignorePatterns, projectPath)) continue;

    const language = detectLanguage(filePath);
    if (!language) continue;

    const relativePath = path.relative(projectPath, filePath);
    files.push(relativePath);

    if (languageMap[language]) {
      languageMap[language].push(relativePath);
    }
  }

  const languages = Object.keys(languageMap).filter(lang => languageMap[lang].length > 0);

  return {
    files,
    languages,
    fileMap: languageMap,
    projectPath,
  };
}

module.exports = {
  discover,
};
