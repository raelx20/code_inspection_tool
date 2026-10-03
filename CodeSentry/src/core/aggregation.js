const { SEVERITIES } = require('../findings/schema');

function aggregate(findings) {
  if (!Array.isArray(findings)) {
    throw new Error('findings must be an array');
  }

  const bySeverity = {};
  for (const s of SEVERITIES) {
    bySeverity[s] = 0;
  }

  const byCategory = {};
  const byTool = {};
  const byFile = {};

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    byTool[f.tool] = (byTool[f.tool] || 0) + 1;
    byFile[f.file] = (byFile[f.file] || 0) + 1;
  }

  return {
    total: findings.length,
    bySeverity,
    byCategory,
    byTool,
    byFile,
  };
}

module.exports = {
  aggregate,
};
