const { SEVERITIES } = require('./schema');

function deduplicate(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return [];

  const groups = new Map();

  for (const finding of findings) {
    const key = finding.fingerprint;
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key).push(finding);
  }

  const deduplicated = [];
  for (const group of groups.values()) {
    if (group.length === 1) {
      deduplicated.push(group[0]);
    } else {
      deduplicated.push(keepHighestSeverity(group));
    }
  }

  return deduplicated;
}

function keepHighestSeverity(findings) {
  let best = findings[0];
  let bestIdx = SEVERITIES.indexOf(best.severity);

  for (let i = 1; i < findings.length; i++) {
    const idx = SEVERITIES.indexOf(findings[i].severity);
    if (idx < bestIdx) {
      best = findings[i];
      bestIdx = idx;
    }
  }

  return best;
}

function getDuplicateGroups(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return [];

  const groups = new Map();
  for (const finding of findings) {
    const key = finding.fingerprint;
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key).push(finding);
  }

  const duplicates = [];
  for (const group of groups.values()) {
    if (group.length > 1) {
      duplicates.push(group);
    }
  }

  return duplicates;
}

module.exports = {
  deduplicate,
  keepHighestSeverity,
  getDuplicateGroups,
};
