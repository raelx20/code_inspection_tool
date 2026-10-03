'use strict';

const { createFinding } = require('../findings/schema');

const SEVERITY_MAP = Object.freeze({
  BLOCKER: 'BLOCKER',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
  WARN: 'INFO',
});

function fallbackFile(rule) {
  const id = String(rule || '');
  if (id.startsWith('VG-PROV')) return '.visionguard/provenance.log';
  return '.visionguard';
}

function reportToFindings(report) {
  const findings = [];
  if (!report || typeof report !== 'object') return findings;
  const seen = new Set();
  const items = [...(Array.isArray(report.findings) ? report.findings : []), ...(Array.isArray(report.warnings) ? report.warnings : [])];
  for (const item of items) {
    if (!item || typeof item !== 'object' || !item.rule) continue;
    const severity = SEVERITY_MAP[item.severity] || 'MEDIUM';
    const file = item.path || fallbackFile(item.rule);
    const finding = createFinding({
      tool: 'visionguard',
      category: 'security',
      severity,
      file,
      line: null,
      rule: item.rule,
      ruleId: item.rule,
      message: item.detail || item.message || String(item.rule),
      confidence: 'high',
    });
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);
    findings.push(finding);
  }
  return findings;
}

module.exports = {
  reportToFindings,
};
