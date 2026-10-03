const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const demo = require('../../../scripts/visionguard-demo');
const { runAssurance, DIMENSION_NAMES } = require('../../../src/visionguard/assurance');
const { reportToFindings } = require('../../../src/visionguard/findings');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');
const vgStore = require('../../../src/visionguard/store');

const NOW = Date.UTC(2026, 9, 2, 12, 0, 0);

let parent;
let base;

before(() => {
  delete process.env.VG_EXPECTED_HEAD;
  parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-assur-'));
  base = { outDir: path.join(parent, 'base'), report: null };
  base.report = demo.runDemo({ outDir: base.outDir, now: NOW });
});

after(() => {
  try {
    fs.rmSync(parent, { recursive: true, force: true });
  } catch {
  }
});

function scenario(name) {
  const outDir = path.join(parent, name);
  fs.cpSync(base.outDir, outDir, { recursive: true });
  return outDir;
}

function requests() {
  return {
    dataset: { name: demo.DATASET_NAME, version: demo.DATASET_VERSION },
    model: { name: demo.MODEL_ID, version: demo.MODEL_VERSION },
    inference: { recordId: base.report.inference.record_id },
  };
}

function run(root, extra = {}) {
  return runAssurance({ root, ...requests(), now: NOW, ...extra });
}

function findingRules(report) {
  return report.findings.map((item) => item.rule);
}

function flipByte(file) {
  const bytes = fs.readFileSync(file);
  bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0xff;
  fs.writeFileSync(file, bytes);
}

describe('runAssurance happy path', () => {
  it('should report VERIFIED with all six dimensions PASS on an untampered demo', () => {
    const root = scenario('clean');
    const report = run(root);
    assert.equal(report.schema_version, '1.0');
    assert.equal(report.kind, 'assurance_report');
    assert.equal(report.overall, 'VERIFIED');
    assert.equal(report.anchored, true);
    assert.deepEqual(report.store, { present: true, valid: true, error: null });
    for (const name of DIMENSION_NAMES) {
      assert.equal(report.dimensions[name].status, 'PASS', `${name} expected PASS`);
    }
    assert.equal(report.dimensions.dataset.entries.length, 1);
    assert.equal(report.dimensions.dataset.entries[0].located, true);
    assert.equal(report.dimensions.dataset.entries[0].signed_binding, true);
    assert.equal(report.dimensions.dataset.signed_binding, true);
    assert.equal(report.findings.length, 0);
    assert.equal(report.warnings.length, 0);
    assert.equal(report.errors.length, 0);
  });

  it('should build a provenance graph with artifacts, contributors, trusts and derivations', () => {
    const root = scenario('clean-graph');
    const report = run(root);
    const refs = report.graph.artifacts.map((item) => item.ref);
    assert.ok(refs.includes(`dataset/${demo.DATASET_NAME}@${demo.DATASET_VERSION}`));
    assert.ok(refs.includes(`model/${demo.MODEL_ID}@${demo.MODEL_VERSION}`));
    assert.deepEqual(
      report.graph.contributors.map((item) => item.contributor).sort(),
      ['A', 'B', 'C', 'D']
    );
    for (const item of report.graph.contributors) {
      assert.ok(item.key_ids.length >= 1, `${item.contributor} must carry a key id`);
    }
    assert.ok(report.graph.trusts.length > 0);
    assert.ok(report.graph.derivedFrom.length > 0);
    for (const item of report.graph.trusts) {
      assert.ok(item.contributor && item.ref);
    }
    for (const item of report.graph.derivedFrom) {
      assert.ok(item.from && item.to && item.from !== item.to);
    }
  });
});

describe('runAssurance tamper detection', () => {
  it('should fail the dataset dimension on a modified dataset file', () => {
    const root = scenario('tamper-dataset');
    flipByte(path.join(root, 'dataset', 'circle', '00.png'));
    const report = run(root);
    assert.equal(report.overall, 'INTEGRITY VIOLATION');
    assert.equal(report.dimensions.dataset.status, 'FAIL');
    assert.equal(report.dimensions.model.status, 'PASS');
    assert.equal(report.dimensions.inference.status, 'PASS');
    assert.ok(findingRules(report).includes('VG-DATA-001'));
    const hit = report.findings.find((item) => item.rule === 'VG-DATA-001');
    assert.equal(hit.path, 'dataset/circle/00.png');
    assert.match(hit.detail, /content changed/);
  });

  it('should fail the model dimension on a modified model file', () => {
    const root = scenario('tamper-model');
    flipByte(path.join(root, 'model', `${demo.MODEL_ID}.safetensors`));
    const report = run(root);
    assert.equal(report.overall, 'INTEGRITY VIOLATION');
    assert.equal(report.dimensions.model.status, 'FAIL');
    assert.equal(report.dimensions.dataset.status, 'PASS');
    assert.ok(findingRules(report).includes('VG-MODEL-001'));
  });

  it('should fail the model dimension when the model file is missing', () => {
    const root = scenario('missing-model');
    fs.rmSync(path.join(root, 'model'), { recursive: true, force: true });
    const report = run(root);
    assert.equal(report.dimensions.model.status, 'FAIL');
    assert.equal(report.overall, 'INTEGRITY VIOLATION');
    assert.ok(findingRules(report).includes('VG-MODEL-001'));
  });

  it('should fail the pipeline dimension when pipeline code is modified', () => {
    const root = scenario('tamper-pipeline');
    fs.appendFileSync(path.join(root, 'pipeline.js'), '\n// tampered\n');
    const report = run(root);
    assert.equal(report.overall, 'INTEGRITY VIOLATION');
    assert.equal(report.dimensions.pipeline.status, 'FAIL');
    assert.ok(findingRules(report).some((rule) => rule.startsWith('VG-PIPE')));
    assert.equal(report.dimensions.dataset.status, 'PASS');
    assert.equal(report.dimensions.model.status, 'PASS');
  });

  it('should fail the output dimension while inference stays PASS', () => {
    const root = scenario('tamper-output');
    fs.appendFileSync(path.join(root, 'outputs', 'prediction.json'), '\n');
    const report = run(root);
    assert.equal(report.overall, 'INTEGRITY VIOLATION');
    assert.equal(report.dimensions.output.status, 'FAIL');
    assert.equal(report.dimensions.inference.status, 'PASS');
    assert.ok(findingRules(report).includes('VG-OUT-001'));
  });

  it('should fail the inference dimension on a modified input while output stays PASS', () => {
    const root = scenario('tamper-input');
    flipByte(path.join(root, 'inputs', 'input.png'));
    const report = run(root);
    assert.equal(report.overall, 'INTEGRITY VIOLATION');
    assert.equal(report.dimensions.inference.status, 'FAIL');
    assert.equal(report.dimensions.output.status, 'PASS');
    assert.ok(findingRules(report).includes('VG-INFER-001'));
  });

  it('should fail the dataset dimension when registered dataset files are missing', () => {
    const root = scenario('missing-dataset');
    fs.rmSync(path.join(root, 'dataset'), { recursive: true, force: true });
    const report = run(root);
    assert.equal(report.dimensions.dataset.status, 'FAIL');
    assert.equal(report.overall, 'INTEGRITY VIOLATION');
    assert.ok(findingRules(report).includes('VG-DATA-002'));
  });
});

describe('runAssurance anchor and store handling', () => {
  it('should report UNANCHORED and INCOMPLETE when the anchor file is deleted', () => {
    const root = scenario('missing-anchor');
    fs.rmSync(path.join(root, '.visionguard', 'anchors', 'head.txt'));
    const report = run(root);
    assert.equal(report.dimensions.provenance.status, 'UNANCHORED');
    assert.ok(report.anchored !== true);
    assert.equal(report.overall, 'INCOMPLETE');
    assert.equal(report.dimensions.dataset.status, 'PASS');
    assert.equal(report.dimensions.model.status, 'PASS');
  });

  it('should fail provenance with VG-PROV-008 when the anchor head is wrong', () => {
    const root = scenario('wrong-anchor');
    fs.writeFileSync(
      path.join(root, '.visionguard', 'anchors', 'head.txt'),
      `sha256:${'0'.repeat(64)}`
    );
    const report = run(root);
    assert.equal(report.dimensions.provenance.status, 'FAIL');
    assert.equal(report.anchored, false);
    assert.equal(report.overall, 'INTEGRITY VIOLATION');
    assert.ok(findingRules(report).includes('VG-PROV-008'));
  });

  it('should force VG-PROV-001 and FAIL provenance on an unreadable store.json', () => {
    const root = scenario('bad-store-json');
    fs.writeFileSync(vgStore.storeJsonPath(path.join(root, '.visionguard')), '{ not json');
    const report = run(root);
    assert.equal(report.store.present, true);
    assert.equal(report.store.valid, false);
    assert.equal(report.dimensions.provenance.status, 'FAIL');
    assert.equal(report.overall, 'INTEGRITY VIOLATION');
    assert.ok(findingRules(report).includes('VG-PROV-001'));
  });

  it('should return INCOMPLETE with every dimension NOT_CHECKED when no store exists', () => {
    const root = path.join(parent, 'storeless');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, 'app.js'), 'module.exports = 1;\n');
    const report = runAssurance({ root, now: NOW });
    assert.equal(report.store.present, false);
    assert.equal(report.overall, 'INCOMPLETE');
    for (const name of DIMENSION_NAMES) {
      assert.equal(report.dimensions[name].status, 'NOT_CHECKED', name);
    }
    assert.equal(report.findings.length, 0);
    assert.equal(report.warnings.length, 0);
    assert.deepEqual(report.graph, { artifacts: [], contributors: [], trusts: [], derivedFrom: [] });
  });
});

describe('runAssurance request validation', () => {
  it('should reject a request for an unregistered dataset', () => {
    const root = scenario('clean');
    assert.throws(
      () => run(root, { dataset: { name: 'nope', version: '9.9.9' } }),
      (err) => {
        assert.ok(isVgError(err), `expected VgError, got ${err && err.message}`);
        assert.equal(err.code, ERROR_CODES.VG_NOT_REGISTERED);
        return true;
      }
    );
  });

  it('should reject a request for an unregistered model', () => {
    const root = scenario('clean');
    assert.throws(
      () => run(root, { model: { name: 'ghost-model', version: '0.0.1' } }),
      (err) => {
        assert.ok(isVgError(err));
        assert.equal(err.code, ERROR_CODES.VG_NOT_REGISTERED);
        return true;
      }
    );
  });

  it('should reject an explicit inference record that is not in the log', () => {
    const root = scenario('clean');
    assert.throws(
      () => run(root, { inference: { recordId: 'sha256:' + 'f'.repeat(64) } }),
      (err) => {
        assert.ok(isVgError(err));
        return true;
      }
    );
  });
});

describe('reportToFindings', () => {
  it('should produce no findings for a clean VERIFIED report', () => {
    const root = scenario('clean');
    const report = run(root);
    assert.deepEqual(reportToFindings(report), []);
  });

  it('should map report findings to valid visionguard CodeSentry findings', () => {
    const root = scenario('findings-map');
    flipByte(path.join(root, 'dataset', 'cross', '03.png'));
    const report = run(root);
    assert.ok(report.findings.length >= 1);
    const findings = reportToFindings(report);
    assert.ok(findings.length >= 1);
    assert.ok(findings.length <= report.findings.length);
    const ids = new Set();
    for (const finding of findings) {
      assert.equal(finding.tool, 'visionguard');
      assert.equal(finding.category, 'security');
      assert.equal(finding.ruleId, finding.rule);
      assert.ok(finding.message.length > 0);
      assert.ok(finding.file.length > 0);
      assert.ok(['BLOCKER', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(finding.severity));
      assert.equal(ids.has(finding.id), false, 'finding ids must be unique within a report');
      ids.add(finding.id);
    }
    assert.ok(findings.some((finding) => finding.rule === 'VG-DATA-001'));
    assert.ok(findings.some((finding) => finding.file === 'dataset/cross/03.png'));
  });

  it('should downgrade WARN severities to INFO and fill fallback file paths', () => {
    const findings = reportToFindings({
      findings: [],
      warnings: [
        { rule: 'VG-PROV-009', severity: 'WARN', detail: 'unsigned records present' },
        { rule: 'VG-DATA-009', severity: 'WARN', path: 'dataset/x.bin', detail: 'policy note' },
      ],
    });
    assert.equal(findings.length, 2);
    for (const finding of findings) {
      assert.equal(finding.severity, 'INFO');
      assert.equal(finding.tool, 'visionguard');
    }
    assert.equal(findings[0].file, '.visionguard/provenance.log');
    assert.equal(findings[1].file, 'dataset/x.bin');
  });

  it('should tolerate malformed report shapes', () => {
    assert.deepEqual(reportToFindings(null), []);
    assert.deepEqual(reportToFindings(undefined), []);
    assert.deepEqual(reportToFindings({}), []);
    assert.deepEqual(reportToFindings({ findings: [{ severity: 'HIGH' }], warnings: [null, 7] }), []);
  });
});
