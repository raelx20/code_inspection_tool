const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const demo = require('../../../scripts/visionguard-demo');
const { scan } = require('../../../src/core/scan');
const { createVisionGuard, applyVisionGuardToScan, reportToFindings } = require('../../../src/visionguard');
const { createCommandParser, COMMANDS, OPTIONS } = require('../../../src/cli/commands');
const { TOOLS, createFinding } = require('../../../src/findings/schema');
const { createReportGenerator } = require('../../../src/cli/report');
const { createFormatter } = require('../../../src/cli/formatter');
const { aggregate } = require('../../../src/core/aggregation');
const { score } = require('../../../src/core/scoring');
const { verdict } = require('../../../src/core/verdict');
const { isVgError } = require('../../../src/visionguard/errors');
const { runAssurance, DIMENSION_NAMES } = require('../../../src/visionguard/assurance');

const NOW = Date.UTC(2026, 9, 2, 12, 0, 0);

let parent;
let base;

before(() => {
  delete process.env.VG_EXPECTED_HEAD;
  parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-int-'));
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

function fakeResult(root, extra = {}) {
  const agg = aggregate([]);
  const sc = score(agg);
  return {
    project: { name: 'fixture', path: root },
    filesAnalyzed: 0,
    languages: [],
    findings: [],
    aggregation: agg,
    score: sc,
    verdict: verdict(sc),
    riskGraph: null,
    metadata: { errors: [], timestamp: '2026-10-02T12:00:00.000Z', duration: 1 },
    ...extra,
  };
}

function flipByte(file) {
  const bytes = fs.readFileSync(file);
  bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0xff;
  fs.writeFileSync(file, bytes);
}

describe('commands seam', () => {
  const parser = createCommandParser();

  it('should parse --vision and --require-verified for scan', () => {
    const parsed = parser.parse(['scan', '.', '--vision', '--require-verified']);
    assert.equal(parsed.command, COMMANDS.SCAN);
    assert.equal(parsed.options.vision, true);
    assert.equal(parsed.options.requireVerified, true);
    assert.deepEqual(parsed.errors, []);
  });

  it('should leave vision options unset by default', () => {
    const parsed = parser.parse(['scan', '.']);
    assert.equal(parsed.options.vision, undefined);
    assert.equal(parsed.options.requireVerified, undefined);
  });

  it('should reject unknown flags as before', () => {
    const parsed = parser.parse(['scan', '.', '--bogus-vision']);
    assert.ok(parsed.errors.length > 0);
  });

  it('should document both flags and an example in help', () => {
    const help = parser.getHelp();
    assert.ok(help.includes('--vision'));
    assert.ok(help.includes('--require-verified'));
    assert.ok(help.includes('--vision --json'));
    assert.equal(OPTIONS.VISION, '--vision');
    assert.equal(OPTIONS.REQUIRE_VERIFIED, '--require-verified');
  });
});

describe('finding schema seam', () => {
  it('should accept visionguard as a finding tool', () => {
    assert.ok(TOOLS.includes('visionguard'));
    const finding = createFinding({
      tool: 'visionguard',
      category: 'security',
      severity: 'HIGH',
      file: 'dataset/a.png',
      rule: 'VG-DATA-001',
      message: 'content changed',
    });
    assert.equal(finding.tool, 'visionguard');
    assert.equal(finding.category, 'security');
    assert.equal(finding.legacyCategory, 'vulnerability');
    assert.equal(finding.ruleId, 'VG-DATA-001');
  });

  it('should still reject unknown tools', () => {
    assert.throws(
      () => createFinding({ tool: 'not-a-tool', category: 'security', file: 'a', message: 'm' }),
      /Invalid tool/
    );
  });
});

describe('applyVisionGuardToScan', () => {
  it('should attach a VERIFIED report without touching score or verdict', () => {
    const root = scenario('adapter-clean');
    const result = fakeResult(root);
    const applied = applyVisionGuardToScan(result, { root });
    assert.equal(applied.report.overall, 'VERIFIED');
    assert.equal(applied.addedFindings, 0);
    assert.equal(applied.exitCode, 0);
    assert.equal(result.visionGuard, applied.report);
    assert.equal(result.verdict.status, 'PASS');
    assert.equal(result.verdict.message, 'Codebase meets quality thresholds.');
    assert.equal(result.aggregation.total, 0);
    for (const name of DIMENSION_NAMES) {
      assert.equal(result.visionGuard.dimensions[name].status, 'PASS', name);
    }
  });

  it('should force FAIL, exit 1 and merge findings on an integrity violation', () => {
    const root = scenario('adapter-tampered');
    flipByte(path.join(root, 'dataset', 'triangle', '01.png'));
    const result = fakeResult(root);
    const applied = applyVisionGuardToScan(result, { root });
    assert.equal(applied.report.overall, 'INTEGRITY VIOLATION');
    assert.equal(applied.exitCode, 1);
    assert.equal(applied.addedFindings, 1);
    assert.equal(result.verdict.status, 'FAIL');
    assert.match(result.verdict.message, /^VisionGuard integrity violation:/);
    assert.ok(result.verdict.message.includes('dataset'));
    assert.equal(result.verdict.score, result.score.value);
    assert.equal(result.aggregation.total, 1);
    assert.equal(result.aggregation.byTool.visionguard, 1);
    assert.ok(result.score.value < result.score.max);
    const vgFindings = result.findings.filter((item) => item.tool === 'visionguard');
    assert.equal(vgFindings.length, 1);
    assert.equal(vgFindings[0].rule, 'VG-DATA-001');
  });

  it('should not double count a visionguard finding already present', () => {
    const root = scenario('adapter-dedupe');
    flipByte(path.join(root, 'dataset', 'square', '02.png'));
    const seed = createFinding({
      tool: 'visionguard',
      category: 'security',
      severity: 'BLOCKER',
      file: 'dataset/square/02.png',
      rule: 'VG-DATA-001',
      message: 'content changed',
    });
    const result = fakeResult(root, { findings: [seed] });
    const applied = applyVisionGuardToScan(result, { root });
    assert.equal(applied.addedFindings, 0);
    assert.equal(result.findings.length, 1);
    assert.equal(result.aggregation.total, 1);
    assert.equal(result.aggregation.byTool.visionguard, 1);
    assert.equal(result.verdict.status, 'FAIL');
  });

  it('should return exit 0 for INCOMPLETE unless requireVerified is set', () => {
    const root = path.join(parent, 'adapter-storeless');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, 'app.js'), 'module.exports = 1;\n');
    const first = fakeResult(root);
    const applied = applyVisionGuardToScan(first, { root });
    assert.equal(applied.report.overall, 'INCOMPLETE');
    assert.equal(applied.exitCode, 0);
    assert.equal(first.verdict.status, 'PASS');
    const second = fakeResult(root);
    const strictApplied = applyVisionGuardToScan(second, { root, requireVerified: true });
    assert.equal(strictApplied.exitCode, 1);
    assert.equal(second.verdict.status, 'PASS');
    assert.equal(second.verdict.message, 'Codebase meets quality thresholds.');
  });

  it('should inject provenance nodes and edges into an existing risk graph', () => {
    const root = scenario('adapter-graph');
    const riskGraph = {
      graph: {
        nodes: new Map([['n1', { id: 'n1', type: 'FILE', label: 'index.js' }]]),
        edges: [{ from: 'n1', to: 'n1', type: 'CALLS' }],
        attackPaths: [],
      },
      summary: { nodeCount: 1, edgeCount: 1, attackPaths: [], hasExploitablePaths: false },
      terminalOutput: null,
      mermaidOutput: '',
    };
    const result = fakeResult(root, { riskGraph });
    const applied = applyVisionGuardToScan(result, { root });
    const graph = result.riskGraph.graph;
    assert.equal(graph.nodes.has('n1'), true);
    const vgNodeIds = [...graph.nodes.keys()].filter((id) => id.startsWith('vg-'));
    const expectedVgNodes =
      applied.report.graph.artifacts.length + applied.report.graph.contributors.length;
    assert.equal(vgNodeIds.length, expectedVgNodes);
    assert.ok(graph.nodes.has('vg-contributor:A'));
    assert.ok(graph.nodes.has(`vg-artifact:dataset/${demo.DATASET_NAME}@${demo.DATASET_VERSION}`));
    assert.equal(graph.edges.some((edge) => edge.type === 'CALLS'), true);
    assert.equal(graph.edges.filter((edge) => edge.type === 'TRUSTS').length, applied.report.graph.trusts.length);
    assert.equal(
      graph.edges.filter((edge) => edge.type === 'DERIVED_FROM').length,
      applied.report.graph.derivedFrom.length
    );
    assert.equal(result.riskGraph.summary.nodeCount, graph.nodes.size);
    assert.equal(result.riskGraph.summary.edgeCount, graph.edges.length);
  });

  it('should tolerate a result without a risk graph', () => {
    const root = scenario('adapter-clean');
    const result = fakeResult(root, { riskGraph: undefined });
    const applied = applyVisionGuardToScan(result, { root });
    assert.equal(applied.report.overall, 'VERIFIED');
    assert.equal(result.riskGraph, undefined);
  });
});

describe('scan pipeline integration', () => {
  let scanned;

  before(async () => {
    const root = scenario('scan-demo');
    scanned = { root, result: await scan(root, { projectPath: root, aiEnabled: false, onProgress: () => {} }) };
  });

  it('should verify a signed store end to end and leave core signals untouched', () => {
    const { root, result } = scanned;
    const beforeTotal = result.aggregation.total;
    const beforeVerdict = result.verdict.status;
    const applied = applyVisionGuardToScan(result, { root });
    assert.equal(applied.report.overall, 'VERIFIED');
    assert.equal(result.visionGuard.overall, 'VERIFIED');
    assert.equal(applied.exitCode, 0);
    assert.equal(result.aggregation.total, beforeTotal);
    assert.equal(result.verdict.status, beforeVerdict);
  });

  it('should expose injected graph nodes through the scan risk graph summary', () => {
    const { result } = scanned;
    const graph = result.riskGraph.graph;
    const vgNodeIds = [...graph.nodes.keys()].filter((id) => id.startsWith('vg-'));
    assert.ok(vgNodeIds.length > 0);
    assert.equal(result.riskGraph.summary.nodeCount, graph.nodes.size);
    assert.equal(result.riskGraph.summary.edgeCount, graph.edges.length);
    assert.ok(graph.edges.some((edge) => edge.type === 'TRUSTS'));
    assert.ok(graph.edges.some((edge) => edge.type === 'DERIVED_FROM'));
  });

  it('should render the VisionGuard section in the markdown report', () => {
    const { root, result } = scanned;
    const outputDir = path.join(parent, 'report-out');
    fs.mkdirSync(outputDir, { recursive: true });
    const generator = createReportGenerator({ outputDir, filename: 'vision.md' });
    const reportPath = generator.generate(result);
    const markdown = fs.readFileSync(reportPath, 'utf8');
    assert.ok(markdown.includes('VisionGuard Integrity Assurance'));
    assert.ok(markdown.includes('**Overall**: **VERIFIED**'));
    assert.ok(markdown.includes('| Dataset Integrity | PASS |'));
    assert.ok(markdown.includes('Every dimension verified against signed records'));
  });

  it('should render the VisionGuard line in the terminal summary', () => {
    const { result } = scanned;
    const formatter = createFormatter();
    const lines = formatter.formatSummary(result).join('\n');
    assert.ok(lines.includes('VisionGuard:'));
    assert.ok(lines.includes('VERIFIED'));
    assert.match(lines, /dataset:? PASS/);
  });
});

describe('report and formatter guards', () => {
  it('should omit the VisionGuard section when the scan had no assurance run', () => {
    const outputDir = path.join(parent, 'report-plain');
    fs.mkdirSync(outputDir, { recursive: true });
    const plain = fakeResult(path.join(parent, 'nowhere'));
    const generator = createReportGenerator({ outputDir, filename: 'plain.md' });
    const reportPath = generator.generate(plain);
    const markdown = fs.readFileSync(reportPath, 'utf8');
    assert.equal(markdown.includes('VisionGuard'), false);
    const lines = createFormatter().formatSummary(plain).join('\n');
    assert.equal(lines.includes('VisionGuard'), false);
  });

  it('should surface a forced integrity violation in report and terminal output', () => {
    const root = scenario('adapter-report-violation');
    flipByte(path.join(root, 'model', `${demo.MODEL_ID}.safetensors`));
    const result = fakeResult(root);
    applyVisionGuardToScan(result, { root });
    const outputDir = path.join(parent, 'report-violation');
    fs.mkdirSync(outputDir, { recursive: true });
    const generator = createReportGenerator({ outputDir, filename: 'violation.md' });
    const reportPath = generator.generate(result);
    const markdown = fs.readFileSync(reportPath, 'utf8');
    assert.ok(markdown.includes('VisionGuard Integrity Assurance'));
    assert.ok(markdown.includes('**Overall**: **INTEGRITY VIOLATION**'));
    assert.ok(markdown.includes('| Model Integrity | FAIL |'));
    assert.ok(markdown.includes('Integrity violation'));
    const lines = createFormatter().formatSummary(result).join('\n');
    assert.ok(lines.includes('VisionGuard:'));
    assert.ok(lines.includes('INTEGRITY VIOLATION'));
    assert.match(lines, /model:? FAIL/);
  });
});

describe('vision guard facade', () => {
  it('should support the documented lifecycle on a fresh store', async () => {
    const root = path.join(parent, 'facade-fresh');
    const dataDir = path.join(root, 'data');
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, 'a.txt'), 'alpha\n');
    fs.writeFileSync(path.join(dataDir, 'b.txt'), 'beta\n');

    const vg = createVisionGuard({ root, now: NOW });
    await assert.rejects(
      () => vg.recordOperation({ op: 'preprocess', inputs: [], outputs: [] }),
      (err) => isVgError(err)
    );

    const registration = await vg.init({
      contributor: 'alice',
      operations: ['curate_dataset', 'preprocess'],
      keyDir: path.join(root, 'keys'),
    });
    assert.equal(registration.contributor, 'alice');
    assert.match(registration.key_id, /^[0-9a-f]{32}$/);
    assert.ok(registration.record_id);
    assert.deepEqual(registration.operations, ['curate_dataset', 'preprocess']);

    const manifestDoc = await vg.registerDataset({ path: dataDir, name: 'facade-ds', version: '1.0.0' });
    assert.equal(manifestDoc.name, 'facade-ds');
    assert.ok(manifestDoc.merkle_root.startsWith('sha256:'));

    const verification = await vg.verifyDataset({ name: 'facade-ds', version: '1.0.0', path: dataDir });
    assert.equal(verification.status, 'UNANCHORED');

    const record = await vg.recordOperation({
      op: 'preprocess',
      inputs: [{ artifact: 'dataset/facade-ds@1.0.0', sha256: manifestDoc.merkle_root.replace(/^sha256:/, '') }],
      outputs: [{ artifact: 'file/features.bin', sha256: '1'.repeat(64) }],
    });
    assert.ok(record.record_hash);
    assert.equal(record.operation, 'preprocess');

    await assert.rejects(
      () =>
        vg.recordOperation({
          op: 'train',
          inputs: [{ artifact: 'file/features.bin', sha256: '1'.repeat(64) }],
          outputs: [{ artifact: 'file/model.bin', sha256: '2'.repeat(64) }],
        }),
      (err) => isVgError(err)
    );

    const report = await vg.verifyAll();
    assert.equal(report.store.present, true);
    assert.equal(report.overall, 'INCOMPLETE');
    assert.equal(report.dimensions.provenance.status, 'UNANCHORED');
  });

  it('should verify the demo store and walk lineage through the facade', async () => {
    const root = scenario('facade-demo');
    const vg = createVisionGuard({ root, now: NOW });
    const report = await vg.verifyAll();
    assert.equal(report.overall, 'VERIFIED');

    const output = await vg.verifyOutput({ recordId: base.report.inference.record_id });
    assert.equal(output.status, 'PASS');
    assert.equal(output.output_status, 'PASS');

    const ancestors = await vg.lineage({ artifact: 'outputs/prediction.json' });
    assert.ok(ancestors.length >= 3);
    assert.ok(ancestors.some((record) => record.kind === 'inference_recorded'));
    assert.ok(ancestors.some((record) => record.kind === 'operation_recorded'));
    assert.ok(ancestors.some((record) => record.kind === 'contributor_registered'));
    for (const record of ancestors) {
      assert.ok(record.record_hash);
    }
    assert.equal(ancestors[ancestors.length - 1].kind, 'inference_recorded');
  });
});

describe('assurance report cross-check', () => {
  it('should keep runAssurance and the adapter report consistent', () => {
    const root = scenario('adapter-crosscheck');
    const direct = runAssurance({ root, ...requests(), now: NOW });
    const result = fakeResult(root);
    const applied = applyVisionGuardToScan(result, { root });
    assert.equal(applied.report.overall, direct.overall);
    assert.deepEqual(
      Object.fromEntries(DIMENSION_NAMES.map((name) => [name, applied.report.dimensions[name].status])),
      Object.fromEntries(DIMENSION_NAMES.map((name) => [name, direct.dimensions[name].status]))
    );
    const directFindings = reportToFindings(direct);
    const adapterFindings = result.findings.filter((item) => item.tool === 'visionguard');
    assert.deepEqual(
      adapterFindings.map((item) => item.rule).sort(),
      directFindings.map((item) => item.rule).sort()
    );
  });
});
