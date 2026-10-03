const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const demo = require('../../../scripts/visionguard-demo');
const prov = require('../../../src/visionguard/provenance');
const vgStore = require('../../../src/visionguard/store');
const { verifyDataset } = require('../../../src/visionguard/manifest');
const { verifyModel, sniffFormat } = require('../../../src/visionguard/model');
const { verifyInference } = require('../../../src/visionguard/inference');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

const NOW1 = Date.UTC(2026, 9, 2, 12, 0, 0);
const NOW2 = Date.UTC(2026, 9, 2, 13, 0, 0);

let parent;
let clean;
let target;

function readLog(storeDir) {
  const text = fs.readFileSync(path.join(storeDir, 'provenance.log'), 'utf8');
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function privateKeyPath(outDir, report, contributor) {
  return path.join(outDir, 'keys', contributor, `${report.contributors[contributor].key_id}.key`);
}

before(() => {
  parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-demo-'));
  clean = { outDir: path.join(parent, 'clean'), report: null };
  target = { outDir: path.join(parent, 'target'), report: null };
  clean.report = demo.runDemo({ outDir: clean.outDir, now: NOW1 });
  target.report = demo.runDemo({ outDir: target.outDir, now: NOW2 });
});

after(() => {
  try {
    fs.rmSync(parent, { recursive: true, force: true });
  } catch {
  }
});

describe('VisionGuard CV pipeline demo', () => {
  it('should verify every dimension and re-execute identically on the happy path', () => {
    const report = clean.report;
    assert.equal(report.overall, 'VERIFIED');
    for (const [name, dimension] of Object.entries(report.dimensions)) {
      assert.equal(dimension.status, 'PASS', `${name} expected PASS, got ${dimension.status}`);
    }
    assert.equal(report.dimensions.provenance.anchored, true);
    assert.equal(report.dimensions.provenance.records, 9);
    assert.equal(report.dimensions.provenance.warnings, 0);
    assert.equal(report.reexecution.identical, true);
    assert.equal(report.reexecution.expected_sha256, report.reexecution.actual_sha256);
    assert.equal(report.dataset.files, 32);
    assert.equal(report.model.format, 'safetensors');
    assert.equal(report.inference.label, 'circle');
    assert.ok(fs.existsSync(path.join(report.storeDir, 'anchors', 'head.txt')));
    const prediction = JSON.parse(fs.readFileSync(path.join(report.outDir, 'outputs', 'prediction.json'), 'utf8'));
    assert.equal(prediction.label, 'circle');
    assert.equal(prediction.input, 'inputs/input.png');
    assert.equal(prediction.model, `model/${demo.MODEL_ID}@${demo.MODEL_VERSION}`);
  });

  it('should register four contributors with least-privilege operations and separate key stores', () => {
    const operations = Object.fromEntries(
      Object.entries(clean.report.contributors).map(([name, entry]) => [name, entry.operations])
    );
    assert.deepEqual(operations, {
      A: ['curate_dataset'],
      B: ['preprocess'],
      C: ['train', 'export_model'],
      D: ['infer']
    });
    for (const [name, entry] of Object.entries(clean.report.contributors)) {
      assert.match(entry.key_id, /^[0-9a-f]{32}$/);
      assert.ok(fs.existsSync(path.join(clean.outDir, 'keys', name, `${entry.key_id}.key`)));
      assert.ok(fs.existsSync(path.join(clean.report.storeDir, 'keys', name, `${entry.key_id}.pub.json`)));
    }
  });

  it('should append a signed hash-linked chain of nine records in dependency order', () => {
    const records = readLog(clean.report.storeDir).map((line) => JSON.parse(line));
    assert.equal(records.length, 9);
    assert.deepEqual(
      records.map((record) => record.kind),
      [
        'contributor_registered',
        'contributor_registered',
        'contributor_registered',
        'contributor_registered',
        'artifact_registered',
        'operation_recorded',
        'artifact_registered',
        'operation_recorded',
        'inference_recorded'
      ]
    );
    assert.deepEqual(
      records.map((record) => record.actor.contributor),
      ['A', 'B', 'C', 'D', 'A', 'B', 'B', 'C', 'D']
    );
    assert.equal(records[0].prev_record_hash, null);
    for (let i = 1; i < records.length; i++) {
      assert.equal(records[i].prev_record_hash, records[i - 1].record_hash);
    }
    const hashes = new Set(records.map((record) => record.record_hash));
    for (const record of records) {
      assert.equal(record.record_id, record.record_hash);
      assert.equal(typeof record.signature, 'string');
      assert.ok(record.signature.length > 0);
      for (const parentHash of record.parent_record_hashes) {
        assert.ok(hashes.has(parentHash), `parent ${parentHash} must exist earlier in the log`);
      }
    }
    const inference = records[records.length - 1];
    assert.deepEqual(
      inference.inputs.map((item) => item.artifact),
      [demo.INPUT_REF, `model/${demo.MODEL_ID}@${demo.MODEL_VERSION}`, `pipeline/${demo.PIPELINE_NAME}@${demo.PIPELINE_VERSION}`]
    );
    assert.equal(inference.outputs.length, 1);
    assert.equal(inference.outputs[0].artifact, demo.OUTPUT_REF);
  });

  it('should produce byte-identical artifacts across independent runs', () => {
    assert.equal(clean.report.dataset.merkle_root, target.report.dataset.merkle_root);
    assert.equal(clean.report.model.sha256, target.report.model.sha256);
    assert.equal(clean.report.pipeline.pipeline_id, target.report.pipeline.pipeline_id);
    assert.equal(
      clean.report.dimensions.output.expected_sha256,
      target.report.dimensions.output.expected_sha256
    );
  });

  it('should reject operations the signing contributor is not authorized for', () => {
    const storeDir = clean.report.storeDir;
    const attempt = (contributor, operation) =>
      prov.recordOperation({
        storeDir,
        keyFile: privateKeyPath(clean.outDir, clean.report, contributor),
        actor: { contributor, key_id: clean.report.contributors[contributor].key_id },
        operation,
        inputs: [{ artifact: `dataset/${demo.DATASET_NAME}@${demo.DATASET_VERSION}`, sha256: 'a'.repeat(64) }],
        outputs: [{ artifact: 'file/x.bin', sha256: 'b'.repeat(64) }],
        now: NOW1 + 90000
      });
    for (const [contributor, operation] of [
      ['D', 'curate_dataset'],
      ['B', 'infer'],
      ['A', 'train']
    ]) {
      assert.throws(
        () => attempt(contributor, operation),
        (err) => {
          assert.ok(isVgError(err), `expected VgError, got ${err && err.message}`);
          assert.equal(err.code, ERROR_CODES.VG_UNAUTHORIZED_OP);
          return true;
        },
        `${contributor} must not be allowed to ${operation}`
      );
    }
    assert.equal(readLog(storeDir).length, 9, 'rejected operations must not append to the log');
  });

  it('should refuse to reuse a directory that already contains a provenance log', () => {
    assert.throws(
      () => demo.runDemo({ outDir: clean.outDir, now: NOW1 }),
      /already contains a VisionGuard store/
    );
  });

  it('should generate deterministic dataset bytes', () => {
    const dirA = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-ds-a-'));
    const dirB = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-ds-b-'));
    try {
      const first = demo.generateDataset(dirA);
      const second = demo.generateDataset(dirB);
      assert.equal(first.count, 32);
      assert.deepEqual(
        first.files.map((file) => file.sha256),
        second.files.map((file) => file.sha256)
      );
    } finally {
      fs.rmSync(dirA, { recursive: true, force: true });
      fs.rmSync(dirB, { recursive: true, force: true });
    }
  });

  it('should detect exactly one modified dataset file', () => {
    const victim = path.join(target.outDir, 'dataset', 'circle', '00.png');
    const bytes = fs.readFileSync(victim);
    bytes[100] = bytes[100] ^ 0xff;
    fs.writeFileSync(victim, bytes);
    const manifest = vgStore.loadDatasetManifest(target.report.storeDir, demo.DATASET_NAME, demo.DATASET_VERSION);
    const result = verifyDataset({ manifest, path: path.join(target.outDir, 'dataset') });
    assert.equal(result.status, 'FAIL');
    const hits = result.findings.filter((finding) => finding.rule === 'VG-DATA-001');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].path, 'circle/00.png');
    assert.match(hits[0].detail, /content changed/);
  });

  it('should detect a modified model file', () => {
    const modelPath = path.join(target.outDir, 'model', `${demo.MODEL_ID}.safetensors`);
    const bytes = fs.readFileSync(modelPath);
    bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0xff;
    fs.writeFileSync(modelPath, bytes);
    const manifest = vgStore.loadModelManifest(target.report.storeDir, demo.MODEL_ID, demo.MODEL_VERSION);
    const result = verifyModel({ manifest, path: modelPath });
    assert.equal(result.status, 'FAIL');
    const hits = result.findings.filter((finding) => finding.rule === 'VG-MODEL-001');
    assert.equal(hits.length, 1);
    assert.match(hits[0].detail, /content changed/);
  });

  it('should detect a tampered prediction output with expected and actual hashes differing', () => {
    const outputPath = path.join(target.outDir, 'outputs', 'prediction.json');
    fs.appendFileSync(outputPath, '\n');
    const result = verifyInference({
      storeDir: target.report.storeDir,
      recordId: target.report.inference.record_id,
      root: target.outDir
    });
    assert.equal(result.status, 'PASS');
    assert.equal(result.output_status, 'FAIL');
    assert.ok(result.findings.some((finding) => finding.rule === 'VG-OUT-001'));
    const actual = demo.sha256Hex(fs.readFileSync(outputPath));
    assert.notEqual(actual, target.report.dimensions.output.expected_sha256);
  });

  it('should detect a modified inference input', () => {
    const inputPath = path.join(target.outDir, 'inputs', 'input.png');
    const bytes = fs.readFileSync(inputPath);
    bytes[50] = bytes[50] ^ 0xff;
    fs.writeFileSync(inputPath, bytes);
    const result = verifyInference({
      storeDir: target.report.storeDir,
      recordId: target.report.inference.record_id,
      root: target.outDir
    });
    assert.equal(result.status, 'FAIL');
    assert.ok(
      result.findings.some(
        (finding) => finding.rule === 'VG-INFER-001' && /input file content does not match/.test(finding.detail)
      )
    );
  });
});

describe('VisionGuard demo codecs', () => {
  it('should roundtrip grayscale PNGs and reject corrupted chunks', () => {
    const width = 16;
    const height = 16;
    const pixels = Buffer.alloc(width * height);
    for (let i = 0; i < pixels.length; i++) pixels[i] = (i * 7) % 256;
    const png = demo.encodePngGray(width, height, pixels);
    const decoded = demo.decodePngGray(png);
    assert.equal(decoded.width, width);
    assert.equal(decoded.height, height);
    assert.deepEqual(decoded.pixels, pixels);
    const corrupted = Buffer.from(png);
    corrupted[corrupted.length - 20] = corrupted[corrupted.length - 20] ^ 0xff;
    assert.throws(() => demo.decodePngGray(corrupted), /CRC/);
    assert.throws(() => demo.decodePngGray(Buffer.from('not a png at all')), /not a PNG/);
  });

  it('should roundtrip safetensors tensors and satisfy the magic-byte sniffer', () => {
    const data = new Float64Array([0.25, -1.5, 3, 4.75]);
    const bytes = demo.writeSafetensors(
      [{ name: 'centroids', shape: [2, 2], data }],
      { classes: '["a","b"]' }
    );
    const read = demo.readSafetensors(bytes);
    assert.deepEqual(read.tensors.centroids.shape, [2, 2]);
    for (let i = 0; i < data.length; i++) {
      assert.equal(read.tensors.centroids.data[i], Math.fround(data[i]));
    }
    assert.equal(read.header.__metadata__.classes, '["a","b"]');
    const sniff = sniffFormat(bytes, bytes.length, 'demo.safetensors');
    assert.equal(sniff.detected, 'safetensors');
    assert.equal(sniff.magicOk, true);
    assert.equal(sniff.pickleBased, false);
    assert.throws(() => demo.readSafetensors(Buffer.alloc(4)), /too small/);
  });
});

describe('VisionGuard demo CLI', () => {
  it('should run from the command line with stable exit codes', () => {
    const script = path.join(__dirname, '..', '..', '..', 'scripts', 'visionguard-demo.js');
    const cliOut = path.join(parent, 'cli');
    const run = spawnSync(process.execPath, [script, '--json', '--out', cliOut], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    const report = JSON.parse(run.stdout);
    assert.equal(report.overall, 'VERIFIED');
    assert.equal(report.reexecution.identical, true);
    const bad = spawnSync(process.execPath, [script, '--bogus'], { encoding: 'utf8' });
    assert.equal(bad.status, 2);
    const help = spawnSync(process.execPath, [script, '--help'], { encoding: 'utf8' });
    assert.equal(help.status, 0);
    assert.match(help.stdout, /Usage: node scripts\/visionguard-demo\.js/);
  });
});
