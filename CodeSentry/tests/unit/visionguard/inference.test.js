const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  recordInference,
  verifyInference,
  compareVersions,
  INFERENCE_FINDING_SEVERITY,
} = require('../../../src/visionguard/inference');
const { registerModel } = require('../../../src/visionguard/model');
const { registerPipeline } = require('../../../src/visionguard/pipeline');
const prov = require('../../../src/visionguard/provenance');
const store = require('../../../src/visionguard/store');
const { canonicalJson, hashRecord } = require('../../../src/visionguard/canonical');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

const FIXED_NOW = '2026-10-02T12:00:00.000Z';
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
    return true;
  });
}

function rules(result) {
  return result.findings.map((item) => item.rule);
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function u64le(value) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(value), 0);
  return buf;
}

function safetensorsBytes(data) {
  const header = JSON.stringify({ t: { dtype: 'F32', shape: [1], data_offsets: [0, 4] } });
  const payload = data || Buffer.from([0, 0, 0, 0]);
  return Buffer.concat([u64le(Buffer.byteLength(header, 'utf8')), Buffer.from(header, 'utf8'), payload]);
}

function writeFile(root, rel, content) {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
  return abs;
}

function makeFixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-infer-'));
  t.after(() => {
    try {
      fs.rmSync(parent, { recursive: true, force: true });
    } catch {
    }
  });
  const root = path.join(parent, 'root');
  const storeDir = path.join(parent, 'store');
  const keyDir = path.join(parent, 'keys');
  fs.mkdirSync(root, { recursive: true });
  return { parent, root, storeDir, keyDir };
}

function setup(t, options = {}) {
  const fx = makeFixture(t);
  const registration = prov.registerContributor({
    storeDir: fx.storeDir,
    keyDir: fx.keyDir,
    contributor: 'alice',
    operations: options.operations,
    now: FIXED_NOW,
  });
  fx.actor = { contributor: 'alice', key_id: registration.key_id };
  fx.keyFile = registration.privateKeyPath;
  fx.registration = registration;

  fx.modelPath = path.join(fx.parent, 'model.safetensors');
  fs.writeFileSync(fx.modelPath, safetensorsBytes());
  fx.model = registerModel({
    path: fx.modelPath,
    id: 'demo-model',
    version: '1.0.0',
    format: 'safetensors',
    actor: fx.actor,
    now: FIXED_NOW,
    storeDir: fx.storeDir,
  });

  writeFile(fx.root, 'pipeline.py', 'print("hello")\n');
  fx.pipeline = registerPipeline({
    root: fx.root,
    code: { files: [{ path: 'pipeline.py' }] },
    name: 'demo-pipeline',
    version: '1.0.0',
    actor: fx.actor,
    now: FIXED_NOW,
    storeDir: fx.storeDir,
  });

  fx.inputBytes = Buffer.from('sample input bytes\n');
  fx.outputBytes = Buffer.from('prediction: cat\n');
  writeFile(fx.root, 'inputs/sample.txt', fx.inputBytes);
  writeFile(fx.root, 'outputs/pred.txt', fx.outputBytes);
  fx.inputSha = sha256(fx.inputBytes);
  fx.outputSha = sha256(fx.outputBytes);
  fx.pipelineSha = fx.pipeline.pipeline_id.replace(/^sha256:/, '');
  return fx;
}

function record(fx, overrides = {}) {
  const fields = {
    storeDir: fx.storeDir,
    keyFile: fx.keyFile,
    actor: fx.actor,
    input: { artifact: 'inputs/sample.txt', sha256: fx.inputSha },
    model: { artifact: 'model/demo-model@1.0.0', sha256: fx.model.sha256 },
    pipeline: { artifact: 'pipeline/demo-pipeline@1.0.0', sha256: fx.pipelineSha },
    output: { artifact: 'outputs/pred.txt', sha256: fx.outputSha },
    params: { threshold: '0.5' },
    now: FIXED_NOW,
  };
  return recordInference({ ...fields, ...overrides });
}

function verify(fx, rec, options = {}) {
  return verifyInference({
    storeDir: fx.storeDir,
    recordId: rec.record_id,
    root: fx.root,
    now: FIXED_NOW,
    ...options,
  });
}

describe('VisionGuard inference recording', () => {
  it('should record an inference with the documented shape', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    assert.equal(rec.kind, 'inference_recorded');
    assert.equal(rec.record_id, rec.record_hash);
    assert.deepEqual(
      rec.inputs.map((item) => item.artifact),
      ['inputs/sample.txt', 'model/demo-model@1.0.0', 'pipeline/demo-pipeline@1.0.0']
    );
    assert.equal(rec.outputs.length, 1);
    assert.equal(rec.outputs[0].artifact, 'outputs/pred.txt');
    assert.deepEqual(rec.metadata.params, { threshold: '0.5' });
    assert.equal(rec.metadata.output_mode, 'raw');
    assert.equal(typeof rec.signature, 'string');
    assert.equal(rec.prev_record_hash, fx.registration.record.record_hash);
  });

  it('should record the opt-in canonical_json output mode', (t) => {
    const fx = setup(t);
    const rec = record(fx, { output_mode: 'canonical_json' });
    assert.equal(rec.metadata.output_mode, 'canonical_json');
  });

  it('should reject an unsupported output mode and deep params', (t) => {
    const fx = setup(t);
    throwsCode(() => record(fx, { output_mode: 'weird' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    let params = {};
    for (let i = 0; i < 8; i++) params = { nested: params };
    throwsCode(() => record(fx, { params }), ERROR_CODES.VG_LIMIT_METADATA);
    throwsCode(
      () => record(fx, { input: { artifact: 'model/demo-model@1.0.0', sha256: fx.model.sha256 } }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
  });

  it('should refuse an unauthorized key for the infer operation', (t) => {
    const fx = setup(t, { operations: ['train'] });
    throwsCode(() => record(fx), ERROR_CODES.VG_UNAUTHORIZED_OP);
  });

  it('should refuse a missing or mismatched key file', (t) => {
    const fx = setup(t);
    throwsCode(() => record(fx, { keyFile: undefined }), ERROR_CODES.VG_KEY_UNKNOWN);
    throwsCode(() => record(fx, { actor: { contributor: 'alice', key_id: 'f'.repeat(32) } }), ERROR_CODES.VG_KEY_UNKNOWN);
  });
});

describe('VisionGuard inference verification', () => {
  it('should PASS a valid inference and keep the provenance chain anchored', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    const result = verify(fx, rec, { modelPath: fx.modelPath });
    assert.equal(result.status, 'PASS');
    assert.equal(result.output_status, 'PASS');
    assert.deepEqual(result.findings, []);
    assert.equal(result.record.line, 2);

    const chain = prov.verifyProvenance({ storeDir: fx.storeDir, expectedHead: rec.record_hash, now: FIXED_NOW });
    assert.equal(chain.status, 'PASS');
    assert.deepEqual(chain.findings, []);
    assert.equal(chain.record_count, 2);
  });

  it('should skip file checks when no root is supplied', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    const result = verifyInference({ storeDir: fx.storeDir, recordId: rec.record_id, now: FIXED_NOW });
    assert.equal(result.status, 'PASS');
    assert.equal(result.output_status, 'NOT_CHECKED');
    assert.deepEqual(result.findings, []);
  });

  it('should detect a modified input file', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    fs.appendFileSync(path.join(fx.root, 'inputs', 'sample.txt'), 'tampered\n');
    const result = verify(fx, rec);
    assert.equal(result.status, 'FAIL');
    assert.equal(result.output_status, 'PASS');
    assert.deepEqual(rules(result), ['VG-INFER-001']);
    assert.match(result.findings[0].detail, /input file content/);
    assert.equal(result.findings[0].expected, rec.inputs[0].sha256);
    assert.match(result.findings[0].actual, /^[0-9a-f]{64}$/);
    assert.notEqual(result.findings[0].actual, result.findings[0].expected);
  });

  it('should detect a missing input file', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    fs.rmSync(path.join(fx.root, 'inputs', 'sample.txt'));
    const result = verify(fx, rec);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-INFER-001']);
  });

  it('should detect a modified model file', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    fs.writeFileSync(fx.modelPath, safetensorsBytes(Buffer.from([9, 9, 9, 9])));
    const result = verify(fx, rec, { modelPath: fx.modelPath });
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-INFER-003']);
    assert.match(result.findings[0].detail, /model file content/);
  });

  it('should detect a recorded model hash that contradicts the registration', (t) => {
    const fx = setup(t);
    const rec = record(fx, { model: { artifact: 'model/demo-model@1.0.0', sha256: 'a'.repeat(64) } });
    const result = verify(fx, rec);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-INFER-003']);
    assert.match(result.findings[0].detail, /does not match the registration/);
  });

  it('should detect an unregistered model reference', (t) => {
    const fx = setup(t);
    const rec = record(fx, { model: { artifact: 'model/ghost@9.9.9', sha256: 'b'.repeat(64) } });
    const result = verify(fx, rec);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-INFER-003']);
    assert.match(result.findings[0].detail, /not registered/);
  });

  it('should detect a stale model version after a newer registration', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    registerModel({
      path: fx.modelPath,
      id: 'demo-model',
      version: '2.0.0',
      format: 'safetensors',
      actor: fx.actor,
      now: FIXED_NOW,
      storeDir: fx.storeDir,
    });
    const result = verify(fx, rec);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-INFER-003']);
    assert.match(result.findings[0].detail, /stale/);
    assert.equal(result.findings[0].newer_version, '2.0.0');
  });

  it('should detect a modified output file', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    fs.appendFileSync(path.join(fx.root, 'outputs', 'pred.txt'), 'tampered\n');
    const result = verify(fx, rec);
    assert.equal(result.status, 'PASS');
    assert.equal(result.output_status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-OUT-001']);
    assert.equal(result.findings[0].severity, INFERENCE_FINDING_SEVERITY['VG-OUT-001']);
  });

  it('should detect a missing output file', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    fs.rmSync(path.join(fx.root, 'outputs', 'pred.txt'));
    const result = verify(fx, rec);
    assert.equal(result.output_status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-OUT-002']);
  });

  it('should detect a malformed output target', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    const outPath = path.join(fx.root, 'outputs', 'pred.txt');
    fs.rmSync(outPath);
    fs.mkdirSync(outPath);
    const result = verify(fx, rec);
    assert.equal(result.output_status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-OUT-002']);
    assert.match(result.findings[0].detail, /not a regular file/);
  });

  it('should detect outputs swapped between two records', (t) => {
    const fx = setup(t);
    const bytesA = Buffer.from('prediction A\n');
    const bytesB = Buffer.from('prediction B\n');
    writeFile(fx.root, 'outputs/pred-a.txt', bytesA);
    writeFile(fx.root, 'outputs/pred-b.txt', bytesB);
    const recA = record(fx, {
      output: { artifact: 'outputs/pred-a.txt', sha256: sha256(bytesA) },
    });
    const recB = record(fx, {
      output: { artifact: 'outputs/pred-b.txt', sha256: sha256(bytesB) },
    });
    fs.writeFileSync(path.join(fx.root, 'outputs', 'pred-a.txt'), bytesB);
    fs.writeFileSync(path.join(fx.root, 'outputs', 'pred-b.txt'), bytesA);

    const resultA = verify(fx, recA);
    assert.equal(resultA.output_status, 'FAIL');
    assert.deepEqual(rules(resultA), ['VG-OUT-003']);
    assert.match(resultA.findings[0].detail, /swapped/);

    const resultB = verify(fx, recB);
    assert.equal(resultB.output_status, 'FAIL');
    assert.deepEqual(rules(resultB), ['VG-OUT-003']);
  });

  it('should detect a missing parent reference', (t) => {
    const fx = setup(t);
    const rec = record(fx, { parents: ['sha256:' + 'f'.repeat(64)] });
    const result = verify(fx, rec);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-INFER-002']);
    assert.equal(result.findings[0].severity, INFERENCE_FINDING_SEVERITY['VG-INFER-002']);
  });

  it('should detect an unregistered pipeline reference', (t) => {
    const fx = setup(t);
    const rec = record(fx, {
      pipeline: { artifact: 'pipeline/ghost@1.0.0', sha256: 'c'.repeat(64) },
    });
    const result = verify(fx, rec);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-PIPE-001']);
    assert.match(result.findings[0].detail, /not registered/);
  });

  it('should detect a pipeline hash that contradicts the registration', (t) => {
    const fx = setup(t);
    const rec = record(fx, {
      pipeline: { artifact: 'pipeline/demo-pipeline@1.0.0', sha256: 'c'.repeat(64) },
    });
    const result = verify(fx, rec);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-PIPE-001']);
    assert.match(result.findings[0].detail, /does not match the registration/);
  });

  it('should report a missing record as an invalid inference record', (t) => {
    const fx = setup(t);
    record(fx);
    const unknown = verifyInference({
      storeDir: fx.storeDir,
      recordId: 'sha256:' + '9'.repeat(64),
      root: fx.root,
      now: FIXED_NOW,
    });
    assert.equal(unknown.status, 'FAIL');
    assert.deepEqual(rules(unknown), ['VG-INFER-001']);
    assert.match(unknown.findings[0].detail, /not found/);

    const wrongKind = verifyInference({
      storeDir: fx.storeDir,
      recordId: fx.registration.record.record_id,
      root: fx.root,
      now: FIXED_NOW,
    });
    assert.equal(wrongKind.status, 'FAIL');
    assert.deepEqual(rules(wrongKind), ['VG-INFER-001']);
    assert.match(wrongKind.findings[0].detail, /not an inference record/);
  });

  it('should report NOT_CHECKED when nothing was ever recorded', (t) => {
    const fx = makeFixture(t);
    store.ensureStoreDirs(fx.storeDir);
    const result = verifyInference({
      storeDir: fx.storeDir,
      recordId: 'sha256:' + '1'.repeat(64),
      now: FIXED_NOW,
    });
    assert.equal(result.status, 'NOT_CHECKED');
    assert.equal(result.output_status, 'NOT_CHECKED');
    assert.deepEqual(result.findings, []);
  });

  it('should not find a record whose metadata was altered after signing', (t) => {
    const fx = setup(t);
    const crafted = prov.buildRecord({
      kind: 'inference_recorded',
      actor: fx.actor,
      timestamp: FIXED_NOW,
      inputs: [
        { artifact: 'inputs/sample.txt', sha256: fx.inputSha },
        { artifact: 'model/demo-model@1.0.0', sha256: fx.model.sha256 },
        { artifact: 'pipeline/demo-pipeline@1.0.0', sha256: fx.pipelineSha },
      ],
      outputs: [{ artifact: 'outputs/pred.txt', sha256: fx.outputSha }],
      metadata: { params: {}, output_mode: 'weird' },
      prev_record_hash: fx.registration.record.record_hash,
    });
    store.appendLogLine(fx.storeDir, canonicalJson(crafted));
    const result = verifyInference({
      storeDir: fx.storeDir,
      recordId: crafted.record_id,
      root: fx.root,
      now: FIXED_NOW,
    });
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-INFER-001']);
  });
});

describe('VisionGuard provenance cross checks for inference refs', () => {
  it('should flag model and pipeline ref mismatches at log level', (t) => {
    const fx = setup(t);
    record(fx, { model: { artifact: 'model/demo-model@1.0.0', sha256: 'a'.repeat(64) } });
    record(fx, { pipeline: { artifact: 'pipeline/demo-pipeline@1.0.0', sha256: 'c'.repeat(64) } });
    const chain = prov.verifyProvenance({ storeDir: fx.storeDir, now: FIXED_NOW });
    const codes = chain.findings.filter((item) => item.rule === 'VG-PROV-011');
    assert.equal(codes.length, 2);
    assert.equal(chain.status, 'FAIL');
  });

  it('should verify a fully consistent chain against its anchor', (t) => {
    const fx = setup(t);
    const rec = record(fx);
    const chain = prov.verifyProvenance({
      storeDir: fx.storeDir,
      expectedHead: rec.record_hash,
      now: FIXED_NOW,
    });
    assert.equal(chain.status, 'PASS');
    assert.equal(chain.anchored, true);
    assert.equal(hashRecord(rec), rec.record_hash);
  });
});

describe('VisionGuard version comparison', () => {
  it('should order versions numerically per segment', () => {
    assert.equal(compareVersions('1.10.0', '1.9.0'), 1);
    assert.equal(compareVersions('2.0.0', '1.9.9'), 1);
    assert.equal(compareVersions('1.0.0', '1.0.1'), -1);
    assert.equal(compareVersions('1.0.0', '1.0.0'), 0);
    assert.equal(compareVersions('1.0', '1.0.0'), -1);
    assert.equal(compareVersions('1.0.0', '1.0'), 1);
  });
});
