const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  registerModel,
  verifyModel,
  validateModelManifest,
  sniffFormat,
  MODEL_FORMATS,
  MODEL_FINDING_SEVERITY,
} = require('../../../src/visionguard/model');
const { loadModelManifest } = require('../../../src/visionguard/store');
const { hashRecord } = require('../../../src/visionguard/canonical');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

const FIXED_NOW = '2026-10-02T12:00:00.000Z';
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const PICKLE_HEAD = Buffer.from([0x80, 0x02]);

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

function makeFixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-model-'));
  t.after(() => {
    try {
      fs.rmSync(parent, { recursive: true, force: true });
    } catch {
    }
  });
  return { parent };
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

function writeModel(parent, name, bytes) {
  const filePath = path.join(parent, name);
  fs.writeFileSync(filePath, bytes);
  return filePath;
}

function register(filePath, options = {}) {
  return registerModel({
    path: filePath,
    id: options.id || 'demo-model',
    version: options.version || '1.0.0',
    format: options.format || 'safetensors',
    actor: options.actor || { contributor: 'tester', key_id: null },
    metadata: options.metadata,
    now: FIXED_NOW,
    storeDir: options.storeDir,
    limits: options.limits,
  });
}

function verify(filePath, manifest) {
  return verifyModel({ path: filePath, manifest, now: FIXED_NOW });
}

describe('VisionGuard model format sniffing', () => {
  it('should detect a valid safetensors header', () => {
    const bytes = safetensorsBytes();
    const result = sniffFormat(bytes, bytes.length, 'model.safetensors');
    assert.equal(result.detected, 'safetensors');
    assert.equal(result.magicOk, true);
    assert.equal(result.pickleBased, false);
    assert.match(result.detail, /safetensors header observed/);
  });

  it('should reject a safetensors header that extends past end of file', () => {
    const bytes = safetensorsBytes();
    const result = sniffFormat(bytes, bytes.length - 40, 'model.safetensors');
    assert.equal(result.detected, 'other');
    assert.equal(result.magicOk, true);
    assert.match(result.detail, /past end of file/);
  });

  it('should reject a safetensors header that is not valid JSON', () => {
    const broken = Buffer.from('{"broken": }', 'utf8');
    const bytes = Buffer.concat([u64le(broken.length), broken, Buffer.alloc(4)]);
    const result = sniffFormat(bytes, bytes.length, 'model.safetensors');
    assert.equal(result.detected, 'other');
    assert.equal(result.magicOk, true);
    assert.match(result.detail, /not valid JSON/);
  });

  it('should accept a huge safetensors header by plausibility without parsing it', () => {
    const headerLength = 1024 * 1024 + 1;
    const head = Buffer.concat([u64le(headerLength), Buffer.from('{', 'utf8')]);
    const size = 8 + headerLength + 4;
    const result = sniffFormat(head, size, 'model.safetensors');
    assert.equal(result.detected, 'safetensors');
    assert.equal(result.magicOk, true);
    assert.match(result.detail, /too large to parse/);
  });

  it('should report an empty file', () => {
    const result = sniffFormat(Buffer.alloc(0), 0, 'model.safetensors');
    assert.equal(result.detected, 'other');
    assert.equal(result.magicOk, false);
    assert.equal(result.detail, 'file is empty');
  });

  it('should detect an onnx file by its protobuf header byte', () => {
    const good = Buffer.concat([Buffer.from([0x08, 0x02]), Buffer.alloc(14)]);
    const goodResult = sniffFormat(good, good.length, 'model.onnx');
    assert.equal(goodResult.detected, 'onnx');
    assert.equal(goodResult.magicOk, true);

    const bad = Buffer.concat([Buffer.from([0x00]), Buffer.alloc(15)]);
    const badResult = sniffFormat(bad, bad.length, 'model.onnx');
    assert.equal(badResult.detected, 'onnx');
    assert.equal(badResult.magicOk, false);
    assert.match(badResult.detail, /0x08/);
  });

  it('should detect a zip-based torch archive', () => {
    const bytes = Buffer.concat([ZIP_MAGIC, Buffer.alloc(20)]);
    const result = sniffFormat(bytes, bytes.length, 'model.pt');
    assert.equal(result.detected, 'pt');
    assert.equal(result.magicOk, true);
    assert.equal(result.pickleBased, false);
    assert.match(result.detail, /zip container/);
  });

  it('should detect a pickle-based torch file', () => {
    const bytes = Buffer.concat([PICKLE_HEAD, Buffer.from('torch payload', 'utf8'), Buffer.alloc(8)]);
    const result = sniffFormat(bytes, bytes.length, 'model.pth');
    assert.equal(result.detected, 'pth');
    assert.equal(result.magicOk, true);
    assert.equal(result.pickleBased, true);
    assert.match(result.detail, /pickle/);
  });

  it('should fail magic for a .pt file carrying PNG bytes', () => {
    const bytes = Buffer.concat([PNG_MAGIC, Buffer.alloc(20)]);
    const result = sniffFormat(bytes, bytes.length, 'model.pt');
    assert.equal(result.detected, 'pt');
    assert.equal(result.magicOk, false);
    assert.equal(result.pickleBased, false);
  });

  it('should classify unknown bytes as the "other" format', () => {
    const bytes = Buffer.concat([PNG_MAGIC, Buffer.alloc(20)]);
    const result = sniffFormat(bytes, bytes.length, 'image.png');
    assert.equal(result.detected, 'other');
    assert.equal(result.magicOk, true);
    assert.equal(result.pickleBased, false);
  });
});

describe('VisionGuard model registration', () => {
  it('should register a valid safetensors file', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    const manifest = register(filePath);

    assert.equal(manifest.schema_version, '1.0');
    assert.equal(manifest.kind, 'model_manifest');
    assert.equal(manifest.id, 'demo-model');
    assert.equal(manifest.version, '1.0.0');
    assert.equal(manifest.format, 'safetensors');
    assert.equal(manifest.detected_format, 'safetensors');
    assert.equal(manifest.size, fs.statSync(filePath).size);
    assert.match(manifest.sha256, /^[0-9a-f]{64}$/);
    assert.equal(manifest.created_at, FIXED_NOW);
    assert.deepEqual(manifest.actor, { contributor: 'tester', key_id: null });
    assert.deepEqual(manifest.metadata, {});
    assert.equal(manifest.record_hash, hashRecord(manifest));
    assert.equal(manifest.signature, null);
  });

  it('should reject an unsupported declared format', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    throwsCode(() => register(filePath, { format: 'pickle' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should reject a declared format that does not match the file family', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'weights.dat', safetensorsBytes());
    throwsCode(() => register(filePath, { format: 'pt' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should reject a .pt file without a zip or pickle signature', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.pt', Buffer.concat([PNG_MAGIC, Buffer.alloc(20)]));
    throwsCode(() => register(filePath, { format: 'pt' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should reject an empty model file', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', Buffer.alloc(0));
    assert.throws(
      () => register(filePath),
      (err) => {
        assert.ok(isVgError(err));
        assert.equal(err.code, ERROR_CODES.VG_MANIFEST_SCHEMA);
        assert.match(err.message, /empty/);
        return true;
      }
    );
  });

  it('should reject a missing model file', (t) => {
    const { parent } = makeFixture(t);
    throwsCode(() => register(path.join(parent, 'absent.safetensors')), ERROR_CODES.VG_UNREADABLE);
  });

  it('should reject an id that is not a safe label', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    throwsCode(() => register(filePath, { id: '../escape' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should refuse to register a model reached through a symbolic link', (t) => {
    const { parent } = makeFixture(t);
    const target = writeModel(parent, 'real.safetensors', safetensorsBytes());
    const linkPath = path.join(parent, 'link.safetensors');
    try {
      fs.symlinkSync(target, linkPath);
    } catch (err) {
      t.skip(`symlink creation unavailable: ${err.code}`);
      return;
    }
    throwsCode(() => register(linkPath), ERROR_CODES.VG_SYMLINK_DENIED);
  });

  it('should reject metadata that nests deeper than the limit', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    let shallow = { leaf: 1 };
    for (let i = 0; i < 5; i++) shallow = { nested: shallow };
    register(filePath, { metadata: shallow });
    let deep = { leaf: 1 };
    for (let i = 0; i < 6; i++) deep = { nested: deep };
    throwsCode(() => register(filePath, { metadata: deep }), ERROR_CODES.VG_LIMIT_METADATA);
  });

  it('should reject metadata larger than the byte limit', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    throwsCode(
      () => register(filePath, { metadata: { blob: 'x'.repeat(5000) } }),
      ERROR_CODES.VG_LIMIT_METADATA
    );
  });

  it('should reject metadata values that cannot be canonicalized', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    throwsCode(() => register(filePath, { metadata: { lr: 0.001 } }), ERROR_CODES.VG_CANONICAL_INVALID);
  });
});

describe('VisionGuard model verification', () => {
  it('should verify an untouched model as PASS', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    const manifest = register(filePath);

    const result = verify(filePath, manifest);
    assert.equal(result.status, 'PASS');
    assert.equal(result.kind, 'model_verification');
    assert.equal(result.schema_version, '1.0');
    assert.equal(result.id, 'demo-model');
    assert.equal(result.version, '1.0.0');
    assert.equal(result.checked_at, FIXED_NOW);
    assert.deepEqual(result.findings, []);
    assert.deepEqual(result.manifestConsistency, { recordHashValid: true });
    assert.deepEqual(result.expected, {
      format: 'safetensors',
      size: manifest.size,
      sha256: manifest.sha256,
    });
    assert.equal(result.actual.size, manifest.size);
    assert.equal(result.actual.sha256, manifest.sha256);
    assert.equal(result.actual.detected_format, 'safetensors');
    assert.equal(result.actual.magicOk, true);
    assert.equal(result.actual.pickleBased, false);
    assert.equal(result.signaturePresent, false);
  });

  it('should FAIL a model modified in place', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    const manifest = register(filePath);
    const bytes = fs.readFileSync(filePath);
    bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0xff;
    fs.writeFileSync(filePath, bytes);

    const result = verify(filePath, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-MODEL-001']);
    assert.equal(result.findings[0].severity, 'BLOCKER');
    assert.equal(result.actual.size, manifest.size);
    assert.notEqual(result.actual.sha256, manifest.sha256);
    assert.equal(result.actual.detected_format, 'safetensors');
    assert.equal(result.actual.magicOk, true);
  });

  it('should FAIL a same-size replacement file', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    const manifest = register(filePath);
    fs.writeFileSync(filePath, safetensorsBytes(Buffer.from([1, 2, 3, 4])));

    const result = verify(filePath, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-MODEL-001']);
    assert.equal(result.actual.size, manifest.size);
    assert.notEqual(result.actual.sha256, manifest.sha256);
  });

  it('should FAIL a truncated model with a magic mismatch', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    const manifest = register(filePath);
    const full = fs.readFileSync(filePath);
    fs.writeFileSync(filePath, full.subarray(0, 40));

    const result = verify(filePath, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-MODEL-001', 'VG-MODEL-002']);
    assert.notEqual(result.actual.sha256, manifest.sha256);
    assert.equal(result.actual.detected_format, 'other');
  });

  it('should FAIL an emptied model with only the empty finding', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    const manifest = register(filePath);
    fs.writeFileSync(filePath, Buffer.alloc(0));

    const result = verify(filePath, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-MODEL-003']);
    assert.equal(result.findings[0].severity, 'BLOCKER');
    assert.equal(result.actual.size, 0);
    assert.equal(result.actual.sha256, null);
    assert.equal(result.actual.detail, 'file is empty');
  });

  it('should FAIL a deleted model file', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    const manifest = register(filePath);
    fs.unlinkSync(filePath);

    const result = verify(filePath, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-MODEL-001']);
    assert.equal(result.findings[0].detail, 'missing from disk');
    assert.equal(result.actual, null);
  });

  it('should FAIL a tampered model manifest', (t) => {
    const { parent } = makeFixture(t);
    const storeDir = path.join(parent, 'store');
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    const manifest = register(filePath, { storeDir });
    const manifestPath = path.join(storeDir, 'manifests', 'model', 'demo-model', '1.0.0.json');
    const tampered = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    tampered.actor.contributor = 'mallory';
    fs.writeFileSync(manifestPath, JSON.stringify(tampered, null, 2));

    const loaded = loadModelManifest(storeDir, 'demo-model', '1.0.0');
    const result = verify(filePath, loaded);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-MODEL-006']);
    assert.equal(result.findings[0].severity, 'BLOCKER');
    assert.equal(result.manifestConsistency.recordHashValid, false);
    assert.equal(result.actual.sha256, loaded.sha256);
  });

  it('should report a pickle-based model without failing it (canary stays untouched)', (t) => {
    const { parent } = makeFixture(t);
    const payload = Buffer.concat([PICKLE_HEAD, Buffer.from('echo pwned > marker.txt', 'utf8')]);
    const filePath = writeModel(parent, 'model.pt', payload);
    const manifest = register(filePath, { format: 'pt' });
    assert.equal(manifest.detected_format, 'pt');

    const result = verify(filePath, manifest);
    assert.equal(result.status, 'PASS');
    assert.deepEqual(rules(result), ['VG-MODEL-005']);
    assert.equal(result.findings[0].severity, 'HIGH');
    assert.equal(result.actual.pickleBased, true);
    assert.equal(fs.existsSync(path.join(parent, 'marker.txt')), false);
    assert.equal(fs.existsSync(path.join(process.cwd(), 'marker.txt')), false);
  });

  it('should FAIL a model whose magic bytes no longer match', (t) => {
    const { parent } = makeFixture(t);
    const bytes = Buffer.concat([ZIP_MAGIC, Buffer.alloc(60)]);
    const filePath = writeModel(parent, 'model.pt', bytes);
    const manifest = register(filePath, { format: 'pt' });
    assert.equal(manifest.detected_format, 'pt');
    fs.writeFileSync(filePath, Buffer.concat([PNG_MAGIC, Buffer.alloc(56)]));

    const result = verify(filePath, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-MODEL-001', 'VG-MODEL-002']);
    assert.equal(result.actual.magicOk, false);
    assert.match(result.findings[1].detail, /magic signature/);
  });

  it('should verify an "other" format file as PASS', (t) => {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'weights.txt', Buffer.from('just some weights', 'utf8'));
    const manifest = register(filePath, { format: 'other' });
    assert.equal(manifest.detected_format, 'other');

    const result = verify(filePath, manifest);
    assert.equal(result.status, 'PASS');
    assert.deepEqual(rules(result), []);
  });
});

describe('VisionGuard model manifest validation', () => {
  it('should export the documented formats and finding severities', () => {
    assert.deepEqual([...MODEL_FORMATS], ['safetensors', 'onnx', 'pt', 'pth', 'other']);
    assert.deepEqual(MODEL_FINDING_SEVERITY, {
      'VG-MODEL-001': 'BLOCKER',
      'VG-MODEL-002': 'BLOCKER',
      'VG-MODEL-003': 'BLOCKER',
      'VG-MODEL-004': 'BLOCKER',
      'VG-MODEL-005': 'HIGH',
      'VG-MODEL-006': 'BLOCKER',
    });
  });

  function validManifest(t) {
    const { parent } = makeFixture(t);
    const filePath = writeModel(parent, 'model.safetensors', safetensorsBytes());
    return register(filePath);
  }

  it('should reject unknown fields in strict mode', (t) => {
    const manifest = validManifest(t);
    manifest.extra = 'field';
    throwsCode(() => validateModelManifest(manifest, { strict: true }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    validateModelManifest(manifest);
  });

  it('should reject an unsupported schema major version', (t) => {
    const manifest = validManifest(t);
    manifest.schema_version = '2.0';
    throwsCode(() => validateModelManifest(manifest), ERROR_CODES.VG_MANIFEST_VERSION);
  });

  it('should reject a kind mismatch', (t) => {
    const manifest = validManifest(t);
    manifest.kind = 'dataset_manifest';
    throwsCode(() => validateModelManifest(manifest), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should reject format and detected_format from different families', (t) => {
    const manifest = validManifest(t);
    manifest.format = 'pt';
    manifest.detected_format = 'safetensors';
    throwsCode(() => validateModelManifest(manifest), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should reject a non-positive size', (t) => {
    const manifest = validManifest(t);
    manifest.size = 0;
    throwsCode(() => validateModelManifest(manifest), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should reject a malformed record_hash', (t) => {
    const manifest = validManifest(t);
    manifest.record_hash = 'sha256:not-a-digest';
    throwsCode(() => validateModelManifest(manifest), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });
});
