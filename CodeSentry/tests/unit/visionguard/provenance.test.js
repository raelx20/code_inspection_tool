const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const {
  parseArtifactRef,
  validateRecord,
  buildRecord,
  parseProvenanceLog,
  appendRecord,
  registerContributor,
  recordOperation,
  recordArtifact,
  verifyProvenance,
} = require('../../../src/visionguard/provenance');
const keys = require('../../../src/visionguard/keys');
const store = require('../../../src/visionguard/store');
const { registerDataset } = require('../../../src/visionguard/manifest');
const { hashRecord, canonicalJson } = require('../../../src/visionguard/canonical');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

const T0 = Date.UTC(2026, 9, 2, 12, 0, 0);
const HEX64_A = 'a'.repeat(64);
const HEX64_B = 'b'.repeat(64);

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}: ${err && err.message}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
    return true;
  });
}

function makeFixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-prov-'));
  const storeDir = path.join(parent, '.visionguard');
  const keyDir = path.join(parent, 'keys');
  fs.mkdirSync(storeDir, { recursive: true });
  t.after(() => {
    try {
      fs.rmSync(parent, { recursive: true, force: true });
    } catch {
    }
  });
  return { parent, storeDir, keyDir };
}

function registerAlice(storeDir, keyDir, operations) {
  return registerContributor({
    storeDir,
    keyDir,
    contributor: 'alice',
    operations,
    now: T0,
  });
}

function trainOperation(storeDir, signer, options = {}) {
  return recordOperation({
    storeDir,
    keyFile: signer.privateKeyPath,
    actor: { contributor: signer.contributor, key_id: signer.key_id },
    operation: options.operation || 'train',
    inputs: options.inputs || [{ artifact: 'file/input.bin', sha256: HEX64_A }],
    outputs: options.outputs || [{ artifact: 'model/out@1.0.0', sha256: HEX64_B }],
    parents: options.parents,
    metadata: options.metadata,
    now: options.now,
  });
}

function readLines(storeDir) {
  const text = fs.readFileSync(store.provenanceLogPath(storeDir), 'utf8');
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function writeLines(storeDir, lines) {
  fs.writeFileSync(store.provenanceLogPath(storeDir), `${lines.join('\n')}\n`);
}

function readRecord(storeDir, index) {
  return JSON.parse(readLines(storeDir)[index]);
}

function patchLine(storeDir, index, patch, options = {}) {
  const lines = readLines(storeDir);
  const record = JSON.parse(lines[index]);
  patch(record);
  if (options.recompute) {
    record.record_hash = hashRecord(record);
    record.record_id = record.record_hash;
  }
  lines[index] = canonicalJson(record);
  writeLines(storeDir, lines);
  return record;
}

function rules(result) {
  return result.findings.map((finding) => finding.rule);
}

function makeModelManifest(storeDir, id, version, sha256) {
  const manifest = {
    schema_version: '1.0',
    kind: 'model_manifest',
    id,
    version,
    format: 'other',
    detected_format: 'other',
    size: 5,
    sha256,
    created_at: '2026-10-02T12:00:00.000Z',
    actor: { contributor: 'tester', key_id: null },
    metadata: {},
    record_hash: '',
    signature: null,
  };
  manifest.record_hash = hashRecord(manifest);
  store.saveModelManifest(storeDir, manifest);
  return manifest;
}

describe('VisionGuard provenance record construction', () => {
  it('should set record_id equal to record_hash and keep it out of the hash', () => {
    const record = buildRecord(
      {
        kind: 'operation_recorded',
        actor: { contributor: 'alice', key_id: null },
        operation: 'train',
        inputs: [{ artifact: 'file/in.bin', sha256: HEX64_A }],
        outputs: [{ artifact: 'file/out.bin', sha256: HEX64_B }],
        metadata: { step: 1 },
      },
      { now: T0 }
    );
    assert.equal(record.record_id, record.record_hash);
    assert.equal(hashRecord(record), record.record_hash);
    assert.equal(record.prev_record_hash, null);
    assert.equal(record.timestamp, new Date(T0).toISOString());
    assert.doesNotThrow(() => validateRecord(record));
    const altered = { ...record, metadata: { step: 2 } };
    assert.notEqual(hashRecord(altered), record.record_hash);
  });

  it('should reject malformed records', () => {
    const base = buildRecord(
      {
        kind: 'operation_recorded',
        actor: { contributor: 'alice', key_id: null },
        operation: 'train',
        inputs: [{ artifact: 'file/in.bin', sha256: HEX64_A }],
        outputs: [{ artifact: 'file/out.bin', sha256: HEX64_B }],
      },
      { now: T0 }
    );
    const bad = (patch) => ({ ...base, ...patch });
    throwsCode(() => validateRecord(bad({ kind: 'nope' })), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateRecord(bad({ extra: 1, record_id: base.record_hash })), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateRecord(bad({ operation: 'launch' })), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(
      () => validateRecord(bad({ inputs: [{ artifact: 'file/in.bin', sha256: HEX64_A, note: 'x' }] })),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(
      () => validateRecord(bad({ inputs: [{ artifact: 'file/in.bin', sha256: HEX64_A.toUpperCase() }] })),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(
      () => validateRecord(bad({ inputs: [{ artifact: `file/${'a'.repeat(600)}`, sha256: HEX64_A }] })),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(() => validateRecord(bad({ record_id: `sha256:${'0'.repeat(64)}` })), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateRecord(bad({ schema_version: '2.0' })), ERROR_CODES.VG_MANIFEST_VERSION);
    throwsCode(
      () => validateRecord(bad({ parent_record_hashes: ['not-a-hash'] })),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    const stripped = { ...base };
    stripped.record_hash = `sha256:${'0'.repeat(64)}`;
    stripped.record_id = stripped.record_hash;
    throwsCode(() => validateRecord(stripped), ERROR_CODES.VG_MANIFEST_HASH_MISMATCH);
    throwsCode(() => validateRecord(null), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should enforce metadata depth and size limits while appending', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const signer = registerAlice(storeDir, keyDir);
    let deep = { leaf: 'x' };
    for (let i = 0; i < 8; i++) deep = { nested: deep };
    throwsCode(
      () => trainOperation(storeDir, signer, { metadata: deep, now: T0 + 1 }),
      ERROR_CODES.VG_LIMIT_METADATA
    );
    throwsCode(
      () =>
        trainOperation(storeDir, signer, {
          metadata: { blob: 'x'.repeat(5000) },
          now: T0 + 1,
        }),
      ERROR_CODES.VG_LIMIT_METADATA
    );
  });

  it('should parse logs and report malformed lines with line numbers', () => {
    const text = `${JSON.stringify({ ok: 1 })}\nnot-json\n\n`;
    const parsed = parseProvenanceLog(text);
    assert.equal(parsed.entries.length, 0);
    assert.equal(parsed.malformed.length, 3);
    assert.deepEqual(
      parsed.malformed.map((item) => item.lineNumber),
      [1, 2, 3]
    );
    assert.deepEqual(parseProvenanceLog('').entries, []);
  });

  it('should parse artifact references loosely and strictly', () => {
    assert.deepEqual(parseArtifactRef('dataset/demo@1.0.0'), {
      type: 'dataset',
      name: 'demo',
      version: '1.0.0',
      ref: 'dataset/demo@1.0.0',
    });
    assert.equal(parseArtifactRef('file/raw.bin'), null);
    assert.equal(parseArtifactRef('dataset/@1.0.0'), null);
    assert.equal(parseArtifactRef('dataset/demo'), null);
    assert.equal(parseArtifactRef('@1.0.0'), null);
    assert.equal(parseArtifactRef(42), null);
  });
});

describe('VisionGuard contributor registration', () => {
  it('should register a contributor with keys and a signed genesis record', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    assert.match(alice.key_id, /^[0-9a-f]{32}$/);
    assert.ok(fs.existsSync(alice.privateKeyPath));
    const keyRecord = keys.loadPublicKey(storeDir, 'alice', alice.key_id);
    assert.equal(keyRecord.status, 'active');
    assert.deepEqual(keyRecord.operations, [...keys.OPERATIONS]);
    assert.equal(alice.record.record_id, alice.record.record_hash);
    assert.equal(alice.record.prev_record_hash, null);

    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'UNANCHORED');
    assert.equal(result.record_count, 1);
    assert.deepEqual(result.findings, []);
    assert.equal(result.head, alice.record.record_hash);

    const anchored = verifyProvenance({ storeDir, expectedHead: result.head, now: T0 + 60000 });
    assert.equal(anchored.status, 'PASS');
    assert.equal(anchored.anchored, true);
  });

  it('should clean up key material when registration cannot be appended', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    fs.writeFileSync(store.provenanceLogPath(storeDir), 'garbage\n');
    throwsCode(() => registerAlice(storeDir, keyDir), ERROR_CODES.VG_MANIFEST_MALFORMED);
    const keyFiles = fs.existsSync(keyDir)
      ? fs.readdirSync(keyDir).flatMap((name) => fs.readdirSync(path.join(keyDir, name)))
      : [];
    assert.deepEqual(keyFiles, []);
    const pubFiles = fs.existsSync(path.join(storeDir, 'keys', 'alice'))
      ? fs.readdirSync(path.join(storeDir, 'keys', 'alice'))
      : [];
    assert.deepEqual(pubFiles, []);
  });
});

describe('VisionGuard operation recording', () => {
  it('should append a multi contributor chain with DAG parents', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    const bob = registerContributor({ storeDir, keyDir, contributor: 'bob', now: T0 });
    const op1 = trainOperation(storeDir, alice, { now: T0 + 1000 });
    const op2 = trainOperation(storeDir, bob, {
      parents: [op1.record_hash],
      now: T0 + 2000,
      inputs: [{ artifact: 'dataset/raw@1.0.0', sha256: HEX64_A }],
    });
    const op3 = trainOperation(storeDir, alice, {
      parents: [op1.record_hash, op2.record_hash],
      now: T0 + 3000,
    });

    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'UNANCHORED');
    assert.equal(result.record_count, 5);
    assert.deepEqual(result.findings, []);
    assert.equal(result.head, op3.record_hash);

    const anchored = verifyProvenance({ storeDir, expectedHead: result.head, now: T0 + 60000 });
    assert.equal(anchored.status, 'PASS');

    const lines = readLines(storeDir);
    assert.equal(lines.length, 5);
    for (const line of lines) {
      assert.equal(line, canonicalJson(JSON.parse(line)), 'log lines must be canonical');
    }
  });

  it('should refuse a missing or mismatched private key', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    throwsCode(
      () =>
        recordOperation({
          storeDir,
          actor: { contributor: 'alice', key_id: alice.key_id },
          operation: 'train',
          inputs: [{ artifact: 'file/a', sha256: HEX64_A }],
          outputs: [{ artifact: 'file/b', sha256: HEX64_B }],
        }),
      ERROR_CODES.VG_KEY_UNKNOWN
    );
    throwsCode(
      () =>
        recordOperation({
          storeDir,
          keyFile: alice.privateKeyPath,
          actor: { contributor: 'alice', key_id: 'f'.repeat(32) },
          operation: 'train',
          inputs: [{ artifact: 'file/a', sha256: HEX64_A }],
          outputs: [{ artifact: 'file/b', sha256: HEX64_B }],
        }),
      ERROR_CODES.VG_KEY_UNKNOWN
    );
  });

  it('should refuse an unregistered contributor key', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const pair = keys.generateKeyPair();
    const keyFile = keys.savePrivateKey(keyDir, 'mallory', pair.keyId, pair.privateKeyDer);
    throwsCode(
      () =>
        recordOperation({
          storeDir,
          keyFile,
          actor: { contributor: 'mallory', key_id: pair.keyId },
          operation: 'train',
          inputs: [{ artifact: 'file/a', sha256: HEX64_A }],
          outputs: [{ artifact: 'file/b', sha256: HEX64_B }],
        }),
      ERROR_CODES.VG_KEY_UNKNOWN
    );
  });

  it('should refuse a revoked key and an unauthorized operation', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const restricted = registerContributor({
      storeDir,
      keyDir,
      contributor: 'alice',
      operations: ['curate_dataset'],
      now: T0,
    });
    throwsCode(() => trainOperation(storeDir, restricted, { now: T0 + 1 }), ERROR_CODES.VG_UNAUTHORIZED_OP);

    const privateKey = keys.loadPrivateKey(restricted.privateKeyPath);
    const current = keys.loadPublicKey(storeDir, 'alice', restricted.key_id);
    const revoked = keys.buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: Buffer.from(current.public_key_der_b64, 'base64'),
      operations: current.operations,
      status: 'revoked',
      privateKey,
      now: T0 + 2,
    });
    keys.savePublicKey(storeDir, revoked);
    throwsCode(() => trainOperation(storeDir, restricted, { operation: 'curate_dataset', now: T0 + 3 }), ERROR_CODES.VG_KEY_REVOKED);
  });

  it('should refuse to append to a broken chain', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    patchLine(storeDir, 1, (record) => {
      record.prev_record_hash = `sha256:${'c'.repeat(64)}`;
    });
    throwsCode(() => trainOperation(storeDir, alice, { now: T0 + 2000 }), ERROR_CODES.VG_MANIFEST_MALFORMED);
  });

  it('should record artifact registrations', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    const record = recordArtifact({
      storeDir,
      keyFile: alice.privateKeyPath,
      actor: { contributor: 'alice', key_id: alice.key_id },
      artifact: 'dataset/demo@1.0.0',
      sha256: HEX64_A,
      now: T0 + 1000,
    });
    assert.equal(record.kind, 'artifact_registered');
    assert.equal(record.outputs[0].artifact, 'dataset/demo@1.0.0');
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.record_count, 2);
    assert.deepEqual(result.findings, []);
  });
});

describe('VisionGuard provenance verification', () => {
  it('should report a missing log as NOT_CHECKED', (t) => {
    const { storeDir } = makeFixture(t);
    const result = verifyProvenance({ storeDir, now: T0 });
    assert.equal(result.status, 'NOT_CHECKED');
    assert.equal(result.record_count, 0);
    assert.equal(result.head, null);
    assert.equal(result.anchored, null);
    assert.deepEqual(result.findings, []);
  });

  it('should detect an altered record', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000, metadata: { step: 1 } });
    patchLine(storeDir, 1, (record) => {
      record.metadata = { step: 2 };
    });
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-001'));
    const finding = result.findings.find((item) => item.rule === 'VG-PROV-001');
    assert.equal(finding.line, 2);
    assert.equal(finding.path, 'provenance.log');
  });

  it('should detect a deleted line as a broken chain', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    trainOperation(storeDir, alice, { now: T0 + 2000 });
    const lines = readLines(storeDir);
    writeLines(storeDir, [lines[0], lines[2]]);
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.equal(result.record_count, 2);
    assert.ok(rules(result).includes('VG-PROV-001'));
  });

  it('should detect reordered lines', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    trainOperation(storeDir, alice, { now: T0 + 2000 });
    const lines = readLines(storeDir);
    writeLines(storeDir, [lines[0], lines[2], lines[1]]);
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-001'));
  });

  it('should detect a duplicated record as replay', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    trainOperation(storeDir, alice, { now: T0 + 2000 });
    const lines = readLines(storeDir);
    lines.push(lines[1]);
    writeLines(storeDir, lines);
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-006'));
  });

  it('should detect front truncation against an anchor', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    trainOperation(storeDir, alice, { now: T0 + 2000 });
    const head = verifyProvenance({ storeDir, now: T0 + 60000 }).head;
    const lines = readLines(storeDir);
    writeLines(storeDir, lines.slice(2));
    const result = verifyProvenance({ storeDir, expectedHead: head, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.equal(result.anchored, true);
    assert.equal(result.head, head);
    assert.ok(rules(result).includes('VG-PROV-001'));
    assert.ok(!rules(result).includes('VG-PROV-008'));
  });

  it('should detect tail truncation against an anchor', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    trainOperation(storeDir, alice, { now: T0 + 2000 });
    const head = verifyProvenance({ storeDir, now: T0 + 60000 }).head;
    const lines = readLines(storeDir);
    writeLines(storeDir, lines.slice(0, lines.length - 1));
    const result = verifyProvenance({ storeDir, expectedHead: head, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.equal(result.anchored, false);
    assert.ok(rules(result).includes('VG-PROV-008'));
  });

  it('should detect a forged signature without breaking the hash chain', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    patchLine(storeDir, 1, (record) => {
      const bytes = Buffer.from(record.signature, 'base64');
      bytes[0] ^= 0xff;
      record.signature = bytes.toString('base64');
    });
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-PROV-002']);
  });

  it('should report stripped signatures as UNSIGNED', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    const lines = readLines(storeDir).map((line) => {
      const record = JSON.parse(line);
      delete record.signature;
      return canonicalJson(record);
    });
    writeLines(storeDir, lines);
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'UNSIGNED');
    assert.equal(result.unsigned_count, 2);
    assert.ok(rules(result).includes('VG-PROV-009'));
    assert.ok(!result.findings.some((finding) => finding.severity === 'BLOCKER'));
  });

  it('should detect an unknown signer when the key file disappears', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    fs.rmSync(path.join(storeDir, 'keys', 'alice', `${alice.key_id}.pub.json`));
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-003'));
  });

  it('should detect a substituted key file that keeps the key_id', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    const attacker = keys.generateKeyPair();
    const forged = keys.buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: attacker.publicKeyDer,
      operations: [...keys.OPERATIONS],
      privateKey: attacker.privateKey,
      now: T0 + 2000,
    });
    const filePath = keys.publicKeyPath(storeDir, 'alice', alice.key_id);
    const substituted = { ...forged, key_id: alice.key_id };
    substituted.record_hash = hashRecord(substituted);
    substituted.signature = keys.signRecordHash(attacker.privateKey, substituted.record_hash);
    fs.writeFileSync(filePath, `${canonicalJson(substituted)}\n`);
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-003'));
  });

  it('should reject a key that is not pinned by a contributor record', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    const spare = keys.generateKeyPair();
    const spareRecord = keys.buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: spare.publicKeyDer,
      operations: [...keys.OPERATIONS],
      privateKey: spare.privateKey,
      now: T0 + 1000,
    });
    keys.savePublicKey(storeDir, spareRecord);

    const last = readRecord(storeDir, 0);
    const record = buildRecord(
      {
        kind: 'operation_recorded',
        actor: { contributor: 'alice', key_id: spare.keyId },
        operation: 'train',
        inputs: [{ artifact: 'file/in.bin', sha256: HEX64_A }],
        outputs: [{ artifact: 'file/out.bin', sha256: HEX64_B }],
        prev_record_hash: last.record_hash,
      },
      { now: T0 + 2000 }
    );
    record.signature = keys.signRecordHash(spare.privateKey, record.record_hash);
    validateRecord(record);
    store.appendLogLine(storeDir, canonicalJson(record));
    void alice;

    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-003'));
    const finding = result.findings.find((item) => item.rule === 'VG-PROV-003');
    assert.match(finding.message, /not pinned/);
  });

  it('should detect an unauthorized operation recorded under a valid key', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000, operation: 'train' });
    const privateKey = keys.loadPrivateKey(alice.privateKeyPath);
    const current = keys.loadPublicKey(storeDir, 'alice', alice.key_id);
    const narrowed = keys.buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: Buffer.from(current.public_key_der_b64, 'base64'),
      operations: ['curate_dataset'],
      privateKey,
      now: T0 + 2000,
    });
    keys.savePublicKey(storeDir, narrowed);
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-004'));
  });

  it('should detect a revoked signer key', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    const privateKey = keys.loadPrivateKey(alice.privateKeyPath);
    const current = keys.loadPublicKey(storeDir, 'alice', alice.key_id);
    const revoked = keys.buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: Buffer.from(current.public_key_der_b64, 'base64'),
      operations: current.operations,
      status: 'revoked',
      privateKey,
      now: T0 + 2000,
    });
    keys.savePublicKey(storeDir, revoked);
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-004'));
  });

  it('should detect a missing parent reference', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { parents: [`sha256:${'d'.repeat(64)}`], now: T0 + 1000 });
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-005'));
  });

  it('should detect a parent pointing at a later record', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    trainOperation(storeDir, alice, { now: T0 + 2000 });
    const forwardHash = readRecord(storeDir, 2).record_hash;
    patchLine(
      storeDir,
      1,
      (record) => {
        record.parent_record_hashes = [forwardHash];
      },
      { recompute: true }
    );
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-007'));
    const finding = result.findings.find((item) => item.rule === 'VG-PROV-007');
    assert.match(finding.message, /later record/);
  });

  it('should detect conflicting artifact registrations', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    recordArtifact({
      storeDir,
      keyFile: alice.privateKeyPath,
      actor: { contributor: 'alice', key_id: alice.key_id },
      artifact: 'dataset/demo@1.0.0',
      sha256: HEX64_A,
      now: T0 + 1000,
    });
    recordArtifact({
      storeDir,
      keyFile: alice.privateKeyPath,
      actor: { contributor: 'alice', key_id: alice.key_id },
      artifact: 'dataset/demo@1.0.0',
      sha256: HEX64_B,
      now: T0 + 2000,
    });
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.ok(rules(result).includes('VG-PROV-010'));
    const finding = result.findings.find((item) => item.rule === 'VG-PROV-010');
    assert.equal(finding.artifact, 'dataset/demo@1.0.0');
    assert.equal(finding.hashes.length, 2);
  });

  it('should cross check registered dataset and model references', (t) => {
    const { parent, storeDir, keyDir } = makeFixture(t);
    const datasetDir = path.join(parent, 'dataset');
    fs.mkdirSync(datasetDir);
    fs.writeFileSync(path.join(datasetDir, 'a.png'), 'content');
    const dataset = registerDataset({
      path: datasetDir,
      name: 'demo',
      version: '1.0.0',
      actor: { contributor: 'tester', key_id: null },
      now: '2026-10-02T12:00:00.000Z',
      storeDir,
    });
    const merkle = dataset.merkle_root.replace(/^sha256:/, '');
    makeModelManifest(storeDir, 'demo-model', '1.0.0', HEX64_B);

    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, {
      now: T0 + 1000,
      inputs: [{ artifact: 'dataset/demo@1.0.0', sha256: merkle }],
      outputs: [{ artifact: 'model/demo-model@1.0.0', sha256: HEX64_B }],
    });
    const clean = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.deepEqual(clean.findings, []);
    assert.deepEqual(
      clean.warnings.map((warning) => warning.rule),
      []
    );

    trainOperation(storeDir, alice, {
      now: T0 + 2000,
      inputs: [{ artifact: 'dataset/demo@1.0.0', sha256: HEX64_B }],
      outputs: [{ artifact: 'model/demo-model@1.0.0', sha256: HEX64_A }],
    });
    const dirty = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(dirty.status, 'FAIL');
    const prov011 = dirty.findings.filter((finding) => finding.rule === 'VG-PROV-011');
    assert.equal(prov011.length, 2);
    assert.deepEqual(
      prov011.map((finding) => finding.artifact).sort(),
      ['dataset/demo@1.0.0', 'model/demo-model@1.0.0']
    );
  });

  it('should warn about unregistered artifact references and stale timestamps', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    const op1 = trainOperation(storeDir, alice, {
      now: T0 + 10000,
      inputs: [{ artifact: 'dataset/unknown@1.0.0', sha256: HEX64_A }],
    });
    trainOperation(storeDir, alice, { parents: [op1.record_hash], now: T0 + 1000 });

    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.deepEqual(result.findings, []);
    const warningRules = result.warnings.map((warning) => warning.rule);
    assert.ok(warningRules.includes('VG-PROV-W002'));
    assert.ok(warningRules.includes('VG-PROV-W001'));
    const anchored = verifyProvenance({ storeDir, expectedHead: result.head, now: T0 + 60000 });
    assert.equal(anchored.status, 'PASS');
  });

  it('should read the expected head from an anchor file', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    const head = verifyProvenance({ storeDir, now: T0 + 60000 }).head;
    const anchorFile = path.join(storeDir, 'anchors', 'head.txt');
    fs.mkdirSync(path.dirname(anchorFile), { recursive: true });
    fs.writeFileSync(anchorFile, `${head}\n`);
    const good = verifyProvenance({ storeDir, anchorFilePath: anchorFile, now: T0 + 60000 });
    assert.equal(good.status, 'PASS');
    assert.equal(good.anchored, true);
    fs.writeFileSync(anchorFile, `sha256:${'0'.repeat(64)}\n`);
    const bad = verifyProvenance({ storeDir, anchorFilePath: anchorFile, now: T0 + 60000 });
    assert.equal(bad.status, 'FAIL');
    assert.ok(rules(bad).includes('VG-PROV-008'));
    throwsCode(() => verifyProvenance({ storeDir, anchorFilePath: path.join(storeDir, 'missing') }), ERROR_CODES.VG_UNREADABLE);
  });

  it('should report an unsigned log as UNSIGNED', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    void alice;
    appendRecord(
      storeDir,
      {
        kind: 'artifact_registered',
        actor: { contributor: 'carol', key_id: null },
        inputs: [],
        outputs: [{ artifact: 'file/raw.bin', sha256: HEX64_A }],
      },
      { sign: false, now: T0 + 1000 }
    );
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'UNSIGNED');
    assert.equal(result.unsigned_count, 1);
    assert.ok(rules(result).includes('VG-PROV-009'));
  });

  it('should detect a crash mid write', (t) => {
    const { storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    trainOperation(storeDir, alice, { now: T0 + 1000 });
    const text = fs.readFileSync(store.provenanceLogPath(storeDir), 'utf8');
    fs.writeFileSync(store.provenanceLogPath(storeDir), `${text}{"schema_version": "1.0", "kind": "op`);
    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.status, 'FAIL');
    assert.equal(result.record_count, 2);
    assert.equal(result.malformed_count, 1);
    const finding = result.findings.find((item) => item.rule === 'VG-PROV-001');
    assert.equal(finding.line, 3);
    assert.match(finding.message, /not valid canonical JSON/);
  });

  it('should cap findings per rule', (t) => {
    const { storeDir } = makeFixture(t);
    const lines = [];
    for (let i = 0; i < 105; i++) lines.push('{"broken":');
    writeLines(storeDir, lines);
    const result = verifyProvenance({ storeDir, now: T0 });
    assert.equal(result.status, 'FAIL');
    const findings001 = result.findings.filter((finding) => finding.rule === 'VG-PROV-001');
    assert.equal(findings001.length, 101);
    assert.equal(findings001[findings001.length - 1].truncated, true);
    assert.match(findings001[findings001.length - 1].message, /5 additional/);
  });
});

describe('VisionGuard concurrent provenance appends', () => {
  it('should keep the chain valid when writers race', async (t) => {
    const { parent, storeDir, keyDir } = makeFixture(t);
    const alice = registerAlice(storeDir, keyDir);
    const provenancePath = path.resolve(__dirname, '../../../src/visionguard/provenance');
    const runnerPath = path.join(parent, 'runner.js');
    fs.writeFileSync(
      runnerPath,
      [
        "'use strict';",
        `const { recordOperation } = require(${JSON.stringify(provenancePath)});`,
        'const T0 = Date.UTC(2026, 9, 2, 12, 0, 0);',
        'const [storeDir, keyFile, contributor, keyId, count, startIndex] = process.argv.slice(2);',
        'for (let i = 0; i < Number(count); i++) {',
        '  const index = Number(startIndex) + i;',
        '  recordOperation({',
        '    storeDir,',
        '    keyFile,',
        '    actor: { contributor, key_id: keyId },',
        "    operation: 'train',",
        "    inputs: [{ artifact: 'file/in-' + index, sha256: String(index).padStart(64, '0') }],",
        "    outputs: [{ artifact: 'file/out-' + index, sha256: String(index).padStart(64, '0').split('').reverse().join('') }],",
        '    now: T0 + index,',
        '  });',
        '}',
      ].join('\n')
    );

    const writers = [];
    for (let w = 0; w < 4; w++) {
      writers.push(
        new Promise((resolve, reject) => {
          const child = spawn(process.execPath, [
            runnerPath,
            storeDir,
            alice.privateKeyPath,
            'alice',
            alice.key_id,
            '4',
            String(w * 4),
          ]);
          let stderr = '';
          child.stderr.on('data', (chunk) => {
            stderr += chunk.toString();
          });
          child.on('error', reject);
          child.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`child exited ${code}: ${stderr}`));
          });
        })
      );
    }
    await Promise.all(writers);

    const result = verifyProvenance({ storeDir, now: T0 + 60000 });
    assert.equal(result.record_count, 17);
    assert.deepEqual(result.findings, []);
    assert.equal(result.status, 'UNANCHORED');
    const anchored = verifyProvenance({ storeDir, expectedHead: result.head, now: T0 + 60000 });
    assert.equal(anchored.status, 'PASS');
    const lines = readLines(storeDir);
    assert.equal(lines.length, 17);
    const parsed = parseProvenanceLog(fs.readFileSync(store.provenanceLogPath(storeDir), 'utf8'));
    assert.equal(parsed.malformed.length, 0);
    assert.equal(parsed.entries.length, 17);
  });
});
