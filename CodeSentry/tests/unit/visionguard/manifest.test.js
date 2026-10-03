const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  registerDataset,
  verifyDataset,
  validateDatasetManifest,
  parseDatasetManifest,
  checkManifestConsistency,
  diffDataset,
} = require('../../../src/visionguard/manifest');
const { hashRecord } = require('../../../src/visionguard/canonical');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

const EMPTY_ROOT = 'sha256:c4b542aff90fd316b787fd1635ce2409ad7572ba9684a5eea53e3f78db6902cf';
const FIXED_NOW = '2026-10-02T12:00:00.000Z';
const NFD_STEM = String.fromCodePoint(0x63, 0x61, 0x66, 0x65, 0x301);
const NFC_STEM = String.fromCodePoint(0x63, 0x61, 0x66, 0xe9);

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
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-man-'));
  const root = path.join(parent, 'dataset');
  fs.mkdirSync(root);
  const storeDir = path.join(parent, 'store');
  t.after(() => {
    try {
      fs.rmSync(parent, { recursive: true, force: true });
    } catch {
    }
  });
  return { parent, root, storeDir };
}

function writeFiles(root, spec) {
  for (const [rel, content] of Object.entries(spec)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
}

function register(root, options = {}) {
  return registerDataset({
    path: root,
    name: options.name || 'demo-dataset',
    version: options.version || '1.0.0',
    actor: options.actor || { contributor: 'tester', key_id: null },
    policy: options.policy,
    limits: options.limits,
    strict: options.strict,
    now: FIXED_NOW,
    storeDir: options.storeDir,
  });
}

function verify(root, manifest, options = {}) {
  return verifyDataset({
    path: root,
    manifest,
    strict: options.strict,
    limits: options.limits,
    now: FIXED_NOW,
  });
}

describe('VisionGuard dataset registration and verification', () => {
  it('should register a valid dataset and verify it as clean but unanchored', (t) => {
    const { root, storeDir } = makeFixture(t);
    writeFiles(root, {
      'images/0001.png': 'image-one',
      'images/0002.png': 'image-two',
      'labels.json': '[]',
    });
    const manifest = register(root, { storeDir });

    assert.equal(manifest.schema_version, '1.0');
    assert.equal(manifest.kind, 'dataset_manifest');
    assert.equal(manifest.name, 'demo-dataset');
    assert.equal(manifest.version, '1.0.0');
    assert.equal(manifest.created_at, FIXED_NOW);
    assert.equal(manifest.hash_algorithm, 'sha256');
    assert.equal(manifest.file_count, 3);
    assert.ok(manifest.total_bytes > 0);
    assert.match(manifest.merkle_root, /^sha256:[0-9a-f]{64}$/);
    assert.equal(manifest.record_hash, hashRecord(manifest));
    assert.equal(manifest.signature, null);
    assert.deepEqual(manifest.actor, { contributor: 'tester', key_id: null });
    assert.deepEqual(
      manifest.files.map((entry) => entry.path),
      ['images/0001.png', 'images/0002.png', 'labels.json']
    );
    assert.ok(fs.existsSync(path.join(storeDir, 'manifests', 'dataset', 'demo-dataset', '1.0.0.json')));

    const result = verify(root, manifest);
    assert.equal(result.status, 'UNANCHORED');
    assert.equal(result.manifestConsistency.consistent, true);
    assert.equal(result.expectedMerkleRoot, manifest.merkle_root);
    assert.equal(result.computedMerkleRoot, manifest.merkle_root);
    assert.equal(result.diff.modified.length, 0);
    assert.equal(result.diff.removed.length, 0);
    assert.equal(result.diff.added.length, 0);
    assert.equal(result.diff.renamed.length, 0);
    assert.equal(result.diff.unchanged, 3);
    assert.deepEqual(result.findings, []);
    assert.equal(result.signaturePresent, false);
    assert.equal(result.checked_at, FIXED_NOW);
  });

  it('should detect modified file content', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'a.png': 'original', 'b.png': 'stable' });
    const manifest = register(root);
    fs.writeFileSync(path.join(root, 'a.png'), 'tampered');

    const result = verify(root, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-DATA-001']);
    const [entry] = result.diff.modified;
    assert.equal(entry.path, 'a.png');
    assert.equal(entry.expected_sha256, manifest.files[0].sha256);
    assert.match(entry.actual_sha256, /^[0-9a-f]{64}$/);
    assert.notEqual(entry.actual_sha256, entry.expected_sha256);
    assert.equal(result.findings[0].severity, 'BLOCKER');
  });

  it('should detect corruption that does not change the file size', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'a.bin': '12345' });
    const manifest = register(root);
    fs.writeFileSync(path.join(root, 'a.bin'), '54321');
    const result = verify(root, manifest);
    assert.equal(result.status, 'FAIL');
    assert.equal(result.diff.modified[0].expected_size, 5);
    assert.equal(result.diff.modified[0].actual_size, 5);
    assert.equal(result.diff.modified[0].expected_size, result.diff.modified[0].actual_size);
  });

  it('should detect deleted files', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'a.png': 'a', 'b.png': 'b' });
    const manifest = register(root);
    fs.rmSync(path.join(root, 'a.png'));
    const result = verify(root, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-DATA-002']);
    assert.equal(result.diff.removed[0].path, 'a.png');
    assert.equal(result.diff.removed[0].expected_sha256, manifest.files[0].sha256);
    assert.equal(result.diff.unchanged, 1);
  });

  it('should detect added files', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'a.png': 'a' });
    const manifest = register(root);
    writeFiles(root, { 'sneaky.png': 'injected' });
    const result = verify(root, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-DATA-003']);
    assert.equal(result.diff.added[0].path, 'sneaky.png');
  });

  it('should detect renames via identical content at a new path', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'old/name.png': 'payload', 'other.png': 'other' });
    const manifest = register(root);
    fs.renameSync(path.join(root, 'old', 'name.png'), path.join(root, 'new-name.png'));
    fs.rmSync(path.join(root, 'old'), { recursive: true });

    const result = verify(root, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-DATA-004']);
    const [renamed] = result.diff.renamed;
    assert.equal(renamed.from, 'old/name.png');
    assert.equal(renamed.to, 'new-name.png');
    assert.equal(result.diff.removed.length, 0);
    assert.equal(result.diff.added.length, 0);
    assert.equal(result.diff.unchanged, 1);
  });

  it('should register an empty dataset with the empty-domain merkle root', (t) => {
    const { root } = makeFixture(t);
    const manifest = register(root);
    assert.equal(manifest.file_count, 0);
    assert.deepEqual(manifest.files, []);
    assert.equal(manifest.merkle_root, EMPTY_ROOT);

    const result = verify(root, manifest);
    assert.equal(result.status, 'UNANCHORED');
    assert.deepEqual(rules(result), ['VG-DATA-010']);
    assert.equal(result.findings[0].severity, 'INFO');
  });

  it('should allow duplicate content at distinct paths', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'copies/a.png': 'same-bytes', 'copies/b.png': 'same-bytes' });
    const manifest = register(root);
    assert.equal(manifest.file_count, 2);
    assert.equal(manifest.files[0].sha256, manifest.files[1].sha256);
    assert.notEqual(manifest.merkle_root, EMPTY_ROOT);

    const result = verify(root, manifest);
    assert.equal(result.status, 'UNANCHORED');
    assert.deepEqual(result.findings, []);
  });

  it('should exclude unsupported extensions by policy and stay consistent', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'images/a.png': 'img', 'notes.txt': 'notes', 'raw.bin': 'bytes' });
    const manifest = register(root, { policy: { extensions: ['.png'] } });
    assert.equal(manifest.file_count, 1);
    assert.equal(manifest.policy_findings.length, 2);
    assert.ok(manifest.policy_findings.every((item) => item.rule === 'VG-DATA-012'));

    const result = verify(root, manifest);
    assert.equal(result.status, 'UNANCHORED');
    assert.ok(rules(result).includes('VG-DATA-012'));
    assert.equal(result.findingCounts['VG-DATA-012'], 2);
    assert.equal(result.diff.added.length, 0);
  });

  it('should record symlink exclusion and escalate it only in strict verify', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'real.png': 'real', 'outside.png': 'outside' });
    try {
      fs.symlinkSync(path.join(root, 'outside.png'), path.join(root, 'link.png'));
    } catch (err) {
      t.skip(`symlink creation unavailable: ${err.code}`);
      return;
    }

    const manifest = register(root);
    assert.equal(manifest.file_count, 2);
    assert.equal(manifest.policy_findings.length, 1);
    assert.equal(manifest.policy_findings[0].rule, 'VG-DATA-005');

    const loose = verify(root, manifest);
    assert.equal(loose.status, 'UNANCHORED');
    assert.ok(rules(loose).includes('VG-DATA-005'));

    const strict = verify(root, manifest, { strict: true });
    assert.equal(strict.status, 'FAIL');
    assert.ok(rules(strict).includes('VG-DATA-005'));

    throwsCode(() => register(root, { strict: true, name: 'strict-ds' }), ERROR_CODES.VG_SYMLINK_DENIED);
  });

  it('should fail registration when a file is unreadable', (t) => {
    if (process.platform === 'win32') {
      t.skip('read permissions are not enforced for the owner on Windows');
      return;
    }
    const { root } = makeFixture(t);
    writeFiles(root, { 'ok.png': 'ok', 'locked.png': 'locked' });
    fs.chmodSync(path.join(root, 'locked.png'), 0);
    t.after(() => {
      try {
        fs.chmodSync(path.join(root, 'locked.png'), 0o644);
      } catch {
      }
    });
    throwsCode(() => register(root), ERROR_CODES.VG_UNREADABLE);
  });

  it('should report unreadable files during verification', (t) => {
    if (process.platform === 'win32') {
      t.skip('read permissions are not enforced for the owner on Windows');
      return;
    }
    const { root } = makeFixture(t);
    writeFiles(root, { 'ok.png': 'ok', 'locked.png': 'locked' });
    const manifest = register(root);
    fs.chmodSync(path.join(root, 'locked.png'), 0);
    t.after(() => {
      try {
        fs.chmodSync(path.join(root, 'locked.png'), 0o644);
      } catch {
      }
    });
    const result = verify(root, manifest);
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(rules(result), ['VG-DATA-008']);
    assert.equal(result.diff.unreadable[0].path, 'locked.png');
  });

  it('should enforce large file limits at registration', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'big.png': '0123456789' });
    throwsCode(() => register(root, { limits: { maxFileSize: 4 } }), ERROR_CODES.VG_LIMIT_FILE_SIZE);
  });

  it('should reject a case collision on case sensitive filesystems', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'A.png': 'a' });
    try {
      fs.writeFileSync(path.join(root, 'a.png'), 'b');
    } catch (err) {
      t.skip(`case-distinct creation unavailable: ${err.code}`);
      return;
    }
    if (fs.readdirSync(root).length < 2) {
      t.skip('filesystem is case insensitive and merged the two names');
      return;
    }
    throwsCode(() => register(root), ERROR_CODES.VG_CASE_COLLISION);
  });

  it('should reject an NFC collision on filesystems that allow both spellings', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { [`${NFD_STEM}.png`]: 'a' });
    try {
      fs.writeFileSync(path.join(root, `${NFC_STEM}.png`), 'b');
    } catch (err) {
      t.skip(`NFC-distinct creation unavailable: ${err.code}`);
      return;
    }
    if (fs.readdirSync(root).length < 2) {
      t.skip('filesystem merged the two spellings');
      return;
    }
    throwsCode(() => register(root), ERROR_CODES.VG_NFC_COLLISION);
  });

  it('should reject duplicate canonical paths in a manifest', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'a.png': 'a' });
    const manifest = register(root);
    const tampered = JSON.parse(JSON.stringify(manifest));
    tampered.files.push({ ...manifest.files[0] });
    throwsCode(() => validateDatasetManifest(tampered), ERROR_CODES.VG_NFC_COLLISION);
  });
});

describe('VisionGuard manifest tampering detection', () => {
  it('should fail when the manifest body is tampered without updating record_hash', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'a.png': 'a' });
    const manifest = register(root);
    const tampered = JSON.parse(JSON.stringify(manifest));
    tampered.actor = { contributor: 'attacker', key_id: null };

    const result = verify(root, tampered);
    assert.equal(result.status, 'FAIL');
    assert.equal(result.manifestConsistency.recordHashValid, false);
    assert.equal(result.manifestConsistency.merkleRootValid, true);
    assert.equal(result.manifestConsistency.countsValid, true);
    assert.deepEqual(rules(result), ['VG-DATA-007']);
    assert.match(result.findings[0].detail, /record_hash/);
  });

  it('should fail when file list and record_hash agree but the merkle root does not', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'a.png': 'a' });
    const manifest = register(root);
    const tampered = JSON.parse(JSON.stringify(manifest));
    tampered.files[0].sha256 = 'f'.repeat(64);
    tampered.record_hash = hashRecord(tampered);

    const result = verify(root, tampered);
    assert.equal(result.status, 'FAIL');
    assert.equal(result.manifestConsistency.recordHashValid, true);
    assert.equal(result.manifestConsistency.merkleRootValid, false);
    assert.deepEqual(rules(result), ['VG-DATA-007', 'VG-DATA-001']);
    const consistencyFinding = result.findings.find((item) => item.rule === 'VG-DATA-007');
    assert.match(consistencyFinding.detail, /merkle_root/);
    assert.equal(result.expectedMerkleRoot, manifest.merkle_root);
    assert.equal(result.computedMerkleRoot, manifest.merkle_root);
    assert.equal(result.expectedMerkleRoot, result.computedMerkleRoot);
  });

  it('should fail when counts are tampered', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'a.png': 'a' });
    const manifest = register(root);
    const tampered = JSON.parse(JSON.stringify(manifest));
    tampered.file_count = 99;
    tampered.record_hash = hashRecord(tampered);
    const consistency = checkManifestConsistency(tampered);
    assert.equal(consistency.recordHashValid, true);
    assert.equal(consistency.countsValid, false);
    assert.equal(consistency.consistent, false);
  });

  it('should reject malformed JSON', () => {
    throwsCode(() => parseDatasetManifest('{"schema_version":'), ERROR_CODES.VG_MANIFEST_MALFORMED);
    throwsCode(() => parseDatasetManifest('not json at all'), ERROR_CODES.VG_MANIFEST_MALFORMED);
    throwsCode(() => parseDatasetManifest(''), ERROR_CODES.VG_MANIFEST_MALFORMED);
  });

  it('should reject unsupported schema versions', () => {
    const base = JSON.parse(JSON.stringify(VALID_MANIFEST));
    throwsCode(() => validateDatasetManifest({ ...base, schema_version: '2.0' }), ERROR_CODES.VG_MANIFEST_VERSION);
    throwsCode(() => validateDatasetManifest({ ...base, schema_version: '0.9' }), ERROR_CODES.VG_MANIFEST_VERSION);
    throwsCode(() => validateDatasetManifest({ ...base, schema_version: 'banana' }), ERROR_CODES.VG_MANIFEST_VERSION);
    const noVersion = { ...base };
    delete noVersion.schema_version;
    throwsCode(() => validateDatasetManifest(noVersion), ERROR_CODES.VG_MANIFEST_SCHEMA);
    validateDatasetManifest({ ...base, schema_version: '1.7' });
  });

  it('should reject structural violations', () => {
    const base = JSON.parse(JSON.stringify(VALID_MANIFEST));
    throwsCode(() => validateDatasetManifest('nope'), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, kind: 'model_manifest' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, hash_algorithm: 'md5' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, name: '../evil' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, name: 'has space' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, version: '' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, created_at: 'yesterday' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, actor: { contributor: '' } }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(
      () => validateDatasetManifest({ ...base, actor: { contributor: 'a', admin: true } }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(() => validateDatasetManifest({ ...base, file_count: -1 }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, merkle_root: 'nope' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, record_hash: 'nope' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, signature: 42 }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, files: 'nope' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateDatasetManifest({ ...base, policy_findings: {} }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(
      () => validateDatasetManifest({ ...base, policy_findings: [{ rule: 'NOPE', path: 'a', detail: 'x' }] }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(() => validateDatasetManifest({ ...base, policy: { allowSymlinks: true } }), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should reject non canonical file paths in manifests', () => {
    const base = JSON.parse(JSON.stringify(VALID_MANIFEST));
    const prefixed = { ...base, files: [{ ...base.files[0], path: `./${base.files[0].path}` }] };
    throwsCode(() => validateDatasetManifest(prefixed), ERROR_CODES.VG_MANIFEST_SCHEMA);
    const traversal = { ...base, files: [{ ...base.files[0], path: '../escape.png' }] };
    throwsCode(() => validateDatasetManifest(traversal), ERROR_CODES.VG_PATH_TRAVERSAL);
  });

  it('should reject unknown fields only in strict mode', () => {
    const base = JSON.parse(JSON.stringify(VALID_MANIFEST));
    validateDatasetManifest({ ...base, unexpected: true });
    throwsCode(() => validateDatasetManifest({ ...base, unexpected: true }, { strict: true }), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should round trip through parseCanonical', (t) => {
    const { root } = makeFixture(t);
    writeFiles(root, { 'a.png': 'a' });
    const manifest = register(root);
    const text = JSON.stringify(manifest, null, 2);
    const parsed = parseDatasetManifest(text);
    assert.deepEqual(parsed, manifest);
    assert.equal(checkManifestConsistency(parsed).consistent, true);
  });
});

describe('VisionGuard diffDataset', () => {
  const entry = (p, hash) => ({ path: p, size: 4, sha256: hash });

  it('should pair one rename and keep unmatched files as removed', () => {
    const h = 'a'.repeat(64);
    const manifestFiles = [entry('x.png', h), entry('y.png', h)];
    const walkResult = { entries: [entry('z.png', h)], unreadable: [] };
    const diff = diffDataset(manifestFiles, walkResult);
    assert.equal(diff.renamed.length, 1);
    assert.deepEqual(diff.renamed[0], { from: 'x.png', to: 'z.png', sha256: h });
    assert.equal(diff.removed.length, 1);
    assert.equal(diff.removed[0].path, 'y.png');
    assert.equal(diff.added.length, 0);
    assert.equal(diff.unchanged, 0);
  });

  it('should not pair renames across different hashes', () => {
    const manifestFiles = [entry('x.png', 'a'.repeat(64))];
    const walkResult = { entries: [entry('y.png', 'b'.repeat(64))], unreadable: [] };
    const diff = diffDataset(manifestFiles, walkResult);
    assert.equal(diff.renamed.length, 0);
    assert.equal(diff.removed.length, 1);
    assert.equal(diff.added.length, 1);
  });

  it('should pass unreadable entries through', () => {
    const unreadable = [{ path: 'gone.png', code: 'VG_UNREADABLE', detail: 'x' }];
    const diff = diffDataset([], { entries: [], unreadable });
    assert.deepEqual(diff.unreadable, unreadable);
  });

  it('should not report unreadable files as removed', () => {
    const manifestFiles = [entry('locked.png', 'a'.repeat(64))];
    const walkResult = {
      entries: [],
      unreadable: [{ path: 'locked.png', code: 'VG_UNREADABLE', detail: 'denied' }],
    };
    const diff = diffDataset(manifestFiles, walkResult);
    assert.equal(diff.removed.length, 0);
    assert.equal(diff.added.length, 0);
    assert.equal(diff.renamed.length, 0);
    assert.equal(diff.unreadable.length, 1);
  });
});

const VALID_MANIFEST = {
  schema_version: '1.0',
  kind: 'dataset_manifest',
  name: 'demo-dataset',
  version: '1.0.0',
  created_at: '2026-10-02T12:00:00.000Z',
  actor: { contributor: 'tester', key_id: null },
  hash_algorithm: 'sha256',
  file_count: 1,
  total_bytes: 4,
  merkle_root: 'sha256:c4b542aff90fd316b787fd1635ce2409ad7572ba9684a5eea53e3f78db6902cf',
  files: [{ path: 'a.png', size: 4, sha256: '1111111111111111111111111111111111111111111111111111111111111111' }],
  policy: { extensions: ['*'], allowSymlinks: false, maxFileSize: null },
  policy_findings: [],
  record_hash: 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
  signature: null,
};
