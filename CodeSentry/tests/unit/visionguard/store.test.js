const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  ensureStoreDirs,
  datasetManifestPath,
  modelManifestPath,
  atomicWriteFileSync,
  saveDatasetManifest,
  loadDatasetManifest,
  saveModelManifest,
  loadModelManifest,
  assertStoreOutside,
  storeJsonPath,
  provenanceLogPath,
  provenanceLockPath,
  buildStoreMetadata,
  validateStoreMetadata,
  saveStoreMetadata,
  loadStoreMetadata,
  withLogLock,
  appendLogLine,
  readProvenanceText,
} = require('../../../src/visionguard/store');
const { registerDataset } = require('../../../src/visionguard/manifest');
const { hashRecord } = require('../../../src/visionguard/canonical');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
    return true;
  });
}

function makeFixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-store-'));
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

function makeManifest(root) {
  fs.writeFileSync(path.join(root, 'a.png'), 'content');
  return registerDataset({
    path: root,
    name: 'store-demo',
    version: '1.0.0',
    actor: { contributor: 'tester', key_id: null },
    now: '2026-10-02T12:00:00.000Z',
  });
}

describe('VisionGuard store layout', () => {
  it('should create the full store directory tree', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    for (const sub of [
      path.join('manifests', 'dataset'),
      path.join('manifests', 'model'),
      path.join('manifests', 'pipeline'),
      'keys',
      'anchors',
    ]) {
      assert.ok(fs.statSync(path.join(storeDir, sub)).isDirectory(), sub);
    }
  });

  it('should reject an empty store directory', () => {
    throwsCode(() => ensureStoreDirs(''), ERROR_CODES.VG_INTERNAL);
  });

  it('should build manifest paths only from validated name and version', () => {
    const filePath = datasetManifestPath('/store', 'my-dataset', '1.0.0');
    assert.equal(filePath, path.join('/store', 'manifests', 'dataset', 'my-dataset', '1.0.0.json'));
    throwsCode(() => datasetManifestPath('/store', '../escape', '1.0.0'), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => datasetManifestPath('/store', 'ok', '../1.json'), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => datasetManifestPath('/store', 'a/b', '1.0.0'), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => datasetManifestPath('/store', '.hidden', '1.0.0'), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => datasetManifestPath('/store', 'ok', 'a\\b'), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });
});

describe('VisionGuard atomic manifest writes', () => {
  it('should write content and leave no temp files behind', (t) => {
    const { storeDir } = makeFixture(t);
    const target = path.join(storeDir, 'nested', 'file.json');
    atomicWriteFileSync(target, '{"ok":true}\n');
    assert.equal(fs.readFileSync(target, 'utf8'), '{"ok":true}\n');
    const siblings = fs.readdirSync(path.join(storeDir, 'nested'));
    assert.deepEqual(siblings, ['file.json']);
  });

  it('should replace an existing file atomically', (t) => {
    const { storeDir } = makeFixture(t);
    const target = path.join(storeDir, 'file.json');
    atomicWriteFileSync(target, 'first');
    atomicWriteFileSync(target, 'second');
    assert.equal(fs.readFileSync(target, 'utf8'), 'second');
    assert.deepEqual(fs.readdirSync(storeDir), ['file.json']);
  });

  it('should clean up the temp file when the rename target cannot be replaced', (t) => {
    const { storeDir } = makeFixture(t);
    fs.mkdirSync(storeDir, { recursive: true });
    const target = path.join(storeDir, 'file.json');
    fs.mkdirSync(target);
    assert.throws(
      () => atomicWriteFileSync(target, 'data'),
      (err) => ['EISDIR', 'ENOTEMPTY', 'EPERM', 'EACCES'].includes(err.code)
    );
    const leftovers = fs.readdirSync(storeDir).filter((name) => name.includes('.tmp'));
    assert.deepEqual(leftovers, []);
    assert.ok(fs.statSync(target).isDirectory());
  });
});

describe('VisionGuard manifest save and load', () => {
  it('should save and load a manifest round trip', (t) => {
    const { root, storeDir } = makeFixture(t);
    const manifest = makeManifest(root);
    const savedPath = saveDatasetManifest(storeDir, manifest);
    assert.equal(savedPath, datasetManifestPath(storeDir, 'store-demo', '1.0.0'));

    const loaded = loadDatasetManifest(storeDir, 'store-demo', '1.0.0');
    assert.deepEqual(loaded, manifest);
    assert.equal(loaded.record_hash, manifest.record_hash);
  });

  it('should overwrite an existing manifest on re-registration', (t) => {
    const { root, storeDir } = makeFixture(t);
    const first = makeManifest(root);
    saveDatasetManifest(storeDir, first);
    fs.writeFileSync(path.join(root, 'a.png'), 'changed content');
    const second = registerDataset({
      path: root,
      name: 'store-demo',
      version: '1.0.0',
      actor: { contributor: 'tester', key_id: null },
      now: '2026-10-02T13:00:00.000Z',
      storeDir,
    });
    const loaded = loadDatasetManifest(storeDir, 'store-demo', '1.0.0');
    assert.deepEqual(loaded, second);
    assert.notEqual(loaded.record_hash, first.record_hash);
    assert.equal(second.created_at, '2026-10-02T13:00:00.000Z');
    const files = fs.readdirSync(path.join(storeDir, 'manifests', 'dataset', 'store-demo'));
    assert.deepEqual(files, ['1.0.0.json']);
  });

  it('should report unregistered datasets', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    throwsCode(() => loadDatasetManifest(storeDir, 'nope', '1.0.0'), ERROR_CODES.VG_NOT_REGISTERED);
  });

  it('should enforce the manifest size limit on save and load', (t) => {
    const { root, storeDir } = makeFixture(t);
    const manifest = makeManifest(root);
    throwsCode(
      () => saveDatasetManifest(storeDir, manifest, { limits: { maxManifestBytes: 16 } }),
      ERROR_CODES.VG_LIMIT_MANIFEST
    );
    saveDatasetManifest(storeDir, manifest);
    throwsCode(
      () => loadDatasetManifest(storeDir, 'store-demo', '1.0.0', { limits: { maxManifestBytes: 16 } }),
      ERROR_CODES.VG_LIMIT_MANIFEST
    );
  });

  it('should reject malformed stored manifests', (t) => {
    const { root, storeDir } = makeFixture(t);
    const manifest = makeManifest(root);
    const filePath = saveDatasetManifest(storeDir, manifest);
    fs.writeFileSync(filePath, '{"schema_version": "1.0",');
    throwsCode(() => loadDatasetManifest(storeDir, 'store-demo', '1.0.0'), ERROR_CODES.VG_MANIFEST_MALFORMED);

    const other = JSON.parse(JSON.stringify(manifest));
    other.kind = 'wrong_kind';
    other.record_hash = manifest.record_hash;
    fs.writeFileSync(filePath, JSON.stringify(other));
    throwsCode(() => loadDatasetManifest(storeDir, 'store-demo', '1.0.0'), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should refuse to load a manifest reached through a symbolic link', (t) => {
    const { parent, root, storeDir } = makeFixture(t);
    const manifest = makeManifest(root);
    const filePath = saveDatasetManifest(storeDir, manifest);
    const elsewhere = path.join(parent, 'elsewhere.json');
    fs.writeFileSync(elsewhere, fs.readFileSync(filePath));
    fs.rmSync(filePath);
    try {
      fs.symlinkSync(elsewhere, filePath);
    } catch (err) {
      t.skip(`symlink creation unavailable: ${err.code}`);
      return;
    }
    throwsCode(() => loadDatasetManifest(storeDir, 'store-demo', '1.0.0'), ERROR_CODES.VG_UNREADABLE);
  });

  it('should save and load a model manifest by id and version', (t) => {
    const { storeDir } = makeFixture(t);
    const manifest = {
      schema_version: '1.0',
      kind: 'model_manifest',
      id: 'demo-model',
      version: '1.0.0',
      format: 'other',
      detected_format: 'other',
      size: 5,
      sha256: '1'.repeat(64),
      created_at: '2026-10-02T12:00:00.000Z',
      actor: { contributor: 'tester', key_id: null },
      metadata: {},
      record_hash: '',
      signature: null,
    };
    manifest.record_hash = hashRecord(manifest);

    const filePath = modelManifestPath(storeDir, 'demo-model', '1.0.0');
    assert.equal(filePath, path.join(storeDir, 'manifests', 'model', 'demo-model', '1.0.0.json'));
    throwsCode(() => modelManifestPath('/store', '../escape', '1.0.0'), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => modelManifestPath('/store', 'ok', '../1.json'), ERROR_CODES.VG_MANIFEST_SCHEMA);

    const savedPath = saveModelManifest(storeDir, manifest);
    assert.equal(savedPath, filePath);
    const loaded = loadModelManifest(storeDir, 'demo-model', '1.0.0');
    assert.deepEqual(loaded, manifest);
    throwsCode(() => loadModelManifest(storeDir, 'nope', '1.0.0'), ERROR_CODES.VG_NOT_REGISTERED);
  });
});

describe('VisionGuard store containment guard', () => {
  it('should reject a store inside the dataset root', (t) => {
    const { root } = makeFixture(t);
    throwsCode(() => assertStoreOutside(root, path.join(root, '.visionguard')), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => assertStoreOutside(root, root), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(
      () => assertStoreOutside(root, path.join(root, 'sub', '..', '.visionguard')),
      ERROR_CODES.VG_PATH_INVALID
    );
  });

  it('should allow a store outside the dataset root', (t) => {
    const { parent, root, storeDir } = makeFixture(t);
    assertStoreOutside(root, storeDir);
    assertStoreOutside(root, path.join(parent, 'sibling'));
  });

  it('should block registration when the store would live inside the dataset', (t) => {
    const { root } = makeFixture(t);
    fs.writeFileSync(path.join(root, 'a.png'), 'a');
    throwsCode(
      () =>
        registerDataset({
          path: root,
          name: 'guarded',
          version: '1.0.0',
          actor: { contributor: 'tester', key_id: null },
          now: '2026-10-02T12:00:00.000Z',
          storeDir: path.join(root, '.visionguard'),
        }),
      ERROR_CODES.VG_PATH_INVALID
    );
    assert.ok(!fs.existsSync(path.join(root, '.visionguard')));
  });
});

describe('VisionGuard store metadata', () => {
  it('should save and load store.json with a verified record hash', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const metadata = buildStoreMetadata({ now: '2026-10-02T12:00:00.000Z' });
    assert.equal(metadata.kind, 'store');
    assert.equal(metadata.hash_algorithm, 'sha256');
    assert.equal(metadata.record_hash, hashRecord(metadata));
    assert.doesNotThrow(() => validateStoreMetadata(metadata));
    assert.equal(storeJsonPath(storeDir), path.join(storeDir, 'store.json'));

    saveStoreMetadata(storeDir, metadata);
    const loaded = loadStoreMetadata(storeDir);
    assert.deepEqual(loaded, metadata);
  });

  it('should detect a tampered store.json', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const metadata = buildStoreMetadata({ now: '2026-10-02T12:00:00.000Z' });
    const filePath = saveStoreMetadata(storeDir, metadata);
    fs.writeFileSync(
      filePath,
      `${JSON.stringify({ ...metadata, created_at: '2020-01-01T00:00:00.000Z' }, null, 2)}\n`
    );
    throwsCode(() => loadStoreMetadata(storeDir), ERROR_CODES.VG_MANIFEST_HASH_MISMATCH);
  });

  it('should reject wrong kinds, versions and malformed content', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    throwsCode(() => loadStoreMetadata(storeDir), ERROR_CODES.VG_NOT_REGISTERED);

    const metadata = buildStoreMetadata({ now: '2026-10-02T12:00:00.000Z' });
    const filePath = saveStoreMetadata(storeDir, metadata);
    fs.writeFileSync(filePath, '{"schema_version": "1.0",');
    throwsCode(() => loadStoreMetadata(storeDir), ERROR_CODES.VG_MANIFEST_MALFORMED);

    const wrongKind = { ...metadata, kind: 'other', record_hash: hashRecord({ ...metadata, kind: 'other' }) };
    throwsCode(() => validateStoreMetadata(wrongKind), ERROR_CODES.VG_MANIFEST_SCHEMA);

    const wrongVersion = { ...metadata, schema_version: '2.0' };
    wrongVersion.record_hash = hashRecord(wrongVersion);
    throwsCode(() => validateStoreMetadata(wrongVersion), ERROR_CODES.VG_MANIFEST_VERSION);

    const wrongAlgorithm = { ...metadata, hash_algorithm: 'md5' };
    wrongAlgorithm.record_hash = hashRecord(wrongAlgorithm);
    throwsCode(() => validateStoreMetadata(wrongAlgorithm), ERROR_CODES.VG_MANIFEST_SCHEMA);

    const noHash = { ...metadata };
    delete noHash.record_hash;
    throwsCode(() => validateStoreMetadata(noHash), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validateStoreMetadata(null), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });
});

describe('VisionGuard provenance log lock', () => {
  it('should hold the lock while running and release it afterwards', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const lockPath = provenanceLockPath(storeDir);
    let held = false;
    const result = withLogLock(storeDir, () => {
      held = fs.existsSync(lockPath);
      return 42;
    });
    assert.equal(held, true);
    assert.equal(result, 42);
    assert.ok(!fs.existsSync(lockPath));
  });

  it('should refuse a fresh lock held elsewhere', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const lockPath = provenanceLockPath(storeDir);
    fs.writeFileSync(lockPath, 'other-process\n');
    throwsCode(
      () => withLogLock(storeDir, () => 'unreachable', { timeoutMs: 50, retryMs: 5 }),
      ERROR_CODES.VG_STORE_LOCKED
    );
    assert.ok(fs.existsSync(lockPath));
  });

  it('should steal a stale lock', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const lockPath = provenanceLockPath(storeDir);
    fs.writeFileSync(lockPath, 'stale\n');
    const past = new Date(Date.now() - 60000);
    fs.utimesSync(lockPath, past, past);
    const result = withLogLock(storeDir, () => 'acquired', { timeoutMs: 500, staleMs: 30000 });
    assert.equal(result, 'acquired');
    assert.ok(!fs.existsSync(lockPath));
  });

  it('should release the lock when the callback throws', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const lockPath = provenanceLockPath(storeDir);
    assert.throws(
      () =>
        withLogLock(storeDir, () => {
          throw new Error('boom');
        }),
      /boom/
    );
    assert.ok(!fs.existsSync(lockPath));
  });
});

describe('VisionGuard provenance log writes', () => {
  it('should append lines separated by newlines', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const size1 = appendLogLine(storeDir, '{"a":1}');
    const size2 = appendLogLine(storeDir, '{"b":2}');
    assert.equal(size1, 8);
    assert.equal(size2, 16);
    assert.equal(fs.readFileSync(provenanceLogPath(storeDir), 'utf8'), '{"a":1}\n{"b":2}\n');
    assert.ok(!fs.existsSync(provenanceLockPath(storeDir)));
  });

  it('should reject empty lines and embedded newlines', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    throwsCode(() => appendLogLine(storeDir, ''), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => appendLogLine(storeDir, '{"a":1}\n{"b":2}'), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => appendLogLine(storeDir, '{"a":1}\r'), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => appendLogLine(storeDir, 42), ERROR_CODES.VG_INTERNAL);
  });

  it('should enforce the log size limit on append and read', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    appendLogLine(storeDir, '{"a":1}');
    throwsCode(
      () => appendLogLine(storeDir, `{"pad":"${'x'.repeat(64)}"}`, { limits: { maxLogBytes: 32 } }),
      ERROR_CODES.VG_LIMIT_LOG
    );
    throwsCode(
      () => readProvenanceText(storeDir, { limits: { maxLogBytes: 4 } }),
      ERROR_CODES.VG_LIMIT_LOG
    );
    const text = readProvenanceText(storeDir);
    assert.equal(text.exists, true);
    assert.equal(text.text, '{"a":1}\n');
    assert.equal(text.size, 8);
  });

  it('should report a missing log and reject a non file log', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const missing = readProvenanceText(storeDir);
    assert.equal(missing.exists, false);
    assert.equal(missing.text, '');
    fs.mkdirSync(provenanceLogPath(storeDir));
    throwsCode(() => readProvenanceText(storeDir), ERROR_CODES.VG_UNREADABLE);
  });

  it('should refuse to read or append through a symbolic link', (t) => {
    const { parent, storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const elsewhere = path.join(parent, 'elsewhere.log');
    fs.writeFileSync(elsewhere, '{"a":1}\n');
    try {
      fs.symlinkSync(elsewhere, provenanceLogPath(storeDir));
    } catch (err) {
      t.skip(`symlink creation unavailable: ${err.code}`);
      return;
    }
    throwsCode(() => readProvenanceText(storeDir), ERROR_CODES.VG_SYMLINK_DENIED);
    throwsCode(() => appendLogLine(storeDir, '{"b":2}'), ERROR_CODES.VG_SYMLINK_DENIED);
    assert.equal(fs.readFileSync(elsewhere, 'utf8'), '{"a":1}\n');
  });
});
