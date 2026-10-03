const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  computePipelineIdentity,
  readRuntimeFacts,
  validatePipelineManifest,
  parsePipelineManifest,
  registerPipeline,
  verifyPipeline,
  PIPELINE_FINDING_SEVERITY,
} = require('../../../src/visionguard/pipeline');
const { loadPipelineManifest, pipelineManifestPath, ensureStoreDirs } = require('../../../src/visionguard/store');
const { hashRecord, canonicalJson } = require('../../../src/visionguard/canonical');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');
const { generateKeyPair, savePrivateKey, verifySignature } = require('../../../src/visionguard/keys');

const FIXED_NOW = '2026-10-02T12:00:00.000Z';
const ACTOR = { contributor: 'tester', key_id: null };

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
    return true;
  });
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function makeFixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pipe-'));
  t.after(() => {
    try {
      fs.rmSync(parent, { recursive: true, force: true });
    } catch {
    }
  });
  const root = path.join(parent, 'root');
  const storeDir = path.join(parent, 'store');
  fs.mkdirSync(root, { recursive: true });
  return { parent, root, storeDir };
}

function writeFile(root, rel, content) {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
  return abs;
}

function specFor(root) {
  writeFile(root, 'pipeline.py', 'print("hello")\n');
  writeFile(root, 'requirements.lock', 'onnxruntime==1.2.3\n');
  writeFile(root, 'preprocess.json', '{"resize": "64x64"}\n');
  return {
    root,
    code: { git_commit: 'abc1234', files: [{ path: 'pipeline.py' }] },
    preprocess_config: { path: 'preprocess.json' },
    dependency_lock: { path: 'requirements.lock' },
    parameters: { resize: '64x64' },
  };
}

describe('VisionGuard pipeline identity', () => {
  it('should compute a deterministic identity independent of key order', () => {
    const a = computePipelineIdentity({
      code: { files: [{ path: 'pipeline.py', sha256: 'a'.repeat(64) }], git_commit: null },
      parameters: { resize: '64x64' },
      runtime: { language: 'node', version: 'v24.16.0', libraries: [] },
    });
    const b = computePipelineIdentity({
      parameters: { resize: '64x64' },
      runtime: { language: 'node', version: 'v24.16.0', libraries: [] },
      code: { git_commit: null, files: [{ path: 'pipeline.py', sha256: 'a'.repeat(64) }] },
    });
    assert.deepEqual(a, b);
    assert.equal(hashRecord(a), hashRecord(b));
    assert.equal(a.kind, 'pipeline_identity');
    assert.equal(a.schema_version, '1.0');
    assert.equal(a.preprocess_config, null);
    assert.equal(a.dependency_lock, null);
    assert.deepEqual(a.parameters, { resize: '64x64' });
  });

  it('should hash identity files from the artifact root', (t) => {
    const { root } = makeFixture(t);
    const spec = specFor(root);
    const identity = computePipelineIdentity(spec);
    const expected = sha256(fs.readFileSync(path.join(root, 'pipeline.py')));
    assert.equal(identity.code.files[0].path, 'pipeline.py');
    assert.equal(identity.code.files[0].sha256, expected);
    assert.equal(identity.preprocess_config.sha256, sha256(fs.readFileSync(path.join(root, 'preprocess.json'))));
    assert.equal(identity.dependency_lock.sha256, sha256(fs.readFileSync(path.join(root, 'requirements.lock'))));
  });

  it('should accept precomputed hashes without reading files', () => {
    const identity = computePipelineIdentity({
      code: { files: [{ path: 'a.py', sha256: 'b'.repeat(64) }] },
      runtime: { language: 'node', version: 'v1', libraries: [] },
    });
    assert.equal(identity.code.files[0].sha256, 'b'.repeat(64));
  });

  it('should require a root when a hash is not supplied', () => {
    throwsCode(
      () => computePipelineIdentity({ code: { files: [{ path: 'a.py' }] } }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
  });

  it('should reject unsafe identity paths', () => {
    throwsCode(
      () => computePipelineIdentity({ code: { files: [{ path: '../escape.py', sha256: 'a'.repeat(64) }] } }),
      ERROR_CODES.VG_PATH_TRAVERSAL
    );
    throwsCode(
      () => computePipelineIdentity({ code: { files: [{ path: '/etc/passwd', sha256: 'a'.repeat(64) }] } }),
      ERROR_CODES.VG_PATH_ABSOLUTE
    );
    throwsCode(
      () => computePipelineIdentity({ code: { files: [{ path: 'a\u0000b', sha256: 'a'.repeat(64) }] } }),
      ERROR_CODES.VG_PATH_NUL
    );
  });

  it('should reject duplicate and unknown fields', () => {
    throwsCode(
      () =>
        computePipelineIdentity({
          code: {
            files: [
              { path: 'a.py', sha256: 'a'.repeat(64) },
              { path: 'a.py', sha256: 'b'.repeat(64) },
            ],
          },
        }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(() => computePipelineIdentity({ nope: true }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(
      () => computePipelineIdentity({ code: { nope: 1 } }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(
      () => computePipelineIdentity({ runtime: { language: 'node', version: 'v1', libraries: [], nope: 1 } }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
  });

  it('should enforce metadata limits on parameters', () => {
    let params = {};
    for (let i = 0; i < 8; i++) params = { nested: params };
    throwsCode(() => computePipelineIdentity({ parameters: params }), ERROR_CODES.VG_LIMIT_METADATA);
  });

  it('should refuse to hash through a symbolic link', (t) => {
    const { parent, root } = makeFixture(t);
    const target = path.join(parent, 'real.py');
    fs.writeFileSync(target, 'print(1)\n');
    const linkPath = path.join(root, 'link.py');
    try {
      fs.symlinkSync(target, linkPath);
    } catch (err) {
      t.skip(`symlink creation unavailable: ${err.code}`);
      return;
    }
    throwsCode(
      () => computePipelineIdentity({ root, code: { files: [{ path: 'link.py' }] } }),
      ERROR_CODES.VG_SYMLINK_DENIED
    );
  });

  it('should report a missing identity file as unreadable', (t) => {
    const { root } = makeFixture(t);
    throwsCode(
      () => computePipelineIdentity({ root, code: { files: [{ path: 'absent.py' }] } }),
      ERROR_CODES.VG_UNREADABLE
    );
  });

  it('should expose runtime facts without importing untrusted code', (t) => {
    const { root } = makeFixture(t);
    assert.deepEqual(readRuntimeFacts(), { language: 'node', version: process.version, libraries: [] });
    const empty = readRuntimeFacts({ root });
    assert.equal(empty.language, 'node');
    assert.deepEqual(empty.libraries, []);

    fs.writeFileSync(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        packages: {
          '': { name: 'demo', version: '1.0.0' },
          'node_modules/onnxruntime': { version: '1.19.0' },
          'node_modules/@scope/pkg': { version: '2.0.1' },
        },
      })
    );
    const locked = readRuntimeFacts({ root });
    assert.deepEqual(locked.libraries, [
      { name: '@scope/pkg', version: '2.0.1' },
      { name: 'onnxruntime', version: '1.19.0' },
    ]);

    fs.rmSync(path.join(root, 'package-lock.json'));
    fs.writeFileSync(
      path.join(root, 'package.json'),
      JSON.stringify({ dependencies: { express: '^4.18.0' }, devDependencies: { tape: '5.0.1' } })
    );
    const declared = readRuntimeFacts({ root });
    assert.deepEqual(declared.libraries, [
      { name: 'express', version: '^4.18.0' },
      { name: 'tape', version: '5.0.1' },
    ]);
  });

  it('should sort code files and validate runtime inputs', () => {
    const identity = computePipelineIdentity({
      code: {
        files: [
          { path: 'z.py', sha256: '1'.repeat(64) },
          { path: 'a.py', sha256: '2'.repeat(64) },
        ],
      },
      runtime: { language: 'node', version: 'v1', libraries: [{ name: 'x', version: '1' }] },
    });
    assert.deepEqual(
      identity.code.files.map((entry) => entry.path),
      ['a.py', 'z.py']
    );
    throwsCode(
      () => computePipelineIdentity({ runtime: { language: 'node', version: 'v1', libraries: [{ name: 'x' }] } }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
  });
});

describe('VisionGuard pipeline manifests', () => {
  it('should register, save and reload a pipeline manifest', (t) => {
    const { root, storeDir } = makeFixture(t);
    const spec = specFor(root);
    ensureStoreDirs(storeDir);
    const manifest = registerPipeline({
      ...spec,
      name: 'demo-pipeline',
      version: '1.0.0',
      actor: ACTOR,
      now: FIXED_NOW,
      storeDir,
    });
    assert.equal(manifest.kind, 'pipeline_manifest');
    assert.equal(manifest.pipeline_id, hashRecord(manifest.identity));
    assert.equal(manifest.record_hash, hashRecord(manifest));
    assert.equal(manifest.signature, null);
    assert.ok(fs.existsSync(pipelineManifestPath(storeDir, 'demo-pipeline', '1.0.0')));

    const loaded = loadPipelineManifest(storeDir, 'demo-pipeline', '1.0.0');
    assert.deepEqual(loaded, manifest);
    assert.doesNotThrow(() => validatePipelineManifest(loaded));
  });

  it('should sign the manifest when a key file is provided', (t) => {
    const { parent, root, storeDir } = makeFixture(t);
    const spec = specFor(root);
    ensureStoreDirs(storeDir);
    const pair = generateKeyPair();
    const keyDir = path.join(parent, 'keys');
    const keyFile = savePrivateKey(keyDir, 'tester', pair.keyId, pair.privateKeyDer);
    const manifest = registerPipeline({
      ...spec,
      name: 'demo-pipeline',
      version: '1.0.0',
      actor: { contributor: 'tester', key_id: pair.keyId },
      keyFile,
      now: FIXED_NOW,
      storeDir,
    });
    assert.equal(typeof manifest.signature, 'string');
    assert.equal(verifySignature(pair.publicKeyDer, manifest.record_hash, manifest.signature), true);
  });

  it('should detect a mismatched signing key', (t) => {
    const { parent, root, storeDir } = makeFixture(t);
    const spec = specFor(root);
    ensureStoreDirs(storeDir);
    const pair = generateKeyPair();
    const other = generateKeyPair();
    const keyDir = path.join(parent, 'keys');
    const keyFile = savePrivateKey(keyDir, 'tester', other.keyId, other.privateKeyDer);
    throwsCode(
      () =>
        registerPipeline({
          ...spec,
          name: 'demo-pipeline',
          version: '1.0.0',
          actor: { contributor: 'tester', key_id: pair.keyId },
          keyFile,
          now: FIXED_NOW,
          storeDir,
        }),
      ERROR_CODES.VG_KEY_UNKNOWN
    );
  });

  it('should detect a tampered manifest on load', (t) => {
    const { root, storeDir } = makeFixture(t);
    const spec = specFor(root);
    ensureStoreDirs(storeDir);
    const manifest = registerPipeline({
      ...spec,
      name: 'demo-pipeline',
      version: '1.0.0',
      actor: ACTOR,
      now: FIXED_NOW,
      storeDir,
    });
    const filePath = pipelineManifestPath(storeDir, 'demo-pipeline', '1.0.0');
    const tampered = { ...manifest, parameters: { changed: true } };
    fs.writeFileSync(filePath, `${JSON.stringify(tampered, null, 2)}\n`);
    throwsCode(() => loadPipelineManifest(storeDir, 'demo-pipeline', '1.0.0'), ERROR_CODES.VG_MANIFEST_HASH_MISMATCH);
  });

  it('should detect an identity that no longer matches pipeline_id', () => {
    const identity = computePipelineIdentity({
      code: { files: [{ path: 'a.py', sha256: 'a'.repeat(64) }] },
      runtime: { language: 'node', version: 'v1', libraries: [] },
    });
    const manifest = {
      schema_version: '1.0',
      kind: 'pipeline_manifest',
      name: 'demo-pipeline',
      version: '1.0.0',
      created_at: FIXED_NOW,
      actor: ACTOR,
      identity,
      pipeline_id: 'sha256:' + 'c'.repeat(64),
      record_hash: '',
      signature: null,
    };
    manifest.record_hash = hashRecord(manifest);
    throwsCode(() => validatePipelineManifest(manifest), ERROR_CODES.VG_MANIFEST_HASH_MISMATCH);
  });

  it('should reject wrong kinds, versions and unknown strict fields', (t) => {
    const { root, storeDir } = makeFixture(t);
    const spec = specFor(root);
    ensureStoreDirs(storeDir);
    const manifest = registerPipeline({
      ...spec,
      name: 'demo-pipeline',
      version: '1.0.0',
      actor: ACTOR,
      now: FIXED_NOW,
      storeDir,
    });
    throwsCode(
      () => validatePipelineManifest({ ...manifest, kind: 'other' }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(
      () => validatePipelineManifest({ ...manifest, schema_version: '2.0' }),
      ERROR_CODES.VG_MANIFEST_VERSION
    );
    throwsCode(
      () => validatePipelineManifest({ ...manifest, surprise: 1 }, { strict: true }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(
      () => parsePipelineManifest('{"schema_version": "1.0",'),
      ERROR_CODES.VG_MANIFEST_MALFORMED
    );
    throwsCode(() => loadPipelineManifest(storeDir, 'absent', '1.0.0'), ERROR_CODES.VG_NOT_REGISTERED);
    throwsCode(
      () => registerPipeline({ ...spec, name: 'bad name', version: '1.0.0', actor: ACTOR, storeDir }),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
  });
});

describe('VisionGuard pipeline verification', () => {
  function registerDemo(root, storeDir, options = {}) {
    const spec = specFor(root);
    return registerPipeline({
      ...spec,
      name: 'demo-pipeline',
      version: '1.0.0',
      actor: ACTOR,
      now: FIXED_NOW,
      storeDir,
      ...options,
    });
  }

  it('should PASS when the registered manifest is intact', (t) => {
    const { root, storeDir } = makeFixture(t);
    const registered = registerDemo(root, storeDir);
    const result = verifyPipeline({ storeDir, name: 'demo-pipeline', version: '1.0.0', now: FIXED_NOW });
    assert.equal(result.status, 'PASS');
    assert.deepEqual(result.findings, []);
    assert.equal(result.pipeline_id, registered.pipeline_id);
  });

  it('should PASS when the spec still matches the current files', (t) => {
    const { root, storeDir } = makeFixture(t);
    registerDemo(root, storeDir);
    const result = verifyPipeline({
      storeDir,
      name: 'demo-pipeline',
      version: '1.0.0',
      root,
      code: { git_commit: 'abc1234', files: [{ path: 'pipeline.py' }] },
      preprocess_config: { path: 'preprocess.json' },
      dependency_lock: { path: 'requirements.lock' },
      parameters: { resize: '64x64' },
      now: FIXED_NOW,
    });
    assert.equal(result.status, 'PASS');
    assert.deepEqual(result.findings, []);
  });

  it('should FAIL when a pipeline file changed', (t) => {
    const { root, storeDir } = makeFixture(t);
    registerDemo(root, storeDir);
    fs.writeFileSync(path.join(root, 'pipeline.py'), 'print("pwned")\n');
    const result = verifyPipeline({
      storeDir,
      name: 'demo-pipeline',
      version: '1.0.0',
      root,
      code: { git_commit: 'abc1234', files: [{ path: 'pipeline.py' }] },
      now: FIXED_NOW,
    });
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(
      result.findings.map((item) => item.rule),
      ['VG-PIPE-001']
    );
    assert.equal(result.findings[0].severity, PIPELINE_FINDING_SEVERITY['VG-PIPE-001']);
  });

  it('should FAIL when the spec cannot be recomputed', (t) => {
    const { root, storeDir } = makeFixture(t);
    registerDemo(root, storeDir);
    fs.rmSync(path.join(root, 'pipeline.py'));
    const result = verifyPipeline({
      storeDir,
      name: 'demo-pipeline',
      version: '1.0.0',
      root,
      code: { git_commit: 'abc1234', files: [{ path: 'pipeline.py' }] },
      now: FIXED_NOW,
    });
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(
      result.findings.map((item) => item.rule),
      ['VG-PIPE-001']
    );
    assert.match(result.findings[0].detail, /cannot recompute/);
  });

  it('should FAIL when a supplied manifest is invalid', () => {
    const result = verifyPipeline({
      manifest: { kind: 'pipeline_manifest' },
      now: FIXED_NOW,
    });
    assert.equal(result.status, 'FAIL');
    assert.deepEqual(
      result.findings.map((item) => item.rule),
      ['VG-PIPE-001']
    );
  });

  it('should report NOT_CHECKED for an unregistered pipeline', (t) => {
    const { storeDir } = makeFixture(t);
    ensureStoreDirs(storeDir);
    const result = verifyPipeline({ storeDir, name: 'ghost', version: '1.0.0', now: FIXED_NOW });
    assert.equal(result.status, 'NOT_CHECKED');
    assert.deepEqual(result.findings, []);
  });

  it('should round trip the manifest through canonical JSON', (t) => {
    const { root, storeDir } = makeFixture(t);
    const manifest = registerDemo(root, storeDir);
    const parsed = parsePipelineManifest(canonicalJson(manifest));
    assert.deepEqual(parsed, manifest);
  });
});
