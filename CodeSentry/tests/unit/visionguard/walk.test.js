const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { walkDataset, normalizePolicy, DEFAULT_POLICY, MAX_FINDINGS_PER_RULE } = require('../../../src/visionguard/walk');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');
const { EMPTY_DATASET_DOMAIN } = require('../../../src/visionguard/hash');

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
    return true;
  });
}

function makeDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-walk-'));
  t.after(() => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
    }
  });
  return dir;
}

function writeFiles(root, spec) {
  for (const [rel, content] of Object.entries(spec)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
}

describe('VisionGuard walkDataset', () => {
  it('should walk nested directories and include image files', (t) => {
    const root = makeDir(t);
    writeFiles(root, {
      'images/train/0001.png': 'png-one',
      'images/train/0002.jpg': 'jpg-two',
      'labels/0001.txt': 'label-one',
      'README.md': 'readme',
    });
    const walk = walkDataset(root, { mode: 'register' });
    assert.deepEqual(
      walk.entries.map((entry) => entry.path),
      ['README.md', 'images/train/0001.png', 'images/train/0002.jpg', 'labels/0001.txt']
    );
    assert.equal(walk.stats.fileCount, 4);
    assert.ok(walk.stats.totalBytes > 0);
    assert.equal(walk.findings.length, 0);
    for (const entry of walk.entries) {
      assert.match(entry.sha256, /^[0-9a-f]{64}$/);
      assert.ok(Number.isSafeInteger(entry.size));
      assert.ok(!entry.path.includes('\\'), 'manifest paths must use forward slashes');
    }
  });

  it('should return entries sorted by path', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'z.png': 'z', 'a.png': 'a', 'm/b.png': 'b', 'm/a.png': 'a2' });
    const walk = walkDataset(root, { mode: 'register' });
    const paths = walk.entries.map((entry) => entry.path);
    assert.deepEqual(paths, ['a.png', 'm/a.png', 'm/b.png', 'z.png']);
  });

  it('should handle an empty directory', (t) => {
    const root = makeDir(t);
    const walk = walkDataset(root, { mode: 'register' });
    assert.deepEqual(walk.entries, []);
    assert.equal(walk.stats.fileCount, 0);
    assert.ok(EMPTY_DATASET_DOMAIN.length > 0);
  });

  it('should reject a missing root', (t) => {
    const missing = path.join(os.tmpdir(), `vg-missing-${Date.now()}`);
    throwsCode(() => walkDataset(missing, { mode: 'register' }), ERROR_CODES.VG_UNREADABLE);
  });

  it('should exclude symlinks with a policy finding in verify mode', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'real.png': 'real', 'outside.png': 'outside' });
    const linkPath = path.join(root, 'link.png');
    try {
      fs.symlinkSync(path.join(root, 'outside.png'), linkPath);
    } catch (err) {
      t.skip(`symlink creation unavailable: ${err.code}`);
      return;
    }
    const walk = walkDataset(root, { mode: 'verify' });
    assert.deepEqual(
      walk.entries.map((entry) => entry.path),
      ['outside.png', 'real.png']
    );
    assert.equal(walk.findingCounts['VG-DATA-005'], 1);
    const finding = walk.findings.find((item) => item.rule === 'VG-DATA-005');
    assert.equal(finding.path, 'link.png');
    assert.equal(finding.severity, 'HIGH');
    assert.equal(finding.detail, 'symbolic link excluded');
  });

  it('should throw on symlinks in strict register mode', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'real.png': 'real' });
    try {
      fs.symlinkSync(path.join(root, 'real.png'), path.join(root, 'link.png'));
    } catch (err) {
      t.skip(`symlink creation unavailable: ${err.code}`);
      return;
    }
    throwsCode(() => walkDataset(root, { mode: 'register', strict: true }), ERROR_CODES.VG_SYMLINK_DENIED);
    const walk = walkDataset(root, { mode: 'register', strict: false });
    assert.equal(walk.findingCounts['VG-DATA-005'], 1);
    assert.equal(walk.entries.length, 1);
  });

  it('should skip special files with a policy finding', (t) => {
    if (process.platform === 'win32') {
      t.skip('fifo creation is unavailable on Windows');
      return;
    }
    const root = makeDir(t);
    writeFiles(root, { 'real.png': 'real' });
    const fifoPath = path.join(root, 'pipe.fifo');
    try {
      execFileSync('mkfifo', [fifoPath]);
    } catch {
      t.skip('mkfifo unavailable');
      return;
    }
    const walk = walkDataset(root, { mode: 'verify' });
    assert.equal(walk.findingCounts['VG-DATA-011'], 1);
    const finding = walk.findings.find((item) => item.rule === 'VG-DATA-011');
    assert.equal(finding.path, 'pipe.fifo');
    assert.deepEqual(
      walk.entries.map((entry) => entry.path),
      ['real.png']
    );
  });

  it('should apply extension policy case-insensitively', (t) => {
    const root = makeDir(t);
    writeFiles(root, {
      'a.png': 'a',
      'B.PNG': 'b',
      'notes.txt': 'notes',
      'noext': 'bare',
    });
    const walk = walkDataset(root, { mode: 'register', policy: { extensions: ['.png'] } });
    assert.deepEqual(
      walk.entries.map((entry) => entry.path),
      ['B.PNG', 'a.png']
    );
    assert.equal(walk.findingCounts['VG-DATA-012'], 2);
    assert.deepEqual(walk.policy.extensions, ['.png']);
  });

  it('should accept every file with the default wildcard policy', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'a.anything': 'x', 'b.bin': 'y' });
    const walk = walkDataset(root, { mode: 'register' });
    assert.equal(walk.entries.length, 2);
    assert.deepEqual(DEFAULT_POLICY.extensions, ['*']);
  });

  it('should cap stored findings per rule while keeping accurate counts', (t) => {
    const root = makeDir(t);
    const spec = { 'keep.png': 'keep' };
    for (let i = 0; i < MAX_FINDINGS_PER_RULE + 5; i++) {
      spec[`skip-${String(i).padStart(3, '0')}.txt`] = 'x';
    }
    writeFiles(root, spec);
    const walk = walkDataset(root, { mode: 'register', policy: { extensions: ['.png'] } });
    assert.equal(walk.findingCounts['VG-DATA-012'], MAX_FINDINGS_PER_RULE + 5);
    assert.equal(walk.findings.length, MAX_FINDINGS_PER_RULE);
    assert.equal(walk.entries.length, 1);
  });

  it('should enforce the file count limit', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'a.png': 'a', 'b.png': 'b', 'c.png': 'c' });
    throwsCode(
      () => walkDataset(root, { mode: 'register', limits: { maxFiles: 2 } }),
      ERROR_CODES.VG_LIMIT_FILE_COUNT
    );
  });

  it('should enforce the file size limit', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'small.png': 'abc', 'big.png': '0123456789' });
    throwsCode(
      () => walkDataset(root, { mode: 'register', limits: { maxFileSize: 4 } }),
      ERROR_CODES.VG_LIMIT_FILE_SIZE
    );
    throwsCode(
      () => walkDataset(root, { mode: 'register', policy: { maxFileSize: 4 } }),
      ERROR_CODES.VG_LIMIT_FILE_SIZE
    );
  });

  it('should enforce the total byte limit', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'a.png': '12345', 'b.png': '67890' });
    throwsCode(
      () => walkDataset(root, { mode: 'register', limits: { maxTotalBytes: 7 } }),
      ERROR_CODES.VG_LIMIT_TOTAL_BYTES
    );
  });

  it('should enforce the depth limit', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'a/b/c/d/e.png': 'deep' });
    throwsCode(
      () => walkDataset(root, { mode: 'register', limits: { maxDepth: 2 } }),
      ERROR_CODES.VG_LIMIT_DEPTH
    );
    const ok = walkDataset(root, { mode: 'register', limits: { maxDepth: 4 } });
    assert.equal(ok.entries.length, 1);
  });

  it('should enforce the directory count limit', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'd1/a.png': 'a', 'd2/b.png': 'b', 'd3/c.png': 'c' });
    throwsCode(
      () => walkDataset(root, { mode: 'register', limits: { maxDirs: 2 } }),
      ERROR_CODES.VG_LIMIT_DIR_COUNT
    );
    const ok = walkDataset(root, { mode: 'register', limits: { maxDirs: 4 } });
    assert.equal(ok.entries.length, 3);
    assert.ok(ok.stats.dirCount <= 4);
  });

  it('should collect unreadable files in verify mode instead of throwing', (t) => {
    if (process.platform === 'win32') {
      t.skip('read permissions are not enforced for the owner on Windows');
      return;
    }
    const root = makeDir(t);
    writeFiles(root, { 'ok.png': 'ok', 'locked.png': 'locked' });
    fs.chmodSync(path.join(root, 'locked.png'), 0);
    t.after(() => {
      try {
        fs.chmodSync(path.join(root, 'locked.png'), 0o644);
      } catch {
      }
    });
    const walk = walkDataset(root, { mode: 'verify' });
    assert.equal(walk.unreadable.length, 1);
    assert.equal(walk.unreadable[0].path, 'locked.png');
    assert.deepEqual(
      walk.entries.map((entry) => entry.path),
      ['ok.png']
    );
    throwsCode(() => walkDataset(root, { mode: 'register' }), ERROR_CODES.VG_UNREADABLE);
  });

  it('should reject backslash filenames', (t) => {
    if (process.platform === 'win32') {
      t.skip('backslashes are path separators on Windows');
      return;
    }
    const root = makeDir(t);
    writeFiles(root, { 'ok.png': 'ok' });
    fs.writeFileSync(path.join(root, 'evil\\name.png'), 'x');
    throwsCode(() => walkDataset(root, { mode: 'register' }), ERROR_CODES.VG_PATH_INVALID);
    const walk = walkDataset(root, { mode: 'verify' });
    assert.equal(walk.unreadable.length, 1);
    assert.equal(walk.unreadable[0].code, ERROR_CODES.VG_PATH_INVALID);
    assert.deepEqual(
      walk.entries.map((entry) => entry.path),
      ['ok.png']
    );
  });

  it('should treat a disappeared file between readdir and lstat as unreadable in verify mode', (t) => {
    const root = makeDir(t);
    writeFiles(root, { 'ghost.png': 'ghost', 'real.png': 'real' });
    const ghostAbs = path.join(root, 'ghost.png');
    const original = fs.lstatSync;
    let patched = false;
    fs.lstatSync = function patchedLstat(target, ...rest) {
      if (!patched && String(target) === ghostAbs) {
        patched = true;
        const err = new Error(`ENOENT: ${target}`);
        err.code = 'ENOENT';
        throw err;
      }
      return original.call(fs, target, ...rest);
    };
    t.after(() => {
      fs.lstatSync = original;
    });
    const walk = walkDataset(root, { mode: 'verify' });
    fs.lstatSync = original;
    assert.equal(walk.unreadable.length, 1);
    assert.equal(walk.unreadable[0].path, 'ghost.png');
    assert.deepEqual(
      walk.entries.map((entry) => entry.path),
      ['real.png']
    );
  });
});

describe('VisionGuard normalizePolicy', () => {
  it('should return the default policy for empty input', () => {
    assert.deepEqual(normalizePolicy(undefined), DEFAULT_POLICY);
    assert.deepEqual(normalizePolicy(null), DEFAULT_POLICY);
  });

  it('should normalize and dedupe extensions', () => {
    const policy = normalizePolicy({ extensions: ['.PNG', '.png', '.jpg'] });
    assert.deepEqual(policy.extensions, ['.jpg', '.png']);
    assert.equal(policy.allowSymlinks, false);
    assert.equal(policy.maxFileSize, null);
  });

  it('should reject invalid policies', () => {
    throwsCode(() => normalizePolicy([]), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => normalizePolicy({ extensions: [] }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => normalizePolicy({ extensions: ['png'] }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => normalizePolicy({ extensions: ['*', '.png'] }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => normalizePolicy({ allowSymlinks: true }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => normalizePolicy({ allowSymlinks: 'yes' }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => normalizePolicy({ maxFileSize: -1 }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => normalizePolicy({ typo: 1 }), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });
});
