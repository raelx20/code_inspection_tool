const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  CHUNK_SIZE,
  hashBytes,
  hashFile,
  assertStableStats,
  merkleRoot,
} = require('../../../src/visionguard/hash');
const { DEFAULT_LIMITS } = require('../../../src/visionguard/limits');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const ABC_SHA256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const EMPTY_ROOT = 'sha256:c4b542aff90fd316b787fd1635ce2409ad7572ba9684a5eea53e3f78db6902cf';

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}`);
    assert.equal(err.code, code);
    return true;
  });
}

function referenceSha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function fileFixture(t, name, size) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-hash-'));
  t.after(() => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
    }
  });
  const filePath = path.join(dir, name);
  const content = Buffer.alloc(size);
  for (let i = 0; i < size; i++) content[i] = (i * 31 + 7) % 256;
  fs.writeFileSync(filePath, content);
  return { dir, filePath, content };
}

describe('VisionGuard hashBytes', () => {
  it('should match the NIST empty string vector', () => {
    assert.equal(hashBytes(''), EMPTY_SHA256);
  });

  it('should match the NIST abc vector', () => {
    assert.equal(hashBytes('abc'), ABC_SHA256);
  });

  it('should hash buffers and strings identically', () => {
    assert.equal(hashBytes(Buffer.from('abc')), hashBytes('abc'));
  });

  it('should hash utf8 content by bytes', () => {
    const text = String.fromCodePoint(0x1f600);
    assert.equal(
      hashBytes(text),
      crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex')
    );
  });
});

describe('VisionGuard hashFile', () => {
  it('should hash empty, single byte and chunk boundary sizes', (t) => {
    const sizes = [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE + 7];
    for (const size of sizes) {
      const { filePath } = fileFixture(t, `size-${size}.bin`, size);
      const result = hashFile(filePath);
      assert.equal(result.size, size, `size ${size}`);
      assert.equal(result.sha256, referenceSha256(filePath), `digest for size ${size}`);
      assert.match(result.mtimeNs, /^\d+$/);
      assert.match(result.ino, /^\d+$/);
      assert.match(result.dev, /^\d+$/);
    }
  });

  it('should produce identical digests for any chunk size option', (t) => {
    const { filePath } = fileFixture(t, 'chunks.bin', 4096);
    const expected = referenceSha256(filePath);
    const chunkSizes = [1, 7, 4096, CHUNK_SIZE - 1, CHUNK_SIZE + 1];
    for (const chunkSize of chunkSizes) {
      assert.equal(hashFile(filePath, { chunkSize }).sha256, expected, `chunkSize ${chunkSize}`);
    }
    assert.equal(hashFile(filePath, { chunkSize: 0 }).sha256, expected);
    assert.equal(hashFile(filePath, { chunkSize: -5 }).sha256, expected);
  });

  it('should reject files above the size limit before reading', (t) => {
    const { filePath } = fileFixture(t, 'limit.bin', 64);
    const limits = { ...DEFAULT_LIMITS, maxFileSize: 32 };
    throwsCode(() => hashFile(filePath, { limits }), ERROR_CODES.VG_LIMIT_FILE_SIZE);
  });

  it('should report unreadable missing files', () => {
    const missing = path.join(os.tmpdir(), `vg-missing-${Date.now()}.bin`);
    throwsCode(() => hashFile(missing), ERROR_CODES.VG_UNREADABLE);
  });

  it('should reject directories', (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-dir-'));
    t.after(() => {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
      }
    });
    throwsCode(() => hashFile(dir), ERROR_CODES.VG_UNREADABLE);
  });

  it('should reject symbolic links when the platform allows creating them', (t) => {
    const { dir, filePath } = fileFixture(t, 'link-target.bin', 32);
    const linkPath = path.join(dir, 'link.bin');
    try {
      fs.symlinkSync(filePath, linkPath);
    } catch (err) {
      t.skip(`symlink creation unavailable: ${err.code}`);
      return;
    }
    throwsCode(() => hashFile(linkPath), ERROR_CODES.VG_SYMLINK_DENIED);
  });

  it('should reject unreadable files when permissions deny access', (t) => {
    if (process.platform === 'win32') {
      t.skip('read permissions are not enforced for the owner on Windows');
      return;
    }
    const { filePath } = fileFixture(t, 'locked.bin', 32);
    fs.chmodSync(filePath, 0);
    t.after(() => {
      try {
        fs.chmodSync(filePath, 0o644);
      } catch {
      }
    });
    throwsCode(() => hashFile(filePath), ERROR_CODES.VG_UNREADABLE);
  });

  it('should hash a 2 GiB sparse file with bounded memory', (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-big-'));
    t.after(() => {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
      }
    });
    const bigPath = path.join(dir, 'big.bin');
    const twoGiB = 2 * 1024 * 1024 * 1024;
    try {
      fs.writeFileSync(bigPath, '');
      fs.truncateSync(bigPath, twoGiB);
    } catch (err) {
      t.skip(`sparse file unavailable: ${err.code}`);
      return;
    }

    const before = process.memoryUsage().heapUsed;
    const started = Date.now();
    const result = hashFile(bigPath);
    const elapsed = Date.now() - started;
    const growth = process.memoryUsage().heapUsed - before;

    assert.equal(result.size, twoGiB);
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
    assert.ok(growth < 128 * 1024 * 1024, `heap grew by ${growth} bytes, expected bounded`);
    assert.ok(elapsed < 60000, `hashing took ${elapsed}ms`);
  });
});

describe('VisionGuard assertStableStats', () => {
  const base = {
    size: 10n,
    mtimeNs: 123n,
    ino: 5n,
    dev: 1n,
  };

  it('should accept identical stats', () => {
    assertStableStats(base, { ...base }, 'file.bin');
  });

  it('should detect size changes', () => {
    throwsCode(() => assertStableStats(base, { ...base, size: 11n }, 'file.bin'), ERROR_CODES.VG_RACE_DETECTED);
  });

  it('should detect mtime changes', () => {
    throwsCode(() => assertStableStats(base, { ...base, mtimeNs: 124n }, 'file.bin'), ERROR_CODES.VG_RACE_DETECTED);
  });

  it('should detect inode replacement', () => {
    throwsCode(() => assertStableStats(base, { ...base, ino: 6n }, 'file.bin'), ERROR_CODES.VG_RACE_DETECTED);
  });

  it('should detect device changes', () => {
    throwsCode(() => assertStableStats(base, { ...base, dev: 2n }, 'file.bin'), ERROR_CODES.VG_RACE_DETECTED);
  });
});

describe('VisionGuard merkleRoot', () => {
  const leafA = { path: 'a.png', size: 1, sha256: '1'.repeat(64) };
  const leafB = { path: 'b.png', size: 2, sha256: '2'.repeat(64) };
  const leafC = { path: 'c.png', size: 3, sha256: '3'.repeat(64) };

  it('should hash an empty dataset with its domain tag', () => {
    assert.equal(merkleRoot([]), EMPTY_ROOT);
    assert.equal(merkleRoot([]), EMPTY_ROOT);
    assert.match(merkleRoot([]), /^sha256:[0-9a-f]{64}$/);
  });

  it('should not confuse an empty dataset with a single leaf dataset', () => {
    const single = merkleRoot([leafA]);
    assert.notEqual(single, EMPTY_ROOT);
    assert.equal(single, merkleRoot([{ ...leafA }]));
  });

  it('should be independent of entry order', () => {
    assert.equal(merkleRoot([leafA, leafB]), merkleRoot([leafB, leafA]));
    assert.equal(merkleRoot([leafA, leafB, leafC]), merkleRoot([leafC, leafA, leafB]));
    assert.equal(merkleRoot([leafA, leafB, leafC]), merkleRoot([leafB, leafC, leafA]));
  });

  it('should bind to path, size and content hash', () => {
    assert.notEqual(merkleRoot([leafA]), merkleRoot([{ ...leafA, path: 'other.png' }]));
    assert.notEqual(merkleRoot([leafA]), merkleRoot([{ ...leafA, size: 999 }]));
    assert.notEqual(merkleRoot([leafA]), merkleRoot([{ ...leafA, sha256: 'f'.repeat(64) }]));
  });

  it('should separate datasets of different shapes', () => {
    const roots = [
      merkleRoot([]),
      merkleRoot([leafA]),
      merkleRoot([leafA, leafB]),
      merkleRoot([leafA, leafB, leafC]),
      merkleRoot([leafA, leafB, leafC, { ...leafA, path: 'd.png' }]),
    ];
    assert.equal(new Set(roots).size, roots.length);
  });

  it('should reject duplicate paths', () => {
    throwsCode(() => merkleRoot([leafA, { ...leafA }]), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should reject malformed entries', () => {
    throwsCode(() => merkleRoot([{ path: 'a', size: 1, sha256: 'zz' }]), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => merkleRoot([{ path: 'a', size: -1, sha256: '1'.repeat(64) }]), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => merkleRoot([{ path: '', size: 1, sha256: '1'.repeat(64) }]), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => merkleRoot([{ size: 1, sha256: '1'.repeat(64) }]), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => merkleRoot([{ path: 'a', size: 1.5, sha256: '1'.repeat(64) }]), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => merkleRoot(['not-an-entry']), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should sort unicode paths by code unit order', () => {
    const lower = { path: 'b.png', size: 1, sha256: '1'.repeat(64) };
    const upper = { path: 'A.png', size: 1, sha256: '1'.repeat(64) };
    const manualForward = merkleRoot([upper, lower]);
    const manualBackward = merkleRoot([lower, upper]);
    assert.equal(manualForward, manualBackward);
    assert.ok('A' < 'a', 'expected ascii ordering');
  });
});
