const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  normalizeRelPath,
  resolveRootReal,
  assertInsideRoot,
  resolveArtifactPath,
  assertNoSymlink,
  findPathCollisions,
} = require('../../../src/visionguard/paths');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

const NUL = String.fromCharCode(0);
const BELL = String.fromCharCode(7);
const RTL_OVERRIDE = String.fromCharCode(0x202e);
const LONE_HIGH = String.fromCharCode(0xd800);
const LONE_LOW = String.fromCharCode(0xdc00);
const NFD_NAME = String.fromCodePoint(0x63, 0x61, 0x66, 0x65, 0x301);
const NFC_NAME = String.fromCodePoint(0x63, 0x61, 0x66, 0xe9);

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
    return true;
  });
}

describe('VisionGuard normalizeRelPath', () => {
  it('should accept plain relative paths', () => {
    assert.equal(normalizeRelPath('a/b.png'), 'a/b.png');
    assert.equal(normalizeRelPath('images/train/0001.jpg'), 'images/train/0001.jpg');
    assert.equal(normalizeRelPath('a.b.c'), 'a.b.c');
  });

  it('should unify windows and posix separators', () => {
    assert.equal(normalizeRelPath('a\\b\\c.png'), 'a/b/c.png');
    assert.equal(normalizeRelPath('a/b\\c.png'), 'a/b/c.png');
  });

  it('should strip leading dot segments', () => {
    assert.equal(normalizeRelPath('./a/b.png'), 'a/b.png');
    assert.equal(normalizeRelPath('././a'), 'a');
    assert.equal(normalizeRelPath('a/./b'), 'a/b');
  });

  it('should normalize to NFC', () => {
    assert.equal(normalizeRelPath(`${NFD_NAME}/x.png`), `${NFC_NAME}/x.png`);
    assert.equal(normalizeRelPath('a/b'), normalizeRelPath('a/b'));
  });

  it('should reject empty and non string input', () => {
    throwsCode(() => normalizeRelPath(''), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath(null), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath(undefined), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath(42), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath('.'), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath('./'), ERROR_CODES.VG_PATH_INVALID);
  });

  it('should reject traversal segments', () => {
    throwsCode(() => normalizeRelPath('../x'), ERROR_CODES.VG_PATH_TRAVERSAL);
    throwsCode(() => normalizeRelPath('a/../x'), ERROR_CODES.VG_PATH_TRAVERSAL);
    throwsCode(() => normalizeRelPath('a/..\\x'), ERROR_CODES.VG_PATH_TRAVERSAL);
    throwsCode(() => normalizeRelPath('a/b/..'), ERROR_CODES.VG_PATH_TRAVERSAL);
    throwsCode(() => normalizeRelPath('..'), ERROR_CODES.VG_PATH_TRAVERSAL);
  });

  it('should reject absolute paths', () => {
    throwsCode(() => normalizeRelPath('/etc/passwd'), ERROR_CODES.VG_PATH_ABSOLUTE);
    throwsCode(() => normalizeRelPath('\\windows\\system32'), ERROR_CODES.VG_PATH_ABSOLUTE);
    throwsCode(() => normalizeRelPath('C:/x.png'), ERROR_CODES.VG_PATH_ABSOLUTE);
    throwsCode(() => normalizeRelPath('c:\\x.png'), ERROR_CODES.VG_PATH_ABSOLUTE);
    throwsCode(() => normalizeRelPath('\\\\server\\share\\x.png'), ERROR_CODES.VG_PATH_ABSOLUTE);
    throwsCode(() => normalizeRelPath('//server/share/x.png'), ERROR_CODES.VG_PATH_ABSOLUTE);
  });

  it('should reject NUL bytes', () => {
    throwsCode(() => normalizeRelPath(`a${NUL}b`), ERROR_CODES.VG_PATH_NUL);
    throwsCode(() => normalizeRelPath(NUL), ERROR_CODES.VG_PATH_NUL);
  });

  it('should reject control characters', () => {
    throwsCode(() => normalizeRelPath(`a${BELL}b`), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath(`a${String.fromCharCode(10)}b`), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath(`a${String.fromCharCode(127)}b`), ERROR_CODES.VG_PATH_INVALID);
  });

  it('should reject bidirectional override characters', () => {
    throwsCode(() => normalizeRelPath(`image${RTL_OVERRIDE}gnp.png`), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath(`a${String.fromCharCode(0x2066)}b`), ERROR_CODES.VG_PATH_INVALID);
  });

  it('should reject lone surrogates', () => {
    throwsCode(() => normalizeRelPath(`a${LONE_HIGH}b`), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath(`a${LONE_LOW}b`), ERROR_CODES.VG_PATH_INVALID);
  });

  it('should reject empty and repeated separators', () => {
    throwsCode(() => normalizeRelPath('a//b'), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath('a\\\\b'), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath('a/'), ERROR_CODES.VG_PATH_INVALID);
    throwsCode(() => normalizeRelPath('/'), ERROR_CODES.VG_PATH_ABSOLUTE);
  });

  it('should reject components longer than the limit', () => {
    throwsCode(() => normalizeRelPath('a'.repeat(256)), ERROR_CODES.VG_PATH_TOO_LONG);
    assert.equal(normalizeRelPath('a'.repeat(255)).length, 255);
    throwsCode(
      () => normalizeRelPath('a'.repeat(50), { maxComponentBytes: 10 }),
      ERROR_CODES.VG_PATH_TOO_LONG
    );
  });

  it('should reject paths longer than the limit', () => {
    const deep = Array.from({ length: 40 }, (_, i) => `segment${i}`).join('/');
    throwsCode(() => normalizeRelPath(deep, { maxPathBytes: 64 }), ERROR_CODES.VG_PATH_TOO_LONG);
    throwsCode(() => normalizeRelPath('b'.repeat(5000)), ERROR_CODES.VG_PATH_TOO_LONG);
  });

  it('should reject surrogate pairs split across segments safely', () => {
    const emoji = String.fromCodePoint(0x1f600);
    assert.equal(normalizeRelPath(`img/${emoji}.png`), `img/${emoji}.png`);
  });
});

describe('VisionGuard root containment', () => {
  it('should resolve and contain paths', (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-root-'));
    t.after(() => {
      try {
        fs.rmSync(root, { recursive: true, force: true });
      } catch {
      }
    });
    const rootReal = resolveRootReal(root);

    assert.equal(assertInsideRoot(rootReal, path.join(rootReal, 'a', 'b.txt')), path.join('a', 'b.txt'));
    assert.equal(assertInsideRoot(rootReal, rootReal), '');

    const resolved = resolveArtifactPath(root, rootReal, 'a/b.png');
    assert.equal(resolved.rel, 'a/b.png');
    assert.equal(resolved.abs, path.join(rootReal, 'a', 'b.png'));

    throwsCode(() => resolveArtifactPath(root, rootReal, '../escape.png'), ERROR_CODES.VG_PATH_TRAVERSAL);
    throwsCode(() => normalizeRelPath('../escape.png'), ERROR_CODES.VG_PATH_TRAVERSAL);

    const outside = path.resolve(rootReal, '..', 'outside.png');
    throwsCode(() => assertInsideRoot(rootReal, outside, 'outside.png'), ERROR_CODES.VG_PATH_TRAVERSAL);
  });

  it('should reject a missing artifact root', () => {
    const missing = path.join(os.tmpdir(), `vg-no-root-${Date.now()}`);
    throwsCode(() => resolveRootReal(missing), ERROR_CODES.VG_UNREADABLE);
  });
});

describe('VisionGuard assertNoSymlink', () => {
  it('should accept regular files', (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-sym-'));
    t.after(() => {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
      }
    });
    const filePath = path.join(dir, 'real.bin');
    fs.writeFileSync(filePath, 'data');
    const stats = assertNoSymlink(filePath, 'real.bin');
    assert.ok(stats.isFile());
  });

  it('should reject missing files', () => {
    const missing = path.join(os.tmpdir(), `vg-no-file-${Date.now()}.bin`);
    throwsCode(() => assertNoSymlink(missing, 'missing.bin'), ERROR_CODES.VG_UNREADABLE);
  });

  it('should reject symbolic links when the platform allows creating them', (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-syml-'));
    t.after(() => {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
      }
    });
    const target = path.join(dir, 'target.bin');
    fs.writeFileSync(target, 'data');
    const linkPath = path.join(dir, 'link.bin');
    try {
      fs.symlinkSync(target, linkPath);
    } catch (err) {
      t.skip(`symlink creation unavailable: ${err.code}`);
      return;
    }
    throwsCode(() => assertNoSymlink(linkPath, 'link.bin'), ERROR_CODES.VG_SYMLINK_DENIED);
  });
});

describe('VisionGuard findPathCollisions', () => {
  it('should return empty collisions for distinct paths', () => {
    const result = findPathCollisions(['a.png', 'b.png', 'c/d.png']);
    assert.deepEqual(result, { nfc: [], caseFold: [] });
  });

  it('should ignore exact duplicates', () => {
    const result = findPathCollisions(['a.png', 'a.png', 'a.png']);
    assert.deepEqual(result, { nfc: [], caseFold: [] });
  });

  it('should detect NFC collisions', () => {
    const nfd = `${NFD_NAME}.png`;
    const nfc = `${NFC_NAME}.png`;
    assert.notEqual(nfd, nfc);
    const result = findPathCollisions([nfd, nfc]);
    assert.equal(result.nfc.length, 1);
    assert.deepEqual(result.nfc[0], [nfd, nfc]);
  });

  it('should detect case fold collisions without duplicating NFC pairs', () => {
    const result = findPathCollisions(['A.png', 'a.png']);
    assert.equal(result.nfc.length, 0);
    assert.equal(result.caseFold.length, 1);
    assert.deepEqual(result.caseFold[0], ['A.png', 'a.png']);
  });

  it('should not report the same pair as both NFC and case fold', () => {
    const nfd = `${NFD_NAME}.png`;
    const nfc = `${NFC_NAME}.png`;
    const result = findPathCollisions([nfd, nfc]);
    assert.equal(result.nfc.length, 1);
    assert.equal(result.caseFold.length, 0);
  });

  it('should report NFC and case fold pairs independently', () => {
    const result = findPathCollisions([`${NFD_NAME}.png`, `${NFC_NAME}.png`, `${NFC_NAME}.PNG`]);
    assert.equal(result.nfc.length, 1);
    assert.equal(result.caseFold.length, 1);
  });

  it('should reject non array input', () => {
    throwsCode(() => findPathCollisions('a'), ERROR_CODES.VG_INTERNAL);
  });
});
