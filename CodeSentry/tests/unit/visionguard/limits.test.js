const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  DEFAULT_LIMITS,
  resolveLimits,
  assertFileCount,
  assertDirCount,
  assertFileSize,
  assertTotalBytes,
  assertDepth,
  assertMetadataBytes,
} = require('../../../src/visionguard/limits');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code}`);
    return true;
  });
}

describe('VisionGuard limits', () => {
  it('should expose frozen defaults', () => {
    assert.ok(Object.isFrozen(DEFAULT_LIMITS));
    assert.equal(DEFAULT_LIMITS.maxFiles, 100000);
    assert.equal(DEFAULT_LIMITS.maxDirs, 100000);
    assert.equal(DEFAULT_LIMITS.maxFileSize, 2 * 1024 * 1024 * 1024);
    assert.equal(DEFAULT_LIMITS.maxTotalBytes, 20 * 1024 * 1024 * 1024);
    assert.equal(DEFAULT_LIMITS.maxDepth, 64);
    assert.equal(DEFAULT_LIMITS.maxMetadataBytes, 4096);
    assert.equal(DEFAULT_LIMITS.maxManifestBytes, 32 * 1024 * 1024);
    assert.equal(DEFAULT_LIMITS.maxLogBytes, 512 * 1024 * 1024);
  });

  it('should return defaults when no overrides are given', () => {
    assert.equal(resolveLimits(undefined).maxFiles, DEFAULT_LIMITS.maxFiles);
    assert.equal(resolveLimits(null).maxFiles, DEFAULT_LIMITS.maxFiles);
    assert.deepEqual(resolveLimits({}), DEFAULT_LIMITS);
  });

  it('should merge overrides over defaults', () => {
    const limits = resolveLimits({ maxFiles: 5 });
    assert.equal(limits.maxFiles, 5);
    assert.equal(limits.maxFileSize, DEFAULT_LIMITS.maxFileSize);
    assert.ok(Object.isFrozen(limits));
  });

  it('should reject unknown or invalid overrides', () => {
    throwsCode(() => resolveLimits({ nope: 1 }), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => resolveLimits({ maxFiles: -1 }), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => resolveLimits({ maxFiles: 0 }), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => resolveLimits({ maxFiles: 1.5 }), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => resolveLimits({ maxFiles: 'many' }), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => resolveLimits([]), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => resolveLimits('strict'), ERROR_CODES.VG_INTERNAL);
  });

  it('should enforce file count limits', () => {
    assertFileCount(0);
    assertFileCount(DEFAULT_LIMITS.maxFiles);
    throwsCode(() => assertFileCount(DEFAULT_LIMITS.maxFiles + 1), ERROR_CODES.VG_LIMIT_FILE_COUNT);
    throwsCode(() => assertFileCount(-1), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => assertFileCount(1.5), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => assertFileCount(101, { ...DEFAULT_LIMITS, maxFiles: 100 }), ERROR_CODES.VG_LIMIT_FILE_COUNT);
  });

  it('should enforce directory count limits', () => {
    assertDirCount(0);
    assertDirCount(DEFAULT_LIMITS.maxDirs);
    throwsCode(() => assertDirCount(DEFAULT_LIMITS.maxDirs + 1), ERROR_CODES.VG_LIMIT_DIR_COUNT);
    throwsCode(() => assertDirCount(-1), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => assertDirCount(1.5), ERROR_CODES.VG_INTERNAL);
    throwsCode(() => assertDirCount(5, { ...DEFAULT_LIMITS, maxDirs: 4 }), ERROR_CODES.VG_LIMIT_DIR_COUNT);
  });

  it('should enforce file size limits', () => {
    assertFileSize(0);
    assertFileSize(DEFAULT_LIMITS.maxFileSize);
    throwsCode(() => assertFileSize(DEFAULT_LIMITS.maxFileSize + 1), ERROR_CODES.VG_LIMIT_FILE_SIZE);
    throwsCode(
      () => assertFileSize(33, { ...DEFAULT_LIMITS, maxFileSize: 32 }, 'a/b.png'),
      ERROR_CODES.VG_LIMIT_FILE_SIZE
    );
    throwsCode(() => assertFileSize(-1), ERROR_CODES.VG_INTERNAL);
  });

  it('should carry the display path in size violations', () => {
    try {
      assertFileSize(33, { ...DEFAULT_LIMITS, maxFileSize: 32 }, 'images/x.png');
      assert.fail('expected a violation');
    } catch (err) {
      assert.ok(isVgError(err));
      assert.equal(err.details.path, 'images/x.png');
      assert.equal(err.details.size, 33);
      assert.equal(err.details.maxFileSize, 32);
    }
  });

  it('should enforce total byte limits', () => {
    assertTotalBytes(0);
    assertTotalBytes(DEFAULT_LIMITS.maxTotalBytes);
    throwsCode(() => assertTotalBytes(DEFAULT_LIMITS.maxTotalBytes + 1), ERROR_CODES.VG_LIMIT_TOTAL_BYTES);
    throwsCode(() => assertTotalBytes(-1), ERROR_CODES.VG_INTERNAL);
  });

  it('should enforce depth limits', () => {
    assertDepth(0);
    assertDepth(DEFAULT_LIMITS.maxDepth);
    throwsCode(() => assertDepth(DEFAULT_LIMITS.maxDepth + 1), ERROR_CODES.VG_LIMIT_DEPTH);
    throwsCode(() => assertDepth(-1), ERROR_CODES.VG_INTERNAL);
  });

  it('should enforce metadata byte limits', () => {
    assertMetadataBytes(0);
    assertMetadataBytes(DEFAULT_LIMITS.maxMetadataBytes);
    throwsCode(() => assertMetadataBytes(DEFAULT_LIMITS.maxMetadataBytes + 1), ERROR_CODES.VG_LIMIT_METADATA);
    throwsCode(() => assertMetadataBytes(-1), ERROR_CODES.VG_INTERNAL);
  });
});
