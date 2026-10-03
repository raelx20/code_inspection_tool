const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { VgError, ERROR_CODES, isVgError, toVgError } = require('../../../src/visionguard/errors');

describe('VisionGuard errors', () => {
  it('should freeze the error code registry', () => {
    assert.ok(Object.isFrozen(ERROR_CODES));
    assert.equal(ERROR_CODES.VG_INTERNAL, 'VG_INTERNAL');
    assert.equal(ERROR_CODES.VG_PATH_TRAVERSAL, 'VG_PATH_TRAVERSAL');
    assert.equal(ERROR_CODES.VG_CANONICAL_INVALID, 'VG_CANONICAL_INVALID');
    assert.equal(ERROR_CODES.VG_LIMIT_METADATA, 'VG_LIMIT_METADATA');
    assert.equal(ERROR_CODES.VG_RACE_DETECTED, 'VG_RACE_DETECTED');
    assert.equal(ERROR_CODES.VG_SYMLINK_DENIED, 'VG_SYMLINK_DENIED');
  });

  it('should create well formed errors', () => {
    const err = new VgError(ERROR_CODES.VG_UNREADABLE, 'cannot read', { path: 'a/b', reason: 'EACCES' });
    assert.ok(err instanceof Error);
    assert.ok(isVgError(err));
    assert.equal(err.name, 'VgError');
    assert.equal(err.code, 'VG_UNREADABLE');
    assert.equal(err.message, 'cannot read');
    assert.deepEqual(err.details, { path: 'a/b', reason: 'EACCES' });
  });

  it('should fall back to VG_INTERNAL for unknown codes', () => {
    const err = new VgError('VG_NOT_A_REAL_CODE', 'boom');
    assert.equal(err.code, ERROR_CODES.VG_INTERNAL);
  });

  it('should sanitize invalid details', () => {
    assert.deepEqual(new VgError(ERROR_CODES.VG_INTERNAL, 'm', null).details, {});
    assert.deepEqual(new VgError(ERROR_CODES.VG_INTERNAL, 'm', 'str').details, {});
    assert.deepEqual(new VgError(ERROR_CODES.VG_INTERNAL, 'm', [1, 2]).details, {});
    assert.deepEqual(new VgError(ERROR_CODES.VG_INTERNAL, 'm').details, {});
  });

  it('should serialize to JSON with code and details', () => {
    const err = new VgError(ERROR_CODES.VG_LIMIT_FILE_SIZE, 'too big', { size: 5 });
    const json = JSON.parse(JSON.stringify(err));
    assert.equal(json.name, 'VgError');
    assert.equal(json.code, 'VG_LIMIT_FILE_SIZE');
    assert.equal(json.message, 'too big');
    assert.deepEqual(json.details, { size: 5 });
  });

  it('should identify VgErrors only', () => {
    assert.equal(isVgError(new VgError(ERROR_CODES.VG_INTERNAL, 'x')), true);
    assert.equal(isVgError(new Error('x')), false);
    assert.equal(isVgError(null), false);
    assert.equal(isVgError({ code: 'VG_INTERNAL' }), false);
  });

  it('should pass through existing VgErrors in toVgError', () => {
    const original = new VgError(ERROR_CODES.VG_STORE_LOCKED, 'locked');
    assert.equal(toVgError(original, ERROR_CODES.VG_INTERNAL, 'other'), original);
  });

  it('should wrap foreign errors', () => {
    const wrapped = toVgError(new Error('io failed'), ERROR_CODES.VG_UNREADABLE, undefined, { path: 'a' });
    assert.ok(isVgError(wrapped));
    assert.equal(wrapped.code, ERROR_CODES.VG_UNREADABLE);
    assert.equal(wrapped.message, 'io failed');
    assert.deepEqual(wrapped.details, { path: 'a' });

    const noMessage = toVgError(undefined, ERROR_CODES.VG_INTERNAL, 'explicit');
    assert.equal(noMessage.message, 'explicit');

    const bare = toVgError(null, ERROR_CODES.VG_INTERNAL, undefined, undefined);
    assert.equal(bare.message, 'unknown error');
    assert.equal(bare.code, ERROR_CODES.VG_INTERNAL);
  });
});
