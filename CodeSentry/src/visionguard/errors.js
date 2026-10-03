'use strict';

const ERROR_CODES = Object.freeze({
  VG_PATH_TRAVERSAL: 'VG_PATH_TRAVERSAL',
  VG_PATH_ABSOLUTE: 'VG_PATH_ABSOLUTE',
  VG_PATH_NUL: 'VG_PATH_NUL',
  VG_PATH_INVALID: 'VG_PATH_INVALID',
  VG_PATH_TOO_LONG: 'VG_PATH_TOO_LONG',
  VG_NFC_COLLISION: 'VG_NFC_COLLISION',
  VG_CASE_COLLISION: 'VG_CASE_COLLISION',
  VG_SYMLINK_DENIED: 'VG_SYMLINK_DENIED',
  VG_RACE_DETECTED: 'VG_RACE_DETECTED',
  VG_UNREADABLE: 'VG_UNREADABLE',
  VG_LIMIT_FILE_COUNT: 'VG_LIMIT_FILE_COUNT',
  VG_LIMIT_DIR_COUNT: 'VG_LIMIT_DIR_COUNT',
  VG_LIMIT_FILE_SIZE: 'VG_LIMIT_FILE_SIZE',
  VG_LIMIT_TOTAL_BYTES: 'VG_LIMIT_TOTAL_BYTES',
  VG_LIMIT_DEPTH: 'VG_LIMIT_DEPTH',
  VG_LIMIT_METADATA: 'VG_LIMIT_METADATA',
  VG_LIMIT_MANIFEST: 'VG_LIMIT_MANIFEST',
  VG_LIMIT_LOG: 'VG_LIMIT_LOG',
  VG_MANIFEST_MALFORMED: 'VG_MANIFEST_MALFORMED',
  VG_MANIFEST_SCHEMA: 'VG_MANIFEST_SCHEMA',
  VG_MANIFEST_VERSION: 'VG_MANIFEST_VERSION',
  VG_MANIFEST_HASH_MISMATCH: 'VG_MANIFEST_HASH_MISMATCH',
  VG_CANONICAL_INVALID: 'VG_CANONICAL_INVALID',
  VG_NOT_REGISTERED: 'VG_NOT_REGISTERED',
  VG_KEY_UNKNOWN: 'VG_KEY_UNKNOWN',
  VG_KEY_REVOKED: 'VG_KEY_REVOKED',
  VG_UNAUTHORIZED_OP: 'VG_UNAUTHORIZED_OP',
  VG_ANCHOR_MISMATCH: 'VG_ANCHOR_MISMATCH',
  VG_STORE_LOCKED: 'VG_STORE_LOCKED',
  VG_INTERNAL: 'VG_INTERNAL',
});

class VgError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'VgError';
    this.code = typeof code === 'string' && Object.prototype.hasOwnProperty.call(ERROR_CODES, code)
      ? code
      : ERROR_CODES.VG_INTERNAL;
    this.details = details !== null && typeof details === 'object' && !Array.isArray(details)
      ? details
      : {};
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      details: this.details,
    };
  }
}

function isVgError(value) {
  return value instanceof VgError;
}

function toVgError(err, code, message, details) {
  if (isVgError(err)) return err;
  return new VgError(code, message || (err && err.message) || 'unknown error', details || {});
}

module.exports = {
  ERROR_CODES,
  VgError,
  isVgError,
  toVgError,
};
