'use strict';

const { ERROR_CODES, VgError } = require('./errors');

const DEFAULT_LIMITS = Object.freeze({
  maxFiles: 100000,
  maxDirs: 100000,
  maxFileSize: 2 * 1024 * 1024 * 1024,
  maxTotalBytes: 20 * 1024 * 1024 * 1024,
  maxDepth: 64,
  maxMetadataBytes: 4096,
  maxManifestBytes: 32 * 1024 * 1024,
  maxLogBytes: 512 * 1024 * 1024,
});

function resolveLimits(overrides) {
  if (overrides === undefined || overrides === null) return DEFAULT_LIMITS;
  if (typeof overrides !== 'object' || Array.isArray(overrides)) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'limits must be an object');
  }
  const merged = { ...DEFAULT_LIMITS };
  for (const [key, value] of Object.entries(overrides)) {
    if (!Object.prototype.hasOwnProperty.call(DEFAULT_LIMITS, key)) {
      throw new VgError(ERROR_CODES.VG_INTERNAL, `unknown limit "${key}"`, { key });
    }
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new VgError(ERROR_CODES.VG_INTERNAL, `limit "${key}" must be a positive integer`, {
        key,
        value,
      });
    }
    merged[key] = value;
  }
  return Object.freeze(merged);
}

function assertFileCount(count, limits = DEFAULT_LIMITS) {
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'file count must be a non-negative integer');
  }
  if (count > limits.maxFiles) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_FILE_COUNT,
      `file count ${count} exceeds the limit of ${limits.maxFiles}`,
      { count, maxFiles: limits.maxFiles }
    );
  }
}

function assertDirCount(count, limits = DEFAULT_LIMITS) {
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'directory count must be a non-negative integer');
  }
  if (count > limits.maxDirs) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_DIR_COUNT,
      `directory count ${count} exceeds the limit of ${limits.maxDirs}`,
      { count, maxDirs: limits.maxDirs }
    );
  }
}

function assertFileSize(size, limits = DEFAULT_LIMITS, displayPath = null) {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'file size must be a non-negative integer');
  }
  if (size > limits.maxFileSize) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_FILE_SIZE,
      `file ${displayPath ? `${displayPath}: ` : ''}size ${size} bytes exceeds the limit of ${limits.maxFileSize} bytes`,
      { size, maxFileSize: limits.maxFileSize, path: displayPath }
    );
  }
}

function assertTotalBytes(total, limits = DEFAULT_LIMITS) {
  if (!Number.isSafeInteger(total) || total < 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'total bytes must be a non-negative integer');
  }
  if (total > limits.maxTotalBytes) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_TOTAL_BYTES,
      `total size ${total} bytes exceeds the limit of ${limits.maxTotalBytes} bytes`,
      { total, maxTotalBytes: limits.maxTotalBytes }
    );
  }
}

function assertDepth(depth, limits = DEFAULT_LIMITS) {
  if (!Number.isSafeInteger(depth) || depth < 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'depth must be a non-negative integer');
  }
  if (depth > limits.maxDepth) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_DEPTH,
      `directory depth ${depth} exceeds the limit of ${limits.maxDepth}`,
      { depth, maxDepth: limits.maxDepth }
    );
  }
}

function assertMetadataBytes(byteLength, limits = DEFAULT_LIMITS) {
  if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'metadata size must be a non-negative integer');
  }
  if (byteLength > limits.maxMetadataBytes) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_METADATA,
      `metadata of ${byteLength} bytes exceeds the limit of ${limits.maxMetadataBytes} bytes`,
      { byteLength, maxMetadataBytes: limits.maxMetadataBytes }
    );
  }
}

module.exports = {
  DEFAULT_LIMITS,
  resolveLimits,
  assertFileCount,
  assertDirCount,
  assertFileSize,
  assertTotalBytes,
  assertDepth,
  assertMetadataBytes,
};
