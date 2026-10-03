'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { ERROR_CODES, VgError } = require('./errors');
const { canonicalJson } = require('./canonical');
const { DEFAULT_LIMITS, assertFileSize } = require('./limits');

const CHUNK_SIZE = 1024 * 1024;
const LEAF_TAG = Buffer.from([0x00]);
const NODE_TAG = Buffer.from([0x01]);
const PROMOTE_TAG = Buffer.from([0x02]);
const EMPTY_TAG = Buffer.from([0x03]);
const EMPTY_DATASET_DOMAIN = 'visionguard:dataset:empty:v1';
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

function hashBytes(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function prefixed(hex) {
  return `sha256:${hex}`;
}

function assertStableStats(before, after, displayPath = 'file') {
  if (
    before.size !== after.size ||
    before.mtimeNs !== after.mtimeNs ||
    before.ino !== after.ino ||
    before.dev !== after.dev
  ) {
    throw new VgError(
      ERROR_CODES.VG_RACE_DETECTED,
      `file changed while being hashed: ${displayPath}`,
      { path: displayPath }
    );
  }
}

function openForReading(absPath, displayPath) {
  let stats;
  try {
    stats = fs.lstatSync(absPath);
  } catch (err) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `file not found: ${displayPath}`, {
      path: displayPath,
      reason: err.code || 'UNKNOWN',
    });
  }
  if (stats.isSymbolicLink()) {
    throw new VgError(ERROR_CODES.VG_SYMLINK_DENIED, `symbolic links are not followed: ${displayPath}`, {
      path: displayPath,
    });
  }
  if (!stats.isFile()) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `not a regular file: ${displayPath}`, {
      path: displayPath,
    });
  }

  const noFollow = typeof fs.constants.O_NOFOLLOW === 'number' ? fs.constants.O_NOFOLLOW : 0;
  try {
    return fs.openSync(absPath, fs.constants.O_RDONLY | noFollow);
  } catch (err) {
    if (err.code === 'ELOOP') {
      throw new VgError(ERROR_CODES.VG_SYMLINK_DENIED, `symbolic links are not followed: ${displayPath}`, {
        path: displayPath,
      });
    }
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      throw new VgError(ERROR_CODES.VG_UNREADABLE, `permission denied: ${displayPath}`, {
        path: displayPath,
        reason: err.code,
      });
    }
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `cannot open ${displayPath}: ${err.code || err.message}`, {
      path: displayPath,
      reason: err.code || 'UNKNOWN',
    });
  }
}

function hashFile(absPath, options = {}) {
  const chunkSize = Number.isInteger(options.chunkSize) && options.chunkSize > 0
    ? options.chunkSize
    : CHUNK_SIZE;
  const displayPath = typeof options.displayPath === 'string' && options.displayPath.length > 0
    ? options.displayPath
    : path.basename(absPath);
  const limits = options.limits || DEFAULT_LIMITS;

  const fd = openForReading(absPath, displayPath);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile()) {
      throw new VgError(ERROR_CODES.VG_UNREADABLE, `not a regular file: ${displayPath}`, {
        path: displayPath,
      });
    }
    assertFileSize(Number(before.size), limits, displayPath);

    const hasher = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(chunkSize);
    let read;
    while ((read = fs.readSync(fd, buffer, 0, chunkSize, null)) > 0) {
      hasher.update(buffer.subarray(0, read));
    }

    const after = fs.fstatSync(fd, { bigint: true });
    assertStableStats(before, after, displayPath);
    fs.closeSync(fd);

    let pathStat;
    try {
      pathStat = fs.statSync(absPath, { bigint: true });
    } catch {
      throw new VgError(
        ERROR_CODES.VG_RACE_DETECTED,
        `file was removed while being hashed: ${displayPath}`,
        { path: displayPath }
      );
    }
    if (pathStat.ino !== before.ino || pathStat.dev !== before.dev || pathStat.size !== before.size) {
      throw new VgError(
        ERROR_CODES.VG_RACE_DETECTED,
        `file was replaced while being hashed: ${displayPath}`,
        { path: displayPath }
      );
    }

    return {
      sha256: hasher.digest('hex'),
      size: Number(before.size),
      mtimeNs: before.mtimeNs.toString(),
      ino: before.ino.toString(),
      dev: before.dev.toString(),
    };
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
    }
  }
}

function sortEntries(entries) {
  return [...entries].sort((a, b) => {
    if (a.path < b.path) return -1;
    if (a.path > b.path) return 1;
    return 0;
  });
}

function assertEntry(entry) {
  if (entry === null || typeof entry !== 'object') {
    throw new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, 'manifest entry must be an object');
  }
  if (typeof entry.path !== 'string' || entry.path.length === 0) {
    throw new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, 'manifest entry requires a path');
  }
  if (!Number.isSafeInteger(entry.size) || entry.size < 0) {
    throw new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, `manifest entry ${entry.path}: invalid size`);
  }
  if (typeof entry.sha256 !== 'string' || !SHA256_HEX_RE.test(entry.sha256)) {
    throw new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, `manifest entry ${entry.path}: invalid sha256`);
  }
}

function leafHash(entry) {
  const body = canonicalJson({ path: entry.path, size: entry.size, sha256: entry.sha256 });
  return crypto.createHash('sha256').update(LEAF_TAG).update(body, 'utf8').digest();
}

function merkleRoot(entries) {
  if (!Array.isArray(entries)) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'merkleRoot expects an array of entries');
  }
  const sorted = sortEntries(entries.map((entry) => {
    assertEntry(entry);
    return entry;
  }));

  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].path === sorted[i - 1].path) {
      throw new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, `duplicate path in manifest: ${sorted[i].path}`, {
        path: sorted[i].path,
      });
    }
  }

  if (sorted.length === 0) {
    const digest = crypto
      .createHash('sha256')
      .update(EMPTY_TAG)
      .update(EMPTY_DATASET_DOMAIN, 'utf8')
      .digest('hex');
    return prefixed(digest);
  }

  let level = sorted.map(leafHash);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(crypto.createHash('sha256').update(NODE_TAG).update(level[i]).update(level[i + 1]).digest());
      } else {
        next.push(crypto.createHash('sha256').update(PROMOTE_TAG).update(level[i]).digest());
      }
    }
    level = next;
  }
  return prefixed(level[0].toString('hex'));
}

module.exports = {
  CHUNK_SIZE,
  hashBytes,
  prefixed,
  hashFile,
  assertStableStats,
  merkleRoot,
  sortEntries,
  assertEntry,
  EMPTY_DATASET_DOMAIN,
  SHA256_HEX_RE,
};
