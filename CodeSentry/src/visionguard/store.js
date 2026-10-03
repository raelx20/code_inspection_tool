'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { ERROR_CODES, VgError } = require('./errors');
const { resolveLimits } = require('./limits');
const { parseCanonical, hashRecord, isPlainObject } = require('./canonical');
const {
  parseDatasetManifest,
  assertNameVersion,
  assertLabel,
  toIso,
  TIMESTAMP_RE,
  RECORD_HASH_RE,
} = require('./manifest');

const SCHEMA_VERSION = '1.0';
const STORE_METADATA_FILE = 'store.json';
const PROVENANCE_LOG_FILE = 'provenance.log';
const PROVENANCE_LOCK_FILE = 'provenance.log.lock';
const LOCK_TIMEOUT_MS = 2000;
const LOCK_STALE_MS = 30000;
const LOCK_RETRY_MS = 10;

const STORE_SUBDIRS = Object.freeze([
  path.join('manifests', 'dataset'),
  path.join('manifests', 'model'),
  path.join('manifests', 'pipeline'),
  'keys',
  'anchors',
]);

function ensureStoreDirs(storeDir) {
  if (typeof storeDir !== 'string' || storeDir.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'storeDir must be a non-empty string');
  }
  for (const sub of STORE_SUBDIRS) {
    fs.mkdirSync(path.join(storeDir, sub), { recursive: true });
  }
  return storeDir;
}

function datasetManifestPath(storeDir, name, version) {
  assertNameVersion(name, version);
  return path.join(storeDir, 'manifests', 'dataset', name, `${version}.json`);
}

function modelManifestPath(storeDir, id, version) {
  assertLabel(id, 'id');
  assertLabel(version, 'version');
  return path.join(storeDir, 'manifests', 'model', id, `${version}.json`);
}

function atomicWriteFileSync(filePath, data) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = path.join(
    dir,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`
  );
  let fd;
  try {
    fd = fs.openSync(tmpPath, 'wx');
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmpPath, filePath);
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
      }
    }
    try {
      fs.unlinkSync(tmpPath);
    } catch {
    }
  }
}

function saveManifestTo(filePath, manifest, limits) {
  const json = `${JSON.stringify(manifest, null, 2)}\n`;
  const byteLength = Buffer.byteLength(json, 'utf8');
  if (byteLength > limits.maxManifestBytes) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_MANIFEST,
      `manifest of ${byteLength} bytes exceeds the limit of ${limits.maxManifestBytes} bytes`,
      { byteLength, maxManifestBytes: limits.maxManifestBytes }
    );
  }
  atomicWriteFileSync(filePath, json);
  return filePath;
}

function readManifestText(filePath, limits, entity, refText, details) {
  let stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new VgError(ERROR_CODES.VG_NOT_REGISTERED, `${entity} not registered: ${refText}`, details);
    }
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `cannot read manifest for ${refText}`, {
      ...details,
      reason: err.code || 'UNKNOWN',
    });
  }
  if (!stats.isFile()) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `manifest for ${refText} is not a regular file`, details);
  }
  if (stats.size > limits.maxManifestBytes) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_MANIFEST,
      `manifest of ${stats.size} bytes exceeds the limit of ${limits.maxManifestBytes} bytes`,
      { byteLength: stats.size, maxManifestBytes: limits.maxManifestBytes }
    );
  }
  return fs.readFileSync(filePath, 'utf8');
}

function saveDatasetManifest(storeDir, manifest, options = {}) {
  const limits = resolveLimits(options.limits);
  return saveManifestTo(datasetManifestPath(storeDir, manifest.name, manifest.version), manifest, limits);
}

function loadDatasetManifest(storeDir, name, version, options = {}) {
  const limits = resolveLimits(options.limits);
  const filePath = datasetManifestPath(storeDir, name, version);
  const text = readManifestText(filePath, limits, 'dataset', `${name}@${version}`, { name, version });
  return parseDatasetManifest(text, { maxBytes: limits.maxManifestBytes, strict: options.strict });
}

function saveModelManifest(storeDir, manifest, options = {}) {
  const limits = resolveLimits(options.limits);
  return saveManifestTo(modelManifestPath(storeDir, manifest.id, manifest.version), manifest, limits);
}

function loadModelManifest(storeDir, id, version, options = {}) {
  const limits = resolveLimits(options.limits);
  const filePath = modelManifestPath(storeDir, id, version);
  const text = readManifestText(filePath, limits, 'model', `${id}@${version}`, { id, version });
  const { parseModelManifest } = require('./model');
  return parseModelManifest(text, { maxBytes: limits.maxManifestBytes, strict: options.strict });
}

function pipelineManifestPath(storeDir, name, version) {
  assertNameVersion(name, version);
  return path.join(storeDir, 'manifests', 'pipeline', name, `${version}.json`);
}

function savePipelineManifest(storeDir, manifest, options = {}) {
  const limits = resolveLimits(options.limits);
  return saveManifestTo(pipelineManifestPath(storeDir, manifest.name, manifest.version), manifest, limits);
}

function loadPipelineManifest(storeDir, name, version, options = {}) {
  const limits = resolveLimits(options.limits);
  const filePath = pipelineManifestPath(storeDir, name, version);
  const text = readManifestText(filePath, limits, 'pipeline', `${name}@${version}`, { name, version });
  const { parsePipelineManifest } = require('./pipeline');
  return parsePipelineManifest(text, { maxBytes: limits.maxManifestBytes, strict: options.strict });
}

function assertStoreOutside(datasetRoot, storeDir) {
  let rootAbs;
  try {
    rootAbs = fs.realpathSync(datasetRoot);
  } catch {
    rootAbs = path.resolve(datasetRoot);
  }
  const storeAbs = path.resolve(storeDir);
  const relative = path.relative(rootAbs, storeAbs);
  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
    throw new VgError(
      ERROR_CODES.VG_PATH_INVALID,
      'store directory must be outside the dataset directory',
      { storeDir }
    );
  }
}

function storeJsonPath(storeDir) {
  return path.join(storeDir, STORE_METADATA_FILE);
}

function provenanceLogPath(storeDir) {
  return path.join(storeDir, PROVENANCE_LOG_FILE);
}

function provenanceLockPath(storeDir) {
  return path.join(storeDir, PROVENANCE_LOCK_FILE);
}

function storeSchemaError(message, details) {
  return new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, message, details || {});
}

function buildStoreMetadata(options = {}) {
  const metadata = {
    schema_version: SCHEMA_VERSION,
    kind: 'store',
    created_at: toIso(options.now),
    hash_algorithm: 'sha256',
  };
  metadata.record_hash = hashRecord(metadata);
  return metadata;
}

function validateStoreMetadata(value, options = {}) {
  if (!isPlainObject(value)) throw storeSchemaError('store metadata must be a plain JSON object');
  if (typeof value.schema_version !== 'string') {
    throw storeSchemaError('schema_version must be a string', { field: 'schema_version' });
  }
  const major = value.schema_version.split('.')[0];
  if (!/^\d+$/.test(major)) {
    throw new VgError(ERROR_CODES.VG_MANIFEST_VERSION, `unrecognized schema_version "${value.schema_version}"`, {
      schema_version: value.schema_version,
    });
  }
  if (major !== '1') {
    throw new VgError(ERROR_CODES.VG_MANIFEST_VERSION, `unsupported schema major version ${major}`, {
      schema_version: value.schema_version,
      supported_major: '1',
    });
  }
  if (value.kind !== 'store') throw storeSchemaError('kind must be "store"', { field: 'kind' });
  if (value.hash_algorithm !== 'sha256') {
    throw storeSchemaError('hash_algorithm must be "sha256"', { field: 'hash_algorithm' });
  }
  if (typeof value.created_at !== 'string' || !TIMESTAMP_RE.test(value.created_at)) {
    throw storeSchemaError('created_at must be an RFC 3339 UTC timestamp with milliseconds', {
      field: 'created_at',
    });
  }
  if (typeof value.record_hash !== 'string' || !RECORD_HASH_RE.test(value.record_hash)) {
    throw storeSchemaError('record_hash must be a sha256 hex digest', { field: 'record_hash' });
  }
  if (options.verifyHash !== false && hashRecord(value) !== value.record_hash) {
    throw new VgError(ERROR_CODES.VG_MANIFEST_HASH_MISMATCH, 'store.json record_hash mismatch', {
      file: STORE_METADATA_FILE,
      expected: hashRecord(value),
      actual: value.record_hash,
    });
  }
  return value;
}

function saveStoreMetadata(storeDir, metadata, options = {}) {
  const limits = resolveLimits(options.limits);
  validateStoreMetadata(metadata, { verifyHash: false });
  return saveManifestTo(storeJsonPath(storeDir), metadata, limits);
}

function loadStoreMetadata(storeDir, options = {}) {
  const limits = resolveLimits(options.limits);
  const filePath = storeJsonPath(storeDir);
  const text = readManifestText(filePath, limits, 'store', STORE_METADATA_FILE, { file: STORE_METADATA_FILE });
  const value = parseCanonical(text, { maxBytes: limits.maxManifestBytes });
  return validateStoreMetadata(value);
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function resolveLockOptions(options = {}) {
  const timeoutMs = Number.isInteger(options.timeoutMs) && options.timeoutMs >= 0
    ? options.timeoutMs
    : LOCK_TIMEOUT_MS;
  const staleMs = Number.isInteger(options.staleMs) && options.staleMs > 0
    ? options.staleMs
    : LOCK_STALE_MS;
  const retryMs = Number.isInteger(options.retryMs) && options.retryMs > 0
    ? options.retryMs
    : LOCK_RETRY_MS;
  return { timeoutMs, staleMs, retryMs };
}

function acquireLock(lockPath, options = {}) {
  const { timeoutMs, staleMs, retryMs } = resolveLockOptions(options);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let fd;
    try {
      fd = fs.openSync(lockPath, 'wx');
      fs.writeSync(fd, `${process.pid}\n`);
      fs.closeSync(fd);
      return lockPath;
    } catch (err) {
      if (fd !== undefined) {
        try {
          fs.closeSync(fd);
        } catch {
        }
      }
      if (err.code === 'ENOENT') {
        fs.mkdirSync(path.dirname(lockPath), { recursive: true });
        continue;
      }
      if (err.code !== 'EEXIST') {
        throw new VgError(ERROR_CODES.VG_INTERNAL, `cannot create lock file: ${err.code || err.message}`, {
          reason: err.code || 'UNKNOWN',
        });
      }
      let stats = null;
      try {
        stats = fs.statSync(lockPath);
      } catch (statErr) {
        if (statErr.code === 'ENOENT') continue;
        throw new VgError(ERROR_CODES.VG_INTERNAL, `cannot stat lock file: ${statErr.code || statErr.message}`, {
          reason: statErr.code || 'UNKNOWN',
        });
      }
      if (Date.now() - stats.mtimeMs > staleMs) {
        try {
          fs.unlinkSync(lockPath);
        } catch {
        }
        continue;
      }
      if (Date.now() >= deadline) {
        throw new VgError(ERROR_CODES.VG_STORE_LOCKED, `provenance log is locked by another process`, {
          lock: path.basename(lockPath),
          timeoutMs,
        });
      }
      sleepSync(retryMs);
    }
  }
}

function releaseLock(lockPath) {
  try {
    fs.unlinkSync(lockPath);
  } catch {
  }
}

function withLogLock(storeDir, fn, options = {}) {
  const lockPath = provenanceLockPath(storeDir);
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });
  acquireLock(lockPath, options);
  try {
    return fn();
  } finally {
    releaseLock(lockPath);
  }
}

function appendLogLineUnlocked(storeDir, line, limits) {
  if (typeof line !== 'string' || line.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'log line must be a non-empty string');
  }
  if (line.includes('\n') || line.includes('\r')) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'log line must not contain newline characters');
  }
  const buffer = Buffer.from(`${line}\n`, 'utf8');
  const logPath = provenanceLogPath(storeDir);
  let size = 0;
  let stats = null;
  try {
    stats = fs.lstatSync(logPath);
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw new VgError(ERROR_CODES.VG_UNREADABLE, 'cannot stat provenance log', {
        file: PROVENANCE_LOG_FILE,
        reason: err.code || 'UNKNOWN',
      });
    }
  }
  if (stats) {
    if (stats.isSymbolicLink()) {
      throw new VgError(ERROR_CODES.VG_SYMLINK_DENIED, 'provenance log must not be a symbolic link', {
        file: PROVENANCE_LOG_FILE,
      });
    }
    if (!stats.isFile()) {
      throw new VgError(ERROR_CODES.VG_UNREADABLE, 'provenance log is not a regular file', {
        file: PROVENANCE_LOG_FILE,
      });
    }
    size = stats.size;
  }
  if (size + buffer.length > limits.maxLogBytes) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_LOG,
      `provenance log of ${size + buffer.length} bytes would exceed the limit of ${limits.maxLogBytes} bytes`,
      { byteLength: size + buffer.length, maxLogBytes: limits.maxLogBytes }
    );
  }
  const fd = fs.openSync(logPath, 'a');
  try {
    let written = 0;
    while (written < buffer.length) {
      written += fs.writeSync(fd, buffer, written, buffer.length - written);
    }
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  return size + buffer.length;
}

function appendLogLine(storeDir, line, options = {}) {
  const limits = resolveLimits(options.limits);
  return withLogLock(storeDir, () => appendLogLineUnlocked(storeDir, line, limits), options);
}

function readProvenanceText(storeDir, options = {}) {
  const limits = resolveLimits(options.limits);
  const logPath = provenanceLogPath(storeDir);
  let stats;
  try {
    stats = fs.lstatSync(logPath);
  } catch (err) {
    if (err.code === 'ENOENT') return { exists: false, text: '', size: 0 };
    throw new VgError(ERROR_CODES.VG_UNREADABLE, 'cannot stat provenance log', {
      file: PROVENANCE_LOG_FILE,
      reason: err.code || 'UNKNOWN',
    });
  }
  if (stats.isSymbolicLink()) {
    throw new VgError(ERROR_CODES.VG_SYMLINK_DENIED, 'provenance log must not be a symbolic link', {
      file: PROVENANCE_LOG_FILE,
    });
  }
  if (!stats.isFile()) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, 'provenance log is not a regular file', {
      file: PROVENANCE_LOG_FILE,
    });
  }
  if (stats.size > limits.maxLogBytes) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_LOG,
      `provenance log of ${stats.size} bytes exceeds the limit of ${limits.maxLogBytes} bytes`,
      { byteLength: stats.size, maxLogBytes: limits.maxLogBytes }
    );
  }
  if (stats.size === 0) return { exists: true, text: '', size: 0 };
  return { exists: true, text: fs.readFileSync(logPath, 'utf8'), size: stats.size };
}

module.exports = {
  STORE_SUBDIRS,
  SCHEMA_VERSION,
  STORE_METADATA_FILE,
  PROVENANCE_LOG_FILE,
  PROVENANCE_LOCK_FILE,
  LOCK_TIMEOUT_MS,
  LOCK_STALE_MS,
  ensureStoreDirs,
  datasetManifestPath,
  modelManifestPath,
  storeJsonPath,
  provenanceLogPath,
  provenanceLockPath,
  atomicWriteFileSync,
  saveManifestTo,
  readManifestText,
  saveDatasetManifest,
  loadDatasetManifest,
  saveModelManifest,
  loadModelManifest,
  pipelineManifestPath,
  savePipelineManifest,
  loadPipelineManifest,
  buildStoreMetadata,
  validateStoreMetadata,
  saveStoreMetadata,
  loadStoreMetadata,
  withLogLock,
  acquireLock,
  releaseLock,
  appendLogLineUnlocked,
  appendLogLine,
  readProvenanceText,
  assertStoreOutside,
};
