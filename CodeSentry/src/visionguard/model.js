'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ERROR_CODES, VgError, isVgError } = require('./errors');
const { parseCanonical, hashRecord, isPlainObject } = require('./canonical');
const { hashFile, assertStableStats, SHA256_HEX_RE } = require('./hash');
const { resolveLimits, assertFileSize } = require('./limits');
const { METADATA_MAX_DEPTH, assertMetadata } = require('./metadata');
const { assertLabel, assertActor, toIso, TIMESTAMP_RE, RECORD_HASH_RE } = require('./manifest');

const SCHEMA_VERSION = '1.0';
const KIND = 'model_manifest';
const VERIFY_KIND = 'model_verification';
const MODEL_FORMATS = Object.freeze(['safetensors', 'onnx', 'pt', 'pth', 'other']);
const FAMILY_BY_FORMAT = Object.freeze({
  safetensors: 'safetensors',
  onnx: 'onnx',
  pt: 'torch',
  pth: 'torch',
  other: 'other',
});
const SNIFF_PROBE_BYTES = 9;
const SNIFF_PARSE_LIMIT = 1024 * 1024;
const SNIFF_MAX_HEADER_BYTES = 100 * 1024 * 1024;
const KNOWN_KEYS = new Set([
  'schema_version',
  'kind',
  'id',
  'version',
  'format',
  'detected_format',
  'size',
  'sha256',
  'created_at',
  'actor',
  'metadata',
  'record_hash',
  'signature',
]);
const MODEL_FINDING_SEVERITY = Object.freeze({
  'VG-MODEL-001': 'BLOCKER',
  'VG-MODEL-002': 'BLOCKER',
  'VG-MODEL-003': 'BLOCKER',
  'VG-MODEL-004': 'BLOCKER',
  'VG-MODEL-005': 'HIGH',
  'VG-MODEL-006': 'BLOCKER',
});

function schemaError(message, details) {
  return new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, message, details || {});
}

function family(format) {
  if (typeof format === 'string' && Object.prototype.hasOwnProperty.call(FAMILY_BY_FORMAT, format)) {
    return FAMILY_BY_FORMAT[format];
  }
  throw schemaError(`unrecognized format "${format}"`, { field: 'format' });
}

function extensionOf(fileName) {
  const base = String(fileName).toLowerCase();
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return '';
  return base.slice(dot + 1);
}

function safetensorsHeaderLength(head, size) {
  if (head.length < SNIFF_PROBE_BYTES || size < SNIFF_PROBE_BYTES) {
    return { ok: false, reason: 'file too short for a safetensors header' };
  }
  const headerLength = head.readBigUInt64LE(0);
  if (headerLength <= 0n) {
    return { ok: false, reason: 'safetensors header length must be positive' };
  }
  if (headerLength > BigInt(SNIFF_MAX_HEADER_BYTES)) {
    return { ok: false, reason: 'safetensors header length exceeds 100 MiB' };
  }
  if (BigInt(8) + headerLength > BigInt(size)) {
    return { ok: false, reason: 'safetensors header extends past end of file' };
  }
  if (head[8] !== 0x7b) {
    return { ok: false, reason: 'safetensors header does not start with "{"' };
  }
  return { ok: true, headerLength };
}

function sniffPickle(head) {
  if (head.length >= 2 && head[0] === 0x80 && head[1] >= 1 && head[1] <= 6) return true;
  if (head.length >= 1 && (head[0] === 0x63 || head[0] === 0x28)) return true;
  return false;
}

function sniffZip(head) {
  return head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04;
}

function sniffFormat(head, size, fileName) {
  const buffer = Buffer.isBuffer(head) ? head : Buffer.alloc(0);
  const total = Number.isSafeInteger(size) && size >= 0 ? size : 0;
  if (total === 0) {
    return { detected: 'other', magicOk: false, pickleBased: false, detail: 'file is empty' };
  }

  const header = safetensorsHeaderLength(buffer, total);
  if (header.ok) {
    if (header.headerLength > BigInt(SNIFF_PARSE_LIMIT)) {
      return {
        detected: 'safetensors',
        magicOk: true,
        pickleBased: false,
        detail: 'safetensors header length observed; header too large to parse',
      };
    }
    const headerBytes = 8 + Number(header.headerLength);
    if (buffer.length < headerBytes) {
      return {
        detected: 'other',
        magicOk: true,
        pickleBased: false,
        detail: 'safetensors header bytes are incomplete',
      };
    }
    let parsed;
    try {
      parsed = JSON.parse(buffer.toString('utf8', 8, headerBytes));
    } catch {
      return { detected: 'other', magicOk: true, pickleBased: false, detail: 'safetensors header is not valid JSON' };
    }
    if (!isPlainObject(parsed)) {
      return {
        detected: 'other',
        magicOk: true,
        pickleBased: false,
        detail: 'safetensors header is not a JSON object',
      };
    }
    return { detected: 'safetensors', magicOk: true, pickleBased: false, detail: 'safetensors header observed' };
  }

  const ext = extensionOf(fileName);
  if (ext === 'onnx') {
    const magicOk = buffer.length > 0 && buffer[0] === 0x08;
    return {
      detected: 'onnx',
      magicOk,
      pickleBased: false,
      detail: magicOk ? 'onnx protobuf header observed' : 'expected onnx protobuf header byte 0x08',
    };
  }
  if (ext === 'pt' || ext === 'pth') {
    if (sniffZip(buffer)) {
      return { detected: ext, magicOk: true, pickleBased: false, detail: 'zip container header observed' };
    }
    if (sniffPickle(buffer)) {
      return { detected: ext, magicOk: true, pickleBased: true, detail: 'python pickle protocol header observed' };
    }
    return {
      detected: ext,
      magicOk: false,
      pickleBased: false,
      detail: `expected zip (PK) or pickle header for ".${ext}" file`,
    };
  }
  return { detected: 'other', magicOk: true, pickleBased: false, detail: header.reason };
}

function openSniffFd(absPath) {
  let stats;
  try {
    stats = fs.lstatSync(absPath);
  } catch (err) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `cannot open ${absPath}: ${err.code || err.message}`, {
      path: absPath,
      reason: err.code || 'UNKNOWN',
    });
  }
  if (stats.isSymbolicLink()) {
    throw new VgError(ERROR_CODES.VG_SYMLINK_DENIED, `symbolic links are not followed: ${absPath}`, {
      path: absPath,
    });
  }
  if (!stats.isFile()) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `not a regular file: ${absPath}`, { path: absPath });
  }
  const noFollow = typeof fs.constants.O_NOFOLLOW === 'number' ? fs.constants.O_NOFOLLOW : 0;
  try {
    return fs.openSync(absPath, fs.constants.O_RDONLY | noFollow);
  } catch (err) {
    if (err.code === 'ELOOP') {
      throw new VgError(ERROR_CODES.VG_SYMLINK_DENIED, `symbolic links are not followed: ${absPath}`, {
        path: absPath,
      });
    }
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `cannot open ${absPath}: ${err.code || err.message}`, {
      path: absPath,
      reason: err.code || 'UNKNOWN',
    });
  }
}

function readSniffHead(absPath, expected) {
  const size = expected.size;
  if (!Number.isSafeInteger(size) || size <= 0) return Buffer.alloc(0);
  const fd = openSniffFd(absPath);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    let head;
    const probe = Buffer.alloc(SNIFF_PROBE_BYTES);
    const probeRead = fs.readSync(fd, probe, 0, SNIFF_PROBE_BYTES, 0);
    if (probeRead < SNIFF_PROBE_BYTES) {
      head = probe.subarray(0, probeRead);
    } else {
      const header = safetensorsHeaderLength(probe, size);
      if (header.ok && header.headerLength <= BigInt(SNIFF_PARSE_LIMIT)) {
        const total = 8 + Number(header.headerLength);
        const full = Buffer.allocUnsafe(total);
        const read = fs.readSync(fd, full, 0, total, 0);
        head = full.subarray(0, read);
      } else {
        head = probe;
      }
    }
    const after = fs.fstatSync(fd, { bigint: true });
    assertStableStats(before, after, absPath);
    if (
      before.ino !== BigInt(expected.ino) ||
      before.dev !== BigInt(expected.dev) ||
      before.size !== BigInt(expected.size) ||
      before.mtimeNs.toString() !== expected.mtimeNs
    ) {
      throw new VgError(ERROR_CODES.VG_RACE_DETECTED, `model file changed while being inspected: ${absPath}`, {
        path: absPath,
      });
    }
    return head;
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
    }
  }
}

function validateModelManifest(value, options = {}) {
  const strict = options.strict === true;
  const limits = resolveLimits(options.limits);
  if (!isPlainObject(value)) throw schemaError('manifest must be a plain JSON object');

  if (strict) {
    for (const key of Object.keys(value)) {
      if (!KNOWN_KEYS.has(key)) throw schemaError(`unknown manifest field "${key}"`, { field: key });
    }
  }

  if (typeof value.schema_version !== 'string') {
    throw schemaError('schema_version must be a string', { field: 'schema_version' });
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

  if (value.kind !== KIND) throw schemaError(`kind must be "${KIND}"`, { field: 'kind' });
  assertLabel(value.id, 'id');
  assertLabel(value.version, 'version');

  if (!MODEL_FORMATS.includes(value.format)) {
    throw schemaError(`format must be one of ${MODEL_FORMATS.join(', ')}`, { field: 'format' });
  }
  if (!MODEL_FORMATS.includes(value.detected_format)) {
    throw schemaError(`detected_format must be one of ${MODEL_FORMATS.join(', ')}`, { field: 'detected_format' });
  }
  if (family(value.format) !== family(value.detected_format)) {
    throw schemaError(`format "${value.format}" does not match detected_format "${value.detected_format}"`, {
      field: 'detected_format',
    });
  }

  if (!Number.isSafeInteger(value.size) || value.size < 1) {
    throw schemaError('size must be a positive integer', { field: 'size' });
  }
  if (typeof value.sha256 !== 'string' || !SHA256_HEX_RE.test(value.sha256)) {
    throw schemaError('sha256 must be a lowercase hex digest', { field: 'sha256' });
  }

  if (typeof value.created_at !== 'string' || !TIMESTAMP_RE.test(value.created_at)) {
    throw schemaError('created_at must be an RFC 3339 UTC timestamp with milliseconds', { field: 'created_at' });
  }
  if (Number.isNaN(Date.parse(value.created_at))) {
    throw schemaError('created_at is not a valid timestamp', { field: 'created_at' });
  }

  assertActor(value.actor);

  if (value.metadata === undefined) throw schemaError('metadata is required', { field: 'metadata' });
  assertMetadata(value.metadata, limits);

  if (typeof value.record_hash !== 'string' || !RECORD_HASH_RE.test(value.record_hash)) {
    throw schemaError('record_hash must be a sha256 prefixed hex digest', { field: 'record_hash' });
  }
  if (value.signature !== null && typeof value.signature !== 'string') {
    throw schemaError('signature must be null or a string', { field: 'signature' });
  }

  return value;
}

function parseModelManifest(text, options = {}) {
  const value = parseCanonical(text, { maxBytes: options.maxBytes, maxDepth: 32 });
  validateModelManifest(value, { strict: options.strict, limits: options.limits });
  return value;
}

function finding(rule, filePath, detail) {
  return { rule, severity: MODEL_FINDING_SEVERITY[rule], path: filePath, detail };
}

function reuseHashed(filePath, expected) {
  if (!expected || typeof expected !== 'object') return null;
  try {
    const stat = fs.lstatSync(filePath, { bigint: true });
    if (
      stat.ino !== BigInt(expected.ino) ||
      stat.dev !== BigInt(expected.dev) ||
      stat.size !== BigInt(expected.size) ||
      stat.mtimeNs.toString() !== expected.mtimeNs
    ) {
      return null;
    }
  } catch {
    return null;
  }
  return expected;
}

function registerModel(options) {
  assertLabel(options.id, 'id');
  assertLabel(options.version, 'version');
  if (!MODEL_FORMATS.includes(options.format)) {
    throw schemaError(`format must be one of ${MODEL_FORMATS.join(', ')}`, { field: 'format' });
  }

  const limits = resolveLimits(options.limits);
  const actor = assertActor(options.actor);
  const rawMetadata = options.metadata === undefined || options.metadata === null ? {} : options.metadata;
  const metadata = assertMetadata(rawMetadata, limits);

  const filePath = options.path;
  if (typeof filePath !== 'string' || filePath.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'model file path is required');
  }

  let stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (err) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `model file not found: ${filePath}`, {
      path: filePath,
      reason: err.code || 'UNKNOWN',
    });
  }
  if (stats.isSymbolicLink()) {
    throw new VgError(ERROR_CODES.VG_SYMLINK_DENIED, `symbolic links are not followed: ${filePath}`, {
      path: filePath,
    });
  }
  if (!stats.isFile()) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `not a regular file: ${filePath}`, { path: filePath });
  }
  if (stats.size === 0) {
    throw schemaError('model file is empty', { path: filePath });
  }
  assertFileSize(stats.size, limits, filePath);

  const hashed = reuseHashed(filePath, options.hashed) || hashFile(filePath, { limits, displayPath: filePath });
  const head = readSniffHead(filePath, hashed);
  const sniff = sniffFormat(head, hashed.size, path.basename(filePath));

  if (family(options.format) !== family(sniff.detected)) {
    throw schemaError(
      `declared format "${options.format}" does not match file content detected as "${sniff.detected}" (${sniff.detail})`,
      { field: 'format', detected_format: sniff.detected }
    );
  }
  if (!sniff.magicOk) {
    throw schemaError(`file does not carry the "${options.format}" magic signature (${sniff.detail})`, {
      field: 'format',
      detected_format: sniff.detected,
    });
  }

  const manifest = {
    schema_version: SCHEMA_VERSION,
    kind: KIND,
    id: options.id,
    version: options.version,
    format: options.format,
    detected_format: sniff.detected,
    size: hashed.size,
    sha256: hashed.sha256,
    created_at: toIso(options.now),
    actor,
    metadata,
    record_hash: '',
    signature: null,
  };
  manifest.record_hash = hashRecord(manifest);
  validateModelManifest(manifest, { limits });

  if (options.storeDir) {
    const store = require('./store');
    store.ensureStoreDirs(options.storeDir);
    store.saveModelManifest(options.storeDir, manifest, { limits: options.limits });
  }
  return manifest;
}

function verifyModel(options) {
  const manifest = options.manifest;
  validateModelManifest(manifest, { limits: options.limits });

  const filePath = options.path;
  if (typeof filePath !== 'string' || filePath.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'model file path is required');
  }
  const limits = resolveLimits(options.limits);
  const consistency = { recordHashValid: hashRecord(manifest) === manifest.record_hash };

  const findings = [];
  if (!consistency.recordHashValid) {
    findings.push(
      finding('VG-MODEL-006', null, 'model manifest self-consistency check failed: record_hash does not match the manifest body')
    );
  }

  const expected = {
    format: manifest.format,
    size: manifest.size,
    sha256: manifest.sha256,
  };

  let actual = null;
  let stats = null;
  try {
    stats = fs.lstatSync(filePath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      findings.push(finding('VG-MODEL-001', filePath, 'missing from disk'));
    } else {
      findings.push(finding('VG-MODEL-001', filePath, `cannot stat model file (${err.code || 'UNKNOWN'})`));
    }
  }

  if (stats) {
    if (stats.isSymbolicLink()) {
      findings.push(finding('VG-MODEL-001', filePath, 'path is a symbolic link'));
    } else if (!stats.isFile()) {
      findings.push(finding('VG-MODEL-001', filePath, 'not a regular file'));
    } else if (stats.size === 0) {
      actual = {
        size: 0,
        sha256: null,
        detected_format: 'other',
        magicOk: false,
        pickleBased: false,
        detail: 'file is empty',
      };
      findings.push(finding('VG-MODEL-003', filePath, 'model file is empty'));
    } else {
      try {
        const hashed = reuseHashed(filePath, options.hashed) || hashFile(filePath, { limits, displayPath: filePath });
        const head = readSniffHead(filePath, hashed);
        const sniff = sniffFormat(head, hashed.size, path.basename(filePath));
        actual = {
          size: hashed.size,
          sha256: hashed.sha256,
          detected_format: sniff.detected,
          magicOk: sniff.magicOk,
          pickleBased: sniff.pickleBased,
          detail: sniff.detail,
        };
        if (hashed.sha256 !== manifest.sha256 || hashed.size !== manifest.size) {
          findings.push(
            finding(
              'VG-MODEL-001',
              filePath,
              `content changed: expected ${manifest.sha256} (${manifest.size} bytes), got ${hashed.sha256} (${hashed.size} bytes)`
            )
          );
        }
        if (sniff.detected !== manifest.format || !sniff.magicOk) {
          const detail =
            sniff.detected !== manifest.format
              ? `expected format "${manifest.format}" but file bytes detect as "${sniff.detected}"`
              : `file does not carry the "${manifest.format}" magic signature: ${sniff.detail}`;
          findings.push(finding('VG-MODEL-002', filePath, detail));
        }
        if (sniff.pickleBased && family(manifest.format) === 'torch') {
          findings.push(
            finding('VG-MODEL-005', filePath, `pickle-based payload detected (${sniff.detail}); executing it can run arbitrary code`)
          );
        }
      } catch (err) {
        const code = isVgError(err) ? err.code : ERROR_CODES.VG_INTERNAL;
        findings.push(finding('VG-MODEL-001', filePath, `cannot hash or inspect model file (${code})`));
      }
    }
  }

  const hasBlocker = findings.some((item) => item.severity === 'BLOCKER');
  const status = hasBlocker ? 'FAIL' : 'PASS';

  return {
    schema_version: SCHEMA_VERSION,
    kind: VERIFY_KIND,
    id: manifest.id,
    version: manifest.version,
    checked_at: toIso(options.now),
    status,
    manifestConsistency: consistency,
    expected,
    actual,
    findings,
    signaturePresent: manifest.signature !== null,
  };
}

module.exports = {
  SCHEMA_VERSION,
  KIND,
  VERIFY_KIND,
  MODEL_FORMATS,
  METADATA_MAX_DEPTH,
  SNIFF_PROBE_BYTES,
  SNIFF_PARSE_LIMIT,
  SNIFF_MAX_HEADER_BYTES,
  MODEL_FINDING_SEVERITY,
  family,
  sniffFormat,
  readSniffHead,
  assertMetadata,
  validateModelManifest,
  parseModelManifest,
  registerModel,
  verifyModel,
};
