'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { ERROR_CODES, VgError } = require('./errors');
const { canonicalJson, hashRecord, isPlainObject, parseCanonical } = require('./canonical');
const { resolveLimits } = require('./limits');
const { hashFile, SHA256_HEX_RE } = require('./hash');
const { normalizeRelPath, resolveRootReal, resolveArtifactPath, assertNoSymlink } = require('./paths');
const {
  assertActor,
  assertNameVersion,
  toIso,
  TIMESTAMP_RE,
  RECORD_HASH_RE,
} = require('./manifest');
const { assertMetadata } = require('./metadata');
const store = require('./store');
const keys = require('./keys');

const SCHEMA_VERSION = '1.0';
const KIND = 'pipeline_manifest';
const IDENTITY_KIND = 'pipeline_identity';
const MAX_CODE_FILES = 1024;
const MAX_LIBRARIES = 512;
const MAX_GIT_COMMIT = 128;
const PIPELINE_FINDING_SEVERITY = Object.freeze({ 'VG-PIPE-001': 'BLOCKER' });
const MANIFEST_KEYS = Object.freeze([
  'schema_version',
  'kind',
  'name',
  'version',
  'created_at',
  'actor',
  'identity',
  'pipeline_id',
  'record_hash',
  'signature',
]);
const IDENTITY_KEYS = Object.freeze(['schema_version', 'kind', 'preprocess_config', 'code', 'dependency_lock', 'parameters', 'runtime']);
const CODE_KEYS = Object.freeze(['git_commit', 'files']);
const RUNTIME_KEYS = Object.freeze(['language', 'version', 'libraries']);
const MANIFEST_KEY_SET = new Set(MANIFEST_KEYS);
const IDENTITY_KEY_SET = new Set(IDENTITY_KEYS);

function schemaError(message, details) {
  return new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, message, details || {});
}

function hasControlChars(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function readJsonFile(filePath, maxBytes) {
  let stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch {
    return null;
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.size > maxBytes) return null;
  try {
    const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return isPlainObject(value) ? value : null;
  } catch {
    return null;
  }
}

function cleanLibrary(name, version) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 128 || hasControlChars(name)) return null;
  if (typeof version !== 'string' || version.length === 0 || version.length > 64 || hasControlChars(version)) {
    return null;
  }
  return { name, version };
}

function librariesFromLock(lock) {
  const out = [];
  if (lock && isPlainObject(lock.packages)) {
    for (const [key, entry] of Object.entries(lock.packages)) {
      const match = /^node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(key);
      if (!match || !isPlainObject(entry)) continue;
      const item = cleanLibrary(match[1], entry.version);
      if (item) out.push(item);
    }
  } else if (lock && isPlainObject(lock.dependencies)) {
    for (const [name, entry] of Object.entries(lock.dependencies)) {
      if (!isPlainObject(entry)) continue;
      const item = cleanLibrary(name, entry.version);
      if (item) out.push(item);
    }
  }
  return out;
}

function librariesFromPackageJson(pkg) {
  const out = [];
  for (const field of ['dependencies', 'devDependencies']) {
    const block = pkg[field];
    if (!isPlainObject(block)) continue;
    for (const [name, version] of Object.entries(block)) {
      const item = cleanLibrary(name, version);
      if (item) out.push(item);
    }
  }
  return out;
}

function finalizeLibraries(items) {
  items.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const seen = new Set();
  const out = [];
  for (const item of items) {
    if (seen.has(item.name)) continue;
    seen.add(item.name);
    out.push(item);
    if (out.length >= MAX_LIBRARIES) break;
  }
  return out;
}

function readRuntimeFacts(options = {}) {
  const limits = resolveLimits(options.limits);
  const root = typeof options.root === 'string' && options.root.length > 0 ? options.root : null;
  let libraries = [];
  if (root) {
    const lock = readJsonFile(path.join(root, 'package-lock.json'), limits.maxManifestBytes);
    const fromLock = lock ? librariesFromLock(lock) : [];
    if (fromLock.length > 0) {
      libraries = finalizeLibraries(fromLock);
    } else {
      const pkg = readJsonFile(path.join(root, 'package.json'), limits.maxManifestBytes);
      libraries = pkg ? finalizeLibraries(librariesFromPackageJson(pkg)) : [];
    }
  }
  return { language: 'node', version: process.version, libraries };
}

function validateRuntime(value, limits) {
  if (!isPlainObject(value)) throw schemaError('runtime must be an object', { field: 'runtime' });
  for (const key of Object.keys(value)) {
    if (!RUNTIME_KEYS.includes(key)) throw schemaError(`unknown runtime field "${key}"`, { field: `runtime.${key}` });
  }
  if (typeof value.language !== 'string' || value.language.length === 0 || value.language.length > 64) {
    throw schemaError('runtime.language must be a non-empty string of at most 64 characters', {
      field: 'runtime.language',
    });
  }
  if (typeof value.version !== 'string' || value.version.length === 0 || value.version.length > 64) {
    throw schemaError('runtime.version must be a non-empty string of at most 64 characters', {
      field: 'runtime.version',
    });
  }
  if (!Array.isArray(value.libraries)) throw schemaError('runtime.libraries must be an array', { field: 'runtime.libraries' });
  if (value.libraries.length > MAX_LIBRARIES) {
    throw schemaError(`runtime.libraries must have at most ${MAX_LIBRARIES} entries`, { field: 'runtime.libraries' });
  }
  const cleaned = [];
  for (let i = 0; i < value.libraries.length; i++) {
    const entry = value.libraries[i];
    const at = `runtime.libraries[${i}]`;
    if (!isPlainObject(entry)) throw schemaError(`${at} must be an object`, { field: at });
    for (const key of Object.keys(entry)) {
      if (key !== 'name' && key !== 'version') throw schemaError(`unknown field "${key}"`, { field: `${at}.${key}` });
    }
    const item = cleanLibrary(entry.name, entry.version);
    if (!item) throw schemaError(`${at} must carry a valid name and version`, { field: at });
    cleaned.push(item);
  }
  canonicalJson({ language: value.language, version: value.version, libraries: cleaned });
  return { language: value.language, version: value.version, libraries: finalizeLibraries(cleaned) };
}

function resolveFileEntry(root, entry, field, limits) {
  if (!isPlainObject(entry)) throw schemaError(`${field} must be an object`, { field });
  for (const key of Object.keys(entry)) {
    if (key !== 'path' && key !== 'sha256') {
      throw schemaError(`unknown ${field} field "${key}"`, { field: `${field}.${key}` });
    }
  }
  const rel = normalizeRelPath(entry.path);
  if (entry.sha256 !== undefined) {
    if (typeof entry.sha256 !== 'string' || !SHA256_HEX_RE.test(entry.sha256)) {
      throw schemaError(`${field}.sha256 must be a 64 character lowercase hex digest`, { field: `${field}.sha256` });
    }
    return { path: rel, sha256: entry.sha256 };
  }
  if (typeof root !== 'string' || root.length === 0) {
    throw schemaError(`root is required to hash ${field}`, { field });
  }
  const rootReal = resolveRootReal(root);
  const { abs } = resolveArtifactPath(root, rootReal, rel);
  assertNoSymlink(abs, rel);
  const hashed = hashFile(abs, { limits, displayPath: rel });
  return { path: rel, sha256: hashed.sha256 };
}

function computePipelineIdentity(spec = {}) {
  if (!isPlainObject(spec)) throw schemaError('pipeline spec must be an object');
  const allowed = new Set(['root', 'preprocess_config', 'code', 'dependency_lock', 'parameters', 'runtime', 'limits']);
  for (const key of Object.keys(spec)) {
    if (!allowed.has(key)) throw schemaError(`unknown pipeline spec field "${key}"`, { field: key });
  }
  const limits = resolveLimits(spec.limits);
  const root = typeof spec.root === 'string' && spec.root.length > 0 ? spec.root : null;

  let preprocess_config = null;
  if (spec.preprocess_config !== undefined && spec.preprocess_config !== null) {
    preprocess_config = resolveFileEntry(root, spec.preprocess_config, 'preprocess_config', limits);
  }

  const rawCode = spec.code === undefined || spec.code === null ? { git_commit: null, files: [] } : spec.code;
  if (!isPlainObject(rawCode)) throw schemaError('code must be an object', { field: 'code' });
  for (const key of Object.keys(rawCode)) {
    if (!CODE_KEYS.includes(key)) throw schemaError(`unknown code field "${key}"`, { field: `code.${key}` });
  }
  const gitCommit = rawCode.git_commit === undefined ? null : rawCode.git_commit;
  if (
    gitCommit !== null &&
    (typeof gitCommit !== 'string' || gitCommit.length === 0 || gitCommit.length > MAX_GIT_COMMIT || hasControlChars(gitCommit))
  ) {
    throw schemaError(`code.git_commit must be null or a string of at most ${MAX_GIT_COMMIT} characters`, {
      field: 'code.git_commit',
    });
  }
  const rawFiles = rawCode.files === undefined ? [] : rawCode.files;
  if (!Array.isArray(rawFiles)) throw schemaError('code.files must be an array', { field: 'code.files' });
  if (rawFiles.length > MAX_CODE_FILES) {
    throw schemaError(`code.files must have at most ${MAX_CODE_FILES} entries`, { field: 'code.files' });
  }
  const files = rawFiles.map((entry, index) => resolveFileEntry(root, entry, `code.files[${index}]`, limits));
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  for (let i = 1; i < files.length; i++) {
    if (files[i].path === files[i - 1].path) {
      throw schemaError(`duplicate code file "${files[i].path}"`, { field: 'code.files' });
    }
  }

  let dependency_lock = null;
  if (spec.dependency_lock !== undefined && spec.dependency_lock !== null) {
    dependency_lock = resolveFileEntry(root, spec.dependency_lock, 'dependency_lock', limits);
  }

  const parameters = assertMetadata(spec.parameters === undefined ? {} : spec.parameters, limits);

  const runtime =
    spec.runtime === undefined || spec.runtime === null
      ? readRuntimeFacts({ root, limits })
      : validateRuntime(spec.runtime, limits);

  const identity = {
    schema_version: SCHEMA_VERSION,
    kind: IDENTITY_KIND,
    preprocess_config,
    code: { git_commit: gitCommit, files },
    dependency_lock,
    parameters,
    runtime,
  };
  canonicalJson(identity);
  return identity;
}

function validateFileShape(value, field) {
  if (!isPlainObject(value)) throw schemaError(`${field} must be an object`, { field });
  for (const key of Object.keys(value)) {
    if (key !== 'path' && key !== 'sha256') {
      throw schemaError(`unknown ${field} field "${key}"`, { field: `${field}.${key}` });
    }
  }
  if (typeof value.path !== 'string') throw schemaError(`${field}.path must be a string`, { field: `${field}.path` });
  normalizeRelPath(value.path);
  if (typeof value.sha256 !== 'string' || !SHA256_HEX_RE.test(value.sha256)) {
    throw schemaError(`${field}.sha256 must be a 64 character lowercase hex digest`, { field: `${field}.sha256` });
  }
}

function validateIdentity(value, limits) {
  if (!isPlainObject(value)) throw schemaError('identity must be an object', { field: 'identity' });
  for (const key of Object.keys(value)) {
    if (!IDENTITY_KEY_SET.has(key)) throw schemaError(`unknown identity field "${key}"`, { field: `identity.${key}` });
  }
  if (typeof value.schema_version !== 'string') {
    throw schemaError('identity.schema_version must be a string', { field: 'identity.schema_version' });
  }
  const major = value.schema_version.split('.')[0];
  if (major !== '1') {
    throw new VgError(ERROR_CODES.VG_MANIFEST_VERSION, `unsupported identity schema major version ${major}`, {
      schema_version: value.schema_version,
      supported_major: '1',
    });
  }
  if (value.kind !== IDENTITY_KIND) throw schemaError(`identity.kind must be "${IDENTITY_KIND}"`, { field: 'identity.kind' });
  if (value.preprocess_config !== null && value.preprocess_config !== undefined) {
    validateFileShape(value.preprocess_config, 'identity.preprocess_config');
  }
  if (!isPlainObject(value.code)) throw schemaError('identity.code must be an object', { field: 'identity.code' });
  for (const key of Object.keys(value.code)) {
    if (!CODE_KEYS.includes(key)) throw schemaError(`unknown code field "${key}"`, { field: `identity.code.${key}` });
  }
  const gitCommit = value.code.git_commit === undefined ? null : value.code.git_commit;
  if (
    gitCommit !== null &&
    (typeof gitCommit !== 'string' || gitCommit.length === 0 || gitCommit.length > MAX_GIT_COMMIT || hasControlChars(gitCommit))
  ) {
    throw schemaError('identity.code.git_commit must be null or a valid string', { field: 'identity.code.git_commit' });
  }
  if (!Array.isArray(value.code.files) || value.code.files.length > MAX_CODE_FILES) {
    throw schemaError('identity.code.files must be an array of at most 1024 entries', { field: 'identity.code.files' });
  }
  for (let i = 0; i < value.code.files.length; i++) {
    validateFileShape(value.code.files[i], `identity.code.files[${i}]`);
  }
  if (value.dependency_lock !== null && value.dependency_lock !== undefined) {
    validateFileShape(value.dependency_lock, 'identity.dependency_lock');
  }
  if (value.parameters !== undefined) assertMetadata(value.parameters, limits);
  validateRuntime(value.runtime, limits);
  return value;
}

function validatePipelineManifest(value, options = {}) {
  const strict = options.strict === true;
  const verifyHash = options.verifyHash !== false;
  const limits = resolveLimits(options.limits);
  if (!isPlainObject(value)) throw schemaError('manifest must be a plain JSON object');
  if (strict) {
    for (const key of Object.keys(value)) {
      if (!MANIFEST_KEY_SET.has(key)) throw schemaError(`unknown manifest field "${key}"`, { field: key });
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
  assertNameVersion(value.name, value.version);
  if (typeof value.created_at !== 'string' || !TIMESTAMP_RE.test(value.created_at)) {
    throw schemaError('created_at must be an RFC 3339 UTC timestamp with milliseconds', { field: 'created_at' });
  }
  if (Number.isNaN(Date.parse(value.created_at))) {
    throw schemaError('created_at is not a valid timestamp', { field: 'created_at' });
  }
  assertActor(value.actor);
  validateIdentity(value.identity, limits);
  if (typeof value.pipeline_id !== 'string' || !RECORD_HASH_RE.test(value.pipeline_id)) {
    throw schemaError('pipeline_id must be a sha256 prefixed hex digest', { field: 'pipeline_id' });
  }
  const expectedId = hashRecord(value.identity);
  if (value.pipeline_id !== expectedId) {
    throw new VgError(ERROR_CODES.VG_MANIFEST_HASH_MISMATCH, 'pipeline_id does not match the identity body', {
      expected: expectedId,
      actual: value.pipeline_id,
    });
  }
  if (typeof value.record_hash !== 'string' || !RECORD_HASH_RE.test(value.record_hash)) {
    throw schemaError('record_hash must be a sha256 prefixed hex digest', { field: 'record_hash' });
  }
  if (value.signature !== null && value.signature !== undefined && typeof value.signature !== 'string') {
    throw schemaError('signature must be null or a string', { field: 'signature' });
  }
  if (verifyHash && hashRecord(value) !== value.record_hash) {
    throw new VgError(ERROR_CODES.VG_MANIFEST_HASH_MISMATCH, 'record_hash mismatch', {
      expected: hashRecord(value),
      actual: value.record_hash,
    });
  }
  return value;
}

function parsePipelineManifest(text, options = {}) {
  const value = parseCanonical(text, { maxBytes: options.maxBytes, maxDepth: 32 });
  validatePipelineManifest(value, {
    strict: options.strict,
    limits: options.limits,
    verifyHash: options.verifyHash,
  });
  return value;
}

function finding(rule, filePath, detail) {
  return { rule, severity: PIPELINE_FINDING_SEVERITY[rule], path: filePath || null, detail };
}

function registerPipeline(options = {}) {
  const limits = resolveLimits(options.limits);
  if (options.name === undefined || options.version === undefined) {
    throw schemaError('name and version are required', { field: 'name' });
  }
  assertNameVersion(options.name, options.version);
  const actor = assertActor(options.actor);
  const identity = computePipelineIdentity({
    root: options.root,
    preprocess_config: options.preprocess_config,
    code: options.code,
    dependency_lock: options.dependency_lock,
    parameters: options.parameters,
    runtime: options.runtime,
    limits,
  });
  const manifest = {
    schema_version: SCHEMA_VERSION,
    kind: KIND,
    name: options.name,
    version: options.version,
    created_at: toIso(options.now),
    actor,
    identity,
    pipeline_id: hashRecord(identity),
    record_hash: '',
    signature: null,
  };
  manifest.record_hash = hashRecord(manifest);
  if (typeof options.keyFile === 'string' && options.keyFile.length > 0) {
    const privateKey = keys.loadPrivateKey(options.keyFile);
    const derived = keys.keyIdFromDer(
      crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' })
    );
    if (actor.key_id !== null && actor.key_id !== derived) {
      throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, 'actor.key_id does not match the key file', {
        expected: derived,
        actual: actor.key_id,
      });
    }
    manifest.signature = keys.signRecordHash(privateKey, manifest.record_hash);
  }
  validatePipelineManifest(manifest, { limits });
  if (options.storeDir) {
    store.ensureStoreDirs(options.storeDir);
    store.savePipelineManifest(options.storeDir, manifest, { limits: options.limits });
  }
  return manifest;
}

function verifyPipeline(options = {}) {
  const limits = resolveLimits(options.limits);
  const findings = [];
  const base = {
    schema_version: SCHEMA_VERSION,
    kind: 'pipeline_verification',
    checked_at: toIso(options.now),
    status: 'NOT_CHECKED',
    manifest: null,
    pipeline_id: null,
    findings,
  };

  let manifest = options.manifest;
  if (!manifest) {
    if (typeof options.storeDir !== 'string' || options.storeDir.length === 0) {
      throw new VgError(ERROR_CODES.VG_INTERNAL, 'storeDir or manifest is required');
    }
    try {
      manifest = store.loadPipelineManifest(options.storeDir, options.name, options.version, { limits });
    } catch (err) {
      if (err.code === ERROR_CODES.VG_NOT_REGISTERED) return base;
      throw err;
    }
  }
  try {
    validatePipelineManifest(manifest, { limits });
  } catch (err) {
    findings.push(finding('VG-PIPE-001', null, `pipeline manifest is invalid: ${err.message}`));
    base.status = 'FAIL';
    return base;
  }
  base.manifest = manifest;
  base.pipeline_id = manifest.pipeline_id;

  const hasSpec =
    options.root !== undefined ||
    options.code !== undefined ||
    options.preprocess_config !== undefined ||
    options.dependency_lock !== undefined ||
    options.parameters !== undefined ||
    options.runtime !== undefined;
  if (hasSpec) {
    try {
      const recomputed = computePipelineIdentity({
        root: options.root,
        preprocess_config: options.preprocess_config,
        code: options.code,
        dependency_lock: options.dependency_lock,
        parameters: options.parameters,
        runtime: options.runtime,
        limits,
      });
      if (canonicalJson(recomputed) !== canonicalJson(manifest.identity)) {
        findings.push(finding('VG-PIPE-001', null, 'recomputed pipeline identity does not match the registered identity'));
      }
    } catch (err) {
      findings.push(finding('VG-PIPE-001', null, `cannot recompute the pipeline identity: ${err.message}`));
    }
  }

  base.status = findings.length > 0 ? 'FAIL' : 'PASS';
  return base;
}

module.exports = {
  SCHEMA_VERSION,
  KIND,
  IDENTITY_KIND,
  PIPELINE_FINDING_SEVERITY,
  readRuntimeFacts,
  computePipelineIdentity,
  validatePipelineManifest,
  parsePipelineManifest,
  registerPipeline,
  verifyPipeline,
};
