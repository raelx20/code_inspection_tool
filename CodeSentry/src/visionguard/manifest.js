'use strict';

const { ERROR_CODES, VgError } = require('./errors');
const { parseCanonical, hashRecord, isPlainObject } = require('./canonical');
const { merkleRoot, assertEntry } = require('./hash');
const { normalizeRelPath } = require('./paths');
const { walkDataset, normalizePolicy, FINDING_SEVERITY, MAX_FINDINGS_PER_RULE } = require('./walk');

const SCHEMA_VERSION = '1.0';
const KIND = 'dataset_manifest';
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const RECORD_HASH_RE = /^sha256:[0-9a-f]{64}$/;
const RULE_RE = /^VG-DATA-\d{3}$/;
const KNOWN_KEYS = new Set([
  'schema_version',
  'kind',
  'name',
  'version',
  'created_at',
  'actor',
  'hash_algorithm',
  'file_count',
  'total_bytes',
  'merkle_root',
  'files',
  'policy',
  'policy_findings',
  'record_hash',
  'signature',
]);

function schemaError(message, details) {
  return new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, message, details || {});
}

function assertLabel(value, field) {
  if (typeof value !== 'string' || !NAME_RE.test(value)) {
    throw schemaError(
      `${field} must start with an alphanumeric character and contain only letters, digits, ".", "_" or "-" (max 64)`,
      { field }
    );
  }
}

function assertNameVersion(name, version) {
  assertLabel(name, 'name');
  assertLabel(version, 'version');
}

function assertActor(actor) {
  if (!isPlainObject(actor)) throw schemaError('actor must be an object', { field: 'actor' });
  for (const key of Object.keys(actor)) {
    if (key !== 'contributor' && key !== 'key_id') {
      throw schemaError(`unknown actor field "${key}"`, { field: `actor.${key}` });
    }
  }
  const contributor = actor.contributor;
  if (typeof contributor !== 'string' || contributor.trim().length === 0 || contributor.length > 128) {
    throw schemaError('actor.contributor must be a non-empty string of at most 128 characters', {
      field: 'actor.contributor',
    });
  }
  const keyId = actor.key_id === undefined ? null : actor.key_id;
  if (keyId !== null && (typeof keyId !== 'string' || keyId.length === 0 || keyId.length > 128)) {
    throw schemaError('actor.key_id must be null or a non-empty string of at most 128 characters', {
      field: 'actor.key_id',
    });
  }
  return { contributor, key_id: keyId };
}

function toIso(now) {
  let date;
  if (now === undefined || now === null) date = new Date();
  else if (now instanceof Date) date = now;
  else if (typeof now === 'string' || typeof now === 'number') date = new Date(now);
  else throw new VgError(ERROR_CODES.VG_INTERNAL, 'now must be a Date, ISO string or epoch millis');
  if (Number.isNaN(date.getTime())) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'now is not a valid time value');
  }
  return date.toISOString();
}

function validateDatasetManifest(value, options = {}) {
  const strict = options.strict === true;
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

  if (value.kind !== KIND) {
    throw schemaError(`kind must be "${KIND}"`, { field: 'kind' });
  }
  if (value.hash_algorithm !== 'sha256') {
    throw schemaError('hash_algorithm must be "sha256"', { field: 'hash_algorithm' });
  }
  assertNameVersion(value.name, value.version);

  if (typeof value.created_at !== 'string' || !TIMESTAMP_RE.test(value.created_at)) {
    throw schemaError('created_at must be an RFC 3339 UTC timestamp with milliseconds', {
      field: 'created_at',
    });
  }
  if (Number.isNaN(Date.parse(value.created_at))) {
    throw schemaError('created_at is not a valid timestamp', { field: 'created_at' });
  }

  assertActor(value.actor);

  if (!Number.isSafeInteger(value.file_count) || value.file_count < 0) {
    throw schemaError('file_count must be a non-negative integer', { field: 'file_count' });
  }
  if (!Number.isSafeInteger(value.total_bytes) || value.total_bytes < 0) {
    throw schemaError('total_bytes must be a non-negative integer', { field: 'total_bytes' });
  }

  if (typeof value.merkle_root !== 'string' || !RECORD_HASH_RE.test(value.merkle_root)) {
    throw schemaError('merkle_root must be a sha256 prefixed hex digest', { field: 'merkle_root' });
  }

  if (!Array.isArray(value.files)) throw schemaError('files must be an array', { field: 'files' });
  const seenPaths = new Set();
  for (const entry of value.files) {
    assertEntry(entry);
    const canonical = normalizeRelPath(entry.path);
    if (canonical !== entry.path) {
      throw schemaError(`file path is not in canonical form: ${entry.path}`, { field: 'files' });
    }
    if (seenPaths.has(entry.path)) {
      throw new VgError(ERROR_CODES.VG_NFC_COLLISION, `duplicate file path in manifest: ${entry.path}`, {
        path: entry.path,
      });
    }
    seenPaths.add(entry.path);
  }

  if (value.policy === undefined) throw schemaError('policy is required', { field: 'policy' });
  normalizePolicy(value.policy);

  if (value.policy_findings === undefined) {
    throw schemaError('policy_findings is required', { field: 'policy_findings' });
  }
  if (!Array.isArray(value.policy_findings)) {
    throw schemaError('policy_findings must be an array', { field: 'policy_findings' });
  }
  if (value.policy_findings.length > MAX_FINDINGS_PER_RULE) {
    throw schemaError(`policy_findings exceeds ${MAX_FINDINGS_PER_RULE} entries`, { field: 'policy_findings' });
  }
  for (const finding of value.policy_findings) {
    if (!isPlainObject(finding)) throw schemaError('policy findings must be objects', { field: 'policy_findings' });
    if (typeof finding.rule !== 'string' || !RULE_RE.test(finding.rule)) {
      throw schemaError('policy finding rule must match VG-DATA-NNN', { field: 'policy_findings' });
    }
    if (typeof finding.path !== 'string') {
      throw schemaError('policy finding path must be a string', { field: 'policy_findings' });
    }
    if (typeof finding.detail !== 'string') {
      throw schemaError('policy finding detail must be a string', { field: 'policy_findings' });
    }
  }

  if (typeof value.record_hash !== 'string' || !RECORD_HASH_RE.test(value.record_hash)) {
    throw schemaError('record_hash must be a sha256 prefixed hex digest', { field: 'record_hash' });
  }
  if (value.signature !== null && typeof value.signature !== 'string') {
    throw schemaError('signature must be null or a string', { field: 'signature' });
  }

  return value;
}

function parseDatasetManifest(text, options = {}) {
  const maxBytes = options.maxBytes;
  const value = parseCanonical(text, { maxBytes, maxDepth: 32 });
  validateDatasetManifest(value, { strict: options.strict });
  return value;
}

function checkManifestConsistency(manifest) {
  const recordHashValid = hashRecord(manifest) === manifest.record_hash;
  let merkleRootValid = true;
  try {
    merkleRootValid = merkleRoot(manifest.files) === manifest.merkle_root;
  } catch {
    merkleRootValid = false;
  }
  let totalBytes = 0;
  for (const entry of manifest.files) totalBytes += entry.size;
  const countsValid = manifest.file_count === manifest.files.length && manifest.total_bytes === totalBytes;
  return {
    recordHashValid,
    merkleRootValid,
    countsValid,
    consistent: recordHashValid && merkleRootValid && countsValid,
  };
}

function buildDatasetManifest(options) {
  const { name, version, walk, now } = options;
  assertNameVersion(name, version);
  const actor = assertActor(options.actor);
  const policy = normalizePolicy(walk.policy);

  const files = walk.entries.map((entry) => ({
    path: entry.path,
    size: entry.size,
    sha256: entry.sha256,
  }));
  let totalBytes = 0;
  for (const entry of files) totalBytes += entry.size;

  const manifest = {
    schema_version: SCHEMA_VERSION,
    kind: KIND,
    name,
    version,
    created_at: toIso(now),
    actor,
    hash_algorithm: 'sha256',
    file_count: files.length,
    total_bytes: totalBytes,
    merkle_root: merkleRoot(files),
    files,
    policy,
    policy_findings: walk.findings.slice(0, MAX_FINDINGS_PER_RULE),
    record_hash: '',
    signature: null,
  };
  manifest.record_hash = hashRecord(manifest);
  validateDatasetManifest(manifest);
  return manifest;
}

function diffDataset(manifestFiles, walkResult) {
  const manifestByPath = new Map(manifestFiles.map((entry) => [entry.path, entry]));
  const walkByPath = new Map(walkResult.entries.map((entry) => [entry.path, entry]));
  const unreadablePaths = new Set(walkResult.unreadable.map((entry) => entry.path));

  const modified = [];
  const removed = [];
  const added = [];
  let unchanged = 0;

  for (const [filePath, expected] of manifestByPath) {
    const actual = walkByPath.get(filePath);
    if (actual === undefined) {
      if (unreadablePaths.has(filePath)) continue;
      removed.push({
        path: filePath,
        expected_sha256: expected.sha256,
        expected_size: expected.size,
      });
      continue;
    }
    if (actual.sha256 !== expected.sha256) {
      modified.push({
        path: filePath,
        expected_sha256: expected.sha256,
        actual_sha256: actual.sha256,
        expected_size: expected.size,
        actual_size: actual.size,
      });
    } else {
      unchanged += 1;
    }
  }

  for (const [filePath, actual] of walkByPath) {
    if (!manifestByPath.has(filePath)) {
      added.push({ path: filePath, size: actual.size, sha256: actual.sha256 });
    }
  }

  const removedByHash = new Map();
  for (let i = 0; i < removed.length; i++) {
    const key = removed[i].expected_sha256;
    if (!removedByHash.has(key)) removedByHash.set(key, []);
    removedByHash.get(key).push(i);
  }

  const renamed = [];
  const removedTaken = new Set();
  const addedTaken = new Set();
  for (let addedIndex = 0; addedIndex < added.length; addedIndex++) {
    const entry = added[addedIndex];
    const candidates = removedByHash.get(entry.sha256);
    if (candidates === undefined) continue;
    while (candidates.length > 0) {
      const index = candidates.shift();
      if (!removedTaken.has(index)) {
        removedTaken.add(index);
        addedTaken.add(addedIndex);
        renamed.push({ from: removed[index].path, to: entry.path, sha256: entry.sha256 });
        break;
      }
    }
  }

  const finalRemoved = removed.filter((_, index) => !removedTaken.has(index));
  const finalAdded = added.filter((entry, index) => !addedTaken.has(index));

  return {
    modified,
    removed: finalRemoved,
    added: finalAdded,
    renamed,
    unchanged,
    unreadable: walkResult.unreadable,
  };
}

function finding(rule, path, detail) {
  return { rule, severity: FINDING_SEVERITY[rule], path, detail };
}

function verifyDataset(options) {
  const manifest = options.manifest;
  const strict = options.strict === true;
  validateDatasetManifest(manifest);
  const consistency = checkManifestConsistency(manifest);

  const walk = walkDataset(options.path, {
    policy: manifest.policy,
    limits: options.limits,
    mode: 'verify',
    strict,
  });
  const diff = diffDataset(manifest.files, walk);

  const findings = [];
  if (!consistency.consistent) {
    const failed = [];
    if (!consistency.recordHashValid) failed.push('record_hash does not match the manifest body');
    if (!consistency.merkleRootValid) failed.push('merkle_root does not match the file list');
    if (!consistency.countsValid) failed.push('file_count or total_bytes does not match the file list');
    findings.push(finding('VG-DATA-007', null, `manifest self-consistency check failed: ${failed.join('; ')}`));
  }
  for (const entry of diff.modified) {
    findings.push(
      finding('VG-DATA-001', entry.path, `content changed: expected ${entry.expected_sha256}, got ${entry.actual_sha256}`)
    );
  }
  for (const entry of diff.removed) {
    findings.push(finding('VG-DATA-002', entry.path, `missing from disk: expected ${entry.expected_sha256}`));
  }
  for (const entry of diff.added) {
    findings.push(finding('VG-DATA-003', entry.path, `not present in manifest: found ${entry.sha256}`));
  }
  for (const entry of diff.renamed) {
    findings.push(finding('VG-DATA-004', entry.to, `renamed from "${entry.from}" to "${entry.to}" (same content)`));
  }
  for (const entry of diff.unreadable) {
    findings.push(finding('VG-DATA-008', entry.path, `unreadable (${entry.code})`));
  }
  for (const item of walk.findings) {
    findings.push({ rule: item.rule, severity: item.severity, path: item.path, detail: item.detail });
  }
  if (manifest.file_count === 0) {
    findings.push(finding('VG-DATA-010', null, 'dataset contains no files'));
  }

  const hasBlocker = findings.some((item) => item.severity === 'BLOCKER');
  const unreadableFail = diff.unreadable.length > 0;
  const strictPolicyFail =
    strict &&
    ((walk.findingCounts['VG-DATA-005'] || 0) > 0 || (walk.findingCounts['VG-DATA-011'] || 0) > 0);
  const status = hasBlocker || unreadableFail || strictPolicyFail ? 'FAIL' : 'UNANCHORED';

  let computedMerkleRoot = null;
  try {
    computedMerkleRoot = merkleRoot(walk.entries);
  } catch {
    computedMerkleRoot = null;
  }

  return {
    schema_version: SCHEMA_VERSION,
    kind: 'dataset_verification',
    name: manifest.name,
    version: manifest.version,
    checked_at: toIso(options.now),
    status,
    strict,
    signaturePresent: manifest.signature !== null,
    manifestConsistency: consistency,
    expectedMerkleRoot: manifest.merkle_root,
    computedMerkleRoot,
    diff,
    findings,
    findingCounts: walk.findingCounts,
    walkStats: walk.stats,
  };
}

function registerDataset(options) {
  assertNameVersion(options.name, options.version);
  const datasetPath = options.path;
  const storeDir = options.storeDir;

  let store = null;
  if (storeDir) {
    store = require('./store');
    store.assertStoreOutside(datasetPath, storeDir);
    store.ensureStoreDirs(storeDir);
  }

  const walk = walkDataset(datasetPath, {
    policy: options.policy,
    limits: options.limits,
    mode: 'register',
    strict: options.strict === true,
  });
  const manifest = buildDatasetManifest({
    name: options.name,
    version: options.version,
    actor: options.actor,
    walk,
    now: options.now,
  });

  if (store) store.saveDatasetManifest(storeDir, manifest, { limits: options.limits });
  return manifest;
}

module.exports = {
  SCHEMA_VERSION,
  KIND,
  NAME_RE,
  TIMESTAMP_RE,
  RECORD_HASH_RE,
  assertLabel,
  assertNameVersion,
  assertActor,
  toIso,
  validateDatasetManifest,
  parseDatasetManifest,
  checkManifestConsistency,
  buildDatasetManifest,
  diffDataset,
  verifyDataset,
  registerDataset,
};
