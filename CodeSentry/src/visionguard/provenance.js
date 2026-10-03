'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const { ERROR_CODES, VgError } = require('./errors');
const { parseCanonical, hashRecord, canonicalJson, isPlainObject } = require('./canonical');
const { resolveLimits } = require('./limits');
const { SHA256_HEX_RE } = require('./hash');
const {
  assertActor,
  toIso,
  TIMESTAMP_RE,
  RECORD_HASH_RE,
  NAME_RE,
  assertLabel,
} = require('./manifest');
const { assertMetadata } = require('./metadata');
const store = require('./store');
const keys = require('./keys');

const SCHEMA_VERSION = '1.0';
const KIND = 'provenance_verification';
const RECORD_KINDS = Object.freeze([
  'contributor_registered',
  'artifact_registered',
  'operation_recorded',
  'inference_recorded',
]);
const ENVELOPE_KEYS = Object.freeze([
  'schema_version',
  'record_id',
  'kind',
  'timestamp',
  'actor',
  'inputs',
  'outputs',
  'parent_record_hashes',
  'prev_record_hash',
  'metadata',
  'record_hash',
  'signature',
]);
const KIND_KEYS = Object.freeze({
  contributor_registered: Object.freeze(['contributor', 'key_id', 'operations', 'public_key_der_b64']),
  artifact_registered: Object.freeze([]),
  operation_recorded: Object.freeze(['operation']),
  inference_recorded: Object.freeze([]),
});
const ARTIFACT_TYPE_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_ARTIFACT_LEN = 512;
const MAX_ARTIFACT_REFS = 4096;
const MAX_PARENTS = 4096;
const MAX_FINDINGS_PER_RULE = 100;
const LOG_PATH = store.PROVENANCE_LOG_FILE;
const PROV_FINDING_SEVERITY = Object.freeze({
  'VG-PROV-001': 'BLOCKER',
  'VG-PROV-002': 'BLOCKER',
  'VG-PROV-003': 'BLOCKER',
  'VG-PROV-004': 'BLOCKER',
  'VG-PROV-005': 'BLOCKER',
  'VG-PROV-006': 'BLOCKER',
  'VG-PROV-007': 'BLOCKER',
  'VG-PROV-008': 'BLOCKER',
  'VG-PROV-009': 'HIGH',
  'VG-PROV-010': 'BLOCKER',
  'VG-PROV-011': 'BLOCKER',
});
const WARNING_RULES = Object.freeze([
  'VG-PROV-W001',
  'VG-PROV-W002',
  'VG-PROV-W003',
  'VG-PROV-W004',
]);
const WARNING_SEVERITY = 'WARN';

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

function assertSha256(value, field) {
  if (typeof value !== 'string' || !SHA256_HEX_RE.test(value)) {
    throw schemaError(`${field} must be a 64 character lowercase hex sha256`, { field });
  }
}

function assertArtifactString(value, field) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ARTIFACT_LEN) {
    throw schemaError(`${field} must be a non-empty reference of at most ${MAX_ARTIFACT_LEN} characters`, {
      field,
    });
  }
  if (hasControlChars(value)) {
    throw schemaError(`${field} must not contain control characters`, { field });
  }
}

function parseArtifactRef(artifact) {
  if (typeof artifact !== 'string') return null;
  const at = artifact.lastIndexOf('@');
  if (at <= 0 || at === artifact.length - 1) return null;
  const prefix = artifact.slice(0, at);
  const version = artifact.slice(at + 1);
  const slash = prefix.indexOf('/');
  if (slash <= 0 || slash === prefix.length - 1) return null;
  const type = prefix.slice(0, slash);
  const name = prefix.slice(slash + 1);
  if (!ARTIFACT_TYPE_RE.test(type)) return null;
  if (!NAME_RE.test(name) || !NAME_RE.test(version)) return null;
  return { type, name, version, ref: `${type}/${name}@${version}` };
}

function assertRefArray(value, field) {
  if (!Array.isArray(value)) throw schemaError(`${field} must be an array`, { field });
  if (value.length > MAX_ARTIFACT_REFS) {
    throw schemaError(`${field} must have at most ${MAX_ARTIFACT_REFS} entries`, { field });
  }
  for (let i = 0; i < value.length; i++) {
    const entry = value[i];
    const at = `${field}[${i}]`;
    if (!isPlainObject(entry)) throw schemaError(`${at} must be an object`, { field: at });
    for (const key of Object.keys(entry)) {
      if (key !== 'artifact' && key !== 'sha256') {
        throw schemaError(`unknown field "${key}" in ${at}`, { field: `${at}.${key}` });
      }
    }
    assertArtifactString(entry.artifact, `${at}.artifact`);
    assertSha256(entry.sha256, `${at}.sha256`);
  }
  return value;
}

function assertHashList(value, field, maxEntries) {
  if (!Array.isArray(value)) throw schemaError(`${field} must be an array`, { field });
  if (value.length > maxEntries) {
    throw schemaError(`${field} must have at most ${maxEntries} entries`, { field });
  }
  for (let i = 0; i < value.length; i++) {
    const entry = value[i];
    if (typeof entry !== 'string' || !RECORD_HASH_RE.test(entry)) {
      throw schemaError(`${field}[${i}] must be a sha256: hex digest`, { field: `${field}[${i}]` });
    }
  }
  return value;
}

function validateRecord(value, options = {}) {
  const limits = resolveLimits(options.limits);
  if (!isPlainObject(value)) throw schemaError('record must be a plain JSON object');
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
  if (typeof value.kind !== 'string' || !RECORD_KINDS.includes(value.kind)) {
    throw schemaError(`kind must be one of ${RECORD_KINDS.join(', ')}`, { field: 'kind' });
  }
  const known = new Set([...ENVELOPE_KEYS, ...KIND_KEYS[value.kind]]);
  for (const key of Object.keys(value)) {
    if (!known.has(key)) throw schemaError(`unknown field "${key}"`, { field: key });
  }
  if (typeof value.timestamp !== 'string' || !TIMESTAMP_RE.test(value.timestamp)) {
    throw schemaError('timestamp must be an RFC 3339 UTC timestamp with milliseconds', {
      field: 'timestamp',
    });
  }
  const actor = assertActor(value.actor);
  const inputs = assertRefArray(value.inputs, 'inputs');
  const outputs = assertRefArray(value.outputs, 'outputs');
  assertHashList(value.parent_record_hashes, 'parent_record_hashes', MAX_PARENTS);
  if (value.prev_record_hash !== null && value.prev_record_hash !== undefined) {
    if (typeof value.prev_record_hash !== 'string' || !RECORD_HASH_RE.test(value.prev_record_hash)) {
      throw schemaError('prev_record_hash must be null or a sha256: hex digest', {
        field: 'prev_record_hash',
      });
    }
  }
  if (value.metadata !== undefined) assertMetadata(value.metadata, limits);
  if (typeof value.record_hash !== 'string' || !RECORD_HASH_RE.test(value.record_hash)) {
    throw schemaError('record_hash must be a sha256: hex digest', { field: 'record_hash' });
  }
  if (value.record_id !== value.record_hash) {
    throw schemaError('record_id must equal record_hash', { field: 'record_id' });
  }
  if (value.signature !== undefined && value.signature !== null) {
    if (typeof value.signature !== 'string' || !BASE64_RE.test(value.signature)) {
      throw schemaError('signature must be base64 or null', { field: 'signature' });
    }
    if (actor.key_id === null) {
      throw schemaError('signed records must carry actor.key_id', { field: 'actor.key_id' });
    }
  }
  if (value.kind === 'contributor_registered') {
    if (inputs.length !== 0 || outputs.length !== 0) {
      throw schemaError('contributor_registered must have empty inputs and outputs', { field: 'inputs' });
    }
    if (value.contributor !== actor.contributor) {
      throw schemaError('contributor must match actor.contributor', { field: 'contributor' });
    }
    if (typeof value.key_id !== 'string' || value.key_id !== actor.key_id) {
      throw schemaError('key_id must match actor.key_id', { field: 'key_id' });
    }
    if (!Array.isArray(value.operations)) {
      throw schemaError('operations must be an array', { field: 'operations' });
    }
    const seenOps = new Set();
    for (const op of value.operations) {
      if (typeof op !== 'string' || !keys.OPERATIONS.includes(op)) {
        throw schemaError(`unsupported operation "${String(op)}"`, { field: 'operations' });
      }
      if (seenOps.has(op)) throw schemaError(`duplicate operation "${op}"`, { field: 'operations' });
      seenOps.add(op);
    }
    if (typeof value.public_key_der_b64 !== 'string' || !BASE64_RE.test(value.public_key_der_b64)) {
      throw schemaError('public_key_der_b64 must be base64', { field: 'public_key_der_b64' });
    }
    const der = Buffer.from(value.public_key_der_b64, 'base64');
    if (!keys.publicKeyObjectFromDer(der)) {
      throw schemaError('public_key_der_b64 must decode to a valid ed25519 SPKI key', {
        field: 'public_key_der_b64',
      });
    }
  } else if (value.kind === 'artifact_registered') {
    if (inputs.length !== 0) {
      throw schemaError('artifact_registered must have empty inputs', { field: 'inputs' });
    }
    if (outputs.length < 1) {
      throw schemaError('artifact_registered requires at least one output', { field: 'outputs' });
    }
  } else if (value.kind === 'operation_recorded') {
    if (typeof value.operation !== 'string' || !keys.OPERATIONS.includes(value.operation)) {
      throw schemaError(`operation must be one of ${keys.OPERATIONS.join(', ')}`, { field: 'operation' });
    }
    if (inputs.length < 1) {
      throw schemaError('operation_recorded requires at least one input', { field: 'inputs' });
    }
    if (outputs.length < 1) {
      throw schemaError('operation_recorded requires at least one output', { field: 'outputs' });
    }
  } else if (value.kind === 'inference_recorded') {
    if (inputs.length !== 3) {
      throw schemaError('inference_recorded must have exactly 3 inputs (input, model, pipeline)', {
        field: 'inputs',
      });
    }
    if (outputs.length !== 1) {
      throw schemaError('inference_recorded must have exactly 1 output', { field: 'outputs' });
    }
    let modelRefs = 0;
    let pipelineRefs = 0;
    let looseInputs = 0;
    for (const item of inputs) {
      const ref = parseArtifactRef(item.artifact);
      if (ref && ref.type === 'model') modelRefs += 1;
      else if (ref && ref.type === 'pipeline') pipelineRefs += 1;
      else looseInputs += 1;
    }
    if (modelRefs !== 1 || pipelineRefs !== 1 || looseInputs !== 1) {
      throw schemaError(
        'inference_recorded inputs must be exactly one input, one "model/...@..." ref and one "pipeline/...@..." ref',
        { field: 'inputs' }
      );
    }
    if (
      value.metadata !== undefined &&
      value.metadata !== null &&
      value.metadata.output_mode !== undefined &&
      value.metadata.output_mode !== 'raw' &&
      value.metadata.output_mode !== 'canonical_json'
    ) {
      throw schemaError('metadata.output_mode must be "raw" or "canonical_json"', {
        field: 'metadata.output_mode',
      });
    }
  }
  if (options.verifyHash !== false && hashRecord(value) !== value.record_hash) {
    throw new VgError(ERROR_CODES.VG_MANIFEST_HASH_MISMATCH, 'record_hash mismatch', {
      record_id: value.record_id,
      expected: hashRecord(value),
      actual: value.record_hash,
    });
  }
  return value;
}

function buildRecord(fields, options = {}) {
  if (!isPlainObject(fields)) throw new VgError(ERROR_CODES.VG_INTERNAL, 'record fields must be an object');
  const kind = fields.kind;
  if (typeof kind !== 'string' || !RECORD_KINDS.includes(kind)) {
    throw schemaError(`kind must be one of ${RECORD_KINDS.join(', ')}`, { field: 'kind' });
  }
  const actor = assertActor(fields.actor);
  const record = {
    schema_version: SCHEMA_VERSION,
    record_id: null,
    kind,
    timestamp: fields.timestamp !== undefined ? fields.timestamp : toIso(options.now),
    actor: { contributor: actor.contributor, key_id: actor.key_id },
    inputs: fields.inputs === undefined ? [] : fields.inputs,
    outputs: fields.outputs === undefined ? [] : fields.outputs,
    parent_record_hashes: fields.parent_record_hashes === undefined ? [] : fields.parent_record_hashes,
    prev_record_hash: fields.prev_record_hash === undefined ? null : fields.prev_record_hash,
    metadata: fields.metadata === undefined ? {} : fields.metadata,
  };
  for (const key of KIND_KEYS[kind]) {
    record[key] = fields[key];
  }
  record.record_hash = hashRecord(record);
  record.record_id = record.record_hash;
  return record;
}

function splitLogLines(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function parseProvenanceLog(text, options = {}) {
  const limits = resolveLimits(options.limits);
  const entries = [];
  const malformed = [];
  const lines = splitLogLines(text);
  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const raw = lines[i];
    if (raw.trim().length === 0) {
      malformed.push({ lineNumber, reason: 'empty line' });
      continue;
    }
    let value;
    try {
      value = parseCanonical(raw, { maxBytes: limits.maxManifestBytes });
    } catch (err) {
      malformed.push({ lineNumber, reason: err.message });
      continue;
    }
    try {
      validateRecord(value, { limits });
    } catch (err) {
      malformed.push({ lineNumber, reason: err.message, code: err.code });
      continue;
    }
    entries.push({ lineNumber, record: value });
  }
  return { entries, malformed };
}

function lockOptionsFrom(options) {
  const lockOptions = {};
  for (const key of ['timeoutMs', 'staleMs', 'retryMs']) {
    if (options[key] !== undefined) lockOptions[key] = options[key];
  }
  return lockOptions;
}

function appendRecord(storeDir, fields, options = {}) {
  const limits = resolveLimits(options.limits);
  const sign = options.sign !== false;
  const privateKey = options.privateKey || null;
  if (sign && !privateKey) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'privateKey is required to append a signed record');
  }
  return store.withLogLock(
    storeDir,
    () => {
      const log = store.readProvenanceText(storeDir, { limits });
      const parsed = parseProvenanceLog(log.text, { limits });
      if (parsed.malformed.length > 0) {
        const first = parsed.malformed[0];
        throw new VgError(
          ERROR_CODES.VG_MANIFEST_MALFORMED,
          `provenance log is corrupt at line ${first.lineNumber}: ${first.reason}`,
          { line: first.lineNumber, reason: first.reason }
        );
      }
      const entries = parsed.entries;
      if (entries.length > 0 && entries[0].record.prev_record_hash !== null) {
        throw new VgError(ERROR_CODES.VG_MANIFEST_MALFORMED, 'provenance chain does not start at genesis', {
          line: entries[0].lineNumber,
        });
      }
      for (let i = 1; i < entries.length; i++) {
        if (entries[i].record.prev_record_hash !== entries[i - 1].record.record_hash) {
          throw new VgError(
            ERROR_CODES.VG_MANIFEST_MALFORMED,
            `provenance chain is broken at line ${entries[i].lineNumber}`,
            { line: entries[i].lineNumber }
          );
        }
      }
      const prev = entries.length > 0 ? entries[entries.length - 1].record.record_hash : null;
      const record = buildRecord({ ...fields, prev_record_hash: prev }, { now: options.now });
      if (sign) record.signature = keys.signRecordHash(privateKey, record.record_hash);
      validateRecord(record, { limits });
      for (const entry of entries) {
        if (entry.record.record_hash === record.record_hash) {
          throw new VgError(ERROR_CODES.VG_MANIFEST_MALFORMED, 'duplicate record_hash', {
            line: entry.lineNumber,
            record_hash: record.record_hash,
          });
        }
      }
      const line = canonicalJson(record);
      const size = store.appendLogLineUnlocked(storeDir, line, limits);
      return { record, line, size, position: entries.length, prev_record_hash: prev };
    },
    lockOptionsFrom(options)
  );
}

function assertOperation(operation) {
  if (typeof operation !== 'string' || !keys.OPERATIONS.includes(operation)) {
    throw schemaError(`operation must be one of ${keys.OPERATIONS.join(', ')}`, { field: 'operation' });
  }
  return operation;
}

function resolveSigner(options) {
  if (typeof options.keyFile !== 'string' || options.keyFile.length === 0) {
    throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, 'a private key file is required', { keyFile: null });
  }
  const actor = assertActor(options.actor);
  if (actor.key_id === null) {
    throw schemaError('actor.key_id is required', { field: 'actor.key_id' });
  }
  const privateKey = keys.loadPrivateKey(options.keyFile);
  const publicKey = crypto.createPublicKey(privateKey);
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const derived = keys.keyIdFromDer(der);
  if (derived !== actor.key_id) {
    throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, 'actor.key_id does not match the key file', {
      expected: derived,
      actual: actor.key_id,
    });
  }
  let keyRecord;
  try {
    keyRecord = keys.loadPublicKey(options.storeDir, actor.contributor, actor.key_id, {
      limits: options.limits,
    });
  } catch (err) {
    throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, `public key is not registered: ${err.message}`, {
      contributor: actor.contributor,
      key_id: actor.key_id,
      reason: err.code || 'UNKNOWN',
    });
  }
  if (keyRecord.status === 'revoked') {
    throw new VgError(ERROR_CODES.VG_KEY_REVOKED, 'signing key has been revoked', {
      contributor: actor.contributor,
      key_id: actor.key_id,
    });
  }
  return { privateKey, keyRecord, actor, der };
}

function registerContributor(options = {}) {
  const storeDir = options.storeDir;
  if (typeof storeDir !== 'string' || storeDir.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'storeDir must be a non-empty string');
  }
  const contributor = options.contributor;
  assertLabel(contributor, 'contributor');
  const operations = Array.isArray(options.operations) && options.operations.length > 0
    ? [...new Set(options.operations)]
    : [...keys.OPERATIONS];
  for (const op of operations) {
    if (typeof op !== 'string' || !keys.OPERATIONS.includes(op)) {
      throw schemaError(`unsupported operation "${String(op)}"`, { field: 'operations' });
    }
  }
  const limits = resolveLimits(options.limits);
  const keyDir = options.keyDir || keys.defaultKeyDir();
  const keyFile = typeof options.keyFile === 'string' && options.keyFile.length > 0 ? options.keyFile : null;
  let pair;
  let privateKeyPath;
  let generated = false;
  if (keyFile) {
    const privateKey = keys.loadPrivateKey(keyFile);
    const publicKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
    pair = { privateKey, publicKeyDer, keyId: keys.keyIdFromDer(publicKeyDer) };
    privateKeyPath = keyFile;
  } else {
    pair = keys.generateKeyPair();
    privateKeyPath = keys.savePrivateKey(keyDir, contributor, pair.keyId, pair.privateKeyDer);
    generated = true;
  }
  const publicKeyRecord = keys.buildPublicKeyRecord({
    contributor,
    publicKeyDer: pair.publicKeyDer,
    operations,
    privateKey: pair.privateKey,
    now: options.now,
  });
  try {
    keys.savePublicKey(storeDir, publicKeyRecord, { limits });
    const appended = appendRecord(
      storeDir,
      {
        kind: 'contributor_registered',
        actor: { contributor, key_id: pair.keyId },
        contributor,
        key_id: pair.keyId,
        operations,
        public_key_der_b64: pair.publicKeyDer.toString('base64'),
        inputs: [],
        outputs: [],
        metadata: options.metadata,
      },
      { privateKey: pair.privateKey, now: options.now, limits, ...lockOptionsFrom(options) }
    );
    return {
      contributor,
      key_id: pair.keyId,
      publicKeyRecord,
      record: appended.record,
      privateKeyPath,
      operations,
    };
  } catch (err) {
    if (generated) {
      try {
        fs.unlinkSync(privateKeyPath);
      } catch {
      }
    }
    try {
      fs.unlinkSync(keys.publicKeyPath(storeDir, contributor, pair.keyId));
    } catch {
    }
    throw err;
  }
}

function recordOperation(options = {}) {
  const storeDir = options.storeDir;
  if (typeof storeDir !== 'string' || storeDir.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'storeDir must be a non-empty string');
  }
  const operation = assertOperation(options.operation);
  const limits = resolveLimits(options.limits);
  const signer = resolveSigner({ ...options, storeDir });
  if (!signer.keyRecord.operations.includes(operation)) {
    throw new VgError(
      ERROR_CODES.VG_UNAUTHORIZED_OP,
      `operation "${operation}" is not authorized for this key`,
      { operation, operations: signer.keyRecord.operations }
    );
  }
  const appended = appendRecord(
    storeDir,
    {
      kind: 'operation_recorded',
      actor: signer.actor,
      operation,
      inputs: options.inputs,
      outputs: options.outputs,
      parent_record_hashes: options.parents || options.parent_record_hashes,
      metadata: options.metadata,
    },
    { privateKey: signer.privateKey, now: options.now, limits, ...lockOptionsFrom(options) }
  );
  return appended.record;
}

function recordArtifact(options = {}) {
  const storeDir = options.storeDir;
  if (typeof storeDir !== 'string' || storeDir.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'storeDir must be a non-empty string');
  }
  const limits = resolveLimits(options.limits);
  const signer = resolveSigner({ ...options, storeDir });
  const entry = { artifact: options.artifact, sha256: options.sha256 };
  assertArtifactString(entry.artifact, 'artifact');
  assertSha256(entry.sha256, 'sha256');
  const appended = appendRecord(
    storeDir,
    {
      kind: 'artifact_registered',
      actor: signer.actor,
      inputs: [],
      outputs: [entry],
      parent_record_hashes: options.parents || options.parent_record_hashes,
      metadata: options.metadata,
    },
    { privateKey: signer.privateKey, now: options.now, limits, ...lockOptionsFrom(options) }
  );
  return appended.record;
}

class FindingSink {
  constructor() {
    this.findings = [];
    this.warnings = [];
    this.counts = new Map();
    this.truncated = new Map();
  }

  add(listName, rule, severity, message, extra) {
    const key = `${listName}:${rule}`;
    const count = this.counts.get(key) || 0;
    if (count >= MAX_FINDINGS_PER_RULE) {
      this.truncated.set(key, (this.truncated.get(key) || 0) + 1);
      return;
    }
    this.counts.set(key, count + 1);
    const item = { rule, severity, message, path: LOG_PATH };
    if (extra) Object.assign(item, extra);
    (listName === 'findings' ? this.findings : this.warnings).push(item);
  }

  finding(rule, message, extra) {
    this.add('findings', rule, PROV_FINDING_SEVERITY[rule] || 'BLOCKER', message, extra);
  }

  warning(rule, message, extra) {
    this.add('warnings', rule, WARNING_SEVERITY, message, extra);
  }

  finalize() {
    for (const [key, extra] of this.truncated) {
      const separator = key.indexOf(':');
      const listName = key.slice(0, separator);
      const rule = key.slice(separator + 1);
      const item = {
        rule,
        severity: listName === 'findings' ? PROV_FINDING_SEVERITY[rule] || 'BLOCKER' : WARNING_SEVERITY,
        message: `${extra} additional ${rule} finding(s) omitted`,
        path: LOG_PATH,
        truncated: true,
      };
      (listName === 'findings' ? this.findings : this.warnings).push(item);
    }
  }
}

function loadArtifactManifest(storeDir, ref, limits, cache) {
  const cached = cache.get(ref.ref);
  if (cached !== undefined) return cached;
  let result;
  try {
    if (ref.type === 'dataset') {
      const manifest = store.loadDatasetManifest(storeDir, ref.name, ref.version, { limits });
      result = { hash: manifest.merkle_root.replace(/^sha256:/, '') };
    } else if (ref.type === 'model') {
      const manifest = store.loadModelManifest(storeDir, ref.name, ref.version, { limits });
      result = { hash: manifest.sha256 };
    } else if (ref.type === 'pipeline') {
      const manifest = store.loadPipelineManifest(storeDir, ref.name, ref.version, { limits });
      result = { hash: manifest.pipeline_id.replace(/^sha256:/, '') };
    } else {
      result = { skipped: true };
    }
  } catch (err) {
    result = { error: err.message };
  }
  cache.set(ref.ref, result);
  return result;
}

function readLogText(storeDir, options = {}) {
  if (typeof storeDir !== 'string' || storeDir.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'storeDir must be a non-empty string');
  }
  const limits = resolveLimits(options.limits);
  const logPath = store.provenanceLogPath(storeDir);
  if (!fs.existsSync(logPath)) return { exists: false, text: '', size: 0 };
  return store.withLogLock(
    storeDir,
    () => store.readProvenanceText(storeDir, { limits }),
    lockOptionsFrom(options)
  );
}

function verifyProvenance(options = {}) {
  const storeDir = options.storeDir;
  if (typeof storeDir !== 'string' || storeDir.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'storeDir must be a non-empty string');
  }
  const limits = resolveLimits(options.limits);
  const sink = new FindingSink();

  let expectedHead = null;
  let expectedHeadProvided = false;
  if (typeof options.expectedHead === 'string' && options.expectedHead.length > 0) {
    expectedHead = options.expectedHead.trim();
    expectedHeadProvided = true;
  } else if (typeof options.anchorFilePath === 'string' && options.anchorFilePath.length > 0) {
    try {
      expectedHead = fs.readFileSync(options.anchorFilePath, 'utf8').trim();
    } catch (err) {
      throw new VgError(ERROR_CODES.VG_UNREADABLE, 'cannot read anchor file', {
        reason: err.code || 'UNKNOWN',
      });
    }
    expectedHeadProvided = true;
  }

  const log = readLogText(storeDir, options);
  const base = {
    schema_version: SCHEMA_VERSION,
    kind: KIND,
    checked_at: toIso(options.now),
    status: 'NOT_CHECKED',
    record_count: 0,
    malformed_count: 0,
    unsigned_count: 0,
    head: null,
    anchored: null,
    expected_head: expectedHeadProvided ? expectedHead : null,
    findings: sink.findings,
    warnings: sink.warnings,
  };

  if (!log.exists || log.text.trim().length === 0) {
    sink.finalize();
    return base;
  }

  const lines = splitLogLines(log.text);
  const entries = [];
  const firstLineByHash = new Map();
  let previousValid = true;
  let previousHash = null;
  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const raw = lines[i];
    if (raw.trim().length === 0) {
      sink.finding('VG-PROV-001', `line ${lineNumber} is empty`, { line: lineNumber });
      previousValid = false;
      previousHash = null;
      continue;
    }
    let value;
    try {
      value = parseCanonical(raw, { maxBytes: limits.maxManifestBytes });
    } catch (err) {
      sink.finding('VG-PROV-001', `line ${lineNumber} is not valid canonical JSON: ${err.message}`, {
        line: lineNumber,
      });
      previousValid = false;
      previousHash = null;
      continue;
    }
    try {
      validateRecord(value, { limits });
    } catch (err) {
      sink.finding('VG-PROV-001', `line ${lineNumber} is invalid: ${err.message}`, {
        line: lineNumber,
        code: err.code,
      });
      previousValid = false;
      previousHash = null;
      continue;
    }
    if (previousValid && value.prev_record_hash !== previousHash) {
      sink.finding('VG-PROV-001', `line ${lineNumber} prev_record_hash does not match the previous record`, {
        line: lineNumber,
        expected: previousHash,
        actual: value.prev_record_hash,
      });
    }
    previousValid = true;
    previousHash = value.record_hash;
    if (!firstLineByHash.has(value.record_hash)) firstLineByHash.set(value.record_hash, lineNumber);
    entries.push({ lineNumber, record: value });
  }

  const indexByHash = new Map();
  for (const entry of entries) {
    if (!indexByHash.has(entry.record.record_hash)) indexByHash.set(entry.record.record_hash, entry);
  }

  for (const entry of entries) {
    const first = firstLineByHash.get(entry.record.record_hash);
    if (first !== entry.lineNumber) {
      sink.finding('VG-PROV-006', `record ${entry.record.record_hash} appears more than once (replay)`, {
        line: entry.lineNumber,
        first_line: first,
        record_hash: entry.record.record_hash,
      });
    }
  }

  for (const entry of entries) {
    const record = entry.record;
    for (const parent of record.parent_record_hashes) {
      if (parent === record.record_hash) {
        sink.finding('VG-PROV-007', `line ${entry.lineNumber} is its own parent`, {
          line: entry.lineNumber,
          record_hash: record.record_hash,
        });
        continue;
      }
      const parentEntry = indexByHash.get(parent);
      if (!parentEntry) {
        sink.finding('VG-PROV-005', `line ${entry.lineNumber} references a missing parent`, {
          line: entry.lineNumber,
          parent,
        });
        continue;
      }
      if (firstLineByHash.get(parent) > entry.lineNumber) {
        sink.finding('VG-PROV-007', `line ${entry.lineNumber} references a later record as parent`, {
          line: entry.lineNumber,
          parent,
          parent_line: parentEntry.lineNumber,
        });
      }
    }
  }

  const keyCache = new Map();
  const resolveKey = (contributor, keyId) => {
    const cacheKey = `${contributor}|${keyId}`;
    if (keyCache.has(cacheKey)) return keyCache.get(cacheKey);
    let result;
    try {
      const record = keys.loadPublicKey(storeDir, contributor, keyId, { limits });
      const der = Buffer.from(record.public_key_der_b64, 'base64');
      result = { ok: true, record, der };
    } catch (err) {
      result = { ok: false, reason: err.message, code: err.code };
    }
    keyCache.set(cacheKey, result);
    return result;
  };

  const unsignedLines = [];
  const registeredContributors = new Set();
  const pinnedKeys = new Map();
  for (const entry of entries) {
    if (entry.record.kind === 'contributor_registered') {
      registeredContributors.add(entry.record.actor.contributor);
      if (!pinnedKeys.has(entry.record.actor.contributor)) {
        pinnedKeys.set(entry.record.actor.contributor, new Set());
      }
      pinnedKeys.get(entry.record.actor.contributor).add(entry.record.key_id);
    }
  }

  for (const entry of entries) {
    const record = entry.record;
    if (record.signature === undefined || record.signature === null) {
      unsignedLines.push(entry.lineNumber);
      continue;
    }
    const resolved = resolveKey(record.actor.contributor, record.actor.key_id);
    if (!resolved.ok) {
      sink.finding('VG-PROV-003', `line ${entry.lineNumber} signer is not trusted: ${resolved.reason}`, {
        line: entry.lineNumber,
        contributor: record.actor.contributor,
        key_id: record.actor.key_id,
      });
      continue;
    }
    const pinned = pinnedKeys.get(record.actor.contributor);
    if (pinned && !pinned.has(record.actor.key_id)) {
      sink.finding(
        'VG-PROV-003',
        `line ${entry.lineNumber} key is not pinned by a contributor_registered record`,
        { line: entry.lineNumber, contributor: record.actor.contributor, key_id: record.actor.key_id }
      );
      continue;
    }
    if (resolved.record.status === 'revoked') {
      sink.finding('VG-PROV-004', `line ${entry.lineNumber} signed by a revoked key`, {
        line: entry.lineNumber,
        contributor: record.actor.contributor,
        key_id: record.actor.key_id,
      });
      continue;
    }
    if (!keys.verifySignature(resolved.der, record.record_hash, record.signature)) {
      sink.finding('VG-PROV-002', `line ${entry.lineNumber} signature does not verify`, {
        line: entry.lineNumber,
        contributor: record.actor.contributor,
        key_id: record.actor.key_id,
      });
      continue;
    }
    if (record.kind === 'operation_recorded' && !resolved.record.operations.includes(record.operation)) {
      sink.finding(
        'VG-PROV-004',
        `line ${entry.lineNumber} operation "${record.operation}" is not authorized for this key`,
        { line: entry.lineNumber, operation: record.operation, operations: resolved.record.operations }
      );
      continue;
    }
    if (record.kind === 'contributor_registered') {
      if (record.public_key_der_b64 !== resolved.record.public_key_der_b64) {
        sink.finding(
          'VG-PROV-003',
          `line ${entry.lineNumber} registered public key does not match the key registry`,
          { line: entry.lineNumber, contributor: record.actor.contributor }
        );
        continue;
      }
      if (record.operations.join(',') !== resolved.record.operations.join(',')) {
        sink.warning(
          'VG-PROV-W003',
          `line ${entry.lineNumber} registered operations differ from the key registry`,
          {
            line: entry.lineNumber,
            record_operations: record.operations,
            key_operations: resolved.record.operations,
          }
        );
      }
    }
    if (!registeredContributors.has(record.actor.contributor)) {
      sink.warning(
        'VG-PROV-W004',
        `line ${entry.lineNumber} signed by "${record.actor.contributor}" with no contributor_registered record`,
        { line: entry.lineNumber, contributor: record.actor.contributor }
      );
    }
  }

  const manifestCache = new Map();
  for (const entry of entries) {
    const record = entry.record;
    for (const group of [record.inputs, record.outputs]) {
      for (const item of group) {
        const ref = parseArtifactRef(item.artifact);
        if (!ref) continue;
        if (ref.type !== 'dataset' && ref.type !== 'model' && ref.type !== 'pipeline') continue;
        const loaded = loadArtifactManifest(storeDir, ref, limits, manifestCache);
        if (loaded.skipped) continue;
        if (loaded.error) {
          sink.warning(
            'VG-PROV-W002',
            `line ${entry.lineNumber} references unverifiable artifact "${ref.ref}": ${loaded.error}`,
            { line: entry.lineNumber, artifact: ref.ref }
          );
          continue;
        }
        if (loaded.hash !== item.sha256) {
          sink.finding(
            'VG-PROV-011',
            `line ${entry.lineNumber} hash for "${ref.ref}" does not match its registration`,
            { line: entry.lineNumber, artifact: ref.ref, expected: loaded.hash, actual: item.sha256 }
          );
        }
      }
    }
  }

  const registeredHashes = new Map();
  for (const entry of entries) {
    if (entry.record.kind !== 'artifact_registered') continue;
    for (const item of entry.record.outputs) {
      const ref = parseArtifactRef(item.artifact);
      if (!ref) continue;
      if (!registeredHashes.has(ref.ref)) registeredHashes.set(ref.ref, new Map());
      const byHash = registeredHashes.get(ref.ref);
      if (!byHash.has(item.sha256)) byHash.set(item.sha256, []);
      byHash.get(item.sha256).push(entry.lineNumber);
    }
  }
  for (const [refText, byHash] of registeredHashes) {
    if (byHash.size > 1) {
      const hashes = [...byHash.keys()];
      const linesFor = [];
      for (const lineNumbers of byHash.values()) linesFor.push(...lineNumbers);
      sink.finding('VG-PROV-010', `artifact "${refText}" has conflicting registered hashes`, {
        artifact: refText,
        hashes,
        lines: linesFor,
      });
    }
  }

  for (const entry of entries) {
    if (entry.record.parent_record_hashes.length === 0) continue;
    let latestParent = null;
    for (const parent of entry.record.parent_record_hashes) {
      const parentEntry = indexByHash.get(parent);
      if (!parentEntry) continue;
      if (firstLineByHash.get(parent) >= entry.lineNumber) continue;
      if (latestParent === null || parentEntry.record.timestamp > latestParent) {
        latestParent = parentEntry.record.timestamp;
      }
    }
    if (latestParent !== null && entry.record.timestamp < latestParent) {
      sink.warning('VG-PROV-W001', `line ${entry.lineNumber} timestamp is earlier than a parent timestamp`, {
        line: entry.lineNumber,
        timestamp: entry.record.timestamp,
        parent_timestamp: latestParent,
      });
    }
  }

  const head = entries.length > 0 ? entries[entries.length - 1].record.record_hash : null;
  base.record_count = entries.length;
  base.malformed_count = lines.length - entries.length;
  base.unsigned_count = unsignedLines.length;
  base.head = head;

  if (unsignedLines.length > 0) {
    sink.finding('VG-PROV-009', `${unsignedLines.length} record(s) are unsigned`, {
      lines: unsignedLines.slice(0, 10),
      count: unsignedLines.length,
    });
  }

  let anchored = null;
  if (expectedHeadProvided) {
    anchored = head !== null && head === expectedHead;
    if (!anchored) {
      sink.finding('VG-PROV-008', 'log head does not match the expected anchor', {
        expected: expectedHead,
        actual: head,
      });
    }
  }
  base.anchored = anchored;

  const hasBlockers = sink.findings.some((finding) => finding.severity === 'BLOCKER');
  if (hasBlockers) base.status = 'FAIL';
  else if (entries.length === 0) base.status = 'NOT_CHECKED';
  else if (unsignedLines.length > 0) base.status = 'UNSIGNED';
  else if (anchored === true) base.status = 'PASS';
  else if (anchored === false) base.status = 'FAIL';
  else base.status = 'UNANCHORED';

  sink.finalize();
  return base;
}

module.exports = {
  SCHEMA_VERSION,
  KIND,
  RECORD_KINDS,
  MAX_ARTIFACT_REFS,
  PROV_FINDING_SEVERITY,
  WARNING_RULES,
  parseArtifactRef,
  validateRecord,
  buildRecord,
  parseProvenanceLog,
  readLogText,
  resolveSigner,
  appendRecord,
  registerContributor,
  recordOperation,
  recordArtifact,
  verifyProvenance,
};
