'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { ERROR_CODES, VgError } = require('./errors');
const { parseCanonical, hashRecord, isPlainObject } = require('./canonical');
const { resolveLimits } = require('./limits');
const { assertLabel, toIso, TIMESTAMP_RE, RECORD_HASH_RE } = require('./manifest');
const { saveManifestTo, readManifestText } = require('./store');

const SCHEMA_VERSION = '1.0';
const KIND = 'public_key';
const ALGORITHM = 'ed25519';
const KEY_ID_RE = /^[0-9a-f]{32}$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const OPERATIONS = Object.freeze([
  'curate_dataset',
  'preprocess',
  'train',
  'export_model',
  'infer',
]);
const STATUSES = Object.freeze(['active', 'revoked']);
const KNOWN_KEYS = new Set([
  'schema_version',
  'kind',
  'contributor',
  'key_id',
  'algorithm',
  'public_key_der_b64',
  'operations',
  'status',
  'created_at',
  'record_hash',
  'signature',
]);

function keySchemaError(message, details) {
  return new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, message, details || {});
}

function defaultKeyDir() {
  return path.join(os.homedir(), '.codesentry', 'visionguard', 'keys');
}

function keyIdFromDer(der) {
  if (!Buffer.isBuffer(der) && !(der instanceof Uint8Array)) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'public key DER must be a Buffer');
  }
  return crypto.createHash('sha256').update(der).digest('hex').slice(0, 32);
}

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync(ALGORITHM);
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const privateKeyDer = privateKey.export({ type: 'pkcs8', format: 'der' });
  return {
    publicKey,
    privateKey,
    publicKeyDer,
    privateKeyDer,
    keyId: keyIdFromDer(publicKeyDer),
  };
}

function assertKeyId(keyId, field = 'key_id') {
  if (typeof keyId !== 'string' || !KEY_ID_RE.test(keyId)) {
    throw keySchemaError(`${field} must be 32 lowercase hex characters`, { field });
  }
}

function privateKeyPath(keyDir, contributor, keyId) {
  assertLabel(contributor, 'contributor');
  assertKeyId(keyId);
  return path.join(keyDir, contributor, `${keyId}.key`);
}

function savePrivateKey(keyDir, contributor, keyId, privateKeyDer, options = {}) {
  const filePath = privateKeyPath(keyDir, contributor, keyId);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const body = `${Buffer.from(privateKeyDer).toString('base64')}\n`;
  try {
    fs.writeFileSync(filePath, body, { flag: 'wx', mode: options.mode === undefined ? 0o600 : options.mode });
  } catch (err) {
    if (err.code === 'EEXIST') {
      throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, 'private key file already exists', {
        contributor,
        key_id: keyId,
      });
    }
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `cannot write private key: ${err.code || err.message}`, {
      reason: err.code || 'UNKNOWN',
    });
  }
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
  }
  return filePath;
}

function loadPrivateKey(filePath) {
  let text;
  try {
    text = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, `cannot read private key file: ${err.code || err.message}`, {
      reason: err.code || 'UNKNOWN',
    });
  }
  const trimmed = text.replace(/\s+/g, '');
  if (trimmed.length === 0 || !BASE64_RE.test(trimmed)) {
    throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, 'private key file must contain base64 PKCS#8 DER', {});
  }
  const der = Buffer.from(trimmed, 'base64');
  let key;
  try {
    key = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } catch (err) {
    throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, 'private key file is not a valid PKCS#8 key', {
      reason: err.message,
    });
  }
  if (key.asymmetricKeyType !== ALGORITHM) {
    throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, `private key must be ${ALGORITHM}`, {
      actual: key.asymmetricKeyType,
    });
  }
  return key;
}

function publicKeyObjectFromDer(der) {
  try {
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== ALGORITHM) return null;
    return key;
  } catch {
    return null;
  }
}

function signRecordHash(privateKey, recordHash) {
  if (typeof recordHash !== 'string' || !RECORD_HASH_RE.test(recordHash)) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'recordHash must be a sha256: hex digest');
  }
  const signature = crypto.sign(null, Buffer.from(recordHash, 'utf8'), privateKey);
  return signature.toString('base64');
}

function verifySignature(publicKeyDer, recordHash, signature) {
  if (!Buffer.isBuffer(publicKeyDer) && !(publicKeyDer instanceof Uint8Array)) return false;
  if (typeof recordHash !== 'string' || !RECORD_HASH_RE.test(recordHash)) return false;
  if (typeof signature !== 'string' || !BASE64_RE.test(signature)) return false;
  const sig = Buffer.from(signature, 'base64');
  if (sig.length !== 64) return false;
  const key = publicKeyObjectFromDer(publicKeyDer);
  if (!key) return false;
  try {
    return crypto.verify(null, Buffer.from(recordHash, 'utf8'), key, sig);
  } catch {
    return false;
  }
}

function buildPublicKeyRecord(options) {
  const contributor = options.contributor;
  assertLabel(contributor, 'contributor');
  const publicKeyDer = options.publicKeyDer;
  if (!Buffer.isBuffer(publicKeyDer)) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'publicKeyDer must be a Buffer');
  }
  const operations = Array.isArray(options.operations) ? [...options.operations] : [];
  const record = {
    schema_version: SCHEMA_VERSION,
    kind: KIND,
    contributor,
    key_id: keyIdFromDer(publicKeyDer),
    algorithm: ALGORITHM,
    public_key_der_b64: publicKeyDer.toString('base64'),
    operations,
    status: options.status === 'revoked' ? 'revoked' : 'active',
    created_at: toIso(options.now),
  };
  record.record_hash = hashRecord(record);
  const status = record.status;
  if (options.privateKey) {
    record.signature = signRecordHash(options.privateKey, record.record_hash);
  } else if (status === 'active') {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'privateKey is required to self-sign an active key record', {
      contributor,
    });
  } else {
    record.signature = null;
  }
  return record;
}

function validatePublicKeyRecord(value, options = {}) {
  if (!isPlainObject(value)) throw keySchemaError('public key record must be a plain JSON object');
  if (options.strict === true) {
    for (const key of Object.keys(value)) {
      if (!KNOWN_KEYS.has(key)) throw keySchemaError(`unknown field "${key}"`, { field: key });
    }
  }
  if (typeof value.schema_version !== 'string') {
    throw keySchemaError('schema_version must be a string', { field: 'schema_version' });
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
  if (value.kind !== KIND) throw keySchemaError(`kind must be "${KIND}"`, { field: 'kind' });
  if (value.algorithm !== ALGORITHM) {
    throw keySchemaError(`algorithm must be "${ALGORITHM}"`, { field: 'algorithm' });
  }
  assertLabel(value.contributor, 'contributor');
  assertKeyId(value.key_id);
  if (typeof value.created_at !== 'string' || !TIMESTAMP_RE.test(value.created_at)) {
    throw keySchemaError('created_at must be an RFC 3339 UTC timestamp with milliseconds', {
      field: 'created_at',
    });
  }
  if (typeof value.public_key_der_b64 !== 'string' || !BASE64_RE.test(value.public_key_der_b64)) {
    throw keySchemaError('public_key_der_b64 must be base64', { field: 'public_key_der_b64' });
  }
  const der = Buffer.from(value.public_key_der_b64, 'base64');
  const key = publicKeyObjectFromDer(der);
  if (!key) {
    throw keySchemaError('public_key_der_b64 must decode to a valid ed25519 SPKI key', {
      field: 'public_key_der_b64',
    });
  }
  const derivedKeyId = keyIdFromDer(der);
  if (derivedKeyId !== value.key_id) {
    throw keySchemaError('key_id does not match the public key DER', {
      field: 'key_id',
      expected: derivedKeyId,
      actual: value.key_id,
    });
  }
  if (!Array.isArray(value.operations)) {
    throw keySchemaError('operations must be an array', { field: 'operations' });
  }
  const seen = new Set();
  for (const op of value.operations) {
    if (typeof op !== 'string' || !OPERATIONS.includes(op)) {
      throw keySchemaError(`unsupported operation "${String(op)}"`, { field: 'operations' });
    }
    if (seen.has(op)) throw keySchemaError(`duplicate operation "${op}"`, { field: 'operations' });
    seen.add(op);
  }
  if (typeof value.status !== 'string' || !STATUSES.includes(value.status)) {
    throw keySchemaError('status must be "active" or "revoked"', { field: 'status' });
  }
  if (typeof value.record_hash !== 'string' || !RECORD_HASH_RE.test(value.record_hash)) {
    throw keySchemaError('record_hash must be a sha256 hex digest', { field: 'record_hash' });
  }
  if (hashRecord(value) !== value.record_hash) {
    throw new VgError(ERROR_CODES.VG_MANIFEST_HASH_MISMATCH, 'public key record_hash mismatch', {
      contributor: value.contributor,
      key_id: value.key_id,
      expected: hashRecord(value),
      actual: value.record_hash,
    });
  }
  if (value.signature === null || value.signature === undefined) {
    if (value.status !== 'revoked') {
      throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, 'public key record is not signed', {
        contributor: value.contributor,
        key_id: value.key_id,
      });
    }
    return value;
  }
  if (typeof value.signature !== 'string' || !BASE64_RE.test(value.signature)) {
    throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, 'public key record signature is malformed', {
      contributor: value.contributor,
      key_id: value.key_id,
    });
  }
  if (options.verifySignature !== false && !verifySignature(der, value.record_hash, value.signature)) {
    throw new VgError(ERROR_CODES.VG_KEY_UNKNOWN, 'public key record signature is invalid', {
      contributor: value.contributor,
      key_id: value.key_id,
    });
  }
  return value;
}

function publicKeyPath(storeDir, contributor, keyId) {
  assertLabel(contributor, 'contributor');
  assertKeyId(keyId);
  return path.join(storeDir, 'keys', contributor, `${keyId}.pub.json`);
}

function savePublicKey(storeDir, record, options = {}) {
  const limits = resolveLimits(options.limits);
  validatePublicKeyRecord(record, { verifySignature: true });
  return saveManifestTo(publicKeyPath(storeDir, record.contributor, record.key_id), record, limits);
}

function loadPublicKey(storeDir, contributor, keyId, options = {}) {
  const limits = resolveLimits(options.limits);
  const filePath = publicKeyPath(storeDir, contributor, keyId);
  const text = readManifestText(filePath, limits, 'public key', `${contributor}/${keyId}`, {
    contributor,
    key_id: keyId,
  });
  const value = parseCanonical(text, { maxBytes: limits.maxManifestBytes });
  return validatePublicKeyRecord(value, { verifySignature: true, strict: options.strict === true });
}

module.exports = {
  SCHEMA_VERSION,
  KIND,
  ALGORITHM,
  KEY_ID_RE,
  OPERATIONS,
  STATUSES,
  defaultKeyDir,
  keyIdFromDer,
  generateKeyPair,
  privateKeyPath,
  savePrivateKey,
  loadPrivateKey,
  publicKeyObjectFromDer,
  signRecordHash,
  verifySignature,
  buildPublicKeyRecord,
  validatePublicKeyRecord,
  publicKeyPath,
  savePublicKey,
  loadPublicKey,
};
