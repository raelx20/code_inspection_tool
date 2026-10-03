'use strict';

const crypto = require('node:crypto');
const { ERROR_CODES, VgError } = require('./errors');

const DEFAULT_MAX_DEPTH = 32;
const DEFAULT_MAX_PARSE_BYTES = 8 * 1024 * 1024;
const RECORD_HASH_FIELD = 'record_hash';
const RECORD_ID_FIELD = 'record_id';
const SIGNATURE_FIELD = 'signature';
const FORBIDDEN_KEYS = new Set(['__proto__']);
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function canonicalInvalid(message, details) {
  return new VgError(ERROR_CODES.VG_CANONICAL_INVALID, message, details || {});
}

function malformed(message, details) {
  return new VgError(ERROR_CODES.VG_MANIFEST_MALFORMED, message, details || {});
}

function assertWellFormedString(value) {
  if (LONE_SURROGATE_RE.test(value)) {
    throw canonicalInvalid('string contains an unpaired surrogate');
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function encode(value, depth, maxDepth) {
  if (depth > maxDepth) {
    throw canonicalInvalid(`maximum nesting depth of ${maxDepth} exceeded`, { maxDepth });
  }
  if (value === null) return 'null';

  const type = typeof value;
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') {
    if (!Number.isFinite(value)) throw canonicalInvalid('NaN and Infinity are not permitted');
    if (!Number.isSafeInteger(value)) {
      throw canonicalInvalid('only safe integers are permitted in hashed positions', { value });
    }
    return String(value === 0 ? 0 : value);
  }
  if (type === 'string') {
    assertWellFormedString(value);
    return JSON.stringify(value);
  }
  if (type !== 'object') {
    throw canonicalInvalid(`values of type ${type} cannot be canonicalized`, { type });
  }

  if (Array.isArray(value)) {
    const parts = [];
    for (let i = 0; i < value.length; i++) {
      if (!(i in value)) throw canonicalInvalid('sparse arrays are not permitted');
      parts.push(encode(value[i], depth + 1, maxDepth));
    }
    return `[${parts.join(',')}]`;
  }

  if (!isPlainObject(value)) {
    throw canonicalInvalid('only plain objects can be canonicalized');
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw canonicalInvalid('symbol keys are not permitted');
  }

  const keys = Object.keys(value).sort();
  const parts = [];
  for (const key of keys) {
    assertWellFormedString(key);
    if (FORBIDDEN_KEYS.has(key)) throw canonicalInvalid(`forbidden key "${key}"`);
    const child = value[key];
    if (child === undefined) {
      throw canonicalInvalid(`undefined value for key "${key}"`, { key });
    }
    parts.push(`${JSON.stringify(key)}:${encode(child, depth + 1, maxDepth)}`);
  }
  return `{${parts.join(',')}}`;
}

function canonicalJson(value, options = {}) {
  const maxDepth = Number.isInteger(options.maxDepth) && options.maxDepth > 0
    ? options.maxDepth
    : DEFAULT_MAX_DEPTH;
  return encode(value, 0, maxDepth);
}

function parseCanonical(text, options = {}) {
  const maxBytes = Number.isInteger(options.maxBytes) && options.maxBytes > 0
    ? options.maxBytes
    : DEFAULT_MAX_PARSE_BYTES;
  const maxDepth = Number.isInteger(options.maxDepth) && options.maxDepth > 0
    ? options.maxDepth
    : DEFAULT_MAX_DEPTH;

  if (typeof text !== 'string') {
    throw malformed('input must be a string');
  }
  const byteLength = Buffer.byteLength(text, 'utf8');
  if (byteLength > maxBytes) {
    throw malformed(`input of ${byteLength} bytes exceeds the ${maxBytes} byte limit`, {
      byteLength,
      maxBytes,
    });
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch (err) {
    throw malformed(`invalid JSON: ${err.message}`);
  }

  encode(value, 0, maxDepth);
  return value;
}

function hashRecord(record, options = {}) {
  if (!isPlainObject(record)) {
    throw canonicalInvalid('record must be a plain object');
  }
  const body = Object.create(null);
  for (const key of Object.keys(record)) {
    if (key === RECORD_HASH_FIELD || key === RECORD_ID_FIELD || key === SIGNATURE_FIELD) continue;
    Object.defineProperty(body, key, {
      value: record[key],
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  const serialized = encode(body, 0, options.maxDepth || DEFAULT_MAX_DEPTH);
  const digest = crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
  return `sha256:${digest}`;
}

function canonicalDigest(value, options = {}) {
  const serialized = canonicalJson(value, options);
  return crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
}

module.exports = {
  canonicalJson,
  parseCanonical,
  hashRecord,
  canonicalDigest,
  isPlainObject,
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_PARSE_BYTES,
  RECORD_HASH_FIELD,
  RECORD_ID_FIELD,
  SIGNATURE_FIELD,
};
