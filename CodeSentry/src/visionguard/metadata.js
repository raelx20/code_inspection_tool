'use strict';

const { ERROR_CODES, VgError } = require('./errors');
const { isPlainObject, canonicalJson } = require('./canonical');
const { assertMetadataBytes } = require('./limits');

const METADATA_MAX_DEPTH = 6;

function metadataDepth(value, depth) {
  if (Array.isArray(value)) {
    let deepest = depth;
    for (const item of value) {
      if (Array.isArray(item) || isPlainObject(item)) {
        const childDepth = metadataDepth(item, depth + 1);
        if (childDepth > deepest) deepest = childDepth;
      }
    }
    return deepest;
  }
  if (!isPlainObject(value)) return depth;
  let deepest = depth;
  for (const key of Object.keys(value)) {
    const child = value[key];
    if (Array.isArray(child) || isPlainObject(child)) {
      const childDepth = metadataDepth(child, depth + 1);
      if (childDepth > deepest) deepest = childDepth;
    }
  }
  return deepest;
}

function assertMetadata(metadata, limits) {
  if (!isPlainObject(metadata)) {
    throw new VgError(
      ERROR_CODES.VG_MANIFEST_SCHEMA,
      'metadata must be a plain JSON object',
      { field: 'metadata' }
    );
  }
  const depth = metadataDepth(metadata, 1);
  if (depth > METADATA_MAX_DEPTH) {
    throw new VgError(
      ERROR_CODES.VG_LIMIT_METADATA,
      `metadata nesting depth ${depth} exceeds the limit of ${METADATA_MAX_DEPTH}`,
      { depth, maxDepth: METADATA_MAX_DEPTH }
    );
  }
  const byteLength = Buffer.byteLength(canonicalJson(metadata), 'utf8');
  assertMetadataBytes(byteLength, limits);
  return metadata;
}

module.exports = {
  METADATA_MAX_DEPTH,
  metadataDepth,
  assertMetadata,
};
