'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ERROR_CODES, VgError } = require('./errors');

const DEFAULT_MAX_PATH_BYTES = 4096;
const DEFAULT_MAX_COMPONENT_BYTES = 255;
const DRIVE_LETTER_RE = /^[A-Za-z]:/;
const SEPARATORS_RE = /[/\\]/;

function pathInvalid(message, details) {
  return new VgError(ERROR_CODES.VG_PATH_INVALID, message, details || {});
}

function hasNulByte(value) {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) === 0) return true;
  }
  return false;
}

function hasControlChars(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function hasBidiControls(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069) ||
      code === 0x200e ||
      code === 0x200f
    ) {
      return true;
    }
  }
  return false;
}

function hasLoneSurrogate(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return true;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function normalizeRelPath(input, options = {}) {
  const maxPathBytes = Number.isInteger(options.maxPathBytes) && options.maxPathBytes > 0
    ? options.maxPathBytes
    : DEFAULT_MAX_PATH_BYTES;
  const maxComponentBytes = Number.isInteger(options.maxComponentBytes) && options.maxComponentBytes > 0
    ? options.maxComponentBytes
    : DEFAULT_MAX_COMPONENT_BYTES;

  if (typeof input !== 'string' || input.length === 0) {
    throw pathInvalid('path must be a non-empty string');
  }
  if (hasNulByte(input)) {
    throw new VgError(ERROR_CODES.VG_PATH_NUL, 'path contains a NUL byte');
  }
  if (hasControlChars(input)) {
    throw pathInvalid('path contains control characters');
  }
  if (hasBidiControls(input)) {
    throw pathInvalid('path contains bidirectional override characters');
  }
  if (hasLoneSurrogate(input)) {
    throw pathInvalid('path contains an unpaired surrogate');
  }
  if (path.isAbsolute(input) || input.startsWith('/') || input.startsWith('\\') || DRIVE_LETTER_RE.test(input)) {
    throw new VgError(ERROR_CODES.VG_PATH_ABSOLUTE, 'path must be relative to the artifact root');
  }

  const rawSegments = input.split(SEPARATORS_RE);
  const segments = [];
  for (const raw of rawSegments) {
    if (raw === '') {
      throw pathInvalid('path contains an empty segment');
    }
    if (raw === '.') {
      continue;
    }
    if (raw === '..') {
      throw new VgError(ERROR_CODES.VG_PATH_TRAVERSAL, 'path contains a ".." segment', { path: input });
    }
    const segment = raw.normalize('NFC');
    if (Buffer.byteLength(segment, 'utf8') > maxComponentBytes) {
      throw new VgError(ERROR_CODES.VG_PATH_TOO_LONG, 'path segment exceeds the component length limit', {
        maxComponentBytes,
      });
    }
    segments.push(segment);
  }

  if (segments.length === 0) {
    throw pathInvalid('path does not name an artifact');
  }

  const normalized = segments.join('/');
  if (Buffer.byteLength(normalized, 'utf8') > maxPathBytes) {
    throw new VgError(ERROR_CODES.VG_PATH_TOO_LONG, 'path exceeds the length limit', { maxPathBytes });
  }
  return normalized;
}

function resolveRootReal(root) {
  try {
    return fs.realpathSync(root);
  } catch (err) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `cannot resolve artifact root: ${err.code || err.message}`, {
      reason: err.code || 'UNKNOWN',
    });
  }
}

function assertInsideRoot(rootReal, absPath, displayPath = null) {
  const relative = path.relative(rootReal, absPath);
  const label = displayPath || path.basename(absPath);
  if (relative === '') return '';
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new VgError(ERROR_CODES.VG_PATH_TRAVERSAL, `path escapes the artifact root: ${label}`, {
      path: label,
    });
  }
  return relative;
}

function resolveArtifactPath(root, rootReal, relPath, options = {}) {
  const rel = normalizeRelPath(relPath, options);
  const abs = path.resolve(rootReal, rel);
  assertInsideRoot(rootReal, abs, rel);
  return { rel, abs };
}

function assertNoSymlink(absPath, displayPath = null) {
  const label = displayPath || path.basename(absPath);
  let stats;
  try {
    stats = fs.lstatSync(absPath);
  } catch (err) {
    throw new VgError(ERROR_CODES.VG_UNREADABLE, `file not found: ${label}`, {
      path: label,
      reason: err.code || 'UNKNOWN',
    });
  }
  if (stats.isSymbolicLink()) {
    throw new VgError(ERROR_CODES.VG_SYMLINK_DENIED, `symbolic links are not followed: ${label}`, {
      path: label,
    });
  }
  return stats;
}

function findPathCollisions(paths) {
  if (!Array.isArray(paths)) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'findPathCollisions expects an array');
  }
  const collisions = { nfc: [], caseFold: [] };
  const byNfc = new Map();
  const byFold = new Map();
  const reportedPairs = new Set();

  for (const original of paths) {
    if (typeof original !== 'string') {
      throw new VgError(ERROR_CODES.VG_INTERNAL, 'path collision check expects string paths');
    }
    const nfc = original.normalize('NFC');

    const seenNfc = byNfc.get(nfc);
    if (seenNfc !== undefined && seenNfc !== original) {
      collisions.nfc.push([seenNfc, original]);
      reportedPairs.add(pairKey(seenNfc, original));
    } else if (seenNfc === undefined) {
      byNfc.set(nfc, original);
    }

    const fold = nfc.toLowerCase();
    const seenFold = byFold.get(fold);
    if (seenFold !== undefined && seenFold !== original) {
      const key = pairKey(seenFold, original);
      if (!reportedPairs.has(key)) {
        collisions.caseFold.push([seenFold, original]);
        reportedPairs.add(key);
      }
    } else if (seenFold === undefined) {
      byFold.set(fold, original);
    }
  }

  return collisions;
}

function pairKey(a, b) {
  return a < b ? `${a} ${b}` : `${b} ${a}`;
}

module.exports = {
  normalizeRelPath,
  resolveRootReal,
  assertInsideRoot,
  resolveArtifactPath,
  assertNoSymlink,
  findPathCollisions,
  hasNulByte,
  hasControlChars,
  hasBidiControls,
  hasLoneSurrogate,
  DEFAULT_MAX_PATH_BYTES,
  DEFAULT_MAX_COMPONENT_BYTES,
};
