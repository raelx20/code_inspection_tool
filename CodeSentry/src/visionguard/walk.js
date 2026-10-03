'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ERROR_CODES, VgError } = require('./errors');
const { hashFile } = require('./hash');
const { normalizeRelPath, resolveRootReal, findPathCollisions } = require('./paths');
const {
  resolveLimits,
  assertFileCount,
  assertDirCount,
  assertFileSize,
  assertTotalBytes,
  assertDepth,
} = require('./limits');

const MAX_FINDINGS_PER_RULE = 100;
const EXTENSION_RE = /^\.[A-Za-z0-9][A-Za-z0-9-]*$/;
const EXTENSION_EXCLUDE_RULE = 'VG-DATA-012';

const FINDING_SEVERITY = Object.freeze({
  'VG-DATA-001': 'BLOCKER',
  'VG-DATA-002': 'BLOCKER',
  'VG-DATA-003': 'BLOCKER',
  'VG-DATA-004': 'BLOCKER',
  'VG-DATA-005': 'HIGH',
  'VG-DATA-006': 'BLOCKER',
  'VG-DATA-007': 'BLOCKER',
  'VG-DATA-008': 'HIGH',
  'VG-DATA-009': 'HIGH',
  'VG-DATA-010': 'INFO',
  'VG-DATA-011': 'INFO',
  'VG-DATA-012': 'INFO',
});

const DEFAULT_POLICY = Object.freeze({
  extensions: Object.freeze(['*']),
  allowSymlinks: false,
  maxFileSize: null,
});

function schemaError(message, details) {
  return new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, message, details || {});
}

function normalizePolicy(policy) {
  if (policy === undefined || policy === null) return DEFAULT_POLICY;
  if (typeof policy !== 'object' || Array.isArray(policy)) {
    throw schemaError('policy must be an object');
  }
  const known = new Set(['extensions', 'allowSymlinks', 'maxFileSize']);
  for (const key of Object.keys(policy)) {
    if (!known.has(key)) throw schemaError(`unknown policy field "${key}"`, { key });
  }

  let extensions = ['*'];
  if (policy.extensions !== undefined) {
    if (!Array.isArray(policy.extensions) || policy.extensions.length === 0) {
      throw schemaError('policy.extensions must be a non-empty array');
    }
    if (policy.extensions.includes('*')) {
      if (policy.extensions.length !== 1) {
        throw schemaError('policy.extensions "*" cannot be combined with other extensions');
      }
      extensions = ['*'];
    } else {
      const seen = new Set();
      for (const ext of policy.extensions) {
        if (typeof ext !== 'string' || !EXTENSION_RE.test(ext)) {
          throw schemaError(`invalid extension "${String(ext)}"`, { extension: String(ext) });
        }
        const lower = ext.toLowerCase();
        if (!seen.has(lower)) seen.add(lower);
      }
      extensions = [...seen].sort();
    }
  }

  if (policy.allowSymlinks !== undefined) {
    if (typeof policy.allowSymlinks !== 'boolean') {
      throw schemaError('policy.allowSymlinks must be a boolean');
    }
    if (policy.allowSymlinks === true) {
      throw schemaError('symlinks are never followed; allowSymlinks must be false');
    }
  }

  let maxFileSize = null;
  if (policy.maxFileSize !== undefined && policy.maxFileSize !== null) {
    if (!Number.isSafeInteger(policy.maxFileSize) || policy.maxFileSize <= 0) {
      throw schemaError('policy.maxFileSize must be a positive integer');
    }
    maxFileSize = policy.maxFileSize;
  }

  return { extensions, allowSymlinks: false, maxFileSize };
}

function extensionAllowed(fileName, extensions) {
  if (extensions[0] === '*') return true;
  const dot = fileName.lastIndexOf('.');
  if (dot <= 0) return false;
  return extensions.includes(fileName.slice(dot).toLowerCase());
}

function compareNames(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function walkDataset(root, options = {}) {
  const limits = resolveLimits(options.limits);
  const policy = normalizePolicy(options.policy);
  const mode = options.mode === 'verify' ? 'verify' : 'register';
  const strict = options.strict === true;
  const realRoot = resolveRootReal(root);
  const effectiveMaxFileSize = policy.maxFileSize === null ? limits.maxFileSize : policy.maxFileSize;

  const entries = [];
  const findings = [];
  const findingCounts = Object.create(null);
  const unreadable = [];
  let fileCount = 0;
  let totalBytes = 0;
  let dirCount = 0;

  function addFinding(rule, findingPath, detail) {
    const count = (findingCounts[rule] || 0) + 1;
    findingCounts[rule] = count;
    if (count <= MAX_FINDINGS_PER_RULE) {
      findings.push({ rule, severity: FINDING_SEVERITY[rule], path: findingPath, detail });
    }
  }

  function handleFileError(err, rel) {
    if (mode === 'register') throw err;
    unreadable.push({ path: rel, code: err.code || ERROR_CODES.VG_INTERNAL, detail: err.message });
  }

  const stack = [{ dir: realRoot, rel: '', depth: 0 }];
  while (stack.length > 0) {
    const frame = stack.pop();
    assertDepth(frame.depth, limits);

    let dirents;
    try {
      dirents = fs.readdirSync(frame.dir, { withFileTypes: true });
    } catch (err) {
      const wrapped = new VgError(ERROR_CODES.VG_UNREADABLE, `cannot read directory: ${frame.rel || '.'}`, {
        path: frame.rel || '.',
        reason: err.code || 'UNKNOWN',
      });
      handleFileError(wrapped, frame.rel || '.');
      continue;
    }
    dirCount += 1;
    assertDirCount(dirCount, limits);
    dirents.sort((a, b) => compareNames(a.name, b.name));

    for (const dirent of dirents) {
      const rel = frame.rel === '' ? dirent.name : `${frame.rel}/${dirent.name}`;
      const abs = path.join(frame.dir, dirent.name);

      if (dirent.name.includes('\\')) {
        handleFileError(
          new VgError(ERROR_CODES.VG_PATH_INVALID, `path contains a backslash: ${rel}`, { path: rel }),
          rel
        );
        continue;
      }

      let normalized;
      try {
        normalized = normalizeRelPath(rel);
      } catch (err) {
        handleFileError(err, rel);
        continue;
      }

      let stats;
      try {
        stats = fs.lstatSync(abs);
      } catch (err) {
        handleFileError(
          new VgError(ERROR_CODES.VG_UNREADABLE, `cannot stat: ${rel}`, {
            path: rel,
            reason: err.code || 'UNKNOWN',
          }),
          rel
        );
        continue;
      }

      if (stats.isSymbolicLink()) {
        if (strict && mode === 'register') {
          throw new VgError(ERROR_CODES.VG_SYMLINK_DENIED, `symbolic links are not followed: ${rel}`, {
            path: rel,
          });
        }
        addFinding('VG-DATA-005', rel, 'symbolic link excluded');
        continue;
      }

      if (stats.isDirectory()) {
        stack.push({ dir: abs, rel, depth: frame.depth + 1 });
        continue;
      }

      if (!stats.isFile()) {
        addFinding('VG-DATA-011', rel, 'special file skipped');
        continue;
      }

      if (!extensionAllowed(dirent.name, policy.extensions)) {
        addFinding(EXTENSION_EXCLUDE_RULE, rel, 'excluded by extension policy');
        continue;
      }

      assertFileSize(Number(stats.size), { ...limits, maxFileSize: effectiveMaxFileSize }, rel);
      fileCount += 1;
      try {
        assertFileCount(fileCount, limits);
        totalBytes += Number(stats.size);
        assertTotalBytes(totalBytes, limits);
      } catch (err) {
        fileCount -= 1;
        totalBytes -= Number(stats.size);
        throw err;
      }

      let hashed;
      try {
        hashed = hashFile(abs, { displayPath: rel, limits: { ...limits, maxFileSize: effectiveMaxFileSize } });
      } catch (err) {
        fileCount -= 1;
        totalBytes -= Number(stats.size);
        handleFileError(err, rel);
        continue;
      }
      entries.push({ path: normalized, size: hashed.size, sha256: hashed.sha256 });
    }
  }

  entries.sort((a, b) => compareNames(a.path, b.path));
  findings.sort((a, b) => compareNames(a.path, b.path) || compareNames(a.rule, b.rule));

  for (let i = 1; i < entries.length; i++) {
    if (entries[i].path === entries[i - 1].path) {
      if (mode === 'register') {
        throw new VgError(
          ERROR_CODES.VG_NFC_COLLISION,
          `multiple filesystem names normalize to "${entries[i].path}"`,
          { path: entries[i].path }
        );
      }
      addFinding('VG-DATA-006', entries[i].path, `multiple filesystem names normalize to "${entries[i].path}"`);
    }
  }
  if (mode === 'verify') {
    findings.sort((a, b) => compareNames(a.path, b.path) || compareNames(a.rule, b.rule));
  }

  const collisions = findPathCollisions(entries.map((entry) => entry.path));
  if (collisions.nfc.length > 0 || collisions.caseFold.length > 0) {
    if (mode === 'register') {
      if (collisions.nfc.length > 0) {
        const [a, b] = collisions.nfc[0];
        throw new VgError(ERROR_CODES.VG_NFC_COLLISION, `paths collide after NFC normalization: "${a}" and "${b}"`, {
          paths: [a, b],
        });
      }
      const [a, b] = collisions.caseFold[0];
      throw new VgError(ERROR_CODES.VG_CASE_COLLISION, `paths collide case-insensitively: "${a}" and "${b}"`, {
        paths: [a, b],
      });
    }
    for (const [a, b] of collisions.nfc) {
      addFinding('VG-DATA-006', a, `NFC collision between "${a}" and "${b}"`);
    }
    for (const [a, b] of collisions.caseFold) {
      addFinding('VG-DATA-006', a, `case-fold collision between "${a}" and "${b}"`);
    }
    findings.sort((a, b) => compareNames(a.path, b.path) || compareNames(a.rule, b.rule));
  }

  return {
    entries,
    findings,
    findingCounts,
    unreadable,
    collisions,
    stats: { fileCount, totalBytes, dirCount },
    policy,
    realRoot,
  };
}

module.exports = {
  walkDataset,
  normalizePolicy,
  DEFAULT_POLICY,
  FINDING_SEVERITY,
  MAX_FINDINGS_PER_RULE,
  EXTENSION_EXCLUDE_RULE,
};
