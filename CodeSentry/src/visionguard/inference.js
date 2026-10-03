'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ERROR_CODES, VgError } = require('./errors');
const { isPlainObject } = require('./canonical');
const { resolveLimits } = require('./limits');
const { hashFile, SHA256_HEX_RE } = require('./hash');
const { normalizeRelPath, resolveRootReal, resolveArtifactPath } = require('./paths');
const { toIso } = require('./manifest');
const store = require('./store');
const prov = require('./provenance');

const SCHEMA_VERSION = '1.0';
const KIND = 'inference_verification';
const OUTPUT_MODES = Object.freeze(['raw', 'canonical_json']);
const LOG_PATH = store.PROVENANCE_LOG_FILE;
const INFERENCE_FINDING_SEVERITY = Object.freeze({
  'VG-INFER-001': 'BLOCKER',
  'VG-INFER-002': 'BLOCKER',
  'VG-INFER-003': 'BLOCKER',
  'VG-PIPE-001': 'BLOCKER',
  'VG-OUT-001': 'BLOCKER',
  'VG-OUT-002': 'BLOCKER',
  'VG-OUT-003': 'BLOCKER',
});

function schemaError(message, details) {
  return new VgError(ERROR_CODES.VG_MANIFEST_SCHEMA, message, details || {});
}

function pushFinding(target, rule, message, extra) {
  const item = {
    rule,
    severity: INFERENCE_FINDING_SEVERITY[rule] || 'BLOCKER',
    path: (extra && extra.path) || LOG_PATH,
    detail: message,
  };
  if (extra) {
    for (const key of Object.keys(extra)) {
      if (key !== 'path') item[key] = extra[key];
    }
  }
  target.findings.push(item);
}

function toRefEntry(value, field) {
  if (!isPlainObject(value)) throw schemaError(`${field} must be an object with { artifact, sha256 }`, { field });
  if (typeof value.artifact !== 'string' || value.artifact.length === 0) {
    throw schemaError(`${field}.artifact must be a non-empty string`, { field: `${field}.artifact` });
  }
  if (typeof value.sha256 !== 'string' || !SHA256_HEX_RE.test(value.sha256)) {
    throw schemaError(`${field}.sha256 must be a 64 character lowercase hex digest`, { field: `${field}.sha256` });
  }
  return { artifact: value.artifact, sha256: value.sha256 };
}

function refOfType(items, type) {
  return items.find((item) => {
    const ref = prov.parseArtifactRef(item.artifact);
    return Boolean(ref) && ref.type === type;
  });
}

function recordInference(options = {}) {
  const storeDir = options.storeDir;
  if (typeof storeDir !== 'string' || storeDir.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'storeDir must be a non-empty string');
  }
  const limits = resolveLimits(options.limits);
  const signer = prov.resolveSigner({ ...options, storeDir });
  if (!signer.keyRecord.operations.includes('infer')) {
    throw new VgError(ERROR_CODES.VG_UNAUTHORIZED_OP, 'operation "infer" is not authorized for this key', {
      operation: 'infer',
      operations: signer.keyRecord.operations,
    });
  }

  const inputEntry = toRefEntry(options.input, 'input');
  const modelEntry = toRefEntry(options.model, 'model');
  const pipelineEntry = toRefEntry(options.pipeline, 'pipeline');
  const outputEntry = toRefEntry(options.output, 'output');
  const modelRef = prov.parseArtifactRef(modelEntry.artifact);
  if (!modelRef || modelRef.type !== 'model') {
    throw schemaError('model must be a "model/<id>@<version>" reference', { field: 'model' });
  }
  const pipelineRef = prov.parseArtifactRef(pipelineEntry.artifact);
  if (!pipelineRef || pipelineRef.type !== 'pipeline') {
    throw schemaError('pipeline must be a "pipeline/<name>@<version>" reference', { field: 'pipeline' });
  }

  let metadata = {};
  if (options.metadata !== undefined && options.metadata !== null) {
    if (!isPlainObject(options.metadata)) throw schemaError('metadata must be an object', { field: 'metadata' });
    metadata = { ...options.metadata };
  }
  if (options.params !== undefined && options.params !== null) {
    if (!isPlainObject(options.params)) throw schemaError('params must be an object', { field: 'params' });
    metadata.params = options.params;
  } else if (metadata.params !== undefined && !isPlainObject(metadata.params)) {
    throw schemaError('metadata.params must be an object', { field: 'metadata.params' });
  }
  if (metadata.params === undefined) metadata.params = {};
  const outputMode =
    options.output_mode !== undefined && options.output_mode !== null
      ? options.output_mode
      : metadata.output_mode !== undefined
        ? metadata.output_mode
        : 'raw';
  if (!OUTPUT_MODES.includes(outputMode)) {
    throw schemaError('output_mode must be "raw" or "canonical_json"', { field: 'output_mode' });
  }
  metadata.output_mode = outputMode;

  const appendOptions = { privateKey: signer.privateKey, now: options.now, limits };
  for (const key of ['timeoutMs', 'staleMs', 'retryMs']) {
    if (options[key] !== undefined) appendOptions[key] = options[key];
  }
  const appended = prov.appendRecord(
    storeDir,
    {
      kind: 'inference_recorded',
      actor: signer.actor,
      inputs: [inputEntry, modelEntry, pipelineEntry],
      outputs: [outputEntry],
      parent_record_hashes: options.parents || options.parent_record_hashes,
      metadata,
    },
    appendOptions
  );
  return appended.record;
}

function hashCheckedFile(absPath, limits) {
  let stats;
  try {
    stats = fs.lstatSync(absPath);
  } catch (err) {
    return { error: `file not found (${err.code || 'UNKNOWN'})` };
  }
  if (stats.isSymbolicLink()) return { error: 'symbolic links are not followed' };
  if (!stats.isFile()) return { error: 'not a regular file' };
  try {
    return { sha256: hashFile(absPath, { limits, displayPath: absPath }).sha256 };
  } catch (err) {
    return { error: err.message };
  }
}

function resolveFilePath(options, item, role) {
  const override = options[`${role}Path`];
  if (typeof override === 'string' && override.length > 0) return override;
  if (typeof options.root !== 'string' || options.root.length === 0) return null;
  if (prov.parseArtifactRef(item.artifact)) return null;
  try {
    normalizeRelPath(item.artifact);
  } catch {
    return null;
  }
  const rootReal = resolveRootReal(options.root);
  const { abs } = resolveArtifactPath(options.root, rootReal, item.artifact);
  return abs;
}

function compareVersions(a, b) {
  const left = String(a).split('.');
  const right = String(b).split('.');
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) {
    const ai = i < left.length ? left[i] : '';
    const bi = i < right.length ? right[i] : '';
    if (ai === bi) continue;
    const an = /^\d+$/.test(ai) ? Number(ai) : null;
    const bn = /^\d+$/.test(bi) ? Number(bi) : null;
    if (an !== null && bn !== null) return an > bn ? 1 : -1;
    if (an !== null) return 1;
    if (bn !== null) return -1;
    return ai > bi ? 1 : -1;
  }
  return 0;
}

function findNewerModelVersion(storeDir, id, refVersion) {
  const dir = path.join(storeDir, 'manifests', 'model', id);
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch {
    return null;
  }
  let best = null;
  for (const name of names) {
    if (!name.endsWith('.json')) continue;
    const version = name.slice(0, -'.json'.length);
    if (version === refVersion) continue;
    if (compareVersions(version, refVersion) > 0 && (best === null || compareVersions(version, best) > 0)) {
      best = version;
    }
  }
  return best;
}

function collectRecordedOutputHashes(entries) {
  const hashes = new Set();
  for (const entry of entries) {
    const kind = entry.record.kind;
    if (kind !== 'inference_recorded' && kind !== 'artifact_registered') continue;
    for (const item of entry.record.outputs) hashes.add(item.sha256);
  }
  return hashes;
}

function verifyInference(options = {}) {
  const storeDir = options.storeDir;
  if (typeof storeDir !== 'string' || storeDir.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'storeDir must be a non-empty string');
  }
  const recordId = options.recordId;
  if (typeof recordId !== 'string' || recordId.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'recordId is required');
  }
  const limits = resolveLimits(options.limits);
  const base = {
    schema_version: SCHEMA_VERSION,
    kind: KIND,
    checked_at: toIso(options.now),
    status: 'NOT_CHECKED',
    output_status: 'NOT_CHECKED',
    record: null,
    findings: [],
  };

  const log = prov.readLogText(storeDir, options);
  if (!log.exists || log.text.trim().length === 0) return base;

  const parsed = prov.parseProvenanceLog(log.text, { limits });
  const entry = parsed.entries.find((item) => item.record.record_id === recordId);
  if (!entry) {
    pushFinding(base, 'VG-INFER-001', `record ${recordId} was not found in the provenance log`);
    base.status = 'FAIL';
    return base;
  }
  const record = entry.record;
  if (record.kind !== 'inference_recorded') {
    pushFinding(
      base,
      'VG-INFER-001',
      `record ${recordId} is a "${record.kind}" record, not an inference record`
    );
    base.status = 'FAIL';
    return base;
  }
  base.record = { record_id: record.record_id, line: entry.lineNumber, timestamp: record.timestamp };

  const indexByHash = new Map();
  for (const item of parsed.entries) indexByHash.set(item.record.record_hash, item);

  for (const parent of record.parent_record_hashes) {
    const parentEntry = indexByHash.get(parent);
    if (!parentEntry || parentEntry.lineNumber >= entry.lineNumber) {
      pushFinding(base, 'VG-INFER-002', `parent ${parent} does not precede this inference record`, {
        parent,
      });
    }
  }

  const inputItem = record.inputs.find((item) => {
    const ref = prov.parseArtifactRef(item.artifact);
    return !ref || (ref.type !== 'model' && ref.type !== 'pipeline');
  });
  const modelItem = refOfType(record.inputs, 'model');
  const pipelineItem = refOfType(record.inputs, 'pipeline');

  if (!modelItem || !pipelineItem || !inputItem) {
    pushFinding(base, 'VG-INFER-001', 'record inputs do not match the required inference shape');
    base.status = 'FAIL';
    return base;
  }

  const modelRef = prov.parseArtifactRef(modelItem.artifact);
  let modelManifest = null;
  try {
    modelManifest = store.loadModelManifest(storeDir, modelRef.name, modelRef.version, { limits });
  } catch (err) {
    pushFinding(
      base,
      'VG-INFER-003',
      `model reference "${modelRef.ref}" is not registered: ${err.message}`,
      { artifact: modelRef.ref }
    );
  }
  if (modelManifest) {
    if (modelManifest.sha256 !== modelItem.sha256) {
      pushFinding(
        base,
        'VG-INFER-003',
        `recorded model hash does not match the registration for "${modelRef.ref}"`,
        { artifact: modelRef.ref }
      );
    }
    const newer = findNewerModelVersion(storeDir, modelRef.name, modelRef.version);
    if (newer !== null) {
      pushFinding(
        base,
        'VG-INFER-003',
        `model reference "${modelRef.ref}" is stale: version "${newer}" is registered`,
        { artifact: modelRef.ref, newer_version: newer }
      );
    }
  }
  if (typeof options.modelSha256 === 'string' && options.modelSha256.length > 0) {
    if (options.modelSha256 !== modelItem.sha256) {
      pushFinding(base, 'VG-INFER-003', 'model file content does not match the recorded hash', {
        path: options.modelPath,
      });
    }
  } else if (typeof options.modelPath === 'string' && options.modelPath.length > 0) {
    const hashed = hashCheckedFile(options.modelPath, limits);
    if (hashed.error) {
      pushFinding(base, 'VG-INFER-003', `model file cannot be verified: ${hashed.error}`, {
        path: options.modelPath,
      });
    } else if (hashed.sha256 !== modelItem.sha256) {
      pushFinding(base, 'VG-INFER-003', 'model file content does not match the recorded hash', {
        path: options.modelPath,
      });
    }
  }

  const pipelineRef = prov.parseArtifactRef(pipelineItem.artifact);
  try {
    const pipelineManifest = store.loadPipelineManifest(storeDir, pipelineRef.name, pipelineRef.version, { limits });
    const registered = pipelineManifest.pipeline_id.replace(/^sha256:/, '');
    if (registered !== pipelineItem.sha256) {
      pushFinding(
        base,
        'VG-PIPE-001',
        `recorded pipeline hash does not match the registration for "${pipelineRef.ref}"`,
        { artifact: pipelineRef.ref }
      );
    }
  } catch (err) {
    pushFinding(base, 'VG-PIPE-001', `pipeline reference "${pipelineRef.ref}" is not registered: ${err.message}`, {
      artifact: pipelineRef.ref,
    });
  }

  const inputPath = resolveFilePath(options, inputItem, 'input');
  if (inputPath) {
    const hashed = hashCheckedFile(inputPath, limits);
    if (hashed.error) {
      pushFinding(base, 'VG-INFER-001', `input file cannot be verified: ${hashed.error}`, { path: inputPath });
    } else if (hashed.sha256 !== inputItem.sha256) {
      pushFinding(base, 'VG-INFER-001', 'input file content does not match the recorded hash', {
        path: inputPath,
        expected: inputItem.sha256,
        actual: hashed.sha256,
      });
    }
  }

  const outputItem = record.outputs[0];
  const outputPath = resolveFilePath(options, outputItem, 'output');
  if (outputPath) {
    const hashed = hashCheckedFile(outputPath, limits);
    if (hashed.error) {
      pushFinding(base, 'VG-OUT-002', `output file cannot be verified: ${hashed.error}`, { path: outputPath });
      base.output_status = 'FAIL';
    } else if (hashed.sha256 === outputItem.sha256) {
      base.output_status = 'PASS';
    } else if (collectRecordedOutputHashes(parsed.entries).has(hashed.sha256)) {
      pushFinding(
        base,
        'VG-OUT-003',
        'output file content matches a different record (outputs appear swapped)',
        { path: outputPath }
      );
      base.output_status = 'FAIL';
    } else {
      pushFinding(
        base,
        'VG-OUT-001',
        `output file content does not match the recorded hash: expected ${outputItem.sha256}, got ${hashed.sha256}`,
        {
          path: outputPath,
          expected: outputItem.sha256,
          actual: hashed.sha256,
        }
      );
      base.output_status = 'FAIL';
    }
  }

  const inferenceRules = new Set(['VG-INFER-001', 'VG-INFER-002', 'VG-INFER-003', 'VG-PIPE-001']);
  base.status = base.findings.some((item) => inferenceRules.has(item.rule)) ? 'FAIL' : 'PASS';
  return base;
}

module.exports = {
  SCHEMA_VERSION,
  KIND,
  OUTPUT_MODES,
  INFERENCE_FINDING_SEVERITY,
  recordInference,
  verifyInference,
  compareVersions,
};
