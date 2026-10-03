'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ERROR_CODES, VgError, isVgError } = require('./errors');
const { hashRecord } = require('./canonical');
const { resolveLimits, DEFAULT_LIMITS } = require('./limits');
const { hashFile } = require('./hash');
const { toIso, verifyDataset } = require('./manifest');
const { verifyModel } = require('./model');
const { verifyPipeline } = require('./pipeline');
const { verifyInference } = require('./inference');
const provenance = require('./provenance');
const store = require('./store');
const keys = require('./keys');

const SCHEMA_VERSION = '1.0';
const KIND = 'assurance_report';
const DIMENSION_NAMES = Object.freeze(['dataset', 'model', 'pipeline', 'inference', 'output', 'provenance']);
const STATUS_RANK = Object.freeze({ FAIL: 3, UNSIGNED: 2, UNANCHORED: 2, NOT_CHECKED: 1, PASS: 0 });
const SKIP_DIRS = new Set(['.git', 'node_modules', '.visionguard']);
const VERIFIED = 'VERIFIED';
const INCOMPLETE = 'INCOMPLETE';
const VIOLATION = 'INTEGRITY VIOLATION';

function statusOf(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && typeof value.status === 'string') return value.status;
  return 'NOT_CHECKED';
}

function rankStatus(status) {
  return Object.prototype.hasOwnProperty.call(STATUS_RANK, status) ? STATUS_RANK[status] : 1;
}

function worstStatus(statuses) {
  if (!Array.isArray(statuses) || statuses.length === 0) return 'NOT_CHECKED';
  let worst = statuses[0];
  for (let i = 1; i < statuses.length; i++) {
    if (rankStatus(statuses[i]) > rankStatus(worst)) worst = statuses[i];
  }
  return worst;
}

function overallVerdict(dimensions) {
  const source = dimensions && typeof dimensions === 'object' ? dimensions : {};
  for (const name of DIMENSION_NAMES) {
    if (statusOf(source[name]) === 'FAIL') return VIOLATION;
  }
  for (const name of DIMENSION_NAMES) {
    if (statusOf(source[name]) !== 'PASS') return INCOMPLETE;
  }
  return VERIFIED;
}

function stripSha256(value) {
  return String(value || '').replace(/^sha256:/, '');
}

function relToRoot(root, target) {
  const rel = path.relative(root, target);
  return (rel || path.basename(target)).replace(/\\/g, '/');
}

function artifactNode(value) {
  const ref = provenance.parseArtifactRef(value);
  return ref ? ref.ref : String(value);
}

function artifactType(value) {
  const ref = provenance.parseArtifactRef(value);
  return ref ? ref.type : 'file';
}

const FINDING_CONSUMED_KEYS = ['rule', 'severity', 'path', 'detail', 'message'];

function addFinding(report, rule, severity, file, detail, extra) {
  const item = { rule, severity: severity || 'BLOCKER', path: file, detail: String(detail) };
  if (extra && typeof extra === 'object') {
    for (const key of Object.keys(extra)) {
      if (FINDING_CONSUMED_KEYS.includes(key)) continue;
      if (item[key] === undefined) item[key] = extra[key];
    }
  }
  report.findings.push(item);
}

function addWarning(report, rule, file, detail) {
  report.warnings.push({ rule, severity: 'WARN', path: file, detail: String(detail) });
}

function listManifestRefs(manifestStoreDir, kind) {
  const baseDir = path.join(manifestStoreDir, 'manifests', kind);
  const refs = [];
  let names;
  try {
    names = fs.readdirSync(baseDir, { withFileTypes: true });
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  for (const entry of names) {
    if (!entry.isDirectory()) continue;
    let versions;
    try {
      versions = fs.readdirSync(path.join(baseDir, entry.name));
    } catch {
      continue;
    }
    for (const file of versions) {
      if (!file.endsWith('.json')) continue;
      refs.push({ name: entry.name, version: file.slice(0, -'.json'.length) });
    }
  }
  refs.sort((a, b) => {
    if (a.name !== b.name) return a.name < b.name ? -1 : 1;
    if (a.version === b.version) return 0;
    return a.version < b.version ? -1 : 1;
  });
  return refs;
}

function listProjectFiles(root, limits, skipDir) {
  const maxFiles = Number.isInteger(limits.maxFiles) && limits.maxFiles > 0 ? limits.maxFiles : DEFAULT_LIMITS.maxFiles;
  const files = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (let i = entries.length - 1; i >= 0; i--) {
      const entry = entries[i];
      if (SKIP_DIRS.has(entry.name)) continue;
      const abs = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (skipDir && abs === skipDir) continue;
        stack.push(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      try {
        const stats = fs.statSync(abs);
        files.push({ abs, rel: path.relative(root, abs).replace(/\\/g, '/'), size: stats.size });
      } catch {
        continue;
      }
      if (files.length >= maxFiles) return files;
    }
  }
  return files;
}

function locateDatasetRoot(root, files, manifestDoc) {
  const entries = Array.isArray(manifestDoc.files) ? manifestDoc.files : [];
  if (entries.length === 0) return null;
  const bySize = new Map();
  for (const entry of entries) {
    const wanted = String(entry.path).replace(/\\/g, '/');
    const list = bySize.get(entry.size) || [];
    list.push({ path: wanted, size: entry.size });
    bySize.set(entry.size, list);
  }
  const votes = new Map();
  for (const file of files) {
    const candidates = bySize.get(file.size);
    if (!candidates) continue;
    for (const entry of candidates) {
      if (!file.rel.endsWith(entry.path)) continue;
      const offset = file.rel.length - entry.path.length;
      if (offset > 0) {
        const sep = file.rel[offset - 1];
        if (sep !== '/' && sep !== '\\') continue;
      }
      const baseRel = offset > 0 ? file.rel.slice(0, offset - 1) : '';
      const baseAbs = baseRel ? path.join(root, baseRel) : root;
      votes.set(baseAbs, (votes.get(baseAbs) || 0) + 1);
    }
  }
  let best = null;
  let bestCount = 0;
  for (const [abs, count] of votes) {
    if (count > bestCount || (count === bestCount && best !== null && abs < best)) {
      best = abs;
      bestCount = count;
    }
  }
  return best;
}

function modelFileNames(manifestDoc) {
  const id = manifestDoc.id;
  return [...new Set([
    `${id}.${manifestDoc.format}`,
    `${id}.safetensors`,
    `${id}.onnx`,
    `${id}.gguf`,
    `${id}.pt`,
    `${id}.pth`,
  ])];
}

function locateModelFile(root, files, manifestDoc, limits) {
  const sameSize = files.filter((file) => file.size === manifestDoc.size);
  for (const file of sameSize) {
    try {
      const hashed = hashFile(file.abs, { limits, displayPath: file.rel });
      if (hashed.sha256 === manifestDoc.sha256) return { abs: file.abs, hashed };
    } catch {
      continue;
    }
  }
  if (sameSize.length > 0) return { abs: sameSize[0].abs, hashed: null };
  const wanted = modelFileNames(manifestDoc);
  const matches = files.filter((file) => wanted.includes(path.posix.basename(file.rel)));
  matches.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return matches.length > 0 ? { abs: matches[0].abs, hashed: null } : null;
}

function datasetSignedBinding(manifestDoc, entries, manifestStoreDir, limits) {
  const wantedRef = `dataset/${manifestDoc.name}@${manifestDoc.version}`;
  const wantedHash = stripSha256(manifestDoc.merkle_root);
  for (const entry of entries) {
    const record = entry.record;
    if (!record.signature) continue;
    let hit = false;
    for (const item of record.outputs) {
      if (artifactNode(item.artifact) === wantedRef && stripSha256(item.sha256) === wantedHash) {
        hit = true;
        break;
      }
    }
    if (!hit) continue;
    try {
      if (hashRecord(record) !== record.record_hash) continue;
      const keyRecord = keys.loadPublicKey(manifestStoreDir, record.actor.contributor, record.actor.key_id, { limits });
      if (keyRecord.status === 'revoked') continue;
      const der = Buffer.from(keyRecord.public_key_der_b64, 'base64');
      if (!keys.verifySignature(der, record.record_hash, record.signature)) continue;
      return true;
    } catch {
      continue;
    }
  }
  return false;
}

function checkStoreMetadata(manifestStoreDir, limits) {
  const file = store.storeJsonPath(manifestStoreDir);
  if (!fs.existsSync(file)) return { valid: true, error: null };
  try {
    store.loadStoreMetadata(manifestStoreDir, { limits });
    return { valid: true, error: null };
  } catch (err) {
    return {
      valid: false,
      error: { code: isVgError(err) ? err.code : ERROR_CODES.VG_INTERNAL, message: err.message },
    };
  }
}

function resolveAnchor(manifestStoreDir, anchor) {
  if (anchor && typeof anchor.expectedHead === 'string' && anchor.expectedHead.trim().length > 0) {
    return { expectedHead: anchor.expectedHead.trim() };
  }
  if (anchor && typeof anchor.anchorFilePath === 'string' && anchor.anchorFilePath.length > 0) {
    return { anchorFilePath: anchor.anchorFilePath };
  }
  const envHead = typeof process.env.VG_EXPECTED_HEAD === 'string' ? process.env.VG_EXPECTED_HEAD.trim() : '';
  if (envHead.length > 0) return { expectedHead: envHead };
  const autoFile = path.join(manifestStoreDir, 'anchors', 'head.txt');
  if (fs.existsSync(autoFile)) return { anchorFilePath: autoFile };
  return {};
}

function readProvenanceEntries(manifestStoreDir, limits) {
  const log = provenance.readLogText(manifestStoreDir, { limits });
  if (!log.exists || log.text.trim().length === 0) return [];
  const parsed = provenance.parseProvenanceLog(log.text, { limits });
  return parsed.entries;
}

function pipelineSpecFromManifest(manifestDoc) {
  const identity = manifestDoc.identity;
  if (!identity || typeof identity !== 'object') {
    throw new VgError(ERROR_CODES.VG_MANIFEST_MALFORMED, 'pipeline manifest has no identity');
  }
  const spec = {};
  if (identity.preprocess_config && identity.preprocess_config.path) {
    spec.preprocess_config = { path: identity.preprocess_config.path };
  }
  spec.code = {
    git_commit: identity.code && identity.code.git_commit ? identity.code.git_commit : null,
    files:
      identity.code && Array.isArray(identity.code.files)
        ? identity.code.files.map((file) => ({ path: file.path }))
        : [],
  };
  if (identity.dependency_lock && identity.dependency_lock.path) {
    spec.dependency_lock = { path: identity.dependency_lock.path };
  }
  spec.parameters = identity.parameters === undefined || identity.parameters === null ? {} : identity.parameters;
  if (identity.runtime) spec.runtime = identity.runtime;
  return spec;
}

function assertRequestedRegistered(requested, refs, label) {
  if (!requested || typeof requested.name !== 'string' || requested.name.length === 0) return;
  const match = refs.some(
    (ref) =>
      ref.name === requested.name &&
      (requested.version === undefined || requested.version === null || ref.version === requested.version)
  );
  if (!match) {
    throw new VgError(ERROR_CODES.VG_NOT_REGISTERED, `${label} "${requested.name}" is not registered`, {
      name: requested.name,
      version: requested.version || null,
    });
  }
}

function buildGraph(entries, manifestArtifacts) {
  const artifacts = new Map();
  const contributors = new Map();
  const trusts = new Set();
  const derived = new Set();

  const addArtifact = (ref, type, sha256) => {
    if (!artifacts.has(ref)) {
      artifacts.set(ref, { ref, type: type || 'file', sha256: sha256 || null });
    } else if (!artifacts.get(ref).sha256 && sha256) {
      artifacts.get(ref).sha256 = sha256;
    }
  };
  const addContributor = (name, keyId) => {
    if (!name) return;
    if (!contributors.has(name)) contributors.set(name, { contributor: name, key_ids: [] });
    if (keyId && !contributors.get(name).key_ids.includes(keyId)) contributors.get(name).key_ids.push(keyId);
  };
  const addTrust = (contributor, ref) => {
    if (contributor && ref) trusts.add(`${contributor}|${ref}`);
  };

  for (const item of manifestArtifacts) {
    addArtifact(item.ref, item.type, item.sha256);
    addContributor(item.contributor, null);
    addTrust(item.contributor, item.ref);
  }

  for (const entry of entries) {
    const record = entry.record;
    const actor = record.actor ? record.actor.contributor : null;
    addContributor(actor, record.actor ? record.actor.key_id : null);
    for (const group of [record.inputs, record.outputs]) {
      for (const item of group) {
        addArtifact(artifactNode(item.artifact), artifactType(item.artifact), item.sha256);
      }
    }
    const outputs = record.outputs.map((item) => artifactNode(item.artifact));
    for (const ref of outputs) addTrust(actor, ref);
    if (record.kind === 'operation_recorded' || record.kind === 'inference_recorded') {
      const inputs = record.inputs.map((item) => artifactNode(item.artifact));
      for (const out of outputs) {
        for (const single of inputs) {
          if (single !== out) derived.add(`${out}|${single}`);
        }
      }
    }
  }

  const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  return {
    artifacts: [...artifacts.values()].sort((a, b) => byText(a.ref, b.ref)),
    contributors: [...contributors.values()].sort((a, b) => byText(a.contributor, b.contributor)),
    trusts: [...trusts]
      .map((key) => {
        const sep = key.indexOf('|');
        return { contributor: key.slice(0, sep), ref: key.slice(sep + 1) };
      })
      .sort((a, b) => byText(`${a.contributor}|${a.ref}`, `${b.contributor}|${b.ref}`)),
    derivedFrom: [...derived]
      .map((key) => {
        const sep = key.indexOf('|');
        return { from: key.slice(0, sep), to: key.slice(sep + 1) };
      })
      .sort((a, b) => byText(`${a.from}|${a.to}`, `${b.from}|${b.to}`)),
  };
}

function runAssurance(options = {}) {
  const root = path.resolve(options.root || process.cwd());
  const manifestStoreDir = options.storeDir ? path.resolve(options.storeDir) : path.join(root, '.visionguard');
  const strict = options.strict === true;
  const limits = resolveLimits(options.limits);
  const now = options.now;
  const logRel = relToRoot(root, store.provenanceLogPath(manifestStoreDir));

  const report = {
    schema_version: SCHEMA_VERSION,
    kind: KIND,
    checked_at: toIso(now),
    overall: INCOMPLETE,
    anchored: null,
    store: { present: fs.existsSync(manifestStoreDir), valid: true, error: null },
    dimensions: {},
    findings: [],
    warnings: [],
    errors: [],
    graph: { artifacts: [], contributors: [], trusts: [], derivedFrom: [] },
  };

  const datasetRefs = listManifestRefs(manifestStoreDir, 'dataset');
  const modelRefs = listManifestRefs(manifestStoreDir, 'model');
  const pipelineRefs = listManifestRefs(manifestStoreDir, 'pipeline');
  assertRequestedRegistered(options.dataset, datasetRefs, 'dataset');
  assertRequestedRegistered(options.model, modelRefs, 'model');

  if (!report.store.present) {
    for (const name of DIMENSION_NAMES) report.dimensions[name] = { status: 'NOT_CHECKED' };
    report.overall = overallVerdict(report.dimensions);
    return report;
  }

  const storeMeta = checkStoreMetadata(manifestStoreDir, limits);
  report.store.valid = storeMeta.valid;
  report.store.error = storeMeta.error;

  const logEntries = readProvenanceEntries(manifestStoreDir, limits);
  const anchorOptions = resolveAnchor(manifestStoreDir, options.anchor);
  const provResult = provenance.verifyProvenance({ storeDir: manifestStoreDir, ...anchorOptions, limits, now });

  let provenanceStatus = provResult.status;
  if (!storeMeta.valid) {
    addFinding(
      report,
      'VG-PROV-001',
      'BLOCKER',
      relToRoot(root, store.storeJsonPath(manifestStoreDir)),
      `store metadata failed validation: ${storeMeta.error ? storeMeta.error.message : 'unknown error'}`
    );
    provenanceStatus = 'FAIL';
  }
  for (const item of provResult.findings) addFinding(report, item.rule, item.severity, logRel, item.message, item);
  for (const item of provResult.warnings) addWarning(report, item.rule, logRel, item.message);

  report.dimensions.provenance = {
    status: provenanceStatus,
    anchored: provResult.anchored,
    head: provResult.head,
    expected_head: provResult.expected_head,
    record_count: provResult.record_count,
    unsigned_count: provResult.unsigned_count,
    malformed_count: provResult.malformed_count,
    warning_count: provResult.warnings.length,
    store_valid: storeMeta.valid,
  };
  report.anchored = provResult.anchored;

  let projectFiles = null;
  const getProjectFiles = () => {
    if (projectFiles === null) projectFiles = listProjectFiles(root, limits, manifestStoreDir);
    return projectFiles;
  };
  const manifestArtifacts = [];
  const modelPathByKey = new Map();
  const modelShaByKey = new Map();

  const datasetEntries = [];
  const datasetStatuses = [];
  const datasetHint =
    datasetRefs.length === 1 && options.dataset && typeof options.dataset.path === 'string' && options.dataset.path
      ? options.dataset.path
      : null;

  for (const ref of datasetRefs) {
    const manifestPath = relToRoot(root, store.datasetManifestPath(manifestStoreDir, ref.name, ref.version));
    let manifestDoc;
    try {
      manifestDoc = store.loadDatasetManifest(manifestStoreDir, ref.name, ref.version, { limits });
    } catch (err) {
      addFinding(report, 'VG-DATA-007', 'BLOCKER', manifestPath, `dataset manifest could not be read: ${err.message}`);
      datasetStatuses.push('FAIL');
      datasetEntries.push({ name: ref.name, version: ref.version, status: 'FAIL', located: false });
      continue;
    }
    const target = datasetHint || locateDatasetRoot(root, getProjectFiles(), manifestDoc);
    if (!target) {
      addFinding(report, 'VG-DATA-002', 'BLOCKER', manifestPath, 'registered dataset files were not found under the project root');
      datasetStatuses.push('FAIL');
      datasetEntries.push({
        name: ref.name,
        version: ref.version,
        status: 'FAIL',
        located: false,
        files: manifestDoc.file_count,
        merkle_root: manifestDoc.merkle_root,
      });
      continue;
    }
    const verification = verifyDataset({ manifest: manifestDoc, path: target, strict, limits, now });
    for (const item of verification.findings) {
      const file = item.path
        ? relToRoot(root, path.resolve(target, item.path))
        : manifestPath;
      addFinding(report, item.rule, item.severity, file, item.detail, item);
    }
    const bound = datasetSignedBinding(manifestDoc, logEntries, manifestStoreDir, limits);
    const status = verification.status === 'FAIL' ? 'FAIL' : bound ? 'PASS' : 'UNANCHORED';
    datasetStatuses.push(status);
    datasetEntries.push({
      name: ref.name,
      version: ref.version,
      status,
      located: true,
      path: relToRoot(root, target),
      files: manifestDoc.file_count,
      total_bytes: manifestDoc.total_bytes,
      merkle_root: manifestDoc.merkle_root,
      signed_binding: bound,
    });
    manifestArtifacts.push({
      ref: `dataset/${ref.name}@${ref.version}`,
      type: 'dataset',
      sha256: stripSha256(manifestDoc.merkle_root),
      contributor: manifestDoc.actor ? manifestDoc.actor.contributor : null,
    });
  }
  report.dimensions.dataset =
    datasetRefs.length === 0
      ? { status: 'NOT_CHECKED', entries: [] }
      : {
          status: worstStatus(datasetStatuses),
          entries: datasetEntries,
          signed_binding: datasetEntries.length > 0 ? datasetEntries.every((entry) => entry.signed_binding === true) : null,
        };

  const modelEntries = [];
  const modelStatuses = [];
  const modelHint =
    modelRefs.length === 1 && options.model && typeof options.model.path === 'string' && options.model.path
      ? options.model.path
      : null;
  const modelHintHashed =
    modelHint && options.model && options.model.hashed && typeof options.model.hashed === 'object'
      ? options.model.hashed
      : null;

  for (const ref of modelRefs) {
    const manifestPath = relToRoot(root, store.modelManifestPath(manifestStoreDir, ref.name, ref.version));
    let manifestDoc;
    try {
      manifestDoc = store.loadModelManifest(manifestStoreDir, ref.name, ref.version, { limits });
    } catch (err) {
      addFinding(report, 'VG-MODEL-006', 'BLOCKER', manifestPath, `model manifest could not be read: ${err.message}`);
      modelStatuses.push('FAIL');
      modelEntries.push({ id: ref.name, version: ref.version, status: 'FAIL', located: false });
      continue;
    }
    const located = modelHint
      ? { abs: modelHint, hashed: modelHintHashed }
      : locateModelFile(root, getProjectFiles(), manifestDoc, limits);
    const target = located ? located.abs : null;
    if (!target) {
      addFinding(report, 'VG-MODEL-001', 'BLOCKER', manifestPath, 'registered model file was not found under the project root');
      modelStatuses.push('FAIL');
      modelEntries.push({
        id: ref.name,
        version: ref.version,
        status: 'FAIL',
        located: false,
        format: manifestDoc.format,
        sha256: manifestDoc.sha256,
        size: manifestDoc.size,
      });
      continue;
    }
    const verification = verifyModel({ manifest: manifestDoc, path: target, hashed: located.hashed, limits, now });
    for (const item of verification.findings) {
      const file = item.path ? relToRoot(root, item.path) : manifestPath;
      addFinding(report, item.rule, item.severity, file, item.detail, item);
    }
    modelPathByKey.set(`model/${ref.name}@${ref.version}`, target);
    modelShaByKey.set(
      `model/${ref.name}@${ref.version}`,
      verification.actual && typeof verification.actual.sha256 === 'string' ? verification.actual.sha256 : null
    );
    modelStatuses.push(verification.status);
    modelEntries.push({
      id: ref.name,
      version: ref.version,
      status: verification.status,
      located: true,
      path: relToRoot(root, target),
      format: manifestDoc.format,
      sha256: manifestDoc.sha256,
      size: manifestDoc.size,
    });
    manifestArtifacts.push({
      ref: `model/${ref.name}@${ref.version}`,
      type: 'model',
      sha256: manifestDoc.sha256,
      contributor: manifestDoc.actor ? manifestDoc.actor.contributor : null,
    });
  }
  report.dimensions.model =
    modelRefs.length === 0 ? { status: 'NOT_CHECKED', entries: [] } : { status: worstStatus(modelStatuses), entries: modelEntries };

  const pipelineEntries = [];
  const pipelineStatuses = [];

  for (const ref of pipelineRefs) {
    const manifestPath = relToRoot(root, store.pipelineManifestPath(manifestStoreDir, ref.name, ref.version));
    let manifestDoc;
    try {
      manifestDoc = store.loadPipelineManifest(manifestStoreDir, ref.name, ref.version, { limits });
    } catch (err) {
      addFinding(report, 'VG-PIPE-001', 'BLOCKER', manifestPath, `pipeline manifest could not be read: ${err.message}`);
      pipelineStatuses.push('FAIL');
      pipelineEntries.push({ name: ref.name, version: ref.version, status: 'FAIL' });
      continue;
    }
    let verification;
    try {
      const spec = pipelineSpecFromManifest(manifestDoc);
      verification = verifyPipeline({ manifest: manifestDoc, root, ...spec, limits, now });
    } catch (err) {
      addFinding(report, 'VG-PIPE-001', 'BLOCKER', manifestPath, `pipeline verification could not run: ${err.message}`);
      pipelineStatuses.push('FAIL');
      pipelineEntries.push({ name: ref.name, version: ref.version, status: 'FAIL' });
      continue;
    }
    for (const item of verification.findings) {
      const file = item.path ? relToRoot(root, item.path) : manifestPath;
      addFinding(report, item.rule, item.severity, file, item.detail, item);
    }
    pipelineStatuses.push(verification.status);
    pipelineEntries.push({
      name: ref.name,
      version: ref.version,
      status: verification.status,
      pipeline_id: verification.pipeline_id || manifestDoc.pipeline_id || null,
    });
    manifestArtifacts.push({
      ref: `pipeline/${ref.name}@${ref.version}`,
      type: 'pipeline',
      sha256: stripSha256(verification.pipeline_id || manifestDoc.pipeline_id || ''),
      contributor: manifestDoc.actor ? manifestDoc.actor.contributor : null,
    });
  }
  report.dimensions.pipeline =
    pipelineRefs.length === 0
      ? { status: 'NOT_CHECKED', entries: [] }
      : { status: worstStatus(pipelineStatuses), entries: pipelineEntries };

  let inferenceRecords = logEntries.filter((entry) => entry.record.kind === 'inference_recorded');
  if (options.inference && typeof options.inference.recordId === 'string' && options.inference.recordId.length > 0) {
    const wanted = options.inference.recordId;
    inferenceRecords = inferenceRecords.filter((entry) => entry.record.record_id === wanted);
    if (inferenceRecords.length === 0) {
      throw new VgError(ERROR_CODES.VG_NOT_REGISTERED, `inference record "${wanted}" is not registered`, {
        record_id: wanted,
      });
    }
  }

  const inferenceEntries = [];
  const inferenceStatuses = [];
  const outputStatuses = [];

  for (const entry of inferenceRecords) {
    const record = entry.record;
    const modelItem = record.inputs.find((item) => {
      const ref = provenance.parseArtifactRef(item.artifact);
      return ref && ref.type === 'model';
    });
    const modelKey = modelItem ? artifactNode(modelItem.artifact) : null;
    const modelPath = modelKey && modelPathByKey.has(modelKey) ? modelPathByKey.get(modelKey) : undefined;
    const modelSha = modelKey && modelShaByKey.has(modelKey) ? modelShaByKey.get(modelKey) : undefined;
    const verification = verifyInference({
      storeDir: manifestStoreDir,
      recordId: record.record_id,
      root,
      ...(modelPath ? { modelPath } : {}),
      ...(modelPath && typeof modelSha === 'string' ? { modelSha256: modelSha } : {}),
      limits,
      now,
    });
    for (const item of verification.findings) {
      const file = item.path && path.isAbsolute(item.path) ? relToRoot(root, item.path) : logRel;
      addFinding(report, item.rule, item.severity, file, item.detail, item);
    }
    inferenceStatuses.push(verification.status);
    outputStatuses.push(verification.output_status);
    inferenceEntries.push({
      record_id: record.record_id,
      line: entry.lineNumber,
      status: verification.status,
      output_status: verification.output_status,
    });
  }

  report.dimensions.inference =
    inferenceRecords.length === 0
      ? { status: 'NOT_CHECKED', entries: [] }
      : { status: worstStatus(inferenceStatuses), entries: inferenceEntries };
  report.dimensions.output =
    inferenceRecords.length === 0
      ? { status: 'NOT_CHECKED', entries: [] }
      : {
          status: worstStatus(outputStatuses),
          entries: inferenceEntries.map((entry) => ({ record_id: entry.record_id, status: entry.output_status })),
        };

  report.graph = buildGraph(logEntries, manifestArtifacts);
  report.overall = overallVerdict(report.dimensions);
  return report;
}

module.exports = {
  SCHEMA_VERSION,
  KIND,
  DIMENSION_NAMES,
  VERIFIED,
  INCOMPLETE,
  VIOLATION,
  statusOf,
  worstStatus,
  overallVerdict,
  runAssurance,
  listManifestRefs,
};
