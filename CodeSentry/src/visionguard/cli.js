'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');
const { createVisionGuard, runAssurance } = require('./index');
const { listManifestRefs } = require('./assurance');
const provenance = require('./provenance');
const keys = require('./keys');
const store = require('./store');
const { hashFile } = require('./hash');
const { parseCanonical, DEFAULT_MAX_DEPTH, DEFAULT_MAX_PARSE_BYTES } = require('./canonical');
const modelLib = require('./model');
const { ERROR_CODES, VgError, isVgError } = require('./errors');

const SCHEMA_VERSION = '1.0';
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const EXIT_OK = 0;
const EXIT_VIOLATION = 1;
const EXIT_USAGE = 2;
const EXIT_INCOMPLETE = 3;
const EXIT_ERROR = 4;

const DIMENSION_LABELS = Object.freeze([
  ['dataset', 'Dataset Integrity'],
  ['model', 'Model Integrity'],
  ['pipeline', 'Pipeline Integrity'],
  ['inference', 'Inference Integrity'],
  ['output', 'Output Integrity'],
  ['provenance', 'Provenance'],
]);

const FLAG_KEYS = Object.freeze({
  '--json': 'json',
  '--verbose': 'verbose',
  '--store': 'store',
  '--key-file': 'keyFile',
  '--actor': 'actor',
  '--name': 'name',
  '--version': 'version',
  '--id': 'id',
  '--format': 'format',
  '--model': 'model',
  '--pipeline': 'pipeline',
  '--code': 'code',
  '--deps': 'deps',
  '--params': 'params',
  '--runtime': 'runtime',
  '--preprocess': 'preprocess',
  '--strict': 'strict',
  '--require-verified': 'requireVerified',
  '--expected-head': 'expectedHead',
  '--anchor-file': 'anchorFile',
  '--artifact': 'artifact',
  '--graph': 'graph',
  '--verify': 'verify',
  '--help': 'help',
  '-h': 'help',
});

const VALUE_FLAGS = new Set([
  'store',
  'keyFile',
  'actor',
  'name',
  'version',
  'id',
  'format',
  'model',
  'pipeline',
  'code',
  'deps',
  'params',
  'runtime',
  'preprocess',
  'expectedHead',
  'anchorFile',
  'artifact',
]);

const KEY_FLAG_TEXT = Object.freeze({
  json: '--json',
  verbose: '--verbose',
  store: '--store',
  keyFile: '--key-file',
  actor: '--actor',
  name: '--name',
  version: '--version',
  id: '--id',
  format: '--format',
  model: '--model',
  pipeline: '--pipeline',
  code: '--code',
  deps: '--deps',
  params: '--params',
  runtime: '--runtime',
  preprocess: '--preprocess',
  strict: '--strict',
  requireVerified: '--require-verified',
  expectedHead: '--expected-head',
  anchorFile: '--anchor-file',
  artifact: '--artifact',
  graph: '--graph',
  verify: '--verify',
  help: '--help',
});

const BASE_FLAGS = ['json', 'verbose', 'store', 'help'];

const ALLOWED = Object.freeze({
  init: [...BASE_FLAGS, 'keyFile', 'actor'],
  'register-data': [...BASE_FLAGS, 'keyFile', 'actor', 'name', 'version'],
  'verify-data': [...BASE_FLAGS, 'strict', 'name', 'version'],
  'register-model': [...BASE_FLAGS, 'actor', 'id', 'version', 'format'],
  'verify-model': [...BASE_FLAGS, 'strict', 'version'],
  'record-pipeline': [...BASE_FLAGS, 'keyFile', 'actor', 'name', 'version', 'code', 'deps', 'params', 'runtime', 'preprocess'],
  'record-inference': [...BASE_FLAGS, 'keyFile', 'actor', 'model', 'pipeline'],
  'verify-output': [...BASE_FLAGS, 'strict'],
  provenance: [...BASE_FLAGS, 'artifact', 'graph', 'verify'],
  verify: [...BASE_FLAGS, 'strict', 'requireVerified', 'expectedHead', 'anchorFile'],
});

const MAX_POSITIONALS = Object.freeze({
  init: 0,
  'register-data': 1,
  'verify-data': 1,
  'register-model': 1,
  'verify-model': 1,
  'record-pipeline': 0,
  'record-inference': 2,
  'verify-output': 1,
  provenance: 0,
  verify: 0,
});

class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
    this.usage = true;
  }
}

function usageText() {
  return [
    'Usage: codesentry vision <command> [options]',
    '',
    'Commands:',
    '  init                        Create .visionguard/, generate an Ed25519 keypair and register a contributor',
    '  register-data <dir>         Register a dataset manifest and sign its binding',
    '  verify-data [<dir>]         Verify a registered dataset against the files on disk',
    '  register-model <file>       Register a model manifest (format sniffed unless --format)',
    '  verify-model <file|id>      Verify a registered model file',
    '  record-pipeline             Record a signed pipeline identity manifest',
    '  record-inference <in> <out> Record a signed inference run',
    '  verify-output <output>      Verify a recorded output artifact',
    '  provenance                  Inspect the provenance log (--artifact X, --graph, --verify)',
    '  verify                      Run all six integrity dimensions',
    '',
    'Global options:',
    '  --json                      Output a single JSON object',
    '  --store <dir>               Store directory (default: <project>/.visionguard)',
    '  --key-file <file>           Private key used for signing, or the key imported by init',
    '  --verbose                   Show detailed output',
    '  --help                      Show this help',
    '',
    'verify options:',
    '  --strict  --require-verified  --expected-head <head>  --anchor-file <file>',
    '',
    'Exit codes: 0 verified, 1 integrity violation, 2 usage, 3 incomplete, 4 internal',
  ].join('\n');
}

function parseVisionArgs(argv) {
  const tokens = Array.isArray(argv) ? argv : [];
  const flags = {};
  const positionals = [];
  let sub = null;
  for (let i = 0; i < tokens.length; i++) {
    const arg = String(tokens[i]);
    if (arg.startsWith('-')) {
      const key = FLAG_KEYS[arg];
      if (!key) throw new UsageError(`unknown option: ${arg}`);
      if (VALUE_FLAGS.has(key)) {
        if (i + 1 >= tokens.length) throw new UsageError(`missing value for ${arg}`);
        flags[key] = String(tokens[i + 1]);
        i++;
      } else {
        flags[key] = true;
      }
      continue;
    }
    if (sub === null) sub = arg;
    else positionals.push(arg);
  }
  return { sub, positionals, flags };
}

function validateLabel(value, field) {
  if (typeof value !== 'string' || !NAME_RE.test(value)) {
    throw new UsageError(
      `${field} must start with an alphanumeric character and contain only letters, digits, ".", "_" or "-" (max 64)`
    );
  }
}

function buildPayload(command, overall, dimensions, details, findings, anchored) {
  return {
    schema_version: SCHEMA_VERSION,
    command,
    overall,
    dimensions,
    details,
    findings,
    anchored,
  };
}

function emit(io, flags, payload, lines) {
  if (flags.json) {
    io.printJSON(payload);
    return;
  }
  for (const line of lines) io.print(line);
}

function dimensionStatus(dimensions, key) {
  const dim = dimensions && dimensions[key];
  if (!dim || typeof dim.status !== 'string') return 'NOT_CHECKED';
  return dim.status;
}

function tableLines(dimensions) {
  const lines = ['', 'VisionGuard Assurance', ''];
  for (const [key, label] of DIMENSION_LABELS) {
    lines.push(`  ${label.padEnd(21)} ${dimensionStatus(dimensions, key)}`);
  }
  return lines;
}

function anchorLine(report) {
  const value = report && report.anchored !== undefined && report.anchored !== null ? report.anchored : null;
  return `  Anchored: ${value === true ? 'yes' : value === false ? 'no' : 'no anchor supplied'}`;
}

function findingLines(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return [];
  const lines = ['', 'Findings:'];
  for (const item of findings) {
    const where = item.path ? ` ${item.path}` : '';
    lines.push(`  [${item.severity}] ${item.rule}${where}: ${item.detail}`);
  }
  return lines;
}

function statusExit(status) {
  if (status === 'PASS') return EXIT_OK;
  if (status === 'FAIL') return EXIT_VIOLATION;
  return EXIT_INCOMPLETE;
}

function scopedOverall(status) {
  if (status === 'PASS') return 'VERIFIED';
  if (status === 'FAIL') return 'INTEGRITY VIOLATION';
  return 'INCOMPLETE';
}

function exitRank(code) {
  if (code === EXIT_VIOLATION) return 3;
  if (code === EXIT_INCOMPLETE) return 2;
  return 1;
}

function worstExit(a, b) {
  return exitRank(b) > exitRank(a) ? b : a;
}

function vgErrorExit(err) {
  if (err.code === ERROR_CODES.VG_NOT_REGISTERED) return EXIT_INCOMPLETE;
  if (String(err.code).startsWith('VG_PATH_')) return EXIT_USAGE;
  return EXIT_ERROR;
}

function looksLikePath(value) {
  return value.includes('/') || value.includes('\\') || value.startsWith('.');
}

function normalizeArtifactTarget(root, value) {
  const text = String(value);
  if (path.isAbsolute(text)) {
    const rel = path.relative(root, text);
    if (rel && !rel.startsWith('..')) return rel.replace(/\\/g, '/');
  }
  return text.replace(/\\/g, '/');
}

function promptFor(question) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      resolve('');
      return;
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(String(answer || '').trim());
    });
  });
}

function registeredContributors(storeDir) {
  try {
    return fs
      .readdirSync(path.join(storeDir, 'keys'), { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
  } catch {
    return [];
  }
}

function resolveActorName(flags, storeDir) {
  if (flags.actor) {
    validateLabel(flags.actor, '--actor');
    return flags.actor;
  }
  const registered = registeredContributors(storeDir);
  if (registered.length === 1) return registered[0];
  if (registered.length === 0) {
    throw new UsageError('--actor is required: no contributor is registered yet (run "codesentry vision init" first)');
  }
  throw new UsageError(`--actor is required: ${registered.length} contributors are registered (${registered.join(', ')})`);
}

function resolveKeyFile(root, contributor, explicit) {
  if (explicit) {
    const abs = path.resolve(root, explicit);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
      throw new UsageError(`key file not found: ${explicit}`);
    }
    return abs;
  }
  const dir = path.join(keys.defaultKeyDir(), contributor);
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((name) => name.endsWith('.key')).sort();
  } catch {
    names = [];
  }
  if (names.length === 1) return path.join(dir, names[0]);
  if (names.length === 0) {
    throw new UsageError(`no private key found for "${contributor}"; pass --key-file <path>`);
  }
  throw new UsageError(`multiple private keys found for "${contributor}"; pass --key-file <path> to select one`);
}

function keyIdFromFile(keyFile) {
  const privateKey = keys.loadPrivateKey(keyFile);
  const der = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  return keys.keyIdFromDer(der);
}

function logHead(storeDir) {
  const log = provenance.readLogText(storeDir, {});
  if (!log.exists || !String(log.text || '').trim()) return [];
  const parsed = provenance.parseProvenanceLog(log.text, {});
  const valid = parsed.entries.filter((entry) => entry.record && entry.record.record_hash);
  if (valid.length === 0) return [];
  return [valid[valid.length - 1].record.record_hash];
}

function resolveTargetRef(refs, kind, name, version) {
  if (!refs || refs.length === 0) {
    throw new VgError(
      ERROR_CODES.VG_NOT_REGISTERED,
      `no ${kind} is registered; run "codesentry vision register-data <dir>" first`,
      {}
    );
  }
  if (!name && !version) {
    if (refs.length === 1) return refs[0];
    return null;
  }
  let matches = refs;
  if (name) matches = matches.filter((ref) => ref.name === name);
  if (version) matches = matches.filter((ref) => ref.version === version);
  if (matches.length === 0) {
    throw new VgError(ERROR_CODES.VG_NOT_REGISTERED, `${kind} "${name || refs[0].name}" is not registered`, {});
  }
  if (matches.length > 1) {
    throw new UsageError(`${matches.length} ${kind} versions are registered; pass --version <version>`);
  }
  return matches[0];
}

function fileRef(root, value, role) {
  const abs = path.resolve(root, value);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
    throw new UsageError(`${role} file not found: ${value}`);
  }
  const rel = path.relative(root, abs);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new UsageError(`${role} must be a file inside the project root: ${value}`);
  }
  const hashed = hashFile(abs, {});
  return { artifact: rel.replace(/\\/g, '/'), sha256: hashed.sha256 };
}

function pipelineFileRef(root, value, flag) {
  const abs = path.resolve(root, value);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
    throw new UsageError(`${flag} file not found: ${value}`);
  }
  const rel = path.relative(root, abs);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new UsageError(`${flag} must be inside the project root: ${value}`);
  }
  return rel.replace(/\\/g, '/');
}

function jsonFlag(root, value, flag) {
  const abs = path.resolve(root, value);
  let stats;
  try {
    stats = fs.statSync(abs);
  } catch {
    stats = null;
  }
  if (!stats || !stats.isFile()) {
    throw new UsageError(`${flag} file not found: ${value}`);
  }
  if (stats.size > DEFAULT_MAX_PARSE_BYTES) {
    throw new UsageError(`${flag} file exceeds the ${DEFAULT_MAX_PARSE_BYTES} byte limit: ${value}`);
  }
  let parsed;
  try {
    parsed = parseCanonical(fs.readFileSync(abs, 'utf8'), {
      maxBytes: DEFAULT_MAX_PARSE_BYTES,
      maxDepth: DEFAULT_MAX_DEPTH,
    });
  } catch (err) {
    throw new UsageError(`${flag} file is not valid JSON: ${err.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new UsageError(`${flag} must contain a JSON object`);
  }
  return parsed;
}

function registeredKeyId(storeDir, contributor) {
  try {
    const names = fs
      .readdirSync(path.join(storeDir, 'keys', contributor))
      .filter((name) => name.endsWith('.pub.json'))
      .sort();
    if (names.length === 0) return null;
    return names[0].slice(0, -'.pub.json'.length);
  } catch {
    return null;
  }
}

function findInferenceForTarget(root, storeDir, target) {
  const log = provenance.readLogText(storeDir, {});
  if (!log.exists || !String(log.text || '').trim()) return null;
  const parsed = provenance.parseProvenanceLog(log.text, {});
  const normalized = normalizeArtifactTarget(root, target);
  let match = null;
  for (const entry of parsed.entries) {
    const record = entry.record;
    if (!record || record.kind !== 'inference_recorded') continue;
    if (record.record_id === target) {
      match = record;
      continue;
    }
    for (const item of record.outputs) {
      const ref = provenance.parseArtifactRef(item.artifact);
      const node = ref ? ref.ref : String(item.artifact);
      if (node === target || node === normalized) {
        match = record;
        break;
      }
    }
  }
  return match;
}

function resolveSignedRef(storeDir, value, kind) {
  const parsedRef = provenance.parseArtifactRef(value);
  let name;
  let version;
  if (parsedRef && parsedRef.type === kind) {
    name = parsedRef.name;
    version = parsedRef.version;
    const exists = listManifestRefs(storeDir, kind).some(
      (ref) => ref.name === name && ref.version === version
    );
    if (!exists) {
      throw new VgError(ERROR_CODES.VG_NOT_REGISTERED, `${kind} "${value}" is not registered`, {});
    }
  } else {
    const refs = listManifestRefs(storeDir, kind).filter((ref) => ref.name === value);
    if (refs.length === 0) {
      throw new VgError(ERROR_CODES.VG_NOT_REGISTERED, `${kind} "${value}" is not registered`, {});
    }
    if (refs.length > 1) {
      throw new UsageError(
        `${refs.length} versions are registered for ${kind} "${value}"; pass ${kind}/${value}@<version>`
      );
    }
    name = refs[0].name;
    version = refs[0].version;
  }
  if (kind === 'model') {
    const manifestDoc = store.loadModelManifest(storeDir, name, version, {});
    return { ref: `model/${name}@${version}`, sha256: manifestDoc.sha256 };
  }
  const manifestDoc = store.loadPipelineManifest(storeDir, name, version, {});
  return {
    ref: `pipeline/${name}@${version}`,
    sha256: String(manifestDoc.pipeline_id).replace(/^sha256:/, ''),
  };
}

function dimensionDetailLines(report, verbose) {
  const dims = report.dimensions || {};
  const lines = [];
  for (const entry of (dims.dataset && dims.dataset.entries) || []) {
    const located = entry.located === false ? ' (files not found)' : '';
    const at = verbose && entry.path ? ` at ${entry.path}` : '';
    lines.push(`  dataset ${entry.name}@${entry.version}: ${entry.status}${located}${at}`);
  }
  for (const entry of (dims.model && dims.model.entries) || []) {
    const at = verbose && entry.path ? ` at ${entry.path}` : '';
    lines.push(`  model ${entry.id}@${entry.version}: ${entry.status}${at}`);
  }
  for (const entry of (dims.pipeline && dims.pipeline.entries) || []) {
    lines.push(`  pipeline ${entry.name}@${entry.version}: ${entry.status}`);
  }
  const prov = dims.provenance;
  if (prov && typeof prov.record_count === 'number') {
    lines.push(
      `  provenance: ${prov.record_count} record(s), ${prov.unsigned_count || 0} unsigned, head ${String(prov.head || '').slice(0, 16)}`
    );
  }
  if (lines.length === 0) return lines;
  lines.unshift('');
  lines.unshift('Details:');
  lines.unshift('');
  return lines;
}

function nextForOverall(overall) {
  if (overall === 'VERIFIED') return 'Next: nothing — all dimensions verified.';
  if (overall === 'INTEGRITY VIOLATION') {
    return 'Next: review the findings above and run "codesentry vision provenance --verify" for chain details.';
  }
  return 'Next: register missing artifacts (vision register-data / register-model), sign them, or anchor with --expected-head <head>.';
}

function nextForDimension(status, dimension) {
  if (status === 'PASS') return `Next: nothing — ${dimension} integrity verified.`;
  if (status === 'FAIL') {
    return `Next: investigate the findings above; re-register ${dimension} only if the change is intentional.`;
  }
  return `Next: register and sign ${dimension} (vision register-data / register-model / record-pipeline) to move this dimension to PASS.`;
}

async function cmdInit(ctx, io) {
  const { root, storeDir, flags } = ctx;
  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY && !flags.json);
  let actor = flags.actor || '';
  if (!actor && interactive) actor = await promptFor('Contributor name: ');
  if (!actor) throw new UsageError('--actor is required when running non-interactively');
  validateLabel(actor, '--actor');
  let keyFile = null;
  if (flags.keyFile) {
    keyFile = path.resolve(root, flags.keyFile);
    if (!fs.existsSync(keyFile) || !fs.statSync(keyFile).isFile()) {
      throw new UsageError(`key file not found: ${flags.keyFile}`);
    }
  } else if (!interactive) {
    throw new UsageError('--key-file is required when running non-interactively');
  }
  const vg = createVisionGuard({ root, storeDir, ...(keyFile ? { keyFile } : {}) });
  const reg = await vg.init({ contributor: actor });
  const relStore = path.relative(root, storeDir).replace(/\\/g, '/');
  const details = {
    contributor: reg.contributor,
    key_id: reg.key_id,
    record_id: reg.record_id,
    operations: reg.operations,
    key_file: reg.key_file,
    store: relStore || '.visionguard',
  };
  const payload = buildPayload('init', 'OK', {}, details, [], null);
  const lines = [
    '',
    'VisionGuard store initialized',
    '',
    `  Contributor: ${reg.contributor}`,
    `  Key ID:      ${reg.key_id}`,
    `  Store:       ${details.store}`,
    `  Private key: ${reg.key_file}`,
    '',
    'Next: codesentry vision register-data <dir>',
  ];
  emit(io, flags, payload, lines);
  return EXIT_OK;
}

async function cmdRegisterData(ctx, io) {
  const { root, storeDir, flags, positionals } = ctx;
  const dirArg = positionals[0];
  if (!dirArg) throw new UsageError('register-data requires a <dir> argument');
  const dirAbs = path.resolve(root, dirArg);
  if (!fs.existsSync(dirAbs) || !fs.statSync(dirAbs).isDirectory()) {
    throw new UsageError(`dataset directory not found: ${dirArg}`);
  }
  const dirRel = path.relative(root, dirAbs);
  if (!dirRel || dirRel.startsWith('..') || path.isAbsolute(dirRel)) {
    throw new UsageError(`dataset directory must be inside the project root: ${dirArg}`);
  }
  const name = flags.name || path.basename(dirAbs);
  const version = flags.version || '1.0.0';
  validateLabel(name, '--name');
  validateLabel(version, '--version');
  const contributor = resolveActorName(flags, storeDir);
  const keyFile = resolveKeyFile(root, contributor, flags.keyFile);
  const actor = { contributor, key_id: keyIdFromFile(keyFile) };
  const vg = createVisionGuard({ root, storeDir, keyFile });
  const manifest = await vg.registerDataset({ path: dirAbs, name, version, actor });
  const merkle = String(manifest.merkle_root).replace(/^sha256:/, '');
  const binding = await vg.recordArtifact({
    artifact: `dataset/${name}@${version}`,
    sha256: merkle,
    actor,
    parents: logHead(storeDir),
    metadata: { files: manifest.file_count },
  });
  const details = {
    name,
    version,
    files: manifest.file_count,
    total_bytes: manifest.total_bytes,
    merkle_root: manifest.merkle_root,
    binding_record: binding.record_hash,
    actor: contributor,
    key_file: keyFile,
  };
  const payload = buildPayload('register-data', 'REGISTERED', {}, details, [], null);
  const lines = [
    '',
    'Dataset registered and binding signed',
    '',
    `  Name:       ${name}@${version}`,
    `  Files:      ${manifest.file_count}`,
    `  Merkle:     ${manifest.merkle_root}`,
    `  Binding:    ${binding.record_hash.slice(0, 16)}...`,
    `  Actor:      ${contributor}`,
    '',
    `Next: codesentry vision verify-data ${dirArg}`,
  ];
  emit(io, flags, payload, lines);
  return EXIT_OK;
}

async function cmdVerifyData(ctx, io) {
  const { root, storeDir, flags, positionals } = ctx;
  const dirArg = positionals[0] || null;
  const refs = listManifestRefs(storeDir, 'dataset');
  const target = resolveTargetRef(refs, 'dataset', flags.name, flags.version);
  const hint = dirArg ? path.resolve(root, dirArg) : null;
  const report = runAssurance({
    root,
    storeDir,
    strict: flags.strict === true,
    dataset: {
      ...(target ? { name: target.name, version: target.version } : {}),
      ...(hint && fs.existsSync(hint) ? { path: hint } : {}),
    },
  });
  const dim = report.dimensions.dataset || { status: 'NOT_CHECKED', entries: [] };
  const entry =
    target
      ? (dim.entries || []).find((item) => item.name === target.name && item.version === target.version) || dim
      : dim;
  const status = entry.status;
  const findings = report.findings.filter((item) => String(item.rule).startsWith('VG-DATA-'));
  const exitCode = statusExit(status);
  const details = {
    name: target ? target.name : null,
    version: target ? target.version : null,
    files: entry.files === undefined ? null : entry.files,
    signed_binding: entry.signed_binding === undefined ? null : entry.signed_binding,
    merkle_root: entry.merkle_root || null,
    store: report.store,
    warnings: report.warnings,
  };
  const payload = buildPayload('verify-data', scopedOverall(status), { dataset: dim }, details, findings, report.anchored);
  const lines = tableLines(report.dimensions);
  lines.push('');
  lines.push(`  Dataset: ${status}`);
  lines.push(anchorLine(report));
  if (target) {
    const extra = [
      entry.files !== undefined && entry.files !== null ? `${entry.files} files` : null,
      entry.signed_binding === true ? 'signed binding' : null,
      flags.verbose && entry.path ? `at ${entry.path}` : null,
    ].filter(Boolean);
    lines.push(`  ${target.name}@${target.version}: ${status}${extra.length ? ` (${extra.join(', ')})` : ''}`);
  }
  lines.push(...findingLines(findings));
  lines.push('');
  lines.push(nextForDimension(status, 'dataset'));
  emit(io, flags, payload, lines);
  return exitCode;
}

async function cmdRegisterModel(ctx, io) {
  const { root, storeDir, flags, positionals } = ctx;
  const fileArg = positionals[0];
  if (!fileArg) throw new UsageError('register-model requires a <file> argument');
  const abs = path.resolve(root, fileArg);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
    throw new UsageError(`model file not found: ${fileArg}`);
  }
  const modelRel = path.relative(root, abs);
  if (!modelRel || modelRel.startsWith('..') || path.isAbsolute(modelRel)) {
    throw new UsageError(`model file must be inside the project root: ${fileArg}`);
  }
  const id = flags.id || path.basename(abs, path.extname(abs));
  const version = flags.version || '1.0.0';
  validateLabel(id, '--id');
  validateLabel(version, '--version');
  const hashed = hashFile(abs, {});
  const head = modelLib.readSniffHead(abs, hashed);
  const sniff = modelLib.sniffFormat(head, hashed.size, path.basename(abs));
  let format;
  if (flags.format) {
    if (!modelLib.MODEL_FORMATS.includes(flags.format)) {
      throw new UsageError(`--format must be one of: ${modelLib.MODEL_FORMATS.join(', ')}`);
    }
    if (!sniff.magicOk) {
      throw new UsageError(`file does not carry the "${flags.format}" magic signature (${sniff.detail})`);
    }
    if (modelLib.family(flags.format) !== modelLib.family(sniff.detected)) {
      throw new UsageError(
        `declared format "${flags.format}" does not match file content detected as "${sniff.detected}" (${sniff.detail})`
      );
    }
    format = flags.format;
  } else {
    if (!sniff.magicOk || !modelLib.MODEL_FORMATS.includes(sniff.detected)) {
      throw new UsageError(`cannot detect a supported model format for ${fileArg} (${sniff.detail}); pass --format`);
    }
    format = sniff.detected;
  }
  const contributor = resolveActorName(flags, storeDir);
  const actor = { contributor, key_id: registeredKeyId(storeDir, contributor) };
  const vg = createVisionGuard({ root, storeDir });
  const manifest = await vg.registerModel({ path: abs, id, version, format, actor, hashed });
  const details = {
    id,
    version,
    format: manifest.format,
    detected_format: manifest.detected_format,
    sha256: manifest.sha256,
    size: manifest.size,
    actor: contributor,
  };
  const payload = buildPayload('register-model', 'REGISTERED', {}, details, [], null);
  const lines = [
    '',
    'Model registered',
    '',
    `  ID:         ${id}@${version}`,
    `  Format:     ${manifest.format} (detected: ${manifest.detected_format})`,
    `  SHA-256:    ${manifest.sha256}`,
    `  Size:       ${manifest.size} bytes`,
    `  Actor:      ${contributor}`,
    '',
    `Next: codesentry vision record-pipeline --name <name> --version <version> --code <file> --actor <name>`,
  ];
  emit(io, flags, payload, lines);
  return EXIT_OK;
}

async function cmdVerifyModel(ctx, io) {
  const { root, storeDir, flags, positionals } = ctx;
  const arg = positionals[0];
  if (!arg) throw new UsageError('verify-model requires a <file|id> argument');
  const refs = listManifestRefs(storeDir, 'model');
  if (refs.length === 0) {
    throw new VgError(
      ERROR_CODES.VG_NOT_REGISTERED,
      'no model is registered; run "codesentry vision register-model <file>" first',
      {}
    );
  }
  let target = null;
  let hint = null;
  let hintHashed = null;
  const abs = path.resolve(root, arg);
  const isFile = fs.existsSync(abs) && fs.statSync(abs).isFile();
  if (isFile) {
    const hashed = hashFile(abs, {});
    for (const ref of refs) {
      let manifestDoc;
      try {
        manifestDoc = store.loadModelManifest(storeDir, ref.name, ref.version, {});
      } catch {
        continue;
      }
      if (manifestDoc.sha256 === hashed.sha256) {
        target = ref;
        hint = abs;
        hintHashed = hashed;
        break;
      }
    }
    if (!target) {
      const baseId = path.basename(abs, path.extname(abs));
      const byBasename = refs.filter((ref) => ref.name === baseId);
      if (byBasename.length > 0) {
        target = resolveTargetRef(byBasename, 'model', baseId, flags.version);
        hint = abs;
        hintHashed = hashed;
      }
    }
    if (!target) {
      throw new VgError(ERROR_CODES.VG_NOT_REGISTERED, `model file "${arg}" does not match any registered model`, {});
    }
    if (flags.version && target.version !== flags.version) {
      throw new VgError(
        ERROR_CODES.VG_NOT_REGISTERED,
        `model file "${arg}" matches ${target.name}@${target.version}, not @${flags.version}`,
        {}
      );
    }
  } else {
    const byId = refs.filter((ref) => ref.name === arg);
    if (byId.length > 0) {
      target = resolveTargetRef(byId, 'model', arg, flags.version);
    } else {
      const baseId = path.basename(arg, path.extname(arg));
      const byBase = refs.filter((ref) => ref.name === baseId);
      if (byBase.length > 0) {
        target = resolveTargetRef(byBase, 'model', baseId, flags.version);
      } else if (looksLikePath(arg)) {
        if (refs.length > 1) {
          throw new VgError(
            ERROR_CODES.VG_NOT_REGISTERED,
            `model file "${arg}" was not found and ${refs.length} models are registered; pass a registered model id`,
            {}
          );
        }
        target = refs[0];
      } else {
        throw new VgError(ERROR_CODES.VG_NOT_REGISTERED, `model "${arg}" is not registered`, {});
      }
    }
  }
  const report = runAssurance({
    root,
    storeDir,
    strict: flags.strict === true,
    model: {
      name: target.name,
      version: target.version,
      ...(hint ? { path: hint } : {}),
      ...(hint && hintHashed ? { hashed: hintHashed } : {}),
    },
  });
  const dim = report.dimensions.model || { status: 'NOT_CHECKED', entries: [] };
  const entry =
    (dim.entries || []).find((item) => item.id === target.name && item.version === target.version) || dim;
  const status = entry.status;
  const findings = report.findings.filter((item) => String(item.rule).startsWith('VG-MODEL-'));
  const exitCode = statusExit(status);
  const details = {
    id: target.name,
    version: target.version,
    format: entry.format || null,
    sha256: entry.sha256 || null,
    located: entry.located === undefined ? null : entry.located,
    store: report.store,
    warnings: report.warnings,
  };
  const payload = buildPayload('verify-model', scopedOverall(status), { model: dim }, details, findings, report.anchored);
  const lines = tableLines(report.dimensions);
  lines.push('');
  lines.push(`  Model: ${status}`);
  lines.push(anchorLine(report));
  const extra = [entry.format ? entry.format : null, flags.verbose && entry.path ? `at ${entry.path}` : null].filter(Boolean);
  lines.push(`  ${target.name}@${target.version}: ${status}${extra.length ? ` (${extra.join(', ')})` : ''}`);
  lines.push(...findingLines(findings));
  lines.push('');
  lines.push(nextForDimension(status, 'model'));
  emit(io, flags, payload, lines);
  return exitCode;
}

async function cmdRecordPipeline(ctx, io) {
  const { root, storeDir, flags } = ctx;
  if (!flags.name) throw new UsageError('--name <name> is required');
  if (!flags.version) throw new UsageError('--version <version> is required');
  validateLabel(flags.name, '--name');
  validateLabel(flags.version, '--version');
  const contributor = resolveActorName(flags, storeDir);
  const keyFile = resolveKeyFile(root, contributor, flags.keyFile);
  const actor = { contributor, key_id: keyIdFromFile(keyFile) };
  const spec = { root };
  if (flags.code) spec.code = { files: [{ path: pipelineFileRef(root, flags.code, '--code') }] };
  if (flags.deps) spec.dependency_lock = { path: pipelineFileRef(root, flags.deps, '--deps') };
  if (flags.preprocess) spec.preprocess_config = { path: pipelineFileRef(root, flags.preprocess, '--preprocess') };
  if (flags.params) spec.parameters = jsonFlag(root, flags.params, '--params');
  if (flags.runtime) spec.runtime = jsonFlag(root, flags.runtime, '--runtime');
  const vg = createVisionGuard({ root, storeDir, keyFile });
  const manifest = await vg.recordPipeline({ name: flags.name, version: flags.version, actor, ...spec });
  const details = {
    name: flags.name,
    version: flags.version,
    pipeline_id: manifest.pipeline_id,
    code_files: spec.code ? spec.code.files.map((item) => item.path) : [],
    actor: contributor,
    key_file: keyFile,
  };
  const payload = buildPayload('record-pipeline', 'RECORDED', {}, details, [], null);
  const lines = [
    '',
    'Pipeline identity recorded and signed',
    '',
    `  Name:       ${flags.name}@${flags.version}`,
    `  Pipeline:   ${manifest.pipeline_id}`,
    `  Code files: ${details.code_files.length}`,
    `  Actor:      ${contributor}`,
    '',
    'Next: codesentry vision record-inference <input> <output> --model <id> --pipeline <name> --actor <name>',
  ];
  emit(io, flags, payload, lines);
  return EXIT_OK;
}

async function cmdRecordInference(ctx, io) {
  const { root, storeDir, flags, positionals } = ctx;
  const inputArg = positionals[0];
  const outputArg = positionals[1];
  if (!inputArg || !outputArg) {
    throw new UsageError('record-inference requires <input> <output> arguments');
  }
  if (!flags.model) throw new UsageError('--model <id> is required');
  if (!flags.pipeline) throw new UsageError('--pipeline <name> is required');
  const contributor = resolveActorName(flags, storeDir);
  const keyFile = resolveKeyFile(root, contributor, flags.keyFile);
  const actor = { contributor, key_id: keyIdFromFile(keyFile) };
  const input = fileRef(root, inputArg, 'input');
  const output = fileRef(root, outputArg, 'output');
  const model = resolveSignedRef(storeDir, flags.model, 'model');
  const pipeline = resolveSignedRef(storeDir, flags.pipeline, 'pipeline');
  const vg = createVisionGuard({ root, storeDir, keyFile });
  const record = await vg.recordInference({
    input,
    output,
    model: { artifact: model.ref, sha256: model.sha256 },
    pipeline: { artifact: pipeline.ref, sha256: pipeline.sha256 },
    actor,
    parents: logHead(storeDir),
  });
  const details = {
    record_id: record.record_id,
    input: input.artifact,
    output: output.artifact,
    model: model.ref,
    pipeline: pipeline.ref,
    actor: contributor,
    key_file: keyFile,
  };
  const payload = buildPayload('record-inference', 'RECORDED', {}, details, [], null);
  const lines = [
    '',
    'Inference recorded and signed',
    '',
    `  Record:     ${record.record_id}`,
    `  Input:      ${input.artifact}`,
    `  Output:     ${output.artifact}`,
    `  Model:      ${model.ref}`,
    `  Pipeline:   ${pipeline.ref}`,
    `  Actor:      ${contributor}`,
    '',
    `Next: codesentry vision verify-output ${outputArg}`,
  ];
  emit(io, flags, payload, lines);
  return EXIT_OK;
}

async function cmdVerifyOutput(ctx, io) {
  const { root, storeDir, flags, positionals } = ctx;
  const arg = positionals[0];
  if (!arg) throw new UsageError('verify-output requires an <output> argument');
  const record = findInferenceForTarget(root, storeDir, arg);
  if (!record) {
    throw new VgError(ERROR_CODES.VG_NOT_REGISTERED, `no inference record matches "${arg}"`, {});
  }
  const report = runAssurance({
    root,
    storeDir,
    strict: flags.strict === true,
    inference: { recordId: record.record_id },
  });
  const dim = report.dimensions.output || { status: 'NOT_CHECKED', entries: [] };
  const entry =
    (dim.entries || []).find((item) => item.record_id === record.record_id) || dim;
  const status = entry.status;
  const findings = report.findings.filter(
    (item) => String(item.rule).startsWith('VG-OUT-') || String(item.rule).startsWith('VG-INFER-')
  );
  const exitCode = statusExit(status);
  const details = {
    record_id: record.record_id,
    output: normalizeArtifactTarget(root, arg),
    store: report.store,
    warnings: report.warnings,
  };
  const payload = buildPayload(
    'verify-output',
    scopedOverall(status),
    { output: dim, inference: report.dimensions.inference || { status: 'NOT_CHECKED' } },
    details,
    findings,
    report.anchored
  );
  const lines = tableLines(report.dimensions);
  lines.push('');
  lines.push(`  Output: ${status}`);
  lines.push(anchorLine(report));
  lines.push(`  record ${record.record_id}: ${status}`);
  lines.push(...findingLines(findings));
  lines.push('');
  lines.push(nextForDimension(status, 'output'));
  emit(io, flags, payload, lines);
  return exitCode;
}

function provenanceSummary(storeDir, verbose) {
  const log = provenance.readLogText(storeDir, {});
  if (!log.exists || !String(log.text || '').trim()) {
    return { records: 0, contributors: [], head: null, store_present: fs.existsSync(storeDir) };
  }
  const parsed = provenance.parseProvenanceLog(log.text, {});
  const records = parsed.entries.filter((entry) => entry.record).map((entry) => entry.record);
  const contributorSet = new Set();
  for (const record of records) {
    if (record.actor && record.actor.contributor) contributorSet.add(record.actor.contributor);
  }
  const summary = {
    records: records.length,
    contributors: [...contributorSet].sort(),
    head: records.length > 0 ? records[records.length - 1].record_hash : null,
    store_present: true,
  };
  if (verbose) {
    summary.record_list = records.map((record) => ({
      record_id: record.record_id,
      kind: record.kind,
      contributor: record.actor ? record.actor.contributor : null,
    }));
  }
  return summary;
}

async function cmdProvenance(ctx, io) {
  const { root, storeDir, flags } = ctx;
  const wantVerify = flags.verify === true;
  const wantGraph = flags.graph === true;
  const wantArtifact = typeof flags.artifact === 'string' && flags.artifact.length > 0;
  let exitCode = EXIT_OK;
  let report = null;
  if (wantVerify || wantGraph) report = runAssurance({ root, storeDir });
  const dimensions = {};
  const findings = [];
  let anchored = null;
  const details = {};
  let verifyStatus = null;
  if (wantVerify) {
    const dim = (report.dimensions && report.dimensions.provenance) || { status: 'NOT_CHECKED' };
    dimensions.provenance = dim;
    verifyStatus = dim.status;
    findings.push(...report.findings.filter((item) => String(item.rule).startsWith('VG-PROV-')));
    anchored = report.anchored;
    details.store = report.store;
    details.head = dim.head === undefined ? null : dim.head;
    details.expected_head = dim.expected_head === undefined ? null : dim.expected_head;
    details.records = dim.record_count === undefined ? null : dim.record_count;
    details.unsigned = dim.unsigned_count === undefined ? null : dim.unsigned_count;
    exitCode = worstExit(exitCode, statusExit(verifyStatus));
  }
  if (wantArtifact) {
    const normalized = normalizeArtifactTarget(root, flags.artifact);
    const vg = createVisionGuard({ root, storeDir });
    let chain = await vg.lineage({ artifact: normalized });
    if (chain.length === 0 && normalized !== flags.artifact) {
      chain = await vg.lineage({ artifact: flags.artifact });
    }
    details.lineage = {
      artifact: flags.artifact,
      found: chain.length > 0,
      records: chain.length,
      chain: chain.map((record) => ({
        record_id: record.record_id,
        kind: record.kind,
        contributor: record.actor ? record.actor.contributor : null,
      })),
    };
    if (chain.length === 0) exitCode = worstExit(exitCode, EXIT_INCOMPLETE);
  }
  if (wantGraph && report) {
    details.graph = {
      artifacts: report.graph.artifacts,
      contributors: report.graph.contributors,
      trusts: report.graph.trusts,
      derivedFrom: report.graph.derivedFrom,
    };
  }
  if (!wantVerify && !wantGraph && !wantArtifact) {
    Object.assign(details, provenanceSummary(storeDir, flags.verbose === true));
  }
  let overall;
  if (wantVerify) {
    overall = scopedOverall(verifyStatus);
    if (overall === 'VERIFIED' && exitCode === EXIT_INCOMPLETE) overall = 'INCOMPLETE';
  } else {
    overall = exitCode === EXIT_INCOMPLETE ? 'INCOMPLETE' : 'OK';
  }
  const payload = buildPayload('provenance', overall, dimensions, details, findings, anchored);
  const lines = [];
  if (wantVerify) {
    lines.push(...tableLines(report.dimensions));
    lines.push('');
    lines.push(`  Provenance: ${verifyStatus}`);
    lines.push(anchorLine(report));
    lines.push(...findingLines(findings));
  } else if (!wantArtifact && !wantGraph) {
    lines.push('', 'VisionGuard Provenance', '');
    if (details.records !== undefined) {
      lines.push(`  Records:      ${details.records}`);
      lines.push(`  Contributors: ${details.contributors.join(', ') || '(none)'}`);
      lines.push(`  Head:         ${details.head || '(empty)'}`);
      if (flags.verbose && details.record_list) {
        lines.push('');
        for (const item of details.record_list) {
          lines.push(`  ${item.kind} by ${item.contributor} (${String(item.record_id || '').slice(0, 16)})`);
        }
      }
    } else {
      lines.push('  No provenance summary available.');
    }
  }
  if (wantArtifact) {
    lines.push('');
    if (details.lineage.found) {
      lines.push(`Lineage for ${flags.artifact}:`);
      details.lineage.chain.forEach((item, index) => {
        lines.push(`  ${index + 1}. ${item.kind} by ${item.contributor} (${String(item.record_id || '').slice(0, 16)})`);
      });
    } else {
      lines.push(`No provenance record references "${flags.artifact}".`);
    }
  }
  if (wantGraph && details.graph) {
    lines.push('');
    lines.push(
      `Provenance graph: ${details.graph.artifacts.length} artifacts, ${details.graph.contributors.length} contributors, ${details.graph.trusts.length} trust links, ${details.graph.derivedFrom.length} derivations`
    );
    if (details.graph.contributors.length > 0) {
      lines.push(`  Contributors: ${details.graph.contributors.map((item) => item.contributor).join(', ')}`);
    }
    if (flags.verbose) {
      for (const edge of details.graph.trusts) lines.push(`  trust  ${edge.contributor} -> ${edge.ref}`);
      for (const edge of details.graph.derivedFrom) lines.push(`  derive ${edge.to} <- ${edge.from}`);
    }
  }
  lines.push('');
  if (wantVerify) lines.push(nextForOverall(scopedOverall(verifyStatus)));
  else if (!wantArtifact && !wantGraph) lines.push('Next: codesentry vision provenance --verify');
  else lines.push('Next: codesentry vision verify');
  emit(io, flags, payload, lines);
  return exitCode;
}

async function cmdVerify(ctx, io) {
  const { root, storeDir, flags } = ctx;
  if (flags.expectedHead && flags.anchorFile) {
    throw new UsageError('--expected-head and --anchor-file are mutually exclusive');
  }
  let anchor;
  if (flags.expectedHead) {
    anchor = { expectedHead: flags.expectedHead };
  } else if (flags.anchorFile) {
    const anchorAbs = path.resolve(root, flags.anchorFile);
    if (!fs.existsSync(anchorAbs) || !fs.statSync(anchorAbs).isFile()) {
      throw new UsageError(`anchor file not found: ${flags.anchorFile}`);
    }
    anchor = { anchorFilePath: anchorAbs };
  }
  const report = runAssurance({
    root,
    storeDir,
    strict: flags.strict === true,
    ...(anchor ? { anchor } : {}),
  });
  const overall = report.overall;
  let exitCode;
  if (overall === 'VERIFIED') exitCode = EXIT_OK;
  else if (overall === 'INTEGRITY VIOLATION') exitCode = EXIT_VIOLATION;
  else exitCode = flags.requireVerified ? EXIT_VIOLATION : EXIT_INCOMPLETE;
  const payload = buildPayload(
    'verify',
    overall,
    report.dimensions,
    { store: report.store, warnings: report.warnings },
    report.findings,
    report.anchored
  );
  const lines = tableLines(report.dimensions);
  lines.push('');
  lines.push(`  Overall: ${overall}`);
  lines.push(anchorLine(report));
  lines.push(...dimensionDetailLines(report, flags.verbose === true));
  lines.push(...findingLines(report.findings));
  lines.push('');
  lines.push(nextForOverall(overall));
  emit(io, flags, payload, lines);
  return exitCode;
}

const HANDLERS = Object.freeze({
  init: cmdInit,
  'register-data': cmdRegisterData,
  'verify-data': cmdVerifyData,
  'register-model': cmdRegisterModel,
  'verify-model': cmdVerifyModel,
  'record-pipeline': cmdRecordPipeline,
  'record-inference': cmdRecordInference,
  'verify-output': cmdVerifyOutput,
  provenance: cmdProvenance,
  verify: cmdVerify,
});

async function runVisionCli(argv, io, options = {}) {
  const root = path.resolve(options.root || process.cwd());
  let jsonMode = Array.isArray(argv) && argv.includes('--json');
  let commandName = 'vision';
  try {
    const parsed = parseVisionArgs(argv);
    jsonMode = parsed.flags.json === true;
    if (parsed.flags.help || parsed.sub === 'help') {
      io.print(usageText());
      return EXIT_OK;
    }
    if (!parsed.sub) throw new UsageError('a subcommand is required');
    commandName = parsed.sub;
    const handler = HANDLERS[parsed.sub];
    if (!handler) throw new UsageError(`unknown command: ${parsed.sub}`);
    const allowed = ALLOWED[parsed.sub];
    for (const key of Object.keys(parsed.flags)) {
      if (!allowed.includes(key)) {
        throw new UsageError(`option ${KEY_FLAG_TEXT[key] || key} is not valid for "vision ${parsed.sub}"`);
      }
    }
    const maxPositionals = MAX_POSITIONALS[parsed.sub];
    if (parsed.positionals.length > maxPositionals) {
      throw new UsageError(`unexpected argument: ${parsed.positionals[maxPositionals]}`);
    }
    const ctx = {
      root,
      storeDir: parsed.flags.store ? path.resolve(root, parsed.flags.store) : path.join(root, '.visionguard'),
      flags: parsed.flags,
      positionals: parsed.positionals,
    };
    return await handler(ctx, io);
  } catch (err) {
    if (err instanceof UsageError || (err && err.usage === true)) {
      io.printError(`Error: ${err.message}`);
      io.printError('Run "codesentry vision --help" for usage.');
      return EXIT_USAGE;
    }
    const code = isVgError(err) ? err.code : 'VG_INTERNAL';
    const exitCode = isVgError(err) ? vgErrorExit(err) : EXIT_ERROR;
    if (jsonMode) {
      io.printJSON(
        buildPayload(
          commandName,
          code === ERROR_CODES.VG_NOT_REGISTERED ? 'INCOMPLETE' : 'ERROR',
          {},
          { error: { code, message: err.message } },
          [],
          null
        )
      );
    } else {
      io.printError(`Error [${code}]: ${err.message}`);
    }
    return exitCode;
  }
}

module.exports = {
  runVisionCli,
  parseVisionArgs,
  usageText,
};
