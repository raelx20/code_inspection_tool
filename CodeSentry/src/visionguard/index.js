'use strict';

const path = require('node:path');
const { ERROR_CODES, VgError } = require('./errors');
const { runAssurance, overallVerdict } = require('./assurance');
const { reportToFindings } = require('./findings');
const { aggregate } = require('../core/aggregation');
const { score } = require('../core/scoring');
const { verdict } = require('../core/verdict');
const provenance = require('./provenance');
const store = require('./store');
const manifest = require('./manifest');
const model = require('./model');
const pipeline = require('./pipeline');
const inference = require('./inference');

function createVisionGuard(options = {}) {
  if (typeof options.root !== 'string' || options.root.length === 0) {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'root is required');
  }
  const root = path.resolve(options.root);
  const storeDir = options.storeDir ? path.resolve(options.storeDir) : path.join(root, '.visionguard');
  const strict = options.strict === true;
  const limits = options.limits;
  const anchor = options.anchor || null;
  const now = options.now;
  const state = {
    actor: null,
    keyFile: typeof options.keyFile === 'string' && options.keyFile.length > 0 ? options.keyFile : null,
  };

  const currentActor = (explicit) => {
    if (explicit) return explicit;
    if (state.actor) return state.actor;
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'an actor is required; call init() first or pass actor');
  };
  const currentKeyFile = () => {
    if (state.keyFile) return state.keyFile;
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'a signing key is required; call init() first');
  };

  return {
    root,
    storeDir,

    async init(initOptions = {}) {
      const registration = provenance.registerContributor({
        storeDir,
        keyDir: initOptions.keyDir || options.keyDir,
        keyFile: initOptions.keyFile || options.keyFile,
        contributor: initOptions.contributor,
        operations: initOptions.operations,
        limits,
        now: initOptions.now === undefined ? now : initOptions.now,
      });
      state.actor = { contributor: registration.contributor, key_id: registration.key_id };
      state.keyFile = registration.privateKeyPath;
      return {
        contributor: registration.contributor,
        key_id: registration.key_id,
        record_id: registration.record.record_id,
        operations: registration.operations,
        key_file: registration.privateKeyPath,
      };
    },

    async registerDataset(registerOptions = {}) {
      return manifest.registerDataset({
        path: registerOptions.path,
        name: registerOptions.name,
        version: registerOptions.version,
        policy: registerOptions.policy,
        strict: registerOptions.strict === undefined ? strict : registerOptions.strict,
        actor: currentActor(registerOptions.actor),
        storeDir,
        limits,
        now: registerOptions.now === undefined ? now : registerOptions.now,
      });
    },

    async verifyDataset(verifyOptions = {}) {
      const manifestDoc = store.loadDatasetManifest(storeDir, verifyOptions.name, verifyOptions.version, { limits });
      return manifest.verifyDataset({
        manifest: manifestDoc,
        path: verifyOptions.path,
        strict: verifyOptions.strict === undefined ? strict : verifyOptions.strict,
        limits,
        now: verifyOptions.now === undefined ? now : verifyOptions.now,
      });
    },

    async registerModel(registerOptions = {}) {
      return model.registerModel({
        path: registerOptions.path,
        id: registerOptions.id,
        version: registerOptions.version,
        format: registerOptions.format,
        metadata: registerOptions.metadata,
        hashed: registerOptions.hashed,
        actor: currentActor(registerOptions.actor),
        storeDir,
        limits,
        now: registerOptions.now === undefined ? now : registerOptions.now,
      });
    },

    async verifyModel(verifyOptions = {}) {
      const manifestDoc = store.loadModelManifest(storeDir, verifyOptions.id, verifyOptions.version, { limits });
      return model.verifyModel({
        manifest: manifestDoc,
        path: verifyOptions.path,
        limits,
        now: verifyOptions.now === undefined ? now : verifyOptions.now,
      });
    },

    async recordOperation(recordOptions = {}) {
      return provenance.recordOperation({
        storeDir,
        keyFile: currentKeyFile(),
        actor: currentActor(recordOptions.actor),
        operation: recordOptions.op,
        inputs: recordOptions.inputs,
        outputs: recordOptions.outputs,
        parents: recordOptions.parents,
        metadata: recordOptions.metadata,
        now: recordOptions.now === undefined ? now : recordOptions.now,
      });
    },

    async recordArtifact(recordOptions = {}) {
      return provenance.recordArtifact({
        storeDir,
        keyFile: currentKeyFile(),
        actor: currentActor(recordOptions.actor),
        artifact: recordOptions.artifact,
        sha256: recordOptions.sha256,
        parents: recordOptions.parents,
        metadata: recordOptions.metadata,
        now: recordOptions.now === undefined ? now : recordOptions.now,
      });
    },

    async recordPipeline(recordOptions = {}) {
      const { name, version, actor, now: recordNow, ...spec } = recordOptions;
      return pipeline.registerPipeline({
        ...spec,
        name,
        version,
        actor: currentActor(actor),
        keyFile: currentKeyFile(),
        storeDir,
        limits,
        now: recordNow === undefined ? now : recordNow,
      });
    },

    async recordInference(recordOptions = {}) {
      return inference.recordInference({
        storeDir,
        keyFile: currentKeyFile(),
        actor: currentActor(recordOptions.actor),
        input: recordOptions.input,
        model: recordOptions.model,
        pipeline: recordOptions.pipeline,
        output: recordOptions.output,
        params: recordOptions.params,
        metadata: recordOptions.metadata,
        output_mode: recordOptions.output_mode,
        parents: recordOptions.parents,
        now: recordOptions.now === undefined ? now : recordOptions.now,
      });
    },

    async verifyOutput(verifyOptions = {}) {
      return inference.verifyInference({
        storeDir,
        recordId: verifyOptions.recordId,
        root: verifyOptions.root || root,
        modelPath: verifyOptions.modelPath,
        limits,
        now: verifyOptions.now === undefined ? now : verifyOptions.now,
      });
    },

    async lineage(lineageOptions = {}) {
      const log = provenance.readLogText(storeDir, { limits });
      if (!log.exists || log.text.trim().length === 0) return [];
      const parsed = provenance.parseProvenanceLog(log.text, { limits });
      const target = String(lineageOptions.artifact || '');
      const indexByHash = new Map();
      for (const entry of parsed.entries) indexByHash.set(entry.record.record_hash, entry);
      const queue = [];
      for (const entry of parsed.entries) {
        for (const item of entry.record.outputs) {
          const ref = provenance.parseArtifactRef(item.artifact);
          const node = ref ? ref.ref : String(item.artifact);
          if (node === target) {
            queue.push(entry);
            break;
          }
        }
      }
      const seen = new Set();
      const ancestors = [];
      while (queue.length > 0) {
        const entry = queue.shift();
        if (seen.has(entry.record.record_hash)) continue;
        seen.add(entry.record.record_hash);
        ancestors.push(entry);
        for (const parent of entry.record.parent_record_hashes) {
          const parentEntry = indexByHash.get(parent);
          if (parentEntry) queue.push(parentEntry);
        }
      }
      ancestors.sort((a, b) => a.lineNumber - b.lineNumber);
      return ancestors.map((entry) => entry.record);
    },

    async verifyAll(verifyOptions = {}) {
      return runAssurance({
        root: verifyOptions.root || root,
        storeDir: verifyOptions.storeDir || storeDir,
        strict: verifyOptions.strict === undefined ? strict : verifyOptions.strict,
        limits: verifyOptions.limits || limits,
        anchor: verifyOptions.anchor === undefined ? anchor : verifyOptions.anchor,
        now: verifyOptions.now === undefined ? now : verifyOptions.now,
        dataset: verifyOptions.dataset,
        model: verifyOptions.model,
        inference: verifyOptions.inference,
      });
    },
  };
}

function injectVisionGraph(riskGraph, report) {
  if (!riskGraph || !riskGraph.graph || !report || !report.graph) return;
  const graph = riskGraph.graph;
  const nodes = graph.nodes;
  const edges = graph.edges;

  for (const contributor of report.graph.contributors) {
    const id = `vg-contributor:${contributor.contributor}`;
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        type: 'CONTRIBUTOR',
        label: contributor.contributor,
        contributor: contributor.contributor,
        key_ids: contributor.key_ids,
      });
    }
  }
  for (const artifact of report.graph.artifacts) {
    const id = `vg-artifact:${artifact.ref}`;
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        type: 'ARTIFACT',
        label: artifact.ref,
        ref: artifact.ref,
        artifact_type: artifact.type,
        sha256: artifact.sha256 || null,
      });
    }
  }

  const seen = new Set();
  for (const edge of edges) seen.add(`${edge.from}|${edge.to}|${edge.type}`);
  for (const trust of report.graph.trusts) {
    const from = `vg-contributor:${trust.contributor}`;
    const to = `vg-artifact:${trust.ref}`;
    const key = `${from}|${to}|TRUSTS`;
    if (seen.has(key)) continue;
    seen.add(key);
    edges.push({ from, to, type: 'TRUSTS', label: 'signed' });
  }
  for (const link of report.graph.derivedFrom) {
    const from = `vg-artifact:${link.from}`;
    const to = `vg-artifact:${link.to}`;
    const key = `${from}|${to}|DERIVED_FROM`;
    if (seen.has(key)) continue;
    seen.add(key);
    edges.push({ from, to, type: 'DERIVED_FROM', label: 'derived from' });
  }

  if (riskGraph.summary) {
    riskGraph.summary.nodeCount = nodes.size;
    riskGraph.summary.edgeCount = edges.length;
  }
}

function failedDimensions(report) {
  const failed = [];
  for (const [name, dimension] of Object.entries(report.dimensions || {})) {
    if (dimension && dimension.status === 'FAIL') failed.push(name);
  }
  return failed;
}

function applyVisionGuardToScan(result, options = {}) {
  if (!result || typeof result !== 'object') {
    throw new VgError(ERROR_CODES.VG_INTERNAL, 'scan result is required');
  }
  const root = options.root
    ? path.resolve(options.root)
    : result.project && result.project.path
      ? result.project.path
      : process.cwd();

  const report = runAssurance({
    root,
    storeDir: options.storeDir,
    strict: options.strict,
    limits: options.limits,
    anchor: options.anchor,
    now: options.now,
    dataset: options.dataset,
    model: options.model,
    inference: options.inference,
  });

  const vgFindings = reportToFindings(report);
  const existing = Array.isArray(result.findings) ? result.findings : [];
  const seen = new Set(existing.map((finding) => finding.id));
  const merged = existing.slice();
  let added = 0;
  for (const finding of vgFindings) {
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);
    merged.push(finding);
    added++;
  }

  result.findings = merged;
  result.aggregation = aggregate(merged);
  result.score = score(result.aggregation);
  result.verdict = verdict(result.score);
  result.visionGuard = report;
  injectVisionGraph(result.riskGraph, report);

  let exitCode = 0;
  if (report.overall === 'INTEGRITY VIOLATION') {
    exitCode = 1;
    const failed = failedDimensions(report);
    const noun = failed.length === 1 ? 'dimension' : 'dimensions';
    result.verdict = {
      status: 'FAIL',
      message: `VisionGuard integrity violation: ${failed.join(', ')} ${noun} failed verification.`,
      score: result.score.value,
    };
  } else if (report.overall === 'INCOMPLETE' && options.requireVerified) {
    exitCode = 1;
  }

  return { report, addedFindings: added, exitCode };
}

module.exports = {
  createVisionGuard,
  runAssurance,
  reportToFindings,
  overallVerdict,
  applyVisionGuardToScan,
};
