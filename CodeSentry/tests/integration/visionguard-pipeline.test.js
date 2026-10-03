const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const demo = require('../../scripts/visionguard-demo');
const { runVisionCli } = require('../../src/visionguard/cli');
const { canonicalJson } = require('../../src/visionguard/canonical');

const NOW = Date.UTC(2026, 9, 5, 12, 0, 0);
const BIN = path.resolve(__dirname, '../../bin/codesentry.js');
const DIMENSIONS = ['dataset', 'model', 'pipeline', 'inference', 'output', 'provenance'];

let parent;
let base;

before(() => {
  delete process.env.VG_EXPECTED_HEAD;
  parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-sih-'));
  base = path.join(parent, 'base');
  demo.runDemo({ outDir: base, now: NOW });
});

after(() => {
  try {
    fs.rmSync(parent, { recursive: true, force: true });
  } catch {
  }
});

function scenario(name) {
  const outDir = path.join(parent, name);
  fs.cpSync(base, outDir, { recursive: true });
  return outDir;
}

function fakeIo() {
  return {
    out: [],
    err: [],
    json: null,
    print(line) {
      this.out.push(String(line));
    },
    printError(line) {
      this.err.push(String(line));
    },
    printJSON(value) {
      this.json = value;
    },
  };
}

async function run(root, argv) {
  const handle = fakeIo();
  const code = await runVisionCli(argv, handle, { root });
  return { code, handle, json: handle.json };
}

function runBin(cwd, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, 'vision', ...args], { cwd });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => {
      out += chunk;
    });
    child.stderr.on('data', (chunk) => {
      err += chunk;
    });
    child.on('error', reject);
    child.on('close', (code) => {
      try {
        resolve({ code, json: out.trim().length > 0 ? JSON.parse(out) : null, out, err });
      } catch (parseError) {
        reject(new Error(`stdout was not JSON: ${parseError.message}\n${out}`));
      }
    });
  });
}

function flipByte(file) {
  const bytes = fs.readFileSync(file);
  bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0xff;
  fs.writeFileSync(file, bytes);
}

function findingRules(json) {
  return (json.findings || []).map((item) => item.rule);
}

function logLines(root) {
  const file = path.join(root, '.visionguard', 'provenance.log');
  const text = fs.readFileSync(file, 'utf8');
  const lines = text.split('\n').filter((line) => line.trim().length > 0);
  return { file, lines };
}

function writeLog(file, lines) {
  fs.writeFileSync(file, lines.length > 0 ? `${lines.join('\n')}\n` : '');
}

describe('SIH demonstration: end-to-end pipeline scenarios A-I', () => {
  it('scenario A: a pristine demo project exits 0 VERIFIED through the real bin', async () => {
    const root = scenario('sih-a-clean');
    const { code, json } = await runBin(root, ['verify', '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'VERIFIED');
    assert.equal(json.anchored, true);
    assert.deepEqual(json.findings, []);
    assert.equal(json.details.store.present, true);
    assert.equal(json.details.store.valid, true);
    for (const dim of DIMENSIONS) {
      assert.equal(json.dimensions[dim].status, 'PASS', `${dim} expected PASS`);
    }
  });

  it('scenario B: one flipped dataset byte exits 1 with VG-DATA-001', async () => {
    const root = scenario('sih-b-dataset');
    flipByte(path.join(root, 'dataset', 'circle', '00.png'));
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.dataset.status, 'FAIL');
    assert.ok(findingRules(json).includes('VG-DATA-001'));
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('scenario C: one modified model byte exits 1 with VG-MODEL-001', async () => {
    const root = scenario('sih-c-model');
    flipByte(path.join(root, 'model', `${demo.MODEL_ID}.safetensors`));
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.model.status, 'FAIL');
    assert.ok(findingRules(json).includes('VG-MODEL-001'));
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('scenario D: one appended pipeline code line exits 1 with VG-PIPE-001', async () => {
    const root = scenario('sih-d-pipeline');
    fs.appendFileSync(path.join(root, 'pipeline.js'), '\nexport function tampered() {}\n');
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.pipeline.status, 'FAIL');
    assert.ok(findingRules(json).includes('VG-PIPE-001'));
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('scenario E: one log-tail rollback behind the live anchor exits 1 with VG-PROV-008', async () => {
    const root = scenario('sih-e-rollback');
    const anchor = path.join(root, '.visionguard', 'anchors', 'head.txt');
    assert.ok(fs.existsSync(anchor), 'demo store must ship a live anchor');
    const { file, lines } = logLines(root);
    writeLog(file, lines.slice(0, -1));
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.provenance.status, 'FAIL');
    assert.ok(findingRules(json).includes('VG-PROV-008'));
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('scenario F: one flipped prediction byte exits 1 with VG-OUT-001 showing expected vs actual hashes', async () => {
    const root = scenario('sih-f-output');
    const outputPath = path.join(root, 'outputs', 'prediction.json');
    const beforeHash = crypto.createHash('sha256').update(fs.readFileSync(outputPath)).digest('hex');
    flipByte(outputPath);
    const afterHash = crypto.createHash('sha256').update(fs.readFileSync(outputPath)).digest('hex');
    assert.notEqual(beforeHash, afterHash);
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.output.status, 'FAIL');
    const hit = (json.findings || []).find((item) => item.rule === 'VG-OUT-001');
    assert.ok(hit, 'VG-OUT-001 finding expected');
    assert.equal(hit.expected, beforeHash);
    assert.equal(hit.actual, afterHash);
    assert.ok(String(hit.detail).includes(beforeHash));
    assert.ok(String(hit.detail).includes(afterHash));
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('scenario G: one edited provenance record exits 1 with VG-PROV-001', async () => {
    const root = scenario('sih-g-record-edit');
    const { file, lines } = logLines(root);
    const index = Math.floor(lines.length / 2);
    assert.ok(index >= 1 && index < lines.length - 1, 'edit must target a middle record');
    const record = JSON.parse(lines[index]);
    record.metadata = { ...record.metadata, tampered: true };
    lines[index] = canonicalJson(record);
    writeLog(file, lines);
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.provenance.status, 'FAIL');
    const hits = (json.findings || []).filter((item) => item.rule === 'VG-PROV-001');
    assert.ok(hits.length > 0, 'VG-PROV-001 finding expected');
    assert.equal(hits[0].line, index + 1);
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('scenario H: one forged signature exits 1 with VG-PROV-002', async () => {
    const root = scenario('sih-h-forged-signature');
    const { file, lines } = logLines(root);
    const index = Math.floor(lines.length / 2);
    const record = JSON.parse(lines[index]);
    assert.equal(typeof record.signature, 'string');
    assert.ok(record.signature.length > 0);
    const bytes = Buffer.from(record.signature, 'base64');
    bytes[0] ^= 0xff;
    record.signature = bytes.toString('base64');
    lines[index] = canonicalJson(record);
    writeLog(file, lines);
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.provenance.status, 'FAIL');
    assert.ok(findingRules(json).includes('VG-PROV-002'));
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('scenario I: the same rollback without an anchor reports UNANCHORED exit 3, never VERIFIED', async () => {
    const root = scenario('sih-i-rollback-unanchored');
    const { file, lines } = logLines(root);
    writeLog(file, lines.slice(0, -1));
    fs.rmSync(path.join(root, '.visionguard', 'anchors', 'head.txt'));
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.dimensions.provenance.status, 'UNANCHORED');
    assert.notEqual(json.anchored, true);
    assert.notEqual(json.overall, 'VERIFIED');
  });
});
