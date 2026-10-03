const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const demo = require('../../../scripts/visionguard-demo');
const { runVisionCli } = require('../../../src/visionguard/cli');
const keys = require('../../../src/visionguard/keys');
const store = require('../../../src/visionguard/store');
const { createVisionGuard } = require('../../../src/visionguard/index');
const { canonicalJson, hashRecord } = require('../../../src/visionguard/canonical');
const { assertStableStats, hashFile } = require('../../../src/visionguard/hash');
const { readSniffHead } = require('../../../src/visionguard/model');

const NOW = Date.UTC(2026, 9, 3, 12, 0, 0);
const BIN = path.resolve(__dirname, '../../../bin/codesentry.js');
const BEL = String.fromCharCode(7);
const RTL_OVERRIDE = String.fromCharCode(0x202e);

let parent;
let base;

before(() => {
  delete process.env.VG_EXPECTED_HEAD;
  parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-sec-'));
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

function fresh(name) {
  const dir = path.join(parent, name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeKey(dir, name) {
  const pair = keys.generateKeyPair();
  const file = path.join(dir, `${name}.key`);
  fs.writeFileSync(file, `${pair.privateKeyDer.toString('base64')}\n`);
  return { file, keyId: pair.keyId };
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

function writeTinyOnnx(root) {
  const file = path.join(root, 'model.onnx');
  fs.writeFileSync(file, Buffer.from([0x08, 0x01, 0x02, 0x03]));
  return file;
}

async function seededStore(name) {
  const root = fresh(name);
  fs.mkdirSync(path.join(root, 'dataset'));
  fs.writeFileSync(path.join(root, 'dataset', 'data.csv'), 'a,b\n1,2\n');
  writeTinyOnnx(root);
  fs.writeFileSync(path.join(root, 'pipeline.py'), 'def run(x):\n    return x\n');
  fs.writeFileSync(path.join(root, 'input.json'), '{"x":1}\n');
  fs.writeFileSync(path.join(root, 'output.json'), '{"y":1}\n');
  const key = writeKey(root, 'alice');
  const init = await run(root, ['init', '--actor', 'alice', '--key-file', key.file, '--json']);
  assert.equal(init.code, 0);
  return { root, key };
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

function findingRules(json) {
  return (json.findings || []).map((item) => item.rule);
}

function tamperDatasetManifest(root, mutate) {
  const file = store.datasetManifestPath(path.join(root, '.visionguard'), demo.DATASET_NAME, demo.DATASET_VERSION);
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  mutate(doc);
  doc.record_hash = hashRecord(doc);
  fs.writeFileSync(file, `${canonicalJson(doc)}\n`);
}

function runBin(cwd, args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, 'vision', ...args], { cwd });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => {
      out += chunk;
    });
    child.stderr.on('data', (chunk) => {
      err += chunk;
    });
    child.on('close', (code) => resolve({ code, out, err }));
  });
}

describe('vision security: register path guards', () => {
  it('should exit 2 when register-data targets a directory outside the project root', async () => {
    const { root } = await seededStore('sec-regdata-outside');
    const outside = fresh('sec-outside-dataset');
    fs.writeFileSync(path.join(outside, 'a.csv'), 'x,y\n1,2\n');
    const { code, handle } = await run(root, ['register-data', outside]);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('must be inside the project root'));
  });

  it('should exit 2 when register-data targets the project root itself', async () => {
    const { root } = await seededStore('sec-regdata-root');
    const { code, handle } = await run(root, ['register-data', '.']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('must be inside the project root'));
  });

  it('should exit 2 when register-model targets a file outside the project root', async () => {
    const { root } = await seededStore('sec-regmodel-outside');
    const outside = fresh('sec-outside-model');
    fs.writeFileSync(path.join(outside, 'evil.onnx'), Buffer.from([0x08, 0x01]));
    const { code, handle } = await run(root, ['register-model', path.join(outside, 'evil.onnx')]);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('must be inside the project root'));
  });
});

describe('vision security: params JSON bombs', () => {
  it('should exit 2 when the params file nests past the canonical depth cap', async () => {
    const { root, key } = await seededStore('sec-params-depth');
    fs.writeFileSync(path.join(root, 'deep.json'), `${'['.repeat(64)}${']'.repeat(64)}`);
    const { code, handle } = await run(root, [
      'record-pipeline',
      '--name',
      'htp',
      '--version',
      '1.0.0',
      '--code',
      'pipeline.py',
      '--params',
      'deep.json',
      '--actor',
      'alice',
      '--key-file',
      key.file,
    ]);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('--params'));
  });

  it('should exit 2 when the params file overflows the JSON parser stack', async () => {
    const { root, key } = await seededStore('sec-params-stack');
    fs.writeFileSync(path.join(root, 'stack.json'), `${'['.repeat(40000)}${']'.repeat(40000)}`);
    const { code, handle } = await run(root, [
      'record-pipeline',
      '--name',
      'htp',
      '--version',
      '1.0.0',
      '--code',
      'pipeline.py',
      '--params',
      'stack.json',
      '--actor',
      'alice',
      '--key-file',
      key.file,
    ]);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('--params'));
  });

  it('should exit 2 before reading an oversized params file', async () => {
    const { root, key } = await seededStore('sec-params-oversize');
    fs.writeFileSync(path.join(root, 'huge.json'), Buffer.alloc(9 * 1024 * 1024, 0x20));
    const { code, handle } = await run(root, [
      'record-pipeline',
      '--name',
      'htp',
      '--version',
      '1.0.0',
      '--code',
      'pipeline.py',
      '--params',
      'huge.json',
      '--actor',
      'alice',
      '--key-file',
      key.file,
    ]);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('byte limit'));
  });
});

describe('vision security: hostile manifest paths', () => {
  it('should exit 1 when manifest paths escape the dataset root', async () => {
    const escapes = ['../escape.png', 'C:/Windows/escape.png'];
    for (let i = 0; i < escapes.length; i++) {
      const root = scenario(`sec-escape-${i}`);
      tamperDatasetManifest(root, (doc) => {
        doc.files[0].path = escapes[i];
      });
      const { code, json } = await run(root, ['verify-data', 'dataset', '--json']);
      assert.equal(code, 1, `path ${escapes[i]} must not verify clean`);
      assert.equal(json.overall, 'INTEGRITY VIOLATION');
      assert.equal(json.dimensions.dataset.status, 'FAIL');
      assert.ok(json.findings.some((item) => item.rule.startsWith('VG-DATA-')));
      assert.equal(fs.existsSync(path.join(root, '..', 'escape.png')), false);
    }
  });

  it('should exit 1 when manifest paths carry control or bidi characters', async () => {
    const hostile = [`evil${BEL}.csv`, `data${RTL_OVERRIDE}evil.csv`];
    for (let i = 0; i < hostile.length; i++) {
      const root = scenario(`sec-hostile-${i}`);
      tamperDatasetManifest(root, (doc) => {
        doc.files[0].path = hostile[i];
      });
      const { code, json } = await run(root, ['verify-data', 'dataset', '--json']);
      assert.equal(code, 1, `path ${JSON.stringify(hostile[i])} must not verify clean`);
      assert.equal(json.overall, 'INTEGRITY VIOLATION');
      assert.equal(json.dimensions.dataset.status, 'FAIL');
      assert.ok(json.findings.some((item) => item.rule.startsWith('VG-DATA-')));
    }
  });

  it('should exit 1 when a manifest path exceeds the length cap', async () => {
    const root = scenario('sec-longpath');
    tamperDatasetManifest(root, (doc) => {
      doc.files[0].path = `${'a'.repeat(300)}.csv`;
    });
    const { code, json } = await run(root, ['verify-data', 'dataset', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.dataset.status, 'FAIL');
    assert.ok(json.findings.some((item) => item.rule.startsWith('VG-DATA-')));
  });
});

describe('vision security: provenance attacks', () => {
  it('should exit 1 with VG-PROV-008 when the log tail is rolled back behind a live anchor', async () => {
    const root = scenario('sec-rollback-anchored');
    const { file, lines } = logLines(root);
    writeLog(file, lines.slice(0, -1));
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.provenance.status, 'FAIL');
    assert.ok(findingRules(json).includes('VG-PROV-008'));
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('should exit 3 as UNANCHORED, never VERIFIED, after rollback without an anchor', async () => {
    const root = scenario('sec-rollback-unanchored');
    const { file, lines } = logLines(root);
    writeLog(file, lines.slice(0, -1));
    fs.rmSync(path.join(root, '.visionguard', 'anchors', 'head.txt'));
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.dimensions.provenance.status, 'UNANCHORED');
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('should exit 3 as UNSIGNED when a signature is stripped, never VERIFIED', async () => {
    const root = scenario('sec-strip-signature');
    const { file, lines } = logLines(root);
    const last = JSON.parse(lines[lines.length - 1]);
    delete last.signature;
    lines[lines.length - 1] = canonicalJson(last);
    writeLog(file, lines);
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.dimensions.provenance.status, 'UNSIGNED');
    assert.ok(findingRules(json).includes('VG-PROV-009'));
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('should exit 1 with VG-PROV-003 when a registered key file is substituted', async () => {
    const root = scenario('sec-key-substitution');
    const storeDir = path.join(root, '.visionguard');
    const attacker = keys.generateKeyPair();
    const forged = keys.buildPublicKeyRecord({
      contributor: 'A',
      publicKeyDer: attacker.publicKeyDer,
      operations: [...keys.OPERATIONS],
      privateKey: attacker.privateKey,
      now: NOW,
    });
    const keyId = fs
      .readdirSync(path.join(storeDir, 'keys', 'A'))
      .find((name) => name.endsWith('.pub.json'))
      .slice(0, -'.pub.json'.length);
    const substituted = { ...forged, key_id: keyId };
    substituted.record_hash = hashRecord(substituted);
    substituted.signature = keys.signRecordHash(attacker.privateKey, substituted.record_hash);
    fs.writeFileSync(keys.publicKeyPath(storeDir, 'A', keyId), `${canonicalJson(substituted)}\n`);
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.dimensions.provenance.status, 'FAIL');
    assert.ok(findingRules(json).includes('VG-PROV-003'));
    assert.notEqual(json.overall, 'VERIFIED');
  });

  it('should exit 1 with VG-PROV-006 when a log record is replayed', async () => {
    const root = scenario('sec-replay');
    const { file, lines } = logLines(root);
    lines.push(lines[1]);
    writeLog(file, lines);
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.dimensions.provenance.status, 'FAIL');
    assert.ok(findingRules(json).includes('VG-PROV-006'));
    assert.notEqual(json.overall, 'VERIFIED');
  });
});

describe('vision security: races and exhaustion', () => {
  it('should detect stats that change while a file is being hashed', () => {
    const stable = { size: 5n, mtimeNs: 10n, ino: 3n, dev: 1n };
    assert.doesNotThrow(() => assertStableStats({ ...stable }, { ...stable }, 'x'));
    assert.throws(
      () => assertStableStats(stable, { ...stable, size: 6n }, 'x'),
      (err) => err.code === 'VG_RACE_DETECTED'
    );
    assert.throws(
      () => assertStableStats(stable, { ...stable, ino: 4n }, 'x'),
      (err) => err.code === 'VG_RACE_DETECTED'
    );
    assert.throws(
      () => assertStableStats(stable, { ...stable, dev: 2n }, 'x'),
      (err) => err.code === 'VG_RACE_DETECTED'
    );
    assert.throws(
      () => assertStableStats(stable, { ...stable, mtimeNs: 11n }, 'x'),
      (err) => err.code === 'VG_RACE_DETECTED'
    );
  });

  it('should reject a model file whose stat drifts from the hashed stat', (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-race-'));
    t.after(() => {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
      }
    });
    const file = path.join(dir, 'drift.onnx');
    fs.writeFileSync(file, Buffer.from([0x08, 0x01, 0x02]));
    const hashed = hashFile(file, {});
    assert.doesNotThrow(() => readSniffHead(file, { ...hashed }));
    assert.throws(
      () => readSniffHead(file, { ...hashed, size: hashed.size + 1 }),
      (err) => err.code === 'VG_RACE_DETECTED'
    );
    assert.throws(
      () => readSniffHead(file, { ...hashed, mtimeNs: String(BigInt(hashed.mtimeNs) + 1n) }),
      (err) => err.code === 'VG_RACE_DETECTED'
    );
  });

  it('should reject dataset registration past the file count limit', async () => {
    const { root, key } = await seededStore('sec-limit-count');
    const dir = path.join(root, 'flood');
    fs.mkdirSync(dir);
    for (let i = 0; i < 5; i++) fs.writeFileSync(path.join(dir, `f${i}.csv`), 'a\n');
    const vg = createVisionGuard({ root, limits: { maxFiles: 2 } });
    await assert.rejects(
      vg.registerDataset({
        path: dir,
        name: 'flood',
        version: '1.0.0',
        actor: { contributor: 'alice', key_id: key.keyId },
      }),
      (err) => err.code === 'VG_LIMIT_FILE_COUNT'
    );
  });

  it('should reject dataset registration when a file exceeds the size limit', async () => {
    const { root, key } = await seededStore('sec-limit-size');
    const dir = path.join(root, 'bigrow');
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, 'big.csv'), 'x'.repeat(4096));
    const vg = createVisionGuard({ root, limits: { maxFileSize: 64 } });
    await assert.rejects(
      vg.registerDataset({
        path: dir,
        name: 'bigrow',
        version: '1.0.0',
        actor: { contributor: 'alice', key_id: key.keyId },
      }),
      (err) => err.code === 'VG_LIMIT_FILE_SIZE'
    );
  });

  it('should keep the store valid when two registrations race', async () => {
    const { root, key } = await seededStore('sec-concurrent');
    for (const name of ['race1', 'race2']) {
      const dir = path.join(root, name);
      fs.mkdirSync(dir);
      fs.writeFileSync(path.join(dir, 'data.csv'), `id,v\n1,${name.length}\n`);
    }
    const shared = ['--actor', 'alice', '--key-file', key.file, '--json'];
    const [a, b] = await Promise.all([
      runBin(root, ['register-data', 'race1', '--name', 'race1', '--version', '1.0.0', ...shared]),
      runBin(root, ['register-data', 'race2', '--name', 'race2', '--version', '1.0.0', ...shared]),
    ]);
    assert.equal(a.code, 0, a.err || a.out);
    assert.equal(b.code, 0, b.err || b.out);
    const one = await run(root, ['verify-data', 'race1', '--name', 'race1', '--json']);
    const two = await run(root, ['verify-data', 'race2', '--name', 'race2', '--json']);
    assert.equal(one.code, 0, JSON.stringify(one.json));
    assert.equal(two.code, 0, JSON.stringify(two.json));
    const report = await run(root, ['verify', '--json']);
    const status = report.json.dimensions.provenance.status;
    assert.notEqual(status, 'FAIL');
    assert.ok(status === 'PASS' || status === 'UNANCHORED');
  });
});
