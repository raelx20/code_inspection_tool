const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const demo = require('../../../scripts/visionguard-demo');
const { runVisionCli } = require('../../../src/visionguard/cli');
const keys = require('../../../src/visionguard/keys');
const store = require('../../../src/visionguard/store');
const { createVisionGuard, runAssurance } = require('../../../src/visionguard/index');

const NOW = Date.UTC(2026, 9, 3, 12, 0, 0);
const PERF = process.env.VG_PERF === '1';
const PERF_SKIP = PERF ? false : 'set VG_PERF=1 to run the heavy benchmarks';

let parent;
let base;

before(() => {
  delete process.env.VG_EXPECTED_HEAD;
  parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-perf-'));
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

async function perfStore(name, modelBytes) {
  const root = fresh(name);
  const body = Buffer.alloc(modelBytes, 0x2a);
  body[0] = 0x08;
  fs.writeFileSync(path.join(root, 'model.onnx'), body);
  fs.writeFileSync(path.join(root, 'pipeline.py'), 'def run(x):\n    return x\n');
  fs.writeFileSync(path.join(root, 'input.json'), '{"x":1}\n');
  fs.writeFileSync(path.join(root, 'output.json'), '{"y":1}\n');
  const key = writeKey(root, 'alice');
  const init = await run(root, ['init', '--actor', 'alice', '--key-file', key.file, '--json']);
  assert.equal(init.code, 0);
  return { root, key };
}

function makeCorpus(root, sub, count) {
  const dir = path.join(root, sub);
  fs.mkdirSync(dir);
  for (let i = 0; i < count; i++) {
    fs.writeFileSync(path.join(dir, `f${i}.csv`), `a,b\n${i},${i * 2}\n`);
  }
  return dir;
}

function spyFileReads() {
  const realOpenSync = fs.openSync;
  const realReadSync = fs.readSync;
  const realCloseSync = fs.closeSync;
  const openPaths = new Map();
  const totals = new Map();
  fs.openSync = function (target, flags, ...rest) {
    const fd = realOpenSync.call(fs, target, flags, ...rest);
    if (typeof flags === 'number' && (flags & 0o3) === 0 && typeof target === 'string') {
      openPaths.set(fd, path.resolve(target));
    }
    return fd;
  };
  fs.readSync = function (fd, ...rest) {
    const read = realReadSync.call(fs, fd, ...rest);
    const file = openPaths.get(fd);
    if (read > 0 && file !== undefined) {
      totals.set(file, (totals.get(file) || 0) + read);
    }
    return read;
  };
  fs.closeSync = function (fd) {
    openPaths.delete(fd);
    return realCloseSync.call(fs, fd);
  };
  return {
    totals,
    restore() {
      fs.openSync = realOpenSync;
      fs.readSync = realReadSync;
      fs.closeSync = realCloseSync;
    },
  };
}

function storeSnapshot(storeDir) {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(abs);
      } else {
        const stat = fs.statSync(abs);
        out.push(`${path.relative(storeDir, abs)}:${stat.size}:${stat.mtimeMs}`);
      }
    }
  };
  walk(storeDir);
  return out;
}

function scrub(value) {
  if (Array.isArray(value)) return value.map(scrub);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (typeof item === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(item)) continue;
      out[key] = scrub(item);
    }
    return out;
  }
  return value;
}

describe('vision performance: single-pass hashing', () => {
  it('should read each dataset file exactly once per register and per verify', async () => {
    const { root, key } = await perfStore('perf-single-pass', 16);
    const dir = makeCorpus(root, 'corpus', 2000);
    const sizes = new Map();
    for (const name of fs.readdirSync(dir)) {
      sizes.set(path.resolve(path.join(dir, name)), fs.statSync(path.join(dir, name)).size);
    }
    const heapBefore = process.memoryUsage().heapUsed;
    const vg = createVisionGuard({ root });
    const regSpy = spyFileReads();
    let manifest;
    try {
      manifest = await vg.registerDataset({
        path: dir,
        name: 'corpus',
        version: '1.0.0',
        actor: { contributor: 'alice', key_id: key.keyId },
      });
    } finally {
      regSpy.restore();
    }
    assert.equal(manifest.file_count, 2000);
    for (const [file, size] of sizes) {
      assert.equal(regSpy.totals.get(file) || 0, size, `register reads of ${file}`);
    }
    const heapAfterRegister = process.memoryUsage().heapUsed;
    const verifySpy = spyFileReads();
    let verdict;
    try {
      verdict = await vg.verifyDataset({ name: 'corpus', version: '1.0.0', path: dir });
    } finally {
      verifySpy.restore();
    }
    assert.notEqual(verdict.status, 'FAIL');
    assert.equal(verdict.diff.unchanged, 2000);
    for (const [file, size] of sizes) {
      assert.equal(verifySpy.totals.get(file) || 0, size, `verify reads of ${file}`);
    }
    const heapGrowth = process.memoryUsage().heapUsed - heapBefore;
    const registerGrowth = heapAfterRegister - heapBefore;
    assert.ok(registerGrowth < 256 * 1024 * 1024, `register heap growth ${registerGrowth} bytes`);
    assert.ok(heapGrowth < 256 * 1024 * 1024, `total heap growth ${heapGrowth} bytes`);
  });

  it('should hash the model file only once per full verification run', async () => {
    const modelBytes = 4 * 1024 * 1024 + 16;
    const { root, key } = await perfStore('perf-model-once', modelBytes);
    const regModel = await run(root, ['register-model', 'model.onnx', '--id', 'clf', '--json']);
    assert.equal(regModel.code, 0);
    const regPipe = await run(root, [
      'record-pipeline',
      '--name',
      'htp',
      '--version',
      '1.0.0',
      '--code',
      'pipeline.py',
      '--actor',
      'alice',
      '--key-file',
      key.file,
      '--json',
    ]);
    assert.equal(regPipe.code, 0);
    const recInf = await run(root, [
      'record-inference',
      'input.json',
      'output.json',
      '--model',
      'clf',
      '--pipeline',
      'htp',
      '--actor',
      'alice',
      '--key-file',
      key.file,
      '--json',
    ]);
    assert.equal(recInf.code, 0);
    const modelAbs = path.resolve(path.join(root, 'model.onnx'));
    const modelSize = fs.statSync(modelAbs).size;
    const storeDir = path.join(root, '.visionguard');
    for (let round = 0; round < 2; round++) {
      const spy = spyFileReads();
      let report;
      try {
        report = runAssurance({ root, storeDir });
      } finally {
        spy.restore();
      }
      const entry = report.dimensions.model.entries[0];
      assert.equal(entry.located, true);
      assert.notEqual(report.dimensions.model.status, 'FAIL');
      const read = spy.totals.get(modelAbs) || 0;
      assert.ok(read < modelSize * 1.5, `round ${round}: model bytes read ${read} of ${modelSize}`);
    }
  });

  it('should give identical verdicts on repeated verification and leave the store untouched', async () => {
    const root = scenario('perf-repeat');
    const storeDir = path.join(root, '.visionguard');
    const before = storeSnapshot(storeDir);
    const seen = [];
    for (let round = 0; round < 3; round++) {
      const { code, json } = await run(root, ['verify', '--json']);
      assert.equal(code, 0);
      assert.deepEqual(storeSnapshot(storeDir), before);
      seen.push(scrub(json));
    }
    assert.deepEqual(seen[1], seen[0]);
    assert.deepEqual(seen[2], seen[0]);
  });
});

describe('vision performance: heavy benchmarks', () => {
  it(
    'should register and repeatedly verify 100000 small files within budget',
    { skip: PERF_SKIP },
    async (t) => {
      const { root, key } = await perfStore('perf-flood', 16);
      const dir = path.join(root, 'flood');
      fs.mkdirSync(dir);
      const count = 100000;
      let started = Date.now();
      for (let i = 0; i < count; i++) {
        fs.writeFileSync(path.join(dir, `f${i}.csv`), `a,b\n${i},x\n`);
      }
      const createMs = Date.now() - started;
      const vg = createVisionGuard({ root });
      const heapBefore = process.memoryUsage().heapUsed;
      started = Date.now();
      const manifest = await vg.registerDataset({
        path: dir,
        name: 'flood',
        version: '1.0.0',
        actor: { contributor: 'alice', key_id: key.keyId },
      });
      const registerMs = Date.now() - started;
      started = Date.now();
      const first = await vg.verifyDataset({ name: 'flood', version: '1.0.0', path: dir });
      const verifyMs = Date.now() - started;
      started = Date.now();
      const second = await vg.verifyDataset({ name: 'flood', version: '1.0.0', path: dir });
      const verifyAgainMs = Date.now() - started;
      const heapGrowth = process.memoryUsage().heapUsed - heapBefore;
      const manifestBytes = fs.statSync(store.datasetManifestPath(path.join(root, '.visionguard'), 'flood', '1.0.0')).size;
      assert.equal(manifest.file_count, count);
      assert.ok(manifestBytes > 8 * 1024 * 1024, `manifest ${manifestBytes} bytes should exceed the old 8 MiB cap`);
      assert.ok(manifestBytes < 32 * 1024 * 1024, `manifest ${manifestBytes} bytes should fit the 32 MiB cap`);
      assert.notEqual(first.status, 'FAIL');
      assert.equal(first.diff.unchanged, count);
      assert.equal(second.status, first.status);
      assert.deepEqual(second.diff, first.diff);
      assert.ok(createMs < 900000, `create took ${createMs}ms`);
      assert.ok(registerMs < 300000, `register took ${registerMs}ms`);
      assert.ok(verifyMs < 300000, `verify took ${verifyMs}ms`);
      assert.ok(verifyAgainMs < 300000, `re-verify took ${verifyAgainMs}ms`);
      assert.ok(heapGrowth < 768 * 1024 * 1024, `heap growth ${heapGrowth} bytes`);
      t.diagnostic(
        `flood: create=${createMs}ms register=${registerMs}ms verify=${verifyMs}ms verify2=${verifyAgainMs}ms heapGrowth=${Math.round(heapGrowth / 1048576)}MiB manifest=${Math.round(manifestBytes / 1048576)}MiB`
      );
    }
  );

  it(
    'should register and verify a few huge sparse files with bounded memory',
    { skip: PERF_SKIP },
    async (t) => {
      const { root, key } = await perfStore('perf-huge', 16);
      const dir = path.join(root, 'huge');
      fs.mkdirSync(dir);
      const size = 512 * 1024 * 1024;
      let sparse = true;
      for (const name of ['a.bin', 'b.bin', 'c.bin']) {
        try {
          fs.writeFileSync(path.join(dir, name), '');
          fs.truncateSync(path.join(dir, name), size);
        } catch {
          sparse = false;
        }
      }
      if (!sparse) {
        t.skip('sparse files unsupported on this filesystem');
        return;
      }
      const vg = createVisionGuard({ root });
      const heapBefore = process.memoryUsage().heapUsed;
      let started = Date.now();
      const manifest = await vg.registerDataset({
        path: dir,
        name: 'huge',
        version: '1.0.0',
        actor: { contributor: 'alice', key_id: key.keyId },
      });
      const registerMs = Date.now() - started;
      started = Date.now();
      const verdict = await vg.verifyDataset({ name: 'huge', version: '1.0.0', path: dir });
      const verifyMs = Date.now() - started;
      const heapGrowth = process.memoryUsage().heapUsed - heapBefore;
      assert.equal(manifest.file_count, 3);
      assert.equal(manifest.total_bytes, 3 * size);
      assert.notEqual(verdict.status, 'FAIL');
      assert.equal(verdict.diff.unchanged, 3);
      assert.ok(registerMs < 180000, `register took ${registerMs}ms`);
      assert.ok(verifyMs < 180000, `verify took ${verifyMs}ms`);
      assert.ok(heapGrowth < 128 * 1024 * 1024, `heap growth ${heapGrowth} bytes`);
      t.diagnostic(
        `huge: register=${registerMs}ms verify=${verifyMs}ms heapGrowth=${Math.round(heapGrowth / 1048576)}MiB`
      );
    }
  );
});
