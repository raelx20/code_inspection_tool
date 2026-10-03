const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const demo = require('./visionguard-demo');
const { canonicalJson } = require('../src/visionguard/canonical');

const BIN = path.resolve(__dirname, '../bin/codesentry.js');
const NOW = Date.UTC(2026, 9, 6, 12, 0, 0);

const USAGE = [
  'Usage: node scripts/visionguard-sih.js [--out <dir>] [--json] [--help]',
  '',
  'Reproduces the SIH demonstration scenarios A-I from scratch: builds one pristine',
  'VisionGuard demo pipeline, copies it per scenario, applies exactly one tamper each',
  '(A applies none), verifies every scenario through the real codesentry vision CLI,',
  'and asserts the expected verdict, exit code and rule.',
  '',
  'Scenarios:',
  '  A  nothing tampered                 -> exit 0  VERIFIED',
  '  B  one dataset byte flipped         -> exit 1  VG-DATA-001',
  '  C  one model byte flipped           -> exit 1  VG-MODEL-001',
  '  D  one pipeline code line appended  -> exit 1  VG-PIPE-001',
  '  E  provenance log tail rolled back  -> exit 1  VG-PROV-008 (live anchor)',
  '  F  one prediction byte flipped      -> exit 1  VG-OUT-001 with expected vs actual hashes',
  '  G  one provenance record edited     -> exit 1  VG-PROV-001',
  '  H  one signature forged             -> exit 1  VG-PROV-002',
  '  I  same rollback, no anchor         -> exit 3  INCOMPLETE / UNANCHORED',
  '',
  'Exit codes: 0 every scenario matched, 1 mismatch, 2 usage error, 4 internal error',
].join('\n');

function parseArgs(argv) {
  const opts = { out: null, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--out') {
      i += 1;
      if (i >= argv.length) throw new UsageError('--out requires a value');
      opts.out = argv[i];
    } else if (arg === '--json') {
      opts.json = true;
    } else if (arg === '--help' || arg === '-h') {
      opts.help = true;
    } else {
      throw new UsageError(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

class UsageError extends Error {}

function flipByte(file) {
  const bytes = fs.readFileSync(file);
  bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0xff;
  fs.writeFileSync(file, bytes);
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

function patchMiddleRecord(root, mutate) {
  const { file, lines } = logLines(root);
  const index = Math.floor(lines.length / 2);
  if (index < 1 || index >= lines.length - 1) {
    throw new Error('demo provenance log is too short for a middle-record edit');
  }
  const record = JSON.parse(lines[index]);
  mutate(record);
  lines[index] = canonicalJson(record);
  writeLog(file, lines);
}

const TAMPER = {
  dataset(root) {
    flipByte(path.join(root, 'dataset', 'circle', '00.png'));
  },
  model(root) {
    flipByte(path.join(root, 'model', `${demo.MODEL_ID}.safetensors`));
  },
  pipeline(root) {
    fs.appendFileSync(path.join(root, 'pipeline.js'), '\nexport function tampered() {}\n');
  },
  rollback(root) {
    const { file, lines } = logLines(root);
    writeLog(file, lines.slice(0, -1));
  },
  output(root) {
    flipByte(path.join(root, 'outputs', 'prediction.json'));
  },
  recordEdit(root) {
    patchMiddleRecord(root, (record) => {
      record.metadata = { ...record.metadata, tampered: true };
    });
  },
  forgedSignature(root) {
    patchMiddleRecord(root, (record) => {
      if (typeof record.signature !== 'string' || record.signature.length === 0) {
        throw new Error('middle provenance record has no signature to forge');
      }
      const bytes = Buffer.from(record.signature, 'base64');
      bytes[0] ^= 0xff;
      record.signature = bytes.toString('base64');
    });
  },
  rollbackUnanchored(root) {
    TAMPER.rollback(root);
    fs.rmSync(path.join(root, '.visionguard', 'anchors', 'head.txt'));
  },
};

const SCENARIOS = [
  {
    id: 'A',
    title: 'pristine demo project',
    tamper: null,
    expect: { code: 0, overall: 'VERIFIED', rule: null },
    evidence: (json) => (json.overall === 'VERIFIED' && json.anchored === true ? 'anchored, 6 dimensions PASS' : 'unexpected'),
  },
  {
    id: 'B',
    title: 'one dataset byte flipped',
    tamper: TAMPER.dataset,
    expect: { code: 1, overall: 'INTEGRITY VIOLATION', rule: 'VG-DATA-001' },
  },
  {
    id: 'C',
    title: 'one model byte flipped',
    tamper: TAMPER.model,
    expect: { code: 1, overall: 'INTEGRITY VIOLATION', rule: 'VG-MODEL-001' },
  },
  {
    id: 'D',
    title: 'one pipeline code line appended',
    tamper: TAMPER.pipeline,
    expect: { code: 1, overall: 'INTEGRITY VIOLATION', rule: 'VG-PIPE-001' },
  },
  {
    id: 'E',
    title: 'provenance log tail rolled back, live anchor present',
    tamper: TAMPER.rollback,
    expect: { code: 1, overall: 'INTEGRITY VIOLATION', rule: 'VG-PROV-008' },
  },
  {
    id: 'F',
    title: 'one prediction byte flipped',
    tamper: TAMPER.output,
    expect: { code: 1, overall: 'INTEGRITY VIOLATION', rule: 'VG-OUT-001' },
    extraCheck: (json) => {
      const hit = (json.findings || []).find((item) => item.rule === 'VG-OUT-001');
      if (!hit) return 'no VG-OUT-001 finding';
      if (!/^[0-9a-f]{64}$/.test(String(hit.expected))) return 'expected hash missing';
      if (!/^[0-9a-f]{64}$/.test(String(hit.actual))) return 'actual hash missing';
      if (hit.expected === hit.actual) return 'expected equals actual';
      if (!String(hit.detail).includes(hit.expected) || !String(hit.detail).includes(hit.actual)) {
        return 'hashes missing from detail';
      }
      return null;
    },
    evidence: (json) => {
      const hit = (json.findings || []).find((item) => item.rule === 'VG-OUT-001');
      return hit ? `expected ${hit.expected.slice(0, 12)}... got ${hit.actual.slice(0, 12)}...` : 'VG-OUT-001';
    },
  },
  {
    id: 'G',
    title: 'one middle provenance record edited',
    tamper: TAMPER.recordEdit,
    expect: { code: 1, overall: 'INTEGRITY VIOLATION', rule: 'VG-PROV-001' },
  },
  {
    id: 'H',
    title: 'one provenance signature forged',
    tamper: TAMPER.forgedSignature,
    expect: { code: 1, overall: 'INTEGRITY VIOLATION', rule: 'VG-PROV-002' },
  },
  {
    id: 'I',
    title: 'same rollback without an anchor',
    tamper: TAMPER.rollbackUnanchored,
    expect: { code: 3, overall: 'INCOMPLETE', rule: 'VG-PROV-008-absent' },
    extraCheck: (json) => {
      const dim = json.dimensions && json.dimensions.provenance;
      if (!dim || dim.status !== 'UNANCHORED') return 'provenance is not UNANCHORED';
      if (json.anchored === true) return 'anchored must not be true';
      if ((json.findings || []).some((item) => item.rule === 'VG-PROV-008')) {
        return 'VG-PROV-008 must not fire without an anchor';
      }
      return null;
    },
    evidence: (json) => 'provenance UNANCHORED, never VERIFIED',
  },
];

function runVerify(root) {
  const result = spawnSync(process.execPath, [BIN, 'vision', 'verify', '--json'], {
    cwd: root,
    env: { ...process.env, VG_EXPECTED_HEAD: '' },
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  let json = null;
  try {
    json = JSON.parse(result.stdout);
  } catch (err) {
    throw new Error(`vision verify did not print JSON: ${err.message}\n${result.stdout}\n${result.stderr}`);
  }
  return { code: result.status, json };
}

function ruleMatches(expectRule, json) {
  if (!expectRule) return true;
  if (expectRule === 'VG-PROV-008-absent') return true;
  return (json.findings || []).some((item) => item.rule === expectRule);
}

function runScenario(scenario, baseDir, parentDir) {
  const root = path.join(parentDir, `scenario-${scenario.id}`);
  fs.cpSync(baseDir, root, { recursive: true });
  if (scenario.tamper) scenario.tamper(root);
  const { code, json } = runVerify(root);
  const failures = [];
  if (code !== scenario.expect.code) failures.push(`exit ${code}, expected ${scenario.expect.code}`);
  if (json.overall !== scenario.expect.overall) {
    failures.push(`overall ${json.overall}, expected ${scenario.expect.overall}`);
  }
  if (scenario.expect.rule && scenario.expect.rule !== 'VG-PROV-008-absent' && !ruleMatches(scenario.expect.rule, json)) {
    failures.push(`missing rule ${scenario.expect.rule}`);
  }
  if (scenario.extraCheck) {
    const extra = scenario.extraCheck(json);
    if (extra) failures.push(extra);
  }
  return {
    id: scenario.id,
    title: scenario.title,
    exit: code,
    overall: json.overall,
    evidence: scenario.evidence ? scenario.evidence(json) : scenario.expect.rule || '-',
    root,
    failures,
    pass: failures.length === 0,
  };
}

function formatTable(rows) {
  const header = ['Scenario', 'Exit', 'Overall', 'Evidence', 'Result'];
  const body = rows.map((row) => [
    row.id,
    String(row.exit),
    row.overall,
    row.evidence,
    row.pass ? 'PASS' : `FAIL (${row.failures.join('; ')})`,
  ]);
  const widths = header.map((cell, i) => Math.max(cell.length, ...body.map((line) => line[i].length)));
  const line = (cells) => cells.map((cell, i) => cell.padEnd(widths[i])).join('  ');
  return [line(header), ...body.map(line)];
}

function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(`visionguard-sih: ${err.message}`);
      console.error(USAGE);
      return 2;
    }
    throw err;
  }
  if (opts.help) {
    console.log(USAGE);
    return 0;
  }
  const parentDir = path.resolve(opts.out || path.join(os.tmpdir(), `vg-sih-${process.pid}`));
  fs.mkdirSync(parentDir, { recursive: true });
  const baseDir = path.join(parentDir, 'base');
  demo.runDemo({ outDir: baseDir, now: NOW });
  const rows = SCENARIOS.map((scenario) => runScenario(scenario, baseDir, parentDir));
  const pass = rows.filter((row) => row.pass).length;
  const failed = rows.filter((row) => !row.pass);
  const summary = {
    total: rows.length,
    pass,
    fail: failed.length,
    workdir: parentDir,
    scenarios: rows.map((row) => ({
      id: row.id,
      title: row.title,
      exit: row.exit,
      overall: row.overall,
      evidence: row.evidence,
      result: row.pass ? 'PASS' : 'FAIL',
      failures: row.failures,
      workdir: row.root,
    })),
  };
  if (opts.json) {
    console.log(JSON.stringify(summary, null, 2));
  } else {
    console.log(`SIH demonstration run (${rows.length} scenarios, workdir: ${parentDir})`);
    console.log('');
    for (const line of formatTable(rows)) console.log(line);
    console.log('');
    console.log(`${pass}/${rows.length} scenarios matched the expected verdicts`);
  }
  return failed.length === 0 ? 0 : 1;
}

if (require.main === module) {
  let exitCode = 0;
  try {
    exitCode = main();
  } catch (err) {
    console.error(`visionguard-sih: ${err && err.message ? err.message : String(err)}`);
    exitCode = 4;
  }
  process.exit(exitCode);
}

module.exports = { USAGE, SCENARIOS };
