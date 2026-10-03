const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const demo = require('../../../scripts/visionguard-demo');
const { runVisionCli, parseVisionArgs, usageText } = require('../../../src/visionguard/cli');
const keys = require('../../../src/visionguard/keys');
const { createCommandParser, COMMANDS } = require('../../../src/cli/commands');

const NOW = Date.UTC(2026, 9, 3, 12, 0, 0);
const PAYLOAD_KEYS = ['schema_version', 'command', 'overall', 'dimensions', 'details', 'findings', 'anchored'];

let parent;
let base;
let baseReport;

before(() => {
  delete process.env.VG_EXPECTED_HEAD;
  parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-cli-'));
  base = path.join(parent, 'base');
  baseReport = demo.runDemo({ outDir: base, now: NOW });
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

function flipByte(file) {
  const bytes = fs.readFileSync(file);
  bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0xff;
  fs.writeFileSync(file, bytes);
}

describe('vision commands parser seam', () => {
  it('should route vision arguments verbatim without parsing them as scan options', () => {
    const parser = createCommandParser();
    const parsed = parser.parse(['vision', 'verify', '--json']);
    assert.equal(parsed.command, COMMANDS.VISION);
    assert.deepEqual(parsed.visionArgs, ['verify', '--json']);
    assert.deepEqual(parsed.options, {});
    assert.deepEqual(parsed.errors, []);
    assert.equal(parser.validate(parsed).valid, true);
  });

  it('should handle a bare vision token', () => {
    const parser = createCommandParser();
    const parsed = parser.parse(['vision']);
    assert.equal(parsed.command, 'vision');
    assert.deepEqual(parsed.visionArgs, []);
  });

  it('should keep scan parsing unchanged', () => {
    const parser = createCommandParser();
    const parsed = parser.parse(['scan', '.', '--json']);
    assert.equal(parsed.command, 'scan');
    assert.equal(parsed.projectPath, '.');
    assert.equal(parsed.options.json, true);
    assert.equal(parsed.visionArgs, undefined);
  });

  it('should mention vision in the top-level help', () => {
    const parser = createCommandParser();
    const help = parser.getHelp();
    assert.ok(help.includes('vision <command>'));
    assert.ok(help.includes('codesentry vision verify --json'));
  });
});

describe('parseVisionArgs', () => {
  it('should collect flags anywhere and positionals after the subcommand', () => {
    const parsed = parseVisionArgs(['--json', 'verify-data', 'dataset', '--strict']);
    assert.equal(parsed.sub, 'verify-data');
    assert.deepEqual(parsed.positionals, ['dataset']);
    assert.equal(parsed.flags.json, true);
    assert.equal(parsed.flags.strict, true);
  });

  it('should consume the next token as a flag value', () => {
    const parsed = parseVisionArgs(['register-data', 'dir', '--store', 'mystore', '--name', 'ds']);
    assert.equal(parsed.flags.store, 'mystore');
    assert.equal(parsed.flags.name, 'ds');
  });

  it('should reject unknown options and missing values', () => {
    assert.throws(() => parseVisionArgs(['verify', '--bogus']), /unknown option: --bogus/);
    assert.throws(() => parseVisionArgs(['verify', '--expected-head']), /missing value for --expected-head/);
  });
});

describe('vision usage errors', () => {
  it('should exit 2 for a missing subcommand', async () => {
    const { code, handle } = await run(base, []);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('Error: a subcommand is required'));
    assert.ok(handle.err[1].includes('Run "codesentry vision --help" for usage.'));
    assert.equal(handle.json, null);
  });

  it('should exit 2 for an unknown subcommand', async () => {
    const { code, handle } = await run(base, ['frobnicate']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('unknown command: frobnicate'));
  });

  it('should exit 2 for an unknown flag', async () => {
    const { code, handle } = await run(base, ['verify', '--bogus']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('unknown option: --bogus'));
  });

  it('should exit 2 for a missing flag value', async () => {
    const { code, handle } = await run(base, ['verify-data', '--store']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('missing value for --store'));
  });

  it('should exit 2 for too many positionals', async () => {
    const { code, handle } = await run(base, ['init', 'extra']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('unexpected argument: extra'));
  });

  it('should exit 2 for a flag that is invalid for the subcommand', async () => {
    const { code, handle } = await run(base, ['init', '--strict']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('option --strict is not valid for "vision init"'));
  });

  it('should print usage and exit 0 for --help and -h', async () => {
    const first = await run(base, ['--help']);
    assert.equal(first.code, 0);
    assert.ok(first.handle.out.join('\n').includes('Usage: codesentry vision <command>'));
    const second = await run(base, ['-h']);
    assert.equal(second.code, 0);
    assert.ok(second.handle.out.join('\n').includes('Exit codes: 0 verified, 1 integrity violation, 2 usage, 3 incomplete, 4 internal'));
  });

  it('should keep usage errors on stderr even with --json', async () => {
    const { code, handle } = await run(base, ['verify', '--bogus', '--json']);
    assert.equal(code, 2);
    assert.equal(handle.json, null);
    assert.ok(handle.err.some((line) => line.includes('Error: unknown option: --bogus')));
  });

  it('should export a usage text with every subcommand', () => {
    const text = usageText();
    for (const sub of ['init', 'register-data', 'verify-data', 'register-model', 'verify-model', 'record-pipeline', 'record-inference', 'verify-output', 'provenance', 'verify']) {
      assert.ok(text.includes(sub), `usage must mention ${sub}`);
    }
  });
});

describe('vision init', () => {
  it('should initialize a store with an imported key and return OK', async () => {
    const root = fresh('init-ok');
    const key = writeKey(root, 'bob');
    const { code, json } = await run(root, ['init', '--actor', 'bob', '--key-file', key.file, '--json']);
    assert.equal(code, 0);
    assert.equal(json.schema_version, '1.0');
    assert.equal(json.command, 'init');
    assert.equal(json.overall, 'OK');
    assert.equal(json.details.contributor, 'bob');
    assert.match(json.details.key_id, /^[0-9a-f]{32}$/);
    assert.match(json.details.record_id, /^sha256:[0-9a-f]{64}$/);
    assert.equal(json.details.store, '.visionguard');
    assert.equal(json.details.key_file, key.file);
    assert.ok(fs.existsSync(path.join(root, '.visionguard', 'provenance.log')));
    assert.ok(fs.existsSync(key.file));
  });

  it('should honour --store for a custom store directory', async () => {
    const root = fresh('init-store');
    const key = writeKey(root, 'bob');
    const { code, json } = await run(root, ['init', '--actor', 'bob', '--key-file', key.file, '--store', 'vgdata', '--json']);
    assert.equal(code, 0);
    assert.equal(json.details.store, 'vgdata');
    assert.ok(fs.existsSync(path.join(root, 'vgdata', 'provenance.log')));
    assert.ok(!fs.existsSync(path.join(root, '.visionguard')));
  });

  it('should exit 2 when non-interactive without --actor', async () => {
    const root = fresh('init-noactor');
    const key = writeKey(root, 'bob');
    const { code, handle } = await run(root, ['init', '--key-file', key.file]);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('--actor is required when running non-interactively'));
  });

  it('should exit 2 when non-interactive without --key-file', async () => {
    const root = fresh('init-nokey');
    const { code, handle } = await run(root, ['init', '--actor', 'bob']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('--key-file is required when running non-interactively'));
  });

  it('should exit 2 when the key file does not exist', async () => {
    const root = fresh('init-keymiss');
    const { code, handle } = await run(root, ['init', '--actor', 'bob', '--key-file', 'nope.key']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('key file not found: nope.key'));
  });

  it('should exit 4 when the key file is not a valid PKCS#8 key', async () => {
    const root = fresh('init-keybad');
    fs.writeFileSync(path.join(root, 'bad.key'), 'definitely-not-a-key\n');
    const { code, json } = await run(root, ['init', '--actor', 'bob', '--key-file', 'bad.key', '--json']);
    assert.equal(code, 4);
    assert.equal(json.overall, 'ERROR');
    assert.equal(json.details.error.code, 'VG_KEY_UNKNOWN');
    assert.ok(json.details.error.message.includes('private key file'));
  });

  it('should exit 2 for an invalid contributor label', async () => {
    const root = fresh('init-label');
    const key = writeKey(root, 'bob');
    const { code, handle } = await run(root, ['init', '--actor', 'bad name!', '--key-file', key.file]);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('--actor must start with an alphanumeric character'));
  });
});

describe('vision register-data and verify-data', () => {
  it('should register a dataset and sign its binding', async () => {
    const { root, key } = await seededStore('data-reg');
    const { code, json } = await run(root, ['register-data', 'dataset', '--actor', 'alice', '--key-file', key.file, '--json']);
    assert.equal(code, 0);
    assert.equal(json.command, 'register-data');
    assert.equal(json.overall, 'REGISTERED');
    assert.equal(json.details.name, 'dataset');
    assert.equal(json.details.version, '1.0.0');
    assert.equal(json.details.files, 1);
    assert.match(json.details.merkle_root, /^sha256:[0-9a-f]{64}$/);
    assert.match(json.details.binding_record, /^sha256:[0-9a-f]{64}$/);
    assert.equal(json.details.actor, 'alice');
  });

  it('should exit 2 when the dataset directory does not exist', async () => {
    const { root, key } = await seededStore('data-missing');
    const { code, handle } = await run(root, ['register-data', 'nope', '--actor', 'alice', '--key-file', key.file]);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('dataset directory not found: nope'));
  });

  it('should exit 2 when no contributor is registered and --actor is absent', async () => {
    const root = fresh('data-noactor');
    fs.mkdirSync(path.join(root, 'dataset'));
    const { code, handle } = await run(root, ['register-data', 'dataset']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('no contributor is registered yet'));
  });

  it('should exit 2 when the contributor has a registered public key but no discoverable private key', async () => {
    const { root, key } = await seededStore('data-nokey');
    const { code, handle } = await run(root, ['register-data', 'dataset', '--actor', 'alice']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('no private key found for "alice"'));
    assert.ok(key.file);
  });

  it('should verify a registered dataset as VERIFIED', async () => {
    const { root, key } = await seededStore('data-ver');
    await run(root, ['register-data', 'dataset', '--actor', 'alice', '--key-file', key.file, '--json']);
    const { code, json } = await run(root, ['verify-data', 'dataset', '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'VERIFIED');
    assert.equal(json.dimensions.dataset.status, 'PASS');
    assert.equal(json.dimensions.dataset.entries[0].name, 'dataset');
    assert.equal(json.dimensions.dataset.entries[0].signed_binding, true);
    assert.equal(json.details.signed_binding, true);
    assert.deepEqual(json.findings, []);
  });

  it('should exit 1 when dataset files were tampered after registration', async () => {
    const { root, key } = await seededStore('data-tamper');
    await run(root, ['register-data', 'dataset', '--actor', 'alice', '--key-file', key.file, '--json']);
    fs.appendFileSync(path.join(root, 'dataset', 'data.csv'), '9,9\n');
    const { code, json } = await run(root, ['verify-data', 'dataset', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.equal(json.dimensions.dataset.status, 'FAIL');
    assert.ok(json.findings.some((item) => item.rule.startsWith('VG-DATA-')));
  });

  it('should exit 3 for an unregistered dataset name', async () => {
    const { root } = await seededStore('data-unreg');
    const { code, json } = await run(root, ['verify-data', '--name', 'ghost', '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.details.error.code, 'VG_NOT_REGISTERED');
  });

  it('should exit 3 on a storeless project', async () => {
    const root = fresh('data-storeless');
    fs.mkdirSync(path.join(root, 'dataset'));
    const { code, json } = await run(root, ['verify-data', 'dataset', '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.details.error.code, 'VG_NOT_REGISTERED');
  });
});

describe('vision register-model and verify-model', () => {
  it('should sniff and register a model without --format', async () => {
    const { root } = await seededStore('model-reg');
    const { code, json } = await run(root, ['register-model', 'model.onnx', '--id', 'clf', '--actor', 'alice', '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'REGISTERED');
    assert.equal(json.details.format, 'onnx');
    assert.equal(json.details.detected_format, 'onnx');
    assert.match(json.details.sha256, /^[0-9a-f]{64}$/);
    assert.equal(json.details.size, 4);
  });

  it('should register with an explicit matching --format', async () => {
    const { root } = await seededStore('model-fmt');
    const { code, json } = await run(root, ['register-model', 'model.onnx', '--id', 'clf', '--format', 'onnx', '--actor', 'alice', '--json']);
    assert.equal(code, 0);
    assert.equal(json.details.format, 'onnx');
  });

  it('should exit 2 when the declared format contradicts the file magic', async () => {
    const { root } = await seededStore('model-fmtbad');
    const { code, handle } = await run(root, ['register-model', 'model.onnx', '--id', 'clf', '--format', 'safetensors', '--actor', 'alice']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('does not match file content detected as'));
  });

  it('should exit 2 for an unsupported --format value', async () => {
    const { root } = await seededStore('model-fmtval');
    const { code, handle } = await run(root, ['register-model', 'model.onnx', '--id', 'clf', '--format', 'gguf', '--actor', 'alice']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('--format must be one of:'));
  });

  it('should exit 2 when the model file is missing', async () => {
    const { root } = await seededStore('model-missing');
    const { code, handle } = await run(root, ['register-model', 'ghost.onnx', '--id', 'clf', '--actor', 'alice']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('model file not found: ghost.onnx'));
  });

  it('should exit 2 when the file is empty and cannot be sniffed', async () => {
    const { root } = await seededStore('model-empty');
    fs.writeFileSync(path.join(root, 'empty.bin'), '');
    const { code, handle } = await run(root, ['register-model', 'empty.bin', '--id', 'clf', '--actor', 'alice']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('cannot detect a supported model format'));
  });

  it('should verify a registered model by id', async () => {
    const { root } = await seededStore('model-ver');
    await run(root, ['register-model', 'model.onnx', '--id', 'clf', '--actor', 'alice', '--json']);
    const { code, json } = await run(root, ['verify-model', 'clf', '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'VERIFIED');
    assert.equal(json.dimensions.model.status, 'PASS');
    assert.equal(json.details.id, 'clf');
    assert.equal(json.details.version, '1.0.0');
  });

  it('should verify a registered model by intact file path', async () => {
    const { root } = await seededStore('model-file');
    await run(root, ['register-model', 'model.onnx', '--id', 'clf', '--actor', 'alice', '--json']);
    const { code, json } = await run(root, ['verify-model', 'model.onnx', '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'VERIFIED');
    assert.match(json.details.sha256, /^[0-9a-f]{64}$/);
    assert.equal(json.details.located, true);
  });

  it('should exit 1 when the model bytes were tampered (by id)', async () => {
    const { root } = await seededStore('model-tamper');
    await run(root, ['register-model', 'model.onnx', '--id', 'clf', '--actor', 'alice', '--json']);
    flipByte(path.join(root, 'model.onnx'));
    const { code, json } = await run(root, ['verify-model', 'clf', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.ok(json.findings.some((item) => item.rule.startsWith('VG-MODEL-')));
  });

  it('should exit 1 when the tampered model is passed as a basename-matching file argument', async () => {
    const { root } = await seededStore('model-tamper-file');
    await run(root, ['register-model', 'model.onnx', '--id', 'model', '--actor', 'alice', '--json']);
    flipByte(path.join(root, 'model.onnx'));
    const { code, json } = await run(root, ['verify-model', 'model.onnx', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
  });

  it('should exit 3 for an unregistered model id', async () => {
    const { root } = await seededStore('model-unreg');
    const { code, json } = await run(root, ['verify-model', 'ghost', '--json']);
    assert.equal(code, 3);
    assert.equal(json.details.error.code, 'VG_NOT_REGISTERED');
  });

  it('should exit 3 on a storeless project', async () => {
    const root = fresh('model-storeless');
    const { code, json } = await run(root, ['verify-model', 'clf', '--json']);
    assert.equal(code, 3);
    assert.equal(json.details.error.code, 'VG_NOT_REGISTERED');
  });
});

describe('vision record-pipeline, record-inference and verify-output', () => {
  it('should record a signed pipeline identity', async () => {
    const { root, key } = await seededStore('pipe-reg');
    const { code, json } = await run(root, ['record-pipeline', '--name', 'htp', '--version', '1.0.0', '--code', 'pipeline.py', '--actor', 'alice', '--key-file', key.file, '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'RECORDED');
    assert.equal(json.details.name, 'htp');
    assert.match(json.details.pipeline_id, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(json.details.code_files, ['pipeline.py']);
  });

  it('should exit 2 when --name or --version is missing', async () => {
    const { root, key } = await seededStore('pipe-flags');
    const noName = await run(root, ['record-pipeline', '--version', '1.0.0', '--actor', 'alice', '--key-file', key.file]);
    assert.equal(noName.code, 2);
    assert.ok(noName.handle.err[0].includes('--name <name> is required'));
    const noVersion = await run(root, ['record-pipeline', '--name', 'htp', '--actor', 'alice', '--key-file', key.file]);
    assert.equal(noVersion.code, 2);
    assert.ok(noVersion.handle.err[0].includes('--version <version> is required'));
  });

  it('should exit 2 when the --code file does not exist', async () => {
    const { root, key } = await seededStore('pipe-nocode');
    const { code, handle } = await run(root, ['record-pipeline', '--name', 'htp', '--version', '1.0.0', '--code', 'ghost.py', '--actor', 'alice', '--key-file', key.file]);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('--code file not found: ghost.py'));
  });

  it('should record a signed inference run with resolved model and pipeline refs', async () => {
    const { root, key } = await seededStore('inf-reg');
    await run(root, ['register-model', 'model.onnx', '--id', 'clf', '--actor', 'alice', '--json']);
    await run(root, ['record-pipeline', '--name', 'htp', '--version', '1.0.0', '--code', 'pipeline.py', '--actor', 'alice', '--key-file', key.file, '--json']);
    const { code, json } = await run(root, ['record-inference', 'input.json', 'output.json', '--model', 'clf', '--pipeline', 'htp', '--actor', 'alice', '--key-file', key.file, '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'RECORDED');
    assert.match(json.details.record_id, /^sha256:[0-9a-f]{64}$/);
    assert.equal(json.details.input, 'input.json');
    assert.equal(json.details.output, 'output.json');
    assert.equal(json.details.model, 'model/clf@1.0.0');
    assert.equal(json.details.pipeline, 'pipeline/htp@1.0.0');
  });

  it('should exit 2 when record-inference is missing flags or positionals', async () => {
    const { root, key } = await seededStore('inf-flags');
    const missingBoth = await run(root, ['record-inference', 'input.json', 'output.json', '--actor', 'alice', '--key-file', key.file]);
    assert.equal(missingBoth.code, 2);
    assert.ok(missingBoth.handle.err[0].includes('--model <id> is required'));
    const missingPos = await run(root, ['record-inference', '--model', 'clf', '--pipeline', 'htp', '--actor', 'alice', '--key-file', key.file]);
    assert.equal(missingPos.code, 2);
    assert.ok(missingPos.handle.err[0].includes('record-inference requires <input> <output> arguments'));
  });

  it('should exit 3 when the referenced model is not registered', async () => {
    const { root, key } = await seededStore('inf-unreg');
    await run(root, ['record-pipeline', '--name', 'htp', '--version', '1.0.0', '--code', 'pipeline.py', '--actor', 'alice', '--key-file', key.file, '--json']);
    const { code, json } = await run(root, ['record-inference', 'input.json', 'output.json', '--model', 'ghost', '--pipeline', 'htp', '--actor', 'alice', '--key-file', key.file, '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.details.error.code, 'VG_NOT_REGISTERED');
  });

  it('should verify a recorded output artifact', async () => {
    const root = scenario('out-ver');
    const { code, json } = await run(root, ['verify-output', demo.OUTPUT_REF, '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'VERIFIED');
    assert.equal(json.dimensions.output.status, 'PASS');
    assert.match(json.details.record_id, /^sha256:[0-9a-f]{64}$/);
  });

  it('should exit 3 when no inference record matches the output', async () => {
    const root = scenario('out-unreg');
    const { code, json } = await run(root, ['verify-output', 'outputs/ghost.json', '--json']);
    assert.equal(code, 3);
    assert.equal(json.details.error.code, 'VG_NOT_REGISTERED');
  });

  it('should exit 1 when the output bytes were tampered', async () => {
    const root = scenario('out-tamper');
    flipByte(path.join(root, 'outputs', 'prediction.json'));
    const { code, json } = await run(root, ['verify-output', demo.OUTPUT_REF, '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.ok(json.findings.some((item) => item.rule.startsWith('VG-OUT-')));
  });
});

describe('vision verify', () => {
  it('should report VERIFIED with all six dimensions and the exact payload key order', async () => {
    const root = scenario('verify-clean');
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 0);
    assert.deepEqual(Object.keys(json), PAYLOAD_KEYS);
    assert.equal(json.schema_version, '1.0');
    assert.equal(json.command, 'verify');
    assert.equal(json.overall, 'VERIFIED');
    assert.equal(json.anchored, true);
    assert.deepEqual(json.findings, []);
    assert.deepEqual(json.warnings, undefined);
    for (const dim of ['dataset', 'model', 'pipeline', 'inference', 'output', 'provenance']) {
      assert.equal(json.dimensions[dim].status, 'PASS', `${dim} expected PASS`);
    }
    assert.equal(json.details.store.present, true);
    assert.equal(json.details.store.valid, true);
  });

  it('should render the human assurance table', async () => {
    const root = scenario('verify-human');
    const { code, handle } = await run(root, ['verify']);
    assert.equal(code, 0);
    const text = handle.out.join('\n');
    assert.ok(text.includes('VisionGuard Assurance'));
    assert.ok(text.includes('Dataset Integrity'));
    assert.ok(text.includes('Model Integrity'));
    assert.ok(text.includes('Pipeline Integrity'));
    assert.ok(text.includes('Inference Integrity'));
    assert.ok(text.includes('Output Integrity'));
    assert.ok(text.includes('Provenance'));
    assert.ok(text.includes('Overall: VERIFIED'));
    assert.ok(text.includes('Anchored: yes'));
    assert.ok(text.includes('Next: nothing'));
    assert.equal(handle.json, null);
  });

  it('should exit 1 when a registered artifact was tampered', async () => {
    const root = scenario('verify-tamper');
    flipByte(path.join(root, 'model', `${demo.MODEL_ID}.safetensors`));
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.ok(json.findings.some((item) => item.rule.startsWith('VG-MODEL-')));
  });

  it('should exit 3 with all dimensions NOT_CHECKED on a storeless project', async () => {
    const root = fresh('verify-storeless');
    const { code, json } = await run(root, ['verify', '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.details.store.present, false);
    for (const dim of ['dataset', 'model', 'pipeline', 'inference', 'output', 'provenance']) {
      assert.equal(json.dimensions[dim].status, 'NOT_CHECKED');
    }
  });

  it('should exit 1 on a storeless project with --require-verified', async () => {
    const root = fresh('verify-require');
    const { code, json } = await run(root, ['verify', '--json', '--require-verified']);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INCOMPLETE');
  });

  it('should exit 2 when both --expected-head and --anchor-file are supplied', async () => {
    const root = scenario('verify-conflict');
    const { code, handle } = await run(root, ['verify', '--expected-head', 'sha256:' + 'a'.repeat(64), '--anchor-file', 'x.txt']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('mutually exclusive'));
  });

  it('should exit 1 when the expected head does not match', async () => {
    const root = scenario('verify-anchor-bad');
    const { code, json } = await run(root, ['verify', '--json', '--expected-head', 'sha256:' + 'a'.repeat(64)]);
    assert.equal(code, 1);
    assert.equal(json.overall, 'INTEGRITY VIOLATION');
    assert.ok(json.findings.some((item) => item.rule.startsWith('VG-PROV-')));
  });

  it('should exit 0 when the expected head matches the committed anchor', async () => {
    const root = scenario('verify-anchor-good');
    const head = fs.readFileSync(path.join(root, '.visionguard', 'anchors', 'head.txt'), 'utf8').trim();
    const { code, json } = await run(root, ['verify', '--json', '--expected-head', head]);
    assert.equal(code, 0);
    assert.equal(json.overall, 'VERIFIED');
    assert.equal(json.anchored, true);
  });

  it('should exit 2 when the anchor file does not exist', async () => {
    const root = scenario('verify-anchor-file-missing');
    const { code, handle } = await run(root, ['verify', '--anchor-file', 'ghost.txt']);
    assert.equal(code, 2);
    assert.ok(handle.err[0].includes('anchor file not found: ghost.txt'));
  });
});

describe('vision provenance', () => {
  it('should summarise the provenance log by default', async () => {
    const root = scenario('prov-summary');
    const { code, json } = await run(root, ['provenance', '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'OK');
    assert.ok(json.details.records > 0);
    assert.ok(json.details.contributors.includes('A'));
    assert.match(json.details.head, /^sha256:[0-9a-f]{64}$/);
    assert.equal(json.details.store_present, true);
  });

  it('should render the human provenance summary', async () => {
    const root = scenario('prov-human');
    const { code, handle } = await run(root, ['provenance']);
    assert.equal(code, 0);
    const text = handle.out.join('\n');
    assert.ok(text.includes('VisionGuard Provenance'));
    assert.ok(text.includes('Records:'));
    assert.ok(text.includes('Next: codesentry vision provenance --verify'));
  });

  it('should verify the chain as PASS when the store is anchored', async () => {
    const root = scenario('prov-verify');
    const { code, json } = await run(root, ['provenance', '--verify', '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'VERIFIED');
    assert.equal(json.dimensions.provenance.status, 'PASS');
    assert.equal(json.anchored, true);
    assert.equal(json.details.unsigned, 0);
  });

  it('should exit 3 with UNANCHORED when no anchor is available', async () => {
    const root = fresh('prov-unanchored');
    const key = writeKey(root, 'alice');
    await run(root, ['init', '--actor', 'alice', '--key-file', key.file, '--json']);
    const { code, json } = await run(root, ['provenance', '--verify', '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.dimensions.provenance.status, 'UNANCHORED');
  });

  it('should resolve lineage for a registered artifact', async () => {
    const root = scenario('prov-artifact');
    const ref = `dataset/${demo.DATASET_NAME}@${demo.DATASET_VERSION}`;
    const { code, json } = await run(root, ['provenance', '--artifact', ref, '--json']);
    assert.equal(code, 0);
    assert.equal(json.details.lineage.found, true);
    assert.ok(json.details.lineage.records >= 1);
    assert.equal(typeof json.details.lineage.chain[0].kind, 'string');
    assert.equal(typeof json.details.lineage.chain[0].record_id, 'string');
    assert.ok(json.details.lineage.chain.some((item) => item.kind === 'artifact_registered'));
    assert.ok(json.details.lineage.chain.every((item) => typeof item.contributor === 'string'));
    const human = await run(root, ['provenance', '--artifact', ref]);
    assert.equal(human.code, 0);
    assert.ok(human.handle.out.join('\n').includes(`Lineage for ${ref}:`));
    assert.ok(!human.handle.out.join('\n').includes('No provenance summary available.'));
  });

  it('should exit 3 when no record references the artifact', async () => {
    const root = scenario('prov-artifact-miss');
    const { code, json } = await run(root, ['provenance', '--artifact', 'ghost', '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.details.lineage.found, false);
  });

  it('should expose the provenance graph with --graph', async () => {
    const root = scenario('prov-graph');
    const { code, json } = await run(root, ['provenance', '--graph', '--json']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'OK');
    assert.ok(Array.isArray(json.details.graph.artifacts));
    assert.ok(json.details.graph.artifacts.length > 0);
    assert.ok(json.details.graph.contributors.length > 0);
    assert.ok(Array.isArray(json.details.graph.trusts));
    assert.ok(Array.isArray(json.details.graph.derivedFrom));
  });

  it('should render graph lines in human mode', async () => {
    const root = scenario('prov-graph-human');
    const { code, handle } = await run(root, ['provenance', '--graph']);
    assert.equal(code, 0);
    const text = handle.out.join('\n');
    assert.ok(text.includes('Provenance graph:'));
    assert.ok(text.includes('contributors'));
  });

  it('should combine --verify and a missing artifact with a failing exit', async () => {
    const root = scenario('prov-combo');
    const { code, json } = await run(root, ['provenance', '--verify', '--artifact', 'ghost', '--json']);
    assert.equal(code, 3);
    assert.equal(json.overall, 'INCOMPLETE');
    assert.equal(json.dimensions.provenance.status, 'PASS');
    assert.equal(json.details.lineage.found, false);
  });

  it('should include the record list with --verbose', async () => {
    const root = scenario('prov-verbose');
    const { code, json } = await run(root, ['provenance', '--json', '--verbose']);
    assert.equal(code, 0);
    assert.ok(Array.isArray(json.details.record_list));
    assert.ok(json.details.record_list.length > 0);
    assert.ok(json.details.record_list[0].kind);
  });
});

describe('vision json error payloads', () => {
  it('should shape VgError failures as a payload on stdout', async () => {
    const root = fresh('err-storeless');
    const { code, json } = await run(root, ['verify-output', 'x.json', '--json']);
    assert.equal(code, 3);
    assert.deepEqual(Object.keys(json), PAYLOAD_KEYS);
    assert.equal(json.command, 'verify-output');
    assert.equal(json.overall, 'INCOMPLETE');
    assert.deepEqual(json.dimensions, {});
    assert.deepEqual(json.findings, []);
    assert.equal(json.anchored, null);
    assert.equal(typeof json.details.error.code, 'string');
    assert.equal(typeof json.details.error.message, 'string');
  });

  it('should report unexpected failures as ERROR with exit 4', async () => {
    const root = fresh('err-invalid-key');
    fs.writeFileSync(path.join(root, 'bad.key'), 'nope\n');
    const { code, json } = await run(root, ['init', '--actor', 'x', '--key-file', 'bad.key', '--json']);
    assert.equal(code, 4);
    assert.equal(json.overall, 'ERROR');
    assert.match(json.details.error.code, /^VG_/);
  });

  it('should keep human-mode failures on stderr without a payload', async () => {
    const root = fresh('err-human');
    const { code, handle } = await run(root, ['verify-model', 'ghost']);
    assert.equal(code, 3);
    assert.equal(handle.json, null);
    assert.ok(handle.err.some((line) => line.includes('Error [VG_NOT_REGISTERED]')));
  });

  it('should honour flags placed before the subcommand', async () => {
    const root = scenario('flags-first');
    const { code, json } = await run(root, ['--json', 'verify']);
    assert.equal(code, 0);
    assert.equal(json.overall, 'VERIFIED');
  });
});
