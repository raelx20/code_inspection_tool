'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');

const { registerDataset, verifyDataset } = require('../src/visionguard/manifest');
const { registerModel, verifyModel } = require('../src/visionguard/model');
const { registerPipeline, verifyPipeline } = require('../src/visionguard/pipeline');
const { recordInference, verifyInference } = require('../src/visionguard/inference');
const prov = require('../src/visionguard/provenance');
const vgStore = require('../src/visionguard/store');

const CLASSES = Object.freeze(['circle', 'square', 'triangle', 'cross']);
const IMAGE_SIZE = 16;
const TARGET_SIZE = 8;
const FEATURE_DIM = TARGET_SIZE * TARGET_SIZE;
const NORM_SCALE = 1024;
const IMAGES_PER_CLASS = 8;
const DATASET_NAME = 'demo-dataset';
const DATASET_VERSION = '1.0.0';
const MODEL_ID = 'demo-clf';
const MODEL_VERSION = '1.0.0';
const PIPELINE_NAME = 'demo-cv';
const PIPELINE_VERSION = '1.0.0';
const INPUT_REF = 'inputs/input.png';
const OUTPUT_REF = 'outputs/prediction.json';
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

class UsageError extends Error {}

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function adler32(buf) {
  let a = 1;
  let b = 0;
  for (let i = 0; i < buf.length; i++) {
    a = (a + buf[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function zlibStoredBlocks(data) {
  const parts = [Buffer.from([0x78, 0x01])];
  const MAX_BLOCK = 65535;
  if (data.length === 0) {
    parts.push(Buffer.from([0x01, 0x00, 0x00, 0xff, 0xff]));
  } else {
    for (let offset = 0; offset < data.length; offset += MAX_BLOCK) {
      const length = Math.min(MAX_BLOCK, data.length - offset);
      const header = Buffer.alloc(5);
      header[0] = offset + length >= data.length ? 1 : 0;
      header.writeUInt16LE(length, 1);
      header.writeUInt16LE(~length & 0xffff, 3);
      parts.push(header, data.subarray(offset, offset + length));
    }
  }
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(adler32(data), 0);
  parts.push(checksum);
  return Buffer.concat(parts);
}

function pngChunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

function encodePngGray(width, height, pixels) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) {
    throw new Error('invalid PNG dimensions');
  }
  if (!Buffer.isBuffer(pixels) || pixels.length !== width * height) {
    throw new Error('pixel buffer size mismatch');
  }
  const stride = width + 1;
  const raw = Buffer.alloc(height * stride);
  for (let y = 0; y < height; y++) {
    raw[y * stride] = 0;
    pixels.copy(raw, y * stride + 1, y * width, (y + 1) * width);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlibStoredBlocks(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function paethPredictor(left, up, upLeft) {
  const p = left + up - upLeft;
  const pa = Math.abs(p - left);
  const pb = Math.abs(p - up);
  const pc = Math.abs(p - upLeft);
  if (pa <= pb && pa <= pc) return left;
  if (pb <= pc) return up;
  return upLeft;
}

function decodePngGray(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 8 || !buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error('not a PNG file');
  }
  let pos = 8;
  let width = 0;
  let height = 0;
  let sawIhdr = false;
  let sawIend = false;
  const idatParts = [];
  while (pos + 12 <= buffer.length) {
    const length = buffer.readUInt32BE(pos);
    if (length > 0x7fffffff || pos + 12 + length > buffer.length) {
      throw new Error('truncated PNG chunk');
    }
    const type = buffer.toString('ascii', pos + 4, pos + 8);
    const data = buffer.subarray(pos + 8, pos + 8 + length);
    const storedCrc = buffer.readUInt32BE(pos + 8 + length);
    if (crc32(buffer.subarray(pos + 4, pos + 8 + length)) !== storedCrc) {
      throw new Error(`PNG chunk ${type} failed CRC check`);
    }
    if (type === 'IHDR') {
      if (length !== 13) throw new Error('malformed IHDR chunk');
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      if (data[8] !== 8 || data[9] !== 0 || data[10] !== 0 || data[12] !== 0) {
        throw new Error('unsupported PNG format (expected 8-bit grayscale, no interlace)');
      }
      sawIhdr = true;
    } else if (type === 'IDAT') {
      idatParts.push(Buffer.from(data));
    } else if (type === 'IEND') {
      sawIend = true;
      break;
    }
    pos += 12 + length;
  }
  if (!sawIhdr || !sawIend || idatParts.length === 0 || width <= 0 || height <= 0) {
    throw new Error('incomplete PNG file');
  }
  const raw = zlib.inflateSync(Buffer.concat(idatParts));
  const stride = width + 1;
  if (raw.length !== height * stride) {
    throw new Error('PNG IDAT length does not match image dimensions');
  }
  const pixels = Buffer.alloc(width * height);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * stride];
    const rowStart = y * stride + 1;
    const outStart = y * width;
    const prevStart = (y - 1) * width;
    for (let x = 0; x < width; x++) {
      const byte = raw[rowStart + x];
      const left = x > 0 ? pixels[outStart + x - 1] : 0;
      const up = y > 0 ? pixels[prevStart + x] : 0;
      const upLeft = y > 0 && x > 0 ? pixels[prevStart + x - 1] : 0;
      let value;
      if (filter === 0) value = byte;
      else if (filter === 1) value = byte + left;
      else if (filter === 2) value = byte + up;
      else if (filter === 3) value = byte + ((left + up) >> 1);
      else if (filter === 4) value = byte + paethPredictor(left, up, upLeft);
      else throw new Error(`unsupported PNG filter type ${filter}`);
      pixels[outStart + x] = value & 0xff;
    }
  }
  return { width, height, pixels };
}

function lcg(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}

function drawShape(className, size, rng) {
  const pixels = Buffer.alloc(size * size);
  const cx = Math.floor(size / 2) + ((rng() % 3) - 1);
  const cy = Math.floor(size / 2) + ((rng() % 3) - 1);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = x - cx;
      const dy = y - cy;
      let inside;
      if (className === 'circle') {
        inside = dx * dx + dy * dy <= 36;
      } else if (className === 'square') {
        inside = Math.abs(dx) <= 5 && Math.abs(dy) <= 5;
      } else if (className === 'triangle') {
        const row = dy + 6;
        inside = row >= 0 && row <= 11 && Math.abs(dx) <= Math.floor((row + 1) / 2);
      } else if (className === 'cross') {
        inside = (Math.abs(dx) <= 6 && Math.abs(dy) <= 1) || (Math.abs(dx) <= 1 && Math.abs(dy) <= 6);
      } else {
        throw new Error(`unknown shape class "${className}"`);
      }
      const base = inside ? 230 : 25;
      const noise = (rng() % 41) - 20;
      pixels[y * size + x] = Math.max(0, Math.min(255, base + noise));
    }
  }
  return pixels;
}

function generateDataset(datasetDir) {
  const files = [];
  CLASSES.forEach((className, classIndex) => {
    const classDir = path.join(datasetDir, className);
    fs.mkdirSync(classDir, { recursive: true });
    for (let i = 0; i < IMAGES_PER_CLASS; i++) {
      const rng = lcg(0x5eed + classIndex * 1000 + i);
      const png = encodePngGray(IMAGE_SIZE, IMAGE_SIZE, drawShape(className, IMAGE_SIZE, rng));
      const fileName = `${String(i).padStart(2, '0')}.png`;
      fs.writeFileSync(path.join(classDir, fileName), png);
      files.push({ path: `${className}/${fileName}`, bytes: png.length, sha256: sha256Hex(png) });
    }
  });
  return { files, count: files.length };
}

function preprocessSpec() {
  return {
    schema_version: '1.0',
    input: { width: IMAGE_SIZE, height: IMAGE_SIZE, channels: 1 },
    resize: { width: TARGET_SIZE, height: TARGET_SIZE, method: 'area_box_average' },
    normalize: { mode: 'fixed_point_scale', divisor: 255, scale: NORM_SCALE },
    classes: [...CLASSES],
  };
}

function writePreprocessConfig(root) {
  const abs = path.join(root, 'preprocess.json');
  fs.writeFileSync(abs, `${JSON.stringify(preprocessSpec(), null, 2)}\n`);
  return abs;
}

function areaResize(pixels, width, height, targetWidth, targetHeight) {
  const out = Buffer.alloc(targetWidth * targetHeight);
  for (let ty = 0; ty < targetHeight; ty++) {
    const y0 = Math.floor((ty * height) / targetHeight);
    const y1 = Math.max(y0 + 1, Math.floor(((ty + 1) * height) / targetHeight));
    for (let tx = 0; tx < targetWidth; tx++) {
      const x0 = Math.floor((tx * width) / targetWidth);
      const x1 = Math.max(x0 + 1, Math.floor(((tx + 1) * width) / targetWidth));
      let sum = 0;
      let count = 0;
      for (let y = y0; y < y1; y++) {
        for (let x = x0; x < x1; x++) {
          sum += pixels[y * width + x];
          count += 1;
        }
      }
      out[ty * targetWidth + tx] = Math.round(sum / count);
    }
  }
  return out;
}

function normalizeFeatures(resized, spec) {
  const out = new Float64Array(resized.length);
  for (let i = 0; i < resized.length; i++) {
    out[i] = Math.round((resized[i] * spec.normalize.scale) / spec.normalize.divisor);
  }
  return out;
}

function preprocessPixels(pixels, width, height, spec) {
  const resized = areaResize(pixels, width, height, spec.resize.width, spec.resize.height);
  return normalizeFeatures(resized, spec);
}

function writeSafetensors(tensors, metadata) {
  const header = { __metadata__: {} };
  for (const key of Object.keys(metadata)) {
    header.__metadata__[key] = String(metadata[key]);
  }
  const dataParts = [];
  let offset = 0;
  for (const tensor of tensors) {
    const buffer = Buffer.alloc(tensor.data.length * 4);
    for (let i = 0; i < tensor.data.length; i++) {
      buffer.writeFloatLE(tensor.data[i], i * 4);
    }
    header[tensor.name] = { dtype: 'F32', shape: tensor.shape, data_offsets: [offset, offset + buffer.length] };
    dataParts.push(buffer);
    offset += buffer.length;
  }
  let headerJson = JSON.stringify(header);
  const pad = (8 - (Buffer.byteLength(headerJson, 'utf8') % 8)) % 8;
  headerJson += ' '.repeat(pad);
  const headerBytes = Buffer.from(headerJson, 'utf8');
  const sizePrefix = Buffer.alloc(8);
  sizePrefix.writeBigUInt64LE(BigInt(headerBytes.length), 0);
  return Buffer.concat([sizePrefix, headerBytes, ...dataParts]);
}

function readSafetensors(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 8) {
    throw new Error('safetensors file is too small');
  }
  const headerLength = Number(buffer.readBigUInt64LE(0));
  if (!Number.isSafeInteger(headerLength) || headerLength <= 0 || 8 + headerLength > buffer.length) {
    throw new Error('invalid safetensors header length');
  }
  const header = JSON.parse(buffer.toString('utf8', 8, 8 + headerLength));
  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    throw new Error('safetensors header is not a JSON object');
  }
  const dataStart = 8 + headerLength;
  const tensors = {};
  for (const key of Object.keys(header)) {
    if (key === '__metadata__') continue;
    const entry = header[key];
    if (!entry || entry.dtype !== 'F32' || !Array.isArray(entry.shape) || !Array.isArray(entry.data_offsets)) {
      throw new Error(`tensor "${key}" has an unsupported descriptor`);
    }
    const [start, end] = entry.data_offsets;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start) {
      throw new Error(`tensor "${key}" has invalid data_offsets`);
    }
    let count = 1;
    for (const dim of entry.shape) {
      if (!Number.isSafeInteger(dim) || dim < 0) throw new Error(`tensor "${key}" has an invalid shape`);
      count *= dim;
    }
    if (end - start !== count * 4) throw new Error(`tensor "${key}" byte length does not match its shape`);
    if (dataStart + end > buffer.length) throw new Error(`tensor "${key}" data extends past end of file`);
    const data = new Float64Array(count);
    for (let i = 0; i < count; i++) {
      data[i] = buffer.readFloatLE(dataStart + start + i * 4);
    }
    tensors[key] = { dtype: entry.dtype, shape: entry.shape, data };
  }
  return { header, tensors };
}

function trainModel(datasetDir, spec) {
  const dim = spec.resize.width * spec.resize.height;
  const sums = spec.classes.map(() => new Float64Array(dim));
  const counts = spec.classes.map(() => 0);
  spec.classes.forEach((className, classIndex) => {
    const classDir = path.join(datasetDir, className);
    const names = fs.readdirSync(classDir).filter((name) => name.endsWith('.png')).sort();
    for (const name of names) {
      const decoded = decodePngGray(fs.readFileSync(path.join(classDir, name)));
      if (decoded.width !== spec.input.width || decoded.height !== spec.input.height) {
        throw new Error(`image ${className}/${name} does not match the declared input size`);
      }
      const features = preprocessPixels(decoded.pixels, decoded.width, decoded.height, spec);
      for (let i = 0; i < dim; i++) {
        sums[classIndex][i] += features[i];
      }
      counts[classIndex] += 1;
    }
  });
  const centroids = sums.map((sum, classIndex) => {
    if (counts[classIndex] === 0) throw new Error(`class "${spec.classes[classIndex]}" contains no images`);
    const out = new Float64Array(dim);
    for (let i = 0; i < dim; i++) {
      out[i] = sum[i] / counts[classIndex];
    }
    return out;
  });
  return { centroids, counts, dim };
}

function writeModelFile(modelPath, training, spec) {
  const flat = new Float64Array(spec.classes.length * training.dim);
  training.centroids.forEach((centroid, classIndex) => {
    flat.set(centroid, classIndex * training.dim);
  });
  const bytes = writeSafetensors(
    [{ name: 'centroids', shape: [spec.classes.length, training.dim], data: flat }],
    {
      classes: JSON.stringify(spec.classes),
      approach: 'nearest-centroid',
      feature_dim: String(training.dim),
      normalize: 'fixed_point_scale'
    }
  );
  fs.writeFileSync(modelPath, bytes);
  return bytes;
}

function classify(features, model, spec) {
  const labels = JSON.parse(model.header.__metadata__.classes);
  const dim = spec.resize.width * spec.resize.height;
  const centroids = model.tensors.centroids.data;
  const distances = labels.map((label, classIndex) => {
    let acc = 0;
    for (let i = 0; i < dim; i++) {
      const delta = features[i] - centroids[classIndex * dim + i];
      acc += delta * delta;
    }
    return acc;
  });
  let best = 0;
  for (let i = 1; i < distances.length; i++) {
    if (distances[i] < distances[best]) best = i;
  }
  return { label: labels[best], labels, distances };
}

function runInference(options) {
  const spec = JSON.parse(fs.readFileSync(options.configPath, 'utf8'));
  const input = decodePngGray(fs.readFileSync(options.inputPath));
  if (input.width !== spec.input.width || input.height !== spec.input.height) {
    throw new Error('input image does not match the declared input size');
  }
  const features = preprocessPixels(input.pixels, input.width, input.height, spec);
  const model = readSafetensors(fs.readFileSync(options.modelPath));
  if (!model.header.__metadata__ || !model.tensors.centroids) {
    throw new Error('model file is missing centroids or metadata');
  }
  const modelClasses = JSON.parse(model.header.__metadata__.classes);
  if (JSON.stringify(modelClasses) !== JSON.stringify(spec.classes)) {
    throw new Error('model class list does not match the preprocess config');
  }
  const result = classify(features, model, spec);
  const distances = {};
  result.labels.forEach((label, index) => {
    distances[label] = Math.round(result.distances[index] * 1e4) / 1e4;
  });
  const prediction = {
    input: options.inputRef,
    label: result.label,
    model: options.modelRef,
    pipeline: options.pipelineRef,
    distances
  };
  const bytes = Buffer.from(`${JSON.stringify(prediction, null, 2)}\n`, 'utf8');
  fs.writeFileSync(options.outputPath, bytes);
  return { prediction, bytes, sha256: sha256Hex(bytes) };
}

function overallVerdict(dimensions) {
  const statuses = Object.values(dimensions).map((dimension) => dimension.status);
  if (statuses.includes('FAIL')) return 'INTEGRITY VIOLATION';
  if (statuses.some((status) => status !== 'PASS')) return 'INCOMPLETE';
  return 'VERIFIED';
}

function runDemo(options = {}) {
  const outDir = options.outDir
    ? path.resolve(options.outDir)
    : fs.mkdtempSync(path.join(os.tmpdir(), 'visionguard-demo-'));
  const storeDir = path.join(outDir, '.visionguard');
  if (fs.existsSync(path.join(storeDir, 'provenance.log'))) {
    throw new Error(`output directory already contains a VisionGuard store: ${outDir}`);
  }
  const keyDir = path.join(outDir, 'keys');
  const datasetDir = path.join(outDir, 'dataset');
  const modelDir = path.join(outDir, 'model');
  const inputsDir = path.join(outDir, 'inputs');
  const outputsDir = path.join(outDir, 'outputs');
  for (const dir of [datasetDir, modelDir, inputsDir, outputsDir, keyDir]) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const base = typeof options.now === 'number' ? options.now : Date.now();
  const step = (n) => base + n * 1000;
  const spec = preprocessSpec();

  const generated = generateDataset(datasetDir);
  const configPath = writePreprocessConfig(outDir);
  const pipelineCopy = path.join(outDir, 'pipeline.js');
  fs.copyFileSync(__filename, pipelineCopy);
  const inputPath = path.join(outDir, 'inputs', 'input.png');
  fs.writeFileSync(inputPath, encodePngGray(IMAGE_SIZE, IMAGE_SIZE, drawShape('circle', IMAGE_SIZE, lcg(0xfeed))));

  const contributorSpecs = [
    { name: 'A', operations: ['curate_dataset'] },
    { name: 'B', operations: ['preprocess'] },
    { name: 'C', operations: ['train', 'export_model'] },
    { name: 'D', operations: ['infer'] }
  ];
  const contributors = {};
  contributorSpecs.forEach((specEntry, index) => {
    const registration = prov.registerContributor({
      storeDir,
      keyDir,
      contributor: specEntry.name,
      operations: specEntry.operations,
      now: step(index)
    });
    contributors[specEntry.name] = {
      key_id: registration.key_id,
      keyFile: registration.privateKeyPath,
      operations: specEntry.operations,
      actor: { contributor: specEntry.name, key_id: registration.key_id },
      record_id: registration.record.record_id
    };
  });

  const datasetManifest = registerDataset({
    path: datasetDir,
    name: DATASET_NAME,
    version: DATASET_VERSION,
    actor: contributors.A.actor,
    storeDir,
    now: step(4)
  });
  const merkleHex = datasetManifest.merkle_root.replace(/^sha256:/, '');
  const datasetRef = `dataset/${DATASET_NAME}@${DATASET_VERSION}`;
  const datasetBinding = prov.recordArtifact({
    storeDir,
    keyFile: contributors.A.keyFile,
    actor: contributors.A.actor,
    artifact: datasetRef,
    sha256: merkleHex,
    parents: [contributors.A.record_id],
    metadata: { files: datasetManifest.file_count },
    now: step(5)
  });

  const configSha = sha256Hex(fs.readFileSync(configPath));
  const preprocessRecord = prov.recordOperation({
    storeDir,
    keyFile: contributors.B.keyFile,
    actor: contributors.B.actor,
    operation: 'preprocess',
    inputs: [{ artifact: datasetRef, sha256: merkleHex }],
    outputs: [{ artifact: 'preprocess.json', sha256: configSha }],
    parents: [datasetBinding.record_hash],
    metadata: { resize: `${IMAGE_SIZE}x${TARGET_SIZE}x${TARGET_SIZE}`, normalize: 'fixed_point_scale' },
    now: step(6)
  });

  const pipelineParameters = { resize: `${TARGET_SIZE}x${TARGET_SIZE}`, normalize: 'fixed_point_scale' };
  const pipelineSpec = {
    root: outDir,
    preprocess_config: { path: 'preprocess.json' },
    code: { files: [{ path: 'pipeline.js' }] },
    parameters: pipelineParameters
  };
  const pipelineManifest = registerPipeline({
    ...pipelineSpec,
    name: PIPELINE_NAME,
    version: PIPELINE_VERSION,
    actor: contributors.B.actor,
    keyFile: contributors.B.keyFile,
    storeDir,
    now: step(7)
  });
  const pipelineHex = pipelineManifest.pipeline_id.replace(/^sha256:/, '');
  const pipelineRef = `pipeline/${PIPELINE_NAME}@${PIPELINE_VERSION}`;
  const pipelineBinding = prov.recordArtifact({
    storeDir,
    keyFile: contributors.B.keyFile,
    actor: contributors.B.actor,
    artifact: pipelineRef,
    sha256: pipelineHex,
    parents: [preprocessRecord.record_hash],
    now: step(8)
  });

  const training = trainModel(datasetDir, spec);
  const modelPath = path.join(modelDir, `${MODEL_ID}.safetensors`);
  const modelBytes = writeModelFile(modelPath, training, spec);
  const modelManifest = registerModel({
    path: modelPath,
    id: MODEL_ID,
    version: MODEL_VERSION,
    format: 'safetensors',
    metadata: { approach: 'nearest-centroid', library: 'none' },
    actor: contributors.C.actor,
    storeDir,
    now: step(9)
  });
  const modelRef = `model/${MODEL_ID}@${MODEL_VERSION}`;
  const trainRecord = prov.recordOperation({
    storeDir,
    keyFile: contributors.C.keyFile,
    actor: contributors.C.actor,
    operation: 'train',
    inputs: [
      { artifact: datasetRef, sha256: merkleHex },
      { artifact: pipelineRef, sha256: pipelineHex }
    ],
    outputs: [{ artifact: modelRef, sha256: modelManifest.sha256 }],
    parents: [pipelineBinding.record_hash],
    metadata: { classes: spec.classes.length, features: training.dim },
    now: step(10)
  });

  const outputPath = path.join(outDir, 'outputs', 'prediction.json');
  const prediction = runInference({
    configPath,
    modelPath,
    inputPath,
    outputPath,
    inputRef: INPUT_REF,
    modelRef,
    pipelineRef
  });
  const inputSha = sha256Hex(fs.readFileSync(inputPath));
  const inferenceRecord = recordInference({
    storeDir,
    keyFile: contributors.D.keyFile,
    actor: contributors.D.actor,
    input: { artifact: INPUT_REF, sha256: inputSha },
    model: { artifact: modelRef, sha256: modelManifest.sha256 },
    pipeline: { artifact: pipelineRef, sha256: pipelineHex },
    output: { artifact: OUTPUT_REF, sha256: prediction.sha256 },
    params: { method: 'nearest-centroid', normalize: 'fixed_point_scale' },
    output_mode: 'raw',
    parents: [trainRecord.record_hash],
    now: step(11)
  });

  const chainState = prov.verifyProvenance({ storeDir, now: step(12) });
  const head = chainState.head;
  const anchorDir = path.join(storeDir, 'anchors');
  fs.mkdirSync(anchorDir, { recursive: true });
  const anchorFile = path.join(anchorDir, 'head.txt');
  fs.writeFileSync(anchorFile, `${head}\n`);
  const provenance = prov.verifyProvenance({ storeDir, anchorFilePath: anchorFile, now: step(13) });

  const datasetVerification = verifyDataset({
    manifest: vgStore.loadDatasetManifest(storeDir, DATASET_NAME, DATASET_VERSION),
    path: datasetDir,
    now: step(14)
  });
  const modelVerification = verifyModel({
    manifest: vgStore.loadModelManifest(storeDir, MODEL_ID, MODEL_VERSION),
    path: modelPath,
    now: step(15)
  });
  const pipelineVerification = verifyPipeline({
    ...pipelineSpec,
    storeDir,
    name: PIPELINE_NAME,
    version: PIPELINE_VERSION,
    now: step(16)
  });
  const inferenceVerification = verifyInference({
    storeDir,
    recordId: inferenceRecord.record_id,
    root: outDir,
    modelPath,
    now: step(17)
  });

  const reexecDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-reexec-'));
  const reexecPath = path.join(reexecDir, 'prediction.json');
  let reexecution;
  try {
    const rerun = runInference({
      configPath,
      modelPath,
      inputPath,
      outputPath: reexecPath,
      inputRef: INPUT_REF,
      modelRef,
      pipelineRef
    });
    reexecution = {
      identical: Buffer.compare(rerun.bytes, prediction.bytes) === 0,
      expected_sha256: prediction.sha256,
      actual_sha256: rerun.sha256
    };
  } finally {
    fs.rmSync(reexecDir, { recursive: true, force: true });
  }

  const datasetBlockers = datasetVerification.findings.some((finding) => finding.severity === 'BLOCKER');
  const provBlockers = provenance.findings.filter((finding) => finding.severity === 'BLOCKER');
  const bindingPresent = provenance.record_count > 0 && provBlockers.length === 0;
  const dimensions = {
    dataset: {
      status: datasetBlockers ? 'FAIL' : bindingPresent ? 'PASS' : 'UNANCHORED',
      verification: datasetVerification.status,
      files: datasetManifest.file_count,
      total_bytes: datasetManifest.total_bytes,
      merkle_root: datasetManifest.merkle_root,
      signed_binding: bindingPresent
    },
    model: {
      status: modelVerification.status,
      format: modelManifest.detected_format,
      sha256: modelManifest.sha256
    },
    pipeline: {
      status: pipelineVerification.status,
      pipeline_id: pipelineManifest.pipeline_id
    },
    inference: {
      status: inferenceVerification.status,
      record_id: inferenceRecord.record_id
    },
    output: {
      status: inferenceVerification.output_status,
      expected_sha256: prediction.sha256
    },
    provenance: {
      status: provenance.status,
      anchored: provenance.anchored,
      head,
      records: provenance.record_count,
      warnings: provenance.warnings.length
    }
  };

  return {
    schema_version: '1.0',
    command: 'visionguard-demo',
    outDir,
    storeDir,
    contributors: Object.fromEntries(
      Object.entries(contributors).map(([name, entry]) => [
        name,
        { key_id: entry.key_id, operations: entry.operations, record_id: entry.record_id }
      ])
    ),
    dataset: {
      name: DATASET_NAME,
      version: DATASET_VERSION,
      files: generated.count,
      merkle_root: datasetManifest.merkle_root
    },
    model: {
      id: MODEL_ID,
      version: MODEL_VERSION,
      format: modelManifest.detected_format,
      bytes: modelBytes.length,
      sha256: modelManifest.sha256
    },
    pipeline: {
      name: PIPELINE_NAME,
      version: PIPELINE_VERSION,
      pipeline_id: pipelineManifest.pipeline_id
    },
    inference: {
      record_id: inferenceRecord.record_id,
      input: INPUT_REF,
      output: OUTPUT_REF,
      label: prediction.prediction.label
    },
    dimensions,
    overall: overallVerdict(dimensions),
    reexecution
  };
}

function formatReport(report) {
  const lines = [];
  lines.push('VisionGuard CV pipeline demo');
  lines.push(`  workspace : ${report.outDir}`);
  lines.push('  honesty   : hashes prove bit-identity only, never accuracy or safety');
  lines.push('  records   :');
  for (const [name, entry] of Object.entries(report.contributors)) {
    lines.push(`    contributor ${name}  key ${entry.key_id}  ops ${entry.operations.join(',')}`);
  }
  lines.push('  dimensions:');
  lines.push(
    `    Dataset     ${report.dimensions.dataset.status}` +
      `  (${report.dimensions.dataset.files} files, ${report.dimensions.dataset.merkle_root})`
  );
  lines.push(
    `    Model       ${report.dimensions.model.status}` +
      `  (${report.dimensions.model.format}, sha256:${report.dimensions.model.sha256})`
  );
  lines.push(`    Pipeline    ${report.dimensions.pipeline.status}  (${report.dimensions.pipeline.pipeline_id})`);
  lines.push(`    Inference   ${report.dimensions.inference.status}  (record ${report.dimensions.inference.record_id})`);
  lines.push(
    `    Output      ${report.dimensions.output.status}` +
      `  (expected sha256:${report.dimensions.output.expected_sha256})`
  );
  lines.push(
    `    Provenance  ${report.dimensions.provenance.status}` +
      `  (${report.dimensions.provenance.records} records, head ${report.dimensions.provenance.head})`
  );
  lines.push(
    `  re-execution: ${report.reexecution.identical ? 'identical output bytes' : 'OUTPUT MISMATCH'}`
  );
  lines.push(`  overall: ${report.overall}`);
  return lines.join('\n');
}

function parseArgs(argv) {
  const opts = { outDir: null, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--out') {
      i += 1;
      if (i >= argv.length) throw new UsageError('--out requires a directory argument');
      opts.outDir = argv[i];
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

const USAGE = [
  'Usage: node scripts/visionguard-demo.js [--out <dir>] [--json]',
  '',
  'Generates a small deterministic CV pipeline, registers every artifact under four',
  'contributors (A: dataset, B: preprocessing, C: model, D: inference), signs and',
  'anchors the provenance chain, verifies every dimension, and re-executes inference',
  'to prove deterministic output.',
  '',
  'Exit codes: 0 VERIFIED, 1 INTEGRITY VIOLATION, 2 usage error, 3 INCOMPLETE, 4 internal error'
].join('\n');

if (require.main === module) {
  let exitCode = 0;
  try {
    const opts = parseArgs(process.argv.slice(2));
    if (opts.help) {
      console.log(USAGE);
    } else {
      const report = runDemo({ outDir: opts.outDir });
      console.log(opts.json ? JSON.stringify(report, null, 2) : formatReport(report));
      exitCode = report.overall === 'VERIFIED' ? 0 : report.overall === 'INTEGRITY VIOLATION' ? 1 : 3;
    }
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(`visionguard-demo: ${err.message}`);
      console.error(USAGE);
      exitCode = 2;
    } else {
      console.error(`visionguard-demo: ${err && err.message ? err.message : String(err)}`);
      exitCode = 4;
    }
  }
  process.exit(exitCode);
}

module.exports = {
  CLASSES,
  IMAGE_SIZE,
  TARGET_SIZE,
  FEATURE_DIM,
  NORM_SCALE,
  IMAGES_PER_CLASS,
  DATASET_NAME,
  DATASET_VERSION,
  MODEL_ID,
  MODEL_VERSION,
  PIPELINE_NAME,
  PIPELINE_VERSION,
  INPUT_REF,
  OUTPUT_REF,
  UsageError,
  sha256Hex,
  crc32,
  adler32,
  encodePngGray,
  decodePngGray,
  lcg,
  drawShape,
  generateDataset,
  preprocessSpec,
  writePreprocessConfig,
  areaResize,
  normalizeFeatures,
  preprocessPixels,
  writeSafetensors,
  readSafetensors,
  trainModel,
  classify,
  runInference,
  runDemo,
  overallVerdict,
  formatReport,
  parseArgs
};
