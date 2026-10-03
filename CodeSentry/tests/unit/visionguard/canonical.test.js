const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  canonicalJson,
  parseCanonical,
  hashRecord,
  canonicalDigest,
  DEFAULT_MAX_DEPTH,
} = require('../../../src/visionguard/canonical');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}`);
    assert.equal(err.code, code);
    return true;
  });
}

describe('VisionGuard canonical JSON', () => {
  it('should serialize an empty object as {}', () => {
    assert.equal(canonicalJson({}), '{}');
  });

  it('should sort object keys', () => {
    assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
    assert.equal(canonicalJson({ b: 1, a: 2 }), canonicalJson({ a: 2, b: 1 }));
  });

  it('should sort keys recursively', () => {
    const value = { z: { y: 1, x: 2 }, a: [3, 1] };
    assert.equal(canonicalJson(value), '{"a":[3,1],"z":{"x":2,"y":1}}');
  });

  it('should serialize negative zero as 0', () => {
    assert.equal(canonicalJson({ n: -0 }), '{"n":0}');
  });

  it('should preserve string content via JSON escaping', () => {
    assert.equal(canonicalJson({ s: 'a"b\\c' }), '{"s":"a\\"b\\\\c"}');
    assert.equal(canonicalJson({ s: 'line\nbreak\ttab' }), '{"s":"line\\nbreak\\ttab"}');
  });

  it('should support empty arrays and null', () => {
    assert.equal(canonicalJson({ a: [], b: null }), '{"a":[],"b":null}');
  });

  it('should reject non-finite numbers', () => {
    throwsCode(() => canonicalJson({ v: NaN }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => canonicalJson({ v: Infinity }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => canonicalJson({ v: -Infinity }), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should reject floats in hashed positions', () => {
    throwsCode(() => canonicalJson({ v: 1.5 }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => canonicalJson({ v: 0.1 }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => canonicalJson({ v: 1e21 }), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should accept safe integers', () => {
    assert.equal(canonicalJson({ v: Number.MAX_SAFE_INTEGER }), `{"v":${Number.MAX_SAFE_INTEGER}}`);
    assert.equal(canonicalJson({ v: -100 }), '{"v":-100}');
  });

  it('should reject unsafe integers', () => {
    throwsCode(() => canonicalJson({ v: Number.MAX_SAFE_INTEGER + 2 }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => canonicalJson({ v: 1e16 + 2 }), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should reject undefined values', () => {
    throwsCode(() => canonicalJson({ v: undefined }), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should reject functions, symbols and class instances', () => {
    throwsCode(() => canonicalJson({ v: () => 1 }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => canonicalJson({ v: Symbol('x') }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => canonicalJson({ v: new Date() }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => canonicalJson({ v: Buffer.from('x') }), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should reject sparse arrays', () => {
    const sparse = [];
    sparse[3] = 1;
    throwsCode(() => canonicalJson({ a: sparse }), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should reject forbidden and prototype keys', () => {
    throwsCode(() => canonicalJson({ ['__proto__']: 1 }), ERROR_CODES.VG_CANONICAL_INVALID);
    const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
    throwsCode(() => canonicalJson(parsed), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should reject lone surrogates', () => {
    throwsCode(() => canonicalJson({ s: String.fromCharCode(0xd800) }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => canonicalJson({ s: String.fromCharCode(0xdc00) }), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should accept well formed surrogate pairs', () => {
    const emoji = String.fromCodePoint(0x1f600);
    assert.equal(canonicalJson({ s: emoji }), `{"s":${JSON.stringify(emoji)}}`);
  });

  it('should reject nesting beyond the depth limit', () => {
    let deep = { v: 1 };
    for (let i = 0; i < 40; i++) deep = { n: deep };
    throwsCode(() => canonicalJson(deep), ERROR_CODES.VG_CANONICAL_INVALID);
    assert.equal(DEFAULT_MAX_DEPTH, 32);
  });

  it('should reject objects that are not plain', () => {
    const withProto = Object.create({ inherited: true });
    withProto.own = 1;
    throwsCode(() => canonicalJson({ v: withProto }), ERROR_CODES.VG_CANONICAL_INVALID);
  });
});

describe('VisionGuard parseCanonical', () => {
  it('should parse and accept canonical input', () => {
    assert.deepEqual(parseCanonical('{"a":1,"b":2}'), { a: 1, b: 2 });
  });

  it('should reject invalid JSON', () => {
    throwsCode(() => parseCanonical('{'), ERROR_CODES.VG_MANIFEST_MALFORMED);
    throwsCode(() => parseCanonical(''), ERROR_CODES.VG_MANIFEST_MALFORMED);
    throwsCode(() => parseCanonical('not json'), ERROR_CODES.VG_MANIFEST_MALFORMED);
  });

  it('should reject non-canonical values inside valid JSON', () => {
    throwsCode(() => parseCanonical('{"a":1.5}'), ERROR_CODES.VG_CANONICAL_INVALID);
    assert.deepEqual(parseCanonical('{"a":null}'), { a: null });
    assert.deepEqual(parseCanonical('{"a":true}'), { a: true });
  });

  it('should reject input larger than the byte limit', () => {
    throwsCode(
      () => parseCanonical('{"a":"0123456789"}', { maxBytes: 8 }),
      ERROR_CODES.VG_MANIFEST_MALFORMED
    );
  });

  it('should reject input deeper than the depth limit', () => {
    let text = '{"a":1}';
    let value = 1;
    for (let i = 0; i < 10; i++) value = { a: value };
    text = JSON.stringify({ a: value });
    throwsCode(() => parseCanonical(text, { maxDepth: 4 }), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should count bytes in utf8', () => {
    const payload = JSON.stringify({ s: String.fromCodePoint(0x1f600) });
    const byteLength = Buffer.byteLength(payload, 'utf8');
    throwsCode(() => parseCanonical(payload, { maxBytes: byteLength - 1 }), ERROR_CODES.VG_MANIFEST_MALFORMED);
    parseCanonical(payload, { maxBytes: byteLength });
  });
});

describe('VisionGuard hashRecord', () => {
  it('should produce a sha256 prefixed hex digest', () => {
    const digest = hashRecord({ id: 1, name: 'sample' });
    assert.match(digest, /^sha256:[0-9a-f]{64}$/);
  });

  it('should be independent of key order', () => {
    assert.equal(hashRecord({ a: 1, b: 2 }), hashRecord({ b: 2, a: 1 }));
  });

  it('should be deterministic', () => {
    const value = { a: 1, b: [1, 2, { c: 'x' }] };
    assert.equal(hashRecord(value), hashRecord(value));
  });

  it('should ignore record_hash and signature fields', () => {
    const base = hashRecord({ id: 1, name: 'x' });
    assert.equal(base, hashRecord({ id: 1, name: 'x', record_hash: 'sha256:deadbeef' }));
    assert.equal(base, hashRecord({ id: 1, name: 'x', signature: 'sig' }));
    assert.equal(base, hashRecord({ id: 1, name: 'x', record_hash: 'sha256:deadbeef', signature: 'sig' }));
  });

  it('should ignore record_id so record_id can equal record_hash', () => {
    const body = { id: 1, name: 'x' };
    const base = hashRecord(body);
    assert.equal(base, hashRecord({ ...body, record_id: base }));
    assert.equal(
      hashRecord({ ...body, record_id: base, record_hash: base, signature: 'sig' }),
      base
    );
  });

  it('should still cover the value of a nested record_id field', () => {
    assert.notEqual(
      hashRecord({ nested: { record_id: 'a' } }),
      hashRecord({ nested: { record_id: 'b' } })
    );
  });

  it('should change when content changes', () => {
    assert.notEqual(hashRecord({ id: 1 }), hashRecord({ id: 2 }));
    assert.notEqual(hashRecord({ id: 1 }), hashRecord({ id: 1, extra: true }));
  });

  it('should hash the empty object to sha256 of {}', () => {
    assert.equal(
      hashRecord({}),
      'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'
    );
  });

  it('should reject non-object records', () => {
    throwsCode(() => hashRecord(null), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => hashRecord('string'), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => hashRecord([1, 2]), ERROR_CODES.VG_CANONICAL_INVALID);
  });

  it('should reject records with non-canonical content', () => {
    throwsCode(() => hashRecord({ v: 1.5 }), ERROR_CODES.VG_CANONICAL_INVALID);
    throwsCode(() => hashRecord({ v: undefined }), ERROR_CODES.VG_CANONICAL_INVALID);
  });
});

describe('VisionGuard canonicalDigest', () => {
  it('should return raw hex without prefix', () => {
    const digest = canonicalDigest({ a: 1 });
    assert.match(digest, /^[0-9a-f]{64}$/);
    assert.equal(`sha256:${digest}`, hashRecord({ a: 1 }));
  });
});
