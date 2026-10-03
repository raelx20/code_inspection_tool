const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  ALGORITHM,
  OPERATIONS,
  defaultKeyDir,
  keyIdFromDer,
  generateKeyPair,
  privateKeyPath,
  savePrivateKey,
  loadPrivateKey,
  signRecordHash,
  verifySignature,
  buildPublicKeyRecord,
  validatePublicKeyRecord,
  publicKeyPath,
  savePublicKey,
  loadPublicKey,
} = require('../../../src/visionguard/keys');
const { hashRecord } = require('../../../src/visionguard/canonical');
const { ERROR_CODES, isVgError } = require('../../../src/visionguard/errors');

function throwsCode(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(isVgError(err), `expected VgError, got ${err && err.name}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
    return true;
  });
}

function makeFixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-keys-'));
  const storeDir = path.join(parent, '.visionguard');
  const keyDir = path.join(parent, 'keys');
  fs.mkdirSync(storeDir, { recursive: true });
  t.after(() => {
    try {
      fs.rmSync(parent, { recursive: true, force: true });
    } catch {
    }
  });
  return { parent, storeDir, keyDir };
}

const SAMPLE_HASH = `sha256:${'a'.repeat(64)}`;

describe('VisionGuard key generation', () => {
  it('should generate an ed25519 pair with a 32 hex key id', () => {
    const pair = generateKeyPair();
    assert.equal(pair.publicKey.asymmetricKeyType, ALGORITHM);
    assert.match(pair.keyId, /^[0-9a-f]{32}$/);
    assert.ok(Buffer.isBuffer(pair.publicKeyDer));
    assert.ok(Buffer.isBuffer(pair.privateKeyDer));
    assert.equal(keyIdFromDer(pair.publicKeyDer), pair.keyId);
  });

  it('should derive distinct key ids for distinct keys', () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    assert.notEqual(a.keyId, b.keyId);
    assert.equal(keyIdFromDer(a.publicKeyDer), a.keyId);
  });

  it('should expose the documented default key directory', () => {
    assert.ok(defaultKeyDir().includes(path.join('.codesentry', 'visionguard', 'keys')));
  });
});

describe('VisionGuard private key files', () => {
  it('should save and reload a private key that still signs', (t) => {
    const { keyDir } = makeFixture(t);
    const pair = generateKeyPair();
    const filePath = savePrivateKey(keyDir, 'alice', pair.keyId, pair.privateKeyDer);
    assert.equal(filePath, privateKeyPath(keyDir, 'alice', pair.keyId));
    assert.ok(fs.existsSync(filePath));
    const reloaded = loadPrivateKey(filePath);
    assert.equal(reloaded.asymmetricKeyType, ALGORITHM);
    const signature = signRecordHash(reloaded, SAMPLE_HASH);
    assert.ok(verifySignature(pair.publicKeyDer, SAMPLE_HASH, signature));
  });

  it('should refuse to overwrite an existing private key', (t) => {
    const { keyDir } = makeFixture(t);
    const pair = generateKeyPair();
    savePrivateKey(keyDir, 'alice', pair.keyId, pair.privateKeyDer);
    throwsCode(
      () => savePrivateKey(keyDir, 'alice', pair.keyId, pair.privateKeyDer),
      ERROR_CODES.VG_KEY_UNKNOWN
    );
  });

  it('should reject a garbage private key file', (t) => {
    const { keyDir } = makeFixture(t);
    const pair = generateKeyPair();
    const filePath = privateKeyPath(keyDir, 'alice', pair.keyId);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, 'not-a-key');
    throwsCode(() => loadPrivateKey(filePath), ERROR_CODES.VG_KEY_UNKNOWN);
    fs.writeFileSync(filePath, '');
    throwsCode(() => loadPrivateKey(filePath), ERROR_CODES.VG_KEY_UNKNOWN);
  });

  it('should reject a non-ed25519 private key', (t) => {
    const { keyDir } = makeFixture(t);
    const crypto = require('node:crypto');
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const der = rsa.privateKey.export({ type: 'pkcs8', format: 'der' });
    const filePath = path.join(keyDir, 'alice', 'deadbeef.key');
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${der.toString('base64')}\n`);
    throwsCode(() => loadPrivateKey(filePath), ERROR_CODES.VG_KEY_UNKNOWN);
  });

  it('should reject unsafe contributors and key ids in paths', () => {
    const pair = generateKeyPair();
    throwsCode(() => privateKeyPath('/keys', '../escape', pair.keyId), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => privateKeyPath('/keys', 'alice', 'not-hex'), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => privateKeyPath('/keys', 'a/b', pair.keyId), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });
});

describe('VisionGuard signatures', () => {
  it('should verify a signature over the record hash string', () => {
    const pair = generateKeyPair();
    const signature = signRecordHash(pair.privateKey, SAMPLE_HASH);
    assert.equal(verifySignature(pair.publicKeyDer, SAMPLE_HASH, signature), true);
    assert.equal(verifySignature(pair.publicKeyDer, `sha256:${'b'.repeat(64)}`, signature), false);
    assert.equal(verifySignature(pair.publicKeyDer, 'not-a-hash', signature), false);
  });

  it('should reject a signature made by another key', () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    const signature = signRecordHash(a.privateKey, SAMPLE_HASH);
    assert.equal(verifySignature(b.publicKeyDer, SAMPLE_HASH, signature), false);
  });

  it('should reject malformed signatures without throwing', () => {
    const pair = generateKeyPair();
    assert.equal(verifySignature(pair.publicKeyDer, SAMPLE_HASH, 42), false);
    assert.equal(verifySignature(pair.publicKeyDer, SAMPLE_HASH, '***not base64***'), false);
    assert.equal(verifySignature(pair.publicKeyDer, SAMPLE_HASH, Buffer.alloc(10).toString('base64')), false);
    assert.equal(verifySignature(Buffer.from('nope'), SAMPLE_HASH, 'AAAA'), false);
    assert.equal(verifySignature(pair.publicKeyDer, SAMPLE_HASH, Buffer.alloc(64).toString('base64')), false);
  });
});

describe('VisionGuard public key records', () => {
  it('should build a self signed record that round trips', (t) => {
    const { storeDir } = makeFixture(t);
    const pair = generateKeyPair();
    const record = buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: pair.publicKeyDer,
      operations: [...OPERATIONS],
      privateKey: pair.privateKey,
      now: '2026-10-02T12:00:00.000Z',
    });
    assert.equal(record.kind, 'public_key');
    assert.equal(record.algorithm, 'ed25519');
    assert.equal(record.key_id, pair.keyId);
    assert.equal(record.status, 'active');
    assert.equal(record.record_hash, hashRecord(record));
    assert.equal(validatePublicKeyRecord(record).contributor, 'alice');

    savePublicKey(storeDir, record);
    const loaded = loadPublicKey(storeDir, 'alice', pair.keyId);
    assert.deepEqual(loaded, record);
    throwsCode(() => loadPublicKey(storeDir, 'bob', pair.keyId), ERROR_CODES.VG_NOT_REGISTERED);
  });

  it('should recompute key_id from the DER so a substituted key cannot keep it', () => {
    const victim = generateKeyPair();
    const attacker = generateKeyPair();
    const record = buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: victim.publicKeyDer,
      operations: ['train'],
      privateKey: victim.privateKey,
      now: '2026-10-02T12:00:00.000Z',
    });
    const substituted = {
      ...record,
      public_key_der_b64: attacker.publicKeyDer.toString('base64'),
    };
    substituted.record_hash = hashRecord(substituted);
    substituted.signature = signRecordHash(attacker.privateKey, substituted.record_hash);
    throwsCode(() => validatePublicKeyRecord(substituted), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should detect a tampered key record by hash and by signature', () => {
    const pair = generateKeyPair();
    const record = buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: pair.publicKeyDer,
      operations: ['train'],
      privateKey: pair.privateKey,
      now: '2026-10-02T12:00:00.000Z',
    });

    const edited = { ...record, operations: [...OPERATIONS] };
    throwsCode(() => validatePublicKeyRecord(edited), ERROR_CODES.VG_MANIFEST_HASH_MISMATCH);

    const resigned = { ...record, operations: [...OPERATIONS] };
    resigned.record_hash = hashRecord(resigned);
    throwsCode(() => validatePublicKeyRecord(resigned), ERROR_CODES.VG_KEY_UNKNOWN);
  });

  it('should require an unsigned record to be revoked', () => {
    const pair = generateKeyPair();
    const active = buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: pair.publicKeyDer,
      operations: ['train'],
      privateKey: pair.privateKey,
      now: '2026-10-02T12:00:00.000Z',
    });
    const stripped = { ...active, signature: null };
    stripped.record_hash = hashRecord(stripped);
    throwsCode(() => validatePublicKeyRecord(stripped), ERROR_CODES.VG_KEY_UNKNOWN);

    const revoked = buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: pair.publicKeyDer,
      operations: ['train'],
      status: 'revoked',
      now: '2026-10-02T12:00:00.000Z',
    });
    assert.equal(revoked.signature, null);
    assert.equal(validatePublicKeyRecord(revoked).status, 'revoked');
  });

  it('should reject unsupported fields, operations and statuses', () => {
    const pair = generateKeyPair();
    const record = buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: pair.publicKeyDer,
      operations: ['train'],
      privateKey: pair.privateKey,
      now: '2026-10-02T12:00:00.000Z',
    });
    const bad = (patch) => {
      const next = { ...record, ...patch };
      next.record_hash = hashRecord(next);
      return next;
    };
    throwsCode(() => validatePublicKeyRecord(bad({ operations: ['mine'] })), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validatePublicKeyRecord(bad({ status: 'bogus' })), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validatePublicKeyRecord(bad({ kind: 'other' })), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(
      () => validatePublicKeyRecord(bad({ operations: ['train', 'train'] })),
      ERROR_CODES.VG_MANIFEST_SCHEMA
    );
    throwsCode(() => validatePublicKeyRecord(bad({ extra: 1 }), { strict: true }), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => validatePublicKeyRecord(bad({ extra: 1 })), ERROR_CODES.VG_KEY_UNKNOWN);
    throwsCode(() => validatePublicKeyRecord(bad({ created_at: 'yesterday' })), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });

  it('should reject an active record signed with the wrong key', () => {
    const pair = generateKeyPair();
    const other = generateKeyPair();
    const record = buildPublicKeyRecord({
      contributor: 'alice',
      publicKeyDer: pair.publicKeyDer,
      operations: ['train'],
      privateKey: pair.privateKey,
      now: '2026-10-02T12:00:00.000Z',
    });
    const forged = { ...record };
    forged.signature = signRecordHash(other.privateKey, record.record_hash);
    throwsCode(() => validatePublicKeyRecord(forged), ERROR_CODES.VG_KEY_UNKNOWN);
  });

  it('should build store paths only from validated inputs', (t) => {
    const { storeDir } = makeFixture(t);
    const pair = generateKeyPair();
    assert.equal(
      publicKeyPath(storeDir, 'alice', pair.keyId),
      path.join(storeDir, 'keys', 'alice', `${pair.keyId}.pub.json`)
    );
    throwsCode(() => publicKeyPath(storeDir, '../escape', pair.keyId), ERROR_CODES.VG_MANIFEST_SCHEMA);
    throwsCode(() => publicKeyPath(storeDir, 'alice', 'xyz'), ERROR_CODES.VG_MANIFEST_SCHEMA);
  });
});
