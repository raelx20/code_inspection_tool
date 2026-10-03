const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  overallVerdict,
  statusOf,
  worstStatus,
  DIMENSION_NAMES,
  VERIFIED,
  INCOMPLETE,
  VIOLATION,
} = require('../../../src/visionguard/assurance');

function passDims() {
  const dims = {};
  for (const name of DIMENSION_NAMES) dims[name] = { status: 'PASS' };
  return dims;
}

describe('overallVerdict truth table', () => {
  it('should expose exactly the six required dimensions', () => {
    assert.deepEqual(DIMENSION_NAMES, ['dataset', 'model', 'pipeline', 'inference', 'output', 'provenance']);
  });

  it('should return VERIFIED only when every dimension is PASS', () => {
    assert.equal(overallVerdict(passDims()), VERIFIED);
    const withExtras = passDims();
    withExtras.notes = 'ignored';
    assert.equal(overallVerdict(withExtras), VERIFIED);
  });

  it('should return INTEGRITY VIOLATION when any dimension is FAIL', () => {
    for (const name of DIMENSION_NAMES) {
      const dims = passDims();
      dims[name] = { status: 'FAIL' };
      assert.equal(overallVerdict(dims), VIOLATION, `${name} FAIL must force VIOLATION`);
    }
    const mixed = passDims();
    mixed.dataset = 'FAIL';
    mixed.model = 'NOT_CHECKED';
    mixed.provenance = null;
    assert.equal(overallVerdict(mixed), VIOLATION, 'FAIL dominates incomplete dimensions');
    assert.equal(overallVerdict({ dataset: { status: 'FAIL' } }), VIOLATION, 'FAIL with missing dimensions still VIOLATION');
  });

  it('should return INCOMPLETE when any required dimension is not PASS and none is FAIL', () => {
    const statuses = ['NOT_CHECKED', 'UNANCHORED', 'UNSIGNED', 'PARTIAL', '', null, undefined];
    for (const name of DIMENSION_NAMES) {
      for (const status of statuses) {
        const dims = passDims();
        dims[name] = status === undefined ? undefined : { status };
        assert.equal(overallVerdict(dims), INCOMPLETE, `${name}=${String(status)} must be INCOMPLETE`);
      }
      const dims = passDims();
      delete dims[name];
      assert.equal(overallVerdict(dims), INCOMPLETE, `missing ${name} must be INCOMPLETE`);
    }
  });

  it('should return INCOMPLETE for empty or partial dimension sets', () => {
    assert.equal(overallVerdict({}), INCOMPLETE);
    assert.equal(overallVerdict(null), INCOMPLETE);
    assert.equal(overallVerdict(undefined), INCOMPLETE);
    assert.equal(overallVerdict({ dataset: { status: 'PASS' } }), INCOMPLETE);
    const five = passDims();
    delete five.provenance;
    assert.equal(overallVerdict(five), INCOMPLETE);
  });
});

describe('status helpers', () => {
  it('should normalize statuses from strings, objects and missing values', () => {
    assert.equal(statusOf('PASS'), 'PASS');
    assert.equal(statusOf({ status: 'FAIL' }), 'FAIL');
    assert.equal(statusOf({ status: 'PASS' }), 'PASS');
    assert.equal(statusOf(null), 'NOT_CHECKED');
    assert.equal(statusOf(undefined), 'NOT_CHECKED');
    assert.equal(statusOf({}), 'NOT_CHECKED');
    assert.equal(statusOf(42), 'NOT_CHECKED');
    assert.equal(statusOf({ status: 7 }), 'NOT_CHECKED');
  });

  it('should rank worst status as FAIL > UNSIGNED/UNANCHORED > NOT_CHECKED > PASS', () => {
    assert.equal(worstStatus(['PASS']), 'PASS');
    assert.equal(worstStatus(['PASS', 'NOT_CHECKED']), 'NOT_CHECKED');
    assert.equal(worstStatus(['PASS', 'UNANCHORED']), 'UNANCHORED');
    assert.equal(worstStatus(['PASS', 'UNSIGNED']), 'UNSIGNED');
    assert.equal(worstStatus(['UNANCHORED', 'UNSIGNED']), 'UNANCHORED');
    assert.equal(worstStatus(['NOT_CHECKED', 'FAIL']), 'FAIL');
    assert.equal(worstStatus(['UNANCHORED', 'PASS', 'FAIL']), 'FAIL');
    assert.equal(worstStatus([]), 'NOT_CHECKED');
    assert.equal(worstStatus(null), 'NOT_CHECKED');
  });

  it('should map non-PASS provenance-style statuses to INCOMPLETE not VERIFIED', () => {
    const dims = passDims();
    dims.provenance = { status: 'UNANCHORED', anchored: false };
    assert.equal(overallVerdict(dims), INCOMPLETE);
    dims.provenance = { status: 'UNSIGNED' };
    assert.equal(overallVerdict(dims), INCOMPLETE);
  });
});
