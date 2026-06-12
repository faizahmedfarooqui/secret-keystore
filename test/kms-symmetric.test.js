'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { setupKmsMock } = require('./helpers/kms-mock');
const {
    encryptKMSValue,
    decryptKMSValue,
    encryptKMSValues,
    decryptKMSValues,
    isEncryptedFormat
} = require('../src/index');

const KEY = 'alias/symmetric-test';

let kms;
before(() => {
    kms = setupKmsMock({ keySpec: 'SYMMETRIC_DEFAULT' });
});
after(() => kms.restore());

test('encryptKMSValue → decryptKMSValue round-trip (prefixed default)', async () => {
    const enc = await encryptKMSValue('super-secret', KEY);
    assert.equal(typeof enc, 'string');
    assert.equal(isEncryptedFormat(enc), true);

    const dec = await decryptKMSValue(enc, KEY);
    assert.equal(dec, 'super-secret');
});

test('output format: base64 returns raw base64 (no ENC[] wrapper)', async () => {
    const enc = await encryptKMSValue('v', KEY, { output: { format: 'base64' } });
    assert.equal(typeof enc, 'string');
    assert.equal(isEncryptedFormat(enc), false);

    const dec = await decryptKMSValue(enc, KEY, { input: { format: 'base64' } });
    assert.equal(dec, 'v');
});

test('output format: buffer returns a Buffer', async () => {
    const enc = await encryptKMSValue('v', KEY, { output: { format: 'buffer' } });
    assert.ok(Buffer.isBuffer(enc));

    const dec = await decryptKMSValue(enc, KEY);
    assert.equal(dec, 'v');
});

test('encryptKMSValues / decryptKMSValues round-trip a map', async () => {
    const enc = await encryptKMSValues({ A: 'one', B: 'two' }, KEY);
    assert.deepEqual(enc.encrypted.sort(), ['A', 'B']);
    assert.equal(isEncryptedFormat(enc.values.A), true);
    assert.equal(isEncryptedFormat(enc.values.B), true);

    const dec = await decryptKMSValues(enc.values, KEY);
    assert.equal(dec.values.A, 'one');
    assert.equal(dec.values.B, 'two');
    assert.deepEqual(dec.decrypted.sort(), ['A', 'B']);
});

test('encryptKMSValues skips empty values by default', async () => {
    const enc = await encryptKMSValues({ A: '', B: 'x' }, KEY);
    assert.deepEqual(enc.skipped, ['A']);
    assert.deepEqual(enc.encrypted, ['B']);
});

test('encryptKMSValues skips already-encrypted values by default', async () => {
    const enc = await encryptKMSValue('x', KEY);
    const second = await encryptKMSValues({ A: enc }, KEY);
    assert.deepEqual(second.skipped, ['A']);
});
