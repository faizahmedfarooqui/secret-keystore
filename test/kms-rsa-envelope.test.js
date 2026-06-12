'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { setupKmsMock } = require('./helpers/kms-mock');
const {
    encryptKMSValue,
    decryptKMSValue,
    isEnvelopeFormat,
    unwrapCiphertext
} = require('../src/index');

const KEY = 'alias/rsa-test';

let kms;
before(() => {
    kms = setupKmsMock({ keySpec: 'RSA_4096' });
});
after(() => kms.restore());

test('RSA key uses AES-256-GCM envelope encryption', async () => {
    const enc = await encryptKMSValue('secret-value', KEY);
    // The wrapped ciphertext decodes to an envelope (version byte 0x01)
    const raw = Buffer.from(unwrapCiphertext(enc), 'base64');
    assert.equal(isEnvelopeFormat(raw), true);
});

test('envelope round-trips a value larger than the RSA direct-encrypt limit', async () => {
    const big = 'x'.repeat(2000);
    const enc = await encryptKMSValue(big, KEY);
    const dec = await decryptKMSValue(enc, KEY);
    assert.equal(dec, big);
});

test('envelope round-trip preserves exact bytes', async () => {
    const value = 'p@ss w0rd with spaces & symbols #!';
    const enc = await encryptKMSValue(value, KEY);
    assert.notEqual(enc, value);
    assert.equal(await decryptKMSValue(enc, KEY), value);
});
