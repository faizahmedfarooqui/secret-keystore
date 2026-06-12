'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { setupKmsMock } = require('./helpers/kms-mock');
const { encryptKMSObject, decryptKMSObject, isEncryptedFormat } = require('../src/index');

const KEY = 'alias/object-test';

let kms;
before(() => {
    kms = setupKmsMock({ keySpec: 'SYMMETRIC_DEFAULT' });
});
after(() => kms.restore());

test('encryptKMSObject encrypts only matched paths', async () => {
    const obj = { db: { password: 'p@ss', host: 'localhost' }, name: 'app' };
    const enc = await encryptKMSObject(obj, KEY, { patterns: ['**.password'] });

    assert.deepEqual(enc.encrypted, ['db.password']);
    assert.ok(isEncryptedFormat(enc.object.db.password));
    assert.equal(enc.object.db.host, 'localhost');
    assert.equal(enc.object.name, 'app');
    // source object is not mutated
    assert.equal(obj.db.password, 'p@ss');
});

test('decryptKMSObject restores matched paths', async () => {
    const obj = { db: { password: 'p@ss' }, name: 'app' };
    const enc = await encryptKMSObject(obj, KEY, { patterns: ['**.password'] });
    const dec = await decryptKMSObject(enc.object, KEY);

    assert.equal(dec.object.db.password, 'p@ss');
    assert.equal(dec.object.name, 'app');
});
