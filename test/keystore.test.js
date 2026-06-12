'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { setupKmsMock } = require('./helpers/kms-mock');
const { createSecretKeyStore, encryptKMSValues } = require('../src/index');

const KEY = 'alias/keystore-test';

let kms;
before(() => {
    kms = setupKmsMock({ keySpec: 'SYMMETRIC_DEFAULT' });
});
after(() => kms.restore());

async function buildStore() {
    const enc = await encryptKMSValues({ API_KEY: 'abc123', DB_PASS: 'p@ssw0rd' }, KEY);
    return createSecretKeyStore({ type: 'values', values: enc.values }, KEY);
}

test('createSecretKeyStore decrypts secrets and exposes them', async () => {
    const store = await buildStore();
    assert.equal(store.isInitialized(), true);
    assert.equal(store.get('API_KEY'), 'abc123');
    assert.equal(store.get('DB_PASS'), 'p@ssw0rd');
    assert.equal(store.has('API_KEY'), true);
    assert.equal(store.has('NOPE'), false);
    assert.deepEqual(store.keys().sort(), ['API_KEY', 'DB_PASS']);
    store.destroy();
});

test('getAll returns the full decrypted map', async () => {
    const store = await buildStore();
    assert.deepEqual(store.getAll(), { API_KEY: 'abc123', DB_PASS: 'p@ssw0rd' });
    store.destroy();
});

test('metadata reflects secret count and source type', async () => {
    const store = await buildStore();
    const meta = store.getMetadata();
    assert.equal(meta.initialized, true);
    assert.equal(meta.secretCount, 2);
    assert.equal(meta.sourceType, 'values');
    store.destroy();
});

test('destroy() marks the store destroyed', async () => {
    const store = await buildStore();
    store.destroy();
    assert.equal(store.getMetadata().destroyed, true);
});
