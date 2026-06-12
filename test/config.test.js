'use strict';

const { test, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { setupKmsMock } = require('./helpers/kms-mock');
const { config, resolveEnvFiles, encryptKMSValue } = require('../src/index');

const KEY = 'alias/config-test';

let kms;
before(() => {
    kms = setupKmsMock({ keySpec: 'SYMMETRIC_DEFAULT' });
});
after(() => kms.restore());

let dir;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sks-config-'));
});
afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
});

function write(name, content) {
    fs.writeFileSync(path.join(dir, name), content);
}

// Produce an ENC[...] value via the mocked KMS.
async function enc(value) {
    return encryptKMSValue(value, KEY);
}

test('loads a single .env: decrypts ENC[] and passes plaintext through', async () => {
    write('.env', ['PLAIN=hello', `SECRET=${await enc('topsecret')}`].join('\n'));

    const store = await config({ kmsKeyId: KEY, cwd: dir });

    assert.equal(store.get('PLAIN'), 'hello');
    assert.equal(store.get('SECRET'), 'topsecret');
    store.destroy();
});

test('cascade: .env.local overrides .env (later wins)', async () => {
    write('.env', `TOKEN=${await enc('base')}`);
    write('.env.local', `TOKEN=${await enc('local-override')}`);

    const store = await config({ kmsKeyId: KEY, cwd: dir });
    assert.equal(store.get('TOKEN'), 'local-override');
    store.destroy();
});

test('cascade: .env.<NODE_ENV> participates when nodeEnv is set', async () => {
    write('.env', `API=${await enc('default')}`);
    write('.env.production', `API=${await enc('prod')}`);

    const store = await config({ kmsKeyId: KEY, cwd: dir, nodeEnv: 'production' });
    assert.equal(store.get('API'), 'prod');
    store.destroy();
});

test('explicit path skips the cascade', async () => {
    write('.env', `X=${await enc('from-default')}`);
    write('custom.env', `X=${await enc('from-custom')}`);

    const store = await config({ kmsKeyId: KEY, cwd: dir, path: 'custom.env' });
    assert.equal(store.get('X'), 'from-custom');
    store.destroy();
});

test('missing kmsKeyId throws (explicit-only)', async () => {
    write('.env', 'A=1');
    await assert.rejects(() => config({ cwd: dir }), /kmsKeyId/);
});

test('does not touch process.env by default; opt-in populates with override', async () => {
    write('.env', `DB_PASS=${await enc('p@ss')}`);

    const fakeEnv = { DB_PASS: 'pre-existing' };

    const store1 = await config({ kmsKeyId: KEY, cwd: dir, processEnv: fakeEnv });
    assert.equal(fakeEnv.DB_PASS, 'pre-existing'); // untouched by default
    store1.destroy();

    const store2 = await config({
        kmsKeyId: KEY,
        cwd: dir,
        populateProcessEnv: true,
        processEnv: fakeEnv
    });
    assert.equal(fakeEnv.DB_PASS, 'p@ss'); // overridden when opted in
    store2.destroy();
});

test('writes nothing decrypted to disk', async () => {
    write('.env', `S=${await enc('secret')}`);
    const before = fs.readdirSync(dir).sort();

    const store = await config({ kmsKeyId: KEY, cwd: dir });
    const after = fs.readdirSync(dir).sort();

    assert.deepEqual(after, before); // no new files created
    store.destroy();
});

test('resolveEnvFiles returns existing files in cascade order', async () => {
    write('.env', 'A=1');
    write('.env.local', 'A=2');
    write('.env.test', 'A=3');

    const files = resolveEnvFiles({ cwd: dir, nodeEnv: 'test' }).map(f => path.basename(f));
    assert.deepEqual(files, ['.env', '.env.local', '.env.test']);
});
