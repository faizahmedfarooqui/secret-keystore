'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { setupKmsMock } = require('./helpers/kms-mock');
const {
    encryptKMSEnvContent,
    decryptKMSEnvContent,
    encryptKMSJsonContent,
    decryptKMSJsonContent,
    encryptKMSYamlContent,
    decryptKMSYamlContent,
    isEncryptedFormat
} = require('../src/index');

const KEY = 'alias/content-test';

let kms;
before(() => {
    kms = setupKmsMock({ keySpec: 'SYMMETRIC_DEFAULT' });
});
after(() => kms.restore());

test('.env content: encrypt then decrypt restores the original', async () => {
    const original = ['# config', 'FOO=bar', 'SECRET=topsecret'].join('\n');

    const enc = await encryptKMSEnvContent(original, KEY);
    assert.deepEqual(enc.encrypted.sort(), ['FOO', 'SECRET']);
    // base64 padding ('=') makes reconstructEnvContent quote the value
    assert.match(enc.content, /SECRET="?ENC\[/);

    const dec = await decryptKMSEnvContent(enc.content, KEY);
    assert.equal(dec.content, original);
});

test('.env content: path selection only encrypts chosen keys', async () => {
    const original = ['FOO=bar', 'SECRET=topsecret'].join('\n');
    const enc = await encryptKMSEnvContent(original, KEY, { paths: ['SECRET'] });

    assert.deepEqual(enc.encrypted, ['SECRET']);
    assert.match(enc.content, /^FOO=bar$/m); // FOO left untouched
    assert.match(enc.content, /SECRET="?ENC\[/);
});

test('.env content: comments are preserved through a round-trip', async () => {
    const original = ['# top comment', '', 'A=1', 'B=2'].join('\n');
    const enc = await encryptKMSEnvContent(original, KEY);
    const dec = await decryptKMSEnvContent(enc.content, KEY);
    assert.equal(dec.content, original);
});

test('JSON content round-trip at selected paths', async () => {
    const original = JSON.stringify({ db: { password: 'p@ss' }, name: 'app' }, null, 2);
    const enc = await encryptKMSJsonContent(original, KEY, { patterns: ['**.password'] });
    assert.ok(isEncryptedFormat(JSON.parse(enc.content).db.password));
    assert.equal(JSON.parse(enc.content).name, 'app');

    const dec = await decryptKMSJsonContent(enc.content, KEY);
    assert.equal(JSON.parse(dec.content).db.password, 'p@ss');
});

test('YAML content round-trip', async () => {
    const original = 'db:\n  password: secret\nname: app\n';
    const enc = await encryptKMSYamlContent(original, KEY, { patterns: ['**.password'] });
    const dec = await decryptKMSYamlContent(enc.content, KEY);
    const { parseYaml } = require('../src/index');
    assert.equal(parseYaml(dec.content).db.password, 'secret');
});
