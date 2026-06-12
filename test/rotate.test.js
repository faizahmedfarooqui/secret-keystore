'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { setupKmsMock } = require('./helpers/kms-mock');
const {
    rotateKMSContent,
    encryptKMSEnvContent,
    decryptKMSEnvContent,
    encryptKMSObject,
    isEncryptedFormat
} = require('../src/index');

const OLD_KEY = 'alias/old-key';
const NEW_KEY = 'alias/new-key';

let kms;
before(() => {
    kms = setupKmsMock({ keySpec: 'SYMMETRIC_DEFAULT' });
});
after(() => kms.restore());

test('.env: rotates only previously-encrypted keys, leaves plaintext alone', async () => {
    const original = ['PLAIN=keepme', 'SECRET=topsecret'].join('\n');
    const encrypted = await encryptKMSEnvContent(original, OLD_KEY, { paths: ['SECRET'] });

    const rotated = await rotateKMSContent(encrypted.content, 'env', OLD_KEY, NEW_KEY);

    assert.deepEqual(rotated.rotated, ['SECRET']);
    // Still decryptable (now under the new key) and round-trips to the original value
    const dec = await decryptKMSEnvContent(rotated.content, NEW_KEY);
    assert.match(dec.content, /^PLAIN=keepme$/m);
    assert.match(dec.content, /^SECRET=topsecret$/m);
});

test('.env: plaintext-only file rotates nothing', async () => {
    const original = 'A=1\nB=2';
    const rotated = await rotateKMSContent(original, 'env', OLD_KEY, NEW_KEY);
    assert.deepEqual(rotated.rotated, []);
});

test('JSON: rotates encrypted leaf paths', async () => {
    const obj = { db: { password: 'p@ss' }, name: 'app' };
    const encrypted = await encryptKMSObject(obj, OLD_KEY, { patterns: ['**.password'] });
    const encryptedJson = JSON.stringify(encrypted.object, null, 2);

    const rotated = await rotateKMSContent(encryptedJson, 'json', OLD_KEY, NEW_KEY);
    assert.deepEqual(rotated.rotated, ['db.password']);

    const out = JSON.parse(rotated.content);
    assert.ok(isEncryptedFormat(out.db.password));
    assert.equal(out.name, 'app');
});

test('YAML: rotates encrypted leaf paths', async () => {
    const encrypted = await encryptKMSObject({ db: { password: 'secret' }, name: 'app' }, OLD_KEY, {
        patterns: ['**.password']
    });
    const encryptedYaml = require('../src/index').serializeYaml(encrypted.object);

    const rotated = await rotateKMSContent(encryptedYaml, 'yaml', OLD_KEY, NEW_KEY);
    assert.deepEqual(rotated.rotated, ['db.password']);
});

test('unsupported format throws', async () => {
    await assert.rejects(
        () => rotateKMSContent('x', 'ini', OLD_KEY, NEW_KEY),
        /Unsupported format/
    );
});
