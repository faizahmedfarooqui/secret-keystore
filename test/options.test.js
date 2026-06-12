'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
    validateKmsKeyId,
    buildEncryptOptions,
    buildDecryptOptions,
    deepMerge,
    ValidationError,
    DEFAULT_ENCRYPT_OPTIONS
} = require('../src/index');

test('validateKmsKeyId accepts ARN, alias, and UUID', () => {
    assert.doesNotThrow(() =>
        validateKmsKeyId(
            'arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-ab12-cd34ef567890'
        )
    );
    assert.doesNotThrow(() => validateKmsKeyId('alias/my-key'));
    assert.doesNotThrow(() => validateKmsKeyId('abcd1234-ef56-7890-ab12-cd34ef567890'));
});

test('validateKmsKeyId rejects empty and malformed ids', () => {
    assert.throws(() => validateKmsKeyId(''), ValidationError);
    assert.throws(() => validateKmsKeyId(null), ValidationError);
    assert.throws(() => validateKmsKeyId('just-a-string'), ValidationError);
});

test('buildEncryptOptions returns defaults and merges overrides', () => {
    const opts = buildEncryptOptions();
    assert.equal(typeof opts, 'object');

    const custom = buildEncryptOptions({ output: { format: 'base64' } });
    assert.equal(custom.output.format, 'base64');
});

test('buildDecryptOptions returns an object', () => {
    assert.equal(typeof buildDecryptOptions(), 'object');
});

test('DEFAULT_ENCRYPT_OPTIONS is exported', () => {
    assert.equal(typeof DEFAULT_ENCRYPT_OPTIONS, 'object');
});

test('deepMerge merges nested objects without losing keys', () => {
    const merged = deepMerge({ a: { x: 1 }, b: 2 }, { a: { y: 3 } });
    assert.deepEqual(merged, { a: { x: 1, y: 3 }, b: 2 });
});
