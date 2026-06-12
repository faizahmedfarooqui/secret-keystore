'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
    SecretKeyStoreError,
    KmsError,
    ValidationError,
    KMS_ERROR_CODES,
    VALIDATION_ERROR_CODES,
    isRecoverableError,
    createKmsErrorFromAws
} = require('../src/index');

test('SecretKeyStoreError carries code and timestamp', () => {
    const err = new SecretKeyStoreError('boom', 'SOME_CODE');
    assert.ok(err instanceof Error);
    assert.equal(err.code, 'SOME_CODE');
    assert.ok(err.timestamp instanceof Date);
});

test('SecretKeyStoreError.toJSON is serializable', () => {
    const err = new SecretKeyStoreError('boom', 'SOME_CODE', new Error('root'));
    const json = err.toJSON();
    assert.equal(json.code, 'SOME_CODE');
    assert.equal(json.message, 'boom');
    assert.equal(typeof json.timestamp, 'string');
    assert.equal(json.cause.message, 'root');
});

test('KmsError is a SecretKeyStoreError with key context', () => {
    const err = new KmsError('nope', KMS_ERROR_CODES.ACCESS_DENIED, 'alias/k');
    assert.ok(err instanceof SecretKeyStoreError);
    assert.equal(err.kmsKeyId, 'alias/k');
    assert.equal(err.code, 'KMS_ACCESS_DENIED');
});

test('error code constant tables are present', () => {
    assert.equal(KMS_ERROR_CODES.THROTTLED, 'KMS_THROTTLED');
    assert.equal(VALIDATION_ERROR_CODES.KMS_KEY_REQUIRED, 'VALIDATION_KMS_KEY_REQUIRED');
});

test('isRecoverableError flags transient codes only', () => {
    assert.equal(isRecoverableError(new KmsError('t', KMS_ERROR_CODES.THROTTLED, 'k')), true);
    assert.equal(isRecoverableError(new KmsError('a', KMS_ERROR_CODES.ACCESS_DENIED, 'k')), false);
    assert.equal(isRecoverableError(new Error('plain')), false);
});

test('createKmsErrorFromAws maps AWS error names to codes', () => {
    const notFound = createKmsErrorFromAws(
        Object.assign(new Error('key not found'), { name: 'NotFoundException' }),
        'alias/k',
        'decrypt'
    );
    assert.ok(notFound instanceof KmsError);
    assert.equal(notFound.code, KMS_ERROR_CODES.KEY_NOT_FOUND);
    assert.equal(notFound.kmsKeyId, 'alias/k');

    const throttled = createKmsErrorFromAws(
        Object.assign(new Error('rate'), { name: 'ThrottlingException' }),
        'alias/k',
        'encrypt'
    );
    assert.equal(throttled.code, KMS_ERROR_CODES.THROTTLED);

    const encFail = createKmsErrorFromAws(new Error('weird'), 'alias/k', 'encrypt');
    assert.equal(encFail.code, KMS_ERROR_CODES.ENCRYPT_FAILED);
});

test('ValidationError exposes field', () => {
    const err = new ValidationError('bad', VALIDATION_ERROR_CODES.INVALID_VALUE, 'myField');
    assert.equal(err.field, 'myField');
});
