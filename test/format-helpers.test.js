'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
    isEncryptedFormat,
    isKmsCiphertext,
    isAlreadyEncrypted,
    isEnvelopeFormat,
    wrapCiphertext,
    unwrapCiphertext,
    maskKmsKeyId,
    ENCRYPTED_PREFIX,
    ENCRYPTED_SUFFIX
} = require('../src/index');

test('ENC[] prefix/suffix constants', () => {
    assert.equal(ENCRYPTED_PREFIX, 'ENC[');
    assert.equal(ENCRYPTED_SUFFIX, ']');
});

test('wrap/unwrap round-trip', () => {
    const wrapped = wrapCiphertext('abc123');
    assert.equal(wrapped, 'ENC[abc123]');
    assert.equal(unwrapCiphertext(wrapped), 'abc123');
});

test('unwrapCiphertext passes through unwrapped input', () => {
    assert.equal(unwrapCiphertext('plain'), 'plain');
});

test('isEncryptedFormat detects ENC[] wrapping', () => {
    assert.equal(isEncryptedFormat('ENC[xyz]'), true);
    assert.equal(isEncryptedFormat('xyz'), false);
    assert.equal(isEncryptedFormat(''), false);
    assert.equal(isEncryptedFormat(null), false);
    assert.equal(isEncryptedFormat(undefined), false);
});

test('isKmsCiphertext detects raw KMS base64', () => {
    const looksLikeKms = 'AQICAH' + 'A'.repeat(60);
    assert.equal(isKmsCiphertext(looksLikeKms), true);
    assert.equal(isKmsCiphertext('AQICAH'), false); // too short
    assert.equal(isKmsCiphertext('not-kms'), false);
    assert.equal(isKmsCiphertext(null), false);
});

test('isAlreadyEncrypted covers both wrapped and raw', () => {
    assert.equal(isAlreadyEncrypted('ENC[xyz]'), true);
    assert.equal(isAlreadyEncrypted('AQICAH' + 'B'.repeat(60)), true);
    assert.equal(isAlreadyEncrypted('plaintext'), false);
});

test('isEnvelopeFormat checks version byte', () => {
    assert.equal(isEnvelopeFormat(Buffer.from([0x01, 0x02, 0x03])), true);
    assert.equal(isEnvelopeFormat(Buffer.from([0x02, 0x03])), false);
    assert.equal(isEnvelopeFormat(Buffer.from([0x01])), false); // length must be > 1
    assert.equal(isEnvelopeFormat('not-a-buffer'), false);
});

test('maskKmsKeyId hides key material but returns a string', () => {
    const arn = 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-ab12-cd34ef567890';
    const masked = maskKmsKeyId(arn);
    assert.equal(typeof masked, 'string');
    assert.ok(masked.length > 0);
    assert.notEqual(masked, arn);
});
