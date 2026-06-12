'use strict';

/**
 * Shared AWS KMS mock for the test suite.
 *
 * Strategy: a fully offline, reversible stand-in for KMS.
 *   - Encrypt  → CiphertextBlob = [MARKER, ...plaintextBytes]
 *   - Decrypt  → Plaintext      = ciphertextBytes without the leading MARKER
 *   - DescribeKey → returns the configured KeySpec
 *
 * MARKER (0xAA) is deliberately not 0x01 (the library's ENVELOPE_VERSION byte),
 * so symmetric ciphertext is never mistaken for an RSA envelope. The same
 * reversible scheme also round-trips the wrapped data key on the RSA path,
 * where the envelope's real AES-256-GCM crypto runs locally.
 */

const { mockClient } = require('aws-sdk-client-mock');
const {
    KMSClient,
    EncryptCommand,
    DecryptCommand,
    DescribeKeyCommand
} = require('@aws-sdk/client-kms');

const MARKER = 0xaa;

function setupKmsMock({ keySpec = 'SYMMETRIC_DEFAULT' } = {}) {
    const kms = mockClient(KMSClient);

    kms.on(DescribeKeyCommand).callsFake(() => ({
        KeyMetadata: { KeySpec: keySpec }
    }));

    kms.on(EncryptCommand).callsFake(input => {
        const plaintext = Buffer.from(input.Plaintext);
        const blob = Buffer.concat([Buffer.from([MARKER]), plaintext]);
        return { CiphertextBlob: new Uint8Array(blob) };
    });

    kms.on(DecryptCommand).callsFake(input => {
        const ciphertext = Buffer.from(input.CiphertextBlob);
        return { Plaintext: new Uint8Array(ciphertext.subarray(1)) };
    });

    return kms;
}

module.exports = { setupKmsMock, MARKER };
