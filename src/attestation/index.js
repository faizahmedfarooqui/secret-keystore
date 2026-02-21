/**
 * @faizahmedfarooqui/secret-keystore - Attestation Module
 *
 * Complete AWS Nitro Enclave attestation support including:
 * - Ephemeral RSA key pair generation
 * - Attestation document fetching from Anjuna/Nitro endpoints
 * - CMS EnvelopedData unwrapping with PKIjs
 * - Lifecycle management with 5-minute refresh
 */

// Key pair utilities
const {
    generateEphemeralKeyPair,
    pemToDerPublic,
    pemToDerPrivate,
    toBase64Url,
    toBase64,
    generateNonce,
    prepareAttestationParams
} = require('./key-pair');

// CMS unwrapping
const {
    unwrapCms,
    importPrivateKey,
    validatePrivateKeyFormat,
    initializePkijsEngine
} = require('./cms-unwrap');

// Attestation client
const {
    fetchAttestationDocument,
    isNitroEnclave,
    isAttestationAvailable,
    DEFAULT_ATTESTATION_ENDPOINT
} = require('./attestation-client');

// Attestation manager
const {
    AttestationManager,
    createAttestationManager
} = require('./attestation-manager');

module.exports = {
    // Key pair
    generateEphemeralKeyPair,
    pemToDerPublic,
    pemToDerPrivate,
    toBase64Url,
    toBase64,
    generateNonce,
    prepareAttestationParams,

    // CMS
    unwrapCms,
    importPrivateKey,
    validatePrivateKeyFormat,
    initializePkijsEngine,

    // Client
    fetchAttestationDocument,
    isNitroEnclave,
    isAttestationAvailable,
    DEFAULT_ATTESTATION_ENDPOINT,

    // Manager
    AttestationManager,
    createAttestationManager
};

