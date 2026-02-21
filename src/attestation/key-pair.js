/**
 * @faizahmedfarooqui/secret-keystore - Ephemeral Key Pair Generation
 *
 * Generates RSA-4096 key pairs for attestation document requests.
 * The public key is embedded in the attestation document, and the
 * private key is used to unwrap the CMS EnvelopedData from KMS.
 */

const crypto = require('node:crypto');

// ═══════════════════════════════════════════════════════════════════════════
// KEY PAIR GENERATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate an ephemeral RSA-4096 key pair for attestation
 * @returns {{ publicKey: string, privateKey: string, publicKeyDer: Buffer, privateKeyDer: Buffer }}
 */
function generateEphemeralKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Export public key as DER (for attestation request)
    const publicKeyDer = crypto.createPublicKey({ key: publicKey, format: 'pem' })
        .export({ format: 'der', type: 'spki' });

    // Export private key as DER (for CMS unwrap with OpenSSL, if needed)
    const privateKeyDer = crypto.createPrivateKey({ key: privateKey, format: 'pem' })
        .export({ format: 'der', type: 'pkcs1' });

    return {
        publicKey,      // PEM format
        privateKey,     // PEM format (PKCS#8)
        publicKeyDer,   // DER format (SPKI)
        privateKeyDer   // DER format (PKCS#1)
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// PEM/DER UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convert PEM public key to DER format
 * @param {string} pem - PEM-encoded public key
 * @returns {Buffer}
 */
function pemToDerPublic(pem) {
    const base64 = String(pem)
        .replaceAll('-----BEGIN PUBLIC KEY-----', '')
        .replaceAll('-----END PUBLIC KEY-----', '')
        .replaceAll(/\s+/g, '');
    return Buffer.from(base64, 'base64');
}

/**
 * Convert PEM private key to DER format (PKCS#8)
 * @param {string} pem - PEM-encoded private key
 * @returns {Buffer}
 */
function pemToDerPrivate(pem) {
    const base64 = String(pem)
        .replaceAll('-----BEGIN PRIVATE KEY-----', '')
        .replaceAll('-----END PRIVATE KEY-----', '')
        .replaceAll(/\s+/g, '');
    return Buffer.from(base64, 'base64');
}

/**
 * Convert buffer to base64url with padding (for attestation params)
 * @param {Buffer} buf
 * @returns {string}
 */
function toBase64Url(buf) {
    return Buffer.from(buf).toString('base64')
        .replaceAll('+', '-')
        .replaceAll('/', '_');
}

/**
 * Convert buffer to standard base64
 * @param {Buffer} buf
 * @returns {string}
 */
function toBase64(buf) {
    return Buffer.from(buf).toString('base64');
}

/**
 * Generate a random nonce for attestation
 * @param {number} [length=16] - Nonce length in bytes
 * @returns {Buffer}
 */
function generateNonce(length = 16) {
    return crypto.randomBytes(length);
}

// ═══════════════════════════════════════════════════════════════════════════
// ATTESTATION PARAMS PREPARATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Prepare attestation request parameters
 * @param {string} publicKeyPem - PEM-encoded public key
 * @param {string} [userData=''] - Optional user data
 * @returns {{ publicKey: string, userData: string, nonce: string }}
 */
function prepareAttestationParams(publicKeyPem, userData = '') {
    const publicKeyDer = pemToDerPublic(publicKeyPem);

    return {
        publicKey: toBase64Url(publicKeyDer),
        userData: userData ? toBase64Url(Buffer.from(userData, 'utf8')) : '',
        nonce: toBase64(generateNonce(16))
    };
}

module.exports = {
    generateEphemeralKeyPair,
    pemToDerPublic,
    pemToDerPrivate,
    toBase64Url,
    toBase64,
    generateNonce,
    prepareAttestationParams
};

