/**
 * @faizahmedfarooqui/secret-keystore - CMS EnvelopedData Unwrapping
 *
 * Uses PKIjs and asn1js to unwrap CMS EnvelopedData returned by AWS KMS
 * when using the Recipient parameter with attestation.
 *
 * When KMS receives a Recipient with AttestationDocument, it returns
 * CiphertextForRecipient instead of Plaintext. This CiphertextForRecipient
 * is a CMS EnvelopedData structure encrypted with the public key from
 * the attestation document.
 */

const crypto = require('node:crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');

// ═══════════════════════════════════════════════════════════════════════════
// PKIJS ENGINE SETUP
// ═══════════════════════════════════════════════════════════════════════════

// Use Node.js WebCrypto for PKIjs
const nodeCrypto = crypto.webcrypto;

/**
 * Initialize PKIjs engine with Node.js crypto
 * Must be called before any PKIjs operations
 */
function initializePkijsEngine() {
    const engine = new pkijs.CryptoEngine({
        name: 'nodeEngine',
        crypto: nodeCrypto,
        subtle: nodeCrypto.subtle
    });
    pkijs.setEngine('nodeEngine', engine);
}

// Initialize on module load
initializePkijsEngine();

// ═══════════════════════════════════════════════════════════════════════════
// CMS UNWRAP
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Unwrap CMS EnvelopedData using PKIjs
 *
 * @param {Buffer} ciphertextForRecipient - The CMS EnvelopedData from KMS
 * @param {string} privateKeyPem - The ephemeral private key (PKCS#8 PEM)
 * @returns {Promise<Buffer>} - The decrypted plaintext
 * @throws {Error} If parsing or decryption fails
 */
async function unwrapCms(ciphertextForRecipient, privateKeyPem) {
    // Ensure engine is initialized
    initializePkijsEngine();

    // 1. Parse CMS DER structure
    const derView = new Uint8Array(
        ciphertextForRecipient.buffer,
        ciphertextForRecipient.byteOffset,
        ciphertextForRecipient.byteLength
    );

    const asn1Result = asn1js.fromBER(derView);
    if (asn1Result.offset === -1) {
        throw new Error('Failed to parse CMS DER structure');
    }

    // 2. Parse ContentInfo
    const contentInfo = new pkijs.ContentInfo({ schema: asn1Result.result });

    // Verify it's EnvelopedData (OID: 1.2.840.113549.1.7.3)
    if (contentInfo.contentType !== '1.2.840.113549.1.7.3') {
        throw new Error(`Expected CMS EnvelopedData (1.2.840.113549.1.7.3), got ${contentInfo.contentType}`);
    }

    // 3. Parse EnvelopedData
    const envelopedData = new pkijs.EnvelopedData({ schema: contentInfo.content });

    // 4. Import private key for decryption
    const privateKey = await importPrivateKey(privateKeyPem);

    // 5. Decrypt the content
    const decryptResult = await envelopedData.decrypt(0, {
        recipientPrivateKey: privateKey,
        crypto: nodeCrypto
    });

    // 6. Handle different return types from PKIjs
    let plaintext;
    if (typeof decryptResult === 'boolean') {
        // PKIjs modifies envelopedData.encryptedContentInfo.encryptedContent in-place
        const encryptedContent = envelopedData.encryptedContentInfo?.encryptedContent;
        if (!encryptedContent) {
            throw new Error('Decryption returned true but no content found');
        }
        plaintext = Buffer.from(encryptedContent.valueBlock.valueHexView);
    } else if (decryptResult instanceof ArrayBuffer) {
        plaintext = Buffer.from(decryptResult);
    } else if (ArrayBuffer.isView(decryptResult)) {
        plaintext = Buffer.from(decryptResult.buffer, decryptResult.byteOffset, decryptResult.byteLength);
    } else {
        throw new TypeError(`Unexpected decrypt result type: ${typeof decryptResult}`);
    }

    return plaintext;
}

/**
 * Import PKCS#8 PEM private key for RSA-OAEP decryption
 *
 * @param {string} privateKeyPem - PKCS#8 PEM private key
 * @returns {Promise<CryptoKey>}
 */
async function importPrivateKey(privateKeyPem) {
    // Extract base64 from PEM
    const base64 = privateKeyPem
        .replaceAll('-----BEGIN PRIVATE KEY-----', '')
        .replaceAll('-----END PRIVATE KEY-----', '')
        .replaceAll(/\s+/g, '');

    const pkcs8Buffer = Buffer.from(base64, 'base64');

    // Import as RSA-OAEP key
    const privateKey = await nodeCrypto.subtle.importKey(
        'pkcs8',
        pkcs8Buffer,
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        },
        false,  // not extractable
        ['decrypt']
    );

    return privateKey;
}

/**
 * Validate that a PEM string is a valid PKCS#8 private key
 *
 * @param {string} pem - The PEM string to validate
 * @returns {boolean}
 */
function validatePrivateKeyFormat(pem) {
    if (!pem || typeof pem !== 'string') {
        return false;
    }

    const hasHeader = pem.includes('-----BEGIN PRIVATE KEY-----');
    const hasFooter = pem.includes('-----END PRIVATE KEY-----');

    return hasHeader && hasFooter;
}

module.exports = {
    unwrapCms,
    importPrivateKey,
    validatePrivateKeyFormat,
    initializePkijsEngine
};

