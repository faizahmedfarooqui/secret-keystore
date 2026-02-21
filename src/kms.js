/**
 * @faizahmedfarooqui/secret-keystore - KMS Operations
 *
 * Core KMS encryption and decryption operations.
 * Uses AWS SDK directly with support for attestation.
 */

const crypto = require('node:crypto');
const { KMSClient, EncryptCommand, DecryptCommand, DescribeKeyCommand } = require('@aws-sdk/client-kms');
const {
    KmsError,
    AttestationError,
    KMS_ERROR_CODES,
    ATTESTATION_ERROR_CODES,
    createKmsErrorFromAws
} = require('./errors');
const { buildAwsSdkOptions, validateKmsKeyId } = require('./options');

// Lazy-load attestation module to avoid circular dependencies
let attestationModule = null;
function getAttestationModule() {
    if (!attestationModule) {
        attestationModule = require('./attestation');
    }
    return attestationModule;
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTED VALUE FORMAT
// ═══════════════════════════════════════════════════════════════════════════

const ENCRYPTED_PREFIX = 'ENC[';
const ENCRYPTED_SUFFIX = ']';

/**
 * Check if a value is in encrypted format (ENC[...])
 * @param {string} value - Value to check
 * @returns {boolean}
 */
function isEncryptedFormat(value) {
    if (!value || typeof value !== 'string') return false;
    return value.startsWith(ENCRYPTED_PREFIX) && value.endsWith(ENCRYPTED_SUFFIX);
}

/**
 * Check if a value looks like KMS ciphertext (base64 starting with AQICAH)
 * @param {string} value - Value to check
 * @returns {boolean}
 */
function isKmsCiphertext(value) {
    if (!value || typeof value !== 'string') return false;
    return /^AQICAH/.test(value) && /^[A-Za-z0-9+/=]{50,}$/.test(value);
}

/**
 * Check if a value is already encrypted (ENC[...] or raw KMS ciphertext)
 * @param {string} value - Value to check
 * @returns {boolean}
 */
function isAlreadyEncrypted(value) {
    return isEncryptedFormat(value) || isKmsCiphertext(value);
}

/**
 * Wrap ciphertext in ENC[...] format
 * @param {string} ciphertext - Base64 ciphertext
 * @returns {string}
 */
function wrapCiphertext(ciphertext) {
    return `${ENCRYPTED_PREFIX}${ciphertext}${ENCRYPTED_SUFFIX}`;
}

/**
 * Unwrap ciphertext from ENC[...] format
 * @param {string} value - Wrapped ciphertext
 * @returns {string} Raw base64 ciphertext
 */
function unwrapCiphertext(value) {
    if (isEncryptedFormat(value)) {
        return value.slice(ENCRYPTED_PREFIX.length, -ENCRYPTED_SUFFIX.length);
    }
    return value;
}

// Envelope encryption for asymmetric (RSA) keys only.
// Payload: version(1) || encDEKLen(2 BE) || encryptedDEK || iv(12) || ciphertext || tag(16)
const ENVELOPE_VERSION = 0x01;
const DEK_LENGTH = 32;
const IV_LENGTH = 12;
const GCM_TAG_LENGTH = 16;

/**
 * Check if ciphertext buffer is envelope format (first byte = ENVELOPE_VERSION)
 * @param {Buffer} buf - Decoded ciphertext buffer
 * @returns {boolean}
 */
function isEnvelopeFormat(buf) {
    return Buffer.isBuffer(buf) && buf.length > 1 && buf[0] === ENVELOPE_VERSION;
}

// ═══════════════════════════════════════════════════════════════════════════
// KMS CLIENT MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

// Cache for KMS clients (keyed by region + credentials hash)
const clientCache = new Map();

/**
 * Get or create a KMS client
 * @param {Object} options - AWS options
 * @returns {KMSClient}
 */
function getKmsClient(options = {}) {
    const sdkOptions = buildAwsSdkOptions(options);
    const cacheKey = JSON.stringify(sdkOptions);

    if (clientCache.has(cacheKey)) {
        return clientCache.get(cacheKey);
    }

    const client = new KMSClient(sdkOptions);
    clientCache.set(cacheKey, client);
    return client;
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY DETECTION
// ═══════════════════════════════════════════════════════════════════════════

// Cache for key algorithms
const keyAlgorithmCache = new Map();

/**
 * Detect if KMS key is RSA (asymmetric) or symmetric
 * @param {KMSClient} client - KMS client
 * @param {string} kmsKeyId - KMS key ID
 * @param {Object} [logger] - Logger instance
 * @returns {Promise<string|null>} Algorithm name or null for symmetric
 */
async function detectKeyAlgorithm(client, kmsKeyId, logger) {
    // Check cache
    if (keyAlgorithmCache.has(kmsKeyId)) {
        return keyAlgorithmCache.get(kmsKeyId);
    }

    try {
        const command = new DescribeKeyCommand({ KeyId: kmsKeyId });
        const response = await client.send(command);

        const keySpec = response.KeyMetadata?.KeySpec;
        let algorithm = null;

        if (['RSA_2048', 'RSA_3072', 'RSA_4096'].includes(keySpec)) {
            algorithm = 'RSAES_OAEP_SHA_256';
            logger?.debug?.(`[KMS] Detected RSA key (${keySpec}), using ${algorithm}`);
        } else {
            logger?.debug?.('[KMS] Detected symmetric key');
        }

        keyAlgorithmCache.set(kmsKeyId, algorithm);
        return algorithm;
    } catch (error) {
        logger?.warn?.(`[KMS] Could not detect key type: ${error.message}`);
        // Default to trying RSA first
        return 'RSAES_OAEP_SHA_256';
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ATTESTATION HANDLING
// ═══════════════════════════════════════════════════════════════════════════

// Cache for AttestationManager instances (keyed by endpoint)
const attestationManagerCache = new Map();

/**
 * Get or create an AttestationManager
 * @param {Object} attestation - Attestation options
 * @param {Object} [logger] - Logger instance
 * @returns {Promise<import('./attestation').AttestationManager>}
 */
async function getAttestationManager(attestation, logger) {
    const { AttestationManager } = getAttestationModule();

    const endpoint = attestation.endpoint || getAttestationModule().DEFAULT_ATTESTATION_ENDPOINT;
    const cacheKey = endpoint;

    // Check cache
    if (attestationManagerCache.has(cacheKey)) {
        const cached = attestationManagerCache.get(cacheKey);
        if (cached.isInitialized()) {
            return cached;
        }
    }

    // Create new manager
    const manager = new AttestationManager({
        endpoint,
        timeout: attestation.timeout || 10000,
        userData: attestation.userData || '',
        logger
    });

    await manager.initialize();
    attestationManagerCache.set(cacheKey, manager);

    return manager;
}

/**
 * Get attestation document from options (legacy mode - pre-generated document)
 * @param {Object} attestation - Attestation options
 * @returns {Promise<{ document: Buffer, privateKey: string } | null>}
 */
async function getAttestationDocumentLegacy(attestation) {
    if (!attestation?.enabled) {
        return null;
    }

    // Check for pre-generated document + private key (legacy mode)
    if (attestation.document && attestation.privateKey) {
        let doc = attestation.document;
        if (typeof doc === 'function') {
            doc = await doc();
        }
        if (typeof doc === 'string') {
            doc = Buffer.from(doc, 'base64');
        }
        return {
            document: doc,
            privateKey: attestation.privateKey
        };
    }

    return null;
}

/**
 * Check if error is a 5-minute attestation age limit error
 * @param {Error} error - Error to check
 * @returns {boolean}
 */
function isAttestationAgeLimitError(error) {
    const message = error.message || '';
    const causeMessage = error.cause?.message || '';

    return message.includes('exceeded the five-minute age limit') ||
        message.includes('exceeded the five minute age limit') ||
        message.includes('age limit') ||
        causeMessage.includes('age limit') ||
        message.includes('cannot parse the attestation document') ||
        causeMessage.includes('cannot parse');
}

// ═══════════════════════════════════════════════════════════════════════════
// ENVELOPE ENCRYPTION (RSA / ASYMMETRIC KEYS ONLY)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt using envelope encryption: DEK encrypts plaintext (AES-256-GCM), KMS encrypts DEK (RSA).
 * Used for asymmetric keys so plaintext size is unlimited.
 *
 * @param {string} plaintext - Value to encrypt
 * @param {string} kmsKeyId - KMS key ID (RSA)
 * @param {Object} options - Options (client, algorithm, output, logger)
 * @returns {Promise<string|Buffer>} Envelope blob (version || encDEKLen || encryptedDEK || iv || ciphertext || tag)
 * @private
 */
async function encryptEnvelopeRSA(plaintext, kmsKeyId, options = {}) {
    const client = options.client;
    const algorithm = options.algorithm || 'RSAES_OAEP_SHA_256';
    const outputFormat = options.output?.format || 'prefixed';

    const plaintextBuffer = Buffer.from(plaintext, 'utf-8');
    const dek = crypto.randomBytes(DEK_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
    const ciphertext = Buffer.concat([
        cipher.update(plaintextBuffer),
        cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    const encryptCommand = new EncryptCommand({
        KeyId: kmsKeyId,
        Plaintext: dek,
        EncryptionAlgorithm: algorithm
    });
    const encResponse = await client.send(encryptCommand);
    const encryptedDEK = Buffer.from(encResponse.CiphertextBlob);

    const encDEKLen = encryptedDEK.length;
    const envelope = Buffer.allocUnsafe(1 + 2 + encDEKLen + IV_LENGTH + ciphertext.length + GCM_TAG_LENGTH);
    let offset = 0;
    envelope[offset++] = ENVELOPE_VERSION;
    envelope.writeUInt16BE(encDEKLen, offset);
    offset += 2;
    encryptedDEK.copy(envelope, offset);
    offset += encDEKLen;
    iv.copy(envelope, offset);
    offset += IV_LENGTH;
    ciphertext.copy(envelope, offset);
    offset += ciphertext.length;
    authTag.copy(envelope, offset);

    switch (outputFormat) {
        case 'buffer':
            return envelope;
        case 'base64':
            return envelope.toString('base64');
        case 'prefixed':
        default:
            return wrapCiphertext(envelope.toString('base64'));
    }
}

/**
 * Decrypt envelope format: KMS decrypts encrypted DEK, then AES-256-GCM decrypt with DEK.
 *
 * @param {KMSClient} client - KMS client
 * @param {Buffer} envelope - Envelope blob (starts with ENVELOPE_VERSION)
 * @param {string} kmsKeyId - KMS key ID
 * @param {Object} options - Options (logger)
 * @returns {Promise<string>} Decrypted plaintext
 * @private
 */
async function decryptEnvelopeRSA(client, envelope, kmsKeyId, options = {}) {
    const encDEKLen = envelope.readUInt16BE(1);
    const encryptedDEK = envelope.subarray(3, 3 + encDEKLen);
    const iv = envelope.subarray(3 + encDEKLen, 3 + encDEKLen + IV_LENGTH);
    const tag = envelope.subarray(envelope.length - GCM_TAG_LENGTH);
    const ciphertext = envelope.subarray(3 + encDEKLen + IV_LENGTH, envelope.length - GCM_TAG_LENGTH);

    const decryptCommand = new DecryptCommand({
        KeyId: kmsKeyId,
        CiphertextBlob: encryptedDEK,
        EncryptionAlgorithm: 'RSAES_OAEP_SHA_256'
    });
    const decResponse = await client.send(decryptCommand);
    if (!decResponse.Plaintext) {
        throw new KmsError('KMS did not return plaintext (envelope DEK)', KMS_ERROR_CODES.DECRYPT_FAILED, kmsKeyId);
    }
    const dek = Buffer.from(decResponse.Plaintext);

    const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);
    return plaintext.toString('utf-8');
}

// ═══════════════════════════════════════════════════════════════════════════
// CORE ENCRYPT FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt a single value using AWS KMS.
 * For asymmetric (RSA) keys uses envelope encryption (no plaintext size limit).
 * For symmetric keys uses direct KMS Encrypt (plaintext max 4KB).
 *
 * @param {string} plaintext - Value to encrypt
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Encrypt options
 * @param {Object} [options.aws] - AWS options
 * @param {Object} [options.output] - Output format options
 * @param {string} [options.output.format='prefixed'] - 'base64' | 'buffer' | 'prefixed'
 * @param {Object} [options.logger] - Logger instance
 * @returns {Promise<string|Buffer>} Encrypted value
 */
async function encryptKMSValue(plaintext, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    const logger = options.logger;
    const outputFormat = options.output?.format || 'prefixed';

    const client = getKmsClient(options);
    const algorithm = await detectKeyAlgorithm(client, kmsKeyId, logger);

    if (algorithm) {
        logger?.debug?.('[KMS] Asymmetric key detected, using envelope encryption');
        return await encryptEnvelopeRSA(plaintext, kmsKeyId, {
            client,
            algorithm,
            output: { format: outputFormat },
            logger
        });
    }

    const commandOptions = {
        KeyId: kmsKeyId,
        Plaintext: Buffer.from(plaintext, 'utf-8')
    };

    try {
        const command = new EncryptCommand(commandOptions);
        const response = await client.send(command);
        const ciphertextBuffer = Buffer.from(response.CiphertextBlob);

        switch (outputFormat) {
            case 'buffer':
                return ciphertextBuffer;
            case 'base64':
                return ciphertextBuffer.toString('base64');
            case 'prefixed':
            default:
                return wrapCiphertext(ciphertextBuffer.toString('base64'));
        }
    } catch (error) {
        throw createKmsErrorFromAws(error, kmsKeyId, 'encrypt');
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CORE DECRYPT FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt a single value using AWS KMS
 *
 * @param {string|Buffer} ciphertext - Value to decrypt
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Decrypt options
 * @param {Object} [options.aws] - AWS options
 * @param {Object} [options.attestation] - Attestation options
 * @param {Object} [options.input] - Input format options
 * @param {string} [options.input.format='auto'] - 'auto' | 'base64' | 'buffer' | 'prefixed'
 * @param {Object} [options.logger] - Logger instance
 * @returns {Promise<string>} Decrypted plaintext
 */
async function decryptKMSValue(ciphertext, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    const logger = options.logger;
    const inputFormat = options.input?.format || 'auto';
    const attestation = options.attestation;

    // Convert ciphertext to buffer
    let ciphertextBuffer;
    if (Buffer.isBuffer(ciphertext)) {
        ciphertextBuffer = ciphertext;
    } else if (typeof ciphertext === 'string') {
        // Handle different input formats
        let base64String = ciphertext;
        if (inputFormat === 'auto' || inputFormat === 'prefixed') {
            base64String = unwrapCiphertext(ciphertext);
        }
        ciphertextBuffer = Buffer.from(base64String, 'base64');
    } else {
        throw new KmsError('Invalid ciphertext format', KMS_ERROR_CODES.INVALID_CIPHERTEXT, kmsKeyId);
    }

    const client = getKmsClient(options);

    if (isEnvelopeFormat(ciphertextBuffer)) {
        return await decryptEnvelopeRSA(client, ciphertextBuffer, kmsKeyId, options);
    }

    const algorithm = await detectKeyAlgorithm(client, kmsKeyId, logger);

    // Try to decrypt with attestation if enabled
    if (attestation?.enabled) {
        return await decryptWithAttestation(client, ciphertextBuffer, kmsKeyId, algorithm, options);
    }

    // Standard decrypt
    return await decryptStandard(client, ciphertextBuffer, kmsKeyId, algorithm, options);
}

/**
 * Decrypt with attestation support
 *
 * Supports two modes:
 * 1. Full attestation (default): Uses AttestationManager to generate key pairs,
 *    fetch attestation documents, and unwrap CMS EnvelopedData
 * 2. Legacy mode: Uses pre-generated document + privateKey from options
 *
 * @private
 */
async function decryptWithAttestation(client, ciphertextBuffer, kmsKeyId, algorithm, options) {
    const { attestation, logger } = options;

    // Check for legacy mode (pre-generated document + private key)
    const legacyMaterials = await getAttestationDocumentLegacy(attestation);
    if (legacyMaterials) {
        logger?.debug?.('[KMS] Using legacy attestation mode (pre-generated document)');
        return await decryptWithAttestationMaterials(
            client,
            ciphertextBuffer,
            kmsKeyId,
            algorithm,
            legacyMaterials,
            logger
        );
    }

    // Full attestation mode - use AttestationManager
    logger?.debug?.('[KMS] Using full attestation mode with AttestationManager');

    let manager;
    try {
        manager = await getAttestationManager(attestation, logger);
    } catch (error) {
        if (attestation.required) {
            throw new AttestationError(
                `Failed to initialize attestation: ${error.message}`,
                ATTESTATION_ERROR_CODES.INIT_FAILED,
                error
            );
        }

        // Fallback to standard if allowed
        if (attestation.fallbackToStandard !== false) {
            logger?.warn?.(`[KMS] Attestation init failed, falling back to standard: ${error.message}`);
            return await decryptStandard(client, ciphertextBuffer, kmsKeyId, algorithm, options);
        }

        throw new AttestationError(
            `Attestation initialization failed and fallback disabled: ${error.message}`,
            ATTESTATION_ERROR_CODES.INIT_FAILED,
            error
        );
    }

    // Use AttestationManager to decrypt (handles 5-minute refresh internally)
    try {
        const plaintext = await manager.decryptWithAttestation(
            client,
            ciphertextBuffer,
            kmsKeyId,
            {
                encryptionAlgorithm: algorithm,
                encryptionContext: attestation.encryptionContext
            }
        );
        return plaintext.toString('utf-8');
    } catch (error) {
        // Check if we should fallback
        if (attestation.fallbackToStandard !== false) {
            logger?.warn?.(`[KMS] Attestation failed, falling back to standard: ${error.message}`);
            return await decryptStandard(client, ciphertextBuffer, kmsKeyId, algorithm, options);
        }
        throw error;
    }
}

/**
 * Decrypt with pre-generated attestation materials (legacy mode)
 *
 * This mode is for when the caller has already generated the key pair
 * and fetched the attestation document themselves.
 *
 * @private
 */
async function decryptWithAttestationMaterials(client, ciphertextBuffer, kmsKeyId, algorithm, materials, logger) {
    const { document: attestationDoc, privateKey } = materials;
    const { unwrapCms } = getAttestationModule();

    const commandOptions = {
        CiphertextBlob: ciphertextBuffer,
        KeyId: kmsKeyId,
        Recipient: {
            KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256',
            AttestationDocument: attestationDoc
        }
    };

    if (algorithm) {
        commandOptions.EncryptionAlgorithm = algorithm;
    }

    logger?.debug?.('[KMS] Sending KMS Decrypt with Recipient...');
    const command = new DecryptCommand(commandOptions);
    const response = await client.send(command);

    // With Recipient, KMS returns CiphertextForRecipient, NOT Plaintext
    if (!response.CiphertextForRecipient) {
        throw new KmsError(
            'KMS did not return CiphertextForRecipient - check key policy and Recipient support',
            KMS_ERROR_CODES.DECRYPT_FAILED,
            kmsKeyId
        );
    }

    const ciphertextForRecipient = Buffer.from(response.CiphertextForRecipient);
    logger?.debug?.(`[KMS] Received CiphertextForRecipient (${ciphertextForRecipient.length} bytes)`);

    // Unwrap CMS EnvelopedData using the private key
    logger?.debug?.('[KMS] Unwrapping CMS EnvelopedData...');
    const plaintext = await unwrapCms(ciphertextForRecipient, privateKey);
    logger?.debug?.(`[KMS] Decrypted plaintext (${plaintext.length} bytes)`);

    return plaintext.toString('utf-8');
}

/**
 * Standard decrypt without attestation
 * @private
 */
async function decryptStandard(client, ciphertextBuffer, kmsKeyId, algorithm, options) {
    const logger = options?.logger;

    const commandOptions = {
        CiphertextBlob: ciphertextBuffer,
        KeyId: kmsKeyId
    };

    if (algorithm) {
        commandOptions.EncryptionAlgorithm = algorithm;
    }

    try {
        const command = new DecryptCommand(commandOptions);
        const response = await client.send(command);

        if (!response.Plaintext) {
            throw new KmsError('KMS did not return plaintext', KMS_ERROR_CODES.DECRYPT_FAILED, kmsKeyId);
        }

        return Buffer.from(response.Plaintext).toString('utf-8');
    } catch (error) {
        // If RSA algorithm failed, try without algorithm (symmetric)
        if (algorithm === 'RSAES_OAEP_SHA_256' &&
            (error.message?.includes('incompatible') || error.name?.includes('InvalidCiphertext'))) {
            logger?.debug?.('[KMS] RSA algorithm failed, trying symmetric...');

            // Clear cached algorithm
            keyAlgorithmCache.delete(kmsKeyId);

            const fallbackCommand = new DecryptCommand({
                CiphertextBlob: ciphertextBuffer,
                KeyId: kmsKeyId
            });
            const response = await client.send(fallbackCommand);

            if (!response.Plaintext) {
                throw new KmsError('KMS did not return plaintext', KMS_ERROR_CODES.DECRYPT_FAILED, kmsKeyId);
            }

            return Buffer.from(response.Plaintext).toString('utf-8');
        }

        throw createKmsErrorFromAws(error, kmsKeyId, 'decrypt');
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCH OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt multiple values using AWS KMS
 *
 * @param {Object} values - Key-value pairs to encrypt
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Encrypt options
 * @returns {Promise<Object>} Result with encrypted values
 */
async function encryptKMSValues(values, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    const result = {
        values: {},
        encrypted: [],
        skipped: [],
        failed: []
    };

    const skipEmpty = options.skip?.empty !== false;
    const skipAlreadyEncrypted = options.skip?.alreadyEncrypted !== false;
    const continueOnError = options.continueOnError === true;

    for (const [key, value] of Object.entries(values)) {
        // Skip empty values
        if (skipEmpty && (!value || (typeof value === 'string' && value.trim() === ''))) {
            result.values[key] = value;
            result.skipped.push(key);
            continue;
        }

        // Skip already encrypted
        if (skipAlreadyEncrypted && isAlreadyEncrypted(value)) {
            result.values[key] = value;
            result.skipped.push(key);
            continue;
        }

        try {
            result.values[key] = await encryptKMSValue(value, kmsKeyId, options);
            result.encrypted.push(key);
        } catch (error) {
            if (continueOnError) {
                result.values[key] = value;
                result.failed.push({ key, error });
            } else {
                throw error;
            }
        }
    }

    return result;
}

/**
 * Decrypt multiple values using AWS KMS
 *
 * @param {Object} values - Key-value pairs to decrypt
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Decrypt options
 * @returns {Promise<Object>} Result with decrypted values
 */
async function decryptKMSValues(values, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    const result = {
        values: {},
        decrypted: [],
        skipped: [],
        failed: []
    };

    const skipUnencrypted = options.skip?.unencrypted !== false;
    const continueOnError = options.continueOnError === true;

    for (const [key, value] of Object.entries(values)) {
        // Skip unencrypted values
        if (skipUnencrypted && !isAlreadyEncrypted(value)) {
            result.values[key] = value;
            result.skipped.push(key);
            continue;
        }

        try {
            result.values[key] = await decryptKMSValue(value, kmsKeyId, options);
            result.decrypted.push(key);
        } catch (error) {
            if (continueOnError) {
                result.values[key] = value;
                result.failed.push({ key, error });
            } else {
                throw error;
            }
        }
    }

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Mask a KMS key ID for logging
 * @param {string} keyId - KMS key ID
 * @returns {string}
 */
function maskKmsKeyId(keyId) {
    if (!keyId) return 'undefined';

    // Handle ARN format
    if (keyId.includes('arn:aws:kms')) {
        const parts = keyId.split('/');
        if (parts.length === 2) {
            return `${parts[0]}/${parts[1].substring(0, 8)}...`;
        }
        return keyId.substring(0, 40) + '...';
    }

    // Handle UUID format
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(keyId)) {
        return `${keyId.substring(0, 8)}-****-****-****-${keyId.substring(keyId.length - 4)}`;
    }

    // Handle alias format
    if (keyId.startsWith('alias/')) {
        return keyId; // Aliases are not sensitive
    }

    // Fallback
    return keyId.substring(0, 8) + '...' + keyId.substring(keyId.length - 4);
}

// ═══════════════════════════════════════════════════════════════════════════
// ATTESTATION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Clear all cached attestation managers
 * Useful for testing or when you need to force re-initialization
 */
function clearAttestationCache() {
    for (const manager of attestationManagerCache.values()) {
        manager.destroy();
    }
    attestationManagerCache.clear();
}

/**
 * Get attestation status for a given endpoint
 * @param {string} [endpoint] - Attestation endpoint (uses default if not provided)
 * @returns {Object | null}
 */
function getAttestationStatus(endpoint) {
    const key = endpoint || getAttestationModule().DEFAULT_ATTESTATION_ENDPOINT;
    const manager = attestationManagerCache.get(key);
    return manager ? manager.getStatus() : null;
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
    // Core KMS operations
    encryptKMSValue,
    decryptKMSValue,
    encryptKMSValues,
    decryptKMSValues,

    // Format helpers
    isEncryptedFormat,
    isKmsCiphertext,
    isAlreadyEncrypted,
    isEnvelopeFormat,
    wrapCiphertext,
    unwrapCiphertext,

    // Utilities
    getKmsClient,
    detectKeyAlgorithm,
    maskKmsKeyId,

    // Attestation utilities
    clearAttestationCache,
    getAttestationStatus,

    // Constants
    ENCRYPTED_PREFIX,
    ENCRYPTED_SUFFIX
};

