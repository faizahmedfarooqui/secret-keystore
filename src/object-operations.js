/**
 * @faizahmedfarooqui/secret-keystore - Object-Based Operations
 *
 * Functions for encrypting/decrypting nested objects using path patterns.
 * Supports ** pattern matching for any-depth selection.
 */

const { encryptKMSValue, decryptKMSValue, isAlreadyEncrypted } = require('./kms');
const { getAllPaths, filterPaths, getByPath, setByPath } = require('./path-matcher');
const { validateKmsKeyId, buildEncryptOptions, buildDecryptOptions } = require('./options');
const { EncryptionError, DecryptionError, ENCRYPTION_ERROR_CODES, DECRYPTION_ERROR_CODES } = require('./errors');

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPT OBJECT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt values at selected paths in a nested object using AWS KMS
 *
 * @param {Object} obj - Source object
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Options
 * @param {Object} [options.aws] - AWS options
 * @param {string[]} [options.paths] - Explicit paths to encrypt
 * @param {string[]} [options.patterns] - Patterns (** only) to match
 * @param {Object} [options.exclude] - Exclusions
 * @param {Object} [options.skip] - Skip options
 * @param {boolean} [options.continueOnError] - Continue on errors
 * @param {Object} [options.output] - Output format options
 * @returns {Promise<Object>} Result with encrypted object
 *
 * @example
 * const result = await encryptKMSObject(config, kmsKeyId, {
 *   patterns: ['**.password', '**.secret_key'],
 *   exclude: { paths: ['kms.key_id'] }
 * });
 */
async function encryptKMSObject(obj, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    const opts = buildEncryptOptions(options);
    const logger = opts.logger;

    // Deep clone the object
    const resultObject = structuredClone(obj);

    // Get all paths and filter based on selection
    const allPaths = getAllPaths(obj);
    const selectedPaths = filterPaths(allPaths, {
        paths: options.paths,
        patterns: options.patterns,
        exclude: options.exclude
    });

    logger?.debug?.(`[encryptKMSObject] Selected ${selectedPaths.length} paths from ${allPaths.length} total`);

    const result = {
        object: resultObject,
        encrypted: [],
        skipped: [],
        failed: []
    };

    const skipEmpty = opts.skip?.empty !== false;
    const skipAlreadyEncrypted = opts.skip?.alreadyEncrypted !== false;
    const continueOnError = opts.continueOnError === true;

    for (const path of selectedPaths) {
        const value = getByPath(obj, path);

        // Only encrypt string values
        if (typeof value !== 'string') {
            logger?.debug?.(`[encryptKMSObject] Skipping non-string at ${path}`);
            result.skipped.push(path);
            continue;
        }

        // Skip empty values
        if (skipEmpty && (!value || value.trim() === '')) {
            logger?.debug?.(`[encryptKMSObject] Skipping empty value at ${path}`);
            result.skipped.push(path);
            continue;
        }

        // Skip already encrypted
        if (skipAlreadyEncrypted && isAlreadyEncrypted(value)) {
            logger?.debug?.(`[encryptKMSObject] Skipping already encrypted at ${path}`);
            result.skipped.push(path);
            continue;
        }

        try {
            const encrypted = await encryptKMSValue(value, kmsKeyId, opts);
            setByPath(resultObject, path, encrypted);
            result.encrypted.push(path);
            logger?.info?.(`[encryptKMSObject] Encrypted: ${path}`);
        } catch (error) {
            if (continueOnError) {
                result.failed.push({ path, error });
                logger?.warn?.(`[encryptKMSObject] Failed to encrypt ${path}: ${error.message}`);
            } else {
                throw new EncryptionError(
                    `Failed to encrypt path: ${path}`,
                    ENCRYPTION_ERROR_CODES.FAILED,
                    path,
                    error
                );
            }
        }
    }

    logger?.info?.(`[encryptKMSObject] Complete: ${result.encrypted.length} encrypted, ${result.skipped.length} skipped, ${result.failed.length} failed`);

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// DECRYPT OBJECT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt values at selected paths in a nested object using AWS KMS
 *
 * @param {Object} obj - Source object with encrypted values
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Options
 * @param {Object} [options.aws] - AWS options
 * @param {Object} [options.attestation] - Attestation options
 * @param {string[]} [options.paths] - Explicit paths to decrypt
 * @param {string[]} [options.patterns] - Patterns (** only) to match
 * @param {Object} [options.exclude] - Exclusions
 * @param {Object} [options.skip] - Skip options
 * @param {boolean} [options.continueOnError] - Continue on errors
 * @returns {Promise<Object>} Result with decrypted object
 *
 * @example
 * const result = await decryptKMSObject(encryptedConfig, kmsKeyId, {
 *   attestation: { enabled: true, document: getAttestationDoc }
 * });
 */
async function decryptKMSObject(obj, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    const opts = buildDecryptOptions(options);
    const logger = opts.logger;

    // Deep clone the object
    const resultObject = structuredClone(obj);

    // Get all paths and filter based on selection
    const allPaths = getAllPaths(obj);
    const selectedPaths = filterPaths(allPaths, {
        paths: options.paths,
        patterns: options.patterns,
        exclude: options.exclude
    });

    logger?.debug?.(`[decryptKMSObject] Selected ${selectedPaths.length} paths from ${allPaths.length} total`);

    const result = {
        object: resultObject,
        decrypted: [],
        skipped: [],
        failed: []
    };

    const skipUnencrypted = opts.skip?.unencrypted !== false;
    const continueOnError = opts.continueOnError === true;

    for (const path of selectedPaths) {
        const value = getByPath(obj, path);

        // Only decrypt string values
        if (typeof value !== 'string') {
            logger?.debug?.(`[decryptKMSObject] Skipping non-string at ${path}`);
            result.skipped.push(path);
            continue;
        }

        // Skip unencrypted values
        if (skipUnencrypted && !isAlreadyEncrypted(value)) {
            logger?.debug?.(`[decryptKMSObject] Skipping unencrypted at ${path}`);
            result.skipped.push(path);
            continue;
        }

        try {
            const decrypted = await decryptKMSValue(value, kmsKeyId, opts);
            setByPath(resultObject, path, decrypted);
            result.decrypted.push(path);
            logger?.info?.(`[decryptKMSObject] Decrypted: ${path}`);
        } catch (error) {
            if (continueOnError) {
                result.failed.push({ path, error });
                logger?.warn?.(`[decryptKMSObject] Failed to decrypt ${path}: ${error.message}`);
            } else {
                throw new DecryptionError(
                    `Failed to decrypt path: ${path}`,
                    DECRYPTION_ERROR_CODES.FAILED,
                    path,
                    error
                );
            }
        }
    }

    logger?.info?.(`[decryptKMSObject] Complete: ${result.decrypted.length} decrypted, ${result.skipped.length} skipped, ${result.failed.length} failed`);

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
    encryptKMSObject,
    decryptKMSObject
};

