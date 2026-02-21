/**
 * @faizahmedfarooqui/secret-keystore - Content-Based Operations
 *
 * Functions for encrypting/decrypting content strings (ENV, JSON, YAML).
 * Preserves comments and formatting during transformation.
 */

const { encryptKMSValue, decryptKMSValue, isAlreadyEncrypted } = require('./kms');
const { encryptKMSObject, decryptKMSObject } = require('./object-operations');
const { validateKmsKeyId, buildEncryptOptions, buildDecryptOptions } = require('./options');
const { ContentError, CONTENT_ERROR_CODES } = require('./errors');

// ═══════════════════════════════════════════════════════════════════════════
// ENV CONTENT OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Extract value and inline comment from a quoted string
 * @param {string} valueWithComment - The value portion after =
 * @param {string} quoteChar - The quote character (" or ')
 * @returns {{value: string, inlineComment: string|null}}
 */
function parseQuotedValue(valueWithComment, quoteChar) {
    const closeQuote = valueWithComment.indexOf(quoteChar, 1);
    if (closeQuote === -1) {
        return { value: valueWithComment.slice(1), inlineComment: null };
    }

    const value = valueWithComment.slice(1, closeQuote);
    const afterQuote = valueWithComment.slice(closeQuote + 1).trim();
    const inlineComment = afterQuote.startsWith('#') ? afterQuote : null;

    return { value, inlineComment };
}

/**
 * Extract value and inline comment from an unquoted string
 * @param {string} valueWithComment - The value portion after =
 * @returns {{value: string, inlineComment: string|null}}
 */
function parseUnquotedValue(valueWithComment) {
    const hashIndex = valueWithComment.indexOf('#');
    if (hashIndex === -1) {
        return { value: valueWithComment.trim(), inlineComment: null };
    }
    return {
        value: valueWithComment.slice(0, hashIndex).trim(),
        inlineComment: valueWithComment.slice(hashIndex)
    };
}

/**
 * Parse .env content into structured entries
 * @param {string} content - Raw .env content
 * @returns {Array<Object>} Parsed entries
 */
function parseEnvContent(content) {
    const lines = content.split('\n');
    const parsed = [];

    for (const line of lines) {
        const trimmed = line.trim();

        if (!trimmed) {
            parsed.push({ type: 'empty', raw: line });
            continue;
        }

        if (trimmed.startsWith('#')) {
            parsed.push({ type: 'comment', raw: line });
            continue;
        }

        const match = trimmed.match(/^([^=]+)=(.*)$/);
        if (!match) {
            parsed.push({ type: 'other', raw: line });
            continue;
        }

        const key = match[1].trim();
        const valueWithComment = match[2];

        let result;
        if (valueWithComment.startsWith('"')) {
            result = parseQuotedValue(valueWithComment, '"');
        } else if (valueWithComment.startsWith("'")) {
            result = parseQuotedValue(valueWithComment, "'");
        } else {
            result = parseUnquotedValue(valueWithComment);
        }

        parsed.push({
            type: 'keyvalue',
            key,
            value: result.value,
            inlineComment: result.inlineComment,
            raw: line
        });
    }

    return parsed;
}

/**
 * Reconstruct .env content from parsed entries
 * @param {Array<Object>} parsed - Parsed entries
 * @returns {string} Reconstructed content
 */
function reconstructEnvContent(parsed) {
    return parsed.map(entry => {
        if (entry.type === 'keyvalue') {
            const needsQuotes = entry.value.includes(' ') ||
                entry.value.includes('#') ||
                entry.value.includes('=') ||
                entry.value.includes('\n');

            let line = needsQuotes
                ? `${entry.key}="${entry.value}"`
                : `${entry.key}=${entry.value}`;

            if (entry.inlineComment) {
                line += ` ${entry.inlineComment}`;
            }

            return line;
        }
        return entry.raw;
    }).join('\n');
}

/**
 * Encrypt .env content string using AWS KMS
 *
 * @param {string} content - Raw .env content
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Options
 * @param {string[]} [options.paths] - Keys to encrypt (encrypt all if not provided)
 * @param {Object} [options.exclude] - Keys to exclude
 * @param {Object} [options.preserve] - Preservation options
 * @returns {Promise<Object>} Result with encrypted content
 */
async function encryptKMSEnvContent(content, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    const opts = buildEncryptOptions(options);
    const logger = opts.logger;

    if (!content || typeof content !== 'string') {
        throw new ContentError('Content must be a non-empty string', CONTENT_ERROR_CODES.EMPTY_CONTENT, 'env');
    }

    const parsed = parseEnvContent(content);
    const keyValueEntries = parsed.filter(e => e.type === 'keyvalue');

    // Determine which keys to encrypt
    let keysToEncrypt;
    if (options.paths && options.paths.length > 0) {
        keysToEncrypt = options.paths;
    } else {
        keysToEncrypt = keyValueEntries.map(e => e.key);
    }

    // Apply exclusions
    if (options.exclude?.paths) {
        keysToEncrypt = keysToEncrypt.filter(k => !options.exclude.paths.includes(k));
    }

    const result = {
        content: '',
        encrypted: [],
        skipped: [],
        failed: []
    };

    const skipEmpty = opts.skip?.empty !== false;
    const skipAlreadyEncrypted = opts.skip?.alreadyEncrypted !== false;
    const continueOnError = opts.continueOnError === true;

    for (const entry of keyValueEntries) {
        if (!keysToEncrypt.includes(entry.key)) {
            result.skipped.push(entry.key);
            continue;
        }

        // Skip empty
        if (skipEmpty && (!entry.value || entry.value.trim() === '')) {
            result.skipped.push(entry.key);
            continue;
        }

        // Skip already encrypted
        if (skipAlreadyEncrypted && isAlreadyEncrypted(entry.value)) {
            result.skipped.push(entry.key);
            continue;
        }

        try {
            entry.value = await encryptKMSValue(entry.value, kmsKeyId, opts);
            result.encrypted.push(entry.key);
            logger?.info?.(`[encryptKMSEnvContent] Encrypted: ${entry.key}`);
        } catch (error) {
            if (continueOnError) {
                result.failed.push({ key: entry.key, error });
                logger?.warn?.(`[encryptKMSEnvContent] Failed: ${entry.key}`);
            } else {
                throw error;
            }
        }
    }

    result.content = reconstructEnvContent(parsed);
    return result;
}

/**
 * Decrypt .env content string using AWS KMS
 *
 * @param {string} content - Encrypted .env content
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Options
 * @param {string[]} [options.paths] - Keys to decrypt (decrypt all if not provided)
 * @param {Object} [options.attestation] - Attestation options
 * @returns {Promise<Object>} Result with decrypted content
 */
async function decryptKMSEnvContent(content, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    const opts = buildDecryptOptions(options);
    const logger = opts.logger;

    if (!content || typeof content !== 'string') {
        throw new ContentError('Content must be a non-empty string', CONTENT_ERROR_CODES.EMPTY_CONTENT, 'env');
    }

    const parsed = parseEnvContent(content);
    const keyValueEntries = parsed.filter(e => e.type === 'keyvalue');

    // Determine which keys to decrypt
    let keysToDecrypt;
    if (options.paths && options.paths.length > 0) {
        keysToDecrypt = options.paths;
    } else {
        keysToDecrypt = keyValueEntries.map(e => e.key);
    }

    // Apply exclusions
    if (options.exclude?.paths) {
        keysToDecrypt = keysToDecrypt.filter(k => !options.exclude.paths.includes(k));
    }

    const result = {
        content: '',
        decrypted: [],
        skipped: [],
        failed: []
    };

    const skipUnencrypted = opts.skip?.unencrypted !== false;
    const continueOnError = opts.continueOnError === true;

    for (const entry of keyValueEntries) {
        if (!keysToDecrypt.includes(entry.key)) {
            result.skipped.push(entry.key);
            continue;
        }

        // Skip unencrypted
        if (skipUnencrypted && !isAlreadyEncrypted(entry.value)) {
            result.skipped.push(entry.key);
            continue;
        }

        try {
            entry.value = await decryptKMSValue(entry.value, kmsKeyId, opts);
            result.decrypted.push(entry.key);
            logger?.info?.(`[decryptKMSEnvContent] Decrypted: ${entry.key}`);
        } catch (error) {
            if (continueOnError) {
                result.failed.push({ key: entry.key, error });
                logger?.warn?.(`[decryptKMSEnvContent] Failed: ${entry.key}`);
            } else {
                throw error;
            }
        }
    }

    result.content = reconstructEnvContent(parsed);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// JSON CONTENT OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt JSON content string using AWS KMS
 *
 * @param {string} content - JSON content string
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Options (same as encryptKMSObject)
 * @returns {Promise<Object>} Result with encrypted JSON content
 */
async function encryptKMSJsonContent(content, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    if (!content || typeof content !== 'string') {
        throw new ContentError('Content must be a non-empty string', CONTENT_ERROR_CODES.EMPTY_CONTENT, 'json');
    }

    let obj;
    try {
        obj = JSON.parse(content);
    } catch (error) {
        throw new ContentError(
            `Failed to parse JSON content: ${error.message}`,
            CONTENT_ERROR_CODES.PARSE_FAILED,
            'json',
            error
        );
    }

    const objectResult = await encryptKMSObject(obj, kmsKeyId, options);

    return {
        content: JSON.stringify(objectResult.object, null, 2),
        encrypted: objectResult.encrypted,
        skipped: objectResult.skipped,
        failed: objectResult.failed
    };
}

/**
 * Decrypt JSON content string using AWS KMS
 *
 * @param {string} content - Encrypted JSON content string
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Options (same as decryptKMSObject)
 * @returns {Promise<Object>} Result with decrypted JSON content
 */
async function decryptKMSJsonContent(content, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    if (!content || typeof content !== 'string') {
        throw new ContentError('Content must be a non-empty string', CONTENT_ERROR_CODES.EMPTY_CONTENT, 'json');
    }

    let obj;
    try {
        obj = JSON.parse(content);
    } catch (error) {
        throw new ContentError(
            `Failed to parse JSON content: ${error.message}`,
            CONTENT_ERROR_CODES.PARSE_FAILED,
            'json',
            error
        );
    }

    const objectResult = await decryptKMSObject(obj, kmsKeyId, options);

    return {
        content: JSON.stringify(objectResult.object, null, 2),
        decrypted: objectResult.decrypted,
        skipped: objectResult.skipped,
        failed: objectResult.failed
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// YAML CONTENT OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

const { parseYaml, serializeYaml, isJsYamlAvailable } = require('./yaml-utils');

/**
 * Encrypt YAML content string using AWS KMS
 *
 * Uses js-yaml if installed, otherwise falls back to simple parser for basic YAML.
 * Complex YAML features (anchors, multi-line strings) require js-yaml.
 *
 * @param {string} content - YAML content string
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Options (same as encryptKMSObject)
 * @returns {Promise<Object>} Result with encrypted YAML content
 */
async function encryptKMSYamlContent(content, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    if (!content || typeof content !== 'string') {
        throw new ContentError('Content must be a non-empty string', CONTENT_ERROR_CODES.EMPTY_CONTENT, 'yaml');
    }

    // Log warning if js-yaml not available
    const opts = buildEncryptOptions(options);
    if (!isJsYamlAvailable()) {
        opts.logger?.warn?.('[encryptKMSYamlContent] js-yaml not installed. Using simple parser (limited features).');
    }

    const obj = parseYaml(content);
    const objectResult = await encryptKMSObject(obj, kmsKeyId, options);

    return {
        content: serializeYaml(objectResult.object),
        encrypted: objectResult.encrypted,
        skipped: objectResult.skipped,
        failed: objectResult.failed
    };
}

/**
 * Decrypt YAML content string using AWS KMS
 *
 * Uses js-yaml if installed, otherwise falls back to simple parser for basic YAML.
 * Complex YAML features (anchors, multi-line strings) require js-yaml.
 *
 * @param {string} content - Encrypted YAML content string
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Options (same as decryptKMSObject)
 * @returns {Promise<Object>} Result with decrypted YAML content
 */
async function decryptKMSYamlContent(content, kmsKeyId, options = {}) {
    validateKmsKeyId(kmsKeyId);

    if (!content || typeof content !== 'string') {
        throw new ContentError('Content must be a non-empty string', CONTENT_ERROR_CODES.EMPTY_CONTENT, 'yaml');
    }

    // Log warning if js-yaml not available
    const opts = buildDecryptOptions(options);
    if (!isJsYamlAvailable()) {
        opts.logger?.warn?.('[decryptKMSYamlContent] js-yaml not installed. Using simple parser (limited features).');
    }

    const obj = parseYaml(content);
    const objectResult = await decryptKMSObject(obj, kmsKeyId, options);

    return {
        content: serializeYaml(objectResult.object),
        decrypted: objectResult.decrypted,
        skipped: objectResult.skipped,
        failed: objectResult.failed
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
    // ENV operations
    encryptKMSEnvContent,
    decryptKMSEnvContent,
    parseEnvContent,
    reconstructEnvContent,

    // JSON operations
    encryptKMSJsonContent,
    decryptKMSJsonContent,

    // YAML operations
    encryptKMSYamlContent,
    decryptKMSYamlContent
};

