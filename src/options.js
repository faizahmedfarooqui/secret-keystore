/**
 * @faizahmedfarooqui/secret-keystore - Options Architecture
 *
 * Layered/namespaced options structure for all library functions.
 * This module provides type definitions, defaults, and validation.
 */

const { ValidationError, VALIDATION_ERROR_CODES } = require('./errors');

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Reserved keys that should NEVER be encrypted.
 * These are required for the encryption/decryption process itself.
 */
const RESERVED_KEYS = [
    'KMS_KEY_ID',
    'AWS_REGION',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN'
];

// ═══════════════════════════════════════════════════════════════════════════
// DEFAULT VALUES
// ═══════════════════════════════════════════════════════════════════════════

const DEFAULT_AWS_OPTIONS = {
    credentials: null,  // Uses IAM role by default
    region: null        // Uses AWS_REGION env var or SDK default
};

const DEFAULT_ATTESTATION_OPTIONS = {
    enabled: false,
    required: false,
    fallbackToStandard: true,
    // Full attestation mode (default) - library handles key pair generation + CMS unwrap
    endpoint: null,     // Attestation endpoint URL (default: localhost:50123)
    timeout: 10000,     // Attestation request timeout in ms
    userData: '',       // User data to include in attestation document
    // Legacy mode - pre-generated document + private key
    document: null,     // Buffer | (() => Buffer) | (() => Promise<Buffer>) | string (base64)
    privateKey: null,   // PEM private key for CMS unwrap (required with document in legacy mode)
    // KMS options
    encryptionContext: null  // KMS encryption context
};

const DEFAULT_COMMON_OPTIONS = {
    aws: { ...DEFAULT_AWS_OPTIONS },
    attestation: { ...DEFAULT_ATTESTATION_OPTIONS },
    logger: null,       // Uses console if not provided
    logLevel: 'info'    // 'debug' | 'info' | 'warn' | 'error' | 'silent'
};

const DEFAULT_ENCRYPT_OPTIONS = {
    ...DEFAULT_COMMON_OPTIONS,
    output: {
        format: 'prefixed'  // 'base64' | 'buffer' | 'prefixed' (ENC[...])
    },
    skip: {
        empty: true,
        alreadyEncrypted: true
    },
    continueOnError: false
};

const DEFAULT_DECRYPT_OPTIONS = {
    ...DEFAULT_COMMON_OPTIONS,
    input: {
        format: 'auto'      // 'auto' | 'base64' | 'buffer' | 'prefixed'
    },
    skip: {
        unencrypted: true
    },
    validation: {
        format: true,
        kmsKeyMatch: true
    },
    continueOnError: false
};

const DEFAULT_PATH_SELECTION_OPTIONS = {
    paths: null,        // Explicit dot-notation paths
    patterns: null,     // Glob patterns using ** for any-depth matching
    exclude: {
        paths: null,
        patterns: null
    }
};

const DEFAULT_CONTENT_OPTIONS = {
    preserve: {
        comments: true,
        formatting: true,
        anchors: true       // YAML only
    }
};

const DEFAULT_KEYSTORE_OPTIONS = {
    ...DEFAULT_DECRYPT_OPTIONS,
    ...DEFAULT_PATH_SELECTION_OPTIONS,
    security: {
        inMemoryEncryption: true,
        secureWipe: true
    },
    access: {
        ttl: null,          // Secret expiry (ms), null = never
        autoRefresh: true,
        accessLimit: null,  // Max access count per key
        clearOnAccess: false
    },
    validation: {
        noProcessEnvLeak: true,
        throwOnMissingKey: false
    },
    retry: {
        attempts: 3,
        delay: 1000,        // ms
        backoff: 'exponential'  // 'linear' | 'exponential'
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Deep merge two objects
 * @param {Object} target - Target object
 * @param {Object} source - Source object
 * @returns {Object}
 */
function deepMerge(target, source) {
    const result = { ...target };

    for (const key of Object.keys(source)) {
        if (source[key] === undefined) {
            continue;
        }

        if (source[key] !== null &&
            typeof source[key] === 'object' &&
            !Array.isArray(source[key]) &&
            !Buffer.isBuffer(source[key]) &&
            typeof source[key] !== 'function') {
            result[key] = deepMerge(target[key] || {}, source[key]);
        } else {
            result[key] = source[key];
        }
    }

    return result;
}

/**
 * Create a logger with the specified level
 * @param {Object} baseLogger - Base logger (console or custom)
 * @param {string} logLevel - Log level
 * @returns {Object}
 */
function createLogger(baseLogger, logLevel = 'info') {
    const logger = baseLogger || console;
    const levels = ['debug', 'info', 'warn', 'error', 'silent'];
    const levelIndex = levels.indexOf(logLevel);

    return {
        debug: (...args) => levelIndex <= 0 && logger.debug?.(...args),
        info: (...args) => levelIndex <= 1 && logger.info?.(...args),
        warn: (...args) => levelIndex <= 2 && logger.warn?.(...args),
        error: (...args) => levelIndex <= 3 && logger.error?.(...args)
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate that kmsKeyId is provided
 * @param {string} kmsKeyId - KMS key ID
 * @throws {ValidationError}
 */
function validateKmsKeyId(kmsKeyId) {
    if (!kmsKeyId || typeof kmsKeyId !== 'string') {
        throw new ValidationError(
            'kmsKeyId is required and must be a non-empty string',
            VALIDATION_ERROR_CODES.KMS_KEY_REQUIRED,
            'kmsKeyId'
        );
    }

    // Basic format validation
    const isArn = kmsKeyId.startsWith('arn:aws:kms:');
    const isAlias = kmsKeyId.startsWith('alias/');
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(kmsKeyId);

    if (!isArn && !isAlias && !isUuid) {
        throw new ValidationError(
            'kmsKeyId must be an ARN (arn:aws:kms:...), alias (alias/...), or UUID',
            VALIDATION_ERROR_CODES.INVALID_VALUE,
            'kmsKeyId'
        );
    }
}

/**
 * Validate AWS options
 * @param {Object} aws - AWS options
 * @throws {ValidationError}
 */
function validateAwsOptions(aws) {
    if (!aws) return;

    if (aws.credentials) {
        const { accessKeyId, secretAccessKey } = aws.credentials;
        if (accessKeyId && !secretAccessKey) {
            throw new ValidationError(
                'secretAccessKey is required when accessKeyId is provided',
                VALIDATION_ERROR_CODES.REQUIRED_FIELD,
                'aws.credentials.secretAccessKey'
            );
        }
        if (!accessKeyId && secretAccessKey) {
            throw new ValidationError(
                'accessKeyId is required when secretAccessKey is provided',
                VALIDATION_ERROR_CODES.REQUIRED_FIELD,
                'aws.credentials.accessKeyId'
            );
        }
    }

    if (aws.region && typeof aws.region !== 'string') {
        throw new ValidationError(
            'aws.region must be a string',
            VALIDATION_ERROR_CODES.INVALID_TYPE,
            'aws.region'
        );
    }
}

/**
 * Validate attestation document format (legacy mode)
 * @private
 */
function validateAttestationDocument(attestation) {
    const isBuffer = Buffer.isBuffer(attestation.document);
    const isFunction = typeof attestation.document === 'function';
    const isString = typeof attestation.document === 'string';

    if (!isBuffer && !isFunction && !isString) {
        throw new ValidationError(
            'attestation.document must be a Buffer, string (base64), or function',
            VALIDATION_ERROR_CODES.INVALID_TYPE,
            'attestation.document'
        );
    }

    // In legacy mode, privateKey is required with document
    if (!attestation.privateKey) {
        throw new ValidationError(
            'attestation.privateKey is required when attestation.document is provided',
            VALIDATION_ERROR_CODES.REQUIRED_FIELD,
            'attestation.privateKey'
        );
    }
}

/**
 * Validate private key format
 * @private
 */
function validatePrivateKeyFormat(privateKey) {
    const isValidPem = typeof privateKey === 'string' &&
        privateKey.includes('-----BEGIN PRIVATE KEY-----');

    if (!isValidPem) {
        throw new ValidationError(
            'attestation.privateKey must be a PEM-encoded PKCS#8 private key',
            VALIDATION_ERROR_CODES.INVALID_TYPE,
            'attestation.privateKey'
        );
    }
}

/**
 * Validate attestation options
 * @param {Object} attestation - Attestation options
 * @throws {ValidationError}
 */
function validateAttestationOptions(attestation) {
    if (!attestation) return;

    if (attestation.required && !attestation.enabled) {
        throw new ValidationError(
            'attestation.enabled must be true when attestation.required is true',
            VALIDATION_ERROR_CODES.INVALID_OPTIONS,
            'attestation'
        );
    }

    // Validate legacy mode (document + privateKey)
    if (attestation.document) {
        validateAttestationDocument(attestation);
        validatePrivateKeyFormat(attestation.privateKey);
    }

    // Validate endpoint URL
    if (attestation.endpoint) {
        try {
            new URL(attestation.endpoint);
        } catch {
            throw new ValidationError(
                'attestation.endpoint must be a valid URL',
                VALIDATION_ERROR_CODES.INVALID_VALUE,
                'attestation.endpoint'
            );
        }
    }

    // Validate timeout
    const hasTimeout = attestation.timeout !== undefined && attestation.timeout !== null;
    const isValidTimeout = typeof attestation.timeout === 'number' && attestation.timeout >= 0;

    if (hasTimeout && !isValidTimeout) {
        throw new ValidationError(
            'attestation.timeout must be a positive number',
            VALIDATION_ERROR_CODES.INVALID_VALUE,
            'attestation.timeout'
        );
    }
}

/**
 * Validate path selection options
 * @param {Object} options - Path selection options
 * @throws {ValidationError}
 */
function validatePathSelectionOptions(options) {
    if (options.paths && !Array.isArray(options.paths)) {
        throw new ValidationError(
            'paths must be an array of strings',
            VALIDATION_ERROR_CODES.INVALID_TYPE,
            'paths'
        );
    }

    if (options.patterns && !Array.isArray(options.patterns)) {
        throw new ValidationError(
            'patterns must be an array of strings',
            VALIDATION_ERROR_CODES.INVALID_TYPE,
            'patterns'
        );
    }

    // Validate patterns only use ** (not single *)
    if (options.patterns) {
        for (const pattern of options.patterns) {
            // Check for single * that's not part of **
            if (/(?<!\*)\*(?!\*)/.test(pattern)) {
                throw new ValidationError(
                    `Invalid pattern "${pattern}": only ** (any-depth) is supported, not * (single-level)`,
                    VALIDATION_ERROR_CODES.INVALID_VALUE,
                    'patterns'
                );
            }
        }
    }
}

/**
 * Validate common options
 * @param {Object} options - Options to validate
 * @throws {ValidationError}
 */
function validateCommonOptions(options) {
    if (!options) return;

    validateAwsOptions(options.aws);
    validateAttestationOptions(options.attestation);

    if (options.logLevel && !['debug', 'info', 'warn', 'error', 'silent'].includes(options.logLevel)) {
        throw new ValidationError(
            'logLevel must be one of: debug, info, warn, error, silent',
            VALIDATION_ERROR_CODES.INVALID_VALUE,
            'logLevel'
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OPTIONS BUILDERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Build common options with defaults
 * @param {Object} options - User provided options
 * @returns {Object}
 */
function buildCommonOptions(options = {}) {
    const merged = deepMerge(DEFAULT_COMMON_OPTIONS, options);
    merged.logger = createLogger(options.logger, merged.logLevel);
    validateCommonOptions(merged);
    return merged;
}

/**
 * Build encrypt options with defaults
 * @param {Object} options - User provided options
 * @returns {Object}
 */
function buildEncryptOptions(options = {}) {
    const merged = deepMerge(DEFAULT_ENCRYPT_OPTIONS, options);
    merged.logger = createLogger(options.logger, merged.logLevel);
    validateCommonOptions(merged);
    return merged;
}

/**
 * Build decrypt options with defaults
 * @param {Object} options - User provided options
 * @returns {Object}
 */
function buildDecryptOptions(options = {}) {
    const merged = deepMerge(DEFAULT_DECRYPT_OPTIONS, options);
    merged.logger = createLogger(options.logger, merged.logLevel);
    validateCommonOptions(merged);
    return merged;
}

/**
 * Build path selection options with defaults
 * @param {Object} options - User provided options
 * @returns {Object}
 */
function buildPathSelectionOptions(options = {}) {
    const merged = deepMerge(DEFAULT_PATH_SELECTION_OPTIONS, options);
    validatePathSelectionOptions(merged);
    return merged;
}

/**
 * Build content options with defaults
 * @param {Object} options - User provided options
 * @returns {Object}
 */
function buildContentOptions(options = {}) {
    return deepMerge(DEFAULT_CONTENT_OPTIONS, options);
}

/**
 * Build keystore options with defaults
 * @param {Object} options - User provided options
 * @returns {Object}
 */
function buildKeystoreOptions(options = {}) {
    const merged = deepMerge(DEFAULT_KEYSTORE_OPTIONS, options);
    merged.logger = createLogger(options.logger, merged.logLevel);
    validateCommonOptions(merged);
    validatePathSelectionOptions(merged);
    return merged;
}

// ═══════════════════════════════════════════════════════════════════════════
// AWS SDK OPTIONS BUILDER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Build AWS SDK client options from library options
 * @param {Object} options - Library options (with aws namespace)
 * @returns {Object} AWS SDK client options
 */
function buildAwsSdkOptions(options = {}) {
    const sdkOptions = {};
    const aws = options.aws || options;

    // Credentials: Only set if explicitly provided
    if (aws.credentials?.accessKeyId && aws.credentials?.secretAccessKey) {
        sdkOptions.credentials = {
            accessKeyId: aws.credentials.accessKeyId,
            secretAccessKey: aws.credentials.secretAccessKey
        };
        if (aws.credentials.sessionToken) {
            sdkOptions.credentials.sessionToken = aws.credentials.sessionToken;
        }
    }

    // Region: Use provided > env var > SDK default
    if (aws.region) {
        sdkOptions.region = aws.region;
    } else if (process.env.AWS_REGION) {
        sdkOptions.region = process.env.AWS_REGION;
    }

    return sdkOptions;
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
    // Constants
    RESERVED_KEYS,

    // Defaults
    DEFAULT_AWS_OPTIONS,
    DEFAULT_ATTESTATION_OPTIONS,
    DEFAULT_COMMON_OPTIONS,
    DEFAULT_ENCRYPT_OPTIONS,
    DEFAULT_DECRYPT_OPTIONS,
    DEFAULT_PATH_SELECTION_OPTIONS,
    DEFAULT_CONTENT_OPTIONS,
    DEFAULT_KEYSTORE_OPTIONS,

    // Helpers
    deepMerge,
    createLogger,

    // Validation
    validateKmsKeyId,
    validateAwsOptions,
    validateAttestationOptions,
    validatePathSelectionOptions,
    validateCommonOptions,

    // Builders
    buildCommonOptions,
    buildEncryptOptions,
    buildDecryptOptions,
    buildPathSelectionOptions,
    buildContentOptions,
    buildKeystoreOptions,
    buildAwsSdkOptions
};

