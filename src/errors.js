/**
 * @faizahmedfarooqui/secret-keystore - Error Classes
 *
 * Comprehensive error taxonomy with codes for proper handling.
 * All errors extend SecretKeyStoreError as the base class.
 */

// ═══════════════════════════════════════════════════════════════════════════
// BASE ERROR CLASS
// ═══════════════════════════════════════════════════════════════════════════

class SecretKeyStoreError extends Error {
    /**
     * @param {string} message - Error message
     * @param {string} code - Error code
     * @param {Error} [cause] - Original error that caused this
     */
    constructor(message, code, cause) {
        super(message);
        this.name = 'SecretKeyStoreError';
        this.code = code;
        this.cause = cause;
        this.timestamp = new Date();
        Error.captureStackTrace(this, this.constructor);
    }

    toJSON() {
        return {
            name: this.name,
            code: this.code,
            message: this.message,
            timestamp: this.timestamp.toISOString(),
            cause: this.cause ? {
                name: this.cause.name,
                message: this.cause.message
            } : undefined
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// KMS ERRORS
// ═══════════════════════════════════════════════════════════════════════════

class KmsError extends SecretKeyStoreError {
    /**
     * @param {string} message - Error message
     * @param {string} code - Error code
     * @param {string} kmsKeyId - KMS key ID
     * @param {Error} [cause] - Original error
     */
    constructor(message, code, kmsKeyId, cause) {
        super(message, code, cause);
        this.name = 'KmsError';
        this.kmsKeyId = kmsKeyId;
        this.awsRequestId = cause?.['$metadata']?.requestId;
    }
}

// KMS Error Codes
const KMS_ERROR_CODES = {
    KEY_NOT_FOUND: 'KMS_KEY_NOT_FOUND',
    KEY_DISABLED: 'KMS_KEY_DISABLED',
    ACCESS_DENIED: 'KMS_ACCESS_DENIED',
    INVALID_CIPHERTEXT: 'KMS_INVALID_CIPHERTEXT',
    THROTTLED: 'KMS_THROTTLED',
    ENCRYPT_FAILED: 'KMS_ENCRYPT_FAILED',
    DECRYPT_FAILED: 'KMS_DECRYPT_FAILED',
    CONNECTION_ERROR: 'KMS_CONNECTION_ERROR'
};

// ═══════════════════════════════════════════════════════════════════════════
// ATTESTATION ERRORS
// ═══════════════════════════════════════════════════════════════════════════

class AttestationError extends SecretKeyStoreError {
    constructor(message, code, cause) {
        super(message, code, cause);
        this.name = 'AttestationError';
    }
}

// Attestation Error Codes
const ATTESTATION_ERROR_CODES = {
    DOCUMENT_MISSING: 'ATTESTATION_DOCUMENT_MISSING',
    DOCUMENT_INVALID: 'ATTESTATION_DOCUMENT_INVALID',
    DOCUMENT_EXPIRED: 'ATTESTATION_DOCUMENT_EXPIRED',
    GETTER_FAILED: 'ATTESTATION_GETTER_FAILED',
    NOT_AVAILABLE: 'ATTESTATION_NOT_AVAILABLE',
    RETRY_FAILED: 'ATTESTATION_RETRY_FAILED',
    INIT_FAILED: 'ATTESTATION_INIT_FAILED',
    CMS_UNWRAP_FAILED: 'ATTESTATION_CMS_UNWRAP_FAILED',
    KEYPAIR_GENERATION_FAILED: 'ATTESTATION_KEYPAIR_GENERATION_FAILED',
    ENDPOINT_UNREACHABLE: 'ATTESTATION_ENDPOINT_UNREACHABLE'
};

// ═══════════════════════════════════════════════════════════════════════════
// CONTENT ERRORS
// ═══════════════════════════════════════════════════════════════════════════

class ContentError extends SecretKeyStoreError {
    /**
     * @param {string} message - Error message
     * @param {string} code - Error code
     * @param {string} [format] - Content format (env, json, yaml)
     * @param {Error} [cause] - Original error
     */
    constructor(message, code, format, cause) {
        super(message, code, cause);
        this.name = 'ContentError';
        this.format = format;
    }
}

// Content Error Codes
const CONTENT_ERROR_CODES = {
    PARSE_FAILED: 'CONTENT_PARSE_FAILED',
    INVALID_FORMAT: 'CONTENT_INVALID_FORMAT',
    EMPTY_CONTENT: 'CONTENT_EMPTY',
    SERIALIZATION_FAILED: 'CONTENT_SERIALIZATION_FAILED'
};

// ═══════════════════════════════════════════════════════════════════════════
// PATH ERRORS
// ═══════════════════════════════════════════════════════════════════════════

class PathError extends SecretKeyStoreError {
    /**
     * @param {string} message - Error message
     * @param {string} code - Error code
     * @param {string} [path] - The path that caused the error
     * @param {Error} [cause] - Original error
     */
    constructor(message, code, path, cause) {
        super(message, code, cause);
        this.name = 'PathError';
        this.path = path;
    }
}

// Path Error Codes
const PATH_ERROR_CODES = {
    NOT_FOUND: 'PATH_NOT_FOUND',
    INVALID_PATTERN: 'PATH_INVALID_PATTERN',
    ACCESS_DENIED: 'PATH_ACCESS_DENIED'
};

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION ERRORS
// ═══════════════════════════════════════════════════════════════════════════

class EncryptionError extends SecretKeyStoreError {
    /**
     * @param {string} message - Error message
     * @param {string} code - Error code
     * @param {string} [key] - The key that failed to encrypt
     * @param {Error} [cause] - Original error
     */
    constructor(message, code, key, cause) {
        super(message, code, cause);
        this.name = 'EncryptionError';
        this.key = key;
    }
}

// Encryption Error Codes
const ENCRYPTION_ERROR_CODES = {
    FAILED: 'ENCRYPTION_FAILED',
    INVALID_VALUE: 'ENCRYPTION_INVALID_VALUE',
    ALREADY_ENCRYPTED: 'ENCRYPTION_ALREADY_ENCRYPTED'
};

// ═══════════════════════════════════════════════════════════════════════════
// DECRYPTION ERRORS
// ═══════════════════════════════════════════════════════════════════════════

class DecryptionError extends SecretKeyStoreError {
    /**
     * @param {string} message - Error message
     * @param {string} code - Error code
     * @param {string} [key] - The key that failed to decrypt
     * @param {Error} [cause] - Original error
     */
    constructor(message, code, key, cause) {
        super(message, code, cause);
        this.name = 'DecryptionError';
        this.key = key;
    }
}

// Decryption Error Codes
const DECRYPTION_ERROR_CODES = {
    FAILED: 'DECRYPTION_FAILED',
    INVALID_CIPHERTEXT: 'DECRYPTION_INVALID_CIPHERTEXT',
    NOT_ENCRYPTED: 'DECRYPTION_NOT_ENCRYPTED'
};

// ═══════════════════════════════════════════════════════════════════════════
// KEYSTORE ERRORS
// ═══════════════════════════════════════════════════════════════════════════

class KeystoreError extends SecretKeyStoreError {
    constructor(message, code, cause) {
        super(message, code, cause);
        this.name = 'KeystoreError';
    }
}

// Keystore Error Codes
const KEYSTORE_ERROR_CODES = {
    NOT_INITIALIZED: 'KEYSTORE_NOT_INITIALIZED',
    ALREADY_INITIALIZED: 'KEYSTORE_ALREADY_INITIALIZED',
    DESTROYED: 'KEYSTORE_DESTROYED',
    SECRET_NOT_FOUND: 'SECRET_NOT_FOUND',
    SECRET_EXPIRED: 'SECRET_EXPIRED',
    ACCESS_LIMIT_EXCEEDED: 'SECRET_ACCESS_LIMIT_EXCEEDED',
    INITIALIZATION_FAILED: 'KEYSTORE_INITIALIZATION_FAILED',
    REFRESH_FAILED: 'KEYSTORE_REFRESH_FAILED'
};

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION ERRORS
// ═══════════════════════════════════════════════════════════════════════════

class ValidationError extends SecretKeyStoreError {
    /**
     * @param {string} message - Error message
     * @param {string} code - Error code
     * @param {string} [field] - The field that failed validation
     * @param {Error} [cause] - Original error
     */
    constructor(message, code, field, cause) {
        super(message, code, cause);
        this.name = 'ValidationError';
        this.field = field;
    }
}

// Validation Error Codes
const VALIDATION_ERROR_CODES = {
    REQUIRED_FIELD: 'VALIDATION_REQUIRED_FIELD',
    INVALID_TYPE: 'VALIDATION_INVALID_TYPE',
    INVALID_VALUE: 'VALIDATION_INVALID_VALUE',
    INVALID_OPTIONS: 'VALIDATION_INVALID_OPTIONS',
    KMS_KEY_REQUIRED: 'VALIDATION_KMS_KEY_REQUIRED',
    PROCESS_ENV_LEAK: 'VALIDATION_PROCESS_ENV_LEAK'
};

// ═══════════════════════════════════════════════════════════════════════════
// CONVENIENCE ERROR CLASSES
// ═══════════════════════════════════════════════════════════════════════════

class InitializationError extends KeystoreError {
    constructor(message, cause) {
        super(message, KEYSTORE_ERROR_CODES.INITIALIZATION_FAILED, cause);
        this.name = 'InitializationError';
    }
}

class SecretNotFoundError extends KeystoreError {
    constructor(key) {
        super(`Secret not found: ${key}`, KEYSTORE_ERROR_CODES.SECRET_NOT_FOUND);
        this.name = 'SecretNotFoundError';
        this.secretKey = key;
    }
}

class NotInitializedError extends KeystoreError {
    constructor() {
        super('SecretKeyStore not initialized. Call initialize() first.', KEYSTORE_ERROR_CODES.NOT_INITIALIZED);
        this.name = 'NotInitializedError';
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if an error is recoverable (can be retried)
 * @param {Error} error - Error to check
 * @returns {boolean}
 */
function isRecoverableError(error) {
    if (!(error instanceof SecretKeyStoreError)) {
        return false;
    }

    const recoverableCodes = [
        KMS_ERROR_CODES.KEY_DISABLED,
        KMS_ERROR_CODES.THROTTLED,
        KMS_ERROR_CODES.CONNECTION_ERROR,
        ATTESTATION_ERROR_CODES.DOCUMENT_EXPIRED,
        KEYSTORE_ERROR_CODES.SECRET_EXPIRED
    ];

    return recoverableCodes.includes(error.code);
}

/**
 * Create a KMS error from an AWS SDK error
 * @param {Error} awsError - AWS SDK error
 * @param {string} kmsKeyId - KMS key ID
 * @param {string} operation - 'encrypt' or 'decrypt'
 * @returns {KmsError}
 */
function createKmsErrorFromAws(awsError, kmsKeyId, operation = 'decrypt') {
    const message = awsError.message || 'KMS operation failed';
    const errorName = awsError.name || '';

    let code;
    if (errorName.includes('NotFoundException') || message.includes('not found')) {
        code = KMS_ERROR_CODES.KEY_NOT_FOUND;
    } else if (errorName.includes('DisabledException') || message.includes('disabled')) {
        code = KMS_ERROR_CODES.KEY_DISABLED;
    } else if (errorName.includes('AccessDeniedException') || message.includes('Access Denied')) {
        code = KMS_ERROR_CODES.ACCESS_DENIED;
    } else if (errorName.includes('InvalidCiphertextException') || message.includes('ciphertext')) {
        code = KMS_ERROR_CODES.INVALID_CIPHERTEXT;
    } else if (errorName.includes('ThrottlingException') || message.includes('throttl')) {
        code = KMS_ERROR_CODES.THROTTLED;
    } else if (operation === 'encrypt') {
        code = KMS_ERROR_CODES.ENCRYPT_FAILED;
    } else {
        code = KMS_ERROR_CODES.DECRYPT_FAILED;
    }

    return new KmsError(message, code, kmsKeyId, awsError);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
    // Base class
    SecretKeyStoreError,

    // Specialized error classes
    KmsError,
    AttestationError,
    ContentError,
    PathError,
    EncryptionError,
    DecryptionError,
    KeystoreError,
    ValidationError,

    // Convenience classes
    InitializationError,
    SecretNotFoundError,
    NotInitializedError,

    // Error codes
    KMS_ERROR_CODES,
    ATTESTATION_ERROR_CODES,
    CONTENT_ERROR_CODES,
    PATH_ERROR_CODES,
    ENCRYPTION_ERROR_CODES,
    DECRYPTION_ERROR_CODES,
    KEYSTORE_ERROR_CODES,
    VALIDATION_ERROR_CODES,

    // Helper functions
    isRecoverableError,
    createKmsErrorFromAws
};
