/**
 * @faizahmedfarooqui/secret-keystore
 *
 * Secure secrets management library with AWS KMS encryption.
 *
 * Features:
 * - Build-time encryption of configuration values
 * - Runtime decryption with secure in-memory storage
 * - Attestation support for AWS Nitro Enclaves
 * - Support for ENV, JSON, and YAML formats
 *
 * SECURITY NOTES:
 * - Decrypted values are ONLY stored in KeyStore memory (never in process.env)
 * - kmsKeyId is REQUIRED for all operations (no auto-detection)
 * - Uses IAM roles by default; explicit credentials are opt-in
 * - No third-party libraries for crypto operations
 */

// ═══════════════════════════════════════════════════════════════════════════
// CORE KMS OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

const {
    encryptKMSValue,
    decryptKMSValue,
    encryptKMSValues,
    decryptKMSValues,
    isEncryptedFormat,
    isKmsCiphertext,
    isAlreadyEncrypted,
    isEnvelopeFormat,
    wrapCiphertext,
    unwrapCiphertext,
    maskKmsKeyId,
    clearAttestationCache,
    getAttestationStatus,
    ENCRYPTED_PREFIX,
    ENCRYPTED_SUFFIX
} = require('./kms');

// ═══════════════════════════════════════════════════════════════════════════
// ATTESTATION MODULE
// ═══════════════════════════════════════════════════════════════════════════

const {
    // Key pair utilities
    generateEphemeralKeyPair,
    prepareAttestationParams,
    toBase64Url,
    toBase64,

    // CMS unwrapping
    unwrapCms,
    validatePrivateKeyFormat,

    // Attestation client
    fetchAttestationDocument,
    isNitroEnclave,
    isAttestationAvailable,
    DEFAULT_ATTESTATION_ENDPOINT,

    // Attestation manager
    AttestationManager,
    createAttestationManager
} = require('./attestation');

// ═══════════════════════════════════════════════════════════════════════════
// OPTIONS ARCHITECTURE
// ═══════════════════════════════════════════════════════════════════════════

const {
    DEFAULT_AWS_OPTIONS,
    DEFAULT_ATTESTATION_OPTIONS,
    DEFAULT_COMMON_OPTIONS,
    DEFAULT_ENCRYPT_OPTIONS,
    DEFAULT_DECRYPT_OPTIONS,
    DEFAULT_PATH_SELECTION_OPTIONS,
    DEFAULT_CONTENT_OPTIONS,
    DEFAULT_KEYSTORE_OPTIONS,
    RESERVED_KEYS,
    validateKmsKeyId,
    validateAwsOptions,
    validateAttestationOptions,
    validatePathSelectionOptions,
    validateCommonOptions,
    buildCommonOptions,
    buildEncryptOptions,
    buildDecryptOptions,
    buildPathSelectionOptions,
    buildContentOptions,
    buildKeystoreOptions,
    buildAwsSdkOptions,
    deepMerge,
    createLogger
} = require('./options');

// ═══════════════════════════════════════════════════════════════════════════
// ERROR CLASSES
// ═══════════════════════════════════════════════════════════════════════════

const {
    SecretKeyStoreError,
    KmsError,
    AttestationError,
    ContentError,
    PathError,
    EncryptionError,
    DecryptionError,
    KeystoreError,
    ValidationError,
    KMS_ERROR_CODES,
    ATTESTATION_ERROR_CODES,
    CONTENT_ERROR_CODES,
    PATH_ERROR_CODES,
    ENCRYPTION_ERROR_CODES,
    DECRYPTION_ERROR_CODES,
    KEYSTORE_ERROR_CODES,
    VALIDATION_ERROR_CODES,
    isRecoverableError,
    createKmsErrorFromAws
} = require('./errors');

// ═══════════════════════════════════════════════════════════════════════════
// PATH MATCHING
// ═══════════════════════════════════════════════════════════════════════════

const {
    getByPath,
    setByPath,
    getAllPaths,
    matchesPattern,
    filterPaths,
    transformAtPaths
} = require('./path-matcher');

// ═══════════════════════════════════════════════════════════════════════════
// OBJECT-BASED OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

const {
    encryptKMSObject,
    decryptKMSObject
} = require('./object-operations');

// ═══════════════════════════════════════════════════════════════════════════
// CONTENT-BASED OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

const {
    encryptKMSEnvContent,
    decryptKMSEnvContent,
    parseEnvContent,
    reconstructEnvContent,
    encryptKMSJsonContent,
    decryptKMSJsonContent,
    encryptKMSYamlContent,
    decryptKMSYamlContent
} = require('./content-operations');

// ═══════════════════════════════════════════════════════════════════════════
// YAML UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

const {
    isJsYamlAvailable,
    parseYaml,
    serializeYaml
} = require('./yaml-utils');

// ═══════════════════════════════════════════════════════════════════════════
// RUNTIME KEYSTORE
// ═══════════════════════════════════════════════════════════════════════════

const {
    SecretKeyStore,
    createSecretKeyStore
} = require('./keystore');

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
    // =========================================================================
    // CORE KMS OPERATIONS
    // =========================================================================

    /** Encrypt a single value using KMS */
    encryptKMSValue,

    /** Decrypt a single value using KMS */
    decryptKMSValue,

    /** Encrypt multiple key-value pairs using KMS */
    encryptKMSValues,

    /** Decrypt multiple key-value pairs using KMS */
    decryptKMSValues,

    // =========================================================================
    // FORMAT HELPERS
    // =========================================================================

    /** Check if value is in ENC[...] format */
    isEncryptedFormat,

    /** Check if value looks like raw KMS ciphertext */
    isKmsCiphertext,

    /** Check if value is already encrypted (any format) */
    isAlreadyEncrypted,

    /** Check if decoded ciphertext buffer is envelope format (RSA envelope encryption) */
    isEnvelopeFormat,

    /** Wrap base64 ciphertext in ENC[...] format */
    wrapCiphertext,

    /** Unwrap ciphertext from ENC[...] format */
    unwrapCiphertext,

    /** Mask KMS key ID for logging */
    maskKmsKeyId,

    /** Encrypted value prefix */
    ENCRYPTED_PREFIX,

    /** Encrypted value suffix */
    ENCRYPTED_SUFFIX,

    // =========================================================================
    // PATH MATCHING
    // =========================================================================

    /** Get value from object by dot-notation path */
    getByPath,

    /** Set value in object by dot-notation path */
    setByPath,

    /** Get all leaf paths in an object */
    getAllPaths,

    /** Check if path matches a ** pattern */
    matchesPattern,

    /** Filter paths using patterns and explicit paths */
    filterPaths,

    /** Transform values at selected paths */
    transformAtPaths,

    // =========================================================================
    // OBJECT-BASED OPERATIONS
    // =========================================================================

    /** Encrypt values at selected paths in a nested object using KMS */
    encryptKMSObject,

    /** Decrypt values at selected paths in a nested object using KMS */
    decryptKMSObject,

    // =========================================================================
    // CONTENT-BASED OPERATIONS
    // =========================================================================

    /** Encrypt .env content string using KMS */
    encryptKMSEnvContent,

    /** Decrypt .env content string using KMS */
    decryptKMSEnvContent,

    /** Parse .env content into structured entries */
    parseEnvContent,

    /** Reconstruct .env content from structured entries */
    reconstructEnvContent,

    /** Encrypt JSON content string using KMS */
    encryptKMSJsonContent,

    /** Decrypt JSON content string using KMS */
    decryptKMSJsonContent,

    /** Encrypt YAML content string using KMS */
    encryptKMSYamlContent,

    /** Decrypt YAML content string using KMS */
    decryptKMSYamlContent,

    // =========================================================================
    // YAML UTILITIES
    // =========================================================================

    /** Check if js-yaml is installed (for complex YAML support) */
    isJsYamlAvailable,

    /** Parse YAML content to object (uses js-yaml if available, falls back to simple parser) */
    parseYaml,

    /** Serialize object to YAML string (uses js-yaml if available) */
    serializeYaml,

    // =========================================================================
    // OPTIONS & DEFAULTS
    // =========================================================================

    DEFAULT_AWS_OPTIONS,
    DEFAULT_ATTESTATION_OPTIONS,
    DEFAULT_COMMON_OPTIONS,
    DEFAULT_ENCRYPT_OPTIONS,
    DEFAULT_DECRYPT_OPTIONS,
    DEFAULT_PATH_SELECTION_OPTIONS,
    DEFAULT_CONTENT_OPTIONS,
    DEFAULT_KEYSTORE_OPTIONS,
    RESERVED_KEYS,

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
    buildAwsSdkOptions,

    // Helpers
    deepMerge,
    createLogger,

    // =========================================================================
    // ERRORS
    // =========================================================================

    SecretKeyStoreError,
    KmsError,
    AttestationError,
    ContentError,
    PathError,
    EncryptionError,
    DecryptionError,
    KeystoreError,
    ValidationError,

    // Error codes
    KMS_ERROR_CODES,
    ATTESTATION_ERROR_CODES,
    CONTENT_ERROR_CODES,
    PATH_ERROR_CODES,
    ENCRYPTION_ERROR_CODES,
    DECRYPTION_ERROR_CODES,
    KEYSTORE_ERROR_CODES,
    VALIDATION_ERROR_CODES,

    // Error helpers
    isRecoverableError,
    createKmsErrorFromAws,

    // =========================================================================
    // RUNTIME KEYSTORE
    // =========================================================================

    /** SecretKeyStore class with TTL, autoRefresh, source types */
    SecretKeyStore,

    /** Create and initialize a keystore */
    createSecretKeyStore,

    // =========================================================================
    // ATTESTATION
    // =========================================================================

    // Key pair utilities
    /** Generate ephemeral RSA-4096 key pair for attestation */
    generateEphemeralKeyPair,

    /** Prepare attestation request parameters */
    prepareAttestationParams,

    /** Convert buffer to base64url */
    toBase64Url,

    /** Convert buffer to base64 */
    toBase64,

    // CMS utilities
    /** Unwrap CMS EnvelopedData using PKIjs */
    unwrapCms,

    /** Validate PKCS#8 PEM private key format */
    validatePrivateKeyFormat,

    // Attestation client
    /** Fetch attestation document from Nitro/Anjuna endpoint */
    fetchAttestationDocument,

    /** Check if running inside Nitro Enclave */
    isNitroEnclave,

    /** Check if attestation endpoint is reachable */
    isAttestationAvailable,

    /** Default attestation endpoint URL */
    DEFAULT_ATTESTATION_ENDPOINT,

    // Attestation manager
    /** AttestationManager class for full attestation lifecycle */
    AttestationManager,

    /** Create and initialize an AttestationManager */
    createAttestationManager,

    /** Clear all cached attestation managers */
    clearAttestationCache,

    /** Get attestation status for an endpoint */
    getAttestationStatus
};
