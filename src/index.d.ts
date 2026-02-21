/**
 * @faizahmedfarooqui/secret-keystore - TypeScript Definitions
 *
 * Version 4.0
 */

// Declare Buffer for environments without @types/node
declare global {
    interface BufferConstructor {
        from(data: string | ArrayBuffer | SharedArrayBuffer | Uint8Array, encoding?: string): Buffer;
    }
    interface Buffer extends Uint8Array {
        toString(encoding?: string): string;
    }
    // eslint-disable-next-line no-var
    var Buffer: BufferConstructor;
}

// ═══════════════════════════════════════════════════════════════════════════
// AWS OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface AwsCredentials {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
}

export interface AwsOptions {
    credentials?: AwsCredentials;
    region?: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// ATTESTATION OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export type AttestationDocument = Buffer | (() => Buffer) | (() => Promise<Buffer>);

export interface AttestationOptions {
    enabled?: boolean;
    required?: boolean;
    fallbackToStandard?: boolean;
    document?: AttestationDocument;
}

// ═══════════════════════════════════════════════════════════════════════════
// LOGGER
// ═══════════════════════════════════════════════════════════════════════════

export interface Logger {
    debug(message: string, ...args: unknown[]): void;
    info(message: string, ...args: unknown[]): void;
    warn(message: string, ...args: unknown[]): void;
    error(message: string, ...args: unknown[]): void;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

// ═══════════════════════════════════════════════════════════════════════════
// COMMON OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface CommonOptions {
    aws?: AwsOptions;
    attestation?: AttestationOptions;
    logger?: Logger;
    logLevel?: LogLevel;
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPT OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export type OutputFormat = 'base64' | 'buffer' | 'prefixed';

export interface EncryptOptions extends CommonOptions {
    output?: {
        format?: OutputFormat;
    };
    skip?: {
        empty?: boolean;
        alreadyEncrypted?: boolean;
    };
    continueOnError?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// DECRYPT OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export type InputFormat = 'auto' | 'base64' | 'buffer' | 'prefixed';

export interface DecryptOptions extends CommonOptions {
    input?: {
        format?: InputFormat;
    };
    skip?: {
        unencrypted?: boolean;
    };
    validation?: {
        format?: boolean;
        kmsKeyMatch?: boolean;
    };
    continueOnError?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// PATH SELECTION OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface PathSelectionOptions {
    paths?: string[];
    patterns?: string[];
    exclude?: {
        paths?: string[];
        patterns?: string[];
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// CONTENT OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface ContentOptions {
    preserve?: {
        comments?: boolean;
        formatting?: boolean;
        anchors?: boolean;
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// KEYSTORE OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface KeystoreValidationOptions {
    noProcessEnvLeak?: boolean;
    throwOnMissingKey?: boolean;
}

export interface KeystoreOptions extends Omit<DecryptOptions, 'validation'>, PathSelectionOptions {
    security?: {
        inMemoryEncryption?: boolean;
        secureWipe?: boolean;
    };
    access?: {
        ttl?: number | null;
        autoRefresh?: boolean;
        accessLimit?: number | null;
        clearOnAccess?: boolean;
    };
    validation?: KeystoreValidationOptions;
    retry?: {
        attempts?: number;
        delay?: number;
        backoff?: 'linear' | 'exponential';
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// RESULT TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface FailedItem {
    key: string;
    error: Error;
}

export interface FailedPath {
    path: string;
    error: Error;
}

export interface ValuesResult {
    values: Record<string, string>;
    encrypted?: string[];
    decrypted?: string[];
    skipped: string[];
    failed: FailedItem[];
}

export interface ObjectResult {
    object: Record<string, unknown>;
    encrypted?: string[];
    decrypted?: string[];
    skipped: string[];
    failed: FailedPath[];
}

export interface ContentResult {
    content: string;
    encrypted?: string[];
    decrypted?: string[];
    skipped: string[];
    failed: FailedItem[];
}

// ═══════════════════════════════════════════════════════════════════════════
// PARSED ENV ENTRY
// ═══════════════════════════════════════════════════════════════════════════

export interface ParsedEnvEntry {
    type: 'empty' | 'comment' | 'keyvalue' | 'other';
    key?: string;
    value?: string;
    inlineComment?: string;
    raw: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// CORE KMS OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

/** Encrypt a single value using AWS KMS */
export function encryptKMSValue(
    plaintext: string,
    kmsKeyId: string,
    options?: EncryptOptions
): Promise<string | Buffer>;

/** Decrypt a single value using AWS KMS */
export function decryptKMSValue(
    ciphertext: string | Buffer,
    kmsKeyId: string,
    options?: DecryptOptions
): Promise<string>;

/** Encrypt multiple key-value pairs using AWS KMS */
export function encryptKMSValues(
    values: Record<string, string>,
    kmsKeyId: string,
    options?: EncryptOptions
): Promise<ValuesResult>;

/** Decrypt multiple key-value pairs using AWS KMS */
export function decryptKMSValues(
    values: Record<string, string>,
    kmsKeyId: string,
    options?: DecryptOptions
): Promise<ValuesResult>;

// ═══════════════════════════════════════════════════════════════════════════
// FORMAT HELPERS
// ═══════════════════════════════════════════════════════════════════════════

export function isEncryptedFormat(value: string): boolean;
export function isKmsCiphertext(value: string): boolean;
export function isAlreadyEncrypted(value: string): boolean;
export function isEnvelopeFormat(buf: Buffer): boolean;
export function wrapCiphertext(ciphertext: string): string;
export function unwrapCiphertext(value: string): string;
export function maskKmsKeyId(keyId: string): string;

export const ENCRYPTED_PREFIX: string;
export const ENCRYPTED_SUFFIX: string;

// ═══════════════════════════════════════════════════════════════════════════
// PATH MATCHING
// ═══════════════════════════════════════════════════════════════════════════

export function getByPath<T = unknown>(obj: Record<string, unknown>, path: string): T | undefined;
export function setByPath<T extends Record<string, unknown>>(obj: T, path: string, value: unknown): T;
export function getAllPaths(obj: Record<string, unknown>, prefix?: string): string[];
export function matchesPattern(path: string, pattern: string): boolean;
export function filterPaths(allPaths: string[], options?: PathSelectionOptions): string[];
export function transformAtPaths(
    obj: Record<string, unknown>,
    paths: string[],
    transformer: (value: unknown, path: string) => Promise<unknown>,
    options?: { continueOnError?: boolean }
): Promise<{
    object: Record<string, unknown>;
    transformed: string[];
    skipped: string[];
    failed: FailedPath[];
}>;

// ═══════════════════════════════════════════════════════════════════════════
// OBJECT-BASED OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface EncryptObjectOptions extends EncryptOptions, PathSelectionOptions {}
export interface DecryptObjectOptions extends DecryptOptions, PathSelectionOptions {}

/** Encrypt values at selected paths in a nested object using AWS KMS */
export function encryptKMSObject(
    obj: Record<string, unknown>,
    kmsKeyId: string,
    options?: EncryptObjectOptions
): Promise<ObjectResult>;

/** Decrypt values at selected paths in a nested object using AWS KMS */
export function decryptKMSObject(
    obj: Record<string, unknown>,
    kmsKeyId: string,
    options?: DecryptObjectOptions
): Promise<ObjectResult>;

// ═══════════════════════════════════════════════════════════════════════════
// CONTENT-BASED OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface EncryptContentOptions extends EncryptOptions, PathSelectionOptions, ContentOptions {}
export interface DecryptContentOptions extends DecryptOptions, PathSelectionOptions, ContentOptions {}

/** Encrypt .env content string using AWS KMS */
export function encryptKMSEnvContent(
    content: string,
    kmsKeyId: string,
    options?: EncryptContentOptions
): Promise<ContentResult>;

/** Decrypt .env content string using AWS KMS */
export function decryptKMSEnvContent(
    content: string,
    kmsKeyId: string,
    options?: DecryptContentOptions
): Promise<ContentResult>;

export function parseEnvContent(content: string): ParsedEnvEntry[];
export function reconstructEnvContent(parsed: ParsedEnvEntry[]): string;

/** Encrypt JSON content string using AWS KMS */
export function encryptKMSJsonContent(
    content: string,
    kmsKeyId: string,
    options?: EncryptContentOptions
): Promise<ContentResult>;

/** Decrypt JSON content string using AWS KMS */
export function decryptKMSJsonContent(
    content: string,
    kmsKeyId: string,
    options?: DecryptContentOptions
): Promise<ContentResult>;

/** Encrypt YAML content string using AWS KMS */
export function encryptKMSYamlContent(
    content: string,
    kmsKeyId: string,
    options?: EncryptContentOptions
): Promise<ContentResult>;

/** Decrypt YAML content string using AWS KMS */
export function decryptKMSYamlContent(
    content: string,
    kmsKeyId: string,
    options?: DecryptContentOptions
): Promise<ContentResult>;

// ═══════════════════════════════════════════════════════════════════════════
// YAML UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/** Check if js-yaml is installed (for complex YAML support) */
export function isJsYamlAvailable(): boolean;

/** Parse YAML content to object (uses js-yaml if available, falls back to simple parser) */
export function parseYaml(content: string): Record<string, unknown>;

/** Serialize object to YAML string (uses js-yaml if available) */
export function serializeYaml(obj: Record<string, unknown>): string;

// ═══════════════════════════════════════════════════════════════════════════
// OPTIONS & DEFAULTS
// ═══════════════════════════════════════════════════════════════════════════

export const RESERVED_KEYS: string[];
export const DEFAULT_AWS_OPTIONS: AwsOptions;
export const DEFAULT_ATTESTATION_OPTIONS: AttestationOptions;
export const DEFAULT_COMMON_OPTIONS: CommonOptions;
export const DEFAULT_ENCRYPT_OPTIONS: EncryptOptions;
export const DEFAULT_DECRYPT_OPTIONS: DecryptOptions;
export const DEFAULT_PATH_SELECTION_OPTIONS: PathSelectionOptions;
export const DEFAULT_CONTENT_OPTIONS: ContentOptions;
export const DEFAULT_KEYSTORE_OPTIONS: KeystoreOptions;

export function validateKmsKeyId(kmsKeyId: string): void;
export function validateAwsOptions(aws: AwsOptions): void;
export function validateAttestationOptions(attestation: AttestationOptions): void;
export function validatePathSelectionOptions(options: PathSelectionOptions): void;
export function validateCommonOptions(options: CommonOptions): void;

export function buildCommonOptions(options?: CommonOptions): CommonOptions;
export function buildEncryptOptions(options?: EncryptOptions): EncryptOptions;
export function buildDecryptOptions(options?: DecryptOptions): DecryptOptions;
export function buildPathSelectionOptions(options?: PathSelectionOptions): PathSelectionOptions;
export function buildContentOptions(options?: ContentOptions): ContentOptions;
export function buildKeystoreOptions(options?: KeystoreOptions): KeystoreOptions;
export function buildAwsSdkOptions(options?: { aws?: AwsOptions }): Record<string, unknown>;

export function deepMerge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T;
export function createLogger(baseLogger: Logger | null, logLevel?: LogLevel): Logger;

// ═══════════════════════════════════════════════════════════════════════════
// ERROR CLASSES
// ═══════════════════════════════════════════════════════════════════════════

export class SecretKeyStoreError extends Error {
    code: string;
    cause?: Error;
    timestamp: Date;
    constructor(message: string, code: string, cause?: Error);
    toJSON(): Record<string, unknown>;
}

export class KmsError extends SecretKeyStoreError {
    kmsKeyId: string;
    awsRequestId?: string;
    constructor(message: string, code: string, kmsKeyId: string, cause?: Error);
}

export class AttestationError extends SecretKeyStoreError {
    constructor(message: string, code: string, cause?: Error);
}

export class ContentError extends SecretKeyStoreError {
    format?: string;
    constructor(message: string, code: string, format?: string, cause?: Error);
}

export class PathError extends SecretKeyStoreError {
    path?: string;
    constructor(message: string, code: string, path?: string, cause?: Error);
}

export class EncryptionError extends SecretKeyStoreError {
    key?: string;
    constructor(message: string, code: string, key?: string, cause?: Error);
}

export class DecryptionError extends SecretKeyStoreError {
    key?: string;
    constructor(message: string, code: string, key?: string, cause?: Error);
}

export class KeystoreError extends SecretKeyStoreError {
    constructor(message: string, code: string, cause?: Error);
}

export class ValidationError extends SecretKeyStoreError {
    field?: string;
    constructor(message: string, code: string, field?: string, cause?: Error);
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR CODES
// ═══════════════════════════════════════════════════════════════════════════

export const KMS_ERROR_CODES: {
    KEY_NOT_FOUND: 'KMS_KEY_NOT_FOUND';
    KEY_DISABLED: 'KMS_KEY_DISABLED';
    ACCESS_DENIED: 'KMS_ACCESS_DENIED';
    INVALID_CIPHERTEXT: 'KMS_INVALID_CIPHERTEXT';
    THROTTLED: 'KMS_THROTTLED';
    ENCRYPT_FAILED: 'KMS_ENCRYPT_FAILED';
    DECRYPT_FAILED: 'KMS_DECRYPT_FAILED';
    CONNECTION_ERROR: 'KMS_CONNECTION_ERROR';
};

export const ATTESTATION_ERROR_CODES: {
    DOCUMENT_MISSING: 'ATTESTATION_DOCUMENT_MISSING';
    DOCUMENT_INVALID: 'ATTESTATION_DOCUMENT_INVALID';
    DOCUMENT_EXPIRED: 'ATTESTATION_DOCUMENT_EXPIRED';
    GETTER_FAILED: 'ATTESTATION_GETTER_FAILED';
    NOT_AVAILABLE: 'ATTESTATION_NOT_AVAILABLE';
    RETRY_FAILED: 'ATTESTATION_RETRY_FAILED';
};

export const CONTENT_ERROR_CODES: {
    PARSE_FAILED: 'CONTENT_PARSE_FAILED';
    INVALID_FORMAT: 'CONTENT_INVALID_FORMAT';
    EMPTY_CONTENT: 'CONTENT_EMPTY';
    SERIALIZATION_FAILED: 'CONTENT_SERIALIZATION_FAILED';
};

export const PATH_ERROR_CODES: {
    NOT_FOUND: 'PATH_NOT_FOUND';
    INVALID_PATTERN: 'PATH_INVALID_PATTERN';
    ACCESS_DENIED: 'PATH_ACCESS_DENIED';
};

export const ENCRYPTION_ERROR_CODES: {
    FAILED: 'ENCRYPTION_FAILED';
    INVALID_VALUE: 'ENCRYPTION_INVALID_VALUE';
    ALREADY_ENCRYPTED: 'ENCRYPTION_ALREADY_ENCRYPTED';
};

export const DECRYPTION_ERROR_CODES: {
    FAILED: 'DECRYPTION_FAILED';
    INVALID_CIPHERTEXT: 'DECRYPTION_INVALID_CIPHERTEXT';
    NOT_ENCRYPTED: 'DECRYPTION_NOT_ENCRYPTED';
};

export const KEYSTORE_ERROR_CODES: {
    NOT_INITIALIZED: 'KEYSTORE_NOT_INITIALIZED';
    ALREADY_INITIALIZED: 'KEYSTORE_ALREADY_INITIALIZED';
    DESTROYED: 'KEYSTORE_DESTROYED';
    SECRET_NOT_FOUND: 'SECRET_NOT_FOUND';
    SECRET_EXPIRED: 'SECRET_EXPIRED';
    ACCESS_LIMIT_EXCEEDED: 'SECRET_ACCESS_LIMIT_EXCEEDED';
    INITIALIZATION_FAILED: 'KEYSTORE_INITIALIZATION_FAILED';
    REFRESH_FAILED: 'KEYSTORE_REFRESH_FAILED';
};

export const VALIDATION_ERROR_CODES: {
    REQUIRED_FIELD: 'VALIDATION_REQUIRED_FIELD';
    INVALID_TYPE: 'VALIDATION_INVALID_TYPE';
    INVALID_VALUE: 'VALIDATION_INVALID_VALUE';
    INVALID_OPTIONS: 'VALIDATION_INVALID_OPTIONS';
    KMS_KEY_REQUIRED: 'VALIDATION_KMS_KEY_REQUIRED';
    PROCESS_ENV_LEAK: 'VALIDATION_PROCESS_ENV_LEAK';
};

export function isRecoverableError(error: Error): boolean;
export function createKmsErrorFromAws(awsError: Error, kmsKeyId: string, operation?: string): KmsError;

// ═══════════════════════════════════════════════════════════════════════════
// RUNTIME KEYSTORE
// ═══════════════════════════════════════════════════════════════════════════

export type KeystoreSourceType = 'env' | 'json' | 'yaml' | 'object' | 'values';

export interface KeystoreSource {
    type: KeystoreSourceType;
    content?: string;
    object?: Record<string, unknown>;
    values?: Record<string, string>;
}

export interface KeystoreMetadata {
    initialized: boolean;
    destroyed: boolean;
    secretCount: number;
    sourceType: KeystoreSourceType;
    hasTTL: boolean;
    ttl: number | null;
    autoRefresh: boolean;
    inMemoryEncryption: boolean;
}

export interface AccessStats {
    createdAt: Date;
    lastAccessedAt: Date | null;
    accessCount: number;
    expiresAt: Date | null;
    isExpired: boolean;
}

export class SecretKeyStore {
    constructor(source: KeystoreSource, kmsKeyId: string, options?: KeystoreOptions);
    initialize(): Promise<void>;
    get(key: string): string | undefined;
    getSection(prefix: string): Record<string, string> | undefined;
    getAll(): Record<string, string>;
    has(key: string): boolean;
    keys(): string[];
    isInitialized(): boolean;
    getMetadata(): KeystoreMetadata;
    getAccessStats(key: string): AccessStats | null;
    refresh(): Promise<void>;
    clear(): void;
    clearKey(key: string): void;
    destroy(): void;
}

export function createSecretKeyStore(
    source: KeystoreSource,
    kmsKeyId: string,
    options?: KeystoreOptions
): Promise<SecretKeyStore>;
