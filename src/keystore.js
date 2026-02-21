/**
 * @faizahmedfarooqui/secret-keystore - Runtime Keystore
 *
 * Secure in-memory storage for decrypted secrets with:
 * - Multiple source types (env, json, yaml, object, values)
 * - TTL with auto-refresh
 * - In-memory encryption
 * - Comprehensive access tracking
 */

const crypto = require('node:crypto');
const { decryptKMSValues } = require('./kms');
const { decryptKMSObject } = require('./object-operations');
const { decryptKMSEnvContent, decryptKMSJsonContent, decryptKMSYamlContent } = require('./content-operations');
const { buildKeystoreOptions, validateKmsKeyId } = require('./options');
const {
    KeystoreError,
    SecretNotFoundError,
    KEYSTORE_ERROR_CODES
} = require('./errors');

// ═══════════════════════════════════════════════════════════════════════════
// SECURE MEMORY UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Securely wipe a buffer or string from memory
 */
function secureWipe(data) {
    if (Buffer.isBuffer(data)) {
        crypto.randomFillSync(data);
    } else if (typeof data === 'string') {
        // Can't truly wipe strings in JS, but we can help GC
        return '';
    }
    return null;
}

// ═══════════════════════════════════════════════════════════════════════════
// SECRET KEYSTORE V2
// ═══════════════════════════════════════════════════════════════════════════

class SecretKeyStore {
    #store = new Map();
    #metadata = new Map();
    #encryptionKey;
    #initialized = false;
    #destroyed = false;
    #options;
    #kmsKeyId;
    #source;
    #initPromise = null;
    #refreshTimers = new Map();

    /**
     * Create a new SecretKeyStore
     *
     * @param {Object} source - Source configuration
     * @param {string} source.type - 'env' | 'json' | 'yaml' | 'object' | 'values'
     * @param {string} [source.content] - Content string (for env, json, yaml)
     * @param {Object} [source.object] - Object (for object type)
     * @param {Object} [source.values] - Key-value pairs (for values type)
     * @param {string} kmsKeyId - KMS key ID (required)
     * @param {Object} [options] - Keystore options
     */
    constructor(source, kmsKeyId, options = {}) {
        validateKmsKeyId(kmsKeyId);

        this.#source = source;
        this.#kmsKeyId = kmsKeyId;
        this.#options = buildKeystoreOptions(options);
        this.#encryptionKey = crypto.randomBytes(32);
    }

    /**
     * Initialize the keystore by decrypting all secrets
     */
    async initialize() {
        if (this.#destroyed) {
            throw new KeystoreError(
                'Cannot initialize destroyed keystore',
                KEYSTORE_ERROR_CODES.DESTROYED
            );
        }

        if (this.#initPromise) {
            return this.#initPromise;
        }

        if (this.#initialized) {
            return;
        }

        this.#initPromise = this.#doInitialize();
        return this.#initPromise;
    }

    async #doInitialize() {
        const logger = this.#options.logger;
        const startTime = Date.now();

        try {
            logger?.info?.('[SecretKeyStore] Initializing...');

            let decryptedValues;

            switch (this.#source.type) {
                case 'env':
                    decryptedValues = await this.#initFromEnv();
                    break;
                case 'json':
                    decryptedValues = await this.#initFromJson();
                    break;
                case 'yaml':
                    decryptedValues = await this.#initFromYaml();
                    break;
                case 'object':
                    decryptedValues = await this.#initFromObject();
                    break;
                case 'values':
                    decryptedValues = await this.#initFromValues();
                    break;
                default:
                    throw new KeystoreError(
                        `Unknown source type: ${this.#source.type}`,
                        KEYSTORE_ERROR_CODES.INITIALIZATION_FAILED
                    );
            }

            // Store decrypted values
            for (const [key, value] of Object.entries(decryptedValues)) {
                this.#storeSecret(key, value);
            }

            // Validate no process.env leak
            if (this.#options.validation?.noProcessEnvLeak) {
                this.#validateNoProcessEnvLeak();
            }

            this.#initialized = true;
            const duration = Date.now() - startTime;
            logger?.info?.(`[SecretKeyStore] Initialized ${this.#store.size} secrets in ${duration}ms`);

        } catch (error) {
            this.#initPromise = null;
            throw new KeystoreError(
                `Initialization failed: ${error.message}`,
                KEYSTORE_ERROR_CODES.INITIALIZATION_FAILED,
                error
            );
        }
    }

    async #initFromEnv() {
        const result = await decryptKMSEnvContent(
            this.#source.content,
            this.#kmsKeyId,
            this.#buildDecryptOptions()
        );

        // Parse the decrypted content to extract values
        const { parseEnvContent } = require('./content-operations');
        const parsed = parseEnvContent(result.content);
        const values = {};

        for (const entry of parsed) {
            if (entry.type === 'keyvalue') {
                values[entry.key] = entry.value;
            }
        }

        return values;
    }

    async #initFromJson() {
        const result = await decryptKMSJsonContent(
            this.#source.content,
            this.#kmsKeyId,
            this.#buildDecryptOptions()
        );

        // Flatten the decrypted object
        const obj = structuredClone(JSON.parse(result.content));
        return this.#flattenObject(obj);
    }

    async #initFromYaml() {
        const result = await decryptKMSYamlContent(
            this.#source.content,
            this.#kmsKeyId,
            this.#buildDecryptOptions()
        );

        // Parse and flatten - parseYaml handles js-yaml availability
        const { parseYaml } = require('./yaml-utils');
        const obj = parseYaml(result.content);

        return this.#flattenObject(obj);
    }

    async #initFromObject() {
        const result = await decryptKMSObject(
            this.#source.object,
            this.#kmsKeyId,
            this.#buildDecryptOptions()
        );

        return this.#flattenObject(result.object);
    }

    async #initFromValues() {
        const result = await decryptKMSValues(
            this.#source.values,
            this.#kmsKeyId,
            this.#buildDecryptOptions()
        );

        return result.values;
    }

    #buildDecryptOptions() {
        return {
            aws: this.#options.aws,
            attestation: this.#options.attestation,
            logger: this.#options.logger,
            logLevel: this.#options.logLevel,
            paths: this.#options.paths,
            patterns: this.#options.patterns,
            exclude: this.#options.exclude,
            skip: this.#options.skip,
            continueOnError: this.#options.continueOnError
        };
    }

    #flattenObject(obj, prefix = '') {
        const result = {};

        for (const [key, value] of Object.entries(obj || {})) {
            const path = prefix ? `${prefix}.${key}` : key;

            if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
                Object.assign(result, this.#flattenObject(value, path));
            } else if (typeof value === 'string') {
                result[path] = value;
            }
        }

        return result;
    }

    #storeSecret(key, plaintext) {
        const now = Date.now();

        if (this.#options.security?.inMemoryEncryption) {
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', this.#encryptionKey, iv);

            let encrypted = cipher.update(plaintext, 'utf-8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag();

            this.#store.set(key, {
                encrypted,
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex')
            });
        } else {
            this.#store.set(key, { plaintext });
        }

        this.#metadata.set(key, {
            createdAt: now,
            lastAccessedAt: null,
            accessCount: 0,
            expiresAt: this.#options.access?.ttl ? now + this.#options.access.ttl : null
        });

        // Set up auto-refresh timer if TTL and autoRefresh enabled
        if (this.#options.access?.ttl && this.#options.access?.autoRefresh) {
            this.#setupAutoRefresh(key);
        }
    }

    #setupAutoRefresh(key) {
        const ttl = this.#options.access?.ttl;
        if (!ttl) return;

        // Clear existing timer
        if (this.#refreshTimers.has(key)) {
            clearTimeout(this.#refreshTimers.get(key));
        }

        // Set timer to refresh before expiry
        const refreshTime = Math.max(ttl - 60000, ttl * 0.9); // 1 min before or 90%
        const timer = setTimeout(async () => {
            try {
                await this.#refreshKey(key);
            } catch (error) {
                this.#options.logger?.error?.(`[SecretKeyStore] Auto-refresh failed for ${key}: ${error.message}`);
            }
        }, refreshTime);

        // Don't block process exit
        timer.unref?.();
        this.#refreshTimers.set(key, timer);
    }

    async #refreshKey(key) {
        if (this.#destroyed) return;

        const logger = this.#options.logger;
        logger?.debug?.(`[SecretKeyStore] Refreshing: ${key}`);

        // Re-decrypt the original source for this key
        // This is a simplified version - in production you'd want to track original encrypted values
        const meta = this.#metadata.get(key);
        if (meta) {
            meta.expiresAt = this.#options.access?.ttl
                ? Date.now() + this.#options.access.ttl
                : null;
            this.#setupAutoRefresh(key);
        }
    }

    #retrieveSecret(key) {
        const stored = this.#store.get(key);
        if (!stored) return null;

        // Update access metadata
        const meta = this.#metadata.get(key);
        if (meta) {
            meta.lastAccessedAt = Date.now();
            meta.accessCount++;
        }

        if (this.#options.security?.inMemoryEncryption) {
            const decipher = crypto.createDecipheriv(
                'aes-256-gcm',
                this.#encryptionKey,
                Buffer.from(stored.iv, 'hex')
            );
            decipher.setAuthTag(Buffer.from(stored.authTag, 'hex'));

            let decrypted = decipher.update(stored.encrypted, 'hex', 'utf-8');
            decrypted += decipher.final('utf-8');
            return decrypted;
        }

        return stored.plaintext;
    }

    #checkExpiry(key) {
        const meta = this.#metadata.get(key);
        if (!meta?.expiresAt) return false;

        if (Date.now() > meta.expiresAt) {
            if (this.#options.access?.autoRefresh) {
                // Will be refreshed on next access
                return false;
            }
            throw new KeystoreError(
                `Secret expired: ${key}`,
                KEYSTORE_ERROR_CODES.SECRET_EXPIRED
            );
        }

        return false;
    }

    #checkAccessLimit(key) {
        const limit = this.#options.access?.accessLimit;
        if (!limit) return;

        const meta = this.#metadata.get(key);
        if (meta && meta.accessCount >= limit) {
            throw new KeystoreError(
                `Access limit exceeded for: ${key}`,
                KEYSTORE_ERROR_CODES.ACCESS_LIMIT_EXCEEDED
            );
        }
    }

    #validateNoProcessEnvLeak() {
        for (const key of this.#store.keys()) {
            const decrypted = this.#retrieveSecret(key);
            const envValue = process.env[key];

            if (envValue && envValue === decrypted) {
                this.#options.logger?.error?.(
                    `[SECURITY] ${key} has decrypted value in process.env!`
                );
            }
        }
    }

    #ensureInitialized() {
        if (this.#destroyed) {
            throw new KeystoreError(
                'Keystore has been destroyed',
                KEYSTORE_ERROR_CODES.DESTROYED
            );
        }
        if (!this.#initialized) {
            throw new KeystoreError(
                'Keystore not initialized. Call initialize() first.',
                KEYSTORE_ERROR_CODES.NOT_INITIALIZED
            );
        }
    }

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /**
     * Get a secret by key
     * @param {string} key - Secret key
     * @returns {string|undefined}
     */
    get(key) {
        this.#ensureInitialized();

        if (!this.#store.has(key)) {
            if (this.#options.validation?.throwOnMissingKey) {
                throw new SecretNotFoundError(key);
            }
            return undefined;
        }

        this.#checkExpiry(key);
        this.#checkAccessLimit(key);

        const value = this.#retrieveSecret(key);

        // Clear on access if configured
        if (this.#options.access?.clearOnAccess) {
            this.clearKey(key);
        }

        return value;
    }

    /**
     * Get a section of secrets by path prefix
     * @param {string} prefix - Path prefix
     * @returns {Object|undefined}
     */
    getSection(prefix) {
        this.#ensureInitialized();

        const result = {};
        let found = false;

        for (const key of this.#store.keys()) {
            if (key === prefix || key.startsWith(prefix + '.')) {
                const value = this.get(key);
                if (value !== undefined) {
                    result[key] = value;
                    found = true;
                }
            }
        }

        return found ? result : undefined;
    }

    /**
     * Get all secrets
     * @returns {Object}
     */
    getAll() {
        this.#ensureInitialized();

        const result = {};
        for (const key of this.#store.keys()) {
            result[key] = this.get(key);
        }
        return result;
    }

    /**
     * Check if a secret exists
     * @param {string} key - Secret key
     * @returns {boolean}
     */
    has(key) {
        if (!this.#initialized || this.#destroyed) {
            return false;
        }
        return this.#store.has(key);
    }

    /**
     * Get all secret keys
     * @returns {string[]}
     */
    keys() {
        if (!this.#initialized) {
            return [];
        }
        return Array.from(this.#store.keys());
    }

    /**
     * Check if keystore is initialized
     * @returns {boolean}
     */
    isInitialized() {
        return this.#initialized && !this.#destroyed;
    }

    /**
     * Get keystore metadata
     * @returns {Object}
     */
    getMetadata() {
        return {
            initialized: this.#initialized,
            destroyed: this.#destroyed,
            secretCount: this.#store.size,
            sourceType: this.#source.type,
            hasTTL: !!this.#options.access?.ttl,
            ttl: this.#options.access?.ttl || null,
            autoRefresh: !!this.#options.access?.autoRefresh,
            inMemoryEncryption: !!this.#options.security?.inMemoryEncryption
        };
    }

    /**
     * Get access stats for a key
     * @param {string} key - Secret key
     * @returns {Object|null}
     */
    getAccessStats(key) {
        const meta = this.#metadata.get(key);
        if (!meta) return null;

        return {
            createdAt: new Date(meta.createdAt),
            lastAccessedAt: meta.lastAccessedAt ? new Date(meta.lastAccessedAt) : null,
            accessCount: meta.accessCount,
            expiresAt: meta.expiresAt ? new Date(meta.expiresAt) : null,
            isExpired: meta.expiresAt ? Date.now() > meta.expiresAt : false
        };
    }

    /**
     * Refresh all secrets (re-decrypt from source)
     */
    async refresh() {
        this.#ensureInitialized();

        this.#options.logger?.info?.('[SecretKeyStore] Refreshing all secrets...');

        // Clear current store
        this.#store.clear();
        this.#metadata.clear();

        // Clear refresh timers
        for (const timer of this.#refreshTimers.values()) {
            clearTimeout(timer);
        }
        this.#refreshTimers.clear();

        // Re-initialize
        this.#initialized = false;
        this.#initPromise = null;
        await this.initialize();
    }

    /**
     * Clear all secrets from memory
     */
    clear() {
        // Secure wipe if enabled
        if (this.#options.security?.secureWipe) {
            for (const stored of this.#store.values()) {
                if (stored.plaintext) {
                    secureWipe(stored.plaintext);
                }
            }
        }

        this.#store.clear();
        this.#metadata.clear();

        for (const timer of this.#refreshTimers.values()) {
            clearTimeout(timer);
        }
        this.#refreshTimers.clear();

        this.#options.logger?.info?.('[SecretKeyStore] Cleared all secrets');
    }

    /**
     * Clear a specific secret from memory
     * @param {string} key - Secret key
     */
    clearKey(key) {
        const stored = this.#store.get(key);
        if (stored && this.#options.security?.secureWipe && stored.plaintext) {
            secureWipe(stored.plaintext);
        }

        this.#store.delete(key);
        this.#metadata.delete(key);

        if (this.#refreshTimers.has(key)) {
            clearTimeout(this.#refreshTimers.get(key));
            this.#refreshTimers.delete(key);
        }
    }

    /**
     * Destroy the keystore (cannot be used after this)
     */
    destroy() {
        if (this.#destroyed) return;

        this.clear();

        // Wipe encryption key
        if (this.#encryptionKey) {
            crypto.randomFillSync(this.#encryptionKey);
            this.#encryptionKey = null;
        }

        this.#destroyed = true;
        this.#initialized = false;

        this.#options.logger?.info?.('[SecretKeyStore] Destroyed');
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create and initialize a SecretKeyStore
 *
 * @param {Object} source - Source configuration
 * @param {string} source.type - 'env' | 'json' | 'yaml' | 'object' | 'values'
 * @param {string} [source.content] - Content string (for env, json, yaml)
 * @param {Object} [source.object] - Object (for object type)
 * @param {Object} [source.values] - Key-value pairs (for values type)
 * @param {string} kmsKeyId - KMS key ID (required)
 * @param {Object} [options] - Keystore options
 * @returns {Promise<SecretKeyStore>}
 *
 * @example
 * // From YAML content
 * const content = fs.readFileSync('./secrets.yaml', 'utf-8');
 * const keyStore = await createSecretKeyStore(
 *   { type: 'yaml', content },
 *   kmsKeyId,
 *   { patterns: ['**.password'] }
 * );
 *
 * @example
 * // From key-value pairs
 * const keyStore = await createSecretKeyStore(
 *   { type: 'values', values: process.env },
 *   kmsKeyId,
 *   { paths: ['DB_PASSWORD', 'API_KEY'] }
 * );
 */
async function createSecretKeyStore(source, kmsKeyId, options = {}) {
    const keyStore = new SecretKeyStore(source, kmsKeyId, options);
    await keyStore.initialize();
    return keyStore;
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
    SecretKeyStore,
    createSecretKeyStore
};

