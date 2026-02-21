/**
 * @faizahmedfarooqui/secret-keystore - Attestation Manager
 *
 * Manages the attestation document lifecycle:
 * - Generates ephemeral RSA key pairs
 * - Fetches attestation documents from Nitro/Anjuna
 * - Caches attestation materials
 * - Handles 5-minute age limit by refreshing on demand
 * - Provides CMS unwrapping for KMS CiphertextForRecipient
 */

const { DecryptCommand } = require('@aws-sdk/client-kms');
const { generateEphemeralKeyPair, prepareAttestationParams } = require('./key-pair');
const { fetchAttestationDocument, DEFAULT_ATTESTATION_ENDPOINT } = require('./attestation-client');
const { unwrapCms } = require('./cms-unwrap');

// ═══════════════════════════════════════════════════════════════════════════
// ATTESTATION MANAGER CLASS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * AttestationManager handles the full attestation lifecycle
 */
class AttestationManager {
    constructor(options = {}) {
        this.endpoint = options.endpoint || DEFAULT_ATTESTATION_ENDPOINT;
        this.timeout = options.timeout || 10000;
        this.userData = options.userData || '';
        this.logger = options.logger || null;

        // Cached materials
        this.cachedKeyPair = null;
        this.cachedDocument = null;
        this.cachedTimestamp = null;

        // Initialization state
        this.initialized = false;
        this.initError = null;

        // Mutex for concurrent initialization
        this.initPromise = null;
    }

    /**
     * Initialize attestation (generate key pair, fetch document)
     * @returns {Promise<void>}
     */
    async initialize() {
        // Prevent concurrent initialization
        if (this.initPromise) {
            return this.initPromise;
        }

        this.initPromise = this._doInitialize();
        try {
            await this.initPromise;
        } finally {
            this.initPromise = null;
        }
    }

    /**
     * Internal initialization logic
     * @private
     */
    async _doInitialize() {
        this._log('debug', 'Initializing attestation...');
        this.initialized = false;
        this.initError = null;

        try {
            // 1. Generate ephemeral RSA-4096 key pair
            this._log('debug', 'Generating ephemeral RSA-4096 key pair...');
            this.cachedKeyPair = generateEphemeralKeyPair();

            // 2. Prepare attestation request parameters
            const params = prepareAttestationParams(
                this.cachedKeyPair.publicKey,
                this.userData
            );

            // 3. Fetch attestation document
            this._log('debug', `Fetching attestation document from ${this.endpoint}...`);
            const response = await fetchAttestationDocument(params, {
                endpoint: this.endpoint,
                timeout: this.timeout
            });

            // 4. Cache the document
            this.cachedDocument = response.attestationDocument;
            this.cachedTimestamp = Date.now();
            this.initialized = true;

            this._log('info', 'Attestation initialized successfully');
        } catch (error) {
            this.initError = error.message;
            this.initialized = false;
            this._log('error', `Attestation initialization failed: ${error.message}`);
            throw error;
        }
    }

    /**
     * Reinitialize attestation (for 5-minute refresh)
     * @returns {Promise<void>}
     */
    async reinitialize() {
        this._log('warn', 'Reinitializing attestation (5-minute refresh)...');
        // Clear current cache
        this.cachedKeyPair = null;
        this.cachedDocument = null;
        this.cachedTimestamp = null;
        this.initialized = false;

        // Re-initialize
        await this.initialize();
    }

    /**
     * Check if attestation is initialized and usable
     * @returns {boolean}
     */
    isInitialized() {
        return this.initialized && !!this.cachedDocument && !!this.cachedKeyPair;
    }

    /**
     * Get cached attestation materials
     * @returns {{ document: string, privateKey: string, publicKey: string } | null}
     */
    getCachedMaterials() {
        if (!this.isInitialized()) {
            return null;
        }

        return {
            document: this.cachedDocument,
            privateKey: this.cachedKeyPair.privateKey,
            publicKey: this.cachedKeyPair.publicKey
        };
    }

    /**
     * Get the age of the cached attestation document in milliseconds
     * @returns {number | null}
     */
    getDocumentAge() {
        if (!this.cachedTimestamp) {
            return null;
        }
        return Date.now() - this.cachedTimestamp;
    }

    /**
     * Perform attested decrypt with KMS
     *
     * This method:
     * 1. Ensures attestation is initialized
     * 2. Calls KMS Decrypt with Recipient parameter
     * 3. Handles CiphertextForRecipient by unwrapping with PKIjs
     * 4. Retries on 5-minute age limit error
     *
     * @param {import('@aws-sdk/client-kms').KMSClient} kmsClient - KMS client
     * @param {Buffer} ciphertextBlob - The encrypted data
     * @param {string} kmsKeyId - The KMS key ID
     * @param {Object} [options] - Additional options
     * @param {string} [options.encryptionAlgorithm] - 'RSAES_OAEP_SHA_256' or 'SYMMETRIC_DEFAULT'
     * @param {Object} [options.encryptionContext] - KMS encryption context
     * @returns {Promise<Buffer>} - Decrypted plaintext
     */
    async decryptWithAttestation(kmsClient, ciphertextBlob, kmsKeyId, options = {}) {
        // Ensure initialized
        if (!this.isInitialized()) {
            await this.initialize();
        }

        const materials = this.getCachedMaterials();
        if (!materials) {
            throw new Error('Failed to get attestation materials after initialization');
        }

        try {
            return await this._performAttestedDecrypt(
                kmsClient,
                ciphertextBlob,
                kmsKeyId,
                materials,
                options
            );
        } catch (error) {
            // Check for 5-minute age limit error
            if (this._isAgeLimitError(error)) {
                this._log('warn', 'Attestation document expired (5-minute limit), refreshing...');

                // Reinitialize to get fresh materials
                await this.reinitialize();

                const freshMaterials = this.getCachedMaterials();
                if (!freshMaterials) {
                    throw new Error('Failed to get fresh attestation materials');
                }

                // Retry once with fresh materials
                return await this._performAttestedDecrypt(
                    kmsClient,
                    ciphertextBlob,
                    kmsKeyId,
                    freshMaterials,
                    options
                );
            }

            throw error;
        }
    }

    /**
     * Perform the actual attested decrypt
     * @private
     */
    async _performAttestedDecrypt(kmsClient, ciphertextBlob, kmsKeyId, materials, options) {
        const attestationBuffer = Buffer.from(materials.document, 'base64');

        // Build KMS Decrypt command with Recipient
        const command = new DecryptCommand({
            KeyId: kmsKeyId,
            CiphertextBlob: ciphertextBlob,
            EncryptionAlgorithm: options.encryptionAlgorithm,
            EncryptionContext: options.encryptionContext,
            Recipient: {
                KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                AttestationDocument: attestationBuffer
            }
        });

        this._log('debug', 'Sending KMS Decrypt with Recipient...');
        const response = await kmsClient.send(command);

        // With Recipient, KMS returns CiphertextForRecipient, NOT Plaintext
        if (!response.CiphertextForRecipient) {
            throw new Error('KMS did not return CiphertextForRecipient - check key policy and Recipient support');
        }

        const ciphertextForRecipient = Buffer.from(response.CiphertextForRecipient);
        this._log('debug', `Received CiphertextForRecipient (${ciphertextForRecipient.length} bytes)`);

        // Unwrap CMS EnvelopedData using our ephemeral private key
        this._log('debug', 'Unwrapping CMS EnvelopedData...');
        const plaintext = await unwrapCms(ciphertextForRecipient, materials.privateKey);
        this._log('debug', `Decrypted plaintext (${plaintext.length} bytes)`);

        return plaintext;
    }

    /**
     * Check if an error is a 5-minute age limit error
     * @private
     */
    _isAgeLimitError(error) {
        const message = error.message || '';
        return (
            message.includes('exceeded the five-minute age limit') ||
            message.includes('exceeded the five minute age limit') ||
            message.includes('age limit') ||
            message.includes('cannot parse the attestation document') ||
            message.includes('cannot parse attestation document')
        );
    }

    /**
     * Log a message
     * @private
     */
    _log(level, message) {
        if (this.logger && typeof this.logger[level] === 'function') {
            this.logger[level](`[AttestationManager] ${message}`);
        }
    }

    /**
     * Get initialization status
     * @returns {Object}
     */
    getStatus() {
        return {
            initialized: this.initialized,
            hasError: !!this.initError,
            error: this.initError,
            hasDocument: !!this.cachedDocument,
            hasKeyPair: !!this.cachedKeyPair,
            documentAge: this.getDocumentAge(),
            endpoint: this.endpoint
        };
    }

    /**
     * Destroy the manager and clear all cached materials
     */
    destroy() {
        this.cachedKeyPair = null;
        this.cachedDocument = null;
        this.cachedTimestamp = null;
        this.initialized = false;
        this.initError = null;
        this._log('debug', 'Attestation manager destroyed');
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create and initialize an AttestationManager
 *
 * @param {Object} [options] - Options
 * @param {string} [options.endpoint] - Attestation endpoint URL
 * @param {number} [options.timeout] - Request timeout in ms
 * @param {string} [options.userData] - User data to include in attestation
 * @param {Object} [options.logger] - Logger instance
 * @param {boolean} [options.autoInitialize=true] - Initialize on creation
 * @returns {Promise<AttestationManager>}
 */
async function createAttestationManager(options = {}) {
    const manager = new AttestationManager(options);

    if (options.autoInitialize !== false) {
        await manager.initialize();
    }

    return manager;
}

module.exports = {
    AttestationManager,
    createAttestationManager
};

