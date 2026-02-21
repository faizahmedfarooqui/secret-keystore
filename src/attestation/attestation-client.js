/**
 * @faizahmedfarooqui/secret-keystore - Attestation Client
 *
 * Fetches attestation documents from AWS Nitro Enclaves or Anjuna endpoints.
 * The attestation document contains the caller's public key and is signed
 * by the enclave's PCR values.
 */

const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');

// ═══════════════════════════════════════════════════════════════════════════
// ATTESTATION CLIENT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Default attestation endpoint (Anjuna)
 */
const DEFAULT_ATTESTATION_ENDPOINT = 'http://localhost:50123/api/v1/attestation/report';

/**
 * Fetch attestation document from Nitro/Anjuna endpoint
 *
 * @param {Object} params - Attestation request parameters
 * @param {string} params.publicKey - Base64url-encoded DER public key
 * @param {string} [params.userData] - Base64url-encoded user data
 * @param {string} [params.nonce] - Base64-encoded nonce
 * @param {Object} [options] - Client options
 * @param {string} [options.endpoint] - Attestation endpoint URL
 * @param {number} [options.timeout] - Request timeout in milliseconds (default: 10000)
 * @returns {Promise<{ attestationDocument: string }>} - Base64-encoded attestation document
 * @throws {Error} If the request fails
 */
async function fetchAttestationDocument(params, options = {}) {
    const endpoint = options.endpoint || DEFAULT_ATTESTATION_ENDPOINT;
    const timeout = options.timeout || 10000;

    // Build URL with query parameters
    const url = new URL(endpoint);
    if (params.publicKey) {
        url.searchParams.set('public_key', params.publicKey);
    }
    if (params.userData) {
        url.searchParams.set('user_data', params.userData);
    }
    if (params.nonce) {
        url.searchParams.set('nonce', params.nonce);
    }

    // Choose http or https based on protocol
    const client = url.protocol === 'https:' ? https : http;

    return new Promise((resolve, reject) => {
        const req = client.get(url.toString(), {
            timeout,
            headers: {
                'Accept': 'application/octet-stream'
            }
        }, (res) => {
            const chunks = [];

            res.on('data', (chunk) => chunks.push(chunk));

            res.on('end', () => {
                const buffer = Buffer.concat(chunks);

                if (res.statusCode !== 200) {
                    const errorMessage = buffer.toString('utf8');
                    reject(new Error(`Attestation endpoint returned ${res.statusCode}: ${errorMessage}`));
                    return;
                }

                // The response is binary attestation document, convert to base64
                const attestationDocument = buffer.toString('base64');

                resolve({ attestationDocument });
            });
        });

        req.on('error', (error) => {
            reject(new Error(`Attestation request failed: ${error.message}`));
        });

        req.on('timeout', () => {
            req.destroy();
            reject(new Error(`Attestation request timed out after ${timeout}ms`));
        });
    });
}

/**
 * Check if running inside a Nitro Enclave
 * Nitro Enclaves have /dev/nsm device
 *
 * @returns {boolean}
 */
function isNitroEnclave() {
    try {
        const fs = require('node:fs');
        return fs.existsSync('/dev/nsm');
    } catch {
        return false;
    }
}

/**
 * Check if attestation endpoint is reachable
 *
 * @param {string} [endpoint] - Attestation endpoint URL
 * @param {number} [timeout] - Request timeout in milliseconds
 * @returns {Promise<boolean>}
 */
async function isAttestationAvailable(endpoint = DEFAULT_ATTESTATION_ENDPOINT, timeout = 3000) {
    const url = new URL(endpoint);
    const client = url.protocol === 'https:' ? https : http;

    return new Promise((resolve) => {
        const req = client.get(url.toString(), { timeout }, (res) => {
            // Any response means the endpoint is available
            res.resume(); // Consume response data to free up memory
            resolve(true);
        });

        req.on('error', () => resolve(false));
        req.on('timeout', () => {
            req.destroy();
            resolve(false);
        });
    });
}

module.exports = {
    fetchAttestationDocument,
    isNitroEnclave,
    isAttestationAvailable,
    DEFAULT_ATTESTATION_ENDPOINT
};

