/**
 * @faizahmedfarooqui/secret-keystore - Runtime config loader
 *
 * Zero-config loader that discovers and cascades .env files, decrypts their
 * KMS-encrypted (ENC[...]) values, and loads everything into an in-memory
 * SecretKeyStore.
 *
 * SECURITY: decrypted values live ONLY in the returned SecretKeyStore's memory.
 * They are never written to disk and — unless populateProcessEnv is explicitly
 * enabled — never placed in process.env. This is deliberate: putting secrets in
 * process.env widens the RCE blast radius (an attacker with code execution can
 * dump them with `env`).
 */

const fs = require('node:fs');
const path = require('node:path');

const { parseEnvContent } = require('./content-operations');
const { createSecretKeyStore } = require('./keystore');
const { validateKmsKeyId } = require('./options');

/**
 * Resolve the ordered list of .env files to load.
 *
 * Cascade order (later overrides earlier):
 *   .env  →  .env.local  →  .env.<NODE_ENV>  →  .env.<NODE_ENV>.local
 *
 * If an explicit `path` is given, only those file(s) are used (in order).
 *
 * @param {Object} options
 * @param {string} [options.cwd=process.cwd()] - Base directory
 * @param {string|string[]} [options.path] - Explicit file path(s)
 * @param {string} [options.nodeEnv] - Environment name for the cascade
 * @returns {string[]} Absolute paths of files that exist, in load order
 */
function resolveEnvFiles({ cwd = process.cwd(), path: explicitPath, nodeEnv } = {}) {
    if (explicitPath) {
        const list = Array.isArray(explicitPath) ? explicitPath : [explicitPath];
        return list.map(p => path.resolve(cwd, p)).filter(f => fs.existsSync(f));
    }

    const names = ['.env', '.env.local'];
    if (nodeEnv) {
        names.push(`.env.${nodeEnv}`, `.env.${nodeEnv}.local`);
    }

    return names.map(n => path.resolve(cwd, n)).filter(f => fs.existsSync(f));
}

/**
 * Merge .env files into a single key→value map (later files win).
 * Values may still be encrypted (ENC[...]) at this stage.
 *
 * @param {string[]} files - Absolute file paths, in load order
 * @returns {{ merged: Record<string, string>, used: string[] }}
 */
function mergeEnvFiles(files) {
    const merged = {};
    const used = [];

    for (const file of files) {
        if (!fs.existsSync(file)) continue;

        const content = fs.readFileSync(file, 'utf-8');
        for (const entry of parseEnvContent(content)) {
            if (entry.type === 'keyvalue') {
                merged[entry.key] = entry.value;
            }
        }
        used.push(file);
    }

    return { merged, used };
}

/**
 * Load and cascade .env files into an in-memory SecretKeyStore.
 *
 * @param {Object} options
 * @param {string} options.kmsKeyId - REQUIRED KMS Key ID (explicit; no env fallback)
 * @param {string} [options.cwd=process.cwd()] - Base directory for discovery
 * @param {string|string[]} [options.path] - Explicit file path(s) (skips cascade)
 * @param {string} [options.nodeEnv=process.env.NODE_ENV] - Environment for the cascade
 * @param {boolean} [options.populateProcessEnv=false] - Opt-in: also copy decrypted
 *   values into process.env (override). Discouraged — widens RCE blast radius.
 * @param {Object} [options.processEnv=process.env] - Target object for populateProcessEnv
 * @param {Object} [options.logger] - Logger instance
 * @returns {Promise<import('./keystore').SecretKeyStore>} Initialized in-memory store
 */
async function config(options = {}) {
    const {
        kmsKeyId,
        cwd = process.cwd(),
        path: explicitPath,
        nodeEnv = process.env.NODE_ENV,
        populateProcessEnv = false,
        processEnv = process.env,
        logger,
        ...keystoreOptions
    } = options;

    // Explicit-only Key ID: throws ValidationError if missing/invalid.
    validateKmsKeyId(kmsKeyId);

    const files = resolveEnvFiles({ cwd, path: explicitPath, nodeEnv });
    const { merged, used } = mergeEnvFiles(files);

    const names = used.map(f => path.basename(f)).join(', ') || '(none)';
    logger?.info?.(`[config] Loaded ${used.length} env file(s): ${names}`);

    const store = await createSecretKeyStore({ type: 'values', values: merged }, kmsKeyId, {
        ...keystoreOptions,
        logger
    });

    if (populateProcessEnv) {
        logger?.warn?.(
            '[config] populateProcessEnv=true: decrypted secrets are being copied into ' +
                'process.env (override). This widens the RCE blast radius (e.g. `env` dumps ' +
                'them). Prefer reading from the returned in-memory store.'
        );
        for (const [key, value] of Object.entries(store.getAll())) {
            processEnv[key] = value;
        }
    }

    return store;
}

module.exports = { config, resolveEnvFiles, mergeEnvFiles };
