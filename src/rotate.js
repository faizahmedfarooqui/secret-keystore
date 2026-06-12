/**
 * @faizahmed/secret-keystore - Key Rotation
 *
 * Re-encrypt the already-encrypted values in a config file under a NEW KMS Key
 * ID, decrypting them with the OLD key first. Values that were plaintext stay
 * plaintext; only previously-encrypted entries are rotated.
 *
 * Decryption happens in memory; nothing plaintext is written to disk by this
 * helper (the caller decides what to do with the returned content string).
 */

const { encryptKMSEnvContent, decryptKMSEnvContent } = require('./content-operations');
const { encryptKMSObject, decryptKMSObject } = require('./object-operations');
const { getAllPaths, getByPath } = require('./path-matcher');
const { isAlreadyEncrypted } = require('./kms');
const { parseEnvContent } = require('./content-operations');
const { parseYaml, serializeYaml } = require('./yaml-utils');
const { ContentError, CONTENT_ERROR_CODES } = require('./errors');

/**
 * Find the keys/paths in a parsed config that are currently encrypted.
 * @private
 */
function findEncryptedEnvKeys(content) {
    return parseEnvContent(content)
        .filter(entry => entry.type === 'keyvalue' && isAlreadyEncrypted(entry.value))
        .map(entry => entry.key);
}

function findEncryptedObjectPaths(obj) {
    return getAllPaths(obj).filter(path => {
        const value = getByPath(obj, path);
        return typeof value === 'string' && isAlreadyEncrypted(value);
    });
}

/**
 * Rotate encrypted values from oldKmsKeyId to newKmsKeyId.
 *
 * @param {string} content - Raw file content
 * @param {'env'|'json'|'yaml'} format - Content format
 * @param {string} oldKmsKeyId - KMS Key ID the content is currently encrypted with
 * @param {string} newKmsKeyId - KMS Key ID to re-encrypt with
 * @param {Object} [options] - Forwarded encrypt/decrypt options (aws, logger, etc.)
 * @returns {Promise<{ content: string, rotated: string[] }>}
 */
async function rotateKMSContent(content, format, oldKmsKeyId, newKmsKeyId, options = {}) {
    if (format === 'env') {
        const encryptedKeys = findEncryptedEnvKeys(content);
        if (encryptedKeys.length === 0) {
            return { content, rotated: [] };
        }
        const decrypted = await decryptKMSEnvContent(content, oldKmsKeyId, options);
        const reEncrypted = await encryptKMSEnvContent(decrypted.content, newKmsKeyId, {
            ...options,
            paths: encryptedKeys
        });
        return { content: reEncrypted.content, rotated: reEncrypted.encrypted };
    }

    if (format === 'json' || format === 'yaml') {
        const obj = format === 'json' ? JSON.parse(content) : parseYaml(content);
        const encryptedPaths = findEncryptedObjectPaths(obj);
        if (encryptedPaths.length === 0) {
            return { content, rotated: [] };
        }

        const decrypted = await decryptKMSObject(obj, oldKmsKeyId, {
            ...options,
            paths: encryptedPaths
        });
        const reEncrypted = await encryptKMSObject(decrypted.object, newKmsKeyId, {
            ...options,
            paths: encryptedPaths
        });

        const output =
            format === 'json'
                ? JSON.stringify(reEncrypted.object, null, 2)
                : serializeYaml(reEncrypted.object);

        return { content: output, rotated: reEncrypted.encrypted };
    }

    throw new ContentError(
        `Unsupported format for rotation: ${format}`,
        CONTENT_ERROR_CODES.INVALID_FORMAT,
        format
    );
}

module.exports = { rotateKMSContent };
