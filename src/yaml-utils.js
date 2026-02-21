/**
 * @faizahmedfarooqui/secret-keystore - YAML Utilities
 *
 * Handles YAML parsing/serialization with optional js-yaml dependency.
 * Falls back to simple parser for basic YAML when js-yaml is not installed.
 */

const { ContentError, CONTENT_ERROR_CODES } = require('./errors');

// ═══════════════════════════════════════════════════════════════════════════
// JS-YAML LOADER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Cached reference to js-yaml module (or null if not available)
 * @type {Object|null|undefined}
 */
let jsYamlModule;
let jsYamlChecked = false;

/**
 * Check if js-yaml is available
 * @returns {boolean}
 */
function isJsYamlAvailable() {
    if (!jsYamlChecked) {
        try {
            jsYamlModule = require('js-yaml');
        } catch {
            jsYamlModule = null;
        }
        jsYamlChecked = true;
    }
    return jsYamlModule !== null;
}

/**
 * Get the js-yaml module
 * @returns {Object|null}
 */
function getJsYaml() {
    if (!jsYamlChecked) {
        isJsYamlAvailable();
    }
    return jsYamlModule;
}

// ═══════════════════════════════════════════════════════════════════════════
// SIMPLE YAML PARSER (FALLBACK)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Features NOT supported by simple parser:
 * - Multi-line strings (| and >)
 * - Anchors and aliases (&, *)
 * - Complex nested arrays
 * - Type tags (!!str, !!int, etc.)
 * - Document separators (---, ...)
 */
const COMPLEX_YAML_PATTERNS = [
    /&\w+/,                // Anchors (&anchor)
    /\*\w+/,               // Aliases (*anchor)
    /<<:/,                 // Merge key
    /:\s*[|>]/m,           // Multi-line strings
    /^---/m,               // Document separator
    /^\.\.\./m,            // Document end
    /!!\w+/,               // Type tags
    /^\s*-\s*[^#\n]+:/m    // Nested objects in arrays
];

/**
 * Check if YAML content has complex features
 * @param {string} content
 * @returns {boolean}
 */
function hasComplexYamlFeatures(content) {
    return COMPLEX_YAML_PATTERNS.some(pattern => pattern.test(content));
}

/**
 * Simple YAML parser (handles basic key: value structures)
 * @param {string} content - YAML content
 * @returns {Object} Parsed object
 */
function parseYamlSimple(content) {
    const lines = content.split('\n');
    const result = {};
    const stack = [{ obj: result, indent: -1 }];

    for (const line of lines) {
        // Skip empty lines and comments
        if (!line.trim() || line.trim().startsWith('#')) continue;

        const match = line.match(/^(\s*)([^:]+):\s*(.*)$/);
        if (!match) continue;

        const indent = match[1].length;
        const key = match[2].trim();
        let value = match[3].trim();

        // Remove inline comments (not in quoted strings)
        if (!value.startsWith('"') && !value.startsWith("'")) {
            const commentIndex = value.indexOf('#');
            if (commentIndex > 0) {
                value = value.substring(0, commentIndex).trim();
            }
        }

        // Remove quotes
        if ((value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
        }

        // Pop stack until we find parent
        while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
            stack.pop();
        }

        const parent = stack[stack.length - 1].obj;

        if (value) {
            parent[key] = value;
        } else {
            parent[key] = {};
            stack.push({ obj: parent[key], indent });
        }
    }

    return result;
}

/**
 * Simple YAML serializer
 * @param {Object} obj - Object to serialize
 * @param {number} indent - Current indentation level
 * @returns {string} YAML string
 */
function serializeYamlSimple(obj, indent = 0) {
    let result = '';
    const spaces = '  '.repeat(indent);

    for (const [key, value] of Object.entries(obj)) {
        if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
            result += `${spaces}${key}:\n`;
            result += serializeYamlSimple(value, indent + 1);
        } else {
            const needsQuotes = typeof value === 'string' &&
                (value.includes(':') || value.includes('#') || value.includes(' ') || value.includes('\n'));
            const formattedValue = needsQuotes ? `"${value}"` : value;
            result += `${spaces}${key}: ${formattedValue}\n`;
        }
    }

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Parse YAML content to object
 *
 * Uses js-yaml if available, falls back to simple parser for basic YAML.
 * Throws an error if content has complex features and js-yaml is not installed.
 *
 * @param {string} content - YAML content string
 * @returns {Object} Parsed object
 * @throws {ContentError} If parsing fails or complex YAML without js-yaml
 */
function parseYaml(content) {
    const yaml = getJsYaml();

    if (yaml) {
        try {
            return yaml.load(content);
        } catch (error) {
            throw new ContentError(
                `Failed to parse YAML: ${error.message}`,
                CONTENT_ERROR_CODES.PARSE_FAILED,
                'yaml',
                error
            );
        }
    }

    // No js-yaml available - check for complex features
    if (hasComplexYamlFeatures(content)) {
        throw new ContentError(
            'YAML content has complex features (anchors, multi-line strings, etc.) that require js-yaml. ' +
            'Install js-yaml: npm install js-yaml',
            CONTENT_ERROR_CODES.PARSE_FAILED,
            'yaml'
        );
    }

    // Use simple parser for basic YAML
    try {
        return parseYamlSimple(content);
    } catch (error) {
        throw new ContentError(
            `Failed to parse YAML: ${error.message}. For complex YAML, install js-yaml: npm install js-yaml`,
            CONTENT_ERROR_CODES.PARSE_FAILED,
            'yaml',
            error
        );
    }
}

/**
 * Serialize object to YAML string
 *
 * Uses js-yaml if available, falls back to simple serializer.
 *
 * @param {Object} obj - Object to serialize
 * @returns {string} YAML string
 */
function serializeYaml(obj) {
    const yaml = getJsYaml();

    if (yaml) {
        try {
            return yaml.dump(obj, { lineWidth: -1 });
        } catch (error) {
            throw new ContentError(
                `Failed to serialize YAML: ${error.message}`,
                CONTENT_ERROR_CODES.SERIALIZATION_FAILED,
                'yaml',
                error
            );
        }
    }

    try {
        return serializeYamlSimple(obj);
    } catch (error) {
        throw new ContentError(
            `Failed to serialize YAML: ${error.message}`,
            CONTENT_ERROR_CODES.SERIALIZATION_FAILED,
            'yaml',
            error
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
    isJsYamlAvailable,
    getJsYaml,
    parseYaml,
    serializeYaml,
    parseYamlSimple,
    serializeYamlSimple,
    hasComplexYamlFeatures
};
