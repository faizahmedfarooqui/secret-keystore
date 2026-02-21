/**
 * @faizahmedfarooqui/secret-keystore - Path Matching
 *
 * Utilities for matching paths in nested objects using ** patterns.
 * Only ** (any-depth) pattern is supported, not * (single-level).
 */

const { PathError, PATH_ERROR_CODES } = require('./errors');

// ═══════════════════════════════════════════════════════════════════════════
// PATH UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Get a value from an object by dot-notation path
 * @param {Object} obj - Object to get value from
 * @param {string} path - Dot-notation path (e.g., 'a.b.c')
 * @returns {*} Value at path or undefined
 */
function getByPath(obj, path) {
    if (!path) return obj;

    const parts = path.split('.');
    let current = obj;

    for (const part of parts) {
        if (current === null || current === undefined) {
            return undefined;
        }
        current = current[part];
    }

    return current;
}

/**
 * Set a value in an object by dot-notation path
 * @param {Object} obj - Object to set value in
 * @param {string} path - Dot-notation path (e.g., 'a.b.c')
 * @param {*} value - Value to set
 * @returns {Object} Modified object
 */
function setByPath(obj, path, value) {
    if (!path) return value;

    const parts = path.split('.');
    let current = obj;

    for (let i = 0; i < parts.length - 1; i++) {
        const part = parts[i];
        if (current[part] === undefined || current[part] === null) {
            current[part] = {};
        }
        current = current[part];
    }

    current[parts[parts.length - 1]] = value;
    return obj;
}

/**
 * Get all paths in an object (leaf nodes only)
 * @param {Object} obj - Object to traverse
 * @param {string} [prefix=''] - Current path prefix
 * @returns {string[]} Array of dot-notation paths
 */
function getAllPaths(obj, prefix = '') {
    const paths = [];

    if (obj === null || obj === undefined) {
        return paths;
    }

    if (typeof obj !== 'object' || Array.isArray(obj) || Buffer.isBuffer(obj)) {
        // Leaf node
        if (prefix) {
            paths.push(prefix);
        }
        return paths;
    }

    for (const [key, value] of Object.entries(obj)) {
        const currentPath = prefix ? `${prefix}.${key}` : key;

        if (value !== null && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value)) {
            // Recurse into nested object
            paths.push(...getAllPaths(value, currentPath));
        } else {
            // Leaf node
            paths.push(currentPath);
        }
    }

    return paths;
}

// ═══════════════════════════════════════════════════════════════════════════
// PATTERN MATCHING (** only)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convert a ** pattern to a regex
 * @param {string} pattern - Pattern with ** wildcards
 * @returns {RegExp}
 */
function patternToRegex(pattern) {
    // Escape special regex characters except **
    let escaped = pattern
        .replaceAll(/[.+^${}()|[\]\\]/g, String.raw`\$&`)  // Escape special chars
        .replaceAll('**', '{{DOUBLE_STAR}}');               // Temporarily replace **

    // Replace ** with regex pattern (match any depth)
    escaped = escaped.replaceAll('{{DOUBLE_STAR}}', '.*');

    // Anchor the pattern
    return new RegExp(`^${escaped}$`);
}

/**
 * Check if a path matches a ** pattern
 * @param {string} path - Dot-notation path
 * @param {string} pattern - Pattern with ** wildcards
 * @returns {boolean}
 */
function matchesPattern(path, pattern) {
    // Handle patterns that start with **
    if (pattern.startsWith('**.')) {
        // **.foo matches any path ending with .foo or just foo
        const suffix = pattern.slice(3);
        if (path === suffix) return true;
        if (path.endsWith('.' + suffix)) return true;
        return false;
    }

    // Handle patterns that end with **
    if (pattern.endsWith('.**')) {
        // foo.** matches foo and any path starting with foo.
        const prefix = pattern.slice(0, -3);
        if (path === prefix) return true;
        if (path.startsWith(prefix + '.')) return true;
        return false;
    }

    // Handle patterns with ** in the middle or complex patterns
    const regex = patternToRegex(pattern);
    return regex.test(path);
}

/**
 * Add explicit paths to selected set
 * @private
 */
function addExplicitPaths(selectedPaths, allPaths, paths) {
    if (!paths || !Array.isArray(paths)) return;

    for (const path of paths) {
        if (allPaths.includes(path)) {
            selectedPaths.add(path);
        }
    }
}

/**
 * Add pattern-matched paths to selected set
 * @private
 */
function addPatternMatches(selectedPaths, allPaths, patterns) {
    if (!patterns || !Array.isArray(patterns)) return;

    for (const pattern of patterns) {
        for (const path of allPaths) {
            if (matchesPattern(path, pattern)) {
                selectedPaths.add(path);
            }
        }
    }
}

/**
 * Filter paths using patterns and explicit paths
 * @param {string[]} allPaths - All available paths
 * @param {Object} options - Selection options
 * @param {string[]} [options.paths] - Explicit paths to include
 * @param {string[]} [options.patterns] - Patterns to match
 * @param {Object} [options.exclude] - Exclusions
 * @param {string[]} [options.exclude.paths] - Explicit paths to exclude
 * @param {string[]} [options.exclude.patterns] - Patterns to exclude
 * @returns {string[]} Matching paths
 */
function filterPaths(allPaths, options = {}) {
    const { paths, patterns, exclude } = options;

    // If no selection criteria, return all paths
    if (!paths && !patterns) {
        return excludePaths(allPaths, exclude);
    }

    const selectedPaths = new Set();

    addExplicitPaths(selectedPaths, allPaths, paths);
    addPatternMatches(selectedPaths, allPaths, patterns);

    return excludePaths(Array.from(selectedPaths), exclude);
}

/**
 * Exclude paths based on exclusion options
 * @param {string[]} paths - Paths to filter
 * @param {Object} [exclude] - Exclusion options
 * @returns {string[]}
 */
function excludePaths(paths, exclude) {
    if (!exclude) return paths;

    return paths.filter(path => {
        // Check explicit exclusions
        if (exclude.paths && exclude.paths.includes(path)) {
            return false;
        }

        // Check pattern exclusions
        if (exclude.patterns) {
            for (const pattern of exclude.patterns) {
                if (matchesPattern(path, pattern)) {
                    return false;
                }
            }
        }

        return true;
    });
}

/**
 * Validate that all explicit paths exist
 * @param {string[]} requestedPaths - Requested paths
 * @param {string[]} existingPaths - Paths that exist
 * @throws {PathError}
 */
function validatePathsExist(requestedPaths, existingPaths) {
    for (const path of requestedPaths) {
        if (!existingPaths.includes(path)) {
            throw new PathError(
                `Path not found: ${path}`,
                PATH_ERROR_CODES.NOT_FOUND,
                path
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OBJECT TRANSFORMATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Transform values at selected paths in an object
 * @param {Object} obj - Source object
 * @param {string[]} paths - Paths to transform
 * @param {Function} transformer - Async function (value, path) => newValue
 * @param {Object} [options] - Options
 * @param {boolean} [options.continueOnError=false] - Continue on transformation errors
 * @returns {Promise<Object>} Result with transformed object
 */
async function transformAtPaths(obj, paths, transformer, options = {}) {
    const continueOnError = options.continueOnError === true;

    const result = {
        object: structuredClone(obj),
        transformed: [],
        skipped: [],
        failed: []
    };

    for (const path of paths) {
        const value = getByPath(obj, path);

        if (value === undefined) {
            result.skipped.push(path);
            continue;
        }

        try {
            const newValue = await transformer(value, path);
            setByPath(result.object, path, newValue);
            result.transformed.push(path);
        } catch (error) {
            if (continueOnError) {
                result.failed.push({ path, error });
            } else {
                throw error;
            }
        }
    }

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
    // Path utilities
    getByPath,
    setByPath,
    getAllPaths,

    // Pattern matching
    patternToRegex,
    matchesPattern,
    filterPaths,
    excludePaths,
    validatePathsExist,

    // Object transformation
    transformAtPaths
};

