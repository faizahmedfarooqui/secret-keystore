#!/usr/bin/env node

/**
 * @faizahmedfarooqui/secret-keystore CLI
 *
 * Command-line interface for encrypting configuration files.
 *
 * Usage:
 *   npx @faizahmedfarooqui/secret-keystore encrypt [options]
 */

const fs = require('node:fs');
const path = require('node:path');
const {
    encryptKMSEnvContent,
    encryptKMSJsonContent,
    encryptKMSYamlContent,
    parseEnvContent,
    maskKmsKeyId,
    validateKmsKeyId
} = require('../src/index');

// ═══════════════════════════════════════════════════════════════════════════
// ARGUMENT PARSING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Strip surrounding quotes from a value
 */
function stripQuotes(value) {
    if (!value) return value;
    return value.replaceAll(/(^["'])|(["']$)/g, '');
}

/**
 * Parse comma-separated list into array
 */
function parseCommaSeparated(value) {
    return value.split(',').map(item => item.trim()).filter(Boolean);
}

/**
 * Apply key-value argument to parsed object
 */
function applyKeyValueArg(parsed, key, value) {
    const handlers = {
        'path': () => { parsed.path = value; },
        'format': () => { parsed.format = value; },
        'kms-key-id': () => { parsed.kmsKeyId = value; },
        'keys': () => { parsed.keys = parseCommaSeparated(value); },
        'patterns': () => { parsed.patterns = parseCommaSeparated(value); },
        'exclude': () => { parsed.exclude = parseCommaSeparated(value); },
        'region': () => { parsed.region = value; },
        'output': () => { parsed.output = value; }
    };

    const handler = handlers[key];
    if (handler) handler();
}

/**
 * Parse a --key=value or --key value style argument
 */
function parseKeyValueArg(arg, args, currentIndex) {
    let key, value;
    let nextIndex = currentIndex;

    if (arg.includes('=')) {
        const eqIndex = arg.indexOf('=');
        key = arg.substring(2, eqIndex);
        value = arg.substring(eqIndex + 1);
    } else {
        key = arg.substring(2);
        nextIndex = currentIndex + 1;
        value = args[nextIndex];
    }

    value = stripQuotes(value);
    return { key, value, nextIndex };
}

function parseArgs(args) {
    const parsed = {
        command: null,
        path: './.env',
        format: null,      // auto-detect
        kmsKeyId: null,    // REQUIRED
        keys: null,
        patterns: null,
        exclude: null,
        region: null,
        output: null,
        useCredentials: false,
        dryRun: false,
        help: false,
        version: false
    };

    const flagHandlers = {
        'encrypt': () => { parsed.command = 'encrypt'; },
        '--help': () => { parsed.help = true; },
        '-h': () => { parsed.help = true; },
        '--version': () => { parsed.version = true; },
        '-v': () => { parsed.version = true; },
        '--use-credentials': () => { parsed.useCredentials = true; },
        '--dry-run': () => { parsed.dryRun = true; }
    };

    let i = 0;
    while (i < args.length) {
        const arg = args[i];

        // Handle simple flags
        const flagHandler = flagHandlers[arg];
        if (flagHandler) {
            flagHandler();
            i += 1;
            continue;
        }

        // Handle --key=value or --key value format
        if (arg.startsWith('--')) {
            const { key, value, nextIndex } = parseKeyValueArg(arg, args, i);
            applyKeyValueArg(parsed, key, value);
            i = nextIndex + 1;
        } else {
            i += 1;
        }
    }

    return parsed;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELP & VERSION
// ═══════════════════════════════════════════════════════════════════════════

function printVersion() {
    const pkg = require('../package.json');
    console.log(`${pkg.name} v${pkg.version}`);
}

function printHelp() {
    console.log(String.raw`
@faizahmedfarooqui/secret-keystore - Secure secrets management with AWS KMS

USAGE:
  npx @faizahmedfarooqui/secret-keystore encrypt [options]

COMMANDS:
  encrypt    Encrypt values in a configuration file

OPTIONS:
  --kms-key-id=<id>     REQUIRED. KMS Key ID (ARN, UUID, or alias)

  --path=<path>         Path to config file (default: ./.env)

  --format=<format>     File format: env, json, yaml (auto-detected if omitted)

  --keys=<keys>         Comma-separated list of keys to encrypt
                        (encrypts all non-reserved keys if omitted)

  --patterns=<patterns> Comma-separated glob patterns (** only)
                        Example: --patterns="**.password,**.secret_key"

  --exclude=<keys>      Comma-separated keys/paths to exclude

  --region=<region>     AWS region (uses AWS_REGION env var if omitted)

  --output=<path>       Output file (default: overwrite input file)

  --use-credentials     Use explicit AWS credentials instead of IAM role
                        Requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY

  --dry-run             Show what would be encrypted without making changes

  --help, -h            Show this help message

  --version, -v         Show version number

AUTHENTICATION:
  By default, this CLI uses IAM roles for AWS authentication.
  This is the recommended approach for production environments.

  To use explicit credentials (e.g., for local development):
    1. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
    2. Pass --use-credentials flag

EXAMPLES:
  # Encrypt all keys in .env (kms-key-id is REQUIRED)
  npx @faizahmedfarooqui/secret-keystore encrypt --kms-key-id="alias/my-key"

  # Encrypt specific keys only
  npx @faizahmedfarooqui/secret-keystore encrypt \
    --kms-key-id="arn:aws:kms:us-east-1:123456789:key/abc-123" \
    --keys="DB_PASSWORD,API_KEY"

  # Encrypt YAML file with patterns
  npx @faizahmedfarooqui/secret-keystore encrypt \
    --path="./secrets.yaml" \
    --kms-key-id="alias/my-key" \
    --patterns="**.password,**.secret"

  # Dry run to preview changes
  npx @faizahmedfarooqui/secret-keystore encrypt \
    --kms-key-id="alias/my-key" \
    --dry-run

  # Encrypt to a different output file
  npx @faizahmedfarooqui/secret-keystore encrypt \
    --path="./.env" \
    --output="./.env.encrypted" \
    --kms-key-id="alias/my-key"
`);
}

// ═══════════════════════════════════════════════════════════════════════════
// FORMAT DETECTION
// ═══════════════════════════════════════════════════════════════════════════

function detectFormat(filePath) {
    const ext = path.extname(filePath).toLowerCase();

    switch (ext) {
        case '.json':
            return 'json';
        case '.yaml':
        case '.yml':
            return 'yaml';
        case '.env':
        default:
            return 'env';
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPT COMMAND - HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate required KMS key ID argument
 */
function validateRequiredKmsKeyId(kmsKeyId) {
    if (!kmsKeyId) {
        console.error('❌ Error: --kms-key-id is REQUIRED');
        console.error('   Example: --kms-key-id="arn:aws:kms:us-east-1:123456789:key/abc-123"');
        console.error('   Example: --kms-key-id="alias/my-key"');
        process.exit(1);
    }

    try {
        validateKmsKeyId(kmsKeyId);
    } catch (error) {
        console.error(`❌ Error: Invalid KMS Key ID - ${error.message}`);
        process.exit(1);
    }
}

/**
 * Validate and resolve file path
 */
function resolveAndValidatePath(inputPath) {
    const resolvedPath = path.resolve(process.cwd(), inputPath);

    if (!fs.existsSync(resolvedPath)) {
        console.error(`❌ Error: File not found: ${resolvedPath}`);
        process.exit(1);
    }

    return resolvedPath;
}

/**
 * Build AWS credentials from environment variables
 */
function buildAwsCredentials() {
    const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
    const sessionToken = process.env.AWS_SESSION_TOKEN;

    if (!accessKeyId || !secretAccessKey) {
        console.error('❌ Error: --use-credentials requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY');
        process.exit(1);
    }

    const credentials = { accessKeyId, secretAccessKey };
    if (sessionToken) {
        credentials.sessionToken = sessionToken;
    }

    return credentials;
}

/**
 * Match a key against a pattern
 */
function matchesPattern(key, pattern) {
    if (pattern.startsWith('**.')) {
        const suffix = pattern.slice(3);
        return key.endsWith(suffix) || key === suffix;
    }
    return key === pattern;
}

/**
 * Filter keys for dry run preview
 */
function filterKeysForDryRun(allKeys, args) {
    let keysToEncrypt = args.keys || allKeys;

    if (args.patterns) {
        keysToEncrypt = allKeys.filter(k =>
            args.patterns.some(p => matchesPattern(k, p))
        );
    }

    if (args.exclude) {
        keysToEncrypt = keysToEncrypt.filter(k => !args.exclude.includes(k));
    }

    return keysToEncrypt;
}

/**
 * Run dry run mode - show what would be encrypted
 */
function runDryRun(content, format, args) {
    console.log('Keys that would be encrypted:');

    if (format === 'env') {
        const parsed = parseEnvContent(content);
        const allKeys = parsed.filter(e => e.type === 'keyvalue').map(e => e.key);
        const keysToEncrypt = filterKeysForDryRun(allKeys, args);

        keysToEncrypt.forEach(k => console.log(`  • ${k}`));
        console.log(`\nTotal: ${keysToEncrypt.length} keys`);
    } else {
        console.log('  (pattern matching preview for JSON/YAML not implemented in dry-run)');
    }

    console.log('\n✨ Dry run complete. No changes made.\n');
}

/**
 * Encrypt content based on format
 */
async function encryptByFormat(content, format, kmsKeyId, options) {
    const encryptors = {
        'json': encryptKMSJsonContent,
        'yaml': encryptKMSYamlContent,
        'env': encryptKMSEnvContent
    };

    const encryptor = encryptors[format] || encryptKMSEnvContent;
    return encryptor(content, kmsKeyId, options);
}

/**
 * Print encryption summary
 */
function printSummary(result) {
    console.log('\n📊 Summary:');
    console.log(`   ✅ Encrypted: ${result.encrypted.length}`);
    console.log(`   ⏭️  Skipped: ${result.skipped.length}`);
    console.log(`   ❌ Failed: ${result.failed.length}`);

    if (result.failed.length > 0) {
        console.log('\n⚠️  Failed keys:');
        result.failed.forEach(f => console.log(`   • ${f.key}: ${f.error.message}`));
        process.exit(1);
    }

    console.log('\n✨ Done!\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPT COMMAND
// ═══════════════════════════════════════════════════════════════════════════

async function runEncrypt(args) {
    console.log('\n🔐 @faizahmedfarooqui/secret-keystore - Encrypt\n');

    validateRequiredKmsKeyId(args.kmsKeyId);

    const resolvedPath = resolveAndValidatePath(args.path);
    const format = args.format || detectFormat(resolvedPath);
    const content = fs.readFileSync(resolvedPath, 'utf-8');

    console.log(`📂 File: ${resolvedPath}`);
    console.log(`📄 Format: ${format}`);
    console.log(`🔑 KMS Key: ${maskKmsKeyId(args.kmsKeyId)}`);
    console.log(args.dryRun ? '🔍 Mode: DRY RUN (no changes will be made)\n' : '');

    // Build credentials
    const credentials = args.useCredentials ? buildAwsCredentials() : null;
    console.log(args.useCredentials ? '🔑 Using explicit AWS credentials\n' : '🔑 Using IAM role (default)\n');

    const options = {
        aws: {
            credentials,
            region: args.region || process.env.AWS_REGION
        },
        paths: args.keys,
        patterns: args.patterns,
        exclude: args.exclude ? { paths: args.exclude } : undefined,
        logLevel: 'info'
    };

    if (args.dryRun) {
        runDryRun(content, format, args);
        return;
    }

    let result;
    try {
        result = await encryptByFormat(content, format, args.kmsKeyId, options);
    } catch (error) {
        console.error(`\n❌ Error: ${error.message}`);
        if (error.cause) {
            console.error(`   Cause: ${error.cause.message}`);
        }
        process.exit(1);
    }

    const outputPath = args.output ? path.resolve(process.cwd(), args.output) : resolvedPath;

    if (result.encrypted.length > 0) {
        fs.writeFileSync(outputPath, result.content, 'utf-8');
        console.log(`\n💾 Written to: ${outputPath}`);
    }

    printSummary(result);
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
    const args = parseArgs(process.argv.slice(2));

    // Show version
    if (args.version) {
        printVersion();
        process.exit(0);
    }

    // Show help
    if (args.help || process.argv.length <= 2) {
        printHelp();
        process.exit(0);
    }

    // Validate command
    if (args.command !== 'encrypt') {
        console.error('Error: Unknown command. Use "encrypt" command.');
        console.error('Run with --help for usage information.');
        process.exit(1);
    }

    await runEncrypt(args);
}

// Top-level await with IIFE for error handling
(async () => {
    try {
        await main();
    } catch (error) {
        console.error(`\n❌ Unexpected error: ${error.message}\n`);
        process.exit(1);
    }
})();
