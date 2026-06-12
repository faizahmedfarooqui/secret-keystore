#!/usr/bin/env node

/**
 * @faizahmed/secret-keystore CLI
 *
 * Command-line interface for encrypting configuration files.
 *
 * Usage:
 *   npx @faizahmed/secret-keystore encrypt [options]
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const {
    encryptKMSEnvContent,
    encryptKMSJsonContent,
    encryptKMSYamlContent,
    decryptKMSEnvContent,
    decryptKMSJsonContent,
    decryptKMSYamlContent,
    parseEnvContent,
    maskKmsKeyId,
    validateKmsKeyId,
    config,
    rotateKMSContent,
    isAlreadyEncrypted,
    getAllPaths,
    getByPath,
    parseYaml
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
    return value
        .split(',')
        .map(item => item.trim())
        .filter(Boolean);
}

/**
 * Apply key-value argument to parsed object
 */
function applyKeyValueArg(parsed, key, value) {
    const handlers = {
        path: () => {
            parsed.path = value;
        },
        format: () => {
            parsed.format = value;
        },
        'kms-key-id': () => {
            parsed.kmsKeyId = value;
        },
        'old-kms-key-id': () => {
            parsed.oldKmsKeyId = value;
        },
        keys: () => {
            parsed.keys = parseCommaSeparated(value);
        },
        patterns: () => {
            parsed.patterns = parseCommaSeparated(value);
        },
        exclude: () => {
            parsed.exclude = parseCommaSeparated(value);
        },
        region: () => {
            parsed.region = value;
        },
        output: () => {
            parsed.output = value;
        }
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
        format: null, // auto-detect
        kmsKeyId: null, // REQUIRED
        oldKmsKeyId: null, // required for rotate
        keys: null,
        patterns: null,
        exclude: null,
        region: null,
        output: null,
        useCredentials: false,
        dryRun: false,
        exec: null, // command + args after `--` (for `run`)
        help: false,
        version: false
    };

    const setCommand = name => () => {
        parsed.command = name;
    };

    const flagHandlers = {
        encrypt: setCommand('encrypt'),
        decrypt: setCommand('decrypt'),
        run: setCommand('run'),
        rotate: setCommand('rotate'),
        edit: setCommand('edit'),
        init: setCommand('init'),
        keys: setCommand('keys'),
        status: setCommand('status'),
        import: setCommand('import'),
        '--help': () => {
            parsed.help = true;
        },
        '-h': () => {
            parsed.help = true;
        },
        '--version': () => {
            parsed.version = true;
        },
        '-v': () => {
            parsed.version = true;
        },
        '--use-credentials': () => {
            parsed.useCredentials = true;
        },
        '--dry-run': () => {
            parsed.dryRun = true;
        }
    };

    let i = 0;
    while (i < args.length) {
        const arg = args[i];

        // Everything after `--` is the command to exec (for `run`)
        if (arg === '--') {
            parsed.exec = args.slice(i + 1);
            break;
        }

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
@faizahmed/secret-keystore - Secure secrets management with AWS KMS

USAGE:
  npx @faizahmed/secret-keystore <command> [options]

COMMANDS:
  encrypt    Encrypt values in a configuration file
  decrypt    Decrypt values in a configuration file
  run        Decrypt and run a command with secrets injected into its env
  rotate     Re-encrypt a file under a new KMS Key ID (requires --old-kms-key-id)
  edit       Decrypt → open in $EDITOR → re-encrypt on save (via a secure temp file)
  init       Scaffold a starter .env
  keys       List the keys/paths in a file (no values)
  status     Show which keys are encrypted vs plaintext (no values)
  import     Encrypt an existing plaintext .env in place (migration)

OPTIONS:
  --kms-key-id=<id>     REQUIRED. KMS Key ID (ARN, UUID, or alias)

  --old-kms-key-id=<id> For "rotate": the current key the file is encrypted with

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
  npx @faizahmed/secret-keystore encrypt --kms-key-id="alias/my-key"

  # Encrypt specific keys only
  npx @faizahmed/secret-keystore encrypt \
    --kms-key-id="arn:aws:kms:us-east-1:123456789:key/abc-123" \
    --keys="DB_PASSWORD,API_KEY"

  # Encrypt YAML file with patterns
  npx @faizahmed/secret-keystore encrypt \
    --path="./secrets.yaml" \
    --kms-key-id="alias/my-key" \
    --patterns="**.password,**.secret"

  # Dry run to preview changes
  npx @faizahmed/secret-keystore encrypt \
    --kms-key-id="alias/my-key" \
    --dry-run

  # Encrypt to a different output file
  npx @faizahmed/secret-keystore encrypt \
    --path="./.env" \
    --output="./.env.encrypted" \
    --kms-key-id="alias/my-key"

  # Decrypt all encrypted values in a file (in place)
  npx @faizahmed/secret-keystore decrypt \
    --path="./.env" \
    --kms-key-id="alias/my-key"

  # Decrypt to a separate output file
  npx @faizahmed/secret-keystore decrypt \
    --path="./.env.encrypted" \
    --output="./.env" \
    --kms-key-id="alias/my-key"

  # Run your app with decrypted secrets injected into its environment
  npx @faizahmed/secret-keystore run \
    --kms-key-id="alias/my-key" -- node server.js

  # Rotate a file from an old key to a new key
  npx @faizahmed/secret-keystore rotate \
    --old-kms-key-id="alias/old-key" \
    --kms-key-id="alias/new-key"

  # Edit an encrypted file in $EDITOR (re-encrypts on save)
  npx @faizahmed/secret-keystore edit \
    --kms-key-id="alias/my-key" --path="./.env"

  # Inspect a file without revealing values
  npx @faizahmed/secret-keystore status --path="./.env"
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
        console.error(
            '❌ Error: --use-credentials requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY'
        );
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
        keysToEncrypt = allKeys.filter(k => args.patterns.some(p => matchesPattern(k, p)));
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
        json: encryptKMSJsonContent,
        yaml: encryptKMSYamlContent,
        env: encryptKMSEnvContent
    };

    const encryptor = encryptors[format] || encryptKMSEnvContent;
    return encryptor(content, kmsKeyId, options);
}

/**
 * Print operation summary (encrypt or decrypt)
 */
function printSummary(result, verb = 'Encrypted') {
    const processed = (result.encrypted || result.decrypted || []).length;
    console.log('\n📊 Summary:');
    console.log(`   ✅ ${verb}: ${processed}`);
    console.log(`   ⏭️  Skipped: ${result.skipped.length}`);
    console.log(`   ❌ Failed: ${result.failed.length}`);

    if (result.failed.length > 0) {
        console.log('\n⚠️  Failed keys:');
        result.failed.forEach(f => console.log(`   • ${f.key || f.path}: ${f.error.message}`));
        process.exit(1);
    }

    console.log('\n✨ Done!\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPT COMMAND
// ═══════════════════════════════════════════════════════════════════════════

async function runEncrypt(args) {
    console.log('\n🔐 @faizahmed/secret-keystore - Encrypt\n');

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
    console.log(
        args.useCredentials
            ? '🔑 Using explicit AWS credentials\n'
            : '🔑 Using IAM role (default)\n'
    );

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
// DECRYPT COMMAND
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt content based on format
 */
async function decryptByFormat(content, format, kmsKeyId, options) {
    const decryptors = {
        json: decryptKMSJsonContent,
        yaml: decryptKMSYamlContent,
        env: decryptKMSEnvContent
    };

    const decryptor = decryptors[format] || decryptKMSEnvContent;
    return decryptor(content, kmsKeyId, options);
}

async function runDecrypt(args) {
    console.log('\n🔓 @faizahmed/secret-keystore - Decrypt\n');

    validateRequiredKmsKeyId(args.kmsKeyId);

    const resolvedPath = resolveAndValidatePath(args.path);
    const format = args.format || detectFormat(resolvedPath);
    const content = fs.readFileSync(resolvedPath, 'utf-8');

    console.log(`📂 File: ${resolvedPath}`);
    console.log(`📄 Format: ${format}`);
    console.log(`🔑 KMS Key: ${maskKmsKeyId(args.kmsKeyId)}`);

    // Build credentials
    const credentials = args.useCredentials ? buildAwsCredentials() : null;
    console.log(
        args.useCredentials
            ? '🔑 Using explicit AWS credentials\n'
            : '🔑 Using IAM role (default)\n'
    );

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

    let result;
    try {
        result = await decryptByFormat(content, format, args.kmsKeyId, options);
    } catch (error) {
        console.error(`\n❌ Error: ${error.message}`);
        if (error.cause) {
            console.error(`   Cause: ${error.cause.message}`);
        }
        process.exit(1);
    }

    const outputPath = args.output ? path.resolve(process.cwd(), args.output) : resolvedPath;

    if (result.decrypted.length > 0) {
        fs.writeFileSync(outputPath, result.content, 'utf-8');
        console.log(`\n💾 Written to: ${outputPath}`);
    }

    printSummary(result, 'Decrypted');
}

// ═══════════════════════════════════════════════════════════════════════════
// SHARED OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

function buildCliOptions(args) {
    const credentials = args.useCredentials ? buildAwsCredentials() : null;
    return {
        aws: { credentials, region: args.region || process.env.AWS_REGION },
        paths: args.keys,
        patterns: args.patterns,
        exclude: args.exclude ? { paths: args.exclude } : undefined,
        logLevel: 'info'
    };
}

/** List keys/paths in a config file (names only — never returns values to callers that print). */
function listFileEntries(content, format) {
    if (format === 'env') {
        return parseEnvContent(content)
            .filter(e => e.type === 'keyvalue')
            .map(e => ({ name: e.key, value: e.value }));
    }
    const obj = format === 'json' ? JSON.parse(content) : parseYaml(content);
    return getAllPaths(obj).map(p => ({ name: p, value: getByPath(obj, p) }));
}

/** Keys/paths whose values are currently encrypted. */
function encryptedSelection(content, format) {
    return listFileEntries(content, format)
        .filter(e => typeof e.value === 'string' && isAlreadyEncrypted(e.value))
        .map(e => e.name);
}

// ═══════════════════════════════════════════════════════════════════════════
// RUN COMMAND
// ═══════════════════════════════════════════════════════════════════════════

async function runRun(args) {
    validateRequiredKmsKeyId(args.kmsKeyId);

    if (!args.exec || args.exec.length === 0) {
        console.error('❌ Error: `run` requires a command after `--`.');
        console.error('   Example: secret-keystore run --kms-key-id="alias/k" -- node server.js');
        process.exit(1);
    }

    const credentials = args.useCredentials ? buildAwsCredentials() : null;
    const explicitPath = args.path && args.path !== './.env' ? args.path : undefined;

    let store;
    try {
        store = await config({
            kmsKeyId: args.kmsKeyId,
            cwd: process.cwd(),
            path: explicitPath,
            aws: { credentials, region: args.region || process.env.AWS_REGION }
        });
    } catch (error) {
        console.error(`\n❌ Error: ${error.message}`);
        process.exit(1);
    }

    // Secrets are injected into the CHILD's environment only. The parent never
    // places them in its own process.env.
    const childEnv = { ...process.env, ...store.getAll() };
    const [command, ...commandArgs] = args.exec;

    const child = spawn(command, commandArgs, { stdio: 'inherit', env: childEnv });

    child.on('error', error => {
        store.destroy();
        console.error(`\n❌ Failed to start "${command}": ${error.message}`);
        process.exit(1);
    });

    child.on('exit', (code, signal) => {
        store.destroy();
        if (signal) {
            process.kill(process.pid, signal);
            return;
        }
        process.exit(code ?? 0);
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// ROTATE COMMAND
// ═══════════════════════════════════════════════════════════════════════════

async function runRotate(args) {
    console.log('\n🔄 @faizahmed/secret-keystore - Rotate\n');

    validateRequiredKmsKeyId(args.kmsKeyId);

    if (!args.oldKmsKeyId) {
        console.error('❌ Error: `rotate` requires --old-kms-key-id (the current key).');
        process.exit(1);
    }
    try {
        validateKmsKeyId(args.oldKmsKeyId);
    } catch (error) {
        console.error(`❌ Error: Invalid --old-kms-key-id - ${error.message}`);
        process.exit(1);
    }

    const resolvedPath = resolveAndValidatePath(args.path);
    const format = args.format || detectFormat(resolvedPath);
    const content = fs.readFileSync(resolvedPath, 'utf-8');

    console.log(`📂 File: ${resolvedPath}`);
    console.log(`🔑 Old Key: ${maskKmsKeyId(args.oldKmsKeyId)}`);
    console.log(`🔑 New Key: ${maskKmsKeyId(args.kmsKeyId)}\n`);

    let result;
    try {
        result = await rotateKMSContent(
            content,
            format,
            args.oldKmsKeyId,
            args.kmsKeyId,
            buildCliOptions(args)
        );
    } catch (error) {
        console.error(`\n❌ Error: ${error.message}`);
        if (error.cause) console.error(`   Cause: ${error.cause.message}`);
        process.exit(1);
    }

    const outputPath = args.output ? path.resolve(process.cwd(), args.output) : resolvedPath;
    if (result.rotated.length > 0) {
        fs.writeFileSync(outputPath, result.content, 'utf-8');
        console.log(`💾 Written to: ${outputPath}`);
    }

    console.log(`\n📊 Rotated ${result.rotated.length} value(s).`);
    console.log('\n✨ Done!\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// EDIT COMMAND
// ═══════════════════════════════════════════════════════════════════════════

function secureDelete(file) {
    try {
        const size = fs.statSync(file).size;
        fs.writeFileSync(file, crypto.randomBytes(size));
    } catch {
        // best-effort overwrite
    }
    try {
        fs.rmSync(file, { force: true });
    } catch {
        // best-effort delete
    }
}

async function runEdit(args) {
    console.log('\n📝 @faizahmed/secret-keystore - Edit\n');

    validateRequiredKmsKeyId(args.kmsKeyId);

    const editor = process.env.EDITOR || process.env.VISUAL;
    if (!editor) {
        console.error(
            '❌ Error: no editor found. Set $EDITOR or $VISUAL (e.g. export EDITOR=vim).'
        );
        process.exit(1);
    }

    const resolvedPath = resolveAndValidatePath(args.path);
    const format = args.format || detectFormat(resolvedPath);
    const content = fs.readFileSync(resolvedPath, 'utf-8');
    const options = buildCliOptions(args);

    // Remember which keys were encrypted so we can re-encrypt exactly those on save.
    const selection = encryptedSelection(content, format);

    let decrypted;
    try {
        decrypted = await decryptByFormat(content, format, args.kmsKeyId, options);
    } catch (error) {
        console.error(`\n❌ Error: ${error.message}`);
        process.exit(1);
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sks-edit-'));
    const tmpFile = path.join(tmpDir, path.basename(resolvedPath));
    fs.writeFileSync(tmpFile, decrypted.content, { mode: 0o600 });

    try {
        const res = spawnSync(editor, [tmpFile], { stdio: 'inherit', shell: true });
        if (res.status !== 0) {
            console.error('\n❌ Editor exited non-zero; aborting (no changes written).');
            process.exit(1);
        }

        const edited = fs.readFileSync(tmpFile, 'utf-8');

        if (selection.length === 0) {
            // Nothing was encrypted; write the edited content back as-is.
            fs.writeFileSync(resolvedPath, edited, 'utf-8');
            console.log(`\n💾 Saved: ${resolvedPath} (no encrypted values to re-encrypt)`);
        } else {
            const reencrypted = await encryptByFormat(edited, format, args.kmsKeyId, {
                ...options,
                paths: selection,
                patterns: undefined
            });
            fs.writeFileSync(resolvedPath, reencrypted.content, 'utf-8');
            console.log(`\n💾 Saved & re-encrypted: ${resolvedPath}`);
            console.log(`📊 Re-encrypted ${reencrypted.encrypted.length} value(s).`);
        }
    } finally {
        secureDelete(tmpFile);
        try {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        } catch {
            // best-effort cleanup
        }
    }

    console.log('\n✨ Done!\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// INIT COMMAND
// ═══════════════════════════════════════════════════════════════════════════

function runInit(args) {
    console.log('\n🚀 @faizahmed/secret-keystore - Init\n');

    const target = path.resolve(process.cwd(), args.path || './.env');
    if (fs.existsSync(target)) {
        console.error(`❌ Error: ${target} already exists. Refusing to overwrite.`);
        process.exit(1);
    }

    const template = [
        '# secret-keystore configuration',
        '# Reserved keys (never encrypted):',
        'KMS_KEY_ID=alias/your-kms-key',
        'AWS_REGION=us-east-1',
        '',
        '# Your secrets — encrypt with:',
        '#   secret-keystore encrypt --kms-key-id="alias/your-kms-key"',
        'DB_PASSWORD=change-me',
        'API_KEY=change-me',
        ''
    ].join('\n');

    fs.writeFileSync(target, template, 'utf-8');

    console.log(`✅ Created ${target}\n`);
    console.log('Next steps:');
    console.log('  1. Set KMS_KEY_ID and your secret values in the file');
    console.log('  2. Encrypt:  secret-keystore encrypt --kms-key-id="alias/your-kms-key"');
    console.log('  3. At runtime: const s = await config({ kmsKeyId }) — secrets stay in memory\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// KEYS & STATUS COMMANDS (read-only — never print secret values)
// ═══════════════════════════════════════════════════════════════════════════

function runKeys(args) {
    const resolvedPath = resolveAndValidatePath(args.path);
    const format = args.format || detectFormat(resolvedPath);
    const content = fs.readFileSync(resolvedPath, 'utf-8');

    for (const entry of listFileEntries(content, format)) {
        console.log(entry.name);
    }
}

function runStatus(args) {
    console.log('\n📋 @faizahmed/secret-keystore - Status\n');

    const resolvedPath = resolveAndValidatePath(args.path);
    const format = args.format || detectFormat(resolvedPath);
    const content = fs.readFileSync(resolvedPath, 'utf-8');

    let encrypted = 0;
    let plaintext = 0;
    for (const entry of listFileEntries(content, format)) {
        const isEnc = typeof entry.value === 'string' && isAlreadyEncrypted(entry.value);
        if (isEnc) encrypted += 1;
        else plaintext += 1;
        console.log(`  ${isEnc ? '🔒 encrypted' : '🔓 plaintext'}  ${entry.name}`);
    }

    const total = encrypted + plaintext;
    console.log(`\n📊 ${encrypted} encrypted, ${plaintext} plaintext, ${total} total\n`);
}

// ═══════════════════════════════════════════════════════════════════════════
// IMPORT COMMAND (encrypt an existing plaintext .env in place)
// ═══════════════════════════════════════════════════════════════════════════

async function runImport(args) {
    console.log('\n📥 @faizahmed/secret-keystore - Import (migrate plaintext → encrypted)\n');
    // Encrypt all non-reserved keys in place.
    await runEncrypt({ ...args, keys: null, patterns: null });
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

    // Validate and dispatch command
    const commands = {
        encrypt: runEncrypt,
        decrypt: runDecrypt,
        run: runRun,
        rotate: runRotate,
        edit: runEdit,
        init: runInit,
        keys: runKeys,
        status: runStatus,
        import: runImport
    };

    const handler = commands[args.command];
    if (!handler) {
        console.error(
            'Error: Unknown command. Use one of: ' + Object.keys(commands).join(', ') + '.'
        );
        console.error('Run with --help for usage information.');
        process.exit(1);
    }

    await handler(args);
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
