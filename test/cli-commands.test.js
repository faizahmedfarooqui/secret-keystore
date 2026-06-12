'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const CLI = path.join(__dirname, '..', 'bin', 'cli.js');

let dir;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sks-cli-'));
});
afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
});

function write(name, content) {
    fs.writeFileSync(path.join(dir, name), content);
}

function runCli(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
        encoding: 'utf-8',
        cwd: dir,
        ...opts
    });
}

test('--help lists all Phase 1 commands', () => {
    const { status, stdout } = runCli(['--help']);
    assert.equal(status, 0);
    for (const cmd of ['run', 'rotate', 'edit', 'init', 'keys', 'status', 'import']) {
        assert.match(stdout, new RegExp(`\\b${cmd}\\b`));
    }
});

test('run injects decrypted secrets into the child process env', () => {
    // Plaintext value → no KMS call needed; exercises the full run path offline.
    write('.env', 'GREETING=hello-from-keystore');

    const { status, stdout } = runCli([
        'run',
        '--kms-key-id=alias/test',
        '--',
        process.execPath,
        '-e',
        'process.stdout.write(process.env.GREETING || "MISSING")'
    ]);

    assert.equal(status, 0);
    assert.match(stdout, /hello-from-keystore/);
});

test('run without a command after -- exits 1', () => {
    write('.env', 'A=1');
    const { status, stderr } = runCli(['run', '--kms-key-id=alias/test']);
    assert.equal(status, 1);
    assert.match(stderr, /requires a command after/);
});

test('rotate without --old-kms-key-id exits 1', () => {
    const { status, stderr } = runCli(['rotate', '--kms-key-id=alias/new']);
    assert.equal(status, 1);
    assert.match(stderr, /old-kms-key-id/);
});

test('edit without $EDITOR exits 1', () => {
    write('.env', 'A=1');
    const { status, stderr } = runCli(['edit', '--kms-key-id=alias/test'], {
        env: { ...process.env, EDITOR: '', VISUAL: '' }
    });
    assert.equal(status, 1);
    assert.match(stderr, /editor/i);
});

test('init scaffolds a starter .env', () => {
    const { status, stdout } = runCli(['init']);
    assert.equal(status, 0);
    assert.match(stdout, /Created/);
    const created = fs.readFileSync(path.join(dir, '.env'), 'utf-8');
    assert.match(created, /KMS_KEY_ID=/);
});

test('init refuses to overwrite an existing file', () => {
    write('.env', 'EXISTING=1');
    const { status, stderr } = runCli(['init']);
    assert.equal(status, 1);
    assert.match(stderr, /already exists/);
});

test('keys lists key names without revealing values', () => {
    write('.env', ['PLAIN=hello', 'SECRET=ENC[abc123==]'].join('\n'));
    const { status, stdout } = runCli(['keys']);
    assert.equal(status, 0);
    assert.match(stdout, /PLAIN/);
    assert.match(stdout, /SECRET/);
    assert.doesNotMatch(stdout, /hello/); // value not printed
});

test('status reports encrypted vs plaintext counts, no values', () => {
    write('.env', ['PLAIN=hello', 'SECRET=ENC[abc123==]'].join('\n'));
    const { status, stdout } = runCli(['status']);
    assert.equal(status, 0);
    assert.match(stdout, /1 encrypted, 1 plaintext, 2 total/);
    assert.doesNotMatch(stdout, /hello/);
});
