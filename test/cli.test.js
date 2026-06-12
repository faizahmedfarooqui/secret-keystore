'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const CLI = path.join(__dirname, '..', 'bin', 'cli.js');

function runCli(args) {
    return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf-8' });
}

test('--help exits 0 and lists both commands', () => {
    const { status, stdout } = runCli(['--help']);
    assert.equal(status, 0);
    assert.match(stdout, /USAGE:/);
    assert.match(stdout, /encrypt/);
    assert.match(stdout, /decrypt/);
});

test('--version exits 0 and prints the package name', () => {
    const { status, stdout } = runCli(['--version']);
    assert.equal(status, 0);
    assert.match(stdout, /secret-keystore v\d+\.\d+\.\d+/);
});

test('unknown command exits 1', () => {
    const { status, stderr } = runCli(['frobnicate']);
    assert.equal(status, 1);
    assert.match(stderr, /Unknown command/);
});

test('decrypt without --kms-key-id exits 1 (key required)', () => {
    const { status, stderr } = runCli(['decrypt']);
    assert.equal(status, 1);
    assert.match(stderr, /kms-key-id is REQUIRED/);
});

test('encrypt with a missing file exits 1', () => {
    const { status, stderr } = runCli([
        'encrypt',
        '--kms-key-id=alias/test',
        '--path=./definitely-does-not-exist.env'
    ]);
    assert.equal(status, 1);
    assert.match(stderr, /File not found/);
});
