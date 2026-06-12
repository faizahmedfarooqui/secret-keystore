'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const runtime = require('../src/index');

const TABLES = [
    'KMS_ERROR_CODES',
    'ATTESTATION_ERROR_CODES',
    'CONTENT_ERROR_CODES',
    'PATH_ERROR_CODES',
    'ENCRYPTION_ERROR_CODES',
    'DECRYPTION_ERROR_CODES',
    'KEYSTORE_ERROR_CODES',
    'VALIDATION_ERROR_CODES'
];

const dts = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.d.ts'), 'utf8');

function dtsKeysFor(table) {
    const match = dts.match(new RegExp(`${table}\\s*:\\s*{([^}]*)}`));
    if (!match) return null;
    return [...match[1].matchAll(/(\w+)\s*:/g)].map(m => m[1]).sort();
}

for (const table of TABLES) {
    test(`${table}: type definitions match runtime keys`, () => {
        const runtimeKeys = Object.keys(runtime[table]).sort();
        const dtsKeys = dtsKeysFor(table);
        assert.notEqual(dtsKeys, null, `${table} not found in index.d.ts`);
        assert.deepEqual(
            dtsKeys,
            runtimeKeys,
            `index.d.ts ${table} is out of sync with src/errors.js`
        );
    });
}
