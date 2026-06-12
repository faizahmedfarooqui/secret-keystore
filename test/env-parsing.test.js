'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseEnvContent, reconstructEnvContent } = require('../src/index');

test('parseEnvContent classifies line types', () => {
    const content = ['# a comment', '', 'FOO=bar', 'not a kv line'].join('\n');
    const parsed = parseEnvContent(content);

    assert.equal(parsed[0].type, 'comment');
    assert.equal(parsed[1].type, 'empty');
    assert.equal(parsed[2].type, 'keyvalue');
    assert.equal(parsed[2].key, 'FOO');
    assert.equal(parsed[2].value, 'bar');
    assert.equal(parsed[3].type, 'other');
});

test('parseEnvContent handles quoted values', () => {
    const parsed = parseEnvContent('GREETING="hello world"');
    assert.equal(parsed[0].type, 'keyvalue');
    assert.equal(parsed[0].key, 'GREETING');
    assert.equal(parsed[0].value, 'hello world');
});

test('parseEnvContent captures inline comments', () => {
    const parsed = parseEnvContent('PORT=3000 # the port');
    assert.equal(parsed[0].value, '3000');
    assert.ok(parsed[0].inlineComment.includes('the port'));
});

test('reconstructEnvContent round-trips comments and empty lines', () => {
    const content = ['# header', '', 'FOO=bar', 'BAZ=qux'].join('\n');
    const out = reconstructEnvContent(parseEnvContent(content));
    assert.equal(out, content);
});

test('reconstructEnvContent quotes values that need it', () => {
    const parsed = parseEnvContent('K=simple');
    parsed[0].value = 'has spaces';
    assert.equal(reconstructEnvContent(parsed), 'K="has spaces"');
});
