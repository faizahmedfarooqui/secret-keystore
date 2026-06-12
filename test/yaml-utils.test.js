'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { isJsYamlAvailable, parseYaml, serializeYaml } = require('../src/index');

test('isJsYamlAvailable returns a boolean', () => {
    assert.equal(typeof isJsYamlAvailable(), 'boolean');
});

test('parseYaml reads simple key/value YAML', () => {
    const obj = parseYaml('host: localhost\nname: app\n');
    assert.equal(obj.host, 'localhost');
    assert.equal(obj.name, 'app');
});

test('serializeYaml + parseYaml round-trip a flat object', () => {
    const original = { host: 'localhost', name: 'app' };
    const yaml = serializeYaml(original);
    assert.equal(typeof yaml, 'string');
    const parsed = parseYaml(yaml);
    assert.equal(parsed.host, 'localhost');
    assert.equal(parsed.name, 'app');
});
