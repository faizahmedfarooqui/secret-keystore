'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
    getByPath,
    setByPath,
    getAllPaths,
    matchesPattern,
    filterPaths,
    transformAtPaths
} = require('../src/index');

test('getByPath reads nested values', () => {
    const obj = { a: { b: { c: 42 } }, x: 1 };
    assert.equal(getByPath(obj, 'a.b.c'), 42);
    assert.equal(getByPath(obj, 'x'), 1);
    assert.equal(getByPath(obj, 'a.b.missing'), undefined);
    assert.equal(getByPath(obj, 'nope.deep'), undefined);
});

test('setByPath writes nested values, creating intermediates', () => {
    const obj = {};
    setByPath(obj, 'a.b.c', 'v');
    assert.deepEqual(obj, { a: { b: { c: 'v' } } });
});

test('getAllPaths returns leaf paths only', () => {
    const obj = { a: { b: 1 }, c: 2, d: { e: { f: 3 } } };
    const paths = getAllPaths(obj).sort();
    assert.deepEqual(paths, ['a.b', 'c', 'd.e.f']);
});

test('matchesPattern: suffix **.x', () => {
    assert.equal(matchesPattern('db.password', '**.password'), true);
    assert.equal(matchesPattern('password', '**.password'), true);
    assert.equal(matchesPattern('db.secret', '**.password'), false);
});

test('matchesPattern: prefix x.**', () => {
    assert.equal(matchesPattern('db', 'db.**'), true);
    assert.equal(matchesPattern('db.password', 'db.**'), true);
    assert.equal(matchesPattern('cache.password', 'db.**'), false);
});

test('matchesPattern: exact', () => {
    assert.equal(matchesPattern('a.b.c', 'a.b.c'), true);
    assert.equal(matchesPattern('a.b.d', 'a.b.c'), false);
});

test('filterPaths returns all when no criteria', () => {
    const all = ['a', 'b.c', 'd'];
    assert.deepEqual(filterPaths(all).sort(), ['a', 'b.c', 'd']);
});

test('filterPaths selects by explicit paths and patterns', () => {
    const all = ['db.password', 'db.host', 'api.secret', 'name'];
    assert.deepEqual(filterPaths(all, { paths: ['name'] }), ['name']);
    const matched = filterPaths(all, { patterns: ['**.password', '**.secret'] }).sort();
    assert.deepEqual(matched, ['api.secret', 'db.password']);
});

test('filterPaths honors excludes', () => {
    const all = ['db.password', 'db.host', 'api.secret'];
    const result = filterPaths(all, {
        patterns: ['**.password', '**.secret'],
        exclude: { paths: ['api.secret'] }
    });
    assert.deepEqual(result, ['db.password']);
});

test('transformAtPaths applies transformer and reports results', async () => {
    const obj = { a: 1, b: { c: 2 }, missing: undefined };
    const result = await transformAtPaths(obj, ['a', 'b.c', 'b.nope'], async v => v * 10);
    assert.equal(result.object.a, 10);
    assert.equal(result.object.b.c, 20);
    assert.deepEqual(result.transformed.sort(), ['a', 'b.c']);
    assert.deepEqual(result.skipped, ['b.nope']);
    // original object not mutated
    assert.equal(obj.a, 1);
});

test('transformAtPaths collects failures when continueOnError', async () => {
    const obj = { a: 1, b: 2 };
    const result = await transformAtPaths(
        obj,
        ['a', 'b'],
        async (v, path) => {
            if (path === 'b') throw new Error('boom');
            return v;
        },
        { continueOnError: true }
    );
    assert.deepEqual(result.transformed, ['a']);
    assert.equal(result.failed.length, 1);
    assert.equal(result.failed[0].path, 'b');
});
