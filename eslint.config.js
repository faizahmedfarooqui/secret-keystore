'use strict';

const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
    {
        ignores: ['node_modules/**', 'coverage/**', 'examples/**', '*.tgz']
    },
    js.configs.recommended,
    {
        // Root-level config files (this file, etc.)
        files: ['*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: { ...globals.node }
        }
    },
    {
        files: ['src/**/*.js', 'bin/**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: {
                ...globals.node
            }
        },
        rules: {
            'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
            'no-console': 'off',
            'prefer-const': 'error',
            eqeqeq: ['error', 'smart']
        }
    },
    {
        files: ['test/**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: {
                ...globals.node
            }
        },
        rules: {
            'no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
        }
    }
];
