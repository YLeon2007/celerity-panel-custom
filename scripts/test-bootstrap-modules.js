'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { bootstrapModules } = require('../src/modules/bootstrapModules');
const relayL2tpManifest = require('../src/modules/relay-l2tp/manifest.json');
const relayL2tpEntry = require('../src/modules/relay-l2tp');

test('bootstraps relay-l2tp exactly once when host capabilities are supported', () => {
    const { registry, modules } = bootstrapModules(['ssh']);

    assert.deepEqual(registry.list(), [relayL2tpManifest]);
    assert.equal(modules.length, 1);
    assert.strictEqual(modules[0].manifest, relayL2tpManifest);
    assert.strictEqual(modules[0].entry, relayL2tpEntry);
});

test('rejects a missing manifest capability before the entry lifecycle hook', () => {
    const originalValidateHost = relayL2tpEntry.validateHost;
    let lifecycleCalls = 0;
    relayL2tpEntry.validateHost = () => {
        lifecycleCalls += 1;
    };

    try {
        assert.throws(
            () => bootstrapModules([]),
            /missing required capabilities: ssh/i,
        );
        assert.equal(lifecycleCalls, 0);
    } finally {
        if (originalValidateHost === undefined) {
            delete relayL2tpEntry.validateHost;
        } else {
            relayL2tpEntry.validateHost = originalValidateHost;
        }
    }
});

test('imports the relay-l2tp entry without startup or worker side effects', () => {
    assert.deepEqual(Object.keys(relayL2tpEntry), [
        'manifest',
        'validateHost',
        'registerModels',
        'registerConfigFragments',
    ]);

    const entryPath = require.resolve('../src/modules/relay-l2tp');
    const importResult = spawnSync(
        process.execPath,
        ['--eval', `require(${JSON.stringify(entryPath)})`],
        {
            encoding: 'utf8',
            timeout: 1_000,
        },
    );

    assert.equal(importResult.error, undefined);
    assert.equal(importResult.signal, null);
    assert.equal(importResult.status, 0, importResult.stderr);
    assert.equal(importResult.stdout, '');
    assert.equal(importResult.stderr, '');
});
