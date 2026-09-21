'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { loadModules } = require('../src/modules/loadModules');
const relayL2tp = require('../src/modules/relay-l2tp');

test('loads the relay-l2tp descriptor into a module registry', () => {
    const registry = loadModules({
        hostCapabilities: ['ssh'],
        modules: [{
            manifest: relayL2tp.manifest,
            entry: relayL2tp,
        }],
    });

    assert.deepEqual(registry.list(), [relayL2tp.manifest]);
});

test('runs validateHost before registering a descriptor', () => {
    const hostCapabilities = ['ssh'];
    const secondManifest = {
        ...relayL2tp.manifest,
        version: '0.2.0',
    };
    const validationError = new Error('host validation failed');
    let validationCalls = 0;
    const entry = {
        validateHost(receivedCapabilities, receivedManifest) {
            validationCalls += 1;
            assert.strictEqual(receivedCapabilities, hostCapabilities);
            assert.strictEqual(receivedManifest, secondManifest);
            throw validationError;
        },
    };

    assert.throws(
        () => loadModules({
            hostCapabilities,
            modules: [
                { manifest: relayL2tp.manifest, entry: relayL2tp },
                { manifest: secondManifest, entry },
            ],
        }),
        error => error === validationError,
    );
    assert.equal(validationCalls, 1);
});

test('rejects a descriptor without an entry with a structured error', () => {
    assert.throws(
        () => loadModules({
            hostCapabilities: ['ssh'],
            modules: [{ manifest: relayL2tp.manifest }],
        }),
        {
            name: 'ModuleLoaderError',
            code: 'MODULE_ENTRY_REQUIRED',
            moduleId: 'relay-l2tp',
            descriptorIndex: 0,
        },
    );
});
