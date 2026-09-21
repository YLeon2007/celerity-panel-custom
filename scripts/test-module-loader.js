'use strict';

const assert = require('assert');
const { createModuleRegistry } = require('../src/modules/moduleRegistry');
const relayManifest = require('../src/modules/relay-l2tp/manifest.json');

function createManifest(overrides = {}) {
    return {
        id: 'relay-l2tp',
        version: '0.1.0',
        moduleApiVersion: 1,
        requiredCapabilities: ['ssh'],
        ...overrides,
    };
}

function testValidRelayManifestRegistersOnce() {
    const registry = createModuleRegistry(['ssh']);

    registry.register(relayManifest, {});

    assert.deepStrictEqual(registry.list(), [relayManifest]);
}

function testMissingCapabilityRejectsBeforeLifecycle() {
    const registry = createModuleRegistry([]);
    const manifest = createManifest();
    let lifecycleCalls = 0;
    const moduleImplementation = {
        initialize() { lifecycleCalls += 1; },
        start() { lifecycleCalls += 1; },
        stop() { lifecycleCalls += 1; },
    };

    assert.throws(
        () => registry.register(manifest, moduleImplementation),
        /missing required capabilities: ssh/i,
    );
    assert.strictEqual(lifecycleCalls, 0);
    assert.deepStrictEqual(registry.list(), []);
}

function testDuplicateIdRejects() {
    const registry = createModuleRegistry(['ssh']);
    const manifest = createManifest();

    registry.register(manifest, {});

    assert.throws(
        () => registry.register({ ...manifest, version: '0.2.0' }, {}),
        /module id already registered: relay-l2tp/i,
    );
    assert.deepStrictEqual(registry.list(), [manifest]);
}

function testModuleImportHasNoRegistrationSideEffects() {
    const registry = createModuleRegistry(['ssh']);

    const relayL2tp = require('../src/modules/relay-l2tp');

    assert.strictEqual(relayL2tp.manifest.moduleApiVersion, 1);
    assert.doesNotThrow(() => registry.validate(relayL2tp.manifest));
    assert.deepStrictEqual(registry.list(), []);
}

function testManifestRequiresMetadataFields() {
    const registry = createModuleRegistry(['ssh']);
    const manifest = createManifest();

    for (const field of ['id', 'version', 'moduleApiVersion', 'requiredCapabilities']) {
        const invalidManifest = { ...manifest };
        delete invalidManifest[field];

        assert.throws(
            () => registry.validate(invalidManifest),
            new RegExp(`manifest\\.${field}`),
        );
    }
}

function testManifestRequiresSupportedApiVersion() {
    const registry = createModuleRegistry(['ssh']);
    const manifest = {
        id: 'relay-l2tp',
        version: '0.1.0',
        moduleApiVersion: 2,
        requiredCapabilities: ['ssh'],
    };

    assert.throws(
        () => registry.validate(manifest),
        /unsupported module api version: 2/i,
    );
}

function testManifestFieldTypes() {
    const registry = createModuleRegistry(['ssh']);
    const manifest = createManifest();
    const invalidFields = [
        ['id', ''],
        ['version', ''],
        ['requiredCapabilities', 'ssh'],
        ['requiredCapabilities', ['']],
    ];

    for (const [field, value] of invalidFields) {
        assert.throws(
            () => registry.validate({ ...manifest, [field]: value }),
            new RegExp(`manifest\\.${field}`),
        );
    }
}

testValidRelayManifestRegistersOnce();
testMissingCapabilityRejectsBeforeLifecycle();
testDuplicateIdRejects();
testModuleImportHasNoRegistrationSideEffects();
testManifestRequiresMetadataFields();
testManifestRequiresSupportedApiVersion();
testManifestFieldTypes();

console.log('test-module-loader: OK');
