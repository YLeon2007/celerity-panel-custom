'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const ENTRY_PATH = require.resolve('..');

const LIFECYCLE_EXPORTS = [
    'manifest',
    'validateHost',
    'registerModels',
    'registerConfigFragments',
];

test('imports the lifecycle entry without loading runtime integrations', () => {
    const importResult = spawnSync(
        process.execPath,
        ['--eval', `
            const assert = require('node:assert/strict');
            const Module = require('node:module');
            const forbidden = new Set([
                'express',
                'mongoose',
                'ssh2',
                'fs',
                'node:fs',
            ]);
            const originalLoad = Module._load;

            Module._load = function guardedLoad(request, parent, isMain) {
                assert.equal(
                    forbidden.has(request),
                    false,
                    'entry import loaded forbidden runtime dependency: ' + request,
                );
                return originalLoad.call(this, request, parent, isMain);
            };

            const entry = require(${JSON.stringify(ENTRY_PATH)});
            assert.deepEqual(Object.keys(entry), ${JSON.stringify(LIFECYCLE_EXPORTS)});
            for (const hook of ${JSON.stringify(LIFECYCLE_EXPORTS.slice(1))}) {
                assert.equal(typeof entry[hook], 'function');
            }
            assert.equal(
                Object.keys(require.cache).some(cachePath => (
                    cachePath.includes('/relay-l2tp/models/')
                    || cachePath.endsWith('/l2tpXrayFragmentProvider.js')
                )),
                false,
                'entry import eagerly loaded lifecycle dependencies',
            );
        `],
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

test('registerModels returns the module model constructors without a registry hook', () => {
    const models = require('..').registerModels({});

    assert.deepEqual(Object.keys(models), [
        'RelayL2tpState',
        'L2tpUser',
        'CascadeRouteGroup',
        'CascadeTopologyState',
        'L2tpOperation',
        'TopologyOperation',
        'NodeOperationLock',
    ]);
});

test('registerModels registers and returns the exact module model constructors', () => {
    const entry = require('..');
    const mongoose = require('mongoose');
    const connectionStateBefore = mongoose.connection.readyState;
    const registrations = [];
    const modelRegistry = {
        register(modelName, modelConstructor) {
            registrations.push([modelName, modelConstructor]);
        },
    };

    const models = entry.registerModels({ modelRegistry });
    const expectedNames = [
        'RelayL2tpState',
        'L2tpUser',
        'CascadeRouteGroup',
        'CascadeTopologyState',
        'L2tpOperation',
        'TopologyOperation',
        'NodeOperationLock',
    ];
    const expectedModels = {
        RelayL2tpState: require('../models/relayL2tpStateModel'),
        L2tpUser: require('../models/l2tpUserModel'),
        CascadeRouteGroup: require('../models/cascadeRouteGroupModel'),
        CascadeTopologyState: require('../models/cascadeTopologyStateModel'),
        L2tpOperation: require('../models/l2tpOperationModel'),
        TopologyOperation: require('../models/topologyOperationModel'),
        NodeOperationLock: require('../models/nodeOperationLockModel'),
    };

    assert.deepEqual(Object.keys(models), expectedNames);
    for (const modelName of expectedNames) {
        assert.strictEqual(models[modelName], expectedModels[modelName]);
    }
    assert.deepEqual(registrations, Object.entries(expectedModels));
    assert.equal(mongoose.connection.readyState, connectionStateBefore);
});

test('registerConfigFragments registers only relay-l2tp with the existing fragment provider', () => {
    const entry = require('..');
    const { createConfigFragmentRegistry } = require('../../../services/configFragmentRegistry');
    const { buildL2tpXrayFragment } = require('../services/l2tpXrayFragmentProvider');
    const registry = createConfigFragmentRegistry(['relay-l2tp']);
    const registrations = [];
    const configFragmentRegistry = {
        register(providerId, provider) {
            registrations.push([providerId, provider]);
            registry.register(providerId, provider);
        },
    };

    entry.registerConfigFragments({ configFragmentRegistry });

    assert.deepEqual(registrations, [[entry.manifest.id, buildL2tpXrayFragment]]);
    assert.equal(registrations[0][0], 'relay-l2tp');

    const [fragment] = registry.compose({
        plan: {
            relay: { controlPlaneIps: ['198.51.100.10'] },
            paths: [{
                pathKey: 'primary',
                healthy: true,
                outboundTag: 'cascade-primary',
            }],
            selectedPathKey: 'primary',
        },
        tags: {
            inbound: 'relay-l2tp-route-group-a',
            blockOutbound: 'block',
        },
        tproxyPort: 12345,
    });

    assert.equal(fragment.id, 'relay-l2tp');
    assert.equal(fragment.inbounds[0].tag, 'relay-l2tp-route-group-a');
    assert.equal(fragment.routingRules.at(-1).outboundTag, 'cascade-primary');
});
