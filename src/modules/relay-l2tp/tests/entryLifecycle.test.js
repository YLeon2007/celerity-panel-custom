'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const ENTRY_PATH = require.resolve('..');

const LIFECYCLE_EXPORTS = [
    'manifest',
    'validateHost',
    'registerModels',
    'registerMigrations',
    'registerConfigFragments',
    'registerRoutes',
    'createTopologyTransferDraftService',
    'createTopologyDeploymentService',
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
                    || cachePath.includes('/relay-l2tp/migrations/')
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

test('registerRoutes mounts the existing panel router with only injected dependencies', () => {
    const registrationResult = spawnSync(
        process.execPath,
        ['--eval', `
            const assert = require('node:assert/strict');
            const Module = require('node:module');
            const entryPath = ${JSON.stringify(ENTRY_PATH)};
            const originalLoad = Module._load;
            const l2tpRouter = { kind: 'l2tp-router' };
            const factoryCalls = [];

            Module._load = function guardedLoad(request, parent, isMain) {
                if (request === './routes/panel' && parent?.filename === entryPath) {
                    return {
                        createL2tpRouter(dependencies) {
                            factoryCalls.push(dependencies);
                            return l2tpRouter;
                        },
                    };
                }
                assert.equal(
                    /(?:^|\\/)services(?:\\/|$)|(?:^|\\/)workers(?:\\/|$)/.test(request),
                    false,
                    'registerRoutes loaded a service or worker: ' + request,
                );
                return originalLoad.call(this, request, parent, isMain);
            };

            const entry = require(entryPath);
            const mounts = [];
            const context = {
                panelRouter: {
                    use(...args) {
                        mounts.push(args);
                    },
                },
                l2tpService: { kind: 'injected-service' },
                stateManagementService: {
                    kind: 'injected-state-management-service',
                    configureRelay() {},
                },
                userManagementService: {
                    kind: 'injected-user-management-service',
                    createUser() {},
                    listUsers() {},
                    updateUser() {},
                    disableUser() {},
                },
                requireAuth() {},
                requireOnboarding() {},
                csrf() {},
                rateLimiter() {},
                loadPanelOverview() {},
                renderPage() {},
            };

            entry.registerRoutes(context);

            assert.deepEqual(factoryCalls, [{
                l2tpService: context.l2tpService,
                stateManagementService: context.stateManagementService,
                userManagementService: context.userManagementService,
                requireAuth: context.requireAuth,
                requireOnboarding: context.requireOnboarding,
                csrf: context.csrf,
                rateLimiter: context.rateLimiter,
                loadPanelOverview: context.loadPanelOverview,
                renderPage: context.renderPage,
            }]);
            assert.deepEqual(mounts, [['/', l2tpRouter]]);
        `],
        {
            encoding: 'utf8',
            timeout: 1_000,
        },
    );

    assert.equal(registrationResult.error, undefined);
    assert.equal(registrationResult.signal, null);
    assert.equal(registrationResult.status, 0, registrationResult.stderr);
    assert.equal(registrationResult.stdout, '');
    assert.equal(registrationResult.stderr, '');
});

test('registerRoutes rejects every missing injected dependency before creating a router', () => {
    const validationResult = spawnSync(
        process.execPath,
        ['--eval', `
            const assert = require('node:assert/strict');
            const Module = require('node:module');
            const entryPath = ${JSON.stringify(ENTRY_PATH)};
            const originalLoad = Module._load;
            let factoryCalls = 0;

            Module._load = function guardedLoad(request, parent, isMain) {
                if (request === './routes/panel' && parent?.filename === entryPath) {
                    return {
                        createL2tpRouter() {
                            factoryCalls += 1;
                            return {};
                        },
                    };
                }
                return originalLoad.call(this, request, parent, isMain);
            };

            const entry = require(entryPath);
            const baseContext = {
                panelRouter: { use() {} },
                l2tpService: {},
                stateManagementService: { configureRelay() {} },
                userManagementService: {
                    createUser() {},
                    listUsers() {},
                    updateUser() {},
                    disableUser() {},
                },
                requireAuth() {},
                requireOnboarding() {},
                csrf() {},
                rateLimiter() {},
                loadPanelOverview() {},
                renderPage() {},
            };

            assert.throws(() => entry.registerRoutes(), /context/i);
            for (const dependencyName of Object.keys(baseContext)) {
                const context = { ...baseContext };
                delete context[dependencyName];
                assert.throws(
                    () => entry.registerRoutes(context),
                    new RegExp(dependencyName, 'i'),
                );
            }
            assert.equal(factoryCalls, 0);
        `],
        {
            encoding: 'utf8',
            timeout: 1_000,
        },
    );

    assert.equal(validationResult.error, undefined);
    assert.equal(validationResult.signal, null);
    assert.equal(validationResult.status, 0, validationResult.stderr);
    assert.equal(validationResult.stdout, '');
    assert.equal(validationResult.stderr, '');
});

test('registerRoutes rejects a second call without creating or mounting another router', () => {
    const duplicateResult = spawnSync(
        process.execPath,
        ['--eval', `
            const assert = require('node:assert/strict');
            const Module = require('node:module');
            const entryPath = ${JSON.stringify(ENTRY_PATH)};
            const originalLoad = Module._load;
            let factoryCalls = 0;

            Module._load = function guardedLoad(request, parent, isMain) {
                if (request === './routes/panel' && parent?.filename === entryPath) {
                    return {
                        createL2tpRouter() {
                            factoryCalls += 1;
                            return {};
                        },
                    };
                }
                return originalLoad.call(this, request, parent, isMain);
            };

            const entry = require(entryPath);
            let mountCalls = 0;
            const context = {
                panelRouter: {
                    use() {
                        mountCalls += 1;
                    },
                },
                l2tpService: {},
                stateManagementService: { configureRelay() {} },
                userManagementService: {
                    createUser() {},
                    listUsers() {},
                    updateUser() {},
                    disableUser() {},
                },
                requireAuth() {},
                requireOnboarding() {},
                csrf() {},
                rateLimiter() {},
                loadPanelOverview() {},
                renderPage() {},
            };

            entry.registerRoutes(context);
            assert.throws(() => entry.registerRoutes(context), /already|twice|once/i);
            assert.equal(factoryCalls, 1);
            assert.equal(mountCalls, 1);
        `],
        {
            encoding: 'utf8',
            timeout: 1_000,
        },
    );

    assert.equal(duplicateResult.error, undefined);
    assert.equal(duplicateResult.signal, null);
    assert.equal(duplicateResult.status, 0, duplicateResult.stderr);
    assert.equal(duplicateResult.stdout, '');
    assert.equal(duplicateResult.stderr, '');
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
        'RelayL2tpMigrationState',
        'RelayL2tpTopologyTransferDraft',
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
        'RelayL2tpMigrationState',
        'RelayL2tpTopologyTransferDraft',
    ];
    const expectedModels = {
        RelayL2tpState: require('../models/relayL2tpStateModel'),
        L2tpUser: require('../models/l2tpUserModel'),
        CascadeRouteGroup: require('../models/cascadeRouteGroupModel'),
        CascadeTopologyState: require('../models/cascadeTopologyStateModel'),
        L2tpOperation: require('../models/l2tpOperationModel'),
        TopologyOperation: require('../models/topologyOperationModel'),
        NodeOperationLock: require('../models/nodeOperationLockModel'),
        RelayL2tpMigrationState: require('../models/relayL2tpMigrationStateModel'),
        RelayL2tpTopologyTransferDraft: require('../models/relayL2tpTopologyTransferDraftModel'),
    };

    assert.deepEqual(Object.keys(models), expectedNames);
    for (const modelName of expectedNames) {
        assert.strictEqual(models[modelName], expectedModels[modelName]);
    }
    assert.deepEqual(registrations, Object.entries(expectedModels));
    assert.equal(mongoose.connection.readyState, connectionStateBefore);
});

test('root service factory lazily composes the topology transfer draft service', () => {
    const models = {
        HyNode: {},
        CascadeLink: {},
        CascadeRouteGroup: {},
        RelayL2tpState: {},
        RelayL2tpTopologyTransferDraft: {},
    };
    const calls = [];
    class Repository {
        constructor(dependencies) {
            calls.push(dependencies);
        }
    }

    const service = require('..').createTopologyTransferDraftService({
        ...models,
        Repository,
    });

    assert.equal(typeof service.exportCurrentTopology, 'function');
    assert.equal(typeof service.importTopologyDraft, 'function');
    assert.deepEqual(calls, [models]);
});

test('root deployment factory stays unavailable without the exact test runtime opt-in', async () => {
    const entry = require('..');
    assert.equal(typeof entry.createTopologyTransferDraftService, 'function');
    assert.equal(typeof entry.createTopologyDeploymentService, 'function');

    const calls = [];
    const unavailable = entry.createTopologyDeploymentService({
        env: {
            L2TP_EXECUTION_ENABLED: 'true',
            L2TP_MIGRATIONS_ENABLED: 'true',
        },
        createTopologyOperationExecutor() {
            calls.push('createTopologyOperationExecutor');
            throw new Error('must not create an executor in disabled mode');
        },
        cascadeNodeDeployer: {
            async deployNode() {
                calls.push('legacy.deployNode');
            },
        },
        cascadeNodeVerifier: {
            async verifyNode() {
                calls.push('legacy.verifyNode');
            },
        },
        cascadeNodeRestorer: {
            async restoreNode() {
                calls.push('legacy.restoreNode');
            },
        },
    });

    await assert.rejects(
        unavailable.deploy({ expectedTopologyRevision: 7 }),
        error => error?.code === 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE',
    );
    assert.deepEqual(calls, []);
});

test('root deployment factory exposes only the exact opted-in queued composition', () => {
    const entry = require('..');
    const calls = [];
    const executor = {
        async prepare() {},
        async commit() {},
        async verify() {},
        async cleanupPrepared() {},
        async rollback() {},
    };
    class SnapshotRepository {
        constructor(dependencies) {
            calls.push({ kind: 'snapshot', dependencies });
        }

        async readDraft() {}
    }
    class DeploymentRepository {
        constructor(dependencies) {
            calls.push({ kind: 'deployment', dependencies });
        }

        async pinTopology() {}

        async markDeployed() {}
    }
    class PlanMaterializer {
        constructor(dependencies) {
            calls.push({ kind: 'materializer', dependencies });
        }

        async materialize() {}
    }
    class OperationRepository {
        constructor(dependencies) {
            calls.push({ kind: 'operationRepository', dependencies });
        }

        async createFrozen() {}
    }
    class OperationWorker {
        constructor(dependencies) {
            calls.push({ kind: 'worker', dependencies });
        }

        async run() {}
    }
    class Coordinator {
        constructor(dependencies) {
            calls.push({ kind: 'coordinator', dependencies });
        }

        async deploy() {
            return { status: 'queued' };
        }
    }
    const models = {
        HyNode: {},
        CascadeLink: {},
        CascadeRouteGroup: {},
        CascadeTopologyState: { updateOne() {} },
        RelayL2tpState: {},
        TopologyOperation: { updateOne() {} },
        NodeOperationLock: {},
    };

    const service = entry.createTopologyDeploymentService({
        ...models,
        env: {
            L2TP_EXECUTION_ENABLED: 'true',
            L2TP_MIGRATIONS_ENABLED: 'true',
            TOPOLOGY_TEST_EXECUTION_ENABLED: 'true',
        },
        createTopologyOperationExecutor(dependencies) {
            calls.push({ kind: 'executor', dependencies });
            return executor;
        },
        SnapshotRepository,
        DeploymentRepository,
        PlanMaterializer,
        OperationRepository,
        OperationWorker,
        Coordinator,
        transactionRunner: async work => work(),
        clock: { now: () => new Date('2026-09-23T00:00:00.000Z') },
        workerId: 'entry-topology-test-worker',
        leaseMs: 30_000,
    });

    assert.ok(service instanceof Coordinator);
    assert.deepEqual(calls.map(call => call.kind), [
        'snapshot',
        'deployment',
        'materializer',
        'operationRepository',
        'executor',
        'worker',
        'coordinator',
    ]);
    assert.equal(calls.some(call => call.kind === 'worker.run'), false);
});

test('registerMigrations lazily registers the ordered module migration registry', () => {
    const entry = require('..');
    const registrations = [];
    const migrationRegistry = {
        register(moduleId, migration) {
            registrations.push([moduleId, migration]);
        },
    };

    const migrations = entry.registerMigrations({ migrationRegistry });

    assert.deepEqual(migrations.map(migration => migration.id), [
        '001-ensure-module-indexes',
    ]);
    assert.deepEqual(registrations, migrations.map(migration => [
        entry.manifest.id,
        migration,
    ]));
    assert.strictEqual(entry.registerMigrations(), migrations);
});

test('registerConfigFragments registers only relay-l2tp with the existing fragment provider', () => {
    const entry = require('..');
    const { createConfigFragmentRegistry } = require('../../../services/configFragmentRegistry');
    const { buildL2tpXrayFragment } = require('../services/l2tpXrayFragmentProvider');
    const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
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
            group: { id: 'route-group-a' },
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
    assert.deepEqual(fragment.outbounds, [{
        tag: 'cascade-primary',
        protocol: 'socks',
        settings: {
            servers: [{
                address: '127.0.0.1',
                port: cascadePathIngressPort('route-group-a', 'primary'),
            }],
        },
    }]);
});
