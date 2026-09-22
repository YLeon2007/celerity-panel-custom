'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { createL2tpPanelHost } = require('../createL2tpPanelHost');
const { L2tpNodeTransport } = require('../relay-l2tp/services/l2tpNodeTransport');
const { NodeOperationLockService } = require('../relay-l2tp/services/nodeOperationLockService');

function passThrough(req, res, next) {
    next();
}

function createHost(overrides = {}) {
    const models = overrides.models || {
        RelayL2tpState: { modelName: 'RelayL2tpState' },
        CascadeRouteGroup: { modelName: 'CascadeRouteGroup' },
        CascadeTopologyState: { modelName: 'CascadeTopologyState' },
        L2tpOperation: { modelName: 'L2tpOperation' },
        NodeOperationLock: { modelName: 'NodeOperationLock' },
    };
    const runtimeCalls = [];
    const runtime = overrides.runtime || {
        service: { kind: 'service' },
        worker: { async runOnce() {} },
        router: { kind: 'router' },
    };

    const host = createL2tpPanelHost({
        requireAuth: passThrough,
        requireOnboarding: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
        renderPage() {},
        moduleEntry: { registerModels: () => models },
        HyNode: { modelName: 'HyNode' },
        CascadeLink: { modelName: 'CascadeLink' },
        topologyRuntime: {},
        Repository: class FakeRepository {},
        createRepositoryAdapters: () => ({
            nodeRepository: { kind: 'node-repository' },
            stateRepository: { kind: 'state-repository' },
            operationRepository: { kind: 'operation-repository' },
        }),
        createPanelOverviewLoader: () => async () => ({}),
        createRuntime(dependencies) {
            runtimeCalls.push(dependencies);
            return runtime;
        },
        ...overrides,
        models: undefined,
        runtime: undefined,
    });

    return { host, models, runtime, runtimeCalls };
}

test('uses the dormant path unless activation is the literal boolean true and complete', async () => {
    for (const workerLifecycle of [
        undefined,
        { enabled: false },
        { enabled: 'true' },
        { enabled: 1 },
        { enabled: true },
    ]) {
        const constructions = [];
        const preflightRunner = async () => ({ ok: true });
        const artifactMaterializer = async () => [];
        const options = {
            workerLifecycle,
            createTransportFactory() {
                constructions.push({ kind: 'transport-factory' });
                throw new Error('transport factory must remain dormant');
            },
            nodeSSHFactory(node) {
                constructions.push({ kind: 'ssh', node });
                return { node };
            },
            NodeTransport: class FakeNodeTransport {
                constructor(dependencies) {
                    constructions.push({ kind: 'transport', dependencies });
                }
            },
            NodeOperationLockService: class FakeLockService {
                constructor(dependencies) {
                    constructions.push({ kind: 'lock-service', dependencies });
                }
            },
            NodeOperationLockRepository: class FakeLockRepository {
                constructor(dependencies) {
                    constructions.push({ kind: 'lock-repository', dependencies });
                }
            },
            preflightRunner,
            ...(workerLifecycle?.enabled === true ? {} : { artifactMaterializer }),
            createWorkerLifecycle(dependencies) {
                constructions.push({ kind: 'lifecycle', dependencies });
                return {
                    start() { constructions.push({ kind: 'start' }); },
                    async stop() { constructions.push({ kind: 'stop' }); },
                };
            },
        };
        const { host, runtimeCalls } = createHost(options);

        assert.equal(runtimeCalls.length, 1);
        assert.notStrictEqual(runtimeCalls[0].preflightRunner, preflightRunner);
        assert.equal(runtimeCalls[0].artifactMaterializer, undefined);
        assert.equal(runtimeCalls[0].transportFactory, undefined);
        assert.equal(typeof runtimeCalls[0].transport.uploadRootFile, 'function');
        assert.equal(constructions.length, 0);
        assert.deepEqual(host.start(), {
            enabled: false,
            running: false,
            inFlight: false,
        });
        assert.deepEqual(await host.stop(), {
            enabled: false,
            running: false,
            inFlight: false,
        });
        assert.equal(constructions.length, 0);
    }
});

test('explicit complete activation composes lock service and a typed transport factory', () => {
    const constructions = [];
    const clock = { now: () => new Date('2026-09-22T12:00:00.000Z') };
    const preflightRunner = async () => ({ ok: true });
    const artifactMaterializer = async () => [];
    const workerLifecycle = {
        enabled: true,
        intervalMs: 2_500,
        timer: { setInterval() {}, clearInterval() {} },
        logger: { error() {} },
    };

    class FakeLockRepository {
        constructor(dependencies) {
            this.kind = 'lock-repository';
            constructions.push({ kind: 'lock-repository', dependencies, instance: this });
        }
    }
    class FakeLockService {
        constructor(dependencies) {
            this.kind = 'lock-service';
            constructions.push({ kind: 'lock-service', dependencies, instance: this });
        }
    }
    class FakeNodeTransport {
        constructor(dependencies) {
            this.kind = 'node-transport';
            constructions.push({ kind: 'node-transport', dependencies, instance: this });
        }
    }
    function nodeSSHFactory(node) {
        const nodeSSH = { kind: 'node-ssh', node };
        constructions.push({ kind: 'node-ssh', node, instance: nodeSSH });
        return nodeSSH;
    }

    const { host, models, runtime, runtimeCalls } = createHost({
        clock,
        workerLifecycle,
        preflightRunner,
        artifactMaterializer,
        nodeSSHFactory,
        NodeTransport: FakeNodeTransport,
        NodeOperationLockService: FakeLockService,
        NodeOperationLockRepository: FakeLockRepository,
        createTransportFactory(dependencies) {
            constructions.push({ kind: 'transport-factory', dependencies });
            return node => new dependencies.NodeTransport({
                nodeSSH: dependencies.nodeSSHFactory(node),
            });
        },
        createWorkerLifecycle(dependencies) {
            constructions.push({ kind: 'lifecycle', dependencies });
            return {
                start() {
                    constructions.push({ kind: 'start' });
                    return {
                        enabled: true,
                        running: true,
                        inFlight: false,
                        privateKey: 'lifecycle-start-secret',
                    };
                },
                async stop() {
                    constructions.push({ kind: 'stop' });
                    return {
                        enabled: true,
                        running: false,
                        inFlight: false,
                        privateKey: 'lifecycle-stop-secret',
                    };
                },
            };
        },
    });

    assert.deepEqual(
        constructions.map(construction => construction.kind),
        ['lock-repository', 'lock-service', 'transport-factory', 'lifecycle'],
    );
    assert.strictEqual(constructions[0].dependencies.model, models.NodeOperationLock);
    assert.strictEqual(constructions[1].dependencies.repository, constructions[0].instance);
    assert.strictEqual(constructions[1].dependencies.clock, clock);
    assert.strictEqual(constructions[2].dependencies.nodeSSHFactory, nodeSSHFactory);
    assert.strictEqual(constructions[2].dependencies.NodeTransport, FakeNodeTransport);
    assert.strictEqual(runtimeCalls[0].operationModel, models.L2tpOperation);
    assert.strictEqual(runtimeCalls[0].preflightRunner, preflightRunner);
    assert.strictEqual(runtimeCalls[0].artifactMaterializer, artifactMaterializer);
    assert.strictEqual(runtimeCalls[0].lockService, constructions[1].instance);
    assert.equal(runtimeCalls[0].transport, undefined);
    assert.equal(typeof runtimeCalls[0].transportFactory, 'function');
    assert.strictEqual(constructions[3].dependencies.worker, runtime.worker);
    assert.deepEqual(constructions[3].dependencies, {
        ...workerLifecycle,
        worker: runtime.worker,
    });

    const operation = { id: 'operation-a', node: 'node-a' };
    const firstTransport = runtimeCalls[0].transportFactory(operation.node);

    assert.equal(firstTransport.kind, 'node-transport');
    assert.deepEqual(
        constructions.slice(4).map(construction => construction.kind),
        ['node-ssh', 'node-transport'],
    );
    assert.equal(constructions[4].node, operation.node);
    assert.strictEqual(constructions[5].dependencies.nodeSSH, constructions[4].instance);
    assert.deepEqual(host.start(), {
        enabled: true,
        running: true,
        inFlight: false,
    });
    assert.deepEqual(constructions.slice(6), [{ kind: 'start' }]);
});

test('active stop remains explicit and returns a safe lifecycle summary', async () => {
    const lifecycleCalls = [];
    const { host } = createHost({
        workerLifecycle: { enabled: true },
        preflightRunner: async () => ({ ok: true }),
        artifactMaterializer: async () => [],
        nodeSSHFactory: () => ({}),
        NodeTransport: class FakeNodeTransport {},
        NodeOperationLockRepository: class FakeLockRepository {},
        NodeOperationLockService: class FakeLockService {},
        createTransportFactory: () => () => ({}),
        createWorkerLifecycle() {
            return {
                start() {
                    lifecycleCalls.push('start');
                    return { enabled: true, running: true, inFlight: false };
                },
                async stop() {
                    lifecycleCalls.push('stop');
                    return {
                        enabled: true,
                        running: false,
                        inFlight: false,
                        privateKey: 'lifecycle-stop-secret',
                    };
                },
            };
        },
    });

    assert.deepEqual(lifecycleCalls, []);
    assert.deepEqual(await host.stop(), {
        enabled: true,
        running: false,
        inFlight: false,
    });
    assert.deepEqual(lifecycleCalls, ['stop']);
});

test('complete activation is production-wirable with the concrete component defaults', () => {
    const nodeSSH = { async exec() {} };
    const preflightRunner = async () => ({ ok: true });
    const artifactMaterializer = async () => [];
    const { runtimeCalls } = createHost({
        workerLifecycle: {
            enabled: true,
            intervalMs: 1_000,
            timer: { setInterval() { return {}; }, clearInterval() {} },
            logger: { error() {} },
        },
        nodeSSHFactory: () => nodeSSH,
        preflightRunner,
        artifactMaterializer,
    });

    assert.equal(runtimeCalls.length, 1);
    assert.strictEqual(runtimeCalls[0].preflightRunner, preflightRunner);
    assert.strictEqual(runtimeCalls[0].artifactMaterializer, artifactMaterializer);
    assert.ok(runtimeCalls[0].lockService instanceof NodeOperationLockService);
    const transport = runtimeCalls[0].transportFactory('node-default');
    assert.ok(transport instanceof L2tpNodeTransport);
    assert.strictEqual(transport.nodeSSH, nodeSSH);
});
