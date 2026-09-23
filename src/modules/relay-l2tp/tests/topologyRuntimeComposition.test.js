'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    REQUIRED_TEST_RUNTIME_FLAGS,
    createTopologyOperationExecutor,
    createTopologyOperationRuntime,
    isTopologyTestExecutionEnabled,
} = require('../runtime/createTopologyOperationRuntime');
const {
    TopologyDeploymentRepository,
} = require('../repositories/topologyDeploymentRepository');
const {
    TopologyDraftRepository,
} = require('../repositories/topologyDraftRepository');
const {
    TopologyOperationRepository,
} = require('../repositories/topologyOperationRepository');
const {
    TEST_TOPOLOGY_HOST_IDENTITY,
    TEST_TOPOLOGY_TARGET,
    TopologyOperationPlanMaterializer,
} = require('../services/topologyOperationPlanMaterializer');
const {
    TopologyOperationExecutor,
} = require('../services/topologyOperationExecutor');
const {
    TopologyOperationCoordinator,
} = require('../services/topologyOperationCoordinator');
const {
    TopologyOperationWorker,
} = require('../workers/topologyOperationWorker');
const {
    TopologyOperationFinalizationRepository,
} = require('../repositories/topologyOperationFinalizationRepository');
const {
    TopologyOperationFinalizer,
} = require('../services/topologyOperationFinalizer');
const {
    NodeOperationLockRepository,
} = require('../services/nodeOperationLockRepository');
const {
    NodeOperationLockService,
} = require('../services/nodeOperationLockService');

const ENABLED_ENV = Object.freeze({
    L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'true',
});

async function assertUnavailable(service) {
    await assert.rejects(
        service.deploy({ expectedTopologyRevision: 7 }),
        error => {
            assert.equal(error.code, 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
            assert.equal(error.message, 'Topology deployment capabilities are unavailable');
            return true;
        },
    );
}

function modelWith(methodNames, calls) {
    return Object.fromEntries(methodNames.map(methodName => [methodName, () => {
        calls.push(methodName);
        throw new Error(`unexpected model call: ${methodName}`);
    }]));
}

function compositionDependencies(calls = []) {
    return {
        env: ENABLED_ENV,
        HyNode: modelWith(['find', 'findById'], calls),
        CascadeLink: modelWith(['find', 'create', 'updateOne', 'deleteOne'], calls),
        CascadeRouteGroup: modelWith(['find', 'create', 'updateOne', 'deleteOne'], calls),
        CascadeTopologyState: modelWith(['findById', 'findOneAndUpdate', 'updateOne'], calls),
        RelayL2tpState: modelWith(['find'], calls),
        TopologyOperation: modelWith(['create', 'findOneAndUpdate', 'updateOne'], calls),
        NodeOperationLock: modelWith(['findOne', 'findOneAndUpdate', 'updateOne', 'deleteOne'], calls),
        transactionRunner: async work => work({ id: 'test-session' }),
        clock: {
            now() {
                calls.push('clock.now');
                throw new Error('worker must not start during composition');
            },
        },
        workerId: 'topology-test-worker',
        leaseMs: 30_000,
    };
}

function typedExecutor(calls) {
    return Object.freeze(Object.fromEntries([
        'prepare',
        'commit',
        'verify',
        'cleanupPrepared',
        'rollback',
    ].map(methodName => [methodName, async () => {
        calls.push(`executor.${methodName}`);
        throw new Error(`worker must not call executor.${methodName} during composition`);
    }])));
}

test('test topology runtime requires all three exact opt-in flags', async () => {
    assert.deepEqual(REQUIRED_TEST_RUNTIME_FLAGS, [
        'L2TP_EXECUTION_ENABLED',
        'L2TP_MIGRATIONS_ENABLED',
        'TOPOLOGY_TEST_EXECUTION_ENABLED',
    ]);
    assert.equal(isTopologyTestExecutionEnabled(ENABLED_ENV), true);

    const disabledEnvironments = [
        {},
        ...REQUIRED_TEST_RUNTIME_FLAGS.flatMap(flagName => [
            { ...ENABLED_ENV, [flagName]: undefined },
            { ...ENABLED_ENV, [flagName]: 'false' },
            { ...ENABLED_ENV, [flagName]: 'TRUE' },
            { ...ENABLED_ENV, [flagName]: true },
        ]),
    ];

    for (const env of disabledEnvironments) {
        let resolverCapabilityReads = 0;
        const guardedHyNode = {};
        Object.defineProperty(guardedHyNode, 'findById', {
            get() {
                resolverCapabilityReads += 1;
                throw new Error('default executor factory must remain disabled');
            },
        });
        const defaultService = createTopologyOperationRuntime({
            env,
            HyNode: guardedHyNode,
            NodeSSH: class FakeNodeSSH {},
        });
        await assertUnavailable(defaultService);
        assert.equal(resolverCapabilityReads, 0, JSON.stringify(env));

        let lockModelReads = 0;
        const guardedDependencies = {
            env,
            createTopologyOperationExecutor() {
                throw new Error('default executor factory must remain disabled');
            },
        };
        Object.defineProperty(guardedDependencies, 'NodeOperationLock', {
            get() {
                lockModelReads += 1;
                throw new Error('disabled runtime must not read the lock model');
            },
        });
        await assertUnavailable(createTopologyOperationRuntime(guardedDependencies));
        assert.equal(lockModelReads, 0, JSON.stringify(env));

        let executorFactoryCalls = 0;
        let workerConstructions = 0;
        const service = createTopologyOperationRuntime({
            env,
            createTopologyOperationExecutor() {
                executorFactoryCalls += 1;
                return typedExecutor([]);
            },
            OperationWorker: class {
                constructor() {
                    workerConstructions += 1;
                }
            },
        });

        await assertUnavailable(service);
        assert.equal(executorFactoryCalls, 0, JSON.stringify(env));
        assert.equal(workerConstructions, 0, JSON.stringify(env));
    }
});

test('default typed executor factory only constructs the fixed test contour', () => {
    const HyNode = modelWith(['findById'], []);
    class FakeNodeSSH {}

    const executor = createTopologyOperationExecutor({
        HyNode,
        NodeSSH: FakeNodeSSH,
        target: TEST_TOPOLOGY_TARGET,
        hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY,
    });

    assert.ok(executor instanceof TopologyOperationExecutor);
    for (const contour of [
        { target: 'production', hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY },
        { target: TEST_TOPOLOGY_TARGET, hostIdentity: 'panel.infograd.online' },
        { target: TEST_TOPOLOGY_TARGET, hostIdentity: undefined },
    ]) {
        assert.equal(createTopologyOperationExecutor({
            HyNode,
            NodeSSH: FakeNodeSSH,
            ...contour,
        }), undefined);
    }
});

test('enabled composition builds the real typed executor with the injected NodeSSH adapter', () => {
    const calls = [];
    const dependencies = compositionDependencies(calls);
    class FakeNodeSSH {}

    const service = createTopologyOperationRuntime({
        ...dependencies,
        NodeSSH: FakeNodeSSH,
    });

    assert.ok(service instanceof TopologyOperationCoordinator);
    assert.ok(service.operationWorker.executor instanceof TopologyOperationExecutor);
    assert.deepEqual(calls, []);
});

test('enabled composition rejects invalid typed executor factory overrides and fails closed', async () => {
    for (const createTopologyOperationExecutor of [
        null,
        () => undefined,
        () => ({}),
        () => Promise.resolve(typedExecutor([])),
        () => { throw new Error('private executor construction detail'); },
    ]) {
        const service = createTopologyOperationRuntime({
            ...compositionDependencies(),
            createTopologyOperationExecutor,
        });

        await assertUnavailable(service);
    }
});

test('enabled composition wires the queued topology runtime without starting its worker', () => {
    const calls = [];
    let executorFactoryDependencies;
    const executor = typedExecutor(calls);
    const dependencies = compositionDependencies(calls);

    const service = createTopologyOperationRuntime({
        ...dependencies,
        createTopologyOperationExecutor(candidateDependencies) {
            calls.push('createTopologyOperationExecutor');
            executorFactoryDependencies = candidateDependencies;
            return executor;
        },
    });

    assert.ok(service instanceof TopologyOperationCoordinator);
    assert.ok(service.topologyRepository instanceof TopologyDeploymentRepository);
    assert.ok(service.topologyRepository.snapshotReader instanceof TopologyDraftRepository);
    assert.strictEqual(service.topologyRepository.CascadeTopologyState, dependencies.CascadeTopologyState);
    assert.strictEqual(service.topologyRepository.snapshotReader.HyNode, dependencies.HyNode);
    assert.strictEqual(
        service.topologyRepository.snapshotReader.CascadeLink,
        dependencies.CascadeLink,
    );
    assert.strictEqual(
        service.topologyRepository.snapshotReader.CascadeRouteGroup,
        dependencies.CascadeRouteGroup,
    );
    assert.strictEqual(
        service.topologyRepository.snapshotReader.RelayL2tpState,
        dependencies.RelayL2tpState,
    );
    assert.ok(service.planMaterializer instanceof TopologyOperationPlanMaterializer);
    assert.ok(service.operationRepository instanceof TopologyOperationRepository);
    assert.strictEqual(service.operationRepository.model, dependencies.TopologyOperation);
    assert.ok(service.operationWorker instanceof TopologyOperationWorker);
    assert.strictEqual(service.operationWorker.operationRepository, service.operationRepository);
    assert.strictEqual(service.operationWorker.executor, executor);
    assert.ok(service.operationWorker.finalizer instanceof TopologyOperationFinalizer);
    assert.ok(service.operationWorker.finalizer.repository instanceof TopologyOperationFinalizationRepository);
    assert.strictEqual(
        service.operationWorker.finalizer.repository.TopologyOperation,
        dependencies.TopologyOperation,
    );
    assert.strictEqual(
        service.operationWorker.finalizer.repository.CascadeTopologyState,
        dependencies.CascadeTopologyState,
    );
    assert.strictEqual(
        service.operationWorker.finalizer.repository.transactionRunner,
        dependencies.transactionRunner,
    );
    assert.ok(service.operationWorker.lockService instanceof NodeOperationLockService);
    assert.ok(service.operationWorker.lockService.repository instanceof NodeOperationLockRepository);
    assert.strictEqual(
        service.operationWorker.lockService.repository.model,
        dependencies.NodeOperationLock,
    );
    assert.strictEqual(service.operationWorker.lockService.clock, dependencies.clock);
    assert.equal(service.operationWorker.workerId, dependencies.workerId);
    assert.equal(service.operationWorker.leaseMs, dependencies.leaseMs);
    assert.deepEqual(executorFactoryDependencies, {
        HyNode: dependencies.HyNode,
        hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY,
        target: TEST_TOPOLOGY_TARGET,
    });
    assert.deepEqual(calls, ['createTopologyOperationExecutor']);
});
