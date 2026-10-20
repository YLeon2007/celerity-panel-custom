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
    L2tpPppDriftSyncRepository,
} = require('../repositories/l2tpPppDriftSyncRepository');
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
    PANEL_DOMAIN: TEST_TOPOLOGY_HOST_IDENTITY,
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
        RelayL2tpState: modelWith(['find', 'findOne', 'findOneAndUpdate'], calls),
        L2tpUser: modelWith(['find'], calls),
        L2tpOperation: modelWith(['findOne', 'countDocuments', 'create'], calls),
        NodeSSH: class FakeNodeSSH {},
        TopologyOperation: modelWith(['create', 'findById', 'findOneAndUpdate', 'updateOne'], calls),
        NodeOperationLock: modelWith(['findOne', 'findOneAndUpdate', 'updateOne', 'deleteOne'], calls),
        TopologyExecutionBinding: modelWith(['findOne'], calls),
        TopologyExecutionEnrollment: modelWith(['findById'], calls),
        TopologyConfigOwner: modelWith(['findOne'], calls),
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

test('preinstalled runtime selects finite user and PPP readiness without opening PROD or legacy defaults', () => {
    const deps = compositionDependencies();
    // Composition-only constructor seam; actual-store proof is separate.
    const db = { getClient: () => ({ options: {}, topology: { description: { type: 'ReplicaSetWithPrimary' } } }) };
    for (const name of ['HyNode', 'TopologyOperation', 'NodeOperationLock', 'TopologyExecutionBinding',
        'TopologyExecutionEnrollment', 'TopologyConfigOwner']) {
        deps[name].db = db; deps[name].findOne ??= () => { throw new Error('no reads during assembly'); };
    }
    const service = createTopologyOperationRuntime({ ...deps, topologyExecutionAuthority: {
        runnerTransport: 'preinstalled-attested-v1', async withHeldAuthority() { throw new Error('composition only'); },
    } });
    assert.ok(service.operationWorker);
    assert.equal(service.operationWorker.userResync.restrictedRunner, true);
    assert.equal(service.operationWorker.pppReadinessGate.readOnly, true);
    assert.equal(service.operationWorker.pppResumeReadinessGate.readOnly, true);
    const legacy = createTopologyOperationRuntime(compositionDependencies());
    assert.equal(legacy.operationWorker.userResync.restrictedRunner, false);
    assert.equal(legacy.operationWorker.pppReadinessGate.readOnly, false);
});

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

test('unknown server runner transport refuses runtime composition instead of falling back to shell bootstrap', async () => {
    for (const runnerTransport of [null, true, 'preinstalled', 'shell-fallback']) {
        const calls = [];
        let selections = 0;
        const service = createTopologyOperationRuntime({ ...compositionDependencies(calls),
            topologyExecutionAuthority: { get runnerTransport() { selections++; return runnerTransport; },
                async withHeldAuthority() { assert.fail('no authority invocation during composition'); } },
            createTopologyOperationExecutor() { assert.fail('malformed selection must not reach executor'); } });
        await assertUnavailable(service);
        assert.equal(selections, 1);
        assert.deepEqual(calls, []);
    }
});

test('default typed executor factory constructs TEST and rejects invalid pairs', () => {
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
    assert.equal(typeof service.operationWorker.userResync?.resyncPlan, 'function');
    assert.equal(typeof service.operationWorker.pppReadinessGate?.verifyPlan, 'function');
    assert.deepEqual(calls, []);
});

test('only the exact TEST host enables TEST topology execution', async () => {
    const captured = [];
    class CaptureWorker extends TopologyOperationWorker {
        constructor(options) {
            super(options);
            captured.push(options);
        }
    }
    for (const domain of ['other.invalid', TEST_TOPOLOGY_HOST_IDENTITY]) {
        const dependencies = compositionDependencies();
        const service = createTopologyOperationRuntime({
            ...dependencies,
            env: { ...ENABLED_ENV, PANEL_DOMAIN: domain },
            OperationWorker: CaptureWorker,
        });
        if (domain === TEST_TOPOLOGY_HOST_IDENTITY) {
            assert.ok(service instanceof TopologyOperationCoordinator);
        } else {
            await assertUnavailable(service);
        }
    }
    assert.deepEqual(captured.map(options => options.allowUnprovenTestExecution), [true]);
    assert.ok(captured[0].pppDriftSync instanceof L2tpPppDriftSyncRepository);
    assert.equal(captured[0].pppReadinessGate.readOnly, false);
    assert.equal(captured[0].pppResumeReadinessGate.readOnly, true);
    assert.notStrictEqual(captured[0].pppReadinessGate, captured[0].pppResumeReadinessGate);
});

test('unknown host never constructs a runtime, drift queue or read-only probe', async () => {
    const dependencies = compositionDependencies();
    let queueCapabilityReads = 0;
    for (const [model, method] of [
        [dependencies.RelayL2tpState, 'findOneAndUpdate'],
        [dependencies.L2tpOperation, 'countDocuments'],
    ]) {
        Object.defineProperty(model, method, {
            get() {
                queueCapabilityReads += 1;
                throw new Error('non-TEST host must not construct PPP drift queue');
            },
        });
    }
    const service = createTopologyOperationRuntime({
        ...dependencies,
        env: { ...ENABLED_ENV, PANEL_DOMAIN: 'other.invalid' },
    });
    await assertUnavailable(service);
    assert.equal(queueCapabilityReads, 0);
});

test('flag-positive composed default worker stays unclaimed without quiescence proof', async () => {
    const calls = [];
    const service = createTopologyOperationRuntime({
        ...compositionDependencies(calls),
        env: { ...ENABLED_ENV, PANEL_DOMAIN: 'lm1.infograd.online', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' },
        // A caller-supplied runtime option cannot grant the unit-test-only seam.
        allowUnprovenTestExecution: true,
        NodeSSH: class ForbiddenSSH {
            constructor() {
                calls.push('ssh');
                throw new Error('SSH must not start');
            }
        },
    });

    assert.ok(service instanceof TopologyOperationCoordinator);
    assert.ok(service.operationWorker instanceof TopologyOperationWorker);
    assert.deepEqual(await service.operationWorker.run('operation-1'), {
        claimed: false,
        operationId: 'operation-1',
        stopped: true,
        errorCode: 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN',
    });
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
    let finalizationDependencies;
    class CaptureFinalizationRepository extends TopologyOperationFinalizationRepository {
        constructor(options) {
            super(options);
            finalizationDependencies = options;
        }
    }
    const executor = typedExecutor(calls);
    const dependencies = compositionDependencies(calls);

    const service = createTopologyOperationRuntime({
        ...dependencies,
        FinalizationRepository: CaptureFinalizationRepository,
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
    for (const key of ['TopologyOperation', 'CascadeTopologyState', 'CascadeLink', 'CascadeRouteGroup',
        'RelayL2tpState', 'HyNode', 'L2tpUser', 'L2tpOperation', 'NodeOperationLock',
        'TopologyExecutionBinding', 'TopologyExecutionEnrollment', 'TopologyConfigOwner']) {
        assert.strictEqual(finalizationDependencies[key], dependencies[key], `${key} must be injected explicitly`);
    }
    for (const key of ['NodeOperationLock', 'TopologyExecutionBinding', 'TopologyExecutionEnrollment', 'TopologyConfigOwner']) {
        assert.strictEqual(service.operationWorker.finalizer.repository[key], dependencies[key]);
    }
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

test('default assembled TEST and PROD executors cannot bootstrap without durable V2 authority', async () => {
    const { createHash } = require('node:crypto');
    const { executionFence, freeze } = require('./helpers/topologyV2Fixture');
    const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
    const candidateHash = createHash('sha256').update(content).digest('hex');
    const context = {
        operationId: 'runtime-proof-17', topologyRevision: 17, priorDeployedRevision: 16,
        executionFence,
        node: freeze({ node: 'portal-node', nodeRef: 'portal', role: 'portal',
            targetProfile: 'xray-main', serviceUnit: 'xray.service',
            serviceUnitPath: '/etc/systemd/system/xray.service',
            configPath: '/usr/local/etc/xray/config.json', checks: [], candidateHash,
            candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
                bytes: [...Buffer.from(content)], sha256: candidateHash },
        }),
    };
    for (const hostIdentity of ['test.infograd.online', 'lm1.infograd.online']) {
        const calls = [];
        const env = { ...ENABLED_ENV, PANEL_DOMAIN: hostIdentity, TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' };
        const service = createTopologyOperationRuntime({ ...compositionDependencies(calls), env });
        assert.ok(service instanceof TopologyOperationCoordinator);
        assert.equal(service.operationWorker.executionContext.hostIdentity, hostIdentity);
        env.PANEL_DOMAIN = 'foreign.invalid';
        assert.equal(service.operationWorker.executor.executionProtocolVersion, 2);
        await assert.rejects(service.operationWorker.executor.prepare(context), {
            code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
        });
        assert.deepEqual(calls, [], 'no node lookup, SSH, bootstrap or persistence');
        if (hostIdentity === 'lm1.infograd.online') {
            assert.equal((await service.operationWorker.run(context.operationId)).errorCode,
                'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN');
            assert.deepEqual(calls, [], 'production gate remains before claim');
        }
    }
});
