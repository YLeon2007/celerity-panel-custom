'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { executionFence, freeze } = require('./helpers/topologyV2Fixture');
const {
    PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD,
    TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST,
} = require('../domain/topologyExecutionContext');

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

function factoryPrepareContext() {
    const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
    const candidateHash = createHash('sha256').update(content).digest('hex');
    return {
        operationId: 'factory-proof-17', topologyRevision: 17, priorDeployedRevision: 16,
        executionFence,
        node: freeze({ node: 'portal-node', nodeRef: 'portal', role: 'portal',
            targetProfile: 'xray-main', serviceUnit: 'xray.service',
            serviceUnitPath: '/etc/systemd/system/xray.service',
            configPath: '/usr/local/etc/xray/config.json', checks: [], candidateHash,
            candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
                bytes: [...Buffer.from(content)], sha256: candidateHash },
        }),
    };
}

// Local reader/attestor seams only: no production reader or physical authority.
test('canonical PROD factory forwards explicit capabilities to the real executor reader with TEST control', async () => {
    for (const executionContext of [TEST, PROD]) {
        const externalCalls = [];
        const reads = [];
        const reader = {
            async readVerified(expected) {
                assert.strictEqual(this, reader);
                reads.push(expected);
                throw new Error('simulated authority stops at earliest real reader boundary');
            },
        };
        const executor = createTopologyOperationExecutor({
            ...executionContext,
            HyNode: modelWith(['findById'], externalCalls),
            NodeSSH: class { constructor() { externalCalls.push('ssh'); } },
            executionBindingReader: reader,
            preinstalledRunnerAuthority: {
                async withVerifiedPreinstalledRunner() { assert.fail('reader must refuse first'); },
            },
        });
        assert.ok(executor instanceof TopologyOperationExecutor);
        const context = factoryPrepareContext();
        await assert.rejects(executor.prepare(context), {
            code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
        });
        assert.equal(reads.length, 1, `${executionContext.target} explicit reader must not be silently dropped`);
        assert.deepEqual(reads[0], {
            executionContext: executionContext.hostIdentity,
            operationId: context.operationId, nodeId: context.node.node,
            candidateHash: `sha256:${context.node.candidateHash}`,
            backupId: `topology-${createHash('sha256').update([
                context.operationId, context.node.node, `sha256:${context.node.candidateHash}`,
                context.node.targetProfile,
            ].join('\0')).digest('hex')}`,
            targetProfile: context.node.targetProfile,
            topologyRevision: context.topologyRevision, priorDeployedRevision: context.priorDeployedRevision,
            ...executionFence,
        });
        assert.equal(Object.isFrozen(reads[0]), true);
        assert.deepEqual(externalCalls, [], 'no credential lookup, SSH, bootstrap or upload');
    }
});

test('canonical PROD factory preserves forwarded attestor refusal before credentials without shell or upload fallback', async () => {
    const { bindingRecord, simulatedConnectionAuthority } = require('./helpers/topologyV2Fixture');
    const context = factoryPrepareContext();
    // Explicit simulated binding and endpoint, NOT persistence or physical proof.
    const record = bindingRecord(context, PROD.hostIdentity);
    const connection = freeze({ expectedHostKeySha256: '2'.repeat(64),
        expectedEndpoint: { ip: '192.0.2.17', port: 2222, username: 'c3-test-runner' } });
    const calls = [];
    const executor = createTopologyOperationExecutor({ ...PROD,
        HyNode: modelWith(['findById'], calls),
        NodeSSH: class { constructor() { calls.push('ssh'); assert.fail('no transport'); } },
        executionBindingReader: {
            async readVerified(expected) {
                calls.push('binding');
                assert.equal(expected.executionContext, PROD.hostIdentity);
                return record;
            },
            async readVerifiedConnection(expected, verified) {
                calls.push('connection');
                assert.strictEqual(verified, record);
                assert.equal(expected.executionContext, PROD.hostIdentity);
                return simulatedConnectionAuthority(record, connection);
            },
        },
        preinstalledRunnerAuthority: {
            async withVerifiedPreinstalledRunner() {
                calls.push('attestor');
                assert.fail('unchanged bootstrap policy rejects PROD identity before callback');
            },
        },
    });
    await assert.rejects(executor.prepare(context), error => {
        assert.equal(error.code, 'TOPOLOGY_OPERATION_EXECUTION_FAILED');
        assert.equal(error.cause?.code, 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE');
        return true;
    });
    assert.deepEqual(calls, ['binding', 'connection'], 'no credential lookup, SSH, shell or upload');
});

test('canonical factories preserve real constructor validation for malformed explicit capabilities', () => {
    for (const executionContext of [TEST, PROD]) {
        const calls = [];
        const dependencies = { ...executionContext, HyNode: modelWith(['findById'], calls),
            NodeSSH: class { constructor() { calls.push('ssh'); } } };
        for (const executionBindingReader of [null, {}, [], { readVerified: true }]) {
            assert.throws(() => createTopologyOperationExecutor({ ...dependencies, executionBindingReader }),
                { name: 'TypeError', message: 'Topology executor binding reader requires readVerified' });
        }
        for (const preinstalledRunnerAuthority of [null, {}, [], { withVerifiedPreinstalledRunner: true }]) {
            assert.throws(() => createTopologyOperationExecutor({ ...dependencies,
                executionBindingReader: { async readVerified() { assert.fail('constructor only'); } },
                preinstalledRunnerAuthority }),
            { name: 'TypeError', message: 'Preinstalled runner requires server authority' });
        }
        assert.deepEqual(calls, []);
    }
});

test('canonical factory capability omissions and explicit undefined retain pre-SSH refusal', async () => {
    for (const executionContext of [TEST, PROD]) {
        for (const capabilities of [{},
            { executionBindingReader: undefined, preinstalledRunnerAuthority: undefined },
            { preinstalledRunnerAuthority: {
                async withVerifiedPreinstalledRunner() { assert.fail('no binding reader'); },
            } },
        ]) {
            const calls = [];
            const executor = createTopologyOperationExecutor({ ...executionContext, ...capabilities,
                HyNode: modelWith(['findById'], calls),
                NodeSSH: class { constructor() { calls.push('ssh'); } } });
            assert.ok(executor instanceof TopologyOperationExecutor);
            await assert.rejects(executor.prepare(factoryPrepareContext()), {
                code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
            });
            assert.deepEqual(calls, []);
        }
    }
});

test('canonical factory malformed operation input refuses before explicit reader or credentials', async () => {
    for (const executionContext of [TEST, PROD]) {
        const calls = [];
        const executor = createTopologyOperationExecutor({ ...executionContext,
            HyNode: modelWith(['findById'], calls),
            NodeSSH: class { constructor() { calls.push('ssh'); } },
            executionBindingReader: { async readVerified() { calls.push('binding'); } },
            preinstalledRunnerAuthority: {
                async withVerifiedPreinstalledRunner() { calls.push('attestor'); },
            },
        });
        await assert.rejects(executor.prepare({}), {
            code: 'INVALID_FROZEN_NODE_PLAN', remoteOutcomeUncertain: false,
        });
        for (const fence of [undefined, {}, { ...executionFence }, freeze({ ...executionFence, attempt: 0 })]) {
            await assert.rejects(executor.prepare({ ...factoryPrepareContext(), executionFence: fence }), {
                code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
            });
        }
        assert.deepEqual(calls, []);
    }
});

test('factory canonical host guard precedes resolver capability access even with explicit capabilities', () => {
    let resolverReads = 0;
    let sshConstructions = 0;
    const HyNode = { get findById() { resolverReads++; assert.fail('must reject before resolver construction'); } };
    for (const contour of [{}, { target: PROD.target }, { hostIdentity: PROD.hostIdentity },
        { target: TEST.target, hostIdentity: PROD.hostIdentity },
        { target: PROD.target, hostIdentity: TEST.hostIdentity },
        { ...PROD, hostIdentity: 'foreign.invalid' }, { ...PROD, hostIdentity: PROD.hostIdentity + '.' },
        { ...PROD, hostIdentity: [PROD.hostIdentity] }, { ...PROD, target: 'Production' },
    ]) {
        assert.equal(createTopologyOperationExecutor({ ...contour, HyNode,
            NodeSSH: class { constructor() { sshConstructions++; } },
            executionBindingReader: null, preinstalledRunnerAuthority: null,
        }), undefined);
    }
    assert.equal(resolverReads, 0);
    assert.equal(sshConstructions, 0);
});

// Actual lifecycle/store/executor/worker/repositories; ONLY persistence and the
// independent physical hold are modeled. No Mongo, credentials or transport.
function heldRuntimeFixture(context = PROD) {
    const deps = compositionDependencies();
    const trace = [];
    const state = { held: false, revoked: false, checks: 0, claims: 0 };
    const deny = () => assert.fail('no persistence, enrollment, transport or background work');
    const db = { getClient: () => ({ options: { directConnection: false },
        topology: { description: { type: 'ReplicaSetWithPrimary' } } }) };
    for (const [name, model] of Object.entries(deps)) {
        if (!model || typeof model !== 'object' || name === 'env' || name === 'clock') continue;
        model.db = db;
        model.findOne ??= deny;
    }
    const controller = { executionContext: { ...context }, runnerTransport: 'preinstalled-attested-v1',
        async withHeldAuthority(selected, work) {
            assert.ok(selected === context);
            state.held = true;
            trace.push('enter');
            try { return await work({ async assertHeld() {
                assert.equal(state.held, true);
                state.checks++;
                if (state.revoked) throw new Error('simulated hold revoked');
            }, withVerifiedAuthority: deny, withVerifiedPreinstalledRunner: deny }); }
            finally { state.held = false; trace.push('leave'); }
        } };
    deps.env = { ...ENABLED_ENV, PANEL_DOMAIN: context.hostIdentity,
        TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' };
    deps.clock = { now: () => new Date('2026-10-24T00:00:00.000Z') };
    deps.topologyExecutionAuthority = controller;
    deps.TopologyOperation.findOne = filter => {
        assert.equal(state.held, true);
        assert.deepEqual(filter, { _id: 'factory-proof-17' });
        trace.push('recovery');
        const query = { select() { return query; }, read(value) { assert.equal(value, 'primary'); return query; },
            readConcern(value) { assert.equal(value, 'majority'); return query; },
            setOptions() { return query; }, async lean() { return null; } };
        return query;
    };
    deps.TopologyOperation.findOneAndUpdate = async (filter, update, options) => {
        const { topologyOperationClaimBindingFilter } = require('../domain/topologyOperationClaimBinding');
        assert.equal(state.held, true);
        assert.equal(state.revoked, false);
        assert.equal(filter._id, 'factory-proof-17');
        for (const [key, value] of Object.entries(topologyOperationClaimBindingFilter(context))) {
            assert.deepEqual(filter[key], value);
        }
        assert.deepEqual(filter.v2Terminal, { $exists: false });
        assert.equal(filter.attempts, 0, 'a native binding never reclaims an existing execution attempt');
        assert.equal(update.$inc.attempts, 1);
        assert.equal(options.runValidators, true);
        state.claims++;
        trace.push('claim');
        return null;
    };
    const fixture = { deps, controller, trace, state };
    deps.OperationWorker = class extends TopologyOperationWorker {
        constructor(options) { super(options); fixture.options = options; }
    };
    return fixture;
}

function assertHeldRuntime(service, context, options) {
    const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
    const { TopologyExecutionBindingStore } = require('../repositories/topologyExecutionBindingStore');
    assert.ok(service instanceof TopologyOperationCoordinator);
    assert.ok(service.operationWorker instanceof TopologyOperationWorker);
    const worker = service.operationWorker;
    assert.ok(worker.executor instanceof TopologyOperationExecutor);
    assert.equal(worker.executor.executionProtocolVersion, 2);
    assert.ok(options.bindingProvisioner instanceof TopologyExecutionBindingStore);
    assert.ok(options.bindingLifecycle instanceof TopologyExecutionAuthorityLifecycle);
    assert.ok(options.bindingProvisioner.executionContext === context);
    assert.ok(options.bindingLifecycle.executionContext === context);
    assert.equal(options.allowUnprovenTestExecution, context === TEST);
    assert.equal(worker.userResync.restrictedRunner, true);
    assert.equal(worker.pppReadinessGate.readOnly, true);
    return worker;
}

test('canonical PROD runtime assembles actual held lifecycle/store/default V2 executor through real recovery and null claim (SIMULATED persistence/physical hold)', async () => {
    for (const context of [PROD, TEST]) {
        const f = heldRuntimeFixture(context);
        const service = createTopologyOperationRuntime(f.deps);
        const worker = assertHeldRuntime(service, context, f.options);
        assert.deepEqual(f.trace, [], 'assembly does not invoke the controller or models');
        Object.assign(f.controller.executionContext, context === PROD ? TEST : PROD);
        f.deps.env.PANEL_DOMAIN = 'foreign.invalid';
        assert.deepEqual(await worker.run('factory-proof-17'), { claimed: false, operationId: 'factory-proof-17' });
        assert.deepEqual(f.trace, ['enter', 'recovery', 'claim', 'leave']);
        assert.equal(f.state.claims, 1, 'native entry performs only the fresh context-fenced claim, never a retry CAS');
        assert.equal(f.state.held, false);
        await assert.rejects(f.options.bindingLifecycle.assertHeld(), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        const store = f.options.bindingProvisioner;
        const readVerified = store.readVerified;
        let readerCalls = 0;
        store.readVerified = async function(expected) {
            assert.ok(this === store);
            assert.equal(expected.executionContext, context.hostIdentity);
            readerCalls++;
            return readVerified.call(this, expected);
        };
        await assert.rejects(worker.executor.prepare(factoryPrepareContext()), {
            code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
        });
        assert.equal(readerCalls, 1, 'default actual executor uses the assembled actual store');
        assert.deepEqual(f.trace, ['enter', 'recovery', 'claim', 'leave'],
            'actual executor/store cannot use authority outside the worker hold');
        assert.equal(worker.pppDriftSync === undefined, context === PROD);
        assert.equal(worker.pppResumeReadinessGate === undefined, context === PROD);
    }
});

test('PROD runtime rejects malformed, foreign and cross-paired explicit controllers before invocation or claim', async () => {
    for (const controller of [null, {}, [], { withHeldAuthority() { assert.fail('undeclared PROD'); } },
        ...[undefined, null, {}, TEST, { target: TEST.target, hostIdentity: PROD.hostIdentity },
            { target: PROD.target, hostIdentity: TEST.hostIdentity }, { ...PROD, extra: true },
            { target: [PROD.target], hostIdentity: PROD.hostIdentity }].map(executionContext => ({
            executionContext, withHeldAuthority() { assert.fail('invalid pairing'); },
            get runnerTransport() { assert.fail('pair validation must precede selection'); },
        })),
    ]) {
        const f = heldRuntimeFixture();
        f.deps.topologyExecutionAuthority = controller;
        await assertUnavailable(createTopologyOperationRuntime(f.deps));
        assert.deepEqual(f.trace, []);
        assert.equal(f.state.claims, 0);
    }
});

test('PROD authority omission cannot inherit raw reader/attestor or TEST bypass inputs', async () => {
    for (const explicitUndefined of [false, true]) {
        const f = heldRuntimeFixture();
        if (explicitUndefined) f.deps.topologyExecutionAuthority = undefined;
        else delete f.deps.topologyExecutionAuthority;
        f.deps.allowUnprovenTestExecution = true;
        f.deps.executionBindingReader = { readVerified() { assert.fail('untrusted runtime input'); } };
        f.deps.preinstalledRunnerAuthority = { withVerifiedPreinstalledRunner() { assert.fail('untrusted runtime input'); } };
        const service = createTopologyOperationRuntime(f.deps);
        assert.ok(service.operationWorker.executor instanceof TopologyOperationExecutor);
        assert.deepEqual(await service.operationWorker.run('factory-proof-17'), {
            claimed: false, operationId: 'factory-proof-17', stopped: true,
            errorCode: 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN',
        });
        assert.deepEqual(f.trace, []);
        assert.equal(f.state.claims, 0);
    }
});

test('PROD rejects unknown explicit transports and missing/cross-connection/undiscovered store prerequisites', async () => {
    for (const change of [
        ...[null, true, 'shell-fallback', 'preinstalled'].map(value => f => { f.controller.runnerTransport = value; }),
        f => { delete f.deps.TopologyExecutionBinding; },
        f => { f.deps.TopologyExecutionEnrollment.db = {}; },
        f => { f.deps.TopologyExecutionBinding.db.getClient = () => ({ options: { directConnection: true } }); },
        f => { f.deps.TopologyExecutionBinding.db.getClient = () => ({ options: {}, topology: { description: { type: 'Unknown' } } }); },
    ]) {
        const f = heldRuntimeFixture();
        change(f);
        await assertUnavailable(createTopologyOperationRuntime(f.deps));
        assert.deepEqual(f.trace, []);
        assert.equal(f.state.claims, 0);
    }
});

test('PROD assembled real lifecycle refuses unheld and revoked recovery before any claim', async () => {
    for (const mode of ['unheld', 'revoked-recovery']) {
        const f = heldRuntimeFixture();
        if (mode === 'unheld') f.controller.withHeldAuthority = async () => {};
        else {
            const read = f.deps.TopologyOperation.findOne;
            f.deps.TopologyOperation.findOne = (...args) => {
                const query = read(...args);
                query.lean = async () => { await Promise.resolve(); f.state.revoked = true; return null; };
                return query;
            };
        }
        const service = createTopologyOperationRuntime(f.deps);
        const worker = assertHeldRuntime(service, PROD, f.options);
        const result = await worker.run('factory-proof-17');
        assert.equal(result.stopped, true);
        assert.equal(result.drainUncertain, true);
        assert.equal(result.errorCode, 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN');
        assert.equal(f.state.claims, 0);
        assert.equal(f.state.held, false);
        assert.deepEqual(f.trace, mode === 'unheld' ? [] : ['enter', 'recovery', 'leave']);
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
