'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createL2tpPanelHost } = require('../createL2tpPanelHost');

const PROD = Object.freeze({ target: 'production', hostIdentity: 'lm1.infograd.online' });
const TEST = Object.freeze({ target: 'test', hostIdentity: 'test.infograd.online' });
const PROD_ENV = Object.freeze({
    L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: PROD.hostIdentity,
});
const TEST_ENV = Object.freeze({
    L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: TEST.hostIdentity,
});

function compose(env, mutateSource = () => {}, topologyExecutionAuthority) {
    const captured = {};
    const worker = { async run() { assert.fail('composition must not execute a worker'); } };
    const intentService = { async runOnce() { assert.fail('composition must not consume'); } };
    const models = {};
    const host = createL2tpPanelHost({
        env,
        topologyExecutionAuthority,
        moduleEntry: {
            registerModels: () => models,
            createTopologyDeploymentService(options) {
                captured.deployment = options;
                return { operationWorker: worker };
            },
            createTopologyIntentService(options) {
                captured.intent = options;
                return intentService;
            },
        },
        HyNode: {}, CascadeLink: {}, topologyRuntime: {},
        Repository: class {},
        createRepositoryAdapters: () => ({ nodeRepository: {}, stateRepository: {}, operationRepository: {} }),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime(options) {
            captured.execution = options;
            mutateSource();
            return {
                runtime: { stateManagementService: {}, simpleService: {} },
                start() {}, async stop() {},
            };
        },
        createTopologyRecoveryLifecycle(options) {
            captured.recovery = options;
            return { start() { captured.started = true; }, async stop() {} };
        },
    });
    return { host, captured, worker, intentService };
}

test('actual panel host forwards explicit server authority for either selected canonical context without invoking it', () => {
    for (const env of [TEST_ENV, PROD_ENV]) {
        const authority = Object.freeze({ executionContext: env === PROD_ENV ? PROD : TEST,
            withHeldAuthority() { assert.fail('composition only'); } });
        const { captured } = compose({ ...env }, () => {}, authority);
        assert.ok(captured.deployment.topologyExecutionAuthority === authority,
            'actual host drops the explicit held authority capability');
        assert.equal(Object.hasOwn(compose({ ...env }).captured.deployment, 'topologyExecutionAuthority'), false);
    }
});

test('actual PROD panel host reaches held recovery and null claim through the actual module runtime/default V2 executor (SIMULATED persistence/physical hold)', async () => {
    const trace = [];
    let held = false, service, recovery;
    const deny = () => assert.fail('no enrollment, DDL, transport or background start');
    const db = { transaction: deny, getClient: () => ({ options: { directConnection: false },
        topology: { description: { type: 'ReplicaSetWithPrimary' } } }) };
    const model = () => ({ db, ...Object.fromEntries(['find', 'findOne', 'findById', 'findOneAndUpdate',
        'updateOne', 'deleteOne', 'create', 'countDocuments'].map(name => [name, deny])) });
    const models = Object.fromEntries(['CascadeRouteGroup', 'CascadeTopologyState', 'RelayL2tpState',
        'L2tpUser', 'L2tpOperation', 'TopologyOperation', 'NodeOperationLock', 'TopologyExecutionBinding',
        'TopologyExecutionEnrollment', 'TopologyConfigOwner'].map(name => [name, model()]));
    models.TopologyOperation.findOne = filter => {
        assert.equal(held, true);
        assert.deepEqual(filter, { _id: 'host-held-null' });
        trace.push('recovery');
        const query = { select() { return query; }, read(value) { assert.equal(value, 'primary'); return query; },
            readConcern(value) { assert.equal(value, 'majority'); return query; },
            setOptions() { return query; }, async lean() { return null; } };
        return query;
    };
    models.TopologyOperation.findOneAndUpdate = async filter => {
        assert.equal(held, true);
        assert.equal(filter._id, 'host-held-null');
        assert.equal(filter['executionContext.target'], PROD.target);
        assert.equal(filter['executionContext.hostIdentity'], PROD.hostIdentity);
        trace.push('claim');
        return null;
    };
    const controller = { executionContext: PROD, runnerTransport: 'preinstalled-attested-v1',
        async withHeldAuthority(context, work) {
            assert.deepEqual(context, PROD);
            held = true; trace.push('enter');
            try { return await work({ assertHeld() { assert.equal(held, true); }, withVerifiedAuthority: deny }); }
            finally { held = false; trace.push('leave'); }
        } };
    createL2tpPanelHost({ env: { ...PROD_ENV, TOPOLOGY_PROBE_USER_ID: 'must-not-activate' },
        topologyExecutionAuthority: controller,
        moduleEntry: { registerModels: () => models,
            createTopologyDeploymentService(options) {
                service = require('../relay-l2tp').createTopologyDeploymentService(options);
                return service;
            } },
        HyNode: model(), CascadeLink: model(), NodeSSH: class { constructor() { deny(); } },
        topologyRuntime: {}, Repository: class {},
        createRepositoryAdapters: () => ({}), createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({ runtime: { stateManagementService: {} }, start: deny, stop: deny }),
        createTopologyRecoveryLifecycle(options) { recovery = options; return { start: deny, stop: deny }; },
        clock: { now: () => new Date('2026-10-24T00:00:00.000Z') },
    });
    assert.deepEqual(trace, [], 'host assembly does not call controller, start or read/write storage');
    const { TopologyOperationExecutor } = require('../relay-l2tp/services/topologyOperationExecutor');
    assert.ok(service.operationWorker.executor instanceof TopologyOperationExecutor);
    assert.equal(service.operationWorker.executor.executionProtocolVersion, 2);
    assert.equal(recovery.clientProofWorker, undefined);
    assert.deepEqual(await service.operationWorker.run('host-held-null'), { claimed: false, operationId: 'host-held-null' });
    assert.deepEqual(trace, ['enter', 'recovery', 'claim', 'leave'], 'V2 never reacquires an existing execution attempt');
    assert.equal(held, false);
});

test('production opt-in composes durable intent admission and recovery with the exact server identity', async () => {
    const { host, captured, worker, intentService } = compose({ ...PROD_ENV });
    assert.strictEqual(host.topologyIntentService, intentService);
    assert.deepEqual(captured.intent.executionContext, PROD);
    assert.equal(Object.isFrozen(captured.intent.executionContext), true);
    assert.strictEqual(captured.recovery.intentConsumer, intentService);
    assert.strictEqual(captured.recovery.worker, worker);
    assert.strictEqual(captured.recovery.executionContext, captured.intent.executionContext);
    assert.deepEqual(captured.deployment.executionContext, PROD);
    assert.equal(captured.execution.runtimeDependencies.enableUnsafeExecutionForTests, false);
    assert.equal(captured.execution.runtimeDependencies.enableInstallAdmission, false);
    host.start();
    assert.equal(captured.started, true);
    await host.stop();
});

test('host snapshots production authorization before an injected factory mutates source environment', () => {
    const env = { ...PROD_ENV };
    const { captured } = compose(env, () => Object.assign(env, TEST_ENV));
    assert.deepEqual(captured.intent.executionContext, PROD);
    assert.deepEqual(captured.recovery.executionContext, PROD);
    assert.equal(captured.deployment.env.PANEL_DOMAIN, PROD.hostIdentity);
    assert.equal(captured.deployment.env.TOPOLOGY_TEST_EXECUTION_ENABLED, undefined);
    assert.strictEqual(captured.recovery.env, captured.deployment.env);
    assert.equal(Object.isFrozen(captured.deployment.env), true);
});

test('TEST keeps its independent worker and ingress admission opt-ins and gets its paired context', () => {
    const { captured } = compose({ ...TEST_ENV });
    assert.deepEqual(captured.intent.executionContext, TEST);
    assert.deepEqual(captured.recovery.executionContext, TEST);
    assert.strictEqual(captured.execution.runtimeDependencies.executionContext, captured.intent.executionContext);
    assert.equal(captured.execution.runtimeDependencies.enableUnsafeExecutionForTests, true);
    assert.equal(captured.execution.runtimeDependencies.enableInstallAdmission, true);
});

test('production L2TP admission requires its own server-only opt-in and never inherits TEST bypass', () => {
    const { captured } = compose({ ...PROD_ENV, L2TP_PRODUCTION_EXECUTION_ENABLED: 'true' });
    assert.strictEqual(captured.execution.runtimeDependencies.executionContext, captured.intent.executionContext);
    assert.deepEqual(captured.execution.runtimeDependencies.executionContext, PROD);
    assert.equal(captured.execution.runtimeDependencies.enableProductionExecution, true);
    assert.equal(captured.execution.runtimeDependencies.enableUnsafeExecutionForTests, false);
    assert.equal(captured.execution.runtimeDependencies.enableInstallAdmission, true);
});

test('production is dormant without all independent production prerequisites', () => {
    for (const env of [
        { ...PROD_ENV, TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: undefined },
        { ...PROD_ENV, TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: undefined,
            TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' },
        { ...PROD_ENV, L2TP_EXECUTION_ENABLED: 'false' },
        { ...PROD_ENV, L2TP_MIGRATIONS_ENABLED: 'false' },
    ]) {
        const { host, captured } = compose(env);
        assert.equal(host.topologyIntentService, undefined);
        assert.equal(captured.intent, undefined);
        assert.equal(captured.recovery, undefined);
        assert.equal(captured.deployment, undefined);
    }
});

test('preexisting TEST flag on PROD cannot compose production admission or recovery', () => {
    const { host, captured } = compose({ ...TEST_ENV, PANEL_DOMAIN: PROD.hostIdentity });
    assert.equal(host.topologyIntentService, undefined);
    assert.equal(captured.deployment, undefined);
    assert.equal(captured.recovery, undefined);
});

test('explicit production opt-in with an unknown host identity fails before factory calls', () => {
    assert.throws(() => compose({ ...PROD_ENV, PANEL_DOMAIN: 'unknown.invalid' }), /exact execution identity/);
    assert.throws(() => compose({ ...PROD_ENV, PANEL_DOMAIN: undefined }), /exact execution identity/);
    assert.throws(() => compose({ ...PROD_ENV, PANEL_DOMAIN: TEST.hostIdentity }), /exact execution identity/);
    assert.throws(() => compose({ ...TEST_ENV, TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' }), /exact execution identity/);
});

test('production never inherits the TEST-only unfenced client-proof queue', () => {
    const { captured } = compose({ ...PROD_ENV, TOPOLOGY_PROBE_USER_ID: 'configured-proof-user' });
    assert.ok(captured.recovery);
    assert.equal(captured.recovery.clientProofWorker, undefined);
});
