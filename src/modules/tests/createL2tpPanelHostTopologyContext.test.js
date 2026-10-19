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

function compose(env, mutateSource = () => {}) {
    const captured = {};
    const worker = { async run() { assert.fail('composition must not execute a worker'); } };
    const intentService = { async runOnce() { assert.fail('composition must not consume'); } };
    const models = {};
    const host = createL2tpPanelHost({
        env,
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
        { ...PROD_ENV, L2TP_EXECUTION_ENABLED: 'false' },
        { ...PROD_ENV, L2TP_MIGRATIONS_ENABLED: 'false' },
        { ...PROD_ENV, PANEL_DOMAIN: undefined },
        { ...PROD_ENV, PANEL_DOMAIN: TEST.hostIdentity },
    ]) {
        const { host, captured } = compose(env);
        assert.equal(host.topologyIntentService, undefined);
        assert.equal(captured.intent, undefined);
        assert.equal(captured.recovery, undefined);
        assert.equal(captured.deployment, undefined);
    }
});

test('TEST flag alone cannot compose production admission or recovery through an injected adapter', () => {
    assert.throws(() => compose({ ...TEST_ENV, PANEL_DOMAIN: PROD.hostIdentity }), /exact execution identity/);
});

test('production never inherits the TEST-only unfenced client-proof queue', () => {
    const { captured } = compose({ ...PROD_ENV, TOPOLOGY_PROBE_USER_ID: 'configured-proof-user' });
    assert.ok(captured.recovery);
    assert.equal(captured.recovery.clientProofWorker, undefined);
});
