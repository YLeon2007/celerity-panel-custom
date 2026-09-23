'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    createTopologyOperationRecoveryLifecycle,
} = require('../runtime/createTopologyOperationRecoveryLifecycle');
const { createL2tpPanelHost } = require('../../createL2tpPanelHost');

const ENABLED_ENV = Object.freeze({
    L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'true',
});

function createFakeTimer() {
    const schedules = [];
    const cleared = [];
    return {
        schedules,
        cleared,
        setInterval(callback, intervalMs) {
            const handle = { callback, intervalMs };
            schedules.push(handle);
            return handle;
        },
        clearInterval(handle) {
            cleared.push(handle);
        },
    };
}

function createScanModel(rows, calls = []) {
    return {
        find(filter) {
            calls.push({ method: 'find', filter });
            const query = {
                select(projection) {
                    calls.push({ method: 'select', projection });
                    return query;
                },
                sort(sort) {
                    calls.push({ method: 'sort', sort });
                    return query;
                },
                limit(limit) {
                    calls.push({ method: 'limit', limit });
                    return query;
                },
                async lean() {
                    calls.push({ method: 'lean' });
                    return rows;
                },
            };
            return query;
        },
    };
}

test('enabled lifecycle recovers queued and expired operation ids at startup', async () => {
    const modelCalls = [];
    const workerCalls = [];
    const timer = createFakeTimer();
    const lifecycle = createTopologyOperationRecoveryLifecycle({
        env: ENABLED_ENV,
        operationModel: createScanModel([
            {
                _id: 'queued-operation',
                status: 'queued',
                leaseOwner: '',
                leaseUntil: null,
                nodes: [{ state: 'pending', backupId: '' }],
            },
            {
                _id: 'expired-operation',
                status: 'preparing',
                leaseOwner: 'stopped-worker',
                leaseUntil: new Date('2026-09-23T11:59:59.999Z'),
                nodes: [{ state: 'pending', backupId: '' }],
            },
        ], modelCalls),
        worker: {
            async run(operationId) {
                workerCalls.push(operationId);
            },
        },
        clock: { now: () => new Date('2026-09-23T12:00:00.000Z') },
        intervalMs: 5_000,
        scanLimit: 25,
        timer,
        logger: { error() {} },
    });

    assert.deepEqual(lifecycle.start(), {
        enabled: true,
        running: true,
        inFlight: true,
    });
    await lifecycle.stop();

    assert.deepEqual(workerCalls, ['queued-operation', 'expired-operation']);
    assert.equal(modelCalls.filter(call => call.method === 'find').length, 1);
    assert.deepEqual(modelCalls.find(call => call.method === 'limit'), {
        method: 'limit',
        limit: 25,
    });
    assert.equal(timer.schedules.length, 1);
    assert.equal(timer.schedules[0].intervalMs, 5_000);
    assert.deepEqual(timer.cleared, [timer.schedules[0]]);
});

test('missing any exact topology test flag leaves recovery dormant without scanning', async () => {
    for (const flagName of Object.keys(ENABLED_ENV)) {
        const env = { ...ENABLED_ENV };
        delete env[flagName];
        let dependencyReads = 0;
        const lifecycle = createTopologyOperationRecoveryLifecycle({
            env,
            get operationModel() {
                dependencyReads += 1;
                throw new Error('disabled recovery must not inspect the model');
            },
            get worker() {
                dependencyReads += 1;
                throw new Error('disabled recovery must not inspect the worker');
            },
            timer: {
                setInterval() {
                    throw new Error('disabled recovery must not create a timer');
                },
                clearInterval() {
                    throw new Error('disabled recovery must not clear an absent timer');
                },
            },
        });

        assert.deepEqual(lifecycle.start(), {
            enabled: false,
            running: false,
            inFlight: false,
        });
        assert.deepEqual(await lifecycle.stop(), {
            enabled: false,
            running: false,
            inFlight: false,
        });
        assert.equal(dependencyReads, 0, flagName);
    }
});

test('scan never invokes the worker for an active unexpired foreign lease', async () => {
    const workerCalls = [];
    const now = new Date('2026-09-23T12:00:00.000Z');
    const lifecycle = createTopologyOperationRecoveryLifecycle({
        env: ENABLED_ENV,
        operationModel: createScanModel([
            {
                _id: 'queued-operation',
                status: 'queued',
                leaseOwner: '',
                leaseUntil: null,
                nodes: [{ state: 'pending', backupId: '' }],
            },
            {
                _id: 'expired-operation',
                status: 'preparing',
                leaseOwner: 'stopped-worker',
                leaseUntil: new Date(now.getTime() - 1),
                nodes: [{ state: 'pending', backupId: '' }],
            },
            {
                _id: 'active-foreign-operation',
                status: 'preparing',
                leaseOwner: 'foreign-worker',
                leaseUntil: new Date(now.getTime() + 60_000),
                nodes: [{ state: 'pending', backupId: '' }],
            },
        ]),
        worker: {
            async run(operationId) {
                workerCalls.push(operationId);
            },
        },
        clock: { now: () => now },
        timer: createFakeTimer(),
        logger: { error() {} },
    });

    lifecycle.start();
    await lifecycle.stop();

    assert.deepEqual(workerCalls, ['queued-operation', 'expired-operation']);
});

test('startup scan recovers expired committing and rolling-back operations', async () => {
    const now = new Date('2026-09-23T12:00:00.000Z');
    const workerCalls = [];
    const lifecycle = createTopologyOperationRecoveryLifecycle({
        env: ENABLED_ENV,
        operationModel: createScanModel([
            {
                _id: 'expired-committing-operation',
                status: 'committing',
                leaseOwner: 'stopped-worker',
                leaseUntil: new Date(now.getTime() - 1),
                nodes: [{ state: 'committed', backupId: 'backup-a' }],
            },
            {
                _id: 'expired-rolling-back-operation',
                status: 'rolling_back',
                leaseOwner: 'stopped-worker',
                leaseUntil: new Date(now.getTime() - 1),
                nodes: [{ state: 'failed', backupId: 'backup-b' }],
            },
        ]),
        worker: {
            async run(operationId) {
                workerCalls.push(operationId);
            },
        },
        clock: { now: () => now },
        timer: createFakeTimer(),
        logger: { error() {} },
    });

    lifecycle.start();
    await lifecycle.stop();

    assert.deepEqual(workerCalls, [
        'expired-committing-operation',
        'expired-rolling-back-operation',
    ]);
});

test('duplicate lifecycle registration is blocked before and after stop', async () => {
    const modelCalls = [];
    const timer = createFakeTimer();
    const lifecycle = createTopologyOperationRecoveryLifecycle({
        env: ENABLED_ENV,
        operationModel: createScanModel([], modelCalls),
        worker: { async run() {} },
        clock: { now: () => new Date('2026-09-23T12:00:00.000Z') },
        timer,
        logger: { error() {} },
    });

    lifecycle.start();
    lifecycle.start();
    await lifecycle.stop();

    assert.deepEqual(lifecycle.start(), {
        enabled: true,
        running: false,
        inFlight: false,
    });
    await lifecycle.stop();

    assert.equal(timer.schedules.length, 1);
    assert.equal(timer.cleared.length, 1);
    assert.equal(modelCalls.filter(call => call.method === 'find').length, 1);
});

test('panel host lazily registers opted-in topology recovery and stops it before shutdown', async () => {
    const calls = [];
    const HyNode = { kind: 'hy-node-model' };
    const CascadeLink = { kind: 'cascade-link-model' };
    const TopologyOperation = { kind: 'topology-operation-model' };
    const topologyWorker = { async run() {} };
    const clock = { now: () => new Date('2026-09-23T12:00:00.000Z') };
    const timer = createFakeTimer();
    const logger = { error() {} };
    const models = {
        RelayL2tpState: {},
        L2tpUser: {},
        CascadeRouteGroup: {},
        CascadeTopologyState: {},
        L2tpOperation: {},
        TopologyOperation,
        NodeOperationLock: {},
    };
    const topologyDeploymentService = { operationWorker: topologyWorker };
    const executionRuntime = {
        runtime: { stateManagementService: {} },
        start() {
            calls.push('execution.start');
            return { running: true };
        },
        async stop() {
            calls.push('execution.stop');
            return { running: false };
        },
    };
    const recoveryLifecycle = {
        start() {
            calls.push('recovery.start');
            return { enabled: true, running: true, inFlight: true };
        },
        async stop() {
            calls.push('recovery.stop');
            return { enabled: true, running: false, inFlight: false };
        },
    };
    let deploymentDependencies;
    let recoveryDependencies;
    const moduleEntry = {
        registerModels() {
            calls.push('models.register');
            return models;
        },
        createTopologyDeploymentService(dependencies) {
            calls.push('topology.create');
            deploymentDependencies = dependencies;
            return topologyDeploymentService;
        },
    };
    const workerLifecycle = {
        intervalMs: 7_500,
        timer,
        logger,
    };

    const host = createL2tpPanelHost({
        env: ENABLED_ENV,
        moduleEntry,
        HyNode,
        CascadeLink,
        NodeSSH: class FakeNodeSSH {},
        topologyRuntime: {},
        Repository: class FakeRepository {},
        createRepositoryAdapters: () => ({
            nodeRepository: {},
            stateRepository: {},
            operationRepository: {},
        }),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime() {
            calls.push('execution.create');
            return executionRuntime;
        },
        createTopologyRecoveryLifecycle(dependencies) {
            calls.push('recovery.create');
            recoveryDependencies = dependencies;
            return recoveryLifecycle;
        },
        workerLifecycle,
        clock,
        workerId: 'panel-worker',
        leaseMs: 30_000,
        topologyRecoveryScanLimit: 17,
    });

    assert.deepEqual(calls, [
        'models.register',
        'execution.create',
        'topology.create',
        'recovery.create',
    ]);
    assert.strictEqual(deploymentDependencies.env, ENABLED_ENV);
    assert.strictEqual(deploymentDependencies.TopologyOperation, TopologyOperation);
    assert.strictEqual(recoveryDependencies.env, ENABLED_ENV);
    assert.strictEqual(recoveryDependencies.operationModel, TopologyOperation);
    assert.strictEqual(recoveryDependencies.worker, topologyWorker);
    assert.strictEqual(recoveryDependencies.clock, clock);
    assert.strictEqual(recoveryDependencies.timer, timer);
    assert.strictEqual(recoveryDependencies.logger, logger);
    assert.equal(recoveryDependencies.intervalMs, 7_500);
    assert.equal(recoveryDependencies.scanLimit, 17);

    host.start();
    await host.stop();

    assert.deepEqual(calls.slice(-4), [
        'execution.start',
        'recovery.start',
        'recovery.stop',
        'execution.stop',
    ]);
});
