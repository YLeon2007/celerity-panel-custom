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

test('topology recovery retains uncertain ownership evidence across idle ticks', async () => {
    let rows = [{ _id: 'queued', status: 'queued' }];
    const timer = createFakeTimer();
    const lifecycle = createTopologyOperationRecoveryLifecycle({ env: ENABLED_ENV,
        operationModel: { find() { return createScanModel(rows).find(); } },
        worker: { async run() { return { claimed: true, stopped: true, status: 'failed',
            errorCode: 'REMOTE_COMMAND_OUTCOME_UNCERTAIN' }; } }, timer,
    });
    lifecycle.start();
    for (let i = 0; i < 30; i++) await Promise.resolve();
    rows = [];
    await timer.schedules[0].callback();
    assert.equal((await lifecycle.stop()).drainUncertain, true);
});

test('topology supervised failures are logged but cannot become a successful drain', async () => {
    for (const boundary of ['worker', 'scan', 'intent', 'proof']) {
        const fail = async () => { throw new Error('unconfirmed outcome'); };
        const model = createScanModel([{ _id: 'queued', status: 'queued' }]);
        if (boundary === 'scan') model.find = () => { throw new Error('read failed'); };
        const lifecycle = createTopologyOperationRecoveryLifecycle({ env: ENABLED_ENV,
            operationModel: model,
            worker: { run: boundary === 'worker' ? fail : async () => ({ claimed: false }) },
            ...(boundary === 'intent' ? { intentConsumer: { runOnce: fail } } : {}),
            ...(boundary === 'proof' ? { clientProofWorker: { runOnce: fail } } : {}),
            timer: createFakeTimer(),
        });
        lifecycle.start();
        assert.equal((await lifecycle.stop()).drainUncertain, true, boundary);
    }
});

test('topology refusal and a settled failed operation remain clean drains', async () => {
    for (const result of [{ claimed: false, stopped: true }, { claimed: true, status: 'failed' }]) {
        const lifecycle = createTopologyOperationRecoveryLifecycle({ env: ENABLED_ENV,
            operationModel: createScanModel([{ _id: 'queued', status: 'queued' }]),
            worker: { async run() { return result; } }, timer: createFakeTimer(),
        });
        lifecycle.start();
        assert.notEqual((await lifecycle.stop()).drainUncertain, true);
    }
});

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

test('TEST ticks run one client proof after the topology scan', async () => {
    const calls = [];
    const timer = createFakeTimer();
    const lifecycle = createTopologyOperationRecoveryLifecycle({
        env: ENABLED_ENV,
        operationModel: createScanModel([{ _id: 'queued', status: 'queued' }], calls),
        worker: { async run(id) { calls.push({ method: 'run', id }); } },
        clientProofWorker: { async runOnce() { calls.push({ method: 'proof' }); } },
        timer,
    });

    lifecycle.start();
    await lifecycle.stop();
    assert.deepEqual(calls.map(call => call.method), [
        'find', 'select', 'sort', 'limit', 'lean', 'run', 'proof',
    ]);
});

test('proof failures log a safe code and do not prevent subsequent topology ticks', async () => {
    const calls = [];
    const logs = [];
    const timer = createFakeTimer();
    const lifecycle = createTopologyOperationRecoveryLifecycle({
        env: ENABLED_ENV,
        operationModel: createScanModel([{ _id: 'queued', status: 'queued' }]),
        worker: { async run(id) { calls.push(id); } },
        clientProofWorker: {
            async runOnce() {
                calls.push('proof');
                throw new Error('sensitive client data');
            },
        },
        timer,
        logger: { error(...args) { logs.push(args); } },
    });

    lifecycle.start();
    await new Promise(resolve => setImmediate(resolve));
    await timer.schedules[0].callback();
    await lifecycle.stop();

    assert.deepEqual(calls, ['queued', 'proof', 'queued', 'proof']);
    assert.deepEqual(logs, [
        ['Topology operation recovery failed', { code: 'TOPOLOGY_CLIENT_PROOF_RECOVERY_RUN_FAILED' }],
        ['Topology operation recovery failed', { code: 'TOPOLOGY_CLIENT_PROOF_RECOVERY_RUN_FAILED' }],
    ]);
});

test('failed topology scan still gives the proof worker one attempt', async () => {
    const codes = [];
    let proofCalls = 0;
    const lifecycle = createTopologyOperationRecoveryLifecycle({
        env: ENABLED_ENV,
        operationModel: createScanModel(null),
        worker: { async run() {} },
        clientProofWorker: { async runOnce() { proofCalls += 1; } },
        timer: createFakeTimer(),
        logger: { error(_message, { code }) { codes.push(code); } },
    });

    lifecycle.start();
    await lifecycle.stop();
    assert.equal(proofCalls, 1);
    assert.deepEqual(codes, ['TOPOLOGY_OPERATION_RECOVERY_SCAN_FAILED']);
});

test('stop waits for an in-flight proof and skips overlapping ticks', async () => {
    const timer = createFakeTimer();
    let releaseProof;
    let proofStarted;
    const started = new Promise(resolve => { proofStarted = resolve; });
    const blocked = new Promise(resolve => { releaseProof = resolve; });
    let proofCalls = 0;
    const lifecycle = createTopologyOperationRecoveryLifecycle({
        env: ENABLED_ENV,
        operationModel: createScanModel([]),
        worker: { async run() {} },
        clientProofWorker: {
            async runOnce() {
                proofCalls += 1;
                proofStarted();
                await blocked;
            },
        },
        timer,
    });

    lifecycle.start();
    await started;
    await timer.schedules[0].callback();
    assert.equal(proofCalls, 1);
    let stopped = false;
    const stopping = lifecycle.stop().then(() => { stopped = true; });
    await Promise.resolve();
    assert.equal(stopped, false);
    releaseProof();
    await stopping;
    assert.equal(stopped, true);
    assert.equal(proofCalls, 1);
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
            get clientProofWorker() {
                dependencyReads += 1;
                throw new Error('disabled recovery must not inspect the proof worker');
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

test('host closes both admissions before joining either drain and preserves topology uncertainty', async () => {
    let finishRecovery;
    const recoveryDrain = new Promise(resolve => { finishRecovery = resolve; });
    const calls = [];
    const host = createL2tpPanelHost({ env: { ...ENABLED_ENV, PANEL_DOMAIN: 'test.infograd.online' }, HyNode: {}, CascadeLink: {},
        moduleEntry: { registerModels: () => ({}),
            createTopologyDeploymentService: () => ({ operationWorker: { async run() {} } }) },
        topologyRuntime: {}, Repository: class {}, createRepositoryAdapters: () => ({}),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({ runtime: {}, start() {},
            async stop() { calls.push('execution-stop'); return { enabled: true, running: false, inFlight: false }; } }),
        createTopologyRecoveryLifecycle: () => ({ start() {},
            stop() { calls.push('recovery-stop'); return recoveryDrain; } }),
    });
    const stopping = host.stop();
    try {
        assert.deepEqual(calls, ['recovery-stop', 'execution-stop']);
    } finally { finishRecovery({ drainUncertain: true }); }
    assert.equal((await stopping).drainUncertain, true);
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
        env: { ...ENABLED_ENV, PANEL_DOMAIN: 'test.infograd.online' },
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
    assert.deepEqual(deploymentDependencies.env, { ...ENABLED_ENV, PANEL_DOMAIN: 'test.infograd.online' });
    assert.strictEqual(deploymentDependencies.TopologyOperation, TopologyOperation);
    assert.strictEqual(recoveryDependencies.env, deploymentDependencies.env);
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

test('assembled TEST host claims one durable client proof per tick and stop waits for it', async () => {
    const timer = createFakeTimer();
    const now = new Date('2026-09-30T12:00:00.000Z');
    const operation = {
        _id: 'proof-op', status: 'succeeded', topologyRevision: 7,
        clientReadiness: 'unverified', clientProofAttempts: 0,
        clientProofLeaseUntil: null, clientProofRetryAfter: null,
        nodes: [{ node: '0123456789abcdef01234567', role: 'portal', state: 'committed' }],
    };
    let singletonChecks = 0;
    let releaseClaim;
    let claimStarted;
    const claiming = new Promise(resolve => { claimStarted = resolve; });
    const blockedClaim = new Promise(resolve => { releaseClaim = resolve; });
    const claims = [];
    const updates = [];
    const TopologyOperation = {
        async create() {},
        find() { return createScanModel([]).find(); },
        async findOneAndUpdate(filter, update) {
            claims.push(filter);
            claimStarted();
            await blockedClaim;
            if (operation.clientProofRetryAfter) return null;
            Object.assign(operation, update.$set);
            operation.clientProofAttempts += update.$inc.clientProofAttempts;
            return { ...operation };
        },
        async updateOne(filter, update) {
            updates.push({ filter, update });
            Object.assign(operation, update.$set);
            return { matchedCount: 1 };
        },
    };
    const models = {
        TopologyOperation, CascadeTopologyState: { findById(key) { assert.equal(key, 'singleton'); singletonChecks += 1; throw Error('no positive proof'); } },
        RelayL2tpState: { find() { throw Error('no live graph for invalid operation'); } },
        CascadeRouteGroup: { find() { throw Error('no live graph for invalid operation'); } },
        L2tpOperation: {}, NodeOperationLock: {},
    };
    const host = createL2tpPanelHost({
        env: { ...ENABLED_ENV, PANEL_DOMAIN: 'test.infograd.online', TOPOLOGY_PROBE_USER_ID: 'test-probe-user' },
        moduleEntry: {
            registerModels: () => models,
            createTopologyDeploymentService: () => ({ operationWorker: { async run() {} } }),
        },
        HyNode: { find() { throw Error('no live graph for invalid operation'); } },
        CascadeLink: { find() { throw Error('no live graph for invalid operation'); } },
        NodeSSH: class {},
        topologyRuntime: {},
        Repository: class {},
        createRepositoryAdapters: () => ({ nodeRepository: {}, stateRepository: {}, operationRepository: {} }),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({ runtime: { stateManagementService: {} }, start() {}, async stop() {} }),
        workerLifecycle: { timer, logger: { error() {} }, intervalMs: 1000 },
        clock: { now: () => now },
    });
    host.start();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(claims.length, 1, 'startup tick must claim a proof');
    await claiming;
    await timer.schedules[0].callback(); // overlapping tick cannot start a second proof
    assert.equal(claims.length, 1);
    let stopped = false;
    const stopping = host.stop().then(() => { stopped = true; });
    await Promise.resolve();
    assert.equal(stopped, false);
    releaseClaim();
    await stopping;
    assert.equal(claims.length, 1);
    assert.equal(claims[0].status, 'succeeded');
    assert.equal(claims[0].clientReadiness, 'unverified');
    assert.equal(updates.length, 1);
    assert.equal(updates[0].update.$set.clientProofReason, 'probe_failed');
    assert.equal(operation.clientReadiness, 'unverified');
    assert.equal(operation.clientProofAttempts, 1);
    assert.equal(singletonChecks, 1, 'host must wire the full-Sync singleton revision fence into the proof executor');
});

test('non-TEST host with a probe user cannot construct or run client proof', async () => {
    let topologyCreates = 0;
    let proofClaims = 0;
    const host = createL2tpPanelHost({
        env: { TOPOLOGY_PROBE_USER_ID: 'probe-user' },
        moduleEntry: {
            registerModels: () => ({ RelayL2tpState: {}, CascadeTopologyState: {},
                CascadeRouteGroup: {}, L2tpOperation: {}, NodeOperationLock: {},
                TopologyOperation: { async findOneAndUpdate() { proofClaims += 1; } } }),
            createTopologyDeploymentService() { topologyCreates += 1; throw Error('non-TEST'); },
        },
        topologyRuntime: {},
        Repository: class {},
        createRepositoryAdapters: () => ({ nodeRepository: {}, stateRepository: {}, operationRepository: {} }),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({ runtime: { stateManagementService: {} }, start() {}, async stop() {} }),
    });
    host.start();
    await host.stop();
    assert.equal(topologyCreates, 0);
    assert.equal(proofClaims, 0);
});

test('TEST host without probe user leaves proof unclaimed while topology recovery still runs', async () => {
    const timer = createFakeTimer();
    let topologyRuns = 0;
    let proofClaims = 0;
    const TopologyOperation = {
        find: () => createScanModel([{ _id: 'queued', status: 'queued' }]).find(),
        async findOneAndUpdate() { proofClaims += 1; throw Error('must not claim'); },
    };
    const host = createL2tpPanelHost({
        env: { ...ENABLED_ENV, PANEL_DOMAIN: 'test.infograd.online' },
        moduleEntry: {
            registerModels: () => ({ TopologyOperation, RelayL2tpState: {}, CascadeTopologyState: {},
                CascadeRouteGroup: {}, L2tpOperation: {}, NodeOperationLock: {} }),
            createTopologyDeploymentService: () => ({ operationWorker: { async run() { topologyRuns += 1; } } }),
        },
        topologyRuntime: {},
        Repository: class {},
        createRepositoryAdapters: () => ({ nodeRepository: {}, stateRepository: {}, operationRepository: {} }),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({ runtime: { stateManagementService: {} }, start() {}, async stop() {} }),
        workerLifecycle: { timer, logger: { error() {} } },
    });
    host.start();
    await host.stop();
    assert.equal(topologyRuns, 1);
    assert.equal(proofClaims, 0);
});
