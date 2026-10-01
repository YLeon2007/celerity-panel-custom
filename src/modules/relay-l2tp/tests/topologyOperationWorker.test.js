'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const { TopologyOperationWorker, LeaseLostError } = require('../workers/topologyOperationWorker');
const { TopologyOperationFinalizer } = require('../services/topologyOperationFinalizer');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');

const NOW = new Date('2026-09-22T10:00:00.000Z');
const CANDIDATE_MEDIA_TYPE = 'application/vnd.celerity.xray-topology-node+json;version=1';
const TARGET_BY_ROLE = Object.freeze({
    portal: Object.freeze({
        targetProfile: 'xray-main',
        serviceUnit: 'xray.service',
        serviceUnitPath: '/etc/systemd/system/xray.service',
        configPath: '/usr/local/etc/xray/config.json',
    }),
    relay: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
    bridge: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
});

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    for (const nested of Object.values(value)) deepFreeze(nested);
    return Object.freeze(value);
}

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonicalize(value[key])]),
    );
}

function frozenNode(node, role, nodeRef) {
    const target = TARGET_BY_ROLE[role];
    const checks = [{
        type: 'service',
        serviceUnit: target.serviceUnit,
        expectedState: 'active',
    }];
    const content = `${JSON.stringify(canonicalize({
        inbounds: [{ tag: `client-${nodeRef}` }],
        outbounds: [{ tag: 'direct' }],
        routing: { rules: [] },
    }))}\n`;
    const sha256 = createHash('sha256').update(content).digest('hex');
    return deepFreeze({
        node,
        nodeRef,
        role,
        ...target,
        candidate: {
            mediaType: CANDIDATE_MEDIA_TYPE,
            bytes: [...Buffer.from(content, 'utf8')],
            sha256,
        },
        candidateHash: sha256,
        checks,
    });
}

function durableNode(node, state = 'pending') {
    return {
        node: node.node,
        nodeRef: node.nodeRef,
        role: node.role,
        targetProfile: node.targetProfile,
        checks: structuredClone(node.checks),
        state,
        candidateHash: node.candidateHash,
        candidate: {
            mediaType: node.candidate.mediaType,
            bytes: [...node.candidate.bytes],
            sha256: node.candidate.sha256,
        },
        backupId: '',
    };
}

function frozenPlan() {
    return deepFreeze({
        operationId: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: [
            frozenNode('node-b', 'bridge', 'bridge'),
            frozenNode('node-a', 'portal', 'portal'),
        ],
    });
}

function durableOperation() {
    const nodes = frozenPlan().nodes
        .map(node => durableNode(node))
        .sort((left, right) => left.node.localeCompare(right.node));
    return {
        _id: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        status: 'queued',
        attempts: 0,
        leaseOwner: '',
        leaseUntil: null,
        nodes,
    };
}

function frozenThreeNodePlan() {
    return deepFreeze({
        operationId: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: [
            frozenNode('node-c', 'bridge', 'bridge'),
            frozenNode('node-a', 'portal', 'portal'),
            frozenNode('node-b', 'relay', 'relay-1'),
        ],
    });
}

function durableThreeNodeOperation() {
    const nodes = frozenThreeNodePlan().nodes
        .map(node => durableNode(node))
        .sort((left, right) => left.node.localeCompare(right.node));
    return {
        ...durableOperation(),
        nodes,
    };
}

function durableTopologyOperation(order) {
    const nodesByRole = {
        portal: frozenNode('node-z', 'portal', 'portal'),
        relay: frozenNode('node-a', 'relay', 'relay-1'),
        bridge: frozenNode('node-m', 'bridge', 'bridge'),
    };
    return {
        ...durableOperation(),
        nodes: order.map(role => durableNode(nodesByRole[role])),
    };
}

function createRepository(operation = durableOperation(), overrides = {}) {
    const calls = [];
    return {
        calls,
        operation,
        async claim(request) {
            calls.push({ method: 'claim', request });
            const expiredPreparing = operation.status === 'preparing'
                && operation.leaseUntil instanceof Date
                && operation.leaseUntil <= request.now;
            if (operation.status !== 'queued' && !expiredPreparing) return null;
            operation.status = 'preparing';
            operation.leaseOwner = request.owner;
            operation.leaseUntil = new Date(request.now.getTime() + request.leaseMs);
            operation.attempts += 1;
            return operation;
        },
        async renewLease(request) {
            calls.push({ method: 'renewLease', request });
            return true;
        },
        async recordNode(request) {
            calls.push({ method: 'recordNode', request });
            const node = operation.nodes.find(item => item.node === request.node);
            if (node) Object.assign(node, {
                state: request.state,
                ...(request.candidateHash === undefined
                    ? {}
                    : { candidateHash: request.candidateHash }),
                ...(request.backupId === undefined ? {} : { backupId: request.backupId }),
            });
            return true;
        },
        async setPhase(request) {
            calls.push({ method: 'setPhase', request });
            if (operation.status !== request.from) return false;
            operation.status = request.to;
            return true;
        },
        async finishClaimed(request) {
            calls.push({ method: 'finishClaimed', request });
            operation.status = request.status;
            return true;
        },
        async recordPppProbeLock({ node, generation, owner }) {
            operation.pppWait.probeLocks ||= [];
            operation.pppWait.probeLocks.push({ node, generation, owner });
            return true;
        },
        async acknowledgePppProbeLockRelease({ node, generation }) {
            operation.pppWait.probeLocks = operation.pppWait.probeLocks.filter(lock =>
                lock.node !== node || lock.generation !== generation);
            return true;
        },
        ...overrides,
    };
}

function createWorker({
    repository,
    executor,
    finalizer,
    clock,
    lockService,
    timer,
    renewalIntervalMs,
    userResync,
    pppReadinessGate,
    pppResumeReadinessGate,
    pppDriftSync,
    allowUnprovenTestExecution = true,
} = {}) {
    const suppliedLockService = lockService || {
        async acquire({ node }) { return { ok: true, lock: { generation: `test-${node}` } }; },
        async renew() { return { ok: true }; },
        async releaseVerified() { return { ok: true }; },
        async release() { return { ok: true }; },
    };
    // Old behavioral fixtures predate generation; supply a test-only token.
    const effectiveLockService = {
        ...suppliedLockService,
        renew: request => suppliedLockService.renew(request),
        release: request => suppliedLockService.release
            ? suppliedLockService.release(request) : Promise.resolve({ ok: true }),
        async acquire(request) {
            const result = await suppliedLockService.acquire(request);
            return result?.ok && !result.lock?.generation
                ? { ...result, lock: { generation: `test-${request.node}` } }
                : result;
        },
        async releaseVerified(request) {
            return suppliedLockService.releaseVerified
                ? suppliedLockService.releaseVerified(request)
                : suppliedLockService.release(request);
        },
    };
    const effectiveFinalizer = finalizer || {
        async finalizeSucceeded(request) {
            return {
                operationId: request.operationId,
                topologyRevision: request.topologyRevision,
                deployedRevision: request.topologyRevision,
                finishedAt: new Date(NOW),
            };
        },
    };
    return new TopologyOperationWorker({
        operationRepository: repository,
        executor,
        finalizer: effectiveFinalizer,
        lockService: effectiveLockService,
        workerId: 'worker-1',
        leaseMs: 30_000,
        clock: clock || { now: () => new Date(NOW) },
        timer,
        renewalIntervalMs,
        userResync,
        pppReadinessGate,
        pppResumeReadinessGate,
        pppDriftSync,
        ...(allowUnprovenTestExecution ? { allowUnprovenTestExecution: true } : {}),
    });
}

test('worker without test-only execution permission rejects before claim, lock, or executor', async () => {
    const repository = createRepository();
    const calls = [];
    const executor = Object.fromEntries([
        'prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback',
    ].map(method => [method, async () => {
        calls.push(`executor.${method}`);
        throw new Error('executor must not run');
    }]));
    const worker = createWorker({
        repository,
        executor,
        allowUnprovenTestExecution: false,
        lockService: {
            async acquire() { calls.push('lock.acquire'); },
            async renew() { calls.push('lock.renew'); },
            async release() { calls.push('lock.release'); },
        },
        clock: { now() { calls.push('clock.now'); return new Date(NOW); } },
    });

    assert.deepEqual(await worker.run('operation-1'), {
        claimed: false,
        operationId: 'operation-1',
        stopped: true,
        errorCode: 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN',
    });
    assert.deepEqual(repository.calls, []);
    assert.deepEqual(calls, []);
    assert.equal(repository.operation.status, 'queued');
    assert.equal(repository.operation.attempts, 0);
});

async function successfulLifecycleEvents(order, lockService) {
    const repository = createRepository(durableTopologyOperation(order));
    const events = [];
    const executor = {
        async prepare(request) {
            events.push({ method: 'prepare', role: request.node.role });
            return {
                backupId: `backup-${request.node.node}`,
                prepared: { opaque: request.node.node },
            };
        },
        async commit(request) {
            events.push({ method: 'commit', role: request.node.role });
            return { ok: true };
        },
        async verify(request) {
            events.push({ method: 'verify', role: request.node.role });
            return { ok: true };
        },
        async cleanupPrepared() { return { ok: true }; },
        async rollback() { return { ok: true }; },
    };
    const worker = createWorker({
        repository,
        executor,
        lockService,
        deploymentRepository: {
            async markDeployed() { return { revision: 7, deployedRevision: 7 }; },
        },
    });

    const result = await worker.run('operation-1');
    assert.equal(result.status, 'succeeded');
    return events;
}

test('normal worker finalization accepts the strict finalizer interface without rolling back', async () => {
    const repository = createRepository();
    let rollbackCount = 0;
    const finalizer = new TopologyOperationFinalizer({
        repository: { async finalizeSucceeded(input) {
            return { operationId: input.operationId, topologyRevision: input.topologyRevision,
                deployedRevision: input.topologyRevision, finishedAt: input.now };
        } },
        clock: { now: () => new Date(NOW) },
    });
    const worker = createWorker({
        repository,
        finalizer,
        executor: {
            async prepare() { return { backupId: 'backup', prepared: { opaque: true } }; },
            async commit() { return { ok: true }; },
            async verify() { return { ok: true }; },
            async rollback() { rollbackCount += 1; return { ok: true }; },
            async cleanupPrepared() { return { ok: true }; },
        },
    });
    assert.equal((await worker.run('operation-1')).status, 'succeeded');
    assert.equal(rollbackCount, 0);
});

test('a verified topology success renews and releases exact-generation node locks for the next link', async () => {
    const held = new Set();
    const lockService = {
        async acquire({node}) { held.add(node); return {ok:true, lock:{generation:`gen-${node}`}}; },
        async renew({node,generation}) { assert.equal(generation,`gen-${node}`); return {ok:true}; },
        async releaseVerified({node,generation}) {
            assert.equal(generation,`gen-${node}`);
            assert.equal(held.delete(node),true);
            return {ok:true};
        },
        async release() { throw new Error('uncertain lock must not be released'); },
    };
    await successfulLifecycleEvents(['portal','relay','bridge'],lockService);
    assert.equal(held.size,0);
});

async function rollbackRolesAfterFinalVerifyFailure(order) {
    const repository = createRepository(durableTopologyOperation(order));
    const rollbackRoles = [];
    const executor = {
        async prepare(request) {
            return {
                backupId: `backup-${request.node.node}`,
                prepared: { opaque: request.node.node },
            };
        },
        async commit() { return { ok: true }; },
        async verify(request) {
            return { ok: request.node.role !== order.at(-1) };
        },
        async cleanupPrepared() { return { ok: true }; },
        async rollback(request) {
            rollbackRoles.push(request.node.role);
            return { ok: true };
        },
    };
    const worker = createWorker({
        repository,
        executor,
        deploymentRepository: {
            async markDeployed() { throw new Error('failed verification must not finalize'); },
        },
    });

    const result = await worker.run('operation-1');
    assert.equal(result.status, 'rolled_back');
    return rollbackRoles;
}

function createManualTimer() {
    let callback;
    return {
        setInterval(next) {
            callback = next;
            return 1;
        },
        clearInterval() {
            callback = undefined;
        },
        async tick() {
            assert.equal(typeof callback, 'function', 'lease heartbeat must be active');
            await callback();
        },
        isActive() {
            return typeof callback === 'function';
        },
    };
}

function deferred() {
    let resolve;
    const promise = new Promise(next => { resolve = next; });
    return { promise, resolve };
}

function createSlowPhaseHarness(phase) {
    const started = deferred();
    const release = deferred();
    let entered = false;
    let prepareCalls = 0;
    let commitCalls = 0;
    const pause = async currentPhase => {
        if (currentPhase !== phase) return;
        if (!entered) {
            entered = true;
            started.resolve();
        }
        await release.promise;
    };
    return {
        started: started.promise,
        release: release.resolve,
        expectedStatus: ['cleanupPrepared', 'rollback'].includes(phase)
            ? 'rolled_back'
            : 'succeeded',
        executor: {
            async prepare(request) {
                prepareCalls += 1;
                if (phase === 'cleanupPrepared' && prepareCalls === 2) {
                    throw new Error('start prepared-node cleanup');
                }
                await pause('prepare');
                return {
                    backupId: `backup-${request.node.node}`,
                    prepared: Object.freeze({ node: request.node.node }),
                };
            },
            async commit() {
                commitCalls += 1;
                if (phase === 'rollback' && commitCalls === 2) {
                    return { ok: false };
                }
                await pause('commit');
                return { ok: true };
            },
            async verify() {
                await pause('verify');
                return { ok: true };
            },
            async cleanupPrepared() {
                await pause('cleanupPrepared');
                return { ok: true };
            },
            async rollback() {
                await pause('rollback');
                return { ok: true };
            },
        },
    };
}

const SLOW_EXECUTOR_PHASES = Object.freeze([
    'prepare',
    'commit',
    'verify',
    'cleanupPrepared',
    'rollback',
]);

test('fresh worker resumes an expired preparing claim from durable candidates only', async () => {
    const operation = durableOperation();
    operation.status = 'preparing';
    operation.leaseOwner = 'stopped-process';
    operation.leaseUntil = new Date(NOW.getTime() - 1);
    const repository = createRepository(operation);
    const preparedNodes = [];
    const executor = {
        async prepare(request) {
            assert.equal(Object.isFrozen(request.node), true);
            assert.equal(Object.isFrozen(request.node.candidate), true);
            assert.equal(request.node.candidateHash, request.node.candidate.sha256);
            preparedNodes.push({
                node: request.node.node,
                role: request.node.role,
                targetProfile: request.node.targetProfile,
            });
            return {
                backupId: `backup-${request.node.node}`,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async commit() { return { ok: true }; },
        async verify() { return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; },
        async rollback() { return { ok: true }; },
    };
    const worker = createWorker({
        repository,
        executor,
        deploymentRepository: {
            async markDeployed() { return { revision: 7, deployedRevision: 7 }; },
        },
    });

    const result = await worker.run('operation-1');

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-1',
        status: 'succeeded',
    });
    assert.deepEqual(preparedNodes, [
        { node: 'node-a', role: 'portal', targetProfile: 'xray-main' },
        { node: 'node-b', role: 'bridge', targetProfile: 'xray-bridge' },
    ]);
    assert.equal(repository.calls[0].method, 'claim');
    assert.equal(repository.calls[0].request.operationId, 'operation-1');
    assert.equal(operation.attempts, 1);
});

test('expired durable node lock stops topology recovery before any executor dispatch', async () => {
    const operation = durableOperation();
    operation.status = 'preparing';
    operation.leaseUntil = new Date(NOW.getTime() - 1);
    const repository = createRepository(operation);
    let inserts = 0;
    const held = { node: 'node-a', owner: 'stopped-process', operationId: 'operation-1',
        leaseUntil: new Date(NOW.getTime() - 1), remoteUncertain: true, generation: 'old-token' };
    const lockService = new NodeOperationLockService({
        repository: new NodeOperationLockRepository({ model: {
            async create() { inserts += 1; throw Object.assign(new Error('duplicate key'), { code: 11000 }); },
            findOne() { return { lean: async () => ({ ...held }) }; },
        } }),
        clock: { now: () => new Date(NOW) },
    });
    let dispatched = 0;
    const forbidden = async () => { dispatched += 1; throw new Error('unexpected dispatch'); };
    const worker = createWorker({ repository, lockService,
        executor: { prepare: forbidden, commit: forbidden, verify: forbidden,
            cleanupPrepared: forbidden, rollback: forbidden },
    });
    for (const attempt of [1, 2]) {
        operation.leaseUntil = new Date(NOW.getTime() - 1);
        assert.deepEqual(await worker.run('operation-1'), {
            claimed: true, operationId: 'operation-1', status: 'preparing',
            stopped: true, errorCode: 'NODE_OPERATION_LOCK_CONFLICT',
        }, `attempt ${attempt} must remain blocked`);
    }
    assert.equal(inserts, 2);
    assert.equal(dispatched, 0);
    assert.equal(held.generation, 'old-token');
});

test('successful deploy resyncs users before atomic success finalization', async () => {
    const operation = durableOperation();
    operation.status = 'preparing';
    operation.leaseOwner = 'stopped-process';
    operation.leaseUntil = new Date(NOW.getTime() - 1);
    const repository = createRepository(operation);
    const executor = {
        async prepare(request) {
            return {
                backupId: `backup-${request.node.node}`,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async commit() { return { ok: true }; },
        async verify() { return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; },
        async rollback() { return { ok: true }; },
    };
    const resynced = [];
    const events = [];
    const worker = createWorker({
        repository,
        executor,
        finalizer: {
            async finalizeSucceeded() {
                events.push('finalized');
                return { ok: true };
            },
        },
        userResync: {
            async resyncPlan(plan) {
                events.push('resynced');
                resynced.push(plan.operationId ?? plan.kind);
                return { ok: true };
            },
        },
    });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'succeeded');
    assert.equal(resynced.length, 1);
    assert.deepEqual(events, ['resynced', 'finalized']);
});

test('user resync failure rolls back changed nodes before finalization', async () => {
    const operation = durableOperation();
    operation.status = 'preparing';
    operation.leaseOwner = 'stopped-process';
    operation.leaseUntil = new Date(NOW.getTime() - 1);
    const repository = createRepository(operation);
    const executor = {
        async prepare(request) {
            return {
                backupId: `backup-${request.node.node}`,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async commit() { return { ok: true }; },
        async verify() { return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; },
        async rollback() { return { ok: true }; },
    };
    const rollbackNodes = [];
    let finalized = false;
    let resyncCalls = 0;
    const worker = createWorker({
        repository,
        executor: {
            ...executor,
            async rollback(request) {
                rollbackNodes.push(String(request.node.node));
                return { ok: true };
            },
        },
        finalizer: {
            async finalizeSucceeded() { finalized = true; return { ok: true }; },
        },
        userResync: {
            async resyncPlan() {
                resyncCalls += 1;
                if (resyncCalls === 1) throw new Error('agent down');
                assert.ok(rollbackNodes.length > 0, 'restore users only after node rollback');
                return { ok: true };
            },
        },
    });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'rolled_back');
    assert.equal(finalized, false);
    assert.ok(rollbackNodes.length > 0);
    assert.equal(resyncCalls, 2);
});

test('only an explicitly staged durable link apply reaches the PPP gate as staged', async t => {
    for (const [kind, staged, expected] of [
        ['link.apply', true, true],
        ['link.apply', false, undefined],
        ['domain.reconcile', true, undefined],
    ]) {
        await t.test(`${kind} staged=${staged}`, async () => {
            const repository = createRepository({ ...durableThreeNodeOperation(), kind, staged });
            const worker = createWorker({
                repository,
                executor: {
                    async prepare() { return { backupId: 'backup', prepared: {} }; },
                    async commit() { return { ok: true }; },
                    async verify() { return { ok: true }; },
                    async cleanupPrepared() { return { ok: true }; },
                    async rollback() { return { ok: true }; },
                },
                pppReadinessGate: { async verifyPlan(plan) {
                    assert.equal(plan.staged, expected);
                    return { ok: true, verifiedRelayCount: expected ? 0 : 1,
                        ...(expected ? { skippedRelayCount: 1 } : {}) };
                } },
            });
            assert.equal((await worker.run('operation-1')).status, 'succeeded');
        });
    }
});

test('PPP node readback failure rolls back changed nodes before terminal success', async t => {
    for (const unavailable of [false, true]) {
        await t.test(unavailable ? 'runner unavailable' : 'runner mismatch', async () => {
            const events = [];
            const repository = createRepository(durableThreeNodeOperation());
            const worker = createWorker({
                repository,
                executor: {
                    async prepare(request) { return { backupId: `backup-${request.node.node}`, prepared: {} }; },
                    async commit() { return { ok: true }; },
                    async verify() { return { ok: true }; },
                    async cleanupPrepared() { return { ok: true }; },
                    async rollback(request) { events.push(`rollback:${request.node.node}`); return { ok: true }; },
                },
                userResync: { async resyncPlan() { events.push('xray-sync'); return { ok: true }; } },
                pppReadinessGate: { async verifyPlan(plan) {
                    events.push('ppp-readback');
                    assert.ok(Object.isFrozen(plan));
                    if (unavailable) throw new Error('private-ppp-password');
                    return { ok: false, verifiedRelayCount: 0 };
                } },
                finalizer: { async finalizeSucceeded() { events.push('finalized'); return { ok: true }; } },
            });
            const result = await worker.run('operation-1');
            assert.equal(result.status, 'rolled_back');
            assert.deepEqual(events.slice(0, 2), ['xray-sync', 'ppp-readback']);
            assert.equal(events.includes('finalized'), false);
            assert.equal(events.filter(event => event.startsWith('rollback:')).length, 3);
        });
    }
});

test('verified PPP drift persists a wait before a quiescent lock handoff and sync enqueue', async () => {
    const events = [];
    const operation = durableThreeNodeOperation();
    operation.heldTopologyAdmission = true;
    const repository = createRepository(operation, {
        async beginPppWait(request) {
            events.push('persist-wait');
            assert.equal(operation.status, 'committing');
            assert.equal(operation.heldTopologyAdmission, true);
            assert.deepEqual(request.locks.map(lock => lock.node).sort(), ['node-a', 'node-b', 'node-c']);
            operation.pppWait = { lockOwner: request.lockOwner,
                relayNode: request.relayNode, credentialRevision: request.credentialRevision,
                locks: request.locks, releasedNodes: [] };
            return true;
        },
        async acknowledgePppLockRelease({ node }) {
            operation.pppWait.releasedNodes.push(node);
            return true;
        },
    });
    const worker = createWorker({
        repository,
        lockService: {
            async acquire({ node }) { return { ok: true, lock: { generation: `gen-${node}` } }; },
            async renew() { return { ok: true }; },
            async releaseVerified({ node }) {
                assert.ok(operation.pppWait, 'wait must be durable before lock release');
                events.push(`release:${node}`);
                return { ok: true };
            },
        },
        executor: {
            async prepare({ node }) { return { backupId: `backup-${node.node}`, prepared: {} }; },
            async commit() { return { ok: true }; },
            async verify() { return { ok: true }; },
            async cleanupPrepared() { return { ok: true }; },
            async rollback() { events.push('rollback'); return { ok: true }; },
        },
        pppReadinessGate: { async verifyPlan() {
            return { ok: false, reason: 'PPP_DRIFT', relayNode: 'node-b', credentialRevision: 7 };
        } },
        pppDriftSync: { async enqueue({ relayNode }) {
            assert.equal(relayNode, 'node-b');
            assert.equal(events.filter(event => event.startsWith('release:')).length, 3);
            events.push('enqueue');
            return { status: 'queued' };
        } },
        finalizer: { async finalizeSucceeded() { events.push('publish'); return { ok: true }; } },
    });
    const result = await worker.run('operation-1');
    assert.equal(result.status, 'awaiting_ppp');
    assert.deepEqual(events, ['persist-wait', 'release:node-c', 'release:node-b',
        'release:node-a', 'enqueue']);
    assert.equal(events.includes('publish'), false);
    assert.equal(events.includes('rollback'), false);
    assert.equal(operation.heldTopologyAdmission, true);
});

test('failed exact-generation wait handoff never enqueues PPP sync or rolls back', async () => {
    const operation = durableThreeNodeOperation();
    operation.heldTopologyAdmission = true;
    const repository = createRepository(operation, {
        async beginPppWait({ locks, relayNode, credentialRevision, lockOwner }) {
            operation.pppWait = { locks, relayNode, credentialRevision, lockOwner,
                releasedNodes: [] };
            return true;
        },
        async acknowledgePppLockRelease() { throw new Error('must not acknowledge failed release'); },
    });
    let queued = 0;
    let rolledBack = 0;
    const worker = createWorker({
        repository,
        executor: {
            async prepare({ node }) { return { backupId: `backup-${node.node}`, prepared: {} }; },
            async commit() { return { ok: true }; },
            async verify() { return { ok: true }; },
            async cleanupPrepared() { return { ok: true }; },
            async rollback() { rolledBack += 1; return { ok: true }; },
        },
        lockService: {
            async acquire({ node }) { return { ok: true, lock: { generation: `gen-${node}` } }; },
            async renew() { return { ok: true }; },
            async releaseVerified() { return { ok: false }; },
        },
        pppReadinessGate: { async verifyPlan() {
            return { ok: false, reason: 'PPP_DRIFT', relayNode: 'node-b', credentialRevision: 7 };
        } },
        pppDriftSync: { async enqueue() { queued += 1; } },
        finalizer: { async finalizeSucceeded() { throw new Error('not ready'); } },
    });
    assert.equal((await worker.run('operation-1')).status, 'awaiting_ppp');
    assert.equal(operation.status, 'committing');
    assert.equal(operation.heldTopologyAdmission, true);
    assert.equal(queued, 0);
    assert.equal(rolledBack, 0);
});

test('recovered PPP wait reacquires fresh locks and re-reads revision before publication', async () => {
    const operation = durableThreeNodeOperation();
    operation.nodes.push(durableNode(frozenNode('node-d', 'relay', 'relay-2')));
    operation.status = 'committing';
    operation.heldTopologyAdmission = true;
    operation.nodes.forEach(node => { node.state = 'committed'; node.backupId = `backup-${node.node}`; });
    operation.pppWait = { lockOwner: 'original-worker', relayNode: 'node-b', credentialRevision: 7,
        locks: ['node-a', 'node-b', 'node-c', 'node-d'].map(node => ({ node, generation: `old-${node}` })),
        releasedNodes: ['node-a', 'node-b', 'node-c', 'node-d'] };
    const events = [];
    const repository = createRepository(operation, {
        async claim({ owner, now, leaseMs }) {
            if (operation.leaseUntil && operation.leaseUntil > now) return null;
            operation.leaseOwner = owner;
            operation.leaseUntil = new Date(now.getTime() + leaseMs);
            return structuredClone(operation);
        },
        async renewLease() { return true; },
    });
    const worker = createWorker({
        repository,
        executor: Object.fromEntries(['prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback']
            .map(method => [method, async () => { throw new Error(`no ${method} on resume`); }])),
        lockService: {
            async acquire({ node }) { events.push(`acquire:${node}`);
                return { ok: true, lock: { generation: `fresh-${node}` } }; },
            async renew({ generation }) { assert.ok(generation.startsWith('fresh-')); return { ok: true }; },
            async releaseVerified({ generation }) { assert.ok(generation.startsWith('fresh-'));
                events.push('release'); return { ok: true }; },
        },
        pppReadinessGate: { async verifyPlan() { throw new Error('bootstrap gate on resume'); } },
        pppResumeReadinessGate: { readOnly: true, async verifyPlan() {
            events.push('fresh-ppp-readback');
            return { ok: true, verifiedRelayCount: 1,
                relayRevisions: [{ relayNode: 'node-b', credentialRevision: 8 }] };
        } },
        pppDriftSync: { async enqueue() { throw new Error('already queued'); } },
        finalizer: { async finalizeSucceeded(request) {
            assert.deepEqual(Object.keys(request).sort(), [
                'leaseUntil', 'operationId', 'owner', 'pppProof',
                'priorDeployedRevision', 'topologyRevision',
            ].sort());
            assert.deepEqual(request.pppProof,
                [{ relayNode: 'node-b', credentialRevision: 8 }]);
            assert.equal(operation.heldTopologyAdmission, true);
            events.push('publish');
            operation.status = 'succeeded';
            return { ok: true };
        } },
    });
    const result = await worker.run('operation-1');
    assert.equal(result.status, 'succeeded');
    assert.deepEqual(events.slice(0, 5), ['acquire:node-a', 'acquire:node-b',
        'acquire:node-c', 'acquire:node-d', 'fresh-ppp-readback']);
    assert.equal(events.filter(event => event === 'release').length, 4);
    assert.equal(events.at(-1), 'publish');
});

test('crash after read-only lock acquisition reclaims durable generations without bootstrap', async () => {
    const operation = durableThreeNodeOperation();
    operation.status = 'committing';
    operation.heldTopologyAdmission = true;
    operation.nodes.forEach(node => { node.state = 'committed'; node.backupId = `backup-${node.node}`; });
    operation.pppWait = { lockOwner: 'old-worker', relayNode: 'node-b',
        credentialRevision: 7, locks: ['node-a', 'node-b', 'node-c'].map(node =>
            ({ node, generation: `old-${node}` })),
        releasedNodes: ['node-b', 'node-c'], probeLocks: [] };
    const repository = createRepository(operation, {
        async claim({ owner, now, leaseMs }) {
            operation.leaseOwner = owner;
            operation.leaseUntil = new Date(now.getTime() + leaseMs);
            return structuredClone(operation);
        },
        async acknowledgePppLockRelease({ node }) {
            operation.pppWait.releasedNodes.push(node);
            return true;
        },
    });
    const held = new Map();
    const releases = [];
    let sequence = 0;
    let probes = 0;
    const lockService = {
        repository: { async findByNode(node) { return held.get(node) || null; } },
        async acquire({ node, owner, operationId }) {
            assert.equal(held.has(node), false, `orphan lock on ${node}`);
            const lock = { node, owner, operationId, generation: `fresh-${++sequence}` };
            held.set(node, lock);
            return { ok: true, lock };
        },
        async renew() { return { ok: true }; },
        async releaseVerified({ node, owner, operationId, generation }) {
            const lock = held.get(node);
            if (!lock || lock.owner !== owner || lock.operationId !== operationId
                || lock.generation !== generation) return { ok: false };
            held.delete(node);
            releases.push(generation);
            return { ok: true };
        },
    };
    const worker = createWorker({
        repository, lockService,
        executor: Object.fromEntries(['prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback']
            .map(method => [method, async () => { throw new Error(`mutating ${method}`); }])),
        pppReadinessGate: { async verifyPlan() { throw new Error('bootstrap'); } },
        pppResumeReadinessGate: { readOnly: true, async verifyPlan() {
            probes += 1;
            if (probes === 1) {
                assert.equal(operation.pppWait.probeLocks.length, 3,
                    'every newly acquired generation must be durable before probing');
                throw new LeaseLostError();
            }
            return { ok: false, reason: 'PPP_UNAVAILABLE' };
        } },
        pppDriftSync: { async enqueue() { throw new Error('unknown is not drift'); } },
        finalizer: { async finalizeSucceeded() { throw new Error('unknown is not success'); } },
    });
    assert.equal((await worker.run('operation-1')).errorCode, 'TOPOLOGY_OPERATION_LEASE_LOST');
    assert.equal(operation.pppWait.releasedNodes.length, 3,
        'readback of absent old generation must be ACKed');
    assert.equal(held.size, 3);
    assert.deepEqual(operation.pppWait.probeLocks.map(lock => lock.generation),
        ['fresh-1', 'fresh-2', 'fresh-3']);
    assert.equal((await worker.run('operation-1')).status, 'awaiting_ppp');
    assert.equal(probes, 2);
    assert.deepEqual(releases.slice(0, 3), ['fresh-3', 'fresh-2', 'fresh-1']);
    assert.equal(held.size, 0);
    assert.deepEqual(operation.pppWait.probeLocks, []);
    assert.equal(operation.status, 'committing');
    assert.equal(operation.heldTopologyAdmission, true);
});

test('resume rejects a bootstrap-capable PPP gate even when supplied separately', () => {
    assert.throws(() => createWorker({
        repository: createRepository(),
        executor: Object.fromEntries(['prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback']
            .map(method => [method, async () => ({ ok: true })])),
        pppResumeReadinessGate: { readOnly: false, async verifyPlan() { return { ok: true }; } },
    }), /read.only/i);
    const sharedGate = { readOnly: true, async verifyPlan() { return { ok: true }; } };
    assert.throws(() => createWorker({
        repository: createRepository(),
        executor: Object.fromEntries(['prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback']
            .map(method => [method, async () => ({ ok: true })])),
        pppReadinessGate: sharedGate,
        pppResumeReadinessGate: sharedGate,
    }), /separate/i);
});

test('post-resume PPP timeout releases fresh locks and retries without bootstrap', async () => {
    const operation = durableThreeNodeOperation();
    operation.status = 'committing';
    operation.heldTopologyAdmission = true;
    operation.nodes.forEach(node => { node.state = 'committed'; node.backupId = `backup-${node.node}`; });
    operation.pppWait = { lockOwner: 'original-worker', relayNode: 'node-b', credentialRevision: 7,
        locks: ['node-a', 'node-b', 'node-c'].map(node => ({ node, generation: `old-${node}` })),
        releasedNodes: ['node-a', 'node-b', 'node-c'] };
    const repository = createRepository(operation, {
        async claim({ owner, now, leaseMs }) {
            operation.leaseOwner = owner;
            operation.leaseUntil = new Date(now.getTime() + leaseMs);
            return structuredClone(operation);
        },
    });
    const held = new Map();
    let checks = 0;
    let finalized = 0;
    let releaseAttempts = 0;
    const worker = createWorker({
        repository,
        executor: Object.fromEntries(['prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback']
            .map(method => [method, async () => { throw new Error(`no ${method}`); }])),
        lockService: {
            repository: { async findByNode(node) {
                return held.has(node) ? { node, generation: held.get(node), operationId: 'operation-1' }
                    : null;
            } },
            async acquire({ node }) {
                if (held.has(node)) return { ok: false, error: { code: 'NODE_OPERATION_LOCK_CONFLICT' } };
                held.set(node, `fresh-${node}`);
                return { ok: true, lock: { generation: `fresh-${node}` } };
            },
            async renew() { return { ok: true }; },
            async releaseVerified({ node, generation }) {
                assert.equal(held.get(node), generation);
                if (++releaseAttempts === 1) return { ok: false }; // uncertain DB delete
                held.delete(node);
                return { ok: true };
            },
        },
        pppReadinessGate: { async verifyPlan() { throw new Error('bootstrap gate on resume'); } },
        pppResumeReadinessGate: { readOnly: true, async verifyPlan() { checks += 1;
            return { ok: false, reason: 'PPP_UNAVAILABLE' }; } },
        pppDriftSync: { async enqueue() { throw new Error('not proven drift'); } },
        finalizer: { async finalizeSucceeded() { finalized += 1; return { ok: true }; } },
    });
    assert.equal((await worker.run('operation-1')).status, 'awaiting_ppp');
    assert.equal(held.size, 3, 'uncertain release must keep exact fresh generations');
    assert.equal(operation.pppWait.probeLocks.length, 3);
    assert.equal(finalized, 0);
    assert.equal((await worker.run('operation-1')).status, 'awaiting_ppp');
    assert.equal(checks, 2, 'a recovered wait retries using fresh read-only locks');
    assert.equal(finalized, 0);
    assert.equal(operation.heldTopologyAdmission, true);
    assert.equal(held.size, 0);
});

test('post-resume verified PPP drift hands off fresh lock generations before retry enqueue', async () => {
    const operation = durableThreeNodeOperation();
    operation.status = 'committing';
    operation.heldTopologyAdmission = true;
    operation.nodes.forEach(node => { node.state = 'committed'; node.backupId = `backup-${node.node}`; });
    operation.pppWait = { lockOwner: 'original-worker', relayNode: 'node-b', credentialRevision: 7,
        locks: ['node-a', 'node-b', 'node-c'].map(node => ({ node, generation: `old-${node}` })),
        releasedNodes: ['node-a', 'node-b', 'node-c'] };
    const repository = createRepository(operation, {
        async claim({ owner, now, leaseMs }) {
            operation.leaseOwner = owner;
            operation.leaseUntil = new Date(now.getTime() + leaseMs);
            return structuredClone(operation);
        },
    });
    const held = new Map();
    let enqueued = 0;
    const worker = createWorker({
        repository,
        executor: Object.fromEntries(['prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback']
            .map(method => [method, async () => { throw new Error(`no ${method}`); }])),
        lockService: {
            async acquire({ node }) { held.set(node, `fresh-${node}`);
                return { ok: true, lock: { generation: `fresh-${node}` } }; },
            async renew() { return { ok: true }; },
            async releaseVerified({ node, generation }) {
                assert.equal(held.get(node), generation);
                held.delete(node);
                return { ok: true };
            },
        },
        pppReadinessGate: { async verifyPlan() { throw new Error('bootstrap gate on resume'); } },
        pppResumeReadinessGate: { readOnly: true, async verifyPlan() {
            return { ok: false, reason: 'PPP_DRIFT', relayNode: 'node-b', credentialRevision: 8 };
        } },
        pppDriftSync: { async enqueue() {
            assert.equal(held.size, 0, 'sync_users must receive the relay only after quiescent release');
            enqueued += 1;
            return { status: 'queued' };
        } },
        finalizer: { async finalizeSucceeded() { throw new Error('drift is not success'); } },
    });
    assert.equal((await worker.run('operation-1')).status, 'awaiting_ppp');
    assert.equal(enqueued, 1);
    assert.equal(held.size, 0);
    assert.equal(operation.heldTopologyAdmission, true);
});

test('persistent user sync failure after rollback cannot be reported as recovered', async () => {
    const repository = createRepository(durableOperation());
    const executor = {
        async prepare(request) { return { backupId: `backup-${request.node.node}`, prepared: { node: request.node.node } }; },
        async commit() { return { ok: true }; },
        async verify() { return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; },
        async rollback() { return { ok: true }; },
    };
    let resyncCalls = 0;
    const worker = createWorker({
        repository,
        executor,
        userResync: { async resyncPlan() { resyncCalls += 1; return { ok: false }; } },
    });
    const result = await worker.run('operation-1');
    assert.equal(result.status, 'failed');
    assert.equal(resyncCalls, 2);
});

test('lease heartbeat renews while a typed executor call is still running', async () => {
    const repository = createRepository();
    const timer = createManualTimer();
    let enterPrepare;
    const prepareStarted = new Promise(resolve => { enterPrepare = resolve; });
    let finishPrepare;
    const prepareResult = new Promise(resolve => { finishPrepare = resolve; });
    let prepareCalls = 0;
    const executor = {
        async prepare(request) {
            prepareCalls += 1;
            if (prepareCalls === 1) {
                enterPrepare();
                await prepareResult;
            }
            return {
                backupId: `backup-${request.node.node}`,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async commit() { return { ok: true }; },
        async verify() { return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; },
        async rollback() { return { ok: true }; },
    };
    const worker = createWorker({
        repository,
        executor,
        timer,
        renewalIntervalMs: 10_000,
        deploymentRepository: {
            async markDeployed() { return { revision: 7, deployedRevision: 7 }; },
        },
    });

    const running = worker.run('operation-1');
    await prepareStarted;
    const renewalsBeforeTick = repository.calls.filter(call => (
        call.method === 'renewLease'
    )).length;

    await timer.tick();

    const renewalsDuringPrepare = repository.calls.filter(call => (
        call.method === 'renewLease'
    )).length;
    assert.ok(renewalsDuringPrepare > renewalsBeforeTick);
    finishPrepare();
    assert.equal((await running).status, 'succeeded');
    assert.equal(timer.isActive(), false, 'lease heartbeat must stop after the run');
});

test('lease heartbeat interval must be shorter than the lease', () => {
    const repository = createRepository();
    const executor = Object.fromEntries([
        'prepare',
        'commit',
        'verify',
        'cleanupPrepared',
        'rollback',
    ].map(method => [method, async () => ({ ok: true })]));

    assert.throws(() => createWorker({
        repository,
        executor,
        renewalIntervalMs: 30_000,
        deploymentRepository: {
            async markDeployed() { return { revision: 7, deployedRevision: 7 }; },
        },
    }), /lease identity and clock/);
});

test('operation and owned-lock heartbeat stays active during every slow executor phase', async t => {
    for (const phase of SLOW_EXECUTOR_PHASES) {
        await t.test(phase, async () => {
            const repository = createRepository();
            const timer = createManualTimer();
            const events = [];
            const lockService = {
                async acquire(request) {
                    events.push({ method: 'acquire', node: request.node });
                    return { ok: true };
                },
                async renew(request) {
                    events.push({ method: 'renew', node: request.node });
                    return { ok: true };
                },
                async release(request) {
                    events.push({ method: 'release', node: request.node });
                    return { ok: true };
                },
            };
            const harness = createSlowPhaseHarness(phase);
            const worker = createWorker({
                repository,
                executor: harness.executor,
                lockService,
                timer,
                renewalIntervalMs: 10_000,
                deploymentRepository: {
                    async markDeployed() { return { revision: 7, deployedRevision: 7 }; },
                },
            });

            const running = worker.run('operation-1');
            await harness.started;
            const operationRenewals = repository.calls.filter(call => (
                call.method === 'renewLease'
            )).length;
            const lockRenewals = events.filter(event => event.method === 'renew').length;

            await timer.tick();

            assert.ok(repository.calls.filter(call => (
                call.method === 'renewLease'
            )).length > operationRenewals);
            assert.ok(events.filter(event => event.method === 'renew').length > lockRenewals);
            harness.release();
            assert.equal((await running).status, harness.expectedStatus);
            assert.equal(timer.isActive(), false, 'heartbeat timer must be stopped');
            assert.deepEqual(events.filter(event => event.method === 'release'),
                harness.expectedStatus === 'succeeded' ? [
                    { method: 'release', node: 'node-b' },
                    { method: 'release', node: 'node-a' },
                ] : []);
        });
    }
});

test('owned-lock renewal loss in every slow executor phase fences progress and success', async t => {
    for (const phase of SLOW_EXECUTOR_PHASES) {
        await t.test(phase, async () => {
            const repository = createRepository();
            const timer = createManualTimer();
            const events = [];
            let renewalOwned = true;
            let finalized = false;
            const lockService = {
                async acquire(request) {
                    events.push({ method: 'acquire', node: request.node });
                    return { ok: true };
                },
                async renew(request) {
                    events.push({ method: 'renew', node: request.node });
                    return renewalOwned
                        ? { ok: true }
                        : { ok: false, error: { code: 'NODE_OPERATION_LOCK_NOT_OWNED' } };
                },
                async release(request) {
                    events.push({ method: 'release', node: request.node });
                    return { ok: true };
                },
            };
            const harness = createSlowPhaseHarness(phase);
            const worker = createWorker({
                repository,
                executor: harness.executor,
                lockService,
                timer,
                renewalIntervalMs: 10_000,
                finalizer: {
                    async finalizeSucceeded() {
                        finalized = true;
                        return { revision: 7, deployedRevision: 7 };
                    },
                },
            });

            const running = worker.run('operation-1');
            await harness.started;
            renewalOwned = false;
            await timer.tick();
            const durableMutations = repository.calls.filter(call => (
                ['recordNode', 'setPhase', 'finishClaimed'].includes(call.method)
            )).length;
            harness.release();
            const result = await running;

            assert.equal(result.errorCode, 'TOPOLOGY_OPERATION_LEASE_LOST');
            assert.equal(finalized, false);
            assert.equal(timer.isActive(), false, 'failed heartbeat timer must be stopped');
            assert.equal(repository.calls.filter(call => (
                ['recordNode', 'setPhase', 'finishClaimed'].includes(call.method)
            )).length, durableMutations, 'stale worker must not persist further progress');
            assert.deepEqual(events.filter(event => event.method === 'release'), []);
        });
    }
});

test('lease loss during commit fences durable progress after that executor call', async () => {
    let leaseOwned = true;
    const operation = durableOperation();
    const repository = createRepository(operation, {
        async renewLease(request) {
            repository.calls.push({ method: 'renewLease', request });
            return leaseOwned;
        },
    });
    const timer = createManualTimer();
    const lockEvents = [];
    const lockService = {
        async acquire() { return { ok: true }; },
        async renew() { return { ok: true }; },
        async release(request) {
            lockEvents.push({ method: 'release', node: request.node });
            return { ok: true };
        },
    };
    let enterCommit;
    const commitStarted = new Promise(resolve => { enterCommit = resolve; });
    let finishCommit;
    const commitResult = new Promise(resolve => { finishCommit = resolve; });
    const executor = {
        async prepare(request) {
            return {
                backupId: `backup-${request.node.node}`,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async commit() {
            enterCommit();
            await commitResult;
            return { ok: true };
        },
        async verify() { return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; },
        async rollback() { return { ok: true }; },
    };
    let finalized = false;
    const worker = createWorker({
        repository,
        executor,
        timer,
        lockService,
        renewalIntervalMs: 10_000,
        finalizer: {
            async finalizeSucceeded() {
                finalized = true;
                throw new Error('must not finalize after lease loss');
            },
        },
    });

    const running = worker.run('operation-1');
    await commitStarted;
    leaseOwned = false;
    await timer.tick();
    finishCommit();
    const result = await running;

    assert.equal(result.errorCode, 'TOPOLOGY_OPERATION_LEASE_LOST');
    assert.equal(finalized, false);
    assert.equal(timer.isActive(), false);
    assert.deepEqual(lockEvents, []);
    assert.equal(repository.calls.some(call => (
        call.method === 'recordNode'
        && call.request.node === 'node-a'
        && call.request.state === 'committed'
    )), false, 'the stale worker must not persist progress after commit returns');
});

test('node locks are acquired by deterministic node id and released in reverse order', async () => {
    const repository = createRepository(durableTopologyOperation([
        'bridge',
        'relay',
        'portal',
    ]));
    const events = [];
    const lockService = {
        async acquire(request) {
            events.push({ method: 'lock.acquire', node: request.node });
            return { ok: true };
        },
        async renew() { return { ok: true }; },
        async release(request) {
            events.push({ method: 'lock.release', node: request.node });
            return { ok: true };
        },
    };
    const executor = {
        async prepare(request) {
            events.push({ method: 'prepare', node: request.node.node });
            return {
                backupId: `backup-${request.node.node}`,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async commit() { return { ok: true }; },
        async verify() { return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; },
        async rollback() { return { ok: true }; },
    };
    const worker = createWorker({
        repository,
        executor,
        lockService,
        deploymentRepository: {
            async markDeployed() { return { revision: 7, deployedRevision: 7 }; },
        },
    });

    assert.equal((await worker.run('operation-1')).status, 'succeeded');
    assert.deepEqual(events.filter(event => event.method.startsWith('lock.')), [
        { method: 'lock.acquire', node: 'node-a' },
        { method: 'lock.acquire', node: 'node-m' },
        { method: 'lock.acquire', node: 'node-z' },
        { method: 'lock.release', node: 'node-z' },
        { method: 'lock.release', node: 'node-m' },
        { method: 'lock.release', node: 'node-a' },
    ]);
    assert.deepEqual(events.filter(event => event.method === 'prepare'), [
        { method: 'prepare', node: 'node-m' },
        { method: 'prepare', node: 'node-a' },
        { method: 'prepare', node: 'node-z' },
    ]);
    assert.ok(
        events.findIndex(event => event.method === 'lock.acquire' && event.node === 'node-z')
            < events.findIndex(event => event.method === 'prepare'),
        'all locks must be held before preparation starts',
    );
});

test('partial node-lock acquisition keeps acquired locks blocked for TEST rollback', async () => {
    const repository = createRepository(durableTopologyOperation([
        'bridge',
        'relay',
        'portal',
    ]));
    const events = [];
    const timer = createManualTimer();
    const lockService = {
        async acquire(request) {
            events.push({ method: 'acquire', node: request.node });
            if (request.node === 'node-z') {
                return {
                    ok: false,
                    error: { code: 'NODE_OPERATION_LOCK_CONFLICT' },
                };
            }
            return { ok: true };
        },
        async renew() { return { ok: true }; },
        async release(request) {
            events.push({ method: 'release', node: request.node });
            return { ok: true };
        },
    };
    let executorCalls = 0;
    const forbidden = async () => {
        executorCalls += 1;
        throw new Error('executor must not run without every node lock');
    };
    const worker = createWorker({
        repository,
        lockService,
        timer,
        executor: {
            prepare: forbidden,
            commit: forbidden,
            verify: forbidden,
            cleanupPrepared: forbidden,
            rollback: forbidden,
        },
        finalizer: { finalizeSucceeded: forbidden },
    });

    const result = await worker.run('operation-1');

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-1',
        status: 'preparing',
        stopped: true,
        errorCode: 'NODE_OPERATION_LOCK_CONFLICT',
    });
    assert.equal(executorCalls, 0);
    assert.equal(timer.isActive(), false, 'heartbeat timer must stop after lock conflict');
    assert.deepEqual(events, [
        { method: 'acquire', node: 'node-a' },
        { method: 'acquire', node: 'node-m' },
        { method: 'acquire', node: 'node-z' },
    ]);
});


test('altered durable candidate hash fails the fenced claim without executor use', async () => {
    const operation = durableOperation();
    operation.nodes[0].candidate.sha256 = '0'.repeat(64);
    operation.nodes[0].candidateHash = '0'.repeat(64);
    const repository = createRepository(operation);
    let executorCalls = 0;
    const forbidden = async () => {
        executorCalls += 1;
        throw new Error('executor must not run');
    };
    const worker = createWorker({
        repository,
        executor: {
            prepare: forbidden,
            commit: forbidden,
            verify: forbidden,
            cleanupPrepared: forbidden,
            rollback: forbidden,
        },
        deploymentRepository: { markDeployed: forbidden },
    });

    const result = await worker.run('operation-1');

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-1',
        status: 'failed',
    });
    assert.equal(executorCalls, 0);
    assert.deepEqual(repository.calls.map(call => call.method), ['claim', 'finishClaimed']);
    assert.equal(repository.calls[1].request.owner, 'worker-1');
    assert.equal(repository.calls[1].request.status, 'failed');
});

test('legacy metadata-only durable candidates fail before executor use', async () => {
    const operation = durableOperation();
    for (const node of operation.nodes) {
        const legacyContent = `${JSON.stringify({
            schemaVersion: 1,
            kind: 'xray-topology-node-candidate',
            mode: 'forward',
            nodeRef: node.nodeRef,
            role: node.role,
            targetProfile: node.targetProfile,
            links: [],
            checks: node.checks,
        })}\n`;
        const sha256 = createHash('sha256').update(legacyContent).digest('hex');
        node.candidate = {
            mediaType: CANDIDATE_MEDIA_TYPE,
            bytes: [...Buffer.from(legacyContent, 'utf8')],
            sha256,
        };
        node.candidateHash = sha256;
    }
    const repository = createRepository(operation);
    let executorCalls = 0;
    const forbidden = async () => {
        executorCalls += 1;
        throw new Error('executor must not run');
    };
    const worker = createWorker({
        repository,
        executor: {
            prepare: forbidden,
            commit: forbidden,
            verify: forbidden,
            cleanupPrepared: forbidden,
            rollback: forbidden,
        },
        deploymentRepository: { markDeployed: forbidden },
    });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'failed');
    assert.equal(executorCalls, 0);
    assert.deepEqual(repository.calls.map(call => call.method), ['claim', 'finishClaimed']);
});

test('executes forward topology Bridge to Relay to Portal through prepare commit and verify', async () => {
    assert.deepEqual(
        await successfulLifecycleEvents(['bridge', 'relay', 'portal']),
        [
            { method: 'prepare', role: 'bridge' },
            { method: 'prepare', role: 'relay' },
            { method: 'prepare', role: 'portal' },
            { method: 'commit', role: 'bridge' },
            { method: 'verify', role: 'bridge' },
            { method: 'commit', role: 'relay' },
            { method: 'verify', role: 'relay' },
            { method: 'commit', role: 'portal' },
            { method: 'verify', role: 'portal' },
        ],
    );
});

test('executes reverse topology Portal to Relay to Bridge through prepare commit and verify', async () => {
    assert.deepEqual(
        await successfulLifecycleEvents(['portal', 'relay', 'bridge']),
        [
            { method: 'prepare', role: 'portal' },
            { method: 'prepare', role: 'relay' },
            { method: 'prepare', role: 'bridge' },
            { method: 'commit', role: 'portal' },
            { method: 'verify', role: 'portal' },
            { method: 'commit', role: 'relay' },
            { method: 'verify', role: 'relay' },
            { method: 'commit', role: 'bridge' },
            { method: 'verify', role: 'bridge' },
        ],
    );
});

test('rolls back forward and reverse topology changes in exact reverse deployment order', async () => {
    assert.deepEqual(
        await rollbackRolesAfterFinalVerifyFailure(['bridge', 'relay', 'portal']),
        ['portal', 'relay', 'bridge'],
    );
    assert.deepEqual(
        await rollbackRolesAfterFinalVerifyFailure(['portal', 'relay', 'bridge']),
        ['bridge', 'relay', 'portal'],
    );
});

test('delegates terminal success to the atomic finalizer with only operation lease and revisions', async () => {
    const repository = createRepository();
    const finalizerCalls = [];
    const executor = {
        async prepare(request) {
            return {
                backupId: `backup-${request.node.node}`,
                prepared: { opaque: request.node.node },
            };
        },
        async commit() { return { ok: true }; },
        async verify() { return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; },
        async rollback() { return { ok: true }; },
    };
    const worker = createWorker({
        repository,
        executor,
        finalizer: {
            async finalizeSucceeded(request) {
                finalizerCalls.push(request);
                return {
                    operationId: request.operationId,
                    topologyRevision: request.topologyRevision,
                    deployedRevision: request.topologyRevision,
                    finishedAt: new Date(NOW),
                };
            },
        },
    });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'succeeded');
    assert.deepEqual(finalizerCalls, [{
        operationId: 'operation-1',
        owner: 'worker-1',
        leaseUntil: repository.operation.leaseUntil,
        topologyRevision: 7,
        priorDeployedRevision: 5,
    }]);
    assert.deepEqual(
        repository.calls.filter(call => (
            call.method === 'finishClaimed' && call.request.status === 'succeeded'
        )),
        [],
    );
});

test('atomic finalizer failure rolls back committed nodes and cannot report success', async () => {
    const repository = createRepository();
    const rollbackNodes = [];
    const executor = {
        async prepare(request) {
            return {
                backupId: `backup-${request.node.node}`,
                prepared: { opaque: request.node.node },
            };
        },
        async commit() { return { ok: true }; },
        async verify() { return { ok: true }; },
        async cleanupPrepared() {
            throw new Error('no prepared-only nodes expected');
        },
        async rollback(request) {
            rollbackNodes.push(request.node.node);
            return { ok: true };
        },
    };
    const worker = createWorker({
        repository,
        executor,
        finalizer: {
            async finalizeSucceeded() {
                throw new Error('atomic finalization failed');
            },
        },
    });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'rolled_back');
    assert.deepEqual(rollbackNodes, ['node-b', 'node-a']);
    assert.equal(repository.operation.status, 'rolled_back');
    assert.equal(
        repository.calls.some(call => (
            call.method === 'finishClaimed' && call.request.status === 'succeeded'
        )),
        false,
    );
});

test('prepares every node before deterministic commit and verify then returns atomic success', async () => {
    const repository = createRepository();
    const events = [];
    const executor = {
        async prepare(request) {
            events.push({ method: 'prepare', node: request.node.node });
            return {
                backupId: `backup-${request.node.node}`,
                prepared: { opaque: request.node.node },
            };
        },
        async commit(request) {
            events.push({ method: 'commit', node: request.node.node });
            return { ok: true };
        },
        async verify(request) {
            events.push({ method: 'verify', node: request.node.node });
            return { ok: true };
        },
        async cleanupPrepared(request) {
            events.push({ method: 'cleanupPrepared', node: request.node.node });
        },
        async rollback(request) {
            events.push({ method: 'rollback', node: request.node.node });
            return { ok: true };
        },
    };
    const worker = createWorker({ repository, executor });

    const first = await worker.run('operation-1');
    const second = await worker.run('operation-1');

    assert.deepEqual(first, {
        claimed: true,
        operationId: 'operation-1',
        status: 'succeeded',
    });
    assert.deepEqual(second, { claimed: false, operationId: 'operation-1' });
    assert.deepEqual(events, [
        { method: 'prepare', node: 'node-a' },
        { method: 'prepare', node: 'node-b' },
        { method: 'commit', node: 'node-a' },
        { method: 'verify', node: 'node-a' },
        { method: 'commit', node: 'node-b' },
        { method: 'verify', node: 'node-b' },
    ]);
    assert.equal(
        repository.calls.some(call => (
            call.method === 'finishClaimed' && call.request.status === 'succeeded'
        )),
        false,
    );
    const persistedCalls = repository.calls.filter(call => call.method === 'recordNode');
    assert.doesNotMatch(JSON.stringify(persistedCalls), /candidate-[ab]-secret/);
});

test('prepare failure cleans only prepared nodes and performs no commits', async () => {
    const repository = createRepository();
    const events = [];
    const executor = {
        async prepare(request) {
            events.push({ method: 'prepare', node: request.node.node });
            if (request.node.node === 'node-b') throw new Error('prepare failed');
            return {
                backupId: `backup-${request.node.node}`,
                prepared: { opaque: request.node.node },
            };
        },
        async commit(request) {
            events.push({ method: 'commit', node: request.node.node });
            return { ok: true };
        },
        async verify() {
            return { ok: true };
        },
        async cleanupPrepared(request) {
            events.push({ method: 'cleanupPrepared', node: request.node.node });
            return { ok: true };
        },
        async rollback(request) {
            events.push({ method: 'rollback', node: request.node.node });
            return { ok: true };
        },
    };
    const worker = createWorker({
        repository,
        executor,
        deploymentRepository: { async markDeployed() { throw new Error('must not finalize'); } },
    });

    const result = await worker.run('operation-1');

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-1',
        status: 'rolled_back',
    });
    assert.deepEqual(events, [
        { method: 'prepare', node: 'node-a' },
        { method: 'prepare', node: 'node-b' },
        { method: 'cleanupPrepared', node: 'node-a' },
    ]);
    assert.equal(repository.operation.status, 'rolled_back');
});

test('commit failure rolls back the current and prior committed nodes in reverse only', async () => {
    const repository = createRepository(durableThreeNodeOperation());
    const events = [];
    const executor = {
        async prepare(request) {
            events.push({ method: 'prepare', node: request.node.node });
            return {
                backupId: `backup-${request.node.node}`,
                prepared: { opaque: request.node.node },
            };
        },
        async commit(request) {
            events.push({ method: 'commit', node: request.node.node });
            if (request.node.node === 'node-b') throw new Error('commit failed');
            return { ok: true };
        },
        async verify(request) {
            events.push({ method: 'verify', node: request.node.node });
            return { ok: true };
        },
        async cleanupPrepared(request) {
            events.push({ method: 'cleanupPrepared', node: request.node.node });
            return { ok: true };
        },
        async rollback(request) {
            events.push({ method: 'rollback', node: request.node.node });
            return { ok: true };
        },
    };
    const worker = createWorker({
        repository,
        executor,
        deploymentRepository: { async markDeployed() { throw new Error('must not finalize'); } },
    });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'rolled_back');
    assert.deepEqual(events.filter(event => event.method === 'rollback'), [
        { method: 'rollback', node: 'node-b' },
        { method: 'rollback', node: 'node-a' },
    ]);
    assert.deepEqual(events.filter(event => event.method === 'cleanupPrepared'), [
        { method: 'cleanupPrepared', node: 'node-c' },
    ]);
    assert.deepEqual(events.filter(event => event.method === 'commit'), [
        { method: 'commit', node: 'node-a' },
        { method: 'commit', node: 'node-b' },
    ]);
});

test('atomic finalizer failure rolls back every changed node and cannot succeed', async () => {
    const repository = createRepository();
    const events = [];
    const executor = {
        async prepare(request) {
            return {
                backupId: `backup-${request.node.node}`,
                prepared: { opaque: request.node.node },
            };
        },
        async commit() {
            return { ok: true };
        },
        async verify() {
            return { ok: true };
        },
        async cleanupPrepared() {
            throw new Error('no prepared-only nodes expected');
        },
        async rollback(request) {
            events.push({ method: 'rollback', node: request.node.node });
            return { ok: true };
        },
    };
    const worker = createWorker({
        repository,
        executor,
        finalizer: {
            async finalizeSucceeded() {
                throw new Error('CAS failed');
            },
        },
    });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'rolled_back');
    assert.deepEqual(events, [
        { method: 'rollback', node: 'node-b' },
        { method: 'rollback', node: 'node-a' },
    ]);
    assert.equal(repository.operation.status, 'rolled_back');
    assert.equal(
        repository.calls.some(call => (
            call.method === 'finishClaimed' && call.request.status === 'succeeded'
        )),
        false,
    );
});

test('verify failure continues reverse rollback and fails terminally when one rollback fails', async () => {
    const repository = createRepository(durableThreeNodeOperation());
    const events = [];
    const executor = {
        async prepare(request) {
            return {
                backupId: `backup-${request.node.node}`,
                prepared: { opaque: request.node.node },
            };
        },
        async commit(request) {
            events.push({ method: 'commit', node: request.node.node });
            return { ok: true };
        },
        async verify(request) {
            events.push({ method: 'verify', node: request.node.node });
            if (request.node.node === 'node-b') return { ok: false };
            return { ok: true };
        },
        async cleanupPrepared(request) {
            events.push({ method: 'cleanupPrepared', node: request.node.node });
            return { ok: true };
        },
        async rollback(request) {
            events.push({ method: 'rollback', node: request.node.node });
            if (request.node.node === 'node-b') throw new Error('rollback failed');
            return { ok: true };
        },
    };
    const worker = createWorker({
        repository,
        executor,
        deploymentRepository: { async markDeployed() { throw new Error('must not finalize'); } },
    });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'failed');
    assert.deepEqual(events.filter(event => event.method === 'rollback'), [
        { method: 'rollback', node: 'node-b' },
        { method: 'rollback', node: 'node-a' },
    ]);
    assert.deepEqual(events.filter(event => event.method === 'cleanupPrepared'), [
        { method: 'cleanupPrepared', node: 'node-c' },
    ]);
    assert.equal(repository.operation.nodes[1].state, 'failed');
    assert.equal(repository.operation.nodes[0].state, 'rolled_back');
    assert.equal(repository.operation.status, 'failed');
});

test('terminal metadata failure is fenced by the current owner and fresh lease', async () => {
    const operation = durableOperation();
    operation.nodes[0].candidateHash = 'sha256:stale';
    const repository = createRepository(operation, {
        async finishClaimed(request) {
            repository.calls.push({ method: 'finishClaimed', request });
            return false;
        },
    });
    const forbidden = async () => {
        throw new Error('executor must not run');
    };
    const worker = createWorker({
        repository,
        executor: {
            prepare: forbidden,
            commit: forbidden,
            verify: forbidden,
            cleanupPrepared: forbidden,
            rollback: forbidden,
        },
        deploymentRepository: { markDeployed: forbidden },
    });

    const result = await worker.run('operation-1');

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-1',
        status: 'running',
        stopped: true,
        errorCode: 'TOPOLOGY_OPERATION_LEASE_LOST',
    });
    assert.equal(operation.status, 'preparing');
});

test('expired partial preparation is rehydrated, cleaned, and retried from fresh prepare state', async () => {
    const operation = durableOperation();
    operation.status = 'preparing';
    operation.leaseOwner = 'stopped-process';
    operation.leaseUntil = new Date(NOW.getTime() - 1);
    const preparedNode = operation.nodes.find(node => node.node === 'node-a');
    preparedNode.state = 'prepared';
    preparedNode.backupId = 'topology-backup-node-a';
    const repository = createRepository(operation);
    const events = [];
    const executor = {
        async rehydrate(request) {
            events.push({ method: 'rehydrate', node: request.node.node, backupId: request.backupId });
            return {
                ok: true,
                backupId: request.backupId,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async cleanupPrepared(request) {
            events.push({ method: 'cleanupPrepared', node: request.node.node });
            return { ok: true };
        },
        async prepare(request) {
            events.push({ method: 'prepare', node: request.node.node });
            return {
                backupId: `topology-backup-${request.node.node}-fresh`,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async commit(request) {
            events.push({ method: 'commit', node: request.node.node });
            return { ok: true };
        },
        async verify(request) {
            events.push({ method: 'verify', node: request.node.node });
            return { ok: true };
        },
        async rollback() { return { ok: true }; },
    };
    const worker = createWorker({ repository, executor });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'succeeded');
    assert.deepEqual(events, [
        { method: 'rehydrate', node: 'node-a', backupId: 'topology-backup-node-a' },
        { method: 'cleanupPrepared', node: 'node-a' },
        { method: 'prepare', node: 'node-a' },
        { method: 'prepare', node: 'node-b' },
        { method: 'commit', node: 'node-a' },
        { method: 'verify', node: 'node-a' },
        { method: 'commit', node: 'node-b' },
        { method: 'verify', node: 'node-b' },
    ]);
    assert.equal(preparedNode.state, 'committed');
    assert.equal(preparedNode.backupId, 'topology-backup-node-a-fresh');
});

test('expired committing operation rolls back only durable committed and prepared bindings', async () => {
    const operation = durableOperation();
    operation.status = 'committing';
    operation.leaseOwner = 'stopped-process';
    operation.leaseUntil = new Date(NOW.getTime() - 1);
    operation.nodes.find(node => node.node === 'node-a').state = 'committed';
    operation.nodes.find(node => node.node === 'node-a').backupId = 'topology-backup-node-a';
    operation.nodes.find(node => node.node === 'node-b').state = 'prepared';
    operation.nodes.find(node => node.node === 'node-b').backupId = 'topology-backup-node-b';
    const repository = createRepository(operation, {
        async claim(request) {
            repository.calls.push({ method: 'claim', request });
            operation.leaseOwner = request.owner;
            operation.leaseUntil = new Date(request.now.getTime() + request.leaseMs);
            operation.attempts += 1;
            return operation;
        },
    });
    const events = [];
    const executor = {
        async rehydrate(request) {
            events.push({ method: 'rehydrate', node: request.node.node, backupId: request.backupId });
            return {
                ok: true,
                backupId: request.backupId,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async cleanupPrepared(request) {
            events.push({ method: 'cleanupPrepared', node: request.node.node });
            return { ok: true };
        },
        async rollback(request) {
            events.push({ method: 'rollback', node: request.node.node });
            return { ok: true };
        },
        async prepare() { throw new Error('must not prepare during rollback recovery'); },
        async commit() { throw new Error('must not commit during rollback recovery'); },
        async verify() { throw new Error('must not verify during rollback recovery'); },
    };
    const worker = createWorker({
        repository,
        executor,
        finalizer: { async finalizeSucceeded() { throw new Error('must not finalize'); } },
    });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'rolled_back');
    assert.deepEqual(events, [
        { method: 'rehydrate', node: 'node-b', backupId: 'topology-backup-node-b' },
        { method: 'cleanupPrepared', node: 'node-b' },
        { method: 'rehydrate', node: 'node-a', backupId: 'topology-backup-node-a' },
        { method: 'rollback', node: 'node-a' },
    ]);
    assert.equal(operation.status, 'rolled_back');
    assert.deepEqual(operation.nodes.map(node => node.state), ['rolled_back', 'rolled_back']);
});

test('expired rollback resumes after a crash point and preserves failed rollback status', async () => {
    const operation = durableOperation();
    operation.status = 'rolling_back';
    operation.leaseOwner = 'stopped-process';
    operation.leaseUntil = new Date(NOW.getTime() - 1);
    operation.nodes.find(node => node.node === 'node-a').state = 'committed';
    operation.nodes.find(node => node.node === 'node-a').backupId = 'topology-backup-node-a';
    operation.nodes.find(node => node.node === 'node-b').state = 'rolled_back';
    operation.nodes.find(node => node.node === 'node-b').backupId = 'topology-backup-node-b';
    const repository = createRepository(operation, {
        async claim(request) {
            repository.calls.push({ method: 'claim', request });
            operation.leaseOwner = request.owner;
            operation.leaseUntil = new Date(request.now.getTime() + request.leaseMs);
            operation.attempts += 1;
            return operation;
        },
    });
    const events = [];
    const executor = {
        async rehydrate(request) {
            events.push({ method: 'rehydrate', node: request.node.node });
            return {
                ok: true,
                backupId: request.backupId,
                prepared: Object.freeze({ node: request.node.node }),
            };
        },
        async rollback(request) {
            events.push({ method: 'rollback', node: request.node.node });
            throw new Error('rollback still unavailable');
        },
        async cleanupPrepared() { throw new Error('must not clean rolled-back nodes'); },
        async prepare() { throw new Error('must not prepare during rollback recovery'); },
        async commit() { throw new Error('must not commit during rollback recovery'); },
        async verify() { throw new Error('must not verify during rollback recovery'); },
    };
    const worker = createWorker({ repository, executor });

    const result = await worker.run('operation-1');

    assert.equal(result.status, 'failed');
    assert.deepEqual(events, [
        { method: 'rehydrate', node: 'node-a' },
        { method: 'rollback', node: 'node-a' },
    ]);
    assert.equal(operation.status, 'failed');
    assert.equal(operation.nodes.find(node => node.node === 'node-a').state, 'failed');
    assert.equal(operation.nodes.find(node => node.node === 'node-b').state, 'rolled_back');
});
