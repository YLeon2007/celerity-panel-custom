'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');

const NOW = new Date('2026-09-22T10:00:00.000Z');

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    for (const nested of Object.values(value)) deepFreeze(nested);
    return Object.freeze(value);
}

function frozenPlan() {
    return deepFreeze({
        operationId: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: [
            {
                node: 'node-b',
                candidateHash: 'sha256:bbb',
                candidate: { content: 'candidate-b-secret' },
            },
            {
                node: 'node-a',
                candidateHash: 'sha256:aaa',
                candidate: { content: 'candidate-a-secret' },
            },
        ],
    });
}

function durableOperation() {
    return {
        _id: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        status: 'queued',
        nodes: [
            { node: 'node-a', state: 'pending', candidateHash: 'sha256:aaa', backupId: '' },
            { node: 'node-b', state: 'pending', candidateHash: 'sha256:bbb', backupId: '' },
        ],
    };
}

function frozenThreeNodePlan() {
    return deepFreeze({
        operationId: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: [
            { node: 'node-c', candidateHash: 'sha256:ccc', candidate: { content: 'c' } },
            { node: 'node-a', candidateHash: 'sha256:aaa', candidate: { content: 'a' } },
            { node: 'node-b', candidateHash: 'sha256:bbb', candidate: { content: 'b' } },
        ],
    });
}

function durableThreeNodeOperation() {
    return {
        ...durableOperation(),
        nodes: [
            { node: 'node-a', state: 'pending', candidateHash: 'sha256:aaa', backupId: '' },
            { node: 'node-b', state: 'pending', candidateHash: 'sha256:bbb', backupId: '' },
            { node: 'node-c', state: 'pending', candidateHash: 'sha256:ccc', backupId: '' },
        ],
    };
}

function createRepository(operation = durableOperation(), overrides = {}) {
    const calls = [];
    return {
        calls,
        operation,
        async claim(request) {
            calls.push({ method: 'claim', request });
            if (operation.status !== 'queued') return null;
            operation.status = 'preparing';
            operation.leaseOwner = request.owner;
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
        ...overrides,
    };
}

function createWorker({ repository, executor, deploymentRepository, clock } = {}) {
    return new TopologyOperationWorker({
        operationRepository: repository,
        executor,
        deploymentRepository,
        workerId: 'worker-1',
        leaseMs: 30_000,
        clock: clock || { now: () => new Date(NOW) },
    });
}

test('prepares every node before deterministic commit and verify then fences deployed revision', async () => {
    const plan = frozenPlan();
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
    const deploymentRepository = {
        async markDeployed(request) {
            events.push({ method: 'markDeployed', request });
            return { revision: 7, deployedRevision: 7 };
        },
    };
    const worker = createWorker({ repository, executor, deploymentRepository });

    const first = await worker.run(plan);
    const second = await worker.run(plan);

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
        {
            method: 'markDeployed',
            request: { expectedRevision: 7, expectedDeployedRevision: 5 },
        },
    ]);
    const finishIndex = repository.calls.findLastIndex(call => call.method === 'finishClaimed');
    const finalCall = repository.calls[finishIndex];
    assert.equal(finalCall.request.status, 'succeeded');
    assert.equal(
        repository.calls[finishIndex - 1].method,
        'renewLease',
        'lease must be renewed after deployedRevision finalization',
    );
    const persistedCalls = repository.calls.filter(call => call.method === 'recordNode');
    assert.doesNotMatch(JSON.stringify(persistedCalls), /candidate-[ab]-secret/);
});

test('prepare failure cleans only prepared nodes and performs no commits', async () => {
    const plan = frozenPlan();
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

    const result = await worker.run(plan);

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

    const result = await worker.run(frozenThreeNodePlan());

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

test('deployed revision finalizer failure rolls back every changed node and cannot succeed', async () => {
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
        deploymentRepository: {
            async markDeployed() {
                events.push({ method: 'markDeployed' });
                throw new Error('CAS failed');
            },
        },
    });

    const result = await worker.run(frozenPlan());

    assert.equal(result.status, 'rolled_back');
    assert.deepEqual(events, [
        { method: 'markDeployed' },
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

    const result = await worker.run(frozenThreeNodePlan());

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

    const result = await worker.run(frozenPlan());

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-1',
        status: 'running',
        stopped: true,
        errorCode: 'TOPOLOGY_OPERATION_LEASE_LOST',
    });
    assert.equal(operation.status, 'preparing');
});
