'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');

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

test('prepares every node before deterministic commit and verify then fences deployed revision', async () => {
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

    const result = await worker.run('operation-1');

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
