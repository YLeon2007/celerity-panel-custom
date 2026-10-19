'use strict';

// Real orchestration and typed SSH transport, with local in-memory persistence
// and a simulated remote writer. No DB connection, SSH connection, or process.
const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { TopologyOperationExecutor } = require('../services/topologyOperationExecutor');
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const { TopologyOperationFinalizer } = require('../services/topologyOperationFinalizer');
const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');
const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
const { QUEUE_ID } = require('../services/topologyIntentService');
const { bindingRecord, bindingReader, runnerRequest, v2Receipt } = require('./helpers/topologyV2Fixture');

const NOW = new Date('2026-10-19T12:00:00Z');
function query(value) {
    return { select() { return this; }, session() { return this; },
        lean: async () => structuredClone(value) };
}
function matches(row, filter) {
    return row && Object.entries(filter).every(([key, value]) =>
        value && typeof value === 'object' && Object.hasOwn(value, '$gt')
            ? row[key] > value.$gt : row[key] === value);
}
function update(row, filter, change) {
    if (!matches(row, filter)) return { matchedCount: 0 };
    Object.assign(row, change.$set);
    for (const [key, value] of Object.entries(change.$inc || {})) row[key] += value;
    for (const key of Object.keys(change.$unset || {})) delete row[key];
    return { matchedCount: 1 };
}
function node(nodeId, role, nodeRef) {
    const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
    const sha256 = createHash('sha256').update(content).digest('hex');
    const serviceUnit = role === 'portal' ? 'xray.service' : 'xray-bridge.service';
    return { node: nodeId, role, nodeRef, targetProfile: role === 'portal' ? 'xray-main' : 'xray-bridge',
        checks: [{ type: 'service', serviceUnit, expectedState: 'active' }],
        candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
            bytes: [...Buffer.from(content)], sha256 },
        candidateHash: sha256, state: 'pending', backupId: '' };
}
function fixture({ outcome = 'timeout', failingNode = 'node-b', safeLocalFailure = false, persistBinding = true } = {}) {
    let now = new Date(NOW);
    let remoteCommitAlive = false;
    const commands = [], released = [], finalizations = [];
    const held = new Map();
    const executionBindingReader = bindingReader([]);
    const executionContext = { target: 'test', hostIdentity: 'test.infograd.online' };
    const idempotencyKey = 'topology:test:revision-7:host-test.infograd.online:00000000-0000-0000-0000-000000000000';
    const operation = { executionContext, idempotencyKey, _id: 'operation-uncertain', topologyRevision: 7, priorDeployedRevision: 5,
        status: 'queued', attempts: 0, leaseOwner: '', leaseUntil: null,
        heldTopologyAdmission: true, admissionFingerprint: 'a'.repeat(64),
        nodes: [node('node-a', 'portal', 'portal'), node('node-b', 'relay', 'relay-1'),
            node('node-c', 'bridge', 'bridge')] };
    const topology = { _id: 'singleton', deployedRevision: 5, topologyAdmissionCount: 1,
        stateTransitionRevision: 0 };
    const intent = { executionContext, operationIdempotencyKey: idempotencyKey, _id: 'intent-head', operationId: operation._id, status: 'admitted', generation: 1,
        topologyRevision: 7, priorDeployedRevision: 5, admissionFingerprint: operation.admissionFingerprint };
    const queue = { _id: QUEUE_ID, outstanding: 2 };
    const db = {};
    const TopologyOperation = { db,
        findById: () => query(operation),
        async updateOne(filter, change) { finalizations.push(filter); return update(operation, filter, change); },
    };
    const CascadeTopologyState = { db,
        async updateOne(filter, change) { return update(topology, filter, change); },
        findOneAndUpdate(filter, change) {
            const result = update(topology, filter, change);
            return query(result.matchedCount ? topology : null);
        },
    };
    const TopologyCreateIntent = { db, findById: () => query(intent),
        async updateOne(filter, change) { return update(intent, filter, change); } };
    const TopologyIntentQueueState = { db,
        async updateOne(filter, change) { return update(queue, filter, change); } };
    const operationRepository = {
        async claim({ owner, leaseMs }) {
            if (operation.status !== 'queued'
                && !(operation.leaseUntil <= now && ['committing', 'rolling_back'].includes(operation.status))) return null;
            if (operation.status === 'queued') operation.status = 'preparing';
            Object.assign(operation, { leaseOwner: owner, leaseUntil: new Date(+now + leaseMs) });
            operation.attempts++;
            return structuredClone(operation);
        },
        async renewLease() { return true; },
        async recordNode({ node: id, state, backupId }) {
            const row = operation.nodes.find(item => item.node === id);
            row.state = state;
            if (backupId !== undefined) row.backupId = backupId;
            return true;
        },
        async setPhase({ from, to }) {
            if (operation.status !== from) return false;
            operation.status = to; return true;
        },
        async finishClaimed({ status }) { operation.status = status; return true; },
    };
    const lockService = new NodeOperationLockService({ clock: { now: () => now },
        repository: new NodeOperationLockRepository({ model: {
            async create(row) {
                if (held.has(row.node)) throw Object.assign(new Error('duplicate'), { code: 11000 });
                held.set(row.node, structuredClone(row));
                // Simulate a separately persisted immutable binding at exact lock
                // acquisition, not a predecessor synthesized during dispatch.
                if (persistBinding) executionBindingReader.rows.set(row.node, bindingRecord({
                    operationId: operation._id, topologyRevision: operation.topologyRevision,
                    priorDeployedRevision: operation.priorDeployedRevision,
                    node: operation.nodes.find(node => node.node === row.node),
                    executionFence: { owner: row.owner, attempt: operation.attempts, generation: row.generation },
                }));
                return row;
            },
            findOne: ({ node }) => query(held.get(node) || null),
            async updateOne(filter, change) { return update(held.get(filter.node), filter, change); },
            async deleteOne(filter) {
                if (!matches(held.get(filter.node), filter)) return { deletedCount: 0 };
                released.push(structuredClone(held.get(filter.node)));
                held.delete(filter.node); return { deletedCount: 1 };
            },
        } }),
    });
    const executor = new TopologyOperationExecutor({ hostIdentity: 'test.infograd.online', target: 'test',
        executionBindingReader,
        RunnerBootstrapper: class { async ensureRunner() {} },
        nodeExecutionResolver: { async resolve() { return {
            async writeFile() {},
            async exec(command) {
                const request = runnerRequest(command);
                commands.push(request);
                if (request.command === 'commit' && request.nodeId === failingNode) {
                    remoteCommitAlive = true;
                    if (outcome === 'timeout') throw new Error('local timeout; remote writer not joined');
                    if (outcome === 'nonzero') return { code: 1, stdout: '', stderr: 'disconnected' };
                    return { code: 0, stdout: `${JSON.stringify({ ok: true, ...request, backupId: 'wrong-backup' })}\n`, stderr: '' };
                }
                return { code: 0, stdout: `${JSON.stringify(v2Receipt(request))}\n`, stderr: '' };
            },
        }; } },
    });
    const effectiveExecutor = safeLocalFailure ? {
        executionProtocolVersion: 2,
        prepare: context => executor.prepare(context),
        commit: context => executor.commit(context.node.node === failingNode
            ? { ...context, backupId: 'wrong-local-binding' } : context),
        verify: context => executor.verify(context),
        rollback: context => executor.rollback(context),
        cleanupPrepared: context => executor.cleanupPrepared(context),
        rehydrate: context => executor.rehydrate(context),
    } : executor;
    const finalizer = new TopologyOperationFinalizer({ clock: { now: () => now },
        repository: new TopologyOperationFinalizationRepository({ TopologyOperation, CascadeTopologyState,
            transactionRunner: work => work({}) }) });
    const worker = new TopologyOperationWorker({ executionContext, operationRepository, executor: effectiveExecutor,
        finalizer, lockService, workerId: 'worker-uncertain', leaseMs: 30000,
        clock: { now: () => now }, allowUnprovenTestExecution: true });
    const consumer = new TopologyIntentConsumer({ executionContext, TopologyOperation, CascadeTopologyState,
        TopologyCreateIntent, TopologyIntentQueueState,
        ...Object.fromEntries(['HyNode', 'CascadeLink', 'CascadeRouteGroup', 'RelayL2tpState']
            .map(key => [key, { db }])), transactionRunner: work => work({}) });
    return { worker, operation, operationRepository, topology, intent, queue, held, released,
        finalizations, commands, consumer, lockService,
        get remoteCommitAlive() { return remoteCommitAlive; },
        expire() { now = new Date(+NOW + 60000); } };
}

test('real typed uncertain commit cannot roll back, release fences, or settle its queue head', async t => {
    for (const outcome of ['timeout', 'nonzero', 'malformed']) {
        for (const failingNode of ['node-a', 'node-b']) await t.test(`${outcome}:${failingNode}`, async () => {
            const f = fixture({ outcome, failingNode });
            const result = await f.worker.run(f.operation._id);
            assert.equal(f.remoteCommitAlive, true);
            assert.equal(result.status, 'failed');
            assert.equal(result.errorCode, 'REMOTE_COMMAND_OUTCOME_UNCERTAIN');
            assert.equal(result.stopped, true);
            assert.equal(f.operation.nodes.find(row => row.node === failingNode).state, 'failed');
            assert.match(f.operation.nodes.find(row => row.node === failingNode).backupId, /^topology-[a-f0-9]{64}$/);
            assert.equal(f.operation.heldTopologyAdmission, true);
            assert.equal(f.topology.topologyAdmissionCount, 1);
            assert.equal(f.held.size, 3);
            const exactLocks = structuredClone([...f.held.values()]);
            assert.deepEqual(f.released, []);
            assert.deepEqual(f.finalizations, []);
            assert.equal(f.commands.some(row => row.command === 'rollback'), false);
            assert.equal(f.commands.filter(row => row.command === 'commit').at(-1).nodeId, failingNode);
            assert.equal(await f.consumer.settle(f.intent), false);
            assert.equal(f.intent.status, 'blocked');
            assert.equal(f.queue.outstanding, 2, 'successor cannot drain behind uncertain head');
            f.expire();
            const contender = await f.lockService.acquire({ node: failingNode, owner: 'installer',
                operationId: 'install-successor', leaseMs: 30000 });
            assert.equal(contender.ok, false, 'install cannot reclaim an expired uncertain generation');
            assert.deepEqual([...f.held.values()], exactLocks);
            assert.equal((await f.worker.run(f.operation._id)).claimed, false);
        });
    }
});

test('commit uncertainty survives loss of its durable failure acknowledgement', async t => {
    for (const boundary of ['recordNode', 'finishClaimed']) await t.test(boundary, async () => {
        const f = fixture();
        const original = f.operationRepository[boundary];
        f.operationRepository[boundary] = async request => {
            if (boundary === 'finishClaimed' || request.state === 'failed') return false;
            return original(request);
        };
        const result = await f.worker.run(f.operation._id);
        assert.equal(result.errorCode, 'TOPOLOGY_OPERATION_LEASE_LOST');
        assert.equal(f.remoteCommitAlive, true);
        assert.equal(f.operation.status, 'committing');
        assert.equal(f.operation.heldTopologyAdmission, true);
        const locks = structuredClone([...f.held.values()]);
        assert.equal(locks.length, 3);
        f.operationRepository[boundary] = original;
        f.expire();
        const recovered = await f.worker.run(f.operation._id);
        assert.equal(recovered.errorCode, 'REMOTE_COMMAND_OUTCOME_UNCERTAIN');
        assert.deepEqual([...f.held.values()], locks);
        assert.deepEqual(f.released, []);
        assert.deepEqual(f.finalizations, []);
        assert.equal(f.commands.some(row => row.command === 'rollback'), false);
        assert.equal(f.topology.topologyAdmissionCount, 1);
        assert.equal(await f.consumer.settle(f.intent), false);
        assert.equal(f.queue.outstanding, 2);
    });
});

test('expired commit recovery has no quiescence proof even when node locks are absent', async t => {
    for (const status of ['committing', 'rolling_back']) {
        for (const state of ['prepared', 'committed']) await t.test(`${status}:${state}`, async () => {
            const f = fixture();
            f.operation.status = status;
            f.operation.leaseUntil = new Date(+NOW - 1);
            f.operation.nodes.forEach(row => {
                row.state = state; row.backupId = 'durable-' + row.node;
            });
            const before = structuredClone(f.operation.nodes);
            const result = await f.worker.run(f.operation._id);
            assert.equal(result.errorCode, 'REMOTE_COMMAND_OUTCOME_UNCERTAIN');
            assert.equal(result.status, status);
            assert.equal(result.stopped, true);
            assert.deepEqual(f.commands, []);
            assert.deepEqual(f.operation.nodes, before);
            assert.equal(f.operation.heldTopologyAdmission, true);
            assert.equal(f.topology.topologyAdmissionCount, 1);
            assert.equal(f.held.size, 0, 'recovery must stop before acquiring new generations');
            assert.equal(await f.consumer.settle(f.intent), false);
            assert.equal(f.queue.outstanding, 2);
        });
    }
});

test('real local commit binding rejection cleans completed predecessors but V2 retains admission', async () => {
    const f = fixture({ safeLocalFailure: true });
    const result = await f.worker.run(f.operation._id);
    assert.equal(result.status, 'failed');
    assert.equal(result.drainUncertain, true);
    assert.equal(f.remoteCommitAlive, false);
    assert.deepEqual(f.commands.filter(row => row.command === 'commit').map(row => row.nodeId), ['node-a']);
    assert.deepEqual(f.commands.filter(row => row.command === 'rollback').map(row => row.nodeId),
        ['node-b', 'node-a', 'node-c']);
    assert.equal(f.operation.heldTopologyAdmission, true);
    assert.equal(f.topology.topologyAdmissionCount, 1);
    assert.equal(f.held.size, 3);
    for (const request of f.commands) {
        assert.equal(request.generation, f.held.get(request.nodeId).generation);
        assert.equal(request.executionContext, 'test.infograd.online');
        assert.equal(request.attemptId, 'attempt-1');
        assert.equal(request.commandId, `${request.command}-${request.nodeId}`);
        assert.equal(request.predecessorGeneration, 'none');
    }
    assert.deepEqual(f.released, []);
    assert.equal(await f.consumer.settle(f.intent), false);
    assert.equal(f.queue.outstanding, 2);
});

test('assembled worker without persisted binding retains ownership without dispatch or terminal fiction', async () => {
    const f = fixture({ persistBinding: false });
    const result = await f.worker.run(f.operation._id);
    assert.equal(result.status, 'preparing');
    assert.equal(result.stopped, true);
    assert.equal(result.errorCode, 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN');
    assert.equal(result.drainUncertain, true);
    assert.deepEqual(f.commands, []);
    assert.deepEqual(f.released, []);
    assert.deepEqual(f.finalizations, []);
    assert.equal(f.held.size, 3);
    assert.equal(f.operation.heldTopologyAdmission, true);
    assert.equal(f.topology.topologyAdmissionCount, 1);
    assert.equal(f.operation.status, 'preparing');
    assert.equal(await f.consumer.settle(f.intent), false);
    assert.equal(f.queue.outstanding, 2);
});
