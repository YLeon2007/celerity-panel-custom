'use strict';
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');

const assert = require('node:assert/strict');
const test = require('node:test');
const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');

function fixture(kind = 'install', count = 1) {
    const session = { id: 'session' };
    const db = { startSession() {} };
    let gate = count;
    let phase = 'running';
    let heldLock = false;
    const operation = { executionContext: TEST, _id: 'operation-1', node: 'relay-1', kind, status: 'succeeded',
        admissionId: 'admission-1', leaseOwner: 'worker-1', ownerGeneration: 2 };
    const admission = { _id: 'admission-1', nodeId: 'relay-1', kind, phase,
        operationId: 'operation-1', leaseOwner: 'worker-1', ownerGeneration: 2 };
    const L2tpOperation = {
        db,
        findOne(filter) {
            return { session(value) {
                assert.strictEqual(value, session);
                return { async lean() {
                    return Object.entries(filter).every(([key, expected]) => operation[key] === expected)
                        ? { ...operation } : null;
                } };
            } };
        },
    };
    const RemoteAdmission = {
        db,
        async create() {},
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            if (!Object.entries(filter).every(([key, expected]) => expected?.$in
                ? expected.$in.includes(admission[key]) : admission[key] === expected)) {
                return { matchedCount: 0 };
            }
            phase = update.$set.phase;
            admission.phase = phase;
            return { matchedCount: 1 };
        },
    };
    const CascadeTopologyState = {
        db,
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            if (filter._id !== 'singleton' || !(gate > 0)) return { matchedCount: 0 };
            gate += update.$inc.remoteAdmissionCount;
            return { matchedCount: 1 };
        },
    };
    const NodeOperationLock = {
        db,
        findOne(filter) {
            assert.equal(filter.node, operation.node);
            assert.equal(filter.operationId, operation._id);
            return { session(value) {
                assert.strictEqual(value, session);
                return { async lean() { return heldLock ? { generation: 'lock-uuid' } : null; } };
            } };
        },
    };
    const repository = new RemoteAdmissionRepository({ L2tpOperation, RemoteAdmission,
        NodeOperationLock, CascadeTopologyState, transactionRunner: async work => {
            const before = { gate, phase };
            try { return await work(session); }
            catch (error) { gate = before.gate; phase = before.phase; admission.phase = phase; throw error; }
        } });
    const request = { admissionId: admission._id, operationId: operation._id,
        nodeId: admission.nodeId, owner: admission.leaseOwner,
        ownerGeneration: admission.ownerGeneration, kind };
    return { repository, request, operation,
        setHeldLock: value => { heldLock = value; },
        setPhase: value => { phase = value; admission.phase = value; },
        getState: () => ({ gate, phase }) };
}

for (const kind of ['install', 'sync_users']) {
    test(`${kind} verified success releases one counted admission exactly once`, async () => {
        const f = fixture(kind);
        await f.repository.completeVerifiedOperation(f.request);
        assert.deepEqual(f.getState(), { gate: 0, phase: 'completed' });
        await assert.rejects(f.repository.completeVerifiedOperation(f.request));
        assert.deepEqual(f.getState(), { gate: 0, phase: 'completed' });
    });
}

test('verified success cannot release while node lock remains and can recover after exact unlock', async () => {
    const f = fixture();
    f.setHeldLock(true);
    await assert.rejects(f.repository.completeVerifiedOperation(f.request),
        { code: 'REMOTE_ADMISSION_LOCK_HELD' });
    assert.deepEqual(f.getState(), { gate: 1, phase: 'running' });
    f.setHeldLock(false);
    f.setPhase('recovery_required');
    assert.equal(await f.repository.completeVerifiedOperation(f.request), true);
    assert.deepEqual(f.getState(), { gate: 0, phase: 'completed' });
});

test('wrong owner, generation, or non-success operation cannot release', async () => {
    for (const change of [{ owner: 'old-worker' }, { ownerGeneration: 1 }, { kind: 'sync_users' }]) {
        const f = fixture();
        await assert.rejects(f.repository.completeVerifiedOperation({ ...f.request, ...change }));
        assert.deepEqual(f.getState(), { gate: 1, phase: 'running' });
    }
    const f = fixture();
    f.operation.status = 'rolling_back';
    await assert.rejects(f.repository.completeVerifiedOperation(f.request));
    assert.deepEqual(f.getState(), { gate: 1, phase: 'running' });
});

test('missing gate rolls admission transition back in the same transaction', async () => {
    const f = fixture('install', 0);
    await assert.rejects(f.repository.completeVerifiedOperation(f.request));
    assert.deepEqual(f.getState(), { gate: 0, phase: 'running' });
});
