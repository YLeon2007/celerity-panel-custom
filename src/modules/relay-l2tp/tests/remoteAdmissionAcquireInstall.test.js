'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');

function matchesAdmission(record, filter) {
    return record && Object.entries(filter).every(([key, expected]) => {
        const value = record[key];
        if (expected && typeof expected === 'object') {
            if ('$exists' in expected) return (value !== undefined) === expected.$exists;
            if ('$in' in expected) return expected.$in.includes(value);
            throw new Error(`Unsupported admission filter: ${key}`);
        }
        return value === expected;
    });
}

function fixture({ gate = {}, ambiguous = false, createFails = false, splitConnection = false,
    sessionUnavailable = false, missingLockModel = false, splitLockConnection = false,
    missingLockQuery = false } = {}) {
    const state = gate === null ? null : { _id: 'singleton', remoteAdmissionCount: 0,
        topologyAdmissionCount: 0, ...gate };
    const records = new Map();
    const locks = new Map();
    const operations = new Map();
    const calls = [];
    const session = { id: 'install-acquisition' };
    const db = { startSession: sessionUnavailable ? undefined : async () => session };
    const CascadeTopologyState = {
        db,
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            calls.push('gate');
            if (!state || filter._id !== 'singleton'
                || filter.remoteDrain?.$exists === false && state.remoteDrain !== undefined
                || filter.replacementReservation?.$exists === false && state.replacementReservation !== undefined
                || filter.remoteAdmissionCount?.$gte !== undefined
                    && !(typeof state.remoteAdmissionCount === 'number'
                        && state.remoteAdmissionCount >= filter.remoteAdmissionCount.$gte)
                || filter.topologyAdmissionCount !== undefined
                    && state.topologyAdmissionCount !== filter.topologyAdmissionCount
                || filter.remoteAdmissionCount?.$gt !== undefined && state.remoteAdmissionCount <= 0) {
                return { matchedCount: 0 };
            }
            state.remoteAdmissionCount += update.$inc.remoteAdmissionCount;
            return { matchedCount: 1 };
        },
    };
    const RemoteAdmission = {
        db: splitConnection ? { startSession: async () => session } : db,
        findOne(filter) {
            const row = [...records.values()].find(record => matchesAdmission(record, filter));
            return { session() { return this; }, async lean() { return row || null; } };
        },
        find(filter) {
            const rows = [...records.values()].filter(record => matchesAdmission(record, filter));
            return { sort() { return this; }, limit(max) { return this._rows = rows.slice(0, max), this; },
                async lean() { return (this._rows ?? rows).map(row => ({ ...row })); } };
        },
        async create(documents, options) {
            assert.strictEqual(options.session, session);
            calls.push('record');
            if (createFails) throw new Error('create unavailable');
            for (const document of documents) {
                if (records.has(document._id)) throw new Error('duplicate admission');
                records.set(document._id, { ...document });
            }
        },
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            const record = records.get(filter._id);
            if (!matchesAdmission(record, filter)) return { matchedCount: 0 };
            Object.assign(record, update.$set);
            return { matchedCount: 1 };
        },
    };
    const L2tpOperation = {
        db,
        findOne(filter) {
            const operation = [...operations.values()].find(candidate =>
                Object.entries(filter).every(([key, expected]) => {
                    const value = candidate[key];
                    if (expected && typeof expected === 'object' && '$in' in expected) {
                        return expected.$in.includes(value);
                    }
                    return value === expected;
                }));
            return {
                session() { return this; },
                async lean() { return operation ? { ...operation } : null; },
            };
        },
    };
    const NodeOperationLock = {
        db,
        findOne({ node, operationId }) {
            const lock = operationId === undefined
                ? [...locks].find(([key]) => key.startsWith(`${node}:`))?.[1]
                : locks.get(`${node}:${operationId}`);
            return { session(value) { assert.strictEqual(value, session); return this; },
                async lean() { return lock ?? null; } };
        },
    };
    if (missingLockQuery) delete NodeOperationLock.findOne;
    if (splitLockConnection) NodeOperationLock.db = {};
    const repository = new RemoteAdmissionRepository({ CascadeTopologyState, RemoteAdmission,
        L2tpOperation, NodeOperationLock: missingLockModel ? undefined : NodeOperationLock,
        transactionRunner: async work => {
            const previousCount = state?.remoteAdmissionCount;
            const previousRecords = new Map([...records].map(([id, record]) => [id, { ...record }]));
            try {
                const result = await work(session);
                if (ambiguous) {
                    const error = new Error('uncertain commit');
                    error.code = 'UNKNOWN_TRANSACTION_COMMIT_RESULT';
                    throw error;
                }
                return result;
            } catch (error) {
                if (error.code !== 'UNKNOWN_TRANSACTION_COMMIT_RESULT') {
                    if (state) state.remoteAdmissionCount = previousCount;
                    records.clear();
                    for (const [id, record] of previousRecords) records.set(id, record);
                }
                throw error;
            }
        } });
    return { repository, state, records, locks, operations, calls };
}

test('acquireInstall blocks a second unresolved same-node install before SSH', async () => {
    const f = fixture();
    const first = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    await assert.rejects(f.repository.acquireInstall({ nodeId: 'relay-1' }),
        { code: 'REMOTE_INSTALL_ALREADY_ACTIVE' });
    assert.deepEqual(f.calls, ['gate', 'record']);
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.deepEqual([...f.records.values()], [{
        _id: first, nodeId: 'relay-1', kind: 'install', phase: 'running', ownerGeneration: 1,
    }]);
});

test('install and standalone preflight share the same-node unresolved fence', async () => {
    const first = fixture();
    await first.repository.acquireInstall({ nodeId: 'relay-1' });
    await assert.rejects(first.repository.acquire({ nodeId: 'relay-1' }),
        { code: 'REMOTE_INSTALL_ALREADY_ACTIVE' });
    assert.equal(first.state.remoteAdmissionCount, 1);

    const second = fixture();
    await second.repository.acquire({ nodeId: 'relay-1' });
    await assert.rejects(second.repository.acquireInstall({ nodeId: 'relay-1' }),
        { code: 'REMOTE_INSTALL_ALREADY_ACTIVE' });
    assert.equal(second.state.remoteAdmissionCount, 1);
});

test('acquireInstall denies absent or legacy gate, drain, and reservation without creating a record', async () => {
    for (const gate of [null, { remoteAdmissionCount: undefined },
        { remoteDrain: { ownerToken: 'drain' } },
        { replacementReservation: { ownerToken: 'reservation' } }]) {
        const f = fixture({ gate });
        await assert.rejects(f.repository.acquireInstall({ nodeId: 'relay-1' }),
            { code: 'REMOTE_ADMISSION_BLOCKED' });
        assert.deepEqual(f.calls, ['gate']);
        assert.equal(f.records.size, 0);
        if (f.state) assert.equal(f.state.remoteAdmissionCount,
            Object.hasOwn(gate, 'remoteAdmissionCount') ? gate.remoteAdmissionCount : 0);
    }
});

test('acquireInstall rejects active or missing topology admission counter before counting', async () => {
    for (const topologyAdmissionCount of [1, undefined, -1]) {
        const f = fixture({ gate: { topologyAdmissionCount } });
        await assert.rejects(f.repository.acquireInstall({ nodeId: 'relay-1' }),
            { code: 'REMOTE_ADMISSION_BLOCKED' });
        assert.equal(f.state.remoteAdmissionCount, 0);
        assert.equal(f.records.size, 0);
        assert.equal(f.state.topologyAdmissionCount, topologyAdmissionCount);
    }
});

test('acquireInstall refuses any existing exact node fence without counting or changing ownership', async () => {
    for (const remoteUncertain of [true, false, undefined]) {
        const f = fixture();
        const lock = { node: 'relay-1', owner: 'topology-worker', operationId: 'topology-op',
            generation: 'foreign-generation', leaseUntil: new Date(0), remoteUncertain };
        f.locks.set('relay-1:topology-op', lock);
        await assert.rejects(f.repository.acquireInstall({ nodeId: 'relay-1' }),
            { code: 'NODE_OPERATION_LOCK_CONFLICT' });
        assert.strictEqual(f.locks.get('relay-1:topology-op'), lock);
        assert.equal(f.state.remoteAdmissionCount, 0);
        assert.equal(f.records.size, 0);
        assert.deepEqual(f.calls, []);
    }
});

test('acquireInstall does not block on a different node fence', async () => {
    const f = fixture();
    f.locks.set('relay-2:topology-op', { node: 'relay-2', generation: 'foreign-generation' });
    await f.repository.acquireInstall({ nodeId: 'relay-1' });
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal(f.locks.size, 1);
});

test('acquireInstall rolls back the count when creating the record fails', async () => {
    const f = fixture({ createFails: true });
    await assert.rejects(f.repository.acquireInstall({ nodeId: 'relay-1' }), error => {
        assert.match(error.message, /create unavailable/);
        assert.ok(error.admissionId);
        return true;
    });
    assert.deepEqual(f.calls, ['gate', 'record']);
    assert.equal(f.state.remoteAdmissionCount, 0);
    assert.equal(f.records.size, 0);
});

test('acquireInstall reports its committed identity on uncertain outcome without retry or release', async () => {
    const f = fixture({ ambiguous: true });
    await assert.rejects(f.repository.acquireInstall({ nodeId: 'relay-1' }), error => {
        assert.equal(error.code, 'UNKNOWN_TRANSACTION_COMMIT_RESULT');
        assert.equal(error.admissionId, [...f.records.keys()][0]);
        return true;
    });
    assert.deepEqual(f.calls, ['gate', 'record']);
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal([...f.records.values()][0].phase, 'running');
});

test('acquireInstall rejects split connections and missing transaction or node-lock capability before mutating', async () => {
    for (const options of [{ splitConnection: true }, { sessionUnavailable: true },
        { missingLockModel: true }, { splitLockConnection: true }, { missingLockQuery: true }]) {
        const f = fixture(options);
        await assert.rejects(f.repository.acquireInstall({ nodeId: 'relay-1' }),
            /models on one transactional Mongo connection/);
        assert.deepEqual(f.calls, []);
        assert.equal(f.state.remoteAdmissionCount, 0);
        assert.equal(f.records.size, 0);
    }
});

test('acquireInstall cannot proceed with a nontransactional session', async () => {
    const db = { startSession: async () => ({ endSession: async () => {} }) };
    let updates = 0;
    const repository = new RemoteAdmissionRepository({
        NodeOperationLock: { db, findOne() { throw new Error('unexpected lock query'); } },
        CascadeTopologyState: { db, updateOne: async () => { updates += 1; return { matchedCount: 1 }; } },
        RemoteAdmission: { db, create: async () => { throw new Error('unexpected create'); },
            findOne() { throw new Error('unexpected findOne'); },
            updateOne: async () => ({ matchedCount: 1 }) },
    });
    await assert.rejects(repository.acquireInstall({ nodeId: 'relay-1' }), error => {
        assert.match(error.message, /withTransaction/);
        assert.ok(error.admissionId);
        return true;
    });
    assert.equal(updates, 0);
});

test('queued install admission cannot be prematurely released by its former running owner', async () => {
    const f = fixture();
    const id = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    f.records.get(id).phase = 'queued';
    await assert.rejects(f.repository.release(id), { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal(f.records.get(id).phase, 'queued');
});

test('install release refuses a running admission with only an operation link, lease, or stale generation', async () => {
    for (const change of [{ operationId: 'install-op' }, { leaseOwner: 'worker' },
        { ownerGeneration: 2 }]) {
        const f = fixture();
        const id = await f.repository.acquireInstall({ nodeId: 'relay-1' });
        Object.assign(f.records.get(id), change);
        await assert.rejects(f.repository.release(id), { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
        assert.equal(f.state.remoteAdmissionCount, 1);
        assert.equal(f.records.get(id).phase, 'running');
        assert.deepEqual(f.calls, ['gate', 'record']);
    }
});

test('release gate CAS miss rolls back a prequeue admission completion', async () => {
    const f = fixture();
    const id = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    f.state.remoteAdmissionCount = 0;
    await assert.rejects(f.repository.release(id), { code: 'REMOTE_ADMISSION_GATE_MISSING' });
    assert.equal(f.records.get(id).phase, 'running');
    assert.equal(f.state.remoteAdmissionCount, 0);
});

test('install release decrements only its own running record once', async () => {
    const f = fixture();
    const first = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    const second = await f.repository.acquireInstall({ nodeId: 'relay-2' });
    await f.repository.release(first);
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal(f.records.get(first).phase, 'completed');
    assert.equal(f.records.get(second).phase, 'running');
    await assert.rejects(f.repository.release(first), { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
    assert.equal(f.state.remoteAdmissionCount, 1);
});

test('acquireInstall rejects missing identity without a gate mutation', async () => {
    const f = fixture();
    await assert.rejects(f.repository.acquireInstall({}), /Invalid install admission/);
    assert.deepEqual(f.calls, []);
});

test('completeTerminalOperation closes a verified rollback and decrements the counted gate once', async () => {
    const f = fixture();
    const admissionId = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    const admission = f.records.get(admissionId);
    Object.assign(admission, {
        phase: 'running', operationId: 'operation-1', leaseOwner: 'worker-1', ownerGeneration: 2,
    });
    f.operations.set('operation-1', {
        _id: 'operation-1', node: 'relay-1', kind: 'install', status: 'rolled_back',
        admissionId, leaseOwner: 'worker-1', ownerGeneration: 2,
    });
    assert.equal(await f.repository.completeTerminalOperation({
        admissionId, operationId: 'operation-1', nodeId: 'relay-1', owner: 'worker-1',
        ownerGeneration: 2, kind: 'install',
    }), true);
    assert.equal(f.state.remoteAdmissionCount, 0);
    assert.equal(admission.phase, 'completed');
    await assert.rejects(f.repository.completeTerminalOperation({
        admissionId, operationId: 'operation-1', nodeId: 'relay-1', owner: 'worker-1',
        ownerGeneration: 2, kind: 'install',
    }), { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
    assert.equal(f.state.remoteAdmissionCount, 0);
});

test('terminal completion refuses a still-owned node lock, even after operation rollback', async () => {
    const f = fixture();
    const admissionId = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    Object.assign(f.records.get(admissionId), {
        operationId: 'op-locked', leaseOwner: 'worker-1', ownerGeneration: 2,
    });
    f.operations.set('op-locked', {
        _id: 'op-locked', node: 'relay-1', kind: 'install', status: 'rolled_back',
        admissionId, leaseOwner: 'worker-1', ownerGeneration: 2,
    });
    f.locks.set('relay-1:op-locked', { generation: 'lock-uuid', remoteUncertain: true });
    const request = { admissionId, operationId: 'op-locked', nodeId: 'relay-1',
        owner: 'worker-1', ownerGeneration: 2, kind: 'install' };
    await assert.rejects(f.repository.completeTerminalOperation(request),
        { code: 'REMOTE_ADMISSION_LOCK_HELD' });
    assert.equal(f.state.remoteAdmissionCount, 1);
    f.locks.delete('relay-1:op-locked');
    assert.equal(await f.repository.completeTerminalOperation(request), true);
    assert.equal(f.state.remoteAdmissionCount, 0);
});

test('failed rollback cannot be counted as a completed remote operation', async () => {
    const f = fixture();
    const admissionId = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    Object.assign(f.records.get(admissionId), {
        operationId: 'op-uncertain', leaseOwner: 'worker-1', ownerGeneration: 2,
    });
    f.operations.set('op-uncertain', {
        _id: 'op-uncertain', node: 'relay-1', kind: 'install', status: 'failed',
        errorCode: 'ROLLBACK_FAILED', progress: 0, admissionId,
        leaseOwner: 'worker-1', ownerGeneration: 2,
    });
    await assert.rejects(f.repository.completeTerminalOperation({
        admissionId, operationId: 'op-uncertain', nodeId: 'relay-1',
        owner: 'worker-1', ownerGeneration: 2, kind: 'install',
    }), { code: 'REMOTE_ADMISSION_NOT_TERMINAL' });
    assert.equal(f.state.remoteAdmissionCount, 1);
});

test('recovery-required admission closes only after verified terminal readback', async () => {
    const f = fixture();
    const admissionId = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    Object.assign(f.records.get(admissionId), {
        phase: 'recovery_required', operationId: 'op-rolled-back',
        leaseOwner: 'worker-1', ownerGeneration: 2,
    });
    f.operations.set('op-rolled-back', {
        _id: 'op-rolled-back', node: 'relay-1', kind: 'install', status: 'rolled_back',
        admissionId, leaseOwner: 'worker-1', ownerGeneration: 2,
    });
    assert.equal(await f.repository.completeTerminalOperation({
        admissionId, operationId: 'op-rolled-back', nodeId: 'relay-1',
        owner: 'worker-1', ownerGeneration: 2, kind: 'install',
    }), true);
    assert.equal(f.state.remoteAdmissionCount, 0);
});

test('recovery scan closes durable pre-SSH failure and leaves uncertain rollback fenced', async () => {
    const f = fixture();
    const pre = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    Object.assign(f.records.get(pre), { operationId: 'pre-op', leaseOwner: 'worker-1', ownerGeneration: 2 });
    f.operations.set('pre-op', { _id: 'pre-op', node: 'relay-1', kind: 'install',
        status: 'failed', progress: 0, errorCode: 'XRAY_CANDIDATE_FAILED',
        admissionId: pre, leaseOwner: 'worker-1', ownerGeneration: 2 });
    const uncertain = await f.repository.acquireInstall({ nodeId: 'relay-2' });
    Object.assign(f.records.get(uncertain), {
        phase: 'recovery_required', operationId: 'uncertain-op',
        leaseOwner: 'worker-2', ownerGeneration: 2,
    });
    f.operations.set('uncertain-op', { _id: 'uncertain-op', node: 'relay-2', kind: 'install',
        status: 'failed', progress: 0, errorCode: 'ROLLBACK_FAILED',
        admissionId: uncertain, leaseOwner: 'worker-2', ownerGeneration: 2 });
    f.locks.set('relay-2:uncertain-op', { generation: 'held-lock' });
    assert.deepEqual(await f.repository.recoverSettledAdmissions(), { scanned: 2, recovered: 1 });
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal(f.records.get(pre).phase, 'completed');
    assert.equal(f.records.get(uncertain).phase, 'recovery_required');
});

test('markOperationRecoveryRequired preserves the counted gate after uncertain worker ownership', async () => {
    const f = fixture();
    const admissionId = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    const admission = f.records.get(admissionId);
    Object.assign(admission, {
        phase: 'running', operationId: 'operation-2', leaseOwner: 'worker-1', ownerGeneration: 2,
    });
    assert.equal(await f.repository.markOperationRecoveryRequired({
        admissionId, operationId: 'operation-2', nodeId: 'relay-1', owner: 'worker-1',
        ownerGeneration: 2, kind: 'install',
    }), true);
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal(admission.phase, 'recovery_required');
});
