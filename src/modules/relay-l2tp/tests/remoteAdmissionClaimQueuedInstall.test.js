'use strict';
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');

const assert = require('node:assert/strict');
const test = require('node:test');
const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');
const L2tpOperationModel = require('../models/l2tpOperationModel');
const RemoteAdmissionModel = require('../models/remoteAdmissionModel');

const nodeId = '507f1f77bcf86cd799439011';
const operationId = '507f1f77bcf86cd799439012';
const now = new Date('2026-09-28T09:00:00Z');
const admissionId = 'admission-one';

function operation(overrides = {}) {
    return { _id: operationId, node: nodeId, kind: 'install', executionContext: TEST, status: 'queued',
        admissionId, attempts: 0, createdAt: new Date('2026-09-27T00:00:00Z'), ...overrides };
}
function admission(overrides = {}) {
    return { _id: admissionId, nodeId, kind: 'install', phase: 'queued',
        operationId, ownerGeneration: 1, ...overrides };
}
function fixture({ operations = [operation()], admissions = [admission()], gate = {},
    split = false, operationCasMiss = false, admissionCasMiss = false } = {}) {
    const session = { token: 'one-session' };
    const db = { startSession: async () => session };
    const state = { _id: 'singleton', remoteAdmissionCount: 1, ...gate };
    const ops = new Map(operations.map(item => [String(item._id), { ...item }]));
    const records = new Map(admissions.map(item => [item._id, { ...item }]));
    const calls = [];
    const CascadeTopologyState = {
        db, updateOne: async () => { throw new Error('count must never change'); },
        findOne(filter) {
            calls.push(['gate', filter]);
            return { session(s) { assert.strictEqual(s, session); return { lean: async () =>
                state._id === 'singleton' && state.remoteAdmissionCount > 0
                && state.remoteDrain === undefined && state.replacementReservation === undefined ? state : null }; } };
        },
    };
    const L2tpOperation = {
        db: split === 'operation' ? {} : db,
        findOne(filter) {
            calls.push(['select', filter]);
            return { sort(sort) {
                assert.deepEqual(sort, { createdAt: 1, _id: 1 });
                return { session(s) { assert.strictEqual(s, session); return { lean: async () => {
                    const eligible = [...ops.values()].filter(item => item.status === 'queued'
                        && item.kind === 'install' && typeof item.admissionId === 'string'
                        && item.admissionId.length > 0);
                    eligible.sort((a, b) => a.createdAt - b.createdAt || String(a._id).localeCompare(String(b._id)));
                    return eligible[0] ? { ...eligible[0] } : null;
                } }; } };
            } };
        },
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            calls.push(['operationCAS', filter, update]);
            const item = ops.get(String(filter._id));
            if (operationCasMiss || !item || item.status !== filter.status
                || item.kind !== filter.kind || item.admissionId !== filter.admissionId
                || item.attempts !== filter.attempts || item.ownerGeneration !== undefined
                || String(item.node) !== String(filter.node)) return { matchedCount: 0 };
            Object.assign(item, update.$set);
            item.attempts += update.$inc.attempts;
            return { matchedCount: 1 };
        },
    };
    const RemoteAdmission = {
        db: split === 'admission' ? {} : db,
        create: async () => { throw new Error('must not create admission'); },
        findOne(filter) {
            calls.push(['admissionLookup', filter]);
            return { session(s) { assert.strictEqual(s, session); return { lean: async () => {
                const item = records.get(filter._id);
                return item && item.nodeId === filter.nodeId && item.kind === filter.kind
                    && item.phase === filter.phase && item.operationId === filter.operationId
                    && item.leaseOwner === undefined
                    ? { ...item } : null;
            } }; } };
        },
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            calls.push(['admissionCAS', filter, update]);
            const item = records.get(filter._id);
            if (admissionCasMiss || !item || item.phase !== filter.phase
                || item.kind !== filter.kind || item.nodeId !== filter.nodeId
                || item.operationId !== filter.operationId
                || item.ownerGeneration !== filter.ownerGeneration) return { matchedCount: 0 };
            Object.assign(item, update.$set);
            item.ownerGeneration += update.$inc.ownerGeneration;
            return { matchedCount: 1 };
        },
    };
    const repository = new RemoteAdmissionRepository({ CascadeTopologyState, RemoteAdmission,
        L2tpOperation, transactionRunner: async work => {
            const oldOps = new Map([...ops].map(([id, value]) => [id, { ...value }]));
            const oldRecords = new Map([...records].map(([id, value]) => [id, { ...value }]));
            try { return await work(session); } catch (error) {
                ops.clear(); for (const [id, value] of oldOps) ops.set(id, value);
                records.clear(); for (const [id, value] of oldRecords) records.set(id, value);
                throw error;
            }
        } });
    return { repository, state, ops, records, calls, session, db,
        CascadeTopologyState, RemoteAdmission, L2tpOperation };
}
const claim = f => f.repository.claimQueuedInstall({ executionContext: TEST, owner: 'worker-one', leaseMs: 30000, now });

test('claims oldest queued install and its admission as one owner generation without changing count', async () => {
    const f = fixture();
    const result = await claim(f);
    assert.equal(String(result._id), operationId);
    assert.equal(result.status, 'running');
    assert.equal(result.ownerGeneration, 2);
    assert.equal(result.leaseOwner, 'worker-one');
    assert.deepEqual(result.leaseUntil, new Date(now.getTime() + 30000));
    assert.equal(result.attempts, 1);
    assert.equal(f.records.get(admissionId).phase, 'running');
    assert.equal(f.records.get(admissionId).leaseOwner, 'worker-one');
    assert.equal(f.records.get(admissionId).ownerGeneration, 2);
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.deepEqual(f.calls.map(([type]) => type), ['gate', 'select', 'admissionLookup', 'operationCAS', 'admissionCAS']);
    assert.deepEqual(f.calls[1][1], { 'executionContext.target': TEST.target, 'executionContext.hostIdentity': TEST.hostIdentity,
        status: 'queued', kind: 'install', admissionId: { $type: 'string', $ne: '' } });
    assert.deepEqual(f.calls[2][1], { _id: admissionId, nodeId, kind: 'install', phase: 'queued',
        operationId, leaseOwner: { $exists: false } });
});

test('deterministically selects oldest eligible install, breaking createdAt ties by id', async () => {
    const laterId = '507f1f77bcf86cd799439013';
    const olderId = '507f1f77bcf86cd799439010';
    const f = fixture({ operations: [
        operation({ _id: laterId, admissionId: 'later', createdAt: new Date('2026-09-28T00:00:00Z') }),
        operation({ _id: operationId, admissionId: 'legacy', kind: 'remove', createdAt: new Date('2026-09-26T00:00:00Z') }),
        operation({ _id: olderId, admissionId: 'older', createdAt: new Date('2026-09-28T00:00:00Z') }),
    ], admissions: [admission({ _id: 'older', operationId: olderId }),
        admission({ _id: 'later', operationId: laterId })] });
    assert.equal(String((await claim(f))._id), olderId);
    assert.equal(f.ops.get(laterId).status, 'queued');
});

test('default runner uses the shared connection transaction and one session for all reads and CAS writes', async () => {
    const f = fixture();
    let opened = 0;
    let transaction = 0;
    let ended = 0;
    f.db.startSession = async () => { opened++; return f.session; };
    f.session.withTransaction = async work => { transaction++; await work(); };
    f.session.endSession = async () => { ended++; };
    f.repository = new RemoteAdmissionRepository({ CascadeTopologyState: f.CascadeTopologyState,
        RemoteAdmission: f.RemoteAdmission, L2tpOperation: f.L2tpOperation });
    assert.equal((await claim(f)).ownerGeneration, 2);
    assert.deepEqual([opened, transaction, ended], [1, 1, 1]);
    assert.deepEqual(f.calls.map(([type]) => type), ['gate', 'select', 'admissionLookup', 'operationCAS', 'admissionCAS']);
});

test('operation CAS race cannot hand off admission', async () => {
    const f = fixture({ operationCasMiss: true });
    assert.equal(await claim(f), null);
    assert.equal(f.ops.get(operationId).status, 'queued');
    assert.equal(f.records.get(admissionId).phase, 'queued');
    assert.equal(f.calls.some(([type]) => type === 'admissionCAS'), false);
});

test('admission CAS race rolls back operation claim, attempts, lease and generation', async () => {
    const f = fixture({ admissionCasMiss: true });
    assert.equal(await claim(f), null);
    assert.deepEqual(f.ops.get(operationId), operation());
    assert.deepEqual(f.records.get(admissionId), admission());
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.deepEqual(f.calls.slice(-2).map(([type]) => type), ['operationCAS', 'admissionCAS']);
});

test('second claim cannot reclaim running operation, even after its lease expires', async () => {
    const f = fixture();
    await claim(f);
    assert.equal(await f.repository.claimQueuedInstall({ executionContext: TEST, owner: 'worker-two', leaseMs: 30000,
        now: new Date('2026-10-01T00:00:00Z') }), null);
    assert.equal(f.ops.get(operationId).leaseOwner, 'worker-one');
    assert.equal(f.ops.get(operationId).attempts, 1);
    assert.equal(f.records.get(admissionId).ownerGeneration, 2);
});

test('legacy queued operation without admission id is never selected', async () => {
    const f = fixture({ operations: [operation({ admissionId: undefined })] });
    assert.equal(await claim(f), null);
    assert.equal(f.ops.get(operationId).status, 'queued');
    assert.equal(f.calls.some(([type]) => type === 'admissionLookup'), false);
});

test('missing or mismatched queued admission cannot authorize claim', async () => {
    const mismatches = [[], [admission({ _id: 'wrong' })],
        [admission({ nodeId: 'wrong' })], [admission({ kind: 'standalone_preflight' })],
        [admission({ phase: 'running' })], [admission({ phase: 'completed' })],
        [admission({ operationId: 'wrong' })], [admission({ leaseOwner: 'old-worker' })],
        [admission({ ownerGeneration: 0 })],
        [admission({ ownerGeneration: Number.MAX_SAFE_INTEGER })]];
    for (const admissions of mismatches) {
        const f = fixture({ admissions });
        assert.equal(await claim(f), null);
        assert.deepEqual(f.ops.get(operationId), operation());
        assert.equal(f.calls.some(([type]) => type === 'operationCAS'), false);
        assert.equal(f.state.remoteAdmissionCount, 1);
    }
});

test('queued operation with invalid attempts cannot fabricate a claimed attempt count', async () => {
    for (const overrides of [{ attempts: undefined }, { attempts: -1 },
        { attempts: Number.MAX_SAFE_INTEGER }, { ownerGeneration: 2 }]) {
        const f = fixture({ operations: [operation(overrides)] });
        assert.equal(await claim(f), null);
        assert.equal(f.calls.some(([type]) => type === 'operationCAS'), false);
        assert.equal(f.records.get(admissionId).phase, 'queued');
    }
});

test('uncounted, missing, draining or reserved singleton blocks claim without mutation', async () => {
    for (const gate of [{ remoteAdmissionCount: 0 }, { remoteAdmissionCount: undefined },
        { _id: 'missing' }, { remoteDrain: { ownerToken: 'drain' } },
        { replacementReservation: { ownerToken: 'replace' } }]) {
        const f = fixture({ gate });
        assert.equal(await claim(f), null);
        assert.deepEqual(f.ops.get(operationId), operation());
        assert.deepEqual(f.records.get(admissionId), admission());
        assert.deepEqual(f.calls.map(([type]) => type), ['gate']);
    }
});

test('missing or split models fail closed before opening a claim transaction', async () => {
    for (const split of ['operation', 'admission']) {
        const f = fixture({ split });
        await assert.rejects(claim(f), /three models on one transactional Mongo connection/);
        assert.equal(f.calls.length, 0);
    }
    const f = fixture();
    f.repository.L2tpOperation = undefined;
    await assert.rejects(claim(f), /three models on one transactional Mongo connection/);
    assert.equal(f.calls.length, 0);
});

test('rejects invalid owner, lease or clock before touching the database', async () => {
    const f = fixture();
    for (const input of [{ owner: '', leaseMs: 100, now },
        { owner: 'worker', leaseMs: 0, now }, { owner: 'worker', leaseMs: 1.5, now },
        { owner: 'worker', leaseMs: 100, now: new Date(NaN) }]) {
        await assert.rejects(f.repository.claimQueuedInstall({ executionContext: TEST, ...input }), /Invalid queued install claim/);
    }
    assert.equal(f.calls.length, 0);
});

test('operation schema stores owner generation but leaves legacy operations unversioned', () => {
    const plan = { ok: true, operationId, relayId: nodeId, topologyRevision: 1, steps: [{ type: 'verify' }] };
    const base = { ...operation(), idempotencyKey: `install:${nodeId}:revision-1`, plan };
    const claimed = new L2tpOperationModel({ ...base, ownerGeneration: 2 });
    assert.equal(claimed.validateSync(), undefined);
    assert.equal(claimed.toObject().ownerGeneration, 2);
    const legacy = new L2tpOperationModel(base);
    assert.equal(legacy.validateSync(), undefined);
    assert.equal(legacy.ownerGeneration, undefined);
    const ownedAdmission = new RemoteAdmissionModel({ ...admission(), phase: 'running',
        leaseOwner: 'worker-one', ownerGeneration: 2 });
    assert.equal(ownedAdmission.validateSync(), undefined);
    assert.equal(ownedAdmission.toObject().leaseOwner, 'worker-one');
    const oldAdmission = new RemoteAdmissionModel(admission());
    assert.equal(oldAdmission.validateSync(), undefined);
    assert.equal(oldAdmission.leaseOwner, undefined);
});

test('execution identity mismatch or absence cannot change operation or admission', async () => {
    const TEST = { target: 'test', hostIdentity: 'test.infograd.online' };
    for (const binding of [undefined, {}, { target: 'production', hostIdentity: 'lm1.infograd.online' },
        { ...TEST, hostIdentity: 'lm1.infograd.online' }, { ...TEST, extra: true }]) {
        const f = fixture({ operations: [operation({ executionContext: binding })] });
        assert.equal(await f.repository.claimQueuedInstall({ owner: 'worker', leaseMs: 30000, now,
            executionContext: TEST }), null);
        assert.equal(f.ops.get(operationId).status, 'queued');
        assert.equal(f.calls.some(([type]) => ['gateCAS', 'operationCAS', 'admissionCAS', 'create'].includes(type)), false);
    }
});
