'use strict';
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');

const assert = require('node:assert/strict');
const test = require('node:test');
const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');
const RemoteAdmissionModel = require('../models/remoteAdmissionModel');

const nodeId = '507f1f77bcf86cd799439011';
const operationId = '507f1f77bcf86cd799439012';
const now = new Date('2026-09-28T09:00:00Z');
const op = (changes = {}) => ({ _id: operationId, node: nodeId, kind: 'sync_users',
    executionContext: TEST, status: 'queued', attempts: 0, createdAt: new Date('2026-09-27'), ...changes });

function fixture({ operations = [op()], gate = {}, admissions = [], split,
    operationCasMiss = false, gateCasMiss = false, createError = null,
    commitError = null } = {}) {
    const db = { startSession: async () => session };
    const session = { token: 'one' };
    const state = { _id: 'singleton', remoteAdmissionCount: 0, ...gate };
    const ops = new Map(operations.map(item => [String(item._id), { ...item }]));
    const records = new Map(admissions.map(item => [item._id, { ...item }]));
    const calls = [];
    let transactionCount = 0;
    const snapshot = () => ({ state: { ...state }, ops: new Map([...ops].map(([k, v]) => [k, { ...v }])),
        records: new Map([...records].map(([k, v]) => [k, { ...v }])) });
    const restore = before => {
        Object.assign(state, before.state);
        ops.clear(); for (const [k, v] of before.ops) ops.set(k, v);
        records.clear(); for (const [k, v] of before.records) records.set(k, v);
    };
    const CascadeTopologyState = {
        db, async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            calls.push(['gateCAS', filter, update]);
            if (gateCasMiss || state._id !== filter._id || !Number.isInteger(state.remoteAdmissionCount)
                || state.remoteAdmissionCount < 0 || state.remoteDrain !== undefined
                || state.replacementReservation !== undefined) return { matchedCount: 0 };
            state.remoteAdmissionCount += update.$inc.remoteAdmissionCount;
            return { matchedCount: 1 };
        },
    };
    const L2tpOperation = {
        db: split === 'operation' ? {} : db,
        findOne(filter) {
            calls.push(['select', filter]);
            return { sort(order) {
                assert.deepEqual(order, { createdAt: 1, _id: 1 });
                return { session(s) {
                    assert.strictEqual(s, session);
                    return { lean: async () => {
                        const selected = [...ops.values()].filter(item => item.status === 'queued'
                            && item.kind === 'sync_users' && item.admissionId === undefined
                            && item.ownerGeneration === undefined)
                            .sort((a, b) => a.createdAt - b.createdAt || String(a._id).localeCompare(String(b._id)))[0];
                        return selected ? { ...selected } : null;
                    } };
                } };
            } };
        },
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            calls.push(['operationCAS', filter, update]);
            const item = ops.get(String(filter._id));
            if (operationCasMiss || !item || item.status !== 'queued' || item.kind !== 'sync_users'
                || item.admissionId !== undefined || item.ownerGeneration !== undefined
                || item.attempts !== filter.attempts || String(item.node) !== String(filter.node)) return { matchedCount: 0 };
            Object.assign(item, update.$set);
            item.attempts += update.$inc.attempts;
            return { matchedCount: 1 };
        },
    };
    const RemoteAdmission = {
        db: split === 'admission' ? {} : db,
        findOne(filter) {
            calls.push(['admissionSelect', filter]);
            const row = [...records.values()].find(item => String(item.nodeId) === String(filter.nodeId)
                && filter.kind.$in.includes(item.kind) && filter.phase.$in.includes(item.phase));
            return { session(s) { assert.strictEqual(s, session); return this; },
                async lean() { return row ? { ...row } : null; } };
        },
        updateOne: async () => ({ matchedCount: 0 }),
        async create(docs, options) {
            assert.strictEqual(options.session, session);
            calls.push(['create', docs]);
            if (createError) throw createError;
            for (const doc of docs) {
                if ([...records.values()].some(item => item.kind === 'sync_users' && item.operationId === doc.operationId)) {
                    const error = new Error('duplicate operation admission'); error.code = 11000; throw error;
                }
                records.set(doc._id, { ...doc });
            }
        },
    };
    const repository = new RemoteAdmissionRepository({ CascadeTopologyState, RemoteAdmission, L2tpOperation,
        transactionRunner: async work => {
            transactionCount++;
            const before = snapshot();
            try {
                const result = await work(session);
                if (commitError) {
                    // An unknown commit outcome can have persisted all writes.
                    throw commitError;
                }
                return result;
            } catch (error) {
                if (!commitError) restore(before);
                throw error;
            }
        } });
    return { repository, state, ops, records, calls, db, session, CascadeTopologyState,
        RemoteAdmission, L2tpOperation, transactions: () => transactionCount };
}
const claim = (f, changes = {}) => f.repository.claimQueuedSyncUsers({ executionContext: TEST, owner: 'worker-one', leaseMs: 30000, now, ...changes });

test('claims oldest legacy queued sync_users, increments gate and creates exactly one linked running admission', async () => {
    const olderId = '507f1f77bcf86cd799439010';
    const laterId = '507f1f77bcf86cd799439013';
    const f = fixture({ operations: [op({ _id: laterId, createdAt: now }),
        op({ _id: olderId, attempts: 2 }), op({ _id: operationId, kind: 'install', createdAt: new Date(0) })] });
    const result = await claim(f);
    assert.equal(String(result._id), olderId);
    assert.equal(result.status, 'running');
    assert.equal(result.attempts, 3);
    assert.equal(result.ownerGeneration, 1);
    assert.equal(result.leaseOwner, 'worker-one');
    assert.deepEqual(result.leaseUntil, new Date(now.getTime() + 30000));
    assert.equal(typeof result.admissionId, 'string');
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal(f.records.size, 1);
    assert.deepEqual(f.records.get(result.admissionId), { _id: result.admissionId,
        kind: 'sync_users', phase: 'running', operationId: olderId, nodeId,
        ownerGeneration: 1, leaseOwner: 'worker-one' });
    assert.deepEqual(f.calls.map(([type]) => type), ['select', 'admissionSelect', 'gateCAS', 'operationCAS', 'create']);
    assert.deepEqual(f.calls[2][1], { _id: 'singleton', remoteDrain: { $exists: false },
        replacementReservation: { $exists: false }, remoteAdmissionCount: { $gte: 0 } });
    assert.equal(f.ops.get(laterId).status, 'queued');
});

test('sync claim refuses a queued user sync when another same-node admission is unresolved', async () => {
    const f = fixture({ admissions: [{ _id: 'install-admission', kind: 'install',
        phase: 'running', nodeId }] });
    assert.equal(await claim(f), null);
    assert.equal(f.state.remoteAdmissionCount, 0);
    assert.deepEqual(f.calls.map(([type]) => type), ['select', 'admissionSelect']);
});

test('a second same-node sync claim stays fenced while the first admission is unresolved', async () => {
    const olderId = '507f1f77bcf86cd799439010';
    const f = fixture({ operations: [op(), op({ _id: olderId })] });
    const first = await claim(f);
    assert.equal(String(first._id), olderId);
    assert.equal(await claim(f, { owner: 'worker-two', now: new Date('2026-10-01') }), null);
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal(f.records.size, 1);
    assert.equal(f.ops.get(olderId).leaseOwner, 'worker-one');
    assert.equal(f.ops.get(olderId).attempts, 1);
});

test('running and rolling_back sync users never reclaim, including expired leases', async () => {
    const f = fixture({ operations: [op({ status: 'running', leaseUntil: new Date(0) }),
        op({ _id: '507f1f77bcf86cd799439013', status: 'rolling_back', leaseUntil: new Date(0) })] });
    assert.equal(await claim(f), null);
    assert.equal(f.state.remoteAdmissionCount, 0);
    assert.deepEqual(f.calls.map(([type]) => type), ['select']);
});

test('missing, draining, reserved or malformed gate blocks claim without an admission', async () => {
    for (const gate of [{ _id: 'missing' }, { remoteAdmissionCount: undefined },
        { remoteAdmissionCount: -1 }, { remoteDrain: {} }, { replacementReservation: {} }]) {
        const f = fixture({ gate });
        assert.equal(await claim(f), null);
        assert.deepEqual(f.ops.get(operationId), op());
        assert.equal(f.records.size, 0);
        assert.deepEqual(f.calls.map(([type]) => type), ['select', 'admissionSelect', 'gateCAS']);
    }
});

test('preexisting admission identity or owner generation cannot be claimed as legacy queued work', async () => {
    for (const changes of [{ admissionId: 'old' }, { ownerGeneration: 1 }]) {
        const f = fixture({ operations: [op(changes)] });
        assert.equal(await claim(f), null);
        assert.equal(f.records.size, 0);
        assert.equal(f.state.remoteAdmissionCount, 0);
    }
});

test('invalid attempt count and CAS misses roll back count and operation claim', async () => {
    for (const changes of [{ attempts: undefined }, { attempts: -1 },
        { attempts: Number.MAX_SAFE_INTEGER }]) {
        const f = fixture({ operations: [op(changes)] });
        assert.equal(await claim(f), null);
        assert.deepEqual(f.ops.get(operationId), op(changes));
        assert.equal(f.state.remoteAdmissionCount, 0);
    }
    for (const options of [{ operationCasMiss: true }, { gateCasMiss: true },
        { createError: new Error('insert failed') }]) {
        const f = fixture(options);
        if (options.createError) await assert.rejects(claim(f), /insert failed/);
        else assert.equal(await claim(f), null);
        assert.deepEqual(f.ops.get(operationId), op());
        assert.equal(f.state.remoteAdmissionCount, 0);
        assert.equal(f.records.size, 0);
    }
});

test('unique operation identity conflict rolls back gate and claim rather than claiming twice', async () => {
    const f = fixture({ admissions: [{ _id: 'prior', kind: 'sync_users', operationId }] });
    await assert.rejects(claim(f), { code: 11000 });
    assert.deepEqual(f.ops.get(operationId), op());
    assert.equal(f.state.remoteAdmissionCount, 0);
    assert.equal(f.records.size, 1);
});

test('uncertain commit exposes stable attempted admission identity and never retries or releases', async () => {
    const f = fixture({ commitError: new Error('unknown commit result') });
    let caught;
    try { await claim(f); } catch (error) { caught = error; }
    assert.match(caught.message, /unknown commit result/);
    assert.equal(caught.admissionId, [...f.records.keys()][0]);
    assert.equal(f.ops.get(operationId).admissionId, caught.admissionId);
    assert.equal(f.transactions(), 1);
    assert.equal(f.state.remoteAdmissionCount, 1);
});

test('default claim opens one transaction and commits without retrying an ambiguous commit', async () => {
    const f = fixture();
    let starts = 0; let commits = 0; let ends = 0;
    f.session.startTransaction = () => { starts++; };
    f.session.commitTransaction = async () => { commits++; throw new Error('uncertain'); };
    f.session.abortTransaction = async () => {};
    f.session.inTransaction = () => true;
    f.session.endSession = async () => { ends++; };
    f.repository = new RemoteAdmissionRepository({ CascadeTopologyState: f.CascadeTopologyState,
        RemoteAdmission: f.RemoteAdmission, L2tpOperation: f.L2tpOperation });
    await assert.rejects(claim(f), error => error.message === 'uncertain'
        && error.admissionId === [...f.records.keys()][0]);
    assert.deepEqual([starts, commits, ends], [1, 1, 1]);
});

test('missing or split models fail closed before opening transaction', async () => {
    for (const split of ['operation', 'admission']) {
        const f = fixture({ split });
        await assert.rejects(claim(f), /three models on one transactional Mongo connection/);
        assert.equal(f.transactions(), 0);
    }
    const f = fixture(); f.repository.L2tpOperation = undefined;
    await assert.rejects(claim(f), /three models on one transactional Mongo connection/);
});

test('rejects invalid owner, lease or date before database access', async () => {
    const f = fixture();
    for (const changes of [{ owner: '' }, { leaseMs: 0 }, { leaseMs: 1.5 },
        { now: new Date(NaN) }]) {
        await assert.rejects(claim(f, changes), /Invalid queued sync_users claim/);
    }
    assert.equal(f.transactions(), 0);
});

test('schema supports sync_users and has a unique partial operationId index scoped to sync admissions', () => {
    const doc = new RemoteAdmissionModel({ _id: 'one', nodeId, kind: 'sync_users',
        phase: 'running', operationId, ownerGeneration: 1, leaseOwner: 'worker-one' });
    assert.equal(doc.validateSync(), undefined);
    const index = RemoteAdmissionModel.schema.indexes().find(([keys, options]) =>
        keys.operationId === 1 && options.unique && options.partialFilterExpression?.kind === 'sync_users');
    assert.ok(index);
    assert.deepEqual(index[1].partialFilterExpression.operationId, { $type: 'string' });
    const legacy = new RemoteAdmissionModel({ _id: 'legacy', nodeId, kind: 'install',
        phase: 'running', ownerGeneration: 1 });
    assert.equal(legacy.validateSync(), undefined);
});

test('execution identity mismatch or absence cannot change operation or admission', async () => {
    const TEST = { target: 'test', hostIdentity: 'test.infograd.online' };
    for (const binding of [undefined, {}, { target: 'production', hostIdentity: 'lm1.infograd.online' },
        { ...TEST, hostIdentity: 'lm1.infograd.online' }, { ...TEST, extra: true }]) {
        const f = fixture({ operations: [op({ executionContext: binding })] });
        assert.equal(await f.repository.claimQueuedSyncUsers({ owner: 'worker', leaseMs: 30000, now,
            executionContext: TEST }), null);
        assert.equal(f.ops.get(operationId).status, 'queued');
        assert.equal(f.calls.some(([type]) => ['gateCAS', 'operationCAS', 'admissionCAS', 'create'].includes(type)), false);
    }
});
