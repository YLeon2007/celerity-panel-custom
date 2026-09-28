'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const mongoose = require('mongoose');
const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');
const RemoteAdmissionModel = require('../models/remoteAdmissionModel');
const L2tpOperationModel = require('../models/l2tpOperationModel');

const node = '507f1f77bcf86cd799439011';
const operationId = '507f1f77bcf86cd799439012';
const admissionId = 'admission-install-1';
const key = `install:${node}:revision-7`;

function operation(overrides = {}) {
    return {
        _id: operationId, node, kind: 'install', status: 'queued',
        idempotencyKey: key,
        plan: { ok: true, operationId, relayId: node, topologyRevision: 7, steps: [{ type: 'verify' }] },
        ...overrides,
    };
}

function fixture({ admission = {}, gate = {}, createError, casMiss = false, operations = [],
    splitConnection = false, missingOperationModel = false } = {}) {
    const session = { id: 'install-handoff' };
    const db = { startSession: async () => session };
    const state = { _id: 'singleton', remoteAdmissionCount: 1, ...gate };
    const record = { _id: admissionId, nodeId: node, kind: 'install', phase: 'running',
        ownerGeneration: 1, ...admission };
    const records = new Map([[admissionId, record]]);
    const created = new Map(operations.map(item => [String(item._id), item]));
    const calls = [];
    const CascadeTopologyState = {
        db, updateOne: async () => { throw new Error('handoff must not change gate'); },
        findOne(filter) {
            calls.push(['gate', filter]);
            assert.deepEqual(filter, { _id: 'singleton', remoteAdmissionCount: { $gt: 0 },
                remoteDrain: { $exists: false }, replacementReservation: { $exists: false } });
            return { session(s) {
                assert.strictEqual(s, session);
                return { lean: async () => state._id === filter._id
                    && state.remoteAdmissionCount > 0
                    && state.remoteDrain === undefined
                    && state.replacementReservation === undefined ? state : null };
            } };
        },
    };
    const RemoteAdmission = {
        db, create: async () => { throw new Error('handoff must not create admission'); },
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            calls.push(['admission', filter, update]);
            assert.deepEqual(filter, { _id: admissionId, nodeId: node, kind: 'install',
                phase: 'running', operationId: { $exists: false } });
            const target = records.get(filter._id);
            if (casMiss || !target || target._id !== filter._id
                || target.kind !== filter.kind || target.phase !== filter.phase
                || target.nodeId !== filter.nodeId || target.operationId !== undefined) {
                return { matchedCount: 0 };
            }
            Object.assign(target, update.$set);
            return { matchedCount: 1 };
        },
    };
    const L2tpOperation = missingOperationModel ? undefined : {
        db: splitConnection ? { startSession: db.startSession } : db,
        async create(documents, options) {
            assert.strictEqual(options.session, session);
            calls.push(['operation', documents]);
            if (createError) throw createError;
            for (const doc of documents) {
                const candidate = new L2tpOperationModel(doc);
                await candidate.validate();
                if (created.has(String(candidate._id))
                    || [...created.values()].some(old => old.idempotencyKey === candidate.idempotencyKey)) {
                    const error = new Error('duplicate operation');
                    error.code = 11000;
                    throw error;
                }
                created.set(String(candidate._id), candidate.toObject());
            }
        },
    };
    const repository = new RemoteAdmissionRepository({ CascadeTopologyState, RemoteAdmission,
        L2tpOperation, transactionRunner: async work => {
            const savedRecords = new Map([...records].map(([id, value]) => [id, { ...value }]));
            const savedOperations = new Map(created);
            const count = state.remoteAdmissionCount;
            try { return await work(session); } catch (error) {
                records.clear();
                for (const [id, value] of savedRecords) records.set(id, value);
                created.clear();
                for (const [id, value] of savedOperations) created.set(id, value);
                state.remoteAdmissionCount = count;
                throw error;
            }
        } });
    return { repository, state, records, created, calls };
}

function unchanged(f, originalCount = 1, originalOperations = 0) {
    assert.equal(f.state.remoteAdmissionCount, originalCount);
    assert.equal(f.records.get(admissionId)?.phase, 'running');
    assert.equal(f.records.get(admissionId)?.operationId, undefined);
    assert.equal(f.created.size, originalOperations);
}

test('queueInstall atomically links a counted install admission and a queued operation without changing the gate', async () => {
    const f = fixture();
    assert.equal(await f.repository.queueInstall({ admissionId, operationDocument: operation() }), operationId);
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal(f.records.get(admissionId).phase, 'queued');
    assert.equal(f.records.get(admissionId).operationId, operationId);
    assert.equal(f.created.get(operationId).admissionId, admissionId);
    assert.equal(f.created.get(operationId).status, 'queued');
    assert.deepEqual(f.calls.map(([kind]) => kind), ['gate', 'operation', 'admission']);
});

test('operation create failure rolls back admission and preserves the count', async () => {
    const f = fixture({ createError: new Error('create unavailable') });
    await assert.rejects(f.repository.queueInstall({ admissionId, operationDocument: operation() }), /create unavailable/);
    unchanged(f);
});

test('admission CAS miss rolls back the newly created operation and preserves the count', async () => {
    const f = fixture({ casMiss: true });
    await assert.rejects(f.repository.queueInstall({ admissionId, operationDocument: operation() }),
        { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
    unchanged(f);
    assert.equal(f.calls.some(([kind]) => kind === 'operation'), true);
});

test('missing or split operation model fails closed even with an injected transaction runner', async () => {
    for (const options of [{ missingOperationModel: true }, { splitConnection: true }]) {
        const f = fixture(options);
        await assert.rejects(f.repository.queueInstall({ admissionId, operationDocument: operation() }),
            /transactional Mongo connection/);
        unchanged(f);
        assert.equal(f.calls.length, 0);
    }
});

test('default runner uses one connection transaction and session for every model', async () => {
    const calls = [];
    const session = { withTransaction: async work => { calls.push('transaction'); await work(); },
        endSession: async () => { calls.push('end'); } };
    const db = { startSession: async () => { calls.push('start'); return session; } };
    const repository = new RemoteAdmissionRepository({
        CascadeTopologyState: {
            db, updateOne: async () => { throw new Error('gate changed'); },
            findOne: () => ({ session: received => {
                assert.strictEqual(received, session);
                return { lean: async () => { calls.push('gate'); return { remoteAdmissionCount: 1 }; } };
            } }),
        },
        RemoteAdmission: {
            db, create: async () => { throw new Error('created admission'); },
            updateOne: async (_filter, _update, options) => {
                assert.strictEqual(options.session, session);
                calls.push('admission'); return { matchedCount: 1 };
            },
        },
        L2tpOperation: { db, create: async (_docs, options) => {
            assert.strictEqual(options.session, session);
            calls.push('operation');
        } },
    });
    assert.equal(await repository.queueInstall({ admissionId, operationDocument: operation() }), operationId);
    assert.deepEqual(calls, ['start', 'transaction', 'gate', 'operation', 'admission', 'end']);
});

test('duplicate operation id or idempotency key fails closed without consuming admission', async () => {
    for (const existing of [operation(), operation({ _id: new mongoose.Types.ObjectId().toString() })]) {
        const f = fixture({ operations: [existing] });
        await assert.rejects(f.repository.queueInstall({ admissionId, operationDocument: operation() }),
            { code: 11000 });
        unchanged(f, 1, 1);
    }
});

test('unknown or stale admission cannot queue an operation', async () => {
    for (const value of [{ _id: 'another-admission' }, { phase: 'completed' },
        { phase: 'queued', operationId: 'old-operation' }, { kind: 'standalone_preflight' },
        { nodeId: 'another-node' }]) {
        const f = fixture({ admission: value });
        await assert.rejects(f.repository.queueInstall({ admissionId, operationDocument: operation() }),
            { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
        assert.equal(f.state.remoteAdmissionCount, 1);
        assert.equal(f.created.size, 0);
        assert.deepEqual(f.records.get(admissionId), { _id: admissionId, nodeId: node, kind: 'install',
            phase: 'running', ownerGeneration: 1, ...value });
    }
});

test('uncounted or held gate cannot hand off an admission', async () => {
    for (const gate of [{ remoteAdmissionCount: 0 }, { remoteAdmissionCount: undefined },
        { remoteDrain: { ownerToken: 'drain', epoch: 1 } },
        { replacementReservation: { ownerToken: 'reservation', epoch: 1 } }]) {
        const f = fixture({ gate });
        await assert.rejects(f.repository.queueInstall({ admissionId, operationDocument: operation() }),
            { code: 'REMOTE_ADMISSION_BLOCKED' });
        assert.equal(f.state.remoteAdmissionCount,
            Object.hasOwn(gate, 'remoteAdmissionCount') ? gate.remoteAdmissionCount : 1);
        assert.equal(f.created.size, 0);
        assert.equal(f.records.get(admissionId).phase, 'running');
    }
});

test('operation identity must match admission node and its own plan before any write', async () => {
    for (const overrides of [
        { node: new mongoose.Types.ObjectId().toString() },
        { kind: 'remove' }, { status: 'running' },
        { plan: { ...operation().plan, operationId: new mongoose.Types.ObjectId().toString() } },
        { plan: { ...operation().plan, relayId: new mongoose.Types.ObjectId().toString() } },
        { idempotencyKey: 'install:another-node:revision-7' },
        { idempotencyKey: `install:${node}:revision-8` },
    ]) {
        const f = fixture();
        await assert.rejects(f.repository.queueInstall({ admissionId, operationDocument: operation(overrides) }),
            { code: 'REMOTE_ADMISSION_INVALID_INSTALL' });
        unchanged(f);
        assert.equal(f.calls.length, 0);
    }
});

test('models retain the optional link and queued install state without changing legacy records', () => {
    const admission = new RemoteAdmissionModel({ _id: admissionId, nodeId: node,
        kind: 'install', phase: 'queued', operationId, ownerGeneration: 1 });
    assert.equal(admission.validateSync(), undefined);
    assert.equal(admission.toObject().operationId, operationId);
    const legacyAdmission = new RemoteAdmissionModel({ _id: 'legacy', nodeId: node,
        kind: 'standalone_preflight', phase: 'running', ownerGeneration: 1 });
    assert.equal(legacyAdmission.validateSync(), undefined);
    const op = new L2tpOperationModel({ ...operation(), admissionId });
    assert.equal(op.validateSync(), undefined);
    assert.equal(op.toObject().admissionId, admissionId);
    const oldOp = new L2tpOperationModel(operation());
    assert.equal(oldOp.validateSync(), undefined);
    assert.equal(oldOp.admissionId, undefined);
});
