'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const mongoose = require('mongoose');
const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');
const RemoteAdmissionModel = require('../models/remoteAdmissionModel');
const L2tpOperationModel = require('../models/l2tpOperationModel');

const nodeId = '507f1f77bcf86cd799439011';
const operationId = '507f1f77bcf86cd799439012';
const admissionId = 'admission-readback-1';
const plan = { ok: true, operationId, relayId: nodeId, topologyRevision: 7,
    steps: [{ type: 'verify' }] };

function fixture({ gate = {}, admission = {}, operation = {}, missing = '', split = '',
    readError = '', rawPlan } = {}) {
    const calls = [];
    const session = { withTransaction: async (work, options) => {
        assert.deepEqual(options, { readConcern: { level: 'snapshot' } });
        calls.push('transaction'); await work();
    }, endSession: async () => { calls.push('end'); } };
    const db = { startSession: async () => { calls.push('start'); return session; } };
    const otherDb = { startSession: db.startSession };
    const state = { _id: 'singleton', remoteAdmissionCount: 1, ...gate };
    const admitted = new RemoteAdmissionModel({ _id: admissionId, nodeId, kind: 'install',
        phase: 'queued', operationId, ownerGeneration: 1, ...admission }).toObject();
    const queued = new L2tpOperationModel({ _id: operationId, node: nodeId, kind: 'install',
        status: 'queued', admissionId, idempotencyKey: `install:${nodeId}:revision-7`,
        plan, ...operation }).toObject();
    if (rawPlan) queued.plan = rawPlan;
    function query(kind, doc) {
        return { session(received) {
            assert.strictEqual(received, session);
            calls.push(kind);
            return { lean: async () => {
                if (readError === kind) throw new Error('database unavailable');
                return missing === kind ? null : doc;
            } };
        } };
    }
    const repository = new RemoteAdmissionRepository({
        CascadeTopologyState: { db: split === 'gate' ? otherDb : db,
            updateOne: async () => { throw new Error('write forbidden'); },
            findOne: filter => {
                assert.deepEqual(filter, { _id: 'singleton', remoteAdmissionCount: { $gt: 0 },
                    remoteDrain: { $exists: false }, replacementReservation: { $exists: false } });
                return query('gate', state);
            } },
        RemoteAdmission: { db: split === 'admission' ? otherDb : db,
            create: async () => { throw new Error('write forbidden'); },
            updateOne: async () => { throw new Error('write forbidden'); },
            findOne: filter => {
                assert.deepEqual(filter, { _id: admissionId, kind: 'install',
                    phase: 'queued', operationId });
                return query('admission', admitted);
            } },
        L2tpOperation: { db: split === 'operation' ? otherDb : db,
            findOne: filter => {
                assert.deepEqual(filter, { _id: operationId, admissionId,
                    kind: 'install', status: 'queued' });
                return query('operation', queued);
            } },
        ...(split ? { transactionRunner: async work => work(session) } : {}),
    });
    return { repository, calls };
}

async function read(f) {
    return f.repository.findInstallHandoff({ admissionId, operationId });
}

test('readback uses one transaction snapshot and returns only normalized linked identities and safe plan', async () => {
    const f = fixture();
    assert.deepEqual(await read(f), {
        admission: { _id: admissionId, nodeId, kind: 'install', phase: 'queued', operationId },
        operation: { _id: operationId, node: nodeId, kind: 'install', status: 'queued',
            admissionId, idempotencyKey: `install:${nodeId}:revision-7`, plan },
    });
    assert.deepEqual(f.calls, ['start', 'transaction', 'gate', 'admission', 'operation', 'end']);
});

test('Mongo-dropped undefined plan fields normalize to the same durable plan', async () => {
    const f = fixture({ rawPlan: { ...plan, routeGroupId: undefined } });
    assert.deepEqual((await read(f)).operation.plan, plan);
});

test('missing, uncounted or held singleton fails closed', async () => {
    for (const options of [{ missing: 'gate' }, { gate: { remoteAdmissionCount: 0 } },
        { gate: { remoteAdmissionCount: undefined } },
        { gate: { remoteDrain: { epoch: 1 } } },
        { gate: { replacementReservation: { epoch: 1 } } }]) {
        assert.equal(await read(fixture(options)), null);
    }
});

test('stale, mismatched or unlinked admission fails closed', async () => {
    for (const admission of [{ _id: 'other' }, { nodeId: 'other' },
        { kind: 'standalone_preflight' }, { phase: 'running' }, { phase: 'completed' },
        { operationId: 'other' }, { operationId: undefined },
        { leaseOwner: 'worker-1' }]) {
        assert.equal(await read(fixture({ admission })), null);
    }
    assert.equal(await read(fixture({ missing: 'admission' })), null);
});

test('mismatched or non-queued operation and plan fail closed', async () => {
    for (const operation of [{ _id: new mongoose.Types.ObjectId() },
        { node: new mongoose.Types.ObjectId() }, { admissionId: 'other' },
        { admissionId: undefined }, { kind: 'remove' }, { status: 'running' },
        { status: 'claimed' }, { ownerGeneration: 2 }, { attempts: 1 },
        { idempotencyKey: 'other' },
        { plan: { ...plan, operationId: 'other' } },
        { plan: { ...plan, relayId: 'other' } },
        { plan: { ...plan, topologyRevision: 8 } }]) {
        assert.equal(await read(fixture({ operation })), null, JSON.stringify(operation));
    }
    assert.equal(await read(fixture({ rawPlan: { ...plan, desired: { psk: 'must-not-leak' } } })), null);
    assert.equal(await read(fixture({ missing: 'operation' })), null);
});

test('split model connections, invalid input and unavailable reads fail closed', async () => {
    for (const split of ['gate', 'admission', 'operation']) {
        const f = fixture({ split });
        assert.equal(await read(f), null);
        assert.deepEqual(f.calls, []);
    }
    for (const kind of ['gate', 'admission', 'operation']) {
        await assert.rejects(read(fixture({ readError: kind })), /database unavailable/);
    }
    assert.equal(await fixture().repository.findInstallHandoff({ admissionId: '', operationId }), null);
});
