'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');

function fixture({ gate = {}, ambiguous = false, createFails = false, splitConnection = false,
    sessionUnavailable = false } = {}) {
    const state = gate === null ? null : { _id: 'singleton', remoteAdmissionCount: 0, ...gate };
    const records = new Map();
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
                || filter.remoteAdmissionCount?.$gt !== undefined && state.remoteAdmissionCount <= 0) {
                return { matchedCount: 0 };
            }
            state.remoteAdmissionCount += update.$inc.remoteAdmissionCount;
            return { matchedCount: 1 };
        },
    };
    const RemoteAdmission = {
        db: splitConnection ? { startSession: async () => session } : db,
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
            if (!record || record.phase !== filter.phase) return { matchedCount: 0 };
            Object.assign(record, update.$set);
            return { matchedCount: 1 };
        },
    };
    const repository = new RemoteAdmissionRepository({ CascadeTopologyState, RemoteAdmission,
        transactionRunner: async work => {
            const previousCount = state?.remoteAdmissionCount;
            const previousRecords = new Map([...records].map(([id, record]) => [id, { ...record }]));
            try {
                await work(session);
                if (ambiguous) {
                    const error = new Error('uncertain commit');
                    error.code = 'UNKNOWN_TRANSACTION_COMMIT_RESULT';
                    throw error;
                }
            } catch (error) {
                if (error.code !== 'UNKNOWN_TRANSACTION_COMMIT_RESULT') {
                    if (state) state.remoteAdmissionCount = previousCount;
                    records.clear();
                    for (const [id, record] of previousRecords) records.set(id, record);
                }
                throw error;
            }
        } });
    return { repository, state, records, calls };
}

test('acquireInstall atomically counts a uniquely owned running install admission', async () => {
    const f = fixture();
    const first = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    const second = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    assert.notEqual(first, second);
    assert.deepEqual(f.calls, ['gate', 'record', 'gate', 'record']);
    assert.equal(f.state.remoteAdmissionCount, 2);
    assert.deepEqual([...f.records.values()], [first, second].map(_id => ({
        _id, nodeId: 'relay-1', kind: 'install', phase: 'running', ownerGeneration: 1,
    })));
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

test('acquireInstall rejects split connections and missing session capability before mutating', async () => {
    for (const options of [{ splitConnection: true }, { sessionUnavailable: true }]) {
        const f = fixture(options);
        await assert.rejects(f.repository.acquireInstall({ nodeId: 'relay-1' }),
            /both models on one transactional Mongo connection/);
        assert.deepEqual(f.calls, []);
        assert.equal(f.state.remoteAdmissionCount, 0);
        assert.equal(f.records.size, 0);
    }
});

test('acquireInstall cannot proceed with a nontransactional session', async () => {
    const db = { startSession: async () => ({ endSession: async () => {} }) };
    let updates = 0;
    const repository = new RemoteAdmissionRepository({
        CascadeTopologyState: { db, updateOne: async () => { updates += 1; return { matchedCount: 1 }; } },
        RemoteAdmission: { db, create: async () => { throw new Error('unexpected create'); },
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

test('install release decrements only its own running record once', async () => {
    const f = fixture();
    const first = await f.repository.acquireInstall({ nodeId: 'relay-1' });
    const second = await f.repository.acquireInstall({ nodeId: 'relay-1' });
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
