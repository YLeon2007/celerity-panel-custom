'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');

function harness({ count = 0, reservation, casFails = false, insertFails = false } = {}) {
    const calls = [];
    const session = { inTransaction: () => true };
    const state = { revision: 7, deployedRevision: 5,
        ...(count === null ? {} : { topologyAdmissionCount: count }),
        ...(reservation ? { replacementReservation: reservation } : {}) };
    const operations = [];
    const repository = new TopologyDeploymentRepository({
        snapshotReader: { async readDraft(candidate) {
            assert.strictEqual(candidate, session);
            calls.push('read');
            return { ...state, nodes: [], links: [], groups: [] };
        } },
        CascadeTopologyState: { findOneAndUpdate(filter, update, options) {
            calls.push('cas');
            assert.strictEqual(options.session, session);
            assert.equal(options.upsert, false);
            assert.equal(filter._id, 'singleton');
            assert.equal(filter.revision, 7);
            assert.deepEqual(filter.replacementReservation, { $exists: false });
            assert.equal(filter.topologyAdmissionCount, 0);
            assert.deepEqual(update.$inc, { topologyAdmissionCount: 1 });
            const query = { select() { return this; }, session(value) {
                assert.strictEqual(value, session); return this;
            }, async lean() {
                if (casFails || state.replacementReservation || state.topologyAdmissionCount !== 0) return null;
                state.topologyAdmissionCount += 1;
                return { ...state };
            } };
            return query;
        } },
        transactionRunner: async work => {
            calls.push('begin');
            const prior = state.topologyAdmissionCount;
            try {
                const result = await work(session);
                calls.push('commit');
                return result;
            } catch (error) {
                state.topologyAdmissionCount = prior;
                operations.length = 0;
                calls.push('abort');
                throw error;
            }
        },
    });
    const admit = async (pinned, candidate) => {
        assert.strictEqual(candidate, session);
        calls.push('insert');
        if (insertFails) throw new Error('private database detail');
        operations.push({ id: 'operation-1', revision: pinned.revision });
    };
    return { repository, calls, state, operations, session, admit };
}

test('atomic topology admission commits a real counted singleton write and frozen insert in one session', async () => {
    const h = harness();
    const result = await h.repository.admitTopology({ expectedRevision: 7,
        prepare: async (snapshot, session) => {
            assert.strictEqual(session, h.session);
            h.calls.push('prepare');
            return { prepared: true };
        }, admit: h.admit });
    assert.deepEqual(h.calls, ['begin', 'read', 'prepare', 'cas', 'insert', 'commit']);
    assert.deepEqual(h.operations, [{ id: 'operation-1', revision: 7 }]);
    assert.equal(h.state.topologyAdmissionCount, 1);
    assert.equal(result.prepared, true);
});

test('missing legacy counter rejects admission without creating an operation', async () => {
    const h = harness({ count: null });
    await assert.rejects(h.repository.admitTopology({ expectedRevision: 7,
        prepare: async () => { h.calls.push('prepare'); return {}; }, admit: h.admit,
    }), error => error.code === 'TOPOLOGY_ADMISSION_UNAVAILABLE');
    assert.deepEqual(h.calls, ['begin', 'read', 'prepare', 'cas', 'abort']);
    assert.deepEqual(h.operations, []);
});

test('reservation held before read rejects without materialization or insert', async () => {
    const h = harness({ reservation: { ownerToken: 'private-token' } });
    await assert.rejects(h.repository.admitTopology({ expectedRevision: 7,
        prepare: async () => { h.calls.push('prepare'); return {}; }, admit: h.admit,
    }), error => error.code === 'TOPOLOGY_REPLACEMENT_RESERVED'
        && !JSON.stringify(error).includes('private-token'));
    assert.deepEqual(h.calls, ['begin', 'read', 'abort']);
});

test('reservation wins singleton CAS after read and cannot insert', async () => {
    const h = harness({ casFails: true });
    await assert.rejects(h.repository.admitTopology({ expectedRevision: 7,
        prepare: async () => { h.calls.push('prepare'); return {}; }, admit: h.admit,
    }), error => error.code === 'TOPOLOGY_ADMISSION_UNAVAILABLE');
    assert.deepEqual(h.calls, ['begin', 'read', 'prepare', 'cas', 'abort']);
    assert.deepEqual(h.operations, []);
});

test('frozen insert failure rolls back the admission count and never commits', async () => {
    const h = harness({ insertFails: true });
    await assert.rejects(h.repository.admitTopology({ expectedRevision: 7,
        prepare: async () => ({ prepared: true }), admit: h.admit,
    }), /private database detail/);
    assert.deepEqual(h.calls, ['begin', 'read', 'cas', 'insert', 'abort']);
    assert.equal(h.state.topologyAdmissionCount, 0);
    assert.deepEqual(h.operations, []);
});

test('missing active transaction rejects before reading, incrementing or inserting', async () => {
    const h = harness();
    h.session.inTransaction = () => false;
    await assert.rejects(h.repository.admitTopology({ expectedRevision: 7,
        prepare: async () => { h.calls.push('prepare'); return {}; }, admit: h.admit,
    }), /active Mongo transaction/);
    assert.deepEqual(h.calls, ['begin', 'abort']);
    assert.equal(h.state.topologyAdmissionCount, 0);
    assert.deepEqual(h.operations, []);
});

test('different model connections reject before a transaction or singleton write', async () => {
    const h = harness();
    h.repository.CascadeTopologyState.db = {};
    h.repository.TopologyOperation = { db: {} };
    await assert.rejects(h.repository.admitTopology({ expectedRevision: 7,
        prepare: async () => ({}), admit: h.admit,
    }), /one transactional connection/);
    assert.deepEqual(h.calls, []);
});
