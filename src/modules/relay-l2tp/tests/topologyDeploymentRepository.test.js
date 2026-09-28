'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TopologyDeploymentRepository,
} = require('../repositories/topologyDeploymentRepository');

function queryResult(value, trace) {
    const query = {
        select(paths) {
            trace.push({ method: 'select', paths });
            return query;
        },
        session(session) {
            trace.push({ method: 'session', session });
            return query;
        },
        lean() {
            trace.push({ method: 'lean' });
            return Promise.resolve(value);
        },
    };
    return query;
}

test('pins and prepares one revision snapshot behind an atomic revision CAS fence', async () => {
    const trace = [];
    const session = { id: 'deployment-snapshot-session' };
    const snapshot = {
        revision: 7,
        deployedRevision: 5,
        nodes: [{ _id: 'node-1' }],
        links: [],
        groups: [],
    };
    const snapshotReader = {
        async readDraft(candidateSession) {
            trace.push({ method: 'readDraft', session: candidateSession });
            return snapshot;
        },
    };
    const state = { _id: 'singleton', revision: 7, deployedRevision: 5 };
    const CascadeTopologyState = {
        findOneAndUpdate(filter, update, options) {
            trace.push({ method: 'pin.cas', filter, update, options });
            const matches = filter._id === state._id && filter.revision === state.revision
                && (filter.replacementReservation?.$exists !== false
                    || state.replacementReservation === undefined);
            return queryResult(matches ? state : null, trace);
        },
    };
    const transactionRunner = async work => {
        trace.push({ method: 'transaction.begin' });
        const result = await work(session);
        trace.push({ method: 'transaction.commit' });
        return result;
    };
    const repository = new TopologyDeploymentRepository({
        snapshotReader,
        CascadeTopologyState,
        transactionRunner,
    });

    const result = await repository.pinTopology({
        expectedRevision: 7,
        async prepare(candidate) {
            trace.push({ method: 'prepare' });
            assert.strictEqual(candidate, snapshot);
            return { compiled: { valid: true } };
        },
    });

    assert.deepEqual(result, {
        revision: 7,
        deployedRevision: 5,
        compiled: { valid: true },
    });
    assert.deepEqual(trace.map(entry => entry.method), [
        'transaction.begin',
        'readDraft',
        'prepare',
        'pin.cas',
        'select',
        'session',
        'lean',
        'transaction.commit',
    ]);
    const cas = trace.find(entry => entry.method === 'pin.cas');
    assert.deepEqual(cas.filter, {
        _id: 'singleton',
        revision: 7,
        replacementReservation: { $exists: false },
    });
    assert.deepEqual(cas.update, { $set: { revision: 7 } });
    assert.deepEqual(cas.options, {
        new: true,
        runValidators: true,
        session,
        timestamps: false,
        upsert: false,
    });
});

test('held replacement reservation rejects pin before prepare or singleton CAS', async () => {
    const trace = [];
    const session = { id: 'reserved-pin' };
    const repository = new TopologyDeploymentRepository({
        snapshotReader: { async readDraft(candidateSession) {
            assert.strictEqual(candidateSession, session);
            trace.push('readDraft');
            return { revision: 7, replacementReservation: { ownerToken: 'private-token' } };
        } },
        CascadeTopologyState: { findOneAndUpdate() { trace.push('pin.cas'); throw new Error('must not pin'); } },
        transactionRunner: async work => work(session),
    });

    await assert.rejects(repository.pinTopology({
        expectedRevision: 7,
        prepare: async () => { trace.push('prepare'); },
    }), error => {
        assert.equal(error.name, 'TopologyDeploymentRepositoryError');
        assert.equal(error.code, 'TOPOLOGY_REPLACEMENT_RESERVED');
        assert.doesNotMatch(JSON.stringify(error), /private-token/);
        return true;
    });
    assert.deepEqual(trace, ['readDraft']);
});

test('marks exactly the pinned revision deployed with a revision and prior-state CAS fence', async () => {
    const trace = [];
    const CascadeTopologyState = {
        findOneAndUpdate(filter, update, options) {
            trace.push({ method: 'deployed.cas', filter, update, options });
            return queryResult({ revision: 7, deployedRevision: 7 }, trace);
        },
    };
    const repository = new TopologyDeploymentRepository({
        snapshotReader: { async readDraft() {} },
        CascadeTopologyState,
        transactionRunner: async work => work({ id: 'unused' }),
    });

    const result = await repository.markDeployed({
        expectedRevision: 7,
        expectedDeployedRevision: 5,
    });

    assert.deepEqual(result, { revision: 7, deployedRevision: 7 });
    const cas = trace.find(entry => entry.method === 'deployed.cas');
    assert.deepEqual(cas.filter, {
        _id: 'singleton',
        revision: 7,
        deployedRevision: 5,
    });
    assert.deepEqual(cas.update, { $set: { deployedRevision: 7 } });
    assert.deepEqual(cas.options, {
        new: true,
        runValidators: true,
        timestamps: false,
    });
    assert.equal(Object.hasOwn(cas.update.$set, 'revision'), false);
});
