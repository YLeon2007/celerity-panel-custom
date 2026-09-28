'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { maintainAutoL2tpPaths } = require('../services/autoL2tpPathMaintenance');

// A transactional model double: writes remain private until commit; a CAS
// mismatch throws away the staged group update. Every database operation must
// carry the same session, so a non-transactional implementation cannot pass.
function fixture({ reservation, beforeCas, existingPath = [] } = {}) {
    const group = { _id: 'group-a', paths: [
        { pathKey: 'foreign', linkIds: ['foreign-link'], priority: 7, enabled: true },
        { pathKey: 'main', linkIds: existingPath, priority: 1, enabled: true },
    ] };
    const state = { _id: 'singleton', revision: 7, ...(reservation ? { replacementReservation: reservation } : {}) };
    const session = {};
    let stagedPaths;
    let casCount = 0;
    let groupWrites = 0;
    const query = value => ({
        session(received) { assert.equal(received, session); return this; },
        select() { return this; },
        async lean() { return value; },
    });
    const models = {
        transactionRunner: async work => {
            stagedPaths = undefined;
            const result = await work(session);
            if (stagedPaths) group.paths = stagedPaths;
            return result;
        },
        RelayL2tpState: { find: () => query([{ node: 'relay-1', routeGroup: 'group-a', desiredState: 'installed' }]) },
        CascadeLink: { find: () => query([{ _id: 'new-link', portalNode: 'relay-1', bridgeNode: 'bridge-1', active: true, status: 'deployed' }]) },
        HyNode: { find: () => query([
            { _id: 'relay-1', cascadeRole: 'relay' },
            { _id: 'bridge-1', cascadeRole: 'bridge' },
        ]) },
        CascadeRouteGroup: {
            findById: () => query({ ...group, paths: stagedPaths || group.paths }),
            updateOne: async (filter, update, options) => {
                assert.equal(options.session, session);
                assert.equal(options.runValidators, true);
                assert.equal(filter._id, 'group-a');
                groupWrites += 1;
                stagedPaths = update.$set.paths;
                return { matchedCount: 1 };
            },
        },
        CascadeTopologyState: {
            findById: () => query({ ...state }),
            findOneAndUpdate: (filter, update, options) => {
                assert.equal(options.session, session);
                casCount += 1;
                beforeCas?.(state);
                assert.deepEqual(filter, {
                    _id: 'singleton', revision: 7,
                    replacementReservation: { $exists: false },
                });
                if (state.revision !== filter.revision || state.replacementReservation !== undefined) {
                    return query(null);
                }
                state.revision += update.$inc.revision;
                return query({ ...state });
            },
        },
    };
    return { models, group, state, get casCount() { return casCount; }, get groupWrites() { return groupWrites; } };
}

test('held replacement reservation prevents maintenance group path and revision writes', async () => {
    const f = fixture({ reservation: { ownerToken: 'replacement', epoch: 1 }, existingPath: ['old-link'] });
    await assert.rejects(maintainAutoL2tpPaths(f.models), { code: 'TOPOLOGY_REPLACEMENT_RESERVED' });
    assert.equal(f.groupWrites, 0);
    assert.equal(f.casCount, 0);
    assert.deepEqual(f.group.paths.map(path => path.linkIds), [['foreign-link'], ['old-link']]);
    assert.equal(f.state.revision, 7);
});

test('reservation racing after snapshot makes CAS fail and rolls back group path', async () => {
    const f = fixture({ beforeCas: state => { state.replacementReservation = { ownerToken: 'racer', epoch: 2 }; } });
    await assert.rejects(maintainAutoL2tpPaths(f.models), { code: 'TOPOLOGY_MAINTENANCE_CONFLICT' });
    assert.equal(f.groupWrites, 1, 'group path was staged before the failed CAS');
    assert.equal(f.casCount, 1);
    assert.deepEqual(f.group.paths.map(path => path.linkIds), [['foreign-link'], []]);
    assert.equal(f.state.revision, 7);
});

test('a concurrent topology revision change rolls back the staged maintenance path', async () => {
    const f = fixture({ beforeCas: state => { state.revision += 1; } });
    await assert.rejects(maintainAutoL2tpPaths(f.models), { code: 'TOPOLOGY_MAINTENANCE_CONFLICT' });
    assert.equal(f.groupWrites, 1);
    assert.deepEqual(f.group.paths.map(path => path.linkIds), [['foreign-link'], []]);
    assert.equal(f.state.revision, 8, 'only the external revision change survives');
});

test('missing transactional connection fails closed before any maintenance read or write', async () => {
    const f = fixture();
    delete f.models.transactionRunner;
    await assert.rejects(maintainAutoL2tpPaths(f.models), /requires models on one transactional Mongo connection/);
    assert.equal(f.groupWrites, 0);
    assert.equal(f.casCount, 0);
});

test('successful maintenance commits only owned path and one revision, then no-ops', async () => {
    const f = fixture();
    const result = await maintainAutoL2tpPaths(f.models);
    assert.deepEqual(result, { updated: 1, deferred: [], revision: 8 });
    assert.deepEqual(f.group.paths.map(path => path.linkIds), [['foreign-link'], ['new-link']]);
    assert.equal(f.state.revision, 8);
    const again = await maintainAutoL2tpPaths(f.models);
    assert.deepEqual(again, { updated: 0, deferred: [], revision: null });
    assert.equal(f.casCount, 1);
});
