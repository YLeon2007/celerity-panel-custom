'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { L2tpSimpleService } = require('../services/l2tpSimpleService');

function fixture({ reservation, beforeCas, groups = [], relayStates = [], links = [], noConnection = false, createRace = false } = {}) {
    const session = {};
    const topology = { revision: 7, topologyAdmissionCount: 0, ...(reservation ? { replacementReservation: reservation } : {}) };
    const stored = structuredClone(groups);
    let staged = structuredClone(groups);
    const calls = { writes: 0, cas: 0, remote: 0, sessions: 0 };
    const db = noConnection ? undefined : {
        transaction: async work => {
            staged = structuredClone(stored);
            const result = await work(session);
            stored.splice(0, stored.length, ...staged);
            return result;
        },
    };
    const query = value => ({
        session(received) { assert.equal(received, session); calls.sessions++; return this; },
        sort() { return this; },
        select() { return this; },
        lean: async () => value(),
    });
    const models = {
        HyNode: {
            find: () => query(() => [{ _id: 'relay-1', cascadeRole: 'relay' }, { _id: 'bridge-1', cascadeRole: 'bridge' }]),
            findById: () => query(() => ({ _id: 'relay-1', cascadeRole: 'relay' })),
        },
        CascadeLink: { find: () => query(() => links) },
        CascadeRouteGroup: {
            find: () => query(() => structuredClone(staged)),
            findById: id => query(() => structuredClone(staged.find(g => g._id === id) ?? null)),
            create: async (documents, options) => {
                assert.equal(options.session, session);
                calls.writes++;
                if (createRace) throw Object.assign(new Error('duplicate group'), { code: 11000 });
                const group = { _id: 'new-group', ...documents[0] };
                staged.push(group);
                return [group];
            },
            updateOne: async (filter, update, options) => {
                assert.equal(options.session, session);
                assert.equal(options.runValidators, true);
                calls.writes++;
                const group = staged.find(g => g._id === filter._id);
                if (group) group.paths = update.$set.paths;
                return { matchedCount: group ? 1 : 0 };
            },
        },
        RelayL2tpState: {
            find: () => query(() => relayStates),
            findOne: filter => query(() => relayStates.find(state => state.node === filter.node) ?? null),
        },
        CascadeTopologyState: {
            findById: () => query(() => ({ ...topology })),
            findOneAndUpdate: (filter, update, options) => {
                assert.equal(options.session, session);
                assert.equal(options.runValidators, true);
                assert.deepEqual(filter, { _id: 'singleton', revision: 7, topologyAdmissionCount: 0, replacementReservation: { $exists: false } });
                calls.cas++;
                beforeCas?.(topology);
                if (topology.revision !== filter.revision || topology.replacementReservation) return query(() => null);
                topology.revision += update.$inc.revision;
                return query(() => ({ ...topology }));
            },
        },
        L2tpUser: { find: () => query(() => []) },
    };
    for (const model of Object.values(models)) model.db = db;
    const service = new L2tpSimpleService({
        ...models,
        l2tpService: { install: async () => { calls.remote++; return {}; }, getOperation: async () => ({}) },
        stateManagementService: { configureRelay: async () => { calls.remote++; }, revealPsk: async () => ({}) },
        userManagementService: { createUser: async () => {}, deleteUser: async () => {}, importUser: async () => { calls.remote++; } },
        stateRepository: { getTopologyRevision: async () => 7 },
        nodeSSHFactory: () => ({}),
        allowRemoteExecution: true,
    });
    return { service, stored, topology, calls, session };
}
const chain = [{ _id: 'link-1', portalNode: 'relay-1', bridgeNode: 'bridge-1' }];

test('held reservation blocks even a no-op pinned install before remote work', async () => {
    const f = fixture({ reservation: { ownerToken: 'other', epoch: 1 }, groups: [{ _id: 'g', name: 'g', paths: [{ pathKey: 'main', linkIds: ['link-1'] }] }], relayStates: [{ node: 'relay-1', routeGroup: 'g', desiredState: 'installed' }], links: chain });
    await assert.rejects(f.service.installRelay('relay-1'), { code: 'TOPOLOGY_REPLACEMENT_RESERVED' });
    assert.deepEqual(f.calls, { writes: 0, cas: 0, remote: 0, sessions: f.calls.sessions });
    assert.ok(f.calls.sessions > 0);
});

test('reservation after path snapshot rolls back staged path and skips revision', async () => {
    const f = fixture({ groups: [{ _id: 'g', name: 'g', paths: [] }], links: chain,
        beforeCas: state => { state.replacementReservation = { ownerToken: 'racer', epoch: 2 }; } });
    await assert.rejects(f.service.ensureRelayGroupPath('relay-1', 'g'), { code: 'SIMPLE_TOPOLOGY_CONFLICT' });
    assert.equal(f.calls.writes, 1);
    assert.equal(f.calls.cas, 1);
    assert.deepEqual(f.stored[0].paths, []);
    assert.equal(f.topology.revision, 7);
});

test('competing revision rolls back staged group creation', async () => {
    const f = fixture({ links: chain, beforeCas: state => { state.revision++; } });
    await assert.rejects(f.service.ensureRouteGroup('relay-1'), { code: 'SIMPLE_TOPOLOGY_CONFLICT' });
    assert.equal(f.calls.writes, 1);
    assert.equal(f.stored.length, 0);
});

test('duplicate group-create race aborts with no revision or leaked group', async () => {
    const f = fixture({ links: chain, createRace: true });
    await assert.rejects(f.service.ensureRouteGroup('relay-1'), { code: 'SIMPLE_TOPOLOGY_CONFLICT' });
    assert.equal(f.calls.cas, 0);
    assert.equal(f.stored.length, 0);
});

test('installed relay cannot publish missing owned path in shared foreign group without prepared ingress', async () => {
    const foreign = { pathKey: 'foreign', linkIds: ['foreign-link'], priority: 7, enabled: true };
    const f = fixture({ groups: [{ _id: 'g', name: 'g', paths: [foreign] }], links: chain,
        relayStates: [{ node: 'relay-1', routeGroup: 'g', status: 'installed' }] });
    await assert.rejects(f.service.ensureRelayGroupPath('relay-1', 'g'), { code: 'PREPARED_INGRESS_REQUIRED' });
    assert.deepEqual(f.stored[0].paths, [foreign]);
    assert.equal(f.calls.writes, 0);
    assert.equal(f.calls.cas, 0);
});

test('installed relay cannot auto-create a replacement group after losing its pinned group', async () => {
    const f = fixture({ links: chain, relayStates: [{ node: 'relay-1', routeGroup: 'deleted-group', status: 'installed' }] });
    await assert.rejects(f.service.ensureRouteGroup('relay-1'), { code: 'PREPARED_INGRESS_REQUIRED' });
    assert.equal(f.calls.writes, 0);
    assert.equal(f.calls.cas, 0);
});

test('installed relay cannot append to a new group when state still points at another group', async () => {
    const f = fixture({ links: chain, groups: [{ _id: 'g', name: 'g', paths: [] }],
        relayStates: [{ node: 'relay-1', routeGroup: 'old-group', status: 'installed' }] });
    await assert.rejects(f.service.ensureRelayGroupPath('relay-1', 'g'), { code: 'PREPARED_INGRESS_REQUIRED' });
    assert.equal(f.calls.writes, 0);
    assert.equal(f.calls.cas, 0);
});

test('installed nonempty path cannot switch to another deployed chain without prepared ingress', async () => {
    const old = { pathKey: 'main', linkIds: ['old-link'], priority: 1, enabled: true };
    const f = fixture({ groups: [{ _id: 'g', name: 'g', paths: [old] }], links: chain,
        relayStates: [{ node: 'relay-1', routeGroup: 'g', status: 'installed' }] });
    await assert.rejects(f.service.ensureRelayGroupPath('relay-1', 'g'), { code: 'PREPARED_INGRESS_REQUIRED' });
    assert.deepEqual(f.stored[0].paths, [old]);
    assert.equal(f.calls.writes, 0);
    assert.equal(f.calls.cas, 0);
});

test('installed relay cannot fill legacy empty path via refresh', async () => {
    const f = fixture({ groups: [{ _id: 'g', name: 'g', paths: [] }], links: chain,
        relayStates: [{ node: 'relay-1', routeGroup: 'g', desiredState: 'installed' }] });
    await assert.rejects(f.service.refreshEmptyRouteGroup('relay-1', 'g'), { code: 'PREPARED_INGRESS_REQUIRED' });
    assert.equal(f.calls.writes, 0);
});

test('fresh path append preserves foreign paths and increments once with shared session', async () => {
    const foreign = { pathKey: 'foreign', linkIds: ['foreign-link'], priority: 7, enabled: true };
    const f = fixture({ groups: [{ _id: 'g', name: 'g', paths: [foreign] }], links: chain });
    await f.service.ensureRelayGroupPath('relay-1', 'g');
    assert.deepEqual(f.stored[0].paths[0], foreign);
    assert.deepEqual(f.stored[0].paths[1].linkIds, ['link-1']);
    assert.equal(f.calls.writes, 1);
    assert.equal(f.calls.cas, 1);
    assert.equal(f.topology.revision, 8);
    assert.ok(f.calls.sessions >= 5);
});

test('shared downstream foreign path is not discarded to add an upstream path', async () => {
    const foreign = { pathKey: 'foreign', linkIds: ['downstream'], priority: 1, enabled: true };
    const f = fixture({ groups: [{ _id: 'g', name: 'g', paths: [foreign] }],
        links: [{ _id: 'link-1', portalNode: 'relay-1', bridgeNode: 'relay-2' },
            { _id: 'downstream', portalNode: 'relay-2', bridgeNode: 'bridge-1' }] });
    await assert.rejects(f.service.ensureRelayGroupPath('relay-1', 'g'), { code: 'SHARED_ROUTE_GROUP_PATH' });
    assert.deepEqual(f.stored[0].paths, [foreign]);
    assert.equal(f.calls.writes, 0);
    assert.equal(f.calls.cas, 0);
});

test('no-op path performs zero group writes and zero revision CAS', async () => {
    const f = fixture({ groups: [{ _id: 'g', name: 'g', paths: [{ pathKey: 'main', linkIds: ['link-1'] }] }], links: chain });
    await f.service.ensureRelayGroupPath('relay-1', 'g');
    assert.equal(f.calls.writes, 0);
    assert.equal(f.calls.cas, 0);
});

test('intent ingress preparation joins the callers active transaction instead of opening a nested commit', async () => {
    const f = fixture(); f.session.inTransaction = () => true;
    f.service.CascadeTopologyState.db.transaction = async () => { throw Error('nested transaction would commit ingress outside the intent binding'); };
    const value = await f.service.withPathWriter(async ({ session, revision }) => {
        assert.strictEqual(session, f.session); return revision;
    }, 7, f.session);
    assert.equal(value, 7);
});

test('missing transactional connection fails closed before group mutation', async () => {
    const f = fixture({ noConnection: true, groups: [{ _id: 'g', name: 'g', paths: [] }], links: chain });
    await assert.rejects(f.service.ensureRelayGroupPath('relay-1', 'g'), /transactional Mongo connection/);
    assert.equal(f.calls.writes, 0);
});
