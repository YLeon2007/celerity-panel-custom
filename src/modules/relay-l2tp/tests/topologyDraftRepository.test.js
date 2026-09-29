'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TopologyDraftRepository,
} = require('../repositories/topologyDraftRepository');

function queryResult(value, trace, label) {
    const query = {
        select(paths) {
            trace.push({ label: `${label}.select`, paths });
            return query;
        },
        session(session) {
            trace.push({ label: `${label}.session`, session });
            return query;
        },
        lean() {
            trace.push({ label: `${label}.lean` });
            return Promise.resolve(value);
        },
    };
    return query;
}

function createModels(trace, session) {
    const connection = {};
    return {
        HyNode: {
            db: connection,
            find(filter) {
                trace.push({ label: 'nodes.find', filter });
                return queryResult([
                    { _id: 'portal-1', cascadeRole: 'portal' },
                    { _id: 'bridge-1', cascadeRole: 'bridge' },
                ], trace, 'nodes');
            },
        },
        CascadeLink: {
            db: connection,
            find(filter) {
                trace.push({ label: 'links.find', filter });
                return queryResult([], trace, 'links');
            },
            async create(documents, options) {
                trace.push({ label: 'links.create', documents, options });
                return documents;
            },
            async updateOne(filter, update, options) {
                trace.push({ label: 'links.updateOne', filter, update, options });
                return { matchedCount: 1 };
            },
            async deleteOne(filter, options) {
                trace.push({ label: 'links.deleteOne', filter, options });
                return { deletedCount: 1 };
            },
        },
        CascadeRouteGroup: {
            db: connection,
            find(filter) {
                trace.push({ label: 'groups.find', filter });
                return queryResult([], trace, 'groups');
            },
            async create(documents, options) {
                trace.push({ label: 'groups.create', documents, options });
                return documents;
            },
            async updateOne(filter, update, options) {
                trace.push({ label: 'groups.updateOne', filter, update, options });
                return { matchedCount: 1 };
            },
            async deleteOne(filter, options) {
                trace.push({ label: 'groups.deleteOne', filter, options });
                return { deletedCount: 1 };
            },
        },
        RelayL2tpState: {
            db: connection,
            find(filter) {
                trace.push({ label: 'states.find', filter });
                return queryResult([], trace, 'states');
            },
        },
        CascadeTopologyState: {
            db: connection,
            findById(id) {
                trace.push({ label: 'topology.findById', id });
                return queryResult({ revision: 7, deployedRevision: 5 }, trace, 'topology');
            },
            findOneAndUpdate(filter, update, options) {
                trace.push({ label: 'topology.cas', filter, update, options });
                return queryResult({ revision: 8, deployedRevision: 5 }, trace, 'topology.cas');
            },
        },
        transactionRunner: async work => {
            trace.push({ label: 'transaction.begin', session });
            const result = await work(session);
            trace.push({ label: 'transaction.commit', session });
            return result;
        },
    };
}

test('reads the transactional topology snapshot without parallel session operations', async () => {
    const trace = [];
    const session = { id: 'exclusive-session' };
    const models = createModels(trace, session);
    let activeQueries = 0;
    function exclusiveQuery(value, label) {
        const query = {
            select() { return query; },
            session(candidateSession) {
                assert.strictEqual(candidateSession, session);
                return query;
            },
            async lean() {
                assert.equal(activeQueries, 0, `${label} overlapped another session operation`);
                activeQueries += 1;
                await new Promise(resolve => setImmediate(resolve));
                activeQueries -= 1;
                return value;
            },
        };
        return query;
    }
    models.HyNode.find = () => exclusiveQuery([], 'nodes');
    models.CascadeLink.find = () => exclusiveQuery([], 'links');
    models.CascadeRouteGroup.find = () => exclusiveQuery([], 'groups');
    models.RelayL2tpState.find = () => exclusiveQuery([], 'states');
    models.CascadeTopologyState.findById = () => exclusiveQuery({
        revision: 7,
        deployedRevision: 5,
    }, 'topology');
    const repository = new TopologyDraftRepository(models);

    assert.deepEqual(await repository.readDraft(session), {
        revision: 7,
        deployedRevision: 5,
        nodes: [],
        links: [],
        groups: [],
        activeRouteGroupIds: [],
        installedRouteGroupIds: [],
        installedRouteOwners: [],
    });
});

test('draft snapshot distinguishes installed L2TP groups from queued desired groups', async () => {
    const trace = [];
    const models = createModels(trace, { id: 'read-session' });
    models.RelayL2tpState.find = () => queryResult([
        { routeGroup: 'installed-group', node: 'owner-relay', status: 'installed' },
        { routeGroup: 'queued-group', node: 'queued-relay', status: 'queued', desiredState: 'installed' },
    ], trace, 'states');
    const snapshot = await new TopologyDraftRepository(models).readDraft();
    assert.deepEqual(snapshot.activeRouteGroupIds, ['installed-group', 'queued-group']);
    assert.deepEqual(snapshot.installedRouteGroupIds, ['installed-group']);
    assert.deepEqual(snapshot.installedRouteOwners,
        [{ groupId: 'installed-group', nodeId: 'owner-relay' }]);
    assert(trace.find(entry => entry.label === 'states.select')
        .paths.split(/\s+/).includes('node'));
    assert(trace.find(entry => entry.label === 'states.select')
        .paths.split(/\s+/).includes('status'));
});

test('pinned link snapshot selects status for scoped pending-link guard', async () => {
    const trace = [];
    const session = { id: 'link-status-session' };
    const repository = new TopologyDraftRepository(createModels(trace, session));
    await repository.readDraft(session);
    const projection = trace.find(entry => entry.label === 'links.select');
    assert.ok(projection.paths.split(/\s+/).includes('status'));
});

test('projects path enablement into topology draft snapshots', async () => {
    const trace = [];
    const session = { id: 'projection-session' };
    const repository = new TopologyDraftRepository(createModels(trace, session));

    await repository.readDraft(session);

    const groupProjection = trace.find(entry => entry.label === 'groups.select');
    assert.ok(groupProjection.paths.split(/\s+/).includes('paths.enabled'));
});

test('persists link and route-group updates and deletes with validators in one session', async () => {
    const trace = [];
    const session = { id: 'mutation-session' };
    const repository = new TopologyDraftRepository(createModels(trace, session));

    await repository.persistMutation({
        kind: 'link.update',
        id: 'link-1',
        changes: { name: 'updated link' },
    }, session);
    await repository.persistMutation({ kind: 'link.delete', id: 'link-2' }, session);
    await repository.persistMutation({
        kind: 'group.update',
        id: 'group-1',
        changes: { name: 'updated group' },
    }, session);
    await repository.persistMutation({ kind: 'group.delete', id: 'group-2' }, session);

    assert.deepEqual(trace.filter(entry => entry.label.endsWith('updateOne')), [
        {
            label: 'links.updateOne',
            filter: { _id: 'link-1' },
            update: { $set: { name: 'updated link' } },
            options: { runValidators: true, session },
        },
        {
            label: 'groups.updateOne',
            filter: { _id: 'group-1' },
            update: { $set: { name: 'updated group' } },
            options: { runValidators: true, session },
        },
    ]);
    assert.deepEqual(trace.filter(entry => entry.label.endsWith('deleteOne')), [
        {
            label: 'links.deleteOne',
            filter: { _id: 'link-2' },
            options: { session },
        },
        {
            label: 'groups.deleteOne',
            filter: { _id: 'group-2' },
            options: { session },
        },
    ]);
});

test('maps a concurrent initial singleton CAS collision to a stale revision error', async () => {
    const trace = [];
    const session = { id: 'initial-topology-transaction' };
    const models = createModels(trace, session);
    models.CascadeTopologyState.findById = id => {
        trace.push({ label: 'topology.findById', id });
        return queryResult(null, trace, 'topology');
    };
    models.CascadeTopologyState.findOneAndUpdate = (filter, update, options) => {
        trace.push({ label: 'topology.cas', filter, update, options });
        const query = queryResult(null, trace, 'topology.cas');
        query.lean = async () => {
            const error = new Error('duplicate singleton');
            error.code = 11000;
            throw error;
        };
        return query;
    };
    const repository = new TopologyDraftRepository(models);

    await assert.rejects(
        repository.commitDraft({
            expectedRevision: 0,
            prepare: async () => ({
                mutation: {
                    kind: 'link.create',
                    document: {
                        _id: 'link-1',
                        portalNode: 'portal-1',
                        bridgeNode: 'bridge-1',
                        mode: 'forward',
                        active: true,
                    },
                },
            }),
        }),
        error => {
            assert.equal(error.name, 'TopologyDraftRepositoryError');
            assert.equal(error.code, 'STALE_TOPOLOGY_REVISION');
            assert.equal(error.expectedTopologyRevision, 0);
            return true;
        },
    );
});

test('aborts before entity mutation or revision advance when draft preparation fails', async () => {
    const trace = [];
    const session = { id: 'validation-failure-transaction' };
    const repository = new TopologyDraftRepository(createModels(trace, session));
    const validationError = new Error('candidate validation failed');

    await assert.rejects(
        repository.commitDraft({
            expectedRevision: 7,
            prepare: async () => { throw validationError; },
        }),
        validationError,
    );

    assert.equal(trace.some(entry => [
        'links.create',
        'links.updateOne',
        'links.deleteOne',
        'groups.create',
        'groups.updateOne',
        'groups.deleteOne',
        'topology.cas',
    ].includes(entry.label)), false);
    assert.equal(trace.some(entry => entry.label === 'transaction.commit'), false);
});

test('rolls back entity mutation when the topology revision CAS fails', async () => {
    const trace = [];
    const session = { id: 'cas-failure-transaction' };
    const state = {
        links: [],
        revision: 7,
        deployedRevision: 5,
    };
    const models = createModels(trace, session);
    models.CascadeTopologyState.findById = id => {
        trace.push({ label: 'topology.findById', id });
        return queryResult({
            revision: state.revision,
            deployedRevision: state.deployedRevision,
        }, trace, 'topology');
    };
    models.CascadeLink.create = async (documents, options) => {
        trace.push({ label: 'links.create', documents, options });
        state.links.push(...documents);
        return documents;
    };
    models.CascadeTopologyState.findOneAndUpdate = (filter, update, options) => {
        trace.push({ label: 'topology.cas', filter, update, options });
        return queryResult(null, trace, 'topology.cas');
    };
    models.transactionRunner = async work => {
        const before = structuredClone(state);
        trace.push({ label: 'transaction.begin', session });
        try {
            const result = await work(session);
            trace.push({ label: 'transaction.commit', session });
            return result;
        } catch (error) {
            state.links = before.links;
            state.revision = before.revision;
            state.deployedRevision = before.deployedRevision;
            trace.push({ label: 'transaction.abort', session });
            throw error;
        }
    };
    const repository = new TopologyDraftRepository(models);

    await assert.rejects(
        repository.commitDraft({
            expectedRevision: 7,
            prepare: async () => ({
                mutation: {
                    kind: 'link.create',
                    document: { _id: 'link-1' },
                },
            }),
        }),
        error => {
            assert.equal(error.code, 'STALE_TOPOLOGY_REVISION');
            return true;
        },
    );

    assert.equal(trace.filter(entry => entry.label === 'links.create').length, 1);
    assert.equal(trace.filter(entry => entry.label === 'topology.cas').length, 1);
    assert.equal(trace.filter(entry => entry.label === 'transaction.abort').length, 1);
    assert.deepEqual(state, {
        links: [],
        revision: 7,
        deployedRevision: 5,
    });
});

test('persists a route-group draft in the same revision transaction', async () => {
    const trace = [];
    const session = { id: 'group-topology-transaction' };
    const models = createModels(trace, session);
    const repository = new TopologyDraftRepository(models);
    const routeGroup = {
        _id: 'group-1',
        name: 'primary',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{ pathKey: 'primary', linkIds: ['link-1'], priority: 1 }],
    };

    await repository.commitDraft({
        expectedRevision: 7,
        prepare: async () => ({
            mutation: { kind: 'group.create', document: routeGroup },
        }),
    });

    assert.deepEqual(trace.filter(entry => entry.label === 'groups.create'), [{
        label: 'groups.create',
        documents: [routeGroup],
        options: { session },
    }]);
    assert.equal(trace.filter(entry => entry.label === 'topology.cas').length, 1);
});

test('persists the draft and advances the singleton revision once in one transaction', async () => {
    const trace = [];
    const session = { id: 'topology-transaction' };
    const models = createModels(trace, session);
    const repository = new TopologyDraftRepository(models);
    const link = {
        _id: 'link-1',
        portalNode: 'portal-1',
        bridgeNode: 'bridge-1',
        mode: 'forward',
        active: true,
    };

    const result = await repository.commitDraft({
        expectedRevision: 7,
        async prepare(snapshot) {
            assert.equal(snapshot.revision, 7);
            assert.equal(snapshot.deployedRevision, 5);
            assert.deepEqual(snapshot.nodes.map(node => node._id), ['portal-1', 'bridge-1']);
            return { mutation: { kind: 'link.create', document: link } };
        },
    });

    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
    assert.deepEqual(trace.filter(entry => entry.label === 'links.create'), [{
        label: 'links.create',
        documents: [link],
        options: { session },
    }]);
    assert.deepEqual(trace.filter(entry => entry.label === 'topology.cas'), [{
        label: 'topology.cas',
        filter: { _id: 'singleton', revision: 7, replacementReservation: { $exists: false } },
        update: { $inc: { revision: 1 } },
        options: {
            new: true,
            runValidators: true,
            session,
            upsert: false,
        },
    }]);
    assert.equal(trace.filter(entry => entry.label === 'transaction.begin').length, 1);
    assert.equal(trace.filter(entry => entry.label === 'transaction.commit').length, 1);
});

test('held replacement reservation rejects link and group CRUD before mutation', async () => {
    for (const kind of [
        'link.create', 'link.update', 'link.delete',
        'group.create', 'group.update', 'group.delete',
    ]) {
        const trace = [];
        const session = { id: `${kind}-held` };
        const models = createModels(trace, session);
        models.CascadeTopologyState.findById = () => queryResult({
            revision: 7,
            deployedRevision: 5,
            replacementReservation: { ownerToken: 'worker-token', epoch: 4 },
        }, trace, 'topology');
        const repository = new TopologyDraftRepository(models);
        await assert.rejects(repository.commitDraft({
            expectedRevision: 7,
            prepare: async () => ({ mutation: { kind, document: { _id: kind } } }),
        }), error => {
            assert.equal(error.name, 'TopologyDraftRepositoryError');
            assert.equal(error.code, 'TOPOLOGY_REPLACEMENT_RESERVED');
            return true;
        });
        assert.equal(trace.some(entry => entry.label === 'transaction.commit'), false);
        assert.equal(trace.some(entry => [
            'links.create', 'links.updateOne', 'links.deleteOne',
            'groups.create', 'groups.updateOne', 'groups.deleteOne', 'topology.cas',
        ].includes(entry.label)), false);
    }
});

test('legacy singleton without reservation retains revision-zero upsert', async () => {
    const trace = [];
    const session = { id: 'legacy-zero' };
    const models = createModels(trace, session);
    models.CascadeTopologyState.findById = () => queryResult(null, trace, 'topology');
    models.CascadeTopologyState.findOneAndUpdate = (filter, update, options) => {
        trace.push({ label: 'topology.cas', filter, update, options });
        return queryResult({ revision: 1, deployedRevision: 0 }, trace, 'topology.cas');
    };
    const repository = new TopologyDraftRepository(models);
    assert.deepEqual(await repository.commitDraft({
        expectedRevision: 0,
        prepare: async () => ({ mutation: { kind: 'group.create', document: { _id: 'group-1' } } }),
    }), { revision: 1, deployedRevision: 0 });
    const cas = trace.find(entry => entry.label === 'topology.cas');
    assert.deepEqual(cas.filter, {
        _id: 'singleton', revision: 0, replacementReservation: { $exists: false },
    });
    assert.deepEqual(cas.update, { $inc: { revision: 1 }, $setOnInsert: { deployedRevision: 0 } });
    assert.equal(cas.options.upsert, true);
    assert.strictEqual(cas.options.session, session);
});

test('stale draft revision still rejects before link or group writes', async () => {
    const trace = [];
    const repository = new TopologyDraftRepository(createModels(trace, { id: 'stale' }));
    await assert.rejects(repository.commitDraft({
        expectedRevision: 6,
        prepare: async () => ({ mutation: { kind: 'link.create', document: { _id: 'link-1' } } }),
    }), error => {
        assert.equal(error.code, 'STALE_TOPOLOGY_REVISION');
        assert.equal(error.topologyRevision, 7);
        return true;
    });
    assert.equal(trace.some(entry => ['links.create', 'topology.cas', 'transaction.commit'].includes(entry.label)), false);
});

test('simulated second-transaction reservation after snapshot rejects link and group writes', async () => {
    for (const kind of ['link.create', 'group.create']) {
        const trace = [];
        const session = { id: `${kind}-race` };
        const models = createModels(trace, session);
        const state = { links: [], groups: [], revision: 7, deployedRevision: 5 };
        models.CascadeTopologyState.findById = () => queryResult({
            revision: state.revision, deployedRevision: state.deployedRevision,
        }, trace, 'topology');
        models.CascadeLink.create = async documents => { state.links.push(...documents); };
        models.CascadeRouteGroup.create = async documents => { state.groups.push(...documents); };
        models.CascadeTopologyState.findOneAndUpdate = (filter, update, options) => {
            trace.push({ label: 'topology.cas', filter, update, options });
            // Simulate the singleton predicate evaluated after another transaction
            // commits its reservation, with the original snapshot still at revision 7.
            if (filter.revision !== state.revision
                || (filter.replacementReservation?.$exists === false
                    && state.replacementReservation !== undefined)) {
                return queryResult(null, trace, 'topology.cas');
            }
            state.revision += update.$inc.revision;
            return queryResult({ revision: state.revision, deployedRevision: state.deployedRevision },
                trace, 'topology.cas');
        };
        models.transactionRunner = async work => {
            const before = structuredClone(state);
            try { return await work(session); } catch (error) {
                state.links = before.links;
                state.groups = before.groups;
                throw error;
            }
        };
        const repository = new TopologyDraftRepository(models);
        await assert.rejects(repository.commitDraft({
            expectedRevision: 7,
            async prepare() {
                // Another transaction owns the singleton without advancing topology revision.
                state.replacementReservation = { ownerToken: 'new-owner', epoch: 4 };
                return { mutation: { kind, document: { _id: kind } } };
            },
        }), error => error.code === 'STALE_TOPOLOGY_REVISION');
        assert.deepEqual(state.links, []);
        assert.deepEqual(state.groups, []);
        assert.deepEqual(state.replacementReservation, { ownerToken: 'new-owner', epoch: 4 });
        assert.equal(state.revision, 7);
        assert.equal(trace.filter(entry => entry.label === 'topology.cas').length, 1);
    }
});
