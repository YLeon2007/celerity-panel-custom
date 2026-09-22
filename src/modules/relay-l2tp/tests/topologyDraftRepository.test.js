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
    });
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
        filter: { _id: 'singleton', revision: 7 },
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
