'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');
const { TopologyOperationFinalizer } = require('../services/topologyOperationFinalizer');

const NOW = new Date('2026-09-29T10:00:00Z');
const LEASE = new Date('2026-09-29T10:01:00Z');
const SESSION = Object.freeze({ transaction: true });
const INPUT = { operationId: 'op', owner: 'worker', leaseUntil: LEASE,
    topologyRevision: 7, priorDeployedRevision: 5 };
const SCOPE = { kind: 'link.attach', groupId: 'group', pathKey: 'main',
    ownerNodeId: 'r1', ownerTopologyRevision: 5, ownerCredentialRevision: 11,
    linkId: 'r2-bridge', linkIds: ['r2-bridge', 'p1-r1', 'r1-r2'],
    newPathLinkIds: ['r1-r2', 'r2-bridge'] };

function harness(changes = {}) {
    const state = {
        operation: { _id: 'op', status: 'committing', leaseOwner: 'worker',
            leaseUntil: LEASE, topologyRevision: 7, priorDeployedRevision: 5,
            heldTopologyAdmission: true, ...SCOPE, ...changes.operation },
        topology: { _id: 'singleton', revision: 7, deployedRevision: 5,
            topologyAdmissionCount: 1, ...changes.topology },
        group: { _id: 'group', paths: [], ...changes.group },
        owner: { node: 'r1', routeGroup: 'group', status: 'installed',
            desiredState: 'installed', activePathKey: 'main',
            appliedTopologyRevision: 5, secretRevision: 11, replacementFence: 0,
            ...changes.owner },
        links: (changes.linkRows || [
            { _id: 'p1-r1', portalNode: 'p1', bridgeNode: 'r1', active: true, status: 'staged' },
            { _id: 'r1-r2', portalNode: 'r1', bridgeNode: 'r2', active: true, status: 'staged' },
            { _id: 'r2-bridge', portalNode: 'r2', bridgeNode: 'bridge', active: true, status: 'pending' },
            { _id: 'foreign', portalNode: 'other', bridgeNode: 'elsewhere', active: true, status: 'pending' },
        ]).map(link => ({
                ...link, ...(changes.links?.[link._id] || {}),
            })),
        users: [{ desiredRevision: 11, appliedRevision: 11, login: 'user' }],
    };
    const calls = [];
    const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    function matches(doc, filter) {
        return Object.entries(filter).every(([key, expected]) => {
            const actual = doc[key];
            if (key === 'paths') return eq(actual, expected);
            if (expected && typeof expected === 'object' && !(expected instanceof Date)) {
                if ('$exists' in expected) return (actual !== undefined) === expected.$exists;
                if ('$in' in expected) return expected.$in.includes(actual);
                if ('$eq' in expected && !eq(actual, expected.$eq)) return false;
                if ('$gt' in expected && !(new Date(actual) > expected.$gt)) return false;
                return true;
            }
            return eq(actual, expected);
        });
    }
    function update(model, target, filter, change, options) {
        assert.strictEqual(options.session, SESSION);
        calls.push({ model, filter, change });
        if (!matches(target, filter)) return { matchedCount: 0 };
        Object.assign(target, structuredClone(change.$set || {}));
        for (const [key, value] of Object.entries(change.$inc || {})) target[key] += value;
        return { matchedCount: 1 };
    }
    const db = {};
    const TopologyOperation = {
        db,
        findById(id) { return {
            select() { return this; },
            session(session) { assert.strictEqual(session, SESSION); return this; },
            async lean() { return id === 'op' ? structuredClone(state.operation) : null; },
        }; },
        async updateOne(filter, change, options) {
            return update('operation', state.operation, filter, change, options);
        },
    };
    const CascadeTopologyState = { db, async updateOne(filter, change, options) {
        return update('topology', state.topology, filter, change, options);
    } };
    const CascadeRouteGroup = { db, async updateOne(filter, change, options) {
        return update('group', state.group, filter, change, options);
    } };
    const RelayL2tpState = { db, async updateOne(filter, change, options) {
        return update('owner', state.owner, filter, change, options);
    } };
    const CascadeLink = { db,
        find(filter) { return {
            select() { return this; },
            session(session) { assert.strictEqual(session, SESSION); return this; },
            async lean() { return structuredClone(state.links.filter(link => filter._id.$in.includes(link._id))); },
        }; },
        async updateMany(filter, change, options) {
        assert.strictEqual(options.session, SESSION);
        calls.push({ model: 'links', filter, change });
        const selected = state.links.filter(link => filter._id.$in.includes(link._id)
            && (filter.active === undefined || link.active === filter.active)
            && (filter.status === undefined || filter.status.$in.includes(link.status)));
        for (const link of selected) Object.assign(link, structuredClone(change.$set));
        return { matchedCount: selected.length };
    } };
    const transactionRunner = async work => {
        const before = structuredClone(state);
        try { return await work(SESSION); }
        catch (error) { Object.assign(state, before); throw error; }
    };
    const repository = new TopologyOperationFinalizationRepository({
        TopologyOperation, CascadeTopologyState,
        CascadeRouteGroup: changes.missingGroup ? undefined : CascadeRouteGroup,
        RelayL2tpState: changes.missingOwner ? undefined : RelayL2tpState,
        CascadeLink: changes.missingLinks ? undefined : CascadeLink,
        transactionRunner,
    });
    const finalizer = new TopologyOperationFinalizer({ repository, clock: { now: () => NOW } });
    return { state, calls, repository, finalizer };
}

test('attach publishes no path until the terminal finalizer; then atomically publishes the sole main path and releases admission', async () => {
    const h = harness();
    assert.deepEqual(h.state.group.paths, []);
    assert.equal(h.state.operation.status, 'committing');
    const result = await h.finalizer.finalizeSucceeded(INPUT);
    assert.deepEqual(result, { operationId: 'op', topologyRevision: 7,
        deployedRevision: 5, finishedAt: NOW });
    assert.deepEqual(h.state.group.paths, [{ pathKey: 'main',
        linkIds: ['r1-r2', 'r2-bridge'], enabled: true, priority: 1 }]);
    assert.deepEqual(h.state.links.map(l => l.status), ['deployed', 'deployed', 'deployed', 'pending']);
    assert.equal(h.state.operation.status, 'succeeded');
    assert.equal(h.state.operation.heldTopologyAdmission, false);
    assert.equal(h.state.topology.topologyAdmissionCount, 0);
    assert.equal(h.state.topology.deployedRevision, 5);
    assert.equal(h.state.owner.replacementFence, 1);
    assert.deepEqual(h.state.users, [{ desiredRevision: 11, appliedRevision: 11, login: 'user' }]);
    const snapshot = structuredClone(h.state);
    assert.equal(await h.finalizer.finalizeSucceeded(INPUT), null);
    assert.deepEqual(h.state, snapshot, 'replay cannot publish or release again');
});

test('lexically shuffled ObjectIds publish only the owner downstream suffix, activating the entire scoped chain', async () => {
    const id = n => n.toString(16).padStart(24, '0');
    const upstream = id(90), first = id(20), terminal = id(10);
    const owner = id(80), relay = id(60);
    const makeHarness = (operation = {}) => harness({
        operation: { ownerNodeId: owner, linkId: terminal,
            linkIds: [terminal, first, upstream], newPathLinkIds: [first, terminal],
            ...operation },
        owner: { node: owner },
        linkRows: [
            { _id: upstream, portalNode: id(70), bridgeNode: owner, active: true, status: 'staged' },
            { _id: first, portalNode: owner, bridgeNode: relay, active: true, status: 'staged' },
            { _id: terminal, portalNode: relay, bridgeNode: id(50), active: true, status: 'pending' },
            { _id: id(99), portalNode: id(30), bridgeNode: id(40), active: true, status: 'pending' },
        ],
    });
    const h = makeHarness();
    assert.equal((await h.finalizer.finalizeSucceeded(INPUT))?.operationId, 'op');
    assert.deepEqual(h.state.group.paths[0].linkIds, [first, terminal]);
    assert.deepEqual(h.state.links.map(link => link.status), ['deployed', 'deployed', 'deployed', 'pending']);
    assert.deepEqual(h.calls.filter(call => call.model === 'links').map(call => call.filter._id.$in),
        [[terminal], [first, upstream]]);
    for (const [name, operation] of [
        ['spurious scoped link', { linkIds: [terminal, first, upstream, id(99)] }],
        ['duplicate scoped link', { linkIds: [terminal, first, first, upstream] }],
        ['wrong suffix order', { newPathLinkIds: [terminal, first] }],
        ['duplicate suffix', { newPathLinkIds: [first, first, terminal] }],
    ]) {
        const invalid = makeHarness(operation);
        const before = structuredClone(invalid.state);
        assert.equal(await invalid.finalizer.finalizeSucceeded(INPUT), null, name);
        assert.deepEqual(invalid.state, before, `${name} cannot publish or release admission`);
    }
});

for (const [name, change] of [
    ['changed owner', { owner: { node: 'other' } }],
    ['disabled owner', { owner: { desiredState: 'absent' } }],
    ['different active path', { owner: { activePathKey: 'other' } }],
    ['changed owner topology revision', { owner: { appliedTopologyRevision: 6 } }],
    ['changed user credential revision', { owner: { secretRevision: 12 } }],
    ['foreign path', { group: { paths: [{ pathKey: 'foreign', linkIds: ['foreign'] }] } }],
    ['already populated path', { group: { paths: [{ pathKey: 'main', linkIds: ['foreign'] }] } }],
    ['revised topology', { topology: { revision: 8 } }],
    ['wrong lease', { operation: { leaseOwner: 'other' } }],
    ['expired lease', { operation: { leaseUntil: new Date('2026-09-29T09:59:59Z') } }],
    ['unverified operation', { operation: { status: 'preparing' } }],
    ['missing held admission', { operation: { heldTopologyAdmission: false } }],
    ['spent admission', { topology: { topologyAdmissionCount: 0 } }],
    ['changed deployed baseline', { topology: { deployedRevision: 6 } }],
    ['foreign reservation without release contract', { topology: { replacementReservation: { ownerToken: 'other', epoch: 2 } } }],
    ['missing group dependency', { missingGroup: true }],
    ['missing owner dependency', { missingOwner: true }],
    ['changed new suffix', { links: { 'r2-bridge': { status: 'offline' } } }],
    ['changed staged prefix', { links: { 'r1-r2': { status: 'pending' } } }],
    ['missing suffix link', { operation: { linkIds: ['p1-r1', 'r2-bridge'] } }],
    ['duplicate prefix link', { operation: { linkIds: ['p1-r1', 'r1-r2', 'r1-r2', 'r2-bridge'] } }],
    ['missing durable suffix', { operation: { newPathLinkIds: undefined } }],
    ['duplicate suffix', { operation: { newPathLinkIds: ['r1-r2', 'r1-r2', 'r2-bridge'] } }],
    ['wrong suffix order', { operation: { newPathLinkIds: ['r2-bridge', 'r1-r2'] } }],
    ['spurious scoped link', { operation: { linkIds: ['p1-r1', 'r1-r2', 'r2-bridge', 'foreign'] } }],
    ['spurious suffix link', { operation: { linkIds: ['p1-r1', 'r1-r2', 'r2-bridge', 'foreign'], newPathLinkIds: ['foreign', 'r2-bridge'] } }],
    ['disconnected suffix', { links: { 'r1-r2': { portalNode: 'other' } } }],
    ['wrong suffix adjacency', { links: { 'r2-bridge': { portalNode: 'other' } } }],
    ['cyclic suffix', { links: { 'r2-bridge': { bridgeNode: 'r1' } } }],
    ['upstream loops into suffix', { links: { 'p1-r1': { portalNode: 'r2' } } }],
    ['disconnected scoped prefix', { links: { 'p1-r1': { bridgeNode: 'other' } } }],
    ['different path identity', { operation: { pathKey: 'fallback' } }],
    ['fake old link', { operation: { oldLinkId: 'old' } }],
    ['missing topology pin', { operation: { ownerTopologyRevision: undefined } }],
    ['missing credential pin', { operation: { ownerCredentialRevision: undefined } }],
]) {
    test(`attach fails closed on ${name} without partial publication`, async () => {
        const h = harness(change);
        const before = structuredClone(h.state);
        assert.equal(await h.finalizer.finalizeSucceeded(INPUT), null);
        assert.deepEqual(h.state, before);
    });
}

test('late link failure rolls back path, owner fence, success marker and admission release', async () => {
    const h = harness({ links: { 'r1-r2': { status: 'error' } } });
    const before = structuredClone(h.state);
    assert.equal(await h.finalizer.finalizeSucceeded(INPUT), null);
    assert.deepEqual(h.state, before);
    assert.deepEqual(h.calls.filter(call => call.model).map(call => call.model),
        ['operation', 'topology', 'owner', 'group', 'links', 'links']);
});

test('finalizer rejects a falsely global attach result at the wrapper boundary', async () => {
    const finalizer = new TopologyOperationFinalizer({
        repository: { finalizeSucceeded: async () => ({
            operationId: 'op', topologyRevision: 7, deployedRevision: 7,
            scopeKind: 'link.attach', finishedAt: NOW,
        }) }, clock: { now: () => NOW },
    });
    assert.equal(await finalizer.finalizeSucceeded(INPUT), null);
});

test('attach schema accepts unordered scoped links and an ordered suffix without oldLinkId', async () => {
    const Model = require('../models/topologyOperationModel');
    const id = n => n.toString(16).padStart(24, '0');
    const fields = { topologyRevision: 7, priorDeployedRevision: 5,
        status: 'queued', kind: 'link.attach', linkId: id(1),
        linkIds: [id(1), id(3), id(2)], newPathLinkIds: [id(2), id(1)],
        groupId: id(3), pathKey: 'main', ownerNodeId: id(4),
        ownerTopologyRevision: 5, ownerCredentialRevision: 11 };
    const valid = new Model(fields);
    await valid.validate();
    assert.equal(valid.oldLinkId, undefined);
    await assert.rejects(new Model({ ...fields, ownerCredentialRevision: undefined }).validate());
    for (const change of [
        { newPathLinkIds: undefined }, { newPathLinkIds: [id(2)] },
        { newPathLinkIds: [id(2), id(2), id(1)] },
        { newPathLinkIds: [id(1), id(2)] },
        { newPathLinkIds: [id(5), id(1)] },
        { linkIds: [id(1), id(3)] },
    ]) await assert.rejects(new Model({ ...fields, ...change }).validate());
});
