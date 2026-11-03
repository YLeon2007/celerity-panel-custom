'use strict';

// Explicit local persistence/lock fixtures, not real Mongo or the production lock helper.
const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const { buildCandidate } = require('../domain/topologyDraft');
const { TopologyDraftWriteService, createTopologyDraftWriteService } = require('../services/topologyDraftWriteService');

function fixture({ snapshot = {}, onAcquire } = {}) {
    const trace = [];
    const state = {
        revision: 7, deployedRevision: 5, topologyAdmissionCount: 0,
        nodes: [
            { _id: 'p', cascadeRole: 'portal' },
            { _id: 'b', cascadeRole: 'bridge' },
            { _id: 'r', cascadeRole: 'relay' },
            { _id: 'b2', cascadeRole: 'bridge' },
        ],
        links: [], groups: [], relays: [], ...structuredClone(snapshot),
    };
    const busy = new Set();
    let held = null;
    const query = value => ({ select() { return this; }, session() { return this; }, async lean() { return structuredClone(value); } });
    const collection = key => ({
        find() { return query(state[key]); },
        async create(rows) { trace.push(['create', key]); state[key].push(...rows); },
        async updateOne({ _id }, { $set }) {
            trace.push(['update', key]);
            Object.assign(state[key].find(row => row._id === _id), $set);
            return { matchedCount: 1 };
        },
        async deleteOne({ _id }) { trace.push(['delete', key]); state[key] = state[key].filter(row => row._id !== _id); return { deletedCount: 1 }; },
    });
    const repository = new TopologyDraftRepository({
        HyNode: collection('nodes'), CascadeLink: collection('links'),
        CascadeRouteGroup: collection('groups'), RelayL2tpState: collection('relays'),
        CascadeTopologyState: {
            findById() { return query(state); },
            findOneAndUpdate(filter, update) {
                trace.push(['cas', filter, update]);
                if (filter.revision !== state.revision
                    || (filter.topologyAdmissionCount === 0 && state.topologyAdmissionCount !== 0)
                    || (filter.replacementReservation?.$exists === false && state.replacementReservation)) return query(null);
                state.revision += update.$inc.revision;
                return query(state);
            },
        },
        async transactionRunner(work) {
            trace.push(['begin', held && [...held]]);
            const before = structuredClone(state);
            try { const result = await work({}); trace.push(['commit', held && [...held]]); return result; }
            catch (error) { Object.assign(state, before); trace.push(['abort']); throw error; }
        },
        allowStandaloneClassicDrafts: true,
        async withScopedNodeLocks({ nodeIds }, work) {
            trace.push(['acquire', nodeIds]);
            if (nodeIds.some(id => busy.has(id))) throw Object.assign(new Error('node busy'), { code: 'NODE_LOCK_CONFLICT' });
            held = new Set(nodeIds);
            for (const id of nodeIds) busy.add(id);
            try {
                await onAcquire?.(state);
                return await work({
                    async verify() { trace.push(['verify']); },
                    async beforeRemoteMutation() { throw Error('pure draft must not authorize remote writes'); },
                });
            } finally {
                for (const id of nodeIds) busy.delete(id);
                trace.push(['release']); held = null;
            }
        },
    });
    const service = new TopologyDraftWriteService({ repository });
    return { repository, service, state, trace, busy };
}
const pair = (id = 'l', source = 'p', target = 'b', extra = {}) => ({
    _id: id, portalNode: source, bridgeNode: target, mode: 'reverse', active: true, ...extra,
});

test('selected-node locks enclose fresh draft read, persistence and transaction completion', async () => {
    const { service, trace, state } = fixture();
    await service.createLink({ expectedTopologyRevision: 7, link: pair() });
    assert.deepEqual(trace.find(row => row[0] === 'acquire'), ['acquire', ['b', 'p']]);
    assert.deepEqual(trace.find(row => row[0] === 'begin'), ['begin', ['b', 'p']]);
    assert.deepEqual(trace.find(row => row[0] === 'commit'), ['commit', ['b', 'p']]);
    assert.equal(trace.at(-1)[0], 'release');
    assert.equal(state.revision, 8);
    assert.equal(state.deployedRevision, 5);
});

test('standalone create, edit and normal delete ignore unrelated native reservations without clearing them', async () => {
    for (const kind of ['create', 'update', 'delete']) {
        const reservation = { ownerToken: 'unrelated-native', remoteDrain: 'retained' };
        const { service, state, busy, trace } = fixture({ snapshot: {
            links: kind === 'create' ? [] : [pair()],
            topologyAdmissionCount: 2, replacementReservation: reservation,
            relays: [{ node: 'r', routeGroup: 'foreign', status: 'installed' }],
        } });
        busy.add('r');
        const input = { expectedTopologyRevision: 7 };
        const result = kind === 'create' ? await service.createLink({ ...input, link: pair() })
            : kind === 'update' ? await service.updateLink({ ...input, linkId: 'l', changes: { name: 'edited' } })
                : await service.deleteLink({ ...input, linkId: 'l' });
        assert.equal(result.standaloneClassicDraft, true);
        assert.equal(state.revision, 8);
        assert.equal(state.deployedRevision, 5);
        assert.equal(state.topologyAdmissionCount, 2);
        assert.deepEqual(state.replacementReservation, reservation);
        assert.deepEqual(trace.find(row => row[0] === 'cas')[1], { _id: 'singleton', revision: 7 });
        assert.equal(state.links.length, kind === 'delete' ? 0 : 1);
    }
});

test('every same-node draft operation refuses before persistence while an independent deployment owns it', async () => {
    for (const kind of ['link.create', 'link.update', 'link.delete', 'group.create', 'group.update', 'group.delete']) {
        const { repository, busy, state, trace } = fixture({ snapshot: {
            links: [pair()], groups: [{ _id: 'g', paths: [{ pathKey: 'main', linkIds: ['l'] }] }],
        } });
        busy.add('p');
        const mutation = kind === 'link.create' ? { kind, document: pair('new') }
            : kind === 'group.create' ? { kind, document: { _id: 'new', paths: [{ linkIds: ['l'] }] } }
                : { kind, id: kind.startsWith('link.') ? 'l' : 'g', changes: { name: 'edited' } };
        await assert.rejects(repository.commitDraft({ expectedRevision: 7,
            prepare: snapshot => buildCandidate(snapshot, mutation) }), { code: 'NODE_LOCK_CONFLICT' });
        assert.equal(trace.some(row => ['create', 'update', 'delete', 'begin', 'cas'].includes(row[0])), false);
        assert.equal(state.revision, 7);
    }
});

test('a concurrent sibling create cannot enter while the first draft transaction is paused', async () => {
    const { repository, service, trace, state } = fixture();
    const create = repository.CascadeLink.create;
    let started, resume;
    const entered = new Promise(resolve => { started = resolve; });
    const released = new Promise(resolve => { resume = resolve; });
    repository.CascadeLink.create = async rows => { started(); await released; return create(rows); };
    const first = service.createLink({ expectedTopologyRevision: 7, link: pair() });
    await entered;
    try {
        await assert.rejects(service.createLink({ expectedTopologyRevision: 7, link: pair('sibling', 'p', 'b2') }),
            { code: 'NODE_LOCK_CONFLICT' });
        assert.equal(trace.filter(row => row[0] === 'begin').length, 1);
    } finally { resume(); }
    await first;
    assert.equal(state.revision, 8);
    assert.deepEqual(state.links.map(row => row._id), ['l']);
});

test('failed held verification after writes aborts the entire local transaction', async () => {
    const { repository, service, state, trace } = fixture();
    let checks = 0;
    repository.withScopedNodeLocks = async (options, work) => work({ async verify() {
        if (++checks === 3) throw Object.assign(Error('lost'), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
    } });
    await assert.rejects(service.createLink({ expectedTopologyRevision: 7, link: pair() }), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
    assert.equal(state.revision, 7);
    assert.deepEqual(state.links, []);
    assert.equal(trace.some(row => row[0] === 'commit'), false);
});

test('empty groups keep strict revision CAS without requesting a fictitious empty node lock', async () => {
    const { repository, trace } = fixture();
    await repository.commitDraft({ expectedRevision: 7,
        prepare: snapshot => buildCandidate(snapshot, { kind: 'group.create', document: { _id: 'empty', paths: [] } }) });
    assert.equal(trace.some(row => row[0] === 'acquire'), false);
    assert.deepEqual(trace.find(row => row[0] === 'cas')[1], { _id: 'singleton', revision: 7,
        topologyAdmissionCount: 0, replacementReservation: { $exists: false } });
});

test('dotted structural path writes cannot bypass selected-node discovery', async () => {
    const { repository, trace } = fixture({ snapshot: { links: [pair()], groups: [{ _id: 'g', paths: [] }] } });
    await assert.rejects(repository.commitDraft({ expectedRevision: 7,
        prepare: snapshot => buildCandidate(snapshot, { kind: 'group.update', id: 'g', changes: { 'paths.0.linkIds': ['l'] } }) }),
    { code: 'TOPOLOGY_DRAFT_LOCK_SCOPE_CHANGED' });
    assert.equal(trace.some(row => ['update', 'cas', 'begin'].includes(row[0])), false);
});

test('endpoint replacement locks old and new endpoints together', async () => {
    const { service, trace } = fixture({ snapshot: { links: [pair()] } });
    await service.updateLink({ expectedTopologyRevision: 7, linkId: 'l', changes: { bridgeNode: 'b2' } });
    assert.deepEqual(trace.find(row => row[0] === 'acquire')[1], ['b', 'b2', 'p']);
});

test('group path changes lock endpoints of both removed and added paths', async () => {
    for (const kind of ['group.create', 'group.update', 'group.delete']) {
        const { repository, trace } = fixture({ snapshot: { links: [pair(), pair('other', 'r', 'b2')],
            groups: [{ _id: 'g', paths: [{ pathKey: 'old', linkIds: ['l'] }] }] } });
        const document = { _id: 'new', paths: [{ pathKey: 'new', linkIds: ['other'] }] };
        const mutation = kind === 'group.create' ? { kind, document }
            : { kind, id: 'g', changes: { paths: document.paths } };
        await repository.commitDraft({ expectedRevision: 7, prepare: snapshot => buildCandidate(snapshot, mutation) });
        assert.deepEqual(trace.find(row => row[0] === 'acquire')[1],
            kind === 'group.update' ? ['b', 'b2', 'p', 'r'] : kind === 'group.create' ? ['b2', 'r'] : ['b', 'p']);
    }
});

test('link deletion locks all dependency-group cleanup endpoints', async () => {
    const { repository, trace, state } = fixture({ snapshot: {
        links: [pair(), pair('other', 'r', 'b2')],
        groups: [{ _id: 'g', paths: [{ pathKey: 'removed', linkIds: ['l', 'other'] }] }],
    } });
    await repository.commitDraft({ expectedRevision: 7,
        prepare: snapshot => buildCandidate(snapshot, { kind: 'link.delete', id: 'l' }) });
    assert.deepEqual(trace.find(row => row[0] === 'acquire')[1], ['b', 'b2', 'p', 'r']);
    assert.deepEqual(state.groups, []);
});

test('fresh transaction refuses expanded endpoints before any persistence', async () => {
    const { service, trace, state } = fixture({ snapshot: { links: [pair()] },
        onAcquire(state) { state.links[0].bridgeNode = 'b2'; } });
    await assert.rejects(service.updateLink({ expectedTopologyRevision: 7, linkId: 'l', changes: { name: 'edited' } }),
        { code: 'TOPOLOGY_DRAFT_LOCK_SCOPE_CHANGED' });
    assert.equal(trace.some(row => ['create', 'update', 'delete', 'cas'].includes(row[0])), false);
    assert.equal(trace.at(-1)[0], 'release');
    assert.equal(state.revision, 7);
});

test('fresh transaction refuses newly introduced group cleanup dependencies before persistence', async () => {
    const { repository, trace } = fixture({ snapshot: { links: [pair(), pair('other', 'r', 'b2')] },
        onAcquire(state) { state.groups.push({ _id: 'g', paths: [{ linkIds: ['l', 'other'] }] }); } });
    await assert.rejects(repository.commitDraft({ expectedRevision: 7,
        prepare: snapshot => buildCandidate(snapshot, { kind: 'link.delete', id: 'l' }) }),
    { code: 'TOPOLOGY_DRAFT_LOCK_SCOPE_CHANGED' });
    assert.equal(trace.some(row => ['create', 'update', 'delete', 'cas'].includes(row[0])), false);
});

test('stale revisions are rejected before lock acquisition and rechecked after acquisition', async () => {
    for (const driftAfterLock of [false, true]) {
        const { service, state, trace } = fixture({ onAcquire: driftAfterLock ? state => { state.revision++; } : undefined });
        await assert.rejects(service.createLink({ expectedTopologyRevision: driftAfterLock ? 7 : 6, link: pair() }),
            { code: 'STALE_TOPOLOGY_REVISION' });
        assert.equal(trace.some(row => ['create', 'cas'].includes(row[0])), false);
        assert.equal(trace.some(row => row[0] === 'acquire'), driftAfterLock);
        assert.equal(state.links.length, 0);
    }
});

test('relay, forward, geo, route-group and transit dependencies retain strict global busy policy', async () => {
    for (const scenario of ['relay', 'forward', 'geo', 'group', 'relay-reference', 'sibling-transit']) {
        const snapshot = { topologyAdmissionCount: 1, links: [] };
        let link = pair();
        if (scenario === 'relay') link = pair('l', 'p', 'r');
        if (scenario === 'forward') link.mode = 'forward';
        if (scenario === 'geo') link.geoRouting = { enabled: true };
        if (scenario === 'group') {
            snapshot.links = [pair('sibling')];
            snapshot.groups = [{ _id: 'g', paths: [{ pathKey: 'main', linkIds: ['sibling'] }] }];
        }
        if (scenario === 'relay-reference') snapshot.relays = [{ node: 'p', status: 'not_installed' }];
        if (scenario === 'sibling-transit') snapshot.links = [pair('sibling', 'p', 'b2'), pair('continuation', 'b2', 'r')];
        const { repository, trace } = fixture({ snapshot });
        await assert.rejects(repository.commitDraft({ expectedRevision: 7,
            prepare: snapshot => buildCandidate(snapshot, { kind: 'link.create', document: link }) }),
        { code: 'TOPOLOGY_DEPLOY_BUSY' });
        assert.equal(trace.some(row => ['create', 'cas'].includes(row[0])), false);
    }
});

test('a fresh new relay reference cancels the standalone exception under held locks', async () => {
    const { service, trace } = fixture({ snapshot: { topologyAdmissionCount: 1 },
        onAcquire(state) { state.relays.push({ node: 'p', status: 'queued' }); } });
    await assert.rejects(service.createLink({ expectedTopologyRevision: 7, link: pair() }), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    assert.equal(trace.some(row => row[0] === 'create'), false);
});

const CLASSIC_ENV = Object.freeze({ PANEL_DOMAIN: 'lm1.infograd.online',
    L2TP_PRODUCTION_EXECUTION_ENABLED: 'true', L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true',
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false' });

test('factory explicitly injects selected-node exclusion and freezes production policy before repository construction', () => {
    const env = { ...CLASSIC_ENV };
    const locks = async () => {};
    let options;
    class Repository {
        constructor(input) { options = input; env.CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED = 'false'; }
        async commitDraft() {}
    }
    createTopologyDraftWriteService({ Repository, deploymentEnv: env, withScopedNodeLocks: locks });
    assert.equal(options.withScopedNodeLocks, locks);
    assert.equal(options.allowStandaloneClassicDrafts, true);
});

test('assembled factory reaches real repository transactions using the explicit local lock fixture', async () => {
    const env = { ...CLASSIC_ENV };
    const { repository, trace, state } = fixture({ snapshot: { topologyAdmissionCount: 1 },
        onAcquire() { env.CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED = 'false'; } });
    const service = createTopologyDraftWriteService({ ...repository, deploymentEnv: env });
    const result = await service.createLink({ expectedTopologyRevision: 7, link: pair() });
    assert.equal(result.standaloneClassicDraft, true);
    assert.deepEqual(trace.find(row => row[0] === 'commit'), ['commit', ['b', 'p']]);
    assert.equal(state.revision, 8);
    assert.equal(state.topologyAdmissionCount, 1);
});

test('factory rejects malformed explicit selected-node lock dependencies', () => {
    for (const withScopedNodeLocks of [null, false, {}, 'locks']) {
        assert.throws(() => createTopologyDraftWriteService({ withScopedNodeLocks }), /withScopedNodeLocks/);
    }
});

test('factory requires real helper on production lock use; missing integration fails instead of silently falling back', async () => {
    let options;
    class Repository { constructor(input) { options = input; } async commitDraft() {} }
    createTopologyDraftWriteService({ Repository, deploymentEnv: CLASSIC_ENV });
    assert.equal(typeof options.withScopedNodeLocks, 'function');
    // This worktree intentionally does not own the separately integrated helper.
    // If present, its real export must be used (the parent runs real-store tests).
    let helper;
    try { helper = require('../../../services/classicPortalBridgeAdmission'); }
    catch (error) {
        assert.equal(error.code, 'MODULE_NOT_FOUND');
        assert.throws(() => options.withScopedNodeLocks({ nodeIds: ['p'] }, () => {}), { code: 'MODULE_NOT_FOUND' });
        return;
    }
    assert.equal(typeof helper.withScopedClassicNodeLocks, 'function');
});
