'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { buildCandidate, projectGroups } = require('../domain/topologyDraft');
const { buildDefaultChainPath } = require('../domain/defaultChainPath');
const { deriveAttachTopology, deriveReplacementTopology } = require('../domain/topologyReplacement');
const { maintainAutoL2tpPaths } = require('../services/autoL2tpPathMaintenance');
const { buildL2tpXrayFragment } = require('../services/l2tpXrayFragmentProvider');

// Local model/domain evidence only: no Mongo, SSH, runtime bootstrap or real
// PPP credentials. Private candidates are not installed-path publication:
// do NOT let best-effort maintenance publish installed paths. The worker must
// prepare/read back ingress and atomically finalize the installed owner first.
//
// Remaining lifecycle handoff (outside this pure-candidate/readiness slice):
// - coordinator/materializer/worker must carry the same private candidate through
//   the existing owned operation, PPP/readback and separate ingress checks.
// - topologyOperationFinalizationRepository currently requires pathKey=main,
//   >=2 suffix links, a nonempty upstream prefix and an empty/sole-path group for
//   attach. Those constraints must be reconciled with owner/key-fenced cutover;
//   changing derivation alone cannot make restore operationally successful.
// - explicit last-exit delete requires a confirmed no-route/block transition in
//   that operation lifecycle. Retain CASCADE_LINK_IN_USE until that path exists;
//   neither draft row deletion nor indefinite last-known-good retention is it.
const NODES = [
    { _id: 'p', cascadeRole: 'portal' },
    { _id: 'r', cascadeRole: 'relay' },
    { _id: 'b', cascadeRole: 'bridge' },
    { _id: 'p-peer', cascadeRole: 'portal' },
    { _id: 'r-peer', cascadeRole: 'relay' },
    { _id: 'b-peer', cascadeRole: 'bridge' },
];
const link = (id, source, target, status = 'online') => ({
    _id: id, portalNode: source, bridgeNode: target,
    mode: 'reverse', active: true, status,
});
const path = (key, ids, priority = 1) => ({
    pathKey: key, linkIds: ids, priority, enabled: true,
});
const installed = (node, activePathKey) => ({
    node, routeGroup: 'shared', activePathKey,
    desiredState: 'installed', status: 'installed',
    appliedTopologyRevision: 7, secretRevision: 3,
    pskEncrypted: 'synthetic-encrypted-placeholder',
    clientCidr: '10.66.0.0/24', localAddress: '10.66.0.1',
    poolStart: '10.66.0.10', poolEnd: '10.66.0.200',
    dnsServers: ['9.9.9.9'], operationId: 'installed-operation',
});

function fixture({ links = [], paths = [], states = [installed('r', 'mine')] } = {}) {
    const group = { _id: 'shared', name: 'Pinned group', mode: 'reverse',
        strategy: 'priority-failover', paths };
    const topology = { _id: 'singleton', revision: 8, deployedRevision: 7 };
    const session = {};
    const writes = [];
    const query = value => ({
        select() { return this; },
        session(received) { assert.equal(received, session); return this; },
        async lean() { return structuredClone(value); },
    });
    const rejectWrite = name => async () => {
        writes.push(name);
        assert.fail(`${name} is not authorized without a prepared installed-route transition`);
    };
    const readOnly = (name, methods) => new Proxy(methods, {
        get(target, method) {
            if (Object.hasOwn(target, method)) return target[method];
            // Make an accidental new writer observable instead of silently
            // omitting the method from a permissive model double.
            if (/^(update|find.*Update|replace|delete|create|insert|bulkWrite)/.test(String(method))) {
                return rejectWrite(`${name}.${String(method)}`);
            }
            return undefined;
        },
    });
    const models = {
        transactionRunner: work => work(session),
        CascadeTopologyState: readOnly('CascadeTopologyState', {
            findById: id => { assert.equal(id, 'singleton'); return query(topology); },
        }),
        RelayL2tpState: readOnly('RelayL2tpState', {
            find: filter => {
                assert.deepEqual(filter, { desiredState: 'installed', routeGroup: { $ne: null } });
                return query(states);
            },
        }),
        CascadeLink: readOnly('CascadeLink', { find: () => query(links) }),
        HyNode: readOnly('HyNode', { find: () => query(NODES) }),
        CascadeRouteGroup: readOnly('CascadeRouteGroup', {
            findById: id => { assert.equal(id, group._id); return query(group); },
        }),
    };
    const snapshot = () => structuredClone({ group, states, links, topology });
    return { models, snapshot, writes };
}

function installedSnapshot({ links, paths, peer = false }) {
    return {
        revision: 8, deployedRevision: 7,
        nodes: structuredClone(NODES), links,
        groups: [{ _id: 'shared', mode: 'reverse', strategy: 'priority-failover', paths }],
        activeRouteGroupIds: ['shared'], installedRouteGroupIds: ['shared'],
        installedRouteOwners: [
            { groupId: 'shared', nodeId: 'r', pathKey: 'mine',
                ownerTopologyRevision: 7, ownerCredentialRevision: 3 },
            ...(peer ? [{ groupId: 'shared', nodeId: 'r-peer', pathKey: 'peer',
                ownerTopologyRevision: 7, ownerCredentialRevision: 4 }] : []),
        ],
    };
}

function deriveWithoutMutation(derive, snapshot, request) {
    const before = structuredClone(snapshot);
    try {
        return derive(snapshot, request);
    } finally {
        assert.deepEqual(snapshot, before, 'candidate preparation cannot publish desired state as installed');
    }
}

test('preservation: incomplete prefix and remove/recreate gap cannot erase an installed shared group', async () => {
    const states = [installed('r', 'mine'), installed('r-peer', 'peer')];
    const paths = [path('mine', ['old-exit'], 4), path('peer', ['peer-exit'], 9)];
    const f = fixture({
        links: [link('incoming', 'p', 'r'), link('peer-exit', 'r-peer', 'b-peer')],
        paths, states,
    });
    const before = f.snapshot();
    const result = await maintainAutoL2tpPaths(f.models);
    assert.deepEqual(result, { updated: 0, revision: null, deferred: [
        { relayNode: 'r', routeGroup: 'shared', reason: 'CHAIN_INCOMPLETE' },
    ] });
    assert.deepEqual(f.snapshot(), before, 'group ID, both paths and installed settings survive');
    assert.deepEqual(f.writes, []);
});

test('preservation: save-only pending exit never displaces the applied path or a peer relay', async () => {
    const f = fixture({
        links: [link('old-exit', 'r', 'b'), link('peer-exit', 'r-peer', 'b-peer'),
            link('new-pending', 'r', 'b-peer', 'pending')],
        paths: [path('mine', ['old-exit'], 4), path('peer', ['peer-exit'], 9)],
        states: [installed('r', 'mine'), installed('r-peer', 'peer')],
    });
    const before = f.snapshot();
    assert.deepEqual(await maintainAutoL2tpPaths(f.models), { updated: 0, deferred: [], revision: null });
    assert.deepEqual(f.snapshot(), before);
    assert.deepEqual(f.writes, []);
});

test('preservation: removing only the portal ingress retains the installed relay suffix and shared peer path', async () => {
    const snapshot = installedSnapshot({
        links: [link('incoming', 'p', 'r'), link('old-exit', 'r', 'b'),
            link('peer-exit', 'r-peer', 'b-peer')],
        paths: [path('mine', ['old-exit']), path('peer', ['peer-exit'], 9)], peer: true,
    });
    const before = structuredClone(snapshot);
    const result = buildCandidate(snapshot, { kind: 'link.delete', id: 'incoming' });
    assert.deepEqual(result.mutation.groupUpdates, []);
    assert.deepEqual(result.mutation.groupDeletes, []);
    assert.deepEqual(result.candidate.groups, projectGroups(snapshot.groups));
    assert.deepEqual(result.candidate.links.map(entry => entry.id), ['old-exit', 'peer-exit']);
    assert.deepEqual(snapshot, before);
    const f = fixture({ links: snapshot.links.filter(entry => entry._id !== 'incoming'),
        paths: snapshot.groups[0].paths,
        states: [installed('r', 'mine'), installed('r-peer', 'peer')] });
    assert.deepEqual(await maintainAutoL2tpPaths(f.models), { updated: 0, deferred: [], revision: null });
    assert.deepEqual(f.writes, []);
});

test('preservation: an installed exit cannot be draft-deleted in lieu of a coordinated no-route transition', () => {
    const snapshot = installedSnapshot({ links: [link('old-exit', 'r', 'b')],
        paths: [path('mine', ['old-exit'])] });
    const before = structuredClone(snapshot);
    assert.throws(() => buildCandidate(snapshot, { kind: 'link.delete', id: 'old-exit' }), {
        code: 'CASCADE_LINK_IN_USE', linkId: 'old-exit', groupId: 'shared',
    });
    assert.deepEqual(snapshot, before);
    // This is containment, not FR-07 completion: a confirmed user deletion
    // still needs a durable operation that blocks no-egress PPP traffic and
    // settles the installed owner before removing the physical exit.
});

test('preservation: recreating a deployed exit still cannot trigger an unprepared installed-route rewrite', async () => {
    const f = fixture({ links: [link('new-exit', 'r', 'b', 'deployed')],
        paths: [path('mine', [], 4)] });
    const before = f.snapshot();
    for (let pass = 0; pass < 2; pass += 1) {
        assert.deepEqual(await maintainAutoL2tpPaths(f.models), { updated: 0, revision: null, deferred: [
            { relayNode: 'r', routeGroup: 'shared', reason: 'REPLACEMENT_REQUIRES_PREPARED_INGRESS' },
        ] });
    }
    assert.deepEqual(f.snapshot(), before);
    assert.deepEqual(f.writes, []);
});

test('preservation: no selected healthy PPP exit generates block, never hidden direct', () => {
    for (const paths of [[], [{ pathKey: 'mine', healthy: false, outboundTag: 'cascade-mine' }]]) {
        const fragment = buildL2tpXrayFragment({
            plan: { group: { id: 'shared' }, selectedPathKey: 'mine', paths,
                relay: { controlPlaneIps: [] } },
            tags: { inbound: 'ppp-in', blockOutbound: 'block' }, tproxyPort: 12345,
        });
        assert.deepEqual(fragment.outbounds, []);
        assert.equal(fragment.routingRules.at(-1).outboundTag, 'block');
        assert.ok(fragment.routingRules.every(rule => rule.outboundTag === 'block'));
    }
});

test('FR-01/09: recreated R-to-B attaches privately for installed PPP without a portal', () => {
    // An empty installed path is a legacy/no-route baseline, not permission
    // for maintenance to invent ingress readiness or reinstall L2TP.
    const snapshot = installedSnapshot({ links: [link('new-exit', 'r', 'b', 'pending')],
        paths: [path('mine', [], 4)] });
    const chain = buildDefaultChainPath({ links: snapshot.links,
        nodesById: new Map(NODES.map(node => [node._id, node])), startNodeId: 'r' });
    assert.equal(chain.complete, true, 'PPP already supplies the ingress; no portal is needed');
    const result = deriveWithoutMutation(deriveAttachTopology, snapshot,
        { groupId: 'shared', pathKey: 'mine', linkId: 'new-exit' });
    assert.equal(result.compiled.valid, true);
    assert.equal(result.ownerNodeId, 'r');
    assert.deepEqual(result.topology.links.map(entry => entry.id), ['new-exit']);
    assert.deepEqual(result.topology.groups[0].paths[0].linkIds, ['new-exit']);
    assert.equal(result.topology.groups[0].paths[0].priority, 4);
});

test('FR-09: one-hop installed PPP suffix can prepare replacement before old-path cutover', () => {
    const snapshot = installedSnapshot({ links: [link('old-exit', 'r', 'b'),
        link('new-exit', 'r', 'b', 'pending')], paths: [path('mine', ['old-exit'], 4)] });
    const result = deriveWithoutMutation(deriveReplacementTopology, snapshot, {
        groupId: 'shared', pathKey: 'mine', oldLinkId: 'old-exit', newLinkId: 'new-exit',
    });
    assert.equal(result.compiled.valid, true);
    assert.equal(result.ownerNodeId, 'r');
    assert.deepEqual(result.oldPathLinkIds, ['old-exit']);
    assert.deepEqual(result.topology.groups[0].paths[0].linkIds, ['new-exit']);
    assert.equal(result.topology.groups[0].paths[0].priority, 4);
});

test('FR-09: restoring one shared-group relay retains the separately owned peer path', () => {
    const snapshot = installedSnapshot({
        links: [link('incoming', 'p', 'r'), link('new-exit', 'r', 'b', 'pending'),
            link('peer-incoming', 'p-peer', 'r-peer'), link('peer-exit', 'r-peer', 'b-peer')],
        paths: [path('mine', [], 4), path('peer', ['peer-exit'], 9)], peer: true,
    });
    const peerBefore = projectGroups(snapshot.groups)[0].paths[1];
    const result = deriveWithoutMutation(deriveAttachTopology, snapshot,
        { groupId: 'shared', pathKey: 'mine', linkId: 'new-exit' });
    assert.equal(result.compiled.valid, true);
    const group = result.topology.groups.find(entry => entry._id === 'shared');
    assert.deepEqual(group.paths.find(entry => entry.pathKey === 'peer'), peerBefore);
    assert.deepEqual(group.paths.find(entry => entry.pathKey === 'mine').linkIds, ['new-exit']);
    assert.equal(group.paths.find(entry => entry.pathKey === 'mine').priority, 4);
    assert.deepEqual(result.topology.links.map(entry => entry.id),
        ['incoming', 'new-exit', 'peer-exit', 'peer-incoming']);
    assert.deepEqual(result.compiled.relays.find(entry => entry.nodeId === 'r-peer')
        .routeGroups[0].candidates[0].suffixLinks.map(entry => entry.id), ['peer-exit']);
});

test('FR-09: replacing a relay-root suffix preserves a disconnected shared-group owner and excludes pending neighbors', () => {
    const snapshot = installedSnapshot({
        links: [link('old-exit', 'r', 'b'), link('new-exit', 'r', 'b', 'pending'),
            link('peer-incoming', 'p-peer', 'r-peer'), link('peer-exit', 'r-peer', 'b-peer'),
            link('pending-input', 'p', 'r', 'pending')],
        paths: [path('mine', ['old-exit'], 4), path('peer', ['peer-exit'], 9)], peer: true,
    });
    const result = deriveWithoutMutation(deriveReplacementTopology, snapshot, {
        groupId: 'shared', pathKey: 'mine', oldLinkId: 'old-exit', newLinkId: 'new-exit',
    });
    assert.equal(result.ownerNodeId, 'r');
    assert.equal(result.compiled.valid, true);
    assert.deepEqual(result.topology.links.map(entry => entry.id), ['new-exit', 'peer-exit', 'peer-incoming']);
    assert.deepEqual(result.topology.groups[0].paths[1], projectGroups(snapshot.groups)[0].paths[1]);
    assert.deepEqual(result.topology.groups[0].paths[0].linkIds, ['new-exit']);
});

test('relay-root attach omits a save-only portal input rather than requiring it to be applied', () => {
    const snapshot = installedSnapshot({
        links: [link('saved-input', 'p', 'r', 'pending'), link('new-exit', 'r', 'b', 'pending')],
        paths: [path('mine', [], 4)],
    });
    const result = deriveWithoutMutation(deriveAttachTopology, snapshot,
        { groupId: 'shared', pathKey: 'mine', linkId: 'new-exit' });
    assert.deepEqual(result.topology.links.map(entry => entry.id), ['new-exit']);
    assert.deepEqual(result.topology.nodes.map(entry => entry.id), ['b', 'r']);
});

function sharedCandidate(kind, change = () => {}) {
    const replacing = kind === 'replace';
    const snapshot = installedSnapshot({
        links: [...(replacing ? [link('old-exit', 'r', 'b')] : []),
            link('new-exit', 'r', 'b', 'pending'), link('peer-exit', 'r-peer', 'b-peer')],
        paths: [path('mine', replacing ? ['old-exit'] : [], 4), path('peer', ['peer-exit'], 9)], peer: true,
    });
    change(snapshot);
    return () => deriveWithoutMutation(replacing ? deriveReplacementTopology : deriveAttachTopology, snapshot,
        { groupId: 'shared', pathKey: 'mine', ...(replacing
            ? { oldLinkId: 'old-exit', newLinkId: 'new-exit' } : { linkId: 'new-exit' }) });
}

test('shared-group candidates require the exact installed owner/key and do not borrow peer authority', () => {
    for (const kind of ['attach', 'replace']) {
        for (const change of [
            snapshot => { snapshot.installedRouteOwners = snapshot.installedRouteOwners.slice(1); },
            snapshot => { snapshot.installedRouteOwners[0].pathKey = 'wrong-key'; },
            snapshot => { snapshot.installedRouteGroupIds = []; },
        ]) {
            assert.throws(sharedCandidate(kind, change), { code: 'GROUP_NOT_INSTALLED' });
        }
        assert.throws(sharedCandidate(kind, snapshot => {
            snapshot.installedRouteOwners[0].nodeId = 'r-peer'; snapshot.installedRouteOwners.pop();
        }), { code: kind === 'attach' ? 'INCOMPLETE_PATH' : 'GROUP_NOT_INSTALLED' });
        for (const change of [
            snapshot => { snapshot.installedRouteOwners.push(structuredClone(snapshot.installedRouteOwners[0])); },
            snapshot => { snapshot.installedRouteOwners[1].nodeId = 'r'; },
            snapshot => { snapshot.installedRouteOwners[1].pathKey = 'mine'; },
        ]) {
            assert.throws(sharedCandidate(kind, change),
                { code: kind === 'attach' ? 'AMBIGUOUS_PATH' : 'GROUP_NOT_INSTALLED' });
        }
        assert.throws(sharedCandidate(kind, snapshot => { delete snapshot.installedRouteOwners[0].pathKey; }),
            { code: kind === 'attach' ? 'MISSING_OWNER_PATH_KEY' : 'GROUP_NOT_INSTALLED' });
    }
});

test('peer preservation never activates missing, disabled or pending peer path members', () => {
    for (const kind of ['attach', 'replace']) {
        for (const change of [
            snapshot => { snapshot.links = snapshot.links.filter(entry => entry._id !== 'peer-exit'); },
            snapshot => { snapshot.links.find(entry => entry._id === 'peer-exit').active = false; },
            snapshot => { snapshot.links.find(entry => entry._id === 'peer-exit').status = 'pending'; },
        ]) {
            assert.throws(sharedCandidate(kind, change), { code: 'UNCONFIRMED_BASELINE' });
        }
        assert.throws(sharedCandidate(kind, snapshot => {
            snapshot.groups[0].paths[1].linkIds.push('new-exit');
        }), { code: 'AMBIGUOUS_LINK_OWNERSHIP' });
    }
});

test('relay-root support keeps bridge-egress and confirmed-baseline guards', () => {
    assert.throws(sharedCandidate('attach', snapshot => {
        snapshot.links.find(entry => entry._id === 'new-exit').bridgeNode = 'r-peer';
        snapshot.links = snapshot.links.filter(entry => entry._id !== 'peer-exit');
        snapshot.groups[0].paths[1].linkIds = [];
    }), { code: 'INCOMPLETE_PATH' });
    assert.throws(sharedCandidate('replace', snapshot => {
        snapshot.links.find(entry => entry._id === 'old-exit').status = 'pending';
    }), { code: 'INVALID_LINK_STATE' });
    assert.throws(sharedCandidate('replace', snapshot => {
        snapshot.links.find(entry => entry._id === 'new-exit').mode = 'forward';
    }), { code: 'REPLACEMENT_METADATA_MISMATCH' });
});
