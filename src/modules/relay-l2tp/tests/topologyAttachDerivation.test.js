'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { deriveAttachTopology } = require('../domain/topologyReplacement');
const { cascadePathIngressPort, cascadePathIngressTag } = require('../domain/cascadePathIngress');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');

function fixture() {
    return {
        nodes: [
            { _id: 'p', cascadeRole: 'portal' },
            { _id: 'r1', cascadeRole: 'relay' },
            { _id: 'r2', cascadeRole: 'relay' },
            { _id: 'b', cascadeRole: 'bridge' },
        ],
        links: [
            { _id: 'pr1', portalNode: 'p', bridgeNode: 'r1', mode: 'reverse', active: true, status: 'staged' },
            { _id: 'r1r2', portalNode: 'r1', bridgeNode: 'r2', mode: 'reverse', active: true, status: 'staged' },
            { _id: 'r2b', portalNode: 'r2', bridgeNode: 'b', mode: 'reverse', active: true, status: 'pending' },
        ],
        groups: [{ _id: 'group', mode: 'reverse', strategy: 'priority-failover', paths: [] }],
        activeRouteGroupIds: ['group'], installedRouteGroupIds: ['group'],
        installedRouteOwners: [{ groupId: 'group', nodeId: 'r1', pathKey: 'main' }],
    };
}
const request = { groupId: 'group', pathKey: 'main', linkId: 'r2b' };
function rejected(snapshot, code, input = request) {
    assert.throws(() => deriveAttachTopology(snapshot, input), { name: 'TopologyReplacementError', code });
}

test('derives a private complete path from the unique installed relay owner, without draft mutation', () => {
    const snapshot = fixture();
    const before = structuredClone(snapshot);
    const { topology, compiled, ownerNodeId } = deriveAttachTopology(snapshot, request);
    assert.deepEqual(snapshot, before);
    assert.notStrictEqual(topology.groups[0], snapshot.groups[0]);
    assert.equal(ownerNodeId, 'r1');
    assert.equal(compiled.valid, true);
    assert.deepEqual(topology.links.map(link => link.id), ['pr1', 'r1r2', 'r2b']);
    assert.deepEqual(topology.groups[0].paths[0].linkIds, ['r1r2', 'r2b']);
    assert.deepEqual(topology.groups[0].paths[0], {
        pathKey: 'main', linkIds: ['r1r2', 'r2b'], priority: 1, enabled: true,
        cascadePathIngress: { tag: cascadePathIngressTag('main'), port: cascadePathIngressPort('group', 'main') },
    });
    for (const id of ['r1', 'r2']) {
        const group = compiled.relays.find(relay => relay.nodeId === id)
            ?.routeGroups.find(entry => entry.groupId === 'group');
        assert.deepEqual(group?.candidates[0].suffixLinks.map(link => link.id),
            id === 'r1' ? ['r1r2', 'r2b'] : ['r2b']);
        assert.equal(group?.candidates[0].pathKey, 'main');
    }
});

test('R1 and R2 each receive the group-specific ingress listener in the private plan', () => {
    const snapshot = fixture();
    const { topology, compiled } = deriveAttachTopology(snapshot, request);
    const nodeMetadata = topology.nodes.map((node, index) => ({
        id: node.id, role: node.role, type: 'xray', active: true,
        ip: `192.0.2.${index + 1}`, domain: `${node.id}.example.test`, port: 24000 + index,
        xray: { apiPort: 61000 + index, inboundTag: `client-${node.id}`, transport: 'tcp', security: 'none' },
    }));
    const linkMetadata = topology.links.map((link, index) => ({
        id: link.id, source: link.source, target: link.target, mode: link.mode,
        tunnelPort: 12000 + index, tunnelUuid: `uuid-${link.id}`,
        tunnelDomain: 'reverse.example.test', tunnelProtocol: 'vless',
        tunnelSecurity: 'none', tunnelTransport: 'tcp',
    }));
    const plan = composeFrozenTopologyDeploymentPlan({ snapshot: topology,
        compiledTopology: compiled, nodeMetadata, linkMetadata });
    for (const nodeRef of ['relay-1', 'relay-2']) {
        const relay = plan.nodes.find(node => node.nodeRef === nodeRef);
        assert(relay, nodeRef);
        const config = JSON.parse(Buffer.from(relay.candidate.bytes).toString('utf8'));
        assert(config.inbounds.some(inbound => inbound.tag === cascadePathIngressTag('main')
            && inbound.port === cascadePathIngressPort('group', 'main')),
        `${nodeRef} lacks main ingress`);
    }
});

test('accepts an existing empty owned path without changing the persisted path', () => {
    const snapshot = fixture();
    snapshot.groups[0].paths = [{ pathKey: 'main', linkIds: [], priority: 4, enabled: true }];
    const before = structuredClone(snapshot);
    const result = deriveAttachTopology(snapshot, request);
    assert.deepEqual(result.topology.groups[0].paths[0].linkIds, ['r1r2', 'r2b']);
    assert.equal(result.topology.groups[0].paths[0].priority, 4);
    assert.deepEqual(snapshot, before);
});

test('requires exactly one installed owner bound to the requested path key', () => {
    const snapshot = fixture();
    snapshot.installedRouteOwners = [];
    rejected(snapshot, 'GROUP_NOT_INSTALLED');
    snapshot.installedRouteOwners = [{ groupId: 'group', nodeId: 'r1', pathKey: 'main' },
        { groupId: 'group', nodeId: 'r1', pathKey: 'main' }];
    rejected(snapshot, 'AMBIGUOUS_PATH');
    snapshot.installedRouteOwners.pop();
    snapshot.installedRouteOwners[0].pathKey = 'other';
    rejected(snapshot, 'GROUP_NOT_INSTALLED');
    delete snapshot.installedRouteOwners[0].pathKey;
    rejected(snapshot, 'MISSING_OWNER_PATH_KEY');
    snapshot.installedRouteOwners[0].pathKey = 'main';
    snapshot.installedRouteGroupIds = [];
    rejected(snapshot, 'GROUP_NOT_INSTALLED');
});

test('rejects fan-in and competing exits even if a selected link sequence is supplied', () => {
    const snapshot = fixture();
    snapshot.links.push({ _id: 'other', portalNode: 'p', bridgeNode: 'r2', mode: 'reverse', active: true, status: 'staged' });
    rejected(snapshot, 'AMBIGUOUS_CHAIN', { ...request, linkIds: ['pr1', 'r1r2', 'r2b'] });
    snapshot.links.pop();
    snapshot.links.push({ _id: 'other', portalNode: 'r1', bridgeNode: 'b', mode: 'reverse', active: true, status: 'pending' });
    rejected(snapshot, 'AMBIGUOUS_CHAIN');
});

test('rejects foreign owned paths and partial or unconfirmed suffixes', () => {
    const snapshot = fixture();
    snapshot.groups.push({ _id: 'foreign', mode: 'reverse', paths: [
        { pathKey: 'foreign', linkIds: ['r1r2', 'r2b'], enabled: false },
    ] });
    rejected(snapshot, 'AMBIGUOUS_LINK_OWNERSHIP');
    snapshot.groups.pop();
    snapshot.groups[0].paths = [{ pathKey: 'foreign', linkIds: ['r1r2'], enabled: false }];
    rejected(snapshot, 'AMBIGUOUS_LINK_OWNERSHIP');
    snapshot.groups[0].paths = [];
    snapshot.links[1].status = 'pending';
    rejected(snapshot, 'UNCONFIRMED_BASELINE');
    snapshot.links[1].status = 'staged';
    snapshot.links.pop();
    rejected(snapshot, 'INCOMPLETE_PATH');
});
