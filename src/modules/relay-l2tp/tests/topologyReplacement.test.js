'use strict';

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.test';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'admin@example.test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret';

const assert = require('node:assert/strict');
const test = require('node:test');
const { cascadePathIngressPort, cascadePathIngressTag } = require('../domain/cascadePathIngress');
const { deriveReplacementTopology } = require('../domain/topologyReplacement');
const { validateTopology } = require('../domain/topologyValidator');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');

function fixture() {
    const nodes = [
        { _id: 'portal', cascadeRole: 'portal' },
        { _id: 'relay', cascadeRole: 'relay' },
        { _id: 'bridge', cascadeRole: 'bridge' },
    ];
    const links = [
        { _id: 'upstream', portalNode: 'portal', bridgeNode: 'relay', mode: 'reverse', active: true, status: 'deployed' },
        { _id: 'old', portalNode: 'relay', bridgeNode: 'bridge', mode: 'reverse', active: true, status: 'online' },
        { _id: 'new', portalNode: 'relay', bridgeNode: 'bridge', mode: 'reverse', active: true, status: 'pending' },
    ];
    const groups = [{ _id: 'group', mode: 'reverse', strategy: 'priority-failover', paths: [
        { pathKey: 'main', linkIds: ['upstream', 'old'], priority: 1, enabled: true },
        { pathKey: 'backup', linkIds: ['upstream', 'old'], priority: 2, enabled: false },
    ] }];
    return {
        snapshot: { nodes, links, groups, activeRouteGroupIds: ['group'],
            installedRouteGroupIds: ['group'] },
        request: { groupId: 'group', pathKey: 'main', oldLinkId: 'old', newLinkId: 'new' },
    };
}

function derive(input) {
    return deriveReplacementTopology(input.snapshot, input.request);
}

function expectRejected(input, code) {
    assert.throws(() => derive(input), { name: 'TopologyReplacementError', code });
}

test('derives a private complete replacement path without mutating the installed draft', () => {
    const input = fixture();
    // The foreign backup path uses old too; ownership is deliberately exclusive.
    input.snapshot.groups[0].paths[1].linkIds = ['upstream', 'old'];
    expectRejected(input, 'AMBIGUOUS_LINK_OWNERSHIP');
    input.snapshot.groups[0].paths[1].linkIds = ['upstream'];
    input.snapshot.groups[0].paths[1].enabled = false;
    const before = structuredClone(input.snapshot);
    const { topology, compiled } = derive(input);
    assert.deepEqual(input.snapshot, before);
    assert.equal(compiled.valid, true);
    assert.deepEqual(topology.links.map(link => link.id), ['new', 'upstream']);
    assert.deepEqual(topology.groups[0].paths.map(path => path.linkIds), [
        ['upstream', 'new'], ['upstream'],
    ]);
    assert.equal(topology.groups[0]._id, 'group');
    assert.equal(topology.groups[0].paths[0].priority, 1);
    assert.deepEqual(input.snapshot.groups[0].paths[0].linkIds, ['upstream', 'old']);
    assert.equal(topology.groups[0].paths[0].cascadePathIngress.port, cascadePathIngressPort('group', 'main'));
});

test('effective graph composes a relay SOCKS ingress that routes to the new link', () => {
    const input = fixture();
    input.snapshot.groups[0].paths.pop();
    const { topology, compiled } = derive(input);
    const nodeMetadata = input.snapshot.nodes.map((node, i) => ({
        id: node._id, role: node.cascadeRole, type: 'xray', active: true,
        ip: `192.0.2.${i + 1}`, domain: `${node._id}.example.test`, port: 24000 + i,
        xray: { apiPort: 61000 + i, inboundTag: `client-${node._id}`, transport: 'tcp', security: 'none' },
    }));
    const linkMetadata = input.snapshot.links.filter(link => link._id !== 'old').map((link, i) => ({
        id: link._id, source: link.portalNode, target: link.bridgeNode, mode: link.mode,
        tunnelPort: 12000 + i, tunnelUuid: `uuid-${i}`, tunnelDomain: 'reverse.example.test',
        tunnelProtocol: 'vless', tunnelSecurity: 'none', tunnelTransport: 'tcp',
    }));
    const plan = composeFrozenTopologyDeploymentPlan({ snapshot: topology, compiledTopology: compiled, nodeMetadata, linkMetadata });
    const relay = plan.nodes.find(node => node.role === 'relay');
    const config = JSON.parse(Buffer.from(relay.candidate.bytes).toString('utf8'));
    const tag = cascadePathIngressTag('main');
    assert(config.inbounds.some(inbound => inbound.tag === tag && inbound.protocol === 'socks'
        && inbound.port === cascadePathIngressPort('group', 'main')));
    assert(config.routing.rules.some(rule => rule.inboundTag?.includes(tag)
        && rule.outboundTag === 'portal-down-link-2'));
    assert(!JSON.stringify(config).includes('uuid-old'));
});

test('installed L2TP relay-root path excludes unrelated upstream pending portal', () => {
    const input = fixture();
    input.snapshot.groups[0].paths.pop();
    input.snapshot.nodes[0].cascadeRole = 'relay';
    input.snapshot.installedRouteOwners = [{ groupId: 'group', nodeId: 'portal' }];
    input.snapshot.nodes.push({ _id: 'portal2', cascadeRole: 'portal' });
    input.snapshot.links.push({ _id: 'pending-portal2', portalNode: 'portal2', bridgeNode: 'portal',
        mode: 'reverse', active: true, status: 'pending' });
    const { topology, compiled } = derive(input);
    assert.equal(validateTopology(topology).valid, true);
    assert.equal(compiled.valid, true);
    assert.deepEqual(topology.links.map(link => link.id), ['new', 'upstream']);
    assert.deepEqual(topology.groups[0].paths[0].linkIds, ['upstream', 'new']);
    assert.equal(input.snapshot.links.at(-1).status, 'pending');
});

test('relay-root replacement requires the installed L2TP owner on that relay', () => {
    const input = fixture();
    input.snapshot.groups[0].paths.pop();
    input.snapshot.nodes[0].cascadeRole = 'relay';
    input.snapshot.installedRouteOwners = [{ groupId: 'group', nodeId: 'other-relay' }];
    expectRejected(input, 'GROUP_NOT_INSTALLED');
});

test('replacement never treats a queued L2TP group as installed', () => {
    const input = fixture();
    input.snapshot.groups[0].paths.pop();
    input.snapshot.installedRouteGroupIds = [];
    assert.throws(() => deriveReplacementTopology(input.snapshot, input.request),
        { code: 'GROUP_NOT_INSTALLED' });
});

test('rejects incomplete installed path and endpoint mismatch', () => {
    const input = fixture(); input.snapshot.groups[0].paths.pop();
    input.snapshot.groups[0].paths[0].linkIds = ['old'];
    expectRejected(input, 'INCOMPLETE_PATH');
    input.snapshot.groups[0].paths[0].linkIds = ['upstream', 'old'];
    input.snapshot.links[2].bridgeNode = 'other';
    expectRejected(input, 'REPLACEMENT_ENDPOINT_MISMATCH');
});

test('rejects pending conflicts and missing installed ownership', () => {
    const input = fixture(); input.snapshot.groups[0].paths.pop();
    input.snapshot.links.push({ _id: 'pending-other', portalNode: 'relay', bridgeNode: 'bridge', mode: 'reverse', active: true, status: 'pending' });
    expectRejected(input, 'CONFLICTING_PENDING_LINK');
    input.snapshot.links.pop();
    input.snapshot.activeRouteGroupIds = [];
    expectRejected(input, 'GROUP_NOT_INSTALLED');
});

test('rejects ambiguous identities, disabled paths, and unconfirmed baselines', () => {
    const input = fixture(); input.snapshot.groups[0].paths.pop();
    input.snapshot.groups.push(structuredClone(input.snapshot.groups[0]));
    expectRejected(input, 'AMBIGUOUS_GROUP');
    input.snapshot.groups.pop();
    input.snapshot.groups[0].paths[0].enabled = false;
    expectRejected(input, 'INACTIVE_PATH');
    input.snapshot.groups[0].paths[0].enabled = true;
    input.snapshot.links[0].status = 'pending';
    expectRejected(input, 'UNCONFIRMED_BASELINE');
});

test('retains an independent confirmed geo leaf and its foreign group path', () => {
    const input = fixture(); input.snapshot.groups[0].paths.pop();
    input.snapshot.nodes.push({ _id: 'geo-bridge', cascadeRole: 'bridge' });
    input.snapshot.links.push({ _id: 'geo', portalNode: 'relay', bridgeNode: 'geo-bridge',
        mode: 'reverse', active: true, status: 'deployed',
        geoRouting: { enabled: true, domains: ['geo.example.test'] } });
    input.snapshot.groups.push({ _id: 'foreign', mode: 'reverse', strategy: 'priority-failover',
        paths: [{ pathKey: 'geo-path', linkIds: ['upstream', 'geo'], priority: 5, enabled: true }] });
    const { topology, compiled } = derive(input);
    assert.equal(compiled.valid, true);
    assert.deepEqual(topology.links.map(link => link.id), ['geo', 'new', 'upstream']);
    assert.deepEqual(topology.groups.find(group => group._id === 'foreign').paths[0].linkIds,
        ['upstream', 'geo']);
    assert.deepEqual(input.snapshot.groups[0].paths[0].linkIds, ['upstream', 'old']);
});

test('rejects colliding relay ingress identities across foreign groups', () => {
    const input = fixture(); input.snapshot.groups[0].paths.pop();
    input.snapshot.nodes.push({ _id: 'geo-bridge', cascadeRole: 'bridge' });
    input.snapshot.links.push({ _id: 'geo', portalNode: 'relay', bridgeNode: 'geo-bridge',
        mode: 'reverse', active: true, status: 'deployed',
        geoRouting: { enabled: true, domains: ['geo.example.test'] } });
    input.snapshot.groups.push({ _id: 'foreign', mode: 'reverse', strategy: 'priority-failover',
        paths: [{ pathKey: 'main', linkIds: ['upstream', 'geo'], priority: 5, enabled: true }] });
    expectRejected(input, 'INGRESS_COLLISION');
});

test('rejects malformed foreign route paths without projecting a partial graph', () => {
    const input = fixture(); input.snapshot.groups[0].paths.pop();
    input.snapshot.groups.push({ _id: 'foreign', paths: [{ pathKey: 'bad', linkIds: 'upstream' }] });
    expectRejected(input, 'INVALID_FOREIGN_PATH');
});

test('rejects metadata drift and geo/default-chain ambiguity', () => {
    const input = fixture(); input.snapshot.groups[0].paths.pop();
    input.snapshot.links[2].geoRouting = { enabled: true, domains: ['example.test'] };
    expectRejected(input, 'GEO_REPLACEMENT_UNSUPPORTED');
    delete input.snapshot.links[2].geoRouting;
    input.snapshot.links[2].mode = 'forward';
    expectRejected(input, 'REPLACEMENT_METADATA_MISMATCH');
    input.snapshot.links[2].mode = 'reverse';
    input.snapshot.links.push({ _id: 'alternate', portalNode: 'relay', bridgeNode: 'bridge', mode: 'reverse', active: true, status: 'deployed' });
    expectRejected(input, 'AMBIGUOUS_DEFAULT_CHAIN');
});
