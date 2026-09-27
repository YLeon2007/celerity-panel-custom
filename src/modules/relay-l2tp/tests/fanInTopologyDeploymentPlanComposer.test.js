'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    composeFrozenTopologyDeploymentPlan,
} = require('../services/frozenTopologyDeploymentPlanComposer');

function nodeMeta(id, role, index) {
    return {
        id,
        role,
        type: 'xray',
        active: true,
        cascadeRole: role,
        ip: `192.0.2.${index}`,
        port: 24000 + index,
        xray: {
            accessLogs: { enabled: false },
            apiPort: 61000 + index,
            inboundTag: `client-${role}-${index}`,
            transport: 'tcp',
            security: 'none',
            extraInbounds: [],
        },
    };
}

function linkMeta(id, tunnelPort, extra = {}) {
    return { id, tunnelPort, ...extra };
}

// pa -> ra -> rm -> bd
// pb -------> rm -> bd
//            rm -> bg (geo leaf, common trunk)
function fanInInput(overrides = {}) {
    return {
        snapshot: {
            nodes: [
                { id: 'node-pa', role: 'portal' },
                { id: 'node-pb', role: 'portal' },
                { id: 'node-ra', role: 'relay' },
                { id: 'node-rm', role: 'relay' },
                { id: 'node-bd', role: 'bridge' },
                { id: 'node-bg', role: 'bridge' },
            ],
            links: [
                { id: 'link-1', source: 'node-pa', target: 'node-ra', mode: 'forward' },
                { id: 'link-2', source: 'node-ra', target: 'node-rm', mode: 'forward' },
                { id: 'link-3', source: 'node-pb', target: 'node-rm', mode: 'forward' },
                { id: 'link-4', source: 'node-rm', target: 'node-bd', mode: 'forward' },
                { id: 'link-5', source: 'node-rm', target: 'node-bg', mode: 'forward' },
            ],
            groups: [],
            ...overrides.snapshot,
        },
        nodeMetadata: [
            nodeMeta('node-pa', 'portal', 1),
            nodeMeta('node-pb', 'portal', 2),
            nodeMeta('node-ra', 'relay', 3),
            nodeMeta('node-rm', 'relay', 4),
            nodeMeta('node-bd', 'bridge', 5),
            nodeMeta('node-bg', 'bridge', 6),
        ],
        linkMetadata: [
            linkMeta('link-1', 10101),
            linkMeta('link-2', 10102),
            linkMeta('link-3', 10103),
            linkMeta('link-4', 10104),
            linkMeta('link-5', 10105, { geoRouting: { enabled: true, geoip: ['ru'], domains: [] } }),
        ],
        compiledTopology: { valid: true, relays: [{ nodeId: 'node-ra' }, { nodeId: 'node-rm' }] },
        ...overrides.root,
    };
}

function planByRef(plan) {
    return new Map(plan.nodes.map(node => [node.nodeRef, node]));
}

function candidateJson(node) {
    return JSON.parse(Buffer.from(node.candidate.bytes).toString('utf8'));
}

test('fan-in: two portals converge to one default bridge with a geo leaf', () => {
    const plan = composeFrozenTopologyDeploymentPlan(fanInInput());
    assert.equal(plan.mode, 'forward');
    assert.equal(plan.nodes.length, 6);

    const byRef = planByRef(plan);
    assert.deepEqual(
        [...byRef.keys()].sort(),
        ['bridge', 'bridge-2', 'portal-1', 'portal-2', 'relay-1', 'relay-2'],
    );

    // Merge relay (relay-2 = rm, second relay in first-seen order) binds one
    // hop inbound per upstream link.
    const mergeRelay = candidateJson(byRef.get('relay-2'));
    const hopInbounds = mergeRelay.inbounds.filter(inbound => String(inbound.tag).startsWith('fwd-hop-'));
    assert.equal(hopInbounds.length, 2);
    assert.deepEqual(hopInbounds.map(inbound => inbound.port).sort(), [10102, 10103]);

    // Default bridge terminates every upstream link (only link-4 here): it must
    // bind a forward hop inbound on the link tunnel port and forward directly,
    // otherwise the verify port check can never pass.
    const bridge = candidateJson(byRef.get('bridge'));
    const bridgeHop = bridge.inbounds.find(inbound => String(inbound.tag).startsWith('fwd-hop-'));
    assert.ok(bridgeHop, 'bridge must bind a fwd-hop inbound');
    assert.equal(bridgeHop.port, 10104);
    assert.ok(bridge.routing.rules.some(rule => (
        rule.inboundTag?.includes(bridgeHop.tag) && rule.outboundTag === 'direct'
    )), 'bridge fwd-hop must route to direct');

    // Each portal originates the full chain along its own path plus the geo
    // branch.
    const portalOne = candidateJson(byRef.get('portal-1'));
    assert.ok(portalOne.outbounds.length >= 4, `portal-1 outbounds: ${portalOne.outbounds.length}`);
    const portalTwo = candidateJson(byRef.get('portal-2'));
    assert.ok(portalTwo.outbounds.length >= 3, `portal-2 outbounds: ${portalTwo.outbounds.length}`);

    // Deployment order: geo bridge and sink first, merge relay before its
    // upstream, portals last.
    const order = plan.nodes.map(node => node.nodeRef);
    assert.ok(order.indexOf('bridge') < order.indexOf('relay-2'));
    assert.ok(order.indexOf('relay-2') < order.indexOf('relay-1'));
    assert.ok(order.indexOf('relay-2') < order.indexOf('portal-2'));
    assert.ok(order.indexOf('relay-1') < order.indexOf('portal-1'));
});

test('fan-in: plan is deterministic across compositions', () => {
    const first = composeFrozenTopologyDeploymentPlan(fanInInput());
    const second = composeFrozenTopologyDeploymentPlan(fanInInput());
    assert.deepEqual(
        first.nodes.map(node => [node.nodeRef, node.candidate.sha256]),
        second.nodes.map(node => [node.nodeRef, node.candidate.sha256]),
    );
});

test('fan-in: two independent chains are rejected (single domain per compose)', () => {
    const input = fanInInput();
    input.snapshot.links = input.snapshot.links.filter(link => link.id !== 'link-2');
    input.linkMetadata = input.linkMetadata.filter(meta => meta.id !== 'link-2');
    // now pa -> ra dead-ends instead of reaching rm
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        error => ['MULTIPLE_DEFAULT_EGRESS', 'NON_LINEAR_TOPOLOGY'].includes(error.code),
    );
});

test('fan-in: geo branch off a non-common node is rejected', () => {
    const input = fanInInput();
    // move the geo leaf from rm (common trunk) to ra (only on portal-1 path)
    input.snapshot.links.find(link => link.id === 'link-5').source = 'node-ra';
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        error => error.code === 'GEO_LEAF_SOURCE_NOT_COMMON_TRUNK',
    );
});

test('fan-in: mixed forward/reverse links compose hop-by-hop', () => {
    const input = fanInInput();
    // pb -> rm becomes reverse: rm dials pb (pb hosts the reverse portal).
    input.snapshot.links.find(link => link.id === 'link-3').mode = 'reverse';
    const plan = composeFrozenTopologyDeploymentPlan(input);
    assert.equal(plan.mode, 'mixed');
    assert.equal(plan.nodes.length, 6);

    const byRef = planByRef(plan);

    // Portal-2 hosts the reverse portal for link-3 and routes its clients in.
    const portalTwo = candidateJson(byRef.get('portal-2'));
    const conn = portalTwo.inbounds.find(inbound => String(inbound.tag).startsWith('bridge-conn-'));
    assert.ok(conn, 'portal-2 must bind the reverse connector inbound');
    assert.equal(conn.port, 10103);
    const portalEntry = (portalTwo.reverse?.portals || [])[0];
    assert.ok(portalEntry, 'portal-2 must declare a reverse portal');
    assert.ok(portalTwo.routing.rules.some(rule => (
        rule.inboundTag?.includes('client-portal-2') && rule.outboundTag === portalEntry.tag
    )), 'portal-2 clients must route into the reverse portal');
    assert.ok(
        !portalTwo.outbounds.some(outbound => String(outbound.tag).startsWith('fwd-')),
        'portal-2 must not originate a forward outbound for a reverse link',
    );

    // Relay-2 dials portal-2 (reverse bridge) and re-originates downstream:
    // upstream exits (reverse bridge tag + forward hop inbound) route into the
    // default downstream outbound.
    const mergeRelay = candidateJson(byRef.get('relay-2'));
    const bridgeEntry = (mergeRelay.reverse?.bridges || [])[0];
    assert.ok(bridgeEntry, 'relay-2 must declare a reverse bridge for link-3');
    const tunnel = mergeRelay.outbounds.find(outbound => String(outbound.tag).startsWith('tunnel-'));
    assert.ok(tunnel, 'relay-2 must have a reverse tunnel outbound');
    assert.equal(
        tunnel.settings?.vnext?.[0]?.address,
        '192.0.2.2',
        'reverse tunnel must dial portal-2',
    );
    assert.equal(tunnel.settings?.vnext?.[0]?.port, 10103);
    const hopInbound = mergeRelay.inbounds.find(inbound => String(inbound.tag).startsWith('fwd-hop-'));
    assert.ok(hopInbound, 'relay-2 keeps the forward hop inbound for link-2');
    assert.equal(hopInbound.port, 10102);
    const fwdOutbound = mergeRelay.outbounds.find(outbound => String(outbound.tag).startsWith('fwd-'));
    assert.ok(fwdOutbound, 'relay-2 originates the default downstream outbound');
    assert.ok(mergeRelay.routing.rules.some(rule => (
        rule.inboundTag?.includes(bridgeEntry.tag) && rule.outboundTag === fwdOutbound.tag
    )), 'reverse tunnel exit must route into the downstream outbound');
    assert.ok(mergeRelay.routing.rules.some(rule => (
        rule.inboundTag?.includes(hopInbound.tag) && rule.outboundTag === fwdOutbound.tag
    )), 'forward hop inbound must route into the downstream outbound');

    // geoip rules require on-demand DNS so domain targets can match them.
    assert.equal(mergeRelay.routing.domainStrategy, 'IPOnDemand');

    // Deployment order: the reverse listener (portal-2) deploys before its
    // dialer (relay-2); forward listeners keep target-first ordering.
    const order = plan.nodes.map(node => node.nodeRef);
    assert.ok(order.indexOf('portal-2') < order.indexOf('relay-2'), 'reverse listener before dialer');
    assert.ok(order.indexOf('bridge') < order.indexOf('relay-2'));
    assert.ok(order.indexOf('relay-2') < order.indexOf('relay-1'));
    assert.ok(order.indexOf('relay-1') < order.indexOf('portal-1'));

    // Verify checks follow per-link listeners: portal-2 expects the reverse
    // connector port, relay-2 the forward hop port of link-2.
    const portalTwoChecks = byRef.get('portal-2').checks
        .filter(check => check.type === 'port').map(check => check.port);
    assert.ok(portalTwoChecks.includes(10103));
    const relayTwoChecks = byRef.get('relay-2').checks
        .filter(check => check.type === 'port').map(check => check.port);
    assert.ok(relayTwoChecks.includes(10102));
    assert.ok(relayTwoChecks.includes(10104) === false, 'dialer does not listen on link-4 port');
});

test('fan-in: uniform reverse domain composes hop-by-hop', () => {
    const input = fanInInput();
    for (const link of input.snapshot.links) link.mode = 'reverse';
    const plan = composeFrozenTopologyDeploymentPlan(input);
    assert.equal(plan.mode, 'reverse');
    assert.equal(plan.nodes.length, 6);
    const byRef = planByRef(plan);
    // Every portal hosts a reverse portal; the sink dials upstream.
    const portalOne = candidateJson(byRef.get('portal-1'));
    assert.ok((portalOne.reverse?.portals || []).length === 1);
    const bridge = candidateJson(byRef.get('bridge'));
    assert.ok((bridge.reverse?.bridges || []).length === 1, 'sink dials its reverse upstream');
    assert.ok(bridge.routing.rules.some(rule => rule.outboundTag === 'direct'));
    // Reverse listeners are link sources: sources deploy before targets.
    const order = plan.nodes.map(node => node.nodeRef);
    assert.ok(order.indexOf('portal-1') < order.indexOf('relay-1'));
    assert.ok(order.indexOf('relay-2') < order.indexOf('bridge'));
});

test('fan-in: a node with two non-geo outgoing links is rejected', () => {
    const input = fanInInput();
    input.snapshot.links.push({ id: 'link-6', source: 'node-rm', target: 'node-bg', mode: 'forward' });
    input.linkMetadata.push(linkMeta('link-6', 10106));
    input.snapshot.links.find(link => link.id === 'link-5').mode = 'forward';
    // remove geo rules from link-5 so both rm outgoing links are non-geo
    input.linkMetadata.find(meta => meta.id === 'link-5').geoRouting = { enabled: false, geoip: [], domains: [] };
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        error => error.code === 'NON_LINEAR_TOPOLOGY',
    );
});

test('fan-in: relay candidates never bind xray-main client inbounds (dual-profile host)', () => {
    const plan = composeFrozenTopologyDeploymentPlan(fanInInput());
    const byRef = planByRef(plan);
    for (const ref of ['relay-1', 'relay-2']) {
        const config = candidateJson(byRef.get(ref));
        const tags = (config.inbounds || []).map(inbound => inbound.tag);
        assert.ok(
            !tags.some(tag => typeof tag === 'string' && tag.startsWith('client-relay')),
            `${ref} candidate must not include the node xray-main inbound, got: ${tags.join(',')}`,
        );
        const ruleTags = (config.routing?.rules || []).flatMap(rule => rule.inboundTag || []);
        assert.ok(
            !ruleTags.some(tag => typeof tag === 'string' && tag.startsWith('client-relay')),
            `${ref} routing rules must not reference stripped inbounds`,
        );
    }
    // Portals keep their xray-main inbounds (they run the xray-main profile).
    const portal = candidateJson(byRef.get('portal-1'));
    assert.ok(
        (portal.inbounds || []).some(inbound => inbound.tag === 'client-portal-1'),
        'portal candidate keeps its client inbound',
    );
});
