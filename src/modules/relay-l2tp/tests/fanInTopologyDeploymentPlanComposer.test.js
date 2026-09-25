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

    // Default bridge terminates every upstream link (only link-4 here).
    const bridge = candidateJson(byRef.get('bridge'));
    assert.ok(bridge.inbounds.length >= 1);

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

test('fan-in: reverse mode is rejected explicitly', () => {
    const input = fanInInput();
    for (const link of input.snapshot.links) link.mode = 'reverse';
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        error => error.code === 'FAN_IN_REVERSE_UNSUPPORTED',
    );
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
