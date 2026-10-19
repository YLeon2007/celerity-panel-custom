'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const {
    composeFrozenTopologyDeploymentPlan,
} = require('../services/frozenTopologyDeploymentPlanComposer');
const {
    cascadePathIngressPort,
} = require('../domain/cascadePathIngress');

// ---------------------------------------------------------------------------
// Staged scoped link.apply for an incomplete chain (P -> R without a bridge):
// the plan must cover exactly the affected endpoints, the terminal relay must
// send transit to `block` (never `direct`), and confirmed-deployed baseline
// links / L2TP path ingress on a shared relay must be preserved.
// ---------------------------------------------------------------------------

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

// Scoped pinned snapshot for an incomplete P -> R link.apply: the old pending
// link (portal-2 -> relay-1) was already excluded upstream by the coordinator,
// so the staged composer must never see it — and must never emit artifacts
// for it on the shared relay.
function stagedInput(overrides = {}) {
    return {
        snapshot: {
            nodes: [
                { id: 'portal-1', role: 'portal' },
                { id: 'relay-1', role: 'relay' },
            ],
            links: [
                { id: 'link-pr', source: 'portal-1', target: 'relay-1', mode: 'reverse' },
            ],
            groups: [],
            ...overrides.snapshot,
        },
        nodeMetadata: [
            nodeMeta('portal-1', 'portal', 1),
            nodeMeta('relay-1', 'relay', 2),
        ],
        linkMetadata: [
            linkMeta('link-pr', 10101),
        ],
        compiledTopology: { valid: true, relays: [{ nodeId: 'relay-1' }] },
        staged: true,
        ...overrides.root,
    };
}

function planByRef(plan) {
    return new Map(plan.nodes.map(node => [node.nodeRef, node]));
}

function candidateJson(node) {
    return JSON.parse(Buffer.from(node.candidate.bytes).toString('utf8'));
}

// Mirror of the composer's deterministicTunnelUuid: the pending link's tunnel
// identity must never leak into a staged candidate it was excluded from.
function tunnelUuidOf(linkIdentity) {
    const hex = createHash('sha256')
        .update(`celerity-topology-v1:${linkIdentity}`)
        .digest('hex')
        .slice(0, 32)
        .split('');
    hex[12] = '5';
    hex[16] = ['8', '9', 'a', 'b'][Number.parseInt(hex[16], 16) % 4];
    return [
        hex.slice(0, 8).join(''),
        hex.slice(8, 12).join(''),
        hex.slice(12, 16).join(''),
        hex.slice(16, 20).join(''),
        hex.slice(20).join(''),
    ].join('-');
}

function transitLeakRules(config, transitTags) {
    return (config.routing?.rules || []).filter(rule => (
        Array.isArray(rule.inboundTag)
        && rule.inboundTag.some(tag => transitTags.includes(tag))
        && (rule.outboundTag === 'direct' || rule.outboundTag === 'freedom')
    ));
}

test('incomplete chain without explicit staged opt-in stays rejected', () => {
    const input = stagedInput({ root: { staged: false } });
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        error => error.code === 'INVALID_TOPOLOGY_ROLES',
    );
});

test('staged reverse P->R: two-node plan, terminal relay blocks transit', () => {
    const plan = composeFrozenTopologyDeploymentPlan(stagedInput());
    assert.equal(plan.staged, true, 'incomplete scoped chain must be marked staged');
    assert.equal(plan.mode, 'reverse');
    assert.equal(plan.nodes.length, 2, 'only the two link endpoints get candidates');

    const byRef = planByRef(plan);
    assert.deepEqual([...byRef.keys()].sort(), ['portal', 'relay-1']);

    // Terminal relay: reverse bridge towards the portal, transit exit -> block.
    const relay = candidateJson(byRef.get('relay-1'));
    const bridgeEntry = (relay.reverse?.bridges || [])[0];
    assert.ok(bridgeEntry, 'relay must declare a reverse bridge for the staged link');
    const tunnel = relay.outbounds.find(outbound => String(outbound.tag).startsWith('tunnel-'));
    assert.ok(tunnel, 'relay must dial the portal through a reverse tunnel outbound');
    assert.equal(tunnel.settings?.vnext?.[0]?.address, '192.0.2.1');
    assert.equal(tunnel.settings?.vnext?.[0]?.port, 10101);
    const blockRules = relay.routing.rules.filter(rule => (
        rule.inboundTag?.includes(bridgeEntry.tag) && rule.outboundTag === 'block'
    ));
    assert.equal(blockRules.length, 1, 'tunnel-exit transit must route to block exactly once');
    assert.ok(relay.outbounds.some(outbound => outbound.tag === 'block'
        && outbound.protocol === 'blackhole'), 'block route must resolve to a blackhole outbound');
    assert.deepEqual(
        transitLeakRules(relay, [bridgeEntry.tag]),
        [],
        'staged terminal relay must never route transit to direct/freedom',
    );
    // No L2TP path ingress may be chained into a downstream that does not exist.
    assert.ok(
        !relay.inbounds.some(inbound => String(inbound.tag).startsWith('socks-path-')),
        'staged terminal relay must not bind path ingress without a deployed downstream',
    );

    // Portal: REALITY client ingress preserved, clients routed into the tunnel.
    const portal = candidateJson(byRef.get('portal'));
    const portalEntry = (portal.reverse?.portals || [])[0];
    assert.ok(portalEntry, 'portal must declare the reverse portal');
    assert.ok(portal.inbounds.some(inbound => inbound.tag === 'client-portal-1'));
    assert.ok(portal.routing.rules.some(rule => (
        rule.inboundTag?.includes('client-portal-1') && rule.outboundTag === portalEntry.tag
    )), 'portal client inbound must route into the reverse portal');
    assert.ok(
        !portal.routing.rules.some(rule => (
            rule.inboundTag?.includes('client-portal-1')
            && (rule.outboundTag === 'direct' || rule.outboundTag === 'block')
        )),
        'portal client traffic must not exit directly nor be blocked at the portal',
    );
    // REALITY-only portal: the staged apply adds no public service ingress
    // (no socks/http inbound, no L2TP-owned artifact) beyond the tunnel.
    assert.ok(
        !portal.inbounds.some(inbound => ['socks', 'http'].includes(inbound.protocol)),
        'portal must not gain non-REALITY public ingress from a staged apply',
    );

    // Listener-first: the reverse tunnel listener lives on the portal (source),
    // so the portal is applied before the relay dialer.
    const order = plan.nodes.map(node => node.nodeRef);
    assert.ok(order.indexOf('portal') < order.indexOf('relay-1'));
    const portalChecks = byRef.get('portal').checks;
    assert.ok(portalChecks.some(check => check.type === 'port' && check.port === 10101),
        'portal must verify the reverse tunnel listener port');
    const relayChecks = byRef.get('relay-1').checks;
    assert.ok(!relayChecks.some(check => check.type === 'port' && check.port === 10101),
        'relay must not claim the reverse listener port');
});

test('staged forward P->R: relay binds hop inbound and blocks transit', () => {
    const input = stagedInput();
    input.snapshot.links[0].mode = 'forward';
    const plan = composeFrozenTopologyDeploymentPlan(input);
    assert.equal(plan.staged, true);
    assert.equal(plan.mode, 'forward');
    assert.equal(plan.nodes.length, 2);

    const byRef = planByRef(plan);
    const relay = candidateJson(byRef.get('relay-1'));
    const hop = relay.inbounds.find(inbound => String(inbound.tag).startsWith('fwd-hop-'));
    assert.ok(hop, 'relay must bind the forward hop inbound');
    assert.equal(hop.port, 10101);
    assert.ok(relay.routing.rules.some(rule => (
        rule.inboundTag?.includes(hop.tag) && rule.outboundTag === 'block'
    )), 'hop inbound transit must route to block');
    assert.deepEqual(transitLeakRules(relay, [hop.tag]), []);

    const portal = candidateJson(byRef.get('portal'));
    const fwd = portal.outbounds.find(outbound => String(outbound.tag).startsWith('fwd-'));
    assert.ok(fwd, 'portal must originate the forward tunnel outbound');
    assert.equal(fwd.settings?.vnext?.[0]?.address, '192.0.2.2');
    assert.equal(fwd.settings?.vnext?.[0]?.port, 10101);
    assert.ok(portal.routing.rules.some(rule => (
        rule.inboundTag?.includes('client-portal-1') && rule.outboundTag === fwd.tag
    )));

    // Forward listener lives on the relay (target): relay applies first.
    const order = plan.nodes.map(node => node.nodeRef);
    assert.ok(order.indexOf('relay-1') < order.indexOf('portal'));
    assert.ok(byRef.get('relay-1').checks.some(check => check.type === 'port' && check.port === 10101));
});

test('staged relay candidate has no direct egress path for transit (negative leak)', () => {
    for (const mode of ['reverse', 'forward']) {
        const input = stagedInput();
        input.snapshot.links[0].mode = mode;
        const plan = composeFrozenTopologyDeploymentPlan(input);
        const relay = candidateJson(planByRef(plan).get('relay-1'));
        const transitTags = relay.routing.rules
            .flatMap(rule => rule.inboundTag || [])
            .filter(tag => /^(bridge|fwd-hop)-/.test(tag));
        assert.ok(transitTags.length > 0, `${mode}: fixture must produce transit tags`);
        assert.deepEqual(
            transitLeakRules(relay, transitTags),
            [],
            `${mode}: no transit tag may reach direct/freedom`,
        );
        // Every transit rule must terminate at the blackhole.
        for (const rule of relay.routing.rules) {
            if (!Array.isArray(rule.inboundTag)
                || !rule.inboundTag.some(tag => transitTags.includes(tag))) continue;
            assert.equal(rule.outboundTag, 'block',
                `${mode}: transit rule ${JSON.stringify(rule)} must block`);
        }
        // The blackhole outbound itself must exist so `block` resolves.
        assert.ok(relay.outbounds.some(outbound => (
            outbound.tag === 'block' && outbound.protocol === 'blackhole'
        )), `${mode}: block outbound must exist`);
        // Private-IP fail-closed rule must survive the staged candidate.
        assert.ok(relay.routing.rules.some(rule => (
            Array.isArray(rule.ip) && rule.ip.includes('geoip:private')
        )), `${mode}: geoip:private block must be preserved`);
    }
});

test('staged plan never emits artifacts for the excluded old pending link', () => {
    const plan = composeFrozenTopologyDeploymentPlan(stagedInput());
    assert.equal(plan.nodes.length, 2, 'pending link endpoints must not get candidates');

    const pendingUuid = tunnelUuidOf('link-pending');
    for (const node of plan.nodes) {
        const raw = Buffer.from(node.candidate.bytes).toString('utf8');
        assert.ok(!raw.includes(pendingUuid),
            `${node.nodeRef}: excluded pending link tunnel identity leaked into candidate`);
        assert.ok(!raw.includes('link-pending'),
            `${node.nodeRef}: excluded pending link id leaked into candidate`);
    }
    // The shared relay binds no listener and no dialer for the pending link's
    // tunnel port (the pending fixture uses 10109 elsewhere in the suite).
    const relay = candidateJson(planByRef(plan).get('relay-1'));
    assert.ok(!relay.inbounds.some(inbound => inbound.port === 10109));
    assert.ok(!relay.outbounds.some(outbound => (
        outbound.settings?.vnext?.some(server => server.port === 10109)
    )));
});

test('staged chain with an intermediate relay blocks only at the terminal relay', () => {
    const input = stagedInput({
        snapshot: {
            nodes: [
                { id: 'portal-1', role: 'portal' },
                { id: 'relay-1', role: 'relay' },
                { id: 'relay-2', role: 'relay' },
            ],
            links: [
                { id: 'link-pr', source: 'portal-1', target: 'relay-1', mode: 'reverse' },
                { id: 'link-rr', source: 'relay-1', target: 'relay-2', mode: 'forward' },
            ],
            groups: [{
                _id: 'group-1',
                paths: [{ pathKey: 'main', linkIds: ['link-pr', 'link-rr'], enabled: true }],
            }],
        },
    });
    input.nodeMetadata.push(nodeMeta('relay-2', 'relay', 3));
    input.linkMetadata.push(linkMeta('link-rr', 10102));
    input.compiledTopology.relays.push({ nodeId: 'relay-2' });

    const plan = composeFrozenTopologyDeploymentPlan(input);
    assert.equal(plan.staged, true);
    assert.equal(plan.mode, 'mixed');
    assert.equal(plan.nodes.length, 3);

    const byRef = planByRef(plan);
    assert.deepEqual([...byRef.keys()].sort(), ['portal', 'relay-1', 'relay-2']);

    // Intermediate relay: transit continues into the downstream tunnel, and the
    // enabled L2TP path crossing its downstream link keeps loopback ingress.
    const mid = candidateJson(byRef.get('relay-1'));
    const downFwd = mid.outbounds.find(outbound => String(outbound.tag).startsWith('fwd-'));
    assert.ok(downFwd, 'intermediate relay must re-originate into the downstream link');
    const midBridge = (mid.reverse?.bridges || [])[0];
    assert.ok(mid.routing.rules.some(rule => (
        rule.inboundTag?.includes(midBridge.tag) && rule.outboundTag === downFwd.tag
    )), 'intermediate relay must route upstream transit into the downstream tunnel');
    const ingressPort = cascadePathIngressPort('group-1', 'main');
    assert.ok(mid.inbounds.some(inbound => inbound.port === ingressPort),
        'intermediate relay must preserve the enabled path socks ingress');
    assert.ok(byRef.get('relay-1').checks.some(check => (
        check.type === 'port' && check.port === ingressPort
    )), 'ingress port must be verified');

    // Terminal relay: everything it terminates goes to block, no path ingress.
    const terminal = candidateJson(byRef.get('relay-2'));
    const hop = terminal.inbounds.find(inbound => String(inbound.tag).startsWith('fwd-hop-'));
    assert.ok(hop, 'terminal relay must bind the downstream hop inbound');
    assert.ok(terminal.routing.rules.some(rule => (
        rule.inboundTag?.includes(hop.tag) && rule.outboundTag === 'block'
    )));
    assert.deepEqual(transitLeakRules(terminal, [hop.tag]), []);
    assert.ok(!terminal.inbounds.some(inbound => inbound.port === ingressPort),
        'terminal relay without a downstream must not bind path ingress');
});

test('complete scope (new link + deployed baseline) keeps the real egress and L2TP ingress', () => {
    // link.apply for P2 -> R where R already has a confirmed-deployed R -> B:
    // the scoped graph reaches a bridge, so the existing builders run and the
    // relay keeps its loopback L2TP ingress chained to the real downstream.
    const input = stagedInput({
        snapshot: {
            nodes: [
                { id: 'portal-2', role: 'portal' },
                { id: 'relay-1', role: 'relay' },
                { id: 'bridge-1', role: 'bridge' },
            ],
            links: [
                { id: 'link-p2r', source: 'portal-2', target: 'relay-1', mode: 'reverse' },
                { id: 'link-rb', source: 'relay-1', target: 'bridge-1', mode: 'reverse' },
            ],
            groups: [{
                _id: 'group-1',
                paths: [{ pathKey: 'main', linkIds: ['link-p2r', 'link-rb'], enabled: true }],
            }],
        },
    });
    input.nodeMetadata = [
        nodeMeta('portal-2', 'portal', 4),
        nodeMeta('relay-1', 'relay', 2),
        nodeMeta('bridge-1', 'bridge', 5),
    ];
    input.linkMetadata = [linkMeta('link-p2r', 10103), linkMeta('link-rb', 10104)];

    const plan = composeFrozenTopologyDeploymentPlan(input);
    assert.equal(plan.staged, undefined, 'a scoped graph reaching a bridge is not staged');
    assert.equal(plan.nodes.length, 3);

    const byRef = planByRef(plan);
    const relay = candidateJson(byRef.get('relay-1'));
    const ingressPort = cascadePathIngressPort('group-1', 'main');
    assert.ok(relay.inbounds.some(inbound => inbound.port === ingressPort),
        'shared relay must keep the confirmed-deployed path ingress');
    assert.ok(byRef.get('relay-1').checks.some(check => (
        check.type === 'port' && check.port === ingressPort
    )));
    // Transit from the new portal's tunnel continues towards the bridge, not block.
    const relayBridge = (relay.reverse?.bridges || [])
        .find(entry => entry.tag && relay.outbounds.some(outbound => (
            outbound.tag === `tunnel-${entry.tag.slice('bridge-'.length)}`
            && outbound.settings?.vnext?.[0]?.address === '192.0.2.4'
        )));
    assert.ok(relayBridge, 'relay must dial the new portal for link-p2r');
    assert.ok(!relay.routing.rules.some(rule => (
        rule.inboundTag?.includes(relayBridge.tag) && rule.outboundTag === 'block'
    )), 'complete-scope transit must not be blocked');

    const bridge = candidateJson(byRef.get('bridge'));
    assert.ok((bridge.reverse?.bridges || []).length === 1,
        'default bridge terminates the baseline link');
});

test('staged plan is deterministic across compositions', () => {
    const first = composeFrozenTopologyDeploymentPlan(stagedInput());
    const second = composeFrozenTopologyDeploymentPlan(stagedInput());
    assert.deepEqual(
        first.nodes.map(node => [node.nodeRef, node.candidate.sha256]),
        second.nodes.map(node => [node.nodeRef, node.candidate.sha256]),
    );
});

test('bridge-less graph without a portal stays a structural error', () => {
    const input = stagedInput({
        snapshot: {
            nodes: [
                { id: 'relay-1', role: 'relay' },
                { id: 'relay-2', role: 'relay' },
            ],
            links: [
                { id: 'link-rr', source: 'relay-1', target: 'relay-2', mode: 'reverse' },
            ],
            groups: [],
        },
    });
    input.nodeMetadata = [nodeMeta('relay-1', 'relay', 2), nodeMeta('relay-2', 'relay', 3)];
    input.linkMetadata = [linkMeta('link-rr', 10102)];
    input.compiledTopology = { valid: true, relays: [{ nodeId: 'relay-1' }, { nodeId: 'relay-2' }] };
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        error => ['INVALID_TOPOLOGY_ROLES', 'NON_LINEAR_TOPOLOGY'].includes(error.code),
    );
});

test('bridge-less graph with geo-routing rules stays a structural error', () => {
    const input = stagedInput();
    input.linkMetadata[0] = linkMeta('link-pr', 10101, {
        geoRouting: { enabled: true, geoip: ['ru'], domains: [] },
    });
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        error => ['NON_LINEAR_TOPOLOGY', 'GEO_LEAF_TARGET_CONFLICT', 'INVALID_TOPOLOGY_ROLES']
            .includes(error.code),
    );
});

test('bridge-less fan-in stages two portal sources to the shared relay without direct egress', () => {
    const input = stagedInput({
        snapshot: {
            nodes: [
                { id: 'portal-1', role: 'portal' },
                { id: 'portal-2', role: 'portal' },
                { id: 'relay-1', role: 'relay' },
            ],
            links: [
                { id: 'link-pr', source: 'portal-1', target: 'relay-1', mode: 'reverse' },
                { id: 'link-p2r', source: 'portal-2', target: 'relay-1', mode: 'reverse' },
            ],
            groups: [],
        },
    });
    input.nodeMetadata.push(nodeMeta('portal-2', 'portal', 4));
    input.linkMetadata.push(linkMeta('link-p2r', 10103));
    const plan = composeFrozenTopologyDeploymentPlan(input);
    assert.equal(plan.staged, true);
    assert.deepEqual(plan.nodes.map(node => node.nodeRef).sort(), ['portal-1', 'portal-2', 'relay-1']);
    const byRef = planByRef(plan);
    const relay = candidateJson(byRef.get('relay-1'));
    assert.equal((relay.reverse?.bridges || []).length, 2);
    for (const bridge of relay.reverse.bridges) {
        assert.ok(relay.routing.rules.some(rule => rule.inboundTag?.includes(bridge.tag)
            && rule.outboundTag === 'block'));
    }
    assert.ok(!relay.routing.rules.some(rule => rule.outboundTag === 'direct'
        && rule.inboundTag?.some(tag => tag.startsWith('bridge-'))));
    const second = composeFrozenTopologyDeploymentPlan(input);
    assert.deepEqual(plan.nodes.map(node => node.candidate.sha256),
        second.nodes.map(node => node.candidate.sha256));
});

test('bridge-less multi-portal with two different relay sinks remains rejected', () => {
    const input = stagedInput({
        snapshot: {
            nodes: [
                { id: 'portal-1', role: 'portal' }, { id: 'portal-2', role: 'portal' },
                { id: 'relay-1', role: 'relay' }, { id: 'relay-2', role: 'relay' },
            ],
            links: [
                { id: 'link-pr', source: 'portal-1', target: 'relay-1', mode: 'reverse' },
                { id: 'link-p2r', source: 'portal-2', target: 'relay-2', mode: 'reverse' },
            ], groups: [],
        },
    });
    input.nodeMetadata.push(nodeMeta('portal-2', 'portal', 4), nodeMeta('relay-2', 'relay', 5));
    input.linkMetadata.push(linkMeta('link-p2r', 10103));
    assert.throws(() => composeFrozenTopologyDeploymentPlan(input),
        error => error.code === 'MULTIPLE_DEFAULT_EGRESS');
});

test('staged chain ending at a non-relay node is rejected', () => {
    const input = stagedInput({
        snapshot: {
            nodes: [
                { id: 'portal-1', role: 'portal' },
                { id: 'portal-2', role: 'portal' },
            ],
            links: [
                { id: 'link-pp', source: 'portal-1', target: 'portal-2', mode: 'forward' },
            ],
            groups: [],
        },
    });
    input.nodeMetadata = [nodeMeta('portal-1', 'portal', 1), nodeMeta('portal-2', 'portal', 4)];
    input.linkMetadata = [linkMeta('link-pp', 10105)];
    input.compiledTopology = { valid: true, relays: [] };
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        error => ['NON_LINEAR_TOPOLOGY', 'INVALID_TOPOLOGY_ROLES'].includes(error.code),
    );
});
