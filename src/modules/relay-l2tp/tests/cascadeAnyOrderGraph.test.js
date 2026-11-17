'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { compileTopology } = require('../domain/topologyCompiler');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');

// Local generation only: actual compiler/materializer/composer/generators,
// query-aware metadata fixtures, no database, transport or client readiness.
function fixture(modes = ['reverse', 'reverse', 'reverse']) {
    const nodes = [['p', 'portal'], ['r', 'relay'], ['b1', 'bridge'], ['b2', 'bridge']]
        .map(([id, role], index) => ({
            id, role, type: 'xray', active: true, ip: `192.0.2.${index + 1}`,
            port: 24001 + index,
            xray: { inboundTag: `client-${id}`, transport: 'tcp', security: 'none', extraInbounds: [] },
        }));
    const links = [['pr', 'p', 'r'], ['rb1', 'r', 'b1'], ['rb2', 'r', 'b2']]
        .map(([id, source, target], index) => ({
            id, source, target, active: true, mode: modes[index], tunnelPort: 12001 + index,
            tunnelSecurity: 'none', tunnelTransport: 'tcp',
            ...(id === 'rb2' ? { geoRouting: { enabled: true, geoip: ['ru'], domains: ['category-ru'] } } : {}),
        }));
    return { nodes, links };
}

function topologyFor(data, linkIds, { keepDetachedNodes = false, groups = [], healthByPathKey } = {}) {
    const links = data.links.filter(link => linkIds.includes(link.id));
    const used = new Set(links.flatMap(link => [link.source, link.target]));
    return {
        nodes: data.nodes.filter(node => keepDetachedNodes || used.has(node.id))
            .map(({ id, role }) => ({ id, role })),
        links: links.map(({ id, source, target, mode }) => ({ id, source, target, mode })),
        groups,
        ...(healthByPathKey === undefined ? {} : { healthByPathKey }),
    };
}

function compose(data, linkIds, options = {}) {
    const snapshot = topologyFor(data, linkIds, options);
    return composeFrozenTopologyDeploymentPlan({
        snapshot, nodeMetadata: data.nodes, linkMetadata: data.links,
        compiledTopology: compileTopology(snapshot), staged: true,
        executionContext: { target: 'test', hostIdentity: 'test.infograd.online' },
    });
}

function materializerFor(data) {
    const reads = [];
    const model = rows => ({
        find(filter) {
            reads.push(structuredClone(filter));
            return {
                select() { return this; },
                async lean() {
                    return structuredClone(rows.filter(row => filter._id.$in.includes(row.id)
                        && row.active === true));
                },
            };
        },
    });
    return { reads, materializer: new TopologyOperationPlanMaterializer({
        HyNode: model(data.nodes), CascadeLink: model(data.links),
    }) };
}

async function materialize(data, linkIds, options = {}) {
    const topology = topologyFor(data, linkIds, options);
    const { materializer, reads } = materializerFor(data);
    const plan = await materializer.materialize({
        target: 'test', hostIdentity: 'test.infograd.online', operationKind: 'link.apply',
        pinnedSnapshot: { revision: 7, topology, compiled: compileTopology(topology) },
    });
    return { plan, reads };
}

function configsOf(plan) {
    return new Map(plan.nodes.map(node => [node.nodeRef, JSON.parse(Buffer.from(node.candidate.bytes))]));
}

for (const [name, ids] of [
    ['source-less G2 R->B', ['rb1']],
    ['source-less G3 R->B1,R->B2', ['rb1', 'rb2']],
]) {
    test(`${name} composes through the existing frozen composer`, () => {
        const plan = compose(fixture(), ids);
        assert.equal(plan.staged, true, 'no portal path is not client-ready');
        assert.equal(plan.nodes.filter(node => node.role === 'relay').length, 1);
        assert.equal(plan.nodes.filter(node => node.role === 'bridge').length, ids.length);
        assert.equal(plan.nodes.some(node => node.role === 'portal'), false);
    });
    test(`${name} materializes as explicit link.apply`, async () => {
        const { plan } = await materialize(fixture(), ids);
        assert.equal(plan.staged, true);
        assert.equal(plan.nodes.length, ids.length + 1);
    });
}

test('R->B1; R->B2; P->R completes without dropping either bridge', async () => {
    const data = fixture();
    const first = await materialize(data, ['rb1']);
    const second = await materialize(data, ['rb1', 'rb2']);
    const final = await materialize(data, ['rb1', 'rb2', 'pr']);
    assert.equal(first.plan.staged, true);
    assert.equal(second.plan.staged, true);
    assert.equal(final.plan.staged, undefined);
    assert.deepEqual([...configsOf(final.plan).keys()].sort(), ['bridge', 'bridge-2', 'portal', 'relay-1']);
});

function routeFor(config, tag, destination = 'public') {
    return config.routing.rules.find(rule => (
        (!rule.inboundTag || rule.inboundTag.includes(tag))
        && (!rule.domain || rule.domain.includes(destination))
        && (!rule.ip || rule.ip.includes(destination))
    ))?.outboundTag;
}

for (const [name, ids, options] of [
    ['bridge-less prefix with a detached bridge', ['pr'], { keepDetachedNodes: true }],
    ['geo-only relay suffix without a default exit', ['rb2'], {}],
    ['portal prefix with only a geo exit', ['pr', 'rb2'], {}],
]) {
    test(`${name} is staged and has no implicit direct on the relay`, async () => {
        const { plan } = await materialize(fixture(), ids, options);
        assert.equal(plan.staged, true);
        const configs = configsOf(plan);
        const relay = configs.get('relay-1');
        assert.ok(relay);
        for (const rule of relay.routing.rules) {
            assert.ok(!['direct', 'freedom'].includes(rule.outboundTag), 'relay may not bypass its missing default');
            assert.notDeepEqual(rule.inboundTag, [], 'an empty ingress must not emit a broad geo rule');
        }
        for (const bridge of relay.reverse?.bridges || []) {
            assert.equal(routeFor(relay, bridge.tag), 'block');
            if (ids.includes('rb2')) {
                assert.match(routeFor(relay, bridge.tag, 'geoip:ru'), /^portal-/);
            }
        }
        if (ids.includes('rb2')) {
            const geo = configs.get('bridge-2');
            assert.ok(geo, 'the permitted geo exit is preserved');
            assert.equal(routeFor(geo, geo.reverse.bridges[0].tag), 'direct');
        }
    });
}

test('a relay-only R1->R2 fragment stages without a portal or bridge', async () => {
    const data = fixture();
    data.nodes.find(node => node.id === 'p').role = 'relay';
    const { plan } = await materialize(data, ['pr']);
    assert.equal(plan.staged, true);
    const terminal = configsOf(plan).get('relay-2');
    assert.equal(routeFor(terminal, terminal.reverse.bridges[0].tag), 'block');
});

function permutations(values) {
    return values.length === 0 ? [[]] : values.flatMap((value, index) =>
        permutations(values.filter((_, other) => other !== index)).map(rest => [value, ...rest]));
}

function modeVectors(length) {
    return length === 0 ? [[]] : modeVectors(length - 1).flatMap(prefix =>
        ['forward', 'reverse'].map(mode => [...prefix, mode]));
}

function listenerClients(plan, port) {
    const matches = [...configsOf(plan).values()].flatMap(config => config.inbounds)
        .filter(inbound => inbound.port === port);
    assert.equal(matches.length, 1, `one listener for tunnel port ${port}`);
    return matches[0].settings.clients;
}

// Enumerate actual candidate assembly, including every intermediate state.
// Explicit policy: rb1 is default; rb2 is RU geo (no new failover strategy).
for (const [graph, edgeIds] of [['G1', ['pr']], ['G2', ['pr', 'rb1']], ['G3', ['pr', 'rb1', 'rb2']]]) {
    for (const modes of modeVectors(edgeIds.length)) {
        for (const order of permutations(edgeIds)) {
            test(`${graph} ${modes.join('/')} assembly ${order.join(';')} preserves policy and tunnel identity`, async () => {
                const data = fixture(modes);
                if (graph === 'G1') data.links[0].target = 'b1';
                const expected = (await materialize(data, edgeIds)).plan;
                const before = structuredClone(data);
                const seen = [];
                const clientsByLink = new Map();
                let final;
                for (const id of order) {
                    seen.push(id);
                    // Also vary the persisted/hydrated row order, not just the
                    // set passed to a helper with otherwise fixed row ordering.
                    const ordered = { ...data, nodes: [...data.nodes].reverse(),
                        links: [...seen.map(key => data.links.find(link => link.id === key)),
                            ...data.links.filter(link => !seen.includes(link.id))] };
                    final = (await materialize(ordered, seen)).plan;
                    const incomplete = graph !== 'G1' && !(seen.includes('pr') && seen.includes('rb1'));
                    assert.equal(final.staged === true, incomplete);
                    for (const key of seen) {
                        const link = data.links.find(entry => entry.id === key);
                        const clients = listenerClients(final, link.tunnelPort);
                        if (clientsByLink.has(key)) assert.deepEqual(clients, clientsByLink.get(key));
                        clientsByLink.set(key, clients);
                        const refs = { p: 'portal', r: 'relay-1', b1: 'bridge', b2: 'bridge-2' };
                        const listener = refs[link.mode === 'reverse' ? link.source : link.target];
                        const dialer = refs[link.mode === 'reverse' ? link.target : link.source];
                        assert.ok(configsOf(final).get(listener).inbounds.some(inbound => inbound.port === link.tunnelPort),
                            'the listener follows this edge mode, not the component mode');
                        assert.ok(final.nodes.find(node => node.nodeRef === listener).checks.some(check =>
                            check.type === 'port' && check.port === link.tunnelPort));
                        assert.ok(final.nodes.findIndex(node => node.nodeRef === listener)
                            < final.nodes.findIndex(node => node.nodeRef === dialer), 'listener is planned before dialer');
                    }
                    if (graph !== 'G1' && !seen.includes('rb1')) {
                        const relay = configsOf(final).get('relay-1');
                        for (const tag of [
                            ...(relay.reverse?.bridges || []).map(bridge => bridge.tag),
                            ...relay.inbounds.filter(inbound => inbound.tag.startsWith('fwd-hop-')).map(inbound => inbound.tag),
                        ]) assert.equal(routeFor(relay, tag), 'block', 'incomplete default may not leak direct');
                    }
                }
                assert.deepEqual(final, expected, 'final config/policy must not depend on assembly order');
                assert.deepEqual(data, before, 'assembly must not rewrite metadata or edge modes');
            });
        }
    }
}

test('pinned scope preserves the sibling geo profile but excludes another pending exit', async () => {
    const data = fixture(['forward', 'reverse', 'forward']);
    const siblingBefore = compose(data, ['pr', 'rb1', 'rb2']);
    data.nodes.push({ ...data.nodes[2], id: 'pending-bridge', ip: '192.0.2.90' });
    data.links.push({ ...data.links[1], id: 'unrequested', target: 'pending-bridge',
        status: 'pending', tunnelPort: 12999 });
    const { plan, reads } = await materialize(data, ['pr', 'rb1', 'rb2']);
    assert.deepEqual(configsOf(plan).get('bridge-2'), configsOf(siblingBefore).get('bridge-2'));
    assert.equal(reads.some(filter => filter._id.$in.includes('unrequested')), false);
    assert.equal(reads.some(filter => filter._id.$in.includes('pending-bridge')), false);
    assert.equal(JSON.stringify([...configsOf(plan).values()]).includes('12999'), false);
});

test('source-less relay path ingress retains explicit default and geo policy in mixed modes', async () => {
    const data = fixture(['reverse', 'forward', 'reverse']);
    // Explicit local selector input, not observed tunnel/PPP/client health.
    const options = { healthByPathKey: { 'group:main': true }, groups: [{ _id: 'group', mode: 'forward', strategy: 'priority-failover',
        paths: [{ pathKey: 'main', linkIds: ['rb1'], priority: 1, enabled: true }] }] };
    const { plan } = await materialize(data, ['rb1', 'rb2'], options);
    const relay = configsOf(plan).get('relay-1');
    assert.equal(plan.staged, true, 'server generation is not portal/client readiness');
    assert.ok(relay.inbounds.some(inbound => inbound.tag === 'cascade-main'));
    const main = routeFor(relay, 'cascade-main');
    const geo = routeFor(relay, 'cascade-main', 'geoip:ru');
    assert.match(main, /^fwd-/);
    assert.equal(relay.outbounds.find(outbound => outbound.tag === main).settings.vnext[0].address,
        data.nodes.find(node => node.id === 'b1').ip);
    assert.equal(relay.outbounds.find(outbound => outbound.tag === main).settings.vnext[0].port, 12002);
    assert.match(geo, /^portal-/);
    assert.ok(relay.reverse.portals.some(portal => portal.tag === geo));
    assert.equal(routeFor(relay, 'cascade-main', 'geosite:category-ru'), geo);
    assert.ok(relay.inbounds.some(inbound => inbound.port === 12003), 'reverse geo listener stays on relay');
    assert.equal(relay.inbounds.some(inbound => inbound.port === 12002), false,
        'forward default listener stays on its bridge');
});

for (const operationKind of [undefined]) {
    test(`source-less materialization does not grant staging to ${String(operationKind)}`, async () => {
        const data = fixture();
        const topology = topologyFor(data, ['rb1']);
        const { materializer, reads } = materializerFor(data);
        await assert.rejects(materializer.materialize({
            target: 'test', hostIdentity: 'test.infograd.online', operationKind,
            pinnedSnapshot: { revision: 7, topology, compiled: compileTopology(topology) },
        }), { code: 'INVALID_TOPOLOGY_ROLES' });
        assert.deepEqual(reads, []);
    });
}

test('domain.reconcile preserves the supported source-less staged plan without claiming client readiness', async () => {
    const data = fixture();
    const topology = topologyFor(data, ['rb1']);
    const { materializer } = materializerFor(data);
    const plan = await materializer.materialize({
        target: 'test', hostIdentity: 'test.infograd.online', operationKind: 'domain.reconcile',
        pinnedSnapshot: { revision: 7, topology, compiled: compileTopology(topology) },
    });
    const selected = (await materialize(data, ['rb1'])).plan;
    const { fullTopology, ...dataPlane } = plan;
    assert.deepEqual(dataPlane, selected, 'reconciliation uses the same supported staged composition');
    assert.deepEqual(fullTopology.nodes.map(node => node.id).sort(), ['b1', 'r']);
    assert.deepEqual(fullTopology.links.map(link => link.id), ['rb1']);
    assert.equal(plan.staged, true);
});

for (const ids of [['rb1'], ['rb1', 'rb2'], ['pr'], ['rb2']]) {
    test(`incomplete ${ids.join(',')} still requires explicit staging permission`, () => {
        const data = fixture();
        const snapshot = topologyFor(data, ids);
        assert.throws(() => composeFrozenTopologyDeploymentPlan({
            snapshot, nodeMetadata: data.nodes, linkMetadata: data.links,
            compiledTopology: compileTopology(snapshot),
        }), error => ['INVALID_TOPOLOGY_ROLES', 'NON_LINEAR_TOPOLOGY'].includes(error.code));
    });
}

for (const [label, mutate] of [
    ['self loop', data => { data.links[0].target = 'p'; }],
    ['routing cycle through a geo edge', data => {
        data.links.push({ ...data.links[0], id: 'cycle', source: 'b2', target: 'p', tunnelPort: 12004 });
    }],
    ['two ambiguous default exits', data => { delete data.links[2].geoRouting; }],
    ['a bridge used as transit', data => { data.nodes[1].role = 'bridge'; }],
]) {
    test(`staging never permits ${label}`, () => {
        const data = fixture();
        mutate(data);
        assert.throws(() => compose(data, data.links.map(link => link.id)),
            error => ['NON_LINEAR_TOPOLOGY', 'MISSING_TOPOLOGY_LINK', 'GEO_LEAF_TARGET_CONFLICT'].includes(error.code));
    });
}
