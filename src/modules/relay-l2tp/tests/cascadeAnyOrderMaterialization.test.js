'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
// Match the ordinary selected coordinator's configuration compiler. This is
// configuration intent, not a tunnel/client readiness attestation.
const { compileConfiguredTopology: compileTopology } = require('../domain/primaryReservePolicy');
const { deriveAttachTopology, deriveReplacementTopology } = require('../domain/topologyReplacement');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { composeXrayConfig } = require('../services/xrayConfigComposer');
const { buildL2tpXrayFragment } = require('../services/l2tpXrayFragmentProvider');

// Real compiler, candidate derivation, materializer, composer and generators.
// Only persistence is modeled; these tests never execute a frozen candidate.
function fixture() {
    const nodes = [['p', 'portal'], ['r', 'relay'], ['b', 'bridge'],
        ['pp', 'portal'], ['rr', 'relay'], ['bb', 'bridge']].map(([id, role], index) => ({
        id, role, type: 'xray', active: true, ip: `192.0.2.${index + 1}`, port: 24001 + index,
        xray: { inboundTag: `client-${id}`, transport: 'tcp', security: 'none', extraInbounds: [] },
    }));
    const links = [['pr', 'p', 'r', 'reverse'], ['rb', 'r', 'b', 'forward'],
        ['pprr', 'pp', 'rr', 'forward'], ['rrbb', 'rr', 'bb', 'reverse']]
        .map(([id, source, target, mode], index) => ({
            id, source, target, mode, active: true, status: 'online', tunnelPort: 12001 + index,
            tunnelSecurity: 'none', tunnelTransport: 'tcp',
        }));
    return { nodes, links, groups: [] };
}
function graph(data, ids, groups = []) {
    const links = data.links.filter(link => ids.includes(link.id));
    const used = new Set(links.flatMap(link => [link.source, link.target]));
    return structuredClone({ nodes: data.nodes.filter(node => used.has(node.id)), links, groups });
}
function reader(data) {
    const reads = [];
    const model = (rows, label) => ({ find(filter) {
        reads.push({ label, filter: structuredClone(filter) });
        return { select() { return this; }, async lean() {
            return structuredClone(rows.filter(row => filter._id.$in.includes(row.id)));
        } };
    } });
    return { reads, materializer: new TopologyOperationPlanMaterializer({
        HyNode: model(data.nodes, 'nodes'), CascadeLink: model(data.links, 'links'),
    }) };
}
function input(topology, operationKind = 'link.apply', extra = {}) {
    return { target: 'test', hostIdentity: 'test.infograd.online', operationKind,
        pinnedSnapshot: { revision: 11, topology, compiled: compileTopology(topology) }, ...extra };
}
function configs(plan) {
    return new Map(plan.nodes.map(node => [node.node, JSON.parse(Buffer.from(node.candidate.bytes))]));
}
function route(config, tag) {
    return config.routing.rules.find(rule => (!rule.inboundTag || rule.inboundTag.includes(tag))
        && !rule.domain && !rule.ip)?.outboundTag;
}

test('delete the installed exit preserves raw profile fragments, users, peer policy and other profile isolation', async () => {
    const data = fixture();
    data.links[0].tunnelUuid = '11111111-1111-4111-8111-111111111111';
    const groups = [{ _id: 'shared', mode: 'reverse', strategy: 'priority-failover', paths: [
        { pathKey: 'mine', linkIds: ['rb'], priority: 4, enabled: true },
        { pathKey: 'peer', linkIds: ['rrbb'], priority: 9, enabled: true },
    ] }];
    const baselineTopology = graph(data, data.links.map(link => link.id), groups);
    const { materializer } = reader(data);
    const initial = await materializer.materialize(input(baselineTopology, 'link.apply', {
        baselineTopology: { nodes: [], links: [], groups: [] }, effectiveTopology: baselineTopology,
    }));
    const initialConfigs = configs(initial);
    const ppp = buildL2tpXrayFragment({ plan: { group: { id: 'shared' }, selectedPathKey: 'mine',
        paths: [{ pathKey: 'mine', healthy: true, outboundTag: 'ppp-egress' }],
        relay: { controlPlaneIps: ['192.0.2.200'] } },
    tags: { inbound: 'ppp-in', blockOutbound: 'block' }, tproxyPort: 12345 });
    const foreign = { id: 'unrelated', inbounds: [{ tag: 'unrelated-in', port: 13001,
        protocol: 'vless', settings: { clients: [{ id: '22222222-2222-4222-8222-222222222222', email: 'existing@user' }],
            decryption: 'none' } }], outbounds: [{ tag: 'unrelated-out', protocol: 'blackhole', settings: {} }],
    routingRules: [{ type: 'field', inboundTag: ['unrelated-in'], outboundTag: 'unrelated-out' }] };
    for (const node of baselineTopology.nodes) {
        node.profileConfig = initialConfigs.get(node.id);
        if (node.id === 'r') node.profileConfig = composeXrayConfig(node.profileConfig, [ppp, foreign]);
        if (node.id === 'p') node.profileConfig.inbounds.find(inbound => inbound.tag === 'client-p')
            .settings.clients.push({ id: '33333333-3333-4333-8333-333333333333', email: 'reality@user', flow: 'xtls-rprx-vision' });
        node.otherProfiles = { 'xray-main': { fingerprint: `unchanged-${node.id}` } };
        node.l2tpState = { users: [{ name: 'existing-ppp', credential: 'synthetic-frozen-secret' }],
            psk: 'synthetic-frozen-psk', pool: '10.66.0.0/24', installed: true };
    }
    const effectiveTopology = graph(baselineTopology, ['pr', 'pprr', 'rrbb'], [{ ...groups[0], paths: [
        { ...groups[0].paths[0], linkIds: [] }, groups[0].paths[1],
    ] }]);
    const saved = structuredClone({ baselineTopology, effectiveTopology });
    const plan = await materializer.materialize(input(effectiveTopology, 'link.delete', {
        baselineTopology, effectiveTopology,
    }));
    const after = configs(plan);
    assert.deepEqual(after.get('r').inbounds.find(inbound => inbound.tag === 'unrelated-in'), foreign.inbounds[0]);
    assert.deepEqual(after.get('r').outbounds.find(outbound => outbound.tag === 'ppp-egress'), ppp.outbounds[0]);
    assert.deepEqual(after.get('p').inbounds.find(inbound => inbound.tag === 'client-p').settings.clients,
        baselineTopology.nodes.find(node => node.id === 'p').profileConfig.inbounds.find(inbound => inbound.tag === 'client-p').settings.clients);
    assert.equal(route(after.get('r'), 'cascade-mine'), 'block');
    for (const id of ['pp', 'rr', 'bb']) assert.deepEqual(after.get(id), initialConfigs.get(id), 'peer policy/config is unchanged');
    assert.equal(after.get('b').inbounds.some(inbound => inbound.port === 12002), false);
    assert.ok(after.get('r').reverse.bridges.length, 'unchanged incoming reverse tunnel survives');
    const source = after.get('p').inbounds.find(inbound => inbound.port === 12001);
    const dialer = after.get('r').outbounds.find(outbound => outbound.settings?.vnext?.[0].port === 12001);
    assert.equal(source.settings.clients[0].id, data.links[0].tunnelUuid);
    assert.equal(dialer.settings.vnext[0].users[0].id, data.links[0].tunnelUuid);
    assert.ok(plan.nodes.every(node => node.targetProfile === (node.role === 'portal' ? 'xray-main' : 'xray-bridge')));
    assert.ok(!after.get('r').inbounds.some(inbound => inbound.tag === 'client-r'), 'bridge profile does not capture MAIN clients');
    assert.deepEqual({ baselineTopology, effectiveTopology }, saved, 'PPP users/settings and all frozen descriptors remain untouched');
});

for (const mode of ['forward', 'reverse']) {
    test(`deleting the last ${mode} suffix emits concrete cleanup configs for both old endpoints`, async () => {
        const data = fixture();
        data.links[1].mode = mode;
        const groups = [{ _id: 'shared', mode: 'forward', strategy: 'priority-failover', paths: [
            { pathKey: 'mine', linkIds: ['rb'], priority: 4, enabled: true },
        ] }];
        const baselineTopology = graph(data, ['rb'], groups);
        const effectiveTopology = { nodes: [], links: [], groups: [{ ...groups[0], paths: [
            { ...groups[0].paths[0], linkIds: [] },
        ] }] };
        const { materializer, reads } = reader(data);
        const plan = await materializer.materialize(input(effectiveTopology, 'link.delete', {
            baselineTopology, effectiveTopology,
        }));
        assert.deepEqual([...configs(plan).keys()].sort(), ['b', 'r'], 'old/new resource union includes detached nodes');
        for (const config of configs(plan).values()) {
            assert.equal(config.inbounds.some(inbound => inbound.port === 12002), false);
            assert.equal(config.outbounds.some(out => out.settings?.vnext), false);
            assert.equal((config.reverse?.bridges || []).length, 0);
            assert.equal((config.reverse?.portals || []).length, 0);
        }
        const relay = configs(plan).get('r');
        assert.ok(relay.inbounds.some(inbound => inbound.tag === 'cascade-mine'));
        assert.equal(route(relay, 'cascade-mine'), 'block', 'installed PPP ingress is explicit no-egress, never direct');
        assert.ok(plan.nodes.every(node => node.checks.some(check => check.type === 'service' && check.expectedState === 'active')),
            'cleanup is a config rewrite, not stopping a common service');
        assert.deepEqual(reads, []);
    });
}

for (const kind of ['attach', 'replace']) {
    test(`real relay-root ${kind} candidate materializes with a separately owned shared-group exit`, async () => {
        const data = fixture();
        data.links.find(link => link.id === 'rb').status = 'pending';
        if (kind === 'replace') data.links.push({ ...data.links[1], id: 'old', status: 'online' });
        const snapshot = { nodes: data.nodes, links: data.links.filter(link => link.id !== 'pr'),
            groups: [{ _id: 'shared', mode: 'reverse', strategy: 'priority-failover', paths: [
                { pathKey: 'mine', linkIds: kind === 'replace' ? ['old'] : [], priority: 4, enabled: true },
                { pathKey: 'peer', linkIds: ['rrbb'], priority: 9, enabled: true },
            ] }], activeRouteGroupIds: ['shared'], installedRouteGroupIds: ['shared'],
            installedRouteOwners: [{ groupId: 'shared', nodeId: 'r', pathKey: 'mine' },
                { groupId: 'shared', nodeId: 'rr', pathKey: 'peer' }] };
        const before = structuredClone(snapshot);
        const candidate = kind === 'attach' ? deriveAttachTopology(snapshot,
            { groupId: 'shared', pathKey: 'mine', linkId: 'rb' }) : deriveReplacementTopology(snapshot,
            { groupId: 'shared', pathKey: 'mine', oldLinkId: 'old', newLinkId: 'rb' });
        const { materializer } = reader(data);
        const plan = await materializer.materialize({ ...input(candidate.topology, `link.${kind}`),
            pinnedSnapshot: { topology: candidate.topology, compiled: compileTopology(candidate.topology) } });
        assert.equal(plan.staged, true, 'PPP egress completeness is not portal readiness');
        assert.deepEqual([...configs(plan).keys()].sort(), ['b', 'bb', 'pp', 'r', 'rr']);
        for (const [relayId, key, bridgeId] of [['r', 'mine', 'b'], ['rr', 'peer', 'bb']]) {
            const config = configs(plan).get(relayId);
            const egress = route(config, `cascade-${key}`);
            assert.ok(egress && !['direct', 'freedom', 'block'].includes(egress));
            if (relayId === 'r') assert.equal(config.outbounds.find(out => out.tag === egress)
                .settings.vnext[0].address, data.nodes.find(node => node.id === bridgeId).ip);
            else assert.ok(config.reverse.portals.some(portal => portal.tag === egress));
        }
        assert.deepEqual(snapshot, before, 'materialization does not publish installed path state');
    });
}

test('trusted effective descriptors ignore saved-only mutable node/link edits and exclude pending neighbors', async () => {
    const data = fixture();
    const baselineTopology = graph(data, ['pr']);
    const effectiveTopology = graph(data, ['pr', 'rb']);
    const trusted = reader(data);
    const expected = await trusted.materializer.materialize(input(effectiveTopology, 'link.apply', {
        baselineTopology, effectiveTopology,
    }));
    const desired = structuredClone(data);
    desired.nodes[0].ip = '198.51.100.77';
    desired.nodes[0].xray.inboundTag = 'save-only-client';
    desired.links[0].tunnelPort = 19999;
    desired.links[0].wsPath = '/save-only';
    desired.links[0].tunnelSecurity = 'reality'; // Invalid saved edit must not be hydrated.
    desired.links.push({ ...desired.links[1], id: 'pending', source: 'p', tunnelPort: 18888, status: 'pending' });
    const { materializer, reads } = reader(desired);
    const actual = await materializer.materialize(input(effectiveTopology, 'link.apply', {
        baselineTopology, effectiveTopology,
    }));
    assert.deepEqual(actual, expected);
    assert.deepEqual(reads, [], 'trusted configuration descriptors must never rehydrate mutable desired fields');
    assert.deepEqual([...configs(actual).keys()].sort(), ['b', 'p', 'r']);
    const portal = configs(actual).get('p');
    assert.ok(portal.inbounds.some(inbound => inbound.tag === 'client-p'));
    assert.ok(portal.inbounds.some(inbound => inbound.port === 12001));
    assert.equal(JSON.stringify([...configs(actual).values()]).includes('19999'), false);
});

for (const operationKind of ['link.attach', 'link.replace']) {
    test(`a single source-less suffix admits ${operationKind} without changing PPP gate authority`, async () => {
        const data = fixture();
        const topology = graph(data, ['rb']);
        const { materializer } = reader(data);
        const plan = await materializer.materialize(input(topology, operationKind));
        assert.equal(plan.staged, true);
        assert.deepEqual([...configs(plan).keys()].sort(), ['b', 'r']);
        assert.equal(Object.hasOwn(plan, 'skipPppReadiness'), false);
    });
}

test('trusted descriptor boundary rejects missing, malformed and mismatched snapshots without desired fallback', async () => {
    const data = fixture();
    const topology = graph(data, ['pr', 'rb']);
    for (const mutate of [
        value => { delete value.baselineTopology; },
        value => { delete value.effectiveTopology; },
        value => { value.baselineTopology = null; },
        value => { value.effectiveTopology.nodes[0].id = ['p']; },
        value => { value.effectiveTopology.nodes[0].ip = undefined; },
        value => { value.effectiveTopology.nodes[0].ip = new Date(); },
        value => { value.effectiveTopology.nodes.push(value.effectiveTopology.nodes[0]); },
        value => { value.effectiveTopology.links[0].source = 'foreign'; },
        value => { value.effectiveTopology.links[0].mode = 'forward'; },
        value => { value.effectiveTopology.groups.push({ _id: 'unexpected', paths: [] }); },
        value => { delete value.effectiveTopology.links[0].tunnelPort; },
        value => { value.baselineTopology.nodes[0].profileConfig = { inbounds: [] }; },
    ]) {
        const extra = { baselineTopology: graph(data, ['pr']), effectiveTopology: structuredClone(topology) };
        mutate(extra);
        const { materializer, reads } = reader(data);
        await assert.rejects(materializer.materialize(input(topology, 'link.apply', extra)));
        assert.deepEqual(reads, []);
    }
});

test('untrusted pinned snapshot fields cannot select the internal descriptor path', async () => {
    const data = fixture();
    const topology = graph(data, ['pr', 'rb']);
    const { materializer, reads } = reader(data);
    const request = input(topology);
    request.pinnedSnapshot.baselineTopology = { nodes: [], links: [], groups: [] };
    request.pinnedSnapshot.effectiveTopology = structuredClone(topology);
    request.pinnedSnapshot.effectiveTopology.links[0].tunnelPort = 19999;
    request.pinnedSnapshot.topology.nodes[0].profileConfig = { command: 'untrusted' };
    const plan = await materializer.materialize(request);
    assert.equal(reads.length, 2, 'legacy pinned identity input still uses allowlisted metadata reads');
    assert.equal(JSON.stringify([...configs(plan).values()]).includes('19999'), false);
});

test('a verified raw profile with a different legacy artifact layout refuses rather than leaving stale listeners', async () => {
    const data = fixture();
    const topology = graph(data, ['rb']);
    const { materializer } = reader(data);
    const legacy = await materializer.materialize(input(topology));
    for (const node of topology.nodes) node.profileConfig = configs(legacy).get(node.id);
    const effectiveTopology = { nodes: [], links: [], groups: [] };
    await assert.rejects(materializer.materialize(input(effectiveTopology, 'link.delete', {
        baselineTopology: topology, effectiveTopology,
    })), { code: 'TOPOLOGY_PROFILE_BASELINE_MISMATCH' });
});

test('delete-to-empty then attach reuses the frozen blocked PPP profile without duplicate ingress or stale block', async () => {
    const data = fixture();
    const groups = [{ _id: 'shared', mode: 'forward', strategy: 'priority-failover', paths: [
        { pathKey: 'mine', linkIds: ['rb'], priority: 4, enabled: true },
    ] }];
    const baselineTopology = graph(data, ['rb'], groups);
    const empty = { nodes: [], links: [], groups: [{ ...groups[0], paths: [{ ...groups[0].paths[0], linkIds: [] }] }] };
    const { materializer } = reader(data);
    const cleanup = await materializer.materialize(input(empty, 'link.delete', {
        baselineTopology, effectiveTopology: empty,
    }));
    const relay = { ...data.nodes.find(node => node.id === 'r'), profileConfig: configs(cleanup).get('r') };
    const beforeAttach = { ...empty, nodes: [relay] };
    const effectiveTopology = graph(data, ['rb'], groups);
    const plan = await materializer.materialize(input(effectiveTopology, 'link.attach', {
        baselineTopology: beforeAttach, effectiveTopology,
    }));
    const config = configs(plan).get('r');
    assert.equal(config.inbounds.filter(inbound => inbound.tag === 'cascade-mine').length, 1);
    assert.match(route(config, 'cascade-mine'), /^fwd-/);
    assert.equal(config.routing.rules.filter(rule => rule.inboundTag?.includes('cascade-mine')
        && rule.outboundTag === 'block').length, 0, 'the old no-egress rule does not survive cutover as a foreign fragment');
});

test('delete refuses identity-only input instead of losing detached cleanup endpoints', async () => {
    const data = fixture();
    const topology = graph(data, ['pr']);
    const { materializer, reads } = reader(data);
    await assert.rejects(materializer.materialize(input(topology, 'link.delete')),
        { code: 'TOPOLOGY_DELETE_BASELINE_REQUIRED' });
    assert.deepEqual(reads, []);
});

test('moving an applied edge retains both old and new endpoints in its cleanup union', async () => {
    const data = fixture();
    const baselineTopology = graph(data, ['rb']);
    const moved = structuredClone(data);
    moved.links.find(link => link.id === 'rb').target = 'bb';
    const effectiveTopology = graph(moved, ['rb']);
    const { materializer } = reader(data);
    const plan = await materializer.materialize(input(effectiveTopology, 'link.apply', {
        baselineTopology, effectiveTopology,
    }));
    assert.deepEqual([...configs(plan).keys()].sort(), ['b', 'bb', 'r']);
    assert.ok(!configs(plan).get('b').inbounds.some(inbound => inbound.port === 12002));
    assert.ok(configs(plan).get('bb').inbounds.some(inbound => inbound.port === 12002));
});

test('disconnected preservation does not drop foreign or duplicate compiled relay identities', async () => {
    const data = fixture();
    const topology = graph(data, ['pr', 'rb', 'pprr', 'rrbb']);
    for (const relays of [[{ nodeId: 'foreign' }], [{ nodeId: 'r' }, { nodeId: 'r' }]]) {
        const request = input(topology);
        request.pinnedSnapshot.compiled.relays = relays;
        await assert.rejects(reader(data).materializer.materialize(request), { code: 'COMPILED_TOPOLOGY_MISMATCH' });
    }
});

test('deleting the middle G5 hop composes the blocked prefix and preserved source-less suffix', async () => {
    const data = fixture();
    data.links.push({ ...data.links[1], id: 'middle', source: 'r', target: 'rr', tunnelPort: 12111 });
    const baselineTopology = graph(data, ['pr', 'middle', 'rrbb']);
    const { materializer } = reader(data);
    const initial = await materializer.materialize(input(baselineTopology, 'link.apply', {
        baselineTopology: { nodes: [], links: [], groups: [] }, effectiveTopology: baselineTopology,
    }));
    for (const node of baselineTopology.nodes) node.profileConfig = configs(initial).get(node.id);
    const effectiveTopology = graph(data, ['pr', 'rrbb']);
    const plan = await materializer.materialize(input(effectiveTopology, 'link.delete', {
        baselineTopology, effectiveTopology,
    }));
    const generated = configs(plan);
    assert.deepEqual([...generated.keys()].sort(), ['bb', 'p', 'r', 'rr']);
    assert.equal(plan.staged, true);
    assert.ok([...generated.values()].every(config => !config.inbounds.some(inbound => inbound.port === 12111)));
    const prefix = generated.get('r');
    assert.equal(route(prefix, prefix.reverse.bridges[0].tag), 'block');
    assert.deepEqual(generated.get('rr').inbounds.find(inbound => inbound.port === 12004),
        configs(initial).get('rr').inbounds.find(inbound => inbound.port === 12004));
    assert.deepEqual(generated.get('bb'), configs(initial).get('bb'));
});

function permutations(values) {
    return values.length === 0 ? [[]] : values.flatMap((value, index) =>
        permutations(values.filter((_, other) => other !== index)).map(rest => [value, ...rest]));
}
function vectors(length) {
    return length === 0 ? [[]] : vectors(length - 1).flatMap(prefix =>
        ['forward', 'reverse'].map(mode => [...prefix, mode]));
}
for (const modes of vectors(3)) {
    for (const order of permutations(['pr', 'rb', 'geo'])) {
        test(`concrete G3 cleanup ${modes.join('/')} ${order.join(';')} retains surviving tunnels and blocks no-egress`, async () => {
            const data = fixture();
            data.nodes.push({ ...data.nodes[2], id: 'geo-bridge', ip: '192.0.2.99' });
            data.links = data.links.slice(0, 2);
            data.links.push({ ...data.links[1], id: 'geo', target: 'geo-bridge', tunnelPort: 12099,
                geoRouting: { enabled: true, domains: ['category-ru'], geoip: ['ru'] } });
            data.links.forEach((link, index) => { link.mode = modes[index]; });
            let before = { nodes: [], links: [], groups: [] };
            let current = graph(data, ['pr', 'rb', 'geo']);
            const { materializer } = reader(data);
            let plan = await materializer.materialize(input(current, 'link.apply', {
                baselineTopology: before, effectiveTopology: current,
            }));
            const clients = port => [...configs(plan).values()].flatMap(config => config.inbounds)
                .find(inbound => inbound.port === port)?.settings.clients;
            const identities = new Map(data.links.map(link => [link.id, clients(link.tunnelPort)]));
            const deleted = new Set();
            for (const id of order) {
                for (const node of current.nodes) node.profileConfig = configs(plan).get(node.id);
                before = current;
                deleted.add(id);
                current = graph(data, data.links.filter(link => !deleted.has(link.id)).map(link => link.id));
                const saved = structuredClone(before);
                plan = await materializer.materialize(input(current, 'link.delete', {
                    baselineTopology: before, effectiveTopology: current,
                }));
                assert.deepEqual(before, saved);
                const generated = configs(plan);
                for (const link of data.links) {
                    const listeners = [...generated.values()].flatMap(config => config.inbounds)
                        .filter(inbound => inbound.port === link.tunnelPort);
                    if (deleted.has(link.id)) assert.equal(listeners.length, 0, 'deleted listeners never remain orphaned');
                    else {
                        assert.equal(listeners.length, 1);
                        assert.deepEqual(listeners[0].settings.clients, identities.get(link.id));
                    }
                }
                if (deleted.has('rb') && generated.has('r')) {
                    const relay = generated.get('r');
                    for (const tag of [
                        ...(relay.reverse?.bridges || []).map(bridge => bridge.tag),
                        ...relay.inbounds.filter(inbound => inbound.tag.startsWith('fwd-hop-')).map(inbound => inbound.tag),
                    ]) assert.equal(route(relay, tag), 'block');
                }
            }
        });
    }
}
