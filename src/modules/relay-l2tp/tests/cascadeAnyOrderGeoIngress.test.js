'use strict';
// Real selected coordinator/materializer/composer/worker/service/gates/finalizer.
// Persistence, accepted node authority and remote replies are local models only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { installedFixture, apply, remove, enableV2 } = require('./cascadeAnyOrderInstalledPublication.test');
const { id } = require('./cascadeAnyOrderSelectedApply.test');
const { ownedIngressRouteState } = require('../services/topologyAttachIngressGate');
const { compileTopology } = require('../domain/topologyCompiler');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
const { createTopologyPppReadinessGate } = require('../services/topologyPppReadinessGate');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const freeze = value => {
    if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
    return value;
};
const configOf = plan => JSON.parse(Buffer.from(plan.nodes.find(node => node.node === plan.ownerNodeId).candidate.bytes));
const ingressRules = config => config.routing.rules.filter(rule => rule.inboundTag?.includes('cascade-mine'));
function rewrite(plan, edit) {
    const copy = structuredClone(plan), config = configOf(copy);
    edit(config);
    const owner = copy.nodes.find(node => node.node === copy.ownerNodeId);
    const bytes = Buffer.from(JSON.stringify(config) + '\n');
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    owner.candidate = { ...owner.candidate, bytes: [...bytes], sha256 }; owner.candidateHash = sha256;
    return freeze(copy);
}
function add(f, edge, modes) {
    const template = f.template;
    const link = edge === 'geo' ? { ...template, _id: id(13), bridgeNode: id(4), tunnelPort: 23500,
        tunnelUuid: '33333333-3333-4333-8333-333333333333', mode: modes[1],
        geoRouting: { enabled: true, geoip: ['ru'], domains: ['category-ru'] } }
        : { ...template, _id: id(12), portalNode: id(3), bridgeNode: id(1), tunnelPort: 23501,
            tunnelUuid: '44444444-4444-4444-8444-444444444444', mode: modes[2] };
    f.CascadeLink.rows.push(link); f.CascadeTopologyState.rows[0].revision++;
    return link._id;
}
function geoFixture(modes = ['reverse', 'reverse', 'reverse']) {
    const f = installedFixture({ mode: modes[0] });
    f.template = structuredClone(f.CascadeLink.rows[0]);
    f.users.push({ ...f.users[0], _id: id(83), login: 'kept-disabled-user', passwordEncrypted: 'kept-disabled-secret',
        ip: '10.255.30.11', enabled: false });
    return f;
}
function assertPolicy(plan) {
    const config = configOf(plan), rules = ingressRules(config);
    assert.equal(rules.length, 3, 'domain + geoip + unconditional default, not default-only routing');
    assert.deepEqual(rules[0].domain, ['geosite:category-ru']);
    assert.deepEqual(rules[1].ip, ['geoip:ru']);
    assert.equal(rules[0].outboundTag, rules[1].outboundTag);
    assert.notEqual(rules[0].outboundTag, rules[2].outboundTag, 'geo traffic must not be forced onto default');
    assert.deepEqual(Object.keys(rules[2]).sort(), ['inboundTag', 'outboundTag', 'type']);
    assert.equal(config.routing.domainStrategy, 'IPOnDemand');
    assert.deepEqual(config.inbounds.find(row => row.tag === 'cascade-mine').sniffing,
        { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true },
        'IP-addressed PPP SOCKS traffic needs route-only protocol sniffing for domain geo rules');
    assert.equal(ownedIngressRouteState(plan), 'egress_configured');
}
function assertNoExitPolicy(plan, previousPlan) {
    const config = configOf(plan), rules = ingressRules(config);
    assert.deepEqual(rules, [{ inboundTag: ['cascade-mine'], outboundTag: 'block', type: 'field' }]);
    assert.equal(config.routing.rules.indexOf(rules[0]), 0, 'explicit PPP no-exit blocks before every global/reverse selector');
    const geoTarget = ingressRules(configOf(previousPlan))[0].outboundTag;
    const transitTags = [
        ...(config.reverse?.bridges || []).map(bridge => bridge.tag),
        ...config.inbounds.filter(inbound => inbound.tag.startsWith('fwd-hop-')).map(inbound => inbound.tag),
    ];
    assert.ok(transitTags.length > 0, 'the surviving portal input still carries ordinary transit');
    for (const tag of transitTags) {
        const transit = config.routing.rules.filter(rule => rule.inboundTag?.includes(tag));
        assert.equal(transit.length, 3, 'transit retains conditional geo/domain, geoip and blocked default');
        assert.deepEqual(transit[0].domain, ['geosite:category-ru']);
        assert.deepEqual(transit[1].ip, ['geoip:ru']);
        assert.equal(transit[0].outboundTag, geoTarget); assert.equal(transit[1].outboundTag, geoTarget);
        assert.deepEqual(transit[2], { inboundTag: [tag], outboundTag: 'block', type: 'field' });
    }
    for (const bridge of config.reverse?.bridges || []) {
        const fullDomain = `full:${bridge.domain}`;
        const handshake = config.routing.rules.find(rule => rule.domain?.includes(fullDomain) && !rule.inboundTag);
        assert.ok(handshake && handshake.outboundTag.startsWith('tunnel-'), 'reverse control route survives');
        assert.ok(config.routing.rules.indexOf(handshake) < config.routing.rules.findIndex(rule => rule.domain?.includes('geosite:category-ru')),
            'ordinary transit handshake still precedes geo selection');
        // Exact full-domain control traffic, not a general Xray policy emulator.
        const controlRoute = inbound => config.routing.rules.find(rule => (!rule.inboundTag || rule.inboundTag.includes(inbound))
            && (!rule.domain || rule.domain.includes(fullDomain)) && !rule.ip);
        assert.equal(controlRoute('cascade-mine'), rules[0], 'even the handshake domain cannot escape the blocked PPP ingress');
        assert.equal(controlRoute(bridge.tag), handshake, 'the scoped PPP block cannot swallow allowed reverse control traffic');
    }
    return config;
}
function protectedData(f) {
    const { appliedTopologyRevision, replacementFence, ...state } = f.state;
    const { paths, ...group } = f.group;
    return structuredClone({ state, users: f.users, group, peer: paths.find(path => path.pathKey === 'peer'),
        independentGroup: f.CascadeRouteGroup.rows[1] });
}
function assertSettled(f, queued, events) {
    const operation = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    assert.equal(operation.status, 'succeeded');
    assert.equal(operation.v2Terminal.state, 'proven');
    assert.equal(operation.heldTopologyAdmission, false);
    assert.equal(f.NodeOperationLock.rows.length, 0);
    assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 0);
    assert.ok(events.includes('close') && events.includes('status'));
}
for (const modes of [ ['forward', 'forward', 'forward'], ['reverse', 'reverse', 'reverse'],
    ['reverse', 'forward', 'reverse'], ['forward', 'reverse', 'forward'] ]) {
    for (const order of [ ['geo', 'input'], ['input', 'geo'] ]) {
        test(`G3 installed actual V2 default->${order.join('->')} ${modes.join('/')} geo and default delete/recreate acceptance`, async t => {
            const f = geoFixture(modes), events = enableV2(f), protectedBefore = protectedData(f);
            assertSettled(f, await apply(f, id(10)), events);
            assert.equal(f.options.plans.at(-1).staged, true, 'R->B has no portal but PPP still has an exit');
            for (const edge of order) {
                assertSettled(f, await apply(f, add(f, edge, modes)), events);
                assert.deepEqual(protectedData(f), protectedBefore);
                assert.equal(f.options.prepares.at(-1).pppInternetProof, 'unverified');
            }
            assertPolicy(f.options.plans.at(-1));
            assert.equal(f.options.plans.at(-1).routeState, 'complete');
            assert.notEqual(f.options.plans.at(-1).staged, true);
            const settled = f.TopologyOperation.rows.at(-1);
            assert.deepEqual(settled.effectiveTopology.links.map(link => link.id).sort(), [id(10), id(12), id(13)].sort());
            assert.equal(settled.clientReadiness, 'unverified', 'node-side PPP readback is not end-client readiness');
            const identities = f.CascadeLink.rows.filter(row => [id(10), id(12), id(13)].includes(row._id))
                .map(row => [row._id, row.tunnelUuid]);
            // Deleting default blocks only its stable owned PPP ingress, while
            // geo remains configured for transit. Deleting geo retains the
            // default; neither action changes installed PPP credentials.
            for (const [linkId, offset] of [[id(13), 100], [id(10), 0]]) {
                const previousPlan = f.options.plans.at(-1);
                const beforeLink = structuredClone(f.CascadeLink.rows.find(row => row._id === linkId));
                const retained = f.CascadeLink.rows.filter(row => [id(10), id(12), id(13)].includes(row._id) && row._id !== linkId)
                    .map(row => [row._id, row.tunnelUuid]);
                const queued = await remove(f, linkId, linkId === id(10) ? id(90) : id(91)), result = await f.worker.run(queued.operationId);
                assert.equal(result.status, 'succeeded', JSON.stringify(result)); assertSettled(f, queued, events);
                assert.equal(f.CascadeLink.rows.some(row => row._id === linkId), false);
                const receipt = f.options.prepares.at(-1), plan = f.options.plans.at(-1);
                if (linkId === id(10)) {
                    assert.deepEqual(f.group.paths.find(path => path.pathKey === 'mine').linkIds, []);
                    assert.equal(receipt.routeState, 'no_bridge_exit'); assert.equal(receipt.pppInternetProof, 'not_applicable');
                    const config = assertNoExitPolicy(plan, previousPlan);
                    assert.equal(ownedIngressRouteState(plan), 'no_bridge_exit');
                    const owner = plan.nodes.find(node => node.node === plan.ownerNodeId);
                    t.diagnostic(JSON.stringify({ kind: 'G3-default-delete', modes, order, candidateHash: owner.candidate.sha256,
                        routing: config.routing, routeState: receipt.routeState, pppInternetProof: receipt.pppInternetProof,
                        status: result.status, terminal: f.TopologyOperation.rows.at(-1).v2Terminal.state }));
                    assert.ok(plan.effectiveTopology.links.some(link => link.id === id(13)), 'geo is retained, not default fallback');
                } else {
                    assert.deepEqual(f.group.paths.find(path => path.pathKey === 'mine').linkIds, [id(10)]);
                    assert.equal(receipt.routeState, 'egress_configured'); assert.equal(receipt.pppInternetProof, 'unverified');
                    assert.equal(ingressRules(configOf(plan)).length, 1);
                }
                for (const [keptId, uuid] of retained) assert.equal(f.CascadeLink.rows.find(row => row._id === keptId).tunnelUuid, uuid);
                assert.deepEqual(protectedData(f), protectedBefore);
                f.CascadeLink.rows.push({ ...beforeLink, status: 'pending', tunnelPort: beforeLink.tunnelPort + offset });
                f.CascadeTopologyState.rows[0].revision++;
                assertSettled(f, await apply(f, linkId), events);
                assertPolicy(f.options.plans.at(-1));
                assert.deepEqual(protectedData(f), protectedBefore);
            }
            for (const [linkId, uuid] of identities) assert.equal(f.CascadeLink.rows.find(row => row._id === linkId).tunnelUuid, uuid);
            assert.equal(f.options.gateCalls.filter(call => call === 'users').length, 7);
            assert.equal(f.options.gateCalls.filter(call => call === 'ingress').length, 7);
        });
    }
}

for (const modes of [['forward', 'forward', 'forward'], ['reverse', 'reverse', 'reverse'],
    ['forward', 'reverse', 'forward'], ['reverse', 'forward', 'reverse']]) {
    test(`source-less G3 ${modes.slice(0, 2).join('/')} actual V2 default delete/recreate preserves nonempty geo peer`, async () => {
        const f = geoFixture(modes), events = enableV2(f);
        await apply(f, id(10)); await apply(f, add(f, 'geo', modes));
        const peer = f.group.paths[1]; Object.assign(peer, { linkIds: [id(13)], enabled: true });
        const before = protectedData(f), geo = structuredClone(f.CascadeLink.rows.find(row => row._id === id(13)));
        const original = structuredClone(f.CascadeLink.rows.find(row => row._id === id(10)));
        const queued = await remove(f, id(10));
        assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded'); assertSettled(f, queued, events);
        assert.deepEqual(f.group.paths[0].linkIds, []);
        assert.equal(f.options.prepares.at(-1).pppInternetProof, 'not_applicable');
        assert.deepEqual(f.CascadeLink.rows.find(row => row._id === id(13)), geo);
        assert.deepEqual(protectedData(f), before);
        f.CascadeLink.rows.push({ ...original, status: 'pending', tunnelPort: original.tunnelPort + 100 });
        f.CascadeTopologyState.rows[0].revision++;
        assertSettled(f, await apply(f, id(10)), events);
        assertPolicy(f.options.plans.at(-1));
        assert.deepEqual(protectedData(f), before);
        assert.equal(f.options.prepares.at(-1).pppInternetProof, 'unverified');
    });
}

test('G3 no-exit block leaves a separately owned same-profile peer ingress and geo policy unchanged', async () => {
    const f = geoFixture(); await apply(f, id(10));
    await apply(f, add(f, 'geo', ['reverse', 'reverse', 'reverse']));
    await apply(f, add(f, 'input', ['reverse', 'reverse', 'reverse']));
    const previousPlan = f.options.plans.at(-1), before = structuredClone(previousPlan.effectiveTopology);
    // Explicitly modeled verified role-profile readbacks, including an already
    // installed peer ingress not owned by this operation's default path.
    for (const node of before.nodes) node.profileConfig = JSON.parse(Buffer.from(previousPlan.nodes.find(row => row.node === node.id).candidate.bytes));
    const profile = before.nodes.find(node => node.id === previousPlan.ownerNodeId).profileConfig;
    const peerIngress = { ...structuredClone(profile.inbounds.find(inbound => inbound.tag === 'cascade-mine')),
        tag: 'cascade-peer', port: require('../domain/cascadePathIngress').cascadePathIngressPort(id(60), 'peer') };
    const peerRules = ingressRules(profile).map(rule => ({ ...structuredClone(rule), inboundTag: ['cascade-peer'],
        outboundTag: ingressRules(profile)[0].outboundTag }));
    profile.inbounds.push(peerIngress); profile.routing.rules.push(...peerRules);
    const peer = before.groups[0].paths.find(path => path.pathKey === 'peer');
    Object.assign(peer, { enabled: true, linkIds: [id(13)] });
    const after = structuredClone(before);
    after.links = after.links.filter(link => link.id !== id(10));
    after.groups[0].paths.find(path => path.pathKey === 'mine').linkIds = [];
    const saved = structuredClone({ before, after });
    const composed = composeFrozenTopologyDeploymentPlan({ snapshot: after, baselineTopology: before,
        compiledTopology: compileTopology(after) });
    const config = assertNoExitPolicy({ ...composed, ownerNodeId: previousPlan.ownerNodeId }, previousPlan);
    assert.deepEqual(config.inbounds.filter(inbound => inbound.tag === 'cascade-peer'), [peerIngress]);
    assert.deepEqual(config.routing.rules.filter(rule => rule.inboundTag?.includes('cascade-peer')), peerRules);
    assert.deepEqual({ before, after }, saved, 'composition does not rewrite installed peer descriptors/readbacks');
});

function relayFragment(mode) {
    const snapshot = { nodes: [{ id: 'r1', role: 'relay' }, { id: 'r2', role: 'relay' }],
        links: [{ id: 'transit', source: 'r1', target: 'r2', mode }], groups: [] };
    const composed = composeFrozenTopologyDeploymentPlan({ snapshot, compiledTopology: compileTopology(snapshot), staged: true,
        nodeMetadata: snapshot.nodes.map((node, index) => ({ ...node, active: true, type: 'xray', ip: `192.0.2.${index + 1}`,
            xray: { security: 'none', transport: 'tcp' } })),
        linkMetadata: [{ ...snapshot.links[0], tunnelPort: 23451, tunnelUuid: '55555555-5555-4555-8555-555555555555',
            tunnelSecurity: 'none', tunnelTransport: 'tcp' }] });
    return freeze({ ...composed, effectiveTopology: snapshot });
}
function fragmentGate({ state = 'installed', dirtyUsers = false, activeOperation = false, epochDrift = false, noSync = false, unavailable = false } = {}) {
    const query = read => ({ select() { return this; }, sort() { return this; }, async lean() { return structuredClone(read()); } });
    const states = { r1: state === 'missing' ? null : state === 'installed'
        ? { node: 'r1', status: 'installed', desiredState: 'installed', secretRevision: 41 }
        : { node: 'r1', status: 'not_installed', desiredState: 'absent', secretRevision: 7 },
    r2: { node: 'r2', status: 'not_installed', desiredState: 'absent', secretRevision: 8 } };
    const calls = [], reads = {};
    const gate = createTopologyPppReadinessGate({ executionContext: context, readOnly: true,
        RelayL2tpState: { findOne: filter => query(() => { calls.push(['state', filter.node]);
            reads[filter.node] = (reads[filter.node] || 0) + 1;
            return epochDrift && reads[filter.node] > 1 ? { ...states[filter.node], secretRevision: 42 } : states[filter.node]; }) },
        L2tpUser: { find: filter => query(() => {
            calls.push(['users', filter.relayNode]);
            return filter.relayNode === 'r1' && state === 'installed' ? [{ relayNode: 'r1', enabled: true,
                desiredRevision: 41, appliedRevision: 41, syncStatus: 'synced', syncOperationId: id(81) }]
                : dirtyUsers ? [{ relayNode: filter.relayNode }] : [];
        }) },
        L2tpOperation: { findOne: filter => query(() => {
            calls.push(['operation', filter.node]);
            return filter.status?.$in ? activeOperation ? { _id: id(82) } : null : noSync ? null : {
                _id: id(81), node: 'r1', kind: 'sync_users', status: 'succeeded', plan: { operationId: id(81), relayId: 'r1', desired: { credentialRevision: 41 } } };
        }) },
        HyNode: { findById: node => query(() => ({ _id: node, active: true, type: 'xray', cascadeRole: 'relay', ssh: {} })) },
        NodeSSH: class { async exec(command) { calls.push(['exec', command]); if (unavailable) throw new Error('modeled unavailable');
            return { code: 0, stderr: '', stdout: JSON.stringify({ ok: true, code: 'USERS_VERIFIED', credentialRevision: 41,
                enabledUserCount: 1, managedUserCount: 1 }) + '\n' }; } },
    });
    return { gate, calls };
}
for (const mode of ['forward', 'reverse']) test(`relay-only ${mode} real composed staged fragment verifies installed PPP and fenced nonPPP, never blanket skips`, async () => {
    const plan = relayFragment(mode);
    assert.equal(plan.staged, true);
    assert.deepEqual(plan.nodes.map(node => node.nodeRef).sort(), ['relay-1', 'relay-2']);
    assert.ok(plan.nodes.every(node => node.role === 'relay'));
    const f = fragmentGate(), result = await f.gate.verifyPlan(plan);
    assert.deepEqual(result, { ok: true, verifiedRelayCount: 1, skippedRelayCount: 1,
        relayRevisions: [{ relayNode: 'r1', credentialRevision: 41 }],
        skippedRelayRevisions: [{ relayNode: 'r2', state: 'not_installed', desiredState: 'absent', credentialRevision: 8 }] });
    assert.equal(f.calls.filter(([kind]) => kind === 'exec').length, 1);
    assert.equal(f.calls.filter(([kind]) => kind === 'state').length, 4);
});

for (const [label, edit] of [
    ['missing graph', plan => { delete plan.effectiveTopology; }],
    ['duplicate graph node', plan => { plan.effectiveTopology.nodes[1] = plan.effectiveTopology.nodes[0]; }],
    ['foreign graph node', plan => { plan.effectiveTopology.nodes[1].id = 'foreign'; }],
    ['backward edge', plan => { plan.effectiveTopology.links[0].source = 'r2'; }],
    ['geo-only edge', plan => { plan.effectiveTopology.links[0].geo = true; }],
    ['noncanonical ref', plan => { plan.nodes[0].nodeRef = 'relay-03'; }],
]) test(`relay-only staged classification rejects ${label} before state reads`, async () => {
    const plan = structuredClone(relayFragment('reverse')); edit(plan);
    const f = fragmentGate();
    assert.deepEqual(await f.gate.verifyPlan(plan), { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
    assert.deepEqual(f.calls, []);
});
for (const [label, options, reason] of [
    ['missing upstream state', { state: 'missing' }, 'PPP_NOT_INSTALLED'],
    ['nonPPP users', { state: 'absent', dirtyUsers: true }, 'PPP_UNKNOWN'],
    ['nonPPP active operation', { state: 'absent', activeOperation: true }, 'PPP_UNKNOWN'],
    ['nonPPP credential drift', { state: 'absent', epochDrift: true }, 'PPP_UNKNOWN'],
    ['installed missing sync', { noSync: true }, 'PPP_UNKNOWN'],
    ['installed readback unavailable', { unavailable: true }, 'PPP_UNAVAILABLE'],
    ['installed epoch changes', { epochDrift: true }, 'PPP_UNKNOWN'],
]) test(`relay-only fragment refuses ${label}`, async () => {
    const f = fragmentGate(options);
    assert.deepEqual(await f.gate.verifyPlan(relayFragment('reverse')), { ok: false, verifiedRelayCount: 0, reason });
});
for (const mode of ['forward', 'reverse']) test(`relay-only ${mode} actual V2 worker carries both checked nonPPP epochs into final settlement`, async () => {
    const { fixture } = require('./cascadeAnyOrderSelectedApply.test');
    const f = fixture();
    f.HyNode.rows.find(node => node._id === id(3)).cascadeRole = 'relay';
    f.TopologyConfigOwner.rows.find(row => row.node === id(3)).profile = 'xray-bridge';
    f.CascadeLink.rows.splice(1);
    Object.assign(f.CascadeLink.rows[0], { bridgeNode: id(3), mode });
    f.RelayL2tpState.rows.push(...[id(1), id(3)].map((node, index) => ({ node,
        status: 'not_installed', desiredState: 'absent', secretRevision: 7 + index })));
    const db = f.TopologyOperation.db;
    const empty = () => ({ select() { return this; }, session() { return this; }, setOptions() { return this; },
        async lean() { return null; } });
    const users = { db, find: () => ({ select() { return this; }, async lean() { return []; } }), findOne: empty };
    const operations = { db, findOne: empty };
    const gate = createTopologyPppReadinessGate({ ...f, executionContext: context, readOnly: true,
        L2tpUser: users, L2tpOperation: operations,
        NodeSSH: class { constructor() { throw new Error('Explicit nonPPP must not use node transport'); } } });
    const events = enableV2(f); f.worker.pppReadinessGate = gate;
    Object.assign(f.worker.finalizer.repository, { L2tpUser: users, L2tpOperation: operations });
    const queued = await apply(f, id(10)); assertSettled(f, queued, events);
    const proof = f.TopologyOperation.rows[0].v2Terminal.sideEffects;
    assert.deepEqual(proof.pppProof, []);
    assert.deepEqual(proof.skippedPppProof.map(row => [row.relayNode, row.credentialRevision]).sort(), [[id(1), 7], [id(3), 8]]);
    assert.equal(f.TopologyOperation.rows[0].clientReadiness, 'unverified');
    assert.equal(f.CascadeLink.rows[0].status, 'staged');
});

const badPolicies = [
    ['conditional direct', (config, rules) => { rules[0].outboundTag = 'direct'; }],
    ['conditional freedom alias', (config, rules) => { config.outbounds.push({ tag: 'escape', protocol: 'freedom' }); rules[0].outboundTag = 'escape'; }],
    ['missing conditional target', (config, rules) => { rules[0].outboundTag = 'missing'; }],
    ['ambiguous conditional portal', (config, rules) => { config.outbounds.push({ tag: rules[0].outboundTag, protocol: 'vless' }); }],
    ['duplicate conditional portal', (config, rules) => { config.reverse.portals.push({ ...config.reverse.portals.find(row => row.tag === rules[0].outboundTag) }); }],
    ['conditional balancer', (config, rules) => { rules[0].balancerTag = 'bypass'; }],
    ['empty domain condition', (config, rules) => { rules[0].domain = []; }],
    ['malformed ip condition', (config, rules) => { rules[1].ip = 'geoip:ru'; }],
    ['extra unconditional route', (config, rules) => { delete rules[0].domain; }],
    ['missing unconditional default', (config, rules) => { config.routing.rules.splice(config.routing.rules.indexOf(rules[2]), 1); }],
    ['conditional after default', (config, rules) => { config.routing.rules.push({ ...rules[0] }); }],
    ['default direct', (config, rules) => { rules[2].outboundTag = 'direct'; }],
    ['duplicate geo rule', (config, rules) => { config.routing.rules.splice(config.routing.rules.indexOf(rules[1]), 0, structuredClone(rules[0])); }],
    ['global preempting direct', config => { config.routing.rules.unshift({ type: 'field', ip: ['203.0.113.0/24'], outboundTag: 'direct' }); }],
    ['empty-tags global preemption', config => { config.routing.rules.unshift({ type: 'field', inboundTag: [], outboundTag: 'direct' }); }],
    ['malformed inbound selector', (config, rules) => { rules[0].inboundTag = 'cascade-mine'; }],
    ['duplicate ingress selector', (config, rules) => { rules[0].inboundTag.push('cascade-mine'); }],
];
for (const [label, change] of badPolicies) test(`G3 actual worker refuses ${label} without publishing or releasing`, async () => {
    const f = geoFixture(); await apply(f, id(10));
    const before = protectedData(f), group = structuredClone(f.group);
    f.options.changePlan = plan => rewrite(plan, config => change(config, ingressRules(config)));
    const linkId = add(f, 'geo', ['reverse', 'reverse', 'reverse']);
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 8, scope: { kind: 'link.apply', linkId, linkIds: [linkId] } });
    const calls = f.options.gateCalls.length;
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'committing'); assert.equal(result.errorCode, 'INVALID_INGRESS_OPERATION');
    assert.deepEqual(f.group, group); assert.deepEqual(protectedData(f), before);
    assert.equal(f.options.gateCalls.length, calls, 'bad candidate refuses before node/PPP probes');
    assert.ok(f.NodeOperationLock.rows.length > 0);
    assert.equal(f.TopologyOperation.rows.at(-1).heldTopologyAdmission, true);
    assert.equal(f.CascadeLink.rows.find(row => row._id === linkId).appliedDescriptor, undefined);
});
for (const [label, mutate, expectedCode] of [
    ['unreadable PPP', f => { f.options.readbackOk = false; }, 'INGRESS_PPP_UNVERIFIED'],
    ['missing sync operation', f => { f.options.noSync = true; }, 'INGRESS_PPP_UNVERIFIED'],
    ['credential changes during readback', f => { f.options.onUsers = () => { f.state.secretRevision++; }; }, 'INGRESS_PPP_UNVERIFIED'],
    ['owner changes during readback', f => { f.options.onUsers = () => { f.state.activePathKey = 'peer'; }; }, 'INGRESS_PPP_UNVERIFIED'],
    ['peer policy changes during readback', f => { f.options.onUsers = () => { f.group.paths[1].priority++; }; }, 'INGRESS_OWNER_CONFLICT'],
    ['MAIN ingress wrong port', f => { f.options.changeMain = main => { main.outbounds[0].settings.servers[0].port++; }; }, 'INGRESS_UNVERIFIED'],
]) test(`G3 installed policy still checks ${label}`, async () => {
    const f = geoFixture(); await apply(f, id(10));
    const path = structuredClone(f.group.paths[0]); mutate(f);
    const linkId = add(f, 'geo', ['reverse', 'reverse', 'reverse']);
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 8, scope: { kind: 'link.apply', linkId, linkIds: [linkId] } });
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.errorCode, expectedCode); assert.equal(result.status, 'committing');
    assert.deepEqual(f.group.paths[0], path); assert.ok(f.NodeOperationLock.rows.length);
    assert.equal(f.options.prepares.length, 1);
});
