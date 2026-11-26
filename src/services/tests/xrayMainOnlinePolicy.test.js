'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { deriveX25519PublicKey } = require('../../utils/xrayVlessWire');
const generator = require('../configGenerator');
const Node = require('../../models/hyNodeModel');
const { profileBytes, profileSha256 } = require('../rebuildTransport');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const { selectClassicMain } = require('../classicAppliedConfig');
const { L2tpXrayCandidateService } = require('../../modules/relay-l2tp/services/l2tpXrayCandidateService');
const { request } = require('./helpers/rebuildPanelRequest');

const id = n => n.toString(16).padStart(24, '0');
const uuid = n => `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
const user = { userId: 'fixture-subscriber', xrayUuid: uuid(1), enabled: true, hwidMode: 'off', nodes: [] };
const token = 'fixture-subscription';
const group = { _id: id(30), name: 'Fixture' };
const domain = 'panel.fixture.invalid';
const seed = Buffer.alloc(32, 42);
const usesOnline = config => config.policy?.levels?.['0']?.statsUserOnline;
const traffic = { statsUserUplink: true, statsUserDownlink: true };
const online = { ...traffic, statsUserOnline: true };
const model = (role, n, type = 'xray') => new Node({ _id: id(n), type, cascadeRole: role, active: true,
    name: role, domain: `${role}.fixture.invalid`, ip: `10.90.0.${n}`, port: 24443 + n, status: 'online',
    xray: { security: 'none', transport: 'tcp', inboundTag: 'client', apiPort: 31000 + n } });
const asInventory = node => ({ ...node.toObject({ transform: false }), _id: String(node._id), groups: [group._id] });

const selectTop = (row, fields) => Object.fromEntries(['_id', ...fields.split(/\s+/)]
    .filter(field => Object.hasOwn(row, field)).map(field => [field, structuredClone(row[field])]));

test('generated MAIN enables level 0 online only for explicit Xray client roles', () => {
    const baselines = {};
    for (const [n, role] of ['standalone', 'portal', 'relay', 'bridge'].entries()) {
        const node = model(role, n + 1);
        const bytes = generator.generateXrayConfigWithApi(node, [user]);
        const config = JSON.parse(bytes);
        const eligible = role === 'portal' || role === 'standalone';
        assert.deepEqual(config.policy.levels['0'], eligible ? online : traffic);
        assert.deepEqual(config.policy.system, {
            statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true,
        });
        assert.deepEqual(config.api.services, ['HandlerService', 'StatsService', 'RoutingService']);
        assert.deepEqual(config.stats, {});
        assert.equal(config.inbounds.find(i => i.tag === 'client').settings.clients[0].id, user.xrayUuid);
        assert.equal(config.inbounds.find(i => i.tag === 'API_INBOUND').listen, '127.0.0.1');
        assert.deepEqual(config.routing.rules[0], { inboundTag: ['API_INBOUND'], outboundTag: 'API', type: 'field' });
        if (!eligible) {
            const legacy = structuredClone(config);
            legacy.api.services.pop(); // The only intentional change to these MAINs.
            baselines[role] = profileSha256(JSON.stringify(legacy, null, 2));
        }
        assert.equal(usesOnline(JSON.parse(generator.generateXrayConfig(node, [user]))), undefined);
        const profiles = composeRebuildProfiles({ nodes: [asInventory(node)], links: [],
            usersByNode: { [String(node._id)]: [user] } });
        assert.deepEqual(profiles.find(p => p.profile === 'main').config.policy.levels['0'], eligible ? online : traffic);
        assert.equal(usesOnline(profiles.find(p => p.profile === 'bridge').config), undefined);
    }
    assert.deepEqual(baselines, classicProtected);
    const nonXray = model('portal', 5, 'hysteria');
    assert.equal(usesOnline(JSON.parse(generator.generateXrayConfigWithApi(nonXray, [user]))), undefined);
});

test('role-stripped cards do not opt in; installed classic compositions do not inherit stale policy', async () => {
    const card = asInventory(model('relay', 2));
    const fields = '_id type active ip port xray';
    const stripped = selectTop(card, fields);
    for (const node of [stripped, Node.hydrate(stripped, Object.fromEntries(fields.split(' ').map(k => [k, 1])))]) {
        assert.equal(node.cascadeRole, undefined, 'fixture must actually strip the persisted role');
        assert.equal(usesOnline(JSON.parse(generator.generateXrayConfigWithApi(node, [user]))), undefined);
    }
    for (const node of [stripped, { ...stripped, role: 'portal' }, { ...card, role: 'portal' },
        { ...card, cascadeRole: 'portal', role: 'relay' }]) {
        assert.equal(usesOnline(JSON.parse(generator.generateXrayConfigWithApi(node, [user]))), undefined);
        for (const { config } of composeRebuildProfiles({ nodes: [node], links: [] })) {
            assert.equal(usesOnline(config), undefined);
        }
    }
    const fresh = JSON.parse(generator.generateXrayConfigWithApi(card, [user]));
    const current = structuredClone(fresh);
    current.policy.levels['0'].statsUserOnline = true;
    const baseline = selectClassicMain({ node: card, current: fresh }).compose(fresh);
    assert.deepEqual(selectClassicMain({ node: card, current }).compose(fresh), baseline);

    const projected = selectTop(card, `${fields} cascadeRole`);
    const plan = { ok: true, operationId: 'fixture-op', relayId: card._id, routeGroupId: group._id,
        selectedPathKey: 'primary', nextHopNodeId: id(3), desired: { tproxyPort: 31281 } };
    let served = fresh;
    const candidate = node => new L2tpXrayCandidateService({ nodeResolver: async () => node, userResolver: async () => [user],
        configGenerator: generator.generateXrayConfigWithApi, currentConfigResolver: async () => served,
    }).buildCandidate({ plan });
    const before = await candidate(projected);
    served = current;
    const after = await candidate(projected);
    assert.equal(after.content, before.content);
    assert.deepEqual(JSON.parse(after.content).policy.levels['0'], traffic);
    await assert.rejects(candidate(stripped), { code: 'NODE_NOT_RELAY' });
    assert.equal(usesOnline(current), true, 'composing a candidate must not modify observed bytes');
});

function fixtureGraph() {
    const nodes = ['portal', 'relay', 'bridge'].map((role, i) => asInventory(model(role, i + 1)));
    Object.assign(nodes[0].xray, { security: 'reality', flow: 'xtls-rprx-vision', realityDest: 'cover.fixture.invalid:443',
        realitySni: ['cover.fixture.invalid'], realityShortIds: ['01234567'], fingerprint: 'chrome',
        realityPrivateKey: seed.toString('base64url'), realityPublicKey: deriveX25519PublicKey(seed) });
    // A bridge can have an ordinary managed VLESS inbound; it is still a bridge.
    const links = nodes.slice(1).map((target, i) => ({ _id: id(10 + i), portalNode: nodes[i]._id,
        bridgeNode: target._id, active: true, mode: 'forward', tunnelPort: 41000 + i,
        tunnelEncryption: 'none', tunnelSecurity: 'none', tunnelUuid: uuid(10 + i) }));
    const states = [{ node: nodes[1]._id, routeGroup: group._id, desiredState: 'installed', status: 'installed',
        tproxyPort: 31281, secretRevision: 1, routingMode: 'follow-relay', routingVersion: 1 }];
    const usersByNode = new Map(nodes.map(node => [node._id, [user]]));
    const controlPlaneAddresses = [domain, ...nodes.flatMap(n => [n.ip, n.domain])];
    const compose = (followRelayStates = states) => composeRebuildProfiles({ nodes, links, usersByNode,
        followRelayStates, controlPlaneAddresses });
    return { nodes, links, states, usersByNode, compose, controlPlaneAddresses };
}

test('DIRECT relay install composes against the pinned MAIN and refuses stale policy bytes', () => {
    const { composeRebuildRelayPair } = require('../rebuildRelayInstallSteps');
    const { nodes, states, compose, controlPlaneAddresses } = fixtureGraph();
    const nodeId = nodes[1]._id;
    const relay = compose([]).filter(p => p.nodeId === nodeId);
    const main = profileBytes(relay.find(p => p.profile === 'main').config);
    const bridge = profileBytes(relay.find(p => p.profile === 'bridge').config);
    const opts = { nodeId, tproxyPort: states[0].tproxyPort, carryDomain: false, controlPlaneAddresses,
        mainSha256: profileSha256(main), bridgeSha256: profileSha256(bridge) };
    const pair = composeRebuildRelayPair({ main, bridge }, opts);
    const candidate = JSON.parse(pair.main);
    assert.equal(pair.bridge, undefined);
    assert.deepEqual(candidate.policy, JSON.parse(main).policy);
    assert.deepEqual(candidate.policy.levels['0'], traffic);
    const stale = JSON.parse(main);
    stale.policy.levels['0'].statsUserOnline = true;
    assert.throws(() => composeRebuildRelayPair({ main: profileBytes(stale), bridge }, opts),
        { code: 'REBUILD_L2TP_PROFILE_PRECONDITION' });
});

// Raw serialized managed profiles, and fresh route bodies, recorded on the
// unmodified 1fb0f3e archive. Compare through the same serializers as Rebuild.
const classicProtected = {
    relay: 'd2e42049b7ee6e1f38999e3a743c96f522a3df13d1ab60518ae1fd962e9f5349',
    bridge: 'd32160a085113c655b9c185554ddb0427af1ad6aad7d698b8b46e6496587d100',
};
const rebuildProtected = {
    'portal/bridge': '3f76dce9030ac8ad74b85986721910a1b95f11e499f7694c7dc22c3d499d5d8c',
    'relay/main': '186071d548b15349d9153fafa006afd43667f635b930c882b9f4697c21facbd1',
    'relay/bridge': '3f76dce9030ac8ad74b85986721910a1b95f11e499f7694c7dc22c3d499d5d8c',
    'bridge/main': 'e74bc4fcc98bd6b9c94a275a4f9f0c7b7e62a2117ec66767ab5c475dc47a5504',
    'bridge/bridge': '9984d3f7149a8e2c554bf42a758e56f6bfddb271fcacd209cd13cde30172e21b',
};
const subscriptionSnapshots = {
    raw: 'acffcf5e4639c345fb2b8a80136744236611ea5635c0fdbc17c69a50218dc99f',
    'xray-json': '3219c87b7d30a02fd7c075a3a3770e118cd7c396639580b24597c62426f3f868',
};

test('mounted Rebuild Preview is policy-only; installed relay, bridge and subscription bytes stay unchanged', async t => {
    const express = require('express');
    const cache = require('../cacheService');
    const HyUser = require('../../models/hyUserModel');
    const { nodes, links, states, usersByNode, compose } = fixtureGraph();
    const portal = nodes[0]._id;
    const key = ({ nodeId, profile }) => `${nodes.find(n => n._id === nodeId).cascadeRole}/${profile}`;
    const isClientMain = p => p.nodeId === portal && p.profile === 'main';
    const baseline = new Map(compose().map(p => {
        if (isClientMain(p)) p.config.policy.levels['0'] = { ...traffic };
        return [key(p), profileBytes(p.config)];
    }));
    const observed = new Map(baseline);
    nodes[1].ssh = { port: 22, username: 'root' };
    let candidates, attemptedWrites = 0, renders = 0;
    const forbidden = () => { attemptedWrites++; assert.fail('Preview attempted an effect'); };
    const query = rows => ({ select() { return this; }, read() { return this; }, readConcern() { return this; },
        lean: async () => structuredClone(rows) });
    const inventory = rows => ({ find: () => query(rows), updateOne: forbidden, deleteOne: forbidden });
    t.mock.method(generator, 'buildPanelInlineCertificate', () => null);
    const connect = node => ({ async requireSupportedCore() {},
        read: async profile => JSON.parse(observed.get(key({ nodeId: node._id, profile }))),
        async checkActivation(options) { assert.equal(options.readOnly, true); },
        stagePair: forbidden, putPair: forbidden, prepareActivation: forbidden, close: async () => {},
    });
    t.mock.method(require('../rebuildTransport'), 'createBoundRelayTransport', (node, grant) => {
        assert.equal(node._id, nodes[1]._id);
        assert.equal(grant.binding.nodeId, nodes[1]._id);
        return { ...connect(node), async attest() {} };
    });
    const { createRebuildService } = require('../rebuildService');
    const { routerForRebuild } = require('../../routes/cascadeRebuild');
    const service = createRebuildService({ Node: inventory(nodes), Link: inventory(links), State: inventory(states),
        sync: { _getUsersForNode: async node => usersByNode.get(node._id) }, cache: { invalidateAllSubscriptions: forbidden },
        locks: { run: fn => fn(async () => {}) }, assertNoRelayAccountIntent: async () => {},
        env: { C3_REBUILD_ENABLED: 'true', PANEL_DOMAIN: domain, C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
            C3_REBUILD_L2TP_RELAY_ID: nodes[1]._id, C3_REBUILD_L2TP_RELAY_MACHINE_ID: 'a'.repeat(32),
            C3_REBUILD_L2TP_SSH_SHA256: 'b'.repeat(64) },
        connect,
        compose(input) { return candidates = composeRebuildProfiles(input); },
    });
    t.mock.method(cache, 'getSubscription', async () => null);
    t.mock.method(cache, 'setSubscription', async () => { renders++; });
    t.mock.method(cache, 'getSettings', async () => ({ subscription: {} }));
    t.mock.method(cache, 'getActiveNodes', async () => null);
    t.mock.method(cache, 'setActiveNodes', async () => {});
    t.mock.method(require('../uaStatsService'), 'track', () => {});
    t.mock.method(HyUser, 'findOne', filter => {
        assert.deepEqual(filter, { subscriptionToken: token });
        return { populate() { return this; }, then: resolve => resolve({ ...user, groups: [group] }) };
    });
    t.mock.method(Node, 'find', filter => {
        assert.deepEqual(filter, { active: true });
        return { select: fields => ({ lean: async () => nodes.map(row => selectTop(row, fields)) }) };
    });
    const app = express();
    app.use('/api/cascade', (req, _res, next) => { req.apiKey = { scopes: ['nodes:write'] }; next(); },
        routerForRebuild({ service, Node: inventory(nodes), Link: inventory(links) }));
    app.use('/api', require('../../routes/subscription'));
    async function render() {
        const snapshots = {};
        for (const [format, agent] of [['raw', 'Fixture/1'], ['xray-json', 'Happ/1 (Android)']]) {
            const res = await request(app, `/api/files/${token}?format=${format}`, { method: 'GET', headers: { 'user-agent': agent } });
            assert.equal(res.status, 200, format);
            assert.ok(res.body.includes('portal.fixture.invalid'));
            assert.ok(res.body.includes(user.xrayUuid));
            assert.doesNotMatch(res.body, /(?:relay|bridge)\.fixture\.invalid|statsUserOnline/);
            snapshots[format] = Buffer.from(res.body);
        }
        return snapshots;
    }
    const beforeBodies = await render();
    const preview = async () => {
        const res = await request(app, '/api/cascade/rebuild/preview', { body: { linkId: links[0]._id } });
        assert.equal(res.status, 200, res.body);
        const payload = JSON.parse(res.body);
        assert.equal(payload.allowed, true);
        assert.match(payload.previewId, /^[a-f0-9]{128}$/);
        return payload;
    };
    const result = await preview();
    const afterBodies = await render();
    assert.equal(renders, 4, 'each snapshot is a fresh generation, not a cache hit');
    assert.deepEqual(afterBodies, beforeBodies);
    const protectedDigests = Object.fromEntries(candidates.filter(p => !isClientMain(p)).map(p => {
        const legacy = structuredClone(p.config);
        if (p.profile === 'main' && legacy.api) assert.equal(legacy.api.services.pop(), 'RoutingService');
        if (key(p) === 'relay/main') {
            // The loopback API rule now precedes both pairs of PPP guards.
            // Restore only its historical position for comparison with 1fb0f3e.
            const rules = legacy.routing.rules;
            assert.deepEqual(rules[0], { inboundTag: ['API_INBOUND'], outboundTag: 'API', type: 'field' });
            const scopes = ['rebuild-relay-ingress', `relay-l2tp-${group._id}`];
            const guards = scopes.flatMap(tag => ['domain', 'ip'].map(selector => ({ tag, selector })));
            for (const [index, { tag, selector }] of guards.entries()) {
                const rule = rules[index + 1];
                assert.deepEqual(rule.inboundTag, [tag]);
                assert.equal(rule.outboundTag, 'rebuild-l2tp-block');
                assert.ok(rule[selector]?.length > 0);
            }
            rules.splice(guards.length, 0, rules.shift());
        }
        return [key(p), profileSha256(profileBytes(legacy))];
    }));
    const bodyDigests = Object.fromEntries(Object.entries(beforeBodies).map(([format, bytes]) => [format, profileSha256(bytes)]));

    for (const node of result.nodes) for (const p of node.profiles) {
        const clientMain = isClientMain({ ...p, nodeId: node.nodeId });
        assert.deepEqual(p, { profile: p.profile, change: clientMain ? 'replace' : 'unchanged',
            sections: clientMain ? ['policy'] : [], protectedChanged: false });
    }
    for (const p of candidates) {
        const bytes = baseline.get(key(p));
        if (isClientMain(p)) {
            const before = JSON.parse(bytes);
            assert.deepEqual(p.config.inbounds, before.inbounds, 'all inbounds, including protectedInterfaces, must match');
            assert.deepEqual(p.config.policy.levels['0'], online);
            before.policy.levels['0'] = { ...online };
            assert.equal(profileBytes(p.config), profileBytes(before), 'only policy changes');
        } else {
            assert.equal(profileBytes(p.config), bytes);
            assert.equal(usesOnline(p.config), undefined);
        }
    }
    assert.deepEqual(protectedDigests, rebuildProtected);
    assert.deepEqual(bodyDigests, subscriptionSnapshots);
    assert.deepEqual(observed, baseline);

    // Even an already contaminated observation must not seed the desired
    // protected profiles. Preview remains read-only and does not repair files.
    for (const name of ['relay/main', 'bridge/main', 'bridge/bridge']) {
        const stale = JSON.parse(baseline.get(name));
        stale.policy ??= { levels: { 0: {} } };
        stale.policy.levels['0'].statsUserOnline = true;
        observed.set(name, profileBytes(stale));
    }
    const stale = new Map(observed);
    await preview();
    for (const p of candidates.filter(p => !isClientMain(p))) assert.equal(profileBytes(p.config), baseline.get(key(p)));
    assert.deepEqual(observed, stale);
    assert.equal(attemptedWrites, 0);
});
