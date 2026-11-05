'use strict';
process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const generator = require('../configGenerator');
const { cascadePathIngressPort } = require('../../modules/relay-l2tp/domain/cascadePathIngress');
const relay = { _id: 'relay', name: 'relay', type: 'xray', cascadeRole: 'relay', active: true, ip: '192.0.2.2', port: 443, ssh: { privateKey: 'fixture' }, xray: { transport: 'tcp', security: 'none' } };
const upstream = { _id: 'up000001', portalNode: { _id: 'head', ip: '192.0.2.1' }, bridgeNode: 'relay', active: true, status: 'online', tunnelUuid: 'up-uuid', mode: 'reverse' };
const down = { _id: 'down0001', portalNode: 'relay', bridgeNode: { _id: 'exit', ip: '192.0.2.3' }, active: true, status: 'online', tunnelUuid: 'down-uuid', mode: 'reverse' };
const group = { _id: 'group', mode: 'reverse', paths: [{ pathKey: 'main', linkIds: [down._id], enabled: true }] };
const users = [{ userId: 'subscriber', xrayUuid: '00000000-0000-4000-8000-000000000001' }];
const uploads = [];
let live = '{}';
let sidecar = null;
let groups = [group];
let links = [upstream, down];
const query = rows => Object.assign(Promise.resolve(rows), { populate: () => query(rows), lean: async () => rows });
const matches = (row, filter) => Object.entries(filter).every(([key, value]) => {
    if (key === '_id' && value?.$in) return value.$in.map(String).includes(String(row._id));
    if (key === 'paths.linkIds') return row.paths.some(path => path.linkIds.some(id => value.$in.map(String).includes(String(id))));
    if (value?.$ne !== undefined) return String(row[key]?._id ?? row[key]) !== String(value.$ne);
    if (value?.$in) return value.$in.includes(row[key]);
    return String(row[key]?._id ?? row[key]) === String(value);
});
class SSH {
    async connect() {}
    disconnect() {}
    async uploadContent(content, path) {
        uploads.push({ content, path });
        if (path === '/usr/local/etc/xray-bridge/config.json') sidecar = content;
    }
    async exec(command) {
        if (command.includes('cat /usr/local/etc/xray-bridge/config.json')) {
            const receipt = command.match(/C3_LEGACY_DONE_[a-f0-9]+/);
            return { code: 0, stdout: (sidecar ?? 'C3_CLASSIC_PROFILE_ABSENT') + (receipt ? '\n' + receipt[0] + '\n' : ''), stderr: '' };
        }
        if (command.includes('cat /usr/local/etc/xray/config.json')) {
            const receipt = command.match(/C3_LEGACY_DONE_[a-f0-9]+/);
            return { code: 0, stdout: live + (receipt ? '\n' + receipt[0] + '\n' : ''), stderr: '' };
        }
        const receipt = command.match(/C3_LEGACY_DONE_[a-f0-9]+/);
        const stdout = command.includes('is-active') ? 'active' : '/usr/local/bin/xray';
        return { code: 0, stdout: stdout + (receipt ? '\n' + receipt[0] + '\n' : ''), stderr: '' };
    }
}
const original = Module._load;
Module._load = function(request, parent, isMain) {
    if (parent?.filename.endsWith('/syncService.js')) {
        if (request === '../models/cascadeLinkModel') return { find: filter => query(links.filter(row => matches(row, filter))) };
        if (request === '../models/hyNodeModel') return { updateOne: async () => ({}) };
        if (request === '../models/hyUserModel' || request === '../models/settingsModel') return {};
        if (request.endsWith('/relayL2tpStateModel')) return { exists: async () => true };
        if (request === './nodeSSH') return SSH;
        if (request === './topologyConfigOwnership') return { APPLIED_LINK_STATUSES: Object.freeze(['staged', 'deployed', 'online']), usesTestTopologyConfig: () => false, topologyManagesNodeConfig: async () => false };
        if (request === './cacheService' || request === './webhookService') return {};
        if (request === './nodeSetup') return {};
        if (request === '../utils/helpers') return { invalidateNodesCache: async () => {} };
        if (request === '../utils/logger') return { info() {}, warn() {}, error() {} };
    }
    if (parent?.filename.endsWith('/cascadeService.js')) {
        if (request === '../models/cascadeLinkModel') return { find: filter => query(links.filter(row => matches(row, filter))) };
        if (request.endsWith('/cascadeRouteGroupModel')) return { find: filter => query(groups.filter(row => matches(row, filter))) };
        if (request.endsWith('/relayL2tpStateModel')) return { exists: async () => true };
        if (request === '../models/hyNodeModel' || request === '../models/settingsModel') return {};
        if (request === './nodeSSH') return SSH;
        if (request === './topologyConfigOwnership') return { APPLIED_LINK_STATUSES: Object.freeze(['staged', 'deployed', 'online']), usesTestTopologyConfig: () => false, topologyManagesNodeConfig: async () => false };
        if (request === './syncService') return { _getUsersForNode: async () => users };
        if (request === './cacheService' || request === './webhookService') return {};
        if (request === '../utils/logger') return { info() {}, warn() {}, error() {} };
    }
    return original.call(this, request, parent, isMain);
};
const cascade = require('../cascadeService');
const sync = require('../syncService');
// Dynamic dependencies are loaded during each call as well.
process.on('exit', () => { Module._load = original; });

test('classic portal regeneration preserves installed L2TP sections and subscription users', async () => {
    const fragment = require('../../modules/relay-l2tp/services/l2tpXrayFragmentProvider').buildL2tpXrayFragment({
        plan: { relay: { controlPlaneIps: [relay.ip] }, group: { id: 'group' }, paths: [{ pathKey: 'main', healthy: true, outboundTag: 'cascade-main' }], selectedPathKey: 'main' },
        tags: { inbound: 'relay-l2tp-group', blockOutbound: 'block' }, tproxyPort: 12345,
    });
    live = generator.generateXrayConfigWithApi(relay, users, { fragments: [fragment] });
    uploads.length = 0;
    await cascade._deployPortalConfig(relay);
    const config = JSON.parse(uploads.find(row => row.path === '/usr/local/etc/xray/config.json').content);
    assert(config.inbounds.some(row => row.tag === 'relay-l2tp-group'));
    assert.deepEqual(config.outbounds.find(row => row.tag === 'cascade-main'), fragment.outbounds[0]);
    assert.equal(config.inbounds.find(row => row.tag === 'vless-in').settings.clients[0].id, users[0].xrayUuid);
});

for (const writer of ['sync', 'cascade']) test(`${writer}: mixed transit relay leaves reverse listeners exclusively in sidecar and preserves ordinary main data`, async t => {
    const prior = { links, groups, live, sidecar };
    const node = { ...relay,
        outbounds: [{ name: 'operator', type: 'socks5', addr: '192.0.2.99:1080' }],
        aclRules: ['operator(all)'],
        xray: { ...relay.xray, extraInbounds: [{ inboundTag: 'extra-vless', port: 8443, transport: 'tcp', security: 'none' }] },
    };
    const geo = { ...down, _id: 'down0002', tunnelPort: 10087, tunnelUuid: 'geo-uuid', geoRouting: { enabled: true, domains: ['google'], geoip: ['ru'] } };
    const forwardOut = { ...down, _id: 'fwdout01', mode: 'forward', tunnelPort: 12000 };
    const forwardIn = { ...upstream, _id: 'fwdin001', mode: 'forward', tunnelPort: 13000 };
    const fragment = require('../../modules/relay-l2tp/services/l2tpXrayFragmentProvider').buildL2tpXrayFragment({
        plan: { relay: { controlPlaneIps: [relay.ip] }, group: { id: 'group' }, paths: [{ pathKey: 'main', healthy: true, outboundTag: 'cascade-main' }], selectedPathKey: 'main' },
        tags: { inbound: 'relay-l2tp-group', blockOutbound: 'block' }, tproxyPort: 12345,
    });
    try {
        links = [upstream, { ...upstream, _id: 'up000002' }, down, geo, forwardOut, forwardIn];
        groups = [group];
        // Faithful old ordinary-Sync shape: duplicated main listeners must not
        // survive regeneration or the preservation of the installed fragment.
        const old = JSON.parse(generator.generateXrayConfigWithApi(node, users, { fragments: [fragment] }));
        generator.applyReversePortal(old, [down, geo], ['vless-in', 'extra-vless']);
        // These assertions concern already installed forward artifacts, not
        // implicit deployment of desired-only neighbors during background Sync.
        generator.applyForwardChain(old, [forwardOut], ['vless-in', 'extra-vless']);
        generator.applyForwardHopInbound(old, [forwardIn]);
        live = JSON.stringify(old);
        t.mock.method(sync, '_getUsersForNode', async () => users);
        t.mock.method(sync, 'checkXrayAgentHealth', async () => ({ online: true }));
        const secondary = JSON.parse(generator.generateRelayConfig(upstream, upstream.portalNode, [down, geo], [], [{ link: { ...upstream, _id: 'up000002' }, portal: upstream.portalNode }]));
        sidecar = JSON.stringify(secondary);
        const sidecarBefore = JSON.stringify(secondary);
        for (let repeat = 0; repeat < 2; repeat++) {
            uploads.length = 0;
            assert.equal(await (writer === 'sync' ? sync.updateXrayNodeConfig(node) : cascade._deployPortalConfig(node)), true);
            assert.deepEqual(uploads.map(row => row.path), ['/usr/local/etc/xray/config.json']);
            const main = JSON.parse(uploads[0].content);
            assert.equal(main.inbounds.filter(row => [10086, 10087].includes(row.port)).length, 0,
                'reverse downstream listeners belong only to the transit sidecar');
            assert.equal(main.reverse?.portals?.length || 0, 0);
            assert(!main.routing.rules.some(row => row.outboundTag?.startsWith('portal-') || row.balancerTag === 'cascade-balancer'));
            for (const port of [10086, 10087]) assert.equal([...main.inbounds, ...secondary.inbounds].filter(row => row.port === port).length, 1);
            for (const tag of ['vless-in', 'extra-vless', 'API_INBOUND', 'relay-l2tp-group']) {
                assert.deepEqual(main.inbounds.find(row => row.tag === tag), old.inbounds.find(row => row.tag === tag));
            }
            for (const tag of ['operator', 'cascade-main']) assert.deepEqual(main.outbounds.find(row => row.tag === tag), old.outbounds.find(row => row.tag === tag));
            assert(main.inbounds.some(row => row.port === 13000), 'unrelated forward-hop listener remains main-owned');
            assert(main.outbounds.some(row => row.tag === 'fwd-fwdout01'), 'unrelated forward chain remains main-owned');
            for (const rule of old.routing.rules.filter(row => row.inboundTag?.includes('relay-l2tp-group') || row.ruleTag === 'acl-catch-all')) {
                assert(main.routing.rules.some(row => JSON.stringify(row) === JSON.stringify(rule)));
            }
            assert.equal(JSON.stringify(secondary), sidecarBefore, 'main regeneration does not mutate or stop the sidecar');
            assert.equal(secondary.reverse.bridges.length, 2, 'both transit upstreams remain');
            live = JSON.stringify(main);
        }
    } finally { links = prior.links; groups = prior.groups; live = prior.live; sidecar = prior.sidecar; }
});

for (const writer of ['sync', 'cascade']) test(`${writer}: actual upstream mode, not declared node role, determines reverse listener profile`, async t => {
    const prior = { links, live, sidecar };
    const fragment = require('../../modules/relay-l2tp/services/l2tpXrayFragmentProvider').buildL2tpXrayFragment({
        plan: { relay: { controlPlaneIps: [relay.ip] }, group: { id: 'group' }, paths: [{ pathKey: 'main', healthy: true, outboundTag: 'cascade-main' }], selectedPathKey: 'main' },
        tags: { inbound: 'relay-l2tp-group', blockOutbound: 'block' }, tproxyPort: 12345,
    });
    t.mock.method(sync, '_getUsersForNode', async () => users);
    t.mock.method(sync, 'checkXrayAgentHealth', async () => ({ online: true }));
    try {
        for (const role of ['portal', 'relay', 'bridge', 'standalone']) {
            for (const incoming of [null, { ...upstream, mode: 'forward' }, upstream, { ...upstream, mode: undefined }, { ...upstream, active: false }]) {
                const node = { ...relay, cascadeRole: role };
                links = [down, ...(incoming ? [incoming] : [])];
                const installed = JSON.parse(generator.generateXrayConfigWithApi(node, users, { fragments: [fragment] }));
                const reverseTransit = incoming?.active === true && incoming.mode !== 'forward';
                if (!reverseTransit) generator.applyReversePortal(installed, [down], ['vless-in']);
                if (incoming?.active && incoming.mode === 'forward') generator.applyForwardHopInbound(installed, [incoming]);
                live = JSON.stringify(installed);
                sidecar = reverseTransit ? generator.generateRelayConfig(incoming, incoming.portalNode, [down]) : null;
                uploads.length = 0;
                assert.equal(await (writer === 'sync' ? sync.updateXrayNodeConfig(node) : cascade._deployPortalConfig(node)), true);
                const main = JSON.parse(uploads[0].content);
                assert.equal(main.inbounds.some(row => row.tag === 'bridge-conn-down0001'), !reverseTransit,
                    `${role}: only a real active reverse upstream transfers downstream listeners to sidecar`);
            }
        }
        if (writer === 'cascade') {
            links = [upstream, down];
            live = generator.generateXrayConfigWithApi(relay, users, { fragments: [fragment] });
            sidecar = generator.generateRelayConfig(upstream, upstream.portalNode, [down]);
            uploads.length = 0;
            await cascade._deployPortalConfig(relay, { excludeLinkIds: [upstream._id] });
            assert(JSON.parse(uploads[0].content).inbounds.some(row => row.tag === 'bridge-conn-down0001'),
                'removed upstream must not keep the remaining portal sidecar-owned');
        }
    } finally { links = prior.links; live = prior.live; sidecar = prior.sidecar; }
});

test('classic forward main upload exposes its accepted path ingress without changing tunnel credentials', async () => {
    const priorLinks = links;
    const priorGroups = groups;
    try {
        links = [{ ...down, mode: 'forward' }];
        groups = [{ ...group, mode: 'forward' }];
        const fragment = require('../../modules/relay-l2tp/services/l2tpXrayFragmentProvider').buildL2tpXrayFragment({
            plan: { relay: { controlPlaneIps: [relay.ip] }, group: { id: 'group' }, paths: [{ pathKey: 'main', healthy: true, outboundTag: 'cascade-main' }], selectedPathKey: 'main' },
            tags: { inbound: 'relay-l2tp-group', blockOutbound: 'block' }, tproxyPort: 12345,
        });
        const installed = JSON.parse(generator.generateXrayConfigWithApi(relay, users, { fragments: [fragment] }));
        generator.applyForwardChain(installed, links, ['vless-in']);
        require('../classicL2tpConfigComposition').applyClassicL2tpPathIngress(installed, {
            nodeId: relay._id, groups, links, mode: 'forward',
        });
        live = JSON.stringify(installed);
        uploads.length = 0;
        await cascade._deployPortalConfig(relay);
        const config = JSON.parse(uploads.find(row => row.path === '/usr/local/etc/xray/config.json').content);
        assert.equal(config.inbounds.find(row => row.tag === 'cascade-main').port, cascadePathIngressPort('group', 'main'));
        assert.equal(config.outbounds.find(row => row.tag === 'fwd-down0001').settings.vnext[0].users[0].id, 'down-uuid');
        assert(config.routing.rules.some(row => row.inboundTag?.includes('cascade-main') && row.outboundTag === 'fwd-down0001'));
        assert(config.routing.rules.some(row => row.inboundTag?.includes('relay-l2tp-group') && row.ip?.includes('geoip:private') && row.outboundTag === 'block'));
    } finally { links = priorLinks; groups = priorGroups; }
});

test('installed L2TP with unreadable live sections refuses before upload', async () => {
    for (const content of ['not-json', '{}']) {
        live = content;
        uploads.length = 0;
        await assert.rejects(cascade._deployPortalConfig(relay));
        assert.deepEqual(uploads, []);
    }
});

test('classic reverse relay and bridge deployment upload the selected SOCKS ingress using persisted tunnel UUID', async () => {
    // The first actual writer installs the sidecar read by the second writer.
    sidecar = null;
    for (const deploy of [
        () => cascade._deployRelayNode(relay, upstream, upstream.portalNode, [down]),
        () => cascade._deployBridgeConfig(upstream, relay, upstream.portalNode),
    ]) {
        uploads.length = 0;
        await deploy();
        const config = JSON.parse(uploads.find(row => row.path === '/usr/local/etc/xray-bridge/config.json').content);
        assert.equal(config.inbounds.find(row => row.tag === 'cascade-main')?.port, cascadePathIngressPort('group', 'main'));
        assert(config.routing.rules.some(row => row.inboundTag?.includes('cascade-main') && row.outboundTag === 'portal-down-down0001'));
        assert.equal(config.inbounds.find(row => row.tag === 'conn-down-down0001').settings.clients[0].id, 'down-uuid');
    }
});
