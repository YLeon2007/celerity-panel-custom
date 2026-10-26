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
    async uploadContent(content, path) { uploads.push({ content, path }); }
    async exec(command) {
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
    if (parent?.filename.endsWith('/cascadeService.js')) {
        if (request === '../models/cascadeLinkModel') return { find: filter => query(links.filter(row => matches(row, filter))) };
        if (request.endsWith('/cascadeRouteGroupModel')) return { find: filter => query(groups.filter(row => matches(row, filter))) };
        if (request.endsWith('/relayL2tpStateModel')) return { exists: async () => true };
        if (request === '../models/hyNodeModel' || request === '../models/settingsModel') return {};
        if (request === './nodeSSH') return SSH;
        if (request === './topologyConfigOwnership') return { usesTestTopologyConfig: () => false, topologyManagesNodeConfig: async () => false };
        if (request === './syncService') return { _getUsersForNode: async () => users };
        if (request === './cacheService' || request === './webhookService') return {};
        if (request === '../utils/logger') return { info() {}, warn() {}, error() {} };
    }
    return original.call(this, request, parent, isMain);
};
const cascade = require('../cascadeService');
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
        live = generator.generateXrayConfigWithApi(relay, users, { fragments: [fragment] });
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
