'use strict';
process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const test = require('node:test');
const assert = require('node:assert/strict');
const generator = require('../configGenerator');
const { cascadePathIngressPort } = require('../../modules/relay-l2tp/domain/cascadePathIngress');
const { applyClassicL2tpPathIngress } = require('../classicL2tpConfigComposition');
const upstream = { _id: 'up000001', portalNode: 'head', bridgeNode: 'relay', tunnelUuid: 'up-uuid' };
const first = { _id: 'down0001', portalNode: 'relay', bridgeNode: { _id: 'middle', ip: '192.0.2.2' }, active: true, status: 'deployed', tunnelUuid: 'first-uuid', mode: 'reverse' };
const second = { _id: 'down0002', portalNode: 'middle', bridgeNode: { _id: 'exit', ip: '192.0.2.3' }, active: true, status: 'online', tunnelUuid: 'second-uuid', mode: 'reverse' };
const other = { ...first, _id: 'down0003', tunnelUuid: 'other-uuid', geoRouting: { enabled: true, domains: ['google'] } };
const group = { _id: 'group', mode: 'reverse', paths: [{ pathKey: 'chosen', enabled: true, linkIds: [first._id, second._id] }] };

test('classic forward ingress uses exact accepted suffix with existing credentials and a catch-all even on geo-tagged exit', () => {
    const links = [first, second].map(link => ({ ...link, mode: 'forward' }));
    links[1].geoRouting = { enabled: true, domains: ['google'] };
    const config = { inbounds: [], outbounds: [{ tag: 'direct', protocol: 'freedom' }], routing: { rules: [] } };
    applyClassicL2tpPathIngress(config, { nodeId: 'relay', groups: [{ ...group, mode: 'forward' }], links, mode: 'forward' });
    assert.equal(config.inbounds.find(row => row.tag === 'cascade-chosen').port, cascadePathIngressPort('group', 'chosen'));
    assert.deepEqual(config.outbounds.find(row => row.tag === 'fwd-down0002').proxySettings, { tag: 'fwd-down0001', transportLayer: true });
    assert.equal(config.outbounds.find(row => row.tag === 'fwd-down0002').settings.vnext[0].users[0].id, 'second-uuid');
    assert(config.routing.rules.some(row => row.inboundTag?.includes('cascade-chosen') && row.outboundTag === 'fwd-down0002' && !row.domain && !row.ip));
});

test('classic ingress refuses missing/unconfirmed/disconnected links, wrong egress and cross-group listener collisions', () => {
    const base = () => JSON.parse(generator.generateRelayConfig(upstream, { ip: '192.0.2.1' }, [first]));
    for (const links of [
        [first],
        [first, { ...second, status: 'pending' }],
        [first, { ...second, portalNode: 'foreign' }],
        [first, { ...second, bridgeNode: 'relay' }],
    ]) {
        assert.throws(() => applyClassicL2tpPathIngress(base(), { nodeId: 'relay', groups: [group], links, mode: 'reverse' }), { code: 'CLASSIC_L2TP_PATH_UNAVAILABLE' });
    }
    const noPortal = base();
    noPortal.reverse.portals = [];
    assert.throws(() => applyClassicL2tpPathIngress(noPortal, { nodeId: 'relay', groups: [group], links: [first, second], mode: 'reverse' }), { code: 'CLASSIC_L2TP_PATH_UNAVAILABLE' });
    assert.throws(() => applyClassicL2tpPathIngress(base(), { nodeId: 'relay', groups: [group, { ...group, _id: 'other-group' }], links: [first, second], mode: 'reverse' }), { code: 'CLASSIC_L2TP_PATH_UNAVAILABLE' });
});

const { isIP } = require('node:net');

// Fixed public-target first-match probe for the generator's actual field rules.
// The target has no reverse-handshake domain or geo classification.
function publicTargetRoute(config, inboundTag, ip, network) {
    return config.routing.rules.find(rule => (!rule.inboundTag || rule.inboundTag.includes(inboundTag))
        && (!rule.network || rule.network.split(',').includes(network))
        && !rule.domain
        && (!rule.ip || rule.ip.some(cidr => cidr === '::/0' && isIP(ip) === 6)));
}

test('canonical classic sidecar selects IPv4 path by first match while retaining fail-closed IPv6/private guards', () => {
    const config = JSON.parse(generator.generateRelayConfig(upstream, { ip: '192.0.2.1' }, [first, other], [], [
        { link: { ...upstream, _id: 'up000002' }, portal: { ip: '192.0.2.9' } },
    ]));
    const guards = config.routing.rules.filter(rule => !rule.inboundTag && rule.outboundTag === 'blackhole');
    applyClassicL2tpPathIngress(config, { nodeId: 'relay', groups: [group], links: [first, second, other], mode: 'reverse' });
    for (const network of ['tcp', 'udp']) {
        assert.equal(publicTargetRoute(config, 'cascade-chosen', '1.1.1.1', network)?.outboundTag, 'portal-down-down0001');
        assert.equal(publicTargetRoute(config, 'cascade-chosen', '2606:4700:4700::1111', network)?.outboundTag, 'blackhole');
    }
    assert.deepEqual(config.routing.rules.filter(rule => !rule.inboundTag && rule.outboundTag === 'blackhole'), guards,
        'do not delete or weaken the existing fail-closed rules');
    assert(!config.routing.rules.some(rule => rule.outboundTag === 'blackhole' && rule.network === 'tcp,udp'
        && !rule.inboundTag && !rule.ip && !rule.domain), 'canonical generator has no unconditional tcp,udp blackhole before ingress');
    assert.equal(config.reverse.bridges.length, 2);
});

test('classic reverse SOCKS ingress routes exactly to accepted first downstream portal, not geo sibling or direct', () => {
    const config = JSON.parse(generator.generateRelayConfig(upstream, { ip: '192.0.2.1' }, [first, other]));
    applyClassicL2tpPathIngress(config, { nodeId: 'relay', groups: [group], links: [first, second, other], mode: 'reverse' });
    const inbound = config.inbounds.find(row => row.tag === 'cascade-chosen');
    assert.equal(inbound?.listen, '127.0.0.1');
    assert.equal(inbound?.port, cascadePathIngressPort('group', 'chosen'));
    const matches = config.routing.rules.filter(row => row.inboundTag?.includes('cascade-chosen'));
    assert.deepEqual(matches, [{ type: 'field', inboundTag: ['cascade-chosen'], outboundTag: 'portal-down-down0001' }]);
    assert.equal(config.inbounds.find(row => row.tag === 'conn-down-down0001').settings.clients[0].id, 'first-uuid');
});
