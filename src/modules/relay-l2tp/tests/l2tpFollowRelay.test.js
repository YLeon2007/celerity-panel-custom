'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const mongoose = require('mongoose');
const State = require('../models/relayL2tpStateModel');
const { buildL2tpXrayFragment } = require('../services/l2tpXrayFragmentProvider');
const { applyFollowRelay, REBUILD_RELAY_INGRESS_TAG, FOLLOW_RELAY_OUTBOUND_TAG } = require('../services/l2tpFollowRelay');
const { selectL2tpRoutingMode, partitionRebuildL2tpStates } = require('../domain/l2tpRoutingSelection');

const nodeId = '000000000000000000000001';
const groupId = '000000000000000000000002';
const ppp = `relay-l2tp-${groupId}`;
const shared = 'rebuild-relay-ingress';
const port = 20001;
const tproxyPort = 12345;
const controlPlaneAddresses = ['198.51.100.7', 'Panel.Example.', '2001:db8:123::/48'];
const route = (inboundTag, outboundTag, matcher = {}) => ({ type: 'field', ...(inboundTag && { inboundTag }), outboundTag, ...matcher });
const block = { tag: 'block', protocol: 'blackhole' };
const server = { tag: 'ordinary', protocol: 'vless', listen: '0.0.0.0', port: 443, settings: { clients: [{ email: 'fixture' }] } };
const handoff = { tag: shared, protocol: 'socks', listen: '127.0.0.1', port,
    settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } };
const target = tag => ({ tag, protocol: 'vless' });

function fixture({ mode = 'forward', replacement = false, routeState = 'egress_configured' } = {}) {
    const state = { node: new mongoose.Types.ObjectId(nodeId), routeGroup: new mongoose.Types.ObjectId(groupId),
        activePathKey: 'old', status: 'installed', desiredState: 'installed', secretRevision: 17,
        routingMode: 'follow-relay', routingVersion: 1, tproxyPort, fwmark: 12, routeTable: 101 };
    const old = buildL2tpXrayFragment({ plan: { relay: { controlPlaneIps: ['old-panel.example', '198.51.100.1'] },
        group: { id: groupId }, paths: [{ pathKey: 'old', outboundTag: 'cascade-old', healthy: true }], selectedPathKey: 'old' },
    tags: { inbound: ppp, blockOutbound: 'block' }, tproxyPort });
    const main = { inbounds: [server, ...old.inbounds],
        outbounds: [{ tag: 'direct', protocol: 'freedom' }, block, ...old.outbounds,
            { tag: 'ordinary-local', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port }] } }],
        routing: { domainStrategy: 'IPIfNonMatch', rules: [route(null, 'block', { ip: ['::/0'] }), route(['ordinary'], 'ordinary-local'),
            ...old.routingRules, route([ppp, 'unrelated'], 'direct', { domain: ['full:shared-legacy.example'] }), route(null, 'direct', { network: 'tcp,udp' })] } };
    const defaultTag = mode === 'reverse' ? 'reverse-portal-fixture' : replacement ? 'new-tunnel' : 'old-tunnel';
    const geoTag = replacement ? 'new-geo' : 'old-geo';
    const reverseRule = route(null, 'reverse-dial', { domain: ['full:reverse.fixture.example'] });
    const reverse = { bridges: [{ tag: 'upstream-bridge', domain: 'reverse.fixture.example' }],
        ...(mode === 'reverse' && { portals: [{ tag: defaultTag, domain: 'exit-reverse.fixture.example' }] }) };
    const bridge = routeState === 'detached' ? null : { inbounds: [handoff], reverse,
        outbounds: [block, target('reverse-dial'), target(geoTag), ...(mode === 'reverse' ? [] : [target(defaultTag)]), { tag: 'direct', protocol: 'freedom' }],
        routing: { domainStrategy: 'IPIfNonMatch', rules: [reverseRule, route(['upstream-bridge'], 'direct'),
            route(null, 'block', { ip: ['::/0'] }),
            route([shared, 'transit'], geoTag, { domain: ['full:regional.example'] }),
            route([shared, 'transit'], geoTag, { ip: ['geoip:ru'] }),
            route([shared, 'transit'], routeState === 'no_bridge_exit' ? 'block' : defaultTag),
            route(null, 'block', { ip: ['geoip:private'] })] } };
    return { nodeId, state, main: structuredClone(main), bridge: structuredClone(bridge), routeState, controlPlaneAddresses };
}

// First-match model for these fixture selectors, NOT Xray or packet evidence.
function firstMatch(config, tag, { domain, ip, network = 'tcp' } = {}) {
    const matchIp = matcher => {
        if (matcher === 'geoip:private') return ip?.startsWith('10.') || ip?.startsWith('127.') || ip?.startsWith('fd');
        if (matcher === 'geoip:ru') return ip === '192.0.2.4';
        if (matcher === '::/0') return ip?.includes(':');
        return ip === matcher;
    };
    return config.routing.rules.find(rule => (!rule.inboundTag || rule.inboundTag.includes(tag))
        && (!rule.domain || rule.domain.includes(`full:${domain}`))
        && (!rule.ip || rule.ip.some(matchIp))
        && (!rule.network || rule.network.split(',').includes(network)))?.outboundTag;
}

test('only a versioned follow-relay selection opts in; installed legacy still requires a group', () => {
    assert.equal(selectL2tpRoutingMode({}), 'route-group');
    assert.throws(() => selectL2tpRoutingMode({ routingMode: 'follow-relay' }), { code: 'L2TP_ROUTING_SELECTION_INVALID' });
    assert.throws(() => selectL2tpRoutingMode({ routingMode: 'follow-relay', routingVersion: 2 }), { code: 'L2TP_ROUTING_SELECTION_INVALID' });
    const legacy = new State({ node: nodeId, status: 'installed', desiredState: 'installed' });
    assert.ok(legacy.validateSync().errors.routeGroup);
    const follow = new State({ node: nodeId, status: 'installed', desiredState: 'installed', routingMode: 'follow-relay', routingVersion: 1 });
    assert.equal(follow.validateSync(), undefined);
    follow.routeGroup = groupId;
    assert.equal(follow.validateSync(), undefined);
    assert.equal(String(follow.routeGroup), groupId);
    follow.routingVersion = undefined;
    assert.ok(follow.validateSync().errors.routingVersion);
});

test('rebuild dependency partition keeps installed follower visible but does not claim its legacy group', () => {
    const follow = fixture().state;
    const legacy = { ...follow, node: 'relay-peer', routingMode: 'route-group', routingVersion: undefined };
    const result = partitionRebuildL2tpStates([legacy, follow]);
    assert.deepEqual(result, { legacyStates: [legacy], followRelayStates: [follow] });
    assert.equal(String(follow.routeGroup), groupId);
    const f = fixture();
    assert.deepEqual(applyFollowRelay({ ...f, state: legacy }), { main: f.main, bridge: f.bridge, applied: false });
    assert.throws(() => applyFollowRelay({ ...f, state: { ...f.state, status: 'drifted' } }), { code: 'L2TP_FOLLOW_RELAY_NOT_INSTALLED' });
    assert.throws(() => applyFollowRelay({ ...f, state: { ...f.state, node: 'unrelated' } }), { code: 'L2TP_FOLLOW_RELAY_NOT_INSTALLED' });
});

test('PPP and ordinary main ingress join the same ordered geo/default policy; retained tproxy and unrelated rules survive', () => {
    assert.equal(REBUILD_RELAY_INGRESS_TAG, shared);
    const f = fixture();
    const before = structuredClone({ main: f.main, bridge: f.bridge });
    const result = applyFollowRelay(f);
    const { main, bridge, applied, inboundTag, routeState } = result;
    assert.equal(applied, true);
    assert.equal(routeState, 'egress_configured');
    assert.equal(inboundTag, ppp);
    assert.deepEqual(main.inbounds, before.main.inbounds);
    assert.deepEqual(main.inbounds.find(row => row.tag === ppp), before.main.inbounds[1]);
    assert.ok(!main.outbounds.some(row => row.tag === 'cascade-old'));
    assert.equal(firstMatch(main, 'unrelated', { domain: 'shared-legacy.example' }), 'direct');
    assert.equal(firstMatch(main, ppp, { domain: 'shared-legacy.example' }), FOLLOW_RELAY_OUTBOUND_TAG);
    const keys = ['old-panel.example', '198.51.100.1', 'cascade-old'];
    for (const key of keys) assert.ok(!JSON.stringify(main).includes(key));
    const socksTarget = tag => main.outbounds.find(row => row.tag === tag);
    for (const ingress of [ppp, 'ordinary']) {
        for (const network of ['udp', 'tcp']) {
            const rule = firstMatch(main, ingress, { ip: '192.0.2.4', network });
            assert.equal(socksTarget(rule)?.protocol, 'socks');
            assert.deepEqual(socksTarget(rule)?.settings?.servers, [{ address: '127.0.0.1', port }]);
        }
        const sidecarTag = bridge.inbounds.find(row => row.port === socksTarget(firstMatch(main, ingress)).settings.servers[0].port).tag;
        assert.equal(firstMatch(bridge, sidecarTag, { domain: 'regional.example' }), 'old-geo');
        assert.equal(firstMatch(bridge, sidecarTag, { ip: '192.0.2.4' }), 'old-geo');
        assert.equal(firstMatch(bridge, sidecarTag, { domain: 'default.example' }), 'old-tunnel');
    }
    assert.equal(bridge.inbounds.find(row => row.tag === shared).sniffing.routeOnly, true);
    assert.deepEqual(bridge.inbounds.find(row => row.tag === shared).sniffing.destOverride, ['http', 'tls', 'quic']);
    assert.equal(bridge.routing.domainStrategy, 'IPOnDemand');
    assert.deepEqual({ main: f.main, bridge: f.bridge }, before);
    assert.deepEqual(applyFollowRelay({ ...f, main, bridge }), result);
});

test('private, IPv6 policy, control-plane IP/domain and reverse control cannot enter shared geo/default', () => {
    const { main, bridge } = applyFollowRelay(fixture({ mode: 'reverse' }));
    for (const flow of [{ ip: '10.0.0.1' }, { ip: '198.51.100.7' }, { domain: 'panel.example' }, { domain: 'reverse.fixture.example' }, { domain: 'exit-reverse.fixture.example' }]) {
        assert.equal(bridge.outbounds.find(row => row.tag === firstMatch(bridge, shared, flow))?.protocol, 'blackhole');
        assert.equal(main.outbounds.find(row => row.tag === firstMatch(main, ppp, flow))?.protocol, 'blackhole');
    }
    assert.equal(firstMatch(bridge, shared, { ip: '2001:db8:123::1' }), 'block');
    assert.equal(firstMatch(bridge, 'upstream-bridge', { domain: 'reverse.fixture.example' }), 'reverse-dial');
    assert.equal(firstMatch(bridge, shared, { domain: 'unrelated.example' }), 'reverse-portal-fixture');
    for (const [config, tag] of [[main, ppp], [bridge, shared]]) {
        assert.ok(!config.routing.rules.some(row => row.domain && row.ip));
        assert.ok(config.routing.rules.some(row => row.inboundTag?.includes(tag) && row.ip?.includes('2001:db8:123::/48')));
    }
});

test('replacement follows fresh policy with stable handoff, without replaying old exit or control rules', () => {
    const f = fixture();
    const old = applyFollowRelay(f);
    const replacement = fixture({ replacement: true });
    const next = applyFollowRelay({ ...replacement, main: old.main });
    assert.deepEqual(next.main.outbounds, old.main.outbounds);
    assert.equal(firstMatch(next.bridge, shared, { domain: 'regional.example' }), 'new-geo');
    assert.equal(firstMatch(next.bridge, shared), 'new-tunnel');
    assert.ok(!JSON.stringify(next.bridge).includes('old-tunnel'));
    replacement.bridge.inbounds[0].port++;
    assert.throws(() => applyFollowRelay({ ...replacement, main: old.main }), { code: 'L2TP_FOLLOW_RELAY_INGRESS' });
});

test('no downstream exit blocks both shared clients and PPP; detached retains tproxy and drops without sidecar', () => {
    const old = applyFollowRelay(fixture());
    for (const routeState of ['no_bridge_exit', 'detached']) {
        const f = fixture({ routeState });
        const result = applyFollowRelay({ ...f, main: old.main });
        assert.equal(result.routeState, routeState);
        assert.equal(result.main.outbounds.find(row => row.tag === firstMatch(result.main, ppp))?.protocol, 'blackhole');
        assert.ok(!result.main.outbounds.some(row => row.tag === FOLLOW_RELAY_OUTBOUND_TAG));
        assert.deepEqual(result.main.inbounds, old.main.inbounds);
        if (routeState === 'no_bridge_exit') {
            for (const flow of [{ domain: 'regional.example' }, { ip: '192.0.2.4' }, { domain: 'reverse.fixture.example' }]) {
                assert.equal(result.bridge.outbounds.find(row => row.tag === firstMatch(result.bridge, shared, flow))?.protocol, 'blackhole');
            }
            assert.equal(firstMatch(result.bridge, 'transit', { domain: 'regional.example' }), 'old-geo');
        } else assert.equal(result.bridge, null);
        assert.deepEqual(applyFollowRelay({ ...f, main: result.main, bridge: result.bridge }), result);
        const reattached = applyFollowRelay({ ...fixture({ replacement: true }), main: result.main });
        assert.equal(firstMatch(reattached.main, ppp), FOLLOW_RELAY_OUTBOUND_TAG);
        assert.equal(firstMatch(reattached.bridge, shared), 'new-tunnel');
    }
});

test('unversioned, unsafe, ambiguous or eclipsed candidates never produce an egress handoff', () => {
    for (const edit of [
        f => { delete f.state.routingVersion; },
        f => { f.bridge.inbounds[0].listen = '0.0.0.0'; },
        f => { f.main.inbounds.push({ ...server, tag: 'collision', port }); },
        f => { f.bridge.routing.rules.unshift(route(null, 'direct', { network: 'tcp,udp' })); },
        f => { f.bridge.routing.rules.unshift(route(null, 'block', { network: 'tcp,udp' })); },
        f => { f.bridge.routing.rules.find(row => row.outboundTag === 'old-tunnel').outboundTag = 'direct'; },
        f => { f.bridge.outbounds.push(target('old-tunnel')); },
        f => { f.bridge.routing.rules = f.bridge.routing.rules.filter(row => row.outboundTag !== 'old-tunnel'); },
        f => { f.controlPlaneAddresses = ['regexp:.*']; },
        f => { f.routeState = 'detached'; },
    ]) {
        const f = fixture();
        edit(f);
        assert.throws(() => applyFollowRelay(f), { code: /^L2TP_(?:FOLLOW_RELAY|ROUTING_SELECTION)_/ });
    }
});

test('use the explicit graph-owned tag and restore only the installed tproxy when MAIN is freshly generated', () => {
    const f = fixture();
    f.state.routeGroup = null;
    f.state.activePathKey = '';
    f.main.inbounds = f.main.inbounds.filter(row => row.tag !== ppp);
    f.main.routing.rules = f.main.routing.rules.filter(row => !row.inboundTag?.includes(ppp));
    f.main.outbounds = f.main.outbounds.filter(row => row.tag !== 'cascade-old');
    f.ingressTag = 'graph-owned-relay-ingress';
    f.bridge.inbounds[0].tag = f.ingressTag;
    for (const rule of f.bridge.routing.rules) {
        if (rule.inboundTag?.includes(shared)) rule.inboundTag = rule.inboundTag.map(tag => tag === shared ? f.ingressTag : tag);
    }
    const result = applyFollowRelay(f);
    const row = result.main.inbounds.find(row => row.tag === `relay-l2tp-${nodeId}`);
    assert.deepEqual(row, { ...fixture().main.inbounds[1], tag: `relay-l2tp-${nodeId}` });
    assert.deepEqual(result.main.inbounds.find(row => row.tag === server.tag), server);
    assert.equal(firstMatch(result.bridge, f.ingressTag, { domain: 'regional.example' }), 'old-geo');
});
