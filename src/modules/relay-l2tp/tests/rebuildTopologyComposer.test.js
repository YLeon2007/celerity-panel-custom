'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { Types } = require('mongoose');
const { composeRebuildProfiles, REBUILD_POLICY_RULE_PREFIX, syntheticTunnelSettings } = require('./helpers/rebuildComposerFixture');

const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const node = (key, role, n) => ({
    _id: key, cascadeRole: role, type: 'xray', active: true, ip: `192.0.2.${n}`, port: 24000 + n,
    xray: { inboundTag: `client-${key}`, transport: 'tcp', security: 'none', apiPort: 23000 + n },
});
const edge = (key, portalNode, bridgeNode, n, extra) => ({
    _id: key, portalNode, bridgeNode, tunnelPort: 13000 + n, tunnelUuid: id(n), _rebuildVless: syntheticTunnelSettings(n), ...extra,
});
const geo = (priority, domains = ['domain:geo.invalid'], geoip = ['ru']) => ({
    priority, geoRouting: { enabled: true, domains, geoip },
});
const route = (config, inbound, dest = '') => config.routing.rules.find(rule => (
    (!rule.inboundTag || rule.inboundTag.includes(inbound))
    && (!rule.domain || rule.domain.includes(dest)) && (!rule.ip || rule.ip.includes(dest))
))?.outboundTag ?? config.outbounds[0].tag;
const byNode = (profiles, nodeId, profile = 'main') => profiles.find(p => p.nodeId === nodeId && p.profile === profile).config;

test('actual profiles route a reverse split/merge with priorities and share relay policy with local ingress', () => {
    const nodes = [node('p', 'portal', 1), node('r', 'relay', 2), node('s', 'relay', 3), node('m', 'relay', 4),
        node('a', 'bridge', 5), node('b', 'bridge', 6), node('c', 'bridge', 7)];
    const links = [edge('ma', 'm', 'a', 1), edge('sm', 's', 'm', 2), edge('rm', 'r', 'm', 3),
        edge('ps', 'p', 's', 4, { priority: 25 }), edge('pr', 'p', 'r', 5, { priority: 10 }),
        edge('pa', 'p', 'a', 6, geo(30)), edge('pb', 'p', 'b', 7, geo(20)),
        edge('rc', 'r', 'c', 8, { priority: 110 }), edge('ra', 'r', 'a', 9, geo(80)), edge('rb', 'r', 'b', 10, geo(70))];
    const input = { nodes, links, usersByNode: { p: [{ userId: 'p-dummy', xrayUuid: id(201) }],
        r: [{ userId: 'r-dummy', xrayUuid: id(202) }] } };
    const output = composeRebuildProfiles(input);
    assert.equal(output.length, 14);
    assert.deepEqual(composeRebuildProfiles({ ...input, nodes: nodes.slice().reverse(), links: links.slice().reverse() }), output);
    const p = byNode(output, 'p');
    const r = byNode(output, 'r');
    const m = byNode(output, 'm');
    assert.equal(p.inbounds.find(i => i.tag === 'client-p').sniffing.routeOnly, false,
        'reverse payload must carry the sniffed hostname to the downstream relay geo policy');
    assert.equal(r.inbounds.find(i => i.tag === 'client-r').sniffing.routeOnly, true,
        'local geo matching does not need to replace the destination');
    assert.equal(route(p, 'client-p'), 'rebuild-rp-egress-pr');
    assert.equal(route(p, 'client-p', 'domain:geo.invalid'), 'rebuild-rp-egress-pb');
    assert.equal(route(p, 'client-p', 'geoip:ru'), 'rebuild-rp-egress-pb');
    assert.equal(route(p, 'rebuild-rp-conn-pr', 'full:pr.reverse.tunnel.internal'), 'block', 'the connector is not a payload ingress');
    assert.equal(route(r, 'rebuild-rp-ingress-pr', 'full:pr.reverse.tunnel.internal'), 'rebuild-rp-egress-rm',
        'the old control domain is no longer special on the payload path');
    assert.equal(route(r, 'rebuild-rp-ingress-pr'), 'rebuild-rp-egress-rm');
    assert.equal(route(r, 'rebuild-rp-ingress-pr', 'geoip:ru'), 'rebuild-rp-egress-rb');
    assert.equal(r.routing.domainStrategy, 'IPOnDemand');
    for (const rule of r.routing.rules.filter(rule => rule.ruleTag?.startsWith(REBUILD_POLICY_RULE_PREFIX))) {
        rule.inboundTag.push('later-local-ingress');
    }
    assert.equal(route(r, 'later-local-ingress', 'domain:geo.invalid'), 'rebuild-rp-egress-rb');
    assert.equal(route(r, 'later-local-ingress'), 'rebuild-rp-egress-rm');
    for (const tag of ['rebuild-rp-ingress-sm', 'rebuild-rp-ingress-rm']) assert.equal(route(m, tag), 'rebuild-rp-egress-ma');
    assert.equal(m.outbounds.find(outbound => outbound.tag === 'rebuild-rp-dial-sm').settings.address, nodes[2].ip);
    assert.equal(m.outbounds.find(outbound => outbound.tag === 'rebuild-rp-dial-rm').settings.address, nodes[1].ip);
    const bridge = byNode(output, 'a', 'bridge');
    assert.deepEqual(bridge.outbounds.filter(item => item.settings?.reverse).map(item => item.settings.reverse.tag),
        ['rebuild-rp-ingress-ma', 'rebuild-rp-ingress-pa', 'rebuild-rp-ingress-ra']);
    assert.equal(route(bridge, 'rebuild-rp-ingress-ra'), 'freedom');
    assert.equal(route(bridge, 'rebuild-rp-ingress-ra', 'geoip:private'), 'block');
    assert.equal(route(bridge, 'unrecognized'), 'block');
    assert.equal(route(byNode(output, 'a'), 'client-a'), 'block');
    assert.deepEqual(p.inbounds.find(i => i.tag === 'client-p').settings.clients.map(c => c.id), [id(201)]);
    assert.deepEqual(r.inbounds.find(i => i.tag === 'client-r').settings.clients.map(c => c.id), [id(202)]);
    assert.deepEqual(p.inbounds.find(i => i.tag === 'rebuild-rp-conn-pr').settings.clients,
        [{ id: id(5), reverse: { tag: 'rebuild-rp-egress-pr' } }]);
    for (const { config } of output) {
        assert.equal(config.reverse, undefined);
        assert.equal(config.routing.balancers, undefined);
        const tags = [...config.inbounds.map(i => i.tag), ...config.outbounds.map(o => o.tag),
            ...config.routing.rules.flatMap(rule => [...(rule.inboundTag ?? []), rule.outboundTag])];
        assert.ok(!tags.some(tag => /^(portal|bridge|tunnel)-/.test(tag)));
        assert.ok(!config.routing.rules.some(rule => rule.domain?.some(domain => domain.endsWith('.reverse.tunnel.internal'))));
        assert.equal(config.outbounds[0].protocol, 'blackhole');
    }
});

test('native-to-forward transit keeps client settings and matching tunnel credentials on both ends', () => {
    const p = node(new Types.ObjectId('000000000000000000000001'), 'portal', 1);
    const r = node('r', 'relay', 2);
    const b = node('b', 'bridge', 3);
    p.xray = { ...p.xray, inboundTag: 'custom-main', security: 'reality', flow: 'xtls-rprx-vision',
        realityDest: 'cover.invalid:443', realitySni: ['cover.invalid'], realityPrivateKey: 'dummy-key', realityShortIds: ['aabb'],
        extraInbounds: [{ inboundTag: 'custom-extra', port: 24443, transport: 'ws', security: 'tls', wsPath: '/fixture',
            wsHost: 'cover.invalid', alpn: ['http/1.1'] }] };
    const rev = edge('rev', p._id, 'r', 1, { muxEnabled: true, tunnelTransport: 'splithttp', xhttpPath: '/fixture-hop' });
    Object.defineProperty(rev, '_rebuildVless', { enumerable: false });
    const output = composeRebuildProfiles({ nodes: [r, b, p], links: [edge('f', 'r', 'b', 2, { mode: 'forward' }),
        rev], usersByNode: new Map([[p._id, [{ userId: 'dummy', xrayUuid: id(301) }]]]),
    panelTls: { serverName: 'cover.invalid', certificate: ['dummy-cert'], key: ['dummy-key'] } });
    const main = byNode(output, p._id.toHexString());
    const orig = main.inbounds.find(i => i.tag === 'custom-main');
    const extra = main.inbounds.find(i => i.tag === 'custom-extra');
    assert.equal(orig.port, p.port);
    assert.equal(orig.streamSettings.realitySettings.dest, 'cover.invalid:443');
    assert.deepEqual(orig.streamSettings.realitySettings.shortIds, ['aabb']);
    assert.equal(orig.settings.clients[0].flow, 'xtls-rprx-vision');
    assert.equal(extra.streamSettings.wsSettings.path, '/fixture');
    assert.deepEqual(extra.streamSettings.tlsSettings.certificates[0].certificate, ['dummy-cert']);
    assert.equal(extra.settings.clients[0].flow, undefined);
    assert.equal(extra.settings.clients[0].id, orig.settings.clients[0].id);
    assert.equal(route(main, 'custom-extra'), 'rebuild-rp-egress-rev');
    assert.equal(route(main, 'API_INBOUND'), 'API');
    const relay = byNode(output, 'r');
    const connector = main.inbounds.find(i => i.tag === 'rebuild-rp-conn-rev');
    const dialer = relay.outbounds.find(o => o.tag === 'rebuild-rp-dial-rev');
    assert.equal(connector.settings.decryption, syntheticTunnelSettings(1).decryption);
    assert.deepEqual(dialer.settings, { address: p.ip, port: connector.port, id: connector.settings.clients[0].id,
        encryption: syntheticTunnelSettings(1).encryption, reverse: { tag: 'rebuild-rp-ingress-rev' } });
    assert.equal(dialer.mux, undefined, 'native reverse multiplexes internally');
    assert.equal(connector.streamSettings.network, 'xhttp');
    assert.deepEqual(dialer.streamSettings.xhttpSettings, connector.streamSettings.xhttpSettings);
    assert.equal(route(relay, dialer.settings.reverse.tag), 'fwd-f');
    assert.equal(byNode(output, 'r', 'bridge').outbounds.length, 1);
    const forward = relay.outbounds.find(outbound => outbound.tag === 'fwd-f');
    const exit = byNode(output, 'b', 'bridge');
    const hop = exit.inbounds.find(inbound => inbound.tag === 'fwd-hop-f');
    assert.equal(forward.settings.vnext[0].port, hop.port);
    assert.equal(forward.settings.vnext[0].users[0].id, hop.settings.clients[0].id);
    assert.equal(forward.settings.vnext[0].users[0].encryption, syntheticTunnelSettings(2).encryption);
    assert.equal(hop.settings.decryption, syntheticTunnelSettings(2).decryption);
    assert.equal(route(exit, hop.tag), 'freedom');
});

test('dead and detached profiles are closed, remove stale tunnel ownership, and do not touch another component', () => {
    const nodes = [node('p', 'portal', 1), node('r', 'relay', 2), node('b', 'bridge', 3), node('u', 'portal', 4),
        node('v', 'bridge', 5)];
    nodes[0].aclRules = ['direct(all)', 'proxy(domain.invalid)', 'reject(denied.invalid)'];
    const input = { nodes, links: [edge('pr', 'p', 'r', 1, geo(10)), edge('rb', 'r', 'b', 2, { active: false }),
        edge('other', 'u', 'v', 3)], affectedNodeIds: ['b', 'r', 'p'] };
    const output = composeRebuildProfiles(input);
    assert.deepEqual([...new Set(output.map(p => p.nodeId))].sort(), ['b', 'p', 'r']);
    assert.equal(route(byNode(output, 'p'), 'client-p', 'domain:geo.invalid'), 'block');
    assert.equal(byNode(output, 'p').routing.domainStrategy, 'IPIfNonMatch', 'no geo IP lookup when no exit is possible');
    assert.equal(route(byNode(output, 'r'), 'rebuild-rp-ingress-pr'), 'block');
    for (const profile of output) assert.equal(profile.config.outbounds.some(o => o.protocol === 'freedom'), false);
    const detached = composeRebuildProfiles({ ...input, links: [] });
    for (const profile of detached) {
        assert.equal(profile.config.reverse, undefined);
        assert.equal(profile.config.inbounds.some(i => /^(rebuild-rp-|bridge-conn-|fwd-hop-)/.test(i.tag)), false);
        assert.equal(profile.config.outbounds.length, 1);
    }
});

test('rejects colliding listener ownership across MAIN and BRIDGE and missing exact tunnel credentials', () => {
    const nodes = [node('p', 'portal', 1), node('b', 'bridge', 2)];
    const link = edge('f', 'p', 'b', 2, { mode: 'forward', tunnelPort: nodes[1].port });
    assert.throws(() => composeRebuildProfiles({ nodes, links: [link] }), { code: 'REBUILD_LISTENER_COLLISION' });
    assert.throws(() => composeRebuildProfiles({ nodes, links: [{ ...link, tunnelUuid: undefined }] }),
        { code: 'REBUILD_INVALID_TUNNEL' });
    for (const mode of ['forward', 'reverse']) {
        assert.throws(() => composeRebuildProfiles({ nodes, links: [edge('no-keys', 'p', 'b', 1, { mode, _rebuildVless: undefined })] }),
            { code: 'REBUILD_INVALID_TUNNEL_KEY_SETTINGS' });
    }
    assert.throws(() => composeRebuildProfiles({ nodes, links: [edge('plaintext', 'p', 'b', 1, {
        _rebuildVless: { decryption: 'none', encryption: 'none' },
    })] }), { code: 'REBUILD_INVALID_TUNNEL_KEY_SETTINGS' });
    const relay = node('r', 'relay', 3);
    relay.xray.inboundTag = 'rebuild-rp-ingress-rev';
    assert.throws(() => composeRebuildProfiles({ nodes: [...nodes, relay], links: [edge('rev', 'p', 'r', 1)] }),
        { code: 'REBUILD_TUNNEL_TAG_COLLISION' });
});

test('geo-only relay blocks unmatched traffic; broken geo edge does not spill into another exit', () => {
    const nodes = [node('p', 'portal', 1), node('r', 'relay', 2), node('s', 'relay', 3), node('b', 'bridge', 4)];
    const links = [edge('pr', 'p', 'r', 1, { mode: 'forward' }), edge('rb', 'r', 'b', 2, geo(30)),
        edge('rs', 'r', 's', 3, geo(20, ['full:closed.invalid'], []))];
    const output = composeRebuildProfiles({ nodes, links });
    const relay = byNode(output, 'r');
    assert.equal(route(byNode(output, 'p'), 'client-p'), 'fwd-pr');
    assert.equal(route(relay, 'fwd-hop-pr', 'domain:geo.invalid'), 'rebuild-rp-egress-rb');
    assert.equal(route(relay, 'fwd-hop-pr', 'full:closed.invalid'), 'block');
    assert.equal(route(relay, 'fwd-hop-pr'), 'block');
    assert.equal(route(relay, 'client-r'), 'block');
    assert.equal(relay.outbounds[0].protocol, 'blackhole');
    assert.equal(byNode(output, 'b', 'bridge').outbounds[0].protocol, 'blackhole');
});

test('TLS tunnels use explicitly supplied certs, not ambient environment', () => {
    const nodes = [node('p', 'portal', 1), node('b', 'bridge', 2)];
    const links = [edge('tls', 'p', 'b', 1, { tunnelSecurity: 'tls', tlsServerName: 'panel.invalid', _rebuildVless: undefined })];
    assert.throws(() => composeRebuildProfiles({ nodes, links, panelTls: { serverName: 'panel.invalid' } }),
        { code: 'PANEL_CERT_UNAVAILABLE' });
    const output = composeRebuildProfiles({ nodes, links, panelTls: {
        serverName: 'panel.invalid', certificate: ['fixture-cert'], key: ['fixture-key'],
    } });
    const inbound = byNode(output, 'p').inbounds.find(item => item.tag === 'rebuild-rp-conn-tls');
    const outbound = byNode(output, 'b', 'bridge').outbounds.find(item => item.tag === 'rebuild-rp-dial-tls');
    assert.equal(inbound.streamSettings.tlsSettings.certificates[0].certificate[0], 'fixture-cert');
    assert.equal(outbound.streamSettings.tlsSettings.serverName, 'panel.invalid');
    assert.equal(outbound.streamSettings.tlsSettings.allowInsecure, undefined);
    assert.equal(inbound.settings.decryption, 'none');
    assert.equal(outbound.settings.encryption, 'none');
});

test('forward VMess retains its wire settings without VLESS keys', () => {
    const nodes = [node('p', 'portal', 1), node('b', 'bridge', 2)];
    const links = [edge('vmess', 'p', 'b', 1, { mode: 'forward', tunnelProtocol: 'vmess', muxEnabled: true,
        muxConcurrency: 4, _rebuildVless: undefined })];
    const output = composeRebuildProfiles({ nodes, links });
    const outbound = byNode(output, 'p').outbounds.find(item => item.tag === 'fwd-vmess');
    const inbound = byNode(output, 'b', 'bridge').inbounds.find(item => item.tag === 'fwd-hop-vmess');
    assert.equal(outbound.protocol, 'vmess');
    assert.equal(inbound.protocol, 'vmess');
    assert.equal(inbound.settings.decryption, undefined);
    assert.deepEqual(outbound.settings.vnext[0].users, [{ id: inbound.settings.clients[0].id, security: 'auto', alterId: 0 }]);
    assert.deepEqual(outbound.mux, { enabled: true, concurrency: 4 });
});
