'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { Types } = require('mongoose');
const { composeRebuildProfiles, REBUILD_POLICY_RULE_PREFIX } = require('../services/rebuildTopologyComposer');

const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const node = (key, role, n) => ({
    _id: key, cascadeRole: role, type: 'xray', active: true, ip: `192.0.2.${n}`, port: 24000 + n,
    xray: { inboundTag: `client-${key}`, transport: 'tcp', security: 'none', apiPort: 23000 + n },
});
const edge = (key, portalNode, bridgeNode, n, extra) => ({
    _id: key, portalNode, bridgeNode, tunnelPort: 13000 + n, tunnelUuid: id(n), ...extra,
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
    assert.equal(route(p, 'client-p'), 'portal-pr');
    assert.equal(route(p, 'client-p', 'domain:geo.invalid'), 'portal-pb');
    assert.equal(route(p, 'client-p', 'geoip:ru'), 'portal-pb');
    assert.equal(route(p, 'bridge-conn-pr', 'full:pr.reverse.tunnel.internal'), 'portal-pr');
    assert.equal(route(p, 'bridge-conn-pr'), 'block');
    assert.equal(route(r, 'client-r', 'full:pr.reverse.tunnel.internal'), 'portal-rm', 'reverse control is not a global rule');
    assert.equal(route(r, 'bridge-pr', 'full:pr.reverse.tunnel.internal'), 'tunnel-pr');
    assert.equal(route(r, 'bridge-pr'), 'portal-rm');
    assert.equal(route(r, 'bridge-pr', 'geoip:ru'), 'portal-rb');
    assert.equal(r.routing.domainStrategy, 'IPOnDemand');
    for (const rule of r.routing.rules.filter(rule => rule.ruleTag?.startsWith(REBUILD_POLICY_RULE_PREFIX))) {
        rule.inboundTag.push('later-local-ingress');
    }
    assert.equal(route(r, 'later-local-ingress', 'domain:geo.invalid'), 'portal-rb');
    assert.equal(route(r, 'later-local-ingress'), 'portal-rm');
    for (const tag of ['bridge-sm', 'bridge-rm']) assert.equal(route(m, tag), 'portal-ma');
    assert.equal(m.outbounds.find(outbound => outbound.tag === 'tunnel-sm').settings.vnext[0].address, nodes[2].ip);
    assert.equal(m.outbounds.find(outbound => outbound.tag === 'tunnel-rm').settings.vnext[0].address, nodes[1].ip);
    const bridge = byNode(output, 'a', 'bridge');
    assert.deepEqual(bridge.reverse.bridges.map(item => item.tag), ['bridge-ma', 'bridge-pa', 'bridge-ra']);
    assert.equal(route(bridge, 'bridge-ra'), 'freedom');
    assert.equal(route(bridge, 'bridge-ra', 'geoip:private'), 'block');
    assert.equal(route(bridge, 'unrecognized'), 'block');
    assert.equal(route(byNode(output, 'a'), 'client-a'), 'block');
    assert.deepEqual(p.inbounds.find(i => i.tag === 'client-p').settings.clients.map(c => c.id), [id(201)]);
    assert.deepEqual(r.inbounds.find(i => i.tag === 'client-r').settings.clients.map(c => c.id), [id(202)]);
    assert.deepEqual(p.inbounds.find(i => i.tag === 'bridge-conn-pr').settings.clients.map(c => c.id), [id(5)]);
    assert.equal(byNode(output, 'r', 'bridge').reverse, undefined);
});

test('completion uses existing per-hop forward and reverse primitives, actual Xray client settings intact', () => {
    const p = node(new Types.ObjectId('000000000000000000000001'), 'portal', 1);
    const r = node('r', 'relay', 2);
    const b = node('b', 'bridge', 3);
    p.xray = { ...p.xray, inboundTag: 'custom-main', security: 'reality', flow: 'xtls-rprx-vision',
        realityDest: 'cover.invalid:443', realitySni: ['cover.invalid'], realityPrivateKey: 'dummy-key', realityShortIds: ['aabb'],
        extraInbounds: [{ inboundTag: 'custom-extra', port: 24443, transport: 'ws', security: 'tls', wsPath: '/fixture',
            wsHost: 'cover.invalid', alpn: ['http/1.1'] }] };
    const output = composeRebuildProfiles({ nodes: [r, b, p], links: [edge('f', 'r', 'b', 2, { mode: 'forward' }),
        edge('rev', p._id, 'r', 1)], usersByNode: new Map([[p._id, [{ userId: 'dummy', xrayUuid: id(301) }]]]),
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
    assert.equal(route(main, 'custom-extra'), 'portal-rev');
    assert.equal(route(main, 'API_INBOUND'), 'API');
    const relay = byNode(output, 'r');
    assert.equal(route(relay, 'bridge-rev'), 'fwd-f');
    const forward = relay.outbounds.find(outbound => outbound.tag === 'fwd-f');
    const exit = byNode(output, 'b', 'bridge');
    const hop = exit.inbounds.find(inbound => inbound.tag === 'fwd-hop-f');
    assert.equal(forward.settings.vnext[0].port, hop.port);
    assert.equal(forward.settings.vnext[0].users[0].id, hop.settings.clients[0].id);
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
    assert.equal(route(byNode(output, 'r'), 'bridge-pr'), 'block');
    for (const profile of output) assert.equal(profile.config.outbounds.some(o => o.protocol === 'freedom'), false);
    const detached = composeRebuildProfiles({ ...input, links: [] });
    for (const profile of detached) {
        assert.equal(profile.config.reverse, undefined);
        assert.equal(profile.config.inbounds.some(i => /bridge-conn|fwd-hop/.test(i.tag)), false);
        assert.equal(profile.config.outbounds.length, 1);
    }
});

test('rejects colliding listener ownership across MAIN and BRIDGE and missing exact tunnel credentials', () => {
    const nodes = [node('p', 'portal', 1), node('b', 'bridge', 2)];
    const link = edge('f', 'p', 'b', 2, { mode: 'forward', tunnelPort: nodes[1].port });
    assert.throws(() => composeRebuildProfiles({ nodes, links: [link] }), { code: 'REBUILD_LISTENER_COLLISION' });
    assert.throws(() => composeRebuildProfiles({ nodes, links: [{ ...link, tunnelUuid: undefined }] }),
        { code: 'REBUILD_INVALID_TUNNEL' });
});

test('geo-only relay blocks unmatched traffic; broken geo edge does not spill into another exit', () => {
    const nodes = [node('p', 'portal', 1), node('r', 'relay', 2), node('s', 'relay', 3), node('b', 'bridge', 4)];
    const links = [edge('pr', 'p', 'r', 1, { mode: 'forward' }), edge('rb', 'r', 'b', 2, geo(30)),
        edge('rs', 'r', 's', 3, geo(20, ['full:closed.invalid'], []))];
    const output = composeRebuildProfiles({ nodes, links });
    const relay = byNode(output, 'r');
    assert.equal(route(byNode(output, 'p'), 'client-p'), 'fwd-pr');
    assert.equal(route(relay, 'fwd-hop-pr', 'domain:geo.invalid'), 'portal-rb');
    assert.equal(route(relay, 'fwd-hop-pr', 'full:closed.invalid'), 'block');
    assert.equal(route(relay, 'fwd-hop-pr'), 'block');
    assert.equal(route(relay, 'client-r'), 'block');
    assert.equal(relay.outbounds[0].protocol, 'blackhole');
    assert.equal(byNode(output, 'b', 'bridge').outbounds[0].protocol, 'blackhole');
});

test('TLS tunnels use explicitly supplied certs, not ambient environment', () => {
    const nodes = [node('p', 'portal', 1), node('b', 'bridge', 2)];
    const links = [edge('tls', 'p', 'b', 1, { tunnelSecurity: 'tls', tlsServerName: 'panel.invalid' })];
    assert.throws(() => composeRebuildProfiles({ nodes, links, panelTls: { serverName: 'panel.invalid' } }),
        { code: 'PANEL_CERT_UNAVAILABLE' });
    const output = composeRebuildProfiles({ nodes, links, panelTls: {
        serverName: 'panel.invalid', certificate: ['fixture-cert'], key: ['fixture-key'],
    } });
    const inbound = byNode(output, 'p').inbounds.find(item => item.tag === 'bridge-conn-tls');
    const outbound = byNode(output, 'b', 'bridge').outbounds.find(item => item.tag === 'tunnel-tls');
    assert.equal(inbound.streamSettings.tlsSettings.certificates[0].certificate[0], 'fixture-cert');
    assert.equal(outbound.streamSettings.tlsSettings.serverName, 'panel.invalid');
    assert.equal(outbound.streamSettings.tlsSettings.allowInsecure, undefined);
});
