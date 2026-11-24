'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Types } = require('mongoose');
const Link = require('../../models/cascadeLinkModel');
const { buildCascadeTunnelStreamSettings: stream } = require('../configGenerator');
const { composeRebuildProfiles: compose } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');

const id = n => new Types.ObjectId(n.toString(16).padStart(24, '0'));
const node = (n, cascadeRole, transport = 'tcp') => ({ _id: id(n), ip: `192.0.2.${n}`, type: 'xray', cascadeRole,
    port: 24000 + n, xray: { transport, security: 'none', apiPort: 25000 + n } });
const row = (extra = {}) => ({ _id: id(10), name: 'fixture link', portalNode: id(1), bridgeNode: id(2),
    tunnelPort: 24002, tunnelUuid: '00000000-0000-4000-8000-000000000001', tunnelTransport: 'kcp',
    tunnelEncryption: 'none', tunnelSecurity: 'none', mode: 'forward', ...extra });
const mask = s => s?.finalmask?.udp?.[0]?.settings?.value;
const secretLike = s => typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);
const byNode = (profiles, n, role) => profiles.find(p => p.nodeId === String(id(n)) && p.profile === role).config;

test('mKCP public inputs are bounded and do not accept a password or coerce arbitrary JSON', () => {
    const { CASCADE_TRANSPORTS, KCP_HEADERS, KCP_INPUT_FIELDS, sanitizeKcpInput, tunnelSocketProtocol } = require('../../utils/cascadeTransport');
    assert.deepEqual(CASCADE_TRANSPORTS, ['tcp', 'ws', 'grpc', 'xhttp', 'splithttp', 'kcp']);
    assert.deepEqual(KCP_HEADERS, ['none', 'wechat', 'dtls', 'srtp', 'wireguard']);
    assert.deepEqual(KCP_INPUT_FIELDS, ['kcpMtu', 'kcpTti', 'kcpUplinkCapacity', 'kcpDownlinkCapacity', 'kcpHeader']);
    assert.deepEqual(sanitizeKcpInput({ kcpMtu: '576', kcpTti: 100, kcpUplinkCapacity: 1, kcpDownlinkCapacity: 1000,
        kcpHeader: 'dtls', kcpPassword: 'untrusted', mtu: 999 }), {
        fields: { kcpMtu: 576, kcpTti: 100, kcpUplinkCapacity: 1, kcpDownlinkCapacity: 1000, kcpHeader: 'dtls' }, error: null,
    });
    for (const value of [null, false, true, [1000], {}, 0, 575, 1461, 576.1, '0x240', '5.76e2', ' 576', '576\n', '']) {
        const result = sanitizeKcpInput({ kcpMtu: value, kcpHeader: 'dtls' });
        assert.match(result.error, /^kcpMtu/);
        assert.deepEqual(result.fields, {});
    }
    for (const kcpHeader of ['DTLS', 'utp', 'salamander', ['dtls'], '']) {
        assert.match(sanitizeKcpInput({ kcpHeader }).error, /^kcpHeader/);
    }
    for (const fields of [{ kcpTti: 9 }, { kcpTti: 101 }, { kcpUplinkCapacity: 0 }, { kcpDownlinkCapacity: 1001 }]) {
        assert.ok(sanitizeKcpInput(fields).error);
    }
    assert.equal(tunnelSocketProtocol(row()), 'udp');
    assert.equal(tunnelSocketProtocol({ tunnelTransport: 'splithttp' }), 'tcp');
});

test('the model persists only opted-in tuning, validates raw fields and never stores a password', () => {
    const unset = new Link(row({ tunnelTransport: undefined }));
    assert.equal(unset.validateSync(), undefined);
    assert.equal(unset.tunnelTransport, 'tcp');
    assert.ok(Object.keys(unset.toObject()).every(key => !key.startsWith('kcp')));
    const set = new Link(row({ kcpMtu: 576, kcpHeader: 'wechat', kcpPassword: 'untrusted' }));
    assert.equal(set.validateSync(), undefined);
    assert.equal(set.toObject().kcpMtu, 576);
    assert.equal(set.toObject().kcpHeader, 'wechat');
    assert.equal(set.toObject().kcpPassword, undefined);
    assert.equal(Link.schema.path('kcpPassword'), undefined);
    for (const fields of [{ kcpMtu: 576.1 }, { kcpTti: null }, { kcpTti: '0x14' }, { kcpUplinkCapacity: true },
        { kcpDownlinkCapacity: 1001 }, { kcpHeader: ['dtls'] }, { kcpHeader: 'utp' }, { tunnelSecurity: 'reality' }]) {
        assert.ok(new Link(row(fields)).validateSync(), Object.keys(fields).join(','));
    }
});

test('mKCP emits the exact modern mask shape and derives from link identity, independently of public fields', () => {
    const link = row({ kcpPassword: 'untrusted' });
    const listen = stream(link, { server: true });
    assert.deepEqual(listen.kcpSettings, { mtu: 1350, tti: 20, uplinkCapacity: 100, downlinkCapacity: 100 });
    assert.equal(listen.network, 'kcp');
    assert.equal(listen.security, 'none');
    assert.deepEqual(Object.keys(listen), ['network', 'security', 'kcpSettings', 'finalmask']);
    assert.equal(listen.finalmask.udp.length, 1);
    assert.equal(listen.finalmask.udp[0].type, 'mkcp-legacy');
    assert.equal(listen.finalmask.udp[0].settings.header, '');
    assert.ok(secretLike(mask(listen)) && mask(listen) !== link.kcpPassword);
    const other = row({ _id: String(link._id), tunnelUuid: 'different-uuid', tunnelPort: 65432,
        kcpMtu: 1460, kcpTti: 10, kcpUplinkCapacity: 1000, kcpDownlinkCapacity: 1, kcpHeader: 'wireguard' });
    const dial = stream(other);
    assert.deepEqual(dial.kcpSettings, { mtu: 1460, tti: 10, uplinkCapacity: 1000, downlinkCapacity: 1 });
    assert.deepEqual(dial.finalmask.udp[1], { type: 'mkcp-legacy', settings: { header: 'wireguard', value: '' } });
    assert.ok(mask(dial) === mask(listen) && mask(stream(row({ _id: id(20) }))) !== mask(listen));
    assert.throws(() => stream(row({ _id: undefined })), { code: 'CASCADE_KCP_LINK_ID_INVALID' });
    assert.throws(() => stream(row({ kcpMtu: 0 })), { code: 'CASCADE_KCP_INPUT_INVALID' });
    assert.throws(() => stream(row({ tunnelSecurity: 'reality' })), { code: 'CASCADE_KCP_SECURITY_INVALID' });
    const preview = stream(link, { redactSecrets: true });
    assert.ok(!JSON.stringify(preview).includes(mask(listen)));
    assert.equal(mask(preview), '<redacted>');
});

test('the readback replacer hides mixed-case masks without modifying the wire', () => {
    const { redactXrayConfig } = require('../vlessServerConfig');
    const wire = stream(row({ kcpHeader: 'wechat' }));
    const secret = mask(wire);
    const config = { inbounds: [{ streamSettings: wire }], outbounds: [
        { streamSettings: { FinalMask: { UDP: [{ TYPE: 'MKCP-LEGACY', Settings: { Value: secret } }] } } },
    ] };
    const display = redactXrayConfig(JSON.stringify(config));
    assert.ok(!display.includes(secret));
    const parsed = JSON.parse(display);
    assert.equal(mask(parsed.inbounds[0].streamSettings), '<redacted>');
    assert.deepEqual(parsed.inbounds[0].streamSettings.finalmask.udp[1], wire.finalmask.udp[1]);
    assert.equal(parsed.outbounds[0].streamSettings.FinalMask.UDP[0].Settings.Value, '<redacted>');
    assert.ok(mask(wire) === secret);
});

test('real rebuild profiles wire forward and reverse mKCP with equal masks, including TLS', () => {
    const nodes = [node(1, 'portal'), node(2, 'bridge')];
    for (const mode of ['forward', 'reverse']) {
        for (const tunnelSecurity of ['none', 'tls']) {
            const link = row({ mode, tunnelSecurity, tunnelPort: 40000, rebuildTlsServerName: 'tunnel.fixture.invalid', kcpHeader: 'srtp' });
            const profiles = compose({ nodes, links: [link] });
            const listener = (mode === 'forward' ? byNode(profiles, 2, 'bridge') : byNode(profiles, 1, 'main'))
                .inbounds.find(i => i.port === link.tunnelPort);
            const outbound = (mode === 'forward' ? byNode(profiles, 1, 'main') : byNode(profiles, 2, 'bridge'))
                .outbounds.find(o => o.streamSettings?.network === 'kcp');
            const l = listener.streamSettings, d = outbound.streamSettings;
            assert.ok(secretLike(mask(l)) && mask(l) === mask(d));
            assert.deepEqual(l.kcpSettings, d.kcpSettings);
            assert.equal(l.finalmask.udp[1].settings.header, 'srtp');
            assert.equal(d.security, tunnelSecurity);
            if (tunnelSecurity === 'tls') {
                assert.equal(d.tlsSettings.serverName, link.rebuildTlsServerName);
                assert.equal(d.tlsSettings.useSystemCA, true);
                assert.ok(l.tlsSettings.certificates[0].keyFile);
            }
        }
    }
    assert.throws(() => compose({ nodes, links: [row({ tunnelSecurity: 'reality' })] }), { code: 'REBUILD_INVALID_TUNNEL' });
});

test('owner checks distinguish UDP from TCP across MAIN and BRIDGE, and reject two UDP owners', () => {
    const nodes = [node(1, 'portal'), node(2, 'bridge')];
    const settings = { bridgesWithClientInbound: new Set([String(id(2))]) };
    const profiles = compose({ nodes, links: [row()], ...settings });
    assert.equal(byNode(profiles, 2, 'main').inbounds.find(i => i.protocol === 'vless').streamSettings.network, 'tcp');
    assert.equal(byNode(profiles, 2, 'bridge').inbounds[0].streamSettings.network, 'kcp');
    assert.throws(() => compose({ nodes, links: [row({ tunnelTransport: 'tcp' })], ...settings }),
        { code: 'REBUILD_LISTENER_COLLISION' });
    const h3 = node(2, 'bridge', 'xhttp');
    Object.assign(h3.xray, { security: 'tls', tlsSource: 'acme', alpn: ['h3'] });
    assert.throws(() => compose({ nodes: [nodes[0], h3], links: [row()], ...settings }),
        { code: 'REBUILD_LISTENER_COLLISION' });
});

test('within a single profile, same-address TCP+UDP is allowed but duplicate binds are rejected', () => {
    const nodes = [node(1, 'portal'), node(2, 'bridge'), node(3, 'portal')];
    const udp = row();
    const other = row({ _id: id(11), portalNode: id(3), tunnelTransport: 'tcp' });
    const profiles = compose({ nodes, links: [udp, other] });
    assert.deepEqual(byNode(profiles, 2, 'bridge').inbounds.map(i => [i.listen, i.port, i.streamSettings.network]),
        [['0.0.0.0', udp.tunnelPort, 'kcp'], ['0.0.0.0', udp.tunnelPort, 'tcp']]);
    assert.throws(() => compose({ nodes, links: [udp, { ...other, tunnelTransport: 'kcp' }] }),
        { code: 'REBUILD_LISTENER_COLLISION' });
    assert.throws(() => compose({ nodes, links: [{ ...udp, tunnelTransport: 'tcp' }, other] }),
        { code: 'REBUILD_LISTENER_COLLISION' });
    const reverse = row({ mode: 'reverse', tunnelPort: nodes[0].xray.apiPort });
    assert.ok(byNode(compose({ nodes: nodes.slice(0, 2), links: [reverse] }), 1, 'main').inbounds
        .some(i => i.port === reverse.tunnelPort && i.streamSettings?.network === 'kcp'));
});
