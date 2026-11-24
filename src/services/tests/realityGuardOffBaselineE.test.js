'use strict';

// (e): synthetic byte oracle from release 2946de17231502807150b3ecc1939614390807fe.
// Generated with Node v22.23.1 against the release's stock modules. The only
// allowed config change since that baseline is statsUserOnline on client MAIN.
// No panel bootstrap, listeners, persistence, cron or transport is needed.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const { Duplex } = require('node:stream');
const { createHash, createPrivateKey, createPublicKey } = require('node:crypto');

const id = n => n.toString(16).padStart(24, '0');
const uuid = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = '302e020100300506032b656e04220420'; // X25519 PKCS#8 prefix
const group = { _id: id(99), name: 'Offline E', subscriptionTitle: 'Fixture E' };
const frozen = {
    // Vectors bind the ordered artifact names, lengths and SHA-256 of exact bytes.
    'legacy-absent': '6ada9ccfd7771a546db85b51acf2c67c90880ee1c37f024f8d839bef3ba3d044',
    'created-off': '110252fb9070fa88407db741122bdea2a8fbff87cce6cde8c5194b287432a204',
    'explicit-off': '85112e3523cc4fb102c16efc9ff9b02a8557f57db25773b028853a208ff0bc9e',
    mixed: '76be9a71b117d5cefb3cf59d7509622875b8002b9fc53da37e5d94fba823754f',
};
const frozenSubscriptions = {
    'legacy-absent': 'c2da3f18269741f6a9291c5a15b6fa98364ebdb9809a17f364959210c22f6af0',
    'created-off': 'b61f70954e007471329b2da6abcaed77ae78612e1e8bd8bb6f631ad5a15cb563',
    'explicit-off': '44bee124e35735fcb30ff9856c8558068faafc21e407815a1ccdbe8a747293d2',
    mixed: '38b9f0af05669696535f44a42592d626be9bac28508cb501b64842fba76b325c',
};
const formats = { raw: 'Fixture/1', shadowrocket: 'Shadowrocket/1',
    'xray-json': 'Happ/1', 'v2ray-json': 'v2rayN/1', clash: 'Clash/1', singbox: 'sing-box/1' };

function reality(n, sni, dest = `${sni}:443`) {
    const raw = createHash('sha256').update(`public-fixture-e/${n}`).digest();
    const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from(hex, 'hex'), raw]), format: 'der', type: 'pkcs8' });
    return { realityDest: dest, realitySni: [sni], realityPrivateKey: raw.toString('base64url'),
        realityPublicKey: createPublicKey(privateKey).export({ format: 'jwk' }).x,
        realityShortIds: ['12ab34cd'] };
}
function node(n, name, role = 'standalone', selfSteal = false) {
    const domain = `${name}.fixture.invalid`;
    const inbound = role === 'portal' || role === 'standalone';
    return { _id: id(n), type: 'xray', name, cascadeRole: role, active: true, status: 'online',
        ip: `192.0.2.${n}`, domain, port: 443, rankingCoefficient: n, groups: [group._id],
        aclRules: ['reject(domain:deny.fixture.invalid)'],
        xray: { inboundTag: 'vless-in', transport: 'tcp', security: inbound ? 'reality' : 'none',
            fingerprint: 'chrome', ...(inbound && reality(n, selfSteal ? domain : 'cover.fixture.invalid',
                selfSteal ? '127.0.0.1:8443' : undefined)) } };
}
function edge(n, portalNode, bridgeNode, mode, options = {}) {
    return { _id: id(n), portalNode: id(portalNode), bridgeNode: id(bridgeNode), mode, active: true, status: 'online',
        tunnelPort: 23000 + n, tunnelUuid: uuid(n), tunnelTransport: 'tcp', tunnelEncryption: 'none',
        tunnelSecurity: mode === 'reverse' ? 'reality' : 'none',
        ...(mode === 'reverse' && reality(n, 'reverse.fixture.invalid')), ...options };
}
function replace(t, path, exports) {
    const key = require.resolve(path), previous = require.cache[key];
    require.cache[key] = { id: key, filename: key, loaded: true, exports };
    t.after(() => { if (previous) require.cache[key] = previous; else delete require.cache[key]; });
}
function request(app, format, token) {
    return new Promise((resolve, reject) => {
        // Use real Express and Node HTTP serialization without opening a socket.
        const chunks = [];
        const wire = new Duplex({ read() {}, write(chunk, _enc, done) { chunks.push(Buffer.from(chunk)); done(); } });
        const req = new http.IncomingMessage(wire);
        req.method = 'GET'; req.url = `/api/files/${token}?format=${format}`;
        req.headers = { host: 'panel.fixture.invalid', 'user-agent': formats[format] };
        const res = new http.ServerResponse(req);
        res.sendDate = false; // Only omit the transport-generated wall clock.
        res.assignSocket(wire);
        res.once('error', reject);
        res.once('finish', () => resolve({ status: res.statusCode, wire: Buffer.concat(chunks),
            length: Number(res.getHeader('Content-Length')) }));
        app(req, res);
    });
}

function configBaselineBytes(bytes, { role, profile, serialize, name }) {
    const config = JSON.parse(bytes);
    const level = config.policy?.levels?.['0'];
    const clientMain = profile === 'main' && ['portal', 'standalone'].includes(role);
    if (!clientMain) {
        assert.equal(Object.hasOwn(level ?? {}, 'statsUserOnline'), false, name);
        return Buffer.from(bytes);
    }
    assert.equal(level?.statsUserOnline, true, `${name}: client MAIN must enable online stats`);
    // Check exact serialization first, so projection cannot hide whitespace or
    // duplicate keys. After deleting the field, all remaining bytes are pinned.
    assert.ok(serialize(config) === bytes, `${name}: noncanonical config bytes`);
    delete level.statsUserOnline;
    return Buffer.from(serialize(config));
}

test('Reality Guard OFF: published /api/files and Xray config bytes against 2946de1', { timeout: 10000 }, async t => {
    let effects = 0;
    const forbidden = () => { effects++; throw new Error('unexpected network, persistence or process effect'); };
    t.mock.method(net.Socket.prototype, 'connect', forbidden);
    t.mock.method(net.Server.prototype, 'listen', forbidden);
    for (const name of ['exec', 'execFile', 'spawn', 'fork', 'execSync', 'execFileSync', 'spawnSync']) {
        t.mock.method(require('node:child_process'), name, forbidden);
    }
    const noop = () => {};
    let current;
    replace(t, '../../utils/logger', { info: noop, debug: noop, warn: noop, error: noop });
    replace(t, '../uaStatsService', { track: noop });
    replace(t, '../webhookService', { emit: forbidden });
    replace(t, '../cacheService', {
        getSettings: () => null, setSettings: noop, getActiveNodes: () => null, setActiveNodes: noop,
        getSubscription(token) { assert.equal(token, current.user.subscriptionToken); current.misses++; return null; },
        setSubscription() { current.renders++; },
    });
    const express = require('express');
    const Node = require('../../models/hyNodeModel');
    const User = require('../../models/hyUserModel');
    const Settings = require('../../models/settingsModel');
    const policyPath = '../../models/realityGuardPolicy';
    const policy = fs.existsSync(`${__dirname}/../../models/realityGuardPolicy.js`) ? require(policyPath) : null;
    t.mock.method(Settings, 'get', async () => current.settings);
    t.mock.method(User, 'findOne', query => {
        assert.deepEqual(query, { subscriptionToken: current.user.subscriptionToken });
        const q = { populate: () => q, then: resolve => resolve(current.user) };
        return q;
    });
    t.mock.method(Node, 'find', query => {
        assert.deepEqual(query, { active: true });
        return { select: paths => ({ lean: () => current.rows.filter(n => n.active).map(n =>
            Object.fromEntries(['_id', ...paths.split(' ')].filter(k => Object.hasOwn(n, k)).map(k => [k, n[k]]))) }) };
    });
    const app = express();
    app.use('/api', require('../../routes/subscription'));
    const { generateXrayConfigWithApi } = require('../configGenerator');
    const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
    const { profileBytes } = require('../rebuildTransport');
    const legacy = node(1, 'legacy');
    const created = node(2, 'new-off');
    const explicit = node(3, 'explicit-off');
    const external = node(4, 'external', 'portal');
    const self = node(5, 'self-steal', 'portal', true);
    if (policy) {
        created.xray.realityGuard = { mode: 'off' };
        explicit.xray.realityGuard = { mode: 'off', status: 'dead', reserveSnis: ['reserve.fixture.invalid'],
            allowedCidr: '192.0.2.0/24' };
        self.xray.realityGuard = { mode: 'off' };
    }
    external.xray.extraInbounds = [{ id: uuid(30), label: 'Extra XHTTP', port: 8443,
        inboundTag: 'vless-extra', transport: 'xhttp', xhttpPath: '/extra', fingerprint: 'firefox',
        security: 'reality', ...reality(30, 'extra-cover.fixture.invalid') }];
    const graph = [external, self, node(6, 'relay', 'relay'), node(7, 'exit', 'bridge'), node(8, 'geo', 'bridge')];
    const links = [edge(21, 4, 6, 'reverse'), edge(22, 5, 6, 'forward'), edge(23, 6, 7, 'forward'),
        edge(24, 6, 8, 'reverse', { geoRouting: { enabled: true, domains: ['domain:geo.fixture.invalid'] } })];
    for (const [label, nodes, globalEnabled] of [
        ['legacy-absent', [legacy], false], ['created-off', [created], false], ['explicit-off', [explicit], true],
        ['mixed', graph, false],
    ]) {
        await t.test(label, async sub => {
            const hydrated = nodes.map(n => n === created
                ? new Node(policy ? policy.withNewRealityGuard(n) : n) : Node.hydrate(n));
            for (const row of hydrated) assert.ok(!row.validateSync(), 'valid node schema');
            const rows = hydrated.map((doc, i) => {
                const persisted = JSON.parse(JSON.stringify(doc));
                // Lean reads of an old stored row do not acquire schema defaults.
                if (!Object.hasOwn(nodes[i].xray, 'realityGuard')) delete persisted.xray.realityGuard;
                else assert.equal(persisted.xray.realityGuard.mode, 'off');
                return persisted;
            });
            const settings = Settings.hydrate({ _id: 'settings', loadBalancing: { hideOffline: true },
                hwid: { enabled: false }, ...(policy && { realityGuard: { enabled: globalEnabled } }) });
            if (policy) assert.equal(settings.realityGuard.enabled, globalEnabled);
            const user = { _id: id(50), userId: 'fixture-e', username: 'fixture-e',
                xrayUuid: uuid(50), subscriptionToken: 'fixture-e-token', enabled: true,
                nodes: label === 'legacy-absent' ? [] : rows, groups: [group], hwidMode: 'off' };
            current = { user, rows, settings, misses: 0, renders: 0 };
            const clientNodes = rows.filter(row => ['standalone', 'portal'].includes(row.cascadeRole));
            const vectors = [];
            function record(name, bytes) {
                assert.ok(bytes.length > 0, name);
                const vector = `${name} ${bytes.length} ${sha256(bytes)}`;
                vectors.push(vector);
                sub.diagnostic(`vector ${label}/${vector}`);
            }
            for (const format of Object.keys(formats)) {
                const response = await request(app, format, user.subscriptionToken);
                assert.equal(response.status, 200, format);
                const split = response.wire.indexOf('\r\n\r\n');
                assert.ok(split >= 0);
                const body = response.wire.subarray(split + 4);
                assert.equal(body.length, response.length, format);
                assert.ok(body.length > 0, format);
                if (format === 'raw') {
                    const endpoints = body.toString().split('\n').map(line => new URL(line));
                    assert.deepEqual(endpoints.map(uri => `${uri.hostname}:${uri.port}`), clientNodes.flatMap(n =>
                        [n.port, ...n.xray.extraInbounds.map(inbound => inbound.port)].map(port => `${n.domain}:${port}`)));
                    assert.ok(endpoints.every(uri => uri.protocol === 'vless:' && uri.username === user.xrayUuid));
                }
                record(`subscription/${format}`, response.wire);
            }
            assert.equal(current.misses, Object.keys(formats).length);
            assert.equal(current.renders, current.misses, 'every response freshly generated, never served from Redis');
            assert.equal(sha256(vectors.join('\n')), frozenSubscriptions[label], `${label}: /api/files byte drift from 2946de1`);
            for (const row of clientNodes) {
                const config = generateXrayConfigWithApi(row, [user]);
                const listener = JSON.parse(config).inbounds.find(inbound => inbound.tag === row.xray.inboundTag);
                assert.ok(listener?.settings.clients.some(client => client.id === user.xrayUuid));
                assert.ok(listener.streamSettings.realitySettings.dest === row.xray.realityDest, 'client REALITY target retained');
                const name = `classic/${row.name}/main`;
                record(name, configBaselineBytes(config, { name, role: row.cascadeRole, profile: 'main',
                    serialize: value => JSON.stringify(value, null, 2) }));
            }
            if (label === 'mixed') {
                const profiles = composeRebuildProfiles({ nodes: rows, links,
                    usersByNode: Object.fromEntries(clientNodes.map(row => [row._id, [user]])),
                    dialerVersions: new Map(rows.map(row => [row._id, '26.11.9'])) });
                assert.equal(profiles.length, 2 * rows.length);
                assert.equal(new Set(profiles.map(p => `${p.nodeId}/${p.profile}`)).size, 2 * rows.length);
                for (const { nodeId, profile, config } of profiles) {
                    const row = rows.find(n => n._id === nodeId);
                    const name = `rebuild/${row.name}/${profile}`;
                    record(name, configBaselineBytes(profileBytes(config), { name, role: row.cascadeRole, profile, serialize: profileBytes }));
                }
            }
            assert.equal(effects, 0);
            assert.equal(sha256(vectors.join('\n')), frozen[label], `${label}: unexpected config byte drift from 2946de1`);
        });
    }
});
