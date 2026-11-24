'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createHash } = require('node:crypto');
const { IncomingMessage, ServerResponse } = require('node:http');
const net = require('node:net');
const { Duplex } = require('node:stream');
const childProcess = require('node:child_process');
const express = require('express');
const yaml = require('yaml');

const uuid = '00000000-0000-4000-8000-000000000042';
const group = { _id: '000000000000000000000099', name: 'Fixture' };
const user = { userId: 'fixture', username: 'fixture', password: 'fixture-password',
    subscriptionToken: 'fixture-token', xrayUuid: uuid, enabled: true, hwidMode: 'off', groups: [group],
    traffic: { tx: 42, rx: 13 }, expireAt: new Date('2099-01-02T00:00:00Z') };
const publicKey = n => Buffer.alloc(32, n).toString('base64url');
const mainPublic = publicKey(4), extraPublic = publicKey(6);
const mainClient = `mlkem768x25519plus.native.0rtt.${mainPublic}`;
const extraClient = `mlkem768x25519plus.xorpub.0rtt.${extraPublic}`;
const confidential = ['synthetic-vless-server-ciphertext', publicKey(11), 'synthetic-reality-private',
    'synthetic-agent-token', 'synthetic-manual-key', 'synthetic-access-token'];
const canaries = { vlessEncryptionPrivateKey: confidential[0], realityPrivateKey: confidential[2],
    agentToken: confidential[3], manualKey: confidential[4], accessLogs: { ingestTokenEncrypted: confidential[5] } };
const enc = (key, mode = 'native') => ({ vlessEncryption: true, vlessEncryptionAuth: 'x25519',
    vlessEncryptionMode: mode, vlessEncryptionPublicKey: key, ...canaries });
const ports = [443, 8443, 9443, 10443];
function fixtureNode() {
    return { _id: '000000000000000000000001', name: 'Fixture', type: 'xray', active: true,
        status: 'online', cascadeRole: 'standalone', domain: 'entry.fixture.invalid', ip: '192.0.2.1',
        port: 443, groups: [group._id], xray: { security: 'reality', transport: 'tcp', flow: 'xtls-rprx-vision',
            realityPublicKey: publicKey(3), realitySni: ['cover.fixture.invalid'], realityShortIds: ['01234567'],
            fingerprint: 'chrome', tlsSource: 'manual', ...canaries, extraInbounds: [
                { port: 8443, label: 'WS TLS', security: 'tls', transport: 'ws', wsPath: '/fixture', ...canaries,
                    vlessEncryptionPrivateKey: confidential[1] },
                { port: 9443, label: 'GRPC', uniqueName: true, security: 'none', transport: 'grpc', grpcServiceName: 'extra' },
                { port: 10443, label: 'XHTTP', security: 'tls', transport: 'xhttp', xhttpPath: '/extra', xhttpMode: 'packet-up' },
            ] } };
}

function replace(t, path, exports) {
    const key = require.resolve(path), previous = require.cache[key];
    require.cache[key] = { id: key, filename: key, loaded: true, exports };
    t.after(() => { if (previous) require.cache[key] = previous; else delete require.cache[key]; });
}

function request(app, { format, ua = 'Fixture/1', browser = false, path = '/api/files/fixture-token', form } = {}) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const wire = new Duplex({ read() {}, write(bytes, _enc, done) { chunks.push(Buffer.from(bytes)); done(); } });
        const req = new IncomingMessage(wire);
        req.complete = true;
        req.method = form ? 'POST' : 'GET';
        req.url = path + (format ? `?format=${format}` : '');
        req.headers = { host: 'panel.fixture.invalid', 'user-agent': ua, ...(browser && { accept: 'text/html' }) };
        if (form) {
            const body = Buffer.from(new URLSearchParams(form).toString());
            req.headers['content-type'] = 'application/x-www-form-urlencoded';
            req.headers['content-length'] = String(body.length);
            req.push(body);
            req.push(null);
        }
        const res = new ServerResponse(req);
        res.sendDate = false;
        res.assignSocket(wire);
        res.once('error', reject);
        res.once('finish', () => {
            const bytes = Buffer.concat(chunks), start = bytes.indexOf('\r\n\r\n');
            assert.ok(start >= 0);
            resolve({ status: res.statusCode, bytes, body: bytes.subarray(start + 4).toString(), headers: res.getHeaders() });
        });
        app(req, res);
    });
}

function withoutPrivate(content) {
    for (const candidate of [...confidential, 'vlessEncryptionPrivateKey', 'realityPrivateKey', 'ingestTokenEncrypted']) {
        assert.equal(content.includes(candidate), false, 'private field/value crossed a publication boundary');
    }
}

function uriPorts(body) {
    return body.split('\n').filter(line => line.startsWith('vless://')).map(line => {
        const uri = new URL(line);
        assert.equal(uri.hostname, 'entry.fixture.invalid');
        assert.equal(uri.username, uuid);
        assert.ok(uri.searchParams.getAll('encryption').length <= 1);
        return [Number(uri.port), uri.searchParams.get('encryption')];
    });
}
function xrayPorts(body, profileArray) {
    const decoded = JSON.parse(body);
    const outbounds = profileArray ? decoded.flatMap(p => p.outbounds) : decoded.outbounds;
    return outbounds.filter(o => o.protocol === 'vless').map(o => {
        const [server] = o.settings.vnext;
        assert.equal(server.users[0].id, uuid);
        return [server.port, server.users[0].encryption];
    });
}
function clashPorts(body) {
    const config = yaml.parse(body);
    assert.deepEqual(config['proxy-groups'][0].proxies, config.proxies.map(p => p.name));
    return config.proxies.map(p => [p.port, p.encryption ?? null]);
}
function singboxPorts(body) {
    const { outbounds } = JSON.parse(body);
    const vless = outbounds.filter(o => o.type === 'vless');
    const tags = vless.map(o => o.tag);
    assert.deepEqual(outbounds.find(o => o.tag === 'auto').outbounds, tags);
    assert.deepEqual(outbounds.find(o => o.tag === 'proxy').outbounds, [...tags, 'direct']);
    return vless.map(o => [o.server_port, o.encryption ?? null]);
}

function projectRoot(row, fields) {
    // Simulate the inclusion projection at the collection boundary, without
    // relying on a Mongoose schema for the sibling patch's encryption fields.
    return Object.fromEntries((fields ? ['_id', ...fields.split(/\s+/)] : Object.keys(row))
        .filter(key => Object.hasOwn(row, key)).map(key => [key, row[key]]));
}

function harness(t) {
    let effects = 0;
    const forbid = () => { effects++; throw new Error('unexpected network or process effect'); };
    t.mock.method(net.Socket.prototype, 'connect', forbid);
    t.mock.method(net.Server.prototype, 'listen', forbid);
    for (const method of ['exec', 'execFile', 'spawn', 'fork', 'execSync', 'execFileSync', 'spawnSync']) {
        t.mock.method(childProcess, method, forbid);
    }
    t.after(() => assert.equal(effects, 0));
    const noop = () => {};
    replace(t, '../../utils/logger', { debug: noop, info: noop, warn: noop, error: noop });
    replace(t, '../../services/uaStatsService', { track: noop });
    replace(t, '../../services/webhookService', { emit: forbid });
    const state = { rows: [fixtureNode()], linked: false, settings: { subscription: {} }, hits: [], writes: [] };
    const entries = new Map();
    const cache = require('../../services/cacheService');
    // Exercise the real cache serialization/key logic with an in-memory Redis driver.
    t.mock.method(cache, 'isConnected', () => true);
    const redis = cache.redis;
    cache.redis = {
        async get(key) { state.hits.push(key); return entries.get(key) ?? null; },
        async setex(key, _ttl, data) { state.writes.push(key); entries.set(key, data); },
        async del(...keys) { for (const key of keys) entries.delete(key); },
        async unlink(...keys) { for (const key of keys) entries.delete(key); },
        async scan(_cursor, _match, pattern) {
            return ['0', [...entries.keys()].filter(key => key.startsWith(pattern.slice(0, -1)))];
        },
    };
    t.after(() => { cache.redis = redis; });
    const HyNode = require('../../models/hyNodeModel');
    const HyUser = require('../../models/hyUserModel');
    const Settings = require('../../models/settingsModel');
    t.mock.method(Settings, 'get', async () => state.settings);
    t.mock.method(HyUser, 'findOne', () => {
        let nodes = [];
        const q = { populate(field, selection) {
            if (field === 'nodes' && state.linked) nodes = state.rows.map(row => projectRoot(row, selection));
            return q;
        }, then: resolve => resolve({ ...user, nodes }) };
        return q;
    });
    t.mock.method(HyNode, 'find', () => ({ select: fields => ({ lean: () => state.rows.map(row => projectRoot(row, fields)) }) }));
    const app = express();
    app.use('/api', require('../subscription'));
    return { app, state, cache, entries, Settings };
}

const matrix = {
    raw: ['Fixture/1', uriPorts], uri: ['Fixture/1', uriPorts],
    shadowrocket: ['Shadowrocket/1', body => uriPorts(Buffer.from(body, 'base64').toString())],
    'xray-json': ['Happ/1', body => xrayPorts(body, true)], 'v2ray-json': ['v2rayN/1', body => xrayPorts(body, false)],
    clash: ['Clash/1', clashPorts], yaml: ['Clash/1', clashPorts],
    singbox: ['sing-box/1', singboxPorts], json: ['sing-box/1', singboxPorts],
};
const formats = Object.keys(matrix);
const sing = format => format === 'singbox' || format === 'json';
const clash = format => format === 'clash' || format === 'yaml';
const xray = format => format === 'xray-json' || format === 'v2ray-json';
const plain = format => xray(format) ? 'none' : null;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

// Frozen from aea64e7 using this harness and the stock router. Only the HTTP
// serializer's wall-clock Date header is disabled; the complete wire is hashed.
const legacyGold = {
    'absent-grouped': '83547763ee560f0a63871afbcb2a4d7ad61fc2d6922d78d8079f2e1bce57fa26',
    'off-linked': '83547763ee560f0a63871afbcb2a4d7ad61fc2d6922d78d8079f2e1bce57fa26',
};

test('OFF and absent: fresh mounted renders match aea64e7 with three extra inbounds', async t => {
    const { app, state, cache } = harness(t);
    for (const label of Object.keys(legacyGold)) {
        state.linked = label === 'off-linked';
        if (state.linked) {
            const { xray: row } = state.rows[0];
            for (const inbound of [row, ...row.extraInbounds]) inbound.vlessEncryption = false;
            state.settings.subscription.singboxVlessEncryption = false;
        }
        await cache.invalidateSettings();
        await cache.invalidateAllSubscriptions();
        const baseline = [];
        const before = state.writes.filter(key => key.startsWith('sub:')).length;
        for (const format of formats) {
            const [ua, decode] = matrix[format];
            const reply = await request(app, { format, ua });
            assert.equal(reply.status, 200, format);
            assert.deepEqual(decode(reply.body), ports.map(port => [port, plain(format)]), format);
            baseline.push(`${format} ${reply.bytes.length} ${sha(reply.bytes)}`);
        }
        const html = await request(app, { browser: true, ua: 'Mozilla/5.0' });
        assert.equal(html.status, 200);
        assert.match(html.body, /Fixture \(WS TLS\)/);
        assert.match(html.body, /GRPC/);
        assert.match(html.body, /Fixture \(XHTTP\)/);
        baseline.push(`html ${html.bytes.length} ${sha(html.bytes)}`);
        assert.equal(state.writes.filter(key => key.startsWith('sub:')).length - before, formats.length);
        t.diagnostic(`${label} ${sha(baseline.join('\n'))}`);
        assert.equal(sha(baseline.join('\n')), legacyGold[label]);
    }
});

test('mixed main/extras: actual subscription formats publish only compatible, usable inbounds', async t => {
    const { app, state, entries, cache } = harness(t);
    const { xray: row } = state.rows[0];
    entries.set('nodes:active', JSON.stringify(state.rows)); // legacy shape retained in Redis
    entries.set('sub:fixture-token:raw', JSON.stringify({ content: 'obsolete unencrypted payload' }));
    Object.assign(row, enc(mainPublic));
    Object.assign(row.extraInbounds[0], enc(extraPublic, 'xorpub'), { vlessEncryptionPrivateKey: confidential[1] });
    Object.assign(row.extraInbounds[1], enc('broken-key'));
    for (const format of formats) {
        const [ua, decode] = matrix[format];
        const reply = await request(app, { format, ua });
        assert.equal(reply.status, 200, format);
        const expected = sing(format) || clash(format) ? [] : [[443, mainClient], [8443, extraClient]];
        assert.deepEqual(decode(reply.body), [...expected, [10443, plain(format)]], format);
        withoutPrivate(format === 'shadowrocket' ? Buffer.from(reply.body, 'base64').toString() : reply.body);
    }
    const html = await request(app, { browser: true, ua: 'Mozilla/5.0' });
    assert.equal(html.status, 200);
    assert.ok(html.body.includes(mainClient) && html.body.includes(extraClient));
    assert.ok(!html.body.includes(':9443?'));
    withoutPrivate(html.body);
    assert.ok(!state.hits.includes('nodes:active') && !state.hits.includes('sub:fixture-token:raw'));
    const inventory = [...entries.entries()].find(([key]) => key.startsWith('nodes:active:'))?.[1];
    assert.ok(inventory);
    assert.ok(inventory.includes(mainPublic) && inventory.includes(extraPublic));
    for (const [key, data] of entries) if (key.includes('+vless-v1') || key.startsWith('nodes:active:')) withoutPrivate(data);
    await cache.invalidateNodes();
    assert.ok(![...entries.keys()].some(key => key.startsWith('nodes:active')));

    // Switch to a corrupt main, valid extra, same token. No `none` downgrade or
    // stale main response is allowed even if the linked user's cache is warm.
    state.linked = true;
    row.vlessEncryptionMode = 'broken-mode';
    const [ua, decode] = matrix['xray-json'];
    const reply = await request(app, { format: 'xray-json', ua });
    assert.equal(reply.status, 200);
    assert.deepEqual(decode(reply.body), [[8443, extraClient], [10443, 'none']]);
});


test('Clash restricts upstream encryption syntax to known compatible Mihomo; cache variants do not cross', async t => {
    const { app, state } = harness(t);
    Object.assign(state.rows[0].xray, enc(mainPublic));
    const plainClash = ports.slice(1).map(port => [port, null]);
    for (const [ua, expected] of [
        ['Mihomo/1.19.13', [[443, mainClient], ...plainClash]],
        ['Mihomo/1.19.12', plainClash], ['Clash/1.19.13', plainClash],
        ['Mihomo', plainClash], ['Mihomo/1.19.13-rc.1', plainClash],
        ['Clash/1 (Mihomo/v1.20.0)', [[443, mainClient], ...plainClash]],
    ]) {
        const reply = await request(app, { format: 'clash', ua });
        assert.equal(reply.status, 200);
        assert.deepEqual(clashPorts(reply.body), expected, ua);
        withoutPrivate(reply.body);
    }
});

test('no compatible endpoint yields 503 rather than an unencrypted or direct-only config', async t => {
    const { app, state } = harness(t);
    state.linked = true;
    const { xray: row } = state.rows[0];
    Object.assign(row, enc(mainPublic), { extraInbounds: [] });
    for (const format of ['clash', 'yaml', 'singbox', 'json']) {
        const reply = await request(app, { format, ua: matrix[format][0] });
        assert.equal(reply.status, 503);
        assert.equal(reply.body, '# No compatible servers available');
    }
    for (const broken of [{ vlessEncryption: 'true' }, { vlessEncryption: true, vlessEncryptionPublicKey: '' }]) {
        Object.assign(row, broken);
        for (const format of formats) assert.equal((await request(app, { format, ua: matrix[format][0] })).status, 503);
        assert.equal((await request(app, { browser: true, ua: 'Mozilla/5.0' })).status, 503);
    }
});

test('settings card renders RU/EN/zh-CN and toggles the stored opt-in plus both cache variants', async t => {
    const { app, state, cache, entries, Settings } = harness(t);
    const key = 'subscription.singboxVlessEncryption';
    const marker = { _subscriptionSettings: '1', _singboxEncryptionSettings: '1' };
    const path = '/panel/settings';
    const updates = [];
    const unsubscribed = ports.slice(1).map(port => [port, null]);
    const subscribed = [[443, mainClient], ...unsubscribed];
    const noop = async () => {};
    replace(t, '../../../index', { reloadSettings: noop });
    replace(t, '../../services/sshPoolService', { reloadSettings: noop });
    for (const service of ['syncService', 'homepageService', 'updateService']) replace(t, `../../services/${service}`, {});
    assert.equal(Settings.hydrate({ _id: 'settings' }).get(key), false);
    state.settings = Settings.hydrate({ _id: 'settings' });
    t.mock.method(Settings, 'findByIdAndUpdate', async (id, { $set }) => {
        assert.equal(id, 'settings');
        updates.push($set);
        state.settings.set($set);
        return state.settings;
    });
    const parser = express.urlencoded({ extended: false });
    app.use('/panel', parser, require('../panel/settings'));
    Object.assign(state.rows[0].xray, enc(mainPublic));
    const settingRenderer = require('ejs');
    const { t: translate } = require('../../middleware/i18n');
    const template = require('node:path').join(__dirname, '../../../views/partials/settings/subscription.ejs');
    const checkCards = async checked => {
        for (const locale of ['ru', 'en', 'zh-CN']) {
            const strings = require(`../../locales/${locale}.json`).settings;
            const html = await settingRenderer.renderFile(template, { settings: state.settings, t: k => translate(k, locale) });
            for (const k of ['subSingboxVlessEncryption', 'subSingboxVlessEncryptionHint']) {
                assert.ok(strings[k], `${locale} has explicit ${k}`);
                assert.ok(html.includes(settingRenderer.escapeXML(strings[k])), `${locale} rendered ${k}`);
            }
            assert.match(html, /name="_singboxEncryptionSettings" value="1"/);
            assert.equal(/name="subscription\.singboxVlessEncryption"\s+checked>/.test(html), checked);
        }
    };
    const assertFormats = async expected => {
        for (const format of ['singbox', 'json']) {
            const reply = await request(app, { format, ua: 'sing-box/1' });
            assert.equal(reply.status, 200);
            assert.deepEqual(singboxPorts(reply.body), expected);
            withoutPrivate(reply.body);
        }
    };
    const submit = async (form, expected) => {
        const reply = await request(app, { path, form });
        assert.equal(reply.status, 302);
        assert.match(reply.headers.location, /[?]message=/);
        assert.equal(updates.at(-1)[key], expected);
        assert.equal(state.settings.get(key), expected ?? true);
    };
    const subEntries = () => [...entries.entries()].filter(([key]) => key.startsWith('sub:'));
    await checkCards(false);
    await assertFormats(unsubscribed);
    const oldEntries = subEntries();
    assert.equal(oldEntries.length, 2);
    await submit({ ...marker, [key]: 'on' }, true);
    assert.equal(subEntries().length, 0);
    assert.ok(!entries.has('settings'));
    // Simulate older in-flight renders repopulating the evicted keys.
    for (const pair of oldEntries) entries.set(...pair);
    await checkCards(true);
    await assertFormats(subscribed);
    const enabledEntries = subEntries().filter(([k]) => !oldEntries.some(([old]) => old === k));
    assert.equal(enabledEntries.length, 2);
    await submit({ _subscriptionSettings: '1', 'subscription.happ.announce': 'other card' }, undefined);
    await assertFormats(subscribed);
    await submit(marker, false);
    assert.equal(subEntries().length, 0);
    for (const pair of enabledEntries) entries.set(...pair);
    await checkCards(false);
    await assertFormats(unsubscribed);

    // Boolean true is required by the renderer, even with a malformed cached setting.
    await cache.setSettings({ subscription: { singboxVlessEncryption: 'true' } });
    await assertFormats(unsubscribed);
});

test('settled publication projects out server keys before the subscriber route sees it', async t => {
    const { app, state, entries } = harness(t);
    const { TopologyDeploymentRepository } = require('../../modules/relay-l2tp/repositories/topologyDeploymentRepository');
    const { TEST_TOPOLOGY_EXECUTION_CONTEXT: executionContext } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');
    const node = state.rows[0];
    node.cascadeRole = 'portal';
    const applied = structuredClone(node);
    applied.id = node._id;
    Object.assign(applied.xray, enc(mainPublic));
    Object.assign(applied.xray.extraInbounds[0], enc(extraPublic, 'xorpub'), { vlessEncryptionPrivateKey: confidential[1] });
    Object.assign(applied.xray.extraInbounds[1], enc('broken'));
    const query = data => ({ select() { return this; }, session() { return this; }, lean: async () => data });
    const owner = { node: node._id, owner: 'topology', lastSettledOperation: 'fixture-settled' };
    const repository = new TopologyDeploymentRepository({
        TopologyConfigOwner: { find: () => query([owner]) }, NodeOperationLock: {},
        CascadeTopologyState: { findOneAndUpdate() {} }, transactionRunner: fn => fn({}),
        snapshotReader: { readDraft: async () => ({}), HyNode: { find: () => query([node]) } },
    });
    t.mock.method(repository, 'readVerifiedBaseline', async () => ({ baseline: { nodes: [applied] }, owners: new Map([[node._id, owner]]) }));
    const read = async input => {
        const result = await repository.readAppliedNodePublication({ ...input, executionContext });
        assert.equal(result.nodes.length, 1);
        withoutPrivate(JSON.stringify(result));
        return result;
    };
    replace(t, '../../modules/l2tpActiveHostProvider', {
        l2tpActiveHostProvider: { getActiveHost: () => ({ readAppliedNodePublication: read }) },
    });
    const reply = await request(app, { format: 'xray-json', ua: 'Happ/1' });
    assert.equal(reply.status, 200);
    assert.deepEqual(xrayPorts(reply.body, true), [[443, mainClient], [8443, extraClient], [10443, 'none']]);
    withoutPrivate(reply.body);
    const cached = [...entries.entries()].find(([key]) => key.includes('+applied:'));
    assert.ok(cached);
    withoutPrivate(cached[1]);
});


test('Marzban alias publishes the same scoped Xray body as the native route', async t => {
    const { app, state } = harness(t);
    state.linked = true;
    Object.assign(state.rows[0].xray, enc(mainPublic));
    const secret = 'synthetic-migration-signature-input';
    const cryptoService = require('../../services/cryptoService');
    state.settings.migration = { marzban: { enabled: true, path: 'sub', jwtSecretEncrypted: cryptoService.encrypt(secret) } };
    replace(t, '../../utils/rateLimiters', { subscriptionLimiter: (_req, _res, next) => next() });
    app.use(require('../marzbanCompat'));
    const encoded = Buffer.from(`${user.userId},1700000000`).toString('base64url');
    const token = encoded + createHash('sha256').update(encoded + secret).digest('base64url').slice(0, 10);
    const native = await request(app, { format: 'v2ray-json', ua: 'v2rayN/1' });
    assert.equal(native.status, 200);
    const before = state.writes.length;
    const compat = await request(app, { path: `/sub/${token}/v2ray-json`, ua: 'v2rayN/1' });
    assert.equal(compat.status, 200);
    assert.deepEqual(xrayPorts(compat.body, false), [[443, mainClient], ...ports.slice(1).map(port => [port, 'none'])]);
    assert.deepEqual(compat.bytes, native.bytes);
    assert.equal(state.writes.length, before, 'same rendered body cache');
    withoutPrivate(compat.body);
});
