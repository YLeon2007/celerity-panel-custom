'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');
const { request } = require('../../services/tests/helpers/rebuildPanelRequest');
const { routerForRebuild } = require('../cascadeRebuild');
const { createCascadeLinksRouter } = require('../cascadeLinks');
const { schemas, manageCascade, queryCascade } = require('../../mcp/tools/cascade');
const { buildCandidate } = require('../../modules/relay-l2tp/domain/topologyDraft');

test.after(() => require('../../services/sshPoolService').closeAll());
const portalNodeId = 'a'.repeat(24), bridgeNodeId = 'b'.repeat(24), id = 'c'.repeat(24);
const config = { kcpMtu: 1400, kcpTti: 30, kcpUplinkCapacity: 150, kcpDownlinkCapacity: 200, kcpHeader: 'dtls' };
const create = { name: 'UDP link', portalNodeId, bridgeNodeId, tunnelTransport: 'kcp', ...config };
const nodes = [{ _id: portalNodeId, cascadeRole: 'portal' }, { _id: bridgeNodeId, cascadeRole: 'bridge' }];
const thenable = value => ({ select() { return this; }, populate() { return this; }, sort() { return this; }, lean() { return this; }, then(resolve, reject) { return Promise.resolve(value).then(resolve, reject); } });

function http(router, mount) {
    const app = express();
    app.use((req, _res, next) => { req.apiKey = { scopes: ['nodes:write', 'nodes:read'] }; next(); });
    app.use(mount, router);
    return async (method, path, body, lang) => {
        const { status, body: raw } = await request(app, mount + path, { method, body,
            headers: lang ? { 'accept-language': lang } : undefined });
        return { status, body: JSON.parse(raw) };
    };
}

test('Rebuild POST and PUT save mKCP settings under the existing lock; invalid edits do not save', async () => {
    let stored, locked = false, verified = false, saves = 0;
    class Link {
        constructor(value) { Object.assign(this, { _id: id, mode: 'reverse', priority: 100, tunnelPort: 10086 }, value); }
        static findById() { return thenable(stored && new Link(stored)); }
        set(key, value) { this[key] = value; }
        toObject() { return { ...this }; }
        markModified() {}
        async save() { assert.ok(locked && verified); stored = this.toObject(); saves++; }
    }
    const inventory = nodes.map((n, i) => ({ ...n, xrayVersion: '26.6.1', ip: `192.0.2.${i + 1}` }));
    const Node = { find: filter => Object.assign(thenable(filter.type === 'hysteria' ? [] : inventory), {
        read() { return this; }, readConcern() { return this; },
    }) };
    const locks = { async run(fn) { locked = true; verified = false;
        try { return await fn(async () => { verified = true; }); } finally { locked = false; } } };
    const service = { ...require('../../services/rebuildService').createRebuildService({ Node, locks, assertNoRelayAccountIntent: async () => {}, env: { C3_REBUILD_ENABLED: 'true' } }),
        async verifyDraftTls(link) { assert.ok(locked); assert.equal(link.tunnelTransport, 'kcp'); },
        async verifyDraftRealityFingerprint() { assert.fail('must reject incompatible security before verification'); } };
    const send = http(routerForRebuild({ Link, Node, service }), '/api/cascade');
    assert.equal((await send('POST', '/links', { ...create, kcpPassword: 'caller-stuff' })).status, 200);
    assert.equal(stored.tunnelSecurity, 'none');
    assert.ok(!Object.hasOwn(stored, 'kcpPassword'));
    for (const [key, value] of Object.entries(config)) assert.equal(stored[key], value);
    assert.equal((await send('PUT', '/links/' + id, { name: 'renamed', kcpTti: '40', tunnelSecurity: 'tls' })).status, 200);
    assert.deepEqual(Object.fromEntries(Object.keys(config).map(k => [k, stored[k]])), { ...config, kcpTti: 40 });
    for (const body of [{ tunnelSecurity: 'reality' }, { tunnelTransport: ['kcp'] }, { kcpMtu: [1400] }, { kcpMtu: 575 }, { kcpTti: 20.5 }, { kcpUplinkCapacity: true }, { kcpHeader: 'dns' }]) {
        assert.equal((await send('PUT', '/links/' + id, body)).status, 400);
    }
    assert.equal(saves, 2);
});

test('classic REST refuses mKCP creation, activation and port checks, but permits safe readback', async () => {
    const stored = { ...create, _id: id, portalNode: portalNodeId, bridgeNode: bridgeNodeId,
        active: true, mode: 'reverse', tunnelPort: 10086, kcpPassword: 'server-fixture' };
    const query = value => Object.assign(thenable(value), { setOptions() { return this; } });
    const Link = { findById: () => query(stored) };
    const Node = { findById: () => query({ _id: portalNodeId }) };
    const forbidden = () => assert.fail('must not dispatch or save');
    const send = http(createCascadeLinksRouter({ Link, Node, deploymentEnv: {},
        topologyDraftWriteService: { createLink: forbidden, updateLink: forbidden },
        topologyIntentService: { accept: forbidden }, portCheckSSH: forbidden }), '/links');
    for (const [method, path, body, expected, lang] of [
        ['POST', '/', { ...create, expectedTopologyRevision: 7 }, /mKCP.*Rebuild/],
        ['PUT', '/' + id, { tunnelTransport: 'kcp', expectedTopologyRevision: 7 }, /mKCP.*Rebuild/],
        ['GET', `/port-check?nodeId=${portalNodeId}&port=10086&tunnelTransport=kcp`, undefined, /supported only in Rebuild/, 'en'],
        ['GET', `/port-check?nodeId=${portalNodeId}&port=10087&linkId=${id}&tunnelTransport=tcp`, undefined, /доступен только в Rebuild/, 'ru'],
    ]) {
        const result = await send(method, path, body, lang);
        assert.equal(result.status, 409);
        assert.equal(result.body.error.code, 'CLASSIC_KCP_REBUILD_ONLY');
        assert.match(result.body.error.message, expected);
        assert.ok(!Object.hasOwn(result.body, 'available'));
    }
    const value = (await send('GET', '/' + id)).body;
    assert.ok(!Object.hasOwn(value, 'kcpPassword'));
    for (const [key, v] of Object.entries(config)) assert.equal(value[key], v);
});

test('MCP advertises bounds and header choices, and the scoped draft checks the effective pair', () => {
    const parse = data => schemas.manageCascade.safeParse({ action: 'update', id, expectedTopologyRevision: 7, data });
    const ok = parse({ tunnelTransport: 'kcp', ...config, kcpPassword: 'crafted' });
    assert.equal(ok.success, true);
    assert.deepEqual(ok.data.data, { tunnelTransport: 'kcp', ...config });
    assert.equal(parse({ kcpTti: 101 }).success, false);
    assert.equal(parse({ kcpHeader: 'dns' }).success, false);
    const snapshot = { nodes, links: [{ _id: id, portalNode: portalNodeId, bridgeNode: bridgeNodeId, tunnelTransport: 'kcp', tunnelSecurity: 'none' }] };
    assert.throws(() => buildCandidate(snapshot, { kind: 'link.update', id, changes: { tunnelSecurity: 'reality' } }), { code: 'INVALID_KCP_LINK_SETTINGS' });
});


test('MCP refuses mKCP writes and still exposes only safe fields in classic reads', async t => {
    const Link = require('../../models/cascadeLinkModel');
    const stored = { ...create, _id: id, portalNode: portalNodeId, bridgeNode: bridgeNodeId,
        active: true, status: 'pending', kcpPassword: 'synthetic-server-value' };
    t.mock.method(Link, 'findById', () => thenable(stored));
    t.mock.method(Link, 'find', () => thenable([stored]));
    for (const action of ['create', 'update']) {
        await assert.rejects(manageCascade({ action, id, expectedTopologyRevision: 7, data: create }),
            { code: 'CLASSIC_KCP_REBUILD_ONLY' });
    }
    const { link } = await queryCascade({ id });
    for (const [key, value] of Object.entries(config)) assert.equal(link[key], value);
    assert.ok(!Object.hasOwn(link, 'kcpPassword') && !Object.hasOwn((await queryCascade({})).links[0], 'kcpPassword'));
});

test('versioned intents bind mKCP fields, preserve legacy fingerprints and omit server-owned passwords', () => {
    const { linkDesiredVersion } = require('../../modules/relay-l2tp/services/topologyIntentService');
    const tcp = { tunnelTransport: 'tcp', tunnelSecurity: 'none', name: 'original' };
    assert.equal(linkDesiredVersion(tcp), linkDesiredVersion({ ...tcp, ...config }));
    const udp = { ...tcp, tunnelTransport: 'kcp', ...config };
    assert.notEqual(linkDesiredVersion(udp), linkDesiredVersion({ ...udp, kcpMtu: 1401 }));
    assert.equal(linkDesiredVersion(udp), linkDesiredVersion({ ...udp, kcpPassword: 'synthetic-server-value' }));
});
