'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');
const express = require('express');
const { Types: { ObjectId }, mongo: { BSON } } = require('mongoose');
const applyProjection = require('mongoose/lib/helpers/projection/applyProjection');
const requireAuth = require('../../middleware/auth');
const Link = require('../../models/cascadeLinkModel');
const Node = require('../../models/hyNodeModel');
const Settings = require('../../models/settingsModel');
const cache = require('../../services/cacheService');
const { appliedLink } = require('../../services/rebuildAppliedLink');
const { kcpApplyFingerprint } = require('../../services/rebuildReverseLinkHealth');
const { request } = require('../../services/tests/helpers/rebuildPanelRequest');
const mapModel = require('../../../public/js/network/src/core/model');
const cascadeRoutes = require('../cascade');
const { routerForRebuild } = require('../cascadeRebuild');
const { createCascadeTopologyDeployRouter } = require('../cascadeTopologyDeploy');

test.after(() => require('../../services/sshPoolService').closeAll());

const path = '/api/cascade/topology';
const sentinel = 'FIXTURE_PRIVATE_SENTINEL';
const observedAt = new Date('2026-01-02T03:04:05Z');
const historical = new Date(observedAt.getTime() - 123_000);
const expiresAt = observedAt.getTime() + 90_000;
const id = n => new ObjectId(n.toString(16).padStart(24, '0'));
const [portal, bridge] = [id(1), id(2)];
const auth = { method: 'GET', session: { authenticated: true } };
const edge = (json, name) => json.edges.find(row => row.data.label === name).data;

function fixture(t, rebuild) {
    const mode = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = String(rebuild);
    t.after(() => {
        if (mode === undefined) delete process.env.C3_REBUILD_ENABLED;
        else process.env.C3_REBUILD_ENABLED = mode;
    });
    const clock = t.mock.method(Date, 'now', () => expiresAt - 1);
    const nodes = [
        { _id: portal, name: 'Portal', type: 'xray', active: true, status: 'unknown', cascadeRole: 'portal',
            ip: '192.0.2.1', domain: 'portal.fixture.invalid', country: 'DE', flag: '🇩🇪', onlineUsers: 4, port: 443,
            mapPosition: { x: 0, y: -12.3, ignored: sentinel }, lastSync: historical,
            lastError: 'Xray runtime API unavailable', ssh: { password: sentinel, username: sentinel },
            xray: { agentToken: sentinel }, statsSecret: sentinel, customConfig: sentinel },
        { _id: bridge, name: 'Bridge', type: 'xray', active: true, status: 'online', cascadeRole: 'bridge',
            mapPosition: { x: 50 }, lastError: `${sentinel}\n${'X'.repeat(800)}` },
        { _id: id(3), name: 'Virtual', active: true, type: 'virtual' },
        { _id: id(4), name: 'Inactive', active: false, type: 'xray' },
    ];
    const rows = [];
    function add(name, fields = {}) {
        const n = 100 + rows.length;
        const row = { _id: id(n), name, active: true, portalNode: portal, bridgeNode: bridge, status: 'deployed',
            tunnelUuid: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, tunnelPort: 12000 + n,
            tunnelProtocol: 'vless', mode: 'reverse', tunnelTransport: 'tcp', tunnelSecurity: 'reality',
            tunnelEncryption: 'vless-enc', updatedAt: historical, rebuildApplyEpoch: 'e'.repeat(32),
            rebuildAppliedMainSha256: 'a'.repeat(64), realityPrivateKey: sentinel, kcpPassword: sentinel,
            rebuildVlessKeyEnvelope: sentinel, profile: { raw: sentinel }, ...fields };
        rows.push(row);
        return row;
    }
    function observed(name, fields) {
        const row = add(name, fields);
        row.rebuildApplied = appliedLink(row);
        row.rebuildReverseObservation = {
            version: 1, established: true, observedAt,
            generation: createHash('sha256').update(JSON.stringify([String(row._id), String(portal), String(bridge),
                row.tunnelPort, row.tunnelUuid, row.tunnelEncryption, historical.getTime(), row.rebuildApplyEpoch])).digest('hex'),
        };
        return row;
    }
    const live = observed('fresh', { lastHealthCheck: historical, lastError: sentinel, priority: 0,
        geoRouting: { enabled: true, domains: [sentinel], geoip: [sentinel] } });
    observed('deleting', { lifecycle: { state: 'deleting', desiredVersion: 'f'.repeat(64) } });
    const wrongEpoch = observed('changed generation');
    wrongEpoch.rebuildApplyEpoch = 'd'.repeat(32);
    add('legacy', { status: 'online', lastHealthCheck: historical, observationExpiresAt: expiresAt });
    add('draft', { status: 'online', rebuildApplied: null, lastHealthCheck: historical });
    add('malformed receipt', { rebuildApplied: { ...appliedLink(live), extra: sentinel } });
    add('malformed listener', { rebuildApplied: { ...appliedLink(live), listener: [portal] } });
    const staleReceipt = add('edited since apply', { mode: 'forward', tunnelSecurity: 'none' });
    staleReceipt.rebuildApplied = { ...appliedLink(staleReceipt), port: staleReceipt.tunnelPort - 1 };
    const kcp = add('current kcp', { mode: 'forward', tunnelTransport: 'kcp', tunnelSecurity: 'tls',
        rebuildTlsServerName: 'kcp.fixture.invalid', kcpHeader: 'wechat-video', kcpMtu: 1200, kcpTti: 20,
        kcpUplinkCapacity: 8, kcpDownlinkCapacity: 30, status: 'online', latencyMs: 12, lastHealthCheck: historical });
    kcp.rebuildApplied = appliedLink(kcp);
    kcp.rebuildKcpApplied = kcpApplyFingerprint(kcp, kcp.rebuildApplyEpoch);
    add('stale kcp', { tunnelTransport: 'tcp', status: 'online', rebuildKcpApplied: kcp.rebuildKcpApplied });
    add('offline forward', { mode: 'forward', status: 'offline', latencyMs: 7,
        lastHealthCheck: historical, lastError: 'Bridge unreachable on tunnel port' });
    add('failed forward', { mode: 'forward', status: 'error', lastError: { nested: sentinel }, lastHealthCheck: sentinel });
    add('unknown forward', { mode: 'forward', status: 'unknown', lastError: sentinel, priority: sentinel });
    add('inactive link', { active: false });

    const calls = [];
    const settings = { _id: 'settings', networkMap: { internetPosition: { x: 200, y: 14, extra: sentinel } }, private: sentinel };
    const project = (name, filter, { projection }, docs) => {
        calls.push({ name, filter, projection });
        // The seam is below Mongoose casting and selection; apply its actual
        // driver projection to BSON-cloned documents (including Date/ObjectId).
        return docs.filter(row => Object.entries(filter).every(([key, value]) => {
            if (value?.$in) return value.$in.some(v => v.equals(row[key]));
            if (value?.$ne !== undefined) return row[key] !== value.$ne;
            return row[key] === value;
        })).map(row => applyProjection(BSON.deserialize(BSON.serialize(row)),
            Object.values(projection ?? {}).includes(1) ? { _id: 1, ...projection } : projection));
    };
    for (const [model, docs] of [[Node, nodes], [Link, rows]]) {
        t.mock.method(model.collection, 'find', (filter, options) => ({ toArray: async () => project(model.modelName, filter, options, docs) }));
    }
    t.mock.method(Settings.collection, 'findOne', async (filter, options) => project('settings', filter, options, [settings])[0] ?? null);
    const previous = cache.redis;
    const cacheCalls = [];
    const redis = new Map([['c3:cascade:topology:kcp-status-v1', JSON.stringify({ nodes: [], edges: [], private: sentinel })]]);
    cache.redis = {
        get: async key => { cacheCalls.push(['get', key]); return redis.get(key); },
        set: async (key, value, ...args) => { cacheCalls.push(['set', key, ...args]); redis.set(key, value); },
    };
    t.after(() => { cache.redis = previous; });
    const app = express();
    if (rebuild) app.use('/api/cascade', requireAuth, routerForRebuild());
    app.use('/api/cascade/topology', createCascadeTopologyDeployRouter());
    app.use('/api/cascade', requireAuth, cascadeRoutes);
    const get = async () => {
        const response = await request(app, path, auth);
        assert.equal(response.status, 200);
        assert.equal(response.headers['cache-control'], rebuild ? 'no-store' : undefined);
        const json = JSON.parse(response.body);
        assert.equal(response.body.includes(sentinel), false, 'no private marker in the response');
        assert.ok(json.edges.every(({ data }) => !Object.hasOwn(data, 'rebuildApplied')
            || typeof data.rebuildApplied === 'boolean'));
        for (const field of ['tunnelUuid', 'ssh', 'profile', 'rebuildAppliedMainSha256', 'rebuildReverseObservation',
            'rebuildKcpApplied', 'rebuildApplyEpoch', 'lifecycle', 'mapPosition']) {
            assert.equal(response.body.includes(`"${field}":`), false, field);
        }
        return json;
    };
    return { app, get, calls, cacheCalls, clock, add };
}

function assertProjection(calls, rebuild) {
    const expected = (name, query, fields) => {
        const { projection } = calls.find(call => call.name === name && query(call.filter));
        assert.deepEqual(projection, Object.fromEntries(fields.trim().split(/\s+/).map(key => [key, 1])));
    };
    expected('HyNode', query => query.active === true && query.type?.$ne === 'virtual',
        `name ip domain flag type status onlineUsers cascadeRole mapPosition.x mapPosition.y country port
        ssh.password ssh.privateKey lastError lastSync`);
    expected('CascadeLink', query => query.active === true,
        `name portalNode bridgeNode status mode tunnelPort latencyMs tunnelProtocol tunnelTransport muxEnabled
        tunnelSecurity lastError lastHealthCheck rebuildKcpApplied ${rebuild ? `active rebuildDelete rebuildDesiredEdited lifecycle updatedAt
        tunnelUuid tunnelEncryption rebuildTlsServerName kcpHeader kcpMtu kcpTti kcpUplinkCapacity kcpDownlinkCapacity
        rebuildApplied rebuildApplyEpoch rebuildReverseObservation rebuildExit rebuildAppliedExit priority geoRouting.enabled` : ''}`);
    for (const { projection } of calls.filter(call => call.filter._id?.$in)) assert.deepEqual(projection, { _id: 1 });
    expected('settings', query => query._id === 'settings', 'networkMap.internetPosition.x networkMap.internetPosition.y');
}

test('mounted Rebuild topology exposes safe inspector fields and conservative KPI inputs', async t => {
    const { app, get, calls, cacheCalls, clock } = fixture(t, true);
    assert.equal((await request(app, path, { method: 'GET' })).status, 401);
    assert.equal(calls.length, 0);
    const graph = await get();
    const index = mapModel.buildIndex(graph);
    const portalInput = index.nodes.get(String(portal));
    const bridgeInput = index.nodes.get(String(bridge));
    assert.deepEqual([portalInput.country, portalInput.flag, portalInput.position, portalInput.lastSync,
        portalInput.lastError, portalInput.sshConfigured],
    ['DE', '🇩🇪', { x: 0, y: -12.3 }, historical.toISOString(), 'Xray runtime API unavailable', true]);
    assert.deepEqual([bridgeInput.country, bridgeInput.flag, bridgeInput.position, bridgeInput.lastSync, bridgeInput.lastError],
        ['', '', null, null, 'Topology check failed']);
    assert.deepEqual(graph.nodes.find(row => row.data.id === 'internet').position, { x: 200, y: 14 });
    assert.equal(Object.hasOwn(graph.nodes.find(row => row.data.id === 'internet').data, 'lastSync'), false);
    assert.equal(Object.hasOwn(graph.edges.find(row => row.data.isInternetEdge).data, 'lastHealthCheck'), false);

    const fresh = edge(graph, 'fresh');
    assert.deepEqual([fresh.priority, fresh.geoRouting], [0, { enabled: true }]);
    assert.deepEqual([edge(graph, 'legacy').priority, edge(graph, 'legacy').geoRouting], [100, { enabled: false }]);
    assert.equal(edge(graph, 'unknown forward').priority, null);
    assert.deepEqual([fresh.status, fresh.lastHealthCheck, fresh.observationExpiresAt, fresh.lastError, fresh.rebuildApplied],
        ['online', observedAt.toISOString(), expiresAt, '', true]);
    assert.deepEqual([edge(graph, 'draft').status, edge(graph, 'draft').rebuildApplied], ['pending', false]);
    for (const name of ['legacy', 'malformed receipt', 'malformed listener']) {
        assert.equal(Object.hasOwn(edge(graph, name), 'rebuildApplied'), false, name);
    }
    assert.equal(edge(graph, 'edited since apply').rebuildApplied, true, 'historical receipt is not current health');
    for (const name of ['legacy', 'deleting', 'changed generation', 'edited since apply']) {
        const l = edge(graph, name);
        assert.deepEqual([l.status, l.observationExpiresAt, l.lastHealthCheck], ['deployed', undefined, null], name);
    }
    const currentKcp = edge(graph, 'current kcp');
    assert.deepEqual([currentKcp.status, currentKcp.tunnelState, currentKcp.tunnelVerification, currentKcp.lastHealthCheck,
        currentKcp.latencyMs, currentKcp.rebuildApplied], ['deployed', 'unknown', 'mkcp_runtime_unsupported', null, null, true]);
    const staleKcp = edge(graph, 'stale kcp');
    assert.deepEqual([staleKcp.status, staleKcp.tunnelState, staleKcp.tunnelVerification], ['pending', 'unknown', 'mkcp_apply_unconfirmed']);
    assert.equal(edge(graph, 'offline forward').lastHealthCheck, historical.toISOString());
    assert.equal(edge(graph, 'offline forward').lastError, 'Bridge unreachable on tunnel port');
    assert.equal(edge(graph, 'failed forward').lastHealthCheck, null);
    assert.equal(edge(graph, 'failed forward').lastError, '');
    assert.equal(edge(graph, 'unknown forward').lastError, 'Topology check failed');
    assert.equal(edge(graph, 'unknown forward').status, 'unknown');
    assert.ok([...graph.nodes, ...graph.edges].every(({ data }) => (data.lastError?.length ?? 0) <= 300));
    assert.deepEqual(mapModel.stats(index), {
        nodes: 2, online: 1, users: 4, links: 13, linksOk: 1, chains: 13, chainsOk: 0, avgLatency: null, problems: 2, unverified: 11,
    });
    assertProjection(calls, true);

    clock.mock.mockImplementation(() => expiresAt);
    const expired = await get();
    const stale = edge(expired, 'fresh');
    assert.deepEqual([stale.status, stale.rebuildApplied, stale.lastHealthCheck, stale.observationExpiresAt],
        ['deployed', true, null, undefined]);
    assert.equal(mapModel.stats(mapModel.buildIndex(expired)).chainsOk, 0);
    assert.deepEqual(cacheCalls, []);
});

test('Rebuild edge edit eligibility and unapplied changes use persisted state, not health', async t => {
    const { get, add } = fixture(t, true);
    const receipt = (name, fields) => {
        const row = add(name, fields);
        row.rebuildApplied = appliedLink(row);
        return row;
    };
    receipt('name-only edit', { status: 'pending', lastHealthCheck: observedAt });
    const older = receipt('pending older apply', { status: 'pending' });
    delete older.rebuildApplyEpoch;
    const kcp = receipt('mKCP tuning edit', { status: 'pending', mode: 'forward', tunnelTransport: 'kcp', tunnelSecurity: 'none', kcpTti: 30 });
    kcp.rebuildKcpApplied = kcpApplyFingerprint({ ...kcp, kcpTti: 20 }, kcp.rebuildApplyEpoch);
    receipt('projected pending only', { mode: 'forward', tunnelTransport: 'kcp', tunnelSecurity: 'none' });
    receipt('pending legacy delete', { status: 'pending', rebuildDelete: true });
    receipt('pending lifecycle', { status: 'pending', lifecycle: { state: 'deleting' } });
    receipt('real error', { status: 'error' });
    receipt('offline with receipt', { status: 'offline', mode: 'forward' });
    add('pending without receipt', { status: 'pending', lastHealthCheck: observedAt });
    add('new draft', { status: 'pending', rebuildApplied: null });
    add('pending malformed receipt', { status: 'pending', rebuildApplied: { listener: portal } });

    const graph = await get();
    for (const name of ['name-only edit', 'pending older apply', 'mKCP tuning edit']) {
        const { canEdit, hasUnappliedChanges, status, lastHealthCheck } = edge(graph, name);
        assert.deepEqual([canEdit, hasUnappliedChanges, status, lastHealthCheck], [true, true, 'pending', null], name);
    }
    for (const name of ['pending legacy delete', 'pending lifecycle', 'deleting']) {
        const { canEdit, hasUnappliedChanges } = edge(graph, name);
        assert.deepEqual([canEdit, hasUnappliedChanges], [false, false], name);
    }
    for (const name of ['pending without receipt', 'new draft', 'pending malformed receipt', 'fresh', 'current kcp',
        'stale kcp', 'projected pending only', 'edited since apply', 'real error', 'offline with receipt']) {
        const { canEdit, hasUnappliedChanges } = edge(graph, name);
        assert.deepEqual([canEdit, hasUnappliedChanges], [true, false], name);
    }
    assert.equal(edge(graph, 'projected pending only').status, 'pending');
    assert.equal(edge(graph, 'real error').status, 'error');
    assert.equal(edge(graph, 'offline with receipt').status, 'offline');
    assert.ok(!graph.edges.some(({ data }) => data.label === 'inactive link'));
    const internet = graph.edges.find(({ data }) => data.isInternetEdge).data;
    assert.equal(Object.hasOwn(internet, 'canEdit'), false);
    assert.equal(Object.hasOwn(internet, 'hasUnappliedChanges'), false);
});

test('mounted Classic topology caches only its public projection, not Rebuild observations', async t => {
    const { get, calls, cacheCalls } = fixture(t, false);
    const first = await get();
    assertProjection(calls, false);
    assert.equal(edge(first, 'fresh').status, 'deployed');
    assert.equal(edge(first, 'legacy').status, 'online');
    assert.equal(edge(first, 'current kcp').status, 'pending');
    assert.equal(edge(first, 'legacy').lastHealthCheck, historical.toISOString());
    assert.ok(first.edges.every(({ data }) => ['rebuildApplied', 'observationExpiresAt', 'canEdit', 'hasUnappliedChanges',
        'priority', 'geoRouting', 'rebuildExit', 'appliedRebuildExit']
        .every(field => !Object.hasOwn(data, field))));
    const readCount = calls.length;
    assert.deepEqual(await get(), first);
    assert.equal(calls.length, readCount, 'no DB read on the cache hit');
    assert.deepEqual(cacheCalls.map(([method, , ...args]) => [method, ...args]), [['get'], ['set', 'EX', 15], ['get']]);
});

test('mounted topology returns a fixed error when the database read fails', async t => {
    const { app } = fixture(t, true);
    t.mock.method(Link.collection, 'find', () => { throw new Error(sentinel); });
    const response = await request(app, path, auth);
    assert.equal(response.status, 500);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.deepEqual(JSON.parse(response.body), { error: 'Unable to load topology' });
});
