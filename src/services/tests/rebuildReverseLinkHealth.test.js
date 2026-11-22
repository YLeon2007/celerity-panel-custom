'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');
const { createHash, randomUUID } = require('node:crypto');
const http = require('node:http');
const { Types: { ObjectId } } = require('mongoose');
const { fixture } = require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture');

// Real mongoose persistence and the ordinary mounted API. The legacy probes
// deliberately succeed for every matching port: this must not prove reverse.
process.env.C3_REBUILD_ENABLED = 'true';
const cascade = require('../cascadeService');
const router = require('../../routes/cascade');
const mcp = require('../../mcp/tools/cascade');
const cache = require('../cacheService');
const sshPool = require('../sshPoolService');
const Settings = require('../../models/settingsModel');

test.after(() => sshPool.closeAll());

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
const close = server => new Promise(resolve => server.close(resolve));

test('authenticated receiver observations alone drive fresh rebuild status, without lifecycle writes', async t => {
    const db = fixture(); t.after(() => db.stop()); await db.start();
    const { CascadeLink: Link, HyNode: Node } = db.models;
    const [portalNode, bridgeNode, _id] = [new ObjectId(), new ObjectId(), new ObjectId()];
    const tunnelUuid = randomUUID().toUpperCase(), tunnelPort = 43119;
    const identity = createHash('sha256').update(tunnelUuid.toLowerCase()).digest('hex');
    const token = randomUUID(), challenges = new Set();
    let behavior = 'positive', held, entered, previousChallenge, requests = 0, redirects = 0;
    const receiver = await listen(http.createServer(async (req, res) => {
        const url = new URL(req.url, 'http://127.0.0.1');
        if (url.pathname === '/redirect-target') { redirects++; res.end(); return; }
        requests++;
        const challenge = url.searchParams.get('challenge');
        const valid = req.headers.authorization === `Bearer ${token}` && req.method === 'GET'
            && url.pathname === `/rebuild/reverse-observation/${_id}`
            && [...url.searchParams.keys()].sort().join(',') === 'challenge,identity,port'
            && url.searchParams.get('port') === String(tunnelPort) && url.searchParams.get('identity') === identity
            && /^[a-f0-9]{32}$/.test(challenge) && !challenges.has(challenge);
        if (!valid) { res.writeHead(400).end(); return; }
        challenges.add(challenge);
        const body = { version: 1, linkId: String(_id), port: tunnelPort, challenge, established: true };
        if (behavior === 'held') { entered.resolve(); await held.promise; }
        if (behavior === 'cut') body.established = false;
        if (behavior === 'replay') body.challenge = previousChallenge;
        if (behavior === 'wrong port') body.port = String(tunnelPort);
        if (behavior === 'wrong link') body.linkId = String(bridgeNode);
        if (behavior === 'wrong version') body.version = 2;
        if (behavior === 'extra') body.reason = 'extra';
        if (behavior === 'redirect') { res.writeHead(302, { location: '/redirect-target' }).end(); return; }
        if (behavior === 'unsupported' || behavior === 'unauthorized') {
            res.writeHead(behavior === 'unsupported' ? 404 : 401).end(); return;
        }
        if (behavior === 'slow') await new Promise(resolve => setTimeout(resolve, 15_250));
        previousChallenge = challenge;
        const json = JSON.stringify(body);
        res.writeHead(behavior === 'wrong status' ? 201 : 200, {
            'Content-Type': behavior === 'wrong type' ? 'text/html' : 'application/json; charset=utf-8',
        }).end(behavior === 'oversized' ? ' '.repeat(5000) + json
            : behavior === 'duplicate' ? `{"port":0,${json.slice(1)}` : json);
    }));
    t.after(() => close(receiver));
    await Node.collection.insertMany([
        { _id: portalNode, name: 'receiving relay', ip: '127.0.0.1', type: 'xray', active: true,
            cascadeRole: 'relay', status: 'offline', xray: { agentToken: token, agentPort: receiver.address().port, agentTls: false } },
        { _id: bridgeNode, name: 'dialer', ip: '127.0.0.2', type: 'xray', active: true, cascadeRole: 'bridge' },
    ]);
    const row = { _id, name: 'synthetic link', active: true, status: 'deployed', updatedAt: new Date(),
        mode: 'reverse', portalNode, bridgeNode, tunnelUuid, tunnelPort, tunnelProtocol: 'vless',
        tunnelSecurity: 'reality', tunnelTransport: 'tcp', tunnelEncryption: 'vless-enc',
        rebuildApplied: { listener: portalNode, mode: 'reverse', protocol: 'vless', port: tunnelPort, uuid: tunnelUuid } };
    await Link.collection.insertOne(row);
    t.mock.method(Settings, 'findById', () => ({ select: () => ({ lean: async () => null }) }));
    const ssh = t.mock.method(cascade, '_checkTunnel', async () => assert.fail('reverse SSH'));
    const tcp = t.mock.method(cascade, '_measureTcpLatency', async () => assert.fail('reverse TCP'));
    const app = express();
    app.use((req, _res, next) => { req.session = { authenticated: true }; next(); });
    app.use('/cascade', router);
    const server = await listen(http.createServer(app)); t.after(() => close(server));
    const get = async suffix => {
        const res = await fetch(`http://127.0.0.1:${server.address().port}/cascade/${suffix}`);
        assert.equal(res.status, 200);
        assert.equal(res.headers.get('cache-control'), 'no-store');
        return res.json();
    };
    const raw = () => Link.collection.findOne({ _id });
    const manual = () => get(`links/${_id}/health`);
    const allSurfaces = async expected => {
        const { links } = await get(`links?status=${expected}`);
        assert.equal(links.length, 1);
        assert.equal(links[0].status, expected);
        assert.equal(links[0].applicationState, 'applied');
        assert.equal(links[0].routeState, 'unknown');
        assert.equal(links[0].tunnelState, expected === 'online' ? 'connected' : 'unknown');
        const expires = links[0].observationExpiresAt;
        assert.equal(Number.isSafeInteger(expires), expected === 'online');
        const map = await get('topology');
        const edge = map.edges.find(e => e.data.linkId === String(_id)).data;
        const mcpEdge = (await mcp.getTopology()).links.find(l => String(l._id) === String(_id));
        const detail = (await mcp.queryCascade({ id: String(_id) })).link;
        const mcpList = (await mcp.queryCascade({ filter: { status: expected } })).links;
        for (const entry of [links[0], edge, mcpEdge, detail, mcpList.find(l => String(l._id) === String(_id))]) {
            assert.equal(entry.status, expected);
            assert.equal(entry.observationExpiresAt, expires);
            for (const key of ['rebuildApplied', 'rebuildApplyEpoch', 'rebuildReverseObservation']) {
                assert.equal(Object.hasOwn(entry, key), false, key);
            }
        }
    };
    await cascade.healthCheckRebuildReverse();
    assert.equal(requests, 1);
    await allSurfaces('online');
    const first = await raw();
    assert.equal(first.status, 'deployed');
    assert.equal(first.updatedAt.getTime(), row.updatedAt.getTime());
    assert.equal(first.rebuildReverseObservation.version, 1);
    // Restart/cron stopped: the DB value remains positive, but every read must expire it.
    const clock = t.mock.method(Date, 'now', () => first.rebuildReverseObservation.observedAt.getTime() + 90000);
    await allSurfaces('deployed');
    assert.equal((await raw()).rebuildReverseObservation.established, true);
    clock.mock.restore();
    assert.equal((await manual()).healthy, true);
    for (const failure of ['cut', 'replay', 'wrong port', 'wrong link', 'wrong version', 'extra', 'duplicate',
        'redirect', 'unsupported', 'unauthorized', 'wrong status', 'wrong type', 'oversized', 'slow']) {
        behavior = failure;
        const before = requests;
        const result = await manual();
        assert.equal(result.status, 'deployed', failure);
        assert.equal(result.healthy, false, failure);
        assert.equal(requests, before + 1, failure);
        if (failure === 'cut') await allSurfaces('deployed');
        behavior = 'positive';
        assert.equal((await manual()).healthy, true, `recovery from ${failure}`);
    }
    assert.equal(redirects, 0);
    // Cancel a response on edit/re-Apply even when the dial tuple stays the same.
    entered = Promise.withResolvers(); held = Promise.withResolvers(); behavior = 'held';
    const inflight = manual();
    await entered.promise;
    const beforeOverlap = requests;
    const sweep = cascade.healthCheckRebuildReverse();
    await cascade.healthCheckRebuildReverse();
    assert.equal(requests, beforeOverlap);
    await Link.collection.updateOne({ _id }, { $set: { status: 'pending' }, $unset: { rebuildReverseObservation: '' } });
    await Link.collection.updateOne({ _id }, { $set: { status: 'deployed', rebuildApplyEpoch: randomUUID().replaceAll('-', '') } });
    held.resolve(); await sweep;
    assert.equal((await inflight).healthy, false);
    assert.equal((await raw()).rebuildReverseObservation, undefined);
    await allSurfaces('deployed');
    behavior = 'positive';
    const current = await raw();
    for (const [field, value] of [
        ['status', 'pending'], ['active', false], ['rebuildDelete', true],
        ['rebuildApplied', null], ['rebuildApplied', { ...row.rebuildApplied, listener: bridgeNode }],
        ['rebuildApplied', { ...row.rebuildApplied, uuid: randomUUID() }],
        ['rebuildApplied', { ...row.rebuildApplied, mode: 'forward' }], ['mode', null],
        ['tunnelProtocol', 'vmess'], ['tunnelTransport', 'ws'], ['tunnelSecurity', 'none'],
        ['tunnelEncryption', 'invalid'], ['tunnelPort', tunnelPort + 1],
    ]) {
        const before = requests;
        await Link.collection.replaceOne({ _id }, { ...current, [field]: value });
        assert.equal((await manual()).healthy, false, field);
        assert.equal(requests, before, field);
    }
    await Link.collection.replaceOne({ _id }, current);
    await Node.collection.updateOne({ _id: portalNode }, { $unset: { 'xray.agentToken': '' } });
    const beforeMissingToken = requests;
    assert.equal((await manual()).healthy, false);
    assert.equal(requests, beforeMissingToken);
    assert.equal(ssh.mock.callCount(), 0);
    assert.equal(tcp.mock.callCount(), 0);
});

test('reverse sweep limits in-flight reads and advances past the first page', { timeout: 15_000 }, async t => {
    const { createReverseObserver } = require('../rebuildReverseLinkHealth');
    const db = fixture(); t.after(() => db.stop()); await db.start();
    const { CascadeLink: Link, HyNode: Node } = db.models;
    const portalNode = new ObjectId(), bridgeNode = new ObjectId();
    await Node.collection.insertOne({ _id: portalNode, active: true, type: 'xray', cascadeRole: 'portal',
        ip: '127.0.0.1', xray: { agentToken: randomUUID() } });
    const rows = Array.from({ length: 51 }, (_, i) => {
        const uuid = randomUUID(), port = 43120 + i;
        return { _id: new ObjectId(), portalNode, bridgeNode, updatedAt: new Date(), active: true,
            status: 'deployed', mode: 'reverse', tunnelTransport: 'tcp', tunnelProtocol: 'vless', tunnelSecurity: 'reality',
            tunnelUuid: uuid, tunnelPort: port, rebuildApplied: { listener: portalNode, mode: 'reverse', protocol: 'vless', uuid, port } };
    });
    await Link.collection.insertMany(rows);
    const entered = Promise.withResolvers(), release = Promise.withResolvers();
    const visited = [];
    let pending = 0, peak = 0;
    const observer = createReverseObserver({ Link, Node, request: async (_node, path) => {
        const linkId = new URL(path, 'http://127.0.0.1').pathname.split('/').at(-1);
        visited.push(linkId);
        peak = Math.max(peak, ++pending);
        if (pending === 5) entered.resolve();
        await release.promise;
        --pending;
        return { status: 404 };
    } });
    const first = observer.sweep();
    try {
        await entered.promise;
        await observer.sweep();
        assert.equal(visited.length, 5, 'overlapping sweeps do not launch a second page');
    } finally { release.resolve(); await first; }
    assert.equal(peak, 5);
    assert.equal(visited.length, 50);
    assert.equal(new Set(visited).size, 50);
    await observer.sweep();
    assert.equal(visited.at(-1), String(rows.at(-1)._id));
    assert.equal(new Set(visited).size, 51);
    await observer.sweep();
    assert.equal(visited.length, 101, 'tail wraps on the next pass');
});

test('rebuild does not promote reverse links from TCP; read, explicit refresh and cron handle old rows', async t => {
    const db = fixture();
    t.after(() => db.stop());
    await db.start();
    const { CascadeLink: Link, HyNode: Node } = db.models;
    const [portalNode, bridgeNode] = [new ObjectId(), new ObjectId()];
    await Node.collection.insertMany([
        { _id: portalNode, name: 'portal', ip: '127.0.0.1', type: 'xray', cascadeRole: 'portal', active: true, status: 'online' },
        { _id: bridgeNode, name: 'bridge', ip: '127.0.0.2', type: 'xray', cascadeRole: 'bridge', active: true, status: 'online' },
    ]);
    const add = async (name, status, extra = {}) => {
        const row = { _id: new ObjectId(), name, active: true, portalNode, bridgeNode, status,
            tunnelPort: 10086, lastHealthCheck: new Date(1), lastError: 'old observation', latencyMs: 5,
            tunnelUuid: 'synthetic', ...extra };
        await Link.collection.insertOne(row);
        return row;
    };
    const old = await add('old-no-mode-or-receipt', 'online');
    const applied = await add('applied-reverse', 'deployed', { mode: 'reverse', rebuildApplied: {
        mode: 'reverse', listener: portalNode, protocol: 'vless', port: 10086, uuid: 'synthetic',
    } });
    const offline = await add('old-offline', 'offline', { mode: 'reverse' });
    const stale = await add('stale-positive', 'online', { mode: 'reverse', rebuildApplied: applied.rebuildApplied });
    const retired = await add('retiring', 'online', { rebuildDelete: true });
    const deleting = await add('lifecycle', 'online', {
        lifecycle: { state: 'deleting', desiredVersion: 'a'.repeat(64), deleteJobId: new ObjectId() },
    });
    const pending = await add('draft', 'pending', { rebuildApplied: null });
    const falseDraft = await add('draft promoted by old health check', 'online', { rebuildApplied: null });
    const inactive = await add('inactive', 'online', { active: false });
    const staged = await add('staged', 'staged');
    const failed = await add('apply failed', 'error', { lastError: 'activation failed' });
    const forward = await add('forward', 'deployed', { mode: 'forward' });
    t.mock.method(Settings, 'findById', () => ({ select: () => ({ lean: async () => null }) }));
    const ssh = t.mock.method(cascade, '_checkTunnel', async () => true);
    const tcp = t.mock.method(cascade, '_measureTcpLatency', async () => 5);
    t.mock.method(cascade, 'deployLink', async () => assert.fail('health must not redeploy'));
    t.mock.method(require('../webhookService'), 'emit', () => {});
    const app = express();
    app.use((req, _res, next) => { req.session = { authenticated: true }; next(); });
    app.use('/cascade', router);
    const server = await new Promise(resolve => {
        const server = app.listen(0, '127.0.0.1', () => resolve(server));
    });
    t.after(() => new Promise(resolve => server.close(resolve)));
    const get = async suffix => {
        const res = await fetch(`http://127.0.0.1:${server.address().port}/cascade/${suffix}`);
        assert.equal(res.status, 200, suffix);
        return res.json();
    };
    const raw = row => Link.collection.findOne({ _id: row._id });
    const edge = (graph, row) => graph.edges.find(e => e.data.linkId === String(row._id)).data;
    const graph = await get('topology');
    assert.equal(edge(graph, old).status, 'deployed');
    assert.equal(edge(graph, falseDraft).status, 'pending');
    assert.equal(edge(graph, retired).status, 'deployed');
    assert.equal(graph.edges.find(e => e.data.isInternetEdge).data.status, 'online');
    assert.equal(graph.nodes.find(n => n.data.id === String(portalNode)).data.status, 'online');
    // An older Redis topology entry from before this fix must not paint green.
    const cached = structuredClone(graph);
    edge(cached, old).status = 'online';
    edge(cached, old).latencyMs = 5;
    const cacheValues = new Map([['c3:cascade:topology', JSON.stringify(cached)]]);
    const previousRedis = cache.redis;
    t.after(() => { cache.redis = previousRedis; });
    cache.redis = {
        get: async key => cacheValues.get(key), set: async (key, value) => cacheValues.set(key, value),
        del: async key => cacheValues.delete(key),
    };
    assert.equal(edge(await get('topology'), old).status, 'deployed');
    assert.equal(edge(await get('topology'), old).latencyMs, null);
    const list = await get('links?status=deployed');
    assert.ok(list.links.some(l => l._id === String(old._id) && l.tunnelState === 'unknown'));
    assert.equal((await get('links?status=online')).links.length, 0);
    assert.equal((await get(`links/${retired._id}`)).applicationState, 'deleting');
    assert.equal((await get(`links/${old._id}`)).applicationState, 'reconcile_required');
    const appliedLink = await get(`links/${applied._id}`);
    assert.equal(appliedLink.applicationState, 'applied');
    assert.equal(appliedLink.tunnelState, 'unknown');
    assert.equal(Object.hasOwn(appliedLink, 'rebuildApplied'), false);
    assert.equal(Object.hasOwn(list.links.find(l => l._id === String(applied._id)), 'rebuildApplied'), false);
    assert.equal((await get(`links/${failed._id}`)).lastError, 'activation failed');
    assert.equal((await mcp.getTopology()).links.find(l => String(l._id) === String(old._id)).status, 'deployed');
    assert.equal((await mcp.queryCascade({ id: String(old._id) })).link.status, 'deployed');
    const mcpApplied = (await mcp.queryCascade({ id: String(applied._id) })).link;
    assert.equal(Object.hasOwn(mcpApplied, 'rebuildApplied'), false);
    assert.equal((await raw(old)).status, 'online', 'read projections must not write');
    assert.deepEqual(await get(`links/${old._id}/health`), {
        status: 'deployed', healthy: false, lastHealthCheck: null, latencyMs: null,
    });
    assert.equal(ssh.mock.callCount(), 0);
    assert.equal(tcp.mock.callCount(), 0);
    // A stale forward observation cannot overwrite a concurrent edit to a reverse draft.
    const staleForward = await Link.findById(forward._id);
    await Link.collection.updateOne({ _id: forward._id }, { $set: { mode: 'reverse', status: 'pending' } });
    assert.equal(await cascade.healthCheckLink(staleForward), false);
    assert.equal((await raw(forward)).status, 'pending');
    await Link.collection.updateOne({ _id: forward._id }, { $set: { mode: 'forward', status: 'deployed' } });
    const tcpBeforeCron = tcp.mock.callCount();
    await cascade.healthCheckAll();
    assert.equal(ssh.mock.callCount(), 0);
    assert.equal(tcp.mock.callCount() - tcpBeforeCron, 2, 'only forward gets the legacy reachability and latency checks');
    assert.equal((await raw(forward)).status, 'online');
    for (const row of [old, applied, offline, stale]) {
        const saved = await raw(row);
        assert.deepEqual(saved, { ...row, status: 'deployed', lastError: '', lastHealthCheck: null, latencyMs: null });
    }
    assert.deepEqual(await raw(falseDraft), { ...falseDraft, status: 'pending', lastError: '', lastHealthCheck: null, latencyMs: null });
    for (const row of [pending, retired, deleting, inactive, staged, failed]) assert.deepEqual(await raw(row), row);
    assert.equal((await get('links?status=online')).links.length, 1, 'only forward is online');

    // The same success is still a classic positive, and classic loss/recovery
    // remains unchanged. No rebuild health writer takes over in classic mode.
    process.env.C3_REBUILD_ENABLED = 'false';
    t.after(() => { process.env.C3_REBUILD_ENABLED = 'true'; });
    for (const established of [true, false, true]) {
        ssh.mock.mockImplementation(async () => established);
        const result = await get(`links/${old._id}/health`);
        assert.equal(result.healthy, established);
        assert.equal(result.status, established ? 'online' : 'offline');
    }
});
