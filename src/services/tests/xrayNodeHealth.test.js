'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const path = require('node:path');
const { test, after } = require('node:test');

const express = require('express');
const HyNode = require('../../models/hyNodeModel');
const HyUser = require('../../models/hyUserModel');
const NodeSSH = require('../nodeSSH');
const sync = require('../syncService');
const cache = require('../cacheService');
const statsService = require('../statsService');
const webhook = require('../webhookService');
const nodes = require('../../routes/nodes');
const requireAuth = require('../../middleware/auth');
const nodeSetup = require('../nodeSetup');
const { manageNode } = require('../../mcp/tools/nodes');
const TOKEN = 'fixture-only-authorization';
const SECRET = 'not-for-response-or-cache';
const ZERO_STATS = { users: {}, node: { tx: 0, rx: 0 } };

after(() => require('../sshPoolService').closeAll());

async function listen(t, listener) {
    const server = http.createServer(listener).listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(async () => {
        const closed = once(server, 'close');
        server.close();
        server.closeAllConnections();
        await closed;
    });
    return server.address().port;
}

async function fixture(t, { status = 'online', agent = true, ssh = false, readOnlineCache = false } = {}) {
    const wire = { health: 'offline', requests: [], stats: ZERO_STATS, online: {}, holdOnline: null, holdInfo: null, healthObserved: null };
    const port = await listen(t, async (req, res) => {
        wire.requests.push(`${req.method} ${req.url}`);
        const authorized = req.headers.authorization === `Bearer ${TOKEN}`;
        let code = 200;
        let result;
        if (!authorized) code = 401;
        else if (req.url === '/info') {
            const hold = wire.holdInfo;
            wire.holdInfo = null;
            if (hold) await hold();
            result = { agent_version: '1.4.0', xray_version: 'Xray fixture', users_count: 0, private: SECRET };
        } else if (req.url === '/xray-health') {
            if (wire.health === 'timeout') { req.socket.destroy(); return; }
            if (wire.health === 'legacy') code = 404;
            else if (wire.health === 'malformed') result = { xray_status: true, error: SECRET };
            else result = { xray_status: wire.health };
            wire.healthObserved?.(result?.xray_status);
        } else if (req.url === '/stats') result = wire.stats;
        else if (req.url === '/online') {
            const online = wire.online;
            const hold = wire.holdOnline;
            wire.holdOnline = null;
            if (hold) await hold();
            if (online === null) code = 404;
            else result = { users: online };
        } else if (req.url === '/sync') result = { added: 0, removed: 0, errors: 0, total: 0 };
        else if (req.url === '/restart') result = { status: 'ok' };
        else code = 404;
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify(result || { error: SECRET }));
    });

    // Real HyNode query/update casting; replace only the database driver.
    let stored = new HyNode({ name: 'health fixture', type: 'xray', active: true,
        ip: '127.0.0.1', status, onlineUsers: 4,
        ...(ssh ? { ssh: { password: 'fixture-only-encrypted-value' } } : {}),
        xray: { agentTls: false, agentPort: port, agentToken: agent ? TOKEN : '' },
    }).toObject();
    const decode = value => HyNode.base.mongo.BSON.deserialize(HyNode.base.mongo.BSON.serialize({ value })).value;
    const get = (obj, key) => key.split('.').reduce((row, part) => row?.[part], obj);
    const set = (key, value) => {
        const p = key.split('.');
        const k = p.pop();
        p.reduce((row, part) => row[part] ??= {}, stored)[k] = value;
    };
    const matches = filter => Object.entries(filter).every(([key, expected]) => {
        if (key === '$or') return expected.some(matches);
        const actual = get(stored, key);
        if (expected === null) return actual == null;
        if (expected?.$lte !== undefined) return actual != null && actual <= expected.$lte;
        if (key === '_id') return String(actual) === String(expected);
        if (expected?.$gte !== undefined) return actual >= expected.$gte;
        if (expected?.$in) return expected.$in.includes(actual ?? null);
        if (expected?.$exists !== undefined && (actual !== undefined) !== expected.$exists) return false;
        if (expected?.$ne !== undefined) return actual !== expected.$ne;
        return actual === expected;
    });
    const apply = update => {
        for (const [key, value] of Object.entries(update.$set || {})) set(key, value);
        for (const [key, value] of Object.entries(update.$inc || {})) set(key, (get(stored, key) ?? 0) + value);
    };
    const project = options => {
        const selection = Object.entries(options?.projection || {});
        if (!selection.some(([, include]) => include === 1)) return decode(stored);
        return decode({ _id: stored._id, ...Object.fromEntries(selection.map(([key]) => [key, get(stored, key)])) });
    };
    const driver = {
        find: filter => ({ toArray: async () => matches(filter) ? [decode(stored)] : [] }),
        findOne: async (filter, options) => matches(filter) ? project(options) : null,
        findOneAndUpdate: async (filter, update, options) => {
            if (!matches(filter)) return null;
            const before = project(options);
            apply(update);
            return options.returnDocument === 'after' ? project(options) : before;
        },
        updateOne: async (filter, update) => {
            const matchedCount = Number(matches(filter));
            if (matchedCount) apply(update);
            return { acknowledged: true, matchedCount, modifiedCount: matchedCount };
        },
    };
    const collection = HyNode.collection;
    const save = { collection: collection.collection, buffer: collection.buffer };
    Object.assign(collection, { collection: driver, buffer: false });
    t.after(() => Object.assign(collection, save));
    t.mock.method(NodeSSH.prototype, 'connect', async () => { assert.fail('unexpected SSH'); });
    const invalidations = [];
    for (const key of ['invalidateNodes', 'invalidateAllSubscriptions', 'invalidateDashboardCounts', 'invalidateTrafficStats']) {
        t.mock.method(cache, key, async () => { invalidations.push(key); });
    }
    const published = [];
    if (readOnlineCache) {
        // Keep both cache methods and serialization real, with a private Redis driver fixture.
        const kv = new Map();
        const redis = cache.redis;
        cache.redis = {
            async setex(key, ttl, value) { kv.set(key, value); },
            async get(key) { return kv.get(key) ?? null; },
        };
        t.after(() => { cache.redis = redis; });
        t.mock.method(cache, 'isConnected', () => true);
    } else {
        t.mock.method(cache, 'setXrayOnlineUsers', async ids => { published.push(ids); });
    }
    const events = [];
    t.mock.method(webhook, 'emit', (...args) => events.push(args));
    const read = () => HyNode.findById(stored._id).lean();
    return { wire, read, id: String(stored._id), invalidations, published, events };
}

async function mountedApi(t, f) {
    const app = express();
    app.use((req, res, next) => {
        if (req.headers['x-fixture-session'] === 'authenticated') req.session = { authenticated: true };
        next();
    });
    app.use(express.json());
    app.use('/api/nodes', requireAuth, nodes);
    const port = await listen(t, app);
    return async (path, method = 'GET', authenticated = true, body) => {
        const res = await fetch(`http://127.0.0.1:${port}/api/nodes/${f.id}/${path}`, {
            method, redirect: 'manual', body: JSON.stringify(body),
            headers: { 'content-type': 'application/json', ...(authenticated && { 'x-fixture-session': 'authenticated' }) },
        });
        const text = await res.text();
        assert.ok(!text.includes(TOKEN) && !text.includes(SECRET), 'no credentials or raw agent diagnostics');
        return { status: res.status, body: res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : null };
    };
}

test('both Xray polling jobs publish the same online users to hynodes and the cache', async t => {
    async function setup(t) {
        const f = await fixture(t, { readOnlineCache: true });
        const started = performance.now();
        let elapsed = 0;
        t.mock.method(performance, 'now', () => started + elapsed);
        t.mock.method(HyUser, 'bulkWrite', async operations => ({ modifiedCount: operations.length }));
        t.mock.method(HyUser, 'aggregate', async () => []);
        t.mock.method(sync, 'enforceTrafficLimit', async () => {});
        return {
            wire: f.wire,
            async poll(method, at, expected) {
                elapsed = at;
                const firstRequest = f.wire.requests.length;
                await sync[method]();
                assert.deepEqual(Object.keys(await cache.getXrayOnlineUsers()).sort(), [...expected].sort(), `${method} at ${at}ms: cache IDs`);
                assert.equal((await f.read()).onlineUsers, expected.length, `${method} at ${at}ms: persisted onlineUsers`);
                assert.equal((await statsService.collectSnapshot()).online, expected.length, `${method} at ${at}ms: chart/dashboard count`);
                const requests = f.wire.requests.slice(firstRequest);
                assert.deepEqual(requests, method === 'collectAllStats' ? ['GET /stats', 'GET /online'] : ['GET /online']);
            },
        };
    }
    await t.test('empty /online, reset counters and 90s expiry without another traffic poll', async t => {
        const { wire, poll } = await setup(t);
        wire.stats = { users: { stream: { tx: 100, rx: 5 } } };
        await poll('collectAllStats', 0, ['stream']);
        await poll('collectXrayAgentOnlineStates', 5_000, ['stream']);
        // /stats resets on each GET: even less than the previous poll is new traffic.
        wire.stats = { users: { stream: { tx: 1, rx: 0 } } };
        await poll('collectAllStats', 30_000, ['stream']);
        wire.stats = ZERO_STATS;
        await poll('collectAllStats', 60_000, ['stream']);
        await poll('collectXrayAgentOnlineStates', 119_999, ['stream']);
        await poll('collectXrayAgentOnlineStates', 120_000, []);
    });
    await t.test('union is deduplicated and a successful empty /online clears log-only users immediately', async t => {
        const { wire, poll } = await setup(t);
        wire.online = { journal: { online: true }, shared: { online: true }, stale: { online: false } };
        wire.stats = { users: { shared: { tx: 5 }, traffic: { rx: 7 }, idle: { tx: 0, rx: 0 } } };
        await poll('collectAllStats', 0, ['journal', 'shared', 'traffic']);
        await poll('collectXrayAgentOnlineStates', 5_000, ['journal', 'shared', 'traffic']);
        wire.online = {};
        await poll('collectXrayAgentOnlineStates', 10_000, ['shared', 'traffic']);
    });
    await t.test('unavailable /online preserves the traffic fallback; a refusal does not extend a prior log sample', async t => {
        const { wire, poll } = await setup(t);
        wire.online = { journal: { online: true } };
        await poll('collectXrayAgentOnlineStates', 0, ['journal']);
        wire.online = null;
        wire.stats = { users: { stream: { tx: 1 } } };
        await poll('collectAllStats', 30_000, ['journal', 'stream']);
        wire.stats = ZERO_STATS;
        await poll('collectXrayAgentOnlineStates', 45_000, ['stream']);
        await poll('collectAllStats', 90_000, ['stream']);
        await poll('collectAllStats', 120_000, []);
    });
    await t.test('an older in-flight /online reply cannot erase new log or traffic evidence', async t => {
        const { wire, poll } = await setup(t);
        let arrived, release;
        const firstRequest = new Promise(resolve => { arrived = resolve; });
        const reply = new Promise(resolve => { release = resolve; });
        wire.holdOnline = async () => { arrived(); await reply; };
        const olderPoll = sync.collectXrayAgentOnlineStates();
        try {
            await firstRequest;
            wire.online = { journal: { online: true } };
            wire.stats = { users: { stream: { tx: 1 } } };
            await poll('collectAllStats', 5_000, ['journal', 'stream']);
        } finally {
            release();
            await olderPoll;
        }
        assert.deepEqual(Object.keys(await cache.getXrayOnlineUsers()).sort(), ['journal', 'stream']);
    });
});

test('periodic refresh demotes live cc-agent with dead Xray, then proves idle recovery', async t => {
    const f = await fixture(t);
    const first = await f.read();
    await sync.healthCheck();
    let row = await f.read();
    assert.equal(row.status, 'offline');
    assert.equal(row.agentStatus, 'online');
    assert.equal(row.agentVersion, '1.4.0');
    assert.equal(row.onlineUsers, 0);
    assert.match(row.lastError, /Xray.*unavailable/i);
    assert.equal(f.invalidations.includes('invalidateAllSubscriptions'), true);
    assert.equal(f.events[0][0], webhook.EVENTS.NODE_OFFLINE);
    f.wire.online = { recent: { online: true } };
    f.wire.stats = { ...ZERO_STATS, node: { tx: 5, rx: 0 } };
    await sync.collectAllStats();
    await sync.collectXrayAgentOnlineStates();
    row = await f.read();
    assert.equal(row.status, 'offline');
    assert.equal(row.onlineUsers, 0);
    assert.deepEqual(f.published.at(-1), []);
    assert.equal(row.traffic.tx, 5, 'traffic accounting is independent of readiness');
    assert.equal(f.wire.requests.every(request => request.startsWith('GET ')), true);
    f.wire.health = 'online';
    f.wire.stats = ZERO_STATS;
    f.wire.online = {};
    await sync.healthCheck();
    await sync.collectAllStats();
    row = await f.read();
    assert.equal(row.status, 'online');
    assert.equal(row.onlineUsers, 0);
    assert.equal(row.lastError, '');
    assert.equal(row.healthFailures, 0);
    assert.ok(row.agentLastSeen instanceof Date);
    assert.ok(!first.agentLastSeen || row.agentLastSeen >= first.agentLastSeen);
    assert.equal(f.events.at(-1)[0], webhook.EVENTS.NODE_ONLINE);
});

test('old agent, invalid proof and no agent are unknown, not healthy', async t => {
    for (const state of ['legacy', 'malformed', 'no-agent']) {
        await t.test(state, async t => {
            const f = await fixture(t, { agent: state !== 'no-agent' });
            f.wire.health = state;
            await sync.healthCheck();
            const row = await f.read();
            assert.equal(row.status, 'unknown');
            assert.match(row.lastError, /Xray health unknown/);
            assert.equal(row.agentStatus, state === 'no-agent' ? 'unknown' : 'online');
            assert.equal(row.onlineUsers, 0);
            assert.deepEqual(f.events, [], 'no outage alert without positive evidence');
            assert.ok(f.invalidations.includes('invalidateNodes'));
            if (state === 'no-agent') assert.deepEqual(f.wire.requests, []);
            await sync.collectXrayAgentOnlineStates();
            assert.deepEqual(f.published.at(-1), []);
        });
    }
});

test('unknown passes node schema validation and renders warning badges on desktop and mobile', async () => {
    const node = new HyNode({ name: 'unverified', type: 'xray', status: 'unknown', agentStatus: 'online' });
    assert.equal(node.validateSync('status'), undefined);
    const html = await require('ejs').renderFile(path.join(__dirname, '../../../views/nodes.ejs'), {
        nodes: [node], groups: [], linksCount: 0, ipProtocolCount: {}, csrfToken: '', loadBalancingEnabled: false,
        t: key => key === 'nodes.statusUnknown' ? 'Unknown' : key,
    });
    assert.match(html, /<option value="unknown">Unknown<\/option>/);
    const badges = [...html.matchAll(/<span class="badge badge-(\w+)" data-node-status-badge[^>]*>\s*(\w+)\s*<\/span>/g)];
    assert.deepEqual(badges.map(([, variant, label]) => [variant, label]), [['warning', 'Unknown'], ['warning', 'Unknown']]);
});

test('agent connection failures debounce; liveness cannot reset the Xray failure streak', async t => {
    const f = await fixture(t);
    f.wire.health = 'timeout';
    for (let count = 1; count <= 3; count++) {
        await sync.healthCheck();
        const row = await f.read();
        assert.equal(row.healthFailures, count);
        assert.equal(row.status, count < 3 ? 'online' : 'offline');
        assert.equal(row.agentStatus, 'online');
        assert.match(row.lastError, /Xray health unknown/);
    }
});

test('mounted info/status/reset separate agent liveness from Xray and never write remotely', async t => {
    const f = await fixture(t, { status: 'offline' });
    const request = await mountedApi(t, f);
    assert.notEqual((await request('agent-info', 'GET', false)).status, 200);
    assert.deepEqual(f.wire.requests, []);
    const down = await request('agent-info');
    assert.equal(down.status, 200);
    assert.equal(down.body.agent_status, 'online');
    assert.equal(down.body.xray_status, 'offline');
    assert.equal(down.body.users_count, 0);
    assert.equal((await request('reset-status', 'POST')).status, 409);
    assert.equal((await request('status')).body.status, 'offline');
    f.wire.health = 'legacy';
    assert.equal((await request('agent-info')).body.xray_status, 'unknown');
    assert.equal((await request('reset-status', 'POST')).status, 409);
    f.wire.health = 'online';
    assert.equal((await request('agent-info')).body.xray_status, 'online');
    assert.equal((await request('status')).body.status, 'unknown', 'GET does not mutate stored status');
    assert.equal((await request('reset-status', 'POST')).status, 200);
    assert.equal((await request('status')).body.status, 'online');
    assert.equal(f.wire.requests.every(request => request.startsWith('GET ')), true);
});

test('topology-managed user-only sync needs Xray proof, not successful empty POST /sync', async t => {
    const f = await fixture(t);
    t.mock.method(sync, '_topologyManagesNode', async () => true);
    t.mock.method(sync, '_getUsersForNode', async () => []);
    assert.equal(await sync.updateXrayNodeConfig(await f.read()), false);
    assert.equal((await f.read()).status, 'offline');
    assert.ok((await f.read()).lastSync instanceof Date);
    f.wire.health = 'online';
    assert.equal(await sync.updateXrayNodeConfig(await f.read()), true);
    assert.equal((await f.read()).status, 'online');
    assert.deepEqual(f.wire.requests.filter(request => request.startsWith('POST ')), ['POST /sync', 'POST /sync']);
});


test('classic sync with successful restart and empty user reconciliation cannot heal dead Xray', async t => {
    const f = await fixture(t);
    t.mock.method(sync, '_topologyManagesNode', async () => false);
    t.mock.method(sync, '_getUsersForNode', async () => []);
    t.mock.method(require('../configGenerator'), 'generateXrayConfigWithApi', () => '{}');
    assert.equal(await sync.updateXrayNodeConfig(await f.read()), false);
    assert.equal((await f.read()).status, 'offline');
    f.wire.health = 'online';
    assert.equal(await sync.updateXrayNodeConfig(await f.read()), true);
    assert.equal((await f.read()).status, 'online');
    assert.deepEqual(f.wire.requests.filter(request => request.startsWith('POST ')),
        ['POST /restart', 'POST /sync', 'POST /restart', 'POST /sync']);
});

test('REST and MCP setup distinguish down, deferred activation, unavailable verification and healthy Xray', async t => {
    const f = await fixture(t, { ssh: true });
    const setupCall = t.mock.method(nodeSetup, 'setupXrayNodeWithAgent', async () => ({
        success: true, logs: ['systemd verified active'], agentToken: TOKEN,
    }));
    const request = await mountedApi(t, f);
    const mcp = (setupOptions) => manageNode({ action: 'setup', id: f.id, setupOptions }, () => {});
    for (const [health, restartService, status, xrayStatus] of [
        ['offline', undefined, 502, 'offline'],
        ['offline', false, 200, 'offline'],
        ['legacy', true, 200, 'unknown'],
        ['online', true, 200, 'online'],
    ]) {
        f.wire.health = health;
        const options = restartService === undefined ? undefined : { restartService };
        const responses = [await request('setup', 'POST', true, options), { body: await mcp(options) }];
        for (const response of responses) {
            const result = response.body;
            assert.equal(response.status ?? result.code ?? 200, status);
            assert.equal(result.success, status === 200);
            assert.equal(result.xray_status, xrayStatus);
            assert.equal(result.xray_verification, xrayStatus === 'unknown' ? 'unavailable' : 'available');
            assert.ok(result.logs.includes('systemd verified active'));
            if (xrayStatus === 'unknown') {
                assert.match(result.warning, /does not support/);
                assert.ok(result.logs.some(log => log.includes(result.warning)));
                assert.equal(result.error, undefined);
            } else if (status === 502) {
                assert.match(result.error, /Xray runtime API unavailable/);
            }
        }
        assert.equal((await f.read()).status, xrayStatus);
    }
    assert.deepEqual(setupCall.mock.calls.map(call => call.arguments[1].restartService), [true, true, false, false, true, true, true, true]);
    assert.ok(f.wire.requests.every(request => request.startsWith('GET ')));
});

test('MCP reset refuses to certify offline or unknown Xray and verifies healthy Xray', async t => {
    const f = await fixture(t);
    const reset = () => manageNode({ action: 'reset_status', id: f.id }, () => {});
    assert.equal((await reset()).code, 409);
    assert.equal((await f.read()).status, 'offline');
    f.wire.health = 'legacy';
    const unknown = await reset();
    assert.equal(unknown.code, 409);
    assert.equal(unknown.xray_status, 'unknown');
    assert.equal(unknown.xray_verification, 'unavailable');
    assert.match(unknown.error, /does not support/);
    assert.equal((await f.read()).status, 'unknown');
    f.wire.health = 'online';
    assert.equal((await reset()).success, true);
    assert.equal((await f.read()).status, 'online');
    assert.ok(f.wire.requests.every(request => request.startsWith('GET ')));
});

test('panel setup redeploys links only with verified Xray', async t => {
    const f = await fixture(t, { ssh: true });
    t.mock.method(nodeSetup, 'setupXrayNodeWithAgent', async () => ({ success: true, logs: [], agentToken: TOKEN }));
    const count = t.mock.method(require('../../models/cascadeLinkModel'), 'countDocuments', async () => 1);
    const redeploy = t.mock.method(require('../cascadeService'), 'redeployAllLinksForNode', async () => {});
    const app = express();
    app.use('/panel', require('../../routes/panel/nodes'));
    const port = await listen(t, app);
    for (const [health, status, redeploys] of [['offline', 502, 0], ['legacy', 200, 0], ['online', 200, 1]]) {
        f.wire.health = health;
        const res = await fetch(`http://127.0.0.1:${port}/panel/nodes/${f.id}/setup`, { method: 'POST' });
        const body = await res.json();
        assert.equal(res.status, status);
        assert.equal(body.success, status === 200);
        assert.equal(body.xray_status, health === 'legacy' ? 'unknown' : health);
        assert.equal(count.mock.callCount(), redeploys);
        assert.equal(redeploy.mock.callCount(), redeploys);
        if (health === 'legacy') assert.match(body.warning, /does not support/);
        if (health === 'offline') assert.match(body.error, /Xray runtime API unavailable/);
    }
    assert.ok(f.wire.requests.every(request => request.startsWith('GET ')));
});

test('wizard progress blocks onboarding for verified down Xray but completes with an explicit legacy warning', async t => {
    const f = await fixture(t, { ssh: true });
    t.mock.method(nodeSetup, 'setupXrayNodeWithAgent', async () => ({ success: true, logs: [], agentToken: TOKEN }));
    const settings = require('../../models/settingsModel');
    t.mock.method(settings, 'get', async () => ({ deployment: { completed: false } }));
    const update = t.mock.method(settings, 'update', async () => {});
    t.mock.method(HyNode, 'updateMany', async () => {});
    t.mock.method(cache, 'invalidateGroups', async () => {});
    t.mock.method(require('../../models/serverGroupModel'), 'findOneAndUpdate', async () => ({ _id: f.id, name: 'fixture group' }));
    const user = require('../../models/hyUserModel');
    t.mock.method(user, 'findOne', async () => ({ _id: f.id, userId: 'admin' }));
    t.mock.method(user, 'updateOne', async () => {});
    t.mock.method(user, 'findById', async () => ({ userId: 'admin', subscriptionToken: 'fixture-subscription' }));
    const setTimeout = global.setTimeout;
    const timers = [];
    t.mock.method(global, 'setTimeout', (callback, delay, ...args) => {
        const timer = setTimeout(callback, delay, ...args);
        if (delay === 10 * 60 * 1000) timers.push(timer);
        return timer;
    });
    t.after(() => timers.forEach(timer => clearTimeout(timer)));

    const app = express();
    app.use(express.json());
    app.use('/panel', require('../../routes/panel/wizard'));
    const port = await listen(t, app);
    for (const [health, success, completed] of [['offline', false, 0], ['legacy', true, 1], ['online', true, 2]]) {
        f.wire.health = health;
        const res = await fetch(`http://127.0.0.1:${port}/panel/wizard/self-host`, {
            method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ installXray: 'on', 'ssh.ip': '127.0.0.1', 'ssh.password': 'fixture' }),
        });
        const location = res.headers.get('location');
        assert.match(location, /^\/panel\/wizard\/progress\/[^/]+$/);
        const stream = await fetch(`http://127.0.0.1:${port}${location}/stream`, { signal: AbortSignal.timeout(3000) });
        const text = await stream.text();
        const events = text.split('\n').filter(line => line.startsWith('data: ')).map(line => JSON.parse(line.slice(6)));
        const done = events.at(-1);
        assert.equal(done.type, 'done');
        assert.equal(done.success, success);
        assert.equal(done.xray_status, health === 'legacy' ? 'unknown' : health);
        assert.equal(done.xray_verification, health === 'legacy' ? 'unavailable' : 'available');
        assert.equal(Boolean(done.starterSubscription), success);
        assert.equal(update.mock.callCount(), completed);
        assert.equal((await f.read()).status, health === 'legacy' ? 'unknown' : health);
        if (health === 'offline') {
            assert.match(text, /\[FAIL\] Xray runtime API unavailable/);
            assert.doesNotMatch(text, /Xray node setup completed|fixture-subscription/i);
        } else if (health === 'legacy') {
            assert.match(text, /\[Warning\].*does not support/);
        } else {
            assert.match(text, /\[OK\] Xray runtime API verified/);
        }
    }
    assert.ok(f.wire.requests.every(request => request.startsWith('GET ')));
});

test('a delayed old healthy observation cannot overwrite confirmed Xray failure', { timeout: 3000 }, async t => {
    const f = await fixture(t);
    f.wire.health = 'online';
    let release, arrived;
    const firstInfo = new Promise(resolve => { arrived = resolve; });
    const firstHealth = new Promise(resolve => { f.wire.healthObserved = resolve; });
    const gate = new Promise(resolve => { release = resolve; });
    f.wire.holdInfo = () => { arrived(); return gate; };
    const slow = sync.checkXrayAgentHealth(await f.read());
    try {
        await firstInfo;
        assert.equal(await firstHealth, 'online');
        // Give the second request a distinct persisted timestamp.
        await new Promise(resolve => setTimeout(resolve, 5));
        f.wire.health = 'offline';
        await sync.checkXrayAgentHealth(await f.read());
        assert.equal((await f.read()).status, 'offline');
    } finally {
        release();
        await slow;
    }
    assert.equal((await f.read()).status, 'offline');
});


test('agent-less enable changes administrative state without reporting Xray online', async t => {
    const f = await fixture(t, { status: 'offline', agent: false, ssh: true });
    await HyNode.updateOne({ _id: f.id }, { $set: { active: false } });
    const start = t.mock.method(nodeSetup, 'startNodeRuntime', async () => ({ success: true, service: 'xray' }));
    const request = await mountedApi(t, f);
    assert.equal((await request('enable', 'POST')).status, 200);
    const row = await f.read();
    assert.equal(row.active, true);
    assert.equal(row.status, 'unknown');
    assert.match(row.lastError, /health unknown/);
    assert.equal(start.mock.callCount(), 1);
    assert.deepEqual(f.wire.requests, []);
});
