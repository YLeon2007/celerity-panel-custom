'use strict';
// Disposable replica set and loopback-only HTTP. No SSH or installed agent.
// The HTTP peer models the 1.4.0 wire responses until the listener is closed.
const assert = require('node:assert/strict');
const { once } = require('node:events');
const http = require('node:http');
const { randomUUID } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { test } = require('node:test');
const express = require('express');
const { fixture } = require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture');

async function listen(t, handler, ip = '127.0.0.1') {
    const server = http.createServer(handler).listen(0, ip);
    await once(server, 'listening');
    const port = server.address().port;
    async function close() {
        if (!server.listening) return;
        const closed = once(server, 'close');
        server.close();
        server.closeAllConnections();
        await closed;
    }
    t.after(close);
    return { port, close };
}

function agentReply(users, stats = {}) {
    return (req, res) => {
        const result = {
            '/online': { users: Object.fromEntries(users.map(id => [id, { online: true }])) },
            '/info': { agent_version: '1.4.0', xray_version: '26.3.27' },
            '/stats': { users: {}, node: { tx: 0, rx: 0 }, ...stats },
        }[req.url];
        res.writeHead(result ? 200 : 404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result || {}));
    };
}

function observeCalls(t, object, method) {
    const pending = [];
    const original = object[method];
    t.mock.method(object, method, function (...args) {
        const work = original.apply(this, args);
        pending.push(work);
        return work;
    });
    return pending;
}

test('masked cc-agent leaves real Mongo state distinct from runtime/telemetry', { timeout: 45000 }, async t => {
    // Ignore ambient dotenv entirely; harness supplies only synthetic config.
    t.mock.method(require('dotenv'), 'config', () => ({}));
    const loggerPath = require.resolve('../../utils/logger');
    require.cache[loggerPath] = { id: loggerPath, filename: loggerPath, loaded: true,
        exports: Object.fromEntries(['info', 'warn', 'debug', 'error'].map(key => [key, () => {}])) };
    t.after(() => { delete require.cache[loggerPath]; });
    const mongo = fixture();
    t.after(() => mongo.stop());
    await mongo.start();
    const { HyNode } = mongo.models;
    const HyUser = require('../../models/hyUserModel');
    const sync = require('../syncService');
    const cache = require('../cacheService');
    const stats = require('../statsService');
    const scheduler = require('../expireScheduler');
    require('../../models/serverGroupModel');
    await HyUser.init();

    const node = async (name, port, ip = '127.0.0.1') => HyNode.create({ name, type: 'xray', cascadeRole: 'portal',
        ip, port: 443, active: true,
        xray: { agentTls: false, agentPort: port, agentToken: randomUUID() } });
    const user = (userId, fields = {}) => HyUser.create({ userId, password: 'fixture-only',
        enabled: true, xrayUuid: randomUUID(), subscriptionToken: randomUUID(), ...fields });

    await t.test('online cache ages only the refused node even while other polls and stats refresh it', async t => {
        const first = await listen(t, agentReply(['masked-user'], { users: { 'masked-user': { tx: 8, rx: 3 } }, node: { tx: 50, rx: 20 } }));
        const second = await listen(t, agentReply(['working-user'], { node: { tx: 7, rx: 5 } }), '127.0.0.2');
        let stamp = performance.now();
        t.mock.method(performance, 'now', () => stamp);
        const p = await node('masked', first.port);
        const b = await node('working', second.port, '127.0.0.2');
        await user('masked-user', { nodes: [p._id] });
        const baseline = await stats.collectSnapshot();
        assert.equal(baseline.online, 0);
        assert.equal(baseline.tx, 0);
        await sync.collectAllStats();
        await sync.collectXrayAgentOnlineStates();
        assert.deepEqual(Object.keys(await cache.getXrayOnlineUsers()).sort(), ['masked-user', 'working-user']);
        const healthy = await stats.collectSnapshot();
        assert.equal(healthy.nodesOn, 2);
        assert.equal(healthy.online, 2);
        assert.equal(healthy.tx, 57);
        assert.equal(healthy.rx, 25);
        await first.close();
        assert.deepEqual(await sync.collectXrayTrafficStats(p), { ok: false, nodeKey: String(p._id), onlineUserIds: [] });
        stamp += 5000;
        await sync.collectXrayAgentOnlineStates();
        assert.deepEqual(Object.keys(await cache.getXrayOnlineUsers()).sort(), ['masked-user', 'working-user'],
            'one refusal retains the recent sample without erasing another node');
        for (let failure = 1; failure <= 3; failure++) {
            await sync.healthCheck();
            const stored = await HyNode.findById(p._id).lean();
            assert.equal(stored.healthFailures, failure);
            assert.equal(stored.agentStatus, 'offline');
            assert.match(stored.lastError, /ECONNREFUSED/);
            assert.equal(stored.status, failure < 3 ? 'online' : 'offline');
        }
        assert.equal((await HyNode.findById(p._id)).onlineUsers, 0);
        stamp += 41_000;
        await sync.collectAllStats();
        const afterStatsPoll = Object.keys(await cache.getXrayOnlineUsers());
        await sync.collectXrayAgentOnlineStates();
        const afterOnlinePoll = Object.keys(await cache.getXrayOnlineUsers());
        const unavailable = await stats.collectSnapshot();
        assert.equal(unavailable.nodesOn, 1);
        assert.equal(unavailable.online, 1);
        assert.equal(unavailable.tx, 7, 'only the still-observed agent advances traffic');
        assert.equal(unavailable.rx, 5);
        assert.deepEqual(unavailable.nodes.find(n => n.i === String(p._id)),
            { i: String(p._id), n: 'masked', o: 0, s: 'offline', t: 0, r: 0 });
        assert.equal((await HyUser.findOne({ userId: 'masked-user' })).traffic.tx, 8);
        await HyNode.updateOne({ _id: b._id }, { $set: { active: false } });
        assert.deepEqual({ afterStatsPoll, afterOnlinePoll },
            { afterStatsPoll: ['working-user'], afterOnlinePoll: ['working-user'] });
    });

    await t.test('ordinary REST add, disable and delete acknowledge Mongo, not runner user mutation', async t => {
        const p = await HyNode.findOne({ name: 'masked' });
        const adds = observeCalls(t, sync, 'addXrayUser');
        const removes = observeCalls(t, sync, 'removeXrayUser');
        const requests = [];
        const original = sync._agentRequest;
        t.mock.method(sync, '_agentRequest', async function (node, method, path, body) {
            try { return await original.call(this, node, method, path, body); }
            catch (error) { requests.push([String(node._id), method, path, error.code]); throw error; }
        });
        const app = express();
        app.use(express.json(), (req, _res, next) => { req.session = { authenticated: true }; next(); });
        app.use('/users', require('../../routes/users'));
        const server = await listen(t, app);
        const origin = `http://127.0.0.1:${server.port}/users`;
        const send = async (method, suffix, status, body) => {
            const reply = await fetch(origin + suffix, { method, headers: { 'content-type': 'application/json' },
                body: body && JSON.stringify(body) });
            assert.equal(reply.status, status);
            await reply.arrayBuffer();
        };
        const settled = async (effects, count) => {
            const deadline = Date.now() + 3000;
            while (effects.length < count && Date.now() < deadline) {
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            assert.equal(effects.length, count);
            assert.equal(await effects[count - 1], false);
        };
        await send('POST', '', 201, { userId: 'ordinary-user', enabled: true });
        await settled(adds, 1);
        assert.equal((await HyUser.findOne({ userId: 'ordinary-user' })).enabled, true);
        await send('POST', '/ordinary-user/disable', 200);
        await settled(removes, 1);
        assert.equal((await HyUser.findOne({ userId: 'ordinary-user' })).enabled, false);
        await send('DELETE', '/ordinary-user', 200);
        await settled(removes, 2);
        assert.equal(await HyUser.findOne({ userId: 'ordinary-user' }), null);
        assert.deepEqual(requests, [
            [String(p._id), 'POST', '/users', 'ECONNREFUSED'],
            [String(p._id), 'DELETE', '/users/ordinary-user', 'ECONNREFUSED'],
            [String(p._id), 'DELETE', '/users/ordinary-user', 'ECONNREFUSED'],
        ]);
    });

    await t.test('expiry processes real overdue row but must not disable a concurrently renewed row', async t => {
        const expiredAt = new Date(Date.now() - 1000);
        await user('expired-user', { expireAt: expiredAt });
        await user('renewed-user', { expireAt: expiredAt });
        const original = sync.disableUser;
        const effects = observeCalls(t, sync, 'removeXrayUser');
        t.mock.method(sync, 'disableUser', async function (snapshot, reason) {
            if (snapshot.userId === 'renewed-user') {
                assert.equal(reason, 'expired');
                await HyUser.updateOne({ userId: snapshot.userId }, { $set: { expireAt: new Date(Date.now() + 60_000) } });
            }
            return original.call(this, snapshot, reason);
        });
        const processed = await scheduler.processExpired();
        assert.equal((await HyUser.findOne({ userId: 'expired-user' })).enabled, false);
        assert.equal(await effects[0], false, 'masked runtime removal is unconfirmed even after expiry');
        assert.equal((await HyUser.findOne({ userId: 'renewed-user' })).enabled, true);
        assert.equal(processed, 1);
        assert.equal(effects.length, 1);
    });

    await t.test('traffic equality disables, concurrent reset does not, unlimited unchanged', async t => {
        await user('over-user', { trafficLimit: 10, traffic: { tx: 6, rx: 4 } });
        await user('reset-user', { trafficLimit: 10, traffic: { tx: 11, rx: 0 } });
        await user('unlimited-user', { trafficLimit: 0, traffic: { tx: 99, rx: 0 } });
        const original = sync.disableUser;
        const effects = observeCalls(t, sync, 'removeXrayUser');
        t.mock.method(sync, 'disableUser', async function (snapshot, reason) {
            if (snapshot.userId === 'reset-user') {
                assert.equal(reason, 'traffic');
                await HyUser.updateOne({ userId: snapshot.userId }, { $set: { 'traffic.tx': 0, 'traffic.rx': 0 } });
            }
            return original.call(this, snapshot, reason);
        });
        await sync.enforceTrafficLimit(['over-user', 'reset-user', 'unlimited-user']);
        assert.equal((await HyUser.findOne({ userId: 'over-user' })).enabled, false);
        assert.equal(await effects[0], false);
        assert.equal((await HyUser.findOne({ userId: 'reset-user' })).enabled, true);
        assert.equal((await HyUser.findOne({ userId: 'unlimited-user' })).enabled, true);
        assert.equal(effects.length, 1);
    });
});
