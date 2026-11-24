'use strict';

// Exact panel entry with real HTTP, Express/session/RedisStore, cron admission,
// sync, Axios and MCP. No external services: Mongo and Redis calls are modeled.
const assert = require('node:assert/strict');
const { fork } = require('node:child_process');
const { once, EventEmitter } = require('node:events');
const http = require('node:http');
const path = require('node:path');
const { test } = require('node:test');
const ROOT = path.resolve(__dirname, '..');
const CLIENTS = '/api/cascade/topology/clients';
const ID = '507f1f77bcf86cd799439011';
const PEER = '203.0.113.211';
const KEY = 'fixture-nodes-read-mcp-key';
const SECRET = 'fixture-session-secret-never-used-outside-this-test';
const cookie = sid => 'connect.sid=' + encodeURIComponent('s:' + require('cookie-signature').sign(sid, SECRET));

if (process.argv[2] === '--fixture') {
    const Module = require('node:module');
    const load = Module._load;
    const mongo = require('mongoose');
    const { ObjectId } = mongo.Types;
    mongo.connect = async () => {
        // No connection/DDL is actually opened in this fixture. Model.init's
        // default disconnected buffer must not masquerade as admitted DDL.
        for (const model of Object.values(mongo.models)) model.$init = Promise.resolve();
    };
    mongo.disconnect = async () => { process.send('MONGO_CLOSE'); };
    mongo.connection.collection = () => ({ dropIndex: async () => {}, indexes: async () => [] });
    const logs = [];
    const logger = Object.assign(new EventEmitter(), { logEmitter: new EventEmitter(), getRecentLogs: () => logs });
    for (const level of ['error', 'warn', 'info', 'debug']) logger[level] = (...args) => logs.push(args);
    const tasks = new Map();
    const cacheWrites = [];
    const mongoWrites = [];
    let served;
    let release;
    const sessions = new Map(Object.entries({
        good: { authenticated: true, adminUsername: 'fixture-admin' },
        stale: { authenticated: true, adminUsername: 'removed-admin' },
        weak: { authenticated: true },
        pending: { panelLogin2faPending: { username: 'fixture-admin' } },
    }));
    const agents = http.createServer(async (req, res) => {
        if (req.url !== '/online-ips' || req.headers.authorization !== 'Bearer fixture-agent-bearer') {
            res.writeHead(403).end();
            return;
        }
        if (release) {
            process.send('AGENT_HELD');
            await served;
        }
        res.setHeader('Content-Type', 'application/json');
        const now = new Date().toISOString();
        res.end(JSON.stringify({ supported: true, updatedAt: now, users: { 'fixture-user': [{ ip: PEER, lastSeen: now }] } }));
    });
    Module._load = function(request, parent, isMain) {
        const fromEntry = parent?.filename === path.join(ROOT, 'index.js');
        if (request.endsWith('/utils/logger') || request === '../utils/logger') return logger;
        if (fromEntry && request === './src/classicSettings') return null;
        if (fromEntry && request === './src/modules/l2tpRuntimeLifecycleHook') {
            return { productionSchemaConnectionOptions: () => ({}), createL2tpRootLifecycle: () => ({
                startAfterDatabase: async () => {}, stop: async () => {},
            }) };
        }
        if (fromEntry && request === 'http') return { ...http, createServer(app) {
            const server = http.createServer(app);
            const listen = server.listen.bind(server);
            server.listen = (_port, callback) => listen(0, '127.0.0.1', () => {
                callback();
                process.send({ port: server.address().port, schedules: [...tasks.keys()] });
            });
            return server;
        } };
        if (fromEntry && request === 'node-cron') return { schedule(expression, run) {
            const task = { run, stop() { process.send(`STOP ${expression}`); } };
            tasks.set(expression, task);
            return task;
        } };
        if (fromEntry && request === './src/services/accessLogs/processService') return { start() {} };
        return load.call(this, request, parent, isMain);
    };
    agents.listen(0, '127.0.0.1', () => {
        const node = { _id: new ObjectId(ID), ip: '127.0.0.1', type: 'xray', active: true, status: 'online',
            onlineUsers: 0, cascadeRole: 'portal', agentVersion: '1.6.0', groups: [],
            xray: { agentTls: false, agentPort: agents.address().port, agentToken: 'fixture-agent-bearer' },
        };
        // Real Mongoose query projection and casting, intercepted at the collection.
        const HyNode = require('../src/models/hyNodeModel');
        const HyUser = require('../src/models/hyUserModel');
        const Admin = require('../src/models/adminModel');
        const ApiKey = require('../src/models/apiKeyModel');
        const project = (doc, projection) => require('mongoose/lib/helpers/projection/applyProjection')(
            doc, projection && { _id: 1, ...projection });
        const cursor = rows => ({ toArray: async () => rows });
        HyNode.collection.find = (_query, opt) => cursor([project(node, opt.projection)]);
        HyNode.collection.findOne = async (query, opt) => String(query._id) === ID ? project(node, opt.projection) : null;
        HyNode.collection.updateOne = async (query, update) => {
            mongoWrites.push({ query, update });
            node.onlineUsers = update.$set.onlineUsers;
            return { matchedCount: 1 };
        };
        HyNode.collection.updateMany = HyUser.collection.updateMany = async () => ({ modifiedCount: 0 });
        HyUser.collection.find = (query, opt = {}) => cursor(query.nodes && query.userId?.$in?.includes('fixture-user') ? [project({
            _id: new ObjectId(), userId: 'fixture-user', username: 'Fixture Display', enabled: true,
        }, opt.projection)] : []);
        Admin.collection.findOne = async query => query.username === 'fixture-admin' ? { _id: new ObjectId() } : null;
        ApiKey.findByKey = async key => key === KEY ? { _id: new ObjectId(), keyPrefix: 'fixture-key',
            scopes: ['nodes:read', 'mcp:enabled'], rateLimit: 20 } : null;
        ApiKey.findByIdAndUpdate = async () => {};
        const cache = require('../src/services/cacheService');
        cache.connect = async () => {
            cache.connected = true;
            cache.redis = {
                async get(key) {
                    const session = sessions.get(key.slice(5));
                    return session && JSON.stringify({ ...session, cookie: { originalMaxAge: 86400_000, secure: false } });
                },
                async setex(...args) { cacheWrites.push(args); process.send('SETEX'); },
                async expire() {}, async ping() { return 'PONG'; },
                async quit() { agents.close(); process.send('REDIS_QUIT'); },
            };
        };
        cache.checkApiKeyRateLimit = async () => ({ allowed: true, limit: 20, count: 1 });
        require('../src/models/settingsModel').get = async () => ({ deployment: { completed: true } });
        require('../src/services/homepageService').init = async () => {};
        require('../src/services/expireScheduler').init = async () => {};
        process.on('message', async msg => {
            if (msg === 'TICK') {
                await tasks.get('*/15 * * * * *').run();
                process.send({ tick: true, count: node.onlineUsers, validWrites: mongoWrites.length > 0 && cacheWrites.length > 0,
                    leak: JSON.stringify({ logs, mongoWrites, cacheWrites }).includes(PEER) });
            } else if (msg === 'OLD') {
                node.agentVersion = '1.5.1'; process.send('OLD');
            } else if (msg === 'UNKNOWN') {
                node.agentVersion = '1.4.0'; node.status = 'unknown'; process.send('UNKNOWN');
            } else if (msg === 'HOLD') {
                node.agentVersion = '1.6.0'; node.status = 'online';
                served = new Promise(resolve => { release = resolve; });
                await tasks.get('*/15 * * * * *').run();
            } else if (msg === 'RELEASE') release();
        });
        require('../index');
    });
} else {
    test('mounted panel requires an admin cookie, keeps MCP unchanged and joins the client poll at SIGTERM', { timeout: 12000 }, async t => {
        const child = fork(__filename, ['--fixture'], { cwd: ROOT, env: {
            PATH: process.env.PATH, NODE_PATH: process.env.NODE_PATH, NODE_ENV: 'test',
            PANEL_DOMAIN: 'fixture.invalid', ACME_EMAIL: 'fixture@fixture.invalid', ENCRYPTION_KEY: 'x'.repeat(32),
            SESSION_SECRET: SECRET, SESSION_COOKIE_SECURE: 'false', USE_CADDY: 'true', PORT: '0',
        }, silent: true });
        const exit = once(child, 'exit');
        const messages = [];
        let stderr = '';
        child.on('message', msg => messages.push(msg));
        child.stderr.on('data', data => { stderr += data; });
        child.stdout.resume();
        t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await exit; });
        const waitFor = async predicate => {
            for (let tries = 0; tries < 500; tries++) {
                const result = messages.find(predicate);
                if (result) return result;
                if (child.exitCode !== null) break;
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            assert.fail('missing child observation: ' + JSON.stringify(messages) + stderr);
        };
        const { port, schedules } = await waitFor(msg => msg?.port);
        for (const expression of ['*/5 * * * * *', '*/15 * * * * *', '*/30 * * * * *']) assert(schedules.includes(expression));
        const call = (pathname, headers = {}, { method = 'GET', data } = {}) => new Promise((resolve, reject) => {
            const req = http.request({ host: '127.0.0.1', port, path: pathname, method, agent: false, headers }, res => {
                let body = ''; res.setEncoding('utf8').on('data', s => { body += s; });
                res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
            });
            req.setTimeout(2000, () => req.destroy(new Error(`HTTP fixture deadline: ${pathname}`)));
            req.on('error', reject); req.end(data);
        });
        const url = CLIENTS + '?nodeId=' + ID;
        const mcpList = async () => {
            const data = JSON.stringify({ jsonrpc: '2.0', id: 'fixture', method: 'tools/list' });
            const response = await call('/api/mcp', { 'x-api-key': KEY, 'content-type': 'application/json',
                'content-length': Buffer.byteLength(data) }, { method: 'POST', data });
            assert.equal(response.status, 200);
            const { tools } = JSON.parse(response.body).result;
            assert(tools.some(tool => tool.name === 'query'));
            assert(!tools.some(tool => /client.*(?:connection|ip)|online.ips/i.test(tool.name)));
            assert(!response.body.includes(PEER));
            return response.body;
        };
        const mcpBefore = await mcpList();
        const admin = { cookie: cookie('good'), 'accept-language': 'zh-CN' };
        const expect = async (pathname, headers, status, state) => {
            const result = await call(pathname, headers);
            assert.equal(result.status, status, result.body);
            assert.equal(result.headers['cache-control'], 'no-store');
            assert.equal(result.headers['x-client-connections-state'], state);
            if (status !== 200) assert(!result.body.includes(PEER));
            return result;
        };
        await expect(url, {}, 401);
        await expect(url, { cookie: cookie('weak') }, 401);
        await expect(url, { cookie: cookie('pending') }, 401);
        await expect(url, { cookie: cookie('stale') }, 403);
        await expect(url, { cookie: 'connect.sid=tampered' }, 401);
        await expect(url, { 'x-api-key': KEY }, 403);
        await expect(url, { ...admin, authorization: `Bearer ${KEY}` }, 403);
        for (const query of ['', '?nodeId[0]=' + ID, '?nodeId=' + ID + '&nodeId=' + ID,
            '?nodeId=1234', '?nodeId=' + ID + '%0A', '?nodeId=' + ID + '&extra=x']) await expect(CLIENTS + query, admin, 400);
        const preflight = await call(url, { origin: 'https://fixture.invalid', 'access-control-request-method': 'GET' }, { method: 'OPTIONS' });
        assert.equal(preflight.headers['cache-control'], 'no-store');
        assert.equal((await expect(url, admin, 200, 'unavailable')).body, '[]');
        child.send('TICK');
        assert.deepEqual(await waitFor(msg => msg?.tick), { tick: true, count: 1, validWrites: true, leak: false });
        const ready = await expect(url, { ...admin, 'if-none-match': '*' }, 200, 'ready');
        assert.equal(ready.headers.etag, undefined);
        const [row] = JSON.parse(ready.body);
        assert.deepEqual(row, { username: 'Fixture Display', ip: PEER, country: null,
            asn: null, region: null, city: null, isp: null, lastSeen: new Date(row.lastSeen).toISOString() });
        assert.equal(await mcpList(), mcpBefore);
        child.send('OLD'); await waitFor(msg => msg === 'OLD');
        assert.equal((await expect(url, admin, 200, 'old-agent')).body, '[]');
        child.send('UNKNOWN'); await waitFor(msg => msg === 'UNKNOWN');
        assert.equal((await expect(url, admin, 200, 'unavailable')).body, '[]');
        child.send('HOLD'); await waitFor(msg => msg === 'AGENT_HELD');
        child.kill('SIGTERM'); await waitFor(msg => msg === 'STOP */15 * * * * *');
        assert(!messages.includes('REDIS_QUIT') && !messages.includes('MONGO_CLOSE'));
        child.send('RELEASE');
        await waitFor(msg => msg === 'MONGO_CLOSE');
        assert.deepEqual(await exit, [0, null], stderr);
        assert(messages.lastIndexOf('SETEX') < messages.indexOf('REDIS_QUIT'));
        assert(messages.indexOf('REDIS_QUIT') < messages.indexOf('MONGO_CLOSE'));
    });
}
