'use strict';
// Bounded real entry/cron -> real sync/cache/ioredis -> disposable Redis probe.
// Only the preceding node query/agent reply and cron time are controlled. Mongo,
// cache commands, Redis close/error handling and index.js shutdown are real.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');
const { spawn } = require('node:child_process');
const net = require('node:net');
const http = require('node:http');
const ROOT = path.resolve(__dirname, '..');
const COUNT = 24000;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

if (process.argv[2] === '--child') {
    const Module = require('node:module');
    const load = Module._load;
    const emit = (event, detail) => process.send({ event, detail });
    let release;
    const reply = new Promise(resolve => { release = resolve; });
    let telemetryTask;
    let cache;
    let polls = 0;
    const cron = require('node-cron');
    const schedule = cron.schedule.bind(cron);
    const users = Object.fromEntries(Array.from({ length: COUNT }, (_, i) => [`local-probe-${i}`, { online: true }]));
    Module._load = function(request, parent, isMain) {
        const value = load.call(this, request, parent, isMain);
        if (request === 'node-cron' && parent.filename === path.join(ROOT, 'index.js')) {
            return { ...value, schedule(expression, work) {
                // Keep node-cron's real execute/stop behavior, without wall-clock
                // ticks or unrelated daily jobs in this narrow test.
                const task = schedule('0 0 1 1 *', work);
                if (!telemetryTask) telemetryTask = task;
                return task;
            } };
        }
        if (request === './src/services/syncService' && parent.filename === path.join(ROOT, 'index.js')) {
            value._agentRequest = async () => {
                emit('POLL_PENDING', ++polls);
                await reply;
                return { data: { users } };
            };
            const Node = load.call(this, './src/models/hyNodeModel', parent, false);
            const find = Node.find.bind(Node);
            Node.find = function(query, ...args) {
                if (query?.['xray.agentToken']?.$exists === true) {
                    return Promise.resolve([{ _id: 'local-node', type: 'xray', active: true }]);
                }
                return find(query, ...args);
            };
        }
        if (request === './src/services/cacheService' && parent.filename === path.join(ROOT, 'index.js')) {
            cache = value;
            const connect = value.connect.bind(value);
            value.connect = async () => {
                await connect();
                const client = value.redis;
                const send = client.sendCommand.bind(client);
                client.sendCommand = function(command, ...args) {
                    emit('COMMAND', command.name);
                    const pending = send(command, ...args);
                    if (command.name === 'setex') pending.then(
                        () => emit('SETEX_ACK'), error => emit('SETEX_ERROR', error.message));
                    return pending;
                };
                client.on('error', error => emit('REDIS_ERROR', error.code));
                const quit = client.quit.bind(client);
                client.quit = () => {
                    // A real slow-reader window makes post-QUIT writes reliably
                    // reach the server's closed TCP socket. No error is injected.
                    client.stream.pause();
                    const pending = quit();
                    emit('QUIT_SENT');
                    release();
                    setTimeout(() => client.stream.resume(), 150);
                    return pending;
                };
            };
        }
        return value;
    };
    process.on('message', async command => {
        try {
            if (command === 'BEGIN') {
                assert.ok(cache.isConnected());
                telemetryTask.execute().then(() => emit('POLL_JOINED'), error => emit('POLL_ERROR', error.message));
            } else if (command === 'LATE_TICK') {
                await telemetryTask.execute();
                emit('LATE_TICK_FINISHED', polls);
            } else if (command === 'RELEASE') release();
        } catch (error) { emit('PROBE_ERROR', error.stack); process.exit(2); }
    });
    require(path.join(ROOT, 'index.js'));
} else {
    const test = require('node:test');
    const Redis = require('ioredis');
    const { MongoClient } = require('mongodb');
    const redact = text => text.replace(/(?:redis|rediss|mongodb(?:\+srv)?|https?):\/\/[^\s"']+/g, '[REDACTED_CONNECTION_STRING]');
    async function port() {
        const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
        const value = server.address().port; await new Promise(resolve => server.close(resolve)); return value;
    }
    async function until(work, ms = 20000) {
        const deadline = Date.now() + ms; let last;
        while (Date.now() < deadline) { try { return await work(); } catch (error) { last = error; await pause(25); } }
        throw last || Error('probe deadline');
    }
    function child(binary, args, env, cwd) {
        const p = spawn(binary, args, { env, cwd, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
        p.output = ''; p.events = [];
        p.stdout.on('data', b => { p.output += b; }); p.stderr.on('data', b => { p.output += b; });
        p.on('message', e => p.events.push(e));
        p.done = once(p, 'exit'); return p;
    }
    async function stop(p) {
        if (p.exitCode !== null || p.signalCode !== null) return;
        p.kill('SIGTERM');
        const deadline = setTimeout(() => p.kill('SIGKILL'), 8000);
        let result;
        try { result = await p.done; } finally { clearTimeout(deadline); }
        assert.deepEqual(result, [0, null], 'fixture must exit without SIGKILL');
    }
    function request(port) {
        return new Promise((resolve, reject) => {
            const q = http.get({ host: '127.0.0.1', port, path: '/classic-ready', agent: false }, r => {
                let body = ''; r.on('data', b => { body += b; }); r.on('end', () => resolve({ status: r.statusCode, body }));
            });
            q.setTimeout(1000, () => q.destroy(Error('HTTP deadline'))); q.on('error', reject);
        });
    }
    test('SIGTERM joins admitted classic telemetry before Redis QUIT and refuses a queued late tick', { timeout: 45000 }, async t => {
        assert.ok(process.env.C3_MONGOD); assert.ok(process.env.C3_REDIS_SERVER); assert.ok(process.env.C3_REDIS_SHUTDOWN_EVIDENCE);
        const evidence = process.env.C3_REDIS_SHUTDOWN_EVIDENCE;
        const dir = fs.mkdtempSync(path.join(process.env.TMPDIR, 'redis-shutdown-'));
        const peers = []; let app, rc, mc;
        t.after(async () => {
            const errors = [];
            try { await rc?.quit(); await mc?.close(); } catch (error) { errors.push(String(error)); }
            for (const p of [app, ...peers].filter(Boolean)) {
                try { await stop(p); } catch (error) { errors.push(String(error)); }
            }
            for (const [i, p] of [app, ...peers].filter(Boolean).entries()) {
                fs.writeFileSync(path.join(evidence, `child-${i}.log`), redact(p.output));
            }
            fs.writeFileSync(path.join(evidence, 'processes.json'), JSON.stringify({
                events: app?.events, errors, children: [app, ...peers].filter(Boolean).map(p => ({ pid: p.pid, exit: p.exitCode, signal: p.signalCode })),
            }, null, 2) + '\n');
            assert.deepEqual(errors, []);
            fs.rmSync(dir, { recursive: true });
        });
        const mp = await port(), rp = await port(), hp = await port();
        const db = path.join(dir, 'mongo'); fs.mkdirSync(db);
        peers.push(child(process.env.C3_MONGOD, ['--dbpath', db, '--bind_ip', '127.0.0.1', '--port', String(mp), '--wiredTigerCacheSizeGB', '0.25'], process.env, dir));
        peers.push(child(process.env.C3_REDIS_SERVER, ['--bind', '127.0.0.1', '--port', String(rp), '--save', '', '--appendonly', 'no', '--maxmemory', '64mb', '--dir', dir], process.env, dir));
        mc = new MongoClient(`mongodb://127.0.0.1:${mp}/shutdown_local`, { serverSelectionTimeoutMS: 300 });
        await until(() => mc.connect());
        rc = new Redis(rp, '127.0.0.1', { lazyConnect: true, retryStrategy: () => 50 });
        rc.on('error', () => {}); await until(async () => { if (rc.status === 'wait') await rc.connect(); assert.equal(await rc.ping(), 'PONG'); });
        const settings = { version: 1, context: 'test.infograd.online', stateDirectory: path.join(dir, 'state'), listenAddress: '127.0.0.1', environment: {
            PANEL_DOMAIN: 'test.infograd.online', ACME_EMAIL: 'local@example.invalid', ENCRYPTION_KEY: 'e'.repeat(32), SESSION_SECRET: 's'.repeat(32),
            MONGO_URI: `mongodb://127.0.0.1:${mp}/shutdown_local`, REDIS_URL: `redis://127.0.0.1:${rp}`, USE_CADDY: 'true', PORT: String(hp),
            L2TP_EXECUTION_ENABLED: 'false', L2TP_MIGRATIONS_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', L2TP_PRODUCTION_EXECUTION_ENABLED: 'false',
        } };
        const file = path.join(dir, 'settings.json'); fs.writeFileSync(file, JSON.stringify(settings), { mode: 0o600 });
        app = child(process.execPath, [__filename, '--child'], { C3_SETTINGS: file, NODE_ENV: 'production', NODE_PATH: process.env.NODE_PATH }, dir);
        await until(async () => { assert.equal(app.exitCode, null, app.output); const r = await request(hp); assert.equal(r.status, 200); assert.equal(r.body, 'c3-classic-ready-v1\n'); });
        app.send('BEGIN');
        await until(() => assert.ok(app.events.some(e => e.event === 'POLL_PENDING')));
        app.kill('SIGTERM');
        await pause(75);
        // On OLD, quit itself releases the late reply and naturally exits 1.
        // On the candidate, shutdown must still be waiting with Redis usable.
        if (app.exitCode === null && app.connected) {
            app.kill('SIGINT');
            app.send('LATE_TICK');
            await until(() => {
                assert.ok(app.exitCode !== null || app.events.some(e => e.event === 'LATE_TICK_FINISHED'));
            });
            if (app.connected) app.send('RELEASE');
        }
        const exit = await app.done;
        assert.deepEqual(exit, [0, null], JSON.stringify(app.events) + '\n' + redact(app.output));
        const events = app.events;
        const ack = events.findIndex(e => e.event === 'SETEX_ACK');
        const quit = events.findIndex(e => e.event === 'QUIT_SENT');
        assert.ok(ack >= 0 && ack < quit, JSON.stringify(events));
        assert.equal(events.filter(e => e.event === 'POLL_PENDING').length, 1, 'late tick must not admit another node poll');
        assert.equal(events.some(e => ['SETEX_ERROR', 'REDIS_ERROR', 'PROBE_ERROR'].includes(e.event)), false);
        const persisted = JSON.parse(await rc.get('xray:online:users'));
        assert.equal(Object.keys(persisted).length, COUNT, 'all admitted users must reach real Redis, not be dropped at shutdown');
        assert.ok(persisted['local-probe-0']); assert.ok(persisted[`local-probe-${COUNT - 1}`]);
        t.diagnostic(JSON.stringify({ events, naturalExit: exit, persistedUsers: Object.keys(persisted).length }));
    });
}
