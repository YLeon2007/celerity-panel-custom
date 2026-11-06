'use strict';
// Real repository entry/routes, disposable loopback replica set + Redis. No loader
// hooks or application mocks; a socket guard refuses non-loopback TCP. C3_SETTINGS
// is absent in the ordinary regression.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { MongoClient } = require('mongodb');
const Redis = require('ioredis');
const ROOT = path.resolve(__dirname, '..');
const READY = 'c3-classic-ready-v1\n';
const NOT_READY = 'c3-classic-not-ready-v1\n';
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const flags = ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED', 'TOPOLOGY_TEST_EXECUTION_ENABLED',
    'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED', 'L2TP_PRODUCTION_EXECUTION_ENABLED',
    'CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED', 'CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED'];
async function port() {
    const s = net.createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening');
    const p = s.address().port; await new Promise(resolve => s.close(resolve)); return p;
}
async function until(work, ms = 30000) {
    const end = Date.now() + ms; let last;
    while (Date.now() < end) { try { return await work(); } catch (error) { last = error; await pause(75); } }
    throw last || Error('fixture deadline');
}
function request(p, url) {
    return new Promise((resolve, reject) => {
        const q = http.get({ hostname: '127.0.0.1', port: p, path: url, agent: false }, r => {
            let body = ''; r.on('data', b => { body += b; });
            r.on('end', () => resolve({ status: r.statusCode, body, headers: r.headers }));
        });
        q.setTimeout(2500, () => q.destroy(Error('HTTP deadline'))); q.on('error', reject);
    });
}
function witness(r, ready) {
    assert.equal(r.status, ready ? 200 : 503);
    assert.equal(r.body, ready ? READY : NOT_READY);
    assert.equal(r.headers['cache-control'], 'no-store');
}
test('ordinary TEST opt-in serves the strict witness without C3_SETTINGS; fresh mode remains identical', { timeout: 120000 }, async t => {
    for (const name of ['C3_MONGOD', 'C3_REDIS_SERVER', 'C3_ORDINARY_READINESS_EVIDENCE', 'TMPDIR']) assert.ok(process.env[name], name);
    const evidence = process.env.C3_ORDINARY_READINESS_EVIDENCE;
    const dir = fs.mkdtempSync(path.join(process.env.TMPDIR, 'ordinary-readiness-'));
    const guard = path.join(dir, 'loopback-only.cjs');
    const networkLog = path.join(evidence, 'socket-attempts.jsonl');
    // Transport exclusion only: retain the real Mongo/Redis/HTTP implementations.
    // Log and throw before any socket can contact an external address.
    fs.writeFileSync(guard, `
        const net = require('node:net'), fs = require('node:fs');
        const connect = net.Socket.prototype.connect;
        net.Socket.prototype.connect = function(...args) {
            const options = Array.isArray(args[0]) ? args[0][0] : net._normalizeArgs(args)[0];
            const host = options.host || 'localhost';
            const allowed = !options.path && ['127.0.0.1', '::1'].includes(host);
            fs.appendFileSync(${JSON.stringify(networkLog)}, JSON.stringify({ pid: process.pid, host, port: options.port, allowed }) + '\\n', { mode: 0o600 });
            if (!allowed) throw Error('non-loopback fixture connection refused');
            return connect.apply(this, args);
        };
    `, { mode: 0o600 });
    const children = [], clients = [], observations = [];
    function child(binary, args, cwd, env, name) {
        const fd = fs.openSync(path.join(evidence, name + '.log'), 'a', 0o600);
        const p = spawn(binary, args, { cwd, env, stdio: ['ignore', fd, fd] }); fs.closeSync(fd);
        p.done = once(p, 'exit'); children.push(p); return p;
    }
    async function stop(p) {
        if (p.exitCode !== null || p.signalCode !== null) {
            assert.deepEqual([p.exitCode, p.signalCode], [0, null], 'owned process already exited cleanly');
            return;
        }
        p.kill('SIGTERM'); const timer = setTimeout(() => p.kill('SIGKILL'), 12000);
        let result; try { result = await p.done; } finally { clearTimeout(timer); }
        assert.deepEqual(result, [0, null], 'owned process must shut down naturally');
    }
    t.after(async () => {
        const errors = [];
        for (const close of clients.reverse()) try { await close(); } catch (e) { errors.push(String(e)); }
        for (const p of children.slice().reverse()) try { await stop(p); } catch (e) { errors.push(String(e)); }
        const reaped = children.every(p => p.exitCode !== null || p.signalCode !== null);
        if (reaped) fs.rmSync(dir, { recursive: true });
        fs.writeFileSync(path.join(evidence, 'fixture-result.json'), JSON.stringify({ observations, errors, removed: !fs.existsSync(dir),
            children: children.map(p => ({ pid: p.pid, exit: p.exitCode, signal: p.signalCode })) }, null, 2) + '\n', { mode: 0o600 });
        assert.deepEqual(errors, []); assert.ok(reaped);
    });
    // Fresh disposable source tree: ordinary mode may write logs in its own copy.
    const app = path.join(dir, 'app'); fs.mkdirSync(app);
    const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT }).toString().split('\0').filter(Boolean);
    const manifest = [];
    for (const name of tracked) {
        const from = path.join(ROOT, name); if (!fs.statSync(from).isFile()) continue;
        const to = path.join(app, name); fs.mkdirSync(path.dirname(to), { recursive: true }); fs.copyFileSync(from, to);
        manifest.push([name, crypto.createHash('sha256').update(fs.readFileSync(to)).digest('hex')]);
    }
    fs.writeFileSync(path.join(evidence, 'executed-source-sha256.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
    const mp = await port(), rp = await port(), hp = await port();
    const mongoDir = path.join(dir, 'mongo'); fs.mkdirSync(mongoDir);
    const peerEnv = { PATH: '/usr/bin:/bin', LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH };
    child(process.env.C3_MONGOD, ['--dbpath', mongoDir, '--port', String(mp), '--bind_ip', '127.0.0.1', '--replSet', 'ordinaryLocal',
        '--wiredTigerCacheSizeGB', '0.25', '--setParameter', 'enableTestCommands=1'], dir, peerEnv, 'mongo');
    child(process.env.C3_REDIS_SERVER, ['--bind', '127.0.0.1', '--port', String(rp), '--save', '', '--appendonly', 'no', '--dir', dir], dir, peerEnv, 'redis');
    const setup = new MongoClient(`mongodb://127.0.0.1:${mp}/admin?directConnection=true`, { serverSelectionTimeoutMS: 300 });
    clients.push(() => setup.close()); await until(() => setup.connect());
    await setup.db().command({ replSetInitiate: { _id: 'ordinaryLocal', members: [{ _id: 0, host: `127.0.0.1:${mp}` }] } });
    await until(async () => assert.equal((await setup.db().command({ hello: 1 })).isWritablePrimary, true));
    const rc = new Redis(rp, '127.0.0.1', { lazyConnect: true, retryStrategy: () => 50 }); rc.on('error', () => {});
    clients.push(() => rc.quit());
    await until(async () => { if (rc.status === 'wait') await rc.connect(); assert.equal(await rc.ping(), 'PONG'); });
    for (const mode of ['ordinary', 'fresh', 'ordinary-disabled', 'ordinary-foreign']) {
        const dbName = 'ordinary_' + crypto.randomBytes(8).toString('hex');
        const uri = `mongodb://127.0.0.1:${mp}/${dbName}?replicaSet=ordinaryLocal`;
        assert.equal((await setup.db(dbName).listCollections().toArray()).length, 0, 'new empty database');
        const environment = { PANEL_DOMAIN: mode === 'ordinary-foreign' ? 'other.invalid' : 'test.infograd.online',
            ACME_EMAIL: 'local@example.invalid', ENCRYPTION_KEY: 'e'.repeat(32), SESSION_SECRET: 's'.repeat(32),
            MONGO_URI: uri, REDIS_URL: `redis://127.0.0.1:${rp}`, USE_CADDY: 'true', PORT: String(hp),
            ...Object.fromEntries(flags.map(key => [key, 'false'])) };
        let env = { ...environment, C3_TEST_CLASSIC_READY: mode === 'ordinary-disabled' ? 'false' : 'true',
            NODE_ENV: 'production', NODE_PATH: process.env.NODE_PATH, TMPDIR: dir, ACCESS_LOGS_DIR: path.join(dir, 'access-logs') };
        if (mode === 'fresh') {
            const freshEnv = { ...environment }; for (const key of flags.slice(5)) delete freshEnv[key];
            const file = path.join(dir, 'classic.json');
            fs.writeFileSync(file, JSON.stringify({ version: 1, context: 'test.infograd.online', stateDirectory: path.join(dir, 'state'),
                listenAddress: '127.0.0.1', environment: freshEnv }), { mode: 0o600 });
            env = { C3_SETTINGS: file, NODE_ENV: 'production', NODE_PATH: process.env.NODE_PATH };
        } else assert.equal(Object.hasOwn(env, 'C3_SETTINGS'), false);
        const positive = mode === 'ordinary' || mode === 'fresh';
        if (positive) await setup.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 },
            data: { failCommands: ['find'], blockConnection: true, blockTimeMS: 750 } });
        const p = child(process.execPath, ['--require', guard, path.join(app, 'index.js')], app, env, mode);
        if (positive) {
            await until(async () => {
                const ops = await setup.db('admin').aggregate([{ $currentOp: { allUsers: true } }, { $match: { 'command.find': { $exists: true }, 'command.$db': dbName } }]).toArray();
                assert.ok(ops.length > 0, 'real boot database operation is still pending');
            });
            await assert.rejects(request(hp, '/classic-ready'), 'no readiness listener before ordinary/fresh startup barriers');
            observations.push({ mode, realPrebootConnectionRefused: true });
        }
        const health = await until(async () => { assert.equal(p.exitCode, null, 'app stays alive'); const r = await request(hp, '/health'); assert.equal(r.status, 200); return JSON.parse(r.body); });
        assert.equal(health.status, 'ok'); assert.equal(typeof health.uptime, 'number');
        const r = await request(hp, '/classic-ready');
        observations.push({ mode, settingsAbsent: !env.C3_SETTINGS, healthStatus: health.status, ready: r, database: dbName });
        if (mode === 'ordinary-disabled' || mode === 'ordinary-foreign') {
            assert.equal(r.status, 404, 'ordinary endpoint is not broadly enabled');
        } else {
            witness(r, true);
            await setup.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 }, data: { failCommands: ['ping'], errorCode: 2 } });
            witness(await request(hp, '/classic-ready'), false);
            witness(await request(hp, '/classic-ready'), true);
            await rc.acl('SETUSER', 'default', '-ping');
            try { witness(await request(hp, '/classic-ready'), false); }
            finally { await rc.acl('SETUSER', 'default', '+ping'); }
            witness(await request(hp, '/classic-ready'), true);
            assert.equal(JSON.parse((await request(hp, '/health')).body).status, 'ok');
            assert.equal((await setup.db(dbName).collection('hynodes').countDocuments()), 0, 'no remote node inventory');
            observations.push({ mode, actualMongoPingFailure503: true, actualRedisPingFailure503: true, recovered: true });
            // Pause an actual Mongo PING in the server, not a promise-shaped mock.
            // HTTP shutdown must join this request, whose final recheck must 503.
            await setup.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 },
                data: { failCommands: ['ping'], blockConnection: true, blockTimeMS: 750 } });
            const pending = request(hp, '/classic-ready');
            await until(async () => {
                const ops = await setup.db('admin').aggregate([{ $currentOp: { allUsers: true } }, { $match: { 'command.ping': 1, 'command.$db': dbName } }]).toArray();
                assert.ok(ops.length > 0, 'real readiness PING is pending');
            });
            const stopped = stop(p);
            const afterStop = await pending;
            witness(afterStop, false);
            await stopped;
            observations.push({ mode, realPendingPingThenSIGTERM: afterStop, naturalExit: p.exitCode });
        }
        await stop(p); await assert.rejects(request(hp, '/classic-ready'));
    }
    const attempts = fs.readFileSync(networkLog, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.ok(attempts.length > 0); assert.ok(attempts.every(row => row.allowed), 'zero external socket attempts');
    observations.push({ loopbackSocketAttempts: attempts.length, externalAttempts: 0 });
});
