'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { createRequire } = require('node:module');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'index.js'), 'utf8');
const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function harness({ httpPending = false, httpError = null, realPool = false } = {}) {
    const drain = deferred();
    const calls = [];
    const timers = new Set();
    let now = 0;
    const timer = {
        setTimeout(fn, delay) { const handle = { fn, at: now + delay, unref() { return this; } }; timers.add(handle); return handle; },
        clearTimeout(handle) { timers.delete(handle); },
    };
    const process = new EventEmitter();
    process.exit = code => calls.push(`exit:${code}`);
    const server = { close(done) { calls.push('http-close'); if (!httpPending) done(httpError); }, closeAllConnections() { calls.push('http-force'); } };
    const poolModule = { exports: {} };
    if (realPool) {
        // Import the actual singleton BEFORE the root signal handlers, exactly
        // as index -> syncService -> NodeSSH -> sshPoolService does in production.
        vm.runInNewContext(fs.readFileSync(path.join(root, 'src/services/sshPoolService.js'), 'utf8'), {
            module: poolModule, process,
            require(name) {
                if (name === 'ssh2') return { Client: class {} };
                if (name === '../utils/logger') return { info() {}, debug() {} };
                if (name === './cryptoService') return {};
                return createRequire(path.join(root, 'src/services/sshPoolService.js'))(name);
            },
            setInterval() { return {}; }, clearInterval() {},
            setTimeout: timer.setTimeout, clearTimeout: timer.clearTimeout,
        });
    } else poolModule.exports = { beginDrain() {}, closeAll() { calls.push('pool-close'); } };
    const context = {
        sshPool: poolModule.exports,
        require: createRequire(path.join(root, 'index.js')),
        process, setTimeout: timer.setTimeout, clearTimeout: timer.clearTimeout,
        logger: { info() {}, error(...args) { calls.push(`error:${args.join(' ')}`); }, warn() {} },
        l2tpRootLifecycle: { stop() { calls.push('worker-stop'); return drain.promise; } },
        cacheService: { isConnected: () => true, redis: { async quit() { calls.push('redis-quit'); } } },
        mongoose: { async disconnect() { calls.push('mongo-disconnect'); } },
        startServer() {},
    };
    vm.createContext(context);
    vm.runInContext(source.slice(source.indexOf('// Graceful shutdown')).replace('const activeServers = [];', 'const activeServers = [server];'), Object.assign(context, { server }));
    return { calls, drain, process, timers, context, start() {
        vm.runInContext(source.slice(source.indexOf('async function startServer()'), source.indexOf('function setupWebSocketServer(')), context);
        return context.startServer();
    }, async advance(ms) {
        now += ms;
        for (const handle of [...timers]) if (handle.at <= now) { timers.delete(handle); handle.fn(); }
        await flush();
    } };
}
test('SIGTERM does not force exit at the old 10-second deadline while worker drain is pending', async () => {
    const h = harness(); h.process.emit('SIGTERM'); await flush();
    assert.equal(h.calls.filter(c => c === 'worker-stop').length, 1);
    await h.advance(10001);
    assert.equal(h.calls.some(c => c.startsWith('exit:')), false, h.calls.join(','));
    assert.equal(h.calls.includes('mongo-disconnect'), false);
    h.drain.resolve(); await flush();
    assert.deepEqual(h.calls.filter(c => !c.startsWith('error:')), ['http-close', 'worker-stop', 'pool-close', 'redis-quit', 'mongo-disconnect', 'exit:0']);
    assert.equal(h.timers.size, 0, 'success must clear every shutdown deadline');
});
test('HTTP close failure cannot abandon the worker drain', async () => {
    const h = harness({ httpError: new Error('HTTP close failed') });
    h.process.emit('SIGTERM'); await flush();
    assert.equal(h.calls.some(c => c.startsWith('exit:')), false, h.calls.join(','));
    h.drain.resolve(); await flush();
    assert.equal(h.calls.at(-1), 'exit:1');
});
test('shutdown during database connect does not start runtime or HTTP preparation later', async () => {
    const h = harness(); const connected = deferred();
    h.context.connectMongo = () => connected.promise;
    h.context.l2tpRootLifecycle.startAfterDatabase = async () => h.calls.push('runtime-start');
    h.context.cacheService.connect = async () => { h.calls.push('http-prepare'); throw new Error('must not accept'); };
    const start = h.start(); h.process.emit('SIGTERM'); await flush();
    connected.resolve(); await start;
    assert.equal(h.calls.includes('runtime-start'), false, h.calls.join(','));
    assert.equal(h.calls.includes('http-prepare'), false);
    h.drain.resolve(); await flush();
});
test('the hard deadline exits nonzero without disconnecting stores or authorizing lock cleanup', async () => {
    const h = harness(); h.process.emit('SIGTERM'); await flush();
    await h.advance(30 * 60 * 1000);
    assert.equal(h.calls.at(-1), 'exit:1');
    assert.equal(h.calls.some(c => c.includes('remote completion is uncertain')), true);
    assert.equal(h.calls.includes('redis-quit'), false);
    assert.equal(h.calls.includes('mongo-disconnect'), false);
    h.drain.resolve(); await flush();
    assert.equal(h.calls.filter(c => c.startsWith('exit:')).length, 1);
});
test('HTTP grace expiry still joins worker completion and reports an unclean shutdown', async () => {
    const h = harness({ httpPending: true }); h.process.emit('SIGTERM'); await flush();
    await h.advance(10001);
    assert.equal(h.calls.includes('worker-stop'), true);
    assert.equal(h.calls.includes('http-force'), true);
    assert.equal(h.calls.some(c => c.startsWith('exit:')), false);
    h.drain.resolve(); await flush();
    assert.equal(h.calls.at(-1), 'exit:1');
    assert.equal(h.timers.size, 0);
});
test('repeated signals and fatal exception join one drain and retain nonzero fatal status', async () => {
    const h = harness();
    h.process.emit('SIGTERM'); h.process.emit('SIGINT'); h.process.emit('SIGTERM');
    h.process.emit('uncaughtException', new Error('fatal')); await flush();
    assert.equal(h.calls.filter(c => c === 'worker-stop').length, 1);
    assert.equal(h.calls.some(c => c.startsWith('exit:')), false);
    h.drain.resolve(); await flush();
    assert.equal(h.calls.at(-1), 'exit:1');
});
test('a rejected supervised drain fails closed and does not disconnect its persistence', async () => {
    const h = harness(); h.process.emit('SIGTERM'); await flush();
    h.drain.reject(new Error('drain failed')); await flush();
    assert.equal(h.calls.at(-1), 'exit:1');
    assert.equal(h.calls.includes('mongo-disconnect'), false);
    assert.equal(h.timers.size, 0);
});
test('a fulfilled drain with unresolved ownership exits nonzero without releasing fences', async () => {
    const h = harness();
    h.process.emit('SIGTERM'); await flush();
    h.drain.resolve({ drainUncertain: true }); await flush();
    assert.equal(h.calls.at(-1), 'exit:1', h.calls.join(','));
    assert.equal(h.calls.some(c => c.includes('retain durable admissions/locks')), true);
});

test('worker drain preserves unresolved ownership evidence after a later idle tick', async () => {
    const { createL2tpWorkerLifecycle } = require('../src/modules/relay-l2tp/runtime/createL2tpWorkerLifecycle');
    const h = harness(); let tick; let runs = 0;
    const lifecycle = createL2tpWorkerLifecycle({ enabled: true,
        worker: { async runOnce() { return ++runs === 1
            ? { claimed: true, status: 'failed', stopped: true, errorCode: 'REMOTE_COMMAND_OUTCOME_UNCERTAIN' }
            : { claimed: false }; } },
        timer: { setInterval(fn) { tick = fn; return {}; }, clearInterval() {} },
    });
    lifecycle.start(); await tick(); await tick();
    h.context.l2tpRootLifecycle.stop = () => lifecycle.stop();
    h.process.emit('SIGTERM'); await flush();
    assert.equal(h.calls.at(-1), 'exit:1', h.calls.join(','));
});

test('worker retained rollback ownership is not hidden by a terminal failed status', async () => {
    const { createL2tpWorkerLifecycle } = require('../src/modules/relay-l2tp/runtime/createL2tpWorkerLifecycle');
    const h = harness(); let tick;
    const lifecycle = createL2tpWorkerLifecycle({ enabled: true,
        worker: { async runOnce() { return { claimed: true, status: 'failed', drainUncertain: true }; } },
        timer: { setInterval(fn) { tick = fn; return {}; }, clearInterval() {} },
    });
    lifecycle.start(); await tick();
    h.context.l2tpRootLifecycle.stop = () => lifecycle.stop();
    h.process.emit('SIGTERM'); await flush();
    assert.equal(h.calls.at(-1), 'exit:1', h.calls.join(','));
});

test('ordinary settled worker failure and refused execution do not make a clean shutdown fail', async () => {
    const { createL2tpWorkerLifecycle } = require('../src/modules/relay-l2tp/runtime/createL2tpWorkerLifecycle');
    for (const result of [{ claimed: true, status: 'failed' }, { claimed: false, stopped: true, unavailable: true }]) {
        const h = harness(); let tick;
        const lifecycle = createL2tpWorkerLifecycle({ enabled: true, worker: { async runOnce() { return result; } },
            timer: { setInterval(fn) { tick = fn; return {}; }, clearInterval() {} } });
        lifecycle.start(); await tick();
        h.context.l2tpRootLifecycle.stop = () => lifecycle.stop();
        h.process.emit('SIGTERM'); await flush();
        assert.equal(h.calls.at(-1), 'exit:0', h.calls.join(','));
    }
});

test('a supervised worker rejection cannot be swallowed into a successful drain', async () => {
    const { createL2tpWorkerLifecycle } = require('../src/modules/relay-l2tp/runtime/createL2tpWorkerLifecycle');
    const h = harness(); let tick;
    const lifecycle = createL2tpWorkerLifecycle({ enabled: true,
        worker: { async runOnce() { throw new Error('remote invocation or persistence failed'); } },
        timer: { setInterval(fn) { tick = fn; return {}; }, clearInterval() {} } });
    lifecycle.start(); await tick();
    h.context.l2tpRootLifecycle.stop = () => lifecycle.stop();
    h.process.emit('SIGTERM'); await flush();
    assert.equal(h.calls.at(-1), 'exit:1', h.calls.join(','));
});

test('actual worker lifecycle remains joined across the process-level HTTP grace window', async () => {
    const { createL2tpWorkerLifecycle } = require('../src/modules/relay-l2tp/runtime/createL2tpWorkerLifecycle');
    const h = harness(); let tick; let schedules = 0; let cleared = 0;
    const lifecycle = createL2tpWorkerLifecycle({ enabled: true, intervalMs: 1000,
        worker: { runOnce: () => h.drain.promise }, logger: { error() {} },
        timer: { setInterval(callback) { schedules++; tick = callback; return {}; }, clearInterval() { cleared++; } },
    });
    lifecycle.start(); const inFlight = tick(); await flush();
    h.context.l2tpRootLifecycle.stop = () => lifecycle.stop();
    h.process.emit('SIGTERM'); await flush(); await h.advance(10001);
    assert.equal(cleared, 1); assert.equal(schedules, 1);
    assert.equal(h.calls.some(c => c.startsWith('exit:')), false);
    assert.equal(h.calls.includes('mongo-disconnect'), false);
    h.drain.resolve(); await inFlight; await flush();
    assert.equal(h.calls.at(-1), 'exit:0');
});

test('actual import-order SIGTERM preserves pooled SSH until the worker joins its remote invocation', async () => {
    const { createL2tpWorkerLifecycle } = require('../src/modules/relay-l2tp/runtime/createL2tpWorkerLifecycle');
    const h = harness({ realPool: true });
    const pool = h.context.sshPool;
    pool.settingsLoaded = true;
    const stream = new EventEmitter(); stream.stderr = new EventEmitter();
    const client = { _sock: { writable: true },
        exec(command, done) { h.calls.push('remote-exec'); done(null, stream); },
        end() { h.calls.push('client-end'); stream.emit('error', new Error('transport closed; remote outcome unknown')); },
    };
    pool.connections.set('node-1', { client, lastUsed: 0, useCount: 0 });
    let tick;
    const lifecycle = createL2tpWorkerLifecycle({ enabled: true,
        worker: { async runOnce() {
            await pool.exec({ id: 'node-1' }, 'local-test-only');
            h.calls.push('remote-outcome-known');
            await h.drain.promise;
            h.calls.push('worker-joined');
            return { claimed: true, status: 'succeeded' };
        } },
        timer: { setInterval(fn) { tick = fn; return {}; }, clearInterval() { h.calls.push('admission-closed'); } },
    });
    lifecycle.start(); const pending = tick(); await flush();
    h.context.l2tpRootLifecycle.stop = () => lifecycle.stop();
    h.process.emit('SIGTERM'); h.process.emit('SIGINT'); await flush();
    // A long invocation looks idle by lastUsed even though it is still active.
    // An already-queued cleanup callback must not defeat the signal drain.
    pool.config.maxIdleTime = 1;
    pool.connections.get('node-1').lastUsed = 0;
    pool.cleanup(); await flush();
    assert.equal(h.calls.includes('admission-closed'), true, h.calls.join(','));
    assert.equal(h.calls.includes('client-end'), false, h.calls.join(','));
    assert.equal(h.calls.some(c => c.startsWith('exit:')), false, h.calls.join(','));
    stream.emit('close', 0); await flush();
    assert.equal(h.calls.includes('client-end'), false, 'worker still persisting outcome');
    h.drain.resolve(); await pending; await flush();
    assert.deepEqual(h.calls.filter(c => !c.startsWith('error:')), [
        'remote-exec', 'http-close', 'admission-closed', 'remote-outcome-known',
        'worker-joined', 'client-end', 'redis-quit', 'mongo-disconnect', 'exit:0',
    ]);
});

test('actual pooled exec timeout stays uncertain after the local drain joins and exits nonzero', async () => {
    const { createL2tpWorkerLifecycle } = require('../src/modules/relay-l2tp/runtime/createL2tpWorkerLifecycle');
    const h = harness({ realPool: true });
    const pool = h.context.sshPool; pool.settingsLoaded = true;
    let tick;
    // Local transport simulator: ending SSH is NOT an attestation that the
    // remote writer stopped. No network/process execution occurs in this probe.
    const client = { _sock: { writable: true },
        exec(command, done) {
            h.calls.push('remote-exec');
            const stream = new EventEmitter(); stream.stderr = new EventEmitter();
            done(null, stream);
        },
        end() { h.calls.push('client-end'); },
    };
    pool.connections.set('node-1', { client, lastUsed: 0, useCount: 0 });
    const lifecycle = createL2tpWorkerLifecycle({ enabled: true,
        worker: { runOnce: () => pool.exec({ id: 'node-1' }, 'local-test-only', { timeout: 20000 }) },
        timer: { setInterval(fn) { tick = fn; return {}; }, clearInterval() { h.calls.push('admission-closed'); } },
    });
    lifecycle.start(); const pending = tick(); await flush();
    h.context.l2tpRootLifecycle.stop = () => lifecycle.stop();
    h.process.emit('SIGTERM'); await flush();
    assert.equal(h.calls.includes('client-end'), false, h.calls.join(','));
    assert.equal(h.calls.some(c => c.startsWith('exit:')), false);
    await h.advance(20000); await pending; await flush();
    assert.equal(h.calls.at(-1), 'exit:1', h.calls.join(','));
    assert.equal(h.calls.filter(c => c === 'client-end').length, 1);
    assert.equal(h.calls.some(c => c.includes('retain durable admissions/locks')), true);
});

test('startup failure joins the supervised shutdown instead of bypassing a pending drain', async () => {
    const h = harness();
    h.context.connectMongo = async () => { throw new Error('startup failed'); };
    const start = h.start(); await flush();
    assert.equal(h.calls.some(c => c.startsWith('exit:')), false, h.calls.join(','));
    assert.equal(h.calls.includes('worker-stop'), true);
    h.drain.resolve(); await start; await flush();
    assert.equal(h.calls.at(-1), 'exit:1');
});
