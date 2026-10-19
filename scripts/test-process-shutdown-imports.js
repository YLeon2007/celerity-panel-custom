'use strict';

// Full entry-point import-order probe. Mongo's connect boundary is suspended,
// so no database, HTTP server, SSH connection, or remote command is opened.
const { spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');

const probe = String.raw`
    const assert = require('node:assert/strict');
    const { EventEmitter } = require('node:events');
    const Module = require('node:module');
    const events = [];
    const exit = process.exit.bind(process);
    const watchdog = setTimeout(() => { console.error(events); exit(2); }, 5000);
    process.exit = code => { events.push('exit:' + code); };
    const flush = async () => { for (let i = 0; i < 100; i++) await Promise.resolve(); };
    const mongoose = require('mongoose');
    mongoose.connect = () => new Promise(() => {});
    mongoose.disconnect = async () => { events.push('mongo-disconnect'); };
    // Any accidental real network connection fails the probe.
    require('node:net').Socket.prototype.connect = () => { throw new Error('network forbidden in local probe'); };
    const { createL2tpWorkerLifecycle } = require('./src/modules/relay-l2tp/runtime/createL2tpWorkerLifecycle');
    let tick;
    let pool;
    const lifecycle = createL2tpWorkerLifecycle({ enabled: true,
        worker: { async runOnce() {
            await pool.exec({ id: 'node-probe' }, 'local-test-only');
            events.push('remote-outcome-known');
        } },
        timer: { setInterval(fn) { tick = fn; return {}; }, clearInterval() { events.push('admission-closed'); } },
    });
    const load = Module._load;
    Module._load = function(request, parent, isMain) {
        if (request === './src/modules/l2tpRuntimeLifecycleHook' && parent.filename.endsWith('/index.js')) {
            return { createL2tpRootLifecycle: () => ({ stop() {
                events.push('worker-stop'); return lifecycle.stop();
            } }) };
        }
        return load.call(this, request, parent, isMain);
    };
    (async () => {
        // Do not preload the pool: exercise index -> syncService -> NodeSSH ->
        // singleton pool before index installs its own shutdown handlers.
        require('./index.js');
        pool = require('./src/services/sshPoolService');
        assert.ok(require.cache[require.resolve('./src/services/nodeSSH')]);
        pool.settingsLoaded = true;
        const stream = new EventEmitter(); stream.stderr = new EventEmitter();
        pool.connections.set('node-probe', { lastUsed: Date.now(), useCount: 0,
            client: { _sock: { writable: true },
                exec(command, done) { events.push('remote-exec'); done(null, stream); },
                end() { events.push('client-end'); stream.emit('error', new Error('outcome unknown')); },
            },
        });
        lifecycle.start(); const running = tick(); await flush();
        process.emit('SIGTERM'); process.emit('SIGINT'); await flush();
        assert.equal(events.includes('client-end'), false, events.join(' -> '));
        assert.equal(events.some(event => event.startsWith('exit:')), false, events.join(' -> '));
        assert.equal(events.filter(event => event === 'admission-closed').length, 1);
        if (process.env.PROBE_UNCERTAIN === 'true') stream.emit('error', new Error('transport outcome unknown'));
        else stream.emit('close', 0);
        await running; await flush();
        const expectedCode = process.env.PROBE_UNCERTAIN === 'true' ? 1 : 0;
        assert.equal(events.at(-1), 'exit:' + expectedCode, events.join(' -> '));
        assert.equal(events.filter(event => event === 'client-end').length, 1);
        assert.ok(events.indexOf('admission-closed') < events.indexOf('client-end'));
        if (!expectedCode) assert.ok(events.indexOf('remote-outcome-known') < events.indexOf('client-end'));
        console.log('SHUTDOWN_PROBE ' + JSON.stringify(events));
        clearTimeout(watchdog); exit(0);
    })().catch(error => { console.error(error.stack); clearTimeout(watchdog); exit(1); });
`;

for (const uncertain of [false, true]) {
    test(`full index import-order shutdown: ${uncertain ? 'uncertain nonzero' : 'joined clean zero'}`, t => {
        const result = spawnSync(process.execPath, ['-e', probe], {
            cwd: path.resolve(__dirname, '..'), encoding: 'utf8', timeout: 10000,
            env: { ...process.env, PANEL_DOMAIN: 'test.local', ACME_EMAIL: 't@t.local',
                ENCRYPTION_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
                SESSION_SECRET: 'test-session-secret', MONGO_URI: 'mongodb://127.0.0.1:27017/c3-celerity',
                NODE_ENV: 'test', PROBE_UNCERTAIN: String(uncertain) },
        });
        assert.equal(result.status, 0, `${result.error || ''}\n${result.stdout}\n${result.stderr}`);
        assert.match(result.stdout, /SHUTDOWN_PROBE /);
        t.diagnostic(result.stdout.split('\n').find(line => line.startsWith('SHUTDOWN_PROBE ')));
    });
}
