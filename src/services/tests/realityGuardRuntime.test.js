'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isDeepStrictEqual: eq } = require('node:util');
const { EventEmitter } = require('node:events');
const { readFileSync } = require('node:fs');
const { compileFunction } = require('node:vm');

const entry = readFileSync(require.resolve('../../../index.js'), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));
const card = () => ({ _id: 'a'.repeat(24), active: true, type: 'xray', cascadeRole: 'portal',
    status: 'online', ip: '93.184.216.10', ssh: { username: 'fixture', port: 22, password: 'dummy-not-a-credential' },
    xray: { security: 'reality', realityDest: 'old.example:443', realitySni: ['old.example'],
        realityGuard: { mode: 'notify', reserveSnis: ['backup.example'], allowedCidr: '93.184.216.0/24' } } });
const get = (row, path) => path.split('.').reduce((v, key) => v?.[key], row);
function set(row, path, value) {
    const keys = path.split('.');
    const key = keys.pop();
    keys.reduce((v, k) => v[k] ??= {}, row)[key] = structuredClone(value);
}
function matches(row, filter) {
    return Object.entries(filter).every(([path, spec]) => {
        if (path === '$or') return spec.some(f => matches(row, f));
        const v = get(row, path);
        if (spec === null || typeof spec !== 'object' || Array.isArray(spec) || spec instanceof Date) return eq(v, spec) || Array.isArray(v) && v.some(item => eq(item, spec));
        return Object.entries(spec).every(([op, arg]) => {
            if (op === '$eq') return eq(v, arg);
            if (op === '$nin') return !arg.some(a => eq(v, a));
            if (op === '$in') return arg.some(a => eq(v, a) || Array.isArray(v) && v.some(item => eq(item, a)));
            if (op === '$exists') return (v !== undefined) === arg;
            if (op === '$ne') return !eq(v, arg);
            if (op === '$size') return Array.isArray(v) && v.length === arg;
            if (op === '$gt') return v > arg;
            assert.fail(`unmodeled raw store operator ${op}`);
        });
    });
}
function project(row, projection) {
    if (!row) return null;
    const result = { _id: row._id };
    for (const path of Object.keys(projection)) {
        const prefix = 'xray.extraInbounds';
        if (path.startsWith(`${prefix}.`) && Array.isArray(get(row, prefix))) {
            const rest = path.slice(prefix.length + 1);
            result.xray ??= {};
            result.xray.extraInbounds ??= row.xray.extraInbounds.map(() => ({}));
            row.xray.extraInbounds.forEach((extra, i) => {
                if (extra[rest] !== undefined) set(result.xray.extraInbounds[i], rest, extra[rest]);
            });
        } else if (get(row, path) !== undefined) set(result, path, get(row, path));
    }
    return result;
}
function loadService(file, bindings, clock = Date) {
    const path = require.resolve(`../${file}`);
    const module = { exports: {} };
    const imports = id => {
        assert.ok(Object.hasOwn(bindings, id), `unexpected runtime import ${id}`);
        return bindings[id];
    };
    compileFunction(readFileSync(path, 'utf8'), ['require', 'module', 'Date'], { filename: path })(imports, module, clock);
    return module.exports;
}
function fixture(options = {}) {
    const { rebuildEnabled = true } = options;
    const flag = Object.hasOwn(options, 'flag') ? options.flag : true;
    const row = card();
    const effects = [], warnings = [], webhook = [], schedules = [], lookups = [], writes = [];
    const counts = { flag: 0, construct: 0, collection: 0, reads: 0, list: 0, credentials: 0,
        writes: 0, panel: 0, dns: 0, ssh: 0, exec: 0 };
    const f = { row, effects, warnings, webhook, counts, lookups, writes, flag };
    const rows = { hynodes: [row], cascadelinks: [], relayl2tpstates: [], c3_rebuild_locks: [], nodeoperationlocks: [],
        l2tpusers: [], l2tpoperations: [], remoteadmissions: [], c3_rebuild_l2tp_relay_grants: [], topologyexecutionenrollments: [] };
    f.rows = rows;
    const db = { collection(name) {
        counts.collection++;
        assert.ok(rows[name], `unexpected collection ${name}`);
        const selected = filter => rows[name].filter(item => matches(item, filter));
        const read = options => {
            counts.reads++;
            assert.equal(options.readConcern.level, 'majority');
            assert.ok(options.projection, 'unprojected DB read');
            lookups.push([name, Object.keys(options.projection)]);
        };
        return {
            find: (filter, options) => ({ toArray: async () => {
                read(options);
                if (name === 'hynodes') counts.list++;
                return selected(filter).slice(0, options.limit).map(item => project(item, options.projection));
            } }),
            findOne: async (filter, options) => {
                read(options);
                if (options.projection['ssh.password'] || options.projection['ssh.privateKey']) {
                    counts.credentials++;
                    await f.atCredentialRead?.();
                }
                return project(selected(filter)[0], options.projection);
            },
            async updateMany(_filter, update) { counts.writes++; writes.push(update); },
        };
    } };
    const policy = { async isGloballyEnabled() {
        counts.flag++;
        await f.atFlagRead?.();
        if (f.flag instanceof Error) throw f.flag;
        return f.flag;
    } };
    const sockets = opts => {
        counts.panel++;
        const socket = Object.assign(new EventEmitter(), { destroy: () => effects.push('panel-close'),
            authorized: true, alpnProtocol: 'h2', getProtocol: () => 'TLSv1.3' });
        queueMicrotask(() => {
            f.atPanelResult?.(opts);
            if (opts.servername === 'old.example' && !f.panelHealthy) socket.emit('error', { code: 'ECONNREFUSED' });
            else socket.emit('secureConnect');
        });
        return socket;
    };
    const dns = { lookup: async host => {
        counts.dns++;
        await f.atDns?.();
        return { address: f.dnsIp ?? (host === 'old.example.' ? '93.184.216.20' : '93.184.216.21') };
    } };
    const sender = loadService('webhookService', {
        crypto: require('node:crypto'),
        axios: { async post(_url, payload, options) {
            const { event, data } = JSON.parse(payload);
            assert.equal(options.maxRedirects, 0);
            assert.equal(options.signal.aborted, false);
            assert.match(options.headers['X-Webhook-Signature'], /^sha256=[a-f0-9]{64}$/);
            webhook.push([event, data]);
        } },
        '../models/settingsModel': { collection: { collection: { async findOne(filter, options) {
            assert.deepEqual(filter, { _id: 'settings' });
            assert.deepEqual(options.projection,
                { _id: 0, 'webhook.enabled': 1, 'webhook.url': 1, 'webhook.secret': 1, 'webhook.events': 1 });
            await f.atWebhookSettings?.();
            if (f.webhookOff) return { webhook: { enabled: false } };
            return { webhook: { enabled: true, url: 'https://webhook.example/synthetic', events: ['node.reality_dest_dead'] } };
        } } } },
        './cryptoService': { decryptSafe: () => 'synthetic-signature-key' },
        '../utils/logger': { debug() {}, error: msg => warnings.push(msg), warn: msg => warnings.push(msg) },
    });
    const localModules = {
        'node:crypto': require('node:crypto'), 'node:net': require('node:net'), 'node:util': require('node:util'), 'node:dns/promises': dns,
        'node:tls': { connect: sockets }, mongoose: { connection: { db } },
        '../models/realityGuardPolicy': policy, '../utils/logger': { warn: msg => warnings.push(msg) },
        './nodeSSH': class {
            constructor(node, options) {
                assert.equal(node.ssh.username, 'fixture');
                f.sshOptions = options;
            }
            async connectObserverOnce(allow) {
                await f.beforeConnect?.();
                if (allow && !await allow()) throw new Error('refused before connect');
                counts.ssh++;
                await f.atSshConnect?.();
                return async command => {
                    counts.exec++;
                    assert.match(command, /^LC_ALL=C timeout -k 1s 6s openssl s_client /);
                    assert.ok(command.includes("-connect '93.184.216.20:443'"));
                    await f.atExec?.();
                    return f.nodeResult ?? { code: 124 };
                };
            }
            disconnect() { effects.push('ssh-disconnect'); }
        },
        './webhookService': sender,
    };
    let time = 1_750_000_000_000;
    const service = loadService('realityGuardService', localModules, class extends Date { static now() { return time; } });
    f.observation = () => service.getRealityGuardObservation(row);
    f.now = () => time;
    const bindings = {
        rebuildEnabled, cron: { schedule: (expression, cb) => {
            schedules.push({ expression, cb });
            return { stop: () => effects.push(`task-stop:${expression}`) };
        } },
        require: id => {
            if (id === './src/models/realityGuardPolicy') return policy;
            assert.equal(id, './src/services/realityGuardService');
            return { createRuntimeRealityGuard() { counts.construct++; return service.createRuntimeRealityGuard(); } };
        },
        logger: { info() {}, warn: msg => warnings.push(msg), error: msg => warnings.push(msg) },
        clearTimeout: timer => { if (timer?.ms === 5000) effects.push('startup-timer-cleared'); },
        setTimeout: (_cb, ms) => ({ ms }),
        process: Object.assign(new EventEmitter(), { exit: code => effects.push(`exit:${code}`) }),
        bootstrapSignalHandlers: [],
        syncService: { clearXrayClientConnections: () => effects.push('client-connections-cleared') },
        mongoose: { models: {}, disconnect: async () => effects.push('db-close') },
        l2tpRootLifecycle: { stop: async () => {} },
        sshPool: { beginDrain: () => effects.push('ssh-drain'), closeAll: () => effects.push('ssh-close-all') },
        cacheService: { isConnected: () => true, redis: { quit: async () => effects.push('cache-close') } },
    };
    // Use the complete production cron registration, dispatcher and shutdown
    // (including the signal handlers), without booting unrelated routes/DDL.
    const entrySlice = entry.slice(entry.indexOf('function setupCronJobs()'), entry.indexOf('// End graceful shutdown registration'));
    const runtime = compileFunction(`${entrySlice}\nreturn { setupCronJobs, shutdown };`, Object.keys(bindings))(...Object.values(bindings));
    runtime.setupCronJobs();
    const registered = schedules.filter(task => task.expression === '*/15 * * * *');
    assert.equal(registered.length, 1);
    assert.ok(schedules.length > 10);
    f.callback = registered[0].cb;
    f.tick = async (n = 1) => { for (let i = 0; i < n; i++) { await f.callback(); time += 15 * 60 * 1000; } };
    f.shutdown = () => { bindings.process.emit('SIGTERM'); return runtime.shutdown('SIGTERM'); };
    return f;
}

test('(f) registered Guard callback reads only the flag when disabled or unreadable', async () => {
    for (const flag of [undefined, false, 'true', new Error('dummy-private-detail')]) {
        for (const rebuildEnabled of [false, true]) {
            const f = fixture({ flag, rebuildEnabled });
            await f.tick(3);
            assert.equal(f.counts.flag, 3);
            assert.ok(Object.entries(f.counts).every(([key, count]) => key === 'flag' || count === 0));
            assert.ok(!JSON.stringify(f.warnings).includes('dummy-private-detail'));
            await f.shutdown();
            const counters = { ...f.counts };
            await f.tick(); // still invoke the captured callback after task.stop()
            assert.deepEqual(f.counts, counters);
            assert.equal(f.effects.filter(event => event === 'task-stop:*/15 * * * * *').length, 1);
            assert.deepEqual(f.effects.slice(-5), ['client-connections-cleared', 'ssh-close-all', 'cache-close', 'db-close', 'exit:0']);
        }
    }
});

test('missing/off/stale-auto and malformed notify are inert even with global opt-in', async () => {
    for (const mode of [undefined, 'off', 'auto', ['notify'], 'Notify', true]) {
        const f = fixture();
        if (mode === undefined) delete f.row.xray.realityGuard;
        else f.row.xray.realityGuard.mode = mode;
        await f.tick(4);
        assert.equal(f.counts.list, 4);
        for (const key of ['dns', 'panel', 'credentials', 'ssh', 'exec', 'writes']) assert.equal(f.counts[key], 0, key);
        assert.deepEqual(f.webhook, []);
    }
});

test('only current destinations are checked; confirmed outage emits once without any writes', async () => {
    for (const rebuildEnabled of [false, true]) {
        const f = fixture({ rebuildEnabled });
        f.row.name = 'Ordinary\nnode';
        f.row.ssh.privateKey = ''; // password authentication, no key
        f.row.ssh.agentToken = 'fixture-secret-marker';
        f.row.xray.extraInbounds = [{ id: 'extra', security: 'reality', realityDest: 'sibling.example:443',
            realitySni: ['sibling.example'], realityPrivateKey: 'fixture-secret-marker' }];
        const original = structuredClone(f.row);
        await f.tick(2);
        assert.deepEqual([f.counts.credentials, f.counts.ssh, f.counts.exec], [0, 0, 0]);
        await f.tick(5);
        assert.equal(f.counts.panel, 14);
        assert.deepEqual([f.counts.ssh, f.counts.exec], [1, 1]);
        assert.deepEqual(f.webhook, [['node.reality_dest_dead', {
            nodeId: f.row._id, name: 'Ordinarynode', dest: 'old.example:443', reason: 'timeout', cause: 'notify_mode',
        }]]);
        assert.equal(f.counts.writes, 0);
        assert.deepEqual(f.row, original);
        assert.ok(f.lookups.every(([, keys]) => !keys.some(k => /reserve|cidr|token|xray.*privatekey|ssh$/i.test(k))));
        f.panelHealthy = true;
        await f.tick();
        f.panelHealthy = false;
        await f.tick(3);
        assert.equal(f.webhook.length, 2, 'recovery rearms the next incident');
    }
});

test('registered monitor records confirmation even when the real sender has no webhook', async () => {
    const f = fixture();
    f.webhookOff = true;
    const before = structuredClone(f.row);
    assert.equal(f.observation(), undefined);
    await f.tick(2);
    assert.equal(f.observation().failCount, 2);
    const lastCheckAt = f.now();
    await f.tick();
    assert.deepEqual(f.observation(), { status: 'dead', lastError: 'timeout', lastCheckAt });
    assert.equal(f.counts.exec, 1);
    assert.deepEqual(f.webhook, []);
    assert.deepEqual(f.row, before);
    assert.equal(f.counts.writes, 0);
    assert.equal(fixture().observation(), undefined, 'fresh module has no observation');
    f.flag = false;
    await f.tick();
    assert.equal(f.observation(), undefined);
});

test('self-steal, transit, L2TP enrollment, and busy cards fail before probing', async () => {
    for (const [label, mutate] of [
        ['self-steal', f => { f.row.xray.realityDest = '[::1]:443'; }],
        ['own public IP via DNS', f => { f.dnsIp = f.row.ip; }],
        ['bridge', f => { f.row.cascadeRole = 'bridge'; }],
        ['relay', f => { f.row.cascadeRole = 'relay'; }],
        ['role mismatch', f => { f.row.role = 'relay'; }],
        ['active filtered relay', f => f.rows.cascadelinks.push({ bridgeNode: f.row._id, transportMode: 'reverse', geo: true })],
        ['managed relay state', f => f.rows.relayl2tpstates.push({ node: f.row._id })],
        ['orphaned L2TP user', f => f.rows.l2tpusers.push({ relayNode: f.row._id })],
        ['existing L2TP grant', f => f.rows.c3_rebuild_l2tp_relay_grants.push({ host: f.row.ip })],
        ['global apply busy', f => f.rows.c3_rebuild_locks.push({ _id: 'apply' })],
        ['node operation busy', f => f.rows.nodeoperationlocks.push({ node: f.row._id, leaseUntil: new Date(0) })],
        ['sync busy', f => { f.row.status = 'syncing'; }],
        ['same-host Xray alias', f => f.rows.hynodes.push({ ...card(), _id: 'b'.repeat(24), active: false })],
    ]) {
        const f = fixture();
        mutate(f);
        await f.tick(4);
        if (label !== 'own public IP via DNS') assert.equal(f.counts.dns, 0, label);
        for (const key of ['panel', 'credentials', 'ssh', 'exec', 'writes']) assert.equal(f.counts[key], 0, `${label}: ${key}`);
        assert.deepEqual(f.webhook, [], label);
    }
});

test('fresh checks gate TLS, SSH admission, command execution and actual webhook dispatch', async () => {
    for (const [hook, edit, counts] of [
        ['atDns', f => { f.flag = false; }, [0, 0, 0, 0]],
        ['atDns', f => { f.row.xray.realityGuard.mode = 'off'; }, [0, 0, 0, 0]],
        ['atCredentialRead', f => { f.flag = false; }, [3, 1, 0, 0]],
        ['beforeConnect', f => { f.row.ssh.port = 2222; }, [3, 1, 0, 0]],
        ['beforeConnect', f => { f.row.ssh.password = 'changed-fixture'; }, [3, 2, 0, 0]],
        ['atSshConnect', f => f.rows.relayl2tpstates.push({ node: f.row._id }), [3, 2, 1, 0]],
        ['atSshConnect', f => { f.flag = false; }, [3, 2, 1, 0]],
        ['atExec', f => { f.row.xray.realityDest = 'new.example:443'; }, [3, 2, 1, 1]],
        ['atWebhookSettings', f => { f.flag = false; }, [3, 2, 1, 1]],
    ]) {
        const f = fixture();
        f[hook] = () => { delete f[hook]; edit(f); };
        await f.tick(3);
        const { panel, credentials, ssh, exec, writes } = f.counts;
        assert.deepEqual([panel, credentials, ssh, exec], counts, hook);
        assert.equal(writes, 0);
        assert.deepEqual(f.webhook, [], hook);
    }
});

test('missing openssl and healthy node-side TLS never produce a dead webhook', async () => {
    for (const nodeResult of [{ code: 127 }, { code: 0, stderr: 'Protocol version: TLSv1.3\nVerification: OK\n' }]) {
        const f = fixture();
        f.nodeResult = nodeResult;
        await f.tick(3);
        assert.equal(f.counts.exec, 1);
        assert.deepEqual(f.webhook, []);
        assert.equal(f.counts.writes, 0);
    }
});

test('existing native enrollment supplies the pin; stale or changed enrollment does not fall back', async () => {
    for (const cut of ['unchanged', 'stale endpoint', 'pin changes after SSH']) {
        const f = fixture();
        const entry = { _id: 'enrollment', nodeId: f.row._id, targetProfile: 'xray-main',
            endpoint: { ip: f.row.ip, port: 22, username: 'fixture' }, nodeIdentity: { sshHostKeySha256: 'a'.repeat(64) } };
        f.rows.topologyexecutionenrollments.push(entry);
        if (cut === 'stale endpoint') entry.endpoint.port = 2222;
        if (cut === 'pin changes after SSH') f.atSshConnect = () => { entry.nodeIdentity.sshHostKeySha256 = 'b'.repeat(64); };
        await f.tick(3);
        if (cut !== 'stale endpoint') assert.deepEqual(f.sshOptions,
            { expectedEndpoint: entry.endpoint, expectedHostKeySha256: 'a'.repeat(64) });
        assert.deepEqual([f.counts.ssh, f.counts.exec, f.webhook.length, f.counts.writes],
            cut === 'unchanged' ? [1, 1, 1, 0] : cut === 'stale endpoint' ? [0, 0, 0, 0] : [1, 0, 0, 0]);
    }
});

test('shutdown joins an admitted observation and prevents late effects', async () => {
    const f = fixture();
    await f.tick(2);
    let release, entered;
    const pending = new Promise(resolve => { release = resolve; });
    const reached = new Promise(resolve => { entered = resolve; });
    f.atExec = () => { entered(); return pending; };
    const tick = f.tick();
    await reached;
    const stop = f.shutdown();
    await flush();
    try {
        assert.ok(f.effects.includes('task-stop:*/15 * * * * *'));
        for (const event of ['client-connections-cleared', 'ssh-close-all', 'cache-close', 'db-close']) {
            assert.ok(!f.effects.includes(event), `${event} before Guard's admitted observation finished`);
        }
    } finally { release(); }
    await Promise.all([tick, stop]);
    assert.deepEqual(f.webhook, []);
    assert.equal(f.counts.writes, 0);
    assert.deepEqual(f.effects.slice(-6), ['ssh-disconnect', 'client-connections-cleared', 'ssh-close-all',
        'cache-close', 'db-close', 'exit:0']);
});
