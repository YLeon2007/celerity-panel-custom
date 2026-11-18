'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const dns = require('node:dns');
const { spawn } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const { setTimeout: sleep } = require('node:timers/promises');
const { performance } = require('node:perf_hooks');
const { makeLink, classify, loopbackConfig, LIMIT_MS } = require('./probe.cjs');

const host = '127.0.0.1';
const repo = path.resolve(__dirname, '../..');
const src = file => require(path.join(repo, 'src', file));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const runnerPath = '/usr/local/bin/celerity-topology-node-runner-v2';
const runner = path.join(repo, 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh');
const fixtureEnv = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', GOMAXPROCS: '2' };
const OBSERVE_APPLY_MS = 360_000; // observation ceiling, never the acceptance target
const rounded = n => Math.round(n * 1000) / 1000;

function noOutsideNetwork() {
    const refused = () => { throw Error('S1 refuses DNS/external IO'); };
    for (const module of [dns, dns.promises]) {
        for (const name of Object.keys(module)) if (/^(lookup|resolve|reverse)/.test(name)) module[name] = refused;
    }
    // net.Server.listen passes even a numeric host through lookup; answer that
    // literal directly without consulting the system resolver.
    dns.lookup = (name, options, cb) => {
        if (name !== host) return refused();
        if (typeof options === 'function') cb = options;
        process.nextTick(() => options?.all ? cb(null, [{ address: host, family: 4 }]) : cb(null, host, 4));
    };
    const connect = net.Socket.prototype.connect;
    net.Socket.prototype.connect = function (...args) {
        const [o] = net._normalizeArgs(args.length === 1 && Array.isArray(args[0]) ? args[0] : args);
        assert.equal(o.host, host, 'S1 allows numeric IPv4 loopback only');
        assert.ok(Number(o.port) >= 1024 && Number(o.port) < 65536);
        return connect.apply(this, args);
    };
}
function listen(server, socket) {
    return new Promise((resolve, reject) => {
        server.once('error', reject);
        const ready = () => { server.removeListener('error', reject); resolve(server.address()); };
        if (socket) server.listen(socket, ready); else server.listen(0, host, ready);
    });
}
function close(server) {
    return new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
}
async function until(deadline, work) {
    while (performance.now() < deadline) {
        const value = await work();
        if (value && performance.now() < deadline) return value;
        await sleep(100);
    }
    return null;
}
function tcpReady(port) {
    return new Promise(resolve => {
        const socket = net.connect({ host, port });
        socket.setTimeout(500);
        const done = value => { socket.destroy(); resolve(value); };
        socket.on('connect', () => done(true)).on('error', () => done(false)).on('timeout', () => done(false));
    });
}
function ownsListener(child, port) {
    if (!child.pid || child.exitCode !== null || child.signalCode !== null) return false;
    try {
        const address = '0100007F:' + port.toString(16).padStart(4, '0').toUpperCase();
        const inode = fs.readFileSync(`/proc/${child.pid}/net/tcp`, 'utf8').split('\n').map(l => l.trim().split(/\s+/))
            .find(row => row[1] === address && row[3] === '0A')?.[9];
        if (!inode) return false;
        const dir = `/proc/${child.pid}/fd`;
        return fs.readdirSync(dir).some(fd => {
            try { return fs.readlinkSync(path.join(dir, fd)) === `socket:[${inode}]`; }
            catch (error) { if (error.code === 'ENOENT') return false; throw error; }
        });
    } catch (error) { if (error.code === 'ENOENT' || error.code === 'ESRCH') return false; throw error; }
}
async function httpResult(port, { url, body, signal }) {
    const resp = await fetch(`http://${host}:${port}${url}`, body ? { method: 'POST', headers: {
        'Content-Type': 'application/json', 'Idempotency-Key': 's1-create-once',
    }, body: JSON.stringify(body), signal } : { signal });
    return { status: resp.status, body: await resp.json() };
}

async function main(rtt, tools) {
    assert.ok(rtt === 150 || rtt === 0);
    assert.ok(path.isAbsolute(tools), 'use an absolute directory for the preinstalled tools');
    assert.ok(Object.keys(process.env).every(k => k === 'PATH'), 'run with env -i');
    assert.notEqual(process.getuid(), 0, 'run as an ordinary user');
    process.umask(0o077);
    const dir = fs.mkdtempSync(path.join(repo, '.s1-'));
    const env = { ...fixtureEnv, HOME: dir, TMPDIR: dir, XRAY_LOCATION_ASSET: tools };
    const bin = name => path.join(tools, name);
    const servers = [], children = new Set(), stopFailures = [];
    let mongoose, root, authority, loggerLoaded = false;
    const evidence = { rttMs: rtt, marksMs: {}, phase: 'setup', gate: 'unproven' };
    const begin = performance.now();
    const marks = Object.create(null);
    const mark = name => { marks[name] ??= performance.now(); evidence.marksMs[name] = rounded(marks[name] - begin); };
    const elapsed = (start, end) => marks[end] - marks[start];
    const link = makeLink(rtt);
    const abort = new AbortController();
    const interrupt = () => abort.abort();
    const signal = abort.signal;
    process.on('SIGINT', interrupt).on('SIGTERM', interrupt);
    function processOf(exe, args, options = {}) {
        signal.throwIfAborted();
        const { stdin, extra = {}, read = false } = options;
        const child = spawn(exe, args, { cwd: dir, env: { ...env, ...extra }, stdio: [stdin === undefined ? 'ignore' : 'pipe', read ? 'pipe' : 'ignore', read ? 'pipe' : 'ignore'] });
        let stdout = '', stderr = '';
        const done = new Promise(resolve => {
            let failure;
            child.once('error', error => { failure = error.code; });
            child.once('close', (code, signal) => resolve({ code, signal, failure, stdout, stderr }));
        });
        children.add(child);
        done.then(() => children.delete(child));
        child.stdout?.on('data', chunk => { stdout += chunk; if (stdout.length > 2 * 1024 * 1024) child.kill(); });
        child.stderr?.on('data', chunk => { stderr += chunk; if (stderr.length > 2 * 1024 * 1024) child.kill(); });
        if (child.stdin) {
            child.stdin.on('error', () => {}); // command result/receipt is authoritative
            child.stdin.end(stdin);
        }
        return Object.assign(child, { done });
    }
    async function stop(child) {
        if (!child) return;
        child.kill('SIGTERM');
        const kill = setTimeout(() => child.kill('SIGKILL'), 2000);
        try { await child.done; } finally { clearTimeout(kill); }
    }
    async function capture(exe, args, options) {
        const child = processOf(exe, args, { ...options, read: true });
        const kill = setTimeout(() => child.kill('SIGKILL'), 65_000); // harness ceiling; never a success signal
        try { return await child.done; } finally { clearTimeout(kill); }
    }
    async function serving(server, socket) {
        const addr = await listen(server, socket);
        servers.push(server);
        return addr;
    }
    const allocated = new Set();
    async function port() {
        while (true) {
            const server = net.createServer();
            const p = (await listen(server)).port; await close(server);
            if (!allocated.has(p)) { allocated.add(p); return p; }
        }
    }
    const put = (file, content, mode = 0o600) => {
        fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
        fs.writeFileSync(file, content, { flag: 'wx', mode });
        fs.chmodSync(file, mode);
    };
    const fileDigest = file => sha(fs.readFileSync(file));
    try {
        for (const name of ['mongod', 'xray']) fs.accessSync(bin(name), fs.constants.X_OK);
        noOutsideNetwork();
        process.chdir(dir);
        // No .env access or file logger outside the owned directory. These
        // constants only satisfy the application config reader (not credentials).
        require('dotenv').config = () => ({});
        const loggerId = require.resolve('../../src/utils/logger');
        let events = [];
        const log = msg => {
            if (typeof msg === 'string' && /^(PRODUCTION|TOPOLOGY)_[A-Z0-9_]+$/.test(msg)) events.push(msg);
        };
        require.cache[loggerId] = { id: loggerId, filename: loggerId, loaded: true,
            exports: { debug() {}, info() {}, warn: log, error: log } };
        loggerLoaded = true;
        const topology = name => src(`modules/relay-l2tp/${name}`);
        const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = topology('domain/topologyExecutionContext');
        Object.assign(process.env, env, { NODE_ENV: 'test', PANEL_DOMAIN: PROD.hostIdentity,
            L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true',
            ENCRYPTION_KEY: '0'.repeat(32), SESSION_SECRET: 's1-public-fixture', ACME_EMAIL: 's1@example.invalid' });
        evidence.calibrationMs = (await link.calibrate()).map(rounded);
        mongoose = require('mongoose');
        mongoose.set('autoIndex', false); mongoose.set('autoCreate', false);
        const dbPort = await port(), setName = 's1Local', dbName = 's1_local';
        const db = path.join(dir, 'db'); fs.mkdirSync(db);
        const mongod = processOf(bin('mongod'), ['--bind_ip', host, '--nounixsocket', '--port', String(dbPort),
            '--replSet', setName, '--dbpath', db, '--wiredTigerCacheSizeGB', '0.25', '--oplogSize', '32', '--logpath', path.join(dir, 'mongo.log')]);
        const address = `mongodb://${host}:${dbPort}`;
        const direct = new mongoose.mongo.MongoClient(`${address}/admin?directConnection=true`, { serverSelectionTimeoutMS: 350 });
        let repl;
        try {
            assert.ok(await until(performance.now() + 15_000, async () => {
                signal.throwIfAborted(); assert.equal(mongod.exitCode, null);
                if (!ownsListener(mongod, dbPort)) return null;
                try { return await direct.connect(); } catch { return null; }
            }), 'mongo_not_listening');
            assert.equal(ownsListener(mongod, dbPort), true);
            await direct.db('admin').command({ replSetInitiate: { _id: setName, members: [{ _id: 0, host: `${host}:${dbPort}` }] } });
            assert.ok(await until(performance.now() + 20_000, async () => (await direct.db('admin').command({ hello: 1 })).isWritablePrimary), 'mongo_not_primary');
            ({ config: repl } = await direct.db('admin').command({ replSetGetConfig: 1 }));
        } finally { await direct.close(); }
        await mongoose.connect(`${address}/${dbName}?replicaSet=${setName}`, { autoIndex: false, autoCreate: false, serverSelectionTimeoutMS: 2000 });
        const models = { ...topology('index').registerModels(), HyNode: src('models/hyNodeModel'),
            CascadeLink: src('models/cascadeLinkModel'), HyUser: src('models/hyUserModel') };
        for (const model of Object.values(models)) {
            await model.init(); await model.createCollection();
            for (const [key, options] of model.schema.indexes()) await model.collection.createIndex(key, options);
        }
        await models.CascadeTopologyState.collection.insertOne({ _id: 'singleton', revision: 0, deployedRevision: 0,
            stateTransitionRevision: 0, replacementEpoch: 0, remoteAdmissionCount: 0, topologyAdmissionCount: 0 });
        const apiPort = await port(), vlessPort = await port(), tunnelPort = await port();
        const nodes = ['portal', 'bridge'].map((role, index) => {
            const id = new mongoose.Types.ObjectId().toString(), digit = `${index + 1}`;
            const targetProfile = role === 'portal' ? 'xray-main' : 'xray-bridge';
            const name = role === 'portal' ? 'xray' : 'xray-bridge';
            const root = path.join(dir, digit);
            const configPath = path.join(root, `/usr/local/etc/${name}/config.json`);
            const unitPath = path.join(root, `/etc/systemd/system/${name}.service`);
            const journal = path.join(root, `var/lib/celerity/topology/fences/${targetProfile}/journal.json`);
            const physical = { machineId: digit.repeat(32), bootId: randomUUID(), sshHostKeySha256: digit.repeat(64) };
            const endpoint = { ip: `127.0.0.${digit}`, port: 22000 + index, username: 'root' };
            put(configPath, '{}\n');
            put(unitPath, role === 'bridge' ? src('services/configGenerator').generateBridgeSystemdService() : 'S1 synthetic original unit\n');
            put(path.join(root, 'proc/sys/kernel/random/boot_id'), `${physical.bootId}\n`);
            put(path.join(root, runnerPath), fs.readFileSync(runner), 0o750);
            fs.mkdirSync(path.join(root, 'var/lib'), { recursive: true });
            fs.symlinkSync(bin('xray'), path.join(root, 'usr/local/bin/xray'));
            fs.mkdirSync(path.join(root, 'usr/local/share/xray'), { recursive: true });
            for (const asset of ['geoip.dat', 'geosite.dat']) fs.symlinkSync(bin(asset), path.join(root, 'usr/local/share/xray', asset));
            fs.mkdirSync(path.join(root, 'usr/bin'), { recursive: true });
            fs.symlinkSync('/usr/bin/ss', path.join(root, 'usr/bin/ss'));
            const pin = { kind: 'node', nodeId: id, targetProfile, endpoint, physical, policySha256: digit.repeat(64),
                privateKeyPath: '/etc/celerity/s1-not-read', maintenanceId: randomUUID(), proofRef: 's1-owned-original',
                acceptedOwner: { owner: 'absent' }, originalSnapshot: { source: 'node-readback', configSha256: fileDigest(configPath),
                    unitSha256: fileDigest(unitPath), serviceActive: 'active', serviceEnabled: 'enabled' } };
            return { id, role, name, root, configPath, unitPath, journal, pin };
        });
        const [p, b] = nodes;
        const user = { userId: 's1-local', xrayUuid: randomUUID(), enabled: true, groups: [], nodes: [new mongoose.Types.ObjectId(p.id)] };
        await models.HyUser.collection.insertOne(user);
        await models.HyNode.create(nodes.map((n, i) => ({ _id: n.id, name: `s1-${n.role}`, ip: i === 0 ? host : '127.0.0.2', port: vlessPort,
            type: 'xray', active: true, cascadeRole: n.role, ssh: { port: n.pin.endpoint.port, username: 'root', privateKey: 's1-not-a-key' },
            xray: { apiPort, transport: 'tcp', security: 'none' } })));
        const originNonce = randomUUID(); let hits = 0;
        const originPort = (await serving(http.createServer((req, res) => {
            if (req.url !== '/s1-proof') { res.writeHead(404).end(); return; }
            hits++; res.end(originNonce);
        }))).port;

        // The runner's systemctl only reaches this per-run AF_UNIX listener. A
        // restart returns after the owned Xray child has consumed the launch copy.
        for (const n of nodes) {
            const ctl = path.join(dir, n.name + '.sock');
            const launch = path.join(n.root, 'local-xray.json');
            let active = true; // Original profile's installed service is modeled.
            const server = net.createServer(socket => {
                socket.setEncoding('utf8'); let cmd = '';
                socket.on('error', () => {});
                socket.on('data', chunk => {
                    cmd += chunk;
                    if (cmd.length > 32) socket.destroy();
                    if (!cmd.endsWith('\n')) return;
                    const action = cmd.trim(); socket.pause();
                    (async () => {
                        if (action === 'restart') {
                            const candidate = fs.readFileSync(n.configPath);
                            const conf = loopbackConfig(JSON.parse(candidate), n === b ? originPort : undefined);
                            await stop(n.proc); active = false;
                            fs.writeFileSync(launch, JSON.stringify(conf));
                            n.proc = processOf(bin('xray'), ['run', '-config', launch], { read: true });
                            const self = n.proc;
                            if (n === p) assert.ok(await until(performance.now() + 3000, async () => ownsListener(self, apiPort) && await tcpReady(apiPort)), 'xray_api_not_ready');
                            else await sleep(50); // no bridge inbound; the later client probe proves the data path
                            assert.equal(self.exitCode, null);
                            active = true; n.launchedCandidate = sha(candidate); mark(`restart_${n.role}`);
                        } else if (action === 'stop') { await stop(n.proc); active = false; }
                        else if (action !== 'show' && action !== 'is-active') throw Error('S1_CTL_UNSUPPORTED');
                        if (n.proc && (n.proc.exitCode !== null || n.proc.signalCode !== null)) active = false;
                        socket.end(JSON.stringify({ active }));
                    })().catch(error => {
                        evidence.ctlFailure = { role: n.role, action,
                            reason: error.message === 'unsafe Xray launch projection' ? 'unsafe_projection' : 'unconfirmed' };
                        socket.end('{"error":true}');
                    });
                });
            });
            await serving(server, ctl);
            put(path.join(n.root, 'usr/bin/systemctl'), `#!/usr/bin/python3 -I
import json,socket,sys
if sys.argv[-1] != ${JSON.stringify(n.name + '.service')} or sys.argv[1] not in ('restart','stop','show','is-active'):
    sys.exit(64)
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(10);s.connect(${JSON.stringify(ctl)});s.sendall((sys.argv[1]+'\\n').encode());r=json.load(s.makefile('r'))
if r.get('error'):sys.exit(1)
if sys.argv[1]=='show':print('Job=\\nActiveState='+('active' if r['active'] else 'inactive')+'\\nSubState='+('running' if r['active'] else 'dead'))
elif sys.argv[1]=='is-active':sys.exit(0 if r['active'] else 3)
`, 0o700);
        }
        const pins = { version: 1, mode: 'enroll', executionContext: PROD,
            host: { ...p.pin, kind: 'host' }, nodes: nodes.map(n => n.pin), admission: { serverContext: PROD, databaseName: dbName,
                maintenanceGeneration: randomUUID(), deployment: { setName, replicaSetId: String(repl.settings.replicaSetId) },
                manifestSha256: topology('services/productionAdmissionInitializer').REVIEWED_MANIFEST_SHA256 } };
        const guardOpen = pin => {
            const n = pin.kind === 'host' ? p : nodes.find(n => n.id === pin.nodeId);
            assert.ok(n);
            let alive = true;
            return { get alive() { return alive; }, close() { alive = false; }, request(action, value) {
                return link.call('guard.' + action, () => {
                    assert.equal(alive, true);
                    const current = { ...n.pin.originalSnapshot, configSha256: fileDigest(n.configPath), unitSha256: fileDigest(n.unitPath) };
                    if (action === 'observe') {
                        const journal = fs.existsSync(n.journal) ? JSON.parse(fs.readFileSync(n.journal)) : null;
                        return { kind: 'node', nodeId: n.id, targetProfile: n.pin.targetProfile, held: true, serverContext: PROD,
                            physical: n.pin.physical, endpoint: n.pin.endpoint, policySha256: n.pin.policySha256, maintenanceId: n.pin.maintenanceId,
                            pristine: journal === null, journal, current, oldBackend: { instanceId: 's1-modeled-old', pid: 42, processStartTime: '123' } };
                    }
                    if (action === 'profile') return { configBase64: fs.readFileSync(n.configPath).toString('base64') };
                    if (action === 'capture') {
                        assert.equal(n.scope, undefined);
                        n.scope = { epoch: randomUUID(), bundleSha256: sha(fs.readFileSync(n.configPath)), ownerGeneration: null, phase: 'captured-held' };
                    } else if (action === 'bind') {
                        assert.equal(n.scope.ownerGeneration, null);
                        n.scope.ownerGeneration = value.ownerGeneration;
                    } else assert.equal(action, 'read');
                    assert.ok(n.scope);
                    return { ...n.scope };
                });
            } };
        };
        class FixtureNodeSSH {
            constructor(node, pin) {
                this.n = nodes.find(n => n.id === String(node._id));
                assert.ok(this.n);
                assert.deepEqual(pin.expectedEndpoint, this.n.pin.endpoint);
                assert.equal(pin.expectedHostKeySha256, this.n.pin.physical.sshHostKeySha256);
            }
            async writeFile() { throw Error('S1 refuses upload'); }
            async exec(command, options = {}) {
                const n = this.n;
                if (command.startsWith('if /usr/bin/test -e /usr/local/bin/.celerity-topology-node-runner-v2.upload')) {
                    return link.call('runner.preinstalled', () => ({ code: 0, stdout: `${fileDigest(path.join(n.root, runnerPath))}  ${runnerPath}\n750\n`, stderr: '' }));
                }
                if (command.startsWith('/usr/bin/systemctl show --property=FragmentPath')) {
                    return link.call('runner.unit', () => {
                        const file = n.unitPath.slice(n.root.length);
                        return { code: 0, stdout: `FragmentPath=${file}\nDropInPaths=\n${fileDigest(n.unitPath)}  ${file}\n`, stderr: '' };
                    });
                }
                if (command === '/usr/bin/install -d -m 0755 -o root -g root /usr/local/etc/xray'
                    || command === '/usr/bin/install -d -m 0755 -o root -g root /usr/local/etc/xray /usr/local/etc/xray-bridge') {
                    return link.call('runner.install-dir', () => {
                        for (const dir of command.split(' ').filter(v => v.startsWith('/usr/local/etc/'))) fs.mkdirSync(path.join(n.root, dir), { recursive: true });
                        return { code: 0, stdout: '', stderr: '' };
                    });
                }
                const [program, ...args] = command.split(' ');
                assert.equal(program, runnerPath, 'only the checked local runner');
                assert.equal(args[0], '--command');
                assert.match(args[1], /^(prepare|commit|verify|observe-verify|rollback|close|status|restore-users|read-restored-users)$/);
                const result = await link.call(`runner.${args[1]}`, () => capture('/bin/bash', [runner, ...args], { stdin: options.stdin,
                    extra: { CELERITY_TOPOLOGY_ROOT: n.root } }));
                evidence.lastRunner = { role: n.role, verb: args[1], code: result.code };
                for (const bytes of [result.stdout, result.stderr]) {
                    try {
                        const code = JSON.parse(bytes).code;
                        if (typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,100}$/.test(code)) evidence.lastRunner.result = code;
                    } catch { /* preserve exit classification; never copy raw output */ }
                }
                if (result.code === 0) mark(`runner_${args[1]}_${n.role}`);
                return result;
            }
        }
        const { createRootTopologyExecutionAuthority } = topology('runtime/productionPhysicalAuthority');
        const { createL2tpRootLifecycle, createL2tpRootHostDependencies } = src('modules/l2tpRuntimeLifecycleHook');
        const { l2tpActiveHostProvider } = src('modules/l2tpActiveHostProvider');
        const express = require('express');
        const { createCascadeLinksRouter } = src('routes/cascadeLinks');
        const app = express(); app.disable('x-powered-by'); app.use(express.json({ limit: '4kb' }));
        app.use((req, res, next) => { req.apiKey = { scopes: ['nodes:read', 'nodes:write'] }; next(); });
        app.use('/api/cascade/links', createCascadeLinksRouter());
        let ready = false;
        app.get('/fixture-ready', (req, res) => res.status(ready ? 200 : 503).json({ ready }));
        evidence.phase = 'startup';
        mark('rootStart');
        root = createL2tpRootLifecycle({ createTopologyExecutionAuthority: options => {
            authority = createRootTopologyExecutionAuthority({ ...options, read(file) {
                assert.equal(file, '/etc/celerity/topology-production.json'); return JSON.stringify(pins);
            }, open: guardOpen });
            return authority;
        }, createHostDependencies: options => createL2tpRootHostDependencies({ ...options, NodeSSH: FixtureNodeSSH }) });
        await root.startAfterDatabase(); mark('rootBarrier');
        assert.equal(typeof l2tpActiveHostProvider.getActiveHost()?.selectedTopologyIntentService?.accept, 'function');
        ready = true;
        const panelPort = (await serving(http.createServer(app))).port;
        assert.deepEqual(await httpResult(panelPort, { url: '/fixture-ready', signal }), { status: 200, body: { ready: true } });
        mark('fixtureReady'); evidence.startupMs = elapsed('rootStart', 'fixtureReady');
        evidence.startupRpc = link.counts();

        evidence.phase = 'apply'; mark('post');
        const deadline = marks.post + OBSERVE_APPLY_MS;
        const ack = await httpResult(panelPort, { url: '/api/cascade/links', signal: AbortSignal.any([signal, AbortSignal.timeout(LIMIT_MS)]), body: { expectedTopologyRevision: 0,
            name: 'S1 first reverse', portalNodeId: p.id, bridgeNodeId: b.id, autoDeploy: true,
            mode: 'reverse', tunnelSecurity: 'none', tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelPort } });
        mark('ack'); evidence.ackMs = elapsed('post', 'ack'); evidence.httpStatus = ack.status;
        if (typeof ack.body.code === 'string') evidence.httpCode = ack.body.code;
        assert.equal(ack.status, 202); assert.equal(ack.body.job.kind, 'link.create');
        const { jobId, linkId } = ack.body.job;
        assert.match(jobId, /^[0-9a-f]{24}$/); assert.match(linkId, /^[0-9a-f]{24}$/);
        const observe = async () => {
            signal.throwIfAborted();
            const job = await models.TopologyCreateIntent.findById(jobId).lean();
            const op = job?.operationId && await models.TopologyOperation.findById(job.operationId).lean();
            evidence.jobStatus = job?.status; evidence.jobCode = job?.errorCode ?? job?.resultCode;
            if (job?.status) mark('job_' + job.status);
            if (!op) return { job };
            mark('op_' + op.status);
            if (op.v2Terminal?.state) mark('terminal_' + op.v2Terminal.state);
            const state = await models.CascadeTopologyState.findById('singleton').lean();
            Object.assign(evidence, { status: op.status, proofs: op.v2Terminal?.proofs?.length || 0,
                lockCount: await models.NodeOperationLock.countDocuments(), heldAdmission: op.heldTopologyAdmission,
                admissionCount: state.topologyAdmissionCount, remoteAdmissionCount: state.remoteAdmissionCount,
                nodes: op.nodes.map(n => n.state), clientReadiness: op.clientReadiness });
            return { op, job };
        };
        const outcome = await until(deadline, async () => {
            const obs = await observe();
            if (['succeeded', 'failed', 'rolled_back'].includes(obs.op?.status) || (!obs.op && ['blocked','failed'].includes(obs.job?.status))) return obs;
            return null;
        });
        if (!outcome) evidence.timedOut = true;
        if (outcome?.op?.status === 'succeeded') {
            const { op } = outcome;
            evidence.exactCandidates = op.nodes.length === 2 && nodes.every(n => {
                const row = op.nodes.find(row => String(row.node) === n.id);
                return row && row.candidateHash === fileDigest(n.configPath) && row.candidateHash === n.launchedCandidate;
            });
            assert.equal(evidence.exactCandidates, true);
            assert.equal(evidence.remoteAdmissionCount, 0);
            const deployedLink = await models.CascadeLink.findById(linkId).lean();
            assert.ok(['online', 'deployed'].includes(deployedLink.status));
            mark('durableReadback');
            evidence.phase = 'client';
            const proxyPort = await port(), cfg = path.join(dir, 'client.json');
            put(cfg, JSON.stringify({ log: { loglevel: 'warning' }, inbounds: [{ listen: host, port: proxyPort, protocol: 'http' }],
                outbounds: [{ protocol: 'vless', settings: { vnext: [{ address: host, port: vlessPort, users: [{ id: user.xrayUuid, encryption: 'none' }] }] } }] }));
            const client = processOf(bin('xray'), ['run', '-config', cfg], { read: true });
            const body = await until(Math.min(deadline, performance.now() + 8000), async () => {
                signal.throwIfAborted(); assert.equal(client.exitCode, null);
                if (!ownsListener(client, proxyPort)) return false;
                return new Promise(resolve => {
                    const req = http.get({ host, port: proxyPort, path: `http://${host}:${originPort}/s1-proof`, timeout: 750 }, res => {
                        let data = ''; res.setEncoding('utf8'); res.on('data', chunk => data += chunk);
                        res.on('end', () => resolve(res.statusCode === 200 && data === originNonce)); res.on('error', () => resolve(false));
                    });
                    req.on('timeout', () => req.destroy()); req.on('error', () => resolve(false));
                });
            });
            if (body && hits > 0 && nodes.every(n => n.proc?.exitCode === null && n.proc.signalCode === null)) {
                mark('clientProof'); evidence.dataPlaneMs = elapsed('post', 'clientProof');
                evidence.combinedMs = elapsed('rootStart', 'clientProof'); evidence.originHits = hits;
            }
        }
        evidence.gate = classify(evidence);
        evidence.codes = [...new Set(events)];
    } catch (error) {
        evidence.failure = { code: typeof error.code === 'string' && /^[A-Z_]{1,128}$/.test(error.code) ? error.code : error.name,
            sites: [...String(error.stack || '').matchAll(/(?:\/src\/|\/scripts\/|\/node_modules\/)[\w./-]+:\d+:\d+/g)].map(m => m[0]).slice(0, 8) };
    } finally {
        const cleanup = async (name, fn) => { try { await fn(); } catch { stopFailures.push(name); } };
        await cleanup('root', async () => { await root?.stop(); authority?.close(); });
        await cleanup('mongoose', async () => { await mongoose?.disconnect(); });
        if (loggerLoaded) await cleanup('sshPool', async () => { src('services/sshPoolService').closeAll(); });
        for (const server of servers.reverse()) {
            server.closeAllConnections?.();
            await cleanup('server', () => close(server));
        }
        for (const child of children) await cleanup('child', () => stop(child));
        process.chdir(repo);
        await cleanup('scratch', () => fs.rmSync(dir, { recursive: true, force: true }));
        process.removeListener('SIGINT', interrupt).removeListener('SIGTERM', interrupt);
        evidence.cleaned = stopFailures.length === 0 && children.size === 0 && !fs.existsSync(dir);
        evidence.stopFailures = stopFailures;
        evidence.rpc = link.counts();
        mark('done');
    }
    console.log('S1 ' + JSON.stringify(evidence));
    return evidence.cleaned && evidence.gate === 'local-e2e-under-5m' ? 0 : 1;
}

if (process.argv.length !== 4 || !['0', '150'].includes(process.argv[2])) {
    console.error('usage: node scripts/prod-path-rtt150/run.cjs {0|150} /absolute/path/to/c3-fast-tools');
    process.exitCode = 2;
} else {
    main(Number(process.argv[2]), process.argv[3]).then(code => { process.exitCode = code; }, error => {
        console.error('S1 harness refused:', error.name); process.exitCode = 2;
    });
}
