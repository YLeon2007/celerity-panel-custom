'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { EventEmitter } = require('node:events');
const { createHash } = require('node:crypto');
const ssh2 = require('ssh2');

// Stub the SSH wire, not NodeSSH or rebuildTransport. Real pin-verifier,
// direct/pool selection, exec/stdin and profile-write code stay in the join.
let openWire;
const originalClient = ssh2.Client;
ssh2.Client = class extends EventEmitter {
    connect(config) { this._sock = { writable: true, destroy: () => this.end() }; this.wire = openWire(this, config); }
    exec(command, cb) { this.wire.exec(command, cb); }
    end() { this._sock.writable = false; this.wire?.close(); }
};
const { createRebuildService } = require('../rebuildService');
const { makeLocks } = require('../rebuildLocks');
const pool = require('../sshPoolService');
const poolConnection = pool.getConnection;
const { MAIN, BRIDGE } = require('../classicAppliedConfig');
const { READ_CHAIN, VERIFY_CHAIN } = require('../rebuildTunnelTls');
const NodeSSH = require('../nodeSSH'); // lazy in rebuildTransport; capture the simulated wire here
ssh2.Client = originalClient;

test.before(() => test.mock.method(require('node:net').Socket.prototype, 'connect', () => assert.fail('fixture must not open sockets')));
test.after(() => pool.closeAll());
const objectId = n => n.toString(16).padStart(24, '0');
const machine = n => n.toString(16).padStart(32, '0');
const wireKey = n => Buffer.from(`synthetic-public-key-blob-${n}`);
const digest = key => createHash('sha256').update(key).digest('hex');
const blank = () => ({ inbounds: [], outbounds: [], routing: { rules: [] } });
const query = fn => ({ select() { return this; }, sort() { return this; }, read() { return this; },
    readConcern() { return this; }, session() { return this; }, async lean() { return structuredClone(fn()); } });
const profileRead = path => `if test -f ${path}; then cat ${path}; elif test ! -e ${path}; then printf 'C3_CLASSIC_PROFILE_ABSENT'; else exit 1; fi`;

function fixture(t, { injected = false, relayCount = 2, ordinaryRelay = false } = {}) {
    const nodes = ['bridge', 'relay', 'relay'].slice(0, 1 + relayCount).map((role, i) => ({
        _id: objectId(i + 1), ip: `node${i}.fixture.invalid`, active: true, type: 'xray', cascadeRole: role,
        sshHostKeySha256: 'f'.repeat(64), ssh: { port: 2222 + i, username: 'root', password: 'fixture-auth',
            hostVerifier: 'not transport authority' },
    }));
    const links = nodes.slice(1).map((n, i) => ({ _id: objectId(10 + i), active: true, portalNode: n._id,
        bridgeNode: nodes[i]._id, tunnelSecurity: 'none', mode: 'reverse', tunnelPort: 40000 + i }));
    // A standalone non-L2TP case still drives the entire writer.
    const request = links.length ? { linkId: links[0]._id } : { nodeId: nodes[0]._id };
    const states = nodes.slice(1).map(n => ({ _id: n._id, node: n._id, status: 'installed', desiredState: 'installed',
        tproxyPort: 31111, secretRevision: 2, routingMode: 'follow-relay' }));
    const bindings = nodes.slice(1).map((n, i) => ({ nodeId: n._id, host: n.ip.toUpperCase(), port: n.ssh.port,
        username: n.ssh.username, machineId: machine(i + 1), sshHostKeySha256: digest(wireKey(i + 1)) }));
    const hosts = nodes.map((n, i) => {
        const main = blank();
        if (i) main.inbounds.push({ protocol: 'dokodemo-door', tag: `relay-l2tp-${n._id}`, port: 31111,
            settings: { followRedirect: true }, streamSettings: { sockopt: { tproxy: 'tproxy' } } });
        return { id: n._id, key: wireKey(i), machine: machine(i), files: { [MAIN]: main, [BRIDGE]: blank() }, staged: new Map() };
    });
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', ENCRYPTION_KEY: '0'.repeat(32),
        C3_REBUILD_L2TP_RELAY_ID: bindings[0]?.nodeId, C3_REBUILD_L2TP_RELAY_MACHINE_ID: bindings[0]?.machineId,
        C3_REBUILD_L2TP_SSH_SHA256: bindings[0]?.sshHostKeySha256 };
    const setList = rows => { env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify(rows); };
    setList(bindings);
    const effects = [], sessions = [], probes = [], commands = [], poolRequests = [], overrides = {};
    let lock;
    const locks = makeLocks({
        async insertOne(row) { assert.equal(lock, undefined); lock = row; },
        async findOne({ token }) { return lock?.token === token ? lock : null; },
        async deleteOne({ token }) { if (lock?.token === token) lock = undefined; },
    });
    const inLock = () => assert.ok(lock, 'remote command or DB effect ran outside Apply lock');
    const effect = (...args) => { inLock(); effects.push(args); };
    openWire = (client, config) => {
        inLock();
        const i = nodes.findIndex(n => n.ip.toLowerCase() === config.host.toLowerCase());
        assert.ok(i >= 0, 'no network or unexpected host');
        const host = hosts[i], session = { host: config.host, id: host.id, pinned: !!config.hostVerifier, closed: false };
        sessions.push(session);
        assert.equal(config.port, nodes[i].ssh.port);
        assert.equal(config.username, nodes[i].ssh.username);
        const verified = !config.hostVerifier || config.hostVerifier(host.key);
        queueMicrotask(() => {
            if (overrides.onHandshake?.(host.id, client, session)) return;
            verified ? client.emit('ready') : client.emit('error', Error('fixture key mismatch'));
        });
        return {
            close() { if (!session.closed) { session.closed = true; client.emit('close'); } },
            exec(command, cb) {
                inLock();
                if (session.closed) return cb(Error('fixture channel closed'));
                assert.ok(verified, 'no command after failed handshake');
                commands.push({ session, command });
                const stream = new EventEmitter();
                // Separately model stdin and stdout directions of an ssh2 Channel.
                stream.stderr = new EventEmitter();
                const dispatch = input => {
                    const finish = (status, stdout = '') => { stream.emit('data', Buffer.from(stdout)); stream.emit('close', status); };
                    if (command === '/usr/bin/head -c 34 /etc/machine-id') {
                        probes.push(session); return finish(0, `${host.machine}\n`);
                    }
                    if (command === '/usr/local/bin/xray version') return finish(0, 'Xray 26.3.27\n');
                    if (command === READ_CHAIN || command === VERIFY_CHAIN) return finish(1);
                    for (const [path, unit] of [[MAIN, 'xray'], [BRIDGE, 'xray-bridge']]) {
                        if (command === profileRead(path)) { overrides.onRead?.(host.id,path); return finish(0, JSON.stringify(host.files[path])); }
                        if (command === `systemctl show -p LoadState --value ${unit}.service`) return finish(0, 'loaded\n');
                        if (command === `systemctl show -p ExecStart --value ${unit}.service`) return finish(0, `path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${path} ;`);
                        if (command.includes(`cat > ${path}.rebuild-`)) {
                            effect('stage', host.id, path); host.staged.set(path, JSON.parse(input));
                            return finish(overrides.onStage?.(host.id, () => session.closed = true) ?? 0);
                        }
                        if (command.includes(`mv -fT ${path}.rebuild-`)) {
                            effect('replace', host.id, path); host.files[path] = host.staged.get(path); host.staged.delete(path);
                            return finish(0);
                        }
                    }
                    if (command.startsWith('systemctl ')) { effect('systemctl', host.id); return finish(0); }
                    if (command.startsWith('rm -f -- ')) { effect('cleanup', host.id); host.staged.clear(); return finish(0); }
                    assert.fail('unexpected SSH command in offline profile fixture');
                };
                if (command.includes('cat > ')) {
                    let input = '';
                    stream.write = chunk => { input += chunk; return true; };
                    stream.end = callback => { callback(); queueMicrotask(() => dispatch(input)); };
                }
                cb(null, stream);
                if (!command.includes('cat > ')) queueMicrotask(() => dispatch());
            },
        };
    };
    t.mock.method(pool, 'getConnection', async function (node, options) {
        poolRequests.push(node._id);
        assert.ok(node._id === nodes[0]._id || ordinaryRelay && node._id === nodes[2]?._id,
            'L2TP transport must not consult the pool');
        return poolConnection.call(this, node, options);
    });

    pool.settingsLoaded = true;
    pool.config.maxRetries = 0;
    t.after(() => pool.closeAll());
    const transportOverrides = injected ? { connect(node) {
        assert.equal(node._id, nodes[0]._id, 'generic injected transport must never own an L2TP binding');
        effect('injected-stock');
        return require('../rebuildTransport').createTransport(node);
    } } : {};
    const service = createRebuildService({ env, locks, ...transportOverrides, assertNoRelayAccountIntent: async () => inLock(),
        Node: { find: ({ _id }) => query(() => nodes.filter(n => _id.$in.includes(n._id))) },
        State: { find: ({ node }) => query(() => states.filter(s => node.$in.includes(s.node))),
            async updateOne() { effect('state'); return { matchedCount: 1 }; } },
        Link: { find: filter => query(() => links.filter(l => !filter._id || filter._id.$in.includes(l._id))),
            db: { async transaction(fn) { inLock(); return fn({}); } },
            async updateOne() { effect('link'); return { acknowledged: true, matchedCount: 1, modifiedCount: 1 }; },
            async deleteMany() { effect('delete'); return { deletedCount: 1 }; } },
        sync: { async _getUsersForNode() { return []; } }, cache: { async invalidateAllSubscriptions() {} },
        compose: ({ affectedNodeIds }) => affectedNodeIds.flatMap(nodeId => [
            { nodeId, profile: 'main', config: { ...hosts.find(h => h.id === nodeId).files[MAIN], log: { loglevel: 'warning' } } },
            { nodeId, profile: 'bridge', config: blank() },
        ]),
    });
    return { service, request, nodes, states, hosts, bindings, env, setList, effects, sessions, probes, commands, poolRequests, overrides, links };
}

const assertNoWrites = f => assert.deepEqual(f.effects.filter(([type]) => type !== 'injected-stock'), []);

test('ordinary Apply attests A+B under its lock and both profile pairs use the actual attested wire', async t => {
    const f = fixture(t);
    const r = await f.service.execute(f.request);
    assert.equal(r.allowed, true);
    assert.deepEqual(f.probes.map(p => p.id), f.bindings.map(b => b.nodeId));
    for (const binding of f.bindings) {
        const owned = f.sessions.filter(s => s.id === binding.nodeId);
        assert.equal(owned.length, 1);
        const [session] = owned;
        assert.equal(session.host, binding.host, 'use operator spelling rather than the corroborating card');
        assert.equal(session.pinned && session.closed, true);
        const commands = f.commands.filter(x => x.session === session).map(x => x.command);
        assert.equal(commands[0], '/usr/bin/head -c 34 /etc/machine-id');
        assert.ok(commands.includes(profileRead(MAIN)));
        assert.equal(commands.filter(c => c.includes(' run -test -config ')).length, 2);
        assert.equal(commands.filter(c => c.includes('mv -fT')).length, 2);
        assert.ok(commands.at(-1).startsWith('rm -f -- '));
    }
    assert.ok(f.sessions.some(s => s.id === f.nodes[0]._id && !s.pinned), 'stock non-relay still uses the ordinary pool');
    assert.equal(f.effects.filter(([verb]) => verb === 'replace').length, 6);
});

for (const [label, mutate, code] of [
    ['missing entry with valid legacy settings', f => f.setList(f.bindings.slice(1)), 'REBUILD_L2TP_INSTALL_DISABLED'],
    ['duplicate machine', f => f.setList([f.bindings[0], { ...f.bindings[1], machineId: f.bindings[0].machineId }]), 'REBUILD_L2TP_INSTALL_DISABLED'],
    ['changed card endpoint', f => f.nodes[2].ssh.port++, 'REBUILD_L2TP_BINDING_MISMATCH'],
    ['install receipt machine drift', f => { f.states[1].rebuildMachineId = machine(9); }, 'REBUILD_L2TP_BINDING_MISMATCH'],
    ['host key mismatch', f => { f.hosts[2].key = wireKey(9); }, 'REBUILD_L2TP_SSH_CONNECT_FAILED'],
    ['machine ID mismatch', f => { f.hosts[2].machine = machine(9); }, 'REBUILD_L2TP_MACHINE_ID_MISMATCH'],
]) {
    test(`Apply refuses ${label} with no writes anywhere (held reentry and injected connector)`, async t => {
        const f = fixture(t, { injected: true });
        const preview = await f.service.execute({ ...f.request, preview: true, remove: true });
        f.effects.length = f.sessions.length = f.commands.length = f.probes.length = 0;
        mutate(f);
        const before = structuredClone(f.hosts.map(h => h.files));
        await f.service.locks.run(verify => assert.rejects(f.service.execute({ ...f.request, remove: true,
            expectedPreview: preview.previewId }, verify), { code }));
        assertNoWrites(f);
        assert.deepEqual(f.hosts.map(h => h.files), before);
        assert.ok(!f.commands.some(x => x.command !== '/usr/bin/head -c 34 /etc/machine-id'), 'attest the whole affected set before any profile/core probe');
        assert.ok(f.sessions.every(s => s.pinned && s.closed));
        if (label.endsWith('mismatch')) {
            assert.equal(f.probes[0]?.id, f.bindings[0].nodeId);
            assert.equal(f.sessions.length, 2, 'no fallback connection after mismatch');
        }
    });
}

test('unconfigured list does not change legacy singleton resolution; non-L2TP ignores even an invalid list', async t => {
    const legacy = fixture(t, { relayCount: 1 });
    delete legacy.env.C3_REBUILD_L2TP_RELAYS_JSON;
    await legacy.service.execute(legacy.request);
    assert.deepEqual(legacy.probes.map(p => p.id), [legacy.bindings[0].nodeId]);
    assert.ok(legacy.sessions.some(s => s.host === legacy.nodes[1].ip && s.pinned));
    pool.closeAll();
    const stock = fixture(t, { relayCount: 0 });
    stock.env.C3_REBUILD_L2TP_RELAYS_JSON = 'invalid fixture list';
    await stock.service.execute(stock.request);
    assert.equal(stock.probes.length, 0);
    assert.deepEqual(stock.sessions.map(s => s.pinned), [false]);
    assert.equal(stock.effects.filter(([verb]) => verb === 'replace').length, 2);
});

test('enrolled uninstalled relay uses the operator pin; a relay without a list entry stays ordinary', async t => {
    const f = fixture(t, { ordinaryRelay: true });
    f.states.length = 0;
    for (const h of f.hosts) h.files[MAIN].inbounds = [];
    f.setList(f.bindings.slice(0, 1));

    f.hosts[1].key = wireKey(9);
    await assert.rejects(f.service.execute(f.request), { code: 'REBUILD_L2TP_SSH_CONNECT_FAILED' });
    assertNoWrites(f);
    assert.deepEqual(f.commands, []);
    assert.deepEqual(f.sessions.map(s => [s.id, s.pinned, s.closed]), [[f.nodes[1]._id, true, true]]);

    f.hosts[1].key = wireKey(1);
    assert.equal((await f.service.execute(f.request)).allowed, true);
    assert.deepEqual(f.probes.map(s => s.id), [f.nodes[1]._id]);
    assert.ok(f.poolRequests.includes(f.nodes[2]._id));
    assert.ok(!f.poolRequests.includes(f.nodes[1]._id));
    const ordinary = f.sessions.filter(s => s.id === f.nodes[2]._id);
    assert.deepEqual(ordinary.map(s => s.pinned), [false]);
    assert.equal(f.effects.filter(([verb]) => verb === 'replace').length, 6);
    assert.ok(!f.effects.some(([verb]) => verb === 'state'), 'enrollment alone does not publish an installed state');
});

test('revoking an uninstalled relay enrollment during the handshake refuses before any command', async t => {
    const f = fixture(t, { relayCount: 1 });
    f.states.length = 0;
    f.hosts[1].files[MAIN].inbounds = [];
    f.overrides.onHandshake = () => { f.setList([]); };
    await assert.rejects(f.service.execute(f.request), { code: 'REBUILD_L2TP_INSTALL_DISABLED' });
    assert.deepEqual(f.sessions.map(s => [s.id, s.pinned, s.closed]), [[f.nodes[1]._id, true, true]]);
    assert.deepEqual(f.poolRequests, []);
    assert.deepEqual(f.commands, []);
    assertNoWrites(f);
});

for (const closeBeforeReady of [true, false]) {
    test(`Apply disposes a ${closeBeforeReady ? 'closed' : 'stalled'} pre-auth wire without retry or late use`, { timeout: 1000 }, async t => {
        const f = fixture(t, { relayCount: 1 });
        if (!closeBeforeReady) shortenAdmission(t);
        pool.config.maxRetries = 2;
        let lateClient;
        f.overrides.onHandshake = (id, client, session) => {
            assert.equal(id, f.nodes[1]._id);
            lateClient = client;
            if (closeBeforeReady) {
                // ssh2 can emit end/close, and clear readyTimeout, without error.
                session.closed = true;
                client._sock.writable = false;
                client.emit('end');
                client.emit('close');
            }
            return true;
        };
        await assert.rejects(f.service.execute(f.request), { code: 'REBUILD_L2TP_SSH_CONNECT_FAILED' });
        assert.deepEqual(f.sessions.map(s => [s.pinned, s.closed]), [[true, true]]);
        await f.service.locks.run(async () => {}); // The failed Apply released its lock.
        assert.equal(lateClient.listenerCount('ready'), 0);
        lateClient.emit('ready');
        lateClient.emit('error', Error('fixture late error'));
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(f.sessions.length, 1);
        assert.deepEqual(f.poolRequests, []);
        assert.deepEqual(f.commands, []);
        assertNoWrites(f);
    });
}

function shortenAdmission(t) {
    const realSetTimeout = setTimeout;
    t.mock.method(global, 'setTimeout', (fn, ms, ...args) => realSetTimeout(fn, ms === 30000 ? 25 : ms, ...args));
}

test('expiry while queued never opens a late direct connection', { timeout: 1000 }, async t => {
    const f = fixture(t, { relayCount: 1 });
    shortenAdmission(t);
    const active = NodeSSH._activeDirect;
    NodeSSH._activeDirect = Infinity; // Model a fully occupied legacy semaphore.
    try {
        await assert.rejects(f.service.execute(f.request), { code: 'REBUILD_L2TP_SSH_CONNECT_FAILED' });
        assert.equal(NodeSSH._waitQueue.length, 0);
        NodeSSH._releaseDirectSlot();
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(f.sessions, []);
        assertNoWrites(f);
    } finally { NodeSSH._activeDirect = active; }
});

test('a changed binding after attestation vetoes the whole component before its first effect', async t => {
    const f = fixture(t);
    f.overrides.onRead = (id,path) => {
        if (id === f.nodes[2]._id && path === BRIDGE) f.setList(f.bindings.slice(0, 1));
    };
    await assert.rejects(f.service.execute(f.request), { code: 'REBUILD_L2TP_INSTALL_DISABLED' });
    assertNoWrites(f);
    assert.equal(f.probes.length, 2);
});

test('staging failure on a lost bound connection cannot reconnect to clean up or write profiles', async t => {
    const f = fixture(t);
    f.overrides.onStage = (id, lose) => {
        if (id !== f.nodes[1]._id) return 0;
        lose(); return 1;
    };
    await assert.rejects(f.service.execute(f.request), { code: 'REBUILD_NODE_COMMAND_FAILED' });
    const a = f.sessions.filter(s => s.id === f.nodes[1]._id);
    assert.equal(a.length, 1);
    assert.equal(f.effects.some(([verb]) => ['replace', 'systemctl', 'state'].includes(verb)), false);
    assert.equal(f.effects.some(([verb, id]) => verb === 'cleanup' && id === f.nodes[1]._id), false);
});

test('draft TLS probes use the same pinned channel and never run on a machine mismatch', async t => {
    const f = fixture(t, { injected: true });
    const draft = { ...f.links[0], tunnelSecurity: 'tls', rebuildTlsServerName: 'tunnel.fixture.invalid' };
    await f.service.locks.run(verify => assert.rejects(f.service.verifyDraftTls(draft, verify), { code: 'REBUILD_TLS_CERT_UNREADABLE' }));
    const command = f.commands.find(c => c.command === READ_CHAIN);
    assert.ok(command?.session.pinned);
    assert.equal(command.session, f.probes[0]);
    f.hosts[1].machine = machine(9);
    f.commands.length = 0;
    await assert.rejects(f.service.verifyDraftTls(draft), { code: 'REBUILD_L2TP_MACHINE_ID_MISMATCH' });
    assert.deepEqual(f.commands.map(c => c.command), ['/usr/bin/head -c 34 /etc/machine-id']);
    assertNoWrites(f);
});

test('reentry rejects an arbitrary or expired verifier before opening a connection', async t => {
    const f = fixture(t);
    let expired;
    await f.service.locks.run(verify => { expired = verify; });
    for (const verify of [async () => true, expired]) {
        await assert.rejects(f.service.execute(f.request, verify), { code: 'REBUILD_LOCK_LOST' });
    }
    assert.equal(f.sessions.length, 0);
    assertNoWrites(f);
});
