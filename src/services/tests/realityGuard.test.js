'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createRealityGuard, collectRealityTargets, parseDest, nodeCheckCommand,
    classifyNodeCheck, tlsHandshake } = require('../realityGuardService');

const peer = '93.184.216.34';
const healthy = { state: 'healthy', ip: peer };
const unknown = { state: 'unknown', reason: 'unavailable' };

test('destination and remote command grammar refuses unsafe args; only attributed failures corroborate', () => {
    for (const dest of ['x.example:443\nwhoami', 'x.example:+443', '/run/local.sock', '[8.8.8.8]:443',
        '10.0.0.4:443', '127.1:443', '0x7f000001:443', '[::1]:443', '[::ffff:127.0.0.1]:443', '-x.example:443']) {
        assert.equal(parseDest(dest), null, dest);
    }
    assert.deepEqual(parseDest('[2606:4700::1111]:443'), { host: '2606:4700::1111', port: 443 });
    assert.equal(nodeCheckCommand({ ip: peer, port: 443, sni: "x.example'; id #" }), null);
    assert.match(nodeCheckCommand({ ip: peer, port: 443, sni: 'safe.example' }), /-verify_hostname 'safe\.example'/);
    assert.equal(classifyNodeCheck({ code: 0, stderr: 'Protocol version: TLSv1.3\nVerification: OK\n' }).state, 'healthy');
    assert.equal(classifyNodeCheck({ code: 1, stderr: 'verify error:num=62:hostname mismatch\n' }).reason, 'cert_name');
    assert.equal(classifyNodeCheck({ code: 1, stderr: 'verify error:num=10:certificate has expired\n' }).reason, 'cert_expired');
    assert.equal(classifyNodeCheck({ code: 1, stderr: 'verify error:num=20:unable to get local issuer certificate\n' }).state, 'unknown');
    assert.equal(classifyNodeCheck({ code: 127, stderr: 'openssl: not found\n' }).state, 'unknown');
    assert.equal(classifyNodeCheck({ code: 0, stderr: 'Verification: OK\n' }).state, 'unknown');
});

test('collect only existing explicit REALITY endpoints, dedupe names, and skip unusable targets', () => {
    const inbound = (dest, realitySni, security = 'reality') => ({ security, realityDest: dest, realitySni });
    const main = inbound('old.example:0443', ['old.example']);
    assert.deepEqual(collectRealityTargets({ ...main, extraInbounds: [
        inbound('tls.example:443', ['tls.example'], 'tls'), inbound('old.example:443', ['OLD.example']),
        inbound('other.example:8443', ['other.example']), inbound('[::1]:443', ['self.example']),
        inbound('malformed.example:443', ['bad name']),
    ] }), [
        { host: 'old.example', port: 443, dest: 'old.example:443', snis: ['old.example'] },
        { host: 'other.example', port: 8443, dest: 'other.example:8443', snis: ['other.example'] },
    ]);
    assert.deepEqual(collectRealityTargets({ ...main, extraInbounds: Array(20).fill(main) }), []);
});

test('TLS uses only its validated numeric peer and exact SNI, and closes every opened socket', async () => {
    const pair = { host: 'configured.example', port: 8443, sni: 'valid.example' };
    let closed = 0;
    const lookup = async host => {
        assert.equal(host, 'configured.example.');
        return { address: peer };
    };
    for (const [code, expected] of [[null, { ...healthy, warning: 'no_h2' }],
        ['ERR_TLS_CERT_ALTNAME_INVALID', { state: 'failed', reason: 'cert_name', ip: peer }],
        ['CERT_HAS_EXPIRED', { state: 'failed', reason: 'cert_expired', ip: peer }],
        ['UNABLE_TO_GET_ISSUER_CERT_LOCALLY', { ...unknown, ip: peer }]]) {
        let called = false;
        const result = await tlsHandshake(pair, { lookup, connect(options) {
            called = true;
            assert.deepEqual(options, { host: peer, port: 8443, servername: 'valid.example',
                minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ecdhCurve: 'X25519',
                ALPNProtocols: ['h2', 'http/1.1'], rejectUnauthorized: true });
            const socket = Object.assign(new EventEmitter(), { destroy: () => { closed++; },
                authorized: true, alpnProtocol: false, getProtocol: () => 'TLSv1.3' });
            queueMicrotask(() => code ? socket.emit('error', { code }) : socket.emit('secureConnect'));
            return socket;
        } });
        assert.ok(called);
        assert.deepEqual(result, expected);
    }
    assert.equal(closed, 4);
    let connects = 0;
    const connect = () => { connects++; };
    for (const address of ['127.0.0.1', '169.254.169.254', '::ffff:93.184.216.34', '2001:db8::1']) {
        assert.deepEqual(await tlsHandshake(pair, { lookup: async () => ({ address }), connect }), unknown);
    }
    let resume;
    const lateLookup = new Promise(resolve => { resume = resolve; });
    assert.deepEqual(await tlsHandshake(pair, { lookup: () => lateLookup, connect, timeout: 10 }), unknown);
    resume({ address: peer });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(connects, 0);
});

test('threshold must accumulate on the same peer, and an unknown sample breaks the streak', async () => {
    const row = { _id: 'fixture', ip: '93.184.216.9', type: 'xray', active: true, cascadeRole: 'portal',
        xray: { security: 'reality', realityDest: 'target.example:443', realitySni: ['target.example'], realityGuard: { mode: 'notify' } } };
    const fail = ip => ({ state: 'failed', reason: 'connect', ip });
    const samples = [fail(peer), fail(peer), unknown, fail(peer), fail(peer), ...Array(3).fill(fail('93.184.216.35'))];
    let confirmations = 0, notifications = 0;
    const guard = createRealityGuard({ isGloballyEnabled: async () => true, listNodes: async () => [row], readNode: async () => row,
        isBusy: async () => false, isClientProfile: async () => true,
        panelProbe: async (_pair, allow) => await allow() ? samples.shift() : unknown,
        withNodeProbe: async (_node, work) => work(pair => { confirmations++; return fail(pair.ip); }),
        notify: async (_event, _data, { beforeDispatch }) => { if (await beforeDispatch()) notifications++; },
    });
    for (let i = 0; i < 7; i++) await guard.checkAll();
    assert.deepEqual([confirmations, notifications], [0, 0]);
    await guard.checkAll();
    assert.deepEqual([confirmations, notifications], [1, 1]);
});

test('batch limits concurrency, prevents overlap and drains already opened work', async () => {
    let release, entered;
    const held = new Promise(resolve => { release = resolve; });
    const reached = new Promise(resolve => { entered = resolve; });
    const rows = Array.from({ length: 12 }, (_, i) => ({ _id: `node-${i}`, ip: '93.184.216.9', type: 'xray', active: true,
        cascadeRole: 'portal', xray: { security: 'reality', realityDest: 'target.example:443',
            realitySni: ['target.example'], realityGuard: { mode: 'notify' } } }));
    let lists = 0, inFlight = 0, peak = 0;
    const guard = createRealityGuard({ isGloballyEnabled: async () => true,
        listNodes: async () => { lists++; return rows; }, readNode: async id => rows.find(row => row._id === id),
        isBusy: async () => false, isClientProfile: async () => true,
        panelProbe: async (_pair, allow) => {
            if (!await allow()) return unknown;
            peak = Math.max(peak, ++inFlight);
            if (peak === 4) entered();
            await held;
            inFlight--;
            return healthy;
        },
    });
    const tick = guard.checkAll();
    await reached;
    await guard.checkAll();
    assert.equal(lists, 1);
    let drained = false;
    const stop = guard.drain().then(() => { drained = true; });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(drained, false);
    release();
    await Promise.all([tick, stop]);
    assert.deepEqual([peak, inFlight, drained], [4, 0, true]);
});

test('real NodeSSH one-shot observation refuses after the direct-slot boundary and does not downgrade pinned execution', async t => {
    // Do not load application configuration or a dotenv file for this test.
    const loggerPath = require.resolve('../../utils/logger');
    const cryptoPath = require.resolve('../cryptoService');
    for (const path of [loggerPath, cryptoPath]) {
        const saved = require.cache[path];
        const noop = () => {};
        require.cache[path] = { loaded: true, exports: { info: noop, debug: noop, warn: noop, error: noop } };
        t.after(() => { if (saved) require.cache[path] = saved; else delete require.cache[path]; });
    }
    const NodeSSH = require('../nodeSSH');
    const node = { ip: '93.184.216.9', ssh: { port: 22, username: 'fixture' } };
    const ssh = new NodeSSH(node, { expectedEndpoint: { ip: node.ip, ...node.ssh }, expectedHostKeySha256: 'a'.repeat(64) });
    ssh.usePool = false;
    let opens = 0;
    const client = Object.assign(new EventEmitter(), { end() {}, exec: () => assert.fail('stale client submitted an exec') });
    ssh._openDirectClient = async () => { opens++; return client; };
    await assert.rejects(ssh.connectObserverOnce(async () => false), /no longer admitted/);
    assert.equal(opens, 0);
    const exec = await ssh.connectObserverOnce(async () => true);
    assert.equal(opens, 1);
    node.ssh.port = 2200;
    await assert.rejects(exec('fixed command'), /selected endpoint is invalid/);
    ssh.disconnect();
    require('../sshPoolService').closeAll();
});
