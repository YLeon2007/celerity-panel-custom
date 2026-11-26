'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');

// Run the real transport, admission and held channel without loading panel
// credentials or opening the on-disk logger. Only the SSH dial is synthetic.
require.cache[require.resolve('../../utils/logger')] = { exports: { debug() {}, info() {}, warn() {}, error() {} } };
require.cache[require.resolve('../cryptoService')] = { exports: { decryptSafe: value => value } };
const NodeSSH = require('../nodeSSH');
const pool = require('../sshPoolService');
const { captureRelayBinding, relayListKey } = require('../rebuildRelayAuthorization');
const fs = require('node:fs');
const read = fs.readFileSync;
const proofBytes = Buffer.alloc(80);
proofBytes.writeUInt16LE(62, 18);
fs.readFileSync = (file, ...args) => typeof file === 'string' && file.endsWith('/libexec/rebuild-main-proof-linux-amd64')
    ? proofBytes : read(file, ...args);
const { createBoundRelayTransport, createMainApplyTransport, createTransport } = require('../rebuildTransport');
fs.readFileSync = read;

test.after(() => pool.closeAll());

const MACHINE = 'a'.repeat(32);
const ATTEST = '/usr/bin/head -c 34 /etc/machine-id';
const ARCH = '/usr/bin/uname -m';
const MAIN = 'fixture bundled MAIN receiver';
const PREAMBLE = 'fixture binary preamble';
const bootstrap = machineId => ({ machineId, managed: ['fixture-tag'], direct: null, routes: [] });
const directModule = require.resolve('../rebuildRelayDirect');
require.cache[directModule] = { exports: { bundledMainReceiverCommand(options, proof) {
    assert.deepEqual(options, bootstrap(options.machineId));
    assert.equal(proof, proofBytes);
    return { command: MAIN, preamble: Buffer.from(PREAMBLE) };
}, bundledMainFingerprintCommand: () => 'fixture fingerprint' } };
const NOT_ATTESTED = 'REBUILD_L2TP_TRANSPORT_NOT_ATTESTED';
const OWNER = 'REBUILD_MAIN_AUTHORITY_UNPROVED';
const USED = 'REBUILD_MAIN_WINDOW_USED';
const fails = (promise, code) => assert.rejects(promise, { code });

function fixture(t, { machine = MACHINE, deferOpen = false } = {}) {
    const binding = { nodeId: '1'.repeat(24), host: '192.0.2.10', port: 2222, username: 'root',
        machineId: MACHINE, sshHostKeySha256: '2'.repeat(64) };
    const node = { _id: binding.nodeId, ip: binding.host, ssh: { port: binding.port, username: binding.username } };
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', [relayListKey]: JSON.stringify([binding]) };
    const fence = captureRelayBinding(env, node._id, node);
    const calls = [], writes = [], checks = [];
    const state = { owner: true, frame: true, lock: undefined };
    let dials = 0, eof = 0, closes = 0;
    const opening = Promise.withResolvers();
    const socket = Object.assign(new EventEmitter(), { destroy() { this.destroyed = true; } });
    const client = Object.assign(new EventEmitter(), { _sock: socket, end() {} });
    const wire = Object.assign(new EventEmitter(), {
        stderr: new EventEmitter(),
        write(bytes, done) {
            writes.push(String(bytes));
            done();
            if (String(bytes) !== PREAMBLE) this.emit('data', Buffer.from('{"ok":true}\n'));
            return true;
        },
        end(done) {
            eof++;
            done();
            this.emit('end');
            this.stderr.emit('end');
            this.emit('close', 0);
        },
        close() { closes++; },
    });
    client.exec = (command, cb) => {
        calls.push(command);
        if (command === ATTEST || command === ARCH) {
            const ch = Object.assign(new EventEmitter(), { stderr: new EventEmitter() });
            cb(null, ch);
            ch.emit('data', Buffer.from(command === ARCH ? 'x86_64\n' : `${machine}\n`));
            ch.stderr.emit('end');
            ch.emit('close', 0);
            return;
        }
        assert.equal(command, MAIN);
        opening.resolve(() => cb(null, wire));
        if (!deferOpen) cb(null, wire);
    };
    t.mock.method(NodeSSH.prototype, '_openDirectClient', async function () {
        dials++;
        assert.equal(this.usePool, false);
        assert.equal(this.node.ip, binding.host);
        assert.equal(this.node.ssh.port, binding.port);
        assert.equal(this.node.ssh.username, binding.username);
        return client;
    });
    t.mock.method(NodeSSH.prototype, 'connect', () => assert.fail('ordinary SSH connect'));
    t.mock.method(NodeSSH.prototype, 'connectDirect', () => assert.fail('retrying SSH connect'));
    t.mock.method(pool, 'exec', () => assert.fail('pooled SSH exec'));
    const transport = createBoundRelayTransport(node, fence, () => { checks.push('lock'); return state.lock; }, undefined, () => {
        checks.push('binding');
        if (state.binding === false) return false;
        return fence.check();
    });
    t.after(() => transport.close());
    const options = { timeout: 2000, maxFrameBytes: 64, bootstrap: bootstrap(MACHINE),
        verifyOwner: () => { checks.push('owner'); return state.owner; },
        verifyBeforeFrame: () => {
            checks.push('frame');
            return typeof state.frame === 'function' ? state.frame() : state.frame;
        } };
    return { transport, options, state, calls, writes, checks, socket, client, opening,
        drift: () => { env[relayListKey] = JSON.stringify([{ ...binding, machineId: 'b'.repeat(32) }]); },
        counts: () => ({ dials, eof, closes }) };
}

test('only an attested bound transport opens the fixed receiver; held frames and EOF join on that wire', async t => {
    const f = fixture(t);
    const plain = createTransport({}, class {});
    assert.equal(plain.openMainWindow, undefined);
    await fails(f.transport.openMainWindow(f.options), NOT_ATTESTED);
    assert.deepEqual(f.calls, []);
    await f.transport.attest();
    assert.deepEqual(f.calls, [ATTEST]);
    f.checks.length = 0;
    await fails(f.transport.openMainWindow({ ...f.options, timeout: Infinity }), 'SSH_HELD_OPTIONS');
    assert.deepEqual(f.checks, []);
    assert.deepEqual(f.calls, [ATTEST]);
    const held = await f.transport.openMainWindow({ ...f.options, command: '/ignored', args: ['ignored'], stdin: 'ignored' });
    assert.deepEqual(f.checks, ['owner', 'lock', 'binding', 'owner', 'lock', 'binding']);
    assert.deepEqual(f.calls, [ATTEST, ARCH, MAIN]);
    assert.deepEqual(f.writes, [PREAMBLE]);
    assert.deepEqual(await held.request({ action: 'read' }), { ok: true });
    assert.deepEqual(f.checks, ['owner', 'lock', 'binding', 'owner', 'lock', 'binding', 'owner', 'frame', 'lock', 'binding']);
    await fails(f.transport.openMainWindow(f.options), USED);
    await held.finish();
    await fails(held.request({ action: 'read' }), 'SSH_HELD_REVOKED');
    await fails(f.transport.openMainWindow(f.options), USED);
    assert.deepEqual(f.writes, [PREAMBLE, '{"action":"read"}\n']);
    assert.deepEqual(f.calls, [ATTEST, ARCH, MAIN]);
    assert.deepEqual(f.counts(), { dials: 1, eof: 1, closes: 0 });
});

test('failed machine attestation cannot launch MAIN', async t => {
    const f = fixture(t, { machine: 'b'.repeat(32) });
    await fails(f.transport.attest(), 'REBUILD_L2TP_MACHINE_ID_MISMATCH');
    await fails(f.transport.openMainWindow(f.options), NOT_ATTESTED);
    assert.deepEqual(f.calls, [ATTEST]);
    assert.equal(f.counts().dials, 1);
});

test('MAIN open refuses nonaffirmative ownership, a lost lock and changed binding before exec', async t => {
    const cases = [
        ['missing verifier', f => { delete f.options.verifyOwner; }, OWNER],
        ['undefined owner', f => { f.state.owner = undefined; }, OWNER],
        ['truthy owner', f => { f.state.owner = 1; }, OWNER],
        ['false owner', f => { f.state.owner = false; }, OWNER],
        ['owner rejection', f => { f.options.verifyOwner = async () => { throw Error('fixture owner'); }; }, OWNER],
        ['lost lock', f => { f.state.lock = false; }, 'REBUILD_LOCK_LOST'],
        ['binding refusal', f => { f.state.binding = false; }, 'REBUILD_L2TP_BINDING_MISMATCH'],
        ['binding drift', f => f.drift(), 'REBUILD_L2TP_BINDING_MISMATCH'],
        ['binding drift during owner check', f => { f.options.verifyOwner = async () => { f.drift(); return true; }; },
            'REBUILD_L2TP_BINDING_MISMATCH'],
    ];
    for (const [name, change, code] of cases) await t.test(name, async t => {
        const f = fixture(t);
        await f.transport.attest();
        change(f);
        await fails(f.transport.openMainWindow(f.options), code);
        assert.deepEqual(f.calls, [ATTEST]);
        assert.deepEqual(f.writes, []);
        assert.equal(f.counts().dials, 1);
    });
});

test('MAIN refuses a frame after fence or binding loss and never replays its write', async t => {
    for (const [name, lose] of [
        ['owner', f => { f.state.owner = undefined; }],
        ['node lock', f => { f.state.lock = false; }],
        ['binding', f => f.drift()],
        ['phase fence', f => { f.state.frame = 1; }],
        ['binding drift during phase check', f => { f.state.frame = async () => { f.drift(); return true; }; }],
    ]) await t.test(name, async t => {
        const f = fixture(t);
        await f.transport.attest();
        const held = await f.transport.openMainWindow(f.options);
        await held.request({ action: 'read' });
        lose(f);
        await fails(held.request({ action: 'fixture' }), 'SSH_HELD_VERIFY');
        await fails(held.request({ action: 'fixture' }), 'SSH_HELD_VERIFY');
        await fails(f.transport.openMainWindow(f.options), USED);
        assert.deepEqual(f.calls, [ATTEST, ARCH, MAIN]);
        assert.deepEqual(f.writes, [PREAMBLE, '{"action":"read"}\n']);
        assert.equal(f.socket.destroyed, true);
        assert.deepEqual(f.counts(), { dials: 1, eof: 0, closes: 1 });
    });
});

test('a concurrent open or missing exec acknowledgement cannot result in a second launch', async t => {
    const f = fixture(t, { deferOpen: true });
    await f.transport.attest();
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const owner = Promise.withResolvers();
    const checked = Promise.withResolvers();
    const opened = fails(f.transport.openMainWindow({ ...f.options, verifyOwner: () => {
        checked.resolve();
        return owner.promise;
    } }), 'SSH_HELD_TIMEOUT');
    await checked.promise;
    await fails(f.transport.openMainWindow(f.options), USED);
    assert.deepEqual(f.calls, [ATTEST]);
    owner.resolve(true);
    const deliver = await f.opening.promise;
    t.mock.timers.tick(f.options.timeout);
    await opened;
    deliver();
    await fails(f.transport.openMainWindow(f.options), USED);
    assert.deepEqual(f.calls, [ATTEST, ARCH, MAIN]);
    assert.deepEqual(f.writes, []);
    assert.equal(f.socket.destroyed, true);
    assert.deepEqual(f.counts(), { dials: 1, eof: 0, closes: 1 });
});

test('closing a pending MAIN open aborts and disposes a late channel with no stdin or EOF', async t => {
    const f = fixture(t, { deferOpen: true });
    await f.transport.attest();
    const opened = fails(f.transport.openMainWindow(f.options), 'SSH_HELD_REVOKED');
    const deliver = await f.opening.promise;
    await f.transport.close();
    await opened;
    deliver();
    await fails(f.transport.openMainWindow(f.options), NOT_ATTESTED);
    assert.deepEqual(f.calls, [ATTEST, ARCH, MAIN]);
    assert.deepEqual(f.writes, []);
    assert.equal(f.socket.destroyed, true);
    assert.deepEqual(f.counts(), { dials: 1, eof: 0, closes: 1 });
});

test('a replaced socket cannot launch the MAIN receiver', async t => {
    const f = fixture(t);
    await f.transport.attest();
    f.client._sock = new EventEmitter();
    await assert.rejects(f.transport.openMainWindow(f.options), /one-shot connection is no longer active/);
    await fails(f.transport.openMainWindow(f.options), USED);
    assert.deepEqual(f.calls, [ATTEST]);
    assert.equal(f.counts().dials, 1);
});

test('ordinary MAIN holds the original Apply client with no mandatory pin or machine-ID', async t => {
    for (const [machineId, changed] of [[null, false], [MACHINE, false], [MACHINE, true]])
        await t.test(JSON.stringify([!!machineId, changed]), async t => {
            const commands = [];
            let dials = 0;
            t.mock.method(NodeSSH.prototype, '_openDirectClient', async function () {
                dials++;
                return Object.assign(new EventEmitter(), {
                    _sock: Object.assign(new EventEmitter(), { destroy() { this.destroyed = true; } }), end() {},
                    exec(command, cb) {
                        commands.push(command);
                        const channel = Object.assign(new EventEmitter(), { stderr: new EventEmitter(), close() {},
                            write(bytes, done) { assert.equal(String(bytes), PREAMBLE); done(); },
                            end(done) { done(); this.emit('end'); this.stderr.emit('end'); this.emit('close', 0); } });
                        cb(null, channel);
                        if (command === MAIN) return;
                        const stdout = command === ATTEST ? `${changed ? 'f'.repeat(32) : MACHINE}\n`
                            : command === ARCH ? 'x86_64\n' : `${'d'.repeat(64)}\n`;
                        channel.emit('data', Buffer.from(stdout));
                        channel.stderr.emit('end'); channel.emit('close', 0);
                    },
                });
            });
            const transport = createMainApplyTransport({ ip: '192.0.2.21', ssh: {} },
                { machineId, sshHostKeySha256: null }, async () => {});
            t.after(() => transport.close());
            if (changed) {
                await fails(transport.attest(), 'REBUILD_L2TP_MACHINE_ID_MISMATCH');
                assert.deepEqual(commands, [ATTEST]);
            } else {
                await transport.attest();
                assert.equal(await transport.verifyMainConnection(), true);
                assert.equal(await transport.readMainSha256(), 'd'.repeat(64));
                const channel = await transport.openMainWindow({ timeout: 1000, maxFrameBytes: 64,
                    verifyOwner: () => true, verifyBeforeFrame: () => true, bootstrap: bootstrap(machineId) });
                await channel.finish();
                assert.deepEqual(commands, [...(machineId ? [ATTEST] : []), 'fixture fingerprint', ARCH, MAIN]);
            }
            assert.equal(dials, 1);
        });
});

test('ordinary MAIN connect sends hostVerifier only for the selected DB pin', async t => {
    const { Client } = require('ssh2');
    const key = Buffer.from('synthetic SSH public key bytes');
    const pin = require('node:crypto').createHash('sha256').update(key).digest('hex');
    const calls = [];
    t.mock.method(Client.prototype, 'connect', function (config) {
        calls.push(Object.hasOwn(config, 'hostVerifier'));
        this._sock = Object.assign(new EventEmitter(), { destroy() { this.destroyed = true; }, end() {} });
        if (config.hostVerifier && !config.hostVerifier(key)) this.emit('error', Error('synthetic mismatch'));
        else this.emit('ready');
        return this;
    });
    for (const [sshHostKeySha256, accepts] of [[null, true], [pin, true], ['a'.repeat(64), false]]) {
        const transport = createMainApplyTransport({ ip: '192.0.2.21', ssh: { password: 'synthetic-ssh' } },
            { machineId: null, sshHostKeySha256 }, async () => {});
        try {
            if (accepts) await transport.attest();
            else await fails(transport.attest(), 'REBUILD_L2TP_SSH_CONNECT_FAILED');
        } finally { await transport.close(); }
    }
    assert.deepEqual(calls, [false, true, true]);
});
