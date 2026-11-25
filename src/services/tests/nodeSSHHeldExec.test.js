'use strict';

const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync } = require('node:crypto');
const { EventEmitter, once } = require('node:events');
const { performance } = require('node:perf_hooks');
const { Duplex } = require('node:stream');
const test = require('node:test');
const { Client, Server, utils } = require('ssh2');
const NodeSSH = require('../nodeSSH');
const pool = require('../sshPoolService');

const COMMAND = '/fixture/held-worker';
const OPTIONS = { timeout: 1000, maxFrameBytes: 32, verifyBeforeFrame: () => true };
const turn = () => new Promise(resolve => setImmediate(resolve));
const fails = (promise, code) => assert.rejects(promise, { code });
test.after(() => pool.closeAll());

async function fixture(t) {
    const node = { ip: '192.0.2.10', ssh: { port: 22, username: 'fixture' } };
    const ssh = new NodeSSH(node, { expectedHostKeySha256: 'a'.repeat(64), expectedEndpoint: { ip: node.ip, ...node.ssh } });
    ssh.usePool = false;
    const socket = new EventEmitter();
    socket.destroy = () => { socket.destroyed = true; };
    const client = Object.assign(new EventEmitter(), { _sock: socket, end() {} });
    client.on('error', () => {});
    let dials = 0, callback, eof = 0, closes = 0;
    const commands = [], writes = [];
    client.exec = (command, cb) => { commands.push(command); callback = cb; };
    ssh._openDirectClient = async () => { dials++; return client; };
    const exec = await ssh.connectDirectOnce(1000);
    t.after(() => ssh.disconnect());
    const channel = new EventEmitter();
    channel.stderr = new EventEmitter();
    channel.write = (bytes, done) => { writes.push(Buffer.from(bytes)); done(); return true; };
    channel.end = done => { eof++; done(); };
    channel.close = () => { closes++; };
    const data = bytes => channel.emit('data', Buffer.from(bytes));
    function open(options, afterCallback) {
        const opened = exec.openHeld(COMMAND, { ...OPTIONS, ...options });
        callback(null, channel);
        afterCallback?.();
        return opened;
    }
    return { node, ssh, exec, socket, client, channel, open, data, writes, commands, deliver: () => callback(null, channel),
        counts: () => ({ dials, eof, closes }) };
}

function terminal(channel, code = 0) {
    channel.emit('close', code);
    channel.emit('end');
    channel.stderr.emit('end');
}

test('held exec serializes JSON lines, verifies each frame and joins terminal evidence', async t => {
    const f = await fixture(t);
    const gates = [Promise.withResolvers(), Promise.withResolvers()];
    let checked = 0;
    const held = await f.open({ verifyBeforeFrame: () => gates[checked++].promise });
    assert.deepEqual(Reflect.ownKeys(held).sort(), ['abort', 'finish', 'request']);
    assert.ok(Object.isFrozen(held));
    assert.equal(checked, 0);
    await assert.rejects(f.exec.openHeld(COMMAND, OPTIONS));
    const first = held.request({ step: 1 });
    await fails(held.request({ step: 2 }), 'SSH_HELD_BUSY');
    await fails(held.finish(), 'SSH_HELD_BUSY');
    assert.deepEqual(f.writes, []);
    gates[0].resolve(true);
    await turn();
    assert.deepEqual(f.writes.map(String), ['{"step":1}\n']);
    const response = Buffer.from('{"text":"ё"}\n');
    const split = response.indexOf(0xd1) + 1;
    f.data(response.subarray(0, split));
    f.data(response.subarray(split));
    assert.deepEqual(await first, { text: 'ё' });
    const second = held.request({ step: 2 });
    await turn();
    assert.equal(f.writes.length, 1);
    gates[1].resolve(true);
    await turn();
    f.data('null\n');
    assert.equal(await second, null);

    let settled = false;
    const finished = held.finish();
    void finished.then(() => { settled = true; });
    assert.equal(f.counts().eof, 1);
    f.channel.emit('close', 0);
    f.channel.emit('end');
    await turn();
    assert.equal(settled, false, 'close and stdout EOF cannot stand in for stderr EOF');
    f.channel.stderr.emit('end');
    await finished;
    await assert.rejects(held.request({ step: 3 }));
    await assert.rejects(f.exec.openHeld(COMMAND, OPTIONS));
    held.abort();
    assert.equal(f.socket.destroyed, undefined);
    assert.deepEqual(f.writes.map(String), ['{"step":1}\n', '{"step":2}\n']);
    assert.deepEqual(f.commands, [COMMAND]);
    assert.deepEqual(f.counts(), { dials: 1, eof: 1, closes: 0 });
});

test('held exec rejects startup stdout and output while awaiting authorization', async t => {
    const startup = await fixture(t);
    await fails(startup.open({}, () => startup.data('0\n')), 'SSH_HELD_PROTOCOL');
    assert.deepEqual(startup.writes, []);
    const f = await fixture(t);
    const gate = Promise.withResolvers();
    const held = await f.open({ verifyBeforeFrame: () => gate.promise });
    const result = fails(held.request(0), 'SSH_HELD_PROTOCOL');
    f.data('0\n');
    await result;
    gate.resolve(true);
    await turn();
    assert.deepEqual(f.writes, []);
    assert.deepEqual(f.counts(), { dials: 1, eof: 0, closes: 1 });
});

test('held exec needs literal true and rechecks endpoint, original client/socket and monotonic deadline', async t => {
    let now = 100;
    t.mock.method(performance, 'now', () => now);
    let replacementDisposals = 0;
    for (const [lose, code] of [
        [(_f, gate) => gate.resolve(1), 'SSH_HELD_VERIFY'],
        [(_f, gate) => gate.reject(new Error('fixture diagnostic')), 'SSH_HELD_VERIFY'],
        [f => { f.node.ssh.port++; }, 'SSH_HELD_REVOKED'],
        [f => { f.ssh.directClient = { end() {}, exec: () => assert.fail('replacement exec') }; }, 'SSH_HELD_REVOKED'],
        [f => { f.client._sock = { destroy: () => replacementDisposals++ }; }, 'SSH_HELD_REVOKED'],
        [() => { now += OPTIONS.timeout; }, 'SSH_HELD_TIMEOUT'],
    ]) {
        const f = await fixture(t);
        const gate = Promise.withResolvers();
        const held = await f.open({ verifyBeforeFrame: () => gate.promise });
        const result = fails(held.request(0), code);
        lose(f, gate);
        gate.resolve(true);
        await result;
        await fails(held.request(0), code);
        await assert.rejects(f.exec.openHeld(COMMAND, OPTIONS));
        assert.deepEqual(f.writes, []);
        assert.deepEqual(f.commands, [COMMAND]);
        assert.equal(f.socket.destroyed, true);
    }
    assert.equal(replacementDisposals, 0);
});

test('abort, disconnect and transport loss do not wait for a pending verifier', async t => {
    for (const revoke of [(f, held) => held.abort(), f => f.ssh.disconnect(), f => f.socket.emit('end'), f => f.client.emit('error', new Error('fixture'))]) {
        const f = await fixture(t);
        const gate = Promise.withResolvers();
        const held = await f.open({ verifyBeforeFrame: () => gate.promise });
        const result = fails(held.request(0), 'SSH_HELD_REVOKED');
        revoke(f, held);
        await result;
        gate.resolve(true);
        await turn();
        assert.deepEqual(f.writes, []);
        assert.deepEqual(f.counts(), { dials: 1, eof: 0, closes: 1 });
        assert.equal(f.socket.destroyed, true);
    }
});

test('one deadline includes unacknowledged open and late channels cannot resume it', async t => {
    const f = await fixture(t);
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const expired = fails(f.exec.openHeld(COMMAND, OPTIONS), 'SSH_HELD_TIMEOUT');
    t.mock.timers.tick(OPTIONS.timeout);
    await expired;
    assert.equal(f.socket.destroyed, true);
    f.deliver();
    f.channel.emit('error', new Error('late fixture error'));
    f.channel.stderr.emit('error', new Error('late fixture error'));
    assert.deepEqual(f.writes, []);
    assert.deepEqual(f.counts(), { dials: 1, eof: 0, closes: 1 });
});

test('held exec counts wire bytes including LF and rejects invalid UTF-8, invalid JSON and pipelining', async t => {
    for (const [bytes, error] of [
        ['"ёё"\n', 'SSH_HELD_LIMIT'], ['123456', 'SSH_HELD_LIMIT'],
        [Buffer.from([0x22, 0xff, 0x22, 0x0a]), 'SSH_HELD_PROTOCOL'],
        ['oops\n', 'SSH_HELD_PROTOCOL'], ['1\n2\n', 'SSH_HELD_PROTOCOL'], ['1\nx', 'SSH_HELD_PROTOCOL'],
    ]) {
        const f = await fixture(t);
        const held = await f.open({ maxFrameBytes: 6 });
        const reply = fails(held.request(0), error);
        await turn();
        f.data(bytes);
        await reply;
        assert.equal(f.writes.length, 1);
        assert.equal(f.counts().eof, 0);
    }
    const f = await fixture(t);
    const held = await f.open({ maxFrameBytes: 6 });
    const reply = held.request('ёa'); // six wire bytes
    await turn();
    f.data('12345');
    f.data('\n');
    assert.equal(await reply, 12345);
    await fails(held.request('ёё'), 'SSH_HELD_LIMIT');
    assert.equal(f.writes.length, 1);
});

test('request waits for write acknowledgement; data after a reply still revokes', async t => {
    const f = await fixture(t);
    let acknowledge;
    f.channel.write = (_bytes, cb) => { acknowledge = cb; return false; };
    const held = await f.open();
    const reply = held.request(0);
    let resolved = false;
    void reply.then(() => { resolved = true; });
    await turn();
    f.data('1\n');
    await turn();
    assert.equal(resolved, false);
    acknowledge();
    assert.equal(await reply, 1);
    f.data('2');
    await fails(held.finish(), 'SSH_HELD_PROTOCOL');
    assert.equal(f.counts().eof, 0);
});

test('a lost reply or a first-write failure is terminal without another write or EOF', async t => {
    for (const cut of ['reply', 'write']) {
        const f = await fixture(t);
        let attempts = 0;
        const write = f.channel.write;
        f.channel.write = (bytes, done) => {
            attempts++;
            if (cut === 'write') throw new Error('fixture first-write error');
            return write(bytes, done);
        };
        t.mock.timers.enable({ apis: ['setTimeout'] });
        const code = cut === 'reply' ? 'SSH_HELD_TIMEOUT' : 'SSH_HELD_IO';
        const held = await f.open();
        const result = fails(held.request(0), code);
        await turn();
        t.mock.timers.tick(OPTIONS.timeout);
        await result;
        f.data('0\n');
        await fails(held.request(0), code);
        await fails(held.finish(), code);
        assert.equal(attempts, 1);
        assert.deepEqual(f.counts(), { dials: 1, eof: 0, closes: 1 });
        t.mock.timers.reset();
    }
});

test('held finish refuses early close, nonzero or missing status, trailing data and incomplete EOF', async t => {
    const early = await fixture(t);
    const premature = await early.open();
    terminal(early.channel);
    await fails(premature.finish(), 'SSH_HELD_PROTOCOL');
    assert.equal(early.counts().eof, 0);
    for (const noise of [f => f.data('0\n'), f => f.channel.stderr.emit('data', Buffer.from('fixture')), f => terminal(f.channel, 1),
        f => { f.channel.emit('close'); f.channel.emit('end'); f.channel.stderr.emit('end'); }]) {
        const f = await fixture(t);
        const held = await f.open();
        const finished = fails(held.finish(), 'SSH_HELD_PROTOCOL');
        noise(f);
        await finished;
    }
    const f = await fixture(t);
    let now = 1;
    t.mock.method(performance, 'now', () => now);
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const held = await f.open();
    now += OPTIONS.timeout - 1;
    const finished = fails(held.finish(), 'SSH_HELD_TIMEOUT');
    f.channel.emit('close', 0);
    f.channel.emit('end');
    t.mock.timers.tick(OPTIONS.timeout);
    await finished;
    f.channel.stderr.emit('end');
    assert.equal(f.socket.destroyed, true);
});

test('held exec refuses unbounded options before dispatch', async t => {
    const f = await fixture(t);
    assert.equal(typeof f.exec.openHeld, 'function');
    for (const options of [{ timeout: 0 }, { timeout: Infinity }, { timeout: 2 ** 31 },
        { maxFrameBytes: Infinity }, { maxFrameBytes: -1 }, { verifyBeforeFrame: undefined }]) {
        await fails(f.exec.openHeld(COMMAND, { ...OPTIONS, ...options }), 'SSH_HELD_OPTIONS');
        assert.deepEqual(f.commands, []);
    }
});

test('ssh2 over in-memory Duplex streams reaches one pinned worker twice and sends one final EOF', { timeout: 5000 }, async t => {
    const hostKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs1' });
    const pin = createHash('sha256').update(utils.parseKey(hostKey).getPublicSSH()).digest('hex');
    function memorySocket() {
        return new Duplex({
            allowHalfOpen: false,
            read() {},
            write(bytes, _encoding, cb) {
                const packet = Buffer.from(bytes);
                // Model socket delivery without reentering the peer's packet parser.
                setImmediate(() => { if (!this.peer.destroyed) this.peer.push(packet); cb(); });
            },
            final(cb) { if (!this.peer.destroyed) this.peer.push(null); cb(); },
            destroy(err, cb) { if (!this.peer.destroyed) this.peer.push(null); cb(err); },
        });
    }
    const local = memorySocket(), remote = memorySocket();
    local.peer = remote;
    remote.peer = local;
    t.after(() => { local.destroy(); remote.destroy(); });
    const originalConnect = Client.prototype.connect;
    let dials = 0, eof = 0;
    t.mock.method(Client.prototype, 'connect', function (config) {
        dials++;
        return originalConnect.call(this, { ...config, sock: local });
    });
    const commands = [], lines = [];
    const peer = new Server({ hostKeys: [hostKey] }, connection => {
        connection.on('error', () => {});
        connection.on('authentication', ctx => {
            if (ctx.method === 'password' && ctx.username === 'fixture' && ctx.password === 'fixture-only') ctx.accept();
            else ctx.reject(['password']);
        });
        connection.on('ready', () => connection.on('session', accept => {
            accept().on('exec', (acceptExec, _reject, { command }) => {
                commands.push(command);
                const channel = acceptExec();
                let pending = '';
                channel.on('data', bytes => {
                    pending += bytes.toString('utf8');
                    const lf = pending.indexOf('\n');
                    if (lf < 0) return;
                    const line = pending.slice(0, lf + 1);
                    pending = pending.slice(lf + 1);
                    lines.push(line);
                    channel.write(JSON.stringify({ reply: JSON.parse(line).step }));
                    channel.write('\n');
                });
                channel.on('end', () => {
                    eof++;
                    channel.exit(pending ? 1 : 0);
                    channel.end();
                });
            });
        }));
    });
    peer.injectSocket(remote);
    const node = { ip: '192.0.2.11', ssh: { username: 'fixture', password: 'fixture-only', port: 22 } };
    const ssh = new NodeSSH(node, { expectedHostKeySha256: pin, expectedEndpoint: { ip: node.ip, port: 22, username: 'fixture' } });
    ssh.usePool = false;
    t.after(() => ssh.disconnect());
    const exec = await ssh.connectDirectOnce(2000);
    const held = await exec.openHeld(COMMAND, OPTIONS);
    assert.equal(ssh.directClient._sock, local);
    assert.deepEqual(await held.request({ step: 1 }), { reply: 1 });
    assert.deepEqual(await held.request({ step: 2 }), { reply: 2 });
    assert.equal(eof, 0);
    await held.finish();
    assert.deepEqual({ dials, eof, commands, lines }, { dials: 1, eof: 1, commands: [COMMAND], lines: ['{"step":1}\n', '{"step":2}\n'] });
    const closed = once(remote, 'close');
    ssh.disconnect();
    await closed;
});
