'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash, generateKeyPairSync } = require('node:crypto');
const { EventEmitter, once } = require('node:events');
const { performance } = require('node:perf_hooks');
const { Duplex } = require('node:stream');
const { createRelayIdentityProbe } = require('../rebuildRelayIdentityProbe');

// This file uses only synthetic credentials and in-memory SSH/socket doubles.
Object.assign(process.env, {
    PANEL_DOMAIN: 'panel.invalid', ACME_EMAIL: 'test@panel.invalid',
    ENCRYPTION_KEY: 'fixture-only-encryption-key-do-not-use', SESSION_SECRET: 'fixture-session',
});
const cryptoService = require('../cryptoService');
function syntheticBlob(type) {
    return Buffer.concat([Buffer.from([0, 0, 0, type.length]), Buffer.from(type, 'latin1'), Buffer.from([0, 128, 255, 10])]);
}
const RAW_KEY = syntheticBlob('ssh-ed25519');
const PIN = sha256(RAW_KEY);
const MACHINE = '1234567890abcdef'.repeat(2);
const CHANGED = 'REBUILD_L2TP_IDENTITY_CHANGED';
const UNAVAILABLE = 'REBUILD_L2TP_IDENTITY_UNAVAILABLE';
const COMMAND = '/usr/bin/head -c 34 /etc/machine-id';
const DIAGNOSTIC = new Error('raw SSH diagnostic with private credential or output');

function sha256(key) { return createHash('sha256').update(key).digest('hex'); }
function node(ssh = { password: 'fixture-password' }) {
    return { ip: 'relay.invalid', ssh: { port: 2222, username: 'relay-admin', ...ssh } };
}
function safeError(code) {
    return error => {
        assert.equal(error.code, code);
        assert.equal(error.message, code);
        assert.equal(error.cause, undefined);
        assert.deepEqual(Object.keys(error), ['code']);
        return true;
    };
}

function fixture({ timeoutMs = 1000 } = {}) {
    const sockets = [], clients = [];
    const probe = createRelayIdentityProbe({ timeoutMs,
        createSocket() {
            const socket = new EventEmitter();
            socket.connect = endpoint => { socket.endpoint = endpoint; };
            socket.destroy = () => {
                assert.ok(!socket.destroyed);
                socket.destroyed = true;
                socket.emit('close');
            };
            sockets.push(socket);
            return socket;
        },
        Client: class extends EventEmitter {
            constructor() {
                super();
                this.commands = [];
                clients.push(this);
            }
            connect(config) { this.config = config; }
            exec(command, cb) {
                this.commands.push(command);
                this.execReply = cb;
            }
        },
    });
    return { probe, sockets, clients };
}

function ready(client, key = RAW_KEY) {
    assert.equal(client.config.hostVerifier(key), true);
    client.emit('handshake');
    const auth = client.config.authHandler();
    assert.ok(auth);
    client.emit('ready');
    assert.deepEqual(client.commands, [COMMAND]);
    return auth;
}

function channel(client) {
    const stream = new EventEmitter();
    stream.stderr = new EventEmitter();
    stream.end = (...args) => {
        assert.deepEqual(args, [], 'no command input');
        stream.stdinEnded = true;
    };
    stream.destroy = () => { stream.destroyed = true; };
    stream.stderr.destroy = () => { stream.stderr.destroyed = true; };
    client.execReply(null, stream);
    return stream;
}

function finish(stream, code = 0, signal) {
    stream.emit('close', code, signal);
    stream.stderr.emit('end');
}

test('key-only probe never inspects credentials, declines KEX, and starts fresh each time', async () => {
    const { probe, sockets, clients } = fixture();
    const card = node();
    for (const field of ['privateKey', 'password', 'agent']) {
        Object.defineProperty(card.ssh, field, { get() { assert.fail(`read ${field}`); } });
    }
    for (const type of ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa', 'ssh-dss']) {
        const key = syntheticBlob(type);
        const result = probe.probeKey(card);
        const { config } = clients.at(-1);
        assert.deepEqual(sockets.at(-1).endpoint, { host: 'relay.invalid', port: 2222 });
        assert.equal(config.sock, sockets.at(-1));
        for (const field of ['hostHash', 'privateKey', 'password', 'agent', 'agentForward', 'tryKeyboard']) {
            assert.equal(Object.hasOwn(config, field), false);
        }
        assert.equal(config.hostVerifier(key), false);
        assert.equal(config.authHandler(), false);
        clients.at(-1).emit('ready');
        clients.at(-1).emit('error', DIAGNOSTIC);
        assert.deepEqual(await result, { sshHostKeySha256: sha256(key), sshHostKeyType: type });
        assert.equal(sockets.at(-1).destroyed, true);
        assert.deepEqual(clients.at(-1).commands, []);
    }
    assert.equal(clients.length, 6);
});

test('probe refuses malformed or non-public-key type fields without exposing bytes', async () => {
    for (const key of [Buffer.from([0, 0, 0]), Buffer.from([0, 0, 0, 20, 1]),
        syntheticBlob('rsa-sha2-512'), syntheticBlob('ssh-rsa\n'), syntheticBlob('\xf3sh-rsa'),
        syntheticBlob('unrecognized-fixture')]) {
        const { probe, clients, sockets } = fixture();
        const pending = probe.probeKey(node());
        assert.equal(clients[0].config.hostVerifier(key), false);
        await assert.rejects(pending, safeError(UNAVAILABLE));
        assert.equal(sockets[0].destroyed, true);
    }
});

test('a fresh mismatched key never reaches auth or exec and is not an outage', async t => {
    const { probe, sockets, clients } = fixture();
    t.mock.method(cryptoService, 'decryptSafe', () => assert.fail('decryption before pin'));
    const result = probe.readMachine(node(), PIN);
    const [client] = clients;
    assert.equal(client.config.hostVerifier(Buffer.from([99])), false);
    client.emit('error', DIAGNOSTIC);
    client.emit('handshake');
    assert.equal(client.config.authHandler(), false);
    client.emit('ready');
    await assert.rejects(result, safeError(CHANGED));
    assert.deepEqual(client.commands, []);
    assert.equal(sockets[0].destroyed, true);
    assert.equal(cryptoService.decryptSafe.mock.callCount(), 0);
});

test('malformed pin and missing endpoint refuse without opening a socket', async () => {
    const { probe, sockets } = fixture();
    for (const pin of [undefined, null, PIN.toUpperCase(), `${PIN}\n`, `${PIN.slice(1)}\n`, Buffer.from(PIN)]) {
        await assert.rejects(probe.readMachine(node(), pin), safeError(UNAVAILABLE));
    }
    await assert.rejects(probe.probeKey({ ...node(), ip: '' }), safeError(UNAVAILABLE));
    await assert.rejects(probe.readMachine(node({ port: '22' }), PIN), safeError(UNAVAILABLE));
    assert.equal(sockets.length, 0);
});

test('hostVerifier match alone does not authorize credentials before verified handshake', async t => {
    const { probe, clients, sockets } = fixture();
    t.mock.method(cryptoService, 'decryptSafe', () => assert.fail('premature decryption'));
    const result = probe.readMachine(node(), PIN);
    assert.equal(clients[0].config.hostVerifier(RAW_KEY), true);
    assert.equal(clients[0].config.authHandler(), false);
    clients[0].emit('handshake');
    clients[0].emit('ready');
    await assert.rejects(result, safeError(UNAVAILABLE));
    assert.equal(cryptoService.decryptSafe.mock.callCount(), 0);
    assert.equal(sockets[0].destroyed, true);
    assert.deepEqual(clients[0].commands, []);
});

test('pinned machine reads use the same SSH client and project decryption semantics', async () => {
    const { probe, clients, sockets } = fixture();
    const key = '-----BEGIN FIXTURE PRIVATE KEY-----\nsynthetic';
    for (const [stored, auth, output] of [
        [{ password: cryptoService.encrypt('encrypted-fixture') }, { type: 'password', password: 'encrypted-fixture' }, `${MACHINE}\n`],
        [{ password: 'legacy-fixture' }, { type: 'password', password: 'legacy-fixture' }, MACHINE],
        [{ privateKey: cryptoService.encrypt(key), password: 'unused' }, { type: 'publickey', key }, 'fedcba9876543210'.repeat(2)],
        [{ privateKey: key, password: 'unused' }, { type: 'publickey', key }, MACHINE],
    ]) {
        const pending = probe.readMachine(node(stored), PIN);
        const client = clients.at(-1);
        assert.equal(client.config.password, undefined);
        assert.equal(client.config.privateKey, undefined);
        assert.deepEqual(ready(client), { username: 'relay-admin', ...auth });
        const stream = channel(client);
        assert.equal(stream.stdinEnded, true);
        stream.emit('data', Buffer.from(output.slice(0, 17)));
        stream.emit('data', Buffer.from(output.slice(17)));
        finish(stream);
        assert.equal(await pending, output.replace(/\n$/, ''));
        assert.equal(sockets.at(-1).destroyed, true);
        assert.equal(stream.destroyed, true);
        assert.equal(stream.stderr.destroyed, true);
    }
    assert.equal(clients.length, 4);
});

test('read rejects unvalidated output, stderr, and failed or incomplete status', async () => {
    for (const [output, code, signal, stderr] of [
        ['', 0], ['not-a-machine-id', 0], [`${MACHINE} `, 0], [`${MACHINE}\r\n`, 0], [`${MACHINE.slice(1)}\n`, 0],
        [`${MACHINE}\n\n`, 0], [`${MACHINE}\nx`, 0], [Buffer.alloc(65536, 97), 0],
        [Buffer.from([0xb1, ...Buffer.from(MACHINE.slice(1))]), 0],
        [MACHINE, 1], [MACHINE, null, 'SIGTERM'], [MACHINE, '0'], [MACHINE, 0, undefined, 'remote stderr'],
    ]) {
        const { probe, sockets, clients } = fixture();
        const result = probe.readMachine(node(), PIN);
        ready(clients[0]);
        const stream = channel(clients[0]);
        stream.emit('data', Buffer.from(output));
        if (stderr) stream.stderr.emit('data', Buffer.from(stderr));
        finish(stream, code, signal);
        await assert.rejects(result, safeError(UNAVAILABLE));
        assert.equal(sockets[0].destroyed, true);
        assert.equal(stream.destroyed, true);
    }
    const { probe, clients } = fixture();
    const result = probe.readMachine(node(), PIN);
    ready(clients[0]);
    const stream = channel(clients[0]);
    stream.emit('data', Buffer.from(MACHINE));
    stream.emit('close');
    stream.stderr.emit('end');
    await assert.rejects(result, safeError(UNAVAILABLE));
});

test('client, channel, stderr and exec errors and pre-ready EOF are sanitized', async () => {
    for (const event of ['error', 'end', 'close']) {
        const { probe, sockets, clients } = fixture();
        const result = probe.probeKey(node());
        clients[0].emit(event, DIAGNOSTIC);
        await assert.rejects(result, safeError(UNAVAILABLE));
        assert.equal(sockets[0].destroyed, true);
    }
    for (const failure of ['exec', 'stream', 'stderr']) {
        const { probe, sockets, clients } = fixture();
        const pending = probe.readMachine(node(), PIN);
        ready(clients[0]);
        if (failure === 'exec') clients[0].execReply(DIAGNOSTIC);
        else {
            const stream = channel(clients[0]);
            (failure === 'stream' ? stream : stream.stderr).emit('error', DIAGNOSTIC);
            stream.emit('error', DIAGNOSTIC);
            stream.stderr.emit('error', DIAGNOSTIC);
        }
        await assert.rejects(pending, safeError(UNAVAILABLE));
        assert.equal(sockets[0].destroyed, true);
    }
});

test('one deadline aborts handshake, pending exec, and incomplete output; late work is disposed', async () => {
    for (const stall of ['handshake', 'open', 'output']) {
        const { probe, clients, sockets } = fixture({ timeoutMs: 20 });
        const pending = stall === 'handshake' ? probe.probeKey(node()) : probe.readMachine(node(), PIN);
        const [client] = clients;
        let stream;
        if (stall !== 'handshake') ready(client);
        if (stall === 'output') {
            stream = channel(client);
            stream.emit('data', Buffer.from(MACHINE));
            stream.emit('close', 0); // stderr EOF is still missing.
        }
        await assert.rejects(pending, safeError(UNAVAILABLE));
        assert.equal(sockets[0].destroyed, true);
        assert.equal(client.config.hostVerifier(RAW_KEY), false);
        assert.equal(client.config.authHandler(), false);
        client.emit('ready');
        client.emit('error', DIAGNOSTIC);
        if (stall === 'open') stream = channel(client);
        if (stream) {
            assert.equal(stream.destroyed, true);
            assert.equal(stream.stderr.destroyed, true);
            stream.emit('error', DIAGNOSTIC);
            stream.stderr.emit('error', DIAGNOSTIC);
        } else assert.deepEqual(client.commands, []);
    }
});

test('deadline is checked at authentication and after channel cleanup, even before the timer callback', async t => {
    let now = 0;
    t.mock.method(performance, 'now', () => now);
    const { probe, clients, sockets } = fixture();
    const pendingAuth = probe.readMachine(node(), PIN);
    assert.equal(clients[0].config.hostVerifier(RAW_KEY), true);
    clients[0].emit('handshake');
    now = 1000;
    assert.equal(clients[0].config.authHandler(), false);
    await assert.rejects(pendingAuth, safeError(UNAVAILABLE));

    const pendingRead = probe.readMachine(node(), PIN);
    ready(clients[1]);
    const stream = channel(clients[1]);
    stream.destroy = () => { now = 2000; };
    stream.emit('data', Buffer.from(MACHINE));
    finish(stream);
    await assert.rejects(pendingRead, safeError(UNAVAILABLE));
    assert.ok(sockets.every(socket => socket.destroyed));
});

test('cleanup attempts both channel sides and socket even if channel teardown throws', async () => {
    const { probe, clients, sockets } = fixture();
    const result = probe.readMachine(node(), PIN);
    ready(clients[0]);
    const stream = channel(clients[0]);
    stream.destroy = () => { throw DIAGNOSTIC; };
    stream.emit('data', Buffer.from(MACHINE));
    finish(stream);
    await assert.rejects(result, safeError(UNAVAILABLE));
    assert.equal(stream.stderr.destroyed, true);
    assert.equal(sockets[0].destroyed, true);
});

// Use the locked ssh2 implementation over paired memory streams. No listener,
// TCP, DNS, shell process, or machine-id file is involved in this fixture.
function memoryPair() {
    function stream() {
        return new Duplex({
            allowHalfOpen: false,
            read() {},
            write(bytes, _encoding, cb) {
                if (!this.peer.destroyed) this.peer.push(Buffer.from(bytes));
                cb();
            },
            final(cb) { if (!this.peer.destroyed) this.peer.push(null); cb(); },
            destroy(error, cb) { if (!this.peer.destroyed) this.peer.push(null); cb(error); },
        });
    }
    const client = stream(), server = stream();
    client.peer = server;
    server.peer = client;
    client.connect = () => {};
    return { client, server };
}

test('real ssh2 wire over simulated streams sends no auth before pin and reads only the fixed command', async () => {
    const { Server, utils } = require('ssh2');
    const hostKey = generateKeyPairSync('rsa', { modulusLength: 2048 })
        .privateKey.export({ format: 'pem', type: 'pkcs1' });
    const fixtureKey = utils.parseKey(hostKey);
    const pin = sha256(fixtureKey.getPublicSSH());
    const peers = [];
    const probe = createRelayIdentityProbe({ createSocket() {
        const { client, server } = memoryPair();
        const record = { closed: once(server, 'close'), auth: [], commands: [], signed: false };
        peers.push(record);
        const peer = new Server({ hostKeys: [hostKey], algorithms: { serverHostKey: ['rsa-sha2-512'] } }, connection => {
            connection.on('error', () => {});
            connection.on('handshake', negotiated => { record.hostKeyAlgorithm = negotiated.serverHostKey; });
            connection.on('authentication', ctx => {
                record.auth.push(ctx.method);
                if (ctx.username === 'relay-admin') {
                    if (ctx.method === 'password' && ctx.password === 'fixture-password') return ctx.accept();
                    if (ctx.method === 'publickey' && ctx.key.data.equals(fixtureKey.getPublicSSH())) {
                        if (!ctx.signature) return ctx.accept();
                        record.signed = fixtureKey.verify(ctx.blob, ctx.signature, ctx.hashAlgo) === true;
                        if (record.signed) return ctx.accept();
                    }
                }
                ctx.reject(['publickey', 'password']);
            });
            connection.on('ready', () => connection.on('session', accept => {
                accept().on('exec', (acceptExec, _reject, { command }) => {
                    record.commands.push(command);
                    const channel = acceptExec();
                    channel.exit(0);
                    channel.end(`${MACHINE}\n`);
                });
            }));
        });
        peer.injectSocket(server);
        return client;
    } });
    assert.deepEqual(await probe.probeKey(node()), { sshHostKeySha256: pin, sshHostKeyType: 'ssh-rsa' });
    await assert.rejects(probe.readMachine(node(), PIN), safeError(CHANGED));
    assert.equal(await probe.readMachine(node(), pin), MACHINE);
    assert.equal(await probe.readMachine(node({ privateKey: cryptoService.encrypt(hostKey), password: 'not-used' }), pin), MACHINE);
    await Promise.all(peers.map(peer => peer.closed));
    assert.deepEqual(peers.map(peer => peer.auth), [[], [], ['password'], ['publickey', 'publickey']]);
    assert.equal(peers[3].signed, true);
    assert.equal(peers[2].hostKeyAlgorithm, 'rsa-sha2-512');
    assert.deepEqual(peers.map(peer => peer.commands), [[], [], [COMMAND], [COMMAND]]);
});
