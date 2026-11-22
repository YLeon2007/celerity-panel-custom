'use strict';

const { createHash, timingSafeEqual } = require('node:crypto');
const { Socket } = require('node:net');
const { performance } = require('node:perf_hooks');

const CHANGED = 'REBUILD_L2TP_IDENTITY_CHANGED';
const UNAVAILABLE = 'REBUILD_L2TP_IDENTITY_UNAVAILABLE';
const TIMEOUT_MS = 15000;
const READ_MACHINE_ID = '/usr/bin/head -c 34 /etc/machine-id';
const safeError = code => Object.assign(new Error(code), { code });
const isHex = (value, length) => typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value);
const ignore = () => {};

function destroy(resource) {
    try { resource?.destroy(); return true; } catch { return false; }
}

function disposeChannel(channel) {
    const closed = destroy(channel);
    const stderrClosed = destroy(channel?.stderr);
    return closed && stderrClosed;
}

function machineAuth(username, privateKey, password) {
    // Same priority and legacy plaintext fallback as sshPoolService.
    const cryptoService = require('./cryptoService');
    if (privateKey) return { type: 'publickey', username, key: cryptoService.decryptPrivateKey(privateKey) };
    if (password) return { type: 'password', username, password: cryptoService.decryptSafe(password) };
    return false;
}

// Takes a server-validated relay card and (for the read) an independently
// approved pin. This is not a pool, a retrying transport, or an approval store.
function createRelayIdentityProbe({ Client = require('ssh2').Client, createSocket = () => new Socket(), timeoutMs = TIMEOUT_MS } = {}) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > TIMEOUT_MS) throw safeError(UNAVAILABLE);

    function run(node, expected) {
        return new Promise((resolve, reject) => {
            let socket, channel, done = false, pinAccepted = false, phase = 'key';
            const deadline = performance.now() + timeoutMs;
            const timer = setTimeout(() => finish(UNAVAILABLE), timeoutMs);

            function finish(code, value) {
                if (done) return;
                done = true; // Cleanup may emit synchronous or late errors/EOF.
                clearTimeout(timer);
                const channelClosed = disposeChannel(channel);
                // Own the socket: ssh2's Client.destroy() skips non-writable sockets.
                const socketClosed = destroy(socket);
                if (!code && (!channelClosed || !socketClosed || performance.now() >= deadline)) code = UNAVAILABLE;
                if (code) reject(safeError(code));
                else resolve(value);
            }
            const unavailable = () => finish(UNAVAILABLE);
            function live() {
                if (!done && performance.now() >= deadline) unavailable();
                return !done;
            }

            function readReply(error, stream) {
                if (!live() || error || !stream) {
                    if (stream) {
                        stream.on('error', ignore);
                        stream.stderr?.on('error', ignore);
                        disposeChannel(stream);
                    }
                    unavailable();
                    return;
                }
                channel = stream;
                const out = Buffer.alloc(33); // 32 hex bytes plus optional LF.
                let size = 0, closed = false, stderrEnded = false;
                function complete() {
                    if (!live() || !closed || !stderrEnded) return;
                    if (size === 33 && out[32] === 10) size--;
                    // ASCII decoding masks high bits in Node; latin1 preserves them.
                    const id = out.toString('latin1', 0, size);
                    if (isHex(id, 32)) finish(null, id);
                    else unavailable();
                }
                try {
                    channel.on('error', unavailable);
                    channel.stderr.on('error', unavailable);
                    channel.on('data', chunk => {
                        if (!live()) return;
                        if (!Buffer.isBuffer(chunk) || chunk.length > out.length - size) return unavailable();
                        chunk.copy(out, size);
                        size += chunk.length;
                    });
                    channel.stderr.on('data', chunk => {
                        if (!Buffer.isBuffer(chunk) || chunk.length !== 0) unavailable();
                    });
                    channel.stderr.once('end', () => { stderrEnded = true; complete(); });
                    channel.once('close', (status, signal) => {
                        if (status !== 0 || signal) return unavailable();
                        closed = true;
                        complete();
                    });
                    channel.end(); // EOF on stdin; never write a payload.
                } catch { unavailable(); }
            }

            try {
                const host = node?.ip, ssh = node?.ssh;
                const { port, username } = ssh ?? {};
                if (typeof host !== 'string' || !host || host.trim() !== host
                    || !Number.isInteger(port) || port < 1 || port > 65535
                    || typeof username !== 'string' || !username || username.trim() !== username) return unavailable();
                // Snapshot stored credential material only for stage two. No
                // credential is decrypted or even supplied to ssh2 until KEX.
                const privateKey = expected ? ssh.privateKey : undefined;
                const password = expected && !privateKey ? ssh.password : undefined;
                const client = new Client();
                socket = createSocket();
                socket.on('error', unavailable);
                client.on('error', unavailable).on('end', unavailable).on('close', unavailable);
                client.on('handshake', () => {
                    // ssh2 emits this after verifying the key exchange signature.
                    if (live() && pinAccepted && phase === 'key') phase = 'verified';
                });
                client.on('ready', () => {
                    if (!live()) return;
                    if (phase !== 'auth') return unavailable();
                    phase = 'read';
                    try { client.exec(READ_MACHINE_ID, readReply); } catch { unavailable(); }
                });
                if (!live()) return;
                socket.connect({ host, port });
                if (!live()) return;
                client.connect({
                    sock: socket, host, port, username, readyTimeout: 0,
                    hostVerifier(key) {
                        if (!live()) return false;
                        if (!Buffer.isBuffer(key) || !key.length) { unavailable(); return false; }
                        const digest = createHash('sha256').update(key).digest();
                        if (!expected) {
                            finish(null, digest.toString('hex'));
                            return false; // Stop before user authentication (even 'none').
                        }
                        if (!live()) return false;
                        if (!timingSafeEqual(digest, expected)) { finish(CHANGED); return false; }
                        pinAccepted = true;
                        return true;
                    },
                    authHandler() {
                        if (!live()) return false;
                        if (phase !== 'verified') { unavailable(); return false; }
                        try {
                            const auth = machineAuth(username, privateKey, password);
                            if (!auth) { unavailable(); return false; }
                            if (!live()) return false;
                            phase = 'auth';
                            return auth;
                        } catch { unavailable(); return false; }
                    },
                });
            } catch { unavailable(); }
        });
    }

    return {
        async probeKey(node) { return run(node); },
        async readMachine(node, expectedPin) {
            if (!isHex(expectedPin, 64)) throw safeError(UNAVAILABLE);
            return run(node, Buffer.from(expectedPin, 'hex'));
        },
    };
}

module.exports = { createRelayIdentityProbe };
