'use strict';

const { constants } = require('node:buffer');
const { performance } = require('node:perf_hooks');

const error = (code, message) => Object.assign(new Error(`SSH held exec ${message}`), { code: `SSH_HELD_${code}` });
const revoked = () => error('REVOKED', 'was revoked');
const timedOut = () => error('TIMEOUT', 'timed out');
const protocol = () => error('PROTOCOL', 'received unexpected channel output or status');
const limit = () => error('LIMIT', 'frame exceeds its byte limit');
const io = () => error('IO', 'channel I/O failed');
const ignoreError = () => {};

function deferred() {
    const result = {};
    result.promise = new Promise((resolve, reject) => { Object.assign(result, { resolve, reject }); });
    return result;
}

function heldOptions(command, options) {
    const { timeout, maxFrameBytes, verifyBeforeFrame } = options ?? {};
    if (typeof command !== 'string' || !command || !Number.isInteger(timeout) || timeout < 1 || timeout > 0x7fffffff
        || !Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 2 || maxFrameBytes > constants.MAX_LENGTH
        || typeof verifyBeforeFrame !== 'function') {
        throw error('OPTIONS', 'requires a command, finite timeout, frame byte limit and verifier');
    }
    return { timeout, maxFrameBytes, verifyBeforeFrame };
}

// The caller owns the pin and gives us the original client/socket pair, not a
// way to dial. A failed exchange is terminal, not evidence of no remote effect.
// The lifetime budget starts at open, and the frame limit includes its LF.
// stderr is not a side channel: any bytes there invalidate the exchange.
function openHeldExec(command, { timeout, maxFrameBytes, verifyBeforeFrame }, {
    client, socket, assertConnection, signal, onTerminal,
}) {
    const deadline = performance.now() + timeout;
    const opened = deferred();
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    const unlisten = [];
    let phase = 'opening', terminalError, stream, timer, pending;
    let input, used = 0;
    let stdoutEnded = false, stderrEnded = false, channelClosed = false, eofWritten = false;

    function listen(target, event, callback) {
        target.on(event, callback);
        unlisten.push(() => target.off(event, callback));
    }

    function drainErrors(channel) {
        channel?.on('error', ignoreError);
        channel?.stderr?.on('error', ignoreError);
    }

    function closeChannel(channel) {
        if (!channel || client._sock !== socket) return;
        // ssh2 destroy() calls end() first. Abort must not deliberately send EOF.
        try { channel.close(); } catch { /* the original socket is also destroyed */ }
    }

    function stop(failure) {
        if (phase === 'done') return;
        phase = 'done';
        terminalError = failure || revoked();
        clearTimeout(timer);
        signal.removeEventListener('abort', abort);
        drainErrors(stream);
        for (const detach of unlisten.splice(0)) detach();
        onTerminal(failure);
        const operation = pending;
        pending = input = undefined;
        if (failure) {
            closeChannel(stream);
            // Covers an unacknowledged exec or a close the peer never answers.
            try { socket.destroy(); } catch { /* preserve the original failure */ }
            opened.reject(failure);
            operation?.reject(failure);
        } else {
            operation.resolve();
        }
        stream = undefined;
    }

    function abort() { stop(revoked()); }

    function live() {
        if (phase === 'done') return false;
        if (performance.now() >= deadline) { stop(timedOut()); return false; }
        try { assertConnection(); } catch { abort(); return false; }
        return true;
    }

    function quiet() {
        if (!live()) return false;
        if (stream.readableLength || stream.stderr.readableLength) { stop(protocol()); return false; }
        return true;
    }

    function writable() {
        if (!quiet()) return false;
        if (stream.destroyed || stream.writableEnded || stream.readableEnded || stream.stderr.readableEnded) {
            stop(protocol());
            return false;
        }
        return true;
    }

    function maybeReply(operation) {
        if (phase !== 'reply' || !operation.written) return;
        phase = 'settling';
        queueMicrotask(() => {
            if (!quiet()) return;
            pending = undefined;
            phase = 'idle';
            operation.resolve(operation.reply);
        });
    }

    function stdout(bytes) {
        if (!bytes.length || !live()) return;
        if (phase !== 'reading' || !Buffer.isBuffer(bytes)) return stop(protocol());
        const lf = bytes.indexOf(0x0a);
        const count = lf < 0 ? bytes.length : lf;
        // Reserve one byte for LF even when it hasn't arrived yet.
        if (used + count >= maxFrameBytes) return stop(limit());
        if (lf >= 0 && lf !== bytes.length - 1) return stop(protocol());
        if (!input || used + count > input.length) {
            const next = Buffer.allocUnsafe(Math.min(maxFrameBytes - 1, Math.max(256, used + count, (input?.length ?? 0) * 2)));
            input?.copy(next, 0, 0, used);
            input = next;
        }
        bytes.copy(input, used, 0, count);
        used += count;
        if (lf < 0) return;
        try { pending.reply = JSON.parse(decoder.decode(input.subarray(0, used))); }
        catch { return stop(protocol()); }
        input = undefined;
        used = 0;
        phase = 'reply';
        maybeReply(pending);
    }

    function maybeFinish() {
        if (phase !== 'finishing' || !channelClosed || !stdoutEnded || !stderrEnded || !eofWritten) return;
        queueMicrotask(() => { if (quiet()) stop(); });
    }

    function end(which) {
        if (phase !== 'finishing') return stop(protocol());
        if (which === 'stdout') stdoutEnded = true;
        else stderrEnded = true;
        maybeFinish();
    }

    async function request(frame) {
        if (!live()) throw terminalError;
        if (phase !== 'idle') throw error('BUSY', 'is busy');
        const operation = pending = deferred();
        phase = 'verifying';
        void send(frame, operation).catch(() => stop(io()));
        return operation.promise;
    }

    async function send(frame, operation) {
        let json;
        try { json = JSON.stringify(frame); } catch { /* invalid frame */ }
        if (!writable()) return;
        if (typeof json !== 'string') return stop(protocol());
        if (Buffer.byteLength(json) >= maxFrameBytes) return stop(limit());
        const bytes = Buffer.from(`${json}\n`);
        let allowed;
        try { allowed = await verifyBeforeFrame(); } catch { /* verifier did not affirm */ }
        if (!live()) return;
        if (allowed !== true) return stop(error('VERIFY', 'frame verifier did not affirm'));
        if (!writable()) return;
        phase = 'reading'; // Latch handoff before entering the writer.
        try {
            stream.write(bytes, failure => {
                if (phase === 'done') return;
                if (failure) return stop(io());
                operation.written = true;
                maybeReply(operation);
            });
        } catch { stop(io()); }
    }

    async function finish() {
        if (!live()) throw terminalError;
        if (phase !== 'idle') throw error('BUSY', 'is busy');
        if (!writable()) throw terminalError;
        const operation = pending = deferred();
        phase = 'finishing';
        try {
            stream.end(failure => {
                if (phase === 'done') return;
                if (failure) return stop(io());
                eofWritten = true;
                maybeFinish();
            });
        } catch { stop(io()); }
        return operation.promise;
    }

    timer = setTimeout(() => stop(timedOut()), timeout);
    try {
        signal.addEventListener('abort', abort, { once: true });
        for (const event of ['end', 'close', 'error']) {
            listen(client, event, abort);
            listen(socket, event, abort);
        }
        listen(socket, 'finish', abort);
        if (signal.aborted) abort();
        if (live()) client.exec(command, (failure, channel) => {
            if (phase === 'done') {
                drainErrors(channel);
                closeChannel(channel);
                return;
            }
            stream = channel;
            if (failure || !stream?.stderr) return stop(io());
            listen(stream, 'error', () => stop(io()));
            listen(stream.stderr, 'error', () => stop(io()));
            listen(stream, 'exit', (code, signalName) => {
                if (phase !== 'finishing' || code !== 0 || signalName) stop(protocol());
            });
            listen(stream, 'close', (code, signalName) => {
                if (phase !== 'finishing' || code !== 0 || signalName) return stop(protocol());
                channelClosed = true;
                maybeFinish();
            });
            listen(stream, 'end', () => end('stdout'));
            listen(stream.stderr, 'end', () => end('stderr'));
            listen(stream.stderr, 'data', bytes => { if (bytes.length) stop(protocol()); });
            listen(stream, 'data', stdout);
            queueMicrotask(() => {
                if (!writable()) return;
                phase = 'idle';
                opened.resolve(Object.freeze({ request, finish, abort }));
            });
        });
    } catch { stop(io()); }
    return opened.promise;
}

module.exports = { heldOptions, openHeldExec };
