'use strict';

const EXEC_STDIN_CHUNK_BYTES = 64 * 1024;
const EXEC_STDIN_ERROR_MESSAGE = 'SSH stdin transfer failed';

function hasExecStdin(options) {
    return options !== null
        && typeof options === 'object'
        && Object.hasOwn(options, 'stdin');
}

function createExecStdinError() {
    return new Error(EXEC_STDIN_ERROR_MESSAGE);
}

// Only dispose the late channel, not the shared connection. The exec request
// may already have reached the server: this is not cancellation or no-dispatch.
function discardLateExecStream(stream) {
    if (!stream) return;
    stream.on('error', () => {});
    stream.stderr.on('error', () => {});
    try { stream.destroy(); } catch { /* caller's timeout is already final */ }
}

function stdinBuffer(input) {
    if (typeof input === 'string' || Buffer.isBuffer(input) || ArrayBuffer.isView(input)) {
        return Buffer.from(input);
    }
    throw createExecStdinError();
}

function writeExecStdin(stream, input, { onComplete, onError }) {
    let active = true;
    let drainListener = null;
    let offset = 0;
    let payload;

    const fail = () => {
        if (!active) return;
        active = false;
        if (drainListener) stream.removeListener('drain', drainListener);
        onError(createExecStdinError());
    };

    const finish = () => {
        if (!active) return;
        try {
            stream.end(() => {
                if (!active) return;
                onComplete();
            });
        } catch {
            fail();
        }
    };

    const writeAvailable = () => {
        if (!active) return;
        drainListener = null;
        try {
            while (offset < payload.length) {
                const nextOffset = Math.min(offset + EXEC_STDIN_CHUNK_BYTES, payload.length);
                const chunk = payload.subarray(offset, nextOffset);
                offset = nextOffset;
                if (!stream.write(chunk)) {
                    drainListener = writeAvailable;
                    stream.once('drain', drainListener);
                    return;
                }
            }
            finish();
        } catch {
            fail();
        }
    };

    try {
        payload = stdinBuffer(input);
        writeAvailable();
    } catch {
        fail();
    }

    return {
        cancel() {
            if (!active) return;
            active = false;
            if (drainListener) stream.removeListener('drain', drainListener);
        },
    };
}

module.exports = {
    createExecStdinError,
    discardLateExecStream,
    hasExecStdin,
    writeExecStdin,
};
