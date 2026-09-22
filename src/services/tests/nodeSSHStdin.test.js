'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');

const NodeSSH = require('../nodeSSH');
const sshPool = require('../sshPoolService');

const SANITIZED_STDIN_ERROR = 'SSH stdin transfer failed';

function createExecStream({ onWrite = () => {}, onEnd = () => {}, writeResult = true } = {}) {
    const stream = new EventEmitter();
    stream.stderr = new EventEmitter();
    stream.write = input => {
        onWrite(input);
        return writeResult;
    };
    stream.end = callback => {
        onEnd();
        queueMicrotask(() => {
            if (typeof callback === 'function') callback();
            stream.emit('close', 0);
        });
    };
    return stream;
}

function createDirectNodeSSH(execImplementation) {
    const nodeSSH = new NodeSSH({ id: 'node-direct', name: 'node-direct' });
    nodeSSH.usePool = false;
    nodeSSH.directClient = { exec: execImplementation };
    return nodeSSH;
}

async function withPooledExec(execImplementation, callback) {
    const originalGetConnection = sshPool.getConnection;
    sshPool.getConnection = async () => ({ exec: execImplementation });
    try {
        return await callback();
    } finally {
        sshPool.getConnection = originalGetConnection;
    }
}

test.after(() => sshPool.closeAll());

test('NodeSSH forwards stdin options through pooled execution', async () => {
    const originalExec = sshPool.exec;
    const calls = [];
    sshPool.exec = async (node, command, options) => {
        calls.push({ node, command, options });
        return { code: 0, stdout: '', stderr: '' };
    };

    try {
        const node = { id: 'node-stdin', name: 'node-stdin' };
        const nodeSSH = new NodeSSH(node);
        const secret = 'pool-stdin-secret';
        const result = await nodeSSH.exec('/fixed/receiver', { stdin: secret });

        assert.deepEqual(result, { code: 0, stdout: '', stderr: '' });
        assert.deepEqual(calls, [{
            node,
            command: '/fixed/receiver',
            options: { stdin: secret },
        }]);
    } finally {
        sshPool.exec = originalExec;
    }
});

test('NodeSSH direct execution writes stdin then closes the remote stream', async () => {
    const writes = [];
    let ended = false;
    const nodeSSH = createDirectNodeSSH((command, callback) => {
        assert.equal(command, '/fixed/receiver');
        callback(null, createExecStream({
            onWrite: input => writes.push(Buffer.from(input)),
            onEnd: () => { ended = true; },
        }));
    });

    const secret = 'direct-stdin-secret';
    const result = await nodeSSH.exec('/fixed/receiver', { stdin: secret });

    assert.deepEqual(result, { code: 0, stdout: '', stderr: '' });
    assert.equal(Buffer.concat(writes).toString(), secret);
    assert.equal(ended, true);
});

test('SSH pool writes stdin then closes the remote stream', async () => {
    const writes = [];
    let ended = false;

    await withPooledExec((command, callback) => {
        assert.equal(command, '/fixed/receiver');
        callback(null, createExecStream({
            onWrite: input => writes.push(Buffer.from(input)),
            onEnd: () => { ended = true; },
        }));
    }, async () => {
        const secret = 'pooled-stream-secret';
        const result = await sshPool.exec(
            { id: 'node-pool-stream' },
            '/fixed/receiver',
            { stdin: secret },
        );

        assert.deepEqual(result, { code: 0, stdout: '', stderr: '' });
        assert.equal(Buffer.concat(writes).toString(), secret);
        assert.equal(ended, true);
    });
});

test('direct and pooled stdin execution wait for drain before closing', async () => {
    const payload = 'x'.repeat(192 * 1024 + 17);

    for (const mode of ['direct', 'pool']) {
        const writes = [];
        let waitingForDrain = false;
        let drains = 0;
        let ended = false;
        const execImplementation = (_command, callback) => {
            const stream = createExecStream({
                onWrite(input) {
                    assert.equal(waitingForDrain, false, `${mode} wrote again before drain`);
                    writes.push(Buffer.from(input));
                    waitingForDrain = true;
                    queueMicrotask(() => {
                        waitingForDrain = false;
                        drains += 1;
                        stream.emit('drain');
                    });
                },
                onEnd() {
                    assert.equal(waitingForDrain, false, `${mode} closed before drain`);
                    ended = true;
                },
                writeResult: false,
            });
            callback(null, stream);
        };

        const result = mode === 'direct'
            ? await createDirectNodeSSH(execImplementation).exec('/fixed/receiver', { stdin: payload })
            : await withPooledExec(
                execImplementation,
                () => sshPool.exec({ id: 'node-backpressure' }, '/fixed/receiver', { stdin: payload }),
            );

        assert.deepEqual(result, { code: 0, stdout: '', stderr: '' });
        assert.equal(Buffer.concat(writes).toString(), payload);
        assert.ok(drains >= 2, `${mode} did not exercise repeated backpressure`);
        assert.equal(ended, true);
    }
});

test('direct and pooled stdin execution reject a premature close with a sanitized error', async () => {
    const secret = 'premature-close-secret';

    for (const mode of ['direct', 'pool']) {
        const execImplementation = (_command, callback) => {
            const stream = createExecStream({ writeResult: false });
            stream.end = () => queueMicrotask(() => stream.emit('close', 0));
            stream.write = () => {
                queueMicrotask(() => stream.emit('close', 0));
                return false;
            };
            callback(null, stream);
        };
        const invocation = mode === 'direct'
            ? createDirectNodeSSH(execImplementation).exec('/fixed/receiver', { stdin: secret })
            : withPooledExec(
                execImplementation,
                () => sshPool.exec({ id: 'node-premature-close' }, '/fixed/receiver', { stdin: secret }),
            );

        await assert.rejects(invocation, error => {
            assert.equal(error.message, SANITIZED_STDIN_ERROR);
            assert.equal(error.message.includes(secret), false);
            return true;
        });
    }
});

test('direct and pooled stdin execution sanitize setup and stream write failures', async () => {
    const secret = 'stdin-failure-secret';

    for (const mode of ['direct', 'pool']) {
        for (const failure of ['setup', 'throw', 'write', 'stream', 'stderr']) {
            const execImplementation = (_command, callback) => {
                if (failure === 'setup') {
                    callback(new Error(`setup leaked ${secret}`));
                    return;
                }
                if (failure === 'throw') {
                    throw new Error(`throw leaked ${secret}`);
                }
                const stream = createExecStream();
                if (failure === 'write') {
                    stream.write = () => { throw new Error(`write leaked ${secret}`); };
                } else if (failure === 'stream') {
                    stream.write = () => {
                        queueMicrotask(() => stream.emit('error', new Error(`stream leaked ${secret}`)));
                        return false;
                    };
                } else if (failure === 'stderr') {
                    stream.write = () => {
                        queueMicrotask(() => stream.stderr.emit('error', new Error(`stderr leaked ${secret}`)));
                        return false;
                    };
                }
                callback(null, stream);
            };
            const invocation = mode === 'direct'
                ? createDirectNodeSSH(execImplementation).exec('/fixed/receiver', { stdin: secret })
                : withPooledExec(
                    execImplementation,
                    () => sshPool.exec({ id: 'node-failure' }, '/fixed/receiver', { stdin: secret }),
                );

            await assert.rejects(invocation, error => {
                assert.equal(error.message, SANITIZED_STDIN_ERROR);
                assert.equal(error.message.includes(secret), false);
                return true;
            });
        }
    }

    const originalGetConnection = sshPool.getConnection;
    sshPool.getConnection = async () => { throw new Error(`connection leaked ${secret}`); };
    try {
        await assert.rejects(
            sshPool.exec({ id: 'node-connection-failure' }, '/fixed/receiver', { stdin: secret }),
            error => {
                assert.equal(error.message, SANITIZED_STDIN_ERROR);
                assert.equal(error.message.includes(secret), false);
                return true;
            },
        );
    } finally {
        sshPool.getConnection = originalGetConnection;
    }
});
