'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { performance } = require('node:perf_hooks');
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

async function createGuardedChannel() {
    const node = { ip: '192.0.2.10', ssh: { port: 22, username: 'test' } };
    const direct = new NodeSSH(node, {
        expectedEndpoint: { ip: node.ip, ...node.ssh }, expectedHostKeySha256: 'a'.repeat(64),
    });
    direct.usePool = false;
    const client = new EventEmitter();
    client.on('error', () => {});
    const calls = [], writes = [];
    let callback, ends = 0, disposed = 0;
    client.exec = (...args) => { calls.push(args); callback = args[1]; };
    client.end = () => {}; // Explicit disconnect must not depend on a peer event.
    direct._openDirectClient = async () => client;
    const execPinned = await direct.connectDirectOnce(1000);
    const listeners = Object.fromEntries(['end', 'close', 'error'].map(event => [event, client.listenerCount(event)]));
    const stream = createExecStream({ onWrite: chunk => writes.push(chunk.toString()), onEnd: () => ends++ });
    stream.destroy = () => { disposed++; stream.emit('close'); };
    return { direct, client, node, calls, writes, stream, listeners, execPinned, open: () => callback(null, stream),
        counts: () => ({ ends, disposed }) };
}

const guardedOptions = { stdin: 'fixture-payload', timeout: 5000 };
const nextTurn = () => new Promise(resolve => setImmediate(resolve));
const stdinFailure = error => {
    assert.equal(error.message, SANITIZED_STDIN_ERROR);
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(error.stack, /private-fixture|fixture-payload/);
    return true;
};

test('guarded direct exec waits for the late channel and the local guard before writing', async () => {
    const fixture = await createGuardedChannel();
    const permission = Promise.withResolvers();
    let checked = 0;
    const done = fixture.direct.exec('/fixed/receiver', guardedOptions, (...args) => {
        assert.deepEqual(args, []);
        checked++;
        return permission.promise;
    });
    assert.equal(checked, 0);
    assert.equal(fixture.calls.length, 1);
    assert.deepEqual(fixture.calls[0], ['/fixed/receiver', fixture.calls[0][1]]);
    fixture.open();
    await nextTurn();
    assert.equal(checked, 1);
    assert.deepEqual(fixture.writes, []);
    assert.deepEqual(fixture.counts(), { ends: 0, disposed: 0 });
    permission.resolve();
    assert.deepEqual(await done, { code: 0, stdout: '', stderr: '' });
    assert.deepEqual(fixture.writes, ['fixture-payload']);
    assert.deepEqual(fixture.counts(), { ends: 1, disposed: 0 });
    for (const event of ['end', 'close', 'error']) assert.equal(fixture.client.listenerCount(event), fixture.listeners[event]);
});

test('one-shot exec joins exit status with stderr EOF and writes subsequent payload on the original client', async () => {
    const f = await createGuardedChannel();
    const probe = f.execPinned('/fixed/observation', { timeout: 5000, maxOutputBytes: 34 });
    let resolved = false;
    void probe.then(() => { resolved = true; });
    f.open();
    f.stream.emit('data', Buffer.from('b'.repeat(32) + '\n'));
    f.stream.emit('close', 0);
    await nextTurn();
    assert.equal(resolved, false);
    assert.deepEqual(f.counts(), { ends: 0, disposed: 0 });
    f.stream.stderr.emit('data', Buffer.from('!'));
    f.stream.stderr.emit('end');
    assert.deepEqual(await probe, { code: 0, stdout: 'b'.repeat(32) + '\n', stderr: '!' });

    const receiver = f.execPinned('/fixed/receiver', guardedOptions, async () => true);
    f.open();
    f.stream.stderr.emit('end');
    assert.deepEqual(await receiver, { code: 0, stdout: '', stderr: '' });
    assert.deepEqual(f.calls.map(([command]) => command), ['/fixed/observation', '/fixed/receiver']);
    assert.deepEqual(f.writes, ['fixture-payload']);
    f.direct.disconnect();
});

test('one-shot exec bounds observation bytes across both streams without sending stdin', async () => {
    const f = await createGuardedChannel();
    const probe = assert.rejects(f.execPinned('/fixed/observation', { timeout: 5000, maxOutputBytes: 34 }),
        { message: 'SSH exec output exceeded its limit' });
    f.open();
    f.stream.emit('data', Buffer.from('b'.repeat(32) + '\n'));
    f.stream.stderr.emit('data', Buffer.from('xx'));
    await probe;
    assert.deepEqual(f.counts(), { ends: 0, disposed: 1 });
    assert.deepEqual(f.writes, []);
    f.direct.disconnect();
});

test('one-shot exec cannot open a payload channel on an independently pinned replacement', async () => {
    const f = await createGuardedChannel();
    const probe = f.execPinned('/fixed/observation', { timeout: 5000 });
    f.open();
    f.stream.emit('data', Buffer.from('b'.repeat(32) + '\n'));
    f.stream.stderr.emit('end');
    f.stream.emit('close', 0);
    assert.equal((await probe).code, 0);

    const replacement = new EventEmitter();
    replacement.exec = () => assert.fail('replacement received payload exec');
    replacement.end = () => {};
    f.direct._openDirectClient = async () => replacement;
    await f.direct.connectDirect();
    assert.equal(f.direct.directClient, replacement);
    await assert.rejects(f.execPinned('/fixed/receiver', guardedOptions, () => true), stdinFailure);
    assert.deepEqual(f.calls.map(([command]) => command), ['/fixed/observation']);
    assert.deepEqual(f.writes, []);
    f.direct.disconnect();
});

test('one-shot exec refuses a changed underlying socket during the stdin guard', async () => {
    const f = await createGuardedChannel();
    const allowed = Promise.withResolvers();
    const receiver = assert.rejects(f.execPinned('/fixed/receiver', guardedOptions, () => allowed.promise), stdinFailure);
    f.open();
    f.client._sock = {};
    allowed.resolve(true);
    await receiver;
    assert.deepEqual(f.writes, []);
    assert.deepEqual(f.counts(), { ends: 0, disposed: 1 });
    f.direct.disconnect();
});

test('guarded direct exec sanitizes a busy lock or a rejected or throwing guard', async () => {
    for (const guard of [() => false, async () => { throw Error('private-fixture'); }, () => { throw Error('private-fixture'); }]) {
        const fixture = await createGuardedChannel();
        const rejected = assert.rejects(fixture.direct.exec('/fixed/receiver', guardedOptions, guard), stdinFailure);
        fixture.open();
        await rejected;
        assert.deepEqual(fixture.writes, []);
        assert.deepEqual(fixture.counts(), { ends: 0, disposed: 1 });
        assert.equal(fixture.calls.length, 1);
    }
});

test('guarded direct exec rejects a changed endpoint or client while awaiting the guard', async () => {
    for (const lose of [f => { f.node.ip = '192.0.2.20'; }, f => { f.node.ssh.port = 2222; },
        f => { f.node.ssh.username = 'private-fixture'; }, f => { f.direct.usePool = true; },
        f => { f.direct.directClient = new EventEmitter(); }]) {
        const fixture = await createGuardedChannel();
        const permission = Promise.withResolvers();
        let checked = false;
        const rejected = assert.rejects(fixture.direct.exec('/fixed/receiver', guardedOptions, () => {
            checked = true;
            return permission.promise;
        }), stdinFailure);
        fixture.open();
        await nextTurn();
        assert.equal(checked, true);
        lose(fixture);
        permission.resolve(true);
        await rejected;
        assert.deepEqual(fixture.writes, []);
        assert.deepEqual(fixture.counts(), { ends: 0, disposed: 1 });
    }
});

test('a newly pinned client does not authorize stdin on the original channel', async () => {
    const fixture = await createGuardedChannel();
    const replacement = new EventEmitter();
    const ready = Promise.withResolvers();
    let attempts = 0;
    fixture.direct._openDirectClient = () => ++attempts === 1 ? fixture.client : ready.promise;
    // Start both dials before a client is published, then delay the second ready event.
    const first = fixture.direct.connectDirect();
    const second = fixture.direct.connectDirect();
    await first;
    const permission = Promise.withResolvers();
    const rejected = assert.rejects(fixture.direct.exec('/fixed/receiver', guardedOptions, () => permission.promise), stdinFailure);
    fixture.open();
    ready.resolve(replacement);
    await second;
    assert.equal(fixture.direct.directClient, replacement);
    permission.resolve(true);
    await rejected;
    assert.deepEqual(fixture.writes, []);
    assert.deepEqual(fixture.counts(), { ends: 0, disposed: 1 });
});

test('guarded stdin refuses a late authorization even when the timeout callback has not run', async t => {
    const fixture = await createGuardedChannel();
    let now = 0;
    t.mock.method(performance, 'now', () => now);
    const permission = Promise.withResolvers();
    const rejected = assert.rejects(fixture.direct.exec('/fixed/receiver', guardedOptions, () => permission.promise), stdinFailure);
    fixture.open();
    now = guardedOptions.timeout;
    permission.resolve(true);
    await rejected;
    assert.deepEqual(fixture.writes, []);
    assert.deepEqual(fixture.counts(), { ends: 0, disposed: 1 });
});

for (const reason of ['timeout before callback', 'timeout', 'disconnect', 'peer end', 'client error', 'channel close']) {
    test(`guarded direct exec cancels stdin on ${reason} even if authorization arrives later`, async t => {
        const fixture = await createGuardedChannel();
        t.mock.timers.enable({ apis: ['setTimeout'] });
        const permission = Promise.withResolvers();
        let checked = 0;
        const rejected = assert.rejects(fixture.direct.exec('/fixed/receiver', guardedOptions, () => {
            checked++;
            return permission.promise;
        }), stdinFailure);
        const lateChannel = reason === 'timeout before callback';
        if (!lateChannel) {
            fixture.open();
            await nextTurn();
        }
        if (reason.startsWith('timeout')) t.mock.timers.tick(guardedOptions.timeout);
        if (reason === 'disconnect') fixture.direct.disconnect();
        if (reason === 'peer end') fixture.client.emit('end');
        if (reason === 'client error') fixture.client.emit('error', Error('private-fixture'));
        if (reason === 'channel close') fixture.stream.emit('close');
        await rejected; // Cancellation must not wait for authorization to return.
        if (lateChannel) fixture.open();
        if (reason === 'client error') permission.reject(Error('private-fixture'));
        else permission.resolve(true);
        await nextTurn();
        assert.equal(checked, lateChannel ? 0 : 1);
        assert.deepEqual(fixture.writes, []);
        assert.equal(fixture.counts().ends, 0);
        assert.equal(fixture.counts().disposed, reason === 'channel close' ? 0 : 1);
        assert.equal(fixture.calls.length, 1);
    });
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

for (const mode of ['pool', 'direct']) {
    test(`${mode}: a timed-out exec ignores the late channel without sending stdin or replaying`, async t => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        let callback;
        let calls = 0;
        let writes = 0;
        let ends = 0;
        let destroyed = 0;
        const exec = (_command, cb) => { calls++; callback = cb; };
        const exercise = async run => {
            const invocation = run();
            const rejected = assert.rejects(invocation, { message: SANITIZED_STDIN_ERROR });
            await Promise.resolve();
            assert.equal(calls, 1);
            t.mock.timers.tick(50);
            const stream = createExecStream({ onWrite: () => writes++, onEnd: () => ends++ });
            stream.destroy = () => destroyed++;
            callback(null, stream);
            await rejected;
            assert.deepEqual({ calls, writes, ends, destroyed }, { calls: 1, writes: 0, ends: 0, destroyed: 1 });
        };
        const options = { stdin: 'local-payload', timeout: 50 };
        if (mode === 'direct') {
            await exercise(() => createDirectNodeSSH(exec).exec('/fixed/receiver', options));
        } else {
            await withPooledExec(exec, () => exercise(() => sshPool.exec({ id: 'late-channel' }, '/fixed/receiver', options)));
        }
    });
}

test('explicit direct exec timeout also applies after channel open without stdin', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const stream = createExecStream();
    let calls = 0;
    const direct = createDirectNodeSSH((_command, callback) => { calls++; callback(null, stream); });
    const rejected = assert.rejects(direct.exec('/fixed/commit', { timeout: 130_000 }), { message: 'Exec timeout (130000ms)' });
    t.mock.timers.tick(130_000);
    stream.emit('data', Buffer.from('late-reply'));
    stream.emit('close', 0);
    await rejected;
    assert.equal(calls, 1);
});

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
        let checked = false;
        const result = await nodeSSH.exec('/fixed/receiver', { stdin: secret }, () => { checked = true; });
        assert.equal(checked, false);

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
